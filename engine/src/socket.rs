//! The page's one socket, answered here instead of by the core: every
//! terminal the page shows goes through it, each on a channel number the
//! page picks. The messages are those of `tterm/api/ws.py`:
//!
//! ```text
//! page → engine  {"op": "attach", "ch": 1, "id": "<terminal>", "after": 41,
//!                 "cols": 120, "rows": 40, "focus": true}
//!                {"op": "resize", "ch": 1, "cols": 100, "rows": 30}
//!                {"op": "focus" | "pause" | "resume" | "detach" | "close", "ch": 1}
//!                {"op": "run", "ch": 1, "command": "ls -la", "confirmed": false}
//!                binary: 0x02, channel (4 bytes), keystrokes
//! engine → page  {"op": "attached" | "reset" | "replayed" | "ev" | "state"
//!                 | "gone" | "confirm" | "refused" | "error", ...}
//!                binary: 0x01, channel (4 bytes), number (8 bytes), output
//! ```

use crate::terminals::{clean_command, Outgoing, Watcher, INPUT};
use crate::Engine;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

/// Channels one page may hold at once.
pub const MAX_CHANNELS: usize = 64;
/// Messages on the way to the page at once, at most: with frames of
/// FRAME_MAX, half a megabyte of output. A page that draws slowly takes
/// slowly, its watchers wait, and so do the shells behind them.
pub const OUTBOX: usize = 16;

pub struct PageSocket {
    engine: Arc<Engine>,
    out: mpsc::Sender<Outgoing>,
    /// None once the page went: an attach still on its way then starts
    /// nothing (as `_closed` in ws.py).
    watchers: Mutex<Option<HashMap<u32, Watcher>>>,
}

impl PageSocket {
    /// A socket of the page; what the engine sends comes out of the
    /// receiver, in order.
    pub fn new(engine: Arc<Engine>) -> (Arc<PageSocket>, mpsc::Receiver<Outgoing>) {
        let (out, rx) = mpsc::channel(OUTBOX);
        (Arc::new(PageSocket { engine, out, watchers: Mutex::new(Some(HashMap::new())) }), rx)
    }

    async fn json(&self, message: Value) {
        let _ = self.out.send(Outgoing::Text(message.to_string())).await;
    }

    /// Keys for a terminal: binary, 0x02, the channel, the keys.
    pub async fn binary(&self, frame: &[u8]) {
        if frame.len() < 5 || frame[0] != INPUT {
            return;
        }
        let ch = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        if let Some(w) = self.watchers.lock().await.as_ref().and_then(|all| all.get(&ch)) {
            w.write(&frame[5..]);
        }
    }

    /// A message in JSON.
    pub async fn text(&self, text: &str) {
        let Ok(msg) = serde_json::from_str::<Value>(text) else {
            self.json(json!({"op": "error", "message": "Not understood."})).await;
            return;
        };
        let Some(op) = msg.get("op").and_then(Value::as_str) else {
            self.json(json!({"op": "error", "message": "Not understood."})).await;
            return;
        };
        let ch = msg.get("ch").and_then(Value::as_u64).unwrap_or(0) as u32;
        if op == "attach" {
            self.attach(ch, &msg).await;
            return;
        }
        let mut guard = self.watchers.lock().await;
        let Some(watchers) = guard.as_mut() else { return };
        let Some(w) = watchers.get(&ch) else { return };
        match op {
            "resize" => resize(w, &msg),
            "focus" => w.focus(),
            "pause" => w.pause(),
            "resume" => w.resume(),
            "detach" => {
                if let Some(w) = watchers.remove(&ch) {
                    w.stop();
                }
            }
            "close" => {
                // Ending a shell can take a moment; the socket goes on.
                let t = w.terminal.clone();
                tokio::spawn(async move { t.close("Closed.").await });
            }
            "run" => {
                let Some(command) = msg.get("command").and_then(Value::as_str) else { return };
                let command = clean_command(command);
                // Running a command is typing: this page becomes the one
                // that types.
                w.focus();
                if let Some(why) = w.terminal.run(&command) {
                    drop(guard);
                    self.json(json!({"op": "refused", "ch": ch, "command": command, "reason": why})).await;
                }
            }
            _ => {}
        }
    }

    async fn attach(&self, ch: u32, msg: &Value) {
        let mut guard = self.watchers.lock().await;
        let Some(watchers) = guard.as_mut() else { return };
        if let Some(old) = watchers.remove(&ch) {
            old.stop();
        }
        let terminal = msg
            .get("id")
            .and_then(Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())
            .and_then(|id| self.engine.terminals.get(&id));
        let Some(terminal) = terminal else {
            drop(guard);
            self.json(json!({"op": "gone", "ch": ch, "terminal": Value::Null})).await;
            return;
        };
        if watchers.len() >= MAX_CHANNELS {
            drop(guard);
            self.json(json!({"op": "error", "message": "Too many terminals."})).await;
            return;
        }
        if let (Some(cols), Some(rows)) = (msg.get("cols").and_then(Value::as_i64), msg.get("rows").and_then(Value::as_i64)) {
            if cols > 0 && rows > 0 {
                terminal.resize(cols, rows);
            }
        }
        let after = msg.get("after").and_then(Value::as_u64);
        let watcher = Watcher::start(terminal, ch, self.out.clone(), after);
        if msg.get("focus") == Some(&Value::Bool(true)) {
            watcher.focus();
        }
        watchers.insert(ch, watcher);
    }

    /// The page went: its watchers stop, the terminals go on, and nothing
    /// it still sends starts anything.
    pub async fn close(&self) {
        let gone = self.watchers.lock().await.take();
        for (_, w) in gone.into_iter().flatten() {
            w.stop();
        }
    }
}

/// A size the page measured. A page that only watches sends none, and
/// leaves the size as it is.
fn resize(w: &Watcher, msg: &Value) {
    if let (Some(cols), Some(rows)) = (msg.get("cols").and_then(Value::as_i64), msg.get("rows").and_then(Value::as_i64)) {
        if cols > 0 && rows > 0 {
            w.terminal.resize(cols, rows);
        }
    }
}
