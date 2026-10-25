//! What the engine's checks share: an engine of their own, its requests,
//! and a page that watches a terminal over the socket.

#![allow(dead_code)]

use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tterm_engine::socket::PageSocket;
use tterm_engine::terminals::Outgoing;
use tterm_engine::{api, Engine};

/// Tests that flood a shell or count CPU time take turns: CPU time is the
/// whole test process's.
pub static HEAVY: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn heavy() -> std::sync::MutexGuard<'static, ()> {
    HEAVY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Room for more open files than a Mac gives a process by default (256):
/// the checks of the sign-in port hold well over a hundred connections at
/// once, next to the other checks running meanwhile.
pub fn room_for_files() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: the calls get a valid pointer, and change only this
        // process's limit.
        unsafe {
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 && limit.rlim_cur < 4096 {
                limit.rlim_cur = limit.rlim_max.min(4096);
                libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
            }
        }
    });
}

/// With a space in it, as "Application Support" has on a Mac: the shell
/// scripts' folder is in it.
pub fn data_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("tterm engine test-{}", uuid::Uuid::new_v4()))
}

pub async fn engine() -> Arc<Engine> {
    let e = Engine::new(&data_dir()).expect("engine");
    e.start_background();
    e
}

pub async fn request(e: &Arc<Engine>, method: &str, path: &str, body: Value) -> (u16, Value) {
    let raw = if body.is_null() { Vec::new() } else { body.to_string().into_bytes() };
    let r = api::handle(e, method, path, &raw).await;
    let value = if r.body.is_empty() { Value::Null } else { serde_json::from_slice(&r.body).unwrap_or(Value::Null) };
    (r.status, value)
}

/// What one page sees of one channel: the output, as bytes, and the JSON
/// messages, in order.
pub struct Page {
    pub sock: Arc<PageSocket>,
    pub rx: mpsc::Receiver<Outgoing>,
    pub out: Vec<u8>,
    pub msgs: Vec<Value>,
    pub last_seq: u64,
    /// Where in `out` each marker came.
    pub marks_at: Vec<usize>,
}

impl Page {
    pub fn new(e: &Arc<Engine>) -> Page {
        let (sock, rx) = PageSocket::new(e.clone());
        Page { sock, rx, out: Vec::new(), msgs: Vec::new(), last_seq: 0, marks_at: Vec::new() }
    }

    pub async fn send(&self, msg: Value) {
        self.sock.text(&msg.to_string()).await;
    }

    pub async fn keys(&self, ch: u32, data: &str) {
        let mut frame = vec![2u8];
        frame.extend_from_slice(&ch.to_be_bytes());
        frame.extend_from_slice(data.as_bytes());
        self.sock.binary(&frame).await;
    }

    pub fn take(&mut self, m: Outgoing) {
        match m {
            Outgoing::Binary(f) => {
                assert_eq!(f[0], 1);
                self.last_seq = u64::from_be_bytes(f[5..13].try_into().unwrap());
                self.out.extend_from_slice(&f[13..]);
            }
            Outgoing::Text(t) => {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["op"] == "ev" {
                    self.marks_at.push(self.out.len());
                }
                if let Some(seq) = v.get("seq").and_then(Value::as_u64) {
                    if v["op"] == "ev" || v["op"] == "reset" {
                        self.last_seq = seq;
                    }
                }
                self.msgs.push(v);
            }
        }
    }

    /// Waits until `done` holds, at most `secs` seconds.
    pub async fn until(&mut self, secs: u64, done: impl Fn(&Page) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            if done(self) {
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            match tokio::time::timeout(left, self.rx.recv()).await {
                Ok(Some(m)) => self.take(m),
                _ => return done(self),
            }
        }
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.out).to_string()
    }

    pub fn state(&self) -> Option<Value> {
        self.msgs.iter().rev().find(|m| m["op"] == "state" || m["op"] == "attached").map(|m| m["terminal"].clone())
    }
}

pub async fn open(e: &Arc<Engine>, cols: i64, rows: i64) -> String {
    let machine = e.settings.lock().unwrap().machine_id.to_string();
    let (status, t) = request(e, "POST", "/api/terminals", json!({"machineId": machine, "cols": cols, "rows": rows})).await;
    assert_eq!(status, 201, "{t}");
    assert_eq!(t["state"], "connecting");
    t["id"].as_str().unwrap().to_string()
}

pub async fn attached(e: &Arc<Engine>, id: &str, cols: i64, rows: i64) -> Page {
    let mut page = Page::new(e);
    page.send(json!({"op": "attach", "ch": 1, "id": id, "after": null, "cols": cols, "rows": rows, "focus": true})).await;
    assert!(page.until(10, |p| p.msgs.iter().any(|m| m["op"] == "replayed")).await, "{:?}", page.msgs);
    assert!(page.until(10, |p| p.state().map(|s| s["state"] == "open").unwrap_or(false)).await, "{:?}", page.msgs);
    page
}
