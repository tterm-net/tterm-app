//! The page's cloud terminals, over its one socket (from 0.3.0). A channel
//! the page attaches to a terminal this app does not have goes to tTerm Web
//! in the cloud, on a socket of the app's own there, one per page socket:
//! its messages go there as the page wrote them, and what tTerm sends comes
//! back as it is. The channels keep their numbers.
//!
//! That socket drops when the network does, or tTerm restarts. The page's
//! socket stays (this computer's terminals go on), and the relay comes back
//! by itself: it attaches its channels again, each from the last number the
//! page has, as the page itself does after its socket comes back; the
//! channel the page focused last takes the keys again, and one the page had
//! paused is paused again. A session that ended (close code 4401) is renewed
//! with the device's key first. When the page is gone, the relay is too.

use crate::account::{Account, Trouble};
use crate::terminals::{Outgoing, INPUT, OUTPUT};
use crate::upstream::SocketRefused;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use tokio_tungstenite::tungstenite::Message;

/// Waits before connecting again, in turn (as the page's socket.ts).
const RETRY_MS: [u64; 5] = [300, 1000, 2000, 4000, 8000];
/// The close code of a session that ended (tterm/api/ws.py).
const SIGNED_OUT: u16 = 4401;

/// A channel of the page's on tTerm: what attaching it again takes.
#[derive(Clone, Debug)]
struct Channel {
    id: String,
    /// The last number the page was sent: from there on, after a drop.
    after: Option<u64>,
    cols: Option<i64>,
    rows: Option<i64>,
    paused: bool,
}

#[derive(Default)]
struct Inner {
    channels: HashMap<u32, Channel>,
    /// The channel the page focused last: the one that types, as its tab is
    /// in front.
    focused: Option<u32>,
    /// To tTerm, while connected.
    link: Option<mpsc::UnboundedSender<Message>>,
    running: bool,
}

/// How a connection to tTerm ended.
enum Ended {
    /// The network, or tTerm restarting.
    Dropped,
    /// tTerm closed it, with this code.
    Closed(u16),
    /// The page went: nothing to relay any more.
    PageGone,
}

/// One page socket's way to tTerm.
pub struct Relay {
    account: Arc<Account>,
    to_page: mpsc::Sender<Outgoing>,
    inner: Mutex<Inner>,
    closed: AtomicBool,
    stop: Notify,
}

impl Relay {
    pub fn new(account: Arc<Account>, to_page: mpsc::Sender<Outgoing>) -> Arc<Relay> {
        Arc::new(Relay { account, to_page, inner: Mutex::new(Inner::default()), closed: AtomicBool::new(false), stop: Notify::new() })
    }

    pub fn has(&self, ch: u32) -> bool {
        self.inner.lock().unwrap().channels.contains_key(&ch)
    }

    /// The page attaches channel `ch` to a terminal on tTerm.
    pub fn attach(self: &Arc<Self>, ch: u32, msg: &Value) {
        let channel = Channel {
            id: msg.get("id").and_then(Value::as_str).unwrap_or("").to_string(),
            after: msg.get("after").and_then(Value::as_u64),
            cols: msg.get("cols").and_then(Value::as_i64),
            rows: msg.get("rows").and_then(Value::as_i64),
            paused: false,
        };
        let focus = msg.get("focus") == Some(&Value::Bool(true));
        let start = {
            let mut inner = self.inner.lock().unwrap();
            if focus {
                inner.focused = Some(ch);
            } else if inner.focused == Some(ch) {
                inner.focused = None;
            }
            if let Some(link) = &inner.link {
                let _ = link.send(Message::Text(attach_message(ch, &channel, focus).into()));
            }
            inner.channels.insert(ch, channel);
            !std::mem::replace(&mut inner.running, true)
        };
        if start && !self.closed.load(Ordering::SeqCst) {
            let me = self.clone();
            tokio::spawn(async move { me.run().await });
        }
    }

    /// A message of the page for one of its channels on tTerm.
    pub fn text(&self, ch: u32, raw: &str, msg: &Value) {
        let mut inner = self.inner.lock().unwrap();
        let op = msg.get("op").and_then(Value::as_str).unwrap_or("");
        match op {
            "detach" => {
                inner.channels.remove(&ch);
                if inner.focused == Some(ch) {
                    inner.focused = None;
                }
            }
            "resize" => {
                if let Some(c) = inner.channels.get_mut(&ch) {
                    c.cols = msg.get("cols").and_then(Value::as_i64).or(c.cols);
                    c.rows = msg.get("rows").and_then(Value::as_i64).or(c.rows);
                }
            }
            "focus" | "run" => inner.focused = Some(ch),
            "pause" | "resume" => {
                if let Some(c) = inner.channels.get_mut(&ch) {
                    c.paused = op == "pause";
                }
            }
            _ => {}
        }
        if let Some(link) = &inner.link {
            let _ = link.send(Message::Text(raw.to_string().into()));
        }
    }

    /// Keys for one of its channels on tTerm.
    pub fn binary(&self, frame: &[u8]) {
        if frame.len() < 5 || frame[0] != INPUT {
            return;
        }
        let inner = self.inner.lock().unwrap();
        if let Some(link) = &inner.link {
            let _ = link.send(Message::Binary(frame.to_vec().into()));
        }
    }

    /// The channel goes to a terminal of this computer instead.
    pub fn forget(&self, ch: u32) {
        let mut inner = self.inner.lock().unwrap();
        if inner.focused == Some(ch) {
            inner.focused = None;
        }
        if inner.channels.remove(&ch).is_some() {
            if let Some(link) = &inner.link {
                let _ = link.send(Message::Text(json!({"op": "detach", "ch": ch}).to_string().into()));
            }
        }
    }

    /// The page went: the socket on tTerm goes too.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let mut inner = self.inner.lock().unwrap();
        inner.link = None;
        inner.channels.clear();
        self.stop.notify_waiters();
        self.stop.notify_one();
    }

    fn done(&self) -> bool {
        self.closed.load(Ordering::SeqCst) || self.inner.lock().unwrap().channels.is_empty()
    }

    async fn run(self: Arc<Self>) {
        let mut turn = 0usize;
        loop {
            if self.done() {
                break;
            }
            // While tTerm cannot be reached, its probe says when it can.
            let mut online = self.account.online.subscribe();
            if !*online.borrow() {
                tokio::select! {
                    _ = online.wait_for(|o| *o) => {}
                    _ = self.stop.notified() => break,
                }
                turn = 0;
                continue;
            }
            let (cookie, session) = match self.account.socket_cookie().await {
                Ok(c) => c,
                Err(Trouble::SignedOut) => break,
                Err(Trouble::Offline) => {
                    self.pause(&mut turn).await;
                    continue;
                }
            };
            match self.account.cloud.socket(&cookie).await {
                Ok(socket) => {
                    turn = 0;
                    match self.pump(socket).await {
                        Ended::PageGone => {
                            self.close();
                            break;
                        }
                        // The session ended: a new one, unless the device was
                        // forgotten.
                        Ended::Closed(SIGNED_OUT) => {
                            if matches!(self.account.session_ended(&session).await, Err(Trouble::SignedOut)) {
                                break;
                            }
                        }
                        Ended::Closed(_) | Ended::Dropped => {}
                    }
                }
                // tTerm takes a session that ended and closes it with 4401;
                // a refusal before that is no matter of the session, and
                // only waits. So does a socket that cannot get through while
                // requests do (a proxy that lets no socket by): the requests
                // say for themselves whether tTerm can be reached.
                Err(SocketRefused::Status(status)) => eprintln!("tterm: tTerm did not open the page's socket ({status})"),
                Err(SocketRefused::Unreachable(why)) => eprintln!("tterm: the page's socket on tTerm could not open: {}", why.0),
            }
            if self.done() {
                break;
            }
            self.pause(&mut turn).await;
        }
        self.inner.lock().unwrap().running = false;
    }

    async fn pause(&self, turn: &mut usize) {
        let wait = RETRY_MS[(*turn).min(RETRY_MS.len() - 1)];
        *turn += 1;
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(wait)) => {}
            _ = self.stop.notified() => {}
        }
    }

    /// One connection: the channels attached, then everything both ways
    /// until it ends.
    async fn pump(&self, socket: crate::upstream::CloudSocket) -> Ended {
        let (mut sink, mut stream) = socket.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        {
            let mut inner = self.inner.lock().unwrap();
            for (ch, channel) in &inner.channels {
                let _ = tx.send(Message::Text(attach_message(*ch, channel, inner.focused == Some(*ch)).into()));
                if channel.paused {
                    let _ = tx.send(Message::Text(json!({"op": "pause", "ch": ch}).to_string().into()));
                }
            }
            inner.link = Some(tx);
        }
        let ended = loop {
            tokio::select! {
                out = rx.recv() => match out {
                    Some(message) => {
                        if sink.send(message).await.is_err() {
                            break Ended::Dropped;
                        }
                    }
                    // The page went (close() dropped the link).
                    None => {
                        let _ = sink.send(Message::Close(None)).await;
                        break Ended::PageGone;
                    }
                },
                came = stream.next() => match came {
                    Some(Ok(Message::Text(text))) => {
                        let text = text.as_str().to_string();
                        self.heard_text(&text);
                        if self.to_page.send(Outgoing::Text(text)).await.is_err() {
                            break Ended::PageGone;
                        }
                    }
                    Some(Ok(Message::Binary(frame))) => {
                        self.heard_binary(&frame);
                        if self.to_page.send(Outgoing::Binary(frame.to_vec())).await.is_err() {
                            break Ended::PageGone;
                        }
                    }
                    Some(Ok(Message::Close(frame))) => break frame.map(|f| Ended::Closed(u16::from(f.code))).unwrap_or(Ended::Dropped),
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break Ended::Dropped,
                },
                _ = self.stop.notified() => {
                    let _ = sink.send(Message::Close(None)).await;
                    break Ended::PageGone;
                }
            }
        };
        self.inner.lock().unwrap().link = None;
        ended
    }

    /// What tTerm said of a channel: how far the page got, and a terminal
    /// it no longer has.
    fn heard_text(&self, text: &str) {
        let Ok(msg) = serde_json::from_str::<Value>(text) else { return };
        let Some(ch) = msg.get("ch").and_then(Value::as_u64).map(|c| c as u32) else { return };
        let mut inner = self.inner.lock().unwrap();
        match msg.get("op").and_then(Value::as_str) {
            Some("gone") => {
                inner.channels.remove(&ch);
            }
            Some("ev") | Some("reset") => {
                if let (Some(c), Some(seq)) = (inner.channels.get_mut(&ch), msg.get("seq").and_then(Value::as_u64)) {
                    c.after = Some(seq);
                }
            }
            _ => {}
        }
    }

    fn heard_binary(&self, frame: &[u8]) {
        if frame.len() < 13 || frame[0] != OUTPUT {
            return;
        }
        let ch = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        let seq = u64::from_be_bytes(frame[5..13].try_into().unwrap_or([0; 8]));
        if let Some(c) = self.inner.lock().unwrap().channels.get_mut(&ch) {
            c.after = Some(seq);
        }
    }
}

/// The attach of a channel, from where the page got to.
fn attach_message(ch: u32, c: &Channel, focus: bool) -> String {
    json!({"op": "attach", "ch": ch, "id": c.id, "after": c.after, "cols": c.cols, "rows": c.rows, "focus": focus}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_again_from_where_it_got() {
        let c = Channel { id: "t1".into(), after: Some(41), cols: Some(120), rows: Some(40), paused: false };
        let m: Value = serde_json::from_str(&attach_message(3, &c, true)).unwrap();
        assert_eq!(m, json!({"op": "attach", "ch": 3, "id": "t1", "after": 41, "cols": 120, "rows": 40, "focus": true}));
    }
}
