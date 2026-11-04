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
//!
//! From 0.8.1 (the contract's v3, tTerm Web 0.1.28) the engine proves on
//! each such socket that the vault is open on this Mac (vault.rs `proof`):
//! tTerm gives the socket a nonce first, and with the vault open the proof
//! goes before the channels' attaches, which tTerm takes in that order, so
//! a terminal of a guarded machine attaches at once. The vault opening later
//! proves it then; locking it says `vault.closed`. The page hears tTerm's
//! `vault.challenge` and its word (`vault.proven`, `vault.unproven`), and the
//! engine's `vault.closed`: it shows the keys open or closed by them, and
//! attaches again what tTerm said was locked. The page's own proof messages
//! go nowhere: in the app it has no key to prove with.

use crate::account::{Account, Trouble};
use crate::terminals::{Outgoing, INPUT, OUTPUT};
use crate::upstream::SocketRefused;
use crate::Engine;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

/// Waits before connecting again, in turn (as the page's socket.ts).
const RETRY_MS: [u64; 5] = [300, 1000, 2000, 4000, 8000];
/// The close code of a session that ended (tterm/api/ws.py).
const SIGNED_OUT: u16 = 4401;
/// How long a new socket waits for tTerm's nonce before it attaches the
/// channels, with the vault open here (0.8.1): it comes first, at once; a
/// tTerm before 0.1.28 sends none.
const CHALLENGE_WAIT: Duration = Duration::from_secs(2);
/// The keys closed on this Mac, to tTerm and to the page (0.8.1).
const CLOSED: &str = r#"{"op":"vault.closed"}"#;

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
    /// The fingerprints the page itself said it can sign for (its own
    /// `vault.can`, from 0.7.0): sent with the engine's, as one list, since
    /// the core takes the last `vault.can` of a socket as the whole of it.
    page_can: Vec<String>,
}

/// The proof of the keys open on one socket to tTerm (0.8.1).
#[derive(Default)]
struct Proving {
    /// The nonce tTerm gave this socket.
    nonce: Option<String>,
    /// A proof sent, tTerm's word on it still to come.
    asked: bool,
    /// The vault password's proof, when that was the one sent.
    password: Option<Zeroizing<String>>,
    /// tTerm took it: the keys are open on this socket.
    proven: bool,
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
    /// The engine, for the vault: it answers `vault.sign` on this socket
    /// itself and tells the core which keys it can sign for (`vault.can`).
    engine: Arc<Engine>,
    to_page: mpsc::Sender<Outgoing>,
    inner: Mutex<Inner>,
    closed: AtomicBool,
    stop: Notify,
}

impl Relay {
    pub fn new(account: Arc<Account>, engine: Arc<Engine>, to_page: mpsc::Sender<Outgoing>) -> Arc<Relay> {
        Arc::new(Relay { account, engine, to_page, inner: Mutex::new(Inner::default()), closed: AtomicBool::new(false), stop: Notify::new() })
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

    /// Connects to tTerm now, with no channel yet (from 0.7.0): the page is
    /// there and signed in, so the core's `vault.pairing` and `vault.changed`
    /// reach it, and the engine can sign for its vault on this socket even
    /// when the page shows no cloud terminal. Needs a runtime to start on;
    /// without one it starts with the page's first message.
    pub fn start(self: &Arc<Self>) -> bool {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return false };
        let start = !std::mem::replace(&mut self.inner.lock().unwrap().running, true);
        if start && !self.closed.load(Ordering::SeqCst) {
            let me = self.clone();
            runtime.spawn(async move { me.run().await });
        }
        true
    }

    /// One of the page's own vault messages, with no channel (`vault.can`,
    /// `vault.signed`, `vault.unable`): a `vault.can` joins the engine's in
    /// the list the core gets; the rest go as the page wrote them.
    pub fn page_vault(self: &Arc<Self>, raw: &str, msg: &Value) {
        let op = msg.get("op").and_then(Value::as_str).unwrap_or("");
        // The proof of the keys open on this socket is the engine's (0.8.1):
        // the page in the app has no key to prove with, nor a word to say
        // of it.
        if op == "vault.prove" || op == "vault.closed" {
            self.start();
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        if op == "vault.can" {
            inner.page_can = msg.get("keys").and_then(Value::as_array).map(|keys| keys.iter().filter_map(|k| k.as_str().map(str::to_string)).collect()).unwrap_or_default();
            let all = joined(&self.vault_can().borrow(), &inner.page_can);
            if let Some(link) = &inner.link {
                let _ = link.send(Message::Text(can_message(&all).into()));
            }
        } else if let Some(link) = &inner.link {
            let _ = link.send(Message::Text(raw.to_string().into()));
        }
        drop(inner);
        self.start();
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

    /// The relay is over when the page's socket went (from 0.7.0): not when
    /// its last cloud channel did, since the socket carries the vault too
    /// (the core's `vault.pairing`, `vault.changed`, and `vault.sign` for
    /// the engine's keys).
    fn done(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
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
        // A vault opened in an account signed out since is locked first:
        // this socket announces nothing of it.
        if let Some(vault) = self.engine.vault.clone() {
            vault.check_account(&self.engine).await;
        }
        let (mut sink, mut stream) = socket.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        // The vault's keys now, and whenever they change while this socket
        // is up: the core asks a socket to sign only for what it announced.
        let mut can = self.vault_can();
        // The vault opening, locking, or what proves it changing (0.8.1).
        let mut news = self.vault_turns();
        news.borrow_and_update();
        let (mut can_on, mut news_on) = (true, true);
        {
            let inner = self.inner.lock().unwrap();
            let all = joined(&can.borrow_and_update(), &inner.page_can);
            let _ = tx.send(Message::Text(can_message(&all).into()));
        }
        // With the vault open here, tTerm's nonce (its first message on a
        // new socket) is waited for, and the proof goes before the attaches
        // (0.8.1): tTerm takes them in that order. The nonce goes on to the
        // page from the loop, as anything tTerm says.
        let mut proving = Proving::default();
        let mut first = None;
        if self.engine.vault.as_ref().map(|v| v.proves()).unwrap_or(false) {
            match tokio::time::timeout(CHALLENGE_WAIT, stream.next()).await {
                Ok(Some(Ok(message))) => {
                    if let Some(nonce) = match &message {
                        Message::Text(text) => challenge_of(text.as_str()),
                        _ => None,
                    } {
                        proving.nonce = Some(nonce);
                        self.prove(&tx, &mut proving);
                    }
                    first = Some(Ok(message));
                }
                Ok(Some(Err(_))) | Ok(None) => {
                    self.inner.lock().unwrap().link = None;
                    return Ended::Dropped;
                }
                // None in time (a tTerm before 0.1.28): on without.
                Err(_) => {}
            }
        }
        let mut stream = futures_util::stream::iter(first).chain(stream);
        {
            let mut inner = self.inner.lock().unwrap();
            for (ch, channel) in &inner.channels {
                let _ = tx.send(Message::Text(attach_message(*ch, channel, inner.focused == Some(*ch)).into()));
                if channel.paused {
                    let _ = tx.send(Message::Text(json!({"op": "pause", "ch": ch}).to_string().into()));
                }
            }
            inner.link = Some(tx.clone());
        }
        let ended = loop {
            tokio::select! {
                changed = can.changed(), if can_on => {
                    // A vault that is gone says nothing more.
                    if changed.is_err() {
                        can_on = false;
                        continue;
                    }
                    let all = joined(&can.borrow_and_update(), &self.inner.lock().unwrap().page_can);
                    if tx.send(Message::Text(can_message(&all).into())).is_err() {
                        break Ended::Dropped;
                    }
                }
                changed = news.changed(), if news_on => {
                    if changed.is_err() {
                        news_on = false;
                        continue;
                    }
                    news.borrow_and_update();
                    if self.vault_turned(&tx, &mut proving).await.is_err() {
                        break Ended::PageGone;
                    }
                }
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
                        // A request to sign a login the engine answers
                        // itself: the key never goes to the page.
                        if self.maybe_sign(&text, &tx) {
                            continue;
                        }
                        // The vault's news goes on to the page once the
                        // engine has read the vault again, so what the page
                        // asks then (GET /api/app/vault) is new already.
                        if self.vault_news(&text) {
                            continue;
                        }
                        // The proof on this socket (0.8.1): tTerm's nonce,
                        // and its word on the proof.
                        if !self.heard_proof(&text, &tx, &mut proving) {
                            continue;
                        }
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

/// The `vault.can` message: the fingerprints this socket can sign for now,
/// empty when the vault is locked.
fn can_message(keys: &[String]) -> String {
    json!({"op": "vault.can", "keys": keys}).to_string()
}

/// The nonce of tTerm's `vault.challenge`, when `text` is one.
fn challenge_of(text: &str) -> Option<String> {
    if !text.contains("\"vault.challenge\"") {
        return None;
    }
    let msg: Value = serde_json::from_str(text).ok()?;
    if msg.get("op").and_then(Value::as_str) != Some("vault.challenge") {
        return None;
    }
    msg.get("nonce").and_then(Value::as_str).map(str::to_string)
}

/// The engine's fingerprints and the page's, each once, the engine's first.
fn joined(engine: &[String], page: &[String]) -> Vec<String> {
    let mut all = engine.to_vec();
    for k in page {
        if !all.contains(k) {
            all.push(k.clone());
        }
    }
    all
}

impl Relay {
    /// What the vault can sign for, to watch; an always-empty one when there
    /// is no vault (so the socket still announces, as locked), which is
    /// closed at once: the pump stops watching it.
    fn vault_can(&self) -> tokio::sync::watch::Receiver<Vec<String>> {
        match self.engine.vault.as_ref() {
            Some(v) => v.watch_can(),
            None => tokio::sync::watch::channel(Vec::new()).1,
        }
    }

    /// The vault opening, locking, or what proves it changing, to watch; as
    /// the above when there is no vault.
    fn vault_turns(&self) -> tokio::sync::watch::Receiver<u64> {
        match self.engine.vault.as_ref() {
            Some(v) => v.watch_news(),
            None => tokio::sync::watch::channel(0).1,
        }
    }

    /// Sends the proof of the vault open here for this socket's nonce, when
    /// there is none on its way and it is not proved already; nothing when
    /// the vault is locked or has nothing to prove it by.
    fn prove(&self, link: &mpsc::UnboundedSender<Message>, proving: &mut Proving) {
        if proving.asked || proving.proven {
            return;
        }
        let (Some(nonce), Some(vault)) = (proving.nonce.as_deref(), self.engine.vault.as_ref()) else { return };
        let Some(made) = vault.proof(nonce) else { return };
        if link.send(Message::Text(made.message.as_str().into())).is_ok() {
            proving.asked = true;
            proving.password = made.password;
        }
    }

    /// The vault opened, locked, or what proves it changed: opened, the
    /// proof goes now; locked, tTerm hears that the keys closed here, and
    /// so does the page. Err when the page went.
    async fn vault_turned(&self, link: &mpsc::UnboundedSender<Message>, proving: &mut Proving) -> Result<(), ()> {
        if self.engine.vault.as_ref().map(|v| v.is_open()).unwrap_or(false) {
            self.prove(link, proving);
            return Ok(());
        }
        if proving.proven || proving.asked {
            proving.proven = false;
            proving.asked = false;
            proving.password = None;
            let _ = link.send(Message::Text(CLOSED.into()));
            self.to_page.send(Outgoing::Text(CLOSED.to_string())).await.map_err(|_| ())?;
        }
        Ok(())
    }

    /// tTerm's messages of the proof on this socket: its nonce (proved at
    /// once, with the vault open here), its word on the proof. Whether the
    /// message goes on to the page: all do, but a word that came after the
    /// vault locked meanwhile, which is answered with `vault.closed` again.
    fn heard_proof(&self, text: &str, link: &mpsc::UnboundedSender<Message>, proving: &mut Proving) -> bool {
        if !text.contains("\"vault.") {
            return true;
        }
        let Ok(msg) = serde_json::from_str::<Value>(text) else { return true };
        match msg.get("op").and_then(Value::as_str) {
            Some("vault.challenge") => {
                let nonce = msg.get("nonce").and_then(Value::as_str).unwrap_or_default().to_string();
                if proving.nonce.as_deref() != Some(nonce.as_str()) {
                    *proving = Proving { nonce: Some(nonce), ..Proving::default() };
                    self.prove(link, proving);
                }
                true
            }
            Some("vault.proven") => {
                proving.asked = false;
                if !self.engine.vault.as_ref().map(|v| v.is_open()).unwrap_or(false) {
                    let _ = link.send(Message::Text(CLOSED.into()));
                    return false;
                }
                proving.proven = true;
                true
            }
            Some("vault.unproven") => {
                proving.asked = false;
                // A password changed elsewhere: its old proof is not sent
                // again, and the page asks for the password.
                if msg.get("wrong") == Some(&Value::Bool(true)) {
                    if let (Some(sent), Some(vault)) = (proving.password.take(), self.engine.vault.as_ref()) {
                        vault.forget_password_proof(&sent);
                    }
                }
                eprintln!("tterm: tTerm did not take the proof of the keys open on the page's socket: {}", msg.get("error").cloned().unwrap_or(Value::Null));
                true
            }
            _ => true,
        }
    }

    /// The core's `vault.changed` (keys or locks changed, in a browser too):
    /// the engine reads its vault again, so what it can sign for, and so
    /// says, follows; then the message goes on to the page. Whether it was
    /// such a message (and so is on its way to the page already).
    fn vault_news(&self, text: &str) -> bool {
        if !text.contains("\"vault.changed\"") {
            return false;
        }
        let Ok(msg) = serde_json::from_str::<Value>(text) else { return false };
        if msg.get("op").and_then(Value::as_str) != Some("vault.changed") {
            return false;
        }
        let Some(vault) = self.engine.vault.clone() else { return false };
        let engine = self.engine.clone();
        let to_page = self.to_page.clone();
        let text = text.to_string();
        tokio::spawn(async move {
            vault.reload(&engine).await;
            let _ = to_page.send(Outgoing::Text(text)).await;
        });
        true
    }

    /// If `text` is a `vault.sign` from the core, the engine signs it with
    /// the vault's key and answers on this socket (`vault.signed`, or
    /// `vault.unable` when it cannot), and the message is not passed to the
    /// page. Whether it was such a message.
    fn maybe_sign(&self, text: &str, link: &mpsc::UnboundedSender<Message>) -> bool {
        let Ok(msg) = serde_json::from_str::<Value>(text) else { return false };
        if msg.get("op").and_then(Value::as_str) != Some("vault.sign") {
            return false;
        }
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let key = msg.get("key").and_then(Value::as_str).unwrap_or("");
        let alg = msg.get("alg").and_then(Value::as_str).unwrap_or("");
        let data = msg.get("data").and_then(Value::as_str).and_then(crate::crypto::from_b64u);
        let signed = match (self.engine.vault.as_ref(), data) {
            (Some(vault), Some(data)) => vault.sign(key, alg, &data),
            _ => None,
        };
        let answer = match signed {
            Some(sig) => json!({"op": "vault.signed", "id": id, "sig": crate::crypto::b64u(&sig)}),
            None => json!({"op": "vault.unable", "id": id}),
        };
        let _ = link.send(Message::Text(answer.to_string().into()));
        true
    }
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
