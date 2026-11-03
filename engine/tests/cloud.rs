//! Signed in (from 0.3.0): the engine against a tTerm Web of the checks' own,
//! on this computer. It answers as tTerm Web 0.1.6 does where the engine
//! needs it: the app's sign-in (`/api/auth/app/*`), which computer this is
//! (`/api/computers/this`), the state, notes, Sign out, and the page's
//! socket with a terminal of its own; from 0.4.0 the agents' hub too, where
//! the app's link connects (reach.rs). The checks act as the browser where
//! the person would: they allow the app, and bring the code back to the
//! engine's port on 127.0.0.1.
//!
//! What only the real tTerm Web can tell is checked against it by hand, and
//! in the app's window (see the checks of 0.3.0 in PROJECT.md).

#![cfg(feature = "cloud")]

mod common;

use common::{request, Page};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request as WsRequest, Response as WsResponse};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tterm_engine::account::{self, challenge_of, link_code, Host};
use tterm_engine::Engine;

// ------------------------------------------------------- the browser's app

#[derive(Default)]
struct FakeHost {
    opened: Mutex<Vec<String>>,
    key: Mutex<Option<String>>,
    /// How long the keychain takes, in milliseconds, as when it asks for
    /// the password: to keep a key, and to answer with the one it had.
    save_ms: AtomicU64,
    load_ms: AtomicU64,
    /// The keychain cannot be read, as when it stays locked.
    load_fails: std::sync::atomic::AtomicBool,
}

impl Host for FakeHost {
    fn open_url(&self, url: &str) -> Result<(), String> {
        self.opened.lock().unwrap().push(url.to_string());
        Ok(())
    }
    fn load_key(&self) -> Result<Option<String>, String> {
        let had = self.key.lock().unwrap().clone();
        std::thread::sleep(Duration::from_millis(self.load_ms.load(Ordering::SeqCst)));
        if self.load_fails.load(Ordering::SeqCst) {
            return Err("The keychain is locked.".into());
        }
        Ok(had)
    }
    fn save_key(&self, key: &str) -> Result<(), String> {
        std::thread::sleep(Duration::from_millis(self.save_ms.load(Ordering::SeqCst)));
        *self.key.lock().unwrap() = Some(key.to_string());
        Ok(())
    }
    fn delete_key(&self) -> Result<(), String> {
        *self.key.lock().unwrap() = None;
        Ok(())
    }
}

// -------------------------------------------------------- tTerm of the checks

#[derive(Default)]
struct Fake {
    grants: HashMap<String, String>,
    /// Device keys, and whether forgotten.
    devices: HashMap<String, bool>,
    /// Live sessions, with their device's key.
    sessions: HashMap<String, String>,
    machines: Vec<Value>,
    /// Keys tTerm refuses, as of a removed computer.
    removed: Vec<String>,
    computers_this: Vec<Value>,
    folders: Vec<Value>,
    notes: Vec<Value>,
    requests: Vec<(String, String, HashMap<String, String>)>,
    attaches: Vec<Value>,
    sockets: usize,
    signouts: Vec<String>,
    /// The next socket message is answered by closing with 4401.
    close_4401: bool,
    /// The session's cookie, as tTerm names it: `__Host-` on https.
    cookie: String,
    /// The page's socket is refused (403), as a proxy that lets no socket
    /// by would.
    no_sockets: bool,
    /// Requests that take their time, in milliseconds: by path, or by
    /// method and path ("POST /api/vault") for one method alone.
    slow: HashMap<String, u64>,
    /// So many saves of a note are refused (422) before they are taken.
    refuse_saves: usize,
    /// The photo, as it came: its type and its bytes (from 0.3.1).
    photo: Option<(String, Vec<u8>)>,
    /// The agents' hub (from 0.4.0): the hellos it heard, what it is to
    /// send to the computer, what the computer said and its terminals
    /// printed, and the links up now.
    hellos: Vec<Value>,
    to_agent: Vec<Value>,
    from_agent: Vec<Value>,
    printed: HashMap<u32, Vec<u8>>,
    links: usize,
    /// So many hellos are refused, as when the key is in use elsewhere.
    refuse_hellos: usize,
    /// The connected computer is removed now: told so, its key retired.
    remove_now: bool,
    /// Keys of another account's computers: no machine of this account's
    /// (409, as machines.this_computer says), and welcome at the hub, as
    /// that account's "work-mac".
    foreign: Vec<String>,
    /// The next request to a path is answered so, and with `{}`, once: tTerm
    /// in trouble, or a proxy's page in its place.
    fail_once: HashMap<String, u16>,
    /// The account's language (from 0.6.0), None while none is chosen.
    language: Option<String>,
    /// The vault (from 0.7.0): the object as GET /api/vault gives it, its
    /// pairings, the own-machines added, and what drives the socket's
    /// vault.sign.
    vault: Option<Value>,
    pairings: HashMap<String, Value>,
    own: Vec<Value>,
    reachable_ok: bool,
    principal_n: u32,
    /// The vault.sign requests the page socket sends, each once it hears a
    /// vault.can with its key: (id, fingerprint, alg, data b64u).
    sign_requests: Vec<(String, String, String, String)>,
    /// The vault.signed / vault.unable the engine answered over the socket,
    /// and the vault.can key lists the socket heard.
    signed: Vec<Value>,
    cans: Vec<Vec<String>>,
    /// What the socket is to send the engine next (vault.changed, …).
    push: Vec<Value>,
    /// The locks said used, the keys taken out of the vault, the locks
    /// added (POST /api/vault/locks), and a refusal for the next own machine.
    lock_used: Vec<String>,
    deleted_keys: Vec<String>,
    locks_added: usize,
    own_refuse: Option<(u16, String)>,
    /// The vault password (0.8.0) as the core keeps it: SHA-256 of the proof
    /// (never the proof), the wrap it hands out for the right one, and the
    /// wrong ones since the last right one; the bodies of POST /api/vault
    /// and of each PUT /api/vault/password, as tTerm got them.
    password_check: Option<[u8; 32]>,
    password_wrap: Option<String>,
    password_wrong: u32,
    vault_posted: Option<Value>,
    password_puts: Vec<Value>,
    /// Write to support with no session (0.8.0): the headers and the body
    /// of each, as tTerm got them, and its answer to the next one, if not
    /// that it went.
    support: Vec<(HashMap<String, String>, Vec<u8>)>,
    support_answer: Option<(u16, Value)>,
}

impl Fake {
    fn device_cookie(&self) -> String {
        account::device_cookie(&self.cookie)
    }
}

struct Cloud {
    base: String,
    port: u16,
    st: Arc<Mutex<Fake>>,
    task: tokio::task::JoinHandle<()>,
    /// Open connections, to drop them as a network does.
    drops: Arc<tokio::sync::watch::Sender<u64>>,
}

impl Cloud {
    async fn start() -> Cloud {
        Self::start_on(0, Arc::new(Mutex::new(Fake { cookie: "tterm-session".into(), ..Default::default() }))).await
    }

    async fn start_on(port: u16, st: Arc<Mutex<Fake>>) -> Cloud {
        common::room_for_files();
        let listener = TcpListener::bind(("127.0.0.1", port)).await.expect("a port");
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");
        let drops = Arc::new(tokio::sync::watch::channel(0u64).0);
        let (st2, base2, drops2) = (st.clone(), base.clone(), drops.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let (st, base, drops) = (st2.clone(), base2.clone(), drops2.clone());
                tokio::spawn(async move { serve(stream, st, base, drops).await });
            }
        });
        Cloud { base, port, st, task, drops }
    }

    /// The network goes: nothing answers at this address.
    fn stop(&self) {
        self.task.abort();
        self.drop_connections();
    }

    /// Every open connection drops, as when the network blinks.
    fn drop_connections(&self) {
        self.drops.send_modify(|n| *n += 1);
    }

    /// The person allows the app in the browser: the code it gets.
    fn allow(&self, challenge: &str) -> String {
        let code = account::random_token(32);
        self.st.lock().unwrap().grants.insert(code.clone(), challenge.to_string());
        code
    }

    fn hub(&self) -> String {
        format!("ws://127.0.0.1:{}/agent", self.port)
    }

    /// Every session ends, as eight hours away do.
    fn end_sessions(&self) {
        self.st.lock().unwrap().sessions.clear();
    }

    fn forget_devices(&self) {
        let mut st = self.st.lock().unwrap();
        for v in st.devices.values_mut() {
            *v = true;
        }
        st.sessions.clear();
    }

    fn count(&self, method: &str, path: &str) -> usize {
        self.st.lock().unwrap().requests.iter().filter(|(m, p, _)| m == method && p == path).count()
    }

    /// Something for the computer connected to the hub (from 0.4.0).
    fn to_agent(&self, msg: Value) {
        self.st.lock().unwrap().to_agent.push(msg);
    }

    /// What terminal `ch` on the computer printed, as text.
    fn printed(&self, ch: u32) -> String {
        String::from_utf8_lossy(self.st.lock().unwrap().printed.get(&ch).map(Vec::as_slice).unwrap_or(&[])).to_string()
    }

    fn heard(&self, t: &str) -> bool {
        self.st.lock().unwrap().from_agent.iter().any(|m| m["t"] == t)
    }

    fn links(&self) -> usize {
        self.st.lock().unwrap().links
    }
}

fn token() -> String {
    account::random_token(32)
}

fn cookie_of(headers: &HashMap<String, String>, name: &str) -> Option<String> {
    headers.get("cookie")?.split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
}

fn state_json(st: &Fake) -> Value {
    let mut machines = st.machines.clone();
    machines.push(json!({"id": "s1", "kind": "server", "name": "web-01", "online": true}));
    let folders: Vec<Value> = st
        .folders
        .iter()
        .map(|f| {
            let mut f = f.clone();
            let notes: Vec<Value> = st.notes.iter().filter(|n| n["folderId"] == f["id"]).cloned().collect();
            f["notes"] = json!(notes);
            f
        })
        .collect();
    json!({
        "version": "0.1.6",
        "me": {"id": "u1", "name": "Anna Fake", "firstName": "Anna", "initials": "AF", "theme": "dark", "projectTint": "badge", "plan": "free", "email": "anna@example.com", "language": st.language},
        "projects": [{"id": "p1", "name": "Personal", "code": "P", "color": "violet", "role": "owner", "personal": true, "own": true, "alone": true, "machines": machines, "folders": folders}],
        "terminals": [{"id": "11111111-1111-1111-1111-111111111111", "machineId": "s1", "machine": "web-01", "label": "P/web-01", "name": "1", "state": "open"}],
    })
}

async fn serve(mut stream: TcpStream, st: Arc<Mutex<Fake>>, base: String, drops: Arc<tokio::sync::watch::Sender<u64>>) {
    let mut gone = drops.subscribe();
    // Is it the page's socket? Looked at without taking it.
    let mut peek = vec![0u8; 8192];
    let head = loop {
        let n = match stream.peek(&mut peek).await {
            Ok(n) => n,
            Err(_) => return,
        };
        let text = String::from_utf8_lossy(&peek[..n]).to_string();
        if text.contains("\r\n\r\n") || n == 0 {
            break text;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    if head.to_ascii_lowercase().contains("upgrade: websocket") {
        if head.starts_with("GET /agent ") {
            return hub(stream, st, gone).await;
        }
        return socket(stream, st, gone).await;
    }
    loop {
        // The network gone first: a request on a connection that went with
        // it is not answered.
        let read = tokio::select! {
            biased;
            _ = gone.changed() => return,
            r = read_request(&mut stream) => r,
        };
        let Some((method, path, headers, body)) = read else { return };
        // A photo, given back as tTerm does: a JPEG, in a session.
        if method == "GET" && path.starts_with("/api/photos/") {
            let photo = {
                let mut st = st.lock().unwrap();
                st.requests.push((method.clone(), path.clone(), headers.clone()));
                let session = cookie_of(&headers, &st.cookie.clone());
                session.filter(|s| st.sessions.contains_key(s)).and(st.photo.clone())
            };
            let reply = match photo {
                Some((_, bytes)) => [format!("HTTP/1.1 200 OK\r\ncontent-type: image/jpeg\r\ncontent-length: {}\r\n\r\n", bytes.len()).into_bytes(), bytes].concat(),
                None => b"HTTP/1.1 404 X\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}".to_vec(),
            };
            if stream.write_all(&reply).await.is_err() {
                return;
            }
            continue;
        }
        let (status, answer) = answer(&st, &base, &method, &path, &headers, &body);
        // An answer made, and slow to arrive: as over a slow network.
        let slow = {
            let st = st.lock().unwrap();
            st.slow.get(&format!("{method} {path}")).or_else(|| st.slow.get(&path)).copied()
        };
        if let Some(ms) = slow {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
        let body = answer.to_string();
        let reply = format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}", body.len());
        if stream.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
    }
}

async fn read_request(stream: &mut TcpStream) -> Option<(String, String, HashMap<String, String>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, path) = (first.next()?.to_string(), first.next()?.to_string());
    let headers: HashMap<String, String> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    let length: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = buf[end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some((method, path, headers, body))
}

fn answer(st: &Arc<Mutex<Fake>>, base: &str, method: &str, path: &str, headers: &HashMap<String, String>, body: &[u8]) -> (u16, Value) {
    let mut st = st.lock().unwrap();
    st.requests.push((method.to_string(), path.to_string(), headers.clone()));
    if let Some(status) = st.fail_once.remove(path) {
        return (status, json!({}));
    }
    if method == "GET" && path.starts_with("/api/search?") {
        // tTerm's own finds: a command on its server, and a note.
        return (200, json!({"words": ["deploy"], "output": [], "recent": [], "more": {"notes": true},
            "commands": [{"terminalId": "11111111-1111-1111-1111-111111111111", "seq": 7, "command": "deploy api",
                "machineId": "s1", "machine": "web-01", "machineKind": "server", "startedAt": 1, "runs": 3, "lines": [], "hit": -1}],
            "notes": [{"noteId": "n-cloud", "title": "Deploy", "lines": [], "hit": -1}]}));
    }
    if (method, path) == ("PUT", "/api/me/photo") {
        let kind = headers.get("content-type").cloned().unwrap_or_default();
        if kind != "image/jpeg" {
            return (415, json!({"error": "The photo comes as a JPEG."}));
        }
        st.photo = Some((kind, body.to_vec()));
        return (200, json!({"photo": "/api/photos/u1?v=1"}));
    }
    // Write to support from someone not signed in (tTerm Web 0.1.25): the
    // address typed is where the answer goes, and no copy goes to it.
    if (method, path) == ("POST", "/api/support") && headers.get("cookie").is_none() {
        st.support.push((headers.clone(), body.to_vec()));
        if let Some(answer) = st.support_answer.take() {
            return answer;
        }
        let email = serde_json::from_slice::<Value>(body).ok().and_then(|b| b.get("email").and_then(Value::as_str).map(str::to_string));
        return (200, json!({"sent": true, "email": email, "copy": false}));
    }
    let body: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let text = |k: &str| body.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    match (method, path) {
        ("GET", "/health") => return (200, json!({"ok": true})),
        ("POST", "/api/auth/app/exchange") => {
            let ok = st.grants.remove(&text("code")).map(|c| c == challenge_of(&text("verifier"))).unwrap_or(false);
            if !ok {
                return (410, json!({"error": "This sign-in is over. Start again in tTerm with Sign in with your browser."}));
            }
            let (key, session) = (token(), token());
            st.devices.insert(key.clone(), false);
            st.sessions.insert(session.clone(), key.clone());
            let hub = format!("ws://{}/agent", base.trim_start_matches("http://"));
            return (200, json!({"key": key, "deviceId": "d-app", "label": "tTerm for Linux on box", "session": session, "cookie": st.cookie,
                "me": {"id": "u1", "name": "Anna Fake", "email": "anna@example.com"}, "hub": hub}));
        }
        ("POST", "/api/auth/app/session") => {
            let key = text("key");
            if st.devices.get(&key) != Some(&false) {
                return (410, json!({"error": "This app was signed out of tTerm. Sign in again with your browser."}));
            }
            let session = token();
            st.sessions.retain(|_, k| *k != key);
            st.sessions.insert(session.clone(), key);
            return (200, json!({"session": session, "cookie": st.cookie}));
        }
        ("POST", "/api/auth/signout") => {
            st.signouts.push(headers.get("cookie").cloned().unwrap_or_default());
            if let Some(key) = cookie_of(headers, &st.device_cookie()) {
                st.devices.insert(key, true);
            }
            if let Some(s) = cookie_of(headers, &st.cookie.clone()) {
                st.sessions.remove(&s);
            }
            return (200, json!({"signedOut": true}));
        }
        _ => {}
    }
    let signed = cookie_of(headers, &st.cookie.clone()).map(|s| st.sessions.contains_key(&s)).unwrap_or(false);
    if !signed {
        return (401, json!({"error": "Sign in to go on.", "signedOut": true}));
    }
    match (method, path) {
        ("POST", "/api/computers/this") => {
            st.computers_this.push(body.clone());
            let key = text("key");
            if st.removed.contains(&key) {
                return (410, json!({"error": "This computer's key stopped working when it was removed from tTerm Web: tTerm makes it a new one."}));
            }
            if st.foreign.contains(&key) {
                return (409, json!({"error": "This computer is in tTerm Web under another account."}));
            }
            if let Some(m) = st.machines.iter().find(|m| m["key"] == key.as_str()) {
                return (200, json!({"machine": {"id": m["id"], "name": m["name"], "projectId": "p1", "code": "P"}, "created": false}));
            }
            let id = uuid::Uuid::new_v4().to_string();
            st.machines.push(json!({"id": id, "kind": "computer", "name": text("name"), "online": false, "key": key}));
            (201, json!({"machine": {"id": id, "name": text("name"), "projectId": "p1", "code": "P"}, "created": true}))
        }
        ("GET", "/api/state") => (200, state_json(&st)),
        // ------------------------------------------------- the vault (0.7.0)
        ("GET", "/api/vault") => (200, json!({"vault": st.vault.clone()})),
        ("POST", "/api/vault") => {
            if st.vault.is_some() {
                return (409, json!({"error": "a vault exists already"}));
            }
            st.vault_posted = Some(body.clone());
            // With a password (0.8.0), or with a recovery code as tTerm for
            // Mac 0.7.x makes it: one of the two, not both.
            let with_code = body.get("recoverySalt").is_some() || body.get("recoveryWrap").is_some();
            if body["password"].is_object() == with_code {
                return (422, json!({"error": "A vault comes with a password or a recovery code."}));
            }
            let mut password = Value::Null;
            if body["password"].is_object() {
                match password_kept(&body["password"]) {
                    Ok((shown, check, wrap)) => {
                        (password, st.password_check, st.password_wrap, st.password_wrong) = (shown, Some(check), Some(wrap), 0);
                    }
                    Err(why) => return (422, json!({"error": why})),
                }
            }
            // A browser makes it with no lock (vault.py create_vault).
            let lock = &body["lock"];
            let locks = if lock.is_object() { json!([{"id": lock["id"], "kind": lock["kind"], "label": lock["label"], "wrap": lock["wrap"], "thisDevice": true}]) } else { json!([]) };
            let vault = json!({
                "id": text("id"),
                "prfSalt": "AAAA",
                "password": password,
                "recoveryAt": if with_code { json!("2026-11-02T10:00:00Z") } else { Value::Null },
                "recoverySalt": body.get("recoverySalt").cloned().unwrap_or(Value::Null),
                "recoveryWrap": body.get("recoveryWrap").cloned().unwrap_or(Value::Null),
                "locks": locks,
                "keys": [],
            });
            st.vault = Some(vault.clone());
            (201, json!({"vault": vault}))
        }
        // The password's proof for its wrap (0.8.0), as the core checks it:
        // against the SHA-256 it keeps, in constant time; 403 with the tries
        // left; after 10 wrong ones every try is paused, the right one too.
        ("POST", "/api/vault/password/open") => {
            if st.vault.is_none() {
                return (404, json!({"error": "This account has no vault."}));
            }
            let (Some(check), Some(wrap)) = (st.password_check, st.password_wrap.clone()) else {
                return (404, json!({"error": "This vault has no password."}));
            };
            if st.password_wrong >= 10 {
                return (429, json!({"error": "Too many wrong passwords.", "paused": true, "retryAt": "2026-11-02T13:00:00Z"}));
            }
            let auth = tterm_engine::crypto::from_b64u(&text("auth")).unwrap_or_default();
            if auth.len() == 32 && tterm_engine::crypto::same(&tterm_engine::crypto::password_check(&auth), &check) {
                st.password_wrong = 0;
                return (200, json!({"wrap": wrap}));
            }
            st.password_wrong += 1;
            (403, json!({"error": "That password does not open your vault.", "wrong": true, "left": 10 - st.password_wrong}))
        }
        // A new password in place of the one there is (or the first: the
        // recovery code is forgotten in the same step).
        ("PUT", "/api/vault/password") => {
            if st.vault.is_none() {
                return (404, json!({"error": "This account has no vault."}));
            }
            let (shown, check, wrap) = match password_kept(&body) {
                Ok(kept) => kept,
                Err(why) => return (422, json!({"error": why})),
            };
            st.password_puts.push(body.clone());
            (st.password_check, st.password_wrap, st.password_wrong) = (Some(check), Some(wrap), 0);
            let v = st.vault.as_mut().unwrap();
            v["password"] = shown;
            for gone in ["recoverySalt", "recoveryWrap", "recoveryAt"] {
                v[gone] = Value::Null;
            }
            (200, json!({"vault": st.vault.clone()}))
        }
        ("GET", "/api/vault/recovery") => match st.vault.as_ref() {
            Some(v) if v["recoveryWrap"].is_string() => (200, json!({"recoverySalt": v["recoverySalt"], "recoveryWrap": v["recoveryWrap"]})),
            Some(_) => (404, json!({"error": "This vault has no recovery code."})),
            None => (404, json!({"error": "This account has no vault."})),
        },
        ("POST", "/api/vault/locks") => {
            let Some(v) = st.vault.as_mut() else { return (404, json!({"error": "This account has no vault."})) };
            if body["kind"] != "app" && body["kind"] != "passkey" {
                return (422, json!({"error": "A lock is a passkey or the app."}));
            }
            let wrap_ok = tterm_engine::crypto::from_b64u(&text("wrap")).map(|w| w.len() == 60).unwrap_or(false);
            if !wrap_ok {
                return (422, json!({"error": "The wrap is not 60 bytes."}));
            }
            v["locks"].as_array_mut().unwrap().push(json!({"id": text("id"), "kind": text("kind"), "label": text("label"), "wrap": text("wrap"), "thisDevice": true}));
            st.locks_added += 1;
            (201, json!({"vault": st.vault.clone()}))
        }
        ("PUT", "/api/vault/recovery") => {
            if st.password_check.is_some() {
                return (409, json!({"error": "This vault has a password: it has no recovery code any more."}));
            }
            if let Some(v) = st.vault.as_mut() {
                v["recoverySalt"] = json!(text("recoverySalt"));
                v["recoveryWrap"] = json!(text("recoveryWrap"));
            }
            (204, Value::Null)
        }
        ("POST", "/api/vault/keys") => {
            let taken = st.vault.as_ref().map(|v| v["keys"].as_array().unwrap().iter().any(|k| k["fingerprint"] == text("fingerprint").as_str())).unwrap_or(false);
            if taken {
                return (409, json!({"error": "This key is in the vault already."}));
            }
            let key = json!({
                "id": text("id"), "name": text("name"), "type": text("type"),
                "publicKey": text("publicKey"), "fingerprint": text("fingerprint"),
                "sealed": text("sealed"), "source": text("source"), "servers": [],
            });
            if let Some(v) = st.vault.as_mut() {
                v["keys"].as_array_mut().unwrap().push(key);
            }
            (201, json!({"vault": st.vault.clone()}))
        }
        ("POST", "/api/machines/reachable") => (200, json!({"ok": st.reachable_ok})),
        ("POST", "/api/machines/own/line") => {
            st.principal_n += 1;
            let principal = format!("m-{}", st.principal_n);
            (200, json!({"principal": principal, "line": format!("cert-authority,principals=\"{principal}\" ssh-ed25519 AAAACA tterm-web ca-1")}))
        }
        ("POST", "/api/machines/own") => {
            if let Some((status, why)) = st.own_refuse.take() {
                return (status, json!({"error": why}));
            }
            let id = uuid::Uuid::new_v4().to_string();
            let m = json!({"id": id, "name": text("name"), "method": text("method"), "host": body["host"].clone(), "keyId": body["keyId"].clone(), "via": body["via"].clone(), "target": body["target"].clone(), "jump": body["jump"].clone()});
            st.own.push(m.clone());
            (201, json!({"machine": m}))
        }
        (m, p) if p.starts_with("/api/vault/pairings/") => {
            return vault_pairing(&mut st, m, p, &body);
        }
        ("POST", p) if p.starts_with("/api/vault/locks/") && p.ends_with("/used") => {
            let id = p.trim_start_matches("/api/vault/locks/").trim_end_matches("/used").to_string();
            let known = st.vault.as_ref().map(|v| v["locks"].as_array().unwrap().iter().any(|l| l["id"] == id.as_str())).unwrap_or(false);
            if !known {
                return (404, json!({"error": "no such lock"}));
            }
            st.lock_used.push(id);
            (204, Value::Null)
        }
        ("DELETE", p) if p.starts_with("/api/vault/keys/") => {
            let id = p.trim_start_matches("/api/vault/keys/").to_string();
            let Some(v) = st.vault.as_mut() else { return (404, json!({"error": "This account has no vault."})) };
            let keys = v["keys"].as_array_mut().unwrap();
            let before = keys.len();
            keys.retain(|k| k["id"] != id.as_str());
            if keys.len() == before {
                return (404, json!({"error": "No such key."}));
            }
            st.deleted_keys.push(id);
            (204, Value::Null)
        }
        ("POST", "/api/folders") => {
            let f = json!({"id": uuid::Uuid::new_v4().to_string(), "projectId": text("projectId"), "name": text("name"), "notes": []});
            st.folders.push(f.clone());
            (201, f)
        }
        ("POST", "/api/notes") => {
            let n = json!({"id": uuid::Uuid::new_v4().to_string(), "folderId": text("folderId"), "title": text("title"), "version": 1, "blocks": []});
            st.notes.push(n.clone());
            (201, n)
        }
        (m, p) if m == "GET" && p.starts_with("/api/notes/") => {
            let id = p.trim_start_matches("/api/notes/").to_string();
            match st.notes.iter().find(|n| n["id"] == id.as_str()) {
                Some(n) => (200, n.clone()),
                None => (404, json!({"error": "No such note."})),
            }
        }
        (m, p) if m == "PUT" && p.starts_with("/api/notes/") => {
            if st.refuse_saves > 0 {
                st.refuse_saves -= 1;
                return (422, json!({"error": "A block holds at most 20000 characters."}));
            }
            let id = p.trim_start_matches("/api/notes/").to_string();
            let Some(n) = st.notes.iter_mut().find(|n| n["id"] == id.as_str()) else { return (404, json!({"error": "No such note."})) };
            let (base, now) = (body["baseVersion"].as_i64().unwrap_or(0), n["version"].as_i64().unwrap_or(1));
            let mut blocks = if base < now { n["blocks"].as_array().cloned().unwrap_or_default() } else { Vec::new() };
            // As tTerm merges a save made from an older version: what is
            // new on either side stays (a block added both ways, once).
            for b in body["blocks"].as_array().cloned().unwrap_or_default() {
                if !blocks.iter().any(|x| x["id"] == b["id"]) {
                    blocks.push(b);
                }
            }
            if base >= now {
                n["title"] = body["title"].clone();
            }
            if n["blocks"] != json!(blocks) {
                n["blocks"] = json!(blocks);
                n["version"] = json!(now + 1);
            }
            (200, n.clone())
        }
        (m, p) => (200, json!({"method": m, "path": p})),
    }
}

/// A vault password as the core takes it (`POST /api/vault`'s `password`,
/// `PUT /api/vault/password`): a salt of 16 bytes, Argon2id within the
/// core's bounds, a proof of 32 bytes and a wrap of 60. What the vault then
/// shows of it (no wrap, no proof), and what the core keeps: the proof's
/// SHA-256, never the proof, and the wrap. Err with the core's sentence.
fn password_kept(p: &Value) -> Result<(Value, [u8; 32], String), String> {
    use tterm_engine::crypto;
    let bytes = |k: &str, n: usize| p[k].as_str().and_then(crypto::from_b64u).filter(|b| b.len() == n);
    let (Some(salt), Some(auth), Some(_)) = (bytes("salt", 16), bytes("auth", 32), bytes("wrap", 60)) else {
        return Err("The password's salt, proof or wrap is not as it should be.".into());
    };
    let kdf = &p["kdf"];
    let within = |k: &str, low: u64, high: u64| kdf[k].as_u64().map(|n| (low..=high).contains(&n)).unwrap_or(false);
    if kdf["alg"] != "argon2id" || !within("m", 65536, 1_048_576) || !within("t", 3, 10) || !within("p", 1, 4) {
        return Err("The password's settings are not ones tTerm takes.".into());
    }
    let shown = json!({"salt": crypto::b64u(&salt), "kdf": {"alg": "argon2id", "m": kdf["m"], "t": kdf["t"], "p": kdf["p"]}, "setAt": "2026-11-02T12:00:00Z"});
    Ok((shown, crypto::password_check(&auth), p["wrap"].as_str().unwrap_or_default().to_string()))
}

/// The vault's pairings in the fake tTerm: the new browser (the test) seeds
/// one waiting, with the commit and the pubB it will reveal; when the Mac
/// answers with pubA, the browser reveals pubB at once.
fn vault_pairing(st: &mut Fake, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let rest = path.trim_start_matches("/api/vault/pairings/");
    let (id, action) = rest.split_once('/').unwrap_or((rest, ""));
    let text = |k: &str| body.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    match (method, action) {
        ("GET", "") => match st.pairings.get(id) {
            Some(p) => (200, p.clone()),
            None => (404, json!({"error": "no such pairing"})),
        },
        ("POST", "answer") => {
            let Some(p) = st.pairings.get_mut(id) else { return (404, json!({"error": "no such pairing"})) };
            // Once only, as the core: from waiting.
            if p["state"] != "waiting" {
                return (409, json!({"error": "This request is not at that step."}));
            }
            p["pubA"] = json!(text("pubA"));
            p["state"] = json!("answered");
            // The browser reveals its pubB as soon as it has pubA.
            if let Some(reveal) = p.get("_pubB").cloned() {
                p["pubB"] = reveal;
                p["state"] = json!("revealed");
            }
            (204, Value::Null)
        }
        ("POST", "approve") => {
            let Some(p) = st.pairings.get_mut(id) else { return (404, json!({"error": "no such pairing"})) };
            if p["state"] != "revealed" {
                return (409, json!({"error": "This request is not at that step."}));
            }
            p["sealed"] = json!(text("sealed"));
            p["state"] = json!("approved");
            (204, Value::Null)
        }
        ("POST", "deny") => {
            if let Some(p) = st.pairings.get_mut(id) {
                p["state"] = json!("denied");
            }
            (204, Value::Null)
        }
        _ => (404, json!({"error": "no such pairing request"})),
    }
}

/// The page's socket: a terminal of its own, 11111111-…, that greets and
/// echoes the keys, numbering what it sends.
#[allow(clippy::result_large_err)]
async fn socket(stream: TcpStream, st: Arc<Mutex<Fake>>, mut gone: tokio::sync::watch::Receiver<u64>) {
    let st2 = st.clone();
    let signed_was = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let signed_in = signed_was.clone();
    let check = move |req: &WsRequest, resp: WsResponse| -> Result<WsResponse, ErrorResponse> {
        let headers: HashMap<String, String> = req.headers().iter().map(|(k, v)| (k.as_str().to_ascii_lowercase(), v.to_str().unwrap_or("").to_string())).collect();
        let fake = st2.lock().unwrap();
        let signed = cookie_of(&headers, &fake.cookie).map(|s| fake.sessions.contains_key(&s)).unwrap_or(false);
        if fake.no_sockets || headers.get("origin").map(|o| !o.starts_with("http://127.0.0.1:")).unwrap_or(true) {
            let mut refused = ErrorResponse::new(Some("no".into()));
            *refused.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::FORBIDDEN;
            return Err(refused);
        }
        signed_in.store(signed, std::sync::atomic::Ordering::SeqCst);
        Ok(resp)
    };
    let Ok(ws) = tokio_tungstenite::accept_hdr_async(stream, check).await else { return };
    st.lock().unwrap().sockets += 1;
    let (mut sink, mut source) = ws.split();
    if !signed_was.load(std::sync::atomic::Ordering::SeqCst) {
        // As page.py: a session that ended is told so on the open socket.
        let _ = sink.send(Message::Close(Some(CloseFrame { code: CloseCode::from(4401), reason: "signed out".into() }))).await;
        return;
    }
    let mut seq: HashMap<u32, u64> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    loop {
        let message = tokio::select! {
            m = source.next() => m,
            _ = gone.changed() => return,
            // What the test has for the engine (vault.changed, …).
            _ = tick.tick() => {
                let push = std::mem::take(&mut st.lock().unwrap().push);
                for m in push {
                    let _ = sink.send(Message::Text(m.to_string().into())).await;
                }
                continue;
            }
        };
        let Some(Ok(message)) = message else { return };
        if std::mem::take(&mut st.lock().unwrap().close_4401) {
            let _ = sink.send(Message::Close(Some(CloseFrame { code: CloseCode::from(4401), reason: "signed out".into() }))).await;
            return;
        }
        match message {
            Message::Text(text) => {
                let msg: Value = serde_json::from_str(text.as_str()).unwrap_or(Value::Null);
                let ch = msg["ch"].as_u64().unwrap_or(0) as u32;
                // The vault over the socket (0.7.0): the engine announces
                // which keys it can sign for, and answers a request to sign.
                if msg["op"] == "vault.can" {
                    let keys: Vec<String> = msg["keys"].as_array().into_iter().flatten().filter_map(|k| k.as_str().map(str::to_string)).collect();
                    // Ask it to sign, each request once, when it can sign
                    // for the key.
                    let asks: Vec<(String, String, String, String)> = {
                        let mut f = st.lock().unwrap();
                        f.cans.push(keys.clone());
                        let (now, later): (Vec<_>, Vec<_>) = std::mem::take(&mut f.sign_requests).into_iter().partition(|(_, fp, _, _)| keys.contains(fp));
                        f.sign_requests = later;
                        now
                    };
                    for (id, fp, alg, data) in asks {
                        let ask = json!({"op": "vault.sign", "id": id, "key": fp, "alg": alg, "data": data, "machine": "web-01", "keyName": "id_ed25519"});
                        let _ = sink.send(Message::Text(ask.to_string().into())).await;
                    }
                    continue;
                }
                if msg["op"] == "vault.signed" || msg["op"] == "vault.unable" {
                    st.lock().unwrap().signed.push(msg.clone());
                    continue;
                }
                if msg["op"] == "attach" {
                    st.lock().unwrap().attaches.push(msg.clone());
                    if msg["id"] != "11111111-1111-1111-1111-111111111111" {
                        let _ = sink.send(Message::Text(json!({"op": "gone", "ch": ch, "terminal": null}).to_string().into())).await;
                        continue;
                    }
                    let after = msg["after"].as_u64();
                    let terminal = json!({"id": "11111111-1111-1111-1111-111111111111", "machineId": "s1", "state": "open"});
                    let _ = sink.send(Message::Text(json!({"op": "attached", "ch": ch, "terminal": terminal, "resumed": after.is_some()}).to_string().into())).await;
                    let n = seq.entry(ch).or_insert(after.unwrap_or(0));
                    *n += 1;
                    let _ = sink.send(Message::Binary(frame(ch, *n, format!("hello on {ch}\r\n").as_bytes()).into())).await;
                }
            }
            Message::Binary(keys) => {
                if keys.len() >= 5 && keys[0] == 2 {
                    let ch = u32::from_be_bytes([keys[1], keys[2], keys[3], keys[4]]);
                    let n = seq.entry(ch).or_insert(0);
                    *n += 1;
                    let _ = sink.send(Message::Binary(frame(ch, *n, &keys[5..]).into())).await;
                }
            }
            Message::Close(_) => return,
            _ => {}
        }
    }
}

/// What tTerm Web says to a computer it removed (agents.REMOVED).
const REMOVED: &str = "This computer was removed from tTerm Web. To connect it again: Add a machine, then Computer.";

/// The agents' hub, as tterm/core/agents.py speaks it, for the app's link
/// (from 0.4.0): a computer it knows by its key is welcome; it answers the
/// signs of life, sends what the checks put in `to_agent`, keeps what its
/// terminals print, and removes the computer when told to.
async fn hub(stream: TcpStream, st: Arc<Mutex<Fake>>, mut gone: tokio::sync::watch::Receiver<u64>) {
    let Ok(ws) = tokio_tungstenite::accept_async(stream).await else { return };
    let (mut sink, mut source) = ws.split();
    let hello = match tokio::time::timeout(Duration::from_secs(5), source.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => serde_json::from_str::<Value>(text.as_str()).unwrap_or(Value::Null),
        _ => return,
    };
    let key = hello["key"].as_str().unwrap_or("").to_string();
    let answer = {
        let mut f = st.lock().unwrap();
        f.hellos.push(hello.clone());
        if f.refuse_hellos > 0 {
            f.refuse_hellos -= 1;
            json!({"t": "error", "error": "This computer is already connected to tTerm Web: its key is in use by another agent. Stop that one first.", "revoked": false})
        } else if f.removed.contains(&key) {
            json!({"t": "error", "error": REMOVED, "revoked": true, "forget": true})
        } else if f.foreign.contains(&key) {
            f.links += 1;
            json!({"t": "welcome", "name": "work-mac"})
        } else if let Some(m) = f.machines.iter_mut().find(|m| m["key"] == key.as_str()) {
            m["online"] = json!(true);
            let name = m["name"].clone();
            f.links += 1;
            json!({"t": "welcome", "name": name})
        } else {
            json!({"t": "error", "error": "This computer is not in tTerm Web, or it was removed.", "revoked": true})
        }
    };
    let welcome = answer["t"] == "welcome";
    let _ = sink.send(Message::Text(answer.to_string().into())).await;
    if !welcome {
        let _ = sink.close().await;
        return;
    }
    let gone_now = |st: &Arc<Mutex<Fake>>| {
        let mut f = st.lock().unwrap();
        f.links = f.links.saturating_sub(1);
        if let Some(m) = f.machines.iter_mut().find(|m| m["key"] == key.as_str()) {
            m["online"] = json!(false);
        }
    };
    loop {
        let (out, remove) = {
            let mut f = st.lock().unwrap();
            (std::mem::take(&mut f.to_agent), std::mem::take(&mut f.remove_now))
        };
        for m in out {
            let message = match m.get("keys").and_then(Value::as_str) {
                // Keys for a terminal: 2, the channel, the bytes.
                Some(keys) => {
                    let mut b = vec![2u8];
                    b.extend_from_slice(&(m["ch"].as_u64().unwrap_or(0) as u32).to_be_bytes());
                    b.extend_from_slice(keys.as_bytes());
                    Message::Binary(b.into())
                }
                None => Message::Text(m.to_string().into()),
            };
            let _ = sink.send(message).await;
        }
        if remove {
            st.lock().unwrap().removed.push(key.clone());
            gone_now(&st);
            let _ = sink.send(Message::Text(json!({"t": "error", "error": REMOVED, "revoked": true, "forget": true}).to_string().into())).await;
            let _ = sink.close().await;
            return;
        }
        let message = tokio::select! {
            m = source.next() => m,
            _ = tokio::time::sleep(Duration::from_millis(20)) => continue,
            _ = gone.changed() => {
                gone_now(&st);
                return;
            }
        };
        match message {
            Some(Ok(Message::Text(text))) => {
                let msg: Value = serde_json::from_str(text.as_str()).unwrap_or(Value::Null);
                if msg["t"] == "hb" {
                    let _ = sink.send(Message::Text(json!({"t": "hb"}).to_string().into())).await;
                } else {
                    st.lock().unwrap().from_agent.push(msg);
                }
            }
            Some(Ok(Message::Binary(b))) if b.len() >= 5 && b[0] == 1 => {
                let ch = u32::from_be_bytes([b[1], b[2], b[3], b[4]]);
                st.lock().unwrap().printed.entry(ch).or_default().extend_from_slice(&b[5..]);
            }
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                gone_now(&st);
                return;
            }
            _ => {}
        }
    }
}

fn frame(ch: u32, seq: u64, data: &[u8]) -> Vec<u8> {
    let mut f = vec![1u8];
    f.extend_from_slice(&ch.to_be_bytes());
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(data);
    f
}

// ---------------------------------------------------------------- helpers

struct App {
    engine: Arc<Engine>,
    host: Arc<FakeHost>,
    env: PathBuf,
    dir: PathBuf,
}

async fn app(cloud: &Cloud) -> App {
    let dir = common::data_dir();
    let env = dir.join("home").join(".tterm-web").join("env");
    app_in(cloud, dir, env, Arc::new(FakeHost::default())).await
}

async fn app_in(cloud: &Cloud, dir: PathBuf, env: PathBuf, host: Arc<FakeHost>) -> App {
    let keeper = common::TestKeeper::new();
    let engine = Engine::with_cloud(&dir, &cloud.base, host.clone(), keeper, &env).expect("engine");
    engine.start_background();
    App { engine, host, env, dir }
}

/// What the browser was sent to.
fn link_of(url: &str) -> HashMap<String, String> {
    let query = url.split_once('?').unwrap().1;
    query.split('&').filter_map(|p| p.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// The browser, back on the engine's port: the page it gets.
async fn come_back(port: &str, query: &str) -> (u16, String) {
    come_back_as(port, query, &format!("127.0.0.1:{port}")).await
}

async fn come_back_as(port: &str, query: &str, host: &str) -> (u16, String) {
    let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).await.expect("the engine waits");
    s.write_all(format!("GET /signed-in?{query} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    let status = out.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, out)
}

async fn until(secs: u64, mut done: impl FnMut() -> bool) -> bool {
    let end = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < end {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    done()
}

async fn link_state(e: &Arc<Engine>) -> Value {
    request(e, "GET", "/api/auth/link", Value::Null).await.1
}

/// Signs the app in, as a person would: Sign in with your browser, Allow.
async fn sign_in(cloud: &Cloud, a: &App) {
    let (status, started) = request(&a.engine, "POST", "/api/auth/link", json!({})).await;
    assert_eq!(status, 200, "{started}");
    let url = a.host.opened.lock().unwrap().last().cloned().expect("the browser opened");
    let link = link_of(&url);
    assert_eq!(started["code"], link_code(&link["challenge"]));
    let code = cloud.allow(&link["challenge"]);
    let (status, page) = come_back(&link["port"], &format!("code={code}&state={}", link["state"])).await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("You are in"), "{page}");
    let mut last = Value::Null;
    for _ in 0..100 {
        last = link_state(&a.engine).await;
        if last["state"] != "waiting" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(last["state"], "done", "{last}");
}

/// The device's key in the keychain's record.
fn kept_key(a: &App) -> String {
    let record = a.host.key.lock().unwrap().clone().expect("signed in");
    let v: Value = serde_json::from_str(&record).expect("a record");
    v["key"].as_str().unwrap().to_string()
}

async fn state(e: &Arc<Engine>) -> Value {
    let (status, s) = request(e, "GET", "/api/state", Value::Null).await;
    assert_eq!(status, 200, "{s}");
    s
}

fn here_machine(s: &Value) -> Value {
    s["projects"][0]["machines"].as_array().unwrap().iter().find(|m| m["here"] == true).cloned().unwrap_or(Value::Null)
}

// ----------------------------------------------------------------- checks

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_app_signs_in_with_the_browser() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    // Before: this computer only, and the welcome of the first start.
    let before = state(&a.engine).await;
    assert_eq!(before["local"], true);
    assert_eq!(before["welcome"], true);
    let url_count = a.host.opened.lock().unwrap().len();
    assert_eq!(url_count, 0);

    let (_, started) = request(&a.engine, "POST", "/api/auth/link", json!({})).await;
    let url = a.host.opened.lock().unwrap()[0].clone();
    assert!(url.starts_with(&format!("{}/connect?app=", cloud.base)), "{url}");
    let link = link_of(&url);
    assert_eq!(link["challenge"].len(), 43);
    assert!(link["state"].len() >= 16);
    assert!(link["port"].parse::<u16>().unwrap() >= 1024);
    assert!(!link["name"].is_empty());
    assert_eq!(started["code"].as_str().unwrap().len(), 7);
    assert_eq!(link_state(&a.engine).await["state"], "waiting");

    // Open the page again: the same sign-in, the same code.
    let (_, again) = request(&a.engine, "POST", "/api/auth/link", json!({"again": true})).await;
    assert_eq!(again["code"], started["code"]);
    assert_eq!(a.host.opened.lock().unwrap().len(), 2);
    assert_eq!(a.host.opened.lock().unwrap()[1], url);

    let code = cloud.allow(&link["challenge"]);
    let (status, page) = come_back(&link["port"], &format!("code={code}&state={}", link["state"])).await;
    assert_eq!(status, 200);
    assert!(page.contains("You are in") && page.contains("Content-Security-Policy: default-src 'none'"), "{page}");
    assert!(until(5, || a.host.key.lock().unwrap().is_some()).await, "the key is in the keychain");
    let mut s = Value::Null;
    for _ in 0..100 {
        s = link_state(&a.engine).await;
        if s["state"] == "done" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(s["state"], "done");

    // The computer's own key went to ~/.tterm-web/env, in the agent's
    // format, and tTerm made it a machine in Personal.
    let env = std::fs::read_to_string(&a.env).expect("the agent's file");
    assert!(env.starts_with(&format!("TTERM_HUB={}\n", cloud.hub())), "{env}");
    let key = env.lines().find_map(|l| l.strip_prefix("TTERM_KEY=")).unwrap().to_string();
    assert!(env.contains(&format!("TTERM_TOKEN={key}\n")));
    let sent = cloud.st.lock().unwrap().computers_this.clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["key"], key.as_str());
    assert_eq!(sent[0].get("app"), None, "no agent's version for tTerm to show");

    // The page now: tTerm's, with this computer marked and online.
    let s = state(&a.engine).await;
    assert_eq!(s["app"], true);
    assert_eq!(s["offline"], false);
    assert_eq!(s.get("local"), None);
    assert_eq!(s.get("welcome"), None);
    assert_eq!(s["me"]["email"], "anna@example.com");
    let here = here_machine(&s);
    assert_eq!(here["online"], true);
    let here_id = here["id"].as_str().unwrap().to_string();
    let machines = cloud.st.lock().unwrap().machines.clone();
    assert_eq!(here_id, machines[0]["id"].as_str().unwrap());
    // A terminal on it runs here, under that machine.
    let (status, t) = request(&a.engine, "POST", "/api/terminals", json!({"machineId": here_id, "cols": 80, "rows": 24})).await;
    assert_eq!(status, 201, "{t}");
    assert_eq!(t["machineId"], here_id.as_str());
    assert_eq!(cloud.count("POST", "/api/terminals"), 0, "not to tTerm");
    let s = state(&a.engine).await;
    let ids: Vec<&str> = s["terminals"].as_array().unwrap().iter().filter_map(|t| t["id"].as_str()).collect();
    assert!(ids.contains(&t["id"].as_str().unwrap()) && ids.contains(&"11111111-1111-1111-1111-111111111111"), "{ids:?}");
    // The browser's code was used once: the port is closed.
    assert!(TcpStream::connect(format!("127.0.0.1:{}", link["port"])).await.is_err());
    // A new start: signed in, from the keychain.
    let b = app_in(&cloud, a.dir.clone(), a.env.clone(), a.host.clone()).await;
    let s = state(&b.engine).await;
    assert_eq!(s["app"], true, "{s}");
    assert_eq!(here_machine(&s)["id"], here_id.as_str());
    assert_eq!(cloud.st.lock().unwrap().machines.len(), 1, "the same computer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_this_sign_ins_return_counts() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    request(&a.engine, "POST", "/api/auth/link", json!({})).await;
    let link = link_of(&a.host.opened.lock().unwrap()[0]);
    let code = cloud.allow(&link["challenge"]);
    // Another state, another host, another path: nothing done.
    let (status, page) = come_back(&link["port"], &format!("code={code}&state=AAAAAAAAAAAAAAAAAAAAAAAA")).await;
    assert_eq!(status, 400);
    assert!(page.contains("not for this sign-in"), "{page}");
    let (status, _) = come_back_as(&link["port"], &format!("code={code}&state={}", link["state"]), "evil.example:80").await;
    assert_eq!(status, 421);
    assert_eq!(link_state(&a.engine).await["state"], "waiting");
    // The same with Cancel in the browser.
    let (status, page) = come_back(&link["port"], &format!("error=cancelled&state={}", link["state"])).await;
    assert_eq!(status, 200);
    assert!(page.contains("Signing in was cancelled"), "{page}");
    assert_eq!(link_state(&a.engine).await["state"], "cancelled");
    assert!(a.host.key.lock().unwrap().is_none());
    assert_eq!(cloud.count("POST", "/api/auth/app/exchange"), 0);

    // A code that does not go with the secret: refused, said in both windows.
    request(&a.engine, "POST", "/api/auth/link", json!({})).await;
    let link = link_of(&a.host.opened.lock().unwrap()[1]);
    let wrong = cloud.allow(&challenge_of("another secret entirely, not this app's"));
    let (status, page) = come_back(&link["port"], &format!("code={wrong}&state={}", link["state"])).await;
    assert_eq!(status, 200);
    assert!(page.contains("Signing in did not work") && page.contains("This sign-in is over"), "{page}");
    let s = link_state(&a.engine).await;
    assert_eq!(s["state"], "failed");
    assert!(s["error"].as_str().unwrap().contains("This sign-in is over"), "{s}");

    // Cancel in the app: nothing waits any more.
    request(&a.engine, "POST", "/api/auth/link", json!({})).await;
    let link = link_of(&a.host.opened.lock().unwrap()[2]);
    let (status, _) = request(&a.engine, "DELETE", "/api/auth/link", Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(link_state(&a.engine).await["state"], "none");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(TcpStream::connect(format!("127.0.0.1:{}", link["port"])).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_machine_is_not_this_computer() {
    // Neither this computer's own machine nor tTerm's: no terminal here,
    // no page of it, and an answer, not a wait.
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    let other = uuid::Uuid::new_v4().to_string();
    let answered = tokio::time::timeout(Duration::from_secs(5), request(&a.engine, "POST", "/api/terminals", json!({"machineId": other, "cols": 80, "rows": 24}))).await;
    assert_eq!(answered.expect("answered").0, 404);
    let answered = tokio::time::timeout(Duration::from_secs(5), request(&a.engine, "GET", &format!("/api/machines/{other}"), Value::Null)).await;
    assert_eq!(answered.expect("answered").0, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_welcome_until_later() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    assert_eq!(state(&a.engine).await["welcome"], true);
    let (status, _) = request(&a.engine, "POST", "/api/app/welcome", json!({"seen": true})).await;
    assert_eq!(status, 204);
    assert_eq!(state(&a.engine).await.get("welcome"), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_go_to_tterm_in_the_apps_session() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    let (status, got) = request(&a.engine, "GET", "/api/account", Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(got, json!({"method": "GET", "path": "/api/account"}));
    let (status, got) = request(&a.engine, "PATCH", "/api/me", json!({"theme": "light"})).await;
    assert_eq!(status, 200);
    assert_eq!(got["method"], "PATCH");
    {
        let st = cloud.st.lock().unwrap();
        let (_, _, h) = st.requests.iter().rev().find(|(m, p, _)| m == "PATCH" && p == "/api/me").unwrap();
        assert_eq!(h.get("x-tterm").map(String::as_str), Some("1"));
        assert_eq!(h.get("origin"), Some(&cloud.base));
    }
    // What the page asks by itself says so to tTerm.
    let r = tterm_engine::api::handle_with(&a.engine, "GET", "/api/state", &[], tterm_engine::api::Flags { background: true, ..Default::default() }).await;
    assert_eq!(r.status, 200);
    {
        let st = cloud.st.lock().unwrap();
        let (_, _, h) = st.requests.iter().rev().find(|(m, p, _)| m == "GET" && p == "/api/state").unwrap();
        assert_eq!(h.get("x-tterm-background").map(String::as_str), Some("1"));
    }
    // A session that ended is renewed with the key, once for all.
    cloud.end_sessions();
    let sessions_before = cloud.count("POST", "/api/auth/app/session");
    let (s1, s2) = tokio::join!(request(&a.engine, "GET", "/api/one", Value::Null), request(&a.engine, "GET", "/api/two", Value::Null));
    assert_eq!((s1.0, s2.0), (200, 200), "{s1:?} {s2:?}");
    assert_eq!(cloud.count("POST", "/api/auth/app/session"), sessions_before + 1);
    // Machines and projects are tTerm's; this computer stays in the app.
    let here = here_machine(&state(&a.engine).await)["id"].as_str().unwrap().to_string();
    let (status, _) = request(&a.engine, "DELETE", &format!("/api/machines/{here}"), Value::Null).await;
    assert_eq!(status, 403);
    let (status, _) = request(&a.engine, "DELETE", "/api/machines/s1", Value::Null).await;
    assert_eq!(status, 200);
}

/// Write to support before signing in (0.8.0, the page of tTerm Web 0.1.25):
/// the page's message goes to tTerm as it is, with the header the core
/// wants and no session, Origin or background mark, and tTerm's answer comes
/// back as it is, its refusals too; with tTerm out of reach, 503 and words of
/// the engine's, so the page gives support's address. Signed in, it goes in
/// the app's session, as the rest of /api/* does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_to_support_before_signing_in_goes_to_tterm_as_it_is() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    let raw = "{\"text\":\"Не  открывается\\nтерминал 🙂\",\"details\":\"tTerm for Mac 0.8.0 · macOS · not signed in\",  \"email\":\"anna@example.com\"}";
    let r = tterm_engine::api::handle(&a.engine, "POST", "/api/support", raw.as_bytes()).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.content_type, "application/json");
    assert_eq!(serde_json::from_slice::<Value>(&r.body).unwrap(), json!({"sent": true, "email": "anna@example.com", "copy": false}));
    {
        let st = cloud.st.lock().unwrap();
        assert_eq!(st.support.len(), 1);
        let (h, body) = &st.support[0];
        assert_eq!(body.as_slice(), raw.as_bytes(), "the body as the page wrote it");
        assert_eq!(h.get("x-tterm").map(String::as_str), Some("1"));
        assert_eq!(h.get("content-type").map(String::as_str), Some("application/json"));
        for none in ["origin", "cookie", "x-tterm-background"] {
            assert!(!h.contains_key(none), "{none}: {h:?}");
        }
    }
    // tTerm's refusals, as it gave them: the limit an hour, its words on
    // what it cannot take, an email that did not go.
    for (status, answer) in [
        (429, json!({"error": "Three messages an hour from one network: write again later, or to support@tterm.net."})),
        (422, json!({"error": "This does not look like an email address."})),
        (503, json!({"error": "The message did not go. Write to support@tterm.net."})),
    ] {
        cloud.st.lock().unwrap().support_answer = Some((status, answer.clone()));
        let (got, back) = request(&a.engine, "POST", "/api/support", json!({"text": "Hi", "details": null, "email": "a@b.c"})).await;
        assert_eq!((got, back), (status, answer));
    }
    assert_eq!(cloud.st.lock().unwrap().support.len(), 4);
    // Signed in: in the app's session, with the rest.
    sign_in(&cloud, &a).await;
    let (status, got) = request(&a.engine, "POST", "/api/support", json!({"text": "Hi", "details": null})).await;
    assert_eq!((status, got), (200, json!({"method": "POST", "path": "/api/support"})));
    {
        let st = cloud.st.lock().unwrap();
        assert_eq!(st.support.len(), 4, "not as someone not signed in");
        let (_, _, h) = st.requests.iter().rev().find(|(m, p, _)| m == "POST" && p == "/api/support").unwrap();
        assert!(h.get("cookie").map(|c| c.contains("tterm-session=")).unwrap_or(false), "{h:?}");
        assert_eq!(h.get("origin"), Some(&cloud.base));
    }
    // Signed out, with tTerm out of reach: the engine's words, 503.
    let (status, _) = request(&a.engine, "POST", "/api/auth/signout", json!({})).await;
    assert_eq!(status, 200);
    cloud.stop();
    let (status, got) = request(&a.engine, "POST", "/api/support", json!({"text": "Hi", "details": null, "email": "a@b.c"})).await;
    assert_eq!(status, 503, "{got}");
    assert_eq!(got["error"], tterm_engine::cloud_api::OFFLINE);
}

/// The language (0.6.0): chosen before signing in, kept on this computer and
/// shown while the account has none; chosen signed in, sent to tTerm and
/// kept here too; the account's, once it has one, taken here; what the app
/// says follows it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_language_is_the_accounts_and_kept_here() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    let mut said = a.engine.language.subscribe();
    let (status, _) = request(&a.engine, "PATCH", "/api/me", json!({"language": "de"})).await;
    assert_eq!(status, 204);
    assert!(said.has_changed().unwrap() && *said.borrow_and_update() == "de");
    let me = state(&a.engine).await["me"].clone();
    assert_eq!(me["language"], "de", "{me}");
    assert!(me.get("systemLanguage").is_some(), "{me}");
    let (status, _) = request(&a.engine, "PATCH", "/api/me", json!({"language": "klingon"})).await;
    assert_eq!(status, 422);
    sign_in(&cloud, &a).await;
    // The account has none yet: the one chosen here.
    assert_eq!(state(&a.engine).await["me"]["language"], "de");
    let (status, _) = request(&a.engine, "PATCH", "/api/me", json!({"language": "fr"})).await;
    assert_eq!(status, 200);
    assert_eq!(a.engine.settings.lock().unwrap().language.as_deref(), Some("fr"), "kept here too");
    assert_eq!(*said.borrow_and_update(), "fr");
    // tTerm refuses it: not kept here.
    cloud.st.lock().unwrap().fail_once.insert("/api/me".into(), 500);
    let (status, _) = request(&a.engine, "PATCH", "/api/me", json!({"language": "ja"})).await;
    assert_eq!(status, 500);
    assert_eq!(a.engine.settings.lock().unwrap().language.as_deref(), Some("fr"));
    // Chosen elsewhere, in the account: taken here, and said in it.
    cloud.st.lock().unwrap().language = Some("pt-BR".into());
    assert_eq!(state(&a.engine).await["me"]["language"], "pt-BR");
    assert_eq!(a.engine.settings.lock().unwrap().language.as_deref(), Some("pt-BR"));
    assert_eq!(*said.borrow_and_update(), "pt-BR");
    assert_eq!(a.engine.language_now(), "pt-BR");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forgotten_device_signs_out_here() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    let here = here_machine(&state(&a.engine).await)["id"].as_str().unwrap().to_string();
    let (_, t) = request(&a.engine, "POST", "/api/terminals", json!({"machineId": here, "cols": 80, "rows": 24})).await;
    cloud.forget_devices();
    let (status, got) = request(&a.engine, "GET", "/api/account", Value::Null).await;
    assert_eq!(status, 401, "the page starts over");
    assert_eq!(got["signedOut"], true, "as the page reads a session that ended: {got}");
    assert!(a.host.key.lock().unwrap().is_none(), "the key is gone from the keychain");
    assert!(!a.dir.join("account.json").exists());
    assert!(!a.dir.join("cloud-state.json").exists());
    let s = state(&a.engine).await;
    assert_eq!(s["local"], true, "this computer only, as before signing in");
    // Its terminals stay, on this computer's own machine again.
    let local = s["projects"][0]["machines"][0]["id"].as_str().unwrap().to_string();
    let listed = s["terminals"].as_array().unwrap().iter().find(|x| x["id"] == t["id"]).cloned().unwrap();
    assert_eq!(listed["machineId"], local.as_str());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_out_forgets_the_key_in_tterm_too() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    let key = kept_key(&a);
    let (status, got) = request(&a.engine, "POST", "/api/auth/signout", json!({})).await;
    assert_eq!(status, 200);
    assert_eq!(got["signedOut"], true);
    let signouts = cloud.st.lock().unwrap().signouts.clone();
    assert_eq!(signouts.len(), 1);
    assert!(signouts[0].contains(&format!("tterm-device={key}")) && signouts[0].contains("tterm-session="), "{signouts:?}");
    assert_eq!(cloud.st.lock().unwrap().devices.get(&key), Some(&true));
    assert!(a.host.key.lock().unwrap().is_none());
    assert_eq!(state(&a.engine).await["local"], true);
    // The agent's file stays: it is the computer's, not the account's.
    assert!(a.env.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_computer_is_known_by_the_agents_key() {
    // With the agent's file for this tTerm: its key.
    let cloud = Cloud::start().await;
    let dir = common::data_dir();
    let env = dir.join("home").join(".tterm-web").join("env");
    let agents = format!("A{}", "b".repeat(31));
    std::fs::create_dir_all(env.parent().unwrap()).unwrap();
    std::fs::write(&env, format!("TTERM_HUB={}\nTTERM_TOKEN=tok\nTTERM_KEY={agents}\nTTERM_NAME=lab\n", cloud.hub())).unwrap();
    let a = app_in(&cloud, dir, env.clone(), Arc::new(FakeHost::default())).await;
    sign_in(&cloud, &a).await;
    let sent = cloud.st.lock().unwrap().computers_this.clone();
    assert_eq!(sent[0]["key"], agents.as_str());
    assert_eq!(sent[0]["name"], "lab");
    assert_eq!(std::fs::read_to_string(&env).unwrap(), format!("TTERM_HUB={}\nTTERM_TOKEN=tok\nTTERM_KEY={agents}\nTTERM_NAME=lab\n", cloud.hub()), "untouched");

    // A key tTerm refuses (its computer was removed): a new one, once.
    let cloud = Cloud::start().await;
    let dir = common::data_dir();
    let env = dir.join("home").join(".tterm-web").join("env");
    std::fs::create_dir_all(env.parent().unwrap()).unwrap();
    std::fs::write(&env, format!("TTERM_HUB={}\nTTERM_TOKEN=tok\nTTERM_KEY={agents}\n", cloud.hub())).unwrap();
    cloud.st.lock().unwrap().removed.push(agents.clone());
    let a = app_in(&cloud, dir, env.clone(), Arc::new(FakeHost::default())).await;
    sign_in(&cloud, &a).await;
    let sent = cloud.st.lock().unwrap().computers_this.clone();
    assert_eq!(sent.len(), 2);
    let fresh = sent[1]["key"].as_str().unwrap().to_string();
    assert_ne!(fresh, agents);
    assert!(std::fs::read_to_string(&env).unwrap().contains(&format!("TTERM_KEY={fresh}\n")));
    assert_eq!(here_machine(&state(&a.engine).await)["online"], true);

    // The agent's file for another tTerm Web: left alone, and this computer
    // is in Personal all the same, in the app.
    let cloud = Cloud::start().await;
    let dir = common::data_dir();
    let env = dir.join("home").join(".tterm-web").join("env");
    std::fs::create_dir_all(env.parent().unwrap()).unwrap();
    std::fs::write(&env, format!("TTERM_HUB=wss://connect-dev.example/agent\nTTERM_TOKEN=tok\nTTERM_KEY={agents}\n")).unwrap();
    let a = app_in(&cloud, dir, env.clone(), Arc::new(FakeHost::default())).await;
    sign_in(&cloud, &a).await;
    assert!(cloud.st.lock().unwrap().computers_this.is_empty());
    let s = state(&a.engine).await;
    let here = here_machine(&s);
    assert_eq!(here["id"], a.engine.settings.lock().unwrap().machine_id.to_string().as_str());
    assert!(std::fs::read_to_string(&env).unwrap().starts_with("TTERM_HUB=wss://connect-dev.example/agent"));
    let (status, _) = request(&a.engine, "POST", "/api/terminals", json!({"machineId": here["id"], "cols": 80, "rows": 24})).await;
    assert_eq!(status, 201);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notes_made_before_go_to_personal() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    let pid = a.engine.settings.lock().unwrap().project_id.to_string();
    let (_, folder) = request(&a.engine, "POST", "/api/folders", json!({"projectId": pid, "name": "Runbooks"})).await;
    let (_, note) = request(&a.engine, "POST", "/api/notes", json!({"folderId": folder["id"], "title": "Deploy"})).await;
    let blocks = json!([{"id": "b1", "type": "p", "text": "ssh in"}, {"id": "b2", "type": "todo", "text": "restart", "done": true}]);
    let (status, _) = request(&a.engine, "PUT", &format!("/api/notes/{}", note["id"].as_str().unwrap()), json!({"baseVersion": 1, "title": "Deploy", "blocks": blocks})).await;
    assert_eq!(status, 200);
    request(&a.engine, "POST", "/api/folders", json!({"projectId": pid, "name": "Empty"})).await;
    sign_in(&cloud, &a).await;
    assert!(until(10, || {
        let fake = cloud.st.lock().unwrap();
        fake.notes.iter().any(|n| n["version"] == 2) && fake.folders.len() == 2
    })
    .await, "the note and both folders went");
    {
        let fake = cloud.st.lock().unwrap();
        let names: Vec<&str> = fake.folders.iter().filter_map(|f| f["name"].as_str()).collect();
        assert_eq!(names, ["Runbooks", "Empty"]);
        assert_eq!(fake.notes[0]["title"], "Deploy");
        assert_eq!(fake.notes[0]["blocks"], json!([{"id": "b1", "type": "p", "text": "ssh in"}, {"id": "b2", "type": "todo", "text": "restart", "done": true}]));
    }
    // And gone from this computer.
    let mut left = (1, 1);
    for _ in 0..100 {
        left = a.engine.terminals.store.run(|c| {
            let n = |t: &str| c.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get::<_, i64>(0)).unwrap();
            (n("notes"), n("note_folders"))
        }).await.unwrap();
        if left == (0, 0) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(left, (0, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_tterm_the_app_works_on() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    let first = state(&a.engine).await;
    let here = here_machine(&first)["id"].as_str().unwrap().to_string();
    let (port, fake) = (cloud.port, cloud.st.clone());
    cloud.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;
    // A request that needs tTerm says so; the state is the last one, offline.
    let (status, got) = request(&a.engine, "GET", "/api/account", Value::Null).await;
    assert_eq!(status, 503);
    assert!(got["error"].as_str().unwrap().starts_with("No connection to tTerm."), "{got}");
    let s = state(&a.engine).await;
    assert_eq!(s["offline"], true);
    assert_eq!(s["app"], true);
    assert_eq!(here_machine(&s)["id"], here.as_str());
    assert_eq!(s["projects"][0]["machines"].as_array().unwrap().len(), 2, "the server is still listed");
    // This computer's terminals work all the same.
    let (status, _) = request(&a.engine, "POST", "/api/terminals", json!({"machineId": here, "cols": 80, "rows": 24})).await;
    assert_eq!(status, 201);
    // tTerm is back: the app finds it by itself.
    let _back = Cloud::start_on(port, fake).await;
    let mut online = false;
    for _ in 0..140 {
        if state(&a.engine).await["offline"] == false {
            online = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(online, "online again");
    let (status, _) = request(&a.engine, "GET", "/api/account", Value::Null).await;
    assert_eq!(status, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_app_starts_without_tterm() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    state(&a.engine).await;
    cloud.stop();
    // A new start with tTerm out of reach: what it said last, kept on disk.
    let b = app_in(&cloud, a.dir.clone(), a.env.clone(), a.host.clone()).await;
    let s = state(&b.engine).await;
    assert_eq!(s["app"], true, "{s}");
    assert_eq!(s["offline"], true);
    assert_eq!(s["me"]["email"], "anna@example.com");
    assert_eq!(here_machine(&s)["online"], true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in ["account.json", "cloud-state.json"] {
            assert_eq!(std::fs::metadata(a.dir.join(f)).unwrap().permissions().mode() & 0o777, 0o600, "{f}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cloud_terminals_over_the_pages_socket() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    let here = here_machine(&state(&a.engine).await)["id"].as_str().unwrap().to_string();
    let (_, local) = request(&a.engine, "POST", "/api/terminals", json!({"machineId": here, "cols": 80, "rows": 24})).await;
    let mut page = Page::new(&a.engine);
    // A cloud terminal on channel 5, this computer's on channel 6.
    page.send(json!({"op": "attach", "ch": 5, "id": "11111111-1111-1111-1111-111111111111", "after": null, "cols": 100, "rows": 30, "focus": true})).await;
    assert!(page.until(10, |p| p.text().contains("hello on 5")).await, "{:?}", page.msgs);
    assert!(page.msgs.iter().any(|m| m["op"] == "attached" && m["ch"] == 5));
    page.send(json!({"op": "attach", "ch": 6, "id": local["id"], "after": null, "cols": 80, "rows": 24, "focus": false})).await;
    assert!(page.until(10, |p| p.msgs.iter().any(|m| m["op"] == "replayed" && m["ch"] == 6)).await, "{:?}", page.msgs);
    page.keys(5, "echo to the cloud").await;
    assert!(page.until(10, |p| p.text().contains("echo to the cloud")).await);
    page.send(json!({"op": "resize", "ch": 5, "cols": 120, "rows": 40})).await;
    // The network drops the socket: the relay comes back by itself, and
    // attaches again from where the page got.
    cloud.drop_connections();
    assert!(until(10, || cloud.st.lock().unwrap().attaches.len() >= 2).await, "attached again");
    let again = cloud.st.lock().unwrap().attaches[1].clone();
    assert_eq!(again["ch"], 5);
    assert_eq!(again["after"], 2, "{again}");
    assert_eq!((again["cols"].as_i64(), again["rows"].as_i64()), (Some(120), Some(40)));
    assert!(page.until(10, |p| p.msgs.iter().filter(|m| m["op"] == "attached" && m["ch"] == 5).count() == 2).await);
    // A session that ended on the socket: a new one, and on.
    let sessions = cloud.count("POST", "/api/auth/app/session");
    cloud.end_sessions();
    cloud.st.lock().unwrap().close_4401 = true;
    page.keys(5, "x").await;
    assert!(until(10, || cloud.count("POST", "/api/auth/app/session") > sessions).await, "renewed");
    assert!(until(10, || cloud.st.lock().unwrap().attaches.len() >= 3).await, "attached in the new session");
    // A channel the page leaves goes from tTerm too.
    page.send(json!({"op": "detach", "ch": 5})).await;
    page.sock.close().await;
}

// ------------------------------------- found by the review of 0.3.0

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_keychain_is_enough_without_the_folders_details() {
    // tTerm on https names its cookie __Host-…: the app knows it from the
    // keychain's record, with the folder's details gone.
    let st = Arc::new(Mutex::new(Fake { cookie: "__Host-tterm-session".into(), ..Default::default() }));
    let cloud = Cloud::start_on(0, st).await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    let here = here_machine(&state(&a.engine).await)["id"].clone();
    std::fs::remove_file(a.dir.join("account.json")).unwrap();
    std::fs::remove_file(a.dir.join("cloud-state.json")).unwrap();
    let b = app_in(&cloud, a.dir.clone(), a.env.clone(), a.host.clone()).await;
    let s = state(&b.engine).await;
    assert_eq!(s["app"], true, "{s}");
    assert_eq!(s["offline"], false);
    assert_eq!(here_machine(&s)["id"], here, "the same machine, asked again");
    let (status, _) = request(&b.engine, "GET", "/api/account", Value::Null).await;
    assert_eq!(status, 200);
    let key = kept_key(&b);
    let (status, _) = request(&b.engine, "POST", "/api/auth/signout", json!({})).await;
    assert_eq!(status, 200);
    let signouts = cloud.st.lock().unwrap().signouts.clone();
    assert!(signouts.last().unwrap().contains(&format!("__Host-tterm-device={key}")), "{signouts:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_gone_leaves_no_socket_behind() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    // Pages that go while their cloud tabs attach (a reload), at every
    // moment of the attach.
    for i in 0..80u64 {
        let page = Page::new(&a.engine);
        let sock = page.sock.clone();
        let attach = tokio::spawn(async move {
            sock.text(&json!({"op": "attach", "ch": 1, "id": "11111111-1111-1111-1111-111111111111", "after": null, "cols": 80, "rows": 24, "focus": true}).to_string()).await;
        });
        tokio::time::sleep(Duration::from_micros((i % 20) * 150)).await;
        page.sock.close().await;
        let _ = attach.await;
        drop(page);
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let settled = cloud.st.lock().unwrap().sockets;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(cloud.st.lock().unwrap().sockets, settled, "nothing comes back for pages that are gone");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_socket_that_cannot_open_takes_nothing_else_down() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    cloud.st.lock().unwrap().no_sockets = true;
    let sessions = cloud.count("POST", "/api/auth/app/session");
    let mut page = Page::new(&a.engine);
    page.send(json!({"op": "attach", "ch": 3, "id": "11111111-1111-1111-1111-111111111111", "after": null, "cols": 80, "rows": 24, "focus": true})).await;
    for _ in 0..12 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let (status, _) = request(&a.engine, "GET", "/api/account", Value::Null).await;
        assert_eq!(status, 200, "requests go on");
    }
    assert_eq!(state(&a.engine).await["offline"], false);
    assert_eq!(cloud.count("POST", "/api/auth/app/session"), sessions, "no new sessions for a socket refused");
    // Let through again: the tab comes.
    cloud.st.lock().unwrap().no_sockets = false;
    assert!(page.until(15, |p| p.text().contains("hello on 3")).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_note_moved_halfway_is_finished_not_made_twice() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    let pid = a.engine.settings.lock().unwrap().project_id.to_string();
    let (_, folder) = request(&a.engine, "POST", "/api/folders", json!({"projectId": pid, "name": "Runbooks"})).await;
    for title in ["First", "Second"] {
        let (_, note) = request(&a.engine, "POST", "/api/notes", json!({"folderId": folder["id"], "title": title})).await;
        let blocks = json!([{"id": format!("b-{title}"), "type": "p", "text": title}]);
        request(&a.engine, "PUT", &format!("/api/notes/{}", note["id"].as_str().unwrap()), json!({"baseVersion": 1, "title": title, "blocks": blocks})).await;
    }
    // The first note's save is refused once: it waits, the other goes.
    cloud.st.lock().unwrap().refuse_saves = 1;
    sign_in(&cloud, &a).await;
    assert!(until(10, || cloud.st.lock().unwrap().notes.iter().filter(|n| n["version"] == 2).count() == 1).await, "one went");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(cloud.st.lock().unwrap().notes.len(), 2, "both begun");
    // The next start finishes the one begun: no third note.
    let b = app_in(&cloud, a.dir.clone(), a.env.clone(), a.host.clone()).await;
    assert!(until(10, || cloud.st.lock().unwrap().notes.iter().filter(|n| n["version"] == 2).count() == 2).await, "both there");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let fake = cloud.st.lock().unwrap().notes.clone();
    assert_eq!(fake.len(), 2, "{fake:?}");
    let left = b.engine.terminals.store.run(|c| c.query_row("SELECT count(*) FROM notes", [], |r| r.get::<_, i64>(0)).unwrap()).await.unwrap();
    assert_eq!(left, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_out_while_the_state_comes_keeps_nothing() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    state(&a.engine).await;
    cloud.st.lock().unwrap().slow.insert("/api/state".into(), 600);
    let e = a.engine.clone();
    let late = tokio::spawn(async move { request(&e, "GET", "/api/state", Value::Null).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    let (status, _) = request(&a.engine, "POST", "/api/auth/signout", json!({})).await;
    assert_eq!(status, 200);
    let _ = late.await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!a.dir.join("cloud-state.json").exists(), "the late answer is not kept");
    assert!(!a.dir.join("account.json").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_while_the_code_is_exchanged_gives_the_key_back() {
    let cloud = Cloud::start().await;
    cloud.st.lock().unwrap().slow.insert("/api/auth/app/exchange".into(), 800);
    let a = app(&cloud).await;
    request(&a.engine, "POST", "/api/auth/link", json!({})).await;
    let link = link_of(&a.host.opened.lock().unwrap()[0]);
    let code = cloud.allow(&link["challenge"]);
    let port = link["port"].clone();
    let query = format!("code={code}&state={}", link["state"]);
    let browser = tokio::spawn(async move { come_back(&port, &query).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    request(&a.engine, "DELETE", "/api/auth/link", Value::Null).await;
    let (status, page) = browser.await.unwrap();
    assert_eq!(status, 200, "the browser gets an answer");
    assert!(page.contains("Signing in was cancelled"), "{page}");
    assert!(a.host.key.lock().unwrap().is_none(), "no key kept");
    assert!(!a.engine.cloud.as_ref().unwrap().signed_in());
    let fake = cloud.st.lock().unwrap();
    assert_eq!(fake.devices.len(), 1);
    assert!(fake.devices.values().all(|forgotten| *forgotten), "tTerm forgot the device");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_left_open_do_not_keep_the_browser_waiting() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    request(&a.engine, "POST", "/api/auth/link", json!({})).await;
    let link = link_of(&a.host.opened.lock().unwrap()[0]);
    let mut idle = Vec::new();
    for _ in 0..3 {
        idle.push(TcpStream::connect(format!("127.0.0.1:{}", link["port"])).await.unwrap());
    }
    let code = cloud.allow(&link["challenge"]);
    let started = std::time::Instant::now();
    let (status, _) = come_back(&link["port"], &format!("code={code}&state={}", link["state"])).await;
    assert_eq!(status, 200);
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
}

// ------------------------------- found by the second look of the review

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_returns_of_one_sign_in_make_one_device() {
    let cloud = Cloud::start().await;
    cloud.st.lock().unwrap().slow.insert("/api/auth/app/exchange".into(), 500);
    let a = app(&cloud).await;
    request(&a.engine, "POST", "/api/auth/link", json!({})).await;
    let link = link_of(&a.host.opened.lock().unwrap()[0]);
    // Allow in two tabs of the same sign-in: two codes, one challenge.
    let (one, two) = (cloud.allow(&link["challenge"]), cloud.allow(&link["challenge"]));
    let (p1, p2) = (link["port"].clone(), link["port"].clone());
    let (q1, q2) = (format!("code={one}&state={}", link["state"]), format!("code={two}&state={}", link["state"]));
    let first = tokio::spawn(async move { come_back(&p1, &q1).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (status, second) = come_back(&p2, &q2).await;
    assert_eq!(status, 200);
    assert!(second.contains("Signing in is being finished"), "{second}");
    let (status, first) = first.await.unwrap();
    assert_eq!(status, 200);
    assert!(first.contains("You are in"), "{first}");
    let mut s = Value::Null;
    for _ in 0..100 {
        s = link_state(&a.engine).await;
        if s["state"] != "waiting" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(s["state"], "done", "{s}");
    assert!(a.engine.cloud.as_ref().unwrap().signed_in());
    assert_eq!(cloud.st.lock().unwrap().devices.len(), 1, "one device");
    assert_eq!(cloud.count("POST", "/api/auth/app/exchange"), 1, "one code traded");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_given_back_leaves_a_new_sign_in_waiting() {
    let cloud = Cloud::start().await;
    cloud.st.lock().unwrap().slow.insert("/api/auth/app/exchange".into(), 600);
    let a = app(&cloud).await;
    request(&a.engine, "POST", "/api/auth/link", json!({})).await;
    let old = link_of(&a.host.opened.lock().unwrap()[0]);
    let code = cloud.allow(&old["challenge"]);
    let (port, query) = (old["port"].clone(), format!("code={code}&state={}", old["state"]));
    let browser = tokio::spawn(async move { come_back(&port, &query).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Cancel, and Sign in with your browser again, while the old code goes.
    request(&a.engine, "DELETE", "/api/auth/link", Value::Null).await;
    let (status, _) = request(&a.engine, "POST", "/api/auth/link", json!({})).await;
    assert_eq!(status, 200);
    let new = link_of(&a.host.opened.lock().unwrap()[1]);
    let (_, page) = browser.await.unwrap();
    assert!(page.contains("Signing in was cancelled"), "{page}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(link_state(&a.engine).await["state"], "waiting", "the new sign-in waits on");
    assert!(TcpStream::connect(format!("127.0.0.1:{}", new["port"])).await.is_ok(), "on its port");
    assert!(!a.engine.cloud.as_ref().unwrap().signed_in());
    assert!(cloud.st.lock().unwrap().devices.values().all(|forgotten| *forgotten), "the old key was given back");
    // The new one signs in as usual.
    let code = cloud.allow(&new["challenge"]);
    let (_, page) = come_back(&new["port"], &format!("code={code}&state={}", new["state"])).await;
    assert!(page.contains("You are in"), "{page}");
    assert!(until(5, || a.engine.cloud.as_ref().unwrap().signed_in()).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_note_written_in_tterm_meanwhile_keeps_both() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    let pid = a.engine.settings.lock().unwrap().project_id.to_string();
    let (_, folder) = request(&a.engine, "POST", "/api/folders", json!({"projectId": pid, "name": "Runbooks"})).await;
    let (_, note) = request(&a.engine, "POST", "/api/notes", json!({"folderId": folder["id"], "title": "Deploy"})).await;
    let mine = json!([{"id": "b-mine", "type": "p", "text": "written here"}]);
    request(&a.engine, "PUT", &format!("/api/notes/{}", note["id"].as_str().unwrap()), json!({"baseVersion": 1, "title": "Deploy", "blocks": mine})).await;
    // The save is refused: an empty Deploy is there, and the person writes
    // in it from a browser.
    cloud.st.lock().unwrap().refuse_saves = 1;
    sign_in(&cloud, &a).await;
    assert!(until(10, || cloud.st.lock().unwrap().notes.len() == 1).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    {
        let mut fake = cloud.st.lock().unwrap();
        let n = &mut fake.notes[0];
        n["blocks"] = json!([{"id": "b-there", "type": "p", "text": "written in the browser"}]);
        n["version"] = json!(2);
    }
    let left = a.engine.terminals.store.run(|c| c.query_row("SELECT count(*) FROM notes", [], |r| r.get::<_, i64>(0)).unwrap()).await.unwrap();
    assert_eq!(left, 1, "not deleted while tTerm has not its text");
    // The next start: merged, both texts, and only then gone from here.
    let b = app_in(&cloud, a.dir.clone(), a.env.clone(), a.host.clone()).await;
    assert!(until(10, || {
        let fake = cloud.st.lock().unwrap();
        let ids: Vec<String> = fake.notes[0]["blocks"].as_array().unwrap().iter().filter_map(|x| x["id"].as_str().map(str::to_string)).collect();
        ids == ["b-there", "b-mine"]
    })
    .await, "{:?}", cloud.st.lock().unwrap().notes);
    assert_eq!(cloud.st.lock().unwrap().notes.len(), 1, "one note");
    let mut left = 1;
    for _ in 0..100 {
        left = b.engine.terminals.store.run(|c| c.query_row("SELECT count(*) FROM notes", [], |r| r.get::<_, i64>(0)).unwrap()).await.unwrap();
        if left == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(left, 0);
}

// -------------------------------- found by the third look of the review

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_page_asked_again_while_signing_in_is_finished_changes_nothing() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    // The keychain asks for the password before it keeps the key.
    a.host.save_ms.store(1500, Ordering::SeqCst);
    let (_, started) = request(&a.engine, "POST", "/api/auth/link", json!({})).await;
    let link = link_of(&a.host.opened.lock().unwrap()[0]);
    let code = cloud.allow(&link["challenge"]);
    let (port, query) = (link["port"].clone(), format!("code={code}&state={}", link["state"]));
    let browser = tokio::spawn(async move { come_back(&port, &query).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(link_state(&a.engine).await["state"], "waiting");
    // Open the page again, and Sign in with your browser on a page loaded
    // again: the sign-in being finished, its code.
    for body in [json!({"again": true}), json!({})] {
        let (status, answer) = request(&a.engine, "POST", "/api/auth/link", body).await;
        assert_eq!(status, 200, "{answer}");
        assert_eq!(answer["code"], started["code"]);
    }
    assert_eq!(a.host.opened.lock().unwrap().len(), 1, "no page opened again");
    let (status, page) = browser.await.unwrap();
    assert_eq!(status, 200);
    assert!(page.contains("You are in"), "{page}");
    let mut s = Value::Null;
    for _ in 0..100 {
        s = link_state(&a.engine).await;
        if s["state"] == "done" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(s["state"], "done", "{s}");
    assert!(a.engine.cloud.as_ref().unwrap().signed_in());
    let fake = cloud.st.lock().unwrap();
    assert_eq!(fake.devices.len(), 1);
    assert!(fake.devices.values().all(|forgotten| !*forgotten), "the device stays");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_left_open_give_way_to_the_browser() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    request(&a.engine, "POST", "/api/auth/link", json!({})).await;
    let link = link_of(&a.host.opened.lock().unwrap()[0]);
    // More left open than are waited for at once.
    let mut idle = Vec::new();
    for _ in 0..80 {
        idle.push(TcpStream::connect(format!("127.0.0.1:{}", link["port"])).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The first of them gave way at once, not after the 2 s a request has.
    let mut byte = [0u8; 1];
    let first = tokio::time::timeout(Duration::from_millis(800), idle[0].read(&mut byte)).await;
    assert!(matches!(first, Ok(Ok(0))), "{first:?}");
    let code = cloud.allow(&link["challenge"]);
    let started = std::time::Instant::now();
    let (status, page) = come_back(&link["port"], &format!("code={code}&state={}", link["state"])).await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("You are in"), "{page}");
    assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_while_the_keychain_answers_late_stays() {
    let cloud = Cloud::start().await;
    // In the keychain, the record of a sign-in before: read at the start,
    // and its answer late, as when the keychain asks for the password.
    let host = Arc::new(FakeHost::default());
    let old = json!({"key": token(), "deviceId": "old-device", "label": "Mac", "hub": cloud.hub(), "cookie": "tterm-session"});
    *host.key.lock().unwrap() = Some(old.to_string());
    host.load_ms.store(1500, Ordering::SeqCst);
    let dir = common::data_dir();
    let a = app_in(&cloud, dir.clone(), dir.join("home").join(".tterm-web").join("env"), host).await;
    // Meanwhile the person signs in: the page waits for the keychain a
    // minute at most, and goes on before signing in.
    let account = a.engine.cloud.clone().unwrap();
    let shown = account.start_link(&a.engine, false).await.expect("a sign-in");
    let link = link_of(&a.host.opened.lock().unwrap()[0]);
    assert_eq!(shown, link_code(&link["challenge"]));
    let code = cloud.allow(&link["challenge"]);
    let (_, page) = come_back(&link["port"], &format!("code={code}&state={}", link["state"])).await;
    assert!(page.contains("You are in"), "{page}");
    let record: Value = serde_json::from_str(&a.host.key.lock().unwrap().clone().unwrap()).unwrap();
    let new = record["deviceId"].as_str().unwrap().to_string();
    assert_ne!(new, "old-device");
    // The keychain answers: the sign-in made meanwhile stays, here as in
    // the keychain.
    tokio::time::sleep(Duration::from_millis(1800)).await;
    assert_eq!(account.device_id().as_deref(), Some(new.as_str()));
    // Its key it is that asks for a session.
    cloud.end_sessions();
    let s = state(&a.engine).await;
    assert_eq!(s["app"], true, "{s}");
    assert_eq!(s["me"]["email"], "anna@example.com");
}

// ------------------------------------------- photos and search, from 0.3.1

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_photo_goes_to_tterm_as_a_picture_and_comes_back_as_one() {
    use tterm_engine::api::{body_type, handle_with, Flags};
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    let photo = b"\xff\xd8\xff\xe0 a photo of 256 pixels \xff\xd9".to_vec();
    let flags = Flags { body_type: body_type(Some("image/jpeg")), ..Default::default() };
    let r = handle_with(&a.engine, "PUT", "/api/me/photo", &photo, flags).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let answer: Value = serde_json::from_slice(&r.body).unwrap();
    let address = answer["photo"].as_str().unwrap().to_string();
    assert_eq!(cloud.st.lock().unwrap().photo, Some(("image/jpeg".to_string(), photo.clone())), "as it came");
    let r = handle_with(&a.engine, "GET", &address, &[], Flags::default()).await;
    assert_eq!((r.status, r.content_type), (200, "image/jpeg"));
    assert_eq!(r.body, photo, "the picture itself");
    // Whatever else the page sends goes as JSON, as before.
    assert_eq!(body_type(None), "application/json");
    assert_eq!(body_type(Some("text/html")), "application/json");
    assert_eq!(body_type(Some("Image/JPEG; q=1")), "image/jpeg");
    let (status, _) = request(&a.engine, "POST", "/api/folders", json!({"projectId": "p1", "name": "Runbooks"})).await;
    assert_eq!(status, 201);
    let folders = cloud.st.lock().unwrap().requests.iter().filter(|(m, p, _)| m == "POST" && p == "/api/folders").map(|(_, _, h)| h.get("content-type").cloned()).collect::<Vec<_>>();
    assert_eq!(folders.last().cloned().flatten().as_deref(), Some("application/json"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn search_finds_this_computers_commands_and_tterms_as_one() {
    use tterm_engine::store::Finished;
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    let store = &a.engine.terminals.store;
    let now = tterm_engine::terminals::now_ms();
    let here_terminal = "22222222-2222-2222-2222-222222222222";
    store.opened(here_terminal, "1", now);
    store.save_block(here_terminal, Finished { seq_start: 5, seq_end: 9, command: "deploy web".into(), started_ms: now - 1000, finished_ms: now - 900,
        exit_code: Some(0), cwd: "/srv".into(), output: b"deployed web\r\n".to_vec(), cols: 80, ..Default::default() });
    // Before signing in: this computer's alone, and its notes.
    let pid = a.engine.settings.lock().unwrap().project_id.to_string();
    let (_, folder) = request(&a.engine, "POST", "/api/folders", json!({"projectId": pid, "name": "Runbooks"})).await;
    let (_, note) = request(&a.engine, "POST", "/api/notes", json!({"folderId": folder["id"], "title": "Deploy steps"})).await;
    let (status, found) = request(&a.engine, "GET", "/api/search?q=Deploy&near=", Value::Null).await;
    assert_eq!(status, 200, "{found}");
    let own = a.engine.settings.lock().unwrap().machine_id.to_string();
    assert_eq!(found["commands"].as_array().unwrap().len(), 1, "{found}");
    assert_eq!((found["commands"][0]["command"].as_str(), found["commands"][0]["machineId"].as_str()), (Some("deploy web"), Some(own.as_str())));
    assert_eq!(found["output"][0]["line"], "deployed web");
    assert_eq!(found["notes"][0]["noteId"], note["id"]);
    let (_, recent) = request(&a.engine, "GET", &format!("/api/search?q=&near={own}"), Value::Null).await;
    assert_eq!(recent["recent"][0]["command"], "deploy web", "{recent}");
    assert_eq!(cloud.count("GET", "/api/search?q=Deploy&near="), 0, "nothing asked of tTerm before signing in");

    // Signed in: tTerm's and this computer's, as one; the notes are tTerm's.
    sign_in(&cloud, &a).await;
    state(&a.engine).await;
    let (status, found) = request(&a.engine, "GET", "/api/search?q=deploy&near=", Value::Null).await;
    assert_eq!(status, 200, "{found}");
    let commands: Vec<(&str, &str)> = found["commands"].as_array().unwrap().iter().map(|b| (b["command"].as_str().unwrap(), b["machineId"].as_str().unwrap())).collect();
    let here = a.engine.place().machine_id.to_string();
    assert_eq!(commands, [("deploy web", here.as_str()), ("deploy api", "s1")], "the latest first");
    assert_eq!(found["notes"], json!([{"noteId": "n-cloud", "title": "Deploy", "lines": [], "hit": -1}]));
    assert_eq!(found["more"]["notes"], true);
    assert_eq!(cloud.count("GET", "/api/search?q=deploy&near="), 1);

    // Without tTerm: this computer's alone.
    cloud.stop();
    let (status, found) = request(&a.engine, "GET", "/api/search?q=deploy+web&near=", Value::Null).await;
    assert_eq!(status, 200, "{found}");
    let commands: Vec<&str> = found["commands"].as_array().unwrap().iter().map(|b| b["command"].as_str().unwrap()).collect();
    assert_eq!(commands, ["deploy web"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_tterm_does_not_hold_back_this_computers_search() {
    use tterm_engine::store::Finished;
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    state(&a.engine).await;
    let store = &a.engine.terminals.store;
    let now = tterm_engine::terminals::now_ms();
    store.opened("33333333-3333-3333-3333-333333333333", "1", now);
    store.save_block("33333333-3333-3333-3333-333333333333", Finished { seq_start: 5, seq_end: 9, command: "deploy web".into(), started_ms: now, finished_ms: now,
        output: b"ok\r\n".to_vec(), cols: 80, ..Default::default() });
    cloud.st.lock().unwrap().slow.insert("/api/search?q=deploy&near=".into(), 8000);
    let started = std::time::Instant::now();
    let (status, found) = request(&a.engine, "GET", "/api/search?q=deploy&near=", Value::Null).await;
    assert_eq!(status, 200, "{found}");
    assert!(started.elapsed() < Duration::from_secs(7), "{:?}", started.elapsed());
    let commands: Vec<&str> = found["commands"].as_array().unwrap().iter().map(|b| b["command"].as_str().unwrap()).collect();
    assert_eq!(commands, ["deploy web"], "this computer's, without waiting for tTerm");
    assert!(!a.engine.cloud.as_ref().unwrap().offline(), "a slow search is no lost connection");
}

// ------------------------------------- this computer from tTerm Web (0.4.0)

/// The link's pauses, short: as the checks of link.rs have them.
fn fast() -> tterm_engine::link::Timing {
    tterm_engine::link::Timing {
        heartbeat: Duration::from_millis(200),
        silence_limit: Duration::from_secs(5),
        ping_every: Duration::from_millis(300),
        ping_timeout: Duration::from_secs(5),
        alive_every: Duration::from_secs(600),
        sleep_jump: Duration::from_secs(15),
        backoff_start: Duration::from_millis(50),
        backoff_max: Duration::from_millis(400),
        healthy_for: Duration::from_millis(600),
        no_network_pause: Duration::from_millis(100),
        claim_wait: Duration::from_secs(1),
        keep_for: Duration::from_secs(3),
        ended_keep: Duration::from_secs(1),
        sweep_every: Duration::from_millis(100),
        open_timeout: Duration::from_secs(3),
        welcome_timeout: Duration::from_secs(3),
        close_timeout: Duration::from_secs(3),
    }
}

async fn reach(e: &Arc<Engine>) -> Value {
    let (status, r) = request(e, "GET", "/api/app/this-computer", Value::Null).await;
    assert_eq!(status, 200, "{r}");
    r
}

/// This computer in Settings, once it says `want`.
async fn until_reach(e: &Arc<Engine>, want: &str) -> Value {
    let mut last = Value::Null;
    for _ in 0..400 {
        last = reach(e).await;
        if last["status"] == want {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never {want}: {last}");
}

async fn open_from_web(e: &Arc<Engine>, open: bool) -> (u16, Value) {
    request(e, "PUT", "/api/app/this-computer", json!({"open": open})).await
}

fn env_key(a: &App) -> String {
    let env = std::fs::read_to_string(&a.env).expect("the agent's file");
    env.lines().find_map(|l| l.strip_prefix("TTERM_KEY=")).expect("a key").to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn this_mac_opens_from_tterm_web_through_the_app() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    // Signed out: nothing to open, and nothing to turn on.
    assert_eq!(until_reach(&a.engine, "signed-out").await["open"], false);
    let (status, _) = open_from_web(&a.engine, true).await;
    assert_eq!(status, 409);
    sign_in(&cloud, &a).await;
    // No agent was set up here: off until the person turns it on.
    let r = until_reach(&a.engine, "off").await;
    assert_eq!((r["open"].clone(), r["background"].clone()), (json!(false), json!(false)));
    assert!(cloud.st.lock().unwrap().hellos.is_empty());
    let (status, r) = open_from_web(&a.engine, true).await;
    assert_eq!(status, 200, "{r}");
    assert_eq!(r["open"], true);
    // The answer says what the link does, not what it did before.
    assert!(r["status"] == "connecting" || r["status"] == "online", "{r}");
    let r = until_reach(&a.engine, "online").await;
    let machine = cloud.st.lock().unwrap().machines[0].clone();
    assert_eq!(r["name"], machine["name"]);
    assert_eq!(r["background"], true, "the app stays in the menu bar for it");
    assert_eq!(machine["online"], true);
    // Its hello: this computer's own key, from ~/.tterm-web/env as the
    // agent's, and the app's version for tTerm Web to show.
    let hello = cloud.st.lock().unwrap().hellos[0].clone();
    let key = env_key(&a);
    assert_eq!((hello["key"].as_str(), hello["token"].as_str()), (Some(key.as_str()), Some(key.as_str())));
    assert_eq!(hello["agent"], format!("app {}", tterm_engine::VERSION));
    assert_eq!(hello["web"], 2);
    // tTerm Web opens a terminal on this computer: its shell runs here, in
    // the app; tTerm Web's installer would know it from the agent's folder.
    let agent_dir = a.env.parent().unwrap().display().to_string();
    cloud.to_agent(json!({"t": "open", "ch": 1, "cmd": "echo answer:$((6*7)) dir:$TTERM_AGENT_DIR; sleep 60", "cols": 80, "rows": 24}));
    assert!(until(10, || cloud.printed(1).contains("answer:42")).await, "{}", cloud.printed(1));
    assert!(cloud.printed(1).contains(&format!("dir:{agent_dir}")), "{}", cloud.printed(1));
    assert_eq!(reach(&a.engine).await["terminals"], 1);
    // Off: tTerm Web hears that its terminals end, and this computer goes
    // offline there.
    let (status, r) = open_from_web(&a.engine, false).await;
    assert_eq!((status, r["open"].clone(), r["status"].clone()), (200, json!(false), json!("off")), "{r}");
    assert!(until(10, || cloud.heard("bye")).await, "the goodbye");
    assert!(until(10, || cloud.links() == 0).await);
    assert_eq!(reach(&a.engine).await["terminals"], 0);
    assert_eq!(cloud.st.lock().unwrap().machines[0]["online"], false);
    // Kept: off after a new start too, and on again after the one after.
    let b = app_in(&cloud, a.dir.clone(), a.env.clone(), a.host.clone()).await;
    b.engine.reach.set_timing(fast());
    let r = until_reach(&b.engine, "off").await;
    assert_eq!(r["open"], false);
    open_from_web(&b.engine, true).await;
    until_reach(&b.engine, "online").await;
    assert_eq!(cloud.st.lock().unwrap().machines.len(), 1, "the same computer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn where_the_agent_was_set_up_the_app_takes_its_place() {
    let cloud = Cloud::start().await;
    let dir = common::data_dir();
    let env = dir.join("home").join(".tterm-web").join("env");
    let agent_dir = env.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&agent_dir).unwrap();
    std::fs::write(agent_dir.join("tterm-agent"), "#!/bin/sh\n").unwrap();
    // The agent, running without an autostart, by its pid.
    let mut agent = std::process::Command::new("sh").args(["-c", &format!("sleep 60; : {}/tterm-agent", agent_dir.display())]).spawn().unwrap();
    std::fs::write(agent_dir.join("agent.pid"), agent.id().to_string()).unwrap();
    let a = app_in(&cloud, dir, env.clone(), Arc::new(FakeHost::default())).await;
    a.engine.reach.set_timing(fast());
    a.engine.reach.set_background(true);
    sign_in(&cloud, &a).await;
    // The person said yes to the agent: the app keeps this computer open,
    // and the agent stops for good, once tTerm took the key.
    let r = until_reach(&a.engine, "online").await;
    assert_eq!(r["open"], true);
    let key = env_key(&a);
    assert!(cloud.st.lock().unwrap().computers_this.iter().any(|c| c["key"] == key.as_str()));
    assert!(until(5, || agent.try_wait().unwrap().is_some()).await, "the agent stopped");
    assert!(!agent_dir.join("agent.pid").exists());
    assert!(agent_dir.join("tterm-agent").exists() && env.exists(), "its files stay, with the key");
    let settings: Value = serde_json::from_slice(&std::fs::read(a.dir.join("settings.json")).unwrap()).unwrap();
    assert_eq!(settings["openFromWeb"], true, "decided once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removed_in_tterm_web_it_goes_off_and_on_again_comes_back() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    open_from_web(&a.engine, true).await;
    until_reach(&a.engine, "online").await;
    let first = env_key(&a);
    // Removed in tTerm Web: the link hears it, and the switch goes off at
    // once, not at the keeper's next look.
    cloud.st.lock().unwrap().remove_now = true;
    let told = std::time::Instant::now();
    let r = until_reach(&a.engine, "removed").await;
    assert!(told.elapsed() < Duration::from_millis(2500), "{:?}", told.elapsed());
    assert_eq!((r["open"].clone(), r["background"].clone()), (json!(false), json!(false)));
    assert!(r["problem"].as_str().unwrap().contains("removed"), "{r}");
    assert_eq!(a.engine.reach.kept_now(), Some(false), "the app is not kept for it");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(cloud.st.lock().unwrap().hellos.len(), 1, "not knocking again");
    // On again: tTerm gives this computer a new key, and it is a new machine.
    open_from_web(&a.engine, true).await;
    let r = until_reach(&a.engine, "online").await;
    assert_eq!(r["open"], true);
    let second = env_key(&a);
    assert_ne!(first, second);
    let st = cloud.st.lock().unwrap();
    assert_eq!(st.hellos.last().unwrap()["key"], second.as_str());
    assert_eq!(st.machines.len(), 2);
    assert!(st.computers_this.iter().any(|c| c["key"] == second.as_str()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removed_while_the_app_was_not_running_it_is_off() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    open_from_web(&a.engine, true).await;
    until_reach(&a.engine, "online").await;
    a.engine.reach.stop().await;
    // Removed in tTerm Web meanwhile, the app not running.
    let key = env_key(&a);
    cloud.st.lock().unwrap().removed.push(key.clone());
    let b = app_in(&cloud, a.dir.clone(), a.env.clone(), a.host.clone()).await;
    b.engine.reach.set_timing(fast());
    let r = until_reach(&b.engine, "removed").await;
    assert_eq!(r["open"], false);
    assert_ne!(env_key(&a), key, "tTerm gave it a new key at the start");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_link_waits_for_its_key_and_says_why() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    // In use by another agent: refused, tried again, said in Settings.
    cloud.st.lock().unwrap().refuse_hellos = 1000;
    open_from_web(&a.engine, true).await;
    let mut said = Value::Null;
    for _ in 0..200 {
        said = reach(&a.engine).await;
        if said["problem"].as_str().map(|p| p.contains("already connected")).unwrap_or(false) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(said["status"], "connecting", "{said}");
    assert!(said["problem"].as_str().unwrap_or("").contains("Stop that one first"), "{said}");
    cloud.st.lock().unwrap().refuse_hellos = 0;
    let r = until_reach(&a.engine, "online").await;
    assert_eq!(r["problem"], Value::Null);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_out_this_mac_is_offline_in_tterm_web() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    open_from_web(&a.engine, true).await;
    until_reach(&a.engine, "online").await;
    cloud.to_agent(json!({"t": "open", "ch": 3, "cmd": "echo up; sleep 60", "cols": 80, "rows": 24}));
    assert!(until(10, || cloud.printed(3).contains("up")).await);
    assert_eq!(a.engine.reach.kept_now(), Some(true));
    let (status, _) = request(&a.engine, "POST", "/api/auth/signout", json!({})).await;
    assert_eq!(status, 200);
    until_reach(&a.engine, "signed-out").await;
    assert!(until(10, || cloud.links() == 0).await);
    assert_eq!(reach(&a.engine).await["terminals"], 0);
    assert_eq!(a.engine.reach.kept_now(), Some(false), "signed out, the app does not start at login for it");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quitting_says_goodbye_to_tterm_web() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    open_from_web(&a.engine, true).await;
    until_reach(&a.engine, "online").await;
    cloud.to_agent(json!({"t": "open", "ch": 2, "cmd": "echo up; sleep 60", "cols": 80, "rows": 24}));
    assert!(until(10, || cloud.printed(2).contains("up")).await);
    let started = std::time::Instant::now();
    a.engine.reach.stop().await;
    assert!(started.elapsed() < Duration::from_secs(7), "{:?}", started.elapsed());
    assert!(cloud.heard("bye"));
    assert!(until(5, || cloud.links() == 0).await);
    assert_eq!(reach(&a.engine).await["status"], "off");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(cloud.st.lock().unwrap().hellos.len(), 1, "not again after the quit");
    // A quit is no switch: the app starts at the next login all the same.
    assert_eq!(a.engine.reach.kept_now(), Some(true));
    let settings: Value = serde_json::from_slice(&std::fs::read(a.dir.join("settings.json")).unwrap()).unwrap();
    assert_eq!(settings["openFromWeb"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_tterm_webs_agent_is_left_alone() {
    let cloud = Cloud::start().await;
    let dir = common::data_dir();
    let env = dir.join("home").join(".tterm-web").join("env");
    let agent_dir = env.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&agent_dir).unwrap();
    std::fs::write(&env, format!("TTERM_HUB=wss://connect-dev.example/agent\nTTERM_TOKEN=tok\nTTERM_KEY={}\n", account::random_token(24))).unwrap();
    std::fs::write(agent_dir.join("tterm-agent"), "#!/bin/sh\n").unwrap();
    let mut agent = std::process::Command::new("sh").args(["-c", &format!("sleep 60; : {}/tterm-agent", agent_dir.display())]).spawn().unwrap();
    std::fs::write(agent_dir.join("agent.pid"), agent.id().to_string()).unwrap();
    let a = app_in(&cloud, dir, env.clone(), Arc::new(FakeHost::default())).await;
    a.engine.reach.set_timing(fast());
    a.engine.reach.set_background(true);
    sign_in(&cloud, &a).await;
    // Not an agent the app can take: off, and nothing kept for it.
    let r = until_reach(&a.engine, "off").await;
    assert_eq!((r["open"].clone(), r["background"].clone()), (json!(false), json!(false)));
    assert!(until(5, || a.engine.reach.kept_now() == Some(false)).await);
    // On: the file says no, and why.
    let (status, r) = open_from_web(&a.engine, true).await;
    assert_eq!(status, 409, "{r}");
    assert!(r["error"].as_str().unwrap().contains("another tTerm Web"), "{r}");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(agent.try_wait().unwrap().is_none(), "that agent runs on");
    assert!(agent_dir.join("agent.pid").exists());
    assert!(cloud.st.lock().unwrap().hellos.is_empty());
    let _ = agent.kill();
    let _ = agent.wait();
}

/// The agent of another account's computer, as tTerm Web's installer of
/// that account sets it up: its key in the file, and it running.
fn their_agent(cloud: &Cloud, env: &std::path::Path) -> (String, std::process::Child) {
    let theirs = account::random_token(32);
    cloud.st.lock().unwrap().foreign.push(theirs.clone());
    let dir = env.parent().unwrap();
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(env, format!("TTERM_HUB={}\nTTERM_TOKEN=tok\nTTERM_KEY={theirs}\n", cloud.hub())).unwrap();
    std::fs::write(dir.join("tterm-agent"), "#!/bin/sh\n").unwrap();
    let agent = std::process::Command::new("sh").args(["-c", &format!("sleep 60; : {}/tterm-agent", dir.display())]).spawn().unwrap();
    std::fs::write(dir.join("agent.pid"), agent.id().to_string()).unwrap();
    (theirs, agent)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_accounts_key_in_the_file_is_not_taken() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    open_from_web(&a.engine, true).await;
    until_reach(&a.engine, "online").await;
    a.engine.reach.stop().await;
    // Meanwhile this computer was set up for another account.
    let (theirs, mut agent) = their_agent(&cloud, &a.env);
    let b = app_in(&cloud, a.dir.clone(), a.env.clone(), a.host.clone()).await;
    b.engine.reach.set_timing(fast());
    b.engine.reach.set_background(true);
    // tTerm says the key is no machine of this account's: off, and why;
    // never connected with it, their agent left alone.
    let r = until_reach(&b.engine, "closed").await;
    assert!(r["problem"].as_str().unwrap().contains("another account"), "{r}");
    assert_eq!(r["open"], false);
    assert!(until(5, || b.engine.reach.kept_now() == Some(false)).await);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!cloud.st.lock().unwrap().hellos.iter().any(|h| h["key"] == theirs.as_str()), "not connected as their computer");
    assert!(agent.try_wait().unwrap().is_none(), "their agent runs on");
    assert!(a.env.parent().unwrap().join("agent.pid").exists());
    // On again: tTerm says no again.
    let (status, r) = open_from_web(&b.engine, true).await;
    assert_eq!(status, 409, "{r}");
    assert!(r["error"].as_str().unwrap().contains("another account"), "{r}");
    assert!(!cloud.st.lock().unwrap().hellos.iter().any(|h| h["key"] == theirs.as_str()));
    let _ = agent.kill();
    let _ = agent.wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_key_in_the_file_is_asked_about_first() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    open_from_web(&a.engine, true).await;
    until_reach(&a.engine, "online").await;
    // While the link runs, another account's installer takes the file.
    let (theirs, mut agent) = their_agent(&cloud, &a.env);
    let r = until_reach(&a.engine, "closed").await;
    assert!(r["problem"].as_str().unwrap().contains("another account"), "{r}");
    assert!(until(5, || cloud.links() == 0).await, "this account's link ended too");
    assert!(cloud.st.lock().unwrap().computers_this.iter().any(|c| c["key"] == theirs.as_str()), "tTerm was asked");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!cloud.st.lock().unwrap().hellos.iter().any(|h| h["key"] == theirs.as_str()));
    let _ = agent.kill();
    let _ = agent.wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_agents_file_written_again_changes_nothing() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    open_from_web(&a.engine, true).await;
    until_reach(&a.engine, "online").await;
    // Written again in place, by hand or by a tool: empty for a moment,
    // then half, then whole.
    let text = std::fs::read_to_string(&a.env).unwrap();
    for part in ["", &text[..10], &text] {
        std::fs::write(&a.env, part).unwrap();
        a.engine.reach.look_again();
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let r = reach(&a.engine).await;
    assert_eq!((r["open"].clone(), r["status"].clone()), (json!(true), json!("online")), "{r}");
    assert_eq!(cloud.st.lock().unwrap().hellos.len(), 1, "the same link all along");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_refused_once_at_the_start_does_not_keep_it_down() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    open_from_web(&a.engine, true).await;
    until_reach(&a.engine, "online").await;
    a.engine.reach.stop().await;
    // The next start: tTerm's database hiccups once, at the session.
    cloud.end_sessions();
    cloud.st.lock().unwrap().fail_once.insert("/api/auth/app/session".into(), 500);
    let b = app_in(&cloud, a.dir.clone(), a.env.clone(), a.host.clone()).await;
    b.engine.reach.set_timing(fast());
    until_reach(&b.engine, "online").await;
    assert!(cloud.st.lock().unwrap().fail_once.is_empty(), "the hiccup happened");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proxys_page_is_no_refusal() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    open_from_web(&a.engine, true).await;
    until_reach(&a.engine, "online").await;
    a.engine.reach.stop().await;
    // The next start: a proxy answers for tTerm once, 403 without tTerm's
    // words. Asked again, tTerm says yes.
    cloud.st.lock().unwrap().fail_once.insert("/api/computers/this".into(), 403);
    let b = app_in(&cloud, a.dir.clone(), a.env.clone(), a.host.clone()).await;
    b.engine.reach.set_timing(fast());
    let r = until_reach(&b.engine, "online").await;
    assert_eq!(r["open"], true);
    assert!(cloud.st.lock().unwrap().fail_once.is_empty(), "the proxy answered");
    assert_eq!(b.engine.reach.kept_now(), Some(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tterm_in_trouble_does_not_stop_a_link_that_runs() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    open_from_web(&a.engine, true).await;
    until_reach(&a.engine, "online").await;
    // On again from a page that did not see it on: tTerm cannot say now.
    cloud.st.lock().unwrap().fail_once.insert("/api/computers/this".into(), 500);
    let (status, r) = open_from_web(&a.engine, true).await;
    assert_eq!(status, 200, "{r}");
    tokio::time::sleep(Duration::from_millis(800)).await;
    let r = reach(&a.engine).await;
    assert_eq!(r["status"], "online", "{r}");
    assert_eq!(cloud.st.lock().unwrap().hellos.len(), 1, "the same link all along");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_set_up_again_gives_way_again() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    a.engine.reach.set_background(true);
    sign_in(&cloud, &a).await;
    open_from_web(&a.engine, true).await;
    until_reach(&a.engine, "online").await;
    // tTerm Web's installer run again meanwhile: the agent runs again,
    // with the same key.
    let dir = a.env.parent().unwrap().to_path_buf();
    std::fs::write(dir.join("tterm-agent"), "#!/bin/sh\n").unwrap();
    let mut agent = std::process::Command::new("sh").args(["-c", &format!("sleep 60; : {}/tterm-agent", dir.display())]).spawn().unwrap();
    std::fs::write(dir.join("agent.pid"), agent.id().to_string()).unwrap();
    assert!(until(10, || agent.try_wait().unwrap().is_some()).await, "the agent gave way");
    assert!(!dir.join("agent.pid").exists());
    assert_eq!(reach(&a.engine).await["status"], "online");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_and_off_at_once_end_off() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    until_reach(&a.engine, "off").await;
    cloud.st.lock().unwrap().slow.insert("/api/computers/this".into(), 1500);
    let e = a.engine.clone();
    let on = tokio::spawn(async move { open_from_web(&e, true).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Off while on still waits for tTerm: the last word stays.
    let (status, r) = open_from_web(&a.engine, false).await;
    assert_eq!((status, r["open"].clone(), r["status"].clone()), (200, json!(false), json!("off")), "{r}");
    assert_eq!(on.await.unwrap().0, 200);
    tokio::time::sleep(Duration::from_millis(800)).await;
    let r = reach(&a.engine).await;
    assert_eq!((r["open"].clone(), r["status"].clone()), (json!(false), json!("off")), "{r}");
    assert!(until(5, || cloud.links() == 0).await);
    let settings: Value = serde_json::from_slice(&std::fs::read(a.dir.join("settings.json")).unwrap()).unwrap();
    assert_eq!(settings["openFromWeb"], false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_out_while_turning_on_leaves_it_as_it_was() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    until_reach(&a.engine, "off").await;
    cloud.st.lock().unwrap().slow.insert("/api/computers/this".into(), 1500);
    let e = a.engine.clone();
    let on = tokio::spawn(async move { open_from_web(&e, true).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (status, _) = request(&a.engine, "POST", "/api/auth/signout", json!({})).await;
    assert_eq!(status, 200);
    let (status, r) = on.await.unwrap();
    assert_eq!(status, 409, "{r}");
    until_reach(&a.engine, "signed-out").await;
    let settings: Value = serde_json::from_slice(&std::fs::read(a.dir.join("settings.json")).unwrap()).unwrap();
    assert_ne!(settings["openFromWeb"], true, "{settings}");
    assert!(cloud.st.lock().unwrap().hellos.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_removed_agents_computer_is_off_and_on_gets_a_new_key() {
    let cloud = Cloud::start().await;
    let dir = common::data_dir();
    let env = dir.join("home").join(".tterm-web").join("env");
    let agent_dir = env.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&agent_dir).unwrap();
    // The agent heard its computer was removed: it forgot the key, said so,
    // and stopped.
    std::fs::write(&env, format!("TTERM_HUB={}\nTTERM_TOKEN=tok\nTTERM_NAME=lab\nTTERM_REMOVED=1\n", cloud.hub())).unwrap();
    std::fs::write(agent_dir.join("tterm-agent"), "#!/bin/sh\n").unwrap();
    let a = app_in(&cloud, dir, env.clone(), Arc::new(FakeHost::default())).await;
    a.engine.reach.set_timing(fast());
    a.engine.reach.set_background(true);
    sign_in(&cloud, &a).await;
    let r = until_reach(&a.engine, "off").await;
    assert_eq!(r["open"], false);
    assert!(until(5, || a.engine.reach.kept_now() == Some(false)).await);
    assert!(cloud.st.lock().unwrap().hellos.is_empty());
    // On: a new key, a new machine, open.
    let (status, r) = open_from_web(&a.engine, true).await;
    assert_eq!(status, 200, "{r}");
    until_reach(&a.engine, "online").await;
    let text = std::fs::read_to_string(&env).unwrap();
    assert!(!text.contains("TTERM_REMOVED") && text.contains("TTERM_NAME=lab"), "{text}");
    let key = env_key(&a);
    assert_eq!(cloud.st.lock().unwrap().hellos.last().unwrap()["key"], key.as_str());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_agents_file_gone_turns_it_off() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    open_from_web(&a.engine, true).await;
    until_reach(&a.engine, "online").await;
    // tTerm Web's uninstaller, while the app runs.
    std::fs::remove_file(&a.env).unwrap();
    let r = until_reach(&a.engine, "closed").await;
    assert!(r["problem"].as_str().unwrap().contains("is gone"), "{r}");
    assert_eq!(r["open"], false);
    assert!(until(5, || cloud.links() == 0).await);
    // On again, and the uninstaller once more, with the app not running:
    // off at the next start, and nothing opened.
    let (status, r) = open_from_web(&a.engine, true).await;
    assert_eq!(status, 200, "{r}");
    until_reach(&a.engine, "online").await;
    a.engine.reach.stop().await;
    std::fs::remove_file(&a.env).unwrap();
    let hellos = cloud.st.lock().unwrap().hellos.len();
    let b = app_in(&cloud, a.dir.clone(), a.env.clone(), a.host.clone()).await;
    b.engine.reach.set_timing(fast());
    let r = until_reach(&b.engine, "closed").await;
    assert!(r["problem"].as_str().unwrap().contains("is gone"), "{r}");
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(cloud.st.lock().unwrap().hellos.len(), hellos, "not opened again");
    assert_eq!(reach(&b.engine).await["open"], false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_keychain_that_cannot_be_read_leaves_the_login_item() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    a.engine.reach.set_timing(fast());
    sign_in(&cloud, &a).await;
    open_from_web(&a.engine, true).await;
    until_reach(&a.engine, "online").await;
    a.engine.reach.stop().await;
    // The next start: the keychain stays locked.
    a.host.load_fails.store(true, Ordering::SeqCst);
    let b = app_in(&cloud, a.dir.clone(), a.env.clone(), a.host.clone()).await;
    b.engine.reach.set_timing(fast());
    until_reach(&b.engine, "signed-out").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(b.engine.reach.kept_now(), None, "not known: the login item stays as it is");
    assert_eq!(reach(&b.engine).await["open"], true);
}

// ------------------------------------------- the vault of SSH keys (0.7.0)

/// The vault's local API, against the fake tTerm (vault.rs). These share a
/// temp home when they read ~/.ssh, so they take turns.
static HOME_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> = std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

async fn app_vault(e: &Arc<Engine>, method: &str, path: &str, body: Value) -> (u16, Value) {
    request(e, method, path, body).await
}

/// The checks' vault password (0.8.0), and another one.
const PASSWORD: &str = "correct horse battery staple";
const ANOTHER: &str = "Tr0ub4dor & 3 by the sea, été";

/// A new vault with the checks' password, as Move to cloud makes it.
async fn create_vault(e: &Arc<Engine>) {
    let (status, made) = app_vault(e, "POST", "/api/app/vault/create", json!({"password": PASSWORD})).await;
    assert_eq!(status, 200, "{made}");
}

/// The words of a Touch ID question, as the engine says them now.
fn reason(e: &Arc<Engine>, key: &'static str) -> String {
    tterm_engine::say::say(e.language_now(), key)
}

/// Another Mac of the same account: an app of its own, signed in.
async fn second_mac(cloud: &Cloud) -> (App, Arc<common::TestKeeper>) {
    let (b, keeper) = app_kept(cloud).await;
    sign_in(cloud, &b).await;
    (b, keeper)
}

/// The app's session ends in a browser (Devices › Forget), the app finds
/// out at its next call to tTerm, and the person signs in again: two epochs
/// on, while a vault request of the first one waits. The vault is not told
/// (no Sign out here), as when it happens while the request waits.
async fn signed_in_again(cloud: &Cloud, a: &App) {
    let before = a.engine.cloud.as_ref().unwrap().epoch_now();
    cloud.forget_devices();
    let (status, got) = request(&a.engine, "GET", "/api/account", Value::Null).await;
    assert_eq!((status, got["signedOut"].clone()), (401, json!(true)), "{got}");
    sign_in(cloud, a).await;
    assert!(a.engine.cloud.as_ref().unwrap().epoch_now() >= before + 2, "signed out, and in again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_vault_is_created_with_its_password_opened_and_locked() {
    use tterm_engine::crypto;
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    // Before: a Mac can hold a vault, none exists, it is not open.
    let (status, v) = app_vault(&a.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!((v["available"].clone(), v["exists"].clone(), v["open"].clone()), (json!(true), json!(false), json!(false)), "{v}");
    // The tTerm Web it is signed in to, as a browser's address bar has it:
    // Move to cloud's result says to open it from another computer.
    assert_eq!(v["web"], json!(cloud.base.trim_start_matches("http://")), "{v}");
    // No password, one that is no text, or one under 12 characters: 422
    // with a sentence, and nothing made.
    for body in [Value::Null, json!({"password": 123456789012u64}), json!({"password": "eleven char"})] {
        let (status, why) = app_vault(&a.engine, "POST", "/api/app/vault/create", body).await;
        assert_eq!(status, 422, "{why}");
        assert!(why["error"].as_str().unwrap().contains("12 characters"), "{why}");
    }
    assert!(cloud.st.lock().unwrap().vault.is_none(), "no vault made");
    // Made with the password the person has just made up: no Touch ID for
    // it, no recovery code, the vault held open.
    let (status, made) = app_vault(&a.engine, "POST", "/api/app/vault/create", json!({"password": PASSWORD})).await;
    assert_eq!((status, made.clone()), (200, json!({"open": true})), "{made}");
    assert!(keeper.reasons_since(0).is_empty(), "no Touch ID when the vault is made: {:?}", keeper.reasons_since(0));
    // What tTerm got: the password's salt, settings, proof and wrap, this
    // Mac's lock, and no recovery code.
    let posted = cloud.st.lock().unwrap().vault_posted.clone().unwrap();
    let vault_id = posted["id"].as_str().unwrap().to_string();
    assert!(uuid::Uuid::parse_str(&vault_id).is_ok(), "{posted}");
    assert!(posted.get("recoverySalt").is_none() && posted.get("recoveryWrap").is_none(), "no recovery code: {posted}");
    let password = &posted["password"];
    let bytes = |v: &Value| crypto::from_b64u(v.as_str().unwrap()).unwrap();
    assert_eq!(password["kdf"], json!({"alg": "argon2id", "m": 65536, "t": 3, "p": 1}), "{posted}");
    assert_eq!((bytes(&password["salt"]).len(), bytes(&password["auth"]).len(), bytes(&password["wrap"]).len()), (16, 32, 60), "{posted}");
    assert_eq!(password.as_object().unwrap().len(), 4, "salt, kdf, auth and wrap, nothing else: {password}");
    assert_eq!((posted["lock"]["kind"].clone(), bytes(&posted["lock"]["wrap"]).len()), (json!("app"), 60), "{posted}");
    // As the contract makes them: the proof and the KEK are the password's
    // with that salt, and its wrap holds the vault key of this Mac's lock.
    let salt = bytes(&password["salt"]);
    let keys = crypto::password_keys(&crypto::password_text(PASSWORD).unwrap(), &salt, &crypto::Kdf::NEW).unwrap();
    assert_eq!(bytes(&password["auth"]), keys.auth.as_slice(), "the proof");
    let vk = crypto::open_key(&keys.kek, &bytes(&password["wrap"]), &crypto::password_aad(&vault_id)).expect("the password's wrap opens");
    assert_eq!(*vk, vault_key_of(&cloud, &keeper), "one vault key");
    // tTerm keeps the proof's SHA-256, never the proof, and shows the salt
    // and the settings only.
    let shown = cloud.st.lock().unwrap().vault.clone().unwrap();
    let mut fields: Vec<&String> = shown["password"].as_object().unwrap().keys().collect();
    fields.sort();
    assert_eq!(fields, ["kdf", "salt", "setAt"], "{shown}");
    assert_eq!(cloud.st.lock().unwrap().password_check, Some(crypto::password_check(keys.auth.as_ref())));
    let (_, v) = app_vault(&a.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!((v["exists"].clone(), v["open"].clone()), (json!(true), json!(true)), "create holds it open: {v}");
    // Lock, then open again with Touch ID, from the keychain and tTerm's wrap.
    let (status, locked) = app_vault(&a.engine, "POST", "/api/app/vault/lock", Value::Null).await;
    assert_eq!((status, locked["open"].clone()), (200, json!(false)), "{locked}");
    let (status, opened) = app_vault(&a.engine, "POST", "/api/app/vault/open", Value::Null).await;
    assert_eq!((status, opened["open"].clone()), (200, json!(true)), "{opened}");
    assert_eq!(keeper.reasons_since(0), [reason(&a.engine, "vault.reason_open")]);
    // A second create is refused: one vault per account.
    let (status, _) = app_vault(&a.engine, "POST", "/api/app/vault/create", json!({"password": PASSWORD})).await;
    assert_eq!(status, 409);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_recovery_codes_are_made_any_more() {
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    let (status, why) = app_vault(&a.engine, "POST", "/api/app/vault/recovery", Value::Null).await;
    assert_eq!(status, 404, "{why}");
    assert!(keeper.reasons_since(0).is_empty(), "no Touch ID for it");
    assert_eq!(cloud.count("PUT", "/api/vault/recovery"), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_password_opens_the_vault_on_a_second_mac_then_touch_id_does() {
    let cloud = Cloud::start().await;
    let (a, a_keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    let (b, keeper) = second_mac(&cloud).await;
    let (_, v) = app_vault(&b.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!((v["exists"].clone(), v["open"].clone()), (json!(true), json!(false)), "{v}");
    // Touch ID opens nothing here yet: no lock of this Mac's, and the page
    // is told to open it with the password.
    let (status, why) = app_vault(&b.engine, "POST", "/api/app/vault/open", json!({})).await;
    assert_eq!(status, 409, "{why}");
    assert!(why["error"].as_str().unwrap().contains("vault password"), "{why}");
    let asked = keeper.auths();
    // A wrong one: 422 with the tries left, as tTerm counted it.
    let (status, why) = app_vault(&b.engine, "POST", "/api/app/vault/open", json!({"password": ANOTHER})).await;
    assert_eq!(status, 422, "{why}");
    assert_eq!((why["wrong"].clone(), why["left"].clone()), (json!(true), json!(9)), "{why}");
    assert!(!why["error"].as_str().unwrap().is_empty(), "{why}");
    // One that is no vault's password (under 12): not tried, no try spent.
    let (status, why) = app_vault(&b.engine, "POST", "/api/app/vault/open", json!({"password": "too short"})).await;
    assert_eq!(status, 422, "{why}");
    assert!(why.get("wrong").is_none(), "{why}");
    assert_eq!((cloud.count("POST", "/api/vault/password/open"), cloud.st.lock().unwrap().password_wrong), (1, 1));
    // The right one: open, with no Touch ID (the person has just typed the
    // password), and this Mac has its own lock now.
    let (status, opened) = app_vault(&b.engine, "POST", "/api/app/vault/open", json!({"password": PASSWORD})).await;
    assert_eq!((status, opened.clone()), (200, json!({"open": true})), "{opened}");
    assert_eq!(keeper.auths(), asked, "no Touch ID with the password");
    {
        let st = cloud.st.lock().unwrap();
        assert_eq!((st.locks_added, st.password_wrong), (1, 0), "its own lock; the count starts again");
    }
    assert_eq!(vault_key_of(&cloud, &keeper), vault_key_of(&cloud, &a_keeper), "the same vault key");
    // Locked, Touch ID alone opens it here now.
    app_vault(&b.engine, "POST", "/api/app/vault/lock", Value::Null).await;
    let (status, opened) = app_vault(&b.engine, "POST", "/api/app/vault/open", json!({})).await;
    assert_eq!(status, 200, "{opened}");
    assert_eq!(keeper.reasons_since(asked), [reason(&b.engine, "vault.reason_open")]);
    // Ten wrong ones in a row and tTerm pauses the tries, the right one's
    // too, saying until when; Touch ID opens it all the same.
    app_vault(&b.engine, "POST", "/api/app/vault/lock", Value::Null).await;
    for left in (0..10).rev() {
        let (status, why) = app_vault(&b.engine, "POST", "/api/app/vault/open", json!({"password": ANOTHER})).await;
        assert_eq!((status, why["wrong"].clone(), why["left"].clone()), (422, json!(true), json!(left)), "{why}");
    }
    for typed in [ANOTHER, PASSWORD] {
        let (status, why) = app_vault(&b.engine, "POST", "/api/app/vault/open", json!({"password": typed})).await;
        assert_eq!(status, 429, "{why}");
        assert_eq!((why["paused"].clone(), why["retryAt"].clone()), (json!(true), json!("2026-11-02T13:00:00Z")), "{why}");
        assert!(!why["error"].as_str().unwrap().is_empty() && why.get("wrong").is_none(), "{why}");
    }
    let (_, v) = app_vault(&b.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!(v["open"], false, "{v}");
    let (status, opened) = app_vault(&b.engine, "POST", "/api/app/vault/open", json!({})).await;
    assert_eq!(status, 200, "{opened}");
    assert_eq!(cloud.st.lock().unwrap().locks_added, 1, "its lock stays the one");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_password_replaces_the_old_with_touch_id() {
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    app_vault(&a.engine, "POST", "/api/app/vault/lock", Value::Null).await;
    let first_salt = cloud.st.lock().unwrap().vault.as_ref().unwrap()["password"]["salt"].clone();
    // Under 12 characters: refused before Touch ID is asked.
    let (status, why) = app_vault(&a.engine, "POST", "/api/app/vault/password", json!({"password": "short one"})).await;
    assert_eq!(status, 422, "{why}");
    assert!(why["error"].as_str().unwrap().contains("12 characters"), "{why}");
    assert_eq!(keeper.auths(), 0);
    // Touch ID refused: 403, and the password stays as it was.
    keeper.auth_fails.store(true, Ordering::SeqCst);
    let (status, why) = app_vault(&a.engine, "POST", "/api/app/vault/password", json!({"password": ANOTHER})).await;
    assert_eq!(status, 403, "{why}");
    assert!(why["error"].as_str().unwrap().contains("Touch ID"), "{why}");
    assert!(cloud.st.lock().unwrap().password_puts.is_empty());
    keeper.auth_fails.store(false, Ordering::SeqCst);
    // The new one: Touch ID once, in its own words, which also opens the
    // locked vault; a new salt, the real settings, and nothing else.
    let asked = keeper.auths();
    let (status, done) = app_vault(&a.engine, "POST", "/api/app/vault/password", json!({"password": ANOTHER})).await;
    assert_eq!((status, done.clone()), (200, json!({"ok": true})), "{done}");
    assert_eq!(keeper.reasons_since(asked), [reason(&a.engine, "vault.reason_password")], "Touch ID once, for the password");
    let (_, v) = app_vault(&a.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!(v["open"], true, "opened for it: {v}");
    let put = cloud.st.lock().unwrap().password_puts[0].clone();
    assert_eq!(put["kdf"], json!({"alg": "argon2id", "m": 65536, "t": 3, "p": 1}), "{put}");
    assert_eq!(put.as_object().unwrap().len(), 4, "salt, kdf, auth and wrap: {put}");
    assert_ne!(put["salt"], first_salt, "a new salt");
    // On another Mac the old password no longer opens the vault; the new one
    // does, typed with its accent as one letter or as two.
    let (b, _) = second_mac(&cloud).await;
    let (status, why) = app_vault(&b.engine, "POST", "/api/app/vault/open", json!({"password": PASSWORD})).await;
    assert_eq!((status, why["wrong"].clone()), (422, json!(true)), "{why}");
    let decomposed = ANOTHER.replace('\u{e9}', "e\u{301}");
    assert_ne!(decomposed, ANOTHER);
    let (status, opened) = app_vault(&b.engine, "POST", "/api/app/vault/open", json!({"password": decomposed})).await;
    assert_eq!(status, 200, "{opened}");
    // Changed again on that Mac, with its own lock and Touch ID.
    let (status, done) = app_vault(&b.engine, "POST", "/api/app/vault/password", json!({"password": PASSWORD})).await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(cloud.st.lock().unwrap().password_puts.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_password_of_an_old_vault_takes_its_recovery_codes_place() {
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    let code = "K7QF-29XM-PL4D-8VHT-R2NC-6WJB";
    let vk = [9u8; 32];
    cloud.st.lock().unwrap().vault = Some(browser_vault(&vk, code));
    let (status, opened) = app_vault(&a.engine, "POST", "/api/app/vault/open", json!({"recoveryCode": code})).await;
    assert_eq!(status, 200, "{opened}");
    app_vault(&a.engine, "POST", "/api/app/vault/lock", Value::Null).await;
    // Its first password, with Touch ID once: tTerm forgets the code.
    let asked = keeper.auths();
    let (status, done) = app_vault(&a.engine, "POST", "/api/app/vault/password", json!({"password": PASSWORD})).await;
    assert_eq!((status, done.clone()), (200, json!({"ok": true})), "{done}");
    assert_eq!(keeper.reasons_since(asked), [reason(&a.engine, "vault.reason_password")]);
    assert!(cloud.st.lock().unwrap().vault.as_ref().unwrap()["recoveryWrap"].is_null(), "the code is forgotten");
    // Another Mac: the code is no way in now, the password is, to the same
    // vault key the code opened.
    let (b, b_keeper) = second_mac(&cloud).await;
    let (status, why) = app_vault(&b.engine, "POST", "/api/app/vault/open", json!({"recoveryCode": code})).await;
    assert_eq!(status, 409, "{why}");
    assert!(why["error"].as_str().unwrap().contains("password"), "{why}");
    let (status, opened) = app_vault(&b.engine, "POST", "/api/app/vault/open", json!({"password": PASSWORD})).await;
    assert_eq!(status, 200, "{opened}");
    assert_eq!(vault_key_of(&cloud, &b_keeper), vk);
}

/// An app whose vault keeper the test can look into.
async fn app_kept(cloud: &Cloud) -> (App, Arc<common::TestKeeper>) {
    let dir = common::data_dir();
    let env = dir.join("home").join(".tterm-web").join("env");
    let keeper = common::TestKeeper::new();
    let host = Arc::new(FakeHost::default());
    let engine = Engine::with_cloud(&dir, &cloud.base, host.clone(), keeper.clone(), &env).expect("engine");
    engine.start_background();
    (App { engine, host, env, dir }, keeper)
}

/// The vault key, as this Mac's lock in the fake tTerm (the app lock the
/// keeper's KEK opens: there may be another Mac's too) gives it back.
fn vault_key_of(cloud: &Cloud, keeper: &common::TestKeeper) -> [u8; 32] {
    use tterm_engine::crypto;
    let vault = cloud.st.lock().unwrap().vault.clone().expect("a vault");
    let kek = crypto::key_of(&keeper.kek(vault["id"].as_str().unwrap()).expect("a KEK")).unwrap();
    let opens = |l: &Value| crypto::open_key(&kek, &crypto::from_b64u(l["wrap"].as_str()?)?, &crypto::lock_aad(l["id"].as_str()?));
    let vk = vault["locks"].as_array().unwrap().iter().filter(|l| l["kind"] == "app").find_map(opens).expect("this Mac's lock opens");
    *vk
}

/// A vault as a browser makes it (vault.py create_vault, no lock): its
/// recovery code's salt and wrap of `vk`, and a passkey lock of the
/// browser's, which is no lock of this Mac's.
fn browser_vault(vk: &[u8; 32], code: &str) -> Value {
    use tterm_engine::crypto::{self, b64u};
    let id = uuid::Uuid::new_v4().to_string();
    let salt = [5u8; 16];
    let kek = crypto::recovery_kek(&crypto::normalize_code(code).unwrap(), &salt);
    let wrap = crypto::seal(&kek, vk, &crypto::recovery_aad(&id));
    json!({"id": id, "prfSalt": "AAAA", "recoverySalt": b64u(&salt), "recoveryWrap": b64u(&wrap),
        "locks": [{"id": uuid::Uuid::new_v4().to_string(), "kind": "passkey", "label": "Safari on Mac", "wrap": b64u(&[1u8; 60]), "credentialId": "AAAA", "thisDevice": false}],
        "keys": []})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_without_touch_id_is_refused() {
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    app_vault(&a.engine, "POST", "/api/app/vault/lock", Value::Null).await;
    // The person cancels the LocalAuthentication: open is refused with 403
    // (not the 401 of a session that ended), and the gate was asked.
    keeper.auth_fails.store(true, std::sync::atomic::Ordering::SeqCst);
    let before = keeper.auths();
    let (status, why) = app_vault(&a.engine, "POST", "/api/app/vault/open", Value::Null).await;
    assert_eq!(status, 403, "{why}");
    assert!(why.get("signedOut").is_none(), "{why}");
    assert!(why["error"].as_str().unwrap().contains("Touch ID"), "{why}");
    assert!(keeper.auths() > before, "the gate was asked");
    let (_, v) = app_vault(&a.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!(v["open"], false, "{v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signing_out_forgets_the_vaults_key_locked_or_open() {
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    let vault_id = cloud.st.lock().unwrap().vault.as_ref().unwrap()["id"].as_str().unwrap().to_string();
    // Locked first: Sign out forgets the KEK all the same.
    app_vault(&a.engine, "POST", "/api/app/vault/lock", Value::Null).await;
    assert!(keeper.kek(&vault_id).is_some());
    let (status, out) = request(&a.engine, "POST", "/api/auth/signout", json!({})).await;
    assert_eq!(status, 200, "{out}");
    assert!(keeper.kek(&vault_id).is_none(), "the KEK is gone");
    let (_, v) = app_vault(&a.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!(v["open"], false, "{v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_forgotten_in_a_browser_locks_the_vault_here() {
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    let vault_id = cloud.st.lock().unwrap().vault.as_ref().unwrap()["id"].as_str().unwrap().to_string();
    let (_, v) = app_vault(&a.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!(v["open"], true);
    // Devices › Forget in a browser: the app's next call to tTerm finds its
    // device gone, and it is signed out here. The vault opened in that
    // account locks, its KEK goes, and the API says signed out.
    cloud.forget_devices();
    let (status, why) = app_vault(&a.engine, "POST", "/api/app/vault/password", json!({"password": ANOTHER})).await;
    assert_eq!(status, 401, "{why}");
    assert_eq!(why["signedOut"], true, "{why}");
    let (_, v) = app_vault(&a.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!(v["open"], false, "{v}");
    assert!(v["keys"].as_array().unwrap().is_empty());
    assert!(keeper.kek(&vault_id).is_none(), "the KEK is gone");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_password_waiting_for_touch_id_across_another_sign_in_goes_nowhere() {
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    let vault_id = cloud.st.lock().unwrap().vault.as_ref().unwrap()["id"].as_str().unwrap().to_string();
    // Touch ID is asked for the new password and waits for the person;
    // meanwhile the session ends in a browser and they sign in again. The
    // vault opened before is still held here: nothing has told it.
    keeper.hold();
    let e = a.engine.clone();
    let asked = tokio::spawn(async move { app_vault(&e, "POST", "/api/app/vault/password", json!({"password": ANOTHER})).await });
    assert!(until(10, || keeper.waiting() == 1).await, "Touch ID is asked");
    signed_in_again(&cloud, &a).await;
    keeper.release();
    let (status, why) = asked.await.unwrap();
    // The request is of the account before: signed out, as a session that
    // ended (changes 23, 50), and no new password went to tTerm in the new
    // session; the vault opened before is locked and its KEK forgotten.
    assert_eq!((status, why["signedOut"].clone()), (401, json!(true)), "{why}");
    assert_eq!(keeper.reasons_since(0), [reason(&a.engine, "vault.reason_password")]);
    assert_eq!(cloud.count("PUT", "/api/vault/password"), 0);
    assert!(cloud.st.lock().unwrap().password_puts.is_empty());
    let (_, v) = app_vault(&a.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!((v["exists"].clone(), v["open"].clone()), (json!(true), json!(false)), "{v}");
    assert!(keeper.kek(&vault_id).is_none(), "the KEK is gone");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_password_answered_after_another_sign_in_opens_nothing() {
    let cloud = Cloud::start().await;
    let (a, _) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    let (b, keeper) = second_mac(&cloud).await;
    // On a second Mac, tTerm's answer for the right password comes late:
    // after the session ended and the person signed in again.
    cloud.st.lock().unwrap().slow.insert("POST /api/vault/password/open".into(), 3000);
    let e = b.engine.clone();
    let opening = tokio::spawn(async move { app_vault(&e, "POST", "/api/app/vault/open", json!({"password": PASSWORD})).await });
    assert!(until(30, || cloud.count("POST", "/api/vault/password/open") == 1).await, "the password is tried");
    signed_in_again(&cloud, &b).await;
    let (status, why) = opening.await.unwrap();
    // Signed out; no lock of this Mac's added in the new session, no KEK
    // kept, and the vault not open.
    assert_eq!((status, why["signedOut"].clone()), (401, json!(true)), "{why}");
    assert_eq!(cloud.count("POST", "/api/vault/locks"), 0);
    assert_eq!(cloud.st.lock().unwrap().locks_added, 0);
    assert_eq!(keeper.keks(), 0, "no KEK kept");
    let (_, v) = app_vault(&b.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!(v["open"], false, "{v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_vault_made_across_another_sign_in_is_not_kept() {
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    // tTerm says late that the account has no vault yet: the person signed
    // in again meanwhile. Nothing is made, in either session.
    cloud.st.lock().unwrap().slow.insert("GET /api/vault".into(), 3000);
    let e = a.engine.clone();
    let making = tokio::spawn(async move { app_vault(&e, "POST", "/api/app/vault/create", json!({"password": PASSWORD})).await });
    assert!(until(10, || cloud.count("GET", "/api/vault") == 1).await, "tTerm is asked");
    signed_in_again(&cloud, &a).await;
    let (status, why) = making.await.unwrap();
    assert_eq!((status, why["signedOut"].clone()), (401, json!(true)), "{why}");
    assert!(cloud.st.lock().unwrap().vault_posted.is_none(), "no vault posted");
    assert_eq!(keeper.keks(), 0, "no KEK kept");
    // Now tTerm's answer to the vault itself comes late: tTerm made it in
    // the session it was asked in, and this Mac keeps nothing of it.
    cloud.st.lock().unwrap().slow = HashMap::from([("POST /api/vault".to_string(), 3000)]);
    let e = a.engine.clone();
    let making = tokio::spawn(async move { app_vault(&e, "POST", "/api/app/vault/create", json!({"password": PASSWORD})).await });
    assert!(until(30, || cloud.st.lock().unwrap().vault_posted.is_some()).await, "the vault is posted");
    signed_in_again(&cloud, &a).await;
    let (status, why) = making.await.unwrap();
    assert_eq!((status, why["signedOut"].clone()), (401, json!(true)), "{why}");
    assert_eq!(keeper.keks(), 0, "its KEK is forgotten");
    let (_, v) = app_vault(&a.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!((v["exists"].clone(), v["open"].clone()), (json!(true), json!(false)), "{v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_password_that_gives_another_vault_key_than_this_macs_lock_opens_nothing() {
    use tterm_engine::crypto;
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    app_vault(&a.engine, "POST", "/api/app/vault/lock", Value::Null).await;
    let (vault_id, salt, right_wrap) = {
        let st = cloud.st.lock().unwrap();
        let v = st.vault.as_ref().unwrap();
        (v["id"].as_str().unwrap().to_string(), crypto::from_b64u(v["password"]["salt"].as_str().unwrap()).unwrap(), st.password_wrap.clone().unwrap())
    };
    let kek = keeper.kek(&vault_id).expect("this Mac's KEK");
    // For the right password tTerm hands out the wrap of another vault key:
    // it opens with the password, and holds not the key this Mac's own lock
    // holds. One of the two was replaced: neither is taken.
    let keys = crypto::password_keys(&crypto::password_text(PASSWORD).unwrap(), &salt, &crypto::Kdf::NEW).unwrap();
    let another = crypto::seal(&keys.kek, &[7u8; 32], &crypto::password_aad(&vault_id));
    cloud.st.lock().unwrap().password_wrap = Some(crypto::b64u(&another));
    let (status, why) = app_vault(&a.engine, "POST", "/api/app/vault/open", json!({"password": PASSWORD})).await;
    assert_eq!(status, 502, "{why}");
    assert!(why["error"].as_str().unwrap().starts_with("Your vault's locks do not agree: "), "{why}");
    assert!(why.get("signedOut").is_none() && why.get("wrong").is_none(), "{why}");
    // Locked, and nothing kept or added: no new lock, the keychain item as
    // it was, this Mac's lock the vault's only one.
    let (_, v) = app_vault(&a.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!((v["open"].clone(), v["keys"].clone()), (json!(false), json!([])), "{v}");
    assert_eq!(cloud.count("POST", "/api/vault/locks"), 0);
    assert_eq!(cloud.st.lock().unwrap().vault.as_ref().unwrap()["locks"].as_array().unwrap().len(), 1);
    assert_eq!(keeper.kek(&vault_id).as_ref(), Some(&kek), "the KEK stays as it was");
    // The right wrap again: the password opens the vault, this Mac's lock
    // kept as its own.
    cloud.st.lock().unwrap().password_wrap = Some(right_wrap);
    let (status, opened) = app_vault(&a.engine, "POST", "/api/app/vault/open", json!({"password": PASSWORD})).await;
    assert_eq!((status, opened.clone()), (200, json!({"open": true})), "{opened}");
    assert_eq!(cloud.count("POST", "/api/vault/locks"), 0, "its own lock kept");
    assert_eq!(keeper.kek(&vault_id), Some(kek));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_vault_made_in_a_browser_opens_once_with_the_code_then_with_touch_id() {
    use tterm_engine::crypto;
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    let vk = [9u8; 32];
    let vault = browser_vault(&vk, "K7QF-29XM-PL4D-8VHT-R2NC-6WJB");
    let vault_id = vault["id"].as_str().unwrap().to_string();
    cloud.st.lock().unwrap().vault = Some(vault);
    let (_, v) = app_vault(&a.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!((v["exists"].clone(), v["open"].clone()), (json!(true), json!(false)), "{v}");

    // Without the code: this Mac has no lock of it, and Touch ID is not
    // asked for nothing.
    let before = keeper.auths();
    let (status, why) = app_vault(&a.engine, "POST", "/api/app/vault/open", json!({})).await;
    assert_eq!(status, 409, "{why}");
    assert!(why["error"].as_str().unwrap().contains("recovery code"), "{why}");
    assert_eq!(keeper.auths(), before);
    // With a password, which it has none of yet: 409, nothing tried.
    let (status, why) = app_vault(&a.engine, "POST", "/api/app/vault/open", json!({"password": PASSWORD})).await;
    assert_eq!(status, 409, "{why}");
    assert!(why["error"].as_str().unwrap().contains("no password"), "{why}");
    assert_eq!(cloud.count("POST", "/api/vault/password/open"), 0);
    assert_eq!(keeper.auths(), before);
    // Not a code, or another vault's: 422, and no lock.
    let (status, why) = app_vault(&a.engine, "POST", "/api/app/vault/open", json!({"recoveryCode": "not a code"})).await;
    assert_eq!(status, 422, "{why}");
    let (status, why) = app_vault(&a.engine, "POST", "/api/app/vault/open", json!({"recoveryCode": "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"})).await;
    assert_eq!(status, 422, "{why}");
    assert_eq!(cloud.st.lock().unwrap().locks_added, 0);
    assert_eq!(keeper.auths(), before, "a wrong code asks no Touch ID");

    // The right one, as a person might type it: open, and this Mac has its
    // own lock now, whose wrap opens with the KEK it kept.
    let (status, opened) = app_vault(&a.engine, "POST", "/api/app/vault/open", json!({"recoveryCode": "k7qf 29xm pl4d 8vht r2nc 6wjb"})).await;
    assert_eq!(status, 200, "{opened}");
    assert_eq!(opened["open"], true);
    assert_eq!(keeper.auths(), before + 1, "Touch ID once, for this Mac's lock");
    assert_eq!(cloud.st.lock().unwrap().locks_added, 1);
    assert_eq!(vault_key_of(&cloud, &keeper), vk, "the lock holds the vault key");
    let lock_id = cloud.st.lock().unwrap().vault.as_ref().unwrap()["locks"].as_array().unwrap().iter().find(|l| l["kind"] == "app").unwrap()["id"].as_str().unwrap().to_string();
    let lock = cloud.st.lock().unwrap().vault.as_ref().unwrap()["locks"].as_array().unwrap().iter().find(|l| l["kind"] == "app").unwrap().clone();
    assert!(lock["label"].as_str().unwrap().starts_with("tTerm for ") && lock["label"].as_str().unwrap().contains(" on "), "{lock}");
    assert_eq!(crypto::from_b64u(lock["wrap"].as_str().unwrap()).unwrap().len(), 60);

    // Locked, it opens again with Touch ID alone, and the lock is said used.
    app_vault(&a.engine, "POST", "/api/app/vault/lock", Value::Null).await;
    let (status, opened) = app_vault(&a.engine, "POST", "/api/app/vault/open", json!({})).await;
    assert_eq!(status, 200, "{opened}");
    assert_eq!(keeper.auths(), before + 2);
    assert!(until(5, || cloud.st.lock().unwrap().lock_used.contains(&lock_id)).await, "the lock was said used");
    // The code again, with a lock here: the lock stays the one.
    app_vault(&a.engine, "POST", "/api/app/vault/lock", Value::Null).await;
    let (status, _) = app_vault(&a.engine, "POST", "/api/app/vault/open", json!({"recoveryCode": "K7QF-29XM-PL4D-8VHT-R2NC-6WJB"})).await;
    assert_eq!(status, 200);
    assert_eq!(cloud.st.lock().unwrap().locks_added, 1, "no second lock");
    assert!(keeper.kek(&vault_id).is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn this_macs_lock_taken_off_in_a_browser_locks_the_vault_here() {
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    let vault_id = cloud.st.lock().unwrap().vault.as_ref().unwrap()["id"].as_str().unwrap().to_string();
    assert!(keeper.kek(&vault_id).is_some());
    // In a browser's Settings › Keys this Mac's lock is taken off; tTerm
    // says vault.changed, and the engine reads the vault again.
    {
        let mut st = cloud.st.lock().unwrap();
        let v = st.vault.as_mut().unwrap();
        v["locks"] = json!([{"id": uuid::Uuid::new_v4().to_string(), "kind": "passkey", "label": "Safari", "wrap": tterm_engine::crypto::b64u(&[1u8; 60]), "credentialId": "AAAA", "thisDevice": false}]);
    }
    let vault = a.engine.vault.clone().unwrap();
    vault.reload(&a.engine).await;
    let (_, v) = app_vault(&a.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!(v["open"], false, "locked here: {v}");
    assert!(keeper.kek(&vault_id).is_none(), "its KEK is no use and is gone");
    let (status, why) = app_vault(&a.engine, "POST", "/api/app/vault/open", json!({})).await;
    assert_eq!(status, 409, "{why}");
    assert!(why["error"].as_str().unwrap().contains("vault password"), "{why}");
    // The password gives this Mac a new lock, and Touch ID opens it again.
    let (status, opened) = app_vault(&a.engine, "POST", "/api/app/vault/open", json!({"password": PASSWORD})).await;
    assert_eq!(status, 200, "{opened}");
    assert!(keeper.kek(&vault_id).is_some(), "a new KEK");
    app_vault(&a.engine, "POST", "/api/app/vault/lock", Value::Null).await;
    let (status, opened) = app_vault(&a.engine, "POST", "/api/app/vault/open", json!({})).await;
    assert_eq!(status, 200, "{opened}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_browser_is_paired_while_the_vault_is_locked() {
    use tterm_engine::crypto;
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    app_vault(&a.engine, "POST", "/api/app/vault/lock", Value::Null).await;
    let id = "abcdefab-cdef-4abc-8def-0123456789ab";
    let (pub_b, priv_b) = x25519_pair();
    let commit = crypto::b64u(&crypto::commit_of(&pub_b));
    cloud.st.lock().unwrap().pairings.insert(id.to_string(), json!({"id": id, "state": "waiting", "commit": commit, "_pubB": crypto::b64u(&pub_b)}));
    // The page answers as soon as the request comes, the vault locked: the
    // six digits, and no Touch ID for that.
    let before = keeper.auths();
    let (status, ans) = app_vault(&a.engine, "POST", &format!("/api/app/vault/pairings/{id}/answer"), Value::Null).await;
    assert_eq!(status, 200, "{ans}");
    assert_eq!(keeper.auths(), before);
    // Asked again (the page shown twice), the same digits: pubA is posted
    // once (the fake, as the core, takes an answer once).
    let (status, again) = app_vault(&a.engine, "POST", &format!("/api/app/vault/pairings/{id}/answer"), Value::Null).await;
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["sas"], ans["sas"]);
    // Allow: one Touch ID opens the vault and seals its key for the browser.
    let (status, done) = app_vault(&a.engine, "POST", &format!("/api/app/vault/pairings/{id}/approve"), Value::Null).await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(keeper.auths(), before + 1, "one Touch ID");
    let (_, v) = app_vault(&a.engine, "GET", "/api/app/vault", Value::Null).await;
    assert_eq!(v["open"], true, "opened for it: {v}");
    let pairing = cloud.st.lock().unwrap().pairings.get(id).cloned().unwrap();
    assert_eq!(pairing["state"], "approved");
    let pub_a = crypto::from_b64u(pairing["pubA"].as_str().unwrap()).unwrap();
    let kek = crypto::pair_kek(&x25519_agree(&priv_b, &pub_a), &pub_a, &pub_b);
    let vk = crypto::open_key(&kek, &crypto::from_b64u(pairing["sealed"].as_str().unwrap()).unwrap(), &crypto::pair_aad(id)).expect("the browser opens it");
    assert_eq!(*vk, vault_key_of(&cloud, &keeper), "the vault's own key");
    // Over: a second Allow is refused.
    let (status, _) = app_vault(&a.engine, "POST", &format!("/api/app/vault/pairings/{id}/approve"), Value::Null).await;
    assert_eq!(status, 409);
}

/// A key of the vault for the socket's checks: the asyncssh Ed25519 case of
/// tests/userauth-vectors.json, sealed with the vault's key into the fake
/// tTerm's vault. Its fingerprint, and a login it really signed.
fn seal_vector_key(cloud: &Cloud, vk: &[u8; 32]) -> (String, Value) {
    use tterm_engine::crypto;
    let vectors: Value = serde_json::from_str(include_str!("userauth-vectors.json")).unwrap();
    let case = vectors["cases"].as_array().unwrap().iter().find(|c| c["key"] == "id_ed25519" && c["source"].as_str().unwrap().starts_with("asyncssh")).unwrap().clone();
    let plaintext = case["plaintext"].as_str().unwrap();
    let fingerprint = tterm_engine::sshkeys::fingerprint(plaintext.as_bytes()).unwrap();
    let key_id = uuid::Uuid::new_v4().to_string();
    let sealed = crypto::seal(vk, plaintext.as_bytes(), &crypto::key_aad(&key_id));
    let key = json!({"id": key_id, "name": "id_ed25519", "type": "ssh-ed25519", "publicKey": case["publicKey"], "fingerprint": fingerprint, "sealed": crypto::b64u(&sealed), "source": "file", "servers": []});
    cloud.st.lock().unwrap().vault.as_mut().unwrap()["keys"].as_array_mut().unwrap().push(key);
    (fingerprint, case)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_engine_signs_logins_on_the_socket_and_nothing_else() {
    use tterm_engine::crypto;
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    let (fingerprint, case) = seal_vector_key(&cloud, &vault_key_of(&cloud, &keeper));
    let login = case["data"].as_str().unwrap().to_string();
    let arbitrary = crypto::b64u(b"an SSHSIG, a git commit, a challenge of anything");
    let mut trailing = crypto::from_b64u(&login).unwrap();
    trailing.push(0);
    cloud.st.lock().unwrap().sign_requests = vec![
        ("sign-any".into(), fingerprint.clone(), "ssh-ed25519".into(), arbitrary),
        ("sign-trailing".into(), fingerprint.clone(), "ssh-ed25519".into(), crypto::b64u(&trailing)),
        ("sign-alg".into(), fingerprint.clone(), "rsa-sha2-256".into(), login.clone()),
        ("sign-login".into(), fingerprint.clone(), "ssh-ed25519".into(), login.clone()),
    ];
    // The page opens its socket and attaches nothing: the engine's socket
    // on tTerm is up all the same. tTerm says vault.changed (the key added
    // in a browser) and the engine reads the vault again: then it announces
    // the key, and the page hears vault.changed after that.
    let mut page = Page::new(&a.engine);
    cloud.st.lock().unwrap().push.push(json!({"op": "vault.changed"}));
    assert!(until(10, || cloud.st.lock().unwrap().signed.len() >= 4).await, "the engine answered: {:?}", cloud.st.lock().unwrap().signed);
    let signed = cloud.st.lock().unwrap().signed.clone();
    let by_id = |id: &str| signed.iter().find(|m| m["id"] == id).cloned().unwrap();
    assert_eq!(by_id("sign-any")["op"], "vault.unable", "not a login");
    assert_eq!(by_id("sign-trailing")["op"], "vault.unable", "bytes after the login");
    assert_eq!(by_id("sign-alg")["op"], "vault.unable", "another algorithm than the login's");
    let ok = by_id("sign-login");
    assert_eq!(ok["op"], "vault.signed", "{ok}");
    let sig = crypto::from_b64u(ok["sig"].as_str().unwrap()).unwrap();
    verify_ed25519(case["publicKey"].as_str().unwrap(), &crypto::from_b64u(&login).unwrap(), &sig);
    // The page never saw a vault.sign; it heard vault.changed.
    assert!(page.until(5, |p| p.msgs.iter().any(|m| m["op"] == "vault.changed")).await, "{:?}", page.msgs);
    assert!(!page.msgs.iter().any(|m| m["op"] == "vault.sign"), "the sign requests stayed in the engine");
    // The page's own vault.can joins the engine's in what tTerm hears.
    page.send(json!({"op": "vault.can", "keys": ["SHA256:the-pages-own"]})).await;
    assert!(until(5, || cloud.st.lock().unwrap().cans.iter().any(|c| c.contains(&fingerprint) && c.contains(&"SHA256:the-pages-own".to_string()))).await, "{:?}", cloud.st.lock().unwrap().cans);
    // Locked: the key is no longer announced.
    app_vault(&a.engine, "POST", "/api/app/vault/lock", Value::Null).await;
    assert!(until(5, || cloud.st.lock().unwrap().cans.last().map(|c| !c.contains(&fingerprint)).unwrap_or(false)).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_browser_is_paired_from_the_mac() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    // The new browser makes its X25519 pair and seeds a waiting pairing
    // with its commit and the pubB it will reveal.
    let id = "abcdefab-cdef-4abc-8def-abcdefabcdef";
    let (pub_b, priv_b) = x25519_pair();
    let commit = tterm_engine::crypto::b64u(&tterm_engine::crypto::commit_of(&pub_b));
    cloud.st.lock().unwrap().pairings.insert(id.to_string(), json!({"id": id, "state": "waiting", "commit": commit, "_pubB": tterm_engine::crypto::b64u(&pub_b)}));
    // The Mac answers: posts pubA, waits for pubB, returns the six digits.
    let (status, ans) = app_vault(&a.engine, "POST", &format!("/api/app/vault/pairings/{id}/answer"), Value::Null).await;
    assert_eq!(status, 200, "{ans}");
    let sas = ans["sas"].as_str().unwrap();
    assert_eq!(sas.len(), 7, "{sas}");
    // Approve: the Mac seals the vault key for the browser.
    let (status, done) = app_vault(&a.engine, "POST", &format!("/api/app/vault/pairings/{id}/approve"), Value::Null).await;
    assert_eq!(status, 200, "{done}");
    let pairing = cloud.st.lock().unwrap().pairings.get(id).cloned().unwrap();
    assert_eq!(pairing["state"], "approved");
    // The six digits match what the browser works out from both public keys.
    let pub_a = tterm_engine::crypto::from_b64u(pairing["pubA"].as_str().unwrap()).unwrap();
    assert_eq!(sas, tterm_engine::crypto::sas_of(&pub_a, &pub_b));
    // The browser opens the sealed vault key with the shared secret.
    let sealed = tterm_engine::crypto::from_b64u(pairing["sealed"].as_str().unwrap()).unwrap();
    let shared = x25519_agree(&priv_b, &pub_a);
    let kek = tterm_engine::crypto::pair_kek(&shared, &pub_a, &pub_b);
    let vk = tterm_engine::crypto::open_key(&kek, &sealed, &tterm_engine::crypto::pair_aad(id));
    assert!(vk.is_some(), "the browser gets the vault key");
}

/// The fake ssh of the move checks: `ssh -G` is the real ssh's; a login is
/// played as TTERM_FAKE_SSH_* say, and written down in the log: the
/// arguments, what the askpass helper answered to a passphrase question and
/// to two others it must refuse, and for `sh -s` the script runs here with
/// the fake server's home as HOME.
const FAKE_SSH: &str = r#"#!/bin/sh
log="${TTERM_FAKE_SSH_LOG:-/dev/null}"
for a in "$@"; do
  if [ "$a" = "-G" ]; then exec "$TTERM_FAKE_SSH_REAL" "$@"; fi
done
printf 'ssh' >> "$log"; for a in "$@"; do printf ' [%s]' "$a" >> "$log"; done; printf '\n' >> "$log"
key=""; verbose=""
while [ $# -gt 0 ]; do
  case "$1" in
    --) shift; break ;;
    -i) key="$2"; shift ;;
    -v) verbose=1 ;;
    -o|-F|-p|-l|-J|-E) shift ;;
  esac
  shift
done
alias="$1"; shift
if [ -n "${SSH_ASKPASS:-}" ] && [ "${SSH_ASKPASS_REQUIRE:-}" = force ]; then
  if answer=$("$SSH_ASKPASS" "Enter passphrase for key '$key': "); then printf 'askpass passphrase [%s]\n' "$answer" >> "$log"; else printf 'askpass passphrase refused\n' >> "$log"; fi
  if answer=$("$SSH_ASKPASS" "deploy@$alias's password: "); then printf 'askpass password ANSWERED [%s]\n' "$answer" >> "$log"; else printf 'askpass password refused\n' >> "$log"; fi
  if answer=$(SSH_ASKPASS_PROMPT=confirm "$SSH_ASKPASS" "Allow use of key $key?"); then printf 'askpass confirm ANSWERED [%s]\n' "$answer" >> "$log"; else printf 'askpass confirm refused\n' >> "$log"; fi
fi
if [ -n "${TTERM_FAKE_SSH_FAIL:-}" ]; then echo "deploy@$alias: Permission denied (publickey)." >&2; exit 255; fi
if [ -n "$verbose" ] && [ -n "${TTERM_FAKE_SSH_FP:-}" ]; then
  echo "debug1: Server accepts key: $key ED25519 $TTERM_FAKE_SSH_FP explicit" >&2
fi
if [ "${1:-}" = sh ] && [ "${2:-}" = -s ]; then
  mkdir -p "$TTERM_FAKE_SSH_REMOTE"
  HOME="$TTERM_FAKE_SSH_REMOTE" exec /bin/sh -s
fi
exit 0
"#;

/// A temp home with ~/.ssh for the move checks, the fake ssh, and the fake
/// server's home; the environment the engine reads them from is put back as
/// it was when this goes. Made under HOME_LOCK.
struct SshLab {
    root: PathBuf,
    home: PathBuf,
    remote: PathBuf,
    log: PathBuf,
    keygen: PathBuf,
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

const LAB_VARS: [&str; 7] = ["TTERM_SSH_HOME", "TTERM_SSH", "TTERM_FAKE_SSH_REAL", "TTERM_FAKE_SSH_LOG", "TTERM_FAKE_SSH_REMOTE", "TTERM_FAKE_SSH_FP", "TTERM_FAKE_SSH_FAIL"];

impl SshLab {
    /// None where OpenSSH is not there to make keys and read configs.
    fn new() -> Option<SshLab> {
        let keygen = ssh_keygen()?;
        let real = which("ssh", "TTERM_SSH")?;
        let root = common::data_dir().join("sshlab");
        let (home, remote, log) = (root.join("home"), root.join("server"), root.join("ssh.log"));
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let fake = root.join("fake-ssh");
        std::fs::write(&fake, FAKE_SSH).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let saved = LAB_VARS.iter().map(|k| (*k, std::env::var_os(k))).collect();
        std::env::set_var("TTERM_SSH_HOME", &home);
        std::env::set_var("TTERM_SSH", &fake);
        std::env::set_var("TTERM_FAKE_SSH_REAL", &real);
        std::env::set_var("TTERM_FAKE_SSH_LOG", &log);
        std::env::set_var("TTERM_FAKE_SSH_REMOTE", &remote);
        std::env::remove_var("TTERM_FAKE_SSH_FP");
        std::env::remove_var("TTERM_FAKE_SSH_FAIL");
        Some(SshLab { root, home, remote, log, keygen, saved })
    }

    /// An Ed25519 key in ~/.ssh, with the passphrase given ("" for none).
    fn key(&self, name: &str, passphrase: &str) -> PathBuf {
        let path = self.home.join(".ssh").join(name);
        assert!(std::process::Command::new(&self.keygen).args(["-t", "ed25519", "-f"]).arg(&path).args(["-N", passphrase, "-C", "lab", "-q"]).status().unwrap().success());
        path
    }

    fn write(&self, name: &str, text: &str) {
        std::fs::write(self.home.join(".ssh").join(name), text).unwrap();
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn server_keys(&self) -> String {
        std::fs::read_to_string(self.remote.join(".ssh").join("authorized_keys")).unwrap_or_default()
    }

    fn set(&self, var: &str, value: Option<&str>) {
        match value {
            Some(v) => std::env::set_var(var, v),
            None => std::env::remove_var(var),
        }
    }
}

impl Drop for SshLab {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

const LAB_HOST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISERVERKEYEXAMPLE000000000000000000000000";

/// Servers of the lab: web-01 and web-02 sign in with `key`, lab-box too
/// but has no host key here.
fn lab_config(lab: &SshLab, key: &std::path::Path) {
    lab.write("config", &format!("Host web-01\n  HostName 203.0.113.9\n  User deploy\n  IdentityFile \"{k}\"\n\nHost web-02\n  HostName 203.0.113.10\n  User deploy\n  IdentityFile ~/.ssh/{n}\n\nHost lab-box\n  HostName 203.0.113.11\n  User root\n", k = key.display(), n = key.file_name().unwrap().to_string_lossy()));
    lab.write("known_hosts", &format!("203.0.113.9 {LAB_HOST_KEY}\n203.0.113.10 {LAB_HOST_KEY}\n"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn moving_a_server_signs_in_with_its_key_then_seals_it_once() {
    use tterm_engine::crypto;
    let _home = HOME_LOCK.lock().await;
    let Some(lab) = SshLab::new() else {
        eprintln!("OpenSSH not found: skipping");
        return;
    };
    let cloud = Cloud::start().await;
    let (a, keeper) = app_kept(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    // Not one of ssh's default names: lab-box (no IdentityFile) has no key.
    let key_path = lab.key("work_key", "");
    let pub_line = std::fs::read_to_string(key_path.with_extension("pub")).unwrap();
    lab_config(&lab, &key_path);

    // GET /api/app/ssh: the servers with their key, as ~/… the same way in
    // identityFiles, keys[].path and key.
    let (status, listed) = app_vault(&a.engine, "GET", "/api/app/ssh", Value::Null).await;
    assert_eq!(status, 200, "{listed}");
    let host = |alias: &str| listed["hosts"].as_array().unwrap().iter().find(|h| h["alias"] == alias).cloned().unwrap_or_else(|| panic!("{alias} listed: {listed}"));
    let web = host("web-01");
    assert_eq!((web["host"].clone(), web["user"].clone(), web["hostKeys"][0].clone()), (json!("203.0.113.9"), json!("deploy"), json!(LAB_HOST_KEY)));
    assert_eq!(web["identityFiles"][0], "~/.ssh/work_key", "{web}");
    assert_eq!(web["key"], "~/.ssh/work_key", "{web}");
    assert_eq!(host("web-02")["key"], "~/.ssh/work_key");
    assert_eq!(host("web-02")["identityFiles"][0], "~/.ssh/work_key");
    assert!(host("lab-box")["key"].is_null(), "no key of its own here: {}", host("lab-box"));
    let listed_key = listed["keys"].as_array().unwrap().iter().find(|k| k["path"] == "~/.ssh/work_key").cloned().expect("the key listed");
    assert_eq!((listed_key["movable"].clone(), listed_key["type"].clone(), listed_key["encrypted"].clone()), (json!(true), json!("ssh-ed25519"), json!(false)));
    let fingerprint = listed_key["fingerprint"].as_str().unwrap().to_string();
    lab.set("TTERM_FAKE_SSH_FP", Some(&fingerprint));

    // Move web-01 with its key ticked: a login with that key alone first,
    // then the key sealed and uploaded, then the machine.
    let body = json!({"project": "p1", "servers": [{"alias": "web-01", "method": "key"}], "keys": [{"path": "~/.ssh/work_key"}]});
    let (status, moved) = app_vault(&a.engine, "POST", "/api/app/move", body).await;
    assert_eq!(status, 200, "{moved}");
    assert_eq!(moved["results"][0]["ok"], true, "{moved}");
    let log = lab.log();
    let login = log.lines().find(|l| l.contains("[web-01] [true]")).unwrap_or_else(|| panic!("a login: {log}"));
    assert!(login.contains(&format!("[-i] [{}]", key_path.display())) && login.contains("[IdentitiesOnly=yes]") && login.contains("[BatchMode=yes]"), "{login}");
    let vault = cloud.st.lock().unwrap().vault.clone().unwrap();
    assert_eq!(vault["keys"].as_array().unwrap().len(), 1);
    let key = vault["keys"][0].clone();
    assert_eq!((key["type"].clone(), key["fingerprint"].clone(), key["source"].clone()), (json!("ssh-ed25519"), json!(fingerprint), json!("mac")));
    assert_eq!(first_two(key["publicKey"].as_str().unwrap()), first_two(&pub_line));
    let own = cloud.st.lock().unwrap().own[0].clone();
    assert_eq!((own["method"].clone(), own["keyId"].clone()), (json!("key"), key["id"].clone()));
    // The sealed box opens with the vault key to the key's plaintext.
    let vk = vault_key_of(&cloud, &keeper);
    let plain = crypto::open(&vk, &crypto::from_b64u(key["sealed"].as_str().unwrap()).unwrap(), &crypto::key_aad(key["id"].as_str().unwrap())).expect("opens");
    assert_eq!(tterm_engine::sshkeys::fingerprint(&plain).as_deref(), Some(fingerprint.as_str()));

    // web-02 has the same key: the vault's is used, nothing uploaded again.
    let body = json!({"project": "p1", "servers": [{"alias": "web-02", "method": "key"}], "keys": []});
    let (status, moved) = app_vault(&a.engine, "POST", "/api/app/move", body).await;
    assert_eq!(status, 200, "{moved}");
    assert_eq!(moved["results"][0]["ok"], true, "{moved}");
    assert_eq!(cloud.st.lock().unwrap().vault.as_ref().unwrap()["keys"].as_array().unwrap().len(), 1);
    assert_eq!(cloud.st.lock().unwrap().own[1]["keyId"], key["id"]);

    // The engine signs a login with the moved key on the page's socket.
    let blob = base64_decode(pub_line.split_whitespace().nth(1).unwrap());
    let data = userauth(&[7u8; 32], "deploy", "ssh-ed25519", &blob);
    cloud.st.lock().unwrap().sign_requests = vec![("sign-1".into(), fingerprint.clone(), "ssh-ed25519".into(), crypto::b64u(&data))];
    let mut page = Page::new(&a.engine);
    assert!(until(10, || !cloud.st.lock().unwrap().signed.is_empty()).await, "the engine answered the sign request");
    let signed = cloud.st.lock().unwrap().signed[0].clone();
    assert_eq!((signed["op"].clone(), signed["id"].clone()), (json!("vault.signed"), json!("sign-1")), "{signed}");
    verify_ed25519(&pub_line, &data, &crypto::from_b64u(signed["sig"].as_str().unwrap()).unwrap());
    page.until(1, |_| false).await;
    assert!(!page.msgs.iter().any(|m| m["op"] == "vault.sign"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_server_moves_only_as_the_person_said() {
    let _home = HOME_LOCK.lock().await;
    let Some(lab) = SshLab::new() else { return };
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    let move_web = |keys: Value| json!({"project": "p1", "servers": [{"alias": "web-01", "method": "key"}], "keys": keys});
    let key_path = lab.key("id_ed25519", "");
    lab_config(&lab, &key_path);
    // The vault locked: a key server waits for it.
    let (_, moved) = app_vault(&a.engine, "POST", "/api/app/move", move_web(json!([{"path": "~/.ssh/id_ed25519"}]))).await;
    assert_eq!(moved["results"][0]["ok"], false, "{moved}");
    assert!(moved["results"][0]["error"].as_str().unwrap().contains("Open your vault"), "{moved}");
    create_vault(&a.engine).await;
    // Its key not ticked: not moved, nothing uploaded, no login.
    let (_, moved) = app_vault(&a.engine, "POST", "/api/app/move", move_web(json!([]))).await;
    assert_eq!(moved["results"][0]["ok"], false, "{moved}");
    assert!(moved["results"][0]["error"].as_str().unwrap().contains("not ticked"), "{moved}");
    assert!(!lab.log().contains("[true]"), "no login: {}", lab.log());
    // The login fails: nothing is saved.
    lab.set("TTERM_FAKE_SSH_FAIL", Some("1"));
    let (_, moved) = app_vault(&a.engine, "POST", "/api/app/move", move_web(json!([{"path": "~/.ssh/id_ed25519"}]))).await;
    assert_eq!(moved["results"][0]["ok"], false, "{moved}");
    assert!(moved["results"][0]["error"].as_str().unwrap().contains("Permission denied"), "{moved}");
    lab.set("TTERM_FAKE_SSH_FAIL", None);
    // The server let it in with another key: not this one's to move.
    lab.set("TTERM_FAKE_SSH_FP", Some("SHA256:anotherkeyaltogether"));
    let (_, moved) = app_vault(&a.engine, "POST", "/api/app/move", move_web(json!([{"path": "~/.ssh/id_ed25519"}]))).await;
    assert_eq!(moved["results"][0]["ok"], false, "{moved}");
    assert!(moved["results"][0]["error"].as_str().unwrap().contains("another key"), "{moved}");
    lab.set("TTERM_FAKE_SSH_FP", None);
    // A server with no host key here is not moved.
    let (_, moved) = app_vault(&a.engine, "POST", "/api/app/move", json!({"project": "p1", "servers": [{"alias": "lab-box", "method": "key"}], "keys": []})).await;
    assert!(moved["results"][0]["error"].as_str().unwrap().contains("host key"), "{moved}");
    {
        let st = cloud.st.lock().unwrap();
        assert!(st.own.is_empty(), "nothing saved");
        assert!(st.vault.as_ref().unwrap()["keys"].as_array().unwrap().is_empty(), "no key uploaded");
    }
    // tTerm does not save the server: the key uploaded for it goes again.
    cloud.st.lock().unwrap().own_refuse = Some((422, "The server sent no host key tTerm could read.".into()));
    let (_, moved) = app_vault(&a.engine, "POST", "/api/app/move", move_web(json!([{"path": "~/.ssh/id_ed25519"}]))).await;
    assert_eq!(moved["results"][0]["ok"], false, "{moved}");
    assert!(moved["results"][0]["error"].as_str().unwrap().contains("no host key tTerm could read"), "{moved}");
    let st = cloud.st.lock().unwrap();
    assert_eq!(st.deleted_keys.len(), 1, "the key went out again");
    assert!(st.vault.as_ref().unwrap()["keys"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_passphrase_answers_only_the_passphrase_question() {
    let _home = HOME_LOCK.lock().await;
    let Some(lab) = SshLab::new() else { return };
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    create_vault(&a.engine).await;
    let key_path = lab.key("id_ed25519", "open sesame");
    lab_config(&lab, &key_path);
    let (_, listed) = app_vault(&a.engine, "GET", "/api/app/ssh", Value::Null).await;
    let k = listed["keys"].as_array().unwrap().iter().find(|k| k["path"] == "~/.ssh/id_ed25519").cloned().unwrap();
    assert_eq!(k["encrypted"], true, "{k}");
    // Without it: the key cannot be read into the vault.
    let move_web = |keys: Value| json!({"project": "p1", "servers": [{"alias": "web-01", "method": "key"}], "keys": keys});
    let (_, moved) = app_vault(&a.engine, "POST", "/api/app/move", move_web(json!([{"path": "~/.ssh/id_ed25519"}]))).await;
    assert_eq!(moved["results"][0]["ok"], false, "{moved}");
    // With it: ssh's passphrase question gets it through the helper; a
    // password or a confirmation question gets nothing.
    let (_, moved) = app_vault(&a.engine, "POST", "/api/app/move", move_web(json!([{"path": "~/.ssh/id_ed25519", "passphrase": "open sesame"}]))).await;
    assert_eq!(moved["results"][0]["ok"], true, "{moved}");
    let log = lab.log();
    assert!(log.contains("askpass passphrase [open sesame]"), "{log}");
    assert!(log.contains("askpass password refused"), "{log}");
    assert!(log.contains("askpass confirm refused"), "{log}");
    assert!(!log.contains("ANSWERED"), "{log}");
    let login = log.lines().rev().find(|l| l.contains("[web-01] [true]")).unwrap();
    assert!(login.contains("[BatchMode=no]") && login.contains("[PasswordAuthentication=no]") && login.contains("[KbdInteractiveAuthentication=no]") && login.contains("[StrictHostKeyChecking=yes]"), "{login}");
    assert!(!login.contains("open sesame"), "the passphrase is in no argument: {login}");
    assert_eq!(cloud.st.lock().unwrap().vault.as_ref().unwrap()["keys"][0]["fingerprint"], k["fingerprint"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn let_tterm_in_adds_its_line_and_takes_it_off_if_not_saved() {
    let _home = HOME_LOCK.lock().await;
    let Some(lab) = SshLab::new() else { return };
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    // The vault is not needed for it: none is made.
    let key_path = lab.key("id_ed25519", "");
    lab_config(&lab, &key_path);
    // The server's authorized_keys, its last line without a newline.
    std::fs::create_dir_all(lab.remote.join(".ssh")).unwrap();
    std::fs::write(lab.remote.join(".ssh").join("authorized_keys"), "ssh-ed25519 AAAAexisting someone@laptop").unwrap();
    let move_cert = |alias: &str| json!({"project": "p1", "servers": [{"alias": alias, "method": "cert"}], "keys": []});
    let (status, moved) = app_vault(&a.engine, "POST", "/api/app/move", move_cert("web-01")).await;
    assert_eq!(status, 200, "{moved}");
    assert_eq!(moved["results"][0]["ok"], true, "{moved}");
    let own = cloud.st.lock().unwrap().own[0].clone();
    assert_eq!(own["method"], "cert");
    let line1 = "cert-authority,principals=\"m-1\" ssh-ed25519 AAAACA tterm-web ca-1";
    assert_eq!(lab.server_keys(), format!("ssh-ed25519 AAAAexisting someone@laptop\n{line1}\n"), "added on a line of its own");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(lab.remote.join(".ssh").join("authorized_keys")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    // tTerm does not save the next one: its line goes off again, the rest
    // stays as it was.
    cloud.st.lock().unwrap().own_refuse = Some((422, "The server did not accept tTerm's certificate.".into()));
    let (_, moved) = app_vault(&a.engine, "POST", "/api/app/move", move_cert("web-02")).await;
    assert_eq!(moved["results"][0]["ok"], false, "{moved}");
    assert!(moved["results"][0]["error"].as_str().unwrap().contains("did not accept"), "{moved}");
    assert_eq!(lab.server_keys(), format!("ssh-ed25519 AAAAexisting someone@laptop\n{line1}\n"), "m-2's line is off again");
    assert_eq!(cloud.st.lock().unwrap().own.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mac_server_adds_a_via_machine() {
    // The move reads the server's settings with ssh -G: in the lab's home,
    // never the real ~/.ssh.
    let _home = HOME_LOCK.lock().await;
    let Some(lab) = SshLab::new() else { return };
    lab.write("config", "Host lab\n  HostName 192.168.1.20\n  User pi\n");
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    // No vault, none open: a server through this Mac needs none.
    let body = json!({"project": "p1", "servers": [{"alias": "lab", "method": "mac"}], "keys": []});
    let (status, moved) = app_vault(&a.engine, "POST", "/api/app/move", body).await;
    assert_eq!(status, 200, "{moved}");
    assert_eq!(moved["results"][0]["ok"], true, "{moved}");
    let own = cloud.st.lock().unwrap().own[0].clone();
    assert_eq!(own["method"], "mac");
    assert_eq!(own["target"], "lab");
    assert!(own["jump"].is_null(), "no bastion for a server through the Mac");
    // The via is this Mac as a machine of the account (the computers/this
    // tTerm answered), not the engine's own id.
    let here = a.engine.cloud.as_ref().unwrap().here().expect("this Mac is known to tTerm now");
    assert_eq!(own["via"], here.id.to_string());
    assert!(cloud.st.lock().unwrap().machines.iter().any(|m| m["id"] == own["via"] && m["kind"] == "computer"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reachable_asks_the_core() {
    let cloud = Cloud::start().await;
    let a = app(&cloud).await;
    sign_in(&cloud, &a).await;
    cloud.st.lock().unwrap().reachable_ok = true;
    let (status, r) = app_vault(&a.engine, "POST", "/api/app/ssh/reachable", json!({"host": "198.51.100.2", "port": 22})).await;
    assert_eq!(status, 200, "{r}");
    assert_eq!(r["ok"], true);
}

/// The signing input of a login (RFC 4252 §7), as a client writes it.
fn userauth(session: &[u8], user: &str, alg: &str, blob: &[u8]) -> Vec<u8> {
    let string = |out: &mut Vec<u8>, v: &[u8]| {
        out.extend_from_slice(&(v.len() as u32).to_be_bytes());
        out.extend_from_slice(v);
    };
    let mut out = Vec::new();
    string(&mut out, session);
    out.push(50);
    string(&mut out, user.as_bytes());
    string(&mut out, b"ssh-connection");
    string(&mut out, b"publickey");
    out.push(1);
    string(&mut out, alg.as_bytes());
    string(&mut out, blob);
    out
}

/// An Ed25519 raw signature verified against an OpenSSH public line.
fn verify_ed25519(public_openssh: &str, data: &[u8], sig: &[u8]) {
    let parts: Vec<&str> = public_openssh.split_whitespace().collect();
    let blob = base64_decode(parts[1]);
    // ssh-ed25519 blob: 4+len "ssh-ed25519", 4+len key(32).
    let key = &blob[blob.len() - 32..];
    let public = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key);
    public.verify(data, sig).expect("the signature verifies");
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

/// An X25519 key pair and agreement for the browser side of a pairing,
/// through the engine's crypto (its test seam).
fn x25519_pair() -> ([u8; 32], Vec<u8>) {
    // Use a fixed seed so the browser side is reproducible.
    let seed: Vec<u8> = (0..32u8).collect();
    let pairer = tterm_engine::crypto::pairer_from_seed(&seed).unwrap();
    (pairer.public, seed)
}

fn x25519_agree(priv_b: &[u8], pub_a: &[u8]) -> Vec<u8> {
    let pairer = tterm_engine::crypto::pairer_from_seed(priv_b).unwrap();
    pairer.agree(pub_a).unwrap().as_ref().to_vec()
}

fn ssh_keygen() -> Option<std::path::PathBuf> {
    which("ssh-keygen", "TTERM_SSH_KEYGEN")
}

fn which(name: &str, env: &str) -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os(env) {
        let p = std::path::PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let p = std::path::Path::new(dir).join(name);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn first_two(line: &str) -> String {
    line.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}
