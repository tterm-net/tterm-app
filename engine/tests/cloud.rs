//! Signed in (from 0.3.0): the engine against a tTerm Web of the checks' own,
//! on this computer. It answers as tTerm Web 0.1.6 does where the engine
//! needs it: the app's sign-in (`/api/auth/app/*`), which computer this is
//! (`/api/computers/this`), the state, notes, Sign out, and the page's
//! socket with a terminal of its own. The checks act as the browser where
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
}

impl Host for FakeHost {
    fn open_url(&self, url: &str) -> Result<(), String> {
        self.opened.lock().unwrap().push(url.to_string());
        Ok(())
    }
    fn load_key(&self) -> Result<Option<String>, String> {
        let had = self.key.lock().unwrap().clone();
        std::thread::sleep(Duration::from_millis(self.load_ms.load(Ordering::SeqCst)));
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
    /// Requests that take their time, by path, in milliseconds.
    slow: HashMap<String, u64>,
    /// So many saves of a note are refused (422) before they are taken.
    refuse_saves: usize,
    /// The photo, as it came: its type and its bytes (from 0.3.1).
    photo: Option<(String, Vec<u8>)>,
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
        "me": {"id": "u1", "name": "Anna Fake", "firstName": "Anna", "initials": "AF", "theme": "dark", "projectTint": "badge", "plan": "free", "email": "anna@example.com"},
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
        let slow = st.lock().unwrap().slow.get(&path).copied();
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
            if let Some(m) = st.machines.iter().find(|m| m["key"] == key.as_str()) {
                return (200, json!({"machine": {"id": m["id"], "name": m["name"], "projectId": "p1", "code": "P"}, "created": false}));
            }
            let id = uuid::Uuid::new_v4().to_string();
            st.machines.push(json!({"id": id, "kind": "computer", "name": text("name"), "online": false, "key": key}));
            (201, json!({"machine": {"id": id, "name": text("name"), "projectId": "p1", "code": "P"}, "created": true}))
        }
        ("GET", "/api/state") => (200, state_json(&st)),
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
    loop {
        let message = tokio::select! {
            m = source.next() => m,
            _ = gone.changed() => return,
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
    let engine = Engine::with_cloud(&dir, &cloud.base, host.clone(), &env).expect("engine");
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
