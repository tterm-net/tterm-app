//! Signing in on this computer (from 0.3.0), with the browser, the way
//! RFC 8252 says an app should, and tTerm Web 0.1.6 expects it.
//!
//! The app makes a secret, opens `app.tterm.net/connect` in the browser with
//! the secret's challenge (RFC 7636, S256) and a port on 127.0.0.1 where it
//! waits. The person signs in there, checks that the browser shows the same
//! code as the app, and presses Allow: the browser brings a one-time code
//! back to 127.0.0.1 (loopback.rs), and the app trades it, with its secret,
//! for a key of its own. The code is of no use to anyone else: it works once,
//! for two minutes, and only with the secret, which never left this app.
//!
//! The key of the app's device is kept in the keychain (Host), with what
//! using it takes (the device's id, where agents connect, the session's
//! cookie); a session is asked for with it when the app starts and whenever
//! the last one ended, and lives in memory only. The computer itself is known to tTerm by its own
//! key, the one in `~/.tterm-web/env` that its agent keeps: the app shows it
//! once signed in, and tTerm answers which of the person's machines this
//! computer is (`/api/computers/this`). Without that file the app writes one
//! with a new key, in the agent's format, so that an agent set up later is
//! this same computer.
//!
//! What tTerm said last is kept, so that the page has the person's projects
//! when tTerm cannot be reached: the app then works on with this computer,
//! and says that the rest waits for the connection.

use crate::loopback::{self, Page};
use crate::upstream::{Answer, Cloud, Unreachable};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;

/// What the app around the engine does for it: opens the browser, and keeps
/// the device's key where only the app reads it (a Mac's keychain).
pub trait Host: Send + Sync {
    fn open_url(&self, url: &str) -> Result<(), String>;
    fn load_key(&self) -> Result<Option<String>, String>;
    fn save_key(&self, key: &str) -> Result<(), String>;
    fn delete_key(&self) -> Result<(), String>;
}

/// How long the app waits for the browser to come back, at most.
pub const LINK_WAIT: Duration = Duration::from_secs(15 * 60);
/// How long the page waits, at most, for the app to look its key up at
/// the start (a keychain may ask the person first).
const READY_WAIT: Duration = Duration::from_secs(60);
/// After tTerm could not be reached: when to look again, in turn.
const PROBE_EVERY: [u64; 5] = [2, 3, 5, 8, 10];

/// The app as tTerm Web names it (auth.APPS): by the system it runs on.
pub fn app_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "mac",
        "windows" => "windows",
        _ => "linux",
    }
}

/// "tTerm for Mac".
pub fn app_title(app: &str) -> String {
    let system = match app {
        "mac" => "Mac",
        "windows" => "Windows",
        _ => "Linux",
    };
    format!("tTerm for {system}")
}

// ------------------------------------------------------------ the secrets

const URL_SAFE: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// `bytes` random bytes, in base64url without padding.
pub fn random_token(bytes: usize) -> String {
    use ring::rand::SecureRandom;
    let mut buf = vec![0u8; bytes];
    ring::rand::SystemRandom::new().fill(&mut buf).expect("random bytes");
    URL_SAFE.encode(buf)
}

/// The challenge of a secret: its SHA-256 in base64url, as RFC 7636 has it
/// for S256.
pub fn challenge_of(verifier: &str) -> String {
    URL_SAFE.encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()))
}

/// Crockford's base32: no I, L, O or U to mistake for other signs.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The code both windows show, from the challenge, as the page of tTerm Web
/// works it out (appLink.ts): the first 30 bits of its SHA-256, in six signs
/// of base32, "K7F-3QX".
pub fn link_code(challenge: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, challenge.as_bytes());
    let b = d.as_ref();
    let bits = (u32::from(b[0]) << 24 | u32::from(b[1]) << 16 | u32::from(b[2]) << 8 | u32::from(b[3])) >> 2;
    let code: String = (0..6).map(|i| ALPHABET[((bits >> (25 - 5 * i)) & 31) as usize] as char).collect();
    format!("{}-{}", &code[..3], &code[3..])
}

/// Whether two secrets are the same, in a time that does not tell where
/// they differ.
pub fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A key or a code as tTerm makes them (auth._TOKEN, machines.KEY_RE).
pub fn is_token(text: &str) -> bool {
    (32..=64).contains(&text.len()) && text.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// Text for a URL's query: everything but letters, digits and `-._~` as
/// %XX of its UTF-8.
pub fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The computer's name as the link carries it: one line, 64 characters at
/// most, as tTerm Web takes it (auth.computer_name).
pub fn link_name(name: &str) -> String {
    let one: String = name.split_whitespace().collect::<Vec<_>>().join(" ");
    let clean: String = one.chars().filter(|c| !c.is_control()).take(64).collect();
    if clean.trim().is_empty() {
        "computer".to_string()
    } else {
        clean.trim().to_string()
    }
}

// ------------------------------------------------------- what is kept

/// The machine this computer is in tTerm Web.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Here {
    pub id: Uuid,
    pub name: String,
    pub project_id: String,
    pub code: String,
}

/// What the keychain keeps: the device's key, and all that using it takes,
/// so that the app stays signed in whatever happens to its folder.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct Kept {
    key: String,
    device_id: String,
    label: String,
    /// Where agents connect: `TTERM_HUB` of `~/.tterm-web/env`.
    hub: String,
    /// The name of the session's cookie.
    cookie: String,
}

/// What the app's folder keeps of the account (`account.json`, for the
/// person alone): who signed in, and which machine this computer is. Nothing
/// the app cannot do without: that is in the keychain.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct Details {
    #[serde(default)]
    device_id: String,
    #[serde(default)]
    me: Value,
    #[serde(default)]
    here: Option<Here>,
    /// Why this computer is no machine of the account's, if it is not.
    #[serde(default)]
    not_here: Option<String>,
}

const DETAILS_FILE: &str = "account.json";
const STATE_FILE: &str = "cloud-state.json";

static WRITES: AtomicU64 = AtomicU64::new(1);

/// Writes a file for the person alone, whole: under a name of its own
/// first (no other writer has it, the agent's installer included), then in
/// its place.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{}-{}.new", std::process::id(), WRITES.fetch_add(1, Ordering::SeqCst)));
    let written = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let mut file = options.open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(bytes)?;
        file.sync_all()
    })();
    match written.and_then(|()| std::fs::rename(&tmp, path)) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok())
}

// -------------------------------------------------- ~/.tterm-web/env

/// What `~/.tterm-web/env` says, read as the agent's installer reads it:
/// the first line that starts with the name, as it is.
#[derive(Debug, Default, PartialEq)]
pub struct AgentEnv {
    pub hub: Option<String>,
    pub key: Option<String>,
    pub name: Option<String>,
    /// The lines as they are, for rewriting.
    lines: Vec<String>,
}

impl AgentEnv {
    pub fn read(path: &Path) -> std::io::Result<Option<AgentEnv>> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut env = AgentEnv { lines: text.lines().map(str::to_string).collect(), ..Default::default() };
        for line in text.lines() {
            for (name, slot) in [("TTERM_HUB=", &mut env.hub), ("TTERM_KEY=", &mut env.key), ("TTERM_NAME=", &mut env.name)] {
                if slot.is_none() {
                    if let Some(value) = line.strip_prefix(name) {
                        *slot = Some(value.to_string());
                    }
                }
            }
        }
        Ok(Some(env))
    }

    /// A key as the installer makes one (`token_urlsafe(24)`, never
    /// starting with "-").
    pub fn new_key() -> String {
        let key = random_token(24);
        match key.strip_prefix('-') {
            Some(rest) => format!("A{rest}"),
            None => key,
        }
    }

    /// The file with `key` as the computer's key and token (the token of a
    /// known key is not checked), for `hub`: written new, or the old one
    /// with its other lines.
    pub fn write(path: &Path, hub: &str, key: &str, old: Option<&AgentEnv>) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(dir)?;
        }
        let mut lines = vec![format!("TTERM_HUB={hub}"), format!("TTERM_TOKEN={key}"), format!("TTERM_KEY={key}")];
        if let Some(old) = old {
            for line in &old.lines {
                let ours = ["TTERM_HUB=", "TTERM_TOKEN=", "TTERM_KEY="].iter().any(|n| line.starts_with(n));
                if !ours && !line.trim().is_empty() {
                    lines.push(line.clone());
                }
            }
        }
        let mut text = lines.join("\n");
        text.push('\n');
        write_private(path, text.as_bytes())
    }
}

/// A hub as tTerm Web names it (machines.hub_url): `wss://` or `ws://`, a
/// host, `/agent`. Nothing else goes into the agent's file.
pub fn good_hub(hub: &str) -> bool {
    let host = hub.strip_prefix("wss://").or_else(|| hub.strip_prefix("ws://")).and_then(|r| r.strip_suffix("/agent"));
    match host {
        Some(host) => !host.is_empty() && host.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b':' | b'[' | b']')),
        None => false,
    }
}

// ------------------------------------------------------- the sign-in

/// How signing in with the browser goes, as the page asks it.
#[derive(Clone, Debug, PartialEq)]
pub enum LinkState {
    Waiting,
    /// The browser came back: its code is being traded (the page still
    /// hears "waiting").
    Exchanging,
    Done,
    Failed(String),
    Cancelled,
}

/// What the browser's code was traded for, before the app keeps it.
#[derive(Clone, Debug)]
struct Traded {
    kept: Kept,
    session: String,
    me: Value,
}

struct Link {
    serial: u64,
    verifier: String,
    state: String,
    url: String,
    code: String,
    status: LinkState,
    stop: watch::Sender<bool>,
}

/// Why a request could not be answered by tTerm.
#[derive(Debug)]
pub enum Trouble {
    /// tTerm could not be reached, or did not answer as it should.
    Offline,
    /// The app is not signed in, or no longer: its device was forgotten.
    SignedOut,
}

/// Why a note did not go to tTerm: try again later (the network), or not
/// this one now (tTerm said no).
enum Hold {
    Stop(String),
    Skip(String),
}

impl From<Trouble> for Hold {
    fn from(t: Trouble) -> Hold {
        Hold::Stop(format!("{t:?}"))
    }
}

#[derive(Default)]
struct St {
    /// Signed in: what the keychain keeps.
    kept: Option<Kept>,
    session: Option<String>,
    details: Details,
    offline: bool,
    probing: bool,
    /// What tTerm said last to `/api/state`.
    last: Option<Value>,
    /// The copy of it on disk, as written.
    written: Option<String>,
    moving: bool,
    /// tTerm answered which machine this computer is, in this run.
    asked_here: bool,
    /// One more with each sign-in and sign-out: what was begun for one
    /// account is not kept for another, or after it.
    epoch: u64,
}

pub struct Account {
    pub cloud: Cloud,
    host: Arc<dyn Host>,
    dir: PathBuf,
    env_file: PathBuf,
    app: &'static str,
    st: Mutex<St>,
    /// The account's files are written and deleted one at a time.
    files: Mutex<()>,
    renewing: tokio::sync::Mutex<()>,
    /// A key traded is kept, or given back, one at a time.
    signing: tokio::sync::Mutex<()>,
    /// Which machine this computer is, asked once at a time.
    asking_here: tokio::sync::Mutex<()>,
    link: Mutex<Option<Link>>,
    serial: AtomicU64,
    /// Whether tTerm answers: the sockets wait for it.
    pub online: watch::Sender<bool>,
    /// The key was looked up at the start.
    ready: watch::Sender<bool>,
    /// The engine, for what is done when tTerm answers again.
    engine: OnceLock<Weak<crate::Engine>>,
}

impl Account {
    /// The account of this app: `dir` is the app's folder, `env_file` the
    /// agent's settings (`~/.tterm-web/env`).
    pub fn new(cloud: Cloud, host: Arc<dyn Host>, dir: &Path, env_file: &Path) -> Arc<Account> {
        let details: Details = read_json(&dir.join(DETAILS_FILE)).unwrap_or_default();
        let last: Option<Value> = read_json(&dir.join(STATE_FILE));
        Arc::new(Account {
            cloud,
            host,
            dir: dir.to_path_buf(),
            env_file: env_file.to_path_buf(),
            app: app_name(),
            st: Mutex::new(St { details, last, ..Default::default() }),
            files: Mutex::new(()),
            renewing: tokio::sync::Mutex::new(()),
            signing: tokio::sync::Mutex::new(()),
            asking_here: tokio::sync::Mutex::new(()),
            link: Mutex::new(None),
            serial: AtomicU64::new(1),
            online: watch::channel(true).0,
            ready: watch::channel(false).0,
            engine: OnceLock::new(),
        })
    }

    /// At the start: the account from the keychain, and if there is one, a
    /// session, this computer's machine and notes made before.
    pub async fn start(self: &Arc<Self>, engine: &Arc<crate::Engine>) {
        let _ = self.engine.set(Arc::downgrade(engine));
        let host = self.host.clone();
        let found = tokio::task::spawn_blocking(move || host.load_key()).await.unwrap_or_else(|e| Err(e.to_string()));
        // Kept as a sign-in keeps its key, one at a time. One made meanwhile
        // (the keychain took longer to answer than the page waits) is newer
        // than what was read: it stays as it is, in the keychain and here.
        let one = self.signing.lock().await;
        let signed = match found {
            _ if self.signed_in() => false,
            Ok(Some(text)) => match serde_json::from_str::<Kept>(&text) {
                Ok(kept) if is_token(&kept.key) && !kept.cookie.is_empty() => {
                    let mut st = self.st.lock().unwrap();
                    if st.details.device_id != kept.device_id {
                        // The folder's details are of another sign-in, or
                        // gone: tTerm says them again.
                        st.details = Details { device_id: kept.device_id.clone(), ..Default::default() };
                        st.last = None;
                    }
                    st.kept = Some(kept);
                    true
                }
                _ => {
                    eprintln!("tterm: the keychain's item of tTerm could not be read: taken out, the app signs in again");
                    let host = self.host.clone();
                    let _ = tokio::task::spawn_blocking(move || host.delete_key()).await;
                    self.drop_kept();
                    false
                }
            },
            Ok(None) => {
                // No key: whatever was kept of an account is old news.
                self.drop_kept();
                false
            }
            Err(why) => {
                eprintln!("tterm: the device's key could not be read from the keychain: {why}");
                false
            }
        };
        drop(one);
        self.ready.send_replace(true);
        if signed {
            self.catch_up(engine).await;
        }
    }

    /// Waits until the key was looked up, at most a minute.
    pub async fn wait_ready(&self) {
        let mut ready = self.ready.subscribe();
        let _ = tokio::time::timeout(READY_WAIT, ready.wait_for(|r| *r)).await;
    }

    pub fn signed_in(&self) -> bool {
        self.st.lock().unwrap().kept.is_some()
    }

    pub fn offline(&self) -> bool {
        self.st.lock().unwrap().offline
    }

    /// This app's device in tTerm.
    pub fn device_id(&self) -> Option<String> {
        self.st.lock().unwrap().kept.as_ref().map(|k| k.device_id.clone())
    }

    /// Who signed in, as tTerm said at the sign-in.
    pub fn me(&self) -> Value {
        self.st.lock().unwrap().details.me.clone()
    }

    /// The machine this computer is in tTerm, once known.
    pub fn here(&self) -> Option<Here> {
        let st = self.st.lock().unwrap();
        st.kept.as_ref()?;
        st.details.here.clone()
    }

    /// What tTerm said last to `/api/state`.
    pub fn last_state(&self) -> Option<Value> {
        self.st.lock().unwrap().last.clone()
    }

    fn epoch(&self) -> u64 {
        self.st.lock().unwrap().epoch
    }

    /// Writes the details, if the account is still the one of `epoch`.
    fn keep_details(&self, epoch: u64) {
        let _one = self.files.lock().unwrap();
        let text = {
            let st = self.st.lock().unwrap();
            if st.epoch != epoch || st.kept.is_none() {
                return;
            }
            serde_json::to_vec_pretty(&st.details).unwrap_or_default()
        };
        if let Err(e) = write_private(&self.dir.join(DETAILS_FILE), &text) {
            eprintln!("tterm: could not keep the account's details: {e}");
        }
    }

    /// Everything kept of an account in the folder goes: the details and
    /// the copy of what tTerm said.
    fn drop_kept(&self) {
        let _one = self.files.lock().unwrap();
        {
            let mut st = self.st.lock().unwrap();
            st.details = Details::default();
            st.last = None;
            st.written = None;
            st.session = None;
        }
        for file in [DETAILS_FILE, STATE_FILE] {
            let _ = std::fs::remove_file(self.dir.join(file));
        }
    }

    // ------------------------------------------------------- signing in

    /// Starts signing in with the browser, or with `again`, opens the page
    /// of the one waiting once more: the code both windows show.
    ///
    /// A sign-in the browser came back to is being finished (the code is
    /// traded, the keychain may be asking for the password): it stays, and
    /// its code is the answer, `again` or not. There is no page to open
    /// again, and only Cancel stops it.
    pub async fn start_link(self: &Arc<Self>, engine: &Arc<crate::Engine>, again: bool) -> Result<String, String> {
        if self.signed_in() {
            return Err("tTerm is signed in already.".into());
        }
        let reopen = {
            let mut link = self.link.lock().unwrap();
            let now = link.as_ref().map(|l| (l.status.clone(), l.url.clone(), l.code.clone()));
            match now {
                Some((LinkState::Exchanging, _, code)) => return Ok(code),
                Some((LinkState::Waiting, url, code)) if again => Some((url, code)),
                _ => {
                    // Whatever was there is over: a new sign-in.
                    if let Some(old) = link.take() {
                        old.stop.send_replace(true);
                    }
                    None
                }
            }
        };
        if let Some((url, code)) = reopen {
            self.host.open_url(&url).map_err(|e| format!("The browser could not be opened: {e}"))?;
            return Ok(code);
        }
        let (listener, port) = loopback::listen().await.map_err(|e| format!("tTerm could not wait for the browser on this computer: {e}"))?;
        let verifier = random_token(48);
        let challenge = challenge_of(&verifier);
        let state = random_token(24);
        let code = link_code(&challenge);
        let name = link_name(&engine.machine_name);
        let url = format!(
            "{}/connect?app={}&name={}&port={port}&challenge={challenge}&state={state}",
            self.cloud.base,
            self.app,
            encode(&name)
        );
        let serial = self.serial.fetch_add(1, Ordering::SeqCst);
        let (stop, stopped) = watch::channel(false);
        *self.link.lock().unwrap() = Some(Link { serial, verifier, state, url: url.clone(), code: code.clone(), status: LinkState::Waiting, stop });
        let me = self.clone();
        let engine = engine.clone();
        tokio::spawn(async move {
            let handler = {
                let me = me.clone();
                move |query: String| {
                    let me = me.clone();
                    let engine = engine.clone();
                    async move { me.came_back(&engine, serial, &query).await }
                }
            };
            let ended = loopback::serve(listener, port, app_title(me.app), stopped, LINK_WAIT, handler).await;
            if ended == loopback::Ended::TimedOut {
                // Only one still waiting: one being traded is finished.
                let mut link = me.link.lock().unwrap();
                if let Some(l) = link.as_mut().filter(|l| l.serial == serial && l.status == LinkState::Waiting) {
                    l.status = LinkState::Failed("The browser did not come back in time. Start again: Sign in with your browser.".into());
                }
            }
        });
        if let Err(e) = self.host.open_url(&url) {
            self.cancel_link();
            return Err(format!("The browser could not be opened: {e}"));
        }
        Ok(code)
    }

    /// The sign-in `serial` is over, as `status` says, if it is not over
    /// already.
    fn set_link(&self, serial: u64, status: LinkState) {
        if let Some(link) = self.link.lock().unwrap().as_mut().filter(|l| l.serial == serial) {
            if matches!(link.status, LinkState::Waiting | LinkState::Exchanging) {
                link.status = status;
                link.stop.send_replace(true);
            }
        }
    }

    /// Whether the code being traded is still for the sign-in waiting: not
    /// cancelled in the app, nor replaced by a new one.
    fn ours(&self, serial: u64) -> bool {
        self.link.lock().unwrap().as_ref().map(|l| l.serial == serial && l.status == LinkState::Exchanging).unwrap_or(false)
    }

    /// How signing in goes: `{state, error?}`, as the page asks.
    pub fn link_status(&self) -> Value {
        match self.link.lock().unwrap().as_ref().map(|l| l.status.clone()) {
            None => json!({"state": "none"}),
            Some(LinkState::Waiting | LinkState::Exchanging) => json!({"state": "waiting"}),
            Some(LinkState::Done) => json!({"state": "done"}),
            Some(LinkState::Cancelled) => json!({"state": "cancelled"}),
            Some(LinkState::Failed(why)) => json!({"state": "failed", "error": why}),
        }
    }

    /// Cancel in the app: nothing waits for the browser any more.
    pub fn cancel_link(&self) {
        if let Some(link) = self.link.lock().unwrap().take() {
            link.stop.send_replace(true);
        }
    }

    /// The browser came back to 127.0.0.1 with `query`: the page it gets.
    ///
    /// The first return with the sign-in's state takes it, under the link's
    /// lock: another one meanwhile (the tab reloaded, Allow in a second tab)
    /// gets a page that says it is being finished, and trades nothing. The
    /// code is traded, and the key kept, each on its own: whatever happens
    /// to the browser's connection, they are done to the end. A key traded
    /// for a sign-in that was cancelled in the app meanwhile, or replaced
    /// by a new one, is given back, and only that key.
    async fn came_back(self: &Arc<Self>, engine: &Arc<crate::Engine>, serial: u64, query: &str) -> loopback::Answer {
        let (code, state, error) = (loopback::query_value(query, "code"), loopback::query_value(query, "state"), loopback::query_value(query, "error"));
        let answer = |page, done| loopback::Answer { page, done };
        let verifier = {
            let mut link = self.link.lock().unwrap();
            let Some(link) = link.as_mut().filter(|l| l.serial == serial) else { return answer(Page::NotThis, false) };
            if !state.as_deref().map(|s| same(s, &link.state)).unwrap_or(false) {
                return answer(Page::NotThis, false);
            }
            match link.status {
                LinkState::Waiting => {}
                LinkState::Exchanging => return answer(Page::Finishing, false),
                _ => return answer(Page::NotThis, false),
            }
            if error.is_some() {
                link.status = LinkState::Cancelled;
                link.stop.send_replace(true);
                return answer(Page::Cancelled, true);
            }
            if !code.as_deref().map(is_token).unwrap_or(false) {
                link.status = LinkState::Failed("The browser came back without a code. Start again: Sign in with your browser.".into());
                link.stop.send_replace(true);
                return answer(Page::Failed("The browser came back without a code.".into()), true);
            }
            link.status = LinkState::Exchanging;
            link.verifier.clone()
        };
        let code = code.unwrap_or_default();
        let failed = |me: &Self, why: String| {
            me.set_link(serial, LinkState::Failed(format!("{why} Start again: Sign in with your browser.")));
            answer(Page::Failed(why), true)
        };
        let me = self.clone();
        let traded = tokio::spawn(async move { me.trade(&code, &verifier).await }).await.unwrap_or_else(|e| Err(e.to_string()));
        let traded = match traded {
            Ok(t) => t,
            Err(why) => return failed(self, why),
        };
        if !self.ours(serial) {
            self.give_back(&traded).await;
            return answer(Page::Cancelled, true);
        }
        let me = self.clone();
        let keeping = traded.clone();
        let kept = tokio::spawn(async move { me.keep(keeping).await }).await.unwrap_or_else(|e| Err(e.to_string()));
        if let Err(why) = kept {
            return failed(self, why);
        }
        if !self.ours(serial) {
            self.undo(&traded).await;
            return answer(Page::Cancelled, true);
        }
        // The browser hears at once; the app finishes, then the page starts
        // over signed in.
        let me = self.clone();
        let engine = engine.clone();
        tokio::spawn(async move {
            me.connected(&engine).await;
            me.set_link(serial, LinkState::Done);
            me.move_notes(&engine).await;
        });
        answer(Page::Done, true)
    }

    /// The code and the secret for the device's key and a first session:
    /// nothing kept yet.
    async fn trade(&self, code: &str, verifier: &str) -> Result<Traded, String> {
        let answer = self
            .cloud
            .json("POST", "/api/auth/app/exchange", &json!({"code": code, "verifier": verifier}), None)
            .await
            .map_err(|_| "tTerm could not be reached. Check the connection.".to_string())?;
        if answer.status != 200 {
            return Err(answer.error().unwrap_or_else(|| format!("tTerm answered {}.", answer.status)));
        }
        let got = answer.json().unwrap_or(Value::Null);
        let text = |k: &str| got.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let kept = Kept { key: text("key"), device_id: text("deviceId"), label: text("label"), hub: text("hub"), cookie: text("cookie") };
        let session = text("session");
        if !is_token(&kept.key) || session.is_empty() || kept.cookie.is_empty() || kept.device_id.is_empty() {
            return Err("tTerm's answer was not complete.".into());
        }
        Ok(Traded { kept, session, me: got.get("me").cloned().unwrap_or(Value::Null) })
    }

    /// The key traded, kept: in the keychain, then here. Not while the app is
    /// signed in already: then it is given back.
    async fn keep(&self, traded: Traded) -> Result<(), String> {
        let _one = self.signing.lock().await;
        if self.signed_in() {
            self.give_back(&traded).await;
            return Err("tTerm is signed in already.".into());
        }
        let host = self.host.clone();
        let record = serde_json::to_string(&traded.kept).unwrap_or_default();
        let saved = tokio::task::spawn_blocking(move || host.save_key(&record)).await.unwrap_or_else(|e| Err(e.to_string()));
        if let Err(why) = saved {
            // A key that cannot be kept is given back, so that no device
            // is left behind that nothing uses.
            self.give_back(&traded).await;
            return Err(format!("tTerm could not keep its key in the keychain ({why})."));
        }
        let epoch = {
            let mut st = self.st.lock().unwrap();
            st.epoch += 1;
            st.details = Details { device_id: traded.kept.device_id.clone(), me: traded.me.clone(), here: None, not_here: None };
            st.kept = Some(traded.kept);
            st.session = Some(traded.session);
            st.last = None;
            st.written = None;
            st.offline = false;
            st.asked_here = false;
            st.epoch
        };
        self.keep_details(epoch);
        self.online.send_replace(true);
        Ok(())
    }

    /// A key traded and not wanted: tTerm forgets its device.
    async fn give_back(&self, traded: &Traded) {
        let k = &traded.kept;
        let cookies = format!("{}={}; {}={}", k.cookie, traded.session, device_cookie(&k.cookie), k.key);
        match self.cloud.send("POST", "/api/auth/signout", Some(b"{}"), Some(&cookies), false).await {
            Ok(a) if a.status == 200 => {}
            Ok(a) => eprintln!("tterm: a key given back was not taken ({}): its device stays in Devices until forgotten there", a.status),
            Err(why) => eprintln!("tterm: a key given back could not reach tTerm ({}): its device stays in Devices until forgotten there", why.0),
        }
    }

    /// A key kept for a sign-in cancelled meanwhile: given back, and gone
    /// from here, if it is the one kept. Another sign-in waiting is left as
    /// it is.
    async fn undo(&self, traded: &Traded) {
        self.give_back(traded).await;
        let _one = self.signing.lock().await;
        let ours = {
            let mut st = self.st.lock().unwrap();
            let ours = st.kept.as_ref().map(|k| k.key == traded.kept.key).unwrap_or(false);
            if ours {
                st.epoch += 1;
                st.asked_here = false;
                st.kept = None;
            }
            ours
        };
        if ours {
            self.drop_kept();
            let host = self.host.clone();
            if let Err(why) = tokio::task::spawn_blocking(move || host.delete_key()).await.unwrap_or_else(|e| Err(e.to_string())) {
                eprintln!("tterm: the device's key could not be taken out of the keychain: {why}");
            }
        }
    }

    /// Signed in and tTerm answering: which machine this computer is, and
    /// what tTerm has for the page.
    async fn connected(self: &Arc<Self>, engine: &Arc<crate::Engine>) {
        if self.session().await.is_err() {
            return;
        }
        self.ensure_here(engine).await;
        let _ = self.cloud_state(false).await;
    }

    /// Which machine this computer is, unless tTerm said it in this run:
    /// asked once at a time, and the page's state waits for it.
    pub async fn ensure_here(self: &Arc<Self>, engine: &Arc<crate::Engine>) {
        let _one = self.asking_here.lock().await;
        let asked = self.st.lock().unwrap().asked_here;
        if !asked {
            self.this_computer(engine).await;
        }
    }

    /// Whether this computer's machine is to be asked for still.
    pub fn here_unknown(&self) -> bool {
        let st = self.st.lock().unwrap();
        st.kept.is_some() && !st.asked_here && st.details.here.is_none()
    }

    /// What waits for tTerm: this computer's machine, if not asked for yet
    /// in this run, and notes made before signing in.
    pub async fn catch_up(self: &Arc<Self>, engine: &Arc<crate::Engine>) {
        let asked = self.st.lock().unwrap().asked_here;
        if !asked {
            self.connected(engine).await;
        }
        self.move_notes(engine).await;
    }

    // ---------------------------------------------------------- sessions

    /// The session, asked for with the device's key if there is none.
    pub async fn session(self: &Arc<Self>) -> Result<String, Trouble> {
        let now = self.st.lock().unwrap().session.clone();
        match now {
            Some(s) => Ok(s),
            None => self.renew(None).await,
        }
    }

    /// A new session, once the one in `stale` ended: asked for once, however
    /// many requests found it ended.
    async fn renew(self: &Arc<Self>, stale: Option<&str>) -> Result<String, Trouble> {
        let _one = self.renewing.lock().await;
        let key = {
            let st = self.st.lock().unwrap();
            match (&st.session, stale) {
                (Some(s), Some(old)) if s != old => return Ok(s.clone()),
                (Some(s), None) => return Ok(s.clone()),
                _ => {}
            }
            st.kept.as_ref().map(|k| k.key.clone())
        };
        let Some(key) = key else { return Err(Trouble::SignedOut) };
        let answer = match self.cloud.json("POST", "/api/auth/app/session", &json!({"key": key}), None).await {
            Ok(a) => a,
            Err(why) => {
                self.went_offline(&why);
                return Err(Trouble::Offline);
            }
        };
        self.came_online();
        match answer.status {
            200 => {
                let got = answer.json().unwrap_or(Value::Null);
                let session = got.get("session").and_then(Value::as_str).unwrap_or("").to_string();
                if session.is_empty() {
                    return Err(Trouble::Offline);
                }
                let mut st = self.st.lock().unwrap();
                st.session = Some(session.clone());
                if let (Some(kept), Some(cookie)) = (st.kept.as_mut(), got.get("cookie").and_then(Value::as_str).filter(|c| !c.is_empty())) {
                    kept.cookie = cookie.to_string();
                }
                Ok(session)
            }
            410 => {
                // Forgotten: in Devices, with Forget all devices, or after
                // 90 days unused. This computer only, as before signing in.
                eprintln!("tterm: the app's device was forgotten in tTerm: signed out here");
                self.forget_here().await;
                Err(Trouble::SignedOut)
            }
            status => {
                eprintln!("tterm: tTerm did not give a session ({status}): {}", answer.error().unwrap_or_default());
                Err(Trouble::Offline)
            }
        }
    }

    /// The session's Cookie header.
    fn cookie(&self, session: &str) -> String {
        let name = self.st.lock().unwrap().kept.as_ref().map(|k| k.cookie.clone()).unwrap_or_default();
        format!("{name}={session}")
    }

    /// A request of the page, to tTerm, in this app's session. A session
    /// that ended is renewed with the device's key, and the request made
    /// again.
    pub async fn call(self: &Arc<Self>, method: &str, path: &str, body: Option<&[u8]>, background: bool) -> Result<Answer, Trouble> {
        if !self.signed_in() {
            return Err(Trouble::SignedOut);
        }
        if self.offline() {
            return Err(Trouble::Offline);
        }
        let session = self.session().await?;
        let answer = match self.cloud.send(method, path, body, Some(&self.cookie(&session)), background).await {
            Ok(a) => a,
            Err(why) => {
                self.went_offline(&why);
                return Err(Trouble::Offline);
            }
        };
        if !session_over(&answer) {
            return Ok(answer);
        }
        let session = self.renew(Some(&session)).await?;
        match self.cloud.send(method, path, body, Some(&self.cookie(&session)), background).await {
            // A session just given, and not taken: not a reason to sign out,
            // nor to ask again and again.
            Ok(a) if session_over(&a) => {
                eprintln!("tterm: tTerm did not take the session it just gave ({method} {path})");
                Err(Trouble::Offline)
            }
            Ok(a) => Ok(a),
            Err(why) => {
                self.went_offline(&why);
                Err(Trouble::Offline)
            }
        }
    }

    /// The session the socket found ended (close code 4401): a new one, if
    /// the device is still trusted.
    pub async fn session_ended(self: &Arc<Self>, stale: &str) -> Result<String, Trouble> {
        self.renew(Some(stale)).await
    }

    /// The Cookie header for the page's socket, and the session in it.
    pub async fn socket_cookie(self: &Arc<Self>) -> Result<(String, String), Trouble> {
        let session = self.session().await?;
        Ok((self.cookie(&session), session))
    }

    // ------------------------------------------------- reach and no reach

    fn went_offline(self: &Arc<Self>, why: &Unreachable) {
        let start = {
            let mut st = self.st.lock().unwrap();
            if !st.offline {
                eprintln!("tterm: tTerm cannot be reached: {}", why.0);
            }
            st.offline = true;
            let start = !st.probing && st.kept.is_some();
            st.probing = st.probing || start;
            start
        };
        self.online.send_replace(false);
        if start {
            let me = self.clone();
            tokio::spawn(async move { me.probe().await });
        }
    }

    fn came_online(self: &Arc<Self>) {
        let was = {
            let mut st = self.st.lock().unwrap();
            std::mem::replace(&mut st.offline, false)
        };
        self.online.send_replace(true);
        if was {
            eprintln!("tterm: tTerm answers again");
            // What waited for it, now.
            if let Some(engine) = self.engine.get().and_then(Weak::upgrade) {
                let me = self.clone();
                tokio::spawn(async move { me.catch_up(&engine).await });
            }
        }
    }

    /// While tTerm cannot be reached: a look now and then, until it
    /// answers. Whether to go on is decided under the lock that went_offline
    /// takes, so that one look is always on while tTerm is out of reach.
    async fn probe(self: Arc<Self>) {
        let mut turn = 0;
        loop {
            let wait = PROBE_EVERY[turn.min(PROBE_EVERY.len() - 1)];
            turn += 1;
            tokio::time::sleep(Duration::from_secs(wait)).await;
            let go_on = {
                let mut st = self.st.lock().unwrap();
                let go_on = st.offline && st.kept.is_some();
                if !go_on {
                    st.probing = false;
                }
                go_on
            };
            if !go_on {
                return;
            }
            if let Ok(answer) = self.cloud.send("GET", "/health", None, None, true).await {
                if answer.status == 200 {
                    self.st.lock().unwrap().probing = false;
                    self.came_online();
                    return;
                }
            }
        }
    }

    // ----------------------------------------------------- this computer

    /// Which of the person's machines this computer is: by its own key in
    /// `~/.tterm-web/env`, written there if there is none.
    pub async fn this_computer(self: &Arc<Self>, engine: &Arc<crate::Engine>) {
        let Some(hub) = self.st.lock().unwrap().kept.as_ref().map(|k| k.hub.clone()) else { return };
        let epoch = self.epoch();
        // The system's name goes with it, once the passport is read (soon
        // after the start; it is not waited for again).
        for _ in 0..80 {
            if engine.passport_read() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        for attempt in 0..2 {
            let (key, name) = match self.computer_key(&hub, attempt > 0) {
                Ok(found) => found,
                Err(why) => {
                    eprintln!("tterm: this computer is not shown to tTerm: {why}");
                    self.set_here(epoch, None, Some(why));
                    return;
                }
            };
            let name = name.unwrap_or_else(|| engine.machine_name.clone());
            // No "app": tTerm Web shows it as the agent's version, and no
            // agent runs here for it yet.
            let body = json!({"key": key, "name": link_name(&name), "os": engine.passport_os()});
            let answer = match self.call("POST", "/api/computers/this", Some(body.to_string().as_bytes()), false).await {
                Ok(a) => a,
                // Asked again when tTerm answers.
                Err(_) => return,
            };
            match answer.status {
                200 | 201 => {
                    let m = answer.json().unwrap_or(Value::Null);
                    let m = &m["machine"];
                    let here = Uuid::parse_str(m["id"].as_str().unwrap_or("")).ok().map(|id| Here {
                        id,
                        name: m["name"].as_str().unwrap_or("").to_string(),
                        project_id: m["projectId"].as_str().unwrap_or("").to_string(),
                        code: m["code"].as_str().unwrap_or("").to_string(),
                    });
                    self.set_here(epoch, here, None);
                    return;
                }
                // A key of a removed computer, or a command's token: a new
                // key, once.
                410 if attempt == 0 => continue,
                _ => {
                    let why = answer.error().unwrap_or_else(|| format!("tTerm answered {}", answer.status));
                    eprintln!("tterm: this computer is no machine of the account's: {why}");
                    self.set_here(epoch, None, Some(why));
                    return;
                }
            }
        }
    }

    /// The computer's key: the agent's, when its file is for this tTerm;
    /// written there if there is no file, or `fresh` (tTerm refused the one
    /// there). Err when the file is another tTerm Web's, or has no key.
    fn computer_key(&self, hub: &str, fresh: bool) -> Result<(String, Option<String>), String> {
        if !good_hub(hub) {
            return Err(format!("tTerm named its agents' address as {hub:?}, which does not go into the agent's file."));
        }
        let shown = self.env_file.display();
        let env = AgentEnv::read(&self.env_file).map_err(|e| format!("{shown} could not be read: {e}"))?;
        match env {
            Some(env) if env.hub.as_deref() != Some(hub) => Err(format!("This computer's agent connects to another tTerm Web ({}).", env.hub.unwrap_or_default())),
            Some(env) if !fresh => match env.key.clone().filter(|k| is_token(k)) {
                Some(key) => Ok((key, env.name.clone())),
                None => Err(format!("{shown} has no key tTerm can take: the agent's installer makes one.")),
            },
            Some(env) => {
                let key = AgentEnv::new_key();
                AgentEnv::write(&self.env_file, hub, &key, Some(&env)).map_err(|e| format!("{shown} could not be written: {e}"))?;
                Ok((key, env.name.clone()))
            }
            None => {
                let key = AgentEnv::new_key();
                AgentEnv::write(&self.env_file, hub, &key, None).map_err(|e| format!("{shown} could not be written: {e}"))?;
                Ok((key, None))
            }
        }
    }

    fn set_here(&self, epoch: u64, here: Option<Here>, why: Option<String>) {
        {
            let mut st = self.st.lock().unwrap();
            if st.epoch != epoch || st.kept.is_none() {
                return;
            }
            st.details.here = here;
            st.details.not_here = why;
            st.asked_here = true;
        }
        self.keep_details(epoch);
    }

    /// tTerm's state named this computer's machine as it is now (renamed,
    /// or in another project): kept.
    fn update_here(&self, epoch: u64, cloud: &Value) {
        let Some(here) = self.here() else { return };
        let found = cloud["projects"].as_array().into_iter().flatten().find_map(|p| {
            p["machines"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|m| m["id"].as_str() == Some(&here.id.to_string()))
                .map(|m| (p, m))
        });
        if let Some((p, m)) = found {
            let now = Here {
                id: here.id,
                name: m["name"].as_str().unwrap_or(&here.name).to_string(),
                project_id: p["id"].as_str().unwrap_or(&here.project_id).to_string(),
                code: p["code"].as_str().unwrap_or(&here.code).to_string(),
            };
            if now != here {
                {
                    let mut st = self.st.lock().unwrap();
                    if st.epoch != epoch {
                        return;
                    }
                    st.details.here = Some(now);
                }
                self.keep_details(epoch);
            }
        }
    }

    // ------------------------------------------------------- the state

    /// What tTerm has for the page now (`/api/state`), kept for when it
    /// cannot be reached.
    pub async fn cloud_state(self: &Arc<Self>, background: bool) -> Result<Value, Trouble> {
        let epoch = self.epoch();
        let answer = self.call("GET", "/api/state", None, background).await?;
        let Some(state) = answer.json().filter(|_| answer.status == 200) else {
            eprintln!("tterm: tTerm's state came back {}", answer.status);
            return Err(Trouble::Offline);
        };
        self.update_here(epoch, &state);
        let text = state.to_string();
        let me = json!({"id": state["me"]["id"], "name": state["me"]["name"], "email": state["me"]["email"]});
        let renamed = {
            let _one = self.files.lock().unwrap();
            let (write, renamed) = {
                let mut st = self.st.lock().unwrap();
                if st.epoch != epoch || st.kept.is_none() {
                    // Signed out, or in again, meanwhile: not this account's.
                    return Err(Trouble::SignedOut);
                }
                st.last = Some(state.clone());
                // Who signed in, as tTerm says it now: for the page when
                // tTerm cannot be reached.
                let renamed = state["me"].is_object() && st.details.me != me;
                if renamed {
                    st.details.me = me;
                }
                let write = st.written.as_deref() != Some(text.as_str());
                if write {
                    st.written = Some(text.clone());
                }
                (write, renamed)
            };
            if write {
                if let Err(e) = write_private(&self.dir.join(STATE_FILE), text.as_bytes()) {
                    eprintln!("tterm: could not keep tTerm's state: {e}");
                }
            }
            renamed
        };
        if renamed {
            self.keep_details(epoch);
        }
        Ok(state)
    }

    // ------------------------------------------------------- signing out

    /// Sign out in the app: tTerm forgets this app's device, and the app its
    /// key. Without a connection, or if tTerm does not agree, the key goes
    /// here all the same: the device then stays in Devices until forgotten
    /// there, or 90 days.
    pub async fn sign_out(self: &Arc<Self>) {
        let (kept, session) = {
            let st = self.st.lock().unwrap();
            (st.kept.clone(), st.session.clone())
        };
        if let Some(kept) = kept {
            let mut cookies = format!("{}={}", device_cookie(&kept.cookie), kept.key);
            if let Some(s) = session {
                cookies = format!("{}={s}; {cookies}", kept.cookie);
            }
            match self.cloud.send("POST", "/api/auth/signout", Some(b"{}"), Some(&cookies), false).await {
                Ok(a) if a.status == 200 => {}
                Ok(a) => eprintln!("tterm: signed out here; tTerm answered {}: the device stays in Devices until forgotten there", a.status),
                Err(why) => eprintln!("tterm: signed out here; tTerm could not be told ({}): the device stays in Devices until forgotten there", why.0),
            }
        }
        self.forget_here().await;
    }

    /// This computer only, as before signing in: the key and everything
    /// kept of the account go.
    pub async fn forget_here(&self) {
        let had = {
            let mut st = self.st.lock().unwrap();
            st.epoch += 1;
            st.asked_here = false;
            st.kept.take().is_some()
        };
        self.drop_kept();
        self.cancel_link();
        if had {
            let host = self.host.clone();
            let gone = tokio::task::spawn_blocking(move || host.delete_key()).await.unwrap_or_else(|e| Err(e.to_string()));
            if let Err(why) = gone {
                eprintln!("tterm: the device's key could not be taken out of the keychain: {why}");
            }
        }
        self.online.send_replace(true);
    }

    // ------------------------------------------------- notes to Personal

    /// Notes made on this computer before signing in go to Personal in
    /// tTerm, one by one; each is deleted here once it is there. Its id in
    /// tTerm is kept here before it gets its text, so that one begun and
    /// broken off is finished the next time, not made twice. Without tTerm
    /// the rest waits; a note tTerm refuses waits too, and the others go.
    pub async fn move_notes(self: &Arc<Self>, engine: &Arc<crate::Engine>) {
        {
            let mut st = self.st.lock().unwrap();
            if st.moving || st.kept.is_none() {
                return;
            }
            st.moving = true;
        }
        let result = self.move_notes_now(engine).await;
        self.st.lock().unwrap().moving = false;
        match result {
            Ok(0) => {}
            Ok(n) => eprintln!("tterm: {n} notes from this computer went to Personal in tTerm"),
            Err(why) => eprintln!("tterm: notes from this computer did not all go to tTerm yet: {why}"),
        }
    }

    async fn move_notes_now(self: &Arc<Self>, engine: &Arc<crate::Engine>) -> Result<usize, String> {
        let local = engine.notes_me().project_id;
        let leaving = engine.terminals.store.run(move |c| crate::notes::to_move(c, &local)).await.ok_or("the store stopped")?.map_err(|e| e.message().to_string())?;
        if leaving.is_empty() {
            return Ok(0);
        }
        let state = self.cloud_state(true).await.map_err(|t| format!("{t:?}"))?;
        let personal = personal_project(&state).cloned().ok_or("no Personal in tTerm")?;
        let mut moved = 0;
        for folder in leaving {
            let folder_id = match self.folder_for(&personal, &folder.name).await {
                Ok(id) => id,
                Err(Hold::Stop(why)) => return Err(why),
                Err(Hold::Skip(why)) => {
                    eprintln!("tterm: the folder {} stays on this computer for now: {why}", folder.name);
                    continue;
                }
            };
            for note in &folder.notes {
                match self.move_note(engine, &folder_id, note).await {
                    Ok(()) => moved += 1,
                    Err(Hold::Stop(why)) => return Err(why),
                    Err(Hold::Skip(why)) => eprintln!("tterm: a note stays on this computer for now: {why}"),
                }
            }
            let gone = folder.id.clone();
            engine.terminals.store.run(move |c| crate::notes::folder_moved(c, &gone)).await;
        }
        Ok(moved)
    }

    /// The folder of Personal in tTerm with this name: there already, or
    /// made.
    async fn folder_for(self: &Arc<Self>, personal: &Value, name: &str) -> Result<String, Hold> {
        let find = |project: &Value| {
            project["folders"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|f| f["name"].as_str().map(|n| n.to_lowercase()) == Some(name.to_lowercase()))
                .and_then(|f| f["id"].as_str().map(str::to_string))
        };
        if let Some(id) = find(personal) {
            return Ok(id);
        }
        let pid = personal["id"].as_str().unwrap_or("");
        let a = self.call("POST", "/api/folders", Some(json!({"projectId": pid, "name": name}).to_string().as_bytes()), false).await?;
        match a.status {
            201 => a.json().and_then(|f| f["id"].as_str().map(str::to_string)).ok_or_else(|| Hold::Skip("tTerm's answer had no folder".into())),
            409 => {
                // Made meanwhile, elsewhere: it is there now.
                let state = self.cloud_state(true).await?;
                let pid = pid.to_string();
                let project = state["projects"].as_array().into_iter().flatten().find(|p| p["id"].as_str() == Some(pid.as_str())).cloned();
                project.as_ref().and_then(find).ok_or_else(|| Hold::Skip(a.error().unwrap_or_default()))
            }
            status => Err(Hold::Skip(format!("tTerm answered {status}: {}", a.error().unwrap_or_default()))),
        }
    }

    /// One note to tTerm: made there (or found, if begun before), then its
    /// text saved as made from its first version, which tTerm merges with
    /// whatever was written in it since (a save that went through before
    /// changes nothing). Deleted here only once tTerm has its text.
    async fn move_note(self: &Arc<Self>, engine: &Arc<crate::Engine>, folder_id: &str, note: &crate::notes::Leaving) -> Result<(), Hold> {
        let store = &engine.terminals.store;
        let local_id = note.id.clone();
        let begun = store.run(move |c| crate::notes::moving_of(c, &local_id)).await.flatten();
        let mut there = None;
        if let Some(id) = begun {
            let a = self.call("GET", &format!("/api/notes/{id}"), None, true).await?;
            match a.status {
                200 => there = Some(id),
                // Deleted there meanwhile: made again.
                404 => {}
                status => return Err(Hold::Skip(format!("tTerm answered {status} for the note begun before"))),
            }
        }
        let id = match there {
            Some(id) => id,
            None => {
                let a = self.call("POST", "/api/notes", Some(json!({"folderId": folder_id, "title": note.title}).to_string().as_bytes()), false).await?;
                if a.status != 201 {
                    return Err(Hold::Skip(format!("tTerm answered {}: {}", a.status, a.error().unwrap_or_default())));
                }
                let id = a.json().and_then(|n| n["id"].as_str().map(str::to_string)).unwrap_or_default();
                if id.is_empty() {
                    return Err(Hold::Skip("tTerm's answer had no note".into()));
                }
                let (local_id, cloud_id) = (note.id.clone(), id.clone());
                if store.run(move |c| crate::notes::moving(c, &local_id, &cloud_id)).await != Some(true) {
                    return Err(Hold::Stop("the store did not keep which note is tTerm's".into()));
                }
                id
            }
        };
        if !note.blocks.is_empty() {
            let body = json!({"baseVersion": 1, "title": note.title, "blocks": note.blocks});
            let a = self.call("PUT", &format!("/api/notes/{id}"), Some(body.to_string().as_bytes()), false).await?;
            match a.status {
                200 => {}
                // Changed there the same places meanwhile: if all of this
                // note's blocks are there, its save went through before.
                409 => {
                    let theirs: Vec<String> = a.json().and_then(|v| v["note"]["blocks"].as_array().cloned()).unwrap_or_default().iter().filter_map(|b| b["id"].as_str().map(str::to_string)).collect();
                    let all_there = note.blocks.iter().all(|b| b["id"].as_str().map(|i| theirs.iter().any(|t| t == i)).unwrap_or(false));
                    if !all_there {
                        return Err(Hold::Skip("the note was changed in tTerm meanwhile, the same places".into()));
                    }
                }
                status => return Err(Hold::Skip(format!("tTerm answered {status}: {}", a.error().unwrap_or_default()))),
            }
        }
        let gone = note.id.clone();
        store.run(move |c| crate::notes::moved(c, &gone)).await;
        Ok(())
    }
}

/// tTerm's answer to a request whose session ended: 401 with `signedOut`,
/// as `signed_in` in page.py gives it. Other 401s are answers of their own.
fn session_over(answer: &Answer) -> bool {
    answer.status == 401 && answer.json().map(|v| v["signedOut"] == true).unwrap_or(false)
}

/// The name of the device's cookie, next to the session's: `__Host-` on
/// https as well.
pub fn device_cookie(session_cookie: &str) -> String {
    if session_cookie.starts_with("__Host-") {
        "__Host-tterm-device".into()
    } else {
        "tterm-device".into()
    }
}

/// The person's Personal in tTerm's state: their own first project.
pub fn personal_project(state: &Value) -> Option<&Value> {
    let projects = state["projects"].as_array()?;
    projects
        .iter()
        .find(|p| p["personal"] == true && p["own"] != false)
        .or_else(|| projects.iter().find(|p| p["own"] == true))
        .or_else(|| projects.first())
}

/// The page's state when signed in: tTerm's, with this computer's machine
/// marked `here` (and online: its terminals run in this app) and this app's
/// terminals with the rest. A computer that is no machine of the account's
/// is in Personal all the same, as `local_machine`. `offline`: tTerm could
/// not be reached, and this is what it said last.
pub fn merge_state(cloud: &Value, here: Option<&Here>, local_machine: Value, local_terminals: Vec<Value>, offline: bool) -> Value {
    let mut state = cloud.clone();
    let mut found = false;
    // What this app read of this computer itself, fuller than tTerm's.
    let passport = local_machine.get("passport").filter(|p| p.as_object().map(|o| !o.is_empty()).unwrap_or(false)).cloned();
    if let Some(here) = here {
        let id = here.id.to_string();
        if let Some(projects) = state["projects"].as_array_mut() {
            for p in projects.iter_mut() {
                if let Some(machines) = p["machines"].as_array_mut() {
                    for m in machines.iter_mut() {
                        if m["id"].as_str() == Some(id.as_str()) {
                            m["here"] = json!(true);
                            m["online"] = json!(true);
                            if let Some(p) = &passport {
                                m["os"] = p.get("os").cloned().unwrap_or(Value::Null);
                                m["passport"] = p.clone();
                            }
                            found = true;
                        }
                    }
                }
            }
        }
    }
    if !found {
        let mut machine = local_machine;
        machine["here"] = json!(true);
        if let Some(here) = here {
            machine["id"] = json!(here.id.to_string());
            machine["name"] = json!(here.name);
        }
        let personal_id = personal_project(&state).and_then(|p| p["id"].as_str().map(str::to_string));
        if let Some(projects) = state["projects"].as_array_mut() {
            if let Some(p) = projects.iter_mut().find(|p| p["id"].as_str().map(str::to_string) == personal_id) {
                match p["machines"].as_array_mut() {
                    Some(list) => list.insert(0, machine),
                    None => p["machines"] = json!([machine]),
                }
            }
        }
    }
    let mut terminals = state["terminals"].as_array().cloned().unwrap_or_default();
    terminals.extend(local_terminals);
    state["terminals"] = Value::Array(terminals);
    state["app"] = json!(true);
    state["offline"] = json!(offline);
    if let Some(o) = state.as_object_mut() {
        o.remove("local");
        o.remove("welcome");
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_7636_s256() {
        assert_eq!(challenge_of("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn the_code_is_the_pages() {
        // As appLink.ts works it out (checked with the page's own code).
        assert_eq!(link_code("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"), "1MM-SP7");
        let c = link_code(&challenge_of(&random_token(48)));
        assert_eq!(c.len(), 7);
        assert!(c.chars().all(|ch| ch == '-' || ALPHABET.contains(&(ch as u8))));
    }

    #[test]
    fn secrets_and_keys() {
        let v = random_token(48);
        assert_eq!(v.len(), 64);
        assert!(is_token(&random_token(24)));
        assert_eq!(random_token(24).len(), 32);
        assert!(!is_token("short"));
        assert!(!is_token(&"a".repeat(65)));
        assert!(!is_token(&format!("{}!", "a".repeat(40))));
        assert!(same("abc", "abc") && !same("abc", "abd") && !same("abc", "abcd"));
        for _ in 0..200 {
            assert!(!AgentEnv::new_key().starts_with('-'));
        }
    }

    #[test]
    fn names_and_queries() {
        assert_eq!(encode("MacBook Pro (Denis)"), "MacBook%20Pro%20%28Denis%29");
        assert_eq!(encode("Мак"), "%D0%9C%D0%B0%D0%BA");
        assert_eq!(link_name("  Mac\tBook \n Pro "), "Mac Book Pro");
        assert_eq!(link_name("\u{7}"), "computer");
        assert_eq!(link_name(&"я".repeat(80)).chars().count(), 64);
        assert_eq!(device_cookie("__Host-tterm-session"), "__Host-tterm-device");
        assert_eq!(device_cookie("tterm-session"), "tterm-device");
    }

    #[test]
    fn hubs_that_go_into_the_agents_file() {
        assert!(good_hub("wss://connect.tterm.net/agent"));
        assert!(good_hub("ws://127.0.0.1:8091/agent"));
        assert!(!good_hub("wss://connect.tterm.net/agent\nTTERM_KEY=x"));
        assert!(!good_hub("https://connect.tterm.net/agent"));
        assert!(!good_hub("wss://connect.tterm.net/other"));
        assert!(!good_hub("wss:///agent"));
        assert!(!good_hub("wss://a b/agent"));
    }

    #[test]
    fn the_agents_file_read_as_its_installer_reads_it() {
        let dir = std::env::temp_dir().join(format!("tterm-env-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("env");
        std::fs::write(&path, "# TTERM_KEY=comment\nTTERM_KEY= first \nTTERM_KEY=second\nTTERM_HUB=wss://h/agent\n").unwrap();
        let env = AgentEnv::read(&path).unwrap().unwrap();
        assert_eq!(env.key.as_deref(), Some(" first "), "the first line, as it is");
        assert_eq!(env.hub.as_deref(), Some("wss://h/agent"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn files_written_side_by_side() {
        let dir = std::env::temp_dir().join(format!("tterm-files-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = Arc::new(dir.join("cloud-state.json"));
        let writers: Vec<_> = (0..8)
            .map(|n| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for i in 0..50 {
                        write_private(&path, json!({"n": n, "i": i, "pad": "x".repeat(4096)}).to_string().as_bytes()).unwrap();
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        let v: Value = serde_json::from_slice(&std::fs::read(&*path).unwrap()).expect("whole");
        assert_eq!(v["i"], 49);
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name()).collect();
        assert_eq!(left.len(), 1, "{left:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_agents_file() {
        let dir = std::env::temp_dir().join(format!("tterm-env-{}", Uuid::new_v4()));
        let path = dir.join(".tterm-web").join("env");
        assert_eq!(AgentEnv::read(&path).unwrap(), None);
        AgentEnv::write(&path, "wss://connect.tterm.net/agent", "k".repeat(32).as_str(), None).unwrap();
        let env = AgentEnv::read(&path).unwrap().unwrap();
        assert_eq!(env.hub.as_deref(), Some("wss://connect.tterm.net/agent"));
        assert_eq!(env.key, Some("k".repeat(32)));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(&format!("TTERM_TOKEN={}", "k".repeat(32))), "{text}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        }
        // A new key keeps the other lines, such as the name.
        std::fs::write(&path, "TTERM_HUB=h\nTTERM_TOKEN=t\nTTERM_KEY=old\nTTERM_NAME=lab\n").unwrap();
        let old = AgentEnv::read(&path).unwrap().unwrap();
        assert_eq!(old.name.as_deref(), Some("lab"));
        AgentEnv::write(&path, "h", &"n".repeat(32), Some(&old)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, format!("TTERM_HUB=h\nTTERM_TOKEN={0}\nTTERM_KEY={0}\nTTERM_NAME=lab\n", "n".repeat(32)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn cloud_state() -> Value {
        json!({
            "me": {"id": "u1", "name": "Denis"},
            "projects": [
                {"id": "p1", "name": "Personal", "code": "P", "personal": true, "own": true, "machines": [
                    {"id": "00000000-0000-0000-0000-000000000001", "kind": "computer", "name": "mac", "online": false},
                    {"id": "s1", "kind": "server", "name": "web-01", "online": true}
                ], "folders": []},
                {"id": "p2", "name": "Client X", "code": "CX", "personal": false, "own": true, "machines": [], "folders": []}
            ],
            "terminals": [{"id": "t-cloud", "machineId": "s1"}]
        })
    }

    #[test]
    fn the_state_with_this_computer() {
        let here = Here { id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), name: "mac".into(), project_id: "p1".into(), code: "P".into() };
        let s = merge_state(&cloud_state(), Some(&here), json!({"id": "local", "passport": {"os": "macOS 15.5", "kernel": "24.5"}}), vec![json!({"id": "t-here"})], false);
        let mac = &s["projects"][0]["machines"][0];
        assert_eq!(mac["here"], true);
        assert_eq!(mac["online"], true, "its terminals run here");
        assert_eq!(mac["passport"]["kernel"], "24.5", "this app's own passport");
        assert_eq!(mac["os"], "macOS 15.5");
        assert_eq!(s["projects"][0]["machines"].as_array().unwrap().len(), 2);
        assert_eq!(s["projects"][0]["machines"][1].get("here"), None);
        assert_eq!(s["terminals"].as_array().unwrap().len(), 2);
        assert_eq!(s["app"], true);
        assert_eq!(s["offline"], false);
        assert_eq!(s.get("local"), None);
        // No machine of the account's: this computer is in Personal anyway.
        let s = merge_state(&cloud_state(), None, json!({"id": "local", "name": "mac"}), vec![], true);
        let first = &s["projects"][0]["machines"][0];
        assert_eq!(first["id"], "local");
        assert_eq!(first["here"], true);
        assert_eq!(s["offline"], true);
        assert_eq!(s["projects"][0]["machines"].as_array().unwrap().len(), 3);
    }
}
