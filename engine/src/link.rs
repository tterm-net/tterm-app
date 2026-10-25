//! The link to tTerm Web: one connection this computer opens itself and
//! keeps, through which tTerm Web reaches the shells here (hosted.rs).
//!
//! A laptop cannot be reached from outside: it has no stable address, it
//! sits behind NAT and it sleeps. So the direction is reversed: this side
//! dials out and keeps the connection alive, and no port is ever opened
//! here. What tterm-agent did in agent.py (connect_once, serve, watchdog,
//! main_loop), the same way and with the same pauses, so that the core needs
//! no change for it. The agent without a window is this engine with this
//! link; the app takes the same link later.
//!
//! The protocol (web 2), all of it on one WebSocket, as the core describes
//! it in tterm/core/agents.py:
//!
//! ```text
//! → hello {token, key, name, user, os, agent, shell, channels, web, kept}
//! ← welcome {name}, or error {error, revoked, forget}
//! ← open {ch, cmd, cols, rows, echo}, resume {ch, from}, size {ch, cols,
//!   rows}, close {ch}, run {id, script, timeout}, ping, hb, error
//! ← bytes: 2, the channel in 4 bytes, keys
//! → bytes: 1, the channel in 4 bytes, output
//! → gap {ch, lost}, exit {ch, code, error, gone}, ran {id, code, out,
//!   err}, hb, pong, bye
//! ```
//!
//! Only tTerm Web's form of it: the Telegram bot's older one (in, out) is
//! not spoken here, and the bot's computers keep agent.py.

use crate::hosted::{self, Frame, Hosted, Out};
use crate::proxy;
use futures_util::stream::SplitStream;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch, Notify, Semaphore};
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

/// Where the link writes what it has to say: a line, without the prefix.
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

/// What this side can do for tTerm Web, said in its hello: terminals of the
/// page's size, raw bytes both ways, and the short scripts it asks for (1);
/// terminals kept through a dropped connection and taken back after it (2).
pub const WEB_PROTOCOL: u32 = 2;

/// The largest message the hub may send, a script with room to spare.
const MESSAGE_MAX: usize = 16 * 1024 * 1024;

/// What may wait to be written, besides the signs of life: a few frames
/// only. The rest waits in the terminals' own rings (hosted.rs), each its
/// own, so that a flood in one terminal holds the others back as little as
/// it can.
const QUEUE: usize = 8;

/// The system's buffer for what is written and not yet sent. Left to grow,
/// it holds megabytes on a slow uplink, and whatever comes after a flood
/// (another terminal's echo, a sign of life) waits behind all of it. This
/// much still carries several megabytes a second at the usual round trips.
const SEND_BUFFER: u32 = 256 * 1024;

/// What the system says when this machine has no way out right now.
const NO_ROUTE: [i32; 4] = [libc::ENETUNREACH, libc::EHOSTUNREACH, libc::ENETDOWN, libc::EADDRNOTAVAIL];

/// The pauses and limits of the link, agent.py's own; the checks shorten
/// them.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// How often a sign of life goes, and how long silence back is borne.
    pub heartbeat: Duration,
    pub silence_limit: Duration,
    /// The WebSocket's own pings, as agent.py's websockets library sent
    /// them (ping_interval, ping_timeout): answered by the hub's WebSocket
    /// itself, they tell a dead connection sooner than the silence does.
    pub ping_every: Duration,
    pub ping_timeout: Duration,
    /// How often the log says the link is still up. Without it a quiet log
    /// reads the same whether the link sat there healthy for an hour or hung
    /// in a dead socket.
    pub alive_every: Duration,
    /// How far the wall clock must run ahead of the monotonic one to call it
    /// a sleep: the monotonic clock stops while the computer sleeps.
    pub sleep_jump: Duration,
    /// The pause before trying again grows from the first to the second; a
    /// connection that held `healthy_for` was a working one, and after it the
    /// pause starts over.
    pub backoff_start: Duration,
    pub backoff_max: Duration,
    pub healthy_for: Duration,
    /// No network at all (no route out, no name lookup): such a try never
    /// reaches the hub and costs it nothing, so it is made this often,
    /// without growing the pause, and the link is back as soon as Wi-Fi is.
    pub no_network_pause: Duration,
    /// After a reconnect, how long tTerm Web has to take back the terminals
    /// offered to it.
    pub claim_wait: Duration,
    /// How long terminals wait for the link, counted while the computer is
    /// awake: a laptop asleep all night loses nothing.
    pub keep_for: Duration,
    /// A terminal whose shell ended is kept this long after its end was
    /// sent: the link may have gone with the end on its way.
    pub ended_keep: Duration,
    pub sweep_every: Duration,
    /// Connecting, and the answer to the hello, at most.
    pub open_timeout: Duration,
    pub welcome_timeout: Duration,
    /// Stopping: how long the goodbye and the closing handshake after it
    /// may take, websockets' close_timeout for agent.py.
    pub close_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            heartbeat: Duration::from_secs(20),
            silence_limit: Duration::from_secs(50),
            ping_every: Duration::from_secs(20),
            ping_timeout: Duration::from_secs(20),
            alive_every: Duration::from_secs(600),
            sleep_jump: Duration::from_secs(15),
            backoff_start: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            healthy_for: Duration::from_secs(60),
            no_network_pause: Duration::from_secs(3),
            claim_wait: Duration::from_secs(30),
            keep_for: Duration::from_secs(3600),
            ended_keep: Duration::from_secs(120),
            sweep_every: Duration::from_secs(5),
            open_timeout: Duration::from_secs(10),
            welcome_timeout: Duration::from_secs(30),
            close_timeout: Duration::from_secs(10),
        }
    }
}

/// Who this computer is to tTerm Web, and where tTerm Web is.
#[derive(Clone, Debug)]
pub struct Config {
    /// wss://connect.tterm.net/agent; ws:// only for a hub on this computer.
    pub hub: String,
    /// The token from Add a machine: it lets the computer join, once.
    pub token: String,
    /// The computer's own key, made by the installer and never shown: tTerm
    /// Web knows the computer by it from then on. Empty for one started by
    /// hand, whose token is its key.
    pub key: String,
    pub name: String,
    /// Said in the hello: the agent's version.
    pub version: String,
    pub timing: Timing,
    /// The *_proxy variables of the environment it started in (proxy.rs):
    /// the proxy agent.py's websockets went through, it goes through too.
    pub proxy_env: Vec<(String, String)>,
}

/// How the link ended for good.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Stopped on purpose.
    Stopped,
    /// tTerm Web says this computer was removed: trying again is pointless.
    /// `forget`: it says so in as many words, and the key is dead.
    Revoked { error: String, forget: bool },
}

enum Fail {
    Revoked { error: String, forget: bool },
    /// Anything else; `no_network` when the try never left this computer.
    Other { why: String, no_network: bool },
}

impl Fail {
    fn other(why: impl Into<String>) -> Fail {
        Fail::Other { why: why.into(), no_network: false }
    }
}

/// How one connection ended, when not by a failure.
enum Ended {
    Clean,
    Stopped,
}

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Keeps the link, through any number of connections, until it is stopped
/// or tTerm Web says this computer was removed. tTerm Web's terminals are
/// `hosted`'s and live across connections; the caller ends them after.
pub async fn run(config: &Config, hosted: Arc<Hosted>, log: Log, mut stop: watch::Receiver<bool>) -> Outcome {
    let t = config.timing;
    let mut backoff = t.backoff_start;
    // Since when there has been no network, by the monotonic clock: said
    // once, then every `alive_every`, not at every try.
    let mut offline_since: Option<Instant> = None;
    let mut offline_note = Instant::now();
    loop {
        if *stop.borrow() {
            return Outcome::Stopped;
        }
        // By the wall clock, which runs on while the machine sleeps: a
        // connection that was up before a sleep was a working one too.
        let started = SystemTime::now();
        match connect_once(config, &hosted, &log, &mut stop).await {
            Ok(Ended::Stopped) => return Outcome::Stopped,
            Ok(Ended::Clean) => {
                // Reconnect straight away, no pause needed.
                offline_since = None;
                backoff = t.backoff_start;
                log("connection closed, reconnecting");
                if pause(t.backoff_start, &mut stop).await {
                    return Outcome::Stopped;
                }
            }
            Err(Fail::Revoked { error, forget }) => return Outcome::Revoked { error, forget },
            Err(Fail::Other { why, no_network }) => {
                if SystemTime::now().duration_since(started).unwrap_or_default() >= t.healthy_for {
                    // It had been working, so this is an ordinary drop rather
                    // than a hub that keeps failing: try again soon.
                    backoff = t.backoff_start;
                }
                if no_network {
                    // Nothing to wait out at the hub: try again in a moment,
                    // and keep the pause as it was for when the network is
                    // back but the hub is not.
                    let now = Instant::now();
                    match offline_since {
                        None => {
                            offline_since = Some(now);
                            offline_note = now;
                            log(&format!(
                                "no network ({why}), trying every {:.0}s until it is back",
                                t.no_network_pause.as_secs_f64()
                            ));
                        }
                        Some(since) => {
                            if now.duration_since(offline_note) >= t.alive_every {
                                offline_note = now;
                                log(&format!("still no network, for {:.0} min", now.duration_since(since).as_secs_f64() / 60.0));
                            }
                        }
                    }
                    if pause(t.no_network_pause, &mut stop).await {
                        return Outcome::Stopped;
                    }
                    continue;
                }
                offline_since = None;
                log(&format!("no link ({why}), retrying in {:.0}s", backoff.as_secs_f64()));
                if pause(backoff, &mut stop).await {
                    return Outcome::Stopped;
                }
                backoff = (backoff * 2).min(t.backoff_max);
            }
        }
    }
}

/// Resolves once the link is to stop; never, if whoever could stop it is gone.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow_and_update() {
            return;
        }
        if stop.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Waits `wait`; true when stopped meanwhile.
async fn pause(wait: Duration, stop: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(wait) => false,
        _ = stopped(stop) => true,
    }
}

/// One connection, from the hello until it drops.
async fn connect_once(config: &Config, hosted: &Arc<Hosted>, log: &Log, stop: &mut watch::Receiver<bool>) -> Result<Ended, Fail> {
    let t = &config.timing;
    let dialed = tokio::select! {
        r = tokio::time::timeout(t.open_timeout, dial(config)) => r,
        _ = stopped(stop) => return Ok(Ended::Stopped),
    };
    let mut ws = match dialed {
        Ok(Ok(ws)) => ws,
        Ok(Err(fail)) => return Err(fail),
        Err(_) => return Err(Fail::other("the hub did not answer in time")),
    };
    let hello = hello(config, hosted.channels());
    ws.send(Message::Text(hello.to_string().into())).await.map_err(|e| Fail::other(describe(&e)))?;
    // The answer to the hello. The WebSocket's own pings and pongs on the
    // way are not it: the hub's keepalive may ping before a late welcome,
    // and the WebSocket answers by itself, as websockets did for agent.py.
    let answer = async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                other => return other,
            }
        }
    };
    let reply = tokio::select! {
        r = tokio::time::timeout(t.welcome_timeout, answer) => r,
        _ = stopped(stop) => return Ok(Ended::Stopped),
    };
    let understood = |v: serde_json::Result<Value>| match v {
        Ok(v) if v.is_object() => Ok(v),
        _ => Err(Fail::other("the hub's answer was not understood")),
    };
    let reply: Value = match reply {
        Err(_) => return Err(Fail::other("the hub did not answer the hello")),
        Ok(None) | Ok(Some(Ok(Message::Close(_)))) => return Err(Fail::other("the hub closed the connection")),
        Ok(Some(Err(e))) => return Err(Fail::other(describe(&e))),
        Ok(Some(Ok(Message::Text(text)))) => understood(serde_json::from_str(text.as_str()))?,
        Ok(Some(Ok(Message::Binary(data)))) => understood(serde_json::from_slice(&data))?,
        Ok(Some(Ok(_))) => return Err(Fail::other("the hub's answer was not understood")),
    };
    if reply.get("t").and_then(Value::as_str) != Some("welcome") {
        let error = match reply.get("error") {
            None | Some(Value::Null) => "the hub refused the connection".to_string(),
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
        };
        if hosted::truthy(reply.get("revoked"), false) {
            return Err(Fail::Revoked { error, forget: reply.get("forget") == Some(&Value::Bool(true)) });
        }
        return Err(Fail::other(error));
    }
    let name = match reply.get("name") {
        Some(Value::String(s)) => s.clone(),
        _ => config.name.clone(),
    };
    log(&format!("connected as «{name}»"));

    let (sink, mut stream) = ws.split();
    // Everything this connection sends goes through one queue, in order; a
    // slow connection holds the senders back, the shells' output first. The
    // signs of life go ahead of it.
    let (tx, rx) = mpsc::channel::<Frame>(QUEUE);
    let (ctl, ctl_rx) = mpsc::channel::<Frame>(16);
    let (quit, quit_rx) = oneshot::channel::<()>();
    let out = Out::new(tx, ctl);
    let writer = tokio::spawn(async move { write(sink, rx, ctl_rx, quit_rx).await });
    let writer_abort = writer.abort_handle();
    hosted.claim(t.claim_wait);
    let health = Health::new();
    let scripts = Arc::new(Semaphore::new(hosted::SIDE_AT_ONCE));
    let mut tasks = JoinSet::new();
    let mut stopping = false;
    let result = tokio::select! {
        r = serve(&mut stream, hosted, &out, &health, &scripts, &mut tasks, log) => r,
        r = watchdog(&out, &health, t, log) => r,
        r = keepalive(&out, &health, t) => r,
        _ = stopped(stop) => {
            // Stopped on purpose (Ctrl+C, the system): tTerm Web's terminals
            // end with the agent, and it hears so now rather than waiting
            // for them to come back.
            stopping = true;
            hosted.close_all();
            let _ = out.control(json!({"t": "bye"}));
            // The goodbye goes; the output still queued does not, its
            // terminals are ending.
            let _ = quit.send(());
            Ok(Ended::Stopped)
        }
    };
    // The scripts of this connection stop: nobody will read their answers.
    tasks.abort_all();
    hosted.detach(&out);
    drop(out);
    if stopping {
        // The closing handshake after the goodbye, as websockets did it for
        // agent.py: the Close goes, and the hub's own is read before the
        // socket goes. A socket closed with something unread in it (a key,
        // an answer to a sign of life) resets the connection, and whatever
        // was still on its way, the goodbye among it, is thrown away.
        let deadline = tokio::time::Instant::now() + t.close_timeout;
        match tokio::time::timeout_at(deadline, writer).await {
            Ok(Ok(Some(mut sink))) => {
                let _ = tokio::time::timeout_at(deadline, sink.close()).await;
                let _ = tokio::time::timeout_at(deadline, async {
                    while let Some(item) = stream.next().await {
                        if matches!(item, Ok(Message::Close(_)) | Err(_)) {
                            break;
                        }
                    }
                })
                .await;
            }
            _ => writer_abort.abort(),
        }
    } else {
        writer_abort.abort();
    }
    result
}

/// Writes what the connection sends, the signs of life first, until every
/// sender is gone or `quit` says so: then whatever waits on the first lane
/// (the goodbye) goes, and the output queued does not. The sink then, to
/// close; None when writing failed.
async fn write<S>(
    mut sink: S,
    mut rx: mpsc::Receiver<Frame>,
    mut ctl_rx: mpsc::Receiver<Frame>,
    mut quit: oneshot::Receiver<()>,
) -> Option<S>
where
    S: futures_util::Sink<Message> + Unpin,
{
    let (mut ctl_open, mut quit_open) = (true, true);
    loop {
        let next = tokio::select! {
            biased;
            c = ctl_rx.recv(), if ctl_open => match c {
                Some(frame) => Some(frame),
                None => {
                    ctl_open = false;
                    continue;
                }
            },
            q = &mut quit, if quit_open => {
                if q.is_err() {
                    quit_open = false;
                    continue;
                }
                while let Ok(frame) = ctl_rx.try_recv() {
                    if sink.send(message(frame)).await.is_err() {
                        return None;
                    }
                }
                return Some(sink);
            }
            d = rx.recv() => d,
        };
        let Some(frame) = next else { break };
        if sink.send(message(frame)).await.is_err() {
            return None;
        }
    }
    Some(sink)
}

fn message(frame: Frame) -> Message {
    match frame {
        Frame::Text(s) => Message::Text(s.into()),
        Frame::Binary(b) => Message::Binary(b.into()),
        Frame::Ping(b) => Message::Ping(b.into()),
    }
}

/// Connects to the hub, through its proxy if this computer has one
/// (proxy.rs): the name looked up and the address dialled here, so that no
/// network at all can be told from a hub that refuses.
async fn dial(config: &Config) -> Result<Ws, Fail> {
    let hub = config.hub.as_str();
    let request = hub.into_client_request().map_err(|e| Fail::other(format!("the hub's address {hub:?}: {e}")))?;
    let uri = request.uri().clone();
    let tls = match uri.scheme_str() {
        Some("wss") => true,
        Some("ws") => false,
        _ => return Err(Fail::other(format!("the hub's address {hub:?} must start with wss://"))),
    };
    let host = uri.host().unwrap_or("").trim_start_matches('[').trim_end_matches(']').to_string();
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let env = proxy::from_environment(&config.proxy_env);
    let system = if env.is_empty() { proxy::system().await } else { None };
    let through = proxy::choose(&host, port, tls, &env, system.as_ref()).map_err(Fail::other)?;
    let (to_host, to_port) = match &through {
        Some(p) => (p.host.clone(), p.port),
        None => (host.clone(), port),
    };
    let addrs: Vec<std::net::SocketAddr> = match tokio::net::lookup_host((to_host.as_str(), to_port)).await {
        Ok(found) => found.collect(),
        Err(e) => return Err(Fail::Other { why: format!("cannot look up {to_host}: {e}"), no_network: true }),
    };
    if addrs.is_empty() {
        return Err(Fail::Other { why: format!("cannot look up {to_host}"), no_network: true });
    }
    let mut last = None;
    let mut stream = None;
    for addr in addrs {
        let socket = if addr.is_ipv4() { tokio::net::TcpSocket::new_v4() } else { tokio::net::TcpSocket::new_v6() };
        let connected = match socket {
            Ok(socket) => {
                let _ = socket.set_send_buffer_size(SEND_BUFFER);
                socket.connect(addr).await
            }
            Err(e) => Err(e),
        };
        match connected {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let Some(mut stream) = stream else {
        let e = last.expect("an address was tried");
        let no_network = e.raw_os_error().is_some_and(|code| NO_ROUTE.contains(&code));
        let why = match &through {
            Some(p) => format!("the proxy {}: {e}", p.name()),
            None => e.to_string(),
        };
        return Err(Fail::Other { why, no_network });
    };
    let _ = stream.set_nodelay(true);
    if let Some(p) = &through {
        proxy::tunnel(&mut stream, p, &host, port, tls, &format!("tterm-agent/{}", config.version)).await.map_err(Fail::other)?;
    }
    let config = WebSocketConfig::default().max_message_size(Some(MESSAGE_MAX)).max_frame_size(Some(MESSAGE_MAX));
    let connector = if tls { Connector::Rustls(tls_config()) } else { Connector::Plain };
    let (ws, _) = tokio_tungstenite::client_async_tls_with_config(request, stream, Some(config), Some(connector))
        .await
        .map_err(|e| Fail::other(describe(&e)))?;
    Ok(ws)
}

/// TLS for the hub: TLS 1.2 or 1.3, the certificate checked against
/// Mozilla's roots, built into the agent so that it does not depend on what
/// the system has, and against the system's own as well, as agent.py's
/// Python took them: a company's root for a proxy that looks into TLS, the
/// private one of a hub of one's own. Those that cannot be read are passed
/// over; a certificate no root vouches for is never taken. The engine's one
/// TLS setting: whatever else of it goes to tTerm Web takes it too.
pub fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            let _ = roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("the default versions of TLS")
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

fn describe(e: &tungstenite::Error) -> String {
    match e {
        tungstenite::Error::Http(response) => format!("the hub answered HTTP {}", response.status().as_u16()),
        other => other.to_string(),
    }
}

/// The hello: who this computer is, and the terminals it kept.
fn hello(config: &Config, kept: Vec<u32>) -> Value {
    let mut hello = json!({
        "t": "hello",
        "token": config.token,
        "name": config.name,
        "user": user(),
        "os": os_name(),
        "agent": config.version,
        // The bot writes its markers for the shell on this end; tTerm Web
        // looks its shells up itself.
        "shell": shell_name(),
        // A shell per terminal, and tTerm Web's own terminals (web).
        "channels": 1,
        "web": WEB_PROTOCOL,
        "kept": kept,
    });
    // Only from tTerm Web's installer.
    if !config.key.is_empty() {
        hello["key"] = json!(config.key);
    }
    hello
}

fn user() -> String {
    for name in ["USER", "LOGNAME"] {
        if let Ok(v) = std::env::var(name) {
            if !v.is_empty() {
                return v;
            }
        }
    }
    String::new()
}

fn os_name() -> String {
    match nix::sys::utsname::uname() {
        Ok(u) => format!("{} {}", u.sysname().to_string_lossy(), u.release().to_string_lossy()),
        Err(_) => std::env::consts::OS.to_string(),
    }
}

/// The person's shell when it is bash or zsh, otherwise bash, as agent.py
/// said it.
fn shell_name() -> String {
    let mut shell = std::env::var("SHELL").unwrap_or_default();
    if shell.is_empty() {
        if let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::getuid()) {
            shell = user.shell.to_string_lossy().to_string();
        }
    }
    let base = shell.rsplit('/').next().unwrap_or("").to_string();
    if base.contains("bash") || base.contains("zsh") {
        base
    } else {
        "bash".to_string()
    }
}

/// Whether the link is actually alive. A socket error cannot be relied
/// upon: when the laptop falls asleep the hub sees the connection drop while
/// this side is left half-open, nothing to read, nothing to fail on, for
/// hours. So this side checks for itself: a sign of life goes, any answer is
/// expected, and a sleep is watched for apart.
struct Health {
    /// When the hub last said something: its messages, not the WebSocket's
    /// pings and pongs, which its WebSocket answers by itself.
    last_in: Mutex<Instant>,
    /// Pongs heard: the answers to the keepalive's pings.
    pongs: AtomicU64,
    pong: Notify,
}

impl Health {
    fn new() -> Health {
        Health { last_in: Mutex::new(Instant::now()), pongs: AtomicU64::new(0), pong: Notify::new() }
    }

    fn heard(&self) {
        *self.last_in.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    fn last_in(&self) -> Instant {
        *self.last_in.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn ponged(&self) {
        self.pongs.fetch_add(1, Ordering::Relaxed);
        self.pong.notify_one();
    }
}

/// The wall clock against the monotonic one: on macOS and Linux the
/// monotonic clock stops while the computer sleeps, so how far the wall
/// clock ran ahead tells a sleep.
struct Clock {
    mono: Instant,
    wall: SystemTime,
}

impl Clock {
    fn now() -> Clock {
        Clock { mono: Instant::now(), wall: SystemTime::now() }
    }

    fn slept(&mut self) -> f64 {
        let (mono, wall) = (Instant::now(), SystemTime::now());
        let wall_ran = match wall.duration_since(self.wall) {
            Ok(d) => d.as_secs_f64(),
            Err(e) => -e.duration().as_secs_f64(),
        };
        let mono_ran = mono.duration_since(self.mono).as_secs_f64();
        self.mono = mono;
        self.wall = wall;
        wall_ran - mono_ran
    }
}

/// Takes tTerm Web's messages and does what they say.
async fn serve(
    stream: &mut SplitStream<Ws>,
    hosted: &Arc<Hosted>,
    out: &Out,
    health: &Health,
    scripts: &Arc<Semaphore>,
    tasks: &mut JoinSet<()>,
    log: &Log,
) -> Result<Ended, Fail> {
    while let Some(item) = stream.next().await {
        let message = item.map_err(|e| Fail::other(describe(&e)))?;
        match message {
            // The WebSocket's own, answered by it (tungstenite, as websockets
            // did for agent.py): not the hub speaking.
            Message::Pong(_) => {
                health.ponged();
                continue;
            }
            Message::Ping(_) | Message::Frame(_) => continue,
            _ => health.heard(),
        }
        match message {
            Message::Binary(data) => {
                // Keys for one of the terminals.
                if data.len() > 5 && data[0] == hosted::INPUT {
                    let ch = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                    hosted.input(ch, &data[5..]);
                }
            }
            Message::Text(text) => {
                let Ok(msg @ Value::Object(_)) = serde_json::from_str::<Value>(text.as_str()) else { continue };
                // A channel is a whole number, or there is none.
                let ch: Option<i64> = match msg.get("ch") {
                    None | Some(Value::Null) => None,
                    Some(Value::Number(n)) => match (n.as_i64(), n.as_u64()) {
                        (Some(i), _) => Some(i),
                        (None, Some(_)) => Some(i64::MAX),
                        _ => continue,
                    },
                    Some(_) => continue,
                };
                let channel = ch.filter(|c| (0..1i64 << 32).contains(c)).map(|c| c as u32);
                let terminal = channel.filter(|c| *c > 0);
                match msg.get("t").and_then(Value::as_str) {
                    Some("open") => {
                        if let Some(ch) = terminal {
                            hosted.open(ch, &msg, out).await;
                        }
                    }
                    Some("resume") => {
                        if let Some(ch) = terminal {
                            hosted.resume(ch, hosted::offset(msg.get("from")), out).await;
                        }
                    }
                    Some("size") => {
                        if let Some(ch) = channel {
                            hosted.resize(ch, &msg);
                        }
                    }
                    Some("close") => {
                        // About the terminal, not the link: the connection
                        // and every other terminal stay as they are.
                        if let Some(ch) = channel {
                            if hosted.close(ch) {
                                log(&format!("hub closed terminal {ch}, keeping the link"));
                            }
                        }
                    }
                    Some("run") => {
                        let permits = scripts.clone();
                        let hosted = hosted.clone();
                        let out = out.clone();
                        tasks.spawn(async move {
                            let Ok(_permit) = permits.acquire_owned().await else { return };
                            hosted.script(&msg, &out).await;
                        });
                    }
                    Some("ping") => {
                        let _ = out.control(json!({"t": "pong"}));
                    }
                    Some("error") => {
                        // tTerm Web ends the connection and says why. A
                        // computer it no longer knows is not coming back;
                        // anything else is tried again after the usual pause.
                        let error = match msg.get("error") {
                            Some(Value::String(s)) if !s.is_empty() => s.clone(),
                            None | Some(Value::Null) | Some(Value::String(_)) => "the hub ended the connection".to_string(),
                            Some(other) => other.to_string(),
                        };
                        if msg.get("revoked") == Some(&Value::Bool(true)) {
                            return Err(Fail::Revoked { error, forget: msg.get("forget") == Some(&Value::Bool(true)) });
                        }
                        return Err(Fail::other(error));
                    }
                    // hb: the answer to ours, heard above; in: the bot's.
                    _ => {}
                }
            }
            Message::Close(_) => return Ok(Ended::Clean),
            _ => {}
        }
        while tasks.try_join_next().is_some() {}
    }
    Ok(Ended::Clean)
}

/// Drops a dead connection, so that the link comes back: a sign of life
/// every `heartbeat`, any answer expected within `silence_limit`, and a
/// sleep of the computer noticed by its clocks.
async fn watchdog(out: &Out, health: &Health, t: &Timing, log: &Log) -> Result<Ended, Fail> {
    let mut last_note = Instant::now();
    // Signs of life sent since the last note, and after how many of them the
    // hub was heard before the next one went: the line in the log then says
    // how the link has been, not only that it is still there.
    let (mut sent, mut answered) = (0u64, 0u64);
    let mut went = Instant::now();
    let mut clock = Clock::now();
    loop {
        tokio::time::sleep(t.heartbeat).await;
        if sent > 0 && health.last_in() >= went {
            answered += 1;
        }
        if last_note.elapsed() >= t.alive_every {
            let minutes = last_note.elapsed().as_secs_f64() / 60.0;
            last_note = Instant::now();
            log(&format!("link alive: the hub answered {answered} of {sent} signs of life in {minutes:.0} min"));
            sent = 0;
            answered = 0;
        }
        let drift = clock.slept();
        if drift > t.sleep_jump.as_secs_f64() {
            log(&format!("machine slept for about {drift:.0}s — reconnecting"));
            return Ok(Ended::Clean);
        }
        went = Instant::now();
        match out.control(json!({"t": "hb"})) {
            Ok(()) => sent += 1,
            // Even the first lane is full: the connection is stuck; the
            // silence below decides.
            Err(true) => {}
            Err(false) => {
                log("could not send sign of life: the connection is gone");
                return Ok(Ended::Clean);
            }
        }
        let silent = health.last_in().elapsed();
        if silent > t.silence_limit {
            log(&format!("hub silent for {:.0}s — reconnecting", silent.as_secs_f64()));
            return Ok(Ended::Clean);
        }
    }
}

/// What websockets did for agent.py by itself (ping_interval=20,
/// ping_timeout=20): a ping every `ping_every`, which the hub's WebSocket
/// answers whatever the core is busy with; no pong within `ping_timeout`, and
/// the connection is dead. A link gone while this computer slept or changed
/// networks is noticed in well under a minute, sooner than by the silence.
async fn keepalive(out: &Out, health: &Health, t: &Timing) -> Result<Ended, Fail> {
    let mut latency = Duration::ZERO;
    let mut number: u32 = 0;
    loop {
        tokio::time::sleep(t.ping_every.saturating_sub(latency)).await;
        number = number.wrapping_add(1);
        let before = health.pongs.load(Ordering::Relaxed);
        let went = Instant::now();
        // A full lane is a stuck connection, and a gone one ends serve: the
        // pong decides either way.
        let _ = out.ping(number.to_be_bytes().to_vec());
        let answered = tokio::time::timeout(t.ping_timeout, async {
            loop {
                let pong = health.pong.notified();
                if health.pongs.load(Ordering::Relaxed) != before {
                    return;
                }
                pong.await;
            }
        })
        .await;
        if answered.is_err() {
            return Err(Fail::other("keepalive ping timeout"));
        }
        latency = went.elapsed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On a slow connection, a sign of life does not wait behind the output
    /// queued before it: it goes with the next write.
    #[tokio::test]
    async fn signs_of_life_go_first() {
        let sent = Arc::new(Mutex::new(Vec::<String>::new()));
        let slow = {
            let sent = sent.clone();
            futures_util::sink::unfold((), move |(), msg: Message| {
                let sent = sent.clone();
                async move {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    let what = match msg {
                        Message::Text(t) => t.to_string(),
                        Message::Binary(b) => format!("data {}", b[0]),
                        _ => String::new(),
                    };
                    sent.lock().unwrap().push(what);
                    Ok::<(), tungstenite::Error>(())
                }
            })
        };
        let (tx, rx) = mpsc::channel::<Frame>(QUEUE);
        let (ctl, ctl_rx) = mpsc::channel::<Frame>(16);
        let out = Out::new(tx, ctl);
        for i in 0..QUEUE as u8 {
            out.bytes(vec![i]).await;
        }
        let (_quit, quit_rx) = oneshot::channel();
        let writer = tokio::spawn(write(Box::pin(slow), rx, ctl_rx, quit_rx));
        tokio::time::sleep(Duration::from_millis(10)).await;
        out.control(json!({"t": "hb"})).unwrap();
        drop(out);
        assert!(writer.await.unwrap().is_some());
        let sent = sent.lock().unwrap().clone();
        assert_eq!(sent.len(), QUEUE + 1);
        assert_eq!(sent[1], r#"{"t":"hb"}"#, "the sign of life right after the write under way: {sent:?}");
    }
}
