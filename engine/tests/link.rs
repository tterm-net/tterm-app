//! The link to tTerm Web (link.rs) and its terminals (hosted.rs), against a
//! hub spoken by hand here: what tTerm Web's core says and expects, as
//! tterm/core/agents.py does, with real shells. The pauses are shortened;
//! the rules are agent.py's.

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tterm_engine::hosted::{self, Hosted};
use tterm_engine::link::{self, Config, Log, Outcome, Timing};

const WAIT: Duration = Duration::from_secs(15);

fn timing() -> Timing {
    Timing {
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

/// The agent's side: the link running, its terminals, what it logged.
struct Agent {
    hosted: Arc<Hosted>,
    lines: Arc<Mutex<Vec<String>>>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Outcome>,
}

impl Agent {
    fn start(hub: &str, timing: Timing) -> Agent {
        Agent::start_with(hub, timing, "")
    }

    fn start_with(hub: &str, timing: Timing, key: &str) -> Agent {
        Agent::start_full(hub, timing, key, Vec::new())
    }

    fn start_env(hub: &str, timing: Timing, proxy_env: Vec<(String, String)>) -> Agent {
        Agent::start_full(hub, timing, "", proxy_env)
    }

    fn start_full(hub: &str, timing: Timing, key: &str, proxy_env: Vec<(String, String)>) -> Agent {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let log: Log = {
            let lines = lines.clone();
            Arc::new(move |msg: &str| lines.lock().unwrap().push(msg.to_string()))
        };
        let hosted = Hosted::new(timing, log.clone(), Some("/opt/agent-dir".into()));
        let _keeper = hosted.spawn_keeper();
        let config = Config {
            hub: hub.to_string(),
            token: "t".repeat(32),
            key: key.to_string(),
            name: "test-mac".into(),
            version: "0.14.0".into(),
            timing,
            proxy_env,
        };
        let (stop, rx) = watch::channel(false);
        let task = {
            let hosted = hosted.clone();
            tokio::spawn(async move { link::run(&config, hosted, log, rx).await })
        };
        Agent { hosted, lines, stop, task }
    }

    fn logged(&self, part: &str) -> bool {
        self.lines.lock().unwrap().iter().any(|l| l.contains(part))
    }

    fn log_text(&self) -> String {
        self.lines.lock().unwrap().join("\n")
    }

    async fn until_logged(&self, part: &str) {
        let end = Instant::now() + WAIT;
        while !self.logged(part) {
            assert!(Instant::now() < end, "never logged {part:?}; the log:\n{}", self.log_text());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

async fn until(what: &str, f: impl Fn() -> bool) {
    let end = Instant::now() + WAIT;
    while !f() {
        assert!(Instant::now() < end, "never: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

struct Hub {
    listener: TcpListener,
    port: u16,
}

/// Room for more open files than a Mac gives a process by default (256),
/// as tests/common does: sixteen shells in one check, next to the others
/// running meanwhile.
fn room_for_files() {
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

impl Hub {
    async fn new() -> Hub {
        room_for_files();
        // A receive buffer of a modest size, as across a network; the
        // loopback's own grows to megabytes.
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(64 * 1024).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(64).unwrap();
        let port = listener.local_addr().unwrap().port();
        Hub { listener, port }
    }

    fn url(&self) -> String {
        format!("ws://127.0.0.1:{}/agent", self.port)
    }

    async fn accept(&self) -> Conn {
        let (tcp, _) = tokio::time::timeout(WAIT, self.listener.accept()).await.expect("the agent came").unwrap();
        let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        Conn { ws, hb_back: true }
    }

    /// A connection, its hello read and welcomed.
    async fn welcomed(&self) -> (Conn, Value) {
        let mut conn = self.accept().await;
        let hello = conn.json().await;
        assert_eq!(hello["t"], "hello", "{hello}");
        conn.send(json!({"t": "welcome", "name": "test-mac"})).await;
        (conn, hello)
    }
}

#[derive(Debug)]
enum In {
    Json(Value),
    Out(u32, Vec<u8>),
    Gone,
}

struct Conn {
    ws: WebSocketStream<TcpStream>,
    /// Answers each sign of life as the core does.
    hb_back: bool,
}

impl Conn {
    async fn send(&mut self, v: Value) {
        self.ws.send(Message::Text(v.to_string().into())).await.unwrap();
    }

    async fn keys(&mut self, ch: u32, data: &[u8]) {
        let mut frame = vec![hosted::INPUT];
        frame.extend_from_slice(&ch.to_be_bytes());
        frame.extend_from_slice(data);
        self.ws.send(Message::Binary(frame.into())).await.unwrap();
    }

    /// The next message but signs of life.
    async fn next(&mut self) -> In {
        loop {
            let got = tokio::time::timeout(WAIT, self.ws.next()).await.expect("a message from the agent");
            match got {
                Some(Ok(Message::Close(_))) => {
                    // Answered at once, as tTerm Web's WebSocket does: the
                    // answer tungstenite queued goes now.
                    let _ = SinkExt::close(&mut self.ws).await;
                    return In::Gone;
                }
                None | Some(Err(_)) => return In::Gone,
                Some(Ok(Message::Text(t))) => {
                    let v: Value = serde_json::from_str(t.as_str()).unwrap();
                    if v["t"] == "hb" {
                        if self.hb_back {
                            // The agent may be closing meanwhile.
                            let _ = self.ws.send(Message::Text(json!({"t": "hb"}).to_string().into())).await;
                        }
                        continue;
                    }
                    return In::Json(v);
                }
                Some(Ok(Message::Binary(b))) => {
                    assert_eq!(b[0], hosted::OUTPUT);
                    assert!(b.len() > 5 && b.len() <= 5 + hosted::FRAME_OUT, "a frame of {} bytes", b.len());
                    let ch = u32::from_be_bytes([b[1], b[2], b[3], b[4]]);
                    return In::Out(ch, b[5..].to_vec());
                }
                Some(Ok(_)) => continue,
            }
        }
    }

    async fn json(&mut self) -> Value {
        match self.next().await {
            In::Json(v) => v,
            other => panic!("expected a message, got {other:?}"),
        }
    }

    /// Output of `ch` until it holds `part`; any message on the way is kept.
    async fn output_until(&mut self, ch: u32, part: &str, got: &mut Vec<u8>, msgs: &mut Vec<Value>) {
        while !String::from_utf8_lossy(got).contains(part) {
            match self.next().await {
                In::Out(c, data) if c == ch => got.extend_from_slice(&data),
                In::Out(..) => {}
                In::Json(v) => msgs.push(v),
                In::Gone => panic!("the connection went before {part:?}; got {:?}", String::from_utf8_lossy(got)),
            }
        }
    }

    /// Everything of `ch` until its exit: the output and the exit message.
    async fn until_exit(&mut self, ch: u32) -> (Vec<u8>, Value) {
        let mut got = Vec::new();
        loop {
            match self.next().await {
                In::Out(c, data) if c == ch => got.extend_from_slice(&data),
                In::Json(v) if v["t"] == "exit" && v["ch"] == ch => return (got, v),
                In::Gone => panic!("the connection went; got {:?}", String::from_utf8_lossy(&got)),
                _ => {}
            }
        }
    }

    async fn open(&mut self, ch: u32, cmd: &str) {
        self.send(json!({"t": "open", "ch": ch, "cmd": cmd, "cols": 80, "rows": 24, "echo": true})).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_hello_and_a_terminal() {
    let hub = Hub::new().await;
    let agent = Agent::start_with(&hub.url(), timing(), &"k".repeat(43));
    let (mut conn, hello) = hub.welcomed().await;
    assert_eq!(hello["token"], "t".repeat(32));
    assert_eq!(hello["key"], "k".repeat(43));
    assert_eq!(hello["name"], "test-mac");
    assert_eq!(hello["agent"], "0.14.0");
    assert_eq!(hello["web"], 2);
    assert_eq!(hello["channels"], 1);
    assert_eq!(hello["kept"], json!([]));
    assert!(hello["os"].as_str().unwrap().contains(' '), "system and release: {hello}");
    let shell = hello["shell"].as_str().unwrap();
    assert!(shell == "bash" || shell == "zsh", "{shell}");
    agent.until_logged("connected as «test-mac»").await;

    conn.send(json!({"t": "open", "ch": 5, "cmd": "stty size; printf '\\320\\266-%s\\n' ok; echo \"$TERM $TTERM_AGENT_DIR\"; exit 3", "cols": 100, "rows": 30})).await;
    let (out, exit) = conn.until_exit(5).await;
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("30 100"), "{text}");
    assert!(text.contains("ж-ok"), "{text}");
    assert!(text.contains("xterm-256color /opt/agent-dir"), "{text}");
    assert_eq!(exit, json!({"t": "exit", "code": 3, "ch": 5}));
    drop(agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_sizes_and_echo_off() {
    let hub = Hub::new().await;
    let _agent = Agent::start(&hub.url(), timing());
    let (mut conn, _) = hub.welcomed().await;
    conn.open(6, "IFS= read -r line; echo \"got:$line\"").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    conn.keys(6, "привет\n".as_bytes()).await;
    let (out, exit) = conn.until_exit(6).await;
    assert!(String::from_utf8_lossy(&out).contains("got:привет"), "{:?}", String::from_utf8_lossy(&out));
    assert_eq!(exit["code"], 0);

    // The page's size changes while it runs.
    conn.open(7, "sleep 0.5; stty size").await;
    conn.send(json!({"t": "size", "ch": 7, "cols": 120, "rows": 40})).await;
    let (out, _) = conn.until_exit(7).await;
    assert!(String::from_utf8_lossy(&out).contains("40 120"), "{:?}", String::from_utf8_lossy(&out));

    // Echo off at the start, as when the core types its one-time key: the
    // key never shows; the script turns echo back on.
    conn.send(json!({"t": "open", "ch": 8, "cmd": "IFS= read -r k; stty echo; echo \"key=$k\"", "cols": 80, "rows": 24, "echo": false})).await;
    conn.keys(8, b"s3cr3t\n").await;
    let (out, _) = conn.until_exit(8).await;
    let text = String::from_utf8_lossy(&out);
    assert_eq!(text.matches("s3cr3t").count(), 1, "{text}");
    assert!(text.contains("key=s3cr3t"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn close_twice_and_too_many() {
    let hub = Hub::new().await;
    let agent = Agent::start(&hub.url(), timing());
    let (mut conn, _) = hub.welcomed().await;
    conn.open(1, "echo first; sleep 30").await;
    let (mut got, mut msgs) = (Vec::new(), Vec::new());
    conn.output_until(1, "first", &mut got, &mut msgs).await;
    // The same window twice: the first stays. Whatever channel 1 prints
    // until channel 2 is up, and a while after, is looked at.
    conn.open(1, "echo second; sleep 30").await;
    conn.open(2, "echo other; sleep 30").await;
    let (mut ones, mut other) = (Vec::new(), Vec::new());
    while !String::from_utf8_lossy(&other).contains("other") {
        match conn.next().await {
            In::Out(1, data) => ones.extend_from_slice(&data),
            In::Out(2, data) => other.extend_from_slice(&data),
            In::Out(..) => {}
            In::Json(v) => msgs.push(v),
            In::Gone => panic!("gone"),
        }
    }
    let settle = tokio::time::Instant::now() + Duration::from_millis(500);
    while let Ok(next) = tokio::time::timeout_at(settle, conn.next()).await {
        if let In::Out(1, data) = next {
            ones.extend_from_slice(&data);
        }
    }
    assert!(!String::from_utf8_lossy(&ones).contains("second"), "a second shell on channel 1: {:?}", String::from_utf8_lossy(&ones));
    assert_eq!(agent.hosted.channels(), vec![1, 2]);

    // Closing one leaves the other and the link.
    conn.send(json!({"t": "close", "ch": 1})).await;
    agent.until_logged("hub closed terminal 1, keeping the link").await;
    until("terminal 1 gone", || agent.hosted.channels() == vec![2]).await;
    conn.keys(2, b"\x03").await; // Ctrl+C stops the sleep, the shell goes on
    conn.send(json!({"t": "close", "ch": 2})).await;
    until("terminal 2 gone", || agent.hosted.channels().is_empty()).await;

    // Sixteen at most.
    for ch in 10..26 {
        conn.open(ch, "sleep 30").await;
    }
    conn.open(26, "sleep 30").await;
    loop {
        match conn.next().await {
            In::Json(v) if v["ch"] == 26 => {
                assert_eq!(v, json!({"t": "exit", "code": null, "error": "too many terminals open on this machine", "ch": 26}));
                break;
            }
            In::Gone => panic!("gone"),
            _ => {}
        }
    }
    assert_eq!(agent.hosted.live(), 16);
    agent.stop.send(true).unwrap();
    match conn.next().await {
        In::Json(v) => assert_eq!(v, json!({"t": "bye"})),
        other => panic!("{other:?}"),
    }
    // Then the Close, answered here: the agent leaves without waiting more.
    assert!(matches!(conn.next().await, In::Gone));
    let stopped = Instant::now();
    assert_eq!(agent.task.await.unwrap(), Outcome::Stopped);
    assert!(stopped.elapsed() < Duration::from_secs(2), "{:?}", stopped.elapsed());
    assert!(agent.hosted.channels().is_empty(), "its terminals end with it");
}

/// The way from the agent to the hub goes, as when Wi-Fi drops: the
/// terminal waits, the agent comes back by itself, and the terminal goes on
/// from the byte the hub has, nothing lost and nothing twice.
#[tokio::test(flavor = "multi_thread")]
async fn a_terminal_waits_for_the_link() {
    let hub = Hub::new().await;
    let agent = Agent::start(&hub.url(), timing());
    let (mut conn, _) = hub.welcomed().await;
    conn.open(11, "for i in $(seq 1 60); do echo L$i; sleep 0.03; done; sleep 30").await;
    let (mut got, mut msgs) = (Vec::new(), Vec::new());
    conn.output_until(11, "L5\r\n", &mut got, &mut msgs).await;
    drop(conn);
    agent.until_logged("keeping 1 terminal(s) for tTerm Web until the link is back").await;

    let mut conn = hub.accept().await;
    let hello = conn.json().await;
    assert_eq!(hello["kept"], json!([11]));
    conn.send(json!({"t": "welcome", "name": "test-mac"})).await;
    conn.send(json!({"t": "resume", "ch": 11, "from": got.len()})).await;
    conn.output_until(11, "L60\r\n", &mut got, &mut msgs).await;
    agent.until_logged("tTerm Web took terminal 11 back").await;
    let text = String::from_utf8_lossy(&got).to_string();
    let lines: Vec<&str> = text.split("\r\n").filter(|l| l.starts_with('L')).collect();
    let want: Vec<String> = (1..=60).map(|i| format!("L{i}")).collect();
    assert_eq!(lines, want, "whole, in order, nothing twice");
    assert!(msgs.is_empty(), "{msgs:?}");
}

/// Taken back from further back than the agent keeps: what is gone is said
/// as such, and the rest follows.
#[tokio::test(flavor = "multi_thread")]
async fn what_is_no_longer_kept_is_a_gap() {
    let hub = Hub::new().await;
    let agent = Agent::start(&hub.url(), timing());
    let (mut conn, _) = hub.welcomed().await;
    conn.open(12, "head -c 3000000 /dev/zero | tr '\\0' a; echo; echo END; sleep 30").await;
    let (mut got, mut msgs) = (Vec::new(), Vec::new());
    conn.output_until(12, "END", &mut got, &mut msgs).await;
    let total = got.len() as u64;
    drop(conn);
    agent.until_logged("keeping 1 terminal(s)").await;

    let (mut conn, hello) = hub.welcomed().await;
    assert_eq!(hello["kept"], json!([12]));
    conn.send(json!({"t": "resume", "ch": 12, "from": 0})).await;
    let first = conn.json().await;
    assert_eq!(first["t"], "gap");
    let lost = first["lost"].as_u64().unwrap();
    assert!(lost >= total - hosted::RING_MAX && lost < total, "lost {lost} of {total}");
    let mut again = Vec::new();
    conn.output_until(12, "END", &mut again, &mut msgs).await;
    assert_eq!(lost + again.len() as u64, total, "the rest, whole");
    assert_eq!(&again[..], &got[lost as usize..]);
}

/// After a reconnect the hub takes back the terminals it wants; the others
/// end by themselves. One whose link does not come back ends too.
#[tokio::test(flavor = "multi_thread")]
async fn terminals_not_taken_back_end() {
    let hub = Hub::new().await;
    let agent = Agent::start(&hub.url(), timing());
    let (mut conn, _) = hub.welcomed().await;
    conn.open(13, "echo up; sleep 30").await;
    let (mut got, mut msgs) = (Vec::new(), Vec::new());
    conn.output_until(13, "up", &mut got, &mut msgs).await;
    drop(conn);
    let (conn, hello) = hub.welcomed().await;
    assert_eq!(hello["kept"], json!([13]));
    agent.until_logged("terminal 13 was not taken back: ending it").await;
    assert!(agent.hosted.channels().is_empty());

    // A resume for one it no longer has: gone.
    let mut conn = conn;
    conn.send(json!({"t": "resume", "ch": 13, "from": 0})).await;
    assert_eq!(conn.json().await, json!({"t": "exit", "code": null, "gone": true, "ch": 13}));

    // No link for longer than it waits.
    conn.open(14, "echo up; sleep 30").await;
    let mut got = Vec::new();
    conn.output_until(14, "up", &mut got, &mut msgs).await;
    drop(conn);
    drop(hub); // nobody listens any more: the agent keeps trying
    agent.until_logged("terminal 14 waited").await;
    assert!(agent.hosted.channels().is_empty());
    assert!(agent.logged("no link ("), "{}", agent.log_text());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ended_terminal_is_said_again_after_a_reconnect() {
    let hub = Hub::new().await;
    let agent = Agent::start(&hub.url(), timing());
    let (mut conn, _) = hub.welcomed().await;
    conn.open(15, "echo bye; exit 4").await;
    let (out, exit) = conn.until_exit(15).await;
    assert!(String::from_utf8_lossy(&out).contains("bye"));
    assert_eq!(exit["code"], 4);
    // The link goes with the end on its way: kept, and said again.
    drop(conn);
    let (mut conn, hello) = hub.welcomed().await;
    assert_eq!(hello["kept"], json!([15]));
    conn.send(json!({"t": "resume", "ch": 15, "from": 0})).await;
    let (again, exit) = conn.until_exit(15).await;
    assert_eq!(again, out);
    assert_eq!(exit["code"], 4);
    // Then, its end said, it goes after a while.
    until("forgotten", || agent.hosted.channels().is_empty()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_hub_gets_everything() {
    let hub = Hub::new().await;
    let _agent = Agent::start(&hub.url(), timing());
    let (mut conn, _) = hub.welcomed().await;
    conn.open(16, "head -c 4000000 /dev/zero | tr '\\0' b; echo; echo END").await;
    let mut got = Vec::new();
    let mut frames = 0;
    loop {
        match conn.next().await {
            In::Out(16, data) => {
                got.extend_from_slice(&data);
                frames += 1;
                if frames % 8 == 0 {
                    // The hub reads slowly: the shell waits for it.
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            }
            In::Json(v) if v["t"] == "exit" => {
                assert_eq!(v["code"], 0);
                break;
            }
            In::Gone => panic!("gone"),
            _ => {}
        }
    }
    let bs = got.iter().filter(|&&c| c == b'b').count();
    assert_eq!(bs, 4_000_000);
    assert!(String::from_utf8_lossy(&got).ends_with("END\r\n"));
}

/// A flood of output on a link that keeps up only just: the signs of life
/// still come through, the hub answers them, and the link is not taken for
/// a dead one. (That they go ahead of the output queued in the agent is
/// checked in link.rs itself.)
#[tokio::test(flavor = "multi_thread")]
async fn signs_of_life_come_through_a_flood() {
    let hub = Hub::new().await;
    let mut t = timing();
    t.silence_limit = Duration::from_secs(2);
    let agent = Agent::start(&hub.url(), t);
    let (mut conn, _) = hub.welcomed().await;
    conn.hb_back = false;
    conn.open(17, "cat /dev/zero | tr '\\0' f").await;
    let started = Instant::now();
    let (mut signs, mut frames, mut bytes, mut owed) = (0, 0, 0, 0);
    while started.elapsed() < Duration::from_secs(4) {
        match tokio::time::timeout(WAIT, conn.ws.next()).await.unwrap() {
            Some(Ok(Message::Text(text))) if text.as_str() == r#"{"t":"hb"}"# => {
                signs += 1;
                conn.send(json!({"t": "hb"})).await;
            }
            Some(Ok(Message::Binary(data))) => {
                // The hub takes about 4 MB a second, by the bytes and not
                // by the frames, which are small on a Mac: far slower than
                // the shell prints, and a Mac's buffers on the way, which
                // grow by themselves, still go through in about a second.
                frames += 1;
                bytes += data.len();
                owed += data.len();
                if owed >= 20_000 {
                    owed -= 20_000;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
            Some(Ok(_)) => {}
            other => panic!("the link went: {other:?}; {}", agent.log_text()),
        }
    }
    assert!(signs >= 5, "{signs} signs of life in 4 s; {frames} frames, {bytes} bytes of output taken");
    assert!(!agent.logged("hub silent"), "{}", agent.log_text());
    conn.send(json!({"t": "close", "ch": 17})).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn scripts() {
    let hub = Hub::new().await;
    let _agent = Agent::start(&hub.url(), timing());
    let (mut conn, _) = hub.welcomed().await;
    let b64 = base64::engine::general_purpose::STANDARD;
    // What the script was given, not what its shell makes up: bash, the
    // sh of a Mac, sets TERM=dumb for itself when there is none.
    conn.send(json!({"t": "run", "id": 7, "script": "echo out; echo err >&2; echo \"$(printenv TERM)|$(printenv TTERM_AGENT_DIR)|$HOME\"; exit 4"})).await;
    let ran = conn.json().await;
    assert_eq!(ran["t"], "ran");
    assert_eq!(ran["id"], 7);
    assert_eq!(ran["code"], 4);
    let out = String::from_utf8(b64.decode(ran["out"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(out, format!("out\n||{}\n", std::env::var("HOME").unwrap()), "no TERM, no TTERM_AGENT_DIR for scripts");
    assert_eq!(b64.decode(ran["err"].as_str().unwrap()).unwrap(), b"err\n");

    // A session of its own (s: its leader), as agent.py's: no terminal of
    // the agent's to ask a password on.
    conn.send(json!({"t": "run", "id": "session", "script": "ps -o stat= -p $$"})).await;
    let ran = conn.json().await;
    let stat = String::from_utf8(b64.decode(ran["out"].as_str().unwrap()).unwrap()).unwrap();
    assert!(stat.trim().contains('s'), "a session leader: {stat:?}");

    // Nothing of the agent's is open in it: 0, 1, 2, and ls's own look.
    conn.send(json!({"t": "run", "id": "fds", "script": "ls /dev/fd/"})).await;
    let ran = conn.json().await;
    let fds = String::from_utf8(b64.decode(ran["out"].as_str().unwrap()).unwrap()).unwrap();
    assert!(fds.split_whitespace().count() <= 4, "open in a script: {fds:?}");

    conn.send(json!({"t": "run", "id": "slow", "script": "sleep 5", "timeout": 0.3})).await;
    let ran = conn.json().await;
    assert_eq!(ran["id"], "slow");
    assert_eq!(ran["code"], Value::Null);
    assert_eq!(b64.decode(ran["err"].as_str().unwrap()).unwrap(), b"the script did not finish in time");

    conn.send(json!({"t": "run", "id": "big", "script": "head -c 3000000 /dev/zero; head -c 10000 /dev/zero >&2"})).await;
    let ran = conn.json().await;
    assert_eq!(b64.decode(ran["out"].as_str().unwrap()).unwrap().len(), hosted::SIDE_OUT_MAX);
    assert_eq!(b64.decode(ran["err"].as_str().unwrap()).unwrap().len(), hosted::SIDE_ERR_MAX);

    // Four at once: eight of half a second take two rounds.
    let started = Instant::now();
    for i in 0..8 {
        conn.send(json!({"t": "run", "id": i, "script": "sleep 0.5"})).await;
    }
    for _ in 0..8 {
        assert_eq!(conn.json().await["code"], 0);
    }
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(950) && took < Duration::from_millis(2600), "{took:?}");

    conn.send(json!({"t": "ping"})).await;
    assert_eq!(conn.json().await, json!({"t": "pong"}));
}

#[tokio::test(flavor = "multi_thread")]
async fn removed_and_refused() {
    // Refused at the hello: removed, and the key is to be forgotten.
    let hub = Hub::new().await;
    let agent = Agent::start(&hub.url(), timing());
    let mut conn = hub.accept().await;
    conn.json().await;
    conn.send(json!({"t": "error", "error": "This computer was removed from tTerm Web.", "revoked": true, "forget": true})).await;
    assert_eq!(
        agent.task.await.unwrap(),
        Outcome::Revoked { error: "This computer was removed from tTerm Web.".into(), forget: true }
    );

    // Removed while connected; its terminals hear nothing more.
    let hub = Hub::new().await;
    let agent = Agent::start(&hub.url(), timing());
    let (mut conn, _) = hub.welcomed().await;
    conn.open(3, "sleep 30").await;
    until("open", || agent.hosted.live() == 1).await;
    conn.send(json!({"t": "error", "error": "removed", "revoked": true})).await;
    assert_eq!(agent.task.await.unwrap(), Outcome::Revoked { error: "removed".into(), forget: false });

    // Any other refusal is tried again, after the usual pause.
    let hub = Hub::new().await;
    let agent = Agent::start(&hub.url(), timing());
    let mut conn = hub.accept().await;
    conn.json().await;
    conn.send(json!({"t": "error", "error": "Too many failed attempts from this address."})).await;
    let (_conn, _) = hub.welcomed().await;
    assert!(agent.logged("no link (Too many failed attempts from this address.), retrying in 0s"), "{}", agent.log_text());
}

/// The pauses between tries: doubling up to the most, from the start again
/// after a connection that worked a while.
#[tokio::test(flavor = "multi_thread")]
async fn pauses_between_tries() {
    let hub = Hub::new().await;
    let agent = Agent::start(&hub.url(), timing());
    let mut times = Vec::new();
    for _ in 0..6 {
        // Taken and dropped at once: not a WebSocket.
        let (tcp, _) = tokio::time::timeout(WAIT, hub.listener.accept()).await.unwrap().unwrap();
        times.push(Instant::now());
        drop(tcp);
    }
    let gaps: Vec<u128> = times.windows(2).map(|w| (w[1] - w[0]).as_millis()).collect();
    for (gap, want) in gaps.iter().zip([50u128, 100, 200, 400, 400]) {
        assert!(*gap >= want && *gap < want + 300, "pauses {gaps:?}");
    }
    // A connection that held longer than healthy_for: the pause starts over.
    let (conn, _) = hub.welcomed().await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    drop(conn);
    let went = Instant::now();
    let (tcp, _) = tokio::time::timeout(WAIT, hub.listener.accept()).await.unwrap().unwrap();
    let pause = went.elapsed();
    assert!(pause < Duration::from_millis(300), "{pause:?}; {}", agent.log_text());
    drop(tcp);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_network_is_tried_often_and_said_once() {
    let agent = Agent::start("ws://no-such-host.invalid/agent", timing());
    agent.until_logged("no network (cannot look up no-such-host.invalid").await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let lines = agent.lines.lock().unwrap().clone();
    assert_eq!(lines.len(), 1, "{lines:?}");
    agent.stop.send(true).unwrap();
    assert_eq!(agent.task.await.unwrap(), Outcome::Stopped);
}

/// A hub that stops answering: after the silence the agent drops the
/// connection and comes back.
#[tokio::test(flavor = "multi_thread")]
async fn silence_drops_the_connection() {
    let hub = Hub::new().await;
    let mut t = timing();
    t.silence_limit = Duration::from_millis(700);
    let agent = Agent::start(&hub.url(), t);
    let (mut conn, _) = hub.welcomed().await;
    conn.hb_back = false;
    // Signs of life come, every heartbeat.
    let mut signs = 0;
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(500) {
        if let Ok(Some(Ok(Message::Text(t)))) = tokio::time::timeout(Duration::from_millis(100), conn.ws.next()).await {
            if t.as_str() == r#"{"t":"hb"}"# {
                signs += 1;
            }
        }
    }
    assert!(signs >= 2, "{signs}");
    let (_again, _) = hub.welcomed().await;
    assert!(agent.logged("hub silent for 1s — reconnecting") || agent.logged("hub silent for 0s"), "{}", agent.log_text());
    assert!(agent.logged("connection closed, reconnecting"));
}

/// The WebSocket's own pings, as websockets sent them for agent.py: while
/// the hub's WebSocket answers them the link stays; once it does not, the
/// connection is left after a ping and its timeout, long before the silence
/// would tell.
#[tokio::test(flavor = "multi_thread")]
async fn unanswered_pings_drop_the_connection() {
    let hub = Hub::new().await;
    let mut t = timing();
    t.ping_every = Duration::from_millis(200);
    t.ping_timeout = Duration::from_millis(500);
    t.silence_limit = Duration::from_secs(30);
    let agent = Agent::start(&hub.url(), t);
    let (mut conn, _) = hub.welcomed().await;
    // Read, and so answer: tungstenite answers a ping while reading.
    let mut pings = 0;
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(1500) {
        if let Ok(Some(Ok(Message::Ping(_)))) = tokio::time::timeout(Duration::from_millis(100), conn.ws.next()).await {
            pings += 1;
        }
    }
    assert!(pings >= 4, "{pings} pings in 1.5 s");
    assert!(!agent.logged("keepalive"), "{}", agent.log_text());
    // No longer read: no pongs.
    let quiet = Instant::now();
    let (_again, _) = hub.welcomed().await;
    assert!(quiet.elapsed() < Duration::from_secs(3), "left after {:?}", quiet.elapsed());
    agent.until_logged("no link (keepalive ping timeout), retrying in").await;
    drop(conn);
}

/// A company's proxy: CONNECT, kept as it was asked; the way through
/// opened when `answer` says 200.
struct Proxy {
    port: u16,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Proxy {
    async fn start(answer: &'static str) -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let kept = asked.clone();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let kept = kept.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut byte = [0u8; 1];
                    while !request.ends_with(b"\r\n\r\n") {
                        if client.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        request.push(byte[0]);
                    }
                    let text = String::from_utf8_lossy(&request).to_string();
                    kept.lock().unwrap().push(text.clone());
                    if !answer.starts_with("HTTP/1.1 200") {
                        let _ = client.write_all(answer.as_bytes()).await;
                        return;
                    }
                    let target = text.split_whitespace().nth(1).unwrap().to_string();
                    let Ok(mut server) = TcpStream::connect(&target).await else { return };
                    client.write_all(answer.as_bytes()).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                });
            }
        });
        Proxy { port, asked }
    }
}

/// Through the proxy of the environment, as agent.py's websockets went: the
/// hub asked for with CONNECT and the login from the proxy's address, then
/// everything through it; straight to the hub when no_proxy names it; a
/// proxy that wants a login said so in the log.
#[tokio::test(flavor = "multi_thread")]
async fn through_a_proxy() {
    let hub = Hub::new().await;
    let proxy = Proxy::start("HTTP/1.1 200 Connection established\r\n\r\n").await;
    let env = vec![("https_proxy".to_string(), format!("http://me:s%40fe@127.0.0.1:{}", proxy.port))];
    let agent = Agent::start_env(&hub.url(), timing(), env);
    let (mut conn, _) = hub.welcomed().await;
    conn.open(31, "echo through-$((6*7))").await;
    let (out, exit) = conn.until_exit(31).await;
    assert!(String::from_utf8_lossy(&out).contains("through-42"), "{}", String::from_utf8_lossy(&out));
    assert_eq!(exit["code"], 0);
    let asked = proxy.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "{asked:?}");
    let login = base64::engine::general_purpose::STANDARD.encode("me:s@fe");
    assert_eq!(
        asked[0],
        format!(
            "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: tterm-agent/0.14.0\r\nProxy-Authorization: Basic {login}\r\n\r\n",
            port = hub.port
        )
    );
    drop(conn);
    drop(agent);

    // no_proxy names the hub: straight to it.
    let direct_hub = Hub::new().await;
    let env = vec![
        ("https_proxy".to_string(), format!("http://127.0.0.1:{}", proxy.port)),
        ("no_proxy".to_string(), "localhost,127.0.0.1".to_string()),
    ];
    let _direct = Agent::start_env(&direct_hub.url(), timing(), env);
    let _welcomed = direct_hub.welcomed().await;
    assert_eq!(proxy.asked.lock().unwrap().len(), 1, "the proxy was not asked again");

    // A proxy that wants a login.
    let strict = Proxy::start("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n").await;
    let env = vec![("HTTPS_PROXY".to_string(), format!("http://127.0.0.1:{}", strict.port))];
    let refused = Agent::start_env(&direct_hub.url(), timing(), env);
    refused.until_logged(&format!("no link (the proxy 127.0.0.1:{} asks for a login (HTTP 407)), retrying in", strict.port)).await;
}

/// A late welcome, the hub's WebSocket pinging before it (its keepalive):
/// the WebSocket answers, and the agent waits on for the welcome, as
/// agent.py did.
#[tokio::test(flavor = "multi_thread")]
async fn a_ping_before_the_welcome() {
    let hub = Hub::new().await;
    let agent = Agent::start(&hub.url(), timing());
    let mut conn = hub.accept().await;
    assert_eq!(conn.json().await["t"], "hello");
    conn.ws.send(Message::Ping(b"keepalive".to_vec().into())).await.unwrap();
    loop {
        match tokio::time::timeout(WAIT, conn.ws.next()).await.expect("an answer") {
            Some(Ok(Message::Pong(payload))) => {
                assert_eq!(&payload[..], b"keepalive");
                break;
            }
            Some(Ok(_)) => continue,
            other => panic!("no pong: {other:?}; {}", agent.log_text()),
        }
    }
    conn.send(json!({"t": "welcome", "name": "test-mac"})).await;
    agent.until_logged("connected as «test-mac»").await;
    assert!(!agent.logged("no link"), "{}", agent.log_text());
    conn.open(32, "echo after-the-ping").await;
    let (out, _) = conn.until_exit(32).await;
    assert!(String::from_utf8_lossy(&out).contains("after-the-ping"));
}

/// Stopped while a terminal floods a slow link and the hub goes on talking:
/// the goodbye still reaches the hub, the Close after it, as in agent.py's
/// closing handshake. Left unread, what the hub said meanwhile would make the
/// system reset the connection and throw away the goodbye still on its way.
#[tokio::test(flavor = "multi_thread")]
async fn the_goodbye_gets_through_a_busy_link() {
    let hub = Hub::new().await;
    let mut t = timing();
    t.close_timeout = Duration::from_secs(10);
    let agent = Agent::start(&hub.url(), t);
    let (mut conn, _) = hub.welcomed().await;
    conn.open(40, "yes flood").await;
    let started = Instant::now();
    let (mut stopped, mut bye, mut after_bye) = (false, false, 0);
    loop {
        assert!(started.elapsed() < WAIT, "no Close; bye: {bye}; {}", agent.log_text());
        // A second of the flood fills what lies on the way, then the stop.
        if !stopped && started.elapsed() > Duration::from_secs(1) {
            agent.stop.send(true).unwrap();
            stopped = true;
        }
        // The hub talks, and reads slowly: about 300 KB a second.
        let _ = conn.ws.send(Message::Text(json!({"t": "size", "ch": 40, "cols": 100, "rows": 30}).to_string().into())).await;
        match tokio::time::timeout(Duration::from_millis(100), conn.ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) if text.as_str() == r#"{"t":"bye"}"# => {
                assert!(stopped);
                bye = true;
            }
            Ok(Some(Ok(Message::Binary(data)))) => {
                if bye {
                    after_bye += 1;
                }
                tokio::time::sleep(Duration::from_secs_f64(data.len() as f64 / 300_000.0)).await;
            }
            Ok(Some(Ok(Message::Close(_)))) => {
                let _ = SinkExt::close(&mut conn.ws).await;
                break;
            }
            Ok(None) => break,
            Ok(Some(Err(e))) => panic!("the connection was not closed but broken ({e}); bye: {bye}; {}", agent.log_text()),
            _ => {}
        }
    }
    assert!(bye, "{}", agent.log_text());
    assert_eq!(after_bye, 0, "output still went after the goodbye");
    let closed = Instant::now();
    assert_eq!(agent.task.await.unwrap(), Outcome::Stopped);
    assert!(closed.elapsed() < Duration::from_secs(2), "{:?}", closed.elapsed());
}

/// Odd values from the hub do no harm.
#[tokio::test(flavor = "multi_thread")]
async fn odd_messages() {
    let hub = Hub::new().await;
    let agent = Agent::start(&hub.url(), timing());
    let (mut conn, _) = hub.welcomed().await;
    for bad in [
        json!("text"),
        json!([1, 2]),
        json!({"t": "open", "ch": "1", "cmd": "echo no"}),
        json!({"t": "open", "ch": 1.5, "cmd": "echo no"}),
        json!({"t": "open", "ch": 0, "cmd": "echo no"}),
        json!({"t": "open", "ch": 4294967296u64, "cmd": "echo no"}),
        json!({"t": "size", "ch": 99, "cols": "x"}),
        json!({"t": "close", "ch": 99}),
        json!({"t": "in", "data": "ls\n"}),
        json!({"t": "whatever"}),
    ] {
        conn.send(bad).await;
    }
    conn.ws.send(Message::Text("{not json".into())).await.unwrap();
    conn.ws.send(Message::Binary(vec![2, 0, 0, 0, 9].into())).await.unwrap();
    conn.ws.send(Message::Binary(vec![9, 0, 0, 0, 1, 65].into())).await.unwrap();
    // Sizes out of reach are brought into it.
    conn.send(json!({"t": "open", "ch": 2, "cmd": "stty size", "cols": 100000, "rows": -5})).await;
    let (out, _) = conn.until_exit(2).await;
    assert!(String::from_utf8_lossy(&out).contains("1 1000"), "{:?}", String::from_utf8_lossy(&out));
    conn.send(json!({"t": "open", "ch": 3, "cmd": "stty size", "cols": "90", "rows": 33.9})).await;
    let (out, _) = conn.until_exit(3).await;
    assert!(String::from_utf8_lossy(&out).contains("33 90"), "{:?}", String::from_utf8_lossy(&out));
    assert_eq!(agent.hosted.channels(), vec![2, 3], "only the good ones opened");
}

#[test]
fn values_as_python_read_them() {
    use hosted::{number, offset, script_timeout, truthy, whole};
    let v = |x: Value| Some(x);
    assert_eq!(whole(v(json!(5)).as_ref()), Some(5));
    assert_eq!(whole(v(json!(5.9)).as_ref()), Some(5));
    assert_eq!(whole(v(json!(-5.9)).as_ref()), Some(-5));
    assert_eq!(whole(v(json!(" 42 ")).as_ref()), Some(42));
    assert_eq!(whole(v(json!("+7")).as_ref()), Some(7));
    assert_eq!(whole(v(json!("4.5")).as_ref()), None);
    assert_eq!(whole(v(json!(true)).as_ref()), Some(1));
    assert_eq!(whole(v(json!(null)).as_ref()), None);
    assert_eq!(whole(None), None);
    assert_eq!(number(v(json!("x")).as_ref(), 80, 1000), 80);
    assert_eq!(number(v(json!(0)).as_ref(), 80, 1000), 1);
    assert_eq!(number(v(json!(5000)).as_ref(), 80, 1000), 1000);
    assert_eq!(number(v(json!(1e300)).as_ref(), 80, 1000), 1000);
    assert_eq!(offset(v(json!(-3)).as_ref()), 0);
    assert_eq!(offset(v(json!("12")).as_ref()), 12);
    assert_eq!(offset(None), 0);
    assert!(truthy(None, true) && !truthy(None, false));
    assert!(!truthy(v(json!(false)).as_ref(), true));
    assert!(!truthy(v(json!(0)).as_ref(), true));
    assert!(!truthy(v(json!("")).as_ref(), true));
    assert!(!truthy(v(json!(null)).as_ref(), true));
    assert!(truthy(v(json!("no")).as_ref(), false));
    assert_eq!(script_timeout(None), hosted::SIDE_TIMEOUT);
    assert_eq!(script_timeout(v(json!(-1)).as_ref()), hosted::SIDE_TIMEOUT);
    assert_eq!(script_timeout(v(json!("nan")).as_ref()), hosted::SIDE_TIMEOUT);
    assert_eq!(script_timeout(v(json!(1000)).as_ref()), hosted::SIDE_TIMEOUT_MAX);
    assert_eq!(script_timeout(v(json!(2.5)).as_ref()), Duration::from_millis(2500));
}
