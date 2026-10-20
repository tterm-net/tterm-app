//! Real shells in real pseudo-terminals, driven the way the page drives
//! them: requests through api::handle, keys and output through the socket.

use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tterm_engine::socket::PageSocket;
use tterm_engine::terminals::{Outgoing, Plan};
use tterm_engine::{api, Engine};

/// Tests that flood a shell or count CPU time take turns: CPU time is the
/// whole test process's.
static HEAVY: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn heavy() -> std::sync::MutexGuard<'static, ()> {
    HEAVY.lock().unwrap_or_else(|e| e.into_inner())
}

fn data_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("tterm-engine-test-{}", uuid::Uuid::new_v4()))
}

async fn engine() -> Arc<Engine> {
    let e = Engine::new(&data_dir()).expect("engine");
    e.start_background();
    e
}

async fn request(e: &Arc<Engine>, method: &str, path: &str, body: Value) -> (u16, Value) {
    let raw = if body.is_null() { Vec::new() } else { body.to_string().into_bytes() };
    let r = api::handle(e, method, path, &raw).await;
    let value = if r.body.is_empty() { Value::Null } else { serde_json::from_slice(&r.body).unwrap_or(Value::Null) };
    (r.status, value)
}

/// What one page sees of one channel: the output, as bytes, and the JSON
/// messages, in order.
struct Page {
    sock: Arc<PageSocket>,
    rx: mpsc::Receiver<Outgoing>,
    out: Vec<u8>,
    msgs: Vec<Value>,
    last_seq: u64,
}

impl Page {
    fn new(e: &Arc<Engine>) -> Page {
        let (sock, rx) = PageSocket::new(e.clone());
        Page { sock, rx, out: Vec::new(), msgs: Vec::new(), last_seq: 0 }
    }

    async fn send(&self, msg: Value) {
        self.sock.text(&msg.to_string()).await;
    }

    async fn keys(&self, ch: u32, data: &str) {
        let mut frame = vec![2u8];
        frame.extend_from_slice(&ch.to_be_bytes());
        frame.extend_from_slice(data.as_bytes());
        self.sock.binary(&frame).await;
    }

    fn take(&mut self, m: Outgoing) {
        match m {
            Outgoing::Binary(f) => {
                assert_eq!(f[0], 1);
                self.last_seq = u64::from_be_bytes(f[5..13].try_into().unwrap());
                self.out.extend_from_slice(&f[13..]);
            }
            Outgoing::Text(t) => {
                let v: Value = serde_json::from_str(&t).unwrap();
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
    async fn until(&mut self, secs: u64, done: impl Fn(&Page) -> bool) -> bool {
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

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.out).to_string()
    }

    fn state(&self) -> Option<Value> {
        self.msgs.iter().rev().find(|m| m["op"] == "state" || m["op"] == "attached").map(|m| m["terminal"].clone())
    }
}

async fn open(e: &Arc<Engine>, cols: i64, rows: i64) -> String {
    let machine = e.settings.lock().unwrap().machine_id.to_string();
    let (status, t) = request(e, "POST", "/api/terminals", json!({"machineId": machine, "cols": cols, "rows": rows})).await;
    assert_eq!(status, 201, "{t}");
    assert_eq!(t["state"], "connecting");
    t["id"].as_str().unwrap().to_string()
}

async fn attached(e: &Arc<Engine>, id: &str, cols: i64, rows: i64) -> Page {
    let mut page = Page::new(e);
    page.send(json!({"op": "attach", "ch": 1, "id": id, "after": null, "cols": cols, "rows": rows, "focus": true})).await;
    assert!(page.until(10, |p| p.msgs.iter().any(|m| m["op"] == "replayed")).await, "{:?}", page.msgs);
    assert!(page.until(10, |p| p.state().map(|s| s["state"] == "open").unwrap_or(false)).await, "{:?}", page.msgs);
    page
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shell_runs_commands_and_ends() {
    let e = engine().await;
    let id = open(&e, 100, 30).await;
    let mut page = attached(&e, &id, 100, 30).await;
    let first = &page.msgs[0];
    assert_eq!(first["op"], "attached");
    assert_eq!(first["resumed"], false);
    assert_eq!(first["terminal"]["machine"], e.machine_name.as_str());

    page.keys(1, "echo hello-$((40+2)); stty size\r").await;
    assert!(page.until(10, |p| p.text().contains("hello-42")).await, "{}", page.text());
    assert!(page.until(10, |p| p.text().contains("30 100")).await, "{}", page.text());

    // Cyrillic, cut anywhere between reads, arrives whole.
    page.keys(1, "printf '%s\\n' привет\r").await;
    assert!(page.until(10, |p| p.text().contains("привет")).await, "{}", page.text());

    // A new size reaches the shell.
    page.send(json!({"op": "resize", "ch": 1, "cols": 120, "rows": 40})).await;
    page.keys(1, "stty size\r").await;
    assert!(page.until(10, |p| p.text().contains("40 120")).await, "{}", page.text());

    page.keys(1, "exit 3\r").await;
    assert!(page.until(15, |p| p.state().map(|s| s["state"] == "ended").unwrap_or(false)).await, "{:?}", page.msgs);
    let s = page.state().unwrap();
    assert_eq!(s["reason"], "The shell ended with code 3.");

    // Ended, it is no longer in the state's list, but still describes itself.
    let (_, state) = request(&e, "GET", "/api/state", Value::Null).await;
    assert!(state["terminals"].as_array().unwrap().iter().all(|t| t["id"] != id.as_str()));
    let (status, t) = request(&e, "GET", &format!("/api/terminals/{id}"), Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(t["state"], "ended");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_coming_back_gets_what_it_missed_or_a_replay() {
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let mut page = attached(&e, &id, 80, 24).await;
    page.keys(1, "echo one-$((1+1))\r").await;
    assert!(page.until(10, |p| p.text().contains("one-2")).await);
    let had = page.last_seq;
    page.sock.close().await;

    // Typed while no page looks (the shell goes on).
    let t = e.terminals.get(&uuid::Uuid::parse_str(&id).unwrap()).unwrap();
    t.write(b"echo two-$((1+2))\r");
    tokio::time::sleep(Duration::from_millis(800)).await;

    // From the number it had: only what came since, no reset.
    let mut back = Page::new(&e);
    back.send(json!({"op": "attach", "ch": 5, "id": id, "after": had, "cols": 80, "rows": 24})).await;
    assert!(back.until(10, |p| p.msgs.iter().any(|m| m["op"] == "replayed")).await);
    assert_eq!(back.msgs[0]["resumed"], true);
    assert!(!back.msgs.iter().any(|m| m["op"] == "reset"));
    assert!(back.text().contains("two-3"));
    assert!(!back.text().contains("one-2"), "{}", back.text());

    // Empty, after a reload: a reset and everything kept.
    let mut fresh = Page::new(&e);
    fresh.send(json!({"op": "attach", "ch": 9, "id": id, "after": null, "cols": 80, "rows": 24})).await;
    assert!(fresh.until(10, |p| p.msgs.iter().any(|m| m["op"] == "replayed")).await);
    assert_eq!(fresh.msgs[0]["resumed"], false);
    assert_eq!(fresh.msgs[1]["op"], "reset");
    assert!(fresh.text().contains("one-2") && fresh.text().contains("two-3"), "{}", fresh.text());

    // A terminal it does not know: gone.
    let mut lost = Page::new(&e);
    lost.send(json!({"op": "attach", "ch": 2, "id": uuid::Uuid::new_v4().to_string()})).await;
    assert!(lost.until(5, |p| p.msgs.iter().any(|m| m["op"] == "gone")).await);

    let (status, _) = request(&e, "DELETE", &format!("/api/terminals/{id}"), Value::Null).await;
    assert_eq!(status, 200);
    assert!(fresh.until(10, |p| p.state().map(|s| s["state"] == "ended" && s["reason"] == "Closed.").unwrap_or(false)).await, "{:?}", fresh.msgs.last());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ctrl_c_stops_a_flood_and_the_shell_goes_on() {
    let _turn = heavy();
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let mut page = attached(&e, &id, 80, 24).await;
    page.keys(1, "yes flood\r").await;
    assert!(page.until(20, |p| p.out.len() > 6_000_000).await, "{}", page.out.len());
    page.keys(1, "\x03").await;
    page.keys(1, "echo after-$((6*7))\r").await;
    let started = Instant::now();
    assert!(page.until(20, |p| p.text().contains("after-42")).await);
    assert!(started.elapsed() < Duration::from_secs(15));
    let t = e.terminals.get(&uuid::Uuid::parse_str(&id).unwrap()).unwrap();
    let (first, last) = t.range();
    assert!(first > 1, "old output was let go: {first}..{last}");
    t.close("Closed.").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_screen_program_is_drawn_again_on_a_new_page() {
    if !std::path::Path::new("/usr/bin/vim").exists() {
        return;
    }
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let mut page = attached(&e, &id, 80, 24).await;
    page.keys(1, "vim -u NONE -N\r").await;
    let t = e.terminals.get(&uuid::Uuid::parse_str(&id).unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !t.lock().modes.alt_screen() && Instant::now() < deadline {
        page.until(1, |_| false).await;
    }
    assert!(t.lock().modes.alt_screen());
    let mut fresh = Page::new(&e);
    fresh.send(json!({"op": "attach", "ch": 3, "id": id, "after": null, "cols": 80, "rows": 24})).await;
    assert!(fresh.until(10, |p| p.msgs.iter().any(|m| m["op"] == "replayed")).await);
    assert!(fresh.text().contains("\x1b[?1049h"), "the second screen is set again");
    page.keys(1, "\x1b:q!\r").await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while t.lock().modes.alt_screen() && Instant::now() < deadline {
        page.until(1, |_| false).await;
    }
    assert!(!t.lock().modes.alt_screen());
    t.close("Closed.").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zsh_as_the_login_shell() {
    let Some(zsh) = ["/bin/zsh", "/usr/bin/zsh"].into_iter().find(|p| std::path::Path::new(p).exists()) else {
        return;
    };
    let e = engine().await;
    let mut env = tterm_engine::pty::clean_env(true);
    env.retain(|(k, _)| k != "SHELL");
    env.push(("SHELL".into(), zsh.into()));
    let plan = Plan {
        shell: "zsh".into(),
        argv: vec![zsh.into(), "-c".into(), "exec \"${SHELL:-/bin/sh}\" -l".into()],
        markers: false,
        blocks: false,
    };
    let t = e.terminals.open(e.place(), plan, env, tterm_engine::pty::home_dir(), 80, 24, 24).await.unwrap();
    let id = t.id.to_string();
    let mut page = attached(&e, &id, 80, 24).await;
    page.keys(1, "echo $ZSH_NAME-$((2*21))\r").await;
    assert!(page.until(10, |p| p.text().contains("zsh-42")).await, "{}", page.text());
    t.close("Closed.").await;
    assert_eq!(t.describe()["reason"], "Closed.");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_background_job_does_not_hold_the_end() {
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let mut page = attached(&e, &id, 80, 24).await;
    page.keys(1, "sleep 60 & exit\r").await;
    let started = Instant::now();
    assert!(page.until(15, |p| p.state().map(|s| s["state"] == "ended").unwrap_or(false)).await, "{:?}", page.msgs.last());
    assert!(started.elapsed() < Duration::from_secs(12), "{:?}", started.elapsed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_typed_before_the_shell_is_up_wait_for_it() {
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let t = e.terminals.get(&uuid::Uuid::parse_str(&id).unwrap()).unwrap();
    t.write(b"echo early-$((3*3))\r");
    let mut page = attached(&e, &id, 80, 24).await;
    assert!(page.until(10, |p| p.text().contains("early-9")).await, "{}", page.text());
    t.close("Closed.").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_active_page_types() {
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let mut a = attached(&e, &id, 80, 24).await;
    let mut b = Page::new(&e);
    b.send(json!({"op": "attach", "ch": 1, "id": id, "after": null})).await;
    assert!(b.until(10, |p| p.msgs.iter().any(|m| m["op"] == "replayed")).await);
    // b never focused: its keys go nowhere.
    b.keys(1, "echo from-b\r").await;
    a.keys(1, "echo from-$((10+1))\r").await;
    assert!(a.until(10, |p| p.text().contains("from-11")).await);
    tokio::time::sleep(Duration::from_millis(500)).await;
    a.until(1, |_| false).await;
    assert!(!a.text().contains("from-b"), "{}", a.text());
    // Focused, b types.
    b.send(json!({"op": "focus", "ch": 1})).await;
    b.keys(1, "echo now-$((20+2))\r").await;
    assert!(a.until(10, |p| p.text().contains("now-22")).await, "{}", a.text());
    let t = e.terminals.get(&uuid::Uuid::parse_str(&id).unwrap()).unwrap();
    t.close("Closed.").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_api_answers_like_the_core() {
    let e = engine().await;
    let (status, auth) = request(&e, "GET", "/api/auth/state", Value::Null).await;
    assert_eq!((status, auth["signedIn"].clone()), (200, json!(true)));
    let (status, state) = request(&e, "GET", "/api/state", Value::Null).await;
    assert_eq!(status, 200);
    let project = &state["projects"][0];
    assert_eq!(project["name"], "Personal");
    assert_eq!(project["code"], "P");
    assert_eq!(project["personal"], true);
    assert_eq!(project["machines"][0]["kind"], "computer");
    assert_eq!(project["machines"][0]["online"], true);
    assert_eq!(state["me"]["plan"], "free");

    let (status, _) = request(&e, "PATCH", "/api/me", json!({"theme": "light"})).await;
    assert_eq!(status, 204);
    let (status, named) = request(&e, "PATCH", "/api/me", json!({"name": "  Denis \u{202e}Gerasimenko "})).await;
    assert_eq!(status, 200);
    assert_eq!(named["name"], "Denis Gerasimenko");
    assert_eq!(named["initials"], "DG");
    let (status, _) = request(&e, "PATCH", "/api/me", json!({"theme": "neon"})).await;
    assert_eq!(status, 422);

    let pid = project["id"].as_str().unwrap();
    let (status, edited) = request(&e, "PATCH", &format!("/api/projects/{pid}"), json!({"name": "Home", "code": "h", "color": "teal"})).await;
    assert_eq!(status, 200, "{edited}");
    assert_eq!(edited["code"], "H");
    let (_, state) = request(&e, "GET", "/api/state", Value::Null).await;
    assert_eq!(state["projects"][0]["name"], "Home");
    assert_eq!(state["me"]["theme"], "light");

    // Remembered on the computer.
    let again = Engine::new(&e.data_dir).unwrap();
    assert_eq!(again.state_json()["projects"][0]["color"], "teal");

    let (status, refused) = request(&e, "POST", "/api/folders", json!({"projectId": pid, "name": "x"})).await;
    assert_eq!(status, 403);
    assert!(refused["error"].as_str().unwrap().contains("later version"));
    let (status, _) = request(&e, "POST", "/api/installs", json!({"projectId": pid, "kind": "server"})).await;
    assert_eq!(status, 403);
    let (status, _) = request(&e, "POST", "/api/terminals", json!({"machineId": uuid::Uuid::new_v4().to_string(), "cols": 80, "rows": 24})).await;
    assert_eq!(status, 404);
    let mid = project["machines"][0]["id"].as_str().unwrap();
    let (status, details) = request(&e, "GET", &format!("/api/machines/{mid}"), Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(details["label"], format!("H/{}", e.machine_name));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_is_running_is_named_before_quitting() {
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let mut page = attached(&e, &id, 80, 24).await;
    assert!(e.terminals.busy().is_empty(), "the shell alone is not busy");
    page.keys(1, "sleep 30\r").await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while e.terminals.busy().is_empty() && Instant::now() < deadline {
        page.until(1, |_| false).await;
    }
    let busy = e.terminals.busy();
    assert_eq!(busy.len(), 1, "{busy:?}");
    assert_eq!(busy[0].1, "sleep");
    assert_eq!(busy[0].0, format!("P/{}", e.machine_name));
    e.terminals.stop_all("tTerm quit.").await;
    assert!(e.terminals.live().is_empty());
}

/// CPU time of this process, user and system, in seconds.
fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let t = |tv: libc::timeval| tv.tv_sec as f64 + tv.tv_usec as f64 / 1e6;
    t(usage.ru_utime) + t(usage.ru_stime)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_terminal_costs_nothing() {
    // A reader that spins (poll on a device, on macOS) would burn a core.
    let _turn = heavy();
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let mut page = attached(&e, &id, 80, 24).await;
    page.keys(1, "echo idle-$((5*5))\r").await;
    assert!(page.until(10, |p| p.text().contains("idle-25")).await);
    let before = cpu_seconds();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let spent = cpu_seconds() - before;
    assert!(spent < 0.6, "an idle terminal used {spent:.2}s of CPU in 3s");
    e.terminals.stop_all("tTerm quit.").await;
}

/// The page as tTerm Web's ClassicTerminal is, for floods (see
/// ClassicTerminal.tsx). It takes all that comes and hands it to xterm.js,
/// which draws it in order at `rate` bytes a second. Its count of what is
/// not drawn yet asks the engine to pause above HIGH and to go on below LOW;
/// a reset sets the count to 0, but xterm.js keeps what it was given, and
/// the write callbacks of that still count down. From a reset until all
/// that came before "replayed" is drawn, it is replaying, and drops what is
/// typed.
struct DrawingPage {
    page: Page,
    rate: f64,
    received: u64,
    drawn: f64,
    count: f64,
    paused: bool,
    replaying: bool,
    replayed_at: Option<u64>,
    resets: usize,
}

const HIGH: f64 = 512.0 * 1024.0;
const LOW: f64 = 128.0 * 1024.0;

impl DrawingPage {
    fn new(page: Page, rate: f64) -> Self {
        DrawingPage { page, rate, received: 0, drawn: 0.0, count: 0.0, paused: false, replaying: false, replayed_at: None, resets: 0 }
    }

    /// Takes and draws for `time`.
    async fn run(&mut self, time: Duration) {
        let end = Instant::now() + time;
        let mut last = Instant::now();
        while Instant::now() < end {
            while let Ok(m) = self.page.rx.try_recv() {
                match &m {
                    Outgoing::Binary(f) => {
                        let n = (f.len() - 13) as u64;
                        self.received += n;
                        self.count += n as f64;
                    }
                    Outgoing::Text(t) => {
                        let v: Value = serde_json::from_str(t).unwrap();
                        if v["op"] == "reset" {
                            self.resets += 1;
                            self.replaying = true;
                            self.count = 0.0;
                        } else if v["op"] == "replayed" {
                            self.replayed_at = Some(self.received);
                        }
                    }
                }
                self.page.take(m);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
            let dt = last.elapsed().as_secs_f64();
            last = Instant::now();
            let before = self.drawn;
            self.drawn = (self.drawn + self.rate * dt).min(self.received as f64);
            self.count -= self.drawn - before;
            if let Some(at) = self.replayed_at {
                if self.drawn >= at as f64 {
                    self.replaying = false;
                    self.replayed_at = None;
                }
            }
            if !self.paused && self.count > HIGH {
                self.paused = true;
                self.page.send(json!({"op": "pause", "ch": 1})).await;
            } else if self.paused && self.count < LOW {
                self.paused = false;
                self.page.send(json!({"op": "resume", "ch": 1})).await;
            }
        }
    }

    /// Typed by a person: lost while the page replays, as on the page.
    async fn type_keys(&self, data: &str) -> bool {
        if self.replaying {
            return false;
        }
        self.page.keys(1, data).await;
        true
    }
}

/// `yes` into a window that draws `rate` bytes a second: the shell keeps to
/// the window, the window never starts over, and Ctrl+C is not lost.
async fn flood_at(rate: f64, flood: Duration) {
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let page = attached(&e, &id, 80, 24).await;
    let mut window = DrawingPage::new(page, rate);
    let deadline = Instant::now() + Duration::from_secs(10);
    while (window.replaying || window.resets == 0) && Instant::now() < deadline {
        window.run(Duration::from_millis(100)).await;
    }
    assert!(!window.replaying, "the first replay is drawn");
    let resets = window.resets;
    let at_start = window.received;

    assert!(window.type_keys("yes flood\r").await);
    window.run(flood).await;
    let came = (window.received - at_start) as f64;
    let secs = flood.as_secs_f64();
    assert!(came > rate * secs * 0.5, "the flood came: {came}");
    assert!(came < rate * secs + 2.0 * 1024.0 * 1024.0, "the shell ran ahead of the window: {came}");
    assert_eq!(window.resets, resets, "the window started over during the flood");

    assert!(window.type_keys("\x03").await, "Ctrl+C was lost: the page was replaying");
    let at_ctrl_c = window.received;
    window.run(Duration::from_millis(300)).await;
    assert!(window.type_keys("echo after-$((6*7))\r").await);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !window.page.text().contains("after-42") && Instant::now() < deadline {
        window.run(Duration::from_millis(100)).await;
    }
    assert!(window.page.text().contains("after-42"), "the shell did not come back");
    let after = window.received - at_ctrl_c;
    assert!(after < 2 * 1024 * 1024, "{after} bytes still came after Ctrl+C");
    let t = e.terminals.get(&uuid::Uuid::parse_str(&id).unwrap()).unwrap();
    t.close("Closed.").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_goes_at_the_pace_of_a_slow_window_too() {
    let _turn = heavy();
    // Slower than the pause of the page lasts STALL: a window busy with
    // colours, or drawing without WebGL.
    flood_at(300.0 * 1024.0, Duration::from_secs(5)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pages_that_come_and_go_during_a_flood_leave_nothing_behind() {
    let _turn = heavy();
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let mut page = attached(&e, &id, 80, 24).await;
    let t = e.terminals.get(&uuid::Uuid::parse_str(&id).unwrap()).unwrap();
    page.keys(1, "yes flood\r").await;
    let other = Page::new(&e);
    for _ in 0..300 {
        other.send(json!({"op": "attach", "ch": 7, "id": id, "after": null})).await;
        // The page takes what comes, as the shim does.
        while let Ok(m) = page.rx.try_recv() {
            page.take(m);
        }
        tokio::task::yield_now().await;
        other.send(json!({"op": "detach", "ch": 7})).await;
    }
    page.keys(1, "\x03").await;
    other.sock.close().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(t.watching(), 1, "pages that went still hold the shell");
    t.close("Closed.").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_goes_at_the_pace_of_the_window_and_ctrl_c_is_not_lost() {
    let _turn = heavy();
    flood_at(4.0 * 1024.0 * 1024.0, Duration::from_secs(3)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_that_stops_taking_does_not_stop_the_shell() {
    let _turn = heavy();
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let mut page = attached(&e, &id, 80, 24).await;
    let done = std::env::temp_dir().join(format!("tterm-done-{}", uuid::Uuid::new_v4()));
    // The page takes nothing from here on (hidden, busy, gone without a word).
    page.keys(1, &format!("head -c 8000000 /dev/zero | tr '\\0' x; echo; echo done > {}\r", done.display())).await;
    let started = Instant::now();
    while !done.exists() && started.elapsed() < Duration::from_secs(15) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(done.exists(), "the shell waited for a page that took nothing");
    assert!(started.elapsed() < tterm_engine::terminals::STALL * 2 + Duration::from_secs(4), "{:?}", started.elapsed());
    let _ = std::fs::remove_file(&done);

    // Back, it starts over from what is kept, and types again.
    assert!(page.until(20, |p| p.msgs.iter().filter(|m| m["op"] == "reset").count() >= 2).await, "no fresh start");
    assert!(page.until(20, |p| p.msgs.iter().filter(|m| m["op"] == "replayed").count() >= 2).await);
    page.keys(1, "echo back-$((2+3))\r").await;
    assert!(page.until(10, |p| p.text().contains("back-5")).await);
    let t = e.terminals.get(&uuid::Uuid::parse_str(&id).unwrap()).unwrap();
    t.close("Closed.").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shell_that_ignores_the_hangup_is_killed_three_seconds_after_it() {
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let mut page = attached(&e, &id, 80, 24).await;
    page.keys(1, "trap '' HUP; echo deaf-$((4*4))\r").await;
    assert!(page.until(10, |p| p.text().contains("deaf-16")).await, "{}", page.text());
    let started = Instant::now();
    let (status, t) = request(&e, "DELETE", &format!("/api/terminals/{id}"), Value::Null).await;
    assert_eq!(status, 200, "{t}");
    let took = started.elapsed();
    assert_eq!(t["state"], "ended");
    assert_eq!(t["reason"], "Closed.");
    assert!(took >= Duration::from_millis(2500) && took < Duration::from_millis(4500), "{took:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attach_after_the_page_went_starts_nothing() {
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let mut first = attached(&e, &id, 80, 24).await;
    first.sock.close().await;
    // On its way when the page went.
    first.send(json!({"op": "attach", "ch": 2, "id": id, "after": null, "focus": true})).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let t = e.terminals.get(&uuid::Uuid::parse_str(&id).unwrap()).unwrap();
    assert_eq!(t.lock().active, None, "the page that went still types");
    // The page that comes next types, without asking.
    let mut next = Page::new(&e);
    next.send(json!({"op": "attach", "ch": 1, "id": id, "after": null})).await;
    assert!(next.until(10, |p| p.msgs.iter().any(|m| m["op"] == "replayed")).await);
    next.keys(1, "echo next-$((3*5))\r").await;
    assert!(next.until(10, |p| p.text().contains("next-15")).await, "{}", next.text());
    while first.rx.try_recv().is_ok() {}
    assert!(!first.msgs.iter().any(|m| m["op"] == "attached" && m["ch"] == 2));
    t.close("Closed.").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_shell_gets_none_of_the_apps_descriptors() {
    // A descriptor of the app left open across exec, as WebKit leaves some.
    let leaked = unsafe {
        let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
        assert!(fd >= 0);
        let high = libc::fcntl(fd, libc::F_DUPFD, 233);
        libc::close(fd);
        assert!(high >= 233);
        high
    };
    let e = engine().await;
    let id = open(&e, 80, 24).await;
    let mut page = attached(&e, &id, 80, 24).await;
    page.keys(1, "echo FDS: $(ls /dev/fd/ | tr '\\n' ' ')END\r").await;
    // The answer, not the command as the shell echoes it.
    let answer = |text: &str| text.lines().filter(|l| l.contains("FDS: ") && !l.contains("$(ls") && l.contains("END")).last().map(str::to_string);
    assert!(page.until(10, |p| answer(&p.text()).is_some()).await, "{}", page.text());
    let line = answer(&page.text()).unwrap();
    let fds: Vec<i32> = line.split("FDS: ").nth(1).unwrap().trim_end_matches("END").split_whitespace().filter_map(|n| n.parse().ok()).collect();
    assert!(!fds.contains(&leaked), "the shell has the app's descriptor {leaked}: {fds:?}");
    // 0 to 2, and what ls opens to list them.
    assert!(fds.iter().all(|&fd| fd < 10), "the shell has more than its own: {fds:?}");
    unsafe { libc::close(leaked) };
    let t = e.terminals.get(&uuid::Uuid::parse_str(&id).unwrap()).unwrap();
    t.close("Closed.").await;
}
