//! The terminals tTerm Web opens on this computer, through the link to it
//! (link.rs). What tterm-agent did in agent.py (WebShell, WebShells,
//! run_script), the same way, so that the core needs no change for it.
//!
//! The core asks for a shell of the page's size with a command to run, sends
//! keys and sizes, and closes it; it also asks for short sh scripts: Tab, the
//! folders and branches over the input line, the passport, the scripts of
//! the markers. Everything else (markers, blocks, history) lives in the core,
//! as for a server, so this side stays a pipe and rarely needs a new version.
//!
//! The shells belong to this computer, not to a connection: the laptop
//! sleeps, the network blinks, and tTerm Web finds them where they were when
//! the link is back. Each counts what it printed from its first byte and
//! keeps the last of it; coming back, the core says how much it has, and the
//! rest is sent again, nothing lost and nothing twice. Kept while the link is
//! down for an hour at most, counted while the computer is awake.

use crate::link::{Log, Timing};
use crate::pty::{self, Pty};
use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};

/// tTerm Web's binary frames: a byte of kind, four of channel, then the data.
pub const OUTPUT: u8 = 1;
pub const INPUT: u8 = 2;

/// What a shell printed is kept this far back, so that what was on its way
/// when the connection went can be sent again.
pub const RING_MAX: u64 = 1024 * 1024;
/// Printed and not sent yet, at most. Past it the shell's output waits, as
/// it does in a terminal nobody reads.
pub const UNSENT_MAX: u64 = 512 * 1024;
/// Output in one frame, at most.
pub const FRAME_OUT: usize = 64 * 1024;
/// Shells open at once, not counting those that ended and wait to say so.
/// Not a policy, only a stop for a runaway that keeps opening windows.
pub const MAX_SHELLS: usize = 16;
/// A shell that has not ended this long after its hangup is killed.
pub const HANGUP_GRACE: Duration = Duration::from_secs(3);

/// tTerm Web's scripts: how many at once on one connection, how long by
/// default and at most, how much of what they print goes back.
pub const SIDE_AT_ONCE: usize = 4;
pub const SIDE_TIMEOUT: Duration = Duration::from_secs(10);
pub const SIDE_TIMEOUT_MAX: Duration = Duration::from_secs(60);
pub const SIDE_OUT_MAX: usize = 2 * 1024 * 1024;
pub const SIDE_ERR_MAX: usize = 4096;

/// One frame for the connection.
#[derive(Debug)]
pub enum Frame {
    Text(String),
    Binary(Vec<u8>),
    /// The WebSocket's own ping, answered by the hub's WebSocket (link.rs,
    /// keepalive).
    Ping(Vec<u8>),
}

/// The way out of one connection: what it sends goes in order, and waits
/// while the connection is slow. Sending on one that is gone does nothing.
/// Signs of life, pongs and the goodbye have a lane of their own that goes
/// first: a flood of output on a slow link must not hold them back, or the
/// hub would seem silent while it is only busy.
#[derive(Clone)]
pub struct Out {
    id: u64,
    tx: mpsc::Sender<Frame>,
    ctl: mpsc::Sender<Frame>,
}

static OUTS: AtomicU64 = AtomicU64::new(1);

impl Out {
    pub fn new(tx: mpsc::Sender<Frame>, ctl: mpsc::Sender<Frame>) -> Out {
        Out { id: OUTS.fetch_add(1, Ordering::Relaxed), tx, ctl }
    }

    pub async fn json(&self, msg: Value) {
        let _ = self.tx.send(Frame::Text(msg.to_string())).await;
    }

    pub async fn bytes(&self, data: Vec<u8>) {
        let _ = self.tx.send(Frame::Binary(data)).await;
    }

    /// On the lane that goes first, without waiting: Err(true) when even it
    /// is full (the connection is stuck), Err(false) when it is gone.
    pub fn control(&self, msg: Value) -> Result<(), bool> {
        self.first(Frame::Text(msg.to_string()))
    }

    /// A WebSocket ping, on the lane that goes first, as `control`.
    pub fn ping(&self, payload: Vec<u8>) -> Result<(), bool> {
        self.first(Frame::Ping(payload))
    }

    fn first(&self, frame: Frame) -> Result<(), bool> {
        match self.ctl.try_send(frame) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(true),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(false),
        }
    }

    fn same(&self, other: &Out) -> bool {
        self.id == other.id
    }
}

/// A whole number from tTerm Web: an integer, a number with a fraction
/// (cut), a string of digits or a boolean, the way Python's int() takes
/// them; None for anything else.
pub fn whole(value: Option<&Value>) -> Option<i64> {
    match value? {
        Value::Bool(b) => Some(*b as i64),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i)
            } else if n.as_u64().is_some() {
                Some(i64::MAX)
            } else {
                let f = n.as_f64()?;
                f.is_finite().then(|| f.trunc().clamp(i64::MIN as f64, i64::MAX as f64) as i64)
            }
        }
        Value::String(s) => s.trim().parse::<i128>().ok().map(|i| i.clamp(i64::MIN as i128, i64::MAX as i128) as i64),
        _ => None,
    }
}

/// A size from tTerm Web as a whole number from 1 to `top`, or the default
/// when it is not a number at all.
pub fn number(value: Option<&Value>, default: u16, top: u16) -> u16 {
    match whole(value) {
        Some(n) => n.clamp(1, top as i64) as u16,
        None => default,
    }
}

/// A byte offset from tTerm Web: a whole number from 0, or 0.
pub fn offset(value: Option<&Value>) -> u64 {
    whole(value).map(|n| n.max(0) as u64).unwrap_or(0)
}

/// Whether a value counts as yes, the way Python's bool() reads it; the
/// default when it is missing.
pub fn truthy(value: Option<&Value>, default: bool) -> bool {
    match value {
        None => default,
        Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// How long one of tTerm Web's scripts may run.
pub fn script_timeout(value: Option<&Value>) -> Duration {
    let seconds = match value {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::Bool(b)) => Some(*b as i64 as f64),
        Some(Value::String(s)) => s.trim().parse::<f64>().ok(),
        _ => None,
    };
    match seconds {
        Some(s) if s.is_finite() && s > 0.0 => Duration::from_secs_f64(s.min(SIDE_TIMEOUT_MAX.as_secs_f64())),
        _ => SIDE_TIMEOUT,
    }
}

/// The text of a value: a string as it is, a number or a boolean written
/// out; nothing for null or a missing value.
fn text(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

struct State {
    /// The last of what it printed, from byte `ring_start` on.
    ring: VecDeque<u8>,
    ring_start: u64,
    /// Bytes printed in all, and how many of them went to a connection.
    produced: u64,
    sent: u64,
    /// Bytes tTerm Web asked for that are no longer kept, to say first.
    gap: u64,
    /// The connection it goes over, None while there is none.
    out: Option<Out>,
    detached_at: Instant,
    /// Offered back after a reconnect: if not taken by then, it ends.
    claim_by: Option<Instant>,
    /// Its output is over; the exit code to report, and when it was.
    over: bool,
    code: Option<i32>,
    reported: Option<Instant>,
    closed: bool,
}

/// One of tTerm Web's terminals for as long as its shell runs, over
/// whichever connection there is, none at all while the link is down.
struct Shell {
    ch: u32,
    pty: Arc<Pty>,
    st: Mutex<State>,
    /// The sender has something to send.
    wake: Notify,
    /// What waits to be sent went below UNSENT_MAX, or the shell closed.
    room: Notify,
}

impl Shell {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Goes over `out` from now on, from byte `start` of its output: how
    /// much tTerm Web has. Anything it is missing is sent again.
    fn attach(&self, out: &Out, start: u64) {
        {
            let mut st = self.lock();
            let mut start = start.min(st.produced);
            if start < st.ring_start {
                st.gap = st.ring_start - start;
                start = st.ring_start;
            }
            st.sent = start;
            st.out = Some(out.clone());
            st.claim_by = None;
            // Its end, if it ended, is said again after what is sent again.
            st.reported = None;
        }
        self.wake.notify_one();
        self.room.notify_one();
    }

    fn keep(st: &mut State, data: &[u8]) {
        st.ring.extend(data);
        st.produced += data.len() as u64;
        // Only what was sent goes. After a reconnect nearly all of the ring
        // may wait to be sent again, and a read under way lands on top of
        // it: the ring then holds that read more until it is sent.
        let over = (st.ring.len() as u64).saturating_sub(RING_MAX);
        let extra = over.min(st.sent.saturating_sub(st.ring_start));
        if extra > 0 {
            st.ring.drain(..extra as usize);
            st.ring_start += extra;
        }
    }
}

/// tTerm Web's terminals on this computer, and its scripts.
pub struct Hosted {
    shells: Mutex<HashMap<u32, Arc<Shell>>>,
    /// The shells of terminals closed and not yet seen to end: the agent,
    /// stopping, waits for them (end_all).
    closing: Mutex<Vec<Arc<Pty>>>,
    timing: Timing,
    log: Log,
    /// Where the agent lives, said to its terminals (TTERM_AGENT_DIR):
    /// tTerm Web's installer, run in one of them, would stop the agent it
    /// runs through, and refuses.
    agent_dir: Option<String>,
}

enum Next {
    Gap(u64),
    Bytes(Vec<u8>),
    Exit(Option<i32>),
}

impl Hosted {
    pub fn new(timing: Timing, log: Log, agent_dir: Option<String>) -> Arc<Hosted> {
        Arc::new(Hosted { shells: Mutex::new(HashMap::new()), closing: Mutex::new(Vec::new()), timing, log, agent_dir })
    }

    fn map(&self) -> MutexGuard<'_, HashMap<u32, Arc<Shell>>> {
        self.shells.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn get(&self, ch: u32) -> Option<Arc<Shell>> {
        self.map().get(&ch).cloned()
    }

    /// The channels of the shells kept, for the hello: the core takes each
    /// back from the byte it has.
    pub fn channels(&self) -> Vec<u32> {
        let mut chs: Vec<u32> = self.map().keys().copied().collect();
        chs.sort_unstable();
        chs
    }

    /// Shells open, not counting those that ended.
    pub fn live(&self) -> usize {
        let shells: Vec<Arc<Shell>> = self.map().values().cloned().collect();
        shells.iter().filter(|s| !s.lock().over).count()
    }

    /// The environment of the terminals (`terminal`) and of the scripts:
    /// made the way sshd makes one, as tterm-agent did, and not the agent's
    /// own, which may carry the settings of the terminal it was started in.
    pub fn env(&self, terminal: bool) -> Vec<(String, String)> {
        let mut env = pty::clean_env(false);
        if terminal {
            env.push(("TERM".into(), "xterm-256color".into()));
            if let Some(dir) = &self.agent_dir {
                env.push(("TTERM_AGENT_DIR".into(), dir.clone()));
            }
        }
        env
    }

    /// tTerm Web opens a terminal: its command, run by the login shell with
    /// -c, as sshd runs one, in a pseudo-terminal of the page's size.
    pub async fn open(self: &Arc<Self>, ch: u32, msg: &Value, out: &Out) {
        if let Some(old) = self.get(ch) {
            let (linked, over) = {
                let st = old.lock();
                (st.out.is_some(), st.over)
            };
            if linked && !over {
                return; // the same window twice: the first stays
            }
            // Kept from before, or over, and the hub no longer knows it:
            // the number is the hub's to give.
            self.close_shell(&old);
        }
        if self.live() >= MAX_SHELLS {
            out.json(json!({"t": "exit", "code": null, "error": "too many terminals open on this machine", "ch": ch})).await;
            return;
        }
        let cmd = text(msg.get("cmd"));
        let cols = number(msg.get("cols"), 80, 1000);
        let rows = number(msg.get("rows"), 24, 500);
        // Off when the core is about to type its one-time key; its shell
        // scripts turn echo back on once they have read it. Set before the
        // shell exists, it cannot race the key.
        let echo = truthy(msg.get("echo"), true);
        let argv = vec![pty::login_shell(), "-c".to_string(), cmd];
        // What the shell printed before it ended is read whole, however long
        // the link takes to come back for it (Drain::Patient), as tterm-agent did.
        let started = match pty::spawn_with(&argv, &self.env(true), &pty::home_dir(), cols, rows, echo, pty::Drain::Patient) {
            Ok(started) => started,
            Err(e) => {
                out.json(json!({"t": "exit", "code": null, "error": format!("could not start the shell: {e}"), "ch": ch})).await;
                return;
            }
        };
        let shell = Arc::new(Shell {
            ch,
            pty: Arc::new(started.pty),
            st: Mutex::new(State {
                ring: VecDeque::new(),
                ring_start: 0,
                produced: 0,
                sent: 0,
                gap: 0,
                out: None,
                detached_at: Instant::now(),
                claim_by: None,
                over: false,
                code: None,
                reported: None,
                closed: false,
            }),
            wake: Notify::new(),
            room: Notify::new(),
        });
        self.map().insert(ch, shell.clone());
        shell.attach(out, 0);
        tokio::spawn(pump(shell.clone(), started.output));
        tokio::spawn(send_loop(shell));
    }

    /// tTerm Web takes back a terminal kept from a connection before, having
    /// `start` bytes of it.
    pub async fn resume(&self, ch: u32, start: u64, out: &Out) {
        let Some(shell) = self.get(ch) else {
            out.json(json!({"t": "exit", "code": null, "gone": true, "ch": ch})).await;
            return;
        };
        shell.attach(out, start);
        (self.log)(&format!("tTerm Web took terminal {ch} back"));
    }

    /// Keys for one of the terminals, while it has a connection.
    pub fn input(&self, ch: u32, data: &[u8]) {
        if let Some(shell) = self.get(ch) {
            if shell.lock().out.is_some() {
                shell.pty.write(data);
            }
        }
    }

    /// The page's size changed: the program in front hears SIGWINCH.
    pub fn resize(&self, ch: u32, msg: &Value) {
        if let Some(shell) = self.get(ch) {
            shell.pty.resize(number(msg.get("cols"), 80, 1000), number(msg.get("rows"), 24, 500));
        }
    }

    /// tTerm Web is done with a terminal: its shell gets a hangup. Whether
    /// there was one.
    pub fn close(&self, ch: u32) -> bool {
        match self.get(ch) {
            Some(shell) => {
                self.close_shell(&shell);
                true
            }
            None => false,
        }
    }

    fn close_shell(&self, shell: &Arc<Shell>) {
        {
            let mut st = shell.lock();
            if st.closed {
                return;
            }
            st.closed = true;
            st.out = None;
        }
        {
            let mut map = self.map();
            if map.get(&shell.ch).is_some_and(|s| Arc::ptr_eq(s, shell)) {
                map.remove(&shell.ch);
            }
        }
        shell.pty.hangup();
        // Its reader goes on until the shell is gone (on macOS a dying
        // process waits until its last output is read); the sender stops.
        shell.room.notify_one();
        shell.wake.notify_one();
        {
            let mut closing = self.closing.lock().unwrap_or_else(|e| e.into_inner());
            closing.retain(|p| p.running());
            closing.push(shell.pty.clone());
        }
        let pty = shell.pty.clone();
        tokio::spawn(async move {
            if pty.wait(HANGUP_GRACE).await.is_none() {
                pty.kill();
            }
        });
    }

    /// The connection `out` went: its terminals wait for the next one.
    pub fn detach(&self, out: &Out) {
        let shells: Vec<Arc<Shell>> = self.map().values().cloned().collect();
        let mut kept = 0;
        for shell in shells {
            let mut st = shell.lock();
            if st.out.as_ref().is_some_and(|o| o.same(out)) {
                st.out = None;
                st.claim_by = None;
                st.detached_at = Instant::now();
                kept += 1;
            }
        }
        if kept > 0 {
            (self.log)(&format!("keeping {kept} terminal(s) for tTerm Web until the link is back"));
        }
    }

    /// Offered back in the hello of a connection that is now up: tTerm Web
    /// takes them, or ends them; any it does neither with end by themselves.
    pub fn claim(&self, wait: Duration) {
        let deadline = Instant::now() + wait;
        let shells: Vec<Arc<Shell>> = self.map().values().cloned().collect();
        for shell in shells {
            let mut st = shell.lock();
            if st.out.is_none() {
                st.claim_by = Some(deadline);
            }
        }
    }

    /// Ends what waited too long: a terminal not taken back, one whose link
    /// did not come back for an hour, one whose end was said a while ago.
    pub fn sweep(&self) {
        let now = Instant::now();
        let shells: Vec<Arc<Shell>> = self.map().values().cloned().collect();
        for shell in shells {
            let why = {
                let st = shell.lock();
                if st.out.is_some() {
                    // Its end reached tTerm Web.
                    match st.reported {
                        Some(at) if now.saturating_duration_since(at) > self.timing.ended_keep => Some(None),
                        _ => None,
                    }
                } else if let Some(by) = st.claim_by {
                    (now > by).then(|| Some(format!("terminal {} was not taken back: ending it", shell.ch)))
                } else if now.saturating_duration_since(st.detached_at) > self.timing.keep_for {
                    Some(Some(format!(
                        "terminal {} waited {:.0} minutes for the link: ending it",
                        shell.ch,
                        self.timing.keep_for.as_secs_f64() / 60.0
                    )))
                } else {
                    None
                }
            };
            if let Some(note) = why {
                if let Some(note) = note {
                    (self.log)(&note);
                }
                self.close_shell(&shell);
            }
        }
    }

    /// Sweeps every few seconds, for as long as it runs.
    pub fn spawn_keeper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(me.timing.sweep_every).await;
                me.sweep();
            }
        })
    }

    /// Every terminal ends: the agent stops.
    pub fn close_all(&self) {
        let shells: Vec<Arc<Shell>> = self.map().values().cloned().collect();
        for shell in shells {
            self.close_shell(&shell);
        }
    }

    /// Every terminal ends, and this waits for their shells and those of
    /// terminals closed before: one that ignores the hangup is killed
    /// HANGUP_GRACE after it. The agent stops.
    pub async fn end_all(&self) {
        self.close_all();
        let ptys: Vec<Arc<Pty>> = std::mem::take(&mut *self.closing.lock().unwrap_or_else(|e| e.into_inner()));
        let deadline = Instant::now() + HANGUP_GRACE;
        for pty in ptys {
            let left = deadline.saturating_duration_since(Instant::now());
            if pty.wait(left).await.is_none() {
                pty.kill();
                pty.wait(Duration::from_millis(500)).await;
            }
        }
    }

    /// One of tTerm Web's scripts; the answer carries the id it came with.
    pub async fn script(&self, msg: &Value, out: &Out) {
        let timeout = script_timeout(msg.get("timeout"));
        let (code, stdout, stderr) = run_script(&text(msg.get("script")), timeout, &self.env(false)).await;
        let b64 = base64::engine::general_purpose::STANDARD;
        out.json(json!({
            "t": "ran",
            "id": msg.get("id").cloned().unwrap_or(Value::Null),
            "code": code,
            "out": b64.encode(stdout),
            "err": b64.encode(stderr),
        }))
        .await;
    }
}

/// Reads what the shell prints into the ring. With too much of it unsent,
/// a slow or missing connection, it stops reading, and the programs in the
/// terminal wait, as in a terminal nobody reads.
async fn pump(shell: Arc<Shell>, mut output: mpsc::Receiver<Vec<u8>>) {
    loop {
        loop {
            let wait = {
                let st = shell.lock();
                !st.closed && st.produced - st.sent > UNSENT_MAX
            };
            if !wait {
                break;
            }
            shell.room.notified().await;
        }
        let Some(data) = output.recv().await else { break };
        {
            let mut st = shell.lock();
            if st.closed {
                continue; // read on until the shell is gone, to nobody
            }
            Shell::keep(&mut st, &data);
        }
        shell.wake.notify_one();
    }
    if shell.lock().closed {
        return;
    }
    // Gone on its own, someone typed `exit`: its code, once it is collected.
    // One that has not ended by now gets a hangup, and a kill if it ignores it.
    let code = bury(&shell.pty).await;
    {
        let mut st = shell.lock();
        st.code = code;
        st.over = true;
    }
    shell.wake.notify_one();
}

async fn bury(pty: &Pty) -> Option<i32> {
    if let Some(code) = pty.wait(HANGUP_GRACE).await {
        return code;
    }
    pty.hangup();
    if let Some(code) = pty.wait(HANGUP_GRACE).await {
        return code;
    }
    pty.kill();
    pty.wait(HANGUP_GRACE).await.flatten()
}

/// Sends what is not sent yet, in order, and the end after it.
async fn send_loop(shell: Arc<Shell>) {
    let head = {
        let mut h = vec![OUTPUT];
        h.extend_from_slice(&shell.ch.to_be_bytes());
        h
    };
    loop {
        shell.wake.notified().await;
        loop {
            let (out, what) = {
                let mut st = shell.lock();
                if st.closed {
                    return;
                }
                let Some(out) = st.out.clone() else { break };
                if st.sent < st.ring_start {
                    // Never so; but were it, what is gone is said as such.
                    let lost = st.ring_start - st.sent;
                    st.gap += lost;
                    st.sent = st.ring_start;
                }
                if st.gap > 0 {
                    let lost = std::mem::take(&mut st.gap);
                    (out, Next::Gap(lost))
                } else if st.sent < st.produced {
                    let at = (st.sent - st.ring_start) as usize;
                    let n = FRAME_OUT.min(st.ring.len().saturating_sub(at));
                    if n == 0 {
                        break;
                    }
                    let mut frame = Vec::with_capacity(head.len() + n);
                    frame.extend_from_slice(&head);
                    let (a, b) = st.ring.as_slices();
                    if at < a.len() {
                        let first = &a[at..a.len().min(at + n)];
                        frame.extend_from_slice(first);
                        let rest = n - first.len();
                        frame.extend_from_slice(&b[..rest]);
                    } else {
                        let from = at - a.len();
                        frame.extend_from_slice(&b[from..from + n]);
                    }
                    st.sent += n as u64;
                    if st.produced - st.sent <= UNSENT_MAX {
                        shell.room.notify_one();
                    }
                    (out, Next::Bytes(frame))
                } else if st.over {
                    // Gone on its own rather than closed by the hub. Said
                    // after all it printed; kept a while more, in case the
                    // link went with it (Timing::ended_keep).
                    if st.reported.is_some() {
                        break;
                    }
                    st.reported = Some(Instant::now());
                    (out, Next::Exit(st.code))
                } else {
                    break;
                }
            };
            match what {
                Next::Gap(lost) => out.json(json!({"t": "gap", "lost": lost, "ch": shell.ch})).await,
                Next::Bytes(frame) => out.bytes(frame).await,
                Next::Exit(code) => {
                    out.json(json!({"t": "exit", "code": code, "ch": shell.ch})).await;
                    break;
                }
            }
        }
    }
}

/// Kills a script's whole group when dropped, unless it finished: not only
/// sh but what it started, a hung df or sudo among them.
struct Group(Option<u32>);

impl Drop for Group {
    fn drop(&mut self) {
        if let Some(pid) = self.0.take() {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    }
}

/// Runs one of tTerm Web's scripts with sh, outside any terminal: the exit
/// code (None when it did not finish in time; minus the signal when one
/// ended it), what it printed (SIDE_OUT_MAX at most) and the end of what it
/// complained about (SIDE_ERR_MAX).
pub async fn run_script(script: &str, timeout: Duration, env: &[(String, String)]) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    use std::os::unix::process::ExitStatusExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let home = pty::home_dir();
    let mut cmd = tokio::process::Command::new("/bin/sh");
    cmd.arg("-s")
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .current_dir(if home.is_dir() { home } else { "/".into() })
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    // A session of its own, as tterm-agent started them: no terminal to
    // ask a password on (an agent started by hand still has the window it
    // was started in), and a group of its own to end whole. Nothing of the
    // agent's reaches it: not even a terminal's descriptors, open a moment
    // before they are marked, should one be starting on another thread.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            pty::close_on_exec_from(3);
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return (None, Vec::new(), e.to_string().into_bytes()),
    };
    let mut group = Group(child.id());
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let work = async {
        let write = async {
            if let Some(mut stdin) = stdin.take() {
                let _ = stdin.write_all(script.as_bytes()).await;
            }
        };
        let read_out = async {
            let mut kept = Vec::new();
            if let Some(stdout) = stdout.as_mut() {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match stdout.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let room = SIDE_OUT_MAX.saturating_sub(kept.len());
                            kept.extend_from_slice(&buf[..n.min(room)]);
                        }
                    }
                }
            }
            kept
        };
        let read_err = async {
            let mut tail: Vec<u8> = Vec::new();
            if let Some(stderr) = stderr.as_mut() {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match stderr.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            tail.extend_from_slice(&buf[..n]);
                            if tail.len() > SIDE_ERR_MAX {
                                tail.drain(..tail.len() - SIDE_ERR_MAX);
                            }
                        }
                    }
                }
            }
            tail
        };
        let ((), out, err) = tokio::join!(write, read_out, read_err);
        let status = child.wait().await;
        (status, out, err)
    };
    match tokio::time::timeout(timeout, work).await {
        Ok((Ok(status), out, err)) => {
            // Done: what it left behind in its group lives on, as after
            // the agent's own scripts.
            group.0 = None;
            let code = status.code().or_else(|| status.signal().map(|s| -s));
            (code, out, err)
        }
        Ok((Err(e), out, _)) => (None, out, e.to_string().into_bytes()),
        Err(_) => (None, Vec::new(), b"the script did not finish in time".to_vec()),
    }
}
