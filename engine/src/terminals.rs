//! Terminals on this computer: real shells, kept by the engine, shown by the
//! page of tTerm Web inside the app's window.
//!
//! A port of `tterm/core/terminals.py`, so that the page sees exactly what
//! the core would show it: the same numbered events, the same replay after
//! a reload, the same one active page per terminal. What differs is where
//! the shell is: here, in a pseudo-terminal of this computer (pty.rs), not
//! at the other end of SSH or of an agent.
//!
//! Everything a terminal sends is numbered: each piece of output and each
//! marker gets the next number. The last few megabytes are kept, so a page
//! that comes back after a moment asks for everything after the last number
//! it has; a page that comes back empty, after a reload, gets all that is
//! kept, drawn again from a clean screen, and a full-screen program is asked
//! to redraw itself.
//!
//! From the shell's markers (shell.rs) each command becomes a block: its
//! text, the directory and branch it ran in, how long it took, how it
//! ended, and its output, the beginning and the end of it if it was long.
//! Finished blocks go to the store (store.rs), for the page's feed and the
//! input line's history; the input line types whole commands (`run`), and
//! asks this computer what a word under Tab can become (`complete`).
//!
//! Unlike the core, the shell here is read no faster than the window draws.
//! A local shell writes a hundred times faster than any network carries, and
//! a page that falls behind what is kept starts over from a replay, during
//! which it drops what is typed: Ctrl+C on `yes` would be lost. So the shell
//! waits for the pages that keep up (see `room`), as a terminal on a
//! computer does, and a page that stops drawing (hidden, gone) stops holding
//! it back.

use crate::blocks::Block;
use crate::complete;
use crate::modes::Modes;
use crate::pty::{self, Pty};
use crate::shell::{self, Marker, MarkerParser, Piece};
use crate::store::{Finished, Store};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch, Notify, Semaphore};
use uuid::Uuid;

/// Output kept for pages that come back after a moment away.
pub const KEEP_BYTES: usize = 4 * 1024 * 1024;
/// What a page that starts over draws: the last of the output...
pub const REPLAY_BYTES: usize = 1024 * 1024;
/// ...and no more lines than the page keeps: 10,000 of history
/// (`scrollback` in ClassicTerminal.tsx) and a screen. A megabyte of `yes`
/// is 170,000 lines, all drawn to be dropped, and seen flying by.
pub const REPLAY_LINES: usize = 10_000 + 500;
/// How long a new shell waits for the page to say the size of its window.
/// The page asks for a terminal with a guess at the size and measures the
/// window a moment later; a shell started at the guess draws its first
/// prompt for the wrong width (zsh leaves its mark for a line left open).
const SIZE_WAIT: Duration = Duration::from_secs(1);
/// An ended terminal stays this long, so a page can still show how it ended.
pub const KEEP_ENDED: Duration = Duration::from_secs(15 * 60);
/// Typed before the shell is up, kept until it is.
const PENDING_MAX: usize = 64 * 1024;
/// A hangup is given this long before the shell is killed.
const HANGUP_GRACE: Duration = Duration::from_secs(3);
/// A killed shell is waited for this long, at most, before its terminal
/// ends without it.
const KILL_WAIT: Duration = Duration::from_secs(1);
/// When the app quits, its shells have this long to end after their
/// hangups; then they end with the app.
const QUIT_WAIT: Duration = Duration::from_millis(1500);
/// Output sent in one frame, at most.
pub const FRAME_MAX: usize = 32 * 1024;
/// How far the shell may write ahead of the slowest page that keeps up.
pub const LEAD_MAX: u64 = 256 * 1024;
/// A page that took nothing for this long while the shell waited for it no
/// longer holds the shell back. It is hidden, or stuck, or gone; if it comes
/// back far behind, it starts over from what is kept, as on the web.
pub const STALL: Duration = Duration::from_secs(2);
/// The same for a page that asked to pause: it is still drawing what it has
/// (half a megabyte and more), which a slow window takes seconds to do.
pub const STALL_PAUSED: Duration = Duration::from_secs(10);
/// Binary frames: one byte of kind, four of channel, eight of number.
pub const OUTPUT: u8 = 1;
pub const INPUT: u8 = 2;
/// A terminal's name, at most.
pub const NAME_MAX: usize = 40;
/// A command typed by `run` that the shell has not answered after this long
/// never started: a quote or a heredoc left open, or a history expansion
/// that failed (bash then shows its prompt again without a marker).
pub const TYPED_STALE: Duration = Duration::from_secs(3);
/// A side script (Tab, the directory and branch lists) may take this long,
/// print this much, and this many may run at once for one terminal.
pub const SIDE_TIMEOUT: Duration = Duration::from_secs(5);
pub const SIDE_MAX: usize = 1024 * 1024;
pub const SIDE_AT_ONCE: usize = 2;
/// The last commands, to say which one a replay starts inside of.
const RECENT: usize = 64;
pub const NOT_OPEN: &str = "The terminal is not open.";

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn iso_seconds(ms: i64) -> String {
    // UTC, to the second, as Python's isoformat(timespec="seconds") writes
    // it for an aware datetime.
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}+00:00")
}

#[derive(Clone, Debug)]
pub enum Kind {
    Out(Arc<[u8]>),
    Ev(Value),
}

#[derive(Clone, Debug)]
pub struct Event {
    pub seq: u64,
    /// Bytes of output from the start up to the end of this event.
    pub end: u64,
    pub kind: Kind,
}

/// How far one page has got: the bytes of output it was sent.
#[derive(Clone, Copy, Debug)]
struct Seen {
    pos: u64,
    /// When it last got further, or paused, or resumed.
    at: Instant,
    /// The page asked to pause: it is drawing what it has.
    paused: bool,
    /// It stopped taking while the shell waited for it, or has not started
    /// yet: the shell goes on without it until it starts over or catches up.
    behind: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Connecting,
    Open,
    Ended,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Connecting => "connecting",
            State::Open => "open",
            State::Ended => "ended",
        }
    }
}

/// Which machine a terminal is on, as tabs and lists name it.
#[derive(Clone, Debug)]
pub struct Place {
    pub machine_id: Uuid,
    pub machine: String,
    pub code: String,
}

impl Place {
    pub fn label(&self) -> String {
        format!("{}/{}", self.code, self.machine)
    }
}

/// How to start the shell: the command and what it marks (see shell.rs).
#[derive(Clone, Debug)]
pub struct Plan {
    pub shell: String,
    pub argv: Vec<String>,
    pub markers: bool,
    pub blocks: bool,
}

/// A command of late: where it starts and ends in the stream.
#[derive(Clone, Debug)]
struct Recent {
    command: String,
    cwd: String,
    branch: String,
    seq_start: u64,
    seq_end: Option<u64>,
    cols: u16,
    at: i64,
}

impl Recent {
    fn json(&self) -> Value {
        json!({
            "command": self.command,
            "cwd": self.cwd,
            "branch": self.branch,
            "seqStart": self.seq_start,
            "seqEnd": self.seq_end,
            "cols": self.cols,
            "at": self.at,
        })
    }
}

pub struct Inner {
    pub place: Place,
    pub name: String,
    pub cols: u16,
    pub rows: u16,
    pub state: State,
    pub reason: Option<String>,
    pub exit_code: Option<i32>,
    pub opened_ms: i64,
    pub ended_at: Option<Instant>,
    pub shell: Option<String>,
    pub markers: bool,
    pub blocks: bool,
    pub cwd: String,
    pub home: String,
    pub branch: String,
    pub venv: String,
    /// The shell's PATH at its last prompt, for Tab on a command.
    pub path: String,
    pub events: VecDeque<Event>,
    pub first_seq: u64,
    pub last_seq: u64,
    /// Bytes of output from the start.
    pub out_pos: u64,
    kept: usize,
    pub modes: Modes,
    base_modes: Modes,
    pub trimmed: bool,
    pending: Vec<u8>,
    pty: Option<Arc<Pty>>,
    closing: Option<String>,
    /// When it was hung up on purpose: the kill comes HANGUP_GRACE later.
    closing_at: Option<Instant>,
    nudging: bool,
    /// The watcher whose page types into this terminal; see Watcher.
    pub active: Option<u64>,
    /// How far each page watching it has got; see `room`.
    seen: HashMap<u64, Seen>,
    /// The one-time key of its markers, and what takes them out.
    key: String,
    parser: MarkerParser,
    /// The command running now.
    block: Option<Block>,
    recent: VecDeque<Recent>,
    /// A command was typed by `run` and the shell has not answered with a
    /// marker yet: no second one goes in on top of it.
    typed: bool,
    typed_at: Instant,
    typed_stale: Duration,
}

pub struct Terminal {
    pub id: Uuid,
    inner: Mutex<Inner>,
    version: watch::Sender<u64>,
    done: watch::Sender<bool>,
    /// A page got further: the shell may write on.
    progress: Notify,
    /// A page said the size of its window: the shell may start.
    sized: watch::Sender<bool>,
    store: Arc<Store>,
    /// Side scripts running for it.
    side: Semaphore,
}

impl Terminal {
    fn new(place: Place, name: String, cols: u16, rows: u16, store: Arc<Store>) -> Arc<Self> {
        let key = shell::new_key();
        let parser = MarkerParser::new(&key);
        Arc::new(Self {
            id: Uuid::new_v4(),
            inner: Mutex::new(Inner {
                place,
                name,
                cols,
                rows,
                state: State::Connecting,
                reason: None,
                exit_code: None,
                opened_ms: now_ms(),
                ended_at: None,
                shell: None,
                markers: false,
                blocks: false,
                cwd: String::new(),
                home: String::new(),
                branch: String::new(),
                venv: String::new(),
                path: String::new(),
                events: VecDeque::new(),
                first_seq: 1,
                last_seq: 0,
                out_pos: 0,
                kept: 0,
                modes: Modes::new(),
                base_modes: Modes::new(),
                trimmed: false,
                pending: Vec::new(),
                pty: None,
                closing: None,
                closing_at: None,
                nudging: false,
                active: None,
                seen: HashMap::new(),
                key,
                parser,
                block: None,
                recent: VecDeque::new(),
                typed: false,
                typed_at: Instant::now(),
                typed_stale: TYPED_STALE,
            }),
            version: watch::channel(0).0,
            done: watch::channel(false).0,
            progress: Notify::new(),
            sized: watch::channel(false).0,
            store,
            side: Semaphore::new(SIDE_AT_ONCE),
        })
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap()
    }

    /// Something changed: those who watch look again.
    pub fn changed(&self) {
        self.version.send_modify(|v| *v = v.wrapping_add(1));
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.version.subscribe()
    }

    pub fn state(&self) -> State {
        self.lock().state
    }

    pub fn label(&self) -> String {
        label_of(&self.lock())
    }

    pub fn describe(&self) -> Value {
        describe(self.id, &self.lock())
    }

    /// Keys from the page: to the shell, or kept until it is up.
    pub fn write(&self, data: &[u8]) {
        let mut st = self.lock();
        match st.state {
            State::Open => {
                if let Some(pty) = &st.pty {
                    pty.write(data);
                }
            }
            State::Connecting => {
                let room = PENDING_MAX.saturating_sub(st.pending.len());
                let take = room.min(data.len());
                st.pending.extend_from_slice(&data[..take]);
            }
            State::Ended => {}
        }
    }

    pub fn resize(&self, cols: i64, rows: i64) {
        let (cols, rows) = pty::clamp_size(cols, rows);
        let starting = {
            let mut st = self.lock();
            if (cols, rows) != (st.cols, st.rows) {
                st.cols = cols;
                st.rows = rows;
                if st.state == State::Open {
                    if let Some(pty) = &st.pty {
                        pty.resize(cols, rows);
                    }
                }
            }
            st.state == State::Connecting
        };
        if starting {
            self.sized.send_replace(true);
        }
    }

    /// Types a whole command at the shell's prompt and presses Enter, the
    /// way tTerm's own input line hands it over. Returns why not, or None.
    ///
    /// The command goes in as a bracketed paste when the shell has that on
    /// (bash 5.1+ and zsh do): the line editor then takes it as text, every
    /// line of it, with no key in it read as a binding, and Enter runs it
    /// all. Without it the text is typed as is.
    ///
    /// Ctrl+U goes first and empties the line. Keys typed into the previous
    /// command that it never read wait in the terminal, and the line editor
    /// takes them in at the prompt; they would end up in front of this
    /// command.
    pub fn run(&self, command: &str) -> Option<String> {
        let mut st = self.lock();
        let Some(pty) = st.pty.clone().filter(|_| st.state == State::Open) else {
            return Some(NOT_OPEN.into());
        };
        if !st.blocks {
            return Some("This shell does not mark where commands start, so it runs in the classic mode only.".into());
        }
        if st.block.is_some() {
            return Some("A command is still running.".into());
        }
        if st.typed {
            if st.typed_at.elapsed() < st.typed_stale {
                return Some("A command is still running.".into());
            }
            // The last one never started. Ctrl+C sets the shell back to an
            // empty prompt; whatever follows it in the same moment would be
            // thrown away by the terminal, so this command waits for Enter
            // again.
            pty.write(b"\x03");
            st.typed_at = Instant::now();
            return Some("The shell had not taken the last command (an open quote, or a history expansion with ! that failed). It is cancelled now: press Enter again.".into());
        }
        let text = clean_command(command);
        if text.trim().is_empty() {
            return Some("There is no command to run.".into());
        }
        let data = if st.modes.bracketed_paste() {
            [b"\x15\x1b[200~".as_slice(), text.as_bytes(), b"\x1b[201~\r"].concat()
        } else {
            [b"\x15".as_slice(), text.replace('\t', " ").as_bytes(), b"\r"].concat()
        };
        st.typed = true;
        st.typed_at = Instant::now();
        pty.write(&data);
        None
    }

    /// For checks: how long a typed command may go unanswered.
    pub fn set_typed_stale(&self, wait: Duration) {
        self.lock().typed_stale = wait;
    }

    /// Whether a command typed by `run` is still waiting for the shell.
    pub fn typed(&self) -> bool {
        self.lock().typed
    }

    /// The command running now, as the page gets it.
    pub fn running(&self) -> Option<Value> {
        running_of(&self.lock())
    }

    /// The command whose output goes on past the number `seq`: a replay
    /// that starts there starts inside it, after its start marker, and the
    /// feed still has to know what it was.
    pub fn block_at(&self, seq: u64) -> Option<Value> {
        let st = self.lock();
        st.recent.iter().rev().find(|e| e.seq_start <= seq && e.seq_end.is_none_or(|end| end > seq)).map(Recent::json)
    }

    // ------------------------------------------------------- side scripts

    /// Runs a small sh script on this computer, outside the terminal, and
    /// returns the lines it listed. An empty list when it fails: Tab then
    /// simply finds nothing.
    async fn side(&self, script: String) -> Result<Vec<String>, String> {
        if self.state() != State::Open {
            return Err(NOT_OPEN.into());
        }
        let _turn = self.side.acquire().await.map_err(|_| NOT_OPEN.to_string())?;
        let (_, out) = crate::machine::run_script(&script, SIDE_TIMEOUT).await;
        Ok(complete::listed(&out[..out.len().min(SIDE_MAX)]))
    }

    /// What the word under the cursor can become. `cursor` counts
    /// characters, as the page's line does.
    pub async fn complete(&self, line: &str, cursor: i64) -> Result<Value, String> {
        let chars: Vec<char> = line.chars().collect();
        let cursor = cursor.clamp(0, chars.len() as i64) as usize;
        let before: String = chars[..cursor].iter().collect();
        let (words, word) = complete::split(&before);
        let ctx = complete::context(&words, word);
        let (cwd, home, path) = {
            let st = self.lock();
            (st.cwd.clone(), st.home.clone(), st.path.clone())
        };
        let word = &ctx.word;
        let mut items: Vec<Value> = Vec::new();
        if ctx.kind == "command" {
            let names = self.side(complete::commands_script(&path, &word.value)).await?;
            items = complete::command_items(word, &names);
        } else if ctx.kind == "git" {
            items = complete::git_items(word);
        }
        if ctx.kind == "branch" || ctx.kind == "branch+file" {
            let refs = self.side(complete::branches_script(&cwd)).await?;
            items = complete::branch_items(word, &refs, ctx.switch);
        }
        if ctx.kind == "file" || ctx.kind == "dir" || ctx.kind == "branch+file" {
            let (place, _, _) = complete::dir_part(&word.value, &home);
            let entries = self.side(complete::list_script(&cwd, &place)).await?;
            items.extend(complete::file_items(word, &entries, &home, ctx.kind == "dir"));
        }
        let more = items.len() > complete::MAX_ITEMS;
        items.truncate(complete::MAX_ITEMS);
        Ok(json!({"start": word.start, "end": cursor, "quote": word.quote, "kind": ctx.kind, "items": items, "more": more}))
    }

    /// The directories in the terminal's current one.
    pub async fn dirs(&self) -> Result<Value, String> {
        let (cwd, home) = {
            let st = self.lock();
            (st.cwd.clone(), st.home.clone())
        };
        let entries = self.side(complete::list_script(&cwd, ".")).await?;
        Ok(json!({"cwd": cwd, "home": home, "dirs": complete::dirs_of(&entries)}))
    }

    /// The branches of the repository the terminal is in.
    pub async fn branches(&self) -> Result<Value, String> {
        let (cwd, branch) = {
            let st = self.lock();
            (st.cwd.clone(), st.branch.clone())
        };
        if branch.is_empty() {
            return Ok(json!({"current": "", "local": [], "remote": []}));
        }
        let refs = self.side(complete::branches_script(&cwd)).await?;
        let (local, remote) = complete::branches_of(&refs);
        Ok(json!({"current": branch, "local": local, "remote": remote}))
    }

    /// Asks a full-screen program to draw itself again: the window narrows
    /// by a column and back, which it hears as two resizes.
    pub fn nudge(self: &Arc<Self>) {
        let (pty, cols, rows) = {
            let mut st = self.lock();
            if st.nudging || st.state != State::Open {
                return;
            }
            let Some(pty) = st.pty.clone() else { return };
            st.nudging = true;
            (pty, st.cols, st.rows)
        };
        let me = self.clone();
        tokio::spawn(async move {
            pty.resize(cols.saturating_sub(1).max(pty::MIN_COLS), rows);
            tokio::time::sleep(Duration::from_millis(80)).await;
            {
                let mut st = me.lock();
                if st.state == State::Open {
                    pty.resize(st.cols, st.rows);
                }
                st.nudging = false;
            }
        });
    }

    // ------------------------------------------------------------ stream

    fn output(st: &mut Inner, data: Vec<u8>) {
        st.last_seq += 1;
        st.kept += data.len();
        st.out_pos += data.len() as u64;
        st.modes.feed(&data);
        let seq = st.last_seq;
        let end = st.out_pos;
        let data: Arc<[u8]> = Arc::from(data);
        if let Some(block) = st.block.as_mut() {
            block.add(&data);
        }
        st.events.push_back(Event { seq, end, kind: Kind::Out(data) });
        while st.kept > KEEP_BYTES && st.events.len() > 1 {
            let old = st.events.pop_front().expect("an event");
            st.first_seq = old.seq + 1;
            st.trimmed = true;
            if let Kind::Out(d) = &old.kind {
                st.kept -= d.len();
                st.base_modes.feed(d);
            }
        }
    }

    fn event(st: &mut Inner, value: Value) {
        st.last_seq += 1;
        let (seq, end) = (st.last_seq, st.out_pos);
        st.events.push_back(Event { seq, end, kind: Kind::Ev(value) });
    }

    /// What the shell printed: the screen's bytes, and our markers out of
    /// them.
    pub fn take(&self, data: Vec<u8>) {
        {
            let mut st = self.lock();
            let pieces = st.parser.feed(&data);
            for piece in pieces {
                match piece {
                    Piece::Out(bytes) => Self::output(&mut st, bytes),
                    Piece::Mark(m) => self.marker(&mut st, m),
                }
            }
        }
        self.changed();
    }

    fn marker(&self, st: &mut Inner, m: Marker) {
        // Markers carry the engine's clock, so that a page drawing them
        // again later still knows when each command started and ended.
        let at = now_ms();
        match m.kind.as_str() {
            "P" => {
                let code = code_of(m.field(0));
                let trim = if st.block.is_some() { self.finish_block(st, code) } else { 0 };
                st.typed = false;
                st.markers = true;
                st.cwd = m.field(1).to_string();
                st.home = m.field(2).to_string();
                st.branch = m.field(3).to_string();
                st.venv = m.field(4).to_string();
                st.path = m.field(5).to_string();
                // trim: how much of the end of the block's output was zsh's
                // partial-line mark, which the block does not keep.
                let value = json!({"t": "P", "code": code, "cwd": st.cwd, "home": st.home, "branch": st.branch, "venv": st.venv, "trim": trim, "at": at});
                Self::event(st, value);
            }
            "C" => {
                let prev = code_of(m.field(1));
                if st.block.is_some() {
                    // One line of several commands: the one before ended here.
                    self.finish_block(st, prev);
                }
                st.typed = false;
                let command = m.field(0).to_string();
                Self::event(st, json!({"t": "C", "command": command, "prev": prev, "at": at}));
                let seq = st.last_seq;
                st.block = Some(Block::new(command.clone(), st.cwd.clone(), st.branch.clone(), seq, at, st.cols));
                st.recent.push_back(Recent { command, cwd: st.cwd.clone(), branch: st.branch.clone(), seq_start: seq, seq_end: None, cols: st.cols, at });
                while st.recent.len() > RECENT {
                    st.recent.pop_front();
                }
            }
            _ => {}
        }
    }

    /// Saves the running command's block; returns how many bytes of zsh's
    /// partial-line mark came off the end of its output.
    fn finish_block(&self, st: &mut Inner, code: Option<i64>) -> usize {
        let Some(block) = st.block.take() else { return 0 };
        let last = st.last_seq;
        if let Some(entry) = st.recent.iter_mut().rev().find(|e| e.seq_start == block.seq_start) {
            entry.seq_end = Some(last);
        }
        let (mut output, cut) = block.output();
        let mut trim = 0;
        if st.shell.as_deref() == Some("zsh") {
            let stripped = shell::strip_eol_mark(&output, st.cols as usize);
            trim = output.len() - stripped.len();
            output = stripped;
        }
        self.store.save_block(
            &self.id.to_string(),
            Finished {
                seq_start: block.seq_start,
                seq_end: last,
                command: block.command,
                started_ms: block.started_ms,
                finished_ms: now_ms(),
                exit_code: code,
                cwd: block.cwd,
                branch: block.branch,
                output,
                cut,
                cols: block.cols,
            },
        );
        trim
    }

    // ------------------------------------------------------------ pace

    /// Waits, before more of the shell's output is taken, until the pages
    /// that keep up are less than LEAD_MAX behind. While it waits, the
    /// shell's writes fill the pseudo-terminal and the shell waits too.
    ///
    /// A page that took nothing for STALL while the shell waited for it
    /// (STALL_PAUSED while it says it is drawing) is marked behind and
    /// waited for no more; it is again once it starts over or catches up.
    /// Without pages, nothing waits.
    async fn room(&self) {
        let started = Instant::now();
        loop {
            let notified = self.progress.notified();
            {
                let mut st = self.lock();
                if st.state != State::Open || st.closing.is_some() {
                    return;
                }
                let out = st.out_pos;
                let slowest = st
                    .seen
                    .iter()
                    .filter(|(_, s)| !s.behind)
                    .min_by_key(|(_, s)| s.pos)
                    .map(|(id, s)| (*id, *s));
                let Some((id, seen)) = slowest else { return };
                if out.saturating_sub(seen.pos) < LEAD_MAX {
                    return;
                }
                let stall = if seen.paused { STALL_PAUSED } else { STALL };
                if started.elapsed() >= stall && seen.at.elapsed() >= stall {
                    if let Some(s) = st.seen.get_mut(&id) {
                        s.behind = true;
                    }
                    continue;
                }
            }
            let _ = tokio::time::timeout(Duration::from_millis(100), notified).await;
        }
    }

    /// A page starts watching: it holds nothing back until its first
    /// replay or resume says where it is.
    fn watch(&self, watcher: u64) {
        let mut st = self.lock();
        let pos = st.out_pos;
        st.seen.insert(watcher, Seen { pos, at: Instant::now(), paused: false, behind: true });
    }

    /// A page was sent the output up to `pos`. `fresh`: it starts over.
    /// Only for a page still watching: a watcher's task may outlive its
    /// watcher by a moment, and must not bring its page back.
    fn seen(&self, watcher: u64, pos: u64, fresh: bool) {
        {
            let mut st = self.lock();
            let out = st.out_pos;
            let Some(s) = st.seen.get_mut(&watcher) else { return };
            if pos > s.pos || fresh {
                s.at = Instant::now();
            }
            s.pos = pos;
            if fresh || out.saturating_sub(pos) < LEAD_MAX {
                s.behind = false;
            }
        }
        self.progress.notify_waiters();
    }

    /// The page asked to pause, or to go on: either way it is there.
    fn paused(&self, watcher: u64, paused: bool) {
        if let Some(s) = self.lock().seen.get_mut(&watcher) {
            s.paused = paused;
            s.at = Instant::now();
        }
        self.progress.notify_waiters();
    }

    /// How many pages watch it.
    pub fn watching(&self) -> usize {
        self.lock().seen.len()
    }

    /// A page stopped watching: it holds nothing back any more.
    fn forget(&self, watcher: u64) {
        self.lock().seen.remove(&watcher);
        self.progress.notify_waiters();
    }

    // ------------------------------------------------------------ replay

    /// What a page that starts over draws: the number the replay follows,
    /// the sequences that bring a clean screen to the modes the stream was
    /// in at that point, and the last of it: REPLAY_BYTES, REPLAY_LINES at
    /// most.
    pub fn snapshot(&self) -> (u64, Vec<u8>, Vec<Event>) {
        let (base, prefix, events, _) = self.snapshot_at();
        (base, prefix, events)
    }

    /// The same, with the bytes of output before the replay.
    fn snapshot_at(&self) -> (u64, Vec<u8>, Vec<Event>, u64) {
        let st = self.lock();
        let events: Vec<Event> = st.events.iter().cloned().collect();
        // From the end back, REPLAY_BYTES and REPLAY_LINES at most. Cut by
        // lines, the replay starts right after a newline, inside an event
        // (`split`, the bytes of it left out); cut by bytes, at an event.
        let (mut start, mut size, mut lines) = (0usize, 0usize, 0usize);
        let mut split: Option<usize> = None;
        for i in (0..events.len()).rev() {
            if let Kind::Out(d) = &events[i].kind {
                let n = d.iter().filter(|b| **b == b'\n').count();
                if lines + n > REPLAY_LINES {
                    let need = REPLAY_LINES - lines;
                    let mut seen = 0usize;
                    let mut at = 0usize;
                    for (j, b) in d.iter().enumerate().rev() {
                        if *b == b'\n' {
                            seen += 1;
                            if seen == need + 1 {
                                at = j + 1;
                                break;
                            }
                        }
                    }
                    start = i;
                    split = Some(at);
                    break;
                }
                size += d.len();
                if size > REPLAY_BYTES {
                    start = i + 1;
                    break;
                }
                lines += n;
            }
        }
        let mut modes = st.base_modes.clone();
        for e in &events[..start] {
            if let Kind::Out(d) = &e.kind {
                modes.feed(d);
            }
        }
        let mut events = events[start..].to_vec();
        let base = events.first().map(|e| e.seq - 1).unwrap_or(st.last_seq);
        let base_pos = match events.first() {
            Some(Event { end, kind: Kind::Out(d), .. }) => end - d.len() as u64,
            Some(Event { end, .. }) => *end,
            None => st.out_pos,
        };
        if let Some(at) = split {
            if let Some(Event { seq, end, kind: Kind::Out(first) }) = events.first().cloned() {
                modes.feed(&first[..at]);
                events[0] = Event { seq, end, kind: Kind::Out(Arc::from(first[at..].to_vec())) };
            }
        } else if st.trimmed || start > 0 {
            if let Some(Event { seq, end, kind: Kind::Out(first) }) = events.first().cloned() {
                // The replay may start inside a line or an escape sequence:
                // it starts at the next line instead.
                let look = &first[..first.len().min(4096)];
                if let Some(nl) = look.iter().position(|b| *b == b'\n') {
                    modes.feed(&first[..=nl]);
                    events[0] = Event { seq, end, kind: Kind::Out(Arc::from(first[nl + 1..].to_vec())) };
                }
            }
        }
        (base, modes.restore(), events, base_pos)
    }

    /// Everything after the number `seq`; Err when that is no longer kept.
    pub fn events_after(&self, seq: u64) -> Result<Vec<Event>, ()> {
        let st = self.lock();
        if seq + 1 < st.first_seq {
            return Err(());
        }
        let skip = (seq + 1 - st.first_seq) as usize;
        Ok(st.events.iter().skip(skip).cloned().collect())
    }

    /// The bytes of output up to the end of event `seq`, as far as kept.
    fn pos_after(&self, seq: u64) -> u64 {
        let st = self.lock();
        if seq + 1 < st.first_seq || st.events.is_empty() {
            return st.out_pos;
        }
        if seq + 1 == st.first_seq {
            return match st.events.front() {
                Some(Event { end, kind: Kind::Out(d), .. }) => end - d.len() as u64,
                Some(e) => e.end,
                None => st.out_pos,
            };
        }
        let at = (seq - st.first_seq) as usize;
        st.events.get(at).map(|e| e.end).unwrap_or(st.out_pos)
    }

    pub fn range(&self) -> (u64, u64) {
        let st = self.lock();
        (st.first_seq, st.last_seq)
    }

    // ------------------------------------------------------------ end

    /// Ends the terminal: the shell gets a hangup, as when a window closes.
    /// `reason` is what the terminal then says.
    pub async fn close(self: &Arc<Self>, reason: &str) {
        let pty = {
            let mut st = self.lock();
            if st.state == State::Ended {
                return;
            }
            st.closing = Some(reason.to_string());
            st.closing_at.get_or_insert_with(Instant::now);
            st.pty.clone()
        };
        match pty {
            None => {
                // Not up yet: it never will be.
                let why = if reason == "Closed." { "Closed before it opened." } else { reason };
                self.end(why.to_string(), None);
            }
            Some(pty) => {
                pty.hangup();
                // The pump ends the terminal once the shell is gone. One that
                // ignores the hangup is killed HANGUP_GRACE after it; should
                // even its end not come in a moment, the terminal ends
                // without it.
                let mut done = self.done.subscribe();
                if tokio::time::timeout(HANGUP_GRACE, done.wait_for(|d| *d)).await.is_err() {
                    pty.kill();
                    if tokio::time::timeout(KILL_WAIT, done.wait_for(|d| *d)).await.is_err() {
                        self.end(reason.to_string(), None);
                    }
                }
            }
        }
    }

    fn end(&self, reason: String, code: Option<i32>) {
        let (last_seq, shell, home) = {
            let mut st = self.lock();
            if st.state == State::Ended {
                return;
            }
            // A command still running ended with the shell.
            if st.block.is_some() {
                self.finish_block(&mut st, code.map(i64::from));
            }
            st.state = State::Ended;
            st.reason = Some(reason.clone());
            st.exit_code = code;
            st.ended_at = Some(Instant::now());
            // Dropping it lets the reader and writer go; the terminal closes
            // with the last of them.
            st.pty = None;
            st.pending.clear();
            (st.last_seq, st.shell.clone(), st.home.clone())
        };
        self.store.ended(&self.id.to_string(), last_seq, &reason, shell.as_deref(), &home);
        self.changed();
        self.done.send_replace(true);
    }

    async fn start(self: Arc<Self>, planner: impl Future<Output = Plan>, env: Vec<(String, String)>, cwd: std::path::PathBuf) {
        // How to start it (the scripts in place, the shells looked up), and
        // meanwhile the size of the window, or the guess a second later.
        let mut sized = self.sized.subscribe();
        let size = async {
            let _ = tokio::time::timeout(SIZE_WAIT, sized.wait_for(|s| *s)).await;
        };
        let (plan, ()) = tokio::join!(planner, size);
        if self.state() == State::Ended {
            return;
        }
        let (cols, rows, machine) = {
            let st = self.lock();
            (st.cols, st.rows, st.place.machine.clone())
        };
        let started = match pty::spawn(&plan.argv, &env, &cwd, cols, rows, !plan.markers) {
            Ok(s) => s,
            Err(e) => {
                self.end(format!("Could not open a terminal on {machine}: {e}"), None);
                return;
            }
        };
        let pty = Arc::new(started.pty);
        let mut output = started.output;
        {
            let mut st = self.lock();
            if st.closing.is_some() {
                drop(st);
                pty.hangup();
                self.end("Closed before it opened.".into(), None);
                return;
            }
            st.shell = Some(plan.shell.clone());
            // Markers once the first one comes; blocks as planned.
            st.markers = false;
            st.blocks = plan.blocks;
            st.home = cwd.to_string_lossy().to_string();
            // The key first, with echo off: the shell reads it, then turns
            // echo back on.
            if plan.markers {
                pty.write(format!("{}\n", st.key).as_bytes());
            }
            let pending = std::mem::take(&mut st.pending);
            if !pending.is_empty() {
                pty.write(&pending);
            }
            st.pty = Some(pty.clone());
            st.state = State::Open;
        }
        self.changed();

        while let Some(data) = output.recv().await {
            self.room().await;
            self.take(data);
        }
        {
            let mut st = self.lock();
            let held = st.parser.flush();
            if !held.is_empty() {
                Self::output(&mut st, held);
            }
        }
        self.changed();

        // The stream is over: the shell ended, or was hung up on. Hung up
        // on purpose, it has HANGUP_GRACE from the hangup, then a kill, as
        // README promises; otherwise it gets a hangup of its own first.
        let hung_up = self.lock().closing_at;
        let code = match hung_up {
            Some(at) => match pty.wait(HANGUP_GRACE.saturating_sub(at.elapsed())).await {
                Some(code) => code,
                None => {
                    pty.kill();
                    pty.wait(HANGUP_GRACE).await.flatten()
                }
            },
            None => match pty.wait(HANGUP_GRACE).await {
                Some(code) => code,
                None => {
                    pty.hangup();
                    match pty.wait(HANGUP_GRACE).await {
                        Some(code) => code,
                        None => {
                            pty.kill();
                            pty.wait(HANGUP_GRACE).await.flatten()
                        }
                    }
                }
            },
        };
        let closing = self.lock().closing.clone();
        let reason = match (closing, code) {
            (Some(why), _) => why,
            (None, Some(code)) => format!("The shell ended with code {code}."),
            (None, None) => "The shell was ended by a signal.".to_string(),
        };
        self.end(reason, code);
    }
}

fn label_of(st: &Inner) -> String {
    if st.name == "1" {
        st.place.label()
    } else {
        format!("{} · {}", st.place.label(), st.name)
    }
}

fn describe(id: Uuid, st: &Inner) -> Value {
    json!({
        "id": id.to_string(),
        "machineId": st.place.machine_id.to_string(),
        "machine": st.place.machine,
        "label": label_of(st),
        "name": st.name,
        "state": st.state.as_str(),
        "reason": st.reason,
        "away": false,
        "awaySince": Value::Null,
        "shell": st.shell,
        "markers": st.markers,
        "blocks": st.blocks,
        "cwd": st.cwd,
        "home": st.home,
        "branch": st.branch,
        "venv": st.venv,
        "running": running_of(st),
        "openedAt": iso_seconds(st.opened_ms),
    })
}

/// The command running now.
fn running_of(st: &Inner) -> Option<Value> {
    st.block.as_ref().map(|b| {
        json!({"command": b.command, "cwd": b.cwd, "branch": b.branch, "seqStart": b.seq_start, "cols": b.cols, "at": b.started_ms})
    })
}

/// An exit code as the shell wrote it: digits, or nothing.
fn code_of(text: &str) -> Option<i64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// A command as the question at quitting names it: its first line, short.
pub fn short_command(command: &str) -> String {
    let line = command.trim().lines().next().unwrap_or("").trim();
    let many = command.trim().lines().count() > 1;
    let mut short: String = line.chars().take(40).collect();
    if many || line.chars().count() > 40 {
        short = short.trim_end().to_string();
        short.push('…');
    }
    short
}

/// A command from the page as it will be typed: lines joined by \n, control
/// characters out. Escape above all: it could end the bracketed paste the
/// command is wrapped in and type keys of its own.
pub fn clean_command(command: &str) -> String {
    let text = command.replace("\r\n", "\n").replace('\r', "\n");
    let text = text.trim_matches('\n');
    text.chars()
        .filter(|&c| !matches!(c as u32, 0x00..=0x08 | 0x0b..=0x1f | 0x7f))
        .collect()
}

/// A terminal's name as its owner gives it: one line, 1 to 40 characters.
pub fn clean_name(name: &str) -> Option<String> {
    let name = crate::names::one_line(name);
    let len = name.chars().count();
    (1..=NAME_MAX).contains(&len).then_some(name)
}

// ------------------------------------------------------------- terminals

pub struct Terminals {
    live: Mutex<HashMap<Uuid, Arc<Terminal>>>,
    opening: tokio::sync::Mutex<()>,
    pub store: Arc<Store>,
}

impl Terminals {
    pub fn new(store: Arc<Store>) -> Self {
        Self { live: Mutex::new(HashMap::new()), opening: tokio::sync::Mutex::new(()), store }
    }

    /// A new terminal on this computer. It starts in the background, as
    /// `plan` says once it is ready; the page attaches to it over the
    /// socket and watches it come up.
    #[allow(clippy::too_many_arguments)]
    pub async fn open(&self, place: Place, plan: impl Future<Output = Plan> + Send + 'static, env: Vec<(String, String)>, cwd: std::path::PathBuf, cols: i64, rows: i64, most: usize) -> Result<Arc<Terminal>, String> {
        let _one_at_a_time = self.opening.lock().await;
        let count = self.live().len();
        if count >= most {
            return Err(format!("You have {count} terminals open, and this app allows {most}. End one to open another."));
        }
        let name = {
            let live = self.live.lock().unwrap();
            let used: Vec<String> = live
                .values()
                .filter_map(|t| {
                    let st = t.lock();
                    (st.place.machine_id == place.machine_id && st.state != State::Ended).then(|| st.name.clone())
                })
                .collect();
            (1..).map(|n: u32| n.to_string()).find(|n| !used.contains(n)).expect("a free number")
        };
        let (cols, rows) = pty::clamp_size(cols, rows);
        let terminal = Terminal::new(place, name.clone(), cols, rows, self.store.clone());
        self.store.opened(&terminal.id.to_string(), &name, terminal.lock().opened_ms);
        self.live.lock().unwrap().insert(terminal.id, terminal.clone());
        tokio::spawn(terminal.clone().start(plan, env, cwd));
        Ok(terminal)
    }

    pub fn get(&self, id: &Uuid) -> Option<Arc<Terminal>> {
        self.live.lock().unwrap().get(id).cloned()
    }

    /// The terminals that have not ended, the oldest first.
    pub fn live(&self) -> Vec<Arc<Terminal>> {
        let mut list: Vec<Arc<Terminal>> = self
            .live
            .lock()
            .unwrap()
            .values()
            .filter(|t| t.state() != State::Ended)
            .cloned()
            .collect();
        list.sort_by_key(|t| t.lock().opened_ms);
        list
    }

    /// The machine's name or the project's code changed: labels follow.
    pub fn retag(&self, machine: Option<&str>, code: Option<&str>) {
        for t in self.live.lock().unwrap().values() {
            {
                let mut st = t.lock();
                if let Some(m) = machine {
                    st.place.machine = m.to_string();
                }
                if let Some(c) = code {
                    st.place.code = c.to_string();
                }
            }
            t.changed();
        }
    }

    /// This computer is another machine now (from 0.3.0): the one it is in
    /// tTerm once signed in, its own again once signed out. Its terminals
    /// follow, and their pages learn it.
    pub fn move_to(&self, place: &Place) {
        for t in self.live.lock().unwrap().values() {
            let changed = {
                let mut st = t.lock();
                let changed = st.place.machine_id != place.machine_id || st.place.machine != place.machine || st.place.code != place.code;
                if changed {
                    st.place = place.clone();
                }
                changed
            };
            if changed {
                t.changed();
            }
        }
    }

    pub fn rename(&self, id: &Uuid, name: &str) -> Result<Arc<Terminal>, (u16, String)> {
        let Some(t) = self.get(id) else { return Err((404, "no such terminal".into())) };
        if t.state() == State::Ended {
            return Err((409, "The terminal is not running any more.".into()));
        }
        let Some(cleaned) = clean_name(name) else {
            return Err((422, format!("Name the terminal: up to {NAME_MAX} characters.")));
        };
        if cleaned.chars().all(|c| c.is_ascii_digit()) {
            return Err((422, "A name needs a letter in it: numbers alone are how tTerm counts terminals.".into()));
        }
        let renamed = {
            let mut st = t.lock();
            let renamed = st.name != cleaned;
            if renamed {
                st.name = cleaned.clone();
            }
            renamed
        };
        if renamed {
            self.store.renamed(&t.id.to_string(), &cleaned);
            t.changed();
        }
        Ok(t)
    }

    /// Ended terminals stay a while, so pages can show how they ended.
    pub fn sweep(&self) {
        self.live.lock().unwrap().retain(|_, t| {
            let st = t.lock();
            match st.ended_at {
                Some(at) => at.elapsed() < KEEP_ENDED,
                None => true,
            }
        });
    }

    /// Ends them all: the app is quitting.
    pub async fn stop_all(&self, reason: &str) {
        let all: Vec<Arc<Terminal>> = self.live.lock().unwrap().values().cloned().collect();
        let mut tasks = Vec::new();
        for t in &all {
            let (t, reason) = (t.clone(), reason.to_string());
            tasks.push(tokio::spawn(async move { t.close(&reason).await }));
        }
        let deadline = tokio::time::Instant::now() + QUIT_WAIT;
        for task in tasks {
            let _ = tokio::time::timeout_at(deadline, task).await;
        }
        // A shell that has not ended by now ignores its hangup: it is
        // killed sooner than the three seconds a closed terminal gives it,
        // and its terminal ends here, with the command it was running, as
        // the core ends its terminals when it stops.
        for t in &all {
            let pty = t.lock().pty.clone();
            if let Some(pty) = pty {
                pty.kill();
            }
            t.end(reason.to_string(), None);
        }
        // What expired goes from the file before the app does, also after a
        // run too short for the sweep in the background; then the last of
        // the blocks, on the disk before the app goes.
        self.store.sweep();
        self.store.flush(Duration::from_secs(1)).await;
    }

    /// What would stop if every terminal ended now, by terminal: the
    /// command running, or, in a shell without markers, the program in
    /// front of it.
    pub fn busy(&self) -> Vec<(String, String)> {
        self.live()
            .iter()
            .filter_map(|t| {
                let (label, pgrp, running) = {
                    let st = t.lock();
                    // bash with its history off marks a command without
                    // its text: then the program in front names it.
                    match st.block.as_ref().map(|b| short_command(&b.command)) {
                        Some(command) if !command.is_empty() => return Some((label_of(&st), command)),
                        running => (label_of(&st), st.pty.as_ref().and_then(|p| p.foreground()), running.is_some()),
                    }
                };
                let name = match pgrp {
                    Some(pgrp) => pty::process_name(pgrp).unwrap_or_else(|| "a program".to_string()),
                    None if running => "a command".to_string(),
                    None => return None,
                };
                Some((label, name))
            })
            .collect()
    }
}

// ------------------------------------------------------------- watching

/// What goes to the page's socket: text (JSON) or a binary frame.
#[derive(Debug, Clone)]
pub enum Outgoing {
    Text(String),
    Binary(Vec<u8>),
}

pub fn output_frame(channel: u32, seq: u64, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(13 + data.len());
    frame.push(OUTPUT);
    frame.extend_from_slice(&channel.to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

static WATCHERS: AtomicU64 = AtomicU64::new(1);

/// One page's view of one terminal, over that page's socket.
///
/// It sends what the page has not seen yet, in order, at the page's pace:
/// the page pauses it when it has more to draw than it can, and resumes it
/// when it caught up. If it falls so far behind that the oldest of what it
/// needs is no longer kept, it starts over from what is kept.
///
/// Of several pages on one terminal, only the active one types: the one the
/// person last clicked into. The page's terminal answers questions programs
/// ask it (where is the cursor, what colours), and two pages would answer
/// twice; in vim, a second answer reads as keys.
pub struct Watcher {
    pub id: u64,
    pub terminal: Arc<Terminal>,
    resume: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Watcher {
    pub fn start(terminal: Arc<Terminal>, channel: u32, out: mpsc::Sender<Outgoing>, after: Option<u64>) -> Watcher {
        let id = WATCHERS.fetch_add(1, Ordering::SeqCst);
        {
            let mut st = terminal.lock();
            if st.active.is_none() {
                st.active = Some(id);
            }
        }
        let (resume, resume_rx) = watch::channel(true);
        terminal.watch(id);
        let t = terminal.clone();
        let task = tokio::spawn(async move {
            let mut w = Watching { id, t, channel, out, sent: 0, state_sent: None, resume: resume_rx };
            let _ = w.run(after).await;
            w.t.forget(id);
        });
        Watcher { id, terminal, resume, task }
    }

    pub fn focus(&self) {
        self.terminal.lock().active = Some(self.id);
    }

    pub fn write(&self, data: &[u8]) {
        let mine = {
            let mut st = self.terminal.lock();
            if st.active.is_none() {
                st.active = Some(self.id);
            }
            st.active == Some(self.id)
        };
        if mine {
            self.terminal.write(data);
        }
    }

    pub fn pause(&self) {
        self.resume.send_replace(false);
        self.terminal.paused(self.id, true);
    }

    pub fn resume(&self) {
        self.resume.send_replace(true);
        self.terminal.paused(self.id, false);
    }

    pub fn stop(self) {
        drop(self);
    }
}

/// However a watcher goes, its page no longer types, and its sending stops.
impl Drop for Watcher {
    fn drop(&mut self) {
        {
            let mut st = self.terminal.lock();
            if st.active == Some(self.id) {
                st.active = None;
            }
        }
        self.task.abort();
        self.terminal.forget(self.id);
    }
}

struct Watching {
    id: u64,
    t: Arc<Terminal>,
    channel: u32,
    out: mpsc::Sender<Outgoing>,
    sent: u64,
    state_sent: Option<(String, Option<String>, bool, Option<String>, String)>,
    resume: watch::Receiver<bool>,
}

type Gone = ();

impl Watching {
    async fn json(&self, message: Value) -> Result<(), Gone> {
        self.out.send(Outgoing::Text(message.to_string())).await.map_err(|_| ())
    }

    async fn frame(&self, seq: u64, data: &[u8]) -> Result<(), Gone> {
        self.out.send(Outgoing::Binary(output_frame(self.channel, seq, data))).await.map_err(|_| ())
    }

    async fn run(&mut self, after: Option<u64>) -> Result<(), Gone> {
        let mut version = self.t.subscribe();
        let (first, last) = self.t.range();
        match after {
            Some(after) if first.saturating_sub(1) <= after && after <= last => {
                self.sent = after;
                let pos = self.t.pos_after(after);
                self.t.seen(self.id, pos, true);
                self.json(json!({"op": "attached", "ch": self.channel, "terminal": self.t.describe(), "resumed": true})).await?;
                // What came since, then the mark that it is all old news:
                // the page's terminal must not answer questions programs
                // asked in it, as on a replay.
                match self.t.events_after(self.sent) {
                    Err(()) => self.replay().await?,
                    Ok(new) => {
                        if !new.is_empty() {
                            self.events(new).await?;
                        }
                        self.json(json!({"op": "replayed", "ch": self.channel, "seq": self.sent})).await?;
                    }
                }
            }
            _ => {
                self.json(json!({"op": "attached", "ch": self.channel, "terminal": self.t.describe(), "resumed": false})).await?;
                self.replay().await?;
            }
        }
        loop {
            version.borrow_and_update();
            if self.resume.wait_for(|on| *on).await.is_err() {
                return Err(());
            }
            let (first, _) = self.t.range();
            if self.sent + 1 < first {
                self.replay().await?;
                continue;
            }
            match self.t.events_after(self.sent) {
                Err(()) => {
                    self.replay().await?;
                    continue;
                }
                Ok(new) if !new.is_empty() => {
                    self.events(new).await?;
                    continue;
                }
                Ok(_) => {}
            }
            self.state().await?;
            if version.changed().await.is_err() {
                return Err(());
            }
        }
    }

    async fn replay(&mut self) -> Result<(), Gone> {
        let (base, prefix, events, base_pos) = self.t.snapshot_at();
        self.t.seen(self.id, base_pos, true);
        // The replay may begin inside a command, after its start marker:
        // the feed needs to know which, to put its output under it.
        let running = self.t.block_at(base);
        self.json(json!({"op": "reset", "ch": self.channel, "seq": base, "running": running})).await?;
        if !prefix.is_empty() {
            self.frame(base, &prefix).await?;
        }
        self.sent = base;
        self.events(events).await?;
        // The page draws history now, not live output: whatever its terminal
        // answers to old questions in it must not reach the shell.
        self.json(json!({"op": "replayed", "ch": self.channel, "seq": self.sent})).await?;
        if self.t.lock().modes.alt_screen() {
            self.t.nudge();
        }
        Ok(())
    }

    async fn events(&mut self, events: Vec<Event>) -> Result<(), Gone> {
        let mut run: Vec<u8> = Vec::new();
        let mut seq = self.sent;
        let mut pos = 0u64;
        for e in events {
            match e.kind {
                Kind::Out(data) => {
                    // Whole events in a frame, as the core sends them: the
                    // number on a frame says all of it is there.
                    if !run.is_empty() && run.len() + data.len() > FRAME_MAX {
                        self.frame(seq, &run).await?;
                        self.sent = seq;
                        self.t.seen(self.id, pos, false);
                        run.clear();
                    }
                    run.extend_from_slice(&data);
                    seq = e.seq;
                    pos = e.end;
                }
                Kind::Ev(value) => {
                    if !run.is_empty() {
                        self.frame(seq, &run).await?;
                        self.sent = seq;
                        self.t.seen(self.id, pos, false);
                        run.clear();
                    }
                    let mut message = json!({"op": "ev", "ch": self.channel, "seq": e.seq});
                    if let (Some(m), Value::Object(fields)) = (message.as_object_mut(), value) {
                        for (k, v) in fields {
                            m.insert(k, v);
                        }
                    }
                    self.json(message).await?;
                    seq = e.seq;
                    self.sent = e.seq;
                    pos = e.end;
                    self.t.seen(self.id, pos, false);
                }
            }
        }
        if !run.is_empty() {
            self.frame(seq, &run).await?;
            self.sent = seq;
            self.t.seen(self.id, pos, false);
        }
        Ok(())
    }

    async fn state(&mut self) -> Result<(), Gone> {
        let now = {
            let st = self.t.lock();
            (st.state.as_str().to_string(), st.reason.clone(), st.markers, st.shell.clone(), label_of(&st))
        };
        if self.state_sent.as_ref() != Some(&now) {
            self.state_sent = Some(now);
            self.json(json!({"op": "state", "ch": self.channel, "terminal": self.t.describe()})).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_dates() {
        assert_eq!(iso_seconds(0), "1970-01-01T00:00:00+00:00");
        assert_eq!(iso_seconds(1_760_000_000_000), "2025-10-09T08:53:20+00:00");
    }

    #[test]
    fn commands_are_cleaned() {
        assert_eq!(clean_command("ls\r\n-la\x1b[201~"), "ls\n-la[201~");
        assert_eq!(clean_command("\n\necho hi\n"), "echo hi");
        assert_eq!(clean_command("a\tb"), "a\tb");
    }

    #[test]
    fn frames() {
        let f = output_frame(7, 42, b"hi");
        assert_eq!(f, vec![1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 42, b'h', b'i']);
    }

    #[test]
    fn commands_are_named_short() {
        assert_eq!(short_command("sleep 30"), "sleep 30");
        assert_eq!(short_command("  make\nmake install"), "make…");
        assert_eq!(short_command(&"x".repeat(50)), format!("{}…", "x".repeat(40)));
        assert_eq!(short_command(""), "");
        assert_eq!(code_of("130"), Some(130));
        assert_eq!(code_of(""), None);
        assert_eq!(code_of("-1"), None);
    }

    fn terminal() -> (Arc<Terminal>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("tterm-terminal-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let place = Place { machine_id: Uuid::new_v4(), machine: "vm".into(), code: "P".into() };
        let t = Terminal::new(place, "1".into(), 80, 24, Store::open(&dir));
        t.store.opened(&t.id.to_string(), "1", 0);
        (t, dir)
    }

    fn mark(t: &Terminal, fields: &[&str]) -> Vec<u8> {
        format!("\x1b]6973;{};{}\x07", t.lock().key, fields.join(";")).into_bytes()
    }

    #[tokio::test]
    async fn a_replay_knows_the_command_it_starts_in() {
        let (t, dir) = terminal();
        t.take(mark(&t, &["P", "0", "/h", "/h", "", "", "/bin"]));
        t.take(mark(&t, &["C", "yes", "0"]));
        let start = t.range().1;
        assert_eq!(t.running().unwrap()["command"], "yes");
        assert_eq!(t.describe()["running"]["seqStart"], start);
        for _ in 0..5 {
            t.take(b"y\r\ny\r\n".to_vec());
        }
        let inside = t.range().1 - 2;
        assert_eq!(t.block_at(inside).unwrap()["command"], "yes", "running: inside it");
        t.take(mark(&t, &["P", "130", "/h", "/h", "", "", "/bin"]));
        let end = t.range().1;
        let got = t.block_at(inside).unwrap();
        assert_eq!(got["seqStart"], start);
        assert_eq!(got["command"], "yes");
        assert!(t.block_at(end).is_none(), "the prompt after it is not inside it");
        assert!(t.block_at(start - 1).is_none());
        assert!(t.running().is_none());
        // The block, in the store, as the stream had it.
        let feed = t.store.feed(&t.id.to_string(), None, 60).await.unwrap();
        let block = &feed["blocks"][0];
        assert_eq!(block["command"], "yes");
        assert_eq!(block["exitCode"], 130);
        assert_eq!(block["seqStart"], start);
        assert_eq!(block["seqEnd"], end - 1);
        assert_eq!(block["cwd"], "/h");
        assert_eq!(t.store.block_output(&t.id.to_string(), start as i64).await.unwrap().0, b"y\r\ny\r\n".repeat(5));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn markers_become_events_and_others_pass() {
        let (t, dir) = terminal();
        let mut data = b"before".to_vec();
        data.extend(mark(&t, &["P", "0", "/w%3Bx", "/h", "main", "venv", "/bin:/usr/bin"]));
        data.extend_from_slice(b"\x1b]6973;0000;P;9\x07after");
        t.take(data);
        let events = t.events_after(0).unwrap();
        let kinds: Vec<String> = events
            .iter()
            .map(|e| match &e.kind {
                Kind::Out(d) => String::from_utf8_lossy(d).to_string(),
                Kind::Ev(v) => format!("ev:{}", v["t"].as_str().unwrap()),
            })
            .collect();
        assert_eq!(kinds.concat(), "beforeev:P\x1b]6973;0000;P;9\x07after");
        let Kind::Ev(p) = &events[1].kind else { panic!("{kinds:?}") };
        assert_eq!(p["cwd"], "/w;x");
        assert_eq!(p["branch"], "main");
        assert_eq!(p["venv"], "venv");
        assert_eq!(p["code"], 0);
        assert_eq!(p["trim"], 0);
        assert_eq!(events[1].end, 6, "an event's place in the output");
        let st = t.lock();
        assert!(st.markers);
        assert_eq!((st.cwd.as_str(), st.home.as_str(), st.path.as_str()), ("/w;x", "/h", "/bin:/usr/bin"));
        drop(st);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
