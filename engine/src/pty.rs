//! A shell on this computer, in a pseudo-terminal of its own.
//!
//! The same way tterm-agent starts tTerm Web's shells (`Shell.start_web` in
//! agent.py), and for the same reasons:
//!
//! - the login shell runs the command with `-c`, the way sshd runs one, in
//!   a clean environment made the way sshd makes one: not the app's own,
//!   which macOS gives a GUI app almost empty;
//! - the size and the echo are set on the terminal before the shell exists:
//!   set later, they race whatever is typed first;
//! - the shell gets a session of its own, with this terminal as its
//!   controlling terminal, and the signals Rust ignores for itself are back
//!   to normal in it (std does that for SIGPIPE when it spawns);
//! - writes never block: a program that reads nothing holds only the writer
//!   thread, which waits for the terminal to take more;
//! - once the shell has ended, its output is read on until the first pause
//!   (half a second), ten seconds at most: a program left in the background
//!   may hold the terminal open for good;
//! - closing sends a hangup, as closing a terminal window does; a shell that
//!   ignores it is killed three seconds later (see Terminal::close).

use nix::pty::{openpty, Winsize};
use nix::sys::signal::{kill, Signal};
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg};
use nix::unistd::Pid;
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

/// What one read takes at most.
pub const READ_CHUNK: usize = 32 * 1024;
/// How long a reader or writer waits at a time before it looks whether it
/// should stop.
const POLL: Duration = Duration::from_millis(500);
/// After the shell ended: output is read on until a pause this long...
const DRAIN_GAP: Duration = Duration::from_millis(500);
/// ...and never longer than this.
const DRAIN_MAX: Duration = Duration::from_secs(10);

pub const MIN_COLS: u16 = 10;
pub const MAX_COLS: u16 = 1000;
pub const MIN_ROWS: u16 = 3;
pub const MAX_ROWS: u16 = 500;

pub fn clamp_size(cols: i64, rows: i64) -> (u16, u16) {
    (
        cols.clamp(MIN_COLS as i64, MAX_COLS as i64) as u16,
        rows.clamp(MIN_ROWS as i64, MAX_ROWS as i64) as u16,
    )
}

/// The person's login shell, the one sshd would start: from SHELL, or from
/// the account database when the app was started with none (macOS gives a
/// GUI app no SHELL at times).
pub fn login_shell() -> String {
    if let Ok(shell) = std::env::var("SHELL") {
        if !shell.is_empty() && std::path::Path::new(&shell).is_file() {
            return shell;
        }
    }
    if let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::getuid()) {
        let shell = user.shell.to_string_lossy().to_string();
        if !shell.is_empty() && std::path::Path::new(&shell).is_file() {
            return shell;
        }
    }
    "/bin/sh".to_string()
}

pub fn home_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home);
        }
    }
    if let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::getuid()) {
        return user.dir;
    }
    PathBuf::from("/")
}

/// A plain PATH, as sshd gives one; the login shell builds the person's own
/// from there. On a Mac with Apple silicon Homebrew lives in /opt/homebrew,
/// which tTerm's scripts, run by sh without a profile, need as well.
pub fn plain_path() -> String {
    let mut dirs: Vec<&str> = Vec::new();
    if cfg!(target_os = "macos") {
        for d in ["/opt/homebrew/bin", "/opt/homebrew/sbin"] {
            if std::path::Path::new(d).is_dir() {
                dirs.push(d);
            }
        }
    }
    dirs.extend(["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]);
    dirs.join(":")
}

/// A clean environment for the shells and scripts, made the way sshd makes
/// one: who, where, a plain PATH and the locale. Without a locale the shell
/// would read every non-ASCII letter as separate bytes, so a UTF-8 one is
/// set when none is given.
pub fn clean_env(terminal: bool) -> Vec<(String, String)> {
    let user = nix::unistd::User::from_uid(nix::unistd::getuid()).ok().flatten();
    let name = user
        .as_ref()
        .map(|u| u.name.clone())
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_default();
    let mut env = vec![
        ("HOME".to_string(), home_dir().to_string_lossy().to_string()),
        ("USER".to_string(), name.clone()),
        ("LOGNAME".to_string(), name),
        ("SHELL".to_string(), login_shell()),
        ("PATH".to_string(), plain_path()),
    ];
    let mut locale = false;
    for key in ["LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "SSH_AUTH_SOCK"] {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() {
                if key.starts_with("L") {
                    locale = true;
                }
                env.push((key.to_string(), value));
            }
        }
    }
    if !locale {
        let lang = if cfg!(target_os = "macos") { "en_US.UTF-8" } else { "C.UTF-8" };
        env.push(("LANG".to_string(), lang.to_string()));
    }
    if terminal {
        env.push(("TERM".to_string(), "xterm-256color".to_string()));
        env.push(("COLORTERM".to_string(), "truecolor".to_string()));
        env.push(("TERM_PROGRAM".to_string(), "tTerm".to_string()));
        env.push(("TERM_PROGRAM_VERSION".to_string(), crate::VERSION.to_string()));
    }
    env
}

/// How the shell ended: its exit code, or None when a signal ended it.
#[derive(Debug, Default)]
struct End {
    at: Option<Instant>,
    code: Option<i32>,
    done: bool,
}

/// A running shell. Dropping it leaves the shell be; `hangup` ends it.
pub struct Pty {
    pid: i32,
    master: Arc<OwnedFd>,
    /// Keys go to the writer thread, in order.
    keys: std_mpsc::Sender<Vec<u8>>,
    /// Set once the terminal is over: its reader and writer let go.
    stopping: Arc<AtomicBool>,
    end: Arc<Mutex<End>>,
    exited: Mutex<Option<oneshot::Receiver<Option<i32>>>>,
}

pub struct Started {
    pub pty: Pty,
    /// What the shell prints, a piece at a time, until it is over.
    pub output: mpsc::Receiver<Vec<u8>>,
}

fn winsize(cols: u16, rows: u16) -> Winsize {
    Winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 }
}

fn cloexec(fd: &OwnedFd) -> io::Result<()> {
    let raw = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Marks every descriptor from `low` up close-on-exec: nothing of the app's
/// reaches the shell, neither what WebKit or the system keep open nor the
/// pseudo-terminal of another terminal started at the same moment. Marked,
/// not closed: std's own pipe for a failed exec lives there (and is marked
/// already). Runs in the child between fork and exec, so only calls that
/// are safe there.
unsafe fn close_on_exec_from(low: i32) {
    #[cfg(target_os = "linux")]
    {
        // close_range(2), since Linux 5.11; the loop below otherwise.
        if libc::syscall(libc::SYS_close_range, low as libc::c_uint, libc::c_uint::MAX, libc::CLOSE_RANGE_CLOEXEC) == 0 {
            return;
        }
    }
    let top = libc::getdtablesize().clamp(low, 1 << 16);
    for fd in low..top {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

fn nonblocking(fd: &OwnedFd) -> io::Result<()> {
    let raw = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Starts `argv` in a new pseudo-terminal of `cols` × `rows`, in `cwd`, with
/// exactly `env`. `echo` false starts the terminal with echo off, for a key
/// typed into it first.
pub fn spawn(argv: &[String], env: &[(String, String)], cwd: &std::path::Path, cols: u16, rows: u16, echo: bool) -> io::Result<Started> {
    if argv.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "nothing to run"));
    }
    let pair = openpty(Some(&winsize(cols, rows)), None).map_err(io::Error::from)?;
    let (master, slave) = (pair.master, pair.slave);
    // Neither end may outlive the exec in the shell, nor leak into the
    // shells of other terminals started later.
    cloexec(&master)?;
    cloexec(&slave)?;
    if !echo {
        let mut attrs = tcgetattr(slave.as_fd()).map_err(io::Error::from)?;
        attrs.local_flags.remove(LocalFlags::ECHO);
        tcsetattr(slave.as_fd(), SetArg::TCSANOW, &attrs).map_err(io::Error::from)?;
    }

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.env_clear();
    cmd.envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    if cwd.is_dir() {
        cmd.current_dir(cwd);
    } else {
        cmd.current_dir("/");
    }
    cmd.stdin(Stdio::from(slave.try_clone()?));
    cmd.stdout(Stdio::from(slave.try_clone()?));
    cmd.stderr(Stdio::from(slave.try_clone()?));
    unsafe {
        cmd.pre_exec(|| {
            // A session of its own, with this terminal (now its stdin) as
            // the controlling terminal.
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            #[allow(clippy::useless_conversion)]
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            // Ignored by the app, not by the shell.
            for sig in [libc::SIGPIPE, libc::SIGXFSZ, libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGCHLD, libc::SIGALRM] {
                libc::signal(sig, libc::SIG_DFL);
            }
            close_on_exec_from(3);
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    drop(slave);
    nonblocking(&master)?;
    let pid = child.id() as i32;
    let master = Arc::new(master);
    let stopping = Arc::new(AtomicBool::new(false));
    let end = Arc::new(Mutex::new(End::default()));

    // The waiter collects the shell's exit status as soon as it ends, so it
    // never lingers as a zombie, and so that the reader knows it ended. It
    // first waits without collecting, then collects and marks it done under
    // the lock `signal` takes: until then the number is still the shell's,
    // and a hangup or a kill cannot reach another process given it since.
    let (exit_tx, exit_rx) = oneshot::channel();
    {
        let end = end.clone();
        thread::Builder::new().name(format!("tterm-wait-{pid}")).spawn(move || {
            loop {
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
                if r == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    break;
                }
            }
            let code = {
                let mut e = end.lock().unwrap();
                let code = match child.wait() {
                    Ok(status) => status.code(),
                    Err(_) => None,
                };
                e.at = Some(Instant::now());
                e.code = code;
                e.done = true;
                code
            };
            let _ = exit_tx.send(code);
        })?;
    }

    // A few reads ahead at most: while the window catches up (see
    // terminals.rs, `room`), the shell itself waits.
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(4);
    {
        let master = master.clone();
        let stopping = stopping.clone();
        let end = end.clone();
        thread::Builder::new().name(format!("tterm-read-{pid}")).spawn(move || read_loop(&master, &out_tx, &stopping, &end))?;
    }

    let (keys_tx, keys_rx) = std_mpsc::channel::<Vec<u8>>();
    {
        let master = master.clone();
        let stopping = stopping.clone();
        thread::Builder::new().name(format!("tterm-write-{pid}")).spawn(move || write_loop(&master, &keys_rx, &stopping))?;
    }

    Ok(Started {
        pty: Pty { pid, master, keys: keys_tx, stopping, end, exited: Mutex::new(Some(exit_rx)) },
        output: out_rx,
    })
}

/// Whether the terminal can be read (or written) within `wait`.
///
/// select, not poll: on macOS poll does not support devices ("The poll()
/// system call currently does not support devices", its manual says), and a
/// pseudo-terminal is one. tterm-agent uses select for the same reason.
fn ready(fd: std::os::fd::RawFd, write: bool, wait: Duration) -> io::Result<bool> {
    if fd < 0 || fd as usize >= libc::FD_SETSIZE as usize {
        // Out of select's reach: look again in a moment, the read itself
        // does not block.
        thread::sleep(Duration::from_millis(10));
        return Ok(true);
    }
    unsafe {
        let mut set: libc::fd_set = std::mem::zeroed();
        libc::FD_ZERO(&mut set);
        libc::FD_SET(fd, &mut set);
        let mut tv = libc::timeval { tv_sec: wait.as_secs() as _, tv_usec: wait.subsec_micros() as _ };
        let none = std::ptr::null_mut();
        let n = if write {
            libc::select(fd + 1, none, &mut set, none, &mut tv)
        } else {
            libc::select(fd + 1, &mut set, none, none, &mut tv)
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                return Ok(false);
            }
            return Err(error);
        }
        Ok(n > 0)
    }
}

fn read_loop(master: &OwnedFd, out: &mpsc::Sender<Vec<u8>>, stopping: &AtomicBool, end: &Mutex<End>) {
    let mut buf = vec![0u8; READ_CHUNK];
    while !stopping.load(Ordering::SeqCst) {
        let ended_at = end.lock().unwrap().at;
        let mut wait = POLL;
        if let Some(at) = ended_at {
            let since = at.elapsed();
            if since >= DRAIN_MAX {
                return;
            }
            wait = DRAIN_GAP.min(DRAIN_MAX - since);
        }
        match ready(master.as_raw_fd(), false, wait) {
            Ok(false) => {
                if let Some(at) = ended_at {
                    if at.elapsed() >= DRAIN_GAP {
                        return;
                    }
                }
                continue;
            }
            Ok(true) => {}
            Err(_) => return,
        }
        let n = unsafe { libc::read(master.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            if out.blocking_send(buf[..n as usize].to_vec()).is_err() {
                return;
            }
        } else if n == 0 {
            return;
        } else {
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                // Linux says EIO once the shell's side is closed.
                _ => return,
            }
        }
    }
}

fn write_loop(master: &OwnedFd, keys: &std_mpsc::Receiver<Vec<u8>>, stopping: &AtomicBool) {
    while let Ok(mut data) = keys.recv() {
        // Whatever else came meanwhile goes in the same write.
        while let Ok(more) = keys.try_recv() {
            data.extend_from_slice(&more);
        }
        let mut at = 0;
        while at < data.len() {
            if stopping.load(Ordering::SeqCst) {
                return;
            }
            let rest = &data[at..];
            let n = unsafe { libc::write(master.as_raw_fd(), rest.as_ptr().cast(), rest.len()) };
            if n >= 0 {
                at += n as usize;
                continue;
            }
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::EAGAIN) => {
                    let _ = ready(master.as_raw_fd(), true, POLL);
                }
                Some(libc::EINTR) => {}
                _ => return,
            }
        }
    }
}

impl Pty {
    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub fn write(&self, data: &[u8]) {
        if !data.is_empty() && !self.stopping.load(Ordering::SeqCst) {
            let _ = self.keys.send(data.to_vec());
        }
    }

    /// The page's size changed: the program in front hears SIGWINCH.
    pub fn resize(&self, cols: u16, rows: u16) {
        let ws = winsize(cols, rows);
        unsafe {
            libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ as _, &ws);
        }
    }

    /// Whether the shell is still running (not yet collected).
    pub fn running(&self) -> bool {
        !self.end.lock().unwrap().done
    }

    fn signal(&self, sig: Signal) {
        // Only while it runs: once collected, its number may belong to
        // another process. The waiter collects it and marks it under the
        // same lock.
        let end = self.end.lock().unwrap();
        if !end.done {
            let _ = kill(Pid::from_raw(self.pid), sig);
        }
    }

    /// A hangup, as when a terminal window closes; the reader and writer
    /// let go.
    pub fn hangup(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        self.signal(Signal::SIGHUP);
    }

    /// For a shell that ignored its hangup.
    pub fn kill(&self) {
        self.signal(Signal::SIGKILL);
    }

    /// Ctrl+C, as a program in front would get it from the keyboard.
    pub fn interrupt_line(&self) {
        self.write(b"\x03");
    }

    /// Waits for the shell to end, at most `timeout`; its code then.
    pub async fn wait(&self, timeout: Duration) -> Option<Option<i32>> {
        {
            let end = self.end.lock().unwrap();
            if end.done {
                return Some(end.code);
            }
        }
        let rx = self.exited.lock().unwrap().take();
        match rx {
            Some(rx) => match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(code)) => Some(code),
                Ok(Err(_)) => {
                    let end = self.end.lock().unwrap();
                    end.done.then_some(end.code)
                }
                Err(_) => {
                    // Not yet: whoever asks next waits on the state.
                    None
                }
            },
            None => {
                let deadline = Instant::now() + timeout;
                while Instant::now() < deadline {
                    {
                        let end = self.end.lock().unwrap();
                        if end.done {
                            return Some(end.code);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                None
            }
        }
    }

    /// The shell's code, once it has ended and been collected.
    pub fn code(&self) -> Option<Option<i32>> {
        let end = self.end.lock().unwrap();
        end.done.then_some(end.code)
    }

    /// The process in front of the terminal, if it is not the shell itself:
    /// what a closing window would stop.
    pub fn foreground(&self) -> Option<i32> {
        let pgrp = unsafe { libc::tcgetpgrp(self.master.as_raw_fd()) };
        (pgrp > 0 && pgrp != self.pid).then_some(pgrp)
    }
}

/// The name of a running process, for what a closing window would stop.
pub fn process_name(pid: i32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }
    #[cfg(not(target_os = "linux"))]
    {
        // As ps shows it: on a Mac, the program's own name.
        let out = std::process::Command::new("/bin/ps").args(["-o", "comm=", "-p", &pid.to_string()]).output().ok()?;
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let name = path.rsplit('/').next().unwrap_or("").trim_start_matches('-').to_string();
        (out.status.success() && !name.is_empty()).then_some(name)
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
    }
}
