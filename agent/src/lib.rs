//! tterm-agent: connects this computer to tTerm Web.
//!
//! Why an agent at all. A laptop cannot be reached from the outside: it has
//! no stable address, it sits behind NAT and it goes to sleep. So the
//! direction is reversed: the agent opens the connection itself and keeps
//! it alive. No port is ever opened on the computer.
//!
//! It is the engine of tTerm's app without its window: the same link to
//! tTerm Web (engine/src/link.rs) and the same shells (engine/src/hosted.rs,
//! pty.rs). It does what agent.py 0.13.0 did for tTerm Web, the same way,
//! and takes its place: the same settings file and key in ~/.tterm-web, the
//! same lines in its log.
//!
//! What it does: starts the shells tTerm Web asks for in pseudo-terminals
//! and passes their bytes both ways; runs, when asked, short sh scripts
//! outside any terminal (Tab, folders and branches, the passport, the
//! scripts of the markers). Anything it can do, so can anyone at this
//! keyboard. What it does not do: open an inbound port; run as root; store
//! passwords or keys other than this computer's own; send anything but what
//! the terminals print and the answers to those scripts. It updates itself
//! to a version only when tTerm's release key signed it, and only while no
//! terminal is open (update.rs).

pub mod update;

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;
use tterm_engine::hosted::Hosted;
use tterm_engine::link::{self, Config, Log, Outcome, Timing};
use update::Trial;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// tTerm Web on its server.
pub const DEFAULT_HUB: &str = "wss://connect.tterm.net/agent";

const USAGE: &str = "usage: tterm-agent [--hub HUB] [--token TOKEN] [--name NAME] [--env-file FILE] [--version]

tTerm's agent: connects this computer to tTerm Web.

  --hub HUB        tTerm Web to connect to (TTERM_HUB, else wss://connect.tterm.net/agent)
  --token TOKEN    the token from Add a machine, then Computer (TTERM_TOKEN)
  --name NAME      this computer's name in tTerm Web (TTERM_NAME, else its own)
  --env-file FILE  read TTERM_HUB, TTERM_TOKEN and the rest from this file
  --version        print the version and exit";

/// A line in the log. The window it ran in may be gone: nowhere to say it
/// then, and that is no reason to stop.
pub fn log(msg: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "[tterm-agent] {msg}");
    let _ = out.flush();
}

/// What the agent runs with.
#[derive(Debug, Clone)]
pub struct Settings {
    pub hub: String,
    pub token: String,
    pub key: String,
    pub name: String,
    /// The settings file it was started with (--env-file), if any.
    pub env_file: Option<PathBuf>,
    /// The environment it was started with, before the settings file was
    /// read into it: a new version starts with it again (update.rs).
    pub launch_env: Vec<(OsString, OsString)>,
    /// A new version on trial (update.rs).
    pub trial: bool,
}

/// To run, or to exit at once with this code.
#[derive(Debug)]
pub enum Start {
    Run(Settings),
    Exit(i32),
}

/// NAME=value lines, as an installer writes them; blank lines and comments
/// are skipped, a later line wins. tTerm Web's installer keeps the token and
/// the key there, readable by this user only, and not in the autostart
/// entry.
pub fn read_env_file(path: &Path) -> std::io::Result<Vec<(String, String)>> {
    let text = std::fs::read_to_string(path)?;
    let mut values: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else { continue };
        let (name, value) = (name.trim().to_string(), value.trim().to_string());
        values.retain(|(n, _)| *n != name);
        values.push((name, value));
    }
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.permissions().mode() & 0o077 != 0 {
            log(&format!(
                "warning: {} can be read by others; it holds this computer's key (chmod 600 it)",
                path.display()
            ));
        }
    }
    Ok(values)
}

/// The computer was removed from tTerm Web: its key goes from the settings
/// file, so that the installer, run again, makes a new one rather than bring
/// back the one it was removed with. The file says the computer was removed,
/// and the agent started with it says so and stops (with success, so that
/// autostart leaves it stopped): left to start, it would join with the token
/// alone, which may still work for a few minutes and is in the shell's
/// history.
pub fn forget_key(path: &Path) {
    let result = (|| -> std::io::Result<bool> {
        let text = std::fs::read_to_string(path)?;
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        if !lines.iter().any(|l| l.starts_with("TTERM_KEY=")) && lines.contains(&"TTERM_REMOVED=1\n") {
            return Ok(false);
        }
        let mut kept = String::new();
        for line in lines.iter().filter(|l| !l.starts_with("TTERM_KEY=") && !l.starts_with("TTERM_REMOVED=")) {
            kept.push_str(line);
            if !line.ends_with('\n') {
                kept.push('\n');
            }
        }
        kept.push_str("TTERM_REMOVED=1\n");
        let mut fresh = path.as_os_str().to_owned();
        fresh.push(".new");
        let fresh = PathBuf::from(fresh);
        let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&fresh)?;
        file.write_all(kept.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&fresh, path)?;
        Ok(true)
    })();
    match result {
        Ok(true) => log("forgot this computer's key: the installer makes a new one"),
        Ok(false) => {}
        Err(e) => log(&format!("could not forget the key in {}: {e}", path.display())),
    }
}

/// The *_proxy variables it was started with: tTerm Web is reached through
/// that proxy, as agent.py reached it (tterm_engine::proxy).
fn proxy_env() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(name, _)| name.to_ascii_lowercase().ends_with("_proxy"))
        .collect()
}

/// Where this agent lives: said to the terminals as TTERM_AGENT_DIR.
pub fn agent_dir() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.to_string_lossy().to_string())
}

/// The uninstaller next to the agent, if an installer put it there
/// (~/.tterm-web); None for an agent started by hand.
fn uninstaller() -> Option<String> {
    let path = PathBuf::from(agent_dir()?).join("uninstall.sh");
    if !path.is_file() {
        return None;
    }
    let shown = path.to_string_lossy().to_string();
    if let Ok(home) = std::env::var("HOME") {
        let home = home.trim_end_matches('/');
        if !home.is_empty() {
            if let Some(rest) = shown.strip_prefix(&format!("{home}/")) {
                return Some(format!("~/{rest}"));
            }
        }
    }
    Some(shown)
}

fn value_of(args: &[String], i: &mut usize, flag: &str) -> Result<Option<String>, String> {
    let arg = &args[*i];
    if arg == flag {
        *i += 1;
        return match args.get(*i) {
            Some(v) => Ok(Some(v.clone())),
            None => Err(format!("argument {flag}: expected one argument")),
        };
    }
    if let Some(v) = arg.strip_prefix(&format!("{flag}=")) {
        return Ok(Some(v.to_string()));
    }
    Ok(None)
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// The command line and the settings file, read the way agent.py read them:
/// the file first, and what it holds becomes the defaults, over whatever the
/// environment it was started from says; flags over both.
pub fn settings(args: Vec<String>) -> Start {
    let launch_env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let usage_error = |why: &str| {
        eprintln!("{}\ntterm-agent: error: {why}", USAGE.lines().next().unwrap_or(""));
        Start::Exit(2)
    };

    let mut env_file: Option<PathBuf> = None;
    let (mut hub, mut token, mut key, mut name) = (None, None, None, None);
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "-h" || arg == "--help" {
            println!("{USAGE}");
            return Start::Exit(0);
        }
        if arg == "--version" {
            println!("{VERSION}");
            return Start::Exit(0);
        }
        let mut matched = false;
        for (flag, slot) in [("--env-file", 0), ("--hub", 1), ("--token", 2), ("--key", 3), ("--name", 4)] {
            match value_of(&args, &mut i, flag) {
                Err(why) => return usage_error(&why),
                Ok(None) => continue,
                Ok(Some(v)) => {
                    match slot {
                        0 => env_file = Some(PathBuf::from(v)),
                        1 => hub = Some(v),
                        2 => token = Some(v),
                        3 => key = Some(v),
                        _ => name = Some(v),
                    }
                    matched = true;
                    break;
                }
            }
        }
        if !matched {
            return usage_error(&format!("unrecognized arguments: {arg}"));
        }
        i += 1;
    }

    if let Some(path) = &env_file {
        let values = match read_env_file(path) {
            Ok(values) => values,
            Err(e) => {
                eprintln!("Could not read {}: {e}", path.display());
                return Start::Exit(1);
            }
        };
        if values.iter().any(|(n, v)| n == "TTERM_REMOVED" && v == "1") {
            // forget_key wrote it: removed in tTerm Web. Not an error, so
            // that autostart leaves the agent stopped.
            log("this computer was removed from tTerm Web: run the installer from Add a machine to connect it again");
            return Start::Exit(0);
        }
        for (n, v) in values {
            if n.starts_with("TTERM_") {
                std::env::set_var(n, v);
            }
        }
    }

    let settings = Settings {
        hub: hub.or_else(|| env("TTERM_HUB")).unwrap_or_else(|| DEFAULT_HUB.to_string()),
        token: token.or_else(|| env("TTERM_TOKEN")).unwrap_or_default(),
        key: key.or_else(|| env("TTERM_KEY")).unwrap_or_default(),
        name: name.or_else(|| env("TTERM_NAME")).unwrap_or_else(tterm_engine::machine::machine_name),
        env_file,
        launch_env,
        trial: false,
    };
    // Read: no program started from here is to see them.
    std::env::remove_var("TTERM_TOKEN");
    std::env::remove_var("TTERM_KEY");

    if settings.token.is_empty() {
        eprintln!("No token given. Get the command from tTerm Web: Add a machine, then Computer.");
        return Start::Exit(1);
    }
    Start::Run(settings)
}

/// The agent itself, where it is: for its updates (update.rs).
fn here() -> Option<PathBuf> {
    std::env::current_exe().and_then(std::fs::canonicalize).ok()
}

/// The start of the agent: `settings`, and before them a new version on
/// trial counts this start (update.rs), so that one that stops again and
/// again, or cannot start with these settings, goes back to the version
/// before.
pub fn start(args: Vec<String>) -> Start {
    let launch_env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    // Not a start to count: a question, or root, which the agent refuses.
    let asking = args.iter().any(|a| matches!(a.as_str(), "--version" | "-h" | "--help")) || nix::unistd::geteuid().is_root();
    let exe = here();
    let trial = match &exe {
        Some(exe) if !asking => update::trial_start(exe, VERSION),
        _ => Trial::No,
    };
    if let (Trial::Over, Some(exe)) = (&trial, &exe) {
        log(&format!("version {VERSION} did not stay up here: back to the version before"));
        go_back(exe, &launch_env, VERSION);
    }
    match settings(args) {
        Start::Exit(code) if code != 0 && trial == Trial::On => {
            if let Some(exe) = &exe {
                log(&format!("version {VERSION} cannot start here: back to the version before"));
                go_back(exe, &launch_env, VERSION);
            }
            Start::Exit(code)
        }
        Start::Run(mut settings) => {
            settings.trial = trial == Trial::On;
            Start::Run(settings)
        }
        other => other,
    }
}

/// What the agent does once its updates stopped it (update.rs).
enum Next {
    /// Starts again as this version, now in its place.
    Update(String),
    /// This version, on trial, did not connect: the one before comes back.
    GoBack,
}

type NextSlot = Arc<Mutex<Option<Next>>>;

/// A new version on trial first shows it stays up; then, if this agent
/// updates itself, newer versions (update.rs).
#[allow(clippy::too_many_arguments)]
async fn updates(exe: PathBuf, trial: bool, keep: Option<([u8; 32], &'static str)>, connected: Arc<AtomicBool>, hosted: Arc<Hosted>, stop: watch::Sender<bool>, next: NextSlot) {
    if trial && !on_trial(&exe, &connected, &stop, &next).await {
        return;
    }
    if let Some((key, platform)) = keep {
        keep_updated(exe, key, platform, hosted, stop, next).await;
    }
}

/// Whether this agent updates itself, with what key and for what system.
fn updates_on(settings: &Settings, exe: &Path) -> Option<([u8; 32], &'static str)> {
    if !update::enabled(exe, settings.env_file.as_deref(), env("TTERM_UPDATE").as_deref()) {
        return None;
    }
    let platform = update::platform()?;
    let Some(key) = update::public_key() else {
        log("updates: this build has no release key, so it does not update itself");
        return None;
    };
    Some((key, platform))
}

/// A new version on trial: connected, and up TRIAL_UP since its start
/// (awake), it stays; not connected after TRIAL_CONNECT, the agent stops to
/// go back to the version before. Whether it stays.
async fn on_trial(exe: &Path, connected: &AtomicBool, stop: &watch::Sender<bool>, next: &NextSlot) -> bool {
    let started = tokio::time::Instant::now();
    loop {
        tokio::time::sleep(update::TRIAL_STEP).await;
        let up = started.elapsed();
        let linked = connected.load(Ordering::SeqCst);
        if linked && up >= update::TRIAL_UP {
            update::trial_passed(exe);
            log(&format!("version {VERSION} works here: it stays"));
            return true;
        }
        if !linked && up >= update::TRIAL_CONNECT {
            log(&format!(
                "version {VERSION} has not connected to tTerm Web in {} minutes: back to the version before",
                update::TRIAL_CONNECT.as_secs() / 60
            ));
            *next.lock().unwrap_or_else(|e| e.into_inner()) = Some(Next::GoBack);
            let _ = stop.send(true);
            return false;
        }
    }
}

async fn keep_updated(exe: PathBuf, key: [u8; 32], platform: &'static str, hosted: Arc<Hosted>, stop: watch::Sender<bool>, next: NextSlot) {
    tokio::time::sleep(update::FIRST_LOOK).await;
    loop {
        // A version that did not come up here: only one newer than that.
        let newer_than = update::skipped(&exe, VERSION).unwrap_or_else(|| VERSION.to_string());
        let wait = match update::look(&newer_than, &key, platform, &proxy_env()).await {
            Ok(Some(found)) => match put_in(&exe, &found, platform, &hosted, &stop).await {
                In::Done => {
                    *next.lock().unwrap_or_else(|e| e.into_inner()) = Some(Next::Update(found.version));
                    let _ = stop.send(true);
                    return;
                }
                In::Waited => std::time::Duration::ZERO,
                In::Failed => update::LOOK_EVERY,
            },
            Ok(None) => update::LOOK_EVERY,
            Err(why) => {
                log(&format!("could not look for a new version: {why}"));
                update::LOOK_EVERY
            }
        };
        tokio::time::sleep(wait).await;
    }
}

enum In {
    Done,
    /// Terminals stayed open: look again, the release may be gone.
    Waited,
    Failed,
}

/// Puts version `found` in the agent's place once no terminal is open here
/// (their shells live in this process, and would end with it), waiting up to
/// LOOK_EVERY for that: a release taken back meanwhile is then not put in.
async fn put_in(exe: &Path, found: &update::Found, platform: &str, hosted: &Hosted, stop: &watch::Sender<bool>) -> In {
    let until = tokio::time::Instant::now() + update::LOOK_EVERY;
    let mut file: Option<Vec<u8>> = None;
    let mut said = false;
    loop {
        if hosted.idle() {
            if file.is_none() {
                match update::get_file(found, platform, &proxy_env()).await {
                    Ok(f) => file = Some(f),
                    Err(why) => {
                        log(&format!("could not get version {}: {why}", found.version));
                        return In::Failed;
                    }
                }
            }
            if hosted.shut_if_idle() {
                if *stop.borrow() {
                    return In::Failed; // stopping anyway
                }
                let (at, version, bytes) = (exe.to_path_buf(), found.version.clone(), file.take().unwrap_or_default());
                let done = tokio::task::spawn_blocking(move || {
                    update::begin_trial(&at, &version).map_err(update::NotReplaced::Io)?;
                    update::replace(&at, &bytes, &version).inspect_err(|_| update::trial_passed(&at))
                })
                .await;
                return match done {
                    Ok(Ok(())) => {
                        log(&format!("updated to {}: starting again as it", found.version));
                        In::Done
                    }
                    Ok(Err(why)) => {
                        hosted.reopen();
                        if let update::NotReplaced::DoesNotStart(_) = why {
                            update::skip(exe, &found.version);
                        }
                        log(&format!("could not update to {}: {why}", found.version));
                        In::Failed
                    }
                    Err(_) => {
                        hosted.reopen();
                        In::Failed
                    }
                };
            }
        }
        if !said {
            log(&format!("version {} is out: it goes in once no terminal is open here", found.version));
            said = true;
        }
        if tokio::time::Instant::now() >= until {
            return In::Waited;
        }
        tokio::time::sleep(update::WAIT_STEP).await;
    }
}

/// Starts the agent again as `version`, now in its place, in this same
/// process, as it was started: autostart sees nothing. Returns only if it
/// could not; the version before then goes back.
fn start_again(exe: &Path, env: &[(OsString, OsString)], version: &str) -> i32 {
    let error = exec(exe, env);
    log(&format!("could not start version {version}: {error}"));
    go_back(exe, env, version);
    1
}

/// The version before goes back in the place of `version`, not to be taken
/// again, and starts in this process. Returns only if it could not.
fn go_back(exe: &Path, env: &[(OsString, OsString)], version: &str) {
    if let Err(e) = update::roll_back(exe, version) {
        log(&format!("could not put the version before back: {e}"));
        update::trial_passed(exe);
        return;
    }
    let error = exec(exe, env);
    log(&format!("could not start the version before: {error}"));
}

/// This process becomes `exe`, with the arguments this one was started with
/// and the environment `env`. By execve itself: execvp, failing to run a
/// file, would try it as a shell script instead. What went wrong, if it
/// returns.
fn exec(exe: &Path, env: &[(OsString, OsString)]) -> String {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = |bytes: &[u8]| CString::new(bytes).map_err(|_| "a NUL in its arguments or environment".to_string());
    let made = || -> Result<(CString, Vec<CString>, Vec<CString>), String> {
        let path = c(exe.as_os_str().as_bytes())?;
        let mut argv = vec![path.clone()];
        for arg in std::env::args_os().skip(1) {
            argv.push(c(arg.as_bytes())?);
        }
        let mut envp = Vec::new();
        for (name, value) in env {
            let mut pair = name.as_bytes().to_vec();
            pair.push(b'=');
            pair.extend_from_slice(value.as_bytes());
            envp.push(c(&pair)?);
        }
        Ok((path, argv, envp))
    };
    let (path, argv, envp) = match made() {
        Ok(made) => made,
        Err(why) => return why,
    };
    let mut tries = 0;
    loop {
        match nix::unistd::execve(&path, &argv, &envp) {
            // Still open for writing in a process started a moment ago,
            // until it runs its own program (Linux).
            Err(nix::errno::Errno::ETXTBSY) if tries < 5 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => return e.desc().to_string(),
            Ok(never) => match never {},
        }
    }
}

/// Whether a signal is ignored: a hangup the agent was started to ignore
/// (nohup) stays ignored.
fn ignored(sig: libc::c_int) -> bool {
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(sig, std::ptr::null(), &mut old) == 0 && old.sa_sigaction == libc::SIG_IGN
    }
}

/// Runs until stopped, or until tTerm Web says this computer was removed.
/// The exit code: 0 both ways, so that autostart does not bring back a
/// computer that was removed; 1 when it could not run at all.
pub fn run(settings: Settings, timing: Timing) -> i32 {
    // Checked before anything starts: the runtime installs its handlers. A
    // signal the agent was started to ignore stays ignored, as for agent.py:
    // a hangup under nohup, an interrupt for a command started in the
    // background by a script.
    let listened: Vec<(libc::c_int, tokio::signal::unix::SignalKind)> = [
        (libc::SIGTERM, tokio::signal::unix::SignalKind::terminate()),
        (libc::SIGINT, tokio::signal::unix::SignalKind::interrupt()),
        (libc::SIGHUP, tokio::signal::unix::SignalKind::hangup()),
    ]
    .into_iter()
    .filter(|(sig, _)| !ignored(*sig))
    .collect();
    log(&format!("version {VERSION}, hub {}", settings.hub));
    // Where it runs from: to start again once a newer version is in its
    // place, or the one before is back (update.rs).
    let exe = here();
    let next: NextSlot = Arc::default();
    // Stopped by a signal: whatever else was under way, it stops.
    let signalled = Arc::new(AtomicBool::new(false));
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("tterm-agent").enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            log(&format!("could not start: {e}"));
            return 1;
        }
    };
    let (next_in, signalled_in, exe_in) = (next.clone(), signalled.clone(), exe.clone());
    let launch_env = settings.launch_env.clone();
    let (code, go_on) = runtime.block_on(async move {
        use tokio::signal::unix::signal;
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        // A stop by the system (launchd, systemd), Ctrl+C, or the window
        // the agent runs in being closed: tTerm Web hears that its
        // terminals end. A second one does not wait for that.
        for (_, kind) in &listened {
            match signal(*kind) {
                Ok(mut s) => {
                    let stop_tx = stop_tx.clone();
                    let signalled = signalled_in.clone();
                    tokio::spawn(async move {
                        while s.recv().await.is_some() {
                            if signalled.swap(true, Ordering::SeqCst) {
                                log("stopped");
                                std::process::exit(1);
                            }
                            let _ = stop_tx.send(true);
                        }
                    });
                }
                Err(e) => log(&format!("could not listen for signal {}: {e}", kind.as_raw_value())),
            }
        }

        // Connected once: a new version on trial is on its way to staying.
        let connected = Arc::new(AtomicBool::new(false));
        let to_log: Log = {
            let connected = connected.clone();
            Arc::new(move |msg: &str| {
                if msg.starts_with("connected as ") {
                    connected.store(true, Ordering::SeqCst);
                }
                log(msg)
            })
        };
        let hosted = Hosted::new(timing, to_log.clone(), agent_dir());
        let keeper = hosted.spawn_keeper();
        let updater = exe_in.clone().map(|exe| {
            let keep = updates_on(&settings, &exe);
            tokio::spawn(updates(exe, settings.trial, keep, connected, hosted.clone(), stop_tx.clone(), next_in.clone()))
        });
        let config = Config {
            hub: settings.hub.clone(),
            token: settings.token.clone(),
            key: settings.key.clone(),
            name: settings.name.clone(),
            version: VERSION.to_string(),
            timing,
            proxy_env: proxy_env(),
        };
        let outcome = link::run(&config, hosted.clone(), to_log, stop_rx).await;
        keeper.abort();
        if let Some(updater) = updater {
            updater.abort();
        }
        // tTerm Web's terminals live as long as the agent does, through any
        // number of connections, and end with it.
        hosted.end_all().await;
        match outcome {
            Outcome::Stopped => {
                let mut go_on = next_in.lock().unwrap_or_else(|e| e.into_inner()).is_some() && !signalled_in.load(Ordering::SeqCst);
                if go_on {
                    // From here a stop by the system ends the agent at once:
                    // nothing reads the signals after this. One that came a
                    // moment before is read meanwhile.
                    for (sig, _) in &listened {
                        unsafe {
                            libc::signal(*sig, libc::SIG_DFL);
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    go_on = !signalled_in.load(Ordering::SeqCst);
                }
                if !go_on {
                    log("stopped");
                }
                (0, go_on)
            }
            Outcome::Revoked { error, forget } => {
                log(&format!("access revoked: {}. Stopping.", error.trim_end_matches('.')));
                // Not a new version's doing: no trial to go on with.
                if let Some(exe) = &exe_in {
                    update::trial_passed(exe);
                }
                if forget && !settings.key.is_empty() {
                    if let Some(path) = &settings.env_file {
                        forget_key(path);
                    }
                }
                if let Some(remove) = uninstaller() {
                    log(&format!("Remove the agent completely: {remove}"));
                }
                (0, false)
            }
        }
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    let next = next.lock().unwrap_or_else(|e| e.into_inner()).take();
    match (go_on && !signalled.load(Ordering::SeqCst), next, exe) {
        (true, Some(Next::Update(version)), Some(exe)) => start_again(&exe, &launch_env, &version),
        (true, Some(Next::GoBack), Some(exe)) => {
            go_back(&exe, &launch_env, VERSION);
            1
        }
        _ => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, text: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("tterm-agent-{}-{name}", std::process::id()));
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[test]
    fn the_settings_file() {
        let path = file("read", "# installer\n\nTTERM_HUB = wss://a/agent\nnonsense\nTTERM_NAME=one\nTTERM_NAME=two=2\n");
        let values = read_env_file(&path).unwrap();
        assert_eq!(
            values,
            vec![("TTERM_HUB".to_string(), "wss://a/agent".to_string()), ("TTERM_NAME".to_string(), "two=2".to_string())]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn the_key_is_forgotten_once() {
        let path = file("forget", "TTERM_HUB=wss://a/agent\nTTERM_TOKEN=t\nTTERM_KEY=secret\nTTERM_NAME=mac");
        forget_key(&path);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, "TTERM_HUB=wss://a/agent\nTTERM_TOKEN=t\nTTERM_NAME=mac\nTTERM_REMOVED=1\n");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // Again: nothing to forget, the file stays as it is.
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        forget_key(&path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), before);
        let _ = std::fs::remove_file(path);
    }
}
