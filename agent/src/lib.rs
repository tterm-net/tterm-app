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
//! the terminals print and the answers to those scripts.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tterm_engine::hosted::Hosted;
use tterm_engine::link::{self, Config, Log, Outcome, Timing};

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
    let listened: Vec<tokio::signal::unix::SignalKind> = [
        (libc::SIGTERM, tokio::signal::unix::SignalKind::terminate()),
        (libc::SIGINT, tokio::signal::unix::SignalKind::interrupt()),
        (libc::SIGHUP, tokio::signal::unix::SignalKind::hangup()),
    ]
    .into_iter()
    .filter(|(sig, _)| !ignored(*sig))
    .map(|(_, kind)| kind)
    .collect();
    log(&format!("version {VERSION}, hub {}", settings.hub));
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("tterm-agent").enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            log(&format!("could not start: {e}"));
            return 1;
        }
    };
    let code = runtime.block_on(async move {
        use tokio::signal::unix::signal;
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        // A stop by the system (launchd, systemd), Ctrl+C, or the window
        // the agent runs in being closed: tTerm Web hears that its
        // terminals end. A second one does not wait for that.
        for kind in listened {
            match signal(kind) {
                Ok(mut s) => {
                    let stop_tx = stop_tx.clone();
                    tokio::spawn(async move {
                        while s.recv().await.is_some() {
                            if *stop_tx.borrow() {
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

        let to_log: Log = Arc::new(|msg: &str| log(msg));
        let hosted = Hosted::new(timing, to_log.clone(), agent_dir());
        let keeper = hosted.spawn_keeper();
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
        // tTerm Web's terminals live as long as the agent does, through any
        // number of connections, and end with it.
        hosted.end_all().await;
        match outcome {
            Outcome::Stopped => {
                log("stopped");
                0
            }
            Outcome::Revoked { error, forget } => {
                log(&format!("access revoked: {}. Stopping.", error.trim_end_matches('.')));
                if forget && !settings.key.is_empty() {
                    if let Some(path) = &settings.env_file {
                        forget_key(path);
                    }
                }
                if let Some(remove) = uninstaller() {
                    log(&format!("Remove the agent completely: {remove}"));
                }
                0
            }
        }
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    code
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
