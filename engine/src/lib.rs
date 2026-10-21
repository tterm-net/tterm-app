//! The engine of tTerm on a computer.
//!
//! The app's window shows the very page of tTerm Web, unchanged. Where that
//! page would talk to the core on a server, here it talks to this engine,
//! which answers for this computer the way the core answers for a machine:
//! the same requests (api.rs), the same socket and its messages (socket.rs),
//! the same terminals with their numbered events and replays (terminals.rs).
//! The shells run here, in pseudo-terminals of this computer (pty.rs), with
//! nothing going over the network. Their markers (shell.rs) cut what they
//! print into commands, kept on this computer (blocks.rs, store.rs), and the
//! input line asks before what cannot be undone (danger.rs) and completes
//! words with Tab (complete.rs).

pub mod api;
pub mod blocks;
pub mod complete;
pub mod danger;
pub mod machine;
pub mod modes;
pub mod names;
pub mod pty;
pub mod settings;
pub mod shell;
pub mod socket;
pub mod store;
pub mod terminals;

use serde_json::{json, Value};
use settings::Settings;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use store::Store;
use terminals::{Place, Plan, Terminals};
use uuid::Uuid;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Terminals open at once on this computer, at most.
pub const MOST_TERMINALS: usize = 24;

/// What a terminal says that the app's last run left open: it was stopped
/// before it could end them, or it crashed.
pub const LEFT_OPEN: &str = "tTerm stopped.";
/// How long looking up the shells may take, at most: past it the shell
/// starts without markers.
const DETECT_TIMEOUT: Duration = Duration::from_secs(10);

/// What the sign-in screens and the account page link to.
pub const TERMS_URL: &str = "https://tterm.net/terms";
pub const PRIVACY_URL: &str = "https://tterm.net/privacy";
pub const SUPPORT: &str = "support@tterm.net";

pub struct Engine {
    pub data_dir: PathBuf,
    pub settings: Mutex<Settings>,
    pub machine_name: String,
    pub account_name: String,
    passport: Mutex<Value>,
    commands: Mutex<Vec<String>>,
    pub terminals: Terminals,
    /// When the engine started, in milliseconds: the "agent" of this
    /// computer is connected since then.
    pub since_ms: i64,
}

impl Engine {
    /// The engine, with its settings and its store in `data_dir` (made on
    /// the first run, for the person alone).
    pub fn new(data_dir: &Path) -> std::io::Result<Arc<Self>> {
        private_dir(data_dir)?;
        let settings = Settings::load(data_dir)?;
        let store = Store::open(data_dir);
        store.close_left_open(LEFT_OPEN);
        Ok(Arc::new(Engine {
            data_dir: data_dir.to_path_buf(),
            settings: Mutex::new(settings),
            machine_name: machine::machine_name(),
            account_name: machine::account_name(),
            passport: Mutex::new(json!({})),
            commands: Mutex::new(Vec::new()),
            terminals: Terminals::new(store),
            since_ms: terminals::now_ms(),
        }))
    }

    /// What runs alongside, on the async runtime: the passport is read once,
    /// ended terminals are swept away after a while.
    pub fn start_background(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            let (passport, commands) = machine::passport(VERSION).await;
            *me.passport.lock().unwrap() = passport;
            *me.commands.lock().unwrap() = commands;
        });
        let me = self.clone();
        tokio::spawn(async move {
            let mut minutes = 0u64;
            loop {
                // What expired in the store: at the start, then hourly.
                if minutes.is_multiple_of(60) {
                    me.terminals.store.sweep();
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
                minutes += 1;
                me.terminals.sweep();
            }
        });
    }

    pub fn save_settings(&self, change: impl FnOnce(&mut Settings)) -> std::io::Result<Settings> {
        let mut settings = self.settings.lock().unwrap();
        let mut next = settings.clone();
        change(&mut next);
        next.save(&self.data_dir)?;
        *settings = next.clone();
        Ok(next)
    }

    pub fn person_name(&self) -> String {
        self.settings.lock().unwrap().name.clone().unwrap_or_else(|| self.account_name.clone())
    }

    pub fn place(&self) -> Place {
        let s = self.settings.lock().unwrap();
        Place { machine_id: s.machine_id, machine: self.machine_name.clone(), code: s.project_code.clone() }
    }

    /// The folder of the shell scripts.
    pub fn shell_dir(&self) -> PathBuf {
        self.data_dir.join(shell::FOLDER)
    }

    /// How a terminal's shell starts, as the core decides it on a machine
    /// (`Terminal._deploy`): the scripts are put in place and the shells
    /// looked up, then the login shell runs the command of the plan, the
    /// way sshd runs one. If that fails the login shell starts without the
    /// scripts: the terminal works, only without blocks. Sending the key to
    /// a shell that does not expect it would type it in as a command.
    pub async fn plan(&self) -> Plan {
        self.plan_for(&pty::login_shell(), &pty::clean_env(false), &pty::home_dir()).await
    }

    /// The same for the login shell `login`, with the shells looked up in
    /// the environment `env` from the folder `home`: those the terminal gets.
    pub async fn plan_for(&self, login: &str, env: &[(String, String)], home: &Path) -> Plan {
        let dir = self.shell_dir();
        let found = match shell::deploy(&dir) {
            Ok(()) => {
                let (code, out) = machine::run_script_with(shell::DETECT, DETECT_TIMEOUT, env, home).await;
                let out = String::from_utf8_lossy(&out).to_string();
                if code == Some(0) && out.contains("shell=") {
                    out
                } else {
                    eprintln!("tterm: could not look up the shells: the terminal starts without markers");
                    String::new()
                }
            }
            Err(e) => {
                eprintln!("tterm: could not put the shell scripts in {}: {e}", dir.display());
                String::new()
            }
        };
        let how = shell::plan(&found, &dir);
        Plan { shell: how.shell, argv: vec![login.to_string(), "-c".into(), how.command], markers: how.markers, blocks: how.blocks }
    }

    /// A terminal no longer in memory, as the store remembers it: what the
    /// page gets for one that ended a while ago, or in an earlier run.
    pub async fn ended_json(&self, id: &Uuid) -> Option<Value> {
        let row = self.terminals.store.ended_row(&id.to_string()).await?;
        let place = self.place();
        let mut label = place.label();
        if !row.name.is_empty() && row.name != "1" {
            label = format!("{label} · {}", row.name);
        }
        Some(json!({
            "id": id.to_string(),
            "machineId": place.machine_id.to_string(),
            "machine": place.machine,
            "label": label,
            "name": row.name,
            "state": "gone",
            "home": row.home.unwrap_or_default(),
            "reason": row.reason.unwrap_or_else(|| "This terminal is no longer running.".to_string()),
        }))
    }

    pub fn me_json(&self) -> Value {
        let s = self.settings.lock().unwrap();
        let name = s.name.clone().unwrap_or_else(|| self.account_name.clone());
        json!({
            "id": s.person_id.to_string(),
            "name": name,
            "firstName": names::first_name(&name),
            "initials": names::initials(&name),
            "theme": s.theme,
            "projectTint": s.project_tint,
            "plan": "free",
            "email": Value::Null,
        })
    }

    pub fn machine_json(&self) -> Value {
        let s = self.settings.lock().unwrap();
        let passport = self.passport.lock().unwrap().clone();
        json!({
            "id": s.machine_id.to_string(),
            "kind": "computer",
            "name": self.machine_name,
            "host": Value::Null,
            "os": passport.get("os").cloned().unwrap_or(Value::Null),
            "passport": passport,
            "online": true,
            "agent": {"version": format!("app {VERSION}"), "since": self.since_ms},
            "lastSeen": terminals::now_ms(),
        })
    }

    pub fn machine_details(&self) -> Value {
        let s = self.settings.lock().unwrap();
        let passport = self.passport.lock().unwrap().clone();
        json!({
            "id": s.machine_id.to_string(),
            "name": self.machine_name,
            "kind": "computer",
            "host": Value::Null,
            "port": Value::Null,
            "label": format!("{}/{}", s.project_code, self.machine_name),
            "project": s.project_name,
            "passport": passport,
            "addedAt": terminals::iso_seconds(s.added_at),
            "online": true,
            "agent": {"version": format!("app {VERSION}"), "since": self.since_ms},
        })
    }

    pub fn project_json(&self) -> Value {
        let s = self.settings.lock().unwrap().clone();
        json!({
            "id": s.project_id.to_string(),
            "name": s.project_name,
            "code": s.project_code,
            "color": s.project_color,
            "role": "owner",
            "personal": true,
            "own": true,
            "alone": true,
            "machines": [self.machine_json()],
            "folders": [],
        })
    }

    pub fn state_json(&self) -> Value {
        json!({
            "version": format!("app {VERSION}"),
            "me": self.me_json(),
            "projects": [self.project_json()],
            "terminals": self.terminals.live().iter().map(|t| t.describe()).collect::<Vec<_>>(),
        })
    }

    pub fn legal_json(&self) -> Value {
        json!({"terms": TERMS_URL, "privacy": PRIVACY_URL, "support": SUPPORT})
    }
}

/// The app's folder, for the person alone: it keeps what their commands
/// printed.
fn private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        builder.mode(0o700);
        builder.create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    builder.create(dir)
}
