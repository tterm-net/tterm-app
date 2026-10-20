//! The engine of tTerm on a computer.
//!
//! The app's window shows the very page of tTerm Web, unchanged. Where that
//! page would talk to the core on a server, here it talks to this engine,
//! which answers for this computer the way the core answers for a machine:
//! the same requests (api.rs), the same socket and its messages (socket.rs),
//! the same terminals with their numbered events and replays (terminals.rs).
//! The shells run here, in pseudo-terminals of this computer (pty.rs), with
//! nothing going over the network.

pub mod api;
pub mod machine;
pub mod modes;
pub mod names;
pub mod pty;
pub mod settings;
pub mod socket;
pub mod terminals;

use serde_json::{json, Value};
use settings::Settings;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use terminals::{Place, Plan, Terminals};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Terminals open at once on this computer, at most.
pub const MOST_TERMINALS: usize = 24;

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
    /// The engine, with its settings in `data_dir` (made on the first run).
    pub fn new(data_dir: &Path) -> std::io::Result<Arc<Self>> {
        let settings = Settings::load(data_dir)?;
        Ok(Arc::new(Engine {
            data_dir: data_dir.to_path_buf(),
            settings: Mutex::new(settings),
            machine_name: machine::machine_name(),
            account_name: machine::account_name(),
            passport: Mutex::new(json!({})),
            commands: Mutex::new(Vec::new()),
            terminals: Terminals::new(),
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
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
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

    /// How a terminal's shell starts: the login shell runs the person's
    /// shell as a login shell, the way tTerm Web starts one with no markers.
    pub fn plan(&self) -> Plan {
        let shell = pty::login_shell();
        let name = Path::new(&shell).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "sh".into());
        Plan {
            shell: name,
            argv: vec![shell, "-c".into(), "exec \"${SHELL:-/bin/sh}\" -l".into()],
            markers: false,
            blocks: false,
        }
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
