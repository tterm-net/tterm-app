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
//! words with Tab (complete.rs). Notes, in folders of Personal, are kept on
//! this computer too (notes.rs), the way the core keeps them.
//!
//! Before anyone signs in, the engine tells the page so (`"local": true` in
//! the state, from tTerm Web 0.1.4), and the page shows this computer only.
//! From 0.3.0 the app signs in with the browser (account.rs, loopback.rs),
//! with the `cloud` feature: the page's requests then go to tTerm Web in the
//! cloud (cloud_api.rs, upstream.rs), and so do its cloud terminals over the
//! socket (upstream_socket.rs); this computer's own stay here.
//!
//! The engine also keeps a link to tTerm Web of its own (link.rs), through
//! which tTerm Web opens terminals on this computer (hosted.rs), as
//! tterm-agent did: the agent without a window (agent/) is this engine with
//! that link, through the computer's proxy if it has one (proxy.rs). From
//! 0.4.0 the app runs that link itself, in the agent's place (reach.rs).

#[cfg(feature = "cloud")]
pub mod account;
pub mod api;
pub mod blocks;
#[cfg(feature = "cloud")]
pub mod cloud_api;
pub mod complete;
pub mod danger;
pub mod hosted;
pub mod link;
#[cfg(feature = "cloud")]
pub mod loopback;
pub mod machine;
pub mod modes;
pub mod names;
pub mod notes;
pub mod proxy;
pub mod pty;
#[cfg(feature = "cloud")]
pub mod reach;
pub mod search;
pub mod settings;
pub mod shell;
pub mod socket;
pub mod store;
pub mod terminals;
#[cfg(feature = "cloud")]
pub mod upstream;
#[cfg(feature = "cloud")]
pub mod upstream_socket;

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
    /// Set while the notes cannot be read (state_json).
    notes_trouble: Mutex<Option<String>>,
    /// tTerm Web in the cloud, once someone signs in (from 0.3.0).
    #[cfg(feature = "cloud")]
    pub cloud: Option<Arc<account::Account>>,
    /// This computer opened from tTerm Web through the app (from 0.4.0).
    #[cfg(feature = "cloud")]
    pub reach: reach::Reach,
}

/// What every request for notes says while they cannot be read.
fn notes_unread(why: &str) -> String {
    format!("The notes on this computer could not be read ({why}). Until they can, nothing is changed in them. Quit tTerm and open it again; if it goes on, write to {SUPPORT}.")
}

impl Engine {
    /// The engine, with its settings and its store in `data_dir` (made on
    /// the first run, for the person alone).
    pub fn new(data_dir: &Path) -> std::io::Result<Arc<Self>> {
        Ok(Arc::new(Self::made(data_dir)?))
    }

    /// The engine of the app, which signs in to tTerm Web at `cloud` (from
    /// 0.3.0): `host` keeps its key and opens the browser, `env_file` is the
    /// agent's settings, where this computer's own key is.
    #[cfg(feature = "cloud")]
    pub fn with_cloud(data_dir: &Path, cloud: &str, host: Arc<dyn account::Host>, env_file: &Path) -> std::io::Result<Arc<Self>> {
        let mut engine = Self::made(data_dir)?;
        engine.cloud = Some(account::Account::new(upstream::Cloud::new(cloud), host, data_dir, env_file));
        engine.reach = reach::Reach::new(env_file);
        Ok(Arc::new(engine))
    }

    fn made(data_dir: &Path) -> std::io::Result<Self> {
        private_dir(data_dir)?;
        let mut settings = Settings::load(data_dir)?;
        let store = Store::open(data_dir);
        // The notes are kept under the ids of the store: settings made anew
        // take them back (Store::identity).
        let (person, project) = store.identity(&settings.person_id.to_string(), &settings.project_id.to_string());
        if let (Ok(person), Ok(project)) = (Uuid::parse_str(&person), Uuid::parse_str(&project)) {
            if (person, project) != (settings.person_id, settings.project_id) {
                eprintln!("tterm: the settings take back the ids the notes are kept under");
                settings.person_id = person;
                settings.project_id = project;
                if let Err(e) = settings.save(data_dir) {
                    // Kept for this run; written with the next change.
                    eprintln!("tterm: could not save the settings: {e}");
                }
            }
        }
        store.close_left_open(LEFT_OPEN);
        Ok(Engine {
            data_dir: data_dir.to_path_buf(),
            settings: Mutex::new(settings),
            machine_name: machine::machine_name(),
            account_name: machine::account_name(),
            passport: Mutex::new(json!({})),
            commands: Mutex::new(Vec::new()),
            terminals: Terminals::new(store),
            since_ms: terminals::now_ms(),
            notes_trouble: Mutex::new(None),
            #[cfg(feature = "cloud")]
            cloud: None,
            #[cfg(feature = "cloud")]
            reach: reach::Reach::new(&pty::home_dir().join(".tterm-web").join("env")),
        })
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
            // What expired in the store: soon after the start, once the page
            // has what it needs to start (it waits for the store: notes),
            // then hourly, and once more when the app quits (stop_all).
            tokio::time::sleep(Duration::from_secs(15)).await;
            loop {
                me.terminals.store.sweep();
                tokio::time::sleep(Duration::from_secs(60 * 60)).await;
            }
        });
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                me.terminals.sweep();
            }
        });
        let me = self.clone();
        tokio::spawn(async move {
            // The text to search of blocks from before 0.3.1, once the start
            // is over.
            tokio::time::sleep(Duration::from_secs(20)).await;
            let made = me.terminals.store.fill_texts().await;
            if made > 0 {
                eprintln!("tterm: search: made the text of {made} earlier blocks");
            }
        });
        #[cfg(feature = "cloud")]
        if let Some(account) = self.cloud.clone() {
            let me = self.clone();
            tokio::spawn(async move {
                account.start(&me).await;
                me.align_terminals();
                me.reach.look_again();
            });
            // This computer opened from tTerm Web, whenever it is to be
            // (from 0.4.0).
            tokio::spawn(reach::Reach::keep(self.clone()));
        }
    }

    pub fn save_settings(&self, change: impl FnOnce(&mut Settings)) -> std::io::Result<Settings> {
        let mut settings = self.settings.lock().unwrap();
        let mut next = settings.clone();
        change(&mut next);
        next.save(&self.data_dir)?;
        *settings = next.clone();
        Ok(next)
    }

    /// The person of this computer, as the notes name them.
    pub fn notes_me(&self) -> notes::Me {
        let s = self.settings.lock().unwrap();
        notes::Me {
            id: s.person_id.to_string(),
            name: s.name.clone().unwrap_or_else(|| self.account_name.clone()),
            project_id: s.project_id.to_string(),
        }
    }

    pub fn person_name(&self) -> String {
        self.settings.lock().unwrap().name.clone().unwrap_or_else(|| self.account_name.clone())
    }

    /// Which machine this computer is: the one it is in tTerm Web once
    /// signed in (from 0.3.0), its own until then.
    pub fn place(&self) -> Place {
        #[cfg(feature = "cloud")]
        if let Some(here) = self.cloud.as_ref().and_then(|a| a.here()) {
            return Place { machine_id: here.id, machine: here.name, code: here.code };
        }
        let s = self.settings.lock().unwrap();
        Place { machine_id: s.machine_id, machine: self.machine_name.clone(), code: s.project_code.clone() }
    }

    /// Where this computer's terminals are, as search says it (search.rs):
    /// its machine, and the project that machine is in.
    pub fn search_place(&self) -> search::Where {
        let place = self.place();
        let (project_id, project) = self.place_project();
        search::Where { machine_id: place.machine_id.to_string(), machine: place.machine, project_id, code: place.code, project }
    }

    /// The project this computer's machine is in: in tTerm once signed in,
    /// as tTerm said last, Personal of the app's own until then.
    fn place_project(&self) -> (String, String) {
        #[cfg(feature = "cloud")]
        if let Some(account) = self.cloud.as_ref() {
            if let Some(here) = account.here() {
                let name = account
                    .last_state()
                    .and_then(|s| s["projects"].as_array().and_then(|ps| ps.iter().find(|p| p["id"].as_str() == Some(here.project_id.as_str())).and_then(|p| p["name"].as_str().map(str::to_string))))
                    .unwrap_or_else(|| "Personal".to_string());
                return (here.project_id, name);
            }
        }
        let s = self.settings.lock().unwrap();
        (s.project_id.to_string(), s.project_name.clone())
    }

    /// The terminals of this computer follow it to the machine it is now.
    pub fn align_terminals(&self) {
        self.terminals.move_to(&self.place());
    }

    /// Whether `id` is this computer: its own machine, or the one it is in
    /// tTerm Web.
    pub fn is_here(&self, id: Uuid) -> bool {
        // The settings let go of before place() takes them again.
        let own = self.settings.lock().unwrap().machine_id;
        id == own || id == self.place().machine_id
    }

    /// The system, as the passport says it ("macOS 15.5"), once read.
    pub fn passport_os(&self) -> String {
        self.passport.lock().unwrap().get("os").and_then(Value::as_str).unwrap_or("").to_string()
    }

    /// Whether the passport was read (it is, once, soon after the start).
    pub fn passport_read(&self) -> bool {
        self.passport.lock().unwrap().get("checked_at").is_some()
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

    /// What the page needs on start. With `"local": true`: no one has
    /// signed in on this computer (the page shows this computer only).
    ///
    /// Notes that cannot be read do not keep the page, and the terminals,
    /// from starting: the folders are left out, and until they can be read
    /// again every request for notes says why (notes_trouble), rather than
    /// a page that shows no notes as if there were none, or writes into a
    /// damaged file.
    pub async fn state_json(&self) -> Value {
        let mut project = self.project_json();
        let me = self.notes_me();
        let read = self.terminals.store.run(move |c| notes::folders_of(c, &me)).await;
        let mut trouble = self.notes_trouble.lock().unwrap();
        match read {
            Some(Ok(folders)) => {
                project["folders"] = Value::Array(folders);
                *trouble = None;
            }
            Some(Err(why)) => *trouble = Some(notes_unread(why.message())),
            None => *trouble = Some(notes_unread("the store stopped")),
        }
        drop(trouble);
        self.align_terminals();
        #[allow(unused_mut)]
        let mut state = json!({
            "version": format!("app {VERSION}"),
            "me": self.me_json(),
            "projects": [project],
            "terminals": self.terminals.live().iter().map(|t| t.describe()).collect::<Vec<_>>(),
            "local": true,
        });
        // The welcome of the app's first start, until Later or Sign in.
        #[cfg(feature = "cloud")]
        if self.cloud.is_some() && !self.settings.lock().unwrap().welcome_seen {
            state["welcome"] = json!(true);
        }
        state
    }

    /// Why notes are not taken now, if they are not.
    pub fn notes_trouble(&self) -> Option<String> {
        self.notes_trouble.lock().unwrap().clone()
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
