//! This computer, opened from tTerm Web and the phone through the app (from
//! 0.4.0, where the app and the agent meet; the owner, 28.10: «вариант 2,
//! делай сразу»). tterm-agent's link to tTerm Web (link.rs) and its
//! terminals (hosted.rs) run in the app: tTerm Web opens terminals on this
//! computer through it, as through the agent before, and on a Mac the agent
//! stops for good, so that there is one link (the core lets a key in once).
//!
//! It runs while the app does, its window closed too: on a Mac the app stays
//! in the menu bar for it, and starts when the person logs in, as long as
//! the switch is on and the app signed in (`kept`; the app's background.rs).
//! Settings has the switch, Open from tTerm Web and your phone; off, there
//! this computer is offline and here nothing changes. The first run signed
//! in decides it, once tTerm said which machine the computer's key is: on
//! where the agent was set up (the person said yes to it then) and the app
//! can take its place, off otherwise, as nothing is opened from outside
//! unasked.
//!
//! The link takes this computer's key from the agent's file (~/.tterm-web/
//! env), as the agent did, so that in tTerm Web it is the same computer; and
//! only a key that tTerm took for this account in this run (account.rs,
//! /api/computers/this). Another key in the file is asked about first.
//!
//! The switch goes off by itself, and Settings says why, when the computer
//! is removed in tTerm Web (the link hears it, or tTerm at the start, with a
//! new key made), when the agent's file goes (its uninstaller), and when the
//! file is another tTerm Web's or tTerm says the key is no machine of this
//! account's. On again, tTerm is asked again.

use crate::account::{is_token, Account, AgentEnv, Verdict};
use crate::hosted::Hosted;
use crate::link::{self, Config, Log, Outcome, State, Timing};
use crate::Engine;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{watch, Notify};

/// How often the keeper looks again at whether the link should run, when
/// nothing told it to sooner.
const LOOK_EVERY: Duration = Duration::from_secs(3);
/// The agent's file says to go off: read again after this first, as a file
/// being written says things for a moment only.
const CLOSE_CHECK: Duration = Duration::from_millis(500);
/// How long a stop waits for the goodbye and the terminals' shells, at most.
pub const STOP_WAIT: Duration = Duration::from_secs(3);

/// The agent's autostart, as tTerm Web's installer sets it up.
pub const AGENT_LABEL: &str = "net.tterm.web-agent";

/// While tTerm has not said which machine the computer's key is.
const NOT_SAID: &str = "tTerm has not said yet which of your machines this computer is.";
/// Removed in tTerm Web, when the link did not hear it itself.
const REMOVED_HERE: &str = "This computer was removed from tTerm Web.";

/// What the link of this computer is doing, for Settings and the menu bar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// The app is starting: the keychain not looked in yet.
    Starting,
    /// Off in Settings.
    Off,
    /// The app is not signed in.
    SignedOut,
    /// On, and it cannot run now: why. It runs once it can.
    Waiting(String),
    Connecting,
    /// Connected: tTerm Web calls this computer `name`.
    Online { name: String },
    NoNetwork,
    /// Removed in tTerm Web: the switch went off. Why, as tTerm said it.
    Removed(String),
    /// The switch went off by itself for another reason: the agent's file
    /// gone, another tTerm Web's, another account's computer. Why.
    Closed(String),
}

impl Status {
    /// One line, for the app's menu in the menu bar.
    pub fn line(&self, here: &str) -> String {
        match self {
            Status::Off | Status::Removed(_) | Status::Closed(_) => format!("{here} is not opened from tTerm Web"),
            Status::Starting => "tTerm is starting…".to_string(),
            Status::SignedOut => "Not signed in to tTerm".to_string(),
            Status::Waiting(_) | Status::Connecting => "Connecting to tTerm Web…".to_string(),
            Status::Online { name } => format!("{name}: online in tTerm Web"),
            Status::NoNetwork => "No network: trying again".to_string(),
        }
    }
}

/// Why the switch did not go on.
#[derive(Debug)]
pub enum NotOn {
    SignedOut,
    /// The agent's file or tTerm says no: why.
    Refused(String),
    Unsaved(std::io::Error),
}

/// What the link should do now.
enum Want {
    /// Run, with these settings.
    Run(Box<Config>),
    /// Not run: what to show.
    Show(Status),
    /// Not run until tTerm said which machine this key is: what to show.
    Ask(Status, String),
    /// Not run, and the switch goes off by itself: why.
    Close(Status),
    /// The agent's file cannot be told now (being written, or unreadable):
    /// a link that runs, with a key tTerm took, runs on; otherwise this.
    Hold(Status),
}

struct Running {
    /// The key it runs with: another in the file is another link.
    key: String,
    hub: String,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Outcome>,
    hosted: Arc<Hosted>,
    keeper: tokio::task::JoinHandle<()>,
    watcher: tokio::task::JoinHandle<()>,
}

pub struct Reach {
    /// The agent's settings, with this computer's key (~/.tterm-web/env);
    /// its folder is the agent's, and its parent the person's home.
    env_file: PathBuf,
    /// Whether that file was there when the app started.
    env_at_start: bool,
    timing: Mutex<Timing>,
    status: watch::Sender<Status>,
    /// Whether the app keeps running in the background for the link: the
    /// switch on and the app signed in. None while not known (the keychain
    /// not looked in, or not readable; the first position not decided).
    kept: watch::Sender<Option<bool>>,
    /// The app keeps running in the background (a Mac, background.rs): only
    /// then does it take the agent's place, and start where the agent was.
    background: AtomicBool,
    nudge: Arc<Notify>,
    running: tokio::sync::Mutex<Option<Running>>,
    /// The switch is turned one way at a time.
    switching: tokio::sync::Mutex<()>,
    /// Why the last try to connect failed, while it tries again.
    problem: Arc<Mutex<Option<String>>>,
    /// tTerm Web's terminals here, while the link runs.
    hosted: Mutex<Option<Arc<Hosted>>>,
    /// Why the switch went off by itself, in this run.
    went: Mutex<Option<Status>>,
    /// tTerm said at the start that the computer was removed.
    retired_seen: AtomicBool,
    /// The person turned it on, and tTerm is asked: its answer that the old
    /// key stopped working is no news then.
    renewing: AtomicBool,
    /// Which key tTerm was last asked about by the keeper, and when.
    asked: Mutex<Option<(String, Instant)>>,
    asking: AtomicBool,
    start_looked: AtomicBool,
    quitting: AtomicBool,
}

impl Reach {
    pub fn new(env_file: &Path) -> Reach {
        Reach {
            env_file: env_file.to_path_buf(),
            env_at_start: env_file.exists(),
            timing: Mutex::new(Timing::default()),
            status: watch::channel(Status::Starting).0,
            kept: watch::channel(None).0,
            background: AtomicBool::new(false),
            nudge: Arc::new(Notify::new()),
            running: tokio::sync::Mutex::new(None),
            switching: tokio::sync::Mutex::new(()),
            problem: Arc::new(Mutex::new(None)),
            hosted: Mutex::new(None),
            went: Mutex::new(None),
            retired_seen: AtomicBool::new(false),
            renewing: AtomicBool::new(false),
            asked: Mutex::new(None),
            asking: AtomicBool::new(false),
            start_looked: AtomicBool::new(false),
            quitting: AtomicBool::new(false),
        }
    }

    /// The checks shorten the link's pauses.
    pub fn set_timing(&self, timing: Timing) {
        *self.timing.lock().unwrap() = timing;
    }

    /// The app says whether it keeps running in the background (on a Mac).
    pub fn set_background(&self, background: bool) {
        self.background.store(background, Ordering::SeqCst);
        self.nudge.notify_one();
    }

    /// What it is doing, to watch.
    pub fn status(&self) -> watch::Receiver<Status> {
        self.status.subscribe()
    }

    pub fn now(&self) -> Status {
        self.status.borrow().clone()
    }

    /// Whether the app keeps running in the background for it, to watch.
    pub fn kept(&self) -> watch::Receiver<Option<bool>> {
        self.kept.subscribe()
    }

    pub fn kept_now(&self) -> Option<bool> {
        *self.kept.borrow()
    }

    fn show(&self, now: Status) {
        self.status.send_if_modified(|was| {
            if *was == now {
                return false;
            }
            *was = now;
            true
        });
    }

    /// The person's home: where the agent's autostart is.
    fn home(&self) -> PathBuf {
        self.env_file.parent().and_then(Path::parent).map(Path::to_path_buf).unwrap_or_else(crate::pty::home_dir)
    }

    fn agent_dir(&self) -> PathBuf {
        self.env_file.parent().map(Path::to_path_buf).unwrap_or_else(|| self.home().join(".tterm-web"))
    }

    /// Terminals of tTerm Web running here now.
    pub fn terminals(&self) -> usize {
        self.hosted.lock().unwrap().as_ref().map(|h| h.live()).unwrap_or(0)
    }

    // ----------------------------------------------------------- the switch

    /// The switch as it is: None until its first position is decided.
    pub fn open(&self, engine: &Engine) -> Option<bool> {
        engine.settings.lock().unwrap().open_from_web
    }

    /// The person turns it on: tTerm says now which machine the key in the
    /// agent's file is (a new key is made if the file has none, or the one
    /// there stopped working), and it is on unless tTerm or the file says
    /// no. Signed out meanwhile, it stays as it was.
    pub async fn turn_on(&self, engine: &Arc<Engine>) -> Result<(), NotOn> {
        let _one = self.switching.lock().await;
        let account = engine.cloud.clone().filter(|a| a.signed_in()).ok_or(NotOn::SignedOut)?;
        let epoch = account.epoch_now();
        self.renewing.store(true, Ordering::SeqCst);
        account.ask_here_again(engine, true).await;
        account.take_retired();
        self.renewing.store(false, Ordering::SeqCst);
        if !account.signed_in() || account.epoch_now() != epoch {
            return Err(NotOn::SignedOut);
        }
        let shown = self.shown();
        match AgentEnv::read(&self.env_file) {
            Ok(Some(env)) if Some(env.hub_or_default()) != account.hub() => return Err(NotOn::Refused(other_hub(&env.hub_or_default()))),
            Ok(Some(env)) => {
                if let Some(Verdict::Refused(why)) = env.key.as_deref().and_then(|k| account.verdict(k)) {
                    return Err(NotOn::Refused(why));
                }
            }
            Ok(None) => return Err(NotOn::Refused(account.not_here().unwrap_or_else(|| format!("{shown} could not be written.")))),
            Err(e) => return Err(NotOn::Refused(format!("{shown} could not be read: {e}"))),
        }
        engine.save_settings(|s| s.open_from_web = Some(true)).map_err(NotOn::Unsaved)?;
        self.went.lock().unwrap().take();
        self.nudge.notify_one();
        Ok(())
    }

    /// The person turns it off.
    pub async fn turn_off(&self, engine: &Engine) -> std::io::Result<()> {
        let _one = self.switching.lock().await;
        engine.save_settings(|s| s.open_from_web = Some(false))?;
        self.went.lock().unwrap().take();
        self.nudge.notify_one();
        Ok(())
    }

    /// Looks again now: signed in or out, what tTerm said.
    pub fn look_again(&self) {
        self.nudge.notify_one();
    }

    /// One look now, for an answer that says what the link does.
    pub async fn settle(&self, engine: &Arc<Engine>) {
        self.reconcile(engine).await;
    }

    /// For the page's Settings.
    pub fn json(&self, engine: &Engine) -> Value {
        let status = self.now();
        let (word, name, problem) = match &status {
            Status::Starting => ("starting", None, None),
            Status::Off => ("off", None, None),
            Status::SignedOut => ("signed-out", None, None),
            Status::Waiting(why) => ("waiting", None, Some(why.clone())),
            Status::Connecting => ("connecting", None, self.problem.lock().unwrap().clone()),
            Status::Online { name } => ("online", Some(name.clone()), None),
            Status::NoNetwork => ("no-network", None, None),
            Status::Removed(why) => ("removed", None, Some(why.clone())),
            Status::Closed(why) => ("closed", None, Some(why.clone())),
        };
        json!({
            "open": self.open(engine).unwrap_or(false),
            "status": word,
            "name": name,
            "problem": problem,
            "terminals": self.terminals(),
            "background": self.kept_now() == Some(true),
        })
    }

    // ------------------------------------------------------------ the keeper

    /// Runs the link whenever it should, for as long as the app does: from
    /// when the keychain was looked in (until then it is not known whether
    /// the app is signed in).
    pub async fn keep(engine: Arc<Engine>) {
        if let Some(account) = engine.cloud.clone() {
            account.wait_ready().await;
        }
        loop {
            if engine.reach.quitting.load(Ordering::SeqCst) {
                return;
            }
            engine.reach.reconcile(&engine).await;
            let _ = tokio::time::timeout(LOOK_EVERY, engine.reach.nudge.notified()).await;
        }
    }

    /// The link as it should be now: started, stopped, or started again
    /// with another key; the switch decided, or off by itself.
    async fn reconcile(&self, engine: &Arc<Engine>) {
        let Some(account) = engine.cloud.clone() else { return };
        let mut running = self.running.lock().await;
        if self.quitting.load(Ordering::SeqCst) {
            return;
        }
        // Removed in tTerm Web while the app was not running: tTerm said so
        // at the start, and gave this computer a new key (account.rs).
        if account.take_retired() && !self.renewing.load(Ordering::SeqCst) {
            self.retired_seen.store(true, Ordering::SeqCst);
            if self.open(engine) != Some(false) {
                self.went_away(engine, Status::Removed(REMOVED_HERE.to_string()));
            }
        }
        // On, and the agent's file was gone at the start: its uninstaller
        // ran while the app was not running.
        if !self.env_at_start && !self.start_looked.swap(true, Ordering::SeqCst) && self.open(engine) == Some(true) {
            self.went_away(engine, Status::Closed(self.gone()));
        }
        self.decide(engine, &account).await;
        // The link ended by itself: removed in tTerm Web.
        if running.as_ref().map(|r| r.task.is_finished()).unwrap_or(false) {
            if let Some(r) = running.take() {
                if let Some(Outcome::Revoked { error, .. }) = self.finish(r).await {
                    self.went_away(engine, Status::Removed(error));
                }
            }
        }
        match self.wanted(engine, &account) {
            Want::Run(config) => {
                let same = running.as_ref().map(|r| r.key == config.key && r.hub == config.hub).unwrap_or(false);
                if let Some(r) = running.take_if(|_| !same) {
                    // Another key: the old link ends first, and what is wanted
                    // is looked at again then, as it may have changed meanwhile.
                    self.finish(r).await;
                    self.nudge.notify_one();
                } else {
                    // With a key tTerm took: the agent stops for good, and
                    // again if it was set up again meanwhile (on a Mac, where
                    // the app keeps the link with its window closed).
                    let (home, dir) = (self.home(), self.agent_dir());
                    if self.background.load(Ordering::SeqCst) && (agent_plist(&home).exists() || dir.join("agent.pid").exists()) {
                        let done = tokio::task::spawn_blocking(move || take_agents_place(&home, &dir)).await.unwrap_or_default();
                        for line in done {
                            eprintln!("tterm: link: {line}");
                        }
                    }
                    if !same && !self.quitting.load(Ordering::SeqCst) {
                        *running = Some(self.start(*config));
                    }
                }
            }
            Want::Show(status) => {
                if let Some(r) = running.take() {
                    self.finish(r).await;
                }
                self.show(status);
            }
            Want::Ask(status, key) => {
                if let Some(r) = running.take() {
                    self.finish(r).await;
                }
                self.show(status);
                self.ask(engine, &account, key);
            }
            Want::Close(status) => {
                tokio::time::sleep(CLOSE_CHECK).await;
                match self.wanted(engine, &account) {
                    Want::Close(again) if again == status => {
                        if let Some(r) = running.take() {
                            self.finish(r).await;
                        }
                        self.went_away(engine, status);
                    }
                    // Said for a moment only: looked at again at once.
                    _ => self.nudge.notify_one(),
                }
            }
            Want::Hold(status) => {
                if running.is_none() {
                    self.show(status);
                }
            }
        }
        drop(running);
        // On, signed in: the app keeps running for it. Not known: as it was.
        let kept = if !account.known() {
            None
        } else if !account.signed_in() {
            Some(false)
        } else {
            self.open(engine)
        };
        self.kept.send_if_modified(|was| {
            if *was == kept {
                return false;
            }
            *was = kept;
            true
        });
    }

    /// The switch's first position, decided once on the first run signed in
    /// that can tell: on where tTerm Web's agent was set up here and the app
    /// can take its place (a Mac; the agent's file for this tTerm Web, with
    /// a key tTerm took for this account), off otherwise. Saved after a
    /// second look, as a file being written says things for a moment only.
    async fn decide(&self, engine: &Arc<Engine>, account: &Arc<Account>) {
        let (open, ask) = self.first_position(engine, account);
        let Some(open) = open else {
            if let Some(key) = ask {
                self.ask(engine, account, key);
            }
            return;
        };
        tokio::time::sleep(CLOSE_CHECK).await;
        if self.first_position(engine, account).0 != Some(open) {
            self.nudge.notify_one();
            return;
        }
        if let Err(e) = engine.save_settings(|s| s.open_from_web = Some(open)) {
            eprintln!("tterm: could not save the settings: {e}");
        }
    }

    /// The first position, if it can be told now; else the key tTerm is to
    /// be asked about first ("" when the file has none yet).
    fn first_position(&self, engine: &Engine, account: &Account) -> (Option<bool>, Option<String>) {
        if self.open(engine).is_some() || !account.known() || !account.signed_in() {
            return (None, None);
        }
        if !self.background.load(Ordering::SeqCst) || self.retired_seen.load(Ordering::SeqCst) || !agent_set_up(&self.home(), &self.agent_dir()) {
            return (Some(false), None);
        }
        let Some(hub) = account.hub() else { return (None, None) };
        // Asked, the account writes a key into a file without one.
        let ask_first = |done: bool| if done { (Some(false), None) } else { (None, Some(String::new())) };
        match AgentEnv::read(&self.env_file) {
            Err(_) => (None, None),
            Ok(None) => ask_first(account.asked_here()),
            Ok(Some(env)) if env.hub_or_default() != hub => (Some(false), None),
            Ok(Some(env)) => match env.key.clone().filter(|k| is_token(k)) {
                None => ask_first(env.removed || account.asked_here()),
                Some(key) => match account.verdict(&key) {
                    Some(Verdict::Ours) => (Some(true), None),
                    Some(Verdict::Refused(_)) => (Some(false), None),
                    Some(Verdict::Failed(_)) | None => (None, Some(key)),
                },
            },
        }
    }

    /// What the link should do now, on or off.
    fn wanted(&self, engine: &Engine, account: &Account) -> Want {
        if !account.ready() {
            return Want::Show(Status::Starting);
        }
        if !account.signed_in() {
            return Want::Show(Status::SignedOut);
        }
        if self.open(engine) != Some(true) {
            return Want::Show(self.went.lock().unwrap().clone().unwrap_or(Status::Off));
        }
        let Some(hub) = account.hub() else { return Want::Show(Status::SignedOut) };
        let shown = self.shown();
        let env = match AgentEnv::read(&self.env_file) {
            Ok(Some(env)) => env,
            Ok(None) => return Want::Close(Status::Closed(self.gone())),
            Err(e) => return Want::Hold(Status::Waiting(format!("{shown} could not be read: {e}"))),
        };
        let env_hub = env.hub_or_default();
        if env_hub != hub {
            return Want::Close(Status::Closed(other_hub(&env_hub)));
        }
        let Some(key) = env.key.clone().filter(|k| is_token(k)) else {
            // The agent forgot the key: the computer was removed.
            if env.removed {
                return Want::Close(Status::Removed(REMOVED_HERE.to_string()));
            }
            return Want::Hold(Status::Waiting(format!("{shown} has no key tTerm can take.")));
        };
        match account.verdict(&key) {
            Some(Verdict::Ours) => {}
            Some(Verdict::Refused(why)) => return Want::Close(Status::Closed(why)),
            Some(Verdict::Failed(why)) => return Want::Ask(Status::Waiting(why), key),
            None => return Want::Ask(Status::Waiting(NOT_SAID.to_string()), key),
        }
        let token = env.token.clone().filter(|t| !t.is_empty()).unwrap_or_else(|| key.clone());
        let name = env.name.clone().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| engine.machine_name.clone());
        Want::Run(Box::new(Config {
            hub,
            token,
            key,
            name,
            version: format!("app {}", crate::VERSION),
            timing: *self.timing.lock().unwrap(),
            proxy_env: proxy_env(),
        }))
    }

    /// tTerm asked which machine the key in the file is, in the background:
    /// at once for a key not asked about yet, again after the link's longest
    /// pause while tTerm cannot say, one question at a time. The account's
    /// own question at the start counts, and one it gave up on does not.
    fn ask(&self, engine: &Arc<Engine>, account: &Arc<Account>, key: String) {
        if self.asking.load(Ordering::SeqCst) {
            return;
        }
        {
            let again = self.timing.lock().unwrap().backoff_max;
            let mut asked = self.asked.lock().unwrap();
            if let Some((k, at)) = asked.as_ref() {
                if *k == key && at.elapsed() < again {
                    return;
                }
            }
            *asked = Some((key, Instant::now()));
        }
        self.asking.store(true, Ordering::SeqCst);
        let (engine, account) = (engine.clone(), account.clone());
        tokio::spawn(async move {
            account.ask_here_unless_said(&engine).await;
            engine.reach.asking.store(false, Ordering::SeqCst);
            engine.reach.nudge.notify_one();
        });
    }

    /// The agent's file as the person knows it: ~/.tterm-web/env.
    fn shown(&self) -> String {
        let home = crate::pty::home_dir();
        match self.env_file.strip_prefix(&home) {
            Ok(rest) if !home.as_os_str().is_empty() => format!("~/{}", rest.display()),
            _ => self.env_file.display().to_string(),
        }
    }

    fn gone(&self) -> String {
        format!("{}, with this computer's key, is gone (as after tTerm Web's agent is uninstalled).", self.shown())
    }

    fn start(&self, config: Config) -> Running {
        *self.problem.lock().unwrap() = None;
        let problem = self.problem.clone();
        let log: Log = Arc::new(move |msg: &str| {
            eprintln!("tterm: link: {msg}");
            // What stands in the way while it tries again: said in Settings.
            if let Some(rest) = msg.strip_prefix("no link (") {
                let why = rest.rsplit_once("), retrying").map(|(w, _)| w).unwrap_or(rest);
                *problem.lock().unwrap() = Some(why.to_string());
            } else if msg.starts_with("connected as ") {
                problem.lock().unwrap().take();
            }
        });
        let hosted = Hosted::new(config.timing, log.clone(), Some(self.agent_dir().to_string_lossy().to_string()));
        *self.hosted.lock().unwrap() = Some(hosted.clone());
        let keeper = hosted.spawn_keeper();
        let (stop, stop_rx) = watch::channel(false);
        let (shown, mut state) = watch::channel(State::Connecting);
        self.show(Status::Connecting);
        let (key, hub) = (config.key.clone(), config.hub.clone());
        let task = {
            let hosted = hosted.clone();
            tokio::spawn(async move { link::run_showing(&config, hosted, log, stop_rx, &shown).await })
        };
        let (status, nudge) = (self.status.clone(), self.nudge.clone());
        let watcher = tokio::spawn(async move {
            loop {
                let now = match &*state.borrow_and_update() {
                    State::Connecting => Some(Status::Connecting),
                    State::Connected { name } => Some(Status::Online { name: name.clone() }),
                    State::NoNetwork => Some(Status::NoNetwork),
                    // The keeper takes it in at once, from the link's outcome.
                    State::Revoked { .. } | State::Stopped => {
                        nudge.notify_one();
                        None
                    }
                };
                if let Some(now) = now {
                    status.send_if_modified(|was| {
                        if *was == now {
                            return false;
                        }
                        *was = now;
                        true
                    });
                }
                if state.changed().await.is_err() {
                    return;
                }
            }
        });
        Running { key, hub, stop, task, hosted, keeper, watcher }
    }

    /// The switch goes off by itself, and says why.
    fn went_away(&self, engine: &Engine, now: Status) {
        let why = match &now {
            Status::Removed(why) | Status::Closed(why) => why.clone(),
            other => format!("{other:?}"),
        };
        eprintln!("tterm: link: {why} Open from tTerm Web is off.");
        if let Err(e) = engine.save_settings(|s| s.open_from_web = Some(false)) {
            eprintln!("tterm: could not save the settings: {e}");
        }
        *self.went.lock().unwrap() = Some(now.clone());
        self.show(now);
    }

    /// The app quits: tTerm Web hears that its terminals end, and they end.
    /// What the app keeps for it (its login item) stays as it is.
    pub async fn stop(&self) {
        self.quitting.store(true, Ordering::SeqCst);
        let taken = self.running.lock().await.take();
        if let Some(r) = taken {
            self.finish(r).await;
        }
        self.show(Status::Off);
        self.nudge.notify_one();
    }

    /// Stops the link and waits, STOP_WAIT at most, for its goodbye and then
    /// for the shells of tTerm Web's terminals; how it ended, if it did.
    async fn finish(&self, r: Running) -> Option<Outcome> {
        let _ = r.stop.send(true);
        let Running { task, hosted, keeper, watcher, .. } = r;
        let abort = task.abort_handle();
        let outcome = match tokio::time::timeout(STOP_WAIT, task).await {
            Ok(Ok(outcome)) => Some(outcome),
            _ => {
                abort.abort();
                None
            }
        };
        let _ = tokio::time::timeout(STOP_WAIT, hosted.end_all()).await;
        keeper.abort();
        watcher.abort();
        let mut now = self.hosted.lock().unwrap();
        if now.as_ref().map(|h| Arc::ptr_eq(h, &hosted)).unwrap_or(false) {
            *now = None;
        }
        outcome
    }
}

fn other_hub(hub: &str) -> String {
    format!("This computer's agent connects to another tTerm Web ({hub}).")
}

/// The *_proxy variables the app was started with: tTerm Web through that
/// proxy, as the agent reached it (proxy.rs).
fn proxy_env() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(name, _)| name.to_ascii_lowercase().ends_with("_proxy"))
        .collect()
}

// ------------------------------------------------------------ the agent

fn agent_plist(home: &Path) -> PathBuf {
    home.join("Library").join("LaunchAgents").join(format!("{AGENT_LABEL}.plist"))
}

/// Whether tTerm Web's agent is set up on this computer: its autostart (it
/// runs from the next login, if not now), or one started by hand running.
/// The person said yes to opening the computer from there.
pub fn agent_set_up(home: &Path, dir: &Path) -> bool {
    if agent_plist(home).exists() {
        return true;
    }
    let pid = std::fs::read_to_string(dir.join("agent.pid")).ok().and_then(|t| t.trim().parse::<i32>().ok());
    pid.map(|pid| pid > 1 && agents_process(pid, dir)).unwrap_or(false)
}

/// Whether process `pid` is the agent's, by what it runs, as the installer
/// tells (`ours`): agent.pid outlives a restart, and its number may by then
/// be another program's.
fn agents_process(pid: i32, dir: &Path) -> bool {
    let out = std::process::Command::new("ps").args(["-o", "command=", "-p", &pid.to_string()]).output();
    match out {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).contains(&format!("{}/", dir.display())),
        _ => false,
    }
}

/// The agent stops for good, the app keeping the link now (on a Mac): its
/// autostart goes (else it starts again next to the app after a restart),
/// and one started without it, by its pid. Its settings stay, with the key;
/// its uninstaller is not run, as it takes the key too. What was done.
pub fn take_agents_place(home: &Path, dir: &Path) -> Vec<String> {
    let mut done = Vec::new();
    let quiet = |cmd: &str, args: &[&str]| {
        let _ = std::process::Command::new(cmd).args(args).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    };
    let plist = agent_plist(home);
    if cfg!(target_os = "macos") && plist.exists() {
        let path = plist.to_string_lossy().to_string();
        quiet("launchctl", &["unload", &path]);
        quiet("launchctl", &["remove", AGENT_LABEL]);
        match std::fs::remove_file(&plist) {
            Ok(()) => done.push(format!("the agent stopped, and its autostart went ({path})")),
            Err(e) => done.push(format!("the agent stopped; its autostart could not go ({path}: {e})")),
        }
    }
    let pid_file = dir.join("agent.pid");
    if let Ok(text) = std::fs::read_to_string(&pid_file) {
        if let Ok(pid) = text.trim().parse::<i32>() {
            if pid > 1 && agents_process(pid, dir) {
                // SAFETY: a signal to a process of this person's own.
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
                done.push(format!("the agent started by hand stopped (pid {pid})"));
            }
        }
        let _ = std::fs::remove_file(&pid_file);
    }
    done
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> PathBuf {
        let d = std::env::temp_dir().join(format!("tterm-reach-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(d.join(".tterm-web")).unwrap();
        d
    }

    #[test]
    fn the_agent_set_up_here_says_yes() {
        let h = home();
        let dir = h.join(".tterm-web");
        assert!(!agent_set_up(&h, &dir), "the app's own file is no agent");
        std::fs::write(dir.join("env"), "TTERM_KEY=k\n").unwrap();
        std::fs::write(dir.join("tterm-agent"), "").unwrap();
        assert!(!agent_set_up(&h, &dir), "its file alone runs nothing");
        // Started by hand, and running.
        let mut agent = std::process::Command::new("sh").args(["-c", &format!("sleep 30; : {}/tterm-agent", dir.display())]).spawn().unwrap();
        std::fs::write(dir.join("agent.pid"), agent.id().to_string()).unwrap();
        assert!(agent_set_up(&h, &dir));
        let _ = agent.kill();
        let _ = agent.wait();
        assert!(!agent_set_up(&h, &dir), "ended");
        // Its autostart.
        std::fs::create_dir_all(agent_plist(&h).parent().unwrap()).unwrap();
        std::fs::write(agent_plist(&h), "").unwrap();
        assert!(agent_set_up(&h, &dir));
        std::fs::remove_dir_all(&h).unwrap();
    }

    #[test]
    fn the_agent_by_hand_stops_and_another_program_does_not() {
        let h = home();
        let dir = h.join(".tterm-web");
        // The agent, as the installer starts it without autostart.
        let mut agent = std::process::Command::new("sh").args(["-c", &format!("sleep 30; : {}/tterm-agent", dir.display())]).spawn().unwrap();
        std::fs::write(dir.join("agent.pid"), agent.id().to_string()).unwrap();
        let done = take_agents_place(&h, &dir);
        assert!(done.iter().any(|d| d.contains("started by hand")), "{done:?}");
        let ended = (0..50).any(|_| {
            std::thread::sleep(Duration::from_millis(50));
            agent.try_wait().unwrap().is_some()
        });
        assert!(ended, "the agent ended");
        assert!(!dir.join("agent.pid").exists());
        // A number some other program has now: left alone.
        let mut other = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        std::fs::write(dir.join("agent.pid"), other.id().to_string()).unwrap();
        assert!(take_agents_place(&h, &dir).is_empty());
        assert!(other.try_wait().unwrap().is_none(), "not the agent's: it runs on");
        let _ = other.kill();
        let _ = other.wait();
        std::fs::remove_dir_all(&h).unwrap();
    }

    #[test]
    fn what_the_menu_bar_says() {
        assert_eq!(Status::Online { name: "MacBook".into() }.line("This Mac"), "MacBook: online in tTerm Web");
        assert_eq!(Status::Off.line("This Mac"), "This Mac is not opened from tTerm Web");
        assert_eq!(Status::Closed("x".into()).line("This Mac"), "This Mac is not opened from tTerm Web");
        assert_eq!(Status::Waiting("x".into()).line("This Mac"), "Connecting to tTerm Web…");
    }
}
