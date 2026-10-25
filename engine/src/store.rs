//! What the app keeps of its terminals on this computer: the commands they
//! ran, as blocks, and how each terminal ended. The core keeps the same in
//! its database (the tables `terminals` and `blocks`); here it is a SQLite
//! file in the app's folder, private to the person (0600).
//!
//! Writes go in order through one thread, so that a terminal's row is there
//! before its blocks and its end, and nothing waits on the disk while it
//! holds a terminal. Reads first let what is on its way be written, so the
//! page reads what the stream has shown it.
//!
//! A command's output is kept compressed, its beginning and end if it was
//! long (see blocks.rs), for 30 days, as tTerm Web keeps it by default.
//! The notes made on this computer (notes.rs) live in the same file, in
//! tables of their own, and stay until they are deleted. From 0.3.1 a block
//! keeps its output as plain text too, for search (search.rs).
//! What expired is taken out of the file itself, not only out of sight:
//! deleted rows are overwritten, the space they took goes back to the
//! disk, and the write-ahead log is emptied after each sweep (if a search
//! was reading just then, after the next one). Commands carry secrets at
//! times (`export TOKEN=…`).

use crate::blocks::{self, Stored, FEED_MAX, HISTORY_MAX, KEEP_DAYS};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// How long a read waits for the writes before it, at most.
const READ_WAIT: Duration = Duration::from_secs(2);
/// How long SQLite waits for the file when another connection holds it.
const BUSY_WAIT: Duration = Duration::from_secs(5);
/// Of that, the sweep's emptying of the log, which waits for any search.
const SWEEP_WAIT: Duration = Duration::from_millis(100);

pub const FILE: &str = "tterm.db";

/// A block that finished, on its way to the store.
#[derive(Debug, Default)]
pub struct Finished {
    pub seq_start: u64,
    pub seq_end: u64,
    pub command: String,
    pub started_ms: i64,
    pub finished_ms: i64,
    pub exit_code: Option<i64>,
    pub cwd: String,
    pub branch: String,
    /// As the terminal printed it; compressed on the way.
    pub output: Vec<u8>,
    pub cut: bool,
    pub cols: u16,
}

/// What the store remembers of a terminal no longer in memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndedRow {
    pub name: String,
    pub home: Option<String>,
    pub reason: Option<String>,
}

type Job = Box<dyn FnOnce(&Connection) + Send>;

pub struct Store {
    conn: Arc<Mutex<Connection>>,
    jobs: Mutex<mpsc::Sender<Job>>,
    pending: Arc<AtomicUsize>,
    idle: Arc<Notify>,
    /// Where it is, or None when it lives in memory only (the file could not
    /// be opened: the app works, and forgets).
    pub path: Option<PathBuf>,
    /// What went wrong with the file when the app started, in words for the
    /// person: the app says it when its window opens.
    pub trouble: Option<String>,
    /// Search's own connection to the file (from 0.3.1): it reads beside the
    /// writes (WAL), so a long search holds up nothing else.
    searcher: Mutex<Option<Connection>>,
    /// The latest search asked for: one before it is not wanted any more.
    searches: AtomicU64,
    /// The search running, and how to stop it.
    searching: Mutex<Option<(u64, rusqlite::InterruptHandle)>>,
}

/// Search's connection: the same file, for reading only.
fn open_searcher(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(BUSY_WAIT)?;
    conn.execute_batch("PRAGMA query_only = ON;")?;
    crate::search::register(&conn)?;
    Ok(conn)
}

fn now_ms() -> i64 {
    crate::terminals::now_ms()
}

fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 1 {
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS terminals (
                 id          TEXT PRIMARY KEY,
                 name        TEXT NOT NULL,
                 opened_at   INTEGER NOT NULL,
                 closed_at   INTEGER,
                 end_reason  TEXT,
                 shell       TEXT,
                 home        TEXT,
                 last_seq    INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS blocks (
                 id          INTEGER PRIMARY KEY,
                 terminal_id TEXT NOT NULL REFERENCES terminals (id) ON DELETE CASCADE,
                 seq_start   INTEGER NOT NULL,
                 seq_end     INTEGER,
                 command     TEXT,
                 started_at  INTEGER NOT NULL,
                 finished_at INTEGER,
                 exit_code   INTEGER,
                 cwd         TEXT,
                 branch      TEXT,
                 output      BLOB,
                 output_cut  INTEGER NOT NULL DEFAULT 0,
                 cols        INTEGER,
                 expires_at  INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS blocks_terminal ON blocks (terminal_id, seq_start);
             CREATE INDEX IF NOT EXISTS blocks_expiry ON blocks (expires_at);
             PRAGMA user_version = 1;
             COMMIT;",
        )?;
    }
    if version < 2 {
        // Notes, from 0.2.0.
        conn.execute_batch(&format!("BEGIN; {} PRAGMA user_version = 2; COMMIT;", crate::notes::TABLES))?;
    }
    if version < 3 {
        // What a command printed, as text to search (from 0.3.1): made with
        // each block, and for those from before in the background
        // (fill_texts).
        conn.execute_batch("BEGIN; ALTER TABLE blocks ADD COLUMN output_text TEXT; PRAGMA user_version = 3; COMMIT;")?;
    }
    // Not by version: a file of a build made before them gets them too. The
    // ids the notes are kept under (identity, a build of 0.2.0); the order
    // search reads the blocks in, the latest first (a build of 0.3.1).
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE INDEX IF NOT EXISTS blocks_started ON blocks (started_at);",
    )?;
    Ok(())
}

/// `PRAGMA auto_vacuum`'s value for INCREMENTAL.
const INCREMENTAL: i64 = 2;

fn prepare(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(BUSY_WAIT)?;
    // Space freed by old blocks goes back to the disk. Set before anything
    // writes the file's first page (WAL does): later SQLite keeps the old
    // setting until a VACUUM, which a file made otherwise gets once here.
    conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")?;
    let mode: i64 = conn.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?;
    if mode != INCREMENTAL {
        conn.execute_batch("VACUUM;")?;
    }
    let _: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    // Deleted rows are overwritten, not only let go.
    conn.execute_batch("PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;")?;
    crate::search::register(conn)?;
    migrate(conn)
}

/// The file, made private before SQLite makes it: its journal files take
/// the same permissions.
fn open_file(path: &Path) -> rusqlite::Result<Connection> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if !path.exists() {
            let _ = std::fs::OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).open(path);
        }
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    let conn = Connection::open(path)?;
    prepare(&conn)?;
    Ok(conn)
}

/// Whether SQLite found the file damaged, or no database at all: then, and
/// only then, it is kept aside for a new one. A file busy or out of reach
/// for a moment stays as it is, for the next run.
fn damaged(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if matches!(f.code, rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase))
}

/// A store in memory: the app works, and forgets when it quits.
fn in_memory() -> Connection {
    let c = Connection::open_in_memory().expect("a store in memory");
    prepare(&c).expect("a store in memory");
    c
}

impl Store {
    /// The store in `dir`. A damaged file is kept aside, under a name of its
    /// own that no later one takes, and a new one made; a file that cannot
    /// be opened otherwise is left alone, and the store lives in memory
    /// until the app quits. Either way `trouble` says so.
    pub fn open(dir: &Path) -> Arc<Store> {
        let path = dir.join(FILE);
        let shown = path.display().to_string();
        let unopened = |e: &rusqlite::Error| {
            eprintln!("tterm: no store on disk ({e}): the commands are kept until the app quits");
            format!(
                "tTerm could not open its file on this computer ({shown}: {e}). Until it can, notes cannot be kept, and commands are kept only until tTerm quits. Quit tTerm and open it again."
            )
        };
        let (conn, path, trouble) = match open_file(&path) {
            Ok(c) => (c, Some(path), None),
            Err(first) if damaged(&first) => {
                let aside = format!("{}.unreadable-{}", path.display(), now_ms());
                eprintln!("tterm: the store {} is damaged ({first}): kept as {aside}, a new one is made", path.display());
                for suffix in ["", "-wal", "-shm"] {
                    let from = PathBuf::from(format!("{}{suffix}", path.display()));
                    if from.exists() {
                        let _ = std::fs::rename(&from, format!("{aside}{suffix}"));
                    }
                }
                match open_file(&path) {
                    Ok(c) => {
                        let told = format!(
                            "tTerm could not read its file on this computer: it was damaged. It is kept as {aside}, and a new one was made. The notes and the commands from before are in the old file."
                        );
                        (c, Some(path), Some(told))
                    }
                    Err(second) => {
                        let told = unopened(&second);
                        (in_memory(), None, Some(told))
                    }
                }
            }
            Err(first) => {
                let told = unopened(&first);
                (in_memory(), None, Some(told))
            }
        };
        let conn = Arc::new(Mutex::new(conn));
        let pending = Arc::new(AtomicUsize::new(0));
        let idle = Arc::new(Notify::new());
        let (tx, rx) = mpsc::channel::<Job>();
        {
            let conn = conn.clone();
            let pending = pending.clone();
            let idle = idle.clone();
            std::thread::Builder::new()
                .name("tterm-store".into())
                .spawn(move || {
                    while let Ok(job) = rx.recv() {
                        {
                            let c = conn.lock().unwrap_or_else(|e| e.into_inner());
                            job(&c);
                        }
                        if pending.fetch_sub(1, Ordering::SeqCst) == 1 {
                            idle.notify_waiters();
                        }
                    }
                })
                .expect("the store's thread");
        }
        Arc::new(Store { conn, jobs: Mutex::new(tx), pending, idle, path, trouble, searcher: Mutex::new(None), searches: AtomicU64::new(0), searching: Mutex::new(None) })
    }

    /// The ids of the person and of Personal that the notes are kept under.
    /// They live here, with the notes, and the first run writes those of the
    /// settings: a settings file made anew (lost, or unreadable) takes them
    /// back, rather than hiding every note behind new ones. At start, before
    /// anything else waits on the store.
    pub fn identity(&self, person: &str, project: &str) -> (String, String) {
        let c = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let read = |key: &str| c.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| r.get::<_, String>(0)).optional();
        match (read("person_id"), read("project_id")) {
            (Ok(Some(p)), Ok(Some(j))) => (p, j),
            (Ok(None), Ok(None)) => {
                let saved = c.execute("INSERT INTO meta (key, value) VALUES ('person_id', ?1), ('project_id', ?2)", params![person, project]);
                if let Err(e) = saved {
                    eprintln!("tterm: could not keep the ids of the notes: {e}");
                }
                (person.to_string(), project.to_string())
            }
            // Half there, or not readable: nothing is written over them.
            (p, j) => {
                eprintln!("tterm: the ids of the notes could not be read ({p:?}, {j:?}): this run uses those of the settings");
                (person.to_string(), project.to_string())
            }
        }
    }

    fn write(&self, job: impl FnOnce(&Connection) -> rusqlite::Result<()> + Send + 'static) {
        self.pending.fetch_add(1, Ordering::SeqCst);
        let job: Job = Box::new(move |c| {
            if let Err(e) = job(c) {
                eprintln!("tterm: could not write to the store: {e}");
            }
        });
        if self.jobs.lock().unwrap().send(job).is_err() {
            self.pending.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Runs `job` on the store, in turn with the writes sent before it, and
    /// gives back what it returns: for what reads and writes at once, such
    /// as a note's save. None if the store's thread is gone.
    pub async fn run<T: Send + 'static>(&self, job: impl FnOnce(&Connection) -> T + Send + 'static) -> Option<T> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.fetch_add(1, Ordering::SeqCst);
        let job: Job = Box::new(move |c| {
            let _ = tx.send(job(c));
        });
        if self.jobs.lock().unwrap().send(job).is_err() {
            self.pending.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        rx.await.ok()
    }

    /// Runs a search, `job`, on search's own connection, beside the writes:
    /// what it reads is what was written, once what was on its way is. A newer search stops this one: the
    /// statement running is interrupted, and `job` is told between its own
    /// (its second argument says whether it is still wanted). None for a
    /// search not wanted any more, or without a store. In memory only, the
    /// one connection there is, in turn with the writes.
    pub async fn search<T: Send + 'static>(self: &Arc<Self>, job: impl FnOnce(&Connection, &dyn Fn() -> bool) -> rusqlite::Result<T> + Send + 'static) -> Option<rusqlite::Result<T>> {
        let Some(path) = self.path.clone() else {
            return self.run(move |c| job(c, &|| true)).await;
        };
        let asked = self.searches.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some((_, running)) = self.searching.lock().unwrap().take() {
            running.interrupt();
        }
        // What is on its way to the file first, as for any read: a command
        // that just ended is found.
        self.flush(READ_WAIT).await;
        let me = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut searcher = me.searcher.lock().unwrap_or_else(|e| e.into_inner());
            let wanted = || me.searches.load(Ordering::SeqCst) == asked;
            if !wanted() {
                return None;
            }
            if searcher.is_none() {
                match open_searcher(&path) {
                    Ok(c) => *searcher = Some(c),
                    Err(e) => {
                        eprintln!("tterm: search could not open the store: {e}");
                        return None;
                    }
                }
            }
            let conn = searcher.as_ref()?;
            *me.searching.lock().unwrap() = Some((asked, conn.get_interrupt_handle()));
            // Asked again since: not started at all.
            let found = if wanted() { Some(job(conn, &wanted)) } else { None };
            let mut running = me.searching.lock().unwrap();
            if running.as_ref().map(|(n, _)| *n == asked).unwrap_or(false) {
                *running = None;
            }
            found
        })
        .await
        .ok()
        .flatten()
    }

    /// Waits until what was sent to be written is written, at most `wait`;
    /// whether it all was.
    pub async fn flush(&self, wait: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.pending.load(Ordering::SeqCst) == 0 {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.pending.load(Ordering::SeqCst) == 0;
            }
        }
    }

    async fn read<T: Send + 'static>(&self, query: impl FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static) -> Option<T> {
        self.flush(READ_WAIT).await;
        let conn = self.conn.clone();
        let got = tokio::task::spawn_blocking(move || {
            let c = conn.lock().unwrap_or_else(|e| e.into_inner());
            query(&c)
        })
        .await;
        match got {
            Ok(Ok(value)) => Some(value),
            Ok(Err(e)) => {
                eprintln!("tterm: could not read the store: {e}");
                None
            }
            Err(_) => None,
        }
    }

    // ------------------------------------------------------------ writes

    /// Terminals do not outlive the app: any left open by the last run (it
    /// was stopped, or it crashed) ended with it.
    pub fn close_left_open(&self, reason: &str) {
        let reason = reason.to_string();
        self.write(move |c| {
            c.execute("UPDATE terminals SET closed_at = ?1, end_reason = ?2 WHERE closed_at IS NULL", params![now_ms(), reason])?;
            Ok(())
        });
    }

    pub fn opened(&self, id: &str, name: &str, opened_ms: i64) {
        let (id, name) = (id.to_string(), name.to_string());
        self.write(move |c| {
            c.execute("INSERT OR IGNORE INTO terminals (id, name, opened_at) VALUES (?1, ?2, ?3)", params![id, name, opened_ms])?;
            Ok(())
        });
    }

    pub fn renamed(&self, id: &str, name: &str) {
        let (id, name) = (id.to_string(), name.to_string());
        self.write(move |c| {
            c.execute("UPDATE terminals SET name = ?2 WHERE id = ?1", params![id, name])?;
            Ok(())
        });
    }

    pub fn ended(&self, id: &str, last_seq: u64, reason: &str, shell: Option<&str>, home: &str) {
        let (id, shell) = (id.to_string(), shell.map(str::to_string));
        let reason: String = reason.chars().take(500).collect();
        let home = (!home.is_empty()).then(|| home.to_string());
        self.write(move |c| {
            c.execute(
                "UPDATE terminals SET closed_at = ?2, last_seq = ?3, end_reason = ?4, shell = ?5, home = ?6 WHERE id = ?1",
                params![id, now_ms(), last_seq as i64, reason, shell, home],
            )?;
            Ok(())
        });
    }

    pub fn save_block(&self, id: &str, block: Finished) {
        let id = id.to_string();
        self.write(move |c| {
            let output = blocks::compress(&block.output);
            let text = crate::search::plain(&block.output);
            c.execute(
                "INSERT INTO blocks (terminal_id, seq_start, seq_end, command, started_at, finished_at, exit_code,
                                     cwd, branch, output, output_cut, cols, expires_at, output_text)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    id,
                    block.seq_start as i64,
                    block.seq_end as i64,
                    block.command,
                    block.started_ms,
                    block.finished_ms,
                    block.exit_code,
                    (!block.cwd.is_empty()).then_some(&block.cwd),
                    (!block.branch.is_empty()).then_some(&block.branch),
                    output,
                    block.cut,
                    block.cols as i64,
                    block.finished_ms + KEEP_DAYS * DAY_MS,
                    text,
                ],
            )?;
            Ok(())
        });
    }

    /// The text to search for blocks kept before 0.3.1, the newest first, a
    /// few at a time with a pause between: the store goes on serving
    /// meanwhile, and the unpacking is not on its thread. How many got it.
    pub async fn fill_texts(&self) -> usize {
        const BATCH: i64 = 50;
        let mut done = 0;
        loop {
            let batch = self
                .run(|c| -> rusqlite::Result<Vec<(i64, Option<Vec<u8>>)>> {
                    let mut st = c.prepare("SELECT id, output FROM blocks WHERE output_text IS NULL ORDER BY id DESC LIMIT ?1")?;
                    let rows = st.query_map(params![BATCH], |r| Ok((r.get(0)?, r.get(1)?)))?;
                    rows.collect()
                })
                .await;
            let batch = match batch {
                Some(Ok(b)) if !b.is_empty() => b,
                Some(Err(e)) => {
                    eprintln!("tterm: could not read the blocks to make their text: {e}");
                    return done;
                }
                _ => return done,
            };
            let texts = tokio::task::spawn_blocking(move || {
                batch
                    .into_iter()
                    .map(|(id, z)| {
                        let text = match z {
                            Some(z) if !z.is_empty() => crate::search::plain(&blocks::decompress(&z)),
                            _ => String::new(),
                        };
                        (id, text)
                    })
                    .collect::<Vec<_>>()
            })
            .await;
            let Ok(texts) = texts else { return done };
            let n = texts.len();
            let written = self
                .run(move |c| -> rusqlite::Result<()> {
                    let tx = c.unchecked_transaction()?;
                    {
                        let mut st = tx.prepare("UPDATE blocks SET output_text = ?2 WHERE id = ?1")?;
                        for (id, text) in &texts {
                            st.execute(params![id, text])?;
                        }
                    }
                    tx.commit()
                })
                .await;
            if !matches!(written, Some(Ok(()))) {
                eprintln!("tterm: could not keep the text of earlier blocks: {written:?}");
                return done;
            }
            done += n;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Lets go of what expired: blocks after 30 days, and terminals ended
    /// as long ago with nothing left of them.
    pub fn sweep(&self) {
        self.write(|c| {
            let now = now_ms();
            c.execute("DELETE FROM blocks WHERE expires_at <= ?1", params![now])?;
            c.execute(
                "DELETE FROM terminals WHERE closed_at IS NOT NULL AND closed_at < ?1
                   AND NOT EXISTS (SELECT 1 FROM blocks WHERE blocks.terminal_id = terminals.id)",
                params![now - KEEP_DAYS * DAY_MS],
            )?;
            // A row for each page it gives back: stepped to the end.
            let mut vacuum = c.prepare("PRAGMA incremental_vacuum")?;
            let mut pages = vacuum.query([])?;
            while pages.next()?.is_some() {}
            drop(pages);
            drop(vacuum);
            // The log keeps copies of the pages it wrote: emptied too. Not
            // while a search reads (on its own connection): emptying waits
            // for it, and every write would wait with it. Then the next time.
            c.busy_timeout(SWEEP_WAIT)?;
            let emptied = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
            c.busy_timeout(BUSY_WAIT)?;
            emptied
        });
    }

    // ------------------------------------------------------------- reads

    /// Whether the store knows the terminal.
    pub async fn known(&self, id: &str) -> bool {
        let id = id.to_string();
        self.read(move |c| c.query_row("SELECT 1 FROM terminals WHERE id = ?1", params![id], |_| Ok(())).optional())
            .await
            .flatten()
            .is_some()
    }

    /// The terminal's finished blocks, the latest `limit` of those that
    /// started before the number `before`, oldest first, each with the end
    /// of its output: `{blocks, more}`. None if the store does not know it.
    pub async fn feed(&self, id: &str, before: Option<i64>, limit: i64) -> Option<Value> {
        if !self.known(id).await {
            return None;
        }
        let id = id.to_string();
        let limit = limit.clamp(1, FEED_MAX);
        let rows = self
            .read(move |c| {
                let mut st = c.prepare(
                    "SELECT id, seq_start, seq_end, command, cwd, branch, started_at, finished_at, exit_code,
                            output, output_cut, cols
                     FROM blocks
                     WHERE terminal_id = ?1 AND expires_at > ?2 AND (?3 IS NULL OR seq_start < ?3)
                     ORDER BY seq_start DESC
                     LIMIT ?4",
                )?;
                let rows = st.query_map(params![id, now_ms(), before, limit + 1], |r| {
                    Ok(Stored {
                        id: r.get(0)?,
                        seq_start: r.get(1)?,
                        seq_end: r.get(2)?,
                        command: r.get(3)?,
                        cwd: r.get(4)?,
                        branch: r.get(5)?,
                        started_ms: r.get(6)?,
                        finished_ms: r.get(7)?,
                        exit_code: r.get(8)?,
                        output: r.get(9)?,
                        cut: r.get(10)?,
                        cols: r.get(11)?,
                    })
                })?;
                rows.collect::<rusqlite::Result<Vec<Stored>>>()
            })
            .await?;
        let more = rows.len() as i64 > limit;
        // Unpacking a few megabytes is work: not on the async threads.
        let blocks = tokio::task::spawn_blocking(move || rows.into_iter().take(limit as usize).rev().map(|r| blocks::feed_json(&r)).collect::<Vec<Value>>()).await.ok()?;
        Some(serde_json::json!({"blocks": blocks, "more": more}))
    }

    /// All a block kept of its output, and whether its middle was cut.
    pub async fn block_output(&self, id: &str, seq_start: i64) -> Option<(Vec<u8>, bool)> {
        let id = id.to_string();
        let row: Option<(Option<Vec<u8>>, bool)> = self
            .read(move |c| {
                c.query_row(
                    "SELECT output, output_cut FROM blocks WHERE terminal_id = ?1 AND seq_start = ?2 AND expires_at > ?3",
                    params![id, seq_start, now_ms()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
            })
            .await
            .flatten();
        let (data, cut) = row?;
        let output = match data {
            Some(z) if !z.is_empty() => tokio::task::spawn_blocking(move || blocks::decompress(&z)).await.ok()?,
            _ => Vec::new(),
        };
        Some((output, cut))
    }

    /// The commands for the input line's history, newest first, each once.
    /// The core gives a person's commands across the project, those of the
    /// terminal's own machine first; here every terminal is on this
    /// computer. None if the store does not know the terminal.
    pub async fn history(&self, id: &str) -> Option<Vec<String>> {
        if !self.known(id).await {
            return None;
        }
        self.read(move |c| {
            let mut st = c.prepare(
                "SELECT command FROM blocks
                 WHERE command IS NOT NULL AND command <> '' AND expires_at > ?1
                 GROUP BY command
                 ORDER BY max(started_at) DESC, max(id) DESC
                 LIMIT ?2",
            )?;
            let rows = st.query_map(params![now_ms(), HISTORY_MAX], |r| r.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<String>>>()
        })
        .await
    }

    /// A terminal no longer in memory, as the store remembers it.
    pub async fn ended_row(&self, id: &str) -> Option<EndedRow> {
        let id = id.to_string();
        self.read(move |c| {
            c.query_row("SELECT name, home, end_reason FROM terminals WHERE id = ?1", params![id], |r| {
                Ok(EndedRow { name: r.get(0)?, home: r.get(1)?, reason: r.get(2)? })
            })
            .optional()
        })
        .await
        .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("tterm-store-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn block(seq: u64, command: &str, at: i64) -> Finished {
        Finished { seq_start: seq, seq_end: seq + 2, command: command.into(), started_ms: at, finished_ms: at + 5, exit_code: Some(0), cwd: "/h".into(), output: format!("{command}\r\n").into_bytes(), cols: 80, ..Default::default() }
    }

    #[tokio::test]
    async fn blocks_and_history_are_kept() {
        let d = dir();
        let s = Store::open(&d);
        assert!(s.path.is_some());
        s.opened("t1", "1", 1);
        let now = now_ms();
        for (i, c) in ["echo first", "seq 1 3", "echo first", "echo last"].iter().enumerate() {
            s.save_block("t1", block(10 * (i as u64 + 1), c, now + i as i64));
        }
        let feed = s.feed("t1", None, 60).await.unwrap();
        let commands: Vec<&str> = feed["blocks"].as_array().unwrap().iter().map(|b| b["command"].as_str().unwrap()).collect();
        assert_eq!(commands, ["echo first", "seq 1 3", "echo first", "echo last"]);
        assert_eq!(feed["more"], false);
        let b = &feed["blocks"][1];
        assert_eq!(b["seqStart"], 20);
        assert_eq!(b["seqEnd"], 22);
        assert_eq!(b["cwd"], "/h");
        assert_eq!(b["branch"], "");
        assert_eq!(b["cols"], 80);
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(b["output"].as_str().unwrap()).unwrap(), b"seq 1 3\r\n");
        let two = s.feed("t1", None, 2).await.unwrap();
        assert_eq!(two["blocks"].as_array().unwrap().len(), 2);
        assert_eq!(two["blocks"][0]["command"], "echo first");
        assert_eq!(two["more"], true);
        let before = s.feed("t1", Some(30), 60).await.unwrap();
        assert_eq!(before["blocks"].as_array().unwrap().len(), 2);
        assert_eq!(s.history("t1").await.unwrap(), ["echo last", "echo first", "seq 1 3"]);
        assert_eq!(s.block_output("t1", 20).await.unwrap(), (b"seq 1 3\r\n".to_vec(), false));
        assert!(s.block_output("t1", 21).await.is_none());
        assert!(s.feed("nobody", None, 60).await.is_none());
        assert!(s.history("nobody").await.is_none());

        s.renamed("t1", "work");
        s.ended("t1", 99, "The shell ended with code 0.", Some("zsh"), "/h");
        let row = s.ended_row("t1").await.unwrap();
        assert_eq!(row, EndedRow { name: "work".into(), home: Some("/h".into()), reason: Some("The shell ended with code 0.".into()) });

        // Remembered by the next run of the app; one left open ended with
        // the last.
        s.opened("t2", "2", 2);
        assert!(s.flush(Duration::from_secs(5)).await);
        drop(s);
        let again = Store::open(&d);
        again.close_left_open("tTerm stopped.");
        assert_eq!(again.ended_row("t2").await.unwrap().reason.as_deref(), Some("tTerm stopped."));
        assert_eq!(again.feed("t1", None, 60).await.unwrap()["blocks"].as_array().unwrap().len(), 4);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.join(FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "the store is private: {mode:o}");
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// From 0.3.1: search reads beside the writes, and a newer search stops
    /// the one before, running or waiting.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn search_reads_beside_the_writes_and_gives_way_to_a_newer_one() {
        let d = dir();
        let s = Store::open(&d);
        s.opened("t", "1", 1);
        s.save_block("t", block(5, "echo a", now_ms()));
        assert!(s.flush(Duration::from_secs(5)).await);
        const LONG: &str = "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 2000000000) SELECT count(*) FROM n";
        let long = {
            let s = s.clone();
            tokio::spawn(async move { s.search(|c, _| c.query_row(LONG, [], |r| r.get::<_, i64>(0))).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Meanwhile the store writes and reads as ever.
        let started = std::time::Instant::now();
        s.save_block("t", block(9, "echo b", now_ms()));
        let feed = s.feed("t", None, 60).await.unwrap();
        assert_eq!(feed["blocks"].as_array().unwrap().len(), 2);
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
        // A newer one: the long one is stopped where it is.
        let started = std::time::Instant::now();
        let newer = s.search(|c, _| c.query_row("SELECT count(*) FROM blocks", [], |r| r.get::<_, i64>(0))).await;
        assert_eq!(newer.unwrap().unwrap(), 2);
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        assert!(matches!(long.await.unwrap(), Some(Err(_))), "the long one was stopped");
        // Between its statements a search cannot be stopped: one asked for
        // meanwhile waits, and once a newer one is asked for, does not run.
        let busy = {
            let s = s.clone();
            tokio::spawn(async move {
                s.search(|_, wanted| {
                    std::thread::sleep(Duration::from_millis(800));
                    Ok(wanted())
                })
                .await
            })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        let waiting = {
            let s = s.clone();
            tokio::spawn(async move { s.search(|_, _| Ok(true)).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        let latest = s.search(|_, _| Ok(true)).await;
        assert!(matches!(latest, Some(Ok(true))), "the latest runs");
        assert!(matches!(busy.await.unwrap(), Some(Ok(false))), "the busy one ran, and learnt it was not wanted");
        assert!(waiting.await.unwrap().is_none(), "the one waiting did not run");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_sweep_does_not_hold_up_the_writes_for_a_search() {
        let d = dir();
        let s = Store::open(&d);
        s.opened("t", "1", 1);
        for i in 0..20 {
            s.save_block("t", block(10 * i + 5, "echo a", now_ms()));
        }
        assert!(s.flush(Duration::from_secs(5)).await);
        // A search that reads a while, the log as it is.
        let reading = {
            let s = s.clone();
            tokio::spawn(async move {
                s.search(|c, _| {
                    let mut st = c.prepare("SELECT id FROM blocks")?;
                    let mut rows = st.query([])?;
                    rows.next()?;
                    std::thread::sleep(Duration::from_secs(3));
                    Ok(())
                })
                .await
            })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        let started = std::time::Instant::now();
        s.sweep();
        s.save_block("t", block(500, "echo b", now_ms()));
        assert!(s.flush(Duration::from_secs(5)).await);
        assert!(started.elapsed() < Duration::from_millis(1500), "the writes waited for the search: {:?}", started.elapsed());
        assert!(matches!(reading.await.unwrap(), Some(Ok(()))), "the search was not stopped");
        // The log is emptied the next time.
        s.sweep();
        assert!(s.flush(Duration::from_secs(5)).await);
        assert_eq!(std::fs::metadata(d.join(format!("{FILE}-wal"))).map(|m| m.len()).unwrap_or(0), 0);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn a_file_made_without_the_index_of_search_gets_it() {
        let d = dir();
        let s = Store::open(&d);
        s.run(|c| c.execute_batch("DROP INDEX blocks_started")).await.unwrap().unwrap();
        drop(s);
        let again = Store::open(&d);
        let has: i64 = again
            .read(|c| c.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'blocks_started'", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(has, 1, "a file of the first build of 0.3.1 is at version 3 already");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn what_expired_goes() {
        let d = dir();
        let s = Store::open(&d);
        s.opened("t", "1", 1);
        let long_ago = now_ms() - 31 * DAY_MS;
        s.save_block("t", block(5, "old", long_ago));
        s.save_block("t", block(9, "new", now_ms()));
        let feed = s.feed("t", None, 60).await.unwrap();
        assert_eq!(feed["blocks"].as_array().unwrap().len(), 1, "expired blocks are not shown");
        assert_eq!(s.history("t").await.unwrap(), ["new"]);
        s.sweep();
        let left: i64 = s.read(|c| c.query_row("SELECT count(*) FROM blocks", [], |r| r.get(0))).await.unwrap();
        assert_eq!(left, 1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn what_expired_leaves_the_file_too() {
        let d = dir();
        let s = Store::open(&d);
        let mode: i64 = s.read(|c| c.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))).await.unwrap();
        assert_eq!(mode, INCREMENTAL);
        s.opened("t", "1", 1);
        let long_ago = now_ms() - 31 * DAY_MS;
        // Output that does not compress: the file grows by it.
        let mut noise = Vec::with_capacity(4_000_000);
        let mut x: u64 = 7;
        for _ in 0..4_000_000 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            noise.push((x >> 56) as u8);
        }
        for i in 0..4 {
            let mut b = block(10 * i, "export TOKEN=SECRET-MARKER-123", long_ago);
            b.output = noise[i as usize * 1_000_000..(i as usize + 1) * 1_000_000].to_vec();
            s.save_block("t", b);
        }
        s.save_block("t", block(99, "echo kept", now_ms()));
        assert!(s.flush(Duration::from_secs(10)).await);
        let file = d.join(FILE);
        let wal = d.join(format!("{FILE}-wal"));
        let size = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        let before = size(&file) + size(&wal);
        assert!(before > 3_000_000, "{before}");
        s.sweep();
        assert!(s.flush(Duration::from_secs(10)).await);
        let after = size(&file) + size(&wal);
        assert!(after < before / 4, "the file did not shrink: {before} → {after}");
        for f in [&file, &wal] {
            let bytes = std::fs::read(f).unwrap_or_default();
            assert!(!bytes.windows(17).any(|w| w == b"SECRET-MARKER-123"), "an expired command is still in {}", f.display());
        }
        assert_eq!(s.history("t").await.unwrap(), ["echo kept"]);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn an_unreadable_file_is_kept_aside() {
        let d = dir();
        let aside = |d: &Path| {
            let mut found: Vec<Vec<u8>> = std::fs::read_dir(d)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with(&format!("{FILE}.unreadable-")))
                .map(|e| std::fs::read(e.path()).unwrap())
                .collect();
            found.sort();
            found
        };
        std::fs::write(d.join(FILE), b"this is not a database, and it is long enough to be read as one").unwrap();
        let s = Store::open(&d);
        assert!(s.path.is_some());
        assert!(s.trouble.as_deref().unwrap().contains("damaged"), "{:?}", s.trouble);
        s.opened("t", "1", 1);
        assert!(s.known("t").await);
        assert_eq!(aside(&d).len(), 1);
        // Left as the app leaves it when it quits: all in the file, nothing
        // on its way to it. The store's thread closes the file some time
        // after the store is gone, and in WAL mode that close writes the
        // file once more: over the damage written below, which made it a
        // database again on a busy computer (nothing kept the second time).
        let mode = s.run(|c| c.query_row("PRAGMA journal_mode = DELETE", [], |r| r.get::<_, String>(0))).await;
        assert_eq!(mode.unwrap().unwrap(), "delete");
        drop(s);
        // Damaged again: the copy kept the first time stays as it was. (The
        // pause gives the second copy a name of its own.)
        tokio::time::sleep(Duration::from_millis(5)).await;
        std::fs::write(d.join(FILE), b"and this one is not a database either, damaged a second time").unwrap();
        let again = Store::open(&d);
        assert!(again.path.is_some());
        let kept = aside(&d);
        assert_eq!(kept.len(), 2, "each damaged file is kept");
        assert!(kept.iter().any(|k| k.starts_with(b"this is not a database")));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn a_file_out_of_reach_is_left_alone() {
        let d = dir();
        // A folder where the file should be: SQLite cannot open it, and it
        // is not damaged; nothing is moved, the store lives in memory.
        std::fs::create_dir(d.join(FILE)).unwrap();
        let s = Store::open(&d);
        assert!(s.path.is_none());
        assert!(s.trouble.as_deref().unwrap().contains("notes cannot be kept"), "{:?}", s.trouble);
        assert!(d.join(FILE).is_dir(), "left where it was");
        s.opened("t", "1", 1);
        assert!(s.known("t").await, "the store works, in memory");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn the_ids_of_the_notes_are_kept_with_them() {
        let d = dir();
        let s = Store::open(&d);
        assert_eq!(s.identity("p1", "j1"), ("p1".to_string(), "j1".to_string()), "the first run writes them");
        assert_eq!(s.identity("p2", "j2"), ("p1".to_string(), "j1".to_string()), "later runs read them");
        drop(s);
        let again = Store::open(&d);
        assert_eq!(again.identity("p3", "j3"), ("p1".to_string(), "j1".to_string()));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
