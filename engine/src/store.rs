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
//! What expired is taken out of the file itself, not only out of sight:
//! deleted rows are overwritten, the space they took goes back to the
//! disk, and the write-ahead log is emptied after each sweep. Commands
//! carry secrets at times (`export TOKEN=…`).

use crate::blocks::{self, Stored, FEED_MAX, HISTORY_MAX, KEEP_DAYS};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// How long a read waits for the writes before it, at most.
const READ_WAIT: Duration = Duration::from_secs(2);

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
    Ok(())
}

/// `PRAGMA auto_vacuum`'s value for INCREMENTAL.
const INCREMENTAL: i64 = 2;

fn prepare(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
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

impl Store {
    /// The store in `dir`. A file that cannot be read is kept aside and a
    /// new one made; if even that fails, the store lives in memory.
    pub fn open(dir: &Path) -> Arc<Store> {
        let path = dir.join(FILE);
        let (conn, path) = match open_file(&path) {
            Ok(c) => (c, Some(path)),
            Err(first) => {
                eprintln!("tterm: the store {} could not be opened ({first}); a new one is made", path.display());
                for suffix in ["", "-wal", "-shm"] {
                    let from = PathBuf::from(format!("{}{suffix}", path.display()));
                    if from.exists() {
                        let _ = std::fs::rename(&from, format!("{}.unreadable{suffix}", path.display()));
                    }
                }
                match open_file(&path) {
                    Ok(c) => (c, Some(path)),
                    Err(second) => {
                        eprintln!("tterm: no store on disk ({second}): the commands are kept until the app quits");
                        let c = Connection::open_in_memory().expect("a store in memory");
                        prepare(&c).expect("a store in memory");
                        (c, None)
                    }
                }
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
        Arc::new(Store { conn, jobs: Mutex::new(tx), pending, idle, path })
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
            c.execute(
                "INSERT INTO blocks (terminal_id, seq_start, seq_end, command, started_at, finished_at, exit_code,
                                     cwd, branch, output, output_cut, cols, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
                ],
            )?;
            Ok(())
        });
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
            // The log keeps copies of the pages it wrote: emptied too.
            c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
            Ok(())
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
        std::fs::write(d.join(FILE), b"this is not a database, and it is long enough to be read as one").unwrap();
        let s = Store::open(&d);
        assert!(s.path.is_some());
        s.opened("t", "1", 1);
        assert!(s.known("t").await);
        assert!(d.join(format!("{FILE}.unreadable")).exists());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
