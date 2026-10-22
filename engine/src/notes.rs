//! Notes on this computer: a port of tterm-web's `tterm/core/notes.py`
//! (notes came to the web in 0.1.0), with its rules and its words, for the
//! notes the page makes before anyone signs in (from 0.2.0 of the app).
//!
//! A note is a title and a list of blocks: a paragraph, a heading, a list
//! item, a checklist item, code, and a divider. The page turns Markdown into
//! blocks as it is typed; the engine keeps them as JSON, as the core does,
//! and the page shows them as text, never as HTML.
//!
//! Notes live in folders of Personal, the one project here, whose owner is
//! the person of this computer: they do everything the core lets an owner
//! do. Every save names the version it was made from, and one made from an
//! older version is merged with what was saved since, block by block, as the
//! core merges a save from another device (here it would come from another
//! tab). The same block changed both ways is a conflict, and the page asks
//! whose to keep. A tick is a change of its own: who ticked and when come
//! from the engine, never from the page.
//!
//! Unlike the blocks of terminals, notes do not expire: they stay until
//! deleted. Their ids and blocks are as in the cloud, so that a note can go
//! there as it is.

use crate::names;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use uuid::Uuid;

/// The kinds of block: a paragraph, a heading, a list item, a checklist
/// item, code, a divider.
pub const TYPES: [&str; 6] = ["p", "h", "li", "todo", "code", "hr"];
/// Blocks that keep the line breaks typed in them; in the others a break
/// becomes a space.
const MULTILINE: [&str; 2] = ["p", "code"];

pub const NAME_MAX: usize = 80;
pub const TITLE_MAX: usize = 200;
pub const TEXT_MAX: usize = 20_000;
pub const BLOCKS_MAX: usize = 2_000;
/// The whole of a note's blocks as JSON, in bytes.
pub const BODY_MAX: usize = 512 * 1024;
pub const EXCERPT_MAX: usize = 140;
/// Versions kept to merge with: a save made further back than that is
/// asked whose version to keep.
pub const KEEP_VERSIONS: i64 = 50;
pub const FOLDERS_MAX: i64 = 200;
pub const NOTES_MAX: i64 = 5_000;
/// A note's save, at most, in bytes, as the page sends it (the core's
/// `NOTE_SAVE_MAX`): its blocks are kept to half that, and JSON escapes a
/// little on the way.
pub const SAVE_MAX: usize = 1024 * 1024;

/// What a save gets when the note changed in the same places meanwhile.
pub const CHANGED: &str = "The note changed elsewhere meanwhile.";
const MOVED_MEANWHILE: &str = "The note was just moved from another tab or device. Look again.";
const NO_FOLDER: &str = "No such folder.";
const NO_NOTE: &str = "No such note.";
const NO_PROJECT: &str = "No such project.";
const STORE_FAILED: &str = "The notes on this computer could not be read or saved.";

/// The tables, in the store's file next to the terminals' (version 2 of it).
/// As the core's (migration 008), with the lowered name of a folder kept for
/// the check that two folders do not share a name: SQLite's own `lower()`
/// knows only ASCII.
pub const TABLES: &str = "
    CREATE TABLE IF NOT EXISTS note_folders (
        id          TEXT PRIMARY KEY,
        project_id  TEXT NOT NULL,
        name        TEXT NOT NULL,
        name_key    TEXT NOT NULL,
        created_by  TEXT,
        created_at  INTEGER NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS note_folders_name ON note_folders (project_id, name_key);
    CREATE TABLE IF NOT EXISTS notes (
        id          TEXT PRIMARY KEY,
        folder_id   TEXT NOT NULL REFERENCES note_folders (id) ON DELETE CASCADE,
        title       TEXT NOT NULL DEFAULT '',
        body        TEXT NOT NULL DEFAULT '[]',
        todo_total  INTEGER NOT NULL DEFAULT 0,
        todo_done   INTEGER NOT NULL DEFAULT 0,
        excerpt     TEXT NOT NULL DEFAULT '',
        version     INTEGER NOT NULL DEFAULT 1,
        created_by  TEXT,
        created_at  INTEGER NOT NULL,
        edited_by   TEXT,
        edited_at   INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS notes_folder ON notes (folder_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS note_versions (
        note_id     TEXT NOT NULL REFERENCES notes (id) ON DELETE CASCADE,
        version     INTEGER NOT NULL,
        title       TEXT NOT NULL,
        body        TEXT NOT NULL,
        PRIMARY KEY (note_id, version)
    );
";

/// Why something was not done, with the answer the core gives for it.
#[derive(Clone, Debug, PartialEq)]
pub enum Refused {
    /// 404: not there, or not this person's to see.
    NotFound(String),
    /// 403.
    NotAllowed(String),
    /// 422: what was sent does not do.
    Invalid(String),
    /// 409: a name in use, or a limit reached.
    Taken(String),
    /// 422, the core's plain `Refused`.
    Other(String),
    /// 409: changed elsewhere in the same places since the version the save
    /// was made from; the note as it is saved now.
    Conflict(Value),
    /// 500: the store failed.
    Store(String),
}

impl Refused {
    pub fn status(&self) -> u16 {
        match self {
            Refused::NotFound(_) => 404,
            Refused::NotAllowed(_) => 403,
            Refused::Invalid(_) | Refused::Other(_) => 422,
            Refused::Taken(_) | Refused::Conflict(_) => 409,
            Refused::Store(_) => 500,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Refused::NotFound(m) | Refused::NotAllowed(m) | Refused::Invalid(m) | Refused::Taken(m) | Refused::Other(m) | Refused::Store(m) => m,
            Refused::Conflict(_) => CHANGED,
        }
    }
}

impl From<rusqlite::Error> for Refused {
    fn from(e: rusqlite::Error) -> Self {
        eprintln!("tterm: notes: {e}");
        Refused::Store(STORE_FAILED.to_string())
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T, Refused> {
    Err(Refused::Invalid(message.into()))
}

fn not_found<T>(message: &str) -> Result<T, Refused> {
    Err(Refused::NotFound(message.to_string()))
}

/// The person of this computer, who owns its one project.
#[derive(Clone, Debug)]
pub struct Me {
    pub id: String,
    pub name: String,
    pub project_id: String,
}

/// The same block changed two ways.
#[derive(Debug, PartialEq, Eq)]
pub struct Clash;

// --------------------------------------------------------------- cleaning

/// Python's `str.isspace`: what `strip` takes off.
fn py_space(c: char) -> bool {
    matches!(c, '\t'..='\r' | '\u{1c}'..='\u{1f}' | ' ' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

fn py_strip(text: &str) -> &str {
    text.trim_matches(py_space)
}

/// Lowered, to tell two names apart regardless of case, as `lower()` does in
/// the core's database.
fn name_key(name: &str) -> String {
    name.to_lowercase()
}

/// A folder's name: one line, 1 to 80 characters, or None.
pub fn clean_name(name: &Value) -> Option<String> {
    let name = names::one_line(name.as_str()?);
    (1..=NAME_MAX).contains(&name.chars().count()).then_some(name)
}

/// A note's title as typed. Only control characters become spaces: a space
/// at the end stays while the person types on, since tidying it away in the
/// saved copy would move their caret.
pub fn clean_title(title: Option<&Value>) -> Result<String, Refused> {
    let title = match title {
        None | Some(Value::Null) => return Ok(String::new()),
        Some(Value::String(t)) => t,
        Some(_) => return invalid("A note's title is text."),
    };
    let title: String = title.chars().map(|c| if (c as u32) < 0x20 || c == '\u{7f}' { ' ' } else { c }).collect();
    if title.chars().count() > TITLE_MAX {
        return invalid(format!("A title is at most {TITLE_MAX} characters."));
    }
    Ok(title)
}

/// `[A-Za-z0-9_-]{1,32}`.
fn good_id(id: &str) -> bool {
    (1..=32).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Line breaks as `\n`, and no control characters but the tab and the break.
fn clean_text(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n").chars().filter(|&c| !matches!(c as u32, 0x00..=0x08 | 0x0b..=0x1f | 0x7f)).collect()
}

/// The blocks as the page sent them, checked and tidied: only the kinds
/// there are, an id of its own for each, text only. Whether a checklist item
/// is done is the page's to say only for an item that is new (`with_ticks`).
pub fn clean_blocks(raw: Option<&Value>) -> Result<Vec<Value>, Refused> {
    let items = match raw {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return invalid("A note's blocks are a list."),
    };
    if items.len() > BLOCKS_MAX {
        return invalid(format!("A note holds at most {BLOCKS_MAX} blocks."));
    }
    let mut seen: HashSet<&str> = HashSet::new();
    let mut blocks = Vec::with_capacity(items.len());
    for item in items {
        let Value::Object(item) = item else { return invalid("A block is an object.") };
        let id = match item.get("id") {
            Some(Value::String(id)) if good_id(id) && !seen.contains(id.as_str()) => id,
            _ => return invalid("Each block needs an id of its own."),
        };
        let kind = match item.get("type") {
            Some(Value::String(k)) if TYPES.contains(&k.as_str()) => k.as_str(),
            other => return invalid(format!("There is no block of the kind {}.", py_repr(other.unwrap_or(&Value::Null)))),
        };
        let text = match item.get("text") {
            None => "",
            Some(Value::String(t)) => t.as_str(),
            Some(_) => return invalid("A block's text is text."),
        };
        let mut text = clean_text(text);
        if kind == "hr" {
            text.clear();
        } else if !MULTILINE.contains(&kind) {
            text = text.replace('\n', " ");
        }
        if text.chars().count() > TEXT_MAX {
            return invalid(format!("A block holds at most {TEXT_MAX} characters."));
        }
        let mut block = Map::new();
        block.insert("id".into(), Value::String(id.clone()));
        block.insert("type".into(), Value::String(kind.to_string()));
        block.insert("text".into(), Value::String(text));
        if kind == "todo" {
            block.insert("done".into(), Value::Bool(item.get("done") == Some(&Value::Bool(true))));
        }
        seen.insert(id.as_str());
        blocks.push(Value::Object(block));
    }
    if dump(&blocks).len() > BODY_MAX {
        return invalid("The note is too long. Split it into two.");
    }
    Ok(blocks)
}

/// The blocks with each checklist item's tick as the engine knows it: an
/// item that was already there keeps its tick, who made it and when, whatever
/// the page says; a new item is ticked or not as written, by the one who
/// saves it.
pub fn with_ticks(current: &[Value], blocks: &[Value], user_id: &str, now: i64) -> Vec<Value> {
    let known: HashMap<&str, &Value> = current
        .iter()
        .filter(|b| b.get("type").and_then(Value::as_str) == Some("todo"))
        .filter_map(|b| Some((b.get("id")?.as_str()?, b)))
        .collect();
    blocks
        .iter()
        .map(|block| {
            let mut out = Map::new();
            for key in ["id", "type", "text"] {
                out.insert(key.into(), block.get(key).cloned().unwrap_or(Value::Null));
            }
            if block.get("type").and_then(Value::as_str) == Some("todo") {
                let done = block.get("done") == Some(&Value::Bool(true));
                let was = block.get("id").and_then(Value::as_str).and_then(|id| known.get(id));
                let (done, by, at) = match was {
                    Some(was) => (
                        was.get("done") == Some(&Value::Bool(true)),
                        was.get("by").cloned().unwrap_or(Value::Null),
                        was.get("at").cloned().unwrap_or(Value::Null),
                    ),
                    None if done => (true, Value::String(user_id.to_string()), json!(now)),
                    None => (false, Value::Null, Value::Null),
                };
                out.insert("done".into(), Value::Bool(done));
                out.insert("by".into(), by);
                out.insert("at".into(), at);
            }
            Value::Object(out)
        })
        .collect()
}

/// Python's truth of a value.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// Checklist items, how many are done, and the start of the text: what
/// lists of notes show.
pub fn summary(blocks: &[Value]) -> (i64, i64, String) {
    let todos: Vec<&Value> = blocks.iter().filter(|b| b.get("type").and_then(Value::as_str) == Some("todo")).collect();
    let mut excerpt = String::new();
    for b in blocks {
        let kind = b.get("type").and_then(Value::as_str).unwrap_or("");
        let text = b.get("text").and_then(Value::as_str).unwrap_or("");
        if matches!(kind, "p" | "li" | "code") && !py_strip(text).is_empty() {
            let first = py_strip(text).split('\n').next().unwrap_or("");
            excerpt = py_strip(first).chars().take(EXCERPT_MAX).collect();
            break;
        }
    }
    let done = todos.iter().filter(|b| truthy(b.get("done"))).count();
    (todos.len() as i64, done as i64, excerpt)
}

// ------------------------------------------------------------------ merge

fn id_of(block: &Value) -> &str {
    block.get("id").and_then(Value::as_str).unwrap_or("")
}

/// What a block says, without its tick: a tick is never a conflict.
fn content(block: Option<&Value>) -> Option<(&Value, &Value)> {
    block.map(|b| (b.get("type").unwrap_or(&Value::Null), b.get("text").unwrap_or(&Value::Null)))
}

fn by_id(blocks: &[Value]) -> HashMap<&str, &Value> {
    blocks.iter().map(|b| (id_of(b), b)).collect()
}

/// A save made from `base`, merged with `theirs`, what was saved since.
///
/// Each side's changes stay where the other did not touch; a block, or the
/// title, changed both ways (deleted on one side, changed on the other
/// counts) is a Clash. The order is theirs, with blocks new on this side put
/// after the block they followed here.
pub fn merge(base_title: &str, base: &[Value], mine_title: &str, mine: &[Value], theirs_title: &str, theirs: &[Value]) -> Result<(String, Vec<Value>), Clash> {
    let title = if mine_title == base_title || mine_title == theirs_title {
        theirs_title
    } else if theirs_title == base_title {
        mine_title
    } else {
        return Err(Clash);
    };
    let (b, m, t) = (by_id(base), by_id(mine), by_id(theirs));
    let ids: HashSet<&str> = b.keys().chain(m.keys()).chain(t.keys()).copied().collect();
    let mut kept: HashMap<&str, &Value> = HashMap::new();
    for id in ids {
        let was = content(b.get(id).copied());
        let mine_now = content(m.get(id).copied());
        let theirs_now = content(t.get(id).copied());
        let (mine_changed, theirs_changed) = (mine_now != was, theirs_now != was);
        if mine_changed && theirs_changed && mine_now != theirs_now {
            return Err(Clash);
        }
        if mine_changed {
            if mine_now.is_some() {
                kept.insert(id, m[id]);
            }
        } else if theirs_now.is_some() {
            kept.insert(id, t[id]);
        }
    }
    let mut order: Vec<&str> = theirs.iter().map(id_of).filter(|id| kept.contains_key(id)).collect();
    let mut placed: HashSet<&str> = order.iter().copied().collect();
    for (i, block) in mine.iter().enumerate() {
        let id = id_of(block);
        if !kept.contains_key(id) || placed.contains(id) {
            continue;
        }
        let after = mine[..i].iter().rev().map(id_of).find(|x| placed.contains(x));
        let at = after.and_then(|x| order.iter().position(|o| *o == x)).map_or(0, |p| p + 1);
        order.insert(at, id);
        placed.insert(id);
    }
    Ok((title.to_string(), order.iter().map(|id| kept[*id].clone()).collect()))
}

// ------------------------------------------------------------- the store

/// As the core writes JSON: compact, letters as they are.
fn dump(blocks: &[Value]) -> String {
    Value::Array(blocks.to_vec()).to_string()
}

fn load(body: &str) -> Result<Vec<Value>, Refused> {
    match serde_json::from_str::<Value>(body) {
        Ok(Value::Array(blocks)) => Ok(blocks),
        _ => {
            eprintln!("tterm: notes: a note's blocks could not be read");
            Err(Refused::Store(STORE_FAILED.to_string()))
        }
    }
}

fn now_ms() -> i64 {
    crate::terminals::now_ms()
}

/// Someone as the page shows them: the name, the first name, the initials.
fn person(id: Option<&str>, me: &Me) -> Value {
    let Some(id) = id else { return Value::Null };
    let name = if id == me.id && !me.name.is_empty() { me.name.as_str() } else { "Someone" };
    json!({"id": id, "name": name, "firstName": names::first_name(name), "initials": names::initials(name)})
}

/// Runs `job` as one transaction: what it changed stays only if it
/// succeeds. A note saved is on the disk before the page hears so, as the
/// core's database makes it: the page lets go of its draft then. (The
/// commands of terminals, which go after 30 days anyway, are written the
/// quicker way.)
pub fn in_turn<T>(c: &Connection, job: impl FnOnce(&Connection) -> Result<T, Refused>) -> Result<T, Refused> {
    c.execute_batch("PRAGMA synchronous = FULL; PRAGMA fullfsync = ON;")?;
    let out = (|| {
        let tx = c.unchecked_transaction()?;
        let out = job(&tx)?;
        tx.commit()?;
        Ok(out)
    })();
    if let Err(e) = c.execute_batch("PRAGMA synchronous = NORMAL; PRAGMA fullfsync = OFF;") {
        eprintln!("tterm: notes: {e}");
    }
    out
}

struct FolderRow {
    project_id: String,
    name: String,
}

struct NoteRow {
    id: String,
    folder_id: String,
    title: String,
    blocks: Vec<Value>,
    version: i64,
    created_by: Option<String>,
    created_at: i64,
    edited_by: Option<String>,
    edited_at: i64,
    project_id: String,
    folder_name: String,
}

fn folder_project(c: &Connection, folder_id: &str) -> Result<Option<String>, Refused> {
    Ok(c.query_row("SELECT project_id FROM note_folders WHERE id = ?1", params![folder_id], |r| r.get(0)).optional()?)
}

fn note_project(c: &Connection, note_id: &str) -> Result<Option<String>, Refused> {
    Ok(c
        .query_row("SELECT f.project_id FROM notes n JOIN note_folders f ON f.id = n.folder_id WHERE n.id = ?1", params![note_id], |r| r.get(0))
        .optional()?)
}

/// The project, if the person is in it: here, if it is theirs.
fn hold(me: &Me, project_id: Option<&str>, missing: &str) -> Result<(), Refused> {
    match project_id {
        Some(p) if p == me.project_id => Ok(()),
        _ => not_found(missing),
    }
}

fn folder_row(c: &Connection, me: &Me, folder_id: &str) -> Result<FolderRow, Refused> {
    let row = c
        .query_row("SELECT project_id, name FROM note_folders WHERE id = ?1", params![folder_id], |r| Ok(FolderRow { project_id: r.get(0)?, name: r.get(1)? }))
        .optional()?;
    match row {
        Some(row) if row.project_id == me.project_id => Ok(row),
        _ => not_found(NO_FOLDER),
    }
}

fn note_row(c: &Connection, me: &Me, note_id: &str) -> Result<NoteRow, Refused> {
    let row = c
        .query_row(
            "SELECT n.id, n.folder_id, n.title, n.body, n.version, n.created_by, n.created_at, n.edited_by,
                    n.edited_at, f.project_id, f.name
             FROM notes n JOIN note_folders f ON f.id = n.folder_id
             WHERE n.id = ?1",
            params![note_id],
            |r| {
                Ok((
                    r.get::<_, String>(3)?,
                    NoteRow {
                        id: r.get(0)?,
                        folder_id: r.get(1)?,
                        title: r.get(2)?,
                        blocks: Vec::new(),
                        version: r.get(4)?,
                        created_by: r.get(5)?,
                        created_at: r.get(6)?,
                        edited_by: r.get(7)?,
                        edited_at: r.get(8)?,
                        project_id: r.get(9)?,
                        folder_name: r.get(10)?,
                    },
                ))
            },
        )
        .optional()?;
    match row {
        Some((body, mut row)) if row.project_id == me.project_id => {
            row.blocks = load(&body)?;
            Ok(row)
        }
        _ => not_found(NO_NOTE),
    }
}

/// A note as the page gets it: everything in it, who wrote it, and the
/// names of those who ticked its checklist.
fn describe(row: &NoteRow, me: &Me) -> Value {
    let mut people = Map::new();
    for b in &row.blocks {
        if b.get("type").and_then(Value::as_str) != Some("todo") {
            continue;
        }
        if let Some(by) = b.get("by").and_then(Value::as_str) {
            // The core names those it knows; here that is the person of
            // this computer.
            if by == me.id {
                people.insert(by.to_string(), person(Some(by), me));
            }
        }
    }
    json!({
        "id": row.id,
        "folderId": row.folder_id,
        "folder": row.folder_name,
        "projectId": row.project_id,
        "title": row.title,
        "blocks": row.blocks,
        "version": row.version,
        "createdBy": person(row.created_by.as_deref(), me),
        "createdAt": row.created_at,
        "editedBy": person(row.edited_by.as_deref(), me),
        "editedAt": row.edited_at,
        "people": people,
        // The owner deletes any note, and writes in all of them.
        "canDelete": true,
        "canWrite": true,
    })
}

/// Writes a new version of the note, and keeps it to merge with.
fn store(c: &Connection, me: &Me, note_id: &str, version: i64, title: &str, blocks: &[Value]) -> Result<(), Refused> {
    let (total, done, excerpt) = summary(blocks);
    let body = dump(blocks);
    c.execute(
        "UPDATE notes SET title = ?2, body = ?3, version = ?4, todo_total = ?5, todo_done = ?6, excerpt = ?7,
                          edited_by = ?8, edited_at = ?9
         WHERE id = ?1",
        params![note_id, title, body, version, total, done, excerpt, me.id, now_ms()],
    )?;
    c.execute("INSERT INTO note_versions (note_id, version, title, body) VALUES (?1, ?2, ?3, ?4)", params![note_id, version, title, body])?;
    c.execute("DELETE FROM note_versions WHERE note_id = ?1 AND version <= ?2", params![note_id, version - KEEP_VERSIONS])?;
    Ok(())
}

fn exists(c: &Connection, sql: &str, args: impl rusqlite::Params) -> Result<bool, Refused> {
    Ok(c.query_row(sql, args, |_| Ok(())).optional()?.is_some())
}

fn count(c: &Connection, sql: &str, args: impl rusqlite::Params) -> Result<i64, Refused> {
    Ok(c.query_row(sql, args, |r| r.get(0))?)
}

fn notes_in_project(c: &Connection, project_id: &str) -> Result<i64, Refused> {
    count(c, "SELECT count(*) FROM notes n JOIN note_folders f ON f.id = n.folder_id WHERE f.project_id = ?1", params![project_id])
}

// ---------------------------------------------------------------- folders

pub fn create_folder(c: &Connection, me: &Me, project_id: &str, name: &Value) -> Result<Value, Refused> {
    let Some(clean) = clean_name(name) else { return invalid(format!("A folder's name is 1 to {NAME_MAX} characters.")) };
    hold(me, Some(project_id), NO_PROJECT)?;
    if count(c, "SELECT count(*) FROM note_folders WHERE project_id = ?1", params![project_id])? >= FOLDERS_MAX {
        return Err(Refused::Taken(format!("A project holds at most {FOLDERS_MAX} folders.")));
    }
    if exists(c, "SELECT 1 FROM note_folders WHERE project_id = ?1 AND name_key = ?2", params![project_id, name_key(&clean)])? {
        return Err(Refused::Taken(format!("There is a folder {clean} here already.")));
    }
    let id = Uuid::new_v4().to_string();
    c.execute(
        "INSERT INTO note_folders (id, project_id, name, name_key, created_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, project_id, clean, name_key(&clean), me.id, now_ms()],
    )?;
    Ok(json!({"id": id, "projectId": project_id, "name": clean, "createdBy": person(Some(me.id.as_str()), me), "notes": []}))
}

pub fn rename_folder(c: &Connection, me: &Me, folder_id: &str, name: &Value) -> Result<Value, Refused> {
    let Some(clean) = clean_name(name) else { return invalid(format!("A folder's name is 1 to {NAME_MAX} characters.")) };
    hold(me, folder_project(c, folder_id)?.as_deref(), NO_FOLDER)?;
    let row = folder_row(c, me, folder_id)?;
    if clean != row.name && exists(c, "SELECT 1 FROM note_folders WHERE project_id = ?1 AND name_key = ?2 AND id <> ?3", params![row.project_id, name_key(&clean), folder_id])? {
        return Err(Refused::Taken(format!("There is a folder {clean} here already.")));
    }
    c.execute("UPDATE note_folders SET name = ?2, name_key = ?3 WHERE id = ?1", params![folder_id, clean, name_key(&clean)])?;
    Ok(json!({"id": folder_id, "projectId": row.project_id, "name": clean}))
}

/// Deletes the folder and the notes in it.
pub fn delete_folder(c: &Connection, me: &Me, folder_id: &str) -> Result<Value, Refused> {
    hold(me, folder_project(c, folder_id)?.as_deref(), NO_FOLDER)?;
    let row = folder_row(c, me, folder_id)?;
    let notes = count(c, "SELECT count(*) FROM notes WHERE folder_id = ?1", params![folder_id])?;
    // The owner deletes a folder with notes in it, as an admin would.
    c.execute("DELETE FROM note_folders WHERE id = ?1", params![folder_id])?;
    Ok(json!({"id": folder_id, "projectId": row.project_id, "name": row.name, "notes": notes}))
}

// ------------------------------------------------------------------ notes

pub fn create_note(c: &Connection, me: &Me, folder_id: &str, title: Option<&Value>) -> Result<Value, Refused> {
    let (title, blocks) = (clean_title(title)?, clean_blocks(None)?);
    hold(me, folder_project(c, folder_id)?.as_deref(), NO_FOLDER)?;
    let folder = folder_row(c, me, folder_id)?;
    if notes_in_project(c, &folder.project_id)? >= NOTES_MAX {
        return Err(Refused::Taken(format!("A project holds at most {NOTES_MAX} notes.")));
    }
    let now = now_ms();
    let ticked = with_ticks(&[], &blocks, &me.id, now);
    let (total, done, excerpt) = summary(&ticked);
    let body = dump(&ticked);
    let id = Uuid::new_v4().to_string();
    c.execute(
        "INSERT INTO notes (id, folder_id, title, body, todo_total, todo_done, excerpt, version, created_by,
                            created_at, edited_by, edited_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?8, ?9)",
        params![id, folder_id, title, body, total, done, excerpt, me.id, now],
    )?;
    c.execute("INSERT INTO note_versions (note_id, version, title, body) VALUES (?1, 1, ?2, ?3)", params![id, title, body])?;
    Ok(describe(&note_row(c, me, &id)?, me))
}

pub fn get_note(c: &Connection, me: &Me, note_id: &str) -> Result<Value, Refused> {
    Ok(describe(&note_row(c, me, note_id)?, me))
}

/// Saves the title and the blocks the page has, made from `base_version`.
/// From an older version they are merged with what was saved since; where
/// both changed the same thing, a Conflict with the note as it is now. The
/// page then merges on its own, the person choosing whose change to keep
/// where both changed, and saves that from the version it was given.
pub fn save_note(c: &Connection, me: &Me, note_id: &str, base_version: i64, title: Option<&Value>, blocks: Option<&Value>) -> Result<Value, Refused> {
    let (clean_t, clean_b) = (clean_title(title)?, clean_blocks(blocks)?);
    let row = note_row(c, me, note_id)?;
    let (mut new_title, mut new_blocks) = (clean_t, clean_b);
    if base_version != row.version {
        let base: Option<(String, String)> = c
            .query_row("SELECT title, body FROM note_versions WHERE note_id = ?1 AND version = ?2", params![note_id, base_version], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let Some((base_title, base_body)) = base.filter(|_| base_version <= row.version) else {
            return Err(Refused::Conflict(describe(&row, me)));
        };
        match merge(&base_title, &load(&base_body)?, &new_title, &new_blocks, &row.title, &row.blocks) {
            Ok((t, b)) => (new_title, new_blocks) = (t, b),
            Err(Clash) => return Err(Refused::Conflict(describe(&row, me))),
        }
    }
    let new_blocks = with_ticks(&row.blocks, &new_blocks, &me.id, now_ms());
    if new_title == row.title && new_blocks == row.blocks {
        return Ok(describe(&row, me));
    }
    store(c, me, note_id, row.version + 1, &new_title, &new_blocks)?;
    Ok(describe(&note_row(c, me, note_id)?, me))
}

/// Ticks a checklist item, or takes the tick off, at once: the note's new
/// version, and the item with who ticked it.
pub fn tick(c: &Connection, me: &Me, note_id: &str, block_id: &str, done: bool) -> Result<Value, Refused> {
    let row = note_row(c, me, note_id)?;
    let mut blocks = row.blocks.clone();
    let item = blocks.iter_mut().find(|b| b.get("id").and_then(Value::as_str) == Some(block_id));
    let Some(Value::Object(item)) = item.filter(|b| b.get("type").and_then(Value::as_str) == Some("todo")) else {
        // Not 404, which says the note is gone: the item went, deleted or
        // turned into text in another tab.
        return invalid("That item is not in the checklist any more.");
    };
    if (item.get("done") == Some(&Value::Bool(true))) != done {
        item.insert("done".into(), Value::Bool(done));
        item.insert("by".into(), if done { Value::String(me.id.clone()) } else { Value::Null });
        item.insert("at".into(), if done { json!(now_ms()) } else { Value::Null });
        store(c, me, note_id, row.version + 1, &row.title, &blocks)?;
    }
    Ok(describe(&note_row(c, me, note_id)?, me))
}

/// Puts the note in another folder of its project. With a project instead of
/// a folder, it goes into that project's folder named as the one it is in
/// now, made for it if there is none. Here there is the one project, so a
/// note goes from folder to folder; another project is not there (the core
/// says the same of one the person is not in).
pub fn move_note(c: &Connection, me: &Me, note_id: &str, folder_id: Option<&str>, project_id: Option<&str>) -> Result<Value, Refused> {
    if folder_id.is_none() == project_id.is_none() {
        return invalid("Say where the note goes: a folder, or a project.");
    }
    let missing = if folder_id.is_some() { NO_FOLDER } else { NO_PROJECT };
    let source = note_project(c, note_id)?;
    let Some(source) = source.filter(|s| *s == me.project_id) else { return not_found(NO_NOTE) };
    let target = match folder_id {
        Some(f) => folder_project(c, f)?,
        None => project_id.map(str::to_string),
    };
    // Another project than its own would have to be one the person writes
    // notes in: here there is none.
    let Some(target) = target.filter(|t| *t == source) else { return not_found(missing) };
    let row = note_row(c, me, note_id)?;
    if row.project_id != source {
        return Err(Refused::Other(MOVED_MEANWHILE.to_string()));
    }
    let folder: (String, String) = match folder_id {
        Some(f) => c.query_row("SELECT id, name FROM note_folders WHERE id = ?1", params![f], |r| Ok((r.get(0)?, r.get(1)?))).optional()?.ok_or_else(|| Refused::NotFound(NO_FOLDER.to_string()))?,
        None => {
            let found = c
                .query_row("SELECT id, name FROM note_folders WHERE project_id = ?1 AND name_key = ?2", params![target, name_key(&row.folder_name)], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            match found {
                Some(f) => f,
                None => {
                    if count(c, "SELECT count(*) FROM note_folders WHERE project_id = ?1", params![target])? >= FOLDERS_MAX {
                        return Err(Refused::Taken(format!("A project holds at most {FOLDERS_MAX} folders.")));
                    }
                    let id = Uuid::new_v4().to_string();
                    c.execute(
                        "INSERT INTO note_folders (id, project_id, name, name_key, created_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![id, target, row.folder_name, name_key(&row.folder_name), me.id, now_ms()],
                    )?;
                    (id, row.folder_name.clone())
                }
            }
        }
    };
    if folder.0 == row.folder_id {
        return Ok(describe(&row, me));
    }
    c.execute("UPDATE notes SET folder_id = ?2 WHERE id = ?1", params![note_id, folder.0])?;
    Ok(describe(&note_row(c, me, note_id)?, me))
}

/// Deletes the note, with its versions.
pub fn delete_note(c: &Connection, me: &Me, note_id: &str) -> Result<Value, Refused> {
    let held = note_project(c, note_id)?;
    hold(me, held.as_deref(), NO_NOTE)?;
    let row = note_row(c, me, note_id)?;
    if Some(&row.project_id) != held.as_ref() {
        return Err(Refused::Other(MOVED_MEANWHILE.to_string()));
    }
    c.execute("DELETE FROM notes WHERE id = ?1", params![note_id])?;
    Ok(json!({"id": note_id, "projectId": row.project_id, "title": row.title, "folder": row.folder_name}))
}

/// The project's folders, by name, and the notes in each, the newest first:
/// what the sidebar and the project's page list, without bodies. Two notes
/// made in the same millisecond go as they were made (the core's times are
/// finer).
pub fn folders_of(c: &Connection, me: &Me) -> Result<Vec<Value>, Refused> {
    let mut st = c.prepare(
        "SELECT n.id, n.folder_id, n.title, n.todo_total, n.todo_done, n.excerpt, n.version, n.created_by,
                n.created_at, n.edited_by, n.edited_at
         FROM notes n JOIN note_folders f ON f.id = n.folder_id
         WHERE f.project_id = ?1
         ORDER BY n.created_at DESC, n.rowid DESC",
    )?;
    let mut by_folder: HashMap<String, Vec<Value>> = HashMap::new();
    let rows = st.query_map(params![me.project_id], |r| {
        let (created_by, edited_by): (Option<String>, Option<String>) = (r.get(7)?, r.get(9)?);
        Ok((
            r.get::<_, String>(1)?,
            json!({
                "id": r.get::<_, String>(0)?,
                "title": r.get::<_, String>(2)?,
                "total": r.get::<_, i64>(3)?,
                "done": r.get::<_, i64>(4)?,
                "excerpt": r.get::<_, String>(5)?,
                "version": r.get::<_, i64>(6)?,
                "createdBy": person(created_by.as_deref(), me),
                "createdAt": r.get::<_, i64>(8)?,
                "editedBy": person(edited_by.as_deref(), me),
                "editedAt": r.get::<_, i64>(10)?,
            }),
        ))
    })?;
    for row in rows {
        let (folder, note) = row?;
        by_folder.entry(folder).or_default().push(note);
    }
    let mut st = c.prepare("SELECT id, name, created_by FROM note_folders WHERE project_id = ?1 ORDER BY name_key, created_at, id")?;
    let folders = st.query_map(params![me.project_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?)))?;
    let mut out = Vec::new();
    for folder in folders {
        let (id, name, created_by) = folder?;
        let notes = by_folder.remove(&id).unwrap_or_default();
        out.push(json!({"id": id, "name": name, "createdBy": person(created_by.as_deref(), me), "notes": notes}));
    }
    Ok(out)
}

// --------------------------------------------------- Python's words for it

/// `repr()` of a value from JSON, as the core's messages name it.
fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) => i.to_string(),
            (_, Some(u), _) => u.to_string(),
            (_, _, Some(f)) if f.fract() == 0.0 && f.abs() < 1e16 => format!("{f:.1}"),
            _ => n.to_string(),
        },
        Value::String(s) => py_str_repr(s),
        Value::Array(items) => format!("[{}]", items.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
        Value::Object(map) => format!("{{{}}}", map.iter().map(|(k, v)| format!("{}: {}", py_str_repr(k), py_repr(v))).collect::<Vec<_>>().join(", ")),
    }
}

/// Python's `str.isprintable`, near enough: what is not a control, a
/// separator other than the space, or a mark that only steers the text.
fn py_printable(c: char) -> bool {
    c == ' ' || !(c.is_control() || c.is_whitespace() || names::hidden(c))
}

fn py_str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if !py_printable(c) => {
                let n = c as u32;
                let _ = if n < 0x100 {
                    write!(out, "\\x{n:02x}")
                } else if n < 0x10000 {
                    write!(out, "\\u{n:04x}")
                } else {
                    write!(out, "\\U{n:08x}")
                };
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(id: &str, text: &str) -> Value {
        json!({"id": id, "type": "p", "text": text})
    }

    fn of(id: &str, text: &str, kind: &str) -> Value {
        json!({"id": id, "type": kind, "text": text})
    }

    #[test]
    fn folder_names() {
        assert_eq!(clean_name(&json!("  Runbooks ")).as_deref(), Some("Runbooks"));
        assert_eq!(clean_name(&json!("Release\n2.4\t notes")).as_deref(), Some("Release 2.4 notes"));
        assert_eq!(clean_name(&json!("")), None);
        assert_eq!(clean_name(&json!("   ")), None);
        assert_eq!(clean_name(&json!("x".repeat(81))), None);
        assert_eq!(clean_name(&json!("x".repeat(80))), Some("x".repeat(80)));
        assert_eq!(clean_name(&json!(42)), None);
        assert_eq!(clean_name(&json!("я".repeat(80))), Some("я".repeat(80)), "characters, not bytes");
    }

    #[test]
    fn titles_are_kept_as_typed() {
        assert_eq!(clean_title(Some(&json!("Release "))).unwrap(), "Release ");
        assert_eq!(clean_title(Some(&json!("  two  spaces "))).unwrap(), "  two  spaces ");
        assert_eq!(clean_title(Some(&json!("a\tb\nc\x07d"))).unwrap(), "a b c d");
        assert_eq!(clean_title(None).unwrap(), "");
        assert_eq!(clean_title(Some(&Value::Null)).unwrap(), "");
        for bad in [json!(5), json!("x".repeat(TITLE_MAX + 1))] {
            assert!(matches!(clean_title(Some(&bad)), Err(Refused::Invalid(_))), "{bad}");
        }
    }

    #[test]
    fn blocks_are_checked_and_tidied() {
        let blocks = clean_blocks(Some(&json!([
            p("a", "one\r\ntwo"),
            of("b", "Heading\nwith a break", "h"),
            {"id": "c", "type": "todo", "text": "item", "done": true, "by": "someone", "at": 1},
            of("d", "x", "hr"),
            of("e", "bell\x07 and tab\t", "code"),
        ])))
        .unwrap();
        assert_eq!(
            Value::Array(blocks),
            json!([
                {"id": "a", "type": "p", "text": "one\ntwo"},
                {"id": "b", "type": "h", "text": "Heading with a break"},
                {"id": "c", "type": "todo", "text": "item", "done": true},
                {"id": "d", "type": "hr", "text": ""},
                {"id": "e", "type": "code", "text": "bell and tab\t"},
            ])
        );
        for bad in [
            json!([p("a", "x"), p("a", "y")]),
            json!([p("a b", "x")]),
            json!([p("", "x")]),
            json!([{"id": "a", "type": "script", "text": "x"}]),
            json!([{"id": "a", "type": "p", "text": 5}]),
            json!([p("a", &"x".repeat(TEXT_MAX + 1))]),
            json!("not a list"),
            json!([["p", "x"]]),
        ] {
            assert!(matches!(clean_blocks(Some(&bad)), Err(Refused::Invalid(_))), "taken: {bad}");
        }
        let many: Vec<Value> = (0..=BLOCKS_MAX).map(|i| p(&format!("b{i}"), "")).collect();
        assert!(clean_blocks(Some(&Value::Array(many))).is_err(), "too many blocks taken");
        let big: Vec<Value> = (0..20).map(|i| p(&format!("b{i}"), &"я".repeat(19_000))).collect();
        assert_eq!(clean_blocks(Some(&Value::Array(big))), Err(Refused::Invalid("The note is too long. Split it into two.".into())));
        assert_eq!(
            clean_blocks(Some(&json!([{"id": "a", "type": "script", "text": "x"}]))),
            Err(Refused::Invalid("There is no block of the kind 'script'.".into()))
        );
        assert_eq!(clean_blocks(Some(&json!([{"id": "a", "text": "x"}]))), Err(Refused::Invalid("There is no block of the kind None.".into())));
        assert_eq!(clean_blocks(Some(&json!([{"id": "a", "type": "p", "text": null}]))), Err(Refused::Invalid("A block's text is text.".into())));
        assert_eq!(clean_blocks(Some(&json!([{"id": "a", "type": "p"}]))).unwrap()[0]["text"], "");
    }

    #[test]
    fn the_summary_counts_ticks_and_takes_the_first_text() {
        let blocks = [
            of("h", "Release", "h"),
            of("a", "", "p"),
            json!({"id": "b", "type": "todo", "text": "Freeze merges", "done": true}),
            json!({"id": "c", "type": "todo", "text": "Deploy", "done": false}),
            p("d", "First words\nsecond line"),
        ];
        assert_eq!(summary(&blocks), (2, 1, "First words".to_string()));
        assert_eq!(summary(&[]), (0, 0, String::new()));
        assert_eq!(summary(&[p("a", "  \u{3000}\n  spaced out  \nmore")]).2, "spaced out");
    }

    fn base() -> Vec<Value> {
        vec![p("a", "one"), p("b", "two"), p("c", "three")]
    }

    fn ids(blocks: &[Value]) -> Vec<&str> {
        blocks.iter().map(id_of).collect()
    }

    #[test]
    fn a_merge_keeps_both_sides_changes_to_different_blocks() {
        let mine = [p("a", "one!"), p("b", "two"), p("c", "three"), p("n", "mine new")];
        let theirs = [p("a", "one"), p("b", "two?"), p("t", "theirs new"), p("c", "three")];
        let (title, blocks) = merge("T", &base(), "T", &mine, "T", &theirs).unwrap();
        assert_eq!(title, "T");
        let got: Vec<(&str, &str)> = blocks.iter().map(|b| (id_of(b), b["text"].as_str().unwrap())).collect();
        assert_eq!(got, [("a", "one!"), ("b", "two?"), ("t", "theirs new"), ("c", "three"), ("n", "mine new")]);
    }

    #[test]
    fn a_merge_puts_a_new_block_after_the_one_it_followed() {
        let mine = [p("a", "one"), p("x", "after one"), p("b", "two"), p("c", "three")];
        let theirs = [p("z", "on top"), p("a", "one"), p("b", "two"), p("c", "three")];
        let (_, blocks) = merge("T", &base(), "T", &mine, "T", &theirs).unwrap();
        assert_eq!(ids(&blocks), ["z", "a", "x", "b", "c"]);
        let mut mine = vec![p("x", "first")];
        mine.extend(base());
        let (_, blocks) = merge("T", &base(), "T", &mine, "T", &base()).unwrap();
        assert_eq!(ids(&blocks), ["x", "a", "b", "c"]);
    }

    #[test]
    fn a_merge_takes_deletions() {
        let mine = [p("a", "one"), p("c", "three")];
        let theirs = [p("a", "one"), p("b", "two"), p("c", "three!")];
        let (_, blocks) = merge("T", &base(), "T", &mine, "T", &theirs).unwrap();
        let got: Vec<(&str, &str)> = blocks.iter().map(|b| (id_of(b), b["text"].as_str().unwrap())).collect();
        assert_eq!(got, [("a", "one"), ("c", "three!")]);
        let (_, blocks) = merge("T", &base(), "T", &mine, "T", &mine).unwrap();
        assert_eq!(ids(&blocks), ["a", "c"]);
    }

    #[test]
    fn a_merge_clashes() {
        let rest = || base()[1..].to_vec();
        let with = |first: Value| {
            let mut v = vec![first];
            v.extend(rest());
            v
        };
        let clash = |mine: &[Value], theirs: &[Value], mt: &str, tt: &str| merge("T", &base(), mt, mine, tt, theirs).is_err();
        assert!(clash(&with(p("a", "one!")), &with(p("a", "one?")), "T", "T"));
        assert!(clash(&rest(), &with(p("a", "one?")), "T", "T"));
        assert!(clash(&with(of("a", "one", "h")), &with(p("a", "one?")), "T", "T"));
        assert!(clash(&base(), &base(), "Mine", "Theirs"));
        assert!(!clash(&with(p("a", "same")), &with(p("a", "same")), "T", "T"));
        assert_eq!(merge("T", &base(), "Mine", &base(), "T", &base()).unwrap().0, "Mine");
        assert_eq!(merge("T", &base(), "T", &base(), "Theirs", &base()).unwrap().0, "Theirs");
    }

    #[test]
    fn a_tick_is_never_a_clash() {
        let base = [json!({"id": "a", "type": "todo", "text": "item", "done": false})];
        let theirs = [json!({"id": "a", "type": "todo", "text": "item", "done": true, "by": "x", "at": 1})];
        let mine = [json!({"id": "a", "type": "todo", "text": "item, reworded", "done": false})];
        let (_, blocks) = merge("T", &base, "T", &mine, "T", &theirs).unwrap();
        assert_eq!(blocks[0]["text"], "item, reworded");
    }

    #[test]
    fn ticks_stay_the_engines() {
        let current = [json!({"id": "a", "type": "todo", "text": "x", "done": true, "by": "me", "at": 5})];
        let page = [json!({"id": "a", "type": "todo", "text": "x", "done": false}), json!({"id": "n", "type": "todo", "text": "new", "done": true}), p("p", "text")];
        let out = with_ticks(&current, &page, "u", 9);
        assert_eq!(out[0], json!({"id": "a", "type": "todo", "text": "x", "done": true, "by": "me", "at": 5}));
        assert_eq!(out[1], json!({"id": "n", "type": "todo", "text": "new", "done": true, "by": "u", "at": 9}));
        assert_eq!(out[2], p("p", "text"));
        let off = with_ticks(&[], &[json!({"id": "a", "type": "todo", "text": "x"})], "u", 9);
        assert_eq!(off[0], json!({"id": "a", "type": "todo", "text": "x", "done": false, "by": null, "at": null}));
    }

    #[test]
    fn names_of_odd_kinds_as_python_writes_them() {
        assert_eq!(py_repr(&json!("it's")), "\"it's\"");
        assert_eq!(py_repr(&json!("say \"hi\" it's")), "'say \"hi\" it\\'s'");
        assert_eq!(py_repr(&json!("a\nb\u{1}\u{a0}")), "'a\\nb\\x01\\xa0'");
        assert_eq!(py_repr(&json!("заметка")), "'заметка'");
        assert_eq!(py_repr(&json!(5)), "5");
        assert_eq!(py_repr(&json!(true)), "True");
        assert_eq!(py_repr(&json!(["p", 1])), "['p', 1]");
    }
}
