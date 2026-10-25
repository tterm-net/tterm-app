//! Search over everything, in the app (from 0.3.1; the owner, 25.10: «Делай
//! сразу в 0.3.1»). tTerm Web's core finds the commands of a person's
//! terminals, what they printed, and notes (core/search.py, 0.1.7). The
//! terminals of this computer run in the app and are kept here, not there,
//! so the engine finds theirs itself, the same way and in the same shape;
//! before signing in, the notes made on this computer too. Signed in, the
//! page's question goes to tTerm as well, and the two answers become one
//! (`merge`, from cloud_api.rs).
//!
//! A query is words: each must be there, in any order and any case, and a
//! word may sit inside another (`cert` finds `certbot`). What a command
//! printed is searched as plain text, the start and the end of a long
//! output (`plain`), kept with its block from 0.3.1; blocks kept before get
//! theirs in the background (Store::fill_texts).

use regex::Regex;
use rusqlite::types::ValueRef;
use rusqlite::{params_from_iter, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

/// A query: this long at most, this many words.
pub const QUERY_MAX: usize = 200;
pub const WORDS_MAX: usize = 8;
/// Of a long output, the text search reads: this much from the start and
/// this much from the end (characters).
const TEXT_HEAD: usize = 8 * 1024;
const TEXT_TAIL: usize = 8 * 1024;
/// Rows looked at for each kind, and found of each kind sent back.
const SCAN_MAX: usize = 400;
const OUTPUT_SCAN_MAX: usize = 200;
pub const FOUND_MAX: usize = 40;
/// Lines of output that come with a block found, each at most so long.
const EXCERPT_LINES: usize = 8;
const LINE_MAX: usize = 300;
/// Of a note found, the blocks around the place.
const NOTE_LINES: usize = 6;
/// Commands for the palette before anything is typed.
pub const RECENT_MAX: usize = 5;
/// Where `plain` cut a long output, on a line of its own.
const CUT: char = '…';

// Escape sequences: CSI (colours, the cursor, erasing), OSC (titles, links),
// the string ones (DCS, SOS, PM, APC), character sets, and the rest of two
// characters; as the core's.
static ESCAPES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\x1b\[[0-?]*[ -/]*[@-~]",
        r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?",
        r"|\x1b[PX^_][^\x1b]*(?:\x1b\\)?",
        r"|\x1b[()*+][0-~]",
        r"|\x1b[ -/]*[0-~]",
    ))
    .expect("the escapes")
});
/// Control characters but the tab; line breaks are dealt with before.
static CONTROL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\x00-\x08\x0b-\x1f\x7f]").expect("the control characters"));

// ------------------------------------------------------------------ text

/// One line as the screen leaves it: a carriage return goes back to the
/// start of the line, so a progress bar ends as its last state, and a
/// backspace one character back.
fn screen_line(raw: &str) -> String {
    if !raw.contains('\r') && !raw.contains('\u{8}') {
        return raw.to_string();
    }
    let mut cells: Vec<char> = Vec::new();
    let mut at = 0usize;
    for ch in raw.chars() {
        match ch {
            '\r' => at = 0,
            '\u{8}' => at = at.saturating_sub(1),
            _ => {
                if at < cells.len() {
                    cells[at] = ch;
                } else {
                    cells.push(ch);
                }
                at += 1;
            }
        }
    }
    cells.into_iter().collect()
}

/// What a terminal printed, as text to search: the escape sequences out,
/// each line as the screen leaves it, no control characters; of a long
/// output its start and its end, whole lines.
pub fn plain(output: &[u8]) -> String {
    if output.is_empty() {
        return String::new();
    }
    let decoded = String::from_utf8_lossy(output);
    let text = ESCAPES.replace_all(&decoded, "").replace("\r\n", "\n");
    let lines: Vec<String> = text.split('\n').map(|l| CONTROL.replace_all(&screen_line(l), "").trim_end().to_string()).collect();
    let joined = lines.join("\n");
    let text = joined.trim_matches('\n');
    let count = text.chars().count();
    if count <= TEXT_HEAD + TEXT_TAIL {
        return text.to_string();
    }
    let head: String = text.chars().take(TEXT_HEAD).collect();
    let tail: String = text.chars().skip(count - TEXT_TAIL).collect();
    let head = match head.rfind('\n') {
        Some(i) => head[..i].to_string(),
        None => head,
    };
    let tail = match tail.find('\n') {
        Some(i) => tail[i + 1..].to_string(),
        None => tail,
    };
    format!("{head}\n{CUT}\n{tail}")
}

/// The words of a query, in lower case, each once; control characters are
/// spaces.
pub fn words(query: &str) -> Vec<String> {
    let query: String = query.chars().take(QUERY_MAX).collect();
    let spaced = CONTROL.replace_all(&query, " ").to_lowercase();
    let mut found: Vec<String> = Vec::new();
    for word in spaced.split_whitespace() {
        if !found.iter().any(|f| f == word) {
            found.push(word.to_string());
        }
    }
    found.truncate(WORDS_MAX);
    found
}

/// Whether the text has every word, in any case.
pub fn has(text: &str, words: &[String]) -> bool {
    let low = text.to_lowercase();
    words.iter().all(|w| low.contains(w.as_str()))
}

fn cut(line: &str) -> String {
    if line.chars().count() <= LINE_MAX {
        line.to_string()
    } else {
        let mut short: String = line.chars().take(LINE_MAX).collect();
        short.push('…');
        short
    }
}

/// The pattern of LIKE that finds the word anywhere, its own % and _ as
/// themselves.
fn like(word: &str) -> String {
    format!("%{}%", word.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"))
}

/// Every word in `column`: LIKE for words of ASCII (SQLite folds the case
/// of ASCII itself, and fast), `tterm_has` for the rest, folded as Rust
/// folds any letter (Store's connection has it).
fn where_words(column: &str, words: &[String], args: &mut Vec<rusqlite::types::Value>) -> String {
    let mut sql = String::new();
    for w in words {
        if w.is_ascii() {
            sql.push_str(&format!(" AND {column} LIKE ? ESCAPE '\\'"));
            args.push(like(w).into());
        } else {
            sql.push_str(&format!(" AND tterm_has({column}, ?)"));
            args.push(w.clone().into());
        }
    }
    sql
}

/// `tterm_has(text, word)` for SQLite: whether the text has the word (given
/// in lower case), in any case. Registered on each connection of the store.
pub fn register(conn: &Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;
    conn.create_scalar_function("tterm_has", 2, FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC, |ctx| {
        let word: String = ctx.get(1)?;
        let text = match ctx.get_raw(0) {
            ValueRef::Text(t) => std::str::from_utf8(t).map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?,
            _ => return Ok(false),
        };
        // Text of ASCII alone has none of the words that are not (in lower
        // case, ASCII stays ASCII): most of what terminals print, at once.
        // Where `plain` cut a long output does not count: those outputs are
        // most of the text kept, and each has the mark.
        if !word.is_ascii() && !word.contains(CUT) && text.split(CUT).all(|part| part.is_ascii()) {
            return Ok(false);
        }
        Ok(text.to_lowercase().contains(&word))
    })
}

// ------------------------------------------------------------- the store

/// Where this computer's terminals are, as the blocks found say it: the
/// machine it is (in tTerm once signed in), its project.
#[derive(Clone, Debug)]
pub struct Where {
    pub machine_id: String,
    pub machine: String,
    pub project_id: String,
    pub code: String,
    pub project: String,
}

struct Row {
    id: i64,
    terminal_id: String,
    seq: i64,
    command: String,
    cwd: String,
    branch: String,
    exit_code: Option<i64>,
    started: Option<i64>,
    finished: Option<i64>,
    text: Option<String>,
    name: String,
    closed: Option<i64>,
    home: Option<String>,
}

const BLOCKS: &str = "
    SELECT b.id, b.terminal_id, b.seq_start, coalesce(b.command, ''), coalesce(b.cwd, ''),
           coalesce(b.branch, ''), b.exit_code, b.started_at, b.finished_at, {text},
           t.name, t.closed_at, t.home
    FROM blocks b
    JOIN terminals t ON t.id = b.terminal_id
    WHERE b.expires_at > ?";

/// The blocks with `extra` true of them, the latest `limit`: their numbers
/// first, by the order of when they started (an index), then each of them
/// whole, with `text` (a column, or NULL): no text goes through the sort.
fn rows(c: &Connection, text: &str, extra: &str, mut args: Vec<rusqlite::types::Value>, limit: usize) -> rusqlite::Result<Vec<Row>> {
    args.insert(0, crate::terminals::now_ms().into());
    let mut ids = c.prepare(&format!("SELECT b.id FROM blocks b WHERE b.expires_at > ?{extra} ORDER BY b.started_at DESC, b.id DESC LIMIT {limit}"))?;
    let ids: Vec<i64> = ids.query_map(params_from_iter(args), |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    let mut one = c.prepare(&format!("{} AND b.id = ?", BLOCKS.replace("{text}", text)))?;
    let now = crate::terminals::now_ms();
    let mut found = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(row) = one.query_row(rusqlite::params![now, id], row_of).optional()? {
            found.push(row);
        }
    }
    Ok(found)
}

fn row_of(r: &rusqlite::Row) -> rusqlite::Result<Row> {
    Ok(Row {
        id: r.get(0)?,
        terminal_id: r.get(1)?,
        seq: r.get(2)?,
        command: r.get(3)?,
        cwd: r.get(4)?,
        branch: r.get(5)?,
        exit_code: r.get(6)?,
        started: r.get(7)?,
        finished: r.get(8)?,
        text: r.get(9)?,
        name: r.get(10)?,
        closed: r.get(11)?,
        home: r.get(12)?,
    })
}

/// A block found, as the page shows it: the command, how it ended, where
/// and when, and its terminal as its tab names it.
fn block(r: &Row, at: &Where, homes: &HashMap<String, String>) -> Value {
    let mut label = format!("{}/{}", at.code, at.machine);
    if !r.name.is_empty() && r.name != "1" {
        label.push_str(&format!(" · {}", r.name));
    }
    let home = r.home.clone().filter(|h| !h.is_empty()).or_else(|| homes.get(&r.terminal_id).cloned()).unwrap_or_default();
    json!({
        "terminalId": r.terminal_id,
        "seq": r.seq,
        "command": r.command,
        "cwd": r.cwd,
        "home": home,
        "branch": r.branch,
        "exitCode": r.exit_code,
        "startedAt": r.started,
        "finishedAt": r.finished,
        "machineId": at.machine_id,
        "machine": at.machine,
        "machineKind": "computer",
        "removed": false,
        "projectId": at.project_id,
        "code": at.code,
        "project": at.project,
        "terminal": label,
        "ended": r.closed.is_some(),
        "endedAt": r.closed,
    })
}

/// The first lines of what these blocks printed: read only for the blocks
/// sent, not for every one looked at.
fn starts(c: &Connection, ids: &[i64]) -> rusqlite::Result<HashMap<i64, Vec<String>>> {
    let mut found = HashMap::new();
    let mut st = c.prepare("SELECT substr(output_text, 1, 4000) FROM blocks WHERE id = ?1")?;
    for id in ids {
        let text: Option<String> = st.query_row([id], |r| r.get(0)).ok().flatten();
        let lines = text.map(|t| t.split('\n').take(EXCERPT_LINES).map(cut).collect()).unwrap_or_default();
        found.insert(*id, lines);
    }
    Ok(found)
}

/// Commands with every word in them, the latest run of each, with how many
/// runs there were and the start of its output.
fn commands(c: &Connection, ws: &[String], at: &Where, homes: &HashMap<String, String>) -> rusqlite::Result<(Vec<Value>, bool)> {
    let mut args = Vec::new();
    let extra = format!(" AND b.command <> ''{}", where_words("b.command", ws, &mut args));
    let found = rows(c, "NULL", &extra, args, SCAN_MAX)?;
    let mut order: Vec<String> = Vec::new();
    let mut by_command: HashMap<String, (Value, i64)> = HashMap::new();
    for r in &found {
        if let Some((b, _)) = by_command.get_mut(&r.command) {
            b["runs"] = json!(b["runs"].as_i64().unwrap_or(1) + 1);
            continue;
        }
        let mut b = block(r, at, homes);
        b["runs"] = json!(1);
        b["lines"] = json!([]);
        b["hit"] = json!(-1);
        by_command.insert(r.command.clone(), (b, r.id));
        order.push(r.command.clone());
    }
    let more = order.len() > FOUND_MAX || found.len() >= SCAN_MAX;
    let listed: Vec<(Value, i64)> = order.iter().take(FOUND_MAX).filter_map(|k| by_command.remove(k)).collect();
    let firsts = starts(c, &listed.iter().map(|(_, id)| *id).collect::<Vec<_>>())?;
    let listed = listed
        .into_iter()
        .map(|(mut b, id)| {
            b["lines"] = json!(firsts.get(&id).cloned().unwrap_or_default());
            b
        })
        .collect();
    Ok((listed, more))
}

/// Blocks whose output has every word, with the line where they are (or
/// the first of them) and the lines around it.
fn output(c: &Connection, ws: &[String], at: &Where, homes: &HashMap<String, String>) -> rusqlite::Result<(Vec<Value>, bool)> {
    let mut args = Vec::new();
    let extra = where_words("b.output_text", ws, &mut args);
    let found = rows(c, "b.output_text", &extra, args, OUTPUT_SCAN_MAX)?;
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut listed = Vec::new();
    for r in &found {
        let text = r.text.clone().unwrap_or_default();
        let lines: Vec<&str> = if text.is_empty() { Vec::new() } else { text.split('\n').collect() };
        let hit = lines.iter().position(|l| has(l, ws)).or_else(|| lines.iter().position(|l| l.to_lowercase().contains(ws[0].as_str()))).unwrap_or(0);
        let line = lines.get(hit).copied().unwrap_or("");
        let key = (r.command.clone(), line.to_string());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        let start = hit.saturating_sub(2);
        let mut b = block(r, at, homes);
        b["line"] = json!(cut(line.trim()));
        b["lines"] = json!(lines.iter().skip(start).take(EXCERPT_LINES).map(|l| cut(l)).collect::<Vec<_>>());
        b["hit"] = json!(hit - start);
        b["lineNo"] = json!(hit);
        listed.push(b);
    }
    let more = listed.len() > FOUND_MAX || found.len() >= OUTPUT_SCAN_MAX;
    listed.truncate(FOUND_MAX);
    Ok((listed, more))
}

/// What the palette offers before anything is typed: the commands run most
/// on this computer, the latest run of each.
fn recent(c: &Connection, at: &Where, homes: &HashMap<String, String>) -> rusqlite::Result<Vec<Value>> {
    let mut st = c.prepare(&format!(
        "SELECT max(id), count(*) FROM blocks
         WHERE command IS NOT NULL AND command <> '' AND expires_at > ?1
         GROUP BY command ORDER BY count(*) DESC, max(started_at) DESC LIMIT {RECENT_MAX}"
    ))?;
    let top: Vec<(i64, i64)> = st.query_map([crate::terminals::now_ms()], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
    let firsts = starts(c, &top.iter().map(|(id, _)| *id).collect::<Vec<_>>())?;
    let mut listed = Vec::new();
    for (id, runs) in top {
        let Some(r) = rows(c, "NULL", " AND b.id = ?", vec![id.into()], 1)?.into_iter().next() else { continue };
        let mut b = block(&r, at, homes);
        b["runs"] = json!(runs);
        b["lines"] = json!(firsts.get(&id).cloned().unwrap_or_default());
        b["hit"] = json!(-1);
        listed.push(b);
    }
    Ok(listed)
}

/// The notes made on this computer with every word in their title or what
/// is written in them, with the block where the words are and the blocks
/// around it (before signing in: then they all are this computer's).
fn notes(c: &Connection, ws: &[String], at: &Where) -> rusqlite::Result<(Vec<Value>, bool)> {
    // Each word in the title or in the text of a block, then the latest of
    // those, then each looked at again below. The body is kept as JSON:
    // what it is written with (`id`, `type`, `text`, the kinds of block) is
    // in every note, so only the texts are looked in, as the core does, and
    // as written (a quote, a backslash). A body that is not JSON: its title.
    // A block is read from itself, not from the body each time (that is a
    // walk to it from the first block).
    const BLOCK: &str = "CASE WHEN b.type = 'object' THEN b.value ELSE '{}' END";
    let mut args: Vec<rusqlite::types::Value> = Vec::new();
    let mut filter = String::new();
    for w in ws {
        let (test, arg): (&str, rusqlite::types::Value) =
            if w.is_ascii() { ("{} LIKE ? ESCAPE '\\'", like(w).into()) } else { ("tterm_has({}, ?)", w.clone().into()) };
        let on = |what: &str| test.replace("{}", what);
        // A word in a text is in the body as kept too (JSON writes any
        // letter as it is), unless JSON writes it otherwise: a quick look
        // first, and only then the blocks.
        let quick = !w.contains('"') && !w.contains('\\');
        filter.push_str(&format!(
            " AND ({} OR ({} EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(n.body) THEN n.body ELSE '[]' END) b
                     WHERE json_extract({BLOCK}, '$.type') IS NOT 'hr' AND {})))",
            on("n.title"),
            if quick { format!("{} AND", on("n.body")) } else { String::new() },
            on(&format!("json_extract({BLOCK}, '$.text')")),
        ));
        args.push(arg.clone());
        if quick {
            args.push(arg.clone());
        }
        args.push(arg);
    }
    let mut st = c.prepare(&format!(
        "SELECT n.id, n.title, n.body, n.edited_at, f.id, f.name FROM notes n
         JOIN note_folders f ON f.id = n.folder_id
         WHERE 1{filter}
         ORDER BY n.edited_at DESC LIMIT {SCAN_MAX}"
    ))?;
    let all: Vec<(String, String, String, Option<i64>, String, String)> =
        st.query_map(params_from_iter(args), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?.collect::<rusqlite::Result<_>>()?;
    let scanned = all.len();
    let mut found = Vec::new();
    for (id, title, body, edited, folder_id, folder) in all {
        let blocks: Vec<Value> = serde_json::from_str::<Vec<Value>>(&body)
            .unwrap_or_default()
            .into_iter()
            .filter(|b| b.is_object() && b["type"] != "hr")
            .collect();
        let texts: Vec<String> = blocks.iter().map(|b| b["text"].as_str().unwrap_or("").to_string()).collect();
        if !has(&format!("{title}\n{}", texts.join("\n")), ws) {
            continue;
        }
        let low_title = title.to_lowercase();
        let mut hit = texts.iter().position(|t| has(t, ws));
        if hit.is_none() {
            let missing: Vec<&String> = ws.iter().filter(|w| !low_title.contains(w.as_str())).collect();
            hit = texts.iter().position(|t| {
                let low = t.to_lowercase();
                !missing.is_empty() && missing.iter().any(|w| low.contains(w.as_str()))
            });
        }
        let start = hit.map(|h| h.saturating_sub(1)).unwrap_or(0);
        let near: Vec<Value> = blocks
            .iter()
            .skip(start)
            .take(NOTE_LINES)
            .map(|b| json!({"text": cut(b["text"].as_str().unwrap_or("")), "type": b["type"].clone(), "done": b["done"] == true}))
            .collect();
        found.push(json!({
            "noteId": id,
            "title": title,
            "folderId": folder_id,
            "folder": folder,
            "projectId": at.project_id,
            "code": at.code,
            "project": at.project,
            "editedAt": edited,
            "inTitle": has(&title, ws),
            "blockId": hit.and_then(|h| blocks[h]["id"].as_str()).map(str::to_string),
            "text": hit.map(|h| cut(texts[h].split('\n').next().unwrap_or(""))).unwrap_or_default(),
            "lines": near,
            "hit": hit.map(|h| (h - start) as i64).unwrap_or(-1),
        }));
        // One more than are sent back says there are more.
        if found.len() > FOUND_MAX {
            break;
        }
    }
    let more = found.len() > FOUND_MAX || scanned >= SCAN_MAX;
    found.truncate(FOUND_MAX);
    Ok((found, more))
}

/// Everything of this computer's with all the words of `query`: commands,
/// their output and, `with_notes`, notes, the latest first. Nothing typed:
/// the commands run most here, if `near` is this computer.
pub async fn search(engine: &Arc<crate::Engine>, query: &str, near: Option<&str>, with_notes: bool) -> Value {
    let ws = words(query);
    let at = engine.search_place();
    let homes: HashMap<String, String> = engine
        .terminals
        .live()
        .iter()
        .filter_map(|t| {
            let d = t.describe();
            Some((d["id"].as_str()?.to_string(), d["home"].as_str()?.to_string()))
        })
        .collect();
    let here = near.and_then(|n| uuid::Uuid::parse_str(n).ok()).map(|n| engine.is_here(n)).unwrap_or(false);
    let empty = json!({"words": ws, "commands": [], "output": [], "notes": [], "recent": [], "more": {}});
    let answer = engine
        .terminals
        .store
        .search(move |c, wanted| -> rusqlite::Result<Value> {
            if ws.is_empty() {
                let recent = if here { recent(c, &at, &homes)? } else { Vec::new() };
                return Ok(json!({"words": [], "commands": [], "output": [], "notes": [], "more": {}, "recent": recent}));
            }
            let (commands, more_c) = commands(c, &ws, &at, &homes)?;
            if !wanted() {
                return Err(superseded());
            }
            let (output, more_o) = output(c, &ws, &at, &homes)?;
            if !wanted() {
                return Err(superseded());
            }
            let (notes, more_n) = if with_notes { notes(c, &ws, &at)? } else { (Vec::new(), false) };
            Ok(json!({"words": ws, "commands": commands, "output": output, "notes": notes, "recent": [],
                "more": {"commands": more_c, "output": more_o, "notes": more_n}}))
        })
        .await;
    match answer {
        Some(Ok(found)) => found,
        // Stopped for a newer search: the page has gone on to that one.
        Some(Err(e)) if stopped(&e) => empty,
        Some(Err(e)) => {
            eprintln!("tterm: search could not read the store: {e}");
            empty
        }
        None => empty,
    }
}

/// What a search stopped for a newer one ends with.
fn superseded() -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT), Some("a newer search came".into()))
}

fn stopped(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::OperationInterrupted)
}

// --------------------------------------------------------------- merging

fn list(v: &Value, key: &str) -> Vec<Value> {
    v[key].as_array().cloned().unwrap_or_default()
}

fn at_of(b: &Value) -> i64 {
    b["startedAt"].as_i64().unwrap_or(0)
}

/// Blocks of both, one entry for a command on a machine: its latest run,
/// with the runs of both counted.
fn by_command(both: Vec<Value>) -> Vec<Value> {
    let mut order: Vec<(String, String)> = Vec::new();
    let mut found: HashMap<(String, String), Value> = HashMap::new();
    for b in both {
        let key = (b["command"].as_str().unwrap_or("").to_string(), b["machineId"].as_str().unwrap_or("").to_string());
        match found.get_mut(&key) {
            Some(kept) => {
                let runs = kept["runs"].as_i64().unwrap_or(1) + b["runs"].as_i64().unwrap_or(1);
                if at_of(&b) > at_of(kept) {
                    *kept = b;
                }
                kept["runs"] = json!(runs);
            }
            None => {
                order.push(key.clone());
                found.insert(key, b);
            }
        }
    }
    order.into_iter().filter_map(|k| found.remove(&k)).collect()
}

/// tTerm's answer and this computer's, as one: commands and output the
/// latest first, a command on a machine once, notes tTerm's (signed in,
/// the notes are there).
pub fn merge(local: &Value, cloud: &Value) -> Value {
    let mut commands = by_command([list(cloud, "commands"), list(local, "commands")].concat());
    commands.sort_by_key(|b| std::cmp::Reverse(at_of(b)));
    let more_c = commands.len() > FOUND_MAX;
    commands.truncate(FOUND_MAX);
    let mut output: Vec<Value> = Vec::new();
    let mut seen: Vec<(String, String, String)> = Vec::new();
    let mut both = [list(cloud, "output"), list(local, "output")].concat();
    both.sort_by_key(|b| std::cmp::Reverse(at_of(b)));
    for b in both {
        let key = (
            b["command"].as_str().unwrap_or("").to_string(),
            b["machineId"].as_str().unwrap_or("").to_string(),
            b["line"].as_str().unwrap_or("").to_string(),
        );
        if !seen.contains(&key) {
            seen.push(key);
            output.push(b);
        }
    }
    let more_o = output.len() > FOUND_MAX;
    output.truncate(FOUND_MAX);
    let mut recent = by_command([list(cloud, "recent"), list(local, "recent")].concat());
    recent.sort_by(|a, b| b["runs"].as_i64().unwrap_or(0).cmp(&a["runs"].as_i64().unwrap_or(0)).then(at_of(b).cmp(&at_of(a))));
    recent.truncate(RECENT_MAX);
    let more = |k: &str| cloud["more"][k].as_bool().unwrap_or(false) || local["more"][k].as_bool().unwrap_or(false);
    let words = if cloud["words"].is_array() { cloud["words"].clone() } else { local["words"].clone() };
    json!({
        "words": words,
        "commands": commands,
        "output": output,
        "notes": list(cloud, "notes"),
        "recent": recent,
        "more": {"commands": more("commands") || more_c, "output": more("output") || more_o, "notes": more("notes")},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_as_the_screen_leaves_it() {
        assert_eq!(plain(b"\x1b[1;32mok\x1b[0m done\r\n"), "ok done");
        assert_eq!(plain(b"10%\r50%\r100% finished\n"), "100% finished");
        assert_eq!(plain(b"ab\x08c\n\x1b]0;title\x07next"), "ac\nnext");
        assert_eq!(plain(b"\n\nline\n\n"), "line");
        assert_eq!(plain("Ошибка: нет файла\n".as_bytes()), "Ошибка: нет файла");
        let long: String = (0..4000).map(|i| format!("line {i}\n")).collect();
        let text = plain(long.as_bytes());
        assert!(text.starts_with("line 0\n") && text.ends_with("line 3999") && text.contains("\n…\n"), "{}", &text[..40]);
        assert!(text.chars().count() <= TEXT_HEAD + TEXT_TAIL + 3);
    }

    #[test]
    fn the_words_of_a_query() {
        assert_eq!(words("  Deploy  web deploy\u{7}ERR "), ["deploy", "web", "err"]);
        assert_eq!(words("Ошибка ФАЙЛА"), ["ошибка", "файла"]);
        assert_eq!(words("a b c d e f g h i j").len(), WORDS_MAX);
        assert!(words("   ").is_empty());
        assert!(has("Certbot renew", &words("CERT ren")));
        assert!(!has("certbot", &words("cert x")));
        assert_eq!(like("50%_a\\b"), "%50\\%\\_a\\\\b%");
    }

    fn b(command: &str, machine: &str, at: i64, runs: i64) -> Value {
        json!({"command": command, "machineId": machine, "startedAt": at, "runs": runs, "line": format!("{command} line")})
    }

    fn at() -> Where {
        Where { machine_id: "m-here".into(), machine: "MacBook-Pro-Anna".into(), project_id: "p-1".into(), code: "P".into(), project: "Personal".into() }
    }

    fn finished(seq: u64, command: &str, output: &str, at: i64) -> crate::store::Finished {
        crate::store::Finished {
            seq_start: seq,
            seq_end: seq + 2,
            command: command.into(),
            started_ms: at,
            finished_ms: at + 5,
            exit_code: Some(0),
            cwd: "/Users/anna/web".into(),
            output: output.as_bytes().to_vec(),
            cols: 80,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn this_computers_commands_output_and_notes_are_found() {
        let dir = std::env::temp_dir().join(format!("tterm-search-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = crate::store::Store::open(&dir);
        let now = crate::terminals::now_ms();
        store.opened("t1", "1", now);
        store.opened("t2", "work", now);
        store.save_block("t1", finished(10, "deploy web", "\x1b[32mdone\x1b[0m\r\n", now - 3000));
        store.save_block("t1", finished(20, "make", "cc main.c\r\n\x1b[31mERROR: disk full\x1b[0m\r\nmake: *** [all] Error 1\r\n", now - 2000));
        store.save_block("t2", finished(30, "deploy web", "done\r\n", now - 1000));
        store.save_block("t2", finished(40, "echo Ошибка", "Ошибка: нет файла\r\n", now - 500));
        store.ended("t1", 50, "Closed.", Some("zsh"), "/Users/anna");
        store.run(|c| {
            c.execute_batch(
                "INSERT INTO note_folders (id, project_id, name, name_key, created_at) VALUES ('f1', 'p-1', 'Runbooks', 'runbooks', 1);
                 INSERT INTO notes (id, folder_id, title, body, created_at, edited_at) VALUES
                   ('n1', 'f1', 'Deploy', '[{\"id\":\"b1\",\"type\":\"p\",\"text\":\"first\"},{\"id\":\"b2\",\"type\":\"todo\",\"text\":\"Check the Disk\",\"done\":true}]', 1, 5);",
            )
            .unwrap()
        })
        .await
        .unwrap();
        let homes = HashMap::from([("t2".to_string(), "/Users/anna".to_string())]);
        let found = store
            .run(move |c| {
                let place = at();
                let deploy = commands(c, &words("DEPLOY"), &place, &homes).unwrap();
                let disk = output(c, &words("disk full"), &place, &homes).unwrap();
                let russian = commands(c, &words("ошибка"), &place, &homes).unwrap();
                let russian_out = output(c, &words("НЕТ файла"), &place, &homes).unwrap();
                let none = commands(c, &words("deploy nothing"), &place, &homes).unwrap();
                let notes = notes(c, &words("disk"), &place).unwrap();
                let top = recent(c, &place, &homes).unwrap();
                (deploy, disk, russian, russian_out, none, notes, top)
            })
            .await
            .unwrap();
        let (deploy, disk, russian, russian_out, none, notes, top) = found;
        assert_eq!(deploy.0.len(), 1, "one entry for a command: {:?}", deploy.0);
        let d = &deploy.0[0];
        assert_eq!((d["runs"].as_i64(), d["seq"].as_i64(), d["terminal"].as_str()), (Some(2), Some(30), Some("P/MacBook-Pro-Anna · work")));
        assert_eq!((d["machineId"].as_str(), d["machineKind"].as_str(), d["ended"].as_bool()), (Some("m-here"), Some("computer"), Some(false)));
        assert_eq!(d["home"], "/Users/anna", "of a terminal running, from it");
        assert_eq!(d["lines"], json!(["done"]));
        let k = &disk.0[0];
        assert_eq!((k["command"].as_str(), k["line"].as_str(), k["hit"].as_i64(), k["lineNo"].as_i64()), (Some("make"), Some("ERROR: disk full"), Some(1), Some(1)));
        assert_eq!(k["lines"], json!(["cc main.c", "ERROR: disk full", "make: *** [all] Error 1"]));
        assert_eq!((k["ended"].as_bool(), k["terminal"].as_str(), k["home"].as_str()), (Some(true), Some("P/MacBook-Pro-Anna"), Some("/Users/anna")));
        assert_eq!(russian.0.len(), 1, "any case, any letters");
        assert_eq!(russian_out.0[0]["line"], "Ошибка: нет файла");
        assert!(none.0.is_empty());
        let n = &notes.0[0];
        assert_eq!((n["noteId"].as_str(), n["blockId"].as_str(), n["hit"].as_i64(), n["inTitle"].as_bool()), (Some("n1"), Some("b2"), Some(1), Some(false)));
        assert_eq!(n["lines"][1], json!({"text": "Check the Disk", "type": "todo", "done": true}));
        let commands_run: Vec<(&str, i64)> = top.iter().map(|b| (b["command"].as_str().unwrap(), b["runs"].as_i64().unwrap())).collect();
        assert_eq!(commands_run, [("deploy web", 2), ("echo Ошибка", 1), ("make", 1)]);

        // Blocks kept before 0.3.1 have no text yet: made in the background.
        store.run(|c| c.execute("UPDATE blocks SET output_text = NULL", []).unwrap()).await.unwrap();
        let before = store.run(|c| output(c, &words("disk"), &at(), &HashMap::new()).unwrap()).await.unwrap();
        assert!(before.0.is_empty());
        assert_eq!(store.fill_texts().await, 4);
        let after = store.run(|c| output(c, &words("disk"), &at(), &HashMap::new()).unwrap()).await.unwrap();
        assert_eq!(after.0.len(), 1);
        assert_eq!(store.fill_texts().await, 0, "once");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn notes_are_found_among_many_and_any_letters_are_matched() {
        let dir = std::env::temp_dir().join(format!("tterm-search-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = crate::store::Store::open(&dir);
        store
            .run(|c| {
                c.execute("INSERT INTO note_folders (id, project_id, name, name_key, created_at) VALUES ('f1', 'p-1', 'Runbooks', 'runbooks', 1)", []).unwrap();
                for i in 0..(SCAN_MAX + 1) {
                    let title = if i == 0 { "Rotate the vault keys".to_string() } else { format!("Note {i}") };
                    c.execute(
                        "INSERT INTO notes (id, folder_id, title, body, created_at, edited_at) VALUES (?1, 'f1', ?2, '[]', 1, ?3)",
                        rusqlite::params![format!("n{i}"), title, i as i64],
                    )
                    .unwrap();
                }
            })
            .await
            .unwrap();
        let (vault, none, ascii, russian) = store
            .run(|c| {
                let vault = notes(c, &words("vault"), &at()).unwrap();
                let none = notes(c, &words("zzz"), &at()).unwrap();
                let has = |text: &str, word: &str| c.query_row("SELECT tterm_has(?1, ?2)", rusqlite::params![text, word], |r| r.get::<_, bool>(0)).unwrap();
                (vault, none, has("PLAIN ascii text", "ошибка"), has("Текст с ОШИБКОЙ", "ошибкой"))
            })
            .await
            .unwrap();
        assert_eq!(vault.0.len(), 1, "the oldest of {} notes", SCAN_MAX + 1);
        assert!(!vault.1, "nothing more");
        assert!(none.0.is_empty() && !none.1, "none, and none more");
        assert!(!ascii && russian);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn notes_are_looked_in_by_what_is_written_not_how_it_is_kept() {
        let dir = std::env::temp_dir().join(format!("tterm-search-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = crate::store::Store::open(&dir);
        store
            .run(|c| {
                c.execute("INSERT INTO note_folders (id, project_id, name, name_key, created_at) VALUES ('f1', 'p-1', 'Runbooks', 'runbooks', 1)", []).unwrap();
                let note = |id: &str, title: &str, body: &str, edited: i64| {
                    c.execute(
                        "INSERT INTO notes (id, folder_id, title, body, created_at, edited_at) VALUES (?1, 'f1', ?2, ?3, 1, ?4)",
                        rusqlite::params![id, title, body, edited],
                    )
                    .unwrap();
                };
                // The oldest, under as many as search looks at: what is
                // written in it has the words its JSON is written with.
                let oldest = json!([
                    {"id": "b1", "type": "p", "text": "Check the type and the text of \"quoted\" in C:\\path"},
                    {"id": "b2", "type": "hr", "text": "hidden"},
                    {"id": "b3", "type": "todo", "text": "Ротация ключей", "done": true},
                ]);
                note("n0", "Old", &oldest.to_string(), 0);
                for i in 1..=(SCAN_MAX as i64) {
                    note(&format!("n{i}"), &format!("Note {i}"), &json!([{"id": format!("x{i}"), "type": "p", "text": "nothing here"}]).to_string(), i);
                }
                // Bodies as nothing writes them: none of them stops search.
                note("bad", "Broken body", "{not json", 1000);
                note("odd", "Odd", r#"["a plain string", {"type": "p", "text": 5}, 7, null]"#, 1001);
                note("obj", "Object", r#"{"text": "an object"}"#, 1002);
            })
            .await
            .unwrap();
        let found = |q: &'static str| {
            let store = store.clone();
            async move {
                store
                    .run(move |c| {
                        let (notes, more) = notes(c, &words(q), &at()).unwrap();
                        (notes.iter().map(|n| n["noteId"].as_str().unwrap().to_string()).collect::<Vec<_>>(), more)
                    })
                    .await
                    .unwrap()
            }
        };
        let oldest = (vec!["n0".to_string()], false);
        assert_eq!(found("type text").await, oldest, "under {SCAN_MAX} newer notes");
        assert_eq!(found("\"quoted\"").await, oldest, "a quote as written");
        assert_eq!(found("c:\\path").await, oldest, "a backslash as written");
        assert_eq!(found("ротация").await, oldest);
        assert_eq!(found("id").await, (vec![], false), "how the note is kept is not looked in");
        assert_eq!(found("hidden").await, (vec![], false), "nor the text of a line");
        assert_eq!(found("broken").await, (vec!["bad".to_string()], false), "a body that is not JSON: its title");
        assert_eq!(found("plain").await, (vec![], false));
        assert_eq!(found("object").await, (vec!["obj".to_string()], false), "its title");
        // Where a long output was cut does not make it text of more than ASCII.
        let (cut_ascii, cut_russian, the_mark) = store
            .run(|c| {
                let has = |text: &str, word: &str| c.query_row("SELECT tterm_has(?1, ?2)", rusqlite::params![text, word], |r| r.get::<_, bool>(0)).unwrap();
                (has("PLAIN ascii\n…\ntext", "ошибка"), has("Текст\n…\nс ОШИБКОЙ", "ошибкой"), has("ascii\n…\ntext", "…"))
            })
            .await
            .unwrap();
        assert!(!cut_ascii && cut_russian && the_mark);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn two_answers_as_one() {
        let local = json!({"words": ["deploy"], "commands": [b("deploy web", "mac", 30, 2), b("deploy db", "mac", 10, 1)],
            "output": [b("deploy web", "mac", 30, 1)], "notes": [], "recent": [b("ls", "mac", 5, 9)], "more": {"commands": false}});
        let cloud = json!({"words": ["deploy"], "commands": [b("deploy web", "mac", 20, 3), b("deploy web", "lab", 40, 1)],
            "output": [b("deploy web", "mac", 20, 1), b("deploy api", "lab", 25, 1)], "notes": [{"noteId": "n1"}],
            "recent": [b("ls", "mac", 7, 4), b("top", "mac", 8, 20)], "more": {"output": true}});
        let m = merge(&local, &cloud);
        let commands: Vec<(String, String, i64, i64)> = m["commands"].as_array().unwrap().iter()
            .map(|x| (x["command"].as_str().unwrap().into(), x["machineId"].as_str().unwrap().into(), x["startedAt"].as_i64().unwrap(), x["runs"].as_i64().unwrap()))
            .collect();
        assert_eq!(commands, [
            ("deploy web".to_string(), "lab".to_string(), 40, 1),
            ("deploy web".to_string(), "mac".to_string(), 30, 5),
            ("deploy db".to_string(), "mac".to_string(), 10, 1),
        ]);
        let output: Vec<i64> = m["output"].as_array().unwrap().iter().map(|x| x["startedAt"].as_i64().unwrap()).collect();
        assert_eq!(output, [30, 25], "the same line of the same command on the same machine once, the latest");
        assert_eq!(m["notes"], json!([{"noteId": "n1"}]));
        let recent: Vec<(String, i64)> = m["recent"].as_array().unwrap().iter().map(|x| (x["command"].as_str().unwrap().into(), x["runs"].as_i64().unwrap())).collect();
        assert_eq!(recent, [("top".to_string(), 20), ("ls".to_string(), 13)]);
        assert_eq!(m["more"], json!({"commands": false, "output": true, "notes": false}));
        assert_eq!(m["words"], json!(["deploy"]));
    }
}
