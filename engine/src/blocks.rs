//! Commands as blocks: what the core's `Block` keeps of a command while it
//! runs, and how a finished one goes to the page's feed (`_block_json` in
//! tterm-web's `tterm/core/terminals.py`).

use crate::modes::Modes;
use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::Arc;

/// Of a long command's output, the block keeps this much from the start
/// and this much from the end.
pub const BLOCK_HEAD: usize = 512 * 1024;
pub const BLOCK_TAIL: usize = 512 * 1024;
/// Of each block in the feed's first answer, the end of its output, this
/// much at most; the rest comes when the person asks for it.
pub const FEED_TAIL: usize = 64 * 1024;
/// Blocks in one answer of the feed, at most.
pub const FEED_MAX: i64 = 200;
/// Commands in the history the input line gets.
pub const HISTORY_MAX: i64 = 1000;
/// Commands are kept this long, as a project of tTerm Web keeps them by
/// default (`output_days`).
pub const KEEP_DAYS: i64 = 30;

/// A command while it runs.
#[derive(Debug)]
pub struct Block {
    pub command: String,
    pub cwd: String,
    pub branch: String,
    /// The number of its start marker.
    pub seq_start: u64,
    /// When it started, in milliseconds.
    pub started_ms: i64,
    /// The width it ran at: the page draws its output again at this width.
    pub cols: u16,
    head: Vec<u8>,
    tail: VecDeque<Arc<[u8]>>,
    tail_bytes: usize,
    total: u64,
    /// The screen modes of everything before the kept tail.
    before_tail: Modes,
}

impl Block {
    pub fn new(command: String, cwd: String, branch: String, seq_start: u64, started_ms: i64, cols: u16) -> Self {
        Block {
            command,
            cwd,
            branch,
            seq_start,
            started_ms,
            cols,
            head: Vec::new(),
            tail: VecDeque::new(),
            tail_bytes: 0,
            total: 0,
            before_tail: Modes::new(),
        }
    }

    pub fn add(&mut self, data: &Arc<[u8]>) {
        self.total += data.len() as u64;
        let room = BLOCK_HEAD.saturating_sub(self.head.len());
        let mut rest: &[u8] = data;
        if room > 0 {
            let take = room.min(data.len());
            self.head.extend_from_slice(&data[..take]);
            self.before_tail.feed(&data[..take]);
            rest = &data[take..];
        }
        if !rest.is_empty() {
            let piece: Arc<[u8]> = if rest.len() == data.len() { data.clone() } else { Arc::from(rest) };
            self.tail_bytes += piece.len();
            self.tail.push_back(piece);
            while self.tail_bytes - self.tail[0].len() >= BLOCK_TAIL {
                let dropped = self.tail.pop_front().expect("a piece");
                self.tail_bytes -= dropped.len();
                self.before_tail.feed(&dropped);
            }
        }
    }

    /// What is kept, and whether the middle was left out. Where it was, the
    /// screen is switched to the modes the tail began in: a full-screen
    /// program that started in the middle otherwise draws its end on the
    /// main screen, as a jumble.
    pub fn output(&self) -> (Vec<u8>, bool) {
        let mut tail: Vec<u8> = Vec::with_capacity(self.tail_bytes);
        for piece in &self.tail {
            tail.extend_from_slice(piece);
        }
        let mut cut = ((self.head.len() + tail.len()) as u64) < self.total;
        let mut before = self.before_tail.clone();
        if tail.len() > BLOCK_TAIL {
            let drop = tail.len() - BLOCK_TAIL;
            before.feed(&tail[..drop]);
            tail.drain(..drop);
            cut = true;
        }
        let mut out = self.head.clone();
        if !cut {
            out.extend_from_slice(&tail);
            return (out, false);
        }
        let mut at_head_end = Modes::new();
        at_head_end.feed(&self.head);
        out.extend_from_slice(&at_head_end.switch_to(&before));
        out.extend_from_slice(&tail);
        (out, true)
    }
}

/// A finished block as the store keeps it.
#[derive(Clone, Debug, Default)]
pub struct Stored {
    pub id: i64,
    pub seq_start: i64,
    pub seq_end: Option<i64>,
    pub command: Option<String>,
    pub cwd: Option<String>,
    pub branch: Option<String>,
    pub started_ms: Option<i64>,
    pub finished_ms: Option<i64>,
    pub exit_code: Option<i64>,
    /// zlib, as the core keeps it.
    pub output: Option<Vec<u8>>,
    pub cut: bool,
    pub cols: Option<i64>,
}

pub fn compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::with_capacity(data.len() / 4 + 64), flate2::Compression::new(6));
    let _ = encoder.write_all(data);
    encoder.finish().unwrap_or_default()
}

pub fn decompress(data: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    if decoder.read_to_end(&mut out).is_err() {
        return Vec::new();
    }
    out
}

/// A finished block for the page: the end of its output only, starting at
/// a line, if it is long.
///
/// That end begins in the screen modes the output was in at that point. A
/// full-screen program (htop, top, vim) switches to its second screen at
/// the start, which the end leaves out: without the switch the page drew
/// its last screens on the main one, a jumble of numbers where the live
/// block had been empty.
pub fn feed_json(row: &Stored) -> Value {
    let output = match &row.output {
        Some(z) if !z.is_empty() => decompress(z),
        _ => Vec::new(),
    };
    let size = output.len();
    let (tail, partial) = if size > FEED_TAIL {
        let start = size - FEED_TAIL;
        let at = match output[start..].iter().position(|b| *b == b'\n') {
            Some(i) if start + i < size - 1 => start + i + 1,
            _ => start,
        };
        let mut modes = Modes::new();
        modes.feed(&output[..at]);
        let mut tail = modes.restore();
        tail.extend_from_slice(&output[at..]);
        (tail, true)
    } else {
        (output, false)
    };
    json!({
        "id": row.id,
        "seqStart": row.seq_start,
        "seqEnd": row.seq_end,
        "command": row.command.clone().unwrap_or_default(),
        "cwd": row.cwd.clone().unwrap_or_default(),
        "branch": row.branch.clone().unwrap_or_default(),
        "startedAt": row.started_ms,
        "finishedAt": row.finished_ms,
        "exitCode": row.exit_code,
        "cols": row.cols,
        "cut": row.cut,
        "partial": partial,
        "size": size,
        "output": base64::engine::general_purpose::STANDARD.encode(&tail),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece(data: &[u8]) -> Arc<[u8]> {
        Arc::from(data)
    }

    #[test]
    fn block_keeps_the_start_and_the_end() {
        let mut block = Block::new("yes".into(), "/".into(), String::new(), 1, 0, 80);
        for i in 0..3000 {
            block.add(&piece(format!("{i:06}").repeat(100).as_bytes()));
        }
        let (out, cut) = block.output();
        assert!(cut);
        assert_eq!(out.len(), BLOCK_HEAD + BLOCK_TAIL);
        assert!(out.starts_with(b"000000"));
        assert!(out.ends_with(b"002999"));
        let mut small = Block::new("ls".into(), "/".into(), String::new(), 1, 0, 80);
        small.add(&piece(b"a\r\n"));
        assert_eq!(small.output(), (b"a\r\n".to_vec(), false));
    }

    fn row(output: &[u8]) -> Stored {
        Stored { id: 1, seq_start: 1, seq_end: Some(2), command: Some("top".into()), output: Some(compress(output)), cols: Some(80), exit_code: Some(0), ..Default::default() }
    }

    #[test]
    fn cut_output_stays_on_its_screen() {
        // A full-screen program's last screens, without its start, are
        // drawn on its second screen, not as a jumble on the main one
        // (found by the owner with top on his Mac, 14.10).
        let mut frames = Vec::new();
        for i in 0..3000 {
            frames.extend_from_slice(b"\x1b[H");
            frames.extend(format!("{i:06} ").repeat(10).into_bytes());
            frames.extend_from_slice(b"\r\n");
        }
        let mut output = b"before\r\n\x1b[?1049h".to_vec();
        output.extend(&frames);
        output.extend_from_slice(b"\x1b[?1049l");
        let sent = feed_json(&row(&output));
        let tail = base64::engine::general_purpose::STANDARD.decode(sent["output"].as_str().unwrap()).unwrap();
        assert_eq!(sent["partial"], true);
        assert!(tail.starts_with(b"\x1b[?1049h\x1b[H"), "{:?}", &tail[..20]);
        assert!(tail.ends_with(b"\x1b[?1049l"));
        assert_eq!(sent["size"], output.len());
        let plain = feed_json(&row(&b"x\r\n".repeat(40000)));
        let plain_tail = base64::engine::general_purpose::STANDARD.decode(plain["output"].as_str().unwrap()).unwrap();
        assert!(!plain_tail.starts_with(b"\x1b"), "plain output starts as it was");
        assert!(plain_tail.starts_with(b"x\r\n"));

        // The middle left out: the program started in it.
        let mut block = Block::new("make; top".into(), "/".into(), String::new(), 1, 0, 80);
        for i in 0..30000 {
            // 720 KB: past what the start keeps.
            block.add(&piece(format!("line {i:06} of the build\r\n").as_bytes()));
        }
        block.add(&piece(b"\x1b[?1049h"));
        for i in 0..40000 {
            let mut f = b"\x1b[H".to_vec();
            f.extend(format!("{i:06} ").repeat(5).into_bytes());
            f.extend_from_slice(b"\r\n");
            block.add(&piece(&f));
        }
        block.add(&piece(b"\x1b[?1049l"));
        let (out, cut) = block.output();
        assert!(cut);
        assert_eq!(&out[BLOCK_HEAD..BLOCK_HEAD + 8], b"\x1b[?1049h");
        assert!(out.ends_with(b"\x1b[?1049l"));
    }

    #[test]
    fn an_empty_block_and_its_fields() {
        let sent = feed_json(&Stored { id: 7, seq_start: 3, ..Default::default() });
        assert_eq!(sent["output"], "");
        assert_eq!(sent["command"], "");
        assert_eq!(sent["exitCode"], Value::Null);
        assert_eq!(sent["seqEnd"], Value::Null);
        assert_eq!(sent["partial"], false);
        assert_eq!(decompress(&compress(b"abc")), b"abc");
        assert!(decompress(b"not zlib").is_empty());
    }
}
