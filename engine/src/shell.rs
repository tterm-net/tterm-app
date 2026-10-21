//! The shell behind a terminal, and what is read from it: a port of
//! tterm-web's `tterm/core/shell.py`.
//!
//! A terminal is the person's login shell in a pseudo-terminal, as on the
//! web. The shell also prints invisible markers, the way iTerm2, VS Code and
//! Warp do: before each prompt (the exit code, the directory, the git
//! branch) and when a command starts (its text). From them the engine cuts
//! the stream into blocks. The scripts that make the shell do this are the
//! very files tTerm Web puts on a machine (engine/shell, checked against
//! tterm-web by scripts/web.sh); this module puts them in the app's folder,
//! starts the shell with them, and takes the markers back out of the stream
//! so the screen never shows them.
//!
//! A marker is an OSC sequence that carries a one-time key:
//!
//! ```text
//! ESC ] 6973 ; <key> ; <type> ; <field> ; ... BEL
//! ```
//!
//! Programs can print anything, so a marker without the key is not ours and
//! passes through untouched. The key reaches the shell as the first line
//! typed into it, with echo off, and lives only in the shell's memory: not
//! in a file, not in the environment, not in the command line.
//!
//! One difference from the web: the scripts go into the app's own folder,
//! not into ~/.tterm, where tterm-agent puts those of the tTerm Web that
//! opens terminals on this computer. The scripts do not care where they are,
//! and the two never write over each other's files.

use regex::bytes::Regex;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// The OSC number of our markers. Nothing else uses it.
pub const OSC: &[u8] = b"6973";

/// A marker with a longer body is not one: a command's text can be long, a
/// pasted script, but not this long.
pub const MARKER_MAX: usize = 256 * 1024;

/// What goes where: the file in the scripts' folder, and what it holds.
pub const FILES: [(&str, &str); 5] = [
    ("bash.sh", include_str!("../shell/bash.sh")),
    ("zsh/.zshenv", include_str!("../shell/zshenv.zsh")),
    ("zsh/.zprofile", include_str!("../shell/zprofile.zsh")),
    ("zsh/.zshrc", include_str!("../shell/zshrc.zsh")),
    ("zsh/.zlogin", include_str!("../shell/zlogin.zsh")),
];

/// The scripts' folder in the app's own.
pub const FOLDER: &str = "shell";

/// Which shells there are: the second half of the core's deploy script,
/// run with sh in the same clean environment as the shells.
pub const DETECT: &str = concat!(
    "printf 'shell=%s\\n' \"${SHELL:-}\"\n",
    "printf 'bash=%s\\n' \"$(command -v bash 2>/dev/null)\"\n",
    "printf 'zsh=%s\\n' \"$(command -v zsh 2>/dev/null)\"\n",
    // Commands get a start marker from bash 4.4 on (PS0).
    "if command -v bash >/dev/null 2>&1; then printf 'bash_version=%s\\n' ",
    "\"$(bash -c 'echo \"${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}\"' ",
    "2>/dev/null)\"; fi\n",
);

/// A fresh one-time key: 32 hex digits, as the core's `secrets.token_hex(16)`.
pub fn new_key() -> String {
    // Two version-4 UUIDs: random bits from the system, 122 in each.
    let a = uuid::Uuid::new_v4().as_u128();
    let b = uuid::Uuid::new_v4().as_u128();
    format!("{:032x}", a ^ b.rotate_left(64))
}

static TEMP: AtomicU64 = AtomicU64::new(1);

/// Writes the scripts into `dir`, as the core's deploy script does on a
/// machine: private (the folders 0700, the files 0600), and each file under
/// a name of its own first, then renamed into place, so that a shell
/// starting at the same moment never reads half a file. Written for every
/// terminal, so that the app always has its own version of them in place.
pub fn deploy(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let mut folders = std::fs::DirBuilder::new();
    folders.recursive(true);
    #[cfg(unix)]
    folders.mode(0o700);
    folders.create(dir.join("zsh"))?;
    for (target, text) in FILES {
        let path = dir.join(target);
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let tmp = path.with_file_name(format!("{name}.{}.{}", std::process::id(), TEMP.fetch_add(1, Ordering::SeqCst)));
        let written = (|| {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&tmp)?;
            file.write_all(text.as_bytes())?;
            drop(file);
            std::fs::rename(&tmp, &path)
        })();
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    }
    Ok(())
}

/// How to start the shell, as the core's `shell.Plan`: which one, the
/// command its login shell runs, whether it has our markers, and whether it
/// marks the start of each command too, which is what cuts the stream into
/// blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellPlan {
    pub shell: String,
    pub command: String,
    pub markers: bool,
    pub blocks: bool,
}

/// A path for sh, quoted: one word whatever is in it.
pub fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// The login shell decides, as with plain ssh: zsh if it is zsh, otherwise
/// bash. Without bash the login shell starts as it is, and the terminal
/// works without blocks. bash older than 4.4 has no PS0: it marks its
/// prompts, but not where commands start. `found` is what DETECT printed,
/// `dir` the scripts' folder.
pub fn plan(found: &str, dir: &Path) -> ShellPlan {
    let mut login = "";
    let mut bash = "";
    let mut zsh = "";
    let mut bash_version = "";
    for line in found.lines() {
        let Some((name, value)) = line.split_once('=') else { continue };
        match name.trim() {
            "shell" => login = value.trim(),
            "bash" => bash = value.trim(),
            "zsh" => zsh = value.trim(),
            "bash_version" => bash_version = value.trim(),
            _ => {}
        }
    }
    let login_name = login.rsplit('/').next().unwrap_or("");
    let dir = dir.to_string_lossy();
    if login_name == "zsh" && !zsh.is_empty() {
        return ShellPlan {
            shell: "zsh".into(),
            command: format!("ZDOTDIR={} exec zsh -il", sh_quote(&format!("{dir}/zsh"))),
            markers: true,
            blocks: true,
        };
    }
    if !bash.is_empty() {
        return ShellPlan {
            shell: "bash".into(),
            command: format!("exec bash --init-file {} -i", sh_quote(&format!("{dir}/bash.sh"))),
            markers: true,
            blocks: version(bash_version) >= (4, 4),
        };
    }
    let name = if login_name.is_empty() { "sh" } else { login_name };
    ShellPlan { shell: name.into(), command: "exec \"${SHELL:-/bin/sh}\" -l".into(), markers: false, blocks: false }
}

fn version(text: &str) -> (u32, u32) {
    let (major, minor) = text.split_once('.').unwrap_or((text, ""));
    let minor = if minor.is_empty() { "0" } else { minor };
    match (major.parse(), minor.parse()) {
        (Ok(a), Ok(b)) => (a, b),
        _ => (0, 0),
    }
}

// --------------------------------------------------------------- markers

/// One marker from the shell.
///
/// P, before a prompt: code, cwd, home, branch, venv, PATH.
/// C, a command starts: its text, and how the command before it ended (a
/// line of several commands has a start marker for each and a prompt only
/// after the last).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Marker {
    pub kind: String,
    pub fields: Vec<String>,
}

impl Marker {
    pub fn field(&self, i: usize) -> &str {
        self.fields.get(i).map(String::as_str).unwrap_or("")
    }
}

/// What the stream brings, in order: bytes for the screen, and markers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    Out(Vec<u8>),
    Mark(Marker),
}

/// Takes our markers out of a terminal's byte stream, as it arrives.
///
/// `feed` returns what came, in order. A marker split between two reads is
/// held back until it is whole, and so is anything at the end that may be
/// the start of one, so the screen never gets half a marker.
pub struct MarkerParser {
    start: Vec<u8>,
    ours: Vec<u8>,
    held: Vec<u8>,
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > haystack.len() {
        return None;
    }
    if needle.len() == 1 {
        return haystack[from..].iter().position(|b| *b == needle[0]).map(|i| i + from);
    }
    haystack[from..].windows(needle.len()).position(|w| w == needle).map(|i| i + from)
}

impl MarkerParser {
    pub fn new(key: &str) -> Self {
        let mut start = b"\x1b]".to_vec();
        start.extend_from_slice(OSC);
        start.push(b';');
        let mut ours = start.clone();
        ours.extend_from_slice(key.as_bytes());
        ours.push(b';');
        MarkerParser { start, ours, held: Vec::new() }
    }

    pub fn feed(&mut self, data: &[u8]) -> Vec<Piece> {
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(data);
        let mut out: Vec<Piece> = Vec::new();
        let start = self.start.len();
        let mut pos = 0usize;
        loop {
            let Some(i) = find(&buf, &self.start, pos) else {
                let keep = partial_prefix(&buf, pos, &self.start);
                out.push(Piece::Out(buf[pos..keep].to_vec()));
                self.held = buf[keep..].to_vec();
                break;
            };
            if i > pos {
                out.push(Piece::Out(buf[pos..i].to_vec()));
            }
            let rest = &buf[i..(i + self.ours.len()).min(buf.len())];
            if rest.len() < self.ours.len() {
                if self.ours.starts_with(rest) {
                    // May be ours: wait for more.
                    self.held = buf[i..].to_vec();
                    break;
                }
                out.push(Piece::Out(buf[i..i + start].to_vec()));
                pos = i + start;
                continue;
            }
            if rest != self.ours.as_slice() {
                // An OSC 6973 without our key: not ours, the screen gets it.
                out.push(Piece::Out(buf[i..i + start].to_vec()));
                pos = i + start;
                continue;
            }
            let body_at = i + self.ours.len();
            let Some(end) = find(&buf, b"\x07", body_at) else {
                if buf.len() - body_at > MARKER_MAX {
                    out.push(Piece::Out(buf[i..i + start].to_vec()));
                    pos = i + start;
                    continue;
                }
                self.held = buf[i..].to_vec();
                break;
            };
            out.push(Piece::Mark(marker(&buf[body_at..end])));
            pos = end + 1;
        }
        out.retain(|p| !matches!(p, Piece::Out(b) if b.is_empty()));
        out
    }

    /// Whatever was held back, when the stream ends.
    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }
}

/// Where a possible beginning of `start` sits at the very end of buf.
fn partial_prefix(buf: &[u8], pos: usize, start: &[u8]) -> usize {
    let most = (start.len() - 1).min(buf.len() - pos);
    for n in (1..=most).rev() {
        if start.starts_with(&buf[buf.len() - n..]) {
            return buf.len() - n;
        }
    }
    buf.len()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// %XX back to the byte, as Python's `unquote_to_bytes`: a % without two
/// hex digits after it stays as it is.
pub fn unquote(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut parts = text.split(|b| *b == b'%');
    out.extend_from_slice(parts.next().unwrap_or(&[]));
    for item in parts {
        match (item.first().copied().and_then(hex), item.get(1).copied().and_then(hex)) {
            (Some(h), Some(l)) => {
                out.push(h << 4 | l);
                out.extend_from_slice(&item[2..]);
            }
            _ => {
                out.push(b'%');
                out.extend_from_slice(item);
            }
        }
    }
    out
}

fn marker(body: &[u8]) -> Marker {
    let mut parts = body.split(|b| *b == b';');
    let kind = parts.next().unwrap_or(&[]).iter().map(|&b| if b < 0x80 { b as char } else { '\u{fffd}' }).collect();
    let fields = parts.map(|p| String::from_utf8_lossy(&unquote(p)).into_owned()).collect();
    Marker { kind, fields }
}

// ------------------------------------------------------------ zsh's mark

fn spaces_at_end() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?-u)( *)\r( *)\r\z").expect("pattern"))
}

/// Takes zsh's partial-line mark off the end of a command's output.
///
/// zsh prints it before the prompt hook runs, so it lands at the end of
/// every block: the mark (an inverse %), spaces up to the edge, \r, as many
/// spaces as the mark is wide, \r. On a screen the prompt then draws over
/// it; in a block it would stay as a stray line.
pub fn strip_eol_mark(output: &[u8], cols: usize) -> Vec<u8> {
    let tail = &output[output.len().saturating_sub(cols + 512)..];
    let Some(m) = spaces_at_end().captures(tail) else { return output.to_vec() };
    let (before, after) = (m.get(1).map_or(0, |g| g.len()), m.get(2).map_or(0, |g| g.len()));
    if before + after != cols {
        return output.to_vec();
    }
    let whole = m.get(0).map_or(0, |g| g.len());
    let mut head = &output[..output.len() - whole];
    let width = after;
    if width > 0 {
        let sgr = r"(?:\x1b\[[0-9;]*m)*";
        let pattern = format!(r"(?-u){sgr}(?:[^\x1b\r\n]{sgr}){{{width}}}\z");
        if let Ok(re) = Regex::new(&pattern) {
            let look = &head[head.len().saturating_sub(512)..];
            if let Some(mark) = re.find(look) {
                head = &head[..head.len() - mark.len()];
            }
        }
    }
    head.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0123456789abcdef0123456789abcdef";

    fn mark(fields: &[&str]) -> Vec<u8> {
        let body: Vec<String> = fields.iter().map(|f| f.replace('%', "%25").replace(';', "%3B")).collect();
        format!("\x1b]6973;{KEY};{}\x07", body.join(";")).into_bytes()
    }

    #[test]
    fn markers_survive_any_split() {
        let mut stream = b"hi\x1b]0;title\x07".to_vec();
        stream.extend(mark(&["C", "echo a;b%c"]));
        stream.extend_from_slice(b"out\r\n");
        stream.extend_from_slice(b"\x1b]6973;not-our-key;P;0\x07");
        stream.extend_from_slice(b"\x1b]6973x");
        stream.extend(mark(&["P", "0", "/home/u", "/home/u", "main", ""]));
        stream.extend_from_slice(b"tail\x1b]69");
        let screen = b"hi\x1b]0;title\x07out\r\n\x1b]6973;not-our-key;P;0\x07\x1b]6973xtail\x1b]69".to_vec();
        // Seeded, as the core's check: the same splits every run.
        let mut seed: u64 = 7;
        let mut next = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        };
        for _ in 0..500 {
            let mut parser = MarkerParser::new(KEY);
            let (mut out, mut marks, mut i) = (Vec::new(), Vec::new(), 0);
            while i < stream.len() {
                let n = 1 + next() % 9;
                for piece in parser.feed(&stream[i..(i + n).min(stream.len())]) {
                    match piece {
                        Piece::Out(b) => out.extend(b),
                        Piece::Mark(m) => marks.push(m),
                    }
                }
                i += n;
            }
            out.extend(parser.flush());
            assert_eq!(out, screen, "{}", String::from_utf8_lossy(&out));
            assert_eq!(marks.iter().map(|m| m.kind.as_str()).collect::<Vec<_>>(), ["C", "P"]);
            assert_eq!(marks[0].field(0), "echo a;b%c");
            assert_eq!(marks[1].field(3), "main");
            assert_eq!(marks[1].field(9), "");
        }
    }

    #[test]
    fn a_marker_without_its_end_is_not_one() {
        let mut parser = MarkerParser::new(KEY);
        let mut data = format!("\x1b]6973;{KEY};C;").into_bytes();
        data.extend(std::iter::repeat_n(b'x', MARKER_MAX + 10));
        let pieces = parser.feed(&data);
        assert!(pieces.iter().all(|p| matches!(p, Piece::Out(_))));
        let all: Vec<u8> = pieces.into_iter().flat_map(|p| if let Piece::Out(b) = p { b } else { Vec::new() }).collect();
        assert!(all.starts_with(b"\x1b]6973;"), "handed to the screen");
    }

    #[test]
    fn fields_come_back_as_they_were() {
        assert_eq!(unquote(b"a%3Bb%25c%0A%1b%07%0d"), b"a;b%c\n\x1b\x07\r");
        assert_eq!(unquote(b"100%"), b"100%");
        assert_eq!(unquote(b"%zz%4"), b"%zz%4");
        let m = marker(b"P;0;/h/%D0%BF%D1%80;;;");
        assert_eq!(m.kind, "P");
        assert_eq!(m.field(1), "/h/пр");
        assert_eq!(m.fields.len(), 5);
        assert_eq!(marker(b"").kind, "");
        assert_eq!(marker(b"\xff;x").kind, "\u{fffd}");
    }

    #[test]
    fn zsh_mark_comes_off_the_end_of_output() {
        let mark = b"\x1b[1m\x1b[7m%\x1b[27m\x1b[1m\x1b[0m".to_vec();
        let mut out = b"hi\r\n".to_vec();
        out.extend(&mark);
        out.extend(std::iter::repeat_n(b' ', 79));
        out.extend_from_slice(b"\r \r");
        assert_eq!(strip_eol_mark(&out, 80), b"hi\r\n");
        let mut nonl = b"foo<no-nl>".to_vec();
        nonl.extend(std::iter::repeat_n(b' ', 73));
        nonl.push(b'\r');
        nonl.extend(std::iter::repeat_n(b' ', 7));
        nonl.push(b'\r');
        assert_eq!(strip_eol_mark(&nonl, 80), b"foo");
        assert_eq!(strip_eol_mark(b"plain\r\n", 80), b"plain\r\n");
        let mut short = b"x".to_vec();
        short.extend(std::iter::repeat_n(b' ', 10));
        short.extend_from_slice(b"\r \r");
        assert_eq!(strip_eol_mark(&short, 80), short, "only a mark as wide as the screen");
    }

    #[test]
    fn shell_follows_the_login_shell() {
        let dir = Path::new("/home/u/Library/Application Support/x/shell");
        assert_eq!(plan("shell=/bin/bash\nbash=/bin/bash\nzsh=\n", dir).shell, "bash");
        let zsh = plan("shell=/usr/bin/zsh\nbash=/bin/bash\nzsh=/usr/bin/zsh\n", dir);
        assert!(zsh.shell == "zsh" && zsh.markers && zsh.blocks);
        assert_eq!(zsh.command, "ZDOTDIR='/home/u/Library/Application Support/x/shell/zsh' exec zsh -il");
        let fish = plan("shell=/usr/bin/fish\nbash=/bin/bash\nzsh=\n", dir);
        assert_eq!(fish.shell, "bash", "neither bash nor zsh: bash, like the bot");
        assert_eq!(fish.command, "exec bash --init-file '/home/u/Library/Application Support/x/shell/bash.sh' -i");
        let bare = plan("shell=/bin/ash\nbash=\nzsh=\n", dir);
        assert!(bare.shell == "ash" && !bare.markers);
        assert!(!plan("", dir).markers, "nothing known: no key typed in");
        assert_eq!(plan("", dir).shell, "sh");
    }

    #[test]
    fn the_plan_says_who_marks_commands() {
        let dir = Path::new("/x");
        assert!(plan("shell=/bin/bash\nbash=/bin/bash\nbash_version=5.2\n", dir).blocks);
        assert!(!plan("shell=/bin/bash\nbash=/bin/bash\nbash_version=3.2\n", dir).blocks, "no PS0 before 4.4");
        assert!(plan("shell=/bin/bash\nbash=/bin/bash\nbash_version=4.4\n", dir).blocks);
        assert!(plan("shell=/usr/bin/zsh\nzsh=/usr/bin/zsh\n", dir).blocks);
        assert!(!plan("shell=/bin/ash\n", dir).blocks);
        assert!(!plan("shell=/bin/bash\nbash=/bin/bash\nbash_version=\n", dir).blocks);
    }

    #[test]
    fn keys_are_fresh_hex() {
        let (a, b) = (new_key(), new_key());
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(a, b);
    }

    #[test]
    fn deploy_puts_the_scripts_in_place() {
        let dir = std::env::temp_dir().join(format!("tterm-shell-{}", uuid::Uuid::new_v4())).join(FOLDER);
        deploy(&dir).unwrap();
        for (target, text) in FILES {
            let written = dir.join(target);
            assert_eq!(std::fs::read_to_string(&written).unwrap(), text, "{target}");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&written).unwrap().permissions().mode();
                assert_eq!(mode & 0o077, 0, "{target} is private");
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join("zsh")).unwrap().permissions().mode() & 0o077, 0);
        }
        deploy(&dir).unwrap();
        let mut names: Vec<String> = std::fs::read_dir(dir.join("zsh")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
        names.sort();
        assert_eq!(names, [".zlogin", ".zprofile", ".zshenv", ".zshrc"], "no leftovers");
        std::fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }
}
