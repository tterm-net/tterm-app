//! The screen modes a byte stream sets, followed without drawing it.
//!
//! The same as `Modes` in tterm-web's `tterm/core/shell.py`: when the start
//! of a terminal's stream is no longer kept, these modes are set again
//! before a replay, so that the screen behaves as it did (the second screen
//! of vim and htop, the cursor keys, the mouse, bracketed paste).

use regex::bytes::Regex;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// DEC private modes that change how the screen behaves or what the keys
/// send, by their number.
fn tracked(mode: u32) -> Option<&'static str> {
    Some(match mode {
        1 => "app_cursor",
        6 => "origin",
        7 => "wrap",
        25 => "cursor",
        47 | 1047 | 1049 => "alt",
        1000 => "mouse_x11",
        1002 => "mouse_button",
        1003 => "mouse_any",
        1004 => "focus",
        1005 => "mouse_utf8",
        1006 => "mouse_sgr",
        1015 => "mouse_urxvt",
        2004 => "paste",
        _ => return None,
    })
}

/// What a fresh screen has: wrapping and a visible cursor are on.
fn default_of(mode: u32) -> bool {
    matches!(tracked(mode), Some("wrap") | Some("cursor"))
}

fn pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?-u)\x1b\[\?([0-9;]+)([hl])|\x1b([=>c])").expect("pattern")
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Modes {
    pub state: BTreeMap<u32, bool>,
    pub keypad: bool,
    tail: Vec<u8>,
}

impl Modes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, data: &[u8]) {
        let mut buf = std::mem::take(&mut self.tail);
        buf.extend_from_slice(data);
        for caps in pattern().captures_iter(&buf) {
            if let Some(c) = caps.get(3) {
                match c.as_bytes()[0] {
                    b'=' => self.keypad = true,
                    b'>' => self.keypad = false,
                    _ => {
                        // ESC c: a full reset.
                        self.state.clear();
                        self.keypad = false;
                    }
                }
                continue;
            }
            let on = &caps[2] == b"h";
            for p in caps[1].split(|b| *b == b';') {
                if p.is_empty() || !p.iter().all(u8::is_ascii_digit) || p.len() > 9 {
                    continue;
                }
                let n: u32 = std::str::from_utf8(p).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
                if tracked(n).is_some() {
                    self.state.insert(n, on);
                }
            }
        }
        // A sequence cut at the end of this read is finished by the next.
        if let Some(cut) = buf.iter().rposition(|b| *b == 0x1b) {
            if buf.len() - cut < 32 {
                self.tail = buf[cut..].to_vec();
            }
        }
    }

    pub fn alt_screen(&self) -> bool {
        [47u32, 1047, 1049].iter().any(|m| self.state.get(m).copied().unwrap_or(false))
    }

    /// Whether the shell's line editor takes pastes in brackets now.
    pub fn bracketed_paste(&self) -> bool {
        self.state.get(&2004).copied().unwrap_or(false)
    }

    /// The sequences that bring a fresh screen to these modes.
    pub fn restore(&self) -> Vec<u8> {
        let mut seq = Vec::new();
        for (&mode, &on) in &self.state {
            if on != default_of(mode) {
                seq.extend_from_slice(format!("\x1b[?{}{}", mode, if on { 'h' } else { 'l' }).as_bytes());
            }
        }
        if self.keypad {
            seq.extend_from_slice(b"\x1b=");
        }
        seq
    }

    /// The sequences that take a screen in these modes to `other`'s: where
    /// the middle of a stream is left out, what follows it is drawn on the
    /// screen it was meant for.
    pub fn switch_to(&self, other: &Modes) -> Vec<u8> {
        let mut seq = Vec::new();
        let mut all: Vec<u32> = self.state.keys().chain(other.state.keys()).copied().collect();
        all.sort_unstable();
        all.dedup();
        for mode in all {
            let default = default_of(mode);
            let now = other.state.get(&mode).copied().unwrap_or(default);
            if self.state.get(&mode).copied().unwrap_or(default) != now {
                seq.extend_from_slice(format!("\x1b[?{}{}", mode, if now { 'h' } else { 'l' }).as_bytes());
            }
        }
        if self.keypad != other.keypad {
            seq.extend_from_slice(if other.keypad { b"\x1b=" } else { b"\x1b>" });
        }
        seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_the_second_screen() {
        let mut m = Modes::new();
        m.feed(b"hello\x1b[?1049h\x1b[?25l");
        assert!(m.alt_screen());
        assert_eq!(m.restore(), b"\x1b[?25l\x1b[?1049h".to_vec());
        m.feed(b"\x1b[?1049l\x1b[?25h");
        assert!(!m.alt_screen());
        assert!(m.restore().is_empty());
    }

    #[test]
    fn a_sequence_cut_between_reads() {
        let mut m = Modes::new();
        m.feed(b"abc\x1b[?10");
        m.feed(b"49h");
        assert!(m.alt_screen());
    }

    #[test]
    fn reset_and_keypad() {
        let mut m = Modes::new();
        m.feed(b"\x1b=\x1b[?1h");
        assert!(m.keypad);
        assert_eq!(m.restore(), b"\x1b[?1h\x1b=".to_vec());
        m.feed(b"\x1bc");
        assert!(!m.keypad);
        assert!(m.state.is_empty());
    }

    #[test]
    fn switch_between() {
        let mut a = Modes::new();
        a.feed(b"\x1b[?1049h");
        let b = Modes::new();
        assert_eq!(a.switch_to(&b), b"\x1b[?1049l".to_vec());
        assert_eq!(b.switch_to(&a), b"\x1b[?1049h".to_vec());
    }

    #[test]
    fn untracked_and_odd_numbers() {
        let mut m = Modes::new();
        m.feed(b"\x1b[?9999999999999h\x1b[?12h\x1b[?2004;1h");
        assert!(m.bracketed_paste());
        assert_eq!(m.state.len(), 2);
    }
}
