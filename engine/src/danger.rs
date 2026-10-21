//! Commands worth asking about twice: a port of tterm-web's
//! `tterm/core/danger.py`, with its rules and its words.
//!
//! The same small set the Telegram bot holds back, for the same reasons. A
//! command typed into tTerm's own input line can come from history, from a
//! suggestion accepted with one key, or from "Run again" on an old block,
//! and the terminal it lands in is not always the one you think you are
//! looking at.
//!
//! The set is deliberately small: a terminal that asks about everything
//! trains people to confirm without reading, which is worse than not asking
//! at all. What qualifies: the damage is immediate, and nothing brings it
//! back.
//!
//! In the classic mode keys go straight to the shell and nothing is
//! checked; the page says so.
//!
//! A command is checked as it will be typed, after `clean_command` (the
//! socket does that): the control characters Python's `\s` counts as space
//! (\x1c to \x1f) are gone by then. Rust's `\w` and `\b` also count
//! combining marks and joiners as parts of a word, and Python's count other
//! numbers (², ½): the two differ only where a keyword touches such a
//! character, which no shell reads as a separator.

use regex::Regex;
use std::sync::OnceLock;

/// Why a command was held back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Danger {
    /// What it does, in plain words.
    pub what: &'static str,
    /// What does not come back.
    pub lost: &'static str,
}

pub const DELETE_TREE: Danger = Danger { what: "delete a directory and everything inside it", lost: "There is no undo and no bin to look in." };

/// Ordered by how bad it is, because the first match wins and the worst
/// description should be the one shown. The first rule, a recursive and
/// forced delete, is `recursive_delete`: the core's pattern for it looks
/// ahead, which this regex engine does not do.
const RULES: [(&str, Danger); 8] = [
    (r"(?i)\bmkfs(\.\w+)?\b|\bfdisk\b|\bparted\b|\bwipefs\b", Danger { what: "rewrite a disk's filesystem", lost: "Everything on that disk goes, not just files." }),
    (r"(?i)\bdd\b[^|;&]*\bof=\s*/dev/", Danger { what: "write directly onto a device", lost: "Whatever was on it is gone the moment this starts." }),
    (r"(?i)\b(DROP\s+(DATABASE|TABLE)|TRUNCATE\s+TABLE)\b", Danger { what: "drop a database or a table", lost: "Only a backup brings it back." }),
    (r"(?i)\b(shutdown|poweroff|halt)\b|\binit\s+0\b", Danger { what: "turn the machine off", lost: "Nothing here can turn it back on: that needs the provider's panel." }),
    (r"(?i)\breboot\b|\binit\s+6\b", Danger { what: "reboot the machine", lost: "The session drops, and whatever was running stops with it." }),
    (r"(?i)\bsystemctl\s+(stop|disable|mask)\s+(ssh|sshd)\b", Danger { what: "stop the SSH service", lost: "That is the way in. Stopping it locks the door from the inside." }),
    (r"(?i)\bufw\s+(deny|reject)\b|\biptables\b[^|;&]*\bDROP\b", Danger { what: "change the firewall", lost: "A wrong rule can cut the machine off with no way back in." }),
    (r"(?i)\buserdel\b|\bdeluser\b", Danger { what: "delete a user account", lost: "Their files and access go with them." }),
];

/// A recursive delete aimed here is not a slip worth one question but one
/// to be called out: nothing on the machine survives it.
const ROOT_TARGETS: &str = r"\brm\b[^|;&]*\s(?:/|/\*|~|~/|~/\*|/\w+/\.\.|\$HOME|\$\{HOME\})\s*(?:$|[|;&])";

struct Compiled {
    rm: Regex,
    recursive: Regex,
    force: Regex,
    rules: Vec<(Regex, Danger)>,
    root: Regex,
}

fn compiled() -> &'static Compiled {
    static C: OnceLock<Compiled> = OnceLock::new();
    C.get_or_init(|| Compiled {
        rm: Regex::new(r"(?i)\brm\b").expect("pattern"),
        recursive: Regex::new(r"(?i)\s(?:-\w*[rR]\w*|--recursive)\b").expect("pattern"),
        force: Regex::new(r"(?i)\s(?:-\w*[fF]\w*|--force)\b").expect("pattern"),
        rules: RULES.iter().map(|(p, d)| (Regex::new(p).expect("pattern"), *d)).collect(),
        root: Regex::new(ROOT_TARGETS).expect("pattern"),
    })
}

/// The core's first rule, `\brm\b(?=[^|;&]*\s(?:-\w*[rR]\w*|--recursive)\b)
/// (?=[^|;&]*\s(?:-\w*[fF]\w*|--force)\b)` with re.I: an `rm`, then in the
/// same command (up to | ; &) a flag with r in it and one with f in it.
fn recursive_delete(line: &str) -> bool {
    let c = compiled();
    c.rm.find_iter(line).any(|m| {
        let rest = &line[m.end()..];
        let command = &rest[..rest.find(['|', ';', '&']).unwrap_or(rest.len())];
        c.recursive.is_match(command) && c.force.is_match(command)
    })
}

/// The lines of a text as Python's `str.splitlines` cuts them.
fn lines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if matches!(c, '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}') {
            out.push(&text[start..i]);
            let mut next = i + c.len_utf8();
            if c == '\r' {
                if let Some(&(j, '\n')) = chars.peek() {
                    chars.next();
                    next = j + 1;
                }
            }
            start = next;
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// The rule this command trips, or None. A command of several lines is
/// looked at line by line, so that `rm` on one line and `-rf` on another do
/// not add up to a delete.
pub fn looks_destructive(command: &str) -> Option<Danger> {
    let lines: Vec<&str> = lines(command).into_iter().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.iter().any(|l| recursive_delete(l)) {
        return Some(DELETE_TREE);
    }
    compiled().rules.iter().find(|(re, _)| lines.iter().any(|l| re.is_match(l))).map(|(_, d)| *d)
}

/// Whether a recursive delete points at the root or a home directory.
pub fn hits_everything(command: &str) -> bool {
    lines(command).iter().any(|l| compiled().root.is_match(l.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminals::clean_command;

    #[test]
    fn dangerous_commands_are_held_back() {
        for cmd in [
            "rm -rf /var/log/old",
            "rm -fr build",
            "sudo rm -rf node_modules",
            "mkfs.ext4 /dev/sdb1",
            "dd if=/dev/zero of=/dev/sda bs=1M",
            "psql -c 'DROP DATABASE prod'",
            "shutdown -h now",
            "reboot",
            "systemctl stop sshd",
            "userdel deploy",
            "ufw deny 22",
            "sudo deluser --remove-home tt-check",
            "cd /tmp\nrm -rf build",
            "RM -RF build",
            "rm -r -f build",
            "rm -rf build|cat",
        ] {
            assert!(looks_destructive(cmd).is_some(), "{cmd}");
        }
        for cmd in [
            "rm file.txt",
            "ls -la",
            "git reset --hard",
            "cd /tmp && ls",
            "docker ps",
            "grep -r pattern .",
            "systemctl restart tterm",
            "cat /etc/passwd",
            "rmdir empty",
            "df -h",
            "rm -i old.log",
            "rm old.log\nls -rf",
            "rm -r build; ls -f",
            "rm build -x-rf",
            "farm -rf x",
        ] {
            assert!(looks_destructive(cmd).is_none(), "{cmd}");
        }
        assert!(hits_everything("rm -rf /") && hits_everything("rm -rf ~"));
        assert!(hits_everything("rm -rf $HOME"));
        assert!(hits_everything("rm -rf ${HOME}"));
        assert!(hits_everything("rm -rf ~/"));
        assert!(hits_everything("ls\nrm -rf /*"));
        assert!(!hits_everything("rm -rf /var/log/old"));
        assert!(looks_destructive("rm --recursive --force build").is_some());
        assert_eq!(looks_destructive("rm -rf x").unwrap(), DELETE_TREE);
        assert_eq!(looks_destructive("reboot; rm -rf x").unwrap().what, "delete a directory and everything inside it", "the worst one shows");
        for (_, rule) in RULES.iter() {
            assert!(!(rule.what.to_string() + rule.lost).contains('—'), "no long dashes");
        }
        // Checked as typed: a control character hidden in a word goes
        // before the check, not after it.
        for sneaky in ["r\x01m -rf /tmp/x", "re\x00boot", "rm -rf\r/tmp/x"] {
            assert!(looks_destructive(&clean_command(sneaky)).is_some(), "{sneaky:?}");
        }
        assert_eq!(clean_command("a\r\nb\rc\x1b[201~"), "a\nb\nc[201~");
    }

    #[test]
    fn lines_as_python_cuts_them() {
        assert_eq!(lines("a\nb\r\nc\rd\u{2028}e"), ["a", "b", "c", "d", "e"]);
        assert_eq!(lines("a\n"), ["a"]);
        assert_eq!(lines("\n\nx"), ["", "", "x"]);
        assert!(lines("").is_empty());
    }
}
