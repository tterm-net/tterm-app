//! Tab in tTerm's own input line, and the lists behind its directory and
//! branch buttons: a port of tterm-web's `tterm/core/complete.py`.
//!
//! The input line is the page's, not the shell's, so the shell's own
//! completion never sees it. What a word can become is asked of this
//! computer with a small sh script, outside the terminal: it lists a
//! directory, the commands on the PATH or the git branches, and never
//! touches the terminal, its screen or its history.
//!
//! The line is read the way the shell would read it, closely enough to know
//! which word the cursor is in, what its value is with quotes and
//! backslashes taken off, and what kind of word it is. The word is then
//! written back with the same kind of quoting. Positions in the line count
//! characters, as the core's (Python) strings do.

use serde_json::{json, Value};

/// Printed by the side scripts before their list: whatever a chatty startup
/// file prints first is cut off at it.
pub const LIST_MARK: &str = "__tterm_list__";
/// A list never gets longer than this.
pub const MAX_LIST: usize = 4000;
/// What the page gets for one Tab, at most.
pub const MAX_ITEMS: usize = 500;

/// Words that run the next word as a command.
const PREFIXES: [&str; 14] = ["sudo", "doas", "time", "nohup", "nice", "env", "exec", "command", "builtin", "watch", "xargs", "stdbuf", "timeout", "strace"];

/// Builtins and keywords: commands with no file on the PATH. Sorted.
const BUILTINS: [&str; 62] = [
    "alias", "bg", "bind", "break", "builtin", "case", "cd", "command", "compgen", "complete", "continue", "declare", "dirs", "disown", "echo", "enable", "eval", "exec", "exit", "export", "false", "fc", "fg", "for", "function", "getopts", "hash", "help", "history", "if", "jobs", "kill", "let", "local", "logout", "popd", "printf", "pushd", "pwd", "read", "readonly", "return", "select", "set", "shift", "shopt", "source", "suspend", "test", "time", "times", "trap", "true", "type", "typeset", "ulimit", "umask", "unalias", "unset", "until", "wait", "while",
];

/// Sorted.
const GIT_COMMANDS: [&str; 33] = [
    "add", "bisect", "blame", "branch", "checkout", "cherry-pick", "clean", "clone", "commit", "config", "diff", "fetch", "grep", "init", "log", "merge", "mv", "pull", "push", "rebase", "reflog", "remote", "reset", "restore", "revert", "rm", "show", "stash", "status", "submodule", "switch", "tag", "worktree",
];
/// git subcommands whose argument is a branch, and those where it may also
/// be a file.
const GIT_BRANCH: [&str; 5] = ["switch", "merge", "rebase", "branch", "cherry-pick"];
const GIT_BRANCH_OR_FILE: [&str; 6] = ["checkout", "diff", "log", "reset", "show", "restore"];

fn separator(c: char) -> bool {
    "|&;()\n`{}".contains(c)
}

fn special(c: char) -> bool {
    " \t\n'\"\\$`!*?;&|<>()[]{}#".contains(c)
}

/// The word under the cursor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Word {
    /// Where it starts in the line, in characters.
    pub start: usize,
    /// As the shell would read it.
    pub value: String,
    /// ' or " when it opened a quote not yet closed.
    pub quote: String,
    /// It follows < or >.
    pub redirect: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    /// command, file, dir, branch, branch+file, git, none.
    pub kind: &'static str,
    pub word: Word,
    /// The command the word belongs to.
    pub command: String,
    /// git switch: remote branches by their short name.
    pub switch: bool,
    pub words: Vec<String>,
}

impl Context {
    fn new(kind: &'static str, word: Word) -> Self {
        Context { kind, word, command: String::new(), switch: false, words: Vec::new() }
    }

    fn of(kind: &'static str, word: Word, command: &str) -> Self {
        Context { kind, word, command: command.to_string(), switch: false, words: Vec::new() }
    }
}

/// The finished words of the command the end of `text` is in, and the word
/// being typed at the end (empty if the text ends in a space).
pub fn split(text: &str) -> (Vec<String>, Word) {
    let text: Vec<char> = text.chars().collect();
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut start: Option<usize> = None;
    let mut quote: Option<char> = None;
    let mut redirect = false;
    let mut word_redirect = false;
    let mut i = 0usize;

    macro_rules! finish {
        () => {
            if start.is_some() {
                if !word_redirect {
                    words.push(std::mem::take(&mut cur));
                }
                start = None;
                cur.clear();
            }
        };
    }
    macro_rules! begin {
        () => {
            if start.is_none() {
                start = Some(i);
                word_redirect = redirect;
                redirect = false;
            }
        };
    }

    while i < text.len() {
        let c = text[i];
        if quote == Some('\'') {
            if c == '\'' {
                quote = None;
            } else {
                cur.push(c);
            }
            i += 1;
            continue;
        }
        if quote == Some('"') {
            if c == '"' {
                quote = None;
            } else if c == '\\' && i + 1 < text.len() && "\"\\$`".contains(text[i + 1]) {
                cur.push(text[i + 1]);
                i += 1;
            } else {
                cur.push(c);
            }
            i += 1;
            continue;
        }
        if c == '\\' {
            begin!();
            if i + 1 < text.len() {
                if text[i + 1] != '\n' {
                    cur.push(text[i + 1]);
                }
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if c == '\'' || c == '"' {
            begin!();
            quote = Some(c);
            i += 1;
            continue;
        }
        if c == ' ' || c == '\t' {
            finish!();
            i += 1;
            continue;
        }
        if c == '$' && text.get(i + 1) == Some(&'(') {
            finish!();
            words.clear();
            i += 2;
            continue;
        }
        if separator(c) {
            finish!();
            words.clear();
            redirect = false;
            i += 1;
            continue;
        }
        if c == '<' || c == '>' {
            finish!();
            redirect = true;
            i += 1;
            while i < text.len() && "<>&|".contains(text[i]) {
                i += 1;
            }
            continue;
        }
        begin!();
        cur.push(c);
        i += 1;
    }
    match start {
        None => (words, Word { start: text.len(), redirect, ..Default::default() }),
        Some(s) => (words, Word { start: s, value: cur, quote: quote.map(String::from).unwrap_or_default(), redirect: word_redirect }),
    }
}

/// What kind of word is being typed.
pub fn context(words: &[String], word: Word) -> Context {
    if word.value.starts_with('$') {
        return Context::new("none", word);
    }
    if word.redirect {
        return Context::new("file", word);
    }
    let mut rest: Vec<String> = words.to_vec();
    // FOO=bar cmd
    while rest.first().is_some_and(|w| w.contains('=') && !w.starts_with('=')) {
        rest.remove(0);
    }
    // sudo, time, env...
    while rest.first().is_some_and(|w| PREFIXES.contains(&w.as_str())) {
        rest.remove(0);
        while rest.first().is_some_and(|w| w.starts_with('-')) {
            rest.remove(0);
        }
    }
    if rest.is_empty() {
        if word.value.contains('/') || word.value.starts_with('~') || word.value.starts_with('.') {
            return Context::new("file", word);
        }
        return Context::new("command", word);
    }
    let command = rest[0].rsplit('/').next().unwrap_or("").to_string();
    if word.value.starts_with('-') {
        return Context::of("none", word, &command);
    }
    if ["cd", "pushd", "rmdir"].contains(&command.as_str()) {
        return Context::of("dir", word, &command);
    }
    if command == "git" {
        let args: Vec<&String> = rest[1..].iter().filter(|w| !w.starts_with('-')).collect();
        let Some(sub) = args.first() else { return Context::of("git", word, &command) };
        if GIT_BRANCH.contains(&sub.as_str()) {
            let switch = sub.as_str() == "switch";
            return Context { switch, ..Context::of("branch", word, &command) };
        }
        if GIT_BRANCH_OR_FILE.contains(&sub.as_str()) {
            return Context::of("branch+file", word, &command);
        }
    }
    Context { words: rest, ..Context::of("file", word, &command) }
}

// ------------------------------------------------------------- quoting

/// A value written back as the shell reads it, in the word's quoting.
pub fn escape(value: &str, quote: &str) -> String {
    if quote == "'" {
        return value.replace('\'', "'\\''");
    }
    if quote == "\"" {
        let mut out = String::with_capacity(value.len());
        for c in value.chars() {
            if "\"\\$`".contains(c) {
                out.push('\\');
            }
            out.push(c);
        }
        return out;
    }
    let mut out = String::with_capacity(value.len());
    for (i, c) in value.chars().enumerate() {
        if special(c) || (c == '~' && i > 0) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A whole word: the opening quote, if the word had one, then the value.
pub fn word_text(value: &str, quote: &str) -> String {
    format!("{quote}{}", escape(value, quote))
}

/// For the side scripts: one argument, safe in any POSIX sh.
pub fn sh_quote(value: &str) -> String {
    crate::shell::sh_quote(value)
}

// ----------------------------------------------------------- the scripts

/// Lists a directory, relative to the terminal's: one name a line,
/// directories with a / after them (symlinks to one too). A relative path
/// from a directory that cannot be entered lists nothing, rather than the
/// wrong place.
pub fn list_script(cwd: &str, path: &str) -> String {
    format!(
        "set -- {} {}\n\
         if ! cd -- \"$1\" 2>/dev/null; then\n  case $2 in /*) ;; *) exit 0 ;; esac\nfi\n\
         printf '%s\\n' {LIST_MARK}\n\
         ls -1ApL -- \"${{2:-.}}\" 2>/dev/null | head -n {MAX_LIST}\n",
        sh_quote(cwd),
        sh_quote(path)
    )
}

/// The commands on the PATH that start with `prefix`: files one may run.
/// The PATH is the one the terminal's shell has, from its last prompt.
pub fn commands_script(path: &str, prefix: &str) -> String {
    format!(
        "set -- {} {}\n\
         [ -n \"$1\" ] || set -- \"$PATH\" \"$2\"\n\
         printf '%s\\n' {LIST_MARK}\n\
         printf '%s\\n' \"$1\" | tr ':' '\\n' | while IFS= read -r d; do\n  \
         [ -n \"$d\" ] && [ -d \"$d\" ] || continue\n  \
         for f in \"$d\"/\"$2\"*; do\n    \
         [ -f \"$f\" ] && [ -x \"$f\" ] && printf '%s\\n' \"${{f##*/}}\"\n  \
         done\n\
         done | head -n {MAX_LIST}\n",
        sh_quote(path),
        sh_quote(prefix)
    )
}

/// The branches of the repository the terminal is in, local and remote.
pub fn branches_script(cwd: &str) -> String {
    format!(
        "set -- {}\n\
         cd -- \"$1\" 2>/dev/null || exit 0\n\
         printf '%s\\n' {LIST_MARK}\n\
         git for-each-ref --format='%(refname)' refs/heads refs/remotes 2>/dev/null | head -n {MAX_LIST}\n",
        sh_quote(cwd)
    )
}

/// The lines a side script printed after its mark, without names that
/// carry control characters: a \r would turn into a second line, and so
/// into a second command.
pub fn listed(output: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(output);
    let mark = format!("{LIST_MARK}\n");
    let Some(at) = text.find(&mark) else { return Vec::new() };
    text[at + mark.len()..]
        .split('\n')
        .filter(|line| !line.is_empty() && !line.chars().any(|c| (c as u32) < 0x20 || c == '\x7f'))
        .map(str::to_string)
        .collect()
}

// ------------------------------------------------------------- the items

/// Splits a path word: the directory to list (as the side script gets it),
/// the part of the value kept as typed, and the name being typed.
pub fn dir_part(value: &str, home: &str) -> (String, String, String) {
    let Some((head, name)) = value.rsplit_once('/') else {
        if value == "~" {
            let home = if home.is_empty() { "~" } else { home };
            return (home.to_string(), "~/".into(), String::new());
        }
        return (".".into(), String::new(), value.to_string());
    };
    let kept = format!("{head}/");
    let mut place = kept.clone();
    if kept == "~/" || kept.starts_with("~/") {
        let home = if home.is_empty() { "~" } else { home };
        place = format!("{home}{}", &kept[1..]);
    }
    if place.is_empty() {
        place = "/".into();
    }
    (place, kept, name.to_string())
}

fn item(text: String, label: String, kind: &str) -> Value {
    json!({"text": text, "label": label, "kind": kind})
}

pub fn file_items(word: &Word, entries: &[String], home: &str, dirs_only: bool) -> Vec<Value> {
    let (_, kept, name) = dir_part(&word.value, home);
    let hidden = name.starts_with('.');
    let mut items: Vec<(bool, String, Value)> = Vec::new();
    for entry in entries {
        let is_dir = entry.ends_with('/');
        let base = if is_dir { &entry[..entry.len() - 1] } else { entry.as_str() };
        if base.is_empty() || base == "." || base == ".." {
            continue;
        }
        if !base.starts_with(name.as_str()) {
            continue;
        }
        if base.starts_with('.') && !hidden {
            continue;
        }
        if dirs_only && !is_dir {
            continue;
        }
        let slash = if is_dir { "/" } else { "" };
        let value = format!("{kept}{base}{slash}");
        let label = format!("{base}{slash}");
        items.push((!is_dir, label.to_lowercase(), item(word_text(&value, &word.quote), label, if is_dir { "dir" } else { "file" })));
    }
    items.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    items.into_iter().map(|(_, _, v)| v).collect()
}

pub fn command_items(word: &Word, names: &[String]) -> Vec<Value> {
    let mut all: Vec<&str> = names.iter().map(String::as_str).chain(BUILTINS).collect();
    all.sort_unstable();
    all.dedup();
    all.into_iter()
        .filter(|n| n.starts_with(word.value.as_str()))
        .map(|n| item(word_text(n, &word.quote), n.to_string(), "command"))
        .collect()
}

pub fn branch_items(word: &Word, refs: &[String], switch: bool) -> Vec<Value> {
    let mut local: Vec<&str> = Vec::new();
    let mut remote: Vec<&str> = Vec::new();
    for r in refs {
        if let Some(name) = r.strip_prefix("refs/heads/") {
            local.push(name);
        } else if let Some(name) = r.strip_prefix("refs/remotes/") {
            if name.ends_with("/HEAD") {
                continue;
            }
            remote.push(name);
        }
    }
    let mut names: Vec<&str> = local;
    if switch {
        // `git switch feature` makes a local branch from origin/feature.
        names.extend(remote.iter().filter_map(|r| r.split_once('/').map(|(_, short)| short)));
    } else {
        names.extend(remote);
    }
    let mut seen: Vec<&str> = Vec::new();
    let mut items = Vec::new();
    for name in names {
        if seen.contains(&name) || !name.starts_with(word.value.as_str()) {
            continue;
        }
        seen.push(name);
        items.push(item(word_text(name, &word.quote), name.to_string(), "branch"));
    }
    items
}

pub fn git_items(word: &Word) -> Vec<Value> {
    GIT_COMMANDS.iter().filter(|c| c.starts_with(word.value.as_str())).map(|c| item(word_text(c, &word.quote), c.to_string(), "command")).collect()
}

/// The directories in a listing, hidden ones last.
pub fn dirs_of(entries: &[String]) -> Vec<String> {
    let mut names: Vec<String> = entries.iter().filter(|e| e.ends_with('/') && e.as_str() != "./" && e.as_str() != "../").map(|e| e[..e.len() - 1].to_string()).collect();
    names.sort_by_cached_key(|n| (n.starts_with('.'), n.to_lowercase()));
    names
}

/// The local and remote branches of a listing of refs, each sorted.
pub fn branches_of(refs: &[String]) -> (Vec<String>, Vec<String>) {
    let mut local: Vec<String> = refs.iter().filter_map(|r| r.strip_prefix("refs/heads/")).map(str::to_string).collect();
    let mut remote: Vec<String> = refs.iter().filter_map(|r| r.strip_prefix("refs/remotes/")).filter(|r| !r.ends_with("/HEAD")).map(str::to_string).collect();
    local.sort_by_cached_key(|n| n.to_lowercase());
    remote.sort_by_cached_key(|n| n.to_lowercase());
    (local, remote)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(line: &str) -> Context {
        let (words, word) = split(line);
        context(&words, word)
    }

    fn w(start: usize, value: &str) -> Word {
        Word { start, value: value.into(), ..Default::default() }
    }

    fn labels(items: &[Value]) -> Vec<String> {
        items.iter().map(|i| i["label"].as_str().unwrap().to_string()).collect()
    }

    fn texts(items: &[Value]) -> Vec<String> {
        items.iter().map(|i| i["text"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn the_lists_are_the_cores() {
        assert!(BUILTINS.windows(2).all(|p| p[0] < p[1]));
        assert!(GIT_COMMANDS.windows(2).all(|p| p[0] < p[1]));
    }

    #[test]
    fn the_line_is_read_like_the_shell_reads_it() {
        let (words, word) = split("git commit -m \"two words\" && cd My\\ Do");
        assert_eq!(words, ["cd"]);
        assert_eq!(word.value, "My Do");
        assert_eq!(word.start, 32);
        let (_, word) = split("ls 'a b");
        assert_eq!((word.value.as_str(), word.quote.as_str()), ("a b", "'"));
        let (_, word) = split("echo \"x\\\"y");
        assert_eq!((word.value.as_str(), word.quote.as_str()), ("x\"y", "\""));
        let (_, word) = split("cat < fi");
        assert!(word.redirect && word.value == "fi");
        let (words, word) = split("ls ");
        assert_eq!(words, ["ls"]);
        assert_eq!((word.value.as_str(), word.start), ("", 3));
        let (words, word) = split("echo $(whi");
        assert!(words.is_empty());
        assert_eq!(word.value, "whi");
        // Characters, not bytes.
        let (_, word) = split("cd Мои\\ до");
        assert_eq!((word.start, word.value.as_str()), (3, "Мои до"));
    }

    #[test]
    fn tab_knows_what_kind_of_word_it_is() {
        assert_eq!(ctx("gi").kind, "command");
        assert_eq!(ctx("sudo -E sys").kind, "command");
        assert_eq!(ctx("FOO=1 py").kind, "command");
        assert_eq!(ctx("./scr").kind, "file");
        assert_eq!(ctx("ls -la sr").kind, "file");
        assert_eq!(ctx("ls -").kind, "none");
        assert_eq!(ctx("echo $HO").kind, "none");
        assert_eq!(ctx("cd sr").kind, "dir");
        assert_eq!(ctx("git sw").kind, "git");
        assert_eq!(ctx("git switch fe").kind, "branch");
        assert!(ctx("git switch fe").switch);
        assert_eq!(ctx("git checkout ma").kind, "branch+file");
        assert_eq!(ctx("ls | gr").kind, "command");
        assert_eq!(ctx("echo hi > ou").kind, "file");
    }

    #[test]
    fn words_go_back_quoted_as_they_came() {
        assert_eq!(escape("My Docs/a&b", ""), "My\\ Docs/a\\&b");
        assert_eq!(escape("~/x y", ""), "~/x\\ y", "a leading ~ is home");
        assert_eq!(escape("a~b", ""), "a\\~b");
        assert_eq!(word_text("it's", "'"), "'it'\\''s");
        assert_eq!(word_text("a\"b$c", "\""), "\"a\\\"b\\$c");
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn items_for_files_commands_and_branches() {
        let entries = |e: &[&str]| e.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let items = file_items(&w(3, "sr"), &entries(&["src/", "srv.txt", ".srx", "lib/"]), "/home/u", false);
        assert_eq!(texts(&items), ["src/", "srv.txt"]);
        assert_eq!(items[0]["kind"], "dir");
        let hidden = file_items(&w(3, "."), &entries(&[".git/", "a"]), "/h", false);
        assert_eq!(labels(&hidden), [".git/"]);
        let tilde = file_items(&w(3, "~/Do"), &entries(&["Docs/", "x"]), "/home/u", false);
        assert_eq!(texts(&tilde), ["~/Docs/"]);
        assert_eq!(dir_part("~/Do", "/home/u"), ("/home/u/".into(), "~/".into(), "Do".into()));
        assert_eq!(dir_part("/etc/pa", "/h"), ("/etc/".into(), "/etc/".into(), "pa".into()));
        assert_eq!(dir_part("pa", "/h"), (".".into(), "".into(), "pa".into()));
        assert_eq!(dir_part("~", "/h"), ("/h".into(), "~/".into(), "".into()));
        assert_eq!(dir_part("/x", "/h"), ("/".into(), "/".into(), "x".into()));
        let spaced = file_items(&w(3, "My"), &entries(&["My Docs/"]), "/h", false);
        assert_eq!(spaced[0]["text"], "My\\ Docs/");
        let dirs = file_items(&w(3, ""), &entries(&["b.txt", "a/", "B/", "c/"]), "/h", true);
        assert_eq!(labels(&dirs), ["a/", "B/", "c/"]);
        let mixed = file_items(&w(3, ""), &entries(&["b.txt", "a/", "A.txt"]), "/h", false);
        assert_eq!(labels(&mixed), ["a/", "A.txt", "b.txt"], "directories first");
        let cmds = command_items(&w(0, "ech"), &entries(&["echo", "ecl"]));
        assert_eq!(labels(&cmds), ["echo"], "listed and builtin, once");
        let refs = entries(&["refs/heads/main", "refs/heads/feature/x", "refs/remotes/origin/HEAD", "refs/remotes/origin/main", "refs/remotes/origin/fix"]);
        assert_eq!(labels(&branch_items(&w(11, ""), &refs, true)), ["main", "feature/x", "fix"]);
        assert_eq!(labels(&branch_items(&w(10, "ori"), &refs, false)), ["origin/main", "origin/fix"]);
        let (local, remote) = branches_of(&refs);
        assert_eq!(local, ["feature/x", "main"]);
        assert_eq!(remote, ["origin/fix", "origin/main"]);
        assert_eq!(dirs_of(&entries(&["b/", ".a/", "f", "A/", "./", "../"])), ["A", "b", ".a"]);
        assert_eq!(labels(&git_items(&w(4, "st"))), ["stash", "status"]);
    }

    #[test]
    fn names_with_control_characters_stay_out() {
        let out = format!("chatty\n{LIST_MARK}\nREADME\nREADME\rmake\ntab\tname\nok/\n");
        assert_eq!(listed(out.as_bytes()), ["README", "ok/"]);
        assert!(listed(b"no mark here\n").is_empty());
    }

    fn sh(script: &str, cwd: &std::path::Path) -> Vec<String> {
        use std::io::Write;
        let mut child = std::process::Command::new("sh").arg("-s").current_dir(cwd).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap().stdout;
        let mut all = b"some chatty startup file\n".to_vec();
        all.extend(out);
        listed(&all)
    }

    #[test]
    fn the_side_scripts_on_a_real_sh() {
        let tmp = std::env::temp_dir().join(format!("ttside-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(tmp.join("My Docs")).unwrap();
        std::fs::create_dir_all(tmp.join("src")).unwrap();
        std::fs::write(tmp.join("it's.txt"), "x").unwrap();
        std::os::unix::fs::symlink(tmp.join("src"), tmp.join("link")).unwrap();
        let root = std::path::Path::new("/");
        let listing = sh(&list_script(tmp.to_str().unwrap(), "."), root);
        for name in ["My Docs/", "src/", "it's.txt", "link/"] {
            assert!(listing.contains(&name.to_string()), "{listing:?}");
        }
        let gone = tmp.join("no-such-dir");
        assert!(sh(&list_script(gone.to_str().unwrap(), "."), &tmp).is_empty(), "a directory that cannot be entered lists nothing, not home");
        assert!(sh(&list_script(gone.to_str().unwrap(), tmp.to_str().unwrap()), root).contains(&"src/".to_string()), "an absolute path still lists");
        let bin = tmp.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("ttool-one"), "#!/bin/sh\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(bin.join("ttool-one"), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(bin.join("ttool-data"), "not runnable").unwrap();
        let cmds = sh(&commands_script(&format!("/nowhere:{}", bin.display()), "ttool"), &tmp);
        assert_eq!(cmds, ["ttool-one"]);
        let git = std::process::Command::new("git").arg("--version").output();
        if git.map(|o| o.status.success()).unwrap_or(false) {
            let repo = tmp.join("repo");
            let run = |args: &[&str]| {
                let ok = std::process::Command::new("git").args(["-C", repo.to_str().unwrap(), "-c", "user.name=t", "-c", "user.email=t@t"]).args(args).output().unwrap().status.success();
                assert!(ok, "git {args:?}");
            };
            std::fs::create_dir_all(&repo).unwrap();
            run(&["init", "-q", "-b", "main"]);
            run(&["commit", "-q", "--allow-empty", "-m", "a"]);
            run(&["branch", "feature/x"]);
            let mut refs = sh(&branches_script(repo.to_str().unwrap()), &tmp);
            refs.sort();
            assert_eq!(refs, ["refs/heads/feature/x", "refs/heads/main"]);
        }
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
