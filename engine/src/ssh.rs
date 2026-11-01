//! What this Mac's `~/.ssh` and its own history say about the servers the
//! person reaches with `ssh` (from 0.7.0, for `GET /api/app/ssh` and Move to
//! cloud). Nothing here connects: it reads files, runs `ssh -G <alias>`
//! (which prints the effective settings and exits), and trusts known_hosts
//! for the host keys to pin.
//!
//! Hosts come from three places: `~/.ssh/config` (its `Host` aliases, the
//! wildcard patterns left out), `known_hosts` (plain and hashed `|1|`
//! entries), and the `ssh` commands this Mac's terminals ran (the engine's
//! own blocks). For each, `ssh -G` gives the hostname, port, user, identity
//! files and `ProxyJump` that OpenSSH itself would use. github.com and the
//! like are marked `noTerminal`: they are listed but not moved.

use ring::hmac;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Hosts that answer `ssh` but open no shell: listed, never moved.
const NO_TERMINAL: [&str; 6] = ["github.com", "gitlab.com", "bitbucket.org", "git.sr.ht", "codeberg.org", "ssh.dev.azure.com"];

/// The `ssh` program, for `ssh -G`: a debug build and the checks take
/// another from TTERM_SSH, so an unpacked OpenSSH can stand in.
pub fn ssh_program() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("TTERM_SSH") {
        return PathBuf::from(p);
    }
    PathBuf::from("ssh")
}

/// How `ssh` is run here: the program, the home whose `~/.ssh` is read, and
/// whether that home is the person's own. OpenSSH finds `~` by the password
/// database, not $HOME: for another home (the checks') its config and
/// known_hosts are named with `-F` and `UserKnownHostsFile`. The person's own
/// is left to ssh, so that the system's `/etc/ssh/ssh_config` (which `-F`
/// would leave out) counts as it does in their terminal.
#[derive(Clone, Debug)]
pub struct Ssh {
    pub program: PathBuf,
    pub home: PathBuf,
    pub own_home: bool,
}

impl Ssh {
    pub fn config(&self) -> PathBuf {
        self.home.join(".ssh").join("config")
    }

    pub fn known_hosts(&self) -> PathBuf {
        self.home.join(".ssh").join("known_hosts")
    }

    /// `-F` and `UserKnownHostsFile` for a home that is not the person's.
    fn file_args(&self) -> Vec<std::ffi::OsString> {
        if self.own_home {
            return Vec::new();
        }
        let mut args: Vec<std::ffi::OsString> = Vec::new();
        if self.config().exists() {
            args.push("-F".into());
            args.push(self.config().into_os_string());
        }
        let mut known = std::ffi::OsString::from("UserKnownHostsFile=");
        known.push(self.known_hosts().as_os_str());
        args.push("-o".into());
        args.push(known);
        args
    }
}

/// A host the person can reach, as the page lists it.
#[derive(Debug, Clone)]
pub struct Host {
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<String>,
    pub proxy_jump: Option<String>,
    pub from: BTreeSet<&'static str>,
    pub last_used: Option<i64>,
    pub no_terminal: bool,
    pub host_keys: Vec<String>,
}

impl Host {
    pub fn to_json(&self) -> Value {
        json!({
            "alias": self.alias,
            "host": self.hostname,
            "port": self.port,
            "user": self.user,
            "identityFiles": self.identity_files,
            "proxyJump": self.proxy_jump,
            "from": self.from.iter().collect::<Vec<_>>(),
            "lastUsed": self.last_used,
            "noTerminal": self.no_terminal,
            "hostKeys": self.host_keys,
        })
    }
}

/// Where a host came up, for `from`: the config, known_hosts, or history.
#[derive(Default)]
struct Found {
    config: bool,
    known: bool,
    history: bool,
    last_used: Option<i64>,
}

/// Every host this Mac knows, with the keys read from `history` (the store's
/// `ssh` commands, newest first), each with what `ssh -G` says of it.
pub fn hosts(ssh: &Ssh, history: &[(String, i64)]) -> Vec<Host> {
    let config_text = std::fs::read_to_string(ssh.config()).unwrap_or_default();
    let known_text = std::fs::read_to_string(ssh.known_hosts()).unwrap_or_default();

    // The config's hosts and the ones typed in tTerm's terminals, by name.
    let mut found: BTreeMap<String, Found> = BTreeMap::new();
    for alias in config_hosts(&config_text) {
        found.entry(alias).or_default().config = true;
    }
    for (command, at) in history {
        if let Some(target) = ssh_target(command) {
            let e = found.entry(target).or_default();
            e.history = true;
            e.last_used = Some(e.last_used.map_or(*at, |had| had.max(*at)));
        }
    }
    let mut hosts: Vec<Host> = found.into_iter().map(|(alias, f)| resolved(ssh, &known_text, alias, f)).collect();
    for name in merge_known(&mut hosts, &known_plain_entries(&known_text)) {
        let found = Found { known: true, ..Found::default() };
        hosts.push(resolved(ssh, &known_text, name, found));
    }
    hosts.sort_by(|a, b| a.alias.cmp(&b.alias));
    hosts
}

/// A host as `ssh -G` sees it, by the name it is listed under.
fn resolved(ssh: &Ssh, known_text: &str, alias: String, f: Found) -> Host {
    let settings = effective(ssh, &alias);
    let hostname = settings.one("hostname").unwrap_or_else(|| alias.clone());
    let port = settings.one("port").and_then(|p| p.parse().ok()).unwrap_or(22);
    let user = settings.one("user").unwrap_or_default();
    let identity_files = settings.many("identityfile");
    let proxy_jump = settings.one("proxyjump").filter(|p| !p.eq_ignore_ascii_case("none"));
    let mut from = BTreeSet::new();
    if f.config {
        from.insert("config");
    }
    if f.known {
        from.insert("known_hosts");
    }
    if f.history {
        from.insert("history");
    }
    let host_keys = host_keys_for(known_text, &hostname, port);
    let no_terminal = is_no_terminal(&hostname);
    Host { alias, hostname, port, user, identity_files, proxy_jump, from, last_used: f.last_used, no_terminal, host_keys }
}

/// known_hosts' plain entries next to the hosts already listed (0.7.0):
/// most are those very servers, written there by ssh under their address
/// and port (`[10.0.0.5]:2222`), and such an entry only adds known_hosts to
/// where that host came from. One that is none of them is a server of its
/// own when it is at port 22, reached by that name: its name is returned,
/// to be listed. One at another port without a Host of its own cannot be
/// reached by its name alone, and is left out. (The app's checks, 01.11:
/// the config's own servers were listed a second time, the port dropped.)
fn merge_known(hosts: &mut [Host], known: &[(String, u16)]) -> Vec<String> {
    let mut more: Vec<String> = Vec::new();
    for (name, port) in known {
        let same = hosts.iter_mut().find(|h| {
            (h.hostname.eq_ignore_ascii_case(name) && h.port == *port)
                || (*port == 22 && h.alias.eq_ignore_ascii_case(name))
        });
        if let Some(h) = same {
            h.from.insert("known_hosts");
        } else if *port == 22 && !more.iter().any(|m| m.eq_ignore_ascii_case(name)) {
            more.push(name.clone());
        }
    }
    more
}

/// Whether a hostname is one of the no-terminal hosts (github.com and the
/// like, and their www. or subdomain forms).
fn is_no_terminal(hostname: &str) -> bool {
    let h = hostname.trim_end_matches('.').to_ascii_lowercase();
    NO_TERMINAL.iter().any(|known| h == *known || h.ends_with(&format!(".{known}")))
}

/// The `Host` aliases of a config, the wildcard patterns (`*`, `?`, and the
/// negations) left out: those are rules, not servers to list. A `Host` line
/// may name several; `Match` blocks are skipped.
fn config_hosts(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((keyword, rest)) = line.split_once(|c: char| c.is_whitespace() || c == '=') else { continue };
        if !keyword.eq_ignore_ascii_case("host") {
            continue;
        }
        for pattern in rest.split_whitespace() {
            let pattern = pattern.trim_matches('"');
            if pattern.is_empty() || pattern.contains(['*', '?', '!']) {
                continue;
            }
            out.push(pattern.to_string());
        }
    }
    out
}

/// The plain entries of known_hosts, each a host and its port (not the
/// hashed `|1|` ones, which hide the name): the first field's names, before
/// a comma, each once.
fn known_plain_entries(text: &str) -> Vec<(String, u16)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("@") {
            continue;
        }
        let Some(first) = line.split_whitespace().next() else { continue };
        if first.starts_with("|1|") {
            continue;
        }
        for entry in first.split(',') {
            let (name, port) = entry_host_port(entry);
            if !name.is_empty() && !name.contains(['*', '?']) {
                out.push((name, port));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// A known_hosts entry's host and port: `[host]:port` is that port, a bare
/// `host` is 22.
fn entry_host_port(entry: &str) -> (String, u16) {
    let entry = entry.trim();
    if let Some(rest) = entry.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once("]:") {
            return (host.to_string(), port.parse().unwrap_or(22));
        }
        return (rest.trim_end_matches(']').to_string(), 22);
    }
    (entry.to_string(), 22)
}

/// The host keys known_hosts pins for a host, as "type base64", from the
/// entries that match it: plain names for this address, and hashed `|1|`
/// entries whose HMAC matches. A non-22 port matches `[host]:port` entries.
pub fn host_keys_for(known_text: &str, hostname: &str, port: u16) -> Vec<String> {
    let bare = hostname.to_ascii_lowercase();
    let bracketed = format!("[{}]:{}", bare, port);
    let mut keys = Vec::new();
    for line in known_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(first), Some(kind), Some(b64)) = (parts.next(), parts.next(), parts.next()) else { continue };
        let matched = if let Some(hash) = first.strip_prefix("|1|") {
            // A hashed entry hides the name and the port: OpenSSH hashes the
            // bare name at 22, and the bracketed form otherwise.
            let name = if port == 22 { bare.as_str() } else { bracketed.as_str() };
            hashed_matches(hash, name)
        } else {
            first.split(',').any(|entry| {
                let (host, entry_port) = entry_host_port(entry);
                host.eq_ignore_ascii_case(&bare) && entry_port == port
            })
        };
        if matched {
            let one = format!("{kind} {b64}");
            if !keys.contains(&one) {
                keys.push(one);
            }
        }
    }
    keys
}

/// Whether a hashed known_hosts entry `salt|mac` is for `name`: the HMAC-SHA1
/// of the name under the salt, as OpenSSH computes it.
fn hashed_matches(hash: &str, name: &str) -> bool {
    use base64::Engine as _;
    let std = base64::engine::general_purpose::STANDARD;
    let Some((salt_b64, mac_b64)) = hash.split_once('|') else { return false };
    let (Ok(salt), Ok(mac)) = (std.decode(salt_b64), std.decode(mac_b64)) else { return false };
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &salt);
    hmac::verify(&key, name.as_bytes(), &mac).is_ok()
}

/// The effective settings OpenSSH would use for `alias`, from `ssh -G`:
/// never connects, never prompts (it only prints).
pub fn effective(ssh: &Ssh, alias: &str) -> Settings {
    let mut cmd = Command::new(&ssh.program);
    cmd.arg("-G").args(ssh.file_args()).arg("--").arg(alias);
    cmd.stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    let text = match cmd.output() {
        Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
        Err(_) => String::new(),
    };
    Settings::parse(&text)
}

/// What a login over `ssh` ended as: whether it got in, the last line of
/// what it said went wrong (Permission denied, a timeout), and the
/// fingerprint of the key the server accepted, when ssh said so (`-v`).
pub struct Attempt {
    pub ok: bool,
    pub error: Option<String>,
    pub accepted: Option<String>,
    /// What the remote command printed (Let tTerm in's script says whether
    /// it added the line), at most OUT_MAX bytes of it.
    pub out: String,
}

/// What of the remote command's output is kept.
const OUT_MAX: usize = 64 * 1024;

/// How long a login may take in all, past ConnectTimeout: a server that
/// takes the connection and then says nothing is given up on.
const LOGIN_WAIT: std::time::Duration = std::time::Duration::from_secs(40);

/// A login with `ssh <extra> <alias> <remote>`: for `try` the remote is
/// `true`; for Let tTerm in, `sh -s` with `stdin` the script. It never asks
/// anything. Without a passphrase it is `BatchMode=yes`, as the contract has
/// it. With one (`askpass`: the helper and the passphrase) BatchMode would
/// not even try it — OpenSSH then gives up on an encrypted key at the empty
/// passphrase — so instead every other question is switched off (passwords,
/// keyboard-interactive, a new host key), one passphrase try is allowed, and
/// SSH_ASKPASS_REQUIRE=force sends the question to the helper, which answers
/// only a passphrase question, from this one process's environment. The ssh
/// runs in a session of its own, so no terminal can be asked either.
pub async fn run(ssh: &Ssh, alias: &str, extra: &[&str], remote: &[&str], stdin: Option<&str>, askpass: Option<(&Path, &str)>) -> Attempt {
    use tokio::io::AsyncWriteExt;
    let mut cmd = tokio::process::Command::new(&ssh.program);
    cmd.args(ssh.file_args()).arg("-o").arg("ConnectTimeout=8");
    match askpass {
        Some((helper, phrase)) => {
            for option in ["BatchMode=no", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "StrictHostKeyChecking=yes", "NumberOfPasswordPrompts=1"] {
                cmd.arg("-o").arg(option);
            }
            cmd.env("SSH_ASKPASS", helper);
            cmd.env("SSH_ASKPASS_REQUIRE", "force");
            cmd.env(ASKPASS_VAR, phrase);
        }
        None => {
            cmd.arg("-o").arg("BatchMode=yes");
            cmd.env_remove("SSH_ASKPASS");
            cmd.env_remove("SSH_ASKPASS_REQUIRE");
            cmd.env_remove(ASKPASS_VAR);
        }
    }
    cmd.args(extra).arg("--").arg(alias).args(remote);
    cmd.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);
    // SAFETY: setsid only, in the child before exec: no terminal is its own.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Attempt { ok: false, error: Some(format!("could not run ssh: {e}")), accepted: None, out: String::new() },
    };
    if let Some(mut si) = child.stdin.take() {
        if let Some(script) = stdin {
            let _ = si.write_all(script.as_bytes()).await;
        }
        let _ = si.shutdown().await;
    }
    let out = match tokio::time::timeout(LOGIN_WAIT, child.wait_with_output()).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => return Attempt { ok: false, error: Some(e.to_string()), accepted: None, out: String::new() },
        Err(_) => return Attempt { ok: false, error: Some("ssh did not finish in time".into()), accepted: None, out: String::new() },
    };
    let ok = out.status.success();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let error = (!ok).then(|| last_problem(&stderr));
    let kept = &out.stdout[..out.stdout.len().min(OUT_MAX)];
    Attempt { ok, error, accepted: accepted_key(&stderr), out: String::from_utf8_lossy(kept).into_owned() }
}

/// The last line of what ssh said that is not one of `-v`'s debug lines:
/// what the page shows when a login did not work.
fn last_problem(stderr: &str) -> String {
    stderr
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("debug"))
        .unwrap_or("ssh did not get in")
        .to_string()
}

/// The fingerprint of the key the server accepted, from `-v`'s last
/// "Server accepts key: <file> <TYPE> <SHA256:…>" line (the target's, after
/// a bastion's own). The file's name may have spaces: the fingerprint is the
/// word that starts with "SHA256:".
pub fn accepted_key(stderr: &str) -> Option<String> {
    let line = stderr.lines().rev().find_map(|l| l.split_once("Server accepts key: ").map(|(_, rest)| rest))?;
    line.split_whitespace().find(|w| w.starts_with("SHA256:")).map(str::to_string)
}

/// The environment variable the askpass helper reads the passphrase from.
pub const ASKPASS_VAR: &str = "TTERM_ASKPASS_VALUE";

/// The askpass helper: answers only ssh's passphrase question, "Enter
/// passphrase for key '…': ", with the passphrase in its environment, and
/// refuses anything else (a confirmation, a PIN, a password), so that no
/// other question could ever get the passphrase.
const ASKPASS_SCRIPT: &str = "#!/bin/sh\n\
    # tTerm's askpass for one ssh login (engine/src/ssh.rs): it holds no secret.\n\
    [ \"${SSH_ASKPASS_PROMPT:-}\" = confirm ] && exit 1\n\
    case \"$1\" in\n\
      'Enter passphrase for '*) printf '%s\\n' \"${TTERM_ASKPASS_VALUE:-}\" ;;\n\
      *) exit 1 ;;\n\
    esac\n";

/// Writes the askpass helper into `dir` and returns its path. It holds no
/// secret itself; the passphrase is only ever in the environment of the one
/// ssh process that runs it.
pub fn askpass_helper(dir: &Path) -> std::io::Result<PathBuf> {
    let path = dir.join("askpass.sh");
    if std::fs::read_to_string(&path).ok().as_deref() != Some(ASKPASS_SCRIPT) {
        std::fs::write(&path, ASKPASS_SCRIPT)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(path)
}

/// The script that adds tTerm's CA line to the server's authorized_keys, as
/// the contract has it: umask 077, mkdir -p ~/.ssh, append only if absent
/// (the whole line, not a commented-out copy), after a newline if the file
/// does not end with one. It prints LINE_ADDED or LINE_PRESENT. `line` is
/// single-quoted safely, so its quotes and spaces are left alone.
pub fn add_line_script(line: &str) -> String {
    let quoted = shell_single_quote(line);
    format!(
        "set -eu\n\
         umask 077\n\
         mkdir -p \"$HOME/.ssh\"\n\
         f=\"$HOME/.ssh/authorized_keys\"\n\
         [ -f \"$f\" ] || : > \"$f\"\n\
         if grep -qxF -e {quoted} \"$f\"; then\n\
           echo {LINE_PRESENT}\n\
         else\n\
           if [ -s \"$f\" ] && [ -n \"$(tail -c 1 \"$f\")\" ]; then printf '\\n' >> \"$f\"; fi\n\
           printf '%s\\n' {quoted} >> \"$f\"\n\
           echo {LINE_ADDED}\n\
         fi\n\
         chmod 600 \"$f\" 2>/dev/null || true\n"
    )
}

/// What `add_line_script` prints when it added the line.
pub const LINE_ADDED: &str = "tterm-web-line-added";
/// What it prints when the line was there already.
pub const LINE_PRESENT: &str = "tterm-web-line-present";

/// The script that takes tTerm's line off again, when the server it was
/// added for was not saved: only that whole line, only if it is there, and
/// the file is left as it was if grep fails.
pub fn remove_line_script(line: &str) -> String {
    let quoted = shell_single_quote(line);
    format!(
        "set -u\n\
         umask 077\n\
         f=\"$HOME/.ssh/authorized_keys\"\n\
         [ -f \"$f\" ] || exit 0\n\
         grep -qxF -e {quoted} \"$f\" || exit 0\n\
         t=\"$f.tterm-$$\"\n\
         grep -vxF -e {quoted} \"$f\" > \"$t\"\n\
         s=$?\n\
         if [ \"$s\" -le 1 ]; then cat \"$t\" > \"$f\"; fi\n\
         rm -f \"$t\"\n"
    )
}

/// A string safely inside single quotes for POSIX sh: every `'` becomes
/// `'\''`.
fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The lines of `ssh -G`: a keyword and its value, lower-cased keywords, a
/// keyword such as identityfile given more than once kept in order.
#[derive(Debug, Default)]
pub struct Settings {
    values: Vec<(String, String)>,
}

impl Settings {
    pub fn parse(text: &str) -> Settings {
        let mut values = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some((key, value)) = line.split_once(char::is_whitespace) {
                values.push((key.to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        Settings { values }
    }

    /// The first value of a keyword.
    pub fn one(&self, key: &str) -> Option<String> {
        self.values.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    /// Every value of a keyword, in order (identityfile).
    pub fn many(&self, key: &str) -> Vec<String> {
        self.values.iter().filter(|(k, _)| k == key).map(|(_, v)| v.clone()).collect()
    }
}

/// The host of an `ssh` command this Mac ran: its first non-option word,
/// the user@ stripped. None when the command is not a plain `ssh host`
/// (a subcommand, an option that eats the next word, a URL).
pub fn ssh_target(command: &str) -> Option<String> {
    let mut words = command.split_whitespace();
    if words.next()? != "ssh" {
        return None;
    }
    // Options that take a value in the next word: it is not the host.
    const TAKES_VALUE: &[char] = &['B', 'b', 'c', 'D', 'E', 'e', 'F', 'I', 'i', 'J', 'L', 'l', 'm', 'O', 'o', 'p', 'Q', 'R', 'S', 'W', 'w'];
    let mut skip_next = false;
    for word in words {
        if skip_next {
            skip_next = false;
            continue;
        }
        if let Some(opt) = word.strip_prefix('-') {
            // A bundle like -4v, or -p with the value joined (-p22): a value
            // option at the end of the bundle eats the next word.
            if let Some(last) = opt.chars().last() {
                let joined = opt.len() > 1 && TAKES_VALUE.contains(&opt.chars().nth(opt.len() - 1).unwrap()) && opt.chars().take(opt.len() - 1).all(|c| !TAKES_VALUE.contains(&c));
                skip_next = TAKES_VALUE.contains(&last) && !joined;
            }
            continue;
        }
        // The first bare word is the host (or user@host); a command after
        // it is the remote command, not another host.
        let host = word.rsplit('@').next().unwrap_or(word);
        if host.is_empty() || host.contains("://") {
            return None;
        }
        return Some(host.to_string());
    }
    None
}

/// A hashed known_hosts entry for a name, as OpenSSH writes it: for the
/// checks that make hashed files.
pub fn hash_entry(name: &str, salt: &[u8]) -> String {
    use base64::Engine as _;
    let std = base64::engine::general_purpose::STANDARD;
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let mac = hmac::sign(&key, name.as_bytes());
    format!("|1|{}|{}", std.encode(salt), std.encode(mac.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_aliases_without_wildcards() {
        let text = "Host web-01 db\n  HostName example.com\nHost *.internal\nHost bastion !!no\nMatch host x\nHost \"quoted\"\n";
        assert_eq!(config_hosts(text), ["web-01", "db", "bastion", "quoted"]);
    }

    #[test]
    fn ssh_targets_from_history() {
        assert_eq!(ssh_target("ssh web-01"), Some("web-01".into()));
        assert_eq!(ssh_target("ssh deploy@example.com uptime"), Some("example.com".into()));
        assert_eq!(ssh_target("ssh -p 2222 -i ~/.ssh/id_ed25519 host"), Some("host".into()));
        assert_eq!(ssh_target("ssh -p2222 host"), Some("host".into()));
        assert_eq!(ssh_target("ssh -4 -J bastion inner"), Some("inner".into()));
        assert_eq!(ssh_target("ssh -o User=x host"), Some("host".into()));
        assert_eq!(ssh_target("scp a b"), None);
        assert_eq!(ssh_target("ssh"), None);
        assert_eq!(ssh_target("ssh -i key"), None, "the option eats the only word");
    }

    #[test]
    fn hashed_and_plain_known_hosts() {
        let salt = [7u8; 20];
        let entry = hash_entry("secret-host", &salt);
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHELLO";
        let plain = format!("example.com {key}\n[example.com]:2222 ssh-rsa AAAABOTHER\n{entry} {key}\n");
        assert_eq!(host_keys_for(&plain, "example.com", 22), [key.to_string()]);
        assert_eq!(host_keys_for(&plain, "example.com", 2222), ["ssh-rsa AAAABOTHER".to_string()]);
        assert_eq!(host_keys_for(&plain, "secret-host", 22), [key.to_string()], "a hashed entry matched for a given host");
        assert!(host_keys_for(&plain, "other", 22).is_empty());
        // The hashed name is not listed among the plain ones; the port is kept.
        assert_eq!(known_plain_entries(&plain), [("example.com".to_string(), 22), ("example.com".to_string(), 2222)]);
    }

    fn listed(alias: &str, hostname: &str, port: u16) -> Host {
        Host {
            alias: alias.into(), hostname: hostname.into(), port, user: "deploy".into(),
            identity_files: Vec::new(), proxy_jump: None, from: BTreeSet::from(["config"]),
            last_used: None, no_terminal: false, host_keys: Vec::new(),
        }
    }

    #[test]
    fn known_hosts_entries_of_listed_servers_are_not_listed_again() {
        // The config's servers as ssh writes them in known_hosts, by address
        // and port; one more server at 22, one at another port, and one
        // under the alias itself.
        let mut hosts = vec![listed("keylab", "10.0.0.5", 2201), listed("web", "web.example.com", 22)];
        let known = [
            ("10.0.0.5".to_string(), 2201),
            ("web.example.com".to_string(), 22),
            ("keylab".to_string(), 22),
            ("192.168.1.9".to_string(), 22),
            ("192.168.1.9".to_string(), 22),
            ("10.0.0.7".to_string(), 2222),
        ];
        let more = merge_known(&mut hosts, &known);
        assert_eq!(more, ["192.168.1.9"], "only the server none of them is, at port 22, once");
        assert!(hosts.iter().all(|h| h.from.contains("known_hosts") && h.from.contains("config")));
    }

    #[test]
    fn no_terminal_hosts() {
        assert!(is_no_terminal("github.com"));
        assert!(is_no_terminal("GitHub.com."));
        assert!(is_no_terminal("altssh.gitlab.com"));
        assert!(!is_no_terminal("example.com"));
    }

    #[test]
    fn settings_from_ssh_g() {
        let g = "hostname example.com\nport 2222\nuser deploy\nidentityfile ~/.ssh/id_ed25519\nidentityfile ~/.ssh/id_rsa\nproxyjump bastion\n";
        let s = Settings::parse(g);
        assert_eq!(s.one("hostname").as_deref(), Some("example.com"));
        assert_eq!(s.one("port").as_deref(), Some("2222"));
        assert_eq!(s.many("identityfile").len(), 2);
        assert_eq!(s.one("proxyjump").as_deref(), Some("bastion"));
    }
}
