//! This computer, as the page sees it: a machine of the Personal project,
//! the way a Mac with tTerm's agent shows in tTerm Web, with its passport.

use serde_json::{json, Map, Value};
use std::time::Duration;

/// The machine's own name. On a Mac the one from its settings (Sharing),
/// which stays put: the hostname follows the network, and a router may make
/// it "MacBookPro.lan" for an evening. Elsewhere the hostname, without the
/// ".local" everyone has.
pub fn machine_name() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("/usr/sbin/scutil").args(["--get", "LocalHostName"]).output() {
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if out.status.success() && !name.is_empty() {
                return name;
            }
        }
    }
    let host = nix::unistd::gethostname().map(|h| h.to_string_lossy().to_string()).unwrap_or_default();
    let host = host.strip_suffix(".local").unwrap_or(&host).to_string();
    if host.is_empty() { "computer".to_string() } else { host }
}

/// The full name of the person logged in to this computer: on a Mac the
/// name System Settings shows. Falls back to the login.
pub fn account_name() -> String {
    if let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::getuid()) {
        let gecos = user.gecos.to_string_lossy().to_string();
        let full = gecos.split(',').next().unwrap_or("").trim().to_string();
        if !full.is_empty() {
            return full;
        }
        if !user.name.is_empty() {
            return user.name;
        }
    }
    std::env::var("USER").unwrap_or_else(|_| "Owner".to_string())
}

pub fn login_name() -> String {
    nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()
        .map(|u| u.name)
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_default()
}

/// The passport script of tterm-web's core (`tterm/core/passport.py`):
/// plain POSIX sh, run without a terminal. Every line is key=value; after
/// the marker, one command name per line.
pub const PASSPORT_SCRIPT: &str = r#"
LC_ALL=C; export LC_ALL
os=""; os_id=""; os_version=""
if [ -r /etc/os-release ]; then
  os=$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-}")
  os_id=$(. /etc/os-release; printf '%s' "${ID:-}")
  os_version=$(. /etc/os-release; printf '%s' "${VERSION_ID:-}")
elif command -v sw_vers >/dev/null 2>&1; then
  os_version=$(sw_vers -productVersion 2>/dev/null)
  os="$(sw_vers -productName 2>/dev/null) $os_version"
  os_id=macos
fi
[ -n "$os" ] || os=$(uname -s)
printf 'os=%s\n' "$os"
printf 'os_id=%s\n' "$os_id"
printf 'os_version=%s\n' "$os_version"
printf 'kernel=%s\n' "$(uname -r)"
printf 'arch=%s\n' "$(uname -m)"
printf 'hostname=%s\n' "$(hostname 2>/dev/null)"
for pm in apt-get dnf yum apk pacman zypper brew; do
  if command -v "$pm" >/dev/null 2>&1; then printf 'package_manager=%s\n' "$pm"; break; fi
done
login=$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f7)
[ -n "$login" ] || login=$(dscl . -read "/Users/$(id -un)" UserShell 2>/dev/null | awk '{print $2}')
[ -n "$login" ] || login=${SHELL:-}
printf 'shell=%s\n' "$login"
for s in bash zsh fish; do
  command -v "$s" >/dev/null 2>&1 && printf 'shells=%s\n' "$s"
done
printf 'cpus=%s\n' "$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null)"
memory=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
[ -n "$memory" ] || memory=$(sysctl -n hw.memsize 2>/dev/null | awk '{printf "%d", $1 / 1024}')
printf 'memory_kb=%s\n' "$memory"
df -Pk / 2>/dev/null | awk 'NR==2 {print "disk_total_kb=" $2; print "disk_free_kb=" $4}'
if sudo -n true 2>/dev/null; then echo sudo=yes
elif command -v sudo >/dev/null 2>&1 && id -Gn 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|wheel|admin'; then echo sudo=password
else echo sudo=no; fi
if [ -d /run/systemd/system ]; then echo systemd=yes; else echo systemd=no; fi
echo '--commands--'
if command -v bash >/dev/null 2>&1; then
  bash -c 'compgen -c' 2>/dev/null | LC_ALL=C sort -u | head -n 5000
fi
"#;

const MARKER: &str = "--commands--";

/// The passport from the script's output, as `passport.parse` reads it:
/// unknown lines are ignored, whatever is missing is simply absent. The
/// commands come back apart, for the input line later.
pub fn parse(output: &str) -> (Map<String, Value>, Vec<String>) {
    let (head, tail) = match output.split_once(&format!("\n{MARKER}\n")) {
        Some((h, t)) => (h, t),
        None => match output.strip_prefix(&format!("{MARKER}\n")) {
            Some(t) => ("", t),
            None => (output, ""),
        },
    };
    let mut passport = Map::new();
    let mut shells: Vec<Value> = Vec::new();
    for line in head.lines() {
        let Some((key, value)) = line.split_once('=') else { continue };
        let value = value.trim();
        match key {
            "os" | "os_id" | "os_version" | "kernel" | "arch" | "hostname" | "package_manager" | "shell" => {
                if !value.is_empty() {
                    passport.insert(key.into(), Value::String(value.chars().take(200).collect()));
                }
            }
            "cpus" | "memory_kb" | "disk_total_kb" | "disk_free_kb" => {
                if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
                    if let Ok(n) = value.parse::<u64>() {
                        passport.insert(key.into(), json!(n));
                    }
                }
            }
            "sudo" | "systemd" => {
                passport.insert(key.into(), json!(value == "yes"));
                if key == "sudo" {
                    passport.insert("sudo_password".into(), json!(value == "password"));
                }
            }
            "shells" => {
                let v = Value::String(value.to_string());
                if !value.is_empty() && !shells.contains(&v) {
                    shells.push(v);
                }
            }
            _ => {}
        }
    }
    passport.insert("shells".into(), Value::Array(shells));
    let mut commands: Vec<String> = tail
        .lines()
        .map(str::trim)
        .filter(|c| !c.is_empty() && c.chars().count() <= 100 && c.chars().all(|ch| !ch.is_control()))
        .map(str::to_string)
        .collect();
    commands.sort();
    commands.dedup();
    commands.truncate(5000);
    (passport, commands)
}

/// Runs one of tTerm's scripts with sh, outside any terminal, in a clean
/// environment: the exit code (None when it did not finish in time) and
/// what it printed.
pub async fn run_script(script: &str, timeout: Duration) -> (Option<i32>, Vec<u8>) {
    run_script_with(script, timeout, &crate::pty::clean_env(false), &crate::pty::home_dir()).await
}

/// The same, in the environment `env`, from the folder `home`.
pub async fn run_script_with(script: &str, timeout: Duration, env: &[(String, String)], home: &std::path::Path) -> (Option<i32>, Vec<u8>) {
    use tokio::io::AsyncWriteExt;
    let home = home.to_path_buf();
    let mut cmd = tokio::process::Command::new("/bin/sh");
    cmd.arg("-s")
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .current_dir(if home.is_dir() { home } else { "/".into() })
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    let Ok(mut child) = cmd.spawn() else { return (None, Vec::new()) };
    let group = child.id();
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(script.as_bytes()).await;
    }
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(out)) => (out.status.code(), out.stdout),
        Ok(Err(_)) => (None, Vec::new()),
        Err(_) => {
            // Out of time: the whole group goes, not only sh, so that a hung
            // df or sudo does not live on (the agent kills its group too).
            if let Some(pid) = group {
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                }
            }
            (None, Vec::new())
        }
    }
}

/// The passport of this computer, as the page shows it: everything but the
/// long list of commands, which it counts.
pub async fn passport(app_version: &str) -> (Value, Vec<String>) {
    let (_, out) = run_script(PASSPORT_SCRIPT, Duration::from_secs(20)).await;
    let (mut p, commands) = parse(&String::from_utf8_lossy(&out));
    p.insert("commands_count".into(), json!(commands.len()));
    p.insert("user".into(), json!(login_name()));
    p.insert("app".into(), json!(app_version));
    p.insert("checked_at".into(), json!(crate::terminals::iso_seconds(crate::terminals::now_ms())));
    (Value::Object(p), commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_like_the_core() {
        let (p, commands) = parse("os=Ubuntu 24.04.5 LTS\nos_id=ubuntu\ncpus=2\nmemory_kb=8000\nsudo=password\nshells=bash\nshells=zsh\nshells=bash\nsystemd=no\nweird\n--commands--\nls\ncd\nls\n");
        assert_eq!(p["os"], "Ubuntu 24.04.5 LTS");
        assert_eq!(p["cpus"], 2);
        assert_eq!(p["sudo"], false);
        assert_eq!(p["sudo_password"], true);
        assert_eq!(p["shells"], json!(["bash", "zsh"]));
        assert_eq!(commands, vec!["cd", "ls"]);
    }

    #[tokio::test]
    async fn a_script_out_of_time_takes_what_it_started_with_it() {
        let file = std::env::temp_dir().join(format!("tterm-group-{}", uuid::Uuid::new_v4()));
        let script = format!("sleep 30 & echo $! > {}; sleep 30\n", file.display());
        let started = std::time::Instant::now();
        let (code, _) = run_script(&script, Duration::from_millis(800)).await;
        assert_eq!(code, None);
        assert!(started.elapsed() < Duration::from_secs(5));
        let pid = std::fs::read_to_string(&file).unwrap().trim().to_string();
        let _ = std::fs::remove_file(&file);
        // The sleep it left in the background is gone, or a zombie at most.
        let mut gone = false;
        for _ in 0..40 {
            let out = std::process::Command::new("ps").args(["-o", "stat=", "-p", &pid]).output().unwrap();
            let stat = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if stat.is_empty() || stat.starts_with('Z') {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(gone, "the script's background sleep {pid} lives on");
    }

    #[tokio::test]
    async fn the_script_runs_here() {
        let (p, commands) = passport("0.0.1").await;
        assert!(p.get("os").is_some(), "{p}");
        assert!(p.get("arch").is_some());
        assert!(!commands.is_empty());
    }
}
