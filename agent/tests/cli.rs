//! tterm-agent as a program: its flags, its settings file, its refusals,
//! the way agent.py had them (tterm-agent's installer and tTerm Web's rely
//! on them).

use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

fn agent() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tterm-agent"));
    cmd.env_clear().env("PATH", "/usr/bin:/bin").env("HOME", std::env::temp_dir());
    cmd
}

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("tterm-agent-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn version_and_usage() {
    let out = agent().arg("--version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), env!("CARGO_PKG_VERSION"));
    let out = agent().arg("--bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unrecognized arguments: --bogus"));
    let out = agent().arg("--hub").output().unwrap();
    assert_eq!(out.status.code(), Some(2), "a flag without its value");
}

#[test]
fn no_token_no_start() {
    let out = agent().output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("No token given"));
}

#[test]
fn a_removed_computer_stays_stopped() {
    let d = dir("removed");
    let env = d.join("env");
    std::fs::write(&env, "TTERM_HUB=wss://example.invalid/agent\nTTERM_TOKEN=x\nTTERM_REMOVED=1\n").unwrap();
    std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = agent().arg("--env-file").arg(&env).output().unwrap();
    // Success: autostart leaves it stopped.
    assert_eq!(out.status.code(), Some(0));
    let log = String::from_utf8_lossy(&out.stdout);
    assert!(log.contains("[tterm-agent] this computer was removed from tTerm Web"), "{log}");
    assert!(log.contains("can be read by others; it holds this computer's key (chmod 600 it)"), "{log}");
    let out = agent().arg("--env-file").arg(d.join("missing")).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Could not read"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn never_as_root() {
    if !nix_is_root() {
        return; // only a check run as root can see it
    }
    let out = agent().args(["--token", "x", "--hub", "ws://127.0.0.1:9/agent"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Do not run the agent as root"));
}

/// The agent started by sh with `ignore` ignored, as a script starts a
/// command in the background (INT), or nohup does (HUP); its hub is not
/// there, so it keeps trying.
fn started_ignoring(ignore: &str) -> Child {
    Command::new("/bin/sh")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", std::env::temp_dir())
        .arg("-c")
        .arg(format!("trap '' {ignore}; exec \"$0\" --token x --hub ws://127.0.0.1:9/agent"))
        .arg(env!("CARGO_BIN_EXE_tterm-agent"))
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
}

fn ended_within(child: &mut Child, wait: Duration) -> Option<ExitStatus> {
    let end = Instant::now() + wait;
    while Instant::now() < end {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn signal(child: &Child, sig: i32) {
    unsafe {
        libc::kill(child.id() as i32, sig);
    }
}

/// A signal it was started to ignore stays ignored, as for agent.py; any
/// other stops it, saying so, with success.
#[test]
fn signals_it_was_started_to_ignore() {
    if nix_is_root() {
        return; // it does not start as root
    }
    let mut child = started_ignoring("INT");
    std::thread::sleep(Duration::from_millis(700));
    signal(&child, libc::SIGINT);
    assert!(ended_within(&mut child, Duration::from_millis(700)).is_none(), "an ignored interrupt stopped it");
    signal(&child, libc::SIGTERM);
    let status = ended_within(&mut child, Duration::from_secs(10)).expect("stopped by SIGTERM");
    assert_eq!(status.code(), Some(0));
    let out = child.wait_with_output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("[tterm-agent] stopped"));

    let mut child = started_ignoring("HUP");
    std::thread::sleep(Duration::from_millis(700));
    signal(&child, libc::SIGHUP);
    assert!(ended_within(&mut child, Duration::from_millis(700)).is_none(), "an ignored hangup stopped it");
    signal(&child, libc::SIGINT);
    let status = ended_within(&mut child, Duration::from_secs(10)).expect("stopped by SIGINT");
    assert_eq!(status.code(), Some(0));
}

fn nix_is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// The agent as an installer puts it: the file, its settings next to it, in
/// a folder of its own. `before` is the version before, a script saying how
/// it was started.
fn installed(name: &str, settings: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let d = dir(name);
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    let exe = d.join("tterm-agent");
    std::fs::copy(env!("CARGO_BIN_EXE_tterm-agent"), &exe).unwrap();
    let before = d.join("tterm-agent.old");
    std::fs::write(&before, "#!/bin/sh\necho \"the version before, with $*, token ${TTERM_TOKEN:-none}\"\n").unwrap();
    std::fs::set_permissions(&before, std::fs::Permissions::from_mode(0o755)).unwrap();
    let env = d.join("env");
    std::fs::write(&env, settings).unwrap();
    std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o600)).unwrap();
    (exe, env)
}

#[test]
fn a_new_version_that_does_not_come_up_goes_back() {
    if nix_is_root() {
        return; // it does not start as root
    }
    let version = env!("CARGO_PKG_VERSION");
    // Started three times on trial without staying up: the fourth goes back.
    let (exe, env) = installed("trial-over", "TTERM_HUB=ws://127.0.0.1:9/agent\nTTERM_TOKEN=t\n");
    let d = exe.parent().unwrap().to_path_buf();
    std::fs::write(d.join("tterm-agent.trial"), format!("{version} 3\n")).unwrap();
    let out = Command::new(&exe).env_clear().env("PATH", "/usr/bin:/bin").env("TTERM_TOKEN", "from-systemd").arg("--env-file").arg(&env).output().unwrap();
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(said.contains(&format!("[tterm-agent] version {version} did not stay up here: back to the version before")), "{said}");
    // The version before, in this same process, as this one was started.
    assert!(said.contains(&format!("the version before, with --env-file {}, token from-systemd", env.display())), "{said}");
    assert!(std::fs::read_to_string(&exe).unwrap().starts_with("#!/bin/sh"), "back in its place");
    assert_eq!(std::fs::read_to_string(d.join("tterm-agent.skip")).unwrap(), format!("{version}\n"), "not taken again");
    assert!(!d.join("tterm-agent.trial").exists() && !d.join("tterm-agent.old").exists());
    let _ = std::fs::remove_dir_all(&d);

    // On trial, and it cannot start with these settings: back at once.
    let (exe, env) = installed("trial-cannot", "TTERM_HUB=ws://127.0.0.1:9/agent\n");
    let d = exe.parent().unwrap().to_path_buf();
    std::fs::write(d.join("tterm-agent.trial"), format!("{version} 0\n")).unwrap();
    let out = Command::new(&exe).env_clear().env("PATH", "/usr/bin:/bin").arg("--env-file").arg(&env).output().unwrap();
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(String::from_utf8_lossy(&out.stderr).contains("No token given"));
    assert!(said.contains(&format!("[tterm-agent] version {version} cannot start here: back to the version before")), "{said}");
    assert!(said.contains("the version before, with --env-file"), "{said}");
    let _ = std::fs::remove_dir_all(&d);

    // A trial left from another version is not this one's: it starts as it is.
    let (exe, env) = installed("trial-other", "TTERM_HUB=ws://127.0.0.1:9/agent\n");
    let d = exe.parent().unwrap().to_path_buf();
    std::fs::write(d.join("tterm-agent.trial"), "0.0.1 3\n").unwrap();
    let out = Command::new(&exe).env_clear().env("PATH", "/usr/bin:/bin").arg("--env-file").arg(&env).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "no token, and nowhere to go back to");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("the version before"));
    assert!(!d.join("tterm-agent.trial").exists());
    let _ = std::fs::remove_dir_all(&d);
}
