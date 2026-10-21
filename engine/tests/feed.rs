//! The feed, as far as the engine goes: real bash and zsh with tTerm's
//! scripts, their markers cut into blocks, the blocks and the history in the
//! store, commands typed by the page, the question before a dangerous one,
//! and Tab. Ports of tterm-web's checks (test_feed.py and the shell parts of
//! test_terminals.py), driven the way the page drives the engine.

use base64::Engine as _;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tterm_engine::terminals::Terminal;
use tterm_engine::Engine;
use uuid::Uuid;

mod common;
use common::*;

/// A home of its own for the shell, as the core's checks make one: bash
/// skipping commands that start with a space, zsh the same, and a
/// repository on a branch with a / in its name. zsh reads none of the
/// machine's own settings (see zsh_as_the_login_shell in terminals.rs).
fn home() -> PathBuf {
    let home = std::env::temp_dir().join(format!("tthome {}", Uuid::new_v4()));
    std::fs::create_dir_all(home.join("repo").join(".git")).unwrap();
    std::fs::write(home.join(".bashrc"), "HISTCONTROL=ignoreboth\nPS1='$ '\n").unwrap();
    std::fs::write(home.join(".profile"), "[ -n \"$BASH\" ] && . ~/.bashrc\n").unwrap();
    std::fs::write(home.join(".zshenv"), "unsetopt GLOBAL_RCS\n").unwrap();
    std::fs::write(home.join(".zshrc"), "HISTFILE=~/.zsh_history\nHISTSIZE=100\nSAVEHIST=100\nsetopt hist_ignore_space\nPROMPT='%% '\n").unwrap();
    std::fs::write(home.join("repo").join(".git").join("HEAD"), "ref: refs/heads/feature/x\n").unwrap();
    home
}

fn shell_path(name: &str) -> Option<String> {
    ["/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"].iter().map(|d| format!("{d}/{name}")).find(|p| Path::new(p).is_file())
}

/// The environment the engine gives a shell, with this home and login shell.
fn env_for(home: &Path, login: &str, terminal: bool) -> Vec<(String, String)> {
    let mut env = tterm_engine::pty::clean_env(terminal);
    env.retain(|(k, _)| k != "HOME" && k != "SHELL");
    env.push(("HOME".into(), home.to_string_lossy().to_string()));
    env.push(("SHELL".into(), login.into()));
    env
}

/// A terminal with `login` as the login shell in `home`, planned by the
/// engine as for the person's own.
async fn terminal_in(e: &Arc<Engine>, login: &str, home: &Path, cols: i64, rows: i64) -> Arc<Terminal> {
    let planner = {
        let (e, login, home) = (e.clone(), login.to_string(), home.to_path_buf());
        let env = env_for(&home, &login, false);
        async move { e.plan_for(&login, &env, &home).await }
    };
    e.terminals.open(e.place(), planner, env_for(home, login, true), home.to_path_buf(), cols, rows, 24).await.unwrap()
}

async fn watched(e: &Arc<Engine>, t: &Arc<Terminal>, cols: i64, rows: i64) -> Page {
    attached(e, &t.id.to_string(), cols, rows).await
}

/// The markers the page got, of one kind.
fn marks(page: &Page, kind: &str) -> Vec<Value> {
    page.msgs.iter().filter(|m| m["op"] == "ev" && m["t"] == kind).cloned().collect()
}

fn prompts(page: &Page) -> usize {
    marks(page, "P").len()
}

/// Waits for the `n`th prompt, and for the line editor to read again.
///
/// The prompt's marker comes before the prompt itself, and the line editor
/// is ready a moment after it: it turns bracketed paste on (bash 5.1 and
/// newer, zsh). Typed sooner, a command reaches a terminal that is not raw
/// yet: the terminal itself echoes it, and bash reads the lines of a paste
/// one by one, with a prompt for each. On the web the network's delay
/// covers that moment, and a person is slower than either.
async fn prompted(page: &mut Page, n: usize, what: &str) {
    assert!(page.until(20, |p| prompts(p) >= n).await, "no prompt after {what}: {:?}", page.text());
    let at = page.marks_at.iter().zip(page.msgs.iter().filter(|m| m["op"] == "ev")).filter(|(_, m)| m["t"] == "P").map(|(at, _)| *at).last().unwrap_or(0);
    page.until(2, |p| p.out[at..].windows(8).any(|w| w == b"\x1b[?2004h")).await;
}

fn same_place(a: &str, b: &Path) -> bool {
    std::fs::canonicalize(a).ok() == std::fs::canonicalize(b).ok()
}

/// What the store keeps of the terminal, oldest first.
async fn saved(e: &Arc<Engine>, t: &Terminal, n: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let feed = e.terminals.store.feed(&t.id.to_string(), None, 200).await.unwrap();
        let blocks = feed["blocks"].as_array().unwrap().clone();
        if blocks.len() >= n {
            return blocks;
        }
        assert!(Instant::now() < deadline, "{} blocks saved, not {n}", blocks.len());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn output_of(block: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(block["output"].as_str().unwrap()).unwrap()
}

/// bash 4.4 or newer, as the plan finds it: it has PS0, so commands get a
/// start marker.
async fn bash_marks_commands(e: &Arc<Engine>, home: &Path) -> Option<String> {
    let login = shell_path("bash")?;
    let plan = e.plan_for(&login, &env_for(home, &login, false), home).await;
    plan.blocks.then_some(login)
}

// ------------------------------------------------------ the real shells

async fn shell_prints_markers(login: &str, full: bool) {
    let e = engine().await;
    let home = home();
    let t = terminal_in(&e, login, &home, 80, 24).await;
    let mut page = watched(&e, &t, 80, 24).await;
    prompted(&mut page, 1, "the start").await;
    // The key is 32 hex digits: nothing like it shows.
    let text = page.text();
    assert!(!text.split(|c: char| !c.is_ascii_hexdigit()).any(|w| w.len() >= 32), "the key never shows: {text}");
    let first = marks(&page, "P")[0].clone();
    // On macOS /var is /private/var: the shell reports the real path.
    assert!(same_place(first["cwd"].as_str().unwrap(), &home), "{first}");
    assert_eq!(first["home"], home.to_string_lossy().as_ref());
    assert!(t.lock().path.contains("/bin"), "the prompt carries the PATH: {}", t.lock().path);
    assert_eq!(t.describe()["markers"], true);

    page.keys(1, "echo hello\r").await;
    prompted(&mut page, 2, "echo").await;
    assert!(page.text().contains("hello"));
    page.keys(1, "false\r").await;
    prompted(&mut page, 3, "false").await;
    assert_eq!(marks(&page, "P").last().unwrap()["code"], 1, "the exit code comes along");
    page.keys(1, "cd repo\r").await;
    prompted(&mut page, 4, "cd repo").await;
    assert_eq!(marks(&page, "P").last().unwrap()["branch"], "feature/x", "the branch, with its /");
    page.keys(1, " echo secret\r").await;
    prompted(&mut page, 5, "the secret").await;
    page.keys(1, "echo \"a;b%c\"\r").await;
    prompted(&mut page, 6, "a;b%c").await;
    let commands: Vec<String> = marks(&page, "C").iter().map(|m| m["command"].as_str().unwrap().to_string()).collect();
    if full {
        assert_eq!(commands[..2], ["echo hello", "false"], "{commands:?}");
        assert_eq!(commands[3].trim(), "echo secret", "a command history skips is still recorded");
        assert_eq!(commands[4], "echo \"a;b%c\"");
    }
    page.keys(1, "fc -ln -10\r").await;
    prompted(&mut page, 7, "fc").await;
    let text = page.text();
    let listed = text.rsplit("fc -ln -10").next().unwrap();
    assert!(!listed.contains("secret"), "but it stays out of history, as asked: {listed}");

    if full {
        // Three commands in one paste: bash marks each, with the code of
        // the one before; zsh takes the paste as one command.
        let before = marks(&page, "C").len();
        page.keys(1, "\x1b[200~(exit 3)\n(exit 5)\necho x\x1b[201~\r").await;
        assert!(page.until(20, |p| marks(p, "C").len() > before && prompts(p) >= 8).await, "{}", page.text());
        tokio::time::sleep(Duration::from_millis(300)).await;
        page.until(1, |_| false).await;
        let cs: Vec<Value> = marks(&page, "C")[before..].to_vec();
        let texts: Vec<&str> = cs.iter().map(|c| c["command"].as_str().unwrap()).collect();
        if login.ends_with("bash") {
            assert_eq!(texts, ["(exit 3)", "(exit 5)", "echo x"]);
            assert_eq!(cs[1]["prev"], 3);
            assert_eq!(cs[2]["prev"], 5);
        } else {
            assert_eq!(texts, ["(exit 3)\n(exit 5)\necho x"]);
        }
        assert_eq!(marks(&page, "P").last().unwrap()["code"], 0);

        // The blocks, as the store keeps them: the paste is three of them
        // in bash, one in zsh.
        let blocks = saved(&e, &t, if login.ends_with("bash") { 9 } else { 7 }).await;
        let hello = blocks.iter().find(|b| b["command"] == "echo hello").unwrap();
        let out = output_of(hello);
        assert!(String::from_utf8_lossy(&out).contains("hello"));
        assert!(!out.windows(7).any(|w| w == b"\x1b]6973"), "no markers in a block");
        assert_eq!(hello["exitCode"], 0);
        assert!(same_place(hello["cwd"].as_str().unwrap(), &home));
        assert_eq!(blocks.iter().find(|b| b["command"] == "false").unwrap()["exitCode"], 1);
        let secret = blocks.iter().find(|b| b["command"].as_str().unwrap().trim() == "echo secret").unwrap();
        assert_eq!(secret["branch"], "feature/x");
        if login.ends_with("zsh") {
            // zsh's mark for a line left open comes off, and the page is
            // told how much.
            assert!(marks(&page, "P")[1]["trim"].as_u64().unwrap() > 0, "{:?}", marks(&page, "P")[1]);
            assert!(!out.ends_with(b"\r \r"), "{:?}", String::from_utf8_lossy(&out));
        }
    }
    t.close("Closed.").await;
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bash_prints_markers() {
    let Some(bash) = shell_path("bash") else { return };
    let e = engine().await;
    let home = home();
    let full = bash_marks_commands(&e, &home).await.is_some();
    let _ = std::fs::remove_dir_all(&home);
    shell_prints_markers(&bash, full).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zsh_prints_markers() {
    let Some(zsh) = shell_path("zsh") else { return };
    shell_prints_markers(&zsh, true).await;
}

/// The shell for the checks below: bash where it marks commands, zsh
/// otherwise (macOS has bash 3.2).
async fn login_shell(e: &Arc<Engine>, home: &Path) -> Option<String> {
    if let Some(bash) = bash_marks_commands(e, home).await {
        return Some(bash);
    }
    shell_path("zsh")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_page_types_whole_commands() {
    let e = engine().await;
    let home = home();
    std::fs::create_dir_all(home.join("My Docs")).unwrap();
    std::fs::create_dir_all(home.join("src")).unwrap();
    let Some(login) = login_shell(&e, &home).await else { return };
    let bash = login.ends_with("bash");
    let t = terminal_in(&e, &login, &home, 100, 30).await;
    let mut page = watched(&e, &t, 100, 30).await;
    prompted(&mut page, 1, "the start").await;
    assert_eq!(t.describe()["blocks"], true);
    assert!(!t.lock().path.is_empty());
    assert_eq!(t.run("echo one\necho two"), None);
    assert_eq!(t.run("echo three").as_deref(), Some("A command is still running."));
    prompted(&mut page, 2, "the pasted lines").await;
    assert!(page.text().contains("one\r\ntwo"), "{:?}", page.text());
    assert_eq!(t.run("printf 'a\\tb\\n'; (exit 4)"), None);
    prompted(&mut page, 3, "tab and code").await;
    assert!(page.text().contains("a\tb") || page.text().contains("a       b"));
    assert_eq!(t.run("echo \x1b[201~evil"), None);
    prompted(&mut page, 4, "no escape").await;
    assert_eq!(t.run("  ").as_deref(), Some("There is no command to run."));
    // Keys typed into a command that never read them wait for the line
    // editor; the next command must not start with them.
    t.write(b"leftover");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(t.run("echo clean"), None);
    prompted(&mut page, 5, "clean").await;
    assert_eq!(marks(&page, "C").last().unwrap()["command"], "echo clean");
    // bash runs the two pasted lines as two commands, zsh as one.
    let rows = saved(&e, &t, if bash { 5 } else { 4 }).await;
    let commands: Vec<&str> = rows.iter().map(|r| r["command"].as_str().unwrap()).collect();
    assert!(commands.contains(&"echo two") || commands.contains(&"echo one\necho two"), "{commands:?}");
    assert_eq!(commands[commands.len() - 2], "echo [201~evil", "the escape was taken out");
    assert_eq!(rows[0]["cols"], 100);
    let printf = rows.iter().find(|r| r["command"] == "printf 'a\\tb\\n'; (exit 4)").unwrap();
    assert_eq!(printf["exitCode"], 4);
    // The events the page builds its blocks from.
    let evs: Vec<&Value> = page.msgs.iter().filter(|m| m["op"] == "ev").collect();
    assert!(evs.iter().all(|e| e["at"].as_i64().is_some()));
    assert!(evs.iter().filter(|e| e["t"] == "P").all(|e| e["trim"].as_u64().is_some()));
    assert_eq!(t.describe()["running"], Value::Null);

    // Tab, by a script beside the terminal.
    let got = t.complete("cd M", 4).await.unwrap();
    assert_eq!((got["kind"].as_str(), got["start"].as_u64()), (Some("dir"), Some(3)), "{got}");
    assert_eq!(got["items"].as_array().unwrap().iter().map(|i| i["text"].as_str().unwrap()).collect::<Vec<_>>(), ["My\\ Docs/"]);
    let got = t.complete("ls s", 4).await.unwrap();
    assert!(got["items"].as_array().unwrap().iter().any(|i| i["text"] == "src/"), "{got}");
    let got = t.complete("ech", 3).await.unwrap();
    assert!(got["items"].as_array().unwrap().iter().any(|i| i["label"] == "echo"), "{got}");
    let dirs = t.dirs().await.unwrap();
    let names: Vec<&str> = dirs["dirs"].as_array().unwrap().iter().map(|d| d.as_str().unwrap()).collect();
    assert!(names.contains(&"src") && names.contains(&"My Docs"), "{dirs}");
    assert_eq!(t.branches().await.unwrap()["local"], json!([]), "not in a repository");

    if bash {
        // A ! that bash cannot expand: it says so and shows its prompt
        // again without any marker. The next command finds that out, sets
        // the shell back, and asks for Enter again.
        t.set_typed_stale(Duration::from_millis(500));
        let n = prompts(&page);
        assert_eq!(t.run("echo \"fix!it\""), None);
        tokio::time::sleep(Duration::from_millis(800)).await;
        page.until(1, |_| false).await;
        assert_eq!(prompts(&page), n, "bash gave no marker");
        let why = t.run("echo next").unwrap();
        assert!(why.contains("Enter again"), "{why}");
        prompted(&mut page, n + 1, "Ctrl+C").await;
        assert_eq!(t.run("echo next"), None);
        prompted(&mut page, n + 2, "next").await;
    }
    let n = prompts(&page);
    assert_eq!(t.run("cd repo"), None);
    prompted(&mut page, n + 1, "cd repo").await;
    assert_eq!(t.lock().branch, "feature/x");
    // A long one: the page sees it as running, then not.
    assert_eq!(t.run("sleep 1; echo slept"), None);
    assert!(page.until(10, |p| marks(p, "C").last().map(|c| c["command"] == "sleep 1; echo slept").unwrap_or(false)).await);
    let running = t.describe()["running"].clone();
    assert_eq!(running["command"], "sleep 1; echo slept", "{running}");
    assert!(running["seqStart"].as_u64().is_some() && running["cols"] == 100);
    assert!(page.until(10, |p| p.text().contains("slept")).await);
    prompted(&mut page, n + 2, "sleep").await;
    assert_eq!(t.describe()["running"], Value::Null);
    let branches = t.branches().await.unwrap();
    assert_eq!(branches["current"], "feature/x");
    t.close("Closed.").await;
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_over_the_socket_asks_about_danger() {
    let e = engine().await;
    let home = home();
    let Some(login) = login_shell(&e, &home).await else { return };
    let t = terminal_in(&e, &login, &home, 90, 25).await;
    let mut page = watched(&e, &t, 90, 25).await;
    prompted(&mut page, 1, "the start").await;
    std::fs::create_dir_all(home.join("junk")).unwrap();
    page.send(json!({"op": "run", "ch": 1, "command": "rm -rf junk"})).await;
    assert!(page.until(10, |p| p.msgs.iter().any(|m| m["op"] == "confirm")).await);
    let ask = page.msgs.iter().find(|m| m["op"] == "confirm").unwrap().clone();
    assert!(ask["what"].as_str().unwrap().contains("delete a directory"), "{ask}");
    assert_eq!(ask["everything"], false);
    assert_eq!(ask["command"], "rm -rf junk");
    assert!(ask["lost"].as_str().unwrap().contains("no undo"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(home.join("junk").exists(), "nothing ran before the yes");
    page.send(json!({"op": "run", "ch": 1, "command": "rm -rf junk", "confirmed": true})).await;
    prompted(&mut page, 2, "the confirmed delete").await;
    assert!(!home.join("junk").exists());
    assert!(!t.typed() && t.running().is_none(), "back at the prompt");
    page.send(json!({"op": "run", "ch": 1, "command": "rm -rf ~"})).await;
    assert!(page.until(10, |p| p.msgs.iter().filter(|m| m["op"] == "confirm").count() >= 2).await);
    assert_eq!(page.msgs.iter().rfind(|m| m["op"] == "confirm").unwrap()["everything"], true);
    page.send(json!({"op": "run", "ch": 1, "command": "sleep 2"})).await;
    assert!(page.until(10, |p| marks(p, "C").iter().any(|c| c["command"] == "sleep 2")).await);
    page.send(json!({"op": "run", "ch": 1, "command": "echo no"})).await;
    assert!(page.until(10, |p| p.msgs.iter().any(|m| m["op"] == "refused")).await);
    let refused = page.msgs.iter().find(|m| m["op"] == "refused").unwrap();
    assert!(refused["reason"].as_str().unwrap().contains("running"), "{refused}");
    assert_eq!(refused["command"], "echo no");
    t.close("Closed.").await;
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_feed_and_history_come_from_the_store() {
    let dir = data_dir();
    let e = Engine::new(&dir).unwrap();
    e.start_background();
    let home = home();
    let Some(login) = login_shell(&e, &home).await else { return };
    let t = terminal_in(&e, &login, &home, 80, 24).await;
    let id = t.id.to_string();
    let mut page = watched(&e, &t, 80, 24).await;
    prompted(&mut page, 1, "the start").await;
    for (i, cmd) in ["echo first", "seq 1 20000", "echo first", "echo last"].iter().enumerate() {
        assert_eq!(t.run(cmd), None, "{cmd}");
        prompted(&mut page, i + 2, cmd).await;
    }
    let rows = saved(&e, &t, 4).await;
    let (status, feed) = request(&e, "GET", &format!("/api/terminals/{id}/blocks?limit=60"), Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(feed["more"], false);
    let commands: Vec<&str> = feed["blocks"].as_array().unwrap().iter().map(|b| b["command"].as_str().unwrap()).collect();
    assert_eq!(commands, ["echo first", "seq 1 20000", "echo first", "echo last"]);
    let big = &feed["blocks"][1];
    let tail = output_of(big);
    assert_eq!(big["partial"], true);
    assert!(big["size"].as_u64().unwrap() > tail.len() as u64, "only its end");
    assert!(tail.ends_with(b"20000\r\n") && tail[0].is_ascii_digit(), "the end, from the start of a line: {:?}", String::from_utf8_lossy(&tail[..20]));
    assert_eq!(big["exitCode"], 0);
    assert_eq!(big["cols"], 80);
    let (_, two) = request(&e, "GET", &format!("/api/terminals/{id}/blocks?limit=2"), Value::Null).await;
    let commands: Vec<&str> = two["blocks"].as_array().unwrap().iter().map(|b| b["command"].as_str().unwrap()).collect();
    assert_eq!(commands, ["echo first", "echo last"]);
    assert_eq!(two["more"], true);
    let before = two["blocks"][0]["seqStart"].as_u64().unwrap();
    let (_, earlier) = request(&e, "GET", &format!("/api/terminals/{id}/blocks?before={before}"), Value::Null).await;
    let commands: Vec<&str> = earlier["blocks"].as_array().unwrap().iter().map(|b| b["command"].as_str().unwrap()).collect();
    assert_eq!(commands, ["echo first", "seq 1 20000"]);
    let (status, _) = request(&e, "GET", &format!("/api/terminals/{id}/blocks?limit=lots"), Value::Null).await;
    assert_eq!(status, 422);
    // Its whole output, as the terminal printed it.
    let seq = rows[1]["seqStart"].as_u64().unwrap();
    let r = tterm_engine::api::handle(&e, "GET", &format!("/api/terminals/{id}/blocks/{seq}/output"), b"").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.content_type, "application/octet-stream");
    assert!(r.body.starts_with(b"1\r\n2\r\n"), "{:?}", String::from_utf8_lossy(&r.body[..20.min(r.body.len())]));
    assert!(r.body.ends_with(b"20000\r\n"));
    let (_, history) = request(&e, "GET", &format!("/api/terminals/{id}/history"), Value::Null).await;
    let commands: Vec<&str> = history["commands"].as_array().unwrap().iter().map(|c| c["command"].as_str().unwrap()).collect();
    assert_eq!(commands, ["echo last", "echo first", "seq 1 20000"]);
    assert!(history["commands"].as_array().unwrap().iter().all(|c| c["here"] == true));
    let (status, got) = request(&e, "POST", &format!("/api/terminals/{id}/complete"), json!({"line": "ech", "cursor": 3})).await;
    assert_eq!(status, 200);
    assert!(!got["items"].as_array().unwrap().is_empty());
    let (status, _) = request(&e, "POST", &format!("/api/terminals/{id}/complete"), json!({"line": "ech"})).await;
    assert_eq!(status, 422);
    let (status, _) = request(&e, "POST", &format!("/api/terminals/{id}/complete"), json!({"line": "x".repeat(70_000), "cursor": 1})).await;
    assert_eq!(status, 422);
    let (status, dirs) = request(&e, "POST", &format!("/api/terminals/{id}/dirs"), json!({})).await;
    assert_eq!(status, 200);
    assert!(dirs["dirs"].as_array().unwrap().iter().any(|d| d == "repo"), "{dirs}");
    let nobody = Uuid::new_v4();
    for path in [format!("/api/terminals/{nobody}/blocks"), format!("/api/terminals/{nobody}/history"), format!("/api/terminals/{nobody}/blocks/1/output"), format!("/api/terminals/{nobody}")] {
        assert_eq!(request(&e, "GET", &path, Value::Null).await.0, 404, "{path}");
    }
    let (status, _) = request(&e, "POST", &format!("/api/terminals/{nobody}/branches"), json!({})).await;
    assert_eq!(status, 409);

    // The shell ends inside a command: that block ends with it.
    assert_eq!(t.run("exit 7"), None);
    assert!(page.until(15, |p| p.state().map(|s| s["state"] == "ended").unwrap_or(false)).await);
    let rows = saved(&e, &t, 5).await;
    assert_eq!(rows[4]["command"], "exit 7");
    assert_eq!(rows[4]["exitCode"], 7);
    let (status, _) = request(&e, "POST", &format!("/api/terminals/{id}/dirs"), json!({})).await;
    assert_eq!(status, 409, "an ended terminal lists nothing");
    let (_, feed) = request(&e, "GET", &format!("/api/terminals/{id}/blocks"), Value::Null).await;
    assert_eq!(feed["blocks"].as_array().unwrap().len(), 5, "an ended terminal keeps its feed");
    let home_seen = t.lock().home.clone();
    assert!(!home_seen.is_empty());

    // The next run of the app: the terminal is gone, its feed is not, and
    // its home comes along, so ~ reads as ~.
    e.terminals.stop_all("tTerm quit.").await;
    drop(page);
    drop(t);
    let again = Engine::new(&dir).unwrap();
    let (status, info) = request(&again, "GET", &format!("/api/terminals/{id}"), Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(info["state"], "gone");
    assert_eq!(info["home"], home_seen.as_str());
    assert_eq!(info["reason"], "The shell ended with code 7.");
    assert_eq!(info["machineId"], again.settings.lock().unwrap().machine_id.to_string());
    let (_, feed) = request(&again, "GET", &format!("/api/terminals/{id}/blocks"), Value::Null).await;
    assert_eq!(feed["blocks"].as_array().unwrap().len(), 5);
    let mut late = Page::new(&again);
    late.send(json!({"op": "attach", "ch": 3, "id": id, "after": null})).await;
    assert!(late.until(5, |p| p.msgs.iter().any(|m| m["op"] == "gone")).await);
    let gone = late.msgs.iter().find(|m| m["op"] == "gone").unwrap();
    assert_eq!(gone["terminal"]["state"], "gone");
    assert_eq!(gone["terminal"]["label"], format!("P/{}", again.machine_name));
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replay_inside_a_long_command_says_which_one() {
    let _turn = heavy();
    let e = engine().await;
    let home = home();
    let Some(login) = login_shell(&e, &home).await else { return };
    let t = terminal_in(&e, &login, &home, 80, 24).await;
    let mut page = watched(&e, &t, 80, 24).await;
    prompted(&mut page, 1, "the start").await;
    // More than a replay holds, then a pause: the replay starts inside it.
    assert_eq!(t.run("seq 1 400000; echo flooded; sleep 3"), None);
    assert!(page.until(30, |p| p.text().contains("400000\r\nflooded")).await);
    let mut fresh = Page::new(&e);
    fresh.send(json!({"op": "attach", "ch": 2, "id": t.id.to_string(), "after": null, "cols": 80, "rows": 24})).await;
    assert!(fresh.until(10, |p| p.msgs.iter().any(|m| m["op"] == "replayed")).await);
    let reset = fresh.msgs.iter().find(|m| m["op"] == "reset").unwrap();
    assert_eq!(reset["running"]["command"], "seq 1 400000; echo flooded; sleep 3", "{reset}");
    assert!(reset["running"]["seqStart"].as_u64().unwrap() <= reset["seq"].as_u64().unwrap());
    assert_eq!(fresh.msgs[0]["terminal"]["running"]["command"], "seq 1 400000; echo flooded; sleep 3");
    prompted(&mut page, 2, "the sleep").await;
    // The prompt after it is not inside it.
    let mut after = Page::new(&e);
    after.send(json!({"op": "attach", "ch": 2, "id": t.id.to_string(), "after": null})).await;
    assert!(after.until(10, |p| p.msgs.iter().any(|m| m["op"] == "replayed")).await);
    let reset = after.msgs.iter().find(|m| m["op"] == "reset").unwrap();
    assert_eq!(reset["running"]["command"], "seq 1 400000; echo flooded; sleep 3", "{reset}");
    assert!(reset["running"]["seqEnd"].as_u64().unwrap() > reset["seq"].as_u64().unwrap(), "{reset}");
    assert_eq!(after.msgs[0]["terminal"]["running"], Value::Null);
    t.close("Closed.").await;
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quitting_names_the_command_running() {
    let e = engine().await;
    let home = home();
    let Some(login) = login_shell(&e, &home).await else { return };
    let t = terminal_in(&e, &login, &home, 80, 24).await;
    let mut page = watched(&e, &t, 80, 24).await;
    prompted(&mut page, 1, "the start").await;
    assert!(e.terminals.busy().is_empty());
    // A builtin waiting for input: no program of its own in front.
    assert_eq!(t.run("read answer"), None);
    assert!(page.until(10, |p| !marks(p, "C").is_empty()).await);
    let busy = e.terminals.busy();
    assert_eq!(busy.len(), 1, "{busy:?}");
    assert_eq!(busy[0].1, "read answer");
    assert_eq!(busy[0].0, format!("P/{}", e.machine_name));
    page.keys(1, "yes\r").await;
    prompted(&mut page, 2, "the answer").await;
    assert!(e.terminals.busy().is_empty());
    if login.ends_with("bash") {
        // With its history off bash marks a command without its text: the
        // program in front names it then.
        assert_eq!(t.run("set +o history"), None);
        prompted(&mut page, 3, "history off").await;
        assert_eq!(t.run("sleep 5"), None);
        assert!(page.until(10, |p| marks(p, "C").len() >= 3).await);
        assert_eq!(marks(&page, "C").last().unwrap()["command"], "");
        let deadline = Instant::now() + Duration::from_secs(5);
        while e.terminals.busy().first().map(|b| b.1 != "sleep").unwrap_or(true) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(e.terminals.busy()[0].1, "sleep");
    }
    t.close("Closed.").await;
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quitting_keeps_what_ran_even_in_a_shell_deaf_to_the_hangup() {
    let dir = data_dir();
    let e = Engine::new(&dir).unwrap();
    let home = home();
    let Some(login) = login_shell(&e, &home).await else { return };
    let t = terminal_in(&e, &login, &home, 80, 24).await;
    let id = t.id.to_string();
    let mut page = watched(&e, &t, 80, 24).await;
    prompted(&mut page, 1, "the start").await;
    let pid_file = home.join("shell.pid");
    assert_eq!(t.run(&format!("trap '' HUP; echo $$ > '{}'", pid_file.display())), None);
    prompted(&mut page, 2, "the trap").await;
    let pid = std::fs::read_to_string(&pid_file).unwrap().trim().to_string();
    assert_eq!(t.run("sleep 30"), None);
    assert!(page.until(10, |p| marks(p, "C").iter().any(|c| c["command"] == "sleep 30")).await);
    let started = Instant::now();
    e.terminals.stop_all("tTerm quit.").await;
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    assert!(e.terminals.live().is_empty());
    // The shell is killed, not left behind.
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
    assert!(gone, "the shell {pid} lives on");
    // As the next run of the app finds it.
    let again = Engine::new(&dir).unwrap();
    let (_, info) = request(&again, "GET", &format!("/api/terminals/{id}"), Value::Null).await;
    assert_eq!(info["reason"], "tTerm quit.");
    let (_, feed) = request(&again, "GET", &format!("/api/terminals/{id}/blocks"), Value::Null).await;
    let commands: Vec<&str> = feed["blocks"].as_array().unwrap().iter().map(|b| b["command"].as_str().unwrap()).collect();
    assert_eq!(commands.len(), 2, "{commands:?}");
    assert_eq!(commands[1], "sleep 30", "the command running is kept too");
    let _ = std::fs::remove_dir_all(&home);
}

/// A bash 3.2, as macOS has it at /bin/bash: there, or where TTERM_BASH32
/// says (one built from Apple's sources, for checks on Linux).
fn bash_32() -> Option<String> {
    let mut candidates: Vec<String> = std::env::var("TTERM_BASH32").into_iter().collect();
    candidates.push("/bin/bash".into());
    candidates.into_iter().filter(|p| Path::new(p).is_file()).find(|p| {
        let out = std::process::Command::new(p).args(["-c", "echo ${BASH_VERSINFO[0]}"]).output();
        out.map(|o| String::from_utf8_lossy(&o.stdout).trim() == "3").unwrap_or(false)
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bash_3_2_marks_its_prompts_only() {
    let Some(bash32) = bash_32() else { return };
    let e = engine().await;
    let home = home();
    // The only bash on the PATH, as on a Mac without Homebrew's.
    let bin = home.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(&bash32, bin.join("bash")).unwrap();
    let login = bin.join("bash").to_string_lossy().to_string();
    let with_path = |terminal: bool| {
        let mut env = env_for(&home, &login, terminal);
        env.retain(|(k, _)| k != "PATH");
        env.push(("PATH".into(), format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", bin.display())));
        env
    };
    let plan = e.plan_for(&login, &with_path(false), &home).await;
    assert!(plan.markers && !plan.blocks, "{plan:?}");
    let planner = {
        let (e, login, home, env) = (e.clone(), login.clone(), home.clone(), with_path(false));
        async move { e.plan_for(&login, &env, &home).await }
    };
    let t = e.terminals.open(e.place(), planner, with_path(true), home.clone(), 80, 24, 24).await.unwrap();
    let mut page = watched(&e, &t, 80, 24).await;
    // No bracketed paste in bash 3.2: a moment for the line editor.
    async fn prompt(page: &mut Page, n: usize) {
        assert!(page.until(20, |p| prompts(p) >= n).await, "{:?}", page.text());
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    prompt(&mut page, 1).await;
    let first = marks(&page, "P")[0].clone();
    assert!(same_place(first["cwd"].as_str().unwrap(), &home), "a folder with a space: {first}");
    assert_eq!((t.describe()["markers"].clone(), t.describe()["blocks"].clone()), (json!(true), json!(false)));
    assert_eq!(t.run("echo x").as_deref(), Some("This shell does not mark where commands start, so it runs in the classic mode only."));
    page.keys(1, "cd repo\r").await;
    prompt(&mut page, 2).await;
    assert_eq!(marks(&page, "P").last().unwrap()["branch"], "feature/x");
    page.keys(1, " echo secret\r").await;
    prompt(&mut page, 3).await;
    page.keys(1, "false\r").await;
    prompt(&mut page, 4).await;
    assert_eq!(marks(&page, "P").last().unwrap()["code"], 1);
    page.keys(1, "fc -ln -10\r").await;
    prompt(&mut page, 5).await;
    let text = page.text();
    let listed = text.rsplit("fc -ln -10").next().unwrap();
    assert!(!listed.contains("secret"), "history skips it, as asked: {listed:?}");
    assert!(listed.contains("false"), "{listed:?}");
    assert!(!text.contains("not a valid identifier"), "{text:?}");
    assert!(marks(&page, "C").is_empty(), "no PS0 before 4.4: no command marks");
    t.close("Closed.").await;
    let feed = e.terminals.store.feed(&t.id.to_string(), None, 60).await.unwrap();
    assert!(feed["blocks"].as_array().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&home);
}
