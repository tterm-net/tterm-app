//! The app's updates (update.rs) against releases on this computer, over
//! TLS, the way tTerm for Mac meets them on GitHub: the list of releases,
//! the signed list of a release's files, the redirect to GitHub's storage.
//! tTerm.app here is a folder like the real one, its program a script that
//! says its version and notes when it is opened; it is put in place and
//! watched the way the app does it, with the folders swapped by Linux's
//! renameat2. The TLS is the link's own: it trusts the checks' CA through
//! SSL_CERT_FILE. That CA and its certificate for 127.0.0.1 are the agent's
//! checks' (agent/tests/update.rs), trusted by nothing else.

#![cfg(feature = "cloud")]

use base64::Engine as _;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once};
#[cfg(target_os = "linux")]
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tterm_engine::update::{self, Config, Phase, Updates, Wish};

const CA: &str = "MIIBvzCCAWWgAwIBAgIUXGszR3igCJjiRoBbGjG6ms7Fj3MwCgYIKoZIzj0EAwIwLDEqMCgGA1UEAwwhdHRlcm0tYWdlbnQgY2hlY2tzLCBub3QgYSByZWFsIENBMCAXDTI2MTAyNTE2MjczM1oYDzIxMjYxMDAxMTYyNzMzWjAsMSowKAYDVQQDDCF0dGVybS1hZ2VudCBjaGVja3MsIG5vdCBhIHJlYWwgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASMSOnL6AwJ2lKqDvL09TzD4GRCLPYEy274pRYGHcqJf/3Kc2BHGhST+fX0EEZFLSLIDjrxcZFAU3HMvGfsphgBo2MwYTAdBgNVHQ4EFgQURZRxQ2FXs6l3sbbG5dsIO11ifNswHwYDVR0jBBgwFoAURZRxQ2FXs6l3sbbG5dsIO11ifNswDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIhAKePYHuekiCz5q+lqJT8MnvZAJW6Jd5tjKvLHbZWxgGYAiALTKxFK4+98s4i4DxhCAXfdmxw4j0Gpr7c+wWVCRAJ+A==";
const SERVER_CERT: &str = "MIIB2DCCAX2gAwIBAgIUI48x/eOSAPobT9oO3x39BKmPRI4wCgYIKoZIzj0EAwIwLDEqMCgGA1UEAwwhdHRlcm0tYWdlbnQgY2hlY2tzLCBub3QgYSByZWFsIENBMCAXDTI2MTAyNTE2MjczM1oYDzIxMjYxMDAxMTYyNzMzWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATq1nzmGS3uhIVO9OrfKqhEWwlFygU0vjI6AVvkU4cjem0CjJdjD3L6UgWg2P78mi8yvgauA3wJRT1M4CkwpIcTo4GSMIGPMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUpRrIGH3I/i+Sw0sjozxOaSGnM6kwHwYDVR0jBBgwFoAURZRxQ2FXs6l3sbbG5dsIO11ifNswCgYIKoZIzj0EAwIDSQAwRgIhAPAhpt7Q/A4yRgL2Oubo0HYPDM9wpxVNk4dtwcmqg5pWAiEA3CxDBi8+96iy7t43Xo7deVuL8++Bgkdc9Dlz5cGSW0o=";
const SERVER_KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgza8dZJTfCqDxVhgUuqqdoSLI9lUpjt1YKYdPlPc2xKmhRANCAATq1nzmGS3uhIVO9OrfKqhEWwlFygU0vjI6AVvkU4cjem0CjJdjD3L6UgWg2P78mi8yvgauA3wJRT1M4CkwpIcT";

fn der(b64: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(b64).unwrap()
}

fn trust_the_checks_ca() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let lines: Vec<String> = CA.as_bytes().chunks(64).map(|c| String::from_utf8_lossy(c).to_string()).collect();
        let path = std::env::temp_dir().join(format!("tterm-app-update-ca-{}.pem", std::process::id()));
        std::fs::write(&path, format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))).unwrap();
        std::env::set_var("SSL_CERT_FILE", &path);
        // No proxy of this computer's between the checks and their site.
        for name in ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"] {
            std::env::remove_var(name);
        }
    });
}

fn folder(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tterm-app-update-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("Applications")).unwrap();
    std::fs::create_dir_all(dir.join("data")).unwrap();
    dir
}

fn plist(identifier: &str, version: &str) -> String {
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n\t<key>CFBundleExecutable</key>\n\t<string>tterm</string>\n\t<key>CFBundleIdentifier</key>\n\t<string>{identifier}</string>\n\t<key>CFBundleShortVersionString</key>\n\t<string>{version}</string>\n</dict>\n</plist>\n")
}

/// tTerm.app in `dir`: its Info.plist, and a program that says `says` when
/// asked its version and, opened, notes it in `dir`/opened-VERSION; asked
/// to watch, it stays a few seconds, as a watcher would.
fn bundle(dir: &Path, identifier: &str, version: &str, says: &str) -> PathBuf {
    let app = dir.join("tTerm.app");
    std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    std::fs::write(app.join("Contents/Info.plist"), plist(identifier, version)).unwrap();
    let exe = app.join("Contents/MacOS/tterm");
    let script = format!("#!/bin/sh\nif [ \"$1\" = --version ]; then echo {says}; exit 0; fi\necho \"$*\" >> \"$(dirname \"$0\")/../../../opened-{version}\"\ncase \"$1\" in --finish-update|--watch-start) sleep 8 ;; esac\n");
    std::fs::write(&exe, script).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    app
}

/// What the release build makes of a tTerm.app: tar.gz of it alone.
fn archive(make: impl FnOnce(&Path)) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!("tterm-app-update-pack-{}-{}", std::process::id(), uuid_like()));
    std::fs::create_dir_all(&dir).unwrap();
    make(&dir);
    let out = std::process::Command::new("tar").arg("-czf").arg("-").arg("-C").arg(&dir).args(std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name())).output().unwrap();
    assert!(out.status.success());
    let _ = std::fs::remove_dir_all(&dir);
    out.stdout
}

fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    N.fetch_add(1, Ordering::SeqCst).to_string()
}

#[derive(Clone)]
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn ok(body: impl Into<Vec<u8>>) -> Answer {
    Answer { status: 200, headers: Vec::new(), body: body.into() }
}

fn redirect(to: String) -> Answer {
    Answer { status: 302, headers: vec![("Location".into(), to)], body: Vec::new() }
}

/// A release of the app, made the way the release build makes one.
struct Release {
    version: String,
    pair: Ed25519KeyPair,
    public: [u8; 32],
    file: Vec<u8>,
}

impl Release {
    fn new(version: &str, file: Vec<u8>) -> Release {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
        Release { version: version.to_string(), pair, public, file }
    }

    /// A good one: tTerm `version`, whole.
    fn tterm(version: &str) -> Release {
        let file = archive(|dir| {
            bundle(dir, update::BUNDLE_ID, version, version);
        });
        Release::new(version, file)
    }

    fn manifest(&self, version: &str, file: &[u8]) -> Vec<u8> {
        let m = json!({"product": "tterm-app", "version": version, "files": {"macos": {"name": "tTerm.app.tar.gz", "size": file.len(), "sha256": update::sha256_hex(file)}}});
        format!("{}\n", serde_json::to_string_pretty(&m).unwrap()).into_bytes()
    }

    fn signature(&self, manifest: &[u8]) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.encode(self.pair.sign(manifest).as_ref()).into_bytes()
    }

    /// GitHub as the app meets it: the list of releases, the agent's among
    /// them, and each file sent on to the storage, a token in its address.
    fn site(&self, port: u16) -> HashMap<String, Answer> {
        let base = format!("https://127.0.0.1:{port}");
        let tag = format!("v{}", self.version);
        let names = ["tterm-app.json", "tterm-app.json.sig", "tTerm.app.tar.gz", "tTerm.dmg"];
        let assets: Vec<_> = names.iter().map(|n| json!({"name": n, "browser_download_url": format!("{base}/download/{tag}/{n}")})).collect();
        let list = json!([
            {"tag_name": "agent-v9.9.9", "draft": false, "prerelease": false, "assets": []},
            {"tag_name": tag, "draft": false, "prerelease": false, "html_url": "https://elsewhere.example/phish", "assets": assets},
            {"tag_name": "v0.4.0", "draft": false, "prerelease": false, "assets": []},
        ]);
        let manifest = self.manifest(&self.version, &self.file);
        let mut site = HashMap::new();
        site.insert("/releases".to_string(), ok(list.to_string()));
        for name in names {
            site.insert(format!("/download/{tag}/{name}"), redirect(format!("{base}/storage/{name}?token=SECRET")));
        }
        site.insert("/storage/tterm-app.json.sig".to_string(), ok(self.signature(&manifest)));
        site.insert("/storage/tterm-app.json".to_string(), ok(manifest));
        site.insert("/storage/tTerm.app.tar.gz".to_string(), ok(self.file.clone()));
        site
    }
}

struct Site {
    port: u16,
    /// What was asked, with the User-Agent (the checks on Linux read it).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    asked: Arc<Mutex<Vec<String>>>,
    /// Its pages, which a check may change: a release taken back.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pages: Arc<Mutex<HashMap<String, Answer>>>,
}

impl Site {
    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }
}

async fn read_head<S: AsyncReadExt + Unpin>(stream: &mut S) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.ok()? == 0 || head.len() > 16 * 1024 {
            return None;
        }
        head.push(byte[0]);
    }
    Some(String::from_utf8_lossy(&head).to_string())
}

fn header(head: &str, name: &str) -> String {
    head.lines().filter_map(|l| l.split_once(':')).find(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()).unwrap_or_default()
}

async fn site(make: impl FnOnce(u16) -> HashMap<String, Answer>) -> Site {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let pages = Arc::new(Mutex::new(make(port)));
    let asked = Arc::new(Mutex::new(Vec::new()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(der(SERVER_CERT))], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der(SERVER_KEY))))
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let log = asked.clone();
    let served = pages.clone();
    tokio::spawn(async move {
        let pages = served;
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, pages, log) = (acceptor.clone(), pages.clone(), log.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let Some(head) = read_head(&mut tls).await else { return };
                let target = head.split_whitespace().nth(1).unwrap_or("").to_string();
                log.lock().unwrap().push(format!("{target} {}", header(&head, "user-agent")));
                let path = target.split('?').next().unwrap_or("");
                let answer = pages.lock().unwrap().get(path).cloned().unwrap_or(Answer { status: 404, headers: Vec::new(), body: b"no".to_vec() });
                let mut out = format!("HTTP/1.1 {} Answer\r\nConnection: close\r\nContent-Length: {}\r\n", answer.status, answer.body.len());
                for (k, v) in &answer.headers {
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                out.push_str("\r\n");
                let _ = tls.write_all(out.as_bytes()).await;
                let _ = tls.write_all(&answer.body).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Site { port, asked, pages }
}

fn config(site: &Site, key: [u8; 32], current: &str, app: &Path, data: &Path) -> Config {
    Config { releases: site.url("/releases"), key: Some(key), current: current.to_string(), bundle: Some(app.to_path_buf()), data_dir: data.to_path_buf(), anywhere: true }
}

fn version_of(app: &Path) -> String {
    update::read_plist(app).unwrap().version
}

/// Whether the phase is Ready with `version`, unpacked at `staged`.
#[cfg(target_os = "linux")]
fn ready_at(phase: &Phase, version: &str, staged: &Path) -> bool {
    matches!(phase, Phase::Ready { version: v, staged: s, digest } if v == version && s == staged && digest.len() == 64)
}

/// The files kept in the app's data.
fn kept(data: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(data).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).filter(|n| n.contains(".tar.gz")).collect();
    names.sort();
    names
}

/// What is beside the app: its own name, and nothing else of the updater's.
fn beside(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir.join("Applications")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    names.sort();
    names
}

/// Waits for a line in `path`: the checks' programs write one each time
/// they are run (the shell makes the file before it writes in it).
#[cfg(target_os = "linux")]
async fn wait_for(path: &Path) -> bool {
    for _ in 0..100 {
        if std::fs::read(path).is_ok_and(|b| b.ends_with(b"\n")) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

// On Linux: there an app is opened as its program is, not by
// LaunchServices, and the checks' tTerm.app needs no code signature.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn from_a_look_to_the_new_version_up() {
    trust_the_checks_ca();
    let dir = folder("whole");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    let release = Release::tterm("0.5.1");
    let site = site(|port| release.site(port)).await;
    let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    assert_eq!(updates.now().phase, Phase::Idle);
    assert!(updates.ready().is_none());

    updates.look().await;
    let staged = apps.join(".tTerm-0.5.1.update");
    assert!(ready_at(&updates.now().phase, "0.5.1", &staged), "{:?}", updates.now().phase);
    assert_eq!(kept(&data), ["update-0.5.1.tar.gz"], "its file kept in the app's data");
    assert_eq!(updates.now().next.as_deref(), Some("0.5.1"));
    assert!(updates.now().checked_at.is_some() && updates.now().ready_at.is_some());
    assert_eq!(version_of(&staged), "0.5.1");
    assert_eq!(beside(&dir), [".tTerm-0.5.1.update", "tTerm.app"], "unpacked under a name no app has");
    let asked = site.asked.lock().unwrap().clone();
    assert!(asked.contains(&format!("/storage/tTerm.app.tar.gz?token=SECRET tTerm/{} (update)", tterm_engine::VERSION)), "{asked:?}");
    // Looked again: the same version, not downloaded again.
    let before = site.asked.lock().unwrap().len();
    updates.look().await;
    let again: Vec<String> = site.asked.lock().unwrap()[before..].to_vec();
    assert!(again.iter().all(|a| !a.contains("tar.gz")), "{again:?}");
    assert!(matches!(updates.now().phase, Phase::Ready { .. }));

    // What's new: GitHub's page of the release, the address made here, not
    // the one in the list.
    let engine = tterm_engine::Engine::new(&dir.join("engine")).unwrap();
    let said = updates.json(&engine);
    assert_eq!(said["state"], "ready");
    assert_eq!(said["next"], "0.5.1");
    assert_eq!(said["notes"], "https://github.com/tterm-net/tterm-app/releases/tag/v0.5.1");
    assert_eq!(said["mode"], "auto");
    assert_eq!(said["version"], "0.5.0");

    // Restart: in place, and the version before watches from beside it.
    let version = updates.install(true, false).unwrap();
    assert_eq!(version, "0.5.1");
    assert_eq!(version_of(&app), "0.5.1");
    assert_eq!(version_of(&staged), "0.5.0");
    assert!(matches!(updates.now().phase, Phase::Installing(_)));
    let file = update::trial_file(&data);
    let trial = update::read_trial(&file).unwrap();
    assert_eq!((trial.from.as_str(), trial.to.as_str(), trial.relaunch, trial.ok), ("0.5.0", "0.5.1", true, false));
    assert!(trial.watcher.is_some(), "its watcher written down");
    // The watcher was started from the version before: here its script
    // notes what it was asked, and the watcher's part is done below.
    assert!(wait_for(&apps.join("opened-0.5.0")).await);
    let asked = std::fs::read_to_string(apps.join("opened-0.5.0")).unwrap();
    assert_eq!(asked.trim(), format!("--finish-update {} {}", file.display(), std::process::id()));

    let watched = file.clone();
    let watcher = std::thread::spawn(move || update::finish_with(&watched, 0, Duration::from_secs(1), Duration::from_secs(20)));
    assert!(wait_for(&apps.join("opened-0.5.1")).await, "the new version opened");
    // The new version starts: it is told it was updated, and says it is up;
    // watched already, it starts no watcher of its own.
    std::fs::remove_file(apps.join("opened-0.5.0")).unwrap();
    let new = Updates::new(config(&site, release.public, "0.5.1", &app, &data));
    assert_eq!(new.now().updated, Some(update::Updated { from: "0.5.0".into(), to: "0.5.1".into() }));
    assert_eq!(update::read_trial(&file).unwrap().pid, Some(std::process::id() as i32));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!apps.join("opened-0.5.0").exists(), "no second watcher");
    new.up();
    assert_eq!(watcher.join().unwrap(), 0, "the watcher let it be");
    assert!(update::read_trial(&file).unwrap().ok);
    assert_eq!(new.json(&engine)["updated"]["to"], "0.5.1");
    // Shown: not again.
    new.seen();
    assert!(!file.exists());
    assert_eq!(new.json(&engine)["updated"], serde_json::Value::Null);
    // What is left beside it goes, and its file.
    new.tidy();
    assert_eq!(beside(&dir), ["opened-0.5.1", "tTerm.app"]);
    assert!(kept(&data).is_empty());
    // And there is nothing newer than itself.
    new.look().await;
    assert_eq!(new.now().phase, Phase::Idle);
    let _ = std::fs::remove_dir_all(&dir);
}

// On Linux: there an app is opened as its program is, not by
// LaunchServices, and the checks' tTerm.app needs no code signature.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_version_that_does_not_come_up_goes_and_is_not_taken_again() {
    trust_the_checks_ca();
    let dir = folder("back");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    let release = Release::tterm("0.5.1");
    let site = site(|port| release.site(port)).await;
    let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    updates.look().await;
    // At Quit: in place, nobody watching yet.
    updates.install(false, true).unwrap();
    assert!(!apps.join("opened-0.5.0").exists(), "no watcher at Quit");
    let file = update::trial_file(&data);
    assert!(update::read_trial(&file).unwrap().background);
    // Watched, and the new version never says it is up.
    let watched = file.clone();
    let code = tokio::task::spawn_blocking(move || update::finish_with(&watched, 0, Duration::from_secs(1), Duration::from_secs(2))).await.unwrap();
    assert_eq!(code, 4);
    assert_eq!(version_of(&app), "0.5.0", "the version before is back");
    assert_eq!(std::fs::read_to_string(apps.join("opened-0.5.1")).unwrap().trim(), "--background", "it was opened, in the background");
    assert!(wait_for(&apps.join("opened-0.5.0")).await, "and the version before opened again");
    assert_eq!(beside(&dir), ["opened-0.5.0", "opened-0.5.1", "tTerm.app"], "the version that did not come up is gone");
    assert!(update::read_trial(&file).unwrap().rolled_back);
    assert_eq!(update::skipped(&data, "0.5.0").as_deref(), Some("0.5.1"));

    // The version before, started again, says so in Settings, and takes
    // only a version after the one that did not come up.
    let before = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    let note = before.now().note.unwrap();
    assert!(note.contains("tTerm 0.5.1 did not start on this Mac, so tTerm 0.5.0 came back"), "{note}");
    assert!(!file.exists());
    before.look().await;
    assert_eq!(before.now().phase, Phase::Idle);
    assert!(before.now().note.is_some(), "the note stays");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn what_is_not_as_signed_or_not_tterm_is_not_taken() {
    trust_the_checks_ca();
    // Each release, and what Settings says of it.
    type Make = Box<dyn Fn(&Release, u16) -> HashMap<String, Answer>>;
    let cases: Vec<(&str, Make)> = vec![
        ("is not the file its signed list names", Box::new(|r: &Release, port| {
            let mut s = r.site(port);
            let mut other = r.file.clone();
            let last = other.len() - 1;
            other[last] ^= 1;
            s.insert("/storage/tTerm.app.tar.gz".into(), ok(other));
            s
        })),
        ("the signature does not check", Box::new(|r: &Release, port| {
            let mut s = r.site(port);
            let other = Release::tterm("0.5.1");
            let manifest = r.manifest("0.5.1", &r.file);
            s.insert("/storage/tterm-app.json.sig".into(), ok(other.signature(&manifest)));
            s
        })),
        ("the signed list is for another version", Box::new(|r: &Release, port| {
            let mut s = r.site(port);
            let old = r.manifest("0.5.0", &r.file);
            s.insert("/storage/tterm-app.json.sig".into(), ok(r.signature(&old)));
            s.insert("/storage/tterm-app.json".into(), ok(old));
            s
        })),
    ];
    for (said, make) in cases {
        let dir = folder("unsigned");
        let (apps, data) = (dir.join("Applications"), dir.join("data"));
        let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
        let release = Release::tterm("0.5.1");
        let site = site(|port| make(&release, port)).await;
        let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
        updates.look().await;
        match updates.now().phase {
            Phase::Failed(why) => assert!(why.contains(said), "{why}"),
            other => panic!("{said}: {other:?}"),
        }
        assert_eq!(beside(&dir), ["tTerm.app"], "{said}: nothing left beside the app");
        assert!(updates.install(false, false).is_err());
        assert_eq!(version_of(&app), "0.5.0");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Signed, and still not taken: not tTerm, not this version, a program
    // that says another, more than the app in the archive, no app at all.
    let unpacked: Vec<(&str, Vec<u8>)> = vec![
        ("it is not tTerm but com.example.other", archive(|d| {
            bundle(d, "com.example.other", "0.5.1", "0.5.1");
        })),
        ("it says it is version 0.5.2", archive(|d| {
            bundle(d, update::BUNDLE_ID, "0.5.2", "0.5.2");
        })),
        // On a Mac the checks' tTerm.app is not signed as tTerm, so its
        // program is never run there.
        (if cfg!(target_os = "macos") { "its code signature does not check" } else { "its program says it is \"0.4.0\"" }, archive(|d| {
            bundle(d, update::BUNDLE_ID, "0.5.1", "0.4.0");
        })),
        ("not tTerm.app alone", archive(|d| {
            bundle(d, update::BUNDLE_ID, "0.5.1", "0.5.1");
            std::fs::write(d.join("extra"), "x").unwrap();
        })),
        ("not tTerm.app alone", archive(|d| {
            std::fs::create_dir_all(d.join("Other.app/Contents")).unwrap();
        })),
        ("not tTerm.app alone", archive(|d| {
            std::os::unix::fs::symlink("/Applications/Safari.app", d.join("tTerm.app")).unwrap();
        })),
    ];
    for (said, file) in unpacked {
        let dir = folder("not-tterm");
        let (apps, data) = (dir.join("Applications"), dir.join("data"));
        let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
        let release = Release::new("0.5.1", file);
        let site = site(|port| release.site(port)).await;
        let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
        updates.look().await;
        match updates.now().phase {
            Phase::Failed(why) => assert!(why.contains(said) && why.contains("tTerm stays as it is"), "{said}: {why}"),
            other => panic!("{said}: {other:?}"),
        }
        assert_eq!(beside(&dir), ["tTerm.app"], "{said}: nothing left beside the app");
        assert!(kept(&data).is_empty(), "{said}: nor its file");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn only_over_https() {
    trust_the_checks_ca();
    let dir = folder("https");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    let release = Release::tterm("0.5.1");
    let site = site(|port| {
        let mut s = release.site(port);
        s.insert("/download/v0.5.1/tTerm.app.tar.gz".into(), redirect(format!("http://127.0.0.1:{port}/storage/tTerm.app.tar.gz?token=SECRET")));
        s
    })
    .await;
    let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    updates.look().await;
    match updates.now().phase {
        Phase::Failed(why) => {
            assert!(why.contains(&format!("not over HTTPS: http://127.0.0.1:{}/storage/tTerm.app.tar.gz", site.port)), "{why}");
            assert!(!why.contains("SECRET"), "the token stays out: {why}");
        }
        other => panic!("{other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn where_it_cannot_update_itself_it_says_why() {
    let dir = folder("where");
    let data = dir.join("data");
    let plain = |bundle: Option<PathBuf>| Config { releases: "https://127.0.0.1:9/releases".into(), key: None, current: "0.5.0".into(), bundle, data_dir: data.clone(), anywhere: true };
    let built = Updates::new(plain(None));
    assert!(matches!(built.now().phase, Phase::Unavailable { ref why, movable: false } if why.contains("runs from a build")));
    let translocated = Updates::new(plain(Some("/private/var/folders/x/T/AppTranslocation/1234/d/tTerm.app".into())));
    assert_eq!(translocated.now().phase, Phase::Unavailable { why: update::FROM_DISK_IMAGE.into(), movable: true });
    let engine = tterm_engine::Engine::new(&dir.join("engine")).unwrap();
    assert_eq!(translocated.json(&engine)["movable"], true);
    assert_eq!(translocated.json(&engine)["state"], "unavailable");
    // Another system than macOS, without the checks' word for it.
    let elsewhere = Updates::new(Config { anywhere: false, ..plain(Some(dir.join("Applications/tTerm.app"))) });
    if cfg!(target_os = "macos") {
        assert!(!matches!(elsewhere.now().phase, Phase::Unavailable { ref why, .. } if why.contains("Only tTerm for Mac")));
    } else {
        assert!(matches!(elsewhere.now().phase, Phase::Unavailable { ref why, movable: false } if why.contains("Only tTerm for Mac")));
    }
    // A folder this account cannot change (root changes any).
    if unsafe { libc::geteuid() } != 0 {
        let locked = dir.join("locked");
        let app = bundle(&locked, update::BUNDLE_ID, "0.5.0", "0.5.0");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
        let cannot = Updates::new(plain(Some(app)));
        assert!(matches!(cannot.now().phase, Phase::Unavailable { ref why, movable: false } if why.contains("cannot change")), "{:?}", cannot.now().phase);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_app_hears_restart_and_the_mode_is_saved() {
    let dir = folder("wish");
    let engine = tterm_engine::Engine::new(&dir.join("engine")).unwrap();
    let updates = Updates::new(Config { releases: String::new(), key: None, current: "0.5.0".into(), bundle: None, data_dir: dir.join("data"), anywhere: true });
    assert!(!updates.wish(Wish::Restart), "no app listens");
    let mut heard = updates.listen();
    assert!(updates.wish(Wish::Restart));
    assert!(updates.wish(Wish::Move));
    assert_eq!(heard.recv().await, Some(Wish::Restart));
    assert_eq!(heard.recv().await, Some(Wish::Move));
    assert_eq!(updates.json(&engine)["mode"], "auto", "Update by itself, unless told otherwise");
    updates.set_mode(&engine, "ask").unwrap();
    assert_eq!(updates.json(&engine)["mode"], "ask");
    assert_eq!(tterm_engine::settings::Settings::load(&dir.join("engine")).unwrap().updates, "ask", "on disk");
    assert!(updates.set_mode(&engine, "sometimes").is_err());
    assert_eq!(updates.json(&engine)["mode"], "ask");
    let _ = std::fs::remove_dir_all(&dir);
}


#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_release_taken_back_goes_and_one_left_ready_is_not_downloaded_again() {
    trust_the_checks_ca();
    let dir = folder("taken-back");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    let release = Release::tterm("0.5.1");
    let site = site(|port| release.site(port)).await;
    let staged = apps.join(".tTerm-0.5.1.update");

    // Ready, and the app quits without Restart (Ask me first): its file,
    // kept in the app's data, is taken again at the next start, not
    // downloaded again, and unpacked and checked again.
    let first = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    first.look().await;
    assert!(ready_at(&first.now().phase, "0.5.1", &staged));
    let downloads = |site: &Site| site.asked.lock().unwrap().iter().filter(|a| a.contains("tTerm.app.tar.gz")).count();
    assert_eq!(downloads(&site), 2, "the redirect and the storage");
    std::fs::write(staged.join("Contents/left"), "left by someone").unwrap();
    let again = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    again.look().await;
    assert!(ready_at(&again.now().phase, "0.5.1", &staged));
    assert_eq!(downloads(&site), 2, "not downloaded again");
    assert!(!staged.join("Contents/left").exists(), "unpacked again, not taken as it was");
    // …unless the file kept is not the one its signed list names any more.
    let kept_file = update::archive_file(&data, "0.5.1");
    let mut bytes = std::fs::read(&kept_file).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&kept_file, bytes).unwrap();
    let third = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    third.look().await;
    assert!(ready_at(&third.now().phase, "0.5.1", &staged));
    assert_eq!(downloads(&site), 4, "downloaded again");
    assert_eq!(std::fs::read(&kept_file).unwrap(), release.file, "and kept again");

    // Changed beside the app since it was checked: it does not go in, and
    // is taken again from its file.
    std::fs::write(staged.join("Contents/MacOS/tterm"), "#!/bin/sh\necho 0.5.1\n").unwrap();
    let why = third.install(false, false).unwrap_err();
    assert!(why.contains("changed since it was checked"), "{why}");
    assert_eq!(version_of(&app), "0.5.0");
    assert!(!staged.exists() && !update::trial_file(&data).exists());
    assert!(matches!(third.now().phase, Phase::Failed(_)));
    third.look().await;
    assert!(ready_at(&third.now().phase, "0.5.1", &staged));
    assert_eq!(downloads(&site), 4, "from its file");

    // Taken back on GitHub (a pre-release now): it goes from beside the app,
    // its file too, and nothing goes in at the next quit.
    let release_list = "[{\"tag_name\": \"v0.5.1\", \"draft\": false, \"prerelease\": true, \"assets\": []}]";
    site.pages.lock().unwrap().insert("/releases".into(), ok(release_list));
    third.look().await;
    assert_eq!(third.now().phase, Phase::Idle);
    assert_eq!(third.now().next, None);
    assert!(!staged.exists(), "gone from beside the app");
    assert!(kept(&data).is_empty(), "and its file");
    assert!(third.install(false, false).is_err());
    assert_eq!(version_of(&app), "0.5.0");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_newer_version_taken_back_is_not_ready_while_an_older_one_comes() {
    trust_the_checks_ca();
    let dir = folder("older-listed");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    let release = Release::tterm("0.5.2");
    let site = site(|port| release.site(port)).await;
    let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    updates.look().await;
    assert!(ready_at(&updates.now().phase, "0.5.2", &apps.join(".tTerm-0.5.2.update")));
    // 0.5.2 made a pre-release; 0.5.1 listed, its file not to be had.
    let older = archive(|d| {
        bundle(d, update::BUNDLE_ID, "0.5.1", "0.5.1");
    });
    let manifest = release.manifest("0.5.1", &older);
    let base = site.url("");
    let names = ["tterm-app.json", "tterm-app.json.sig", "tTerm.app.tar.gz"];
    let assets: Vec<_> = names.iter().map(|n| json!({"name": n, "browser_download_url": format!("{base}/older/{n}")})).collect();
    let list = json!([
        {"tag_name": "v0.5.2", "draft": false, "prerelease": true, "assets": []},
        {"tag_name": "v0.5.1", "draft": false, "prerelease": false, "assets": assets},
    ]);
    {
        let mut pages = site.pages.lock().unwrap();
        pages.insert("/releases".into(), ok(list.to_string()));
        pages.insert("/older/tterm-app.json.sig".into(), ok(release.signature(&manifest)));
        pages.insert("/older/tterm-app.json".into(), ok(manifest));
    }
    updates.look().await;
    match updates.now().phase {
        Phase::Failed(why) => assert!(why.contains("Could not take tTerm 0.5.1") && why.contains("HTTP 404"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(!apps.join(".tTerm-0.5.2.update").exists(), "0.5.2 gone from beside the app");
    assert!(kept(&data).is_empty(), "and its file");
    assert!(updates.install(false, false).is_err(), "nothing goes in at the quit");
    assert_eq!(version_of(&app), "0.5.0");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn what_was_left_beside_the_app_is_neither_run_nor_taken() {
    trust_the_checks_ca();
    let dir = folder("planted");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    let release = Release::tterm("0.5.1");
    let site = site(|port| release.site(port)).await;
    // A tTerm 0.5.1 put beside the app under the name the next version
    // waits under, by something else: its program notes it was run.
    let elsewhere = dir.join("elsewhere");
    let planted = bundle(&elsewhere, update::BUNDLE_ID, "0.5.1", "0.5.1");
    let ran = dir.join("planted-ran");
    let exe = planted.join("Contents/MacOS/tterm");
    std::fs::write(&exe, format!("#!/bin/sh\necho \"$*\" >> {}\necho 0.5.1\n", ran.display())).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(planted.join("Contents/PLANTED"), "not from the signed file").unwrap();
    std::fs::rename(&planted, apps.join(".tTerm-0.5.1.update")).unwrap();

    let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    updates.look().await;
    assert!(ready_at(&updates.now().phase, "0.5.1", &apps.join(".tTerm-0.5.1.update")));
    assert!(!ran.exists(), "what was left there never ran");
    assert_eq!(site.asked.lock().unwrap().iter().filter(|a| a.contains("tTerm.app.tar.gz")).count(), 2, "the signed file was downloaded");
    updates.install(false, false).unwrap();
    assert!(!app.join("Contents/PLANTED").exists(), "what went in is the signed file's");
    assert_eq!(version_of(&app), "0.5.1");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_version_comes_back_once_whoever_watches() {
    trust_the_checks_ca();
    let release = Release::tterm("0.5.1");
    for round in 0..6 {
        let dir = folder(&format!("two-watchers-{round}"));
        let (apps, data) = (dir.join("Applications"), dir.join("data"));
        let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
        let site = site(|port| release.site(port)).await;
        let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
        updates.look().await;
        updates.install(false, false).unwrap();
        let file = update::trial_file(&data);
        // A start that ended before it was up, watched twice.
        let mut gone = std::process::Command::new("true").spawn().unwrap();
        let pid = gone.id() as i32;
        gone.wait().unwrap();
        let trial = update::read_trial(&file).unwrap();
        update::write_trial(&file, &update::Trial { pid: Some(pid), ..trial }).unwrap();
        let (a, b) = (file.clone(), file.clone());
        let one = std::thread::spawn(move || update::finish_started(&a, pid, Duration::from_secs(5)));
        if round % 2 == 1 {
            std::thread::sleep(Duration::from_millis(30));
        }
        let two = std::thread::spawn(move || update::finish_started(&b, pid, Duration::from_secs(5)));
        let mut codes = [one.join().unwrap(), two.join().unwrap()];
        codes.sort();
        assert_eq!(codes, [0, 4], "round {round}: one of them brings it back");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(version_of(&app), "0.5.0", "round {round}");
        assert_eq!(beside(&dir), ["opened-0.5.0", "tTerm.app"], "round {round}");
        assert_eq!(std::fs::read_to_string(apps.join("opened-0.5.0")).unwrap().lines().count(), 1, "round {round}: opened once");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_trial_of_another_place_is_left_alone() {
    trust_the_checks_ca();
    let dir = folder("other-place");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    let release = Release::tterm("0.5.1");
    let site = site(|port| release.site(port)).await;
    let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    updates.look().await;
    updates.install(false, false).unwrap();
    let file = update::trial_file(&data);
    let trial = update::read_trial(&file).unwrap();
    // The same version run from elsewhere (the disk image), and an older
    // copy: neither takes the trial, nor ends it.
    let copies = dir.join("Volumes");
    let copy = bundle(&copies, update::BUNDLE_ID, "0.5.1", "0.5.1");
    let same = Updates::new(config(&site, release.public, "0.5.1", &copy, &data));
    assert_eq!(same.now().updated, None);
    same.up();
    let older = Updates::new(config(&site, release.public, "0.4.9", &copy, &data));
    older.seen();
    assert_eq!(update::read_trial(&file), Some(trial.clone()), "as it was");
    assert!(apps.join(".tTerm-0.5.1.update").exists(), "the version before stays");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!apps.join("opened-0.5.0").exists(), "and does not watch them");
    // Up in its place, and not shown yet: the copy of the same version
    // elsewhere neither shows it nor ends it.
    let up = update::Trial { ok: true, ..trial };
    update::write_trial(&file, &up).unwrap();
    let same = Updates::new(config(&site, release.public, "0.5.1", &copy, &data));
    assert_eq!(same.now().updated, None);
    same.seen();
    assert_eq!(update::read_trial(&file), Some(up), "as it was");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_pid_written_down_is_taken_only_for_that_process() {
    trust_the_checks_ca();
    let dir = folder("pids");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    let release = Release::tterm("0.5.1");
    let site = site(|port| release.site(port)).await;
    let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    updates.look().await;
    updates.install(false, false).unwrap();
    let file = update::trial_file(&data);
    // The pids written down are another process's by now (the Mac started
    // again since): a process alive, but not the one that started then.
    let mut other = std::process::Command::new("sleep").arg("30").spawn().unwrap();
    let pid = other.id() as i32;
    let then = Some("1.000001".to_string());
    assert_ne!(update::started_at(pid), then);
    let trial = update::read_trial(&file).unwrap();
    update::write_trial(&file, &update::Trial { pid: Some(pid), started: then.clone(), watcher: Some(pid), watcher_started: then.clone(), ..trial.clone() }).unwrap();
    // The new version starting takes the trial, and is watched.
    let new = Updates::new(config(&site, release.public, "0.5.1", &app, &data));
    let me = std::process::id() as i32;
    let taken = update::read_trial(&file).unwrap();
    assert_eq!((taken.pid, taken.started.clone()), (Some(me), update::started_at(me)));
    assert!(wait_for(&apps.join("opened-0.5.0")).await, "watched");
    assert_ne!(taken.watcher, Some(pid));
    // Not up, and the pid written down another's: that process is left
    // alone, and the version before comes back.
    update::write_trial(&file, &update::Trial { pid: Some(pid), started: then, ..taken }).unwrap();
    let watched = file.clone();
    let code = tokio::task::spawn_blocking(move || update::finish_started(&watched, pid, Duration::from_secs(2))).await.unwrap();
    assert_eq!(code, 4);
    assert_eq!(version_of(&app), "0.5.0");
    assert!(other.try_wait().unwrap().is_none(), "the other process still runs");
    let _ = other.kill();
    let _ = other.wait();
    drop(new);
    // And pids that no process has (0, -1) are not taken at all.
    std::fs::write(&file, serde_json::to_vec(&json!({"from": "0.5.0", "to": "0.5.1", "app": app, "old": apps.join(".tTerm-0.5.1.update"), "at": 1, "pid": -1, "watcher": 0})).unwrap()).unwrap();
    let read = update::read_trial(&file).unwrap();
    assert_eq!((read.pid, read.watcher), (None, None));
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_second_copy_of_the_app_leaves_the_version_before_alone() {
    trust_the_checks_ca();
    let dir = folder("second-copy");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    let release = Release::tterm("0.5.1");
    let site = site(|port| release.site(port)).await;
    let first = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    let second = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    first.look().await;
    first.install(false, false).unwrap();
    // The second copy of 0.5.0, still running, looks: the app in its place
    // is not it any more, and what waits beside it is the version before.
    second.look().await;
    assert_eq!(second.now().phase, Phase::Idle);
    assert_eq!(version_of(&apps.join(".tTerm-0.5.1.update")), "0.5.0", "the version before, as it was");
    // Had it been changed all the same, nothing comes back in its place.
    std::fs::write(apps.join(".tTerm-0.5.1.update/Contents/Info.plist"), plist(update::BUNDLE_ID, "0.5.1")).unwrap();
    let file = update::trial_file(&data);
    let watched = file.clone();
    let mut gone = std::process::Command::new("true").spawn().unwrap();
    let pid = gone.id() as i32;
    gone.wait().unwrap();
    let code = tokio::task::spawn_blocking(move || update::finish_started(&watched, pid, Duration::from_secs(2))).await.unwrap();
    assert_eq!(code, 3, "not swapped");
    assert_eq!(version_of(&app), "0.5.1");
    assert!(apps.join(".tTerm-0.5.1.update").exists(), "nothing thrown away");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_start_that_ends_right_after_it_wrote_its_pid_is_not_waited_for() {
    trust_the_checks_ca();
    let dir = folder("ends-at-once");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    // The version before, opened again, notes whether the trial file's lock
    // was let go before it was opened.
    let exe = app.join("Contents/MacOS/tterm");
    let lock = data.join("update.lock");
    std::fs::write(&exe, format!("#!/bin/sh\ncase \"$1\" in --version) echo 0.5.0; exit 0 ;; --*) exit 0 ;; esac\nif flock -n {} true; then echo free; else echo held; fi >> {}\n", lock.display(), apps.join("opened-0.5.0").display())).unwrap();
    let release = Release::tterm("0.5.1");
    let site = site(|port| release.site(port)).await;
    let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    updates.look().await;
    updates.install(true, false).unwrap();
    let file = update::trial_file(&data);
    // Restart: a start of the new version wrote its pid and ended at once.
    let mut gone = std::process::Command::new("true").spawn().unwrap();
    let pid = gone.id() as i32;
    let started = update::started_at(pid);
    gone.wait().unwrap();
    let trial = update::read_trial(&file).unwrap();
    update::write_trial(&file, &update::Trial { pid: Some(pid), started, ..trial }).unwrap();
    std::fs::remove_file(apps.join("opened-0.5.0")).ok();
    let watched = file.clone();
    let at = std::time::Instant::now();
    let code = tokio::task::spawn_blocking(move || update::finish_with(&watched, 0, Duration::from_secs(1), Duration::from_secs(20))).await.unwrap();
    assert_eq!(code, 4);
    assert!(at.elapsed() < Duration::from_secs(5), "not the whole wait: {:?}", at.elapsed());
    assert!(!apps.join("opened-0.5.1").exists(), "written down already: not opened again");
    assert_eq!(version_of(&app), "0.5.0");
    assert!(wait_for(&apps.join("opened-0.5.0")).await);
    assert_eq!(std::fs::read_to_string(apps.join("opened-0.5.0")).unwrap().trim(), "free", "opened once the lock was let go");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_version_put_in_place_at_quit_is_watched_when_it_starts() {
    trust_the_checks_ca();
    let dir = folder("at-quit");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    let release = Release::tterm("0.5.1");
    let site = site(|port| release.site(port)).await;
    let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    updates.look().await;
    // Quit, Update by itself: in place, nobody watching.
    updates.install(false, false).unwrap();
    let file = update::trial_file(&data);
    assert!(!update::read_trial(&file).unwrap().relaunch);

    // The new version starts by itself: the version before, beside it, is
    // started to watch this start, with its pid, and written down.
    let new = Updates::new(config(&site, release.public, "0.5.1", &app, &data));
    let me = std::process::id();
    assert!(wait_for(&apps.join("opened-0.5.0")).await, "the watcher of the start");
    assert_eq!(std::fs::read_to_string(apps.join("opened-0.5.0")).unwrap().trim(), format!("--watch-start {} {me}", file.display()));
    let trial = update::read_trial(&file).unwrap();
    assert_eq!(trial.pid, Some(me as i32));
    assert!(trial.watcher.is_some());
    // Started again before it said it was up, the start before gone: no
    // second watcher while the first one watches.
    std::fs::remove_file(apps.join("opened-0.5.0")).unwrap();
    let mut gone = std::process::Command::new("true").spawn().unwrap();
    let dead = gone.id() as i32;
    gone.wait().unwrap();
    update::write_trial(&file, &update::Trial { pid: Some(dead), ..trial }).unwrap();
    let _again = Updates::new(config(&site, release.public, "0.5.1", &app, &data));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!apps.join("opened-0.5.0").exists(), "this start is watched already");
    assert_eq!(update::read_trial(&file).unwrap().pid, Some(me as i32), "and is the one on trial");
    // Up: the watcher lets it be, and the version before goes a moment later.
    new.up();
    let watched = file.clone();
    assert_eq!(update::finish_started(&watched, me as i32, Duration::from_secs(5)), 0);
    let staged = apps.join(".tTerm-0.5.1.update");
    for _ in 0..80 {
        if !staged.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!staged.exists(), "the version before is gone from beside the app");
    assert_eq!(version_of(&app), "0.5.1");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_start_that_ends_before_it_is_up_brings_the_version_before_back() {
    trust_the_checks_ca();
    let dir = folder("start-ends");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    let release = Release::tterm("0.5.1");
    let site = site(|port| release.site(port)).await;
    let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    updates.look().await;
    updates.install(false, false).unwrap();
    let file = update::trial_file(&data);
    // The new version's process: started, written down, and gone before it
    // said it was up.
    let mut gone = std::process::Command::new("true").spawn().unwrap();
    let pid = gone.id() as i32;
    gone.wait().unwrap();
    let trial = update::read_trial(&file).unwrap();
    update::write_trial(&file, &update::Trial { pid: Some(pid), ..trial }).unwrap();
    let watched = file.clone();
    let code = tokio::task::spawn_blocking(move || update::finish_started(&watched, pid, Duration::from_secs(20))).await.unwrap();
    assert_eq!(code, 4, "not the whole wait: it ended");
    assert_eq!(version_of(&app), "0.5.0", "the version before is back");
    assert!(wait_for(&apps.join("opened-0.5.0")).await, "and opened");
    assert_eq!(update::skipped(&data, "0.5.0").as_deref(), Some("0.5.1"));

    // The start it watches gone, but another one written down since,
    // alive: that one is watched, and is up.
    let trial = update::Trial { rolled_back: false, ok: false, pid: Some(std::process::id() as i32), ..update::read_trial(&file).unwrap() };
    update::write_trial(&file, &trial).unwrap();
    let watched = file.clone();
    let watcher = std::thread::spawn(move || update::finish_started(&watched, pid, Duration::from_secs(20)));
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(!watcher.is_finished(), "still watching, the start after");
    update::write_trial(&file, &update::Trial { ok: true, ..trial }).unwrap();
    assert_eq!(watcher.join().unwrap(), 0);
    assert_eq!(version_of(&app), "0.5.0", "nothing swapped");

    // A trial file gone while it watches is taken for up: a running app is
    // never put aside on a doubt.
    let trial = update::Trial { rolled_back: false, ok: false, pid: Some(std::process::id() as i32), ..update::read_trial(&file).unwrap() };
    update::write_trial(&file, &trial).unwrap();
    let watched = file.clone();
    let watcher = std::thread::spawn(move || update::finish_started(&watched, std::process::id() as i32, Duration::from_secs(20)));
    tokio::time::sleep(Duration::from_millis(500)).await;
    std::fs::remove_file(&file).unwrap();
    assert_eq!(watcher.join().unwrap(), 0);
    assert_eq!(version_of(&app), "0.5.0", "nothing swapped");
    // And none at all: nothing to watch.
    assert_eq!(update::finish_started(&file, std::process::id() as i32, Duration::from_secs(5)), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_version_before_opened_from_beside_the_app_opens_the_app_instead() {
    let dir = std::env::temp_dir().join(format!("tterm-app-update-{}-aside", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tTerm.app/Contents/MacOS")).unwrap();
    std::fs::create_dir_all(dir.join(".tTerm-0.5.1.update/Contents/MacOS")).unwrap();
    assert_eq!(update::moved_aside(&dir.join(".tTerm-0.5.1.update/Contents/MacOS/tterm")), Some(dir.join("tTerm.app")));
    assert_eq!(update::moved_aside(&dir.join("tTerm.app/Contents/MacOS/tterm")), None);
    assert_eq!(update::moved_aside(Path::new("/usr/local/bin/tterm")), None);
    let _ = std::fs::remove_dir_all(&dir);
    // Signed with tTerm's certificate, and nothing else: not Apple's anchor
    // alone, which every Apple developer's certificate has.
    assert_eq!(update::requirement(), "identifier \"net.tterm.desktop\" and certificate leaf = H\"92afcfee87ea405a6754d73095c1446ad46d8ce2\"");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn two_copies_ready_and_one_goes_in_the_other_touches_nothing() {
    trust_the_checks_ca();
    let dir = folder("two-ready");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    let release = Release::tterm("0.5.1");
    let site = site(|port| release.site(port)).await;
    // Two copies of 0.5.0 at the same place, both with 0.5.1 ready.
    let first = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    let second = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    first.look().await;
    second.look().await;
    let staged = apps.join(".tTerm-0.5.1.update");
    assert!(ready_at(&first.now().phase, "0.5.1", &staged) && ready_at(&second.now().phase, "0.5.1", &staged));
    first.install(false, false).unwrap();
    assert_eq!(version_of(&staged), "0.5.0");
    // The second one, at its quit, its Restart or by itself: nothing of it
    // goes in, and nothing beside the app goes.
    let why = second.install(false, false).unwrap_err();
    assert!(why.contains("Another tTerm has put a new version in place"), "{why}");
    assert_eq!(second.now().phase, Phase::Idle);
    assert_eq!(version_of(&staged), "0.5.0", "the version before, as it was");
    assert_eq!(version_of(&app), "0.5.1");
    second.tidy();
    second.look().await;
    assert_eq!(second.now().phase, Phase::Idle);
    assert_eq!(version_of(&staged), "0.5.0", "neither tidied nor taken");
    // Nor is anything unpacked over it while the new version is on trial.
    let err = update::stage(&release.file, &app, "0.5.1", &data).unwrap_err();
    assert!(err.contains("another tTerm is updating itself"), "{err}");
    assert_eq!(version_of(&staged), "0.5.0");
    assert_eq!(beside(&dir), [".tTerm-0.5.1.update", "tTerm.app"], "nothing of the unpacking left");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn only_the_version_before_watches_and_a_trial_that_cannot_end_well_ends() {
    trust_the_checks_ca();
    let dir = folder("not-the-one-before");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    let release = Release::tterm("0.5.1");
    let site = site(|port| release.site(port)).await;
    let updates = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    updates.look().await;
    updates.install(false, false).unwrap();
    let file = update::trial_file(&data);
    // Where the version before waits, a 0.5.1 now.
    let staged = apps.join(".tTerm-0.5.1.update");
    std::fs::remove_dir_all(&staged).unwrap();
    let elsewhere = dir.join("elsewhere");
    std::fs::rename(bundle(&elsewhere, update::BUNDLE_ID, "0.5.1", "0.5.1"), &staged).unwrap();
    // The new version starts: what is there is not the version before, and
    // does not watch it.
    let new = Updates::new(config(&site, release.public, "0.5.1", &app, &data));
    assert_eq!(new.now().updated, Some(update::Updated { from: "0.5.0".into(), to: "0.5.1".into() }));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!apps.join("opened-0.5.1").exists(), "no watcher");
    assert_eq!(update::read_trial(&file).unwrap().watcher, None);
    // Not up: the version before cannot come back, and the trial is over;
    // what is in place stays, and no start after is watched by what is not
    // the version before.
    let mut gone = std::process::Command::new("true").spawn().unwrap();
    let pid = gone.id() as i32;
    gone.wait().unwrap();
    let watched = file.clone();
    let code = tokio::task::spawn_blocking(move || update::finish_started(&watched, pid, Duration::from_secs(2))).await.unwrap();
    assert_eq!(code, 3);
    assert!(!file.exists(), "the trial is over");
    assert_eq!(version_of(&app), "0.5.1");
    assert!(staged.exists(), "nothing thrown away");
    let again = Updates::new(config(&site, release.public, "0.5.1", &app, &data));
    assert_eq!(again.now().updated, None);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!apps.join("opened-0.5.1").exists(), "no watcher started, and this one still runs: not opened again");
    drop(new);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_copy_under_another_name_in_the_same_folder_touches_nothing() {
    trust_the_checks_ca();
    let dir = folder("keep-both");
    let (apps, data) = (dir.join("Applications"), dir.join("data"));
    let app = bundle(&apps, update::BUNDLE_ID, "0.5.0", "0.5.0");
    // Finder's Keep Both: tTerm.app and tTerm 2.app, the same data.
    let other_dir = dir.join("other");
    let other = apps.join("tTerm 2.app");
    std::fs::rename(bundle(&other_dir, update::BUNDLE_ID, "0.5.0", "0.5.0"), &other).unwrap();
    let release = Release::tterm("0.5.1");
    let site = site(|port| release.site(port)).await;
    let first = Updates::new(config(&site, release.public, "0.5.0", &app, &data));
    let second = Updates::new(config(&site, release.public, "0.5.0", &other, &data));
    first.look().await;
    second.look().await;
    let staged = apps.join(".tTerm-0.5.1.update");
    assert!(ready_at(&first.now().phase, "0.5.1", &staged) && ready_at(&second.now().phase, "0.5.1", &staged), "one folder for both");
    first.install(false, false).unwrap();
    assert_eq!(version_of(&staged), "0.5.0");
    // tTerm 2.app, at its quit or its Restart, tidying, looking: nothing of
    // the first one's version before goes.
    let why = second.install(false, false).unwrap_err();
    assert!(why.contains("Another tTerm has put a new version in place"), "{why}");
    assert_eq!(second.now().phase, Phase::Idle);
    second.tidy();
    second.look().await;
    assert_eq!(second.now().phase, Phase::Idle);
    assert_eq!(version_of(&staged), "0.5.0", "the version before, as it was");
    assert_eq!((version_of(&app), version_of(&other)), ("0.5.1".to_string(), "0.5.0".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}
