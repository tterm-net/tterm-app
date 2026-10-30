//! tTerm for Mac updates itself (from 0.5.0), the way tterm-agent does
//! (agent/src/update.rs): a new version comes from tTerm's releases on
//! GitHub, where the release build signs the list of its files,
//! tterm-app.json, with the release key, the one the agent's releases are
//! signed with. The app takes a version only when that signature checks
//! against the public half built into it (agent/release-key.pub), and the
//! file against the list. GitHub decides only whether there is a new version
//! and which: it can hold one back, never make one up. "What's new" goes to
//! the release's page on GitHub, an address made here, not taken from the
//! list.
//!
//! What it takes is tTerm.app itself, in a tar.gz. It is unpacked next to
//! the app, on the same disk, under a name that is no app to Finder or to the
//! login item (.tTerm-0.5.1.update), and checked there: its Info.plist says
//! it is tTerm and this version, for a macOS this Mac has; its code
//! signature is whole and tTerm's (codesign, against `requirement`); and
//! only then its program runs, to say this version (--version). Then it is
//! ready, and the page and the menus say so: Restart to update. What was
//! checked is written down (`tree_digest`), and it goes in only as it was:
//! it may wait there for days. Nothing found beside the app is taken or run
//! unless it was unpacked here from the file its signed list names; that
//! file waits in the app's data (update-0.5.1.tar.gz), so that a start after
//! does not download it again. A version ready that is no longer the newest
//! GitHub lists (made a pre-release, or deleted) is not ready any more.
//!
//! It goes in place in one step: the two folders swap (renamex_np with
//! RENAME_SWAP), so the app's place never holds half an app. The version
//! before stays in the other folder until the new one has started. The new
//! one writes its pid in the trial file as it starts (`claim`, before its
//! window), and the version before, run from where it is now, watches it:
//! --finish-update after Restart, which opens the new one first;
//! --watch-start when it went in as tTerm quit and starts by itself. One
//! that does not say it is up (`up`) within UP_WITHIN, or whose start ends
//! before, goes, and the one before comes back; that version is not taken
//! again. Once it is up, the version before goes from beside it, so that
//! nothing that followed the folder there (the Dock) opens it; one opened
//! there all the same opens the app in its place (`moved_aside`). Whatever
//! changes the trial file holds its lock (update.lock): a version comes back
//! once, whoever watches.
//!
//! The watcher is always the version before, so what it does is a contract
//! between versions: --finish-update and --watch-start, --version, the trial
//! file (update.json: from, to, app, old, pid and started, watcher and
//! watcherStarted, ok, rolledBack) and its lock stay as they are. A pid is
//! taken only with the start written down with it: after a restart of the
//! Mac it is another process's.
//!
//! When it goes in: when the person says so (Restart to update, in the page,
//! in the menu bar, in tTerm's menu), after the question Quit asks when
//! terminals would end. With "Update by itself" (Settings, the default) also
//! when tTerm quits, and while its window is closed with nothing running on
//! this Mac; with "Ask me first" only when the person says so. That part is
//! the app's (app/src/updates.rs): it knows the window and the quitting.
//!
//! Where it cannot: on another system than macOS, in a build that is not
//! tTerm.app, and where it cannot write. It says why there; from the disk
//! image, or a copy macOS runs from elsewhere (translocated), it offers to
//! move itself to Applications.
//!
//! GitHub is reached the way tTerm Web's hub is (link.rs): the same TLS,
//! with the roots built in and the system's own, and the same proxy, if
//! this computer has one (proxy.rs). Only over HTTPS, redirects included.

use crate::{proxy, Engine};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::CString;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Notify};

/// Where the releases are listed: the app's and the agent's share the
/// repository; the app's tags are v0.5.1, the agent's agent-v0.14.1.
pub const RELEASES: &str = "https://api.github.com/repos/tterm-net/tterm-app/releases?per_page=100";
pub const TAG: &str = "v";
/// The page of a release, for What's new.
pub const RELEASE_PAGE: &str = "https://github.com/tterm-net/tterm-app/releases/tag/v";
/// The list of a release's files and its signature, among its files.
pub const MANIFEST: &str = "tterm-app.json";
pub const SIGNATURE: &str = "tterm-app.json.sig";
/// What the signed list says it is the list of: not the agent's.
pub const PRODUCT: &str = "tterm-app";
/// The app's file in the list: one for every Mac, Intel and Apple silicon.
pub const PLATFORM: &str = "macos";
pub const BUNDLE_ID: &str = "net.tterm.desktop";
pub const APP_NAME: &str = "tTerm.app";

/// The public half of the release key, as hex: the agent's (the same key
/// signs both). It never changes: apps and agents out there know only this.
pub const PUBLIC_KEY_HEX: &str = include_str!("../../agent/release-key.pub");

/// The SHA-1 of tTerm's own certificate, the one the release build signs
/// with (macos-cert.sha1). A version ready must be signed with it: then
/// macOS takes it for the same app, and what the person allowed stays
/// allowed. Moving to an Apple Developer ID, the version before the move
/// adds its Team ID to `requirement` (anchor apple generic and certificate
/// leaf[subject.OU] = "…"), never Apple's anchor alone: every Apple
/// developer's certificate has that one.
pub const CERT_SHA1: &str = include_str!("../../macos-cert.sha1");

/// What codesign checks a version ready against, and the version before,
/// before it watches.
pub fn requirement() -> String {
    format!("identifier \"{BUNDLE_ID}\" and certificate leaf = H\"{}\"", CERT_SHA1.trim())
}

/// The first look a while after the start, so that the rest comes up first;
/// then every few hours, as the agent.
pub const FIRST_LOOK: Duration = Duration::from_secs(120);
pub const LOOK_EVERY: Duration = Duration::from_secs(6 * 3600);
/// Check now looks again only this long after the last look: GitHub answers
/// 60 an hour to an address.
pub const CHECK_GAP: Duration = Duration::from_secs(30);

/// The app's file, at most: about 15 megabytes now.
pub const FILE_MAX: u64 = 128 * 1024 * 1024;
const LIST_MAX: u64 = 2 * 1024 * 1024;
const MANIFEST_MAX: u64 = 64 * 1024;
const SIGNATURE_MAX: u64 = 1024;
/// GitHub sends a release's files on to its storage: one redirect, a few
/// allowed.
const REDIRECTS_MAX: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const SMALL_TIMEOUT: Duration = Duration::from_secs(60);
/// The whole file, on a slow line too.
const FILE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Unpacking, codesign, and the new program saying its version.
const TOOL_TIME: Duration = Duration::from_secs(120);
const PROBE_TIME: Duration = Duration::from_secs(15);

/// The app before quits within this (its terminals end in 6 s at most).
pub const QUIT_WITHIN: Duration = Duration::from_secs(30);
/// The new version says it is up within this, once opened.
pub const UP_WITHIN: Duration = Duration::from_secs(45);
/// What changes the trial file waits this long, at most, for another that
/// does: a version coming back takes a few seconds.
const LOCK_WAIT: Duration = Duration::from_secs(20);

/// What the page and the menus are told while tTerm cannot update itself
/// from where it runs, and moving it helps.
pub const FROM_DISK_IMAGE: &str = "tTerm runs from the disk image. Move it to Applications, and it updates itself.";

// ------------------------------------------------------------- releases

/// A version as numbers: "0.5.1" → [0, 5, 1]; None for anything else.
pub fn version(text: &str) -> Option<Vec<u64>> {
    let parts: Option<Vec<u64>> = text.split('.').map(|p| if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) { p.parse::<u64>().ok() } else { None }).collect();
    parts.filter(|p| p.len() == 3)
}

/// Whether `candidate` is newer than `current`.
pub fn newer(candidate: &str, current: &str) -> bool {
    match (version(candidate), version(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

/// A release in GitHub's list, what the app reads of it.
#[derive(Debug, Deserialize)]
pub struct Listed {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
}

/// A release newer than this app: its version, and where each of its files
/// is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub files: HashMap<String, String>,
}

impl Release {
    fn url(&self, name: &str) -> Result<&str, String> {
        self.files.get(name).map(String::as_str).ok_or_else(|| format!("release {} has no {name:?}", self.version))
    }
}

/// The newest of the app's releases in GitHub's list, if newer than
/// `newer_than` and it has its list of files and their signature. Drafts,
/// pre-releases and the agent's releases are not taken.
pub fn pick(list: &[Listed], newer_than: &str) -> Option<Release> {
    let mut best: Option<(Vec<u64>, Release)> = None;
    for release in list {
        if release.draft || release.prerelease {
            continue;
        }
        let Some(v) = release.tag_name.strip_prefix(TAG) else { continue };
        let Some(numbers) = version(v) else { continue };
        if !newer(v, newer_than) || best.as_ref().is_some_and(|(b, _)| *b >= numbers) {
            continue;
        }
        let files: HashMap<String, String> = release.assets.iter().map(|a| (a.name.clone(), a.browser_download_url.clone())).collect();
        if !files.contains_key(MANIFEST) || !files.contains_key(SIGNATURE) {
            continue;
        }
        best = Some((numbers, Release { version: v.to_string(), files }));
    }
    best.map(|(_, r)| r)
}

/// What the signed list says of the app's file: its name among the
/// release's files, its size and its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// Checks the signature over the list as it came, byte for byte, and only
/// then reads it: the app's list, for `version_wanted`, and its file.
pub fn verify(manifest: &[u8], signature: &[u8], key: &[u8; 32], version_wanted: &str) -> Result<Wanted, String> {
    use base64::Engine as _;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(String::from_utf8_lossy(signature).trim())
        .map_err(|_| "the signature is not base64".to_string())?;
    UnparsedPublicKey::new(&ED25519, key).verify(manifest, &sig).map_err(|_| "the signature does not check".to_string())?;
    let m: Value = serde_json::from_slice(manifest).map_err(|_| "the signed list is not understood".to_string())?;
    if m.get("product").and_then(Value::as_str) != Some(PRODUCT) {
        return Err("the signed list is not tTerm's app's".into());
    }
    if m.get("version").and_then(Value::as_str) != Some(version_wanted) {
        return Err("the signed list is for another version".into());
    }
    let file = m.get("files").and_then(|f| f.get(PLATFORM)).ok_or_else(|| "the signed list has no file for a Mac".to_string())?;
    let name = file.get("name").and_then(Value::as_str).unwrap_or("");
    let size = file.get("size").and_then(Value::as_u64).unwrap_or(0);
    let sha256 = file.get("sha256").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
    let plain = !name.is_empty() && !name.starts_with('.') && name.ends_with(".tar.gz") && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if !plain || size == 0 || size > FILE_MAX || sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("the signed list's file for a Mac is not one".into());
    }
    Ok(Wanted { name: name.to_string(), size, sha256 })
}

pub fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// The public key built in; None if release-key.pub holds no key.
pub fn public_key() -> Option<[u8; 32]> {
    key_from_hex(PUBLIC_KEY_HEX)
}

fn key_from_hex(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    (key != [0u8; 32]).then_some(key)
}

/// A client for each request, by its address.
pub type Clients = dyn Fn(&reqwest::Url) -> Result<reqwest::Client, String> + Send + Sync;

/// The way to GitHub: the link's TLS, HTTPS only, redirects followed by
/// `get`, and the proxy the link would take to that host.
pub fn clients(user_agent: String, env: HashMap<String, String>, system: Option<proxy::System>) -> impl Fn(&reqwest::Url) -> Result<reqwest::Client, String> + Send + Sync {
    move |url: &reqwest::Url| {
        let host = url.host_str().unwrap_or("").trim_start_matches('[').trim_end_matches(']');
        let port = url.port_or_known_default().unwrap_or(443);
        let mut builder = reqwest::Client::builder()
            .use_preconfigured_tls((*crate::link::tls_config()).clone())
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .user_agent(user_agent.clone())
            .no_proxy();
        if let Some(p) = proxy::choose(host, port, true, &env, system.as_ref())? {
            let mut via = reqwest::Proxy::all(format!("http://{}", p.name())).map_err(|e| format!("the proxy {}: {}", p.name(), why(e)))?;
            if let Some((user, password)) = &p.login {
                via = via.basic_auth(user, password);
            }
            builder = builder.proxy(via);
        }
        builder.build().map_err(why)
    }
}

/// The app's clients: through the proxy the environment names, or the
/// system's.
async fn app_clients() -> impl Fn(&reqwest::Url) -> Result<reqwest::Client, String> + Send + Sync {
    let vars: Vec<(String, String)> = std::env::vars().collect();
    let env = proxy::from_environment(&vars);
    let system = if env.is_empty() { proxy::system().await } else { None };
    clients(format!("tTerm/{} (update)", crate::VERSION), env, system)
}

/// What reqwest says went wrong, with what lies under it, and without the
/// address: the caller says it, without its query (GitHub's storage puts a
/// signed token there).
fn why(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut text = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(s) = source {
        text.push_str(": ");
        text.push_str(&s.to_string());
        source = s.source();
    }
    text
}

/// An address as it is said: without its query.
fn shown(url: &reqwest::Url) -> String {
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    format!("{}://{}{port}{}", url.scheme(), url.host_str().unwrap_or(""), url.path())
}

/// What is at `url`, at most `max` bytes, over HTTPS only, following the
/// redirects GitHub gives (to its storage, for a release's files).
pub async fn get(clients: &Clients, url: &str, accept: &str, max: u64, timeout: Duration) -> Result<Vec<u8>, String> {
    let mut url = reqwest::Url::parse(url).map_err(|_| format!("not an address: {url:?}"))?;
    for _ in 0..=REDIRECTS_MAX {
        let at = shown(&url);
        if url.scheme() != "https" {
            return Err(format!("not over HTTPS: {at}"));
        }
        let client = clients(&url)?;
        let mut response = client
            .get(url.clone())
            .header(reqwest::header::ACCEPT, accept)
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| format!("{at}: {}", why(e)))?;
        let status = response.status();
        if status.is_redirection() {
            let location = response.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok());
            let next = location.and_then(|l| url.join(l).ok());
            url = next.ok_or_else(|| format!("{at}: HTTP {}, and no address to go on to", status.as_u16()))?;
            continue;
        }
        if !status.is_success() {
            return Err(format!("{at}: HTTP {}", status.as_u16()));
        }
        if response.content_length().is_some_and(|n| n > max) {
            return Err(format!("{at}: larger than expected"));
        }
        let mut data = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| format!("{at}: {}", why(e)))? {
            if (data.len() + chunk.len()) as u64 > max {
                return Err(format!("{at}: larger than expected"));
            }
            data.extend_from_slice(&chunk);
        }
        return Ok(data);
    }
    Err(format!("{}: too many redirects", shown(&url)))
}

/// A newer version, its signed list checked: what to download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub version: String,
    pub wanted: Wanted,
    pub url: String,
}

/// A version newer than `newer_than` among the releases listed at
/// `releases`, its signed list checked.
pub async fn find(clients: &Clients, releases: &str, newer_than: &str, key: &[u8; 32]) -> Result<Option<Found>, String> {
    let list = get(clients, releases, "application/vnd.github+json", LIST_MAX, SMALL_TIMEOUT).await?;
    let list: Vec<Listed> = serde_json::from_slice(&list).map_err(|_| "GitHub's list of releases is not understood".to_string())?;
    let Some(release) = pick(&list, newer_than) else { return Ok(None) };
    let binary = "application/octet-stream";
    let manifest = get(clients, release.url(MANIFEST)?, binary, MANIFEST_MAX, SMALL_TIMEOUT).await?;
    let signature = get(clients, release.url(SIGNATURE)?, binary, SIGNATURE_MAX, SMALL_TIMEOUT).await?;
    let wanted = verify(&manifest, &signature, key, &release.version).map_err(|why| format!("version {}: {why}", release.version))?;
    let url = release.url(&wanted.name)?.to_string();
    Ok(Some(Found { version: release.version, wanted, url }))
}

/// The file `found` names, checked against its signed list: a gzip.
pub async fn download(clients: &Clients, found: &Found) -> Result<Vec<u8>, String> {
    let file = get(clients, &found.url, "application/octet-stream", found.wanted.size, FILE_TIMEOUT).await?;
    if file.len() as u64 != found.wanted.size || sha256_hex(&file) != found.wanted.sha256 {
        return Err(format!("version {}: {} is not the file its signed list names", found.version, found.wanted.name));
    }
    if !file.starts_with(&[0x1f, 0x8b]) {
        return Err(format!("version {}: {} is not a tar.gz", found.version, found.wanted.name));
    }
    Ok(file)
}

// --------------------------------------------------------------- the app

/// The app's bundle, from where its program is:
/// …/tTerm.app/Contents/MacOS/tterm. None for a build run from elsewhere.
pub fn bundle_of(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    if macos.file_name()? != "MacOS" {
        return None;
    }
    let contents = macos.parent()?;
    if contents.file_name()? != "Contents" {
        return None;
    }
    let bundle = contents.parent()?;
    if bundle.extension()? != "app" {
        return None;
    }
    Some(bundle.to_path_buf())
}

/// A string of an XML Info.plist, as Tauri writes it: the <string> right
/// after its <key>.
pub fn plist_string(xml: &str, key: &str) -> Option<String> {
    let needle = format!("<key>{key}</key>");
    let at = xml.find(&needle)? + needle.len();
    let rest = xml[at..].trim_start().strip_prefix("<string>")?;
    let end = rest.find("</string>")?;
    let text = &rest[..end];
    (!text.contains('<')).then(|| text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&"))
}

/// What a bundle's Info.plist says: its identifier, version and program,
/// and the macOS it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plist {
    pub identifier: String,
    pub version: String,
    pub executable: String,
    pub minimum_system: Option<String>,
}

pub fn read_plist(bundle: &Path) -> Result<Plist, String> {
    let path = bundle.join("Contents").join("Info.plist");
    let mut text = String::new();
    std::fs::File::open(&path).and_then(|f| f.take(1024 * 1024).read_to_string(&mut text)).map_err(|e| format!("its Info.plist: {e}"))?;
    let get = |key: &str| plist_string(&text, key).ok_or_else(|| format!("its Info.plist has no {key}"));
    let executable = get("CFBundleExecutable")?;
    let plain = !executable.is_empty() && !executable.starts_with('.') && executable.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if !plain {
        return Err("its Info.plist names no plain program".into());
    }
    Ok(Plist { identifier: get("CFBundleIdentifier")?, version: get("CFBundleShortVersionString")?, executable, minimum_system: plist_string(&text, "LSMinimumSystemVersion") })
}

/// A macOS version as numbers: "13.6.1" → [13, 6, 1], "14.0" → [14, 0].
pub fn system_version(text: &str) -> Option<Vec<u64>> {
    let parts: Option<Vec<u64>> = text.trim().split('.').map(|p| if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) { p.parse::<u64>().ok() } else { None }).collect();
    parts.filter(|p| !p.is_empty() && p.len() <= 4)
}

/// Whether a Mac with macOS `this` is older than `needs`: 13.6 than 14.0.
pub fn system_older(this: &[u64], needs: &[u64]) -> bool {
    let whole = |v: &[u64]| {
        let mut v = v.to_vec();
        v.resize(4, 0);
        v
    };
    whole(this) < whole(needs)
}

/// The macOS of this Mac, as it says (kern.osproductversion).
#[cfg(target_os = "macos")]
fn this_system() -> Option<String> {
    let name = CString::new("kern.osproductversion").ok()?;
    let mut buffer = [0u8; 64];
    let mut length = buffer.len();
    let done = unsafe { libc::sysctlbyname(name.as_ptr(), buffer.as_mut_ptr().cast(), &mut length, std::ptr::null_mut(), 0) };
    if done != 0 || length > buffer.len() {
        return None;
    }
    let text = buffer[..length].split(|b| *b == 0).next()?;
    std::str::from_utf8(text).ok().map(str::to_string)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether the bundle at `path` is signed as tTerm and whole: a Mac's
/// codesign, against `requirement`. Elsewhere (the checks) nothing is
/// signed.
pub fn signed(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    run(Command::new("/usr/bin/codesign").args(["--verify", "--strict", "--deep", "-R"]).arg(format!("={}", requirement())).arg(path), TOOL_TIME, None)
        .map_err(|e| format!("its code signature does not check ({e})"))?;
    #[cfg(not(target_os = "macos"))]
    let _ = path;
    Ok(())
}

/// What a bundle holds, as one SHA-256: every name in it, what each is
/// (folder, file, link), its mode, each file's bytes, each link's target;
/// but Finder's .DS_Store files, which codesign leaves out too (a look at
/// the folder in Finder writes one). Written down as a version is checked;
/// at install the same, or it does not go in.
pub fn tree_digest(root: &Path) -> Result<String, String> {
    use ring::digest::{Context, SHA256};
    use std::os::unix::fs::MetadataExt;
    fn add(all: &mut Context, parts: &[&[u8]]) {
        for part in parts {
            all.update(part);
            all.update(b"\0");
        }
    }
    fn walk(dir: &Path, name: &[u8], all: &mut Context, count: &mut usize) -> std::io::Result<()> {
        let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            *count += 1;
            if *count > 100_000 {
                return Err(std::io::Error::other("too many files"));
            }
            let path = entry.path();
            let mut inner = name.to_vec();
            if !inner.is_empty() {
                inner.push(b'/');
            }
            inner.extend_from_slice(entry.file_name().as_bytes());
            let meta = std::fs::symlink_metadata(&path)?;
            let mode = format!("{:o}", meta.mode() & 0o7777);
            let kind = meta.file_type();
            if kind.is_file() && entry.file_name() == ".DS_Store" {
                continue;
            }
            if kind.is_symlink() {
                let target = std::fs::read_link(&path)?;
                add(all, &[b"l", &inner, target.as_os_str().as_bytes()]);
            } else if kind.is_dir() {
                add(all, &[b"d", &inner, mode.as_bytes()]);
                walk(&path, &inner, all, count)?;
            } else if kind.is_file() {
                // Never a pipe put at its name meanwhile: nothing waits on one.
                let mut file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path)?;
                if !file.metadata()?.is_file() {
                    return Err(std::io::Error::other("not a plain file"));
                }
                let mut bytes = Context::new(&SHA256);
                let mut buffer = vec![0u8; 64 * 1024];
                let mut size: u64 = 0;
                loop {
                    let n = file.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    size += n as u64;
                    bytes.update(&buffer[..n]);
                }
                let (size, sum) = (size.to_string(), hex(bytes.finish().as_ref()));
                add(all, &[b"f", &inner, mode.as_bytes(), size.as_bytes(), sum.as_bytes()]);
            } else {
                return Err(std::io::Error::other("neither a file, a folder nor a link"));
            }
        }
        Ok(())
    }
    let mut all = Context::new(&SHA256);
    let mut count = 0;
    walk(root, b"", &mut all, &mut count).map_err(|e| format!("it cannot be read whole ({e})"))?;
    Ok(hex(all.finish().as_ref()))
}

/// The program of a bundle.
pub fn program(bundle: &Path) -> Result<PathBuf, String> {
    Ok(bundle.join("Contents").join("MacOS").join(read_plist(bundle)?.executable))
}

/// Where a version waits, unpacked and checked, next to the app: no app to
/// Finder or LaunchServices, its name not ending in .app.
pub fn staged_for(bundle: &Path, version: &str) -> PathBuf {
    bundle.with_file_name(format!(".tTerm-{version}.update"))
}

/// Whether `path` is one of the folders this module makes next to `bundle`:
/// what a file of its own may name, and nothing else.
fn ours_beside(bundle: &Path, path: &Path) -> bool {
    let (Some(a), Some(b)) = (bundle.parent(), path.parent()) else { return false };
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    a == b && name.starts_with(".tTerm-") && (name.ends_with(".update") || name.contains(".unpack-") || name.starts_with(".tTerm-swap-"))
}

/// Runs `command` with nothing on its input, at most `time`: what it printed,
/// if it ended well.
fn run(command: &mut Command, time: Duration, input: Option<&[u8]>) -> Result<String, String> {
    let name = command.get_program().to_string_lossy().to_string();
    command.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| format!("{name}: {e}"))?;
    if let Some(data) = input {
        // On a thread: tar reads while it writes, and the pipe is small.
        let mut stdin = child.stdin.take().ok_or("no input")?;
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
    }
    let (mut out, mut err) = (child.stdout.take(), child.stderr.take());
    let reader = std::thread::spawn(move || {
        let mut said = Vec::new();
        if let Some(o) = out.as_mut() {
            let _ = o.take(64 * 1024).read_to_end(&mut said);
        }
        let mut complained = Vec::new();
        if let Some(e) = err.as_mut() {
            let _ = e.take(8 * 1024).read_to_end(&mut complained);
        }
        (said, complained)
    });
    let deadline = Instant::now() + time;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| format!("{name}: {e}"))? {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{name} did not finish in time"));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let (said, complained) = reader.join().unwrap_or_default();
    if status.success() {
        Ok(String::from_utf8_lossy(&said).to_string())
    } else {
        let complained = String::from_utf8_lossy(&complained).trim().lines().last().unwrap_or("").to_string();
        Err(format!("{name}: {status}{}", if complained.is_empty() { String::new() } else { format!(": {complained}") }))
    }
}

/// Whether the bundle at `staged` is tTerm `version`, whole: its Info.plist,
/// for a macOS this Mac has (LaunchServices opens no other), and on a Mac
/// its code signature; only then its program runs, to say that version.
/// Only for a bundle just unpacked from the file its signed list names
/// (`stage`): nothing else beside the app runs.
pub fn check_bundle(staged: &Path, version: &str) -> Result<(), String> {
    let plist = read_plist(staged)?;
    if plist.identifier != BUNDLE_ID {
        return Err(format!("it is not tTerm but {}", plist.identifier));
    }
    if plist.version != version {
        return Err(format!("it says it is version {}", plist.version));
    }
    #[cfg(target_os = "macos")]
    if let (Some(needs), Some(this)) = (plist.minimum_system.as_deref(), this_system()) {
        if let (Some(n), Some(t)) = (system_version(needs), system_version(&this)) {
            if system_older(&t, &n) {
                return Err(format!("it needs macOS {needs}, and this Mac has {this}"));
            }
        }
    }
    signed(staged)?;
    let exe = staged.join("Contents").join("MacOS").join(&plist.executable);
    let said = run(Command::new(&exe).arg("--version").env_clear(), PROBE_TIME, None).map_err(|e| format!("it does not start here ({e})"))?;
    if said.trim() != version {
        return Err(format!("its program says it is {:?}", said.trim()));
    }
    Ok(())
}

/// Unpacks `archive`, version `version`, next to `bundle` and checks it,
/// in a folder of this process's own; then puts it where it waits, ready,
/// with what it holds (`tree_digest`). Only what is unpacked here is
/// checked, and run. Into its place under the trial file's lock: whatever is
/// there goes, but never the version before of an update on trial (another
/// tTerm at the same place may have put one in meanwhile). Nothing of it is
/// left behind when it is not taken.
pub fn stage(archive: &[u8], bundle: &Path, version: &str, data_dir: &Path) -> Result<(PathBuf, String), String> {
    let staged = staged_for(bundle, version);
    let unpack = bundle.with_file_name(format!(".tTerm-{version}.unpack-{}", std::process::id()));
    let _ = remove_tree(&unpack);
    let done = (|| -> Result<String, String> {
        std::fs::create_dir(&unpack).map_err(|e| format!("cannot unpack next to tTerm: {e}"))?;
        let tar = if Path::new("/usr/bin/tar").exists() { "/usr/bin/tar" } else { "tar" };
        run(Command::new(tar).arg("-xzf").arg("-").arg("-C").arg(&unpack), TOOL_TIME, Some(archive)).map_err(|e| format!("it does not unpack ({e})"))?;
        let names: Vec<String> = std::fs::read_dir(&unpack).map_err(|e| e.to_string())?.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string()).collect();
        let app = unpack.join(APP_NAME);
        let real_dir = std::fs::symlink_metadata(&app).is_ok_and(|m| m.is_dir());
        if names != [APP_NAME] || !real_dir {
            return Err(format!("it holds {names:?}, not {APP_NAME} alone"));
        }
        let digest = tree_digest(&app)?;
        check_bundle(&app, version)?;
        if tree_digest(&app)? != digest {
            return Err("it changed while it was checked".into());
        }
        let _held = lock(data_dir, LOCK_WAIT).ok_or("another tTerm is updating itself")?;
        if read_trial(&trial_file(data_dir)).is_some_and(|t| t.old == staged && !t.ok && !t.rolled_back) {
            return Err("another tTerm is updating itself".into());
        }
        let _ = remove_tree(&staged);
        std::fs::rename(&app, &staged).map_err(|e| e.to_string())?;
        Ok(digest)
    })();
    let _ = remove_tree(&unpack);
    done.map(|digest| (staged, digest))
}

/// Where the file of a version waits, downloaded and checked, until it goes
/// in: the app's own data, so that a start after takes it from there.
pub fn archive_file(data_dir: &Path, version: &str) -> PathBuf {
    data_dir.join(format!("update-{version}.tar.gz"))
}

/// The file kept at `path`, if it is still the one `wanted` names.
fn kept_archive(path: &Path, wanted: &Wanted) -> Option<Vec<u8>> {
    let mut file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    (&mut file).take(wanted.size + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 == wanted.size && sha256_hex(&bytes) == wanted.sha256).then_some(bytes)
}

/// The kept files of other versions than `keep` go.
fn keep_archives(data_dir: &Path, keep: Option<&str>) {
    let Ok(entries) = std::fs::read_dir(data_dir) else { return };
    let keep = keep.map(|v| format!("update-{v}.tar.gz"));
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // And what a write of one left (write_small).
        let ours = (name.starts_with("update-") && name.ends_with(".tar.gz")) || (name.starts_with(".update-") && name.contains(".tar.gz.") && name.ends_with(".tmp"));
        if ours && keep.as_ref() != Some(&name) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Removes a folder of this module's, and what is in it, without following
/// links.
fn remove_tree(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// The two folders trade places, in one step: renamex_np(RENAME_SWAP) on a
/// Mac, renameat2(RENAME_EXCHANGE) on Linux (the checks). A disk that cannot
/// swap gets three renames, the app's place empty for a moment.
pub fn swap(a: &Path, b: &Path) -> std::io::Result<()> {
    let (ca, cb) = (CString::new(a.as_os_str().as_bytes())?, CString::new(b.as_os_str().as_bytes())?);
    #[cfg(target_os = "macos")]
    let done = unsafe { libc::renamex_np(ca.as_ptr(), cb.as_ptr(), libc::RENAME_SWAP) };
    #[cfg(target_os = "linux")]
    let done = unsafe { libc::renameat2(libc::AT_FDCWD, ca.as_ptr(), libc::AT_FDCWD, cb.as_ptr(), libc::RENAME_EXCHANGE) };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let done = {
        let _ = (&ca, &cb);
        -1
    };
    if done == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    let cannot = matches!(error.raw_os_error(), Some(libc::ENOTSUP) | Some(libc::EINVAL)) || (cfg!(target_os = "linux") && error.raw_os_error() == Some(libc::ENOSYS));
    if !cannot {
        return Err(error);
    }
    let aside = b.with_file_name(format!(".tTerm-swap-{}", std::process::id()));
    std::fs::rename(b, &aside)?;
    if let Err(e) = std::fs::rename(a, b) {
        let _ = std::fs::rename(&aside, b);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&aside, a) {
        // Back as it was: each to its own place.
        let _ = std::fs::rename(b, a);
        let _ = std::fs::rename(&aside, b);
        return Err(e);
    }
    Ok(())
}

/// Whether this account may write to `path`.
fn writable(path: &Path) -> bool {
    CString::new(path.as_os_str().as_bytes()).map(|p| unsafe { libc::access(p.as_ptr(), libc::W_OK) } == 0).unwrap_or(false)
}

fn alive(pid: i32) -> bool {
    pid > 1 && (unsafe { libc::kill(pid, 0) } == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
}

/// When the process `pid` started, as this system says: with its pid, who
/// it is. A pid written down earlier may be another process's by now (one
/// that started since, after a restart of the Mac too). None when there is
/// no such process (a zombie neither) or it cannot be told.
pub fn started_at(pid: i32) -> Option<String> {
    if pid <= 1 {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let got = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size) };
        if got != size {
            return None;
        }
        Some(format!("{}.{:06}", info.pbi_start_tvsec, info.pbi_start_tvusec))
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Linux (the checks): the start in ticks since the boot, field 22
        // of /proc/PID/stat, after the program's name in parentheses. Not
        // with the boot's time: that moves when the clock is set.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = stat.get(stat.rfind(')')? + 1..)?;
        let mut fields = rest.split_whitespace();
        if fields.next() == Some("Z") {
            return None;
        }
        Some(fields.nth(18)?.to_string())
    }
}

/// Whether `pid` is still the process that started at `started`; one
/// written down without its start (it could not be told then): whether it
/// is alive.
fn same(pid: i32, started: &Option<String>) -> bool {
    match started {
        Some(s) => started_at(pid).as_deref() == Some(s.as_str()),
        None => alive(pid),
    }
}

/// Opens the app at `app`: on a Mac by LaunchServices (`open`), in the
/// background with --background; elsewhere (the checks) its program, as is.
/// `fresh`: a new one (`open -n`), where the one before has gone, so that
/// LaunchServices does not bring forward one still on its way out.
pub fn launch(app: &Path, background: bool, fresh: bool) -> std::io::Result<()> {
    let mut command = if cfg!(target_os = "macos") {
        let mut c = Command::new("/usr/bin/open");
        if fresh {
            c.arg("-n");
        }
        if background {
            c.arg("-g");
        }
        c.arg(app);
        if background {
            c.args(["--args", "--background"]);
        }
        c
    } else {
        let exe = program(app).map_err(std::io::Error::other)?;
        let mut c = Command::new(exe);
        if background {
            c.arg("--background");
        }
        c
    };
    command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).process_group(0);
    let mut child = command.spawn()?;
    if cfg!(target_os = "macos") {
        // open hands it over and ends.
        let status = child.wait()?;
        if !status.success() {
            return Err(std::io::Error::other(format!("open: {status}")));
        }
    } else {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
    Ok(())
}

// ------------------------------------------------------------- the trial

/// A new version put in place, until it has started: the file of the
/// watcher and of the new version (update.json in the app's folder).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Trial {
    pub from: String,
    pub to: String,
    /// The app's place, with the new version in it.
    pub app: PathBuf,
    /// The version before, beside it, until the new one is up.
    pub old: PathBuf,
    /// When it was put in place, in milliseconds.
    pub at: i64,
    /// Opened again by the watcher (Restart, or by itself in the menu bar);
    /// not after a Quit.
    #[serde(default)]
    pub relaunch: bool,
    #[serde(default)]
    pub background: bool,
    /// The new version's process, once it starts, and when that process
    /// started (`started_at`): so that a pid that is another's by now is not
    /// taken for it.
    #[serde(default)]
    pub pid: Option<i32>,
    #[serde(default)]
    pub started: Option<String>,
    /// The version before's process that watches it, once one is started,
    /// and when it started.
    #[serde(default)]
    pub watcher: Option<i32>,
    #[serde(default)]
    pub watcher_started: Option<String>,
    /// The new version said it is up.
    #[serde(default)]
    pub ok: bool,
    /// It was not, and the version before came back.
    #[serde(default)]
    pub rolled_back: bool,
}

pub fn trial_file(data_dir: &Path) -> PathBuf {
    data_dir.join("update.json")
}

/// The version that did not come up here: only newer ones are taken.
pub fn skip_file(data_dir: &Path) -> PathBuf {
    data_dir.join("update-skip")
}

pub fn read_trial(path: &Path) -> Option<Trial> {
    let mut text = String::new();
    std::fs::File::open(path).ok()?.take(64 * 1024).read_to_string(&mut text).ok()?;
    let mut trial: Trial = serde_json::from_str(&text).ok()?;
    // Only the app's place and the folder beside it, whatever the file says;
    // and only pids of processes (never 0 or -1, which kill would take for
    // many).
    let sane = trial.app.is_absolute() && trial.app.extension().is_some_and(|e| e == "app") && trial.old == staged_for(&trial.app, &trial.to) && version(&trial.from).is_some() && version(&trial.to).is_some();
    trial.pid = trial.pid.filter(|p| *p > 1);
    trial.watcher = trial.watcher.filter(|p| *p > 1);
    sane.then_some(trial)
}

/// A small file written whole, under its name, in one step; for the person
/// alone. Never through a link left at its name.
fn write_small(path: &Path, text: &[u8]) -> std::io::Result<()> {
    let fresh = path.with_file_name(format!(".{}.{}.tmp", path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), std::process::id()));
    let _ = std::fs::remove_file(&fresh);
    let written = (|| {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&fresh)?;
        f.write_all(text)?;
        f.sync_all()?;
        std::fs::rename(&fresh, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&fresh);
    }
    written
}

pub fn write_trial(path: &Path, trial: &Trial) -> std::io::Result<()> {
    write_small(path, &serde_json::to_vec_pretty(trial).map_err(std::io::Error::other)?)
}

/// The lock of the trial file (update.lock beside it), held by whatever
/// changes the file, whichever process: None when another holds it longer
/// than `within`, or it cannot be made. On a disk without such locks (some
/// network homes) it is had at once: nothing better to do there.
pub fn lock(data_dir: &Path, within: Duration) -> Option<std::fs::File> {
    use std::os::fd::AsRawFd;
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(data_dir.join("update.lock")).ok()?;
    let end = Instant::now() + within;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Some(file);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(e) if e == libc::EWOULDBLOCK || e == libc::EINTR => {}
            Some(e) if e == libc::ENOTSUP || e == libc::EOPNOTSUPP || e == libc::ENOLCK => return Some(file),
            _ => return None,
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// This start, when it is the new version on trial in this app's place: its
/// pid goes in the trial file, and unless the version before watches
/// already (its watcher written down, still that process), it is started to
/// watch this start (--watch-start). As early as the app starts (main.rs,
/// before its window), and again in `Updates::new`. Some(the trial) when
/// this start is the one on trial.
pub fn claim(config: &Config) -> Option<Trial> {
    let bundle = config.bundle.as_ref()?;
    let file = trial_file(&config.data_dir);
    // Only this app's place, this version, not decided yet: a copy run from
    // elsewhere (the disk image) leaves it alone, and so does every other
    // start; looked at first without the lock, which a version coming back
    // holds while it opens that version (`roll_back`).
    let ours = |t: &Trial| t.app == *bundle && t.to == config.current && !t.ok && !t.rolled_back;
    if !read_trial(&file).is_some_and(|t| ours(&t)) {
        return None;
    }
    let _held = lock(&config.data_dir, LOCK_WAIT)?;
    let mut trial = read_trial(&file).filter(|t| ours(t))?;
    let me = std::process::id() as i32;
    if trial.pid.is_some_and(|p| p != me && same(p, &trial.started)) {
        // Another start of this version has it.
        return None;
    }
    if trial.pid != Some(me) {
        trial.pid = Some(me);
        trial.started = started_at(me);
    }
    if !trial.watcher.is_some_and(|w| same(w, &trial.watcher_started)) {
        let (watcher, started) = watch_start(&trial, &file, me).unzip();
        trial.watcher = watcher;
        trial.watcher_started = started.flatten();
    }
    let _ = write_trial(&file, &trial);
    Some(trial)
}

/// Starts the version before, beside the app, to watch the start `pid`:
/// only that version, as signed as tTerm. Its pid, and when it started.
fn watch_start(trial: &Trial, file: &Path, pid: i32) -> Option<(i32, Option<String>)> {
    if !read_plist(&trial.old).is_ok_and(|p| p.identifier == BUNDLE_ID && p.version == trial.from) {
        eprintln!("tterm: tTerm {} is not beside the app to watch this start", trial.from);
        return None;
    }
    if let Err(why) = signed(&trial.old) {
        eprintln!("tterm: the version before does not watch this start: {why}");
        return None;
    }
    let watcher = program(&trial.old).ok()?;
    let spawned = Command::new(watcher).arg("--watch-start").arg(file).arg(pid.to_string()).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).process_group(0).spawn();
    match spawned {
        Ok(child) => Some(reap(child)),
        Err(e) => {
            eprintln!("tterm: the version before cannot watch this start: {e}");
            None
        }
    }
}

/// A child left to run: its pid and when it started, and it is waited for
/// once it ends, so that it is not taken for alive.
fn reap(mut child: std::process::Child) -> (i32, Option<String>) {
    let pid = child.id() as i32;
    let started = started_at(pid);
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    (pid, started)
}

/// The version that did not start here, if newer than `current`.
pub fn skipped(data_dir: &Path, current: &str) -> Option<String> {
    let text = std::fs::read_to_string(skip_file(data_dir)).ok()?;
    let v = text.trim().to_string();
    newer(&v, current).then_some(v)
}

/// Whether an update is on trial in the folder of `bundle`: of this app, or
/// of another copy of it there ("tTerm 2.app"): what waits beside them has
/// one name for all of them (`staged_for`), and may be that update's
/// version before.
fn pending_beside(data_dir: &Path, bundle: &Path) -> bool {
    read_trial(&trial_file(data_dir)).is_some_and(|t| !t.ok && !t.rolled_back && (t.app == bundle || ours_beside(bundle, &t.old)))
}

/// The watcher, run from the version before (`tterm --finish-update FILE
/// PID`): once the app that put the new version in place has quit, it opens
/// the new one, and waits for it to say it is up; one that does not, within
/// UP_WITHIN, goes, and the version before comes back, its next version not
/// taken again. The exit code is for the log.
pub fn finish(file: &Path, quitting: i32) -> i32 {
    finish_with(file, quitting, QUIT_WITHIN, UP_WITHIN)
}

pub fn finish_with(file: &Path, quitting: i32, quit_within: Duration, up_within: Duration) -> i32 {
    let Some(trial) = read_trial(file) else { return 1 };
    let end = Instant::now() + quit_within;
    while alive(quitting) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(100));
    }
    if alive(quitting) {
        // Still quitting: the new version stays where it is, and is watched
        // when it starts (`claim`: this watcher is gone by then).
        return 2;
    }
    std::thread::sleep(Duration::from_millis(300));
    let opened = Instant::now();
    // Opened by then all the same (a click in the Dock): watched, not opened
    // twice. And should open say no, LaunchServices may have opened it all
    // the same: again only while no start has written its pid.
    let claimed = || read_trial(file).is_some_and(|t| t.pid.is_some() || t.ok || t.rolled_back);
    if !claimed() && launch(&trial.app, trial.background, true).is_err() {
        let end = Instant::now() + Duration::from_secs(3);
        while !claimed() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(200));
        }
        if !claimed() {
            let _ = launch(&trial.app, trial.background, true);
        }
    }
    watch_up(file, opened, up_within, None)
}

/// The new version started by itself, put in place as tTerm quit, or after
/// its watcher was gone: the version before, beside it, watches this start
/// (`tterm --watch-start FILE PID`).
pub fn finish_started(file: &Path, started: i32, up_within: Duration) -> i32 {
    if read_trial(file).is_none() {
        return 1;
    }
    watch_up(file, Instant::now(), up_within, Some((started, started_at(started))))
}

/// Waits for the new version to say it is up: the start it watches, or one
/// that has written its pid since (opened again meanwhile). One that does
/// not, within `up_within`, or whose start ends before, goes. A file gone,
/// or not understood any more, is taken for up: never a running app put
/// aside on a doubt.
fn watch_up(file: &Path, since: Instant, up_within: Duration, started: Option<(i32, Option<String>)>) -> i32 {
    let mut watching = started;
    loop {
        let Some(t) = read_trial(file) else { return 0 };
        if t.ok || t.rolled_back {
            return 0;
        }
        if let Some(p) = t.pid {
            // The first start written down is watched whether it still runs
            // or not (one that ended right after it wrote its pid is not up);
            // a later one, while it runs.
            let other = watching.as_ref().is_none_or(|(w, _)| *w != p);
            if other && (watching.is_none() || same(p, &t.started)) {
                watching = Some((p, t.started.clone()));
            }
        }
        if watching.as_ref().is_some_and(|(p, s)| !same(*p, s)) || since.elapsed() >= up_within {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    roll_back(file)
}

/// Not up: whatever of it runs ends, and the version before comes back,
/// its next version not taken again. Once, whoever watches: under the trial
/// file's lock, as the file says it is then. Whatever is in the app's place
/// opens again, once the lock is let go (it asks for it as it starts):
/// never nothing. Where the version before cannot come back (the two
/// versions not where the file says: a second copy of the app may have
/// changed them), the trial is over: what runs there runs, and nothing
/// watches it again.
fn roll_back(file: &Path) -> i32 {
    let Some(dir) = file.parent() else { return 1 };
    // (the trial, whether to open what is in place, the exit code)
    let (now, open, code) = {
        let Some(_held) = lock(dir, LOCK_WAIT) else { return 5 };
        let Some(now) = read_trial(file) else { return 0 };
        if now.ok || now.rolled_back {
            return 0;
        }
        // The process written down, while it is still that one: never a pid
        // that is another's by now.
        let running = now.pid.filter(|p| *p > 1 && now.started.is_some() && same(*p, &now.started));
        let is = |p: &Path, v: &str| read_plist(p).is_ok_and(|pl| pl.identifier == BUNDLE_ID && pl.version == v);
        if !is(&now.app, &now.to) || !is(&now.old, &now.from) {
            let _ = std::fs::remove_file(file);
            let open = running.is_none();
            (now, open, 3)
        } else {
            if let Some(pid) = running.filter(|p| *p != std::process::id() as i32) {
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
                let end = Instant::now() + Duration::from_secs(3);
                while same(pid, &now.started) && Instant::now() < end {
                    std::thread::sleep(Duration::from_millis(100));
                }
                if same(pid, &now.started) {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
            if swap(&now.old, &now.app).is_err() {
                let _ = std::fs::remove_file(file);
                (now, true, 3)
            } else {
                let _ = write_small(&skip_file(dir), format!("{}\n", now.to).as_bytes());
                let _ = write_trial(file, &Trial { rolled_back: true, ..now.clone() });
                let _ = remove_tree(&now.old);
                (now, true, 4)
            }
        }
    };
    if open {
        let _ = launch(&now.app, now.background, true);
    }
    code
}

/// The watcher, when the program was started as one: Some(exit code).
/// --finish-update FILE PID: after a restart, PID the app quitting;
/// --watch-start FILE PID: PID the new version, started by itself.
pub fn watcher_main(args: &[String]) -> Option<i32> {
    let which = args.get(1).map(String::as_str);
    if which != Some("--finish-update") && which != Some("--watch-start") {
        return None;
    }
    let (Some(file), Some(pid)) = (args.get(2), args.get(3).and_then(|p| p.parse::<i32>().ok())) else { return Some(1) };
    Some(if which == Some("--finish-update") { finish(Path::new(file), pid) } else { finish_started(Path::new(file), pid, UP_WITHIN) })
}

/// The version before, run from beside the app where an update put it, by
/// something that followed it there (a bookmark of the Dock): the app in
/// its place, to open instead.
pub fn moved_aside(exe: &Path) -> Option<PathBuf> {
    let folder = exe.parent()?.parent()?.parent()?;
    let name = folder.file_name()?.to_string_lossy().to_string();
    if !(name.starts_with(".tTerm-") && name.ends_with(".update")) {
        return None;
    }
    let app = folder.with_file_name(APP_NAME);
    app.is_dir().then_some(app)
}

/// LaunchServices told of the app in its place now (a Mac's lsregister).
fn register(app: &Path) {
    if cfg!(target_os = "macos") {
        let lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
        let _ = run(Command::new(lsregister).arg("-f").arg(app), TOOL_TIME, None);
    }
}

// ---------------------------------------------------------- the updater

/// Where the updater is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// Not looked yet, or nothing newer.
    Idle,
    Checking,
    Downloading(String),
    /// Unpacked next to the app and checked: what Restart puts in place, as
    /// it was then (`tree_digest`).
    Ready { version: String, staged: PathBuf, digest: String },
    Installing(String),
    /// The last look or download did not work: why.
    Failed(String),
    /// Not here: why, and whether moving to Applications helps.
    Unavailable { why: String, movable: bool },
}

impl Phase {
    pub fn word(&self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Checking => "checking",
            Phase::Downloading(_) => "downloading",
            Phase::Ready { .. } => "ready",
            Phase::Installing(_) => "installing",
            Phase::Failed(_) => "failed",
            Phase::Unavailable { .. } => "unavailable",
        }
    }
}

/// A new version put in place and up: said once, until the page has shown
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Updated {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    /// The version Ready or on its way, and when it became ready.
    pub next: Option<String>,
    pub ready_at: Option<i64>,
    pub checked_at: Option<i64>,
    pub updated: Option<Updated>,
    /// A line Settings keeps showing: the version that did not start here.
    pub note: Option<String>,
}

/// What the page or a menu asks of the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wish {
    Restart,
    Move,
}

/// Where the updater looks and what it is: the app's own, or the checks'.
#[derive(Debug, Clone)]
pub struct Config {
    pub releases: String,
    pub key: Option<[u8; 32]>,
    /// The version this app is.
    pub current: String,
    /// tTerm.app, if the app runs from one.
    pub bundle: Option<PathBuf>,
    pub data_dir: PathBuf,
    /// Updating where only the checks do (Linux).
    pub anywhere: bool,
}

impl Config {
    /// The app's: from its program's place. A debug build takes, for the
    /// checks, another list of releases (TTERM_UPDATE_RELEASES), its key
    /// (TTERM_UPDATE_KEY), another version to be (TTERM_PRETEND_VERSION) and
    /// the bundle it is run for (TTERM_PRETEND_BUNDLE: a script there runs
    /// the build from elsewhere).
    pub fn app(data_dir: &Path) -> Config {
        let bundle = std::env::current_exe().ok().and_then(|e| bundle_of(&e));
        let mut config = Config { releases: RELEASES.to_string(), key: public_key(), current: crate::VERSION.to_string(), bundle, data_dir: data_dir.to_path_buf(), anywhere: false };
        if cfg!(debug_assertions) {
            if let Ok(releases) = std::env::var("TTERM_UPDATE_RELEASES") {
                config.releases = releases;
                config.key = std::env::var("TTERM_UPDATE_KEY").ok().and_then(|k| key_from_hex(&k));
                config.anywhere = true;
            }
            if let Some(v) = std::env::var("TTERM_PRETEND_VERSION").ok().filter(|v| version(v).is_some()) {
                config.current = v;
            }
            if let Some(b) = std::env::var_os("TTERM_PRETEND_BUNDLE").map(PathBuf::from).filter(|b| b.is_absolute()) {
                config.bundle = Some(b);
            }
        }
        config
    }

    /// The version this app is: what --version says.
    pub fn version_said() -> String {
        if cfg!(debug_assertions) {
            if let Some(v) = std::env::var("TTERM_PRETEND_VERSION").ok().filter(|v| version(v).is_some()) {
                return v;
            }
        }
        crate::VERSION.to_string()
    }
}

pub struct Updates {
    pub config: Config,
    state: watch::Sender<Status>,
    nudge: Notify,
    wishes: Mutex<Option<mpsc::UnboundedSender<Wish>>>,
    looked: Mutex<Option<Instant>>,
    /// This start is a new version's, on trial: it says it is up (`up`).
    trial_mine: Mutex<bool>,
    /// The version going in that a look meanwhile found no longer the newest
    /// listed: should it not go in, it is not ready again.
    withdrawn: Mutex<Option<String>>,
    /// Held while what is beside the app is tidied, and as a version ready
    /// starts to go in: the one never while the other.
    tidying: Mutex<()>,
}

fn now_ms() -> i64 {
    crate::terminals::now_ms()
}

impl Updates {
    pub fn new(config: Config) -> Updates {
        let file = trial_file(&config.data_dir);
        let mut status = Status { phase: Phase::Idle, next: None, ready_at: None, checked_at: None, updated: None, note: None };
        let mut mine = false;
        if let Some(t) = claim(&config) {
            // The new version, started: the watcher hears it once it is up.
            mine = true;
            status.updated = Some(Updated { from: t.from, to: t.to });
        } else if let Some(_held) = file.exists().then(|| lock(&config.data_dir, LOCK_WAIT)).flatten() {
            let here = |t: &Trial| config.bundle.as_ref() == Some(&t.app);
            match read_trial(&file) {
                // Another place's (a copy run from elsewhere): not this one's
                // to judge.
                Some(t) if !here(&t) => {}
                // Up at a start before, and not said yet.
                Some(t) if t.to == config.current && t.ok && !t.rolled_back => {
                    status.updated = Some(Updated { from: t.from, to: t.to });
                }
                // Another start of this version is on trial.
                Some(t) if t.to == config.current && !t.rolled_back => {}
                Some(t) if t.rolled_back && t.from == config.current => {
                    status.note = Some(format!("tTerm {} did not start on this Mac, so tTerm {} came back. The version after it will be taken.", t.to, t.from));
                    let _ = std::fs::remove_file(&file);
                }
                // For the version before to say.
                Some(t) if t.rolled_back => {}
                // Put in place by another copy of the app, at the same place,
                // started before it was: that version's, not this one's.
                Some(t) if read_plist(&t.app).is_ok_and(|p| p.identifier == BUNDLE_ID && p.version == t.to) => {}
                _ => {
                    let _ = std::fs::remove_file(&file);
                }
            }
        }
        if let Err((why, movable)) = usable(&config) {
            status.phase = Phase::Unavailable { why, movable };
        }
        let (state, _) = watch::channel(status);
        Updates { config, state, nudge: Notify::new(), wishes: Mutex::new(None), looked: Mutex::new(None), trial_mine: Mutex::new(mine), withdrawn: Mutex::new(None), tidying: Mutex::new(()) }
    }

    /// An updater that does nothing: for the engine without the app.
    pub fn none(data_dir: &Path) -> Updates {
        let config = Config { releases: String::new(), key: None, current: crate::VERSION.to_string(), bundle: None, data_dir: data_dir.to_path_buf(), anywhere: false };
        let (state, _) = watch::channel(Status { phase: Phase::Unavailable { why: "Only tTerm for Mac updates itself.".into(), movable: false }, next: None, ready_at: None, checked_at: None, updated: None, note: None });
        Updates { config, state, nudge: Notify::new(), wishes: Mutex::new(None), looked: Mutex::new(None), trial_mine: Mutex::new(false), withdrawn: Mutex::new(None), tidying: Mutex::new(()) }
    }

    pub fn status(&self) -> watch::Receiver<Status> {
        self.state.subscribe()
    }

    pub fn now(&self) -> Status {
        self.state.borrow().clone()
    }

    fn set(&self, change: impl FnOnce(&mut Status)) {
        self.state.send_modify(change);
    }

    /// The version ready to go in, and where it waits.
    pub fn ready(&self) -> Option<(String, PathBuf)> {
        match &self.state.borrow().phase {
            Phase::Ready { version, staged, .. } => Some((version.clone(), staged.clone())),
            _ => None,
        }
    }

    /// The app hears what the page and the menus ask of it here.
    pub fn listen(&self) -> mpsc::UnboundedReceiver<Wish> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.wishes.lock().unwrap() = Some(tx);
        rx
    }

    /// Asks the app: false when no app listens (the engine alone).
    pub fn wish(&self, wish: Wish) -> bool {
        self.wishes.lock().unwrap().as_ref().is_some_and(|tx| tx.send(wish).is_ok())
    }

    /// Check now: a look at once, unless one was just made.
    pub fn check_now(&self) {
        self.nudge.notify_one();
    }

    /// A look as soon as the one going on, if any, is over.
    fn look_again(&self) {
        *self.looked.lock().unwrap() = None;
        self.check_now();
    }

    /// The new version on trial is up: the watcher lets it be, and the
    /// version before goes.
    pub fn up(&self) {
        let mut mine = self.trial_mine.lock().unwrap();
        if !*mine {
            return;
        }
        *mine = false;
        let file = trial_file(&self.config.data_dir);
        let Some(held) = lock(&self.config.data_dir, LOCK_WAIT) else { return };
        let Some(t) = read_trial(&file) else { return };
        if self.config.bundle.as_ref() != Some(&t.app) || t.to != self.config.current || t.rolled_back {
            return;
        }
        // Said, or the watcher would end this one: only then may the version
        // before go.
        let said = t.ok || write_trial(&file, &Trial { ok: true, ..t.clone() }).is_ok();
        drop(held);
        if said && ours_beside(&t.app, &t.old) {
            // A moment later, once its watcher has seen this one up and gone:
            // nothing finds it beside the app any more (a bookmark of the
            // Dock would follow it). Under the trial file's lock, and only
            // the version before: another copy of the app there may have
            // put something else in its place since.
            let data = self.config.data_dir.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(5));
                let Some(_held) = lock(&data, LOCK_WAIT) else { return };
                let named = read_trial(&trial_file(&data)).is_some_and(|n| n.old == t.old && !n.ok && !n.rolled_back);
                if !named && read_plist(&t.old).is_ok_and(|p| p.identifier == BUNDLE_ID && p.version == t.from) {
                    let _ = remove_tree(&t.old);
                }
            });
        }
    }

    /// The page has said "tTerm is updated": not again.
    pub fn seen(&self) {
        self.set(|s| s.updated = None);
        let file = trial_file(&self.config.data_dir);
        if !file.exists() {
            return;
        }
        let Some(_held) = lock(&self.config.data_dir, LOCK_WAIT) else { return };
        if read_trial(&file).is_some_and(|t| t.ok && t.to == self.config.current && self.config.bundle.as_ref() == Some(&t.app)) {
            let _ = std::fs::remove_file(&file);
        }
    }

    /// What the page shows in Settings, the strip and the card.
    pub fn json(&self, engine: &Engine) -> Value {
        let s = self.now();
        let mode = engine.settings.lock().unwrap().updates.clone();
        let (problem, movable) = match &s.phase {
            Phase::Failed(why) => (Some(why.clone()), false),
            Phase::Unavailable { why, movable } => (Some(why.clone()), *movable),
            _ => (None, false),
        };
        json!({
            "version": self.config.current,
            "mode": mode,
            "state": s.phase.word(),
            "next": s.next,
            "notes": s.next.as_ref().map(|v| format!("{RELEASE_PAGE}{v}")),
            "readyAt": s.ready_at,
            "checkedAt": s.checked_at,
            "problem": problem,
            "movable": movable,
            "updated": s.updated.as_ref().map(|u| json!({"from": u.from, "to": u.to, "notes": format!("{RELEASE_PAGE}{}", u.to)})),
            "note": s.note,
        })
    }

    /// The looks: the first a while after the start, then every few hours,
    /// and when the person asks.
    pub async fn keep(engine: Arc<Engine>) {
        let me = &engine.updates;
        if matches!(me.now().phase, Phase::Unavailable { .. }) {
            return;
        }
        let mut wait = FIRST_LOOK;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = me.nudge.notified() => {}
            }
            wait = LOOK_EVERY;
            let recent = me.looked.lock().unwrap().is_some_and(|at| at.elapsed() < CHECK_GAP);
            if !recent {
                me.look().await;
            }
            me.tidy();
        }
    }

    /// What is left of other versions beside the app, and their files in
    /// the app's data: once the one on trial is up, and never the one ready.
    pub fn tidy(&self) {
        let Some(bundle) = &self.config.bundle else { return };
        let Some(dir) = bundle.parent() else { return };
        // Not while a version starts to go in (`install`), and not where
        // another copy of the app has put one in: what is beside the app is
        // then that one's.
        let _tidying = self.tidying.lock().unwrap();
        // And under the trial file's lock, had at once: another copy of the
        // app putting a version in now is not tidied away.
        let Some(_held) = lock(&self.config.data_dir, Duration::ZERO) else { return };
        let phase = self.now().phase;
        if matches!(phase, Phase::Installing(_)) || self.replaced() {
            return;
        }
        let ready = match phase {
            Phase::Ready { version, staged, .. } => Some((version, staged)),
            _ => None,
        };
        let keep = ready.as_ref().map(|(_, staged)| staged.clone());
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            // Never what a swap of three renames holds for a moment (it may be
            // the app itself), nor what another copy of the app unpacks now.
            let swapping = name.starts_with(".tTerm-swap-");
            let unpacking = name.rsplit_once(".unpack-").and_then(|(_, pid)| pid.parse::<i32>().ok()).is_some_and(|pid| pid != std::process::id() as i32 && alive(pid));
            if ours_beside(bundle, &path) && !swapping && !unpacking && Some(&path) != keep.as_ref() {
                let _ = remove_tree(&path);
            }
        }
        keep_archives(&self.config.data_dir, ready.as_ref().map(|(v, _)| v.as_str()));
    }

    /// Whether another copy of the app, at the same place, has put another
    /// version there, or one is on trial there: what is beside the app is
    /// then not this one's to take or tidy (it may be that version's
    /// version before).
    fn replaced(&self) -> bool {
        let Some(bundle) = &self.config.bundle else { return false };
        read_plist(bundle).map_or(true, |p| p.version != self.config.current) || pending_beside(&self.config.data_dir, bundle)
    }

    /// Removes a folder this updater made beside the app: under the trial
    /// file's lock, had at once (or not at all: tidying takes it later), and
    /// never where another copy of the app has put a version in.
    fn remove_staged(&self, staged: &Path) {
        let Some(_held) = lock(&self.config.data_dir, Duration::ZERO) else { return };
        if !self.replaced() {
            let _ = remove_tree(staged);
        }
    }

    /// One look at the releases, and the download of a newer version.
    pub async fn look(&self) {
        if matches!(self.now().phase, Phase::Installing(_) | Phase::Unavailable { .. }) {
            return;
        }
        *self.looked.lock().unwrap() = Some(Instant::now());
        let (Some(key), Some(bundle)) = (self.config.key, self.config.bundle.clone()) else {
            self.set(|s| s.phase = Phase::Failed("This tTerm has no release key built in.".into()));
            return;
        };
        let data = self.config.data_dir.clone();
        // Another copy of the app, at the same place, has put another version
        // there, or one is on trial: this one leaves all to it, and what it
        // had ready is not ready any more (that folder may hold the version
        // before now, and stays as it is).
        if self.replaced() {
            self.set(|s| {
                if matches!(s.phase, Phase::Ready { .. }) {
                    s.phase = Phase::Idle;
                    s.next = None;
                }
            });
            return;
        }
        // Every change of the phase here is decided where it is made
        // (send_modify): Restart may have been pressed meanwhile.
        self.set(|s| {
            if matches!(s.phase, Phase::Idle | Phase::Failed(_)) {
                s.phase = Phase::Checking;
            }
        });
        let floor = skipped(&data, &self.config.current).unwrap_or_else(|| self.config.current.clone());
        let clients = app_clients().await;
        let found = find(&clients, &self.config.releases, &floor, &key).await;
        let checked = now_ms();
        let found = match found {
            Ok(Some(found)) => found,
            Ok(None) => {
                // Nothing newer listed: a version ready was taken back (made
                // a pre-release, or deleted), and goes; one going in now is
                // not ready again, should it not go in.
                let mut gone = None;
                let mut going_in = None;
                self.set(|s| {
                    s.checked_at = Some(checked);
                    match &s.phase {
                        Phase::Installing(v) => going_in = Some(v.clone()),
                        Phase::Ready { staged, .. } => {
                            gone = Some(staged.clone());
                            s.phase = Phase::Idle;
                            s.next = None;
                        }
                        _ => {
                            s.phase = Phase::Idle;
                            s.next = None;
                        }
                    }
                });
                if going_in.is_some() {
                    *self.withdrawn.lock().unwrap() = going_in;
                }
                if let Some(staged) = gone {
                    self.remove_staged(&staged);
                }
                keep_archives(&data, None);
                return;
            }
            Err(why) => {
                eprintln!("tterm: could not look for a new version: {why}");
                self.set(|s| {
                    s.checked_at = Some(checked);
                    if matches!(s.phase, Phase::Checking) {
                        s.phase = Phase::Failed(format!("Could not look for a new version: {why}"));
                    }
                });
                return;
            }
        };
        let version = found.version.clone();
        let mut same = false;
        let mut dropped = None;
        let mut going_in = None;
        self.set(|s| {
            s.checked_at = Some(checked);
            match &s.phase {
                Phase::Ready { version: v, .. } if *v == version => same = true,
                Phase::Installing(v) => {
                    same = true;
                    if *v != version {
                        going_in = Some(v.clone());
                    }
                }
                phase => {
                    // Another version is the newest listed: the one ready is
                    // not ready any more (taken back on GitHub, or not the
                    // newest), not even while this one downloads.
                    if let Phase::Ready { version: v, staged, .. } = phase {
                        dropped = Some((v.clone(), staged.clone()));
                    }
                    s.phase = Phase::Downloading(version.clone());
                    s.next = Some(version.clone());
                }
            }
        });
        if going_in.is_some() {
            *self.withdrawn.lock().unwrap() = going_in;
        }
        if let Some((v, staged)) = dropped {
            self.remove_staged(&staged);
            let _ = std::fs::remove_file(archive_file(&data, &v));
        }
        if same {
            return;
        }
        // Its file, kept from a download before (Ask me first, a start
        // since), when it is still the one the list names; or downloaded,
        // and kept. Unpacked and checked again either way: nothing left
        // beside the app is taken as it is.
        let kept = archive_file(&data, &version);
        let from_before = {
            let (kept, wanted) = (kept.clone(), found.wanted.clone());
            tokio::task::spawn_blocking(move || kept_archive(&kept, &wanted)).await.ok().flatten()
        };
        let archive = match from_before {
            Some(archive) => Ok((archive, false)),
            None => download(&clients, &found).await.map(|archive| (archive, true)),
        };
        let staged = match archive {
            Ok((archive, fresh)) => {
                let (bundle, version, kept, data) = (bundle.clone(), version.clone(), kept.clone(), data.clone());
                tokio::task::spawn_blocking(move || {
                    if fresh {
                        let _ = write_small(&kept, &archive);
                    }
                    stage(&archive, &bundle, &version, &data)
                })
                .await
                .unwrap_or_else(|e| Err(e.to_string()))
            }
            Err(why) => Err(why),
        };
        match staged {
            Ok((staged, digest)) => {
                let mut took = false;
                let mut before = None;
                self.set(|s| match &s.phase {
                    // Restart was pressed meanwhile, for the version before.
                    Phase::Installing(_) => {}
                    phase => {
                        if let Phase::Ready { staged: b, .. } = phase {
                            before = Some(b.clone());
                        }
                        took = true;
                        s.phase = Phase::Ready { version: version.clone(), staged: staged.clone(), digest: digest.clone() };
                        s.next = Some(version.clone());
                        s.ready_at = Some(now_ms());
                        s.note = None;
                    }
                });
                if !took {
                    self.remove_staged(&staged);
                } else {
                    if let Some(before) = before.filter(|b| *b != staged) {
                        self.remove_staged(&before);
                    }
                    keep_archives(&data, Some(&version));
                }
            }
            Err(why) => {
                eprintln!("tterm: version {version} not taken: {why}");
                let _ = std::fs::remove_file(&kept);
                self.set(|s| {
                    if matches!(s.phase, Phase::Downloading(_)) {
                        s.phase = Phase::Failed(format!("Could not take tTerm {version}: {why}. tTerm stays as it is."));
                        s.next = Some(version.clone());
                    }
                });
            }
        }
    }

    /// Puts the version ready in the app's place, in one step, with the file
    /// of its trial; with `relaunch` the version before watches the new one
    /// start (`finish`). The app quits right after. Only as it was checked
    /// (`tree_digest`): it may have waited beside the app for days. What goes
    /// wrong leaves the app as it was and the version ready, for Restart
    /// again, unless it changed, or GitHub took it back meanwhile.
    pub fn install(&self, relaunch: bool, background: bool) -> Result<String, String> {
        let bundle = self.config.bundle.clone().ok_or("tTerm runs from a build, not from tTerm.app.")?;
        // From Ready to Installing in one step, never while tidying: a look
        // that ends meanwhile leaves it alone, and so does tidying.
        let mut taken = None;
        {
            let _tidying = self.tidying.lock().unwrap();
            self.state.send_modify(|s| {
                if let Phase::Ready { version, staged, digest } = &s.phase {
                    taken = Some((version.clone(), staged.clone(), digest.clone()));
                    s.phase = Phase::Installing(version.clone());
                }
            });
        }
        let (version, staged, digest) = taken.ok_or("No new version is ready.")?;
        let back = |why: String| {
            let withdrawn = self.withdrawn.lock().unwrap().take().is_some_and(|w| w == version);
            let mut dropped = false;
            self.set(|s| {
                if matches!(s.phase, Phase::Installing(_)) {
                    if withdrawn {
                        s.phase = Phase::Idle;
                        s.next = None;
                        dropped = true;
                    } else {
                        s.phase = Phase::Ready { version: version.clone(), staged: staged.clone(), digest: digest.clone() };
                    }
                }
            });
            if dropped {
                let _ = remove_tree(&staged);
                self.look_again();
            }
            why
        };
        let file = trial_file(&self.config.data_dir);
        let trial = Trial { from: self.config.current.clone(), to: version.clone(), app: bundle.clone(), old: staged.clone(), at: now_ms(), relaunch, background, pid: None, started: None, watcher: None, watcher_started: None, ok: false, rolled_back: false };
        {
            // Under the trial file's lock, from the last look at what goes in
            // to the swap: another copy of the app at the same place changes
            // nothing of it meanwhile (`stage`, its `install`).
            let Some(_held) = lock(&self.config.data_dir, LOCK_WAIT) else {
                return Err(back("Could not put the new version in: another tTerm is updating itself. Try again in a moment.".into()));
            };
            if self.replaced() {
                // Another copy has put a version in: nothing of this one's
                // goes in, and nothing beside the app is touched (it may be
                // that version's version before).
                self.withdrawn.lock().unwrap().take();
                self.set(|s| {
                    if matches!(s.phase, Phase::Installing(_)) {
                        s.phase = Phase::Idle;
                        s.next = None;
                    }
                });
                return Err("Another tTerm has put a new version in place already. Quit this one, and open tTerm again.".into());
            }
            if tree_digest(&staged).ok().as_deref() != Some(digest.as_str()) {
                let _ = remove_tree(&staged);
                let why = format!("tTerm {version}, waiting beside tTerm, changed since it was checked, and does not go in. It is taken again.");
                self.withdrawn.lock().unwrap().take();
                self.set(|s| {
                    s.phase = Phase::Failed(why.clone());
                    s.next = Some(version.clone());
                });
                self.look_again();
                return Err(why);
            }
            // The trial written down before anything moves: tTerm ended
            // between here and its watcher (a logout) leaves a new version
            // that is still watched when it starts, or the version before
            // with a trial that is not its own, which it drops.
            write_trial(&file, &trial).map_err(|e| back(format!("Could not write down the update: {e}")))?;
            if let Err(e) = swap(&staged, &bundle) {
                let _ = std::fs::remove_file(&file);
                return Err(back(not_in_place(&version, &e)));
            }
        }
        register(&bundle);
        if relaunch {
            // The version before watching it start, or all back as it was.
            // Should even that not work, the new version stays in, with its
            // trial: it is watched when it starts.
            let undo = |why: String| -> String {
                let swapped_back = match lock(&self.config.data_dir, LOCK_WAIT) {
                    Some(_held) => {
                        // Only while no start of the new version has taken
                        // its trial: one that has is in place, and watched.
                        let unclaimed = read_trial(&file).is_some_and(|t| t.to == version && t.pid.is_none() && !t.ok && !t.rolled_back);
                        let done = unclaimed && swap(&staged, &bundle).is_ok();
                        if done {
                            let _ = std::fs::remove_file(&file);
                        }
                        done
                    }
                    None => false,
                };
                if swapped_back {
                    return back(why);
                }
                self.withdrawn.lock().unwrap().take();
                let said = format!("tTerm {version} is in place, and the version before cannot watch it start ({why}). Quit tTerm and open it again.");
                self.set(|s| {
                    s.phase = Phase::Failed(said.clone());
                    s.next = Some(version.clone());
                });
                said
            };
            let watcher = program(&staged).map_err(|e| undo(format!("The version before cannot watch: {e}")))?;
            let spawned = Command::new(watcher)
                .arg("--finish-update")
                .arg(&file)
                .arg(std::process::id().to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .map_err(|e| undo(format!("The version before cannot watch: {e}")))?;
            let (watcher, started) = reap(spawned);
            // Written down: the new version, started, sees it is watched.
            if let Some(_held) = lock(&self.config.data_dir, LOCK_WAIT) {
                if let Some(now) = read_trial(&file) {
                    let _ = write_trial(&file, &Trial { watcher: Some(watcher), watcher_started: started, ..now });
                }
            }
        }
        Ok(version)
    }

    /// Copies tTerm to Applications, in the place of one there: where the app
    /// opens from next, once this one has quit.
    pub fn move_to_applications(&self) -> Result<PathBuf, String> {
        let bundle = self.config.bundle.clone().ok_or("tTerm runs from a build, not from tTerm.app.")?;
        let apps = Path::new("/Applications");
        if !cfg!(target_os = "macos") {
            return Err("Only tTerm for Mac moves itself.".into());
        }
        if !writable(apps) {
            return Err("Your account cannot change Applications. Drag tTerm there in Finder.".into());
        }
        let target = apps.join(APP_NAME);
        if let Ok(there) = read_plist(&target) {
            if there.identifier == BUNDLE_ID && newer(&there.version, &self.config.current) {
                return Err(format!("A newer tTerm ({}) is in Applications: open that one.", there.version));
            }
        }
        let copy = apps.join(format!(".tTerm-move-{}", std::process::id()));
        let _ = remove_tree(&copy);
        run(Command::new("/usr/bin/ditto").arg("--noqtn").arg(&bundle).arg(&copy), TOOL_TIME, None).map_err(|e| {
            let _ = remove_tree(&copy);
            format!("Could not copy tTerm to Applications ({e})")
        })?;
        let placed = if std::fs::symlink_metadata(&target).is_ok() {
            swap(&copy, &target).map(|()| {
                let _ = remove_tree(&copy);
            })
        } else {
            std::fs::rename(&copy, &target)
        };
        placed.map_err(|e| {
            let _ = remove_tree(&copy);
            format!("Could not put tTerm in Applications ({e})")
        })?;
        Ok(target)
    }

    /// Settings' Update by itself or Ask me first.
    pub fn set_mode(&self, engine: &Engine, mode: &str) -> Result<(), String> {
        if !crate::settings::UPDATES.contains(&mode) {
            return Err("Say mode: auto or ask.".into());
        }
        engine.save_settings(|s| s.updates = mode.to_string()).map(|_| ()).map_err(|_| "Could not save the settings on this computer.".to_string())
    }
}

/// Why the version ready did not go in place. On a Mac from 13 on, App
/// Management may keep an app from changing apps, its own too, until the
/// person allows it.
fn not_in_place(version: &str, error: &std::io::Error) -> String {
    if cfg!(target_os = "macos") && matches!(error.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
        format!("macOS did not let tTerm put tTerm {version} in its place ({error}). Allow tTerm in System Settings, Privacy & Security, App Management, and press Restart to update again.")
    } else {
        format!("Could not put tTerm {version} in place: {error}")
    }
}

/// Whether the app can update itself from where it runs: why not, and
/// whether moving it to Applications helps.
fn usable(config: &Config) -> Result<(), (String, bool)> {
    if !cfg!(target_os = "macos") && !config.anywhere {
        return Err(("Only tTerm for Mac updates itself.".into(), false));
    }
    let Some(bundle) = &config.bundle else {
        return Err(("This tTerm runs from a build, not from tTerm.app: it does not update itself.".into(), false));
    };
    let path = bundle.to_string_lossy();
    if path.contains("/AppTranslocation/") {
        return Err((FROM_DISK_IMAGE.into(), true));
    }
    let parent = bundle.parent().unwrap_or(Path::new("/"));
    if !writable(parent) || !writable(bundle) {
        if path.starts_with("/Volumes/") {
            return Err((FROM_DISK_IMAGE.into(), true));
        }
        return Err((format!("tTerm cannot change {}, where it is, so it cannot update itself. Download the new version from tterm.net.", parent.display()), false));
    }
    Ok(())
}

/// The program as its own --version: what the watcher of the version before
/// asks of a new one. Some(the version) when that is what was asked.
pub fn version_main(args: &[String]) -> Option<String> {
    (args.get(1).map(String::as_str) == Some("--version")).then(Config::version_said)
}

// The checks of the parts that need no network are here; the looks, the
// downloads and the whole update against releases on this computer are in
// tests/update.rs.
#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::os::unix::fs::PermissionsExt;

    fn keys() -> (Ed25519KeyPair, [u8; 32]) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
        (pair, public)
    }

    fn signed(pair: &Ed25519KeyPair, manifest: &[u8]) -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(pair.sign(manifest).as_ref()).into_bytes()
    }

    fn folder(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tterm-update-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn versions() {
        assert!(newer("0.5.1", "0.5.0") && newer("0.10.0", "0.9.9") && newer("1.0.0", "0.99.99"));
        assert!(!newer("0.5.0", "0.5.0") && !newer("0.4.9", "0.5.0"));
        assert!(!newer("0.6", "0.5.0") && !newer("0.6.0-beta", "0.5.0") && !newer("0.+6.0", "0.5.0"));
        // macOS: the version a bundle needs, against this Mac's.
        let v = |t: &str| system_version(t).unwrap();
        assert_eq!(v("13.6.1"), [13, 6, 1]);
        assert_eq!(v("26.0"), [26, 0]);
        assert_eq!(v(" 14 "), [14]);
        assert!(system_version("").is_none() && system_version("14.x").is_none() && system_version("1.2.3.4.5").is_none() && system_version("+14").is_none());
        assert!(system_older(&v("13.6.1"), &v("14.0")) && system_older(&v("10.15.7"), &v("11.0")) && system_older(&v("11"), &v("11.0.1")));
        assert!(!system_older(&v("14.0"), &v("14")) && !system_older(&v("11.0"), &v("11.0")) && !system_older(&v("26.0"), &v("11.0")));
    }

    #[test]
    fn what_a_bundle_holds_is_one_digest() {
        let dir = folder("digest");
        let make = |at: &Path| {
            std::fs::create_dir_all(at.join("Contents/MacOS")).unwrap();
            std::fs::write(at.join("Contents/Info.plist"), "plist").unwrap();
            std::fs::write(at.join("Contents/MacOS/tterm"), "program").unwrap();
            std::fs::set_permissions(at.join("Contents/MacOS/tterm"), std::fs::Permissions::from_mode(0o755)).unwrap();
            std::os::unix::fs::symlink("MacOS/tterm", at.join("Contents/link")).unwrap();
        };
        let (a, b) = (dir.join("a.app"), dir.join("b.app"));
        make(&a);
        make(&b);
        let digest = tree_digest(&a).unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(tree_digest(&b).unwrap(), digest, "the same, wherever it is");
        // Whatever changes in it, the digest does.
        std::fs::write(b.join("Contents/MacOS/tterm"), "programme").unwrap();
        let changed = tree_digest(&b).unwrap();
        assert_ne!(changed, digest, "a file's bytes");
        std::fs::write(b.join("Contents/MacOS/tterm"), "program").unwrap();
        assert_eq!(tree_digest(&b).unwrap(), digest);
        std::fs::set_permissions(b.join("Contents/MacOS/tterm"), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_ne!(tree_digest(&b).unwrap(), digest, "a mode");
        std::fs::set_permissions(b.join("Contents/MacOS/tterm"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(b.join("Contents/extra"), "").unwrap();
        assert_ne!(tree_digest(&b).unwrap(), digest, "a file more");
        std::fs::remove_file(b.join("Contents/extra")).unwrap();
        std::fs::remove_file(b.join("Contents/link")).unwrap();
        std::os::unix::fs::symlink("/bin/sh", b.join("Contents/link")).unwrap();
        assert_ne!(tree_digest(&b).unwrap(), digest, "a link's target");
        std::fs::remove_file(b.join("Contents/link")).unwrap();
        std::os::unix::fs::symlink("MacOS/tterm", b.join("Contents/link")).unwrap();
        assert_eq!(tree_digest(&b).unwrap(), digest);
        // What Finder writes, looking at the folder, is not the app's.
        std::fs::write(b.join(".DS_Store"), "finder").unwrap();
        std::fs::write(b.join("Contents/.DS_Store"), "finder").unwrap();
        assert_eq!(tree_digest(&b).unwrap(), digest);
        // A pipe is no file of an app.
        let fifo = CString::new(b.join("Contents/fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        assert!(tree_digest(&b).is_err());
        assert!(tree_digest(&dir.join("nothing.app")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_newest_app_release_is_picked_not_the_agents() {
        use serde_json::json;
        let asset = |tag: &str, name: &str| json!({"name": name, "browser_download_url": format!("https://github.com/tterm-net/tterm-app/releases/download/{tag}/{name}")});
        let release = |tag: &str, draft: bool, pre: bool| json!({"tag_name": tag, "draft": draft, "prerelease": pre, "assets": [asset(tag, MANIFEST), asset(tag, SIGNATURE), asset(tag, "tTerm.app.tar.gz")]});
        let list: Vec<Listed> = serde_json::from_value(json!([
            release("agent-v9.9.9", false, false),
            release("v0.7.0", true, false),
            release("v0.8.0", false, true),
            release("v0.5.2", false, false),
            release("v0.6.1", false, false),
            {"tag_name": "v0.6.9", "draft": false, "prerelease": false, "assets": [asset("v0.6.9", MANIFEST)]},
            release("v0.4.0", false, false),
            release("vx.y.z", false, false),
        ]))
        .unwrap();
        let picked = pick(&list, "0.5.0").unwrap();
        assert_eq!(picked.version, "0.6.1");
        assert!(picked.url("tTerm.app.tar.gz").unwrap().ends_with("/v0.6.1/tTerm.app.tar.gz"));
        assert_eq!(pick(&list, "0.6.1"), None, "nothing newer");
        assert_eq!(pick(&list, "0.6.0").unwrap().version, "0.6.1");
    }

    #[test]
    fn only_the_apps_signed_list_counts() {
        let (pair, public) = keys();
        let make = |m: Value| serde_json::to_vec(&m).unwrap();
        let file = json!({"name": "tTerm.app.tar.gz", "size": 1234, "sha256": "AB".repeat(32)});
        let manifest = make(json!({"product": PRODUCT, "version": "0.5.1", "files": {"macos": file}}));
        let wanted = verify(&manifest, &signed(&pair, &manifest), &public, "0.5.1").unwrap();
        assert_eq!(wanted, Wanted { name: "tTerm.app.tar.gz".into(), size: 1234, sha256: "ab".repeat(32) });
        assert!(verify(&manifest, &signed(&pair, &manifest), &public, "0.5.2").is_err(), "another version");
        let (other, _) = keys();
        assert!(verify(&manifest, &signed(&other, &manifest), &public, "0.5.1").is_err(), "another key");
        // The agent's list, signed with the same key, is not the app's.
        let agents = make(json!({"version": "0.5.1", "files": {"macos": {"name": "tterm-agent-macos", "size": 9, "sha256": "ab".repeat(32)}}}));
        assert_eq!(verify(&agents, &signed(&pair, &agents), &public, "0.5.1"), Err("the signed list is not tTerm's app's".into()));
        for bad in [
            json!({"name": "../x.tar.gz", "size": 1, "sha256": "ab".repeat(32)}),
            json!({"name": "tterm-agent-macos", "size": 1, "sha256": "ab".repeat(32)}),
            json!({"name": "x.tar.gz", "size": FILE_MAX + 1, "sha256": "ab".repeat(32)}),
            json!({"name": "x.tar.gz", "size": 0, "sha256": "ab".repeat(32)}),
            json!({"name": "x.tar.gz", "size": 1, "sha256": "zz".repeat(32)}),
        ] {
            let evil = make(json!({"product": PRODUCT, "version": "0.5.1", "files": {"macos": bad}}));
            assert!(verify(&evil, &signed(&pair, &evil), &public, "0.5.1").is_err(), "{bad}");
        }
    }

    #[test]
    fn the_key_built_in_is_the_agents() {
        assert_eq!(PUBLIC_KEY_HEX.trim(), "657dc196a166183d1e7b6bb90bda4e5d2fca83d7479c5dde4d61eeb982d4f971");
        assert!(public_key().is_some());
    }

    #[test]
    fn a_bundle_and_its_plist() {
        assert_eq!(bundle_of(Path::new("/Applications/tTerm.app/Contents/MacOS/tterm")), Some(PathBuf::from("/Applications/tTerm.app")));
        assert_eq!(bundle_of(Path::new("/Users/d/Work/tterm-app/target/debug/tterm")), None);
        assert_eq!(bundle_of(Path::new("/Applications/.tTerm-0.5.1.update/Contents/MacOS/tterm")), None, "no app");
        let xml = "<?xml version=\"1.0\"?>\n<plist version=\"1.0\">\n<dict>\n\t<key>CFBundleExecutable</key>\n\t<string>tterm</string>\n\t<key>CFBundleIdentifier</key>\n\t<string>net.tterm.desktop</string>\n\t<key>CFBundleShortVersionString</key>\n\t<string>0.5.1</string>\n\t<key>NSHumanReadableCopyright</key>\n\t<string>&#169; tTerm &amp; co</string>\n</dict>\n</plist>\n";
        assert_eq!(plist_string(xml, "CFBundleShortVersionString").as_deref(), Some("0.5.1"));
        assert_eq!(plist_string(xml, "CFBundleIdentifier").as_deref(), Some("net.tterm.desktop"));
        assert_eq!(plist_string(xml, "Nothing"), None);
        assert_eq!(staged_for(Path::new("/Applications/tTerm.app"), "0.5.1"), PathBuf::from("/Applications/.tTerm-0.5.1.update"));
        assert!(ours_beside(Path::new("/Applications/tTerm.app"), Path::new("/Applications/.tTerm-0.5.1.update")));
        assert!(!ours_beside(Path::new("/Applications/tTerm.app"), Path::new("/Applications/Safari.app")));
        assert!(!ours_beside(Path::new("/Applications/tTerm.app"), Path::new("/tmp/.tTerm-0.5.1.update")));
    }

    #[test]
    fn two_folders_swap_in_one_step() {
        let dir = folder("swap");
        let (a, b) = (dir.join("tTerm.app"), dir.join(".tTerm-0.5.1.update"));
        std::fs::create_dir_all(a.join("Contents")).unwrap();
        std::fs::create_dir_all(b.join("Contents")).unwrap();
        std::fs::write(a.join("Contents/which"), "old").unwrap();
        std::fs::write(b.join("Contents/which"), "new").unwrap();
        swap(&b, &a).unwrap();
        assert_eq!(std::fs::read_to_string(a.join("Contents/which")).unwrap(), "new");
        assert_eq!(std::fs::read_to_string(b.join("Contents/which")).unwrap(), "old");
        assert!(swap(&dir.join("nothing"), &a).is_err());
        assert_eq!(std::fs::read_to_string(a.join("Contents/which")).unwrap(), "new", "as it was");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_trial_file_names_only_the_apps_place() {
        let dir = folder("trial");
        let file = trial_file(&dir);
        let trial = Trial { from: "0.5.0".into(), to: "0.5.1".into(), app: "/Applications/tTerm.app".into(), old: "/Applications/.tTerm-0.5.1.update".into(), at: 1, relaunch: true, background: false, pid: None, started: None, watcher: Some(7), watcher_started: Some("1.5".into()), ok: false, rolled_back: false };
        write_trial(&file, &trial).unwrap();
        assert_eq!(read_trial(&file), Some(trial.clone()));
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        for evil in [
            Trial { old: "/Users/d/Documents".into(), ..trial.clone() },
            Trial { app: "/etc/passwd".into(), old: "/etc/.tTerm-0.5.1.update".into(), ..trial.clone() },
            Trial { app: "relative/tTerm.app".into(), old: "relative/.tTerm-0.5.1.update".into(), ..trial.clone() },
            Trial { to: "0.5.1/../..".into(), old: "/Applications/.tTerm-0.5.1/../...update".into(), ..trial.clone() },
        ] {
            write_trial(&file, &evil).unwrap();
            assert_eq!(read_trial(&file), None, "{evil:?}");
        }
        std::fs::write(&file, "not json").unwrap();
        assert_eq!(read_trial(&file), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
