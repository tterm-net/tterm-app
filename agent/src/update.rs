//! Updating itself. A new version of the agent comes from tTerm's releases
//! on GitHub, where the release build signs the list of its files,
//! tterm-agent.json, with a key only that build holds (its secrets); the
//! agent takes a file only when that signature checks against the public
//! half built into it (agent/release-key.pub), and the file against the
//! list. The agent holds shells, so a file put in its place by anyone else
//! would be a way into the computer: not GitHub's word, nor the network's,
//! but the signature decides. GitHub decides only whether there is a new
//! version and which: it can hold one back, never make one up.
//!
//! It replaces itself only while no terminal is open on the computer, so as
//! not to end anybody's work, and starts again as the new version in the same
//! process: autostart (launchd, systemd) sees nothing. Before that the new
//! file is asked its version; one that does not say it is not put in place.
//! The file it replaced stays next to it, as tterm-agent.old.
//!
//! A new version is on trial until it has connected to tTerm Web and stayed
//! up a while (tterm-agent.trial counts its starts). One that stops again
//! and again, cannot start with these settings, or does not connect at all
//! goes, and the one before comes back; the version is written in
//! tterm-agent.skip and not taken again. A release can be stopped by making
//! it a pre-release or deleting it: agents do not take it from then on, and
//! one waiting for its terminals to close looks again within LOOK_EVERY.
//!
//! Only an agent an installer put in place updates itself: one started with
//! its settings file next to it, in a folder of the person's own that no one
//! else can write to (~/.tterm-web). One started by hand, to try a version,
//! stays the version it is. TTERM_UPDATE=off in the settings file turns it
//! off.
//!
//! GitHub is reached the way tTerm Web is (link.rs): the same TLS, with the
//! roots built in and the system's own, and the same proxy, if this
//! computer has one (proxy.rs). Only over HTTPS, redirects included.

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tterm_engine::proxy::{self, System};

/// Where the releases are listed: tTerm's app and the agent share the
/// repository, the agent's tags start with TAG.
pub const RELEASES: &str = "https://api.github.com/repos/tterm-net/tterm-app/releases?per_page=100";
/// The tags of the agent's releases: agent-v0.14.1.
pub const TAG: &str = "agent-v";
/// The list of a release's files and its signature, among its files.
pub const MANIFEST: &str = "tterm-agent.json";
pub const SIGNATURE: &str = "tterm-agent.json.sig";

/// The public half of the release key, as hex. The owner made the key with
/// its private half going straight into the release build's secrets. It
/// never changes: agents out there know only this one.
pub const PUBLIC_KEY_HEX: &str = include_str!("../release-key.pub");

/// The first look a while after the start, so that the link comes up first
/// and an agent restarted in a loop does not ask GitHub every time; then
/// every few hours.
pub const FIRST_LOOK: Duration = Duration::from_secs(120);
pub const LOOK_EVERY: Duration = Duration::from_secs(6 * 3600);
/// While a newer version waits for the terminals to close.
pub const WAIT_STEP: Duration = Duration::from_secs(60);

/// A new version on trial: started this many times without staying up, it
/// goes back to the one before.
pub const TRIAL_STARTS: u32 = 3;
/// Connected, and up this long since its start: it stays.
pub const TRIAL_UP: Duration = Duration::from_secs(10 * 60);
/// Not connected this long after its start: back to the one before. A
/// computer without a network meanwhile keeps the version before too, until
/// the next release; a safe mistake.
pub const TRIAL_CONNECT: Duration = Duration::from_secs(15 * 60);
pub const TRIAL_STEP: Duration = Duration::from_secs(30);

/// A file of the agent, at most: a few megabytes, and room to grow.
pub const FILE_MAX: u64 = 64 * 1024 * 1024;
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
/// A new file says its version within this.
const PROBE_TIME: Duration = Duration::from_secs(10);

/// Which of the release's files is this system's.
pub fn platform() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", _) => Some("macos"),
        ("linux", "x86_64") => Some("linux-x86_64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        _ => None,
    }
}

/// The public key built in; None if release-key.pub holds no key.
pub fn public_key() -> Option<[u8; 32]> {
    let hex = PUBLIC_KEY_HEX.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    (key != [0u8; 32]).then_some(key)
}

/// A version as numbers: "0.14.1" → [0, 14, 1]; None for anything else.
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

/// A release in GitHub's list, what the agent reads of it; the rest is
/// skipped as it is read.
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

/// A release newer than this agent: its version, and where each of its
/// files is.
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

/// The newest of the agent's releases in GitHub's list, if newer than
/// `newer_than` and it has its list of files and their signature. Drafts
/// and pre-releases are not taken.
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

/// What the signed list says of this system's file: its name among the
/// release's files, its size and its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// Checks the signature over the list as it came, byte for byte, and only
/// then reads it: for `version_wanted`, the file for `platform`.
pub fn verify(manifest: &[u8], signature: &[u8], key: &[u8; 32], version_wanted: &str, platform: &str) -> Result<Wanted, String> {
    use base64::Engine as _;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(String::from_utf8_lossy(signature).trim())
        .map_err(|_| "the signature is not base64".to_string())?;
    UnparsedPublicKey::new(&ED25519, key).verify(manifest, &sig).map_err(|_| "the signature does not check".to_string())?;
    let m: Value = serde_json::from_slice(manifest).map_err(|_| "the signed list is not understood".to_string())?;
    if m.get("version").and_then(Value::as_str) != Some(version_wanted) {
        return Err("the signed list is for another version".into());
    }
    let file = m.get("files").and_then(|f| f.get(platform)).ok_or_else(|| format!("the signed list has no file for {platform}"))?;
    let name = file.get("name").and_then(Value::as_str).unwrap_or("");
    let size = file.get("size").and_then(Value::as_u64).unwrap_or(0);
    let sha256 = file.get("sha256").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
    let plain = !name.is_empty() && !name.starts_with('.') && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if !plain || size == 0 || size > FILE_MAX || sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("the signed list's file for {platform} is not one"));
    }
    Ok(Wanted { name: name.to_string(), size, sha256 })
}

pub fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `file` is a program for `platform` on this computer, by its first
/// bytes: a release with its files mixed up must not take the place of an
/// agent that runs, for one that cannot start.
pub fn program_for(platform: &str, file: &[u8]) -> bool {
    let u16le = |at: usize| file.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32le = |at: usize| file.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let u32be = |at: usize| file.get(at..at + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    // 64 bits, little-endian, and the processor.
    let elf = |machine: u16| file.starts_with(b"\x7fELF\x02\x01") && u16le(18) == Some(machine);
    match platform {
        "linux-x86_64" => elf(62),
        "linux-arm64" => elf(183),
        "macos" => {
            let cpu: u32 = match std::env::consts::ARCH {
                "aarch64" => 0x0100_000c,
                "x86_64" => 0x0100_0007,
                _ => return false,
            };
            if u32be(0) == Some(0xcafe_babe) {
                // Universal: Apple silicon and Intel in one; this Mac's among them.
                let count = u32be(4).unwrap_or(0).min(8) as usize;
                (0..count).any(|i| u32be(8 + i * 20) == Some(cpu))
            } else {
                u32le(0) == Some(0xfeed_facf) && u32le(4) == Some(cpu)
            }
        }
        _ => false,
    }
}

/// A client for each request, by its address.
pub type Clients = dyn Fn(&reqwest::Url) -> Result<reqwest::Client, String> + Send + Sync;

/// The agent's own way to GitHub: the link's TLS (link::tls_config), HTTPS
/// only, redirects followed by `get`, and the proxy the link would take to
/// that host, chosen for each host the way it is chosen for the hub.
pub fn clients(user_agent: String, env: HashMap<String, String>, system: Option<System>) -> impl Fn(&reqwest::Url) -> Result<reqwest::Client, String> + Send + Sync {
    move |url: &reqwest::Url| {
        let host = url.host_str().unwrap_or("").trim_start_matches('[').trim_end_matches(']');
        let port = url.port_or_known_default().unwrap_or(443);
        let mut builder = reqwest::Client::builder()
            .use_preconfigured_tls((*tterm_engine::link::tls_config()).clone())
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

/// The agent's clients, through the proxy in `proxy_env` (the *_proxy
/// variables), or on macOS when they name none, the system's: as the link.
async fn agent_clients(proxy_env: &[(String, String)]) -> impl Fn(&reqwest::Url) -> Result<reqwest::Client, String> + Send + Sync {
    let env = proxy::from_environment(proxy_env);
    let system = if env.is_empty() { proxy::system().await } else { None };
    clients(format!("tterm-agent/{}", crate::VERSION), env, system)
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

/// An address as the log says it: without its query.
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
/// `releases`, for `platform`, its signed list checked.
pub async fn find(clients: &Clients, releases: &str, newer_than: &str, key: &[u8; 32], platform: &str) -> Result<Option<Found>, String> {
    let list = get(clients, releases, "application/vnd.github+json", LIST_MAX, SMALL_TIMEOUT).await?;
    let list: Vec<Listed> = serde_json::from_slice(&list).map_err(|_| "GitHub's list of releases is not understood".to_string())?;
    let Some(release) = pick(&list, newer_than) else { return Ok(None) };
    let binary = "application/octet-stream";
    let manifest = get(clients, release.url(MANIFEST)?, binary, MANIFEST_MAX, SMALL_TIMEOUT).await?;
    let signature = get(clients, release.url(SIGNATURE)?, binary, SIGNATURE_MAX, SMALL_TIMEOUT).await?;
    let wanted = verify(&manifest, &signature, key, &release.version, platform).map_err(|why| format!("version {}: {why}", release.version))?;
    let url = release.url(&wanted.name)?.to_string();
    Ok(Some(Found { version: release.version, wanted, url }))
}

/// The file `found` names, checked against its signed list and for this
/// computer.
pub async fn download(clients: &Clients, found: &Found, platform: &str) -> Result<Vec<u8>, String> {
    let file = get(clients, &found.url, "application/octet-stream", found.wanted.size, FILE_TIMEOUT).await?;
    if file.len() as u64 != found.wanted.size || sha256_hex(&file) != found.wanted.sha256 {
        return Err(format!("version {}: {} is not the file its signed list names", found.version, found.wanted.name));
    }
    if !program_for(platform, &file) {
        return Err(format!("version {}: {} is not a program for {platform}", found.version, found.wanted.name));
    }
    Ok(file)
}

/// `find`, then `download`: a newer version and its file, checked.
pub async fn fetch(clients: &Clients, releases: &str, newer_than: &str, key: &[u8; 32], platform: &str) -> Result<Option<(String, Vec<u8>)>, String> {
    let Some(found) = find(clients, releases, newer_than, key, platform).await? else { return Ok(None) };
    let file = download(clients, &found, platform).await?;
    Ok(Some((found.version, file)))
}

/// A look at tTerm's releases for a version newer than `newer_than`, the
/// way the link reaches tTerm Web.
pub async fn look(newer_than: &str, key: &[u8; 32], platform: &str, proxy_env: &[(String, String)]) -> Result<Option<Found>, String> {
    let clients = agent_clients(proxy_env).await;
    find(&clients, RELEASES, newer_than, key, platform).await
}

/// The file of a version found by `look`.
pub async fn get_file(found: &Found, platform: &str, proxy_env: &[(String, String)]) -> Result<Vec<u8>, String> {
    let clients = agent_clients(proxy_env).await;
    download(&clients, found, platform).await
}

fn beside(exe: &Path, ext: &str) -> PathBuf {
    let mut p = exe.as_os_str().to_owned();
    p.push(ext);
    PathBuf::from(p)
}

/// A name of this process's own next to `exe`, for a file written before
/// it takes its place.
fn own_name(exe: &Path, what: &str) -> PathBuf {
    let name = exe.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    exe.with_file_name(format!(".{name}.{}.{what}", std::process::id()))
}

/// A new file at `path` and nothing else: never one that is there already,
/// or a link someone left at that name (O_EXCL).
fn create_new(path: &Path, mode: u32) -> std::io::Result<std::fs::File> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(path)
}

/// A small file written whole, in one step, under its name.
fn write_small(path: &Path, text: &str) -> std::io::Result<()> {
    let fresh = own_name(path, "tmp");
    let written = (|| {
        let mut f = create_new(&fresh, 0o600)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&fresh, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&fresh);
    }
    written
}

/// Why a new version was not put in place.
#[derive(Debug)]
pub enum NotReplaced {
    /// It does not start here: not to be taken again.
    DoesNotStart(String),
    Io(std::io::Error),
}

impl std::fmt::Display for NotReplaced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotReplaced::DoesNotStart(why) => write!(f, "{why}"),
            NotReplaced::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for NotReplaced {
    fn from(e: std::io::Error) -> NotReplaced {
        NotReplaced::Io(e)
    }
}

/// A file the system cannot run at all: not a program for it.
fn cannot_run(e: &std::io::Error) -> bool {
    // EBADARCH: a Mac's "bad CPU type in executable".
    matches!(e.raw_os_error(), Some(libc::ENOEXEC)) || (cfg!(target_os = "macos") && e.raw_os_error() == Some(86))
}

/// Runs `file --version` with nothing of the agent's environment: Ok when
/// it says `version` within `time`.
fn probe(file: &Path, version: &str, time: Duration) -> Result<(), NotReplaced> {
    use std::process::{Command, Stdio};
    let mut tries = 0;
    let mut child = loop {
        match Command::new(file).arg("--version").env_clear().stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
            Ok(child) => break child,
            // Still open for writing in a process started a moment ago on
            // another thread, until it runs its own program (Linux).
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && tries < 5 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) if cannot_run(&e) => return Err(NotReplaced::DoesNotStart(format!("version {version} does not start here: {e}"))),
            Err(e) => return Err(NotReplaced::Io(e)),
        }
    };
    let deadline = Instant::now() + time;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(NotReplaced::DoesNotStart(format!("version {version} did not say its version in time")));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut said = String::new();
    if let Some(out) = child.stdout.take() {
        let _ = out.take(1024).read_to_string(&mut said);
    }
    if status.success() && said.trim() == version {
        Ok(())
    } else {
        Err(NotReplaced::DoesNotStart(format!("version {version} does not start here ({status}, it said {:?})", said.trim())))
    }
}

/// Puts `file`, version `version`, in the place of the agent at `exe`:
/// written next to it under a name of this process's own, asked its version,
/// then moved over it in one step, the one there kept as .old. The place
/// never holds half a file, nor one that does not start.
pub fn replace(exe: &Path, file: &[u8], version: &str) -> Result<(), NotReplaced> {
    replace_with(exe, file, version, PROBE_TIME)
}

fn replace_with(exe: &Path, file: &[u8], version: &str, probe_time: Duration) -> Result<(), NotReplaced> {
    let fresh = own_name(exe, "new");
    let kept = own_name(exe, "old");
    let done = (|| -> Result<(), NotReplaced> {
        {
            let mut f = create_new(&fresh, 0o755)?;
            f.write_all(file)?;
            f.sync_all()?;
        }
        // Whatever the umask took away.
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o755))?;
        probe(&fresh, version, probe_time)?;
        if std::fs::hard_link(exe, &kept).is_err() {
            let mut from = std::fs::File::open(exe)?;
            let mut to = create_new(&kept, 0o755)?;
            std::io::copy(&mut from, &mut to)?;
            to.sync_all()?;
        }
        std::fs::rename(&kept, beside(exe, ".old"))?;
        std::fs::rename(&fresh, exe)?;
        Ok(())
    })();
    if done.is_err() {
        let _ = std::fs::remove_file(&fresh);
        let _ = std::fs::remove_file(&kept);
    }
    done?;
    if let Some(dir) = exe.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Where a version on trial counts its starts: "0.14.1 2".
pub fn trial_file(exe: &Path) -> PathBuf {
    beside(exe, ".trial")
}

/// The version that did not come up here, not to be taken again.
pub fn skip_file(exe: &Path) -> PathBuf {
    beside(exe, ".skip")
}

/// `version` goes in on trial (written before it takes the agent's place).
pub fn begin_trial(exe: &Path, version: &str) -> std::io::Result<()> {
    write_small(&trial_file(exe), &format!("{version} 0\n"))
}

/// Whether this start is a new version's on trial.
#[derive(Debug, PartialEq, Eq)]
pub enum Trial {
    No,
    On,
    /// Started TRIAL_STARTS times without staying up: back to the one before.
    Over,
}

/// The start of version `current` at `exe`, counted if it is on trial.
pub fn trial_start(exe: &Path, current: &str) -> Trial {
    let path = trial_file(exe);
    let Ok(text) = std::fs::read_to_string(&path) else { return Trial::No };
    let mut words = text.split_whitespace();
    let (Some(v), Some(starts)) = (words.next(), words.next().and_then(|n| n.parse::<u32>().ok())) else {
        let _ = std::fs::remove_file(&path);
        return Trial::No;
    };
    if v != current {
        // Left from another version: put back by hand, or by an installer.
        let _ = std::fs::remove_file(&path);
        return Trial::No;
    }
    let starts = starts.saturating_add(1);
    if starts > TRIAL_STARTS {
        return Trial::Over;
    }
    let _ = write_small(&path, &format!("{v} {starts}\n"));
    Trial::On
}

/// The version on trial stays.
pub fn trial_passed(exe: &Path) {
    let _ = std::fs::remove_file(trial_file(exe));
}

/// `version` is not taken again here.
pub fn skip(exe: &Path, version: &str) {
    let _ = write_small(&skip_file(exe), &format!("{version}\n"));
}

/// The version before goes back in the place of `version`, which is not
/// taken again.
pub fn roll_back(exe: &Path, version: &str) -> std::io::Result<()> {
    std::fs::rename(beside(exe, ".old"), exe)?;
    skip(exe, version);
    trial_passed(exe);
    Ok(())
}

/// A version that did not come up here, if it is newer than `current`.
pub fn skipped(exe: &Path, current: &str) -> Option<String> {
    let text = std::fs::read_to_string(skip_file(exe)).ok()?;
    let v = text.trim().to_string();
    newer(&v, current).then_some(v)
}

/// Whether this agent updates itself: an installer put it next to its
/// settings file, in a folder of this user's that no one else can write
/// to, and the file does not say TTERM_UPDATE=off.
pub fn enabled(exe: &Path, env_file: Option<&Path>, update_setting: Option<&str>) -> bool {
    let Some(env_file) = env_file else { return false };
    let (Some(dir), Some(env_dir)) = (exe.parent(), env_file.parent()) else { return false };
    let env_dir = if env_dir.as_os_str().is_empty() { Path::new(".") } else { env_dir };
    let same = matches!((std::fs::canonicalize(dir), std::fs::canonicalize(env_dir)), (Ok(a), Ok(b)) if a == b);
    let own = std::fs::metadata(dir).is_ok_and(|m| m.uid() == nix::unistd::geteuid().as_raw() && m.mode() & 0o022 == 0);
    same && own && !matches!(update_setting.map(|s| s.trim().to_ascii_lowercase()).as_deref(), Some("off" | "0" | "no" | "false"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;

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

    /// A folder of its own for one check, as an installer makes it.
    fn folder(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tterm-agent-update-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    /// A program that says `version` when asked, as the agent does.
    fn says(version: &str) -> Vec<u8> {
        format!("#!/bin/sh\n[ \"$1\" = --version ] && echo {version}\n").into_bytes()
    }

    #[test]
    fn versions() {
        assert!(newer("0.14.1", "0.14.0"));
        assert!(newer("0.15.0", "0.14.9"));
        assert!(newer("1.0.0", "0.99.99"));
        assert!(newer("0.14.10", "0.14.9"), "as numbers, not as text");
        assert!(!newer("0.14.0", "0.14.0"));
        assert!(!newer("0.13.9", "0.14.0"));
        assert!(!newer("0.15", "0.14.0") && !newer("x.y.z", "0.1.0") && !newer("0.15.0-rc1", "0.14.0"));
        assert!(!newer("0.+15.0", "0.14.0") && !newer("0.15.0 ", "0.14.0") && !newer("0..15", "0.0.0"), "digits only");
    }

    #[test]
    fn the_newest_agent_release_is_picked() {
        let asset = |tag: &str, name: &str| json!({"name": name, "browser_download_url": format!("https://github.com/tterm-net/tterm-app/releases/download/{tag}/{name}")});
        let release = |tag: &str, draft: bool, pre: bool| {
            json!({"tag_name": tag, "draft": draft, "prerelease": pre, "body": "notes", "assets": [asset(tag, MANIFEST), asset(tag, SIGNATURE), asset(tag, "tterm-agent-macos")]})
        };
        let list: Vec<Listed> = serde_json::from_value(json!([
            release("v0.3.0", false, false),
            release("agent-v0.16.0", true, false),
            release("agent-v0.17.0", false, true),
            release("agent-v0.14.2", false, false),
            release("agent-v0.15.1", false, false),
            {"tag_name": "agent-v0.15.9", "draft": false, "prerelease": false, "assets": [asset("agent-v0.15.9", MANIFEST)]},
            release("agent-v0.13.0", false, false),
        ]))
        .unwrap();
        let picked = pick(&list, "0.14.0").unwrap();
        assert_eq!(picked.version, "0.15.1");
        assert!(picked.url(MANIFEST).unwrap().ends_with("/agent-v0.15.1/tterm-agent.json"));
        assert!(picked.url(SIGNATURE).unwrap().ends_with("/agent-v0.15.1/tterm-agent.json.sig"));
        assert!(picked.url("tterm-agent-macos").unwrap().ends_with("/agent-v0.15.1/tterm-agent-macos"));
        assert!(picked.url("tterm-agent-linux-x86_64").is_err());
        assert_eq!(pick(&list, "0.15.1"), None, "nothing newer");
        assert!(serde_json::from_value::<Vec<Listed>>(json!({"message": "API rate limit exceeded"})).is_err());
        assert!(serde_json::from_slice::<Vec<Listed>>(&vec![b'0'; 1000]).is_err());
    }

    #[test]
    fn only_a_signed_list_counts() {
        let (pair, public) = keys();
        let manifest = serde_json::to_vec(&json!({
            "version": "0.14.1",
            "files": {
                "macos": {"name": "tterm-agent-macos", "size": 1234, "sha256": "AB".repeat(32)},
                "linux-x86_64": {"name": "tterm-agent-linux-x86_64", "size": 99, "sha256": "cd".repeat(32)}
            }
        }))
        .unwrap();
        let sig = signed(&pair, &manifest);
        let wanted = verify(&manifest, &sig, &public, "0.14.1", "macos").unwrap();
        assert_eq!(wanted, Wanted { name: "tterm-agent-macos".into(), size: 1234, sha256: "ab".repeat(32) });
        assert!(verify(&manifest, &sig, &public, "0.14.2", "macos").is_err(), "another version");
        assert!(verify(&manifest, &sig, &public, "0.14.1", "linux-arm64").is_err(), "no file for it");
        let mut tampered = manifest.clone();
        let at = tampered.iter().position(|&c| c == b'9').unwrap();
        tampered[at] = b'8';
        assert_eq!(verify(&tampered, &sig, &public, "0.14.1", "macos"), Err("the signature does not check".into()));
        let (other, _) = keys();
        assert!(verify(&manifest, &signed(&other, &manifest), &public, "0.14.1", "macos").is_err(), "another key");
        assert!(verify(&manifest, b"not base64!", &public, "0.14.1", "macos").is_err());
        assert!(verify(&manifest, b"", &public, "0.14.1", "macos").is_err());
        // Signed, and still not taken: a name that would leave the release,
        // or say something odd in the log; a file too large or empty, a
        // checksum that is not one.
        for file in [
            json!({"name": "../x", "size": 1, "sha256": "ab".repeat(32)}),
            json!({"name": ".hidden", "size": 1, "sha256": "ab".repeat(32)}),
            json!({"name": "x\ny", "size": 1, "sha256": "ab".repeat(32)}),
            json!({"name": "x", "size": FILE_MAX + 1, "sha256": "ab".repeat(32)}),
            json!({"name": "x", "size": 0, "sha256": "ab".repeat(32)}),
            json!({"name": "x", "size": 1, "sha256": "zz".repeat(32)}),
            json!({"name": "x", "size": "1", "sha256": "ab".repeat(32)}),
        ] {
            let evil = serde_json::to_vec(&json!({"version": "0.14.1", "files": {"macos": file}})).unwrap();
            assert!(verify(&evil, &signed(&pair, &evil), &public, "0.14.1", "macos").is_err(), "{file}");
        }
    }

    #[test]
    fn programs_for_each_system() {
        let elf = |machine: u16| {
            let mut f = b"\x7fELF\x02\x01\x01\x00".to_vec();
            f.resize(18, 0);
            f.extend_from_slice(&machine.to_le_bytes());
            f.resize(64, 0);
            f
        };
        assert!(program_for("linux-x86_64", &elf(62)));
        assert!(program_for("linux-arm64", &elf(183)));
        assert!(!program_for("linux-x86_64", &elf(183)), "ARM's for Intel");
        assert!(!program_for("linux-arm64", &elf(62)));
        assert!(!program_for("linux-x86_64", b"#!/bin/sh\necho hi\n"));
        assert!(!program_for("linux-x86_64", b"\x7fELF"));
        assert!(!program_for("windows", &elf(62)));

        let here: u32 = if std::env::consts::ARCH == "aarch64" { 0x0100_000c } else { 0x0100_0007 };
        let other: u32 = if here == 0x0100_000c { 0x0100_0007 } else { 0x0100_000c };
        let fat = |cpus: &[u32]| {
            let mut f = 0xcafe_babe_u32.to_be_bytes().to_vec();
            f.extend_from_slice(&(cpus.len() as u32).to_be_bytes());
            for cpu in cpus {
                f.extend_from_slice(&cpu.to_be_bytes());
                f.extend_from_slice(&[0u8; 16]);
            }
            f
        };
        let thin = |cpu: u32| {
            let mut f = 0xfeed_facf_u32.to_le_bytes().to_vec();
            f.extend_from_slice(&cpu.to_le_bytes());
            f.resize(32, 0);
            f
        };
        assert!(program_for("macos", &fat(&[0x0100_0007, 0x0100_000c])), "universal");
        assert!(program_for("macos", &fat(&[here])));
        assert!(!program_for("macos", &fat(&[other])));
        assert!(program_for("macos", &thin(here)));
        assert!(!program_for("macos", &thin(other)));
        assert!(!program_for("macos", &elf(62)));
    }

    #[test]
    fn the_key_built_in() {
        // The owner's, made 25.10.2026. Agents out there know only this one:
        // a change here would stop them updating, so it fails here first.
        assert_eq!(PUBLIC_KEY_HEX.trim(), "657dc196a166183d1e7b6bb90bda4e5d2fca83d7479c5dde4d61eeb982d4f971");
        assert!(public_key().is_some());
    }

    #[test]
    fn replacing_keeps_the_old_one() {
        let dir = folder("replace");
        let exe = dir.join("tterm-agent");
        std::fs::write(&exe, says("0.14.0")).unwrap();
        replace(&exe, &says("0.14.1"), "0.14.1").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), says("0.14.1"));
        assert_eq!(std::fs::read(dir.join("tterm-agent.old")).unwrap(), says("0.14.0"));
        assert_eq!(std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777, 0o755);
        replace(&exe, &says("0.14.2"), "0.14.2").unwrap();
        assert_eq!(std::fs::read(dir.join("tterm-agent.old")).unwrap(), says("0.14.1"));
        // Nothing of its own left behind.
        let names: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
        assert_eq!(names.len(), 2, "{names:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_does_not_start_is_not_put_in_place() {
        let dir = folder("probe");
        let exe = dir.join("tterm-agent");
        std::fs::write(&exe, says("0.14.0")).unwrap();
        // Another version than its release says; one that fails; one that
        // says nothing in time; one that cannot run at all.
        let slow = b"#!/bin/sh\nsleep 5\necho 0.14.1\n".to_vec();
        for (file, time) in [(says("0.13.0"), PROBE_TIME), (b"#!/bin/sh\nexit 3\n".to_vec(), PROBE_TIME), (slow, Duration::from_millis(300)), (b"\x7fELF\x02\x01\x01\x00garbage".to_vec(), PROBE_TIME)] {
            assert!(replace_with(&exe, &file, "0.14.1", time).is_err());
            assert_eq!(std::fs::read(&exe).unwrap(), says("0.14.0"), "the agent stays as it was");
            assert!(!dir.join("tterm-agent.old").exists());
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "nothing left behind");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn links_left_at_its_names_are_not_followed() {
        let dir = folder("links");
        let exe = dir.join("tterm-agent");
        let precious = dir.join("authorized_keys");
        std::fs::write(&exe, says("0.14.0")).unwrap();
        std::fs::write(&precious, "ssh-ed25519 AAAA mine\n").unwrap();
        for name in [own_name(&exe, "new"), own_name(&exe, "old"), dir.join("tterm-agent.old"), dir.join("tterm-agent.skip"), dir.join("tterm-agent.trial")] {
            std::os::unix::fs::symlink(&precious, &name).unwrap();
        }
        replace(&exe, &says("0.14.1"), "0.14.1").unwrap();
        begin_trial(&exe, "0.14.1").unwrap();
        roll_back(&exe, "0.14.1").unwrap();
        assert_eq!(std::fs::read_to_string(&precious).unwrap(), "ssh-ed25519 AAAA mine\n", "untouched");
        assert_eq!(std::fs::read(&exe).unwrap(), says("0.14.0"));
        assert!(!std::fs::symlink_metadata(&exe).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(dir.join("tterm-agent.skip")).unwrap(), "0.14.1\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_version_on_trial() {
        let dir = folder("trial");
        let exe = dir.join("tterm-agent");
        std::fs::write(&exe, says("0.14.0")).unwrap();
        assert_eq!(trial_start(&exe, "0.14.0"), Trial::No);
        replace(&exe, &says("0.14.1"), "0.14.1").unwrap();
        begin_trial(&exe, "0.14.1").unwrap();
        // Three starts, then back.
        for _ in 0..TRIAL_STARTS {
            assert_eq!(trial_start(&exe, "0.14.1"), Trial::On);
        }
        assert_eq!(trial_start(&exe, "0.14.1"), Trial::Over);
        roll_back(&exe, "0.14.1").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), says("0.14.0"));
        assert!(!trial_file(&exe).exists());
        assert_eq!(skipped(&exe, "0.14.0").as_deref(), Some("0.14.1"), "not taken again");
        assert_eq!(skipped(&exe, "0.14.1"), None, "once past it, it does not matter");
        assert!(roll_back(&exe, "0.14.1").is_err(), "nothing to go back to");

        // One that stays.
        replace(&exe, &says("0.14.2"), "0.14.2").unwrap();
        begin_trial(&exe, "0.14.2").unwrap();
        assert_eq!(trial_start(&exe, "0.14.2"), Trial::On);
        trial_passed(&exe);
        assert_eq!(trial_start(&exe, "0.14.2"), Trial::No);

        // Left from another version: not this one's.
        begin_trial(&exe, "0.14.9").unwrap();
        assert_eq!(trial_start(&exe, "0.14.2"), Trial::No);
        assert!(!trial_file(&exe).exists());
        std::fs::write(trial_file(&exe), "nonsense").unwrap();
        assert_eq!(trial_start(&exe, "0.14.2"), Trial::No);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_where_an_installer_put_it() {
        let dir = folder("enabled");
        let exe = dir.join("tterm-agent");
        let env = dir.join("env");
        std::fs::write(&exe, "").unwrap();
        std::fs::write(&env, "").unwrap();
        assert!(enabled(&exe, Some(&env), None));
        assert!(!enabled(&exe, Some(&env), Some("off")));
        assert!(!enabled(&exe, Some(&env), Some(" OFF ")));
        assert!(enabled(&exe, Some(&env), Some("on")));
        assert!(!enabled(&exe, None, None), "started by hand");
        assert!(!enabled(&exe, Some(Path::new("/nonexistent/elsewhere/env")), None));
        // A folder others can write to: someone else could put a file there.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!enabled(&exe, Some(&env), None));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(!enabled(&exe, Some(&env), None));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(enabled(&exe, Some(&env), None));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod openssl_made {
    /// A list signed the way the release build signs it (openssl pkeyutl
    /// -sign -rawin with an Ed25519 key), checked the way the agent checks.
    #[test]
    fn a_release_signature_checks() {
        let manifest: &str = "{\"files\": {\"macos\": {\"name\": \"tterm-agent-macos\", \"sha256\": \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\", \"size\": 3}}, \"version\": \"0.14.1\"}\n";
        let public = "3dddbaa1a6ca35d77b3d3044c18d8641d05e3dbd67b2f6414702614f22c4579c";
        let sig: &[u8] = b"UYObR1Ny8wJz6+S6KySrWwOhCMH53RtljU79QQquqkiJpjF9KPX7EJz4WnZ1enadGwYCrfO1ucrey2Fi1keSDw==";
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = u8::from_str_radix(&public[i * 2..i * 2 + 2], 16).unwrap();
        }
        let wanted = super::verify(manifest.as_bytes(), sig, &key, "0.14.1", "macos").unwrap();
        assert_eq!(wanted.size, 3);
        assert!(super::verify(manifest.replace("0.14.1", "0.14.2").as_bytes(), sig, &key, "0.14.2", "macos").is_err());
    }
}
