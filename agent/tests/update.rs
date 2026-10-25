//! The agent's updates (update.rs) against releases on this computer, over
//! TLS: GitHub's list of releases, the signed list of a release's files, the
//! redirect to GitHub's storage, a company's proxy. The TLS is the link's
//! own: it trusts the checks' CA through SSL_CERT_FILE, as it would trust a
//! company's. That CA and its certificate for 127.0.0.1 are throwaway ones
//! made for these checks, trusted by nothing else.

use base64::Engine as _;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Once};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tterm_agent::update;
use tterm_engine::proxy;

/// The checks' CA, their certificate for 127.0.0.1 and localhost, and its
/// key (PKCS#8), all DER in base64; valid until 2126.
const CA: &str = "MIIBvzCCAWWgAwIBAgIUXGszR3igCJjiRoBbGjG6ms7Fj3MwCgYIKoZIzj0EAwIwLDEqMCgGA1UEAwwhdHRlcm0tYWdlbnQgY2hlY2tzLCBub3QgYSByZWFsIENBMCAXDTI2MTAyNTE2MjczM1oYDzIxMjYxMDAxMTYyNzMzWjAsMSowKAYDVQQDDCF0dGVybS1hZ2VudCBjaGVja3MsIG5vdCBhIHJlYWwgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASMSOnL6AwJ2lKqDvL09TzD4GRCLPYEy274pRYGHcqJf/3Kc2BHGhST+fX0EEZFLSLIDjrxcZFAU3HMvGfsphgBo2MwYTAdBgNVHQ4EFgQURZRxQ2FXs6l3sbbG5dsIO11ifNswHwYDVR0jBBgwFoAURZRxQ2FXs6l3sbbG5dsIO11ifNswDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIhAKePYHuekiCz5q+lqJT8MnvZAJW6Jd5tjKvLHbZWxgGYAiALTKxFK4+98s4i4DxhCAXfdmxw4j0Gpr7c+wWVCRAJ+A==";
const SERVER_CERT: &str = "MIIB2DCCAX2gAwIBAgIUI48x/eOSAPobT9oO3x39BKmPRI4wCgYIKoZIzj0EAwIwLDEqMCgGA1UEAwwhdHRlcm0tYWdlbnQgY2hlY2tzLCBub3QgYSByZWFsIENBMCAXDTI2MTAyNTE2MjczM1oYDzIxMjYxMDAxMTYyNzMzWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATq1nzmGS3uhIVO9OrfKqhEWwlFygU0vjI6AVvkU4cjem0CjJdjD3L6UgWg2P78mi8yvgauA3wJRT1M4CkwpIcTo4GSMIGPMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUpRrIGH3I/i+Sw0sjozxOaSGnM6kwHwYDVR0jBBgwFoAURZRxQ2FXs6l3sbbG5dsIO11ifNswCgYIKoZIzj0EAwIDSQAwRgIhAPAhpt7Q/A4yRgL2Oubo0HYPDM9wpxVNk4dtwcmqg5pWAiEA3CxDBi8+96iy7t43Xo7deVuL8++Bgkdc9Dlz5cGSW0o=";
const SERVER_KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgza8dZJTfCqDxVhgUuqqdoSLI9lUpjt1YKYdPlPc2xKmhRANCAATq1nzmGS3uhIVO9OrfKqhEWwlFygU0vjI6AVvkU4cjem0CjJdjD3L6UgWg2P78mi8yvgauA3wJRT1M4CkwpIcT";

fn der(b64: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(b64).unwrap()
}

/// Once, before any TLS in this program: the link's roots are read once.
fn trust_the_checks_ca() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let lines: Vec<String> = CA.as_bytes().chunks(64).map(|c| String::from_utf8_lossy(c).to_string()).collect();
        let path = std::env::temp_dir().join(format!("tterm-agent-update-ca-{}.pem", std::process::id()));
        std::fs::write(&path, format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))).unwrap();
        std::env::set_var("SSL_CERT_FILE", &path);
    });
}

/// What the site answers for a path.
#[derive(Clone)]
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// No Content-Length: the body ends with the connection.
    no_length: bool,
}

fn ok(body: impl Into<Vec<u8>>) -> Answer {
    Answer { status: 200, headers: Vec::new(), body: body.into(), no_length: false }
}

fn redirect(to: String) -> Answer {
    Answer { status: 302, headers: vec![("Location".into(), to)], body: Vec::new(), no_length: false }
}

/// A release of the agent, made the way the release build makes one.
struct Release {
    version: String,
    pair: Ed25519KeyPair,
    public: [u8; 32],
    file: Vec<u8>,
    manifest: Vec<u8>,
}

impl Release {
    fn new(version: &str) -> Release {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
        let mut file = elf(62);
        file.extend(format!("tterm-agent {version} for Linux\n").repeat(5000).into_bytes());
        let manifest = manifest(version, &file);
        Release { version: version.to_string(), pair, public, file, manifest }
    }

    fn signature(&self, manifest: &[u8]) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.encode(self.pair.sign(manifest).as_ref()).into_bytes()
    }

    /// GitHub as the agent meets it: the list of releases, the app's among
    /// them, and each file of a release sent on to the storage, with a
    /// token in its address.
    fn site(&self, port: u16) -> HashMap<String, Answer> {
        let base = format!("https://127.0.0.1:{port}");
        let tag = format!("agent-v{}", self.version);
        let names = ["tterm-agent.json", "tterm-agent.json.sig", "tterm-agent-linux-x86_64"];
        let assets: Vec<_> = names.iter().map(|n| json!({"name": n, "browser_download_url": format!("{base}/download/{tag}/{n}")})).collect();
        let list = json!([
            {"tag_name": "v9.9.9", "draft": false, "prerelease": false, "assets": []},
            {"tag_name": tag, "draft": false, "prerelease": false, "assets": assets},
            {"tag_name": "agent-v0.13.0", "draft": false, "prerelease": false, "assets": []},
        ]);
        let mut site = HashMap::new();
        site.insert("/releases".to_string(), ok(list.to_string()));
        for name in names {
            site.insert(format!("/download/{tag}/{name}"), redirect(format!("{base}/storage/{name}?token=SECRET")));
        }
        site.insert("/storage/tterm-agent.json".to_string(), ok(self.manifest.clone()));
        site.insert("/storage/tterm-agent.json.sig".to_string(), ok(self.signature(&self.manifest)));
        site.insert("/storage/tterm-agent-linux-x86_64".to_string(), ok(self.file.clone()));
        site
    }
}

/// The head of a Linux program, for a processor: 62 Intel and AMD, 183 ARM.
fn elf(machine: u16) -> Vec<u8> {
    let mut head = b"\x7fELF\x02\x01\x01\x00".to_vec();
    head.resize(18, 0);
    head.extend_from_slice(&machine.to_le_bytes());
    head.resize(64, 0);
    head
}

fn manifest(version: &str, file: &[u8]) -> Vec<u8> {
    let entry = |name: &str| json!({"name": name, "size": file.len(), "sha256": update::sha256_hex(file)});
    let m = json!({"version": version, "files": {"linux-x86_64": entry("tterm-agent-linux-x86_64"), "macos": entry("tterm-agent-macos")}});
    format!("{}\n", serde_json::to_string_pretty(&m).unwrap()).into_bytes()
}

/// A site on this computer: the paths asked for, with their query and
/// the User-Agent.
struct Site {
    port: u16,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Site {
    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }
    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
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
    head.lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default()
}

async fn site(make: impl FnOnce(u16) -> HashMap<String, Answer>) -> Site {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let pages = Arc::new(make(port));
    let asked = Arc::new(Mutex::new(Vec::new()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(der(SERVER_CERT))], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der(SERVER_KEY))))
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let log = asked.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, pages, log) = (acceptor.clone(), pages.clone(), log.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let Some(head) = read_head(&mut tls).await else { return };
                let target = head.split_whitespace().nth(1).unwrap_or("").to_string();
                log.lock().unwrap().push(format!("{target} {}", header(&head, "user-agent")));
                let path = target.split('?').next().unwrap_or("");
                let answer = pages.get(path).cloned().unwrap_or(Answer { status: 404, headers: Vec::new(), body: b"no".to_vec(), no_length: false });
                let mut out = format!("HTTP/1.1 {} Answer\r\nConnection: close\r\n", answer.status);
                if !answer.no_length {
                    out.push_str(&format!("Content-Length: {}\r\n", answer.body.len()));
                }
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
    Site { port, asked }
}

/// A company's proxy: CONNECT, with a login. What it was asked.
async fn connect_proxy() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let log = asked.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let Some(head) = read_head(&mut client).await else { return };
                let first = head.lines().next().unwrap_or("").to_string();
                log.lock().unwrap().push(format!("{first} | {}", header(&head, "proxy-authorization")));
                let to = first.split_whitespace().nth(1).unwrap_or("").to_string();
                let Ok(mut upstream) = TcpStream::connect(&to).await else { return };
                if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (port, asked)
}

fn direct() -> impl Fn(&reqwest::Url) -> Result<reqwest::Client, String> + Send + Sync {
    update::clients("tterm-agent/0.14.0".to_string(), HashMap::new(), None)
}

#[tokio::test]
async fn a_newer_version_comes_checked() {
    trust_the_checks_ca();
    let release = Release::new("0.99.0");
    let site = site(|port| release.site(port)).await;
    let got = update::fetch(&direct(), &site.url("/releases"), "0.14.0", &release.public, "linux-x86_64").await.unwrap();
    assert_eq!(got, Some(("0.99.0".to_string(), release.file.clone())));
    let asked = site.asked();
    assert!(asked.contains(&"/storage/tterm-agent-linux-x86_64?token=SECRET tterm-agent/0.14.0".to_string()), "{asked:?}");
    assert!(asked.iter().all(|a| a.ends_with(" tterm-agent/0.14.0")), "{asked:?}");
    // The newest there is, already.
    let got = update::fetch(&direct(), &site.url("/releases"), "0.99.0", &release.public, "linux-x86_64").await.unwrap();
    assert_eq!(got, None);
}

#[tokio::test]
async fn what_the_signature_does_not_cover_is_not_taken() {
    trust_the_checks_ca();
    let release = Release::new("0.99.0");
    let fetch = |site: Site, key: [u8; 32]| async move {
        update::fetch(&direct(), &site.url("/releases"), "0.14.0", &key, "linux-x86_64").await.unwrap_err()
    };

    // Another file of the same size in its place.
    let site_ = site(|port| {
        let mut s = release.site(port);
        let mut other = release.file.clone();
        other[0] ^= 1;
        s.insert("/storage/tterm-agent-linux-x86_64".into(), ok(other));
        s
    })
    .await;
    let why = fetch(site_, release.public).await;
    assert!(why.contains("tterm-agent-linux-x86_64 is not the file its signed list names"), "{why}");

    // A list signed with another key: the file is not even asked for.
    let site_ = site(|port| release.site(port)).await;
    let other = Release::new("0.99.0");
    let asked = site_.asked.clone();
    let why = fetch(site_, other.public).await;
    assert_eq!(why, "version 0.99.0: the signature does not check");
    assert!(!asked.lock().unwrap().iter().any(|a| a.contains("linux-x86_64")), "{:?}", asked.lock().unwrap());

    // An old list, signed, under a newer tag.
    let site_ = site(|port| {
        let mut s = release.site(port);
        let old = manifest("0.98.0", &release.file);
        s.insert("/storage/tterm-agent.json.sig".into(), ok(release.signature(&old)));
        s.insert("/storage/tterm-agent.json".into(), ok(old));
        s
    })
    .await;
    let why = fetch(site_, release.public).await;
    assert_eq!(why, "version 0.99.0: the signed list is for another version");

    // Signed, and for another processor: an agent that runs is not put
    // aside for one that cannot start.
    let site_ = site(|port| {
        let mut s = release.site(port);
        let mut arm = elf(183);
        arm.extend_from_slice(&release.file[arm.len()..]);
        let listed = manifest("0.99.0", &arm);
        s.insert("/storage/tterm-agent.json.sig".into(), ok(release.signature(&listed)));
        s.insert("/storage/tterm-agent.json".into(), ok(listed));
        s.insert("/storage/tterm-agent-linux-x86_64".into(), ok(arm));
        s
    })
    .await;
    let why = fetch(site_, release.public).await;
    assert_eq!(why, "version 0.99.0: tterm-agent-linux-x86_64 is not a program for linux-x86_64");
}

#[tokio::test]
async fn only_over_https() {
    trust_the_checks_ca();
    let release = Release::new("0.99.0");
    let site = site(|port| {
        let mut s = release.site(port);
        s.insert("/download/agent-v0.99.0/tterm-agent-linux-x86_64".into(), redirect(format!("http://127.0.0.1:{port}/storage/tterm-agent-linux-x86_64?token=SECRET")));
        s
    })
    .await;
    let why = update::fetch(&direct(), &site.url("/releases"), "0.14.0", &release.public, "linux-x86_64").await.unwrap_err();
    assert_eq!(why, format!("not over HTTPS: http://127.0.0.1:{}/storage/tterm-agent-linux-x86_64", site.port));
    let why = update::fetch(&direct(), &format!("http://127.0.0.1:{}/releases", site.port), "0.14.0", &release.public, "linux-x86_64").await.unwrap_err();
    assert!(why.starts_with("not over HTTPS"), "{why}");
}

#[tokio::test]
async fn no_more_than_the_list_says() {
    trust_the_checks_ca();
    let release = Release::new("0.99.0");
    for no_length in [false, true] {
        let site = site(|port| {
            let mut s = release.site(port);
            let mut longer = release.file.clone();
            longer.extend_from_slice(b"and more");
            s.insert("/storage/tterm-agent-linux-x86_64".into(), Answer { no_length, ..ok(longer) });
            s
        })
        .await;
        let why = update::fetch(&direct(), &site.url("/releases"), "0.14.0", &release.public, "linux-x86_64").await.unwrap_err();
        assert_eq!(why, format!("{}: larger than expected", site.url("/storage/tterm-agent-linux-x86_64")), "no_length: {no_length}");
    }
}

#[tokio::test]
async fn refusals_are_said_without_the_token() {
    trust_the_checks_ca();
    let release = Release::new("0.99.0");
    let site = site(|port| {
        let mut s = release.site(port);
        s.insert("/storage/tterm-agent-linux-x86_64".into(), Answer { status: 403, ..ok("expired") });
        s
    })
    .await;
    let why = update::fetch(&direct(), &site.url("/releases"), "0.14.0", &release.public, "linux-x86_64").await.unwrap_err();
    assert_eq!(why, format!("{}: HTTP 403", site.url("/storage/tterm-agent-linux-x86_64")));
    let why = update::fetch(&direct(), &site.url("/nothing"), "0.14.0", &release.public, "linux-x86_64").await.unwrap_err();
    assert_eq!(why, format!("{}: HTTP 404", site.url("/nothing")));
}

#[tokio::test]
async fn through_a_companys_proxy() {
    trust_the_checks_ca();
    let release = Release::new("0.99.0");
    let site = site(|port| release.site(port)).await;
    let (proxy_port, proxied) = connect_proxy().await;
    let env = proxy::from_environment(&[("https_proxy".to_string(), format!("http://who:pass%21@127.0.0.1:{proxy_port}"))]);
    let via = update::clients("tterm-agent/0.14.0".to_string(), env.clone(), None);
    let got = update::fetch(&via, &site.url("/releases"), "0.14.0", &release.public, "linux-x86_64").await.unwrap();
    assert_eq!(got.map(|(v, _)| v), Some("0.99.0".to_string()));
    let seen = proxied.lock().unwrap().clone();
    // The list, then each of three files and the storage it is sent to.
    assert_eq!(seen.len(), 7, "{seen:?}");
    let login = base64::engine::general_purpose::STANDARD.encode("who:pass!");
    assert!(seen.iter().all(|s| *s == format!("CONNECT 127.0.0.1:{} HTTP/1.1 | Basic {login}", site.port)), "{seen:?}");

    // Not for the hosts no_proxy names.
    let mut env = env;
    env.insert("no".to_string(), "127.0.0.1".to_string());
    let direct_too = update::clients("tterm-agent/0.14.0".to_string(), env, None);
    update::fetch(&direct_too, &site.url("/releases"), "0.14.0", &release.public, "linux-x86_64").await.unwrap();
    assert_eq!(proxied.lock().unwrap().len(), 7);
}
