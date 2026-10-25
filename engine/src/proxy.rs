//! The proxy on the way to tTerm Web, when this computer has one.
//!
//! agent.py's websockets library (15 and later) went through a proxy by
//! itself, the one Python's urllib finds: in the environment (https_proxy
//! and the like, no_proxy), and on macOS, when the environment names none,
//! the system's own (System Settings, Network, Proxies). The link
//! (link.rs) finds it the same way, so that a computer that reached tTerm
//! Web through its proxy with agent.py still does.
//!
//! Only proxies spoken to in plain HTTP (http://), through CONNECT, with a
//! login when the address has one: the link's TLS goes on end to end inside,
//! and the proxy sees only where to. websockets needed a library the
//! installer did not put in for SOCKS, so agent.py could not use one either;
//! a SOCKS proxy is passed over here for the next one named. A proxy spoken
//! to over https:// is not supported: the link says so.

use base64::Engine as _;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A proxy to go through.
#[derive(Clone, PartialEq, Eq)]
pub struct Proxy {
    pub host: String,
    pub port: u16,
    /// The user and password from its address, if any.
    pub login: Option<(String, String)>,
}

impl std::fmt::Debug for Proxy {
    // The password stays out of any log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Proxy {
    /// host:port, as the log says it: without the login.
    pub fn name(&self) -> String {
        host_port(&self.host, self.port)
    }
}

/// The system's proxies (macOS), as Python's _scproxy reads them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct System {
    /// Those turned on, by scheme: "http://host:port".
    pub proxies: HashMap<String, String>,
    /// Names without a dot go direct.
    pub exclude_simple: bool,
    /// Bypass these hosts and domains: *.local, 169.254/16.
    pub exceptions: Vec<String>,
}

/// The *_proxy variables among `vars`, as urllib's getproxies_environment
/// reads them: a name ending in _proxy in any case, the lowercase name
/// winning, and one set empty in lowercase taking its scheme away. The key
/// is the name before _proxy, in lowercase: "https", "no" for no_proxy.
pub fn from_environment(vars: &[(String, String)]) -> HashMap<String, String> {
    let mut proxies = HashMap::new();
    for (name, value) in vars {
        let name = name.to_ascii_lowercase();
        if !value.is_empty() && name.ends_with("_proxy") {
            proxies.insert(name[..name.len() - 6].to_string(), value.clone());
        }
    }
    for (name, value) in vars {
        if let Some(scheme) = name.strip_suffix("_proxy") {
            let scheme = scheme.to_ascii_lowercase();
            if value.is_empty() {
                proxies.remove(&scheme);
            } else {
                proxies.insert(scheme, value.clone());
            }
        }
    }
    proxies
}

/// The proxy for the hub at `host`:`port`, as websockets chose it
/// (get_proxy): from the environment if it names any proxy at all, else
/// from the system's settings; none when the hub is to be reached direct.
/// For wss://, the wss proxy, then https; for ws://, ws, https, then http.
/// Err for one named that cannot be used here.
pub fn choose(
    host: &str,
    port: u16,
    tls: bool,
    env: &HashMap<String, String>,
    system: Option<&System>,
) -> Result<Option<Proxy>, String> {
    // websockets asked urllib with the port on.
    let at = format!("{host}:{port}");
    let (proxies, bypass) = if !env.is_empty() {
        (env, bypass_environment(&at, env))
    } else if let Some(system) = system {
        (&system.proxies, bypass_system(&at, system))
    } else {
        return Ok(None);
    };
    if bypass {
        return Ok(None);
    }
    let schemes: &[&str] = if tls { &["wss", "socks", "https"] } else { &["ws", "socks", "https", "http"] };
    for scheme in schemes {
        if *scheme == "socks" {
            continue;
        }
        if let Some(address) = proxies.get(*scheme) {
            return parse(address).map(Some);
        }
    }
    Ok(None)
}

/// Whether no_proxy names the hub, as urllib's proxy_bypass_environment
/// reads it: "*" for all; otherwise names, the hub's or a domain it is in,
/// a leading dot or not, with or without its port.
fn bypass_environment(at: &str, env: &HashMap<String, String>) -> bool {
    let Some(no) = env.get("no") else { return false };
    if no == "*" {
        return true;
    }
    let at = at.to_lowercase();
    let host = split_port(&at).0;
    for name in no.split(',') {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let name = name.trim_start_matches('.').to_lowercase();
        if host == name || at == name {
            return true;
        }
        let domain = format!(".{name}");
        if host.ends_with(&domain) || at.ends_with(&domain) {
            return true;
        }
    }
    false
}

/// Whether the system's settings send the hub direct, as urllib's
/// _proxy_bypass_macosx_sysconf reads them: a name without a dot when simple
/// names go direct; an exception, an address range (169.254/16) or a pattern
/// (*.local).
fn bypass_system(at: &str, system: &System) -> bool {
    let host = split_port(at).0;
    if !at.contains('.') && system.exclude_simple {
        return true;
    }
    let ip: Option<u64> = host.parse::<std::net::Ipv4Addr>().ok().map(|a| u32::from(a) as u64);
    for value in &system.exceptions {
        if value.is_empty() {
            continue;
        }
        match (ip, address_range(value)) {
            (Some(ip), Some((base, bits))) => {
                if bits > 32 {
                    continue;
                }
                let shift = 32 - bits;
                if ip >> shift == base >> shift {
                    return true;
                }
            }
            _ => {
                if matches(value, at) || matches(value, host) {
                    return true;
                }
            }
        }
    }
    false
}

/// "169.254/16" as a number and the bits that count, as urllib reads an
/// exception (the pattern \d+(\.\d+)*(/\d+)? at its start): the parts
/// missing are zeros, and without a length the parts given count.
fn address_range(value: &str) -> Option<(u64, u32)> {
    let b = value.as_bytes();
    let mut parts: Vec<u64> = Vec::new();
    let mut i = 0;
    loop {
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            if parts.is_empty() {
                return None;
            }
            // The dot before is not part of it.
            i -= 1;
            break;
        }
        parts.push(value[start..i].parse::<u64>().unwrap_or(u64::MAX));
        if i < b.len() && b[i] == b'.' {
            i += 1;
        } else {
            break;
        }
    }
    let bits = match value[i..].strip_prefix('/') {
        Some(length) if length.starts_with(|c: char| c.is_ascii_digit()) => {
            let digits: String = length.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<u32>().unwrap_or(u32::MAX)
        }
        _ => 8 * parts.len() as u32,
    };
    parts.resize(4, 0);
    let base = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    Some((base, bits))
}

/// A shell-style pattern (fnmatch): * for any run, ? for one character.
fn matches(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// "host:port" as urllib's _splitport splits it: the port only when digits
/// follow the last colon.
fn split_port(at: &str) -> (&str, Option<&str>) {
    if let Some((host, port)) = at.rsplit_once(':') {
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return (host, Some(port));
        }
    }
    (at, None)
}

fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// A proxy's address, as websockets took it (parse_proxy): http://, a
/// user and password before an @ if any, the port or 80. Without a scheme
/// it is taken as http://, as curl takes it (websockets refused it).
pub fn parse(address: &str) -> Result<Proxy, String> {
    let (scheme, rest) = match address.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => ("http".to_string(), address),
    };
    let (login, at) = match rest.rsplit_once('@') {
        Some((login, at)) => (Some(login), at),
        None => (None, rest),
    };
    // What the log may say of it: without the login.
    let shown = format!("{scheme}://{at}");
    if scheme != "http" {
        return Err(format!("the proxy {shown} cannot be used: only http:// proxies can"));
    }
    let at = at.strip_suffix('/').unwrap_or(at);
    if at.contains(['/', '?', '#']) {
        return Err(format!("the proxy's address {shown} is not one"));
    }
    let (host, port) = if let Some(bracketed) = at.strip_prefix('[') {
        let (host, rest) = bracketed.split_once(']').ok_or_else(|| format!("the proxy's address {shown} is not one"))?;
        let port = match rest.strip_prefix(':') {
            Some(p) => Some(p),
            None if rest.is_empty() => None,
            None => return Err(format!("the proxy's address {shown} is not one")),
        };
        (host.to_string(), port)
    } else {
        match at.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), Some(port)),
            None => (at.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err(format!("the proxy's address {shown} has no host"));
    }
    let port = match port {
        None | Some("") => 80,
        Some(p) => p.parse::<u16>().map_err(|_| format!("the proxy's address {shown} has no port that works"))?,
    };
    let login = match login {
        None => None,
        Some(login) => {
            let (user, password) =
                login.split_once(':').ok_or_else(|| format!("the proxy {shown} has a user but no password"))?;
            Some((unquote(user), unquote(password)))
        }
    };
    Ok(Proxy { host: host.to_lowercase(), port, login })
}

/// %xx in a login, as urllib's unquote reads it.
fn unquote(text: &str) -> String {
    let bytes = text.as_bytes();
    let hex = |b: u8| (b as char).to_digit(16);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((high * 16 + low) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// The system's proxy settings from what `scutil --proxy` prints, as
/// Python's _scproxy takes them: each proxy turned on, as
/// http://host:port; the exceptions; whether simple names go direct. Only
/// the settings at the top count: those nested deeper are for one network
/// interface (__SCOPED__) or for the domains of a VPN (__SUPPLEMENTAL__).
pub fn parse_scutil(text: &str) -> System {
    let mut values: HashMap<String, String> = HashMap::new();
    let mut exceptions = Vec::new();
    // How deep the line is: 1 inside the outer dictionary; and whether it
    // is in the top ExceptionsList.
    let mut depth = 0usize;
    let mut in_exceptions = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('}') {
            depth = depth.saturating_sub(1);
            if depth <= 1 {
                in_exceptions = false;
            }
            continue;
        }
        let opens = line.ends_with('{');
        match line.split_once(" : ") {
            Some((key, value)) => {
                let (key, value) = (key.trim(), value.trim());
                if opens {
                    in_exceptions = depth == 1 && key == "ExceptionsList";
                    depth += 1;
                } else if depth == 1 {
                    values.insert(key.to_string(), value.to_string());
                } else if depth == 2 && in_exceptions {
                    exceptions.push(value.to_string());
                }
            }
            None if opens => depth += 1,
            None => {}
        }
    }
    let on = |key: &str| values.get(key).and_then(|v| v.parse::<i64>().ok()).is_some_and(|v| v != 0);
    let mut proxies = HashMap::new();
    for (scheme, key) in [("http", "HTTP"), ("https", "HTTPS"), ("ftp", "FTP"), ("gopher", "Gopher"), ("socks", "SOCKS")] {
        if !on(&format!("{key}Enable")) {
            continue;
        }
        let Some(host) = values.get(&format!("{key}Proxy")).filter(|h| !h.is_empty()) else { continue };
        let address = match values.get(&format!("{key}Port")).and_then(|p| p.parse::<i64>().ok()) {
            Some(port) => format!("http://{host}:{port}"),
            None => format!("http://{host}"),
        };
        proxies.insert(scheme.to_string(), address);
    }
    System { proxies, exclude_simple: on("ExcludeSimpleHostnames"), exceptions }
}

/// The system's proxy settings, on macOS; None elsewhere, or when they
/// cannot be read.
pub async fn system() -> Option<System> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let run = tokio::process::Command::new("/usr/sbin/scutil")
        .arg("--proxy")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(std::time::Duration::from_secs(3), run).await {
        Ok(Ok(out)) if out.status.success() => Some(parse_scutil(&String::from_utf8_lossy(&out.stdout))),
        _ => None,
    }
}

/// The largest answer to CONNECT read.
const ANSWER_MAX: usize = 16 * 1024;

/// Asks the proxy on `stream` for a way through to `host`:`port`, as
/// websockets asked (prepare_connect_request), and reads its answer; Ok
/// once the way is open. Nothing past the answer is read: what follows is
/// the hub's.
pub async fn tunnel(stream: &mut TcpStream, proxy: &Proxy, host: &str, port: u16, tls: bool, agent: &str) -> Result<(), String> {
    let default_port = if tls { 443 } else { 80 };
    let host_header = if port == default_port {
        if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        }
    } else {
        host_port(host, port)
    };
    let mut request = format!("CONNECT {} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {agent}\r\n", host_port(host, port));
    if let Some((user, password)) = &proxy.login {
        let pair = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {pair}\r\n"));
    }
    request.push_str("\r\n");
    let name = proxy.name();
    stream.write_all(request.as_bytes()).await.map_err(|e| format!("the proxy {name}: {e}"))?;
    let mut answer = Vec::new();
    let mut byte = [0u8; 1];
    while !answer.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(0) => return Err(format!("the proxy {name} closed the connection")),
            Ok(_) => answer.push(byte[0]),
            Err(e) => return Err(format!("the proxy {name}: {e}")),
        }
        if answer.len() > ANSWER_MAX {
            return Err(format!("the proxy {name} gave an answer that was not understood"));
        }
    }
    let text = String::from_utf8_lossy(&answer);
    let status = text.lines().next().unwrap_or("");
    let mut words = status.split_whitespace();
    let code = match (words.next(), words.next().and_then(|c| c.parse::<u16>().ok())) {
        (Some(version), Some(code)) if version.starts_with("HTTP/") => code,
        _ => return Err(format!("the proxy {name} gave an answer that was not understood")),
    };
    match code {
        200..=299 => Ok(()),
        407 => Err(format!("the proxy {name} asks for a login (HTTP 407)")),
        _ => Err(format!("the proxy {name} answered HTTP {code}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn env(list: &[(&str, &str)]) -> HashMap<String, String> {
        from_environment(&vars(list))
    }

    #[test]
    fn the_environment_as_urllib_reads_it() {
        let found = env(&[("HTTPS_PROXY", "http://upper:1"), ("https_proxy", "http://lower:2"), ("PATH", "/bin"), ("NO_PROXY", "a")]);
        assert_eq!(found.get("https").map(String::as_str), Some("http://lower:2"));
        assert_eq!(found.get("no").map(String::as_str), Some("a"));
        assert_eq!(found.len(), 2);
        // Set empty in lowercase: no proxy for that scheme.
        let found = env(&[("HTTPS_PROXY", "http://upper:1"), ("https_proxy", "")]);
        assert!(found.is_empty(), "{found:?}");
        // Empty in capitals: not there.
        assert!(env(&[("HTTPS_PROXY", "")]).is_empty());
        // Whatever ends in _proxy counts, as for urllib.
        assert_eq!(env(&[("Wss_Proxy", "http://w:3")]).get("wss").map(String::as_str), Some("http://w:3"));
    }

    #[test]
    fn which_proxy_for_the_hub() {
        let hub = "connect.tterm.net";
        let p = |list: &[(&str, &str)], tls: bool| choose(hub, if tls { 443 } else { 80 }, tls, &env(list), None);
        assert_eq!(p(&[], true).unwrap(), None);
        let got = p(&[("https_proxy", "http://proxy.corp:3128")], true).unwrap().unwrap();
        assert_eq!((got.host.as_str(), got.port, got.login.clone()), ("proxy.corp", 3128, None));
        // wss first, then https; http only for ws://.
        assert_eq!(p(&[("https_proxy", "http://a:1"), ("wss_proxy", "http://b:2")], true).unwrap().unwrap().host, "b");
        assert_eq!(p(&[("http_proxy", "http://a:1")], true).unwrap(), None);
        assert_eq!(p(&[("http_proxy", "http://a:1")], false).unwrap().unwrap().host, "a");
        assert_eq!(p(&[("http_proxy", "http://a:1"), ("https_proxy", "http://b:2")], false).unwrap().unwrap().host, "b");
        // all_proxy was not websockets' to take.
        assert_eq!(p(&[("all_proxy", "http://a:1")], true).unwrap(), None);
        // SOCKS: passed over for the next one named.
        assert_eq!(p(&[("socks_proxy", "socks5://s:1080"), ("https_proxy", "http://b:2")], true).unwrap().unwrap().host, "b");
        assert_eq!(p(&[("socks_proxy", "socks5://s:1080")], true).unwrap(), None);
        // One that cannot be used says so.
        let no = p(&[("https_proxy", "https://user:secret@tls.proxy:443")], true).unwrap_err();
        assert!(no.contains("only http://") && no.contains("tls.proxy") && !no.contains("secret"), "{no}");
        assert!(p(&[("https_proxy", "socks5h://s:1080")], true).is_err());
    }

    #[test]
    fn no_proxy_as_urllib_reads_it() {
        let via = |no: &str| {
            choose("connect.tterm.net", 443, true, &env(&[("https_proxy", "http://p:1"), ("no_proxy", no)]), None).unwrap().is_some()
        };
        assert!(via("localhost,127.0.0.1"));
        assert!(!via("*"));
        assert!(!via("connect.tterm.net"));
        assert!(!via("tterm.net"));
        assert!(!via(".tterm.net"));
        assert!(!via(" example.com , .TTERM.NET "));
        assert!(!via("connect.tterm.net:443"));
        assert!(via("connect.tterm.net:80"));
        assert!(via("nottterm.net"));
        assert!(via("*.tterm.net"), "no patterns in no_proxy, as for urllib");
        // no_proxy alone: the environment names proxies, so the system's
        // are not looked at.
        let system = System { proxies: HashMap::from([("https".into(), "http://sys:8080".into())]), ..Default::default() };
        assert_eq!(choose("connect.tterm.net", 443, true, &env(&[("no_proxy", "x")]), Some(&system)).unwrap(), None);
    }

    #[test]
    fn the_address_of_a_proxy() {
        let p = parse("http://me:p%40ss%3Aw@Proxy.Corp:8080/").unwrap();
        assert_eq!(p.host, "proxy.corp");
        assert_eq!(p.port, 8080);
        assert_eq!(p.login, Some(("me".to_string(), "p@ss:w".to_string())));
        assert_eq!(format!("{p:?}"), "proxy.corp:8080", "no password in the log");
        assert_eq!(parse("http://proxy").unwrap().port, 80);
        assert_eq!(parse("proxy.corp:3128").unwrap().port, 3128);
        let v6 = parse("http://[fd00::1]:3128").unwrap();
        assert_eq!((v6.host.as_str(), v6.port, v6.name()), ("fd00::1", 3128, "[fd00::1]:3128".to_string()));
        assert!(parse("http://me@proxy:1").unwrap_err().contains("no password"));
        assert!(parse("http://proxy:99999").is_err());
        assert!(parse("http://proxy:1/path").is_err());
        assert!(parse("http://:1").is_err());
        assert_eq!(unquote("a%2"), "a%2");
        assert_eq!(unquote("%zz%41"), "%zzA");
    }

    const SCUTIL: &str = "<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
    2 : 10/8
    3 : *.corp.example
  }
  ExcludeSimpleHostnames : 1
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 3128
  HTTPProxy : proxy.corp.example
  HTTPSEnable : 1
  HTTPSPort : 3129
  HTTPSProxy : secure.corp.example
  ProxyAutoConfigEnable : 0
  SOCKSEnable : 0
  SOCKSPort : 1080
  SOCKSProxy : socks.corp.example
}
";

    #[test]
    fn the_system_settings_on_macos() {
        let system = parse_scutil(SCUTIL);
        assert_eq!(system.proxies.get("http").map(String::as_str), Some("http://proxy.corp.example:3128"));
        assert_eq!(system.proxies.get("https").map(String::as_str), Some("http://secure.corp.example:3129"));
        assert!(!system.proxies.contains_key("socks"), "turned off");
        assert!(system.exclude_simple);
        assert_eq!(system.exceptions, vec!["*.local", "169.254/16", "10/8", "*.corp.example"]);
        let via = |host: &str| choose(host, 443, true, &HashMap::new(), Some(&system)).unwrap().map(|p| p.name());
        assert_eq!(via("connect.tterm.net"), Some("secure.corp.example:3129".to_string()));
        assert_eq!(via("printer.local"), None);
        assert_eq!(via("git.corp.example"), None);
        assert_eq!(via("10.1.2.3"), None);
        assert_eq!(via("169.254.9.9"), None);
        assert_eq!(via("169.253.9.9"), Some("secure.corp.example:3129".to_string()));
        assert_eq!(via("intranet"), None, "a simple name goes direct");
        // Nothing turned on.
        let off = parse_scutil("<dictionary> {\n  HTTPEnable : 0\n  HTTPProxy : p\n}\n");
        assert!(off.proxies.is_empty() && !off.exclude_simple && off.exceptions.is_empty());
        assert_eq!(choose("connect.tterm.net", 443, true, &HashMap::new(), Some(&off)).unwrap(), None);
        // A port is not a must.
        let bare = parse_scutil("<dictionary> {\n  HTTPSEnable : 1\n  HTTPSProxy : p.example\n}\n");
        assert_eq!(bare.proxies.get("https").map(String::as_str), Some("http://p.example"));
    }

    /// As macOS prints it with a VPN on: the settings of each interface, and
    /// a proxy for the VPN's own domain, after those that count.
    const SCUTIL_NESTED: &str = "<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPSEnable : 1
  HTTPSPort : 3129
  HTTPSProxy : secure.corp.example
  __SCOPED__ : <dictionary> {
    en0 : <dictionary> {
      ExceptionsList : <array> {
        0 : *.scoped
      }
      HTTPSEnable : 1
      HTTPSPort : 3129
      HTTPSProxy : secure.corp.example
    }
    utun3 : <dictionary> {
      FTPPassive : 1
      HTTPSEnable : 0
    }
  }
  __SUPPLEMENTAL__ : <array> {
    0 : <dictionary> {
      HTTPEnable : 1
      HTTPPort : 8080
      HTTPProxy : vpn.corp.example
      SupplementalMatchDomain : corp.example
    }
  }
}
";

    #[test]
    fn only_the_top_settings_count() {
        let system = parse_scutil(SCUTIL_NESTED);
        assert_eq!(system.proxies.get("https").map(String::as_str), Some("http://secure.corp.example:3129"));
        assert!(!system.proxies.contains_key("http"), "the VPN's, for its domain only: {:?}", system.proxies);
        assert_eq!(system.exceptions, vec!["*.local", "169.254/16"]);
        assert!(!system.exclude_simple);
        let via = choose("connect.tterm.net", 443, true, &HashMap::new(), Some(&system)).unwrap();
        assert_eq!(via.map(|p| p.name()), Some("secure.corp.example:3129".to_string()));
        // Nothing at the top, a proxy for a VPN's domain only: direct.
        let vpn_only = parse_scutil(
            "<dictionary> {\n  FTPPassive : 1\n  __SUPPLEMENTAL__ : <array> {\n    0 : <dictionary> {\n      HTTPSEnable : 1\n      HTTPSProxy : vpn.example\n    }\n  }\n}\n",
        );
        assert!(vpn_only.proxies.is_empty(), "{:?}", vpn_only.proxies);
    }

    #[test]
    fn patterns_and_ranges() {
        assert!(matches("*.local", "printer.local"));
        assert!(!matches("*.local", "printer.local:443"));
        assert!(matches("*", ""));
        assert!(matches("a?c*", "abcdef"));
        assert!(!matches("a?c", "ac"));
        assert_eq!(address_range("169.254/16"), Some((169 << 24 | 254 << 16, 16)));
        assert_eq!(address_range("10"), Some((10 << 24, 8)));
        assert_eq!(address_range("192.168.1.5"), Some((0xC0A80105, 32)));
        assert_eq!(address_range("*.local"), None);
        assert_eq!(address_range("10.0.0.0/40").map(|r| r.1), Some(40));
        assert_eq!(address_range("10./8"), Some((10 << 24, 8)));
        assert_eq!(address_range("1..2/8"), Some((1 << 24, 8)));
        assert_eq!(address_range("1.2.3.4.5"), Some((0x01020304, 40)));
    }
}
