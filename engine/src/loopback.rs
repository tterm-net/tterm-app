//! Where the browser comes back to when signing in (from 0.3.0): a port on
//! 127.0.0.1 of this computer, open only while the app waits (RFC 8252,
//! 7.3). The page of tTerm Web sends the browser to
//! `http://127.0.0.1:<port>/signed-in?code=…&state=…` once the person
//! allowed the app, or with `error=cancelled`; the app answers with a page
//! of its own, in the look of tTerm's, and stops listening.
//!
//! Nothing else is answered: a request for another path gets 404, one that
//! names another host 421 (a site that made its own name point here, to
//! talk to the app as if it were this computer), and one without the
//! sign-in's `state` a page that says it is not for this sign-in. A request
//! is a few kilobytes at most and must come within seconds. Connections are
//! read side by side, so that one left open does not keep the browser
//! waiting; a few dozen at most are waited for, and when one more comes, the
//! one waited for longest is closed for it: however many are left open, the
//! browser's is read.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};

/// A request, at most: its line and headers.
const HEAD_MAX: usize = 8 * 1024;
/// How long a request may take to arrive.
const READ_WAIT: Duration = Duration::from_secs(2);
/// How long the answer may take to go.
const WRITE_WAIT: Duration = Duration::from_secs(5);
/// Connections waited for at once, at most, until their request comes:
/// more than a browser opens.
const AT_ONCE: usize = 64;

/// A port of this computer only, chosen by the system.
pub async fn listen() -> std::io::Result<(TcpListener, u16)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

/// Why listening ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    /// The browser came back, and the sign-in is over.
    Done,
    /// The app stopped waiting (Cancel, or a new sign-in).
    Stopped,
    /// The browser did not come back in time.
    TimedOut,
}

/// The page the browser gets.
#[derive(Debug, Clone, PartialEq)]
pub enum Page {
    Done,
    /// The browser came back once more while the first return is being
    /// finished (a reload, Allow in a second tab).
    Finishing,
    Cancelled,
    Failed(String),
    NotThis,
}

/// What the app makes of the browser's return: the page, and whether the
/// sign-in is over (then nothing more is answered).
pub struct Answer {
    pub page: Page,
    pub done: bool,
}

/// The connections whose request has not come yet, the longest waited for
/// first.
#[derive(Default)]
struct Waited {
    next: u64,
    queue: VecDeque<(u64, oneshot::Sender<()>)>,
}

impl Waited {
    /// One more connection to wait for: its number, and what tells it that
    /// it gave way to a newer one. When as many are waited for as may be,
    /// the first of them gives way.
    fn join(&mut self) -> (u64, oneshot::Receiver<()>) {
        if self.queue.len() >= AT_ONCE {
            if let Some((_, first)) = self.queue.pop_front() {
                let _ = first.send(());
            }
        }
        let (give_way, given_way) = oneshot::channel();
        let id = self.next;
        self.next += 1;
        self.queue.push_back((id, give_way));
        (id, given_way)
    }

    /// Its request came, or not: no longer waited for.
    fn leave(&mut self, id: u64) {
        self.queue.retain(|(i, _)| *i != id);
    }
}

/// Answers on `listener` until the sign-in is over, `stop` says so, or
/// `wait` has passed. `handler` gets the query of `/signed-in`. Each
/// connection is answered on its own: one the handler is busy with is
/// answered to the end, whatever happens meanwhile.
pub async fn serve<F, Fut>(listener: TcpListener, port: u16, title: String, mut stop: watch::Receiver<bool>, wait: Duration, handler: F) -> Ended
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Answer> + Send + 'static,
{
    let deadline = tokio::time::Instant::now() + wait;
    let handler = Arc::new(handler);
    let title = Arc::new(title);
    let (over, mut overs) = mpsc::channel::<()>(1);
    let waited = Arc::new(Mutex::new(Waited::default()));
    loop {
        let accepted = tokio::select! {
            a = listener.accept() => a,
            _ = overs.recv() => return Ended::Done,
            _ = stop.wait_for(|s| *s) => return Ended::Stopped,
            _ = tokio::time::sleep_until(deadline) => return Ended::TimedOut,
        };
        let Ok((mut stream, _)) = accepted else {
            // No room for one more on this computer just now (too many open
            // files): a moment, rather than asking again and again.
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let (id, given_way) = waited.lock().unwrap().join();
        let (handler, title, over, waited) = (handler.clone(), title.clone(), over.clone(), waited.clone());
        tokio::spawn(async move {
            // A request already here is read first: it is answered, even
            // if newer connections took its place meanwhile.
            let head = tokio::select! {
                biased;
                head = tokio::time::timeout(READ_WAIT, read_head(&mut stream)) => head.ok().flatten(),
                _ = given_way => None,
            };
            waited.lock().unwrap().leave(id);
            let Some(head) = head else { return };
            if answer(stream, &head, port, &title, &*handler).await {
                let _ = over.send(()).await;
            }
        });
    }
}

/// One request, come: true once the sign-in is over.
async fn answer<F, Fut>(mut stream: TcpStream, head: &str, port: u16, title: &str, handler: &F) -> bool
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Answer>,
{
    let Some(request) = parse(head) else {
        let _ = reply(&mut stream, 400, "text/plain; charset=utf-8", b"Not understood.\n").await;
        return false;
    };
    if !request.host.eq_ignore_ascii_case(&format!("127.0.0.1:{port}")) {
        let _ = reply(&mut stream, 421, "text/plain; charset=utf-8", b"Not here.\n").await;
        return false;
    }
    if request.method != "GET" || request.path != "/signed-in" {
        let _ = reply(&mut stream, 404, "text/plain; charset=utf-8", b"Not found.\n").await;
        return false;
    }
    let Answer { page, done } = handler(request.query).await;
    let status = if page == Page::NotThis { 400 } else { 200 };
    let _ = reply(&mut stream, status, "text/html; charset=utf-8", render(&page, title).as_bytes()).await;
    done
}

async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            buf.truncate(end);
            return String::from_utf8(buf).ok();
        }
        if buf.len() > HEAD_MAX {
            return None;
        }
    }
}

#[derive(Debug, PartialEq)]
struct Request {
    method: String,
    path: String,
    query: String,
    host: String,
}

fn parse(head: &str) -> Option<Request> {
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target, version) = (first.next()?, first.next()?, first.next()?);
    if !version.starts_with("HTTP/1.") || first.next().is_some() {
        return None;
    }
    let host = lines.filter_map(|l| l.split_once(':')).find(|(name, _)| name.trim().eq_ignore_ascii_case("host")).map(|(_, v)| v.trim().to_string())?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Some(Request { method: method.to_string(), path: path.to_string(), query: query.to_string(), host })
}

/// One value of a query, decoded, as the browser encoded it.
pub fn query_value(query: &str, name: &str) -> Option<String> {
    query.split('&').filter_map(|pair| pair.split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| decode(v))
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let pair = (b == b'%' && i + 2 < bytes.len()).then(|| hex(bytes[i + 1]).zip(hex(bytes[i + 2]))).flatten();
        if let Some((hi, lo)) = pair {
            out.push(hi << 4 | lo);
            i += 3;
            continue;
        }
        out.push(if b == b'+' { b' ' } else { b });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn reply(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        421 => "Misdirected Request",
        _ => "",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
         Referrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tokio::time::timeout(WRITE_WAIT, async {
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.shutdown().await
    })
    .await
    .unwrap_or(Ok(()))
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

const LOGO: &str = r##"<svg width="36" height="36" viewBox="0 0 512 512" aria-hidden="true"><rect width="512" height="512" rx="116" fill="#131417"/><path d="M118 168 L206 256 L118 344" fill="none" stroke="#E9A33F" stroke-width="56" stroke-linecap="round" stroke-linejoin="round"/><path d="M330 140 L330 316 C330 344 344 356 372 350" fill="none" stroke="#EDEFF3" stroke-width="56" stroke-linecap="round"/><path d="M272 212 L392 212" fill="none" stroke="#EDEFF3" stroke-width="56" stroke-linecap="round"/></svg>"##;

const STYLE: &str = r#"
:root { --page: #F3F4F6; --paper: #FFFFFF; --line: transparent; --ink: #15171C; --dim: #545B67; --faint: #5F6673;
  --green-ink: #15702F; --green-tint: rgba(47, 158, 76, .12); --amber-ink: #93560A; --amber-tint: rgba(233, 163, 63, .16);
  --raised: #E8EAEE; --shadow: 0 1px 2px rgba(21, 23, 28, .04), 0 12px 32px rgba(21, 23, 28, .07); color-scheme: light dark; }
@media (prefers-color-scheme: dark) {
  :root { --page: #0D0E11; --paper: #16181C; --line: #262A31; --ink: #EDEFF3; --dim: #9AA0AA; --faint: #7D838E;
    --green-ink: #46B95C; --green-tint: rgba(70, 185, 92, .12); --amber-ink: #E9A33F; --amber-tint: rgba(233, 163, 63, .12);
    --raised: #1D2026; --shadow: none; }
}
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--page); color: var(--ink);
  font: 15px/1.5 Manrope, -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }
body { min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 0 16px; }
header { display: flex; align-items: center; gap: 12px; padding-top: 48px; font: 800 28px/1 Manrope, -apple-system, BlinkMacSystemFont, system-ui, sans-serif; letter-spacing: -.02em; }
main { flex: 1 0 auto; width: 100%; display: flex; align-items: center; justify-content: center; padding: 40px 0; }
section { width: 100%; max-width: 440px; padding: 44px 40px 36px; border: 1px solid var(--line); border-radius: 24px;
  background: var(--paper); box-shadow: var(--shadow); text-align: center; }
.mark { width: 44px; height: 44px; margin: 0 auto; display: flex; align-items: center; justify-content: center; border-radius: 50%; }
.ok { background: var(--green-tint); color: var(--green-ink); }
.warn { background: var(--amber-tint); color: var(--amber-ink); }
.off { background: var(--raised); color: var(--dim); }
h1 { margin: 16px 0 0; font-size: 28px; line-height: 1.2; font-weight: 800; letter-spacing: -.02em; overflow-wrap: anywhere; }
p { margin: 10px 0 0; font-size: 15px; color: var(--dim); overflow-wrap: anywhere; }
footer { padding: 24px 0 32px; font-size: 13px; }
footer a { color: var(--faint); text-decoration: none; }
@media (max-width: 480px) { section { padding: 32px 22px 28px; } h1 { font-size: 24px; } }
"#;

/// The page for the browser, in the look of tTerm Web's sign-in.
pub fn render(page: &Page, app_title: &str) -> String {
    let app = escape(app_title);
    let (class, icon, heading, text) = match page {
        Page::Done => ("ok", r#"<path d="M5 12l5 5L20 7"/>"#, "You are in".to_string(), format!("Go back to {app}. This page can be closed.")),
        Page::Finishing => (
            "off",
            r#"<path d="M7 12h.01M12 12h.01M17 12h.01"/>"#,
            "Signing in is being finished".to_string(),
            format!("{app} finishes it from another page of the browser. Go back to {app}; this page can be closed."),
        ),
        Page::Cancelled => (
            "off",
            r#"<path d="M7 7l10 10M17 7L7 17"/>"#,
            "Signing in was cancelled".to_string(),
            format!("{app} works on with this computer only. This page can be closed."),
        ),
        Page::Failed(why) => (
            "warn",
            r#"<path d="M12 7v6"/><path d="M12 17h.01"/>"#,
            "Signing in did not work".to_string(),
            format!("{} Start again in {app}: Sign in with your browser.", escape(why)),
        ),
        Page::NotThis => (
            "warn",
            r#"<path d="M12 7v6"/><path d="M12 17h.01"/>"#,
            "This page is not for this sign-in".to_string(),
            format!("Start again in {app}: Sign in with your browser."),
        ),
    };
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"robots\" content=\"noindex\">\n<title>{heading} · tTerm</title>\n<style>{STYLE}</style>\n</head>\n<body>\n\
         <header>{LOGO}<span>tTerm</span></header>\n<main><section>\n\
         <span class=\"mark {class}\" aria-hidden=\"true\"><svg width=\"22\" height=\"22\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.6\" stroke-linecap=\"round\" stroke-linejoin=\"round\">{icon}</svg></span>\n\
         <h1>{heading}</h1>\n<p>{text}</p>\n</section></main>\n\
         <footer><a href=\"mailto:{support}\">{support}</a></footer>\n</body>\n</html>\n",
        support = crate::SUPPORT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_read() {
        let r = parse("GET /signed-in?code=abc&state=x%2Dy HTTP/1.1\r\nHost: 127.0.0.1:5123\r\nUser-Agent: x").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/signed-in");
        assert_eq!(r.host, "127.0.0.1:5123");
        assert_eq!(query_value(&r.query, "state").as_deref(), Some("x-y"));
        assert_eq!(query_value(&r.query, "code").as_deref(), Some("abc"));
        assert_eq!(query_value(&r.query, "error"), None);
        assert_eq!(parse("GET / HTTP/1.1\r\nUser-Agent: x"), None, "no host");
        assert_eq!(parse("GARBAGE"), None);
        assert_eq!(decode("a+b%20c%"), "a b c%");
        assert_eq!(decode("%zz%41"), "%zzA");
    }

    /// The browser's request came, then many newer connections, before its
    /// own is read (one thread, as when the app is busy): it gave way, and
    /// is answered all the same.
    #[tokio::test]
    async fn a_request_come_is_answered_whatever_comes_after() {
        // Room for the connections: a Mac gives a process 256 open files.
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: the calls get a valid pointer, and change only this
        // process's limit.
        unsafe {
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 && limit.rlim_cur < 1024 {
                limit.rlim_cur = limit.rlim_max.min(1024);
                libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
            }
        }
        for _ in 0..20 {
            let (listener, port) = listen().await.unwrap();
            let mut browser = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            browser.write_all(format!("GET /signed-in?state=s HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes()).await.unwrap();
            let mut newer = Vec::new();
            for _ in 0..AT_ONCE {
                newer.push(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
            }
            let (_stop, stopped) = watch::channel(false);
            let handler = |_query: String| async { Answer { page: Page::Done, done: true } };
            let serving = tokio::spawn(serve(listener, port, "tTerm".into(), stopped, Duration::from_secs(5), handler));
            let mut out = String::new();
            browser.read_to_string(&mut out).await.unwrap();
            assert!(out.contains("You are in"), "{out:?}");
            assert_eq!(serving.await.unwrap(), Ended::Done);
            drop(newer);
        }
    }

    #[test]
    fn the_pages() {
        let done = render(&Page::Done, "tTerm for Mac");
        assert!(done.contains("You are in") && done.contains("Go back to tTerm for Mac."));
        let failed = render(&Page::Failed("<b>No</b>".into()), "tTerm for Mac");
        assert!(failed.contains("&lt;b&gt;No&lt;/b&gt;") && !failed.contains("<b>No"));
        assert!(!done.contains("<script"));
    }
}
