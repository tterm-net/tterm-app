//! The way to tTerm Web in the cloud (from 0.3.0): its requests, and its
//! socket, for the page of a person who signed in.
//!
//! TLS is the agent's link's own, the engine's one setting
//! (link::tls_config): rustls on ring, TLS 1.2 and 1.3, the roots of Mozilla
//! and those of this computer (on a Mac its keychains, which have a
//! company's own certificates). Plain HTTP only to this very computer, for
//! the checks.

use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// tTerm Web.
pub const CLOUD: &str = "https://app.tterm.net";

/// How long a connection to tTerm may take to open, and a request to be
/// answered: past them tTerm counts as out of reach.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The header of what the page asks by itself, now and then: the core
/// keeps no session on for it (`BACKGROUND_HEADER` in page.py).
pub const BACKGROUND: &str = "x-tterm-background";

/// The page's socket on tTerm.
pub type CloudSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// TLS for every connection to tTerm: the link's (link::tls_config).
pub fn tls_config() -> Arc<rustls::ClientConfig> {
    crate::link::tls_config()
}

/// tTerm could not be reached: no network, the server restarting, a
/// request with no answer in time. What it was, for the log.
#[derive(Debug, Clone)]
pub struct Unreachable(pub String);

/// An answer of tTerm.
#[derive(Debug, Clone)]
pub struct Answer {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// The core's words in an answer that refuses: `{"error": "…"}`.
    pub fn error(&self) -> Option<String> {
        self.json().and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
    }
}

/// What the socket on tTerm would not open with.
#[derive(Debug)]
pub enum SocketRefused {
    /// The session is over (401, 403), or tTerm said no otherwise.
    Status(u16),
    Unreachable(Unreachable),
}

/// tTerm Web at an address: `https://app.tterm.net`, or for the checks one
/// on this very computer.
#[derive(Clone)]
pub struct Cloud {
    /// Scheme, host and port, as the page's Origin is: no slash at the end.
    pub base: String,
    http: reqwest::Client,
}

impl Cloud {
    pub fn new(base: &str) -> Cloud {
        let base = base.trim_end_matches('/').to_string();
        let mut builder = reqwest::Client::builder()
            .use_preconfigured_tls((*tls_config()).clone())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(format!("tTerm/{}", crate::VERSION));
        if base.starts_with("http://") {
            // The checks' tTerm on this computer: never through a proxy.
            builder = builder.no_proxy();
        }
        Cloud { http: builder.build().expect("the HTTP client"), base }
    }

    /// The address of the page there.
    pub fn host(&self) -> &str {
        self.base.split_once("://").map(|(_, h)| h).unwrap_or(&self.base)
    }

    /// A request, as the page makes it there: with the header the core
    /// wants on what changes something, and the page's Origin. `cookie` is
    /// the Cookie header, if any; `background`, for what the page asks by
    /// itself.
    pub async fn send(&self, method: &str, path: &str, body: Option<&[u8]>, cookie: Option<&str>, background: bool) -> Result<Answer, Unreachable> {
        self.send_as(method, path, body, "application/json", cookie, background).await
    }

    /// The same, with a body of another type than JSON (a photo).
    pub async fn send_as(&self, method: &str, path: &str, body: Option<&[u8]>, body_type: &str, cookie: Option<&str>, background: bool) -> Result<Answer, Unreachable> {
        let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| Unreachable(format!("no such method: {method}")))?;
        let mut request = self
            .http
            .request(method.clone(), format!("{}{}", self.base, path))
            .header("accept", "application/json")
            .header("x-tterm", "1");
        if method != reqwest::Method::GET && method != reqwest::Method::HEAD {
            request = request.header("origin", &self.base);
        }
        if let Some(body) = body {
            request = request.header("content-type", body_type).body(body.to_vec());
        }
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        if background {
            request = request.header(BACKGROUND, "1");
        }
        let response = request.send().await.map_err(|e| Unreachable(why(&e)))?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        let body = response.bytes().await.map_err(|e| Unreachable(why(&e)))?.to_vec();
        let answer = Answer { status, content_type, body };
        if gateway_down(&answer) {
            return Err(Unreachable(format!("tTerm answered {status}: the server is restarting or down")));
        }
        Ok(answer)
    }

    /// JSON there and back.
    pub async fn json(&self, method: &str, path: &str, body: &Value, cookie: Option<&str>) -> Result<Answer, Unreachable> {
        self.send(method, path, Some(body.to_string().as_bytes()), cookie, false).await
    }

    /// The page's socket there, with the session in `cookie` and the page's
    /// Origin, as the core wants it.
    pub async fn socket(&self, cookie: &str) -> Result<CloudSocket, SocketRefused> {
        let scheme = if self.base.starts_with("https://") { "wss" } else { "ws" };
        let url = format!("{scheme}://{}/api/ws", self.host());
        let mut request = url.into_client_request().map_err(|e| SocketRefused::Unreachable(Unreachable(e.to_string())))?;
        let headers = request.headers_mut();
        headers.insert("origin", HeaderValue::from_str(&self.base).map_err(|e| SocketRefused::Unreachable(Unreachable(e.to_string())))?);
        headers.insert("cookie", HeaderValue::from_str(cookie).map_err(|e| SocketRefused::Unreachable(Unreachable(e.to_string())))?);
        let connector = tokio_tungstenite::Connector::Rustls(tls_config());
        let connecting = tokio_tungstenite::connect_async_tls_with_config(request, None, true, Some(connector));
        match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
            Err(_) => Err(SocketRefused::Unreachable(Unreachable("the socket did not open in time".into()))),
            Ok(Ok((socket, _))) => Ok(socket),
            Ok(Err(tokio_tungstenite::tungstenite::Error::Http(response))) => {
                let status = response.status().as_u16();
                if matches!(status, 502..=504) {
                    Err(SocketRefused::Unreachable(Unreachable(format!("tTerm answered {status}"))))
                } else {
                    Err(SocketRefused::Status(status))
                }
            }
            Ok(Err(e)) => Err(SocketRefused::Unreachable(Unreachable(e.to_string()))),
        }
    }
}

/// What reqwest says went wrong, with what lies under it.
fn why(error: &reqwest::Error) -> String {
    let mut text = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(s) = source {
        text.push_str(": ");
        text.push_str(&s.to_string());
        source = s.source();
    }
    text
}

/// nginx in front of the core, with the core not there (restarting, or
/// down): the page cannot reach tTerm, as without a network. The core's
/// own refusals are JSON.
fn gateway_down(answer: &Answer) -> bool {
    matches!(answer.status, 502 | 504) || (answer.status == 503 && !answer.content_type.starts_with("application/json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hosts() {
        assert_eq!(Cloud::new("https://app.tterm.net/").host(), "app.tterm.net");
        assert_eq!(Cloud::new("http://127.0.0.1:8090").host(), "127.0.0.1:8090");
        assert_eq!(Cloud::new("https://app.tterm.net").base, "https://app.tterm.net");
    }

    #[test]
    fn tls_is_ring_with_roots() {
        let config = tls_config();
        assert!(Arc::ptr_eq(&config, &tls_config()), "made once");
    }

    #[test]
    fn a_gateway_is_no_answer_of_the_core() {
        let a = |status, ty: &str| Answer { status, content_type: ty.into(), body: Vec::new() };
        assert!(gateway_down(&a(502, "text/html")));
        assert!(gateway_down(&a(503, "text/html")));
        assert!(!gateway_down(&a(503, "application/json")));
        assert!(!gateway_down(&a(401, "application/json")));
    }
}
