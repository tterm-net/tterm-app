//! The page's requests once the app is signed in (from 0.3.0): they go to
//! tTerm Web in the cloud, in the app's session, and come back as tTerm
//! answered them. This computer's own terminals stay here: opened on the
//! machine this computer is in tTerm, or known to this app's store.
//!
//! What only the app does is answered here, signed in or not: signing in
//! with the browser (`/api/auth/link`), the welcome of the first start
//! (`/api/app/welcome`), This computer in Settings (`/api/app/this-computer`,
//! from 0.4.0: reach.rs), and Sign out, which forgets the app's key too.
//! `/api/state` is tTerm's, with this computer's machine marked `here` and
//! this app's terminals with the rest (account::merge_state); when tTerm
//! cannot be reached, it is what tTerm said last, with `"offline": true`,
//! and requests that need tTerm are refused with words the page shows.

use crate::account::{self, Account, Trouble};
use crate::api::{Flags, Response};
use crate::reach::NotOn;
use crate::{names, Engine};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

/// What a request that needs tTerm gets while it cannot be reached.
pub const OFFLINE: &str = "No connection to tTerm. This computer works as usual; the rest comes back with the connection.";
const SIGNED_OUT: &str = "Signed out of tTerm on this computer.";
const STAYS: &str = "This is the computer tTerm runs on: it stays in the app.";

/// Answers the request if the cloud has it; None for what is answered
/// here, for this computer (api.rs).
pub async fn route(engine: &Arc<Engine>, method: &str, path: &str, body: &[u8], flags: Flags) -> Option<Response> {
    let account = engine.cloud.clone()?;
    let (bare, _) = path.split_once('?').unwrap_or((path, ""));
    let parts: Vec<&str> = bare.trim_start_matches('/').split('/').collect();
    let method = method.to_ascii_uppercase();
    if parts.as_slice() == ["health"] {
        return None;
    }
    account.wait_ready().await;
    // The app's own, signed in or not.
    match (method.as_str(), parts.as_slice()) {
        ("POST", ["api", "auth", "link"]) => {
            let again = serde_json::from_slice::<Value>(body).ok().and_then(|b| b.get("again").and_then(Value::as_bool)).unwrap_or(false);
            return Some(match account.start_link(engine, again).await {
                Ok(code) => Response::json(200, json!({"code": code})),
                Err(why) => Response::error(409, &why),
            });
        }
        ("GET", ["api", "auth", "link"]) => return Some(Response::json(200, account.link_status())),
        ("DELETE", ["api", "auth", "link"]) => {
            account.cancel_link();
            return Some(Response::json(200, json!({})));
        }
        ("POST", ["api", "app", "welcome"]) => {
            let saved = engine.save_settings(|s| s.welcome_seen = true);
            return Some(if saved.is_ok() { Response::empty(204) } else { Response::error(500, "Could not save the settings on this computer.") });
        }
        ("GET", ["api", "app", "this-computer"]) => return Some(Response::json(200, engine.reach.json(engine))),
        ("PUT", ["api", "app", "this-computer"]) => {
            let Some(open) = serde_json::from_slice::<Value>(body).ok().and_then(|b| b.get("open").and_then(Value::as_bool)) else {
                return Some(Response::error(422, "Say open: true or false."));
            };
            let done = if open { engine.reach.turn_on(engine).await } else { engine.reach.turn_off(engine).await.map_err(NotOn::Unsaved) };
            // The answer says what the link does now.
            engine.reach.settle(engine).await;
            return Some(match done {
                Ok(()) => Response::json(200, engine.reach.json(engine)),
                Err(NotOn::SignedOut) => Response::error(409, "Sign in first: this Mac opens from tTerm Web in your account."),
                Err(NotOn::Refused(why)) => Response::error(409, &why),
                Err(NotOn::Unsaved(_)) => Response::error(500, "Could not save the settings on this computer."),
            });
        }
        _ => {}
    }
    if !account.signed_in() {
        return None;
    }
    let here = account.here();
    match (method.as_str(), parts.as_slice()) {
        ("GET", ["api", "state"]) => Some(state(engine, &account, flags.background).await),
        ("POST", ["api", "auth", "signout"]) => {
            account.sign_out().await;
            engine.align_terminals();
            engine.reach.look_again();
            Some(Response::json(200, json!({"signedOut": true})))
        }
        ("POST", ["api", "auth", "signout-everywhere"]) => {
            let answer = proxy(&account, &method, path, body, flags).await;
            if answer.status == 200 {
                account.forget_here().await;
                engine.align_terminals();
                engine.reach.look_again();
            }
            Some(answer)
        }
        ("DELETE", ["api", "devices", id]) => {
            let answer = proxy(&account, &method, path, body, flags).await;
            let ours = account.device_id().map(|d| d == *id).unwrap_or(false);
            if answer.status == 200 && ours {
                account.forget_here().await;
                engine.align_terminals();
                engine.reach.look_again();
            }
            Some(answer)
        }
        // The sign-in screen's question: signed in, here, whatever tTerm
        // says while it cannot be reached.
        ("GET", ["api", "auth", "state"]) if account.offline() => None,
        // A terminal on this computer: here.
        ("POST", ["api", "terminals"]) => {
            let machine = serde_json::from_slice::<Value>(body).ok().and_then(|b| b.get("machineId").and_then(Value::as_str).and_then(|m| Uuid::parse_str(m).ok()));
            if machine.map(|m| engine.is_here(m)).unwrap_or(false) {
                None
            } else {
                Some(proxy(&account, &method, path, body, flags).await)
            }
        }
        (_, ["api", "terminals", id, ..]) => {
            if local_terminal(engine, id).await {
                None
            } else {
                Some(proxy(&account, &method, path, body, flags).await)
            }
        }
        // Search (from 0.3.1): tTerm's answer and this computer's, as one.
        ("GET", ["api", "search"]) => Some(search(engine, &account, path, flags).await),
        // This computer's machine: tTerm's page of it while it answers.
        ("GET", ["api", "machines", id]) if account.offline() && Uuid::parse_str(id).map(|m| engine.is_here(m)).unwrap_or(false) => None,
        ("DELETE", ["api", "machines", id]) if Uuid::parse_str(id).map(|m| engine.is_here(m)).unwrap_or(false) => Some(Response::error(403, STAYS)),
        (_, ["api", ..]) => {
            let _ = &here;
            Some(proxy(&account, &method, path, body, flags).await)
        }
        _ => None,
    }
}

/// Whether the terminal is this computer's: running in this app, or kept
/// in its store.
pub async fn local_terminal(engine: &Arc<Engine>, id: &str) -> bool {
    let Ok(id) = Uuid::parse_str(id) else { return false };
    engine.terminals.get(&id).is_some() || engine.terminals.store.known(&id.to_string()).await
}

/// The request, to tTerm, and its answer, as the page gets it.
async fn proxy(account: &Arc<Account>, method: &str, path: &str, body: &[u8], flags: Flags) -> Response {
    let body = (!(method == "GET" || method == "HEAD") || !body.is_empty()).then_some(body);
    match account.call_as(method, path, body, flags.body_type, flags.background).await {
        Ok(answer) => Response { status: answer.status, content_type: content_type(&answer.content_type), body: answer.body },
        Err(Trouble::Offline) => Response::error(503, OFFLINE),
        Err(Trouble::SignedOut) => signed_out(),
    }
}

/// How long search waits for tTerm's half, at most: then this computer's
/// half goes alone, and tTerm is not taken for gone over a slow search.
const CLOUD_SEARCH_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Search, signed in: tTerm finds what is there, this computer what runs in
/// the app (search.rs), both at once; without tTerm, or with tTerm slow,
/// this computer's alone.
async fn search(engine: &Arc<Engine>, account: &Arc<Account>, path: &str, flags: Flags) -> Response {
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let near = crate::api::query_text(query, "near");
    let q = crate::api::query_text(query, "q");
    let near = Some(near.as_str()).filter(|n| !n.is_empty());
    let cloud = tokio::time::timeout(CLOUD_SEARCH_WAIT, account.call("GET", path, None, flags.background));
    let (local, cloud) = tokio::join!(crate::search::search(engine, &q, near, false), cloud);
    match cloud {
        Ok(Ok(answer)) if answer.status == 200 => match answer.json() {
            Some(found) => Response::json(200, crate::search::merge(&local, &found)),
            None => Response::json(200, local),
        },
        Ok(Err(Trouble::SignedOut)) => signed_out(),
        _ => Response::json(200, local),
    }
}

/// What the page takes for a session that ended, as the core says it
/// (`signed_in` in page.py): it then starts over, here before signing in.
fn signed_out() -> Response {
    Response::json(401, json!({"error": SIGNED_OUT, "signedOut": true}))
}

/// The types tTerm's answers come in, as the page reads them: a photo is a
/// JPEG (from 0.3.1).
fn content_type(given: &str) -> &'static str {
    if given.starts_with("application/json") {
        "application/json"
    } else if given.starts_with("text/plain") {
        "text/plain"
    } else if given.starts_with("image/jpeg") {
        "image/jpeg"
    } else {
        "application/octet-stream"
    }
}

/// The page's state, signed in.
async fn state(engine: &Arc<Engine>, account: &Arc<Account>, background: bool) -> Response {
    // Which machine this computer is, if tTerm has not said it yet (its
    // details in the folder gone): asked first, a while at most.
    if !account.offline() && account.here_unknown() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(15), account.ensure_here(engine)).await;
    }
    let fresh = if account.offline() { None } else { Some(account.cloud_state(background).await) };
    let (cloud, offline) = match fresh {
        Some(Ok(cloud)) => (cloud, false),
        Some(Err(Trouble::SignedOut)) => {
            // Forgotten meanwhile: the page starts over, before signing in.
            return signed_out();
        }
        _ => match account.last_state() {
            Some(last) => (last, true),
            None => (bare_state(engine, account), true),
        },
    };
    engine.align_terminals();
    let terminals = engine.terminals.live().iter().map(|t| t.describe()).collect();
    let mut machine = engine.machine_json();
    if offline {
        machine["online"] = json!(true);
    }
    Response::json(200, account::merge_state(&cloud, account.here().as_ref(), machine, terminals, offline))
}

/// What the page needs when tTerm never answered since signing in: the
/// person, and Personal with this computer.
fn bare_state(engine: &Arc<Engine>, account: &Arc<Account>) -> Value {
    let me = account.me();
    let name = me["name"].as_str().map(str::to_string).unwrap_or_else(|| engine.person_name());
    let settings = engine.settings.lock().unwrap().clone();
    let here = account.here();
    json!({
        "version": format!("app {}", crate::VERSION),
        "me": {
            "id": me["id"].as_str().unwrap_or(""),
            "name": name,
            "firstName": names::first_name(&name),
            "initials": names::initials(&name),
            "theme": settings.theme,
            "projectTint": settings.project_tint,
            "plan": "free",
            "email": me["email"].clone(),
        },
        "projects": [{
            "id": here.as_ref().map(|h| h.project_id.clone()).unwrap_or_else(|| settings.project_id.to_string()),
            "name": "Personal",
            "code": here.as_ref().map(|h| h.code.clone()).unwrap_or_else(|| settings.project_code.clone()),
            "color": settings.project_color,
            "role": "owner",
            "personal": true,
            "own": true,
            "alone": true,
            "machines": [],
            "folders": [],
        }],
        "terminals": [],
    })
}
