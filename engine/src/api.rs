//! The page's requests, answered for this computer the way tterm-web's core
//! answers them (`tterm/api/page.py`): the same paths, the same JSON, the
//! same refusals where the page reads them.
//!
//! What only an account can do (sign-in, more projects, servers, notes) is
//! refused with a sentence the page shows: it comes with signing in, in a
//! later version of the app.

use crate::{names, settings, Engine};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    fn json(status: u16, value: Value) -> Self {
        Response { status, content_type: "application/json", body: value.to_string().into_bytes() }
    }

    fn error(status: u16, message: &str) -> Self {
        Self::json(status, json!({"error": message}))
    }

    fn empty(status: u16) -> Self {
        Response { status, content_type: "text/plain", body: Vec::new() }
    }
}

const LATER_ACCOUNT: &str = "This comes with signing in to tTerm, in a later version of the app. For now the app works with this computer only.";
const LATER_NOTES: &str = "Notes come to the app with signing in, in a later version. Until then they are in tTerm Web, in your browser.";
const LATER_MACHINES: &str = "Servers and other computers come to the app with signing in, in a later version. Until then they are in tTerm Web, in your browser.";
const NOT_OPEN: &str = "The terminal is not open.";

fn body_json(body: &[u8]) -> Option<Value> {
    if body.is_empty() {
        return Some(json!({}));
    }
    serde_json::from_slice(body).ok()
}

fn uuid_of(text: &str) -> Option<Uuid> {
    Uuid::parse_str(text).ok()
}

/// Answers one request of the page: `path` with its query, as the page
/// wrote it ("/api/terminals/…/blocks?limit=60").
pub async fn handle(engine: &Arc<Engine>, method: &str, path: &str, body: &[u8]) -> Response {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let method = method.to_ascii_uppercase();
    match (method.as_str(), parts.as_slice()) {
        // ------------------------------------------------------- sign in
        ("GET", ["api", "auth", "state"]) => Response::json(200, json!({"signedIn": true, "legal": engine.legal_json()})),
        ("POST", ["api", "auth", _]) => Response::error(409, LATER_ACCOUNT),
        ("GET", ["api", "devices"]) => Response::json(200, json!({"devices": []})),
        ("DELETE", ["api", "devices", _]) => Response::error(404, "no such device"),
        ("GET", ["health"]) => Response::json(200, json!({"ok": true, "service": "tterm app", "version": crate::VERSION})),

        // ---------------------------------------------- the person, the page
        ("GET", ["api", "state"]) => Response::json(200, engine.state_json()),
        ("PATCH", ["api", "me"]) => patch_me(engine, body),
        ("GET", ["api", "account"]) => Response::json(200, json!({
            "plan": {"id": "free", "name": "Free", "limits": {"machines": 1, "terminals": crate::MOST_TERMINALS}},
            "usage": {"machines": 1, "terminals": engine.terminals.live().len()},
            "devices": [],
            "legal": engine.legal_json(),
        })),

        // ------------------------------------------------------ machines
        ("POST", ["api", "installs"]) => Response::error(403, LATER_MACHINES),
        ("GET", ["api", "installs", _]) => Response::error(404, "no such install"),
        ("GET", ["api", "machines", id]) => {
            if uuid_of(id) == Some(engine.settings.lock().unwrap().machine_id) {
                Response::json(200, engine.machine_details())
            } else {
                Response::error(404, "no such machine")
            }
        }
        ("DELETE", ["api", "machines", _]) => Response::error(403, "This is the computer tTerm runs on: it stays in the app."),
        ("POST", ["api", "machines", _, "move"]) => Response::error(403, LATER_ACCOUNT),

        // ----------------------------------------------------- terminals
        ("POST", ["api", "terminals"]) => open_terminal(engine, body).await,
        ("GET", ["api", "terminals", id]) => match uuid_of(id).and_then(|id| engine.terminals.get(&id)) {
            Some(t) => Response::json(200, t.describe()),
            None => Response::error(404, "no such terminal"),
        },
        ("PATCH", ["api", "terminals", id]) => {
            let Some(id) = uuid_of(id) else { return Response::error(404, "no such terminal") };
            let name = body_json(body).and_then(|b| b.get("name").and_then(Value::as_str).map(str::to_string));
            let Some(name) = name else { return Response::error(422, "Name the terminal: up to 40 characters.") };
            match engine.terminals.rename(&id, &name) {
                Ok(t) => Response::json(200, t.describe()),
                Err((status, why)) => Response::error(status, &why),
            }
        }
        ("DELETE", ["api", "terminals", id]) => {
            let Some(t) = uuid_of(id).and_then(|id| engine.terminals.get(&id)) else {
                return Response::error(404, "no such terminal");
            };
            t.close("Closed.").await;
            Response::json(200, t.describe())
        }
        ("GET", ["api", "terminals", id, "blocks"]) => match uuid_of(id).and_then(|id| engine.terminals.get(&id)) {
            Some(_) => {
                let _ = query;
                Response::json(200, json!({"blocks": [], "more": false}))
            }
            None => Response::error(404, "no such terminal"),
        },
        ("GET", ["api", "terminals", _, "blocks", _, "output"]) => Response::error(404, "no such block"),
        ("GET", ["api", "terminals", id, "history"]) => match uuid_of(id).and_then(|id| engine.terminals.get(&id)) {
            Some(_) => Response::json(200, json!({"commands": []})),
            None => Response::error(404, "no such terminal"),
        },
        ("POST", ["api", "terminals", _, "complete" | "dirs" | "branches"]) => Response::error(409, NOT_OPEN),

        // ------------------------------------------------------ projects
        ("POST", ["api", "projects"]) => Response::error(403, LATER_ACCOUNT),
        ("PATCH", ["api", "projects", id]) => edit_project(engine, id, body),
        ("DELETE", ["api", "projects", _]) => Response::error(403, "Personal is yours alone and stays."),

        // --------------------------------------------------------- notes
        ("POST", ["api", "folders"]) | ("POST", ["api", "notes"]) => Response::error(403, LATER_NOTES),
        (_, ["api", "folders", ..]) | (_, ["api", "notes", ..]) => Response::error(404, "The note is not there any more."),

        _ => Response::error(404, "Not found."),
    }
}

fn patch_me(engine: &Arc<Engine>, body: &[u8]) -> Response {
    let Some(change) = body_json(body) else { return Response::error(422, "That is not JSON.") };
    let name = match change.get("name") {
        None | Some(Value::Null) => None,
        Some(Value::String(n)) => {
            let n = names::one_line(n);
            if n.is_empty() || n.chars().count() > 100 {
                return Response::error(422, "Enter your name: up to 100 characters.");
            }
            Some(n)
        }
        Some(_) => return Response::error(422, "Enter your name: up to 100 characters."),
    };
    let theme = change.get("theme").and_then(Value::as_str).map(str::to_string);
    if let Some(t) = &theme {
        if !settings::THEMES.contains(&t.as_str()) {
            return Response::error(422, "theme must be one of system, light, dark");
        }
    }
    let tint = change.get("projectTint").and_then(Value::as_str).map(str::to_string);
    if let Some(t) = &tint {
        if !settings::TINTS.contains(&t.as_str()) {
            return Response::error(422, "The tint is one of badge, block.");
        }
    }
    let saved = engine.save_settings(|s| {
        if let Some(t) = theme {
            s.theme = t;
        }
        if let Some(t) = tint {
            s.project_tint = t;
        }
        if let Some(n) = name.clone() {
            s.name = Some(n);
        }
    });
    if saved.is_err() {
        return Response::error(500, "Could not save the settings on this computer.");
    }
    match name {
        None => Response::empty(204),
        Some(n) => Response::json(200, json!({"name": n, "firstName": names::first_name(&n), "initials": names::initials(&n)})),
    }
}

fn edit_project(engine: &Arc<Engine>, id: &str, body: &[u8]) -> Response {
    let project_id = engine.settings.lock().unwrap().project_id;
    if uuid_of(id) != Some(project_id) {
        return Response::error(404, "No such project.");
    }
    let Some(change) = body_json(body) else { return Response::error(422, "That is not JSON.") };
    let name = match change.get("name").and_then(Value::as_str) {
        Some(n) => {
            let n = names::one_line(n);
            if n.is_empty() || n.chars().count() > 60 {
                return Response::error(422, "Name the project: up to 60 characters.");
            }
            Some(n)
        }
        None => None,
    };
    let code = match change.get("code").and_then(Value::as_str) {
        Some(c) => {
            let c = c.trim().to_uppercase();
            if !names::valid_code(&c) {
                return Response::error(422, "The code is one to four letters or digits.");
            }
            Some(c)
        }
        None => None,
    };
    let color = match change.get("color").and_then(Value::as_str) {
        Some(c) if settings::COLORS.contains(&c) => Some(c.to_string()),
        Some(_) => return Response::error(422, "No such color."),
        None => None,
    };
    let recode = code.clone();
    let saved = engine.save_settings(|s| {
        if let Some(n) = name {
            s.project_name = n;
        }
        if let Some(c) = code {
            s.project_code = c;
        }
        if let Some(c) = color {
            s.project_color = c;
        }
    });
    match saved {
        Ok(s) => {
            if let Some(c) = recode {
                engine.terminals.retag(None, Some(&c));
            }
            Response::json(200, json!({"id": s.project_id.to_string(), "name": s.project_name, "code": s.project_code, "color": s.project_color}))
        }
        Err(_) => Response::error(500, "Could not save the settings on this computer."),
    }
}

async fn open_terminal(engine: &Arc<Engine>, body: &[u8]) -> Response {
    let Some(request) = body_json(body) else { return Response::error(422, "That is not JSON.") };
    let machine = request.get("machineId").and_then(Value::as_str).and_then(uuid_of);
    if machine != Some(engine.settings.lock().unwrap().machine_id) {
        return Response::error(404, "No such machine.");
    }
    let cols = request.get("cols").and_then(Value::as_i64).unwrap_or(80);
    let rows = request.get("rows").and_then(Value::as_i64).unwrap_or(24);
    let plan = engine.plan();
    let env = crate::pty::clean_env(true);
    let home = crate::pty::home_dir();
    match engine.terminals.open(engine.place(), plan, env, home, cols, rows, crate::MOST_TERMINALS).await {
        Ok(t) => Response::json(201, t.describe()),
        Err(why) => Response::error(404, &why),
    }
}
