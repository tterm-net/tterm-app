//! tTerm on a computer: the page of tTerm Web in a window of its own, with
//! the shells of this computer behind it.
//!
//! The window loads the page from the app itself, never from a server. A
//! small script (shim.js) sends the page's requests and its socket to the
//! commands below, and they go to the engine (the tterm-engine crate), which
//! answers for this computer the way tTerm Web's core answers for a machine.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(target_os = "macos")]
mod mac;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::ipc::{InvokeBody, Request, Response};
use tauri::webview::PageLoadEvent;
use tauri::{AppHandle, Manager, RunEvent, State, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_opener::OpenerExt;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tterm_engine::socket::PageSocket;
use tterm_engine::terminals::Outgoing;
use tterm_engine::{api, Engine};

const SHIM: &str = include_str!("shim.js");
/// What one answer to the page's socket carries at most.
const BATCH_MAX: usize = 1024 * 1024;
/// How long the page's socket waits for something to come, at most, before
/// it asks again: also how it shows it is still there.
const POLL_WAIT: Duration = Duration::from_secs(25);
/// A socket nobody asked for this long belongs to a page that is gone.
const STALE: Duration = Duration::from_secs(60);

struct Socket {
    page: Arc<PageSocket>,
    rx: AsyncMutex<mpsc::Receiver<Outgoing>>,
    asked: Mutex<Instant>,
}

struct Shared {
    engine: Arc<Engine>,
    sockets: Mutex<HashMap<u64, Arc<Socket>>>,
    next_socket: AtomicU64,
    /// The person said yes to quitting: the next exit goes through.
    quitting: AtomicBool,
    /// The question is on screen: no second one on top of it.
    asking: AtomicBool,
}

type App = Arc<Shared>;

fn header(request: &Request<'_>, name: &str) -> Option<String> {
    request.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

/// The bytes the shim sent. Normally they come as they are; after one IPC
/// request fails, Tauri sends everything by postMessage for good, and there
/// bytes arrive as a JSON array of numbers.
fn raw_body(request: &Request<'_>) -> Vec<u8> {
    match request.body() {
        InvokeBody::Raw(bytes) => bytes.clone(),
        InvokeBody::Json(value) if value.is_null() => Vec::new(),
        InvokeBody::Json(value) => match serde_json::from_value::<Vec<u8>>(value.clone()) {
            Ok(bytes) => bytes,
            Err(_) => value.to_string().into_bytes(),
        },
    }
}

/// One request of the page, answered by the engine: two bytes of status,
/// one of the type's length, the type, the body.
#[tauri::command]
async fn api(request: Request<'_>, app: State<'_, App>) -> Result<Response, String> {
    let method = header(&request, "x-tterm-method").unwrap_or_else(|| "GET".into());
    let path = header(&request, "x-tterm-path").ok_or("no path")?;
    if !(path.starts_with("/api/") || path == "/health") {
        return Err("not a request of the page".into());
    }
    let answer = api::handle(&app.engine, &method, &path, &raw_body(&request)).await;
    let mut out = Vec::with_capacity(3 + answer.content_type.len() + answer.body.len());
    out.extend_from_slice(&answer.status.to_be_bytes());
    out.push(answer.content_type.len() as u8);
    out.extend_from_slice(answer.content_type.as_bytes());
    out.extend_from_slice(&answer.body);
    Ok(Response::new(out))
}

#[tauri::command]
fn ws_open(app: State<'_, App>) -> u64 {
    let (page, rx) = PageSocket::new(app.engine.clone());
    let id = app.next_socket.fetch_add(1, Ordering::SeqCst);
    let socket = Arc::new(Socket { page, rx: AsyncMutex::new(rx), asked: Mutex::new(Instant::now()) });
    app.sockets.lock().unwrap().insert(id, socket);
    id
}

fn socket(app: &App, id: u64) -> Option<Arc<Socket>> {
    app.sockets.lock().unwrap().get(&id).cloned()
}

/// What the page sent, in order: [type u8][length u32][payload], 0 text,
/// 1 binary.
#[tauri::command]
async fn ws_send(request: Request<'_>, app: State<'_, App>) -> Result<(), String> {
    let id: u64 = header(&request, "x-tterm-socket").and_then(|v| v.parse().ok()).ok_or("no socket")?;
    let Some(s) = socket(&app, id) else { return Err("no such socket".into()) };
    let body = raw_body(&request);
    let mut at = 0;
    while at + 5 <= body.len() {
        let kind = body[at];
        let len = u32::from_be_bytes([body[at + 1], body[at + 2], body[at + 3], body[at + 4]]) as usize;
        let end = (at + 5).saturating_add(len).min(body.len());
        let payload = &body[at + 5..end];
        if kind == 0 {
            s.page.text(&String::from_utf8_lossy(payload)).await;
        } else {
            s.page.binary(payload).await;
        }
        at = end;
    }
    Ok(())
}

/// What the engine has for the page, waiting for it if there is nothing
/// yet: a byte of flags (1: the socket is closed), then the messages.
#[tauri::command]
async fn ws_recv(id: u64, app: State<'_, App>) -> Result<Response, String> {
    let Some(s) = socket(&app, id) else { return Ok(Response::new(vec![1])) };
    *s.asked.lock().unwrap() = Instant::now();
    let mut rx = s.rx.lock().await;
    let mut out = vec![0u8];
    let put = |m: Outgoing, out: &mut Vec<u8>| {
        let (kind, payload) = match m {
            Outgoing::Text(t) => (0u8, t.into_bytes()),
            Outgoing::Binary(b) => (1u8, b),
        };
        out.push(kind);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
    };
    match tokio::time::timeout(POLL_WAIT, rx.recv()).await {
        Ok(Some(m)) => put(m, &mut out),
        Ok(None) => return Ok(Response::new(vec![1])),
        Err(_) => return Ok(Response::new(out)),
    }
    while out.len() < BATCH_MAX {
        match rx.try_recv() {
            Ok(m) => put(m, &mut out),
            Err(_) => break,
        }
    }
    *s.asked.lock().unwrap() = Instant::now();
    Ok(Response::new(out))
}

#[tauri::command]
async fn ws_close(id: u64, app: State<'_, App>) -> Result<(), String> {
    let gone = app.sockets.lock().unwrap().remove(&id);
    if let Some(s) = gone {
        s.page.close().await;
    }
    Ok(())
}

/// A link out of the page: in the browser, or the mail app.
#[tauri::command]
fn open_external(url: String, handle: AppHandle) -> Result<(), String> {
    let ok = url.starts_with("https://") || url.starts_with("http://") || url.starts_with("mailto:");
    if !ok {
        return Err("not a link to open".into());
    }
    handle.opener().open_url(url, None::<&str>).map_err(|e| e.to_string())
}

/// The page went (a reload, or it navigated): its sockets go with it.
fn close_sockets(app: &App) {
    let all: Vec<Arc<Socket>> = app.sockets.lock().unwrap().drain().map(|(_, s)| s).collect();
    tauri::async_runtime::spawn(async move {
        for s in all {
            s.page.close().await;
        }
    });
}

fn sweep_sockets(app: &App) {
    let stale: Vec<Arc<Socket>> = {
        let mut sockets = app.sockets.lock().unwrap();
        let ids: Vec<u64> = sockets
            .iter()
            .filter(|(_, s)| s.asked.lock().unwrap().elapsed() > STALE && s.rx.try_lock().is_ok())
            .map(|(id, _)| *id)
            .collect();
        ids.into_iter().filter_map(|id| sockets.remove(&id)).collect()
    };
    tauri::async_runtime::spawn(async move {
        for s in stale {
            s.page.close().await;
        }
    });
}

// ---------------------------------------------------------------- quitting

fn question(engine: &Engine) -> Option<String> {
    let open = engine.terminals.live().len();
    if open == 0 {
        return None;
    }
    let shells = if open == 1 { "The shell of 1 terminal".to_string() } else { format!("The shells of {open} terminals") };
    let busy = engine.terminals.busy();
    if busy.is_empty() {
        return Some(format!("{shells} will end."));
    }
    let running: Vec<String> = busy.iter().map(|(label, name)| format!("{name} in {label}")).collect();
    Some(format!("Running now: {}. It will stop, and {} will end.", running.join(", "), shells.to_lowercase()))
}

/// For a quit from outside the app (see mac.rs): true when it may go at
/// once, nothing being open or the person having said yes; otherwise the
/// question goes on screen, and the app quits if they say so.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn may_quit_now(handle: &AppHandle) -> bool {
    let app: App = handle.state::<App>().inner().clone();
    if app.quitting.load(Ordering::SeqCst) {
        return true;
    }
    if question(&app.engine).is_none() {
        app.quitting.store(true, Ordering::SeqCst);
        return true;
    }
    ask_to_quit(handle);
    false
}

/// Quits, after asking when shells would end: as Terminal on a Mac asks.
fn ask_to_quit(handle: &AppHandle) {
    let app: App = handle.state::<App>().inner().clone();
    if app.asking.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(text) = question(&app.engine) else {
        quit(handle.clone(), app);
        return;
    };
    let handle2 = handle.clone();
    handle
        .dialog()
        .message(text)
        .title("Quit tTerm?")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom("Quit".into(), "Cancel".into()))
        .show(move |yes| {
            if yes {
                quit(handle2, app);
            } else {
                app.asking.store(false, Ordering::SeqCst);
            }
        });
}

fn quit(handle: AppHandle, app: App) {
    app.quitting.store(true, Ordering::SeqCst);
    tauri::async_runtime::spawn(async move {
        let engine = app.engine.clone();
        // Hangups for all, and a moment for them; whatever is left goes
        // with the app, its terminals ended and kept (2.5 s at most).
        engine.terminals.stop_all("tTerm quit.").await;
        handle.exit(0);
    });
}

// -------------------------------------------------------------------- menu

/// The menu of the Mac: the usual items, with Copy and Paste (the page needs
/// them for its keys), and the tab's Cmd+T and Cmd+W. Built everywhere, so
/// that every build checks it; set on the Mac only, where apps have one.
fn menu(handle: &AppHandle) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{AboutMetadata, Menu, MenuItem, PredefinedMenuItem, Submenu};
    let about = PredefinedMenuItem::about(
        handle,
        Some("About tTerm"),
        Some(AboutMetadata {
            name: Some("tTerm".into()),
            version: Some(env!("CARGO_PKG_VERSION").into()),
            copyright: Some("© 2026 tTerm. AGPL-3.0.".into()),
            website: Some("https://tterm.net".into()),
            website_label: Some("tterm.net".into()),
            ..Default::default()
        }),
    )?;
    let app_menu = Submenu::with_items(
        handle,
        "tTerm",
        true,
        &[
            &about,
            &PredefinedMenuItem::separator(handle)?,
            &PredefinedMenuItem::services(handle, None)?,
            &PredefinedMenuItem::separator(handle)?,
            &PredefinedMenuItem::hide(handle, None)?,
            &PredefinedMenuItem::hide_others(handle, None)?,
            &PredefinedMenuItem::show_all(handle, None)?,
            &PredefinedMenuItem::separator(handle)?,
            &MenuItem::with_id(handle, "quit", "Quit tTerm", true, Some("CmdOrCtrl+Q"))?,
        ],
    )?;
    let edit = Submenu::with_items(
        handle,
        "Edit",
        true,
        &[
            &PredefinedMenuItem::undo(handle, None)?,
            &PredefinedMenuItem::redo(handle, None)?,
            &PredefinedMenuItem::separator(handle)?,
            &PredefinedMenuItem::cut(handle, None)?,
            &PredefinedMenuItem::copy(handle, None)?,
            &PredefinedMenuItem::paste(handle, None)?,
            &PredefinedMenuItem::select_all(handle, None)?,
        ],
    )?;
    let view = Submenu::with_items(
        handle,
        "View",
        true,
        &[
            &MenuItem::with_id(handle, "reload", "Reload", true, Some("CmdOrCtrl+R"))?,
            &PredefinedMenuItem::separator(handle)?,
            &PredefinedMenuItem::fullscreen(handle, None)?,
        ],
    )?;
    let window = Submenu::with_items(
        handle,
        "Window",
        true,
        &[
            &MenuItem::with_id(handle, "new-terminal", "New Terminal", true, Some("CmdOrCtrl+T"))?,
            &MenuItem::with_id(handle, "close-tab", "Close Tab", true, Some("CmdOrCtrl+W"))?,
            &PredefinedMenuItem::separator(handle)?,
            &PredefinedMenuItem::minimize(handle, None)?,
            &PredefinedMenuItem::maximize(handle, None)?,
        ],
    )?;
    Menu::with_items(handle, &[&app_menu, &edit, &view, &window])
}

fn on_menu(handle: &AppHandle, id: &str) {
    let window = handle.get_webview_window("main");
    match id {
        "quit" => ask_to_quit(handle),
        "reload" => {
            // The page again; and the app's page, should the window ever
            // be elsewhere.
            if let Some(w) = window {
                match w.url() {
                    Ok(url) if ours(&url) => {
                        let _ = w.eval("location.reload()");
                    }
                    _ => {
                        if let Ok(home) = HOME.parse() {
                            let _ = w.navigate(home);
                        }
                    }
                }
            }
        }
        "new-terminal" | "close-tab" => {
            if let Some(w) = window {
                let _ = w.eval(&format!("window.__ttermApp && window.__ttermApp.action('{id}')"));
            }
        }
        _ => {}
    }
}

// -------------------------------------------------------------------- main

/// Where the app's page is: Tauri's own scheme, which Windows spells as an
/// address of its own.
const HOME: &str = if cfg!(windows) { "http://tauri.localhost/" } else { "tauri://localhost/" };

/// Only the app's own page: anything else opens in the browser instead.
fn ours(url: &tauri::Url) -> bool {
    if cfg!(windows) {
        matches!(url.scheme(), "http" | "https") && url.host_str() == Some("tauri.localhost")
    } else {
        url.scheme() == "tauri" && url.host_str() == Some("localhost")
    }
}

fn main() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![api, ws_open, ws_send, ws_recv, ws_close, open_external])
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            let engine = Engine::new(&dir)?;
            let shared: App = Arc::new(Shared {
                engine: engine.clone(),
                sockets: Mutex::new(HashMap::new()),
                next_socket: AtomicU64::new(1),
                quitting: AtomicBool::new(false),
                asking: AtomicBool::new(false),
            });
            app.manage(shared.clone());
            tauri::async_runtime::spawn(async move {
                engine.start_background();
            });
            {
                let shared = shared.clone();
                tauri::async_runtime::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(20)).await;
                        sweep_sockets(&shared);
                    }
                });
            }

            let m = menu(app.handle())?;
            if cfg!(target_os = "macos") {
                app.set_menu(m)?;
            }
            #[cfg(target_os = "macos")]
            mac::install(app.handle());
            app.on_menu_event(|handle, event| on_menu(handle, event.id().as_ref()));

            let handle = app.handle().clone();
            let on_load = shared.clone();
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("tTerm")
                .inner_size(1280.0, 820.0)
                .min_inner_size(640.0, 420.0)
                .background_color(tauri::window::Color(19, 20, 23, 255))
                .initialization_script(SHIM)
                .on_navigation(move |url| {
                    if ours(url) {
                        return true;
                    }
                    let link = url.as_str();
                    if link.starts_with("https://") || link.starts_with("http://") || link.starts_with("mailto:") {
                        let _ = handle.opener().open_url(link, None::<&str>);
                    }
                    false
                })
                .on_page_load(move |_, payload| {
                    if payload.event() == PageLoadEvent::Started {
                        close_sockets(&on_load);
                    }
                })
                .build()?;
            // What went wrong with the app's file at start (a damaged file
            // kept aside, or one it could not open): said once, plainly, so
            // that notes missing, or not taken, are not a mystery.
            if let Some(text) = shared.engine.terminals.store.trouble.clone() {
                app.dialog().message(text).title("tTerm").kind(MessageDialogKind::Warning).show(|_| {});
            }
            Ok(())
        });

    let app = builder.build(tauri::generate_context!()).expect("tTerm could not start");
    app.run(|handle, event| match event {
        RunEvent::WindowEvent { event: WindowEvent::CloseRequested { api, .. }, .. } => {
            let shared = handle.state::<App>();
            if !shared.quitting.load(Ordering::SeqCst) {
                api.prevent_close();
                ask_to_quit(handle);
            }
        }
        RunEvent::ExitRequested { api, .. } => {
            let shared = handle.state::<App>();
            if !shared.quitting.load(Ordering::SeqCst) {
                api.prevent_exit();
                ask_to_quit(handle);
            }
        }
        _ => {}
    });
}
