//! tTerm on a computer: the page of tTerm Web in a window of its own, with
//! the shells of this computer behind it.
//!
//! The window loads the page from the app itself, never from a server. A
//! small script (shim.js) sends the page's requests and its socket to the
//! commands below, and they go to the engine (the tterm-engine crate), which
//! answers for this computer the way tTerm Web's core answers for a machine.
//! Signed in (from 0.3.0), the engine takes the rest to tTerm Web: the app
//! keeps the key of its device in the keychain (keychain.rs). From 0.4.0 it
//! opens this computer to tTerm Web too, in the agent's place, and while it
//! does it stays in the menu bar with its window closed (background.rs).
//! From 0.5.0 it updates itself (updates.rs, and the engine's update.rs).
//! From 0.6.0 its menus and questions are in the language the page shows
//! (the engine's say.rs), and change with it.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod background;
mod keychain;
#[cfg(target_os = "macos")]
mod mac;
// The vault's keeper for the GUI checks (TTERM_TEST_KEEPER=1): never in a
// release build.
#[cfg(debug_assertions)]
mod test_keeper;
mod updates;

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
use tterm_engine::say::{say, Said};
use tterm_engine::socket::PageSocket;
use tterm_engine::terminals::Outgoing;
use tterm_engine::{api, upstream, Engine};

const SHIM: &str = include_str!("shim.js");

/// The vault's keeper: the keychain and LocalAuthentication (keychain.rs);
/// in a debug build with TTERM_TEST_KEEPER=1, the checks' in-memory one.
fn vault_keeper(host: Arc<keychain::AppHost>) -> Arc<dyn tterm_engine::vault::Keeper> {
    #[cfg(debug_assertions)]
    if test_keeper::wanted() {
        return Arc::new(test_keeper::TestKeeper::new());
    }
    host
}

/// The shim, after the language the app shows: the page's first paint is
/// in it before the page has asked anything (from 0.6.0).
fn shim(lang: &str) -> String {
    format!("window.__ttermLanguage = {};\n{SHIM}", serde_json::to_string(lang).unwrap_or_else(|_| "\"en\"".into()))
}
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
    let flags = api::Flags {
        background: header(&request, "x-tterm-background").as_deref() == Some("1"),
        body_type: api::body_type(header(&request, "x-tterm-type").as_deref()),
    };
    let answer = api::handle_with(&app.engine, &method, &path, &raw_body(&request), flags).await;
    let mut out = Vec::with_capacity(3 + answer.content_type.len() + answer.body.len());
    out.extend_from_slice(&answer.status.to_be_bytes());
    out.push(answer.content_type.len() as u8);
    out.extend_from_slice(answer.content_type.as_bytes());
    out.extend_from_slice(&answer.body);
    Ok(Response::new(out))
}

/// A socket of the page. Async (from 0.7.0), so it opens on the runtime:
/// signed in, its socket on tTerm starts with it, for the vault.
#[tauri::command]
async fn ws_open(app: State<'_, App>) -> Result<u64, String> {
    let (page, rx) = PageSocket::new(app.engine.clone());
    let id = app.next_socket.fetch_add(1, Ordering::SeqCst);
    let socket = Arc::new(Socket { page, rx: AsyncMutex::new(rx), asked: Mutex::new(Instant::now()) });
    app.sockets.lock().unwrap().insert(id, socket);
    Ok(id)
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

/// What ends if tTerm quits now, in the language shown; None when nothing
/// would.
fn question(engine: &Engine) -> Option<String> {
    let lang = engine.language_now();
    let open = engine.terminals.live().len() as u64;
    // Opened from tTerm Web on this computer, through the app (from 0.4.0).
    let web = engine.reach.terminals() as u64;
    if open == 0 && web == 0 {
        return None;
    }
    let mut said = Vec::new();
    if open > 0 {
        let busy = engine.terminals.busy();
        if busy.is_empty() {
            said.push(Said::new("quit.shells_end").count(open).said_in(lang));
        } else {
            // Listed and put together as the language does ("a, b", "a、b").
            let running = busy
                .iter()
                .map(|(label, name)| Said::new("quit.running_item").with("name", name.clone()).with("label", label.clone()).said_in(lang))
                .reduce(|a, b| Said::new("quit.list").with("a", a).with("b", b).said_in(lang))
                .unwrap_or_default();
            said.push(Said::new("quit.running").count(open).with("running", running).said_in(lang));
        }
    }
    if web > 0 {
        said.push(Said::new("quit.web_end").count(web).said_in(lang));
    }
    said.into_iter().reduce(|a, b| Said::new("quit.both").with("first", a).with("second", b).said_in(lang))
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
    // The question in front, with its window: also when the app was in the
    // menu bar only (a quit from there, a logout).
    background::show_window(handle);
    let handle2 = handle.clone();
    let lang = app.engine.language_now();
    handle
        .dialog()
        .message(text)
        .title(say(lang, "quit.title"))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(say(lang, "quit.yes"), say(lang, "quit.cancel")))
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
        // with the app, its terminals ended and kept (2.5 s at most). At the
        // same time tTerm Web hears that this computer's terminals there
        // end, and they do (6 s at most, after a change of the link that
        // was under way).
        tokio::join!(engine.terminals.stop_all("tTerm quit."), engine.reach.stop());
        handle.exit(0);
    });
}

// -------------------------------------------------------------------- menu

/// The menu of the Mac: the usual items, with Copy and Paste (the page needs
/// them for its keys), and the tab's Cmd+T and Cmd+W. Built everywhere, so
/// that every build checks it; set on the Mac only, where apps have one.
/// In the language shown (from 0.6.0), and made again in another
/// (follow_language). Enter Full Screen is macOS's own, in its words.
fn menu(handle: &AppHandle, lang: &str) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{AboutMetadata, Menu, MenuItem, PredefinedMenuItem, Submenu};
    let t = |key: &'static str| say(lang, key);
    let about = PredefinedMenuItem::about(
        handle,
        Some(&t("menu.about")),
        Some(AboutMetadata {
            name: Some("tTerm".into()),
            version: Some(env!("CARGO_PKG_VERSION").into()),
            copyright: Some("© 2026 tTerm. AGPL-3.0.".into()),
            website: Some("https://tterm.net".into()),
            website_label: Some("tterm.net".into()),
            ..Default::default()
        }),
    )?;
    // Check for Updates…, or Restart to Update once a version is ready
    // (updates.rs).
    let update = MenuItem::with_id(handle, "update", updates::menu_text(handle, lang), true, None::<&str>)?;
    *handle.state::<updates::MenuLine>().0.lock().unwrap() = Some(update.clone());
    let app_menu = Submenu::with_items(
        handle,
        "tTerm",
        true,
        &[
            &about,
            &update,
            &PredefinedMenuItem::separator(handle)?,
            &PredefinedMenuItem::services(handle, Some(&t("menu.services")))?,
            &PredefinedMenuItem::separator(handle)?,
            &PredefinedMenuItem::hide(handle, Some(&t("menu.hide")))?,
            &PredefinedMenuItem::hide_others(handle, Some(&t("menu.hide_others")))?,
            &PredefinedMenuItem::show_all(handle, Some(&t("menu.show_all")))?,
            &PredefinedMenuItem::separator(handle)?,
            &MenuItem::with_id(handle, "quit", t("menu.quit"), true, Some("CmdOrCtrl+Q"))?,
        ],
    )?;
    let edit = Submenu::with_items(
        handle,
        t("menu.edit"),
        true,
        &[
            &PredefinedMenuItem::undo(handle, Some(&t("menu.undo")))?,
            &PredefinedMenuItem::redo(handle, Some(&t("menu.redo")))?,
            &PredefinedMenuItem::separator(handle)?,
            &PredefinedMenuItem::cut(handle, Some(&t("menu.cut")))?,
            &PredefinedMenuItem::copy(handle, Some(&t("menu.copy")))?,
            &PredefinedMenuItem::paste(handle, Some(&t("menu.paste")))?,
            &PredefinedMenuItem::select_all(handle, Some(&t("menu.select_all")))?,
        ],
    )?;
    let view = Submenu::with_items(
        handle,
        t("menu.view"),
        true,
        &[
            &MenuItem::with_id(handle, "reload", t("menu.reload"), true, Some("CmdOrCtrl+R"))?,
            &PredefinedMenuItem::separator(handle)?,
            &PredefinedMenuItem::fullscreen(handle, None)?,
        ],
    )?;
    let window = Submenu::with_items(
        handle,
        t("menu.window"),
        true,
        &[
            &MenuItem::with_id(handle, "new-terminal", t("menu.new_terminal"), true, Some("CmdOrCtrl+T"))?,
            &MenuItem::with_id(handle, "close-tab", t("menu.close_tab"), true, Some("CmdOrCtrl+W"))?,
            &PredefinedMenuItem::separator(handle)?,
            &PredefinedMenuItem::minimize(handle, Some(&t("menu.minimize")))?,
            &PredefinedMenuItem::maximize(handle, Some(&t("menu.zoom")))?,
        ],
    )?;
    Menu::with_items(handle, &[&app_menu, &edit, &view, &window])
}

/// Another language chosen (on the page, or in the account): tTerm's menu
/// and the icon's in it, at once.
fn follow_language(handle: &AppHandle, engine: &Engine) {
    let mut language = engine.language.subscribe();
    let h = handle.clone();
    tauri::async_runtime::spawn(async move {
        while language.changed().await.is_ok() {
            let lang = *language.borrow_and_update();
            let on = h.clone();
            let _ = h.run_on_main_thread(move || {
                if cfg!(target_os = "macos") {
                    match menu(&on, lang) {
                        Ok(m) => {
                            if let Err(e) = on.set_menu(m) {
                                eprintln!("tterm: tTerm's menu in another language: {e}");
                            }
                        }
                        Err(e) => eprintln!("tterm: tTerm's menu in another language: {e}"),
                    }
                }
                background::relabel(&on);
            });
        }
    });
}

fn on_menu(handle: &AppHandle, id: &str) {
    let window = handle.get_webview_window("main");
    match id {
        "quit" => ask_to_quit(handle),
        "update" => updates::menu_item(handle),
        // The icon in the menu bar (background.rs).
        "bar-open" => background::show_window(handle),
        "bar-update" => updates::restart(handle),
        "bar-quit" => ask_to_quit(handle),
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

/// tTerm Web: app.tterm.net. A debug build, for the checks, takes another
/// on this very computer from TTERM_CLOUD.
fn cloud_address() -> String {
    if cfg!(debug_assertions) {
        if let Ok(other) = std::env::var("TTERM_CLOUD") {
            if other.starts_with("https://") || other.starts_with("http://127.0.0.1:") || other.starts_with("http://localhost:") {
                return other.trim_end_matches('/').to_string();
            }
        }
    }
    upstream::CLOUD.to_string()
}

/// The agent's settings, with this computer's own key: `~/.tterm-web/env`.
/// A debug build takes another file from TTERM_WEB_ENV, for the checks.
fn agent_env() -> std::path::PathBuf {
    if cfg!(debug_assertions) {
        if let Some(other) = std::env::var_os("TTERM_WEB_ENV") {
            return other.into();
        }
    }
    tterm_engine::pty::home_dir().join(".tterm-web").join("env")
}

fn main() {
    // Asked by the version before, before it puts this one in place, and
    // the watcher it runs as itself (the engine's update.rs): no window.
    let args: Vec<String> = std::env::args().collect();
    if let Some(version) = tterm_engine::update::version_main(&args) {
        println!("{version}");
        return;
    }
    if let Some(code) = tterm_engine::update::watcher_main(&args) {
        std::process::exit(code);
    }
    // The version before, opened from beside the app where an update put
    // it for a moment (a bookmark of the Dock follows it): the app in its
    // place opens instead.
    #[cfg(target_os = "macos")]
    if let Some(app) = std::env::current_exe().ok().and_then(|exe| tterm_engine::update::moved_aside(&exe)) {
        let _ = tterm_engine::update::launch(&app, background::started_at_login(), false);
        return;
    }
    // A new version on trial says so before anything that could end this
    // start, and the version before watches it (the engine's update.rs). In
    // the place of data Tauri gives the app (app_data_dir), found the way
    // Tauri finds it.
    if let Some(data) = dirs::data_dir() {
        let _ = tterm_engine::update::claim(&tterm_engine::update::Config::app(&data.join(tterm_engine::update::BUNDLE_ID)));
    }
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![api, ws_open, ws_send, ws_recv, ws_close, open_external])
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            let cloud = cloud_address();
            let host = Arc::new(keychain::AppHost::new(app.handle().clone(), &cloud, dir.clone()));
            // The same AppHost is the vault's keeper (the keychain and
            // LocalAuthentication, from 0.7.0) and the account's host.
            let engine = Engine::with_cloud(&dir, &cloud, host.clone(), vault_keeper(host), &agent_env())?;
            let shared: App = Arc::new(Shared {
                engine: engine.clone(),
                sockets: Mutex::new(HashMap::new()),
                next_socket: AtomicU64::new(1),
                quitting: AtomicBool::new(false),
                asking: AtomicBool::new(false),
            });
            app.manage(shared.clone());
            app.manage(background::Bar::default());
            app.manage(updates::MenuLine::default());
            // On a Mac the app keeps this computer's link with its window
            // closed, and so takes the agent's place (the engine's reach.rs).
            engine.reach.set_background(background::supported());
            background::follow(app.handle(), engine.clone());
            updates::follow(app.handle(), engine.clone());
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

            let m = menu(app.handle(), shared.engine.language_now())?;
            if cfg!(target_os = "macos") {
                app.set_menu(m)?;
            }
            follow_language(app.handle(), &shared.engine);
            #[cfg(target_os = "macos")]
            mac::install(app.handle());
            app.on_menu_event(|handle, event| on_menu(handle, event.id().as_ref()));

            let handle = app.handle().clone();
            let on_load = shared.clone();
            // Started at login (background.rs): in the menu bar, no window
            // until asked for.
            let hidden = background::supported() && background::started_at_login();
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("tTerm")
                .visible(!hidden)
                .inner_size(1280.0, 820.0)
                .min_inner_size(640.0, 420.0)
                .background_color(tauri::window::Color(19, 20, 23, 255))
                .initialization_script(shim(shared.engine.language_now()))
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
            if hidden {
                background::hide_window(app.handle());
            }
            // What went wrong with the app's file at start (a damaged file
            // kept aside, or one it could not open): said once, plainly, so
            // that notes missing, or not taken, are not a mystery.
            if let Some(text) = shared.engine.terminals.store.trouble.clone() {
                app.dialog().message(text).title("tTerm").kind(MessageDialogKind::Warning).show(|_| {});
            }
            // A new version on trial: up, and the version before, watching,
            // goes.
            shared.engine.updates.up();
            Ok(())
        });

    let app = builder.build(tauri::generate_context!()).expect("tTerm could not start");
    app.run(|handle, event| match event {
        RunEvent::WindowEvent { event: WindowEvent::CloseRequested { api, .. }, .. } => {
            let shared = handle.state::<App>();
            if !shared.quitting.load(Ordering::SeqCst) {
                api.prevent_close();
                // Opened from tTerm Web: the app stays, in the menu bar.
                if background::on(handle) {
                    background::hide_window(handle);
                } else {
                    ask_to_quit(handle);
                }
            }
        }
        // The app opened again (the Dock, Finder) with its window closed.
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => background::show_window(handle),
        RunEvent::ExitRequested { api, .. } => {
            let shared = handle.state::<App>();
            if !shared.quitting.load(Ordering::SeqCst) {
                api.prevent_exit();
                ask_to_quit(handle);
            }
        }
        // Quitting, whichever way: Update by itself puts the version ready
        // in place.
        RunEvent::Exit => updates::at_exit(&handle.state::<App>().engine),
        _ => {}
    });
}
