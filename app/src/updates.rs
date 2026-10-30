//! tTerm updating itself, the app's part (from 0.5.0). The engine looks for
//! a new version, downloads it and checks it (the engine's update.rs); the
//! page shows it ready: Restart to update in its top bar, on a card above
//! the account, in Settings. Here it goes in, which is quitting: the version
//! ready goes in the app's place, the terminals end as at Quit, and the
//! version before, beside it, opens the new one and watches it start.
//!
//! Restart to update comes from the page, from the icon in the menu bar and
//! from tTerm's menu (Check for Updates… until a version is ready). When
//! terminals would end, it asks first, with the very question of Quit.
//!
//! "Update by itself" (Settings, the default) also puts the version ready in
//! place when tTerm quits, whichever way (main.rs, RunEvent::Exit), and,
//! with tTerm in the menu bar and its window closed, as soon as nothing runs
//! on this Mac: it starts again in the menu bar, and tTerm Web sees this Mac
//! go for a few seconds. That one is tried once a version: should it not go
//! in (App Management), Restart to update or the next Quit puts it in. "Ask
//! me first": only when the person says so.
//!
//! Started from the disk image, tTerm offers once to move itself to
//! Applications, where it can update itself.

use crate::{background, App};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::menu::MenuItem;
use tauri::{AppHandle, Manager, Wry};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tterm_engine::update::{Phase, Status, Wish};
use tterm_engine::Engine;

/// How often "by itself" looks whether nothing runs.
const BY_ITSELF_EVERY: Duration = Duration::from_secs(30);

/// tTerm's menu's item: Check for Updates…, or Restart to Update.
#[derive(Default)]
pub struct MenuLine(pub Mutex<Option<MenuItem<Wry>>>);

pub const CHECK: &str = "Check for Updates…";

fn restart_text(version: &str) -> String {
    format!("Restart to Update ({version})…")
}

fn ready_version(status: &Status) -> Option<String> {
    match &status.phase {
        Phase::Ready { version, .. } => Some(version.clone()),
        _ => None,
    }
}

/// Whether the person chose Update by itself.
pub fn by_itself(engine: &Engine) -> bool {
    engine.settings.lock().unwrap().updates == "auto"
}

/// The menus follow the updater, the app hears the page, and by itself the
/// version ready goes in while nothing runs.
pub fn follow(handle: &AppHandle, engine: Arc<Engine>) {
    let mut wishes = engine.updates.listen();
    let h = handle.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(wish) = wishes.recv().await {
            let on = h.clone();
            let _ = h.run_on_main_thread(move || match wish {
                Wish::Restart => restart(&on),
                Wish::Move => offer_move(&on, false),
            });
        }
    });

    let mut status = engine.updates.status();
    let h = handle.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let ready = ready_version(&status.borrow_and_update());
            let on = h.clone();
            let _ = h.run_on_main_thread(move || show(&on, ready));
            if status.changed().await.is_err() {
                return;
            }
        }
    });

    // A version that did not go in by itself is not tried by itself again
    // (App Management may keep it out until the person allows it): Restart
    // to update and Quit still put it in.
    let tried: Arc<Mutex<Option<String>>> = Arc::default();
    let h = handle.clone();
    let e = engine.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(BY_ITSELF_EVERY).await;
            let ready = e.updates.ready().map(|(v, _)| v);
            if ready.is_none() || *tried.lock().unwrap() == ready || !quiet_now(&h, &e) {
                continue;
            }
            let on = h.clone();
            let tried = tried.clone();
            let _ = h.run_on_main_thread(move || {
                // Looked at again where the window lives.
                let engine = on.state::<App>().engine.clone();
                if quiet_now(&on, &engine) && !go(&on, true) {
                    *tried.lock().unwrap() = engine.updates.ready().map(|(v, _)| v);
                }
            });
        }
    });

    // From the disk image: once, a moment after the window is up.
    if matches!(engine.updates.now().phase, Phase::Unavailable { movable: true, .. }) {
        let h = handle.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let on = h.clone();
            let _ = h.run_on_main_thread(move || offer_move(&on, true));
        });
    }
}

/// Update by itself, a version ready, tTerm in the menu bar with its window
/// closed, and nothing running on this Mac: it may go in now.
fn quiet_now(handle: &AppHandle, engine: &Engine) -> bool {
    let app = handle.state::<App>();
    by_itself(engine)
        && engine.updates.ready().is_some()
        && background::on(handle)
        && background::closed(handle)
        && crate::question(engine).is_none()
        && !app.asking.load(Ordering::SeqCst)
        && !app.quitting.load(Ordering::SeqCst)
}

/// tTerm's menu and the icon in the menu bar say whether a version is
/// ready.
fn show(handle: &AppHandle, ready: Option<String>) {
    if let Some(item) = handle.state::<MenuLine>().0.lock().unwrap().as_ref() {
        let _ = item.set_text(ready.as_deref().map(restart_text).unwrap_or_else(|| CHECK.to_string()));
    }
    background::set_update(handle, ready.map(|v| restart_text(&v)));
}

/// tTerm's menu: Restart to Update when a version is ready; otherwise a look
/// now, with Settings' Updates on screen to say what it finds.
pub fn menu_item(handle: &AppHandle) {
    let engine = handle.state::<App>().engine.clone();
    if engine.updates.ready().is_some() {
        restart(handle);
        return;
    }
    engine.updates.check_now();
    background::show_window(handle);
    if let Some(w) = handle.get_webview_window("main") {
        let _ = w.eval("window.__ttermApp && window.__ttermApp.action('updates')");
    }
}

/// Restart to update: asked first when terminals would end, as at Quit.
pub fn restart(handle: &AppHandle) {
    let app: App = handle.state::<App>().inner().clone();
    let Some((version, _)) = app.engine.updates.ready() else { return };
    if app.quitting.load(Ordering::SeqCst) || app.asking.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(text) = crate::question(&app.engine) else {
        go(handle, background::closed(handle));
        return;
    };
    background::show_window(handle);
    let h = handle.clone();
    handle
        .dialog()
        .message(format!("tTerm {version} is ready. {text}"))
        .title("Restart tTerm to update?")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom("Restart".into(), "Later".into()))
        .show(move |yes| {
            if yes {
                // The window was shown for the question: back as it was.
                go(&h, false);
            } else {
                h.state::<App>().asking.store(false, Ordering::SeqCst);
            }
        });
}

/// The version ready in place first, so that what goes wrong leaves all as
/// it was; then the quit, and the version before opens the new one. In the
/// background, it opens in the menu bar again. Whether it went in.
fn go(handle: &AppHandle, background: bool) -> bool {
    let app: App = handle.state::<App>().inner().clone();
    app.asking.store(true, Ordering::SeqCst);
    match app.engine.updates.install(true, background) {
        Ok(_) => {
            crate::quit(handle.clone(), app);
            true
        }
        Err(why) => {
            app.asking.store(false, Ordering::SeqCst);
            if !background {
                handle.dialog().message(why).title("tTerm could not update").kind(MessageDialogKind::Warning).show(|_| {});
            } else {
                eprintln!("tterm: could not update: {why}");
            }
            false
        }
    }
}

/// From the disk image: Move to Applications, once at the start, or when
/// Settings asks.
fn offer_move(handle: &AppHandle, at_start: bool) {
    let app: App = handle.state::<App>().inner().clone();
    if !matches!(app.engine.updates.now().phase, Phase::Unavailable { movable: true, .. }) {
        return;
    }
    if app.quitting.load(Ordering::SeqCst) || app.asking.swap(true, Ordering::SeqCst) {
        return;
    }
    let mut text = String::from("tTerm runs from the disk image now. It can update itself only from the Applications folder.");
    if let Some(ending) = crate::question(&app.engine) {
        text.push_str(" It opens again from there. ");
        text.push_str(&ending);
    }
    if !at_start {
        background::show_window(handle);
    }
    let h = handle.clone();
    handle
        .dialog()
        .message(text)
        .title("Move tTerm to Applications?")
        .kind(MessageDialogKind::Info)
        .buttons(MessageDialogButtons::OkCancelCustom("Move to Applications".into(), "Not now".into()))
        .show(move |yes| {
            let app: App = h.state::<App>().inner().clone();
            if !yes {
                app.asking.store(false, Ordering::SeqCst);
                return;
            }
            match app.engine.updates.move_to_applications() {
                Ok(target) => {
                    open_after_quit(&target);
                    crate::quit(h.clone(), app);
                }
                Err(why) => {
                    app.asking.store(false, Ordering::SeqCst);
                    h.dialog().message(why).title("tTerm could not move").kind(MessageDialogKind::Warning).show(|_| {});
                }
            }
        });
}

/// Opens tTerm at `app` once this one has gone.
fn open_after_quit(app: &Path) {
    let spawned = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("while kill -0 \"$1\" 2>/dev/null; do sleep 0.2; done; sleep 0.3; exec /usr/bin/open -n \"$2\"")
        .arg("sh")
        .arg(std::process::id().to_string())
        .arg(app)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn();
    if let Err(e) = spawned {
        eprintln!("tterm: could not open {} after quitting: {e}", app.display());
    }
}

/// As tTerm quits, whichever way: by itself, the version ready goes in,
/// and is the one that opens next. Nobody watches it start: the version
/// before is gone by then.
pub fn at_exit(engine: &Engine) {
    if by_itself(engine) && engine.updates.ready().is_some() {
        if let Err(why) = engine.updates.install(false, false) {
            eprintln!("tterm: the new version did not go in as tTerm quit: {why}");
        }
    }
}

#[cfg(test)]
mod tests {
    /// The app finds its data before Tauri does (main.rs, for a new version
    /// on trial), by the identifier Tauri keeps it under.
    #[test]
    fn the_data_is_where_tauri_keeps_it() {
        let config: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(config["identifier"], tterm_engine::update::BUNDLE_ID);
        assert!(config["app"].get("appDirectoriesOverride").is_none(), "Tauri's places as they are");
    }
}
