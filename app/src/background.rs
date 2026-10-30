//! tTerm in the background (from 0.4.0; the owner, 28.10: «вариант 2»):
//! while this Mac is opened from tTerm Web and the phone (Settings; the
//! engine's reach.rs), the app keeps that link with its window closed, in
//! the menu bar, and starts when the person logs in, as tTerm Web's agent
//! did before it. Its icon there opens the window, says how the link is,
//! and quits; from 0.5.0, with a new version ready, Restart to Update
//! (updates.rs). Otherwise the app is as before: closing its window quits
//! it.
//!
//! What it follows is the switch and the sign-in (the engine's `kept`), not
//! the link of the moment: no network, a quit, a slow keychain leave the
//! login item as it is.
//!
//! On a Mac only, for now: elsewhere closing the window quits the app, and
//! the link runs while it does.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::image::Image;
use tauri::menu::{IsMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Manager, Wry};
use tterm_engine::reach::Status;
use tterm_engine::Engine;

/// The icon in the menu bar, 36 by 36, black on nothing: the two signs of
/// the logo (icons/source/tray.svg).
const ICON: &[u8] = include_bytes!("../icons/tray.rgba");
const ICON_SIDE: u32 = 36;

/// The app's own autostart: a login item of launchd, as the agent had.
pub const LABEL: &str = "net.tterm.app";

/// Started at login by its autostart: no window until asked for.
pub const ARG: &str = "--background";

/// What the menu bar says of this computer.
const HERE: &str = "This Mac";

/// Whether this system keeps the app in the background.
pub fn supported() -> bool {
    cfg!(target_os = "macos")
}

/// Whether the app was started at login, by its autostart.
pub fn started_at_login() -> bool {
    std::env::args().any(|a| a == ARG)
}

/// The icon in the menu bar, once made, and the line of its menu that says
/// how the link is.
#[derive(Default)]
pub struct Bar {
    tray: Mutex<Option<(TrayIcon<Wry>, MenuItem<Wry>)>>,
    /// The app keeps running in the background for the link; None until
    /// the engine knows.
    on: Mutex<Option<bool>>,
    /// What the line of the link says now, and the item of a version
    /// ready, if one is (from 0.5.0): the menu is made again with them.
    said: Mutex<String>,
    update: Mutex<Option<String>>,
    /// The window closed into the menu bar (hide_window), not minimized or
    /// hidden with Cmd+H: what updating by itself waits for (updates.rs).
    closed: AtomicBool,
}

/// Whether closing the window leaves the app running.
pub fn on(handle: &AppHandle) -> bool {
    supported() && *handle.state::<Bar>().on.lock().unwrap() == Some(true)
}

/// Follows the switch and the link: the menu bar and the login item with
/// them. A start at login with nothing to keep in the background shows the
/// window, once the account was looked up and the link had its say.
pub fn follow(handle: &AppHandle, engine: Arc<Engine>) {
    if !supported() {
        return;
    }
    let (mut kept, mut status) = (engine.reach.kept(), engine.reach.status());
    let h = handle.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let k = *kept.borrow_and_update();
            let now = status.borrow_and_update().clone();
            // On the main thread, as the menu of a version ready
            // (set_update): the icon's menu is changed in one place.
            let on = h.clone();
            let _ = h.run_on_main_thread(move || show(&on, k, &now));
            tokio::select! {
                changed = kept.changed() => if changed.is_err() { return },
                changed = status.changed() => if changed.is_err() { return },
            }
        }
    });
    if started_at_login() {
        let h = handle.clone();
        tauri::async_runtime::spawn(async move {
            if let Some(account) = engine.cloud.clone() {
                account.wait_ready().await;
            }
            engine.reach.look_again();
            tokio::time::sleep(Duration::from_secs(2)).await;
            if engine.reach.kept_now() != Some(true) {
                show_window(&h);
            }
        });
    }
}

fn show(handle: &AppHandle, kept: Option<bool>, now: &Status) {
    let bar = handle.state::<Bar>();
    if let Some(on) = kept {
        let was = bar.on.lock().unwrap().replace(on);
        if was != Some(on) {
            login_item(handle, on);
            // App Nap would slow the link's signs of life with the window
            // closed (mac.rs).
            #[cfg(target_os = "macos")]
            let _ = handle.run_on_main_thread(move || crate::mac::stay_awake(on));
        }
        // No more in the background (off, removed in tTerm Web, signed
        // out): the window again, rather than an app nobody sees.
        if was == Some(true) && !on && hidden(handle) {
            show_window(handle);
        }
    }
    let on = *bar.on.lock().unwrap() == Some(true);
    *bar.said.lock().unwrap() = now.line(HERE);
    let update = bar.update.lock().unwrap().clone();
    let mut tray = bar.tray.lock().unwrap();
    if on && tray.is_none() {
        match make(handle, update.as_deref()) {
            Ok(made) => *tray = Some(made),
            Err(e) => eprintln!("tterm: no icon in the menu bar: {e}"),
        }
    }
    if let Some((icon, line)) = tray.as_ref() {
        let _ = line.set_text(now.line(HERE));
        let _ = icon.set_visible(on);
    }
}

/// The icon's menu with Restart to Update (`text`) or without it. On the
/// main thread, as `show`.
pub fn set_update(handle: &AppHandle, text: Option<String>) {
    let bar = handle.state::<Bar>();
    {
        let mut update = bar.update.lock().unwrap();
        if *update == text {
            return;
        }
        update.clone_from(&text);
    }
    let said = bar.said.lock().unwrap().clone();
    let mut tray = bar.tray.lock().unwrap();
    let Some((icon, line)) = tray.as_mut() else { return };
    match menu(handle, text.as_deref()) {
        Ok((menu, fresh)) => {
            let _ = fresh.set_text(said);
            if icon.set_menu(Some(menu)).is_ok() {
                *line = fresh;
            }
        }
        Err(e) => eprintln!("tterm: the menu in the menu bar: {e}"),
    }
}

pub fn hidden(handle: &AppHandle) -> bool {
    handle.get_webview_window("main").map(|w| !w.is_visible().unwrap_or(true)).unwrap_or(false)
}

/// The icon's menu: Open tTerm, how the link is, Restart to Update when a
/// version is ready, Quit tTerm. Its items are the app's menu's (main.rs,
/// on_menu).
fn menu(handle: &AppHandle, update: Option<&str>) -> tauri::Result<(Menu<Wry>, MenuItem<Wry>)> {
    let open = MenuItem::with_id(handle, "bar-open", "Open tTerm", true, None::<&str>)?;
    let line = MenuItem::with_id(handle, "bar-status", HERE, false, None::<&str>)?;
    let restart = update.map(|text| MenuItem::with_id(handle, "bar-update", text, true, None::<&str>)).transpose()?;
    let quit = MenuItem::with_id(handle, "bar-quit", "Quit tTerm", true, None::<&str>)?;
    let (one, two) = (PredefinedMenuItem::separator(handle)?, PredefinedMenuItem::separator(handle)?);
    let mut items: Vec<&dyn IsMenuItem<Wry>> = vec![&open, &one, &line, &two];
    if let Some(restart) = restart.as_ref() {
        items.push(restart);
    }
    items.push(&quit);
    Ok((Menu::with_items(handle, &items)?, line))
}

/// The icon and its menu.
fn make(handle: &AppHandle, update: Option<&str>) -> tauri::Result<(TrayIcon<Wry>, MenuItem<Wry>)> {
    let (menu, line) = menu(handle, update)?;
    let icon = TrayIconBuilder::with_id("tterm")
        .icon(Image::new(ICON, ICON_SIDE, ICON_SIDE))
        .icon_as_template(true)
        .tooltip("tTerm")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .build(handle)?;
    Ok((icon, line))
}

/// Whether the window was closed into the menu bar, and not opened since.
pub fn closed(handle: &AppHandle) -> bool {
    handle.state::<Bar>().closed.load(Ordering::SeqCst)
}

/// The window, shown and in front, with the app in the Dock again.
pub fn show_window(handle: &AppHandle) {
    handle.state::<Bar>().closed.store(false, Ordering::SeqCst);
    in_dock(handle, true);
    if let Some(w) = handle.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// The window closed, the app running on in the menu bar, out of the Dock.
pub fn hide_window(handle: &AppHandle) {
    handle.state::<Bar>().closed.store(true, Ordering::SeqCst);
    if let Some(w) = handle.get_webview_window("main") {
        let _ = w.hide();
    }
    in_dock(handle, false);
}

#[cfg(target_os = "macos")]
fn in_dock(handle: &AppHandle, shown: bool) {
    let policy = if shown { tauri::ActivationPolicy::Regular } else { tauri::ActivationPolicy::Accessory };
    let _ = handle.set_activation_policy(policy);
}

#[cfg(not(target_os = "macos"))]
fn in_dock(_handle: &AppHandle, _shown: bool) {}

// ------------------------------------------------------------ login item

/// Whether the app runs from its bundle (tTerm.app), not from a build.
fn from_bundle() -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let Some(contents) = exe.parent().and_then(|p| p.parent()) else { return false };
    let bundle = contents.parent();
    contents.file_name().map(|n| n == "Contents").unwrap_or(false) && bundle.and_then(|b| b.extension()).map(|e| e == "app").unwrap_or(false)
}

fn plist_path() -> PathBuf {
    tterm_engine::pty::home_dir().join("Library").join("LaunchAgents").join(format!("{LABEL}.plist"))
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The login item for the app with this bundle identifier: open starts it,
/// without a window and behind the others, wherever it is now (moved, or
/// new), or brings the running one. Login Items in System Settings name it
/// after the app.
pub fn plist_for(identifier: &str) -> String {
    let id = xml(identifier);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LABEL}</string>
  <key>AssociatedBundleIdentifiers</key>
  <array><string>{id}</string></array>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/open</string>
    <string>-g</string>
    <string>-b</string>
    <string>{id}</string>
    <string>--args</string>
    <string>{ARG}</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>
"#
    )
}

/// The login item there or gone, as the switch and the sign-in say:
/// launchd starts it at the next login. Put in only by the app from its
/// bundle, not by a build.
fn login_item(handle: &AppHandle, on: bool) {
    let path = plist_path();
    if !on {
        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                eprintln!("tterm: could not take the login item out ({}): {e}", path.display());
            }
        }
        return;
    }
    if !from_bundle() {
        return;
    }
    let text = plist_for(&handle.config().identifier);
    if std::fs::read_to_string(&path).ok().as_deref() == Some(text.as_str()) {
        return;
    }
    let written = path.parent().map(std::fs::create_dir_all).unwrap_or(Ok(())).and_then(|_| std::fs::write(&path, text));
    if let Err(e) = written {
        eprintln!("tterm: could not put the login item in ({}): {e}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_login_item() {
        let text = plist_for("net.tterm.desktop");
        assert!(text.contains("<string>-b</string>\n    <string>net.tterm.desktop</string>"), "{text}");
        assert!(text.contains("<string>--background</string>") && text.contains("<key>RunAtLoad</key><true/>"));
        assert!(!text.contains("KeepAlive"), "quit is quit");
        assert!(plist_for("a&b").contains("<string>a&amp;b</string>"));
    }
}
