//! What the engine needs of the app around it (from 0.3.0): the device's
//! key kept where only this app reads it, and the browser opened.
//!
//! On a Mac the key is in the login keychain: item "tTerm", with the address
//! of tTerm Web as its account, together with what the engine needs to use
//! it (the engine's own record). Another program does not read it without
//! the person allowing it. While the app is not signed by Apple (until stage 4),
//! each new version is another program to the keychain: the first time it
//! reads the key, the Mac asks for the password once, and Always Allow keeps
//! it so.
//!
//! Elsewhere (Linux, where the app is built for the checks) the key is in a
//! file of the app's folder, for the person alone.

use std::path::PathBuf;
use tauri::AppHandle;
use tauri_plugin_opener::OpenerExt;
use tterm_engine::account::Host;

pub struct AppHost {
    handle: AppHandle,
    /// The keychain item's account: tTerm Web's address.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    account: String,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    file: PathBuf,
    /// For the checks only (debug builds): addresses are written here
    /// instead of opened.
    open_log: Option<PathBuf>,
}

/// The keychain item's name, as the Mac shows it when it asks.
#[cfg(target_os = "macos")]
const SERVICE: &str = "tTerm";

impl AppHost {
    pub fn new(handle: AppHandle, cloud: &str, data_dir: PathBuf) -> AppHost {
        let account = cloud.split_once("://").map(|(_, h)| h).unwrap_or(cloud).to_string();
        let open_log = if cfg!(debug_assertions) { std::env::var_os("TTERM_OPEN_LOG").map(PathBuf::from) } else { None };
        AppHost { handle, account, file: data_dir.join("device-key"), open_log }
    }
}

impl Host for AppHost {
    fn open_url(&self, url: &str) -> Result<(), String> {
        if let Some(log) = &self.open_log {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(log).map_err(|e| e.to_string())?;
            return writeln!(f, "{url}").map_err(|e| e.to_string());
        }
        self.handle.opener().open_url(url, None::<&str>).map_err(|e| e.to_string())
    }

    #[cfg(target_os = "macos")]
    fn load_key(&self) -> Result<Option<String>, String> {
        use security_framework::passwords::{generic_password, PasswordOptions};
        match generic_password(PasswordOptions::new_generic_password(SERVICE, &self.account)) {
            Ok(bytes) => String::from_utf8(bytes).map(Some).map_err(|_| "the key in the keychain is not text".to_string()),
            Err(e) if e.code() == NOT_FOUND => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    #[cfg(target_os = "macos")]
    fn save_key(&self, key: &str) -> Result<(), String> {
        security_framework::passwords::set_generic_password(SERVICE, &self.account, key.as_bytes()).map_err(|e| e.to_string())
    }

    #[cfg(target_os = "macos")]
    fn delete_key(&self) -> Result<(), String> {
        match security_framework::passwords::delete_generic_password(SERVICE, &self.account) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == NOT_FOUND => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn load_key(&self) -> Result<Option<String>, String> {
        match std::fs::read_to_string(&self.file) {
            Ok(text) => Ok(Some(text.trim().to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn save_key(&self, key: &str) -> Result<(), String> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.file).map_err(|e| e.to_string())?;
        file.write_all(key.as_bytes()).map_err(|e| e.to_string())
    }

    #[cfg(not(target_os = "macos"))]
    fn delete_key(&self) -> Result<(), String> {
        match std::fs::remove_file(&self.file) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// errSecItemNotFound: there is no such item in the keychain.
#[cfg(target_os = "macos")]
const NOT_FOUND: i32 = -25300;
