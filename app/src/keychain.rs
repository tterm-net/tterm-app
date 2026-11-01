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
//!
//! The vault's lock (from 0.7.0) is kept in the keychain too: its KEK under
//! the vault id (service `net.tterm.desktop.vault`), read only after a
//! LocalAuthentication check (Touch ID or the Mac's password).
//!
//! Plainly, as it is without an Apple Developer profile: the check is a gate
//! in this app's own code, run before it reads a normal keychain item. It
//! guards against someone at the keyboard of an unlocked Mac, who must pass
//! Touch ID or the password before this app opens the vault; it does not
//! guard against other programs of the same user. Those can ask the keychain
//! for the item themselves, and what stands in their way is the keychain's
//! own question to the person ("… wants to use your confidential
//! information"), not Touch ID. A biometric access control on the item
//! itself, and the data protection keychain it lives in, need entitlements
//! that only a provisioning profile allows (PROJECT.md, the contract).
//!
//! The item is asked for as this Mac's alone, readable only while the Mac is
//! unlocked (kSecAttrAccessibleWhenUnlockedThisDeviceOnly): in the data
//! protection keychain such an item never leaves the Mac, in a backup or in
//! iCloud. macOS gives that keychain only to an app with those entitlements,
//! so this build falls back to the login keychain, where macOS does not
//! apply the attribute at all (Apple's kSecAttrAccessible: "only if you also
//! set kSecUseDataProtectionKeychain"); the item is then in the login
//! keychain's file, which Time Machine backs up encrypted with the login
//! password. Signed with a profile, the same code keeps it this Mac's only.
//!
//! On Linux the vault lock is not offered (`available` is false); the KEK,
//! where the checks ask for it, is a file.

use std::path::PathBuf;
use tauri::AppHandle;
use tauri_plugin_opener::OpenerExt;
use tterm_engine::account::Host;
use tterm_engine::vault::Keeper;

pub struct AppHost {
    handle: AppHandle,
    /// The keychain item's account: tTerm Web's address.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    account: String,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    file: PathBuf,
    /// Where the vault's KEK is on Linux (the checks): a file per vault id.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    data_dir: PathBuf,
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
        AppHost { handle, account, file: data_dir.join("device-key"), data_dir, open_log }
    }
}

/// The keychain service the vault's KEK is kept under.
#[cfg(target_os = "macos")]
const VAULT_SERVICE: &str = tterm_engine::vault::KEYCHAIN_SERVICE;

impl Keeper for AppHost {
    #[cfg(target_os = "macos")]
    fn available(&self) -> bool {
        true
    }

    #[cfg(target_os = "macos")]
    fn authenticate(&self, reason: &str) -> Result<(), String> {
        local_authentication(reason)
    }

    /// In the data protection keychain, this Mac's only and only while it
    /// is unlocked; where this build may not use it, in the login keychain
    /// (see the note above). One copy only: the other place's goes.
    #[cfg(target_os = "macos")]
    fn save_kek(&self, vault_id: &str, kek: &[u8]) -> Result<(), String> {
        use security_framework::access_control::{ProtectionMode, SecAccessControl};
        use security_framework::passwords::{delete_generic_password_options, set_generic_password, set_generic_password_options};
        // A new item each time (an update would not match an item with an
        // access control in the query).
        let _ = delete_generic_password_options(vault_item(vault_id, true));
        let protected = SecAccessControl::create_with_protection(Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly), 0).and_then(|access| {
            let mut options = vault_item(vault_id, true);
            options.set_access_control(access);
            set_generic_password_options(kek, options)
        });
        match protected {
            Ok(()) => {
                let _ = delete_generic_password_options(vault_item(vault_id, false));
                Ok(())
            }
            Err(e) => {
                if e.code() != MISSING_ENTITLEMENT {
                    eprintln!("tterm: the vault key is not in the data protection keychain ({}): in the login keychain instead", e.code());
                }
                set_generic_password(VAULT_SERVICE, vault_id, kek).map_err(|e| e.to_string())
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn load_kek(&self, vault_id: &str) -> Result<Option<Vec<u8>>, String> {
        use security_framework::passwords::generic_password;
        if let Ok(bytes) = generic_password(vault_item(vault_id, true)) {
            return Ok(Some(bytes));
        }
        match generic_password(vault_item(vault_id, false)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.code() == NOT_FOUND => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    #[cfg(target_os = "macos")]
    fn delete_kek(&self, vault_id: &str) -> Result<(), String> {
        use security_framework::passwords::delete_generic_password_options;
        let _ = delete_generic_password_options(vault_item(vault_id, true));
        match delete_generic_password_options(vault_item(vault_id, false)) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == NOT_FOUND => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    // Linux (the checks): no Touch ID, so the vault lock is not offered;
    // the KEK, where a test asks for it, is a file for the person alone.
    #[cfg(not(target_os = "macos"))]
    fn available(&self) -> bool {
        false
    }

    #[cfg(not(target_os = "macos"))]
    fn authenticate(&self, _reason: &str) -> Result<(), String> {
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn save_kek(&self, vault_id: &str, kek: &[u8]) -> Result<(), String> {
        std::fs::write(self.kek_file(vault_id), kek).map_err(|e| e.to_string())
    }

    #[cfg(not(target_os = "macos"))]
    fn load_kek(&self, vault_id: &str) -> Result<Option<Vec<u8>>, String> {
        match std::fs::read(self.kek_file(vault_id)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn delete_kek(&self, vault_id: &str) -> Result<(), String> {
        match std::fs::remove_file(self.kek_file(vault_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(not(target_os = "macos"))]
impl AppHost {
    fn kek_file(&self, vault_id: &str) -> PathBuf {
        let safe: String = vault_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
        self.data_dir.join(format!("vault-kek-{safe}"))
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

/// errSecMissingEntitlement: the data protection keychain is not this
/// build's (no provisioning profile).
#[cfg(target_os = "macos")]
const MISSING_ENTITLEMENT: i32 = -34018;

/// The vault's keychain item for `vault_id`: in the data protection keychain
/// (`protected`), or in the login keychain.
#[cfg(target_os = "macos")]
fn vault_item(vault_id: &str, protected: bool) -> security_framework::passwords::PasswordOptions {
    let mut options = security_framework::passwords::PasswordOptions::new_generic_password(VAULT_SERVICE, vault_id);
    if protected {
        options.use_protected_keychain();
    }
    options
}

/// The LocalAuthentication gate before the vault key is read (from 0.7.0):
/// Touch ID, or the Mac's password as the fallback. Runs `evaluatePolicy:
/// localizedReason:reply:` with `deviceOwnerAuthentication`, waits for its
/// completion block, and gives back Ok to go on or Err with the reason the
/// Mac gave. Without an Apple Developer profile this is a gate in this app,
/// not a lock bound to the keychain item: it guards against someone at the
/// keyboard, not against other programs of the same user (see the note
/// above).
#[cfg(target_os = "macos")]
fn local_authentication(reason: &str) -> Result<(), String> {
    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::{AnyClass, AnyObject, Bool};
    use objc2::msg_send;
    use std::sync::mpsc;
    use std::time::Duration;

    /// LAPolicyDeviceOwnerAuthentication: Touch ID or the password.
    const POLICY: isize = 2;
    /// How long to wait for the person to answer, at most.
    const WAIT: Duration = Duration::from_secs(120);

    // SAFETY: the LocalAuthentication framework's LAContext is used as its
    // headers document; every pointer is checked before it is sent a
    // message, and the reply block only sends its result down a channel.
    unsafe {
        let Some(class) = AnyClass::get(c"LAContext") else {
            return Err("LocalAuthentication is not available on this Mac.".into());
        };
        let context: *mut AnyObject = msg_send![class, new];
        if context.is_null() {
            return Err("LocalAuthentication could not start.".into());
        }
        // Owned, so it lives until the check is done and is released after.
        let context: Retained<AnyObject> = Retained::from_raw(context).ok_or("LocalAuthentication could not start.")?;
        let Some(ns_string) = AnyClass::get(c"NSString") else {
            return Err("LocalAuthentication could not start.".into());
        };
        let reason_c = std::ffi::CString::new(reason).unwrap_or_else(|_| std::ffi::CString::new("open your tTerm vault").unwrap());
        let ns_reason: *mut AnyObject = msg_send![ns_string, stringWithUTF8String: reason_c.as_ptr()];

        let (tx, rx) = mpsc::channel::<Result<(), String>>();
        let reply = RcBlock::new(move |success: Bool, error: *mut AnyObject| {
            let result = if success.as_bool() {
                Ok(())
            } else {
                Err(error_text(error))
            };
            let _ = tx.send(result);
        });
        let _: () = msg_send![&*context, evaluatePolicy: POLICY, localizedReason: ns_reason, reply: &*reply];
        match rx.recv_timeout(WAIT) {
            Ok(result) => result,
            Err(_) => Err("the check timed out".into()),
        }
    }
}

/// An NSError's `localizedDescription` as a Rust string, for the reason a
/// check failed; a plain sentence when there is none.
#[cfg(target_os = "macos")]
unsafe fn error_text(error: *mut objc2::runtime::AnyObject) -> String {
    use objc2::runtime::AnyObject;
    use objc2::msg_send;
    if error.is_null() {
        return "the check did not pass".into();
    }
    let description: *mut AnyObject = msg_send![error, localizedDescription];
    if description.is_null() {
        return "the check did not pass".into();
    }
    let utf8: *const std::os::raw::c_char = msg_send![description, UTF8String];
    if utf8.is_null() {
        return "the check did not pass".into();
    }
    std::ffi::CStr::from_ptr(utf8).to_string_lossy().into_owned()
}

// Links LocalAuthentication so LAContext is there (checked, never dlopened).
#[cfg(target_os = "macos")]
#[link(name = "LocalAuthentication", kind = "framework")]
extern "C" {}
