//! The vault of SSH keys, in the engine (from 0.7.0): the vault key (VK) in
//! memory only while the vault is open, and all that opening it takes done
//! through the app around the engine (the keychain, LocalAuthentication) and
//! tTerm Web in the cloud (the sealed keys and locks). The crypto is
//! crypto.rs; the keys read and signed are sshkeys.rs; `~/.ssh` and the
//! logins are ssh.rs; the cloud calls go through the signed-in account.
//!
//! The app's lock is a key (KEK) of 32 random bytes in the macOS keychain
//! (service `net.tterm.desktop.vault`, account the vault id), read only
//! after a LocalAuthentication check (Touch ID or the Mac's password). The
//! vault key is kept wrapped for that lock in tTerm Web (each lock of `GET
//! /api/vault` carries its wrap); the app opens the wrap with the KEK and
//! holds the vault key in memory while it runs, until Lock or sign out.
//! Without an Apple Developer profile the keychain item cannot be bound to
//! biometrics, so the check is a gate before reading a normal item, not a
//! lock on the item itself (PROJECT.md).
//!
//! A vault made in a browser has no lock of this Mac's: it opens here once
//! with its recovery code, and then gets the app's own lock, so that the next
//! open is Touch ID only. What needs the vault key (allowing a new browser,
//! a new recovery code) opens the vault too, under the same one check.
//!
//! The keychain and LocalAuthentication are the app's (macOS); the engine
//! reaches them through `Keeper`, which the app implements and the checks
//! stand in for on Linux.

use crate::account::Trouble;
use crate::crypto::{self, Key, Pairer};
use crate::upstream::Answer;
use crate::Engine;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The keychain item's service, as the contract has it.
pub const KEYCHAIN_SERVICE: &str = "net.tterm.desktop.vault";

/// What the LocalAuthentication prompt says it is for, as keys of the app's
/// own words (engine/i18n, say.rs): macOS shows each after "tTerm is trying
/// to …" in its own dialog, so it is said in the language the app shows.
pub const REASON_OPEN: &str = "vault.reason_open";
pub const REASON_CREATE: &str = "vault.reason_create";
pub const REASON_LOCK: &str = "vault.reason_lock";
pub const REASON_APPROVE: &str = "vault.reason_approve";
pub const REASON_RECOVERY: &str = "vault.reason_recovery";

/// What the page shows when this Mac has no lock of the vault (a vault made
/// in a browser, or this Mac's lock taken off): the recovery code opens it
/// once, and then this Mac has its own.
pub const NO_LOCK_HERE: &str = "This Mac has no lock on your vault yet. Open it once with your recovery code: after that Touch ID opens it here.";
const SIGNED_OUT: &str = "Signed out of tTerm on this computer.";

/// How long `answer` waits for the new browser to reveal its key, at most
/// (it asks every two seconds; the pairing lasts five minutes).
const REVEAL_WAIT: Duration = Duration::from_secs(120);
const REVEAL_POLL: Duration = Duration::from_secs(1);

/// What the engine needs of the app for the vault: the macOS keychain, where
/// the app's KEK is kept, and the LocalAuthentication gate before it is read.
/// The app implements it; on Linux the checks stand in with memory and no
/// real gate, so the engine's tests run without a Mac.
pub trait Keeper: Send + Sync {
    /// Whether the vault can be an app lock here: true on a Mac, where the
    /// keychain and LocalAuthentication are. The page shows `available`.
    fn available(&self) -> bool;
    /// The LocalAuthentication gate (`deviceOwnerAuthentication`): Touch ID
    /// or the Mac's password. Ok to go on, Err with a reason the page shows.
    fn authenticate(&self, reason: &str) -> Result<(), String>;
    /// Keeps the KEK under the vault id, in place of any there.
    fn save_kek(&self, vault_id: &str, kek: &[u8]) -> Result<(), String>;
    /// The KEK of this vault, if the keychain has one; None when it does not.
    fn load_kek(&self, vault_id: &str) -> Result<Option<Vec<u8>>, String>;
    /// Takes the KEK out (Lock does not; Sign out and a failed create do).
    fn delete_kek(&self, vault_id: &str) -> Result<(), String>;
}

/// A key of the vault, as the engine holds it while open: enough to sign for
/// it and to say it can (vault.can). The sealed box opens with the VK.
#[derive(Clone)]
struct Held {
    fingerprint: String,
    sealed: Vec<u8>,
    key_id: String,
}

/// The vault open: the vault id, the lock of this Mac's it is open with,
/// the vault key, the keys it holds now, and the account's epoch it was
/// opened in (a sign-out or another sign-in since locks it).
struct Open {
    vault_id: String,
    lock_id: String,
    vk: Key,
    keys: Vec<Held>,
    epoch: u64,
}

/// One pairing of a new browser being answered on this Mac: this side's
/// X25519 key from `answer` until `approve`, the browser's once revealed,
/// and the vault key sealed for it once allowed (posted again if the post
/// did not go through).
struct Pending {
    pairer: Option<Pairer>,
    pub_a: [u8; 32],
    pub_b: Option<Vec<u8>>,
    sealed: Option<Vec<u8>>,
}

pub struct Vault {
    host: Arc<dyn Keeper>,
    label: String,
    open: Mutex<Option<Open>>,
    pairings: Mutex<HashMap<String, Pending>>,
    /// The fingerprints the vault can sign for now, empty when locked: the
    /// page's socket to the cloud (upstream_socket.rs) watches it and sends
    /// `vault.can` upstream on each change.
    can: watch::Sender<Vec<String>>,
    /// What opens or makes the vault, or adds a lock, one at a time: two
    /// opens at once with the recovery code make one lock, not two.
    one: tokio::sync::Mutex<()>,
    /// The vault id tTerm named last, and the account's epoch then: what a
    /// sign-out forgets the KEK of, open or not.
    known: Mutex<Option<(String, u64)>>,
}

/// What a vault request could not do, as a status and a sentence the page
/// shows (the local API answers with them); `signed_out` when tTerm says the
/// app's session is over, which the page takes as the rest of the API does.
pub struct Failed {
    pub status: u16,
    pub message: String,
    pub signed_out: bool,
}

impl Failed {
    fn new(status: u16, message: impl Into<String>) -> Failed {
        Failed { status, message: message.into(), signed_out: false }
    }
}

type Done<T> = Result<T, Failed>;

impl Vault {
    pub fn new(host: Arc<dyn Keeper>, label: String) -> Vault {
        Vault {
            host,
            label,
            open: Mutex::new(None),
            pairings: Mutex::new(HashMap::new()),
            can: watch::channel(Vec::new()).0,
            one: tokio::sync::Mutex::new(()),
            known: Mutex::new(None),
        }
    }

    /// The account's epoch now (one more with each sign-in and sign-out),
    /// None while not signed in.
    fn epoch(engine: &Arc<Engine>) -> Option<u64> {
        engine.cloud.as_ref().filter(|a| a.signed_in()).map(|a| a.epoch_now())
    }

    /// The vault of an account that is gone (signed out, here or in a
    /// browser, or another sign-in since): locked, its pairings dropped and
    /// its KEK forgotten, as a sign out does. Asked before anything that
    /// uses or shows the vault, and when the page's socket to tTerm opens.
    pub async fn check_account(&self, engine: &Arc<Engine>) {
        let now = Self::epoch(engine);
        let stale_open = self.open.lock().unwrap().as_ref().filter(|o| Some(o.epoch) != now).map(|o| o.vault_id.clone());
        let stale_known = {
            let mut known = self.known.lock().unwrap();
            match known.as_ref() {
                Some((id, epoch)) if Some(*epoch) != now => {
                    let id = id.clone();
                    *known = None;
                    Some(id)
                }
                _ => None,
            }
        };
        if stale_open.is_some() {
            self.drop_open();
            self.pairings.lock().unwrap().clear();
        }
        for id in stale_open.into_iter().chain(stale_known).collect::<BTreeSet<_>>() {
            eprintln!("tterm: signed out of the account the vault was opened in: locked, and its key forgotten on this Mac");
            self.forget_kek(&id).await;
        }
    }

    fn know(&self, engine: &Arc<Engine>, vault_id: &str) {
        if let Some(epoch) = Self::epoch(engine) {
            *self.known.lock().unwrap() = Some((vault_id.to_string(), epoch));
        }
    }

    /// Whether this computer can be an app lock (a Mac).
    pub fn available(&self) -> bool {
        self.host.available()
    }

    /// Whether the vault is open now.
    pub fn is_open(&self) -> bool {
        self.open.lock().unwrap().is_some()
    }

    /// The fingerprints the vault can sign for now, to watch.
    pub fn watch_can(&self) -> watch::Receiver<Vec<String>> {
        self.can.subscribe()
    }

    /// The fingerprints the vault can sign for now.
    pub fn can_now(&self) -> Vec<String> {
        self.can.borrow().clone()
    }

    fn set_can(&self, keys: &[Held]) {
        let fps: Vec<String> = keys.iter().map(|k| k.fingerprint.clone()).collect();
        self.can.send_replace(fps);
    }

    /// `GET /api/app/vault`: what the page shows before it does anything.
    pub async fn status_json(&self, engine: &Arc<Engine>) -> Value {
        self.check_account(engine).await;
        let open = self.is_open();
        // Whether a vault exists is tTerm's to say; asked only when it might
        // matter (available and not already open), and softly: an app that
        // cannot reach tTerm still says what it knows. In the background, as
        // the page asks it: it keeps no session from ending.
        let exists = if open {
            true
        } else if self.available() {
            matches!(self.cloud_get_as(engine, true).await, Ok(Some(_)))
        } else {
            false
        };
        json!({
            "available": self.available(),
            "exists": exists,
            "open": open,
            "keys": self.can_now(),
        })
    }

    // -------------------------------------------------- create, open, lock

    /// `POST /api/app/vault/create`: a new vault, its app lock and a recovery
    /// code. The KEK goes in the keychain, the wraps to tTerm; the recovery
    /// code is shown once and kept nowhere.
    pub async fn create(&self, engine: &Arc<Engine>) -> Done<Value> {
        self.check_account(engine).await;
        let _one = self.one.lock().await;
        if !self.available() {
            return Err(Failed::new(409, "This computer cannot hold a vault lock. Open the vault in a browser with a passkey, or use a Mac."));
        }
        if self.is_open() {
            return Err(Failed::new(409, "The vault is open already."));
        }
        if self.cloud_get(engine).await?.is_some() {
            return Err(Failed::new(409, "A vault exists for this account already. Open it instead."));
        }
        self.authenticate(engine, REASON_CREATE).await?;
        let vault_id = Uuid::new_v4().to_string();
        let vk = crypto::new_key();
        let kek = crypto::new_key();
        let lock_id = Uuid::new_v4().to_string();
        let wrap = crypto::seal(&kek, vk.as_ref(), &crypto::lock_aad(&lock_id));
        let code = crypto::new_recovery_code();
        let salt = crypto::random::<{ crypto::RECOVERY_SALT_LEN }>();
        let normalized = crypto::normalize_code(&code).expect("a code we just made");
        let rkek = crypto::recovery_kek(&normalized, &salt);
        let recovery_wrap = crypto::seal(&rkek, vk.as_ref(), &crypto::recovery_aad(&vault_id));
        // The KEK first, so a vault tTerm takes always has its lock here; a
        // failure after this takes the item out again.
        self.save_kek(&vault_id, kek.as_ref()).await?;
        let body = json!({
            "id": vault_id,
            "recoverySalt": crypto::b64u(&salt),
            "recoveryWrap": crypto::b64u(&recovery_wrap),
            "lock": {"id": lock_id, "kind": "app", "wrap": crypto::b64u(&wrap), "label": self.label},
        });
        let answer = match self.cloud_call(engine, "POST", "/api/vault", Some(&body)).await {
            Ok(a) => a,
            Err(f) => {
                self.forget_kek(&vault_id).await;
                return Err(f);
            }
        };
        if answer.status != 201 {
            self.forget_kek(&vault_id).await;
            return Err(self.from_cloud(&answer, "The vault could not be made"));
        }
        self.hold(engine, vault_id, lock_id, vk, Vec::new());
        Ok(json!({"recoveryCode": code.as_str()}))
    }

    /// `POST /api/app/vault/open`: with this Mac's lock (Touch ID, the KEK
    /// from the keychain, the lock's wrap from `GET /api/vault`); or, with
    /// `recovery_code`, a vault this Mac has no lock of yet (made in a
    /// browser): the code opens it, and this Mac gets its own lock.
    pub async fn open(&self, engine: &Arc<Engine>, recovery_code: Option<&str>) -> Done<Value> {
        self.check_account(engine).await;
        let _one = self.one.lock().await;
        if self.is_open() {
            return Ok(json!({"open": true}));
        }
        if !self.available() {
            return Err(Failed::new(409, "This computer cannot open the vault. Use a browser with a passkey, or the recovery code."));
        }
        let Some(vault) = self.cloud_get(engine).await? else {
            return Err(Failed::new(404, "There is no vault yet. Make one first."));
        };
        match recovery_code.map(str::trim).filter(|c| !c.is_empty()) {
            Some(code) => self.open_with_code(engine, &vault, code).await?,
            None => self.open_with_lock(engine, &vault, true).await?,
        }
        Ok(json!({"open": true}))
    }

    /// Opens the vault with this Mac's lock: the KEK from the keychain opens
    /// the wrap of one of the vault's app locks (this device's first). The
    /// check comes first unless the caller made it already.
    async fn open_with_lock(&self, engine: &Arc<Engine>, vault: &Value, check: bool) -> Done<()> {
        let vault_id = vault["id"].as_str().unwrap_or_default().to_string();
        let locks = app_locks(vault);
        // No lock of an app at all (a vault made in a browser): Touch ID
        // would open nothing, so it is not asked.
        if locks.is_empty() {
            return Err(Failed::new(409, NO_LOCK_HERE));
        }
        if check {
            self.authenticate(engine, REASON_OPEN).await?;
        }
        let Some(kek) = self.load_kek(&vault_id).await? else {
            return Err(Failed::new(409, NO_LOCK_HERE));
        };
        let kek = crypto::key_of(&kek).ok_or_else(|| Failed::new(500, "This Mac's keychain item is not a vault key."))?;
        let opened = locks.iter().find_map(|(lock_id, wrap)| crypto::open_key(&kek, wrap, &crypto::lock_aad(lock_id)).map(|vk| (lock_id.clone(), vk)));
        let Some((lock_id, vk)) = opened else {
            // This Mac's key opens none of the locks: its own was taken off
            // (in a browser's Settings › Keys). The item is no use any more.
            self.forget_kek(&vault_id).await;
            return Err(Failed::new(409, NO_LOCK_HERE));
        };
        let keys = read_keys(vault, &vk);
        self.hold(engine, vault_id, lock_id.clone(), vk, keys);
        self.lock_used(engine, &lock_id);
        Ok(())
    }

    /// Opens the vault with its recovery code (the contract's recovery KEK
    /// over `GET /api/vault/recovery`), then gives this Mac its own lock:
    /// Touch ID, a new KEK in the keychain, `POST /api/vault/locks` of kind
    /// app. If this Mac's keychain still opens one of the vault's app locks,
    /// that lock is kept and none is added.
    async fn open_with_code(&self, engine: &Arc<Engine>, vault: &Value, code: &str) -> Done<()> {
        let vault_id = vault["id"].as_str().unwrap_or_default().to_string();
        let normalized = crypto::normalize_code(code).ok_or_else(|| Failed::new(422, "That is not a recovery code: it is 24 letters and digits, as XXXX-XXXX-XXXX-XXXX-XXXX-XXXX."))?;
        let answer = self.cloud_call(engine, "GET", "/api/vault/recovery", None).await?;
        if answer.status != 200 {
            return Err(self.from_cloud(&answer, "The vault's recovery could not be read"));
        }
        let got = answer.json().unwrap_or(Value::Null);
        let (Some(salt), Some(wrap)) = (got["recoverySalt"].as_str().and_then(crypto::from_b64u), got["recoveryWrap"].as_str().and_then(crypto::from_b64u)) else {
            return Err(Failed::new(502, "tTerm's answer for the recovery code was not understood."));
        };
        let rkek = crypto::recovery_kek(&normalized, &salt);
        let vk = crypto::open_key(&rkek, &wrap, &crypto::recovery_aad(&vault_id)).ok_or_else(|| Failed::new(422, "That recovery code does not open your vault."))?;
        // The code is right: now this Mac's own lock, with the person's say.
        self.authenticate(engine, REASON_LOCK).await?;
        let kept = match self.load_kek(&vault_id).await? {
            Some(kek) => crypto::key_of(&kek).and_then(|kek| {
                app_locks(vault).into_iter().find(|(lock_id, wrap)| crypto::open_key(&kek, wrap, &crypto::lock_aad(lock_id)).is_some()).map(|(lock_id, _)| lock_id)
            }),
            None => None,
        };
        let lock_id = match kept {
            Some(lock_id) => lock_id,
            None => self.add_lock(engine, &vault_id, &vk).await?,
        };
        let keys = read_keys(vault, &vk);
        self.hold(engine, vault_id, lock_id, vk, keys);
        Ok(())
    }

    /// A new app lock for this Mac: a new KEK in the keychain (in place of a
    /// stale one), the vault key wrapped for it, `POST /api/vault/locks`.
    async fn add_lock(&self, engine: &Arc<Engine>, vault_id: &str, vk: &Key) -> Done<String> {
        let kek = crypto::new_key();
        let lock_id = Uuid::new_v4().to_string();
        let wrap = crypto::seal(&kek, vk.as_ref(), &crypto::lock_aad(&lock_id));
        self.save_kek(vault_id, kek.as_ref()).await?;
        let body = json!({"id": lock_id, "kind": "app", "wrap": crypto::b64u(&wrap), "label": self.label});
        let answer = match self.cloud_call(engine, "POST", "/api/vault/locks", Some(&body)).await {
            Ok(a) => a,
            Err(f) => {
                self.forget_kek(vault_id).await;
                return Err(f);
            }
        };
        if answer.status != 201 && answer.status != 200 {
            self.forget_kek(vault_id).await;
            return Err(self.from_cloud(&answer, "This Mac's lock could not be added"));
        }
        Ok(lock_id)
    }

    /// `POST /api/vault/locks/{id}/used`, in the background: Settings › Keys
    /// shows when each lock was last used. Nothing waits for it.
    fn lock_used(&self, engine: &Arc<Engine>, lock_id: &str) {
        let Some(account) = engine.cloud.clone() else { return };
        let path = format!("/api/vault/locks/{lock_id}/used");
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = account.call("POST", &path, Some(b"{}"), true).await;
            });
        }
    }

    /// `POST /api/app/vault/lock`: the vault key is dropped; the keychain
    /// item stays, so it opens again with Touch ID.
    pub fn lock(&self) -> Value {
        self.drop_open();
        json!({"open": false})
    }

    /// Sign out forgets the KEK too, so nothing left on this Mac could open
    /// the vault without the browser's say.
    pub async fn on_sign_out(&self) {
        let open_id = self.open.lock().unwrap().as_ref().map(|o| o.vault_id.clone());
        let known_id = self.known.lock().unwrap().take().map(|(id, _)| id);
        self.drop_open();
        self.pairings.lock().unwrap().clear();
        // Open or locked: the KEK of the vault tTerm named goes.
        for id in open_id.into_iter().chain(known_id).collect::<BTreeSet<_>>() {
            self.forget_kek(&id).await;
        }
    }

    /// The vault again from tTerm (`vault.changed`: keys or locks changed,
    /// in a browser too): the keys it can sign for follow. A vault gone, or
    /// this Mac's lock taken off, locks it here.
    pub async fn reload(&self, engine: &Arc<Engine>) {
        self.check_account(engine).await;
        let Some((vault_id, lock_id)) = self.open.lock().unwrap().as_ref().map(|o| (o.vault_id.clone(), o.lock_id.clone())) else { return };
        let vault = match self.cloud_get(engine).await {
            Ok(v) => v,
            // tTerm out of reach: as it was.
            Err(_) => return,
        };
        match vault {
            Some(v) if v["id"].as_str() == Some(vault_id.as_str()) => {
                if app_locks(&v).iter().any(|(id, _)| *id == lock_id) {
                    self.refresh(&v);
                } else {
                    self.drop_open();
                    self.forget_kek(&vault_id).await;
                }
            }
            _ => self.drop_open(),
        }
    }

    /// `POST /api/app/vault/recovery`: a new recovery code, the old one no
    /// longer opening the vault. Touch ID first; a locked vault opens with
    /// this Mac's lock under the same check.
    pub async fn new_recovery_code(&self, engine: &Arc<Engine>) -> Done<Value> {
        let (vault_id, vk) = self.vault_key_checked(engine, REASON_RECOVERY).await?;
        let code = crypto::new_recovery_code();
        let salt = crypto::random::<{ crypto::RECOVERY_SALT_LEN }>();
        let normalized = crypto::normalize_code(&code).expect("a code we just made");
        let rkek = crypto::recovery_kek(&normalized, &salt);
        let wrap = crypto::seal(&rkek, vk.as_ref(), &crypto::recovery_aad(&vault_id));
        let body = json!({"recoverySalt": crypto::b64u(&salt), "recoveryWrap": crypto::b64u(&wrap)});
        let answer = self.cloud_call(engine, "PUT", "/api/vault/recovery", Some(&body)).await?;
        if answer.status != 204 && answer.status != 200 {
            return Err(self.from_cloud(&answer, "The recovery code could not be changed"));
        }
        Ok(json!({"recoveryCode": code.as_str()}))
    }

    /// The vault id and key, after one LocalAuthentication check: the vault
    /// open already, or opened now with this Mac's lock under that check.
    async fn vault_key_checked(&self, engine: &Arc<Engine>, reason: &'static str) -> Done<(String, Key)> {
        self.check_account(engine).await;
        let _one = self.one.lock().await;
        if !self.available() {
            return Err(Failed::new(409, "This computer cannot hold the vault."));
        }
        self.authenticate(engine, reason).await?;
        if let Ok(open) = self.vault_key() {
            return Ok(open);
        }
        let Some(vault) = self.cloud_get(engine).await? else {
            return Err(Failed::new(404, "There is no vault yet. Make one first."));
        };
        self.open_with_lock(engine, &vault, false).await?;
        self.vault_key()
    }

    // ---------------------------------------------------------- signing

    /// Signs `data` with the vault's key of `fingerprint`, by `alg`, if the
    /// vault is open and holds it: the raw signature the core asks for over
    /// the socket. None when the vault cannot sign for it (locked, no such
    /// key, the wrong algorithm): the socket then says `vault.unable`.
    ///
    /// Only a login of that key is signed (sshkeys::check_login): anything
    /// else the core might ask is refused, and said so in the log.
    pub fn sign(&self, fingerprint: &str, alg: &str, data: &[u8]) -> Option<Vec<u8>> {
        let open = self.open.lock().unwrap();
        let open = open.as_ref()?;
        let held = open.keys.iter().find(|k| k.fingerprint == fingerprint)?;
        let plaintext = crypto::open(&open.vk, &held.sealed, &crypto::key_aad(&held.key_id))?;
        match crate::sshkeys::sign(&plaintext, alg, data) {
            Ok(sig) => Some(sig),
            Err(crate::sshkeys::SignError::NotLogin(why)) => {
                eprintln!("tterm: the vault did not sign for {fingerprint}: what tTerm asked to sign is not a login with that key ({why:?})");
                None
            }
            Err(e) => {
                eprintln!("tterm: the vault could not sign for {fingerprint}: {e:?}");
                None
            }
        }
    }

    // ---------------------------------------------------------- pairing

    /// `POST /api/app/vault/pairings/{id}/answer`: this Mac makes its X25519
    /// key and posts pubA (once), waits for the browser's pubB, checks it
    /// against the commit, and answers the six digits both screens show. The
    /// vault need not be open for it: only Allow uses the vault key. Asked
    /// again for the same request, it waits again rather than post twice.
    pub async fn pairing_answer(&self, engine: &Arc<Engine>, id: &str) -> Done<Value> {
        self.check_account(engine).await;
        let known = self.pairings.lock().unwrap().get(id).map(|p| (p.pub_a, p.pub_b.clone()));
        let pub_a = match known {
            Some((pub_a, Some(pub_b))) => return Ok(json!({"sas": crypto::sas_of(&pub_a, &pub_b)})),
            Some((pub_a, None)) => pub_a,
            None => {
                let pairer = Pairer::new().ok_or_else(|| Failed::new(500, "A pairing key could not be made."))?;
                let pub_a = pairer.public;
                self.pairings.lock().unwrap().insert(id.to_string(), Pending { pairer: Some(pairer), pub_a, pub_b: None, sealed: None });
                let body = json!({"pubA": crypto::b64u(&pub_a)});
                let posted = self.cloud_call(engine, "POST", &format!("/api/vault/pairings/{id}/answer"), Some(&body)).await;
                let refused = match posted {
                    Ok(a) if a.status == 204 || a.status == 200 => None,
                    Ok(a) => Some(self.from_cloud(&a, "The request could not be answered")),
                    Err(f) => Some(f),
                };
                if let Some(f) = refused {
                    self.pairings.lock().unwrap().remove(id);
                    return Err(f);
                }
                pub_a
            }
        };
        let pub_b = self.await_reveal(engine, id).await?;
        let sas = crypto::sas_of(&pub_a, &pub_b);
        if let Some(p) = self.pairings.lock().unwrap().get_mut(id) {
            p.pub_b = Some(pub_b);
        }
        Ok(json!({"sas": sas}))
    }

    /// `POST /api/app/vault/pairings/{id}/approve`: Touch ID, then the vault
    /// key sealed for the new browser. A locked vault opens with this Mac's
    /// lock under the same check.
    pub async fn pairing_approve(&self, engine: &Arc<Engine>, id: &str) -> Done<Value> {
        let ready = self.pairings.lock().unwrap().get(id).map(|p| p.pub_b.is_some());
        match ready {
            None => return Err(Failed::new(409, "Answer the request first.")),
            Some(false) => return Err(Failed::new(409, "The new browser has not shown its key yet.")),
            Some(true) => {}
        }
        let (_vault_id, vk) = self.vault_key_checked(engine, REASON_APPROVE).await?;
        // Sealed once; a post that did not go through sends the same again.
        let sealed = {
            let mut pairings = self.pairings.lock().unwrap();
            let Some(p) = pairings.get_mut(id) else { return Err(Failed::new(409, "Answer the request first.")) };
            if let Some(sealed) = &p.sealed {
                sealed.clone()
            } else {
                let (Some(pairer), Some(pub_b)) = (p.pairer.take(), p.pub_b.clone()) else {
                    return Err(Failed::new(409, "Answer the request again."));
                };
                let shared = pairer.agree(&pub_b).ok_or_else(|| Failed::new(409, "The new browser's key was not understood."))?;
                let kek = crypto::pair_kek(shared.as_ref(), &p.pub_a, &pub_b);
                let sealed = crypto::seal(&kek, vk.as_ref(), &crypto::pair_aad(id));
                p.sealed = Some(sealed.clone());
                sealed
            }
        };
        let body = json!({"sealed": crypto::b64u(&sealed)});
        let answer = self.cloud_call(engine, "POST", &format!("/api/vault/pairings/{id}/approve"), Some(&body)).await?;
        if answer.status != 204 && answer.status != 200 {
            return Err(self.from_cloud(&answer, "The browser could not be allowed"));
        }
        self.pairings.lock().unwrap().remove(id);
        Ok(json!({"approved": true}))
    }

    /// `POST /api/app/vault/pairings/{id}/deny`: "It's not me".
    pub async fn pairing_deny(&self, engine: &Arc<Engine>, id: &str) -> Done<Value> {
        self.pairings.lock().unwrap().remove(id);
        let answer = self.cloud_call(engine, "POST", &format!("/api/vault/pairings/{id}/deny"), Some(&json!({}))).await?;
        if answer.status != 204 && answer.status != 200 {
            return Err(self.from_cloud(&answer, "The request could not be denied"));
        }
        Ok(json!({"denied": true}))
    }

    /// Waits for the browser to reveal pubB and checks it against the commit
    /// the pairing was opened with. tTerm checks it too; this Mac does not
    /// trust a pubB whose hash is not the commit.
    async fn await_reveal(&self, engine: &Arc<Engine>, id: &str) -> Done<Vec<u8>> {
        let until = tokio::time::Instant::now() + REVEAL_WAIT;
        loop {
            let answer = self.cloud_call(engine, "GET", &format!("/api/vault/pairings/{id}"), None).await?;
            if answer.status != 200 {
                return Err(self.from_cloud(&answer, "The request could not be read"));
            }
            let got = answer.json().unwrap_or(Value::Null);
            if matches!(got["state"].as_str(), Some("denied") | Some("expired") | Some("approved")) {
                self.pairings.lock().unwrap().remove(id);
                return Err(Failed::new(409, "The request is no longer waiting."));
            }
            if let Some(pub_b) = got["pubB"].as_str().and_then(crypto::from_b64u) {
                let commit = got["commit"].as_str().and_then(crypto::from_b64u).unwrap_or_default();
                if !crypto::same(&commit, &crypto::commit_of(&pub_b)) {
                    self.pairings.lock().unwrap().remove(id);
                    return Err(Failed::new(409, "The new browser's key did not match its promise. Deny the request."));
                }
                return Ok(pub_b);
            }
            if tokio::time::Instant::now() >= until {
                return Err(Failed::new(409, "The new browser did not answer in time. It can ask again."));
            }
            tokio::time::sleep(REVEAL_POLL).await;
        }
    }

    // --------------------------------------------------- ssh and move

    /// How ssh is run for the vault: the person's home, or in a debug build
    /// the checks' own from TTERM_SSH_HOME.
    fn ssh(&self) -> crate::ssh::Ssh {
        let (home, own_home) = vault_home();
        crate::ssh::Ssh { program: crate::ssh::ssh_program(), home, own_home }
    }

    /// `GET /api/app/ssh`: the servers this Mac knows and the keys in
    /// `~/.ssh`, for Move to cloud and the strip after `ssh`. Nothing is
    /// connected. Paths are written as `~/…` under the home, the same in
    /// `identityFiles`, `keys[].path` and a host's `key`.
    pub async fn ssh_json(&self, engine: &Arc<Engine>) -> Value {
        let ssh = self.ssh();
        let history = engine.terminals.store.ssh_commands().await;
        // ssh -G runs a process per host: off the async threads.
        let for_hosts = ssh.clone();
        let hosts = tokio::task::spawn_blocking(move || crate::ssh::hosts(&for_hosts, &history)).await.unwrap_or_default();
        // The keys the hosts use (their identity files), and any other
        // private keys in ~/.ssh, so the list is not empty when the config
        // names none.
        let mut wanted: BTreeSet<String> = hosts.iter().flat_map(|h| h.identity_files.iter().map(|f| expand(&ssh.home, f))).collect();
        wanted.extend(private_key_files(&ssh.home.join(".ssh")));
        let keys = read_key_files(&ssh.home, &wanted);
        let movable: HashMap<String, bool> = keys.iter().filter_map(|k| Some((k["path"].as_str()?.to_string(), k["movable"] == true))).collect();
        let hosts: Vec<Value> = hosts
            .iter()
            .map(|h| {
                let mut j = h.to_json();
                let files: Vec<String> = h.identity_files.iter().map(|f| shorten(&ssh.home, &expand(&ssh.home, f))).collect();
                // The key it signs in with, as far as this Mac can tell: its
                // first identity file that is here and can be moved.
                let key = files.iter().find(|f| movable.get(*f) == Some(&true)).cloned();
                j["identityFiles"] = json!(files);
                j["key"] = json!(key);
                j
            })
            .collect();
        json!({"hosts": hosts, "keys": keys})
    }

    /// `POST /api/app/ssh/try`: whether `ssh <alias> true` gets in. A key
    /// with a passphrase (given in `passphrase`) comes in through the
    /// askpass helper.
    pub async fn ssh_try(&self, engine: &Arc<Engine>, alias: &str, passphrase: Option<&str>) -> Done<Value> {
        let ssh = self.ssh();
        let helper = self.askpass(engine, passphrase)?;
        let attempt = crate::ssh::run(&ssh, alias, &[], &["true"], None, askpass_pair(&helper, passphrase)).await;
        Ok(json!({"ok": attempt.ok, "error": attempt.error}))
    }

    /// `POST /api/app/move`: for each server in order, the way in the request
    /// asks; nothing is saved for one that fails. Only `key` servers need the
    /// vault open; their keys are the ticked ones (`keys`), each uploaded
    /// once (none that the vault has already), after a login with it.
    pub async fn move_to_cloud(&self, engine: &Arc<Engine>, project: &str, servers: &[(String, String)], keys: &[(String, Option<String>)]) -> Done<Value> {
        self.check_account(engine).await;
        let ssh = self.ssh();
        let ticked: HashMap<String, Option<String>> = keys.iter().map(|(p, ph)| (expand(&ssh.home, p), ph.clone().filter(|p| !p.is_empty()))).collect();
        let mut work = Moving { ticked, in_vault: None, uploaded: HashMap::new(), saved_with: BTreeSet::new() };
        let mut results = Vec::new();
        for (alias, method) in servers {
            let one = self.move_one(engine, &ssh, project, alias, method, &mut work).await;
            results.push(match one {
                Ok(machine) => json!({"alias": alias, "ok": true, "machine": machine}),
                Err(why) => json!({"alias": alias, "ok": false, "error": why}),
            });
        }
        // A key uploaded for servers that all failed goes again: nothing is
        // saved for a server that fails.
        for (path, (key_id, _)) in &work.uploaded {
            if !work.saved_with.contains(key_id) {
                let _ = self.cloud_call(engine, "DELETE", &format!("/api/vault/keys/{key_id}"), None).await;
                eprintln!("tterm: move: {} went out of the vault again, its servers did not move", shorten(&ssh.home, path));
            }
        }
        // The vault's keys as tTerm has them now: what it can sign for.
        if !work.uploaded.is_empty() {
            if let Ok(Some(vault)) = self.cloud_get(engine).await {
                self.refresh(&vault);
            }
        }
        Ok(json!({"results": results}))
    }

    /// One server of a move, start to finish; Err is the reason the page
    /// shows for it, and nothing was saved.
    async fn move_one(&self, engine: &Arc<Engine>, ssh: &crate::ssh::Ssh, project: &str, alias: &str, method: &str, work: &mut Moving) -> Result<Value, String> {
        let settings = {
            let (ssh, alias) = (ssh.clone(), alias.to_string());
            tokio::task::spawn_blocking(move || crate::ssh::effective(&ssh, &alias)).await.map_err(|e| e.to_string())?
        };
        let hostname = settings.one("hostname").unwrap_or_else(|| alias.to_string());
        let port: u16 = settings.one("port").and_then(|p| p.parse().ok()).unwrap_or(22);
        let login = settings.one("user").unwrap_or_default();
        let known = std::fs::read_to_string(ssh.known_hosts()).unwrap_or_default();
        let host_keys = crate::ssh::host_keys_for(&known, &hostname, port);
        if host_keys.is_empty() && method != "mac" {
            return Err("This Mac has no host key for this server in known_hosts. Open it from this Mac once, then move it.".into());
        }
        let mut body = json!({
            "project": project,
            "name": alias,
            "host": hostname,
            "port": port,
            "login": login,
            "hostKeys": host_keys,
            "method": method,
        });
        let mut used_key = None;
        let mut added_line = None;
        match method {
            "key" => {
                if let Some(j) = self.jump_block(ssh, &settings, &known) {
                    body["jump"] = j;
                }
                let key_id = self.key_for(engine, ssh, alias, &settings, work).await?;
                body["keyId"] = json!(key_id);
                used_key = Some(key_id);
            }
            "cert" => {
                if let Some(j) = self.jump_block(ssh, &settings, &known) {
                    body["jump"] = j;
                }
                let (principal, line) = self.ca_line(engine, project, alias).await?;
                let script = crate::ssh::add_line_script(&line);
                let phrase = self.phrase_for(ssh, &settings, work);
                let helper = self.askpass(engine, phrase.as_deref()).map_err(|f| f.message)?;
                let attempt = crate::ssh::run(ssh, alias, &[], &["sh", "-s"], Some(&script), askpass_pair(&helper, phrase.as_deref())).await;
                if !attempt.ok {
                    return Err(format!("This Mac could not sign in to add tTerm's line: {}", attempt.error.unwrap_or_default()));
                }
                let added = attempt.out.lines().any(|l| l.trim() == crate::ssh::LINE_ADDED);
                if !added && !attempt.out.lines().any(|l| l.trim() == crate::ssh::LINE_PRESENT) {
                    return Err("The server did not say it took tTerm's line (is its shell sh?). Nothing was saved.".into());
                }
                body["principal"] = json!(principal);
                // Taken off again if tTerm does not save the server; a line
                // that was there before is left alone.
                if added {
                    added_line = Some((line, phrase));
                }
            }
            "mac" => {
                // This Mac, as a machine of the account: what tTerm opens the
                // terminal on, to run ssh there.
                let account = engine.cloud.clone().ok_or("Sign in to tTerm first.")?;
                if account.here().is_none() && !account.offline() {
                    // Asked as the page's state asks it, a while at most.
                    let _ = tokio::time::timeout(Duration::from_secs(15), account.ensure_here(engine)).await;
                }
                let here = account.here().ok_or("This Mac is not one of your account's machines yet. Wait until tTerm shows it in Personal, then move the server.")?;
                body["via"] = json!(here.id.to_string());
                body["target"] = json!(alias);
            }
            other => return Err(format!("There is no way in called {other}.")),
        }
        let saved = self.cloud_call(engine, "POST", "/api/machines/own", Some(&body)).await;
        let refused = match saved {
            Ok(answer) if answer.status == 201 || answer.status == 200 => {
                if let Some(key_id) = used_key {
                    work.saved_with.insert(key_id);
                }
                return Ok(answer.json().unwrap_or(Value::Null)["machine"].clone());
            }
            Ok(answer) => self.from_cloud(&answer, "tTerm did not add the server").message,
            Err(f) => f.message,
        };
        // Not saved: tTerm's line goes off the server again, best we can.
        if let Some((line, phrase)) = added_line {
            let helper = self.askpass(engine, phrase.as_deref()).ok().flatten();
            let script = crate::ssh::remove_line_script(&line);
            let _ = crate::ssh::run(ssh, alias, &[], &["sh", "-s"], Some(&script), askpass_pair(&helper, phrase.as_deref())).await;
        }
        Err(refused)
    }

    /// The vault key a `key` server is moved with: of its identity files, the
    /// first ticked one (`keys` of the request), else one the vault has
    /// already. Before anything is saved this Mac signs in with that key
    /// alone, as the core takes the app's word for it; then it is sealed and
    /// uploaded, once per move, unless the vault has it.
    async fn key_for(&self, engine: &Arc<Engine>, ssh: &crate::ssh::Ssh, alias: &str, settings: &crate::ssh::Settings, work: &mut Moving) -> Result<String, String> {
        let (_vault_id, vk) = self.vault_key().map_err(|_| "Open your vault first.".to_string())?;
        let files = existing_identity_files(&ssh.home, settings);
        if files.is_empty() {
            return Err("No key of this server is in ~/.ssh. Move it through this Mac instead.".into());
        }
        let in_vault = self.vault_fingerprints(engine, work).await?;
        let mut chosen = files.iter().find(|f| work.ticked.contains_key(*f)).cloned();
        if chosen.is_none() {
            chosen = files.iter().find(|f| peek_file(f).map(|p| in_vault.contains_key(&p.fingerprint)).unwrap_or(false)).cloned();
        }
        let Some(path) = chosen else {
            return Err(format!("Its key, {}, is not ticked to go to your vault.", shorten(&ssh.home, &files[0])));
        };
        let shown = shorten(&ssh.home, &path);
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{shown} could not be read: {e}"))?;
        let peek = crate::sshkeys::peek(&text).map_err(|e| format!("{shown}: {}", e.message()))?;
        if let Some(why) = peek.why {
            return Err(format!("{shown} cannot be moved ({}): move this server through this Mac.", why.word()));
        }
        let phrase = work.ticked.get(&path).cloned().flatten();
        // The key itself first: a wrong passphrase is said as such, not as
        // the server's "Permission denied" (the app's checks, 01.11).
        let key = crate::sshkeys::read(&text, phrase.as_deref()).map_err(|e| format!("{shown}: {}", e.message()))?;
        // The login, with this key alone (and the agent's copy of it).
        let helper = self.askpass(engine, phrase.as_deref()).map_err(|f| f.message)?;
        let extra = ["-v", "-o", "FingerprintHash=sha256", "-o", "IdentitiesOnly=yes", "-i", path.as_str()];
        let attempt = crate::ssh::run(ssh, alias, &extra, &["true"], None, askpass_pair(&helper, phrase.as_deref())).await;
        if !attempt.ok {
            return Err(format!("This Mac could not sign in with {shown}: {}", attempt.error.unwrap_or_default()));
        }
        if let Some(fp) = attempt.accepted.as_deref() {
            if fp != peek.fingerprint {
                return Err(format!("The server let this Mac in with another key ({fp}), not {shown}."));
            }
        }
        // Already in the vault (moved before, or added in a browser).
        if let Some(id) = in_vault.get(&peek.fingerprint) {
            return Ok(id.clone());
        }
        if let Some((id, _)) = work.uploaded.get(&path) {
            return Ok(id.clone());
        }
        let key_id = Uuid::new_v4().to_string();
        let sealed = crypto::seal(&vk, key.plaintext.as_bytes(), &crypto::key_aad(&key_id));
        let body = json!({
            "id": key_id,
            "name": key_file_name(&path),
            "type": key.kind,
            "publicKey": key.public_openssh.trim(),
            "fingerprint": key.fingerprint,
            "sealed": crypto::b64u(&sealed),
            "source": "mac",
            "sourceLabel": self.label,
        });
        let answer = self.cloud_call(engine, "POST", "/api/vault/keys", Some(&body)).await.map_err(|f| f.message)?;
        if answer.status != 201 && answer.status != 200 {
            return Err(self.from_cloud(&answer, "The key could not be saved in your vault").message);
        }
        work.uploaded.insert(path, (key_id.clone(), key.fingerprint));
        Ok(key_id)
    }

    /// The fingerprints of the keys the vault has, with their ids: read from
    /// tTerm once per move.
    async fn vault_fingerprints(&self, engine: &Arc<Engine>, work: &mut Moving) -> Result<HashMap<String, String>, String> {
        if let Some(known) = &work.in_vault {
            let mut all = known.clone();
            for (id, fp) in work.uploaded.values() {
                all.insert(fp.clone(), id.clone());
            }
            return Ok(all);
        }
        let vault = self.cloud_get(engine).await.map_err(|f| f.message)?;
        let known: HashMap<String, String> = vault
            .as_ref()
            .and_then(|v| v["keys"].as_array())
            .into_iter()
            .flatten()
            .filter_map(|k| Some((k["fingerprint"].as_str()?.to_string(), k["id"].as_str()?.to_string())))
            .collect();
        work.in_vault = Some(known.clone());
        Ok(known)
    }

    /// The jump host block for a server with a `ProxyJump`, resolved with
    /// `ssh -G` of the jump alias and its host keys; None without one.
    fn jump_block(&self, ssh: &crate::ssh::Ssh, settings: &crate::ssh::Settings, known: &str) -> Option<Value> {
        let jump = settings.one("proxyjump").filter(|p| !p.eq_ignore_ascii_case("none"))?;
        // Just the first hop if several are chained; its own alias may carry
        // user@host:port.
        let first = jump.split(',').next()?.trim().trim_start_matches("ssh://");
        let (login, rest) = first.rsplit_once('@').map(|(u, h)| (u.to_string(), h)).unwrap_or((String::new(), first));
        let (host_alias, port_given) = match rest.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h.trim_matches(['[', ']']), p.parse::<u16>().ok()),
            _ => (rest, None),
        };
        let js = crate::ssh::effective(ssh, host_alias);
        let host = js.one("hostname").unwrap_or_else(|| host_alias.to_string());
        let port: u16 = port_given.or_else(|| js.one("port").and_then(|p| p.parse().ok())).unwrap_or(22);
        let login = if login.is_empty() { js.one("user").unwrap_or_default() } else { login };
        let host_keys = crate::ssh::host_keys_for(known, &host, port);
        Some(json!({"host": host, "port": port, "login": login, "hostKeys": host_keys}))
    }

    /// The passphrase given for a server's key, if one of its identity files
    /// was ticked with one: for Let tTerm in's login.
    fn phrase_for(&self, ssh: &crate::ssh::Ssh, settings: &crate::ssh::Settings, work: &Moving) -> Option<String> {
        existing_identity_files(&ssh.home, settings).into_iter().find_map(|f| work.ticked.get(&f).cloned().flatten())
    }

    /// `POST /api/machines/own/line`: the CA line and its principal the app
    /// is to add on the server.
    async fn ca_line(&self, engine: &Arc<Engine>, project: &str, name: &str) -> Result<(String, String), String> {
        let body = json!({"project": project, "name": name});
        let answer = self.cloud_call(engine, "POST", "/api/machines/own/line", Some(&body)).await.map_err(|f| f.message)?;
        if answer.status != 200 && answer.status != 201 {
            return Err(self.from_cloud(&answer, "tTerm did not give its line").message);
        }
        let got = answer.json().unwrap_or(Value::Null);
        let (Some(principal), Some(line)) = (got["principal"].as_str(), got["line"].as_str()) else {
            return Err("tTerm's line was not understood.".into());
        };
        if line.contains(['\n', '\r', '\'']) {
            return Err("tTerm's line was not understood.".into());
        }
        Ok((principal.to_string(), line.to_string()))
    }

    /// The askpass helper's path, written once in the app's folder, when a
    /// passphrase was given; None otherwise.
    fn askpass(&self, engine: &Arc<Engine>, passphrase: Option<&str>) -> Done<Option<PathBuf>> {
        if passphrase.filter(|p| !p.is_empty()).is_none() {
            return Ok(None);
        }
        crate::ssh::askpass_helper(&engine.data_dir).map(Some).map_err(|e| Failed::new(500, format!("The passphrase helper could not be written: {e}")))
    }

    // ------------------------------------------------------- the cloud

    /// `GET /api/vault` → the vault object, or None when there is none.
    async fn cloud_get(&self, engine: &Arc<Engine>) -> Done<Option<Value>> {
        self.cloud_get_as(engine, false).await
    }

    async fn cloud_get_as(&self, engine: &Arc<Engine>, background: bool) -> Done<Option<Value>> {
        let answer = self.cloud_call_as(engine, "GET", "/api/vault", None, background).await?;
        if answer.status != 200 {
            return Err(self.from_cloud(&answer, "The vault could not be read from tTerm"));
        }
        let got = answer.json().unwrap_or(Value::Null);
        match got.get("vault") {
            Some(Value::Null) | None => Ok(None),
            Some(v) => {
                if let Some(id) = v["id"].as_str() {
                    self.know(engine, id);
                }
                Ok(Some(v.clone()))
            }
        }
    }

    /// A call to tTerm in the app's session, or a failure the page shows.
    async fn cloud_call(&self, engine: &Arc<Engine>, method: &str, path: &str, body: Option<&Value>) -> Done<Answer> {
        self.cloud_call_as(engine, method, path, body, false).await
    }

    async fn cloud_call_as(&self, engine: &Arc<Engine>, method: &str, path: &str, body: Option<&Value>, background: bool) -> Done<Answer> {
        let Some(account) = engine.cloud.clone() else {
            return Err(Failed::new(409, "Sign in to tTerm first."));
        };
        let raw = body.map(|b| b.to_string().into_bytes());
        match account.call(method, path, raw.as_deref(), background).await {
            Ok(answer) => Ok(answer),
            Err(Trouble::SignedOut) => {
                // The account is gone: so is the vault opened in it.
                Box::pin(self.check_account(engine)).await;
                Err(Failed { status: 401, message: SIGNED_OUT.into(), signed_out: true })
            }
            Err(Trouble::Offline) => Err(Failed::new(503, crate::cloud_api::OFFLINE)),
        }
    }

    /// tTerm's refusal in a sentence: its own words when it gave them.
    fn from_cloud(&self, answer: &Answer, what: &str) -> Failed {
        let why = answer.error().unwrap_or_else(|| format!("tTerm answered {}.", answer.status));
        Failed::new(answer.status.max(400), format!("{what}: {why}"))
    }

    // --------------------------------------------------------- the host

    // The keeper waits for the person (Touch ID; the keychain asking for the
    // Mac's password for a new version of the app): off the async threads.

    /// The keeper's `f`, on a thread that may wait.
    async fn with_host<T: Send + 'static>(&self, f: impl FnOnce(&dyn Keeper) -> T + Send + 'static) -> Result<T, String> {
        let host = self.host.clone();
        tokio::task::spawn_blocking(move || f(host.as_ref())).await.map_err(|e| e.to_string())
    }

    /// LocalAuthentication: Touch ID or the Mac's password, asked with the
    /// words of `reason` (a key of REASON_*) in the app's language. Not
    /// passed (the person cancelled, or it failed) is 403, not the session's
    /// 401.
    async fn authenticate(&self, engine: &Arc<Engine>, reason: &'static str) -> Done<()> {
        let reason = crate::say::say(engine.language_now(), reason);
        self.with_host(move |h| h.authenticate(&reason))
            .await
            .and_then(|r| r)
            .map_err(|e| Failed::new(403, format!("Touch ID or your Mac's password did not go through ({e}). The vault stays as it was.")))
    }

    async fn save_kek(&self, vault_id: &str, kek: &[u8]) -> Done<()> {
        let (vault_id, kek) = (vault_id.to_string(), Zeroizing::new(kek.to_vec()));
        self.with_host(move |h| h.save_kek(&vault_id, &kek))
            .await
            .and_then(|r| r)
            .map_err(|e| Failed::new(500, format!("The vault key could not be kept in the keychain: {e}")))
    }

    async fn load_kek(&self, vault_id: &str) -> Done<Option<Zeroizing<Vec<u8>>>> {
        let vault_id = vault_id.to_string();
        self.with_host(move |h| h.load_kek(&vault_id).map(|k| k.map(Zeroizing::new)))
            .await
            .and_then(|r| r)
            .map_err(|e| Failed::new(500, format!("The keychain could not be read: {e}")))
    }

    /// The KEK out of the keychain, as far as it goes: nothing waits on it.
    async fn forget_kek(&self, vault_id: &str) {
        let vault_id = vault_id.to_string();
        if let Ok(Err(e)) = self.with_host(move |h| h.delete_kek(&vault_id)).await {
            eprintln!("tterm: the vault's keychain item could not be taken out: {e}");
        }
    }

    // --------------------------------------------------------- the state

    /// The vault id and key while open, or a refusal.
    fn vault_key(&self) -> Done<(String, Key)> {
        let open = self.open.lock().unwrap();
        match open.as_ref() {
            Some(o) => Ok((o.vault_id.clone(), Zeroizing::new(*o.vk))),
            None => Err(Failed::new(409, "Open the vault first.")),
        }
    }

    fn hold(&self, engine: &Arc<Engine>, vault_id: String, lock_id: String, vk: Key, keys: Vec<Held>) {
        let epoch = Self::epoch(engine).unwrap_or_default();
        self.know(engine, &vault_id);
        self.set_can(&keys);
        *self.open.lock().unwrap() = Some(Open { vault_id, lock_id, vk, keys, epoch });
    }

    fn drop_open(&self) {
        *self.open.lock().unwrap() = None;
        self.can.send_replace(Vec::new());
    }

    /// The vault's keys read again from tTerm's vault object (after a move,
    /// or `vault.changed`): what it can sign for.
    pub fn refresh(&self, vault: &Value) {
        let mut open = self.open.lock().unwrap();
        if let Some(o) = open.as_mut() {
            o.keys = read_keys(vault, &o.vk);
            self.set_can(&o.keys);
        }
    }
}

/// What one move keeps from server to server: the ticked keys with their
/// passphrases, the vault's keys as tTerm said them, the keys uploaded in
/// this move (by path: id and fingerprint), and those a saved server uses.
struct Moving {
    ticked: HashMap<String, Option<String>>,
    in_vault: Option<HashMap<String, String>>,
    uploaded: HashMap<String, (String, String)>,
    saved_with: BTreeSet<String>,
}

/// The person's home, where `~/.ssh` is, and whether it is their own. A
/// debug build (the checks) takes another from TTERM_SSH_HOME, so the
/// discovery and the move read a temp `~` without touching the real one; a
/// release build always uses the home.
fn vault_home() -> (PathBuf, bool) {
    #[cfg(debug_assertions)]
    if let Some(h) = std::env::var_os("TTERM_SSH_HOME") {
        return (h.into(), false);
    }
    (crate::pty::home_dir(), true)
}

/// `~/path` and `$HOME/path` to a full path under `home`; anything else is
/// left as it is.
fn expand(home: &Path, path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("$HOME/")) {
        return home.join(rest).to_string_lossy().into_owned();
    }
    if path == "~" {
        return home.to_string_lossy().into_owned();
    }
    path.to_string()
}

/// A path shown as `~/…` when it is under home.
fn shorten(home: &Path, path: &str) -> String {
    match Path::new(path).strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.to_string(),
    }
}

/// A server's identity files (`ssh -G`'s order) that are files here.
fn existing_identity_files(home: &Path, settings: &crate::ssh::Settings) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for f in settings.many("identityfile") {
        let full = expand(home, &f);
        if Path::new(&full).is_file() && !out.contains(&full) {
            out.push(full);
        }
    }
    out
}

/// What a key file is, read without its passphrase.
fn peek_file(path: &str) -> Option<crate::sshkeys::Peek> {
    let text = std::fs::read_to_string(path).ok()?;
    crate::sshkeys::peek(&text).ok()
}

/// The askpass argument for `ssh::run`: the helper and the passphrase, when
/// both are there.
fn askpass_pair<'a>(helper: &'a Option<PathBuf>, passphrase: Option<&'a str>) -> Option<(&'a Path, &'a str)> {
    match (helper.as_deref(), passphrase.filter(|p| !p.is_empty())) {
        (Some(h), Some(p)) => Some((h, p)),
        _ => None,
    }
}

/// The name a key is saved under: its file name.
fn key_file_name(path: &str) -> String {
    Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "key".into())
}

/// The keys at `paths`, each listed with its type, fingerprint and whether
/// it can be moved, for `GET /api/app/ssh`. A file that is no private key
/// this reads (a public key, an old PEM key) is left out.
fn read_key_files(home: &Path, paths: &BTreeSet<String>) -> Vec<Value> {
    let mut out = Vec::new();
    for path in paths {
        let p = Path::new(path);
        if !p.is_file() || p.metadata().map(|m| m.len() > 64 * 1024).unwrap_or(true) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(p) else { continue };
        let Ok(peek) = crate::sshkeys::peek(&text) else { continue };
        // An encrypted OpenSSH key keeps its comment inside: the .pub has it.
        let comment = if peek.comment.is_empty() { pub_comment(path) } else { peek.comment.clone() };
        out.push(json!({
            "path": shorten(home, path),
            "name": key_file_name(path),
            "type": peek.kind,
            "fingerprint": peek.fingerprint,
            "comment": comment,
            "encrypted": peek.encrypted,
            "movable": peek.why.is_none(),
            "why": peek.why.map(|w| w.word()),
        }));
    }
    out
}

/// The comment of a key's `.pub`, when there is one.
fn pub_comment(path: &str) -> String {
    let text = std::fs::read_to_string(format!("{path}.pub")).unwrap_or_default();
    text.split_whitespace().skip(2).collect::<Vec<_>>().join(" ")
}

/// The private-key files in `~/.ssh`, the known config files left out.
fn private_key_files(ssh_dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(ssh_dir) else { return out };
    const SKIP: [&str; 5] = ["config", "known_hosts", "authorized_keys", "environment", "rc"];
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".pub") || name.starts_with('.') || SKIP.contains(&name.as_str()) || name.starts_with("known_hosts") || name.starts_with("authorized_keys") {
            continue;
        }
        if entry.path().is_file() {
            out.push(entry.path().to_string_lossy().into_owned());
        }
    }
    out
}

/// The app locks of a vault object, as (lock id, wrap), this device's first.
fn app_locks(vault: &Value) -> Vec<(String, Vec<u8>)> {
    let Some(locks) = vault["locks"].as_array() else { return Vec::new() };
    let mut app: Vec<&Value> = locks.iter().filter(|l| l["kind"] == "app").collect();
    app.sort_by_key(|l| l["thisDevice"] != true);
    app.iter().filter_map(|l| Some((l["id"].as_str()?.to_string(), crypto::from_b64u(l["wrap"].as_str()?)?))).collect()
}

/// The keys the vault holds, from tTerm's vault object: those whose sealed
/// box opens with the vault key (a key sealed for another vault is left out
/// rather than taken for one this can sign), and whose fingerprint is the
/// key's own.
fn read_keys(vault: &Value, vk: &Key) -> Vec<Held> {
    let Some(keys) = vault["keys"].as_array() else { return Vec::new() };
    let mut held = Vec::new();
    for k in keys {
        let (Some(id), Some(fp), Some(sealed)) = (k["id"].as_str(), k["fingerprint"].as_str(), k["sealed"].as_str().and_then(crypto::from_b64u)) else {
            continue;
        };
        let Some(plaintext) = crypto::open(vk, &sealed, &crypto::key_aad(id)) else { continue };
        // Listed under the fingerprint of the key itself: one tTerm lists
        // under another key's is not announced as that key.
        if crate::sshkeys::fingerprint(&plaintext).as_deref() != Some(fp) {
            eprintln!("tterm: a key of the vault is not the key tTerm lists it as ({fp}): left out");
            continue;
        }
        held.push(Held { fingerprint: fp.to_string(), sealed, key_id: id.to_string() });
    }
    held
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_app_locks_this_devices_first() {
        let w = |n: u8| crypto::b64u(&[n; 60]);
        let vault = json!({"locks": [
            {"id": "l1", "kind": "passkey", "wrap": w(1)},
            {"id": "l2", "kind": "app", "wrap": w(2), "thisDevice": false},
            {"id": "l3", "kind": "app", "wrap": w(3), "thisDevice": true},
        ]});
        let ids: Vec<String> = app_locks(&vault).into_iter().map(|(id, _)| id).collect();
        assert_eq!(ids, ["l3", "l2"], "this device's first, no passkey lock");
        assert!(app_locks(&json!({"locks": [{"id": "l1", "kind": "passkey", "wrap": w(1)}]})).is_empty());
        assert!(app_locks(&json!({"locks": [{"id": "l2", "kind": "app"}]})).is_empty(), "no wrap, no lock to open");
    }

    #[test]
    fn the_touch_id_reasons_are_words_of_the_app() {
        for key in [REASON_OPEN, REASON_CREATE, REASON_LOCK, REASON_APPROVE, REASON_RECOVERY] {
            for lang in crate::say::LANGUAGES {
                let said = crate::say::say(lang, key);
                assert!(!said.is_empty() && said != key, "{lang}: {key} is not in engine/i18n");
                assert!(!said.ends_with('.'), "{lang}: {key} goes on after \"tTerm is trying to\"");
            }
        }
        assert_eq!(crate::say::say("en", REASON_OPEN), "open your tTerm vault");
    }

    #[test]
    fn paths_as_the_page_reads_them() {
        let home = Path::new("/Users/denis");
        assert_eq!(expand(home, "~/.ssh/id_ed25519"), "/Users/denis/.ssh/id_ed25519");
        assert_eq!(shorten(home, "/Users/denis/.ssh/id_ed25519"), "~/.ssh/id_ed25519");
        assert_eq!(shorten(home, "/opt/keys/aws.pem"), "/opt/keys/aws.pem");
        assert_eq!(shorten(home, &expand(home, "~/.ssh/work")), "~/.ssh/work");
    }
}
