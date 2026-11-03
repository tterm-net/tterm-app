//! The vault's crypto against the shared vectors (vault-vectors.json), which
//! the page (WebCrypto) must reproduce too: the box format, the HKDF infos,
//! the vault password's NFC, Argon2id and keys, the recovery code's
//! normalization, a pairing's commit, its six digits and its KEK. The same
//! bytes on both sides are what lets a browser open what the app sealed, and
//! the core check a signature the device made.

#![cfg(feature = "cloud")]

use serde_json::Value;
use tterm_engine::crypto;

fn vectors() -> Value {
    let text = include_str!("vault-vectors.json");
    serde_json::from_str(text).expect("the vectors are JSON")
}

fn b(v: &Value, path: &[&str]) -> Vec<u8> {
    let mut at = v;
    for p in path {
        at = &at[p];
    }
    crypto::from_b64u(at.as_str().expect("a base64url string")).expect("base64url")
}

fn s<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut at = v;
    for p in path {
        at = &at[p];
    }
    at.as_str().expect("a string")
}

fn key32(v: &Value, path: &[&str]) -> [u8; 32] {
    <[u8; 32]>::try_from(b(v, path).as_slice()).expect("32 bytes")
}

/// A box of the vault, sealed with the vectors' own nonce, is their bytes
/// exactly, and opens back to the plaintext.
#[test]
fn a_key_box_matches_the_vector() {
    let v = vectors();
    let vk = key32(&v, &["vk"]);
    let nonce = <[u8; 12]>::try_from(b(&v, &["nonce"]).as_slice()).unwrap();
    let plain = s(&v, &["key", "plaintext"]).as_bytes();
    let aad = s(&v, &["key", "aad"]);
    assert_eq!(aad, crypto::key_aad(s(&v, &["key", "id"])));
    let sealed = crypto::seal_with(&vk, nonce, plain, aad);
    assert_eq!(crypto::b64u(&sealed), s(&v, &["key", "sealed"]), "the box is the vector's bytes");
    let opened = crypto::open(&vk, &sealed, aad).expect("opens");
    assert_eq!(opened.as_slice(), plain);
    // The real bytes of the vector open the same way.
    assert_eq!(crypto::open(&vk, &b(&v, &["key", "sealed"]), aad).unwrap().as_slice(), plain);
}

/// A passkey lock's KEK is HKDF of the PRF output, and its wrap holds the
/// vault key.
#[test]
fn the_passkey_kek_and_wrap_match() {
    let v = vectors();
    let prf = b(&v, &["prf_lock", "prf_output"]);
    let kek = crypto::prf_kek(&prf);
    assert_eq!(crypto::b64u(kek.as_ref()), s(&v, &["prf_lock", "kek"]), "HKDF with 32 zero bytes and the PRF info");
    assert_eq!(s(&v, &["prf_lock", "info"]), crypto::PRF_INFO);
    let aad = s(&v, &["prf_lock", "aad"]);
    assert_eq!(aad, crypto::lock_aad(s(&v, &["prf_lock", "lock_id"])));
    let vk = crypto::open_key(&*kek, &b(&v, &["prf_lock", "wrap"]), aad).expect("the vault key");
    assert_eq!(vk.as_ref(), &key32(&v, &["vk"]), "the wrap holds the vault key");
}

/// The vault password (0.8.0), both cases of the vectors: "small" (fast
/// settings, and a password with "e" and a combining accent that NFC makes
/// "é", and Cyrillic) and "default" (the settings a password is set with).
/// The NFC text and its UTF-8, Argon2id's output, the KEK and the proof,
/// the core's SHA-256 of the proof, and the wrap of the vault key are the
/// vectors' bytes, which two other Argon2 implementations made.
#[test]
fn the_vault_password_matches_the_vectors() {
    let v = vectors();
    let vk = key32(&v, &["vk"]);
    let nonce = <[u8; 12]>::try_from(b(&v, &["nonce"]).as_slice()).unwrap();
    for case in ["small", "default"] {
        let c = &v["password"][case];
        let typed = s(c, &["password"]);
        let nfc = crypto::password_text(typed).unwrap_or_else(|n| panic!("{case}: a password of {n} code points"));
        assert_eq!(nfc.as_str(), s(c, &["nfc"]), "{case}: NFC");
        assert_eq!(crypto::b64u(nfc.as_bytes()), s(c, &["utf8"]), "{case}: its UTF-8");
        let kdf = &c["kdf"];
        assert_eq!(kdf["alg"], "argon2id");
        let n = |k: &str| u32::try_from(kdf[k].as_u64().unwrap()).unwrap();
        let kdf = crypto::Kdf { m: n("m"), t: n("t"), p: n("p") };
        let salt = b(c, &["salt"]);
        assert_eq!(salt.len(), crypto::PASSWORD_SALT_LEN);
        let out = crypto::argon2id(nfc.as_bytes(), &salt, &kdf).expect("Argon2id");
        assert_eq!(crypto::b64u(out.as_ref()), s(c, &["argon2"]), "{case}: Argon2id");
        assert_eq!(s(c, &["kek_info"]), crypto::PASSWORD_KEK_INFO);
        assert_eq!(s(c, &["auth_info"]), crypto::PASSWORD_AUTH_INFO);
        let keys = crypto::password_keys(&nfc, &salt, &kdf).expect("the keys");
        assert_eq!(crypto::b64u(keys.kek.as_ref()), s(c, &["kek"]), "{case}: the KEK");
        assert_eq!(crypto::b64u(keys.auth.as_ref()), s(c, &["auth"]), "{case}: the proof");
        assert_eq!(crypto::b64u(&crypto::password_check(keys.auth.as_ref())), s(c, &["check"]), "{case}: what the core keeps");
        let aad = s(c, &["aad"]);
        assert_eq!(aad, crypto::password_aad(s(c, &["vault_id"])));
        assert_eq!(crypto::b64u(&crypto::seal_with(&keys.kek, nonce, &vk, aad)), s(c, &["wrap"]), "{case}: the wrap");
        let opened = crypto::open_key(&keys.kek, &b(c, &["wrap"]), aad).expect("the wrap opens");
        assert_eq!(opened.as_ref(), &vk, "{case}: it holds the vault key");
        // The same password typed with the accent at once makes the same keys.
        let typed_at_once = crypto::password_text(s(c, &["nfc"])).unwrap();
        assert_eq!(crypto::password_keys(&typed_at_once, &salt, &kdf).unwrap().kek.as_ref(), keys.kek.as_ref());
    }
    // Only the real settings are a vault password's; the small ones are the
    // checks' alone.
    assert_eq!(v["password"]["default"]["kdf"], serde_json::json!({"alg": "argon2id", "m": crypto::Kdf::NEW.m, "t": crypto::Kdf::NEW.t, "p": crypto::Kdf::NEW.p}));
    assert_ne!(s(&v, &["password", "small", "password"]), s(&v, &["password", "small", "nfc"]), "the small one is typed with a combining accent");
}

/// The recovery code normalizes to the vector's text, its KEK is HKDF of
/// that with the recovery salt, and the wrap holds the vault key.
#[test]
fn the_recovery_code_kek_and_wrap_match() {
    let v = vectors();
    let normalized = crypto::normalize_code(s(&v, &["recovery", "code"])).expect("a code");
    assert_eq!(normalized.as_str(), s(&v, &["recovery", "normalized"]));
    let salt = b(&v, &["recovery", "salt"]);
    let kek = crypto::recovery_kek(&normalized, &salt);
    assert_eq!(crypto::b64u(kek.as_ref()), s(&v, &["recovery", "kek"]));
    assert_eq!(s(&v, &["recovery", "info"]), crypto::RECOVERY_INFO);
    let aad = s(&v, &["recovery", "aad"]);
    assert_eq!(aad, crypto::recovery_aad(s(&v, &["recovery", "vault_id"])));
    let vk = crypto::open_key(&*kek, &b(&v, &["recovery", "wrap"]), aad).expect("the vault key");
    assert_eq!(vk.as_ref(), &key32(&v, &["vk"]));
}

/// A pairing's commit, six digits and KEK are the vectors', and the sealed
/// vault key opens with the KEK.
#[test]
fn a_pairing_matches_the_vectors() {
    let v = vectors();
    let pub_a = b(&v, &["pairing", "pubA"]);
    let pub_b = b(&v, &["pairing", "pubB"]);
    assert_eq!(crypto::b64u(&crypto::commit_of(&pub_b)), s(&v, &["pairing", "commit"]));
    assert_eq!(crypto::sas_of(&pub_a, &pub_b), s(&v, &["pairing", "sas"]));
    let shared = b(&v, &["pairing", "shared"]);
    let kek = crypto::pair_kek(&shared, &pub_a, &pub_b);
    assert_eq!(crypto::b64u(kek.as_ref()), s(&v, &["pairing", "kek"]));
    let aad = s(&v, &["pairing", "aad"]);
    assert_eq!(aad, crypto::pair_aad(s(&v, &["pairing", "id"])));
    let vk = crypto::open_key(&*kek, &b(&v, &["pairing", "sealed"]), aad).expect("the vault key");
    assert_eq!(vk.as_ref(), &key32(&v, &["vk"]));
}

/// The private keys of the vectors' pairing agree on the shared secret
/// both ways (X25519), as the app and the new browser do.
#[test]
fn the_pairing_keys_agree_both_ways() {
    let v = vectors();
    let priv_a = b(&v, &["pairing", "privA"]);
    let priv_b = b(&v, &["pairing", "privB"]);
    let pub_a = b(&v, &["pairing", "pubA"]);
    let pub_b = b(&v, &["pairing", "pubB"]);
    let shared = b(&v, &["pairing", "shared"]);
    // Each side's private key gives the vector's public key, and agreeing
    // with the other's public key gives the vector's shared secret.
    let a = crypto::pairer_from_seed(&priv_a).expect("A");
    assert_eq!(a.public, pub_a.as_slice(), "A's public key");
    assert_eq!(a.agree(&pub_b).unwrap().as_ref(), shared.as_slice(), "A agrees");
    let b_side = crypto::pairer_from_seed(&priv_b).expect("B");
    assert_eq!(b_side.public, pub_b.as_slice());
    assert_eq!(b_side.agree(&pub_a).unwrap().as_ref(), shared.as_slice(), "B agrees");
}
