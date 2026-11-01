//! The vault's crypto against the shared vectors (vault-vectors.json), which
//! the page (WebCrypto) must reproduce too: the box format, the HKDF infos,
//! the recovery code's normalization, a pairing's commit, its six digits and
//! its KEK. The same bytes on both sides are what lets a browser open what
//! the app sealed, and the core check a signature the device made.

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
