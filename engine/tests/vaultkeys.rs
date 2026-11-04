//! Reading real SSH keys into the vault and signing with them (sshkeys.rs).
//! The keys are made with ssh-keygen in a temp folder, one of each type the
//! vault keeps and some it does not, with a passphrase and without; what
//! they sign is a login with that key (the vault signs nothing else), and
//! the raw signatures are checked against each key's public half, as the
//! core does before it uses one.
//!
//! ssh-keygen is found at $TTERM_SSH_KEYGEN (the review runs it from an
//! unpacked openssh-client) or on PATH; without it the test is skipped, so
//! the suite still runs where OpenSSH is absent.

#![cfg(feature = "cloud")]

use ring::signature;
use std::path::{Path, PathBuf};
use std::process::Command;
use tterm_engine::sshkeys::{self, Unread, Why};

fn keygen() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("TTERM_SSH_KEYGEN") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let p = Path::new(dir).join("ssh-keygen");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

struct Lab {
    dir: PathBuf,
    keygen: PathBuf,
}

impl Lab {
    fn new() -> Option<Lab> {
        let keygen = keygen()?;
        let dir = std::env::temp_dir().join(format!("tterm-keys-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Some(Lab { dir, keygen })
    }

    /// A key of `kind` ("ed25519", "rsa", "ecdsa" with -b bits), with the
    /// passphrase given (empty for none): its file's path.
    fn make(&self, name: &str, kind: &str, bits: Option<&str>, passphrase: &str, comment: &str) -> PathBuf {
        let path = self.dir.join(name);
        let mut cmd = Command::new(&self.keygen);
        cmd.args(["-t", kind, "-f"]).arg(&path).args(["-N", passphrase, "-C", comment, "-q"]);
        if let Some(bits) = bits {
            cmd.args(["-b", bits]);
        }
        let status = cmd.status().expect("ssh-keygen runs");
        assert!(status.success(), "ssh-keygen -t {kind} failed");
        path
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The signing input of a login with the key of `public_openssh` by `alg`
/// (RFC 4252 §7), as the core's asyncssh writes it: what the vault signs.
fn login(public_openssh: &str, alg: &str) -> Vec<u8> {
    let blob = ssh_key::PublicKey::from_openssh(public_openssh).expect("a public key").to_bytes().unwrap();
    let string = |out: &mut Vec<u8>, v: &[u8]| {
        out.extend_from_slice(&(v.len() as u32).to_be_bytes());
        out.extend_from_slice(v);
    };
    let mut out = Vec::new();
    string(&mut out, &[0x5a; 32]);
    out.push(50);
    string(&mut out, b"deploy");
    string(&mut out, b"ssh-connection");
    string(&mut out, b"publickey");
    out.push(1);
    string(&mut out, alg.as_bytes());
    string(&mut out, &blob);
    out
}

/// Verifies a raw signature over `data` against the OpenSSH public key, the
/// way the core does once the device returns it.
fn verify(public_openssh: &str, kind: &str, data: &[u8], sig: &[u8]) {
    let key = ssh_key::PublicKey::from_openssh(public_openssh).expect("a public key");
    match (kind, key.key_data()) {
        (sshkeys::ED25519, ssh_key::public::KeyData::Ed25519(k)) => {
            assert_eq!(sig.len(), 64, "Ed25519 is 64 bytes");
            let public = signature::UnparsedPublicKey::new(&signature::ED25519, k.0.as_slice());
            public.verify(data, sig).expect("Ed25519 verifies");
        }
        (sshkeys::P256, ssh_key::public::KeyData::Ecdsa(ssh_key::public::EcdsaPublicKey::NistP256(p))) => {
            assert_eq!(sig.len(), 64, "P-256 r||s is 64 bytes");
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, p.as_bytes()).verify(data, sig).expect("P-256 verifies");
        }
        (sshkeys::P384, ssh_key::public::KeyData::Ecdsa(ssh_key::public::EcdsaPublicKey::NistP384(p))) => {
            assert_eq!(sig.len(), 96, "P-384 r||s is 96 bytes");
            signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, p.as_bytes()).verify(data, sig).expect("P-384 verifies");
        }
        (sshkeys::RSA, ssh_key::public::KeyData::Rsa(r)) => {
            let n = r.n.as_positive_bytes().unwrap();
            let e = r.e.as_positive_bytes().unwrap();
            let public = signature::RsaPublicKeyComponents { n, e };
            public.verify(&signature::RSA_PKCS1_2048_8192_SHA256, data, sig).expect("RSA SHA-256 verifies");
        }
        other => panic!("the public key does not match {kind}: {other:?}"),
    }
}

#[test]
fn ed25519_read_signed_and_verified() {
    let Some(lab) = Lab::new() else {
        eprintln!("ssh-keygen not found: skipping");
        return;
    };
    let path = lab.make("id_ed25519", "ed25519", None, "", "denis@mac");
    let text = std::fs::read_to_string(&path).unwrap();
    let key = sshkeys::read(&text, None).expect("read");
    assert_eq!(key.kind, sshkeys::ED25519);
    assert_eq!(key.comment, "denis@mac");
    assert!(key.fingerprint.starts_with("SHA256:"));
    // The public half the engine reports matches the .pub ssh-keygen wrote.
    let pub_file = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    assert_eq!(first_two(&key.public_openssh), first_two(&pub_file));
    let data = login(&key.public_openssh, sshkeys::ALG_ED25519);
    let sig = sshkeys::sign(key.plaintext.as_bytes(), sshkeys::ALG_ED25519, &data).expect("sign");
    verify(&key.public_openssh, sshkeys::ED25519, &data, &sig);
    // The fingerprint from the plaintext is ssh-keygen's.
    assert_eq!(sshkeys::fingerprint(key.plaintext.as_bytes()).unwrap(), key.fingerprint);
}

#[test]
fn ecdsa_p256_and_p384() {
    let Some(lab) = Lab::new() else { return };
    for (name, bits, kind, alg) in [("p256", "256", sshkeys::P256, sshkeys::ALG_P256), ("p384", "384", sshkeys::P384, sshkeys::ALG_P384)] {
        let path = lab.make(name, "ecdsa", Some(bits), "", "ec@mac");
        let text = std::fs::read_to_string(&path).unwrap();
        let key = sshkeys::read(&text, None).unwrap_or_else(|e| panic!("{name}: {:?}", e));
        assert_eq!(key.kind, kind);
        let data = login(&key.public_openssh, alg);
        let sig = sshkeys::sign(key.plaintext.as_bytes(), alg, &data).expect("sign");
        verify(&key.public_openssh, kind, &data, &sig);
        assert_eq!(sshkeys::fingerprint(key.plaintext.as_bytes()).unwrap(), key.fingerprint, "{name}");
    }
}

#[test]
fn rsa_read_signed_and_verified() {
    let Some(lab) = Lab::new() else { return };
    let path = lab.make("id_rsa", "rsa", Some("2048"), "", "rsa@mac");
    let text = std::fs::read_to_string(&path).unwrap();
    let key = sshkeys::read(&text, None).expect("read");
    assert_eq!(key.kind, sshkeys::RSA);
    let data = login(&key.public_openssh, sshkeys::ALG_RSA_SHA256);
    let sig = sshkeys::sign(key.plaintext.as_bytes(), sshkeys::ALG_RSA_SHA256, &data).expect("sign SHA-256");
    verify(&key.public_openssh, sshkeys::RSA, &data, &sig);
    assert_eq!(sshkeys::fingerprint(key.plaintext.as_bytes()).unwrap(), key.fingerprint);
    // SHA-512 too: a signature the modulus long, which verifies.
    let data512 = login(&key.public_openssh, sshkeys::ALG_RSA_SHA512);
    let sig512 = sshkeys::sign(key.plaintext.as_bytes(), sshkeys::ALG_RSA_SHA512, &data512).expect("sign SHA-512");
    let pub_key = ssh_key::PublicKey::from_openssh(&key.public_openssh).unwrap();
    if let ssh_key::public::KeyData::Rsa(r) = pub_key.key_data() {
        let public = signature::RsaPublicKeyComponents { n: r.n.as_positive_bytes().unwrap(), e: r.e.as_positive_bytes().unwrap() };
        public.verify(&signature::RSA_PKCS1_2048_8192_SHA512, &data512, &sig512).expect("RSA SHA-512 verifies");
    }
    // A login written for SHA-256 is not signed with SHA-512.
    assert!(matches!(sshkeys::sign(key.plaintext.as_bytes(), sshkeys::ALG_RSA_SHA512, &data), Err(sshkeys::SignError::NotLogin(sshkeys::NotLogin::Algorithm))));
}

#[test]
fn an_encrypted_key_needs_its_passphrase() {
    let Some(lab) = Lab::new() else { return };
    let path = lab.make("id_locked", "ed25519", None, "open sesame", "locked@mac");
    let text = std::fs::read_to_string(&path).unwrap();
    // Peeked, it is listed as encrypted, with its type and fingerprint.
    let peek = sshkeys::peek(&text).expect("peek");
    assert!(peek.encrypted);
    assert_eq!(peek.kind, sshkeys::ED25519);
    assert!(peek.fingerprint.starts_with("SHA256:"));
    assert!(peek.why.is_none());
    // No passphrase, the wrong one, then the right one.
    assert!(matches!(sshkeys::read(&text, None), Err(Unread::Passphrase)));
    assert!(matches!(sshkeys::read(&text, Some("")), Err(Unread::Passphrase)));
    assert!(matches!(sshkeys::read(&text, Some("wrong")), Err(Unread::WrongPassphrase)));
    let key = sshkeys::read(&text, Some("open sesame")).expect("opens");
    let data = login(&key.public_openssh, sshkeys::ALG_ED25519);
    let sig = sshkeys::sign(key.plaintext.as_bytes(), sshkeys::ALG_ED25519, &data).expect("sign");
    verify(&key.public_openssh, sshkeys::ED25519, &data, &sig);
}

#[test]
fn a_security_key_and_other_types_are_set_apart() {
    let Some(lab) = Lab::new() else { return };
    // DSA: a type the vault does not keep.
    let dsa = lab.dir.join("id_dsa");
    let made = Command::new(&lab.keygen).args(["-t", "dsa", "-f"]).arg(&dsa).args(["-N", "", "-q"]).status();
    if made.map(|s| s.success()).unwrap_or(false) {
        let text = std::fs::read_to_string(&dsa).unwrap();
        assert!(matches!(sshkeys::read(&text, None), Err(Unread::Not(Why::Type))), "DSA is not kept");
    }
    // A broken file is no key.
    assert!(matches!(sshkeys::read("not a key at all", None), Err(Unread::Broken(_))));
}

#[test]
fn the_wrong_algorithm_for_a_key_is_refused() {
    let Some(lab) = Lab::new() else { return };
    let path = lab.make("id_alg", "ed25519", None, "", "alg@mac");
    let text = std::fs::read_to_string(&path).unwrap();
    let key = sshkeys::read(&text, None).unwrap();
    // The core would never ask an Ed25519 key for an RSA signature, but if
    // it did, even with a login that says so, it is refused rather than
    // signed wrong.
    let data = login(&key.public_openssh, sshkeys::ALG_RSA_SHA256);
    assert!(matches!(sshkeys::sign(key.plaintext.as_bytes(), sshkeys::ALG_RSA_SHA256, &data), Err(sshkeys::SignError::Algorithm)));
}

/// ECDSA keys whose secret OpenSSH wrote with no zero in front, so shorter
/// than its curve's (31 bytes of P-256's 32, 47 of P-384's 48): one key in
/// 256 is such a key, and ssh-key 0.6 alone reads none of them (the build of
/// the v0.8.0 tag failed on one it made). Made by ssh-keygen and kept here,
/// with their public lines, and the same keys with the passphrase
/// "short scalar" (ssh-keygen -p). Throwaway keys of the checks.
const SHORT_P256: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTr82xUe1bPDC/aizuvDiswjAg9nL3d
H+a1CbzI/EDbFE+tM/H232I6AoPaSCJcM/yA1+IvQbN8KtTydSZ12e9EAAAAqCeAMdIngD
HSAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOvzbFR7Vs8ML9qL
O68OKzCMCD2cvd0f5rUJvMj8QNsUT60z8fbfYjoCg9pIIlwz/IDX4i9Bs3wq1PJ1JnXZ70
QAAAAfTWkjscHsPLqAWfiLaF3jJQYz2hHwb4w8LkTC4IZFnwAAAA9zaG9ydC1wMjU2QHRl
c3QBAg==
-----END OPENSSH PRIVATE KEY-----"#;
const SHORT_P256_PUB: &str = r#"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOvzbFR7Vs8ML9qLO68OKzCMCD2cvd0f5rUJvMj8QNsUT60z8fbfYjoCg9pIIlwz/IDX4i9Bs3wq1PJ1JnXZ70Q= short-p256@test"#;
const SHORT_P256_LOCKED: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABB+h7ojPh
rf3iG4XYGLg+WvAAAAGAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBOvzbFR7Vs8ML9qLO68OKzCMCD2cvd0f5rUJvMj8QNsUT60z8fbfYjoCg9
pIIlwz/IDX4i9Bs3wq1PJ1JnXZ70QAAACgb3w/ZrP+zxEuZZ5BN1mYezWWwnPuP/MP3OCU
YS/Xz1wMpCLlWdX4NUjUuLx1cwUXRSEPUUUQUQPgSvuqrkuQh9qdo8P0vQrsLRQkXk0Hdu
ePYiBmVns77sm+6Sf/mm1up1jxfZFPm6HINUdvvu9GiTGlMStYfjHiisZz5OcpAJYNIHED
VXen21ccbrHHQoxoVOYzsjMuCh+Ia5MAVMVTng==
-----END OPENSSH PRIVATE KEY-----"#;
const SHORT_P384: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQTseMs1eUH5ZjNibdIiw6A5zEY8CpnC
yZk6wvo/M7EgZ2zEFKyFe44ZRQI6XSjqRlNRl07/1nXzl6qvVZqOz2ysjTKC562q0EVokg
jVHzi8FJnssm5LnRNbVIL+2RzPQPMAAADY9xYRRfcWEUUAAAATZWNkc2Etc2hhMi1uaXN0
cDM4NAAAAAhuaXN0cDM4NAAAAGEE7HjLNXlB+WYzYm3SIsOgOcxGPAqZwsmZOsL6PzOxIG
dsxBSshXuOGUUCOl0o6kZTUZdO/9Z185eqr1Wajs9srI0yguetqtBFaJII1R84vBSZ7LJu
S50TW1SC/tkcz0DzAAAALxb5A0v2WRewzQwU4CVAwBo+UHO50/UqeW41xauKpoL0UXwR+r
7PEZFfTwQGjEtIAAAAD3Nob3J0LXAzODRAdGVzdAEC
-----END OPENSSH PRIVATE KEY-----"#;
const SHORT_P384_PUB: &str = r#"ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBOx4yzV5QflmM2Jt0iLDoDnMRjwKmcLJmTrC+j8zsSBnbMQUrIV7jhlFAjpdKOpGU1GXTv/WdfOXqq9Vmo7PbKyNMoLnrarQRWiSCNUfOLwUmeyybkudE1tUgv7ZHM9A8w== short-p384@test"#;
const SHORT_P384_LOCKED: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCmspNg4c
qiykLT+lLkTk2tAAAAGAAAAAEAAACIAAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlz
dHAzODQAAABhBOx4yzV5QflmM2Jt0iLDoDnMRjwKmcLJmTrC+j8zsSBnbMQUrIV7jhlFAj
pdKOpGU1GXTv/WdfOXqq9Vmo7PbKyNMoLnrarQRWiSCNUfOLwUmeyybkudE1tUgv7ZHM9A
8wAAANBJEtB5T60TTs4DqYCtZQEen6WZ4j+beKQUBKKbJJML1MTTcNtrI8YyDuwqdZ+C7p
h27AkIpKvlkAxX3yoFXCbAEqd1fWNj6klOPmDJmQulGY7J/vQVBBdwZzhWEwheS50nsufr
iwtAjt+VnQrhZoa4P5ITTeBc8OJ5JvFcq2SsHFnfkSf4QCiLvH8aOP22s2Z6T+1oQALwo0
bzPgwymbNsiYStgu1yrYkwvc8GPMsVYKiu22DJesqmTxj0Ej6ifbB+2bTowDW+Zp23zo9c
6vlY
-----END OPENSSH PRIVATE KEY-----"#;

#[test]
fn ecdsa_keys_with_a_short_secret_are_read() {
    let cases = [
        (sshkeys::P256, sshkeys::ALG_P256, 32, SHORT_P256, SHORT_P256_PUB, SHORT_P256_LOCKED),
        (sshkeys::P384, sshkeys::ALG_P384, 48, SHORT_P384, SHORT_P384_PUB, SHORT_P384_LOCKED),
    ];
    for (kind, alg, size, plain, public, locked) in cases {
        // ssh-key alone does not read them: what the engine pads.
        assert!(ssh_key::PrivateKey::from_openssh(plain).is_err(), "{kind}: ssh-key reads it by itself now, and the padding can go");
        let key = sshkeys::read(plain, None).unwrap_or_else(|e| panic!("{kind}: {e:?}"));
        assert_eq!(key.kind, kind);
        assert_eq!(first_two(&key.public_openssh), first_two(public), "{kind}: ssh-keygen's public half");
        // The JWK's secret has the curve's full length, the zero in front,
        // as WebCrypto takes it.
        let jwk: serde_json::Value = serde_json::from_str(&key.plaintext).unwrap();
        let d = tterm_engine::crypto::from_b64u(jwk["jwk"]["d"].as_str().unwrap()).unwrap();
        assert_eq!((d.len(), d[0]), (size, 0), "{kind}");
        // It signs a login that verifies, and proves the keys open.
        let data = login(&key.public_openssh, alg);
        let sig = sshkeys::sign(key.plaintext.as_bytes(), alg, &data).expect("sign");
        verify(&key.public_openssh, kind, &data, &sig);
        let nonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let (proved_with, proof) = sshkeys::prove(key.plaintext.as_bytes(), nonce).expect("prove");
        assert_eq!(proved_with, alg);
        verify(&key.public_openssh, kind, &sshkeys::proof_blob(nonce), &proof);
        // With its passphrase: needed, a wrong one refused as such, the right
        // one the very same key.
        let peek = sshkeys::peek(locked).expect("peek");
        assert!(peek.encrypted && peek.why.is_none());
        assert_eq!(peek.fingerprint, key.fingerprint);
        assert!(matches!(sshkeys::read(locked, None), Err(Unread::Passphrase)));
        assert!(matches!(sshkeys::read(locked, Some("not the one")), Err(Unread::WrongPassphrase)), "{kind}");
        let opened = sshkeys::read(locked, Some("short scalar")).unwrap_or_else(|e| panic!("{kind} with its passphrase: {e:?}"));
        let opened_jwk: serde_json::Value = serde_json::from_str(&opened.plaintext).unwrap();
        assert_eq!((opened.fingerprint.as_str(), &opened_jwk["jwk"]), (key.fingerprint.as_str(), &jwk["jwk"]), "{kind}");
    }
}

#[test]
fn every_type_proves_the_keys_open_over_the_nonce_alone() {
    let Some(lab) = Lab::new() else { return };
    let nonce = "lYMXv3-wQ9Ckfw2T1kFJmJ0fEa6vW8b1fGQqk7nqzQk";
    let blob = sshkeys::proof_blob(nonce);
    assert!(blob.starts_with(b"SSHSIG"), "an SSHSIG blob, which no login is");
    for (name, kind, bits, want) in [
        ("e", "ed25519", None, sshkeys::ALG_ED25519),
        ("p256", "ecdsa", Some("256"), sshkeys::ALG_P256),
        ("p384", "ecdsa", Some("384"), sshkeys::ALG_P384),
        ("r", "rsa", Some("2048"), sshkeys::ALG_RSA_SHA512),
    ] {
        let path = lab.make(name, kind, bits, "", "proof@mac");
        let key = sshkeys::read(&std::fs::read_to_string(&path).unwrap(), None).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let (alg, sig) = sshkeys::prove(key.plaintext.as_bytes(), nonce).expect("prove");
        assert_eq!(alg, want, "{name}");
        if key.kind == sshkeys::RSA {
            // RSA proves with SHA-512, as ssh-keygen -Y signs.
            let public = ssh_key::PublicKey::from_openssh(&key.public_openssh).unwrap();
            let ssh_key::public::KeyData::Rsa(r) = public.key_data() else { panic!("RSA") };
            let rsa = signature::RsaPublicKeyComponents { n: r.n.as_positive_bytes().unwrap(), e: r.e.as_positive_bytes().unwrap() };
            rsa.verify(&signature::RSA_PKCS1_2048_8192_SHA512, &blob, &sig).expect("RSA SHA-512 verifies");
        } else {
            verify(&key.public_openssh, key.kind, &blob, &sig);
        }
        // The login signer takes no proof blob.
        assert!(matches!(sshkeys::sign(key.plaintext.as_bytes(), alg, &blob), Err(sshkeys::SignError::NotLogin(_))), "{name}");
    }
}

/// The type and base64 of an OpenSSH public line, without the comment: the
/// engine's own line and ssh-keygen's name the same key.
fn first_two(line: &str) -> String {
    line.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}
