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

/// The type and base64 of an OpenSSH public line, without the comment: the
/// engine's own line and ssh-keygen's name the same key.
fn first_two(line: &str) -> String {
    line.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}
