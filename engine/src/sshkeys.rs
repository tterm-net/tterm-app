//! The person's SSH keys for the vault (from 0.7.0): a private key read from
//! a file as OpenSSH writes it (its own format, a passphrase's too), put into
//! the vault's plaintext as a JWK (vault-design.md "Crypto"), and used to
//! sign a login raw, the way the core asks over the socket. Reading is
//! ssh-key's (RustCrypto); the signatures are ring's, as the rest of the
//! engine.
//!
//! The vault keeps four types: Ed25519, ECDSA on P-256 and P-384, and RSA.
//! A key of another kind, a security key (sk-*), or one only an agent has is
//! told apart with the reason the page shows, and its servers go through the
//! Mac instead.

use crate::crypto::b64u;
use num_bigint::BigUint;
use ring::signature;
use serde::{Deserialize, Serialize};
use ssh_key::private::KeypairData;
use ssh_key::{HashAlg, PrivateKey};
use zeroize::Zeroizing;

/// The types of key the vault keeps, as SSH names them.
pub const ED25519: &str = "ssh-ed25519";
pub const P256: &str = "ecdsa-sha2-nistp256";
pub const P384: &str = "ecdsa-sha2-nistp384";
pub const RSA: &str = "ssh-rsa";

/// Why a key does not go to the vault, as the page's `why` has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// sk-*: the secret stays on the security key.
    SecurityKey,
    /// Only an agent has it (Secretive, 1Password, IdentityAgent).
    AgentOnly,
    /// Another type the vault does not take (DSA, NIST P-521).
    Type,
}

impl Why {
    pub fn word(self) -> &'static str {
        match self {
            Why::SecurityKey => "security key",
            Why::AgentOnly => "agent only",
            Why::Type => "type",
        }
    }
}

/// Why a private key could not be read into the vault.
#[derive(Debug, PartialEq, Eq)]
pub enum Unread {
    /// It is encrypted and no passphrase was given.
    Passphrase,
    /// The passphrase does not open it.
    WrongPassphrase,
    /// It is a kind the vault does not take, with the reason.
    Not(Why),
    /// It is no key this can read: what is wrong (not OpenSSH's format, a
    /// DSA key, a broken file).
    Broken(String),
}

impl Unread {
    /// A sentence for the page, where a key fails to move.
    pub fn message(&self) -> String {
        match self {
            Unread::Passphrase => "This key has a passphrase. Enter it to move the key.".into(),
            Unread::WrongPassphrase => "That passphrase does not open the key.".into(),
            Unread::Not(why) => format!("This key cannot be moved ({}).", why.word()),
            Unread::Broken(e) => format!("This key could not be read: {e}"),
        }
    }
}

/// A private key read into the vault: its type, the JWK plaintext the vault
/// seals, and the OpenSSH public line and SHA256 fingerprint the core keeps.
pub struct VaultKey {
    pub kind: &'static str,
    pub comment: String,
    pub public_openssh: String,
    pub fingerprint: String,
    /// The plaintext of the box, as the contract has it: wiped when let go.
    pub plaintext: Zeroizing<String>,
}

/// The vault's plaintext for a key: `{"v":1,"type":T,"jwk":J,"comment":C}`.
/// The fields are in the contract's order, which the page reproduces.
#[derive(Serialize)]
struct Plaintext<'a> {
    v: u8,
    #[serde(rename = "type")]
    kind: &'a str,
    jwk: Jwk,
    comment: &'a str,
}

/// The private key as a JWK (RFC 7517/7518), the half the page's WebCrypto
/// imports. Only the fields a type uses are written.
#[derive(Serialize, Default)]
struct Jwk {
    kty: &'static str,
    #[serde(skip_serializing_if = "str::is_empty")]
    crv: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    q: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dq: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    qi: Option<String>,
}

/// What a file holds before a passphrase is tried: whether it needs one,
/// and the key's type and fingerprint, so the page can list it either way.
pub struct Peek {
    pub kind: &'static str,
    pub comment: String,
    pub public_openssh: String,
    pub fingerprint: String,
    pub encrypted: bool,
    /// Set when the vault cannot take it: the reason, and no plaintext.
    pub why: Option<Why>,
}

/// Reads the text of a private-key file far enough to list it: its type and
/// whether it is encrypted, without the passphrase. ssh-key reads the public
/// half of an encrypted OpenSSH key without decrypting it.
pub fn peek(text: &str) -> Result<Peek, Unread> {
    let key = parse(text)?;
    let (kind, why) = classify(&key);
    Ok(Peek {
        kind: kind.unwrap_or(""),
        comment: key.comment().to_string(),
        public_openssh: key.public_key().to_openssh().unwrap_or_default(),
        fingerprint: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
        encrypted: key.is_encrypted(),
        why,
    })
}

/// Reads a private key into the vault, with `passphrase` if it has one.
pub fn read(text: &str, passphrase: Option<&str>) -> Result<VaultKey, Unread> {
    let key = parse(text)?;
    let key = if key.is_encrypted() {
        let phrase = passphrase.filter(|p| !p.is_empty()).ok_or(Unread::Passphrase)?;
        key.decrypt(phrase).map_err(|_| Unread::WrongPassphrase)?
    } else {
        key
    };
    let (kind, why) = classify(&key);
    if let Some(why) = why {
        return Err(Unread::Not(why));
    }
    let kind = kind.ok_or(Unread::Not(Why::Type))?;
    let comment = key.comment().to_string();
    let jwk = jwk_of(&key).ok_or_else(|| Unread::Broken("the key's numbers are not as expected".into()))?;
    let plaintext = Plaintext { v: 1, kind, jwk, comment: &comment };
    let plaintext = Zeroizing::new(serde_json::to_string(&plaintext).map_err(|e| Unread::Broken(e.to_string()))?);
    Ok(VaultKey {
        kind,
        comment,
        public_openssh: key.public_key().to_openssh().map_err(|e| Unread::Broken(e.to_string()))?,
        fingerprint: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
        plaintext,
    })
}

/// A private key from the text of a file. A format this does not read (an
/// old PEM key) is Broken, so its servers go through the Mac.
fn parse(text: &str) -> Result<PrivateKey, Unread> {
    PrivateKey::from_openssh(text.trim()).map_err(|e| Unread::Broken(ssh_error(&e)))
}

/// ssh-key's error in a few words, without its debug punctuation.
fn ssh_error(e: &ssh_key::Error) -> String {
    match e {
        ssh_key::Error::AlgorithmUnknown | ssh_key::Error::Encrypted => "not a key tTerm reads".into(),
        _ => "not an OpenSSH private key".into(),
    }
}

/// The key's vault type, or why it is not taken. An encrypted key (peeked
/// before the passphrase) is classified by its public half.
fn classify(key: &PrivateKey) -> (Option<&'static str>, Option<Why>) {
    use ssh_key::public::KeyData;
    // A security key, whether or not it is still encrypted.
    if matches!(key.public_key().key_data(), KeyData::SkEcdsaSha2NistP256(_) | KeyData::SkEd25519(_)) {
        return (None, Some(Why::SecurityKey));
    }
    match key.public_key().key_data() {
        KeyData::Ed25519(_) => (Some(ED25519), None),
        KeyData::Rsa(_) => (Some(RSA), None),
        KeyData::Ecdsa(ec) => match ec {
            ssh_key::public::EcdsaPublicKey::NistP256(_) => (Some(P256), None),
            ssh_key::public::EcdsaPublicKey::NistP384(_) => (Some(P384), None),
            _ => (None, Some(Why::Type)),
        },
        _ => (None, Some(Why::Type)),
    }
}

/// The JWK of a decrypted key: its public and private numbers.
fn jwk_of(key: &PrivateKey) -> Option<Jwk> {
    match key.key_data() {
        KeypairData::Ed25519(pair) => Some(Jwk {
            kty: "OKP",
            crv: "Ed25519",
            x: Some(b64u(&pair.public.0)),
            d: Some(b64u(&pair.private.to_bytes())),
            ..Default::default()
        }),
        KeypairData::Ecdsa(pair) => {
            let (crv, half) = match pair.curve() {
                ssh_key::EcdsaCurve::NistP256 => ("P-256", 32),
                ssh_key::EcdsaCurve::NistP384 => ("P-384", 48),
                _ => return None,
            };
            // The public key is a SEC1 point 0x04 || x || y.
            let point = pair.public_key_bytes();
            if point.len() != 1 + 2 * half || point[0] != 0x04 {
                return None;
            }
            Some(Jwk {
                kty: "EC",
                crv,
                x: Some(b64u(&point[1..1 + half])),
                y: Some(b64u(&point[1 + half..])),
                d: Some(b64u(pair.private_key_bytes())),
                ..Default::default()
            })
        }
        KeypairData::Rsa(pair) => {
            let n = pair.public.n.as_positive_bytes()?;
            let e = pair.public.e.as_positive_bytes()?;
            let d = pair.private.d.as_positive_bytes()?;
            let p = pair.private.p.as_positive_bytes()?;
            let q = pair.private.q.as_positive_bytes()?;
            let qi = pair.private.iqmp.as_positive_bytes()?;
            // OpenSSH keeps iqmp but not dP, dQ: they are d mod (p-1) and
            // d mod (q-1), which the JWK and ring's signing both want.
            let (dp, dq) = crt_exponents(d, p, q)?;
            Some(Jwk {
                kty: "RSA",
                n: Some(b64u(n)),
                e: Some(b64u(e)),
                d: Some(b64u(d)),
                p: Some(b64u(p)),
                q: Some(b64u(q)),
                dp: Some(b64u(&dp)),
                dq: Some(b64u(&dq)),
                qi: Some(b64u(qi)),
                ..Default::default()
            })
        }
        _ => None,
    }
}

// ------------------------------------------------------------- signing

/// The algorithms the core asks a key to sign with, over the socket
/// (vault-design.md): the raw signature a device returns.
pub const ALG_ED25519: &str = "ssh-ed25519";
pub const ALG_RSA_SHA256: &str = "rsa-sha2-256";
pub const ALG_RSA_SHA512: &str = "rsa-sha2-512";
pub const ALG_P256: &str = "ecdsa-sha2-nistp256";
pub const ALG_P384: &str = "ecdsa-sha2-nistp384";

/// The vault's plaintext, read back to sign with: the type and the JWK.
#[derive(Deserialize)]
struct Secret {
    #[serde(rename = "type")]
    kind: String,
    jwk: SecretJwk,
}

#[derive(Deserialize)]
struct SecretJwk {
    #[serde(default)]
    x: String,
    #[serde(default)]
    y: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
    #[serde(default)]
    d: String,
    #[serde(default)]
    p: String,
    #[serde(default)]
    q: String,
    #[serde(default)]
    dp: String,
    #[serde(default)]
    dq: String,
    #[serde(default)]
    qi: String,
}

/// Why a signature could not be made.
#[derive(Debug)]
pub enum SignError {
    /// The algorithm does not fit the key (rsa-sha2-256 on an Ed25519 key).
    Algorithm,
    /// The data is not a login of this key's to sign (see `check_login`):
    /// nothing was signed.
    NotLogin(NotLogin),
    /// The key's numbers are not as a key's should be.
    Key(String),
    /// The signing itself failed.
    Failed,
}

fn un(field: &str) -> Result<Vec<u8>, SignError> {
    crate::crypto::from_b64u(field).ok_or_else(|| SignError::Key("a JWK number is not base64url".into()))
}

/// Signs `data` with the key in `plaintext` (the vault's sealed JSON), by
/// `alg`, and returns the raw signature: Ed25519's 64 bytes, RSA's PKCS#1
/// v1.5, ECDSA's r||s of fixed length (P1363), as the core builds the SSH
/// blob from and verifies with the public half. The signing is ring's.
///
/// Only a login is signed: `data` must be the signing input of an SSH
/// user-auth request of this very key by `alg` (`check_login`), or nothing
/// is signed and the answer is `NotLogin`. So whoever asks over the socket
/// (the core, or anything in its place) cannot have the person's key sign
/// anything else with it: an SSHSIG, a git commit, another challenge.
pub fn sign(plaintext: &[u8], alg: &str, data: &[u8]) -> Result<Vec<u8>, SignError> {
    let secret: Secret = serde_json::from_slice(plaintext).map_err(|e| SignError::Key(e.to_string()))?;
    let blob = public_blob(&secret)?;
    check_login(data, alg, &blob).map_err(SignError::NotLogin)?;
    sign_raw(&secret, alg, data)
}

/// The signature itself, over whatever `data` is: only ever after
/// `check_login` (and the shared vector's check, below).
fn sign_raw(secret: &Secret, alg: &str, data: &[u8]) -> Result<Vec<u8>, SignError> {
    let jwk = &secret.jwk;
    match secret.kind.as_str() {
        ED25519 if alg == ALG_ED25519 => {
            let seed = un(&jwk.d)?;
            let public = un(&jwk.x)?;
            let pair = signature::Ed25519KeyPair::from_seed_and_public_key(&seed, &public).map_err(|e| SignError::Key(e.to_string()))?;
            Ok(pair.sign(data).as_ref().to_vec())
        }
        P256 if alg == ALG_P256 => sign_ecdsa(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, jwk, 32, data),
        P384 if alg == ALG_P384 => sign_ecdsa(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, jwk, 48, data),
        RSA if alg == ALG_RSA_SHA256 => sign_rsa(&signature::RSA_PKCS1_SHA256, jwk, data),
        RSA if alg == ALG_RSA_SHA512 => sign_rsa(&signature::RSA_PKCS1_SHA512, jwk, data),
        ED25519 | P256 | P384 | RSA => Err(SignError::Algorithm),
        _ => Err(SignError::Key("unknown key type".into())),
    }
}

/// ECDSA, from the JWK's private scalar and its public point: ring wants
/// the point as 0x04 || x || y, and gives r||s of fixed length.
fn sign_ecdsa(alg: &'static signature::EcdsaSigningAlgorithm, jwk: &SecretJwk, size: usize, data: &[u8]) -> Result<Vec<u8>, SignError> {
    let point = ec_point(jwk, size)?;
    let d = Zeroizing::new(fixed(&un(&jwk.d)?, size).ok_or_else(|| SignError::Key("the private scalar is too long".into()))?);
    let pair = signature::EcdsaKeyPair::from_private_key_and_public_key(alg, &d, &point, &ring::rand::SystemRandom::new()).map_err(|e| SignError::Key(e.to_string()))?;
    let sig = pair.sign(&ring::rand::SystemRandom::new(), data).map_err(|_| SignError::Failed)?;
    Ok(sig.as_ref().to_vec())
}

/// The public point 0x04 || x || y, each coordinate `size` bytes (a JWK
/// should have them so; one written shorter is padded, as the number it is).
fn ec_point(jwk: &SecretJwk, size: usize) -> Result<Vec<u8>, SignError> {
    let long = || SignError::Key("a coordinate is too long for the curve".into());
    let x = fixed(&un(&jwk.x)?, size).ok_or_else(long)?;
    let y = fixed(&un(&jwk.y)?, size).ok_or_else(long)?;
    let mut point = Vec::with_capacity(1 + 2 * size);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    Ok(point)
}

/// A big-endian number in exactly `len` bytes, zeros in front; None when it
/// does not fit.
fn fixed(be: &[u8], len: usize) -> Option<Vec<u8>> {
    let start = be.iter().take_while(|b| **b == 0).count();
    let digits = &be[start..];
    if digits.len() > len {
        return None;
    }
    let mut out = vec![0u8; len - digits.len()];
    out.extend_from_slice(digits);
    Some(out)
}

// ------------------------------------------------------ what is a login

/// Why `data` is not a login this key may sign (`check_login`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotLogin {
    /// Not that shape at all: cut short, or a length past its end.
    Shape,
    /// The session id is not 16 to 64 bytes.
    SessionId,
    /// Not a user-auth request: the message number is not 50.
    NotRequest,
    /// For another service than "ssh-connection".
    Service,
    /// Another method than "publickey" (publickey-hostbound too).
    Method,
    /// The boolean is not TRUE: a query, which carries no signature.
    NoSignature,
    /// The algorithm in it is not the request's, or not one the vault signs
    /// with.
    Algorithm,
    /// The public key in it is not this key.
    OtherKey,
    /// Bytes after the public key.
    Trailing,
}

/// SSH_MSG_USERAUTH_REQUEST.
const USERAUTH_REQUEST: u8 = 50;
/// The session id is a hash of the key exchange: SHA-1's 20 bytes to
/// SHA-512's 64; at least 16 whatever the hash.
const SESSION_ID_MIN: usize = 16;
const SESSION_ID_MAX: usize = 64;

/// Whether `data` is exactly what a client signs to log in with this key
/// (RFC 4252 §7), as OpenSSH and asyncssh (the core's) write it:
///
/// ```text
/// string    session id (16 to 64 bytes)
/// byte      50, SSH_MSG_USERAUTH_REQUEST
/// string    user name (any: a jump host may have another)
/// string    "ssh-connection"
/// string    "publickey"
/// boolean   TRUE
/// string    the algorithm, which is `alg`
/// string    the public key, which is `public_blob` (this key's own)
/// ```
///
/// and nothing after it.
pub fn check_login(data: &[u8], alg: &str, public_blob: &[u8]) -> Result<(), NotLogin> {
    if ![ALG_ED25519, ALG_RSA_SHA256, ALG_RSA_SHA512, ALG_P256, ALG_P384].contains(&alg) {
        return Err(NotLogin::Algorithm);
    }
    let mut at = data;
    let session = take_string(&mut at).ok_or(NotLogin::Shape)?;
    if !(SESSION_ID_MIN..=SESSION_ID_MAX).contains(&session.len()) {
        return Err(NotLogin::SessionId);
    }
    if take_byte(&mut at).ok_or(NotLogin::Shape)? != USERAUTH_REQUEST {
        return Err(NotLogin::NotRequest);
    }
    take_string(&mut at).ok_or(NotLogin::Shape)?;
    if take_string(&mut at).ok_or(NotLogin::Shape)? != b"ssh-connection" {
        return Err(NotLogin::Service);
    }
    if take_string(&mut at).ok_or(NotLogin::Shape)? != b"publickey" {
        return Err(NotLogin::Method);
    }
    if take_byte(&mut at).ok_or(NotLogin::Shape)? != 1 {
        return Err(NotLogin::NoSignature);
    }
    if take_string(&mut at).ok_or(NotLogin::Shape)? != alg.as_bytes() {
        return Err(NotLogin::Algorithm);
    }
    if take_string(&mut at).ok_or(NotLogin::Shape)? != public_blob {
        return Err(NotLogin::OtherKey);
    }
    if !at.is_empty() {
        return Err(NotLogin::Trailing);
    }
    Ok(())
}

/// An SSH `string`: a 32-bit big-endian length and that many bytes.
fn take_string<'a>(at: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, rest) = at.split_first_chunk::<4>()?;
    let len = u32::from_be_bytes(*len) as usize;
    if rest.len() < len {
        return None;
    }
    let (value, rest) = rest.split_at(len);
    *at = rest;
    Some(value)
}

fn take_byte(at: &mut &[u8]) -> Option<u8> {
    let (first, rest) = at.split_first()?;
    *at = rest;
    Some(*first)
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

/// An SSH `mpint` of a positive big-endian number: no zeros in front but
/// one where the top bit is set.
fn put_mpint(out: &mut Vec<u8>, be: &[u8]) {
    let start = be.iter().take_while(|b| **b == 0).count();
    let digits = &be[start..];
    if digits.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v = Vec::with_capacity(digits.len() + 1);
        v.push(0);
        v.extend_from_slice(digits);
        put_string(out, &v);
    } else {
        put_string(out, digits);
    }
}

/// The key's public half as SSH writes it on the wire (RFC 4253 §6.6, RFC
/// 5656 §3.1, RFC 8709 §4), from its JWK: what a login names the key by.
fn public_blob(secret: &Secret) -> Result<Vec<u8>, SignError> {
    let jwk = &secret.jwk;
    let mut out = Vec::new();
    match secret.kind.as_str() {
        ED25519 => {
            let x = un(&jwk.x)?;
            if x.len() != 32 {
                return Err(SignError::Key("an Ed25519 public key is 32 bytes".into()));
            }
            put_string(&mut out, ED25519.as_bytes());
            put_string(&mut out, &x);
        }
        P256 | P384 => {
            let (curve, size) = if secret.kind == P256 { ("nistp256", 32) } else { ("nistp384", 48) };
            put_string(&mut out, secret.kind.as_bytes());
            put_string(&mut out, curve.as_bytes());
            put_string(&mut out, &ec_point(jwk, size)?);
        }
        RSA => {
            put_string(&mut out, RSA.as_bytes());
            put_mpint(&mut out, &un(&jwk.e)?);
            put_mpint(&mut out, &un(&jwk.n)?);
        }
        _ => return Err(SignError::Key("unknown key type".into())),
    }
    Ok(out)
}

/// The SHA256 fingerprint of the key in `plaintext`, as `ssh-keygen -l`
/// writes it: what the vault lists the key by, from the key itself.
pub fn fingerprint(plaintext: &[u8]) -> Option<String> {
    use base64::Engine as _;
    let secret: Secret = serde_json::from_slice(plaintext).ok()?;
    let blob = public_blob(&secret).ok()?;
    let hash = ring::digest::digest(&ring::digest::SHA256, &blob);
    Some(format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash.as_ref())))
}

/// RSA, from the JWK's numbers: ring builds the key from its components and
/// signs with PKCS#1 v1.5. A key below 2048 bits ring will not take.
fn sign_rsa(alg: &'static dyn signature::RsaEncoding, jwk: &SecretJwk, data: &[u8]) -> Result<Vec<u8>, SignError> {
    let (n, e, d) = (un(&jwk.n)?, un(&jwk.e)?, un(&jwk.d)?);
    let (p, q) = (un(&jwk.p)?, un(&jwk.q)?);
    let (dp, dq, qi) = (un(&jwk.dp)?, un(&jwk.dq)?, un(&jwk.qi)?);
    #[allow(non_snake_case)]
    let components = ring::rsa::KeyPairComponents { public_key: ring::rsa::PublicKeyComponents { n: &n, e: &e }, d: &d, p: &p, q: &q, dP: &dp, dQ: &dq, qInv: &qi };
    let pair = signature::RsaKeyPair::from_components(&components).map_err(|e| SignError::Key(e.to_string()))?;
    let mut sig = vec![0u8; pair.public().modulus_len()];
    pair.sign(alg, &ring::rand::SystemRandom::new(), data, &mut sig).map_err(|_| SignError::Failed)?;
    Ok(sig)
}

/// dP = d mod (p-1) and dQ = d mod (q-1), big-endian without leading zeros.
fn crt_exponents(d: &[u8], p: &[u8], q: &[u8]) -> Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)> {
    let d = BigUint::from_bytes_be(d);
    let p = BigUint::from_bytes_be(p);
    let q = BigUint::from_bytes_be(q);
    let one = BigUint::from(1u8);
    if p <= one || q <= one {
        return None;
    }
    let dp = Zeroizing::new((&d % (&p - &one)).to_bytes_be());
    let dq = Zeroizing::new((&d % (&q - &one)).to_bytes_be());
    Some((dp, dq))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reasons_read_as_the_page_wants() {
        assert_eq!(Why::SecurityKey.word(), "security key");
        assert_eq!(Why::AgentOnly.word(), "agent only");
        assert_eq!(Why::Type.word(), "type");
    }

    /// The shared vectors' signature (vault-vectors.json): Ed25519 is
    /// deterministic, so the raw signature over the vector's data is its
    /// bytes. The data is no login, so this goes past `check_login` on
    /// purpose; `sign` itself refuses it.
    #[test]
    fn the_vectors_signature_and_its_refusal() {
        let v: serde_json::Value = serde_json::from_str(include_str!("../tests/vault-vectors.json")).unwrap();
        let plaintext = v["key"]["plaintext"].as_str().unwrap().as_bytes();
        let data = crate::crypto::from_b64u(v["signature"]["data"].as_str().unwrap()).unwrap();
        let secret: Secret = serde_json::from_slice(plaintext).unwrap();
        let raw = sign_raw(&secret, ALG_ED25519, &data).unwrap();
        assert_eq!(b64u(&raw), v["signature"]["raw_sig"].as_str().unwrap());
        assert!(matches!(sign(plaintext, ALG_ED25519, &data), Err(SignError::NotLogin(NotLogin::Shape))));
        // The fingerprint from the key itself is the vector's public key's.
        let line = v["key"]["openssh_public"].as_str().unwrap();
        let public = ssh_key::PublicKey::from_openssh(line).unwrap();
        assert_eq!(fingerprint(plaintext).unwrap(), public.fingerprint(HashAlg::Sha256).to_string());
        assert_eq!(public_blob(&secret).unwrap(), public.to_bytes().unwrap(), "the blob is the key on the wire");
    }

    #[test]
    fn numbers_on_the_wire() {
        let mut out = Vec::new();
        put_mpint(&mut out, &[0x00, 0x01, 0x00, 0x01]);
        assert_eq!(out, [0, 0, 0, 3, 1, 0, 1], "no zeros in front");
        out.clear();
        put_mpint(&mut out, &[0x80, 0x01]);
        assert_eq!(out, [0, 0, 0, 3, 0, 0x80, 1], "a zero where the top bit is set");
        out.clear();
        put_mpint(&mut out, &[0, 0]);
        assert_eq!(out, [0, 0, 0, 0], "zero is empty");
        assert_eq!(fixed(&[1, 2], 4).unwrap(), [0, 0, 1, 2]);
        assert_eq!(fixed(&[0, 0, 0, 0, 9], 4).unwrap(), [0, 0, 0, 9]);
        assert!(fixed(&[1, 2, 3, 4, 5], 4).is_none());
    }
}
