//! The vault's cryptography (from 0.7.0), exactly as the contract between
//! the core, the page and the app has it (vault-design.md, "Crypto"): what a
//! box is, how its keys are derived, the vault password (from 0.8.0), the
//! recovery code of a vault made before, and the numbers of pairing a new
//! browser. The page does the same with WebCrypto and Argon2id of its own;
//! the shared vectors (tests/vault-vectors.json) hold both to the same bytes.
//!
//! A box is AES-256-GCM with a random nonce of 12 bytes: the nonce, then the
//! ciphertext with its tag of 16, what WebCrypto's encrypt returns after the
//! nonce. Every box says what it is for in its additional data (`tterm/vault/
//! key/v1/<id>` and the like), so that one cannot be passed off as another.
//! Keys are HKDF-SHA256 (RFC 5869); a new browser and this app agree on one
//! with X25519. All of it is ring's, the TLS of the rest of the engine; the
//! password's Argon2id is RustCrypto's (argon2).

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::{SecureRandom, SystemRandom};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

/// Base64url without padding, as every binary value of the vault is
/// written in JSON; padding is taken when it comes all the same.
const B64U: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, GeneralPurposeConfig::new().with_encode_padding(false).with_decode_padding_mode(DecodePaddingMode::Indifferent));

pub fn b64u(bytes: &[u8]) -> String {
    B64U.encode(bytes)
}

/// The bytes of a base64url value; None for anything else.
pub fn from_b64u(text: &str) -> Option<Vec<u8>> {
    B64U.decode(text.trim()).ok()
}

/// A key of the vault: the vault key itself, or one that opens it.
pub type Key = Zeroizing<[u8; 32]>;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// `N` random bytes, from the system.
pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    SystemRandom::new().fill(&mut out).expect("random bytes from the system");
    out
}

/// A new random key.
pub fn new_key() -> Key {
    Zeroizing::new(random::<32>())
}

/// A key from the 32 bytes of one; None for any other length.
pub fn key_of(bytes: &[u8]) -> Option<Key> {
    <[u8; 32]>::try_from(bytes).ok().map(Zeroizing::new)
}

// ------------------------------------------------------------------ boxes

/// What a box is for, in its additional data: a key of the vault.
pub fn key_aad(key_id: &str) -> String {
    format!("tterm/vault/key/v1/{key_id}")
}

/// The vault key wrapped for a lock (a passkey, the app).
pub fn lock_aad(lock_id: &str) -> String {
    format!("tterm/vault/lock/v1/{lock_id}")
}

/// The vault key wrapped for the vault password.
pub fn password_aad(vault_id: &str) -> String {
    format!("tterm/vault/password/v1/{vault_id}")
}

/// The vault key wrapped for the recovery code.
pub fn recovery_aad(vault_id: &str) -> String {
    format!("tterm/vault/recovery/v1/{vault_id}")
}

/// The vault key sealed for a new browser.
pub fn pair_aad(pairing_id: &str) -> String {
    format!("tterm/vault/pair/v1/{pairing_id}")
}

/// `plain` in a box of `key`, with a random nonce.
pub fn seal(key: &[u8; 32], plain: &[u8], aad: &str) -> Vec<u8> {
    seal_with(key, random::<NONCE_LEN>(), plain, aad)
}

/// The same with the nonce given: for the vectors.
pub fn seal_with(key: &[u8; 32], nonce: [u8; NONCE_LEN], plain: &[u8], aad: &str) -> Vec<u8> {
    let sealing = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("a key of 32 bytes"));
    // Sealed where it lies, in room made for the tag: no copy of the plain
    // text is left behind.
    let mut out = Vec::with_capacity(NONCE_LEN + plain.len() + TAG_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plain);
    let tag = sealing.seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad.as_bytes()), &mut out[NONCE_LEN..]).expect("sealed");
    out.extend_from_slice(tag.as_ref());
    out
}

/// What a box of `key` holds, if it is one for `aad`, whole and unchanged.
pub fn open(key: &[u8; 32], boxed: &[u8], aad: &str) -> Option<Zeroizing<Vec<u8>>> {
    if boxed.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let opening = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).ok()?);
    let nonce = Nonce::try_assume_unique_for_key(&boxed[..NONCE_LEN]).ok()?;
    let mut body = Zeroizing::new(boxed[NONCE_LEN..].to_vec());
    let plain_len = opening.open_in_place(nonce, Aad::from(aad.as_bytes()), &mut body).ok()?.len();
    body.truncate(plain_len);
    Some(body)
}

/// A key out of a box of `key`: the vault key from a lock's wrap.
pub fn open_key(key: &[u8; 32], boxed: &[u8], aad: &str) -> Option<Key> {
    open(key, boxed, aad).and_then(|plain| key_of(&plain))
}

// --------------------------------------------------------------- deriving

/// HKDF-SHA256 of `ikm` with `salt` and `info`, 32 bytes of it.
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &str) -> Key {
    let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, salt).extract(ikm);
    let info = [info.as_bytes()];
    let okm = prk.expand(&info, ring::hkdf::HKDF_SHA256).expect("32 bytes of HKDF");
    let mut out = Zeroizing::new([0u8; 32]);
    okm.fill(out.as_mut()).expect("32 bytes of HKDF");
    out
}

pub const PRF_INFO: &str = "tterm/vault/prf/v1";
pub const PASSWORD_KEK_INFO: &str = "tterm/vault/password/kek/v1";
pub const PASSWORD_AUTH_INFO: &str = "tterm/vault/password/auth/v1";
pub const RECOVERY_INFO: &str = "tterm/vault/recovery/v1";
pub const PAIR_INFO: &str = "tterm/vault/pair/v1";

/// The key of a browser's passkey lock, from its PRF output: the page's,
/// here for the vectors.
pub fn prf_kek(prf_output: &[u8]) -> Key {
    hkdf(prf_output, &[0u8; 32], PRF_INFO)
}

// ---------------------------------------------------------- the password

/// The vault password (from 0.8.0), the one way into the vault from any
/// browser with no Mac: as typed, in Unicode NFC, from 12 to 256 code
/// points then, nothing trimmed. The core never sees it.
pub const PASSWORD_MIN: usize = 12;
pub const PASSWORD_MAX: usize = 256;
/// The password's salt: new each time a password is set.
pub const PASSWORD_SALT_LEN: usize = 16;

/// Argon2id's settings for a password (RFC 9106, version 0x13): `m` KiB of
/// memory, `t` passes, `p` lanes, as tTerm keeps them with the password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl Kdf {
    /// What a password is set with: 64 MiB, three passes, one lane.
    pub const NEW: Kdf = Kdf { m: 65536, t: 3, p: 1 };

    /// Whether a vault password may have these settings (the core takes no
    /// others): never weaker than a new one's, as weaker ones would make the
    /// proof sent to tTerm cheaper to guess the password from, nor so heavy
    /// that working it out would take the Mac's memory.
    pub fn acceptable(&self) -> bool {
        (65536..=1_048_576).contains(&self.m) && (3..=10).contains(&self.t) && (1..=4).contains(&self.p)
    }
}

/// A vault password as typed, the way its keys are made from it: in Unicode
/// NFC (an "é" typed as "e" and an accent is the "é" of every other
/// keyboard), nothing trimmed. Err with how many code points it has when
/// that is not 12 to 256.
pub fn password_text(typed: &str) -> Result<Zeroizing<String>, usize> {
    // Many times longer than any password can be: not worth normalizing.
    if typed.len() > PASSWORD_MAX * 64 {
        return Err(typed.chars().count());
    }
    // Room for all of it at once (NFC is at most three times as long), so
    // that no shorter copy is left behind as it grows.
    let mut nfc = Zeroizing::new(String::with_capacity(typed.len() * 3));
    nfc.extend(typed.nfc());
    let n = nfc.chars().count();
    if (PASSWORD_MIN..=PASSWORD_MAX).contains(&n) {
        Ok(nfc)
    } else {
        Err(n)
    }
}

/// Argon2id of `password` with `salt`, 32 bytes, no secret and no associated
/// data, in memory of its own that is wiped when done (Argon2id fills all of
/// it from the password). None for settings Argon2 does not take, or a salt
/// shorter than 8 bytes.
pub fn argon2id(password: &[u8], salt: &[u8], kdf: &Kdf) -> Option<Key> {
    use argon2::{Algorithm, Argon2, Block, Params, Version};
    let params = Params::new(kdf.m, kdf.t, kdf.p, Some(32)).ok()?;
    let mut memory = vec![Block::default(); params.block_count()];
    let mut out = Zeroizing::new([0u8; 32]);
    let done = Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into_with_memory(password, salt, out.as_mut(), &mut memory[..]);
    memory.iter_mut().for_each(Zeroize::zeroize);
    done.ok()?;
    Some(out)
}

/// What a vault password gives: the key its wrap of the vault key opens
/// with, and the proof tTerm asks for before it hands that wrap out (it
/// keeps the proof's SHA-256 only, never the proof, and never sees the key).
pub struct PasswordKeys {
    pub kek: Key,
    pub auth: Key,
}

/// The keys of a password, from its NFC text (password_text), its salt and
/// its settings: Argon2id, then HKDF of that with 32 zero bytes of salt and
/// each one's info.
pub fn password_keys(nfc: &str, salt: &[u8], kdf: &Kdf) -> Option<PasswordKeys> {
    let out = argon2id(nfc.as_bytes(), salt, kdf)?;
    Some(PasswordKeys {
        kek: hkdf(out.as_ref(), &[0u8; 32], PASSWORD_KEK_INFO),
        auth: hkdf(out.as_ref(), &[0u8; 32], PASSWORD_AUTH_INFO),
    })
}

/// What tTerm keeps of the proof: its SHA-256. The core makes it, never
/// this app; here for the checks, which play tTerm.
pub fn password_check(auth: &[u8]) -> [u8; 32] {
    sha256(&[auth])
}

// ---------------------------------------------------------- recovery code

/// Crockford's base32, as the sign-in code (account.rs): no I, L, O or U.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// The code's signs: 24 of them, 120 bits. A vault made before 0.8.0 has
/// one until its first password; no new codes are made.
pub const CODE_LEN: usize = 24;

/// A recovery code as typed, the way the KEK is made from it: upper case,
/// without dashes or spaces, O as 0, I and L as 1. None when it is not 24
/// signs of the code's alphabet then.
pub fn normalize_code(code: &str) -> Option<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(CODE_LEN));
    for c in code.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' => continue,
            c if c.is_whitespace() => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !c.is_ascii() || !CROCKFORD.contains(&(c as u8)) {
            return None;
        }
        out.push(c);
    }
    (out.len() == CODE_LEN).then_some(out)
}

/// The key of the recovery code's lock: from the code, normalized, and the
/// vault's recovery salt.
pub fn recovery_kek(normalized: &str, salt: &[u8]) -> Key {
    hkdf(normalized.as_bytes(), salt, RECOVERY_INFO)
}

// ---------------------------------------------------------------- pairing

const COMMIT_PREFIX: &[u8] = b"tterm/vault/pair/commit/v1";
const SAS_PREFIX: &[u8] = b"tterm/vault/pair/sas/v1";

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for p in parts {
        ctx.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// What a new browser promises before it sees the app's key: the hash of
/// its own.
pub fn commit_of(pub_b: &[u8]) -> [u8; 32] {
    sha256(&[COMMIT_PREFIX, pub_b])
}

/// The six digits both screens show, as "482 913": the first four bytes of
/// a hash of both public keys, big-endian, modulo a million.
pub fn sas_of(pub_a: &[u8], pub_b: &[u8]) -> String {
    let h = sha256(&[SAS_PREFIX, pub_a, pub_b]);
    let n = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

/// The key the vault key goes to the new browser in, from what both agreed.
pub fn pair_kek(shared: &[u8], pub_a: &[u8], pub_b: &[u8]) -> Key {
    let salt = [pub_a, pub_b].concat();
    hkdf(shared, &salt, PAIR_INFO)
}

/// Pairer::from_seed, for the vectors' keys.
pub fn pairer_from_seed(seed: &[u8]) -> Option<Pairer> {
    Pairer::from_seed(seed)
}

/// Whether two secrets are the same, in a time that does not tell where
/// they differ.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// This side's X25519 key for one pairing: its public half goes to the
/// core, its private half agrees once, with the new browser's.
pub struct Pairer {
    private: EphemeralPrivateKey,
    pub public: [u8; 32],
}

impl Pairer {
    pub fn new() -> Option<Pairer> {
        Self::from(&SystemRandom::new())
    }

    /// From the randomness given: the system's, or the vectors' own.
    pub fn from(rng: &dyn SecureRandom) -> Option<Pairer> {
        let private = EphemeralPrivateKey::generate(&X25519, rng).ok()?;
        let public = <[u8; 32]>::try_from(private.compute_public_key().ok()?.as_ref()).ok()?;
        Some(Pairer { private, public })
    }

    /// From a fixed 32-byte seed (the vectors' private keys), so that both
    /// sides' bytes can be checked against them. X25519's private key is the
    /// 32 random bytes the RNG hands out, so a seed given whole is that key.
    /// ring's own fixed-bytes RNG is the only way to seal that sealed trait.
    #[allow(deprecated)]
    pub fn from_seed(seed: &[u8]) -> Option<Pairer> {
        if seed.len() != 32 {
            return None;
        }
        Self::from(&ring::test::rand::FixedSliceRandom { bytes: seed })
    }

    /// The secret both sides have, with the new browser's public key; None
    /// for a key that is none (of another length, or of a low order).
    pub fn agree(self, pub_b: &[u8]) -> Option<Key> {
        agreement::agree_ephemeral(self.private, &UnparsedPublicKey::new(&X25519, pub_b), |shared| key_of(shared)).ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_box_opens_only_with_its_key_and_its_purpose() {
        // The shared vectors (box format, HKDF, pairing) are checked in
        // tests/vault.rs, which the page reproduces with WebCrypto.
        let key = new_key();
        let sealed = seal(&key, b"secret", &key_aad("k1"));
        assert_eq!(sealed.len(), NONCE_LEN + 6 + TAG_LEN);
        assert_eq!(open(&key, &sealed, &key_aad("k1")).unwrap().as_slice(), b"secret");
        assert!(open(&key, &sealed, &key_aad("k2")).is_none(), "another key's box");
        assert!(open(&new_key(), &sealed, &key_aad("k1")).is_none(), "another key");
        let mut changed = sealed.clone();
        changed[NONCE_LEN] ^= 1;
        assert!(open(&key, &changed, &key_aad("k1")).is_none(), "changed on the way");
        assert!(open(&key, &sealed[..10], &key_aad("k1")).is_none());
        assert_ne!(seal(&key, b"secret", "a")[..NONCE_LEN], seal(&key, b"secret", "a")[..NONCE_LEN], "a new nonce each time");
    }

    #[test]
    fn the_password_as_its_keys_are_made_from_it() {
        // NFC: "e" and a combining accent are the "é" typed at once.
        assert_eq!(password_text("caf\u{65}\u{301} au lait!").unwrap().as_str(), "caf\u{e9} au lait!");
        // 12 code points at least, 256 at most, after NFC; nothing trimmed.
        assert_eq!(password_text("eleven char"), Err(11));
        assert_eq!(password_text("twelve chars").unwrap().as_str(), "twelve chars");
        assert_eq!(password_text("  spaces too  ").unwrap().as_str(), "  spaces too  ");
        assert_eq!(password_text(&"e\u{301}".repeat(11)), Err(11), "11 after NFC, though 22 typed");
        assert_eq!(password_text("тёплый вечер").unwrap().chars().count(), 12);
        assert!(password_text(&"x".repeat(256)).is_ok());
        assert_eq!(password_text(&"x".repeat(257)), Err(257));
        assert_eq!(password_text(&"x".repeat(100_000)), Err(100_000));
        assert_eq!(password_text(""), Err(0));
        // The settings a vault password may have: a new one's, never weaker.
        assert!(Kdf::NEW.acceptable());
        assert!(!Kdf { m: 256, t: 2, p: 1 }.acceptable(), "the small vectors' are for the checks only");
        assert!(!Kdf { m: 65536, t: 2, p: 1 }.acceptable());
        assert!(!Kdf { m: 2 * 1_048_576, t: 3, p: 1 }.acceptable());
        assert!(Kdf { m: 1_048_576, t: 10, p: 4 }.acceptable());
        // What Argon2 does not take is no key.
        assert!(argon2id(b"twelve chars", &[1u8; 7], &Kdf { m: 64, t: 1, p: 1 }).is_none(), "a salt under 8 bytes");
        assert!(argon2id(b"twelve chars", &[1u8; 16], &Kdf { m: 4, t: 1, p: 1 }).is_none());
        let small = Kdf { m: 64, t: 1, p: 1 };
        let a = password_keys("twelve chars", &[1u8; 16], &small).unwrap();
        let b = password_keys("twelve chars", &[2u8; 16], &small).unwrap();
        assert_ne!(a.kek.as_slice(), a.auth.as_slice(), "the key and the proof are not the same");
        assert_ne!(a.kek.as_slice(), b.kek.as_slice(), "another salt, another key");
        assert_eq!(password_aad("v1"), "tterm/vault/password/v1/v1");
    }

    #[test]
    fn recovery_codes() {
        assert_eq!(normalize_code("K7QF-29XM-PL4D-8VHT-R2NC-6WJB").unwrap().len(), CODE_LEN);
        assert_eq!(normalize_code(" k7qf 29xm-pl4d-8vht-r2nc-6wjb ").unwrap().as_str(), "K7QF29XMP14D8VHTR2NC6WJB");
        assert_eq!(normalize_code("OOOO-IIII-LLLL-0000-1111-2222").unwrap().as_str(), "000011111111000011112222");
        assert!(normalize_code("K7QF-29XM-PL4D-8VHT-R2NC-6WJ").is_none(), "one short");
        assert!(normalize_code("K7QF-29XM-PL4D-8VHT-R2NC-6WJBU").is_none(), "U is no sign of it");
        assert!(normalize_code("K7QF-29XM-PL4D-8VHT-R2NC-6WJ!").is_none());
    }

    #[test]
    fn the_digits_of_a_pairing() {
        let (a, b) = (Pairer::new().unwrap(), Pairer::new().unwrap());
        let (pa, pb) = (a.public, b.public);
        let sas = sas_of(&pa, &pb);
        assert_eq!(sas.len(), 7);
        assert_eq!(&sas[3..4], " ");
        assert_eq!(a.agree(&pb).unwrap().as_slice(), b.agree(&pa).unwrap().as_slice(), "both sides agree");
        assert!(Pairer::new().unwrap().agree(&[0u8; 32]).is_none(), "no key of a low order");
        assert!(Pairer::new().unwrap().agree(&[1u8; 31]).is_none());
        assert!(same(b"abc", b"abc") && !same(b"abc", b"abd") && !same(b"ab", b"abc"));
    }
}
