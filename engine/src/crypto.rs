//! The vault's cryptography (from 0.7.0), exactly as the contract between
//! the core, the page and the app has it (vault-design.md, "Crypto"): what a
//! box is, how its keys are derived, the recovery code, and the numbers of
//! pairing a new browser. The page does the same with WebCrypto; the shared
//! vectors (tests/vault-vectors.json) hold both to the same bytes.
//!
//! A box is AES-256-GCM with a random nonce of 12 bytes: the nonce, then the
//! ciphertext with its tag of 16, what WebCrypto's encrypt returns after the
//! nonce. Every box says what it is for in its additional data (`tterm/vault/
//! key/v1/<id>` and the like), so that one cannot be passed off as another.
//! Keys are HKDF-SHA256 (RFC 5869); a new browser and this app agree on one
//! with X25519. All of it is ring's, the TLS of the rest of the engine.

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

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
pub const RECOVERY_INFO: &str = "tterm/vault/recovery/v1";
pub const PAIR_INFO: &str = "tterm/vault/pair/v1";

/// The key of a browser's passkey lock, from its PRF output: the page's,
/// here for the vectors.
pub fn prf_kek(prf_output: &[u8]) -> Key {
    hkdf(prf_output, &[0u8; 32], PRF_INFO)
}

// ---------------------------------------------------------- recovery code

/// Crockford's base32, as the sign-in code (account.rs): no I, L, O or U.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// The code's signs: 24 of them, 120 bits.
pub const CODE_LEN: usize = 24;
/// The recovery salt's bytes, as the core keeps them.
pub const RECOVERY_SALT_LEN: usize = 16;

/// A new recovery code, as it is shown once: six groups of four signs,
/// "K7QF-29XM-PL4D-8VHT-R2NC-6WJB".
pub fn new_recovery_code() -> Zeroizing<String> {
    let bytes = Zeroizing::new(random::<15>());
    let mut signs = Zeroizing::new(String::with_capacity(CODE_LEN + 5));
    // 15 bytes are 120 bits: five at a time, from the first.
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut n = 0;
    for b in bytes.iter() {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            if n > 0 && n % 4 == 0 {
                signs.push('-');
            }
            signs.push(CROCKFORD[((acc >> bits) & 31) as usize] as char);
            n += 1;
        }
        acc &= (1 << bits) - 1;
    }
    signs
}

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
    fn recovery_codes() {
        for _ in 0..200 {
            let code = new_recovery_code();
            assert_eq!(code.len(), 29, "{}", code.as_str());
            assert_eq!(code.split('-').count(), 6);
            assert!(code.split('-').all(|g| g.len() == 4));
            assert_eq!(normalize_code(&code).unwrap().len(), CODE_LEN);
        }
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
