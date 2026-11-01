//! What the vault signs (sshkeys::check_login): a login with the key itself,
//! and nothing else. The cases in userauth-vectors.json are real signing
//! inputs that asyncssh (the core's client, through a key pair shaped like
//! the core's RelayKeyPair) and OpenSSH's ssh (through an agent that wrote
//! the request down) handed to the key as they logged in to a local server,
//! for each type the vault keeps, RSA with both hashes; the keys are
//! throwaway ones, in the vault's plaintext form. Each is signed, and the
//! signature verifies. Changed a little (bytes after it, another key, an
//! algorithm other than the request's, a session id too short or too long,
//! another message, service, method, a query), or not a login at all (an
//! SSHSIG, a git commit's text), nothing is signed.

#![cfg(feature = "cloud")]

use ring::signature;
use serde_json::Value;
use tterm_engine::crypto::from_b64u;
use tterm_engine::sshkeys::{self, NotLogin, SignError};

fn vectors() -> Value {
    serde_json::from_str(include_str!("userauth-vectors.json")).expect("JSON")
}

fn case<'a>(v: &'a Value, source: &str, key: &str, alg: &str) -> &'a Value {
    v["cases"].as_array().unwrap().iter().find(|c| c["source"].as_str().unwrap().starts_with(source) && c["key"] == key && c["alg"] == alg).unwrap_or_else(|| panic!("no case {source} {key} {alg}"))
}

/// The fields of a login, to change one and write it again.
struct Fields {
    session: Vec<u8>,
    message: u8,
    user: Vec<u8>,
    service: Vec<u8>,
    method: Vec<u8>,
    flag: u8,
    alg: Vec<u8>,
    blob: Vec<u8>,
}

fn take(at: &mut &[u8]) -> Vec<u8> {
    let n = u32::from_be_bytes(at[..4].try_into().unwrap()) as usize;
    let v = at[4..4 + n].to_vec();
    *at = &at[4 + n..];
    v
}

fn parse(data: &[u8]) -> Fields {
    let mut at = data;
    let session = take(&mut at);
    let message = at[0];
    at = &at[1..];
    let (user, service, method) = (take(&mut at), take(&mut at), take(&mut at));
    let flag = at[0];
    at = &at[1..];
    let (alg, blob) = (take(&mut at), take(&mut at));
    assert!(at.is_empty());
    Fields { session, message, user, service, method, flag, alg, blob }
}

fn write(f: &Fields) -> Vec<u8> {
    let string = |out: &mut Vec<u8>, v: &[u8]| {
        out.extend_from_slice(&(v.len() as u32).to_be_bytes());
        out.extend_from_slice(v);
    };
    let mut out = Vec::new();
    string(&mut out, &f.session);
    out.push(f.message);
    string(&mut out, &f.user);
    string(&mut out, &f.service);
    string(&mut out, &f.method);
    out.push(f.flag);
    string(&mut out, &f.alg);
    string(&mut out, &f.blob);
    out
}

fn verify(public_openssh: &str, alg: &str, data: &[u8], sig: &[u8]) {
    let key = ssh_key::PublicKey::from_openssh(public_openssh).expect("a public key");
    use ssh_key::public::{EcdsaPublicKey, KeyData};
    match (alg, key.key_data()) {
        (sshkeys::ALG_ED25519, KeyData::Ed25519(k)) => signature::UnparsedPublicKey::new(&signature::ED25519, k.0.as_slice()).verify(data, sig),
        (sshkeys::ALG_P256, KeyData::Ecdsa(EcdsaPublicKey::NistP256(p))) => signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, p.as_bytes()).verify(data, sig),
        (sshkeys::ALG_P384, KeyData::Ecdsa(EcdsaPublicKey::NistP384(p))) => signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, p.as_bytes()).verify(data, sig),
        (sshkeys::ALG_RSA_SHA256 | sshkeys::ALG_RSA_SHA512, KeyData::Rsa(r)) => {
            let public = signature::RsaPublicKeyComponents { n: r.n.as_positive_bytes().unwrap(), e: r.e.as_positive_bytes().unwrap() };
            let params = if alg == sshkeys::ALG_RSA_SHA256 { &signature::RSA_PKCS1_2048_8192_SHA256 } else { &signature::RSA_PKCS1_2048_8192_SHA512 };
            public.verify(params, data, sig)
        }
        other => panic!("{alg} does not fit {other:?}"),
    }
    .unwrap_or_else(|_| panic!("the {alg} signature verifies"));
}

fn refused(plaintext: &str, alg: &str, data: &[u8]) -> NotLogin {
    match sshkeys::sign(plaintext.as_bytes(), alg, data) {
        Err(SignError::NotLogin(why)) => why,
        Ok(_) => panic!("signed what is no login of this key's"),
        Err(e) => panic!("refused, but not as no login: {e:?}"),
    }
}

#[test]
fn real_logins_of_asyncssh_and_openssh_are_signed() {
    let v = vectors();
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9, "four types from both clients, and RSA's other hash");
    for c in cases {
        let (alg, plaintext, public) = (c["alg"].as_str().unwrap(), c["plaintext"].as_str().unwrap(), c["publicKey"].as_str().unwrap());
        let data = from_b64u(c["data"].as_str().unwrap()).unwrap();
        let sig = sshkeys::sign(plaintext.as_bytes(), alg, &data).unwrap_or_else(|e| panic!("{} {}: {e:?}", c["source"], c["key"]));
        verify(public, alg, &data, &sig);
        // The key's own fingerprint, from its plaintext, is ssh-keygen's.
        let fp = ssh_key::PublicKey::from_openssh(public).unwrap().fingerprint(ssh_key::HashAlg::Sha256).to_string();
        assert_eq!(sshkeys::fingerprint(plaintext.as_bytes()).unwrap(), fp);
        // Whoever logs in: the user name is not looked at (a jump host may
        // have another).
        let mut f = parse(&data);
        f.user = b"root".to_vec();
        assert!(sshkeys::sign(plaintext.as_bytes(), alg, &write(&f)).is_ok());
    }
}

#[test]
fn anything_else_is_refused() {
    let v = vectors();
    let c = case(&v, "asyncssh", "id_ed25519", "ssh-ed25519");
    let plaintext = c["plaintext"].as_str().unwrap();
    let alg = sshkeys::ALG_ED25519;
    let data = from_b64u(c["data"].as_str().unwrap()).unwrap();
    // Not a login at all.
    assert_eq!(refused(plaintext, alg, b"any bytes at all"), NotLogin::Shape);
    assert_eq!(refused(plaintext, alg, b""), NotLogin::Shape);
    let mut sshsig = b"SSHSIG".to_vec();
    sshsig.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 3, b'g', b'i', b't']);
    assert!(matches!(refused(plaintext, alg, &sshsig), NotLogin::Shape | NotLogin::SessionId));
    assert!(matches!(refused(plaintext, alg, b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@b> 0 +0000\n\nmsg\n"), NotLogin::Shape | NotLogin::SessionId));
    // A login with more after it, or cut short.
    let mut more = data.clone();
    more.push(0);
    assert_eq!(refused(plaintext, alg, &more), NotLogin::Trailing);
    assert_eq!(refused(plaintext, alg, &data[..data.len() - 1]), NotLogin::Shape);
    // Another key's login.
    let other = ssh_key::PublicKey::from_openssh(v["otherKey"]["publicKey"].as_str().unwrap()).unwrap().to_bytes().unwrap();
    let mut f = parse(&data);
    f.blob = other;
    assert_eq!(refused(plaintext, alg, &write(&f)), NotLogin::OtherKey);
    // An algorithm other than the request's, or one the vault never signs.
    assert_eq!(refused(plaintext, sshkeys::ALG_P256, &data), NotLogin::Algorithm);
    assert_eq!(refused(plaintext, "ssh-dss", &data), NotLogin::Algorithm);
    let mut f = parse(&data);
    f.alg = b"ssh-ed25519-cert-v01@openssh.com".to_vec();
    assert_eq!(refused(plaintext, alg, &write(&f)), NotLogin::Algorithm);
    // The session id: 16 to 64 bytes.
    for (len, ok) in [(15, false), (16, true), (20, true), (64, true), (65, false), (0, false)] {
        let mut f = parse(&data);
        f.session = vec![0x33; len];
        let got = sshkeys::sign(plaintext.as_bytes(), alg, &write(&f));
        assert_eq!(got.is_ok(), ok, "a session id of {len}");
        if !ok {
            assert!(matches!(got, Err(SignError::NotLogin(NotLogin::SessionId))), "{len}");
        }
    }
    // Another message, service, method; a query (no signature is TRUE).
    let changed = |change: &dyn Fn(&mut Fields)| {
        let mut f = parse(&data);
        change(&mut f);
        refused(plaintext, alg, &write(&f))
    };
    assert_eq!(changed(&|f| f.message = 51), NotLogin::NotRequest);
    assert_eq!(changed(&|f| f.service = b"ssh-userauth".to_vec()), NotLogin::Service);
    assert_eq!(changed(&|f| f.method = b"publickey-hostbound-v00@openssh.com".to_vec()), NotLogin::Method);
    assert_eq!(changed(&|f| f.method = b"hostbased".to_vec()), NotLogin::Method);
    assert_eq!(changed(&|f| f.flag = 0), NotLogin::NoSignature);
    assert_eq!(changed(&|f| f.flag = 2), NotLogin::NoSignature);
}

#[test]
fn rsa_signs_with_the_hash_its_login_names() {
    let v = vectors();
    let c256 = case(&v, "asyncssh", "id_rsa", "rsa-sha2-256");
    let c512 = case(&v, "OpenSSH", "id_rsa", "rsa-sha2-512");
    let plaintext = c256["plaintext"].as_str().unwrap();
    let d256 = from_b64u(c256["data"].as_str().unwrap()).unwrap();
    let d512 = from_b64u(c512["data"].as_str().unwrap()).unwrap();
    assert_eq!(refused(plaintext, sshkeys::ALG_RSA_SHA512, &d256), NotLogin::Algorithm);
    assert_eq!(refused(plaintext, sshkeys::ALG_RSA_SHA256, &d512), NotLogin::Algorithm);
    // The old SHA-1 name is never signed with.
    let mut f = parse(&d256);
    f.alg = b"ssh-rsa".to_vec();
    assert_eq!(refused(plaintext, "ssh-rsa", &write(&f)), NotLogin::Algorithm);
    // An ECDSA key's login is no RSA key's.
    let p256 = case(&v, "asyncssh", "id_p256", "ecdsa-sha2-nistp256");
    assert_eq!(refused(plaintext, sshkeys::ALG_P256, &from_b64u(p256["data"].as_str().unwrap()).unwrap()), NotLogin::OtherKey);
}
