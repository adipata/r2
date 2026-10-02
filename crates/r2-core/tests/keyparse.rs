//! Key material parsing (spec §4.4.3, §5.4) — port of c2 `tests/unit/test_keyparse.py`, the
//! R6 cases of `tests/unit/test_l13_hardening.py`, plus the §4.4.3 R6 fixtures (pyca's
//! curve set, explicit parameters, RSA-PSS, DSA, encrypted-input scheme sets). All fixtures
//! are generated at test time with OpenSSL.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

#[path = "support/keygen.rs"]
mod keygen;

use std::cell::RefCell;
use std::rc::Rc;

use keygen::*;
use openssl::ec::{Asn1Flag, EcGroup, EcKey, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::symm::Cipher;
use r2_core::codec::{InputFormat, decode_data};
use r2_core::error::{ConsoleError, ErrorKind};
use r2_core::keyparse::{KeyHint, PasswordCallback, parse_key_material};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyMaterial};
use secrecy::SecretString;

// ---------------------------------------------------------------------------- helpers

fn parse_one(data: &[u8]) -> KeyMaterial {
    let mut materials = parse_key_material(data, KeyHint::Auto, None).unwrap();
    assert_eq!(materials.len(), 1);
    materials.remove(0)
}

fn parse_one_hint(data: &[u8], hint: KeyHint) -> KeyMaterial {
    let mut materials = parse_key_material(data, hint, None).unwrap();
    assert_eq!(materials.len(), 1);
    materials.remove(0)
}

fn parse_with(
    data: &[u8],
    cb: &mut dyn FnMut(&str) -> r2_core::Result<SecretString>,
) -> r2_core::Result<Vec<KeyMaterial>> {
    let cb: PasswordCallback<'_> = cb;
    parse_key_material(data, KeyHint::Auto, Some(cb))
}

fn err(data: &[u8]) -> ConsoleError {
    let err = parse_key_material(data, KeyHint::Auto, None).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse, "{err:?}");
    err
}

fn err_hint(data: &[u8], hint: KeyHint) -> ConsoleError {
    let err = parse_key_material(data, hint, None).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse, "{err:?}");
    err
}

/// c2 KEY_CASES: (key, algorithm, curve, size_bits).
type KeyCase = (PKey<Private>, KeyAlgorithm, Option<Curve>, Option<u32>);

fn key_cases() -> Vec<KeyCase> {
    vec![
        (rsa_key(2048), KeyAlgorithm::Rsa, None, Some(2048)),
        (p256(), KeyAlgorithm::Ec, Some(Curve::P256), None),
        (
            ed25519(),
            KeyAlgorithm::EcEdwards,
            Some(Curve::Ed25519),
            None,
        ),
        (
            x25519(),
            KeyAlgorithm::EcMontgomery,
            Some(Curve::X25519),
            None,
        ),
    ]
}

const PASSWORD_HINT: &str =
    "provide --password or run interactively so the password can be prompted";
const WRONG_PW: &str = "incorrect password for encrypted private key (or corrupt encrypted data)";
/// pyca's prefix of a `pem` crate error (`{e:?}` follows).
const PEM_FAQ: &str = "Unable to load PEM file. See https://cryptography.io/en/latest/faq/#why-can-t-i-import-my-pem-file for more details. ";

// ------------------------------------------------------------- private-key round-trips

#[test]
fn pkcs8_pem_private_roundtrip() {
    for (key, algorithm, curve, size_bits) in key_cases() {
        let material = parse_one(&pkcs8_pem(&key));
        assert_eq!(material.key_class, KeyClass::Private);
        assert_eq!(material.algorithm, algorithm);
        assert_eq!(material.curve, curve);
        assert_eq!(material.size_bits, size_bits);
        assert_eq!(*material.data, pkcs8_der(&key)); // canonical: unencrypted PKCS#8 DER
        assert_eq!(material.label_hint, None);
    }
}

#[test]
fn pkcs8_der_private_roundtrip() {
    for (key, algorithm, curve, size_bits) in key_cases() {
        let material = parse_one(&pkcs8_der(&key));
        assert_eq!(material.key_class, KeyClass::Private);
        assert_eq!(material.algorithm, algorithm);
        assert_eq!(material.curve, curve);
        assert_eq!(material.size_bits, size_bits);
        assert_eq!(*material.data, pkcs8_der(&key));
    }
}

#[test]
fn traditional_pkcs1_rsa_roundtrip() {
    let key = rsa_key(2048);
    let rsa = key.rsa().unwrap();
    for data in [
        rsa.private_key_to_pem().unwrap(),
        rsa.private_key_to_der().unwrap(),
    ] {
        let material = parse_one(&data);
        assert_eq!(material.key_class, KeyClass::Private);
        assert_eq!(material.algorithm, KeyAlgorithm::Rsa);
        assert_eq!(*material.data, pkcs8_der(&key));
    }
}

#[test]
fn sec1_ec_roundtrip() {
    let key = p256();
    let ec = key.ec_key().unwrap();
    for data in [
        ec.private_key_to_pem().unwrap(),
        ec.private_key_to_der().unwrap(),
    ] {
        let material = parse_one(&data);
        assert_eq!(material.key_class, KeyClass::Private);
        assert_eq!(material.algorithm, KeyAlgorithm::Ec);
        assert_eq!(material.curve, Some(Curve::P256));
        assert_eq!(*material.data, pkcs8_der(&key));
    }
}

// -------------------------------------------------------------- public-key round-trips

#[test]
fn spki_pem_and_der_roundtrip() {
    for (key, algorithm, curve, size_bits) in key_cases() {
        for data in [spki_pem(&key), spki_der(&key)] {
            let material = parse_one(&data);
            assert_eq!(material.key_class, KeyClass::Public);
            assert_eq!(material.algorithm, algorithm);
            assert_eq!(material.curve, curve);
            assert_eq!(material.size_bits, size_bits);
            assert_eq!(*material.data, spki_der(&key));
        }
    }
}

#[test]
fn pkcs1_rsa_public_key_der_loads_as_spki() {
    // pyca's load_der_public_key accepts a PKCS#1 RSAPublicKey (DER try-chain step 4).
    let key = rsa_key(1024);
    let pkcs1 = key.rsa().unwrap().public_key_to_der_pkcs1().unwrap();
    let material = parse_one(&pkcs1);
    assert_eq!(material.key_class, KeyClass::Public);
    assert_eq!(material.algorithm, KeyAlgorithm::Rsa);
    assert_eq!(material.size_bits, Some(1024));
    assert_eq!(*material.data, spki_der(&key));
}

// ------------------------------------------------------------------ certificates & CSR

#[test]
fn certificate_pem_and_der() {
    let key = p256();
    let cert = cn_cert(&key, "My Test Cert");
    let der = cert.to_der().unwrap();
    let pem = cert.to_pem().unwrap();
    for data in [pem, der.clone()] {
        let material = parse_one(&data);
        assert_eq!(material.key_class, KeyClass::Certificate);
        assert_eq!(material.algorithm, KeyAlgorithm::Ec); // embedded public key's algorithm
        assert_eq!(material.curve, Some(Curve::P256));
        assert_eq!(*material.data, der); // cert retained as DER X.509
        assert_eq!(material.label_hint.as_deref(), Some("My Test Cert"));
    }
}

#[test]
fn certificate_without_cn_has_no_label_hint() {
    let key = rsa_key(2048);
    let cert = make_cert(&key, &[(Nid::ORGANIZATIONNAME, "ACME")]);
    let material = parse_one(&cert.to_der().unwrap());
    assert_eq!(material.key_class, KeyClass::Certificate);
    assert_eq!(material.algorithm, KeyAlgorithm::Rsa);
    assert_eq!(material.size_bits, Some(2048));
    assert_eq!(material.label_hint, None);
}

#[test]
fn csr_pem_and_der() {
    let key = p256();
    let csr = make_csr(&key, "csr-cn");
    for data in [csr.to_pem().unwrap(), csr.to_der().unwrap()] {
        let material = parse_one(&data);
        assert_eq!(material.key_class, KeyClass::Public); // CSR yields its public key
        assert_eq!(material.algorithm, KeyAlgorithm::Ec);
        assert_eq!(*material.data, spki_der(&key));
        assert_eq!(material.label_hint.as_deref(), Some("csr-cn"));
    }
}

// ------------------------------------------------------------------- encrypted inputs

#[test]
fn encrypted_pkcs8_with_password() {
    let key = p256();
    for data in [
        key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"hunter2")
            .unwrap(),
        key.private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), b"hunter2")
            .unwrap(),
    ] {
        let prompts = Rc::new(RefCell::new(Vec::new()));
        let mut cb = recording_cb("hunter2", prompts.clone());
        let materials = parse_with(&data, &mut cb).unwrap();
        assert_eq!(materials.len(), 1);
        assert_eq!(materials[0].key_class, KeyClass::Private);
        assert_eq!(*materials[0].data, pkcs8_der(&key));
        assert_eq!(prompts.borrow().len(), 1);
        assert!(!prompts.borrow()[0].is_empty()); // prompt text is non-empty
    }
}

#[test]
fn encrypted_input_prompt_texts() {
    let key = p256();
    let cases = [
        (
            key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"pw")
                .unwrap(),
            "Password for encrypted ENCRYPTED PRIVATE KEY",
        ),
        (
            key.private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), b"pw")
                .unwrap(),
            "Password for encrypted private key",
        ),
        (
            key.ec_key()
                .unwrap()
                .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), b"pw")
                .unwrap(),
            "Password for encrypted EC PRIVATE KEY",
        ),
    ];
    for (data, prompt) in cases {
        let prompts = Rc::new(RefCell::new(Vec::new()));
        let mut cb = recording_cb("pw", prompts.clone());
        parse_with(&data, &mut cb).unwrap();
        assert_eq!(*prompts.borrow(), vec![prompt.to_owned()]);
    }
}

#[test]
fn encrypted_traditional_pem_with_password() {
    // RFC-1421 headers (Proc-Type/DEK-Info), file path.
    let key = p256();
    let data = key
        .ec_key()
        .unwrap()
        .private_key_to_pem_passphrase(Cipher::aes_256_cbc(), b"hunter2")
        .unwrap();
    assert!(String::from_utf8_lossy(&data).contains("Proc-Type: 4,ENCRYPTED"));
    let prompts = Rc::new(RefCell::new(Vec::new()));
    let mut cb = recording_cb("hunter2", prompts.clone());
    let materials = parse_with(&data, &mut cb).unwrap();
    assert_eq!(*materials[0].data, pkcs8_der(&key));
    assert_eq!(prompts.borrow().len(), 1);
}

#[test]
fn encrypted_pkcs8_wrong_password() {
    let key = p256();
    for data in [
        key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"hunter2")
            .unwrap(),
        key.private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), b"hunter2")
            .unwrap(),
    ] {
        let err = parse_with(&data, &mut answer("wrong")).unwrap_err();
        assert_eq!(err.kind, ErrorKind::KeyParse);
        assert!(err.message.contains("password"));
        assert_eq!(err.message, WRONG_PW);
        assert_eq!(err.hint, None);
    }
}

#[test]
fn encrypted_pkcs8_without_callback() {
    let key = p256();
    let data = key
        .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"hunter2")
        .unwrap();
    let err = err(&data);
    assert!(err.message.contains("password"));
    assert_eq!(err.message, "encrypted key material requires a password");
    assert_eq!(err.hint.as_deref(), Some(PASSWORD_HINT));
}

#[test]
fn encrypted_with_empty_password_still_requires_a_password() {
    // pyca TypeError parity: "asked" counts, even when the empty password would decrypt.
    // An EMPTY answer is no password to pyca either ("Password was not given but private
    // key is encrypted", which crashed c2): r2 answers with the no-password error after the
    // prompt (§11 D12(h)), for encrypted PKCS#8 (DER and PEM) and traditional PEM alike.
    let key = p256();
    let ec = key.ec_key().unwrap();
    for (data, prompt) in [
        (
            key.private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), b"")
                .unwrap(),
            "Password for encrypted private key",
        ),
        (
            key.private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), b"pw")
                .unwrap(),
            "Password for encrypted private key",
        ),
        (
            key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"")
                .unwrap(),
            "Password for encrypted ENCRYPTED PRIVATE KEY",
        ),
        (
            ec.private_key_to_pem_passphrase(Cipher::aes_128_cbc(), b"pw")
                .unwrap(),
            "Password for encrypted EC PRIVATE KEY",
        ),
    ] {
        assert_eq!(
            err(&data).message,
            "encrypted key material requires a password"
        );
        let prompts = Rc::new(RefCell::new(Vec::new()));
        let mut cb = recording_cb("", prompts.clone());
        let err = parse_with(&data, &mut cb).unwrap_err();
        assert_eq!(err.message, "encrypted key material requires a password");
        assert_eq!(err.hint.as_deref(), Some(PASSWORD_HINT));
        assert_eq!(*prompts.borrow(), vec![prompt.to_owned()]);
    }
}

#[test]
fn password_callback_errors_propagate_unchanged() {
    let key = p256();
    let data = key
        .private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), b"pw")
        .unwrap();
    let mut abort =
        |_: &str| -> r2_core::Result<SecretString> { Err(ConsoleError::user_abort("aborted")) };
    let err = parse_with(&data, &mut abort).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
}

#[test]
fn traditional_pem_cipher_set_is_pycas() {
    // pyca 49 decrypts AES-128-CBC, AES-256-CBC and DES-EDE3-CBC; every other DEK-Info
    // cipher (AES-192-CBC, DES-CBC, CAMELLIA, AES-128-CFB…) is refused AFTER the prompt
    // with the wrong-password text (§5.4, §11 "resolved without deviation").
    r2_core::ensure_legacy_provider();
    let key = p256();
    let ec = key.ec_key().unwrap();
    let ok = [
        Cipher::aes_128_cbc(),
        Cipher::aes_256_cbc(),
        Cipher::des_ede3_cbc(),
    ];
    for cipher in ok {
        let data = ec.private_key_to_pem_passphrase(cipher, b"pw").unwrap();
        let materials = parse_with(&data, &mut answer("pw")).unwrap();
        assert_eq!(*materials[0].data, pkcs8_der(&key));
        let err = parse_with(&data, &mut answer("bad")).unwrap_err();
        assert_eq!(err.message, WRONG_PW);
    }
    let refused = [
        Cipher::aes_192_cbc(),
        Cipher::des_cbc(),
        Cipher::camellia_128_cbc(),
        Cipher::aes_128_cfb128(),
    ];
    for cipher in refused {
        let data = ec.private_key_to_pem_passphrase(cipher, b"pw").unwrap();
        let text = String::from_utf8_lossy(&data).into_owned();
        assert!(text.contains("DEK-Info"), "{text}");
        assert_eq!(
            err(&data).message,
            "encrypted key material requires a password"
        );
        let prompts = Rc::new(RefCell::new(Vec::new()));
        let mut cb = recording_cb("pw", prompts.clone());
        let err = parse_with(&data, &mut cb).unwrap_err();
        assert_eq!(err.message, WRONG_PW, "{text}");
        assert_eq!(prompts.borrow().len(), 1);
    }
}

#[test]
fn encrypted_pkcs8_scheme_set_is_pycas() {
    // PBES2 with AES-*-CBC / DES-EDE3-CBC decrypts; CAMELLIA / DES-CBC are "Unknown key
    // encryption algorithm" in pyca → c2's wrong-password text after the prompt.
    r2_core::ensure_legacy_provider();
    let key = p256();
    for cipher in [
        Cipher::aes_128_cbc(),
        Cipher::aes_192_cbc(),
        Cipher::aes_256_cbc(),
        Cipher::des_ede3_cbc(),
    ] {
        let data = key.private_key_to_pkcs8_passphrase(cipher, b"pw").unwrap();
        let materials = parse_with(&data, &mut answer("pw")).unwrap();
        assert_eq!(*materials[0].data, pkcs8_der(&key));
    }
    // RC2-CBC: pyca decrypts only rc2ParameterVersion 58 (128-bit effective key).
    let data = key
        .private_key_to_pkcs8_passphrase(Cipher::rc2_cbc(), b"pw")
        .unwrap();
    let materials = parse_with(&data, &mut answer("pw")).unwrap();
    assert_eq!(*materials[0].data, pkcs8_der(&key));
    let data = key
        .private_key_to_pkcs8_passphrase(Cipher::rc2_40_cbc(), b"pw")
        .unwrap();
    let prompts = Rc::new(RefCell::new(Vec::new()));
    let mut cb = recording_cb("pw", prompts.clone());
    let err = parse_with(&data, &mut cb).unwrap_err();
    assert_eq!(err.message, WRONG_PW);
    assert_eq!(prompts.borrow().len(), 1);
    for cipher in [Cipher::camellia_128_cbc(), Cipher::des_cbc()] {
        let data = key.private_key_to_pkcs8_passphrase(cipher, b"pw").unwrap();
        let err = parse_with(&data, &mut answer("pw")).unwrap_err();
        assert_eq!(err.message, WRONG_PW);
        let pem = key
            .private_key_to_pem_pkcs8_passphrase(cipher, b"pw")
            .unwrap();
        let err = parse_with(&pem, &mut answer("pw")).unwrap_err();
        assert_eq!(err.message, WRONG_PW);
    }
}

#[test]
fn pbkdf2_iteration_counts_above_c_int_are_the_wrong_password_text() {
    // §11 D12(k): OpenSSL's PKCS5_PBKDF2_HMAC takes a C int; rust-openssl unwraps the
    // conversion, so pyca panicked (c2 crashed: PanicException) on 2^31 iterations. r2
    // treats it as pyca's ValueError → the wrong-password text after the prompt.
    // EncryptedPrivateKeyInfo: PBES2 / PBKDF2 (salt "saltsalt", iterations 2^31,
    // hmacWithSHA256) / AES-256-CBC (zero IV), 32 zero bytes of ciphertext.
    let der_2_31 = unhex(concat!(
        "307e305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f04087361",
        "6c7473616c7402050080000000300c06082a864886f70d02090500301d06096086480165",
        "0304012a0410000000000000000000000000000000000420000000000000000000000000",
        "0000000000000000000000000000000000000000",
    ));
    // the same with 2^40 iterations (one more INTEGER content byte)
    let der_2_40 = unhex(concat!(
        "307f305b06092a864886f70d01050d304e302d06092a864886f70d01050c302004087361",
        "6c7473616c740206010000000000300c06082a864886f70d02090500301d060960864801",
        "650304012a04100000000000000000000000000000000004200000000000000000000000",
        "000000000000000000000000000000000000000000",
    ));
    for der in [der_2_31, der_2_40] {
        for data in [der.clone(), pem_wrap(&der, "ENCRYPTED PRIVATE KEY")] {
            let prompts = Rc::new(RefCell::new(Vec::new()));
            let mut cb = recording_cb("pw", prompts.clone());
            let err = parse_with(&data, &mut cb).unwrap_err();
            assert_eq!(err.kind, ErrorKind::KeyParse);
            assert_eq!(err.message, WRONG_PW);
            assert_eq!(prompts.borrow().len(), 1);
        }
    }
}

// --------------------------------------------------------------------------- PKCS#12

/// (pkcs12-DER, cert-DER, chain-cert-DER) with friendly name 'bundle', pw 'secret'.
fn p12_bundle(rsa: &PKey<Private>, ec: &PKey<Private>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let cert = cn_cert(rsa, "p12-subject");
    let chain = cn_cert(ec, "Chain CA");
    let mut stack = Stack::new().unwrap();
    stack.push(chain.clone()).unwrap();
    let mut builder = Pkcs12::builder();
    builder.name("bundle").pkey(rsa).cert(&cert).ca(stack);
    let p12 = builder.build2("secret").unwrap().to_der().unwrap();
    (p12, cert.to_der().unwrap(), chain.to_der().unwrap())
}

#[test]
fn pkcs12_multi_material_shared_label_hint() {
    let (rsa, ec) = (rsa_key(2048), p256());
    let (p12, cert_der, chain_der) = p12_bundle(&rsa, &ec);
    let prompts = Rc::new(RefCell::new(Vec::new()));
    let mut cb = recording_cb("secret", prompts.clone());
    let materials = parse_with(&p12, &mut cb).unwrap();
    let classes: Vec<KeyClass> = materials.iter().map(|m| m.key_class).collect();
    assert_eq!(
        classes,
        [
            KeyClass::Private,
            KeyClass::Certificate,
            KeyClass::Certificate
        ]
    );
    assert_eq!(*materials[0].data, pkcs8_der(&rsa));
    assert_eq!(materials[0].algorithm, KeyAlgorithm::Rsa);
    assert_eq!(*materials[1].data, cert_der);
    assert_eq!(*materials[2].data, chain_der);
    // PKCS12 friendly name, shared
    assert!(
        materials
            .iter()
            .all(|m| m.label_hint.as_deref() == Some("bundle"))
    );
    assert_eq!(*prompts.borrow(), vec!["Password for PKCS#12".to_owned()]);
}

#[test]
fn pkcs12_wrong_password() {
    let (p12, _, _) = p12_bundle(&rsa_key(2048), &p256());
    let err = parse_with(&p12, &mut answer("wrong")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(err.message.contains("password"));
    assert_eq!(
        err.message,
        "incorrect password for PKCS#12 (or corrupt PKCS#12 data)"
    );
}

#[test]
fn pkcs12_password_with_nul_is_the_wrong_password_text() {
    // §11 D16: parse2 would panic on an interior NUL; c2's answer is "wrong password".
    let (p12, _, _) = p12_bundle(&rsa_key(1024), &p256());
    let err = parse_with(&p12, &mut answer("sec\0ret")).unwrap_err();
    assert_eq!(
        err.message,
        "incorrect password for PKCS#12 (or corrupt PKCS#12 data)"
    );
}

#[test]
fn pkcs12_without_callback() {
    let (p12, _, _) = p12_bundle(&rsa_key(2048), &p256());
    let err = err(&p12);
    assert!(err.message.contains("password"));
    assert_eq!(
        err.message,
        "PKCS#12 requires a password (or the PKCS#12 data is corrupt)"
    );
    assert_eq!(err.hint.as_deref(), Some(PASSWORD_HINT));
}

#[test]
fn pkcs12_unencrypted_needs_no_callback() {
    // pyca NoEncryption: unencrypted bags (keyBag, plain certBag) — no callback needed.
    let key = p256();
    let cert = cn_cert(&key, "plain");
    let mut builder = Pkcs12::builder();
    builder
        .name("plain")
        .pkey(&key)
        .cert(&cert)
        .key_algorithm(Nid::from_raw(-1))
        .cert_algorithm(Nid::from_raw(-1));
    let unencrypted = builder.build2("").unwrap().to_der().unwrap();
    // … and bags encrypted with the empty password load the same way (parse2("")).
    let mut builder = Pkcs12::builder();
    builder.name("plain").pkey(&key).cert(&cert);
    let empty_password = builder.build2("").unwrap().to_der().unwrap();
    for p12 in [unencrypted, empty_password] {
        let materials = parse_key_material(&p12, KeyHint::Auto, None).unwrap();
        let classes: Vec<KeyClass> = materials.iter().map(|m| m.key_class).collect();
        assert_eq!(classes, [KeyClass::Private, KeyClass::Certificate]);
        assert_eq!(*materials[0].data, pkcs8_der(&key));
        assert!(
            materials
                .iter()
                .all(|m| m.label_hint.as_deref() == Some("plain"))
        );
    }
}

/// The PFX without its MacData (`openssl pkcs12 -export -nomac`).
fn strip_mac(p12: &[u8]) -> Vec<u8> {
    fn tlv_len(data: &[u8]) -> (usize, usize) {
        let first = data[1];
        if first < 0x80 {
            (2, usize::from(first))
        } else {
            let n = usize::from(first & 0x7f);
            let len = data[2..2 + n]
                .iter()
                .fold(0usize, |acc, b| acc * 256 + usize::from(*b));
            (2 + n, len)
        }
    }
    let (header, _) = tlv_len(p12);
    let body = &p12[header..];
    let (vh, vl) = tlv_len(body);
    let rest = &body[vh + vl..];
    let (ah, al) = tlv_len(rest);
    let mut content = body[..vh + vl].to_vec();
    content.extend_from_slice(&rest[..ah + al]);
    tlv(0x30, &content)
}

#[test]
fn pkcs12_without_a_mac_loads_with_its_password() {
    // `openssl pkcs12 -export -nomac`: pyca (and c2) load it with the password; OpenSSL 3.0's
    // PKCS12_parse wants a MAC for a non-empty password, so r2 supplies one.
    r2_core::ensure_legacy_provider();
    let key = p256();
    let cert = cn_cert(&key, "nomac");
    let mut builder = Pkcs12::builder();
    builder.name("fn").pkey(&key).cert(&cert);
    let p12 = strip_mac(&builder.build2("pw").unwrap().to_der().unwrap());
    let prompts = Rc::new(RefCell::new(Vec::new()));
    let mut cb = recording_cb("pw", prompts.clone());
    let materials = parse_with(&p12, &mut cb).unwrap();
    assert_eq!(*materials[0].data, pkcs8_der(&key));
    assert_eq!(*materials[1].data, cert.to_der().unwrap());
    assert!(
        materials
            .iter()
            .all(|m| m.label_hint.as_deref() == Some("fn"))
    );
    assert_eq!(*prompts.borrow(), vec!["Password for PKCS#12".to_owned()]);
    assert_eq!(
        parse_with(&p12, &mut answer("bad")).unwrap_err().message,
        "incorrect password for PKCS#12 (or corrupt PKCS#12 data)"
    );
    assert_eq!(
        err(&p12).message,
        "PKCS#12 requires a password (or the PKCS#12 data is corrupt)"
    );
    // without a MAC and without bag encryption: no password at all
    let mut builder = Pkcs12::builder();
    builder
        .pkey(&key)
        .cert(&cert)
        .key_algorithm(Nid::from_raw(-1))
        .cert_algorithm(Nid::from_raw(-1));
    let p12 = strip_mac(&builder.build2("").unwrap().to_der().unwrap());
    let materials = parse_key_material(&p12, KeyHint::Auto, None).unwrap();
    assert!(
        materials
            .iter()
            .all(|m| m.label_hint.as_deref() == Some("nomac"))
    );
}

#[test]
fn pkcs12_without_friendly_name_uses_subject_cn() {
    let key = p256();
    let cert = cn_cert(&key, "cn-label");
    let mut builder = Pkcs12::builder();
    builder.pkey(&key).cert(&cert);
    let p12 = builder.build2("pw").unwrap().to_der().unwrap();
    let materials = parse_with(&p12, &mut answer("pw")).unwrap();
    assert!(
        materials
            .iter()
            .all(|m| m.label_hint.as_deref() == Some("cn-label"))
    );
}

#[test]
fn legacy_pkcs12_rc2_3des_sha1_loads() {
    // `openssl pkcs12 -export -legacy`: RC2-40 certificate bag, 3DES key bag, SHA-1 MAC.
    r2_core::ensure_legacy_provider();
    let key = rsa_key(1024);
    let cert = cn_cert(&key, "legacy");
    let mut builder = Pkcs12::builder();
    builder
        .name("legacy")
        .pkey(&key)
        .cert(&cert)
        .key_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
        .cert_algorithm(Nid::PBE_WITHSHA1AND40BITRC2_CBC)
        .mac_md(openssl::hash::MessageDigest::sha1());
    let p12 = builder.build2("pw").unwrap().to_der().unwrap();
    let materials = parse_with(&p12, &mut answer("pw")).unwrap();
    assert_eq!(*materials[0].data, pkcs8_der(&key));
    assert_eq!(*materials[1].data, cert.to_der().unwrap());
}

// ---------------------------------------------------------------------------- raw AES

#[test]
fn raw_aes() {
    for length in [16usize, 24, 32] {
        for hint in [KeyHint::Auto, KeyHint::Aes] {
            let data: Vec<u8> = (0..length as u8).collect();
            let material = parse_one_hint(&data, hint);
            assert_eq!(material.key_class, KeyClass::Secret);
            assert_eq!(material.algorithm, KeyAlgorithm::Aes);
            assert_eq!(material.size_bits, Some(length as u32 * 8));
            assert_eq!(*material.data, data);
        }
    }
}

#[test]
fn raw_aes_bad_length() {
    let err = err_hint(&[0xaa; 20], KeyHint::Aes);
    assert!(err.message.contains("attempted"));
}

#[test]
fn raw_bytes_not_allowed_for_non_aes_hint() {
    err_hint(&[0xaa; 32], KeyHint::Rsa);
}

// ------------------------------------------------------------------- hex-wrapped PEM

#[test]
fn hex_wrapped_pem_through_codec() {
    let key = p256();
    let pem = pkcs8_pem(&key);
    let (data, fmt) = decode_data(&hex(&pem)).unwrap();
    assert_eq!(fmt, InputFormat::Pem); // codec unwraps hex → re-wrapped PEM text bytes
    let material = parse_one(&data);
    assert_eq!(material.key_class, KeyClass::Private);
    assert_eq!(*material.data, pkcs8_der(&key));
}

#[test]
fn mangled_pasted_pem_through_codec() {
    // single-line paste: newlines collapsed to spaces; codec re-wraps, keyparse parses
    let key = rsa_key(2048);
    let pem = String::from_utf8(pkcs8_pem(&key))
        .unwrap()
        .replace('\n', " ");
    let (data, fmt) = decode_data(&pem).unwrap();
    assert_eq!(fmt, InputFormat::Pem);
    assert_eq!(*parse_one(&data).data, pkcs8_der(&key));
}

// ---------------------------------------------------------------------- hint handling

#[test]
fn hint_mismatch_cases() {
    let (rsa, ec, ed) = (rsa_key(2048), p256(), ed25519());
    let cert_der = cn_cert(&rsa, "c").to_der().unwrap();
    let cases: Vec<(Vec<u8>, KeyHint)> = vec![
        (pkcs8_pem(&rsa), KeyHint::Aes), // spec's example: hint=aes, data is PEM RSA
        (pkcs8_der(&ec), KeyHint::Rsa),
        (spki_der(&rsa), KeyHint::Ec),
        (pkcs8_der(&rsa), KeyHint::Cert),
        (cert_der, KeyHint::Aes),
        (pkcs8_der(&ed), KeyHint::Rsa),
    ];
    for (data, hint) in cases {
        let err = err_hint(&data, hint);
        assert!(err.message.contains("hint"));
        assert_eq!(
            err.hint.as_deref(),
            Some("use hint='auto' or the hint matching the pasted material")
        );
    }
    assert_eq!(
        err_hint(&pkcs8_pem(&rsa), KeyHint::Aes).message,
        "parsed rsa private material but hint is 'aes'"
    );
    assert_eq!(
        err_hint(&cn_cert(&ec, "c").to_der().unwrap(), KeyHint::Rsa).message,
        "parsed ec certificate material but hint is 'rsa'"
    );
}

#[test]
fn hint_matches() {
    let (rsa, ec, ed, x) = (rsa_key(2048), p256(), ed25519(), x25519());
    let cert_der = cn_cert(&rsa, "c").to_der().unwrap();
    assert_eq!(
        parse_one_hint(&pkcs8_der(&rsa), KeyHint::Rsa).algorithm,
        KeyAlgorithm::Rsa
    );
    assert_eq!(
        parse_one_hint(&pkcs8_der(&ec), KeyHint::Ec).algorithm,
        KeyAlgorithm::Ec
    );
    // the whole EC family counts as "ec"
    assert_eq!(
        parse_one_hint(&pkcs8_der(&ed), KeyHint::Ec).algorithm,
        KeyAlgorithm::EcEdwards
    );
    assert_eq!(
        parse_one_hint(&pkcs8_der(&x), KeyHint::Ec).algorithm,
        KeyAlgorithm::EcMontgomery
    );
    assert_eq!(
        parse_one_hint(&cert_der, KeyHint::Cert).key_class,
        KeyClass::Certificate
    );
    // certificates satisfy the algorithm hint of their embedded public key
    assert_eq!(
        parse_one_hint(&cert_der, KeyHint::Rsa).key_class,
        KeyClass::Certificate
    );
}

#[test]
fn unknown_hint_value() {
    let err = "bogus".parse::<KeyHint>().unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(err.message.contains("hint"));
    assert_eq!(err.message, "unknown key material hint 'bogus'");
    assert_eq!(
        err.hint.as_deref(),
        Some("valid hints: auto, aes, rsa, ec, cert")
    );
    for hint in [
        KeyHint::Auto,
        KeyHint::Aes,
        KeyHint::Rsa,
        KeyHint::Ec,
        KeyHint::Cert,
    ] {
        assert_eq!(hint.as_str().parse::<KeyHint>().unwrap(), hint);
    }
    assert_eq!(KeyHint::default(), KeyHint::Auto);
    assert!("AES".parse::<KeyHint>().is_err());
}

// --------------------------------------------------------------------- garbage inputs

#[test]
fn garbage_input_lists_attempted_formats() {
    let err = err(b"\x01\x02\x03 definitely not a key \xff\xfe");
    assert!(err.message.contains("attempted"));
    assert_eq!(
        err.message,
        "could not parse key material (attempted: PEM, DER (PKCS#8, SPKI, PKCS#1, SEC1, X.509, CSR, PKCS#12), raw AES (16/24/32 bytes))"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some(
            "supported inputs: PEM/DER keys, certificates, CSRs, PKCS#12, raw AES keys of 16/24/32 bytes"
        )
    );
}

#[test]
fn empty_input() {
    let err = err(b"");
    assert!(err.message.contains("empty"));
    assert_eq!(err.message, "empty key material");
}

#[test]
fn garbage_der_prefix() {
    let mut data = vec![0x30];
    data.extend([0xa5; 40]);
    assert!(err(&data).message.contains("attempted"));
}

#[test]
fn truncated_pem_block() {
    let err = err(b"-----BEGIN CERTIFICATE-----\nAAAA\n");
    assert!(err.message.contains("PEM"));
    assert_eq!(err.message, "no complete PEM block found");
    assert_eq!(
        err.hint.as_deref(),
        Some("a PEM block is '-----BEGIN <LABEL>----- … -----END <LABEL>-----'")
    );
}

#[test]
fn mismatched_pem_labels() {
    let err = err(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END PUBLIC KEY-----\n");
    assert!(err.message.contains("closed by"));
    assert_eq!(
        err.message,
        "PEM block 'BEGIN CERTIFICATE' is closed by 'END PUBLIC KEY'"
    );
}

#[test]
fn unsupported_pem_label() {
    let data = b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
    let err = err(data);
    assert!(err.message.contains("unsupported PEM block"));
    assert_eq!(
        err.message,
        "unsupported PEM block type 'OPENSSH PRIVATE KEY'"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some(
            "supported PEM blocks: PRIVATE KEY, ENCRYPTED PRIVATE KEY, RSA/EC PRIVATE KEY, PUBLIC KEY, CERTIFICATE, CERTIFICATE REQUEST"
        )
    );
}

#[test]
fn corrupt_pem_body() {
    let data = b"-----BEGIN CERTIFICATE-----\nnot!base64@@\n-----END CERTIFICATE-----\n";
    let err = err(data);
    assert!(err.message.contains("CERTIFICATE"));
    assert!(
        err.message.starts_with("malformed CERTIFICATE PEM block: "),
        "{}",
        err.message
    );
}

#[test]
fn pem_marker_in_non_utf8_data() {
    let mut data = b"-----BEGIN X-----".to_vec();
    data.push(0xff);
    assert_eq!(
        err(&data).message,
        "data contains a PEM marker but is not valid text"
    );
}

#[test]
fn pem_labels_strip_spaces_before_comparing() {
    // c2 compares the stripped labels (so this is not "closed by"), but pyca's PEM parser
    // compares the raw tags: "malformed … PEM block" with pyca's MismatchedTags text.
    let key = p256();
    let pem = String::from_utf8(spki_pem(&key))
        .unwrap()
        .replace("-----END PUBLIC KEY-----", "-----END PUBLIC KEY -----");
    assert_eq!(
        err(pem.as_bytes()).message,
        format!(
            "malformed PUBLIC KEY PEM block: {PEM_FAQ}MismatchedTags(\"PUBLIC KEY\", \"PUBLIC KEY \")"
        )
    );
    // equal raw tags with a trailing space: pyca's tag filter refuses the block
    let pem = String::from_utf8(cn_cert(&key, "x").to_pem().unwrap())
        .unwrap()
        .replace("CERTIFICATE-----", "CERTIFICATE -----");
    assert_eq!(
        err(pem.as_bytes()).message,
        "malformed CERTIFICATE PEM block: Valid PEM but no BEGIN CERTIFICATE/END CERTIFICATE delimiters. Are you sure this is a certificate?"
    );
}

// ------------------------------------------------------------------- multi-block PEM

#[test]
fn multiblock_pem_bundle() {
    let (rsa, ec) = (rsa_key(2048), p256());
    let cert = cn_cert(&ec, "bundle-cert");
    let mut data = pkcs8_pem(&rsa);
    data.extend(cert.to_pem().unwrap());
    let materials = parse_key_material(&data, KeyHint::Auto, None).unwrap();
    let classes: Vec<KeyClass> = materials.iter().map(|m| m.key_class).collect();
    assert_eq!(classes, [KeyClass::Private, KeyClass::Certificate]);
    assert_eq!(*materials[0].data, pkcs8_der(&rsa));
    assert_eq!(*materials[1].data, cert.to_der().unwrap());
    assert_eq!(materials[1].label_hint.as_deref(), Some("bundle-cert"));
}

// ----------------------------------------------- lazily-parsed corrupt embedded SPKIs

/// Zero the X‖Y bytes of the EC point inside `der` (keeps the 0x04 prefix).
fn corrupt_spki(der: &[u8], key: &PKey<Private>) -> Vec<u8> {
    let ec = key.ec_key().unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let point = ec
        .public_key()
        .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
        .unwrap();
    let pos = der
        .windows(point.len())
        .position(|w| w == point.as_slice())
        .expect("the point must actually occur");
    let mut out = der.to_vec();
    for byte in &mut out[pos + 1..pos + point.len()] {
        *byte = 0;
    }
    out
}

#[test]
fn certificate_with_corrupt_spki() {
    let key = p256();
    let bad_der = corrupt_spki(&cn_cert(&key, "bad-spki").to_der().unwrap(), &key);
    // sanity: the certificate itself still parses — the failure is lazy
    openssl::x509::X509::from_der(&bad_der).unwrap();
    for data in [bad_der.clone(), pem_wrap(&bad_der, "CERTIFICATE")] {
        let err = err(&data);
        assert!(
            err.message.contains("invalid public key"),
            "{}",
            err.message
        );
        assert!(
            err.message
                .starts_with("certificate contains an invalid public key: ")
        );
    }
}

#[test]
fn csr_with_corrupt_spki() {
    let key = p256();
    let bad_der = corrupt_spki(&make_csr(&key, "bad-spki").to_der().unwrap(), &key);
    openssl::x509::X509Req::from_der(&bad_der).unwrap(); // sanity: loads fine, fails lazily
    for data in [bad_der.clone(), pem_wrap(&bad_der, "CERTIFICATE REQUEST")] {
        let err = err(&data);
        assert!(
            err.message.contains("invalid public key"),
            "{}",
            err.message
        );
        assert!(
            err.message
                .starts_with("certificate request contains an invalid public key: ")
        );
    }
}

#[test]
fn pkcs12_with_corrupt_chain_cert_spki() {
    let key = p256();
    let cert = cn_cert(&key, "good");
    let bad_chain =
        openssl::x509::X509::from_der(&corrupt_spki(&cert.to_der().unwrap(), &key)).unwrap();
    let mut stack = Stack::new().unwrap();
    stack.push(bad_chain).unwrap();
    let mut builder = Pkcs12::builder();
    builder.name("bad-chain").pkey(&key).cert(&cert).ca(stack);
    let p12 = builder.build2("").unwrap().to_der().unwrap();
    let err = err(&p12);
    assert!(
        err.message.contains("invalid public key"),
        "{}",
        err.message
    );
}

#[test]
fn p12_shaped_garbage_without_callback_hedges_corruption() {
    // valid PFX version marker (SEQUENCE { INTEGER 3 …) but otherwise garbage: without a
    // callback the error must not claim with certainty that a password is missing
    let mut data = b"\x30\x82\x01\x00\x02\x01\x03".to_vec();
    data.extend([0xaa; 200]);
    let err = err(&data);
    assert!(err.message.contains("corrupt"));
    // with a callback: prompted, then the hedged wrong-password text
    let err = parse_with(&data, &mut answer("x")).unwrap_err();
    assert_eq!(
        err.message,
        "incorrect password for PKCS#12 (or corrupt PKCS#12 data)"
    );
}

// ----------------------------------- §4.4.3 R6 fixtures: curves, explicit params, PSS, DSA

#[test]
fn other_pyca_curves_load_with_pycas_lowercase_names() {
    let cases = [
        (Nid::X9_62_PRIME192V1, "secp192r1"),
        (Nid::SECP224R1, "secp224r1"),
        (Nid::SECP256K1, "secp256k1"),
        (Nid::BRAINPOOL_P256R1, "brainpoolp256r1"),
        (Nid::BRAINPOOL_P384R1, "brainpoolp384r1"),
        (Nid::BRAINPOOL_P512R1, "brainpoolp512r1"),
    ];
    for (nid, name) in cases {
        let key = ec_key(nid);
        for data in [pkcs8_der(&key), pkcs8_pem(&key), spki_der(&key)] {
            let material = parse_one(&data);
            assert_eq!(material.algorithm, KeyAlgorithm::Ec);
            assert_eq!(material.curve, Some(Curve::Other(name.to_owned())));
            assert_eq!(material.size_bits, None);
        }
        let cert = parse_one(&cn_cert(&key, "c").to_der().unwrap());
        assert_eq!(cert.curve, Some(Curve::Other(name.to_owned())));
    }
    for (nid, curve) in [(Nid::SECP384R1, Curve::P384), (Nid::SECP521R1, Curve::P521)] {
        let key = ec_key(nid);
        let material = parse_one(&pkcs8_der(&key));
        assert_eq!(material.curve, Some(curve));
        assert_eq!(*material.data, pkcs8_der(&key));
    }
}

#[test]
fn unsupported_curves_are_rejected_with_pycas_text() {
    let cases = [
        (Nid::X9_62_PRIME239V1, "1.2.840.10045.3.1.4"),
        (Nid::SECP112R1, "1.3.132.0.6"),
        (Nid::SECT163K1, "1.3.132.0.1"),
    ];
    for (nid, oid) in cases {
        let key = ec_key(nid);
        let detail = format!("Curve {oid} is not supported");
        // PEM → malformed {label} PEM block
        assert_eq!(
            err(&pkcs8_pem(&key)).message,
            format!("malformed PRIVATE KEY PEM block: {detail}")
        );
        let sec1 = key.ec_key().unwrap().private_key_to_pem().unwrap();
        assert_eq!(
            err(&sec1).message,
            format!("malformed EC PRIVATE KEY PEM block: {detail}")
        );
        assert_eq!(
            err(&spki_pem(&key)).message,
            format!("malformed PUBLIC KEY PEM block: {detail}")
        );
        // DER → the try-chain step fails and the chain continues
        assert!(
            err(&pkcs8_der(&key))
                .message
                .starts_with("could not parse key material")
        );
        assert!(
            err(&spki_der(&key))
                .message
                .starts_with("could not parse key material")
        );
        // certificate / CSR → invalid public key (c2 crashed: §11 D12 b)
        let ecdsa_signer = p256();
        let mut cert = cn_cert(&ecdsa_signer, "x");
        let mut builder = openssl::x509::X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(cert.subject_name()).unwrap();
        builder.set_issuer_name(cert.subject_name()).unwrap();
        builder.set_not_before(cert.not_before()).unwrap();
        builder.set_not_after(cert.not_after()).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .sign(&ecdsa_signer, openssl::hash::MessageDigest::sha256())
            .unwrap();
        cert = builder.build();
        let der = cert.to_der().unwrap();
        for data in [der.clone(), pem_wrap(&der, "CERTIFICATE")] {
            assert_eq!(
                err(&data).message,
                format!("certificate contains an invalid public key: {detail}")
            );
        }
        let mut req = openssl::x509::X509Req::builder().unwrap();
        req.set_pubkey(&key).unwrap();
        req.sign(&ecdsa_signer, openssl::hash::MessageDigest::sha256())
            .unwrap();
        let req = req.build().to_der().unwrap();
        assert_eq!(
            err(&req).message,
            format!("certificate request contains an invalid public key: {detail}")
        );
    }
}

fn explicit(key: &PKey<Private>) -> PKey<Private> {
    let ec = key.ec_key().unwrap();
    let nid = ec.group().curve_name().unwrap();
    let mut group = EcGroup::from_curve_name(nid).unwrap();
    group.set_asn1_flag(Asn1Flag::EXPLICIT_CURVE);
    let key = EcKey::from_private_components(&group, ec.private_key(), ec.public_key()).unwrap();
    PKey::from_ec_key(key).unwrap()
}

#[test]
fn explicit_parameter_p256_key_is_reencoded_on_the_named_curve() {
    let key = p256();
    let explicit_key = explicit(&key);
    let explicit_der = pkcs8_der(&explicit_key);
    assert_ne!(explicit_der, pkcs8_der(&key)); // the fixture really is explicit
    for data in [explicit_der, pkcs8_pem(&explicit_key)] {
        let material = parse_one(&data);
        assert_eq!(material.curve, Some(Curve::P256));
        assert_eq!(*material.data, pkcs8_der(&key));
    }
    let material = parse_one(&spki_der(&explicit_key));
    assert_eq!(material.curve, Some(Curve::P256));
    assert_eq!(*material.data, spki_der(&key));
    // P-384 / P-521 too
    for nid in [Nid::SECP384R1, Nid::SECP521R1] {
        let key = ec_key(nid);
        assert_eq!(
            *parse_one(&pkcs8_der(&explicit(&key))).data,
            pkcs8_der(&key)
        );
    }
}

#[test]
fn explicit_parameters_of_other_curves_are_refused() {
    // pyca maps explicit parameters only to secp256r1/secp384r1/secp521r1.
    let text = "ECDSA keys with explicit parameters are only supported when they map to secp256r1, secp384r1, or secp521r1. No custom curves are supported.";
    for nid in [Nid::SECP224R1, Nid::BRAINPOOL_P256R1] {
        let key = explicit(&ec_key(nid));
        assert_eq!(
            err(&pkcs8_pem(&key)).message,
            format!("malformed PRIVATE KEY PEM block: {text}")
        );
        assert!(err(&pkcs8_der(&key)).message.starts_with("could not parse"));
    }
}

#[test]
fn compressed_points_are_reencoded_uncompressed() {
    let key = p256();
    let ec = key.ec_key().unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let compressed = ec
        .public_key()
        .to_bytes(ec.group(), PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();
    let spki = spki_der(&key);
    let uncompressed = ec
        .public_key()
        .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
        .unwrap();
    // SPKI with the compressed point: rebuild the header around it
    let header_len = spki.len() - uncompressed.len();
    let mut body = spki[2..header_len].to_vec();
    let bitstring_len_pos = body.len() - 2;
    body[bitstring_len_pos] = (compressed.len() + 1) as u8;
    body.extend(&compressed);
    let mut compressed_spki = vec![0x30, body.len() as u8];
    compressed_spki.extend(body);
    let material = parse_one(&compressed_spki);
    assert_eq!(*material.data, spki);
}

/// An rsassaPss PKCS#8: the rsaEncryption AlgorithmIdentifier swapped for id-RSASSA-PSS
/// (no parameters), the RSAPrivateKey unchanged.
fn rsa_pss_pkcs8(rsa_pkcs8: &[u8]) -> Vec<u8> {
    let rsa_alg = unhex("300d06092a864886f70d0101010500");
    let pss_alg = unhex("300b06092a864886f70d01010a");
    let pos = rsa_pkcs8
        .windows(rsa_alg.len())
        .position(|w| w == rsa_alg.as_slice())
        .unwrap();
    let mut inner = rsa_pkcs8[4..pos].to_vec(); // after the outer 30 82 xx xx
    inner.extend(&pss_alg);
    inner.extend(&rsa_pkcs8[pos + rsa_alg.len()..]);
    let mut out = vec![0x30, 0x82, (inner.len() >> 8) as u8, inner.len() as u8];
    out.extend(inner);
    out
}

#[test]
fn rsa_pss_keys_load_as_plain_rsa() {
    let key = rsa_key(2048);
    let pss = rsa_pss_pkcs8(&pkcs8_der(&key));
    let pss_key = PKey::private_key_from_der(&pss).unwrap();
    assert_eq!(pss_key.id(), openssl::pkey::Id::RSA_PSS); // the fixture really is PSS
    let material = parse_one(&pss);
    assert_eq!(material.algorithm, KeyAlgorithm::Rsa);
    assert_eq!(material.size_bits, Some(2048));
    assert_eq!(*material.data, pkcs8_der(&key)); // rebuilt as rsaEncryption
    let material = parse_one(&pem_wrap(&pss, "PRIVATE KEY"));
    assert_eq!(*material.data, pkcs8_der(&key));
    let pss_spki = pss_key.public_key_to_der().unwrap();
    assert_ne!(pss_spki, spki_der(&key));
    assert_eq!(*parse_one(&pss_spki).data, spki_der(&key));
}

#[test]
fn rsa_size_bits_is_the_modulus_bit_length() {
    let key = rsa_key(1023);
    assert_eq!(parse_one(&pkcs8_der(&key)).size_bits, Some(1023));
}

#[test]
fn dsa_keys_are_unsupported_algorithms() {
    let dsa = openssl::dsa::Dsa::generate(1024).unwrap();
    let key = PKey::from_dsa(dsa).unwrap();
    for (data, class) in [
        (pkcs8_der(&key), "DSAPrivateKey"),
        (pkcs8_pem(&key), "DSAPrivateKey"),
        (spki_der(&key), "DSAPublicKey"),
    ] {
        let err = err(&data);
        assert_eq!(err.message, format!("unsupported key algorithm: {class}"));
        assert_eq!(
            err.hint.as_deref(),
            Some("supported: AES, RSA, EC, Ed25519/Ed448, X25519/X448")
        );
    }
}

#[test]
fn ed448_and_x448_classify() {
    let material = parse_one(&pkcs8_der(&ed448()));
    assert_eq!(
        (material.algorithm, material.curve, material.size_bits),
        (KeyAlgorithm::EcEdwards, Some(Curve::Ed448), None)
    );
    let material = parse_one(&spki_pem(&x448()));
    assert_eq!(
        (material.algorithm, material.curve, material.size_bits),
        (KeyAlgorithm::EcMontgomery, Some(Curve::X448), None)
    );
}

// ------------------------------------------------- test_l13_hardening (R6 cases)

fn encrypted_traditional_pem() -> (String, PKey<Private>) {
    let key = p256();
    let pem = key
        .ec_key()
        .unwrap()
        .private_key_to_pem_passphrase(Cipher::aes_256_cbc(), b"s3cret")
        .unwrap();
    let pem = String::from_utf8(pem).unwrap();
    assert!(pem.contains("Proc-Type: 4,ENCRYPTED")); // RFC-1421 headers
    (pem, key)
}

#[test]
fn encrypted_traditional_pem_paste_keeps_headers() {
    let (pem, key) = encrypted_traditional_pem();
    let (data, fmt) = decode_data(&pem).unwrap();
    assert_eq!(fmt, InputFormat::Pem);
    let text = String::from_utf8(data.to_vec()).unwrap();
    assert!(text.contains("Proc-Type: 4,ENCRYPTED"));
    assert!(text.contains("DEK-Info: "));
    let header_end = text.find("DEK-Info").unwrap();
    assert!(text[header_end..].contains("\n\n")); // RFC 1421: blank line closes headers
    let materials = parse_with(&data, &mut answer("s3cret")).unwrap();
    let classes: Vec<KeyClass> = materials.iter().map(|m| m.key_class).collect();
    assert_eq!(classes, [KeyClass::Private]);
    let reloaded = PKey::private_key_from_der(&materials[0].data).unwrap();
    assert_eq!(
        reloaded.ec_key().unwrap().private_key().to_vec(),
        key.ec_key().unwrap().private_key().to_vec()
    );
}

#[test]
fn encrypted_traditional_pem_survives_indented_paste() {
    let (pem, _key) = encrypted_traditional_pem();
    let indented: Vec<String> = pem.lines().map(|line| format!("   {line}")).collect();
    let (data, fmt) = decode_data(&indented.join("\n")).unwrap();
    assert_eq!(fmt, InputFormat::Pem);
    assert!(String::from_utf8_lossy(&data).contains("DEK-Info: "));
    let materials = parse_with(&data, &mut answer("s3cret")).unwrap();
    assert_eq!(materials[0].algorithm, KeyAlgorithm::Ec);
}

#[test]
fn key_material_debug_never_shows_bytes() {
    let material = parse_one(&[7u8; 16]);
    let debug = format!("{material:?}");
    assert!(debug.contains("<16 bytes>"), "{debug}");
}

#[test]
fn encrypted_label_with_a_non_encrypted_body_is_malformed_without_prompting() {
    let key = p256();
    let data = pem_wrap(&spki_der(&key), "ENCRYPTED PRIVATE KEY");
    let prompts = Rc::new(RefCell::new(Vec::new()));
    let mut cb = recording_cb("pw", prompts.clone());
    let err = parse_with(&data, &mut cb).unwrap_err();
    assert!(
        err.message
            .starts_with("malformed ENCRYPTED PRIVATE KEY PEM block: "),
        "{}",
        err.message
    );
    assert!(prompts.borrow().is_empty());
}

#[test]
fn a_refused_key_inside_an_encrypted_container_is_the_wrong_password_text() {
    // c2: the decrypt-and-load step catches pyca's UnsupportedAlgorithm as "incorrect password".
    let key = ec_key(Nid::SECP112R1);
    let data = key
        .private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), b"pw")
        .unwrap();
    let err = parse_with(&data, &mut answer("pw")).unwrap_err();
    assert_eq!(err.message, WRONG_PW);
}

// ------------------------------------------- pyca's DER strictness for key material

/// The outer SEQUENCE length re-encoded one byte longer (BER, not DER).
fn nonminimal_outer_length(der: &[u8]) -> Vec<u8> {
    assert_eq!(der[0], 0x30);
    if der[1] < 0x80 {
        let mut out = vec![0x30, 0x81, der[1]];
        out.extend_from_slice(&der[2..]);
        out
    } else {
        let n = usize::from(der[1] & 0x7f);
        let mut out = vec![0x30, 0x80 | (n as u8 + 1), 0x00];
        out.extend_from_slice(&der[2..]);
        out
    }
}

/// (name, DER, PEM label) of every key encoding the DER try-chain and the PEM loaders read.
fn key_ders() -> Vec<(&'static str, Vec<u8>, &'static str)> {
    let (ec, rsa, ed) = (p256(), rsa_key(1024), ed25519());
    vec![
        ("ec pkcs8", pkcs8_der(&ec), "PRIVATE KEY"),
        ("rsa pkcs8", pkcs8_der(&rsa), "PRIVATE KEY"),
        ("ed25519 pkcs8", pkcs8_der(&ed), "PRIVATE KEY"),
        (
            "sec1",
            ec.ec_key().unwrap().private_key_to_der().unwrap(),
            "EC PRIVATE KEY",
        ),
        (
            "pkcs1",
            rsa.rsa().unwrap().private_key_to_der().unwrap(),
            "RSA PRIVATE KEY",
        ),
        ("ec spki", spki_der(&ec), "PUBLIC KEY"),
        ("rsa spki", spki_der(&rsa), "PUBLIC KEY"),
        (
            "rsa pkcs1 public",
            rsa.rsa().unwrap().public_key_to_der_pkcs1().unwrap(),
            "PUBLIC KEY",
        ),
        (
            "encrypted pkcs8",
            ec.private_key_to_pkcs8_passphrase(Cipher::aes_128_cbc(), b"pw")
                .unwrap(),
            "ENCRYPTED PRIVATE KEY",
        ),
    ]
}

#[test]
fn key_der_with_trailing_bytes_or_ber_lengths_is_refused() {
    // pyca parses keys as strict DER (rust-asn1); OpenSSL's d2i accepts trailing bytes and
    // non-minimal lengths. c2 refuses all of these — the encrypted one without a prompt.
    for (name, der, label) in key_ders() {
        assert!(
            !parse_with(&der, &mut answer("pw")).unwrap().is_empty(),
            "{name}"
        );
        let mut variants = Vec::new();
        for suffix in [&[0x00][..], &[0x05, 0x00], &[0x00, 0x00]] {
            let mut data = der.clone();
            data.extend_from_slice(suffix);
            variants.push(data);
        }
        variants.push(nonminimal_outer_length(&der));
        for data in variants {
            let prompts = Rc::new(RefCell::new(Vec::new()));
            let mut cb = recording_cb("pw", prompts.clone());
            let err = parse_with(&data, &mut cb).unwrap_err();
            assert!(
                err.message
                    .starts_with("could not parse key material (attempted: "),
                "{name}: {}",
                err.message
            );
            assert!(prompts.borrow().is_empty(), "{name}");
            if label == "PUBLIC KEY" && name == "rsa pkcs1 public" {
                continue; // pyca's PUBLIC KEY label is SPKI-only anyway
            }
            let prompts = Rc::new(RefCell::new(Vec::new()));
            let mut cb = recording_cb("pw", prompts.clone());
            let err = parse_with(&pem_wrap(&data, label), &mut cb).unwrap_err();
            assert!(
                err.message
                    .starts_with(&format!("malformed {label} PEM block: ")),
                "{name}: {}",
                err.message
            );
            assert!(prompts.borrow().is_empty(), "{name}");
        }
    }
}

// --------------------------------------------- pyca's PEM framing (the `pem` 3.0 crate)

fn lines_with(pem: &[u8], f: impl Fn(&str) -> String) -> Vec<u8> {
    String::from_utf8(pem.to_vec())
        .unwrap()
        .split('\n')
        .map(|line| {
            if line.is_empty() || line.starts_with("-----") || line.contains(':') {
                line.to_owned()
            } else {
                f(line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

fn first_body_line(pem: &[u8]) -> String {
    String::from_utf8(pem.to_vec())
        .unwrap()
        .split('\n')
        .nth(1)
        .unwrap()
        .to_owned()
}

#[test]
fn pem_framing_is_pycas() {
    let key = p256();
    let spki = spki_pem(&key);
    let text = String::from_utf8(spki.clone()).unwrap();
    // a blank line inside the body: everything before it is read as header lines
    let blank_mid = lines_with(&spki, |line| format!("{line}\n"));
    assert_eq!(
        err(&blank_mid).message,
        format!(
            "malformed PUBLIC KEY PEM block: {PEM_FAQ}InvalidHeader({:?})",
            first_body_line(&spki)
        )
    );
    // a header line not ended by a blank line is base64 data (':' is byte 58)
    let no_blank = text.replacen("-----\n", "-----\nFoo: bar\n", 1);
    assert_eq!(
        err(no_blank.as_bytes()).message,
        format!("malformed PUBLIC KEY PEM block: {PEM_FAQ}InvalidData(InvalidByte(3, 58))")
    );
    // "------END": the pem crate's naive marker search finds no END
    let six = text.replace("\n-----END", "\n------END");
    assert_eq!(
        err(six.as_bytes()).message,
        format!("malformed PUBLIC KEY PEM block: {PEM_FAQ}MalformedFraming")
    );
    // accepted: headers ended by a blank line, a blank line after BEGIN, CRLF, lines padded
    // with any Unicode whitespace (VT, NBSP), indentation
    let accepted = [
        text.replacen("-----\n", "-----\nFoo: bar\n\n", 1)
            .into_bytes(),
        text.replacen("-----\n", "-----\n\n", 1).into_bytes(),
        text.replace('\n', "\r\n").into_bytes(),
        lines_with(&spki, |line| format!("{line}\u{b}")),
        lines_with(&spki, |line| format!("{line}\u{a0}")),
        lines_with(&spki, |line| format!("  {line}")),
        lines_with(&spki, |line| format!("\t{line}")),
    ];
    for data in accepted {
        assert_eq!(
            *parse_one(&data).data,
            spki_der(&key),
            "{}",
            String::from_utf8_lossy(&data)
        );
    }
    // BEGIN/END raw tags differ (c2's stripped labels agree)
    let cert = String::from_utf8(cn_cert(&key, "x").to_pem().unwrap()).unwrap();
    let spaced = cert.replacen("CERTIFICATE-----", "CERTIFICATE  -----", 1);
    assert_eq!(
        err(spaced.as_bytes()).message,
        format!(
            "malformed CERTIFICATE PEM block: {PEM_FAQ}MismatchedTags(\"CERTIFICATE  \", \"CERTIFICATE\")"
        )
    );
}

// ------------------------------------- RFC 1421 encryption headers (pyca `decrypt_pem`)

fn traditional_ec(key: &PKey<Private>) -> String {
    let pem = key
        .ec_key()
        .unwrap()
        .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), b"pw")
        .unwrap();
    String::from_utf8(pem).unwrap()
}

/// (error message, prompts) of parsing `data` with a callback answering "pw".
fn outcome(data: &[u8]) -> (std::result::Result<Vec<u8>, String>, Vec<String>) {
    let prompts = Rc::new(RefCell::new(Vec::new()));
    let mut cb = recording_cb("pw", prompts.clone());
    let result = parse_with(data, &mut cb)
        .map(|m| m[0].data.to_vec())
        .map_err(|e| e.message);
    let prompts = prompts.borrow().clone();
    (result, prompts)
}

#[test]
fn pem_encryption_headers_are_pycas() {
    let key = p256();
    let trad = traditional_ec(&key);
    let pkcs8 = String::from_utf8(pkcs8_pem(&key)).unwrap();
    let invalid_proc = |label: &str| {
        format!(
            "malformed {label} PEM block: Proc-Type PEM header is not valid, key could not be decrypted."
        )
    };
    // only an exact "4,ENCRYPTED" decrypts; any other Proc-Type fails before any prompt
    let cases: Vec<(String, std::result::Result<Vec<u8>, String>, usize)> = vec![
        (
            pkcs8.replacen("-----\n", "-----\nProc-Type: 4,NONE\n\n", 1),
            Err(invalid_proc("PRIVATE KEY")),
            0,
        ),
        (
            pkcs8.replacen("-----\n", "-----\nProc-Type: 4,MIC-ONLY\n\n", 1),
            Err(invalid_proc("PRIVATE KEY")),
            0,
        ),
        (
            trad.replace("4,ENCRYPTED", "4, ENCRYPTED"),
            Err(invalid_proc("EC PRIVATE KEY")),
            0,
        ),
        (
            trad.lines()
                .filter(|l| !l.starts_with("DEK-Info"))
                .collect::<Vec<_>>()
                .join("\n"),
            Err(
                "malformed EC PRIVATE KEY PEM block: Encrypted PEM doesn't have a DEK-Info header."
                    .to_owned(),
            ),
            0,
        ),
        (
            trad.replace("AES-128-CBC,", "AES-128-CBC "),
            Err(
                "malformed EC PRIVATE KEY PEM block: Encrypted PEM's DEK-Info header is not valid."
                    .to_owned(),
            ),
            0,
        ),
        // DEK-Info parts are not trimmed: " ,"/", " → an unknown cipher / bad IV after the prompt
        (trad.replace("AES-128-CBC,", "AES-128-CBC ,"), Err(WRONG_PW.to_owned()), 1),
        (trad.replace("AES-128-CBC,", "AES-128-CBC, "), Err(WRONG_PW.to_owned()), 1),
        // the header name/value are trimmed
        (
            trad.replace("Proc-Type: ", "Proc-Type:"),
            Ok(pkcs8_der(&key)),
            1,
        ),
        // the headers apply to every private label: a plaintext PKCS#8 with them is
        // "encrypted" (prompt, then the wrong-password text)
        (
            pkcs8.replacen(
                "-----\n",
                "-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\n",
                1,
            ),
            Err(WRONG_PW.to_owned()),
            1,
        ),
        // an encrypted SEC1 relabelled PRIVATE KEY decrypts, then fails to load as PKCS#8
        (trad.replace("EC PRIVATE KEY", "PRIVATE KEY"), Err(WRONG_PW.to_owned()), 1),
    ];
    for (data, expected, prompt_count) in cases {
        let (result, prompts) = outcome(data.as_bytes());
        assert_eq!(result, expected, "{data}");
        assert_eq!(prompts.len(), prompt_count, "{data}");
    }
    // without a callback the relabelled block needs a password (pyca TypeError)
    assert_eq!(
        err(trad.replace("EC PRIVATE KEY", "PRIVATE KEY").as_bytes()).message,
        "encrypted key material requires a password"
    );
    // ENCRYPTED PRIVATE KEY under traditional headers: decrypted first, then not an
    // EncryptedPrivateKeyInfo → wrong password
    let enc = String::from_utf8(
        key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_128_cbc(), b"pw")
            .unwrap(),
    )
    .unwrap()
    .replacen(
        "-----\n",
        "-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\n",
        1,
    );
    let (result, prompts) = outcome(enc.as_bytes());
    assert_eq!(result, Err(WRONG_PW.to_owned()));
    assert_eq!(
        prompts,
        vec!["Password for encrypted ENCRYPTED PRIVATE KEY".to_owned()]
    );
}

// ------------------------------------------ certificates read by pyca's parser alone

#[test]
fn certificates_openssl_refuses_load_as_in_pyca() {
    // OpenSSL's X509 decoder refuses these Name value encodings; pyca (c2) loads them.
    let key = p256();
    let astral: Vec<u8> = "a\u{1f600}"
        .encode_utf16()
        .flat_map(|u| u.to_be_bytes())
        .collect();
    let cases: [(u8, Vec<u8>, &str); 4] = [
        (0x1a, b"a b".to_vec(), "a b"),
        (0x1a, b"AB\x01C".to_vec(), "AB\u{1}C"),
        (0x04, b"ABCD".to_vec(), "ABCD"),
        (0x1e, astral, "a\u{1f600}"),
    ];
    for (tag, value, cn) in cases {
        let der = name_cert(&key, &raw_name(&[(CN_OID, tag, &value)]));
        for data in [der.clone(), pem_wrap(&der, "CERTIFICATE")] {
            let material = parse_one(&data);
            assert_eq!(material.key_class, KeyClass::Certificate);
            assert_eq!(*material.data, der);
            assert_eq!(material.label_hint.as_deref(), Some(cn));
        }
    }
}

#[test]
fn certificate_label_hint_with_a_unique_identifier_in_the_subject() {
    // x500UniqueIdentifier is the one OID pyca reads as a BIT STRING (bytes value).
    let key = p256();
    let subject = raw_name(&[(CN_OID, 0x0c, b"x"), (UID_OID, 0x03, b"\x00\xab")]);
    let material = parse_one(&name_cert(&key, &subject));
    assert_eq!(material.label_hint.as_deref(), Some("x"));
    let only_uid = raw_name(&[(UID_OID, 0x03, b"\x01\x02")]);
    assert_eq!(parse_one(&name_cert(&key, &only_uid)).label_hint, None);
}

#[test]
fn lazily_undecodable_subject_names_are_keyparse_errors() {
    // pyca loads these certificates but cannot decode the subject: c2's `_subject_cn`
    // crashed; r2 raises KeyParse "certificate is not valid DER X.509: …" (§11 D12(b)).
    let key = p256();
    let cases: [(&str, u8, &[u8], Option<&str>); 4] = [
        (CN_OID, 0x16, b"ZZ\xe9Q", None),
        (CN_OID, 0x14, b"ZZ\xe9Q", None),
        (CN_OID, 0x0c, b"ZZ\xffQ", None),
        (
            CN_OID,
            0x03,
            b"\x00ab",
            Some("oid must be X500_UNIQUE_IDENTIFIER for BitString type."),
        ),
    ];
    for (oid, tag, value, text) in cases {
        let der = name_cert(&key, &raw_name(&[(oid, tag, value)]));
        for data in [der.clone(), pem_wrap(&der, "CERTIFICATE")] {
            let err = err(&data);
            assert!(
                err.message
                    .starts_with("certificate is not valid DER X.509: "),
                "{}",
                err.message
            );
            if let Some(text) = text {
                assert_eq!(
                    err.message,
                    format!("certificate is not valid DER X.509: {text}")
                );
            }
        }
        // a label supplied by a PKCS#12 friendly name never decodes the subject in c2
    }
}

// --------------------------- pyca's structures (cryptography 49's own ASN.1 parsers)

const COULD_NOT_PARSE: &str = "could not parse key material (attempted: ";

fn assert_could_not_parse(name: &str, data: &[u8]) {
    let prompts = Rc::new(RefCell::new(Vec::new()));
    let mut cb = recording_cb("pw", prompts.clone());
    let err = parse_with(data, &mut cb).unwrap_err();
    assert!(
        err.message.starts_with(COULD_NOT_PARSE),
        "{name}: {}",
        err.message
    );
    assert!(prompts.borrow().is_empty(), "{name}");
}

fn int_tlv(value: u8) -> Vec<u8> {
    if value & 0x80 != 0 {
        tlv(0x02, &[0x00, value])
    } else {
        tlv(0x02, &[value])
    }
}

/// A certificate assembled from TBS fields (not re-signed: pyca does not verify at load).
fn cert_from(tbs: &[Vec<u8>], sig_alg: &[u8]) -> Vec<u8> {
    der_seq(&[
        der_seq(tbs),
        sig_alg.to_vec(),
        tlv(0x03, &[0x00, 0x01, 0x02]),
    ])
}

const ECDSA_SHA256: &str = "300a06082a8648ce3d040302";

/// TBS fields of a valid v3 EC certificate: version, serial, sigalg, issuer, validity,
/// subject, SPKI, [3] extensions (basicConstraints critical CA:FALSE).
fn tbs_fields(key: &PKey<Private>) -> Vec<Vec<u8>> {
    let name = raw_name(&[(CN_OID, 0x0c, b"structure")]);
    let validity = der_seq(&[tlv(0x17, b"200101000000Z"), tlv(0x17, b"300101000000Z")]);
    let basic_constraints = der_seq(&[
        tlv(0x06, &unhex("551d13")),
        tlv(0x01, &[0xff]),
        tlv(0x04, &der_seq(&[])),
    ]);
    vec![
        tlv(0xa0, &int_tlv(2)),
        int_tlv(7),
        unhex(ECDSA_SHA256),
        name.clone(),
        validity,
        name,
        spki_der(key),
        tlv(0xa3, &der_seq(&[basic_constraints])),
    ]
}

#[test]
fn certificate_structure_is_pycas() {
    // pyca parses the whole Certificate at load (rust-asn1 + cryptography-x509): every
    // case c2 answered "could not parse key material" (ValueError) is refused here too.
    let key = p256();
    let base = tbs_fields(&key);
    let sig = unhex(ECDSA_SHA256);
    let material = parse_one(&cert_from(&base, &sig));
    assert_eq!(material.key_class, KeyClass::Certificate);
    // still loads: critical TRUE, both unique IDs, the version absent (DEFAULT v1, no
    // extensions), RSA-style NULL-less ECDSA params
    let mut with_ids = base.clone();
    with_ids.insert(7, tlv(0x81, &[0x00, 0xaa]));
    with_ids.insert(8, tlv(0x82, &[0x00, 0xbb]));
    parse_one(&cert_from(&with_ids, &sig));
    parse_one(&cert_from(&base[1..7], &sig));

    let with = |index: usize, field: Vec<u8>| {
        let mut tbs = base.clone();
        tbs[index] = field;
        cert_from(&tbs, &sig)
    };
    let extension = |critical: &[u8]| {
        let mut ext = vec![tlv(0x06, &unhex("551d13"))];
        if !critical.is_empty() {
            ext.push(critical.to_vec());
        }
        ext.push(tlv(0x04, &der_seq(&[])));
        tlv(0xa3, &der_seq(&[der_seq(&ext)]))
    };
    let mut trailing = base.clone();
    trailing.push(tlv(0x04, b"x"));
    let sig_params = unhex("300d06082a8648ce3d0403020201ff");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        // an encoded DEFAULT (v1), a negative version, a version over u8
        ("explicit v1", with(0, tlv(0xa0, &int_tlv(0)))),
        ("negative version", with(0, tlv(0xa0, &tlv(0x02, &[0xff])))),
        ("version 256", with(0, tlv(0xa0, &tlv(0x02, &[0x01, 0x00])))),
        // critical: BOOLEAN DEFAULT FALSE — FALSE encoded, a non-DER TRUE
        ("critical false", with(7, extension(&[0x01, 0x01, 0x00]))),
        ("critical 0x01", with(7, extension(&[0x01, 0x01, 0x01]))),
        (
            "extensions not a sequence",
            with(7, tlv(0xa3, &tlv(0x04, &[]))),
        ),
        (
            "extension not an Extension",
            with(7, tlv(0xa3, &der_seq(&[der_seq(&[int_tlv(1)])]))),
        ),
        ("trailing TBS field", cert_from(&trailing, &sig)),
        // ecdsa-with-SHA256 has no parameters in pyca's DEFINED BY table
        ("tbs sigalg params", with(2, sig_params.clone())),
        ("outer sigalg params", cert_from(&base, &sig_params)),
        (
            "spki rsa params not NULL",
            with(6, {
                let mut items = der_items(&spki_der(&rsa_key(1024)));
                items[0] = der_seq(&[tlv(0x06, &unhex("2a864886f70d010101")), tlv(0x04, &[])]);
                der_seq(&items)
            }),
        ),
        (
            "spki ec params not a curve",
            with(6, {
                let mut items = der_items(&spki_der(&key));
                items[0] = der_seq(&[tlv(0x06, &unhex("2a8648ce3d0201")), int_tlv(1)]);
                der_seq(&items)
            }),
        ),
    ];
    for (name, der) in &cases {
        assert_could_not_parse(name, der);
        let err = err(&pem_wrap(der, "CERTIFICATE"));
        assert!(
            err.message
                .starts_with("malformed CERTIFICATE PEM block: error parsing asn1 value: "),
            "{name}: {}",
            err.message
        );
    }
    // pyca's InvalidVersion (v2 = 1, or above v3) is not a ValueError: c2 crashed; r2
    // raises KeyParse (§11 D12(b)).
    for version in [1u8, 3, 5] {
        let der = with(0, tlv(0xa0, &int_tlv(version)));
        assert_eq!(
            err(&der).message,
            format!("certificate is not valid DER X.509: {version} is not a valid X509 version")
        );
    }
}

/// A CSR assembled from its CertificationRequestInfo fields (not re-signed).
fn csr_from(info: &[Vec<u8>], sig_alg: &[u8]) -> Vec<u8> {
    der_seq(&[der_seq(info), sig_alg.to_vec(), tlv(0x03, &[0x00, 0x01])])
}

#[test]
fn csr_structure_is_pycas() {
    let key = p256();
    let name = raw_name(&[(CN_OID, 0x0c, b"csr")]);
    let attribute = |oid: &str, values: &[Vec<u8>]| {
        der_seq(&[tlv(0x06, &unhex(oid)), tlv(0x31, &values.concat())])
    };
    let challenge = attribute("2a864886f70d010907", &[tlv(0x0c, b"pw")]);
    let info = vec![int_tlv(0), name, spki_der(&key), tlv(0xa0, &challenge)];
    let sig = unhex(ECDSA_SHA256);
    let material = parse_one(&csr_from(&info, &sig));
    assert_eq!(material.label_hint.as_deref(), Some("csr"));
    let with = |index: usize, field: Vec<u8>| {
        let mut fields = info.clone();
        fields[index] = field;
        csr_from(&fields, &sig)
    };
    let unordered = tlv(
        0xa0,
        &[challenge.clone(), attribute("2a864886f70d010902", &[])].concat(),
    );
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "attributes not attributes",
            with(3, tlv(0xa0, &tlv(0x04, &[]))),
        ),
        ("attributes out of order", with(3, unordered)),
        (
            "attribute values out of order",
            with(
                3,
                tlv(
                    0xa0,
                    &attribute("2a864886f70d010907", &[tlv(0x0c, b"b"), tlv(0x0c, b"a")]),
                ),
            ),
        ),
        (
            "bad attribute oid",
            with(
                3,
                tlv(0xa0, &der_seq(&[tlv(0x06, &[0x80]), tlv(0x31, &[])])),
            ),
        ),
        (
            "sigalg params",
            csr_from(&info, &unhex("300d06082a8648ce3d0403020201ff")),
        ),
    ];
    for (name, der) in &cases {
        assert_could_not_parse(name, der);
    }
    for version in [1u8, 2, 3] {
        let der = with(0, int_tlv(version));
        assert_eq!(
            err(&der).message,
            format!(
                "certificate request is not valid DER X.509: {version} is not a valid CSR version"
            )
        );
    }
}

/// `der` with its first element (the version INTEGER) replaced.
fn with_version(der: &[u8], version: Vec<u8>) -> Vec<u8> {
    let mut items = der_items(der);
    items[0] = version;
    der_seq(&items)
}

#[test]
fn private_key_structures_are_pycas() {
    // pyca's version checks (OpenSSL's decoders accept every one of these): PKCS#8 version
    // 0 only, SEC1 ECPrivateKey version 1, PKCS#1 RSAPrivateKey version 0 without
    // otherPrimeInfos (multi-prime RSA) — pyca's "Invalid key".
    let (ec, rsa, ed) = (p256(), rsa_key(1024), ed25519());
    let sec1 = ec.ec_key().unwrap().private_key_to_der().unwrap();
    let pkcs1 = rsa.rsa().unwrap().private_key_to_der().unwrap();
    let multi_prime = {
        let mut items = der_items(&pkcs1);
        items[0] = int_tlv(1);
        let prime_info = der_seq(&[int_tlv(7), int_tlv(3), int_tlv(5)]);
        items.push(der_seq(&[prime_info]));
        der_seq(&items)
    };
    let pkcs8_of = |inner: &[u8]| {
        let mut items = der_items(&pkcs8_der(&rsa));
        items[2] = tlv(0x04, inner);
        der_seq(&items)
    };
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "pkcs8 v1",
            with_version(&pkcs8_der(&ec), int_tlv(1)),
            "PRIVATE KEY",
        ),
        (
            "pkcs8 v2",
            with_version(&pkcs8_der(&rsa), int_tlv(2)),
            "PRIVATE KEY",
        ),
        (
            "ed25519 pkcs8 v2",
            with_version(&pkcs8_der(&ed), int_tlv(2)),
            "PRIVATE KEY",
        ),
        ("sec1 v0", with_version(&sec1, int_tlv(0)), "EC PRIVATE KEY"),
        ("sec1 v2", with_version(&sec1, int_tlv(2)), "EC PRIVATE KEY"),
        (
            "pkcs1 v1",
            with_version(&pkcs1, int_tlv(1)),
            "RSA PRIVATE KEY",
        ),
        ("multi-prime pkcs1", multi_prime.clone(), "RSA PRIVATE KEY"),
        ("multi-prime pkcs8", pkcs8_of(&multi_prime), "PRIVATE KEY"),
    ];
    for (name, der, label) in &cases {
        assert_could_not_parse(name, der);
        assert_eq!(
            err(&pem_wrap(der, label)).message,
            format!("malformed {label} PEM block: Invalid key"),
            "{name}"
        );
    }
    // a OneAsymmetricKey [1] publicKey is not in pyca's PrivateKeyInfo; Ed25519 takes no
    // parameters; a negative or oversized version is a parse error
    let mut with_public = der_items(&pkcs8_der(&ed));
    with_public[0] = int_tlv(1);
    with_public.push(tlv(0x81, &[0x00; 33]));
    let mut ed_null = der_items(&pkcs8_der(&ed));
    ed_null[1] = der_seq(&[tlv(0x06, &unhex("2b6570")), tlv(0x05, &[])]);
    for (name, der) in [
        ("ed25519 v1 publicKey", der_seq(&with_public)),
        ("ed25519 NULL params", der_seq(&ed_null)),
        ("sec1 v -1", with_version(&sec1, tlv(0x02, &[0xff]))),
        (
            "pkcs8 v 0x80",
            with_version(&pkcs8_der(&ec), tlv(0x02, &[0x00, 0x80])),
        ),
    ] {
        assert_could_not_parse(name, &der);
    }
}

#[test]
fn public_key_structures_are_pycas() {
    // pyca reads the RSA modulus and exponent as unsigned INTEGERs and the RSA parameters
    // as NULL or absent; OpenSSL imported a different (positive) modulus from a negative one.
    let rsa = rsa_key(1024);
    let pkcs1_public = rsa.rsa().unwrap().public_key_to_der_pkcs1().unwrap();
    let negative_modulus = {
        let mut items = der_items(&pkcs1_public);
        assert_eq!(items[0][..4], [0x02, 0x81, 0x81, 0x00]);
        items[0][3] = 0x95; // the sign octet replaced: a negative INTEGER
        der_seq(&items)
    };
    let mut spki = der_items(&spki_der(&rsa));
    spki[1] = tlv(0x03, &[&[0x00][..], &negative_modulus].concat());
    let negative_spki = der_seq(&spki);
    let mut octet_params = der_items(&spki_der(&rsa));
    octet_params[0] = der_seq(&[tlv(0x06, &unhex("2a864886f70d010101")), tlv(0x04, &[])]);
    for (name, der) in [
        ("negative modulus pkcs1", negative_modulus),
        ("negative modulus spki", negative_spki),
        ("rsa params not NULL", der_seq(&octet_params)),
    ] {
        assert_could_not_parse(name, &der);
    }
    // an absent RSA parameter is fine (pyca: Option<NULL>)
    let mut absent = der_items(&spki_der(&rsa));
    absent[0] = der_seq(&[tlv(0x06, &unhex("2a864886f70d010101"))]);
    assert_eq!(parse_one(&der_seq(&absent)).size_bits, Some(1024));
}

/// An RSA key whose CRT coefficient is wrong (OpenSSL builds it; RSA_check_key refuses).
fn tampered_rsa() -> PKey<Private> {
    let rsa = rsa_key(1024).rsa().unwrap();
    let mut iqmp = rsa.iqmp().unwrap().to_owned().unwrap();
    iqmp.add_word(2).unwrap();
    let bad = openssl::rsa::Rsa::from_private_components(
        rsa.n().to_owned().unwrap(),
        rsa.e().to_owned().unwrap(),
        rsa.d().to_owned().unwrap(),
        rsa.p().unwrap().to_owned().unwrap(),
        rsa.q().unwrap().to_owned().unwrap(),
        rsa.dmp1().unwrap().to_owned().unwrap(),
        rsa.dmq1().unwrap().to_owned().unwrap(),
        iqmp,
    )
    .unwrap();
    PKey::from_rsa(bad).unwrap()
}

fn nocert_pkcs12(key: &PKey<Private>, password: &str) -> Vec<u8> {
    Pkcs12::builder()
        .pkey(key)
        .build2(password)
        .unwrap()
        .to_der()
        .unwrap()
}

#[test]
fn invalid_rsa_private_keys_are_pycas_value_errors() {
    // pyca's `RSA_check_key` refusal ("Invalid private key") is a ValueError: the DER chain
    // moves on, PEM reports it, and inside a PKCS#12 it fails the attempt like a wrong
    // password (c2's `except ValueError` loop) — not D12(i).
    let key = tampered_rsa();
    let pkcs1 = key.rsa().unwrap().private_key_to_der().unwrap();
    assert_could_not_parse("tampered pkcs1", &pkcs1);
    assert_could_not_parse("tampered pkcs8", &pkcs8_der(&key));
    assert_eq!(
        err(&pem_wrap(&pkcs1, "RSA PRIVATE KEY")).message,
        "malformed RSA PRIVATE KEY PEM block: Invalid private key"
    );
    assert_eq!(
        err(&pkcs8_pem(&key)).message,
        "malformed PRIVATE KEY PEM block: Invalid private key"
    );
    let protected = nocert_pkcs12(&key, "pw");
    let err_pw = parse_with(&protected, &mut answer("pw")).unwrap_err();
    assert_eq!(
        err_pw.message,
        "incorrect password for PKCS#12 (or corrupt PKCS#12 data)"
    );
    let open = nocert_pkcs12(&key, "");
    let err_open = err(&open);
    assert_eq!(
        err_open.message,
        "PKCS#12 requires a password (or the PKCS#12 data is corrupt)"
    );
    assert_eq!(err_open.hint.as_deref(), Some(PASSWORD_HINT));
    assert_eq!(err(&protected).message, err_open.message);
}

#[test]
fn ec_private_keys_must_match_their_public_point() {
    // pyca's SEC1 parser: the [1] public key must be the private key's point
    // (EC_KEY_check_key → "Invalid key"), and the private value must be the curve's order
    // length.
    let (key, other) = (p256(), p256());
    let mut items = der_items(&key.ec_key().unwrap().private_key_to_der().unwrap());
    let other_items = der_items(&other.ec_key().unwrap().private_key_to_der().unwrap());
    items[3] = other_items[3].clone();
    let mismatched = der_seq(&items);
    assert_could_not_parse("mismatched public point", &mismatched);
    assert_eq!(
        err(&pem_wrap(&mismatched, "EC PRIVATE KEY")).message,
        "malformed EC PRIVATE KEY PEM block: Invalid key"
    );
    let mut short = der_items(&key.ec_key().unwrap().private_key_to_der().unwrap());
    short[1] = tlv(0x04, &[0x01; 31]);
    short.remove(3);
    assert!(
        err(&pem_wrap(&der_seq(&short), "EC PRIVATE KEY"))
            .message
            .starts_with(
                "malformed EC PRIVATE KEY PEM block: EC private key is not encoded properly: private key value is too short."
            )
    );
}

#[test]
fn pkcs12_with_a_key_pyca_does_not_support_is_d12i() {
    // §11 D12(i): pyca's UnsupportedAlgorithm escaped c2's `except ValueError` loop (c2
    // crashed); r2 raises KeyParse — both without and after the prompt.
    let p239 = ec_key(Nid::X9_62_PRIME239V1);
    let explicit224 = {
        let mut group = EcGroup::from_curve_name(Nid::SECP224R1).unwrap();
        group.set_asn1_flag(Asn1Flag::EXPLICIT_CURVE);
        let ec = EcKey::generate(&group).unwrap();
        PKey::from_ec_key(ec).unwrap()
    };
    let cases = [
        (
            p239,
            "PKCS#12 contains an unsupported private key: Curve 1.2.840.10045.3.1.4 is not supported",
        ),
        (
            explicit224,
            "PKCS#12 contains an unsupported private key: ECDSA keys with explicit parameters are only supported when they map to secp256r1, secp384r1, or secp521r1. No custom curves are supported.",
        ),
    ];
    for (key, text) in cases {
        let open = nocert_pkcs12(&key, "");
        assert_eq!(err(&open).message, text);
        let protected = nocert_pkcs12(&key, "pw");
        assert_eq!(
            parse_with(&protected, &mut answer("pw"))
                .unwrap_err()
                .message,
            text
        );
    }
    // a DSA key loads (pyca supports the type) and is then refused by c2's classifier
    let dsa = PKey::from_dsa(openssl::dsa::Dsa::generate(1024).unwrap()).unwrap();
    let err = parse_with(&nocert_pkcs12(&dsa, "pw"), &mut answer("pw")).unwrap_err();
    assert_eq!(err.message, "unsupported key algorithm: DSAPrivateKey");
}

#[test]
fn long_passwords_decrypt_pkcs8_as_pyca() {
    // pyca decrypts PKCS#8 with the whole password (no 1024-byte callback buffer).
    let key = p256();
    for len in [1023usize, 1024, 1025, 1500] {
        let password = "a".repeat(len);
        let der = key
            .private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), password.as_bytes())
            .unwrap();
        let materials = parse_with(&der, &mut answer(&password)).unwrap();
        assert_eq!(*materials[0].data, pkcs8_der(&key), "{len}");
    }
    // a key encrypted under the 1024-byte prefix does not open with the longer password
    let prefix = "a".repeat(1024);
    let der = key
        .private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), prefix.as_bytes())
        .unwrap();
    assert_eq!(
        parse_with(&der, &mut answer(&"a".repeat(1500)))
            .unwrap_err()
            .message,
        WRONG_PW
    );
}

#[test]
fn traditional_pem_iv_longer_than_the_cipher_iv_decrypts() {
    // pyca passes the whole DEK-Info IV to OpenSSL, which uses its first IV-length bytes.
    let key = p256();
    let trad = traditional_ec(&key);
    let start = trad.find("AES-128-CBC,").unwrap() + "AES-128-CBC,".len();
    let iv = &trad[start..start + 32];
    for extra in ["00", "0011223344556677"] {
        let data = trad.replacen(iv, &format!("{iv}{extra}"), 1);
        let (result, prompts) = outcome(data.as_bytes());
        assert_eq!(result, Ok(pkcs8_der(&key)), "{extra}");
        assert_eq!(prompts.len(), 1);
    }
    // a shorter IV still fails after the prompt
    let data = trad.replacen(iv, &iv[..30], 1);
    assert_eq!(outcome(data.as_bytes()).0, Err(WRONG_PW.to_owned()));
}
