//! Export re-serialization (spec §4.4.6, §5.6) — the byte assertions of c2
//! `tests/unit/services/test_keyexport.py` (keyexport's pyca serializers moved to R6, spec
//! §4.1.1; the `export_bytes` format resolution stays R8's), plus the §4.4.6 error texts.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

#[path = "support/keygen.rs"]
mod keygen;

use keygen::*;
use openssl::pkey::PKey;
use openssl::symm::Cipher;
use openssl::x509::X509;
use r2_core::error::ErrorKind;
use r2_core::formats::{
    Encoding, cert_spki, certificate_bytes, pkcs8_public_spki, private_key_bytes, public_key_bytes,
};
use r2_core::keyparse::{KeyHint, parse_key_material};

#[test]
fn test_private_auto_is_pem_pkcs8() {
    let key = rsa_key(2048);
    let payload = private_key_bytes(&pkcs8_der(&key), Encoding::Pem, None).unwrap();
    assert!(payload.starts_with(b"-----BEGIN PRIVATE KEY-----"));
    let reloaded = PKey::private_key_from_pem_callback(&payload, |_| Ok(0)).unwrap();
    assert_eq!(reloaded.id(), openssl::pkey::Id::RSA);
    assert_eq!(*payload, pkcs8_pem(&key)); // byte-identical writer
}

#[test]
fn test_private_der_round_trips() {
    let key = rsa_key(2048);
    let payload = private_key_bytes(&pkcs8_der(&key), Encoding::Der, None).unwrap();
    assert_eq!(*payload, pkcs8_der(&key));
}

#[test]
fn test_private_password_encrypts_pkcs8() {
    let key = rsa_key(2048);
    let payload =
        private_key_bytes(&pkcs8_der(&key), Encoding::Pem, Some(&secret("s3cret"))).unwrap();
    let text = String::from_utf8(payload.to_vec()).unwrap();
    assert!(text.contains("ENCRYPTED PRIVATE KEY"));
    // without a password: "requires a password"; with it: the same key
    let err = parse_key_material(&payload, KeyHint::Auto, None).unwrap_err();
    assert_eq!(err.message, "encrypted key material requires a password");
    let mut cb = answer("s3cret");
    let materials = parse_key_material(&payload, KeyHint::Auto, Some(&mut cb)).unwrap();
    assert_eq!(*materials[0].data, pkcs8_der(&key));
    // DER form + the BestAvailableEncryption scheme: PBES2 / PBKDF2 / HMAC-SHA256 / AES-256-CBC
    let der = private_key_bytes(&pkcs8_der(&key), Encoding::Der, Some(&secret("s3cret"))).unwrap();
    let text = hex(&der);
    for needle in [
        "06092a864886f70d01050d",
        "06092a864886f70d01050c",
        "06082a864886f70d0209",
        "060960864801650304012a",
        "020208", // 2048 iterations
    ] {
        assert!(text.contains(needle), "{needle}");
    }
    let reloaded = PKey::private_key_from_pkcs8_callback(&der, |buf| {
        buf[..6].copy_from_slice(b"s3cret");
        Ok(6)
    })
    .unwrap();
    assert_eq!(pkcs8_der(&reloaded), pkcs8_der(&key));
}

#[test]
fn test_public_auto_is_pem_spki() {
    let key = rsa_key(2048);
    let payload = public_key_bytes(&spki_der(&key), Encoding::Pem).unwrap();
    assert!(payload.starts_with(b"-----BEGIN PUBLIC KEY-----"));
    assert_eq!(payload, spki_pem(&key));
    assert_eq!(
        public_key_bytes(&spki_der(&key), Encoding::Der).unwrap(),
        spki_der(&key)
    );
}

#[test]
fn test_certificate_pem_and_der() {
    let cert = cn_cert(&rsa_key(2048), "unit-test-cert");
    let der = cert.to_der().unwrap();
    let pem = certificate_bytes(&der, Encoding::Pem).unwrap();
    let der_out = certificate_bytes(&der, Encoding::Der).unwrap();
    assert!(pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
    assert_eq!(der_out, der);
    assert_eq!(pem, cert.to_pem().unwrap());
    assert_eq!(
        X509::from_pem(&pem)
            .unwrap()
            .serial_number()
            .to_bn()
            .unwrap(),
        X509::from_der(&der_out)
            .unwrap()
            .serial_number()
            .to_bn()
            .unwrap()
    );
}

#[test]
fn encoding_tokens() {
    assert_eq!(
        (Encoding::Pem.as_str(), Encoding::Der.as_str()),
        ("pem", "der")
    );
}

#[test]
fn der_outputs_are_verbatim_without_validation() {
    // c2 `_serialize_spki` / certificate "der": returned as-is.
    assert_eq!(public_key_bytes(b"junk", Encoding::Der).unwrap(), b"junk");
    assert_eq!(certificate_bytes(b"junk", Encoding::Der).unwrap(), b"junk");
}

#[test]
fn invalid_inputs_have_c2s_prefixes() {
    let err = private_key_bytes(b"\x30\x00", Encoding::Pem, None).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(
        err.message
            .starts_with("exported private key is not valid unencrypted PKCS#8 DER: ")
    );
    let encrypted = p256()
        .private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), b"pw")
        .unwrap();
    let err = private_key_bytes(&encrypted, Encoding::Der, None).unwrap_err();
    assert_eq!(
        err.message,
        "exported private key is not valid unencrypted PKCS#8 DER: Password was not given but private key is encrypted"
    );
    let err = public_key_bytes(b"\x30\x00", Encoding::Pem).unwrap_err();
    assert!(
        err.message
            .starts_with("exported public key is not valid DER SubjectPublicKeyInfo: ")
    );
    let err = certificate_bytes(b"\x30\x00", Encoding::Pem).unwrap_err();
    assert!(
        err.message
            .starts_with("exported certificate is not valid DER X.509: ")
    );
    let err = cert_spki(b"\x30\x00").unwrap_err();
    assert!(
        err.message
            .starts_with("exported certificate is not valid DER X.509: ")
    );
    let err = pkcs8_public_spki(b"junk").unwrap_err();
    assert!(
        err.message
            .starts_with("exported private key is not valid unencrypted PKCS#8 DER: ")
    );
}

#[test]
fn password_guards() {
    let pkcs8 = pkcs8_der(&p256());
    let err = private_key_bytes(&pkcs8, Encoding::Pem, Some(&secret(""))).unwrap_err();
    assert_eq!(err.param_name(), Some("password"));
    assert_eq!(err.message, "password must not be empty");
    // §11 D16
    let err = private_key_bytes(&pkcs8, Encoding::Der, Some(&secret("a\0b"))).unwrap_err();
    assert_eq!(err.param_name(), Some("password"));
    assert_eq!(err.message, "password must not contain NUL characters");
    // invalid input is reported before the password (c2 loads the key first)
    let err = private_key_bytes(b"junk", Encoding::Pem, Some(&secret(""))).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
}

#[test]
fn spki_derivations() {
    let key = p256();
    let cert = cn_cert(&key, "c").to_der().unwrap();
    assert_eq!(cert_spki(&cert).unwrap(), spki_der(&key));
    assert_eq!(pkcs8_public_spki(&pkcs8_der(&key)).unwrap(), spki_der(&key));
    let rsa = rsa_key(1024);
    assert_eq!(pkcs8_public_spki(&pkcs8_der(&rsa)).unwrap(), spki_der(&rsa));
    let ed = ed25519();
    assert_eq!(pkcs8_public_spki(&pkcs8_der(&ed)).unwrap(), spki_der(&ed));
}

#[test]
fn public_pem_of_a_pkcs1_rsa_key_is_spki() {
    // pyca's load_der_public_key also takes PKCS#1 RSAPublicKey; the PEM is SPKI.
    let key = rsa_key(1024);
    let pkcs1 = key.rsa().unwrap().public_key_to_der_pkcs1().unwrap();
    assert_eq!(
        public_key_bytes(&pkcs1, Encoding::Pem).unwrap(),
        spki_pem(&key)
    );
}
