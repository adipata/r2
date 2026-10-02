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
    // invalid input is reported before the password (c2 loads the key first)
    let err = private_key_bytes(b"junk", Encoding::Pem, Some(&secret(""))).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
}

#[test]
fn nul_in_the_password_is_an_ordinary_byte() {
    // c2 (pyca BestAvailableEncryption) encrypts under b"a\x00b"; so does r2, and the key
    // reloads with that password only.
    let pkcs8 = pkcs8_der(&p256());
    for encoding in [Encoding::Pem, Encoding::Der] {
        let out = private_key_bytes(&pkcs8, encoding, Some(&secret("a\0b"))).unwrap();
        let mut cb = answer("a\0b");
        let materials = parse_key_material(&out, KeyHint::Auto, Some(&mut cb)).unwrap();
        assert_eq!(*materials[0].data, pkcs8);
        for wrong in ["a", "ab"] {
            let mut cb = answer(wrong);
            assert!(parse_key_material(&out, KeyHint::Auto, Some(&mut cb)).is_err());
        }
    }
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

#[test]
fn key_der_with_trailing_bytes_is_not_valid() {
    // pyca re-parses canonical bytes as strict DER (OpenSSL's d2i would accept these).
    let key = p256();
    let mut p8 = pkcs8_der(&key);
    p8.push(0);
    for result in [
        private_key_bytes(&p8, Encoding::Der, None).map(|b| b.to_vec()),
        pkcs8_public_spki(&p8),
    ] {
        let err = result.unwrap_err();
        assert!(
            err.message
                .starts_with("exported private key is not valid unencrypted PKCS#8 DER: "),
            "{}",
            err.message
        );
    }
    let mut spki = spki_der(&key);
    spki.extend_from_slice(&[0, 0]);
    let err = public_key_bytes(&spki, Encoding::Pem).unwrap_err();
    assert!(
        err.message
            .starts_with("exported public key is not valid DER SubjectPublicKeyInfo: ")
    );
    // DER export stays verbatim (c2 `_serialize_spki`)
    assert_eq!(public_key_bytes(&spki, Encoding::Der).unwrap(), spki);
}

#[test]
fn certificate_pem_of_a_name_openssl_refuses() {
    // pyca loads a VisibleString CN; OpenSSL's X509 decoder does not. The PEM is the DER as
    // loaded, 64 columns, LF.
    let key = p256();
    let der = name_cert(&key, &raw_name(&[(CN_OID, 0x1a, b"a b")]));
    assert!(X509::from_der(&der).is_err());
    assert_eq!(
        certificate_bytes(&der, Encoding::Pem).unwrap(),
        pem_wrap(&der, "CERTIFICATE")
    );
    assert_eq!(cert_spki(&der).unwrap(), spki_der(&key));
}

#[test]
fn passwords_over_1023_bytes_are_refused_as_pyca() {
    // pyca's BestAvailableEncryption refuses passwords over 1023 bytes (a ValueError c2 did
    // not catch, §11 D12(j)); 1023 bytes round-trip through the parser.
    let key = p256();
    let pkcs8 = pkcs8_der(&key);
    let ok = "a".repeat(1023);
    let out = private_key_bytes(&pkcs8, Encoding::Der, Some(&secret(&ok))).unwrap();
    let mut cb = answer(&ok);
    let materials = parse_key_material(&out, KeyHint::Auto, Some(&mut cb)).unwrap();
    assert_eq!(*materials[0].data, pkcs8);
    for password in ["a".repeat(1024), "a".repeat(1500), "é".repeat(512)] {
        for encoding in [Encoding::Der, Encoding::Pem] {
            let err = private_key_bytes(&pkcs8, encoding, Some(&secret(&password))).unwrap_err();
            assert_eq!(err.param_name(), Some("password"));
            assert_eq!(
                err.message,
                "Passwords longer than 1023 bytes are not supported by this backend"
            );
        }
    }
}

#[test]
fn private_key_structures_pyca_refuses_are_not_exported() {
    // pyca's PKCS#8 / PKCS#1 version checks (OpenSSL's decoders accept these): c2's
    // `_load_private` raised "Invalid key".
    let rsa = rsa_key(1024);
    let mut multi_prime = der_items(&rsa.rsa().unwrap().private_key_to_der().unwrap());
    multi_prime[0] = tlv(0x02, &[1]);
    multi_prime.push(der_seq(&[der_seq(&[
        tlv(0x02, &[7]),
        tlv(0x02, &[3]),
        tlv(0x02, &[5]),
    ])]));
    let mut pkcs8 = der_items(&pkcs8_der(&rsa));
    pkcs8[2] = tlv(0x04, &der_seq(&multi_prime));
    let mut v1 = der_items(&pkcs8_der(&p256()));
    v1[0] = tlv(0x02, &[1]);
    for der in [der_seq(&pkcs8), der_seq(&v1)] {
        for result in [
            private_key_bytes(&der, Encoding::Der, None).map(|_| ()),
            pkcs8_public_spki(&der).map(|_| ()),
        ] {
            assert_eq!(
                result.unwrap_err().message,
                "exported private key is not valid unencrypted PKCS#8 DER: Invalid key"
            );
        }
    }
}

/// R13 (R4/R6/R10 hand-off): a private key DER followed by trailing bytes — e.g. the
/// zero padding a token's KW-PAD unwrap leaves on a PKCS#8 (`copy softhsm:<priv> mem` on
/// SoftHSM 2.6.1) — fails like pyca's `load_der_private_key`: rust-asn1 parses the value's
/// content before it reports data after it, so the LAST attempt (EncryptedPrivateKeyInfo)
/// names the INTEGER where it wanted the AlgorithmIdentifier SEQUENCE. Texts from pyca in
/// c2's venv (c2@408d6f2), verbatim.
#[test]
fn private_key_der_with_trailing_bytes_reports_pycas_unexpected_tag() {
    const PYCA: &str = "Could not deserialize key data. The data may be in an incorrect format, it may be encrypted with an unsupported algorithm, or it may be an unsupported key type (e.g. EC curves with explicit parameters). Details: ASN.1 parsing error: unexpected tag (got Tag { value: 2, constructed: false, class: Universal })";
    let rsa = rsa_key(2048);
    let ec = p256();
    let ed = PKey::generate_ed25519().unwrap();
    let ders = [
        ("rsa pkcs8", pkcs8_der(&rsa)),
        ("rsa pkcs1", rsa.private_key_to_der().unwrap()),
        ("ec pkcs8", pkcs8_der(&ec)),
        ("ec sec1", ec.private_key_to_der().unwrap()),
        ("ed25519 pkcs8", pkcs8_der(&ed)),
    ];
    for (name, der) in ders {
        for suffix in [
            &[0x00][..],
            &[0x00, 0x00],
            &[0x05, 0x00],
            &[0x02, 0x01, 0x00],
            &[0x00; 7],
        ] {
            let mut data = der.clone();
            data.extend_from_slice(suffix);
            let err = private_key_bytes(&data, Encoding::Der, None).unwrap_err();
            assert_eq!(err.kind, ErrorKind::KeyParse, "{name}");
            assert_eq!(
                err.message,
                format!("exported private key is not valid unencrypted PKCS#8 DER: {PYCA}"),
                "{name} + {suffix:02x?}"
            );
        }
    }
}
