//! X.509 builders (spec §4.4.4, §5.6, §5.7) — port of c2 `tests/unit/test_x509build.py`
//! plus the RFC 4514 subject vectors generated with pyca 49 (support/gen_x509_vectors.py).
//! Key fixtures are generated at test time with OpenSSL; the CSR tests drive the sign
//! callback with software keys, including the PKCS#11-style raw r‖s → DER conversion.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

#[path = "support/keygen.rs"]
mod keygen;
#[path = "support/x509_vectors.rs"]
mod x509_vectors;

use keygen::*;
use openssl::asn1::Asn1Time;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::symm::Cipher;
use openssl::x509::{X509, X509Req};
use r2_core::der::ecdsa_rs_to_der;
use r2_core::error::ErrorKind;
use r2_core::keyparse::{KeyHint, parse_key_material};
use r2_core::keys::KeyClass;
use r2_core::x509build::{
    DEFAULT_CERT_DAYS, SignatureAlg, build_csr, build_pkcs12, build_self_signed_cert,
    parse_rfc4514_subject,
};
use r2_core::x509info::rfc4514_string;

// ---------------------------------------------------------------------------- helpers

fn sign_with(key: &PKey<Private>, md: Option<MessageDigest>, data: &[u8]) -> Vec<u8> {
    let mut signer = match md {
        Some(md) => Signer::new(md, key).unwrap(),
        None => Signer::new_without_digest(key).unwrap(),
    };
    signer.sign_oneshot_to_vec(data).unwrap()
}

/// What a PKCS#11 ECDSA signer returns: fixed-width r‖s.
fn raw_rs(key: &PKey<Private>, md: MessageDigest, data: &[u8], width: usize) -> Vec<u8> {
    let der = sign_with(key, Some(md), data);
    let sig = EcdsaSig::from_der(&der).unwrap();
    let mut out = sig.r().to_vec_padded(width as i32).unwrap();
    out.extend(sig.s().to_vec_padded(width as i32).unwrap());
    out
}

fn csr(
    spki: &[u8],
    subject: &str,
    alg: SignatureAlg,
    sign: &mut dyn FnMut(&[u8]) -> r2_core::Result<Vec<u8>>,
) -> r2_core::Result<X509Req> {
    let pem = build_csr(spki, subject, alg, sign)?;
    Ok(X509Req::from_pem(&pem).unwrap())
}

fn subject_text(req: &X509Req) -> String {
    rfc4514_string(&req.subject_name().to_der().unwrap()).unwrap()
}

fn validity_secs(cert: &X509) -> i64 {
    let diff = cert.not_before().diff(cert.not_after()).unwrap();
    i64::from(diff.days) * 86_400 + i64::from(diff.secs)
}

fn sig_alg_nid(req: &X509Req) -> Nid {
    // CertificationRequest ::= SEQUENCE { info, AlgorithmIdentifier, BIT STRING }
    let der = req.to_der().unwrap();
    let parsed = x509_cert::request::CertReq::try_from(der.as_slice()).unwrap();
    let oid = parsed.algorithm.oid.to_string();
    match oid.as_str() {
        "1.2.840.113549.1.1.11" => Nid::SHA256WITHRSAENCRYPTION,
        "1.2.840.113549.1.1.12" => Nid::SHA384WITHRSAENCRYPTION,
        "1.2.840.113549.1.1.13" => Nid::SHA512WITHRSAENCRYPTION,
        "1.2.840.10045.4.3.2" => Nid::ECDSA_WITH_SHA256,
        "1.2.840.10045.4.3.3" => Nid::ECDSA_WITH_SHA384,
        "1.3.101.112" => Nid::from_raw(openssl::pkey::Id::ED25519.as_raw()),
        other => panic!("unexpected {other}"),
    }
}

// --------------------------------------------------------------- build_self_signed_cert

#[test]
fn self_signed_rsa() {
    let key = rsa_key(2048);
    let der = build_self_signed_cert(&pkcs8_der(&key), "mykey", DEFAULT_CERT_DAYS).unwrap();
    let cert = X509::from_der(&der).unwrap();
    // subject == issuer == CN, a single UTF8String
    let expected = "3010310e300c06035504030c056d796b6579";
    assert_eq!(hex(&cert.subject_name().to_der().unwrap()), expected);
    assert_eq!(hex(&cert.issuer_name().to_der().unwrap()), expected);
    let text = String::from_utf8(cert.to_text().unwrap()).unwrap();
    assert!(
        text.contains("X509v3 Basic Constraints: critical"),
        "{text}"
    );
    assert!(text.contains("CA:FALSE"), "{text}");
    assert!(text.contains("Version: 3"), "{text}");
    assert_eq!(
        cert.signature_algorithm().object().nid(),
        Nid::SHA256WITHRSAENCRYPTION
    );
    assert!(cert.verify(&cert.public_key().unwrap()).unwrap()); // signature
    assert_eq!(
        cert.public_key().unwrap().public_key_to_der().unwrap(),
        spki_der(&key)
    );
    assert_eq!(validity_secs(&cert), 3650 * 86_400);
}

#[test]
fn self_signed_ec() {
    let key = p256();
    let der = build_self_signed_cert(&pkcs8_der(&key), "ec-key", 3650).unwrap();
    let cert = X509::from_der(&der).unwrap();
    assert_eq!(
        cert.signature_algorithm().object().nid(),
        Nid::ECDSA_WITH_SHA256
    );
    assert!(cert.verify(&cert.public_key().unwrap()).unwrap());
}

#[test]
fn self_signed_ed25519() {
    let key = ed25519();
    let der = build_self_signed_cert(&pkcs8_der(&key), "ed-key", 3650).unwrap();
    let cert = X509::from_der(&der).unwrap();
    assert_eq!(
        cert.signature_algorithm().object().nid(),
        Nid::from_raw(openssl::pkey::Id::ED25519.as_raw())
    ); // Ed keys: no hash
    assert!(cert.verify(&cert.public_key().unwrap()).unwrap());
    let der = build_self_signed_cert(&pkcs8_der(&ed448()), "ed448", 3650).unwrap();
    let cert = X509::from_der(&der).unwrap();
    assert_eq!(
        cert.signature_algorithm().object().nid(),
        Nid::from_raw(openssl::pkey::Id::ED448.as_raw())
    );
    assert!(cert.verify(&cert.public_key().unwrap()).unwrap());
}

#[test]
fn self_signed_days() {
    let key = p256();
    let der = build_self_signed_cert(&pkcs8_der(&key), "short", 30).unwrap();
    let cert = X509::from_der(&der).unwrap();
    assert_eq!(validity_secs(&cert), 30 * 86_400);
    // notBefore = now
    let now = Asn1Time::days_from_now(0).unwrap();
    let skew = cert.not_before().diff(&now).unwrap();
    assert!(skew.days == 0 && skew.secs.abs() < 120, "{skew:?}");
}

#[test]
fn self_signed_serials_are_random() {
    let key = p256();
    let serials: Vec<Vec<u8>> = (0..2)
        .map(|_| {
            let der = build_self_signed_cert(&pkcs8_der(&key), "s", 3650).unwrap();
            let cert = X509::from_der(&der).unwrap();
            cert.serial_number().to_bn().unwrap().to_vec()
        })
        .collect();
    assert_ne!(serials[0], serials[1]);
    assert!(serials.iter().all(|s| s.len() <= 20)); // 159 random bits
}

#[test]
fn self_signed_parses_as_certificate_material() {
    let key = p256();
    let der = build_self_signed_cert(&pkcs8_der(&key), "roundtrip-cn", 3650).unwrap();
    let material = &parse_key_material(&der, KeyHint::Auto, None).unwrap()[0];
    assert_eq!(material.key_class, KeyClass::Certificate);
    assert_eq!(material.label_hint.as_deref(), Some("roundtrip-cn"));
}

#[test]
fn self_signed_rejects_non_signing_key() {
    for (key, class) in [(x25519(), "X25519PrivateKey"), (x448(), "X448PrivateKey")] {
        let err = build_self_signed_cert(&pkcs8_der(&key), "nope", 3650).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Crypto);
        assert!(err.message.contains("cannot sign"));
        assert_eq!(
            err.message,
            format!("key type {class} cannot sign a certificate")
        );
        assert_eq!(
            err.hint.as_deref(),
            Some("self-signed certificates need an RSA, EC or Ed25519/Ed448 key")
        );
    }
}

#[test]
fn self_signed_rejects_garbage_pkcs8() {
    let err = build_self_signed_cert(b"\x30\x03\x02\x01\x00", "bad", 3650).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(
        err.message
            .starts_with("self-signed certificate key is not a valid DER PKCS#8 private key: "),
        "{}",
        err.message
    );
}

#[test]
fn self_signed_rejects_encrypted_pkcs8() {
    let key = p256();
    let encrypted = key
        .private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), b"pw")
        .unwrap();
    let err = build_self_signed_cert(&encrypted, "enc", 3650).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(err.message.contains("unencrypted"));
    assert_eq!(
        err.message,
        "self-signed certificate key must be an unencrypted PKCS#8 private key"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some(
            "decrypt the key first — the §4.3 canonical private-key format is unencrypted PKCS#8 DER"
        )
    );
}

#[test]
fn self_signed_cn_length_is_measured_in_utf8_bytes() {
    // §11 D12 (a): the defensive check of the builder.
    let key = p256();
    let pkcs8 = pkcs8_der(&key);
    for (cn, n) in [
        (String::new(), 0usize),
        ("é".repeat(40), 80),
        ("x".repeat(65), 65),
    ] {
        let err = build_self_signed_cert(&pkcs8, &cn, 3650).unwrap_err();
        assert_eq!(
            err.kind,
            ErrorKind::Param {
                param_name: "subject_cn".to_owned()
            }
        );
        assert_eq!(
            err.message,
            format!("Attribute's length must be >= 1 and <= 64, but it was {n}")
        );
        assert_eq!(
            err.hint.as_deref(),
            Some("the self-signed certificate uses the key label as its CN")
        );
    }
    for cn in ["é".repeat(32), "x".repeat(64), "a\0b".to_owned()] {
        let der = build_self_signed_cert(&pkcs8, &cn, 3650).unwrap();
        let material = &parse_key_material(&der, KeyHint::Auto, None).unwrap()[0];
        assert_eq!(material.label_hint.as_deref(), Some(cn.as_str()));
    }
}

// --------------------------------------------------------------------------- build_csr

#[test]
fn csr_rsa_signed_via_callback() {
    let key = rsa_key(2048);
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut sign = |tbs: &[u8]| {
        seen.push(tbs.to_vec());
        Ok(sign_with(&key, Some(MessageDigest::sha256()), tbs))
    };
    let pem = build_csr(
        &spki_der(&key),
        "CN=mykey",
        SignatureAlg::RsaPkcs1Sha256,
        &mut sign,
    )
    .unwrap();
    assert!(pem.starts_with(b"-----BEGIN CERTIFICATE REQUEST-----\n"));
    assert!(pem.ends_with(b"-----END CERTIFICATE REQUEST-----\n"));
    let req = X509Req::from_pem(&pem).unwrap();
    assert!(req.verify(&req.public_key().unwrap()).unwrap()); // verifies under OpenSSL
    assert_eq!(seen.len(), 1);
    // the callback got the DER CertificationRequestInfo
    let parsed = x509_cert::request::CertReq::try_from(req.to_der().unwrap().as_slice()).unwrap();
    assert_eq!(der::Encode::to_der(&parsed.info).unwrap(), seen[0]);
    assert_eq!(subject_text(&req), "CN=mykey");
    assert_eq!(
        req.public_key().unwrap().public_key_to_der().unwrap(),
        spki_der(&key)
    );
    assert_eq!(sig_alg_nid(&req), Nid::SHA256WITHRSAENCRYPTION);
    // RSA PKCS#1: explicit NULL parameters; CRI = version 0, subject, SPKI, [0] {}
    assert_eq!(
        parsed
            .algorithm
            .parameters
            .map(|p| der::Encode::to_der(&p).unwrap()),
        Some(vec![0x05, 0x00])
    );
    let mut expected_cri = vec![0x02, 0x01, 0x00];
    expected_cri.extend(parse_rfc4514_subject("CN=mykey").unwrap());
    expected_cri.extend(spki_der(&key));
    expected_cri.extend([0xa0, 0x00]);
    let (_, cri_body) = split_tlv(&seen[0]);
    assert_eq!(cri_body, expected_cri.as_slice());
}

fn split_tlv(der: &[u8]) -> (u8, &[u8]) {
    let (len, header) = if der[1] < 0x80 {
        (der[1] as usize, 2)
    } else {
        let n = (der[1] & 0x7f) as usize;
        let len = der[2..2 + n]
            .iter()
            .fold(0usize, |acc, b| acc * 256 + *b as usize);
        (len, 2 + n)
    };
    (der[0], &der[header..header + len])
}

#[test]
fn csr_rsa_hash_variants() {
    let key = rsa_key(2048);
    for (alg, md, nid) in [
        (
            SignatureAlg::RsaPkcs1Sha384,
            MessageDigest::sha384(),
            Nid::SHA384WITHRSAENCRYPTION,
        ),
        (
            SignatureAlg::RsaPkcs1Sha512,
            MessageDigest::sha512(),
            Nid::SHA512WITHRSAENCRYPTION,
        ),
    ] {
        let req = csr(&spki_der(&key), "CN=hashy", alg, &mut |tbs| {
            Ok(sign_with(&key, Some(md), tbs))
        })
        .unwrap();
        assert!(req.verify(&req.public_key().unwrap()).unwrap());
        assert_eq!(sig_alg_nid(&req), nid);
    }
}

#[test]
fn csr_rsa_is_deterministic_for_deterministic_signers() {
    // Byte-identical output for RSA PKCS#1 v1.5 (deterministic): two runs agree.
    let key = rsa_key(1024);
    let mut sign = |tbs: &[u8]| Ok(sign_with(&key, Some(MessageDigest::sha256()), tbs));
    let a = build_csr(
        &spki_der(&key),
        "CN=x,O=y",
        SignatureAlg::RsaPkcs1Sha256,
        &mut sign,
    )
    .unwrap();
    let b = build_csr(
        &spki_der(&key),
        "CN=x,O=y",
        SignatureAlg::RsaPkcs1Sha256,
        &mut sign,
    )
    .unwrap();
    assert_eq!(a, b);
    let pem = String::from_utf8(a).unwrap();
    assert!(pem.lines().all(|line| line.len() <= 64));
}

#[test]
fn csr_ecdsa_raw_rs_converted_to_der() {
    // Simulate a PKCS#11 signer: raw r‖s out of the token, converted to DER by the caller.
    let key = p256();
    let req = csr(
        &spki_der(&key),
        "CN=eckey",
        SignatureAlg::EcdsaSha256,
        &mut |tbs| {
            let raw = raw_rs(&key, MessageDigest::sha256(), tbs, 32); // what C_Sign returns
            ecdsa_rs_to_der(&raw) // mandatory conversion BEFORE returning (§4.4)
        },
    )
    .unwrap();
    assert!(req.verify(&req.public_key().unwrap()).unwrap());
    assert_eq!(sig_alg_nid(&req), Nid::ECDSA_WITH_SHA256);
    let parsed = x509_cert::request::CertReq::try_from(req.to_der().unwrap().as_slice()).unwrap();
    assert!(parsed.algorithm.parameters.is_none()); // ECDSA: absent parameters
}

#[test]
fn csr_ecdsa_unconverted_raw_rs_is_invalid() {
    // Returning raw r‖s without DER conversion must NOT verify — proves the conversion in
    // the previous test is load-bearing, not decorative.
    let key = p256();
    let req = csr(
        &spki_der(&key),
        "CN=eckey",
        SignatureAlg::EcdsaSha256,
        &mut |tbs| {
            Ok(raw_rs(&key, MessageDigest::sha256(), tbs, 32)) // WRONG: still raw
        },
    )
    .unwrap();
    let valid = req.verify(&req.public_key().unwrap()).unwrap_or(false);
    assert!(!valid);
}

#[test]
fn csr_ecdsa_p384() {
    let key = ec_key(Nid::SECP384R1);
    let req = csr(
        &spki_der(&key),
        "CN=p384",
        SignatureAlg::EcdsaSha384,
        &mut |tbs| ecdsa_rs_to_der(&raw_rs(&key, MessageDigest::sha384(), tbs, 48)),
    )
    .unwrap();
    assert!(req.verify(&req.public_key().unwrap()).unwrap());
    assert_eq!(sig_alg_nid(&req), Nid::ECDSA_WITH_SHA384);
}

#[test]
fn csr_ed25519() {
    let key = ed25519();
    let req = csr(
        &spki_der(&key),
        "CN=edkey",
        SignatureAlg::Ed25519,
        &mut |tbs| Ok(sign_with(&key, None, tbs)),
    )
    .unwrap();
    assert!(req.verify(&req.public_key().unwrap()).unwrap());
    assert_eq!(
        sig_alg_nid(&req),
        Nid::from_raw(openssl::pkey::Id::ED25519.as_raw())
    );
    let key = ed448();
    let req = csr(
        &spki_der(&key),
        "CN=ed448",
        SignatureAlg::Ed448,
        &mut |tbs| Ok(sign_with(&key, None, tbs)),
    )
    .unwrap();
    assert!(req.verify(&req.public_key().unwrap()).unwrap());
}

#[test]
fn csr_multi_rdn_subject() {
    let key = p256();
    let req = csr(
        &spki_der(&key),
        "CN=mykey,O=ACME",
        SignatureAlg::EcdsaSha256,
        &mut |tbs| Ok(sign_with(&key, Some(MessageDigest::sha256()), tbs)),
    )
    .unwrap();
    assert!(req.verify(&req.public_key().unwrap()).unwrap());
    assert_eq!(subject_text(&req), "CN=mykey,O=ACME");
}

#[test]
fn csr_bad_subject() {
    let key = p256();
    let err = build_csr(
        &spki_der(&key),
        "not a subject at all",
        SignatureAlg::EcdsaSha256,
        &mut |_| Ok(Vec::new()),
    )
    .unwrap_err();
    assert_eq!(err.param_name(), Some("subject"));
    assert_eq!(err.message, "invalid subject 'not a subject at all': ");
    assert_eq!(
        err.hint.as_deref(),
        Some("RFC 4514 syntax, e.g. \"CN=mykey,O=ACME\"")
    );
}

#[test]
fn csr_bad_spki() {
    let err = build_csr(
        b"\x30\x03\x02\x01\x00",
        "CN=x",
        SignatureAlg::RsaPkcs1Sha256,
        &mut |_| Ok(Vec::new()),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(err.message.contains("SubjectPublicKeyInfo"));
    assert!(
        err.message
            .starts_with("public key is not a valid DER SubjectPublicKeyInfo: ")
    );
}

#[test]
fn csr_sign_callback_errors_propagate() {
    let key = p256();
    let err = build_csr(
        &spki_der(&key),
        "CN=x",
        SignatureAlg::EcdsaSha256,
        &mut |_| Err(r2_core::ConsoleError::crypto("token said no")),
    )
    .unwrap_err();
    assert_eq!(
        (err.kind, err.message.as_str()),
        (ErrorKind::Crypto, "token said no")
    );
}

#[test]
fn signature_alg_tokens_and_oids() {
    let table = [
        (
            SignatureAlg::RsaPkcs1Sha256,
            "sha256WithRSAEncryption",
            "1.2.840.113549.1.1.11",
            true,
        ),
        (
            SignatureAlg::RsaPkcs1Sha384,
            "sha384WithRSAEncryption",
            "1.2.840.113549.1.1.12",
            true,
        ),
        (
            SignatureAlg::RsaPkcs1Sha512,
            "sha512WithRSAEncryption",
            "1.2.840.113549.1.1.13",
            true,
        ),
        (
            SignatureAlg::EcdsaSha256,
            "ecdsa-with-SHA256",
            "1.2.840.10045.4.3.2",
            false,
        ),
        (
            SignatureAlg::EcdsaSha384,
            "ecdsa-with-SHA384",
            "1.2.840.10045.4.3.3",
            false,
        ),
        (
            SignatureAlg::EcdsaSha512,
            "ecdsa-with-SHA512",
            "1.2.840.10045.4.3.4",
            false,
        ),
        (SignatureAlg::Ed25519, "ed25519", "1.3.101.112", false),
        (SignatureAlg::Ed448, "ed448", "1.3.101.113", false),
    ];
    for (alg, token, oid, null) in table {
        assert_eq!(
            (alg.as_str(), alg.oid(), alg.null_params()),
            (token, oid, null)
        );
    }
}

// --------------------------------------------------------------- RFC 4514 (pyca vectors)

#[test]
fn rfc4514_subject_vectors_match_pyca() {
    for (subject, expected, csr_error) in x509_vectors::SUBJECTS {
        match (parse_rfc4514_subject(subject), expected) {
            (Ok(der), Ok(hex_der)) => {
                assert_eq!(hex(&der), *hex_der, "{subject:?}");
                // round trip through pyca's rfc4514_string port
                if csr_error.is_empty() {
                    rfc4514_string(&der).unwrap();
                }
            }
            (Err(err), Err(text)) => {
                assert_eq!(err.param_name(), Some("subject"), "{subject:?}");
                assert_eq!(
                    err.message,
                    format!(
                        "invalid subject {}: {text}",
                        r2_core::text::py_repr(subject)
                    ),
                    "{subject:?}"
                );
                assert_eq!(
                    err.hint.as_deref(),
                    Some("RFC 4514 syntax, e.g. \"CN=mykey,O=ACME\"")
                );
            }
            (got, want) => panic!("{subject:?}: got {got:?}, want {want:?}"),
        }
    }
}

#[test]
fn csr_reparse_rejects_what_pyca_rejects() {
    // c2's build_csr re-parses the assembled CSR with pyca, which validates PrintableString
    // values (C, serialNumber, dnQualifier, jurisdictionC) → "assembled CSR failed to parse".
    let key = p256();
    let spki = spki_der(&key);
    for (subject, expected, csr_error) in x509_vectors::SUBJECTS {
        if expected.is_err() {
            continue;
        }
        let result = build_csr(&spki, subject, SignatureAlg::EcdsaSha256, &mut |tbs| {
            Ok(sign_with(&key, Some(MessageDigest::sha256()), tbs))
        });
        if csr_error.is_empty() {
            let pem = result.unwrap_or_else(|e| panic!("{subject:?}: {e:?}"));
            let req = X509Req::from_pem(&pem).unwrap();
            assert!(
                req.verify(&req.public_key().unwrap()).unwrap(),
                "{subject:?}"
            );
            assert_eq!(
                hex(&req.subject_name().to_der().unwrap()),
                expected.unwrap(),
                "{subject:?}"
            );
        } else {
            let err = result.unwrap_err();
            assert_eq!(err.kind, ErrorKind::Crypto, "{subject:?}");
            assert_eq!(
                err.message,
                format!("assembled CSR failed to parse: {csr_error}"),
                "{subject:?}"
            );
        }
    }
}

// ------------------------------------------------------------------------ build_pkcs12

fn reload(p12: &[u8], password: &str) -> openssl::pkcs12::ParsedPkcs12_2 {
    Pkcs12::from_der(p12).unwrap().parse2(password).unwrap()
}

#[test]
fn pkcs12_roundtrip_with_pyca() {
    let (rsa, ec) = (rsa_key(2048), p256());
    let cert_der = build_self_signed_cert(&pkcs8_der(&rsa), "p12key", 3650).unwrap();
    let extra_der = build_self_signed_cert(&pkcs8_der(&ec), "chain", 3650).unwrap();
    let p12 = build_pkcs12(
        &pkcs8_der(&rsa),
        &cert_der,
        "p12key",
        &secret("pw12"),
        std::slice::from_ref(&extra_der),
    )
    .unwrap();
    let loaded = reload(&p12, "pw12");
    let key = loaded.pkey.unwrap();
    assert_eq!(key.id(), openssl::pkey::Id::RSA);
    assert_eq!(pkcs8_der(&key), pkcs8_der(&rsa));
    let cert = loaded.cert.unwrap();
    assert_eq!(cert.to_der().unwrap(), cert_der);
    assert_eq!(cert.alias(), Some(b"p12key".as_slice()));
    let chain: Vec<Vec<u8>> = loaded
        .ca
        .unwrap()
        .iter()
        .map(|c| c.to_der().unwrap())
        .collect();
    assert_eq!(chain, vec![extra_der]);
}

#[test]
fn pkcs12_profile_is_best_available_encryption() {
    // PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC bags at 20000 iterations, SHA-256 MAC at 2048.
    let key = p256();
    let cert = build_self_signed_cert(&pkcs8_der(&key), "k", 3650).unwrap();
    let p12 = build_pkcs12(&pkcs8_der(&key), &cert, "k", &secret("pw"), &[]).unwrap();
    let text = hex(&p12);
    // pbes2 OID, pbkdf2 OID, aes256-cbc OID, hmacWithSHA256 OID, 20000 = 0x4e20
    for needle in [
        "06092a864886f70d01050d",
        "06092a864886f70d01050c",
        "060960864801650304012a",
        "06082a864886f70d0209",
        "02024e20",
    ] {
        assert!(text.contains(needle), "{needle}");
    }
    // MacData: DigestInfo sha256 … iterations 2048 (0x0800) at the end
    assert!(text.contains("0609608648016503040201"));
    assert!(text.ends_with("02020800"));
    assert!(reload(&p12, "pw").ca.is_none_or(|ca| ca.is_empty()));
}

#[test]
fn pkcs12_wrong_password_fails_reload() {
    let key = p256();
    let cert_der = build_self_signed_cert(&pkcs8_der(&key), "k", 3650).unwrap();
    let p12 = build_pkcs12(&pkcs8_der(&key), &cert_der, "k", &secret("right"), &[]).unwrap();
    assert!(Pkcs12::from_der(&p12).unwrap().parse2("wrong").is_err());
}

#[test]
fn pkcs12_ed25519() {
    let key = ed25519();
    let cert_der = build_self_signed_cert(&pkcs8_der(&key), "edp12", 3650).unwrap();
    let p12 = build_pkcs12(&pkcs8_der(&key), &cert_der, "edp12", &secret("pw"), &[]).unwrap();
    assert_eq!(
        reload(&p12, "pw").pkey.unwrap().id(),
        openssl::pkey::Id::ED25519
    );
}

#[test]
fn pkcs12_output_reparses_via_parse_key_material() {
    let key = rsa_key(2048);
    let cert_der = build_self_signed_cert(&pkcs8_der(&key), "loop", 3650).unwrap();
    let p12 = build_pkcs12(&pkcs8_der(&key), &cert_der, "loop", &secret("pw"), &[]).unwrap();
    let mut cb = answer("pw");
    let materials = parse_key_material(&p12, KeyHint::Auto, Some(&mut cb)).unwrap();
    let classes: Vec<KeyClass> = materials.iter().map(|m| m.key_class).collect();
    assert_eq!(classes, [KeyClass::Private, KeyClass::Certificate]);
    assert!(
        materials
            .iter()
            .all(|m| m.label_hint.as_deref() == Some("loop"))
    );
    assert_eq!(*materials[0].data, pkcs8_der(&key));
}

#[test]
fn pkcs12_empty_password() {
    let key = p256();
    let cert_der = build_self_signed_cert(&pkcs8_der(&key), "k", 3650).unwrap();
    let err = build_pkcs12(&pkcs8_der(&key), &cert_der, "k", &secret(""), &[]).unwrap_err();
    assert_eq!(err.param_name(), Some("password"));
    assert_eq!(err.message, "PKCS#12 password must not be empty");
    assert_eq!(
        err.hint.as_deref(),
        Some("PKCS#12 output is always encrypted (§5.6)")
    );
}

#[test]
fn pkcs12_nul_guards() {
    // §11 D16: r2 texts where rust-openssl would panic.
    let key = p256();
    let pkcs8 = pkcs8_der(&key);
    let cert_der = build_self_signed_cert(&pkcs8, "k", 3650).unwrap();
    let err = build_pkcs12(&pkcs8, &cert_der, "k", &secret("p\0w"), &[]).unwrap_err();
    assert_eq!(err.param_name(), Some("password"));
    assert_eq!(
        err.message,
        "PKCS#12 password must not contain NUL characters"
    );
    let err = build_pkcs12(&pkcs8, &cert_der, "k\0", &secret("pw"), &[]).unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(
        err.message,
        "PKCS#12 friendly name must not contain NUL characters"
    );
}

#[test]
fn pkcs12_bad_cert_der() {
    let key = p256();
    let err = build_pkcs12(&pkcs8_der(&key), b"\x30\x00", "k", &secret("pw"), &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(err.message.contains("X.509"));
    assert!(
        err.message
            .starts_with("certificate is not valid DER X.509: ")
    );
}

#[test]
fn pkcs12_bad_extra_cert() {
    let key = p256();
    let cert_der = build_self_signed_cert(&pkcs8_der(&key), "k", 3650).unwrap();
    let err = build_pkcs12(
        &pkcs8_der(&key),
        &cert_der,
        "k",
        &secret("pw"),
        &[b"\x30".to_vec()],
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(err.message.contains("extra certificate #0"));
    assert!(
        err.message
            .starts_with("extra certificate #0 is not valid DER X.509: ")
    );
}

#[test]
fn pkcs12_rejects_x25519() {
    let (xk, ek) = (x25519(), p256());
    let cert_der = build_self_signed_cert(&pkcs8_der(&ek), "c", 3650).unwrap();
    let err = build_pkcs12(&pkcs8_der(&xk), &cert_der, "x", &secret("pw"), &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Crypto);
    assert!(err.message.contains("PKCS#12"));
    assert_eq!(
        err.message,
        "key type X25519PrivateKey cannot be stored in a PKCS#12"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("PKCS#12 supports RSA, EC and Ed25519/Ed448 private keys")
    );
}

#[test]
fn pkcs12_key_loading_errors() {
    let key = p256();
    let cert_der = build_self_signed_cert(&pkcs8_der(&key), "k", 3650).unwrap();
    let encrypted = key
        .private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), b"pw")
        .unwrap();
    let err = build_pkcs12(&encrypted, &cert_der, "k", &secret("pw"), &[]).unwrap_err();
    assert_eq!(
        err.message,
        "PKCS#12 private key must be an unencrypted PKCS#8 private key"
    );
    let err = build_pkcs12(b"\x30\x00", &cert_der, "k", &secret("pw"), &[]).unwrap_err();
    assert!(
        err.message
            .starts_with("PKCS#12 private key is not a valid DER PKCS#8 private key: ")
    );
}

#[test]
fn csr_spki_with_trailing_bytes_is_refused_before_signing() {
    // pyca's load_der_public_key is strict DER; c2 raised before assembling anything.
    let key = p256();
    let mut spki = spki_der(&key);
    spki.push(0);
    let mut called = false;
    let mut sign = |_: &[u8]| -> r2_core::Result<Vec<u8>> {
        called = true;
        Ok(Vec::new())
    };
    let err = build_csr(&spki, "CN=x", SignatureAlg::EcdsaSha256, &mut sign).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(
        err.message
            .starts_with("public key is not a valid DER SubjectPublicKeyInfo: "),
        "{}",
        err.message
    );
    assert!(!called);
}

#[test]
fn pkcs12_of_a_certificate_openssl_cannot_decode_is_refused() {
    // §11 D24: pyca writes PKCS#12 natively; r2 needs an OpenSSL X509, whose decoder
    // refuses e.g. a VisibleString CN that pyca loads.
    let key = p256();
    let der = name_cert(&key, &raw_name(&[(CN_OID, 0x1a, b"a b")]));
    let err = build_pkcs12(&pkcs8_der(&key), &der, "k", &secret("pw"), &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(
        err.message
            .starts_with("certificate is not valid DER X.509: "),
        "{}",
        err.message
    );
}
