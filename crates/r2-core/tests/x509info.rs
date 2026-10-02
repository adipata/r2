//! Certificate facts (spec §4.4.5) — port of the `certificate_details` cases of c2
//! `tests/unit/services/test_certops.py` (moved to R6, spec §4.1.1), the Name vectors of
//! pyca 49 (support/gen_x509_vectors.py), and the cert_facts / attribute-set contracts.
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
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509, X509NameBuilder};
use r2_core::error::ErrorKind;
use r2_core::keys::{Curve, KeyAlgorithm};
use r2_core::template::AttrValue;
use r2_core::x509info::{
    Classifier, cert_attributes, cert_facts, certificate_details, memory_cert_attributes,
    rfc4514_string, spki_facts,
};

/// c2 services/conftest `rsa_cert`: CN=unit-test-cert, valid now .. now + 1 day.
fn rsa_cert_der() -> Vec<u8> {
    cn_cert(&rsa_key(2048), "unit-test-cert").to_der().unwrap()
}

/// A certificate with chosen serial, validity (unix seconds) and names.
fn custom_cert(
    key: &PKey<Private>,
    serial: &BigNum,
    not_before: i64,
    not_after: i64,
    subject: &[(Nid, &str)],
    issuer: &[(Nid, &str)],
) -> Vec<u8> {
    let name = |entries: &[(Nid, &str)]| {
        let mut builder = X509NameBuilder::new().unwrap();
        for (nid, value) in entries {
            builder.append_entry_by_nid(*nid, value).unwrap();
        }
        builder.build()
    };
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&Asn1Integer::from_bn(serial).unwrap())
        .unwrap();
    builder.set_subject_name(&name(subject)).unwrap();
    builder.set_issuer_name(&name(issuer)).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(not_before).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(not_after).unwrap())
        .unwrap();
    builder.set_pubkey(key).unwrap();
    builder.sign(key, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}

#[test]
fn test_certificate_details_rows() {
    let rows = certificate_details(&rsa_cert_der()).unwrap();
    let names: Vec<&str> = rows.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        [
            "subject",
            "issuer",
            "serial",
            "not valid before",
            "not valid after"
        ]
    );
    let get = |key: &str| rows.iter().find(|(k, _)| k == key).unwrap().1.clone();
    assert_eq!(get("subject"), "CN=unit-test-cert");
    assert_eq!(get("issuer"), "CN=unit-test-cert");
}

#[test]
fn test_certificate_details_garbage() {
    let err = certificate_details(b"\x30\x03\x02\x01\x00").unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(err.message.contains("X.509"));
    assert!(
        err.message
            .starts_with("certificate is not valid DER X.509: ")
    );
}

#[test]
fn certificate_details_formats_serial_and_validity_like_pyca() {
    let key = p256();
    // 2001-09-09T01:46:40Z .. 2286-11-20T17:46:39Z (GeneralizedTime beyond 2049)
    let der = custom_cert(
        &key,
        &BigNum::from_hex_str("00ab").unwrap(),
        1_000_000_000,
        9_999_999_999,
        &[(Nid::COMMONNAME, "s"), (Nid::ORGANIZATIONNAME, "O, Inc.")],
        &[(Nid::COMMONNAME, "issuer")],
    );
    let rows = certificate_details(&der).unwrap();
    assert_eq!(
        rows,
        vec![
            ("subject".to_owned(), "O=O\\, Inc.,CN=s".to_owned()),
            ("issuer".to_owned(), "CN=issuer".to_owned()),
            ("serial".to_owned(), "ab".to_owned()),
            (
                "not valid before".to_owned(),
                "2001-09-09T01:46:40+00:00".to_owned()
            ),
            (
                "not valid after".to_owned(),
                "2286-11-20T17:46:39+00:00".to_owned()
            ),
        ]
    );
    let zero = custom_cert(&key, &BigNum::from_u32(0).unwrap(), 0, 86_400, &[], &[]);
    let rows = certificate_details(&zero).unwrap();
    assert_eq!(rows[0].1, "");
    assert_eq!(rows[2].1, "0");
    assert_eq!(rows[3].1, "1970-01-01T00:00:00+00:00");
    let big = BigNum::from_hex_str("0102030405060708090a0b0c0d0e0f1011121314").unwrap();
    let der = custom_cert(&key, &big, 0, 1, &[], &[]);
    assert_eq!(
        certificate_details(&der).unwrap()[2].1,
        "102030405060708090a0b0c0d0e0f1011121314"
    );
}

#[test]
fn cert_attribute_sets_match_c2() {
    let key = p256();
    let der = custom_cert(
        &key,
        &BigNum::from_u32(0x1234).unwrap(),
        1_700_000_000,
        1_800_000_000,
        &[(Nid::COMMONNAME, "sub")],
        &[(Nid::COMMONNAME, "iss"), (Nid::COUNTRYNAME, "LU")],
    );
    let pkcs11 = cert_attributes(&der).unwrap();
    assert_eq!(
        pkcs11.into_iter().collect::<Vec<_>>(),
        vec![
            (
                "CKA_ISSUER".to_owned(),
                AttrValue::Str("C=LU,CN=iss".to_owned())
            ),
            (
                "CKA_SERIAL_NUMBER".to_owned(),
                AttrValue::Str("1234".to_owned())
            ),
            (
                "CKA_SUBJECT".to_owned(),
                AttrValue::Str("CN=sub".to_owned())
            ),
        ]
    );
    let memory = memory_cert_attributes(&der).unwrap();
    assert_eq!(
        memory.into_iter().collect::<Vec<_>>(),
        vec![
            (
                "issuer".to_owned(),
                AttrValue::Str("C=LU,CN=iss".to_owned())
            ),
            (
                "not_valid_after".to_owned(),
                AttrValue::Str("2027-01-15T08:00:00+00:00".to_owned())
            ),
            (
                "not_valid_before".to_owned(),
                AttrValue::Str("2023-11-14T22:13:20+00:00".to_owned())
            ),
            (
                "serial_number".to_owned(),
                AttrValue::Str("1234".to_owned())
            ),
            ("subject".to_owned(), AttrValue::Str("CN=sub".to_owned())),
        ]
    );
    assert!(cert_attributes(b"\x30\x00").is_err());
    assert!(memory_cert_attributes(b"junk").is_err());
}

#[test]
fn cert_facts_reports_key_names_and_exact_der_parts() {
    let key = rsa_key(2048);
    let cert = cn_cert(&key, "facts");
    let der = cert.to_der().unwrap();
    let facts = cert_facts(&der, Classifier::KeyParse).unwrap();
    assert_eq!(facts.algorithm, KeyAlgorithm::Rsa);
    assert_eq!(facts.size_bits, Some(2048));
    assert_eq!(facts.curve, None);
    assert_eq!(facts.spki_der, spki_der(&key));
    assert_eq!(facts.subject_der, cert.subject_name().to_der().unwrap());
    assert_eq!(facts.issuer_der, cert.issuer_name().to_der().unwrap());
    let serial = cert.serial_number().to_bn().unwrap().to_vec();
    let mut serial_der = vec![0x02];
    let body = if serial[0] & 0x80 != 0 {
        [vec![0], serial].concat()
    } else {
        serial
    };
    serial_der.push(body.len() as u8);
    serial_der.extend(body);
    assert_eq!(facts.serial_der, serial_der);
    assert_eq!(facts.subject_cn.as_deref(), Some("facts"));
    // CKA_SUBJECT bytes are those of the certificate
    assert!(
        der.windows(facts.subject_der.len())
            .any(|w| w == facts.subject_der.as_slice())
    );
}

#[test]
fn classifiers_differ_only_where_c2s_did() {
    let other = ec_key(Nid::SECP256K1);
    let der = cn_cert(&other, "k1").to_der().unwrap();
    let keyparse = cert_facts(&der, Classifier::KeyParse).unwrap();
    assert_eq!(keyparse.curve, Some(Curve::Other("secp256k1".to_owned())));
    let pkcs11 = cert_facts(&der, Classifier::Pkcs11).unwrap();
    assert_eq!((pkcs11.algorithm, pkcs11.curve), (KeyAlgorithm::Ec, None));
    for (key, curve) in [
        (p256(), Curve::P256),
        (ec_key(Nid::SECP384R1), Curve::P384),
        (ec_key(Nid::SECP521R1), Curve::P521),
    ] {
        let der = cn_cert(&key, "c").to_der().unwrap();
        assert_eq!(
            cert_facts(&der, Classifier::Pkcs11).unwrap().curve,
            Some(curve)
        );
    }
    for (key, alg, curve) in [
        (ed25519(), KeyAlgorithm::EcEdwards, Curve::Ed25519),
        (ed448(), KeyAlgorithm::EcEdwards, Curve::Ed448),
    ] {
        let der = cn_cert(&key, "c").to_der().unwrap();
        for classifier in [Classifier::KeyParse, Classifier::Pkcs11] {
            let facts = cert_facts(&der, classifier).unwrap();
            assert_eq!(
                (facts.algorithm, facts.curve, facts.size_bits),
                (alg, Some(curve.clone()), None)
            );
        }
    }
    // DSA: the two classifiers' texts
    let dsa = PKey::from_dsa(openssl::dsa::Dsa::generate(1024).unwrap()).unwrap();
    let der = cn_cert(&dsa, "dsa").to_der().unwrap();
    let err = cert_facts(&der, Classifier::KeyParse).unwrap_err();
    assert_eq!(err.message, "unsupported key algorithm: DSAPublicKey");
    assert_eq!(
        err.hint.as_deref(),
        Some("supported: AES, RSA, EC, Ed25519/Ed448, X25519/X448")
    );
    let err = cert_facts(&der, Classifier::Pkcs11).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert_eq!(err.message, "unsupported public key type DSAPublicKey");
    assert_eq!(err.hint, None);
    // X25519 SPKI
    let x = x25519();
    assert_eq!(
        spki_facts(&spki_der(&x), Classifier::Pkcs11).unwrap(),
        (KeyAlgorithm::EcMontgomery, Some(Curve::X25519), None)
    );
}

#[test]
fn cert_facts_errors() {
    let err = cert_facts(b"\x30\x03\x02\x01\x00", Classifier::KeyParse).unwrap_err();
    assert!(
        err.message
            .starts_with("certificate is not valid DER X.509: ")
    );
    // an unsupported curve → invalid public key (pyca's lazy public_key() failure)
    let signer = p256();
    let key = ec_key(Nid::X9_62_PRIME239V1);
    let mut builder = X509::builder().unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(1).unwrap())
        .unwrap();
    builder.sign(&signer, MessageDigest::sha256()).unwrap();
    let der = builder.build().to_der().unwrap();
    for classifier in [Classifier::KeyParse, Classifier::Pkcs11] {
        let err = cert_facts(&der, classifier).unwrap_err();
        assert_eq!(
            err.message,
            "certificate contains an invalid public key: Curve 1.2.840.10045.3.1.4 is not supported"
        );
    }
    let err = spki_facts(b"\x30\x00", Classifier::KeyParse).unwrap_err();
    assert!(
        err.message
            .starts_with("public key is not a valid DER SubjectPublicKeyInfo: ")
    );
}

#[test]
fn certificates_with_oids_const_oid_cannot_hold_still_load() {
    // pyca reads OIDs with unbounded arcs (e.g. 2.999 and 2.25.<uuid>); so does r2.
    let key = p256();
    let subject = r2_core::x509build::parse_rfc4514_subject(
        "2.999=x,2.25.329800735698586629295641978511506172918=y",
    )
    .unwrap();
    let name = openssl::x509::X509Name::from_der(&subject).unwrap();
    let mut builder = X509::builder().unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(1).unwrap())
        .unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    let der = builder.build().to_der().unwrap();
    let rows = certificate_details(&der).unwrap();
    assert_eq!(
        rows[0].1,
        "2.999=x,2.25.329800735698586629295641978511506172918=y"
    );
}

#[test]
fn rfc4514_string_matches_pyca_vectors() {
    for (case, der_hex, expected) in x509_vectors::NAMES {
        let der = unhex(der_hex);
        let got = rfc4514_string(&der);
        match expected {
            Ok((text, _cn)) => assert_eq!(got.unwrap(), *text, "{case}"),
            Err(text) => {
                let err = got.expect_err(case);
                assert_eq!(err.kind, ErrorKind::KeyParse, "{case}");
                // pyca's text for ValueError/TypeError; KeyError cases only fail.
                if let Some(detail) = text
                    .strip_prefix("ValueError: ")
                    .or_else(|| text.strip_prefix("TypeError: "))
                {
                    assert_eq!(
                        err.message,
                        format!("name is not a valid DER X.509 Name: {detail}"),
                        "{case}"
                    );
                }
            }
        }
    }
}

#[test]
fn subject_cn_follows_pyca_first_common_name() {
    let key = p256();
    for (case, der_hex, expected) in x509_vectors::NAMES {
        let Ok((_, cn)) = expected else { continue };
        let name = openssl::x509::X509Name::from_der(&unhex(der_hex));
        let Ok(name) = name else { continue }; // OpenSSL cannot carry every vector
        let mut builder = X509::builder().unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder
            .set_not_before(&Asn1Time::from_unix(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::from_unix(1).unwrap())
            .unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let der = builder.build().to_der().unwrap();
        let facts = cert_facts(&der, Classifier::KeyParse).unwrap();
        assert_eq!(facts.subject_cn.as_deref(), *cn, "{case}");
    }
}

// ------------------------------------------- x500UniqueIdentifier, year 0, PKCS#11 skips

#[test]
fn unique_identifier_bit_string_renders_as_hex() {
    // pyca: the BIT STRING value is bytes (its raw content) → "2.5.4.45=#<hex>".
    let key = p256();
    let subject = raw_name(&[(CN_OID, 0x0c, b"x"), (UID_OID, 0x03, b"\x00\xab")]);
    let der = name_cert(&key, &subject);
    let rows = certificate_details(&der).unwrap();
    assert_eq!(
        rows[0],
        ("subject".to_owned(), "2.5.4.45=#00ab,CN=x".to_owned())
    );
    assert_eq!(rows[1].1, "2.5.4.45=#00ab,CN=x");
    let facts = cert_facts(&der, Classifier::Pkcs11).unwrap();
    assert_eq!(facts.subject_cn.as_deref(), Some("x"));
    let attrs = cert_attributes(&der).unwrap();
    assert_eq!(
        attrs["CKA_SUBJECT"],
        AttrValue::Str("2.5.4.45=#00ab,CN=x".to_owned())
    );
    let attrs = memory_cert_attributes(&der).unwrap();
    assert_eq!(
        attrs["subject"],
        AttrValue::Str("2.5.4.45=#00ab,CN=x".to_owned())
    );
    let only = name_cert(&key, &raw_name(&[(UID_OID, 0x03, b"\x01\x02")]));
    assert_eq!(certificate_details(&only).unwrap()[0].1, "2.5.4.45=#0102");
}

#[test]
fn year_zero_validity_fails_only_where_c2_formatted_it() {
    // pyca loads GeneralizedTime 0000…; Python's datetime refuses year 0 (c2 crashed in
    // certificate_details / the memory attributes). The PKCS#11 attributes never read it.
    let key = p256();
    let name = raw_name(&[(CN_OID, 0x0c, b"y0")]);
    let der = raw_cert(&key, &name, &name, "00000101000000Z", "20500101000000Z");
    let expected = "certificate is not valid DER X.509: year 0 is out of range";
    assert_eq!(certificate_details(&der).unwrap_err().message, expected);
    assert_eq!(memory_cert_attributes(&der).unwrap_err().message, expected);
    assert_eq!(
        cert_attributes(&der).unwrap()["CKA_SUBJECT"],
        AttrValue::Str("CN=y0".to_owned())
    );
    assert!(cert_facts(&der, Classifier::Pkcs11).is_ok());
}

#[test]
fn pkcs11_skip_classification_mirrors_pycas_exception_classes() {
    use r2_core::x509info::pkcs11_skips_certificate;
    let key = p256();
    // ValueError in c2 → skipped
    let skipped = [
        b"\x30\x00".to_vec(),
        name_cert(&key, &raw_name(&[(CN_OID, 0x0c, b"ZZ\xffQ")])),
        name_cert(&key, &raw_name(&[(CN_OID, 0x13, b"a_b")])),
    ];
    for der in skipped {
        let err = cert_facts(&der, Classifier::Pkcs11)
            .and_then(|_| cert_attributes(&der))
            .unwrap_err();
        assert!(pkcs11_skips_certificate(&err), "{}", err.message);
    }
    // TypeError / KeyError / UnsupportedAlgorithm / KeyParseError in c2 → propagated
    let propagated = [
        name_cert(&key, &raw_name(&[(CN_OID, 0x03, b"\x00ab")])),
        name_cert(&key, &raw_name(&[(CN_OID, 0x30, b"")])),
    ];
    for der in propagated {
        let err = cert_attributes(&der).unwrap_err();
        assert!(!pkcs11_skips_certificate(&err), "{}", err.message);
    }
    let odd_curve = cn_cert(&ec_key(Nid::X9_62_PRIME239V1), "c")
        .to_der()
        .unwrap();
    let err = cert_facts(&odd_curve, Classifier::Pkcs11).unwrap_err();
    assert_eq!(
        err.message,
        "certificate contains an invalid public key: Curve 1.2.840.10045.3.1.4 is not supported"
    );
    assert!(!pkcs11_skips_certificate(&err));
    let dsa = {
        let dsa = openssl::dsa::Dsa::generate(1024).unwrap();
        cn_cert(&PKey::from_dsa(dsa).unwrap(), "d")
            .to_der()
            .unwrap()
    };
    let err = cert_facts(&dsa, Classifier::Pkcs11).unwrap_err();
    assert_eq!(err.message, "unsupported public key type DSAPublicKey");
    assert!(!pkcs11_skips_certificate(&err));
    let not_keyparse = r2_core::error::ConsoleError::crypto("x");
    assert!(!pkcs11_skips_certificate(&not_keyparse));
}

#[test]
fn certificates_get_pycas_load_time_structure_checks() {
    use r2_core::x509info::pkcs11_skips_certificate;
    // the TBS version: an encoded DEFAULT (v1) is pyca's EncodedDefault (a ValueError — the
    // PKCS#11 read path skipped it); v2 or a version over v3 is InvalidVersion (c2 crashed,
    // §11 D12(b) — propagated).
    let der = cn_cert(&p256(), "v").to_der().unwrap();
    let with_version = |version: u8| {
        let mut cert = der_items(&der);
        let mut tbs = der_items(&cert[0]);
        tbs[0] = tlv(0xa0, &tlv(0x02, &[version]));
        cert[0] = der_seq(&tbs);
        der_seq(&cert)
    };
    let err = certificate_details(&with_version(0)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert_eq!(
        err.message,
        "certificate is not valid DER X.509: error parsing asn1 value: ParseError { kind: EncodedDefault }"
    );
    assert!(pkcs11_skips_certificate(
        &cert_facts(&with_version(0), Classifier::Pkcs11).unwrap_err()
    ));
    for version in [1u8, 3] {
        let err = cert_attributes(&with_version(version)).unwrap_err();
        assert_eq!(
            err.message,
            format!("certificate is not valid DER X.509: {version} is not a valid X509 version")
        );
        assert!(!pkcs11_skips_certificate(&err));
    }
    assert!(certificate_details(&with_version(2)).is_ok());
}
