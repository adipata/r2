// MemoryProvider wrap/unwrap for the §5.4 KEK-load mechanisms — port of c2
// tests/unit/test_memory_wrap_kek.py.
//
// AES-CBC, AES-GCM and RSA-PKCS1 are wrap-capable for the wrapped-key load feature.
// Round-trips prove the provider agrees with itself; the cross-checks build the same blob
// with OpenSSL directly (a different code path, spec §8 "KAT cross-check" style) so an
// externally wrapped blob really does load. Private-key payloads travel as unencrypted
// PKCS#8 DER — the §5.5 convention the copy routes use.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod support;

use openssl::pkey::{PKey, Private};
use openssl::rsa::Padding;
use openssl::symm::{Cipher, encrypt, encrypt_aead};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::ParamValue;
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_memory::MemoryProvider;
use r2_provider::{Provider, WrapOptions};
use support::*;

const TARGET_BYTES: [u8; 32] = [0xab; 32];

fn kek_bytes() -> Vec<u8> {
    (0u8..32).collect()
}
fn iv16() -> Vec<u8> {
    (0u8..16).collect()
}
fn iv12() -> Vec<u8> {
    (0u8..12).collect()
}

fn opts() -> WrapOptions {
    WrapOptions::default()
}

fn import_private_key(provider: &MemoryProvider, key: &PKey<Private>, label: &str) -> KeyInfo {
    let algorithm = if key.rsa().is_ok() {
        KeyAlgorithm::Rsa
    } else {
        KeyAlgorithm::Ec
    };
    import_private(provider, key, algorithm, label, None, None)
}

fn import_rsa_public(provider: &MemoryProvider, key: &PKey<Private>, label: &str) -> KeyInfo {
    import_public(provider, key, KeyAlgorithm::Rsa, label, None)
}

// ---------------------------------------------------------------------------------------
// round-trips
// ---------------------------------------------------------------------------------------

#[test]
fn test_aes_kek_round_trip_secret() {
    let cases: [(&str, Vec<(&str, ParamValue)>); 4] = [
        (
            "AES-CBC",
            vec![("iv", bytes(&iv16())), ("padding", text("pkcs7"))],
        ),
        (
            "AES-CBC",
            vec![("iv", bytes(&iv16())), ("padding", text("none"))],
        ),
        (
            "AES-GCM",
            vec![
                ("iv", bytes(&iv12())),
                ("aad", bytes(b"")),
                ("tag_bits", text("128")),
            ],
        ),
        (
            "AES-GCM",
            vec![
                ("iv", bytes(&iv12())),
                ("aad", bytes(b"ctx")),
                ("tag_bits", text("96")),
            ],
        ),
    ];
    for (name, params) in cases {
        let provider = make();
        let kek = import_aes(&provider, &kek_bytes(), "kek", None, None);
        let target = import_aes(&provider, &TARGET_BYTES, "target", None, None);
        let mechanism = mech(name, &params);
        let blob = provider
            .wrap_key(&kek, &mechanism, &target, &opts())
            .unwrap();
        let restored = provider
            .unwrap_key(
                &kek,
                &mechanism,
                &blob,
                &unwrap_req(
                    KeyAlgorithm::Aes,
                    KeyClass::Secret,
                    "restored",
                    Some(exportable()),
                    None,
                ),
            )
            .unwrap();
        assert_eq!(*provider.export_key(&restored).unwrap().data, TARGET_BYTES);
        assert_eq!(restored.size_bits, Some(256));
    }
}

#[test]
fn test_aes_kek_round_trip_private_keys() {
    for name in ["AES-CBC", "AES-GCM"] {
        let params = if name == "AES-CBC" {
            vec![("iv", bytes(&iv16()))]
        } else {
            vec![("iv", bytes(&iv12()))]
        };
        let mechanism = mech(name, &params);
        let provider = make();
        let kek = import_aes(&provider, &kek_bytes(), "kek", None, None);
        for (label, key, algorithm, curve) in [
            ("rsakey", rsa_2048(), KeyAlgorithm::Rsa, None),
            ("eckey", ec_p256(), KeyAlgorithm::Ec, Some(Curve::P256)),
        ] {
            let target = import_private_key(&provider, &key, label);
            let blob = provider
                .wrap_key(&kek, &mechanism, &target, &opts())
                .unwrap();
            let restored = provider
                .unwrap_key(
                    &kek,
                    &mechanism,
                    &blob,
                    &unwrap_req(
                        algorithm,
                        KeyClass::Private,
                        &format!("{label}-restored"),
                        Some(exportable()),
                        None,
                    ),
                )
                .unwrap();
            assert_eq!(*provider.export_key(&restored).unwrap().data, pkcs8(&key));
            assert_eq!(restored.curve, curve);
        }
    }
}

#[test]
fn test_rsa_pkcs1_round_trip() {
    let provider = make();
    let key = rsa_2048();
    let private = import_private_key(&provider, &key, "rsakek");
    let public = import_rsa_public(&provider, &key, "rsakek-pub");
    let target = import_aes(&provider, &TARGET_BYTES, "target", None, None);
    let pkcs1 = mech("RSA-PKCS1", &[]);
    let blob = provider
        .wrap_key(&public, &pkcs1, &target, &opts())
        .unwrap();
    assert_eq!(blob.len(), 256);
    let restored = provider
        .unwrap_key(
            &private,
            &pkcs1,
            &blob,
            &unwrap_req(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                "restored",
                Some(exportable()),
                None,
            ),
        )
        .unwrap();
    assert_eq!(*provider.export_key(&restored).unwrap().data, TARGET_BYTES);
}

// ---------------------------------------------------------------------------------------
// cross-checks against OpenSSL (blobs built OUTSIDE the provider)
// ---------------------------------------------------------------------------------------

/// CBC with OpenSSL's own PKCS#7 padding (an independent path from the provider's).
fn cbc_pkcs7(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    encrypt(Cipher::aes_256_cbc(), key, Some(iv), data).unwrap()
}

#[test]
fn test_cbc_wrap_matches_pyca_cbc_pkcs7() {
    let provider = make();
    let kek = import_aes(&provider, &kek_bytes(), "kek", None, None);
    let target = import_aes(&provider, &TARGET_BYTES, "target", None, None);
    let blob = provider
        .wrap_key(
            &kek,
            &mech(
                "AES-CBC",
                &[("iv", bytes(&iv16())), ("padding", text("pkcs7"))],
            ),
            &target,
            &opts(),
        )
        .unwrap();
    assert_eq!(blob, cbc_pkcs7(&kek_bytes(), &iv16(), &TARGET_BYTES));
}

#[test]
fn test_gcm_wrap_matches_pyca_aesgcm_ct_tag() {
    let provider = make();
    let kek = import_aes(&provider, &kek_bytes(), "kek", None, None);
    let target = import_aes(&provider, &TARGET_BYTES, "target", None, None);
    let blob = provider
        .wrap_key(
            &kek,
            &mech(
                "AES-GCM",
                &[
                    ("iv", bytes(&iv12())),
                    ("aad", bytes(b"ctx")),
                    ("tag_bits", text("128")),
                ],
            ),
            &target,
            &opts(),
        )
        .unwrap();
    // §5.8 convention: ct‖tag, which is exactly the AEAD one-shot output
    let mut tag = [0u8; 16];
    let mut expected = encrypt_aead(
        Cipher::aes_256_gcm(),
        &kek_bytes(),
        Some(&iv12()),
        b"ctx",
        &TARGET_BYTES,
        &mut tag,
    )
    .unwrap();
    expected.extend(tag);
    assert_eq!(blob, expected);
}

#[test]
fn test_externally_pkcs1_wrapped_blob_unwraps() {
    // The decrypt-direction KAT: v1.5 padding is randomized, so the blob is built with
    // OpenSSL and only the unwrap direction is compared.
    let provider = make();
    let key = rsa_2048();
    let private = import_private_key(&provider, &key, "rsakek");
    let rsa = key.rsa().unwrap();
    let mut blob = vec![0u8; rsa.size() as usize];
    let n = rsa
        .public_encrypt(&TARGET_BYTES, &mut blob, Padding::PKCS1)
        .unwrap();
    blob.truncate(n);
    let restored = provider
        .unwrap_key(
            &private,
            &mech("RSA-PKCS1", &[]),
            &blob,
            &unwrap_req(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                "restored",
                Some(exportable()),
                None,
            ),
        )
        .unwrap();
    assert_eq!(*provider.export_key(&restored).unwrap().data, TARGET_BYTES);
}

#[test]
fn test_externally_cbc_wrapped_ec_key_unwraps() {
    let provider = make();
    let kek = import_aes(&provider, &kek_bytes(), "kek", None, None);
    let der = pkcs8(&ec_p256());
    let blob = cbc_pkcs7(&kek_bytes(), &iv16(), &der);
    let restored = provider
        .unwrap_key(
            &kek,
            &mech(
                "AES-CBC",
                &[("iv", bytes(&iv16())), ("padding", text("pkcs7"))],
            ),
            &blob,
            &unwrap_req(
                KeyAlgorithm::Ec,
                KeyClass::Private,
                "restored",
                Some(exportable()),
                None,
            ),
        )
        .unwrap();
    assert_eq!(*provider.export_key(&restored).unwrap().data, der);
    assert_eq!(restored.curve, Some(Curve::P256));
}

// ---------------------------------------------------------------------------------------
// negatives
// ---------------------------------------------------------------------------------------

#[test]
fn test_gcm_tag_tamper_is_detected() {
    let provider = make();
    let kek = import_aes(&provider, &kek_bytes(), "kek", None, None);
    let target = import_aes(&provider, &TARGET_BYTES, "target", None, None);
    let gcm = mech("AES-GCM", &[("iv", bytes(&iv12()))]);
    let mut blob = provider.wrap_key(&kek, &gcm, &target, &opts()).unwrap();
    *blob.last_mut().unwrap() ^= 0x01;
    let err = err_class(
        provider.unwrap_key(
            &kek,
            &gcm,
            &blob,
            &unwrap_req(KeyAlgorithm::Aes, KeyClass::Secret, "nope", None, None),
        ),
        "CryptoError",
    );
    assert!(err.message.contains("authentication failed"));
}

#[test]
fn test_cbc_padding_none_rejects_misaligned_payload() {
    let provider = make();
    let kek = import_aes(&provider, &kek_bytes(), "kek", None, None);
    let target = import_private_key(&provider, &ec_p256(), "eckey"); // PKCS#8 is not 16-aligned
    let err = err_class(
        provider.wrap_key(
            &kek,
            &mech(
                "AES-CBC",
                &[("iv", bytes(&iv16())), ("padding", text("none"))],
            ),
            &target,
            &opts(),
        ),
        "ParamError",
    );
    assert!(err.message.contains("multiple of 16"));
}

#[test]
fn test_pkcs1_payload_too_large_for_the_modulus() {
    let provider = make();
    let key = rsa_2048();
    let public = import_rsa_public(&provider, &key, "rsakek-pub");
    let target = import_private_key(&provider, &rsa_2048(), "big"); // ~1.2 kB PKCS#8
    let err = err_class(
        provider.wrap_key(&public, &mech("RSA-PKCS1", &[]), &target, &opts()),
        "CryptoError",
    );
    assert!(err.message.contains("RSA-PKCS1 wrap failed"));
    assert_eq!(
        err.hint.as_deref(),
        Some(
            "PKCS#1 v1.5 fits at most k-11 payload bytes (245 at RSA-2048); use an AES KEK for private keys"
        )
    );
}

#[test]
fn test_pkcs1_unwrap_of_a_bogus_blob_leaks_no_padding_detail() {
    // Bleichenbacher hygiene. OpenSSL >= 3.2 applies *implicit rejection*: a v1.5 decrypt
    // of a corrupt blob returns deterministic pseudo-random bytes instead of failing, so
    // the error then surfaces at the parse backstop (wrong key length) rather than in the
    // decrypt branch. Either way the message says nothing about the padding.
    let provider = make();
    let private = import_private_key(&provider, &rsa_2048(), "rsakek");
    let err = provider
        .unwrap_key(
            &private,
            &mech("RSA-PKCS1", &[]),
            &[0x01u8; 256],
            &unwrap_req(KeyAlgorithm::Aes, KeyClass::Secret, "nope", None, None),
        )
        .unwrap_err();
    assert!(!err.message.to_lowercase().contains("padding"));
    assert!(
        err.message == "RSA-PKCS1 unwrap failed" || err.message.contains("AES key must be"),
        "{}",
        err.message
    );
}

#[test]
fn test_wrong_declared_algorithm_fails_the_parse_backstop() {
    let provider = make();
    let kek = import_aes(&provider, &kek_bytes(), "kek", None, None);
    let target = import_private_key(&provider, &ec_p256(), "eckey");
    let cbc = mech("AES-CBC", &[("iv", bytes(&iv16()))]);
    let blob = provider.wrap_key(&kek, &cbc, &target, &opts()).unwrap();
    let err = err_class(
        provider.unwrap_key(
            &kek,
            &cbc,
            &blob,
            // blob holds an EC key
            &unwrap_req(KeyAlgorithm::Rsa, KeyClass::Private, "nope", None, None),
        ),
        "KeyParseError",
    );
    assert_eq!(
        err.message,
        "material declares algorithm 'rsa' but data parses as 'ec'"
    );
}

#[test]
fn test_non_extractable_target_is_never_wrapped() {
    let provider = make();
    let kek = import_aes(&provider, &kek_bytes(), "kek", None, None);
    let locked = provider
        .import_key(
            &KeyMaterial {
                size_bits: Some(256),
                ..KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, TARGET_BYTES.to_vec())
            },
            "locked",
            Some(&KeyTemplate::new(vec![TemplateAttr::new(
                "CKA_EXTRACTABLE",
                AttrKind::Bool,
                AttrValue::Bool(false),
            )])),
            None,
        )
        .unwrap();
    for (name, iv) in [("AES-CBC", iv16()), ("AES-GCM", iv12())] {
        err_class(
            provider.wrap_key(&kek, &mech(name, &[("iv", bytes(&iv))]), &locked, &opts()),
            "KeyNotExportableError",
        );
    }
}

#[test]
fn test_aes_mechanisms_need_a_secret_kek() {
    let provider = make();
    let private = import_private_key(&provider, &rsa_2048(), "rsakek");
    let target = import_aes(&provider, &TARGET_BYTES, "target", None, None);
    let err = provider
        .wrap_key(
            &private,
            &mech("AES-GCM", &[("iv", bytes(&iv12()))]),
            &target,
            &opts(),
        )
        .unwrap_err();
    assert!(
        err.message.contains("requires a secret AES key"),
        "{}",
        err.message
    );
    assert_eq!(
        err.message,
        "wrap_key with an AES mechanism requires a secret AES key (got rsa private)"
    );
}

#[test]
fn test_sensitive_but_extractable_wraps_though_plain_export_refuses() {
    // §5.5/§5.6: wrappable = CKA_EXTRACTABLE alone — the reason `export --kek` exists: the
    // key cannot be plain-read, but it can leave wrapped. (c2's keyexport.export_bytes
    // refusal text "Refusing to export …" is R8's services layer; here the provider half:
    // export_key refuses, wrap_key succeeds.)
    let provider = make();
    let kek = import_aes(&provider, &kek_bytes(), "kek", None, None);
    let sensitive = provider
        .import_key(
            &KeyMaterial {
                size_bits: Some(256),
                ..KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, TARGET_BYTES.to_vec())
            },
            "sensitive",
            Some(&template(true, true)),
            None,
        )
        .unwrap();
    assert!(!sensitive.exportable);
    err_class(provider.export_key(&sensitive), "KeyNotExportableError");

    let kwp = mech("AES-KEY-WRAP-PAD", &[]);
    let blob = provider.wrap_key(&kek, &kwp, &sensitive, &opts()).unwrap();
    let restored = provider
        .unwrap_key(
            &kek,
            &kwp,
            &blob,
            &unwrap_req(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                "restored",
                Some(exportable()),
                None,
            ),
        )
        .unwrap();
    assert_eq!(*provider.export_key(&restored).unwrap().data, TARGET_BYTES);
}
