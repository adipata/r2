// MemoryProvider behaviour for the L16 object kinds (spec §4.3/§5.9) — port of c2
// tests/unit/test_memory_objects.py: HMAC over generic secrets (independent cross-check +
// RFC 4231 vector), generic secret import/generate/wrap rules, CKO_DATA objects, and the
// key-type checks.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod support;

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_memory::MemoryProvider;
use r2_provider::{KeySelector, Provider, WrapOptions};
use support::*;

const DATA: &[u8] = b"what do ya want for nothing?";
const VALUE: &[u8] = b"\x00\x01 opaque data object bytes \xff";

fn key() -> Vec<u8> {
    (1u8..=32).collect()
}

fn import_generic(provider: &MemoryProvider, key: &[u8], label: &str) -> KeyInfo {
    provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, key.to_vec()),
            label,
            None,
            None,
        )
        .unwrap()
}

fn import_aes32(provider: &MemoryProvider, label: &str) -> KeyInfo {
    provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![0u8; 32]),
            label,
            None,
            None,
        )
        .unwrap()
}

fn data_material() -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, VALUE.to_vec())
}

/// Independent HMAC (c2: stdlib `hmac.new`).
fn reference_hmac(key: &[u8], data: &[u8], md: MessageDigest) -> Vec<u8> {
    let pkey = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(md, &pkey).unwrap();
    signer.update(data).unwrap();
    signer.sign_to_vec().unwrap()
}

// ---------------------------------------------------------------------------------------
// HMAC (§5.9)
// ---------------------------------------------------------------------------------------

#[test]
fn test_hmac_matches_stdlib_for_every_hash() {
    for (hash_name, md, size) in [
        ("sha1", MessageDigest::sha1(), 20),
        ("sha224", MessageDigest::sha224(), 28),
        ("sha256", MessageDigest::sha256(), 32),
        ("sha384", MessageDigest::sha384(), 48),
        ("sha512", MessageDigest::sha512(), 64),
    ] {
        let provider = make();
        let info = import_generic(&provider, &key(), "g");
        let hmac = mech("HMAC", &[("hash", text(hash_name))]);
        let mac = provider.sign(&info, &hmac, DATA).unwrap();
        assert_eq!(mac, reference_hmac(&key(), DATA, md));
        assert_eq!(mac.len(), size);
        assert!(provider.verify(&info, &hmac, DATA, &mac).unwrap());
        assert!(
            !provider
                .verify(&info, &hmac, b"what do ya want for nothing?!", &mac)
                .unwrap()
        );
    }
}

#[test]
fn test_hmac_rfc4231_case2_sha256_vector() {
    let provider = make();
    let info = import_generic(&provider, b"Jefe", "g");
    let mac = provider
        .sign(&info, &mech("HMAC", &[("hash", text("sha256"))]), DATA)
        .unwrap();
    assert_eq!(
        mac,
        hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
}

#[test]
fn test_hmac_defaults_to_sha256_and_truncates_by_mac_len() {
    let provider = make();
    let info = import_generic(&provider, &key(), "g");
    let full = provider.sign(&info, &mech("HMAC", &[]), DATA).unwrap();
    assert_eq!(full, reference_hmac(&key(), DATA, MessageDigest::sha256()));
    let mac16 = mech("HMAC", &[("mac_len", int(16))]);
    let short = provider.sign(&info, &mac16, DATA).unwrap();
    assert_eq!(short, full[..16]);
    assert!(provider.verify(&info, &mac16, DATA, &short).unwrap());
    let err = err_class(
        provider.sign(&info, &mech("HMAC", &[("mac_len", int(0))]), DATA),
        "ParamError",
    );
    assert_eq!(err.message, "mac_len must be between 1 and 32 bytes");
    err_class(
        provider.sign(&info, &mech("HMAC", &[("mac_len", int(33))]), DATA), // > SHA-256 digest
        "ParamError",
    );
    let sha512 = mech("HMAC", &[("hash", text("sha512")), ("mac_len", int(64))]);
    assert_eq!(provider.sign(&info, &sha512, DATA).unwrap().len(), 64);
}

#[test]
fn test_hmac_needs_generic_and_cmac_needs_aes() {
    let provider = make();
    let aes = import_aes32(&provider, "aes");
    let generic = import_generic(&provider, &key(), "g");
    let err = err_class(
        provider.sign(&aes, &mech("HMAC", &[]), DATA),
        "UnsupportedOperationError",
    );
    assert!(err.message.contains("generic secret"));
    assert_eq!(
        err.message,
        "sign with HMAC requires a generic secret key (got aes secret)"
    );
    let err = err_class(
        provider.sign(&generic, &mech("AES-CMAC", &[]), DATA),
        "UnsupportedOperationError",
    );
    assert!(err.message.contains("AES"));
    assert_eq!(
        err.message,
        "sign with AES-CMAC requires a secret AES key (got generic secret)"
    );
    err_class(
        provider.encrypt(
            &generic,
            &mech("AES-ECB", &[("padding", text("pkcs7"))]),
            DATA,
        ),
        "UnsupportedOperationError",
    );
}

// ---------------------------------------------------------------------------------------
// generic secrets
// ---------------------------------------------------------------------------------------

#[test]
fn test_generic_secret_any_length_round_trip() {
    let provider = make();
    let short = import_generic(&provider, b"\x01\x02\x03\x04\x05", "short");
    assert_eq!(short.algorithm, KeyAlgorithm::Generic);
    assert_eq!(short.size_bits, Some(40));
    assert_eq!(
        *provider.export_key(&short).unwrap().data,
        b"\x01\x02\x03\x04\x05"
    );
    let empty = KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, Vec::new());
    let err = err_class(
        provider.import_key(&empty, "empty", None, None),
        "KeyParseError",
    );
    assert_eq!(err.message, "generic secret key material must not be empty");
}

#[test]
fn test_generate_generic_secret_size_rules() {
    let provider = make();
    let info = generate(
        &provider,
        KeyAlgorithm::Generic,
        Some(512),
        None,
        "g512",
        None,
    )
    .unwrap();
    assert_eq!(
        (info.algorithm, info.size_bits, info.key_class),
        (KeyAlgorithm::Generic, Some(512), KeyClass::Secret)
    );
    assert_eq!(provider.export_key(&info).unwrap().data.len(), 64);
    for bad in [0u32, 12, 16384] {
        let err = err_class(
            generate(
                &provider,
                KeyAlgorithm::Generic,
                Some(bad),
                None,
                &format!("bad{bad}"),
                None,
            ),
            "ParamError",
        );
        assert_eq!(
            err.message,
            format!(
                "invalid generic secret size {bad}; expected a multiple of 8 between 8 and 8192 bits"
            )
        );
    }
    let err = err_class(
        generate(&provider, KeyAlgorithm::Generic, None, None, "nosize", None),
        "ParamError",
    );
    assert_eq!(err.message, "size_bits is required for generic");
    for listing_only in [KeyAlgorithm::None, KeyAlgorithm::Other] {
        let err = err_class(
            generate(&provider, listing_only, Some(128), None, "nope", None),
            "ParamError",
        );
        assert_eq!(err.message, format!("cannot generate {listing_only} keys"));
        assert_eq!(err.param_name(), Some("algorithm"));
    }
}

#[test]
fn test_generic_secret_wraps_and_unwraps_under_an_aes_kek() {
    let provider = make();
    let kek = generate(&provider, KeyAlgorithm::Aes, Some(256), None, "kek", None).unwrap();
    let value: Vec<u8> = (40u8..77).collect(); // 37 bytes
    let target = import_generic(&provider, &value, "target");
    let kwp = mech("AES-KEY-WRAP-PAD", &[]);
    let blob = provider
        .wrap_key(&kek, &kwp, &target, &WrapOptions::default())
        .unwrap();
    let unwrapped = provider
        .unwrap_key(
            &kek,
            &kwp,
            &blob,
            &unwrap_req(
                KeyAlgorithm::Generic,
                KeyClass::Secret,
                "unwrapped",
                None,
                None,
            ),
        )
        .unwrap();
    assert_eq!(unwrapped.algorithm, KeyAlgorithm::Generic);
    assert_eq!(*provider.export_key(&unwrapped).unwrap().data, value);
}

// ---------------------------------------------------------------------------------------
// data objects
// ---------------------------------------------------------------------------------------

#[test]
fn test_data_object_lifecycle() {
    let provider = make();
    let info = provider
        .import_key(&data_material(), "blob", None, None)
        .unwrap();
    assert_eq!(
        (info.key_class, info.algorithm, info.key_ref.key_id.clone()),
        (KeyClass::Data, KeyAlgorithm::None, None)
    );
    assert_eq!(info.size_bits, u32::try_from(VALUE.len() * 8).ok());
    assert!(info.exportable);
    assert_eq!(
        provider
            .find_key(&KeySelector::label("blob").with_class(Some(KeyClass::Data)))
            .unwrap()
            .key_ref,
        info.key_ref
    );
    assert_eq!(*provider.export_key(&info).unwrap().data, VALUE);
    let template = provider.read_key_template(&info).unwrap();
    let names: Vec<&str> = template.attrs.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, ["CKA_LABEL"]); // no CKA_ID (§4.3)
    let result = provider
        .update_key(
            &info,
            &KeyTemplate::new(vec![TemplateAttr::new(
                "CKA_LABEL",
                AttrKind::Str,
                AttrValue::Str("blob2".to_owned()),
            )]),
        )
        .unwrap();
    assert_eq!(result.key.key_ref.label, "blob2");
    assert_eq!(result.key.key_ref.key_id, None);
    let err = err_class(
        provider.update_key(
            &result.key,
            &KeyTemplate::new(vec![TemplateAttr::new(
                "CKA_ID",
                AttrKind::Bytes,
                AttrValue::Bytes(b"\x01".to_vec()),
            )]),
        ),
        "ParamError",
    );
    assert_eq!(err.message, "data objects carry no CKA_ID (§4.3)");
    assert_eq!(err.param_name(), Some("CKA_ID"));
    assert_eq!(
        err.hint.as_deref(),
        Some("data objects are identified by label alone")
    );
    provider.delete_key(&result.key).unwrap();
    err_class(find(&provider, "blob2", None), "KeyNotFoundError");
}

#[test]
fn test_data_object_refuses_ids_twins_and_verbs() {
    let provider = make();
    let err = err_class(
        provider.import_key(&data_material(), "blob", None, Some(b"\x01")),
        "ParamError",
    );
    assert_eq!(err.message, "data objects carry no CKA_ID (§4.3)");
    assert_eq!(err.param_name(), Some("key_id"));
    assert_eq!(
        err.hint.as_deref(),
        Some("drop --id; data objects are identified by label alone")
    );
    let info = provider
        .import_key(&data_material(), "blob", None, None)
        .unwrap();
    let err = err_class(
        provider.import_key(&data_material(), "blob", None, None),
        "DuplicateKeyError",
    );
    assert_eq!(
        err.message,
        "a data object with label 'blob' and no id already exists on mem"
    );
    err_class(
        provider.sign(&info, &mech("HMAC", &[]), DATA),
        "UnsupportedOperationError",
    );
    err_class(
        provider.encrypt(&info, &mech("AES-GCM", &[("iv", bytes(&[0u8; 12]))]), DATA),
        "UnsupportedOperationError",
    );
    let kek = generate(&provider, KeyAlgorithm::Aes, Some(256), None, "kek", None).unwrap();
    err_class(
        provider.wrap_key(
            &kek,
            &mech("AES-KEY-WRAP-PAD", &[]),
            &info,
            &WrapOptions::default(),
        ),
        "UnsupportedOperationError",
    );
    // data material never carries an algorithm
    let aes_data = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Data, VALUE.to_vec());
    let err = err_class(
        provider.import_key(&aes_data, "x", None, None),
        "KeyParseError",
    );
    assert_eq!(err.message, "data objects carry no algorithm (got 'aes')");
    assert_eq!(
        err.hint.as_deref(),
        Some("data material uses KeyAlgorithm.NONE")
    );
    let empty = KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, Vec::new());
    let err = err_class(
        provider.import_key(&empty, "x", None, None),
        "KeyParseError",
    );
    assert_eq!(err.message, "data object value must not be empty");
}
