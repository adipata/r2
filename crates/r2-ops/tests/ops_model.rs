// OperationSpec helpers (invocation, param, mirrored), suggest_hint, the custom-mechanism
// helpers and the complete §4.6.6 table, row by row (spec §4.6.2/§4.6.3/§4.6.6) — R3.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]
use std::collections::BTreeSet;

use r2_core::keys::{KeyAlgorithm, KeyClass};
use r2_ops::custom::{derive_key_classes, raw_mechparam_spec};
use r2_ops::{
    OperationRegistry, OperationSpec, ParamKind, ParamSpec, ParamStruct, ParamValue, Params, Verb,
    register_builtins, suggest_hint,
};

fn reg() -> OperationRegistry {
    let mut registry = OperationRegistry::new();
    register_builtins(&mut registry).unwrap();
    registry
}

fn spec(param_struct: ParamStruct) -> OperationSpec {
    OperationSpec {
        id: "vendor.encrypt.x".to_owned(),
        verb: Verb::Encrypt,
        algorithm: KeyAlgorithm::Aes,
        key_classes: BTreeSet::from([KeyClass::Secret]),
        mechanism: "vendor.x".to_owned(),
        cli_name: "x".to_owned(),
        label: "X".to_owned(),
        params: vec![ParamSpec::new("mechparam", ParamKind::Bytes, "p")],
        provider_types: None,
        providers: None,
        curves: None,
        raw_ckm: Some(0x8000_0001),
        param_struct,
    }
}

#[test]
fn invocation_copies_the_command_layer_fields() {
    let mut params = Params::new();
    params.insert("mechparam".to_owned(), ParamValue::Bytes(vec![1, 2]));
    let raw = spec(ParamStruct::Raw).invocation(params.clone());
    assert_eq!(raw.mechanism, "vendor.x");
    assert_eq!(raw.params, params);
    assert_eq!(raw.raw_ckm, Some(0x8000_0001));
    assert_eq!(raw.param_struct, ParamStruct::Raw);
    assert_eq!(raw.raw_param_bytes, Some(vec![1, 2]));
    // only the raw packer carries raw_param_bytes; a non-bytes value is not copied
    let iv = spec(ParamStruct::Iv).invocation(params);
    assert_eq!(iv.raw_param_bytes, None);
    let mut text = Params::new();
    text.insert("mechparam".to_owned(), ParamValue::Str("x".to_owned()));
    assert_eq!(
        spec(ParamStruct::Raw).invocation(text).raw_param_bytes,
        None
    );
    assert_eq!(
        spec(ParamStruct::Raw)
            .invocation(Params::new())
            .raw_param_bytes,
        None
    );
}

#[test]
fn param_lookup_and_mirror_rule() {
    let reg = reg();
    let gcm = reg.get("aes.encrypt.gcm").unwrap();
    assert_eq!(gcm.param("aad").unwrap().name, "aad");
    assert!(gcm.param("nope").is_none());
    let mirror = gcm.mirrored(Verb::Decrypt, "label", None);
    assert_eq!(mirror.id, "aes.decrypt.gcm");
    assert_eq!(mirror.key_classes, gcm.key_classes);
    // first occurrence only; key classes replaced when given
    let odd = OperationSpec {
        id: "x.encrypt.encrypt.encrypt".to_owned(),
        ..gcm.clone()
    };
    let mirror = odd.mirrored(
        Verb::Decrypt,
        "d",
        Some(BTreeSet::from([KeyClass::Private])),
    );
    assert_eq!(mirror.id, "x.decrypt.encrypt.encrypt");
    assert_eq!(mirror.label, "d");
    assert_eq!(mirror.key_classes, BTreeSet::from([KeyClass::Private]));
}

#[test]
fn suggest_hint_rules() {
    assert_eq!(
        suggest_hint("x", &[]),
        "no operations are registered for this verb and key type"
    );
    assert_eq!(
        suggest_hint("ebc", &["gcm", "cbc", "ecb", "ctr"]),
        "did you mean: ecb, cbc"
    );
    assert_eq!(
        suggest_hint("zzz", &["gcm", "cbc"]),
        "valid choices: cbc, gcm"
    );
}

#[test]
fn custom_helpers() {
    assert_eq!(
        raw_mechparam_spec(),
        ParamSpec::new(
            "mechparam",
            ParamKind::Bytes,
            "Raw mechanism parameter bytes"
        )
    );
    assert_eq!(
        derive_key_classes(Verb::Verify, KeyAlgorithm::EcEdwards),
        BTreeSet::from([KeyClass::Public, KeyClass::Certificate])
    );
    assert_eq!(
        derive_key_classes(Verb::Sign, KeyAlgorithm::Generic),
        BTreeSet::from([KeyClass::Secret])
    );
}

type Row = (
    &'static str,
    Verb,
    KeyAlgorithm,
    &'static [KeyClass],
    &'static str,
    &'static str,
    &'static str,
    &'static [&'static str],
);

const S: &[KeyClass] = &[KeyClass::Secret];
const PRIV: &[KeyClass] = &[KeyClass::Private];
const PUB: &[KeyClass] = &[KeyClass::Public, KeyClass::Certificate];
const PRIV_PUBK: &[KeyClass] = &[KeyClass::Private, KeyClass::Public];

/// The §4.6.6 table: id, verb, algorithm, key_classes, mechanism, cli, label, param names.
const TABLE: [Row; 33] = [
    (
        "aes.encrypt.ecb",
        Verb::Encrypt,
        KeyAlgorithm::Aes,
        S,
        "AES-ECB",
        "ecb",
        "AES-ECB encryption",
        &["padding"],
    ),
    (
        "aes.decrypt.ecb",
        Verb::Decrypt,
        KeyAlgorithm::Aes,
        S,
        "AES-ECB",
        "ecb",
        "AES-ECB decryption",
        &["padding"],
    ),
    (
        "aes.encrypt.cbc",
        Verb::Encrypt,
        KeyAlgorithm::Aes,
        S,
        "AES-CBC",
        "cbc",
        "AES-CBC encryption",
        &["iv", "padding"],
    ),
    (
        "aes.decrypt.cbc",
        Verb::Decrypt,
        KeyAlgorithm::Aes,
        S,
        "AES-CBC",
        "cbc",
        "AES-CBC decryption",
        &["iv", "padding"],
    ),
    (
        "aes.encrypt.gcm",
        Verb::Encrypt,
        KeyAlgorithm::Aes,
        S,
        "AES-GCM",
        "gcm",
        "AES-GCM authenticated encryption",
        &["iv", "aad", "tag_bits"],
    ),
    (
        "aes.decrypt.gcm",
        Verb::Decrypt,
        KeyAlgorithm::Aes,
        S,
        "AES-GCM",
        "gcm",
        "AES-GCM authenticated decryption",
        &["iv", "aad", "tag_bits"],
    ),
    (
        "aes.encrypt.ctr",
        Verb::Encrypt,
        KeyAlgorithm::Aes,
        S,
        "AES-CTR",
        "ctr",
        "AES-CTR encryption",
        &["counter_block", "counter_bits"],
    ),
    (
        "aes.decrypt.ctr",
        Verb::Decrypt,
        KeyAlgorithm::Aes,
        S,
        "AES-CTR",
        "ctr",
        "AES-CTR decryption",
        &["counter_block", "counter_bits"],
    ),
    (
        "aes.sign.cmac",
        Verb::Sign,
        KeyAlgorithm::Aes,
        S,
        "AES-CMAC",
        "cmac",
        "AES-CMAC MAC",
        &["mac_len"],
    ),
    (
        "aes.verify.cmac",
        Verb::Verify,
        KeyAlgorithm::Aes,
        S,
        "AES-CMAC",
        "cmac",
        "AES-CMAC MAC verification",
        &["mac_len"],
    ),
    (
        "aes.sign.gmac",
        Verb::Sign,
        KeyAlgorithm::Aes,
        S,
        "AES-GMAC",
        "gmac",
        "AES-GMAC MAC",
        &["iv", "mac_len"],
    ),
    (
        "aes.verify.gmac",
        Verb::Verify,
        KeyAlgorithm::Aes,
        S,
        "AES-GMAC",
        "gmac",
        "AES-GMAC MAC verification",
        &["iv", "mac_len"],
    ),
    (
        "rsa.encrypt.oaep",
        Verb::Encrypt,
        KeyAlgorithm::Rsa,
        PUB,
        "RSA-OAEP",
        "oaep",
        "RSA-OAEP encryption",
        &["hash", "mgf_hash", "label"],
    ),
    (
        "rsa.decrypt.oaep",
        Verb::Decrypt,
        KeyAlgorithm::Rsa,
        PRIV,
        "RSA-OAEP",
        "oaep",
        "RSA-OAEP decryption",
        &["hash", "mgf_hash", "label"],
    ),
    (
        "rsa.encrypt.pkcs1",
        Verb::Encrypt,
        KeyAlgorithm::Rsa,
        PUB,
        "RSA-PKCS1",
        "pkcs1",
        "RSA PKCS#1 v1.5 encryption",
        &[],
    ),
    (
        "rsa.decrypt.pkcs1",
        Verb::Decrypt,
        KeyAlgorithm::Rsa,
        PRIV,
        "RSA-PKCS1",
        "pkcs1",
        "RSA PKCS#1 v1.5 decryption",
        &[],
    ),
    (
        "rsa.encrypt.raw",
        Verb::Encrypt,
        KeyAlgorithm::Rsa,
        PUB,
        "RSA-RAW",
        "raw",
        "Raw RSA (textbook) encryption — input left-padded to modulus length",
        &[],
    ),
    (
        "rsa.decrypt.raw",
        Verb::Decrypt,
        KeyAlgorithm::Rsa,
        PRIV_PUBK,
        "RSA-RAW",
        "raw",
        "Raw RSA (textbook) decryption — input left-padded to modulus length",
        &[],
    ),
    (
        "rsa.sign.pkcs1",
        Verb::Sign,
        KeyAlgorithm::Rsa,
        PRIV,
        "RSA-PKCS1",
        "pkcs1",
        "RSA PKCS#1 v1.5 signature",
        &["hash"],
    ),
    (
        "rsa.verify.pkcs1",
        Verb::Verify,
        KeyAlgorithm::Rsa,
        PUB,
        "RSA-PKCS1",
        "pkcs1",
        "RSA PKCS#1 v1.5 signature verification",
        &["hash"],
    ),
    (
        "rsa.sign.pss",
        Verb::Sign,
        KeyAlgorithm::Rsa,
        PRIV,
        "RSA-PSS",
        "pss",
        "RSA-PSS signature",
        &["hash", "mgf_hash", "salt_len"],
    ),
    (
        "rsa.verify.pss",
        Verb::Verify,
        KeyAlgorithm::Rsa,
        PUB,
        "RSA-PSS",
        "pss",
        "RSA-PSS signature verification",
        &["hash", "mgf_hash", "salt_len"],
    ),
    (
        "rsa.sign.raw",
        Verb::Sign,
        KeyAlgorithm::Rsa,
        PRIV,
        "RSA-RAW",
        "raw",
        "Raw RSA signature — caller supplies the padded block",
        &[],
    ),
    (
        "rsa.verify.raw",
        Verb::Verify,
        KeyAlgorithm::Rsa,
        PUB,
        "RSA-RAW",
        "raw",
        "Raw RSA signature verification — caller supplies the padded block",
        &[],
    ),
    (
        "ec.sign.ecdsa",
        Verb::Sign,
        KeyAlgorithm::Ec,
        PRIV,
        "ECDSA",
        "ecdsa",
        "ECDSA signature (canonical fixed-width r||s)",
        &["hash"],
    ),
    (
        "ec.verify.ecdsa",
        Verb::Verify,
        KeyAlgorithm::Ec,
        PUB,
        "ECDSA",
        "ecdsa",
        "ECDSA signature verification",
        &["hash"],
    ),
    (
        "ec.sign.eddsa",
        Verb::Sign,
        KeyAlgorithm::EcEdwards,
        PRIV,
        "EDDSA",
        "eddsa",
        "EdDSA signature (Ed25519/Ed448, raw)",
        &[],
    ),
    (
        "ec.verify.eddsa",
        Verb::Verify,
        KeyAlgorithm::EcEdwards,
        PUB,
        "EDDSA",
        "eddsa",
        "EdDSA signature verification",
        &[],
    ),
    (
        "ec.derive.ecdh",
        Verb::Derive,
        KeyAlgorithm::Ec,
        PRIV,
        "ECDH",
        "ecdh",
        "ECDH key agreement",
        &["peer", "kdf", "shared_data", "out_len"],
    ),
    (
        "ec.derive.x25519",
        Verb::Derive,
        KeyAlgorithm::EcMontgomery,
        PRIV,
        "ECDH",
        "x25519",
        "X25519 key agreement",
        &["peer"],
    ),
    (
        "ec.derive.x448",
        Verb::Derive,
        KeyAlgorithm::EcMontgomery,
        PRIV,
        "ECDH",
        "x448",
        "X448 key agreement",
        &["peer"],
    ),
    (
        "generic.sign.hmac",
        Verb::Sign,
        KeyAlgorithm::Generic,
        S,
        "HMAC",
        "hmac",
        "HMAC (SHA-1/224/256/384/512) over a generic secret",
        &["hash", "mac_len"],
    ),
    (
        "generic.verify.hmac",
        Verb::Verify,
        KeyAlgorithm::Generic,
        S,
        "HMAC",
        "hmac",
        "HMAC verification",
        &["hash", "mac_len"],
    ),
];

#[test]
fn builtin_table_matches_the_spec_row_by_row() {
    let reg = reg();
    for (id, verb, algorithm, classes, mechanism, cli, label, params) in TABLE {
        let spec = reg.get(id).unwrap();
        assert_eq!(spec.verb, verb, "{id}");
        assert_eq!(spec.algorithm, algorithm, "{id}");
        assert_eq!(spec.key_classes, classes.iter().copied().collect(), "{id}");
        assert_eq!(spec.mechanism, mechanism, "{id}");
        assert_eq!(spec.cli_name, cli, "{id}");
        assert_eq!(spec.label, label, "{id}");
        let names: Vec<&str> = spec.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, params, "{id}");
        assert_eq!(spec.provider_types, None, "{id}");
        assert_eq!(spec.providers, None, "{id}");
        assert_eq!(spec.raw_ckm, None, "{id}");
        assert_eq!(spec.param_struct, ParamStruct::None, "{id}");
        if !id.starts_with("ec.derive.x") {
            assert_eq!(spec.curves, None, "{id}");
        }
        for param in &spec.params {
            // every ENUM default is `Enum` (§4.6.1); no validators on built-ins
            if param.kind == ParamKind::Enum {
                assert!(
                    matches!(param.default, Some(ParamValue::Enum(_)) | None),
                    "{id}.{}",
                    param.name
                );
                assert!(param.choices.is_some(), "{id}.{}", param.name);
            }
            assert!(param.validate.is_none());
        }
    }
}

#[test]
fn shared_param_lists_match_the_spec() {
    let reg = reg();
    let p = |id: &str, name: &str| reg.get(id).unwrap().param(name).unwrap().clone();
    let enum_param = |name: &str, prompt: &str, default: &str, choices: &[&str]| {
        ParamSpec::new(name, ParamKind::Enum, prompt)
            .optional(Some(ParamValue::Enum(default.to_owned())))
            .choices(choices)
    };
    let hashes5 = ["sha1", "sha224", "sha256", "sha384", "sha512"];
    let hashes4 = ["sha1", "sha256", "sha384", "sha512"];
    assert_eq!(
        p("aes.encrypt.ecb", "padding"),
        enum_param("padding", "Padding", "none", &["none", "pkcs7"])
    );
    assert_eq!(
        p("aes.decrypt.cbc", "iv"),
        ParamSpec::new("iv", ParamKind::Bytes, "IV (16 bytes)").length(16)
    );
    assert_eq!(
        p("aes.encrypt.gcm", "iv"),
        ParamSpec::new("iv", ParamKind::Bytes, "IV / nonce (12 bytes typical)")
    );
    assert_eq!(
        p("aes.encrypt.gcm", "aad"),
        ParamSpec::new(
            "aad",
            ParamKind::Bytes,
            "Additional authenticated data (empty for none)"
        )
        .optional(Some(ParamValue::Bytes(Vec::new())))
    );
    assert_eq!(
        p("aes.encrypt.ctr", "counter_block"),
        ParamSpec::new(
            "counter_block",
            ParamKind::Bytes,
            "Initial counter block (16 bytes)"
        )
        .length(16)
    );
    assert_eq!(
        p("aes.encrypt.ctr", "counter_bits"),
        ParamSpec::new("counter_bits", ParamKind::Int, "Counter width in bits")
            .optional(Some(ParamValue::Int(128)))
    );
    assert_eq!(
        p("aes.verify.gmac", "iv"),
        ParamSpec::new("iv", ParamKind::Bytes, "IV (12 bytes)").length(12)
    );
    assert_eq!(
        p("generic.sign.hmac", "hash"),
        enum_param("hash", "Hash", "sha256", &hashes5)
    );
    assert_eq!(
        p("generic.sign.hmac", "mac_len"),
        ParamSpec::new(
            "mac_len",
            ParamKind::Int,
            "MAC length in bytes (empty = full digest)"
        )
        .optional(None)
    );
    assert_eq!(
        p("rsa.decrypt.oaep", "hash"),
        enum_param("hash", "Hash algorithm", "sha256", &hashes4)
    );
    assert_eq!(
        p("rsa.decrypt.oaep", "mgf_hash"),
        ParamSpec::new(
            "mgf_hash",
            ParamKind::Enum,
            "MGF1 hash algorithm (defaults to hash)"
        )
        .optional(None)
        .default_from("hash")
        .choices(&hashes4)
    );
    assert_eq!(
        p("rsa.decrypt.oaep", "label"),
        ParamSpec::new("label", ParamKind::Bytes, "OAEP label (empty for none)")
            .optional(Some(ParamValue::Bytes(Vec::new())))
    );
    assert_eq!(
        p("rsa.verify.pss", "mgf_hash"),
        ParamSpec::new(
            "mgf_hash",
            ParamKind::Enum,
            "MGF1 hash algorithm (defaults to hash)"
        )
        .optional(None)
        .default_from("hash")
        .choices(&hashes5)
    );
    assert_eq!(
        p("rsa.verify.pss", "salt_len"),
        ParamSpec::new(
            "salt_len",
            ParamKind::Int,
            "Salt length in bytes (empty = digest length, -1 = maximum)"
        )
        .optional(None)
    );
    assert_eq!(
        p("ec.verify.ecdsa", "hash"),
        enum_param("hash", "Hash algorithm", "sha256", &hashes5)
    );
    assert_eq!(
        p("ec.derive.ecdh", "peer"),
        ParamSpec::new(
            "peer",
            ParamKind::Bytes,
            "Peer public key (SPKI DER or raw point 0x04||X||Y)"
        )
    );
    assert_eq!(
        p("ec.derive.ecdh", "kdf"),
        enum_param(
            "kdf",
            "KDF applied to the shared secret",
            "null",
            &["null", "sha1", "sha256", "sha384", "sha512"]
        )
    );
    assert_eq!(
        p("ec.derive.ecdh", "shared_data"),
        ParamSpec::new(
            "shared_data",
            ParamKind::Bytes,
            "KDF shared data (empty for none)"
        )
        .optional(Some(ParamValue::Bytes(Vec::new())))
    );
    assert_eq!(
        p("ec.derive.ecdh", "out_len"),
        ParamSpec::new(
            "out_len",
            ParamKind::Int,
            "Output length in bytes (0 = curve size)"
        )
        .optional(Some(ParamValue::Int(0)))
    );
    assert_eq!(
        p("ec.derive.x25519", "peer"),
        ParamSpec::new(
            "peer",
            ParamKind::Bytes,
            "Peer public key (SPKI DER or raw 32-byte u-coordinate)"
        )
    );
    assert_eq!(
        p("ec.derive.x448", "peer"),
        ParamSpec::new(
            "peer",
            ParamKind::Bytes,
            "Peer public key (SPKI DER or raw 56-byte u-coordinate)"
        )
    );
    assert_eq!(
        p("aes.sign.cmac", "mac_len"),
        ParamSpec::new("mac_len", ParamKind::Int, "MAC length in bytes")
            .optional(Some(ParamValue::Int(16)))
    );
}
