// OperationRegistry, the §4.6.6 built-in table and load_custom — the port of c2
// tests/unit/test_ops_registry.py (R3). Config values are constructed directly (no YAML):
// R2's decoder is a merge-order-only dependency.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]
use std::collections::{BTreeMap, BTreeSet};

use r2_config::model::{CustomMechanismConfig, ParamSpecConfig};
use r2_config::yaml::Value;
use r2_core::error::ErrorKind;
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyRef};
use r2_ops::{
    OperationRegistry, OperationSpec, ParamKind, ParamSpec, ParamStruct, ParamValue, Verb,
    register_builtins,
};
use r2_provider::Provider;
use r2_provider::mechanism::CANONICAL_MECHANISMS;
use r2_testkit::FakeProvider;

const EXPECTED_BUILTIN_IDS: [&str; 33] = [
    // AES encrypt/decrypt mirrors
    "aes.encrypt.ecb",
    "aes.decrypt.ecb",
    "aes.encrypt.cbc",
    "aes.decrypt.cbc",
    "aes.encrypt.gcm",
    "aes.decrypt.gcm",
    "aes.encrypt.ctr",
    "aes.decrypt.ctr",
    // AES sign/verify mirrors
    "aes.sign.cmac",
    "aes.verify.cmac",
    "aes.sign.gmac",
    "aes.verify.gmac",
    // RSA encrypt/decrypt mirrors
    "rsa.encrypt.oaep",
    "rsa.decrypt.oaep",
    "rsa.encrypt.pkcs1",
    "rsa.decrypt.pkcs1",
    "rsa.encrypt.raw",
    "rsa.decrypt.raw",
    // RSA sign/verify mirrors
    "rsa.sign.pkcs1",
    "rsa.verify.pkcs1",
    "rsa.sign.pss",
    "rsa.verify.pss",
    "rsa.sign.raw",
    "rsa.verify.raw",
    // EC sign/verify mirrors + derive
    "ec.sign.ecdsa",
    "ec.verify.ecdsa",
    "ec.sign.eddsa",
    "ec.verify.eddsa",
    "ec.derive.ecdh",
    "ec.derive.x25519",
    "ec.derive.x448",
    // generic-secret sign/verify mirror (HMAC)
    "generic.sign.hmac",
    "generic.verify.hmac",
];

fn key(algorithm: KeyAlgorithm, key_class: KeyClass, curve: Option<Curve>) -> KeyInfo {
    KeyInfo {
        key_ref: KeyRef::new("fake", "k", None),
        key_class,
        algorithm,
        size_bits: None,
        curve,
        exportable: true,
        attributes: BTreeMap::new(),
        handle: None,
    }
}

fn param<'s>(spec: &'s OperationSpec, name: &str) -> &'s ParamSpec {
    spec.param(name)
        .unwrap_or_else(|| panic!("{} has no param {name:?}", spec.id))
}

fn reg() -> OperationRegistry {
    let mut registry = OperationRegistry::new();
    register_builtins(&mut registry).unwrap();
    registry
}

fn classes(classes: &[KeyClass]) -> BTreeSet<KeyClass> {
    classes.iter().copied().collect()
}

fn names(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn ids(specs: &[&OperationSpec]) -> Vec<String> {
    specs.iter().map(|spec| spec.id.clone()).collect()
}

fn id_set(specs: &[&OperationSpec]) -> BTreeSet<String> {
    specs.iter().map(|spec| spec.id.clone()).collect()
}

fn choices(values: &[&str]) -> Option<Vec<String>> {
    Some(values.iter().map(|value| (*value).to_owned()).collect())
}

fn enum_default(text: &str) -> Option<ParamValue> {
    Some(ParamValue::Enum(text.to_owned()))
}

fn mirror_of(verb: Verb) -> Option<Verb> {
    match verb {
        Verb::Encrypt => Some(Verb::Decrypt),
        Verb::Sign => Some(Verb::Verify),
        _ => None,
    }
}

// -- TestRegistryBasics ----------------------------------------------------------------

#[test]
fn test_duplicate_id_raises_config_error() {
    let mut reg = reg();
    let spec = reg.get("aes.encrypt.gcm").unwrap().clone();
    let err = reg.register(spec).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Config);
    assert_eq!(
        err.message,
        "operation 'aes.encrypt.gcm' is already registered"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("operation ids (built-in and custom_mechanisms[].id) must be unique")
    );
}

#[test]
fn test_get_unknown_raises_with_suggestion() {
    let err = reg().get("aes.encrypt.gmc").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnknownOperation);
    assert_eq!(err.message, "unknown operation 'aes.encrypt.gmc'");
    let hint = err.hint.expect("hint");
    assert!(hint.contains("aes.encrypt.gcm"), "{hint}");
    assert!(hint.starts_with("did you mean: "), "{hint}");
}

// -- TestBuiltinTable ------------------------------------------------------------------

#[test]
fn test_full_builtin_id_set() {
    // exactly the frozen §4.6.6 table — nothing missing, nothing extra
    let reg = reg();
    for op_id in EXPECTED_BUILTIN_IDS {
        assert_eq!(reg.get(op_id).unwrap().id, op_id);
    }
    // c2 inspected `reg._specs`; r2 has no iteration API, so it enumerates every spec
    // reachable through available_for with probe keys covering every
    // verb/algorithm/class/curve combination, against probe providers of both presented
    // types ("memory", "pkcs11") whose mechanism set is the canonical one widened by every
    // mechanism the table uses. Residual gap: a stray row restricted to a specific
    // provider *name* (`providers`) or using a mechanism no expected row uses would not be
    // reached.
    let provider = FakeProvider::new("fake");
    let mut mechanisms = provider.mechanisms();
    mechanisms.extend(
        EXPECTED_BUILTIN_IDS
            .iter()
            .map(|op_id| reg.get(op_id).unwrap().mechanism.clone()),
    );
    let probes = [
        FakeProvider::new("fake").with_mechanisms(mechanisms.clone()),
        FakeProvider::new("fake")
            .with_type_name("pkcs11")
            .with_mechanisms(mechanisms),
    ];
    let algorithms = [
        KeyAlgorithm::Aes,
        KeyAlgorithm::Rsa,
        KeyAlgorithm::Ec,
        KeyAlgorithm::EcEdwards,
        KeyAlgorithm::EcMontgomery,
        KeyAlgorithm::Generic,
        KeyAlgorithm::None,
        KeyAlgorithm::Other,
    ];
    let mut curves: Vec<Option<Curve>> = Curve::KNOWN.into_iter().map(Some).collect();
    curves.push(None);
    let mut reachable = BTreeSet::new();
    for probe_provider in &probes {
        for verb in Verb::ALL {
            for algorithm in algorithms {
                for key_class in KeyClass::ALL {
                    for curve in &curves {
                        let probe = key(algorithm, key_class, curve.clone());
                        reachable.extend(id_set(&reg.available_for(verb, &probe, probe_provider)));
                    }
                }
            }
        }
    }
    assert_eq!(reachable, names(&EXPECTED_BUILTIN_IDS));
    assert_eq!(EXPECTED_BUILTIN_IDS.len(), 33);
    // the rows are registered in §4.6.6 table order
    let order = EXPECTED_BUILTIN_IDS;
    let aes_secret = key(KeyAlgorithm::Aes, KeyClass::Secret, None);
    assert_eq!(
        ids(&reg.available_for(Verb::Encrypt, &aes_secret, &provider)),
        [order[0], order[2], order[4], order[6]]
    );
}

#[test]
fn test_mirror_rows_share_cli_mechanism_and_params() {
    let reg = reg();
    for op_id in EXPECTED_BUILTIN_IDS {
        let spec = reg.get(op_id).unwrap();
        let Some(mirror_verb) = mirror_of(spec.verb) else {
            continue;
        };
        let mirror_id = op_id.replacen(
            &format!(".{}.", spec.verb.as_str()),
            &format!(".{}.", mirror_verb.as_str()),
            1,
        );
        let mirror = reg.get(&mirror_id).unwrap();
        assert_eq!(mirror.verb, mirror_verb);
        assert_eq!(mirror.cli_name, spec.cli_name);
        assert_eq!(mirror.mechanism, spec.mechanism);
        assert_eq!(mirror.params, spec.params);
        assert_eq!(mirror.algorithm, spec.algorithm);
    }
}

#[test]
fn test_key_classes() {
    let reg = reg();
    let secret = classes(&[KeyClass::Secret]);
    let private = classes(&[KeyClass::Private]);
    let public_or_cert = classes(&[KeyClass::Public, KeyClass::Certificate]);
    assert_eq!(reg.get("aes.encrypt.gcm").unwrap().key_classes, secret);
    assert_eq!(reg.get("aes.verify.cmac").unwrap().key_classes, secret);
    assert_eq!(
        reg.get("rsa.encrypt.oaep").unwrap().key_classes,
        public_or_cert
    );
    assert_eq!(reg.get("rsa.decrypt.oaep").unwrap().key_classes, private);
    assert_eq!(reg.get("rsa.sign.pss").unwrap().key_classes, private);
    assert_eq!(
        reg.get("rsa.verify.pss").unwrap().key_classes,
        public_or_cert
    );
    assert_eq!(reg.get("ec.sign.ecdsa").unwrap().key_classes, private);
    assert_eq!(
        reg.get("ec.verify.ecdsa").unwrap().key_classes,
        public_or_cert
    );
    assert_eq!(reg.get("ec.derive.ecdh").unwrap().key_classes, private);
    // r2: the whole table (§4.6.6 key_classes column)
    assert_eq!(
        reg.get("rsa.decrypt.raw").unwrap().key_classes,
        classes(&[KeyClass::Private, KeyClass::Public])
    );
}

#[test]
fn test_gcm_params() {
    let reg = reg();
    let spec = reg.get("aes.encrypt.gcm").unwrap();
    assert_eq!(spec.mechanism, "AES-GCM");
    assert_eq!(spec.cli_name, "gcm");
    let param_names: Vec<&str> = spec.params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(param_names, ["iv", "aad", "tag_bits"]);
    let iv = param(spec, "iv");
    assert!(iv.kind == ParamKind::Bytes && iv.required && iv.length.is_none());
    let aad = param(spec, "aad");
    assert!(!aad.required);
    assert_eq!(aad.default, Some(ParamValue::Bytes(Vec::new())));
    let tag_bits = param(spec, "tag_bits");
    assert_eq!(tag_bits.kind, ParamKind::Enum);
    assert_eq!(
        tag_bits.choices,
        choices(&["128", "120", "112", "104", "96"])
    );
    assert_eq!(tag_bits.default, enum_default("128"));
}

#[test]
fn test_cbc_ctr_gmac_byte_lengths() {
    let reg = reg();
    assert_eq!(
        param(reg.get("aes.encrypt.cbc").unwrap(), "iv").length,
        Some(16)
    );
    assert_eq!(
        param(reg.get("aes.encrypt.cbc").unwrap(), "padding").default,
        enum_default("pkcs7")
    );
    assert_eq!(
        param(reg.get("aes.encrypt.ecb").unwrap(), "padding").default,
        enum_default("none")
    );
    let counter_block = param(reg.get("aes.encrypt.ctr").unwrap(), "counter_block");
    assert_eq!(counter_block.length, Some(16));
    assert_eq!(
        param(reg.get("aes.encrypt.ctr").unwrap(), "counter_bits").default,
        Some(ParamValue::Int(128))
    );
    assert_eq!(
        param(reg.get("aes.sign.gmac").unwrap(), "iv").length,
        Some(12)
    );
    assert_eq!(
        param(reg.get("aes.sign.cmac").unwrap(), "mac_len").default,
        Some(ParamValue::Int(16))
    );
}

#[test]
fn test_oaep_default_from_encoding() {
    let reg = reg();
    let spec = reg.get("rsa.encrypt.oaep").unwrap();
    assert_eq!(
        param(spec, "hash").choices,
        choices(&["sha1", "sha256", "sha384", "sha512"])
    );
    assert_eq!(param(spec, "hash").default, enum_default("sha256"));
    let mgf = param(spec, "mgf_hash");
    assert_eq!(mgf.default_from.as_deref(), Some("hash"));
    assert_eq!(mgf.default, None);
    assert!(!mgf.required);
    assert_eq!(
        param(spec, "label").default,
        Some(ParamValue::Bytes(Vec::new()))
    );
}

#[test]
fn test_pss_salt_len_encoding() {
    let reg = reg();
    let spec = reg.get("rsa.sign.pss").unwrap();
    assert_eq!(
        param(spec, "hash").choices,
        choices(&["sha1", "sha224", "sha256", "sha384", "sha512"])
    );
    assert_eq!(
        param(spec, "mgf_hash").default_from.as_deref(),
        Some("hash")
    );
    let salt_len = param(spec, "salt_len");
    assert_eq!(salt_len.kind, ParamKind::Int);
    assert!(!salt_len.required);
    assert_eq!(salt_len.default, None); // None → digest length (provider-resolved)
    assert!(salt_len.prompt.contains("-1")); // the max-salt sentinel is documented
}

#[test]
fn test_no_param_rows_are_empty() {
    let reg = reg();
    for op_id in [
        "rsa.encrypt.pkcs1",
        "rsa.encrypt.raw",
        "rsa.sign.raw",
        "ec.sign.eddsa",
    ] {
        assert!(reg.get(op_id).unwrap().params.is_empty(), "{op_id}");
    }
}

#[test]
fn test_derive_rows_curves() {
    let reg = reg();
    assert_eq!(reg.get("ec.derive.ecdh").unwrap().curves, None);
    assert_eq!(reg.get("ec.sign.ecdsa").unwrap().curves, None);
    assert_eq!(reg.get("ec.sign.eddsa").unwrap().curves, None);
    assert_eq!(
        reg.get("ec.derive.x25519").unwrap().curves,
        Some(BTreeSet::from([Curve::X25519]))
    );
    assert_eq!(
        reg.get("ec.derive.x448").unwrap().curves,
        Some(BTreeSet::from([Curve::X448]))
    );
    assert_eq!(reg.get("ec.derive.x25519").unwrap().mechanism, "ECDH");
    let ecdh = reg.get("ec.derive.ecdh").unwrap();
    assert_eq!(ecdh.params[0].name, "peer");
    let param_names: Vec<&str> = ecdh.params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(param_names, ["peer", "kdf", "shared_data", "out_len"]);
}

// -- TestResolveCli --------------------------------------------------------------------

#[test]
fn test_happy_path() {
    let reg = reg();
    let aes = key(KeyAlgorithm::Aes, KeyClass::Secret, None);
    assert_eq!(
        reg.resolve_cli(Verb::Encrypt, &aes, "gcm").unwrap().id,
        "aes.encrypt.gcm"
    );
    assert_eq!(
        reg.resolve_cli(Verb::Sign, &aes, "cmac").unwrap().id,
        "aes.sign.cmac"
    );
}

#[test]
fn test_verb_selects_between_same_cli_names() {
    let reg = reg();
    let rsa_priv = key(KeyAlgorithm::Rsa, KeyClass::Private, None);
    assert_eq!(
        reg.resolve_cli(Verb::Sign, &rsa_priv, "pkcs1").unwrap().id,
        "rsa.sign.pkcs1"
    );
    assert_eq!(
        reg.resolve_cli(Verb::Decrypt, &rsa_priv, "pkcs1")
            .unwrap()
            .id,
        "rsa.decrypt.pkcs1"
    );
}

#[test]
fn test_certificate_resolves_as_public_key_algorithm() {
    let reg = reg();
    let cert = key(KeyAlgorithm::Rsa, KeyClass::Certificate, None); // cert of an RSA key (§4.3)
    assert_eq!(
        reg.resolve_cli(Verb::Verify, &cert, "pss").unwrap().id,
        "rsa.verify.pss"
    );
    assert_eq!(
        reg.resolve_cli(Verb::Encrypt, &cert, "oaep").unwrap().id,
        "rsa.encrypt.oaep"
    );
}

#[test]
fn test_typo_gets_difflib_suggestion() {
    let reg = reg();
    let aes = key(KeyAlgorithm::Aes, KeyClass::Secret, None);
    let err = reg.resolve_cli(Verb::Encrypt, &aes, "gcmm").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnknownOperation);
    assert_eq!(err.message, "no encrypt operation 'gcmm' for aes keys");
    let hint = err.hint.expect("hint");
    assert!(hint.contains("gcm"), "{hint}");
    assert_eq!(hint, "did you mean: gcm");
    // no close match → every valid choice, sorted
    let err = reg.resolve_cli(Verb::Encrypt, &aes, "zzz").unwrap_err();
    assert_eq!(
        err.hint.as_deref(),
        Some("valid choices: cbc, ctr, ecb, gcm")
    );
}

#[test]
fn test_curve_filter() {
    let reg = reg();
    let x25519 = key(
        KeyAlgorithm::EcMontgomery,
        KeyClass::Private,
        Some(Curve::X25519),
    );
    assert_eq!(
        reg.resolve_cli(Verb::Derive, &x25519, "x25519").unwrap().id,
        "ec.derive.x25519"
    );
    let err = reg.resolve_cli(Verb::Derive, &x25519, "x448").unwrap_err(); // wrong curve
    assert_eq!(err.kind, ErrorKind::UnknownOperation);
    assert_eq!(
        err.message,
        "no derive operation 'x448' for ec-montgomery keys (curve x25519)"
    );
    assert_eq!(err.hint.as_deref(), Some("valid choices: x25519"));
}

#[test]
fn test_wrong_algorithm() {
    let reg = reg();
    let aes = key(KeyAlgorithm::Aes, KeyClass::Secret, None);
    let err = reg.resolve_cli(Verb::Encrypt, &aes, "oaep").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnknownOperation);
    // no candidates for derive on AES → the empty-registry hint
    let err = reg.resolve_cli(Verb::Derive, &aes, "ecdh").unwrap_err();
    assert_eq!(
        err.hint.as_deref(),
        Some("no operations are registered for this verb and key type")
    );
}

// -- TestAvailableFor ------------------------------------------------------------------

#[test]
fn test_filters_by_verb_algorithm_and_class() {
    let reg = reg();
    let provider = FakeProvider::new("fake");
    let aes = key(KeyAlgorithm::Aes, KeyClass::Secret, None);
    assert_eq!(
        id_set(&reg.available_for(Verb::Encrypt, &aes, &provider)),
        names(&[
            "aes.encrypt.ecb",
            "aes.encrypt.cbc",
            "aes.encrypt.gcm",
            "aes.encrypt.ctr"
        ])
    );
    assert_eq!(
        id_set(&reg.available_for(Verb::Sign, &aes, &provider)),
        names(&["aes.sign.cmac", "aes.sign.gmac"])
    );
}

#[test]
fn test_filters_by_provider_mechanisms() {
    let reg = reg();
    let provider = FakeProvider::new("fake").with_mechanisms(["AES-GCM", "AES-CMAC"]);
    let aes = key(KeyAlgorithm::Aes, KeyClass::Secret, None);
    assert_eq!(
        ids(&reg.available_for(Verb::Encrypt, &aes, &provider)),
        ["aes.encrypt.gcm"]
    );
    assert_eq!(
        ids(&reg.available_for(Verb::Sign, &aes, &provider)),
        ["aes.sign.cmac"]
    );
}

#[test]
fn test_certificate_as_public_rules() {
    // §5.11: certs work wherever PUBLIC does (encrypt/verify), never decrypt/sign/derive.
    let reg = reg();
    let provider = FakeProvider::new("fake");
    let cert = key(KeyAlgorithm::Rsa, KeyClass::Certificate, None);
    assert_eq!(
        id_set(&reg.available_for(Verb::Encrypt, &cert, &provider)),
        names(&["rsa.encrypt.oaep", "rsa.encrypt.pkcs1", "rsa.encrypt.raw"])
    );
    assert_eq!(
        id_set(&reg.available_for(Verb::Verify, &cert, &provider)),
        names(&["rsa.verify.pkcs1", "rsa.verify.pss", "rsa.verify.raw"])
    );
    assert!(
        reg.available_for(Verb::Decrypt, &cert, &provider)
            .is_empty()
    );
    assert!(reg.available_for(Verb::Sign, &cert, &provider).is_empty());
    assert!(reg.available_for(Verb::Derive, &cert, &provider).is_empty());
}

#[test]
fn test_public_key_decrypts_raw_only() {
    // §5.8: RAW decrypt with a PUBLIC key is signature recovery; the padded modes stay
    // PRIVATE-only.
    let reg = reg();
    let provider = FakeProvider::new("fake");
    let public = key(KeyAlgorithm::Rsa, KeyClass::Public, None);
    assert_eq!(
        ids(&reg.available_for(Verb::Decrypt, &public, &provider)),
        ["rsa.decrypt.raw"]
    );
    assert_eq!(
        id_set(&reg.available_for(Verb::Encrypt, &public, &provider)),
        names(&["rsa.encrypt.oaep", "rsa.encrypt.pkcs1", "rsa.encrypt.raw"])
    );
}

#[test]
fn test_curves_filter_montgomery_derive() {
    let reg = reg();
    let provider = FakeProvider::new("fake");
    let x25519 = key(
        KeyAlgorithm::EcMontgomery,
        KeyClass::Private,
        Some(Curve::X25519),
    );
    assert_eq!(
        ids(&reg.available_for(Verb::Derive, &x25519, &provider)),
        ["ec.derive.x25519"]
    );
    let p256 = key(KeyAlgorithm::Ec, KeyClass::Private, Some(Curve::P256));
    assert_eq!(
        ids(&reg.available_for(Verb::Derive, &p256, &provider)),
        ["ec.derive.ecdh"]
    );
}

#[test]
fn test_logged_out_pkcs11_provider_offers_nothing() {
    let reg = reg();
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    r2_provider::Provider::logout(&provider).unwrap();
    let aes = key(KeyAlgorithm::Aes, KeyClass::Secret, None);
    assert!(reg.available_for(Verb::Encrypt, &aes, &provider).is_empty());
}

fn sign_spec(id: &str, cli_name: &str, label: &str) -> OperationSpec {
    OperationSpec {
        id: id.to_owned(),
        verb: Verb::Sign,
        algorithm: KeyAlgorithm::Aes,
        key_classes: classes(&[KeyClass::Secret]),
        mechanism: "AES-CMAC".to_owned(),
        cli_name: cli_name.to_owned(),
        label: label.to_owned(),
        params: Vec::new(),
        provider_types: None,
        providers: None,
        curves: None,
        raw_ckm: None,
        param_struct: ParamStruct::None,
    }
}

#[test]
fn test_provider_types_and_providers_filters() {
    let mut reg = reg();
    let pkcs11_only = OperationSpec {
        provider_types: Some(names(&["pkcs11"])),
        ..sign_spec("zz.sign.vendor", "vendor", "vendor op")
    };
    let named_only = OperationSpec {
        providers: Some(names(&["prodhsm"])),
        ..sign_spec("zz.sign.named", "named", "named-instance op")
    };
    reg.register(pkcs11_only).unwrap();
    reg.register(named_only).unwrap();
    let aes = key(KeyAlgorithm::Aes, KeyClass::Secret, None);
    let memory = FakeProvider::new("mem");
    let prodhsm = FakeProvider::new("prodhsm").with_type_name("pkcs11");
    let otherhsm = FakeProvider::new("otherhsm").with_type_name("pkcs11");
    let mem_ids = id_set(&reg.available_for(Verb::Sign, &aes, &memory));
    assert!(!mem_ids.contains("zz.sign.vendor")); // provider_types filter
    assert!(!mem_ids.contains("zz.sign.named")); // providers filter
    let prod_ids = id_set(&reg.available_for(Verb::Sign, &aes, &prodhsm));
    assert!(prod_ids.is_superset(&names(&["zz.sign.vendor", "zz.sign.named"])));
    let other_ids = id_set(&reg.available_for(Verb::Sign, &aes, &otherhsm));
    assert!(other_ids.contains("zz.sign.vendor"));
    assert!(!other_ids.contains("zz.sign.named"));
}

// -- TestLoadCustom --------------------------------------------------------------------

struct Entry {
    id: &'static str,
    verb: Verb,
    algorithm: KeyAlgorithm,
    cli_name: String,
    param_struct: ParamStruct,
    params: Vec<ParamSpecConfig>,
    provider_types: Option<Vec<String>>,
    providers: Option<Vec<String>>,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            id: "vendor.acme.kcv",
            verb: Verb::Sign,
            algorithm: KeyAlgorithm::Aes,
            cli_name: "acme-kcv".to_owned(),
            param_struct: ParamStruct::None,
            params: Vec::new(),
            provider_types: None,
            providers: None,
        }
    }
}

/// Builds a §4.8 CustomMechanismConfig (c2 `_custom_entry`).
fn custom_entry(entry: Entry) -> CustomMechanismConfig {
    CustomMechanismConfig {
        id: entry.id.to_owned(),
        verb: entry.verb,
        algorithm: entry.algorithm,
        cli_name: entry.cli_name,
        label: "ACME key check value".to_owned(),
        ckm: 0x8000_0A01,
        param_struct: entry.param_struct,
        params: entry.params,
        provider_types: entry.provider_types,
        providers: entry.providers,
    }
}

fn rounds(required: bool, default: Option<i64>) -> ParamSpecConfig {
    ParamSpecConfig {
        name: "rounds".to_owned(),
        kind: ParamKind::Int,
        prompt: "KCV rounds".to_owned(),
        required,
        default: default.map(ParamValue::Int),
        default_raw: default.map(|value| Value::Number(value.into())),
        choices: None,
    }
}

#[test]
fn test_spec_derivation_basics() {
    let mut reg = reg();
    let entry = custom_entry(Entry {
        params: vec![rounds(false, Some(1))],
        providers: Some(vec!["prodhsm".to_owned()]),
        ..Entry::default()
    });
    reg.load_custom(&[entry]).unwrap();
    let spec = reg.get("vendor.acme.kcv").unwrap();
    assert_eq!(spec.verb, Verb::Sign);
    assert_eq!(spec.algorithm, KeyAlgorithm::Aes);
    assert_eq!(spec.cli_name, "acme-kcv");
    assert_eq!(spec.label, "ACME key check value");
    assert_eq!(spec.mechanism, "vendor.acme.kcv"); // mechanism = entry.id (§4.6)
    assert_eq!(spec.raw_ckm, Some(0x8000_0A01));
    assert_eq!(spec.param_struct, ParamStruct::None);
    assert_eq!(spec.key_classes, classes(&[KeyClass::Secret])); // AES → SECRET, every verb
    assert_eq!(spec.provider_types, Some(names(&["pkcs11"]))); // None → pkcs11 default
    assert_eq!(spec.providers, Some(names(&["prodhsm"])));
    assert_eq!(spec.curves, None);
    assert_eq!(spec.params.len(), 1);
    let rounds = &spec.params[0];
    assert_eq!(
        (rounds.name.as_str(), rounds.kind, rounds.prompt.as_str()),
        ("rounds", ParamKind::Int, "KCV rounds")
    );
    assert!(!rounds.required);
    assert_eq!(rounds.default, Some(ParamValue::Int(1)));
}

#[test]
fn test_key_class_derivation_rules() {
    let mut reg = reg();
    let cases = [
        (
            Verb::Encrypt,
            KeyAlgorithm::Aes,
            classes(&[KeyClass::Secret]),
        ),
        (
            Verb::Derive,
            KeyAlgorithm::Aes,
            classes(&[KeyClass::Secret]),
        ),
        (
            Verb::Encrypt,
            KeyAlgorithm::Rsa,
            classes(&[KeyClass::Public, KeyClass::Certificate]),
        ),
        (
            Verb::Verify,
            KeyAlgorithm::Ec,
            classes(&[KeyClass::Public, KeyClass::Certificate]),
        ),
        (
            Verb::Decrypt,
            KeyAlgorithm::Rsa,
            classes(&[KeyClass::Private]),
        ),
        (
            Verb::Sign,
            KeyAlgorithm::EcEdwards,
            classes(&[KeyClass::Private]),
        ),
        (
            Verb::Derive,
            KeyAlgorithm::EcMontgomery,
            classes(&[KeyClass::Private]),
        ),
    ];
    let ids: Vec<String> = (0..cases.len())
        .map(|i| format!("vendor.case{i}"))
        .collect();
    let entries: Vec<CustomMechanismConfig> = cases
        .iter()
        .enumerate()
        .map(|(i, (verb, algorithm, _))| {
            let mut entry = custom_entry(Entry {
                verb: *verb,
                algorithm: *algorithm,
                cli_name: format!("case{i}"),
                ..Entry::default()
            });
            entry.id.clone_from(&ids[i]);
            entry
        })
        .collect();
    reg.load_custom(&entries).unwrap();
    for (i, (_, _, expected)) in cases.iter().enumerate() {
        assert_eq!(&reg.get(&ids[i]).unwrap().key_classes, expected, "case{i}");
    }
}

#[test]
fn test_raw_param_struct_appends_mechparam() {
    let mut reg = reg();
    let entry = custom_entry(Entry {
        param_struct: ParamStruct::Raw,
        params: vec![rounds(true, None)],
        ..Entry::default()
    });
    reg.load_custom(&[entry]).unwrap();
    let spec = reg.get("vendor.acme.kcv").unwrap();
    assert_eq!(spec.param_struct, ParamStruct::Raw);
    let param_names: Vec<&str> = spec.params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(param_names, ["rounds", "mechparam"]);
    let mechparam = spec.params.last().unwrap();
    assert_eq!(mechparam.kind, ParamKind::Bytes);
    assert!(mechparam.required);
    assert_eq!(mechparam.prompt, "Raw mechanism parameter bytes");
}

#[test]
fn test_explicit_provider_types_pass_through() {
    let mut reg = reg();
    let entry = custom_entry(Entry {
        provider_types: Some(vec!["pkcs11".to_owned(), "memory".to_owned()]),
        ..Entry::default()
    });
    reg.load_custom(&[entry]).unwrap();
    assert_eq!(
        reg.get("vendor.acme.kcv").unwrap().provider_types,
        Some(names(&["pkcs11", "memory"]))
    );
}

#[test]
fn test_duplicate_custom_id_raises_config_error() {
    let mut reg = reg();
    reg.load_custom(&[custom_entry(Entry::default())]).unwrap();
    let err = reg
        .load_custom(&[custom_entry(Entry::default())])
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Config);
    assert_eq!(
        err.message,
        "operation 'vendor.acme.kcv' is already registered"
    );
}

#[test]
fn test_custom_op_available_only_where_advertised() {
    let mut reg = reg();
    reg.load_custom(&[custom_entry(Entry::default())]).unwrap();
    let aes = key(KeyAlgorithm::Aes, KeyClass::Secret, None);
    let with_vendor = || {
        CANONICAL_MECHANISMS
            .iter()
            .copied()
            .chain(["vendor.acme.kcv"])
            .collect::<Vec<_>>()
    };
    let plain_hsm = FakeProvider::new("plainhsm").with_type_name("pkcs11");
    let vendor_hsm = FakeProvider::new("vendorhsm")
        .with_type_name("pkcs11")
        .with_mechanisms(with_vendor());
    let memory = FakeProvider::new("mem").with_mechanisms(with_vendor());
    // token doesn't list the CKM → mechanisms() lacks the id
    assert!(!id_set(&reg.available_for(Verb::Sign, &aes, &plain_hsm)).contains("vendor.acme.kcv"));
    assert!(id_set(&reg.available_for(Verb::Sign, &aes, &vendor_hsm)).contains("vendor.acme.kcv"));
    // provider_types defaults to {"pkcs11"}
    assert!(!id_set(&reg.available_for(Verb::Sign, &aes, &memory)).contains("vendor.acme.kcv"));
}
