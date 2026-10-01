// build_operation_registry (moved from c2 app.py, spec §4.1.1) — the registry cases of c2
// tests/unit/console/test_app.py (R3). c2 built the config through make_config(...); r2
// constructs the custom_mechanisms entry directly (R2's decoder is merge-order-only).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]
use std::collections::{BTreeMap, BTreeSet};

use r2_config::model::{CustomMechanismConfig, ParamSpecConfig};
use r2_config::yaml::Value;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyRef};
use r2_ops::{ParamKind, ParamStruct, ParamValue, Verb, build_operation_registry};

/// c2 CUSTOM_MECH: id vendor.acme.kcv, sign/aes, cli acme-kcv, ckm 0x80000A01, raw, one
/// optional INT param "rounds" (default 1).
fn custom_mech() -> CustomMechanismConfig {
    CustomMechanismConfig {
        id: "vendor.acme.kcv".to_owned(),
        verb: Verb::Sign,
        algorithm: KeyAlgorithm::Aes,
        cli_name: "acme-kcv".to_owned(),
        label: "ACME key check value".to_owned(),
        ckm: 0x8000_0A01,
        param_struct: ParamStruct::Raw,
        params: vec![ParamSpecConfig {
            name: "rounds".to_owned(),
            kind: ParamKind::Int,
            prompt: "KCV rounds".to_owned(),
            required: false,
            default: Some(ParamValue::Int(1)),
            default_raw: Some(Value::Number(1.into())),
            choices: None,
        }],
        provider_types: None,
        providers: None,
    }
}

#[test]
fn test_build_operation_registry_registers_builtins_and_customs() {
    let registry = build_operation_registry(&[custom_mech()]).unwrap();
    let spec = registry.get("vendor.acme.kcv").unwrap();
    assert_eq!(spec.mechanism, "vendor.acme.kcv");
    assert_eq!(spec.raw_ckm, Some(0x8000_0A01));
    assert_eq!(spec.param_struct, ParamStruct::Raw);
    assert_eq!(
        spec.provider_types,
        Some(BTreeSet::from(["pkcs11".to_owned()]))
    );
    let names: Vec<&str> = spec.params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["rounds", "mechparam"]); // raw appends mechparam
    assert_eq!(registry.get("aes.encrypt.gcm").unwrap().cli_name, "gcm");
    // no customs → exactly the built-ins; a duplicate custom id fails the bootstrap
    let builtins = build_operation_registry(&[]).unwrap();
    assert!(builtins.get("vendor.acme.kcv").is_err());
    let err = build_operation_registry(&[custom_mech(), custom_mech()]).unwrap_err();
    assert_eq!(
        err.message,
        "operation 'vendor.acme.kcv' is already registered"
    );
}

#[test]
fn test_custom_op_resolves_via_cli_name() {
    let registry = build_operation_registry(&[custom_mech()]).unwrap();
    let key = KeyInfo {
        key_ref: KeyRef::new("hsm", "k", None),
        key_class: KeyClass::Secret,
        algorithm: KeyAlgorithm::Aes,
        size_bits: Some(256),
        curve: None,
        exportable: false,
        attributes: BTreeMap::new(),
        handle: None,
    };
    assert_eq!(
        registry
            .resolve_cli(Verb::Sign, &key, "acme-kcv")
            .unwrap()
            .id,
        "vendor.acme.kcv"
    );
}

#[test]
fn custom_reusing_a_builtin_cli_name_is_shadowed_by_the_builtin() {
    // §4.6.2: resolve_cli returns the FIRST spec in registration order (c2 parity).
    let shadow = CustomMechanismConfig {
        id: "vendor.acme.cmac".to_owned(),
        cli_name: "cmac".to_owned(),
        params: Vec::new(),
        param_struct: ParamStruct::None,
        ..custom_mech()
    };
    let registry = build_operation_registry(&[shadow]).unwrap();
    let key = KeyInfo {
        key_ref: KeyRef::new("hsm", "k", None),
        key_class: KeyClass::Secret,
        algorithm: KeyAlgorithm::Aes,
        size_bits: None,
        curve: None,
        exportable: true,
        attributes: BTreeMap::new(),
        handle: None,
    };
    assert_eq!(
        registry.resolve_cli(Verb::Sign, &key, "cmac").unwrap().id,
        "aes.sign.cmac"
    );
    assert!(registry.get("vendor.acme.cmac").is_ok());
}
