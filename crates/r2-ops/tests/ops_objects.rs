// The generic.sign.hmac / generic.verify.hmac rows, their capability filtering and the
// custom-mechanism class derivation for generic secrets — the port of c2
// tests/unit/test_ops_objects.py (R3).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]
use std::collections::{BTreeMap, BTreeSet};

use r2_config::model::CustomMechanismConfig;
use r2_core::error::ErrorKind;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyRef};
use r2_ops::custom::spec_from_config;
use r2_ops::{OperationRegistry, ParamKind, ParamStruct, ParamValue, Verb, register_builtins};
use r2_testkit::FakeProvider;

fn reg() -> OperationRegistry {
    let mut registry = OperationRegistry::new();
    register_builtins(&mut registry).unwrap();
    registry
}

fn key(key_class: KeyClass, algorithm: KeyAlgorithm) -> KeyInfo {
    KeyInfo {
        key_ref: KeyRef::new("mem", "k", None),
        key_class,
        algorithm,
        size_bits: None,
        curve: None,
        exportable: true,
        attributes: BTreeMap::new(),
        handle: None,
    }
}

#[test]
fn test_hmac_spec_shape_and_mirror() {
    let reg = reg();
    let sign = reg.get("generic.sign.hmac").unwrap();
    assert_eq!(sign.verb, Verb::Sign);
    assert_eq!(sign.algorithm, KeyAlgorithm::Generic);
    assert_eq!(sign.key_classes, BTreeSet::from([KeyClass::Secret]));
    assert_eq!(sign.mechanism, "HMAC");
    assert_eq!(sign.cli_name, "hmac");
    let names: Vec<&str> = sign.params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["hash", "mac_len"]);
    let (hash, mac_len) = (&sign.params[0], &sign.params[1]);
    assert_eq!(hash.kind, ParamKind::Enum);
    assert_eq!(
        hash.choices,
        Some(
            ["sha1", "sha224", "sha256", "sha384", "sha512"]
                .map(str::to_owned)
                .to_vec()
        )
    );
    assert_eq!(hash.default, Some(ParamValue::Enum("sha256".to_owned())));
    assert!(!hash.required);
    assert_eq!(mac_len.kind, ParamKind::Int);
    assert!(!mac_len.required);
    assert_eq!(mac_len.default, None); // None = full digest
    let verify = reg.get("generic.verify.hmac").unwrap();
    assert_eq!(verify.verb, Verb::Verify);
    assert_eq!(
        (&verify.cli_name, &verify.mechanism, &verify.params),
        (&sign.cli_name, &sign.mechanism, &sign.params)
    );
}

#[test]
fn test_hmac_available_for_generic_secrets_only() {
    let reg = reg();
    let provider = FakeProvider::new("mem"); // advertises every canonical mechanism incl. HMAC
    let generic = key(KeyClass::Secret, KeyAlgorithm::Generic);
    let ids = |verb, key: &KeyInfo| -> Vec<String> {
        reg.available_for(verb, key, &provider)
            .iter()
            .map(|spec| spec.id.clone())
            .collect()
    };
    assert_eq!(ids(Verb::Sign, &generic), ["generic.sign.hmac"]);
    assert_eq!(ids(Verb::Verify, &generic), ["generic.verify.hmac"]);
    let aes_ids = ids(Verb::Sign, &key(KeyClass::Secret, KeyAlgorithm::Aes));
    assert!(!aes_ids.contains(&"generic.sign.hmac".to_owned()));
    assert!(aes_ids.contains(&"aes.sign.cmac".to_owned()));
    assert!(ids(Verb::Sign, &key(KeyClass::Data, KeyAlgorithm::None)).is_empty());
    assert_eq!(
        reg.resolve_cli(Verb::Sign, &generic, "hmac").unwrap().id,
        "generic.sign.hmac"
    );
    let err = reg
        .resolve_cli(Verb::Sign, &key(KeyClass::Data, KeyAlgorithm::None), "hmac")
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnknownOperation);
    assert_eq!(err.message, "no sign operation 'hmac' for none keys");
    let err = reg
        .resolve_cli(
            Verb::Sign,
            &key(KeyClass::Secret, KeyAlgorithm::Other),
            "hmac",
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnknownOperation);
}

#[test]
fn test_custom_mechanism_generic_derives_secret_class() {
    for verb in Verb::ALL {
        let entry = CustomMechanismConfig {
            id: format!("vendor.acme.{}", verb.as_str()),
            verb,
            algorithm: KeyAlgorithm::Generic,
            cli_name: "acme".to_owned(),
            label: "ACME".to_owned(),
            ckm: 0x8000_0A01,
            param_struct: ParamStruct::None,
            params: Vec::new(),
            provider_types: None,
            providers: None,
        };
        assert_eq!(
            spec_from_config(&entry).key_classes,
            BTreeSet::from([KeyClass::Secret])
        );
    }
}
