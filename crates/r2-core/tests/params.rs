//! Core parameter types (spec §4.6.1) — port of c2 `tests/unit/core/test_params.py`, plus
//! the builtin param readers (`param_int` / `param_str` / `param_choice` = c2 `_param_int`,
//! pkcs11 `_param_str`, memory `_param_choice`) with c2's texts.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::BTreeMap;

use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyRef};
use r2_core::params::{
    ParamKind, ParamSpec, ParamStruct, ParamValidator, ParamValue, Params, Verb, param_choice,
    param_int, param_str,
};

#[test]
fn test_verb_values() {
    let values: Vec<&str> = Verb::ALL.iter().map(|v| v.as_str()).collect();
    assert_eq!(values, ["encrypt", "decrypt", "sign", "verify", "derive"]);
    for verb in Verb::ALL {
        assert_eq!(verb.to_string(), verb.as_str());
        assert_eq!(verb.as_str().parse::<Verb>().unwrap(), verb);
    }
    let err = "Encrypt".parse::<Verb>().unwrap_err();
    assert_eq!(
        (err.kind, err.message.as_str()),
        (ErrorKind::Generic, "unknown verb 'Encrypt'")
    );
}

#[test]
fn test_param_kind_values() {
    let kinds = [
        ParamKind::Bytes,
        ParamKind::Int,
        ParamKind::Str,
        ParamKind::Bool,
        ParamKind::Enum,
        ParamKind::KeyRef,
    ];
    let values: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
    assert_eq!(values, ["bytes", "int", "str", "bool", "enum", "keyref"]);
    for kind in kinds {
        assert_eq!(kind.to_string(), kind.as_str());
        assert_eq!(kind.as_str().parse::<ParamKind>().unwrap(), kind);
    }
    assert_eq!(
        "integer".parse::<ParamKind>().unwrap_err().message,
        "unknown parameter kind 'integer'"
    );
}

#[test]
fn param_struct_values() {
    let structs = [
        ParamStruct::None,
        ParamStruct::Iv,
        ParamStruct::Gcm,
        ParamStruct::Oaep,
        ParamStruct::Raw,
    ];
    let values: Vec<&str> = structs.iter().map(|s| s.as_str()).collect();
    assert_eq!(values, ["none", "iv", "gcm", "oaep", "raw"]);
    for value in structs {
        assert_eq!(value.to_string(), value.as_str());
        assert_eq!(value.as_str().parse::<ParamStruct>().unwrap(), value);
    }
    assert_eq!(ParamStruct::default(), ParamStruct::None);
    assert_eq!(
        "pss".parse::<ParamStruct>().unwrap_err().message,
        "unknown param_struct 'pss'"
    );
}

#[test]
fn test_param_spec_defaults() {
    let spec = ParamSpec::new("iv", ParamKind::Bytes, "IV");
    assert!(spec.required);
    assert_eq!(spec.default, None);
    assert_eq!(spec.default_from, None);
    assert_eq!(spec.choices, None);
    assert_eq!(spec.length, None);
    assert_eq!(spec.validate, None);
    assert_eq!(
        (spec.name.as_str(), spec.kind, spec.prompt.as_str()),
        ("iv", ParamKind::Bytes, "IV")
    );
    // The blessed synthetic STR spec.
    let label = ParamSpec::str("label", "Key label");
    assert_eq!(label, ParamSpec::new("label", ParamKind::Str, "Key label"));
}

fn reject_sha1(value: &ParamValue) -> Result<()> {
    if value.as_str() == Some("sha1") {
        return Err(ConsoleError::param("sha1 is not allowed here", "hash"));
    }
    Ok(())
}

fn accept_all(_: &ParamValue) -> Result<()> {
    Ok(())
}

#[test]
fn test_param_spec_full_construction() {
    let spec = ParamSpec::new("hash", ParamKind::Enum, "Hash algorithm")
        .optional(Some(ParamValue::Enum("sha256".to_owned())))
        .choices(&["sha1", "sha256", "sha384", "sha512"])
        .validate(reject_sha1);
    assert!(!spec.required);
    assert_eq!(spec.default, Some(ParamValue::Enum("sha256".to_owned())));
    assert_eq!(spec.default_from, None);
    let choices = spec.choices.as_ref().unwrap();
    assert!(choices.iter().any(|c| c == "sha256"));
    let validate = spec.validate.unwrap();
    let err = (validate.0)(&ParamValue::Enum("sha1".to_owned())).unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(err.param_name(), Some("hash"));
    assert!((validate.0)(&ParamValue::Enum("sha256".to_owned())).is_ok());
    // length builder (exact BYTES length)
    assert_eq!(
        ParamSpec::new("iv", ParamKind::Bytes, "IV")
            .length(16)
            .length,
        Some(16)
    );
}

#[test]
fn test_param_spec_default_from_mirror() {
    let spec = ParamSpec::new("mgf_hash", ParamKind::Enum, "MGF1 hash")
        .choices(&["sha1", "sha256"])
        .default_from("hash");
    assert_eq!(spec.default_from.as_deref(), Some("hash"));
    assert!(spec.required); // default_from does not change `required`
}

/// ParamValidator compares by function address; Debug never prints the address.
#[test]
fn param_validator_identity_and_debug() {
    assert_eq!(ParamValidator(reject_sha1), ParamValidator(reject_sha1));
    assert_ne!(ParamValidator(reject_sha1), ParamValidator(accept_all));
    assert_eq!(
        format!("{:?}", ParamValidator(accept_all)),
        "ParamValidator(..)"
    );
    let a = ParamSpec::str("x", "X").validate(reject_sha1);
    assert_eq!(a.clone(), a);
    assert_ne!(a, ParamSpec::str("x", "X").validate(accept_all));
}

fn key_info() -> KeyInfo {
    KeyInfo {
        key_ref: KeyRef::new("mem", "k", Some(vec![1, 2])),
        key_class: KeyClass::Secret,
        algorithm: KeyAlgorithm::Aes,
        size_bits: Some(128),
        curve: None,
        exportable: true,
        attributes: BTreeMap::new(),
        handle: None,
    }
}

#[test]
fn param_value_accessors() {
    let key = ParamValue::KeyRef(Box::new(key_info()));
    let values = [
        ParamValue::Bytes(vec![1]),
        ParamValue::Int(-1),
        ParamValue::Str("s".to_owned()),
        ParamValue::Bool(true),
        ParamValue::Enum("96".to_owned()),
        key,
    ];
    assert_eq!(values[0].as_bytes(), Some(&[1u8][..]));
    assert_eq!(values[1].as_int(), Some(-1));
    assert_eq!(values[2].as_str(), Some("s"));
    assert_eq!(values[4].as_str(), Some("96")); // Str or Enum
    assert_eq!(values[4].as_int(), None); // never as_int() on an ENUM (§4.5.4)
    assert_eq!(values[3].as_bool(), Some(true));
    assert_eq!(values[5].as_key().unwrap().key_ref.display(), "mem:k#0102");
    for (index, value) in values.iter().enumerate() {
        assert_eq!(value.as_bytes().is_some(), index == 0);
        assert_eq!(value.as_int().is_some(), index == 1);
        assert_eq!(value.as_str().is_some(), index == 2 || index == 4);
        assert_eq!(value.as_bool().is_some(), index == 3);
        assert_eq!(value.as_key().is_some(), index == 5);
    }
}

fn params(entries: &[(&str, ParamValue)]) -> Params {
    entries
        .iter()
        .map(|(name, value)| ((*name).to_owned(), value.clone()))
        .collect()
}

#[test]
fn param_int_reads_like_c2() {
    let p = params(&[
        ("int", ParamValue::Int(96)),
        ("enum", ParamValue::Enum("96".to_owned())),
        ("str", ParamValue::Str(" 1_000 ".to_owned())),
        ("neg", ParamValue::Str("-1".to_owned())),
        ("bad", ParamValue::Str("12a".to_owned())),
        ("huge", ParamValue::Enum("9223372036854775808".to_owned())),
        ("bool", ParamValue::Bool(true)),
        ("bytes", ParamValue::Bytes(vec![1])),
        ("key", ParamValue::KeyRef(Box::new(key_info()))),
    ]);
    assert_eq!(param_int(&p, "absent", 128).unwrap(), 128);
    assert_eq!(param_int(&p, "int", 128).unwrap(), 96);
    assert_eq!(param_int(&p, "enum", 128).unwrap(), 96); // tag_bits arrives as Enum("96")
    assert_eq!(param_int(&p, "str", 0).unwrap(), 1000);
    assert_eq!(param_int(&p, "neg", 0).unwrap(), -1);
    let err = param_int(&p, "bad", 0).unwrap_err();
    assert_eq!(err.message, "parameter 'bad' must be an integer, got '12a'");
    assert_eq!(err.param_name(), Some("bad"));
    assert_eq!(err.hint, None);
    // outside i64 counts as unparsable (§11 D18)
    assert_eq!(
        param_int(&p, "huge", 0).unwrap_err().message,
        "parameter 'huge' must be an integer, got '9223372036854775808'"
    );
    for name in ["bool", "bytes", "key"] {
        let err = param_int(&p, name, 0).unwrap_err();
        assert_eq!(
            err.message,
            format!("parameter '{name}' must be an integer")
        );
        assert_eq!(err.param_name(), Some(name));
    }
}

#[test]
fn param_str_reads_like_c2() {
    let p = params(&[
        ("hash", ParamValue::Enum("sha384".to_owned())),
        ("label", ParamValue::Str("x".to_owned())),
        ("n", ParamValue::Int(1)),
    ]);
    assert_eq!(param_str(&p, "absent", "sha256").unwrap(), "sha256");
    assert_eq!(param_str(&p, "hash", "sha256").unwrap(), "sha384");
    assert_eq!(param_str(&p, "label", "").unwrap(), "x");
    let err = param_str(&p, "n", "").unwrap_err();
    assert_eq!(err.message, "parameter 'n' must be a string");
    assert_eq!(err.param_name(), Some("n"));
}

#[test]
fn param_choice_reads_like_c2() {
    const HASHES: [&str; 5] = ["sha1", "sha224", "sha256", "sha384", "sha512"];
    const TAGS: [&str; 5] = ["128", "120", "112", "104", "96"];
    let p = params(&[
        ("hash", ParamValue::Enum("sha512".to_owned())),
        ("tag_bits", ParamValue::Int(96)),
        ("bad", ParamValue::Str("md5".to_owned())),
        ("flag", ParamValue::Bool(false)),
        ("raw", ParamValue::Bytes(b"x'".to_vec())),
    ]);
    assert_eq!(
        param_choice(&p, "absent", &HASHES, "sha256").unwrap(),
        "sha256"
    );
    assert_eq!(
        param_choice(&p, "hash", &HASHES, "sha256").unwrap(),
        "sha512"
    );
    assert_eq!(param_choice(&p, "tag_bits", &TAGS, "128").unwrap(), "96");
    let err = param_choice(&p, "bad", &HASHES, "sha256").unwrap_err();
    assert_eq!(
        err.message,
        "parameter 'bad' must be one of sha1, sha224, sha256, sha384, sha512; got 'md5'"
    );
    assert_eq!(err.param_name(), Some("bad"));
    assert_eq!(
        param_choice(&p, "flag", &["a"], "a").unwrap_err().message,
        "parameter 'flag' must be one of a; got 'False'"
    );
    assert_eq!(
        param_choice(&p, "raw", &["a"], "a").unwrap_err().message,
        r#"parameter 'raw' must be one of a; got 'b"x\'"'"#
    );
}
