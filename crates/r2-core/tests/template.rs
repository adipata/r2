//! Template model tests (spec §4.7) — port of c2 `tests/unit/core/test_templates.py`
//! (enabled/disabled/locked + `set()` semantics) plus the AttrValue text helpers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use r2_core::error::ErrorKind;
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};

fn make_template() -> KeyTemplate {
    KeyTemplate::new(vec![
        TemplateAttr::new("CKA_CLASS", AttrKind::Ulong, AttrValue::Ulong(4)).locked(),
        TemplateAttr::new("CKA_KEY_TYPE", AttrKind::Ulong, AttrValue::Ulong(31)).locked(),
        TemplateAttr::new("CKA_TOKEN", AttrKind::Bool, AttrValue::Bool(true)),
        TemplateAttr::new("CKA_ENCRYPT", AttrKind::Bool, AttrValue::Bool(true)),
        TemplateAttr::new("CKA_EXTRACTABLE", AttrKind::Bool, AttrValue::Bool(false)).disabled(),
        TemplateAttr::new(
            "CKA_ID",
            AttrKind::Bytes,
            AttrValue::Bytes(vec![0x01, 0x02]),
        ),
    ])
}

fn names(attrs: &[&TemplateAttr]) -> Vec<String> {
    attrs.iter().map(|attr| attr.name.clone()).collect()
}

#[test]
fn test_attr_kind_values() {
    let kinds = [
        AttrKind::Bool,
        AttrKind::Str,
        AttrKind::Bytes,
        AttrKind::Ulong,
    ];
    let values: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
    assert_eq!(values, ["bool", "str", "bytes", "ulong"]);
    for kind in kinds {
        assert_eq!(kind.to_string(), kind.as_str());
        assert_eq!(kind.as_str().parse::<AttrKind>().unwrap(), kind);
    }
    let err = "int".parse::<AttrKind>().unwrap_err();
    assert_eq!(
        (err.kind, err.message.as_str()),
        (ErrorKind::Generic, "unknown attribute kind 'int'")
    );
}

#[test]
fn test_template_attr_defaults() {
    let attr = TemplateAttr::new("CKA_SIGN", AttrKind::Bool, AttrValue::Bool(true));
    assert!(attr.enabled);
    assert!(!attr.locked);
    let both = attr.clone().disabled().locked();
    assert!(!both.enabled && both.locked);
    assert_eq!(
        (both.name, both.kind, both.value),
        (attr.name, attr.kind, attr.value)
    );
}

#[test]
fn test_get_returns_attr_or_none() {
    let template = make_template();
    let attr = template.get("CKA_TOKEN").unwrap();
    assert_eq!(attr.value, AttrValue::Bool(true));
    assert!(template.get("CKA_NOPE").is_none());
}

#[test]
fn test_set_updates_value_in_place() {
    let mut template = make_template();
    template.set("CKA_ENCRYPT", AttrValue::Bool(false)).unwrap();
    assert_eq!(
        template.get("CKA_ENCRYPT").unwrap().value,
        AttrValue::Bool(false)
    );
    // the kind is unchanged by set()
    assert_eq!(template.get("CKA_ENCRYPT").unwrap().kind, AttrKind::Bool);
}

#[test]
fn test_set_unknown_name_raises_param_error() {
    let mut template = make_template();
    let err = template
        .set("CKA_BOGUS", AttrValue::Bool(true))
        .unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(err.param_name(), Some("CKA_BOGUS"));
    let hint = err.hint.as_deref().unwrap();
    assert!(hint.contains("CKA_TOKEN")); // lists the known names
    assert_eq!(err.message, "unknown template attribute 'CKA_BOGUS'");
    assert_eq!(
        hint,
        "known attributes: CKA_CLASS, CKA_KEY_TYPE, CKA_TOKEN, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_ID"
    );
    let err = KeyTemplate::default()
        .set("CKA_X", AttrValue::Ulong(1))
        .unwrap_err();
    assert_eq!(
        err.hint.as_deref(),
        Some("known attributes: (no attributes)")
    );
}

#[test]
fn test_set_does_not_flip_enabled_or_locked() {
    let mut template = make_template();
    template
        .set("CKA_EXTRACTABLE", AttrValue::Bool(true))
        .unwrap();
    let attr = template.get("CKA_EXTRACTABLE").unwrap();
    assert_eq!(attr.value, AttrValue::Bool(true));
    assert!(!attr.enabled); // still disabled: set() only changes the value
    template.set("CKA_CLASS", AttrValue::Ulong(3)).unwrap();
    assert!(template.get("CKA_CLASS").unwrap().locked);
}

#[test]
fn test_enabled_attrs_omits_disabled_preserving_order() {
    let template = make_template();
    let enabled = names(&template.enabled_attrs());
    assert_eq!(
        enabled,
        [
            "CKA_CLASS",
            "CKA_KEY_TYPE",
            "CKA_TOKEN",
            "CKA_ENCRYPT",
            "CKA_ID"
        ]
    );
    assert!(!enabled.contains(&"CKA_EXTRACTABLE".to_owned()));
}

#[test]
fn test_disable_then_reenable_roundtrip() {
    let mut template = make_template();
    template.get_mut("CKA_TOKEN").unwrap().enabled = false;
    assert!(!names(&template.enabled_attrs()).contains(&"CKA_TOKEN".to_owned()));
    template.get_mut("CKA_TOKEN").unwrap().enabled = true;
    assert!(names(&template.enabled_attrs()).contains(&"CKA_TOKEN".to_owned()));
    assert!(template.get_mut("CKA_NOPE").is_none());
}

#[test]
fn test_locked_flag_is_carried_not_enforced_by_model() {
    // §4.7: locked means the EDITOR must refuse toggling; the model just carries it.
    let template = make_template();
    let locked: Vec<&str> = template
        .attrs
        .iter()
        .filter(|a| a.locked)
        .map(|a| a.name.as_str())
        .collect();
    assert_eq!(locked, ["CKA_CLASS", "CKA_KEY_TYPE"]);
    assert!(
        template
            .attrs
            .iter()
            .filter(|a| a.locked)
            .all(|a| a.enabled)
    );
}

/// §4.7 AttrValue helpers: inferred kind, editor cell, `key info` cell, Python type name
/// and repr (the "got {T}" / "{value!r}" parts of c2's conversion texts).
#[test]
fn attr_value_text_helpers() {
    let cases = [
        (
            AttrValue::Bool(true),
            AttrKind::Bool,
            "true",
            "True",
            "bool",
            "True",
        ),
        (
            AttrValue::Bool(false),
            AttrKind::Bool,
            "false",
            "False",
            "bool",
            "False",
        ),
        (
            AttrValue::Ulong(4128),
            AttrKind::Ulong,
            "4128",
            "4128",
            "int",
            "4128",
        ),
        (
            AttrValue::Bytes(vec![0x0a, 0xff]),
            AttrKind::Bytes,
            "0x0aff",
            "0x0aff",
            "bytes",
            "b'\\n\\xff'",
        ),
        (
            AttrValue::Bytes(vec![]),
            AttrKind::Bytes,
            "0x",
            "0x",
            "bytes",
            "b''",
        ),
        (
            AttrValue::Str("it's".into()),
            AttrKind::Str,
            "it's",
            "it's",
            "str",
            "\"it's\"",
        ),
        (
            AttrValue::Symbol("CKM_AES_KEY_GEN".into()),
            AttrKind::Ulong,
            "CKM_AES_KEY_GEN",
            "CKM_AES_KEY_GEN",
            "str",
            "'CKM_AES_KEY_GEN'",
        ),
    ];
    for (value, kind, cell, info, type_name, repr) in cases {
        assert_eq!(value.inferred_kind(), kind, "{value:?}");
        assert_eq!(value.render_value(), cell, "{value:?}");
        assert_eq!(value.render_info(), info, "{value:?}");
        assert_eq!(value.py_type_name(), type_name, "{value:?}");
        assert_eq!(value.py_repr(), repr, "{value:?}");
    }
}
