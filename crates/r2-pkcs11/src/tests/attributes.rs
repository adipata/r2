//! Ports of c2 tests/unit/pkcs11/test_attributes.py (CKA_CATALOG shape, template →
//! attribute conversion, vendor codec, template identity).
use indexmap::IndexMap;
use r2_config::model::CustomAttributeDef;
use r2_core::catalog::{CKA_CATALOG, cka};
use r2_core::error::ErrorKind;
use r2_core::template::{AttrKind, AttrValue, TemplateAttr};

use super::{boolean, bytes_attr, str_attr, symbol, tpl, ulong_attr};
use crate::attributes::{
    ULONG_SIZE, decode_vendor_value, encode_vendor_value, template_identity, template_to_attrs,
};

fn no_custom() -> IndexMap<String, CustomAttributeDef> {
    IndexMap::new()
}

// ---- TestCatalog ----

#[test]
fn catalog_frozen_shape() {
    let shape = |name: &str| cka(name).map(|e| (e.code, e.kind));
    assert_eq!(shape("CKA_TOKEN"), Some((0x0001, AttrKind::Bool)));
    assert_eq!(shape("CKA_CLASS"), Some((0x0000, AttrKind::Ulong)));
    assert_eq!(shape("CKA_LABEL"), Some((0x0003, AttrKind::Str)));
    assert_eq!(shape("CKA_VALUE"), Some((0x0011, AttrKind::Bytes)));
    assert_eq!(shape("CKA_EC_PARAMS"), Some((0x0180, AttrKind::Bytes)));
    assert_eq!(shape("CKA_EXTRACTABLE"), Some((0x0162, AttrKind::Bool)));
    assert_eq!(shape("CKA_VALUE_LEN"), Some((0x0161, AttrKind::Ulong)));
}

#[test]
fn catalog_every_entry_well_formed() {
    let mut names = std::collections::BTreeSet::new();
    for entry in CKA_CATALOG {
        assert!(entry.name.starts_with("CKA_"), "{}", entry.name);
        assert!(names.insert(entry.name), "duplicate {}", entry.name);
    }
    // the literal codes equal the PKCS#11 constants (cryptoki-sys cross-check)
    let sys_codes = [
        ("CKA_CLASS", cryptoki_sys::CKA_CLASS),
        ("CKA_CERTIFICATE_CATEGORY", cryptoki_sys::CKA_CERTIFICATE_CATEGORY),
        ("CKA_KEY_GEN_MECHANISM", cryptoki_sys::CKA_KEY_GEN_MECHANISM),
        ("CKA_EC_POINT", cryptoki_sys::CKA_EC_POINT),
        ("CKA_WRAP_WITH_TRUSTED", cryptoki_sys::CKA_WRAP_WITH_TRUSTED),
        ("CKA_PUBLIC_KEY_INFO", cryptoki_sys::CKA_PUBLIC_KEY_INFO),
    ];
    for (name, code) in sys_codes {
        assert_eq!(cka(name).map(|e| e.code), Some(u64::from(code)), "{name}");
    }
}

// ---- TestConversion ----

#[test]
fn conversion_enabled_only_disabled_omitted() {
    let template = tpl(vec![
        boolean("CKA_TOKEN", true),
        boolean("CKA_SIGN", true).disabled(),
        boolean("CKA_ENCRYPT", false),
    ]);
    let entries = template_to_attrs(&template, &no_custom()).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["CKA_TOKEN", "CKA_ENCRYPT"]);
    assert_eq!(entries[0].value, AttrValue::Bool(true));
    assert_eq!(entries[1].value, AttrValue::Bool(false));
}

#[test]
fn conversion_order_preserved() {
    let template = tpl(vec![
        boolean("CKA_SENSITIVE", true),
        boolean("CKA_TOKEN", true),
        str_attr("CKA_LABEL", "x"),
    ]);
    let names: Vec<String> = template_to_attrs(&template, &no_custom())
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["CKA_SENSITIVE", "CKA_TOKEN", "CKA_LABEL"]);
}

#[test]
fn conversion_unknown_name_raises() {
    let template = tpl(vec![boolean("CKA_BOGUS", true)]);
    let err = template_to_attrs(&template, &no_custom()).unwrap_err();
    assert_eq!(err.param_name(), Some("CKA_BOGUS"));
    assert_eq!(err.message, "unknown PKCS#11 attribute 'CKA_BOGUS'");
    assert_eq!(
        err.hint.as_deref(),
        Some("known names come from CKA_CATALOG or templates.custom_attributes")
    );
}

#[test]
fn conversion_symbolic_ulong_passes_through() {
    // config emits SYMBOLIC values for the locked rows (§4.8) — conversion must not
    // resolve them (that is the provider's job)
    let template = tpl(vec![
        ulong_attr("CKA_CLASS", symbol("CKO_SECRET_KEY")),
        ulong_attr("CKA_KEY_TYPE", symbol("CKK_AES")),
        // a STR row holding a constant name (config inference keeps it STR)
        ulong_attr("CKA_KEY_GEN_MECHANISM", AttrValue::Str("CKM_AES_KEY_GEN".into())),
    ]);
    let entries = template_to_attrs(&template, &no_custom()).unwrap();
    assert_eq!(entries[0].value, symbol("CKO_SECRET_KEY"));
    assert_eq!(entries[1].value, symbol("CKK_AES"));
    assert_eq!(entries[2].value, symbol("CKM_AES_KEY_GEN"));
    assert!(!entries[0].vendor);
}

#[test]
fn conversion_value_kind_mismatches() {
    let cases = [
        (
            TemplateAttr::new("CKA_TOKEN", AttrKind::Bool, AttrValue::Str("yes".into())),
            "template attribute CKA_TOKEN expects a boolean, got str",
            None,
        ),
        (
            TemplateAttr::new("CKA_VALUE_LEN", AttrKind::Ulong, AttrValue::Bool(true)),
            "template attribute CKA_VALUE_LEN expects an integer, got a boolean",
            None,
        ),
        (
            TemplateAttr::new("CKA_VALUE_LEN", AttrKind::Ulong, AttrValue::Str("not-a-symbol".into())),
            "template attribute CKA_VALUE_LEN expects an integer or a CKO_/CKK_/CKC_/CKM_ \
             constant name, got 'not-a-symbol'",
            None,
        ),
        (
            TemplateAttr::new("CKA_VALUE", AttrKind::Bytes, AttrValue::Str("0xzz".into())),
            "template attribute CKA_VALUE expects bytes, got str",
            Some("use a 0x… hex value"),
        ),
        (
            TemplateAttr::new("CKA_LABEL", AttrKind::Str, AttrValue::Ulong(7)),
            "template attribute CKA_LABEL expects a string, got int",
            None,
        ),
    ];
    for (attr, message, hint) in cases {
        let name = attr.name.clone();
        let err = template_to_attrs(&tpl(vec![attr]), &no_custom()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Param { param_name: name });
        assert_eq!(err.message, message);
        assert_eq!(err.hint.as_deref(), hint);
    }
    // c2's `-1` case: a negative ULONG cannot exist in r2 (u64; config/template-file loads
    // reject it, §11 D18) — covered by the R2/R14 loaders.
}

#[test]
fn conversion_custom_attribute_resolution() {
    let mut custom = IndexMap::new();
    custom.insert(
        "CKA_ACME_USAGE".to_string(),
        CustomAttributeDef { code: 0x8000_0101, kind: AttrKind::Bytes },
    );
    let template = tpl(vec![bytes_attr("CKA_ACME_USAGE", b"\xaa\xbb")]);
    let entries = template_to_attrs(&template, &custom).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].code, 0x8000_0101);
    assert_eq!(entries[0].kind, AttrKind::Bytes);
    assert!(entries[0].vendor);
    assert_eq!(entries[0].value, AttrValue::Bytes(vec![0xaa, 0xbb]));
}

#[test]
fn conversion_catalog_wins_over_custom() {
    let mut custom = IndexMap::new();
    custom.insert(
        "CKA_TOKEN".to_string(),
        CustomAttributeDef { code: 0x8000_0001, kind: AttrKind::Bytes },
    );
    let entries = template_to_attrs(&tpl(vec![boolean("CKA_TOKEN", true)]), &custom).unwrap();
    assert_eq!(entries[0].code, 0x0001);
    assert!(!entries[0].vendor);
}

// ---- TestVendorEncoding ----

#[test]
fn vendor_encoding_bool() {
    assert_eq!(encode_vendor_value(AttrKind::Bool, &AttrValue::Bool(true)).unwrap(), [1]);
    assert_eq!(encode_vendor_value(AttrKind::Bool, &AttrValue::Bool(false)).unwrap(), [0]);
}

#[test]
fn vendor_encoding_ulong_native_endian() {
    let encoded = encode_vendor_value(AttrKind::Ulong, &AttrValue::Ulong(0x1234)).unwrap();
    assert_eq!(encoded.len(), ULONG_SIZE);
    assert_eq!(encoded, (0x1234 as cryptoki_sys::CK_ULONG).to_ne_bytes());
}

#[test]
fn vendor_encoding_ulong_rejects_non_int() {
    let err = encode_vendor_value(AttrKind::Ulong, &AttrValue::Symbol("CKO_SECRET_KEY".into()))
        .unwrap_err();
    assert_eq!(err.message, "vendor ULONG attribute expects an integer, got 'CKO_SECRET_KEY'");
    assert_eq!(err.param_name(), Some("CKO_SECRET_KEY"));
}

#[test]
fn vendor_encoding_str_and_bytes() {
    assert_eq!(
        encode_vendor_value(AttrKind::Str, &AttrValue::Str("héllo".into())).unwrap(),
        "héllo".as_bytes()
    );
    assert_eq!(
        encode_vendor_value(AttrKind::Bytes, &AttrValue::Bytes(vec![0x00, 0xff])).unwrap(),
        [0x00, 0xff]
    );
    let err = encode_vendor_value(AttrKind::Bytes, &AttrValue::Ulong(42)).unwrap_err();
    assert_eq!(err.message, "vendor BYTES attribute expects bytes, got int");
    assert_eq!(err.param_name(), Some("42"));
}

// ---- TestVendorDecoding ----

#[test]
fn vendor_decoding_round_trips_every_kind() {
    let cases = [
        (AttrKind::Bool, AttrValue::Bool(true)),
        (AttrKind::Bool, AttrValue::Bool(false)),
        (AttrKind::Ulong, AttrValue::Ulong(0x1234)),
        (AttrKind::Str, AttrValue::Str("héllo".into())),
        (AttrKind::Bytes, AttrValue::Bytes(vec![0x00, 0xff])),
    ];
    for (kind, value) in cases {
        let encoded = encode_vendor_value(kind, &value).unwrap();
        assert_eq!(decode_vendor_value(kind, &encoded), value);
    }
}

#[test]
fn vendor_decoding_bool_any_nonzero_byte_is_true() {
    assert_eq!(decode_vendor_value(AttrKind::Bool, &[0, 0]), AttrValue::Bool(false));
    assert_eq!(decode_vendor_value(AttrKind::Bool, &[0, 2]), AttrValue::Bool(true));
}

#[test]
fn vendor_decoding_str_replaces_undecodable_bytes() {
    assert_eq!(decode_vendor_value(AttrKind::Str, &[0xff]), AttrValue::Str("\u{fffd}".into()));
}

// ---- TestTemplateIdentity ----

#[test]
fn identity_none_templates_yield_nothing() {
    assert_eq!(template_identity(&[None, None]).unwrap(), (None, None));
}

#[test]
fn identity_extracts_enabled_rows() {
    let template = tpl(vec![
        boolean("CKA_TOKEN", true),
        bytes_attr("CKA_ID", b"\xc0\xfe"),
        str_attr("CKA_LABEL", "renamed"),
    ]);
    assert_eq!(
        template_identity(&[Some(&template)]).unwrap(),
        (Some("renamed".to_string()), Some(vec![0xc0, 0xfe]))
    );
}

#[test]
fn identity_disabled_rows_ignored() {
    let template = tpl(vec![bytes_attr("CKA_ID", b"\x01").disabled(), str_attr("CKA_LABEL", "x").disabled()]);
    assert_eq!(template_identity(&[Some(&template)]).unwrap(), (None, None));
}

#[test]
fn identity_agreeing_templates_merge() {
    let private = tpl(vec![bytes_attr("CKA_ID", b"\x01")]);
    let public = tpl(vec![bytes_attr("CKA_ID", b"\x01")]);
    assert_eq!(template_identity(&[Some(&private), Some(&public)]).unwrap(), (None, Some(vec![1])));
}

#[test]
fn identity_conflicting_ids_rejected() {
    let private = tpl(vec![bytes_attr("CKA_ID", b"\x01")]);
    let public = tpl(vec![bytes_attr("CKA_ID", b"\x02")]);
    let err = template_identity(&[Some(&private), Some(&public)]).unwrap_err();
    assert_eq!(err.param_name(), Some("CKA_ID"));
    assert_eq!(
        err.message,
        "templates disagree on CKA_ID (0x01 vs 0x02) — keypair objects share one id"
    );
}

#[test]
fn identity_conflicting_labels_rejected() {
    let private = tpl(vec![str_attr("CKA_LABEL", "a")]);
    let public = tpl(vec![str_attr("CKA_LABEL", "b")]);
    let err = template_identity(&[Some(&private), Some(&public)]).unwrap_err();
    assert_eq!(err.param_name(), Some("CKA_LABEL"));
    assert_eq!(
        err.message,
        "templates disagree on CKA_LABEL ('a' vs 'b') — keypair objects share one label"
    );
}

#[test]
fn identity_empty_id_rejected() {
    let err = template_identity(&[Some(&tpl(vec![bytes_attr("CKA_ID", b"")]))]).unwrap_err();
    assert_eq!(err.message, "template CKA_ID expects non-empty bytes");
    assert_eq!(err.hint.as_deref(), Some("use a 0x… hex value"));
}

#[test]
fn identity_empty_label_rejected() {
    let err = template_identity(&[Some(&tpl(vec![str_attr("CKA_LABEL", "")]))]).unwrap_err();
    assert_eq!(err.message, "template CKA_LABEL expects a non-empty string");
    assert_eq!(err.param_name(), Some("CKA_LABEL"));
}
