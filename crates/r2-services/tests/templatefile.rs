// services::templatefile — port of c2 tests/unit/services/test_templatefile.py (codec
// round-trip + seeding policy, §5.16) plus the `--template` seeding cases of
// test_keyload.py, test_wrapload.py and test_transfer.py (R14), and r2's interop vectors:
// dumps byte-identical to c2's (PyYAML `safe_dump`), c2 dumps (incl. a SoftHSM object
// imported in c2, `CKA_KEY_GEN_MECHANISM: -1`) seeding r2. FakeProvider + RecordingEditor
// only (spec §4.10).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod keyload_fixtures;

use std::path::Path;

use indexmap::IndexMap;
use keyload_fixtures::{aes16_material, make_templates, rsa_cert_der, rsa_pkcs8_der};
use r2_config::model::{CustomAttributeDef, TemplatesSection};
use r2_config::yaml::{self, Value};
use r2_core::error::{ConsoleError, ErrorKind};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_core::x509build::build_pkcs12;
use r2_provider::Provider;
use r2_services::keyload;
use r2_services::templatefile::{
    self, EditorSeeding, NON_CREATION_ATTRS, SECRET_MATERIAL_ATTRS, SeedTemplates,
};
use r2_testkit::{FakeProvider, RecordingEditor, ScriptedIo};
use secrecy::SecretString;

fn no_custom() -> IndexMap<String, CustomAttributeDef> {
    IndexMap::new()
}

fn attr(name: &str, kind: AttrKind, value: AttrValue) -> TemplateAttr {
    TemplateAttr::new(name, kind, value)
}

fn sym(text: &str) -> AttrValue {
    AttrValue::Symbol(text.to_owned())
}

fn bool_attr(name: &str, value: bool) -> TemplateAttr {
    attr(name, AttrKind::Bool, AttrValue::Bool(value))
}

/// A read_full_template-shaped dump: symbolic rows, identity, policy, material.
fn full_rsa_private_template() -> KeyTemplate {
    KeyTemplate::new(vec![
        attr("CKA_CLASS", AttrKind::Ulong, sym("CKO_PRIVATE_KEY")),
        attr("CKA_KEY_TYPE", AttrKind::Ulong, sym("CKK_RSA")),
        attr(
            "CKA_LABEL",
            AttrKind::Str,
            AttrValue::Str("0xdeadbeef".into()),
        ),
        attr(
            "CKA_ID",
            AttrKind::Bytes,
            AttrValue::Bytes(vec![0x0a, 0x1b]),
        ),
        bool_attr("CKA_TOKEN", true),
        bool_attr("CKA_SENSITIVE", false),
        attr("CKA_MODULUS_BITS", AttrKind::Ulong, AttrValue::Ulong(2048)),
        attr(
            "CKA_MODULUS",
            AttrKind::Bytes,
            AttrValue::Bytes(vec![0xb1, 0xc2]),
        ),
    ])
}

fn rows(template: &KeyTemplate) -> Vec<(String, AttrKind, AttrValue)> {
    template
        .attrs
        .iter()
        .map(|a| (a.name.clone(), a.kind, a.value.clone()))
        .collect()
}

fn names(template: &KeyTemplate) -> Vec<String> {
    template.attrs.iter().map(|a| a.name.clone()).collect()
}

fn write(dir: &Path, text: &str) -> std::path::PathBuf {
    let path = dir.join("tpl.yaml");
    std::fs::write(&path, text).unwrap();
    path
}

fn load_text(text: &str) -> r2_core::Result<SeedTemplates> {
    let dir = tempfile::tempdir().unwrap();
    templatefile::load_seed_file(&write(dir.path(), text), &no_custom())
}

fn load_err(text: &str) -> ConsoleError {
    load_text(text).unwrap_err()
}

fn param_name(err: &ConsoleError) -> &str {
    match &err.kind {
        ErrorKind::Param { param_name } => param_name,
        other => panic!("not a Param error: {other:?} ({})", err.message),
    }
}

// ---------------------------------------------------------------------------------------
// codec (c2 test_templatefile.py)
// ---------------------------------------------------------------------------------------

#[test]
fn test_dump_load_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpl.yaml");
    templatefile::dump_template_file(&path, "rsa_private", &full_rsa_private_template()).unwrap();
    let sections = templatefile::load_seed_file(&path, &no_custom()).unwrap();
    assert_eq!(sections.keys().collect::<Vec<_>>(), ["rsa_private"]);
    let loaded = &sections["rsa_private"];
    assert_eq!(
        rows(loaded),
        vec![
            ("CKA_CLASS".into(), AttrKind::Ulong, sym("CKO_PRIVATE_KEY")),
            ("CKA_KEY_TYPE".into(), AttrKind::Ulong, sym("CKK_RSA")),
            // kind comes from the catalog by NAME: the hex-looking label stays STR.
            (
                "CKA_LABEL".into(),
                AttrKind::Str,
                AttrValue::Str("0xdeadbeef".into())
            ),
            (
                "CKA_ID".into(),
                AttrKind::Bytes,
                AttrValue::Bytes(vec![0x0a, 0x1b])
            ),
            ("CKA_TOKEN".into(), AttrKind::Bool, AttrValue::Bool(true)),
            (
                "CKA_SENSITIVE".into(),
                AttrKind::Bool,
                AttrValue::Bool(false)
            ),
            (
                "CKA_MODULUS_BITS".into(),
                AttrKind::Ulong,
                AttrValue::Ulong(2048)
            ),
            (
                "CKA_MODULUS".into(),
                AttrKind::Bytes,
                AttrValue::Bytes(vec![0xb1, 0xc2])
            ),
        ]
    );
    // loaded rows are plain enabled rows; seeding decides enabled/locked (build_seed)
    assert!(loaded.attrs.iter().all(|a| a.enabled && !a.locked));
}

#[test]
fn test_dump_writes_per_kind_yaml_scalars() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpl.yaml");
    templatefile::dump_template_file(&path, "rsa_private", &full_rsa_private_template()).unwrap();
    let raw = yaml::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let section = &raw["rsa_private"];
    // symbolic ULONG kept verbatim
    assert_eq!(
        section["CKA_CLASS"],
        Value::String("CKO_PRIVATE_KEY".into())
    );
    assert_eq!(section["CKA_TOKEN"], Value::Bool(true));
    assert_eq!(yaml::as_int(&section["CKA_MODULUS_BITS"]), Some(2048));
    assert_eq!(section["CKA_ID"], Value::String("0x0a1b".into()));
    assert_eq!(section["CKA_MODULUS"], Value::String("0xb1c2".into()));
}

#[test]
fn test_dump_write_failure_raises_dataioerror() {
    let dir = tempfile::tempdir().unwrap();
    let err = templatefile::dump_template_file(
        &dir.path().join("absent-dir").join("tpl.yaml"),
        "aes",
        &KeyTemplate::default(),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::DataIo);
    assert!(err.message.contains("cannot write"), "{}", err.message);
    assert!(
        err.message.ends_with("tpl.yaml: No such file or directory"),
        "{}",
        err.message
    );
}

#[test]
fn test_load_missing_file_raises_dataioerror() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.yaml");
    let err = templatefile::load_seed_file(&path, &no_custom()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::DataIo);
    assert_eq!(
        err.message,
        format!("cannot read {}: No such file or directory", path.display())
    );
}

#[test]
fn test_load_malformed_yaml_raises_paramerror() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "rsa_private: [unclosed");
    let err = templatefile::load_seed_file(&path, &no_custom()).unwrap_err();
    assert_eq!(param_name(&err), "template");
    assert!(
        err.message.starts_with(&format!(
            "invalid YAML in template file {}: ",
            path.display()
        )),
        "{}",
        err.message
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("template files are class-keyed YAML (spec §5.16)")
    );
}

#[test]
fn test_load_without_sections_raises_paramerror() {
    for text in ["", "just a string", "[]"] {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), text);
        let err = templatefile::load_seed_file(&path, &no_custom()).unwrap_err();
        assert_eq!(param_name(&err), "template", "{text:?}");
        assert_eq!(
            err.message,
            format!("template file {} has no sections", path.display())
        );
        assert_eq!(
            err.hint.as_deref(),
            Some(
                "valid sections: aes, rsa_private, rsa_public, ec_private, ec_public, \
                 certificate, generic_secret, data"
            )
        );
    }
    // an empty mapping (`{}`) and a null document have no sections either
    for text in ["{}\n", "~\n", "# only a comment\n"] {
        assert!(
            load_err(text).message.ends_with("has no sections"),
            "{text:?}"
        );
    }
}

#[test]
fn test_load_unknown_section_raises_paramerror() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "rsa_priv:\n  CKA_TOKEN: true\n");
    let err = templatefile::load_seed_file(&path, &no_custom()).unwrap_err();
    assert_eq!(param_name(&err), "template");
    assert_eq!(
        err.message,
        format!("unknown template section 'rsa_priv' in {}", path.display())
    );
    assert!(
        err.hint
            .as_deref()
            .unwrap_or("")
            .contains("aes, rsa_private")
    );
}

#[test]
fn unknown_section_keys_render_like_python_str() {
    // c2 f-string `{section_key}` over the PyYAML-typed key
    for (text, shown) in [
        ("1: {CKA_TOKEN: true}\n", "1"),
        ("yes: {CKA_TOKEN: true}\n", "True"),
        ("~: {CKA_TOKEN: true}\n", "None"),
        ("1.5: {CKA_TOKEN: true}\n", "1.5"),
        ("AES: {CKA_TOKEN: true}\n", "AES"),
        // date/datetime/bytes keys: Python `str()` of the object PyYAML built (c2@408d6f2)
        ("2002-12-14: {CKA_TOKEN: true}\n", "2002-12-14"),
        (
            "2001-12-14t21:59:43.10-05:00:\n  CKA_TOKEN: true\n",
            "2001-12-14 21:59:43.100000-05:00",
        ),
        ("!!binary aGk=: {CKA_TOKEN: true}\n", "b'hi'"),
    ] {
        let err = load_err(text);
        assert!(
            err.message
                .starts_with(&format!("unknown template section '{shown}' in ")),
            "{text:?}: {}",
            err.message
        );
    }
}

#[test]
fn unknown_attribute_keys_render_like_python_str() {
    // c2 `str(name)` over the PyYAML-typed key; param_name is the same text (c2@408d6f2)
    for (text, shown) in [
        (
            "aes:\n  2001-12-14 21:59:43.10: 1\n",
            "2001-12-14 21:59:43.100000",
        ),
        (
            "aes:\n  2001-12-14t21:59:43.10-05:00: x\n",
            "2001-12-14 21:59:43.100000-05:00",
        ),
        (
            "aes:\n  2001-12-14T21:59:43Z: 1\n",
            "2001-12-14 21:59:43+00:00",
        ),
        (
            "aes:\n  2001-1-2   1:02:03.1234567 +5: 1\n",
            "2001-01-02 01:02:03.123456+05:00",
        ),
        ("aes:\n  !!binary aGVsbG8=: 1\n", "b'hello'"),
        ("aes:\n  ? !!binary AAEC\n  : x\n", "b'\\x00\\x01\\x02'"),
        ("aes:\n  !!binary \"\": 1\n", "b''"),
        ("aes:\n  2002-12-14: 1\n", "2002-12-14"),
        ("aes:\n  1000.0: 1\n", "1000.0"),
    ] {
        let err = load_err(text);
        assert_eq!(
            err.message,
            format!("unknown PKCS#11 attribute '{shown}'"),
            "{text:?}"
        );
        assert_eq!(param_name(&err), shown, "{text:?}");
    }
}

#[test]
fn test_load_non_mapping_section_raises_paramerror() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "aes: [CKA_TOKEN]\n");
    let err = templatefile::load_seed_file(&path, &no_custom()).unwrap_err();
    assert_eq!(param_name(&err), "template");
    assert_eq!(
        err.message,
        format!(
            "template section 'aes' in {} is not a mapping",
            path.display()
        )
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("each section maps CKA_* names to values")
    );
    // a section without entries is null, not an empty mapping
    assert!(load_err("aes:\n").message.ends_with("is not a mapping"));
    // `{}` is an empty (valid) section
    assert!(load_text("aes: {}\n").unwrap()["aes"].attrs.is_empty());
}

#[test]
fn test_load_unknown_attribute_hints_custom_attributes() {
    let err = load_err("aes:\n  CKA_ACME_USAGE: '0x01'\n");
    assert_eq!(err.message, "unknown PKCS#11 attribute 'CKA_ACME_USAGE'");
    assert_eq!(param_name(&err), "CKA_ACME_USAGE");
    assert_eq!(
        err.hint.as_deref(),
        Some("define it under templates.custom_attributes (code + kind)")
    );
}

#[test]
fn test_load_custom_attribute_kind_comes_from_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "aes:\n  CKA_ACME_USAGE: '0x0102'\n");
    let mut custom = no_custom();
    custom.insert(
        "CKA_ACME_USAGE".into(),
        CustomAttributeDef {
            code: 0x8000_0101,
            kind: AttrKind::Bytes,
        },
    );
    let sections = templatefile::load_seed_file(&path, &custom).unwrap();
    assert_eq!(
        rows(&sections["aes"]),
        vec![(
            "CKA_ACME_USAGE".into(),
            AttrKind::Bytes,
            AttrValue::Bytes(vec![1, 2])
        )]
    );
}

#[test]
fn test_load_value_kind_mismatch_raises_paramerror() {
    for (line, expected, name) in [
        (
            "CKA_TOKEN: 'yes'",
            "CKA_TOKEN expects true/false",
            "CKA_TOKEN",
        ),
        (
            "CKA_MODULUS_BITS: '2048'",
            "CKA_MODULUS_BITS expects an integer or CKO_/CKK_/CKC_/CKM_ constant",
            "CKA_MODULUS_BITS",
        ),
        // bool is not an acceptable int
        (
            "CKA_MODULUS_BITS: true",
            "CKA_MODULUS_BITS expects an integer",
            "CKA_MODULUS_BITS",
        ),
        (
            "CKA_ID: 'nothex'",
            "CKA_ID expects a 0x… hex string",
            "CKA_ID",
        ),
        ("CKA_ID: '0xzz'", "CKA_ID has invalid hex", "CKA_ID"),
        ("CKA_LABEL: 7", "CKA_LABEL expects a string", "CKA_LABEL"),
    ] {
        let err = load_err(&format!("rsa_private:\n  {line}\n"));
        assert_eq!(err.message, expected, "{line}");
        assert_eq!(param_name(&err), name, "{line}");
        assert_eq!(err.hint, None, "{line}");
    }
}

#[test]
fn yaml_1_1_typing_decides_the_value_never_the_name_alone() {
    // plain `yes` is a bool (PyYAML YAML 1.1): fine for a BOOL row, wrong for a STR row
    let sections = load_text("aes:\n  CKA_TOKEN: yes\n  CKA_PRIVATE: off\n").unwrap();
    assert_eq!(
        rows(&sections["aes"]),
        vec![
            ("CKA_TOKEN".into(), AttrKind::Bool, AttrValue::Bool(true)),
            ("CKA_PRIVATE".into(), AttrKind::Bool, AttrValue::Bool(false)),
        ]
    );
    assert_eq!(
        load_err("aes:\n  CKA_LABEL: yes\n").message,
        "CKA_LABEL expects a string"
    );
    // quoted, it is a string
    let sections = load_text("aes:\n  CKA_LABEL: 'yes'\n").unwrap();
    assert_eq!(sections["aes"].attrs[0].value, AttrValue::Str("yes".into()));
    // YAML 1.1 ints: hex / octal / sexagesimal plain scalars are ints for ULONG rows
    let sections =
        load_text("aes:\n  CKA_VALUE_LEN: 0x20\n  CKA_KEY_GEN_MECHANISM: 0o17\n").unwrap_err();
    assert_eq!(
        sections.message,
        "CKA_KEY_GEN_MECHANISM expects an integer or CKO_/CKK_/CKC_/CKM_ constant"
    );
    let sections = load_text("aes:\n  CKA_VALUE_LEN: 0x20\n  CKA_MODULUS_BITS: 017\n").unwrap();
    assert_eq!(sections["aes"].attrs[0].value, AttrValue::Ulong(32));
    assert_eq!(sections["aes"].attrs[1].value, AttrValue::Ulong(15));
    // a hex-looking plain BYTES value is a YAML int, so it is not a 0x… string
    assert_eq!(
        load_err("aes:\n  CKA_ID: 0x0a1b\n").message,
        "CKA_ID expects a 0x… hex string"
    );
    // floats, nulls and timestamps are not integers
    for value in ["1.5", "~", "2001-01-01"] {
        assert_eq!(
            load_err(&format!("aes:\n  CKA_VALUE_LEN: {value}\n")).message,
            "CKA_VALUE_LEN expects an integer or CKO_/CKK_/CKC_/CKM_ constant",
            "{value}"
        );
    }
}

#[test]
fn ulong_symbols_bytes_and_strings_load_by_name() {
    let sections = load_text(
        "rsa_public:\n  CKA_KEY_GEN_MECHANISM: CKM_RSA_PKCS_KEY_PAIR_GEN\n  \
         CKA_CERTIFICATE_TYPE: CKC_X_509\n  CKA_APPLICATION: CKM_SHA256\n  \
         CKA_SUBJECT: 0x\n  CKA_ID: '0x 0A 1b'\n  CKA_LABEL: ''\n",
    )
    .unwrap();
    assert_eq!(
        rows(&sections["rsa_public"]),
        vec![
            (
                "CKA_KEY_GEN_MECHANISM".into(),
                AttrKind::Ulong,
                sym("CKM_RSA_PKCS_KEY_PAIR_GEN")
            ),
            (
                "CKA_CERTIFICATE_TYPE".into(),
                AttrKind::Ulong,
                sym("CKC_X_509")
            ),
            // a STR row keeps a CKM_… name as a string (§4.7 conversion resolves it)
            (
                "CKA_APPLICATION".into(),
                AttrKind::Str,
                AttrValue::Str("CKM_SHA256".into())
            ),
            (
                "CKA_SUBJECT".into(),
                AttrKind::Bytes,
                AttrValue::Bytes(vec![])
            ),
            // Python bytes.fromhex skips whitespace between bytes
            (
                "CKA_ID".into(),
                AttrKind::Bytes,
                AttrValue::Bytes(vec![0x0a, 0x1b])
            ),
            (
                "CKA_LABEL".into(),
                AttrKind::Str,
                AttrValue::Str(String::new())
            ),
        ]
    );
    // a ULONG string that is no CKO_/CKK_/CKC_/CKM_ name is refused (prefix is case-exact)
    assert_eq!(
        load_err("aes:\n  CKA_VALUE_LEN: cko_data\n").message,
        "CKA_VALUE_LEN expects an integer or CKO_/CKK_/CKC_/CKM_ constant"
    );
    // a BYTES prefix is lower-case `0x` only (c2 `startswith("0x")`)
    assert_eq!(
        load_err("aes:\n  CKA_ID: '0X0a'\n").message,
        "CKA_ID expects a 0x… hex string"
    );
    // a !!binary value is Python bytes, not a 0x… string
    assert_eq!(
        load_err("aes:\n  CKA_ID: !!binary AQI=\n").message,
        "CKA_ID expects a 0x… hex string"
    );
}

#[test]
fn negative_ulong_is_twos_complement_only_in_non_creation_rows() {
    // §11 D18: c2 dumped PyKCS11's signed C long; such a row seeds r2 like r2's own dump
    let sections =
        load_text("aes:\n  CKA_KEY_GEN_MECHANISM: -1\n  CKA_VALUE_LEN: -9223372036854775808\n")
            .unwrap();
    assert_eq!(
        sections["aes"].attrs[0].value,
        AttrValue::Ulong(18_446_744_073_709_551_615)
    );
    assert_eq!(
        sections["aes"].attrs[1].value,
        AttrValue::Ulong(9_223_372_036_854_775_808)
    );
    // any other ULONG row refuses a negative value at load
    for line in ["CKA_CERTIFICATE_TYPE: -1", "CKA_VALUE_BITS: -5"] {
        let err = load_err(&format!("aes:\n  {line}\n"));
        let name = line.split(':').next().unwrap();
        assert_eq!(
            err.message,
            format!("template attribute {name} must not be negative")
        );
        assert_eq!(param_name(&err), name);
        assert_eq!(err.hint, None);
    }
    // a custom (vendor) ULONG row too
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "aes:\n  CKA_ACME_LEVEL: -1\n");
    let mut custom = no_custom();
    custom.insert(
        "CKA_ACME_LEVEL".into(),
        CustomAttributeDef {
            code: 0x8000_0102,
            kind: AttrKind::Ulong,
        },
    );
    let err = templatefile::load_seed_file(&path, &custom).unwrap_err();
    assert_eq!(
        err.message,
        "template attribute CKA_ACME_LEVEL must not be negative"
    );
    // integers beyond the u64 range are a YAML load error (§11 D17 (c))
    let err = load_err("aes:\n  CKA_VALUE_LEN: 18446744073709551616\n");
    assert!(
        err.message.contains("integer out of range"),
        "{}",
        err.message
    );
    assert_eq!(param_name(&err), "template");
}

#[test]
fn negative_class_rows_load_and_are_dropped_like_c2() {
    // c2 loaded `CKA_CLASS: -1` unchanged and build_seed dropped it (the flow supplies the
    // class and key type), so it never raised; r2 loads the two's complement (§11 D18)
    let sections = load_text(
        "aes:\n  CKA_CLASS: -1\n  CKA_KEY_TYPE: -9223372036854775808\n  CKA_TOKEN: true\n",
    )
    .unwrap();
    assert_eq!(
        rows(&sections["aes"]),
        vec![
            (
                "CKA_CLASS".into(),
                AttrKind::Ulong,
                AttrValue::Ulong(u64::MAX)
            ),
            (
                "CKA_KEY_TYPE".into(),
                AttrKind::Ulong,
                AttrValue::Ulong(9_223_372_036_854_775_808)
            ),
            ("CKA_TOKEN".into(), AttrKind::Bool, AttrValue::Bool(true)),
        ]
    );
    let seed = templatefile::build_seed(
        &make_templates(),
        Some(&sections),
        KeyClass::Secret,
        KeyAlgorithm::Aes,
    )
    .unwrap();
    let class_rows: Vec<(String, AttrValue, bool)> = seed
        .attrs
        .iter()
        .filter(|a| a.name == "CKA_CLASS" || a.name == "CKA_KEY_TYPE")
        .map(|a| (a.name.clone(), a.value.clone(), a.locked))
        .collect();
    assert_eq!(
        class_rows,
        vec![
            ("CKA_CLASS".into(), sym("CKO_SECRET_KEY"), true),
            ("CKA_KEY_TYPE".into(), sym("CKK_AES"), true),
        ]
    );
    assert_eq!(names(&seed), ["CKA_CLASS", "CKA_KEY_TYPE", "CKA_TOKEN"]);
}

#[test]
fn non_utf8_file_is_an_unreadable_file() {
    // §11 D12 (s): c2 `read_text` raised UnicodeDecodeError past `except OSError`
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpl.yaml");
    std::fs::write(&path, b"aes:\n  CKA_LABEL: \xff\n").unwrap();
    let err = templatefile::load_seed_file(&path, &no_custom()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::DataIo);
    assert_eq!(
        err.message,
        format!(
            "cannot read {}: 'utf-8' codec can't decode byte 0xff in position 18: invalid \
             start byte",
            path.display()
        )
    );
}

#[test]
fn construction_errors_of_the_yaml_loader_are_invalid_yaml() {
    // §11 D12 (s): c2 let PyYAML's non-YAMLError construction exceptions escape
    for (text, detail) in [
        (
            "aes:\n  CKA_START_DATE: 2001-02-30\n",
            "day is out of range for month",
        ),
        (
            "aes:\n  CKA_VALUE_LEN: !!int x\n",
            "invalid literal for int() with base 10: 'x'",
        ),
        (
            "aes:\n  CKA_VALUE_LEN: !!int \"1:x\"\n",
            "invalid literal for int() with base 10: 'x'",
        ),
        (
            "aes:\n  CKA_VALUE_LEN: !!float \"abc\"\n",
            "could not convert string to float: 'abc'",
        ),
        // c2 crashed with KeyError / AttributeError / IndexError here: the yaml loader's text
        (
            "aes:\n  CKA_TOKEN: !!bool \"abc\"\n",
            "invalid boolean value 'abc'",
        ),
        (
            "aes:\n  CKA_START_DATE: !!timestamp \"abc\"\n",
            "invalid timestamp 'abc'",
        ),
        (
            "aes:\n  CKA_VALUE_LEN: !!int \"\"\n",
            "invalid literal for int() with base 10: ''",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), text);
        let err = templatefile::load_seed_file(&path, &no_custom()).unwrap_err();
        assert_eq!(param_name(&err), "template");
        assert_eq!(
            err.message,
            format!("invalid YAML in template file {}: {detail}", path.display())
        );
    }
}

#[test]
fn crlf_text_and_duplicate_keys_load_like_pyyaml() {
    // universal newlines; a repeated key keeps its first position and its last value
    let sections =
        load_text("aes:\r\n  CKA_TOKEN: true\r\n  CKA_PRIVATE: true\r\n  CKA_TOKEN: false\r\n")
            .unwrap();
    assert_eq!(
        rows(&sections["aes"]),
        vec![
            ("CKA_TOKEN".into(), AttrKind::Bool, AttrValue::Bool(false)),
            ("CKA_PRIVATE".into(), AttrKind::Bool, AttrValue::Bool(true)),
        ]
    );
    // several sections, file order kept
    let sections =
        load_text("rsa_public: {CKA_VERIFY: true}\nrsa_private: {CKA_SIGN: true}\n").unwrap();
    assert_eq!(
        sections.keys().collect::<Vec<_>>(),
        ["rsa_public", "rsa_private"]
    );
}

/// c2 6.0.3 `safe_dump` output of this template (generated with c2's
/// `templatefile.dump_template_file`), except CKA_KEY_GEN_MECHANISM: c2's template held
/// PyKCS11's signed `-1`, r2's holds the unsigned value (§11 D18).
const C2_DUMP: &str = "rsa_private:\n  CKA_CLASS: CKO_PRIVATE_KEY\n  CKA_KEY_TYPE: CKK_RSA\n  \
CKA_LABEL: \"\\u043A\\u043B\\u044E\\u0447 'yes' \\u0438 \\u0434\\u043B\\u0438\\u043D\\u043D\\\n    \
\\u044B\\u0439 \\u044F\\u0440\\u043B\\u044B\\u043A \\u043A\\u043B\\u044E\\u0447 'yes' \\u0438\\\n    \
\\ \\u0434\\u043B\\u0438\\u043D\\u043D\\u044B\\u0439 \\u044F\\u0440\\u043B\\u044B\\u043A \\u043A\\\n    \
\\u043B\\u044E\\u0447 'yes' \\u0438 \\u0434\\u043B\\u0438\\u043D\\u043D\\u044B\\u0439 \\u044F\\\n    \
\\u0440\\u043B\\u044B\\u043A \"\n  CKA_APPLICATION: 'yes'\n  CKA_SUBJECT: 0x\n  CKA_ID: \
'0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'\n  \
CKA_TOKEN: true\n  CKA_PRIVATE: false\n  CKA_KEY_GEN_MECHANISM: -1\n  CKA_MODULUS_BITS: 2048\n  \
CKA_START_DATE: 0x\n";

fn interop_template() -> KeyTemplate {
    KeyTemplate::new(vec![
        attr("CKA_CLASS", AttrKind::Ulong, sym("CKO_PRIVATE_KEY")),
        attr("CKA_KEY_TYPE", AttrKind::Ulong, sym("CKK_RSA")),
        attr(
            "CKA_LABEL",
            AttrKind::Str,
            AttrValue::Str("ключ 'yes' и длинный ярлык ".repeat(3)),
        ),
        attr(
            "CKA_APPLICATION",
            AttrKind::Str,
            AttrValue::Str("yes".into()),
        ),
        attr("CKA_SUBJECT", AttrKind::Bytes, AttrValue::Bytes(vec![])),
        attr(
            "CKA_ID",
            AttrKind::Bytes,
            AttrValue::Bytes((0u8..48).collect()),
        ),
        bool_attr("CKA_TOKEN", true),
        bool_attr("CKA_PRIVATE", false),
        attr(
            "CKA_KEY_GEN_MECHANISM",
            AttrKind::Ulong,
            AttrValue::Ulong(u64::MAX),
        ),
        attr("CKA_MODULUS_BITS", AttrKind::Ulong, AttrValue::Ulong(2048)),
        attr("CKA_START_DATE", AttrKind::Bytes, AttrValue::Bytes(vec![])),
    ])
}

#[test]
fn dump_is_byte_identical_to_c2() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpl.yaml");
    templatefile::dump_template_file(&path, "rsa_private", &interop_template()).unwrap();
    let written = std::fs::read_to_string(&path).unwrap();
    let expected = C2_DUMP.replace(
        "CKA_KEY_GEN_MECHANISM: -1",
        "CKA_KEY_GEN_MECHANISM: 18446744073709551615",
    );
    assert_eq!(written, expected);
}

#[test]
fn c2_dump_seeds_r2_and_r2_dump_reloads_identically() {
    // a file dumped by c2 loads in r2 to the template r2 itself would have dumped
    let c2_sections = load_text(C2_DUMP).unwrap();
    assert_eq!(rows(&c2_sections["rsa_private"]), rows(&interop_template()));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("r2.yaml");
    templatefile::dump_template_file(&path, "rsa_private", &interop_template()).unwrap();
    let r2_sections = templatefile::load_seed_file(&path, &no_custom()).unwrap();
    assert_eq!(r2_sections, c2_sections);
}

/// `key template` of an AES key IMPORTED on SoftHSM 2.6.1 by c2 (`load hsm aes
/// 000102…0f --label imp --id 0a1b`, §7 default template) — c2's dump verbatim.
const C2_SOFTHSM_IMPORTED_AES: &str = "aes:\n  CKA_CLASS: CKO_SECRET_KEY\n  CKA_TOKEN: true\n  \
CKA_PRIVATE: true\n  CKA_LABEL: imp\n  CKA_TRUSTED: false\n  CKA_CHECK_VALUE: '0xc6a13b'\n  \
CKA_KEY_TYPE: CKK_AES\n  CKA_ID: '0x0a1b'\n  CKA_START_DATE: 0x\n  CKA_END_DATE: 0x\n  \
CKA_SENSITIVE: true\n  CKA_ENCRYPT: true\n  CKA_DECRYPT: true\n  CKA_WRAP: false\n  \
CKA_UNWRAP: false\n  CKA_SIGN: true\n  CKA_VERIFY: true\n  CKA_DERIVE: false\n  \
CKA_VALUE_LEN: 16\n  CKA_EXTRACTABLE: false\n  CKA_LOCAL: false\n  CKA_NEVER_EXTRACTABLE: false\n  \
CKA_ALWAYS_SENSITIVE: false\n  CKA_KEY_GEN_MECHANISM: -1\n  CKA_MODIFIABLE: true\n  \
CKA_COPYABLE: true\n  CKA_DESTROYABLE: true\n  CKA_WRAP_WITH_TRUSTED: false\n";

#[test]
fn c2_dump_of_an_imported_softhsm_object_seeds_a_disabled_unavailable_row() {
    let sections = load_text(C2_SOFTHSM_IMPORTED_AES).unwrap();
    let seed = templatefile::build_seed(
        &make_templates(),
        Some(&sections),
        KeyClass::Secret,
        KeyAlgorithm::Aes,
    )
    .unwrap();
    let mech = seed.get("CKA_KEY_GEN_MECHANISM").unwrap();
    assert_eq!(mech.value, AttrValue::Ulong(18_446_744_073_709_551_615));
    assert_eq!(mech.kind, AttrKind::Ulong);
    assert!(!mech.enabled);
    // the same row of r2's own dump of that object seeds identically
    let own = load_text(&C2_SOFTHSM_IMPORTED_AES.replace(
        "CKA_KEY_GEN_MECHANISM: -1",
        "CKA_KEY_GEN_MECHANISM: 18446744073709551615",
    ))
    .unwrap();
    assert_eq!(own, sections);
    // the c2 dump re-dumped by r2 differs from c2's only in that D18 value
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("redump.yaml");
    templatefile::dump_template_file(&path, "aes", &sections["aes"]).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        C2_SOFTHSM_IMPORTED_AES.replace(
            "CKA_KEY_GEN_MECHANISM: -1",
            "CKA_KEY_GEN_MECHANISM: 18446744073709551615"
        )
    );
    // seeding policy over a real dump: locked flow rows, identity + NON_CREATION disabled
    let enabled: Vec<&str> = seed
        .attrs
        .iter()
        .filter(|a| a.enabled && !a.locked)
        .map(|a| a.name.as_str())
        .collect();
    assert_eq!(
        enabled,
        [
            "CKA_TOKEN",
            "CKA_PRIVATE",
            "CKA_TRUSTED",
            "CKA_START_DATE",
            "CKA_END_DATE",
            "CKA_SENSITIVE",
            "CKA_ENCRYPT",
            "CKA_DECRYPT",
            "CKA_WRAP",
            "CKA_UNWRAP",
            "CKA_SIGN",
            "CKA_VERIFY",
            "CKA_DERIVE",
            "CKA_EXTRACTABLE",
            "CKA_MODIFIABLE",
            "CKA_COPYABLE",
            "CKA_DESTROYABLE",
            "CKA_WRAP_WITH_TRUSTED",
        ]
    );
    let disabled: Vec<&str> = seed
        .attrs
        .iter()
        .filter(|a| !a.enabled)
        .map(|a| a.name.as_str())
        .collect();
    assert_eq!(
        disabled,
        [
            "CKA_LABEL",
            "CKA_CHECK_VALUE",
            "CKA_ID",
            "CKA_VALUE_LEN",
            "CKA_LOCAL",
            "CKA_NEVER_EXTRACTABLE",
            "CKA_ALWAYS_SENSITIVE",
            "CKA_KEY_GEN_MECHANISM",
        ]
    );
    // `-1` in an ENABLED-seeded (creation) row is refused at load
    let err = load_err("aes:\n  CKA_TOKEN: true\n  CKA_CERTIFICATE_CATEGORY: -1\n");
    assert_eq!(
        err.message,
        "template attribute CKA_CERTIFICATE_CATEGORY must not be negative"
    );
}

#[test]
fn dump_encodes_values_like_c2_encode_value() {
    // c2 `_encode_value`: bool(value), "0x"+hex (non-bytes → "0x"), str ULONG verbatim,
    // int(value), str(value)
    let template = KeyTemplate::new(vec![
        attr("CKA_TOKEN", AttrKind::Bool, AttrValue::Ulong(0)),
        attr("CKA_PRIVATE", AttrKind::Bool, AttrValue::Str("x".into())),
        attr("CKA_ID", AttrKind::Bytes, AttrValue::Str("abc".into())),
        attr(
            "CKA_VALUE_LEN",
            AttrKind::Ulong,
            AttrValue::Str("CKM_X".into()),
        ),
        attr("CKA_MODULUS_BITS", AttrKind::Ulong, AttrValue::Bool(true)),
        attr("CKA_LABEL", AttrKind::Str, AttrValue::Bool(false)),
        attr("CKA_APPLICATION", AttrKind::Str, AttrValue::Ulong(7)),
        attr("CKA_URL", AttrKind::Str, AttrValue::Bytes(b"a'".to_vec())),
        attr(
            "CKA_OBJECT_ID",
            AttrKind::Bytes,
            AttrValue::Bytes(vec![0xAB]),
        ),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpl.yaml");
    templatefile::dump_template_file(&path, "data", &template).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "data:\n  CKA_TOKEN: false\n  CKA_PRIVATE: true\n  CKA_ID: 0x\n  CKA_VALUE_LEN: CKM_X\n  \
         CKA_MODULUS_BITS: 1\n  CKA_LABEL: 'False'\n  CKA_APPLICATION: '7'\n  CKA_URL: \
         b\"a'\"\n  CKA_OBJECT_ID: '0xab'\n"
    );
    // c2 `int(b"99999999999999999999")` is a plain int; r2 has no YAML int outside
    // -2^63..=2^64-1 (§11 D17 (c)), so the row is written quoted and reloads as a mismatch
    let big = KeyTemplate::new(vec![attr(
        "CKA_VALUE_LEN",
        AttrKind::Ulong,
        AttrValue::Bytes(b"99999999999999999999".to_vec()),
    )]);
    templatefile::dump_template_file(&path, "aes", &big).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "aes:\n  CKA_VALUE_LEN: '99999999999999999999'\n"
    );
    let err = templatefile::load_seed_file(&path, &no_custom()).unwrap_err();
    assert_eq!(
        err.message,
        "CKA_VALUE_LEN expects an integer or CKO_/CKK_/CKC_/CKM_ constant"
    );
    // an empty template is an empty mapping
    templatefile::dump_template_file(&path, "aes", &KeyTemplate::default()).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "aes: {}\n");
}

#[test]
fn constants_match_c2() {
    assert_eq!(NON_CREATION_ATTRS.len(), 27);
    assert_eq!(SECRET_MATERIAL_ATTRS.len(), 7);
    for name in NON_CREATION_ATTRS
        .iter()
        .chain(SECRET_MATERIAL_ATTRS.iter())
    {
        assert!(r2_core::catalog::cka(name).is_some(), "{name}");
    }
    // secret material is also seeded disabled
    for name in SECRET_MATERIAL_ATTRS {
        assert!(NON_CREATION_ATTRS.contains(&name), "{name}");
    }
}

// ---------------------------------------------------------------------------------------
// build_seed (§5.16 seeding policy)
// ---------------------------------------------------------------------------------------

fn summary(template: &KeyTemplate) -> Vec<(String, AttrValue, bool, bool)> {
    template
        .attrs
        .iter()
        .map(|a| (a.name.clone(), a.value.clone(), a.enabled, a.locked))
        .collect()
}

fn rsa_sections() -> SeedTemplates {
    let mut sections = SeedTemplates::new();
    sections.insert("rsa_private".into(), full_rsa_private_template());
    sections
}

#[test]
fn test_build_seed_without_file_returns_defaults() {
    let templates = make_templates();
    let seed =
        templatefile::build_seed(&templates, None, KeyClass::Secret, KeyAlgorithm::Aes).unwrap();
    let default = templates
        .default_template(KeyClass::Secret, KeyAlgorithm::Aes)
        .unwrap();
    assert_eq!(summary(&seed), summary(&default));
}

#[test]
fn test_build_seed_missing_section_falls_back_to_defaults() {
    let templates = make_templates();
    let sections = rsa_sections();
    let seed = templatefile::build_seed(
        &templates,
        Some(&sections),
        KeyClass::Public,
        KeyAlgorithm::Rsa,
    )
    .unwrap();
    let default = templates
        .default_template(KeyClass::Public, KeyAlgorithm::Rsa)
        .unwrap();
    assert_eq!(names(&seed), names(&default));
    assert_eq!(summary(&seed), summary(&default));
}

#[test]
fn test_build_seed_uses_matching_section() {
    let templates = make_templates();
    let sections = rsa_sections();
    let seed = templatefile::build_seed(
        &templates,
        Some(&sections),
        KeyClass::Private,
        KeyAlgorithm::Rsa,
    )
    .unwrap();

    // The two locked rows come from the FLOW, not the file.
    let locked: Vec<(String, AttrValue)> = seed
        .attrs
        .iter()
        .filter(|a| a.locked)
        .map(|a| (a.name.clone(), a.value.clone()))
        .collect();
    assert_eq!(
        locked,
        vec![
            ("CKA_CLASS".into(), sym("CKO_PRIVATE_KEY")),
            ("CKA_KEY_TYPE".into(), sym("CKK_RSA")),
        ]
    );
    let by_name = |name: &str| seed.get(name).unwrap();
    // Identity rows present but disabled (§4.7 footgun guard).
    assert!(!by_name("CKA_LABEL").enabled);
    assert!(!by_name("CKA_ID").enabled);
    // Read-only/material attrs present but disabled.
    assert!(!by_name("CKA_MODULUS").enabled);
    assert!(!by_name("CKA_MODULUS_BITS").enabled);
    // Policy attrs enabled with the FILE values (not the config defaults).
    assert!(by_name("CKA_TOKEN").enabled);
    assert_eq!(by_name("CKA_SENSITIVE").value, AttrValue::Bool(false));
    // No config-default rows leak in beside the file rows.
    assert!(seed.get("CKA_ENCRYPT").is_none());
}

#[test]
fn flow_locked_rows_win_over_file_class_rows() {
    // a section's CKA_CLASS/CKA_KEY_TYPE entries are dropped even when they disagree
    let mut sections = SeedTemplates::new();
    sections.insert(
        "ec_private".into(),
        KeyTemplate::new(vec![
            attr("CKA_KEY_TYPE", AttrKind::Ulong, sym("CKK_RSA")),
            bool_attr("CKA_DERIVE", true),
            attr("CKA_CLASS", AttrKind::Ulong, sym("CKO_DATA")),
        ]),
    );
    let seed = templatefile::build_seed(
        &TemplatesSection {
            pkcs11: IndexMap::new(),
            pkcs11_raw: IndexMap::new(),
            custom_attributes: IndexMap::new(),
        },
        Some(&sections),
        KeyClass::Private,
        KeyAlgorithm::EcEdwards,
    )
    .unwrap();
    assert_eq!(
        summary(&seed),
        vec![
            ("CKA_CLASS".into(), sym("CKO_PRIVATE_KEY"), true, true),
            ("CKA_KEY_TYPE".into(), sym("CKK_EC_EDWARDS"), true, true),
            ("CKA_DERIVE".into(), AttrValue::Bool(true), true, false),
        ]
    );
    // certificate and data seeds carry no CKA_KEY_TYPE row
    let mut sections = SeedTemplates::new();
    sections.insert(
        "certificate".into(),
        KeyTemplate::new(vec![
            bool_attr("CKA_TRUSTED", true),
            attr("CKA_SUBJECT", AttrKind::Bytes, AttrValue::Bytes(vec![0x30])),
        ]),
    );
    let seed = templatefile::build_seed(
        &make_templates(),
        Some(&sections),
        KeyClass::Certificate,
        KeyAlgorithm::Rsa,
    )
    .unwrap();
    assert_eq!(
        summary(&seed),
        vec![
            ("CKA_CLASS".into(), sym("CKO_CERTIFICATE"), true, true),
            ("CKA_TRUSTED".into(), AttrValue::Bool(true), true, false),
            (
                "CKA_SUBJECT".into(),
                AttrValue::Bytes(vec![0x30]),
                false,
                false
            ),
        ]
    );
    // an object of an `other` key type has no class key (§4.8 error)
    let err = templatefile::build_seed(
        &make_templates(),
        Some(&sections),
        KeyClass::Secret,
        KeyAlgorithm::Other,
    )
    .unwrap_err();
    assert_eq!(
        err.message,
        "other secret objects have no template class key"
    );
}

#[test]
fn every_non_creation_attr_seeds_disabled() {
    let attrs: Vec<TemplateAttr> = NON_CREATION_ATTRS
        .iter()
        .map(|name| {
            let kind = r2_core::catalog::cka(name).unwrap().kind;
            let value = match kind {
                AttrKind::Bool => AttrValue::Bool(true),
                AttrKind::Ulong => AttrValue::Ulong(1),
                AttrKind::Bytes => AttrValue::Bytes(vec![1]),
                AttrKind::Str => AttrValue::Str("x".into()),
            };
            attr(name, kind, value)
        })
        .chain([bool_attr("CKA_COPYABLE", false)])
        .collect();
    let mut sections = SeedTemplates::new();
    sections.insert("generic_secret".into(), KeyTemplate::new(attrs));
    let seed = templatefile::build_seed(
        &make_templates(),
        Some(&sections),
        KeyClass::Secret,
        KeyAlgorithm::Generic,
    )
    .unwrap();
    assert_eq!(seed.attrs.len(), 2 + 27 + 1);
    for row in &seed.attrs[2..29] {
        assert!(!row.enabled && !row.locked, "{}", row.name);
    }
    assert!(seed.attrs[29].enabled);
}

#[test]
fn test_build_seed_returns_fresh_attr_objects() {
    let templates = make_templates();
    let sections = rsa_sections();
    let mut seed_a = templatefile::build_seed(
        &templates,
        Some(&sections),
        KeyClass::Private,
        KeyAlgorithm::Rsa,
    )
    .unwrap();
    let seed_b = templatefile::build_seed(
        &templates,
        Some(&sections),
        KeyClass::Private,
        KeyAlgorithm::Rsa,
    )
    .unwrap();
    seed_a.set("CKA_TOKEN", AttrValue::Bool(false)).unwrap();
    assert_eq!(
        seed_b.get("CKA_TOKEN").unwrap().value,
        AttrValue::Bool(true)
    );
    let source = sections["rsa_private"].get("CKA_TOKEN").unwrap();
    assert_eq!(source.value, AttrValue::Bool(true));
}

#[test]
fn editor_seeding_opens_the_editor_with_the_seed() {
    let templates = make_templates();
    let sections = rsa_sections();
    let editor = RecordingEditor::new();
    let seeding = EditorSeeding {
        editor: &editor,
        templates: &templates,
        seeds: Some(&sections),
    };
    let edited = seeding
        .edit(KeyClass::Private, KeyAlgorithm::Rsa, "title")
        .unwrap();
    assert_eq!(editor.titles(), ["title"]);
    assert_eq!(
        edited,
        templatefile::build_seed(
            &templates,
            Some(&sections),
            KeyClass::Private,
            KeyAlgorithm::Rsa
        )
        .unwrap()
    );
}

// ---------------------------------------------------------------------------------------
// --template seeding through the create flows (c2 test_keyload / test_wrapload /
// test_transfer cases)
// ---------------------------------------------------------------------------------------

fn hsm() -> FakeProvider {
    FakeProvider::new("hsm").with_type_name("pkcs11")
}

#[test]
fn test_import_seed_template_section_replaces_defaults() {
    let provider = hsm();
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let mut sections = SeedTemplates::new();
    sections.insert(
        "aes".into(),
        KeyTemplate::new(vec![
            bool_attr("CKA_SENSITIVE", false),
            bool_attr("CKA_EXTRACTABLE", true),
        ]),
    );
    let seeding = EditorSeeding {
        editor: &editor,
        templates: &templates,
        seeds: Some(&sections),
    };
    let infos =
        keyload::import_materials(&provider, &[aes16_material(None)], "k", None, &seeding).unwrap();
    let seed = &editor.templates()[0];
    assert_eq!(
        names(seed),
        [
            "CKA_CLASS",
            "CKA_KEY_TYPE",
            "CKA_SENSITIVE",
            "CKA_EXTRACTABLE"
        ]
    );
    // File values (not the §7 sensitive/non-extractable defaults) reached import_key.
    assert!(infos[0].exportable);
}

#[test]
fn test_import_pkcs12_picks_section_per_material() {
    let password = SecretString::from("pw".to_owned());
    let p12 = build_pkcs12(&rsa_pkcs8_der(), &rsa_cert_der(), "bundle", &password, &[]).unwrap();
    let materials = keyload::parse_materials(
        &p12,
        "auto",
        Some(&password),
        &ScriptedIo::new(Vec::<String>::new()),
    )
    .unwrap();
    let provider = hsm();
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let mut sections = SeedTemplates::new();
    sections.insert(
        "rsa_private".into(),
        KeyTemplate::new(vec![bool_attr("CKA_SIGN", true)]),
    );
    let seeding = EditorSeeding {
        editor: &editor,
        templates: &templates,
        seeds: Some(&sections),
    };
    keyload::import_materials(&provider, &materials, "bundle", None, &seeding).unwrap();
    let seeds = editor.templates();
    assert_eq!(seeds.len(), 2); // private then certificate (§5.4)
    assert_eq!(names(&seeds[0]), ["CKA_CLASS", "CKA_KEY_TYPE", "CKA_SIGN"]);
    let cert_names = names(&seeds[1]); // no section → §7 defaults
    assert!(!cert_names.contains(&"CKA_SIGN".to_owned()));
    assert!(cert_names.contains(&"CKA_TOKEN".to_owned()));
}

#[test]
fn test_load_wrapped_seed_templates_reach_the_editor() {
    use r2_core::params::Params;
    use r2_services::wrapload::{self, UnwrapJob};

    let provider = hsm();
    let mut kek_material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![0x01; 32]);
    kek_material.size_bits = Some(256);
    let kek = provider
        .import_key(&kek_material, "aeskek", None, None)
        .unwrap();
    let entry = wrapload::wrap_mechs()
        .into_iter()
        .find(|e| e.spec.cli_name == "kwp")
        .unwrap();
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let mut sections = SeedTemplates::new();
    sections.insert(
        "aes".into(),
        KeyTemplate::new(vec![bool_attr("CKA_DECRYPT", true)]),
    );
    let seeding = EditorSeeding {
        editor: &editor,
        templates: &templates,
        seeds: Some(&sections),
    };
    let wrapped = [0u8; 40];
    // c2 calls load_wrapped outside `pytest.raises`: the unwrap itself must succeed
    wrapload::load_wrapped(
        &provider,
        UnwrapJob {
            kek: &kek,
            entry: &entry,
            params: Params::new(),
            wrapped: &wrapped,
            result_algorithm: KeyAlgorithm::Aes,
            result_class: KeyClass::Secret,
            label: "unwrapped".into(),
            key_id: None,
        },
        &seeding,
    )
    .expect("load_wrapped succeeds on FakeProvider like c2");
    let seen = editor.templates();
    let names = names(&seen[0]);
    assert_eq!(names[..2], ["CKA_CLASS", "CKA_KEY_TYPE"]); // flow-locked rows (§5.16)
    assert!(names.contains(&"CKA_DECRYPT".to_owned()));
}

fn policy_template(sensitive: bool, extractable: bool) -> KeyTemplate {
    KeyTemplate::new(vec![
        bool_attr("CKA_SENSITIVE", sensitive),
        bool_attr("CKA_EXTRACTABLE", extractable),
    ])
}

fn empty_templates() -> TemplatesSection {
    TemplatesSection {
        pkcs11: IndexMap::new(),
        pkcs11_raw: IndexMap::new(),
        custom_attributes: IndexMap::new(),
    }
}

/// c2 test_transfer's wrap-route copy: a sensitive+extractable AES key between two HSMs.
fn transfer_copy(sections: &SeedTemplates) -> Vec<KeyTemplate> {
    use r2_services::transfer::copy_key;
    let src = FakeProvider::new("srchsm").with_type_name("pkcs11");
    let dst = FakeProvider::new("dsthsm").with_type_name("pkcs11");
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![0x5a; 32]);
    material.size_bits = Some(256);
    let key = src
        .import_key(
            &material,
            "aeskey",
            Some(&policy_template(true, true)),
            None,
        )
        .unwrap();
    let editor = RecordingEditor::new();
    let templates = empty_templates();
    let seeding = EditorSeeding {
        editor: &editor,
        templates: &templates,
        seeds: Some(sections),
    };
    copy_key(
        &src,
        &key,
        &dst,
        &ScriptedIo::new(Vec::<String>::new()),
        &seeding,
        None,
        None,
    )
    .unwrap();
    editor.templates()
}

#[test]
fn test_wrap_route_editor_seeded_from_matching_section() {
    let mut sections = SeedTemplates::new();
    sections.insert("aes".into(), policy_template(false, true));
    let calls = transfer_copy(&sections);
    let seed = calls.last().unwrap();
    assert_eq!(
        names(seed),
        [
            "CKA_CLASS",
            "CKA_KEY_TYPE",
            "CKA_SENSITIVE",
            "CKA_EXTRACTABLE"
        ]
    );
    let sensitive = seed.get("CKA_SENSITIVE").unwrap();
    assert_eq!(sensitive.value, AttrValue::Bool(false));
    assert!(sensitive.enabled);
}

#[test]
fn test_wrap_route_missing_section_falls_back_to_defaults() {
    let mut sections = SeedTemplates::new();
    sections.insert("rsa_private".into(), policy_template(true, false));
    let calls = transfer_copy(&sections);
    // empty TemplatesSection → the default seed is just the two locked rows
    assert_eq!(names(calls.last().unwrap()), ["CKA_CLASS", "CKA_KEY_TYPE"]);
}

#[test]
fn seeding_helpers_compile_against_the_frozen_surface() {
    // keep the Provider import used when the ignored cases are compiled out of a run
    let provider = hsm();
    assert_eq!(provider.type_name(), "pkcs11");
}

#[test]
fn nel_is_a_line_break_and_quoted_continuations_must_be_indented() {
    // §11 D17 (f): NEL is normalized to `\n` before parsing, so it loads like PyYAML
    // wherever a line break would …
    let sections = load_text("aes:\u{85}  CKA_TOKEN: true\u{85}").unwrap();
    assert_eq!(
        rows(&sections["aes"]),
        vec![("CKA_TOKEN".into(), AttrKind::Bool, AttrValue::Bool(true))]
    );
    // … but inside a quoted scalar the continuation line it starts must be indented per
    // YAML 1.2 (D17 (b)); PyYAML folded it (c2: CKA_LABEL='a b')
    let err = load_err("aes:\n  CKA_LABEL: \"a\u{85}b\"\n");
    assert_eq!(param_name(&err), "template");
    assert!(
        err.message
            .ends_with("invalid indentation in quoted scalar at byte 18 line 2 column 14"),
        "{}",
        err.message
    );
}
