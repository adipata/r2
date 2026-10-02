// Console behaviour for the generic-secret / data / other / certificate object kinds —
// port of the R8 cases of c2 tests/unit/console/test_keys_cmd_objects.py (`keys` rows,
// `generate … generic`, `load … generic|data`, `key info/edit` on data objects, raw data
// export and delete; the copy / ops / sign / verify cases are R9's and R10's).
use r2_core::error::ErrorKind;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::template::AttrValue;
use r2_provider::{KeySelector, Provider};

use super::keys_cmd_support::*;
use crate::commands::all_commands;
use crate::testing::run_line;

const VALUE: &[u8] = b"Hello, data!";

fn data_material() -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, VALUE.to_vec())
}

fn generic_material() -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, (0u8..32).collect())
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn find(provider: &dyn Provider, label: &str) -> r2_core::keys::KeyInfo {
    provider.find_key(&KeySelector::label(label)).unwrap()
}

fn complete(p: &Pair, command: &str, tokens: &[&str], cursor: &str) -> Vec<String> {
    let commands = all_commands().unwrap();
    let tokens: Vec<String> = tokens.iter().map(|t| (*t).to_owned()).collect();
    commands[command].complete(&p.ctx, &tokens, cursor)
}

// ---------------------------------------------------------------------------------------
// keys / key info
// ---------------------------------------------------------------------------------------

#[test]
fn test_keys_lists_every_object_kind() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&generic_material(), "mac", None, None)
        .unwrap();
    p.mem
        .import_key(&data_material(), "note", None, None)
        .unwrap();
    p.hsm
        .import_key(&cert_material(), "trust", None, None)
        .unwrap();
    // an unmodelled key type on the token (sanctioned backdoor)
    p.hsm.store_key_unchecked(
        &KeyMaterial::new(KeyAlgorithm::Other, KeyClass::Secret, vec![b'k'; 24]),
        "des3",
        None,
        Some(&[0x01]),
    );
    run_line(&p.ctx, "keys").unwrap();
    let text = p.io.text();
    let rows: Vec<&str> = text.lines().filter(|line| line.contains(':')).collect();
    let mac_row = rows.iter().find(|line| line.contains("mem:mac")).unwrap();
    assert!(mac_row.contains("secret") && mac_row.contains("generic") && mac_row.contains("256"));
    let note_row = rows.iter().find(|line| line.contains("mem:note")).unwrap();
    assert!(note_row.contains("data") && note_row.contains(" - "));
    assert!(note_row.contains(&(VALUE.len() * 8).to_string()));
    assert!(
        rows.iter()
            .find(|l| l.contains("hsm:trust"))
            .unwrap()
            .contains("cert")
    );
    assert!(
        rows.iter()
            .find(|l| l.contains("hsm:des3"))
            .unwrap()
            .contains("other")
    );
}

#[test]
fn test_key_info_data_object() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&data_material(), "note", None, None)
        .unwrap();
    run_line(&p.ctx, "key info mem:note").unwrap();
    let text = p.io.text();
    assert!(text.contains("data"));
    // the algorithm cell is "-" (c2 asserted " - " in rich's padded layout; r2 trims
    // trailing blanks, §11 D1)
    let row = text
        .lines()
        .find(|l| l.trim_start().starts_with("algorithm"))
        .unwrap();
    assert!(row.ends_with(" -"), "{row}");
    run_line(&p.ctx, "key info mem:note:data").unwrap(); // the §4.3 selector
    assert!(p.io.text().matches("mem:note").count() >= 2);
}

// ---------------------------------------------------------------------------------------
// generate generic
// ---------------------------------------------------------------------------------------

#[test]
fn test_generate_generic_inline_and_default_size() {
    let p = make_pair(&[]);
    run_line(&p.ctx, "generate mem generic size=512 --label mac").unwrap();
    assert_eq!(
        p.io.output().last().unwrap(),
        "generated mem:mac (512-bit generic)"
    );
    let info = find(p.mem.as_ref(), "mac");
    assert_eq!(
        (info.key_class, info.algorithm, info.size_bits),
        (KeyClass::Secret, KeyAlgorithm::Generic, Some(512))
    );
    run_line(&p.ctx, "generate mem generic --label mac2").unwrap(); // defaults to 256
    assert_eq!(find(p.mem.as_ref(), "mac2").size_bits, Some(256));
    assert!(p.io.prompts().is_empty());
    let err = run_line(&p.ctx, "generate mem generic size=12 --label bad").unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "size".into()
        }
    );
    assert_eq!(
        err.message,
        "invalid generic secret size 12; expected a multiple of 8 between 8 and 8192 bits"
    );
    for bad in ["0", "8200", "-8"] {
        let err = run_line(
            &p.ctx,
            &format!("generate mem generic size={bad} --label bad"),
        )
        .unwrap_err();
        assert_eq!(
            err.kind,
            ErrorKind::Param {
                param_name: "size".into()
            }
        );
    }
    let err = run_line(&p.ctx, "generate mem generic size=big --label bad").unwrap_err();
    assert_eq!(err.message, "size: invalid integer 'big'");
}

#[test]
fn test_generate_generic_on_pkcs11_opens_one_secret_editor() {
    let p = make_pair(&[]);
    run_line(&p.ctx, "generate hsm generic --label mac").unwrap();
    assert_eq!(
        p.editor.titles(),
        ["PKCS#11 template — generic secret key 'mac'"]
    );
    let template = &p.editor.seeds()[0];
    assert_eq!(
        template.get("CKA_CLASS").unwrap().value,
        AttrValue::Symbol("CKO_SECRET_KEY".into())
    );
    assert_eq!(
        template.get("CKA_KEY_TYPE").unwrap().value,
        AttrValue::Symbol("CKK_GENERIC_SECRET".into())
    );
    assert_eq!(find(p.hsm.as_ref(), "mac").algorithm, KeyAlgorithm::Generic);
}

#[test]
fn test_generate_completion_offers_generic() {
    let p = make_pair(&[]);
    assert!(complete(&p, "generate", &["generate", "mem", "g"], "g").contains(&"generic".into()));
    let sizes = complete(&p, "generate", &["generate", "mem", "generic", "s"], "s");
    for size in ["size=128", "size=256", "size=512"] {
        assert!(sizes.contains(&size.to_owned()), "{size}");
    }
}

// ---------------------------------------------------------------------------------------
// load generic / data
// ---------------------------------------------------------------------------------------

#[test]
fn test_load_generic_and_data_inline() {
    let p = make_pair(&[]);
    run_line(
        &p.ctx,
        "load mem generic 00112233445566778899aabbccddeeff --label mac",
    )
    .unwrap();
    assert_eq!(find(p.mem.as_ref(), "mac").algorithm, KeyAlgorithm::Generic);
    assert!(p.io.text().contains("generic"));
    run_line(
        &p.ctx,
        &format!("load mem data {} --label note", hex(VALUE)),
    )
    .unwrap();
    let info = find(p.mem.as_ref(), "note");
    assert_eq!(info.key_class, KeyClass::Data);
    assert!(info.key_ref.key_id.is_none());
    assert_eq!(p.mem.export_key(&info).unwrap().data.as_slice(), VALUE);
    assert!(p.io.text().contains("data"));
    // data objects carry no CKA_ID (§4.3)
    let err = run_line(&p.ctx, "load mem data 00 --label note2 --id 0a").unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
}

#[test]
fn test_load_data_from_file_is_verbatim() {
    let p = make_pair(&[]);
    let blob = b"-----BEGIN CERTIFICATE-----\nnot really\n-----END CERTIFICATE-----\n\x00\xff";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blob.bin");
    std::fs::write(&path, blob).unwrap();
    run_line(
        &p.ctx,
        &format!(
            "load mem --file {} --format data --label blob",
            path.display()
        ),
    )
    .unwrap();
    let info = find(p.mem.as_ref(), "blob");
    assert_eq!(p.mem.export_key(&info).unwrap().data.as_slice(), &blob[..]);
}

#[test]
fn test_load_data_into_pkcs11_opens_data_editor() {
    let p = make_pair(&[]);
    run_line(
        &p.ctx,
        &format!("load hsm data {} --label note", hex(VALUE)),
    )
    .unwrap();
    assert_eq!(p.editor.titles(), ["PKCS#11 template — data 'note'"]);
    assert_eq!(find(p.hsm.as_ref(), "note").key_class, KeyClass::Data);
}

#[test]
fn test_load_completion_offers_new_hints() {
    let p = make_pair(&[]);
    let hints = complete(&p, "load", &["load", "mem", "g"], "g");
    for hint in ["generic", "data", "cert", "auto"] {
        assert!(hints.contains(&hint.to_owned()), "{hint}");
    }
    assert!(complete(&p, "load", &["load", "mem", "--format", "d"], "d").contains(&"data".into()));
}

// ---------------------------------------------------------------------------------------
// edit / export / delete on data objects
// ---------------------------------------------------------------------------------------

#[test]
fn test_key_edit_data_prompts_label_only() {
    let p = make_pair(&["renamed"]); // exactly one answer: no id prompt may follow
    p.mem
        .import_key(&data_material(), "note", None, None)
        .unwrap();
    run_line(&p.ctx, "key edit mem:note").unwrap();
    assert_eq!(find(p.mem.as_ref(), "renamed").key_class, KeyClass::Data);
    assert_eq!(p.io.prompts(), ["New label (empty = keep 'note')"]);
    let err = run_line(&p.ctx, "key edit mem:renamed --id 0a").unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
}

#[test]
fn test_export_data_raw_and_format_refusal() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&data_material(), "note", None, None)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("note.bin");
    run_line(&p.ctx, &format!("export mem:note {}", out.display())).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), VALUE);
    let err = run_line(
        &p.ctx,
        &format!("export mem:note {} --format pem", out.display()),
    )
    .unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
}

#[test]
fn test_delete_data_object() {
    let p = make_pair(&["y"]);
    p.mem
        .import_key(&data_material(), "note", None, None)
        .unwrap();
    run_line(&p.ctx, "delete mem:note").unwrap();
    assert!(
        !p.mem
            .list_keys()
            .unwrap()
            .iter()
            .any(|k| k.key_ref.label == "note")
    );
    assert_eq!(p.io.prompts(), ["delete mem:note (data)?"]);
}
