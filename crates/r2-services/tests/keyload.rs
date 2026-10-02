// services::keyload — port of c2 tests/unit/services/test_keyload.py (R8) plus the keyload
// cases of test_objects_services.py. FakeProvider + ScriptedIo only (spec §4.10); fixtures
// are generated at test time.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod keyload_fixtures;

use keyload_fixtures::*;
use r2_core::error::ErrorKind;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate};
use r2_core::x509build::build_pkcs12;
use r2_provider::Provider;
use r2_services::keyload;
use r2_services::templatefile::EditorSeeding;
use r2_testkit::{FakeProvider, RecordingEditor, ScriptedIo};
use secrecy::SecretString;

fn secret(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

fn seeding<'a>(
    editor: &'a RecordingEditor,
    templates: &'a r2_config::model::TemplatesSection,
) -> EditorSeeding<'a> {
    EditorSeeding {
        editor,
        templates,
        seeds: None,
    }
}

fn p12_bundle() -> Vec<u8> {
    build_pkcs12(
        &rsa_pkcs8_der(),
        &rsa_cert_der(),
        "bundle",
        &secret("pw"),
        &[],
    )
    .unwrap()
}

#[test]
fn test_read_key_file_missing_path_raises_dataioerror() {
    let dir = tempfile::tempdir().unwrap();
    let err = keyload::read_key_file(&dir.path().join("absent.pem")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::DataIo);
    assert!(err.message.contains("cannot read"), "{}", err.message);
    assert!(
        err.message
            .ends_with("absent.pem: No such file or directory")
    );
}

#[test]
fn read_key_file_returns_the_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k.bin");
    std::fs::write(&path, b"\x00\x01").unwrap();
    assert_eq!(
        keyload::read_key_file(&path).unwrap().as_slice(),
        b"\x00\x01"
    );
}

#[test]
fn test_parse_materials_raw_aes() {
    let materials = keyload::parse_materials(&AES_16, "aes", None, &ScriptedIo::empty()).unwrap();
    assert_eq!(materials.len(), 1);
    assert_eq!(materials[0].key_class, KeyClass::Secret);
    assert_eq!(materials[0].algorithm, KeyAlgorithm::Aes);
    assert_eq!(materials[0].data.as_slice(), &AES_16);
}

#[test]
fn test_parse_materials_pem_private_key() {
    let materials =
        keyload::parse_materials(&rsa_private_pem(), "rsa", None, &ScriptedIo::empty()).unwrap();
    let classes: Vec<KeyClass> = materials.iter().map(|m| m.key_class).collect();
    assert_eq!(classes, [KeyClass::Private]);
    assert_eq!(materials[0].algorithm, KeyAlgorithm::Rsa);
}

#[test]
fn test_parse_materials_hint_mismatch() {
    let err = keyload::parse_materials(&rsa_private_pem(), "aes", None, &ScriptedIo::empty())
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(err.message.contains("hint"), "{}", err.message);
}

#[test]
fn test_parse_materials_encrypted_pem_prompts_password_once() {
    let pem = rsa_encrypted_pem("hunter2");
    let io = ScriptedIo::new(["hunter2"]);
    let materials = keyload::parse_materials(&pem, "rsa", None, &io).unwrap();
    assert_eq!(materials[0].key_class, KeyClass::Private);
    assert_eq!(io.prompts().len(), 1); // prompt_secret used exactly once
    assert_eq!(
        io.prompts(),
        ["Password for encrypted ENCRYPTED PRIVATE KEY"]
    );
}

#[test]
fn test_parse_materials_explicit_password_never_prompts() {
    let pem = rsa_encrypted_pem("hunter2");
    let io = ScriptedIo::empty(); // empty queue — any prompt would panic
    let materials = keyload::parse_materials(&pem, "rsa", Some(&secret("hunter2")), &io).unwrap();
    assert_eq!(materials[0].key_class, KeyClass::Private);
}

#[test]
fn test_parse_materials_wrong_password() {
    let pem = rsa_encrypted_pem("hunter2");
    let err = keyload::parse_materials(&pem, "rsa", Some(&secret("wrong")), &ScriptedIo::empty())
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(err.message.contains("password"), "{}", err.message);
}

#[test]
fn parse_materials_unknown_hint_is_keyparse() {
    let err = keyload::parse_materials(&AES_16, "dsa", None, &ScriptedIo::empty()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert_eq!(err.message, "unknown key material hint 'dsa'");
}

// ---------------------------------------------------------------------------------------
// resolve_label
// ---------------------------------------------------------------------------------------

#[test]
fn test_resolve_label_explicit_wins_over_hint() {
    let label = keyload::resolve_label(
        &[aes16_material(Some("hinted"))],
        Some("given"),
        &ScriptedIo::empty(),
    )
    .unwrap();
    assert_eq!(label, "given");
}

#[test]
fn test_resolve_label_uses_material_hint() {
    let label = keyload::resolve_label(
        &[aes16_material(Some("hinted"))],
        None,
        &ScriptedIo::empty(),
    )
    .unwrap();
    assert_eq!(label, "hinted");
}

#[test]
fn resolve_label_skips_empty_hints_and_trims_explicit_labels() {
    let materials = [aes16_material(Some("")), aes16_material(Some("second"))];
    assert_eq!(
        keyload::resolve_label(&materials, None, &ScriptedIo::empty()).unwrap(),
        "second"
    );
    assert_eq!(
        keyload::resolve_label(&materials, Some("  padded \u{1f}"), &ScriptedIo::empty()).unwrap(),
        "padded"
    );
}

#[test]
fn test_resolve_label_prompts_when_nothing_known() {
    let io = ScriptedIo::new(["typed-label"]);
    assert_eq!(
        keyload::resolve_label(&[aes16_material(None)], None, &io).unwrap(),
        "typed-label"
    );
    assert_eq!(io.prompts(), ["Key label"]);
}

#[test]
fn test_resolve_label_rejects_empty() {
    for bad in ["", "   "] {
        let err = keyload::resolve_label(&[aes16_material(None)], Some(bad), &ScriptedIo::empty())
            .unwrap_err();
        assert_eq!(
            err.kind,
            ErrorKind::Param {
                param_name: "label".into()
            }
        );
        assert_eq!(err.message, "label must not be empty");
    }
    // the prompted answer follows the same rule
    let err = keyload::resolve_label(&[aes16_material(None)], None, &ScriptedIo::new(["  "]))
        .unwrap_err();
    assert_eq!(err.message, "label must not be empty");
}

// ---------------------------------------------------------------------------------------
// import_materials
// ---------------------------------------------------------------------------------------

#[test]
fn test_import_into_memory_skips_template_editor() {
    let provider = FakeProvider::new("mem");
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let infos = keyload::import_materials(
        &provider,
        &[aes16_material(None)],
        "k",
        None,
        &seeding(&editor, &templates),
    )
    .unwrap();
    assert!(editor.titles().is_empty()); // §5.12: editor only for PKCS#11 targets
    let refs: Vec<String> = infos.iter().map(|i| i.key_ref.display()).collect();
    assert_eq!(refs, ["mem:k"]);
}

#[test]
fn test_import_into_pkcs11_opens_editor_and_applies_template() {
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let infos = keyload::import_materials(
        &provider,
        &[aes16_material(None)],
        "k",
        None,
        &seeding(&editor, &templates),
    )
    .unwrap();
    let titles = editor.titles();
    assert_eq!(titles.len(), 1);
    assert!(titles[0].contains("aes") && titles[0].contains("'k'"));
    assert_eq!(titles[0], "PKCS#11 template — aes secret 'k'");
    // default aes template: CKA_SENSITIVE=true, CKA_EXTRACTABLE=false → not exportable,
    // proving the edited template reached import_key.
    assert!(!infos[0].exportable);
    assert_eq!(
        infos[0].attributes.get("CKA_SENSITIVE"),
        Some(&AttrValue::Bool(true))
    );
}

#[test]
fn test_import_editor_result_wins() {
    // The template returned by the editor (not the seed) is what gets imported.
    let editor = RecordingEditor::with(|mut template: KeyTemplate| {
        assert!(template.get("CKA_SENSITIVE").is_some()); // seeded from config
        template.set("CKA_SENSITIVE", AttrValue::Bool(false))?;
        template.set("CKA_EXTRACTABLE", AttrValue::Bool(true))?;
        Ok(template)
    });
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    let templates = make_templates();
    let infos = keyload::import_materials(
        &provider,
        &[aes16_material(None)],
        "k",
        None,
        &seeding(&editor, &templates),
    )
    .unwrap();
    assert!(infos[0].exportable);
}

#[test]
fn test_import_pkcs12_members_share_generated_key_id() {
    // §5.4: PKCS#12 private + certificate land under ONE label and CKA_ID.
    let materials = keyload::parse_materials(
        &p12_bundle(),
        "auto",
        Some(&secret("pw")),
        &ScriptedIo::empty(),
    )
    .unwrap();
    let classes: Vec<KeyClass> = materials.iter().map(|m| m.key_class).collect();
    assert_eq!(classes, [KeyClass::Private, KeyClass::Certificate]);

    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let infos = keyload::import_materials(
        &provider,
        &materials,
        "bundle",
        None,
        &seeding(&editor, &templates),
    )
    .unwrap();
    assert_eq!(infos.len(), 2);
    assert_eq!(editor.titles().len(), 2); // one editor per material
    assert!(infos[0].key_ref.key_id.is_some());
    assert_eq!(infos[0].key_ref.key_id.as_ref().unwrap().len(), 4);
    assert_eq!(infos[0].key_ref.key_id, infos[1].key_ref.key_id);
    assert!(infos.iter().all(|i| i.key_ref.label == "bundle"));
}

#[test]
fn memory_pkcs12_import_keeps_no_key_id() {
    let materials = keyload::parse_materials(
        &p12_bundle(),
        "auto",
        Some(&secret("pw")),
        &ScriptedIo::empty(),
    )
    .unwrap();
    let provider = FakeProvider::new("mem");
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let infos = keyload::import_materials(
        &provider,
        &materials,
        "bundle",
        None,
        &seeding(&editor, &templates),
    )
    .unwrap();
    assert!(infos.iter().all(|i| i.key_ref.key_id.is_none()));
    assert!(editor.titles().is_empty());
}

#[test]
fn test_import_explicit_key_id_is_used_verbatim() {
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let infos = keyload::import_materials(
        &provider,
        &[aes16_material(None)],
        "k",
        Some(&[0x0a, 0x1b]),
        &seeding(&editor, &templates),
    )
    .unwrap();
    assert_eq!(infos[0].key_ref.key_id.as_deref(), Some(&[0x0a, 0x1b][..]));
}

#[test]
fn test_import_records_template_in_provider_calls() {
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    let editor = RecordingEditor::new();
    let templates = make_templates();
    keyload::import_materials(
        &provider,
        &[aes16_material(None)],
        "k",
        None,
        &seeding(&editor, &templates),
    )
    .unwrap();
    let import_calls: Vec<Vec<String>> = provider
        .calls()
        .into_iter()
        .filter(|c| c[0] == "import_key")
        .collect();
    assert_eq!(import_calls.len(), 1);
    assert!(import_calls[0][3].starts_with("template(")); // a KeyTemplate was passed
}

#[test]
fn test_pkcs8_der_material_parses_and_imports() {
    let materials =
        keyload::parse_materials(&rsa_pkcs8_der(), "auto", None, &ScriptedIo::empty()).unwrap();
    let provider = FakeProvider::new("mem");
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let infos = keyload::import_materials(
        &provider,
        &materials,
        "rsa1",
        None,
        &seeding(&editor, &templates),
    )
    .unwrap();
    assert_eq!(infos[0].key_class, KeyClass::Private);
    assert_eq!(infos[0].algorithm, KeyAlgorithm::Rsa);
}

#[test]
fn test_make_templates_helper_yields_default_template() {
    let templates = make_templates();
    let template = templates
        .default_template(KeyClass::Secret, KeyAlgorithm::Aes)
        .unwrap();
    let locked: Vec<&str> = template
        .attrs
        .iter()
        .filter(|a| a.locked)
        .map(|a| a.name.as_str())
        .collect();
    assert_eq!(locked, ["CKA_CLASS", "CKA_KEY_TYPE"]);
    let token = template.get("CKA_TOKEN").unwrap();
    assert_eq!(token.kind, AttrKind::Bool);
}

#[test]
fn import_errors_stop_at_the_failing_material() {
    // the editor's UserAbort (cancel) propagates unchanged and nothing is imported
    let editor = RecordingEditor::with(|_| {
        Err(r2_core::ConsoleError::user_abort("template edit cancelled"))
    });
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    let templates = make_templates();
    let err = keyload::import_materials(
        &provider,
        &[aes16_material(None)],
        "k",
        None,
        &seeding(&editor, &templates),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert!(provider.list_keys().unwrap().is_empty());
}

// ---------------------------------------------------------------------------------------
// verbatim generic / data hints (test_objects_services.py)
// ---------------------------------------------------------------------------------------

const VALUE: &[u8] = b"opaque bytes \x00\x01\x02 -- not a key";

#[test]
fn test_generic_and_data_hints_are_verbatim() {
    assert!(keyload::VALID_HINTS.contains(&"generic") && keyload::VALID_HINTS.contains(&"data"));
    assert_eq!(
        keyload::verbatim_hint("generic"),
        Some((KeyAlgorithm::Generic, KeyClass::Secret))
    );
    assert_eq!(
        keyload::verbatim_hint("data"),
        Some((KeyAlgorithm::None, KeyClass::Data))
    );
    assert_eq!(keyload::verbatim_hint("aes"), None);
    let generic =
        keyload::parse_materials(b"\x01\x02\x03", "generic", None, &ScriptedIo::empty()).unwrap();
    assert_eq!(generic.len(), 1);
    assert_eq!(
        (
            generic[0].algorithm,
            generic[0].key_class,
            generic[0].data.as_slice(),
            generic[0].size_bits
        ),
        (
            KeyAlgorithm::Generic,
            KeyClass::Secret,
            &b"\x01\x02\x03"[..],
            Some(24)
        )
    );
    let pem_looking = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    let data = keyload::parse_materials(pem_looking, "data", None, &ScriptedIo::empty()).unwrap();
    assert_eq!(
        (
            data[0].algorithm,
            data[0].key_class,
            data[0].data.as_slice()
        ),
        (KeyAlgorithm::None, KeyClass::Data, &pem_looking[..]) // never sniffed
    );
    let err = keyload::parse_materials(b"", "data", None, &ScriptedIo::empty()).unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "data".into()
        }
    );
    assert_eq!(err.message, "data material must not be empty");
    let err = keyload::parse_materials(b"", "generic", None, &ScriptedIo::empty()).unwrap_err();
    assert_eq!(err.message, "generic material must not be empty");
}

#[test]
fn test_editor_titles_and_data_import() {
    let data = KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, VALUE.to_vec());
    assert_eq!(
        keyload::editor_title(&data, "n"),
        "PKCS#11 template — data 'n'"
    );
    let generic = KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, vec![1]);
    assert_eq!(
        keyload::editor_title(&generic, "n"),
        "PKCS#11 template — generic secret 'n'"
    );
    let hsm = FakeProvider::new("hsm").with_type_name("pkcs11");
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let infos =
        keyload::import_materials(&hsm, &[data], "blob", None, &seeding(&editor, &templates))
            .unwrap();
    assert_eq!(editor.titles(), ["PKCS#11 template — data 'blob'"]);
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].key_class, KeyClass::Data);
    assert!(infos[0].key_ref.key_id.is_none());
}
