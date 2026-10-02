// `key template` and `--template` seeding (spec §5.16; R14) — port of the template-file
// cases of c2 tests/unit/console/test_keys_cmd.py and test_copy_cmd.py, plus r2 checks the
// spec requires (usage texts, auth-first order, class-key refusal, path normalization).
// FakeProvider + ScriptedIo + SpyEditor throughout (spec §4.10).
use std::path::Path;
use std::rc::Rc;

use r2_config::yaml::{self, Value};
use r2_core::error::{ConsoleError, ErrorKind};
use r2_core::io::{ConsoleIo, TemplateEditor};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_provider::{KeySelector, Provider, ProviderRegistry};
use r2_testkit::{FakeHooks, FakeProvider, ScriptedIo};

use super::keys_cmd_support::*;
use crate::commands::all_commands;
use crate::commands::key_template::KEY_USAGE;
use crate::testing::{CtxBuilder, run_line};

fn find(provider: &dyn Provider, label: &str) -> KeyInfo {
    provider.find_key(&KeySelector::label(label)).unwrap()
}

fn section(path: &Path, class_key: &str) -> Value {
    let raw = yaml::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
    raw[class_key].clone()
}

fn kind_is(err: &ConsoleError, expected: &str) -> bool {
    match (&err.kind, expected) {
        (ErrorKind::Param { .. }, "param") => true,
        (ErrorKind::UnsupportedOperation, "unsupported") => true,
        (kind, _) => panic!("unexpected kind {kind:?}: {}", err.message),
    }
}

fn aes16_material() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![0x02; 16]);
    material.size_bits = Some(128);
    material
}

// ---------------------------------------------------------------------------------------
// key template (c2 test_keys_cmd.py)
// ---------------------------------------------------------------------------------------

#[test]
fn test_key_template_rejects_memory_provider() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "aeskey", None, None)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpl.yaml");
    let err = run_line(
        &p.ctx,
        &format!("key template mem:aeskey {}", path.display()),
    )
    .unwrap_err();
    assert!(kind_is(&err, "unsupported"));
    assert_eq!(
        err.message,
        "key template works only with PKCS#11 providers"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("mem keys have no PKCS#11 attribute template")
    );
    assert!(!path.exists());
    assert!(calls_of(&p.mem, "read_full_template").is_empty());
}

#[test]
fn test_key_template_dumps_class_keyed_file() {
    let p = make_pair(&[]);
    p.hsm
        .import_key(&aes_material(), "k", None, Some(&[0x0a, 0x1b]))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpl.yaml");
    run_line(&p.ctx, &format!("key template hsm:k {}", path.display())).unwrap();
    let section = section(&path, "aes");
    assert_eq!(section["CKA_CLASS"], Value::String("CKO_SECRET_KEY".into()));
    assert_eq!(section["CKA_KEY_TYPE"], Value::String("CKK_AES".into()));
    assert_eq!(section["CKA_LABEL"], Value::String("k".into()));
    assert_eq!(section["CKA_ID"], Value::String("0x0a1b".into()));
    // §5.5 flag pair
    assert!(section.get("CKA_SENSITIVE").is_some() && section.get("CKA_EXTRACTABLE").is_some());
    let output = p.io.output();
    assert!(
        output
            .iter()
            .any(|line| line.contains("wrote aes template")),
        "{output:?}"
    );
    assert!(!output.iter().any(|line| line.contains("key material")));
    // the exact line (c2 f-string): count, display ref, normalized path
    let template = p
        .hsm
        .read_full_template(&find(p.hsm.as_ref(), "k"))
        .unwrap();
    assert_eq!(
        output,
        [format!(
            "wrote aes template ({} attributes) for hsm:k#0a1b to {}",
            template.attrs.len(),
            path.display()
        )]
    );
}

/// Fault-injection hook (c2 MaterialFake): the dump includes a readable CKA_VALUE.
struct MaterialDump(Vec<TemplateAttr>);
impl FakeHooks for MaterialDump {
    fn read_full_template(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
    ) -> Option<r2_core::Result<KeyTemplate>> {
        Some(next.read_full_template(key).map(|mut template| {
            template.attrs.extend(self.0.iter().cloned());
            template
        }))
    }
}

fn material_hsm(
    extra: Vec<TemplateAttr>,
) -> (
    Rc<ScriptedIo>,
    Rc<crate::context::AppContext>,
    Rc<FakeProvider>,
) {
    let io = Rc::new(ScriptedIo::new(Vec::<String>::new()));
    let hsm = Rc::new(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .with_hooks(Rc::new(MaterialDump(extra))),
    );
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::clone(&hsm) as Rc<dyn Provider>)
        .unwrap();
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .providers(registry)
        .build();
    (io, ctx, hsm)
}

#[test]
fn test_key_template_warns_when_material_dumped() {
    let (io, ctx, hsm) = material_hsm(vec![TemplateAttr::new(
        "CKA_VALUE",
        AttrKind::Bytes,
        AttrValue::Bytes(vec![0x01; 16]),
    )]);
    hsm.import_key(&aes_material(), "k", None, None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    run_line(
        &ctx,
        &format!(
            "key template hsm:k {}",
            dir.path().join("tpl.yaml").display()
        ),
    )
    .unwrap();
    let output = io.output();
    assert!(
        output
            .iter()
            .any(|line| line.contains("key material") && line.contains("CKA_VALUE")),
        "{output:?}"
    );
}

#[test]
fn material_note_lists_sorted_names_for_private_keys_only() {
    let rsa_material =
        |name: &str| TemplateAttr::new(name, AttrKind::Bytes, AttrValue::Bytes(vec![0x01]));
    let (io, ctx, hsm) = material_hsm(vec![
        rsa_material("CKA_PRIME_2"),
        rsa_material("CKA_PRIVATE_EXPONENT"),
        rsa_material("CKA_MODULUS"),
        rsa_material("CKA_COEFFICIENT"),
    ]);
    hsm.import_key(&private_material(), "pair", None, None)
        .unwrap();
    hsm.import_key(&public_material(), "pair", None, None)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("priv.yaml");
    run_line(
        &ctx,
        &format!("key template hsm:pair:priv {}", path.display()),
    )
    .unwrap();
    assert_eq!(
        io.output()[1],
        "note: the file contains key material (CKA_COEFFICIENT, CKA_PRIME_2, \
         CKA_PRIVATE_EXPONENT) — handle it like a private key"
    );
    assert!(section(&path, "rsa_private").get("CKA_MODULUS").is_some());
    // a PUBLIC key never gets the note, even with material-named rows in the dump
    let path = dir.path().join("pub.yaml");
    run_line(
        &ctx,
        &format!("key template hsm:pair:pub {}", path.display()),
    )
    .unwrap();
    let output = io.output();
    assert_eq!(output.len(), 3, "{output:?}");
    assert!(output[2].starts_with("wrote rsa_public template ("));
}

#[test]
fn key_template_needs_both_arguments_with_the_key_usage() {
    let p = make_pair(&[]);
    for line in ["key template", "key template hsm:k"] {
        let err = run_line(&p.ctx, line).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Generic, "{line}");
        let what = if line == "key template" {
            "provider:label"
        } else {
            "path"
        };
        assert_eq!(err.message, format!("missing <{what}> argument"));
        assert_eq!(err.hint, Some(format!("usage: {KEY_USAGE}")));
    }
    // the hint quotes the `key` command's own usage line
    let commands = all_commands().unwrap();
    assert_eq!(commands["key"].usage(), KEY_USAGE);
}

#[test]
fn key_template_resolves_then_requires_login_then_the_provider_type() {
    let p = make_pair(&[]);
    // unknown key → the resolve error, nothing read
    let err = run_line(&p.ctx, "key template hsm:nosuch /tmp/x.yaml").unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotFound);
    // logged out → AuthRequired before the dump (c2 `_require_usable`)
    p.hsm.import_key(&aes_material(), "k", None, None).unwrap();
    p.hsm.logout().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpl.yaml");
    let err = run_line(&p.ctx, &format!("key template hsm:k {}", path.display()));
    // resolve_ref of a logged-out fake fails (key listing needs login) or the auth check
    // refuses — either way an AuthRequired, and no file
    let err = err.unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired, "{}", err.message);
    assert!(!path.exists());
}

#[test]
fn key_template_refuses_objects_without_a_class_key() {
    let p = make_pair(&[]);
    let material = KeyMaterial::new(KeyAlgorithm::Other, KeyClass::Secret, vec![1, 2, 3]);
    p.hsm.store_key_unchecked(&material, "odd", None, None);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpl.yaml");
    let err = run_line(&p.ctx, &format!("key template hsm:odd {}", path.display())).unwrap_err();
    assert!(kind_is(&err, "unsupported"));
    assert_eq!(
        err.message,
        "other secret objects have no template class key"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("objects of unsupported key types can be listed and deleted only")
    );
    assert!(!path.exists());
    assert!(p.io.output().is_empty());
}

#[test]
fn key_template_dumps_data_objects_and_certificates() {
    let p = make_pair(&[]);
    let data = KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, b"payload".to_vec());
    p.hsm.import_key(&data, "blob", None, None).unwrap();
    p.hsm
        .import_key(&cert_material(), "trust", None, None)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.yaml");
    run_line(&p.ctx, &format!("key template hsm:blob {}", path.display())).unwrap();
    let data_section = section(&path, "data");
    assert_eq!(data_section["CKA_CLASS"], Value::String("CKO_DATA".into()));
    assert!(data_section.get("CKA_KEY_TYPE").is_none());
    let path = dir.path().join("cert.yaml");
    run_line(
        &p.ctx,
        &format!("key template hsm:trust {}", path.display()),
    )
    .unwrap();
    let cert_section = section(&path, "certificate");
    assert_eq!(
        cert_section["CKA_CLASS"],
        Value::String("CKO_CERTIFICATE".into())
    );
    assert!(cert_section.get("CKA_KEY_TYPE").is_none());
    // data/cert objects never get the key-material note
    assert!(!p.io.text().contains("key material"));
}

#[test]
fn key_template_path_is_normalized_and_write_errors_are_dataio() {
    let p = make_pair(&[]);
    p.hsm.import_key(&aes_material(), "k", None, None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let typed = format!("{}//./sub/../tpl.yaml", dir.path().display());
    // `..` is kept verbatim by pathlib, so `sub` must exist
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    run_line(&p.ctx, &format!("key template hsm:k {typed}")).unwrap();
    let shown = format!("{}/sub/../tpl.yaml", dir.path().display());
    assert!(
        p.io.text().ends_with(&format!("to {shown}")),
        "{}",
        p.io.text()
    );
    let err = run_line(
        &p.ctx,
        &format!(
            "key template hsm:k {}/absent/tpl.yaml",
            dir.path().display()
        ),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::DataIo);
    assert_eq!(
        err.message,
        format!(
            "cannot write {}/absent/tpl.yaml: No such file or directory",
            dir.path().display()
        )
    );
}

#[test]
fn key_template_dump_reseeds_a_generate() {
    // dump → --template round trip on FakeProvider (the SoftHSM variant is in
    // key_template_softhsm.rs)
    let p = make_pair(&[]);
    p.hsm
        .import_key(
            &aes16_material(),
            "src",
            Some(&sensitive_template()),
            Some(&[7]),
        )
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpl.yaml");
    run_line(&p.ctx, &format!("key template hsm:src {}", path.display())).unwrap();
    run_line(
        &p.ctx,
        &format!(
            "generate hsm aes size=128 --label dst --template {}",
            path.display()
        ),
    )
    .unwrap();
    let seed = &p.editor.seeds()[0];
    let rows: Vec<(String, bool, bool)> = seed
        .attrs
        .iter()
        .map(|a| (a.name.clone(), a.enabled, a.locked))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("CKA_CLASS".into(), true, true),
            ("CKA_KEY_TYPE".into(), true, true),
            ("CKA_LABEL".into(), false, false),
            ("CKA_ID".into(), false, false),
            // FakeProvider dumps its stored attributes in name order
            ("CKA_EXTRACTABLE".into(), true, false),
            ("CKA_SENSITIVE".into(), true, false),
        ]
    );
    let dst = find(p.hsm.as_ref(), "dst");
    assert!(!dst.exportable); // the file's sensitive policy drove the generate
    assert_ne!(dst.key_ref.key_id, Some(vec![7])); // the disabled source id did not
}

// ---------------------------------------------------------------------------------------
// --template seeding (generate / load)
// ---------------------------------------------------------------------------------------

fn template_file(dir: &Path, text: &str) -> String {
    let path = dir.join("tpl.yaml");
    std::fs::write(&path, text).unwrap();
    path.display().to_string()
}

#[test]
fn test_generate_template_seeds_editor_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = template_file(
        dir.path(),
        "aes:\n  CKA_LABEL: old\n  CKA_TOKEN: false\n  CKA_VALUE: '0x01'\n",
    );
    let p = make_pair(&[]);
    run_line(
        &p.ctx,
        &format!("generate hsm aes size=256 --label k --template {path}"),
    )
    .unwrap();
    let seeds = p.editor.seeds();
    assert_eq!(seeds.len(), 1);
    let seed = &seeds[0];
    let locked: Vec<(String, AttrValue)> = seed
        .attrs
        .iter()
        .filter(|a| a.locked)
        .map(|a| (a.name.clone(), a.value.clone()))
        .collect();
    assert_eq!(
        locked,
        vec![
            (
                "CKA_CLASS".into(),
                AttrValue::Symbol("CKO_SECRET_KEY".into())
            ),
            ("CKA_KEY_TYPE".into(), AttrValue::Symbol("CKK_AES".into())),
        ]
    );
    let by_name = |name: &str| seed.get(name).unwrap();
    assert!(!by_name("CKA_LABEL").enabled); // identity rows arrive disabled
    assert!(!by_name("CKA_VALUE").enabled); // material rows arrive disabled
    assert!(by_name("CKA_TOKEN").enabled);
    assert_eq!(by_name("CKA_TOKEN").value, AttrValue::Bool(false));
    assert!(seed.get("CKA_SENSITIVE").is_none()); // config defaults are NOT merged in
    // generation went through
    assert_eq!(find(p.hsm.as_ref(), "k").key_class, KeyClass::Secret);
}

#[test]
fn test_generate_keypair_template_section_per_editor() {
    let dir = tempfile::tempdir().unwrap();
    let path = template_file(dir.path(), "rsa_private:\n  CKA_SIGN: true\n");
    let p = make_pair(&[]);
    run_line(
        &p.ctx,
        &format!("generate hsm rsa size=2048 --label pair --template {path}"),
    )
    .unwrap();
    let seeds = p.editor.seeds();
    assert_eq!(seeds.len(), 2); // private then public (§5.3)
    let names = |t: &KeyTemplate| t.attrs.iter().map(|a| a.name.clone()).collect::<Vec<_>>();
    assert_eq!(names(&seeds[0]), ["CKA_CLASS", "CKA_KEY_TYPE", "CKA_SIGN"]);
    let public_names = names(&seeds[1]); // no section → §7 defaults
    assert!(public_names.contains(&"CKA_ENCRYPT".to_owned()));
    assert!(!public_names.contains(&"CKA_SIGN".to_owned()));
}

#[test]
fn test_generate_template_on_memory_target_raises() {
    let dir = tempfile::tempdir().unwrap();
    let path = template_file(dir.path(), "aes:\n  CKA_TOKEN: true\n");
    let p = make_pair(&[]);
    let err = run_line(
        &p.ctx,
        &format!("generate mem aes size=256 --label k --template {path}"),
    )
    .unwrap_err();
    assert!(kind_is(&err, "param"));
    assert_eq!(err.message, "--template applies only to PKCS#11 targets");
    assert_eq!(
        err.hint.as_deref(),
        Some("the template editor never opens for mem")
    );
    assert!(p.editor.titles().is_empty());
}

#[test]
fn test_load_template_seeds_editor_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = template_file(dir.path(), "aes:\n  CKA_TOKEN: false\n");
    let p = make_pair(&[]);
    run_line(
        &p.ctx,
        &format!(
            "load hsm aes {} --label k --template {path}",
            "02".repeat(16)
        ),
    )
    .unwrap();
    let names: Vec<String> = p.editor.seeds()[0]
        .attrs
        .iter()
        .map(|a| a.name.clone())
        .collect();
    assert_eq!(names, ["CKA_CLASS", "CKA_KEY_TYPE", "CKA_TOKEN"]);
    assert_eq!(find(p.hsm.as_ref(), "k").algorithm, KeyAlgorithm::Aes);
}

#[test]
fn bad_template_file_fails_before_any_prompt_or_provider_call() {
    let dir = tempfile::tempdir().unwrap();
    let path = template_file(dir.path(), "aes:\n  CKA_NOPE: true\n");
    // no --label: the label prompt would come first if the file were parsed late
    let p = make_pair(&["k"]);
    p.hsm.clear_calls();
    let err = run_line(
        &p.ctx,
        &format!("generate hsm aes size=256 --template {path}"),
    )
    .unwrap_err();
    assert_eq!(err.message, "unknown PKCS#11 attribute 'CKA_NOPE'");
    assert!(p.io.prompts().is_empty());
    assert_eq!(p.io.remaining(), 1);
    assert!(p.editor.titles().is_empty());
    assert!(calls_of(&p.hsm, "generate_key").is_empty());
    // a missing file is the DataIo read error
    let err = run_line(
        &p.ctx,
        &format!(
            "load hsm aes {} --label k --template {}/absent.yaml",
            "02".repeat(16),
            dir.path().display()
        ),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::DataIo);
    assert_eq!(
        err.message,
        format!(
            "cannot read {}/absent.yaml: No such file or directory",
            dir.path().display()
        )
    );
    assert!(calls_of(&p.hsm, "import_key").is_empty());
}

#[test]
fn template_file_seeds_a_memory_editor_never() {
    // load on a memory target with --template is refused even when the file is fine
    let dir = tempfile::tempdir().unwrap();
    let path = template_file(dir.path(), "aes:\n  CKA_TOKEN: true\n");
    let p = make_pair(&[]);
    let err = run_line(
        &p.ctx,
        &format!(
            "load mem aes {} --label k --template {path}",
            "02".repeat(16)
        ),
    )
    .unwrap_err();
    assert_eq!(err.message, "--template applies only to PKCS#11 targets");
    assert!(calls_of(&p.mem, "import_key").is_empty());
}

// ---------------------------------------------------------------------------------------
// copy --template (c2 test_copy_cmd.py; the copy command is R10's)
// ---------------------------------------------------------------------------------------

#[test]
fn test_copy_template_seeds_destination_editor() {
    // §5.16: the file section (extractable, non-sensitive) seeds the REAL checklist editor;
    // accepting it unchanged proves the seed drove the copy.
    let dir = tempfile::tempdir().unwrap();
    let path = template_file(
        dir.path(),
        "aes:\n  CKA_SENSITIVE: false\n  CKA_EXTRACTABLE: true\n",
    );
    let io = Rc::new(ScriptedIo::new(["ok"]));
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>).build();
    run_line(&ctx, &format!("copy mem:aeskey hsm --template {path}")).unwrap();
    let (hsm, copied) = ctx.providers.resolve_ref("hsm:aeskey").unwrap();
    assert_eq!(hsm.name(), "hsm");
    let expected: std::collections::BTreeMap<String, AttrValue> = [
        ("CKA_SENSITIVE".to_owned(), AttrValue::Bool(false)),
        ("CKA_EXTRACTABLE".to_owned(), AttrValue::Bool(true)),
    ]
    .into_iter()
    .collect();
    assert_eq!(copied.attributes, expected);
    assert!(copied.exportable);
}

#[test]
fn test_copy_template_memory_destination_raises() {
    let dir = tempfile::tempdir().unwrap();
    let path = template_file(dir.path(), "aes:\n  CKA_TOKEN: true\n");
    let io = Rc::new(ScriptedIo::new(Vec::<String>::new()));
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>).build();
    let err = run_line(&ctx, &format!("copy mem:aeskey mem --template {path}")).unwrap_err();
    assert!(kind_is(&err, "param"));
    assert!(
        err.message.contains("PKCS#11 destinations"),
        "{}",
        err.message
    );
}

#[test]
fn spy_editor_is_a_template_editor() {
    // keep the trait import meaningful for the helper-based cases
    let editor: Rc<dyn TemplateEditor> = Rc::new(SpyEditor::new());
    let out = editor.edit(KeyTemplate::default(), "t").unwrap();
    assert!(out.attrs.is_empty());
}
