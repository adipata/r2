// `copy` command tests (R10, spec §5.1/§5.5) — port of c2
// tests/unit/console/test_copy_cmd.py (FakeProvider + ScriptedIo, the REAL checklist editor
// wired by CtxBuilder) and the copy case of test_keys_cmd_objects.py. The decision matrix
// itself is covered by r2-services' tests/transfer.rs; these cover argument handling, ref
// resolution, option parsing and the one-line result rendering.
use std::collections::BTreeMap;
use std::rc::Rc;

use r2_core::error::ErrorKind;
use r2_core::io::ConsoleIo;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::template::AttrValue;
use r2_provider::{GenerateRequest, KeySelector, Provider};
use r2_testkit::{FakeProvider, ScriptedIo};

use super::keys_cmd_support::{cert_material, make_pair};
use crate::commands::all_commands;
use crate::context::AppContext;
use crate::testing::{CtxBuilder, run_line};

fn scripted(answers: &[&str]) -> Rc<ScriptedIo> {
    Rc::new(ScriptedIo::new(answers.iter().copied()))
}

/// c2 `make_ctx(io)`: mem (FakeProvider memory holding "aeskey" = 16 × 0x01) + hsm
/// (FakeProvider presenting pkcs11), the real checklist editor.
fn make_ctx(io: &Rc<ScriptedIo>) -> Rc<AppContext> {
    CtxBuilder::new(Rc::clone(io) as Rc<dyn ConsoleIo>).build()
}

fn provider(ctx: &AppContext, name: &str) -> Rc<dyn Provider> {
    ctx.providers.get(name).unwrap()
}

fn fake(ctx: &AppContext, name: &str) -> Rc<dyn Provider> {
    let provider = provider(ctx, name);
    assert!(provider.as_any().downcast_ref::<FakeProvider>().is_some());
    provider
}

fn calls(provider: &Rc<dyn Provider>) -> Vec<Vec<String>> {
    provider
        .as_any()
        .downcast_ref::<FakeProvider>()
        .unwrap()
        .calls()
}

fn find(provider: &Rc<dyn Provider>, label: &str) -> KeyInfo {
    provider.find_key(&KeySelector::label(label)).unwrap()
}

fn policy(sensitive: bool, extractable: bool) -> BTreeMap<String, AttrValue> {
    BTreeMap::from([
        ("CKA_EXTRACTABLE".to_owned(), AttrValue::Bool(extractable)),
        ("CKA_SENSITIVE".to_owned(), AttrValue::Bool(sensitive)),
    ])
}

fn complete(ctx: &AppContext, tokens: &[&str], cursor: &str) -> Vec<String> {
    let commands = all_commands().unwrap();
    let tokens: Vec<String> = tokens.iter().map(|t| (*t).to_owned()).collect();
    commands["copy"].complete(ctx, &tokens, cursor)
}

#[test]
fn test_copy_is_auto_discovered() {
    let commands = all_commands().unwrap();
    let copy = &commands["copy"];
    assert_eq!(copy.name(), "copy");
    assert_eq!(
        copy.summary(),
        "Copy a key to another provider (wrapped in transit when possible)"
    );
    assert_eq!(
        copy.usage(),
        "copy <src-provider>:<label>[:<class>] <dst-provider> [--label <l>] [--id <hex>] [--template <path>]"
    );
    assert!(copy.flags().is_empty());
}

#[test]
fn test_copy_mem_to_pkcs11_end_to_end() {
    // the REAL checklist editor is wired by CtxBuilder (§4.9.3). The §7 aes template
    // defaults to CKA_SENSITIVE=true/CKA_EXTRACTABLE=false (rows 5/6 after the two locked
    // rows); toggling both makes the copy exportable — the operator consciously enables
    // extractability (§7).
    let io = scripted(&["5", "6", "ok"]);
    let ctx = make_ctx(&io);
    run_line(&ctx, "copy mem:aeskey hsm").unwrap();
    let hsm = provider(&ctx, "hsm");
    let copied = find(&hsm, "aeskey");
    assert!(copied.key_ref.key_id.is_some()); // fresh CKA_ID on the pkcs11 side
    assert_eq!(copied.attributes, policy(false, true));
    assert_eq!(
        hsm.export_key(&copied).unwrap().data.to_vec(),
        vec![0x01; 16]
    );
    let expected = format!("copied mem:aeskey -> {}", copied.key_ref.display());
    assert!(io.output().iter().any(|line| line.contains(&expected)));
    assert_eq!(
        io.output().last().unwrap(),
        &format!("{expected} (secret aes)")
    );
    // the editor title names the destination
    assert!(io.text().contains("template for hsm:aeskey (secret aes)"));
}

#[test]
fn test_copy_editor_defaults_keep_the_copy_locked_down() {
    // accepting the §7 defaults untouched yields a sensitive, non-extractable copy
    let io = scripted(&["ok"]);
    let ctx = make_ctx(&io);
    run_line(&ctx, "copy mem:aeskey hsm").unwrap();
    let copied = find(&provider(&ctx, "hsm"), "aeskey");
    assert!(!copied.exportable);
    assert_eq!(copied.attributes, policy(true, false));
}

#[test]
fn test_copy_honors_label_and_id_options() {
    let io = scripted(&["ok"]);
    let ctx = make_ctx(&io);
    run_line(&ctx, "copy mem:aeskey hsm --label renamed --id 0x0a1b").unwrap();
    let copied = find(&provider(&ctx, "hsm"), "renamed");
    assert_eq!(copied.key_ref.key_id.as_deref(), Some(&[0x0a, 0x1b][..]));
}

#[test]
fn test_copy_id_without_prefix() {
    let io = scripted(&["ok"]);
    let ctx = make_ctx(&io);
    run_line(&ctx, "copy mem:aeskey hsm --id deadbeef").unwrap();
    let copied = find(&provider(&ctx, "hsm"), "aeskey");
    assert_eq!(
        copied.key_ref.key_id.as_deref(),
        Some(&[0xde, 0xad, 0xbe, 0xef][..])
    );
    // an upper-case prefix is a prefix too (c2 `raw.lower().startswith("0x")`)
    let io = scripted(&["ok"]);
    let ctx = make_ctx(&io);
    run_line(&ctx, "copy mem:aeskey hsm --id 0XC0FE").unwrap();
    let copied = find(&provider(&ctx, "hsm"), "aeskey");
    assert_eq!(copied.key_ref.key_id.as_deref(), Some(&[0xc0, 0xfe][..]));
}

#[test]
fn test_copy_public_half_by_class_ref_takes_plain_route() {
    // §4.3 ':pub' selector + §5.5 matrix: the public value travels as plain material (no
    // wrap, no template editor for a memory destination).
    let io = scripted(&[]);
    let ctx = make_ctx(&io);
    let hsm = fake(&ctx, "hsm");
    let mut request = GenerateRequest::new(KeyAlgorithm::Rsa, "pair");
    request.size_bits = Some(2048);
    hsm.generate_key(&request).unwrap();
    run_line(&ctx, "copy hsm:pair:pub mem").unwrap();
    let copied = find(&provider(&ctx, "mem"), "pair");
    assert_eq!(copied.key_class, KeyClass::Public);
    assert!(!calls(&hsm).iter().any(|call| call[0] == "wrap_key"));
    assert_eq!(
        io.output().last().unwrap(),
        "copied hsm:pair#00000001 -> mem:pair (public rsa)"
    );
}

#[test]
fn test_copy_wrong_arity_raises_usage_error() {
    for line in ["copy", "copy mem:aeskey", "copy mem:aeskey hsm extra"] {
        let ctx = make_ctx(&scripted(&[]));
        let err = run_line(&ctx, line).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Generic, "{line}");
        assert_eq!(
            err.message,
            "copy takes a source key reference and a destination provider"
        );
        assert!(err.hint.as_deref().unwrap_or("").contains("usage: copy"));
    }
}

#[test]
fn test_copy_bad_id_hex_raises_param_error() {
    let ctx = make_ctx(&scripted(&[]));
    let err = run_line(&ctx, "copy mem:aeskey hsm --id nothex").unwrap_err();
    assert_eq!(err.param_name(), Some("id"));
    assert_eq!(err.message, "--id is not valid hex: 'nothex'");
    assert_eq!(
        err.hint.as_deref(),
        Some("whole bytes as hex, e.g. --id 0a1b")
    );
    let err = run_line(&ctx, "copy mem:aeskey hsm --id 0x").unwrap_err();
    assert_eq!(err.param_name(), Some("id"));
    assert_eq!(err.message, "--id must not be empty");
    // nothing was copied
    assert!(provider(&ctx, "hsm").list_keys().unwrap().is_empty());
}

#[test]
fn test_copy_unknown_source_key_and_dest_provider() {
    let ctx = make_ctx(&scripted(&[]));
    let err = run_line(&ctx, "copy mem:missing hsm").unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotFound);
    let err = run_line(&ctx, "copy mem:aeskey nosuch").unwrap_err();
    assert_eq!(err.kind, ErrorKind::ProviderNotFound);
}

#[test]
fn copy_template_option_is_refused_for_a_memory_destination_before_reading_the_file() {
    // §5.16 (c2 copy_cmd text: "destinations"); the file is never read
    let ctx = make_ctx(&scripted(&[]));
    let err = run_line(&ctx, "copy mem:aeskey mem --template /nonexistent/tpl.yaml").unwrap_err();
    assert_eq!(err.param_name(), Some("template"));
    assert_eq!(
        err.message,
        "--template applies only to PKCS#11 destinations"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("the template editor never opens for mem")
    );
}

#[test]
fn test_complete_offers_refs_providers_and_options() {
    let ctx = make_ctx(&scripted(&[]));
    assert_eq!(complete(&ctx, &["copy"], ""), ["mem:", "hsm:"]);
    assert_eq!(complete(&ctx, &["copy", "mem:aeskey"], ""), ["mem", "hsm"]);
    assert_eq!(
        complete(&ctx, &["copy", "mem:aeskey", "hsm"], ""),
        ["--label", "--id", "--template"]
    );
}

#[test]
fn test_complete_source_ref_offers_key_refs_and_selectors() {
    let ctx = make_ctx(&scripted(&[]));
    assert_eq!(
        complete(&ctx, &["copy", "mem:aes"], "mem:aes"),
        ["mem:aeskey"]
    );
    assert_eq!(
        complete(&ctx, &["copy", "mem:aeskey:"], "mem:aeskey:"),
        ["mem:aeskey:secret"] // §4.3 class selector continuation
    );
    let hsm = provider(&ctx, "hsm");
    hsm.logout().unwrap(); // §5.1/§6: logged-out source completes just the prefix
    assert_eq!(complete(&ctx, &["copy", "hsm:x"], "hsm:x"), ["hsm:"]);
}

#[test]
fn completing_the_template_value_lists_paths() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("tpl.yaml"), "aes: {}\n").unwrap();
    let ctx = make_ctx(&scripted(&[]));
    let prefix = format!("{}/t", dir.path().display());
    let got = complete(
        &ctx,
        &["copy", "mem:aeskey", "hsm", "--template", &prefix],
        &prefix,
    );
    assert_eq!(got, [format!("{}/tpl.yaml", dir.path().display())]);
}

#[test]
fn copy_runs_through_the_repl_dispatch_and_reports_errors_unprinted() {
    // errors are returned (rendered only by the REPL loop), never printed by the command
    let io = scripted(&[]);
    let ctx = make_ctx(&io);
    let hsm = provider(&ctx, "hsm");
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![9; 16]);
    material.size_bits = Some(128);
    let template = r2_core::template::KeyTemplate::new(vec![r2_core::template::TemplateAttr::new(
        "CKA_EXTRACTABLE",
        r2_core::template::AttrKind::Bool,
        AttrValue::Bool(false),
    )]);
    hsm.import_key(&material, "locked", Some(&template), None)
        .unwrap();
    let err = run_line(&ctx, "copy hsm:locked mem").unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert_eq!(
        err.message,
        "key 'locked' is non-extractable on this token and cannot be copied"
    );
    assert!(io.output().is_empty());
}

// ---------------------------------------------------------------------------------------
// c2 test_keys_cmd_objects.py — copy output vocabulary
// ---------------------------------------------------------------------------------------

#[test]
fn test_copy_output_uses_table_vocabulary() {
    let p = make_pair(&[]);
    p.mem
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, b"Hello, data!".to_vec()),
            "note",
            None,
            None,
        )
        .unwrap();
    p.mem
        .import_key(&cert_material(), "trust", None, None)
        .unwrap();
    run_line(&p.ctx, "copy mem:note mem --label note2").unwrap();
    assert!(p.io.output().last().unwrap().ends_with("(data -)"));
    let copied = p.mem.find_key(&KeySelector::label("note2")).unwrap();
    assert_eq!(
        p.mem.export_key(&copied).unwrap().data.to_vec(),
        b"Hello, data!"
    );
    run_line(&p.ctx, "copy mem:trust mem --label trust2").unwrap();
    assert!(p.io.output().last().unwrap().ends_with("(cert rsa)"));
}

// ---------------------------------------------------------------------------------------
// §5.16 --template seeding (R14's `load_seed_file`; the R0 stub answers not-implemented)
// ---------------------------------------------------------------------------------------

#[test]
fn copy_template_seeds_the_real_destination_editor() {
    // the file section (extractable, non-sensitive) seeds the REAL checklist editor;
    // accepting it unchanged proves the seed drove the copy
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpl.yaml");
    std::fs::write(
        &path,
        "aes:\n  CKA_SENSITIVE: false\n  CKA_EXTRACTABLE: true\n",
    )
    .unwrap();
    let io = scripted(&["ok"]);
    let ctx = make_ctx(&io);
    run_line(
        &ctx,
        &format!("copy mem:aeskey hsm --template {}", path.display()),
    )
    .unwrap();
    let copied = find(&provider(&ctx, "hsm"), "aeskey");
    assert_eq!(copied.attributes, policy(false, true));
    assert!(copied.exportable);
}
