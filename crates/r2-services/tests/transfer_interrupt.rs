// services::transfer — the §11 D13 Ctrl-C step boundaries of `copy_key` (R10). The Ctrl-C
// flag (`r2_core::runtime::request_interrupt`) is process-global and every `copy_key`
// checks it, so these tests live in their own test binary (one process even under the
// `cargo test` fallback) and hold `global_state_lock()` among themselves.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::TemplatesSection;
use r2_core::error::{ErrorKind, Result};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_provider::{MechanismInvocation, Provider, WrapOptions};
use r2_services::templatefile::EditorSeeding;
use r2_services::transfer::{TRANSPORT_PREFIX, copy_key};
use r2_testkit::{FakeHooks, FakeProvider, RecordingEditor, ScriptedIo, global_state_lock};

fn templates_section() -> TemplatesSection {
    TemplatesSection {
        pkcs11: IndexMap::new(),
        pkcs11_raw: IndexMap::new(),
        custom_attributes: IndexMap::new(),
    }
}

fn make_hsm(name: &str) -> FakeProvider {
    FakeProvider::new(name).with_type_name("pkcs11")
}

fn import_aes(provider: &dyn Provider, label: &str, sensitive: bool, extractable: bool) -> KeyInfo {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, (0u8..32).collect());
    material.size_bits = Some(256);
    let policy = KeyTemplate::new(vec![
        TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(sensitive)),
        TemplateAttr::new(
            "CKA_EXTRACTABLE",
            AttrKind::Bool,
            AttrValue::Bool(extractable),
        ),
    ]);
    provider
        .import_key(&material, label, Some(&policy), None)
        .unwrap()
}

fn copy_with(
    source: &dyn Provider,
    key: &KeyInfo,
    dest: &dyn Provider,
    editor: &RecordingEditor,
) -> Result<KeyInfo> {
    let io = ScriptedIo::empty();
    let templates = templates_section();
    let seeding = EditorSeeding {
        editor,
        templates: &templates,
        seeds: None,
    };
    copy_key(source, key, dest, &io, &seeding, None, None)
}

fn do_copy(source: &dyn Provider, key: &KeyInfo, dest: &dyn Provider) -> Result<KeyInfo> {
    copy_with(source, key, dest, &RecordingEditor::new())
}

fn transport_labels(provider: &dyn Provider) -> Vec<String> {
    provider
        .list_keys()
        .unwrap()
        .into_iter()
        .map(|info| info.key_ref.label)
        .filter(|label| label.starts_with(TRANSPORT_PREFIX))
        .collect()
}

fn called(provider: &FakeProvider, method: &str) -> Vec<Vec<String>> {
    provider
        .calls()
        .into_iter()
        .filter(|call| call[0] == method)
        .collect()
}

/// Sets the Ctrl-C flag when a chosen method runs (the flag is then seen at the next
/// step boundary).
struct InterruptOn(&'static str);
impl FakeHooks for InterruptOn {
    fn wrap_key(
        &self,
        _next: &dyn Provider,
        _wrapping_key: &KeyInfo,
        _mech: &MechanismInvocation,
        _target: &KeyInfo,
        _options: &WrapOptions,
    ) -> Option<Result<Vec<u8>>> {
        if self.0 == "wrap_key" {
            r2_core::runtime::request_interrupt();
        }
        None
    }
    fn export_key(&self, _next: &dyn Provider, _key: &KeyInfo) -> Option<Result<KeyMaterial>> {
        if self.0 == "export_key" {
            r2_core::runtime::request_interrupt();
        }
        None
    }
}

#[test]
fn ctrl_c_between_wrap_and_unwrap_aborts_and_still_destroys_the_transport_keys() {
    let _lock = global_state_lock();
    r2_core::runtime::reset_interrupt();
    let src = make_hsm("srchsm").with_hooks(Rc::new(InterruptOn("wrap_key")));
    let dst = make_hsm("dsthsm");
    let key = import_aes(&src, "aeskey", true, true);
    let editor = RecordingEditor::new();
    let result = copy_with(&src, &key, &dst, &editor);
    r2_core::runtime::reset_interrupt();
    let err = result.unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert!(editor.titles().is_empty()); // stopped before the editor / unwrap
    assert!(called(&dst, "unwrap_key").is_empty());
    assert!(transport_labels(&src).is_empty() && transport_labels(&dst).is_empty());
}

#[test]
fn ctrl_c_after_a_plain_export_aborts_before_the_destination_is_touched() {
    let _lock = global_state_lock();
    r2_core::runtime::reset_interrupt();
    let src = FakeProvider::new("m1").with_hooks(Rc::new(InterruptOn("export_key")));
    let dst = make_hsm("dsthsm");
    let key = import_aes(&src, "aeskey", false, true);
    let result = do_copy(&src, &key, &dst);
    r2_core::runtime::reset_interrupt();
    assert_eq!(result.unwrap_err().kind, ErrorKind::UserAbort);
    assert!(dst.calls().is_empty());
}

#[test]
fn ctrl_c_before_the_ladder_creates_nothing() {
    let _lock = global_state_lock();
    r2_core::runtime::reset_interrupt();
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", true, true);
    r2_core::runtime::request_interrupt();
    let result = do_copy(&src, &key, &dst);
    r2_core::runtime::reset_interrupt();
    assert_eq!(result.unwrap_err().kind, ErrorKind::UserAbort);
    assert_eq!(called(&src, "import_key").len(), 1);
    assert!(dst.calls().is_empty());
}
