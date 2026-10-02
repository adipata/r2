// services::transfer — port of c2 tests/unit/test_transfer.py (R10) and the copy cases of
// tests/unit/services/test_objects_services.py: two FakeProviders (one or both presenting
// "pkcs11"), ScriptedIo and RecordingEditor. Proves the decision matrix on `type_name`,
// the auth-then-ladder pre-probe, transport-key destruction on success AND failure, the
// sensitive-but-extractable wrap path, the ephemeral-RSA and single-shot fallbacks, the
// plain-read last resort and the confirm-then-raise refusal UX. c2's FakeProvider
// subclasses (FailingWrap / FailingUnwrap) are FakeHooks here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod keyload_fixtures;

use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::TemplatesSection;
use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_provider::{KeySelector, MechanismInvocation, Provider, UnwrapRequest, WrapOptions};
use r2_services::templatefile::EditorSeeding;
use r2_services::transfer::{TRANSPORT_PREFIX, copy_key};
use r2_testkit::{FakeHooks, FakeProvider, RecordingEditor, ScriptedIo};
use secrecy::SecretString;

const AES_BYTES: [u8; 32] = {
    let mut bytes = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        bytes[i] = i as u8;
        i += 1;
    }
    bytes
};

/// Opaque to FakeProvider (c2 `b"\x30\x82\x01\x00" + bytes(range(60))`).
fn pkcs8_bytes() -> Vec<u8> {
    let mut data = vec![0x30, 0x82, 0x01, 0x00];
    data.extend(0u8..60);
    data
}

fn bool_attr(name: &str, value: bool) -> TemplateAttr {
    TemplateAttr::new(name, AttrKind::Bool, AttrValue::Bool(value))
}

fn policy_template(sensitive: bool, extractable: bool) -> KeyTemplate {
    KeyTemplate::new(vec![
        bool_attr("CKA_SENSITIVE", sensitive),
        bool_attr("CKA_EXTRACTABLE", extractable),
    ])
}

/// c2 `TemplatesSection(pkcs11={}, custom_attributes={})`.
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

fn make_hsm_with(name: &str, mechanisms: &[&str]) -> FakeProvider {
    make_hsm(name).with_mechanisms(mechanisms.iter().copied())
}

fn aes_material() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, AES_BYTES.to_vec());
    material.size_bits = Some(256);
    material
}

fn import_aes(provider: &dyn Provider, label: &str, sensitive: bool, extractable: bool) -> KeyInfo {
    provider
        .import_key(
            &aes_material(),
            label,
            Some(&policy_template(sensitive, extractable)),
            None,
        )
        .unwrap()
}

fn rsa_private(size_bits: Option<u32>) -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, pkcs8_bytes());
    material.size_bits = size_bits;
    material
}

fn rsa_public() -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Public, vec![0x30; 64])
}

/// One `copy_key` call (c2 `do_copy`).
struct Run<'a> {
    io: Option<&'a ScriptedIo>,
    editor: Option<&'a RecordingEditor>,
    label: Option<&'a str>,
    key_id: Option<&'a [u8]>,
    templates: TemplatesSection,
}

impl<'a> Run<'a> {
    fn new() -> Self {
        Self {
            io: None,
            editor: None,
            label: None,
            key_id: None,
            templates: templates_section(),
        }
    }
    fn io(self, io: &'a ScriptedIo) -> Self {
        Self {
            io: Some(io),
            ..self
        }
    }
    fn editor(self, editor: &'a RecordingEditor) -> Self {
        Self {
            editor: Some(editor),
            ..self
        }
    }
    fn label(self, label: &'a str) -> Self {
        Self {
            label: Some(label),
            ..self
        }
    }
    fn key_id(self, key_id: &'a [u8]) -> Self {
        Self {
            key_id: Some(key_id),
            ..self
        }
    }
    fn templates(self, templates: TemplatesSection) -> Self {
        Self { templates, ..self }
    }
    fn copy(self, source: &dyn Provider, key: &KeyInfo, dest: &dyn Provider) -> Result<KeyInfo> {
        let default_io = ScriptedIo::empty();
        let default_editor = RecordingEditor::new();
        let io = self.io.unwrap_or(&default_io);
        let editor = self.editor.unwrap_or(&default_editor);
        let seeding = EditorSeeding {
            editor,
            templates: &self.templates,
            seeds: None,
        };
        copy_key(source, key, dest, io, &seeding, self.label, self.key_id)
    }
}

fn do_copy(source: &dyn Provider, key: &KeyInfo, dest: &dyn Provider) -> Result<KeyInfo> {
    Run::new().copy(source, key, dest)
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

fn deleted_transports(provider: &FakeProvider) -> Vec<Vec<String>> {
    provider
        .calls()
        .into_iter()
        .filter(|call| call[0] == "delete_key" && call[1].contains(TRANSPORT_PREFIX))
        .collect()
}

fn called(provider: &FakeProvider, method: &str) -> Vec<Vec<String>> {
    provider
        .calls()
        .into_iter()
        .filter(|call| call[0] == method)
        .collect()
}

fn wrap_mechs(provider: &FakeProvider) -> Vec<String> {
    called(provider, "wrap_key")
        .into_iter()
        .map(|call| call[2].clone())
        .collect()
}

fn exported(provider: &dyn Provider, key: &KeyInfo) -> Vec<u8> {
    provider.export_key(key).unwrap().data.to_vec()
}

fn export_call(key: &KeyInfo) -> Vec<String> {
    vec!["export_key".to_owned(), key.key_ref.display()]
}

/// c2's `FailingWrap` / `FailingUnwrap` subclasses.
struct Failing {
    wrap: bool,
    unwrap: bool,
}
impl FakeHooks for Failing {
    fn wrap_key(
        &self,
        _next: &dyn Provider,
        _wrapping_key: &KeyInfo,
        _mech: &MechanismInvocation,
        _target: &KeyInfo,
        _options: &WrapOptions,
    ) -> Option<Result<Vec<u8>>> {
        self.wrap
            .then(|| Err(ConsoleError::crypto("simulated wrap failure")))
    }
    fn unwrap_key(
        &self,
        _next: &dyn Provider,
        _wrapping_key: &KeyInfo,
        _mech: &MechanismInvocation,
        _wrapped: &[u8],
        _request: &UnwrapRequest,
    ) -> Option<Result<KeyInfo>> {
        self.unwrap
            .then(|| Err(ConsoleError::crypto("simulated unwrap failure")))
    }
}

fn failing(wrap: bool, unwrap: bool) -> Rc<dyn FakeHooks> {
    Rc::new(Failing { wrap, unwrap })
}

// ---------------------------------------------------------------------------------------
// pkcs11 → pkcs11: transport-key protocol
// ---------------------------------------------------------------------------------------

#[test]
fn test_sensitive_but_extractable_key_copies_via_wrap() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", true, true);
    assert!(!key.exportable); // sensitive → not plain-readable (§5.5)
    let editor = RecordingEditor::new();
    let result = Run::new().editor(&editor).copy(&src, &key, &dst).unwrap();
    // the copy is the same key material, delivered without a plain read
    assert_eq!(exported(&dst, &result), AES_BYTES);
    assert!(!src.calls().contains(&export_call(&key)));
    assert_eq!(wrap_mechs(&src), ["AES-KEY-WRAP-PAD"]);
    let unwraps: Vec<String> = called(&dst, "unwrap_key")
        .into_iter()
        .map(|call| call[2].clone())
        .collect();
    assert_eq!(unwraps, ["AES-KEY-WRAP-PAD"]);
}

#[test]
fn test_transport_key_destroyed_on_success() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", true, true);
    do_copy(&src, &key, &dst).unwrap();
    assert!(transport_labels(&src).is_empty());
    assert!(transport_labels(&dst).is_empty());
    assert_eq!(deleted_transports(&src).len(), 1);
    assert_eq!(deleted_transports(&dst).len(), 1);
}

#[test]
fn transport_objects_are_single_purpose_session_objects() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", true, true);
    do_copy(&src, &key, &dst).unwrap();
    // one transport label, used on both tokens: "r2-transport-" + 8 hex digits (§11 D7)
    let imports: Vec<Vec<String>> = called(&src, "import_key")
        .into_iter()
        .chain(called(&dst, "import_key"))
        .filter(|call| call[2].starts_with(TRANSPORT_PREFIX))
        .collect();
    assert_eq!(imports.len(), 2);
    assert_eq!(imports[0][2], imports[1][2]);
    let suffix = &imports[0][2][TRANSPORT_PREFIX.len()..];
    assert_eq!(suffix.len(), 8);
    assert!(
        suffix
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    // AES-256 material, a 5-row template (TOKEN/PRIVATE/SENSITIVE/EXTRACTABLE + usage)
    for call in &imports {
        assert_eq!(call[1], "aes/secret:32B");
        assert_eq!(call[3], "template(5 attrs)");
        assert_eq!(call[4], "None");
    }
}

#[test]
fn test_transport_key_destroyed_when_unwrap_fails() {
    let src = make_hsm("srchsm");
    let dst = make_hsm("dsthsm").with_hooks(failing(false, true));
    let key = import_aes(&src, "aeskey", true, true);
    let err = do_copy(&src, &key, &dst).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Crypto);
    assert!(transport_labels(&src).is_empty());
    assert!(transport_labels(&dst).is_empty());
    assert_eq!(deleted_transports(&src).len(), 1);
    assert_eq!(deleted_transports(&dst).len(), 1);
}

#[test]
fn test_transport_key_destroyed_when_wrap_fails() {
    let src = make_hsm("srchsm").with_hooks(failing(true, false));
    let dst = make_hsm("dsthsm");
    let key = import_aes(&src, "aeskey", true, true);
    let err = do_copy(&src, &key, &dst).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Crypto);
    assert!(transport_labels(&src).is_empty());
    assert!(transport_labels(&dst).is_empty());
}

#[test]
fn test_editor_runs_for_pkcs11_destination_and_template_reaches_unwrap() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", true, true);
    let editor = RecordingEditor::new();
    Run::new().editor(&editor).copy(&src, &key, &dst).unwrap();
    assert_eq!(editor.templates().len(), 1);
    let template = &editor.templates()[0];
    // seeded from TemplatesSection::default_template: two locked rows
    let names: Vec<&str> = template.attrs.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, ["CKA_CLASS", "CKA_KEY_TYPE"]);
    assert!(editor.titles()[0].contains("dsthsm"));
    assert_eq!(
        editor.titles()[0],
        "template for dsthsm:aeskey (secret aes)"
    );
    let unwrap = &called(&dst, "unwrap_key")[0];
    assert!(unwrap.contains(&"template(2 attrs)".to_owned()));
}

#[test]
fn test_plain_aes_key_wrap_used_for_aligned_secret_when_pad_missing() {
    let src = make_hsm_with("srchsm", &["AES-KEY-WRAP"]);
    let dst = make_hsm_with("dsthsm", &["AES-KEY-WRAP"]);
    let key = import_aes(&src, "aeskey", true, true);
    let result = do_copy(&src, &key, &dst).unwrap();
    assert_eq!(exported(&dst, &result), AES_BYTES);
    assert_eq!(wrap_mechs(&src), ["AES-KEY-WRAP"]);
}

#[test]
fn plain_aes_key_wrap_needs_an_aligned_secret_of_at_least_16_bytes() {
    // a 20-byte generic secret is not 8-byte aligned: no KW rung, and (sensitive, so not
    // plain-readable) no route at all
    let src = make_hsm_with("srchsm", &["AES-KEY-WRAP"]);
    let dst = make_hsm_with("dsthsm", &["AES-KEY-WRAP"]);
    let mut material = KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, vec![7; 20]);
    material.size_bits = Some(160);
    let key = src
        .import_key(&material, "g20", Some(&policy_template(true, true)), None)
        .unwrap();
    let err = do_copy(&src, &key, &dst).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(
        err.message,
        "cannot copy: srchsm lacks AES-KEY-WRAP-PAD and RSA-OAEP and RSA-AES-KEY-WRAP; dsthsm lacks AES-KEY-WRAP-PAD and RSA-OAEP and RSA-AES-KEY-WRAP"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("the source must wrap and the destination must unwrap with a common mechanism (§5.5)")
    );
    // a 24-byte one is aligned
    let mut material = KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, vec![7; 24]);
    material.size_bits = Some(192);
    let key = src
        .import_key(&material, "g24", Some(&policy_template(true, true)), None)
        .unwrap();
    let result = do_copy(&src, &key, &dst).unwrap();
    assert_eq!(exported(&dst, &result), vec![7; 24]);
}

#[test]
fn test_label_and_id_defaults() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = import_aes(&src, "orig-label", true, true);
    let result = do_copy(&src, &key, &dst).unwrap();
    assert_eq!(result.key_ref.label, "orig-label"); // destination label defaults to source
    // §5.5: a cross-token pkcs11→pkcs11 copy inherits the source CKA_ID
    assert_eq!(result.key_ref.key_id, key.key_ref.key_id);
}

#[test]
fn test_label_and_id_overrides() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", true, true);
    let result = Run::new()
        .label("renamed")
        .key_id(&[0xaa, 0xbb])
        .copy(&src, &key, &dst)
        .unwrap();
    assert_eq!(result.key_ref.label, "renamed");
    assert_eq!(result.key_ref.key_id.as_deref(), Some(&[0xaa, 0xbb][..]));
}

// ---------------------------------------------------------------------------------------
// §5.5 CKA_ID inheritance (pkcs11 → pkcs11, cross-token only)
// ---------------------------------------------------------------------------------------

#[test]
fn test_same_token_copy_keeps_fresh_id() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let token = src.status().token.unwrap();
    dst.logout().unwrap();
    dst.login(&token, &SecretString::from("1234".to_owned()), false)
        .unwrap(); // both entries point at ONE token
    let key = src
        .import_key(
            &aes_material(),
            "aeskey",
            Some(&policy_template(true, true)),
            Some(&[0x5a, 0x5a]),
        )
        .unwrap();
    let result = do_copy(&src, &key, &dst).unwrap();
    assert!(result.key_ref.key_id.is_some());
    // same token: label#id must stay unambiguous (§4.3), so no inheritance
    assert_ne!(result.key_ref.key_id, key.key_ref.key_id);
}

#[test]
fn test_memory_source_id_not_inherited() {
    let (mem, dst) = (FakeProvider::new("mem"), make_hsm("dsthsm"));
    let key = mem
        .import_key(&aes_material(), "aeskey", None, Some(&[0x0a, 0x1b]))
        .unwrap();
    let result = do_copy(&mem, &key, &dst).unwrap();
    assert!(result.key_ref.key_id.is_some());
    // the gate is pkcs11→pkcs11, not id presence
    assert_ne!(result.key_ref.key_id, key.key_ref.key_id);
}

#[test]
fn test_pkcs11_to_memory_id_not_inherited() {
    let (src, mem) = (make_hsm("srchsm"), FakeProvider::new("mem"));
    let key = import_aes(&src, "aeskey", true, true);
    let result = do_copy(&src, &key, &mem).unwrap();
    assert_eq!(result.key_ref.key_id, None); // memory presentation keeps None
}

#[test]
fn test_repeated_cross_token_copy_refused_as_duplicate() {
    // inherited id + same label → the second copy would create an exact (class, label,
    // id) twin at the destination; the §4.7 guard refuses it (pass --id for a second copy)
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", true, true);
    do_copy(&src, &key, &dst).unwrap();
    let err = do_copy(&src, &key, &dst).unwrap_err();
    assert_eq!(err.kind, ErrorKind::DuplicateKey);
    // the escape hatch
    let second = Run::new()
        .key_id(&[0xbe, 0xef])
        .copy(&src, &key, &dst)
        .unwrap();
    assert_eq!(second.key_ref.key_id.as_deref(), Some(&[0xbe, 0xef][..]));
    // the refused copy still destroyed its transport keys
    assert!(transport_labels(&src).is_empty() && transport_labels(&dst).is_empty());
}

#[test]
fn test_template_id_row_outranks_inheritance() {
    // §4.7: an operator CKA_ID row must govern — transfer passes key_id=None so the row
    // never turns into a bogus --id conflict at the provider.
    let editor = RecordingEditor::with(|mut template| {
        template.attrs.push(TemplateAttr::new(
            "CKA_ID",
            AttrKind::Bytes,
            AttrValue::Bytes(vec![0xca, 0xfe]),
        ));
        Ok(template)
    });
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = src
        .import_key(
            &aes_material(),
            "aeskey",
            Some(&policy_template(true, true)),
            Some(&[0x5a, 0x5a]),
        )
        .unwrap();
    let result = Run::new().editor(&editor).copy(&src, &key, &dst).unwrap();
    assert_ne!(result.key_ref.key_id, key.key_ref.key_id); // inheritance suppressed
    let unwrap = &called(&dst, "unwrap_key")[0];
    assert_eq!(unwrap[7], "None"); // the key_id argument transfer passed
}

#[test]
fn test_accepted_offer_inherits_public_parts_own_id() {
    // refusal path: the copied object is the PUBLIC part, so its own CKA_ID is inherited
    // (mirrors the own-label rule), not the private's
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = src
        .import_key(
            &rsa_private(None),
            "rsakey",
            Some(&policy_template(true, false)),
            Some(&[0x11, 0x11]),
        )
        .unwrap();
    let public = src
        .import_key(&rsa_public(), "rsakey", None, Some(&[0x22, 0x22]))
        .unwrap(); // label-matched part with its own id
    let io = ScriptedIo::new(["y"]);
    let result = Run::new().io(&io).copy(&src, &key, &dst).unwrap();
    assert_eq!(result.key_class, KeyClass::Public);
    assert_eq!(result.key_ref.key_id, public.key_ref.key_id);
    assert_ne!(result.key_ref.key_id, key.key_ref.key_id);
}

#[test]
fn data_objects_never_inherit_an_id() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let info = src
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, b"blob".to_vec()),
            "blob",
            None,
            None,
        )
        .unwrap();
    let result = do_copy(&src, &info, &dst).unwrap();
    assert_eq!(result.key_ref.key_id, None);
}

// ---------------------------------------------------------------------------------------
// fallback ladder
// ---------------------------------------------------------------------------------------

#[test]
fn test_ephemeral_rsa_oaep_route_for_secret_targets() {
    let src = make_hsm_with("srchsm", &["RSA-OAEP"]);
    let dst = make_hsm_with("dsthsm", &["RSA-OAEP"]);
    let key = import_aes(&src, "aeskey", true, true);
    let result = do_copy(&src, &key, &dst).unwrap();
    assert_eq!(exported(&dst, &result), AES_BYTES);
    assert_eq!(wrap_mechs(&src), ["RSA-OAEP"]);
    // ephemeral keypair generated on the DESTINATION (§5.5), then destroyed
    assert_eq!(called(&dst, "generate_key").len(), 1);
    assert!(transport_labels(&src).is_empty());
    assert!(transport_labels(&dst).is_empty());
    assert_eq!(deleted_transports(&src).len(), 1); // imported public wrapping key
    assert_eq!(deleted_transports(&dst).len(), 2); // private + public halves
}

#[test]
fn ephemeral_rsa_keypair_shape_and_oaep_defaults() {
    let src = make_hsm_with("srchsm", &["RSA-OAEP"]);
    let dst = make_hsm_with("dsthsm", &["RSA-OAEP"]);
    let key = import_aes(&src, "aeskey", true, true);
    struct Spy(std::cell::RefCell<Vec<MechanismInvocation>>);
    impl FakeHooks for Spy {
        fn wrap_key(
            &self,
            _next: &dyn Provider,
            _wrapping_key: &KeyInfo,
            mech: &MechanismInvocation,
            _target: &KeyInfo,
            _options: &WrapOptions,
        ) -> Option<Result<Vec<u8>>> {
            self.0.borrow_mut().push(mech.clone());
            None
        }
    }
    let spy = Rc::new(Spy(std::cell::RefCell::new(Vec::new())));
    let src = src.with_hooks(Rc::clone(&spy) as Rc<dyn FakeHooks>);
    do_copy(&src, &key, &dst).unwrap();
    let mech = spy.0.borrow()[0].clone();
    assert_eq!(mech.mechanism, "RSA-OAEP");
    let params: Vec<(String, r2_core::params::ParamValue)> = mech.params.into_iter().collect();
    use r2_core::params::ParamValue;
    assert_eq!(
        params,
        [
            ("hash".to_owned(), ParamValue::Enum("sha256".into())),
            ("mgf_hash".to_owned(), ParamValue::Enum("sha256".into())),
            ("label".to_owned(), ParamValue::Bytes(Vec::new())),
        ]
    );
    let generate = &called(&dst, "generate_key")[0];
    // generate_key(algorithm, size_bits, curve, label, key_id, template, public_template)
    assert_eq!(generate[1], "KeyAlgorithm.RSA");
    assert_eq!(generate[2], "2048");
    assert!(generate[4].starts_with(TRANSPORT_PREFIX));
    assert_eq!(generate[6], "template(6 attrs)");
    assert_eq!(generate[7], "template(4 attrs)");
    let source_import = called(&src, "import_key")
        .into_iter()
        .find(|call| call[2].starts_with(TRANSPORT_PREFIX))
        .unwrap();
    assert_eq!(source_import[1], "rsa/public:64B");
    assert_eq!(source_import[3], "template(4 attrs)");
}

#[test]
fn test_ephemeral_rsa_cleanup_on_failure() {
    let src = make_hsm_with("srchsm", &["RSA-OAEP"]);
    let dst = make_hsm_with("dsthsm", &["RSA-OAEP"]).with_hooks(failing(false, true));
    let key = import_aes(&src, "aeskey", true, true);
    let err = do_copy(&src, &key, &dst).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Crypto);
    assert!(transport_labels(&src).is_empty());
    assert!(transport_labels(&dst).is_empty());
}

#[test]
fn test_single_shot_rsa_aes_key_wrap_for_private_targets() {
    let src = make_hsm_with("srchsm", &["RSA-AES-KEY-WRAP"]);
    let dst = make_hsm_with("dsthsm", &["RSA-AES-KEY-WRAP"]);
    let key = src
        .import_key(
            &rsa_private(Some(2048)),
            "rsakey",
            Some(&policy_template(true, true)),
            None,
        )
        .unwrap();
    let result = do_copy(&src, &key, &dst).unwrap();
    assert_eq!(result.key_class, KeyClass::Private);
    assert_eq!(exported(&dst, &result), pkcs8_bytes());
    assert_eq!(wrap_mechs(&src), ["RSA-AES-KEY-WRAP"]);
    assert!(transport_labels(&src).is_empty());
    assert!(transport_labels(&dst).is_empty());
}

#[test]
fn test_oaep_not_used_for_private_targets() {
    // RSA-OAEP alone cannot carry a private key (§5.5) → single-shot wins
    let src = make_hsm_with("srchsm", &["RSA-OAEP", "RSA-AES-KEY-WRAP"]);
    let dst = make_hsm_with("dsthsm", &["RSA-OAEP", "RSA-AES-KEY-WRAP"]);
    let key = src
        .import_key(
            &rsa_private(Some(2048)),
            "rsakey",
            Some(&policy_template(true, true)),
            None,
        )
        .unwrap();
    do_copy(&src, &key, &dst).unwrap();
    assert_eq!(wrap_mechs(&src), ["RSA-AES-KEY-WRAP"]);
}

#[test]
fn test_plain_read_last_resort_with_confirmation() {
    let src = make_hsm_with("srchsm", &[]); // no wrap mechanisms at all
    let dst = make_hsm_with("dsthsm", &[]);
    let key = import_aes(&src, "aeskey", false, true); // exportable
    let io = ScriptedIo::new(["y"]);
    let result = Run::new().io(&io).copy(&src, &key, &dst).unwrap();
    assert_eq!(exported(&dst, &result), AES_BYTES);
    assert!(called(&src, "wrap_key").is_empty());
    assert!(src.calls().contains(&export_call(&key)));
    assert!(
        io.prompts()
            .iter()
            .any(|prompt| prompt.contains("plaintext"))
    );
    assert_eq!(
        io.prompts(),
        [
            "No wrap route is available — the key material of 'srchsm:aeskey#00000001' will transit process memory in plaintext. Continue?"
        ]
    );
    // a cross-token plain read inherits the id too
    assert_eq!(result.key_ref.key_id, key.key_ref.key_id);
}

#[test]
fn test_plain_read_declined_aborts_before_export() {
    let src = make_hsm_with("srchsm", &[]);
    let dst = make_hsm_with("dsthsm", &[]);
    let key = import_aes(&src, "aeskey", false, true);
    let io = ScriptedIo::new(["n"]);
    let err = Run::new().io(&io).copy(&src, &key, &dst).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert!(!src.calls().contains(&export_call(&key)));
}

#[test]
fn test_no_route_names_missing_mechanisms() {
    let src = make_hsm_with("srchsm", &["AES-GCM"]);
    let dst = make_hsm_with("dsthsm", &["AES-KEY-WRAP-PAD"]);
    let key = import_aes(&src, "aeskey", true, true); // not plain-readable
    let err = do_copy(&src, &key, &dst).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.starts_with("cannot copy:"));
    assert!(err.message.contains("srchsm lacks AES-KEY-WRAP-PAD"));
    assert!(err.message.contains("RSA-OAEP"));
    // the capable side is not blamed for the missing pieces it has
    assert!(!err.message.contains("dsthsm lacks AES-KEY-WRAP-PAD"));
    assert_eq!(
        err.message,
        "cannot copy: srchsm lacks AES-KEY-WRAP-PAD and RSA-OAEP and RSA-AES-KEY-WRAP; dsthsm lacks RSA-OAEP and RSA-AES-KEY-WRAP"
    );
    // nothing touched a token
    assert!(called(&src, "import_key").len() == 1 && called(&dst, "import_key").is_empty());
}

// ---------------------------------------------------------------------------------------
// auth pre-probe (§5.5 probe order)
// ---------------------------------------------------------------------------------------

#[test]
fn test_logged_out_source_raises_auth_error_not_mechanism_error() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", true, true);
    src.logout().unwrap(); // mechanisms() is now empty — must NOT surface as "lacks"
    let err = do_copy(&src, &key, &dst).unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert!(err.message.contains("srchsm"));
    assert_eq!(err.message, "provider 'srchsm' is not logged in");
    assert_eq!(err.hint.as_deref(), Some("run `login srchsm` first"));
}

#[test]
fn test_logged_out_destination_raises_auth_error() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", true, true);
    dst.logout().unwrap();
    let err = do_copy(&src, &key, &dst).unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert!(err.message.contains("dsthsm"));
}

// ---------------------------------------------------------------------------------------
// refusal UX (§5.5): confirm-then-raise
// ---------------------------------------------------------------------------------------

#[test]
fn test_non_extractable_with_no_public_part_raises_without_prompt() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", true, false);
    let io = ScriptedIo::empty();
    let err = Run::new().io(&io).copy(&src, &key, &dst).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(err.message.contains("non-extractable"));
    assert_eq!(
        err.message,
        "key 'aeskey' is non-extractable on this token and cannot be copied"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("only its public part (if any) can leave the token")
    );
    assert!(io.prompts().is_empty()); // nothing public to offer → no confirm
}

fn non_extractable_pair(src: &FakeProvider) -> KeyInfo {
    let key = src
        .import_key(
            &rsa_private(None),
            "rsakey",
            Some(&policy_template(true, false)),
            None,
        )
        .unwrap();
    src.import_key(&rsa_public(), "rsakey", None, None).unwrap();
    key
}

#[test]
fn test_non_extractable_offer_declined_raises() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = non_extractable_pair(&src);
    let io = ScriptedIo::new(["n"]);
    let err = Run::new().io(&io).copy(&src, &key, &dst).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(
        io.prompts()
            .iter()
            .any(|p| p.contains("copy its public part"))
    );
    assert_eq!(
        io.prompts(),
        [
            "key 'srchsm:rsakey#00000001' cannot be copied; copy its public part 'srchsm:rsakey#00000002' instead?"
        ]
    );
    assert!(called(&dst, "import_key").is_empty());
}

#[test]
fn test_non_extractable_offer_accepted_copies_public_part() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = non_extractable_pair(&src);
    let editor = RecordingEditor::new();
    let io = ScriptedIo::new(["y"]);
    let result = Run::new()
        .io(&io)
        .editor(&editor)
        .copy(&src, &key, &dst)
        .unwrap();
    assert_eq!(result.key_class, KeyClass::Public);
    assert_eq!(exported(&dst, &result), rsa_public().data.to_vec());
    assert!(called(&src, "wrap_key").is_empty());
    assert_eq!(editor.titles().len(), 1); // public import into pkcs11 → editor too
}

#[test]
fn test_accepted_offer_honors_label_and_id_overrides() {
    // explicit --label/--id must win even when the public part is copied
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = non_extractable_pair(&src);
    let io = ScriptedIo::new(["y"]);
    let result = Run::new()
        .io(&io)
        .label("renamed")
        .key_id(&[0xaa, 0xbb])
        .copy(&src, &key, &dst)
        .unwrap();
    assert_eq!(result.key_class, KeyClass::Public);
    assert_eq!(result.key_ref.label, "renamed");
    assert_eq!(result.key_ref.key_id.as_deref(), Some(&[0xaa, 0xbb][..]));
    assert_eq!(exported(&dst, &result), rsa_public().data.to_vec());
}

#[test]
fn test_accepted_offer_defaults_to_public_parts_own_label() {
    // without --label the public part keeps ITS label, not the private's
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let shared_id = [0x99u8; 4];
    let key = src
        .import_key(
            &rsa_private(None),
            "priv-label",
            Some(&policy_template(true, false)),
            Some(&shared_id),
        )
        .unwrap();
    src.import_key(&rsa_public(), "pub-label", None, Some(&shared_id))
        .unwrap(); // matched by CKA_ID (§5.5), label differs
    let io = ScriptedIo::new(["y"]);
    let result = Run::new().io(&io).copy(&src, &key, &dst).unwrap();
    assert_eq!(result.key_class, KeyClass::Public);
    assert_eq!(result.key_ref.label, "pub-label");
}

#[test]
fn public_part_ranking_prefers_public_then_same_id() {
    // PUBLIC beats CERTIFICATE, a same-id match beats a same-label one (c2 ranks 0..3)
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let key = src
        .import_key(
            &rsa_private(None),
            "rsakey",
            Some(&policy_template(true, false)),
            Some(&[1]),
        )
        .unwrap();
    src.import_key(
        &keyload_fixtures::cert_material(),
        "rsakey",
        None,
        Some(&[1]),
    )
    .unwrap(); // rank 2
    src.import_key(&rsa_public(), "rsakey", None, Some(&[9]))
        .unwrap(); // rank 1 (same label, other id)
    let io = ScriptedIo::new(["n"]);
    Run::new().io(&io).copy(&src, &key, &dst).unwrap_err();
    assert!(io.prompts()[0].ends_with("copy its public part 'srchsm:rsakey#09' instead?"));
    let other = src
        .import_key(&rsa_public(), "elsewhere", None, Some(&[1]))
        .unwrap(); // rank 0 (same id)
    let io = ScriptedIo::new(["n"]);
    Run::new().io(&io).copy(&src, &key, &dst).unwrap_err();
    assert!(io.prompts()[0].ends_with(&format!(
        "copy its public part '{}' instead?",
        other.key_ref.display()
    )));
}

// ---------------------------------------------------------------------------------------
// decision matrix: memory-type source / destination, public objects
// ---------------------------------------------------------------------------------------

#[test]
fn test_memory_to_memory_plain_copy_without_editor() {
    let (src, dst) = (FakeProvider::new("m1"), FakeProvider::new("m2"));
    let key = import_aes(&src, "aeskey", false, true);
    let editor = RecordingEditor::new();
    let result = Run::new().editor(&editor).copy(&src, &key, &dst).unwrap();
    assert_eq!(exported(&dst, &result), AES_BYTES);
    assert_eq!(result.key_ref.key_id, None); // memory presentation keeps None
    assert!(editor.titles().is_empty()); // no editor for a memory destination
    assert!(called(&src, "wrap_key").is_empty());
}

#[test]
fn test_memory_to_pkcs11_plain_copy_with_editor() {
    let (src, dst) = (FakeProvider::new("m1"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", false, true);
    let editor = RecordingEditor::new();
    let result = Run::new().editor(&editor).copy(&src, &key, &dst).unwrap();
    assert_eq!(exported(&dst, &result), AES_BYTES);
    assert_eq!(editor.titles().len(), 1);
    assert!(called(&src, "wrap_key").is_empty());
    assert!(src.calls().contains(&export_call(&key)));
}

#[test]
fn test_memory_source_never_wraps_even_when_both_sides_could() {
    // matrix binds on type_name: memory → pkcs11 is always plain (§5.5)
    let (src, dst) = (FakeProvider::new("m1"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", false, true);
    do_copy(&src, &key, &dst).unwrap();
    assert_eq!(called(&src, "import_key").len(), 1); // no transport key on source
}

#[test]
fn test_non_exportable_memory_key_gets_refusal_ux() {
    let (src, dst) = (FakeProvider::new("m1"), FakeProvider::new("m2"));
    let key = import_aes(&src, "aeskey", true, true);
    let io = ScriptedIo::empty();
    let err = Run::new().io(&io).copy(&src, &key, &dst).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
}

#[test]
fn test_pkcs11_to_memory_uses_wrap_route_without_editor() {
    let (src, dst) = (make_hsm("srchsm"), FakeProvider::new("mem"));
    let key = import_aes(&src, "aeskey", true, true);
    let editor = RecordingEditor::new();
    let result = Run::new().editor(&editor).copy(&src, &key, &dst).unwrap();
    assert_eq!(exported(&dst, &result), AES_BYTES);
    assert_eq!(wrap_mechs(&src), ["AES-KEY-WRAP-PAD"]);
    assert!(editor.titles().is_empty()); // memory destination → no editor
    assert!(transport_labels(&src).is_empty());
    assert!(transport_labels(&dst).is_empty());
}

#[test]
fn test_public_key_copies_plain_between_pkcs11_providers() {
    let (src, dst) = (make_hsm("srchsm"), make_hsm("dsthsm"));
    let mut material = KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Public, vec![0x04; 65]);
    material.curve = Some(Curve::P256);
    let key = src.import_key(&material, "ecpub", None, None).unwrap();
    let editor = RecordingEditor::new();
    let result = Run::new().editor(&editor).copy(&src, &key, &dst).unwrap();
    assert_eq!(result.key_class, KeyClass::Public);
    assert!(called(&src, "wrap_key").is_empty());
    assert_eq!(editor.titles(), ["template for dsthsm:ecpub (public ec)"]);
}

#[test]
fn test_certificate_copies_plain() {
    let (src, dst) = (make_hsm("srchsm"), FakeProvider::new("mem"));
    let material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, vec![0x30; 100]);
    let key = src.import_key(&material, "cert", None, None).unwrap();
    let result = do_copy(&src, &key, &dst).unwrap();
    assert_eq!(result.key_class, KeyClass::Certificate);
    assert_eq!(exported(&dst, &result), material.data.to_vec());
    assert!(called(&src, "wrap_key").is_empty());
}

#[test]
fn editor_seed_comes_from_the_configured_templates_and_cancel_aborts() {
    // §5.12: seeded via TemplatesSection::default_template (here the embedded §7 one)
    let (src, dst) = (FakeProvider::new("m1"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", false, true);
    let editor =
        RecordingEditor::with(|_| Err(ConsoleError::user_abort("template edit cancelled")));
    let err = Run::new()
        .editor(&editor)
        .templates(keyload_fixtures::make_templates())
        .copy(&src, &key, &dst)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    let seed = &editor.templates()[0];
    assert_eq!(seed.attrs.len(), 12); // 2 locked rows + the 10 aes policy rows of §7
    assert!(called(&dst, "import_key").is_empty());
}

// ---------------------------------------------------------------------------------------
// object kinds (c2 test_objects_services.py, transfer part)
// ---------------------------------------------------------------------------------------

const VALUE: &[u8] = b"opaque bytes \x00\x01\x02 -- not a key";

fn data_material() -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, VALUE.to_vec())
}

#[test]
fn test_copy_data_object_takes_the_plain_route() {
    let mem = FakeProvider::new("mem");
    let hsm = make_hsm("hsm");
    let info = mem
        .import_key(&data_material(), "blob", None, None)
        .unwrap();
    let editor = RecordingEditor::new();
    let result = Run::new().editor(&editor).copy(&mem, &info, &hsm).unwrap();
    assert_eq!(result.key_class, KeyClass::Data);
    assert_eq!(result.key_ref.key_id, None); // data objects carry no CKA_ID (§4.3)
    assert_eq!(exported(&hsm, &result), VALUE);
    assert_eq!(editor.titles(), ["template for hsm:blob (data)"]);
    assert!(
        !hsm.calls()
            .iter()
            .any(|call| call[0] == "wrap_key" || call[0] == "unwrap_key")
    );
    let back = Run::new().label("blob2").copy(&hsm, &result, &mem).unwrap();
    assert_eq!(exported(&mem, &back), VALUE);
}

/// Serves the data value for any export (the source snapshot is a hand-built KeyInfo
/// carrying CKA_APPLICATION / CKA_OBJECT_ID, which FakeProvider does not model).
struct ExportsData;
impl FakeHooks for ExportsData {
    fn export_key(&self, _next: &dyn Provider, _key: &KeyInfo) -> Option<Result<KeyMaterial>> {
        Some(Ok(data_material()))
    }
}

#[test]
fn copy_of_a_data_object_carries_its_extras_into_the_editor_seed() {
    let src = make_hsm("srchsm").with_hooks(Rc::new(ExportsData));
    let dst = make_hsm("dsthsm");
    let mut attributes = std::collections::BTreeMap::new();
    attributes.insert("CKA_APPLICATION".to_owned(), AttrValue::Str("acme".into()));
    attributes.insert(
        "CKA_OBJECT_ID".to_owned(),
        AttrValue::Bytes(vec![0x2a, 0x2b]),
    );
    let info = KeyInfo {
        key_ref: r2_core::keys::KeyRef::new("srchsm", "blob", None),
        key_class: KeyClass::Data,
        algorithm: KeyAlgorithm::None,
        size_bits: Some(8 * VALUE.len() as u32),
        curve: None,
        exportable: true,
        attributes,
        handle: None,
    };
    let editor = RecordingEditor::new();
    let result = Run::new()
        .editor(&editor)
        .templates(keyload_fixtures::make_templates())
        .copy(&src, &info, &dst)
        .unwrap();
    assert_eq!(exported(&dst, &result), VALUE);
    let seed = &editor.templates()[0];
    let names: Vec<&str> = seed.attrs.iter().map(|a| a.name.as_str()).collect();
    // §7 data section (CKA_TOKEN, CKA_PRIVATE) + the extras appended
    assert_eq!(
        names,
        [
            "CKA_CLASS",
            "CKA_TOKEN",
            "CKA_PRIVATE",
            "CKA_APPLICATION",
            "CKA_OBJECT_ID"
        ]
    );
    let app = seed.get("CKA_APPLICATION").unwrap();
    assert!(app.value == AttrValue::Str("acme".into()) && app.enabled);
    let oid = seed.get("CKA_OBJECT_ID").unwrap();
    assert!(oid.value == AttrValue::Bytes(vec![0x2a, 0x2b]) && oid.enabled);
    assert_eq!(editor.titles(), ["template for dsthsm:blob (data)"]);
}

#[test]
fn test_copy_certificate_round_trip_is_plain_material() {
    let mem = FakeProvider::new("mem");
    let hsm = make_hsm("hsm");
    let mut material = KeyMaterial::new(
        KeyAlgorithm::Rsa,
        KeyClass::Certificate,
        keyload_fixtures::rsa_cert_der(),
    );
    material.size_bits = Some(2048);
    let cert = mem.import_key(&material, "crt", None, None).unwrap();
    let on_hsm = do_copy(&mem, &cert, &hsm).unwrap();
    assert_eq!(on_hsm.key_class, KeyClass::Certificate);
    let back = Run::new().label("crt2").copy(&hsm, &on_hsm, &mem).unwrap();
    assert_eq!(exported(&mem, &back), keyload_fixtures::rsa_cert_der());
    assert!(
        !hsm.calls()
            .iter()
            .chain(mem.calls().iter())
            .any(|call| call[0] == "wrap_key" || call[0] == "unwrap_key")
    );
}

#[test]
fn test_copy_refuses_unmodelled_key_types() {
    let hsm = make_hsm("hsm");
    let mem = FakeProvider::new("mem");
    let info = hsm.store_key_unchecked(
        &KeyMaterial::new(KeyAlgorithm::Other, KeyClass::Secret, vec![b'x'; 24]),
        "des3",
        None,
        Some(&[0x01]),
    );
    let err = do_copy(&hsm, &info, &mem).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("cannot be copied"));
    assert!(
        err.message
            .ends_with("of 'hsm:des3#01' is not supported by r2 and cannot be copied")
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("objects of unsupported key types can be listed and deleted only")
    );
}

// ---------------------------------------------------------------------------------------
// §11 D13 cleanup guard (the Ctrl-C step-boundary tests live in transfer_interrupt.rs: the
// interrupt flag is process-global, so they get their own test binary)
// ---------------------------------------------------------------------------------------

/// delete_key fails: a provider error is logged and ignored (c2 `_destroy_quietly`), a
/// UserAbort is never swallowed (§4.2) and replaces the copy's own outcome.
struct FailingDelete(ErrorKind);
impl FakeHooks for FailingDelete {
    fn delete_key(&self, _next: &dyn Provider, key: &KeyInfo) -> Option<Result<()>> {
        if !key.key_ref.label.starts_with(TRANSPORT_PREFIX) {
            return None;
        }
        Some(Err(ConsoleError::new(self.0.clone(), "cannot destroy")))
    }
}

#[test]
fn transport_destroy_failures_are_quiet_but_user_abort_propagates() {
    let src = make_hsm("srchsm").with_hooks(Rc::new(FailingDelete(ErrorKind::Provider)));
    let dst = make_hsm("dsthsm");
    let key = import_aes(&src, "aeskey", true, true);
    let result = do_copy(&src, &key, &dst).unwrap();
    assert_eq!(exported(&dst, &result), AES_BYTES);
    assert!(transport_labels(&dst).is_empty()); // the other side was still destroyed

    let src = make_hsm("srchsm").with_hooks(Rc::new(FailingDelete(ErrorKind::UserAbort)));
    let dst = make_hsm("dsthsm");
    let key = import_aes(&src, "aeskey", true, true);
    let err = do_copy(&src, &key, &dst).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert!(transport_labels(&dst).is_empty());
}

/// unwrap_key panics, and so would delete_key of a transport object: the transport guard
/// must not call the provider while unwinding (spec §4 unwind-safety), else the second
/// panic aborts the process instead of reporting the first.
struct PanickingUnwrapAndDelete;
impl FakeHooks for PanickingUnwrapAndDelete {
    fn unwrap_key(
        &self,
        _next: &dyn Provider,
        _wrapping_key: &KeyInfo,
        _mech: &MechanismInvocation,
        _wrapped: &[u8],
        _request: &UnwrapRequest,
    ) -> Option<Result<KeyInfo>> {
        panic!("simulated unwrap panic");
    }
    fn delete_key(&self, _next: &dyn Provider, key: &KeyInfo) -> Option<Result<()>> {
        if key.key_ref.label.starts_with(TRANSPORT_PREFIX) {
            panic!("delete_key called while unwinding");
        }
        None
    }
}

#[test]
fn transport_guard_makes_no_provider_call_while_unwinding() {
    let src = make_hsm("srchsm");
    let dst = make_hsm("dsthsm").with_hooks(Rc::new(PanickingUnwrapAndDelete));
    let key = import_aes(&src, "aeskey", true, true);
    let outcome =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| do_copy(&src, &key, &dst)));
    let Err(payload) = outcome else {
        panic!("the unwrap panic propagates");
    };
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"simulated unwrap panic")
    );
    assert!(deleted_transports(&src).is_empty());
    assert!(deleted_transports(&dst).is_empty());
}

#[test]
fn the_copy_lands_where_the_editor_says() {
    // the edited template (not the seed) reaches import_key on the plain route
    let (src, dst) = (FakeProvider::new("m1"), make_hsm("dsthsm"));
    let key = import_aes(&src, "aeskey", false, true);
    let editor = RecordingEditor::with(|mut template| {
        template.attrs.push(bool_attr("CKA_SENSITIVE", true));
        template.attrs.push(bool_attr("CKA_EXTRACTABLE", false));
        Ok(template)
    });
    let result = Run::new().editor(&editor).copy(&src, &key, &dst).unwrap();
    assert!(!result.exportable);
    let found = dst.find_key(&KeySelector::label("aeskey")).unwrap();
    assert_eq!(found.key_ref, result.key_ref);
}
