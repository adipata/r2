// Provider trait defaults, §4.5 data types, ProviderRegistry and FakeProvider behavior —
// the port of c2 tests/unit/test_provider_base.py (R3).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial, KeyRef};
use r2_core::params::{ParamStruct, ParamValue, Params};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_provider::mechanism::CANONICAL_MECHANISMS;
use r2_provider::*;
use r2_testkit::FakeProvider;
use secrecy::SecretString;
use zeroize::Zeroizing;

fn aes_material() -> KeyMaterial {
    KeyMaterial {
        size_bits: Some(256),
        ..KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, (0u8..32).collect())
    }
}

fn token() -> TokenInfo {
    TokenInfo {
        slot_id: 1,
        label: "tok".to_owned(),
        manufacturer: "m".to_owned(),
        model: "m".to_owned(),
        serial: "s".to_owned(),
    }
}

fn pin(text: &str) -> SecretString {
    SecretString::from(text)
}

fn template(extractable: bool, sensitive: bool) -> KeyTemplate {
    KeyTemplate::new(vec![
        TemplateAttr::new(
            "CKA_EXTRACTABLE",
            AttrKind::Bool,
            AttrValue::Bool(extractable),
        ),
        TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(sensitive)),
    ])
}

fn mech(mechanism: &str, params: Vec<(&str, ParamValue)>) -> MechanismInvocation {
    MechanismInvocation::new(
        mechanism,
        params
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn secret_key(provider: &str) -> KeyInfo {
    KeyInfo {
        key_ref: KeyRef::new(provider, "k", None),
        key_class: KeyClass::Secret,
        algorithm: KeyAlgorithm::Aes,
        size_bits: Some(256),
        curve: None,
        exportable: true,
        attributes: BTreeMap::new(),
        handle: None,
    }
}

fn generate(
    provider: &dyn Provider,
    algorithm: KeyAlgorithm,
    size_bits: Option<u32>,
    curve: Option<Curve>,
    label: &str,
) -> Result<KeyInfo> {
    provider.generate_key(&GenerateRequest {
        size_bits,
        curve,
        ..GenerateRequest::new(algorithm, label)
    })
}

#[track_caller]
fn err_kind<T>(result: Result<T>) -> ConsoleError {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(err) => err,
    }
}

fn calls(provider: &FakeProvider) -> Vec<Vec<String>> {
    provider.calls()
}

fn call(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn same_provider(a: &Rc<dyn Provider>, b: &Rc<dyn Provider>) -> bool {
    std::ptr::addr_eq(Rc::as_ptr(a), Rc::as_ptr(b))
}

/// Smallest concrete Provider — exercises the trait's non-required defaults.
struct MinimalProvider;

impl Provider for MinimalProvider {
    fn name(&self) -> &str {
        "mini"
    }
    fn type_name(&self) -> &str {
        "memory"
    }
    fn initialize(&self) -> Result<()> {
        Ok(())
    }
    fn shutdown(&self) -> Result<()> {
        Ok(())
    }
    fn status(&self) -> ProviderStatus {
        ProviderStatus {
            auth: AuthState::NotRequired,
            token: None,
        }
    }
    fn mechanisms(&self) -> BTreeSet<String> {
        BTreeSet::from(["AES-GCM".to_owned()])
    }
    fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        Ok(Vec::new())
    }
    fn find_key(&self, selector: &KeySelector) -> Result<KeyInfo> {
        Err(ConsoleError::key_not_found(format!(
            "no key '{}'",
            selector.label
        )))
    }
    fn import_key(
        &self,
        _material: &KeyMaterial,
        _label: &str,
        _template: Option<&KeyTemplate>,
        _key_id: Option<&[u8]>,
    ) -> Result<KeyInfo> {
        Err(ConsoleError::unsupported("stub"))
    }
    fn generate_key(&self, _request: &GenerateRequest) -> Result<KeyInfo> {
        Err(ConsoleError::unsupported("stub"))
    }
    fn delete_key(&self, _key: &KeyInfo) -> Result<()> {
        Err(ConsoleError::unsupported("stub"))
    }
    fn export_key(&self, _key: &KeyInfo) -> Result<KeyMaterial> {
        Err(ConsoleError::unsupported("stub"))
    }
    fn encrypt(
        &self,
        _key: &KeyInfo,
        _mech: &MechanismInvocation,
        _data: &[u8],
    ) -> Result<Vec<u8>> {
        Err(ConsoleError::unsupported("stub"))
    }
    fn decrypt(
        &self,
        _key: &KeyInfo,
        _mech: &MechanismInvocation,
        _data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        Err(ConsoleError::unsupported("stub"))
    }
    fn sign(&self, _key: &KeyInfo, _mech: &MechanismInvocation, _data: &[u8]) -> Result<Vec<u8>> {
        Err(ConsoleError::unsupported("stub"))
    }
    fn verify(
        &self,
        _key: &KeyInfo,
        _mech: &MechanismInvocation,
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<bool> {
        Err(ConsoleError::unsupported("stub"))
    }
    fn derive(&self, _key: &KeyInfo, _mech: &MechanismInvocation) -> Result<DeriveResult> {
        Err(ConsoleError::unsupported("stub"))
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// -- TestProviderDefaults --------------------------------------------------------------

#[test]
fn test_list_tokens_defaults_to_empty() {
    assert_eq!(MinimalProvider.list_tokens().unwrap(), Vec::new());
}

#[test]
fn test_login_default_raises_unsupported() {
    let err = err_kind(MinimalProvider.login(&token(), &pin("0000"), false));
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(err.message, "mini does not require login");
}

#[test]
fn test_logout_default_is_noop() {
    MinimalProvider.logout().unwrap(); // concrete default: must simply not fail
}

#[test]
fn test_supports_delegates_to_mechanisms() {
    assert!(MinimalProvider.supports("AES-GCM"));
    assert!(!MinimalProvider.supports("AES-CBC"));
}

#[test]
fn test_wrap_unwrap_default_to_unsupported() {
    let key = secret_key("mini");
    let mech = mech("AES-KEY-WRAP", Vec::new());
    let err = err_kind(MinimalProvider.wrap_key(&key, &mech, &key, &WrapOptions::default()));
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(err.message, "mini does not support key wrapping");
    let request = UnwrapRequest::new(KeyAlgorithm::Aes, KeyClass::Secret, "out");
    let err = err_kind(MinimalProvider.unwrap_key(&key, &mech, &[0u8; 32], &request));
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(err.message, "mini does not support key unwrapping");
}

#[test]
fn test_key_edit_defaults_to_unsupported() {
    let key = secret_key("mini");
    let err = err_kind(MinimalProvider.read_key_template(&key));
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(err.message, "mini does not support key editing");
    let err = err_kind(MinimalProvider.update_key(&key, &KeyTemplate::default()));
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    // r2 addition: the third editing default and the seams.
    let err = err_kind(MinimalProvider.read_full_template(&key));
    assert_eq!(err.message, "mini does not support template dumps");
    assert!(MinimalProvider.as_token_init().is_none());
}

// -- TestDataTypes -----------------------------------------------------------------------

#[test]
fn test_mechanism_invocation_defaults() {
    let mech = mech("AES-GCM", vec![("iv", ParamValue::Bytes(vec![0; 12]))]);
    assert_eq!(mech.raw_ckm, None);
    assert_eq!(mech.param_struct, ParamStruct::None);
    assert_eq!(mech.param_struct.as_str(), "none");
    assert_eq!(mech.raw_param_bytes, None);
}

#[test]
fn test_key_edit_result_objects_are_frozen() {
    // Rust values are immutable unless bound `mut`; the c2 assertions that remain are the
    // field defaults/shapes.
    let outcome = AttrEditOutcome {
        name: "CKA_LABEL".to_owned(),
        applied: true,
        detail: None,
    };
    assert_eq!(outcome.detail, None);
    let result = KeyEditResult {
        key: secret_key("mini"),
        outcomes: vec![outcome.clone()],
    };
    assert_eq!(result.outcomes, vec![outcome]);
    assert_eq!(result.key.key_ref.label, "k");
}

#[test]
fn auth_state_tokens_and_derive_result_debug_hides_bytes() {
    assert_eq!(AuthState::NotRequired.as_str(), "not_required");
    assert_eq!(AuthState::LoggedOut.as_str(), "logged_out");
    assert_eq!(AuthState::LoggedIn.as_str(), "logged_in");
    let result = DeriveResult {
        key: None,
        raw: Some(Zeroizing::new(vec![0xAB; 5])),
    };
    let debug = format!("{result:?}");
    assert!(debug.contains("<5 bytes>"), "{debug}");
    assert!(!debug.contains("171"), "{debug}");
}

#[test]
fn request_constructors_and_selector_builders() {
    let request = GenerateRequest::new(KeyAlgorithm::Rsa, "k");
    assert_eq!(request.label, "k");
    assert_eq!(
        (request.size_bits, &request.curve, &request.key_id),
        (None, &None, &None)
    );
    assert!(request.template.is_none() && request.public_template.is_none());
    let unwrap = UnwrapRequest::new(KeyAlgorithm::Aes, KeyClass::Secret, "u");
    assert_eq!(unwrap.key_id, None);
    assert_eq!(unwrap.template, None);
    assert_eq!(unwrap.options, WrapOptions::default());
    let selector = KeySelector::label("x")
        .with_id(Some(vec![1]))
        .with_class(Some(KeyClass::Public))
        .with_handle(Some(7));
    assert_eq!(
        selector,
        KeySelector {
            label: "x".to_owned(),
            key_id: Some(vec![1]),
            key_class: Some(KeyClass::Public),
            handle: Some(7),
        }
    );
    let parsed = r2_core::keys::parse_ref("p:x#01:pub@7").unwrap();
    assert_eq!(KeySelector::from(&parsed), selector);
}

// -- TestProviderRegistry ----------------------------------------------------------------

#[test]
fn test_register_and_get() {
    let registry = ProviderRegistry::new();
    let provider: Rc<dyn Provider> = Rc::new(FakeProvider::new("mem"));
    registry.register(Rc::clone(&provider)).unwrap();
    assert!(same_provider(&registry.get("mem").unwrap(), &provider));
}

#[test]
fn test_duplicate_name_raises_config_error() {
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::new(FakeProvider::new("mem")))
        .unwrap();
    let err =
        err_kind(registry.register(Rc::new(FakeProvider::new("mem").with_type_name("pkcs11"))));
    assert_eq!(err.kind, ErrorKind::Config);
    assert_eq!(err.message, "provider 'mem' is already registered");
    assert_eq!(
        err.hint.as_deref(),
        Some("provider names must be unique across the configuration")
    );
}

#[test]
fn test_unknown_name_raises_provider_not_found() {
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::new(FakeProvider::new("mem")))
        .unwrap();
    let err = err_kind(registry.get("nope"));
    assert_eq!(err.kind, ErrorKind::ProviderNotFound);
    assert!(err.message.contains("nope"));
    assert!(err.hint.as_deref().is_some_and(|hint| hint.contains("mem")));
    // exact texts (§4.5.3): registration order, and the empty registry
    assert_eq!(err.message, "unknown provider 'nope'");
    assert_eq!(err.hint.as_deref(), Some("known providers: mem"));
    let empty = ProviderRegistry::new();
    assert_eq!(
        err_kind(empty.get("x")).hint.as_deref(),
        Some("known providers: (none registered)")
    );
    registry
        .register(Rc::new(FakeProvider::new("hsm").with_type_name("pkcs11")))
        .unwrap();
    registry
        .register(Rc::new(FakeProvider::new("amem")))
        .unwrap();
    assert_eq!(
        err_kind(registry.get("nope")).hint.as_deref(),
        Some("known providers: mem, hsm, amem")
    );
}

#[test]
fn test_all_is_config_order_memory_first() {
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::new(FakeProvider::new("hsm1").with_type_name("pkcs11")))
        .unwrap();
    registry
        .register(Rc::new(FakeProvider::new("mem1")))
        .unwrap();
    registry
        .register(Rc::new(FakeProvider::new("hsm2").with_type_name("pkcs11")))
        .unwrap();
    registry
        .register(Rc::new(FakeProvider::new("mem2")))
        .unwrap();
    let names: Vec<String> = registry.all().iter().map(|p| p.name().to_owned()).collect();
    assert_eq!(names, ["mem1", "mem2", "hsm1", "hsm2"]);
}

#[test]
fn test_resolve_ref_happy_path() {
    let registry = ProviderRegistry::new();
    let fake = Rc::new(FakeProvider::new("mem"));
    fake.import_key(&aes_material(), "mykey", None, Some(b"\x0a\x1b"))
        .unwrap();
    let provider: Rc<dyn Provider> = fake;
    registry.register(Rc::clone(&provider)).unwrap();
    let (resolved, info) = registry.resolve_ref("mem:mykey").unwrap();
    assert!(same_provider(&resolved, &provider));
    assert_eq!(info.key_ref.label, "mykey");
    let (_, by_id) = registry.resolve_ref("mem:mykey#0a1b").unwrap();
    assert_eq!(by_id.key_ref.key_id.as_deref(), Some(&b"\x0a\x1b"[..]));
}

#[test]
fn test_resolve_ref_error_paths() {
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::new(FakeProvider::new("mem")))
        .unwrap();
    let err = err_kind(registry.resolve_ref("no-colon-here"));
    assert!(matches!(err.kind, ErrorKind::Parse { .. }), "{err:?}");
    assert_eq!(
        err_kind(registry.resolve_ref("ghost:key")).kind,
        ErrorKind::ProviderNotFound
    );
    assert_eq!(
        err_kind(registry.resolve_ref("mem:missing")).kind,
        ErrorKind::KeyNotFound
    );
}

// -- TestFakeProviderBehavior ------------------------------------------------------------

#[test]
fn test_default_mechanisms_are_the_canonical_list() {
    let provider = FakeProvider::new("fake");
    let expected: BTreeSet<String> = CANONICAL_MECHANISMS
        .iter()
        .map(|m| (*m).to_owned())
        .collect();
    assert_eq!(provider.mechanisms(), expected);
    assert!(provider.mechanisms().contains("RSA-AES-KEY-WRAP"));
    assert_eq!(expected.len(), 17);
}

#[test]
fn test_restricted_mechanisms() {
    let provider = FakeProvider::new("fake").with_mechanisms(["AES-GCM"]);
    assert!(provider.supports("AES-GCM"));
    assert!(!provider.supports("AES-CBC"));
    let info = provider
        .import_key(&aes_material(), "k", None, None)
        .unwrap();
    let err = err_kind(provider.encrypt(&info, &mech("AES-CBC", Vec::new()), b"x"));
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(err.message, "fake does not support mechanism AES-CBC");
}

#[test]
fn test_call_recording_encoding() {
    let provider = FakeProvider::new("fake");
    let info = provider
        .import_key(&aes_material(), "k", None, None)
        .unwrap();
    provider
        .encrypt(&info, &mech("AES-GCM", Vec::new()), b"hello")
        .unwrap();
    let recorded = calls(&provider);
    assert!(recorded.contains(&call(&[
        "import_key",
        "aes/secret:32B",
        "k",
        "None",
        "None"
    ])));
    assert!(recorded.contains(&call(&["encrypt", "fake:k", "AES-GCM", "5B"])));
}

#[test]
fn test_login_pin_is_never_recorded() {
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    provider.logout().unwrap();
    provider.login(&token(), &pin("123456"), true).unwrap();
    let recorded = calls(&provider);
    let logins: Vec<&Vec<String>> = recorded.iter().filter(|c| c[0] == "login").collect();
    assert_eq!(logins, [&call(&["login", "tok", "***", "True"])]);
    assert!(
        recorded
            .iter()
            .flatten()
            .all(|part| !part.contains("123456"))
    );
}

#[test]
fn test_pkcs11_presentation_login_lifecycle() {
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    assert_eq!(provider.type_name(), "pkcs11");
    let status = provider.status();
    assert_eq!(status.auth, AuthState::LoggedIn);
    let synthetic = status.token.clone().expect("logged-in token");
    assert_eq!(provider.list_tokens().unwrap(), vec![synthetic.clone()]);
    let err = err_kind(provider.login(&token(), &pin("0000"), false));
    assert_eq!(err.kind, ErrorKind::AlreadyLoggedIn);
    assert_eq!(err.message, "already logged in");
    assert_eq!(err.hint.as_deref(), Some("logout first"));
    provider.logout().unwrap();
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    assert_eq!(provider.status().token, None);
    assert_eq!(provider.mechanisms(), BTreeSet::new());
    let err = err_kind(provider.list_keys());
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert_eq!(err.message, "login required: run `login hsm`");
    assert_eq!(
        err_kind(provider.import_key(&aes_material(), "k", None, None)).kind,
        ErrorKind::AuthRequired
    );
    provider.login(&token(), &pin("0000"), false).unwrap();
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
    assert_eq!(provider.status().token, Some(token()));
    // the synthetic token (§4.10.2)
    assert_eq!(
        synthetic,
        TokenInfo {
            slot_id: 0,
            label: "hsm-token".to_owned(),
            manufacturer: "r2".to_owned(),
            model: "FakeProvider".to_owned(),
            serial: "FAKE0001".to_owned(),
        }
    );
}

#[test]
fn test_shutdown_logs_out() {
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    provider.shutdown().unwrap();
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
}

#[test]
fn test_memory_presentation_has_no_login() {
    let provider = FakeProvider::new("mem");
    assert_eq!(provider.status().auth, AuthState::NotRequired);
    assert_eq!(provider.list_tokens().unwrap(), Vec::new());
    let err = err_kind(provider.login(&token(), &pin("0000"), false));
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(err.message, "mem does not require login");
    provider.logout().unwrap(); // no-op
    assert_eq!(provider.status().auth, AuthState::NotRequired);
}

#[test]
fn test_pkcs11_key_ids_are_generated_4_bytes() {
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    let info = provider
        .import_key(&aes_material(), "k", None, None)
        .unwrap();
    assert_eq!(info.key_ref.key_id.as_ref().map(Vec::len), Some(4));
    let private = generate(&provider, KeyAlgorithm::Ec, None, Some(Curve::P256), "pair").unwrap();
    let publics: Vec<KeyInfo> = provider
        .list_keys()
        .unwrap()
        .into_iter()
        .filter(|k| k.key_ref.label == "pair" && k.key_class == KeyClass::Public)
        .collect();
    assert_eq!(private.key_ref.key_id.as_ref().map(Vec::len), Some(4));
    assert_eq!(publics[0].key_ref.key_id, private.key_ref.key_id);
    assert_ne!(info.key_ref.key_id, private.key_ref.key_id);
    // counter-based and reproducible: 1, 2, … big endian
    assert_eq!(info.key_ref.key_id, Some(vec![0, 0, 0, 1]));
    assert_eq!(private.key_ref.key_id, Some(vec![0, 0, 0, 2]));
}

#[test]
fn test_memory_presentation_keeps_key_id_none() {
    let provider = FakeProvider::new("mem");
    assert_eq!(
        provider
            .import_key(&aes_material(), "k", None, None)
            .unwrap()
            .key_ref
            .key_id,
        None
    );
}

#[test]
fn test_generate_requires_size_or_curve() {
    let provider = FakeProvider::new("fake");
    let err = err_kind(generate(&provider, KeyAlgorithm::Aes, None, None, "k"));
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(err.message, "size_bits is required for aes");
    assert_eq!(err.param_name(), Some("size_bits"));
    let err = err_kind(generate(&provider, KeyAlgorithm::Rsa, None, None, "k"));
    assert_eq!(err.message, "size_bits is required for RSA");
    let err = err_kind(generate(&provider, KeyAlgorithm::Ec, None, None, "k"));
    assert_eq!(err.message, "curve is required for ec");
    assert_eq!(err.param_name(), Some("curve"));
}

#[test]
fn test_sensitive_but_extractable_is_wrappable_not_exportable() {
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    let kek = generate(&provider, KeyAlgorithm::Aes, Some(256), None, "kek").unwrap();
    let target = provider
        .import_key(&aes_material(), "victim", Some(&template(true, true)), None)
        .unwrap();
    assert!(!target.exportable);
    assert_eq!(
        target.attributes,
        BTreeMap::from([
            ("CKA_SENSITIVE".to_owned(), AttrValue::Bool(true)),
            ("CKA_EXTRACTABLE".to_owned(), AttrValue::Bool(true)),
        ])
    );
    let err = err_kind(provider.export_key(&target));
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert_eq!(
        err.message,
        format!("key '{}' is not exportable", target.key_ref.display())
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("CKA_SENSITIVE/CKA_EXTRACTABLE forbid a plain-value read (§5.5)")
    );
    let wrap = mech("AES-KEY-WRAP-PAD", Vec::new());
    // wrappable = extractable alone (§5.5)
    let blob = provider
        .wrap_key(&kek, &wrap, &target, &WrapOptions::default())
        .unwrap();
    assert_ne!(blob, *aes_material().data);
}

#[test]
fn test_non_extractable_key_cannot_be_wrapped() {
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    let kek = generate(&provider, KeyAlgorithm::Aes, Some(256), None, "kek").unwrap();
    let target = provider
        .import_key(
            &aes_material(),
            "locked",
            Some(&template(false, true)),
            None,
        )
        .unwrap();
    let wrap = mech("AES-KEY-WRAP-PAD", Vec::new());
    let err = err_kind(provider.wrap_key(&kek, &wrap, &target, &WrapOptions::default()));
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert_eq!(
        err.message,
        format!(
            "key '{}' is not extractable and cannot be wrapped",
            target.key_ref.display()
        )
    );
    assert_eq!(err.hint, None);
}

#[test]
fn test_transforms_are_deterministic_across_instances() {
    let (a, b) = (FakeProvider::new("twin"), FakeProvider::new("twin"));
    let info_a = generate(&a, KeyAlgorithm::Aes, Some(256), None, "k").unwrap();
    let info_b = generate(&b, KeyAlgorithm::Aes, Some(256), None, "k").unwrap();
    assert_eq!(
        a.export_key(&info_a).unwrap().data,
        b.export_key(&info_b).unwrap().data
    );
    let gcm = mech("AES-GCM", Vec::new());
    assert_eq!(
        a.encrypt(&info_a, &gcm, b"data").unwrap(),
        b.encrypt(&info_b, &gcm, b"data").unwrap()
    );
}

#[test]
fn test_cross_provider_wrap_unwrap_transport() {
    // The copy transport-key protocol shape: same KEK bytes on both sides.
    let src = FakeProvider::new("src").with_type_name("pkcs11");
    let dst = FakeProvider::new("dst").with_type_name("pkcs11");
    let kek_material = KeyMaterial::new(
        KeyAlgorithm::Aes,
        KeyClass::Secret,
        (0u8..32).rev().collect(),
    );
    let src_kek = src
        .import_key(&kek_material, "transport", None, None)
        .unwrap();
    let dst_kek = dst
        .import_key(&kek_material, "transport", None, None)
        .unwrap();
    let target = src
        .import_key(&aes_material(), "payload", None, None)
        .unwrap();
    let wrap = mech("AES-KEY-WRAP-PAD", Vec::new());
    let blob = src
        .wrap_key(&src_kek, &wrap, &target, &WrapOptions::default())
        .unwrap();
    let request = UnwrapRequest::new(KeyAlgorithm::Aes, KeyClass::Secret, "payload");
    let copied = dst.unwrap_key(&dst_kek, &wrap, &blob, &request).unwrap();
    assert_eq!(dst.export_key(&copied).unwrap().data, aes_material().data);
    assert_eq!(copied.size_bits, Some(256));
}

#[test]
fn test_derive_is_symmetric_between_two_fakes() {
    let (alice, bob) = (FakeProvider::new("alice"), FakeProvider::new("bob"));
    let priv_a = generate(&alice, KeyAlgorithm::Ec, None, Some(Curve::P256), "a").unwrap();
    let priv_b = generate(&bob, KeyAlgorithm::Ec, None, Some(Curve::P256), "b").unwrap();
    let public = |provider: &FakeProvider| {
        provider
            .list_keys()
            .unwrap()
            .into_iter()
            .find(|k| k.key_class == KeyClass::Public)
            .unwrap()
    };
    let peer_for_alice = bob.export_key(&public(&bob)).unwrap().data.to_vec();
    let peer_for_bob = alice.export_key(&public(&alice)).unwrap().data.to_vec();
    let mech_a = mech("ECDH", vec![("peer", ParamValue::Bytes(peer_for_alice))]);
    let mech_b = mech("ECDH", vec![("peer", ParamValue::Bytes(peer_for_bob))]);
    let result_a = alice.derive(&priv_a, &mech_a).unwrap();
    let result_b = bob.derive(&priv_b, &mech_b).unwrap();
    assert!(result_a.raw.is_some());
    assert_eq!(result_a.raw, result_b.raw);
}

#[test]
fn test_derive_honors_out_len() {
    let provider = FakeProvider::new("fake");
    let private = generate(&provider, KeyAlgorithm::Ec, None, Some(Curve::P256), "a").unwrap();
    let ecdh = mech(
        "ECDH",
        vec![
            ("peer", ParamValue::Bytes(vec![0x04; 65])),
            ("out_len", ParamValue::Int(48)),
        ],
    );
    let result = provider.derive(&private, &ecdh).unwrap();
    assert_eq!(result.raw.map(|raw| raw.len()), Some(48));
}

#[test]
fn test_find_key_prefers_private_half_of_a_pair() {
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    let private = generate(&provider, KeyAlgorithm::Rsa, Some(2048), None, "pair").unwrap();
    let found = provider.find_key(&KeySelector::label("pair")).unwrap();
    assert_eq!(found.key_class, KeyClass::Private);
    assert_eq!(found.key_ref, private.key_ref);
}

#[test]
fn test_pair_half_preference_also_applies_on_memory() {
    let provider = FakeProvider::new("mem");
    let private = generate(&provider, KeyAlgorithm::Rsa, Some(2048), None, "pair").unwrap();
    // halves share the label; both ids are None
    let found = provider.find_key(&KeySelector::label("pair")).unwrap();
    assert_eq!(found.key_class, KeyClass::Private);
    assert_eq!(found.key_ref, private.key_ref);
}

#[test]
fn test_same_class_duplicate_labels_are_ambiguous_on_memory() {
    // Regression: with key_id None everywhere (memory presentation), two distinct
    // same-class keys under one label are a genuine ambiguity — the keypair-half class
    // preference must not swallow it. Creating such a twin through the API is refused (the
    // §4.7 guard), so the second one goes through the store_key_unchecked backdoor.
    let provider = FakeProvider::new("mem");
    let other = KeyMaterial {
        size_bits: Some(256),
        ..KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, (32u8..64).collect())
    };
    provider
        .import_key(&aes_material(), "dup", None, None)
        .unwrap();
    let err = err_kind(provider.import_key(&other, "dup", None, None));
    assert_eq!(err.kind, ErrorKind::DuplicateKey);
    assert_eq!(
        err.message,
        "a secret object with label 'dup' and no id already exists on mem"
    );
    provider.store_key_unchecked(&other, "dup", None, None);
    let err = err_kind(provider.find_key(&KeySelector::label("dup")));
    assert_eq!(err.candidates().map(<[_]>::len), Some(2));
    assert_eq!(
        err.message,
        "'dup' matches 2 keys on mem: mem:dup:secret@1, mem:dup:secret@2"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("disambiguate with label#id, a :priv/:pub/:cert/:secret/:data suffix, or @handle")
    );
}

#[test]
fn test_class_selector_overrides_pair_preference() {
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    generate(&provider, KeyAlgorithm::Rsa, Some(2048), None, "pair").unwrap();
    let public = provider
        .find_key(&KeySelector::label("pair").with_class(Some(KeyClass::Public)))
        .unwrap();
    assert_eq!(public.key_class, KeyClass::Public);
    let err = err_kind(
        provider.find_key(&KeySelector::label("pair").with_class(Some(KeyClass::Certificate))),
    );
    assert_eq!(err.kind, ErrorKind::KeyNotFound);
    assert!(
        err.message.contains("no certificate key"),
        "{}",
        err.message
    );
    assert_eq!(err.message, "no certificate key 'pair' on provider hsm");
}

#[test]
fn test_resolve_ref_with_class_and_handle_selectors() {
    let registry = ProviderRegistry::new();
    let fake = Rc::new(FakeProvider::new("hsm").with_type_name("pkcs11"));
    registry
        .register(Rc::clone(&fake) as Rc<dyn Provider>)
        .unwrap();
    generate(&*fake, KeyAlgorithm::Rsa, Some(2048), None, "pair").unwrap();
    let (_, public) = registry.resolve_ref("hsm:pair:pub").unwrap();
    assert_eq!(public.key_class, KeyClass::Public);
    let (_, private) = registry.resolve_ref("hsm:pair:priv").unwrap();
    assert_eq!(private.key_class, KeyClass::Private);
    let handle = public.handle.expect("integer handle");
    let (_, by_handle) = registry.resolve_ref(&format!("hsm:pair@{handle}")).unwrap();
    assert_eq!(by_handle.key_class, KeyClass::Public);
    assert_eq!(by_handle.handle, Some(handle));
}

#[test]
fn hmac_output_lengths_follow_the_hash_param() {
    let provider = FakeProvider::new("fake");
    let generic = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, vec![7; 32]),
            "g",
            None,
            None,
        )
        .unwrap();
    for (hash, width) in [
        ("sha1", 20),
        ("sha224", 28),
        ("sha256", 32),
        ("sha384", 48),
        ("sha512", 64),
    ] {
        let hmac = mech("HMAC", vec![("hash", ParamValue::Enum(hash.to_owned()))]);
        assert_eq!(
            provider.sign(&generic, &hmac, b"m").unwrap().len(),
            width,
            "{hash}"
        );
    }
    // absent hash = sha256
    let params: Params = Params::new();
    let hmac = MechanismInvocation::new("HMAC", params);
    assert_eq!(provider.sign(&generic, &hmac, b"m").unwrap().len(), 32);
}
