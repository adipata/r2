// services::wrapload — port of c2 tests/unit/services/test_wrapload.py (R15) and the
// wrapload cases of test_objects_services.py. FakeProvider + ScriptedIo only (spec §4.10),
// plus MemoryProvider round-trips for every table row (r2 additions).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod keyload_fixtures;

use std::collections::BTreeSet;

use keyload_fixtures::{make_templates, rsa_cert_der, rsa_pkcs8_der, rsa_spki_der};
use r2_core::error::{ConsoleError, ErrorKind};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::{ParamValue, Params};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_memory::MemoryProvider;
use r2_provider::{
    GenerateRequest, KeySelector, MechanismInvocation, Provider, ProviderRegistry, UnwrapRequest,
    WrapOptions,
};
use r2_services::keyexport;
use r2_services::templatefile::EditorSeeding;
use r2_services::wrapload::{self, Direction, UnwrapJob, WrapMechEntry};
use r2_testkit::{FakeProvider, RecordingEditor, ScriptedIo};
use std::rc::Rc;

/// canonical §4.6 names — the table may only reference these
const CANONICAL: [&str; 6] = [
    "AES-KEY-WRAP",
    "AES-KEY-WRAP-PAD",
    "AES-CBC",
    "AES-GCM",
    "RSA-OAEP",
    "RSA-PKCS1",
];

fn aes_32() -> Vec<u8> {
    (0u8..32).collect()
}

fn make_provider(name: &str, type_name: &str) -> Rc<FakeProvider> {
    Rc::new(FakeProvider::new(name).with_type_name(type_name))
}

fn hsm() -> Rc<FakeProvider> {
    make_provider("hsm", "pkcs11")
}

fn limited(mechanisms: &[&str]) -> Rc<FakeProvider> {
    Rc::new(
        FakeProvider::new("small")
            .with_type_name("pkcs11")
            .with_mechanisms(mechanisms.iter().copied()),
    )
}

fn aes_material(data: &[u8]) -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, data.to_vec());
    material.size_bits = Some(u32::try_from(data.len() * 8).unwrap());
    material
}

fn import_aes(provider: &dyn Provider, label: &str) -> KeyInfo {
    import_aes_data(provider, label, &aes_32())
}

fn import_aes_data(provider: &dyn Provider, label: &str, data: &[u8]) -> KeyInfo {
    provider
        .import_key(&aes_material(data), label, None, None)
        .unwrap()
}

fn import_rsa_private(provider: &dyn Provider, label: &str) -> KeyInfo {
    let mut material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, rsa_pkcs8_der());
    material.size_bits = Some(2048);
    provider.import_key(&material, label, None, None).unwrap()
}

fn import_rsa_public(provider: &dyn Provider, label: &str) -> KeyInfo {
    let mut material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Public, rsa_spki_der());
    material.size_bits = Some(2048);
    provider.import_key(&material, label, None, None).unwrap()
}

fn import_cert(provider: &dyn Provider, label: &str) -> KeyInfo {
    let material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, rsa_cert_der());
    provider.import_key(&material, label, None, None).unwrap()
}

fn generate_pair(provider: &dyn Provider, label: &str) {
    let mut request = GenerateRequest::new(KeyAlgorithm::Rsa, label);
    request.size_bits = Some(2048);
    provider.generate_key(&request).unwrap();
}

fn find_class(provider: &dyn Provider, label: &str, class: KeyClass) -> KeyInfo {
    provider
        .find_key(&KeySelector::label(label).with_class(Some(class)))
        .unwrap()
}

fn registry_with(providers: &[Rc<FakeProvider>]) -> ProviderRegistry {
    let registry = ProviderRegistry::new();
    for provider in providers {
        registry
            .register(Rc::clone(provider) as Rc<dyn Provider>)
            .unwrap();
    }
    registry
}

fn entry_for(cli: &str) -> WrapMechEntry {
    wrapload::wrap_mechs()
        .into_iter()
        .find(|e| e.spec.cli_name == cli)
        .unwrap()
}

fn clis(entries: &[WrapMechEntry]) -> Vec<String> {
    entries.iter().map(|e| e.spec.cli_name.clone()).collect()
}

fn hint(err: &ConsoleError) -> &str {
    err.hint.as_deref().unwrap_or("")
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

fn policy(sensitive: bool, extractable: bool) -> KeyTemplate {
    KeyTemplate::new(vec![
        TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(sensitive)),
        TemplateAttr::new(
            "CKA_EXTRACTABLE",
            AttrKind::Bool,
            AttrValue::Bool(extractable),
        ),
    ])
}

fn gcm_params() -> Params {
    let mut params = Params::new();
    params.insert("iv".into(), ParamValue::Bytes(vec![0; 12]));
    params.insert("aad".into(), ParamValue::Bytes(Vec::new()));
    params.insert("tag_bits".into(), ParamValue::Enum("128".into()));
    params
}

fn job<'a>(
    kek: &'a KeyInfo,
    entry: &'a WrapMechEntry,
    wrapped: &'a [u8],
    result: (KeyAlgorithm, KeyClass),
    label: &str,
) -> UnwrapJob<'a> {
    UnwrapJob {
        kek,
        entry,
        params: Params::new(),
        wrapped,
        result_algorithm: result.0,
        result_class: result.1,
        label: label.to_owned(),
        key_id: None,
    }
}

fn calls_of(provider: &FakeProvider, method: &str) -> Vec<Vec<String>> {
    provider
        .calls()
        .into_iter()
        .filter(|call| call[0] == method)
        .collect()
}

// ---------------------------------------------------------------------------------------
// the §5.4 table itself
// ---------------------------------------------------------------------------------------

#[test]
fn test_table_shape_is_the_spec_contract() {
    let table = wrapload::wrap_mechs();
    let names = clis(&table);
    assert_eq!(names, ["kw", "kwp", "cbc", "gcm", "oaep", "pkcs1"]);
    assert_eq!(
        names.iter().collect::<BTreeSet<_>>().len(),
        names.len(),
        "cli names unique"
    );
    for entry in &table {
        assert!(CANONICAL.contains(&entry.spec.mechanism.as_str()));
        assert_eq!(
            entry.spec.id,
            format!("load.unwrap.{}", entry.spec.cli_name)
        );
        // both result classes are loadable for every v1 row (§5.4)
        assert_eq!(
            entry.result_classes,
            BTreeSet::from([KeyClass::Secret, KeyClass::Private])
        );
        // param names are unique so ParamResolver's `given` mapping is total
        let params: Vec<&str> = entry.spec.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(params.iter().collect::<BTreeSet<_>>().len(), params.len());
    }
}

#[test]
fn test_kek_requirements_split_by_algorithm_and_direction() {
    // AES uses one secret key both ways; RSA unwraps private, wraps public.
    for cli in ["kw", "kwp", "cbc", "gcm"] {
        let entry = entry_for(cli);
        assert_eq!(entry.kek_algorithm, KeyAlgorithm::Aes);
        assert_eq!(entry.unwrap_kek_class, KeyClass::Secret);
        assert_eq!(entry.wrap_kek_classes, BTreeSet::from([KeyClass::Secret]));
    }
    for cli in ["oaep", "pkcs1"] {
        let entry = entry_for(cli);
        assert_eq!(entry.kek_algorithm, KeyAlgorithm::Rsa);
        assert_eq!(entry.unwrap_kek_class, KeyClass::Private);
        // §4.3: a certificate stands in for its public key
        assert_eq!(
            entry.wrap_kek_classes,
            BTreeSet::from([KeyClass::Public, KeyClass::Certificate])
        );
    }
}

#[test]
fn test_param_shapes_match_the_builtin_rows() {
    let names = |cli: &str| -> Vec<String> {
        entry_for(cli)
            .spec
            .params
            .iter()
            .map(|p| p.name.clone())
            .collect()
    };
    assert_eq!(names("cbc"), ["iv", "padding"]);
    let cbc = entry_for("cbc");
    assert_eq!(cbc.spec.params[0].length, Some(16));
    assert_eq!(
        cbc.spec.params[1].default,
        Some(ParamValue::Enum("pkcs7".into()))
    );
    assert_eq!(names("gcm"), ["iv", "aad", "tag_bits"]);
    assert_eq!(
        entry_for("gcm").spec.params[2].default,
        Some(ParamValue::Enum("128".into()))
    );
    assert_eq!(names("oaep"), ["hash", "mgf_hash", "label"]);
    assert_eq!(
        entry_for("oaep").spec.params[1].default_from.as_deref(),
        Some("hash")
    );
    assert!(entry_for("kw").spec.params.is_empty());
}

#[test]
fn param_specs_equal_the_registered_builtin_rows() {
    // r2 addition: the synthetic rows are identical to the §4.6 built-ins they mirror —
    // the encrypt rows, whose IVs carry the §11 D30 random fallback (only `export --kek`
    // gives the resolver an RNG; `load --kek` never does).
    let registry = r2_ops::build_operation_registry(&[]).unwrap();
    for (cli, op) in [
        ("cbc", "aes.encrypt.cbc"),
        ("gcm", "aes.encrypt.gcm"),
        ("oaep", "rsa.encrypt.oaep"),
    ] {
        assert_eq!(
            entry_for(cli).spec.params,
            registry.get(op).unwrap().params,
            "{cli}"
        );
    }
}

#[test]
fn test_result_by_hint_excludes_opaque_hints() {
    for hint in ["auto", "cert", "data", "AES", ""] {
        assert_eq!(wrapload::result_by_hint(hint), None, "{hint}");
    }
    assert_eq!(
        wrapload::result_by_hint("generic"),
        Some((KeyAlgorithm::Generic, KeyClass::Secret))
    );
    assert_eq!(
        wrapload::result_by_hint("aes"),
        Some((KeyAlgorithm::Aes, KeyClass::Secret))
    );
    assert_eq!(
        wrapload::result_by_hint("ec"),
        Some((KeyAlgorithm::Ec, KeyClass::Private))
    );
    assert_eq!(
        wrapload::result_by_hint("rsa"),
        Some((KeyAlgorithm::Rsa, KeyClass::Private))
    );
}

// ---------------------------------------------------------------------------------------
// resolve_kek (§5.4 same-provider rule + §4.3 selectors)
// ---------------------------------------------------------------------------------------

#[test]
fn test_resolve_kek_bare_label() {
    let provider = hsm();
    import_aes(provider.as_ref(), "mykek");
    let resolved = wrapload::resolve_kek(
        &registry_with(&[Rc::clone(&provider)]),
        provider.as_ref(),
        "mykek",
        Direction::Unwrap,
    )
    .unwrap();
    assert_eq!(resolved.key_ref.label, "mykek");
    assert_eq!(resolved.key_class, KeyClass::Secret);
}

#[test]
fn test_resolve_kek_accepts_full_ref_for_the_same_provider() {
    let provider = hsm();
    import_aes(provider.as_ref(), "mykek");
    let resolved = wrapload::resolve_kek(
        &registry_with(&[Rc::clone(&provider)]),
        provider.as_ref(),
        "hsm:mykek",
        Direction::Unwrap,
    )
    .unwrap();
    assert_eq!(resolved.key_ref.label, "mykek");
}

#[test]
fn test_resolve_kek_honors_id_and_class_selectors() {
    let provider = hsm();
    let info = provider
        .import_key(&aes_material(&aes_32()), "dup", None, Some(&[0x0a, 0x1b]))
        .unwrap();
    assert_eq!(info.key_ref.key_id, Some(vec![0x0a, 0x1b]));
    let registry = registry_with(&[Rc::clone(&provider)]);
    let by_id =
        wrapload::resolve_kek(&registry, provider.as_ref(), "dup#0a1b", Direction::Unwrap).unwrap();
    assert_eq!(by_id.key_ref.key_id, Some(vec![0x0a, 0x1b]));
    let by_class = wrapload::resolve_kek(
        &registry,
        provider.as_ref(),
        "dup#0a1b:secret",
        Direction::Unwrap,
    )
    .unwrap();
    assert_eq!(by_class.key_class, KeyClass::Secret);
}

#[test]
fn test_resolve_kek_keypair_label_collapses_to_private_half() {
    let provider = hsm();
    generate_pair(provider.as_ref(), "pair");
    let resolved = wrapload::resolve_kek(
        &registry_with(&[Rc::clone(&provider)]),
        provider.as_ref(),
        "pair",
        Direction::Unwrap,
    )
    .unwrap();
    assert_eq!(resolved.key_class, KeyClass::Private);
}

#[test]
fn test_resolve_kek_cross_provider_is_refused() {
    let target = hsm();
    let other = make_provider("mem", "memory");
    import_aes(other.as_ref(), "mykek");
    let err = wrapload::resolve_kek(
        &registry_with(&[Rc::clone(&target), Rc::clone(&other)]),
        target.as_ref(),
        "mem:mykek",
        Direction::Unwrap,
    )
    .unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
    assert!(err.message.contains("targets 'hsm'"), "{}", err.message);
    assert_eq!(err.param_name(), Some("kek"));
    assert!(hint(&err).contains("copy"));
}

#[test]
fn cross_provider_texts_are_c2_verbatim() {
    let target = hsm();
    let other = make_provider("mem", "memory");
    let registry = registry_with(&[Rc::clone(&target), Rc::clone(&other)]);
    let err = wrapload::resolve_kek(&registry, target.as_ref(), " mem:k ", Direction::Unwrap)
        .unwrap_err();
    assert_eq!(
        err.message,
        "KEK 'mem:k' is on provider 'mem' but the load targets 'hsm'"
    );
    assert_eq!(
        hint(&err),
        "the KEK must already live in that provider (C_UnwrapKey semantics) — `copy mem:k \
         hsm` first"
    );
    let err =
        wrapload::resolve_kek(&registry, target.as_ref(), "mem:k", Direction::Wrap).unwrap_err();
    assert_eq!(
        err.message,
        "KEK 'mem:k' is on provider 'mem' but the export targets 'hsm'"
    );
    assert!(hint(&err).contains("(C_WrapKey semantics)"));
}

#[test]
fn test_resolve_kek_missing_and_empty() {
    let provider = hsm();
    let registry = registry_with(&[Rc::clone(&provider)]);
    let err = wrapload::resolve_kek(&registry, provider.as_ref(), "absent", Direction::Unwrap)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotFound);
    let err =
        wrapload::resolve_kek(&registry, provider.as_ref(), "   ", Direction::Unwrap).unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
    assert_eq!(err.message, "KEK must not be empty");
    assert_eq!(err.param_name(), Some("kek"));
    assert_eq!(hint(&err), "expected <label>[#<id-hex>][:<class>]");
}

#[test]
fn invalid_kek_reference_is_a_param_error() {
    // r2 addition: a grammar error after prefixing the provider (c2 texts).
    let provider = hsm();
    let registry = registry_with(&[Rc::clone(&provider)]);
    let err =
        wrapload::resolve_kek(&registry, provider.as_ref(), "k#zz", Direction::Unwrap).unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
    assert_eq!(err.param_name(), Some("kek"));
    assert!(
        err.message
            .starts_with("invalid KEK reference 'k#zz': invalid hex digit 'z' in key id"),
        "{}",
        err.message
    );
    assert_eq!(hint(&err), "expected <label>[#<id-hex>][:<class>]");
}

#[test]
fn test_resolve_kek_ambiguous_propagates() {
    let provider = hsm();
    provider
        .import_key(&aes_material(&aes_32()), "twin", None, Some(&[0x01]))
        .unwrap();
    provider
        .import_key(&aes_material(&aes_32()), "twin", None, Some(&[0x02]))
        .unwrap();
    let err = wrapload::resolve_kek(
        &registry_with(&[Rc::clone(&provider)]),
        provider.as_ref(),
        "twin",
        Direction::Unwrap,
    )
    .unwrap_err();
    assert!(matches!(err.kind, ErrorKind::AmbiguousKey { .. }));
}

#[test]
fn test_resolve_kek_label_containing_colon_is_not_a_provider() {
    // An unregistered 'provider' prefix keeps its ':' as part of the label (§4.3).
    let provider = hsm();
    import_aes(provider.as_ref(), "od:d");
    let resolved = wrapload::resolve_kek(
        &registry_with(&[Rc::clone(&provider)]),
        provider.as_ref(),
        "od:d",
        Direction::Unwrap,
    )
    .unwrap();
    assert_eq!(resolved.key_ref.label, "od:d");
}

// ---------------------------------------------------------------------------------------
// candidates / resolve_mech / select_mech
// ---------------------------------------------------------------------------------------

#[test]
fn test_candidates_filter_by_kek_and_provider_mechanisms() {
    let provider = hsm();
    let aes_kek = import_aes(provider.as_ref(), "aeskek");
    let rsa_kek = import_rsa_private(provider.as_ref(), "rsakek");
    assert_eq!(
        clis(&wrapload::candidates(
            &aes_kek,
            provider.as_ref(),
            Direction::Unwrap
        )),
        ["kw", "kwp", "cbc", "gcm"]
    );
    assert_eq!(
        clis(&wrapload::candidates(
            &rsa_kek,
            provider.as_ref(),
            Direction::Unwrap
        )),
        ["oaep", "pkcs1"]
    );

    let small = limited(&["AES-KEY-WRAP-PAD"]);
    let small_kek = import_aes(small.as_ref(), "aeskek");
    assert_eq!(
        clis(&wrapload::candidates(
            &small_kek,
            small.as_ref(),
            Direction::Unwrap
        )),
        ["kwp"]
    );
}

#[test]
fn test_candidates_empty_for_a_public_kek_when_unwrapping() {
    // Unwrapping needs the private half — the public one offers nothing.
    let provider = hsm();
    generate_pair(provider.as_ref(), "pair");
    let public = find_class(provider.as_ref(), "pair", KeyClass::Public);
    assert!(wrapload::candidates(&public, provider.as_ref(), Direction::Unwrap).is_empty());
}

#[test]
fn test_resolve_mech_by_cli_and_canonical_name() {
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let p = provider.as_ref();
    let unwrap = Direction::Unwrap;
    assert_eq!(
        wrapload::resolve_mech("kwp", &kek, p, unwrap)
            .unwrap()
            .spec
            .mechanism,
        "AES-KEY-WRAP-PAD"
    );
    assert_eq!(
        wrapload::resolve_mech("AES-KEY-WRAP-PAD", &kek, p, unwrap)
            .unwrap()
            .spec
            .cli_name,
        "kwp"
    );
    assert_eq!(
        wrapload::resolve_mech(" KWP ", &kek, p, unwrap)
            .unwrap()
            .spec
            .cli_name,
        "kwp"
    );
}

#[test]
fn test_resolve_mech_unknown_name_suggests() {
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let err =
        wrapload::resolve_mech("kwpp", &kek, provider.as_ref(), Direction::Unwrap).unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
    assert_eq!(err.message, "unknown wrap mechanism 'kwpp'");
    assert_eq!(err.param_name(), Some("mech"));
    assert!(hint(&err).contains("kwp"));
}

#[test]
fn unknown_mech_hints_are_c2_verbatim() {
    // Vectors from c2 (difflib over cli names then canonical names, n=3).
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let p = provider.as_ref();
    let err = wrapload::resolve_mech("kwpp", &kek, p, Direction::Unwrap).unwrap_err();
    assert_eq!(hint(&err), "did you mean: kwp, kw?");
    let err = wrapload::resolve_mech("zzz", &kek, p, Direction::Unwrap).unwrap_err();
    assert_eq!(err.message, "unknown wrap mechanism 'zzz'");
    assert_eq!(
        hint(&err),
        "valid mechanisms: kw, kwp, cbc, gcm, oaep, pkcs1"
    );
}

#[test]
fn test_resolve_mech_checks_advertised_before_kek_match() {
    // A mechanism the provider lacks is an UnsupportedOperation even when the KEK would
    // not match either — capability first (§5.4).
    let small = limited(&["AES-KEY-WRAP-PAD"]);
    let kek = import_aes(small.as_ref(), "aeskek");
    let err = wrapload::resolve_mech("oaep", &kek, small.as_ref(), Direction::Unwrap).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(err.message, "provider 'small' does not advertise RSA-OAEP");
    assert_eq!(
        hint(&err),
        "wrap support varies by token and login state — omit --mech to pick from what is \
         available"
    );
}

#[test]
fn test_resolve_mech_kek_class_algorithm_mismatch() {
    let provider = hsm();
    let aes_kek = import_aes(provider.as_ref(), "aeskek");
    let err =
        wrapload::resolve_mech("oaep", &aes_kek, provider.as_ref(), Direction::Unwrap).unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
    assert!(
        err.message.contains("needs a private rsa KEK"),
        "{}",
        err.message
    );
    assert_eq!(err.param_name(), Some("mech"));
    assert_eq!(
        err.message,
        "RSA-OAEP unwrap needs a private rsa KEK; 'hsm:aeskek#00000001' is a secret aes key"
    );
    assert_eq!(
        hint(&err),
        "AES secret KEKs unwrap via kw/kwp/cbc/gcm; RSA private KEKs via oaep/pkcs1"
    );

    generate_pair(provider.as_ref(), "pair");
    let public = find_class(provider.as_ref(), "pair", KeyClass::Public);
    let err =
        wrapload::resolve_mech("oaep", &public, provider.as_ref(), Direction::Unwrap).unwrap_err();
    assert!(err.message.contains("needs a private rsa KEK"));
}

#[test]
fn test_select_mech_prompts_and_returns_choice() {
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let io = ScriptedIo::new(["gcm — AES-GCM wrapped blob (ct‖tag)"]);
    let entry = wrapload::select_mech(&io, &kek, provider.as_ref(), Direction::Unwrap).unwrap();
    assert_eq!(entry.spec.cli_name, "gcm");
    assert_eq!(
        io.prompts(),
        ["Select wrap mechanism for KEK hsm:aeskek#00000001"]
    );
}

#[test]
fn test_select_mech_without_candidates_raises() {
    let small = limited(&["AES-CMAC"]);
    let kek = import_aes(small.as_ref(), "aeskek");
    let err = wrapload::select_mech(
        &ScriptedIo::empty(),
        &kek,
        small.as_ref(),
        Direction::Unwrap,
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(
        err.message.contains("no unwrap mechanisms available"),
        "{}",
        err.message
    );
    assert_eq!(
        err.message,
        "no unwrap mechanisms available for KEK small:aeskek#00000001 (secret aes) on small"
    );
}

#[test]
fn test_select_mech_ctrl_c_is_user_abort() {
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let io = ScriptedIo::new([ScriptedIo::CTRL_C]);
    let err = wrapload::select_mech(&io, &kek, provider.as_ref(), Direction::Unwrap).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert_eq!(err.message, "aborted while selecting a wrap mechanism");
}

// ---------------------------------------------------------------------------------------
// load_wrapped
// ---------------------------------------------------------------------------------------

#[test]
fn test_load_wrapped_round_trips_through_the_provider() {
    // memory-type: no template editor runs, so the §7 secure defaults
    // (sensitive/non-extractable) do not block the round-trip assertion
    let provider = make_provider("mem", "memory");
    let kek = import_aes(provider.as_ref(), "aeskek");
    let target = import_aes_data(provider.as_ref(), "target", &[0xab; 32]);
    let blob = provider
        .wrap_key(
            &kek,
            &MechanismInvocation::new("AES-KEY-WRAP-PAD", Params::new()),
            &target,
            &WrapOptions::default(),
        )
        .unwrap();
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let entry = entry_for("kwp");
    let info = wrapload::load_wrapped(
        provider.as_ref(),
        job(
            &kek,
            &entry,
            &blob,
            (KeyAlgorithm::Aes, KeyClass::Secret),
            "restored",
        ),
        &seeding(&editor, &templates),
    )
    .unwrap();
    assert_eq!(info.key_ref.label, "restored");
    assert_eq!(*provider.export_key(&info).unwrap().data, vec![0xab; 32]);
}

#[test]
fn test_load_wrapped_opens_the_editor_for_pkcs11_seeded_from_the_result() {
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let entry = entry_for("kwp");
    wrapload::load_wrapped(
        provider.as_ref(),
        job(
            &kek,
            &entry,
            &[0; 40],
            (KeyAlgorithm::Rsa, KeyClass::Private),
            "unwrapped",
        ),
        &seeding(&editor, &templates),
    )
    .unwrap();
    assert_eq!(
        editor.titles(),
        ["PKCS#11 template — rsa private 'unwrapped'"]
    );
    // seeded from the RESULT (rsa private), not from the KEK
    assert_eq!(
        editor.templates()[0],
        templates
            .default_template(KeyClass::Private, KeyAlgorithm::Rsa)
            .unwrap()
    );
}

/// Resets the process-global Ctrl-C flag even when an assertion fails.
struct ResetInterrupt;

impl Drop for ResetInterrupt {
    fn drop(&mut self) {
        r2_core::runtime::reset_interrupt();
    }
}

#[test]
fn load_wrapped_checks_interrupt_between_the_editor_and_unwrap() {
    // §11 D13: a Ctrl-C raised while the §5.12 editor is open never reaches C_UnwrapKey.
    let _lock = r2_testkit::global_state_lock();
    let _reset = ResetInterrupt;
    r2_core::runtime::reset_interrupt();
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let editor = RecordingEditor::with(|template| {
        r2_core::runtime::request_interrupt_on_this_thread();
        Ok(template)
    });
    let templates = make_templates();
    let entry = entry_for("kwp");
    let err = wrapload::load_wrapped(
        provider.as_ref(),
        job(
            &kek,
            &entry,
            &[0; 40],
            (KeyAlgorithm::Aes, KeyClass::Secret),
            "unwrapped",
        ),
        &seeding(&editor, &templates),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert_eq!(err.message, "interrupted");
    assert_eq!(editor.titles().len(), 1);
    assert!(calls_of(&provider, "unwrap_key").is_empty());
}

#[test]
fn test_load_wrapped_skips_the_editor_for_memory_targets() {
    let provider = make_provider("mem", "memory");
    let kek = import_aes(provider.as_ref(), "aeskek");
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let entry = entry_for("kwp");
    wrapload::load_wrapped(
        provider.as_ref(),
        job(
            &kek,
            &entry,
            &[0; 40],
            (KeyAlgorithm::Aes, KeyClass::Secret),
            "unwrapped",
        ),
        &seeding(&editor, &templates),
    )
    .unwrap();
    assert!(editor.titles().is_empty());
}

#[test]
fn test_load_wrapped_threads_mechanism_params_and_identity() {
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let entry = entry_for("gcm");
    let mut unwrap_job = job(
        &kek,
        &entry,
        &[0x11; 48],
        (KeyAlgorithm::Aes, KeyClass::Secret),
        "unwrapped",
    );
    unwrap_job.params = gcm_params();
    unwrap_job.key_id = Some(vec![0x0a, 0x0b]);
    wrapload::load_wrapped(provider.as_ref(), unwrap_job, &seeding(&editor, &templates)).unwrap();
    let call = &calls_of(&provider, "unwrap_key")[0];
    // FakeProvider's frozen call encoding: (method, kek ref, mech name, blob len, …)
    assert_eq!(call[1], kek.key_ref.display());
    assert_eq!(call[2], "AES-GCM");
    assert_eq!(call[3], "48B");
    let info = provider.find_key(&KeySelector::label("unwrapped")).unwrap();
    assert_eq!(info.key_ref.key_id, Some(vec![0x0a, 0x0b]));
}

#[test]
fn test_load_wrapped_rejects_a_result_class_the_entry_forbids() {
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let entry = WrapMechEntry {
        spec: entry_for("kwp").spec,
        kek_algorithm: KeyAlgorithm::Aes,
        unwrap_kek_class: KeyClass::Secret,
        wrap_kek_classes: BTreeSet::from([KeyClass::Secret]),
        result_classes: BTreeSet::from([KeyClass::Secret]),
    };
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let err = wrapload::load_wrapped(
        provider.as_ref(),
        job(
            &kek,
            &entry,
            &[0; 40],
            (KeyAlgorithm::Rsa, KeyClass::Private),
            "nope",
        ),
        &seeding(&editor, &templates),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(err.message, "AES-KEY-WRAP-PAD cannot unwrap a private key");
    assert!(editor.titles().is_empty(), "refused before the editor");
}

// ---------------------------------------------------------------------------------------
// wrap direction (§5.6 export --kek)
// ---------------------------------------------------------------------------------------

#[test]
fn test_wrap_candidates_need_the_public_half_for_rsa() {
    let provider = hsm();
    generate_pair(provider.as_ref(), "pair");
    let private = find_class(provider.as_ref(), "pair", KeyClass::Private);
    let public = find_class(provider.as_ref(), "pair", KeyClass::Public);
    assert_eq!(
        clis(&wrapload::candidates(
            &public,
            provider.as_ref(),
            Direction::Wrap
        )),
        ["oaep", "pkcs1"]
    );
    // the private half wraps nothing (it is the unwrap side)
    assert!(wrapload::candidates(&private, provider.as_ref(), Direction::Wrap).is_empty());
}

#[test]
fn test_wrap_candidates_accept_a_certificate_as_the_public_key() {
    // §4.3: certificates stand in wherever a public key is accepted.
    let provider = hsm();
    let cert = import_cert(provider.as_ref(), "trust");
    assert_eq!(
        clis(&wrapload::candidates(
            &cert,
            provider.as_ref(),
            Direction::Wrap
        )),
        ["oaep", "pkcs1"]
    );
}

#[test]
fn test_aes_kek_candidates_are_direction_independent() {
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let both = ["kw", "kwp", "cbc", "gcm"];
    assert_eq!(
        clis(&wrapload::candidates(
            &kek,
            provider.as_ref(),
            Direction::Wrap
        )),
        both
    );
    assert_eq!(
        clis(&wrapload::candidates(
            &kek,
            provider.as_ref(),
            Direction::Unwrap
        )),
        both
    );
}

#[test]
fn test_resolve_mech_wrap_refuses_the_private_half_with_a_pub_hint() {
    let provider = hsm();
    generate_pair(provider.as_ref(), "pair");
    let private = find_class(provider.as_ref(), "pair", KeyClass::Private);
    let err =
        wrapload::resolve_mech("oaep", &private, provider.as_ref(), Direction::Wrap).unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
    assert!(
        err.message.contains("RSA-OAEP wrap needs"),
        "{}",
        err.message
    );
    // §4.3 note: the class tokens sorted by as_str() — "certificate or public"
    assert_eq!(
        err.message,
        "RSA-OAEP wrap needs a certificate or public rsa KEK; 'hsm:pair#00000001' is a \
         private rsa key"
    );
    assert!(hint(&err).contains("pair:pub"));
    assert_eq!(
        hint(&err),
        "wrapping uses the public half: `--kek pair:pub`"
    );
}

#[test]
fn wrap_mismatch_on_another_algorithm_gives_the_general_hint() {
    // r2 addition: an AES KEK naming an RSA mechanism gets the wrap requirements line.
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let err =
        wrapload::resolve_mech("pkcs1", &kek, provider.as_ref(), Direction::Wrap).unwrap_err();
    assert_eq!(
        hint(&err),
        "AES secret KEKs wrap via kw/kwp/cbc/gcm; RSA wraps with the PUBLIC half — select it \
         explicitly, e.g. `--kek <label>:pub` (a certificate also works)"
    );
}

#[test]
fn test_resolve_mech_wrap_accepts_the_public_half() {
    let provider = hsm();
    let public = import_rsa_public(provider.as_ref(), "rsapub");
    let entry =
        wrapload::resolve_mech("oaep", &public, provider.as_ref(), Direction::Wrap).unwrap();
    assert_eq!(entry.spec.mechanism, "RSA-OAEP");
}

#[test]
fn test_resolve_mech_unwrap_still_refuses_the_public_half() {
    let provider = hsm();
    let public = import_rsa_public(provider.as_ref(), "rsapub");
    let err =
        wrapload::resolve_mech("oaep", &public, provider.as_ref(), Direction::Unwrap).unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
    assert!(
        err.message.contains("RSA-OAEP unwrap needs"),
        "{}",
        err.message
    );
}

#[test]
fn test_select_mech_wrap_lists_the_wrap_candidates() {
    let provider = hsm();
    let public = import_rsa_public(provider.as_ref(), "rsapub");
    let io = ScriptedIo::new(["pkcs1 — RSA PKCS#1 v1.5 wrapped blob"]);
    let entry = wrapload::select_mech(&io, &public, provider.as_ref(), Direction::Wrap).unwrap();
    assert_eq!(entry.spec.cli_name, "pkcs1");
}

#[test]
fn test_select_mech_wrap_without_candidates_names_the_direction() {
    let small = limited(&["AES-CMAC"]);
    let kek = import_aes(small.as_ref(), "aeskek");
    let err = wrapload::select_mech(&ScriptedIo::empty(), &kek, small.as_ref(), Direction::Wrap)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(
        err.message.contains("no wrap mechanisms available"),
        "{}",
        err.message
    );
    assert!(hint(&err).starts_with("AES secret KEKs wrap via"));
}

#[test]
fn test_refuse_non_wrappable_only_blocks_non_extractable() {
    let provider = hsm();
    let imported = |label: &str, sensitive: bool, extractable: bool| -> KeyInfo {
        provider
            .import_key(
                &aes_material(&aes_32()),
                label,
                Some(&policy(sensitive, extractable)),
                None,
            )
            .unwrap()
    };
    // THE point of §5.6 wrapped export: sensitive but extractable is wrappable
    let sensitive = imported("sensitive", true, true);
    assert!(!sensitive.exportable, "a plain export would be refused");
    wrapload::refuse_non_wrappable(&sensitive).unwrap();

    wrapload::refuse_non_wrappable(&imported("open", false, true)).unwrap();

    let locked = imported("locked", true, false);
    let err = wrapload::refuse_non_wrappable(&locked).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(err.message.contains("not extractable"), "{}", err.message);
    assert_eq!(
        err.message,
        "key 'hsm:locked#00000003' is not extractable and cannot be wrapped"
    );
    assert_eq!(
        hint(&err),
        "CKA_EXTRACTABLE=false forbids the key leaving the token in any form"
    );
}

#[test]
fn test_wrap_for_export_round_trips_through_the_provider() {
    let provider = make_provider("mem", "memory");
    let kek = import_aes(provider.as_ref(), "aeskek");
    let target = import_aes_data(provider.as_ref(), "target", &[0xab; 32]);
    let blob = wrapload::wrap_for_export(
        provider.as_ref(),
        &kek,
        &entry_for("kwp"),
        Params::new(),
        &target,
    )
    .unwrap();
    let restored = provider
        .unwrap_key(
            &kek,
            &MechanismInvocation::new("AES-KEY-WRAP-PAD", Params::new()),
            &blob,
            &UnwrapRequest::new(KeyAlgorithm::Aes, KeyClass::Secret, "restored"),
        )
        .unwrap();
    assert_eq!(
        *provider.export_key(&restored).unwrap().data,
        vec![0xab; 32]
    );
}

#[test]
fn test_wrap_for_export_threads_mechanism_params() {
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let target = import_aes(provider.as_ref(), "target");
    wrapload::wrap_for_export(
        provider.as_ref(),
        &kek,
        &entry_for("gcm"),
        gcm_params(),
        &target,
    )
    .unwrap();
    let call = &calls_of(&provider, "wrap_key")[0];
    assert_eq!(call[1], kek.key_ref.display());
    assert_eq!(call[2], "AES-GCM");
}

#[test]
fn test_wrap_for_export_refuses_public_and_certificate_targets() {
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let public = import_rsa_public(provider.as_ref(), "rsapub");
    let cert = import_cert(provider.as_ref(), "trust");
    for target in [&public, &cert] {
        let err = wrapload::wrap_for_export(
            provider.as_ref(),
            &kek,
            &entry_for("kwp"),
            Params::new(),
            target,
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
        assert!(
            err.message.contains("only secret and private"),
            "{}",
            err.message
        );
        assert!(hint(&err).contains("--kek"));
    }
    assert!(calls_of(&provider, "wrap_key").is_empty());
}

#[test]
fn test_wrap_for_export_refuses_a_non_extractable_target() {
    let provider = hsm();
    let kek = import_aes(provider.as_ref(), "aeskek");
    let locked_template = KeyTemplate::new(vec![TemplateAttr::new(
        "CKA_EXTRACTABLE",
        AttrKind::Bool,
        AttrValue::Bool(false),
    )]);
    let locked = provider
        .import_key(
            &aes_material(&aes_32()),
            "locked",
            Some(&locked_template),
            None,
        )
        .unwrap();
    let err = wrapload::wrap_for_export(
        provider.as_ref(),
        &kek,
        &entry_for("kwp"),
        Params::new(),
        &locked,
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(err.message.contains("not extractable"), "{}", err.message);
    // pre-flight: the provider is never asked
    assert!(calls_of(&provider, "wrap_key").is_empty());
}

// ---------------------------------------------------------------------------------------
// test_objects_services.py — wrapload part
// ---------------------------------------------------------------------------------------

fn other_key(provider: &FakeProvider) -> KeyInfo {
    // An unmodelled-key-type object via the sanctioned FakeProvider backdoor.
    provider.store_key_unchecked(
        &KeyMaterial::new(KeyAlgorithm::Other, KeyClass::Secret, vec![b'x'; 24]),
        "des3",
        None,
        Some(&[0x01]),
    )
}

#[test]
fn test_export_and_wrap_refuse_unmodelled_key_types() {
    let mem = FakeProvider::new("mem");
    let info = other_key(&mem);
    let err = keyexport::export_bytes(&mem, &info, "auto", false, None).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("not supported"), "{}", err.message);
    let err = wrapload::refuse_non_wrappable(&info).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(
        err.message,
        "key type unknown of 'mem:des3#01' is not supported by r2 and cannot be wrapped"
    );
    // a PKCS#11 object carries its CKK symbol, rendered verbatim (c2's str())
    let mut des3 = info.clone();
    des3.attributes
        .insert("CKA_KEY_TYPE".into(), AttrValue::Symbol("CKK_DES3".into()));
    let err = wrapload::refuse_non_wrappable(&des3).unwrap_err();
    assert_eq!(
        err.message,
        "key type CKK_DES3 of 'mem:des3#01' is not supported by r2 and cannot be wrapped"
    );
    assert_eq!(
        hint(&err),
        "objects of unsupported key types can be listed and deleted only"
    );
}

#[test]
fn test_wrapload_generic_hint_and_data_refusal() {
    assert_eq!(
        wrapload::result_by_hint("generic"),
        Some((KeyAlgorithm::Generic, KeyClass::Secret))
    );
    let mem = FakeProvider::new("mem");
    let value = b"opaque bytes \x00\x01\x02 -- not a key".to_vec();
    let info = mem
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, value),
            "blob",
            None,
            None,
        )
        .unwrap();
    let err = wrapload::refuse_non_wrappable(&info).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(hint(&err).contains("data objects"));
    assert_eq!(
        err.message,
        "only secret and private keys are wrapped; 'mem:blob' is a data object"
    );
}

// ---------------------------------------------------------------------------------------
// r2 additions: every table row round-trips on the real MemoryProvider
// ---------------------------------------------------------------------------------------

fn memory_round_trip(cli: &str, kek: &KeyInfo, unwrap_kek: &KeyInfo, provider: &MemoryProvider) {
    let params: Params = match cli {
        "cbc" => {
            let mut p = Params::new();
            p.insert("iv".into(), ParamValue::Bytes(vec![7; 16]));
            p.insert("padding".into(), ParamValue::Enum("pkcs7".into()));
            p
        }
        "gcm" => gcm_params(),
        "oaep" => {
            let mut p = Params::new();
            p.insert("hash".into(), ParamValue::Enum("sha256".into()));
            p.insert("mgf_hash".into(), ParamValue::Enum("sha256".into()));
            p.insert("label".into(), ParamValue::Bytes(Vec::new()));
            p
        }
        _ => Params::new(),
    };
    let target = import_aes_data(provider, &format!("target-{cli}"), &[0x5a; 32]);
    let entry = entry_for(cli);
    let blob = wrapload::wrap_for_export(provider, kek, &entry, params.clone(), &target).unwrap();
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let mut unwrap_job = job(
        unwrap_kek,
        &entry,
        &blob,
        (KeyAlgorithm::Aes, KeyClass::Secret),
        &format!("back-{cli}"),
    );
    unwrap_job.params = params;
    let info = wrapload::load_wrapped(provider, unwrap_job, &seeding(&editor, &templates)).unwrap();
    assert_eq!(
        *provider.export_key(&info).unwrap().data,
        vec![0x5a; 32],
        "{cli}"
    );
}

#[test]
fn every_row_round_trips_on_the_memory_provider() {
    let provider = MemoryProvider::new("mem");
    let aes_kek = import_aes(&provider, "aeskek");
    for cli in ["kw", "kwp", "cbc", "gcm"] {
        memory_round_trip(cli, &aes_kek, &aes_kek, &provider);
    }
    let private = import_rsa_private(&provider, "rsakek");
    let public = import_rsa_public(&provider, "rsakek-pub");
    for cli in ["oaep", "pkcs1"] {
        memory_round_trip(cli, &public, &private, &provider);
    }
}

#[test]
fn private_key_payload_is_pkcs8_der_on_the_memory_provider() {
    let provider = MemoryProvider::new("mem");
    let kek = import_aes(&provider, "aeskek");
    let key = import_rsa_private(&provider, "rsakey");
    let entry = entry_for("kwp");
    let blob = wrapload::wrap_for_export(&provider, &kek, &entry, Params::new(), &key).unwrap();
    let editor = RecordingEditor::new();
    let templates = make_templates();
    let info = wrapload::load_wrapped(
        &provider,
        job(
            &kek,
            &entry,
            &blob,
            (KeyAlgorithm::Rsa, KeyClass::Private),
            "back",
        ),
        &seeding(&editor, &templates),
    )
    .unwrap();
    assert_eq!(*provider.export_key(&info).unwrap().data, rsa_pkcs8_der());
}
