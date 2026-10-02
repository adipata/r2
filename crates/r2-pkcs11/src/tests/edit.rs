//! read_key_template / update_key / read_full_template over the FakeBackend: ports of c2
//! tests/unit/pkcs11/test_provider_edit.py (all), the edit/dump cases of
//! test_provider_objects.py (TestReadFullTemplate) and test_objects.py (data-object edit
//! surfaces, CKA_CERTIFICATE_CATEGORY byte path) — §5.15, §5.16.
use std::collections::BTreeMap;

use indexmap::IndexMap;
use r2_config::model::CustomAttributeDef;
use r2_core::error::ErrorKind;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_provider::{AuthState, KeySelector, Provider};

use super::{
    USER_PIN, boolean, bytes_attr, exportable, logged_in, object_of, pin, provider_over,
    provider_with, str_attr, token_at, tpl, ul, ulong_attr,
};
use crate::backend::fake::FakeBackend;
use crate::ckr::rv;

const CKA_CLASS: u64 = 0x0000;
const CKA_TOKEN: u64 = 0x0001;
const CKA_APPLICATION: u64 = 0x0010;
const CKA_KEY_TYPE: u64 = 0x0100;
const CKA_ID: u64 = 0x0102;
const CKA_SENSITIVE: u64 = 0x0103;
const CKA_ENCRYPT: u64 = 0x0104;
const CKA_DECRYPT: u64 = 0x0105;
const CKA_CERTIFICATE_CATEGORY: u64 = 0x0087;
const CKA_LOCAL: u64 = 0x0163;
const CKA_NEVER_EXTRACTABLE: u64 = 0x0164;
const CKA_ALWAYS_SENSITIVE: u64 = 0x0165;
const CKA_MODIFIABLE: u64 = 0x0170;
const VENDOR_ATTR: u64 = 0x8000_0101;

fn aes_key() -> Vec<u8> {
    (0u8..32).collect()
}

fn aes() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, aes_key());
    material.size_bits = Some(256);
    material
}

fn data_material() -> KeyMaterial {
    KeyMaterial::new(
        KeyAlgorithm::None,
        KeyClass::Data,
        b"opaque data object value \x00\xff".to_vec(),
    )
}

fn certificate() -> KeyMaterial {
    let (_pkcs8, cert) = r2_testkit::fixtures::rsa_pkcs8_and_cert();
    let mut material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert);
    material.size_bits = Some(2048);
    material
}

fn vendor_provider(kind: AttrKind) -> (std::rc::Rc<FakeBackend>, crate::Pkcs11Provider) {
    let backend = std::rc::Rc::new(FakeBackend::new());
    let mut custom = IndexMap::new();
    custom.insert(
        "CKA_ACME_USAGE".to_string(),
        CustomAttributeDef {
            code: VENDOR_ATTR,
            kind,
        },
    );
    let provider = provider_with(&backend, BTreeMap::new(), custom);
    let token = token_at(&provider, 0);
    provider.login(&token, &pin(USER_PIN), false).unwrap();
    (backend, provider)
}

fn applied(result: &r2_provider::KeyEditResult) -> Vec<(String, bool)> {
    result
        .outcomes
        .iter()
        .map(|o| (o.name.clone(), o.applied))
        .collect()
}

fn pairs(items: &[(&str, bool)]) -> Vec<(String, bool)> {
    items.iter().map(|(n, a)| ((*n).to_string(), *a)).collect()
}

// ---------------------------------------------------------------------------
// TestReadKeyTemplate
// ---------------------------------------------------------------------------

#[test]
fn read_key_template_secret_key_snapshot() {
    let (_backend, provider) = logged_in();
    let info = provider
        .import_key(
            &aes(),
            "rt-secret",
            Some(&tpl(vec![
                boolean("CKA_SENSITIVE", true),
                boolean("CKA_EXTRACTABLE", true),
                boolean("CKA_ENCRYPT", true),
            ])),
            Some(&[0x0a]),
        )
        .unwrap();
    let template = provider.read_key_template(&info).unwrap();
    let class = template.get("CKA_CLASS").unwrap();
    assert!(class.locked);
    assert_eq!(class.value, AttrValue::Symbol("CKO_SECRET_KEY".into()));
    assert_eq!(class.kind, AttrKind::Ulong);
    let key_type = template.get("CKA_KEY_TYPE").unwrap();
    assert!(key_type.locked);
    assert_eq!(key_type.value, AttrValue::Symbol("CKK_AES".into()));
    assert_eq!(
        template.get("CKA_LABEL").unwrap().value,
        AttrValue::Str("rt-secret".into())
    );
    let id = template.get("CKA_ID").unwrap();
    assert!(id.enabled);
    assert_eq!(id.value, AttrValue::Bytes(vec![0x0a]));
    assert_eq!(
        template.get("CKA_SENSITIVE").unwrap().value,
        AttrValue::Bool(true)
    );
    assert_eq!(
        template.get("CKA_ENCRYPT").unwrap().value,
        AttrValue::Bool(true)
    );
    // never stored by the fake token → skipped, not invented
    assert!(template.get("CKA_MODIFIABLE").is_none());
    // row order: locked class/type, label, id, then the class's policy attrs
    let names: Vec<&str> = template.attrs.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(
        names[..4],
        ["CKA_CLASS", "CKA_KEY_TYPE", "CKA_LABEL", "CKA_ID"]
    );
}

#[test]
fn read_key_template_certificate_has_no_key_type_row() {
    let (_backend, provider) = logged_in();
    let cert = provider
        .import_key(&certificate(), "rt-cert", None, Some(&[0x0b]))
        .unwrap();
    let template = provider.read_key_template(&cert).unwrap();
    assert_eq!(
        template.get("CKA_CLASS").unwrap().value,
        AttrValue::Symbol("CKO_CERTIFICATE".into())
    );
    assert!(template.get("CKA_KEY_TYPE").is_none()); // certs carry no key type (§4.7)
}

#[test]
fn read_key_template_vendor_attribute_decoded() {
    let (_backend, provider) = vendor_provider(AttrKind::Bytes);
    let info = provider
        .import_key(
            &aes(),
            "rt-vendor",
            Some(&tpl(vec![TemplateAttr::new(
                "CKA_ACME_USAGE",
                AttrKind::Bytes,
                AttrValue::Bytes(vec![1, 2]),
            )])),
            None,
        )
        .unwrap();
    let template = provider.read_key_template(&info).unwrap();
    assert_eq!(
        template.get("CKA_ACME_USAGE").unwrap().value,
        AttrValue::Bytes(vec![1, 2])
    );
}

#[test]
fn read_key_template_absent_id_is_a_disabled_empty_row() {
    let (backend, provider) = logged_in();
    backend.plant_object(
        0,
        vec![
            (CKA_CLASS, ul(4)),
            (CKA_KEY_TYPE, ul(0x1F)),
            (0x0003, b"noid".to_vec()),
            (0x0161, ul(16)),
        ],
        &[1; 16],
    );
    let info = provider.find_key(&KeySelector::label("noid")).unwrap();
    let template = provider.read_key_template(&info).unwrap();
    let id = template.get("CKA_ID").unwrap();
    assert!(!id.enabled);
    assert_eq!(id.value, AttrValue::Bytes(Vec::new()));
}

// ---------------------------------------------------------------------------
// TestUpdateKey
// ---------------------------------------------------------------------------

#[test]
fn update_key_usage_flag_applied() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&aes(), "up-flag", None, Some(&[1]))
        .unwrap();
    let result = provider
        .update_key(&info, &tpl(vec![boolean("CKA_DECRYPT", true)]))
        .unwrap();
    assert_eq!(applied(&result), pairs(&[("CKA_DECRYPT", true)]));
    assert_eq!(object_of(&backend, "up-flag")[&CKA_DECRYPT], vec![1]);
}

#[test]
fn update_key_partial_failure_continues_per_attribute() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(
            &aes(),
            "up-partial",
            Some(&tpl(vec![
                boolean("CKA_SENSITIVE", true),
                boolean("CKA_EXTRACTABLE", true),
            ])),
            Some(&[2]),
        )
        .unwrap();
    let result = provider
        .update_key(
            &info,
            &tpl(vec![
                boolean("CKA_DECRYPT", true),
                // SoftHSM one-direction rule: SENSITIVE never goes true→false
                boolean("CKA_SENSITIVE", false),
                boolean("CKA_ENCRYPT", true),
            ]),
        )
        .unwrap();
    assert_eq!(
        applied(&result),
        pairs(&[
            ("CKA_DECRYPT", true),
            ("CKA_SENSITIVE", false),
            ("CKA_ENCRYPT", true)
        ])
    );
    let refused = &result.outcomes[1];
    let detail = refused.detail.as_deref().unwrap();
    assert!(detail.contains("CKR_ATTRIBUTE_READ_ONLY"));
    assert_eq!(
        detail,
        "token forbids changing this attribute (CKR_ATTRIBUTE_READ_ONLY)"
    );
    let object = object_of(&backend, "up-partial");
    assert_eq!(object[&CKA_DECRYPT], vec![1]);
    assert_eq!(object[&CKA_ENCRYPT], vec![1]);
    assert_eq!(object[&CKA_SENSITIVE], vec![1]); // unchanged
}

#[test]
fn update_key_rename_updates_object_and_info() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&aes(), "up-old", None, Some(&[3]))
        .unwrap();
    let result = provider
        .update_key(
            &info,
            &tpl(vec![
                str_attr("CKA_LABEL", "up-new"),
                bytes_attr("CKA_ID", &[0x33]),
            ]),
        )
        .unwrap();
    assert!(result.outcomes.iter().all(|o| o.applied));
    assert_eq!(result.key.key_ref.label, "up-new");
    assert_eq!(result.key.key_ref.key_id, Some(vec![0x33]));
    assert_eq!(object_of(&backend, "up-new")[&CKA_ID], vec![0x33]);
    // one batched call for both identity rows
    let sets = backend
        .calls()
        .iter()
        .filter(|c| **c == "set_attrs")
        .count();
    assert_eq!(sets, 1);
}

#[test]
fn update_key_identity_batch_is_all_or_nothing() {
    let (backend, provider) = logged_in();
    backend.set_read_only(&[
        CKA_CLASS,
        CKA_KEY_TYPE,
        CKA_TOKEN,
        CKA_LOCAL,
        CKA_MODIFIABLE,
        CKA_NEVER_EXTRACTABLE,
        CKA_ALWAYS_SENSITIVE,
        CKA_ID,
    ]);
    let info = provider
        .import_key(&aes(), "up-batch", None, Some(&[4]))
        .unwrap();
    let result = provider
        .update_key(
            &info,
            &tpl(vec![
                str_attr("CKA_LABEL", "up-batch-new"),
                bytes_attr("CKA_ID", &[0x44]),
            ]),
        )
        .unwrap();
    assert_eq!(
        applied(&result),
        pairs(&[("CKA_LABEL", false), ("CKA_ID", false)])
    );
    // label untouched too
    assert_eq!(object_of(&backend, "up-batch")[&CKA_ID], vec![4]);
    assert_eq!(result.key.key_ref.label, "up-batch");
}

#[test]
fn update_key_duplicate_identity_precheck_mutates_nothing() {
    let (backend, provider) = logged_in();
    provider
        .import_key(&aes(), "up-taken", None, Some(&[5]))
        .unwrap();
    let info = provider
        .import_key(&aes(), "up-source", None, Some(&[5]))
        .unwrap();
    let err = provider
        .update_key(
            &info,
            &tpl(vec![
                str_attr("CKA_LABEL", "up-taken"),
                boolean("CKA_DECRYPT", true),
            ]),
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::DuplicateKey);
    assert_eq!(
        err.message,
        "a secret object with label 'up-taken' and id 0x05 already exists on hsm"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("pick a different id or label, or delete the existing object first")
    );
    // nothing applied before the guard
    assert!(!object_of(&backend, "up-source").contains_key(&CKA_DECRYPT));
}

#[test]
fn update_key_label_only_rename_keeping_id_is_allowed() {
    let (_backend, provider) = logged_in();
    provider
        .import_key(&aes(), "up-other", None, Some(&[0x66]))
        .unwrap();
    let info = provider
        .import_key(&aes(), "up-move", None, Some(&[6]))
        .unwrap();
    let result = provider
        .update_key(&info, &tpl(vec![str_attr("CKA_LABEL", "up-other")]))
        .unwrap();
    assert!(result.outcomes[0].applied); // distinct ids → no twin (§4.7)
    let found = provider
        .find_key(&KeySelector::label("up-other").with_id(Some(vec![6])))
        .unwrap();
    assert_eq!(found.key_ref.key_id, Some(vec![6]));
}

#[test]
fn update_key_locked_names_rejected() {
    let (_backend, provider) = logged_in();
    let info = provider
        .import_key(&aes(), "up-locked", None, Some(&[7]))
        .unwrap();
    let err = provider
        .update_key(
            &info,
            &tpl(vec![ulong_attr(
                "CKA_CLASS",
                AttrValue::Str("CKO_DATA".into()),
            )]),
        )
        .unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(err.message, "CKA_CLASS cannot be edited after creation");
    assert_eq!(err.param_name(), Some("CKA_CLASS"));
}

#[test]
fn update_key_empty_identity_values_rejected() {
    let (_backend, provider) = logged_in();
    let info = provider
        .import_key(&aes(), "up-empty", None, Some(&[8]))
        .unwrap();
    let err = provider
        .update_key(&info, &tpl(vec![str_attr("CKA_LABEL", "")]))
        .unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(err.message, "CKA_LABEL expects a non-empty string");
    let err = provider
        .update_key(&info, &tpl(vec![bytes_attr("CKA_ID", b"")]))
        .unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(err.message, "CKA_ID expects non-empty bytes");
    assert_eq!(err.hint.as_deref(), Some("use a 0x… hex value"));
}

#[test]
fn update_key_vendor_attribute_encoded_on_write() {
    let (backend, provider) = vendor_provider(AttrKind::Bytes);
    let info = provider
        .import_key(&aes(), "up-vendor", None, Some(&[9]))
        .unwrap();
    let result = provider
        .update_key(
            &info,
            &tpl(vec![TemplateAttr::new(
                "CKA_ACME_USAGE",
                AttrKind::Bytes,
                AttrValue::Bytes(vec![0xaa, 0xbb]),
            )]),
        )
        .unwrap();
    assert!(result.outcomes[0].applied);
    assert_eq!(
        object_of(&backend, "up-vendor")[&VENDOR_ATTR],
        vec![0xaa, 0xbb]
    );
}

#[test]
fn update_key_keep_pin_recovery_retries_whole_edit_once() {
    let backend = std::rc::Rc::new(FakeBackend::new());
    let provider = provider_over(&backend);
    let token = token_at(&provider, 0);
    provider.login(&token, &pin(USER_PIN), true).unwrap();
    let info = provider
        .import_key(&aes(), "up-recover", None, Some(&[0x0c]))
        .unwrap();
    backend.invalidate_session(); // the token dropped the session
    let result = provider
        .update_key(
            &info,
            &tpl(vec![
                boolean("CKA_DECRYPT", true),
                str_attr("CKA_LABEL", "up-recovered"),
            ]),
        )
        .unwrap();
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
    assert_eq!(backend.sessions_opened(), 2); // a fresh session was opened
    // outcomes come from the retried closure only — never duplicated
    assert_eq!(
        applied(&result),
        pairs(&[("CKA_DECRYPT", true), ("CKA_LABEL", true)])
    );
    assert_eq!(result.key.key_ref.label, "up-recovered");
}

#[test]
fn update_key_recovery_after_rename_landed_re_resolves_new_identity() {
    // the session dies right after the identity write: the retried closure no longer
    // finds the old ref and must re-resolve under the NEW identity
    let backend = std::rc::Rc::new(FakeBackend::new());
    let provider = provider_over(&backend);
    let token = token_at(&provider, 0);
    provider.login(&token, &pin(USER_PIN), true).unwrap();
    let info = provider
        .import_key(&aes(), "up-mid", None, Some(&[0x0e]))
        .unwrap();
    backend.invalidate_after_next_set(); // the write landed, then the session died
    let result = provider
        .update_key(&info, &tpl(vec![str_attr("CKA_LABEL", "up-mid2")]))
        .unwrap();
    assert_eq!(applied(&result), pairs(&[("CKA_LABEL", true)]));
    assert_eq!(result.key.key_ref.label, "up-mid2");
    let found = provider
        .find_key(&KeySelector::label("up-mid2").with_id(Some(vec![0x0e])))
        .unwrap();
    assert_eq!(found.key_ref.label, "up-mid2");
}

#[test]
fn update_key_without_keep_pin_drops_to_logged_out() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&aes(), "up-lost", None, Some(&[0x0f]))
        .unwrap();
    backend.invalidate_session();
    let err = provider
        .update_key(&info, &tpl(vec![boolean("CKA_DECRYPT", true)]))
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert_eq!(err.message, "session lost — login again");
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
}

#[test]
fn update_key_second_session_failure_drops_to_logged_out() {
    // §5.2: the edit is retried once after recovery; a second failure drops the login
    let backend = std::rc::Rc::new(FakeBackend::new());
    let provider = provider_over(&backend);
    let token = token_at(&provider, 0);
    provider.login(&token, &pin(USER_PIN), true).unwrap();
    let info = provider
        .import_key(&aes(), "up-twice", None, Some(&[0x11]))
        .unwrap();
    backend.fail_always("set_attrs", rv::CKR_SESSION_HANDLE_INVALID);
    let err = provider
        .update_key(&info, &tpl(vec![boolean("CKA_DECRYPT", true)]))
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert_eq!(err.message, "session lost — login again");
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    assert_eq!(
        backend
            .calls()
            .iter()
            .filter(|c| **c == "set_attrs")
            .count(),
        2
    );
    backend.clear_failures();
    provider.login(&token, &pin(USER_PIN), false).unwrap();
    let result = provider
        .update_key(&info, &tpl(vec![boolean("CKA_DECRYPT", true)]))
        .unwrap();
    assert!(result.outcomes[0].applied);
}

#[test]
fn update_key_auth_required_aborts_the_edit() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&aes(), "up-auth", None, Some(&[0x10]))
        .unwrap();
    backend.fail_next("set_attrs", rv::CKR_USER_NOT_LOGGED_IN);
    let err = provider
        .update_key(
            &info,
            &tpl(vec![
                boolean("CKA_DECRYPT", true),
                boolean("CKA_ENCRYPT", true),
            ]),
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert_eq!(err.message, "login required: run `login hsm`");
    // the second attribute was never attempted
    assert_eq!(
        backend
            .calls()
            .iter()
            .filter(|c| **c == "set_attrs")
            .count(),
        1
    );
}

// ---------------------------------------------------------------------------
// TestCkrMapping
// ---------------------------------------------------------------------------

#[test]
fn attribute_read_only_maps_to_friendly_pkcs11_error() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&aes(), "map-ro", None, Some(&[0x0d]))
        .unwrap();
    backend.fail_next("find_objects", rv::CKR_ATTRIBUTE_READ_ONLY);
    let err = provider.export_key(&info).unwrap_err();
    assert_eq!(err.kind.class_name(), "Pkcs11Error");
    assert_eq!(
        err.ckr().map(|(_, n)| n.to_string()).as_deref(),
        Some("CKR_ATTRIBUTE_READ_ONLY")
    );
    assert!(
        err.message
            .contains("token forbids changing this attribute")
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("the attribute is fixed after object creation on this token")
    );
}

// ---------------------------------------------------------------------------
// data objects (c2 test_objects.py TestDataObjects::test_edit_surfaces)
// ---------------------------------------------------------------------------

#[test]
fn data_object_edit_surfaces() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(
            &data_material(),
            "d5",
            Some(&tpl(vec![str_attr("CKA_APPLICATION", "a")])),
            None,
        )
        .unwrap();
    let seed = provider.read_key_template(&info).unwrap();
    let names: Vec<&str> = seed.attrs.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names[..2], ["CKA_CLASS", "CKA_LABEL"]); // no CKA_KEY_TYPE, no CKA_ID
    assert!(!names.contains(&"CKA_ID"));
    assert!(seed.get("CKA_APPLICATION").is_some());
    let full = provider.read_full_template(&info).unwrap();
    let full_names: Vec<&str> = full.attrs.iter().map(|a| a.name.as_str()).collect();
    assert!(!full_names.contains(&"CKA_KEY_TYPE") && !full_names.contains(&"CKA_ID"));
    assert_eq!(
        full.get("CKA_CLASS").unwrap().value,
        AttrValue::Symbol("CKO_DATA".into())
    );
    let result = provider
        .update_key(&info, &tpl(vec![str_attr("CKA_APPLICATION", "b")]))
        .unwrap();
    assert_eq!(
        result
            .outcomes
            .iter()
            .map(|o| o.applied)
            .collect::<Vec<_>>(),
        [true]
    );
    assert_eq!(object_of(&backend, "d5")[&CKA_APPLICATION], b"b".to_vec());
    let err = provider
        .update_key(&info, &tpl(vec![bytes_attr("CKA_ID", &[1])]))
        .unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(err.message, "data objects carry no CKA_ID (§4.3)");
    assert_eq!(err.param_name(), Some("CKA_ID"));
    assert_eq!(
        err.hint.as_deref(),
        Some("data objects are identified by label alone")
    );
}

// ---------------------------------------------------------------------------
// TestReadFullTemplate
// ---------------------------------------------------------------------------

#[test]
fn full_dump_covers_catalog_and_identity() {
    let (_backend, provider) = logged_in();
    let info = provider
        .import_key(&aes(), "full-1", Some(&exportable()), Some(&[0x0a, 0x1b]))
        .unwrap();
    let full = provider.read_full_template(&info).unwrap();
    let get = |name: &str| full.get(name).map(|a| a.value.clone());
    // symbolic values (§5.16)
    assert_eq!(
        get("CKA_CLASS"),
        Some(AttrValue::Symbol("CKO_SECRET_KEY".into()))
    );
    assert_eq!(
        get("CKA_KEY_TYPE"),
        Some(AttrValue::Symbol("CKK_AES".into()))
    );
    assert_eq!(get("CKA_LABEL"), Some(AttrValue::Str("full-1".into())));
    assert_eq!(get("CKA_ID"), Some(AttrValue::Bytes(vec![0x0a, 0x1b])));
    assert_eq!(get("CKA_VALUE"), Some(AttrValue::Bytes(aes_key()))); // extractable → readable
    assert_eq!(get("CKA_SENSITIVE"), Some(AttrValue::Bool(false)));
    assert!(get("CKA_MODULUS").is_none()); // absent attrs are skipped, not None-filled
    // CKA_KEY_GEN_MECHANISM of an imported object reads CK_UNAVAILABLE_INFORMATION and is
    // reported numerically (§5.16)
    assert_eq!(
        get("CKA_KEY_GEN_MECHANISM"),
        Some(AttrValue::Ulong(crate::ulong_to_u64(
            cryptoki_sys::CK_UNAVAILABLE_INFORMATION
        )))
    );
    // catalog order, unlocked rows
    let names: Vec<&str> = full.attrs.iter().map(|a| a.name.as_str()).collect();
    let order: Vec<&str> = r2_core::catalog::CKA_CATALOG
        .iter()
        .map(|e| e.name)
        .filter(|n| names.contains(n))
        .collect();
    assert_eq!(names, order);
    assert!(full.attrs.iter().all(|a| !a.locked && a.enabled));
}

#[test]
fn full_dump_skips_refused_value_on_sensitive_key() {
    let (_backend, provider) = logged_in();
    let template = tpl(vec![
        boolean("CKA_SENSITIVE", true),
        boolean("CKA_EXTRACTABLE", false),
    ]);
    let info = provider
        .import_key(&aes(), "full-2", Some(&template), None)
        .unwrap();
    let full = provider.read_full_template(&info).unwrap();
    assert!(full.get("CKA_VALUE").is_none()); // the token refuses it → skipped (§5.16)
    assert_eq!(
        full.get("CKA_SENSITIVE").unwrap().value,
        AttrValue::Bool(true)
    );
}

#[test]
fn full_dump_skips_attributes_whose_read_fails() {
    // c2 `_read_one_attr`: any non-recoverable read failure is a skipped attribute
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&aes(), "full-4", Some(&exportable()), None)
        .unwrap();
    backend.refuse_read(
        info.handle.unwrap(),
        CKA_ENCRYPT,
        rv::CKR_ATTRIBUTE_SENSITIVE,
    );
    backend.refuse_read(info.handle.unwrap(), CKA_SENSITIVE, rv::CKR_GENERAL_ERROR);
    let full = provider.read_full_template(&info).unwrap();
    assert!(full.get("CKA_ENCRYPT").is_none());
    assert!(full.get("CKA_SENSITIVE").is_none());
    assert!(full.get("CKA_LABEL").is_some());
}

#[test]
fn full_dump_includes_vendor_attr() {
    let (_backend, provider) = vendor_provider(AttrKind::Ulong);
    let template = tpl(vec![TemplateAttr::new(
        "CKA_ACME_USAGE",
        AttrKind::Ulong,
        AttrValue::Ulong(7),
    )]);
    let info = provider
        .import_key(&aes(), "full-3", Some(&template), None)
        .unwrap();
    let full = provider.read_full_template(&info).unwrap();
    let vendor = full.get("CKA_ACME_USAGE").unwrap();
    assert_eq!(vendor.kind, AttrKind::Ulong);
    assert_eq!(vendor.value, AttrValue::Ulong(7));
}

// ---------------------------------------------------------------------------
// certificate polish: byte-encoded ULONG attrs (c2 test_objects.py)
// ---------------------------------------------------------------------------

#[test]
fn certificate_category_round_trips_through_the_byte_path() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(
            &certificate(),
            "crt",
            Some(&tpl(vec![ulong_attr(
                "CKA_CERTIFICATE_CATEGORY",
                AttrValue::Ulong(1),
            )])),
            None,
        )
        .unwrap();
    // PyKCS11 cannot encode it: native-endian CK_ULONG bytes
    assert_eq!(object_of(&backend, "crt")[&CKA_CERTIFICATE_CATEGORY], ul(1));
    let full = provider.read_full_template(&info).unwrap();
    assert_eq!(
        full.get("CKA_CERTIFICATE_CATEGORY").unwrap().value,
        AttrValue::Ulong(1)
    );
    assert!(full.get("CKA_KEY_TYPE").is_none());
    let seed = provider.read_key_template(&info).unwrap();
    assert_eq!(
        seed.get("CKA_CERTIFICATE_CATEGORY").unwrap().value,
        AttrValue::Ulong(1)
    );
}

#[test]
fn edit_surfaces_need_a_login() {
    let backend = std::rc::Rc::new(FakeBackend::new());
    let provider = provider_over(&backend);
    let info = r2_core::keys::KeyInfo {
        key_ref: r2_core::keys::KeyRef::new("hsm", "x", None),
        key_class: KeyClass::Secret,
        algorithm: KeyAlgorithm::Aes,
        size_bits: None,
        curve: None,
        exportable: false,
        attributes: BTreeMap::new(),
        handle: None,
    };
    for err in [
        provider.read_key_template(&info).unwrap_err(),
        provider.read_full_template(&info).unwrap_err(),
        provider
            .update_key(&info, &KeyTemplate::default())
            .unwrap_err(),
    ] {
        assert_eq!(err.kind, ErrorKind::AuthRequired);
        assert_eq!(err.message, "login required: run `login hsm`");
    }
}
