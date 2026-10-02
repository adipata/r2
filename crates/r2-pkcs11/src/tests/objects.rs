//! Ports of the non-verb parts of c2 tests/unit/pkcs11/test_provider_objects.py and
//! test_objects.py: template conversion on the wire, material injection, identity
//! resolution, the twin guard and exact-handle re-targeting, generic secrets, CKO_DATA,
//! the `other` catch-all and export.
use std::collections::BTreeMap;
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::CustomAttributeDef;
use r2_core::error::ErrorKind;
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::template::{AttrKind, AttrValue};
use r2_provider::{GenerateRequest, KeySelector, Provider};

use super::{
    USER_PIN, boolean, bytes_attr, exportable, logged_in, object_of, pin, provider_with, str_attr,
    symbol, token_at, tpl, ul, ulong_attr,
};
use crate::backend::fake::FakeBackend;

const CKA_CLASS: u64 = 0x0000;
const CKA_TOKEN: u64 = 0x0001;
const CKA_LABEL: u64 = 0x0003;
const CKA_APPLICATION: u64 = 0x0010;
const CKA_VALUE: u64 = 0x0011;
const CKA_OBJECT_ID: u64 = 0x0012;
const CKA_CERTIFICATE_TYPE: u64 = 0x0080;
const CKA_KEY_TYPE: u64 = 0x0100;
const CKA_SUBJECT: u64 = 0x0101;
const CKA_ID: u64 = 0x0102;
const CKA_SENSITIVE: u64 = 0x0103;
const CKA_WRAP: u64 = 0x0106;
const CKA_MODULUS: u64 = 0x0120;
const CKA_VALUE_LEN: u64 = 0x0161;
const CKA_EXTRACTABLE: u64 = 0x0162;
const CKA_KEY_GEN_MECHANISM: u64 = 0x0166;
const CKA_EC_PARAMS: u64 = 0x0180;
const CKA_EC_POINT: u64 = 0x0181;
const CKA_CERTIFICATE_CATEGORY: u64 = 0x0087;

const CKO_DATA: u64 = 0;
const CKO_CERTIFICATE: u64 = 1;
const CKO_PUBLIC_KEY: u64 = 2;
const CKO_SECRET_KEY: u64 = 4;
const CKK_GENERIC_SECRET: u64 = 0x10;
const CKK_DES3: u64 = 0x15;
const CKK_AES: u64 = 0x1F;
const CKK_SHA256_HMAC: u64 = 0x2B;

fn aes_key() -> Vec<u8> {
    (0u8..32).collect()
}

fn aes() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, aes_key());
    material.size_bits = Some(256);
    material
}

fn generic_key() -> Vec<u8> {
    (64u8..96).collect()
}

fn generic() -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, generic_key())
}

const DATA_VALUE: &[u8] = b"opaque data object value \x00\xff";

fn data() -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, DATA_VALUE.to_vec())
}

fn cert_material(cn: &str) -> (KeyMaterial, Vec<u8>) {
    let pkcs8 = r2_testkit::fixtures::rsa2048_pkcs8();
    let der = r2_testkit::fixtures::self_signed_cert(&pkcs8, cn);
    (KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, der.clone()), der)
}

fn sel(label: &str) -> KeySelector {
    KeySelector::label(label)
}

fn generate(algorithm: KeyAlgorithm, label: &str) -> GenerateRequest {
    GenerateRequest::new(algorithm, label)
}

fn with_size(mut request: GenerateRequest, bits: u32) -> GenerateRequest {
    request.size_bits = Some(bits);
    request
}

fn param_name(err: &r2_core::ConsoleError) -> Option<&str> {
    err.param_name()
}

// ---------------------------------------------------------------------------
// TestTemplateConversion
// ---------------------------------------------------------------------------

#[test]
fn enabled_only_and_disabled_omitted() {
    let (backend, provider) = logged_in();
    let template = tpl(vec![
        ulong_attr("CKA_CLASS", symbol("CKO_SECRET_KEY")),
        ulong_attr("CKA_KEY_TYPE", symbol("CKK_AES")),
        boolean("CKA_TOKEN", true),
        boolean("CKA_WRAP", true).disabled(),
        boolean("CKA_SENSITIVE", true),
        boolean("CKA_EXTRACTABLE", false),
    ]);
    provider.import_key(&aes(), "conv-1", Some(&template), Some(b"\x0a")).unwrap();
    let obj = object_of(&backend, "conv-1");
    assert!(!obj.contains_key(&CKA_WRAP)); // disabled → OMITTED from the call (§4.7)
    assert_eq!(obj[&CKA_TOKEN], [1]);
    // symbolic locked rows resolved to numerics
    assert_eq!(obj[&CKA_CLASS], ul(CKO_SECRET_KEY));
    assert_eq!(obj[&CKA_KEY_TYPE], ul(CKK_AES));
    // loader-injected label/id/material (§4.7)
    assert_eq!(obj[&CKA_LABEL], b"conv-1");
    assert_eq!(obj[&CKA_ID], [0x0a]);
    assert_eq!(obj[&CKA_VALUE], aes_key());
}

#[test]
fn locked_class_mismatch_rejected() {
    let (_backend, provider) = logged_in();
    let template = tpl(vec![ulong_attr("CKA_CLASS", symbol("CKO_PRIVATE_KEY"))]);
    let err = provider.import_key(&aes(), "conv-2", Some(&template), None).unwrap_err();
    assert_eq!(param_name(&err), Some("CKA_CLASS"));
    assert_eq!(
        err.message,
        "template CKA_CLASS ('CKO_PRIVATE_KEY') does not match the secret object being created"
    );
}

#[test]
fn locked_key_type_mismatch_rejected() {
    let (_backend, provider) = logged_in();
    let template = tpl(vec![ulong_attr("CKA_KEY_TYPE", symbol("CKK_RSA"))]);
    let err = provider.import_key(&aes(), "conv-3", Some(&template), None).unwrap_err();
    assert_eq!(param_name(&err), Some("CKA_KEY_TYPE"));
    assert_eq!(
        err.message,
        "template CKA_KEY_TYPE ('CKK_RSA') does not match the aes key being created"
    );
}

#[test]
fn unknown_symbol_is_a_param_error() {
    let (_backend, provider) = logged_in();
    let template = tpl(vec![ulong_attr("CKA_KEY_GEN_MECHANISM", symbol("CKM_NOPE"))]);
    let err = provider.import_key(&aes(), "conv-x", Some(&template), None).unwrap_err();
    assert_eq!(err.message, "unknown PKCS#11 constant 'CKM_NOPE'");
    assert_eq!(param_name(&err), Some("CKM_NOPE"));
    assert_eq!(
        err.hint.as_deref(),
        Some("ULONG template values may be ints or CKO_/CKK_/CKC_/CKM_ names")
    );
}

#[test]
fn str_constant_row_converts_for_ulong_attrs() {
    // §4.7 test vector: CKA_KEY_GEN_MECHANISM: CKM_AES_KEY_GEN (a STR row) → 0x1080
    let (backend, provider) = logged_in();
    let template = tpl(vec![str_attr("CKA_KEY_GEN_MECHANISM", "CKM_AES_KEY_GEN")]);
    provider.import_key(&aes(), "conv-y", Some(&template), None).unwrap();
    assert_eq!(object_of(&backend, "conv-y")[&CKA_KEY_GEN_MECHANISM], ul(0x1080));
}

#[test]
fn import_defaults_exportable_when_template_silent() {
    let (backend, provider) = logged_in();
    let info = provider.import_key(&aes(), "conv-4", None, None).unwrap();
    let obj = object_of(&backend, "conv-4");
    // SoftHSM-quirk compensation: silent template → SENSITIVE=F/EXTRACTABLE=T
    assert_eq!(obj[&CKA_SENSITIVE], [0]);
    assert_eq!(obj[&CKA_EXTRACTABLE], [1]);
    assert!(info.exportable);
    assert_eq!(info.size_bits, Some(256));
    // explicit template rows are NOT overridden
    let template = tpl(vec![boolean("CKA_SENSITIVE", true), boolean("CKA_EXTRACTABLE", true)]);
    let info2 = provider.import_key(&aes(), "conv-5", Some(&template), None).unwrap();
    assert!(!info2.exportable); // sensitive wins (§5.5)
    let expected = BTreeMap::from([
        ("CKA_EXTRACTABLE".to_string(), AttrValue::Bool(true)),
        ("CKA_SENSITIVE".to_string(), AttrValue::Bool(true)),
    ]);
    assert_eq!(info2.attributes, expected);
}

#[test]
fn vendor_attribute_byte_encoded() {
    let backend = Rc::new(FakeBackend::new());
    let mut custom = IndexMap::new();
    custom.insert(
        "CKA_ACME_USAGE".to_string(),
        CustomAttributeDef { code: 0x8000_0101, kind: AttrKind::Ulong },
    );
    let provider = provider_with(&backend, BTreeMap::new(), custom);
    provider.login(&token_at(&provider, 0), &pin(USER_PIN), false).unwrap();
    let template = tpl(vec![ulong_attr("CKA_ACME_USAGE", AttrValue::Ulong(7))]);
    provider.import_key(&aes(), "conv-6", Some(&template), None).unwrap();
    // vendor codes go over the wire as native-endian CK_ULONG bytes
    assert_eq!(object_of(&backend, "conv-6")[&0x8000_0101], ul(7));
}

#[test]
fn certificate_template_drops_key_type() {
    let (backend, provider) = logged_in();
    let (material, der) = cert_material("unit-cert");
    // TemplatesSection::default_template emits a CKA_KEY_TYPE row even for CERTIFICATE
    // templates — the provider must ignore/replace it (§4.7)
    let template = tpl(vec![
        ulong_attr("CKA_CLASS", symbol("CKO_CERTIFICATE")),
        ulong_attr("CKA_KEY_TYPE", symbol("CKK_RSA")),
        boolean("CKA_TOKEN", true),
    ]);
    let info = provider.import_key(&material, "cert-1", Some(&template), None).unwrap();
    let obj = object_of(&backend, "cert-1");
    assert!(!obj.contains_key(&CKA_KEY_TYPE)); // ignored for cert objects
    assert_eq!(obj[&CKA_CLASS], ul(CKO_CERTIFICATE));
    assert_eq!(obj[&CKA_CERTIFICATE_TYPE], ul(0)); // CKC_X_509
    assert_eq!(obj[&CKA_VALUE], der);
    let facts = r2_core::x509info::cert_facts(&der, r2_core::x509info::Classifier::Pkcs11).unwrap();
    assert_eq!(obj[&CKA_SUBJECT], facts.subject_der);
    assert_eq!(info.key_class, KeyClass::Certificate);
    assert_eq!(info.algorithm, KeyAlgorithm::Rsa);
    assert_eq!(info.size_bits, Some(2048));
    assert!(info.exportable);
    assert_eq!(
        info.attributes.get("CKA_SUBJECT"),
        Some(&AttrValue::Str("CN=unit-cert".to_string()))
    );
    assert_eq!(provider.export_key(&info).unwrap().data.to_vec(), der);
}

#[test]
fn certificate_category_round_trips_through_the_byte_path() {
    let (backend, provider) = logged_in();
    let (material, _der) = cert_material("crt");
    let template = tpl(vec![ulong_attr("CKA_CERTIFICATE_CATEGORY", AttrValue::Ulong(1))]);
    provider.import_key(&material, "crt", Some(&template), None).unwrap();
    assert_eq!(object_of(&backend, "crt")[&CKA_CERTIFICATE_CATEGORY], ul(1));
}

#[test]
fn certificate_material_must_be_der() {
    let (_backend, provider) = logged_in();
    let material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, b"junk".to_vec());
    let err = provider.import_key(&material, "bad-cert", None, None).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(err.message.starts_with("certificate material is not DER X.509: "), "{}", err.message);
}

// ---------------------------------------------------------------------------
// material attribute sets (§5.4)
// ---------------------------------------------------------------------------

#[test]
fn rsa_private_material_carries_the_full_crt_set_and_exports_back() {
    let (backend, provider) = logged_in();
    let pkcs8 = r2_testkit::fixtures::rsa2048_pkcs8();
    let material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, pkcs8.clone());
    let info = provider.import_key(&material, "rsa-imp", Some(&exportable()), None).unwrap();
    let obj = object_of(&backend, "rsa-imp");
    for code in [0x120u64, 0x122, 0x123, 0x124, 0x125, 0x126, 0x127, 0x128] {
        assert!(obj.contains_key(&code), "missing 0x{code:x}");
    }
    assert_eq!(info.size_bits, Some(2048));
    let exported = provider.export_key(&info).unwrap();
    assert_eq!(exported.data.to_vec(), pkcs8); // same canonical PKCS#8 (private_key_to_pkcs8)
}

#[test]
fn ec_material_injects_params_point_and_fixed_width_scalar() {
    let (backend, provider) = logged_in();
    let pkcs8 = r2_testkit::fixtures::ec_p256_pkcs8();
    let private = KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Private, pkcs8.clone());
    let info = provider.import_key(&private, "ec-imp", Some(&exportable()), None).unwrap();
    let obj = object_of(&backend, "ec-imp");
    assert_eq!(obj[&CKA_EC_PARAMS], hex_bytes("06082a8648ce3d030107"));
    assert_eq!(obj[&CKA_VALUE].len(), 32);
    assert_eq!(info.curve, Some(Curve::P256));
    assert_eq!(info.size_bits, None);
    assert_eq!(provider.export_key(&info).unwrap().data.to_vec(), pkcs8);
    // the public half: CKA_EC_POINT is a DER OCTET STRING around the uncompressed point
    let spki = r2_core::formats::pkcs8_public_spki(&pkcs8).unwrap();
    let public = KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Public, spki.clone());
    let pub_info = provider.import_key(&public, "ec-pub", None, None).unwrap();
    let point = &object_of(&backend, "ec-pub")[&CKA_EC_POINT];
    assert_eq!(point[..2], [0x04, 0x41]);
    assert_eq!(point[2], 0x04);
    assert_eq!(provider.export_key(&pub_info).unwrap().data.to_vec(), spki);
}

#[test]
fn ed25519_material_round_trips() {
    let (backend, provider) = logged_in();
    let pkcs8 = r2_testkit::fixtures::ed25519_pkcs8();
    let material = KeyMaterial::new(KeyAlgorithm::EcEdwards, KeyClass::Private, pkcs8.clone());
    let info = provider.import_key(&material, "ed-imp", Some(&exportable()), None).unwrap();
    let obj = object_of(&backend, "ed-imp");
    assert_eq!(obj[&CKA_EC_PARAMS], hex_bytes("06032b6570"));
    assert_eq!(obj[&CKA_VALUE].len(), 32);
    assert_eq!(info.algorithm, KeyAlgorithm::EcEdwards);
    assert_eq!(info.curve, Some(Curve::Ed25519));
    assert_eq!(provider.export_key(&info).unwrap().data.to_vec(), pkcs8);
}

fn hex_bytes(text: &str) -> Vec<u8> {
    r2_core::text::py_fromhex(text).unwrap()
}

// ---------------------------------------------------------------------------
// TestKeyManagement
// ---------------------------------------------------------------------------

#[test]
fn generate_aes_passes_value_len() {
    let (backend, provider) = logged_in();
    let mut request = with_size(generate(KeyAlgorithm::Aes, "gen-aes"), 192);
    request.template = Some(exportable());
    let info = provider.generate_key(&request).unwrap();
    let obj = object_of(&backend, "gen-aes");
    assert_eq!(obj[&CKA_VALUE_LEN], ul(24));
    assert_eq!(info.size_bits, Some(192));
    assert_eq!(info.key_class, KeyClass::Secret);
    assert_eq!(provider.export_key(&info).unwrap().data.len(), 24);
}

#[test]
fn generate_aes_requires_size() {
    let (_backend, provider) = logged_in();
    let err = provider.generate_key(&generate(KeyAlgorithm::Aes, "gen-bad")).unwrap_err();
    assert_eq!(err.message, "size_bits is required for aes");
    assert_eq!(param_name(&err), Some("size_bits"));
}

#[test]
fn generate_keypair_shares_label_and_id() {
    let (_backend, provider) = logged_in();
    let info = provider.generate_key(&with_size(generate(KeyAlgorithm::Rsa, "gen-rsa"), 2048)).unwrap();
    assert_eq!(info.key_class, KeyClass::Private);
    assert_eq!(info.size_bits, Some(2048));
    let publics: Vec<KeyInfo> = provider
        .list_keys()
        .unwrap()
        .into_iter()
        .filter(|k| k.key_ref.label == "gen-rsa" && k.key_class == KeyClass::Public)
        .collect();
    assert_eq!(publics.len(), 1);
    assert_eq!(publics[0].key_ref.key_id, info.key_ref.key_id);
    assert_eq!(info.key_ref.key_id.as_ref().map(Vec::len), Some(4)); // random 4-byte id
}

#[test]
fn generate_rsa_requires_size() {
    let (_backend, provider) = logged_in();
    let err = provider.generate_key(&generate(KeyAlgorithm::Rsa, "r")).unwrap_err();
    assert_eq!(err.message, "size_bits is required for RSA");
}

#[test]
fn generate_ec_curve_checks() {
    let (_backend, provider) = logged_in();
    let err = provider.generate_key(&generate(KeyAlgorithm::Ec, "no-curve")).unwrap_err();
    assert_eq!(err.message, "curve is required for ec");
    let mut bad = generate(KeyAlgorithm::Ec, "bad-curve");
    bad.curve = Some(Curve::Other("p999".into()));
    let err = provider.generate_key(&bad).unwrap_err();
    assert_eq!(err.message, "unknown curve 'p999'");
    assert_eq!(err.hint.as_deref(), Some("valid curves: ed25519, ed448, p256, p384, p521, x25519, x448"));
    let mut mismatch = generate(KeyAlgorithm::Ec, "mismatch");
    mismatch.curve = Some(Curve::Ed25519);
    let err = provider.generate_key(&mismatch).unwrap_err();
    assert_eq!(err.message, "curve 'ed25519' does not belong to algorithm ec");
    assert_eq!(param_name(&err), Some("curve"));
}

#[test]
fn generate_ec_injects_params_into_public_template() {
    let (backend, provider) = logged_in();
    let mut request = generate(KeyAlgorithm::Ec, "gen-ec");
    request.curve = Some(Curve::P384);
    let info = provider.generate_key(&request).unwrap();
    assert_eq!(info.curve, Some(Curve::P384));
    let public = backend
        .objects()
        .into_iter()
        .map(|(_, a)| a)
        .find(|a| a.get(&CKA_LABEL).map(Vec::as_slice) == Some(b"gen-ec") && a[&CKA_CLASS] == ul(CKO_PUBLIC_KEY))
        .unwrap();
    assert_eq!(public[&CKA_EC_PARAMS], hex_bytes("06052b81040022"));
}

#[test]
fn generate_honors_template_id() {
    // the reported field bug: `add CKA_ID=0xc0fe` in the editor must win
    let (backend, provider) = logged_in();
    let mut request = with_size(generate(KeyAlgorithm::Aes, "id-aes"), 128);
    request.template = Some(tpl(vec![bytes_attr("CKA_ID", b"\xc0\xfe")]));
    let info = provider.generate_key(&request).unwrap();
    assert_eq!(info.key_ref.key_id, Some(vec![0xc0, 0xfe]));
    assert_eq!(object_of(&backend, "id-aes")[&CKA_ID], [0xc0, 0xfe]);
}

#[test]
fn generate_explicit_id_conflicting_with_template_rejected() {
    let (_backend, provider) = logged_in();
    let mut request = with_size(generate(KeyAlgorithm::Aes, "id-clash"), 128);
    request.key_id = Some(vec![0x0a, 0x0b]);
    request.template = Some(tpl(vec![bytes_attr("CKA_ID", b"\xc0\xfe")]));
    let err = provider.generate_key(&request).unwrap_err();
    assert_eq!(param_name(&err), Some("CKA_ID"));
    assert_eq!(err.message, "template CKA_ID 0xc0fe conflicts with --id 0x0a0b");
    assert_eq!(err.hint.as_deref(), Some("drop one of the two — they must agree"));
}

#[test]
fn generate_explicit_id_agreeing_with_template_ok() {
    let (_backend, provider) = logged_in();
    let mut request = with_size(generate(KeyAlgorithm::Aes, "id-agree"), 128);
    request.key_id = Some(vec![0x0a]);
    request.template = Some(tpl(vec![bytes_attr("CKA_ID", b"\x0a")]));
    assert_eq!(provider.generate_key(&request).unwrap().key_ref.key_id, Some(vec![0x0a]));
}

#[test]
fn generate_keypair_shares_template_id() {
    let (_backend, provider) = logged_in();
    let mut request = with_size(generate(KeyAlgorithm::Rsa, "id-rsa"), 2048);
    request.template = Some(tpl(vec![bytes_attr("CKA_ID", b"\x42")]));
    let info = provider.generate_key(&request).unwrap();
    assert_eq!(info.key_ref.key_id, Some(vec![0x42]));
    let public = provider
        .find_key(&sel("id-rsa").with_class(Some(KeyClass::Public)))
        .unwrap();
    assert_eq!(public.key_ref.key_id, Some(vec![0x42]));
}

#[test]
fn generate_keypair_templates_disagreeing_on_id_rejected() {
    let (_backend, provider) = logged_in();
    let mut request = with_size(generate(KeyAlgorithm::Rsa, "id-split"), 2048);
    request.template = Some(tpl(vec![bytes_attr("CKA_ID", b"\x01")]));
    request.public_template = Some(tpl(vec![bytes_attr("CKA_ID", b"\x02")]));
    let err = provider.generate_key(&request).unwrap_err();
    assert_eq!(param_name(&err), Some("CKA_ID"));
}

#[test]
fn generate_template_label_overrides_argument() {
    let (backend, provider) = logged_in();
    let mut request = with_size(generate(KeyAlgorithm::Aes, "original"), 128);
    request.template = Some(tpl(vec![str_attr("CKA_LABEL", "renamed")]));
    let info = provider.generate_key(&request).unwrap();
    assert_eq!(info.key_ref.label, "renamed");
    object_of(&backend, "renamed"); // the object carries the template label
}

#[test]
fn import_honors_template_id() {
    let (_backend, provider) = logged_in();
    let template = tpl(vec![bytes_attr("CKA_ID", b"\xc0\xfe")]);
    let info = provider.import_key(&aes(), "id-import", Some(&template), None).unwrap();
    assert_eq!(info.key_ref.key_id, Some(vec![0xc0, 0xfe]));
}

#[test]
fn find_ambiguity_and_delete() {
    let (_backend, provider) = logged_in();
    provider.import_key(&aes(), "dup", None, Some(b"\x01")).unwrap();
    provider.import_key(&aes(), "dup", None, Some(b"\x02")).unwrap();
    let err = provider.find_key(&sel("dup")).unwrap_err();
    assert_eq!(err.candidates().map(<[_]>::len), Some(2));
    assert_eq!(err.message, "'dup' matches 2 keys on hsm: hsm:dup#01, hsm:dup#02");
    let by_id = provider.find_key(&sel("dup").with_id(Some(vec![2]))).unwrap();
    provider.delete_key(&by_id).unwrap();
    assert_eq!(provider.find_key(&sel("dup")).unwrap().key_ref.key_id, Some(vec![1]));
}

#[test]
fn keypair_family_prefers_private() {
    let (_backend, provider) = logged_in();
    provider.generate_key(&with_size(generate(KeyAlgorithm::Rsa, "fam"), 2048)).unwrap();
    assert_eq!(provider.find_key(&sel("fam")).unwrap().key_class, KeyClass::Private);
}

#[test]
fn find_key_class_selector_targets_half() {
    let (_backend, provider) = logged_in();
    provider.generate_key(&with_size(generate(KeyAlgorithm::Rsa, "fam2"), 2048)).unwrap();
    let public = provider.find_key(&sel("fam2").with_class(Some(KeyClass::Public))).unwrap();
    assert_eq!(public.key_class, KeyClass::Public);
    let err = provider
        .find_key(&sel("fam2").with_class(Some(KeyClass::Certificate)))
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotFound);
    assert_eq!(err.message, "no certificate key 'fam2' on provider hsm");
}

#[test]
fn find_key_handle_selects_among_identical_objects() {
    // §4.3 '@<handle>': same label+id+class twins — only the handle picks one; the twin
    // comes from an external writer (the provider's own guard refuses it)
    let (backend, provider) = logged_in();
    let first = provider.import_key(&aes(), "twin", None, Some(b"\x0a")).unwrap();
    let wanted = backend.clone_object(first.handle.unwrap(), None);
    let picked = provider
        .find_key(&sel("twin").with_class(Some(KeyClass::Secret)).with_handle(Some(wanted)))
        .unwrap();
    assert_eq!(picked.handle, Some(wanted));
}

#[test]
fn key_info_carries_the_numeric_handle() {
    // c2 test_key_info_handle_is_a_plain_int: every KeyInfo from import/list_keys has Some(handle)
    let (_backend, provider) = logged_in();
    let info = provider.import_key(&aes(), "plainhandle", None, None).unwrap();
    assert!(info.handle.is_some());
    assert!(provider.list_keys().unwrap().iter().all(|k| k.handle.is_some()));
}

#[test]
fn export_refused_for_non_exportable() {
    let (_backend, provider) = logged_in();
    let template = tpl(vec![boolean("CKA_SENSITIVE", true), boolean("CKA_EXTRACTABLE", false)]);
    let info = provider.import_key(&aes(), "noexp", Some(&template), None).unwrap();
    let err = provider.export_key(&info).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert_eq!(err.message, format!("key '{}' is not exportable", info.key_ref.display()));
    assert_eq!(
        err.hint.as_deref(),
        Some("CKA_SENSITIVE/CKA_EXTRACTABLE forbid a plain-value read (§5.5)")
    );
}

#[test]
fn zero_length_id_lists_and_resolves_as_none() {
    // §4.10.4: objects created with a zero-length CKA_ID list and resolve with key_id None
    let (backend, provider) = logged_in();
    backend.plant_object(
        0,
        vec![
            (CKA_CLASS, ul(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ul(CKK_AES)),
            (CKA_LABEL, b"noid".to_vec()),
            (CKA_ID, Vec::new()),
            (CKA_VALUE_LEN, ul(16)),
        ],
        &[7; 16],
    );
    let listed = provider.list_keys().unwrap();
    let info = listed.iter().find(|k| k.key_ref.label == "noid").unwrap();
    assert_eq!(info.key_ref.key_id, None);
    assert_eq!(info.key_ref.display(), "hsm:noid");
    let found = provider.find_key(&sel("noid")).unwrap();
    assert_eq!(found.key_ref.key_id, None);
    provider.delete_key(&found).unwrap();
}

#[test]
fn list_keys_orders_by_class_then_creation() {
    let (_backend, provider) = logged_in();
    let (cert, _) = cert_material("c");
    provider.import_key(&data(), "d", None, None).unwrap();
    provider.import_key(&cert, "c", None, None).unwrap();
    provider.generate_key(&with_size(generate(KeyAlgorithm::Rsa, "k"), 2048)).unwrap();
    provider.import_key(&aes(), "s2", None, None).unwrap();
    provider.import_key(&aes(), "s1", None, None).unwrap();
    let order: Vec<(String, KeyClass)> = provider
        .list_keys()
        .unwrap()
        .into_iter()
        .map(|k| (k.key_ref.label, k.key_class))
        .collect();
    assert_eq!(
        order,
        [
            ("s2".to_string(), KeyClass::Secret),
            ("s1".to_string(), KeyClass::Secret),
            ("k".to_string(), KeyClass::Private),
            ("k".to_string(), KeyClass::Public),
            ("c".to_string(), KeyClass::Certificate),
            ("d".to_string(), KeyClass::Data),
        ]
    );
}

// ---------------------------------------------------------------------------
// TestTwinSafety
// ---------------------------------------------------------------------------

#[test]
fn delete_with_twins_and_stale_handle_raises_and_destroys_nothing() {
    for stale_handle in [Some(9999), None] {
        let (backend, provider) = logged_in();
        let info = provider.import_key(&aes(), "twin", None, Some(b"\x0a")).unwrap();
        backend.clone_object(info.handle.unwrap(), None);
        let stale = KeyInfo { handle: stale_handle, ..info };
        let before = backend.objects();
        let err = provider.delete_key(&stale).unwrap_err();
        assert!(matches!(err.kind, ErrorKind::AmbiguousKey { .. }));
        assert_eq!(backend.objects(), before);
    }
}

#[test]
fn delete_with_twins_targets_selected_twin() {
    let (backend, provider) = logged_in();
    let first = provider.import_key(&aes(), "twin", None, Some(b"\x0a")).unwrap();
    let clone = backend.clone_object(first.handle.unwrap(), None);
    let picked = provider
        .find_key(&sel("twin").with_class(Some(KeyClass::Secret)).with_handle(Some(clone)))
        .unwrap();
    provider.delete_key(&picked).unwrap();
    let handles: Vec<u64> = backend.objects().into_iter().map(|(h, _)| h).collect();
    assert!(!handles.contains(&clone));
    assert!(handles.contains(&first.handle.unwrap()));
}

#[test]
fn export_with_twins_returns_selected_twins_value() {
    let (backend, provider) = logged_in();
    let other_value: Vec<u8> = (32u8..64).collect();
    let first = provider.import_key(&aes(), "twin", None, Some(b"\x0a")).unwrap();
    let clone = backend.clone_object(first.handle.unwrap(), Some(&other_value));
    let secret = |handle| sel("twin").with_class(Some(KeyClass::Secret)).with_handle(Some(handle));
    let original = provider.find_key(&secret(first.handle.unwrap())).unwrap();
    let picked = provider.find_key(&secret(clone)).unwrap();
    assert_eq!(provider.export_key(&original).unwrap().data.to_vec(), aes_key());
    assert_eq!(provider.export_key(&picked).unwrap().data.to_vec(), other_value);
}

#[test]
fn single_match_with_stale_handle_still_succeeds() {
    // handles legitimately renumber across re-login — a single match wins
    let (_backend, provider) = logged_in();
    let info = provider.import_key(&aes(), "solo", None, Some(b"\x05")).unwrap();
    let stale = KeyInfo { handle: Some(424_242), ..info };
    provider.delete_key(&stale).unwrap();
    assert_eq!(provider.find_key(&sel("solo")).unwrap_err().kind, ErrorKind::KeyNotFound);
}

#[test]
fn twin_ambiguity_lists_handle_suffixed_candidates() {
    let (backend, provider) = logged_in();
    let first = provider.import_key(&aes(), "twin", None, Some(b"\x0a")).unwrap();
    let first_handle = first.handle.unwrap();
    let clone = backend.clone_object(first_handle, None);
    let blind = KeyInfo { handle: None, ..first };
    let err = provider.export_key(&blind).unwrap_err();
    assert_eq!(err.candidates().map(<[_]>::len), Some(2));
    assert_eq!(
        err.message,
        format!(
            "key 'hsm:twin#0a' matches 2 identical objects on hsm: hsm:twin#0a:secret@{first_handle}, \
             hsm:twin#0a:secret@{clone}"
        )
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("refresh with `keys` and re-select the object with its @<handle> suffix")
    );
}

// ---------------------------------------------------------------------------
// TestDuplicateGuard
// ---------------------------------------------------------------------------

#[test]
fn import_duplicate_identity_refused() {
    let (backend, provider) = logged_in();
    provider.import_key(&aes(), "dup-g", None, Some(b"\x01")).unwrap();
    let before = backend.objects().len();
    let err = provider.import_key(&aes(), "dup-g", None, Some(b"\x01")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::DuplicateKey);
    assert_eq!(err.message, "a secret object with label 'dup-g' and id 0x01 already exists on hsm");
    assert_eq!(
        err.hint.as_deref(),
        Some("pick a different --id or label, or delete the existing object first")
    );
    assert_eq!(backend.objects().len(), before);
}

#[test]
fn import_same_label_different_id_allowed() {
    let (_backend, provider) = logged_in();
    provider.import_key(&aes(), "dup-ok", None, Some(b"\x01")).unwrap();
    let info = provider.import_key(&aes(), "dup-ok", None, Some(b"\x02")).unwrap();
    assert_eq!(info.key_ref.key_id, Some(vec![2]));
}

#[test]
fn generate_over_existing_identity_refused() {
    let (_backend, provider) = logged_in();
    provider.import_key(&aes(), "gen-g", None, Some(b"\x01")).unwrap();
    let mut request = with_size(generate(KeyAlgorithm::Aes, "gen-g"), 128);
    request.key_id = Some(vec![1]);
    assert_eq!(provider.generate_key(&request).unwrap_err().kind, ErrorKind::DuplicateKey);
}

#[test]
fn generate_keypair_over_existing_half_refused_atomically() {
    let (backend, provider) = logged_in();
    let mut request = with_size(generate(KeyAlgorithm::Rsa, "pair-g"), 2048);
    request.key_id = Some(vec![2]);
    let pair = provider.generate_key(&request).unwrap();
    provider.delete_key(&pair).unwrap(); // PRIVATE half gone; PUBLIC remains
    let before = backend.objects();
    let err = provider.generate_key(&request).unwrap_err();
    assert_eq!(err.kind, ErrorKind::DuplicateKey);
    assert_eq!(err.message, "a public object with label 'pair-g' and id 0x02 already exists on hsm");
    assert_eq!(backend.objects(), before); // no half-created pair
}

#[test]
fn keypair_and_certificates_may_share_identity() {
    // keypair halves share one label+id; PKCS#12 chain certs may repeat the full identity
    let (_backend, provider) = logged_in();
    let mut request = with_size(generate(KeyAlgorithm::Rsa, "fam-g"), 2048);
    request.key_id = Some(vec![3]);
    provider.generate_key(&request).unwrap();
    let (cert, _) = cert_material("twin-cert");
    provider.import_key(&cert, "fam-g", None, Some(b"\x03")).unwrap();
    provider.import_key(&cert, "fam-g", None, Some(b"\x03")).unwrap();
    let certs = provider
        .list_keys()
        .unwrap()
        .into_iter()
        .filter(|k| k.key_ref.label == "fam-g" && k.key_class == KeyClass::Certificate)
        .count();
    assert_eq!(certs, 2);
}

// ---------------------------------------------------------------------------
// test_objects.py — generic secrets, CKO_DATA, `other`
// ---------------------------------------------------------------------------

#[test]
fn generate_uses_generic_keygen_and_value_len() {
    let (backend, provider) = logged_in();
    let info = provider.generate_key(&with_size(generate(KeyAlgorithm::Generic, "gen-g"), 256)).unwrap();
    assert_eq!((info.key_class, info.algorithm, info.size_bits), (KeyClass::Secret, KeyAlgorithm::Generic, Some(256)));
    let obj = object_of(&backend, "gen-g");
    assert_eq!(obj[&CKA_KEY_TYPE], ul(CKK_GENERIC_SECRET));
    assert_eq!(obj[&CKA_VALUE_LEN], ul(32));
    assert_eq!(
        backend.last_mechanism(),
        Some(crate::backend::MechSpec::Plain { ckm: 0x350 }) // CKM_GENERIC_SECRET_KEY_GEN
    );
    let err = provider.generate_key(&with_size(generate(KeyAlgorithm::Generic, "bad"), 12)).unwrap_err();
    assert_eq!(param_name(&err), Some("size_bits"));
    assert_eq!(
        err.message,
        "invalid generic secret size 12; expected a multiple of 8 between 8 and 8192 bits"
    );
}

#[test]
fn generic_import_reads_back_as_generic() {
    let (backend, provider) = logged_in();
    let info = provider.import_key(&generic(), "imp-g", Some(&exportable()), None).unwrap();
    assert_eq!(info.algorithm, KeyAlgorithm::Generic);
    assert_eq!(info.size_bits, Some(256)); // SoftHSM-style derived CKA_VALUE_LEN
    assert_eq!(object_of(&backend, "imp-g")[&CKA_KEY_TYPE], ul(CKK_GENERIC_SECRET));
    assert_eq!(provider.export_key(&info).unwrap().data.to_vec(), generic_key());
    let listed = provider.list_keys().unwrap();
    let listed: Vec<&KeyInfo> = listed.iter().filter(|k| k.key_ref.label == "imp-g").collect();
    assert_eq!(listed[0].algorithm, KeyAlgorithm::Generic);
}

#[test]
fn hmac_key_types_fold_into_generic_on_read() {
    let (backend, provider) = logged_in();
    backend.plant_object(
        0,
        vec![
            (CKA_CLASS, ul(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ul(CKK_SHA256_HMAC)),
            (CKA_LABEL, b"hmac-typed".to_vec()),
            (CKA_ID, vec![7]),
            (CKA_VALUE_LEN, ul(32)),
            (CKA_SENSITIVE, vec![1]),
            (CKA_EXTRACTABLE, vec![0]),
        ],
        &generic_key(),
    );
    let info = provider.find_key(&sel("hmac-typed")).unwrap();
    assert_eq!(info.algorithm, KeyAlgorithm::Generic);
    assert!(!info.exportable);
}

#[test]
fn data_import_template_has_no_key_type_id_or_policy() {
    let (backend, provider) = logged_in();
    let template = tpl(vec![
        str_attr("CKA_APPLICATION", "acme"),
        bytes_attr("CKA_OBJECT_ID", b"\x2a"),
        boolean("CKA_TOKEN", true),
    ]);
    let info = provider.import_key(&data(), "d1", Some(&template), None).unwrap();
    let obj = object_of(&backend, "d1");
    assert_eq!(obj[&CKA_CLASS], ul(CKO_DATA));
    for absent in [CKA_KEY_TYPE, CKA_ID, CKA_SENSITIVE, CKA_EXTRACTABLE] {
        assert!(!obj.contains_key(&absent), "0x{absent:x}");
    }
    assert_eq!(obj[&CKA_VALUE], DATA_VALUE);
    assert_eq!(obj[&CKA_APPLICATION], b"acme");
    assert_eq!(obj[&CKA_OBJECT_ID], [0x2a]);
    assert_eq!((info.key_class, info.algorithm, info.key_ref.key_id.clone()), (KeyClass::Data, KeyAlgorithm::None, None));
    assert_eq!(info.size_bits, Some(u32::try_from(DATA_VALUE.len() * 8).unwrap()));
    assert!(info.exportable);
    let expected = BTreeMap::from([
        ("CKA_APPLICATION".to_string(), AttrValue::Str("acme".into())),
        ("CKA_OBJECT_ID".to_string(), AttrValue::Bytes(vec![0x2a])),
    ]);
    assert_eq!(info.attributes, expected);
}

#[test]
fn data_list_find_export_delete() {
    let (_backend, provider) = logged_in();
    let info = provider.import_key(&data(), "d2", None, None).unwrap();
    let listed: Vec<String> = provider
        .list_keys()
        .unwrap()
        .into_iter()
        .filter(|k| k.key_class == KeyClass::Data)
        .map(|k| k.key_ref.label)
        .collect();
    assert_eq!(listed, ["d2"]);
    assert_eq!(provider.find_key(&sel("d2")).unwrap().key_class, KeyClass::Data);
    assert_eq!(provider.find_key(&sel("d2").with_class(Some(KeyClass::Data))).unwrap().key_ref, info.key_ref);
    let exported = provider.export_key(&info).unwrap();
    assert_eq!((exported.key_class, exported.algorithm), (KeyClass::Data, KeyAlgorithm::None));
    assert_eq!(exported.data.to_vec(), DATA_VALUE);
    provider.delete_key(&info).unwrap();
    assert_eq!(provider.find_key(&sel("d2")).unwrap_err().kind, ErrorKind::KeyNotFound);
}

#[test]
fn data_identity_rules() {
    let (_backend, provider) = logged_in();
    let err = provider.import_key(&data(), "d3", None, Some(b"\x01")).unwrap_err();
    assert_eq!(err.message, "data objects carry no CKA_ID (§4.3)");
    assert_eq!(param_name(&err), Some("CKA_ID"));
    assert_eq!(
        err.hint.as_deref(),
        Some("drop --id / the template CKA_ID row; data objects are identified by label alone")
    );
    let template = tpl(vec![bytes_attr("CKA_ID", b"\x01")]);
    assert_eq!(param_name(&provider.import_key(&data(), "d3", Some(&template), None).unwrap_err()), Some("CKA_ID"));
    provider.import_key(&data(), "d3", None, None).unwrap();
    let err = provider.import_key(&data(), "d3", None, None).unwrap_err();
    assert_eq!(err.kind, ErrorKind::DuplicateKey);
    assert_eq!(err.message, "a data object with label 'd3' and no id already exists on hsm");
    // a same-label SECRET key is no twin of a data object
    provider.import_key(&generic(), "d3", None, None).unwrap();
    assert_eq!(
        provider.find_key(&sel("d3").with_class(Some(KeyClass::Data))).unwrap().key_class,
        KeyClass::Data
    );
}

#[test]
fn other_key_types_are_listed_and_refused_for_export() {
    let (backend, provider) = logged_in();
    backend.plant_object(
        0,
        vec![
            (CKA_CLASS, ul(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ul(CKK_DES3)),
            (CKA_LABEL, b"des3".to_vec()),
            (CKA_ID, vec![3]),
            (CKA_VALUE_LEN, ul(24)),
            (CKA_SENSITIVE, vec![0]),
            (CKA_EXTRACTABLE, vec![1]),
            (CKA_VALUE, vec![b'k'; 24]),
        ],
        &[b'k'; 24],
    );
    let listed = provider.list_keys().unwrap();
    let info = listed.into_iter().find(|k| k.key_ref.label == "des3").unwrap();
    assert_eq!(info.algorithm, KeyAlgorithm::Other);
    assert_eq!(info.attributes.get("CKA_KEY_TYPE"), Some(&AttrValue::Symbol("CKK_DES3".into())));
    assert!(!info.exportable);
    assert_eq!(info.size_bits, Some(192));
    assert_eq!(provider.find_key(&sel("des3")).unwrap().algorithm, KeyAlgorithm::Other);
    let err = provider.export_key(&info).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(err.message, "key type CKK_DES3 of 'hsm:des3#03' is not supported by r2 for export");
    assert_eq!(err.hint.as_deref(), Some("objects of unsupported key types can be listed and deleted only"));
    provider.delete_key(&info).unwrap();
    assert_eq!(provider.find_key(&sel("des3")).unwrap_err().kind, ErrorKind::KeyNotFound);
}

#[test]
fn import_and_generate_refuse_other() {
    let (_backend, provider) = logged_in();
    let material = KeyMaterial::new(KeyAlgorithm::Other, KeyClass::Secret, b"x".to_vec());
    let err = provider.import_key(&material, "x", None, None).unwrap_err();
    assert_eq!(err.message, "cannot import other secret material");
    assert_eq!(param_name(&err), Some("material"));
    let none = KeyMaterial::new(KeyAlgorithm::None, KeyClass::Secret, b"x".to_vec());
    assert_eq!(param_name(&provider.import_key(&none, "x", None, None).unwrap_err()), Some("material"));
    let err = provider.generate_key(&with_size(generate(KeyAlgorithm::Other, "x"), 128)).unwrap_err();
    assert_eq!(err.message, "cannot generate other keys");
    assert_eq!(param_name(&err), Some("algorithm"));
}

#[test]
fn imported_objects_read_key_gen_mechanism_as_unavailable() {
    // §4.10.4 SoftHSM flavor: imported key objects carry CK_UNAVAILABLE_INFORMATION
    let (backend, provider) = logged_in();
    provider.import_key(&aes(), "kgm", None, None).unwrap();
    assert_eq!(object_of(&backend, "kgm")[&CKA_KEY_GEN_MECHANISM], ul(u64::MAX));
}

#[test]
fn every_kind_imports_and_lists() {
    let (_backend, provider) = logged_in();
    let (cert, _) = cert_material("all");
    let rsa = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, r2_testkit::fixtures::rsa2048_pkcs8());
    let ec = KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Private, r2_testkit::fixtures::ec_p256_pkcs8());
    let ed = KeyMaterial::new(KeyAlgorithm::EcEdwards, KeyClass::Private, r2_testkit::fixtures::ed25519_pkcs8());
    for (material, label) in [(aes(), "a"), (rsa, "r"), (ec, "e"), (ed, "ed"), (cert, "c"), (generic(), "g"), (data(), "d")] {
        provider.import_key(&material, label, None, None).unwrap();
    }
    assert_eq!(provider.list_keys().unwrap().len(), 7);
}
