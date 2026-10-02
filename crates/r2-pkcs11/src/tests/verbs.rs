//! The crypto verbs over the FakeBackend: ports of the verb cases of c2
//! tests/unit/pkcs11/test_objects.py (TestGenericSecrets HMAC/CMAC, TestDataObjects /
//! TestOtherKeyTypes refusals) and test_provider_objects.py (public RSA-RAW, CKR mapping,
//! custom dispatch, derive, twin-targeted sign), plus r2 tests of every software fallback
//! (ECB PKCS#7, non-SHA1 OAEP, DigestInfo, bare-ECDSA prehash, CMAC/HMAC truncation, GMAC
//! construction, PSS salt) the spec requires (§5.8–§5.10).
use std::collections::BTreeMap;

use indexmap::IndexMap;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use r2_core::error::ErrorKind;
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::template::AttrValue;
use r2_provider::{GenerateRequest, KeySelector, Provider};

use super::{exportable, logged_in, logged_in_with, mech, pbytes, penum, pint, ul};
use crate::backend::fake::{DEFAULT_MECHANISMS, FakeBackend};
use crate::backend::{Backend, MechSpec};
use crate::ckr::rv;

const CKA_CLASS: u64 = 0x0000;
const CKA_LABEL: u64 = 0x0003;
const CKA_VALUE: u64 = 0x0011;
const CKA_KEY_TYPE: u64 = 0x0100;
const CKA_ID: u64 = 0x0102;
const CKA_SENSITIVE: u64 = 0x0103;
const CKA_VALUE_LEN: u64 = 0x0161;
const CKA_EXTRACTABLE: u64 = 0x0162;
const CKA_MODULUS: u64 = 0x0120;
const CKO_SECRET_KEY: u64 = 4;
const CKK_DES3: u64 = 0x15;
const CKK_SHA256_HMAC: u64 = 0x2B;

const CKM_RSA_PKCS: u64 = 0x0001;
const CKM_RSA_X_509: u64 = 0x0003;
const CKM_RSA_PKCS_OAEP: u64 = 0x0009;
const CKM_RSA_PKCS_PSS: u64 = 0x000D;
const CKM_SHA256_RSA_PKCS: u64 = 0x0040;
const CKM_SHA256_RSA_PKCS_PSS: u64 = 0x0043;
const CKM_SHA256_HMAC: u64 = 0x0251;
const CKM_SHA384_HMAC: u64 = 0x0261;
const CKM_SHA512_HMAC: u64 = 0x0271;
const CKM_ECDSA: u64 = 0x1041;
const CKM_ECDSA_SHA256: u64 = 0x1044;
const CKM_EDDSA: u64 = 0x1057;
const CKM_AES_ECB: u64 = 0x1081;
const CKM_AES_CBC: u64 = 0x1082;
const CKM_AES_CBC_PAD: u64 = 0x1085;
const CKM_AES_GCM: u64 = 0x1087;
const CKM_AES_GMAC: u64 = 0x108E;
const CKM_AES_CMAC: u64 = 0x108A;

fn generic_key() -> Vec<u8> {
    (64u8..96).collect()
}

fn generic() -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, generic_key())
}

fn aes(data: Vec<u8>) -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, data)
}

fn data_material() -> KeyMaterial {
    KeyMaterial::new(
        KeyAlgorithm::None,
        KeyClass::Data,
        b"opaque data object value \x00\xff".to_vec(),
    )
}

fn sel(label: &str) -> KeySelector {
    KeySelector::label(label)
}

fn mechs_without(removed: &[u64]) -> Vec<u64> {
    DEFAULT_MECHANISMS
        .iter()
        .copied()
        .filter(|c| !removed.contains(c))
        .collect()
}

fn mechs_with(added: &[u64]) -> Vec<u64> {
    let mut codes = DEFAULT_MECHANISMS.to_vec();
    codes.extend_from_slice(added);
    codes
}

fn last_ckm(backend: &FakeBackend) -> u64 {
    crate::backend::fake::spec_ckm(&backend.last_mechanism().unwrap())
}

fn rsa_pair(provider: &crate::Pkcs11Provider, label: &str) -> (KeyInfo, KeyInfo) {
    let mut request = GenerateRequest::new(KeyAlgorithm::Rsa, label);
    request.size_bits = Some(2048);
    request.template = Some(exportable());
    let private = provider.generate_key(&request).unwrap();
    let public = provider
        .find_key(&sel(label).with_class(Some(KeyClass::Public)))
        .unwrap();
    (private, public)
}

fn ec_private(provider: &crate::Pkcs11Provider, label: &str, curve: Curve) -> KeyInfo {
    let mut request = GenerateRequest::new(curve.algorithm(), label);
    request.curve = Some(curve);
    provider.generate_key(&request).unwrap();
    provider.find_key(&sel(label)).unwrap() // family preference → PRIVATE
}

// ---------------------------------------------------------------------------
// generic secrets & HMAC (c2 test_objects.py TestGenericSecrets)
// ---------------------------------------------------------------------------

#[test]
fn hmac_key_types_fold_into_generic() {
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
    let template = provider.read_key_template(&info).unwrap();
    let key_type = template.get("CKA_KEY_TYPE").unwrap();
    assert_eq!(key_type.value, AttrValue::Symbol("CKK_SHA256_HMAC".into())); // the actual type
}

#[test]
fn hmac_sign_selects_ckm_by_hash_and_truncates() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&generic(), "hm", Some(&exportable()), None)
        .unwrap();
    let data = b"payload";
    let mac = provider
        .sign(&info, &mech("HMAC", vec![("hash", penum("sha384"))]), data)
        .unwrap();
    assert_eq!(mac.len(), 48);
    assert_eq!(last_ckm(&backend), CKM_SHA384_HMAC);
    let short = provider
        .sign(
            &info,
            &mech(
                "HMAC",
                vec![("hash", penum("sha384")), ("mac_len", pint(20))],
            ),
            data,
        )
        .unwrap();
    assert_eq!(short, mac[..20]);
    let sha384 = mech("HMAC", vec![("hash", penum("sha384"))]);
    assert!(provider.verify(&info, &sha384, data, &mac).unwrap());
    assert!(!provider.verify(&info, &sha384, b"payload!", &mac).unwrap());
    let truncated = mech(
        "HMAC",
        vec![("hash", penum("sha384")), ("mac_len", pint(20))],
    );
    assert!(provider.verify(&info, &truncated, data, &short).unwrap());
    let default = provider.sign(&info, &mech("HMAC", vec![]), data).unwrap();
    assert_eq!(default.len(), 32); // sha256 default
    assert_eq!(last_ckm(&backend), CKM_SHA256_HMAC);
    let err = provider
        .sign(
            &info,
            &mech(
                "HMAC",
                vec![("hash", penum("sha256")), ("mac_len", pint(40))],
            ),
            data,
        )
        .unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(err.message, "mac_len must be between 1 and 32 for sha256");
    assert_eq!(err.param_name(), Some("mac_len"));
}

#[test]
fn hmac_requires_generic_and_cmac_requires_aes() {
    let (backend, provider) = logged_in();
    let aes_key = provider
        .import_key(&aes(vec![0; 32]), "aes-k", Some(&exportable()), None)
        .unwrap();
    let generic_key = provider
        .import_key(&generic(), "gen-k", Some(&exportable()), None)
        .unwrap();
    let calls = backend.calls().len();
    let err = provider
        .sign(&aes_key, &mech("HMAC", vec![]), b"x")
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("generic secret"));
    assert_eq!(
        err.message,
        "HMAC requires a generic secret key (got aes secret)"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("generate/load a `generic` key (CKK_GENERIC_SECRET) for HMAC")
    );
    let err = provider
        .sign(&generic_key, &mech("AES-CMAC", vec![]), b"x")
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("AES"));
    assert_eq!(
        err.message,
        "AES-CMAC requires an AES secret key (got generic secret)"
    );
    // refused BEFORE any token crypto call (§4.6.6 note)
    assert!(
        !backend.calls()[calls..]
            .iter()
            .any(|c| *c == "sign" || *c == "encrypt_multipart")
    );
}

#[test]
fn missing_hmac_ckm_is_an_unsupported_operation() {
    let (_backend, provider) = logged_in_with(
        mechs_without(&[CKM_SHA512_HMAC]),
        BTreeMap::new(),
        IndexMap::new(),
    );
    let info = provider
        .import_key(&generic(), "hm2", Some(&exportable()), None)
        .unwrap();
    assert!(provider.mechanisms().contains("HMAC")); // sha256 still serves it
    let mac = provider
        .sign(&info, &mech("HMAC", vec![("hash", penum("sha256"))]), b"x")
        .unwrap();
    assert_eq!(mac.len(), 32);
    let err = provider
        .sign(&info, &mech("HMAC", vec![("hash", penum("sha512"))]), b"x")
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("CKM_SHA512_HMAC"));
    assert_eq!(err.message, "token lacks CKM_SHA512_HMAC for HMAC (sha512)");
}

#[test]
fn key_size_range_is_translated_with_a_hint() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&generic(), "short", Some(&exportable()), None)
        .unwrap();
    backend.fail_next("sign", rv::CKR_KEY_SIZE_RANGE);
    let err = provider
        .sign(&info, &mech("HMAC", vec![("hash", penum("sha512"))]), b"x")
        .unwrap_err();
    assert_eq!(err.kind.class_name(), "Pkcs11Error");
    assert_eq!(
        err.ckr().map(|(_, n)| n.to_string()).as_deref(),
        Some("CKR_KEY_SIZE_RANGE")
    );
    assert!(err.hint.as_deref().unwrap_or("").contains("digest length"));
    assert_eq!(
        err.message,
        "key length unsuitable for sign with HMAC (CKR_KEY_SIZE_RANGE)"
    );
}

#[test]
fn cmac_is_full_width_on_token_and_truncated_locally() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&aes((0u8..16).collect()), "cm", Some(&exportable()), None)
        .unwrap();
    let full = provider
        .sign(&info, &mech("AES-CMAC", vec![]), b"m")
        .unwrap();
    assert_eq!(full.len(), 16);
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Plain { ckm: CKM_AES_CMAC })
    );
    let short = provider
        .sign(&info, &mech("AES-CMAC", vec![("mac_len", pint(8))]), b"m")
        .unwrap();
    assert_eq!(short, full[..8]);
    let eight = mech("AES-CMAC", vec![("mac_len", pint(8))]);
    assert!(provider.verify(&info, &eight, b"m", &short).unwrap());
    assert!(!provider.verify(&info, &eight, b"m", &full).unwrap());
    for bad in [0, 17] {
        let err = provider
            .sign(&info, &mech("AES-CMAC", vec![("mac_len", pint(bad))]), b"m")
            .unwrap_err();
        assert_eq!(err.message, "mac_len must be between 1 and 16");
        assert_eq!(err.param_name(), Some("mac_len"));
    }
}

#[test]
fn gmac_uses_the_gcm_construction_without_ckm_aes_gmac() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&aes((0u8..32).collect()), "gm", Some(&exportable()), None)
        .unwrap();
    let iv: Vec<u8> = (0u8..12).collect();
    let gmac = mech("AES-GMAC", vec![("iv", pbytes(&iv)), ("mac_len", pint(16))]);
    let tag = provider.sign(&info, &gmac, b"authenticate me").unwrap();
    assert_eq!(tag.len(), 16);
    // multi-part GCM with the message as AAD and an empty plaintext (§5.9)
    assert_eq!(backend.calls().last(), Some(&"encrypt_multipart"));
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Gcm {
            ckm: CKM_AES_GCM,
            iv: iv.clone(),
            aad: zeroize::Zeroizing::new(b"authenticate me".to_vec()),
            tag_bits: 128
        })
    );
    assert!(
        provider
            .verify(&info, &gmac, b"authenticate me", &tag)
            .unwrap()
    );
    assert!(
        !provider
            .verify(&info, &gmac, b"authenticate me!", &tag)
            .unwrap()
    );
    let err = provider
        .sign(
            &info,
            &mech("AES-GMAC", vec![("iv", pbytes(&iv)), ("mac_len", pint(3))]),
            b"m",
        )
        .unwrap_err();
    assert_eq!(err.message, "mac_len must be between 4 and 16");
}

#[test]
fn gmac_prefers_ckm_aes_gmac_when_listed() {
    let (backend, provider) = logged_in_with(
        mechs_with(&[CKM_AES_GMAC]),
        BTreeMap::new(),
        IndexMap::new(),
    );
    let info = provider
        .import_key(&aes((0u8..32).collect()), "gm2", Some(&exportable()), None)
        .unwrap();
    let iv = vec![9u8; 12];
    let gmac = mech("AES-GMAC", vec![("iv", pbytes(&iv)), ("mac_len", pint(12))]);
    provider.sign(&info, &gmac, b"msg").unwrap();
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Gcm {
            ckm: CKM_AES_GMAC,
            iv,
            aad: zeroize::Zeroizing::new(Vec::new()),
            tag_bits: 96
        })
    );
    assert_eq!(backend.calls().last(), Some(&"sign"));
}

// ---------------------------------------------------------------------------
// data objects and `other` key types (c2 test_objects.py)
// ---------------------------------------------------------------------------

#[test]
fn data_object_verbs_refused() {
    let (_backend, provider) = logged_in();
    let info = provider
        .import_key(&data_material(), "d4", None, None)
        .unwrap();
    let err = provider
        .sign(&info, &mech("HMAC", vec![]), b"x")
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("data objects"));
    assert_eq!(err.message, "data objects cannot be used for sign (§4.3)");
    assert_eq!(
        err.hint.as_deref(),
        Some("data objects hold opaque bytes, not key material — export or copy them")
    );
    let err = provider
        .verify(&info, &mech("HMAC", vec![]), b"x", b"y")
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    let err = provider
        .encrypt(
            &info,
            &mech("AES-GCM", vec![("iv", pbytes(&[0; 12]))]),
            b"x",
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    let mut request = GenerateRequest::new(KeyAlgorithm::Aes, "kek4");
    request.size_bits = Some(256);
    let kek = provider.generate_key(&request).unwrap();
    let err = provider
        .wrap_key(
            &kek,
            &mech("AES-KEY-WRAP-PAD", vec![]),
            &info,
            &Default::default(),
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(
        err.message,
        "data objects cannot be used for wrap_key (target) (§4.3)"
    );
}

#[test]
fn other_key_types_listed_as_other_and_refused_elsewhere() {
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
            (CKA_VALUE, b"k".repeat(24)),
        ],
        &b"k".repeat(24),
    );
    let listed = provider.list_keys().unwrap();
    let info = listed
        .iter()
        .find(|k| k.key_ref.label == "des3")
        .unwrap()
        .clone();
    assert_eq!(info.algorithm, KeyAlgorithm::Other);
    assert_eq!(
        info.attributes.get("CKA_KEY_TYPE"),
        Some(&AttrValue::Symbol("CKK_DES3".into()))
    );
    assert!(!info.exportable);
    assert_eq!(info.size_bits, Some(192));
    assert_eq!(
        provider.find_key(&sel("des3")).unwrap().algorithm,
        KeyAlgorithm::Other
    );
    let err = provider.export_key(&info).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("not supported"));
    let err = provider
        .sign(&info, &mech("AES-CMAC", vec![]), b"x")
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(
        err.message,
        "key type CKK_DES3 of 'hsm:des3#03' is not supported by r2 for sign"
    );
    let err = provider
        .encrypt(&info, &mech("AES-ECB", vec![]), &[b'x'; 16])
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    let template = provider.read_full_template(&info).unwrap();
    assert_eq!(
        template.get("CKA_KEY_TYPE").unwrap().value,
        AttrValue::Symbol("CKK_DES3".into())
    );
    provider.delete_key(&info).unwrap();
    let err = provider.find_key(&sel("des3")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotFound);
}

// ---------------------------------------------------------------------------
// c2 test_provider_objects.py verb cases
// ---------------------------------------------------------------------------

#[test]
fn rsa_raw_decrypt_with_public_key_runs_in_software() {
    // §5.8 signature recovery: no C_Decrypt with a public handle — the provider computes
    // the public-exponent modexp from CKA_MODULUS/CKA_PUBLIC_EXPONENT.
    let (backend, provider) = logged_in();
    let (_private, public) = rsa_pair(&provider, "rawpub");
    let objects = backend.objects();
    let modulus = objects
        .iter()
        .find(|(h, _)| Some(*h) == public.handle)
        .map(|(_, attrs)| attrs[&CKA_MODULUS].clone())
        .unwrap();
    let calls = backend.calls().len();
    let out = provider
        .decrypt(&public, &mech("RSA-RAW", vec![]), &[2])
        .unwrap();
    // pow(2, 65537, n) as len(modulus) big-endian bytes
    let n = openssl::bn::BigNum::from_slice(&modulus).unwrap();
    let two = openssl::bn::BigNum::from_u32(2).unwrap();
    let e = openssl::bn::BigNum::from_u32(65537).unwrap();
    let mut expected = openssl::bn::BigNum::new().unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    expected.mod_exp(&two, &e, &n, &mut ctx).unwrap();
    let expected = expected
        .to_vec_padded(i32::try_from(modulus.len()).unwrap())
        .unwrap();
    assert_eq!(out.as_slice(), expected.as_slice());
    assert!(!backend.calls()[calls..].contains(&"decrypt")); // never on the token
}

#[test]
fn mechanism_invalid_maps_to_unsupported() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&aes((0u8..32).collect()), "ckr-1", None, None)
        .unwrap();
    // AES-CBC advertised, but the token errors at invocation time
    backend.fail_next("encrypt", rv::CKR_MECHANISM_INVALID);
    let err = provider
        .encrypt(
            &info,
            &mech("AES-CBC", vec![("iv", pbytes(&[0; 16]))]),
            b"0123456789abcdef",
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(
        err.message,
        "token does not support encrypt with AES-CBC (or its parameters) (CKR_MECHANISM_INVALID)"
    );
}

const VENDOR_CKM: u64 = 0x8000_0A01;

#[test]
fn custom_dispatch_uses_raw_ckm() {
    let mut custom = BTreeMap::new();
    custom.insert(VENDOR_CKM, "vendor.acme.kcv".to_string());
    let (backend, provider) = logged_in_with(mechs_with(&[VENDOR_CKM]), custom, IndexMap::new());
    let info = provider
        .import_key(&aes((0u8..32).collect()), "vendor-key", None, None)
        .unwrap();
    let mut invocation = mech("vendor.acme.kcv", vec![]);
    invocation.raw_ckm = Some(VENDOR_CKM);
    invocation.param_struct = r2_core::params::ParamStruct::Raw;
    invocation.raw_param_bytes = Some(vec![1, 2]);
    let signature = provider.sign(&info, &invocation, b"kcv input").unwrap();
    assert!(!signature.is_empty());
    assert!(
        provider
            .verify(&info, &invocation, b"kcv input", &signature)
            .unwrap()
    );
    assert_eq!(last_ckm(&backend), VENDOR_CKM);
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Bytes {
            ckm: VENDOR_CKM,
            param: vec![1, 2]
        })
    );
}

#[test]
fn unadvertised_mechanism_rejected() {
    let (_backend, provider) = logged_in();
    let info = provider
        .import_key(&aes((0u8..32).collect()), "no-mech", None, None)
        .unwrap();
    let err = provider
        .encrypt(&info, &mech("NO-SUCH-MECH", vec![]), b"x")
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(err.message, "hsm does not support mechanism NO-SUCH-MECH");
}

#[test]
fn derive_extractable_returns_raw() {
    let (_backend, provider) = logged_in();
    let base = ec_private(&provider, "drv-1", Curve::P256);
    let mut peer = vec![4u8];
    peer.extend([0u8; 64]);
    let result = provider
        .derive(&base, &mech("ECDH", vec![("peer", pbytes(&peer))]))
        .unwrap();
    let raw = result.raw.as_ref().unwrap();
    assert_eq!(raw.len(), 32);
    let key = result.key.as_ref().unwrap();
    assert!(key.exportable);
    assert_eq!(key.key_ref.label, "drv-1.shared");
    assert_eq!(key.algorithm, KeyAlgorithm::Generic);
    assert_eq!(key.key_ref.key_id.as_ref().map(Vec::len), Some(4));
}

#[test]
fn derive_degrades_to_resident_key_when_forbidden() {
    // §5.10 [U]: the token forbids extractable generic secrets → the provider retries
    // with a resident template and returns raw=None
    let (backend, provider) = logged_in();
    backend.set_forbid_extractable_secrets(true);
    let base = ec_private(&provider, "drv-2", Curve::P256);
    let mut peer = vec![4u8];
    peer.extend([0u8; 64]);
    let result = provider
        .derive(
            &base,
            &mech("ECDH", vec![("peer", pbytes(&peer)), ("out_len", pint(48))]),
        )
        .unwrap();
    assert!(result.raw.is_none());
    let key = result.key.unwrap();
    assert!(!key.exportable);
    assert_eq!(key.size_bits, Some(48 * 8));
    let mut expected = BTreeMap::new();
    expected.insert("CKA_SENSITIVE".to_string(), AttrValue::Bool(true));
    expected.insert("CKA_EXTRACTABLE".to_string(), AttrValue::Bool(false));
    assert_eq!(key.attributes, expected);
    // first the extractable template, then the resident one
    let derives = backend
        .calls()
        .iter()
        .filter(|c| **c == "derive_key")
        .count();
    assert_eq!(derives, 2);
}

#[test]
fn derive_template_is_c2s() {
    let (backend, provider) = logged_in();
    let base = ec_private(&provider, "drv-3", Curve::P384);
    let mut peer = vec![4u8];
    peer.extend([1u8; 96]);
    let result = provider
        .derive(&base, &mech("ECDH", vec![("peer", pbytes(&peer))]))
        .unwrap();
    // out_len 0 → the curve's field size (p384: 48)
    assert_eq!(result.raw.as_ref().unwrap().len(), 48);
    let derived = backend
        .objects()
        .into_iter()
        .find(|(h, _)| Some(*h) == result.key.as_ref().unwrap().handle)
        .unwrap()
        .1;
    assert_eq!(derived[&CKA_CLASS], ul(CKO_SECRET_KEY));
    assert_eq!(derived[&CKA_KEY_TYPE], ul(0x10)); // CKK_GENERIC_SECRET
    assert_eq!(derived[&0x0001], vec![0]); // CKA_TOKEN false
    assert_eq!(derived[&CKA_SENSITIVE], vec![0]);
    assert_eq!(derived[&CKA_EXTRACTABLE], vec![1]);
    assert_eq!(derived[&CKA_VALUE_LEN], ul(48));
    assert_eq!(derived[&CKA_LABEL], b"drv-3.shared".to_vec());
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Ecdh1 {
            kdf: 1,
            shared_data: Vec::new(),
            public_data: peer
        })
    );
}

#[test]
fn derive_peer_rules() {
    let (_backend, provider) = logged_in();
    let base = ec_private(&provider, "drv-4", Curve::P256);
    let derive = |peer: &[u8]| provider.derive(&base, &mech("ECDH", vec![("peer", pbytes(peer))]));
    let err = derive(&[2u8; 33]).unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(
        err.message,
        "EC peer must be SPKI DER or an uncompressed 0x04‖X‖Y point"
    );
    assert_eq!(err.param_name(), Some("peer"));
    // an SPKI peer becomes its uncompressed point
    let peer_key = openssl::ec::EcKey::generate(
        &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
    )
    .unwrap();
    let spki = PKey::from_ec_key(peer_key)
        .unwrap()
        .public_key_to_der()
        .unwrap();
    assert!(derive(&spki).is_ok());
    // an RSA SPKI is no agreement key
    let rsa_spki = PKey::from_rsa(openssl::rsa::Rsa::generate(1024).unwrap())
        .unwrap()
        .public_key_to_der()
        .unwrap();
    let err = derive(&rsa_spki).unwrap_err();
    assert_eq!(err.message, "peer SPKI is not an EC/X25519/X448 key");
    // garbage after 0x30 is no SPKI
    let err = derive(&[0x30, 0x03, 0x01]).unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(
        err.message,
        "peer is not a valid SPKI public key: Could not deserialize key data. The data may \
         be in an incorrect format, it may be encrypted with an unsupported algorithm, or it \
         may be an unsupported key type (e.g. EC curves with explicit parameters). Details: \
         ASN.1 parsing error: short data (needed at least 2 additional bytes)"
    );
    assert_eq!(err.param_name(), Some("peer"));
    // an unknown kdf
    let err = provider
        .derive(
            &base,
            &mech("ECDH", vec![("peer", pbytes(&spki)), ("kdf", penum("md5"))]),
        )
        .unwrap_err();
    assert_eq!(err.message, "unknown ECDH kdf 'md5'");
    // public keys and certificates cannot derive
    let public = provider
        .find_key(&sel("drv-4").with_class(Some(KeyClass::Public)))
        .unwrap();
    let err = provider.derive(&public, &mech("ECDH", vec![])).unwrap_err();
    assert_eq!(err.message, "derive requires a private key");
}

#[test]
fn derive_negative_out_len_is_the_tokens_value_invalid() {
    // §11 D12(q): CKA_VALUE_LEN is a CK_ULONG — a negative out_len never reaches the token
    let (backend, provider) = logged_in();
    let base = ec_private(&provider, "drv-neg", Curve::P256);
    let peer_key = openssl::ec::EcKey::generate(
        &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
    )
    .unwrap();
    let spki = PKey::from_ec_key(peer_key)
        .unwrap()
        .public_key_to_der()
        .unwrap();
    let err = provider
        .derive(
            &base,
            &mech("ECDH", vec![("peer", pbytes(&spki)), ("out_len", pint(-1))]),
        )
        .unwrap_err();
    assert_eq!(err.kind.class_name(), "Pkcs11Error");
    assert_eq!(
        err.message,
        "template attribute rejected by token (CKR_ATTRIBUTE_VALUE_INVALID)"
    );
    assert!(!backend.calls().contains(&"derive_key"));
}

#[test]
fn sign_with_twins_uses_selected_twin() {
    let (backend, provider) = logged_in();
    let first = provider
        .import_key(&aes((0u8..32).collect()), "twin", None, Some(&[0x0a]))
        .unwrap();
    let other: Vec<u8> = (32u8..64).collect();
    let clone = backend.clone_object(first.handle.unwrap(), Some(&other));
    let by_handle = |handle: u64| {
        provider
            .find_key(
                &sel("twin")
                    .with_class(Some(KeyClass::Secret))
                    .with_handle(Some(handle)),
            )
            .unwrap()
    };
    let original = by_handle(first.handle.unwrap());
    let picked = by_handle(clone);
    let cmac = mech("AES-CMAC", vec![("mac_len", pint(16))]);
    let data = b"which twin signed this?";
    let sig_original = provider.sign(&original, &cmac, data).unwrap();
    let sig_picked = provider.sign(&picked, &cmac, data).unwrap();
    assert_ne!(sig_original, sig_picked);
    assert!(
        provider
            .verify(&original, &cmac, data, &sig_original)
            .unwrap()
    );
    assert!(
        !provider
            .verify(&picked, &cmac, data, &sig_original)
            .unwrap()
    );
}

// ---------------------------------------------------------------------------
// encrypt/decrypt fallbacks and mechanism selection (§5.8)
// ---------------------------------------------------------------------------

#[test]
fn ecb_pkcs7_padding_is_provider_side() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&aes((0u8..16).collect()), "ecb", None, None)
        .unwrap();
    let pkcs7 = mech("AES-ECB", vec![("padding", penum("pkcs7"))]);
    let ct = provider.encrypt(&info, &pkcs7, b"short").unwrap();
    assert_eq!(ct.len(), 16); // padded before the token call
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Plain { ckm: CKM_AES_ECB })
    );
    assert_eq!(
        provider.decrypt(&info, &pkcs7, &ct).unwrap().as_slice(),
        b"short"
    );
    // a whole block of padding for aligned input
    let ct = provider.encrypt(&info, &pkcs7, &[7; 16]).unwrap();
    assert_eq!(ct.len(), 32);
    // padding=none needs aligned input (checked before the token)
    let none = mech("AES-ECB", vec![]);
    let err = provider.encrypt(&info, &none, b"short").unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(
        err.message,
        "data length must be a multiple of 16 with padding=none"
    );
    assert_eq!(err.param_name(), Some("padding"));
    // bad padding after a raw decrypt
    let raw = provider.encrypt(&info, &none, &[0; 16]).unwrap();
    let err = provider.decrypt(&info, &pkcs7, &raw).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Crypto);
    assert_eq!(err.message, "invalid PKCS7 padding in decrypted data");
}

#[test]
fn empty_one_shot_input_is_the_tokens_arguments_bad() {
    // SoftHSM-like FakeBackend: an empty one-shot buffer (sent as NULL, §4.5.5) is
    // CKR_ARGUMENTS_BAD for encrypt/decrypt/sign/verify — before any provider-side unpadding
    let (_backend, provider) = logged_in();
    let info = provider
        .import_key(&aes((0u8..16).collect()), "empty", None, None)
        .unwrap();
    let mac = provider
        .import_key(&generic(), "empty-mac", None, None)
        .unwrap();
    let ecb = mech("AES-ECB", vec![]);
    let pkcs7 = mech("AES-ECB", vec![("padding", penum("pkcs7"))]);
    let hmac = mech("HMAC", vec![("hash", penum("sha256"))]);
    let cases = [
        (
            provider.encrypt(&info, &ecb, b"").unwrap_err(),
            "PKCS#11 encrypt with AES-ECB failed (CKR_ARGUMENTS_BAD)",
        ),
        (
            provider.decrypt(&info, &pkcs7, b"").unwrap_err(),
            "PKCS#11 decrypt with AES-ECB failed (CKR_ARGUMENTS_BAD)",
        ),
        (
            provider
                .sign(&info, &mech("AES-CMAC", vec![]), b"")
                .unwrap_err(),
            "PKCS#11 sign with AES-CMAC failed (CKR_ARGUMENTS_BAD)",
        ),
        (
            provider.verify(&mac, &hmac, b"", &[0; 32]).unwrap_err(),
            "PKCS#11 verify with HMAC failed (CKR_ARGUMENTS_BAD)",
        ),
    ];
    for (err, text) in cases {
        assert_eq!(err.kind.class_name(), "Pkcs11Error", "{}", err.message);
        assert_eq!(err.message, text);
    }
}

#[test]
fn cbc_picks_the_ckm_by_padding_and_requires_it() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&aes((0u8..16).collect()), "cbc", None, None)
        .unwrap();
    let iv: Vec<u8> = (0u8..16).collect();
    provider
        .encrypt(&info, &mech("AES-CBC", vec![("iv", pbytes(&iv))]), b"x")
        .unwrap();
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Bytes {
            ckm: CKM_AES_CBC_PAD,
            param: iv.clone()
        })
    );
    provider
        .encrypt(
            &info,
            &mech(
                "AES-CBC",
                vec![("iv", pbytes(&iv)), ("padding", penum("none"))],
            ),
            &[0; 16],
        )
        .unwrap();
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Bytes {
            ckm: CKM_AES_CBC,
            param: iv.clone()
        })
    );
    let (_b, provider) = logged_in_with(
        mechs_without(&[CKM_AES_CBC_PAD]),
        BTreeMap::new(),
        IndexMap::new(),
    );
    let info = provider
        .import_key(&aes((0u8..16).collect()), "cbc2", None, None)
        .unwrap();
    let err = provider
        .encrypt(&info, &mech("AES-CBC", vec![("iv", pbytes(&iv))]), b"x")
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(
        err.message,
        "token lacks CKM_AES_CBC_PAD for AES-CBC padding=pkcs7"
    );
    // a missing iv
    let err = provider
        .encrypt(
            &info,
            &mech("AES-CBC", vec![("padding", penum("none"))]),
            &[0; 16],
        )
        .unwrap_err();
    assert_eq!(err.message, "missing parameter 'iv'");
    assert_eq!(err.param_name(), Some("iv"));
}

#[test]
fn gcm_and_ctr_build_their_parameter_structs() {
    let (backend, provider) = logged_in();
    let info = provider
        .import_key(&aes((0u8..32).collect()), "gcm", None, None)
        .unwrap();
    let gcm = mech(
        "AES-GCM",
        vec![
            ("iv", pbytes(&[1; 12])),
            ("aad", pbytes(b"hdr")),
            ("tag_bits", penum("96")),
        ],
    );
    let ct = provider.encrypt(&info, &gcm, b"payload").unwrap();
    assert_eq!(ct.len(), 7 + 12); // ct‖tag native
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Gcm {
            ckm: CKM_AES_GCM,
            iv: vec![1; 12],
            aad: zeroize::Zeroizing::new(b"hdr".to_vec()),
            tag_bits: 96
        })
    );
    assert_eq!(
        provider.decrypt(&info, &gcm, &ct).unwrap().as_slice(),
        b"payload"
    );
    let ctr = mech("AES-CTR", vec![("counter_block", pbytes(&[2; 16]))]);
    provider.encrypt(&info, &ctr, b"stream").unwrap();
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Ctr {
            counter_bits: 128,
            counter_block: [2; 16]
        })
    );
}

#[test]
fn oaep_falls_back_to_software_padding_when_the_token_rejects_the_params() {
    // the fake token (like SoftHSM) accepts only SHA-1/MGF1-SHA1 OAEP with an empty label
    let (backend, provider) = logged_in();
    let pkcs8 = r2_testkit::fixtures::rsa2048_pkcs8();
    let private = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, pkcs8.clone()),
            "oaep",
            Some(&exportable()),
            None,
        )
        .unwrap();
    let public_spki = r2_core::formats::pkcs8_public_spki(&pkcs8).unwrap();
    let public = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Public, public_spki),
            "oaep",
            None,
            private.key_ref.key_id.as_deref(),
        )
        .unwrap();
    let sha256 = mech(
        "RSA-OAEP",
        vec![
            ("hash", penum("sha256")),
            ("mgf_hash", penum("sha256")),
            ("label", pbytes(b"L")),
        ],
    );
    let ct = provider
        .encrypt(&public, &sha256, b"secret payload")
        .unwrap();
    assert_eq!(ct.len(), 256);
    // the token was asked first, then OpenSSL padded with the token's public numbers
    assert_eq!(
        backend.calls().iter().filter(|c| **c == "encrypt").count(),
        1
    );
    let key = PKey::private_key_from_der(&pkcs8).unwrap();
    let mut decrypter = openssl::encrypt::Decrypter::new(&key).unwrap();
    decrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
    decrypter
        .set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())
        .unwrap();
    decrypter
        .set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())
        .unwrap();
    decrypter.set_rsa_oaep_label(b"L").unwrap();
    let mut out = vec![0; decrypter.decrypt_len(&ct).unwrap()];
    let n = decrypter.decrypt(&ct, &mut out).unwrap();
    assert_eq!(&out[..n], b"secret payload");
    // SHA-1 with an empty label is accepted by the token: no fallback
    let sha1 = mech("RSA-OAEP", vec![("hash", penum("sha1"))]);
    let before = backend.calls().len();
    provider.encrypt(&public, &sha1, b"x").unwrap();
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Oaep {
            ckm: CKM_RSA_PKCS_OAEP,
            hash_ckm: 0x220,
            mgf: 1,
            label: Vec::new()
        })
    );
    assert_eq!(
        &backend.calls()[before..]
            .iter()
            .filter(|c| **c == "encrypt")
            .count(),
        &1
    );
    // decrypt fallback: raw RSA on the token (CKM_RSA_X_509), OAEP decoded in software
    let _ = provider.decrypt(&private, &sha256, &ct);
    assert_eq!(last_ckm(&backend), CKM_RSA_X_509);
}

#[test]
fn oaep_software_fallback_failure_is_a_crypto_error() {
    // §11 D12(q): pyca's ValueError escaped c2; r2 reports the memory provider's text
    let (backend, provider) = logged_in();
    let pkcs8 = r2_testkit::fixtures::rsa2048_pkcs8();
    let public_spki = r2_core::formats::pkcs8_public_spki(&pkcs8).unwrap();
    let public = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Public, public_spki),
            "oaep-long",
            None,
            None,
        )
        .unwrap();
    let sha256 = mech("RSA-OAEP", vec![("hash", penum("sha256"))]);
    // k − 2·hLen − 2 = 256 − 66 = 190 bytes fit; 191 do not
    assert_eq!(
        provider
            .encrypt(&public, &sha256, &[7u8; 190])
            .unwrap()
            .len(),
        256
    );
    let err = provider.encrypt(&public, &sha256, &[7u8; 191]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Crypto);
    assert_eq!(
        err.message,
        "RSA-OAEP encryption failed: data too large for key size"
    );
    // the token refused the parameters first
    assert!(backend.calls().contains(&"encrypt"));
}

#[test]
fn oaep_decode_is_rfc8017() {
    // EM produced by a raw private RSA operation over an OpenSSL OAEP ciphertext
    let key = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(key.clone()).unwrap();
    for (hash, mgf, label) in [
        ("sha256", "sha256", b"".as_slice()),
        ("sha384", "sha1", b"lbl".as_slice()),
        ("sha1", "sha1", b"".as_slice()),
    ] {
        let md = |name: &str| match name {
            "sha1" => openssl::hash::MessageDigest::sha1(),
            "sha384" => openssl::hash::MessageDigest::sha384(),
            _ => openssl::hash::MessageDigest::sha256(),
        };
        let mut encrypter = openssl::encrypt::Encrypter::new(&pkey).unwrap();
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        encrypter.set_rsa_oaep_md(md(hash)).unwrap();
        encrypter.set_rsa_mgf1_md(md(mgf)).unwrap();
        if !label.is_empty() {
            encrypter.set_rsa_oaep_label(label).unwrap();
        }
        let mut ct = vec![0; encrypter.encrypt_len(b"msg").unwrap()];
        let n = encrypter.encrypt(b"msg", &mut ct).unwrap();
        ct.truncate(n);
        let mut em = vec![0; 256];
        let m = key.private_decrypt(&ct, &mut em, Padding::NONE).unwrap();
        em.truncate(m);
        let plain = crate::mechanisms::oaep_decode(&em, hash, mgf, label).unwrap();
        assert_eq!(plain.as_slice(), b"msg");
        let err = crate::mechanisms::oaep_decode(&em, hash, mgf, b"wrong").unwrap_err();
        assert_eq!(err.message, "OAEP decoding failed");
        assert_eq!(
            err.hint.as_deref(),
            Some("wrong key, hash or label parameters?")
        );
    }
}

#[test]
fn rsa_raw_pads_to_the_modulus_and_refuses_longer_input() {
    let (backend, provider) = logged_in();
    let (private, public) = rsa_pair(&provider, "raw");
    let ct = provider
        .encrypt(&public, &mech("RSA-RAW", vec![]), &[1, 2, 3])
        .unwrap();
    assert_eq!(ct.len(), 256); // left-padded to the modulus length before the call
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Plain { ckm: CKM_RSA_X_509 })
    );
    let err = provider
        .encrypt(&public, &mech("RSA-RAW", vec![]), &[1; 257])
        .unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(
        err.message,
        "input (257 bytes) exceeds the RSA modulus length (256 bytes)"
    );
    assert_eq!(err.param_name(), Some("data"));
    let sig = provider
        .sign(&private, &mech("RSA-RAW", vec![]), &[9])
        .unwrap();
    assert!(
        provider
            .verify(&public, &mech("RSA-RAW", vec![]), &[9], &sig)
            .unwrap()
    );
}

// ---------------------------------------------------------------------------
// sign/verify mechanism selection (§5.9)
// ---------------------------------------------------------------------------

#[test]
fn pkcs1_prefers_the_combined_ckm_else_digestinfo_over_bare_rsa_pkcs() {
    let (backend, provider) = logged_in();
    let (private, public) = rsa_pair(&provider, "p1");
    let sha256 = mech("RSA-PKCS1", vec![("hash", penum("sha256"))]);
    let sig = provider.sign(&private, &sha256, b"data").unwrap();
    assert_eq!(last_ckm(&backend), CKM_SHA256_RSA_PKCS);
    assert!(provider.verify(&public, &sha256, b"data", &sig).unwrap());
    // sha384 is not combined on this token → local DigestInfo + CKM_RSA_PKCS
    let sha384 = mech("RSA-PKCS1", vec![("hash", penum("sha384"))]);
    let sig = provider.sign(&private, &sha384, b"data").unwrap();
    assert_eq!(last_ckm(&backend), CKM_RSA_PKCS);
    let info = crate::mechanisms::digest_info("sha384", b"data").unwrap();
    let direct = backend
        .sign(
            &MechSpec::Plain { ckm: CKM_RSA_PKCS },
            private.handle.unwrap(),
            &info,
        )
        .unwrap();
    assert_eq!(sig, direct);
    assert!(provider.verify(&public, &sha384, b"data", &sig).unwrap());
    assert!(!provider.verify(&public, &sha384, b"data!", &sig).unwrap());
    // an unknown hash is a Param error (c2 crashed with KeyError, §11 D12(q))
    let err = provider
        .sign(
            &private,
            &mech("RSA-PKCS1", vec![("hash", penum("md5"))]),
            b"x",
        )
        .unwrap_err();
    assert_eq!(err.message, "unknown hash 'md5'");
}

#[test]
fn ecdsa_hashes_locally_for_a_bare_ckm_ecdsa_token() {
    let (backend, provider) = logged_in_with(
        mechs_without(&[CKM_ECDSA_SHA256]),
        BTreeMap::new(),
        IndexMap::new(),
    );
    let private = ec_private(&provider, "ec1", Curve::P256);
    let public = provider
        .find_key(&sel("ec1").with_class(Some(KeyClass::Public)))
        .unwrap();
    let ecdsa = mech("ECDSA", vec![("hash", penum("sha256"))]);
    let sig = provider.sign(&private, &ecdsa, b"data").unwrap();
    assert_eq!(sig.len(), 64);
    assert_eq!(last_ckm(&backend), CKM_ECDSA);
    let digest = openssl::sha::sha256(b"data");
    let direct = backend
        .sign(
            &MechSpec::Plain { ckm: CKM_ECDSA },
            private.handle.unwrap(),
            &digest,
        )
        .unwrap();
    assert_eq!(sig, direct);
    assert!(provider.verify(&public, &ecdsa, b"data", &sig).unwrap());
    // combined on the default token
    let (backend, provider) = logged_in();
    let private = ec_private(&provider, "ec2", Curve::P256);
    provider.sign(&private, &ecdsa, b"data").unwrap();
    assert_eq!(last_ckm(&backend), CKM_ECDSA_SHA256);
}

#[test]
fn pss_resolves_the_salt_and_prefers_the_combined_ckm() {
    let (backend, provider) = logged_in();
    let (private, public) = rsa_pair(&provider, "pss");
    let sha256 = mech("RSA-PSS", vec![("hash", penum("sha256"))]);
    let sig = provider.sign(&private, &sha256, b"data").unwrap();
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Pss {
            ckm: CKM_SHA256_RSA_PKCS_PSS,
            hash_ckm: 0x250,
            mgf: 2,
            salt_len: 32
        })
    );
    assert!(provider.verify(&public, &sha256, b"data", &sig).unwrap());
    // salt_len=-1 → ceil(bits/8) − hLen − 2; sha512 not combined → bare PSS over a digest
    let max = mech(
        "RSA-PSS",
        vec![
            ("hash", penum("sha512")),
            ("mgf_hash", penum("sha1")),
            ("salt_len", pint(-1)),
        ],
    );
    provider.sign(&private, &max, b"data").unwrap();
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Pss {
            ckm: CKM_RSA_PKCS_PSS,
            hash_ckm: 0x270,
            mgf: 1,
            salt_len: 256 - 64 - 2
        })
    );
    let err = provider
        .sign(
            &private,
            &mech("RSA-PSS", vec![("salt_len", pint(-2))]),
            b"data",
        )
        .unwrap_err();
    assert_eq!(err.message, "salt_len must be >= -1");
    assert_eq!(err.param_name(), Some("salt_len"));
}

#[test]
fn eddsa_uses_the_listed_ckm_and_ed448_params() {
    let (backend, provider) = logged_in();
    let ed25519 = ec_private(&provider, "ed", Curve::Ed25519);
    provider
        .sign(&ed25519, &mech("EDDSA", vec![]), b"m")
        .unwrap();
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Eddsa {
            ckm: CKM_EDDSA,
            ed448: false
        })
    );
    let ed448 = ec_private(&provider, "ed4", Curve::Ed448);
    provider.sign(&ed448, &mech("EDDSA", vec![]), b"m").unwrap();
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Eddsa {
            ckm: CKM_EDDSA,
            ed448: true
        })
    );
    // a token with only a vendor EdDSA id uses the advisory probe
    let vendor = crate::capability::EDDSA_VENDOR_CKMS[0];
    let (backend, provider) = logged_in_with(
        {
            let mut m = mechs_without(&[CKM_EDDSA]);
            m.push(vendor);
            m
        },
        BTreeMap::new(),
        IndexMap::new(),
    );
    let ed = ec_private(&provider, "edv", Curve::Ed25519);
    // the fake token signs with any listed code
    let _ = provider.sign(&ed, &mech("EDDSA", vec![]), b"m");
    assert_eq!(
        backend.last_mechanism(),
        Some(MechSpec::Eddsa {
            ckm: vendor,
            ed448: false
        })
    );
}

#[test]
fn certificates_stand_in_for_public_keys_only() {
    let (_backend, provider) = logged_in();
    let (pkcs8, cert) = r2_testkit::fixtures::rsa_pkcs8_and_cert();
    let private = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, pkcs8),
            "crt",
            Some(&exportable()),
            Some(&[0x42]),
        )
        .unwrap();
    let certificate = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert),
            "crt",
            None,
            Some(&[0x42]),
        )
        .unwrap();
    let pkcs1 = mech("RSA-PKCS1", vec![]);
    let sig = provider.sign(&private, &pkcs1, b"m").unwrap();
    // verify with the certificate: resolved to a session public key from its SPKI
    assert!(provider.verify(&certificate, &pkcs1, b"m", &sig).unwrap());
    for err in [
        provider.sign(&certificate, &pkcs1, b"m").unwrap_err(),
        provider.decrypt(&certificate, &pkcs1, b"m").unwrap_err(),
        provider
            .derive(&certificate, &mech("ECDH", vec![]))
            .unwrap_err(),
    ] {
        assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
        assert!(err.message.starts_with("certificates cannot be used for "));
        assert_eq!(
            err.hint.as_deref(),
            Some("certificates stand in for PUBLIC keys only (encrypt/verify/wrap)")
        );
    }
}
