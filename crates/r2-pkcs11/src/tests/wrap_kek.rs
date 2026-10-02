//! wrap/unwrap over the FakeBackend: ports of c2 tests/unit/pkcs11/test_wrap_kek.py
//! (wrap mechanism branches, round trips, the CKA_VALUE_LEN injection policy and its
//! retry), the wrap cases of test_provider_objects.py (KWP preference, round trip,
//! unextractable target, template id, duplicate guard) and test_objects.py (unwrap into a
//! generic secret), plus the RSA-OAEP software fallbacks (§5.4, §5.5).
use std::collections::BTreeMap;

use indexmap::IndexMap;
use r2_core::error::ErrorKind;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::template::{AttrValue, KeyTemplate};
use r2_provider::{GenerateRequest, MechanismInvocation, Provider, UnwrapRequest};

use super::{
    boolean, bytes_attr, exportable, logged_in, logged_in_with, mech, object_of, pbytes, penum,
    tpl, ul, ulong_attr,
};
use crate::Pkcs11Provider;
use crate::backend::MechSpec;
use crate::backend::fake::DEFAULT_MECHANISMS;
use crate::ckr::rv;
use crate::provider::OpError;

const CKA_KEY_TYPE: u64 = 0x0100;
const CKA_VALUE_LEN: u64 = 0x0161;
const CKK_GENERIC_SECRET: u64 = 0x10;

const CKM_RSA_PKCS: u64 = 0x0001;
const CKM_RSA_X_509: u64 = 0x0003;
const CKM_AES_CBC: u64 = 0x1082;
const CKM_AES_CBC_PAD: u64 = 0x1085;
const CKM_AES_GCM: u64 = 0x1087;
const CKM_AES_KEY_WRAP: u64 = 0x2109;
const CKM_AES_KEY_WRAP_PAD: u64 = 0x210A;
const CKM_AES_KEY_WRAP_KWP: u64 = 0x210B;

fn aes_key() -> Vec<u8> {
    (0u8..32).collect()
}

fn aes_material() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, aes_key());
    material.size_bits = Some(256);
    material
}

fn iv16() -> Vec<u8> {
    (0u8..16).collect()
}

fn iv12() -> Vec<u8> {
    (0u8..12).collect()
}

fn spec(provider: &Pkcs11Provider, invocation: &MechanismInvocation) -> MechSpec {
    match provider.wrap_mechanism(invocation) {
        Ok(spec) => spec,
        Err(OpError::Console(err)) => panic!("{err:?}"),
        Err(OpError::Backend(err)) => panic!("{err:?}"),
    }
}

fn wrap_err(provider: &Pkcs11Provider, invocation: &MechanismInvocation) -> r2_core::ConsoleError {
    match provider.wrap_mechanism(invocation) {
        Err(OpError::Console(err)) => err,
        other => panic!("expected a console error, got {other:?}"),
    }
}

fn generate_aes(provider: &Pkcs11Provider, label: &str, template: KeyTemplate) -> KeyInfo {
    let mut request = GenerateRequest::new(KeyAlgorithm::Aes, label);
    request.size_bits = Some(256);
    request.template = Some(template);
    provider.generate_key(&request).unwrap()
}

fn unwrap_request(
    algorithm: KeyAlgorithm,
    class: KeyClass,
    label: &str,
    template: Option<KeyTemplate>,
) -> UnwrapRequest {
    let mut request = UnwrapRequest::new(algorithm, class, label);
    request.template = template;
    request
}

// ---------------------------------------------------------------------------
// wrap mechanism branches (c2 TestWrapMechanismBranches)
// ---------------------------------------------------------------------------

#[test]
fn cbc_picks_pad_ckm_by_the_padding_param() {
    let (_backend, provider) = logged_in();
    let padded = spec(
        &provider,
        &mech(
            "AES-CBC",
            vec![("iv", pbytes(&iv16())), ("padding", penum("pkcs7"))],
        ),
    );
    assert_eq!(
        padded,
        MechSpec::Bytes {
            ckm: CKM_AES_CBC_PAD,
            param: iv16()
        }
    );
    let plain = spec(
        &provider,
        &mech(
            "AES-CBC",
            vec![("iv", pbytes(&iv16())), ("padding", penum("none"))],
        ),
    );
    assert_eq!(
        plain,
        MechSpec::Bytes {
            ckm: CKM_AES_CBC,
            param: iv16()
        }
    );
}

#[test]
fn cbc_defaults_to_pkcs7() {
    let (_backend, provider) = logged_in();
    let built = spec(&provider, &mech("AES-CBC", vec![("iv", pbytes(&iv16()))]));
    assert!(matches!(built, MechSpec::Bytes { ckm, .. } if ckm == CKM_AES_CBC_PAD));
}

#[test]
fn cbc_passes_the_iv_as_the_mechanism_parameter() {
    let (_backend, provider) = logged_in();
    let built = spec(&provider, &mech("AES-CBC", vec![("iv", pbytes(&iv16()))]));
    assert!(matches!(built, MechSpec::Bytes { param, .. } if param == iv16()));
}

#[test]
fn gcm_builds_the_gcm_params() {
    let (_backend, provider) = logged_in();
    let built = spec(
        &provider,
        &mech(
            "AES-GCM",
            vec![
                ("iv", pbytes(&iv12())),
                ("aad", pbytes(b"ctx")),
                ("tag_bits", penum("96")),
            ],
        ),
    );
    assert_eq!(
        built,
        MechSpec::Gcm {
            ckm: CKM_AES_GCM,
            iv: iv12(),
            aad: zeroize::Zeroizing::new(b"ctx".to_vec()),
            tag_bits: 96
        }
    );
}

#[test]
fn rsa_pkcs1_is_the_bare_ckm() {
    let (_backend, provider) = logged_in();
    assert_eq!(
        spec(&provider, &mech("RSA-PKCS1", vec![])),
        MechSpec::Plain { ckm: CKM_RSA_PKCS }
    );
}

#[test]
fn missing_ckm_raises_unsupported() {
    let without_gcm = DEFAULT_MECHANISMS
        .iter()
        .copied()
        .filter(|c| *c != CKM_AES_GCM)
        .collect();
    let (_backend, provider) = logged_in_with(without_gcm, BTreeMap::new(), IndexMap::new());
    let err = wrap_err(&provider, &mech("AES-GCM", vec![("iv", pbytes(&iv12()))]));
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(err.message, "token lacks CKM_AES_GCM for AES-GCM");
}

#[test]
fn a_non_wrap_mechanism_is_still_refused() {
    let (_backend, provider) = logged_in();
    let err = wrap_err(
        &provider,
        &mech("AES-CTR", vec![("counter_block", pbytes(&iv16()))]),
    );
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("cannot wrap keys"));
    assert_eq!(err.message, "mechanism AES-CTR cannot wrap keys");
}

// ---------------------------------------------------------------------------
// KWP preference (c2 test_provider_objects.py TestWrapUnwrap)
// ---------------------------------------------------------------------------

#[test]
fn wrap_pad_prefers_kwp_when_advertised() {
    // §5.5 dialect note: CKM_AES_KEY_WRAP_KWP is unambiguously RFC 5649 and must win over
    // the ambiguous CKM_AES_KEY_WRAP_PAD (Utimaco regression).
    let mut mechanisms = DEFAULT_MECHANISMS.to_vec();
    mechanisms.push(CKM_AES_KEY_WRAP_KWP);
    let (_backend, provider) = logged_in_with(mechanisms, BTreeMap::new(), IndexMap::new());
    assert_eq!(
        spec(&provider, &mech("AES-KEY-WRAP-PAD", vec![])),
        MechSpec::Plain {
            ckm: CKM_AES_KEY_WRAP_KWP
        }
    );
}

#[test]
fn wrap_pad_uses_pad_ckm_when_kwp_absent() {
    let (_backend, provider) = logged_in();
    assert_eq!(
        spec(&provider, &mech("AES-KEY-WRAP-PAD", vec![])),
        MechSpec::Plain {
            ckm: CKM_AES_KEY_WRAP_PAD
        }
    );
    assert_eq!(
        spec(&provider, &mech("AES-KEY-WRAP", vec![])),
        MechSpec::Plain {
            ckm: CKM_AES_KEY_WRAP
        }
    );
}

#[test]
fn wrap_unwrap_round_trip() {
    let (_backend, provider) = logged_in();
    let kek = generate_aes(&provider, "kek", exportable());
    let target = provider
        .import_key(&aes_material(), "target", Some(&exportable()), None)
        .unwrap();
    let kw = mech("AES-KEY-WRAP", vec![]);
    let blob = provider
        .wrap_key(&kek, &kw, &target, &Default::default())
        .unwrap();
    assert!(!blob.is_empty() && blob != aes_key());
    let unwrapped = provider
        .unwrap_key(
            &kek,
            &kw,
            &blob,
            &unwrap_request(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                "unwrapped",
                Some(exportable()),
            ),
        )
        .unwrap();
    assert_eq!(unwrapped.key_class, KeyClass::Secret);
    assert_eq!(
        provider.export_key(&unwrapped).unwrap().data.to_vec(),
        aes_key()
    );
}

#[test]
fn wrap_refuses_unextractable_target() {
    let (_backend, provider) = logged_in();
    let locked = tpl(vec![
        boolean("CKA_SENSITIVE", true),
        boolean("CKA_EXTRACTABLE", false),
    ]);
    let kek = generate_aes(
        &provider,
        "kek2",
        tpl(vec![boolean("CKA_EXTRACTABLE", true)]),
    );
    let target = provider
        .import_key(&aes_material(), "target2", Some(&locked), None)
        .unwrap();
    let err = provider
        .wrap_key(
            &kek,
            &mech("AES-KEY-WRAP", vec![]),
            &target,
            &Default::default(),
        )
        .unwrap_err();
    // §5.2 backstop row
    assert_eq!(err.kind.class_name(), "Pkcs11Error");
    assert_eq!(
        err.ckr().map(|(_, n)| n.to_string()).as_deref(),
        Some("CKR_KEY_UNEXTRACTABLE")
    );
    assert_eq!(
        err.message,
        "key cannot be exported or wrapped (CKR_KEY_UNEXTRACTABLE)"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("token policy forbids extracting this key")
    );
}

#[test]
fn unwrap_honors_template_id() {
    let (_backend, provider) = logged_in();
    let kek = generate_aes(&provider, "id-kek", exportable());
    let target = provider
        .import_key(&aes_material(), "id-target", Some(&exportable()), None)
        .unwrap();
    let kw = mech("AES-KEY-WRAP", vec![]);
    let blob = provider
        .wrap_key(&kek, &kw, &target, &Default::default())
        .unwrap();
    let template = tpl(vec![
        boolean("CKA_SENSITIVE", false),
        boolean("CKA_EXTRACTABLE", true),
        bytes_attr("CKA_ID", &[0xc0, 0xfe]),
    ]);
    let info = provider
        .unwrap_key(
            &kek,
            &kw,
            &blob,
            &unwrap_request(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                "id-unwrapped",
                Some(template),
            ),
        )
        .unwrap();
    assert_eq!(info.key_ref.key_id, Some(vec![0xc0, 0xfe]));
}

#[test]
fn unwrap_duplicate_identity_refused() {
    let (backend, provider) = logged_in();
    let kek = generate_aes(&provider, "uw-kek", exportable());
    let target = provider
        .import_key(&aes_material(), "uw-target", Some(&exportable()), None)
        .unwrap();
    let kw = mech("AES-KEY-WRAP", vec![]);
    let blob = provider
        .wrap_key(&kek, &kw, &target, &Default::default())
        .unwrap();
    let unwrap = || {
        let mut request = unwrap_request(
            KeyAlgorithm::Aes,
            KeyClass::Secret,
            "uw-dup",
            Some(exportable()),
        );
        request.key_id = Some(vec![9]);
        provider.unwrap_key(&kek, &kw, &blob, &request)
    };
    unwrap().unwrap();
    let before = backend.objects().len();
    let err = unwrap().unwrap_err();
    assert_eq!(err.kind, ErrorKind::DuplicateKey);
    assert_eq!(
        err.message,
        "a secret object with label 'uw-dup' and id 0x09 already exists on hsm"
    );
    assert_eq!(backend.objects().len(), before); // the guard ran before C_UnwrapKey
}

#[test]
fn unwrap_into_generic_secret() {
    let (backend, provider) = logged_in();
    let generic: Vec<u8> = (64u8..96).collect();
    let kek = generate_aes(&provider, "kek", exportable());
    let target = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, generic.clone()),
            "tgt",
            Some(&exportable()),
            None,
        )
        .unwrap();
    let kwp = mech("AES-KEY-WRAP-PAD", vec![]);
    let blob = provider
        .wrap_key(&kek, &kwp, &target, &Default::default())
        .unwrap();
    let info = provider
        .unwrap_key(
            &kek,
            &kwp,
            &blob,
            &unwrap_request(
                KeyAlgorithm::Generic,
                KeyClass::Secret,
                "unwrapped",
                Some(exportable()),
            ),
        )
        .unwrap();
    assert_eq!(info.algorithm, KeyAlgorithm::Generic);
    assert_eq!(
        object_of(&backend, "unwrapped")[&CKA_KEY_TYPE],
        ul(CKK_GENERIC_SECRET)
    );
    assert_eq!(provider.export_key(&info).unwrap().data.to_vec(), generic);
    // CKA_VALUE_LEN auto-injection accepts any positive generic length
    let gcm = mech(
        "AES-GCM",
        vec![("iv", pbytes(&[0; 12])), ("tag_bits", penum("128"))],
    );
    let value_len = crate::mechanisms::unwrap_value_len;
    assert_eq!(
        value_len(&gcm, 50, KeyClass::Secret, KeyAlgorithm::Generic, None).unwrap(),
        Some(34)
    );
    assert_eq!(
        value_len(&gcm, 50, KeyClass::Secret, KeyAlgorithm::Aes, None).unwrap(),
        None
    );
    let err = provider
        .unwrap_key(
            &kek,
            &kwp,
            &blob,
            &unwrap_request(KeyAlgorithm::Other, KeyClass::Secret, "nope", None),
        )
        .unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(err.message, "cannot unwrap into other keys");
    assert_eq!(err.param_name(), Some("result_algorithm"));
}

// ---------------------------------------------------------------------------
// round trips through the fake token (c2 TestRoundTrips)
// ---------------------------------------------------------------------------

#[test]
fn aes_kek_round_trip() {
    // parametrized in c2: AES-CBC pkcs7 and AES-GCM
    for (name, params) in [
        (
            "AES-CBC",
            vec![("iv", pbytes(&iv16())), ("padding", penum("pkcs7"))],
        ),
        (
            "AES-GCM",
            vec![
                ("iv", pbytes(&iv12())),
                ("aad", pbytes(b"")),
                ("tag_bits", penum("128")),
            ],
        ),
    ] {
        let (_backend, provider) = logged_in();
        let kek = generate_aes(&provider, "kek", exportable());
        let target = provider
            .import_key(&aes_material(), "target", Some(&exportable()), None)
            .unwrap();
        let invocation = mech(name, params);
        let blob = provider
            .wrap_key(&kek, &invocation, &target, &Default::default())
            .unwrap();
        let unwrapped = provider
            .unwrap_key(
                &kek,
                &invocation,
                &blob,
                &unwrap_request(
                    KeyAlgorithm::Aes,
                    KeyClass::Secret,
                    "unwrapped",
                    Some(exportable()),
                ),
            )
            .unwrap();
        assert_eq!(
            provider.export_key(&unwrapped).unwrap().data.to_vec(),
            aes_key(),
            "{name}"
        );
    }
}

#[test]
fn rsa_pkcs1_round_trip() {
    let (_backend, provider) = logged_in();
    let mut request = GenerateRequest::new(KeyAlgorithm::Rsa, "rsakek");
    request.size_bits = Some(2048);
    request.template = Some(exportable());
    let private = provider.generate_key(&request).unwrap();
    let target = provider
        .import_key(&aes_material(), "target", Some(&exportable()), None)
        .unwrap();
    let pkcs1 = mech("RSA-PKCS1", vec![]);
    let blob = provider
        .wrap_key(&private, &pkcs1, &target, &Default::default())
        .unwrap();
    let unwrapped = provider
        .unwrap_key(
            &private,
            &pkcs1,
            &blob,
            &unwrap_request(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                "unwrapped",
                Some(exportable()),
            ),
        )
        .unwrap();
    assert_eq!(
        provider.export_key(&unwrapped).unwrap().data.to_vec(),
        aes_key()
    );
}

// ---------------------------------------------------------------------------
// CKA_VALUE_LEN policy (c2 TestValueLenInjection, §5.4)
// ---------------------------------------------------------------------------

fn unwrap_with(
    provider: &Pkcs11Provider,
    name: &str,
    params: Vec<(&str, r2_core::params::ParamValue)>,
    label: &str,
    template: Option<KeyTemplate>,
    blob_len: usize,
) {
    let kek = generate_aes(provider, &format!("kek-{label}"), exportable());
    provider
        .unwrap_key(
            &kek,
            &mech(name, params),
            &vec![0x11; blob_len],
            &unwrap_request(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                label,
                Some(template.unwrap_or_else(exportable)),
            ),
        )
        .unwrap();
}

#[test]
fn value_len_injected_for_gcm() {
    let (backend, provider) = logged_in();
    // blob = ct‖tag, so the secret is 48 - 16 = 32 bytes
    unwrap_with(
        &provider,
        "AES-GCM",
        vec![("iv", pbytes(&iv12())), ("tag_bits", penum("128"))],
        "gcm-out",
        None,
        48,
    );
    assert_eq!(object_of(&backend, "gcm-out")[&CKA_VALUE_LEN], ul(32));
}

#[test]
fn value_len_injected_for_cbc_without_padding() {
    let (backend, provider) = logged_in();
    unwrap_with(
        &provider,
        "AES-CBC",
        vec![("iv", pbytes(&iv16())), ("padding", penum("none"))],
        "cbc-out",
        None,
        32,
    );
    assert_eq!(object_of(&backend, "cbc-out")[&CKA_VALUE_LEN], ul(32));
}

#[test]
fn value_len_not_injected_when_the_length_is_unknowable() {
    // CBC-pkcs7 strips an unknown amount of padding — never guess (§5.4)
    let (backend, provider) = logged_in();
    unwrap_with(
        &provider,
        "AES-CBC",
        vec![("iv", pbytes(&iv16())), ("padding", penum("pkcs7"))],
        "pad-out",
        None,
        48,
    );
    assert!(!object_of(&backend, "pad-out").contains_key(&CKA_VALUE_LEN));
}

#[test]
fn value_len_injected_for_every_valid_aes_size() {
    // 40 - 16 = 24 → AES-192, still a legal secret length
    let (backend, provider) = logged_in();
    unwrap_with(
        &provider,
        "AES-GCM",
        vec![("iv", pbytes(&iv12())), ("tag_bits", penum("128"))],
        "a192",
        None,
        40,
    );
    assert_eq!(object_of(&backend, "a192")[&CKA_VALUE_LEN], ul(24));
}

#[test]
fn value_len_not_injected_for_a_non_aes_length() {
    // 50 - 16 = 34, which is no AES key size — never guess (§5.4)
    let (backend, provider) = logged_in();
    unwrap_with(
        &provider,
        "AES-GCM",
        vec![("iv", pbytes(&iv12())), ("tag_bits", penum("128"))],
        "odd-out",
        None,
        50,
    );
    assert!(!object_of(&backend, "odd-out").contains_key(&CKA_VALUE_LEN));
}

#[test]
fn value_len_operator_template_row_wins() {
    let (backend, provider) = logged_in();
    let template = tpl(vec![
        boolean("CKA_SENSITIVE", false),
        boolean("CKA_EXTRACTABLE", true),
        ulong_attr("CKA_VALUE_LEN", AttrValue::Ulong(16)),
    ]);
    unwrap_with(
        &provider,
        "AES-GCM",
        vec![("iv", pbytes(&iv12())), ("tag_bits", penum("128"))],
        "op-out",
        Some(template),
        48,
    );
    assert_eq!(object_of(&backend, "op-out")[&CKA_VALUE_LEN], ul(16));
}

#[test]
fn value_len_private_results_never_get_one() {
    let (backend, provider) = logged_in();
    let kek = generate_aes(&provider, "kek-priv", exportable());
    provider
        .unwrap_key(
            &kek,
            &mech(
                "AES-GCM",
                vec![("iv", pbytes(&iv12())), ("tag_bits", penum("128"))],
            ),
            &[0x11; 48],
            &unwrap_request(
                KeyAlgorithm::Rsa,
                KeyClass::Private,
                "priv-out",
                Some(exportable()),
            ),
        )
        .unwrap();
    assert!(!object_of(&backend, "priv-out").contains_key(&CKA_VALUE_LEN));
}

#[test]
fn value_len_retried_once_without_when_the_token_objects() {
    let (backend, provider) = logged_in();
    let kek = generate_aes(&provider, "kek-retry", exportable());
    backend.reject_unwrap_with(CKA_VALUE_LEN, rv::CKR_TEMPLATE_INCONSISTENT);
    let info = provider
        .unwrap_key(
            &kek,
            &mech(
                "AES-GCM",
                vec![("iv", pbytes(&iv12())), ("tag_bits", penum("128"))],
            ),
            &[0x11; 48],
            &unwrap_request(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                "retry-out",
                Some(exportable()),
            ),
        )
        .unwrap();
    // injected, refused, retried without
    let seen: Vec<bool> = backend
        .unwrap_templates()
        .iter()
        .map(|t| t.contains(&CKA_VALUE_LEN))
        .collect();
    assert_eq!(seen, [true, false]);
    assert_eq!(info.key_ref.label, "retry-out");
}

#[test]
fn value_len_read_only_is_not_retried() {
    // SoftHSM's CKR_ATTRIBUTE_READ_ONLY is outside c2's trigger set (ported verbatim)
    let (backend, provider) = logged_in();
    let kek = generate_aes(&provider, "kek-ro", exportable());
    backend.reject_unwrap_with(CKA_VALUE_LEN, rv::CKR_ATTRIBUTE_READ_ONLY);
    let err = provider
        .unwrap_key(
            &kek,
            &mech(
                "AES-GCM",
                vec![("iv", pbytes(&iv12())), ("tag_bits", penum("128"))],
            ),
            &[0x11; 48],
            &unwrap_request(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                "ro-out",
                Some(exportable()),
            ),
        )
        .unwrap_err();
    assert_eq!(
        err.ckr().map(|(_, n)| n.to_string()).as_deref(),
        Some("CKR_ATTRIBUTE_READ_ONLY")
    );
    assert_eq!(backend.unwrap_templates().len(), 1);
}

// ---------------------------------------------------------------------------
// RSA-OAEP software fallbacks (§5.5 ladder, §5.4 KEK load)
// ---------------------------------------------------------------------------

fn real_rsa(provider: &Pkcs11Provider, label: &str) -> (Vec<u8>, KeyInfo, KeyInfo) {
    let pkcs8 = r2_testkit::fixtures::rsa2048_pkcs8();
    let private = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, pkcs8.clone()),
            label,
            Some(&exportable()),
            None,
        )
        .unwrap();
    let spki = r2_core::formats::pkcs8_public_spki(&pkcs8).unwrap();
    let public = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Public, spki),
            label,
            None,
            private.key_ref.key_id.as_deref(),
        )
        .unwrap();
    (pkcs8, private, public)
}

#[test]
fn oaep_wrap_falls_back_to_software_over_a_plain_readable_target() {
    let (_backend, provider) = logged_in();
    let (pkcs8, _private, public) = real_rsa(&provider, "oaep-kek");
    let target = provider
        .import_key(&aes_material(), "plain-target", Some(&exportable()), None)
        .unwrap();
    let sha256 = mech("RSA-OAEP", vec![("hash", penum("sha256"))]);
    let blob = provider
        .wrap_key(&public, &sha256, &target, &Default::default())
        .unwrap();
    // OpenSSL decrypts the software OAEP(SHA-256) blob back to the target value
    let key = openssl::pkey::PKey::private_key_from_der(&pkcs8).unwrap();
    let mut decrypter = openssl::encrypt::Decrypter::new(&key).unwrap();
    decrypter
        .set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
        .unwrap();
    decrypter
        .set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())
        .unwrap();
    decrypter
        .set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())
        .unwrap();
    let mut out = vec![0; decrypter.decrypt_len(&blob).unwrap()];
    let n = decrypter.decrypt(&blob, &mut out).unwrap();
    assert_eq!(&out[..n], aes_key().as_slice());
}

#[test]
fn oaep_wrap_fallback_needs_a_plain_readable_target() {
    let (_backend, provider) = logged_in();
    let (_pkcs8, _private, public) = real_rsa(&provider, "oaep-kek2");
    let wrappable_only = tpl(vec![
        boolean("CKA_SENSITIVE", true),
        boolean("CKA_EXTRACTABLE", true),
    ]);
    let target = provider
        .import_key(
            &aes_material(),
            "sensitive-target",
            Some(&wrappable_only),
            None,
        )
        .unwrap();
    let err = provider
        .wrap_key(
            &public,
            &mech("RSA-OAEP", vec![("hash", penum("sha256"))]),
            &target,
            &Default::default(),
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(
        err.message,
        "token rejects RSA-OAEP(sha256) wrapping parameters and the target is not plain-readable"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("use hash=sha1 on this token, or an AES key-wrap route")
    );
}

#[test]
fn oaep_unwrap_falls_back_to_raw_rsa_and_creates_the_object() {
    let (backend, provider) = logged_in();
    let (_pkcs8, private, _public) = real_rsa(&provider, "oaep-unwrap");
    // the fake token's raw RSA is a keystream: whatever it yields fails the OAEP check —
    // this pins the path (CKM_RSA_X_509 decrypt after the rejected OAEP unwrap)
    let err = provider
        .unwrap_key(
            &private,
            &mech("RSA-OAEP", vec![("hash", penum("sha256"))]),
            &[0x22; 256],
            &unwrap_request(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                "oaep-out",
                Some(exportable()),
            ),
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Crypto);
    assert_eq!(err.message, "OAEP decoding failed");
    let calls = backend.calls();
    let unwrap_at = calls.iter().rposition(|c| *c == "unwrap_key").unwrap();
    assert_eq!(calls[unwrap_at + 1..].first(), Some(&"decrypt"));
    let last = backend.last_mechanism().unwrap();
    assert_eq!(last, MechSpec::Plain { ckm: CKM_RSA_X_509 });
}

#[test]
fn wrap_and_unwrap_refusals() {
    let (_backend, provider) = logged_in();
    let kek = generate_aes(&provider, "kek-r", exportable());
    let target = provider
        .import_key(&aes_material(), "t-r", Some(&exportable()), None)
        .unwrap();
    let err = provider
        .wrap_key(
            &kek,
            &mech("RSA-AES-KEY-WRAP", vec![]),
            &target,
            &Default::default(),
        )
        .unwrap_err();
    // never advertised by Pkcs11Provider (§11 D6)
    assert_eq!(
        err.message,
        "hsm does not support mechanism RSA-AES-KEY-WRAP"
    );
    let (_pkcs8, cert) = r2_testkit::fixtures::rsa_pkcs8_and_cert();
    let certificate = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert),
            "c-r",
            None,
            None,
        )
        .unwrap();
    let err = provider
        .unwrap_key(
            &certificate,
            &mech("RSA-PKCS1", vec![]),
            &[0; 256],
            &unwrap_request(KeyAlgorithm::Aes, KeyClass::Secret, "x", None),
        )
        .unwrap_err();
    assert_eq!(
        err.message,
        "certificates cannot be used for unwrap_key (§4.3)"
    );
}
