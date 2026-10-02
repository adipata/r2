//! Pkcs11Provider verbs against a real SoftHSM2 token: c2
//! tests/integration/test_pkcs11_provider.py TestCrypto / TestKeyEdit, the provider-level
//! cases of tests/integration/test_objects_softhsm.py (HMAC, generic secrets), and the R5b
//! acceptance checks (PSS/EdDSA/CMAC/derive/OAEP fallbacks/full template dump, CBC/GCM
//! wraps tolerated where the token lacks CKF_WRAP, Montgomery translations, §11 D6).
//! Feature `softhsm`; fails (never skips) without the fixture from
//! `scripts/softhsm-init.sh`. Session objects (CKA_TOKEN=false) under unique labels; each
//! test holds `global_state_lock` so the `cargo test` fallback never finalizes a module
//! under another test. Cross-checks use OpenSSL where c2 used pyca (r2-pkcs11 may not
//! dev-depend on r2-memory, §4.1.2).
#![cfg(feature = "softhsm")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::BTreeMap;

use indexmap::IndexMap;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};
use openssl::symm::{Cipher, encrypt_aead};
use r2_config::model::Pkcs11InstanceConfig;
use r2_core::error::ErrorKind;
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::{ParamValue, Params};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_pkcs11::Pkcs11Provider;
use r2_provider::{
    GenerateRequest, KeySelector, MechanismInvocation, Provider, UnwrapRequest, WrapOptions,
};
use r2_testkit::softhsm::{softhsm_token, unique_label};
use secrecy::SecretString;

const MESSAGE: &[u8] = b"what do ya want for nothing?";

fn boolean(name: &str, value: bool) -> TemplateAttr {
    TemplateAttr::new(name, AttrKind::Bool, AttrValue::Bool(value))
}

/// Session-object template: exportable, plus the given usage bools (c2 `_session_template`).
fn session_template(extra_true: &[&str]) -> KeyTemplate {
    let mut attrs = vec![
        boolean("CKA_TOKEN", false),
        boolean("CKA_SENSITIVE", false),
        boolean("CKA_EXTRACTABLE", true),
    ];
    attrs.extend(extra_true.iter().map(|name| boolean(name, true)));
    KeyTemplate::new(attrs)
}

fn session_only() -> KeyTemplate {
    KeyTemplate::new(vec![boolean("CKA_TOKEN", false)])
}

fn logged_in() -> Pkcs11Provider {
    let token = softhsm_token();
    let mut config = Pkcs11InstanceConfig::new("softhsm", token.module_path.clone());
    config.slot = Some(token.slot);
    config.token_label = Some(token.token_label.clone());
    let provider = Pkcs11Provider::new("softhsm", config, BTreeMap::new(), IndexMap::new());
    let info = provider
        .list_tokens()
        .unwrap()
        .into_iter()
        .find(|t| t.label == token.token_label)
        .unwrap();
    provider
        .login(&info, &SecretString::from(token.user_pin.clone()), false)
        .unwrap();
    provider
}

fn mech(name: &str, params: Vec<(&str, ParamValue)>) -> MechanismInvocation {
    let mut map = Params::new();
    for (key, value) in params {
        map.insert(key.to_string(), value);
    }
    MechanismInvocation::new(name, map)
}

fn b(value: &[u8]) -> ParamValue {
    ParamValue::Bytes(value.to_vec())
}

fn e(value: &str) -> ParamValue {
    ParamValue::Enum(value.to_string())
}

fn i(value: i64) -> ParamValue {
    ParamValue::Int(value)
}

fn generate(
    provider: &Pkcs11Provider,
    algorithm: KeyAlgorithm,
    size_bits: Option<u32>,
    curve: Option<Curve>,
    label: &str,
    template: KeyTemplate,
) -> KeyInfo {
    let mut request = GenerateRequest::new(algorithm, label);
    request.size_bits = size_bits;
    request.curve = curve;
    request.template = Some(template);
    request.public_template = Some(session_only());
    provider.generate_key(&request).unwrap()
}

fn public_of(provider: &Pkcs11Provider, label: &str) -> KeyInfo {
    provider
        .list_keys()
        .unwrap()
        .into_iter()
        .find(|k| k.key_ref.label == label && k.key_class == KeyClass::Public)
        .unwrap()
}

fn public_pkey(provider: &Pkcs11Provider, public: &KeyInfo) -> PKey<openssl::pkey::Public> {
    PKey::public_key_from_der(&provider.export_key(public).unwrap().data).unwrap()
}

fn hmac(key: &[u8], hash: MessageDigest, data: &[u8]) -> Vec<u8> {
    let pkey = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(hash, &pkey).unwrap();
    signer.update(data).unwrap();
    signer.sign_to_vec().unwrap()
}

fn digest_of(name: &str) -> MessageDigest {
    match name {
        "sha1" => MessageDigest::sha1(),
        "sha224" => MessageDigest::sha224(),
        "sha384" => MessageDigest::sha384(),
        "sha512" => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    }
}

// ---------------------------------------------------------------------------
// c2 TestCrypto
// ---------------------------------------------------------------------------

#[test]
fn softhsm_cbc_round_trip_and_padding_modes() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let info = generate(
        &provider,
        KeyAlgorithm::Aes,
        Some(256),
        None,
        &label,
        session_template(&[]),
    );
    let iv: Vec<u8> = (0u8..16).collect();
    let pkcs7 = mech("AES-CBC", vec![("iv", b(&iv)), ("padding", e("pkcs7"))]);
    let plaintext = b"cbc round trip payload"; // not block-aligned
    let ciphertext = provider.encrypt(&info, &pkcs7, plaintext).unwrap();
    assert_eq!(ciphertext.len(), 32); // padded to the next block
    assert_eq!(
        provider
            .decrypt(&info, &pkcs7, &ciphertext)
            .unwrap()
            .as_slice(),
        plaintext
    );
    let none = mech("AES-CBC", vec![("iv", b(&iv)), ("padding", e("none"))]);
    let aligned = [0u8; 32];
    let ciphertext = provider.encrypt(&info, &none, &aligned).unwrap();
    assert_eq!(ciphertext.len(), 32);
    assert_eq!(
        provider
            .decrypt(&info, &none, &ciphertext)
            .unwrap()
            .as_slice(),
        aligned
    );
    // CBC_PAD == OpenSSL CBC + PKCS#7 (KAT cross-check, §5.8)
    let key = provider.export_key(&info).unwrap().data;
    let expected =
        openssl::symm::encrypt(Cipher::aes_256_cbc(), &key, Some(&iv), plaintext).unwrap();
    assert_eq!(
        provider.encrypt(&info, &pkcs7, plaintext).unwrap(),
        expected
    );
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_gcm_round_trip_matches_openssl() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let info = generate(
        &provider,
        KeyAlgorithm::Aes,
        Some(256),
        None,
        &label,
        session_template(&[]),
    );
    let key = provider.export_key(&info).unwrap().data;
    let (iv, aad) = ([0u8; 12], b"header");
    let gcm = mech(
        "AES-GCM",
        vec![("iv", b(&iv)), ("aad", b(aad)), ("tag_bits", e("128"))],
    );
    let plaintext = b"gcm payload";
    let ciphertext = provider.encrypt(&info, &gcm, plaintext).unwrap(); // ct‖tag (§5.8)
    let mut tag = [0u8; 16];
    let mut expected = encrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&iv),
        aad,
        plaintext,
        &mut tag,
    )
    .unwrap();
    expected.extend_from_slice(&tag);
    assert_eq!(ciphertext, expected);
    assert_eq!(
        provider
            .decrypt(&info, &gcm, &ciphertext)
            .unwrap()
            .as_slice(),
        plaintext
    );
    // a tampered tag is a token error (CKR_GENERAL_ERROR 2.6.1 / ENCRYPTED_DATA_INVALID 2.7.0)
    let mut tampered = ciphertext.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let err = provider.decrypt(&info, &gcm, &tampered).unwrap_err();
    assert!(err.kind.is_provider(), "{err:?}");
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_gmac_construction_matches_openssl() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let info = generate(
        &provider,
        KeyAlgorithm::Aes,
        Some(256),
        None,
        &label,
        session_template(&[]),
    );
    let key = provider.export_key(&info).unwrap().data;
    let iv: Vec<u8> = (0u8..12).collect();
    let message = b"authenticate me";
    let gmac = mech("AES-GMAC", vec![("iv", b(&iv)), ("mac_len", i(16))]);
    let tag = provider.sign(&info, &gmac, message).unwrap();
    // GMAC == GCM tag over AAD-only, byte-identical by definition (§5.9)
    let mut expected = [0u8; 16];
    encrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&iv),
        message,
        b"",
        &mut expected,
    )
    .unwrap();
    assert_eq!(tag, expected);
    assert!(provider.verify(&info, &gmac, message, &tag).unwrap());
    assert!(
        !provider
            .verify(&info, &gmac, b"authenticate me!", &tag)
            .unwrap()
    );
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_pkcs1_sign_verify_and_openssl_crosscheck() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let private = generate(
        &provider,
        KeyAlgorithm::Rsa,
        Some(2048),
        None,
        &label,
        session_template(&["CKA_SIGN"]),
    );
    let public = public_of(&provider, &label);
    let data = b"sign me with pkcs1";
    for hash in ["sha256", "sha224", "sha512"] {
        // sha224 only through the unfiltered list / DigestInfo path (§5.9)
        let pkcs1 = mech("RSA-PKCS1", vec![("hash", e(hash))]);
        let signature = provider.sign(&private, &pkcs1, data).unwrap();
        assert!(provider.verify(&public, &pkcs1, data, &signature).unwrap());
        assert!(
            !provider
                .verify(&public, &pkcs1, b"sign me!", &signature)
                .unwrap()
        );
        let pkey = public_pkey(&provider, &public);
        let mut verifier = Verifier::new(digest_of(hash), &pkey).unwrap();
        verifier.update(data).unwrap();
        assert!(verifier.verify(&signature).unwrap(), "{hash}");
    }
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_ecdsa_sign_verify_and_openssl_crosscheck() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let private = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        &label,
        session_template(&["CKA_SIGN"]),
    );
    let public = public_of(&provider, &label);
    let ecdsa = mech("ECDSA", vec![("hash", e("sha256"))]);
    let data = b"sign me with ecdsa";
    let signature = provider.sign(&private, &ecdsa, data).unwrap();
    assert_eq!(signature.len(), 64); // fixed-width r‖s (§4.5.4)
    assert!(provider.verify(&public, &ecdsa, data, &signature).unwrap());
    assert!(
        !provider
            .verify(&public, &ecdsa, b"sign me!", &signature)
            .unwrap()
    );
    let der = r2_core::der::ecdsa_rs_to_der(&signature).unwrap();
    let pkey = public_pkey(&provider, &public);
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
    verifier.update(data).unwrap();
    assert!(verifier.verify(&der).unwrap());
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_wrap_unwrap_round_trip() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let kek_label = unique_label();
    let kek = generate(
        &provider,
        KeyAlgorithm::Aes,
        Some(256),
        None,
        &kek_label,
        session_template(&["CKA_WRAP", "CKA_UNWRAP"]),
    );
    let target_label = unique_label();
    let target = generate(
        &provider,
        KeyAlgorithm::Aes,
        Some(256),
        None,
        &target_label,
        session_template(&[]),
    );
    let target_value = provider.export_key(&target).unwrap().data;
    for name in ["AES-KEY-WRAP-PAD", "AES-KEY-WRAP"] {
        let wrap = mech(name, vec![]);
        let blob = provider
            .wrap_key(&kek, &wrap, &target, &WrapOptions::default())
            .unwrap();
        assert!(!blob.is_empty());
        assert_ne!(blob.as_slice(), target_value.as_slice());
        // the AES-256 KW/KWP blob of an 8-aligned 32-byte value is 40 bytes on both versions
        assert_eq!(blob.len(), 40, "{name}");
        let out_label = unique_label();
        let mut request =
            UnwrapRequest::new(KeyAlgorithm::Aes, KeyClass::Secret, out_label.as_str());
        request.template = Some(session_template(&[]));
        let unwrapped = provider.unwrap_key(&kek, &wrap, &blob, &request).unwrap();
        assert_eq!(provider.export_key(&unwrapped).unwrap().data, target_value);
    }
    provider.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// c2 TestKeyEdit
// ---------------------------------------------------------------------------

#[test]
fn softhsm_edit_mixes_applied_and_refused_attributes() {
    // §5.15 on a real token: label rename + usage toggle apply while the one-direction
    // CKA_SENSITIVE true→false change is refused per attribute
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let info = generate(
        &provider,
        KeyAlgorithm::Aes,
        Some(256),
        None,
        &label,
        KeyTemplate::new(vec![
            boolean("CKA_TOKEN", false),
            boolean("CKA_SENSITIVE", true),
            boolean("CKA_EXTRACTABLE", false),
            boolean("CKA_ENCRYPT", true),
            boolean("CKA_DECRYPT", false),
        ]),
    );
    let new_label = unique_label();
    let result = provider
        .update_key(
            &info,
            &KeyTemplate::new(vec![
                boolean("CKA_DECRYPT", true),
                boolean("CKA_SENSITIVE", false), // one-direction: must be refused
                TemplateAttr::new(
                    "CKA_LABEL",
                    AttrKind::Str,
                    AttrValue::Str(new_label.to_string()),
                ),
            ]),
        )
        .unwrap();
    let by_name: BTreeMap<&str, &r2_provider::AttrEditOutcome> = result
        .outcomes
        .iter()
        .map(|o| (o.name.as_str(), o))
        .collect();
    assert!(by_name["CKA_DECRYPT"].applied);
    assert!(by_name["CKA_LABEL"].applied);
    assert!(!by_name["CKA_SENSITIVE"].applied);
    let detail = by_name["CKA_SENSITIVE"].detail.as_deref().unwrap();
    assert!(detail.contains("CKR_"), "{detail}");
    assert_eq!(result.key.key_ref.label, new_label.as_str());
    let renamed = provider
        .find_key(&KeySelector::label(new_label.as_str()).with_id(info.key_ref.key_id.clone()))
        .unwrap();
    assert_eq!(
        renamed.attributes.get("CKA_SENSITIVE"),
        Some(&AttrValue::Bool(true)) // unchanged on token
    );
    let template = provider.read_key_template(&renamed).unwrap();
    assert_eq!(
        template.get("CKA_DECRYPT").unwrap().value,
        AttrValue::Bool(true)
    );
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_read_key_template_snapshots_the_object() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let info = generate(
        &provider,
        KeyAlgorithm::Aes,
        Some(256),
        None,
        &label,
        session_template(&["CKA_ENCRYPT"]),
    );
    let template = provider.read_key_template(&info).unwrap();
    let class = template.get("CKA_CLASS").unwrap();
    assert!(class.locked);
    assert_eq!(
        template.get("CKA_LABEL").unwrap().value,
        AttrValue::Str(label.to_string())
    );
    assert_eq!(
        template.get("CKA_ENCRYPT").unwrap().value,
        AttrValue::Bool(true)
    );
    assert_eq!(
        template.get("CKA_SENSITIVE").unwrap().value,
        AttrValue::Bool(false)
    );
    // SoftHSM returns CKA_MODIFIABLE (the fake token did not)
    assert!(template.get("CKA_MODIFIABLE").is_some());
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_keypair_half_rename_leaves_sibling() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let mut request = GenerateRequest::new(KeyAlgorithm::Rsa, label.as_str());
    request.size_bits = Some(2048);
    request.template = Some(session_template(&["CKA_SIGN"]));
    request.public_template = Some(KeyTemplate::new(vec![
        boolean("CKA_TOKEN", false),
        boolean("CKA_VERIFY", true),
    ]));
    let private = provider.generate_key(&request).unwrap();
    let new_label = unique_label();
    let result = provider
        .update_key(
            &private,
            &KeyTemplate::new(vec![TemplateAttr::new(
                "CKA_LABEL",
                AttrKind::Str,
                AttrValue::Str(new_label.to_string()),
            )]),
        )
        .unwrap();
    assert_eq!(result.key.key_ref.label, new_label.as_str());
    let id = private.key_ref.key_id.clone();
    assert_eq!(
        provider
            .find_key(&KeySelector::label(new_label.as_str()).with_id(id.clone()))
            .unwrap()
            .key_class,
        KeyClass::Private
    );
    // §5.15: the sibling is untouched
    let public = provider
        .find_key(&KeySelector::label(label.as_str()).with_id(id))
        .unwrap();
    assert_eq!(public.key_class, KeyClass::Public);
    provider.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// c2 test_objects_softhsm.py (provider level)
// ---------------------------------------------------------------------------

fn generic_material(key: &[u8]) -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, key.to_vec())
}

fn hmac_mech(hash: &str, extra: Vec<(&str, ParamValue)>) -> MechanismInvocation {
    let mut params = vec![("hash", e(hash))];
    params.extend(extra);
    mech("HMAC", params)
}

#[test]
fn softhsm_hmac_matches_openssl_and_crosses_providers() {
    // c2 crossed into MemoryProvider; r2-pkcs11 cannot dev-depend on r2-memory (§4.1.2), so
    // the software side is OpenSSL's HMAC — the computation MemoryProvider performs (§5.9)
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let generic_key: Vec<u8> = (0u8..64).collect(); // ≥ every digest length (SoftHSM rule)
    assert!(provider.mechanisms().contains("HMAC"));
    let label = unique_label();
    let on_token = provider
        .import_key(
            &generic_material(&generic_key),
            &format!("{}-hmac", label.as_str()),
            Some(&session_template(&["CKA_SIGN", "CKA_VERIFY"])),
            None,
        )
        .unwrap();
    assert_eq!(on_token.algorithm, KeyAlgorithm::Generic);
    assert_eq!(on_token.size_bits, Some(64 * 8));
    for hash in ["sha1", "sha224", "sha256", "sha384", "sha512"] {
        let expected = hmac(&generic_key, digest_of(hash), MESSAGE);
        let token_mac = provider
            .sign(&on_token, &hmac_mech(hash, vec![]), MESSAGE)
            .unwrap();
        assert_eq!(token_mac, expected, "{hash}");
        assert_eq!(token_mac.len(), digest_of(hash).size());
        assert!(
            provider
                .verify(&on_token, &hmac_mech(hash, vec![]), MESSAGE, &expected)
                .unwrap()
        );
        assert!(
            !provider
                .verify(
                    &on_token,
                    &hmac_mech(hash, vec![]),
                    b"what do ya want!",
                    &expected
                )
                .unwrap()
        );
    }
    let short = provider
        .sign(
            &on_token,
            &hmac_mech("sha256", vec![("mac_len", i(12))]),
            MESSAGE,
        )
        .unwrap();
    assert_eq!(
        short,
        hmac(&generic_key, MessageDigest::sha256(), MESSAGE)[..12]
    );
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_generate_generic_on_token_and_export() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let info = generate(
        &provider,
        KeyAlgorithm::Generic,
        Some(384),
        None,
        &format!("{}-gen", label.as_str()),
        session_template(&["CKA_SIGN"]),
    );
    assert_eq!(
        (info.algorithm, info.size_bits, info.exportable),
        (KeyAlgorithm::Generic, Some(384), true)
    );
    let raw = provider.export_key(&info).unwrap().data;
    assert_eq!(raw.len(), 48);
    let mac = provider
        .sign(&info, &hmac_mech("sha384", vec![]), MESSAGE)
        .unwrap();
    assert_eq!(mac, hmac(&raw, MessageDigest::sha384(), MESSAGE));
    let listed: Vec<KeyInfo> = provider
        .list_keys()
        .unwrap()
        .into_iter()
        .filter(|k| k.key_ref == info.key_ref)
        .collect();
    assert_eq!(listed[0].algorithm, KeyAlgorithm::Generic);
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_short_key_sha512_is_a_key_size_range_error() {
    // xfail(strict=False) in c2 ("other builds may not"); SoftHSM 2.6.1 and 2.7.0 enforce
    // HMAC key length ≥ digest length (S0), so r2 asserts it outright
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let short = provider
        .import_key(
            &generic_material(&(0u8..16).collect::<Vec<u8>>()),
            &format!("{}-short", label.as_str()),
            Some(&session_template(&["CKA_SIGN"])),
            None,
        )
        .unwrap();
    let err = provider
        .sign(&short, &hmac_mech("sha512", vec![]), MESSAGE)
        .unwrap_err();
    assert_eq!(
        err.ckr().map(|(_, n)| n.to_string()).as_deref(),
        Some("CKR_KEY_SIZE_RANGE")
    );
    assert!(err.hint.as_deref().unwrap_or("").contains("digest length"));
    provider.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// R5b acceptance: the remaining verbs and fallbacks on a real token
// ---------------------------------------------------------------------------

#[test]
fn softhsm_pss_sign_verify_and_salt_max() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let private = generate(
        &provider,
        KeyAlgorithm::Rsa,
        Some(2048),
        None,
        &label,
        session_template(&["CKA_SIGN"]),
    );
    let public = public_of(&provider, &label);
    let pkey = public_pkey(&provider, &public);
    for (hash, salt) in [("sha256", None), ("sha384", Some(-1)), ("sha224", Some(0))] {
        let mut params = vec![("hash", e(hash))];
        if let Some(salt) = salt {
            params.push(("salt_len", i(salt)));
        }
        let pss = mech("RSA-PSS", params);
        let signature = provider.sign(&private, &pss, MESSAGE).unwrap();
        assert!(provider.verify(&public, &pss, MESSAGE, &signature).unwrap());
        assert!(
            !provider
                .verify(&public, &pss, b"other", &signature)
                .unwrap()
        );
        let mut verifier = Verifier::new(digest_of(hash), &pkey).unwrap();
        verifier
            .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
            .unwrap();
        verifier.set_rsa_mgf1_md(digest_of(hash)).unwrap();
        let salt_len = match salt {
            None => digest_of(hash).size() as i32,
            Some(-1) => 256 - digest_of(hash).size() as i32 - 2,
            Some(n) => n as i32,
        };
        verifier
            .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::custom(salt_len))
            .unwrap();
        verifier.update(MESSAGE).unwrap();
        assert!(verifier.verify(&signature).unwrap(), "{hash}");
    }
    // SoftHSM: mgf ≠ hash → CKR_ARGUMENTS_BAD (§5.9 note)
    let err = provider
        .sign(
            &private,
            &mech(
                "RSA-PSS",
                vec![("hash", e("sha256")), ("mgf_hash", e("sha1"))],
            ),
            MESSAGE,
        )
        .unwrap_err();
    assert_eq!(
        err.ckr().map(|(_, n)| n.to_string()).as_deref(),
        Some("CKR_ARGUMENTS_BAD")
    );
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_eddsa_sign_verify_matches_openssl() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let eddsa = mech("EDDSA", vec![]);
    for curve in [Curve::Ed25519, Curve::Ed448] {
        // generated pairs: SoftHSM writes CKA_EC_PARAMS as a curve-name PrintableString,
        // which c2 (and r2) read as curve None — sign/verify still round-trip
        let label = unique_label();
        let private = generate(
            &provider,
            KeyAlgorithm::EcEdwards,
            None,
            Some(curve.clone()),
            &label,
            session_template(&["CKA_SIGN"]),
        );
        let public = public_of(&provider, &label);
        let signature = provider.sign(&private, &eddsa, MESSAGE).unwrap();
        assert_eq!(
            signature.len(),
            if curve == Curve::Ed25519 { 64 } else { 114 }
        );
        assert!(
            provider
                .verify(&public, &eddsa, MESSAGE, &signature)
                .unwrap()
        );
        assert!(
            !provider
                .verify(&public, &eddsa, b"other", &signature)
                .unwrap()
        );
    }
    // imported keys: deterministic EdDSA equals OpenSSL's signature (RFC 8032)
    for key in [
        PKey::generate_ed25519().unwrap(),
        PKey::generate_ed448().unwrap(),
    ] {
        let label = unique_label();
        let private = provider
            .import_key(
                &KeyMaterial::new(
                    KeyAlgorithm::EcEdwards,
                    KeyClass::Private,
                    key.private_key_to_pkcs8().unwrap(),
                ),
                label.as_str(),
                Some(&session_template(&["CKA_SIGN"])),
                None,
            )
            .unwrap();
        let public = provider
            .import_key(
                &KeyMaterial::new(
                    KeyAlgorithm::EcEdwards,
                    KeyClass::Public,
                    key.public_key_to_der().unwrap(),
                ),
                label.as_str(),
                Some(&session_only()),
                private.key_ref.key_id.as_deref(),
            )
            .unwrap();
        let signature = provider.sign(&private, &eddsa, MESSAGE).unwrap();
        let mut signer = Signer::new_without_digest(&key).unwrap();
        assert_eq!(signer.sign_oneshot_to_vec(MESSAGE).unwrap(), signature);
        assert!(
            provider
                .verify(&public, &eddsa, MESSAGE, &signature)
                .unwrap()
        );
    }
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_cmac_and_ctr_and_ecb_match_openssl() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let key: Vec<u8> = (0u8..16).collect();
    let info = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, key.clone()),
            label.as_str(),
            Some(&session_template(&[
                "CKA_SIGN",
                "CKA_ENCRYPT",
                "CKA_DECRYPT",
            ])),
            None,
        )
        .unwrap();
    let cmac_key = PKey::cmac(&Cipher::aes_128_cbc(), &key).unwrap();
    let mut signer = Signer::new_without_digest(&cmac_key).unwrap();
    signer.update(MESSAGE).unwrap();
    let full = signer.sign_to_vec().unwrap();
    let tag = provider
        .sign(&info, &mech("AES-CMAC", vec![("mac_len", i(10))]), MESSAGE)
        .unwrap();
    assert_eq!(tag, full[..10]); // full-width on token, truncated locally
    let block = [0xf0u8; 16];
    let ctr = mech("AES-CTR", vec![("counter_block", b(&block))]);
    let ct = provider.encrypt(&info, &ctr, MESSAGE).unwrap();
    let expected =
        openssl::symm::encrypt(Cipher::aes_128_ctr(), &key, Some(&block), MESSAGE).unwrap();
    assert_eq!(ct, expected);
    assert_eq!(
        provider.decrypt(&info, &ctr, &ct).unwrap().as_slice(),
        MESSAGE
    );
    let ecb = mech("AES-ECB", vec![("padding", e("pkcs7"))]);
    let ct = provider.encrypt(&info, &ecb, MESSAGE).unwrap();
    let expected = openssl::symm::encrypt(Cipher::aes_128_ecb(), &key, None, MESSAGE).unwrap();
    assert_eq!(ct, expected); // provider-side PKCS#7 == OpenSSL's
    assert_eq!(
        provider.decrypt(&info, &ecb, &ct).unwrap().as_slice(),
        MESSAGE
    );
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_oaep_fallbacks_and_raw_rsa() {
    // SoftHSM accepts only SHA-1/MGF1-SHA1 OAEP with an empty label: SHA-256 encrypts in
    // software and decrypts through raw RSA on the token + software OAEP decoding (§5.8)
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let private = generate(
        &provider,
        KeyAlgorithm::Rsa,
        Some(2048),
        None,
        &label,
        session_template(&["CKA_DECRYPT", "CKA_SIGN"]),
    );
    let public = public_of(&provider, &label);
    for params in [
        vec![("hash", e("sha256")), ("label", b(b"ctx"))],
        vec![("hash", e("sha1"))],
        vec![("hash", e("sha512")), ("mgf_hash", e("sha1"))],
    ] {
        let oaep = mech("RSA-OAEP", params);
        let ct = provider.encrypt(&public, &oaep, MESSAGE).unwrap();
        assert_eq!(ct.len(), 256);
        assert_eq!(
            provider.decrypt(&private, &oaep, &ct).unwrap().as_slice(),
            MESSAGE
        );
    }
    // RSA-RAW: public-exponent recovery in software inverts a raw private signature
    let raw = mech("RSA-RAW", vec![]);
    let signature = provider.sign(&private, &raw, &[0x42; 8]).unwrap();
    assert_eq!(signature.len(), 256);
    let recovered = provider.decrypt(&public, &raw, &signature).unwrap();
    let mut expected = vec![0u8; 248];
    expected.extend([0x42; 8]);
    assert_eq!(recovered.as_slice(), expected.as_slice());
    assert!(
        provider
            .verify(&public, &raw, &[0x42; 8], &signature)
            .unwrap()
    );
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_rsa_wraps_hard_and_cbc_gcm_tolerated() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let target_label = unique_label();
    let target = generate(
        &provider,
        KeyAlgorithm::Aes,
        Some(256),
        None,
        &target_label,
        session_template(&[]),
    );
    let target_value = provider.export_key(&target).unwrap().data;
    // RSA: PKCS#1 and OAEP-SHA1 on the token, OAEP-SHA256 through the software fallbacks
    let rsa_label = unique_label();
    let private = generate(
        &provider,
        KeyAlgorithm::Rsa,
        Some(2048),
        None,
        &rsa_label,
        session_template(&["CKA_UNWRAP", "CKA_DECRYPT"]),
    );
    let public = public_of(&provider, &rsa_label);
    for (name, params) in [
        ("RSA-PKCS1", vec![]),
        ("RSA-OAEP", vec![("hash", e("sha1"))]),
        ("RSA-OAEP", vec![("hash", e("sha256"))]),
    ] {
        let wrap = mech(name, params);
        let blob = provider
            .wrap_key(&public, &wrap, &target, &WrapOptions::default())
            .unwrap();
        let out_label = unique_label();
        let mut request =
            UnwrapRequest::new(KeyAlgorithm::Aes, KeyClass::Secret, out_label.as_str());
        request.template = Some(session_template(&[]));
        let unwrapped = provider
            .unwrap_key(&private, &wrap, &blob, &request)
            .unwrap();
        assert_eq!(
            provider.export_key(&unwrapped).unwrap().data,
            target_value,
            "{name}"
        );
    }
    // CBC/GCM: tolerated where the token lacks CKF_WRAP for them (SoftHSM: CBC unwraps
    // never, CBC_PAD unwraps only on 2.7.0, GCM never) — a refusal must be a translated
    // provider/operation error, never a panic or a wrong key
    let kek_label = unique_label();
    let kek = generate(
        &provider,
        KeyAlgorithm::Aes,
        Some(256),
        None,
        &kek_label,
        session_template(&["CKA_WRAP", "CKA_UNWRAP"]),
    );
    for (name, params) in [
        (
            "AES-CBC",
            vec![("iv", b(&[3; 16])), ("padding", e("pkcs7"))],
        ),
        ("AES-CBC", vec![("iv", b(&[3; 16])), ("padding", e("none"))]),
        ("AES-GCM", vec![("iv", b(&[3; 12])), ("tag_bits", e("128"))]),
    ] {
        let wrap = mech(name, params);
        match provider.wrap_key(&kek, &wrap, &target, &WrapOptions::default()) {
            Ok(blob) => {
                let out_label = unique_label();
                let mut request =
                    UnwrapRequest::new(KeyAlgorithm::Aes, KeyClass::Secret, out_label.as_str());
                request.template = Some(session_template(&[]));
                match provider.unwrap_key(&kek, &wrap, &blob, &request) {
                    Ok(unwrapped) => {
                        assert_eq!(provider.export_key(&unwrapped).unwrap().data, target_value);
                    }
                    Err(err) => assert!(
                        err.kind.is_provider() || err.kind.is_operation(),
                        "{name}: {err:?}"
                    ),
                }
            }
            Err(err) => assert!(
                err.kind.is_provider() || err.kind.is_operation(),
                "{name}: {err:?}"
            ),
        }
    }
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_derive_matches_openssl() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let private = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        &label,
        session_template(&["CKA_DERIVE"]),
    );
    let ours = PKey::private_key_from_der(&provider.export_key(&private).unwrap().data).unwrap();
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let peer = PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap();
    let mut deriver = openssl::derive::Deriver::new(&ours).unwrap();
    deriver.set_peer(&peer).unwrap();
    let z = deriver.derive_to_vec().unwrap();
    // SPKI peer and raw point peer give the same Z
    let spki = peer.public_key_to_der().unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let point = peer
        .ec_key()
        .unwrap()
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .unwrap();
    for peer_bytes in [spki, point] {
        let result = provider
            .derive(&private, &mech("ECDH", vec![("peer", b(&peer_bytes))]))
            .unwrap();
        assert_eq!(result.raw.as_ref().unwrap().as_slice(), z.as_slice());
        let key = result.key.unwrap();
        assert_eq!(key.key_ref.label, format!("{}.shared", label.as_str()));
        assert!(key.exportable);
    }
    // out_len becomes CKA_VALUE_LEN: the token shortens Z itself (SoftHSM keeps a 16-byte
    // slice of Z; which end is token behavior, not r2's)
    let short = provider
        .derive(
            &private,
            &mech(
                "ECDH",
                vec![
                    ("peer", b(&peer.public_key_to_der().unwrap())),
                    ("out_len", i(16)),
                ],
            ),
        )
        .unwrap();
    let short = short.raw.unwrap();
    assert_eq!(short.len(), 16);
    assert!(z.windows(16).any(|w| w == short.as_slice()));
    // SoftHSM accepts only kdf=null (CKR_MECHANISM_PARAM_INVALID otherwise, §5.10)
    let err = provider
        .derive(
            &private,
            &mech(
                "ECDH",
                vec![
                    ("peer", b(&peer.public_key_to_der().unwrap())),
                    ("kdf", e("sha256")),
                ],
            ),
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(
        err.message,
        "token does not support derive with ECDH (or its parameters) (CKR_MECHANISM_PARAM_INVALID)"
    );
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_read_full_template_dumps_the_object() {
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let label = unique_label();
    let key: Vec<u8> = (0u8..32).collect();
    let info = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, key.clone()),
            label.as_str(),
            Some(&session_template(&[])),
            Some(&[0x0a, 0x1b]),
        )
        .unwrap();
    let full = provider.read_full_template(&info).unwrap();
    let get = |name: &str| full.get(name).map(|a| a.value.clone());
    assert_eq!(
        get("CKA_CLASS"),
        Some(AttrValue::Symbol("CKO_SECRET_KEY".into()))
    );
    assert_eq!(
        get("CKA_KEY_TYPE"),
        Some(AttrValue::Symbol("CKK_AES".into()))
    );
    assert_eq!(get("CKA_LABEL"), Some(AttrValue::Str(label.to_string())));
    assert_eq!(get("CKA_ID"), Some(AttrValue::Bytes(vec![0x0a, 0x1b])));
    assert_eq!(get("CKA_VALUE"), Some(AttrValue::Bytes(key)));
    assert_eq!(get("CKA_VALUE_LEN"), Some(AttrValue::Ulong(32)));
    assert_eq!(get("CKA_TOKEN"), Some(AttrValue::Bool(false)));
    // imported objects: CK_UNAVAILABLE_INFORMATION reported numerically (§5.16)
    assert_eq!(
        get("CKA_KEY_GEN_MECHANISM"),
        Some(AttrValue::Ulong(u64::MAX))
    );
    assert!(get("CKA_MODULUS").is_none());
    // a sensitive key withholds CKA_VALUE: skipped, not an error
    let sensitive_label = unique_label();
    let sensitive = generate(
        &provider,
        KeyAlgorithm::Aes,
        Some(128),
        None,
        &sensitive_label,
        KeyTemplate::new(vec![
            boolean("CKA_TOKEN", false),
            boolean("CKA_SENSITIVE", true),
        ]),
    );
    let full = provider.read_full_template(&sensitive).unwrap();
    assert!(full.get("CKA_VALUE").is_none());
    assert_eq!(
        full.get("CKA_SENSITIVE").unwrap().value,
        AttrValue::Bool(true)
    );
    // certificates: no CKA_KEY_TYPE row
    let (_pkcs8, cert) = r2_testkit::fixtures::rsa_pkcs8_and_cert();
    let cert_label = unique_label();
    let certificate = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert.clone()),
            cert_label.as_str(),
            Some(&session_only()),
            None,
        )
        .unwrap();
    let full = provider.read_full_template(&certificate).unwrap();
    assert!(full.get("CKA_KEY_TYPE").is_none());
    assert_eq!(full.get("CKA_VALUE").unwrap().value, AttrValue::Bytes(cert));
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_montgomery_curves_are_translated_errors() {
    // SoftHSM 2.6.1/2.7.0 model neither CKK_EC_MONTGOMERY nor its keypair generation; c2
    // surfaced the translated CKRs (verified against c2 on SoftHSM 2.6.1)
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    for id in [openssl::pkey::Id::X25519, openssl::pkey::Id::X448] {
        let key = match id {
            openssl::pkey::Id::X25519 => PKey::generate_x25519().unwrap(),
            _ => PKey::generate_x448().unwrap(),
        };
        let pkcs8 = key.private_key_to_pkcs8().unwrap();
        let spki = key.public_key_to_der().unwrap();
        for material in [
            KeyMaterial::new(KeyAlgorithm::EcMontgomery, KeyClass::Private, pkcs8),
            KeyMaterial::new(KeyAlgorithm::EcMontgomery, KeyClass::Public, spki),
        ] {
            let label = unique_label();
            let err = provider
                .import_key(&material, label.as_str(), Some(&session_only()), None)
                .unwrap_err();
            assert_eq!(err.kind.class_name(), "Pkcs11Error");
            assert_eq!(
                err.message,
                "template attribute rejected by token (CKR_ATTRIBUTE_VALUE_INVALID)"
            );
            assert_eq!(
                err.hint.as_deref(),
                Some("reopen the template editor and adjust the offending attribute")
            );
        }
        let label = unique_label();
        let mut request = GenerateRequest::new(KeyAlgorithm::EcMontgomery, label.as_str());
        request.curve = Some(if id == openssl::pkey::Id::X25519 {
            Curve::X25519
        } else {
            Curve::X448
        });
        request.template = Some(session_only());
        request.public_template = Some(session_only());
        let err = provider.generate_key(&request).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
        assert_eq!(
            err.message,
            "token does not support keypair generation (or its parameters) (CKR_MECHANISM_INVALID)"
        );
    }
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_rsa_aes_key_wrap_is_never_advertised() {
    // §11 D6: resolved as "no deviation" — RSA-AES-KEY-WRAP ∉ mechanisms() on 2.6.1 and
    // 2.7.0 (2.7.0 lists CKM_RSA_AES_KEY_WRAP)
    let _lock = r2_testkit::global_state_lock();
    let provider = logged_in();
    let mechanisms = provider.mechanisms();
    assert!(!mechanisms.contains("RSA-AES-KEY-WRAP"), "{mechanisms:?}");
    for name in [
        "AES-ECB",
        "AES-CBC",
        "AES-CTR",
        "AES-GCM",
        "AES-CMAC",
        "AES-GMAC",
        "HMAC",
        "RSA-OAEP",
        "RSA-PKCS1",
        "RSA-PSS",
        "RSA-RAW",
        "ECDSA",
        "EDDSA",
        "ECDH",
        "AES-KEY-WRAP",
        "AES-KEY-WRAP-PAD",
    ] {
        assert!(
            mechanisms.contains(name),
            "{name} missing from {mechanisms:?}"
        );
    }
    provider.shutdown().unwrap();
}
