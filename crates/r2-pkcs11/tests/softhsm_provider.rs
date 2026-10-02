//! Pkcs11Provider against a real SoftHSM2 token (c2 tests/integration/test_pkcs11_provider.py
//! TestLogin / TestGenerate / TestLoadObjects / TestInitToken, plus the §4.5.5 shared-module
//! symlink test). Feature `softhsm`; fails (never skips) without the fixture from
//! `scripts/softhsm-init.sh`. Objects are session objects (CKA_TOKEN=false) under unique
//! labels; nextest runs these one at a time (softhsm test group).
#![cfg(feature = "softhsm")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::BTreeMap;

use indexmap::IndexMap;
use r2_config::model::Pkcs11InstanceConfig;
use r2_core::error::ErrorKind;
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_pkcs11::Pkcs11Provider;
use r2_provider::{AuthState, GenerateRequest, KeySelector, Provider, TokenInfo};
use r2_testkit::softhsm::{SofthsmToken, softhsm_token, unique_label};
use secrecy::SecretString;

fn pin(text: &str) -> SecretString {
    SecretString::from(text.to_string())
}

fn boolean(name: &str, value: bool) -> TemplateAttr {
    TemplateAttr::new(name, AttrKind::Bool, AttrValue::Bool(value))
}

/// Session-object template: exportable, plus the given usage bools.
fn session_template(extra_true: &[&str]) -> KeyTemplate {
    let mut attrs = vec![
        boolean("CKA_TOKEN", false),
        boolean("CKA_SENSITIVE", false),
        boolean("CKA_EXTRACTABLE", true),
    ];
    attrs.extend(extra_true.iter().map(|name| boolean(name, true)));
    KeyTemplate::new(attrs)
}

fn make_provider_at(
    token: &SofthsmToken,
    name: &str,
    library: std::path::PathBuf,
) -> Pkcs11Provider {
    let mut config = Pkcs11InstanceConfig::new(name, library);
    config.slot = Some(token.slot);
    config.token_label = Some(token.token_label.clone());
    Pkcs11Provider::new(name, config, BTreeMap::new(), IndexMap::new())
}

fn make_provider(token: &SofthsmToken, name: &str) -> Pkcs11Provider {
    make_provider_at(token, name, token.module_path.clone())
}

fn login(provider: &Pkcs11Provider, token: &SofthsmToken, keep_pin: bool) -> TokenInfo {
    let info = provider
        .list_tokens()
        .unwrap()
        .into_iter()
        .find(|t| t.label == token.token_label)
        .unwrap_or_else(|| panic!("token {:?} not found", token.token_label));
    provider
        .login(&info, &pin(&token.user_pin), keep_pin)
        .unwrap();
    info
}

fn logged_in() -> Pkcs11Provider {
    let token = softhsm_token();
    let provider = make_provider(token, "softhsm");
    login(&provider, token, false);
    provider
}

// ---- TestLogin ----

#[test]
fn softhsm_login_status_logout() {
    let token = softhsm_token();
    let provider = make_provider(token, "softhsm");
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    assert!(provider.mechanisms().is_empty());
    let info = login(&provider, token, false);
    assert_eq!(info.manufacturer, "SoftHSM project");
    let status = provider.status();
    assert_eq!(status.auth, AuthState::LoggedIn);
    assert_eq!(status.token.as_ref(), Some(&info));
    let mechs = provider.mechanisms();
    for name in [
        "AES-CBC", "AES-GCM", "AES-GMAC", "RSA-OAEP", "ECDSA", "ECDH",
    ] {
        assert!(mechs.contains(name), "{name} missing from {mechs:?}");
    }
    assert!(!mechs.contains("RSA-AES-KEY-WRAP")); // never advertised (§11 D6)
    let err = provider
        .login(&info, &pin(&token.user_pin), false)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AlreadyLoggedIn);
    provider.logout().unwrap();
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    assert!(provider.mechanisms().is_empty());
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_wrong_pin() {
    let token = softhsm_token();
    let provider = make_provider(token, "softhsm");
    let info = provider
        .list_tokens()
        .unwrap()
        .into_iter()
        .find(|t| t.label == token.token_label)
        .unwrap();
    let err = provider
        .login(&info, &pin("not-the-pin"), false)
        .unwrap_err();
    assert_eq!(
        err.ckr().map(|(_, n)| n.to_string()),
        Some("CKR_PIN_INCORRECT".to_string())
    );
    assert!(err.message.contains(&token.token_label), "{}", err.message);
    provider.shutdown().unwrap();
}

// ---- TestGenerate ----

#[test]
fn softhsm_generate_aes_applies_template() {
    let provider = logged_in();
    let label = unique_label();
    let mut request = GenerateRequest::new(KeyAlgorithm::Aes, label.as_str());
    request.size_bits = Some(256);
    request.template = Some(session_template(&[]));
    let info = provider.generate_key(&request).unwrap();
    assert_eq!(
        (info.key_class, info.algorithm, info.size_bits),
        (KeyClass::Secret, KeyAlgorithm::Aes, Some(256))
    );
    // template applied: sensitive/extractable flags round-trip via §5.5
    let expected = BTreeMap::from([
        ("CKA_EXTRACTABLE".to_string(), AttrValue::Bool(true)),
        ("CKA_SENSITIVE".to_string(), AttrValue::Bool(false)),
    ]);
    assert_eq!(info.attributes, expected);
    assert!(info.exportable);
    assert_eq!(provider.export_key(&info).unwrap().data.len(), 32);
    // non-exportable template honored too
    let locked_label = unique_label();
    let mut locked = GenerateRequest::new(KeyAlgorithm::Aes, locked_label.as_str());
    locked.size_bits = Some(128);
    locked.template = Some(KeyTemplate::new(vec![
        boolean("CKA_TOKEN", false),
        boolean("CKA_SENSITIVE", true),
        boolean("CKA_EXTRACTABLE", false),
    ]));
    let locked = provider.generate_key(&locked).unwrap();
    assert!(!locked.exportable);
    let expected = BTreeMap::from([
        ("CKA_EXTRACTABLE".to_string(), AttrValue::Bool(false)),
        ("CKA_SENSITIVE".to_string(), AttrValue::Bool(true)),
    ]);
    assert_eq!(locked.attributes, expected);
    assert_eq!(
        provider.export_key(&locked).unwrap_err().kind,
        ErrorKind::KeyNotExportable
    );
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_generate_rsa_keypair_shared_label_and_id() {
    let provider = logged_in();
    let label = unique_label();
    let mut request = GenerateRequest::new(KeyAlgorithm::Rsa, label.as_str());
    request.size_bits = Some(2048);
    request.key_id = Some(vec![0x11, 0x22]);
    request.template = Some(session_template(&["CKA_SIGN", "CKA_DECRYPT"]));
    request.public_template = Some(KeyTemplate::new(vec![
        boolean("CKA_TOKEN", false),
        boolean("CKA_VERIFY", true),
    ]));
    let private = provider.generate_key(&request).unwrap();
    assert_eq!(private.key_class, KeyClass::Private);
    assert_eq!(private.size_bits, Some(2048));
    assert_eq!(private.key_ref.key_id, Some(vec![0x11, 0x22]));
    let publics: Vec<_> = provider
        .list_keys()
        .unwrap()
        .into_iter()
        .filter(|k| k.key_ref.label == label.as_str() && k.key_class == KeyClass::Public)
        .collect();
    assert_eq!(publics.len(), 1);
    assert_eq!(publics[0].key_ref.key_id, Some(vec![0x11, 0x22]));
    assert_eq!(publics[0].size_bits, Some(2048));
    // the family collapses to the private half; regenerating the identity is refused
    assert_eq!(
        provider
            .find_key(&KeySelector::label(label.as_str()))
            .unwrap()
            .key_class,
        KeyClass::Private
    );
    assert_eq!(
        provider.generate_key(&request).unwrap_err().kind,
        ErrorKind::DuplicateKey
    );
    provider.shutdown().unwrap();
}

#[test]
fn softhsm_generate_ec_and_montgomery_translation() {
    let provider = logged_in();
    let label = unique_label();
    let mut request = GenerateRequest::new(KeyAlgorithm::Ec, label.as_str());
    request.curve = Some(Curve::P256);
    request.template = Some(session_template(&["CKA_SIGN"]));
    request.public_template = Some(KeyTemplate::new(vec![boolean("CKA_TOKEN", false)]));
    let info = provider.generate_key(&request).unwrap();
    assert_eq!(info.curve, Some(Curve::P256));
    // §5.3 field note: SoftHSM has no CKM_EC_MONTGOMERY_KEY_PAIR_GEN
    let x_label = unique_label();
    let mut x = GenerateRequest::new(KeyAlgorithm::EcMontgomery, x_label.as_str());
    x.curve = Some(Curve::X25519);
    x.template = Some(KeyTemplate::new(vec![boolean("CKA_TOKEN", false)]));
    x.public_template = Some(KeyTemplate::new(vec![boolean("CKA_TOKEN", false)]));
    let err = provider.generate_key(&x).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(
        err.message,
        "token does not support keypair generation (or its parameters) (CKR_MECHANISM_INVALID)"
    );
    provider.shutdown().unwrap();
}

// ---- TestLoadObjects ----

#[test]
fn softhsm_load_every_object_kind() {
    let provider = logged_in();
    let (pkcs8, cert_der) = r2_testkit::fixtures::rsa_pkcs8_and_cert();
    let shared_id = vec![0x77, 0x01];

    let aes_label = unique_label();
    let mut aes = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, (0u8..24).collect());
    aes.size_bits = Some(192);
    let aes_info = provider
        .import_key(
            &aes,
            &aes_label,
            Some(&session_template(&["CKA_ENCRYPT", "CKA_DECRYPT"])),
            None,
        )
        .unwrap();
    assert_eq!(aes_info.size_bits, Some(192));
    assert_eq!(
        provider.export_key(&aes_info).unwrap().data.to_vec(),
        (0u8..24).collect::<Vec<_>>()
    );

    let rsa_label = unique_label();
    let rsa = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, pkcs8.clone());
    let rsa_info = provider
        .import_key(
            &rsa,
            &rsa_label,
            Some(&session_template(&["CKA_SIGN", "CKA_DECRYPT"])),
            Some(&shared_id),
        )
        .unwrap();
    assert_eq!(rsa_info.key_class, KeyClass::Private);
    assert_eq!(rsa_info.size_bits, Some(2048));
    // plain-readable private key exports back to the same key material
    assert_eq!(provider.export_key(&rsa_info).unwrap().data.to_vec(), pkcs8);

    let ec_label = unique_label();
    let ec_pkcs8 = r2_testkit::fixtures::ec_p256_pkcs8();
    let ec = KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Private, ec_pkcs8.clone());
    let ec_info = provider
        .import_key(
            &ec,
            &ec_label,
            Some(&session_template(&["CKA_SIGN", "CKA_DERIVE"])),
            None,
        )
        .unwrap();
    assert_eq!(ec_info.curve, Some(Curve::P256));
    assert_eq!(ec_info.algorithm, KeyAlgorithm::Ec);
    assert_eq!(
        provider.export_key(&ec_info).unwrap().data.to_vec(),
        ec_pkcs8
    );

    let ed_label = unique_label();
    let ed_pkcs8 = r2_testkit::fixtures::ed25519_pkcs8();
    let ed = KeyMaterial::new(KeyAlgorithm::EcEdwards, KeyClass::Private, ed_pkcs8.clone());
    let ed_info = provider
        .import_key(&ed, &ed_label, Some(&session_template(&["CKA_SIGN"])), None)
        .unwrap();
    assert_eq!(
        (ed_info.algorithm, ed_info.curve.clone()),
        (KeyAlgorithm::EcEdwards, Some(Curve::Ed25519))
    );
    assert_eq!(
        provider.export_key(&ed_info).unwrap().data.to_vec(),
        ed_pkcs8
    );
    // its public half (SPKI) imports as CKK_EC_EDWARDS with a DER-wrapped point
    let ed_spki = r2_core::formats::pkcs8_public_spki(&ed_pkcs8).unwrap();
    let ed_pub = KeyMaterial::new(KeyAlgorithm::EcEdwards, KeyClass::Public, ed_spki.clone());
    let ed_pub_info = provider
        .import_key(
            &ed_pub,
            &ed_label,
            Some(&KeyTemplate::new(vec![boolean("CKA_TOKEN", false)])),
            ed_info.key_ref.key_id.as_deref(),
        )
        .unwrap();
    assert_eq!(
        provider.export_key(&ed_pub_info).unwrap().data.to_vec(),
        ed_spki
    );

    let cert_label = unique_label();
    let cert = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert_der.clone());
    let cert_info = provider
        .import_key(
            &cert,
            &cert_label,
            Some(&KeyTemplate::new(vec![boolean("CKA_TOKEN", false)])),
            Some(&shared_id),
        )
        .unwrap();
    assert_eq!(cert_info.key_class, KeyClass::Certificate);
    assert!(cert_info.exportable);
    assert_eq!(cert_info.algorithm, KeyAlgorithm::Rsa);
    assert_eq!(
        cert_info.attributes.get("CKA_SUBJECT"),
        Some(&AttrValue::Str("CN=r2-contract".to_string()))
    );
    assert_eq!(
        provider.export_key(&cert_info).unwrap().data.to_vec(),
        cert_der
    );
    assert_eq!(
        provider
            .find_key(&KeySelector::label(cert_label.as_str()))
            .unwrap()
            .key_class,
        KeyClass::Certificate
    );

    let generic_label = unique_label();
    let generic = KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, vec![0x5a; 20]);
    let generic_info = provider
        .import_key(
            &generic,
            &generic_label,
            Some(&session_template(&["CKA_SIGN"])),
            None,
        )
        .unwrap();
    assert_eq!(
        (generic_info.algorithm, generic_info.size_bits),
        (KeyAlgorithm::Generic, Some(160))
    );
    assert_eq!(
        provider.export_key(&generic_info).unwrap().data.to_vec(),
        vec![0x5a; 20]
    );

    let data_label = unique_label();
    let data = KeyMaterial::new(
        KeyAlgorithm::None,
        KeyClass::Data,
        b"opaque \x00\xff".to_vec(),
    );
    let data_template = KeyTemplate::new(vec![
        boolean("CKA_TOKEN", false),
        TemplateAttr::new(
            "CKA_APPLICATION",
            AttrKind::Str,
            AttrValue::Str("acme".into()),
        ),
    ]);
    let data_info = provider
        .import_key(&data, &data_label, Some(&data_template), None)
        .unwrap();
    assert_eq!(
        (data_info.key_class, data_info.key_ref.key_id.clone()),
        (KeyClass::Data, None)
    );
    assert_eq!(
        data_info.attributes.get("CKA_APPLICATION"),
        Some(&AttrValue::Str("acme".into()))
    );
    assert_eq!(
        provider.export_key(&data_info).unwrap().data.to_vec(),
        b"opaque \x00\xff"
    );

    let listed: Vec<String> = provider
        .list_keys()
        .unwrap()
        .into_iter()
        .map(|k| k.key_ref.label)
        .collect();
    for label in [
        &aes_label,
        &rsa_label,
        &ec_label,
        &ed_label,
        &cert_label,
        &generic_label,
        &data_label,
    ] {
        assert!(
            listed.iter().any(|l| l == label.as_str()),
            "{} not listed",
            label.as_str()
        );
    }
    provider.delete_key(&data_info).unwrap();
    provider.shutdown().unwrap();
}

// ---- TestInitToken ----

#[test]
fn softhsm_init_token_label_round_trips_exactly() {
    // C_InitToken wants a 32-byte space-padded label; an unpadded one comes back NUL-filled
    let token = softhsm_token();
    let provider = make_provider(token, "softhsm-init");
    let free: Vec<TokenInfo> = provider
        .list_tokens()
        .unwrap()
        .into_iter()
        .filter(|t| t.label.is_empty())
        .collect();
    assert!(
        !free.is_empty(),
        "SoftHSM always exposes one free/uninitialized slot"
    );
    let label = format!("R2INIT-{}", &unique_label().as_str()[7..15]);
    provider
        .init_token(free[0].slot_id, &label, &pin("8765"), &pin("5678"))
        .unwrap();
    let matches: Vec<TokenInfo> = provider
        .list_tokens()
        .unwrap()
        .into_iter()
        .filter(|t| t.label == label)
        .collect();
    assert_eq!(matches.len(), 1); // exact label — no NUL/space garbage
    assert!(!matches[0].label.contains('\0'));
    provider.login(&matches[0], &pin("5678"), false).unwrap(); // C_InitPIN took effect
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
    provider.shutdown().unwrap();
}

// ---- §4.5.5 / §11 D21: one shared module per canonical library path ----

#[test]
fn softhsm_symlinked_library_shares_one_module() {
    // the final set_env_and_reset writes the process environment
    let _lock = r2_testkit::global_state_lock();
    let _restore = r2_testkit::set_env("R2_UNUSED_RESET", None);
    let token = softhsm_token();
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("libsofthsm2-link.so");
    std::os::unix::fs::symlink(&token.module_path, &link).unwrap();
    let first = make_provider(token, "softhsm");
    let second = make_provider_at(token, "softhsm-link", link);
    // `first` only loads the module (C_Logout is token-wide for the application, so a
    // logged-in sibling's shutdown would end `second`'s login exactly as in c2 — that is
    // PKCS#11 login semantics, not module sharing)
    assert!(!first.list_tokens().unwrap().is_empty());
    login(&second, token, false);
    // both hold the one module (is_sole_module_user false): the wizard's reset is
    // refused for both
    for provider in [&first, &second] {
        let reset = provider
            .as_token_init()
            .unwrap()
            .set_env_and_reset("R2_UNUSED_RESET", "x");
        let err = reset.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Provider);
        assert!(
            err.message
                .ends_with("shares its PKCS#11 module with another provider")
        );
    }
    assert_eq!(std::env::var_os("R2_UNUSED_RESET"), None); // refused before set_var
    // shutting one down leaves the other's session usable (no C_Finalize under it)
    first.shutdown().unwrap();
    assert!(second.list_keys().is_ok());
    let label = unique_label();
    let mut request = GenerateRequest::new(KeyAlgorithm::Aes, label.as_str());
    request.size_bits = Some(128);
    request.template = Some(session_template(&[]));
    second.generate_key(&request).unwrap();
    // `second` is now the sole user: the reset goes through (and finalizes the module)
    second
        .as_token_init()
        .unwrap()
        .set_env_and_reset("R2_UNUSED_RESET", "x")
        .unwrap();
    assert_eq!(second.status().auth, AuthState::LoggedOut);
    assert!(!second.list_tokens().unwrap().is_empty()); // lazy re-initialize works
    second.shutdown().unwrap();
}
