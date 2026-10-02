//! The §5.2 CKR table at the choke point (every row), plus c2 test_provider_objects.py
//! TestCkrMapping through the provider.
use std::borrow::Cow;

use r2_core::error::ErrorKind;
use r2_provider::{KeySelector, Provider};

use super::logged_in;
use crate::backend::{BackendError, Ckr};
use crate::ckr::{pykcs11_error_text, rv, translate};

fn tr(code: u64, context: &str) -> r2_core::ConsoleError {
    translate(
        BackendError::Ckr(Ckr {
            code,
            function: "test",
        }),
        "hsm",
        context,
        Some("TOK"),
    )
}

fn pkcs11(code: u64, name: &str) -> ErrorKind {
    ErrorKind::Pkcs11 {
        ckr_code: code,
        ckr_name: Cow::Owned(name.to_string()),
    }
}

#[test]
fn every_section_5_2_row() {
    let e = tr(rv::CKR_PIN_INCORRECT, "login");
    assert_eq!(e.kind, pkcs11(0xA0, "CKR_PIN_INCORRECT"));
    assert_eq!(e.message, "wrong PIN for token 'TOK' (CKR_PIN_INCORRECT)");
    assert_eq!(e.hint.as_deref(), Some("re-enter the PIN"));

    let e = tr(rv::CKR_PIN_LOCKED, "login");
    assert_eq!(e.kind, pkcs11(0xA4, "CKR_PIN_LOCKED"));
    assert_eq!(
        e.message,
        "token locked — too many bad PINs (CKR_PIN_LOCKED)"
    );
    assert_eq!(e.hint.as_deref(), Some("unlock with the SO PIN"));

    let e = tr(rv::CKR_USER_NOT_LOGGED_IN, "key listing");
    assert_eq!(e.kind, ErrorKind::AuthRequired);
    assert_eq!(e.message, "login required: run `login hsm`");
    assert_eq!(e.hint, None);

    for code in [rv::CKR_SESSION_HANDLE_INVALID, rv::CKR_DEVICE_REMOVED] {
        let e = tr(code, "key listing");
        assert_eq!(e.kind, ErrorKind::AuthRequired);
        assert_eq!(e.message, "session lost — login again");
    }

    let e = tr(rv::CKR_TOKEN_NOT_PRESENT, "key listing");
    assert_eq!(e.message, "no token in slot (CKR_TOKEN_NOT_PRESENT)");
    assert_eq!(
        e.hint.as_deref(),
        Some("re-insert the token and run `slots hsm`")
    );

    let e = tr(rv::CKR_MECHANISM_INVALID, "keypair generation");
    assert_eq!(e.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(
        e.message,
        "token does not support keypair generation (or its parameters) (CKR_MECHANISM_INVALID)"
    );
    let e = tr(rv::CKR_MECHANISM_PARAM_INVALID, "encrypt with AES-GCM");
    assert_eq!(
        e.message,
        "token does not support encrypt with AES-GCM (or its parameters) (CKR_MECHANISM_PARAM_INVALID)"
    );

    let e = tr(rv::CKR_KEY_HANDLE_INVALID, "sign with HMAC");
    assert_eq!(
        e.message,
        "key no longer available on token (CKR_KEY_HANDLE_INVALID)"
    );
    assert_eq!(e.hint.as_deref(), Some("refresh with `keys`"));

    for (code, name) in [
        (
            rv::CKR_ATTRIBUTE_VALUE_INVALID,
            "CKR_ATTRIBUTE_VALUE_INVALID",
        ),
        (rv::CKR_ATTRIBUTE_TYPE_INVALID, "CKR_ATTRIBUTE_TYPE_INVALID"),
    ] {
        let e = tr(code, "object creation");
        assert_eq!(e.kind, pkcs11(code, name));
        assert_eq!(
            e.message,
            format!("template attribute rejected by token ({name})")
        );
        assert_eq!(
            e.hint.as_deref(),
            Some("reopen the template editor and adjust the offending attribute")
        );
    }

    let e = tr(rv::CKR_ATTRIBUTE_READ_ONLY, "set CKA_TOKEN");
    assert_eq!(
        e.message,
        "token forbids changing this attribute (CKR_ATTRIBUTE_READ_ONLY)"
    );
    assert_eq!(
        e.hint.as_deref(),
        Some("the attribute is fixed after object creation on this token")
    );

    for (code, name) in [
        (rv::CKR_KEY_NOT_WRAPPABLE, "CKR_KEY_NOT_WRAPPABLE"),
        (rv::CKR_KEY_UNEXTRACTABLE, "CKR_KEY_UNEXTRACTABLE"),
    ] {
        let e = tr(code, "wrap with AES-KEY-WRAP");
        assert_eq!(
            e.message,
            format!("key cannot be exported or wrapped ({name})")
        );
        assert_eq!(
            e.hint.as_deref(),
            Some("token policy forbids extracting this key")
        );
    }

    let e = tr(rv::CKR_KEY_SIZE_RANGE, "sign with HMAC");
    assert_eq!(
        e.message,
        "key length unsuitable for sign with HMAC (CKR_KEY_SIZE_RANGE)"
    );
    assert_eq!(
        e.hint.as_deref(),
        Some(
            "HMAC keys must be at least the digest length on this token (e.g. 32 bytes for \
             sha256, 64 for sha512)"
        )
    );

    let e = tr(rv::CKR_FUNCTION_NOT_SUPPORTED, "token initialization");
    assert_eq!(
        e.message,
        "token firmware lacks this function (CKR_FUNCTION_NOT_SUPPORTED)"
    );
    assert_eq!(
        e.hint.as_deref(),
        Some("capability missing for token initialization")
    );

    let e = tr(rv::CKR_DEVICE_ERROR, "key listing");
    assert_eq!(e.kind, pkcs11(0x30, "CKR_DEVICE_ERROR"));
    assert_eq!(e.message, "PKCS#11 key listing failed (CKR_DEVICE_ERROR)");
    assert_eq!(e.hint, None);
}

#[test]
fn pin_texts_default_to_question_mark() {
    let e = translate(
        BackendError::Ckr(Ckr {
            code: rv::CKR_PIN_INCORRECT,
            function: "test",
        }),
        "hsm",
        "token initialization",
        None,
    );
    assert_eq!(e.message, "wrong PIN for token '?' (CKR_PIN_INCORRECT)");
}

#[test]
fn unnamed_codes_render_as_c2_did() {
    // CKR_ACTION_PROHIBITED (0x1B) is in cryptoki-sys but not in PyKCS11's table
    let e = tr(0x1B, "key export");
    assert_eq!(e.kind, pkcs11(0x1B, "CKR_0x0000001B"));
    assert_eq!(e.message, "PKCS#11 key export failed (CKR_0x0000001B)");
    let e = tr(0x8000_0123, "key export");
    assert_eq!(e.message, "PKCS#11 key export failed (CKR_0x80000123)");
}

#[test]
fn binding_errors_are_c2s_minus_one() {
    let e = translate(
        BackendError::Binding("NotSupported".into()),
        "hsm",
        "key listing",
        None,
    );
    assert_eq!(e.kind, pkcs11(0xFFFF_FFFF, "CKR_0xFFFFFFFF"));
    assert_eq!(e.message, "PKCS#11 key listing failed (CKR_0xFFFFFFFF)");
}

#[test]
fn library_unavailable_is_provider_unavailable() {
    let e = translate(
        BackendError::LibraryUnavailable("x".into()),
        "hsm",
        "/opt/lib.so",
        None,
    );
    assert_eq!(e.kind, ErrorKind::ProviderUnavailable);
    assert_eq!(e.message, "cannot load PKCS#11 library /opt/lib.so: x");
    assert_eq!(
        e.hint.as_deref(),
        Some("check providers.pkcs11[].library in the configuration")
    );
}

#[test]
fn pykcs11_error_texts() {
    assert_eq!(pykcs11_error_text(5), "CKR_GENERAL_ERROR (0x00000005)");
    assert_eq!(pykcs11_error_text(0x8000_0001), "Vendor error (0x00000001)");
    assert_eq!(pykcs11_error_text(0x12345), "Unknown error (0x00012345)");
}

// ---- c2 TestCkrMapping (through the provider) ----

#[test]
fn attribute_invalid_maps_to_pkcs11error() {
    let (backend, provider) = logged_in();
    backend.fail_next("create_object", rv::CKR_ATTRIBUTE_VALUE_INVALID);
    let material = r2_core::keys::KeyMaterial::new(
        r2_core::keys::KeyAlgorithm::Aes,
        r2_core::keys::KeyClass::Secret,
        vec![0; 32],
    );
    let err = provider
        .import_key(&material, "ckr-2", None, None)
        .unwrap_err();
    assert_eq!(err.ckr(), Some((0x13, "CKR_ATTRIBUTE_VALUE_INVALID")));
}

#[test]
fn user_not_logged_in_maps_to_auth_required() {
    let (backend, provider) = logged_in();
    backend.fail_next("find_objects", rv::CKR_USER_NOT_LOGGED_IN);
    let err = provider.list_keys().unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
}

#[test]
fn unknown_ckr_keeps_code_and_name() {
    let (backend, provider) = logged_in();
    backend.fail_next("find_objects", rv::CKR_DEVICE_ERROR);
    let err = provider.list_keys().unwrap_err();
    assert_eq!(err.ckr(), Some((0x30, "CKR_DEVICE_ERROR")));
}

#[test]
fn key_handle_invalid_message() {
    // c2: export of a deleted key → KeyNotFound (the re-resolve finds nothing)
    let (_backend, provider) = logged_in();
    let material = r2_core::keys::KeyMaterial::new(
        r2_core::keys::KeyAlgorithm::Aes,
        r2_core::keys::KeyClass::Secret,
        vec![0; 32],
    );
    let info = provider.import_key(&material, "ckr-3", None, None).unwrap();
    provider.delete_key(&info).unwrap();
    let err = provider.export_key(&info).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotFound);
    assert_eq!(
        err.message,
        format!(
            "key '{}' no longer available on hsm",
            info.key_ref.display()
        )
    );
    assert_eq!(err.hint.as_deref(), Some("refresh with `keys`"));
    let missing = provider.find_key(&KeySelector::label("ckr-3")).unwrap_err();
    assert_eq!(missing.message, "no key 'ckr-3' on provider hsm");
}
