//! Ports of c2 tests/unit/pkcs11/test_provider_session.py: session lifecycle and login
//! states over the FakeBackend (§5.2), plus TokenInit and the real-backend load failures.
use std::rc::Rc;

use r2_core::error::ErrorKind;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_provider::{AuthState, KeySelector, Provider, TokenInit};

use super::{USER_PIN, config, logged_in, pin, provider_over, token_at};
use crate::Pkcs11Provider;
use crate::backend::fake::{DEFAULT_MECHANISMS, FakeBackend};
use crate::ckr::rv;

fn aes() -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![0; 32])
}

fn new_provider() -> (Rc<FakeBackend>, Pkcs11Provider) {
    let backend = Rc::new(FakeBackend::new());
    let provider = provider_over(&backend);
    (backend, provider)
}

// ---- TestInitialize ----

#[test]
fn load_failure_is_provider_unavailable() {
    let (backend, provider) = new_provider();
    backend.set_load_error("Load (/fake/libfake.so)");
    let err = provider.initialize().unwrap_err();
    assert_eq!(err.kind, ErrorKind::ProviderUnavailable);
    assert_eq!(
        err.message,
        "cannot load PKCS#11 library /fake/libfake.so: Load (/fake/libfake.so)"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("check providers.pkcs11[].library in the configuration")
    );
}

#[test]
fn wrong_library_path() {
    // the REAL backend over a path that does not exist: libloading fails → ProviderUnavailable
    let _lock = r2_testkit::global_state_lock();
    let config = r2_config::model::Pkcs11InstanceConfig::new("hsm", "/nonexistent/lib.so");
    let provider = Pkcs11Provider::new("hsm", config, Default::default(), Default::default());
    let err = provider.initialize().unwrap_err();
    assert_eq!(err.kind, ErrorKind::ProviderUnavailable);
    assert!(
        err.message
            .starts_with("cannot load PKCS#11 library /nonexistent/lib.so: "),
        "{}",
        err.message
    );
    // status never loads anything and stays logged out
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    provider.shutdown().unwrap();
}

#[test]
fn idempotent() {
    let (backend, provider) = new_provider();
    provider.initialize().unwrap();
    provider.initialize().unwrap();
    assert_eq!(backend.load_counts(), (1, 0));
}

#[test]
fn instance_env_applied_before_load() {
    let _lock = r2_testkit::global_state_lock();
    let _guard = r2_testkit::set_env("R2_FAKE_ENV", None);
    let backend = Rc::new(FakeBackend::new());
    let mut cfg = config("hsm");
    cfg.env
        .insert("R2_FAKE_ENV".into(), "set-by-provider".into());
    let shared: Rc<dyn crate::backend::Backend> = backend.clone();
    let provider =
        Pkcs11Provider::with_backend("hsm", cfg, Default::default(), Default::default(), shared);
    provider.initialize().unwrap();
    assert_eq!(
        std::env::var("R2_FAKE_ENV").as_deref(),
        Ok("set-by-provider")
    );
    assert_eq!(backend.calls(), ["initialize"]);
}

#[test]
fn shutdown_safe_when_never_initialized() {
    let (backend, provider) = new_provider();
    provider.shutdown().unwrap(); // must not raise
    assert_eq!(backend.load_counts(), (0, 0));
}

// ---- TestLogin ----

#[test]
fn status_and_token_enumeration() {
    let (_backend, provider) = new_provider();
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    assert_eq!(provider.status().token, None);
    let tokens = provider.list_tokens().unwrap();
    assert_eq!(tokens.iter().map(|t| t.slot_id).collect::<Vec<_>>(), [0]);
    assert_eq!(tokens[0].label, "fake-token"); // stripped padding
    assert_eq!(tokens[0].serial, "FAKE0001");
}

#[test]
fn token_strings_strip_trailing_spaces_and_nuls() {
    let mut info = FakeBackend::token("pad\0\0  \0", "SER  ");
    info.manufacturer = "maker \0".into();
    let backend = Rc::new(FakeBackend::with_slots(vec![(
        3,
        info,
        DEFAULT_MECHANISMS.to_vec(),
    )]));
    let provider = provider_over(&backend);
    let token = token_at(&provider, 3);
    assert_eq!(
        (
            token.label.as_str(),
            token.serial.as_str(),
            token.manufacturer.as_str()
        ),
        ("pad", "SER", "maker")
    );
}

#[test]
fn login_logout_cycle() {
    let (_backend, provider) = new_provider();
    let token = token_at(&provider, 0);
    provider.login(&token, &pin(USER_PIN), false).unwrap();
    let status = provider.status();
    assert_eq!(status.auth, AuthState::LoggedIn);
    assert_eq!(
        status.token.as_ref().map(|t| t.label.as_str()),
        Some("fake-token")
    );
    assert!(!provider.mechanisms().is_empty()); // §4.5: non-empty post-login
    provider.logout().unwrap();
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    assert!(provider.mechanisms().is_empty()); // §4.5: empty while logged out
    let err = provider.list_keys().unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert_eq!(err.message, "login required: run `login hsm`");
}

#[test]
fn wrong_pin() {
    let (_backend, provider) = new_provider();
    let token = token_at(&provider, 0);
    let err = provider.login(&token, &pin("9999"), false).unwrap_err();
    assert_eq!(err.ckr().map(|(_, n)| n), Some("CKR_PIN_INCORRECT"));
    assert_eq!(
        err.message,
        "wrong PIN for token 'fake-token' (CKR_PIN_INCORRECT)"
    );
    assert_eq!(err.hint.as_deref(), Some("re-enter the PIN"));
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
}

#[test]
fn pin_locked() {
    let (backend, provider) = new_provider();
    backend.set_pin_locked(0, true);
    let token = token_at(&provider, 0);
    let err = provider.login(&token, &pin(USER_PIN), false).unwrap_err();
    assert_eq!(err.ckr().map(|(_, n)| n), Some("CKR_PIN_LOCKED"));
}

#[test]
fn already_logged_in_provider_state() {
    let (backend, provider) = logged_in();
    let token = token_at(&provider, 0);
    let before = backend.calls().len();
    let err = provider.login(&token, &pin(USER_PIN), false).unwrap_err();
    assert_eq!(err.kind, ErrorKind::AlreadyLoggedIn);
    assert_eq!(err.message, "already logged in");
    assert_eq!(err.hint.as_deref(), Some("logout first"));
    assert_eq!(backend.calls().len(), before); // checked before C_Login
}

#[test]
fn raw_ckr_user_already_logged_in_swallowed() {
    // another session/process already logged the token in (§5.2: success)
    let (backend, provider) = new_provider();
    backend.set_logged_in(0, true);
    let token = token_at(&provider, 0);
    provider.login(&token, &pin(USER_PIN), false).unwrap();
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
}

#[test]
fn logout_keeps_session_reusable() {
    let (backend, provider) = new_provider();
    let token = token_at(&provider, 0);
    provider.login(&token, &pin(USER_PIN), false).unwrap();
    assert_eq!(backend.sessions_opened(), 1);
    provider.logout().unwrap();
    provider.login(&token, &pin(USER_PIN), false).unwrap(); // same session reused (§5.2)
    assert_eq!(backend.sessions_opened(), 1);
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
}

#[test]
fn single_token_rule_closes_previous_session() {
    let backend = Rc::new(FakeBackend::with_slots(vec![
        (
            5,
            FakeBackend::token("TOK-A", "A"),
            DEFAULT_MECHANISMS.to_vec(),
        ),
        (
            6,
            FakeBackend::token("TOK-B", "B"),
            DEFAULT_MECHANISMS.to_vec(),
        ),
    ]));
    let provider = provider_over(&backend);
    provider
        .login(&token_at(&provider, 5), &pin(USER_PIN), false)
        .unwrap();
    assert_eq!(backend.session_slot(), Some(5));
    provider.logout().unwrap();
    provider
        .login(&token_at(&provider, 6), &pin(USER_PIN), false)
        .unwrap();
    assert_eq!(backend.session_slot(), Some(6)); // previous slot's session closed (§5.2)
    assert!(backend.calls().contains(&"close_session"));
    assert_eq!(backend.sessions_opened(), 2);
    assert_eq!(
        provider.status().token.map(|t| t.label),
        Some("TOK-B".to_string())
    );
}

// ---- TestRecovery ----

#[test]
fn keep_pin_recovers_and_retries_once() {
    let (backend, provider) = new_provider();
    provider
        .login(&token_at(&provider, 0), &pin(USER_PIN), true)
        .unwrap();
    provider.import_key(&aes(), "rec-key", None, None).unwrap();
    backend.invalidate_session(); // token dropped the session
    let found = provider.find_key(&KeySelector::label("rec-key")).unwrap(); // transparently recovered
    assert_eq!(found.key_ref.label, "rec-key");
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
    assert_eq!(backend.sessions_opened(), 2); // a fresh session was opened
}

#[test]
fn without_keep_pin_drops_to_logged_out() {
    let (backend, provider) = logged_in(); // default: no stored PIN
    provider.import_key(&aes(), "rec-key2", None, None).unwrap();
    backend.invalidate_session();
    let err = provider
        .find_key(&KeySelector::label("rec-key2"))
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert_eq!(err.message, "session lost — login again");
    assert_eq!(
        err.hint.as_deref(),
        Some("run `login hsm` (use --keep-pin for auto-reconnect)")
    );
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    assert!(provider.mechanisms().is_empty());
}

#[test]
fn second_failure_drops_even_with_keep_pin() {
    let (backend, provider) = new_provider();
    provider
        .login(&token_at(&provider, 0), &pin(USER_PIN), true)
        .unwrap();
    provider.import_key(&aes(), "rec-key3", None, None).unwrap();
    backend.invalidate_all(); // recovery succeeds, the retry fails
    let err = provider
        .find_key(&KeySelector::label("rec-key3"))
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert_eq!(err.message, "session lost — login again");
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
}

#[test]
fn recovery_fails_when_token_gone() {
    let (backend, provider) = new_provider();
    provider
        .login(&token_at(&provider, 0), &pin(USER_PIN), true)
        .unwrap();
    provider.import_key(&aes(), "rec-key4", None, None).unwrap();
    backend.invalidate_session();
    backend.remove_slot(0); // token pulled
    let err = provider
        .find_key(&KeySelector::label("rec-key4"))
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert_eq!(
        err.message,
        "token 'fake-token' is no longer present — login again"
    );
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
}

#[test]
fn device_removed_is_recoverable_too() {
    let (backend, provider) = new_provider();
    provider
        .login(&token_at(&provider, 0), &pin(USER_PIN), true)
        .unwrap();
    backend.fail_next("find_objects", rv::CKR_DEVICE_REMOVED);
    assert!(provider.list_keys().unwrap().is_empty());
    assert_eq!(backend.sessions_opened(), 2);
}

// ---- TestShutdown ----

#[test]
fn shutdown_clears_everything() {
    let (backend, provider) = new_provider();
    provider
        .login(&token_at(&provider, 0), &pin(USER_PIN), true)
        .unwrap();
    provider.shutdown().unwrap();
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    assert!(!crate::backend::Backend::has_session(backend.as_ref()));
    assert_eq!(backend.load_counts(), (1, 1));
    assert!(!backend.is_logged_in(0));
    provider.shutdown().unwrap(); // idempotent / safe to repeat
    assert_eq!(backend.load_counts(), (1, 1));
}

// ---- TestLoginFailureHygiene ----

#[test]
fn failed_login_closes_fresh_session() {
    let (backend, provider) = new_provider();
    let token = token_at(&provider, 0);
    assert!(provider.login(&token, &pin("9999"), false).is_err());
    // the freshly opened session must not leak on a failed login
    assert_eq!(backend.sessions_opened(), 1);
    assert!(!crate::backend::Backend::has_session(backend.as_ref()));
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    provider.login(&token, &pin(USER_PIN), false).unwrap(); // clean retry
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
}

#[test]
fn mechanism_list_failure_leaves_consistent_state() {
    let (backend, provider) = new_provider();
    let token = token_at(&provider, 0);
    backend.fail_next("mechanism_list", rv::CKR_DEVICE_ERROR);
    let err = provider.login(&token, &pin(USER_PIN), false).unwrap_err();
    assert_eq!(err.ckr().map(|(_, n)| n), Some("CKR_DEVICE_ERROR"));
    // state committed only after the full sequence: still fully logged out
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    assert!(provider.mechanisms().is_empty());
    assert!(!crate::backend::Backend::has_session(backend.as_ref()));
    // retry succeeds (raw CKR_USER_ALREADY_LOGGED_IN from the token is swallowed)
    provider.login(&token, &pin(USER_PIN), false).unwrap();
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
    assert!(!provider.mechanisms().is_empty());
}

// ---- TestInitToken ----

#[test]
fn init_token_pads_label_and_sets_user_pin() {
    let (backend, provider) = new_provider();
    provider
        .init_token(9, "NEWTOK", &pin("4321"), &pin("9876"))
        .unwrap();
    // C_InitToken stored the 32-byte space-padded form...
    assert_eq!(backend.raw_label(9), Some(format!("{:<32}", "NEWTOK")));
    // ...and readback strips the padding to the exact label
    let tokens: Vec<_> = provider
        .list_tokens()
        .unwrap()
        .into_iter()
        .filter(|t| t.label == "NEWTOK")
        .collect();
    assert_eq!(tokens.len(), 1);
    provider.login(&tokens[0], &pin("9876"), false).unwrap(); // C_InitPIN took effect
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
}

#[test]
fn init_token_refuses_labels_over_32_bytes() {
    let (backend, provider) = new_provider();
    let label = "é".repeat(17); // 17 chars, 34 bytes
    let err = TokenInit::init_token(&provider, 9, &label, &pin("4321"), &pin("9876")).unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "label".into()
        }
    );
    assert_eq!(err.message, "token label must be at most 32 bytes");
    assert!(backend.calls().is_empty());
    TokenInit::init_token(&provider, 9, &"x".repeat(32), &pin("4321"), &pin("9876")).unwrap();
}

#[test]
fn init_token_wrong_so_pin_is_translated() {
    let (_backend, provider) = new_provider();
    let err = provider
        .init_token(0, "X", &pin("0000"), &pin("1"))
        .unwrap_err();
    assert_eq!(err.message, "wrong PIN for token '?' (CKR_PIN_INCORRECT)");
}

#[test]
fn init_token_on_a_logged_in_provider_ends_its_login() {
    // §11 D15(c): the SO session replaces the provider's one backend session
    let (backend, provider) = logged_in();
    provider
        .init_token(9, "NEWTOK", &pin("4321"), &pin("9876"))
        .unwrap();
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    assert!(!crate::backend::Backend::has_session(backend.as_ref()));
}

#[test]
fn failed_init_token_keeps_the_provider_session() {
    let (backend, provider) = logged_in();
    assert!(
        provider
            .init_token(9, "NEWTOK", &pin("0000"), &pin("9876"))
            .is_err()
    );
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
    assert!(crate::backend::Backend::has_session(backend.as_ref()));
    provider.list_keys().unwrap();
}

// ---- TokenInit::set_env_and_reset (§5.13 step 2) ----

#[test]
fn set_env_and_reset_applies_env_and_shuts_down() {
    let _lock = r2_testkit::global_state_lock();
    let _guard = r2_testkit::set_env("R2_FAKE_CONF", None);
    let (backend, provider) = logged_in();
    provider
        .set_env_and_reset("R2_FAKE_CONF", "/tmp/x.conf")
        .unwrap();
    assert_eq!(std::env::var("R2_FAKE_CONF").as_deref(), Ok("/tmp/x.conf"));
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    assert_eq!(backend.load_counts(), (1, 1));
    // the next use initializes again
    provider.list_tokens().unwrap();
    assert_eq!(backend.load_counts(), (2, 1));
}

#[test]
fn set_env_and_reset_refuses_a_shared_module() {
    let _lock = r2_testkit::global_state_lock();
    let _guard = r2_testkit::set_env("R2_FAKE_CONF2", None);
    let (backend, provider) = logged_in();
    backend.set_shared(true);
    let err = provider
        .set_env_and_reset("R2_FAKE_CONF2", "/tmp/x.conf")
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Provider);
    assert_eq!(
        err.message,
        "'hsm' shares its PKCS#11 module with another provider"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("restart r2 after the setup, or remove the other provider entry")
    );
    assert!(std::env::var("R2_FAKE_CONF2").is_err()); // nothing changed
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
}

#[test]
fn as_token_init_is_some() {
    let (_backend, provider) = new_provider();
    assert!(provider.as_token_init().is_some());
    assert_eq!(provider.type_name(), "pkcs11");
    assert_eq!(provider.name(), "hsm");
}

#[test]
fn unsettable_env_entries_are_errors_not_panics() {
    // §11 D12(l): std::env::set_var panics on these; c2's os.environ raised ValueError
    // (OSError for the empty name) out of initialize
    let _lock = r2_testkit::global_state_lock();
    let _guard = r2_testkit::set_env("R2_FAKE_OK", None);
    let cases = [
        ("A=B", "x", "illegal environment variable name: 'A=B'"),
        ("", "x", "illegal environment variable name: ''"),
        ("R2_FAKE_NUL", "a\0b", "embedded null byte: 'R2_FAKE_NUL'"),
        ("R2\0X", "x", "embedded null byte: 'R2\\x00X'"),
    ];
    for (key, value, detail) in cases {
        let backend = Rc::new(FakeBackend::new());
        let shared: Rc<dyn crate::backend::Backend> = backend.clone();
        let mut cfg = config("hsm");
        cfg.env.insert("R2_FAKE_OK".into(), "1".into());
        cfg.env.insert(key.into(), value.into());
        let provider = Pkcs11Provider::with_backend(
            "hsm",
            cfg,
            Default::default(),
            Default::default(),
            shared,
        );
        let err = provider.list_tokens().unwrap_err();
        assert_eq!(err.kind, ErrorKind::ProviderUnavailable);
        assert_eq!(
            err.message,
            format!("cannot load PKCS#11 library /fake/libfake.so: {detail}")
        );
        assert_eq!(
            err.hint.as_deref(),
            Some("check providers.pkcs11[].env in the configuration")
        );
        // nothing was set, nothing was loaded
        assert_eq!(std::env::var_os("R2_FAKE_OK"), None);
        assert_eq!(backend.load_counts(), (0, 0));
    }
    let (_backend, provider) = logged_in();
    let err = provider.set_env_and_reset("A=B", "x").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Provider);
    assert_eq!(
        err.message,
        "cannot set environment variable 'A=B': illegal environment variable name"
    );
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
}

// ---- raw CK_TOKEN_INFO decoding (§4.5.5: never cryptoki's get_token_info) ----

fn padded<const N: usize>(text: &str, pad: u8) -> [u8; N] {
    let mut field = [pad; N];
    field[..text.len()].copy_from_slice(text.as_bytes());
    field
}

#[test]
fn raw_token_info_ignores_a_blank_utc_time() {
    // A token with CKF_CLOCK_ON_TOKEN and a blank clock: cryptoki's TokenInfo conversion
    // fails on it (ParseInt), PyKCS11 lists it normally — so must r2.
    let info = cryptoki_sys::CK_TOKEN_INFO {
        label: padded("R2TEST", b' '),
        manufacturerID: padded("SoftHSM project", b' '),
        model: padded("SoftHSM v2\0", b' '),
        serialNumber: padded("fe2447789e9c5c09", b'\0'),
        flags: cryptoki_sys::CKF_CLOCK_ON_TOKEN | cryptoki_sys::CKF_TOKEN_INITIALIZED,
        utcTime: [b' '; 16],
        ..Default::default()
    };
    let raw = crate::backend::raw::decode_token_info(7, &info);
    assert_eq!(raw.slot_id, 7);
    assert_eq!(raw.label, "R2TEST");
    assert_eq!(raw.manufacturer, "SoftHSM project");
    assert_eq!(raw.model, "SoftHSM v2");
    assert_eq!(raw.serial, "fe2447789e9c5c09");
    assert!(raw.initialized);
    let garbage = cryptoki_sys::CK_TOKEN_INFO {
        flags: cryptoki_sys::CKF_CLOCK_ON_TOKEN,
        utcTime: *b"\xffxx-garbage\0\0\0\0\0",
        ..Default::default()
    };
    let raw = crate::backend::raw::decode_token_info(0, &garbage);
    assert!(!raw.initialized);
    assert_eq!(raw.label, "");
    // PyKCS11 decodes the text fields with errors="ignore": invalid bytes are dropped
    // (no U+FFFD), then the padding is trimmed.
    let mut latin1 = cryptoki_sys::CK_TOKEN_INFO {
        flags: cryptoki_sys::CKF_CLOCK_ON_TOKEN | cryptoki_sys::CKF_TOKEN_INITIALIZED,
        utcTime: [b' '; 16],
        ..Default::default()
    };
    latin1.label = [b' '; 32];
    latin1.label[..4].copy_from_slice(b"ab\xffc");
    latin1.manufacturerID = [b' '; 32];
    latin1.manufacturerID[..6].copy_from_slice(b"Caf\xe9 \xe2");
    latin1.model = [b'\0'; 16];
    latin1.model[..3].copy_from_slice(b"m\x80x");
    latin1.serialNumber = [b' '; 16];
    latin1.serialNumber[..3].copy_from_slice(b"\xfe12");
    let raw = crate::backend::raw::decode_token_info(1, &latin1);
    assert_eq!(raw.label, "abc");
    assert_eq!(raw.manufacturer, "Caf");
    assert_eq!(raw.model, "mx");
    assert_eq!(raw.serial, "12");
    assert!(raw.initialized);
}

#[test]
fn empty_pin_is_arguments_bad_not_pin_incorrect() {
    // PyKCS11 sends pPin=NULL for an empty PIN; the token rejects the arguments rather
    // than counting a bad PIN (c2: "PKCS#11 login failed (CKR_ARGUMENTS_BAD)").
    let (_backend, provider) = new_provider();
    let token = token_at(&provider, 0);
    let err = provider.login(&token, &pin(""), false).unwrap_err();
    assert_eq!(err.ckr().map(|(_, n)| n), Some("CKR_ARGUMENTS_BAD"));
    assert_eq!(err.message, "PKCS#11 login failed (CKR_ARGUMENTS_BAD)");
    assert_eq!(provider.status().auth, AuthState::LoggedOut);
    provider.login(&token, &pin(USER_PIN), false).unwrap();
}
