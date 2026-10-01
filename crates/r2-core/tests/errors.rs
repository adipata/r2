//! Error model tests (spec §4.2) — port of c2 `tests/unit/core/test_errors.py`. c2's class
//! hierarchy becomes `ErrorKind` + the family predicates (`isinstance` → `is_provider()` /
//! `is_key_lookup()` / `is_operation()`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::borrow::Cow;

use r2_core::error::{ConsoleError, ErrorKind};
use r2_core::keys::KeyRef;

/// Family of a kind, as c2's direct parent class name.
fn parent(kind: &ErrorKind) -> &'static str {
    if kind.is_provider() && !matches!(kind, ErrorKind::Provider) {
        "ProviderError"
    } else if kind.is_key_lookup() && !matches!(kind, ErrorKind::KeyLookup) {
        "KeyLookupError"
    } else if kind.is_operation() && !matches!(kind, ErrorKind::Operation) {
        "OperationError"
    } else if matches!(kind, ErrorKind::Generic) {
        "Exception"
    } else {
        "ConsoleError"
    }
}

fn every_kind() -> Vec<ErrorKind> {
    vec![
        ErrorKind::Generic,
        ErrorKind::Config,
        ErrorKind::Parse {
            line: String::new(),
            pos: 0,
        },
        ErrorKind::Codec,
        ErrorKind::KeyParse,
        ErrorKind::DataIo,
        ErrorKind::Provider,
        ErrorKind::ProviderUnavailable,
        ErrorKind::ProviderNotFound,
        ErrorKind::AuthRequired,
        ErrorKind::AlreadyLoggedIn,
        ErrorKind::Pkcs11 {
            ckr_code: 0,
            ckr_name: Cow::Borrowed("CKR_OK"),
        },
        ErrorKind::KeyLookup,
        ErrorKind::KeyNotFound,
        ErrorKind::AmbiguousKey { candidates: vec![] },
        ErrorKind::DuplicateKey,
        ErrorKind::KeyNotExportable,
        ErrorKind::Operation,
        ErrorKind::UnknownOperation,
        ErrorKind::UnsupportedOperation,
        ErrorKind::Param {
            param_name: String::new(),
        },
        ErrorKind::Crypto,
        ErrorKind::UserAbort,
    ]
}

/// c2 HIERARCHY (22 parametrizations), plus DuplicateKeyError (a KeyLookupError in c2's
/// errors.py that the c2 table does not list).
#[test]
fn test_hierarchy() {
    let hierarchy: &[(&str, &str)] = &[
        ("ConsoleError", "Exception"),
        ("ConfigError", "ConsoleError"),
        ("ParseError", "ConsoleError"),
        ("CodecError", "ConsoleError"),
        ("KeyParseError", "ConsoleError"),
        ("DataIOError", "ConsoleError"),
        ("ProviderError", "ConsoleError"),
        ("ProviderUnavailableError", "ProviderError"),
        ("ProviderNotFoundError", "ProviderError"),
        ("AuthRequiredError", "ProviderError"),
        ("AlreadyLoggedInError", "ProviderError"),
        ("Pkcs11Error", "ProviderError"),
        ("KeyLookupError", "ConsoleError"),
        ("KeyNotFoundError", "KeyLookupError"),
        ("AmbiguousKeyError", "KeyLookupError"),
        ("KeyNotExportableError", "ConsoleError"),
        ("OperationError", "ConsoleError"),
        ("UnknownOperationError", "OperationError"),
        ("UnsupportedOperationError", "OperationError"),
        ("ParamError", "OperationError"),
        ("CryptoError", "OperationError"),
        ("UserAbort", "ConsoleError"),
        ("DuplicateKeyError", "KeyLookupError"),
    ];
    let kinds = every_kind();
    assert_eq!(kinds.len(), hierarchy.len());
    for (class, expected_parent) in hierarchy {
        let kind = kinds
            .iter()
            .find(|kind| kind.class_name() == *class)
            .unwrap_or_else(|| panic!("no ErrorKind for {class}"));
        assert_eq!(parent(kind), *expected_parent, "{class}");
    }
    // The family predicates are disjoint, and UserAbort is in none of them.
    for kind in &kinds {
        let families = [
            kind.is_provider(),
            kind.is_key_lookup(),
            kind.is_operation(),
        ];
        assert!(families.iter().filter(|f| **f).count() <= 1, "{kind:?}");
        assert_eq!(kind.is_user_abort(), matches!(kind, ErrorKind::UserAbort));
    }
    // The base classes are members of their own family.
    assert!(ErrorKind::Provider.is_provider());
    assert!(ErrorKind::KeyLookup.is_key_lookup());
    assert!(ErrorKind::Operation.is_operation());
    assert!(!ErrorKind::KeyNotExportable.is_key_lookup());
}

#[test]
fn test_console_error_message_and_hint() {
    let err = ConsoleError::generic("boom").with_hint("try again");
    assert_eq!(err.message, "boom");
    assert_eq!(err.hint.as_deref(), Some("try again"));
    assert_eq!(err.to_string(), "boom");
}

#[test]
fn test_console_error_hint_defaults_to_none() {
    let err = ConsoleError::config("bad config");
    assert_eq!(err.message, "bad config");
    assert_eq!(err.hint, None);
    assert_eq!(err.kind, ErrorKind::Config);
}

#[test]
fn test_parse_error_extras() {
    let err = ConsoleError::parse("bad token", "foo bar", 4).with_hint("quote it");
    assert_eq!(err.parse_position(), Some(("foo bar", 4)));
    assert_eq!(
        err.kind,
        ErrorKind::Parse {
            line: "foo bar".to_owned(),
            pos: 4
        }
    );
    assert_eq!(err.message, "bad token");
    assert_eq!(err.hint.as_deref(), Some("quote it"));
}

#[test]
fn test_pkcs11_error_extras() {
    let err = ConsoleError::pkcs11("pin wrong", 0xA0, "CKR_PIN_INCORRECT");
    assert_eq!(err.ckr(), Some((0xA0, "CKR_PIN_INCORRECT")));
    assert!(err.kind.is_provider());
    assert_eq!(err.kind.class_name(), "Pkcs11Error");
    let owned = ConsoleError::pkcs11("x", 0x8000_0001, format!("CKR_0x{:08X}", 0x8000_0001u64));
    assert_eq!(owned.ckr(), Some((0x8000_0001, "CKR_0x80000001")));
}

#[test]
fn test_ambiguous_key_error_extras() {
    let candidates = vec![
        KeyRef::new("hsm", "k", Some(vec![0x01])),
        KeyRef::new("hsm", "k", Some(vec![0x02])),
    ];
    let err = ConsoleError::ambiguous_key("ambiguous", candidates.clone());
    assert_eq!(err.candidates(), Some(candidates.as_slice()));
    assert!(err.kind.is_key_lookup());
}

#[test]
fn test_param_error_extras() {
    let err = ConsoleError::param("bad iv", "iv").with_hint("16 bytes");
    assert_eq!(err.param_name(), Some("iv"));
    assert!(err.kind.is_operation());
    assert_eq!(err.hint.as_deref(), Some("16 bytes"));
}

#[test]
fn test_everything_catchable_as_console_error() {
    // Every error is a ConsoleError by type; the kind carries the c2 class.
    let abort = ConsoleError::user_abort("aborted");
    assert_eq!(abort.kind.class_name(), "UserAbort");
    assert!(abort.kind.is_user_abort());
    let pkcs11 = ConsoleError::pkcs11("x", 5, "CKR_GENERAL_ERROR");
    assert_eq!(pkcs11.kind.class_name(), "Pkcs11Error");
    let as_std: &dyn std::error::Error = &pkcs11;
    assert_eq!(as_std.to_string(), "x");
}

/// r2: every per-kind constructor builds its kind with no hint; accessors are None for
/// kinds that do not carry the field.
#[test]
fn constructors_build_their_kind_and_accessors_are_kind_specific() {
    let cases: Vec<(ConsoleError, &str)> = vec![
        (ConsoleError::generic("m"), "ConsoleError"),
        (ConsoleError::config("m"), "ConfigError"),
        (ConsoleError::parse("m", "l", 1), "ParseError"),
        (ConsoleError::codec("m"), "CodecError"),
        (ConsoleError::key_parse("m"), "KeyParseError"),
        (ConsoleError::data_io("m"), "DataIOError"),
        (ConsoleError::provider("m"), "ProviderError"),
        (
            ConsoleError::provider_unavailable("m"),
            "ProviderUnavailableError",
        ),
        (
            ConsoleError::provider_not_found("m"),
            "ProviderNotFoundError",
        ),
        (ConsoleError::auth_required("m"), "AuthRequiredError"),
        (ConsoleError::already_logged_in("m"), "AlreadyLoggedInError"),
        (ConsoleError::pkcs11("m", 1, "CKR_CANCEL"), "Pkcs11Error"),
        (ConsoleError::key_lookup("m"), "KeyLookupError"),
        (ConsoleError::key_not_found("m"), "KeyNotFoundError"),
        (
            ConsoleError::ambiguous_key("m", vec![]),
            "AmbiguousKeyError",
        ),
        (ConsoleError::duplicate_key("m"), "DuplicateKeyError"),
        (
            ConsoleError::key_not_exportable("m"),
            "KeyNotExportableError",
        ),
        (ConsoleError::operation("m"), "OperationError"),
        (
            ConsoleError::unknown_operation("m"),
            "UnknownOperationError",
        ),
        (ConsoleError::unsupported("m"), "UnsupportedOperationError"),
        (ConsoleError::param("m", "p"), "ParamError"),
        (ConsoleError::crypto("m"), "CryptoError"),
        (ConsoleError::user_abort("m"), "UserAbort"),
    ];
    for (err, class) in &cases {
        assert_eq!(err.kind.class_name(), *class);
        assert_eq!(err.message, "m");
        assert_eq!(err.hint, None);
        assert_eq!(err.param_name().is_some(), *class == "ParamError");
        assert_eq!(err.ckr().is_some(), *class == "Pkcs11Error");
        assert_eq!(err.candidates().is_some(), *class == "AmbiguousKeyError");
        assert_eq!(err.parse_position().is_some(), *class == "ParseError");
    }
    let err = ConsoleError::new(ErrorKind::Crypto, "x").with_hint_opt(Some("h".to_owned()));
    assert_eq!(err.hint.as_deref(), Some("h"));
    assert_eq!(err.with_hint_opt(None).hint, None);
}
