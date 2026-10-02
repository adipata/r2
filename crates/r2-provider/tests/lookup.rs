// Shared lookup helpers (spec §4.5.3: matches_selector, select_match, duplicate_identity) —
// R3. c2 implemented these inside each provider's find_key / twin guard; the texts are
// c2's (memory.py / provider.py / fake_provider.py).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]
use std::collections::BTreeMap;

use r2_core::error::ErrorKind;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyRef};
use r2_provider::KeySelector;
use r2_provider::lookup::{CLASS_PREFERENCE, duplicate_identity, matches_selector, select_match};

fn info(label: &str, key_id: Option<&[u8]>, key_class: KeyClass, handle: u64) -> KeyInfo {
    KeyInfo {
        key_ref: KeyRef::new("p", label, key_id.map(<[u8]>::to_vec)),
        key_class,
        algorithm: KeyAlgorithm::Rsa,
        size_bits: None,
        curve: None,
        exportable: true,
        attributes: BTreeMap::new(),
        handle: Some(handle),
    }
}

#[test]
fn class_preference_order() {
    assert_eq!(
        CLASS_PREFERENCE,
        [
            KeyClass::Private,
            KeyClass::Secret,
            KeyClass::Public,
            KeyClass::Certificate,
            KeyClass::Data
        ]
    );
}

#[test]
fn matches_selector_filters() {
    let key = info("k", Some(b"\x01"), KeyClass::Public, 7);
    assert!(matches_selector(&key, &KeySelector::label("k")));
    assert!(!matches_selector(&key, &KeySelector::label("K")));
    assert!(matches_selector(
        &key,
        &KeySelector::label("k").with_id(Some(vec![1]))
    ));
    assert!(!matches_selector(
        &key,
        &KeySelector::label("k").with_id(Some(vec![2]))
    ));
    assert!(matches_selector(
        &key,
        &KeySelector::label("k").with_class(Some(KeyClass::Public))
    ));
    assert!(!matches_selector(
        &key,
        &KeySelector::label("k").with_class(Some(KeyClass::Private))
    ));
    assert!(matches_selector(
        &key,
        &KeySelector::label("k").with_handle(Some(7))
    ));
    assert!(!matches_selector(
        &key,
        &KeySelector::label("k").with_handle(Some(8))
    ));
    // a key without an id never matches an id selector
    let no_id = info("k", None, KeyClass::Public, 1);
    assert!(!matches_selector(
        &no_id,
        &KeySelector::label("k").with_id(Some(vec![1]))
    ));
}

#[test]
fn not_found_texts() {
    let err = select_match("prov", &KeySelector::label("x"), Vec::new()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotFound);
    assert_eq!(err.message, "no key 'x' on provider prov");
    let selector = KeySelector::label("x").with_class(Some(KeyClass::Certificate));
    let err = select_match("prov", &selector, Vec::new()).unwrap_err();
    assert_eq!(err.message, "no certificate key 'x' on provider prov");
}

#[test]
fn single_match_and_family_collapse() {
    let only = info("k", None, KeyClass::Secret, 1);
    assert_eq!(
        select_match("p", &KeySelector::label("k"), vec![only.clone()]).unwrap(),
        only
    );
    // keypair + certificate sharing one id: private preferred regardless of order
    let family = vec![
        info("k", Some(b"\x01"), KeyClass::Certificate, 1),
        info("k", Some(b"\x01"), KeyClass::Public, 2),
        info("k", Some(b"\x01"), KeyClass::Private, 3),
    ];
    let found = select_match("p", &KeySelector::label("k"), family.clone()).unwrap();
    assert_eq!(found.handle, Some(3));
    // public + certificate only: public preferred
    let found = select_match("p", &KeySelector::label("k"), family[..2].to_vec()).unwrap();
    assert_eq!(found.key_class, KeyClass::Public);
}

#[test]
fn ambiguity_rules() {
    // distinct ids → ambiguous even with distinct classes
    let mixed = vec![
        info("k", Some(b"\x01"), KeyClass::Private, 1),
        info("k", Some(b"\x02"), KeyClass::Public, 2),
    ];
    let err = select_match("p", &KeySelector::label("k"), mixed).unwrap_err();
    assert!(matches!(err.kind, ErrorKind::AmbiguousKey { .. }));
    assert_eq!(err.message, "'k' matches 2 keys on p: p:k#01, p:k#02");
    assert_eq!(
        err.candidates().unwrap(),
        [
            KeyRef::new("p", "k", Some(vec![1])),
            KeyRef::new("p", "k", Some(vec![2]))
        ]
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("disambiguate with label#id, a :priv/:pub/:cert/:secret/:data suffix, or @handle")
    );
    // same class, same (absent) id → ambiguous; display_refs adds class then handle
    let twins = vec![
        info("k", None, KeyClass::Secret, 4),
        info("k", None, KeyClass::Secret, 9),
    ];
    let err = select_match("p", &KeySelector::label("k"), twins).unwrap_err();
    assert_eq!(
        err.message,
        "'k' matches 2 keys on p: p:k:secret@4, p:k:secret@9"
    );
    // a class selector disables the collapse (several matches of that class stay ambiguous)
    let pair = vec![
        info("k", Some(b"\x01"), KeyClass::Private, 1),
        info("k", Some(b"\x01"), KeyClass::Public, 2),
    ];
    let selector = KeySelector::label("k").with_class(Some(KeyClass::Private));
    let err = select_match("p", &selector, pair).unwrap_err();
    assert_eq!(
        err.message,
        "'k' matches 2 keys on p: p:k#01:priv, p:k#01:pub"
    );
}

#[test]
fn duplicate_identity_texts() {
    let err = duplicate_identity("mem", KeyClass::Secret, "k", Some(b"\x0a\xff"), false);
    assert_eq!(err.kind, ErrorKind::DuplicateKey);
    assert_eq!(
        err.message,
        "a secret object with label 'k' and id 0x0aff already exists on mem"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("pick a different --id or label, or delete the existing object first")
    );
    let err = duplicate_identity("hsm", KeyClass::Data, "d", None, true);
    assert_eq!(
        err.message,
        "a data object with label 'd' and no id already exists on hsm"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("pick a different id or label, or delete the existing object first")
    );
}
