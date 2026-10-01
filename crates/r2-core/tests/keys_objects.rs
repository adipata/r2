//! Key-model additions of c2 L16 (spec §4.3) — port of c2
//! `tests/unit/core/test_keys_objects.py`: the DATA class/selector and the
//! generic/none/other algorithm members (ref grammar, tokens, listing display).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::BTreeMap;

use r2_core::keys::{
    CLASS_SELECTORS, KeyAlgorithm, KeyClass, KeyInfo, KeyRef, class_selector, display_refs,
    parse_ref,
};

fn info(label: &str, key_class: KeyClass, algorithm: KeyAlgorithm) -> KeyInfo {
    KeyInfo {
        key_ref: KeyRef::new("p", label, None),
        key_class,
        algorithm,
        size_bits: None,
        curve: None,
        exportable: true,
        attributes: BTreeMap::new(),
        handle: None,
    }
}

#[test]
fn test_data_selector_parses_case_insensitively() {
    let parsed = parse_ref("p:blob:data").unwrap();
    assert_eq!(parsed.provider, "p");
    assert_eq!(parsed.label, "blob");
    assert_eq!(parsed.key_id, None);
    assert_eq!(parsed.key_class, Some(KeyClass::Data));
    assert_eq!(
        parse_ref("p:blob:DATA").unwrap().key_class,
        Some(KeyClass::Data)
    );
    // the selector also composes with the other stages
    let parsed = parse_ref("p:blob:data@7").unwrap();
    assert_eq!(parsed.key_class, Some(KeyClass::Data));
    assert_eq!(parsed.handle, Some(7));
}

#[test]
fn test_class_tokens_and_selectors_cover_every_class() {
    // CLASS_TOKENS → KeyClass::token(): one token per class.
    let tokens: Vec<&str> = KeyClass::ALL.iter().map(|c| c.token()).collect();
    assert_eq!(tokens, ["secret", "priv", "pub", "cert", "data"]);
    assert_eq!(KeyClass::Data.token(), "data");
    assert_eq!(class_selector("data"), Some(KeyClass::Data));
    for key_class in KeyClass::ALL {
        assert_eq!(class_selector(key_class.token()), Some(key_class));
    }
    // CLASS_SELECTORS: c2's order and long forms; lookups are case-insensitive.
    let names: Vec<&str> = CLASS_SELECTORS.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names,
        [
            "priv",
            "private",
            "pub",
            "public",
            "cert",
            "certificate",
            "secret",
            "data"
        ]
    );
    for (name, key_class) in CLASS_SELECTORS {
        assert_eq!(class_selector(name), Some(key_class));
        assert_eq!(class_selector(&name.to_uppercase()), Some(key_class));
    }
    assert_eq!(class_selector("Certificate"), Some(KeyClass::Certificate));
    assert_eq!(class_selector("frob"), None);
    assert_eq!(class_selector(""), None);
}

#[test]
fn test_display_refs_suffixes_data_objects_on_collision() {
    let infos = [
        info("x", KeyClass::Secret, KeyAlgorithm::Aes),
        info("x", KeyClass::Data, KeyAlgorithm::None),
    ];
    let shown = display_refs(&infos);
    assert_eq!(shown, ["p:x:secret", "p:x:data"]);
    for text in &shown {
        parse_ref(text).unwrap(); // every emitted form parses (§4.3)
    }
    assert_eq!(
        display_refs(&[info("lonely", KeyClass::Data, KeyAlgorithm::None)]),
        ["p:lonely"]
    );
}

#[test]
fn test_new_algorithm_members() {
    assert_eq!(KeyAlgorithm::Generic.as_str(), "generic");
    assert_eq!(KeyAlgorithm::None.as_str(), "none");
    assert_eq!(KeyAlgorithm::Other.as_str(), "other");
    assert_eq!(KeyClass::Data.as_str(), "data");
}
