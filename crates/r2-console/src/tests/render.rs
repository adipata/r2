// Console render helpers — the console's case of c2 tests/unit/console/test_render.py (R7;
// the renderer cases moved to R1) plus the shared `keys`-table cell texts.
use std::collections::BTreeMap;

use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyRef};

use crate::render::{algo_text, class_text, suggest};

#[test]
fn test_suggest_close_match_and_none() {
    let hint = suggest("helpp", &["help", "exit", "quit"]).unwrap();
    assert!(hint.contains("help"));
    assert!(hint.starts_with("did you mean: "));
    assert_eq!(hint, "did you mean: help");
    assert_eq!(suggest("zzzzzz", &["help", "exit"]), None);
}

#[test]
fn suggest_takes_three_matches_in_difflib_order() {
    // CPython difflib.get_close_matches over the sorted command names (§4.2 vectors)
    let names = [
        "clear",
        "config",
        "copy",
        "csr",
        "decrypt",
        "delete",
        "derive",
        "encrypt",
        "exit",
        "export",
        "generate",
        "help",
        "key",
        "keys",
        "load",
        "login",
        "logout",
        "ops",
        "providers",
        "quit",
        "sign",
        "slots",
        "verify",
    ];
    assert_eq!(
        suggest("decrept", &names).as_deref(),
        Some("did you mean: decrypt, encrypt, derive")
    );
    assert_eq!(
        suggest("aecrypt", &names).as_deref(),
        Some("did you mean: encrypt, decrypt")
    );
    assert_eq!(
        suggest("cps", &names).as_deref(),
        Some("did you mean: ops, csr")
    );
}

fn info(key_class: KeyClass, algorithm: KeyAlgorithm) -> KeyInfo {
    KeyInfo {
        key_ref: KeyRef::new("mem", "k", None),
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
fn keys_table_cells() {
    assert_eq!(class_text(KeyClass::Certificate), "cert");
    assert_eq!(class_text(KeyClass::Private), "private");
    assert_eq!(class_text(KeyClass::Public), "public");
    assert_eq!(class_text(KeyClass::Secret), "secret");
    assert_eq!(class_text(KeyClass::Data), "data");
    assert_eq!(algo_text(&info(KeyClass::Data, KeyAlgorithm::None)), "-");
    assert_eq!(
        algo_text(&info(KeyClass::Secret, KeyAlgorithm::Generic)),
        "generic"
    );
    assert_eq!(
        algo_text(&info(KeyClass::Private, KeyAlgorithm::EcEdwards)),
        "ec-edwards"
    );
    assert_eq!(
        algo_text(&info(KeyClass::Private, KeyAlgorithm::Other)),
        "other"
    );
}
