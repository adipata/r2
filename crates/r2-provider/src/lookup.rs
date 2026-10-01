// R0 skeleton — owner R3 (generated from spec §4)
// ---- spec §4.5.3 block 1
// provider (memory, pkcs11, FakeProvider)
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{KeyClass, KeyInfo};

use crate::types::KeySelector;

/// Family collapse preference.
pub const CLASS_PREFERENCE: [KeyClass; 5] = [
    KeyClass::Private,
    KeyClass::Secret,
    KeyClass::Public,
    KeyClass::Certificate,
    KeyClass::Data,
];

/// True when `info` matches label, and key_id/key_class/handle when given.
pub fn matches_selector(info: &KeyInfo, selector: &KeySelector) -> bool {
    let _ = (info, selector);
    unimplemented!("R3")
}

/// Pick the result of find_key from the matches (provider order). 0 matches → KeyNotFound
/// "no {class }key '{label}' on provider {provider}" ("{class} " = `key_class.as_str()`
/// plus a space when a class selector was given, else empty). 1 match → it. Several: when
/// `selector.key_class` is None AND all matches share one key_id AND their classes are
/// pairwise distinct (a keypair / key+certificate family) → the first match in
/// CLASS_PREFERENCE order; otherwise AmbiguousKey "'{label}' matches {n} keys on
/// {provider}: {display_refs(matches) joined ', '}" with candidates = their refs and hint
/// "disambiguate with label#id, a :priv/:pub/:cert/:secret/:data suffix, or @handle".
pub fn select_match(
    provider: &str,
    selector: &KeySelector,
    matches: Vec<KeyInfo>,
) -> Result<KeyInfo> {
    let _ = (provider, selector, matches);
    Err(r2_core::ConsoleError::not_implemented("R3"))
}

/// The §4.7 duplicate-identity error: DuplicateKey "a {class} object with label '{label}'
/// and {shown} already exists on {provider}" where shown = "id 0x{hex}" or "no id"; hint
/// "pick a different --id or label, or delete the existing object first" (create flows) or
/// "pick a different id or label, or delete the existing object first" (rename = true).
pub fn duplicate_identity(
    provider: &str,
    key_class: KeyClass,
    label: &str,
    key_id: Option<&[u8]>,
    rename: bool,
) -> ConsoleError {
    let _ = (provider, key_class, label, key_id, rename);
    unimplemented!("R3")
}
