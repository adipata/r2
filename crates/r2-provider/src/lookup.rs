// Shared find/twin rules for every provider (memory, pkcs11, FakeProvider) — spec §4.5.3,
// a port of the lookup logic c2 duplicated in each provider's `find_key`.
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{KeyClass, KeyInfo, display_refs};

use crate::types::KeySelector;

/// Family collapse preference.
pub const CLASS_PREFERENCE: [KeyClass; 5] = [
    KeyClass::Private,
    KeyClass::Secret,
    KeyClass::Public,
    KeyClass::Certificate,
    KeyClass::Data,
];

const AMBIGUOUS_HINT: &str =
    "disambiguate with label#id, a :priv/:pub/:cert/:secret/:data suffix, or @handle";

/// True when `info` matches label, and key_id/key_class/handle when given.
pub fn matches_selector(info: &KeyInfo, selector: &KeySelector) -> bool {
    info.key_ref.label == selector.label
        && selector
            .key_id
            .as_ref()
            .is_none_or(|id| info.key_ref.key_id.as_ref() == Some(id))
        && selector
            .key_class
            .is_none_or(|class| info.key_class == class)
        && selector
            .handle
            .is_none_or(|handle| info.handle == Some(handle))
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
    let mut matches = matches;
    match matches.len() {
        0 => {
            let wanted = selector
                .key_class
                .map(|class| format!("{} ", class.as_str()))
                .unwrap_or_default();
            return Err(ConsoleError::key_not_found(format!(
                "no {wanted}key '{}' on provider {provider}",
                selector.label
            )));
        }
        1 => return Ok(matches.remove(0)),
        _ => {}
    }
    if selector.key_class.is_none() {
        let first_id = &matches[0].key_ref.key_id;
        let one_id = matches.iter().all(|info| &info.key_ref.key_id == first_id);
        let distinct_classes = matches.iter().enumerate().all(|(i, info)| {
            matches[..i]
                .iter()
                .all(|other| other.key_class != info.key_class)
        });
        if one_id && distinct_classes {
            for preferred in CLASS_PREFERENCE {
                if let Some(pos) = matches.iter().position(|info| info.key_class == preferred) {
                    return Ok(matches.swap_remove(pos));
                }
            }
        }
    }
    let shown = display_refs(&matches).join(", ");
    let candidates = matches.iter().map(|info| info.key_ref.clone()).collect();
    Err(ConsoleError::ambiguous_key(
        format!(
            "'{}' matches {} keys on {provider}: {shown}",
            selector.label,
            matches.len()
        ),
        candidates,
    )
    .with_hint(AMBIGUOUS_HINT))
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
    let shown = match key_id {
        Some(id) => format!("id 0x{}", hex_lower(id)),
        None => "no id".to_owned(),
    };
    let hint = if rename {
        "pick a different id or label, or delete the existing object first"
    } else {
        "pick a different --id or label, or delete the existing object first"
    };
    ConsoleError::duplicate_key(format!(
        "a {} object with label '{label}' and {shown} already exists on {provider}",
        key_class.as_str()
    ))
    .with_hint(hint)
}

fn hex_lower(data: &[u8]) -> String {
    use std::fmt::Write;
    data.iter()
        .fold(String::with_capacity(data.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}
