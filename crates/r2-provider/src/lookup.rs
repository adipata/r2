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
/// pairwise distinct (a keypair / key+certificate family) and no Secret match sits beside
/// a Private, Public or Certificate one (that is two keys, r2 addition) → the first match
/// in CLASS_PREFERENCE order; otherwise AmbiguousKey "'{label}' matches {n} keys on
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
        // a secret key is never one key with a private/public key or a certificate:
        // the same label on both is two keys, and picking one would be a silent guess
        let has = |class: KeyClass| matches.iter().any(|info| info.key_class == class);
        let secret_with_asymmetric = has(KeyClass::Secret)
            && (has(KeyClass::Private) || has(KeyClass::Public) || has(KeyClass::Certificate));
        if one_id && distinct_classes && !secret_with_asymmetric {
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

/// `Provider::find_objects(query)` for a lookup around a known object, `anchor` (§5.19).
/// The targeted search matches CKA_LABEL byte for byte, while a KeyInfo label is decoded
/// (invalid UTF-8 dropped, a missing CKA_LABEL read as ""), so it can miss objects the old
/// list-and-compare lookup found. When the query asks for the empty label, or the search
/// does not return the anchor although it matches the query, this falls back to
/// `list_keys` filtered by the query, exactly the old behavior.
pub fn find_related(
    provider: &dyn crate::provider::Provider,
    query: &crate::types::ObjectQuery,
    anchor: &KeyInfo,
) -> Result<Vec<KeyInfo>> {
    if query.label.as_deref() != Some("") {
        let found = provider.find_objects(query)?;
        let misses_anchor = anchor.handle.is_some()
            && query.matches(anchor)
            && !found.iter().any(|info| info.handle == anchor.handle);
        if !misses_anchor {
            return Ok(found);
        }
    }
    Ok(provider
        .list_keys()?
        .into_iter()
        .filter(|info| query.matches(info))
        .collect())
}

/// The objects of `classes` that share `key`'s CKA_ID (when it has one) or its label — the
/// candidates for a key's public half / certificate / siblings — found with targeted
/// searches (`Provider::find_objects`, §5.19) instead of a whole-token listing. Order: the
/// id matches, then the label matches (each in `list_keys` order), without duplicates.
pub fn family_candidates(
    provider: &dyn crate::provider::Provider,
    key: &KeyInfo,
    classes: &[KeyClass],
) -> Result<Vec<KeyInfo>> {
    let mut found: Vec<KeyInfo> = Vec::new();
    let mut queries = Vec::new();
    if let Some(id) = &key.key_ref.key_id {
        queries.push(crate::types::ObjectQuery::id(id.clone()));
    }
    queries.push(crate::types::ObjectQuery::label(key.key_ref.label.clone()));
    for query in queries {
        for info in find_related(provider, &query, key)? {
            if !classes.contains(&info.key_class) {
                continue;
            }
            let duplicate = found.iter().any(|seen| {
                seen.key_class == info.key_class
                    && seen.handle == info.handle
                    && seen.key_ref == info.key_ref
            });
            if !duplicate {
                found.push(info);
            }
        }
    }
    Ok(found)
}
