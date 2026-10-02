// Typed path-aware decoder (spec §4.8.3; owner R2). R2-internal: the c2 `_as_*`/`_req`/
// `_warn_unknown` helpers of `config/model.py`, every message c2-verbatim.
use std::path::PathBuf;

use r2_core::error::{ConsoleError, Result};
use r2_core::template::AttrValue;
use r2_core::text::{close_matches, py_fromhex, py_repr};

use crate::dirs::expand_user;
use crate::yaml::{Mapping, Value, as_int, py_value_repr, python_type_name};

/// c2 `_join`: "{path}.{key}", or `key` at the root.
pub(crate) fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

/// c2 `_fail`: Config "{path}: {problem}".
pub(crate) fn fail(path: &str, problem: impl AsRef<str>) -> ConsoleError {
    ConsoleError::config(format!("{path}: {}", problem.as_ref()))
}

/// c2 `_warn_unknown`: every key not in `known` is logged (never printed) with a
/// difflib suggestion. The caller has checked that keys are strings.
pub(crate) fn warn_unknown(data: &Mapping, known: &[&str], path: &str, what: &str) {
    for key in data.keys() {
        let Value::String(key) = key else {
            continue;
        };
        if known.contains(&key.as_str()) {
            continue;
        }
        let suggestion = close_matches(key, known, 1)
            .first()
            .map(|m| format!(" (did you mean {}?)", py_repr(m)))
            .unwrap_or_default();
        tracing::warn!(
            target: "r2::config",
            "unknown {what} {}{suggestion}",
            py_repr(&join(path, key))
        );
    }
}

/// c2 `_as_mapping`: a mapping whose keys are all strings.
pub(crate) fn as_mapping<'a>(value: &'a Value, path: &str) -> Result<&'a Mapping> {
    let Value::Mapping(map) = value else {
        return Err(fail(
            path,
            format!("expected a mapping, got {}", python_type_name(value)),
        ));
    };
    for key in map.keys() {
        if !matches!(key, Value::String(_)) {
            return Err(fail(
                path,
                format!("mapping keys must be strings, got {}", py_value_repr(key)),
            ));
        }
    }
    Ok(map)
}

pub(crate) fn as_list<'a>(value: &'a Value, path: &str) -> Result<&'a [Value]> {
    match value {
        Value::Sequence(items) => Ok(items),
        other => Err(fail(
            path,
            format!("expected a list, got {}", python_type_name(other)),
        )),
    }
}

pub(crate) fn as_str<'a>(value: &'a Value, path: &str) -> Result<&'a str> {
    match value {
        Value::String(text) => Ok(text),
        other => Err(fail(
            path,
            format!("expected a string, got {}", python_type_name(other)),
        )),
    }
}

pub(crate) fn as_bool(value: &Value, path: &str) -> Result<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        other => Err(fail(
            path,
            format!("expected a boolean, got {}", python_type_name(other)),
        )),
    }
}

pub(crate) fn as_int_at(value: &Value, path: &str) -> Result<i128> {
    as_int(value).ok_or_else(|| {
        fail(
            path,
            format!("expected an integer, got {}", python_type_name(value)),
        )
    })
}

/// An integer that must not be negative (c2 "must not be negative"), converted into the
/// field's unsigned type; a value above that type's range → "must be at most {max}"
/// (r2 addition, §11 D18).
pub(crate) fn non_negative<T: TryFrom<i128> + std::fmt::Display + Copy>(
    value: &Value,
    path: &str,
    max: T,
) -> Result<T> {
    let v = as_int_at(value, path)?;
    if v < 0 {
        return Err(fail(path, "must not be negative"));
    }
    T::try_from(v).map_err(|_| fail(path, format!("must be at most {max}")))
}

/// c2 `_as_path` = `Path(_as_str(v)).expanduser()`.
pub(crate) fn as_path(value: &Value, path: &str) -> Result<PathBuf> {
    Ok(expand_user(as_str(value, path)?))
}

/// c2 `_req`: "{path}.{key}: required key missing".
pub(crate) fn req<'a>(data: &'a Mapping, key: &str, path: &str) -> Result<&'a Value> {
    data.get(key)
        .ok_or_else(|| fail(&join(path, key), "required key missing"))
}

/// c2 `data.get(key)`: None when the key is absent or its value is null.
pub(crate) fn get<'a>(data: &'a Mapping, key: &str) -> Option<&'a Value> {
    data.get(key).filter(|v| !v.is_null())
}

/// c2 `_req_map`.
pub(crate) fn req_map<'a>(data: &'a Mapping, key: &str, path: &str) -> Result<&'a Mapping> {
    as_mapping(req(data, key, path)?, &join(path, key))
}

/// c2 `_enum_of`: "invalid value {text!r}" (hint "valid values: …").
pub(crate) fn enum_of<'a>(value: &'a Value, path: &str, choices: &[&str]) -> Result<&'a str> {
    let text = as_str(value, path)?;
    if !choices.contains(&text) {
        return Err(fail(path, format!("invalid value {}", py_repr(text)))
            .with_hint(format!("valid values: {}", choices.join(", "))));
    }
    Ok(text)
}

/// c2 `_IDENT_RE` = `[A-Za-z_][A-Za-z0-9_-]*\Z`.
pub(crate) fn is_ident(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// c2 `_check_ident`.
pub(crate) fn check_ident(name: &str, path: &str) -> Result<()> {
    if is_ident(name) {
        Ok(())
    } else {
        Err(
            fail(path, format!("invalid provider name {}", py_repr(name)))
                .with_hint("provider names match [A-Za-z_][A-Za-z0-9_-]*"),
        )
    }
}

/// c2 `_build_template_attr` (the §4.7 kind-inference rule): bool → Bool, int → Ulong
/// (negative → "must not be negative", r2 §11 D18), "0x…" → Bytes, other string → Str.
pub(crate) fn template_value(raw: &Value, path: &str) -> Result<AttrValue> {
    match raw {
        Value::Bool(b) => Ok(AttrValue::Bool(*b)),
        Value::Number(_) if as_int(raw).is_some() => {
            let value = as_int(raw).unwrap_or_default();
            u64::try_from(value)
                .map(AttrValue::Ulong)
                .map_err(|_| fail(path, "must not be negative"))
        }
        Value::String(text) => match text.strip_prefix("0x") {
            Some(hex) => py_fromhex(hex).map(AttrValue::Bytes).ok_or_else(|| {
                fail(path, format!("invalid hex bytes {}", py_repr(text)))
                    .with_hint("0x… values hold whole hex bytes")
            }),
            None => Ok(AttrValue::Str(text.clone())),
        },
        other => Err(fail(
            path,
            format!(
                "template attribute values must be bool, int or string, got {}",
                python_type_name(other)
            ),
        )
        .with_hint("bool → BOOL, int → ULONG, \"0x…\" → BYTES, other string → STR (§4.7)")),
    }
}
