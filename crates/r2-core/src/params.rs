// Core parameter types (spec §4.6.1; owner R1).
use crate::error::{ConsoleError, Result};
use crate::keys::KeyInfo;
use crate::text::{py_bool, py_bytes_repr, py_int, py_repr};
use indexmap::IndexMap;
use std::fmt;
use std::str::FromStr;

/// Token: "encrypt" | "decrypt" | "sign" | "verify" | "derive".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Verb {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Derive,
}
impl Verb {
    pub const ALL: [Verb; 5] = [
        Verb::Encrypt,
        Verb::Decrypt,
        Verb::Sign,
        Verb::Verify,
        Verb::Derive,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Verb::Encrypt => "encrypt",
            Verb::Decrypt => "decrypt",
            Verb::Sign => "sign",
            Verb::Verify => "verify",
            Verb::Derive => "derive",
        }
    }
}

/// Token: "bytes" | "int" | "str" | "bool" | "enum" | "keyref".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParamKind {
    /// hex/base64 via decode_data; "0x…" accepted.
    Bytes,
    /// Decimal digits with an optional leading '-' only (no "max" tokens; sentinels such as
    /// salt_len=-1 are documented per param).
    Int,
    Str,
    /// true/false/yes/no/on/off/1/0, case-insensitive.
    Bool,
    /// `choices` required.
    Enum,
    /// Full §4.3 ref grammar, resolved via ProviderRegistry to the target's KeyInfo.
    KeyRef,
}
impl ParamKind {
    /// Declaration order (c2 enum order) — the FromStr search space.
    const ALL: [ParamKind; 6] = [
        ParamKind::Bytes,
        ParamKind::Int,
        ParamKind::Str,
        ParamKind::Bool,
        ParamKind::Enum,
        ParamKind::KeyRef,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            ParamKind::Bytes => "bytes",
            ParamKind::Int => "int",
            ParamKind::Str => "str",
            ParamKind::Bool => "bool",
            ParamKind::Enum => "enum",
            ParamKind::KeyRef => "keyref",
        }
    }
}

/// Custom-mechanism parameter packer selector. Token: "none" | "iv" | "gcm" | "oaep" | "raw".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ParamStruct {
    #[default]
    None,
    Iv,
    Gcm,
    Oaep,
    Raw,
}
impl ParamStruct {
    /// Declaration order — the FromStr search space.
    const ALL: [ParamStruct; 5] = [
        ParamStruct::None,
        ParamStruct::Iv,
        ParamStruct::Gcm,
        ParamStruct::Oaep,
        ParamStruct::Raw,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            ParamStruct::None => "none",
            ParamStruct::Iv => "iv",
            ParamStruct::Gcm => "gcm",
            ParamStruct::Oaep => "oaep",
            ParamStruct::Raw => "raw",
        }
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Exact tokens; else Generic "unknown verb {s!r}".
impl FromStr for Verb {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        Verb::ALL
            .into_iter()
            .find(|value| value.as_str() == s)
            .ok_or_else(|| ConsoleError::generic(format!("unknown verb {}", py_repr(s))))
    }
}
impl fmt::Display for ParamKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Exact tokens; else Generic "unknown parameter kind {s!r}".
impl FromStr for ParamKind {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        ParamKind::ALL
            .into_iter()
            .find(|value| value.as_str() == s)
            .ok_or_else(|| ConsoleError::generic(format!("unknown parameter kind {}", py_repr(s))))
    }
}
impl fmt::Display for ParamStruct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Exact tokens; else Generic "unknown param_struct {s!r}".
impl FromStr for ParamStruct {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        ParamStruct::ALL
            .into_iter()
            .find(|value| value.as_str() == s)
            .ok_or_else(|| ConsoleError::generic(format!("unknown param_struct {}", py_repr(s))))
    }
}

/// A resolved parameter value (c2 `object`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamValue {
    Bytes(Vec<u8>),
    Int(i64),
    Str(String),
    Bool(bool),
    /// The chosen ENUM token, verbatim (e.g. tag_bits "128"). Normative: EVERY value of an
    /// ENUM param is `Enum` — built-in and custom defaults, resolver output, `default_from`
    /// mirrors and maps that services build by hand (certops' `{"hash": …}`, the transfer
    /// OAEP defaults). Sole exception: a custom-mechanism ENUM default written as a YAML int
    /// stays `Int` (§4.8.3, c2 parity for the gcm packer's `tag_bits`). Providers read
    /// builtin params only through `param_int`/`param_str`/`param_choice` below (and
    /// `as_bytes()`/`as_bool()`/`as_key()`), never by matching a variant; `as_int()` is
    /// NEVER used for a builtin param of kind ENUM (tag_bits), whose value is `Enum("96")`.
    Enum(String),
    KeyRef(Box<KeyInfo>),
}
impl ParamValue {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            ParamValue::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            ParamValue::Int(value) => Some(*value),
            _ => None,
        }
    }
    /// Str or Enum.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ParamValue::Str(text) | ParamValue::Enum(text) => Some(text),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ParamValue::Bool(value) => Some(*value),
            _ => None,
        }
    }
    pub fn as_key(&self) -> Option<&KeyInfo> {
        match self {
            ParamValue::KeyRef(info) => Some(info),
            _ => None,
        }
    }
}

/// Resolved parameters in ParamSpec order. A non-required parameter whose default is
/// c2's `None` (e.g. salt_len, mac_len) is ABSENT from the map (c2 stored an explicit None;
/// the one observable consequence — custom packers — is §4.6.3 / §11 D18).
pub type Params = IndexMap<String, ParamValue>;

/// c2 `_param_int` (memory.py:403, pkcs11/provider.py:378), the ONE way MemoryProvider,
/// Pkcs11Provider (non-custom paths) and FakeProvider read a numeric builtin param
/// (tag_bits, counter_bits, mac_len, salt_len, out_len): absent → `default`; `Int(v)` → v;
/// `Str(s)`/`Enum(s)` → `text::py_int(s, 10)` (outside i64 counts as unparsable — §11
/// D18), else Param "parameter '{name}' must be an integer, got {py_repr(s)}"; `Bool`,
/// `Bytes`, `KeyRef` → Param "parameter '{name}' must be an integer". param_name = name.
pub fn param_int(params: &Params, name: &str, default: i64) -> Result<i64> {
    match params.get(name) {
        None => Ok(default),
        Some(ParamValue::Int(value)) => Ok(*value),
        Some(ParamValue::Str(text) | ParamValue::Enum(text)) => py_int(text, 10)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| {
                ConsoleError::param(
                    format!(
                        "parameter '{name}' must be an integer, got {}",
                        py_repr(text)
                    ),
                    name,
                )
            }),
        Some(ParamValue::Bool(_) | ParamValue::Bytes(_) | ParamValue::KeyRef(_)) => Err(
            ConsoleError::param(format!("parameter '{name}' must be an integer"), name),
        ),
    }
}
/// c2 pkcs11 `_param_str`: absent → `default`; `Str(s)`/`Enum(s)` → s; anything else →
/// Param "parameter '{name}' must be a string" (param_name = name). Pkcs11Provider and
/// FakeProvider read string builtin params (hash, mgf_hash, padding, kdf) through it.
pub fn param_str<'a>(params: &'a Params, name: &str, default: &'a str) -> Result<&'a str> {
    match params.get(name) {
        None => Ok(default),
        Some(ParamValue::Str(text) | ParamValue::Enum(text)) => Ok(text),
        Some(_) => Err(ConsoleError::param(
            format!("parameter '{name}' must be a string"),
            name,
        )),
    }
}
/// c2 memory `_param_choice`/`_validate_choice`: absent → `default`; else the value's text
/// (`Str`/`Enum` verbatim, `Int` decimal, `Bool` `text::py_bool`, `Bytes`
/// `text::py_bytes_repr`, `KeyRef` its `key_ref.display()` — unreachable in practice,
/// since the resolver types ENUM params) must be a member of `choices`, else
/// Param "parameter '{name}' must be one of {choices joined ', '}; got {py_repr(text)}"
/// (param_name = name). MemoryProvider reads its ENUM params (hash, mgf_hash, padding,
/// tag_bits, kdf) through it; `int(param_choice(.., "tag_bits", ..))` is then a plain parse
/// of a member of {128,120,112,104,96}.
pub fn param_choice(
    params: &Params,
    name: &str,
    choices: &[&str],
    default: &str,
) -> Result<String> {
    let Some(value) = params.get(name) else {
        return Ok(default.to_owned());
    };
    let text = match value {
        ParamValue::Str(text) | ParamValue::Enum(text) => text.clone(),
        ParamValue::Int(number) => number.to_string(),
        ParamValue::Bool(flag) => py_bool(*flag).to_owned(),
        ParamValue::Bytes(bytes) => py_bytes_repr(bytes),
        ParamValue::KeyRef(info) => info.key_ref.display(),
    };
    if choices.contains(&text.as_str()) {
        Ok(text)
    } else {
        Err(ConsoleError::param(
            format!(
                "parameter '{name}' must be one of {}; got {}",
                choices.join(", "),
                py_repr(&text)
            ),
            name,
        ))
    }
}

/// Per-param validator; returns Param itself on failure. Compared by function address
/// (`std::ptr::fn_addr_eq`); Debug prints "ParamValidator(..)".
#[derive(Clone, Copy)]
pub struct ParamValidator(pub fn(&ParamValue) -> Result<()>);
impl fmt::Debug for ParamValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ParamValidator(..)")
    }
}
impl PartialEq for ParamValidator {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::fn_addr_eq(self.0, other.0)
    }
}
impl Eq for ParamValidator {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamSpec {
    pub name: String,
    pub kind: ParamKind,
    /// Prompt text without the trailing ": " (the IO appends it).
    pub prompt: String,
    pub required: bool,
    pub default: Option<ParamValue>,
    /// Mirror another (earlier) param's resolved value when this one is not given.
    pub default_from: Option<String>,
    pub choices: Option<Vec<String>>,
    /// Exact byte length (BYTES).
    pub length: Option<usize>,
    pub validate: Option<ParamValidator>,
    /// BYTES chosen by the caller (IVs, nonces, counter blocks of encrypt/sign/wrap rows):
    /// an EMPTY answer at the prompt draws this many bytes from the resolver's RNG provider
    /// instead (§11 D30). Inert unless the resolver was given one (`with_rng`).
    pub random: Option<usize>,
}
impl ParamSpec {
    /// required = true, everything else None.
    pub fn new(name: impl Into<String>, kind: ParamKind, prompt: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind,
            prompt: prompt.into(),
            required: true,
            default: None,
            default_from: None,
            choices: None,
            length: None,
            validate: None,
            random: None,
        }
    }
    /// The blessed synthetic STR spec (template-editor line, REPL fallback, labels).
    pub fn str(name: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self::new(name, ParamKind::Str, prompt)
    }
    /// required = false with this default (None = c2's `default=None`).
    pub fn optional(self, default: Option<ParamValue>) -> Self {
        Self {
            required: false,
            default,
            ..self
        }
    }
    pub fn default_from(self, name: impl Into<String>) -> Self {
        Self {
            default_from: Some(name.into()),
            ..self
        }
    }
    pub fn choices(self, choices: &[&str]) -> Self {
        Self {
            choices: Some(choices.iter().map(|choice| (*choice).to_owned()).collect()),
            ..self
        }
    }
    pub fn length(self, length: usize) -> Self {
        Self {
            length: Some(length),
            ..self
        }
    }
    pub fn validate(self, validator: fn(&ParamValue) -> Result<()>) -> Self {
        Self {
            validate: Some(ParamValidator(validator)),
            ..self
        }
    }
    /// §11 D30: an empty prompt answer = `len` random bytes (see `random`).
    pub fn random(self, len: usize) -> Self {
        Self {
            random: Some(len),
            ..self
        }
    }
}
