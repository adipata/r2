// R0 skeleton — owner R1 (generated from spec §4)
use crate::error::{ConsoleError, Result};
use crate::keys::KeyInfo;
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
        unimplemented!("R1")
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
    pub fn as_str(self) -> &'static str {
        unimplemented!("R1")
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
    pub fn as_str(self) -> &'static str {
        unimplemented!("R1")
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        unimplemented!("R1")
    }
}
/// Exact tokens; else Generic "unknown verb {s!r}".
impl FromStr for Verb {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        let _ = s;
        Err(crate::error::ConsoleError::not_implemented("R1"))
    }
}
impl fmt::Display for ParamKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        unimplemented!("R1")
    }
}
/// Exact tokens; else Generic "unknown parameter kind {s!r}".
impl FromStr for ParamKind {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        let _ = s;
        Err(crate::error::ConsoleError::not_implemented("R1"))
    }
}
impl fmt::Display for ParamStruct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        unimplemented!("R1")
    }
}
/// Exact tokens; else Generic "unknown param_struct {s!r}".
impl FromStr for ParamStruct {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        let _ = s;
        Err(crate::error::ConsoleError::not_implemented("R1"))
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
        unimplemented!("R1")
    }
    pub fn as_int(&self) -> Option<i64> {
        unimplemented!("R1")
    }
    /// Str or Enum.
    pub fn as_str(&self) -> Option<&str> {
        unimplemented!("R1")
    }
    pub fn as_bool(&self) -> Option<bool> {
        unimplemented!("R1")
    }
    pub fn as_key(&self) -> Option<&KeyInfo> {
        unimplemented!("R1")
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
    let _ = (params, name, default);
    Err(crate::error::ConsoleError::not_implemented("R1"))
}
/// c2 pkcs11 `_param_str`: absent → `default`; `Str(s)`/`Enum(s)` → s; anything else →
/// Param "parameter '{name}' must be a string" (param_name = name). Pkcs11Provider and
/// FakeProvider read string builtin params (hash, mgf_hash, padding, kdf) through it.
pub fn param_str<'a>(params: &'a Params, name: &str, default: &'a str) -> Result<&'a str> {
    let _ = (params, name, default);
    Err(crate::error::ConsoleError::not_implemented("R1"))
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
    let _ = (params, name, choices, default);
    Err(crate::error::ConsoleError::not_implemented("R1"))
}

/// Per-param validator; returns Param itself on failure. Compared by function address
/// (`std::ptr::fn_addr_eq`); Debug prints "ParamValidator(..)".
#[derive(Clone, Copy)]
pub struct ParamValidator(pub fn(&ParamValue) -> Result<()>);
impl fmt::Debug for ParamValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        unimplemented!("R1")
    }
}
impl PartialEq for ParamValidator {
    fn eq(&self, other: &Self) -> bool {
        let _ = other;
        unimplemented!("R1")
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
}
impl ParamSpec {
    /// required = true, everything else None.
    pub fn new(name: impl Into<String>, kind: ParamKind, prompt: impl Into<String>) -> Self {
        let _ = (name, kind, prompt);
        unimplemented!("R1")
    }
    /// The blessed synthetic STR spec (template-editor line, REPL fallback, labels).
    pub fn str(name: impl Into<String>, prompt: impl Into<String>) -> Self {
        let _ = (name, prompt);
        unimplemented!("R1")
    }
    /// required = false with this default (None = c2's `default=None`).
    pub fn optional(self, default: Option<ParamValue>) -> Self {
        let _ = default;
        unimplemented!("R1")
    }
    pub fn default_from(self, name: impl Into<String>) -> Self {
        let _ = name;
        unimplemented!("R1")
    }
    pub fn choices(self, choices: &[&str]) -> Self {
        let _ = choices;
        unimplemented!("R1")
    }
    pub fn length(self, length: usize) -> Self {
        let _ = length;
        unimplemented!("R1")
    }
    pub fn validate(self, validator: fn(&ParamValue) -> Result<()>) -> Self {
        let _ = validator;
        unimplemented!("R1")
    }
}
