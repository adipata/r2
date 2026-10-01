// R0 skeleton — owner R2 (generated from spec §4)
use crate::yaml::Value;
use indexmap::IndexMap;
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{KeyAlgorithm, KeyClass};
use r2_core::params::{ParamKind, ParamStruct, ParamValue, Verb};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate};
use std::path::PathBuf;

/// The six top-level sections in defaults.yaml order (`config show --origin`).
pub const CONFIG_SECTIONS: [&str; 6] = [
    "app",
    "ui",
    "providers",
    "softhsm",
    "templates",
    "custom_mechanisms",
];
/// Class keys of templates.pkcs11 (§7) and of template files (§5.16).
pub const TEMPLATE_CLASS_KEYS: [&str; 8] = [
    "aes",
    "rsa_private",
    "rsa_public",
    "ec_private",
    "ec_public",
    "certificate",
    "generic_secret",
    "data",
];

/// Token: "debug" | "info" | "warning" | "error".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}
/// Token: "auto" | "always" | "never".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        unimplemented!("R2")
    }
}
impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = f;
        unimplemented!("R2")
    }
}
/// Exact tokens; else Config "invalid value {s!r}" (hint "valid values: debug, info,
/// warning, error"); the decoder prefixes "{path}: ".
impl std::str::FromStr for LogLevel {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        let _ = s;
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}
impl ColorMode {
    pub fn as_str(self) -> &'static str {
        unimplemented!("R2")
    }
}
impl std::fmt::Display for ColorMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = f;
        unimplemented!("R2")
    }
}
/// Exact tokens; else Config "invalid value {s!r}" (hint "valid values: auto, always,
/// never"); the decoder prefixes "{path}: ".
impl std::str::FromStr for ColorMode {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        let _ = s;
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogSection {
    pub level: LogLevel,
    pub file: PathBuf,
    pub max_bytes: u64,
    pub backups: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppSection {
    pub history_file: PathBuf,
    pub log: LogSection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UiSection {
    pub color: ColorMode,
    /// Bytes per group in hex output; 0 = continuous.
    pub hex_group: usize,
    /// Bytes per line (≥ 1).
    pub hex_width: usize,
    pub confirm_delete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemorySection {
    pub enabled: bool,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pkcs11InstanceConfig {
    pub name: String,
    /// `~` expanded. Existence is NOT checked at load (§6: a broken library surfaces as
    /// ProviderUnavailable on first use).
    pub library: PathBuf,
    /// A negative YAML value is a load error in r2 (c2 accepted it) — §11 D18.
    pub slot: Option<u64>,
    pub token_label: Option<String>,
    /// Set in the process environment immediately before C_Initialize (§4.5.5).
    pub env: IndexMap<String, String>,
}
impl Pkcs11InstanceConfig {
    /// slot/token_label None, env empty (the SoftHSM autodetect instance).
    pub fn new(name: impl Into<String>, library: impl Into<PathBuf>) -> Self {
        let _ = (name, library);
        unimplemented!("R2")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvidersSection {
    pub memory: MemorySection,
    pub pkcs11: Vec<Pkcs11InstanceConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoftHsmSection {
    pub autodetect: bool,
    pub provider_name: String,
    /// Passed to `find_softhsm_module` (§4.5.5).
    pub search_paths: Vec<PathBuf>,
    pub conf_dir: PathBuf,
    pub token_dir: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustomAttributeDef {
    /// Vendor CKA_* code.
    pub code: u64,
    pub kind: AttrKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplatesSection {
    /// class key → attribute name → value, values already converted by the §4.7 kind
    /// inference rule (YAML order preserved). Unknown class keys are kept (and warned).
    pub pkcs11: IndexMap<String, IndexMap<String, AttrValue>>,
    /// The SOURCE YAML scalar of every `pkcs11` entry, same keys in the same order (c2
    /// kept `dict(attrs)` unconverted). Used only by `AppConfig::to_value`, so
    /// `config show` prints e.g. `CKA_ID: 0x0A 0B` verbatim, as c2 does.
    pub pkcs11_raw: IndexMap<String, IndexMap<String, Value>>,
    pub custom_attributes: IndexMap<String, CustomAttributeDef>,
}
impl TemplatesSection {
    /// The editable KeyTemplate for load/copy/generate (never reimplemented per command):
    /// locked enabled rows CKA_CLASS = Symbol(key_class.cko_symbol()) and — for
    /// Secret/Private/Public only — CKA_KEY_TYPE = Symbol(algorithm.ckk_symbol()),
    /// followed by the class key's config attrs (kind = value.inferred_kind()), all
    /// enabled, in config order; fresh (unshared) rows. Errors as template_class_key.
    pub fn default_template(
        &self,
        key_class: KeyClass,
        algorithm: KeyAlgorithm,
    ) -> Result<KeyTemplate> {
        let _ = (key_class, algorithm);
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}

/// (class, algorithm) → class key; class is checked first: Certificate → "certificate",
/// Data → "data"; algorithm None/Other → UnsupportedOperation "{algorithm} {class} objects
/// have no template class key" (hint "objects of unsupported key types can be listed and
/// deleted only"); Aes → "aes"; Generic → "generic_secret"; Rsa → "rsa_private" /
/// "rsa_public"; Ec/EcEdwards/EcMontgomery → "ec_private" / "ec_public" (Private →
/// "_private", any other class → "_public").
pub fn template_class_key(key_class: KeyClass, algorithm: KeyAlgorithm) -> Result<&'static str> {
    let _ = (key_class, algorithm);
    Err(r2_core::ConsoleError::not_implemented("R2"))
}

/// YAML param entry of a custom mechanism; converted 1:1 into a ParamSpec by r2-ops.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamSpecConfig {
    pub name: String,
    pub kind: ParamKind,
    pub prompt: String,
    pub required: bool,
    /// Typed at load by `kind` (§4.8.3).
    pub default: Option<ParamValue>,
    /// The source YAML value of `default` (c2 stored `data.get("default")` raw); None when
    /// the key is absent or null. Used only by `AppConfig::to_value` (`config show`).
    pub default_raw: Option<Value>,
    pub choices: Option<Vec<String>>,
}

/// Config-defined vendor mechanism (frozen-provisional, §4.11: param encoding v1 = the five
/// ParamStruct packers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomMechanismConfig {
    /// e.g. "vendor.acme.kcv".
    pub id: String,
    pub verb: Verb,
    /// Never None/Other (rejected at load).
    pub algorithm: KeyAlgorithm,
    pub cli_name: String,
    pub label: String,
    /// Raw CKM code (warning when < 0x80000000).
    pub ckm: u64,
    pub param_struct: ParamStruct,
    pub params: Vec<ParamSpecConfig>,
    /// None → {"pkcs11"} (applied by r2-ops).
    pub provider_types: Option<Vec<String>>,
    pub providers: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppConfig {
    pub app: AppSection,
    pub ui: UiSection,
    pub providers: ProvidersSection,
    pub softhsm: SoftHsmSection,
    pub templates: TemplatesSection,
    pub custom_mechanisms: Vec<CustomMechanismConfig>,
}
impl AppConfig {
    /// Typed decode of the merged tree + cross-checks (§4.8.3).
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let _ = (value, path);
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
    /// Plain tree for `config show` (c2 `_to_plain`): field order = struct order, paths as
    /// strings, enums as tokens, Option None as null. The raw mirrors are emitted IN PLACE
    /// of their typed fields and never as keys of their own: `templates.pkcs11` comes from
    /// `TemplatesSection::pkcs11_raw` and `params[].default` from
    /// `ParamSpecConfig::default_raw` (null when None), verbatim — never re-rendered from
    /// AttrValue/ParamValue (c2 printed the raw YAML objects; "0x…" lower-hex rendering
    /// would break byte identity for `'0x0A0B'`, `'0x0a 0b'`, `hex:0A0B`, `AQID`).
    pub fn to_value(&self) -> Value {
        unimplemented!("R2")
    }
}

/// Loader result: typed config + provenance (feeds `config path` / `config show --origin`
/// without re-running discovery).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedConfig {
    pub config: AppConfig,
    /// The external file actually loaded, if any.
    pub source_path: Option<PathBuf>,
    /// Top-level section → "default" | source path text, in CONFIG_SECTIONS order.
    pub origins: IndexMap<String, String>,
}

impl LogSection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let _ = (value, path);
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}
impl AppSection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let _ = (value, path);
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}
impl UiSection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let _ = (value, path);
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}
impl MemorySection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let _ = (value, path);
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}
impl Pkcs11InstanceConfig {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let _ = (value, path);
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}
impl ProvidersSection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let _ = (value, path);
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}
impl SoftHsmSection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let _ = (value, path);
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}
impl CustomAttributeDef {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let _ = (value, path);
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}
impl TemplatesSection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let _ = (value, path);
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}
impl ParamSpecConfig {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let _ = (value, path);
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}
impl CustomMechanismConfig {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let _ = (value, path);
        Err(r2_core::ConsoleError::not_implemented("R2"))
    }
}
