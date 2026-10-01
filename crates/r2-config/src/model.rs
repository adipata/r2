// Configuration model (spec §4.8.2/§4.8.3; owner R2): plain value types importable by any
// crate, each with the c2 `from_dict(data, path)` decoder as `from_value`.
use std::collections::BTreeSet;
use std::path::PathBuf;

use indexmap::IndexMap;
use r2_core::codec::decode_data;
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{KeyAlgorithm, KeyClass};
use r2_core::params::{ParamKind, ParamStruct, ParamValue, Verb};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_core::text::py_repr;

use crate::decode::{
    as_bool, as_int_at, as_list, as_mapping, as_path, as_str, check_ident, enum_of, fail, get,
    join, non_negative, req, req_map, template_value, warn_unknown,
};
use crate::yaml::{Mapping, Value, as_int, python_type_name};

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
    const ALL: [LogLevel; 4] = [
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warning,
        LogLevel::Error,
    ];
    const TOKENS: [&'static str; 4] = ["debug", "info", "warning", "error"];
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
        }
    }
}
impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Exact tokens; else Config "invalid value {s!r}" (hint "valid values: debug, info,
/// warning, error"); the decoder prefixes "{path}: ".
impl std::str::FromStr for LogLevel {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        token_of(s, &Self::ALL, Self::as_str, &Self::TOKENS)
    }
}
impl ColorMode {
    const ALL: [ColorMode; 3] = [ColorMode::Auto, ColorMode::Always, ColorMode::Never];
    const TOKENS: [&'static str; 3] = ["auto", "always", "never"];
    pub fn as_str(self) -> &'static str {
        match self {
            ColorMode::Auto => "auto",
            ColorMode::Always => "always",
            ColorMode::Never => "never",
        }
    }
}
impl std::fmt::Display for ColorMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Exact tokens; else Config "invalid value {s!r}" (hint "valid values: auto, always,
/// never"); the decoder prefixes "{path}: ".
impl std::str::FromStr for ColorMode {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        token_of(s, &Self::ALL, Self::as_str, &Self::TOKENS)
    }
}

/// Exact token lookup; else Config "invalid value {s!r}" (hint "valid values: …").
fn token_of<T: Copy>(
    s: &str,
    all: &[T],
    as_str: fn(T) -> &'static str,
    tokens: &[&str],
) -> Result<T> {
    all.iter()
        .copied()
        .find(|value| as_str(*value) == s)
        .ok_or_else(|| {
            ConsoleError::config(format!("invalid value {}", py_repr(s)))
                .with_hint(format!("valid values: {}", tokens.join(", ")))
        })
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
        Self {
            name: name.into(),
            library: library.into(),
            slot: None,
            token_label: None,
            env: IndexMap::new(),
        }
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
        let class_key = template_class_key(key_class, algorithm)?;
        let mut attrs = vec![
            TemplateAttr::new(
                "CKA_CLASS",
                AttrKind::Ulong,
                AttrValue::Symbol(key_class.cko_symbol().to_owned()),
            )
            .locked(),
        ];
        if key_class.has_key_type() {
            // template_class_key already rejected the algorithms without a CKK name.
            let ckk = algorithm
                .ckk_symbol()
                .ok_or_else(|| no_class_key(key_class, algorithm))?;
            attrs.push(
                TemplateAttr::new(
                    "CKA_KEY_TYPE",
                    AttrKind::Ulong,
                    AttrValue::Symbol(ckk.to_owned()),
                )
                .locked(),
            );
        }
        if let Some(config_attrs) = self.pkcs11.get(class_key) {
            for (name, value) in config_attrs {
                attrs.push(TemplateAttr::new(
                    name.clone(),
                    value.inferred_kind(),
                    value.clone(),
                ));
            }
        }
        Ok(KeyTemplate::new(attrs))
    }
}

/// (class, algorithm) → class key; class is checked first: Certificate → "certificate",
/// Data → "data"; algorithm None/Other → UnsupportedOperation "{algorithm} {class} objects
/// have no template class key" (hint "objects of unsupported key types can be listed and
/// deleted only"); Aes → "aes"; Generic → "generic_secret"; Rsa → "rsa_private" /
/// "rsa_public"; Ec/EcEdwards/EcMontgomery → "ec_private" / "ec_public" (Private →
/// "_private", any other class → "_public").
pub fn template_class_key(key_class: KeyClass, algorithm: KeyAlgorithm) -> Result<&'static str> {
    match (key_class, algorithm) {
        (KeyClass::Certificate, _) => Ok("certificate"),
        (KeyClass::Data, _) => Ok("data"),
        (_, KeyAlgorithm::None | KeyAlgorithm::Other) => Err(no_class_key(key_class, algorithm)),
        (_, KeyAlgorithm::Aes) => Ok("aes"),
        (_, KeyAlgorithm::Generic) => Ok("generic_secret"),
        (KeyClass::Private, KeyAlgorithm::Rsa) => Ok("rsa_private"),
        (_, KeyAlgorithm::Rsa) => Ok("rsa_public"),
        (KeyClass::Private, _) => Ok("ec_private"),
        (_, _) => Ok("ec_public"),
    }
}

fn no_class_key(key_class: KeyClass, algorithm: KeyAlgorithm) -> ConsoleError {
    ConsoleError::unsupported(format!(
        "{algorithm} {key_class} objects have no template class key"
    ))
    .with_hint("objects of unsupported key types can be listed and deleted only")
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
        let data = as_mapping(value, path)?;
        warn_unknown(data, &CONFIG_SECTIONS, path, "config key");
        let mechs_path = join(path, "custom_mechanisms");
        let mut custom_mechanisms = Vec::new();
        for (i, entry) in as_list(req(data, "custom_mechanisms", path)?, &mechs_path)?
            .iter()
            .enumerate()
        {
            custom_mechanisms.push(CustomMechanismConfig::from_value(
                entry,
                &format!("{mechs_path}[{i}]"),
            )?);
        }
        let config = Self {
            app: AppSection::from_value(req(data, "app", path)?, &join(path, "app"))?,
            ui: UiSection::from_value(req(data, "ui", path)?, &join(path, "ui"))?,
            providers: ProvidersSection::from_value(
                req(data, "providers", path)?,
                &join(path, "providers"),
            )?,
            softhsm: SoftHsmSection::from_value(
                req(data, "softhsm", path)?,
                &join(path, "softhsm"),
            )?,
            templates: TemplatesSection::from_value(
                req(data, "templates", path)?,
                &join(path, "templates"),
            )?,
            custom_mechanisms,
        };
        config.cross_check(path)?;
        Ok(config)
    }
    /// Plain tree for `config show` (c2 `_to_plain`): field order = struct order, paths as
    /// strings, enums as tokens, Option None as null. The raw mirrors are emitted IN PLACE
    /// of their typed fields and never as keys of their own: `templates.pkcs11` comes from
    /// `TemplatesSection::pkcs11_raw` and `params[].default` from
    /// `ParamSpecConfig::default_raw` (null when None), verbatim — never re-rendered from
    /// AttrValue/ParamValue (c2 printed the raw YAML objects; "0x…" lower-hex rendering
    /// would break byte identity for `'0x0A0B'`, `'0x0a 0b'`, `hex:0A0B`, `AQID`).
    pub fn to_value(&self) -> Value {
        let app = map([
            ("history_file", path_value(&self.app.history_file)),
            (
                "log",
                map([
                    ("level", Value::from(self.app.log.level.as_str())),
                    ("file", path_value(&self.app.log.file)),
                    ("max_bytes", Value::from(self.app.log.max_bytes)),
                    ("backups", Value::from(self.app.log.backups)),
                ]),
            ),
        ]);
        let ui = map([
            ("color", Value::from(self.ui.color.as_str())),
            ("hex_group", Value::from(self.ui.hex_group as u64)),
            ("hex_width", Value::from(self.ui.hex_width as u64)),
            ("confirm_delete", Value::from(self.ui.confirm_delete)),
        ]);
        let pkcs11: Vec<Value> = self
            .providers
            .pkcs11
            .iter()
            .map(|inst| {
                map([
                    ("name", Value::from(inst.name.as_str())),
                    ("library", path_value(&inst.library)),
                    ("slot", inst.slot.map_or(Value::Null, Value::from)),
                    (
                        "token_label",
                        inst.token_label.as_deref().map_or(Value::Null, Value::from),
                    ),
                    (
                        "env",
                        Value::Mapping(
                            inst.env
                                .iter()
                                .map(|(k, v)| (Value::from(k.as_str()), Value::from(v.as_str())))
                                .collect(),
                        ),
                    ),
                ])
            })
            .collect();
        let providers = map([
            (
                "memory",
                map([
                    ("enabled", Value::from(self.providers.memory.enabled)),
                    ("name", Value::from(self.providers.memory.name.as_str())),
                ]),
            ),
            ("pkcs11", Value::Sequence(pkcs11)),
        ]);
        let softhsm = map([
            ("autodetect", Value::from(self.softhsm.autodetect)),
            (
                "provider_name",
                Value::from(self.softhsm.provider_name.as_str()),
            ),
            (
                "search_paths",
                Value::Sequence(
                    self.softhsm
                        .search_paths
                        .iter()
                        .map(|p| path_value(p))
                        .collect(),
                ),
            ),
            ("conf_dir", path_value(&self.softhsm.conf_dir)),
            ("token_dir", path_value(&self.softhsm.token_dir)),
        ]);
        let templates_pkcs11: Mapping = self
            .templates
            .pkcs11_raw
            .iter()
            .map(|(class_key, attrs)| {
                (
                    Value::from(class_key.as_str()),
                    Value::Mapping(
                        attrs
                            .iter()
                            .map(|(name, raw)| (Value::from(name.as_str()), raw.clone()))
                            .collect(),
                    ),
                )
            })
            .collect();
        let custom_attributes: Mapping = self
            .templates
            .custom_attributes
            .iter()
            .map(|(name, def)| {
                (
                    Value::from(name.as_str()),
                    map([
                        ("code", Value::from(def.code)),
                        ("kind", Value::from(def.kind.as_str())),
                    ]),
                )
            })
            .collect();
        let templates = map([
            ("pkcs11", Value::Mapping(templates_pkcs11)),
            ("custom_attributes", Value::Mapping(custom_attributes)),
        ]);
        let mechanisms: Vec<Value> = self
            .custom_mechanisms
            .iter()
            .map(|mech| {
                let params: Vec<Value> = mech
                    .params
                    .iter()
                    .map(|param| {
                        map([
                            ("name", Value::from(param.name.as_str())),
                            ("kind", Value::from(param.kind.as_str())),
                            ("prompt", Value::from(param.prompt.as_str())),
                            ("required", Value::from(param.required)),
                            ("default", param.default_raw.clone().unwrap_or(Value::Null)),
                            ("choices", opt_str_list(param.choices.as_deref())),
                        ])
                    })
                    .collect();
                map([
                    ("id", Value::from(mech.id.as_str())),
                    ("verb", Value::from(mech.verb.as_str())),
                    ("algorithm", Value::from(mech.algorithm.as_str())),
                    ("cli_name", Value::from(mech.cli_name.as_str())),
                    ("label", Value::from(mech.label.as_str())),
                    ("ckm", Value::from(mech.ckm)),
                    ("param_struct", Value::from(mech.param_struct.as_str())),
                    ("params", Value::Sequence(params)),
                    (
                        "provider_types",
                        opt_str_list(mech.provider_types.as_deref()),
                    ),
                    ("providers", opt_str_list(mech.providers.as_deref())),
                ])
            })
            .collect();
        map([
            ("app", app),
            ("ui", ui),
            ("providers", providers),
            ("softhsm", softhsm),
            ("templates", templates),
            ("custom_mechanisms", Value::Sequence(mechanisms)),
        ])
    }

    /// c2 `_cross_check`: unique provider names; custom mechanism providers defined.
    fn cross_check(&self, path: &str) -> Result<()> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        seen.insert(self.providers.memory.name.as_str());
        for (i, instance) in self.providers.pkcs11.iter().enumerate() {
            if !seen.insert(instance.name.as_str()) {
                return Err(fail(
                    &join(path, &format!("providers.pkcs11[{i}].name")),
                    format!("duplicate provider name {}", py_repr(&instance.name)),
                )
                .with_hint("provider names must be unique across memory and pkcs11 instances"));
            }
        }
        let mut defined = seen;
        defined.insert(self.softhsm.provider_name.as_str());
        for (i, mech) in self.custom_mechanisms.iter().enumerate() {
            for name in mech.providers.iter().flatten() {
                if !defined.contains(name.as_str()) {
                    let names: Vec<&str> = defined.iter().copied().collect();
                    return Err(fail(
                        &join(path, &format!("custom_mechanisms[{i}].providers")),
                        format!("unknown provider {}", py_repr(name)),
                    )
                    .with_hint(format!("defined providers: {}", names.join(", "))));
                }
            }
        }
        Ok(())
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

// ---- decoders (c2 `from_dict`, same check order) -----------------------------------------

fn map<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Mapping(
        entries
            .into_iter()
            .map(|(k, v)| (Value::from(k), v))
            .collect(),
    )
}

/// c2 `_to_plain(Path)` = `str(path)`.
fn path_value(path: &std::path::Path) -> Value {
    Value::from(path.to_string_lossy().into_owned())
}

fn opt_str_list(items: Option<&[String]>) -> Value {
    match items {
        None => Value::Null,
        Some(items) => Value::Sequence(items.iter().map(|s| Value::from(s.as_str())).collect()),
    }
}

/// c2 `_opt_str_list`.
fn decode_opt_str_list(data: &Mapping, key: &str, path: &str) -> Result<Option<Vec<String>>> {
    let Some(raw) = get(data, key) else {
        return Ok(None);
    };
    let list_path = join(path, key);
    let mut out = Vec::new();
    for (i, entry) in as_list(raw, &list_path)?.iter().enumerate() {
        out.push(as_str(entry, &format!("{list_path}[{i}]"))?.to_owned());
    }
    Ok(Some(out))
}

fn ident(data: &Mapping, key: &str, path: &str) -> Result<String> {
    let name_path = join(path, key);
    let name = as_str(req(data, key, path)?, &name_path)?;
    check_ident(name, &name_path)?;
    Ok(name.to_owned())
}

impl LogSection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let data = as_mapping(value, path)?;
        warn_unknown(
            data,
            &["level", "file", "max_bytes", "backups"],
            path,
            "config key",
        );
        let max_bytes = non_negative(
            req(data, "max_bytes", path)?,
            &join(path, "max_bytes"),
            u64::MAX,
        )?;
        let backups = non_negative(
            req(data, "backups", path)?,
            &join(path, "backups"),
            u32::MAX,
        )?;
        let level_path = join(path, "level");
        let level = enum_of(req(data, "level", path)?, &level_path, &LogLevel::TOKENS)?;
        Ok(Self {
            level: level.parse()?,
            file: as_path(req(data, "file", path)?, &join(path, "file"))?,
            max_bytes,
            backups,
        })
    }
}
impl AppSection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let data = as_mapping(value, path)?;
        warn_unknown(data, &["history_file", "log"], path, "config key");
        Ok(Self {
            history_file: as_path(
                req(data, "history_file", path)?,
                &join(path, "history_file"),
            )?,
            log: LogSection::from_value(req(data, "log", path)?, &join(path, "log"))?,
        })
    }
}
impl UiSection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let data = as_mapping(value, path)?;
        warn_unknown(
            data,
            &["color", "hex_group", "hex_width", "confirm_delete"],
            path,
            "config key",
        );
        let group_path = join(path, "hex_group");
        let hex_group = as_int_at(req(data, "hex_group", path)?, &group_path)?;
        if hex_group < 0 {
            return Err(fail(&group_path, "must not be negative (0 = continuous)"));
        }
        let hex_group = usize::try_from(hex_group)
            .map_err(|_| fail(&group_path, format!("must be at most {}", usize::MAX)))?;
        let width_path = join(path, "hex_width");
        let hex_width = as_int_at(req(data, "hex_width", path)?, &width_path)?;
        if hex_width < 1 {
            return Err(fail(&width_path, "must be at least 1"));
        }
        let hex_width = usize::try_from(hex_width)
            .map_err(|_| fail(&width_path, format!("must be at most {}", usize::MAX)))?;
        let color = enum_of(
            req(data, "color", path)?,
            &join(path, "color"),
            &ColorMode::TOKENS,
        )?;
        Ok(Self {
            color: color.parse()?,
            hex_group,
            hex_width,
            confirm_delete: as_bool(
                req(data, "confirm_delete", path)?,
                &join(path, "confirm_delete"),
            )?,
        })
    }
}
impl MemorySection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let data = as_mapping(value, path)?;
        warn_unknown(data, &["enabled", "name"], path, "config key");
        let enabled = as_bool(req(data, "enabled", path)?, &join(path, "enabled"))?;
        Ok(Self {
            enabled,
            name: ident(data, "name", path)?,
        })
    }
}
impl Pkcs11InstanceConfig {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let data = as_mapping(value, path)?;
        warn_unknown(
            data,
            &["name", "library", "slot", "token_label", "env"],
            path,
            "config key",
        );
        let name = ident(data, "name", path)?;
        let library = as_path(req(data, "library", path)?, &join(path, "library"))?;
        let slot = match get(data, "slot") {
            None => None,
            Some(raw) => Some(non_negative(raw, &join(path, "slot"), u64::MAX)?),
        };
        let token_label = match get(data, "token_label") {
            None => None,
            Some(raw) => Some(as_str(raw, &join(path, "token_label"))?.to_owned()),
        };
        let mut env = IndexMap::new();
        if let Some(raw) = get(data, "env") {
            let env_path = join(path, "env");
            for (key, value) in as_mapping(raw, &env_path)? {
                let key = as_str(key, &env_path)?;
                env.insert(
                    key.to_owned(),
                    as_str(value, &join(&env_path, key))?.to_owned(),
                );
            }
        }
        Ok(Self {
            name,
            library,
            slot,
            token_label,
            env,
        })
    }
}
impl ProvidersSection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let data = as_mapping(value, path)?;
        warn_unknown(data, &["memory", "pkcs11"], path, "config key");
        let pkcs11_path = join(path, "pkcs11");
        let mut pkcs11 = Vec::new();
        for (i, entry) in as_list(req(data, "pkcs11", path)?, &pkcs11_path)?
            .iter()
            .enumerate()
        {
            pkcs11.push(Pkcs11InstanceConfig::from_value(
                entry,
                &format!("{pkcs11_path}[{i}]"),
            )?);
        }
        Ok(Self {
            memory: MemorySection::from_value(req(data, "memory", path)?, &join(path, "memory"))?,
            pkcs11,
        })
    }
}
impl SoftHsmSection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let data = as_mapping(value, path)?;
        warn_unknown(
            data,
            &[
                "autodetect",
                "provider_name",
                "search_paths",
                "conf_dir",
                "token_dir",
            ],
            path,
            "config key",
        );
        let paths_path = join(path, "search_paths");
        let mut search_paths = Vec::new();
        for (i, entry) in as_list(req(data, "search_paths", path)?, &paths_path)?
            .iter()
            .enumerate()
        {
            search_paths.push(as_path(entry, &format!("{paths_path}[{i}]"))?);
        }
        let autodetect = as_bool(req(data, "autodetect", path)?, &join(path, "autodetect"))?;
        let provider_name = ident(data, "provider_name", path)?;
        Ok(Self {
            autodetect,
            provider_name,
            search_paths,
            conf_dir: as_path(req(data, "conf_dir", path)?, &join(path, "conf_dir"))?,
            token_dir: as_path(req(data, "token_dir", path)?, &join(path, "token_dir"))?,
        })
    }
}
impl CustomAttributeDef {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let data = as_mapping(value, path)?;
        warn_unknown(data, &["code", "kind"], path, "config key");
        let code = non_negative(req(data, "code", path)?, &join(path, "code"), u64::MAX)?;
        let kind = enum_of(
            req(data, "kind", path)?,
            &join(path, "kind"),
            &["bool", "str", "bytes", "ulong"],
        )?;
        Ok(Self {
            code,
            kind: kind.parse()?,
        })
    }
}
impl TemplatesSection {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let data = as_mapping(value, path)?;
        warn_unknown(data, &["pkcs11", "custom_attributes"], path, "config key");
        let pkcs11_path = join(path, "pkcs11");
        let raw_classes = req_map(data, "pkcs11", path)?;
        warn_unknown(
            raw_classes,
            &TEMPLATE_CLASS_KEYS,
            &pkcs11_path,
            "template class key",
        );
        let mut pkcs11 = IndexMap::new();
        let mut pkcs11_raw = IndexMap::new();
        for (class_key, raw_attrs) in raw_classes {
            let class_key = as_str(class_key, &pkcs11_path)?;
            let class_path = join(&pkcs11_path, class_key);
            let attrs = as_mapping(raw_attrs, &class_path)?;
            let mut typed = IndexMap::new();
            let mut raw = IndexMap::new();
            for (name, raw_value) in attrs {
                let name = as_str(name, &class_path)?;
                typed.insert(
                    name.to_owned(),
                    template_value(raw_value, &join(&class_path, name))?,
                );
                raw.insert(name.to_owned(), raw_value.clone());
            }
            pkcs11.insert(class_key.to_owned(), typed);
            pkcs11_raw.insert(class_key.to_owned(), raw);
        }
        let custom_path = join(path, "custom_attributes");
        let mut custom_attributes = IndexMap::new();
        for (name, raw_def) in req_map(data, "custom_attributes", path)? {
            let name = as_str(name, &custom_path)?;
            custom_attributes.insert(
                name.to_owned(),
                CustomAttributeDef::from_value(raw_def, &join(&custom_path, name))?,
            );
        }
        Ok(Self {
            pkcs11,
            pkcs11_raw,
            custom_attributes,
        })
    }
}

/// §4.8.3: a custom-mechanism parameter default typed at load by its kind (§11 D18).
fn typed_default(kind: ParamKind, raw: &Value, path: &str) -> Result<ParamValue> {
    let mismatch = || {
        fail(
            path,
            format!(
                "expected a {} default, got {}",
                kind.as_str(),
                python_type_name(raw)
            ),
        )
    };
    let int = |raw: &Value| -> Result<ParamValue> {
        let v = as_int(raw).ok_or_else(mismatch)?;
        i64::try_from(v)
            .map(ParamValue::Int)
            .map_err(|_| fail(path, format!("must be at most {}", i64::MAX)))
    };
    match (kind, raw) {
        (ParamKind::KeyRef, _) => Err(fail(path, "keyref parameters cannot have a default")),
        (ParamKind::Int, Value::Number(_)) if as_int(raw).is_some() => int(raw),
        (ParamKind::Str, Value::String(s)) => Ok(ParamValue::Str(s.clone())),
        (ParamKind::Bool, Value::Bool(b)) => Ok(ParamValue::Bool(*b)),
        (ParamKind::Enum, Value::String(s)) => Ok(ParamValue::Enum(s.clone())),
        (ParamKind::Enum, Value::Number(_)) if as_int(raw).is_some() => int(raw),
        (ParamKind::Bytes, Value::String(s)) => decode_data(s)
            .map(|(bytes, _)| ParamValue::Bytes(bytes.to_vec()))
            .map_err(|e| fail(path, &e.message).with_hint_opt(e.hint)),
        _ => Err(mismatch()),
    }
}

impl ParamSpecConfig {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let data = as_mapping(value, path)?;
        warn_unknown(
            data,
            &["name", "kind", "prompt", "required", "default", "choices"],
            path,
            "config key",
        );
        let name_path = join(path, "name");
        let name = as_str(req(data, "name", path)?, &name_path)?;
        if name.is_empty() {
            return Err(fail(&name_path, "must not be empty"));
        }
        let kind: ParamKind = enum_of(
            req(data, "kind", path)?,
            &join(path, "kind"),
            &["bytes", "int", "str", "bool", "enum", "keyref"],
        )?
        .parse()?;
        // c2 `data.get("required", True)`: an explicit null is NOT the default.
        let required_raw = data.get("required").cloned().unwrap_or(Value::Bool(true));
        let mut choices = None;
        if let Some(raw) = get(data, "choices") {
            let choices_path = join(path, "choices");
            let mut out = Vec::new();
            for (i, entry) in as_list(raw, &choices_path)?.iter().enumerate() {
                out.push(as_str(entry, &format!("{choices_path}[{i}]"))?.to_owned());
            }
            choices = Some(out);
        }
        if kind == ParamKind::Enum && choices.as_ref().is_none_or(Vec::is_empty) {
            return Err(fail(&join(path, "choices"), "required for kind 'enum'"));
        }
        let prompt = as_str(req(data, "prompt", path)?, &join(path, "prompt"))?.to_owned();
        let required = as_bool(&required_raw, &join(path, "required"))?;
        let (default, default_raw) = match get(data, "default") {
            None => (None, None),
            Some(raw) => (
                Some(typed_default(kind, raw, &join(path, "default"))?),
                Some(raw.clone()),
            ),
        };
        Ok(Self {
            name: name.to_owned(),
            kind,
            prompt,
            required,
            default,
            default_raw,
            choices,
        })
    }
}
impl CustomMechanismConfig {
    pub fn from_value(value: &Value, path: &str) -> Result<Self> {
        let data = as_mapping(value, path)?;
        warn_unknown(
            data,
            &[
                "id",
                "verb",
                "algorithm",
                "cli_name",
                "label",
                "ckm",
                "param_struct",
                "params",
                "provider_types",
                "providers",
            ],
            path,
            "config key",
        );
        let id_path = join(path, "id");
        let id = as_str(req(data, "id", path)?, &id_path)?;
        if id.is_empty() {
            return Err(fail(&id_path, "must not be empty"));
        }
        let verb: Verb = enum_of(
            req(data, "verb", path)?,
            &join(path, "verb"),
            &["encrypt", "decrypt", "sign", "verify", "derive"],
        )?
        .parse()?;
        let algorithm: KeyAlgorithm = enum_of(
            req(data, "algorithm", path)?,
            &join(path, "algorithm"),
            &["aes", "rsa", "ec", "ec-edwards", "ec-montgomery", "generic"],
        )?
        .parse()?;
        let cli_path = join(path, "cli_name");
        let cli_name = as_str(req(data, "cli_name", path)?, &cli_path)?;
        if cli_name.is_empty() {
            return Err(fail(&cli_path, "must not be empty"));
        }
        let ckm_path = join(path, "ckm");
        let ckm = non_negative(req(data, "ckm", path)?, &ckm_path, u64::MAX)?;
        if ckm < 0x8000_0000 {
            tracing::warn!(
                target: "r2::config",
                "{ckm_path}: CKM code 0x{ckm:08x} is below the vendor-defined range (>= 0x80000000)"
            );
        }
        // c2 `data.get("param_struct", "none")`: an explicit null is NOT the default.
        let struct_raw = data
            .get("param_struct")
            .cloned()
            .unwrap_or_else(|| Value::from("none"));
        let param_struct: ParamStruct = enum_of(
            &struct_raw,
            &join(path, "param_struct"),
            &["none", "iv", "gcm", "oaep", "raw"],
        )?
        .parse()?;
        let mut params = Vec::new();
        if let Some(raw) = get(data, "params") {
            let params_path = join(path, "params");
            for (i, entry) in as_list(raw, &params_path)?.iter().enumerate() {
                params.push(ParamSpecConfig::from_value(
                    entry,
                    &format!("{params_path}[{i}]"),
                )?);
            }
        }
        let label = as_str(req(data, "label", path)?, &join(path, "label"))?.to_owned();
        Ok(Self {
            id: id.to_owned(),
            verb,
            algorithm,
            cli_name: cli_name.to_owned(),
            label,
            ckm,
            param_struct,
            params,
            provider_types: decode_opt_str_list(data, "provider_types", path)?,
            providers: decode_opt_str_list(data, "providers", path)?,
        })
    }
}
