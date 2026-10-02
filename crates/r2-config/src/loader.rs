// Configuration discovery + deep merge (spec §4.8.1; owner R2).
//
// Exactly one external file, first match wins; a missing or unreadable explicit choice is
// a hard error (never a silent fallthrough): `--config`, `$R2_CONFIG`, `./r2.yaml`,
// `<user config dir>/r2.yaml`. Mappings merge recursively, scalars and LISTS replace.
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use r2_core::error::{ConsoleError, Result};
use r2_core::text::os_error_text;

use crate::dirs::{expand_user_path, user_config_dir};
use crate::model::{AppConfig, LoadedConfig};
use crate::yaml::{self, Mapping, Value, py_value_repr};

pub const ENV_VAR: &str = "R2_CONFIG";
pub const FILE_NAME: &str = "r2.yaml";
pub const APP_DIR: &str = "r2";
/// The embedded defaults (spec §7 with `c2`→`r2` path renames). `config show --defaults`
/// prints this text verbatim; it never goes through the loader.
pub const DEFAULTS_YAML: &str = include_str!("defaults.yaml");

/// path = --config value or None (env/cwd/user-dir discovery).
pub fn load_config(path: Option<&Path>) -> Result<LoadedConfig> {
    let defaults = read_defaults()?;
    let source_path = discover(path)?;
    let (external, merged) = match &source_path {
        None => (Mapping::new(), Value::Mapping(defaults.clone())),
        Some(source) => {
            let external = read_external(source)?;
            let merged = deep_merge(
                &Value::Mapping(defaults.clone()),
                &Value::Mapping(external.clone()),
            );
            (external, merged)
        }
    };
    let origin_text = source_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    let mut origins = IndexMap::new();
    for section in defaults.keys() {
        let Value::String(section) = section else {
            continue;
        };
        let origin = match &origin_text {
            Some(text) if external.contains_key(section.as_str()) => text.clone(),
            _ => "default".to_owned(),
        };
        origins.insert(section.clone(), origin);
    }
    let config = AppConfig::from_value(&merged, "").map_err(|err| match &source_path {
        Some(source) => ConsoleError::config(format!(
            "{} (config file: {})",
            err.message,
            source.display()
        ))
        .with_hint_opt(err.hint),
        None => err,
    })?;
    Ok(LoadedConfig {
        config,
        source_path,
        origins,
    })
}
/// Test/support helper (no discovery, no file): DEFAULTS_YAML deep-merged with `external`
/// (YAML text, same rules as a config file), decoded. Errors carry no "(config file: …)".
pub fn config_from_yaml(external: Option<&str>) -> Result<AppConfig> {
    let defaults = Value::Mapping(read_defaults()?);
    let merged = match external {
        None => defaults,
        Some(text) => {
            let overlay = external_mapping(text, "config text")?;
            deep_merge(&defaults, &Value::Mapping(overlay))
        }
    };
    AppConfig::from_value(&merged, "")
}
/// Mappings merge recursively (keys of `overlay` appended in their order when new);
/// scalars and sequences from `overlay` replace.
pub fn deep_merge(base: &Value, overlay: &Value) -> Value {
    match (base, overlay) {
        (Value::Mapping(base_map), Value::Mapping(overlay_map)) => {
            let mut merged = base_map.clone();
            for (key, value) in overlay_map {
                let new_value = match merged.get(key) {
                    Some(existing) => deep_merge(existing, value),
                    None => value.clone(),
                };
                merged.insert(key.clone(), new_value);
            }
            Value::Mapping(merged)
        }
        _ => overlay.clone(),
    }
}
/// The first existing discovery candidate, applying the hard-error rules (exposed for
/// `config path` tests): `--config` / non-empty `$R2_CONFIG` are `expand_user`-ed, and a
/// path that is not an existing regular FILE (c2 `Path.is_file()`) → "config file not
/// found: {path}" (the expanded path).
pub fn discover(cli_path: Option<&Path>) -> Result<Option<PathBuf>> {
    if let Some(cli_path) = cli_path {
        let path = expand_user_path(cli_path);
        if !path.is_file() {
            return Err(
                ConsoleError::config(format!("config file not found: {}", path.display()))
                    .with_hint("--config must point to an existing file"),
            );
        }
        return Ok(Some(path));
    }
    if let Some(env_value) = std::env::var_os(ENV_VAR).filter(|v| !v.is_empty()) {
        let path = expand_user_path(Path::new(&env_value));
        if !path.is_file() {
            return Err(
                ConsoleError::config(format!("config file not found: {}", path.display()))
                    .with_hint(format!("${ENV_VAR} must point to an existing file")),
            );
        }
        return Ok(Some(path));
    }
    // A deleted working directory skips this candidate (c2 crashed, §11 D12 (d)).
    if let Ok(cwd) = std::env::current_dir() {
        let cwd_file = cwd.join(FILE_NAME);
        if cwd_file.is_file() {
            return Ok(Some(cwd_file));
        }
    }
    if let Some(dir) = user_config_dir() {
        let user_file = dir.join(FILE_NAME);
        if user_file.is_file() {
            return Ok(Some(user_file));
        }
    }
    Ok(None)
}

/// Parse the embedded defaults.yaml (package-controlled; guarded anyway).
fn read_defaults() -> Result<Mapping> {
    match yaml::parse(DEFAULTS_YAML) {
        Ok(Value::Mapping(map)) => Ok(map),
        _ => Err(ConsoleError::config(
            "embedded defaults.yaml is not a mapping (corrupt installation)",
        )),
    }
}

/// CPython's `UnicodeDecodeError` text for invalid UTF-8 (`Path.read_text`).
fn utf8_error_text(bytes: &[u8], error: &std::str::Utf8Error) -> String {
    let start = error.valid_up_to();
    match error.error_len() {
        None => {
            let end = bytes.len() - 1;
            if end == start {
                format!(
                    "'utf-8' codec can't decode byte 0x{:02x} in position {start}: unexpected \
                     end of data",
                    bytes[start]
                )
            } else {
                format!(
                    "'utf-8' codec can't decode bytes in position {start}-{end}: unexpected \
                     end of data"
                )
            }
        }
        // CPython reports a truncated multi-byte sequence (maximal subpart, the same rule as
        // `error_len`) as a byte range.
        Some(len) if len > 1 => format!(
            "'utf-8' codec can't decode bytes in position {start}-{}: invalid continuation byte",
            start + len - 1
        ),
        Some(_) => {
            let first = bytes[start];
            let reason = if (0x80..=0xc1).contains(&first) || first >= 0xf5 {
                "invalid start byte"
            } else {
                "invalid continuation byte"
            };
            format!("'utf-8' codec can't decode byte 0x{first:02x} in position {start}: {reason}")
        }
    }
}

/// Read and validate the external file (c2 `_read_external`).
fn read_external(path: &Path) -> Result<Mapping> {
    let shown = path.display();
    let bytes = std::fs::read(path).map_err(|err| {
        ConsoleError::config(format!(
            "cannot read config file {shown}: {}",
            os_error_text(&err)
        ))
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|err| {
        ConsoleError::config(format!(
            "cannot read config file {shown}: {}",
            utf8_error_text(&bytes, &err)
        ))
    })?;
    // Python text mode: universal newlines.
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    external_mapping(&text, &format!("config file {shown}"))
}

/// Parse external YAML text and apply the top-level rules; `what` names the source in
/// messages ("config file {path}").
fn external_mapping(text: &str, what: &str) -> Result<Mapping> {
    let data = yaml::parse(text)
        .map_err(|err| ConsoleError::config(format!("invalid YAML in {what}: {}", err.message)))?;
    let map = match data {
        Value::Null => return Ok(Mapping::new()),
        Value::Mapping(map) => map,
        _ => {
            return Err(ConsoleError::config(format!(
                "{what} must contain a top-level mapping"
            )));
        }
    };
    for key in map.keys() {
        if !matches!(key, Value::String(_)) {
            return Err(ConsoleError::config(format!(
                "{what}: top-level keys must be strings, got {}",
                py_value_repr(key)
            )));
        }
    }
    Ok(map)
}
