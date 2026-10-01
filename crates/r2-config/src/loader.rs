// R0 skeleton — owner R2 (generated from spec §4)
// ---- spec §4.8.1 block 0
use crate::model::{AppConfig, LoadedConfig};
use crate::yaml::Value;
use r2_core::error::Result;
use std::path::{Path, PathBuf};

pub const ENV_VAR: &str = "R2_CONFIG";
pub const FILE_NAME: &str = "r2.yaml";
pub const APP_DIR: &str = "r2";
/// The embedded defaults (spec §7 with `c2`→`r2` path renames). `config show --defaults`
/// prints this text verbatim; it never goes through the loader.
pub const DEFAULTS_YAML: &str = include_str!("defaults.yaml");

/// path = --config value or None (env/cwd/user-dir discovery).
pub fn load_config(path: Option<&Path>) -> Result<LoadedConfig> {
    let _ = path;
    Err(r2_core::ConsoleError::not_implemented("R2"))
}
/// Test/support helper (no discovery, no file): DEFAULTS_YAML deep-merged with `external`
/// (YAML text, same rules as a config file), decoded. Errors carry no "(config file: …)".
pub fn config_from_yaml(external: Option<&str>) -> Result<AppConfig> {
    let _ = external;
    Err(r2_core::ConsoleError::not_implemented("R2"))
}
/// Mappings merge recursively (keys of `overlay` appended in their order when new);
/// scalars and sequences from `overlay` replace.
pub fn deep_merge(base: &Value, overlay: &Value) -> Value {
    let _ = (base, overlay);
    unimplemented!("R2")
}
/// The first existing discovery candidate, applying the hard-error rules (exposed for
/// `config path` tests): `--config` / non-empty `$R2_CONFIG` are `expand_user`-ed, and a
/// path that is not an existing regular FILE (c2 `Path.is_file()`) → "config file not
/// found: {path}" (the expanded path).
pub fn discover(cli_path: Option<&Path>) -> Result<Option<PathBuf>> {
    let _ = cli_path;
    Err(r2_core::ConsoleError::not_implemented("R2"))
}
