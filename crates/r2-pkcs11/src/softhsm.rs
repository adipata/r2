//! SoftHSM2 module detection (spec §4.5.5 / §5.13) — pure path probing, never loads a
//! library.
use std::path::PathBuf;
/// Environment variable overriding the probe list.
pub const SOFTHSM2_LIB_ENV: &str = "SOFTHSM2_LIB";
/// `$SOFTHSM2_LIB` (non-empty; `text::py_path`-normalized, no `~` expansion — c2
/// `Path(override)`) wins: returned iff it exists (an explicit override never
/// falls through). Otherwise the first existing path of `search_paths` (the caller passes
/// `AppConfig.softhsm.search_paths`); None when nothing exists.
pub fn find_softhsm_module(search_paths: &[PathBuf]) -> Option<PathBuf> {
    if let Some(value) = std::env::var_os(SOFTHSM2_LIB_ENV)
        && !value.is_empty()
    {
        let path = match value.to_str() {
            Some(text) => r2_core::text::py_path(text),
            None => PathBuf::from(value),
        };
        return path.exists().then_some(path);
    }
    search_paths.iter().find(|p| p.exists()).cloned()
}
