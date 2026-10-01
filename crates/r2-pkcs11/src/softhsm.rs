// R0 skeleton — owner R5a (generated from spec §4)
// ---- spec §4.5.5 block 4
use std::path::PathBuf;
/// Environment variable overriding the probe list.
pub const SOFTHSM2_LIB_ENV: &str = "SOFTHSM2_LIB";
/// `$SOFTHSM2_LIB` (non-empty; `text::py_path`-normalized, no `~` expansion — c2
/// `Path(override)`) wins: returned iff it exists (an explicit override never
/// falls through). Otherwise the first existing path of `search_paths` (the caller passes
/// `AppConfig.softhsm.search_paths`); None when nothing exists.
pub fn find_softhsm_module(search_paths: &[PathBuf]) -> Option<PathBuf> {
    let _ = search_paths;
    unimplemented!("R5a")
}
