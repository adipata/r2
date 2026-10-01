// R0 skeleton — owner R2 (generated from spec §4)
// ---- spec §4.8.1 block 0
use std::path::PathBuf;

/// platformdirs-compatible `user_config_dir("r2")` (rules above); no extra dependency:
/// home = `std::env::home_dir()`, Windows base = `%LOCALAPPDATA%` (platformdirs' env
/// fallback). None when that lookup fails.
pub fn user_config_dir() -> Option<PathBuf> {
    unimplemented!("R2")
}
/// Python `Path(p).expanduser()`: `text::py_path(p)` first (c2 always built the `Path`
/// before expanding), then a leading `~` or `~/…` (`~\…` on Windows) → home dir; anything
/// else is the normalized path.
pub fn expand_user(path: &str) -> PathBuf {
    let _ = path;
    unimplemented!("R2")
}
