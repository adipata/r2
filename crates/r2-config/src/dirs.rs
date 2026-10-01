// platformdirs-compatible config dir and `~` expansion (spec §4.8.1; owner R2).
use std::path::PathBuf;

use r2_core::text::py_path;

use crate::loader::APP_DIR;

/// platformdirs-compatible `user_config_dir("r2")` (rules above); no extra dependency:
/// home = `std::env::home_dir()`, Windows base = `%LOCALAPPDATA%` (platformdirs' env
/// fallback). None when that lookup fails.
pub fn user_config_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        // platformdirs Windows: user_config_dir = user_data_dir (roaming=False → Local),
        // appauthor defaults to appname: %LOCALAPPDATA%\r2\r2.
        let base = std::env::var("LOCALAPPDATA").ok()?;
        if base.is_empty() {
            return None;
        }
        return Some(py_path(&format!("{base}\\{APP_DIR}\\{APP_DIR}")));
    }
    if cfg!(target_os = "macos") {
        let home = home_text()?;
        return Some(py_path(&format!(
            "{home}/Library/Application Support/{APP_DIR}"
        )));
    }
    // Unix (platformdirs `Unix.user_config_dir`): $XDG_CONFIG_HOME when set and not blank
    // (`path.strip()`), else `os.path.expanduser("~/.config")`.
    let xdg = std::env::var("XDG_CONFIG_HOME").unwrap_or_default();
    let base = if xdg.trim().is_empty() {
        format!("{}/.config", home_text()?)
    } else {
        xdg
    };
    Some(py_path(&format!("{base}/{APP_DIR}")))
}

/// The home directory as text (`os.path.expanduser("~")`); None when unknown.
fn home_text() -> Option<String> {
    let home = std::env::home_dir()?;
    Some(home.to_string_lossy().into_owned())
}

/// Python `Path(p).expanduser()`: `text::py_path(p)` first (c2 always built the `Path`
/// before expanding), then a leading `~` or `~/…` (`~\…` on Windows) → home dir; anything
/// else is the normalized path.
pub fn expand_user(path: &str) -> PathBuf {
    let normalized = py_path(path);
    let text = normalized.to_string_lossy();
    let separators: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    let rest = if text == "~" {
        Some("")
    } else {
        text.strip_prefix('~')
            .filter(|rest| rest.starts_with(separators))
    };
    match (rest, home_text()) {
        (Some(rest), Some(home)) => {
            // Path(home) / tail, normalized like every c2 Path.
            let joined = PathBuf::from(home).join(rest.trim_start_matches(separators));
            py_path(&joined.to_string_lossy())
        }
        _ => normalized,
    }
}
