// platformdirs-compatible config dir and `~` expansion (spec §4.8.1; owner R2).
use std::path::{Path, PathBuf};

use crate::loader::APP_DIR;

/// platformdirs-compatible `user_config_dir("r2")` (rules above); no extra dependency:
/// home = `std::env::home_dir()`, Windows base = `%LOCALAPPDATA%` (platformdirs' env
/// fallback). None when that lookup fails.
pub fn user_config_dir() -> Option<PathBuf> {
    platform::user_config_dir()
}

/// Python `Path(p).expanduser()`: `text::py_path(p)` first (c2 always built the `Path`
/// before expanding), then a leading `~` or `~/…` (`~\…` on Windows) → home dir; anything
/// else is the normalized path.
///
/// POSIX details (`posixpath.expanduser`): `~` is `$HOME` used as is whenever it is set
/// (even empty: `~/x` → `/x`), else the passwd home; `~name/…` is that user's home from
/// `/etc/passwd`; an unknown user (or no home at all) keeps the path literally (§11 D17 (g)).
pub fn expand_user(path: &str) -> PathBuf {
    platform::expand(Path::new(path))
}

/// `expand_user` for a path that may not be valid UTF-8 (`--config`, `$R2_CONFIG`): POSIX
/// paths are handled byte for byte, like Python's surrogateescape round trip.
pub(crate) fn expand_user_path(path: &Path) -> PathBuf {
    platform::expand(path)
}

#[cfg(unix)]
mod platform {
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};

    use super::APP_DIR;

    /// `text::py_path`'s PurePosixPath rules on bytes: repeated `/` collapse, `.` parts are
    /// dropped, a trailing `/` is dropped, exactly two leading slashes are kept, empty → `.`.
    pub(super) fn normalize(bytes: &[u8]) -> Vec<u8> {
        let leading = bytes.iter().take_while(|&&b| b == b'/').count();
        let mut out: Vec<u8> = match leading {
            0 => Vec::new(),
            2 => b"//".to_vec(),
            _ => b"/".to_vec(),
        };
        let mut first = true;
        for part in bytes.split(|&b| b == b'/') {
            if part.is_empty() || part == b"." {
                continue;
            }
            if !first {
                out.push(b'/');
            }
            out.extend_from_slice(part);
            first = false;
        }
        if out.is_empty() {
            out.push(b'.');
        }
        out
    }

    fn from_bytes(bytes: Vec<u8>) -> PathBuf {
        PathBuf::from(OsString::from_vec(bytes))
    }

    /// `os.path.expanduser("~")`'s home: `$HOME` as is when set (even empty), else the
    /// passwd entry of the current user (`std::env::home_dir`, which then uses getpwuid).
    fn current_home() -> Option<Vec<u8>> {
        match std::env::var_os("HOME") {
            Some(home) => Some(home.into_vec()),
            None => std::env::home_dir().map(|home| home.into_os_string().into_vec()),
        }
    }

    /// `pwd.getpwnam(name).pw_dir`, read from /etc/passwd (no libc call needed).
    fn user_home(name: &[u8]) -> Option<Vec<u8>> {
        let passwd = std::fs::read("/etc/passwd").ok()?;
        passwd.split(|&b| b == b'\n').find_map(|line| {
            let mut fields = line.split(|&b| b == b':');
            if fields.next()? != name {
                return None;
            }
            fields.nth(4).map(<[u8]>::to_vec)
        })
    }

    /// `userhome.rstrip('/') + rest`, `or '/'` (posixpath.expanduser), then `Path(…)`.
    fn join_home(home: Vec<u8>, rest: &[u8]) -> PathBuf {
        let mut home = home;
        while home.last() == Some(&b'/') {
            home.pop();
        }
        let mut joined = home;
        joined.extend_from_slice(rest);
        if joined.is_empty() {
            joined.push(b'/');
        }
        from_bytes(normalize(&joined))
    }

    pub(super) fn expand(path: &Path) -> PathBuf {
        let normalized = normalize(path.as_os_str().as_bytes());
        if normalized.first() != Some(&b'~') {
            return from_bytes(normalized);
        }
        let end = normalized
            .iter()
            .position(|&b| b == b'/')
            .unwrap_or(normalized.len());
        let (first, rest) = normalized.split_at(end);
        let home = if first.len() == 1 {
            current_home()
        } else {
            user_home(&first[1..])
        };
        match home {
            Some(home) => join_home(home, rest),
            None => from_bytes(normalized),
        }
    }

    #[cfg(target_os = "macos")]
    pub(super) fn user_config_dir() -> Option<PathBuf> {
        let home = current_home()?;
        Some(join_home(
            home,
            format!("/Library/Application Support/{APP_DIR}").as_bytes(),
        ))
    }

    /// platformdirs `Unix.user_config_dir`: $XDG_CONFIG_HOME when set and not blank
    /// (`path.strip()`), else `os.path.expanduser("~/.config")`; then `/r2`.
    #[cfg(not(target_os = "macos"))]
    pub(super) fn user_config_dir() -> Option<PathBuf> {
        use r2_core::text::py_strip;
        let xdg = std::env::var_os("XDG_CONFIG_HOME").unwrap_or_default();
        let mut base = if py_strip(&xdg.to_string_lossy()).is_empty() {
            let home = join_home(current_home()?, b"/.config");
            home.into_os_string().into_vec()
        } else {
            xdg.into_vec()
        };
        base.push(b'/');
        base.extend_from_slice(OsStr::new(APP_DIR).as_bytes());
        Some(from_bytes(normalize(&base)))
    }
}

#[cfg(not(unix))]
mod platform {
    use std::path::{Path, PathBuf};

    use r2_core::text::py_path;

    use super::APP_DIR;

    /// The home directory as text (`os.path.expanduser("~")`); None when unknown.
    fn home_text() -> Option<String> {
        let home = std::env::home_dir()?;
        Some(home.to_string_lossy().into_owned())
    }

    pub(super) fn user_config_dir() -> Option<PathBuf> {
        // platformdirs Windows: user_config_dir = user_data_dir (roaming=False → Local),
        // appauthor defaults to appname: %LOCALAPPDATA%\r2\r2.
        let base = std::env::var("LOCALAPPDATA").ok()?;
        if base.is_empty() {
            return None;
        }
        Some(py_path(&format!("{base}\\{APP_DIR}\\{APP_DIR}")))
    }

    pub(super) fn expand(path: &Path) -> PathBuf {
        let normalized = py_path(&path.to_string_lossy());
        let text = normalized.to_string_lossy();
        let separators: &[char] = &['/', '\\'];
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
}
