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

    /// Python `str.strip()` on a POSIX environment value, as `os.environ` sees it
    /// (surrogateescape): only valid UTF-8 can be whitespace (`text::is_py_space`), an
    /// undecodable byte never is, so non-UTF-8 values are trimmed byte for byte.
    pub(super) fn py_strip_bytes(bytes: &[u8]) -> &[u8] {
        use r2_core::text::is_py_space;
        let mut chunks = bytes.utf8_chunks();
        let start = chunks.next().map_or(0, |first| {
            let valid = first.valid();
            valid.len() - valid.trim_start_matches(is_py_space).len()
        });
        let end = match bytes.utf8_chunks().last() {
            Some(last) if last.invalid().is_empty() => {
                let valid = last.valid();
                bytes.len() - (valid.len() - valid.trim_end_matches(is_py_space).len())
            }
            _ => bytes.len(),
        };
        if start >= end {
            &[]
        } else {
            &bytes[start..end]
        }
    }

    /// The platform default base when $XDG_CONFIG_HOME is unset or blank: macOS
    /// `~/Library/Application Support`, elsewhere `os.path.expanduser("~/.config")`.
    fn default_config_base() -> Option<Vec<u8>> {
        let rest: &[u8] = if cfg!(target_os = "macos") {
            b"/Library/Application Support"
        } else {
            b"/.config"
        };
        Some(join_home(current_home()?, rest).into_os_string().into_vec())
    }

    /// platformdirs 4.10.1 `XDGMixin.user_config_dir` (Unix and MacOS alike): the
    /// STRIPPED $XDG_CONFIG_HOME when that is not blank, else the platform default
    /// (`default_config_base`); then `/r2`.
    pub(super) fn user_config_dir() -> Option<PathBuf> {
        let xdg = std::env::var_os("XDG_CONFIG_HOME").unwrap_or_default();
        let stripped = py_strip_bytes(xdg.as_bytes());
        let mut base = if stripped.is_empty() {
            default_config_base()?
        } else {
            stripped.to_vec()
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

#[cfg(all(test, unix))]
mod tests {
    use super::platform::py_strip_bytes;

    #[test]
    pub(super) fn py_strip_bytes_is_surrogateescape_str_strip() {
        assert_eq!(py_strip_bytes(b"  /tmp/abc \n"), b"/tmp/abc");
        assert_eq!(py_strip_bytes(b" \t\x0b\x0c\r\x1c\x1f"), b"");
        assert_eq!(py_strip_bytes(b""), b"");
        // U+00A0 / U+2003 are str whitespace; an undecodable byte (a surrogate) is not.
        assert_eq!(py_strip_bytes(b"\xc2\xa0/a\xe2\x80\x83"), b"/a");
        assert_eq!(py_strip_bytes(b" /\xff/x \n"), b"/\xff/x");
        assert_eq!(py_strip_bytes(b"\xff "), b"\xff");
        assert_eq!(py_strip_bytes(b" \xa0/x"), b"\xa0/x");
        assert_eq!(py_strip_bytes(b"/x\xc2"), b"/x\xc2");
    }
}
