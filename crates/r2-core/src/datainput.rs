// DataInput / DataOutput (spec §4.4.2; owner R1) — c2 `core/datainput.py`.
use base64::Engine as _;

use crate::codec::{decode_data, format_hex};
use crate::error::{ConsoleError, ErrorKind, Result};
use crate::io::{ConsoleIo, Renderable};
use crate::text::{os_error_text, py_repr};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use zeroize::Zeroizing;

/// Token: "auto" | "raw" | "hex" | "b64".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InFormat {
    #[default]
    Auto,
    Raw,
    Hex,
    B64,
}
/// Token: "raw" | "hex" | "b64" (the `--outformat` values).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutFormat {
    #[default]
    Raw,
    Hex,
    B64,
}

impl InFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            InFormat::Auto => "auto",
            InFormat::Raw => "raw",
            InFormat::Hex => "hex",
            InFormat::B64 => "b64",
        }
    }
}
impl fmt::Display for InFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Exact tokens; else Generic "unknown format {s!r}".
impl FromStr for InFormat {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        [InFormat::Auto, InFormat::Raw, InFormat::Hex, InFormat::B64]
            .into_iter()
            .find(|fmt| fmt.as_str() == s)
            .ok_or_else(|| ConsoleError::generic(format!("unknown format {}", py_repr(s))))
    }
}
impl OutFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            OutFormat::Raw => "raw",
            OutFormat::Hex => "hex",
            OutFormat::B64 => "b64",
        }
    }
}
impl fmt::Display for OutFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Exact tokens; else Generic "unknown format {s!r}".
impl FromStr for OutFormat {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        [OutFormat::Raw, OutFormat::Hex, OutFormat::B64]
            .into_iter()
            .find(|fmt| fmt.as_str() == s)
            .ok_or_else(|| ConsoleError::generic(format!("unknown format {}", py_repr(s))))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataInput {
    /// "inline" | the file path as displayed — for messages.
    pub origin: String,
    /// Inline form only.
    pub token: Option<String>,
    /// File form only.
    pub path: Option<PathBuf>,
    pub fmt: InFormat,
}
impl DataInput {
    pub fn inline(token: impl Into<String>) -> Self {
        Self {
            origin: "inline".to_owned(),
            token: Some(token.into()),
            path: None,
            fmt: InFormat::Auto,
        }
    }
    pub fn file(path: impl Into<PathBuf>, fmt: InFormat) -> Self {
        let path = path.into();
        Self {
            origin: path.display().to_string(),
            token: None,
            path: Some(path),
            fmt,
        }
    }
    /// inline → decode_data; file raw → bytes verbatim; file hex/b64 → forced decode of the
    /// ASCII text (non-ASCII → Codec "{path}: file is not text, cannot decode as {fmt}",
    /// hint "use --format raw for binary files"); file auto → when the content is ASCII
    /// and every char is printable (0x20..=0x7E) or \t \r \n AND decode_data succeeds, the
    /// decoded bytes; otherwise the raw bytes. Read failure → DataIo
    /// "cannot read {path}: {os_error_text}". Neither token nor path → DataIo
    /// "data input has neither an inline token nor a file path".
    pub fn resolve(&self) -> Result<Zeroizing<Vec<u8>>> {
        if let Some(token) = &self.token {
            return decode_data(token).map(|(data, _)| data);
        }
        let Some(path) = &self.path else {
            return Err(ConsoleError::data_io(
                "data input has neither an inline token nor a file path",
            ));
        };
        let raw = Zeroizing::new(std::fs::read(path).map_err(|err| {
            ConsoleError::data_io(format!(
                "cannot read {}: {}",
                path.display(),
                os_error_text(&err)
            ))
        })?);
        match self.fmt {
            InFormat::Raw => Ok(raw),
            InFormat::Hex | InFormat::B64 => {
                let text = std::str::from_utf8(&raw)
                    .ok()
                    .filter(|_| raw.is_ascii())
                    .ok_or_else(|| {
                        ConsoleError::codec(format!(
                            "{}: file is not text, cannot decode as {}",
                            path.display(),
                            self.fmt
                        ))
                        .with_hint("use --format raw for binary files")
                    })?;
                let forced = Zeroizing::new(format!("{}:{text}", self.fmt));
                decode_data(&forced).map(|(data, _)| data)
            }
            InFormat::Auto => {
                // printable ASCII (0x20..=0x7E) plus \t \r \n that passes decode_data → decoded;
                // anything else → the raw bytes.
                let printable = raw
                    .iter()
                    .all(|&b| (0x20..=0x7e).contains(&b) || matches!(b, b'\t' | b'\r' | b'\n'));
                if !printable {
                    return Ok(raw);
                }
                let Ok(text) = std::str::from_utf8(&raw) else {
                    return Ok(raw);
                };
                match decode_data(text) {
                    Ok((data, _)) => Ok(data),
                    Err(err) if err.kind == ErrorKind::Codec => Ok(raw),
                    Err(err) => Err(err),
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataOutput {
    /// None = console.
    pub path: Option<PathBuf>,
    pub fmt: OutFormat,
    /// Console rendering (from ui config).
    pub hex_group: usize,
    pub hex_width: usize,
}
impl DataOutput {
    pub fn console(group: usize, width: usize) -> Self {
        Self {
            path: None,
            fmt: OutFormat::Raw,
            hex_group: group,
            hex_width: width,
        }
    }
    /// hex_group = 2, hex_width = 32.
    pub fn file(path: impl Into<PathBuf>, fmt: OutFormat) -> Self {
        Self {
            path: Some(path.into()),
            fmt,
            hex_group: 2,
            hex_width: 32,
        }
    }
    /// Console → `io.print(Renderable::Text(format_hex(data, group, width)))`. File: Raw →
    /// bytes verbatim; Hex → continuous lower-case hex + "\n"; B64 → standard base64 + "\n".
    /// Write failure → DataIo "cannot write {path}: {os_error_text}".
    pub fn write(&self, data: &[u8], io: &dyn ConsoleIo) -> Result<()> {
        let Some(path) = &self.path else {
            io.print(Renderable::Text(format_hex(
                data,
                self.hex_group,
                self.hex_width,
            )));
            return Ok(());
        };
        let payload: Zeroizing<Vec<u8>> = match self.fmt {
            OutFormat::Raw => Zeroizing::new(data.to_vec()),
            OutFormat::Hex => Zeroizing::new(format!("{}\n", hex::encode(data)).into_bytes()),
            OutFormat::B64 => Zeroizing::new(
                format!(
                    "{}\n",
                    base64::engine::general_purpose::STANDARD.encode(data)
                )
                .into_bytes(),
            ),
        };
        std::fs::write(path, &*payload).map_err(|err| {
            ConsoleError::data_io(format!(
                "cannot write {}: {}",
                path.display(),
                os_error_text(&err)
            ))
        })
    }
}
