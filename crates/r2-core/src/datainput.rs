// R0 skeleton — owner R1 (generated from spec §4)
use crate::error::{ConsoleError, Result};
use crate::io::ConsoleIo;
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
        unimplemented!("R1")
    }
}
impl fmt::Display for InFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        unimplemented!("R1")
    }
}
/// Exact tokens; else Generic "unknown format {s!r}".
impl FromStr for InFormat {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        let _ = s;
        Err(crate::error::ConsoleError::not_implemented("R1"))
    }
}
impl OutFormat {
    pub fn as_str(self) -> &'static str {
        unimplemented!("R1")
    }
}
impl fmt::Display for OutFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        unimplemented!("R1")
    }
}
/// Exact tokens; else Generic "unknown format {s!r}".
impl FromStr for OutFormat {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        let _ = s;
        Err(crate::error::ConsoleError::not_implemented("R1"))
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
        let _ = token;
        unimplemented!("R1")
    }
    pub fn file(path: impl Into<PathBuf>, fmt: InFormat) -> Self {
        let _ = (path, fmt);
        unimplemented!("R1")
    }
    /// inline → decode_data; file raw → bytes verbatim; file hex/b64 → forced decode of the
    /// ASCII text (non-ASCII → Codec "{path}: file is not text, cannot decode as {fmt}",
    /// hint "use --format raw for binary files"); file auto → when the content is ASCII
    /// and every char is printable (0x20..=0x7E) or \t \r \n AND decode_data succeeds, the
    /// decoded bytes; otherwise the raw bytes. Read failure → DataIo
    /// "cannot read {path}: {os_error_text}". Neither token nor path → DataIo
    /// "data input has neither an inline token nor a file path".
    pub fn resolve(&self) -> Result<Zeroizing<Vec<u8>>> {
        Err(crate::error::ConsoleError::not_implemented("R1"))
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
        let _ = (group, width);
        unimplemented!("R1")
    }
    /// hex_group = 2, hex_width = 32.
    pub fn file(path: impl Into<PathBuf>, fmt: OutFormat) -> Self {
        let _ = (path, fmt);
        unimplemented!("R1")
    }
    /// Console → `io.print(Renderable::Text(format_hex(data, group, width)))`. File: Raw →
    /// bytes verbatim; Hex → continuous lower-case hex + "\n"; B64 → standard base64 + "\n".
    /// Write failure → DataIo "cannot write {path}: {os_error_text}".
    pub fn write(&self, data: &[u8], io: &dyn ConsoleIo) -> Result<()> {
        let _ = (data, io);
        Err(crate::error::ConsoleError::not_implemented("R1"))
    }
}
