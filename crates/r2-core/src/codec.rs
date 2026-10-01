// R0 skeleton — owner R1 (generated from spec §4)
use crate::error::Result;
use zeroize::Zeroizing;

/// `decode_data` outcomes only. Token (`as_str()` only; no Display/FromStr): "hex" |
/// "base64" | "pem".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputFormat {
    Hex,
    Base64,
    Pem,
}
impl InputFormat {
    pub fn as_str(self) -> &'static str {
        unimplemented!("R1")
    }
}

/// Decode operator-pasted data (algorithm below). Errors → Codec (with hint).
pub fn decode_data(text: &str) -> Result<(Zeroizing<Vec<u8>>, InputFormat)> {
    let _ = text;
    Err(crate::error::ConsoleError::not_implemented("R1"))
}

/// Grouped lower-case hex for console display. `group` = bytes per space-separated group
/// (0 → continuous); `width` = bytes per line (0 → one line). Empty input → "".
/// Defaults are ui.hex_group=2 / ui.hex_width=32.
pub fn format_hex(data: &[u8], group: usize, width: usize) -> String {
    let _ = (data, group, width);
    unimplemented!("R1")
}
