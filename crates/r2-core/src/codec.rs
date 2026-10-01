// Input codec (spec §4.4.1; owner R1): operator-pasted data → bytes. A faithful port of c2's
// `core/codec.py` (its regexes are emulated by hand: r2-core has no regex dependency).
use zeroize::Zeroizing;

use crate::error::{ConsoleError, Result};
use crate::text::{is_py_space, py_splitlines, py_strip};

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
        match self {
            InputFormat::Hex => "hex",
            InputFormat::Base64 => "base64",
            InputFormat::Pem => "pem",
        }
    }
}

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_LINE_LEN: usize = 64;

/// Decode operator-pasted data (algorithm below). Errors → Codec (with hint).
///
/// Detection order (frozen, c2 verbatim): explicit prefix (`hex:`/`0x`, `b64:`, `pem:`; no
/// fallback on failure) → `-----BEGIN ` anywhere → PEM → strip all whitespace (empty is an
/// error) → even-length hex (hex-wrapped PEM re-parsed) → padded base64 (base64-wrapped PEM
/// re-parsed) → "not hex, base64 or PEM". Hex beats base64 for ambiguous text. PEM branches
/// return the re-wrapped PEM TEXT as bytes, never DER.
pub fn decode_data(text: &str) -> Result<(Zeroizing<Vec<u8>>, InputFormat)> {
    let stripped = py_strip(text);
    if let Some(rest) = stripped.strip_prefix("hex:") {
        return Ok((forced_hex(rest)?, InputFormat::Hex));
    }
    if let Some(rest) = stripped.strip_prefix("0x") {
        return Ok((forced_hex(rest)?, InputFormat::Hex));
    }
    if let Some(rest) = stripped.strip_prefix("b64:") {
        return Ok((forced_b64(rest)?, InputFormat::Base64));
    }
    if let Some(rest) = stripped.strip_prefix("pem:") {
        return Ok((rewrap_pem(rest)?, InputFormat::Pem));
    }

    if text.contains(PEM_BEGIN) {
        return Ok((rewrap_pem(text)?, InputFormat::Pem));
    }

    let compact = remove_whitespace(text);
    if compact.is_empty() {
        return Err(ConsoleError::codec("empty input").with_hint("paste hex, base64 or PEM data"));
    }

    if is_hex_text(&compact)
        && compact.len().is_multiple_of(2)
        && let Some(data) = hex_decode(&compact)
    {
        if data.starts_with(b"-----BEGIN") {
            return Ok((reparse_wrapped_pem(&data, "hex")?, InputFormat::Pem));
        }
        return Ok((data, InputFormat::Hex));
    }

    if is_b64_text(&compact)
        && compact.len().is_multiple_of(4)
        && let Some(data) = b64decode_strict(&compact)
    {
        if data.starts_with(b"-----BEGIN") {
            return Ok((reparse_wrapped_pem(&data, "base64")?, InputFormat::Pem));
        }
        return Ok((data, InputFormat::Base64));
    }

    Err(ConsoleError::codec("not hex, base64 or PEM").with_hint("force with hex:/b64:/pem: prefix"))
}

/// Grouped lower-case hex for console display. `group` = bytes per space-separated group
/// (0 → continuous); `width` = bytes per line (0 → one line). Empty input → "".
/// Defaults are ui.hex_group=2 / ui.hex_width=32.
pub fn format_hex(data: &[u8], group: usize, width: usize) -> String {
    if data.is_empty() {
        return String::new();
    }
    let line_bytes = if width > 0 { width } else { data.len() };
    let lines: Vec<String> = data
        .chunks(line_bytes)
        .map(|chunk| {
            if group > 0 {
                chunk
                    .chunks(group)
                    .map(hex::encode)
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                hex::encode(chunk)
            }
        })
        .collect();
    lines.join("\n")
}

// ---- helpers ---------------------------------------------------------------------------

/// c2 `_WS_RE.sub("", text)` (`\s` of a str pattern = `str.isspace()`). The result is the
/// pasted secret (hex/base64 text of a key): one allocation of `text.len()` bytes, never
/// reallocated, wiped on drop.
fn remove_whitespace(text: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    out.extend(text.chars().filter(|&c| !is_py_space(c)));
    out
}

/// `bytes.fromhex` of validated hex text (even length, hex digits only) into one
/// zeroizing buffer; None if the text is not hex after all.
fn hex_decode(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(vec![0u8; text.len() / 2]);
    hex::decode_to_slice(text, &mut out[..]).ok()?;
    Some(out)
}

/// `^[0-9A-Fa-f]+$`
fn is_hex_text(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `^[A-Za-z0-9+/]+={0,2}$`
fn is_b64_text(text: &str) -> bool {
    let body = text.trim_end_matches('=');
    let padding = text.len() - body.len();
    padding <= 2
        && !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

fn forced_hex(content: &str) -> Result<Zeroizing<Vec<u8>>> {
    let compact = remove_whitespace(content);
    if compact.is_empty() {
        return Err(ConsoleError::codec("hex prefix given but no data follows"));
    }
    let failed = || {
        ConsoleError::codec("forced hex decode failed")
            .with_hint("hex is an even number of [0-9a-fA-F] digits (whitespace ignored)")
    };
    if !is_hex_text(&compact) || !compact.len().is_multiple_of(2) {
        return Err(failed());
    }
    hex_decode(&compact).ok_or_else(failed)
}

fn forced_b64(content: &str) -> Result<Zeroizing<Vec<u8>>> {
    let compact = remove_whitespace(content);
    if compact.is_empty() {
        return Err(ConsoleError::codec("b64 prefix given but no data follows"));
    }
    if !is_b64_text(&compact) || !compact.len().is_multiple_of(4) {
        return Err(ConsoleError::codec("forced base64 decode failed")
            .with_hint("base64 uses [A-Za-z0-9+/] with '=' padding to a multiple of 4"));
    }
    b64decode_strict(&compact).ok_or_else(|| ConsoleError::codec("forced base64 decode failed"))
}

/// Python `base64.b64decode(text, validate=True)` (= `binascii.a2b_base64(strict_mode=True)`
/// of CPython 3.12), ported verbatim: alphabet only, no leading padding, no data after a
/// completing pad, no discontinuous padding, extra '=' after a complete quad tolerated,
/// non-zero trailing bits accepted. None where Python raises (incl. non-ASCII text, which
/// Python rejects before decoding).
fn b64decode_strict(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let data = text.as_bytes();
    if !text.is_ascii() || data.first() == Some(&b'=') {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(data.len() / 4 * 3 + 3));
    let mut padding_started = false;
    let mut quad_pos = 0u8;
    let mut left: u8 = 0;
    let mut pads = 0u8;
    for (index, &byte) in data.iter().enumerate() {
        if byte == b'=' {
            padding_started = true;
            pads += 1;
            if quad_pos >= 2 && quad_pos + pads >= 4 {
                // A completing pad: strict mode refuses anything after it.
                return (index + 1 == data.len()).then_some(out);
            }
            continue;
        }
        let value = b64_value(byte)?;
        if padding_started {
            return None;
        }
        pads = 0;
        match quad_pos {
            0 => {
                quad_pos = 1;
                left = value;
            }
            1 => {
                quad_pos = 2;
                out.push(left << 2 | value >> 4);
                left = value & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push(left << 4 | value >> 2);
                left = value & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push(left << 6 | value);
                left = 0;
            }
        }
    }
    (quad_pos == 0).then_some(out)
}

fn b64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn reparse_wrapped_pem(data: &[u8], wrapper: &str) -> Result<Zeroizing<Vec<u8>>> {
    match std::str::from_utf8(data) {
        Ok(text) if data.is_ascii() => rewrap_pem(text),
        _ => Err(ConsoleError::codec(format!(
            "data looks like {wrapper}-wrapped PEM but is not ASCII text"
        ))),
    }
}

/// One match of c2's `_PEM_BLOCK_RE` (byte ranges into the searched text).
struct PemMatch<'a> {
    begin_label: &'a str,
    body: &'a str,
    end_label: &'a str,
}

/// `[A-Za-z0-9][A-Za-z0-9 ]*?` followed by `-----` at `start`: the label's end offset.
/// The lazy quantifier can only stop where `-----` begins, and label characters exclude
/// '-', so the label is the maximal label-character run.
fn pem_label_end(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if !bytes.get(start)?.is_ascii_alphanumeric() {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b' ')
    {
        end += 1;
    }
    text[end..].starts_with("-----").then_some(end)
}

/// `re.finditer(r"-----BEGIN (L)-----(.*?)-----END (L)-----", text, re.DOTALL)` with
/// L = `[A-Za-z0-9][A-Za-z0-9 ]*?`, emulated on bytes (every literal is ASCII, so byte
/// offsets never split a UTF-8 sequence).
fn find_pem_blocks(text: &str) -> Vec<PemMatch<'_>> {
    let mut matches = Vec::new();
    let mut search_from = 0;
    while let Some(found) = text[search_from..].find(PEM_BEGIN) {
        let begin = search_from + found;
        let label_start = begin + PEM_BEGIN.len();
        let attempt = pem_label_end(text, label_start).and_then(|label_end| {
            let body_start = label_end + 5;
            let mut candidate = body_start;
            while let Some(offset) = text[candidate..].find("-----END ") {
                let end_marker = candidate + offset;
                let end_label_start = end_marker + "-----END ".len();
                if let Some(end_label_end) = pem_label_end(text, end_label_start) {
                    return Some((
                        PemMatch {
                            begin_label: &text[label_start..label_end],
                            body: &text[body_start..end_marker],
                            end_label: &text[end_label_start..end_label_end],
                        },
                        end_label_end + 5,
                    ));
                }
                candidate = end_marker + 1;
            }
            None
        });
        match attempt {
            Some((found_match, match_end)) => {
                matches.push(found_match);
                search_from = match_end;
            }
            None => search_from = begin + 1,
        }
    }
    matches
}

/// `^[A-Za-z][A-Za-z0-9-]*:` (RFC 1421 encapsulated header line, e.g. "DEK-Info: …").
fn is_pem_header_line(line: &str) -> bool {
    let bytes = line.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_alphabetic) {
        return false;
    }
    for &byte in &bytes[1..] {
        if byte == b':' {
            return true;
        }
        if !(byte.is_ascii_alphanumeric() || byte == b'-') {
            return false;
        }
    }
    false
}

/// c2 `_split_pem_headers`: (header lines, remaining body text — a copy of the secret
/// base64, wiped on drop).
fn split_pem_headers(body: &str) -> (Vec<&str>, Zeroizing<String>) {
    let lines = py_splitlines(body);
    let mut index = 0;
    while index < lines.len() && py_strip(lines[index]).is_empty() {
        index += 1;
    }
    let mut headers = Vec::new();
    while index < lines.len() {
        let line = py_strip(lines[index]);
        if line.is_empty() {
            index += 1; // the blank separator line closes the header section
            break;
        }
        if !is_pem_header_line(line) {
            break;
        }
        headers.push(line);
        index += 1;
    }
    if headers.is_empty() {
        return (headers, Zeroizing::new(body.to_owned()));
    }
    // `join` allocates the exact length once.
    (headers, Zeroizing::new(lines[index..].join("\n")))
}

/// c2 `_rewrap_pem`: every block kept in order, RFC 1421 headers preserved (plus one blank
/// line), body whitespace removed, validated, re-wrapped at 64 columns; blocks joined with
/// "\n", trailing "\n".
fn rewrap_pem(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let blocks_found = find_pem_blocks(text);
    if blocks_found.is_empty() {
        return Err(
            ConsoleError::codec("malformed PEM: no complete BEGIN/END block found")
                .with_hint("a PEM block is '-----BEGIN <LABEL>----- … -----END <LABEL>-----'"),
        );
    }
    // Every intermediate holds the secret's text: wiped on drop, allocated once.
    let mut blocks: Vec<Zeroizing<String>> = Vec::with_capacity(blocks_found.len());
    for block in blocks_found {
        let begin_label = py_strip(block.begin_label);
        let end_label = py_strip(block.end_label);
        if begin_label != end_label {
            return Err(ConsoleError::codec(format!(
                "malformed PEM: 'BEGIN {begin_label}' closed by 'END {end_label}'"
            )));
        }
        let (headers, base64_text) = split_pem_headers(block.body);
        let body = remove_whitespace(&base64_text);
        if !headers.is_empty() && body.is_empty() {
            return Err(ConsoleError::codec(format!(
                "malformed PEM: the {begin_label} block has encapsulated headers but no base64 body"
            ))
            .with_hint("paste the block with its line breaks intact"));
        }
        if b64decode_strict(&body).is_none() {
            return Err(ConsoleError::codec(format!(
                "malformed PEM: body of the {begin_label} block is not valid base64"
            )));
        }
        let mut lines: Vec<&str> = vec![];
        let begin = format!("-----BEGIN {begin_label}-----");
        lines.push(&begin);
        lines.extend(headers.iter().copied());
        if !headers.is_empty() {
            lines.push(""); // RFC 1421: a blank line terminates the header section
        }
        // The validated body is ASCII, so 64-byte chunks are 64-character lines.
        let mut rest = body.as_str();
        while !rest.is_empty() {
            let (line, tail) = rest.split_at(rest.len().min(PEM_LINE_LEN));
            lines.push(line);
            rest = tail;
        }
        let end = format!("-----END {begin_label}-----");
        lines.push(&end);
        blocks.push(Zeroizing::new(lines.join("\n")));
    }
    let total = blocks.iter().map(|block| block.len() + 1).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    for (index, block) in blocks.iter().enumerate() {
        if index > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(block.as_bytes());
    }
    out.push(b'\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64decode_strict_matches_cpython_binascii() {
        // (input, CPython 3.12 `base64.b64decode(s, validate=True).hex()` or None = raises)
        let cases: &[(&str, Option<&str>)] = &[
            ("", Some("")),
            ("A", None),
            ("AA", None),
            ("AAA", None),
            ("AAAA", Some("000000")),
            ("AA=", None),
            ("AA==", Some("00")),
            ("AAA=", Some("0000")),
            ("AAA==", None),
            ("AA===", None),
            ("AAAA=", Some("000000")),
            ("AAAA==", Some("000000")),
            ("AAAA====", Some("000000")),
            ("AA==AA==", None),
            ("AAA=AAAA", None),
            ("=AAA", None),
            ("A=AA", None),
            ("AB==", Some("00")),
            ("AAB=", Some("0000")),
            ("AAAAB===", None),
            ("AQ==", Some("01")),
            ("AR==", Some("01")),
            ("+/+/", Some("fbffbf")),
            ("-_-_", None),
            ("AAAA\n", None),
            ("AA AA", None),
            ("ABC=D", None),
            ("AAAAAA==", Some("00000000")),
            ("AAAAAAA=", Some("0000000000")),
            ("AAAAA", None),
            ("SGVsbG8=", Some("48656c6c6f")),
            ("deadbeef", Some("75e69d6de79f")),
            ("AAAé", None),
        ];
        for (input, expected) in cases {
            let got = b64decode_strict(input).map(|data| hex::encode(&*data));
            assert_eq!(got.as_deref(), *expected, "input {input:?}");
        }
    }

    #[test]
    fn pem_block_scan_emulates_the_c2_regex() {
        let blocks = find_pem_blocks("x -----BEGIN A B -----body-----END A B -----tail");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].begin_label, "A B ");
        assert_eq!(blocks[0].body, "body");
        assert_eq!(blocks[0].end_label, "A B ");
        // A BEGIN without a valid label is skipped; the scan resumes after it.
        let blocks = find_pem_blocks("-----BEGIN -----BEGIN X-----b-----END X-----");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].begin_label, "X");
        // The lazy body skips an END marker whose label does not match the grammar.
        let blocks = find_pem_blocks("-----BEGIN X-----a-----END !-----b-----END X-----");
        assert_eq!(blocks[0].body, "a-----END !-----b");
        // The first acceptable END closes the block, even with another label.
        let blocks = find_pem_blocks("-----BEGIN A-----x-----BEGIN B-----y-----END B-----");
        assert_eq!(blocks.len(), 1);
        assert_eq!((blocks[0].begin_label, blocks[0].end_label), ("A", "B"));
        assert!(find_pem_blocks("-----BEGIN X-----no end").is_empty());
        assert!(find_pem_blocks("-----BEGIN x").is_empty());
    }

    #[test]
    fn pem_header_line_grammar() {
        assert!(is_pem_header_line("Proc-Type: 4,ENCRYPTED"));
        assert!(is_pem_header_line("DEK-Info:x"));
        assert!(is_pem_header_line("a:"));
        assert!(!is_pem_header_line("1a: x"));
        assert!(!is_pem_header_line("MIIB/abc"));
        assert!(!is_pem_header_line("Proc Type: x"));
        assert!(!is_pem_header_line(""));
    }
}
