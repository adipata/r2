// Message-parity helpers (spec §4.2; owner R1): Python-faithful repr/strip/int/path/difflib.
use std::collections::HashMap;
use std::path::PathBuf;

/// Python `repr(str)` of CPython 3.12 (c2's interpreter; Unicode 15.0.0): single quotes
/// unless the text contains `'` and no `"`; escapes `\\`, the chosen quote, `\n` `\r` `\t`,
/// and every other code point for which CPython's `str.isprintable()` is false as
/// `\xNN` / `\uNNNN` / `\UNNNNNNNN` (lower-case hex). The non-printable set (categories
/// Cc, Cf, Cs, Co, Cn, Zl, Zp, Zs except U+0020 — 712 ranges at Unicode 15.0) is a static
/// range table committed in this file, generated once from CPython
/// (`not chr(c).isprintable()`); `char::is_control` is NOT a substitute. Every c2 message
/// written `{x!r}` uses this.
pub fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if is_py_printable(c) => out.push(c),
            c => {
                let code = u32::from(c);
                if code <= 0xff {
                    out.push_str(&format!("\\x{code:02x}"));
                } else if code <= 0xffff {
                    out.push_str(&format!("\\u{code:04x}"));
                } else {
                    out.push_str(&format!("\\U{code:08x}"));
                }
            }
        }
    }
    out.push(quote);
    out
}
/// Python `repr(bytes)`: `b'…'` with the same quote choice, `\\`, `\t` `\n` `\r`,
/// printable ASCII 0x20..=0x7E verbatim, everything else `\xNN`.
pub fn py_bytes_repr(data: &[u8]) -> String {
    let quote = if data.contains(&b'\'') && !data.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::with_capacity(data.len() + 3);
    out.push('b');
    out.push(char::from(quote));
    for &byte in data {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b if b == quote => {
                out.push('\\');
                out.push(char::from(b));
            }
            0x20..=0x7e => out.push(char::from(byte)),
            b => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out.push(char::from(quote));
    out
}
/// Python `str(bool)`: "True" / "False".
pub fn py_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}
/// Python `OSError.strerror` equivalent: `err.to_string()` without the trailing
/// " (os error N)" (c2 messages use `{exc.strerror or exc}`).
pub fn os_error_text(err: &std::io::Error) -> String {
    let text = err.to_string();
    match err.raw_os_error() {
        Some(code) => text
            .strip_suffix(&format!(" (os error {code})"))
            .map(str::to_owned)
            .unwrap_or(text),
        None => text,
    }
}
/// Python `str(OSError)` for a one-path error: "[Errno {n}] {strerror}: {py_repr(path)}"
/// (e.g. "[Errno 13] Permission denied: '/p'"); without a raw OS error code →
/// `os_error_text(err)`. (Windows prints `[WinError n]` for some calls in CPython; r2 always
/// uses the POSIX form — D18.)
pub fn py_os_error_str(err: &std::io::Error, path: &std::path::Path) -> String {
    match err.raw_os_error() {
        Some(code) => format!(
            "[Errno {code}] {}: {}",
            os_error_text(err),
            py_repr(&path.to_string_lossy())
        ),
        None => os_error_text(err),
    }
}
/// Python `str.isspace()` for one char (`char::is_whitespace` plus U+001C..=U+001F).
pub fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}
/// Python `str.strip()` (no argument): trims leading/trailing chars where `is_py_space`.
/// Every c2 `.strip()` site — including ParamResolver's "trimmed" — uses this, never
/// `str::trim` (which keeps U+001C..=U+001F).
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(is_py_space)
}
/// Python `bytes.fromhex`: pairs of hex digits (either case); ASCII whitespace is skipped
/// BETWEEN pairs only ("0a 1b" ok, "0 a" invalid); None on any error. c2 uses it in
/// `--id` parsing, config/template-file `0x…` values and the template editor.
pub fn py_fromhex(text: &str) -> Option<Vec<u8>> {
    // CPython `_PyBytes_FromHex`: non-ASCII input is an error; ASCII whitespace
    // (Py_ISSPACE: space, \t, \n, \r, \x0b, \x0c) is skipped before each pair only.
    if !text.is_ascii() {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        if is_ascii_space(bytes[i]) {
            i += 1;
            continue;
        }
        let high = hex_value(bytes[i])?;
        let low = hex_value(*bytes.get(i + 1)?)?;
        out.push(high << 4 | low);
        i += 2;
    }
    Some(out)
}
/// Python `int(text, radix)` for radix 10 or 16: strip CPython `int()`'s whitespace first
/// (`py_strip`'s set minus U+001C..=U+001F, which `int()` keeps), optional `+`/`-`, for
/// radix 16 an optional `0x`/`0X` prefix (which may be followed by one `_`), digits with
/// single `_` separators between digits; ASCII digits only (CPython also accepts other
/// Unicode decimal digits — D18). None on any error or outside i128.
pub fn py_int(text: &str, radix: u32) -> Option<i128> {
    if radix != 10 && radix != 16 {
        return None;
    }
    // CPython `int()`: non-ASCII whitespace becomes ' '
    // (`_PyUnicode_TransformDecimalAndSpaceToASCII`), then ASCII whitespace (`Py_ISSPACE`) is
    // skipped — so unlike `py_strip`, U+001C..=U+001F are NOT stripped.
    let mut rest =
        text.trim_matches(|c: char| is_py_space(c) && !('\u{1c}'..='\u{1f}').contains(&c));
    let negative = match rest.as_bytes().first() {
        Some(b'-') => {
            rest = &rest[1..];
            true
        }
        Some(b'+') => {
            rest = &rest[1..];
            false
        }
        _ => false,
    };
    if radix == 16 && (rest.starts_with("0x") || rest.starts_with("0X")) {
        rest = &rest[2..];
        // CPython: "One underscore allowed here."
        if let Some(tail) = rest.strip_prefix('_') {
            rest = tail;
        }
    }
    let digits = rest.as_bytes();
    if digits.is_empty() || digits[0] == b'_' || digits[digits.len() - 1] == b'_' {
        return None;
    }
    let mut value: i128 = 0;
    let mut previous_underscore = false;
    for &byte in digits {
        if byte == b'_' {
            if previous_underscore {
                return None;
            }
            previous_underscore = true;
            continue;
        }
        previous_underscore = false;
        let digit = match (radix, byte) {
            (_, b'0'..=b'9') => byte - b'0',
            (16, b'a'..=b'f') => byte - b'a' + 10,
            (16, b'A'..=b'F') => byte - b'A' + 10,
            _ => return None,
        };
        // Accumulate negatively so i128::MIN stays representable.
        value = value
            .checked_mul(i128::from(radix))?
            .checked_sub(i128::from(digit))?;
    }
    if negative {
        Some(value)
    } else {
        value.checked_neg()
    }
}
/// Python `str.isdigit()` as c2 uses it to gate `int()`: non-empty and every char an ASCII
/// digit `0`-`9` (no sign, no `_`, no whitespace — the caller strips first). CPython also
/// accepts other Unicode digits (superscripts, where c2's following `int()` then raised —
/// §11 D18). Used by `ConsoleIo::select` answers and template-editor row numbers, never
/// `py_int` there (which would accept "+2", "1_0", "-0").
pub fn py_isdigit(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}
/// Python `pathlib.Path(text)` lexical normalization (PurePosixPath rules): repeated `/`
/// collapse to one; `.` components are dropped, including a leading one (`./x` → `x`,
/// `a/./b/` → `a/b`); a trailing `/` is dropped; exactly two leading slashes are kept
/// (`//x`), three or more become one (`///x` → `/x`); `..` is kept verbatim; empty → `.`.
/// Windows: the same rules with both `/` and `\` as separators and `\` as the output
/// separator; a drive (`C:`) or UNC/verbatim prefix (`\\server\share`, `\\?\`) is kept as
/// typed (PureWindowsPath differences there: §11 D22). Binding at every c2 `Path(x)` site:
/// every CLI path option and positional (`--in`, `--out`, `--sig-file`, `--template`,
/// export/csr/`key template` paths, file-backed `load` data), `--config`, `$R2_CONFIG`,
/// `$SOFTHSM2_LIB`, and every config `PathBuf` field (through `dirs::expand_user`). So every
/// message, `DataInput.origin` and `config show` value shows c2's normalized form
/// (`wrote 3 bytes to out.bin` for `--out ./out.bin`).
pub fn py_path(text: &str) -> std::path::PathBuf {
    PathBuf::from(normalize_path(text, cfg!(windows)))
}
/// `difflib.get_close_matches(word, possibilities, n, cutoff=0.6)` of CPython 3.12, exactly:
/// for each candidate compute SequenceMatcher(None, candidate, word).ratio() (seq1 =
/// candidate, seq2 = word; same matching-block algorithm as CPython, autojunk irrelevant
/// for these lengths) as f64; keep ratio >= 0.6; order by (ratio descending, candidate
/// descending) — `heapq.nlargest` over (score, word) tuples — and take n. The result
/// therefore does not depend on the order of `possibilities`. The `difflib` crate's
/// `get_close_matches` is NOT used (it keeps ties in input order); its `SequenceMatcher`
/// may compute the ratio. R1 vectors (generated with CPython): 'sha' over
/// sha1/224/256/384/512 → sha1, sha512, sha384; 'ebc' and 'cb' over the AES cli names →
/// ecb, cbc; over the command names: 'decrept' → decrypt, encrypt, derive; 'aecrypt' →
/// encrypt, decrypt; 'cps' → ops, csr.
pub fn close_matches(word: &str, possibilities: &[&str], n: usize) -> Vec<String> {
    const CUTOFF: f64 = 0.6;
    if n == 0 {
        return Vec::new();
    }
    let word_chars: Vec<char> = word.chars().collect();
    let matcher = SequenceMatcher::new(&word_chars);
    let mut scored: Vec<(f64, &str)> = Vec::new();
    for candidate in possibilities {
        let candidate_chars: Vec<char> = candidate.chars().collect();
        let ratio = matcher.ratio(&candidate_chars);
        if ratio >= CUTOFF {
            scored.push((ratio, candidate));
        }
    }
    // heapq.nlargest over (score, word) tuples: score descending, then word descending;
    // the stable sort keeps the input order of fully equal tuples, like CPython.
    scored.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| b.1.cmp(a.1)));
    scored
        .into_iter()
        .take(n)
        .map(|(_, candidate)| candidate.to_owned())
        .collect()
}

// ---- private helpers ---------------------------------------------------------------

/// Python `str.splitlines()` (no keepends): \n, \r, \r\n, \x0b, \x0c, \x1c, \x1d, \x1e,
/// \x85,  ,  ; no trailing empty line for a final terminator.
pub(crate) fn py_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((offset, c)) = chars.next() {
        let is_break = matches!(
            c,
            '\n' | '\r'
                | '\u{0b}'
                | '\u{0c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !is_break {
            continue;
        }
        lines.push(&text[start..offset]);
        let mut next = offset + c.len_utf8();
        if c == '\r' && chars.peek().is_some_and(|&(_, n)| n == '\n') {
            chars.next();
            next += 1;
        }
        start = next;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// CPython `str.isprintable()` for one char (Unicode 15.0.0 table below).
fn is_py_printable(c: char) -> bool {
    let code = u32::from(c);
    NON_PRINTABLE
        .binary_search_by(|&(lo, hi)| {
            if hi < code {
                std::cmp::Ordering::Less
            } else if lo > code {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_err()
}

/// CPython `Py_ISSPACE` (ASCII whitespace: space, \t, \n, \r, \x0b, \x0c).
fn is_ascii_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// `pathlib.PurePosixPath(text)` (windows = false) or r2's PureWindowsPath subset
/// (windows = true; §11 D22) as a string. Compiled on every platform so both flavors are
/// unit-tested everywhere; `py_path` picks the host flavor.
fn normalize_path(text: &str, windows: bool) -> String {
    let is_sep = |c: char| c == '/' || (windows && c == '\\');
    let out_sep = if windows { "\\" } else { "/" };
    let (prefix, rest) = if windows {
        split_windows_prefix(text)
    } else {
        ("", text)
    };
    let leading = rest.chars().take_while(|&c| is_sep(c)).count();
    let root = match (windows, leading) {
        (_, 0) => String::new(),
        // PurePosixPath keeps exactly two leading slashes (POSIX implementation-defined).
        (false, 2) => "//".to_owned(),
        _ => out_sep.to_owned(),
    };
    let parts: Vec<&str> = rest
        .split(is_sep)
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let joined = format!("{prefix}{root}{}", parts.join(out_sep));
    if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

/// Windows drive / UNC / verbatim prefix, kept as typed: `C:`, `\\server\share`,
/// `\\?\…` / `\\.\…` (the device/verbatim prefix plus its first component).
fn split_windows_prefix(text: &str) -> (&str, &str) {
    let is_sep = |c: char| c == '/' || c == '\\';
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some(a), Some(b)) if is_sep(a) && is_sep(b) => {
            // UNC (`\\server\share`) or device/verbatim (`\\?\C:`, `\\.\pipe`): the
            // prefix runs through the second component after the leading pair.
            let after = &text[2..];
            if after.is_empty() || after.starts_with(is_sep) {
                return ("", text);
            }
            let Some(first_end) = after.find(is_sep).map(|i| 2 + i) else {
                return (text, "");
            };
            let Some(second_start) = text[first_end..]
                .find(|c: char| !is_sep(c))
                .map(|i| first_end + i)
            else {
                return text.split_at(first_end);
            };
            let second_end = text[second_start..]
                .find(is_sep)
                .map_or(text.len(), |i| second_start + i);
            text.split_at(second_end)
        }
        (Some(letter), Some(':')) if letter.is_ascii_alphabetic() => text.split_at(2),
        _ => ("", text),
    }
}

/// CPython 3.12 `difflib.SequenceMatcher(None, a, b)` with `b` fixed (`set_seq2`), autojunk
/// on: only the parts `ratio()` needs (`b2j`, popular purge, find_longest_match,
/// get_matching_blocks' block sizes).
struct SequenceMatcher<'b> {
    b: &'b [char],
    /// char → ascending indices into `b` (popular elements purged).
    b2j: HashMap<char, Vec<usize>>,
}

impl<'b> SequenceMatcher<'b> {
    fn new(b: &'b [char]) -> Self {
        let mut b2j: HashMap<char, Vec<usize>> = HashMap::new();
        for (index, &elt) in b.iter().enumerate() {
            b2j.entry(elt).or_default().push(index);
        }
        let n = b.len();
        if n >= 200 {
            let ntest = n / 100 + 1;
            b2j.retain(|_, indices| indices.len() <= ntest);
        }
        Self { b, b2j }
    }

    /// `_calculate_ratio(sum of matching block sizes, len(a) + len(b))`.
    fn ratio(&self, a: &[char]) -> f64 {
        let length = a.len() + self.b.len();
        if length == 0 {
            return 1.0;
        }
        let matches = self.matching_total(a);
        2.0 * matches as f64 / length as f64
    }

    fn matching_total(&self, a: &[char]) -> usize {
        let mut total = 0;
        let mut queue = vec![(0, a.len(), 0, self.b.len())];
        while let Some((alo, ahi, blo, bhi)) = queue.pop() {
            let (i, j, k) = self.find_longest_match(a, alo, ahi, blo, bhi);
            if k > 0 {
                total += k;
                if alo < i && blo < j {
                    queue.push((alo, i, blo, j));
                }
                if i + k < ahi && j + k < bhi {
                    queue.push((i + k, ahi, j + k, bhi));
                }
            }
        }
        total
    }

    fn find_longest_match(
        &self,
        a: &[char],
        alo: usize,
        ahi: usize,
        blo: usize,
        bhi: usize,
    ) -> (usize, usize, usize) {
        let b = self.b;
        let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0);
        let mut j2len: HashMap<usize, usize> = HashMap::new();
        for (i, elt) in a.iter().enumerate().take(ahi).skip(alo) {
            let mut new_j2len: HashMap<usize, usize> = HashMap::new();
            if let Some(indices) = self.b2j.get(elt) {
                for &j in indices {
                    if j < blo {
                        continue;
                    }
                    if j >= bhi {
                        break;
                    }
                    let previous = if j == 0 {
                        0
                    } else {
                        j2len.get(&(j - 1)).copied().unwrap_or(0)
                    };
                    let k = previous + 1;
                    new_j2len.insert(j, k);
                    if k > bestsize {
                        besti = i + 1 - k;
                        bestj = j + 1 - k;
                        bestsize = k;
                    }
                }
            }
            j2len = new_j2len;
        }
        // No junk (isjunk=None): extend by equal (popular) elements on both ends.
        while besti > alo && bestj > blo && a[besti - 1] == b[bestj - 1] {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi
            && bestj + bestsize < bhi
            && a[besti + bestsize] == b[bestj + bestsize]
        {
            bestsize += 1;
        }
        (besti, bestj, bestsize)
    }
}

/// Code points for which CPython 3.12's `str.isprintable()` is false (Unicode 15.0.0),
/// as inclusive ranges, sorted. Generated once with
/// `[c for c in range(0x110000) if not chr(c).isprintable()]` (c2's interpreter, 3.12.3).
const NON_PRINTABLE: [(u32, u32); 712] = [
    (0x0000, 0x001F),
    (0x007F, 0x00A0),
    (0x00AD, 0x00AD),
    (0x0378, 0x0379),
    (0x0380, 0x0383),
    (0x038B, 0x038B),
    (0x038D, 0x038D),
    (0x03A2, 0x03A2),
    (0x0530, 0x0530),
    (0x0557, 0x0558),
    (0x058B, 0x058C),
    (0x0590, 0x0590),
    (0x05C8, 0x05CF),
    (0x05EB, 0x05EE),
    (0x05F5, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070E, 0x070F),
    (0x074B, 0x074C),
    (0x07B2, 0x07BF),
    (0x07FB, 0x07FC),
    (0x082E, 0x082F),
    (0x083F, 0x083F),
    (0x085C, 0x085D),
    (0x085F, 0x085F),
    (0x086B, 0x086F),
    (0x088F, 0x0897),
    (0x08E2, 0x08E2),
    (0x0984, 0x0984),
    (0x098D, 0x098E),
    (0x0991, 0x0992),
    (0x09A9, 0x09A9),
    (0x09B1, 0x09B1),
    (0x09B3, 0x09B5),
    (0x09BA, 0x09BB),
    (0x09C5, 0x09C6),
    (0x09C9, 0x09CA),
    (0x09CF, 0x09D6),
    (0x09D8, 0x09DB),
    (0x09DE, 0x09DE),
    (0x09E4, 0x09E5),
    (0x09FF, 0x0A00),
    (0x0A04, 0x0A04),
    (0x0A0B, 0x0A0E),
    (0x0A11, 0x0A12),
    (0x0A29, 0x0A29),
    (0x0A31, 0x0A31),
    (0x0A34, 0x0A34),
    (0x0A37, 0x0A37),
    (0x0A3A, 0x0A3B),
    (0x0A3D, 0x0A3D),
    (0x0A43, 0x0A46),
    (0x0A49, 0x0A4A),
    (0x0A4E, 0x0A50),
    (0x0A52, 0x0A58),
    (0x0A5D, 0x0A5D),
    (0x0A5F, 0x0A65),
    (0x0A77, 0x0A80),
    (0x0A84, 0x0A84),
    (0x0A8E, 0x0A8E),
    (0x0A92, 0x0A92),
    (0x0AA9, 0x0AA9),
    (0x0AB1, 0x0AB1),
    (0x0AB4, 0x0AB4),
    (0x0ABA, 0x0ABB),
    (0x0AC6, 0x0AC6),
    (0x0ACA, 0x0ACA),
    (0x0ACE, 0x0ACF),
    (0x0AD1, 0x0ADF),
    (0x0AE4, 0x0AE5),
    (0x0AF2, 0x0AF8),
    (0x0B00, 0x0B00),
    (0x0B04, 0x0B04),
    (0x0B0D, 0x0B0E),
    (0x0B11, 0x0B12),
    (0x0B29, 0x0B29),
    (0x0B31, 0x0B31),
    (0x0B34, 0x0B34),
    (0x0B3A, 0x0B3B),
    (0x0B45, 0x0B46),
    (0x0B49, 0x0B4A),
    (0x0B4E, 0x0B54),
    (0x0B58, 0x0B5B),
    (0x0B5E, 0x0B5E),
    (0x0B64, 0x0B65),
    (0x0B78, 0x0B81),
    (0x0B84, 0x0B84),
    (0x0B8B, 0x0B8D),
    (0x0B91, 0x0B91),
    (0x0B96, 0x0B98),
    (0x0B9B, 0x0B9B),
    (0x0B9D, 0x0B9D),
    (0x0BA0, 0x0BA2),
    (0x0BA5, 0x0BA7),
    (0x0BAB, 0x0BAD),
    (0x0BBA, 0x0BBD),
    (0x0BC3, 0x0BC5),
    (0x0BC9, 0x0BC9),
    (0x0BCE, 0x0BCF),
    (0x0BD1, 0x0BD6),
    (0x0BD8, 0x0BE5),
    (0x0BFB, 0x0BFF),
    (0x0C0D, 0x0C0D),
    (0x0C11, 0x0C11),
    (0x0C29, 0x0C29),
    (0x0C3A, 0x0C3B),
    (0x0C45, 0x0C45),
    (0x0C49, 0x0C49),
    (0x0C4E, 0x0C54),
    (0x0C57, 0x0C57),
    (0x0C5B, 0x0C5C),
    (0x0C5E, 0x0C5F),
    (0x0C64, 0x0C65),
    (0x0C70, 0x0C76),
    (0x0C8D, 0x0C8D),
    (0x0C91, 0x0C91),
    (0x0CA9, 0x0CA9),
    (0x0CB4, 0x0CB4),
    (0x0CBA, 0x0CBB),
    (0x0CC5, 0x0CC5),
    (0x0CC9, 0x0CC9),
    (0x0CCE, 0x0CD4),
    (0x0CD7, 0x0CDC),
    (0x0CDF, 0x0CDF),
    (0x0CE4, 0x0CE5),
    (0x0CF0, 0x0CF0),
    (0x0CF4, 0x0CFF),
    (0x0D0D, 0x0D0D),
    (0x0D11, 0x0D11),
    (0x0D45, 0x0D45),
    (0x0D49, 0x0D49),
    (0x0D50, 0x0D53),
    (0x0D64, 0x0D65),
    (0x0D80, 0x0D80),
    (0x0D84, 0x0D84),
    (0x0D97, 0x0D99),
    (0x0DB2, 0x0DB2),
    (0x0DBC, 0x0DBC),
    (0x0DBE, 0x0DBF),
    (0x0DC7, 0x0DC9),
    (0x0DCB, 0x0DCE),
    (0x0DD5, 0x0DD5),
    (0x0DD7, 0x0DD7),
    (0x0DE0, 0x0DE5),
    (0x0DF0, 0x0DF1),
    (0x0DF5, 0x0E00),
    (0x0E3B, 0x0E3E),
    (0x0E5C, 0x0E80),
    (0x0E83, 0x0E83),
    (0x0E85, 0x0E85),
    (0x0E8B, 0x0E8B),
    (0x0EA4, 0x0EA4),
    (0x0EA6, 0x0EA6),
    (0x0EBE, 0x0EBF),
    (0x0EC5, 0x0EC5),
    (0x0EC7, 0x0EC7),
    (0x0ECF, 0x0ECF),
    (0x0EDA, 0x0EDB),
    (0x0EE0, 0x0EFF),
    (0x0F48, 0x0F48),
    (0x0F6D, 0x0F70),
    (0x0F98, 0x0F98),
    (0x0FBD, 0x0FBD),
    (0x0FCD, 0x0FCD),
    (0x0FDB, 0x0FFF),
    (0x10C6, 0x10C6),
    (0x10C8, 0x10CC),
    (0x10CE, 0x10CF),
    (0x1249, 0x1249),
    (0x124E, 0x124F),
    (0x1257, 0x1257),
    (0x1259, 0x1259),
    (0x125E, 0x125F),
    (0x1289, 0x1289),
    (0x128E, 0x128F),
    (0x12B1, 0x12B1),
    (0x12B6, 0x12B7),
    (0x12BF, 0x12BF),
    (0x12C1, 0x12C1),
    (0x12C6, 0x12C7),
    (0x12D7, 0x12D7),
    (0x1311, 0x1311),
    (0x1316, 0x1317),
    (0x135B, 0x135C),
    (0x137D, 0x137F),
    (0x139A, 0x139F),
    (0x13F6, 0x13F7),
    (0x13FE, 0x13FF),
    (0x1680, 0x1680),
    (0x169D, 0x169F),
    (0x16F9, 0x16FF),
    (0x1716, 0x171E),
    (0x1737, 0x173F),
    (0x1754, 0x175F),
    (0x176D, 0x176D),
    (0x1771, 0x1771),
    (0x1774, 0x177F),
    (0x17DE, 0x17DF),
    (0x17EA, 0x17EF),
    (0x17FA, 0x17FF),
    (0x180E, 0x180E),
    (0x181A, 0x181F),
    (0x1879, 0x187F),
    (0x18AB, 0x18AF),
    (0x18F6, 0x18FF),
    (0x191F, 0x191F),
    (0x192C, 0x192F),
    (0x193C, 0x193F),
    (0x1941, 0x1943),
    (0x196E, 0x196F),
    (0x1975, 0x197F),
    (0x19AC, 0x19AF),
    (0x19CA, 0x19CF),
    (0x19DB, 0x19DD),
    (0x1A1C, 0x1A1D),
    (0x1A5F, 0x1A5F),
    (0x1A7D, 0x1A7E),
    (0x1A8A, 0x1A8F),
    (0x1A9A, 0x1A9F),
    (0x1AAE, 0x1AAF),
    (0x1ACF, 0x1AFF),
    (0x1B4D, 0x1B4F),
    (0x1B7F, 0x1B7F),
    (0x1BF4, 0x1BFB),
    (0x1C38, 0x1C3A),
    (0x1C4A, 0x1C4C),
    (0x1C89, 0x1C8F),
    (0x1CBB, 0x1CBC),
    (0x1CC8, 0x1CCF),
    (0x1CFB, 0x1CFF),
    (0x1F16, 0x1F17),
    (0x1F1E, 0x1F1F),
    (0x1F46, 0x1F47),
    (0x1F4E, 0x1F4F),
    (0x1F58, 0x1F58),
    (0x1F5A, 0x1F5A),
    (0x1F5C, 0x1F5C),
    (0x1F5E, 0x1F5E),
    (0x1F7E, 0x1F7F),
    (0x1FB5, 0x1FB5),
    (0x1FC5, 0x1FC5),
    (0x1FD4, 0x1FD5),
    (0x1FDC, 0x1FDC),
    (0x1FF0, 0x1FF1),
    (0x1FF5, 0x1FF5),
    (0x1FFF, 0x200F),
    (0x2028, 0x202F),
    (0x205F, 0x206F),
    (0x2072, 0x2073),
    (0x208F, 0x208F),
    (0x209D, 0x209F),
    (0x20C1, 0x20CF),
    (0x20F1, 0x20FF),
    (0x218C, 0x218F),
    (0x2427, 0x243F),
    (0x244B, 0x245F),
    (0x2B74, 0x2B75),
    (0x2B96, 0x2B96),
    (0x2CF4, 0x2CF8),
    (0x2D26, 0x2D26),
    (0x2D28, 0x2D2C),
    (0x2D2E, 0x2D2F),
    (0x2D68, 0x2D6E),
    (0x2D71, 0x2D7E),
    (0x2D97, 0x2D9F),
    (0x2DA7, 0x2DA7),
    (0x2DAF, 0x2DAF),
    (0x2DB7, 0x2DB7),
    (0x2DBF, 0x2DBF),
    (0x2DC7, 0x2DC7),
    (0x2DCF, 0x2DCF),
    (0x2DD7, 0x2DD7),
    (0x2DDF, 0x2DDF),
    (0x2E5E, 0x2E7F),
    (0x2E9A, 0x2E9A),
    (0x2EF4, 0x2EFF),
    (0x2FD6, 0x2FEF),
    (0x2FFC, 0x3000),
    (0x3040, 0x3040),
    (0x3097, 0x3098),
    (0x3100, 0x3104),
    (0x3130, 0x3130),
    (0x318F, 0x318F),
    (0x31E4, 0x31EF),
    (0x321F, 0x321F),
    (0xA48D, 0xA48F),
    (0xA4C7, 0xA4CF),
    (0xA62C, 0xA63F),
    (0xA6F8, 0xA6FF),
    (0xA7CB, 0xA7CF),
    (0xA7D2, 0xA7D2),
    (0xA7D4, 0xA7D4),
    (0xA7DA, 0xA7F1),
    (0xA82D, 0xA82F),
    (0xA83A, 0xA83F),
    (0xA878, 0xA87F),
    (0xA8C6, 0xA8CD),
    (0xA8DA, 0xA8DF),
    (0xA954, 0xA95E),
    (0xA97D, 0xA97F),
    (0xA9CE, 0xA9CE),
    (0xA9DA, 0xA9DD),
    (0xA9FF, 0xA9FF),
    (0xAA37, 0xAA3F),
    (0xAA4E, 0xAA4F),
    (0xAA5A, 0xAA5B),
    (0xAAC3, 0xAADA),
    (0xAAF7, 0xAB00),
    (0xAB07, 0xAB08),
    (0xAB0F, 0xAB10),
    (0xAB17, 0xAB1F),
    (0xAB27, 0xAB27),
    (0xAB2F, 0xAB2F),
    (0xAB6C, 0xAB6F),
    (0xABEE, 0xABEF),
    (0xABFA, 0xABFF),
    (0xD7A4, 0xD7AF),
    (0xD7C7, 0xD7CA),
    (0xD7FC, 0xF8FF),
    (0xFA6E, 0xFA6F),
    (0xFADA, 0xFAFF),
    (0xFB07, 0xFB12),
    (0xFB18, 0xFB1C),
    (0xFB37, 0xFB37),
    (0xFB3D, 0xFB3D),
    (0xFB3F, 0xFB3F),
    (0xFB42, 0xFB42),
    (0xFB45, 0xFB45),
    (0xFBC3, 0xFBD2),
    (0xFD90, 0xFD91),
    (0xFDC8, 0xFDCE),
    (0xFDD0, 0xFDEF),
    (0xFE1A, 0xFE1F),
    (0xFE53, 0xFE53),
    (0xFE67, 0xFE67),
    (0xFE6C, 0xFE6F),
    (0xFE75, 0xFE75),
    (0xFEFD, 0xFF00),
    (0xFFBF, 0xFFC1),
    (0xFFC8, 0xFFC9),
    (0xFFD0, 0xFFD1),
    (0xFFD8, 0xFFD9),
    (0xFFDD, 0xFFDF),
    (0xFFE7, 0xFFE7),
    (0xFFEF, 0xFFFB),
    (0xFFFE, 0xFFFF),
    (0x1000C, 0x1000C),
    (0x10027, 0x10027),
    (0x1003B, 0x1003B),
    (0x1003E, 0x1003E),
    (0x1004E, 0x1004F),
    (0x1005E, 0x1007F),
    (0x100FB, 0x100FF),
    (0x10103, 0x10106),
    (0x10134, 0x10136),
    (0x1018F, 0x1018F),
    (0x1019D, 0x1019F),
    (0x101A1, 0x101CF),
    (0x101FE, 0x1027F),
    (0x1029D, 0x1029F),
    (0x102D1, 0x102DF),
    (0x102FC, 0x102FF),
    (0x10324, 0x1032C),
    (0x1034B, 0x1034F),
    (0x1037B, 0x1037F),
    (0x1039E, 0x1039E),
    (0x103C4, 0x103C7),
    (0x103D6, 0x103FF),
    (0x1049E, 0x1049F),
    (0x104AA, 0x104AF),
    (0x104D4, 0x104D7),
    (0x104FC, 0x104FF),
    (0x10528, 0x1052F),
    (0x10564, 0x1056E),
    (0x1057B, 0x1057B),
    (0x1058B, 0x1058B),
    (0x10593, 0x10593),
    (0x10596, 0x10596),
    (0x105A2, 0x105A2),
    (0x105B2, 0x105B2),
    (0x105BA, 0x105BA),
    (0x105BD, 0x105FF),
    (0x10737, 0x1073F),
    (0x10756, 0x1075F),
    (0x10768, 0x1077F),
    (0x10786, 0x10786),
    (0x107B1, 0x107B1),
    (0x107BB, 0x107FF),
    (0x10806, 0x10807),
    (0x10809, 0x10809),
    (0x10836, 0x10836),
    (0x10839, 0x1083B),
    (0x1083D, 0x1083E),
    (0x10856, 0x10856),
    (0x1089F, 0x108A6),
    (0x108B0, 0x108DF),
    (0x108F3, 0x108F3),
    (0x108F6, 0x108FA),
    (0x1091C, 0x1091E),
    (0x1093A, 0x1093E),
    (0x10940, 0x1097F),
    (0x109B8, 0x109BB),
    (0x109D0, 0x109D1),
    (0x10A04, 0x10A04),
    (0x10A07, 0x10A0B),
    (0x10A14, 0x10A14),
    (0x10A18, 0x10A18),
    (0x10A36, 0x10A37),
    (0x10A3B, 0x10A3E),
    (0x10A49, 0x10A4F),
    (0x10A59, 0x10A5F),
    (0x10AA0, 0x10ABF),
    (0x10AE7, 0x10AEA),
    (0x10AF7, 0x10AFF),
    (0x10B36, 0x10B38),
    (0x10B56, 0x10B57),
    (0x10B73, 0x10B77),
    (0x10B92, 0x10B98),
    (0x10B9D, 0x10BA8),
    (0x10BB0, 0x10BFF),
    (0x10C49, 0x10C7F),
    (0x10CB3, 0x10CBF),
    (0x10CF3, 0x10CF9),
    (0x10D28, 0x10D2F),
    (0x10D3A, 0x10E5F),
    (0x10E7F, 0x10E7F),
    (0x10EAA, 0x10EAA),
    (0x10EAE, 0x10EAF),
    (0x10EB2, 0x10EFC),
    (0x10F28, 0x10F2F),
    (0x10F5A, 0x10F6F),
    (0x10F8A, 0x10FAF),
    (0x10FCC, 0x10FDF),
    (0x10FF7, 0x10FFF),
    (0x1104E, 0x11051),
    (0x11076, 0x1107E),
    (0x110BD, 0x110BD),
    (0x110C3, 0x110CF),
    (0x110E9, 0x110EF),
    (0x110FA, 0x110FF),
    (0x11135, 0x11135),
    (0x11148, 0x1114F),
    (0x11177, 0x1117F),
    (0x111E0, 0x111E0),
    (0x111F5, 0x111FF),
    (0x11212, 0x11212),
    (0x11242, 0x1127F),
    (0x11287, 0x11287),
    (0x11289, 0x11289),
    (0x1128E, 0x1128E),
    (0x1129E, 0x1129E),
    (0x112AA, 0x112AF),
    (0x112EB, 0x112EF),
    (0x112FA, 0x112FF),
    (0x11304, 0x11304),
    (0x1130D, 0x1130E),
    (0x11311, 0x11312),
    (0x11329, 0x11329),
    (0x11331, 0x11331),
    (0x11334, 0x11334),
    (0x1133A, 0x1133A),
    (0x11345, 0x11346),
    (0x11349, 0x1134A),
    (0x1134E, 0x1134F),
    (0x11351, 0x11356),
    (0x11358, 0x1135C),
    (0x11364, 0x11365),
    (0x1136D, 0x1136F),
    (0x11375, 0x113FF),
    (0x1145C, 0x1145C),
    (0x11462, 0x1147F),
    (0x114C8, 0x114CF),
    (0x114DA, 0x1157F),
    (0x115B6, 0x115B7),
    (0x115DE, 0x115FF),
    (0x11645, 0x1164F),
    (0x1165A, 0x1165F),
    (0x1166D, 0x1167F),
    (0x116BA, 0x116BF),
    (0x116CA, 0x116FF),
    (0x1171B, 0x1171C),
    (0x1172C, 0x1172F),
    (0x11747, 0x117FF),
    (0x1183C, 0x1189F),
    (0x118F3, 0x118FE),
    (0x11907, 0x11908),
    (0x1190A, 0x1190B),
    (0x11914, 0x11914),
    (0x11917, 0x11917),
    (0x11936, 0x11936),
    (0x11939, 0x1193A),
    (0x11947, 0x1194F),
    (0x1195A, 0x1199F),
    (0x119A8, 0x119A9),
    (0x119D8, 0x119D9),
    (0x119E5, 0x119FF),
    (0x11A48, 0x11A4F),
    (0x11AA3, 0x11AAF),
    (0x11AF9, 0x11AFF),
    (0x11B0A, 0x11BFF),
    (0x11C09, 0x11C09),
    (0x11C37, 0x11C37),
    (0x11C46, 0x11C4F),
    (0x11C6D, 0x11C6F),
    (0x11C90, 0x11C91),
    (0x11CA8, 0x11CA8),
    (0x11CB7, 0x11CFF),
    (0x11D07, 0x11D07),
    (0x11D0A, 0x11D0A),
    (0x11D37, 0x11D39),
    (0x11D3B, 0x11D3B),
    (0x11D3E, 0x11D3E),
    (0x11D48, 0x11D4F),
    (0x11D5A, 0x11D5F),
    (0x11D66, 0x11D66),
    (0x11D69, 0x11D69),
    (0x11D8F, 0x11D8F),
    (0x11D92, 0x11D92),
    (0x11D99, 0x11D9F),
    (0x11DAA, 0x11EDF),
    (0x11EF9, 0x11EFF),
    (0x11F11, 0x11F11),
    (0x11F3B, 0x11F3D),
    (0x11F5A, 0x11FAF),
    (0x11FB1, 0x11FBF),
    (0x11FF2, 0x11FFE),
    (0x1239A, 0x123FF),
    (0x1246F, 0x1246F),
    (0x12475, 0x1247F),
    (0x12544, 0x12F8F),
    (0x12FF3, 0x12FFF),
    (0x13430, 0x1343F),
    (0x13456, 0x143FF),
    (0x14647, 0x167FF),
    (0x16A39, 0x16A3F),
    (0x16A5F, 0x16A5F),
    (0x16A6A, 0x16A6D),
    (0x16ABF, 0x16ABF),
    (0x16ACA, 0x16ACF),
    (0x16AEE, 0x16AEF),
    (0x16AF6, 0x16AFF),
    (0x16B46, 0x16B4F),
    (0x16B5A, 0x16B5A),
    (0x16B62, 0x16B62),
    (0x16B78, 0x16B7C),
    (0x16B90, 0x16E3F),
    (0x16E9B, 0x16EFF),
    (0x16F4B, 0x16F4E),
    (0x16F88, 0x16F8E),
    (0x16FA0, 0x16FDF),
    (0x16FE5, 0x16FEF),
    (0x16FF2, 0x16FFF),
    (0x187F8, 0x187FF),
    (0x18CD6, 0x18CFF),
    (0x18D09, 0x1AFEF),
    (0x1AFF4, 0x1AFF4),
    (0x1AFFC, 0x1AFFC),
    (0x1AFFF, 0x1AFFF),
    (0x1B123, 0x1B131),
    (0x1B133, 0x1B14F),
    (0x1B153, 0x1B154),
    (0x1B156, 0x1B163),
    (0x1B168, 0x1B16F),
    (0x1B2FC, 0x1BBFF),
    (0x1BC6B, 0x1BC6F),
    (0x1BC7D, 0x1BC7F),
    (0x1BC89, 0x1BC8F),
    (0x1BC9A, 0x1BC9B),
    (0x1BCA0, 0x1CEFF),
    (0x1CF2E, 0x1CF2F),
    (0x1CF47, 0x1CF4F),
    (0x1CFC4, 0x1CFFF),
    (0x1D0F6, 0x1D0FF),
    (0x1D127, 0x1D128),
    (0x1D173, 0x1D17A),
    (0x1D1EB, 0x1D1FF),
    (0x1D246, 0x1D2BF),
    (0x1D2D4, 0x1D2DF),
    (0x1D2F4, 0x1D2FF),
    (0x1D357, 0x1D35F),
    (0x1D379, 0x1D3FF),
    (0x1D455, 0x1D455),
    (0x1D49D, 0x1D49D),
    (0x1D4A0, 0x1D4A1),
    (0x1D4A3, 0x1D4A4),
    (0x1D4A7, 0x1D4A8),
    (0x1D4AD, 0x1D4AD),
    (0x1D4BA, 0x1D4BA),
    (0x1D4BC, 0x1D4BC),
    (0x1D4C4, 0x1D4C4),
    (0x1D506, 0x1D506),
    (0x1D50B, 0x1D50C),
    (0x1D515, 0x1D515),
    (0x1D51D, 0x1D51D),
    (0x1D53A, 0x1D53A),
    (0x1D53F, 0x1D53F),
    (0x1D545, 0x1D545),
    (0x1D547, 0x1D549),
    (0x1D551, 0x1D551),
    (0x1D6A6, 0x1D6A7),
    (0x1D7CC, 0x1D7CD),
    (0x1DA8C, 0x1DA9A),
    (0x1DAA0, 0x1DAA0),
    (0x1DAB0, 0x1DEFF),
    (0x1DF1F, 0x1DF24),
    (0x1DF2B, 0x1DFFF),
    (0x1E007, 0x1E007),
    (0x1E019, 0x1E01A),
    (0x1E022, 0x1E022),
    (0x1E025, 0x1E025),
    (0x1E02B, 0x1E02F),
    (0x1E06E, 0x1E08E),
    (0x1E090, 0x1E0FF),
    (0x1E12D, 0x1E12F),
    (0x1E13E, 0x1E13F),
    (0x1E14A, 0x1E14D),
    (0x1E150, 0x1E28F),
    (0x1E2AF, 0x1E2BF),
    (0x1E2FA, 0x1E2FE),
    (0x1E300, 0x1E4CF),
    (0x1E4FA, 0x1E7DF),
    (0x1E7E7, 0x1E7E7),
    (0x1E7EC, 0x1E7EC),
    (0x1E7EF, 0x1E7EF),
    (0x1E7FF, 0x1E7FF),
    (0x1E8C5, 0x1E8C6),
    (0x1E8D7, 0x1E8FF),
    (0x1E94C, 0x1E94F),
    (0x1E95A, 0x1E95D),
    (0x1E960, 0x1EC70),
    (0x1ECB5, 0x1ED00),
    (0x1ED3E, 0x1EDFF),
    (0x1EE04, 0x1EE04),
    (0x1EE20, 0x1EE20),
    (0x1EE23, 0x1EE23),
    (0x1EE25, 0x1EE26),
    (0x1EE28, 0x1EE28),
    (0x1EE33, 0x1EE33),
    (0x1EE38, 0x1EE38),
    (0x1EE3A, 0x1EE3A),
    (0x1EE3C, 0x1EE41),
    (0x1EE43, 0x1EE46),
    (0x1EE48, 0x1EE48),
    (0x1EE4A, 0x1EE4A),
    (0x1EE4C, 0x1EE4C),
    (0x1EE50, 0x1EE50),
    (0x1EE53, 0x1EE53),
    (0x1EE55, 0x1EE56),
    (0x1EE58, 0x1EE58),
    (0x1EE5A, 0x1EE5A),
    (0x1EE5C, 0x1EE5C),
    (0x1EE5E, 0x1EE5E),
    (0x1EE60, 0x1EE60),
    (0x1EE63, 0x1EE63),
    (0x1EE65, 0x1EE66),
    (0x1EE6B, 0x1EE6B),
    (0x1EE73, 0x1EE73),
    (0x1EE78, 0x1EE78),
    (0x1EE7D, 0x1EE7D),
    (0x1EE7F, 0x1EE7F),
    (0x1EE8A, 0x1EE8A),
    (0x1EE9C, 0x1EEA0),
    (0x1EEA4, 0x1EEA4),
    (0x1EEAA, 0x1EEAA),
    (0x1EEBC, 0x1EEEF),
    (0x1EEF2, 0x1EFFF),
    (0x1F02C, 0x1F02F),
    (0x1F094, 0x1F09F),
    (0x1F0AF, 0x1F0B0),
    (0x1F0C0, 0x1F0C0),
    (0x1F0D0, 0x1F0D0),
    (0x1F0F6, 0x1F0FF),
    (0x1F1AE, 0x1F1E5),
    (0x1F203, 0x1F20F),
    (0x1F23C, 0x1F23F),
    (0x1F249, 0x1F24F),
    (0x1F252, 0x1F25F),
    (0x1F266, 0x1F2FF),
    (0x1F6D8, 0x1F6DB),
    (0x1F6ED, 0x1F6EF),
    (0x1F6FD, 0x1F6FF),
    (0x1F777, 0x1F77A),
    (0x1F7DA, 0x1F7DF),
    (0x1F7EC, 0x1F7EF),
    (0x1F7F1, 0x1F7FF),
    (0x1F80C, 0x1F80F),
    (0x1F848, 0x1F84F),
    (0x1F85A, 0x1F85F),
    (0x1F888, 0x1F88F),
    (0x1F8AE, 0x1F8AF),
    (0x1F8B2, 0x1F8FF),
    (0x1FA54, 0x1FA5F),
    (0x1FA6E, 0x1FA6F),
    (0x1FA7D, 0x1FA7F),
    (0x1FA89, 0x1FA8F),
    (0x1FABE, 0x1FABE),
    (0x1FAC6, 0x1FACD),
    (0x1FADC, 0x1FADF),
    (0x1FAE9, 0x1FAEF),
    (0x1FAF9, 0x1FAFF),
    (0x1FB93, 0x1FB93),
    (0x1FBCB, 0x1FBEF),
    (0x1FBFA, 0x1FFFF),
    (0x2A6E0, 0x2A6FF),
    (0x2B73A, 0x2B73F),
    (0x2B81E, 0x2B81F),
    (0x2CEA2, 0x2CEAF),
    (0x2EBE1, 0x2F7FF),
    (0x2FA1E, 0x2FFFF),
    (0x3134B, 0x3134F),
    (0x323B0, 0xE00FF),
    (0xE01F0, 0x10FFFF),
];

#[cfg(test)]
mod tests {
    use super::normalize_path;

    /// PureWindowsPath vectors (CPython 3.12) for the plain cases, run on every platform.
    #[test]
    fn windows_flavor_matches_pure_windows_path() {
        let cases = [
            ("a/b", "a\\b"),
            ("a\\b\\", "a\\b"),
            ("./x", "x"),
            ("C:\\x\\.\\y", "C:\\x\\y"),
            ("C:x", "C:x"),
            ("C:", "C:"),
            ("C:\\", "C:\\"),
            ("\\\\server\\share\\x", "\\\\server\\share\\x"),
            ("\\x", "\\x"),
            ("", "."),
            ("a//b", "a\\b"),
            ("..\\x", "..\\x"),
            ("x/./", "x"),
            ("\\\\?\\C:\\x\\..\\y", "\\\\?\\C:\\x\\..\\y"),
            ("C:/a/b/", "C:\\a\\b"),
        ];
        for (text, expected) in cases {
            assert_eq!(normalize_path(text, true), expected, "{text:?}");
        }
        // Prefixes are kept as typed (§11 D22; PureWindowsPath would rewrite them).
        assert_eq!(
            normalize_path("//server/share/x", true),
            "//server/share\\x"
        );
        assert_eq!(normalize_path("\\\\server", true), "\\\\server");
    }

    #[test]
    fn posix_flavor_keeps_backslashes() {
        assert_eq!(normalize_path("a\\b/./c", false), "a\\b/c");
        assert_eq!(normalize_path("C:/x", false), "C:/x");
    }
}
