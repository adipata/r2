// PyYAML-faithful YAML loading and dumping (spec §4.8.4, §4.8.5; owner R2).
//
// Loader: the `yaml-rust2` EVENT parser (it reports scalar styles) composes a node graph,
// which is then constructed with PyYAML 6.0.3 `SafeLoader` semantics (YAML 1.1 implicit
// resolvers on plain scalars only, `<<` merge keys, first-position/last-value duplicate
// keys, `!!timestamp`/`!!binary` as tagged values).
// Emitter: a port of PyYAML 6.0.3's `SafeRepresenter` + `Serializer` + `Emitter` for the
// block-style subset that `safe_dump(sort_keys=False, default_flow_style=False)` produces.
use std::collections::HashMap;
use std::fmt::Write as _;
use std::rc::Rc;

use r2_core::error::{ConsoleError, Result};
use r2_core::text::{is_py_space, py_bytes_repr, py_repr};
use serde_yaml_ng::value::{Tag, TaggedValue};
pub use serde_yaml_ng::{Mapping, Number, Value};
use yaml_rust2::parser::{Event, Parser, Tag as EventTag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// Load one YAML document with PyYAML `safe_load` semantics (§4.8.4). Err = Generic whose
/// message is the parser's text; callers embed `err.message` in their own c2 message
/// ("invalid YAML in config file {path}: {text}", "invalid YAML in template file {path}:
/// {text}", …) with their own kind.
pub fn parse(text: &str) -> Result<Value> {
    // PyYAML's `Reader` rejects non-printable characters before anything else is read.
    check_printable(text)?;
    // PyYAML's scanner skips a byte order mark at the start of the stream.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    // PyYAML (YAML 1.1) treats NEL as a line break everywhere and its `scan_line_break`
    // turns it into '\n'; yaml-rust2 (YAML 1.2) would keep it as content.
    let text: std::borrow::Cow<'_, str> = if text.contains('\u{85}') {
        std::borrow::Cow::Owned(text.replace('\u{85}', "\n"))
    } else {
        std::borrow::Cow::Borrowed(text)
    };
    reject_line_separators(&text)?;
    let root = compose(&text)?;
    match root {
        None => Ok(Value::Null),
        Some(node) => Constructor::default().construct(&node, 0),
    }
}
/// PyYAML `Reader.check_printable`: the first character outside `[\t\n\r\x20-\x7E\x85
/// \xA0-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]` fails with PyYAML's `ReaderError` text
/// (`position` = character index in the text, a BOM included).
fn check_printable(text: &str) -> Result<()> {
    let printable = |c: char| {
        matches!(c, '\t' | '\n' | '\r' | '\x20'..='\x7e' | '\u{85}' | '\u{a0}'..='\u{fffd}')
            || c >= '\u{10000}'
    };
    match text.chars().enumerate().find(|(_, c)| !printable(*c)) {
        None => Ok(()),
        Some((position, ch)) => Err(err(format!(
            "unacceptable character #x{:04x}: special characters are not allowed\n  \
             in \"<unicode string>\", position {position}",
            u32::from(ch)
        ))),
    }
}
/// LS/PS (U+2028/U+2029) are line breaks to PyYAML but kept as the break character itself
/// in folded content; yaml-rust2 treats them as ordinary characters. Rather than load a
/// different value, r2 rejects them (§11 D17 (f)).
fn reject_line_separators(text: &str) -> Result<()> {
    let Some((offset, ch)) = text
        .char_indices()
        .find(|(_, c)| matches!(c, '\u{2028}' | '\u{2029}'))
    else {
        return Ok(());
    };
    let before = &text[..offset];
    let line = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
    Err(err(format!(
        "unsupported line break character U+{:04X} at line {line}, column {column}",
        u32::from(ch)
    )))
}
/// PyYAML `safe_dump(sort_keys=False, default_flow_style=False)` port (§4.8.4); trailing "\n".
pub fn dump(value: &Value) -> String {
    let node = represent(value);
    let mut emitter = Emitter::new();
    emitter.expect_node(&node, true, false, false, false);
    // DOCUMENT-END (implicit) then STREAM-END.
    emitter.write_indent();
    if emitter.open_ended {
        emitter.write_indicator("...", true, false, false);
        emitter.write_indent();
    }
    emitter.out
}
/// The integer of an int `Number` (i64/u64), else None — never coerces strings or bools
/// (c2 `_as_int`: `isinstance(v, int) and not isinstance(v, bool)`).
pub fn as_int(value: &Value) -> Option<i128> {
    match value {
        Value::Number(number) => {
            if let Some(v) = number.as_i64() {
                Some(i128::from(v))
            } else {
                number.as_u64().map(i128::from)
            }
        }
        _ => None,
    }
}
/// Python type name of the value PyYAML produced ("dict", "list", "str", "int", "float",
/// "bool", "NoneType", and for `Value::Tagged` `!!timestamp` "date"/"datetime", `!!binary`
/// "bytes").
pub fn python_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(number) => {
            if number.is_f64() {
                "float"
            } else {
                "int"
            }
        }
        Value::String(_) => "str",
        Value::Sequence(_) => "list",
        Value::Mapping(_) => "dict",
        Value::Tagged(tagged) => {
            if tagged.tag == TIMESTAMP_TAG {
                match tagged_text(tagged).and_then(parse_timestamp_fields) {
                    Some(ts) if ts.time.is_none() => "date",
                    _ => "datetime",
                }
            } else if tagged.tag == BINARY_TAG {
                "bytes"
            } else {
                python_type_name(&tagged.value)
            }
        }
    }
}

// ---- crate-internal helpers -------------------------------------------------------------

/// The `Value::Tagged` tag of a `!!timestamp` scalar (text kept verbatim).
pub(crate) const TIMESTAMP_TAG: &str = "!!timestamp";
/// The `Value::Tagged` tag of a `!!binary` scalar (text kept verbatim).
pub(crate) const BINARY_TAG: &str = "!!binary";

/// Python `repr()` of the object PyYAML produced (used for "got {key!r}" messages).
pub(crate) fn py_value_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Number(number) => number_repr(number),
        Value::String(text) => py_repr(text),
        Value::Sequence(items) => {
            let parts: Vec<String> = items.iter().map(py_value_repr).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Mapping(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", py_value_repr(k), py_value_repr(v)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        Value::Tagged(tagged) => {
            if tagged.tag == TIMESTAMP_TAG
                && let Some(ts) = tagged_text(tagged).and_then(parse_timestamp_fields)
            {
                return ts.py_repr();
            }
            if tagged.tag == BINARY_TAG
                && let Some(text) = tagged_text(tagged)
                && let Ok(bytes) = a2b_base64_lenient(text)
            {
                return py_bytes_repr(&bytes);
            }
            py_value_repr(&tagged.value)
        }
    }
}

fn number_repr(number: &Number) -> String {
    if let Some(v) = number.as_i64() {
        v.to_string()
    } else if let Some(v) = number.as_u64() {
        v.to_string()
    } else {
        py_float_repr(number.as_f64().unwrap_or(f64::NAN))
    }
}

/// Python `repr(float)` (shortest round-trip digits, `'r'` format: exponent form when the
/// decimal exponent is < -4 or >= 16, else fixed with at least one fractional digit).
pub(crate) fn py_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    // Rust's `{:e}` is the shortest round-trip representation in scientific form.
    let sci = format!("{value:e}");
    let (negative, sci) = match sci.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, sci.as_str()),
    };
    let (mantissa, exponent) = sci.split_once('e').unwrap_or((sci, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if !(-4..16).contains(&exponent) {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let sign = if exponent < 0 { '-' } else { '+' };
        let _ = write!(out, "e{sign}{:02}", exponent.unsigned_abs());
    } else if exponent < 0 {
        out.push_str("0.");
        for _ in 0..(-exponent - 1) {
            out.push('0');
        }
        out.push_str(digits);
    } else {
        let point = usize::try_from(exponent).unwrap_or(0) + 1;
        if digits.len() <= point {
            out.push_str(digits);
            for _ in digits.len()..point {
                out.push('0');
            }
            out.push_str(".0");
        } else {
            out.push_str(&digits[..point]);
            out.push('.');
            out.push_str(&digits[point..]);
        }
    }
    out
}

fn tagged_text(tagged: &TaggedValue) -> Option<&str> {
    match &tagged.value {
        Value::String(text) => Some(text),
        _ => None,
    }
}

fn err(message: impl Into<String>) -> ConsoleError {
    ConsoleError::generic(message)
}

// ---- implicit resolvers (PyYAML Resolver, YAML 1.1) ---------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Resolved {
    Bool,
    Float,
    Int,
    Merge,
    Null,
    Timestamp,
    Value,
    Str,
}
impl Resolved {
    fn tag(self) -> &'static str {
        match self {
            Resolved::Bool => "tag:yaml.org,2002:bool",
            Resolved::Float => "tag:yaml.org,2002:float",
            Resolved::Int => "tag:yaml.org,2002:int",
            Resolved::Merge => "tag:yaml.org,2002:merge",
            Resolved::Null => "tag:yaml.org,2002:null",
            Resolved::Timestamp => "tag:yaml.org,2002:timestamp",
            Resolved::Value => "tag:yaml.org,2002:value",
            Resolved::Str => "tag:yaml.org,2002:str",
        }
    }
}

/// PyYAML `resolve(ScalarNode, value, (True, False))`: the implicit resolvers in their
/// registration order (bool, float, int, merge, null, timestamp, value), else str.
fn resolve_plain(text: &str) -> Resolved {
    if is_bool(text) {
        Resolved::Bool
    } else if is_float(text) {
        Resolved::Float
    } else if is_int(text) {
        Resolved::Int
    } else if text == "<<" {
        Resolved::Merge
    } else if matches!(text, "" | "~" | "null" | "Null" | "NULL") {
        Resolved::Null
    } else if is_timestamp(text) {
        Resolved::Timestamp
    } else if text == "=" {
        Resolved::Value
    } else {
        Resolved::Str
    }
}

fn is_bool(text: &str) -> bool {
    matches!(
        text,
        "yes"
            | "Yes"
            | "YES"
            | "no"
            | "No"
            | "NO"
            | "true"
            | "True"
            | "TRUE"
            | "false"
            | "False"
            | "FALSE"
            | "on"
            | "On"
            | "ON"
            | "off"
            | "Off"
            | "OFF"
    )
}

fn strip_sign(text: &[u8]) -> &[u8] {
    match text.first() {
        Some(b'-' | b'+') => &text[1..],
        _ => text,
    }
}

fn all_of(text: &[u8], allowed: impl Fn(u8) -> bool) -> bool {
    text.iter().all(|&b| allowed(b))
}

/// `[0-5]?[0-9]` exactly.
fn is_sexagesimal_part(part: &[u8]) -> bool {
    match part {
        [d] => d.is_ascii_digit(),
        [a, b] => (b'0'..=b'5').contains(a) && b.is_ascii_digit(),
        _ => false,
    }
}

/// `[0-9][0-9_]*` exactly.
fn is_digits_underscores(text: &[u8]) -> bool {
    matches!(text.first(), Some(b) if b.is_ascii_digit())
        && all_of(text, |b| b.is_ascii_digit() || b == b'_')
}

/// `(?:[eE][-+][0-9]+)?` exactly (empty allowed).
fn is_opt_exponent(text: &[u8]) -> bool {
    if text.is_empty() {
        return true;
    }
    text.len() >= 3
        && matches!(text[0], b'e' | b'E')
        && matches!(text[1], b'-' | b'+')
        && all_of(&text[2..], |b| b.is_ascii_digit())
}

fn is_float(text: &str) -> bool {
    let bytes = text.as_bytes();
    // [-+]?\.(?:inf|Inf|INF)   and   \.(?:nan|NaN|NAN)
    if matches!(strip_sign(bytes), b".inf" | b".Inf" | b".INF")
        || matches!(bytes, b".nan" | b".NaN" | b".NAN")
    {
        return true;
    }
    // \.[0-9][0-9_]*(?:[eE][-+][0-9]+)?
    if let Some(rest) = bytes.strip_prefix(b".") {
        let end = rest
            .iter()
            .position(|&b| !(b.is_ascii_digit() || b == b'_'))
            .unwrap_or(rest.len());
        return is_digits_underscores(&rest[..end]) && is_opt_exponent(&rest[end..]);
    }
    let body = strip_sign(bytes);
    let Some(dot) = body.iter().position(|&b| b == b'.') else {
        return false;
    };
    let (head, tail) = (&body[..dot], &body[dot + 1..]);
    // [-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?
    if is_digits_underscores(head) {
        let end = tail
            .iter()
            .position(|&b| !(b.is_ascii_digit() || b == b'_'))
            .unwrap_or(tail.len());
        if is_opt_exponent(&tail[end..]) {
            return true;
        }
    }
    // [-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*
    let mut parts = head.split(|&b| b == b':');
    let first = parts.next().unwrap_or(&[]);
    let rest: Vec<&[u8]> = parts.collect();
    !rest.is_empty()
        && is_digits_underscores(first)
        && rest.iter().all(|p| is_sexagesimal_part(p))
        && all_of(tail, |b| b.is_ascii_digit() || b == b'_')
}

fn is_int(text: &str) -> bool {
    let body = strip_sign(text.as_bytes());
    if let Some(rest) = body.strip_prefix(b"0b") {
        return !rest.is_empty() && all_of(rest, |b| matches!(b, b'0' | b'1' | b'_'));
    }
    if let Some(rest) = body.strip_prefix(b"0x") {
        return !rest.is_empty() && all_of(rest, |b| b.is_ascii_hexdigit() || b == b'_');
    }
    if body == b"0" {
        return true;
    }
    if let Some(rest) = body.strip_prefix(b"0") {
        return !rest.is_empty() && all_of(rest, |b| matches!(b, b'0'..=b'7' | b'_'));
    }
    if !matches!(body.first(), Some(b'1'..=b'9')) {
        return false;
    }
    let mut parts = body.split(|&b| b == b':');
    let first = parts.next().unwrap_or(&[]);
    let rest: Vec<&[u8]> = parts.collect();
    is_digits_underscores(first) && rest.iter().all(|p| is_sexagesimal_part(p))
}

fn take_digits(text: &[u8], min: usize, max: usize) -> Option<(&[u8], &[u8])> {
    let n = text
        .iter()
        .take(max)
        .take_while(|b| b.is_ascii_digit())
        .count();
    (n >= min).then(|| text.split_at(n))
}

/// The PyYAML timestamp RESOLVER regex (date-only form needs two-digit month/day).
fn is_timestamp(text: &str) -> bool {
    let b = text.as_bytes();
    if b.len() == 10
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        })
    {
        return true;
    }
    parse_timestamp_fields(text).is_some_and(|ts| ts.time.is_some())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TzInfo {
    Utc,
    /// Offset in minutes (PyYAML builds `timezone(timedelta(hours, minutes))`).
    Offset(i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TimeFields {
    hour: u32,
    minute: u32,
    second: u32,
    micro: u32,
    tz: Option<TzInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Timestamp {
    year: u32,
    month: u32,
    day: u32,
    time: Option<TimeFields>,
}

fn num(digits: &[u8]) -> u32 {
    digits
        .iter()
        .fold(0u32, |acc, d| acc * 10 + u32::from(d - b'0'))
}

/// The PyYAML CONSTRUCTOR timestamp regex (`timestamp_regexp`); None when it does not
/// match. Field ranges are not checked here.
fn parse_timestamp_fields(text: &str) -> Option<Timestamp> {
    let b = text.as_bytes();
    let (year, rest) = take_digits(b, 4, 4)?;
    let rest = rest.strip_prefix(b"-")?;
    let (month, rest) = take_digits(rest, 1, 2)?;
    let rest = rest.strip_prefix(b"-")?;
    let (day, rest) = take_digits(rest, 1, 2)?;
    let mut ts = Timestamp {
        year: num(year),
        month: num(month),
        day: num(day),
        time: None,
    };
    if rest.is_empty() {
        return Some(ts);
    }
    let rest = if let Some(r) = rest.strip_prefix(b"T").or_else(|| rest.strip_prefix(b"t")) {
        r
    } else {
        let n = rest
            .iter()
            .take_while(|c| matches!(c, b' ' | b'\t'))
            .count();
        if n == 0 {
            return None;
        }
        &rest[n..]
    };
    let (hour, rest) = take_digits(rest, 1, 2)?;
    let rest = rest.strip_prefix(b":")?;
    let (minute, rest) = take_digits(rest, 2, 2)?;
    let rest = rest.strip_prefix(b":")?;
    let (second, mut rest) = take_digits(rest, 2, 2)?;
    let mut micro = 0;
    if let Some(r) = rest.strip_prefix(b".") {
        let n = r.iter().take_while(|c| c.is_ascii_digit()).count();
        let mut fraction: Vec<u8> = r[..n].iter().take(6).copied().collect();
        if !fraction.is_empty() {
            while fraction.len() < 6 {
                fraction.push(b'0');
            }
            micro = num(&fraction);
        }
        rest = &r[n..];
    }
    let mut tz = None;
    if !rest.is_empty() {
        let n = rest
            .iter()
            .take_while(|c| matches!(c, b' ' | b'\t'))
            .count();
        let r = &rest[n..];
        if r == b"Z" {
            tz = Some(TzInfo::Utc);
        } else {
            let negative = match r.first() {
                Some(b'-') => true,
                Some(b'+') => false,
                _ => return None,
            };
            let (tz_hour, r) = take_digits(&r[1..], 1, 2)?;
            let tz_minute = if r.is_empty() {
                0
            } else {
                let r = r.strip_prefix(b":")?;
                let (m, r) = take_digits(r, 2, 2)?;
                if !r.is_empty() {
                    return None;
                }
                num(m)
            };
            if r.len() > 3 {
                return None;
            }
            let minutes = i64::from(num(tz_hour)) * 60 + i64::from(tz_minute);
            tz = Some(TzInfo::Offset(if negative { -minutes } else { minutes }));
        }
    }
    ts.time = Some(TimeFields {
        hour: num(hour),
        minute: num(minute),
        second: num(second),
        micro,
        tz,
    });
    Some(ts)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) {
                29
            } else {
                28
            }
        }
    }
}

/// Python `timedelta` repr of an offset in minutes.
fn timedelta_repr(minutes: i64) -> String {
    let seconds = minutes * 60;
    if seconds == 0 {
        return "datetime.timedelta(0)".to_owned();
    }
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    match (days, rest) {
        (0, s) => format!("datetime.timedelta(seconds={s})"),
        (d, 0) => format!("datetime.timedelta(days={d})"),
        (d, s) => format!("datetime.timedelta(days={d}, seconds={s})"),
    }
}

impl Timestamp {
    /// Python's `datetime.date`/`datetime.datetime` constructor range checks.
    fn validate(&self) -> Result<()> {
        // PyYAML builds `timezone(delta)` before `datetime(...)`: the offset is checked first.
        if let Some(TimeFields {
            tz: Some(TzInfo::Offset(minutes)),
            ..
        }) = &self.time
            && minutes.abs() >= 24 * 60
        {
            return Err(err(format!(
                "offset must be a timedelta strictly between -timedelta(hours=24) and \
                 timedelta(hours=24), not {}.",
                timedelta_repr(*minutes)
            )));
        }
        if !(1..=9999).contains(&self.year) {
            return Err(err(format!("year {} is out of range", self.year)));
        }
        if !(1..=12).contains(&self.month) {
            return Err(err("month must be in 1..12"));
        }
        if self.day < 1 || self.day > days_in_month(self.year, self.month) {
            return Err(err("day is out of range for month"));
        }
        if let Some(time) = &self.time {
            if time.hour > 23 {
                return Err(err("hour must be in 0..23"));
            }
            if time.minute > 59 {
                return Err(err("minute must be in 0..59"));
            }
            if time.second > 59 {
                return Err(err("second must be in 0..59"));
            }
        }
        Ok(())
    }

    /// Python `date.isoformat()` / `datetime.isoformat(' ')` (PyYAML `represent_date[time]`).
    fn isoformat(&self) -> String {
        let mut out = format!("{:04}-{:02}-{:02}", self.year, self.month, self.day);
        if let Some(time) = &self.time {
            let _ = write!(
                out,
                " {:02}:{:02}:{:02}",
                time.hour, time.minute, time.second
            );
            if time.micro != 0 {
                let _ = write!(out, ".{:06}", time.micro);
            }
            match time.tz {
                None => {}
                Some(TzInfo::Utc) => out.push_str("+00:00"),
                Some(TzInfo::Offset(minutes)) => {
                    let sign = if minutes < 0 { '-' } else { '+' };
                    let abs = minutes.abs();
                    let _ = write!(out, "{sign}{:02}:{:02}", abs / 60, abs % 60);
                }
            }
        }
        out
    }

    fn py_repr(&self) -> String {
        let Some(time) = &self.time else {
            return format!("datetime.date({}, {}, {})", self.year, self.month, self.day);
        };
        let mut fields = vec![
            self.year.to_string(),
            self.month.to_string(),
            self.day.to_string(),
            time.hour.to_string(),
            time.minute.to_string(),
        ];
        if time.micro != 0 {
            fields.push(time.second.to_string());
            fields.push(time.micro.to_string());
        } else if time.second != 0 {
            fields.push(time.second.to_string());
        }
        let mut out = format!("datetime.datetime({}", fields.join(", "));
        match time.tz {
            None => {}
            Some(TzInfo::Utc) | Some(TzInfo::Offset(0)) => {
                out.push_str(", tzinfo=datetime.timezone.utc");
            }
            Some(TzInfo::Offset(minutes)) => {
                let _ = write!(
                    out,
                    ", tzinfo=datetime.timezone({})",
                    timedelta_repr(minutes)
                );
            }
        }
        out.push(')');
        out
    }
}

// ---- base64 (CPython binascii, non-strict) -------------------------------------------------

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// CPython 3.12 `binascii.a2b_base64(data, strict_mode=False)` (`base64.decodebytes`):
/// characters outside the alphabet are skipped; a pad sequence ends the input.
fn a2b_base64_lenient(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut quad_pos = 0usize;
    let mut left_char = 0u8;
    let mut pads = 0usize;
    let mut data_chars = 0usize;
    for &c in text.as_bytes() {
        if c == b'=' {
            if quad_pos >= 2 {
                pads += 1;
                if quad_pos + pads >= 4 {
                    return Ok(out);
                }
            }
            continue;
        }
        let Some(v) = b64_value(c) else {
            continue;
        };
        pads = 0;
        data_chars += 1;
        match quad_pos {
            0 => {
                quad_pos = 1;
                left_char = v;
            }
            1 => {
                quad_pos = 2;
                out.push((left_char << 2) | (v >> 4));
                left_char = v & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push((left_char << 4) | (v >> 2));
                left_char = v & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push((left_char << 6) | v);
                left_char = 0;
            }
        }
    }
    match quad_pos {
        0 => Ok(out),
        1 => Err(err(format!(
            "Invalid base64-encoded string: number of data characters ({data_chars}) cannot \
             be 1 more than a multiple of 4"
        ))),
        _ => Err(err("Incorrect padding")),
    }
}

/// CPython `base64.encodebytes`: lines of at most 76 characters, each ending in "\n".
fn encodebytes(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(57) {
        for triple in chunk.chunks(3) {
            let b0 = triple[0];
            let b1 = triple.get(1).copied().unwrap_or(0);
            let b2 = triple.get(2).copied().unwrap_or(0);
            out.push(char::from(ALPHABET[usize::from(b0 >> 2)]));
            out.push(char::from(
                ALPHABET[usize::from(((b0 & 0x03) << 4) | (b1 >> 4))],
            ));
            if triple.len() > 1 {
                out.push(char::from(
                    ALPHABET[usize::from(((b1 & 0x0f) << 2) | (b2 >> 6))],
                ));
            } else {
                out.push('=');
            }
            if triple.len() > 2 {
                out.push(char::from(ALPHABET[usize::from(b2 & 0x3f)]));
            } else {
                out.push('=');
            }
        }
        out.push('\n');
    }
    out
}

// ---- composer: events → node graph ---------------------------------------------------------

/// Nesting limit of the composer (deeper documents are rejected instead of overflowing the
/// stack; CPython's recursion limit stops PyYAML between 400 and 500 levels).
const MAX_DEPTH: usize = 400;
/// Limit on constructed values (alias expansion copies shared nodes; a "billion laughs"
/// document is rejected instead of exhausting memory).
const MAX_NODES: usize = 1_000_000;
/// Limit on scalar text copied by alias expansion (64 MiB): a few aliases of a large scalar
/// would otherwise exhaust memory long before `MAX_NODES` values.
const MAX_COPIED_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug)]
enum NodeKind {
    Scalar { text: String, plain: bool },
    Seq(Vec<Rc<Node>>),
    Map(Vec<(Rc<Node>, Rc<Node>)>),
}

#[derive(Debug)]
struct Node {
    kind: NodeKind,
    /// Full tag (`tag:yaml.org,2002:str`, `!local`, `!`), None when untagged.
    tag: Option<String>,
}
impl Node {
    fn id(&self) -> &'static str {
        match self.kind {
            NodeKind::Scalar { .. } => "scalar",
            NodeKind::Seq(_) => "sequence",
            NodeKind::Map(_) => "mapping",
        }
    }
}

fn full_tag(tag: Option<EventTag>) -> Option<String> {
    tag.map(|t| format!("{}{}", t.handle, t.suffix))
}

/// Line view of the text for the two places where yaml-rust2 (YAML 1.2) and PyYAML load a
/// block scalar (`|`, `>`) that runs to the end of the text differently: PyYAML keeps only
/// the line breaks it actually read, while yaml-rust2 (a) appends a break when the last
/// line of a clip/keep scalar has content (or spaces up to the indentation) and no break
/// after it, and (b) returns the header's own break for a clip scalar, or a keep scalar
/// without empty lines, that has no content line before the end of the text.
struct BlockScalarEof<'a> {
    lines: Vec<&'a str>,
    /// Does the text end with a line break?
    final_break: bool,
    /// `min_indent[i]`: the smallest indentation of lines `i..` (0-based), where a non-final
    /// line made only of spaces counts as unbounded (yaml-rust2 skips it inside the scalar)
    /// and the final line counts its leading spaces.
    min_indent: Vec<usize>,
    /// `blank_from[i]`: lines `i..` are all made only of spaces.
    blank_from: Vec<bool>,
}

impl<'a> BlockScalarEof<'a> {
    fn new(text: &'a str) -> Self {
        let lines: Vec<&str> = text
            .split("\r\n")
            .flat_map(|l| l.split(['\r', '\n']))
            .collect();
        let last = lines.len().saturating_sub(1);
        let mut min_indent = vec![usize::MAX; lines.len() + 1];
        let mut blank_from = vec![true; lines.len() + 1];
        for (i, line) in lines.iter().enumerate().rev() {
            let lead = line.bytes().take_while(|b| *b == b' ').count();
            let blank = lead == line.len();
            let indent = if i != last && blank { usize::MAX } else { lead };
            min_indent[i] = min_indent[i + 1].min(indent);
            blank_from[i] = blank_from[i + 1] && blank;
        }
        Self {
            lines,
            final_break: text.ends_with(['\n', '\r']),
            min_indent,
            blank_from,
        }
    }

    /// PyYAML's value for the block scalar event `value` at `mark`.
    fn fix(&self, value: &mut String, mark: Marker) -> Result<()> {
        let line = mark.line(); // 1-based: `line` indexes the lines after it
        if value.bytes().all(|b| b == b'\n') {
            // No content line: at the end of the text, yaml-rust2's mark is the indicator.
            if !self.blank_from.get(line).copied().unwrap_or(false) {
                return Ok(());
            }
            let Some(header) = line.checked_sub(1).and_then(|i| self.lines.get(i)) else {
                return Ok(());
            };
            let mut chars = header.chars().skip(mark.col());
            if !matches!(chars.next(), Some('|' | '>')) {
                return Ok(());
            }
            let keep = chars.take(2).any(|c| c == '+');
            // PyYAML: the empty lines after the header for keep, else nothing.
            let breaks = if keep {
                self.lines.len().saturating_sub(line + 1)
            } else {
                0
            };
            *value = "\n".repeat(breaks);
            return Ok(());
        }
        let indent = mark.col();
        if indent == 0 {
            // YAML 1.2 lets a top-level block scalar have unindented content; to PyYAML
            // (minimum indentation 1) such a line ends the scalar.
            return Err(err(format!(
                "unindented block scalar content at line {line}, column 1"
            )));
        }
        if !self.final_break
            && self.min_indent.get(line).is_some_and(|min| *min >= indent)
            && value.ends_with('\n')
        {
            value.pop();
        }
        Ok(())
    }
}

struct Composer<'a> {
    parser: Parser<std::str::Chars<'a>>,
    anchors: HashMap<usize, Rc<Node>>,
    text: &'a str,
    /// Built on the first block scalar.
    block_eof: Option<BlockScalarEof<'a>>,
    mark: Option<Marker>,
}

impl Composer<'_> {
    /// Kept out of line: `compose_node` recurses up to `MAX_DEPTH` deep.
    #[inline(never)]
    fn scalar_node(
        &mut self,
        mut text: String,
        style: TScalarStyle,
        tag: Option<EventTag>,
    ) -> Result<Node> {
        if matches!(style, TScalarStyle::Literal | TScalarStyle::Folded)
            && let Some(mark) = self.mark
        {
            let source = self.text;
            self.block_eof
                .get_or_insert_with(|| BlockScalarEof::new(source))
                .fix(&mut text, mark)?;
        }
        Ok(Node {
            kind: NodeKind::Scalar {
                text,
                plain: style == TScalarStyle::Plain,
            },
            tag: full_tag(tag),
        })
    }

    fn next(&mut self) -> Result<Event> {
        let (event, mark) = self.parser.next_token().map_err(|e| err(e.to_string()))?;
        self.mark = Some(mark);
        Ok(event)
    }

    fn compose_node(&mut self, event: Event, depth: usize) -> Result<Rc<Node>> {
        if depth > MAX_DEPTH {
            return Err(err(format!(
                "maximum nesting depth of {MAX_DEPTH} exceeded"
            )));
        }
        let (node, anchor) = match event {
            Event::Alias(id) => {
                return self.anchors.get(&id).cloned().ok_or_else(|| {
                    err("found undefined alias (recursive aliases are not supported)")
                });
            }
            Event::Scalar(text, style, anchor, tag) => {
                (self.scalar_node(text, style, tag)?, anchor)
            }
            Event::SequenceStart(anchor, tag) => {
                let mut items = Vec::new();
                loop {
                    let event = self.next()?;
                    if event == Event::SequenceEnd {
                        break;
                    }
                    items.push(self.compose_node(event, depth + 1)?);
                }
                (
                    Node {
                        kind: NodeKind::Seq(items),
                        tag: full_tag(tag),
                    },
                    anchor,
                )
            }
            Event::MappingStart(anchor, tag) => {
                let mut pairs = Vec::new();
                loop {
                    let event = self.next()?;
                    if event == Event::MappingEnd {
                        break;
                    }
                    let key = self.compose_node(event, depth + 1)?;
                    let event = self.next()?;
                    let value = self.compose_node(event, depth + 1)?;
                    pairs.push((key, value));
                }
                (
                    Node {
                        kind: NodeKind::Map(pairs),
                        tag: full_tag(tag),
                    },
                    anchor,
                )
            }
            other => return Err(err(format!("unexpected YAML event {other:?}"))),
        };
        let node = Rc::new(node);
        if anchor != 0 {
            self.anchors.insert(anchor, Rc::clone(&node));
        }
        Ok(node)
    }
}

/// PyYAML `Composer.get_single_node`: None for an empty stream.
fn compose(text: &str) -> Result<Option<Rc<Node>>> {
    let mut composer = Composer {
        parser: Parser::new_from_str(text),
        anchors: HashMap::new(),
        text,
        block_eof: None,
        mark: None,
    };
    if composer.next()? != Event::StreamStart {
        return Err(err("did not find expected <stream-start>"));
    }
    let mut root = None;
    loop {
        match composer.next()? {
            Event::StreamEnd => return Ok(root),
            Event::DocumentStart => {
                if root.is_some() {
                    return Err(err("expected a single document in the stream"));
                }
                composer.anchors.clear();
                let event = composer.next()?;
                root = Some(composer.compose_node(event, 0)?);
                if composer.next()? != Event::DocumentEnd {
                    return Err(err("did not find expected <document end>"));
                }
            }
            other => return Err(err(format!("unexpected YAML event {other:?}"))),
        }
    }
}

// ---- constructor: node graph → Value (PyYAML SafeConstructor) --------------------------------

const STR_TAG: &str = "tag:yaml.org,2002:str";
const SEQ_TAG: &str = "tag:yaml.org,2002:seq";
const MAP_TAG: &str = "tag:yaml.org,2002:map";

#[derive(Default)]
struct Constructor {
    nodes: usize,
    /// Scalar nodes constructed at least once (by address): a second construction is an
    /// alias copy.
    scalars_seen: std::collections::HashSet<usize>,
    /// Bytes of scalar text copied by alias expansion.
    copied_bytes: usize,
}

fn no_constructor(tag: &str) -> ConsoleError {
    err(format!(
        "could not determine a constructor for the tag {}",
        py_repr(tag)
    ))
}

/// CPython `int()`/`float()` whitespace: `str.isspace()` minus U+001C..=U+001F.
fn py_num_strip(text: &str) -> &str {
    text.trim_matches(|c: char| is_py_space(c) && !('\u{1c}'..='\u{1f}').contains(&c))
}

enum IntError {
    Invalid,
    Overflow,
}

/// Python `int(text, base)` for the text PyYAML hands it (underscores already removed):
/// surrounding whitespace stripped, an optional sign, for base 2/8/16 an optional
/// `0b`/`0o`/`0x` prefix (either case), then ASCII digits of the base. Overflow of i128 is
/// reported separately (the literal itself is valid).
fn py_int_base(text: &str, base: u32) -> std::result::Result<i128, IntError> {
    let mut rest = py_num_strip(text);
    let negative = rest.starts_with('-');
    if rest.starts_with(['-', '+']) {
        rest = &rest[1..];
    }
    let prefix = match base {
        2 => Some(['b', 'B']),
        8 => Some(['o', 'O']),
        16 => Some(['x', 'X']),
        _ => None,
    };
    if let Some(letters) = prefix
        && let Some(tail) = rest.strip_prefix('0')
        && let Some(tail) = tail.strip_prefix(letters)
    {
        rest = tail;
    }
    if rest.is_empty() || !rest.chars().all(|c| c.is_digit(base)) {
        return Err(IntError::Invalid);
    }
    let mut value: i128 = 0;
    for c in rest.chars() {
        let d = c.to_digit(base).ok_or(IntError::Invalid)?;
        value = value
            .checked_mul(i128::from(base))
            .and_then(|v| v.checked_add(i128::from(d)))
            .ok_or(IntError::Overflow)?;
    }
    Ok(if negative { -value } else { value })
}

/// PyYAML `construct_yaml_int`; `original` is the scalar text (for the range message).
fn construct_int(original: &str) -> Result<Value> {
    let mut value: String = original.chars().filter(|c| *c != '_').collect();
    let mut sign: i128 = 1;
    if value.starts_with('-') {
        sign = -1;
    }
    if value.starts_with(['-', '+']) {
        value.remove(0);
    }
    let out_of_range = || err(format!("integer out of range: {original}"));
    let int = |digits: &str, base: u32| {
        py_int_base(digits, base).map_err(|e| match e {
            IntError::Overflow => out_of_range(),
            IntError::Invalid => err(format!(
                "invalid literal for int() with base {base}: {}",
                py_repr(digits)
            )),
        })
    };
    let magnitude: i128 = if value == "0" {
        0
    } else if let Some(digits) = value.strip_prefix("0b") {
        int(digits, 2)?
    } else if let Some(digits) = value.strip_prefix("0x") {
        int(digits, 16)?
    } else if value.starts_with('0') {
        int(&value, 8)?
    } else if value.contains(':') {
        let parts = value
            .split(':')
            .map(|part| int(part, 10))
            .collect::<Result<Vec<_>>>()?;
        let mut total: i128 = 0;
        let mut base: i128 = 1;
        for digit in parts.into_iter().rev() {
            total = digit
                .checked_mul(base)
                .and_then(|d| total.checked_add(d))
                .ok_or_else(out_of_range)?;
            base = base.checked_mul(60).ok_or_else(out_of_range)?;
        }
        total
    } else {
        int(&value, 10)?
    };
    let signed = magnitude.checked_mul(sign).ok_or_else(out_of_range)?;
    if let Ok(v) = i64::try_from(signed) {
        Ok(Value::Number(Number::from(v)))
    } else if let Ok(v) = u64::try_from(signed) {
        Ok(Value::Number(Number::from(v)))
    } else {
        Err(out_of_range())
    }
}

/// Python `float(text)` (ASCII decimal forms only).
fn py_float(text: &str) -> Option<f64> {
    let t = py_num_strip(text);
    let lower = t.to_ascii_lowercase();
    let body = lower.trim_start_matches(['+', '-']);
    if matches!(body, "inf" | "infinity" | "nan") {
        return lower.parse::<f64>().ok();
    }
    if t.is_empty()
        || !t
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
    {
        return None;
    }
    t.parse::<f64>().ok()
}

/// PyYAML `construct_yaml_float`.
fn construct_float(original: &str) -> Result<Value> {
    let mut value: String = original
        .chars()
        .filter(|c| *c != '_')
        .collect::<String>()
        .to_lowercase();
    let mut sign = 1.0;
    if value.starts_with('-') {
        sign = -1.0;
    }
    if value.starts_with(['-', '+']) {
        value.remove(0);
    }
    let invalid = |text: &str| {
        err(format!(
            "could not convert string to float: {}",
            py_repr(text)
        ))
    };
    let magnitude = if value == ".inf" {
        f64::INFINITY
    } else if value == ".nan" {
        f64::NAN
    } else if value.contains(':') {
        let mut total = 0.0;
        let mut base = 1.0;
        for part in value.split(':').rev() {
            total += py_float(part).ok_or_else(|| invalid(part))? * base;
            base *= 60.0;
        }
        total
    } else {
        py_float(&value).ok_or_else(|| invalid(&value))?
    };
    Ok(Value::Number(Number::from(sign * magnitude)))
}

fn tagged(tag: &str, text: &str) -> Value {
    Value::Tagged(Box::new(TaggedValue {
        tag: Tag::new(tag),
        value: Value::String(text.to_owned()),
    }))
}

/// Python dict hash/equality class of a bool/int/float key (`1 == 1.0 == True`, exactly as
/// Python compares an int with a float; PyYAML's single `nan` object collides with itself).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum NumKey {
    Int(i128),
    Float(u64),
    Nan,
}

fn num_key(value: &Value) -> Option<NumKey> {
    match value {
        Value::Bool(b) => Some(NumKey::Int(i128::from(*b))),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(NumKey::Int(i128::from(i)))
            } else if let Some(u) = n.as_u64() {
                Some(NumKey::Int(i128::from(u)))
            } else {
                let f = n.as_f64()?;
                if f.is_nan() {
                    Some(NumKey::Nan)
                } else if f.fract() == 0.0 && f.abs() < 1.0e38 {
                    // An integral float within i128 is exactly that integer.
                    #[allow(clippy::cast_possible_truncation)]
                    Some(NumKey::Int(f as i128))
                } else {
                    Some(NumKey::Float(f.to_bits()))
                }
            }
        }
        _ => None,
    }
}

/// A Python dict under construction: `dict[key] = value` — an existing (Python-equal) key
/// keeps its first position and its first key object and takes the new value. Numeric keys
/// are found through a side index (O(1), not a scan).
#[derive(Default)]
struct PyDict {
    map: Mapping,
    numeric: HashMap<NumKey, Value>,
}

impl PyDict {
    fn insert(&mut self, key: Value, value: Value) {
        if let Some(class) = num_key(&key) {
            match self.numeric.get(&class) {
                Some(existing) => {
                    self.map.insert(existing.clone(), value);
                }
                None => {
                    self.numeric.insert(class, key.clone());
                    self.map.insert(key, value);
                }
            }
            return;
        }
        self.map.insert(key, value);
    }
}

impl Constructor {
    fn count(&mut self) -> Result<()> {
        self.charge(1)
    }

    fn charge(&mut self, n: usize) -> Result<()> {
        self.nodes = self.nodes.saturating_add(n);
        if self.nodes > MAX_NODES {
            return Err(err(format!(
                "document too large: more than {MAX_NODES} nodes after alias expansion"
            )));
        }
        Ok(())
    }

    /// A scalar node constructed a second time is an alias copy: charge its text.
    #[inline(never)]
    fn charge_copy(&mut self, node: &Node, text: &str) -> Result<()> {
        if self.scalars_seen.insert(std::ptr::from_ref(node).addr()) {
            return Ok(());
        }
        self.copied_bytes = self.copied_bytes.saturating_add(text.len());
        if self.copied_bytes > MAX_COPIED_BYTES {
            return Err(err(format!(
                "document too large: more than {MAX_COPIED_BYTES} bytes of scalar text \
                 copied by alias expansion"
            )));
        }
        Ok(())
    }

    fn construct(&mut self, node: &Node, depth: usize) -> Result<Value> {
        self.count()?;
        if depth > MAX_DEPTH {
            return Err(err(format!(
                "maximum nesting depth of {MAX_DEPTH} exceeded"
            )));
        }
        let tag = node.tag.as_deref();
        match &node.kind {
            NodeKind::Scalar { text, plain } => {
                self.charge_copy(node, text)?;
                self.construct_scalar(text, *plain, tag)
            }
            NodeKind::Seq(items) => match tag {
                None | Some("!") | Some(SEQ_TAG) => {
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        out.push(self.construct(item, depth + 1)?);
                    }
                    Ok(Value::Sequence(out))
                }
                Some(MAP_TAG) => Err(err(format!(
                    "expected a mapping node, but found {}",
                    node.id()
                ))),
                Some(t) if t.starts_with("tag:yaml.org,2002:") && is_scalar_tag(t) => Err(err(
                    format!("expected a scalar node, but found {}", node.id()),
                )),
                Some(t) => Err(no_constructor(t)),
            },
            NodeKind::Map(_) => match tag {
                None | Some("!") | Some(MAP_TAG) => self.construct_mapping(node, depth),
                Some(SEQ_TAG) => Err(err(format!(
                    "expected a sequence node, but found {}",
                    node.id()
                ))),
                Some(t) if t.starts_with("tag:yaml.org,2002:") && is_scalar_tag(t) => Err(err(
                    format!("expected a scalar node, but found {}", node.id()),
                )),
                Some(t) => Err(no_constructor(t)),
            },
        }
    }

    fn construct_scalar(&mut self, text: &str, plain: bool, tag: Option<&str>) -> Result<Value> {
        // PyYAML parser: a plain untagged scalar, or ANY scalar with the non-specific `!`
        // tag, is resolved implicitly (`implicit = (True, False)`).
        let resolved = match tag {
            None if plain => resolve_plain(text).tag(),
            Some("!") => resolve_plain(text).tag(),
            None => STR_TAG,
            Some(t) => t,
        };
        match resolved {
            "tag:yaml.org,2002:str" => Ok(Value::String(text.to_owned())),
            "tag:yaml.org,2002:null" => Ok(Value::Null),
            "tag:yaml.org,2002:bool" => match text.to_lowercase().as_str() {
                "yes" | "true" | "on" => Ok(Value::Bool(true)),
                "no" | "false" | "off" => Ok(Value::Bool(false)),
                _ => Err(err(format!("invalid boolean value {}", py_repr(text)))),
            },
            "tag:yaml.org,2002:int" => construct_int(text),
            "tag:yaml.org,2002:float" => construct_float(text),
            "tag:yaml.org,2002:timestamp" => {
                let ts = parse_timestamp_fields(text)
                    .ok_or_else(|| err(format!("invalid timestamp {}", py_repr(text))))?;
                ts.validate()?;
                Ok(tagged(TIMESTAMP_TAG, text))
            }
            "tag:yaml.org,2002:binary" => {
                if !text.is_ascii() {
                    return Err(err(
                        "failed to convert base64 data into ascii: 'ascii' codec can't \
                         encode characters",
                    ));
                }
                a2b_base64_lenient(text)
                    .map_err(|e| err(format!("failed to decode base64 data: {}", e.message)))?;
                Ok(tagged(BINARY_TAG, text))
            }
            "tag:yaml.org,2002:seq" => Err(err("expected a sequence node, but found scalar")),
            "tag:yaml.org,2002:map" => Err(err("expected a mapping node, but found scalar")),
            other => Err(no_constructor(other)),
        }
    }

    /// PyYAML `flatten_mapping`: merged pairs first (later sources before earlier ones, so
    /// that the earlier source wins), then the node's own pairs.
    fn flatten<'n>(&mut self, node: &'n Node, depth: usize) -> Result<Vec<(&'n Node, &'n Node)>> {
        if depth > MAX_DEPTH {
            return Err(err(format!(
                "maximum nesting depth of {MAX_DEPTH} exceeded"
            )));
        }
        let NodeKind::Map(pairs) = &node.kind else {
            return Ok(Vec::new());
        };
        let mut merge: Vec<(&Node, &Node)> = Vec::new();
        let mut own: Vec<(&Node, &Node)> = Vec::new();
        for (key, value) in pairs {
            if is_merge_key(key) {
                match &value.kind {
                    NodeKind::Map(_) => merge.extend(self.flatten(value, depth + 1)?),
                    NodeKind::Seq(items) => {
                        let mut submerge = Vec::new();
                        for sub in items {
                            if !matches!(sub.kind, NodeKind::Map(_)) {
                                return Err(err(format!(
                                    "expected a mapping for merging, but found {}",
                                    sub.id()
                                )));
                            }
                            submerge.push(self.flatten(sub, depth + 1)?);
                        }
                        for pairs in submerge.into_iter().rev() {
                            merge.extend(pairs);
                        }
                    }
                    NodeKind::Scalar { .. } => {
                        return Err(err(format!(
                            "expected a mapping or list of mappings for merging, but found {}",
                            value.id()
                        )));
                    }
                }
            } else {
                own.push((key.as_ref(), value.as_ref()));
            }
        }
        merge.extend(own);
        // Merged pair lists count against the value budget too: nested `<<` lists of
        // aliases otherwise grow exponentially before anything is constructed.
        self.charge(merge.len())?;
        Ok(merge)
    }

    fn construct_mapping(&mut self, node: &Node, depth: usize) -> Result<Value> {
        let pairs = self.flatten(node, depth)?;
        let mut dict = PyDict::default();
        for (key_node, value_node) in pairs {
            let key = if is_value_key(key_node) {
                // PyYAML `flatten_mapping` retags a `!!value` key as `!!str`.
                self.count()?;
                match &key_node.kind {
                    NodeKind::Scalar { text, .. } => Value::String(text.clone()),
                    _ => {
                        return Err(err(format!(
                            "expected a scalar node, but found {}",
                            key_node.id()
                        )));
                    }
                }
            } else {
                self.construct(key_node, depth + 1)?
            };
            if matches!(key, Value::Sequence(_) | Value::Mapping(_)) {
                return Err(err("found unhashable key"));
            }
            let value = self.construct(value_node, depth + 1)?;
            dict.insert(key, value);
        }
        Ok(Value::Mapping(dict.map))
    }
}

fn is_scalar_tag(tag: &str) -> bool {
    matches!(
        tag.strip_prefix("tag:yaml.org,2002:"),
        Some("str" | "int" | "float" | "bool" | "null" | "binary" | "timestamp")
    )
}

/// The node's tag as PyYAML's composer resolves it equals `resolved`: an untagged plain
/// scalar, or any scalar with the non-specific `!` tag, goes through the implicit resolvers;
/// an explicit tag is compared as is (for every node kind, like `flatten_mapping`).
fn scalar_resolves_to(node: &Node, resolved: Resolved) -> bool {
    match (&node.kind, node.tag.as_deref()) {
        (NodeKind::Scalar { text, plain: true }, None)
        | (NodeKind::Scalar { text, .. }, Some("!")) => resolve_plain(text) == resolved,
        (_, Some(tag)) => tag == resolved.tag(),
        _ => false,
    }
}

fn is_merge_key(node: &Node) -> bool {
    scalar_resolves_to(node, Resolved::Merge)
}

fn is_value_key(node: &Node) -> bool {
    scalar_resolves_to(node, Resolved::Value)
}

// ---- representer + serializer -------------------------------------------------------------

#[derive(Debug)]
struct DScalar {
    value: Vec<char>,
    /// Full tag.
    tag: &'static str,
    implicit: (bool, bool),
    /// Requested style (`|` for binary), None = default.
    style: Option<char>,
}

#[derive(Debug)]
enum DNode {
    Scalar(DScalar),
    Seq(Vec<DNode>),
    Map(Vec<(DNode, DNode)>),
}

fn scalar(value: String, resolved: Resolved, style: Option<char>) -> DNode {
    let tag = resolved.tag();
    // Serializer: implicit = (tag == resolve(value, (True, False)), tag == resolve(value,
    // (False, True))), the latter being the default str tag.
    let implicit = (resolve_plain(&value).tag() == tag, tag == STR_TAG);
    DNode::Scalar(DScalar {
        value: value.chars().collect(),
        tag,
        implicit,
        style,
    })
}

/// PyYAML `SafeRepresenter.represent_float`.
fn represent_float(value: f64) -> String {
    if value.is_nan() {
        ".nan".to_owned()
    } else if value == f64::INFINITY {
        ".inf".to_owned()
    } else if value == f64::NEG_INFINITY {
        "-.inf".to_owned()
    } else {
        let text = py_float_repr(value).to_lowercase();
        if !text.contains('.') && text.contains('e') {
            text.replacen('e', ".0e", 1)
        } else {
            text
        }
    }
}

fn represent(value: &Value) -> DNode {
    match value {
        Value::Null => scalar("null".to_owned(), Resolved::Null, None),
        Value::Bool(b) => scalar(
            if *b { "true" } else { "false" }.to_owned(),
            Resolved::Bool,
            None,
        ),
        Value::Number(n) => {
            if n.is_f64() {
                scalar(
                    represent_float(n.as_f64().unwrap_or(f64::NAN)),
                    Resolved::Float,
                    None,
                )
            } else {
                scalar(number_repr(n), Resolved::Int, None)
            }
        }
        Value::String(s) => scalar(s.clone(), Resolved::Str, None),
        Value::Sequence(items) => DNode::Seq(items.iter().map(represent).collect()),
        Value::Mapping(map) => DNode::Map(
            map.iter()
                .map(|(k, v)| (represent(k), represent(v)))
                .collect(),
        ),
        Value::Tagged(t) => {
            if t.tag == TIMESTAMP_TAG
                && let Some(ts) = tagged_text(t).and_then(parse_timestamp_fields)
            {
                return scalar(ts.isoformat(), Resolved::Timestamp, None);
            }
            if t.tag == BINARY_TAG
                && let Some(text) = tagged_text(t)
            {
                let bytes = a2b_base64_lenient(text).unwrap_or_default();
                let tag = "tag:yaml.org,2002:binary";
                return DNode::Scalar(DScalar {
                    value: encodebytes(&bytes).chars().collect(),
                    tag,
                    implicit: (false, false),
                    style: Some('|'),
                });
            }
            represent(&t.value)
        }
    }
}

// ---- emitter (PyYAML Emitter port) --------------------------------------------------------

const BEST_INDENT: usize = 2;
const BEST_WIDTH: usize = 80;

#[derive(Debug, Default)]
struct Analysis {
    empty: bool,
    multiline: bool,
    allow_flow_plain: bool,
    allow_block_plain: bool,
    allow_single_quoted: bool,
    allow_block: bool,
}

fn is_break(ch: char) -> bool {
    matches!(ch, '\n' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

fn is_space_or_break_z(ch: char) -> bool {
    matches!(
        ch,
        '\0' | ' ' | '\t' | '\r' | '\n' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// PyYAML `Emitter.analyze_scalar` with `allow_unicode=False`.
fn analyze_scalar(scalar: &[char]) -> Analysis {
    if scalar.is_empty() {
        return Analysis {
            empty: true,
            multiline: false,
            allow_flow_plain: false,
            allow_block_plain: true,
            allow_single_quoted: true,
            allow_block: false,
        };
    }
    let mut block_indicators = false;
    let mut flow_indicators = false;
    let mut line_breaks = false;
    let mut special_characters = false;
    let mut leading_space = false;
    let mut leading_break = false;
    let mut trailing_space = false;
    let mut trailing_break = false;
    let mut break_space = false;
    let mut space_break = false;
    let starts_with = |prefix: &str| {
        let p: Vec<char> = prefix.chars().collect();
        scalar.starts_with(&p)
    };
    if starts_with("---") || starts_with("...") {
        block_indicators = true;
        flow_indicators = true;
    }
    let mut preceded_by_whitespace = true;
    let mut followed_by_whitespace = scalar.len() == 1 || is_space_or_break_z(scalar[1]);
    let mut previous_space = false;
    let mut previous_break = false;
    let len = scalar.len();
    for (index, &ch) in scalar.iter().enumerate() {
        if index == 0 {
            if "#,[]{}&*!|>'\"%@`".contains(ch) {
                flow_indicators = true;
                block_indicators = true;
            }
            if ch == '?' || ch == ':' {
                flow_indicators = true;
                if followed_by_whitespace {
                    block_indicators = true;
                }
            }
            if ch == '-' && followed_by_whitespace {
                flow_indicators = true;
                block_indicators = true;
            }
        } else {
            if ",?[]{}".contains(ch) {
                flow_indicators = true;
            }
            if ch == ':' {
                flow_indicators = true;
                if followed_by_whitespace {
                    block_indicators = true;
                }
            }
            if ch == '#' && preceded_by_whitespace {
                flow_indicators = true;
                block_indicators = true;
            }
        }
        if is_break(ch) {
            line_breaks = true;
        }
        if !(ch == '\n' || ('\x20'..='\x7e').contains(&ch)) {
            // allow_unicode=False: unicode characters are special too.
            special_characters = true;
        }
        if ch == ' ' {
            if index == 0 {
                leading_space = true;
            }
            if index == len - 1 {
                trailing_space = true;
            }
            if previous_break {
                break_space = true;
            }
            previous_space = true;
            previous_break = false;
        } else if is_break(ch) {
            if index == 0 {
                leading_break = true;
            }
            if index == len - 1 {
                trailing_break = true;
            }
            if previous_space {
                space_break = true;
            }
            previous_space = false;
            previous_break = true;
        } else {
            previous_space = false;
            previous_break = false;
        }
        preceded_by_whitespace = is_space_or_break_z(ch);
        followed_by_whitespace = index + 2 >= len || is_space_or_break_z(scalar[index + 2]);
    }
    let mut a = Analysis {
        empty: false,
        multiline: line_breaks,
        allow_flow_plain: true,
        allow_block_plain: true,
        allow_single_quoted: true,
        allow_block: true,
    };
    if leading_space || leading_break || trailing_space || trailing_break {
        a.allow_flow_plain = false;
        a.allow_block_plain = false;
    }
    if trailing_space {
        a.allow_block = false;
    }
    if break_space {
        a.allow_flow_plain = false;
        a.allow_block_plain = false;
        a.allow_single_quoted = false;
    }
    if space_break || special_characters {
        a.allow_flow_plain = false;
        a.allow_block_plain = false;
        a.allow_single_quoted = false;
        a.allow_block = false;
    }
    if line_breaks {
        a.allow_flow_plain = false;
        a.allow_block_plain = false;
    }
    if flow_indicators {
        a.allow_flow_plain = false;
    }
    if block_indicators {
        a.allow_block_plain = false;
    }
    a
}

/// PyYAML `prepare_tag` for the `tag:yaml.org,2002:` tags r2 emits.
fn prepare_tag(tag: &str) -> String {
    match tag.strip_prefix("tag:yaml.org,2002:") {
        Some(suffix) => format!("!!{suffix}"),
        None => format!("!<{tag}>"),
    }
}

struct Emitter {
    out: String,
    indents: Vec<Option<usize>>,
    indent: Option<usize>,
    flow_level: usize,
    root_context: bool,
    mapping_context: bool,
    simple_key_context: bool,
    column: usize,
    whitespace: bool,
    indention: bool,
    open_ended: bool,
}

impl Emitter {
    fn new() -> Self {
        Self {
            out: String::new(),
            indents: Vec::new(),
            indent: None,
            flow_level: 0,
            root_context: false,
            mapping_context: false,
            simple_key_context: false,
            column: 0,
            whitespace: true,
            indention: true,
            open_ended: false,
        }
    }

    fn increase_indent(&mut self, flow: bool, indentless: bool) {
        self.indents.push(self.indent);
        match self.indent {
            None => self.indent = Some(if flow { BEST_INDENT } else { 0 }),
            Some(indent) if !indentless => self.indent = Some(indent + BEST_INDENT),
            Some(_) => {}
        }
    }

    fn pop_indent(&mut self) {
        self.indent = self.indents.pop().flatten();
    }

    fn expect_node(
        &mut self,
        node: &DNode,
        root: bool,
        _sequence: bool,
        mapping: bool,
        simple_key: bool,
    ) {
        self.root_context = root;
        self.mapping_context = mapping;
        self.simple_key_context = simple_key;
        match node {
            DNode::Scalar(s) => {
                let analysis = analyze_scalar(&s.value);
                let style = self.choose_scalar_style(s, &analysis);
                // process_tag
                let implicit_ok =
                    (style.is_none() && s.implicit.0) || (style.is_some() && s.implicit.1);
                if !implicit_ok {
                    let tag = prepare_tag(s.tag);
                    self.write_indicator(&tag, true, false, false);
                }
                // expect_scalar
                self.increase_indent(true, false);
                self.process_scalar(s, style);
                self.pop_indent();
            }
            DNode::Seq(items) => {
                if self.flow_level > 0 || items.is_empty() {
                    self.write_indicator("[", true, true, false);
                    self.flow_level += 1;
                    self.increase_indent(true, false);
                    for (i, item) in items.iter().enumerate() {
                        if i > 0 {
                            self.write_indicator(",", false, false, false);
                        }
                        if self.column > BEST_WIDTH {
                            self.write_indent();
                        }
                        self.expect_node(item, false, true, false, false);
                    }
                    self.pop_indent();
                    self.flow_level -= 1;
                    self.write_indicator("]", false, false, false);
                } else {
                    let indentless = self.mapping_context && !self.indention;
                    self.increase_indent(false, indentless);
                    for item in items {
                        self.write_indent();
                        self.write_indicator("-", true, false, true);
                        self.expect_node(item, false, true, false, false);
                    }
                    self.pop_indent();
                }
            }
            DNode::Map(pairs) => {
                if self.flow_level > 0 || pairs.is_empty() {
                    self.write_indicator("{", true, true, false);
                    self.flow_level += 1;
                    self.increase_indent(true, false);
                    for (i, (key, value)) in pairs.iter().enumerate() {
                        if i > 0 {
                            self.write_indicator(",", false, false, false);
                        }
                        if self.column > BEST_WIDTH {
                            self.write_indent();
                        }
                        if check_simple_key(key) {
                            self.expect_node(key, false, false, true, true);
                            self.write_indicator(":", false, false, false);
                        } else {
                            self.write_indicator("?", true, false, false);
                            self.expect_node(key, false, false, true, false);
                            if self.column > BEST_WIDTH {
                                self.write_indent();
                            }
                            self.write_indicator(":", true, false, false);
                        }
                        self.expect_node(value, false, false, true, false);
                    }
                    self.pop_indent();
                    self.flow_level -= 1;
                    self.write_indicator("}", false, false, false);
                } else {
                    self.increase_indent(false, false);
                    for (key, value) in pairs {
                        self.write_indent();
                        if check_simple_key(key) {
                            self.expect_node(key, false, false, true, true);
                            self.write_indicator(":", false, false, false);
                        } else {
                            self.write_indicator("?", true, false, true);
                            self.expect_node(key, false, false, true, false);
                            self.write_indent();
                            self.write_indicator(":", true, false, true);
                        }
                        self.expect_node(value, false, false, true, false);
                    }
                    self.pop_indent();
                }
            }
        }
    }

    /// PyYAML `choose_scalar_style`: None = plain, Some('\'' | '"' | '|' | '>').
    fn choose_scalar_style(&self, s: &DScalar, a: &Analysis) -> Option<char> {
        if s.style == Some('"') {
            return Some('"');
        }
        if s.style.is_none()
            && s.implicit.0
            && !(self.simple_key_context && (a.empty || a.multiline))
            && ((self.flow_level > 0 && a.allow_flow_plain)
                || (self.flow_level == 0 && a.allow_block_plain))
        {
            return None;
        }
        if let Some(style @ ('|' | '>')) = s.style
            && self.flow_level == 0
            && !self.simple_key_context
            && a.allow_block
        {
            return Some(style);
        }
        if (s.style.is_none() || s.style == Some('\''))
            && a.allow_single_quoted
            && !(self.simple_key_context && a.multiline)
        {
            return Some('\'');
        }
        Some('"')
    }

    fn process_scalar(&mut self, s: &DScalar, style: Option<char>) {
        let split = !self.simple_key_context;
        match style {
            Some('"') => self.write_double_quoted(&s.value, split),
            Some('\'') => self.write_single_quoted(&s.value, split),
            Some('|') => self.write_literal(&s.value),
            Some(_) => self.write_folded(&s.value),
            None => self.write_plain(&s.value, split),
        }
    }

    fn write_str(&mut self, data: &str) {
        self.out.push_str(data);
    }

    fn write_chars(&mut self, data: &[char]) {
        self.column += data.len();
        self.out.extend(data.iter());
    }

    fn write_indicator(
        &mut self,
        indicator: &str,
        need_whitespace: bool,
        whitespace: bool,
        indention: bool,
    ) {
        let data = if self.whitespace || !need_whitespace {
            indicator.to_owned()
        } else {
            format!(" {indicator}")
        };
        self.whitespace = whitespace;
        self.indention = self.indention && indention;
        self.column += data.chars().count();
        self.open_ended = false;
        self.write_str(&data);
    }

    fn write_indent(&mut self) {
        let indent = self.indent.unwrap_or(0);
        if !self.indention || self.column > indent || (self.column == indent && !self.whitespace) {
            self.write_line_break(None);
        }
        if self.column < indent {
            self.whitespace = true;
            let data = " ".repeat(indent - self.column);
            self.column = indent;
            self.write_str(&data);
        }
    }

    fn write_line_break(&mut self, data: Option<char>) {
        self.whitespace = true;
        self.indention = true;
        self.column = 0;
        self.out.push(data.unwrap_or('\n'));
    }

    fn write_line_breaks(&mut self, breaks: &[char]) {
        for &br in breaks {
            if br == '\n' {
                self.write_line_break(None);
            } else {
                self.write_line_break(Some(br));
            }
        }
    }

    fn write_single_quoted(&mut self, text: &[char], split: bool) {
        self.write_indicator("'", true, false, false);
        let mut spaces = false;
        let mut breaks = false;
        let mut start = 0;
        let mut end = 0;
        while end <= text.len() {
            let ch = text.get(end).copied();
            if spaces {
                if ch != Some(' ') {
                    if start + 1 == end
                        && self.column > BEST_WIDTH
                        && split
                        && start != 0
                        && end != text.len()
                    {
                        self.write_indent();
                    } else {
                        self.write_chars(&text[start..end]);
                    }
                    start = end;
                }
            } else if breaks {
                if ch.is_none_or(|c| !is_break(c)) {
                    if text[start] == '\n' {
                        self.write_line_break(None);
                    }
                    self.write_line_breaks(&text[start..end]);
                    self.write_indent();
                    start = end;
                }
            } else if (ch.is_none_or(|c| c == ' ' || is_break(c) || c == '\'')) && start < end {
                self.write_chars(&text[start..end]);
                start = end;
            }
            if ch == Some('\'') {
                self.column += 2;
                self.write_str("''");
                start = end + 1;
            }
            if let Some(c) = ch {
                spaces = c == ' ';
                breaks = is_break(c);
            }
            end += 1;
        }
        self.write_indicator("'", false, false, false);
    }

    fn write_double_quoted(&mut self, text: &[char], split: bool) {
        self.write_indicator("\"", true, false, false);
        let mut start = 0;
        let mut end = 0;
        while end <= text.len() {
            let ch = text.get(end).copied();
            let needs_escape = match ch {
                None => true,
                Some(c) => {
                    matches!(
                        c,
                        '"' | '\\' | '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{feff}'
                    ) || !('\x20'..='\x7e').contains(&c)
                }
            };
            if needs_escape {
                if start < end {
                    self.write_chars(&text[start..end]);
                    start = end;
                }
                if let Some(c) = ch {
                    let data = match c {
                        '\0' => "\\0".to_owned(),
                        '\x07' => "\\a".to_owned(),
                        '\x08' => "\\b".to_owned(),
                        '\x09' => "\\t".to_owned(),
                        '\x0a' => "\\n".to_owned(),
                        '\x0b' => "\\v".to_owned(),
                        '\x0c' => "\\f".to_owned(),
                        '\x0d' => "\\r".to_owned(),
                        '\x1b' => "\\e".to_owned(),
                        '"' => "\\\"".to_owned(),
                        '\\' => "\\\\".to_owned(),
                        '\u{85}' => "\\N".to_owned(),
                        '\u{a0}' => "\\_".to_owned(),
                        '\u{2028}' => "\\L".to_owned(),
                        '\u{2029}' => "\\P".to_owned(),
                        c if u32::from(c) <= 0xff => format!("\\x{:02X}", u32::from(c)),
                        c if u32::from(c) <= 0xffff => format!("\\u{:04X}", u32::from(c)),
                        c => format!("\\U{:08X}", u32::from(c)),
                    };
                    self.column += data.chars().count();
                    self.write_str(&data);
                    start = end + 1;
                }
            }
            // Python: `self.column + (end - start)`, where `start` may be `end + 1`.
            let width = self.column as isize + end as isize - start as isize;
            if 0 < end
                && end + 1 < text.len()
                && (ch == Some(' ') || start >= end)
                && width > BEST_WIDTH as isize
                && split
            {
                // Python slicing: an inverted range is empty.
                let mut data: String = text[start.min(end)..end].iter().collect();
                data.push('\\');
                if start < end {
                    start = end;
                }
                self.column += data.chars().count();
                self.write_str(&data);
                self.write_indent();
                self.whitespace = false;
                self.indention = false;
                if text[start] == ' ' {
                    self.column += 1;
                    self.write_str("\\");
                }
            }
            end += 1;
        }
        self.write_indicator("\"", false, false, false);
    }

    fn determine_block_hints(text: &[char]) -> String {
        let mut hints = String::new();
        if let (Some(&first), Some(&last)) = (text.first(), text.last()) {
            if first == ' ' || is_break(first) {
                hints.push_str(&BEST_INDENT.to_string());
            }
            if !is_break(last) {
                hints.push('-');
            } else if text.len() == 1 || is_break(text[text.len() - 2]) {
                hints.push('+');
            }
        }
        hints
    }

    fn write_folded(&mut self, text: &[char]) {
        let hints = Self::determine_block_hints(text);
        self.write_indicator(&format!(">{hints}"), true, false, false);
        if hints.ends_with('+') {
            self.open_ended = true;
        }
        self.write_line_break(None);
        let mut leading_space = true;
        let mut spaces = false;
        let mut breaks = true;
        let mut start = 0;
        let mut end = 0;
        while end <= text.len() {
            let ch = text.get(end).copied();
            if breaks {
                if ch.is_none_or(|c| !is_break(c)) {
                    if !leading_space && ch.is_some_and(|c| c != ' ') && text[start] == '\n' {
                        self.write_line_break(None);
                    }
                    leading_space = ch == Some(' ');
                    self.write_line_breaks(&text[start..end]);
                    if ch.is_some() {
                        self.write_indent();
                    }
                    start = end;
                }
            } else if spaces {
                if ch != Some(' ') {
                    if start + 1 == end && self.column > BEST_WIDTH {
                        self.write_indent();
                    } else {
                        self.write_chars(&text[start..end]);
                    }
                    start = end;
                }
            } else if ch.is_none_or(|c| c == ' ' || is_break(c)) {
                self.write_chars(&text[start..end]);
                if ch.is_none() {
                    self.write_line_break(None);
                }
                start = end;
            }
            if let Some(c) = ch {
                breaks = is_break(c);
                spaces = c == ' ';
            }
            end += 1;
        }
    }

    fn write_literal(&mut self, text: &[char]) {
        let hints = Self::determine_block_hints(text);
        self.write_indicator(&format!("|{hints}"), true, false, false);
        if hints.ends_with('+') {
            self.open_ended = true;
        }
        self.write_line_break(None);
        let mut breaks = true;
        let mut start = 0;
        let mut end = 0;
        while end <= text.len() {
            let ch = text.get(end).copied();
            if breaks {
                if ch.is_none_or(|c| !is_break(c)) {
                    self.write_line_breaks(&text[start..end]);
                    if ch.is_some() {
                        self.write_indent();
                    }
                    start = end;
                }
            } else if ch.is_none_or(is_break) {
                // write_literal does not advance the column (PyYAML).
                self.out.extend(text[start..end].iter());
                if ch.is_none() {
                    self.write_line_break(None);
                }
                start = end;
            }
            if let Some(c) = ch {
                breaks = is_break(c);
            }
            end += 1;
        }
    }

    fn write_plain(&mut self, text: &[char], split: bool) {
        if self.root_context {
            self.open_ended = true;
        }
        if text.is_empty() {
            return;
        }
        if !self.whitespace {
            self.column += 1;
            self.write_str(" ");
        }
        self.whitespace = false;
        self.indention = false;
        let mut spaces = false;
        let mut breaks = false;
        let mut start = 0;
        let mut end = 0;
        while end <= text.len() {
            let ch = text.get(end).copied();
            if spaces {
                if ch != Some(' ') {
                    if start + 1 == end && self.column > BEST_WIDTH && split {
                        self.write_indent();
                        self.whitespace = false;
                        self.indention = false;
                    } else {
                        self.write_chars(&text[start..end]);
                    }
                    start = end;
                }
            } else if breaks {
                if ch.is_none_or(|c| !is_break(c)) {
                    if text[start] == '\n' {
                        self.write_line_break(None);
                    }
                    self.write_line_breaks(&text[start..end]);
                    self.write_indent();
                    self.whitespace = false;
                    self.indention = false;
                    start = end;
                }
            } else if ch.is_none_or(|c| c == ' ' || is_break(c)) {
                self.write_chars(&text[start..end]);
                start = end;
            }
            if let Some(c) = ch {
                spaces = c == ' ';
                breaks = is_break(c);
            }
            end += 1;
        }
    }
}

/// PyYAML `check_simple_key` (the tag length counts even when the tag is not written).
fn check_simple_key(node: &DNode) -> bool {
    match node {
        DNode::Scalar(s) => {
            let analysis = analyze_scalar(&s.value);
            let length = prepare_tag(s.tag).chars().count() + s.value.len();
            length < 128 && !analysis.empty && !analysis.multiline
        }
        DNode::Seq(items) => items.is_empty(),
        DNode::Map(pairs) => pairs.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_repr_matches_python() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (1.5, "1.5"),
            (1e16, "1e+16"),
            (1.5e16, "1.5e+16"),
            (1e15, "1000000000000000.0"),
            (1e-4, "0.0001"),
            (1e-5, "1e-05"),
            (0.1, "0.1"),
            (123.456, "123.456"),
            (1e300, "1e+300"),
            (-2.5e-7, "-2.5e-07"),
            (5e-324, "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
        ];
        for (value, expected) in cases {
            assert_eq!(py_float_repr(*value), *expected, "{value}");
        }
        assert_eq!(represent_float(1e17), "1.0e+17");
        assert_eq!(represent_float(f64::NEG_INFINITY), "-.inf");
    }

    #[test]
    fn resolvers_follow_pyyaml() {
        for (text, expected) in [
            ("yes", Resolved::Bool),
            ("Off", Resolved::Bool),
            ("yEs", Resolved::Str),
            ("1.0", Resolved::Float),
            ("1e3", Resolved::Str),
            ("1.0e+3", Resolved::Float),
            ("1.0e3", Resolved::Str),
            (".5", Resolved::Float),
            ("1:30.5", Resolved::Float),
            ("-.inf", Resolved::Float),
            ("+.nan", Resolved::Str),
            ("017", Resolved::Int),
            ("08", Resolved::Str),
            ("0o17", Resolved::Str),
            ("0x1F", Resolved::Int),
            ("0b101", Resolved::Int),
            ("1:30", Resolved::Int),
            ("1:60", Resolved::Str),
            ("1_000", Resolved::Int),
            ("1_000x", Resolved::Str),
            ("<<", Resolved::Merge),
            ("~", Resolved::Null),
            ("", Resolved::Null),
            ("2001-12-14", Resolved::Timestamp),
            ("2001-1-1", Resolved::Str),
            ("2001-12-14t21:59:43.10-05:00", Resolved::Timestamp),
            ("2001-12-14 21:59:43.10 Z", Resolved::Timestamp),
            ("=", Resolved::Value),
        ] {
            assert_eq!(resolve_plain(text), expected, "{text:?}");
        }
    }

    #[test]
    fn lenient_base64_matches_cpython() {
        assert_eq!(a2b_base64_lenient("AQID").unwrap(), vec![1, 2, 3]);
        assert_eq!(a2b_base64_lenient("AQ==").unwrap(), vec![1]);
        assert_eq!(a2b_base64_lenient("A Q\n=*=").unwrap(), vec![1]);
        assert_eq!(
            a2b_base64_lenient("AQ").unwrap_err().message,
            "Incorrect padding"
        );
        assert!(a2b_base64_lenient("AQIDB").is_err());
        assert_eq!(encodebytes(&[1, 2, 3]), "AQID\n");
        assert_eq!(encodebytes(&[]), "");
        assert_eq!(encodebytes(&[0u8; 58]).lines().next().unwrap().len(), 76);
    }

    mod vectors {
        #![allow(dead_code)]
        include!("../tests/support/yaml_vectors.rs");
    }

    /// PyYAML `safe_load` typing, compared through Python `repr` (generated vectors).
    #[test]
    fn load_vectors_match_pyyaml() {
        for (text, expected) in vectors::LOAD {
            let got = parse(text);
            match (expected, &got) {
                (Ok(repr), Ok(value)) => {
                    assert_eq!(py_value_repr(value), *repr, "load {text:?}");
                }
                (Err(Some(message)), Err(e)) => assert_eq!(e.message, *message, "load {text:?}"),
                (Err(None), Err(_)) => {}
                _ => panic!("load {text:?}: expected {expected:?}, got {got:?}"),
            }
        }
    }

    /// Seeded random number-like plain scalars: same typing as PyYAML.
    #[test]
    fn load_fuzz_vectors_match_pyyaml() {
        for (text, repr) in vectors::LOAD_FUZZ {
            let value = parse(text).unwrap_or_else(|e| panic!("parse {text:?}: {e:?}"));
            assert_eq!(py_value_repr(&value), *repr, "load {text:?}");
        }
    }

    /// §11 D17 (e): alias expansion limits and anchor rebinding.
    #[test]
    fn alias_expansion_rules() {
        assert!(parse("a: &x [1, *x]").is_err());
        let v = parse("a: &x 1\nb: &x 2\nc: *x\n").unwrap();
        assert_eq!(py_value_repr(&v), "{'a': 1, 'b': 2, 'c': 2}");
        let deep = format!("{}{}", "[".repeat(1100), "]".repeat(1100));
        assert!(parse(&deep).is_err()); // yaml-rust2's own flow limit
        let block: String = (0..1100)
            .map(|i| format!("{}- \n", "  ".repeat(i)))
            .collect();
        assert!(parse(&block).unwrap_err().message.contains("nesting depth"));
        let ok: String = (0..400)
            .map(|i| format!("{}- \n", "  ".repeat(i)))
            .collect();
        let value = parse(&ok).unwrap();
        assert_eq!(dump(&value), format!("{}null\n", "- ".repeat(400)));
        assert!(py_value_repr(&value).ends_with(&format!("[None{}", "]".repeat(400))));
        let mut laughs = String::from("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
        for (i, name) in ["b", "c", "d", "e", "f", "g", "h"].iter().enumerate() {
            let prev = ["a", "b", "c", "d", "e", "f", "g"][i];
            laughs.push_str(&format!(
                "{name}: &{name} [*{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}]\n"
            ));
        }
        assert!(
            parse(&laughs)
                .unwrap_err()
                .message
                .starts_with("document too large")
        );
        // malformed explicit scalars: Python's ValueError texts (§11 D12 (f))
        assert_eq!(
            parse("!!int x").unwrap_err().message,
            "invalid literal for int() with base 10: 'x'"
        );
        assert_eq!(
            parse("!!float x").unwrap_err().message,
            "could not convert string to float: 'x'"
        );
    }

    /// Nested `<<` lists of aliases are charged against the value budget while they are
    /// flattened (they grow tenfold per level before anything is constructed).
    #[test]
    fn nested_merges_hit_the_value_budget() {
        fn level(i: usize) -> String {
            if i == 0 {
                return "&l0 {a: 1}".to_owned();
            }
            format!(
                "&l{i} {{<<: [{}{}]}}",
                level(i - 1),
                format!(", *l{}", i - 1).repeat(9)
            )
        }
        let doc = format!("x: {}", level(8));
        assert!(
            parse(&doc)
                .unwrap_err()
                .message
                .starts_with("document too large")
        );
        // a small nested merge still loads
        let ok = parse(&format!("x: {}", level(2))).unwrap();
        assert_eq!(py_value_repr(&ok), "{'x': {'a': 1}}");
    }

    /// §11 D17 (e): scalar text copied by alias expansion is bounded too (a 100 KB scalar
    /// aliased 11,110 times is far below the value budget but would need over 1 GB).
    #[test]
    fn aliased_large_scalar_hits_the_byte_budget() {
        let mut doc = format!("a: &a '{}'\n", "x".repeat(100_000));
        let mut prev = "a".to_owned();
        for i in 0..4 {
            let name = format!("n{i}");
            doc.push_str(&format!(
                "{name}: &{name} [{}]\n",
                vec![format!("*{prev}"); 10].join(", ")
            ));
            prev = name;
        }
        let e = parse(&doc).unwrap_err();
        assert!(
            e.message
                .starts_with("document too large: more than 67108864 bytes"),
            "{}",
            e.message
        );
        // a few hundred copies still load
        let ok = format!(
            "a: &a '{}'\nb: [{}]\n",
            "x".repeat(100_000),
            vec!["*a"; 600].join(", ")
        );
        let Value::Mapping(map) = parse(&ok).unwrap() else {
            panic!("not a mapping");
        };
        assert_eq!(map.len(), 2);
    }

    /// Numeric keys are deduplicated through an index, not a scan (40,000 keys load fast;
    /// the scan took seconds) and with Python's exact int/float equality.
    #[test]
    fn many_numeric_keys_load_in_linear_time() {
        let doc: String = (0..40_000).map(|i| format!("{i}: {i}\n")).collect();
        let start = std::time::Instant::now();
        let Value::Mapping(map) = parse(&doc).unwrap() else {
            panic!("not a mapping");
        };
        assert_eq!(map.len(), 40_000);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        let dup = parse("{1: a, 1.0: b, true: c, 2: d}").unwrap();
        assert_eq!(py_value_repr(&dup), "{1: 'c', 2: 'd'}");
    }

    /// §11 D17: the inputs PyYAML accepts and r2 rejects.
    #[test]
    fn load_r2_errors() {
        for (text, message) in vectors::LOAD_R2_ERRORS {
            let e = parse(text).unwrap_err();
            assert_eq!(e.message, *message, "{text:?}");
            assert_eq!(e.kind, r2_core::ErrorKind::Generic);
        }
    }

    /// Byte equality with PyYAML `safe_dump(sort_keys=False, default_flow_style=False)`.
    #[test]
    fn dump_vectors_match_pyyaml() {
        for (text, expected) in vectors::DUMP {
            let value = parse(text).unwrap_or_else(|e| panic!("parse {text:?}: {e:?}"));
            assert_eq!(dump(&value), *expected, "dump of {text:?}");
        }
    }
}
