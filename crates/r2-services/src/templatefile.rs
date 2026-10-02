// Template-file codec + editor seeding (spec §5.16, §4.9.10; owner R14) — c2
// `services/templatefile.py`.
//
// Serializes a provider's full attribute snapshot to a class-keyed YAML file and parses such
// files back into per-class `KeyTemplate` seeds for the template editor. Attribute kinds are
// resolved by NAME (`CKA_CATALOG` first, then `templates.custom_attributes`) — never inferred
// from the value, so a hex-looking CKA_LABEL stays a string. YAML goes through the PyYAML
// port of `r2_config::yaml` (§4.8.4), so a file dumped by c2 seeds r2 and vice versa.
use indexmap::IndexMap;
use r2_config::model::{
    CustomAttributeDef, TEMPLATE_CLASS_KEYS, TemplatesSection, template_class_key,
};
use r2_config::yaml::{self, Mapping, Number, Value};
use r2_core::catalog::cka;
use r2_core::error::ConsoleError;
use r2_core::io::TemplateEditor;
use r2_core::keys::{KeyAlgorithm, KeyClass};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_core::text::{os_error_text, py_bytes_repr, py_fromhex, py_int};
use std::path::Path;

use crate::keyexport::write_output;

/// §5.16 file sections: class key → template (kinds resolved by NAME).
pub type SeedTemplates = IndexMap<String, KeyTemplate>;
/// Read-only lifecycle + material attrs seeded DISABLED (§5.16).
pub const NON_CREATION_ATTRS: [&str; 27] = [
    "CKA_LOCAL",
    "CKA_ALWAYS_SENSITIVE",
    "CKA_NEVER_EXTRACTABLE",
    "CKA_KEY_GEN_MECHANISM",
    "CKA_MODULUS",
    "CKA_MODULUS_BITS",
    "CKA_PUBLIC_EXPONENT",
    "CKA_PRIVATE_EXPONENT",
    "CKA_PRIME_1",
    "CKA_PRIME_2",
    "CKA_EXPONENT_1",
    "CKA_EXPONENT_2",
    "CKA_COEFFICIENT",
    "CKA_PRIME",
    "CKA_SUBPRIME",
    "CKA_BASE",
    "CKA_EC_PARAMS",
    "CKA_EC_POINT",
    "CKA_VALUE",
    "CKA_VALUE_LEN",
    "CKA_CHECK_VALUE",
    "CKA_SERIAL_NUMBER",
    "CKA_ISSUER",
    "CKA_SUBJECT",
    "CKA_PUBLIC_KEY_INFO",
    "CKA_HASH_OF_SUBJECT_PUBLIC_KEY",
    "CKA_HASH_OF_ISSUER_PUBLIC_KEY",
];
/// Secret material a dump may carry — `key template` prints the handle-like-a-private-key note.
pub const SECRET_MATERIAL_ATTRS: [&str; 7] = [
    "CKA_VALUE",
    "CKA_PRIVATE_EXPONENT",
    "CKA_PRIME_1",
    "CKA_PRIME_2",
    "CKA_EXPONENT_1",
    "CKA_EXPONENT_2",
    "CKA_COEFFICIENT",
];

/// Enabled template identity rows are honored at creation (§4.7) — a dumped file carries
/// the SOURCE key's identity, so these are seeded DISABLED too.
const IDENTITY_ATTRS: [&str; 2] = ["CKA_LABEL", "CKA_ID"];
/// §4.8 symbolic ULONG values.
const SYMBOL_PREFIXES: [&str; 4] = ["CKO_", "CKK_", "CKC_", "CKM_"];

/// Write `template` as one class-keyed YAML section via `yaml::dump` + `keyexport::write_output`.
pub fn dump_template_file(
    path: &Path,
    class_key: &str,
    template: &KeyTemplate,
) -> r2_core::Result<()> {
    // c2: `{attr.name: _encode_value(attr) for attr in template.attrs}` — a repeated name
    // keeps its first position and its last value (IndexMap insert, as a Python dict).
    let mut section = Mapping::new();
    for attr in &template.attrs {
        section.insert(Value::String(attr.name.clone()), encode_value(attr)?);
    }
    let mut root = Mapping::new();
    root.insert(Value::String(class_key.to_owned()), Value::Mapping(section));
    let text = yaml::dump(&Value::Mapping(root));
    write_output(path, text.as_bytes())
}

/// ★ (R8, R10, R15 via cmdutil/copy) Parse a §5.16 file. Unreadable → DataIo "cannot read
/// {path}: {err}"; bad YAML → Param "invalid YAML in template file {path}: {err}" (param
/// "template", hint "template files are class-keyed YAML (spec §5.16)"); empty/non-mapping →
/// Param "template file {path} has no sections" (hint "valid sections: {TEMPLATE_CLASS_KEYS
/// joined ', '}"); unknown section → "unknown template section '{key}' in {path}"; section
/// not a mapping → "template section '{key}' in {path} is not a mapping" (hint "each section
/// maps CKA_* names to values"); unknown CKA name → Param "unknown PKCS#11 attribute
/// '{name}'" (hint "define it under templates.custom_attributes (code + kind)"); kind/value
/// mismatch (c2 `_value_from_yaml`, param_name = name) → BOOL: "{name} expects true/false";
/// ULONG: a bool → "{name} expects an integer", a non-int non-symbol → "{name} expects an
/// integer or CKO_/CKK_/CKC_/CKM_ constant", a negative int n ≥ −2^63 in a
/// NON_CREATION_ATTRS row → its 64-bit two's complement 2^64 + n (c2 dumped PyKCS11's signed
/// C long: `CKA_KEY_GEN_MECHANISM: -1` of an imported object loads as
/// 18446744073709551615 = CK_UNAVAILABLE_INFORMATION, what r2's own dump writes; the row
/// arrives disabled — §11 D18), any other negative int → "template attribute {name} must
/// not be negative" (c2 raised it later, at conversion — §11 D18); BYTES: "{name}
/// expects a 0x… hex string" | "{name} has invalid hex" (`text::py_fromhex`); STR: "{name}
/// expects a string". Values are typed by the §4.8.4 loader, so `CKA_TOKEN: yes` is a bool
/// and `CKA_LABEL: yes` fails "expects a string", exactly as in c2.
pub fn load_seed_file(
    path: &Path,
    custom_attributes: &IndexMap<String, CustomAttributeDef>,
) -> r2_core::Result<SeedTemplates> {
    let shown = path.display();
    let bytes = std::fs::read(path).map_err(|err| {
        ConsoleError::data_io(format!("cannot read {shown}: {}", os_error_text(&err)))
    })?;
    // c2 `path.read_text(encoding="utf-8")`: invalid UTF-8 raised UnicodeDecodeError past
    // c2's `except OSError` (a crash); r2 reports it as the unreadable file (§11 D12 (s)).
    let text = std::str::from_utf8(&bytes).map_err(|err| {
        ConsoleError::data_io(format!(
            "cannot read {shown}: {}",
            utf8_error_text(&bytes, &err)
        ))
    })?;
    // Python text mode: universal newlines.
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let raw = yaml::parse(&text).map_err(|err| {
        ConsoleError::param(
            format!("invalid YAML in template file {shown}: {}", err.message),
            "template",
        )
        .with_hint("template files are class-keyed YAML (spec §5.16)")
    })?;
    let section_hint = format!("valid sections: {}", TEMPLATE_CLASS_KEYS.join(", "));
    let map = match raw {
        Value::Mapping(map) if !map.is_empty() => map,
        _ => {
            return Err(ConsoleError::param(
                format!("template file {shown} has no sections"),
                "template",
            )
            .with_hint(section_hint));
        }
    };
    let mut sections = SeedTemplates::new();
    for (raw_key, section) in &map {
        let section_key = py_str(raw_key);
        if !matches!(raw_key, Value::String(_)) || !TEMPLATE_CLASS_KEYS.contains(&&*section_key) {
            return Err(ConsoleError::param(
                format!("unknown template section '{section_key}' in {shown}"),
                "template",
            )
            .with_hint(section_hint));
        }
        let Value::Mapping(entries) = section else {
            return Err(ConsoleError::param(
                format!("template section '{section_key}' in {shown} is not a mapping"),
                "template",
            )
            .with_hint("each section maps CKA_* names to values"));
        };
        let mut attrs = Vec::with_capacity(entries.len());
        for (raw_name, value) in entries {
            let name = py_str(raw_name);
            let kind = kind_of(&name, custom_attributes)?;
            let value = value_from_yaml(&name, kind, value)?;
            attrs.push(TemplateAttr::new(name, kind, value));
        }
        sections.insert(section_key, KeyTemplate::new(attrs));
    }
    Ok(sections)
}

/// ★ Editor seed for one (class, algorithm): the matching file section when present
/// (locked CKA_CLASS/CKA_KEY_TYPE rows from the FLOW via default_template, file entries for
/// them dropped; CKA_LABEL/CKA_ID and NON_CREATION_ATTRS rows disabled; everything else
/// enabled with its file value), else `templates.default_template(..)` unchanged.
pub fn build_seed(
    templates: &TemplatesSection,
    seeds: Option<&SeedTemplates>,
    key_class: KeyClass,
    algorithm: KeyAlgorithm,
) -> r2_core::Result<KeyTemplate> {
    let base = templates.default_template(key_class, algorithm)?;
    let Some(seeds) = seeds else {
        return Ok(base);
    };
    let Some(section) = seeds.get(template_class_key(key_class, algorithm)?) else {
        return Ok(base);
    };
    let mut attrs: Vec<TemplateAttr> = base.attrs.into_iter().filter(|a| a.locked).collect();
    for attr in &section.attrs {
        if attr.name == "CKA_CLASS" || attr.name == "CKA_KEY_TYPE" {
            continue;
        }
        let name = attr.name.as_str();
        let mut row = TemplateAttr::new(name, attr.kind, attr.value.clone());
        row.enabled = !IDENTITY_ATTRS.contains(&name) && !NON_CREATION_ATTRS.contains(&name);
        attrs.push(row);
    }
    Ok(KeyTemplate::new(attrs))
}

/// ★ The seeding context every create flow passes around (keyload, transfer, wrapload).
#[derive(Clone, Copy)]
pub struct EditorSeeding<'a> {
    pub editor: &'a dyn TemplateEditor,
    pub templates: &'a TemplatesSection,
    pub seeds: Option<&'a SeedTemplates>,
}
impl<'a> EditorSeeding<'a> {
    /// `build_seed(..)` then `editor.edit(seed, title)`.
    pub fn edit(
        &self,
        key_class: KeyClass,
        algorithm: KeyAlgorithm,
        title: &str,
    ) -> r2_core::Result<KeyTemplate> {
        let seed = build_seed(self.templates, self.seeds, key_class, algorithm)?;
        self.editor.edit(seed, title)
    }
}

// ---- codec helpers ------------------------------------------------------------------------

/// TemplateAttr value → YAML scalar per kind (c2 `_encode_value`, §5.16 encoding).
fn encode_value(attr: &TemplateAttr) -> r2_core::Result<Value> {
    Ok(match attr.kind {
        // c2 `bool(attr.value)` (Python truthiness for a value of another type)
        AttrKind::Bool => Value::Bool(truthy(&attr.value)),
        AttrKind::Bytes => match &attr.value {
            AttrValue::Bytes(bytes) => Value::String(format!("0x{}", hex_lower(bytes))),
            _ => Value::String("0x".to_owned()),
        },
        AttrKind::Ulong => match &attr.value {
            // symbolic CKO_/CKK_… constant (any c2 str), kept verbatim
            AttrValue::Symbol(text) | AttrValue::Str(text) => Value::String(text.clone()),
            AttrValue::Ulong(n) => Value::Number(Number::from(*n)),
            AttrValue::Bool(b) => Value::Number(Number::from(u64::from(*b))),
            AttrValue::Bytes(bytes) => {
                // c2 `int(bytes)`: Python parses ASCII digits, else ValueError
                let text = String::from_utf8_lossy(bytes);
                match py_int(&text, 10) {
                    Some(n) => int_value(n),
                    None => {
                        return Err(ConsoleError::generic(format!(
                            "invalid literal for int() with base 10: {}",
                            py_bytes_repr(bytes)
                        )));
                    }
                }
            }
        },
        // c2 `str(attr.value)`
        AttrKind::Str => Value::String(match &attr.value {
            AttrValue::Bytes(bytes) => py_bytes_repr(bytes),
            other => other.render_info(),
        }),
    })
}

fn int_value(n: i128) -> Value {
    if let Ok(v) = u64::try_from(n) {
        Value::Number(Number::from(v))
    } else if let Ok(v) = i64::try_from(n) {
        Value::Number(Number::from(v))
    } else {
        Value::String(n.to_string())
    }
}

/// Python truthiness of a c2 template value.
fn truthy(value: &AttrValue) -> bool {
    match value {
        AttrValue::Bool(b) => *b,
        AttrValue::Ulong(n) => *n != 0,
        AttrValue::Bytes(bytes) => !bytes.is_empty(),
        AttrValue::Str(text) | AttrValue::Symbol(text) => !text.is_empty(),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// c2 `_kind_of`: CKA_CATALOG first, then templates.custom_attributes.
fn kind_of(
    name: &str,
    custom_attributes: &IndexMap<String, CustomAttributeDef>,
) -> r2_core::Result<AttrKind> {
    if let Some(entry) = cka(name) {
        return Ok(entry.kind);
    }
    if let Some(custom) = custom_attributes.get(name) {
        return Ok(custom.kind);
    }
    Err(
        ConsoleError::param(format!("unknown PKCS#11 attribute '{name}'"), name)
            .with_hint("define it under templates.custom_attributes (code + kind)"),
    )
}

/// c2 `_value_from_yaml`: YAML scalar → template value; kind comes from the catalog, never
/// the value.
fn value_from_yaml(name: &str, kind: AttrKind, raw: &Value) -> r2_core::Result<AttrValue> {
    let mismatch = |text: String| ConsoleError::param(text, name);
    match kind {
        AttrKind::Bool => match raw {
            Value::Bool(b) => Ok(AttrValue::Bool(*b)),
            _ => Err(mismatch(format!("{name} expects true/false"))),
        },
        AttrKind::Ulong => {
            if matches!(raw, Value::Bool(_)) {
                return Err(mismatch(format!("{name} expects an integer")));
            }
            if let Some(n) = yaml::as_int(raw) {
                return ulong_from_int(name, n);
            }
            if let Value::String(text) = raw
                && SYMBOL_PREFIXES.iter().any(|p| text.starts_with(p))
            {
                // resolved by the provider at creation (§4.8)
                return Ok(AttrValue::Symbol(text.clone()));
            }
            Err(mismatch(format!(
                "{name} expects an integer or CKO_/CKK_/CKC_/CKM_ constant"
            )))
        }
        AttrKind::Bytes => match raw {
            Value::String(text) if text.starts_with("0x") => match py_fromhex(&text[2..]) {
                Some(bytes) => Ok(AttrValue::Bytes(bytes)),
                None => Err(mismatch(format!("{name} has invalid hex"))),
            },
            _ => Err(mismatch(format!("{name} expects a 0x… hex string"))),
        },
        AttrKind::Str => match raw {
            Value::String(text) => Ok(AttrValue::Str(text.clone())),
            _ => Err(mismatch(format!("{name} expects a string"))),
        },
    }
}

/// A YAML int for a ULONG row: non-negative as is; a negative value in a NON_CREATION_ATTRS
/// row (c2 dumped PyKCS11's signed C long, e.g. `CKA_KEY_GEN_MECHANISM: -1`) as its 64-bit
/// two's complement; any other negative refused at load (§11 D18).
fn ulong_from_int(name: &str, n: i128) -> r2_core::Result<AttrValue> {
    if let Ok(v) = u64::try_from(n) {
        return Ok(AttrValue::Ulong(v));
    }
    if NON_CREATION_ATTRS.contains(&name)
        && let Ok(signed) = i64::try_from(n)
    {
        return Ok(AttrValue::Ulong(signed.cast_unsigned()));
    }
    Err(ConsoleError::param(
        format!("template attribute {name} must not be negative"),
        name,
    ))
}

/// Python `str()` of a YAML mapping key as PyYAML constructed it (c2 f-strings / `str(..)`).
fn py_str(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::String(text) => text.clone(),
        Value::Number(number) => {
            if let Some(v) = number.as_i64() {
                v.to_string()
            } else if let Some(v) = number.as_u64() {
                v.to_string()
            } else {
                py_float_repr(number.as_f64().unwrap_or(f64::NAN))
            }
        }
        // `!!timestamp` / `!!binary` keys (and any other tagged scalar): the source text
        Value::Tagged(tagged) => py_str(&tagged.value),
        // unhashable keys never get here (the loader rejects them); a value is never a key
        Value::Sequence(_) | Value::Mapping(_) => String::new(),
    }
}

/// Python `repr(float)` (= `str(float)`): shortest round-trip digits, exponent form when
/// the decimal exponent is < -4 or >= 16, else fixed with at least one fractional digit.
fn py_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
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
        out.push_str(&format!("e{sign}{:02}", exponent.unsigned_abs()));
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

/// CPython's `UnicodeDecodeError` text for invalid UTF-8 (`Path.read_text`).
fn utf8_error_text(bytes: &[u8], error: &std::str::Utf8Error) -> String {
    let start = error.valid_up_to();
    let first = bytes.get(start).copied().unwrap_or(0);
    match error.error_len() {
        None => {
            let end = bytes.len().saturating_sub(1);
            if end == start {
                format!(
                    "'utf-8' codec can't decode byte 0x{first:02x} in position {start}: \
                     unexpected end of data"
                )
            } else {
                format!(
                    "'utf-8' codec can't decode bytes in position {start}-{end}: unexpected \
                     end of data"
                )
            }
        }
        // CPython reports a truncated multi-byte sequence (maximal subpart) as a byte range.
        Some(len) if len > 1 => format!(
            "'utf-8' codec can't decode bytes in position {start}-{}: invalid continuation byte",
            start + len - 1
        ),
        Some(_) => {
            let reason = if (0x80..=0xc1).contains(&first) || first >= 0xf5 {
                "invalid start byte"
            } else {
                "invalid continuation byte"
            };
            format!("'utf-8' codec can't decode byte 0x{first:02x} in position {start}: {reason}")
        }
    }
}
