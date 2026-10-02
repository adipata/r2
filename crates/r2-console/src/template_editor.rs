// Checklist template editor (spec §5.12) behind the frozen §4.9.3 factory — owner R10.
// Port of c2 console/template_editor.py.
//
// Line-based checklist — works in every terminal and is scriptable via ScriptedIo
// (deliberately not a full-screen dialog). Rendered as a table: index, state glyph
// (`[x]`/`[ ]` bool, `(-)` disabled, `(*)` locked), attribute, kind, value. Mini-REPL
// grammar (§5.12):
//
//     3             toggle boolean attr #3
//     5=0xAABBCC    set value of attr #5 (BYTES/STR/ULONG; bytes as 0x…)
//     -7  /  +7     disable / re-enable attr #7   (disabled = omitted from the call)
//     add CKA_X=v   add an attribute known to CKA_CATALOG or templates.custom_attributes
//     ok            accept      cancel      abort (UserAbort)
//
// The mini-REPL line is read through `ConsoleIo::prompt` with a synthetic STR ParamSpec
// (the §5.12 blessed pattern). Locked rows (CKA_CLASS/CKA_KEY_TYPE) cannot be toggled,
// edited or disabled. Editing happens on the template passed by value (the caller's copy
// is never touched); `ok` returns it, `cancel` returns UserAbort. Input errors are printed
// and re-prompted (the ParamResolver pattern); they never leave the editor.
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::{AppConfig, CustomAttributeDef};
use r2_core::catalog;
use r2_core::error::{ConsoleError, Result};
use r2_core::io::{self, ConsoleIo, TemplateEditor};
use r2_core::params::ParamSpec;
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_core::text::{py_fromhex, py_int, py_isdigit, py_repr, py_strip};

/// The editor help line (c2 `_HELP`).
pub(crate) const HELP: &str = "commands: <n> toggle | <n>=<value> set | -<n>/+<n> disable/enable | add CKA_X=<value> | ok | cancel";

/// §4.7 identity attributes are provider-injected; an added row is honored, but the
/// command flag is the normal channel — tell the operator what happens (c2 `_IDENTITY_NOTES`).
fn identity_note(name: &str) -> Option<&'static str> {
    match name {
        "CKA_ID" => Some(
            "note: CKA_ID is normally set with --id; this value will be used as the new object's id",
        ),
        "CKA_LABEL" => Some(
            "note: CKA_LABEL is normally set with --label; this value overrides the label given earlier",
        ),
        _ => None,
    }
}

/// §4.6 boolean tokens (same set as ParamResolver — one convention everywhere).
fn bool_word(token: &str) -> Option<bool> {
    match token.to_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

/// The §5.12 checklist editor over the loaded configuration (it reads
/// `config.templates.custom_attributes`). Its mini-REPL line is read with
/// `io.prompt(&ParamSpec::str("template", "template> "))`.
pub fn create_template_editor(io: Rc<dyn ConsoleIo>, config: &AppConfig) -> Rc<dyn TemplateEditor> {
    Rc::new(ChecklistTemplateEditor::new(
        io,
        config.templates.custom_attributes.clone(),
    ))
}

/// The §5.12 line-based checklist editor (c2 `ChecklistTemplateEditor`).
pub(crate) struct ChecklistTemplateEditor {
    io: Rc<dyn ConsoleIo>,
    custom: IndexMap<String, CustomAttributeDef>,
}

impl TemplateEditor for ChecklistTemplateEditor {
    fn edit(&self, template: KeyTemplate, title: &str) -> Result<KeyTemplate> {
        let mut working = template;
        let spec = ParamSpec::str("template", "template> ");
        self.render(&working, title);
        loop {
            let line = match self.io.prompt(&spec) {
                Ok(line) => line,
                // c2: KeyboardInterrupt / EOFError at the prompt → UserAbort.
                Err(err) if err.kind.is_user_abort() => {
                    return Err(ConsoleError::user_abort("template edit cancelled"));
                }
                Err(err) => return Err(err),
            };
            let line = py_strip(&line);
            if line.is_empty() {
                self.render(&working, title);
                continue;
            }
            if line == "ok" {
                return Ok(working);
            }
            if line == "cancel" || line == "abort" {
                return Err(ConsoleError::user_abort("template edit cancelled"));
            }
            match self.apply(&mut working, line) {
                Ok(()) => self.render(&working, title),
                // keep editing (ParamResolver pattern); anything else propagates
                Err(err) if err.param_name().is_some() => self.io.print_error(&err),
                Err(err) => return Err(err),
            }
        }
    }
}

impl ChecklistTemplateEditor {
    pub(crate) fn new(io: Rc<dyn ConsoleIo>, custom: IndexMap<String, CustomAttributeDef>) -> Self {
        Self { io, custom }
    }

    // -- rendering ------------------------------------------------------------------

    fn render(&self, template: &KeyTemplate, title: &str) {
        let rows = template
            .attrs
            .iter()
            .enumerate()
            .map(|(index, attr)| {
                vec![
                    (index + 1).to_string(),
                    glyph(attr).to_owned(),
                    attr.name.clone(),
                    attr.kind.as_str().to_owned(),
                    attr.value.render_value(),
                ]
            })
            .collect();
        self.io.print(io::table(
            Some(title),
            &["#", "state", "attribute", "kind", "value"],
            rows,
        ));
        self.io.print(HELP.into());
    }

    // -- mini-REPL commands -----------------------------------------------------------

    fn apply(&self, template: &mut KeyTemplate, line: &str) -> Result<()> {
        if line == "add" || line.starts_with("add ") {
            return self.add(template, py_strip(&line[3..]));
        }
        if let Some(rest) = line.strip_prefix(['+', '-']) {
            let (index, attr) = row(template, py_strip(rest))?;
            reject_locked(index, attr)?;
            attr.enabled = line.starts_with('+');
            return Ok(());
        }
        if let Some((index_text, value_text)) = line.split_once('=') {
            let (index, attr) = row(template, py_strip(index_text))?;
            reject_locked(index, attr)?;
            attr.value = parse_value(&attr.name, attr.kind, value_text)?;
            return Ok(());
        }
        let (index, attr) = row(template, line)?;
        reject_locked(index, attr)?;
        if attr.kind != AttrKind::Bool {
            return Err(ConsoleError::param(
                format!("row {index} ({}) is not boolean", attr.name),
                attr.name.clone(),
            )
            .with_hint(format!("set its value with {index}=<value>")));
        }
        if !attr.enabled {
            return Err(ConsoleError::param(
                format!("row {index} ({}) is disabled", attr.name),
                attr.name.clone(),
            )
            .with_hint(format!("re-enable it first with +{index}")));
        }
        attr.value = AttrValue::Bool(!truthy(&attr.value));
        Ok(())
    }

    fn add(&self, template: &mut KeyTemplate, spec_text: &str) -> Result<()> {
        let (name, value_text) = match spec_text.split_once('=') {
            Some((name, value)) if !py_strip(name).is_empty() => (py_strip(name), value),
            _ => {
                return Err(
                    ConsoleError::param("add expects: add CKA_NAME=<value>", "add").with_hint(HELP),
                );
            }
        };
        if let Some(position) = template.attrs.iter().position(|attr| attr.name == name) {
            let row = position + 1;
            return Err(
                ConsoleError::param(format!("{name} is already row {row}"), name)
                    .with_hint(format!("set it with {row}=<value>")),
            );
        }
        let kind = self.kind_of(name)?;
        let value = parse_value(name, kind, value_text)?;
        template.attrs.push(TemplateAttr::new(name, kind, value));
        if let Some(note) = identity_note(name) {
            self.io.print(note.into());
        }
        Ok(())
    }

    /// §5.12: names come from CKA_CATALOG or templates.custom_attributes, which also
    /// supply the AttrKind used to parse the value.
    fn kind_of(&self, name: &str) -> Result<AttrKind> {
        if let Some(entry) = catalog::cka(name) {
            return Ok(entry.kind);
        }
        if let Some(custom) = self.custom.get(name) {
            return Ok(custom.kind);
        }
        Err(
            ConsoleError::param(format!("unknown attribute {}", py_repr(name)), name)
                .with_hint("add accepts CKA catalog names or templates.custom_attributes entries"),
        )
    }
}

// ---------------------------------------------------------------------------------------
// helpers (no editor state involved)
// ---------------------------------------------------------------------------------------

/// Python truthiness of the c2 value (`bool(attr.value)`).
fn truthy(value: &AttrValue) -> bool {
    match value {
        AttrValue::Bool(value) => *value,
        AttrValue::Ulong(value) => *value != 0,
        AttrValue::Bytes(value) => !value.is_empty(),
        AttrValue::Str(value) | AttrValue::Symbol(value) => !value.is_empty(),
    }
}

/// The state cell (c2 `_glyph`).
pub(crate) fn glyph(attr: &TemplateAttr) -> &'static str {
    if attr.locked {
        "(*)"
    } else if !attr.enabled {
        "(-)"
    } else if attr.kind == AttrKind::Bool {
        if truthy(&attr.value) { "[x]" } else { "[ ]" }
    } else {
        ""
    }
}

/// c2 `_row`: the token must pass `str.isdigit()`, then lie in 1..=rows.
fn row<'a>(template: &'a mut KeyTemplate, token: &str) -> Result<(usize, &'a mut TemplateAttr)> {
    if !py_isdigit(token) {
        return Err(
            ConsoleError::param(format!("{} is not a row number", py_repr(token)), "row")
                .with_hint(HELP),
        );
    }
    let rows = template.attrs.len();
    let index = token.parse::<u64>().ok();
    match index.and_then(|i| usize::try_from(i).ok()) {
        Some(index) if (1..=rows).contains(&index) => Ok((index, &mut template.attrs[index - 1])),
        _ => {
            // Python int(): the decimal value — leading zeros dropped (u64 overflow: the
            // token with its leading zeros stripped).
            let shown = match index {
                Some(index) => index.to_string(),
                None => token.trim_start_matches('0').to_owned(),
            };
            Err(ConsoleError::param(
                format!("row {shown} is out of range (1..{rows})"),
                "row",
            ))
        }
    }
}

fn reject_locked(index: usize, attr: &TemplateAttr) -> Result<()> {
    if attr.locked {
        return Err(ConsoleError::param(
            format!(
                "row {index} ({}) is locked and cannot be changed",
                attr.name
            ),
            attr.name.clone(),
        )
        .with_hint("locked rows (CKA_CLASS/CKA_KEY_TYPE) are derived from the key (§5.12)"));
    }
    Ok(())
}

/// True when `text` starts with "0x" under Python `str.lower()` (only '0' + 'x'/'X').
fn has_hex_prefix(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next() == Some('0') && matches!(chars.next(), Some('x' | 'X'))
}

/// Python `int(token, radix)` syntax without a value bound (the token is already
/// stripped): Some(negative) when CPython would parse it. Used only after `py_int` failed,
/// to tell an out-of-range integer from malformed text.
fn int_syntax(token: &str, radix: u32) -> Option<bool> {
    let (negative, mut rest) = match token.as_bytes().first() {
        Some(b'-') => (true, &token[1..]),
        Some(b'+') => (false, &token[1..]),
        _ => (false, token),
    };
    if radix == 16 && has_hex_prefix(rest) {
        rest = &rest[2..];
        rest = rest.strip_prefix('_').unwrap_or(rest);
    }
    let valid_digit = |b: u8| {
        if radix == 16 {
            b.is_ascii_hexdigit()
        } else {
            b.is_ascii_digit()
        }
    };
    let groups: Vec<&str> = rest.split('_').collect();
    let ok = !rest.is_empty()
        && groups
            .iter()
            .all(|group| !group.is_empty() && group.bytes().all(valid_digit));
    ok.then_some(negative)
}

/// Parse one mini-REPL value per AttrKind (c2 `_parse_value`); Param on mismatch.
fn parse_value(name: &str, kind: AttrKind, text: &str) -> Result<AttrValue> {
    if kind == AttrKind::Str {
        return Ok(AttrValue::Str(text.to_owned()));
    }
    let token = py_strip(text);
    match kind {
        AttrKind::Bool => bool_word(token).map(AttrValue::Bool).ok_or_else(|| {
            ConsoleError::param(format!("{name}: invalid boolean {}", py_repr(text)), name)
                .with_hint("accepted: true/false, yes/no, on/off, 1/0")
        }),
        AttrKind::Bytes => {
            if !has_hex_prefix(token) {
                return Err(ConsoleError::param(
                    format!("{name}: byte values are written 0x…"),
                    name,
                )
                .with_hint("e.g. 0xaabbcc"));
            }
            py_fromhex(&token[2..])
                .map(AttrValue::Bytes)
                .ok_or_else(|| {
                    ConsoleError::param(
                        format!("{name}: invalid hex bytes {}", py_repr(text)),
                        name,
                    )
                    .with_hint("0x… holds whole bytes (2 hex digits each)")
                })
        }
        _ => {
            let radix = if has_hex_prefix(token) { 16 } else { 10 };
            let negative = match py_int(token, radix) {
                Some(value) => match u64::try_from(value) {
                    Ok(value) => return Ok(AttrValue::Ulong(value)),
                    Err(_) => value < 0,
                },
                None => match int_syntax(token, radix) {
                    Some(negative) => negative,
                    None => {
                        return Err(ConsoleError::param(
                            format!("{name}: invalid integer {}", py_repr(text)),
                            name,
                        )
                        .with_hint("decimal digits or 0x… hex"));
                    }
                },
            };
            if negative {
                return Err(ConsoleError::param(
                    format!("{name} must not be negative"),
                    name,
                ));
            }
            // §11 D18: AttrValue::Ulong is a 64-bit CK_ULONG (c2 kept any Python int).
            Err(ConsoleError::param(
                format!("{name}: {} does not fit a 64-bit CK_ULONG", py_repr(text)),
                name,
            )
            .with_hint("the largest value is 18446744073709551615"))
        }
    }
}
