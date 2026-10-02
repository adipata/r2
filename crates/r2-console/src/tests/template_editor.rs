// ChecklistTemplateEditor tests (R10, spec §5.12) — port of c2
// tests/unit/console/test_template_editor.py, ScriptedIo-driven: toggle, set, disable →
// attr omitted from `enabled_attrs()`, locked rows immutable, `add` via CKA_CATALOG and
// `templates.custom_attributes`, cancel → UserAbort — plus the §4.9.3 factory wiring and
// the r2 row-number / ULONG rules of §5.12 / §11 D18.
use std::rc::Rc;

use r2_core::error::{ErrorKind, Result};
use r2_core::io::{ConsoleIo, TemplateEditor};
use r2_core::keys::{KeyAlgorithm, KeyClass};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_testkit::ScriptedIo;

use crate::template_editor::{ChecklistTemplateEditor, HELP, create_template_editor, glyph};
use crate::testing::{CtxBuilder, make_config};

/// An editor seed shaped like TemplatesSection::default_template output.
fn make_template() -> KeyTemplate {
    KeyTemplate::new(vec![
        TemplateAttr::new(
            "CKA_CLASS",
            AttrKind::Ulong,
            AttrValue::Symbol("CKO_SECRET_KEY".into()),
        )
        .locked(),
        TemplateAttr::new(
            "CKA_KEY_TYPE",
            AttrKind::Ulong,
            AttrValue::Symbol("CKK_AES".into()),
        )
        .locked(),
        TemplateAttr::new("CKA_TOKEN", AttrKind::Bool, AttrValue::Bool(true)),
        TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(true)),
        TemplateAttr::new("CKA_VALUE_LEN", AttrKind::Ulong, AttrValue::Ulong(32)),
        TemplateAttr::new("CKA_ID", AttrKind::Bytes, AttrValue::Bytes(vec![1, 2])),
        TemplateAttr::new("CKA_LABEL", AttrKind::Str, AttrValue::Str("seed".into())),
    ])
}

fn make_editor(answers: &[&str]) -> (ChecklistTemplateEditor, Rc<ScriptedIo>) {
    let io = Rc::new(ScriptedIo::new(answers.iter().copied()));
    let editor = ChecklistTemplateEditor::new(
        Rc::clone(&io) as Rc<dyn ConsoleIo>,
        make_config(None).templates.custom_attributes,
    );
    (editor, io)
}

fn edit(answers: &[&str]) -> Result<KeyTemplate> {
    let (editor, _io) = make_editor(answers);
    editor.edit(make_template(), "t")
}

fn value(template: &KeyTemplate, name: &str) -> AttrValue {
    template.get(name).unwrap().value.clone()
}

fn errors(io: &ScriptedIo) -> Vec<String> {
    io.output()
        .into_iter()
        .filter(|line| line.starts_with("error:"))
        .collect()
}

// ---------------------------------------------------------------------------------------
// accept / cancel
// ---------------------------------------------------------------------------------------

#[test]
fn test_ok_returns_copy_and_leaves_input_untouched() {
    let original = make_template();
    let (editor, _io) = make_editor(&["3", "ok"]);
    let result = editor.edit(original.clone(), "t").unwrap();
    assert_eq!(value(&original, "CKA_TOKEN"), AttrValue::Bool(true));
    assert_eq!(value(&result, "CKA_TOKEN"), AttrValue::Bool(false));
    assert_eq!(original, make_template());
}

#[test]
fn test_cancel_raises_user_abort() {
    let err = edit(&["cancel"]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert_eq!(err.message, "template edit cancelled");
}

#[test]
fn test_abort_synonym_raises_user_abort_after_edits() {
    let err = edit(&["3", "abort"]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
}

#[test]
fn ctrl_c_and_ctrl_d_at_the_editor_prompt_propagate_the_io_abort() {
    // c2's ConsoleIO.prompt raises its own UserAbort for Ctrl-C/Ctrl-D, which the editor
    // passes through unchanged ("template edit cancelled" is only for typed cancel/abort)
    for sentinel in [ScriptedIo::CTRL_C, ScriptedIo::CTRL_D] {
        let err = edit(&["3", sentinel]).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UserAbort);
        assert_eq!(err.message, "aborted while entering 'template'");
    }
}

// ---------------------------------------------------------------------------------------
// toggle
// ---------------------------------------------------------------------------------------

#[test]
fn test_toggle_flips_boolean_rows() {
    let result = edit(&["3", "4", "4", "ok"]).unwrap();
    assert_eq!(value(&result, "CKA_TOKEN"), AttrValue::Bool(false));
    assert_eq!(value(&result, "CKA_SENSITIVE"), AttrValue::Bool(true));
}

#[test]
fn test_toggle_rejects_non_boolean_row() {
    let (editor, io) = make_editor(&["5", "ok"]);
    let result = editor.edit(make_template(), "t").unwrap();
    assert_eq!(value(&result, "CKA_VALUE_LEN"), AttrValue::Ulong(32));
    assert!(io.output().iter().any(|line| line.contains("not boolean")));
    assert!(io.text().contains(
        "error: row 5 (CKA_VALUE_LEN) is not boolean (hint: set its value with 5=<value>)"
    ));
}

#[test]
fn test_toggle_rejects_disabled_row() {
    let (editor, io) = make_editor(&["-3", "3", "ok"]);
    let result = editor.edit(make_template(), "t").unwrap();
    assert_eq!(value(&result, "CKA_TOKEN"), AttrValue::Bool(true));
    assert!(!result.get("CKA_TOKEN").unwrap().enabled);
    assert!(io.output().iter().any(|line| line.contains("disabled")));
    assert!(
        io.text()
            .contains("error: row 3 (CKA_TOKEN) is disabled (hint: re-enable it first with +3)")
    );
}

// ---------------------------------------------------------------------------------------
// set
// ---------------------------------------------------------------------------------------

#[test]
fn test_set_ulong_bytes_str_and_bool_values() {
    let result = edit(&["5=16", "6=0xAABBCC", "7=renamed", "4=off", "ok"]).unwrap();
    assert_eq!(value(&result, "CKA_VALUE_LEN"), AttrValue::Ulong(16));
    assert_eq!(
        value(&result, "CKA_ID"),
        AttrValue::Bytes(vec![0xaa, 0xbb, 0xcc])
    );
    assert_eq!(
        value(&result, "CKA_LABEL"),
        AttrValue::Str("renamed".into())
    );
    assert_eq!(value(&result, "CKA_SENSITIVE"), AttrValue::Bool(false));
}

#[test]
fn test_set_bad_values_are_reported_and_editing_continues() {
    let (editor, io) = make_editor(&["5=abc", "6=AABB", "6=0xZZ", "4=maybe", "9=1", "x=1", "ok"]);
    let result = editor.edit(make_template(), "t").unwrap();
    // every bad line was rejected: nothing changed
    assert_eq!(value(&result, "CKA_VALUE_LEN"), AttrValue::Ulong(32));
    assert_eq!(value(&result, "CKA_ID"), AttrValue::Bytes(vec![1, 2]));
    assert_eq!(value(&result, "CKA_SENSITIVE"), AttrValue::Bool(true));
    let errors = errors(&io);
    assert_eq!(errors.len(), 6);
    assert!(errors.iter().any(|line| line.contains("0x"))); // bytes want the 0x… form
    assert!(errors.iter().any(|line| line.contains("out of range")));
    assert!(errors.iter().any(|line| line.contains("not a row number")));
    // c2 texts verbatim
    assert_eq!(
        errors,
        [
            "error: CKA_VALUE_LEN: invalid integer 'abc' (hint: decimal digits or 0x… hex)",
            "error: CKA_ID: byte values are written 0x… (hint: e.g. 0xaabbcc)",
            "error: CKA_ID: invalid hex bytes '0xZZ' (hint: 0x… holds whole bytes (2 hex digits each))",
            "error: CKA_SENSITIVE: invalid boolean 'maybe' (hint: accepted: true/false, yes/no, on/off, 1/0)",
            "error: row 9 is out of range (1..7)",
            &format!("error: 'x' is not a row number (hint: {HELP})"),
        ]
    );
}

#[test]
fn ulong_values_follow_python_int_and_the_ck_ulong_range() {
    // c2 `int(token, 16 if 0x… else 10)`: whitespace, sign, `_` separators, 0X prefix
    let result = edit(&["5= 0X1_0 ", "ok"]).unwrap();
    assert_eq!(value(&result, "CKA_VALUE_LEN"), AttrValue::Ulong(16));
    let result = edit(&["5=+1_000", "ok"]).unwrap();
    assert_eq!(value(&result, "CKA_VALUE_LEN"), AttrValue::Ulong(1000));
    let result = edit(&["5=18446744073709551615", "ok"]).unwrap();
    assert_eq!(value(&result, "CKA_VALUE_LEN"), AttrValue::Ulong(u64::MAX));
    let (editor, io) = make_editor(&[
        "5=-1",
        "5=-0x5",
        "5=18446744073709551616",
        "5=-99999999999999999999999999999999999999999",
        "5=1__0",
        "5=",
        "ok",
    ]);
    let result = editor.edit(make_template(), "t").unwrap();
    assert_eq!(value(&result, "CKA_VALUE_LEN"), AttrValue::Ulong(32));
    assert_eq!(
        errors(&io),
        [
            "error: CKA_VALUE_LEN must not be negative",
            "error: CKA_VALUE_LEN: invalid integer '-0x5' (hint: decimal digits or 0x… hex)",
            "error: CKA_VALUE_LEN: '18446744073709551616' does not fit a 64-bit CK_ULONG (hint: the largest value is 18446744073709551615)",
            "error: CKA_VALUE_LEN must not be negative",
            "error: CKA_VALUE_LEN: invalid integer '1__0' (hint: decimal digits or 0x… hex)",
            "error: CKA_VALUE_LEN: invalid integer '' (hint: decimal digits or 0x… hex)",
        ]
    );
}

#[test]
fn ulong_over_4300_decimal_digits_is_invalid_integer() {
    // CPython 3.12 `int(str, 10)` refuses more than 4300 digits (ValueError → c2's
    // "invalid integer"); leading zeros and `_`-separated digits count; hex is unlimited
    let nines = "9".repeat(4301);
    let zeros = format!("{}1", "0".repeat(4300));
    let grouped = format!("{}1", "1_".repeat(4300));
    let at_limit = "9".repeat(4300);
    let hex = format!("0x{}", "f".repeat(5000));
    let lines = [
        format!("5={nines}"),
        format!("5=-{nines}"),
        format!("5={zeros}"),
        format!("5={grouped}"),
        format!("5={at_limit}"),
        format!("5=-{at_limit}"),
        format!("5={hex}"),
        "ok".to_owned(),
    ];
    let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
    let (editor, io) = make_editor(&lines);
    let result = editor.edit(make_template(), "t").unwrap();
    assert_eq!(value(&result, "CKA_VALUE_LEN"), AttrValue::Ulong(32));
    let invalid = |text: &str| {
        format!("error: CKA_VALUE_LEN: invalid integer '{text}' (hint: decimal digits or 0x… hex)")
    };
    assert_eq!(
        errors(&io),
        [
            invalid(&nines),
            invalid(&format!("-{nines}")),
            invalid(&zeros),
            invalid(&grouped),
            format!(
                "error: CKA_VALUE_LEN: '{at_limit}' does not fit a 64-bit CK_ULONG (hint: the largest value is 18446744073709551615)"
            ),
            "error: CKA_VALUE_LEN must not be negative".to_owned(),
            format!(
                "error: CKA_VALUE_LEN: '{hex}' does not fit a 64-bit CK_ULONG (hint: the largest value is 18446744073709551615)"
            ),
        ]
    );
}

#[test]
fn row_token_over_4300_digits_is_out_of_range() {
    // §11 D18: c2's `int()` raised ValueError here (unexpected-error path)
    let ones = "1".repeat(4301);
    let (editor, io) = make_editor(&[&ones, "ok"]);
    editor.edit(make_template(), "t").unwrap();
    assert_eq!(
        errors(&io),
        [format!("error: row {ones} is out of range (1..7)")]
    );
}

#[test]
fn row_token_over_4300_digits_is_out_of_range_even_with_a_small_value() {
    // §11 D18: leading zeros keep the value small, but c2's `int()` still hit the digit
    // limit (unexpected-error path) and changed nothing — neither the toggle (row 3,
    // CKA_TOKEN) nor the `=value` form (row 5, CKA_VALUE_LEN) may edit the row
    let toggle = format!("{}3", "0".repeat(4300));
    let set = format!("{}5=5", "0".repeat(4300));
    let zeros = "0".repeat(4301);
    let (editor, io) = make_editor(&[&toggle, &set, &zeros, "ok"]);
    let result = editor.edit(make_template(), "t").unwrap();
    assert_eq!(
        errors(&io),
        [
            "error: row 3 is out of range (1..7)",
            "error: row 5 is out of range (1..7)",
            "error: row 0 is out of range (1..7)",
        ]
    );
    assert_eq!(result, make_template());
}

#[test]
fn str_values_keep_the_raw_text_after_the_equals_sign() {
    let result = edit(&["7=  two words = x ", "ok"]).unwrap();
    // the line is stripped first; the value text after the first '=' is kept verbatim
    assert_eq!(
        value(&result, "CKA_LABEL"),
        AttrValue::Str("  two words = x".into())
    );
}

#[test]
fn row_tokens_are_gated_by_isdigit() {
    // §5.12: "1_0", "--3", "+-3" would pass py_int but are not row numbers; leading zeros
    // are dropped; an overflowing token shows its digits without leading zeros
    let (editor, io) = make_editor(&[
        "1_0",
        "--3",
        "+-3",
        "003",
        "0",
        "000184467440737095516160",
        "-",
        "=1",
        "ok",
    ]);
    let result = editor.edit(make_template(), "t").unwrap();
    assert_eq!(value(&result, "CKA_TOKEN"), AttrValue::Bool(false)); // "003" toggled row 3
    assert_eq!(
        errors(&io),
        [
            format!("error: '1_0' is not a row number (hint: {HELP})"),
            format!("error: '-3' is not a row number (hint: {HELP})"),
            format!("error: '-3' is not a row number (hint: {HELP})"),
            "error: row 0 is out of range (1..7)".to_owned(),
            "error: row 184467440737095516160 is out of range (1..7)".to_owned(),
            format!("error: '' is not a row number (hint: {HELP})"),
            format!("error: '' is not a row number (hint: {HELP})"),
        ]
    );
}

#[test]
fn empty_line_rerenders_and_the_prompt_is_the_synthetic_template_spec() {
    let (editor, io) = make_editor(&["", "ok"]);
    editor.edit(make_template(), "my title").unwrap();
    assert_eq!(io.prompts(), ["template> ", "template> "]);
    let output = io.output();
    // table + help, twice (initial render and the empty-line re-render)
    assert_eq!(output.len(), 4);
    assert_eq!(output[1], HELP);
    assert_eq!(output[0], output[2]);
    assert!(output[0].lines().next().unwrap().trim() == "my title");
}

// ---------------------------------------------------------------------------------------
// disable / re-enable
// ---------------------------------------------------------------------------------------

#[test]
fn test_disable_omits_attr_from_enabled_attrs() {
    let result = edit(&["-4", "ok"]).unwrap();
    let attr = result.get("CKA_SENSITIVE").unwrap();
    assert!(!attr.enabled);
    assert!(
        !result
            .enabled_attrs()
            .iter()
            .any(|a| a.name == "CKA_SENSITIVE")
    );
    // the row is still present (disabled ≠ removed)
    let names: Vec<&str> = result.attrs.iter().map(|a| a.name.as_str()).collect();
    let seed = make_template();
    let seed_names: Vec<&str> = seed.attrs.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, seed_names);
}

#[test]
fn test_reenable_restores_attr() {
    let result = edit(&["-4", "+4", "ok"]).unwrap();
    assert!(
        result
            .enabled_attrs()
            .iter()
            .any(|a| a.name == "CKA_SENSITIVE")
    );
}

// ---------------------------------------------------------------------------------------
// locked rows
// ---------------------------------------------------------------------------------------

#[test]
fn test_locked_rows_are_immutable() {
    for line in ["1", "1=42", "-1", "+2", "2=CKK_RSA"] {
        let (editor, io) = make_editor(&[line, "ok"]);
        let result = editor.edit(make_template(), "t").unwrap();
        assert_eq!(
            value(&result, "CKA_CLASS"),
            AttrValue::Symbol("CKO_SECRET_KEY".into())
        );
        assert_eq!(
            value(&result, "CKA_KEY_TYPE"),
            AttrValue::Symbol("CKK_AES".into())
        );
        assert!(result.get("CKA_CLASS").unwrap().enabled);
        assert!(result.get("CKA_KEY_TYPE").unwrap().enabled);
        assert!(io.output().iter().any(|l| l.contains("locked")), "{line}");
    }
    let (editor, io) = make_editor(&["1", "ok"]);
    editor.edit(make_template(), "t").unwrap();
    assert_eq!(
        errors(&io),
        [
            "error: row 1 (CKA_CLASS) is locked and cannot be changed (hint: locked rows (CKA_CLASS/CKA_KEY_TYPE) are derived from the key (§5.12))"
        ]
    );
}

// ---------------------------------------------------------------------------------------
// add
// ---------------------------------------------------------------------------------------

#[test]
fn test_add_via_cka_catalog() {
    let result = edit(&[
        "add CKA_EXTRACTABLE=true",
        "add CKA_CHECK_VALUE=0x010203",
        "ok",
    ])
    .unwrap();
    let added = result.get("CKA_EXTRACTABLE").unwrap();
    assert_eq!(
        (added.kind, &added.value, added.enabled, added.locked),
        (AttrKind::Bool, &AttrValue::Bool(true), true, false)
    );
    let check = result.get("CKA_CHECK_VALUE").unwrap();
    assert_eq!(
        (check.kind, &check.value),
        (AttrKind::Bytes, &AttrValue::Bytes(vec![1, 2, 3]))
    );
}

#[test]
fn test_add_via_custom_attributes() {
    let config = make_config(Some(
        "templates:\n  custom_attributes:\n    CKA_ACME_USAGE: {code: 0x80000101, kind: bytes}\n    CKA_ACME_ROUNDS: {code: 0x80000102, kind: ulong}\n",
    ));
    let io = Rc::new(ScriptedIo::new([
        "add CKA_ACME_USAGE=0x0a0b",
        "add CKA_ACME_ROUNDS=7",
        "ok",
    ]));
    let editor = ChecklistTemplateEditor::new(
        Rc::clone(&io) as Rc<dyn ConsoleIo>,
        config.templates.custom_attributes,
    );
    let result = editor.edit(make_template(), "t").unwrap();
    let usage = result.get("CKA_ACME_USAGE").unwrap();
    let rounds = result.get("CKA_ACME_ROUNDS").unwrap();
    assert_eq!(
        (usage.kind, &usage.value),
        (AttrKind::Bytes, &AttrValue::Bytes(vec![0x0a, 0x0b]))
    );
    assert_eq!(
        (rounds.kind, &rounds.value),
        (AttrKind::Ulong, &AttrValue::Ulong(7))
    );
}

#[test]
fn test_add_identity_attrs_kept_and_noted() {
    // §5.12: identity rows are honored (§4.7), but the editor points at the flags
    let seed = KeyTemplate::new(vec![
        TemplateAttr::new(
            "CKA_CLASS",
            AttrKind::Ulong,
            AttrValue::Symbol("CKO_SECRET_KEY".into()),
        )
        .locked(),
    ]);
    let (editor, io) = make_editor(&["add CKA_ID=0xc0fe", "add CKA_LABEL=renamed", "ok"]);
    let result = editor.edit(seed, "t").unwrap();
    let added_id = result.get("CKA_ID").unwrap();
    assert_eq!(
        (added_id.kind, &added_id.value, added_id.enabled),
        (AttrKind::Bytes, &AttrValue::Bytes(vec![0xc0, 0xfe]), true)
    );
    let added_label = result.get("CKA_LABEL").unwrap();
    assert_eq!(
        (added_label.kind, &added_label.value),
        (AttrKind::Str, &AttrValue::Str("renamed".into()))
    );
    let notes: Vec<String> = io
        .output()
        .into_iter()
        .filter(|line| line.starts_with("note:"))
        .collect();
    assert!(notes.iter().any(|line| line.contains("--id")));
    assert!(notes.iter().any(|line| line.contains("--label")));
    assert_eq!(
        notes,
        [
            "note: CKA_ID is normally set with --id; this value will be used as the new object's id",
            "note: CKA_LABEL is normally set with --label; this value overrides the label given earlier",
        ]
    );
}

#[test]
fn test_add_unknown_name_and_duplicates_are_rejected() {
    let (editor, io) = make_editor(&[
        "add CKA_NOT_A_THING=1",
        "add CKA_TOKEN=false",
        "add CKA_WRAP",
        "ok",
    ]);
    let result = editor.edit(make_template(), "t").unwrap();
    assert_eq!(result.attrs.len(), make_template().attrs.len()); // nothing appended
    assert_eq!(value(&result, "CKA_TOKEN"), AttrValue::Bool(true));
    let errors = errors(&io);
    assert!(errors.iter().any(|line| line.contains("unknown attribute")));
    assert!(errors.iter().any(|line| line.contains("already row")));
    assert!(errors.iter().any(|line| line.contains("add expects")));
    assert_eq!(
        errors,
        [
            "error: unknown attribute 'CKA_NOT_A_THING' (hint: add accepts CKA catalog names or templates.custom_attributes entries)".to_owned(),
            "error: CKA_TOKEN is already row 3 (hint: set it with 3=<value>)".to_owned(),
            format!("error: add expects: add CKA_NAME=<value> (hint: {HELP})"),
        ]
    );
}

#[test]
fn add_with_an_empty_name_and_a_bad_value_is_rejected() {
    let (editor, io) = make_editor(&["add =1", "add", "add CKA_WRAP=perhaps", "ok"]);
    let result = editor.edit(make_template(), "t").unwrap();
    assert!(result.get("CKA_WRAP").is_none());
    assert_eq!(
        errors(&io),
        [
            format!("error: add expects: add CKA_NAME=<value> (hint: {HELP})"),
            format!("error: add expects: add CKA_NAME=<value> (hint: {HELP})"),
            "error: CKA_WRAP: invalid boolean 'perhaps' (hint: accepted: true/false, yes/no, on/off, 1/0)".to_owned(),
        ]
    );
}

// ---------------------------------------------------------------------------------------
// rendering & factory wiring
// ---------------------------------------------------------------------------------------

#[test]
fn test_render_reflects_state_glyphs() {
    let (editor, io) = make_editor(&["-4", "ok"]);
    editor.edit(make_template(), "aes template").unwrap();
    let b = |value: bool| TemplateAttr::new("a", AttrKind::Bool, AttrValue::Bool(value));
    assert_eq!(glyph(&b(true)), "[x]");
    assert_eq!(glyph(&b(false)), "[ ]");
    assert_eq!(glyph(&b(true).locked()), "(*)");
    assert_eq!(
        glyph(&TemplateAttr::new("a", AttrKind::Str, AttrValue::Str("x".into())).disabled()),
        "(-)"
    );
    assert_eq!(
        glyph(&TemplateAttr::new(
            "a",
            AttrKind::Ulong,
            AttrValue::Ulong(1)
        )),
        ""
    );
    // the glyphs reach the rendered table verbatim (cells are never markup, §5.12)
    let rendered = io.output()[2].clone();
    let row = |name: &str| {
        rendered
            .lines()
            .find(|line| line.contains(name))
            .unwrap()
            .to_owned()
    };
    assert!(row("CKA_CLASS").contains("(*)") && row("CKA_CLASS").contains("CKO_SECRET_KEY"));
    assert!(row("CKA_TOKEN").contains("[x]") && row("CKA_TOKEN").contains("true"));
    assert!(row("CKA_SENSITIVE").contains("(-)"));
    assert!(row("CKA_ID").contains("bytes") && row("CKA_ID").contains("0x0102"));
    assert!(row("CKA_VALUE_LEN").contains("ulong") && row("CKA_VALUE_LEN").contains("32"));
    let header = rendered.lines().nth(1).unwrap();
    for column in ["#", "state", "attribute", "kind", "value"] {
        assert!(header.contains(column), "{header}");
    }
}

#[test]
fn test_create_template_editor_factory() {
    let io = Rc::new(ScriptedIo::new(["ok"]));
    let editor = create_template_editor(Rc::clone(&io) as Rc<dyn ConsoleIo>, &make_config(None));
    let template = make_template();
    assert_eq!(editor.edit(template.clone(), "t").unwrap(), template);
    // the real checklist editor ran: it consumed the answer at its own prompt
    assert_eq!(io.remaining(), 0);
    assert_eq!(io.prompts(), ["template> "]);
}

#[test]
fn test_bootstrap_picks_up_the_real_editor() {
    // §4.9.3/§5.12: the AppContext's editor is the checklist editor (r2-cli and
    // testing::CtxBuilder both call create_template_editor; no identity fallback exists)
    let io = Rc::new(ScriptedIo::new(["cancel"]));
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>).build();
    let err = ctx.template_editor.edit(make_template(), "t").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert_eq!(io.prompts(), ["template> "]);
}

#[test]
fn test_editor_seeded_from_default_template_flow() {
    // end-to-end §5.12 seeding: default_template → editor → enabled_attrs
    let config = make_config(None);
    let seed = config
        .templates
        .default_template(KeyClass::Secret, KeyAlgorithm::Aes)
        .unwrap();
    let io = Rc::new(ScriptedIo::new(["add CKA_VALUE_LEN=32", "-5", "ok"]));
    let editor = ChecklistTemplateEditor::new(
        Rc::clone(&io) as Rc<dyn ConsoleIo>,
        config.templates.custom_attributes.clone(),
    );
    let result = editor.edit(seed, "generate aes").unwrap();
    let names: Vec<&str> = result
        .enabled_attrs()
        .iter()
        .map(|a| a.name.as_str())
        .collect();
    assert!(names.contains(&"CKA_VALUE_LEN"));
    assert!(!names.contains(&result.attrs[4].name.as_str())); // row 5 disabled
    assert!(result.attrs[0].locked && result.attrs[1].locked);
}
