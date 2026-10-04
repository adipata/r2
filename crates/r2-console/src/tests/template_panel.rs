// Interactive template panel tests (spec §5.12, §11 D34; owner R10): the panel state
// machine key by key (navigation, toggles, kind-aware value inputs, the add list, the `:`
// grammar line, accept/cancel/abort), its frames at several terminal sizes, and the
// editor's choice between the panel and the line checklist through a scripted interactive
// ConsoleIo — including the fall-back with the edits kept when the terminal fails.
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::CustomAttributeDef;
use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::io::{ConsoleIo, Frame, Key, KeySession, Line, Renderable, TemplateEditor};
use r2_core::params::ParamSpec;
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_testkit::ScriptedIo;
use secrecy::SecretString;

use crate::io::session::text_cells;
use crate::template_editor::panel::{Candidate, End, MIN_COLUMNS, MIN_ROWS, Message, Panel};
use crate::template_editor::{ChecklistTemplateEditor, HELP};
use crate::testing::make_config;

/// The template_editor tests' seed: rows 1-2 locked, 3 TOKEN, 4 SENSITIVE, 5 VALUE_LEN,
/// 6 ID, 7 LABEL.
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

/// The seed without its CKA_ID row (for adding one).
fn without_id() -> KeyTemplate {
    let mut template = make_template();
    template.attrs.retain(|attr| attr.name != "CKA_ID");
    template
}

fn no_custom() -> IndexMap<String, CustomAttributeDef> {
    make_config(None).templates.custom_attributes
}

fn acme_custom() -> IndexMap<String, CustomAttributeDef> {
    make_config(Some(
        "templates:\n  custom_attributes:\n    CKA_ACME_USAGE: {code: 0x80000101, kind: bytes}\n",
    ))
    .templates
    .custom_attributes
}

/// Feed `keys`; the first End stops the feed.
fn press(panel: &mut Panel<'_>, keys: impl IntoIterator<Item = Key>) -> Option<End> {
    for key in keys {
        if let Some(end) = panel.handle(key) {
            return Some(end);
        }
    }
    None
}

fn chars(text: &str) -> Vec<Key> {
    text.chars().map(Key::Char).collect()
}

fn value(template: &KeyTemplate, name: &str) -> AttrValue {
    template.get(name).unwrap().value.clone()
}

fn line_text(line: &Line) -> String {
    line.iter().map(|span| span.text.as_str()).collect()
}

fn frame_text(frame: &Frame) -> Vec<String> {
    frame.lines.iter().map(line_text).collect()
}

fn error(text: &str, hint: Option<&str>) -> Message {
    Message::Error(text.to_owned(), hint.map(str::to_owned))
}

// ---------------------------------------------------------------------------------------
// navigation, toggles, accept / cancel / abort
// ---------------------------------------------------------------------------------------

#[test]
fn cursor_starts_on_the_first_unlocked_row_and_never_lands_on_locked_rows() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    assert_eq!(panel.cursor(), 2);
    press(&mut panel, [Key::Up, Key::Up]);
    assert_eq!(panel.cursor(), 2, "rows 1-2 are locked");
    press(&mut panel, [Key::End]);
    assert_eq!(panel.cursor(), 7, "the OK row follows the 7 attribute rows");
    press(&mut panel, [Key::Down]);
    assert_eq!(panel.cursor(), 7);
    press(&mut panel, [Key::Home, Key::Down, Key::Down]);
    assert_eq!(panel.cursor(), 4);
    press(&mut panel, [Key::PageDown]);
    assert_eq!(
        panel.cursor(),
        5,
        "the page step is 1 before any frame was laid out"
    );
}

#[test]
fn space_and_enter_flip_boolean_rows() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(&mut panel, [Key::Char(' ')]);
    assert_eq!(value(&panel.template, "CKA_TOKEN"), AttrValue::Bool(false));
    press(&mut panel, [Key::Enter]);
    assert_eq!(value(&panel.template, "CKA_TOKEN"), AttrValue::Bool(true));
    press(&mut panel, [Key::Down, Key::Char(' ')]);
    assert_eq!(
        value(&panel.template, "CKA_SENSITIVE"),
        AttrValue::Bool(false)
    );
}

#[test]
fn enter_on_the_ok_row_accepts_esc_cancels_and_ctrl_c_aborts() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    assert!(matches!(
        press(&mut panel, [Key::End, Key::Enter]),
        Some(End::Accept)
    ));
    let mut panel = Panel::new(make_template(), "t", &custom);
    assert!(
        press(&mut panel, [Key::End, Key::Char(' ')]).is_none(),
        "only Enter accepts on the OK row"
    );
    assert!(matches!(press(&mut panel, [Key::Esc]), Some(End::Cancel)));
    let mut panel = Panel::new(make_template(), "t", &custom);
    assert!(matches!(
        press(&mut panel, [Key::Ctrl('c')]),
        Some(End::Abort)
    ));
    let mut panel = Panel::new(make_template(), "t", &custom);
    assert!(matches!(
        press(&mut panel, [Key::Ctrl('d')]),
        Some(End::Abort)
    ));
    let mut panel = Panel::new(make_template(), "t", &custom);
    // Ctrl-C aborts from inside an input too
    assert!(matches!(
        press(&mut panel, [Key::Char(':'), Key::Char('3'), Key::Ctrl('c')]),
        Some(End::Abort)
    ));
}

#[test]
fn minus_and_delete_disable_plus_and_space_enable() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(&mut panel, [Key::Char('-')]);
    assert!(!panel.template.get("CKA_TOKEN").unwrap().enabled);
    press(&mut panel, [Key::Char(' ')]);
    let token = panel.template.get("CKA_TOKEN").unwrap();
    assert!(token.enabled, "space re-enables a disabled row");
    assert_eq!(token.value, AttrValue::Bool(true), "without flipping it");
    press(&mut panel, [Key::Delete]);
    assert!(!panel.template.get("CKA_TOKEN").unwrap().enabled);
    press(&mut panel, [Key::Char('+')]);
    assert!(panel.template.get("CKA_TOKEN").unwrap().enabled);
    // the OK row has nothing to disable
    press(&mut panel, [Key::End, Key::Char('-')]);
    assert!(panel.template.attrs.iter().all(|attr| attr.enabled));
}

#[test]
fn resize_and_unbound_keys_change_nothing() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    assert!(
        press(
            &mut panel,
            [Key::Resize, Key::Char('z'), Key::Tab, Key::Left]
        )
        .is_none()
    );
    assert_eq!(panel.template, make_template());
    assert_eq!(panel.cursor(), 2);
}

// ---------------------------------------------------------------------------------------
// value inputs
// ---------------------------------------------------------------------------------------

#[test]
fn bytes_input_starts_from_the_value_and_takes_hex_digits_only() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(&mut panel, [Key::Down, Key::Down, Key::Down, Key::Enter]);
    assert_eq!(panel.input(), Some("0102"), "CKA_ID opens without its 0x");
    press(&mut panel, [Key::Char('g')]);
    assert_eq!(
        panel.message(),
        Some(&error("CKA_ID takes hex digits (0-9, a-f)", None))
    );
    assert_eq!(panel.input(), Some("0102"));
    press(&mut panel, [Key::Ctrl('u')]);
    press(&mut panel, chars("c0fe"));
    assert_eq!(panel.message(), None, "typing clears the message");
    press(&mut panel, [Key::Enter]);
    assert_eq!(panel.input(), None);
    assert_eq!(
        value(&panel.template, "CKA_ID"),
        AttrValue::Bytes(vec![0xc0, 0xfe])
    );
}

#[test]
fn odd_hex_digits_keep_the_input_open_with_the_line_editors_error() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(
        &mut panel,
        [Key::Down, Key::Down, Key::Down, Key::Enter, Key::Ctrl('u')],
    );
    press(&mut panel, chars("c0f"));
    press(&mut panel, [Key::Enter]);
    assert_eq!(
        panel.message(),
        Some(&error(
            "CKA_ID: invalid hex bytes '0xc0f'",
            Some("0x… holds whole bytes (2 hex digits each)")
        ))
    );
    assert_eq!(panel.input(), Some("c0f"));
    press(&mut panel, [Key::Esc]);
    assert_eq!(panel.input(), None);
    assert_eq!(
        value(&panel.template, "CKA_ID"),
        AttrValue::Bytes(vec![1, 2])
    );
}

#[test]
fn pasted_hex_drops_its_0x_spaces_and_colons() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(
        &mut panel,
        [Key::Down, Key::Down, Key::Down, Key::Enter, Key::Ctrl('u')],
    );
    press(&mut panel, [Key::Paste(" 0xC0:FE 01\n".into())]);
    assert_eq!(panel.input(), Some("C0FE01"));
    press(&mut panel, [Key::Paste("zz".into())]);
    assert_eq!(
        panel.message(),
        Some(&error("CKA_ID takes hex digits (0-9, a-f)", None))
    );
    press(&mut panel, [Key::Enter]);
    assert_eq!(
        value(&panel.template, "CKA_ID"),
        AttrValue::Bytes(vec![0xc0, 0xfe, 0x01])
    );
}

#[test]
fn an_empty_bytes_input_is_empty_bytes_like_a_bare_0x() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(
        &mut panel,
        [
            Key::Down,
            Key::Down,
            Key::Down,
            Key::Enter,
            Key::Ctrl('u'),
            Key::Enter,
        ],
    );
    assert_eq!(
        value(&panel.template, "CKA_ID"),
        AttrValue::Bytes(Vec::new())
    );
}

#[test]
fn text_input_keeps_any_text_and_drops_pasted_line_breaks() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(&mut panel, [Key::End, Key::Up, Key::Enter]);
    assert_eq!(panel.input(), Some("seed"));
    press(&mut panel, [Key::Ctrl('u')]);
    press(&mut panel, chars("my key é"));
    press(&mut panel, [Key::Paste("\nx\r".into())]);
    press(&mut panel, [Key::Enter]);
    assert_eq!(
        value(&panel.template, "CKA_LABEL"),
        AttrValue::Str("my key éx".into())
    );
}

#[test]
fn integer_input_reports_the_line_editors_errors() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(&mut panel, [Key::Down, Key::Down, Key::Enter]);
    assert_eq!(panel.input(), Some("32"));
    press(&mut panel, [Key::Char('z')]);
    assert_eq!(
        panel.message(),
        Some(&error(
            "CKA_VALUE_LEN takes decimal digits or 0x… hex",
            None
        ))
    );
    press(
        &mut panel,
        [Key::Ctrl('u'), Key::Char('0'), Key::Char('x'), Key::Enter],
    );
    assert_eq!(
        panel.message(),
        Some(&error(
            "CKA_VALUE_LEN: invalid integer '0x'",
            Some("decimal digits or 0x… hex")
        ))
    );
    press(&mut panel, [Key::Ctrl('u')]);
    press(&mut panel, chars("0x40"));
    press(&mut panel, [Key::Enter]);
    assert_eq!(
        value(&panel.template, "CKA_VALUE_LEN"),
        AttrValue::Ulong(64)
    );
}

#[test]
fn input_editing_keys_move_and_delete() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(&mut panel, [Key::End, Key::Up, Key::Enter]); // "seed", cursor at the end
    press(&mut panel, [Key::Left, Key::Backspace]); // "sed"
    press(&mut panel, [Key::Home, Key::Delete]); // "ed"
    press(&mut panel, [Key::Right, Key::Char('X')]); // "eXd"
    press(&mut panel, [Key::Ctrl('a'), Key::Ctrl('d')]); // "Xd"
    press(&mut panel, [Key::Ctrl('e'), Key::Char('!')]); // "Xd!"
    press(&mut panel, [Key::Left, Key::Ctrl('k')]); // "Xd"
    assert_eq!(panel.input(), Some("Xd"));
}

#[test]
fn a_value_typed_into_a_disabled_row_enables_it() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(
        &mut panel,
        [Key::Down, Key::Down, Key::Down, Key::Char('-')],
    );
    assert!(!panel.template.get("CKA_ID").unwrap().enabled);
    press(&mut panel, [Key::Enter, Key::Ctrl('u')]);
    press(&mut panel, chars("aa"));
    press(&mut panel, [Key::Enter]);
    let id = panel.template.get("CKA_ID").unwrap();
    assert!(id.enabled);
    assert_eq!(id.value, AttrValue::Bytes(vec![0xaa]));
}

// ---------------------------------------------------------------------------------------
// the add list
// ---------------------------------------------------------------------------------------

#[test]
fn add_list_ranks_names_starting_with_the_filter_first() {
    let custom = acme_custom();
    let panel = Panel::new(make_template(), "t", &custom);
    let names = |filter: &str| -> Vec<String> {
        panel
            .candidates(filter)
            .into_iter()
            .map(|candidate| candidate.name)
            .collect()
    };
    assert_eq!(names("ext"), ["CKA_EXTRACTABLE", "CKA_NEVER_EXTRACTABLE"]);
    assert_eq!(names("cka_id")[0], "CKA_ID");
    assert!(names("id").contains(&"CKA_OBJECT_ID".to_owned()));
    assert!(names("nothing-like-this").is_empty());
    let all = panel.candidates("");
    assert_eq!(all.len(), r2_core::catalog::CKA_CATALOG.len() + 1);
    assert_eq!(all[0].name, "CKA_CLASS");
    assert_eq!(
        all.last().unwrap(),
        &Candidate {
            name: "CKA_ACME_USAGE".into(),
            kind: AttrKind::Bytes,
            custom: true
        }
    );
}

#[test]
fn adding_a_boolean_appends_it_checked_with_the_cursor_on_it() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(&mut panel, [Key::Char('a')]);
    press(&mut panel, chars("trusted"));
    press(&mut panel, [Key::Enter]);
    let added = panel.template.attrs.last().unwrap();
    assert_eq!(
        added,
        &TemplateAttr::new("CKA_TRUSTED", AttrKind::Bool, AttrValue::Bool(true))
    );
    assert_eq!(panel.cursor(), 7);
    press(&mut panel, [Key::Char(' ')]);
    assert_eq!(
        value(&panel.template, "CKA_TRUSTED"),
        AttrValue::Bool(false)
    );
}

#[test]
fn adding_other_kinds_asks_for_the_value_and_notes_identity_rows() {
    let custom = no_custom();
    let mut panel = Panel::new(without_id(), "t", &custom);
    press(&mut panel, [Key::Insert]);
    press(&mut panel, chars("id"));
    press(&mut panel, [Key::Enter]);
    assert_eq!(panel.input(), Some(""), "the value input of the new CKA_ID");
    press(&mut panel, chars("c0fe"));
    press(&mut panel, [Key::Enter]);
    assert_eq!(
        panel.template.attrs.last().unwrap(),
        &TemplateAttr::new(
            "CKA_ID",
            AttrKind::Bytes,
            AttrValue::Bytes(vec![0xc0, 0xfe])
        )
    );
    assert_eq!(panel.cursor(), 6);
    assert_eq!(
        panel.message(),
        Some(&Message::Note(
            "note: CKA_ID is normally set with --id; this value will be used as the new object's id"
                .into()
        ))
    );
}

#[test]
fn custom_attributes_can_be_added_from_the_list() {
    let custom = acme_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(&mut panel, [Key::Char('a')]);
    press(&mut panel, chars("acme"));
    press(&mut panel, [Key::Enter]);
    press(&mut panel, [Key::Paste("0a0b".into()), Key::Enter]);
    assert_eq!(
        value(&panel.template, "CKA_ACME_USAGE"),
        AttrValue::Bytes(vec![0x0a, 0x0b])
    );
}

#[test]
fn picking_a_name_already_in_the_template_moves_the_cursor_to_it() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(&mut panel, [Key::Char('a')]);
    press(&mut panel, chars("label"));
    press(&mut panel, [Key::Enter]);
    assert_eq!(panel.cursor(), 6);
    assert_eq!(
        panel.message(),
        Some(&Message::Note("CKA_LABEL is already row 7".into()))
    );
    assert_eq!(panel.template, make_template());
    // a locked row is named but not selected
    press(&mut panel, [Key::Char('a')]);
    press(&mut panel, chars("class"));
    press(&mut panel, [Key::Enter]);
    assert_eq!(panel.cursor(), 6);
    assert_eq!(
        panel.message(),
        Some(&Message::Note("CKA_CLASS is already row 1".into()))
    );
}

#[test]
fn an_unknown_name_is_the_line_editors_error() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(&mut panel, [Key::Char('a')]);
    press(&mut panel, chars("nope"));
    press(&mut panel, [Key::Enter]);
    assert_eq!(
        panel.message(),
        Some(&error(
            "unknown attribute 'nope'",
            Some("add accepts CKA catalog names or templates.custom_attributes entries")
        ))
    );
    assert_eq!(panel.input(), Some("nope"), "the list stays open");
    // any later key clears the message
    press(&mut panel, [Key::Down]);
    assert_eq!(panel.message(), None);
}

#[test]
fn add_list_choice_moves_and_esc_leaves_without_adding() {
    let custom = no_custom();
    let mut panel = Panel::new(without_id(), "t", &custom);
    press(&mut panel, [Key::Char('a')]);
    press(&mut panel, chars("ext"));
    press(
        &mut panel,
        [Key::Down, Key::Down, Key::Up, Key::PageDown, Key::PageUp],
    );
    press(&mut panel, [Key::Down, Key::Enter]);
    assert_eq!(
        panel.template.attrs.last().unwrap().name,
        "CKA_NEVER_EXTRACTABLE"
    );
    // Esc in the list, and Esc at the value prompt of a picked name, add nothing
    let rows = panel.template.attrs.len();
    press(
        &mut panel,
        [Key::Char('a'), Key::Char('x'), Key::Backspace, Key::Esc],
    );
    press(&mut panel, [Key::Char('a')]);
    press(&mut panel, chars("cka_id"));
    press(&mut panel, [Key::Enter, Key::Char('a'), Key::Esc]);
    assert_eq!(panel.template.attrs.len(), rows);
    assert_eq!(panel.input(), None);
}

// ---------------------------------------------------------------------------------------
// the `:` line
// ---------------------------------------------------------------------------------------

fn command(panel: &mut Panel<'_>, line: &str) -> Option<End> {
    press(panel, [Key::Char(':')]);
    press(panel, chars(line));
    press(panel, [Key::Enter])
}

#[test]
fn command_line_runs_the_line_grammar() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    assert!(command(&mut panel, "5=16").is_none());
    assert_eq!(
        value(&panel.template, "CKA_VALUE_LEN"),
        AttrValue::Ulong(16)
    );
    command(&mut panel, "3");
    assert_eq!(value(&panel.template, "CKA_TOKEN"), AttrValue::Bool(false));
    command(&mut panel, "-4");
    assert!(!panel.template.get("CKA_SENSITIVE").unwrap().enabled);
    command(&mut panel, "add CKA_EXTRACTABLE=true");
    assert_eq!(
        value(&panel.template, "CKA_EXTRACTABLE"),
        AttrValue::Bool(true)
    );
    assert_eq!(panel.cursor(), 7, "the cursor goes to the added row");
    assert!(
        command(&mut panel, "   ").is_none(),
        "an empty line closes the : line"
    );
    assert_eq!(panel.input(), None);
    assert!(matches!(command(&mut panel, "ok"), Some(End::Accept)));
    let mut panel = Panel::new(make_template(), "t", &custom);
    assert!(matches!(command(&mut panel, "cancel"), Some(End::Cancel)));
    let mut panel = Panel::new(make_template(), "t", &custom);
    assert!(matches!(command(&mut panel, " abort "), Some(End::Cancel)));
}

#[test]
fn command_line_errors_keep_the_line_for_correction() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    command(&mut panel, "9=1");
    assert_eq!(
        panel.message(),
        Some(&error("row 9 is out of range (1..7)", None))
    );
    assert_eq!(panel.input(), Some("9=1"));
    press(&mut panel, [Key::Ctrl('u')]);
    press(&mut panel, chars("1=42"));
    press(&mut panel, [Key::Enter]);
    assert_eq!(
        panel.message(),
        Some(&error(
            "row 1 (CKA_CLASS) is locked and cannot be changed",
            Some("locked rows (CKA_CLASS/CKA_KEY_TYPE) are derived from the key (§5.12)")
        ))
    );
    press(&mut panel, [Key::Left]);
    assert_eq!(panel.message(), None, "any later key clears the message");
    assert_eq!(panel.input(), Some("1=42"));
    press(&mut panel, [Key::Esc]);
    assert_eq!(panel.input(), None);
    assert_eq!(panel.template, make_template());
}

#[test]
fn command_line_add_of_an_identity_row_shows_the_note() {
    let custom = no_custom();
    let mut panel = Panel::new(without_id(), "t", &custom);
    command(&mut panel, "add CKA_ID=0xc0fe");
    assert_eq!(
        value(&panel.template, "CKA_ID"),
        AttrValue::Bytes(vec![0xc0, 0xfe])
    );
    assert!(matches!(panel.message(), Some(Message::Note(note)) if note.contains("--id")));
    // a pasted line works too
    press(
        &mut panel,
        [Key::Char(':'), Key::Paste("5=7\n".into()), Key::Enter],
    );
    assert_eq!(value(&panel.template, "CKA_VALUE_LEN"), AttrValue::Ulong(7));
}

// ---------------------------------------------------------------------------------------
// frames
// ---------------------------------------------------------------------------------------

#[test]
fn frame_shows_title_header_rows_ok_row_and_keys() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "PKCS#11 template — AES key 'k'", &custom);
    let frame = panel.frame(80, 24);
    let text = frame_text(&frame);
    assert_eq!(text[0], "PKCS#11 template — AES key 'k'");
    assert_eq!(text[1], "  #  state  attribute      kind   value");
    assert_eq!(text[2], "─".repeat(79));
    assert_eq!(text[3], "  1  (*)    CKA_CLASS      ulong  CKO_SECRET_KEY");
    assert_eq!(text[5], "❯ 3  [x]    CKA_TOKEN      bool   true");
    assert_eq!(text[8], "  6         CKA_ID         bytes  0x0102");
    assert_eq!(text[10], format!("{}[ OK ]", " ".repeat(12)));
    assert_eq!(text[11], "─".repeat(79));
    assert!(text[12].starts_with("↑↓ move · space/enter toggle or edit"));
    assert!(text.join("\n").contains("esc cancel"));
    assert_eq!(frame.cursor, None, "the cursor is hidden while browsing");
    assert!(text.iter().all(|line| text_cells(line) <= 79));
}

#[test]
fn frame_puts_the_cursor_in_the_value_being_edited() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(&mut panel, [Key::Down, Key::Down, Key::Down, Key::Enter]);
    let frame = panel.frame(80, 24);
    let text = frame_text(&frame);
    assert_eq!(text[8], "❯ 6         CKA_ID         bytes  0x0102  2 bytes");
    // marker 2 + index 1 + 2 + state 5 + 2 + name 13 + 2 + kind 5 + 2 = 34, then "0x0102"
    assert_eq!(frame.cursor, Some((8, 34 + 2 + 4)));
    assert!(text.join("\n").contains("enter set · esc keep"));
    press(&mut panel, [Key::Backspace]);
    let text = frame_text(&panel.frame(80, 24));
    assert_eq!(
        text[8],
        "❯ 6         CKA_ID         bytes  0x010  odd number of hex digits"
    );
}

#[test]
fn long_templates_scroll_to_keep_the_cursor_visible() {
    let custom = no_custom();
    let mut attrs = vec![
        TemplateAttr::new(
            "CKA_CLASS",
            AttrKind::Ulong,
            AttrValue::Symbol("CKO_DATA".into()),
        )
        .locked(),
    ];
    for i in 0..40 {
        attrs.push(TemplateAttr::new(
            format!("CKA_VENDOR_{i}"),
            AttrKind::Bool,
            AttrValue::Bool(i % 2 == 0),
        ));
    }
    let mut panel = Panel::new(KeyTemplate::new(attrs), "t", &custom);
    let frame = panel.frame(80, 14);
    let text = frame_text(&frame);
    assert!(frame.lines.len() <= 13, "{} lines", frame.lines.len());
    assert!(
        text.iter().any(|line| line.starts_with("  rows 1–")),
        "{text:#?}"
    );
    assert!(text.iter().any(|line| line.contains("CKA_VENDOR_0")));
    press(&mut panel, [Key::End, Key::Up]);
    let text = frame_text(&panel.frame(80, 14));
    assert!(
        text.iter()
            .any(|line| line.starts_with("❯ 41") && line.contains("CKA_VENDOR_39"))
    );
    assert!(!text.iter().any(|line| line.contains("CKA_VENDOR_0 ")));
    // PageUp moves by the rows the frame showed
    press(&mut panel, [Key::PageUp]);
    assert!(panel.cursor() < 40 - 3);
}

#[test]
fn narrow_terminals_shorten_names_and_values_to_fit() {
    let custom = no_custom();
    let mut template = make_template();
    template.attrs.push(TemplateAttr::new(
        "CKA_HASH_OF_SUBJECT_PUBLIC_KEY",
        AttrKind::Bytes,
        AttrValue::Bytes(vec![0xab; 20]),
    ));
    let mut panel = Panel::new(
        template,
        "a title that is longer than the terminal is wide",
        &custom,
    );
    let text = frame_text(&panel.frame(MIN_COLUMNS, 24));
    // the title is left to the session's clipping; every laid-out row fits
    assert!(
        text.iter()
            .skip(1)
            .all(|line| text_cells(line) < MIN_COLUMNS),
        "{text:#?}"
    );
    assert!(
        text.iter().any(|line| line.contains("CKA_HASH…")),
        "{text:#?}"
    );
    // at the smallest size the frame still fits the screen, the key help in two rows
    let frame = panel.frame(MIN_COLUMNS, MIN_ROWS);
    assert!(frame.lines.len() < MIN_ROWS, "{:#?}", frame_text(&frame));
    let text = frame_text(&frame);
    assert!(text.last().unwrap().ends_with("esc cancel"), "{text:#?}");
}

#[test]
fn add_list_frame_marks_present_and_automatic_attributes() {
    let custom = acme_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(&mut panel, [Key::Char('a')]);
    press(&mut panel, chars("value"));
    let frame = panel.frame(80, 30);
    let text = frame_text(&frame);
    let filter_row = text.iter().position(|line| line == "add › value").unwrap();
    assert_eq!(
        frame.cursor,
        Some((filter_row, "add › value".chars().count()))
    );
    // names padded to the longest candidate (CKA_CHECK_VALUE, 15 cells)
    assert_eq!(
        text[filter_row + 1].trim_end(),
        "❯ CKA_VALUE        bytes  set automatically"
    );
    assert_eq!(text[filter_row + 2].trim_end(), "  CKA_VALUE_BITS   ulong");
    assert_eq!(
        text[filter_row + 3].trim_end(),
        "  CKA_VALUE_LEN    ulong  row 5"
    );
    assert_eq!(
        text[filter_row + 4].trim_end(),
        "  CKA_CHECK_VALUE  bytes  set automatically"
    );
    press(&mut panel, [Key::Ctrl('u')]);
    press(&mut panel, chars("acme"));
    let text = frame_text(&panel.frame(80, 30));
    assert!(
        text.iter()
            .any(|line| line.contains("CKA_ACME_USAGE") && line.ends_with("custom"))
    );
    press(&mut panel, [Key::Ctrl('u')]);
    let text = frame_text(&panel.frame(80, 30));
    assert!(
        text.iter().any(|line| line.contains("(↑↓ choose)")),
        "{text:#?}"
    );
    press(&mut panel, chars("zzz"));
    let text = frame_text(&panel.frame(80, 30));
    assert!(
        text.iter()
            .any(|line| line.trim() == "no attribute matches")
    );
}

#[test]
fn value_prompt_and_command_frames_show_their_input_and_help() {
    let custom = no_custom();
    let mut panel = Panel::new(without_id(), "t", &custom);
    press(&mut panel, [Key::Char('a')]);
    press(&mut panel, chars("cka_id"));
    press(&mut panel, [Key::Enter]);
    press(&mut panel, chars("c0"));
    let frame = panel.frame(80, 24);
    let text = frame_text(&frame);
    let row = text
        .iter()
        .position(|line| line.starts_with("CKA_ID = "))
        .unwrap();
    assert_eq!(text[row], "CKA_ID = 0xc0  1 byte");
    assert_eq!(frame.cursor, Some((row, "CKA_ID = 0xc0".len())));
    press(&mut panel, [Key::Esc, Key::Char(':')]);
    press(&mut panel, chars("5=1"));
    let frame = panel.frame(120, 24);
    let text = frame_text(&frame);
    let row = text.iter().position(|line| line == ": 5=1").unwrap();
    assert_eq!(frame.cursor, Some((row, 5)));
    assert_eq!(text[row + 1], HELP);
    assert_eq!(text[row + 2], "enter run · esc back");
}

#[test]
fn errors_show_their_message_and_hint_lines() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    command(&mut panel, "x=1");
    let text = frame_text(&panel.frame(120, 24));
    assert!(
        text.contains(&"✗ 'x' is not a row number".to_owned()),
        "{text:#?}"
    );
    assert!(text.contains(&format!("  hint: {HELP}")));
}

#[test]
fn long_inputs_scroll_to_keep_the_cursor_visible() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    press(&mut panel, [Key::Down, Key::Down, Key::Down, Key::Enter]);
    press(&mut panel, [Key::Paste("ab".repeat(100))]);
    let frame = panel.frame(60, 24);
    let text = frame_text(&frame);
    let row = text
        .iter()
        .position(|line| line.starts_with("❯ 6"))
        .unwrap();
    assert!(text[row].contains("0x…"), "{}", text[row]);
    assert!(text_cells(&text[row]) <= 59);
    let (_, column) = frame.cursor.unwrap();
    assert!(column <= 59);
}

// ---------------------------------------------------------------------------------------
// run(): the session loop
// ---------------------------------------------------------------------------------------

/// A KeySession over queued keys that records every frame; reading fails after `fail_after`
/// keys (or when the queue is empty), like a terminal that went away.
struct ScriptedSession {
    keys: VecDeque<Key>,
    size: (usize, usize),
    frames: Vec<Frame>,
    reads: usize,
    fail_after: Option<usize>,
}

impl ScriptedSession {
    fn new(keys: Vec<Key>, size: (usize, usize)) -> Self {
        Self {
            keys: keys.into(),
            size,
            frames: Vec::new(),
            reads: 0,
            fail_after: None,
        }
    }
}

impl KeySession for ScriptedSession {
    fn size(&self) -> (usize, usize) {
        self.size
    }
    fn draw(&mut self, frame: &Frame) -> Result<()> {
        self.frames.push(frame.clone());
        Ok(())
    }
    fn read_key(&mut self) -> Result<Key> {
        if self.fail_after == Some(self.reads) {
            return Err(ConsoleError::generic("terminal error: gone"));
        }
        self.reads += 1;
        self.keys
            .pop_front()
            .ok_or_else(|| ConsoleError::generic("terminal error: no more keys"))
    }
}

#[test]
fn run_draws_a_frame_before_every_key() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    let mut session = ScriptedSession::new(vec![Key::Char(' '), Key::End, Key::Enter], (80, 24));
    assert!(matches!(panel.run(&mut session), End::Accept));
    assert_eq!(session.frames.len(), 3);
    assert!(
        frame_text(&session.frames[1])[5].contains("[ ]"),
        "the toggle is drawn"
    );
    assert_eq!(value(&panel.template, "CKA_TOKEN"), AttrValue::Bool(false));
}

#[test]
fn run_gives_up_on_small_terminals_without_drawing() {
    let custom = no_custom();
    for size in [(MIN_COLUMNS - 1, 24), (80, MIN_ROWS - 1)] {
        let mut panel = Panel::new(make_template(), "t", &custom);
        let mut session = ScriptedSession::new(vec![Key::Enter], size);
        assert!(matches!(panel.run(&mut session), End::TooSmall));
        assert!(session.frames.is_empty());
    }
}

#[test]
fn run_reports_a_lost_terminal_and_keeps_the_edits() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    let mut session = ScriptedSession::new(vec![Key::Char(' ')], (80, 24));
    session.fail_after = Some(1);
    assert!(matches!(panel.run(&mut session), End::TerminalLost));
    assert_eq!(value(&panel.template, "CKA_TOKEN"), AttrValue::Bool(false));
}

/// A session whose draw fails at once.
struct BrokenSession;
impl KeySession for BrokenSession {
    fn size(&self) -> (usize, usize) {
        (80, 24)
    }
    fn draw(&mut self, _frame: &Frame) -> Result<()> {
        Err(ConsoleError::generic("terminal error: gone"))
    }
    fn read_key(&mut self) -> Result<Key> {
        Ok(Key::Enter)
    }
}

#[test]
fn run_reports_a_failed_draw_as_a_lost_terminal() {
    let custom = no_custom();
    let mut panel = Panel::new(make_template(), "t", &custom);
    assert!(matches!(panel.run(&mut BrokenSession), End::TerminalLost));
}

// ---------------------------------------------------------------------------------------
// the editor: panel on an interactive IO, the line checklist otherwise
// ---------------------------------------------------------------------------------------

/// A ConsoleIo that is interactive: `interactive` runs `f` over a ScriptedSession; every
/// other method is the inner ScriptedIo's (line prompts after a fall-back, output).
struct PanelIo {
    lines: Rc<ScriptedIo>,
    session: RefCell<Option<ScriptedSession>>,
    frames: RefCell<Vec<Frame>>,
}

impl PanelIo {
    fn new(session: ScriptedSession, answers: &[&str]) -> Rc<Self> {
        Rc::new(Self {
            lines: Rc::new(ScriptedIo::new(answers.iter().copied())),
            session: RefCell::new(Some(session)),
            frames: RefCell::new(Vec::new()),
        })
    }
}

impl ConsoleIo for PanelIo {
    fn prompt(&self, spec: &ParamSpec) -> Result<String> {
        self.lines.prompt(spec)
    }
    fn prompt_secret(&self, text: &str) -> Result<SecretString> {
        self.lines.prompt_secret(text)
    }
    fn prompt_multiline(&self, text: &str) -> Result<String> {
        self.lines.prompt_multiline(text)
    }
    fn select(&self, title: &str, options: &[String]) -> Result<usize> {
        self.lines.select(title, options)
    }
    fn confirm(&self, text: &str, default: bool) -> Result<bool> {
        self.lines.confirm(text, default)
    }
    fn print(&self, renderable: Renderable) {
        self.lines.print(renderable);
    }
    fn print_error(&self, err: &ConsoleError) {
        self.lines.print_error(err);
    }
    fn interactive(&self, f: &mut dyn FnMut(&mut dyn KeySession)) -> bool {
        let Some(mut session) = self.session.borrow_mut().take() else {
            return false;
        };
        f(&mut session);
        self.frames.borrow_mut().extend(session.frames);
        true
    }
}

fn panel_editor(io: &Rc<PanelIo>) -> ChecklistTemplateEditor {
    ChecklistTemplateEditor::new(Rc::clone(io) as Rc<dyn ConsoleIo>, no_custom())
}

#[test]
fn editor_uses_the_panel_and_prints_the_accepted_template_once() {
    let session = ScriptedSession::new(vec![Key::Char(' '), Key::End, Key::Enter], (80, 24));
    let io = PanelIo::new(session, &[]);
    let result = panel_editor(&io).edit(make_template(), "PKCS#11 template — AES key 'k'");
    let result = result.unwrap();
    assert_eq!(value(&result, "CKA_TOKEN"), AttrValue::Bool(false));
    assert!(io.lines.prompts().is_empty(), "no line prompt was asked");
    assert_eq!(io.frames.borrow().len(), 3);
    let output = io.lines.text();
    assert!(
        output.contains("PKCS#11 template — AES key 'k'"),
        "{output}"
    );
    assert!(output.contains("CKA_TOKEN"));
    assert!(
        !output.contains(HELP),
        "the line editor's help is not printed"
    );
    assert_eq!(io.lines.renderables().len(), 1);
}

#[test]
fn editor_panel_esc_is_template_edit_cancelled_and_ctrl_c_is_the_prompt_abort() {
    let io = PanelIo::new(ScriptedSession::new(vec![Key::Esc], (80, 24)), &[]);
    let err = panel_editor(&io).edit(make_template(), "t").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert_eq!(err.message, "template edit cancelled");
    assert!(io.lines.output().is_empty(), "nothing is printed on cancel");

    let io = PanelIo::new(ScriptedSession::new(vec![Key::Ctrl('c')], (80, 24)), &[]);
    let err = panel_editor(&io).edit(make_template(), "t").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert_eq!(err.message, "aborted while entering 'template'");
}

#[test]
fn editor_continues_in_the_line_checklist_with_the_edits_when_the_terminal_fails() {
    let mut session = ScriptedSession::new(vec![Key::Char(' ')], (80, 24));
    session.fail_after = Some(1);
    let io = PanelIo::new(session, &["4", "ok"]);
    let result = panel_editor(&io).edit(make_template(), "t").unwrap();
    assert_eq!(
        value(&result, "CKA_TOKEN"),
        AttrValue::Bool(false),
        "panel edit kept"
    );
    assert_eq!(
        value(&result, "CKA_SENSITIVE"),
        AttrValue::Bool(false),
        "line edit"
    );
    assert_eq!(io.lines.prompts(), ["template> ", "template> "]);
    assert!(io.lines.output().iter().any(|line| line == HELP));
}

#[test]
fn editor_uses_the_line_checklist_on_a_small_terminal() {
    let session = ScriptedSession::new(vec![], (MIN_COLUMNS, MIN_ROWS - 1));
    let io = PanelIo::new(session, &["3", "ok"]);
    let result = panel_editor(&io).edit(make_template(), "t").unwrap();
    assert_eq!(value(&result, "CKA_TOKEN"), AttrValue::Bool(false));
    assert!(io.frames.borrow().is_empty());
}

#[test]
fn editor_without_an_interactive_terminal_is_the_line_checklist() {
    // the second edit finds no session left: `interactive` returns false
    let io = PanelIo::new(
        ScriptedSession::new(vec![Key::End, Key::Enter], (80, 24)),
        &["ok"],
    );
    let editor = panel_editor(&io);
    editor.edit(make_template(), "t").unwrap();
    let before = io.lines.renderables().len();
    let result = editor.edit(make_template(), "t").unwrap();
    assert_eq!(result, make_template());
    assert_eq!(io.lines.prompts(), ["template> "]);
    assert_eq!(io.lines.renderables().len(), before + 2, "table + help");
}
