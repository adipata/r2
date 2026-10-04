//! Interaction-trait tests (spec §4.9.1) — port of c2 `tests/unit/core/test_io_protocols.py`.
//! The structural half of its two Protocol cases is compiler-enforced in Rust (`impl
//! ConsoleIo for ScriptedIo`, `impl TemplateEditor for IdentityTemplateEditor`); their
//! behavioral assertions are ported below, through `&dyn` trait objects.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use r2_core::io::{ConsoleIo, IdentityTemplateEditor, Renderable, TemplateEditor};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_testkit::ScriptedIo;

fn use_io(io: &dyn ConsoleIo) {
    io.print(Renderable::from("via protocol"));
}

fn use_editor(editor: &dyn TemplateEditor, template: KeyTemplate) -> KeyTemplate {
    editor.edit(template, "Edit template").unwrap()
}

#[test]
fn test_scripted_io_passes_as_console_io_argument() {
    let io = ScriptedIo::empty();
    use_io(&io); // ScriptedIo accepted where a ConsoleIo is required
    assert_eq!(io.output(), ["via protocol"]);
}

#[test]
fn test_identity_editor_satisfies_template_editor_protocol() {
    let template = KeyTemplate::new(vec![TemplateAttr::new(
        "CKA_TOKEN",
        AttrKind::Bool,
        AttrValue::Bool(true),
    )]);
    assert_eq!(
        use_editor(&IdentityTemplateEditor, template.clone()),
        template
    );
}

/// The `[dependencies]` keys of r2-core's manifest.
fn core_dependencies() -> Vec<String> {
    let manifest = include_str!("../Cargo.toml");
    let mut in_section = false;
    let mut names = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line == "[dependencies]";
            continue;
        }
        if in_section && !line.is_empty() && !line.starts_with('#') {
            let name = line.split(['=', ' ', '.']).next().unwrap().trim();
            names.push(name.to_owned());
        }
    }
    names
}

/// c2 §3.1: core never imports prompt_toolkit/rich/console. In r2 the crate graph enforces
/// layering (§4.1.2): r2-core depends on exactly its third-party list — no terminal or
/// line-editor crate and no workspace crate (the renderer's anstyle is permitted there
/// because ScriptedIo stores rendered text, §4.1.2).
#[test]
fn test_core_stays_console_free() {
    let mut deps = core_dependencies();
    deps.sort();
    let mut allowed = vec![
        "openssl",
        "der",
        "spki",
        "x509-cert",
        "const-oid",
        "secrecy",
        "zeroize",
        "indexmap",
        "hex",
        "base64",
        "anstyle",
        "tracing",
    ];
    allowed.sort_unstable();
    assert_eq!(deps, allowed);
    for banned in [
        "reedline",
        "crossterm",
        "nu-ansi-term",
        "rpassword",
        "indicatif",
        "console",
        "clap",
        "r2-console",
        "r2-config",
        "r2-provider",
    ] {
        assert!(!deps.iter().any(|dep| dep == banned), "{banned}");
    }
}

/// §4.9.1 / §11 D34: `ConsoleIo::interactive` defaults to "no interactive terminal" — it
/// returns false and never calls `f` — so ScriptedIo (and every IO without a terminal)
/// keeps callers on their line prompts.
#[test]
fn interactive_defaults_to_unavailable_without_calling_f() {
    let io = ScriptedIo::empty();
    let mut called = false;
    let opened = (&io as &dyn ConsoleIo).interactive(&mut |_session| called = true);
    assert!(!opened);
    assert!(!called);
    assert!(io.output().is_empty());
}

/// The interactive session types are plain data: a Frame defaults to no rows and a hidden
/// cursor, and keys compare by value (a paste carries its whole text).
#[test]
fn frame_and_key_values() {
    use r2_core::io::{Frame, Key};
    let frame = Frame::default();
    assert!(frame.lines.is_empty());
    assert_eq!(frame.cursor, None);
    assert_eq!(Key::Paste("c0fe".into()), Key::Paste("c0fe".into()));
    assert_ne!(Key::Ctrl('c'), Key::Char('c'));
}
