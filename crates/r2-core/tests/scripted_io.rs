//! ScriptedIo / RecordingEditor tests (spec §4.10.1) — port of c2
//! `tests/unit/core/test_scripted_io.py` (scripted prompt flows over the ConsoleIo trait), plus
//! the r2 additions: CTRL_C/CTRL_D sentinels, read_command, rendered output, the editor
//! double and the global-state lock.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::io::{
    CommandInput, ConsoleIo, IdentityTemplateEditor, Renderable, TemplateEditor, busy_with,
    error_panel, table,
};
use r2_core::params::{ParamKind, ParamSpec};
use r2_core::render::{RenderConfig, render_plain};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_testkit::{RecordingEditor, ScriptedIo, global_state_lock};
use secrecy::ExposeSecret;

fn label_spec() -> ParamSpec {
    ParamSpec::new("label", ParamKind::Str, "Key label")
}

fn mechs() -> Vec<String> {
    ["AES-GCM", "AES-CBC", "AES-CTR"]
        .map(str::to_owned)
        .to_vec()
}

/// The panic message of `f` (ScriptedIo's c2 AssertionError).
fn panic_message(f: impl FnOnce()) -> String {
    let payload = catch_unwind(AssertUnwindSafe(f)).expect_err("expected a panic");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_default()
}

/// A miniature interactive flow, written against the trait only.
fn scripted_flow(io: &dyn ConsoleIo) -> Result<(String, String, bool)> {
    let label = io.prompt(&label_spec())?;
    let pin = io.prompt_secret("Enter PIN")?;
    let data = io.prompt_multiline("Paste data (empty line ends)")?;
    let mechs = mechs();
    let mech = mechs[io.select("Choose mechanism", &mechs)?].clone();
    if !io.confirm(&format!("Encrypt with {mech}?"), false)? {
        return Err(ConsoleError::user_abort("aborted"));
    }
    io.print(Renderable::from(format!(
        "{label}: {} chars via {mech} (pin length {})",
        data.chars().count(),
        pin.expose_secret().len()
    )));
    Ok((label, mech, true))
}

#[test]
fn test_scripted_flow_runs_off_queued_answers() {
    let io = ScriptedIo::new(["mykey", "1234", "de ad be ef", "AES-CBC", "y"]);
    let (label, mech, ok) = scripted_flow(&io).unwrap();
    assert_eq!(
        (label.as_str(), mech.as_str(), ok),
        ("mykey", "AES-CBC", true)
    );
    assert_eq!(
        io.prompts(),
        [
            "Key label",
            "Enter PIN",
            "Paste data (empty line ends)",
            "Choose mechanism",
            "Encrypt with AES-CBC?",
        ]
    );
    assert_eq!(io.output(), ["mykey: 11 chars via AES-CBC (pin length 4)"]);
    assert!(io.output().iter().all(|line| !line.contains("1234"))); // never echo secrets
    assert_eq!(io.remaining(), 0);
}

#[test]
fn test_scripted_flow_abort_path() {
    let io = ScriptedIo::new(["mykey", "1234", "00", "AES-GCM", "n"]);
    let err = scripted_flow(&io).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
}

#[test]
fn test_prompt_answers_pop_in_order() {
    let io = ScriptedIo::new(["first", "second"]);
    assert_eq!(io.prompt(&label_spec()).unwrap(), "first");
    assert_eq!(io.remaining(), 1);
    assert_eq!(io.prompt(&label_spec()).unwrap(), "second");
    assert_eq!(io.remaining(), 0);
}

#[test]
fn test_exhausted_queue_raises_assertion_error() {
    let io = ScriptedIo::new(["only"]);
    assert_eq!(io.prompt(&label_spec()).unwrap(), "only");
    assert_eq!(
        panic_message(|| drop(io.prompt(&label_spec()))),
        "ScriptedIo: answer queue exhausted at prompt(\"Key label\")"
    );
    assert_eq!(
        panic_message(|| drop(ScriptedIo::empty().confirm("sure?", false))),
        "ScriptedIo: answer queue exhausted at confirm(\"sure?\")"
    );
    assert_eq!(
        panic_message(|| drop(ScriptedIo::empty().select("pick", &["a".to_owned()]))),
        "ScriptedIo: answer queue exhausted at select(\"pick\")"
    );
    assert_eq!(
        panic_message(|| drop(ScriptedIo::empty().prompt_secret("PIN"))),
        "ScriptedIo: answer queue exhausted at prompt_secret(\"PIN\")"
    );
    assert_eq!(
        panic_message(|| drop(ScriptedIo::empty().prompt_multiline("paste"))),
        "ScriptedIo: answer queue exhausted at prompt_multiline(\"paste\")"
    );
    assert_eq!(
        panic_message(|| drop(ScriptedIo::empty().read_command("r2> "))),
        "ScriptedIo: answer queue exhausted at read_command(\"r2> \")"
    );
}

#[test]
fn test_select_matches_by_option_text() {
    let io = ScriptedIo::new(["AES-CBC"]);
    assert_eq!(io.select("mech", &mechs()).unwrap(), 1);
}

#[test]
fn test_select_matches_by_index() {
    let io = ScriptedIo::new(["2"]);
    assert_eq!(io.select("mech", &mechs()).unwrap(), 2);
}

#[test]
fn test_select_prefers_option_text_over_index() {
    // "1" is an option itself here, so it must match by text (index 0), not index 1.
    let io = ScriptedIo::new(["1"]);
    assert_eq!(
        io.select("pick", &["1".to_owned(), "0".to_owned()])
            .unwrap(),
        0
    );
}

#[test]
fn test_select_rejects_unknown_answer() {
    let message = panic_message(|| drop(ScriptedIo::new(["nope"]).select("mech", &mechs())));
    assert!(message.contains("is neither an option"), "{message}");
    let message = panic_message(|| drop(ScriptedIo::new(["7"]).select("mech", &mechs())));
    assert!(message.contains("out of range"), "{message}"); // out of range
    let message = panic_message(|| drop(ScriptedIo::new(["-1"]).select("mech", &mechs())));
    assert!(message.contains("out of range"), "{message}");
}

#[test]
fn test_confirm_answers() {
    assert!(ScriptedIo::new(["y"]).confirm("go?", false).unwrap());
    assert!(ScriptedIo::new(["YES"]).confirm("go?", false).unwrap());
    assert!(!ScriptedIo::new(["n"]).confirm("go?", true).unwrap());
    assert!(!ScriptedIo::new(["no"]).confirm("go?", false).unwrap());
    assert!(ScriptedIo::new([""]).confirm("go?", true).unwrap());
    assert!(!ScriptedIo::new([""]).confirm("go?", false).unwrap());
    assert!(ScriptedIo::new([" Yes "]).confirm("go?", false).unwrap());
    let message = panic_message(|| drop(ScriptedIo::new(["maybe"]).confirm("go?", false)));
    assert!(message.contains("is not y/n"), "{message}");
}

#[test]
fn test_prompt_secret_and_multiline_pop_answers() {
    let io = ScriptedIo::new(["s3cret", "line one\nline two"]);
    assert_eq!(io.prompt_secret("PIN").unwrap().expose_secret(), "s3cret");
    assert_eq!(io.prompt_multiline("paste").unwrap(), "line one\nline two");
}

#[test]
fn test_print_collects_plain_strings() {
    let io = ScriptedIo::empty();
    io.print(Renderable::from("hello"));
    io.print(Renderable::from(42.to_string()));
    assert_eq!(io.output(), ["hello", "42"]);
    assert_eq!(io.text(), "hello\n42");
}

#[test]
fn test_print_error_collects_message_and_hint() {
    let io = ScriptedIo::empty();
    io.print_error(&ConsoleError::codec("bad data"));
    io.print_error(&ConsoleError::codec("bad data").with_hint("use hex:"));
    let output = io.output();
    assert_eq!(output[0], "error: bad data");
    assert!(output[1].contains("bad data"));
    assert!(output[1].contains("use hex:"));
    assert_eq!(output[1], "error: bad data (hint: use hex:)");
    // renderables() records the error panels
    assert_eq!(
        io.renderables(),
        [
            error_panel("bad data", None),
            error_panel("bad data", Some("use hex:"))
        ]
    );
}

/// §4.10.1: print records `render_plain(r, CAPTURE)` (width 200) and the raw Renderable.
#[test]
fn print_renders_plain_text_at_capture_width() {
    let io = ScriptedIo::empty();
    let rendered = table(None, &["#", "name"], vec![vec!["1".into(), "k".into()]]);
    io.print(rendered.clone());
    io.print(r2_core::io::hex(&[0xde, 0xad], Some("data")));
    // The trait default prints the clear sequence as content, recorded verbatim (c2
    // `test_clear_falls_back_to_ansi_for_plain_io`: output == ["\x1b[2J\x1b[H"]).
    io.clear();
    let output = io.output();
    assert!(!output[0].contains('\u{1b}'));
    assert!(output[0].contains("name") && output[0].contains('k'));
    assert_eq!(
        output[1],
        render_plain(
            &r2_core::io::hex(&[0xde, 0xad], Some("data")),
            &RenderConfig::CAPTURE
        )
    );
    assert!(
        output[1].starts_with("╭─ data ─╮\n│ dead   │\n"),
        "{}",
        output[1]
    );
    assert_eq!(output[2], "\u{1b}[2J\u{1b}[H");
    assert_eq!(io.renderables()[0], rendered);
}

/// Sentinels: CTRL_C / CTRL_D are the keys at that read (§4.9.1 abort texts).
#[test]
fn ctrl_c_and_ctrl_d_sentinels() {
    let spec = label_spec();
    for sentinel in [ScriptedIo::CTRL_C, ScriptedIo::CTRL_D] {
        let io = ScriptedIo::new([sentinel; 4]);
        let err = io.prompt(&spec).unwrap_err();
        assert_eq!(
            (err.kind, err.message.as_str()),
            (ErrorKind::UserAbort, "aborted while entering 'label'")
        );
        let err = io.prompt_secret("PIN").unwrap_err();
        assert_eq!(err.message, "aborted secret input");
        let err = io.select("pick", &mechs()).unwrap_err();
        assert_eq!(err.message, "selection aborted");
        let err = io.confirm("go?", true).unwrap_err();
        assert_eq!(err.message, "confirmation aborted");
        assert!(err.kind.is_user_abort());
    }
    // Multiline: Ctrl-C aborts, Ctrl-D (EOF) ends the input.
    let io = ScriptedIo::new([ScriptedIo::CTRL_C, ScriptedIo::CTRL_D]);
    let err = io.prompt_multiline("paste").unwrap_err();
    assert_eq!(
        (err.kind, err.message.as_str()),
        (ErrorKind::UserAbort, "aborted multiline input")
    );
    assert_eq!(io.prompt_multiline("paste").unwrap(), "");
}

/// read_command: verbatim prompts recorded; sentinels → Interrupted / Eof.
#[test]
fn read_command_pops_lines_and_sentinels() {
    let io = ScriptedIo::new([
        "keys mem",
        "load \"a",
        "b\"",
        ScriptedIo::CTRL_C,
        ScriptedIo::CTRL_D,
    ]);
    assert_eq!(
        io.read_command("r2> ").unwrap(),
        CommandInput::Line("keys mem".into())
    );
    assert_eq!(
        io.read_command("r2> ").unwrap(),
        CommandInput::Line("load \"a".into())
    );
    assert_eq!(
        io.read_command("…> ").unwrap(),
        CommandInput::Line("b\"".into())
    );
    assert_eq!(io.read_command("r2> ").unwrap(), CommandInput::Interrupted);
    assert_eq!(io.read_command("r2> ").unwrap(), CommandInput::Eof);
    assert_eq!(io.prompts(), ["r2> ", "r2> ", "…> ", "r2> ", "r2> "]);
}

/// The ConsoleIo contract: an empty option list is a Generic error (no answer consumed).
#[test]
fn select_with_no_options_is_an_error() {
    let io = ScriptedIo::new(["0"]);
    let err = io.select("Choose mechanism", &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(err.message, "nothing to select for: Choose mechanism");
    assert_eq!(io.remaining(), 1);
}

/// busy_with returns the closure's value through the IO's `busy` (default: just runs it).
#[test]
fn busy_with_runs_the_closure_once() {
    let io = ScriptedIo::empty();
    let mut calls = 0;
    let value = busy_with(&io, "working", || {
        calls += 1;
        io.print(Renderable::from("inside")); // re-entering the IO is allowed
        41 + 1
    });
    assert_eq!((value, calls), (42, 1));
    assert_eq!(io.output(), ["inside"]);

    /// An IO whose busy never runs `f` (a contract violation): busy_with still runs it.
    struct Lazy;
    impl ConsoleIo for Lazy {
        fn prompt(&self, _: &ParamSpec) -> Result<String> {
            unreachable!()
        }
        fn prompt_secret(&self, _: &str) -> Result<secrecy::SecretString> {
            unreachable!()
        }
        fn prompt_multiline(&self, _: &str) -> Result<String> {
            unreachable!()
        }
        fn select(&self, _: &str, _: &[String]) -> Result<usize> {
            unreachable!()
        }
        fn confirm(&self, _: &str, _: bool) -> Result<bool> {
            unreachable!()
        }
        fn print(&self, _: Renderable) {}
        fn print_error(&self, _: &ConsoleError) {}
        fn busy(&self, _: &str, _: &mut dyn FnMut()) {}
    }
    assert_eq!(busy_with(&Lazy, "x", || "result"), "result");
}

/// The trait's default read_command goes through `prompt` with the synthetic STR spec.
#[test]
fn default_read_command_uses_the_prompt_method() {
    struct PromptOnly(ScriptedIo);
    impl ConsoleIo for PromptOnly {
        fn prompt(&self, spec: &ParamSpec) -> Result<String> {
            assert_eq!((spec.name.as_str(), spec.kind), ("command", ParamKind::Str));
            self.0.prompt(spec)
        }
        fn prompt_secret(&self, text: &str) -> Result<secrecy::SecretString> {
            self.0.prompt_secret(text)
        }
        fn prompt_multiline(&self, text: &str) -> Result<String> {
            self.0.prompt_multiline(text)
        }
        fn select(&self, title: &str, options: &[String]) -> Result<usize> {
            self.0.select(title, options)
        }
        fn confirm(&self, text: &str, default: bool) -> Result<bool> {
            self.0.confirm(text, default)
        }
        fn print(&self, renderable: Renderable) {
            self.0.print(renderable);
        }
        fn print_error(&self, err: &ConsoleError) {
            self.0.print_error(err);
        }
    }
    let io = PromptOnly(ScriptedIo::new(["help", ScriptedIo::CTRL_C]));
    assert_eq!(
        io.read_command("r2> ").unwrap(),
        CommandInput::Line("help".into())
    );
    assert_eq!(io.read_command("r2> ").unwrap(), CommandInput::Interrupted);
    assert_eq!(io.0.prompts(), ["r2> ", "r2> "]); // shown verbatim, no ": " appended
}

fn one_attr_template() -> KeyTemplate {
    KeyTemplate::new(vec![TemplateAttr::new(
        "CKA_TOKEN",
        AttrKind::Bool,
        AttrValue::Bool(true),
    )])
}

/// c2 test_io_protocols: the identity editor returns the template unchanged.
#[test]
fn identity_editor_returns_the_template() {
    let template = one_attr_template();
    let editor: &dyn TemplateEditor = &IdentityTemplateEditor;
    assert_eq!(
        editor.edit(template.clone(), "Edit template").unwrap(),
        template
    );
}

#[test]
fn recording_editor_records_and_responds() {
    let editor = RecordingEditor::new();
    let template = one_attr_template();
    assert_eq!(editor.edit(template.clone(), "first").unwrap(), template);
    assert_eq!(editor.titles(), ["first"]);
    assert_eq!(editor.templates(), std::slice::from_ref(&template));

    let disabling = RecordingEditor::with(|mut template| {
        template.attrs[0].enabled = false;
        Ok(template)
    });
    let edited = disabling.edit(template.clone(), "second").unwrap();
    assert!(!edited.attrs[0].enabled);
    assert_eq!(disabling.templates(), std::slice::from_ref(&template)); // records what it received

    let cancelling =
        RecordingEditor::with(|_| Err(ConsoleError::user_abort("template edit cancelled")));
    let err = cancelling.edit(template, "third").unwrap_err();
    assert_eq!(err.message, "template edit cancelled");
    assert_eq!(cancelling.titles(), ["third"]);
}

/// The lock is released on drop and survives poisoning (a panic while held).
#[test]
fn global_state_lock_recovers_from_poison() {
    let poisoned = catch_unwind(|| {
        let _guard = global_state_lock();
        panic!("poison the lock");
    });
    assert!(poisoned.is_err());
    let guard = global_state_lock();
    drop(guard);
    let _again = global_state_lock();
}
