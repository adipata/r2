// LineIo unit tests over a scripted LineReader (spec §4.9.1/§4.9.7) — the port of c2
// tests/unit/console/test_io.py (R7). c2 drove PromptToolkitIO through prompt_toolkit pipe
// input ("\x03" = Ctrl-C, a closed pipe = EOF); r2 keeps the prompt logic editor-agnostic in
// `LineIo<R: LineReader>`, so the same flows run over a reader yielding Line / Interrupted /
// Eof. Output is captured from the sink (Plain style, 100 columns, like c2's
// `Console(force_terminal=False, width=100)`).
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::ColorMode;
use r2_core::error::{ConsoleError, ErrorKind};
use r2_core::io::{CommandInput, ConsoleIo, Renderable, busy_with};
use r2_core::params::{ParamKind, ParamSpec, ParamValue};
use r2_core::runtime::spinner_active;
use r2_ops::ParamResolver;
use r2_provider::ProviderRegistry;
use reedline::{History, HistoryItem, SearchDirection, SearchQuery};
use secrecy::{ExposeSecret, SecretString};

use crate::io::line::{Sink, SinkTarget, WidthRule, choices_for, console_width};
use crate::io::{
    LineIo, LineReader, ReadOutcome, SecretFilteringHistory, SecretRead, SinkStyle, is_secret_line,
    resolve_color,
};

/// One scripted read.
#[derive(Clone, Debug)]
pub(crate) enum Step {
    Line(String),
    CtrlC,
    Eof,
    Fail,
}

pub(crate) fn line(text: &str) -> Step {
    Step::Line(text.to_owned())
}

/// What the reader saw: (kind, prompt, choices).
pub(crate) type Seen = Rc<RefCell<Vec<(&'static str, String, Vec<String>)>>>;

/// The pipe-input double: an exhausted script reads as EOF (c2: a closed pipe).
pub(crate) struct ScriptedReader {
    steps: VecDeque<Step>,
    seen: Seen,
}

impl ScriptedReader {
    fn next(&mut self, kind: &'static str, prompt: &str, choices: &[String]) -> Step {
        self.seen
            .borrow_mut()
            .push((kind, prompt.to_owned(), choices.to_vec()));
        self.steps.pop_front().unwrap_or(Step::Eof)
    }
    fn outcome(step: Step) -> io::Result<ReadOutcome> {
        match step {
            Step::Line(text) => Ok(ReadOutcome::Line(text)),
            Step::CtrlC => Ok(ReadOutcome::Interrupted),
            Step::Eof => Ok(ReadOutcome::Eof),
            Step::Fail => Err(io::Error::from_raw_os_error(5)),
        }
    }
}

impl LineReader for ScriptedReader {
    fn read_command(&mut self, prompt: &str) -> io::Result<ReadOutcome> {
        let step = self.next("command", prompt, &[]);
        Self::outcome(step)
    }
    fn read_param(&mut self, prompt: &str, choices: &[String]) -> io::Result<ReadOutcome> {
        let step = self.next("param", prompt, choices);
        Self::outcome(step)
    }
    fn read_secret(&mut self, prompt: &str) -> io::Result<SecretRead> {
        match self.next("secret", prompt, &[]) {
            Step::Line(text) => Ok(SecretRead::Secret(SecretString::from(text))),
            Step::CtrlC => Ok(SecretRead::Interrupted),
            Step::Eof => Ok(SecretRead::Eof),
            Step::Fail => Err(io::Error::from_raw_os_error(5)),
        }
    }
}

/// A LineIo over a scripted reader, its captured output and the reader's log.
pub(crate) struct Harness {
    pub(crate) io: Rc<LineIo<ScriptedReader>>,
    pub(crate) out: Rc<RefCell<Vec<u8>>>,
    pub(crate) seen: Seen,
}

impl Harness {
    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.out.borrow().clone()).unwrap()
    }
    fn prompts(&self) -> Vec<String> {
        self.seen
            .borrow()
            .iter()
            .map(|(_, p, _)| p.clone())
            .collect()
    }
}

pub(crate) fn harness_with(steps: Vec<Step>, style: SinkStyle) -> Harness {
    let out = Rc::new(RefCell::new(Vec::new()));
    let seen: Seen = Rc::new(RefCell::new(Vec::new()));
    let reader = ScriptedReader {
        steps: steps.into(),
        seen: Rc::clone(&seen),
    };
    let sink = Sink {
        style,
        target: SinkTarget::Capture(Rc::clone(&out)),
        width: WidthRule::Fixed(100),
    };
    Harness {
        io: Rc::new(LineIo::new(reader, sink, 2, 32, false)),
        out,
        seen,
    }
}

pub(crate) fn harness(steps: Vec<Step>) -> Harness {
    harness_with(steps, SinkStyle::Plain)
}

fn spec() -> ParamSpec {
    ParamSpec::new("p", ParamKind::Str, "Value")
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}

#[test]
fn test_prompt_returns_typed_line() {
    let h = harness(vec![line("sha256")]);
    assert_eq!(h.io.prompt(&spec()).unwrap(), "sha256");
    assert_eq!(h.prompts(), ["Value: "]);
}

#[test]
fn test_prompt_ctrl_c_raises_user_abort() {
    let h = harness(vec![Step::CtrlC]);
    let err = h.io.prompt(&spec()).unwrap_err();
    assert!(err.kind.is_user_abort());
    assert_eq!(err.message, "aborted while entering 'p'");
}

#[test]
fn test_prompt_eof_raises_user_abort() {
    let h = harness(vec![]);
    let err = h.io.prompt(&spec()).unwrap_err();
    assert!(err.kind.is_user_abort());
    assert_eq!(err.message, "aborted while entering 'p'");
}

#[test]
fn test_prompt_secret_returns_text() {
    let h = harness(vec![line("hunter2")]);
    assert_eq!(
        h.io.prompt_secret("PIN").unwrap().expose_secret(),
        "hunter2"
    );
    assert_eq!(h.seen.borrow()[0].0, "secret");
    assert_eq!(h.prompts(), ["PIN: "]);
    // never echoed through the sink
    assert!(!h.text().contains("hunter2"));
    for step in [Step::CtrlC, Step::Eof] {
        let h = harness(vec![step]);
        let err = h.io.prompt_secret("PIN").unwrap_err();
        assert_eq!(err, ConsoleError::user_abort("aborted secret input"));
    }
}

#[test]
fn test_prompt_multiline_until_empty_line() {
    let h = harness(vec![line("line one"), line("line two"), line("")]);
    assert_eq!(
        h.io.prompt_multiline("Paste data").unwrap(),
        "line one\nline two"
    );
    assert_eq!(h.text(), "Paste data (finish with an empty line)\n");
    assert_eq!(h.prompts(), ["| ", "| ", "| "]);
}

#[test]
fn test_prompt_multiline_eof_ends_paste() {
    let h = harness(vec![line("only")]);
    assert_eq!(h.io.prompt_multiline("Paste data").unwrap(), "only");
    // Ctrl-C aborts the paste
    let h = harness(vec![line("x"), Step::CtrlC]);
    assert_eq!(
        h.io.prompt_multiline("Paste data").unwrap_err(),
        ConsoleError::user_abort("aborted multiline input")
    );
    // a bracketed paste arrives as ONE answer (newlines and blank lines included)
    let h = harness(vec![line("a\n\nb"), line("")]);
    assert_eq!(h.io.prompt_multiline("Paste data").unwrap(), "a\n\nb");
}

#[test]
fn test_select_by_number_is_one_based() {
    let h = harness(vec![line("2")]);
    assert_eq!(
        h.io.select("mechanism", &strings(&["gcm", "cbc", "ctr"]))
            .unwrap(),
        1
    );
    assert!(h.text().contains("gcm")); // the pick list was rendered
    assert_eq!(h.prompts(), ["Select [1-3]: "]);
    let text = h.text();
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].contains('#') && lines[0].contains("mechanism"));
    assert!(text.contains("1   gcm") || text.contains("1  gcm"));
}

#[test]
fn test_select_by_option_text() {
    let h = harness(vec![line("ctr")]);
    assert_eq!(
        h.io.select("mechanism", &strings(&["gcm", "cbc", "ctr"]))
            .unwrap(),
        2
    );
}

#[test]
fn test_select_reprompts_on_invalid() {
    let h = harness(vec![line("9"), line("x"), line("1")]);
    assert_eq!(
        h.io.select("mechanism", &strings(&["gcm", "cbc"])).unwrap(),
        0
    );
    let text = h.text();
    assert!(text.contains("invalid choice"));
    assert!(text.contains("invalid choice '9' — enter 1-2 or the option text"));
    assert!(text.contains("invalid choice 'x' — enter 1-2 or the option text"));
}

#[test]
fn select_answer_rules_follow_c2() {
    // text wins over number; "02" is a number; "+2", "1_0", "-0", " 2 " (stripped → "2")
    let options = strings(&["a", "2", "c"]);
    let h = harness(vec![line("2")]);
    assert_eq!(h.io.select("t", &options).unwrap(), 1); // option "2" by text
    let h = harness(vec![line(" 03 ")]);
    assert_eq!(h.io.select("t", &options).unwrap(), 2);
    let h = harness(vec![
        line("+2"),
        line("1_0"),
        line("-0"),
        line("²"),
        line("1"),
    ]);
    assert_eq!(h.io.select("t", &options).unwrap(), 0);
    let text = h.text();
    for bad in ["'+2'", "'1_0'", "'-0'", "'²'"] {
        assert!(
            text.contains(&format!("invalid choice {bad} — enter 1-3")),
            "{bad}"
        );
    }
    let h = harness(vec![line("99999999999999999999999"), Step::Eof]);
    assert_eq!(
        h.io.select("t", &options).unwrap_err(),
        ConsoleError::user_abort("selection aborted")
    );
}

#[test]
fn test_select_empty_options_raises() {
    let h = harness(vec![]);
    let err = h.io.select("nothing", &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(err.message, "nothing to select for: nothing");
    assert!(h.seen.borrow().is_empty());
}

#[test]
fn test_confirm_empty_answer_picks_default() {
    let h = harness(vec![line("")]);
    assert!(h.io.confirm("Proceed?", true).unwrap());
    assert_eq!(h.prompts(), ["Proceed? [Y/n] "]);
    let h = harness(vec![line("")]);
    assert!(!h.io.confirm("Proceed?", false).unwrap());
    assert_eq!(h.prompts(), ["Proceed? [y/N] "]);
}

#[test]
fn test_confirm_yes_no_and_reprompt() {
    let h = harness(vec![line("maybe"), line("YES")]);
    assert!(h.io.confirm("Proceed?", false).unwrap());
    assert!(h.text().contains("please answer y or n"));
    let h = harness(vec![line("n")]);
    assert!(!h.io.confirm("Proceed?", true).unwrap());
    let h = harness(vec![line(" y ")]);
    assert!(h.io.confirm("Proceed?", false).unwrap());
}

#[test]
fn test_confirm_ctrl_c_raises_user_abort() {
    for step in [Step::CtrlC, Step::Eof] {
        let h = harness(vec![step]);
        assert_eq!(
            h.io.confirm("Proceed?", false).unwrap_err(),
            ConsoleError::user_abort("confirmation aborted")
        );
    }
}

#[test]
fn test_print_error_renders_red_panel_text() {
    let h = harness(vec![]);
    h.io.print_error(&ConsoleError::generic("it broke").with_hint("fix it"));
    let text = h.text();
    assert!(text.contains("it broke"));
    assert!(text.contains("hint: fix it"));
    assert!(text.contains("╭─ error "));
    // Full style carries the panel's SGR (red border, bold red message)
    let h = harness_with(vec![], SinkStyle::Full);
    h.io.print_error(&ConsoleError::generic("it broke"));
    assert!(h.text().contains("\u{1b}["));
    assert!(!h.text().contains("hint:")); // an empty hint is none
}

#[test]
fn test_read_command_reads_a_raw_line() {
    let h = harness(vec![line("help config")]);
    assert_eq!(
        h.io.read_command("r2> ").unwrap(),
        CommandInput::Line("help config".to_owned())
    );
    assert_eq!(h.seen.borrow()[0].0, "command");
    assert_eq!(h.prompts(), ["r2> "]); // verbatim, never "r2> : "
    let h = harness(vec![Step::CtrlC]);
    assert_eq!(
        h.io.read_command("r2> ").unwrap(),
        CommandInput::Interrupted
    );
}

#[test]
fn test_read_command_propagates_eof() {
    let h = harness(vec![]);
    assert_eq!(h.io.read_command("r2> ").unwrap(), CommandInput::Eof);
}

#[test]
fn reader_errors_become_console_errors() {
    let h = harness(vec![Step::Fail]);
    let err = h.io.read_command("r2> ").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(err.message, "cannot read input: Input/output error");
    let h = harness(vec![Step::Fail]);
    assert!(h.io.prompt(&spec()).is_err());
}

#[test]
fn test_completer_for_enum_offers_choices() {
    let enum_spec = ParamSpec::new("hash", ParamKind::Enum, "Hash").choices(&["sha1", "sha256"]);
    assert_eq!(choices_for(&enum_spec), ["sha1", "sha256"]);
    // the choices reach the reader with the prompt
    let h = harness(vec![line("sha256")]);
    assert_eq!(h.io.prompt(&enum_spec).unwrap(), "sha256");
    assert_eq!(
        h.seen.borrow()[0],
        ("param", "Hash: ".to_owned(), strings(&["sha1", "sha256"]))
    );
}

#[test]
fn test_completer_for_bool_and_plain_kinds() {
    let words = choices_for(&ParamSpec::new("b", ParamKind::Bool, "B"));
    assert!(words.contains(&"yes".to_owned()));
    assert_eq!(words, ["true", "false", "yes", "no", "on", "off"]);
    assert!(choices_for(&ParamSpec::new("s", ParamKind::Str, "S")).is_empty());
    assert!(choices_for(&ParamSpec::new("d", ParamKind::Bytes, "D")).is_empty());
    // no completer leaks into later prompts: every read carries its own choices
    let h = harness(vec![line("sha1"), line("y"), line("x")]);
    let enum_spec = ParamSpec::new("hash", ParamKind::Enum, "Hash").choices(&["sha1"]);
    h.io.prompt(&enum_spec).unwrap();
    h.io.confirm("Proceed?", false).unwrap();
    h.io.prompt(&spec()).unwrap();
    let choices: Vec<Vec<String>> = h.seen.borrow().iter().map(|s| s.2.clone()).collect();
    assert_eq!(choices, [strings(&["sha1"]), vec![], vec![]]);
}

#[test]
fn test_enum_prompt_reprompts_and_receives_choices() {
    // c2 test_params.py: the full ParamSpec (with choices) reaches the prompt; r2 asserts it
    // at the line reader, through ParamResolver + LineIo.
    let h = harness(vec![line("nope"), line("aa")]);
    let providers = ProviderRegistry::new();
    let param = ParamSpec::new("e", ParamKind::Enum, "Pick one").choices(&["aa", "bb"]);
    let resolver = ParamResolver::new(h.io.as_ref(), &providers);
    assert_eq!(
        resolver.parse_value(&param, "aa").unwrap(),
        ParamValue::Enum("aa".to_owned())
    );
    let spec = r2_ops::OperationSpec {
        id: "test.op".to_owned(),
        verb: r2_core::params::Verb::Encrypt,
        algorithm: r2_core::keys::KeyAlgorithm::Aes,
        key_classes: std::collections::BTreeSet::from([r2_core::keys::KeyClass::Secret]),
        mechanism: "AES-GCM".to_owned(),
        cli_name: "test".to_owned(),
        label: "test op".to_owned(),
        params: vec![param],
        provider_types: None,
        providers: None,
        curves: None,
        raw_ckm: None,
        param_struct: r2_core::params::ParamStruct::None,
    };
    let values = resolver.resolve(&spec, &IndexMap::new()).unwrap();
    assert_eq!(values["e"], ParamValue::Enum("aa".to_owned()));
    let seen = h.seen.borrow().clone();
    assert_eq!(
        seen,
        [
            ("param", "Pick one: ".to_owned(), strings(&["aa", "bb"])),
            ("param", "Pick one: ".to_owned(), strings(&["aa", "bb"])),
        ]
    );
    assert!(h.text().contains("e: invalid choice 'nope'"));
}

#[test]
fn test_history_filters_pin_and_password_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history");
    {
        let mut history = SecretFilteringHistory::open(Some(&path));
        for entry in [
            "login hsm --pin 1234",
            "export mem:k out.p12 --password secret",
            "keys mem",
        ] {
            history.save(HistoryItem::from_command_line(entry)).unwrap();
        }
        // not in the in-session list either (Up-arrow, hints)
        let all = history
            .search(SearchQuery::everything(SearchDirection::Forward, None))
            .unwrap();
        let lines: Vec<&str> = all.iter().map(|i| i.command_line.as_str()).collect();
        assert_eq!(lines, ["keys mem"]);
        history.sync().unwrap();
    }
    let stored = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(!stored.contains("1234"));
    assert!(!stored.contains("secret"));
    assert!(stored.contains("keys mem"));
    assert!(is_secret_line("x --pin"));
    assert!(is_secret_line("x --password=y"));
    assert!(!is_secret_line("load mem aes 00112233")); // §11 D8 option A (parity)
}

#[test]
fn history_save_answers_ok_and_update_never_smuggles_a_secret() {
    let mut history = SecretFilteringHistory::open(None);
    let saved = history
        .save(HistoryItem::from_command_line("login hsm --pin 1"))
        .unwrap();
    assert_eq!(saved.id, None);
    let kept = history
        .save(HistoryItem::from_command_line("keys mem"))
        .unwrap();
    let id = kept.id.unwrap();
    // (FileBackedHistory itself refuses updates; either way nothing secret gets in)
    let _ = history.update(id, &|item| HistoryItem {
        command_line: "login x --pin 9".to_owned(),
        ..item
    });
    assert_eq!(history.load(id).unwrap().command_line, "keys mem");
    // multi-line commands are one logical entry with reedline's escaping (§11 D7)
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("h");
    {
        let mut history = SecretFilteringHistory::open(Some(&path));
        history
            .save(HistoryItem::from_command_line("load mem aes \"x\ny\""))
            .unwrap();
        history.sync().unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "load mem aes \"x<\\n>y\"\n"
    );
}

#[test]
fn test_bad_history_path_falls_back_to_memory() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, "file, not a directory").unwrap();
    let mut history = SecretFilteringHistory::open(Some(&blocker.join("sub").join("history")));
    history.save(HistoryItem::from_command_line("ok")).unwrap();
    assert_eq!(
        history
            .count(SearchQuery::everything(SearchDirection::Forward, None))
            .unwrap(),
        1
    );
    assert!(history.sync().is_ok());
    assert!(!blocker.join("sub").exists());
    // a directory as the history file also falls back
    let mut history = SecretFilteringHistory::open(Some(dir.path()));
    history.save(HistoryItem::from_command_line("ok")).unwrap();
}

#[test]
fn test_prompttoolkitio_print_does_not_eat_markup_lookalikes() {
    // test_l13_hardening: printed text is data, never markup
    let h = harness(vec![]);
    h.io.print(Renderable::Text(
        "usage: key info <provider>:<label>[#<id-hex>]".to_owned(),
    ));
    assert!(h.text().contains("[#<id-hex>]"));
    assert_eq!(h.text(), "usage: key info <provider>:<label>[#<id-hex>]\n");
}

#[test]
fn sink_styles_choose_the_rendering() {
    let r = Renderable::Styled(vec![vec![r2_core::io::Span {
        text: "x".to_owned(),
        tone: r2_core::io::Tone::Error,
    }]]);
    let full = harness_with(vec![], SinkStyle::Full);
    full.io.print(r.clone());
    assert!(full.text().contains("\u{1b}[1;31m") || full.text().contains("31"));
    let no_color = harness_with(vec![], SinkStyle::NoColor);
    no_color.io.print(r.clone());
    assert!(no_color.text().contains("\u{1b}[1m"));
    assert!(!no_color.text().contains("31"));
    let plain = harness_with(vec![], SinkStyle::Plain);
    plain.io.print(r);
    assert_eq!(plain.text(), "x\n");
}

#[test]
fn clear_writes_the_sequence_unless_plain() {
    let plain = harness(vec![]);
    plain.io.clear();
    assert_eq!(plain.text(), "");
    let full = harness_with(vec![], SinkStyle::Full);
    full.io.clear();
    assert_eq!(full.text(), "\u{1b}[2J\u{1b}[H");
    let no_color = harness_with(vec![], SinkStyle::NoColor);
    no_color.io.clear();
    assert_eq!(no_color.text(), "\u{1b}[2J\u{1b}[H");
}

#[test]
fn busy_runs_the_closure_once_without_a_spinner() {
    let _lock = r2_testkit::global_state_lock();
    let h = harness(vec![]);
    let mut runs = 0;
    let value = busy_with(h.io.as_ref(), "waiting", || {
        runs += 1;
        // prints and nested busy sections inside re-enter the IO
        h.io.print(Renderable::Text("inside".to_owned()));
        busy_with(h.io.as_ref(), "nested", || 7)
    });
    assert_eq!((value, runs), (7, 1));
    assert_eq!(h.text(), "inside\n");
    assert!(!spinner_active());
}

fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |key: &str| map.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

#[test]
fn resolve_color_reproduces_richs_decision() {
    use ColorMode::{Always, Auto, Never};
    use SinkStyle::{Full, NoColor, Plain};
    type Case<'a> = (ColorMode, bool, Vec<(&'a str, &'a str)>, SinkStyle);
    let cases: Vec<Case<'_>> = vec![
        (Auto, true, vec![], Full),
        (Auto, false, vec![], Plain),
        (Auto, true, vec![("NO_COLOR", "1")], NoColor),
        (Auto, true, vec![("NO_COLOR", "")], Full),
        (Auto, false, vec![("FORCE_COLOR", "1")], Full),
        (Auto, false, vec![("FORCE_COLOR", "")], Plain),
        (Auto, true, vec![("FORCE_COLOR", "")], Plain),
        (
            Auto,
            true,
            vec![("TTY_COMPATIBLE", "0"), ("FORCE_COLOR", "1")],
            Plain,
        ),
        (Auto, false, vec![("TTY_COMPATIBLE", "1")], Full),
        (
            Auto,
            false,
            vec![("TTY_COMPATIBLE", "2"), ("FORCE_COLOR", "1")],
            Full,
        ),
        (Auto, false, vec![("CLICOLOR_FORCE", "1")], Plain),
        (Auto, true, vec![("CLICOLOR", "0")], Full),
        (Always, false, vec![], Full),
        (Always, false, vec![("NO_COLOR", "1")], NoColor),
        (Always, false, vec![("TERM", "dumb")], Plain),
        (Always, true, vec![("TERM", "Unknown")], Plain),
        (Auto, true, vec![("TERM", "DUMB")], Plain),
        (Never, true, vec![], NoColor),
        (Never, false, vec![], Plain),
        (Never, false, vec![("FORCE_COLOR", "1")], NoColor),
        (Never, true, vec![("TERM", "dumb")], Plain),
    ];
    for (ui, tty, env, expected) in cases {
        assert_eq!(
            resolve_color(ui, tty, &env_of(&env)),
            expected,
            "{ui:?} tty={tty} {env:?}"
        );
    }
}

#[test]
fn console_width_is_richs_size_rule() {
    // all cases avoid the real terminal (COLUMNS or the dumb rule decides)
    assert_eq!(console_width(false, &env_of(&[("COLUMNS", "50")])), 50);
    assert_eq!(console_width(true, &env_of(&[("COLUMNS", "120")])), 120);
    assert_eq!(
        console_width(true, &env_of(&[("TERM", "dumb"), ("COLUMNS", "50")])),
        80
    );
    assert_eq!(
        console_width(
            true,
            &env_of(&[("TERM", "dumb"), ("COLUMNS", "50"), ("LINES", "9")])
        ),
        50
    );
    assert_eq!(
        console_width(false, &env_of(&[("TERM", "dumb"), ("COLUMNS", "50")])),
        50
    );
    assert_eq!(console_width(true, &env_of(&[("TERM", "unknown")])), 80);
    assert_eq!(
        console_width(false, &env_of(&[("COLUMNS", "0"), ("LINES", "1")])),
        80
    );
}

#[test]
fn test_prompt_secret_does_not_mask_later_prompts() {
    // c2 regression (sticky prompt_toolkit kwargs): a PIN prompt must not leave later
    // prompts masked — the next prompt is an ordinary (param) read returning the text
    let h = harness(vec![line("hunter2"), line("3=0xc0fe")]);
    assert_eq!(
        h.io.prompt_secret("PIN").unwrap().expose_secret(),
        "hunter2"
    );
    assert_eq!(h.io.prompt(&spec()).unwrap(), "3=0xc0fe");
    let kinds: Vec<&str> = h.seen.borrow().iter().map(|s| s.0).collect();
    assert_eq!(kinds, ["secret", "param"]);
}

#[test]
fn test_param_completer_does_not_leak_to_later_prompts() {
    // c2 regression: an ENUM completer stuck to the param session; r2 passes the choices
    // per read, so the confirm after it carries none
    let h = harness(vec![line("sha256"), line("y")]);
    let enum_spec = ParamSpec::new("hash", ParamKind::Enum, "Hash").choices(&["sha1", "sha256"]);
    h.io.prompt(&enum_spec).unwrap();
    assert!(h.io.confirm("Proceed?", false).unwrap());
    let choices: Vec<Vec<String>> = h.seen.borrow().iter().map(|s| s.2.clone()).collect();
    assert_eq!(choices, [strings(&["sha1", "sha256"]), vec![]]);
}

// -- PlainReader: logical history entries, stale interrupts (R7 fix round 1) ---------

fn history_entries(path: &std::path::Path) -> Vec<String> {
    let history = SecretFilteringHistory::open(Some(path));
    history
        .search(SearchQuery::everything(SearchDirection::Forward, None))
        .unwrap()
        .into_iter()
        .map(|item| item.command_line)
        .collect()
}

#[test]
fn plain_reader_stores_one_logical_history_entry_per_command() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history");
    let mut reader =
        crate::io::PlainReader::new(false, Some(SecretFilteringHistory::open(Some(&path))));
    let mut input =
        io::Cursor::new(b"help 'a\nb'\nconfig show 'x\n\ny' --pin 1\nhelp \"never\n".to_vec());
    let mut lines = Vec::new();
    loop {
        match reader.read_command_from("r2> ", &mut input).unwrap() {
            ReadOutcome::Line(line) => lines.push(line),
            ReadOutcome::Eof => break,
            ReadOutcome::Interrupted => panic!("no interrupt"),
        }
    }
    // the REPL still sees the physical lines; history holds the joined command once, the
    // secret one not at all, and an unterminated quote at EOF never
    assert_eq!(lines.len(), 6);
    assert_eq!(history_entries(&path), ["help 'a\nb'"]);
    let file = std::fs::read_to_string(&path).unwrap();
    assert_eq!(file, "help 'a<\\n>b'\n");
}

#[test]
fn plain_reader_on_a_terminal_ignores_a_stale_interrupt() {
    // rpassword's raise(SIGINT) or a Ctrl-C pressed while a command ran sets the flag
    // before the next command read; that read must still return the typed command
    let _lock = r2_testkit::global_state_lock();
    let mut reader = crate::io::PlainReader::new(true, None);
    r2_core::runtime::request_interrupt();
    let mut input = io::Cursor::new(b"help\n".to_vec());
    let outcome = reader.read_command_from("r2> ", &mut input).unwrap();
    assert!(
        matches!(outcome, ReadOutcome::Line(ref l) if l == "help"),
        "{outcome:?}"
    );
    r2_core::runtime::reset_interrupt();
}

// -- PlainReader: SIGINT with piped stdin (R7 fix round 2) ---------------------------

/// A piped stdin whose read "receives" a SIGINT while it blocks (the ctrlc handler's flag
/// is set before the data arrives).
struct InterruptedRead(io::Cursor<Vec<u8>>);
impl io::Read for InterruptedRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
impl io::BufRead for InterruptedRead {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        r2_core::runtime::request_interrupt();
        self.0.fill_buf()
    }
    fn consume(&mut self, amount: usize) {
        self.0.consume(amount);
    }
}

#[test]
fn piped_sigint_during_a_read_aborts_it_and_keeps_the_line() {
    // c2: KeyboardInterrupt at the prompt → "Aborted.", the piped line is read next
    let _lock = r2_testkit::global_state_lock();
    r2_core::runtime::reset_interrupt();
    let mut reader = crate::io::PlainReader::new(false, None);
    let mut input = InterruptedRead(io::Cursor::new(b"config path\nhelp\n".to_vec()));
    let first = reader.read_command_from("r2> ", &mut input).unwrap();
    assert!(matches!(first, ReadOutcome::Interrupted), "{first:?}");
    assert!(!r2_core::runtime::interrupted());
    // the stashed line comes back first, then stdin continues (no further SIGINT)
    let mut rest = io::Cursor::new(b"help\n".to_vec());
    let second = reader.read_command_from("r2> ", &mut rest).unwrap();
    assert!(
        matches!(second, ReadOutcome::Line(ref l) if l == "config path"),
        "{second:?}"
    );
    let third = reader.read_command_from("r2> ", &mut rest).unwrap();
    assert!(
        matches!(third, ReadOutcome::Line(ref l) if l == "help"),
        "{third:?}"
    );
}

#[test]
fn piped_sigint_before_a_read_aborts_it_without_consuming_input() {
    // a SIGINT that arrived while a command ran (or before the read) aborts the next read
    let _lock = r2_testkit::global_state_lock();
    let mut reader = crate::io::PlainReader::new(false, None);
    let mut input = io::Cursor::new(b"answer\n".to_vec());
    r2_core::runtime::request_interrupt();
    let first = reader.read_command_from("r2> ", &mut input).unwrap();
    assert!(matches!(first, ReadOutcome::Interrupted), "{first:?}");
    let second = reader.read_command_from("r2> ", &mut input).unwrap();
    assert!(
        matches!(second, ReadOutcome::Line(ref l) if l == "answer"),
        "{second:?}"
    );
}
