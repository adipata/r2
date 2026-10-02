// TerminalIo (spec §4.9.7, §5.1; owner R7): reedline 0.49 command and answer editors +
// rpassword secrets, behind a DegradingReader that falls back to plain reads for good on the
// first terminal error.
use std::borrow::Cow;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use nu_ansi_term::Style;
use reedline::{
    Color, DefaultHinter, Emacs, FileBackedHistory, IdeMenu, KeyCode, KeyModifiers, MenuBuilder,
    Prompt, PromptEditMode, PromptHistorySearch, PromptHistorySearchStatus, Reedline,
    ReedlineEvent, ReedlineMenu, Signal, Span, StyledText, Suggestion, ValidationResult, Validator,
    default_emacs_keybindings,
};

use super::assist::{BridgeCompleter, BridgeHighlighter, plain_text};
use super::history::SecretFilteringHistory;
use super::line::{LineIo, LineReader, ReadOutcome, SecretRead};
use super::plain::{PlainReader, rpassword_secret};
use crate::parser::line_is_complete;
use crate::repl::CONTINUATION_PROMPT;

/// `r2> ` (or a param prompt text) with the `…> ` multiline indicator; uncoloured like c2.
struct ConsolePrompt<'a> {
    left: &'a str,
}
impl Prompt for ConsolePrompt<'_> {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.left)
    }
    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }
    fn render_prompt_indicator(&self, _mode: PromptEditMode) -> Cow<'_, str> {
        Cow::Borrowed("")
    }
    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed(CONTINUATION_PROMPT)
    }
    fn render_prompt_history_search_indicator(&self, search: PromptHistorySearch) -> Cow<'_, str> {
        let failing = if matches!(search.status, PromptHistorySearchStatus::Failing) {
            "failing "
        } else {
            ""
        };
        Cow::Owned(format!("({failing}reverse-search: {}) ", search.term))
    }
    fn get_prompt_color(&self) -> Color {
        Color::Reset
    }
    fn get_prompt_multiline_color(&self) -> nu_ansi_term::Color {
        nu_ansi_term::Color::Default
    }
    fn get_indicator_color(&self) -> Color {
        Color::Reset
    }
}

/// Multi-line through the validator: Incomplete exactly while an unterminated quote keeps
/// the buffer open, so Enter inserts a newline and reedline draws `…> ` (typed input,
/// bracketed AND un-bracketed paste).
pub(crate) struct QuoteValidator;
impl Validator for QuoteValidator {
    fn validate(&self, line: &str) -> ValidationResult {
        if line_is_complete(line) {
            ValidationResult::Complete
        } else {
            ValidationResult::Incomplete
        }
    }
}

/// Answer-prompt completer: the ENUM choices / BOOL words of the current prompt (plain
/// Strings, so a `Send` Arc<Mutex<…>> — no bridge needed).
pub(crate) struct ChoiceCompleter(pub(crate) Arc<Mutex<Vec<String>>>);
impl reedline::Completer for ChoiceCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let prefix = line.get(..pos).unwrap_or(line);
        let choices = self.0.lock().map(|c| c.clone()).unwrap_or_default();
        choices
            .into_iter()
            .filter(|choice| choice.starts_with(prefix))
            .map(|value| Suggestion {
                value,
                span: Span::new(0, pos),
                append_whitespace: false,
                ..Suggestion::default()
            })
            .collect()
    }
}

/// Answers are data: no styling (`Reedline::create()` defaults to ExampleHighlighter).
struct PlainHighlighter;
impl reedline::Highlighter for PlainHighlighter {
    fn highlight(&self, line: &str, _cursor: usize) -> StyledText {
        plain_text(line)
    }
}

fn keybindings() -> reedline::Keybindings {
    let mut bindings = default_emacs_keybindings();
    bindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_owned()),
            ReedlineEvent::MenuNext,
        ]),
    );
    bindings.add_binding(
        KeyModifiers::SHIFT,
        KeyCode::BackTab,
        ReedlineEvent::MenuPrevious,
    );
    bindings
}

fn completion_menu() -> ReedlineMenu {
    ReedlineMenu::EngineCompleter(Box::new(
        IdeMenu::default()
            .with_name("completion_menu")
            .with_marker("")
            .with_default_border(),
    ))
}

fn from_signal(signal: Signal) -> ReadOutcome {
    match signal {
        Signal::Success(line) => ReadOutcome::Line(line),
        Signal::CtrlD => ReadOutcome::Eof,
        // CtrlC and everything never enabled (HostCommand, ExternalBreak)
        _ => ReadOutcome::Interrupted,
    }
}

/// A panic inside reedline must not leave the terminal raw (the panic hook never touches
/// the terminal).
struct RawModeGuard;
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

/// The reedline primary of TerminalIo (R7-internal).
pub(crate) struct ReedlineReader {
    command: Reedline,
    answer: Reedline,
    choices: Arc<Mutex<Vec<String>>>,
}

impl ReedlineReader {
    pub(crate) fn new(history_file: Option<&Path>, ansi_colors: bool) -> Self {
        let command = Reedline::create()
            .with_history(Box::new(SecretFilteringHistory::open(history_file)))
            .with_hinter(Box::new(
                DefaultHinter::default().with_style(Style::new().fg(nu_ansi_term::Color::DarkGray)),
            ))
            .with_completer(Box::new(BridgeCompleter))
            .with_highlighter(Box::new(BridgeHighlighter))
            .with_validator(Box::new(QuoteValidator))
            .with_menu(completion_menu())
            .with_edit_mode(Box::new(Emacs::new(keybindings())))
            .with_quick_completions(true)
            .with_partial_completions(true)
            .use_bracketed_paste(true)
            .with_ansi_colors(ansi_colors);
        let choices = Arc::new(Mutex::new(Vec::new()));
        let answer = Reedline::create()
            .with_history(Box::new(FileBackedHistory::new(100).unwrap_or_default()))
            .with_completer(Box::new(ChoiceCompleter(Arc::clone(&choices))))
            .with_highlighter(Box::new(PlainHighlighter))
            .with_menu(completion_menu())
            .with_edit_mode(Box::new(Emacs::new(keybindings())))
            .with_quick_completions(true)
            .with_partial_completions(true)
            .use_bracketed_paste(true)
            .with_ansi_colors(ansi_colors);
        Self {
            command,
            answer,
            choices,
        }
    }
}

impl LineReader for ReedlineReader {
    fn read_command(&mut self, prompt: &str) -> io::Result<ReadOutcome> {
        let _raw = RawModeGuard;
        let signal = self
            .command
            .read_line(&ConsolePrompt { left: prompt })
            .map_err(io::Error::other)?;
        // reedline writes the history file only on sync(); c2 appended immediately.
        let _ = self.command.sync_history();
        Ok(from_signal(signal))
    }
    fn read_param(&mut self, prompt: &str, choices: &[String]) -> io::Result<ReadOutcome> {
        if let Ok(mut slot) = self.choices.lock() {
            *slot = choices.to_vec();
        }
        let _raw = RawModeGuard;
        let signal = self
            .answer
            .read_line(&ConsolePrompt { left: prompt })
            .map_err(io::Error::other)?;
        Ok(from_signal(signal))
    }
    fn read_secret(&mut self, prompt: &str) -> io::Result<SecretRead> {
        rpassword_secret(prompt)
    }
    fn clear_screen(&mut self) {
        let _ = self.command.clear_screen();
    }
}

/// reedline primary (R7-internal `ReedlineReader`), `PlainReader` fallback (rules below).
pub struct DegradingReader {
    primary: Option<ReedlineReader>,
    plain: PlainReader,
}

impl DegradingReader {
    pub(crate) fn new(primary: ReedlineReader, plain: PlainReader) -> Self {
        Self {
            primary: Some(primary),
            plain,
        }
    }

    /// The first terminal error disables raw mode, prints one warning and switches the
    /// session to plain reads permanently; the REPL never exits because of it.
    fn run<T>(&mut self, f: impl Fn(&mut dyn LineReader) -> io::Result<T>) -> io::Result<T> {
        if let Some(primary) = self.primary.as_mut() {
            match f(primary) {
                Ok(outcome) => return Ok(outcome),
                Err(err) => {
                    let _ = crossterm::terminal::disable_raw_mode();
                    // one of the two sanctioned stderr warnings (§4.1.3)
                    let mut stderr = io::stderr().lock();
                    let _ = writeln!(
                        stderr,
                        "\r\nwarning: line editor unavailable ({err}); continuing with plain input"
                    );
                    self.primary = None;
                }
            }
        }
        f(&mut self.plain)
    }
}

impl LineReader for DegradingReader {
    fn read_command(&mut self, prompt: &str) -> std::io::Result<super::line::ReadOutcome> {
        self.run(|reader| reader.read_command(prompt))
    }
    fn read_param(
        &mut self,
        prompt: &str,
        choices: &[String],
    ) -> std::io::Result<super::line::ReadOutcome> {
        self.run(|reader| reader.read_param(prompt, choices))
    }
    fn read_secret(&mut self, prompt: &str) -> std::io::Result<super::line::SecretRead> {
        self.run(|reader| reader.read_secret(prompt))
    }
    fn clear_screen(&mut self) {
        if let Some(primary) = self.primary.as_mut() {
            primary.clear_screen();
        }
    }
}
pub type TerminalIo = LineIo<DegradingReader>;
