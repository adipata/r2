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

use crossterm::event as ct;
use r2_core::io::Key;

use super::assist::{BridgeCompleter, BridgeHighlighter, plain_text};
use super::history::SecretFilteringHistory;
use super::line::{LineIo, LineReader, ReadOutcome, SecretRead};
use super::plain::{PlainReader, rpassword_secret};
use super::session::{TermOp, TerminalDriver};
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
                Err(err) => self.fall_back(&err),
            }
        }
        f(&mut self.plain)
    }

    /// Raw mode off, the one warning, plain reads from now on (a no-op once degraded).
    fn fall_back(&mut self, err: &io::Error) {
        if self.primary.take().is_none() {
            return;
        }
        let _ = crossterm::terminal::disable_raw_mode();
        // one of the two sanctioned stderr warnings (§4.1.3)
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "warning: line editor unavailable ({err}); continuing with plain input"
        );
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
        // rpassword is no line-editor failure: its error is returned as is and never
        // degrades the session (the plain fallback would call rpassword again anyway)
        match self.primary.as_mut() {
            Some(primary) => primary.read_secret(prompt),
            None => self.plain.read_secret(prompt),
        }
    }
    fn clear_screen(&mut self) {
        if let Some(primary) = self.primary.as_mut() {
            primary.clear_screen();
        }
    }
    fn terminal_driver(&mut self) -> Option<Box<dyn TerminalDriver>> {
        self.primary
            .as_ref()
            .map(|_| Box::new(CrosstermDriver { raw: false }) as Box<dyn TerminalDriver>)
    }
    fn degrade(&mut self, err: &io::Error) {
        self.fall_back(err);
    }
}
pub type TerminalIo = LineIo<DegradingReader>;

/// The crossterm side of an interactive key session (§11 D34): raw mode, no auto-wrap and
/// bracketed paste while it is open; keys come from crossterm's reader on the controlling
/// terminal (`use-dev-tty`), the one reedline uses, so nothing typed ahead is lost between
/// the two.
pub(crate) struct CrosstermDriver {
    raw: bool,
}

impl TerminalDriver for CrosstermDriver {
    fn enter(&mut self) -> io::Result<()> {
        crossterm::terminal::enable_raw_mode()?;
        self.raw = true;
        let mut out = io::stdout().lock();
        crossterm::execute!(out, crossterm::terminal::DisableLineWrap)?;
        // legacy Windows consoles have no bracketed paste (pastes arrive as keystrokes)
        let _ = crossterm::execute!(out, crossterm::event::EnableBracketedPaste);
        Ok(())
    }
    fn size(&self) -> io::Result<(u16, u16)> {
        crossterm::terminal::size()
    }
    fn read_key(&mut self) -> io::Result<Key> {
        loop {
            if let Some(key) = key_of(crossterm::event::read()?) {
                return Ok(key);
            }
        }
    }
    fn apply(&mut self, ops: &[TermOp]) -> io::Result<()> {
        use crossterm::cursor::{Hide, MoveTo, MoveToColumn, MoveUp, Show};
        use crossterm::style::Print;
        use crossterm::terminal::{
            BeginSynchronizedUpdate, Clear, ClearType, EndSynchronizedUpdate,
        };
        let mut out = io::stdout().lock();
        crossterm::queue!(out, BeginSynchronizedUpdate)?;
        for op in ops {
            match op {
                TermOp::Up(n) => crossterm::queue!(out, MoveUp(*n))?,
                TermOp::Column(column) => crossterm::queue!(out, MoveToColumn(*column))?,
                TermOp::ClearLineRight => crossterm::queue!(out, Clear(ClearType::UntilNewLine))?,
                TermOp::ClearDown => crossterm::queue!(out, Clear(ClearType::FromCursorDown))?,
                TermOp::ClearScreen => crossterm::queue!(out, Clear(ClearType::All), MoveTo(0, 0))?,
                TermOp::Text(text) => crossterm::queue!(out, Print(text.as_str()))?,
                TermOp::Newline => crossterm::queue!(out, Print("\r\n"))?,
                TermOp::ShowCursor => crossterm::queue!(out, Show)?,
                TermOp::HideCursor => crossterm::queue!(out, Hide)?,
            }
        }
        crossterm::queue!(out, EndSynchronizedUpdate)?;
        out.flush()
    }
    fn leave(&mut self) {
        let mut out = io::stdout().lock();
        let _ = crossterm::execute!(
            out,
            crossterm::event::DisableBracketedPaste,
            crossterm::terminal::EnableLineWrap,
            crossterm::cursor::Show
        );
        if self.raw {
            self.raw = false;
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

/// The session key of one crossterm event; None for events the session ignores (key
/// releases — Windows reports them —, Alt combinations, mouse and focus events). Ctrl+Alt
/// with a character is AltGr on Windows: the character itself.
pub(crate) fn key_of(event: ct::Event) -> Option<Key> {
    let ct::KeyEvent {
        code,
        modifiers,
        kind,
        ..
    } = match event {
        ct::Event::Key(key) => key,
        ct::Event::Paste(text) => return Some(Key::Paste(text)),
        ct::Event::Resize(..) => return Some(Key::Resize),
        _ => return None,
    };
    if kind == ct::KeyEventKind::Release {
        return None;
    }
    let ctrl = modifiers.contains(ct::KeyModifiers::CONTROL);
    let alt = modifiers.contains(ct::KeyModifiers::ALT);
    Some(match code {
        ct::KeyCode::Char(c) if ctrl && !alt => Key::Ctrl(c.to_ascii_lowercase()),
        ct::KeyCode::Char(_) if alt && !ctrl => return None,
        ct::KeyCode::Char(c) => Key::Char(c),
        ct::KeyCode::Enter => Key::Enter,
        ct::KeyCode::Esc => Key::Esc,
        ct::KeyCode::Tab => Key::Tab,
        ct::KeyCode::BackTab => Key::BackTab,
        ct::KeyCode::Backspace => Key::Backspace,
        ct::KeyCode::Delete => Key::Delete,
        ct::KeyCode::Insert => Key::Insert,
        ct::KeyCode::Up => Key::Up,
        ct::KeyCode::Down => Key::Down,
        ct::KeyCode::Left => Key::Left,
        ct::KeyCode::Right => Key::Right,
        ct::KeyCode::Home => Key::Home,
        ct::KeyCode::End => Key::End,
        ct::KeyCode::PageUp => Key::PageUp,
        ct::KeyCode::PageDown => Key::PageDown,
        _ => return None,
    })
}
