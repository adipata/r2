// LineIo (spec §4.9.1/§4.9.7; owner R7) — the ONE ConsoleIo over a LineReader. Port of
// c2 `console/io.py` PromptToolkitIO's prompt/secret/multiline/select/confirm logic; the
// texts live only here. The reader seam (`LineReader`) is what TerminalIo (reedline +
// rpassword) and PlainIo (stdin lines) plug into, and what the unit tests script.
use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use r2_core::error::ConsoleError;
use r2_core::io::{CommandInput, Renderable, error_panel, table};
use r2_core::params::{ParamKind, ParamSpec};
use r2_core::render::{RenderConfig, render, render_no_color, render_plain};
use r2_core::runtime::set_spinner_active;
use r2_core::text::{os_error_text, py_isdigit, py_repr, py_strip};
use secrecy::SecretString;

use super::SinkStyle;

/// One non-secret read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    Line(String),
    Interrupted,
    Eof,
}
/// One secret read — the reader wraps the text in `SecretString` itself, so a secret never
/// crosses the seam as a plain `String` (D3).
#[derive(Debug)]
pub enum SecretRead {
    Secret(SecretString),
    Interrupted,
    Eof,
}

/// Console-internal reader seam; LineIo's unit tests drive it with a scripted reader.
pub trait LineReader {
    /// `prompt` is shown verbatim ("r2> ", "…> ").
    fn read_command(&mut self, prompt: &str) -> io::Result<ReadOutcome>;
    /// `prompt` verbatim (LineIo has appended ": " where §4.9.1 says so); `choices` feed
    /// completion (ENUM choices / BOOL words).
    fn read_param(&mut self, prompt: &str, choices: &[String]) -> io::Result<ReadOutcome>;
    fn read_secret(&mut self, prompt: &str) -> io::Result<SecretRead>;
    /// Terminal side of `clear` (reedline repaint). Default: nothing.
    fn clear_screen(&mut self) {}
}

/// c2 `_BOOL_WORDS`: the completion words of a BOOL prompt.
pub(crate) const BOOL_WORDS: [&str; 6] = ["true", "false", "yes", "no", "on", "off"];

/// Per-kind prompt completion (c2 `completer_for`): ENUM choices, BOOL words, else none.
pub(crate) fn choices_for(spec: &ParamSpec) -> Vec<String> {
    match spec.kind {
        ParamKind::Enum => spec.choices.clone().unwrap_or_default(),
        ParamKind::Bool => BOOL_WORDS.iter().map(|w| (*w).to_owned()).collect(),
        _ => Vec::new(),
    }
}

/// Where rendered output goes.
pub(crate) enum SinkTarget {
    /// The process stdout (Full/NoColor through `anstream::AutoStream` with
    /// `ColorChoice::Always`, Plain straight to stdout).
    Stdout,
    /// Tests: the bytes that would have reached stdout.
    #[cfg_attr(not(test), allow(dead_code))]
    Capture(Rc<RefCell<Vec<u8>>>),
}

/// How the render width is chosen per print.
pub(crate) enum WidthRule {
    /// rich 15's `Console.size` rule (§4.9.2); `is_terminal` = rich's decision.
    Console { is_terminal: bool },
    #[cfg_attr(not(test), allow(dead_code))]
    Fixed(usize),
}

/// The output sink: the only place output styling is decided (§4.9.7).
pub(crate) struct Sink {
    pub(crate) style: SinkStyle,
    pub(crate) target: SinkTarget,
    pub(crate) width: WidthRule,
}

impl Sink {
    pub(crate) fn width(&self) -> usize {
        match self.width {
            WidthRule::Fixed(width) => width,
            WidthRule::Console { is_terminal } => console_width(is_terminal, &|key| {
                std::env::var_os(key).map(|v| v.to_string_lossy().into_owned())
            }),
        }
    }

    /// Render per style — never filtered or stripped afterwards (§4.9.2).
    pub(crate) fn render(&self, renderable: &Renderable, cfg: &RenderConfig) -> String {
        match self.style {
            SinkStyle::Full => render(renderable, cfg),
            SinkStyle::NoColor => render_no_color(renderable, cfg),
            SinkStyle::Plain => render_plain(renderable, cfg),
        }
    }

    /// Write `text` unchanged; I/O errors on stdout are ignored (rich wrote best effort).
    pub(crate) fn write(&self, text: &str) {
        match &self.target {
            SinkTarget::Capture(buffer) => buffer.borrow_mut().extend_from_slice(text.as_bytes()),
            SinkTarget::Stdout => {
                if self.style == SinkStyle::Plain {
                    let mut out = io::stdout().lock();
                    let _ = out.write_all(text.as_bytes());
                    let _ = out.flush();
                } else {
                    let mut out =
                        anstream::AutoStream::new(io::stdout(), anstream::ColorChoice::Always);
                    let _ = out.write_all(text.as_bytes());
                    let _ = out.flush();
                }
            }
        }
    }
}

/// rich 15 `Console.size` width (§4.9.2): a terminal with TERM dumb/unknown → 80 unless both
/// `$COLUMNS` and `$LINES` are all ASCII digits; else `$COLUMNS` when all ASCII digits; else
/// the terminal's width when any of stdin/stdout/stderr is a terminal; 0 or missing → 80.
pub(crate) fn console_width(is_terminal: bool, env: &dyn Fn(&str) -> Option<String>) -> usize {
    let digits = |key: &str| {
        env(key).filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
    };
    let columns = digits("COLUMNS");
    let width = if columns.is_some() && digits("LINES").is_some() {
        columns.and_then(|c| c.parse::<usize>().ok())
    } else if is_terminal
        && env("TERM").is_some_and(|term| {
            let term = term.to_lowercase();
            term == "dumb" || term == "unknown"
        })
    {
        Some(80)
    } else if let Some(columns) = columns {
        columns.parse::<usize>().ok()
    } else {
        terminal_width()
    };
    match width {
        Some(width) if width > 0 => width,
        _ => 80,
    }
}

/// The controlling terminal's width when any std stream is a terminal (rich tries fd 0, 1, 2).
fn terminal_width() -> Option<usize> {
    use crossterm::tty::IsTty;
    if io::stdin().is_tty() || io::stdout().is_tty() || io::stderr().is_tty() {
        crossterm::terminal::size()
            .ok()
            .map(|(width, _)| usize::from(width))
    } else {
        None
    }
}

/// The input error of a reader (only PlainReader can produce one; TerminalIo degrades).
fn read_error(err: &io::Error) -> ConsoleError {
    ConsoleError::generic(format!("cannot read input: {}", os_error_text(err)))
}

/// indicatif draw target reporting `width − 3`: indicatif pads bar lines to the full width,
/// so the tty's `^C` echo would wrap and `finish_and_clear` would miss the spinner row.
#[derive(Debug)]
struct NarrowTerm(console::Term);
impl indicatif::TermLike for NarrowTerm {
    fn width(&self) -> u16 {
        self.0.size().1.saturating_sub(3).max(10)
    }
    fn height(&self) -> u16 {
        self.0.size().0
    }
    fn move_cursor_up(&self, n: usize) -> io::Result<()> {
        self.0.move_cursor_up(n)
    }
    fn move_cursor_down(&self, n: usize) -> io::Result<()> {
        self.0.move_cursor_down(n)
    }
    fn move_cursor_right(&self, n: usize) -> io::Result<()> {
        self.0.move_cursor_right(n)
    }
    fn move_cursor_left(&self, n: usize) -> io::Result<()> {
        self.0.move_cursor_left(n)
    }
    fn write_line(&self, s: &str) -> io::Result<()> {
        self.0.write_line(s)
    }
    fn write_str(&self, s: &str) -> io::Result<()> {
        self.0.write_str(s)
    }
    fn clear_line(&self) -> io::Result<()> {
        self.0.clear_line()
    }
    fn flush(&self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Drop guard of `busy`: always resets the spinner flag; clears the bar on success and
/// error; while unwinding it calls NO ProgressBar method (each locks a possibly poisoned
/// mutex) and only drops the handle.
struct BusyGuard<'a> {
    slot: &'a RefCell<Option<ProgressBar>>,
    bar: Option<ProgressBar>,
}
impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        set_spinner_active(false);
        if let Ok(mut slot) = self.slot.try_borrow_mut() {
            slot.take();
        }
        if let Some(bar) = self.bar.take()
            && !std::thread::panicking()
        {
            bar.finish_and_clear();
        }
    }
}

/// The ONE ConsoleIo over a LineReader: the §4.9.1 prompt/secret/multiline/select/confirm
/// logic and texts exist only here.
pub struct LineIo<R: LineReader> {
    reader: RefCell<R>,
    sink: Sink,
    hex_group: usize,
    hex_width: usize,
    /// TerminalIo with stderr a terminal only (§4.9.8).
    spinner_allowed: bool,
    spinner: RefCell<Option<ProgressBar>>,
}

impl<R: LineReader> LineIo<R> {
    pub(crate) fn new(
        reader: R,
        sink: Sink,
        hex_group: usize,
        hex_width: usize,
        spinner_allowed: bool,
    ) -> Self {
        Self {
            reader: RefCell::new(reader),
            sink,
            hex_group,
            hex_width,
            spinner_allowed,
            spinner: RefCell::new(None),
        }
    }

    /// Run ONE terminal primitive (a sink write, a reader call) with an active spinner
    /// suspended; never nested.
    fn quiet<T>(&self, f: impl FnOnce() -> T) -> T {
        let bar = self.spinner.try_borrow().ok().and_then(|slot| slot.clone());
        match bar {
            Some(bar) => bar.suspend(f),
            None => f(),
        }
    }

    fn ask(&self, prompt: &str, choices: &[String]) -> r2_core::Result<ReadOutcome> {
        self.quiet(|| self.reader.borrow_mut().read_param(prompt, choices))
            .map_err(|err| read_error(&err))
    }

    fn render_config(&self) -> RenderConfig {
        RenderConfig {
            width: self.sink.width(),
            hex_group: self.hex_group,
            hex_width: self.hex_width,
        }
    }
}

impl<R: LineReader> r2_core::io::ConsoleIo for LineIo<R> {
    fn prompt(&self, spec: &ParamSpec) -> r2_core::Result<String> {
        match self.ask(&format!("{}: ", spec.prompt), &choices_for(spec))? {
            ReadOutcome::Line(line) => Ok(line),
            ReadOutcome::Interrupted | ReadOutcome::Eof => Err(ConsoleError::user_abort(format!(
                "aborted while entering '{}'",
                spec.name
            ))),
        }
    }
    fn prompt_secret(&self, text: &str) -> r2_core::Result<SecretString> {
        let read = self
            .quiet(|| self.reader.borrow_mut().read_secret(&format!("{text}: ")))
            .map_err(|err| read_error(&err))?;
        match read {
            SecretRead::Secret(secret) => Ok(secret),
            SecretRead::Interrupted | SecretRead::Eof => {
                Err(ConsoleError::user_abort("aborted secret input"))
            }
        }
    }
    fn prompt_multiline(&self, text: &str) -> r2_core::Result<String> {
        self.print(Renderable::Text(format!(
            "{text} (finish with an empty line)"
        )));
        let mut lines: Vec<String> = Vec::new();
        loop {
            match self.ask("| ", &[])? {
                ReadOutcome::Line(line) if line.is_empty() => break,
                ReadOutcome::Line(line) => lines.push(line),
                ReadOutcome::Eof => break,
                ReadOutcome::Interrupted => {
                    return Err(ConsoleError::user_abort("aborted multiline input"));
                }
            }
        }
        Ok(lines.join("\n"))
    }
    fn select(&self, title: &str, options: &[String]) -> r2_core::Result<usize> {
        if options.is_empty() {
            return Err(ConsoleError::generic(format!(
                "nothing to select for: {title}"
            )));
        }
        let rows = options
            .iter()
            .enumerate()
            .map(|(index, option)| vec![(index + 1).to_string(), option.clone()])
            .collect();
        self.print(table(None, &["#", title], rows));
        let count = options.len();
        loop {
            let answer = match self.ask(&format!("Select [1-{count}]: "), &[])? {
                ReadOutcome::Line(line) => py_strip(&line).to_owned(),
                ReadOutcome::Interrupted | ReadOutcome::Eof => {
                    return Err(ConsoleError::user_abort("selection aborted"));
                }
            };
            if let Some(index) = options.iter().position(|option| *option == answer) {
                return Ok(index);
            }
            if py_isdigit(&answer)
                && let Ok(number) = answer.parse::<u64>()
                && let Ok(number) = usize::try_from(number)
                && (1..=count).contains(&number)
            {
                return Ok(number - 1);
            }
            self.print(Renderable::Text(format!(
                "invalid choice {} — enter 1-{count} or the option text",
                py_repr(&answer)
            )));
        }
    }
    fn confirm(&self, text: &str, default: bool) -> r2_core::Result<bool> {
        let suffix = if default { "[Y/n]" } else { "[y/N]" };
        loop {
            let answer = match self.ask(&format!("{text} {suffix} "), &[])? {
                ReadOutcome::Line(line) => py_strip(&line).to_lowercase(),
                ReadOutcome::Interrupted | ReadOutcome::Eof => {
                    return Err(ConsoleError::user_abort("confirmation aborted"));
                }
            };
            match answer.as_str() {
                "" => return Ok(default),
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => self.print(Renderable::Text("please answer y or n".to_owned())),
            }
        }
    }
    fn print(&self, renderable: Renderable) {
        let mut text = self.sink.render(&renderable, &self.render_config());
        text.push('\n');
        self.quiet(|| self.sink.write(&text));
    }
    fn print_error(&self, err: &ConsoleError) {
        let hint = err.hint.as_deref().filter(|hint| !hint.is_empty());
        self.print(error_panel(&err.message, hint));
    }
    fn read_command(&self, prompt: &str) -> r2_core::Result<CommandInput> {
        let outcome = self
            .quiet(|| self.reader.borrow_mut().read_command(prompt))
            .map_err(|err| read_error(&err))?;
        Ok(match outcome {
            ReadOutcome::Line(line) => CommandInput::Line(line),
            ReadOutcome::Interrupted => CommandInput::Interrupted,
            ReadOutcome::Eof => CommandInput::Eof,
        })
    }
    fn clear(&self) {
        // rich `Console.clear()`: nothing when not a terminal (or a dumb one).
        if self.sink.style != SinkStyle::Plain {
            self.quiet(|| self.sink.write("\u{1b}[2J\u{1b}[H"));
        }
        self.quiet(|| self.reader.borrow_mut().clear_screen());
    }
    fn busy(&self, message: &str, f: &mut dyn FnMut()) {
        let nested = self
            .spinner
            .try_borrow()
            .map(|slot| slot.is_some())
            .unwrap_or(true);
        if !self.spinner_allowed || nested {
            f();
            return;
        }
        let bar = ProgressBar::with_draw_target(
            None,
            ProgressDrawTarget::term_like_with_hz(
                Box::new(NarrowTerm(console::Term::stderr())),
                20,
            ),
        );
        if let Ok(style) = ProgressStyle::with_template("{spinner} {msg}") {
            bar.set_style(style);
        }
        bar.set_message(message.to_owned());
        bar.enable_steady_tick(Duration::from_millis(80));
        if let Ok(mut slot) = self.spinner.try_borrow_mut() {
            *slot = Some(bar.clone());
        }
        set_spinner_active(true);
        let _guard = BusyGuard {
            slot: &self.spinner,
            bar: Some(bar),
        };
        f();
    }
}
