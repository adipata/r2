// Interaction traits and the Renderable model (spec §4.9.1/§4.9.2; owner R1).
use std::time::Duration;

use crate::error::{ConsoleError, ErrorKind, Result};
use crate::params::ParamSpec;
use crate::template::KeyTemplate;
use secrecy::SecretString;
use zeroize::Zeroizing;

/// One REPL read at the command prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandInput {
    Line(String),
    /// Ctrl-C at the prompt: the REPL prints `Aborted.` and re-prompts.
    Interrupted,
    /// Ctrl-D on an empty line / end of piped input: the REPL exits (status 0).
    Eof,
}

/// frozen-provisional (§4.11).
pub trait ConsoleIo {
    /// One parameter value. Rendered "{spec.prompt}: "; ENUM choices / BOOL words
    /// (true,false,yes,no,on,off) complete. Answers never enter the command history.
    /// Ctrl-C / Ctrl-D → UserAbort "aborted while entering '{spec.name}'".
    fn prompt(&self, spec: &ParamSpec) -> Result<String>;
    /// Hidden input (PINs, passwords). Rendered "{text}: " (c2 parity, even when `text`
    /// already ends with ": "); never echoed, logged or stored in any history.
    /// Ctrl-C / Ctrl-D → UserAbort "aborted secret input".
    fn prompt_secret(&self, text: &str) -> Result<SecretString>;
    /// Prints "{text} (finish with an empty line)", then reads lines with the prompt "| "
    /// until an empty line or EOF (EOF ends the input, it is not an abort); returns the
    /// lines joined with "\n". Ctrl-C → UserAbort "aborted multiline input".
    fn prompt_multiline(&self, text: &str) -> Result<String>;
    /// Prints table(None, ["#", title], [[1-based index, option]…]), then asks
    /// "Select [1-{N}]: " and, on the `text::py_strip`-trimmed answer, in this order (c2):
    /// (1) equal to an option text → the index of the FIRST equal option (text wins over
    /// number, so an option "2" is picked by text); (2) else `text::py_isdigit(answer)` and
    /// its `u64` value (overflow = invalid) in 1..=N → value − 1 ("02" → index 1; "+2",
    /// "1_0", "-0" are NOT numbers); (3) else prints "invalid choice
    /// {answer!r} — enter 1-{N} or the option text" and asks again. Never `py_int` or
    /// `str::parse::<usize>` alone (both accept "+2").
    /// Returns the 0-based index. Empty `options` → Generic "nothing to select for: {title}".
    /// Ctrl-C / Ctrl-D → UserAbort "selection aborted".
    fn select(&self, title: &str, options: &[String]) -> Result<usize>;
    /// Asks "{text} [Y/n] " (default true) or "{text} [y/N] "; empty → default;
    /// y/yes → true, n/no → false (trimmed, case-insensitive); else prints "please answer y
    /// or n" and asks again. Ctrl-C / Ctrl-D → UserAbort "confirmation aborted".
    fn confirm(&self, text: &str, default: bool) -> Result<bool>;
    /// Render output. Content is data — never interpreted as markup.
    fn print(&self, renderable: Renderable);
    /// Render `error_panel(&err.message, err.hint.as_deref())`.
    fn print_error(&self, err: &ConsoleError);

    /// The REPL's command-line read (history, hints, completion, highlighting in
    /// TerminalIo). `prompt` ("r2> ", "…> ") is shown VERBATIM (no ": " appended):
    /// `LineIo` and `ScriptedIo` override this method; the default (the blessed
    /// synthetic-STR-ParamSpec pattern) exists for other implementations.
    fn read_command(&self, prompt: &str) -> Result<CommandInput> {
        match self.prompt(&ParamSpec::str("command", prompt)) {
            Ok(line) => Ok(CommandInput::Line(line)),
            Err(err) if matches!(err.kind, ErrorKind::UserAbort) => Ok(CommandInput::Interrupted),
            Err(err) => Err(err),
        }
    }
    /// The `clear` command.
    fn clear(&self) {
        self.print(Renderable::Text("\u{1b}[2J\u{1b}[H".to_owned()));
    }
    /// Run `f` while showing a spinner with `message` (provisional r2 addition, §4.9.8;
    /// c2 never had one). Default: just run `f`. Contract for every implementation: `f` is
    /// called exactly once, and no `RefCell` borrow of the IO is held while it runs (prints
    /// and prompts inside `f` re-enter the IO); a nested `busy` just runs its `f`. Callers
    /// use `busy_with`, which returns `f`'s value.
    fn busy(&self, message: &str, f: &mut dyn FnMut()) {
        let _ = message;
        f();
    }
    /// Hand `f` the keyboard and the screen rows below the output so far (provisional r2
    /// addition, §11 D34; c2 never had one). TerminalIo on a working terminal with styled
    /// output calls `f` exactly once with a `KeySession`, erases the last frame when `f`
    /// returns, and returns true. Otherwise — the default: PlainIo, ScriptedIo, a degraded
    /// session, the Plain sink — it returns false WITHOUT calling `f`, and the caller falls
    /// back to line prompts. A terminal failure surfaces as Generic "terminal error: …"
    /// from `draw`/`read_key`; TerminalIo then degrades the session like a failed read (the
    /// §11 D2 warning) once `f` has returned. No `RefCell` borrow of the IO is held while
    /// `f` runs, but `f` must not print or prompt through the IO while the session is open.
    fn interactive(&self, f: &mut dyn FnMut(&mut dyn KeySession)) -> bool {
        let _ = f;
        false
    }
}

/// One key of an interactive session (`ConsoleIo::interactive`; provisional, §11 D34).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// A printable character (Shift applied; no Ctrl, no Alt).
    Char(char),
    /// Ctrl + a letter, lower-case: `Ctrl('c')` is Ctrl-C.
    Ctrl(char),
    Enter,
    Esc,
    Tab,
    BackTab,
    Backspace,
    Delete,
    Insert,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    /// A bracketed paste: the whole text as one event.
    Paste(String),
    /// The terminal changed size; the session's owner redraws.
    Resize,
}

/// One screen of an interactive session (provisional, §11 D34).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frame {
    /// The rows, top to bottom. A row wider than the terminal minus one column is clipped;
    /// rows beyond the terminal height minus one are not drawn; control characters show
    /// as U+FFFD.
    pub lines: Vec<Line>,
    /// Where the terminal cursor is shown: (row, column in cells). None hides it.
    pub cursor: Option<(usize, usize)>,
}

/// The terminal side of `ConsoleIo::interactive` (provisional, §11 D34).
pub trait KeySession {
    /// The terminal size: (columns, rows), each at least 1.
    fn size(&self) -> (usize, usize);
    /// Draw `frame` in place of the previous one (nothing on the first call), on the rows
    /// below the output so far.
    fn draw(&mut self, frame: &Frame) -> Result<()>;
    /// The next key; blocks until one arrives.
    fn read_key(&mut self) -> Result<Key>;
}

/// Runs `f` through `io.busy(message, ..)` and returns its value; if the implementation
/// did not call the closure (a contract violation), runs `f` directly — never panics, never
/// loses `f`'s result. The only sanctioned way to call `busy` (it avoids the
/// `Option<Result<T>>` dance under `-D clippy::unwrap_used`).
pub fn busy_with<T>(io: &dyn ConsoleIo, message: &str, f: impl FnOnce() -> T) -> T {
    let mut job = Some(f);
    let mut result = None;
    io.busy(message, &mut || {
        if let Some(job) = job.take() {
            result = Some(job());
        }
    });
    match (result, job) {
        (Some(value), _) => value,
        // Contract violation (the implementation never ran `f`): run it here.
        (None, Some(job)) => job(),
        // Unreachable: `job` is only taken by the closure, which then stores its result.
        (None, None) => busy_with_unreachable(),
    }
}

#[cold]
fn busy_with_unreachable() -> ! {
    unreachable!("busy_with: the closure took the job without storing its result")
}

/// One-method hook (frozen-provisional, §4.11). Edits a copy; returns the edited template;
/// UserAbort "template edit cancelled" on cancel.
pub trait TemplateEditor {
    fn edit(&self, template: KeyTemplate, title: &str) -> Result<KeyTemplate>;
}

/// Returns the template unchanged (c2 `_IdentityTemplateEditor`; also the R0 stub of
/// `create_template_editor`).
#[derive(Clone, Copy, Debug, Default)]
pub struct IdentityTemplateEditor;
impl TemplateEditor for IdentityTemplateEditor {
    fn edit(&self, template: KeyTemplate, title: &str) -> Result<KeyTemplate> {
        let _ = title;
        Ok(template)
    }
}
// ---- Renderable model (spec §4.9.2) ----
/// Text style. Error = bold red, Danger = red, Success = bold green.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tone {
    #[default]
    Plain,
    Bold,
    Dim,
    Italic,
    Error,
    Danger,
    /// Bold green (rich "bold green": `verify`'s `signature VALID`, §5.1).
    Success,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub text: String,
    pub tone: Tone,
}
pub type Line = Vec<Span>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableData {
    pub title: Option<String>,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PanelData {
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub border: Tone,
    pub body: Vec<Line>,
}

/// Closed set of outputs. Nothing is ever parsed as markup (rich's `[#…]`/`[x]` eating
/// cannot happen).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Renderable {
    /// Plain text (may contain newlines); never markup. Laid out like rich's `Text`
    /// (control codes stripped, tabs expanded, fold-wrapped at the width; §4.9.2).
    Text(String),
    /// Pre-styled lines (caret echo, banners); laid out like `Text`.
    Styled(Vec<Line>),
    Table(TableData),
    /// Hex result: the panel's titled top and "{n} bytes" bottom borders around one unbroken
    /// line of hex (§4.9.2, §11 D28). `data` is wiped on drop (it may be plaintext or a
    /// derived secret, D3); `elapsed` = the provider time shown after the byte count
    /// ("16 bytes in 4ms", §11 D31).
    Hex {
        data: Zeroizing<Vec<u8>>,
        title: Option<String>,
        elapsed: Option<Duration>,
    },
    Panel(PanelData),
}
impl From<&str> for Renderable {
    fn from(text: &str) -> Self {
        Renderable::Text(text.to_owned())
    }
}
impl From<String> for Renderable {
    fn from(text: String) -> Self {
        Renderable::Text(text)
    }
}

/// Red-bordered panel titled "error": message line (Tone::Error), then "hint: {hint}"
/// (Tone::Dim) when given.
pub fn error_panel(message: &str, hint: Option<&str>) -> Renderable {
    let mut body = vec![vec![Span {
        text: message.to_owned(),
        tone: Tone::Error,
    }]];
    // c2 `if err.hint:` — an empty hint is no hint.
    if let Some(hint) = hint.filter(|hint| !hint.is_empty()) {
        body.push(vec![Span {
            text: format!("hint: {hint}"),
            tone: Tone::Dim,
        }]);
    }
    Renderable::Panel(PanelData {
        title: Some("error".to_owned()),
        subtitle: None,
        border: Tone::Danger,
        body,
    })
}
/// The physical row of `line` containing byte offset `pos` (clamped to 0..=len), then a
/// row of spaces + "^" (Tone::Error) whose column is the display width of the row prefix
/// before `pos` as the renderer lays the row out (rich cell widths, control codes stripped,
/// tabs expanded to 8 columns; §4.9.2, §11 D14).
pub fn caret(line: &str, pos: usize) -> Renderable {
    let mut pos = pos.min(line.len());
    while !line.is_char_boundary(pos) {
        pos -= 1;
    }
    let row_start = line[..pos].rfind('\n').map_or(0, |i| i + 1);
    let row_end = line[pos..].find('\n').map_or(line.len(), |i| pos + i);
    let column = crate::render::caret_column(&line[row_start..pos]);
    Renderable::Styled(vec![
        vec![Span {
            text: line[row_start..row_end].to_owned(),
            tone: Tone::Plain,
        }],
        vec![
            Span {
                text: " ".repeat(column),
                tone: Tone::Plain,
            },
            Span {
                text: "^".to_owned(),
                tone: Tone::Error,
            },
        ],
    ])
}
/// Uniform table used by every command (cells are data, never markup; control codes
/// stripped as in rich).
pub fn table(title: Option<&str>, columns: &[&str], rows: Vec<Vec<String>>) -> Renderable {
    Renderable::Table(TableData {
        title: title.map(str::to_owned),
        columns: columns.iter().map(|column| (*column).to_owned()).collect(),
        rows,
    })
}
/// Hex result (c2 `render.hex_panel`, laid out per §11 D28), without timing.
pub fn hex(data: &[u8], title: Option<&str>) -> Renderable {
    hex_timed(data, title, None)
}
/// Hex result whose footer also shows the provider time `elapsed` (§11 D31).
pub fn hex_timed(data: &[u8], title: Option<&str>, elapsed: Option<Duration>) -> Renderable {
    Renderable::Hex {
        data: Zeroizing::new(data.to_vec()),
        title: title.map(str::to_owned),
        elapsed,
    }
}
