// Interaction traits and the Renderable model (spec §4.9.1/§4.9.2; owner R1).
use crate::error::{ConsoleError, ErrorKind, Result};
use crate::params::ParamSpec;
use crate::template::KeyTemplate;
use secrecy::SecretString;

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
/// Text style. Error = bold red, Danger = red.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tone {
    #[default]
    Plain,
    Bold,
    Dim,
    Italic,
    Error,
    Danger,
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
    /// Verbatim text (may contain newlines).
    Text(String),
    /// Pre-styled lines (caret echo, banners).
    Styled(Vec<Line>),
    Table(TableData),
    /// Grouped hex dump panel; grouping/width from RenderConfig at render time.
    Hex {
        data: Vec<u8>,
        title: Option<String>,
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
/// row of spaces + "^" (Tone::Error) whose column is the unicode-width display width of
/// the row prefix before `pos`.
pub fn caret(line: &str, pos: usize) -> Renderable {
    let mut pos = pos.min(line.len());
    while !line.is_char_boundary(pos) {
        pos -= 1;
    }
    let row_start = line[..pos].rfind('\n').map_or(0, |i| i + 1);
    let row_end = line[pos..].find('\n').map_or(line.len(), |i| pos + i);
    let column = crate::render::display_width(&line[row_start..pos]);
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
/// Uniform table used by every command (cells verbatim).
pub fn table(title: Option<&str>, columns: &[&str], rows: Vec<Vec<String>>) -> Renderable {
    Renderable::Table(TableData {
        title: title.map(str::to_owned),
        columns: columns.iter().map(|column| (*column).to_owned()).collect(),
        rows,
    })
}
/// Hex dump panel (c2 `render.hex_panel`).
pub fn hex(data: &[u8], title: Option<&str>) -> Renderable {
    Renderable::Hex {
        data: data.to_vec(),
        title: title.map(str::to_owned),
    }
}
