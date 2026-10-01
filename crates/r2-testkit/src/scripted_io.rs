// ScriptedIo, RecordingEditor and the global-state lock (spec §4.10.1; owner R1) — the port
// of c2 `tests/support/scripted_io.py`.
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};

use r2_core::error::{ConsoleError, Result};
use r2_core::io::{CommandInput, ConsoleIo, Renderable, TemplateEditor, error_panel};
use r2_core::params::ParamSpec;
use r2_core::render::{RenderConfig, render_plain};
use r2_core::template::KeyTemplate;
use r2_core::text::{py_int, py_strip};
use secrecy::SecretString;

/// The project-standard ConsoleIo double (frozen surface).
///
/// Every `prompt`/`prompt_secret`/`prompt_multiline`/`select`/`confirm`/`read_command` records
/// its text in `prompts()` and pops the next answer; an exhausted queue PANICS (c2's
/// AssertionError — the test fails loudly). `CTRL_C`/`CTRL_D` answers behave like the keys.
pub struct ScriptedIo {
    answers: RefCell<VecDeque<String>>,
    output: RefCell<Vec<String>>,
    renderables: RefCell<Vec<Renderable>>,
    prompts: RefCell<Vec<String>>,
}

/// What a popped answer means.
enum Answer {
    Text(String),
    CtrlC,
    CtrlD,
}

impl ScriptedIo {
    /// Sentinel answer: behaves like Ctrl-C at that read.
    pub const CTRL_C: &str = "\u{3}";
    /// Sentinel answer: behaves like Ctrl-D / end of input at that read.
    pub const CTRL_D: &str = "\u{4}";
    pub fn new<I, S>(answers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            answers: RefCell::new(answers.into_iter().map(Into::into).collect()),
            output: RefCell::new(Vec::new()),
            renderables: RefCell::new(Vec::new()),
            prompts: RefCell::new(Vec::new()),
        }
    }
    /// No scripted answers (c2 `ScriptedIO([])`; `new([])` cannot infer its types).
    pub fn empty() -> Self {
        Self::new(Vec::<String>::new())
    }
    /// Every print as `render_plain(r, &RenderConfig::CAPTURE)`; every print_error as
    /// "error: {message}" + " (hint: {hint})" when a hint exists (c2 ScriptedIO format).
    pub fn output(&self) -> Vec<String> {
        self.output.borrow().clone()
    }
    /// `output()` joined with "\n".
    pub fn text(&self) -> String {
        self.output.borrow().join("\n")
    }
    /// The raw Renderables passed to print (errors as `error_panel`), in order.
    pub fn renderables(&self) -> Vec<Renderable> {
        self.renderables.borrow().clone()
    }
    /// Every prompt text (`spec.prompt`), secret text, multiline text, select title,
    /// confirm text AND `read_command` prompt ("r2> ", "…> " — c2's REPL read through
    /// `prompt(ParamSpec("command", "c2> "))`, so test_repl.py asserts them), in order.
    pub fn prompts(&self) -> Vec<String> {
        self.prompts.borrow().clone()
    }
    /// Answers not yet consumed.
    pub fn remaining(&self) -> usize {
        self.answers.borrow().len()
    }

    /// Record `text` in `prompts()` and pop the next answer (c2 `_next_answer`).
    fn next_answer(&self, kind: &str, text: &str) -> Answer {
        self.prompts.borrow_mut().push(text.to_owned());
        let answer = self.answers.borrow_mut().pop_front();
        match answer {
            None => panic!("ScriptedIo: answer queue exhausted at {kind}({text:?})"),
            Some(answer) if answer == Self::CTRL_C => Answer::CtrlC,
            Some(answer) if answer == Self::CTRL_D => Answer::CtrlD,
            Some(answer) => Answer::Text(answer),
        }
    }
}

impl ConsoleIo for ScriptedIo {
    fn prompt(&self, spec: &ParamSpec) -> Result<String> {
        match self.next_answer("prompt", &spec.prompt) {
            Answer::Text(answer) => Ok(answer),
            Answer::CtrlC | Answer::CtrlD => Err(ConsoleError::user_abort(format!(
                "aborted while entering '{}'",
                spec.name
            ))),
        }
    }
    fn prompt_secret(&self, text: &str) -> Result<SecretString> {
        match self.next_answer("prompt_secret", text) {
            Answer::Text(answer) => Ok(SecretString::from(answer)),
            Answer::CtrlC | Answer::CtrlD => Err(ConsoleError::user_abort("aborted secret input")),
        }
    }
    fn prompt_multiline(&self, text: &str) -> Result<String> {
        match self.next_answer("prompt_multiline", text) {
            Answer::Text(answer) => Ok(answer),
            // EOF ends the input; it is not an abort (§4.9.1).
            Answer::CtrlD => Ok(String::new()),
            Answer::CtrlC => Err(ConsoleError::user_abort("aborted multiline input")),
        }
    }
    fn select(&self, title: &str, options: &[String]) -> Result<usize> {
        if options.is_empty() {
            // The ConsoleIo contract (§4.9.1); no answer is consumed.
            self.prompts.borrow_mut().push(title.to_owned());
            return Err(ConsoleError::generic(format!(
                "nothing to select for: {title}"
            )));
        }
        let answer = match self.next_answer("select", title) {
            Answer::Text(answer) => answer,
            Answer::CtrlC | Answer::CtrlD => {
                return Err(ConsoleError::user_abort("selection aborted"));
            }
        };
        if let Some(index) = options.iter().position(|option| *option == answer) {
            return Ok(index);
        }
        let Some(index) = py_int(&answer, 10) else {
            panic!(
                "ScriptedIo: select answer {answer:?} is neither an option in {options:?} nor an index"
            );
        };
        match usize::try_from(index) {
            Ok(index) if index < options.len() => Ok(index),
            _ => panic!("ScriptedIo: select index {index} out of range for {options:?}"),
        }
    }
    fn confirm(&self, text: &str, default: bool) -> Result<bool> {
        let answer = match self.next_answer("confirm", text) {
            Answer::Text(answer) => py_strip(&answer).to_lowercase(),
            Answer::CtrlC | Answer::CtrlD => {
                return Err(ConsoleError::user_abort("confirmation aborted"));
            }
        };
        match answer.as_str() {
            "" => Ok(default),
            "y" | "yes" => Ok(true),
            "n" | "no" => Ok(false),
            _ => panic!("ScriptedIo: confirm answer {answer:?} is not y/n"),
        }
    }
    fn print(&self, renderable: Renderable) {
        let text = render_plain(&renderable, &RenderConfig::CAPTURE);
        self.output.borrow_mut().push(text);
        self.renderables.borrow_mut().push(renderable);
    }
    fn print_error(&self, err: &ConsoleError) {
        let hint = err.hint.as_deref().filter(|hint| !hint.is_empty());
        let mut line = format!("error: {}", err.message);
        if let Some(hint) = hint {
            line.push_str(&format!(" (hint: {hint})"));
        }
        self.output.borrow_mut().push(line);
        self.renderables
            .borrow_mut()
            .push(error_panel(&err.message, hint));
    }
    fn read_command(&self, prompt: &str) -> Result<CommandInput> {
        Ok(match self.next_answer("read_command", prompt) {
            Answer::Text(line) => CommandInput::Line(line),
            Answer::CtrlC => CommandInput::Interrupted,
            Answer::CtrlD => CommandInput::Eof,
        })
    }
}

static GLOBAL_STATE: Mutex<()> = Mutex::new(());

/// Serializes tests that touch process-global state (the `r2_core::runtime` flags, the
/// process environment, a PKCS#11 module) under plain `cargo test`; hold the guard for the
/// whole test and restore what you changed (§4.1.3 test runner rule). A poisoned lock is
/// recovered (`into_inner`), never a panic.
pub fn global_state_lock() -> MutexGuard<'static, ()> {
    GLOBAL_STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The response hook of a `RecordingEditor::with` editor.
type Respond = Box<dyn Fn(KeyTemplate) -> Result<KeyTemplate>>;

/// TemplateEditor double: records titles and received templates; returns the template
/// unchanged, or `respond(template)` when built with `with`.
#[derive(Default)]
pub struct RecordingEditor {
    calls: RefCell<Vec<(String, KeyTemplate)>>,
    respond: Option<Respond>,
}
impl RecordingEditor {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(respond: impl Fn(KeyTemplate) -> Result<KeyTemplate> + 'static) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            respond: Some(Box::new(respond)),
        }
    }
    pub fn titles(&self) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .map(|(title, _)| title.clone())
            .collect()
    }
    pub fn templates(&self) -> Vec<KeyTemplate> {
        self.calls
            .borrow()
            .iter()
            .map(|(_, template)| template.clone())
            .collect()
    }
}
impl TemplateEditor for RecordingEditor {
    fn edit(&self, template: KeyTemplate, title: &str) -> Result<KeyTemplate> {
        self.calls
            .borrow_mut()
            .push((title.to_owned(), template.clone()));
        match &self.respond {
            Some(respond) => respond(template),
            None => Ok(template),
        }
    }
}
