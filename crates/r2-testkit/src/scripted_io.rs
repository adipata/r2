#![allow(dead_code)]
// R0 skeleton — owner R1 (generated from spec §4)
// ---- spec §4.10.1 block 0
use r2_core::error::{ConsoleError, Result};
use r2_core::io::{ConsoleIo, Renderable, TemplateEditor}; // + CommandInput for R1's read_command override
use r2_core::params::ParamSpec;
use r2_core::template::KeyTemplate;
use secrecy::SecretString;

/// The project-standard ConsoleIo double (frozen surface).
pub struct ScriptedIo {}
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
        let _ = answers;
        unimplemented!("R1")
    }
    /// No scripted answers (c2 `ScriptedIO([])`; `new([])` cannot infer its types).
    pub fn empty() -> Self {
        unimplemented!("R1")
    }
    /// Every print as `render_plain(r, &RenderConfig::CAPTURE)`; every print_error as
    /// "error: {message}" + " (hint: {hint})" when a hint exists (c2 ScriptedIO format).
    pub fn output(&self) -> Vec<String> {
        unimplemented!("R1")
    }
    /// `output()` joined with "\n".
    pub fn text(&self) -> String {
        unimplemented!("R1")
    }
    /// The raw Renderables passed to print (errors as `error_panel`), in order.
    pub fn renderables(&self) -> Vec<Renderable> {
        unimplemented!("R1")
    }
    /// Every prompt text (`spec.prompt`), secret text, multiline text, select title,
    /// confirm text AND `read_command` prompt ("r2> ", "…> " — c2's REPL read through
    /// `prompt(ParamSpec("command", "c2> "))`, so test_repl.py asserts them), in order.
    pub fn prompts(&self) -> Vec<String> {
        unimplemented!("R1")
    }
    /// Answers not yet consumed.
    pub fn remaining(&self) -> usize {
        unimplemented!("R1")
    }
}
impl ConsoleIo for ScriptedIo {
    fn prompt(&self, spec: &ParamSpec) -> Result<String> {
        let _ = spec;
        Err(r2_core::ConsoleError::not_implemented("R1"))
    }
    fn prompt_secret(&self, text: &str) -> Result<SecretString> {
        let _ = text;
        Err(r2_core::ConsoleError::not_implemented("R1"))
    }
    fn prompt_multiline(&self, text: &str) -> Result<String> {
        let _ = text;
        Err(r2_core::ConsoleError::not_implemented("R1"))
    }
    fn select(&self, title: &str, options: &[String]) -> Result<usize> {
        let _ = (title, options);
        Err(r2_core::ConsoleError::not_implemented("R1"))
    }
    fn confirm(&self, text: &str, default: bool) -> Result<bool> {
        let _ = (text, default);
        Err(r2_core::ConsoleError::not_implemented("R1"))
    }
    fn print(&self, renderable: Renderable) {
        let _ = renderable;
        unimplemented!("R1")
    }
    fn print_error(&self, err: &ConsoleError) {
        let _ = err;
        unimplemented!("R1")
    }
}

/// Serializes tests that touch process-global state (the `r2_core::runtime` flags, the
/// process environment, a PKCS#11 module) under plain `cargo test`; hold the guard for the
/// whole test and restore what you changed (§4.1.3 test runner rule). A poisoned lock is
/// recovered (`into_inner`), never a panic.
pub fn global_state_lock() -> std::sync::MutexGuard<'static, ()> {
    unimplemented!("R1")
}
/// TemplateEditor double: records titles and received templates; returns the template
/// unchanged, or `respond(template)` when built with `with`.
#[derive(Default)]
pub struct RecordingEditor {}
impl RecordingEditor {
    pub fn new() -> Self {
        unimplemented!("R1")
    }
    pub fn with(respond: impl Fn(KeyTemplate) -> Result<KeyTemplate> + 'static) -> Self {
        let _ = respond;
        unimplemented!("R1")
    }
    pub fn titles(&self) -> Vec<String> {
        unimplemented!("R1")
    }
    pub fn templates(&self) -> Vec<KeyTemplate> {
        unimplemented!("R1")
    }
}
impl TemplateEditor for RecordingEditor {
    fn edit(&self, template: KeyTemplate, title: &str) -> Result<KeyTemplate> {
        let _ = (template, title);
        Err(r2_core::ConsoleError::not_implemented("R1"))
    }
}
