#![allow(dead_code)]
// R0 skeleton — owner R7 (generated from spec §4)
// ---- spec §4.9.7 block 2
use secrecy::SecretString;
use std::io;

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

/// The ONE ConsoleIo over a LineReader: the §4.9.1 prompt/secret/multiline/select/confirm
/// logic and texts exist only here.
pub struct LineIo<R: LineReader> {
    _marker: std::marker::PhantomData<R>,
}
impl<R: LineReader> r2_core::io::ConsoleIo for LineIo<R> {
    fn prompt(&self, spec: &r2_core::params::ParamSpec) -> r2_core::Result<String> {
        let _ = spec;
        Err(r2_core::ConsoleError::not_implemented("R7"))
    }
    fn prompt_secret(&self, text: &str) -> r2_core::Result<SecretString> {
        let _ = text;
        Err(r2_core::ConsoleError::not_implemented("R7"))
    }
    fn prompt_multiline(&self, text: &str) -> r2_core::Result<String> {
        let _ = text;
        Err(r2_core::ConsoleError::not_implemented("R7"))
    }
    fn select(&self, title: &str, options: &[String]) -> r2_core::Result<usize> {
        let _ = (title, options);
        Err(r2_core::ConsoleError::not_implemented("R7"))
    }
    fn confirm(&self, text: &str, default: bool) -> r2_core::Result<bool> {
        let _ = (text, default);
        Err(r2_core::ConsoleError::not_implemented("R7"))
    }
    fn print(&self, renderable: r2_core::io::Renderable) {
        let _ = renderable;
        unimplemented!("R7")
    }
    fn print_error(&self, err: &r2_core::ConsoleError) {
        let _ = err;
        unimplemented!("R7")
    }
}
