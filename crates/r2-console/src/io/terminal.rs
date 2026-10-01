#![allow(dead_code)]
// R0 skeleton — owner R7 (generated from spec §4)
// ---- spec §4.9.7 block 4
use super::line::{LineIo, LineReader};

/// reedline primary (R7-internal `ReedlineReader`), `PlainReader` fallback (rules below).
pub struct DegradingReader {}
impl LineReader for DegradingReader {
    fn read_command(&mut self, prompt: &str) -> std::io::Result<super::line::ReadOutcome> {
        let _ = prompt;
        unimplemented!("R7")
    }
    fn read_param(
        &mut self,
        prompt: &str,
        choices: &[String],
    ) -> std::io::Result<super::line::ReadOutcome> {
        let _ = (prompt, choices);
        unimplemented!("R7")
    }
    fn read_secret(&mut self, prompt: &str) -> std::io::Result<super::line::SecretRead> {
        let _ = prompt;
        unimplemented!("R7")
    }
}
pub type TerminalIo = LineIo<DegradingReader>;
