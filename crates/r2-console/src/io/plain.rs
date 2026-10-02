// PlainReader / PlainIo (spec §4.9.7, §6, §11 D2; owner R7) — line reads from the global
// stdin handle for non-terminal sessions (pipes, files, CI), `TERM=dumb`, a redirected
// stdout, and degraded TerminalIo sessions.
use std::io::{self, BufRead, Write};

use r2_core::runtime::{interrupted, reset_interrupt};
use secrecy::SecretString;

use super::history::SecretFilteringHistory;
use super::line::{LineIo, LineReader, ReadOutcome, SecretRead};

/// Plain line reads from the global stdin handle (rules below).
pub struct PlainReader {
    /// stdin is a terminal: the tty driver echoes (r2 does not echo again), secrets go
    /// through rpassword, and Ctrl-C is honored at the next Enter (§11 D2).
    stdin_is_tty: bool,
    /// The command history (c2's prompt_toolkit session kept its FileHistory in piped
    /// sessions too): every command line read is saved and synced; secret lines are dropped.
    history: Option<SecretFilteringHistory>,
}

impl PlainReader {
    pub(crate) fn new(stdin_is_tty: bool, history: Option<SecretFilteringHistory>) -> Self {
        Self {
            stdin_is_tty,
            history,
        }
    }

    /// Prompt to stdout, one byte-level line from the global stdin handle (never a second
    /// BufReader), trailing `\r`/`\n` stripped, lossy UTF-8; echo per the rules; at EOF a
    /// newline and Eof (None). The byte buffer is wiped once decoded (it may hold a secret).
    fn read_line(&mut self, prompt: &str, secret: bool) -> io::Result<Option<String>> {
        {
            let mut out = io::stdout().lock();
            out.write_all(prompt.as_bytes())?;
            out.flush()?;
        }
        let mut buffer = Vec::new();
        let read = io::stdin().lock().read_until(b'\n', &mut buffer)?;
        if read == 0 {
            let mut out = io::stdout().lock();
            out.write_all(b"\n")?;
            out.flush()?;
            return Ok(None);
        }
        while buffer.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            buffer.pop();
        }
        let line = String::from_utf8_lossy(&buffer).into_owned();
        zeroize::Zeroize::zeroize(&mut buffer);
        if !self.stdin_is_tty {
            let mut out = io::stdout().lock();
            if secret {
                out.write_all(b"\n")?;
            } else {
                out.write_all(line.as_bytes())?;
                out.write_all(b"\n")?;
            }
            out.flush()?;
        }
        Ok(Some(line))
    }

    /// On a terminal, Ctrl-C reached the ctrlc handler while the cooked read blocked: the
    /// line typed after it is discarded and the read reports Interrupted (§11 D2).
    fn interrupted_on_tty(&self) -> bool {
        if self.stdin_is_tty && interrupted() {
            reset_interrupt();
            return true;
        }
        false
    }

    fn outcome(&mut self, prompt: &str) -> io::Result<ReadOutcome> {
        let line = self.read_line(prompt, false)?;
        if self.interrupted_on_tty() {
            return Ok(ReadOutcome::Interrupted);
        }
        Ok(match line {
            Some(line) => ReadOutcome::Line(line),
            None => ReadOutcome::Eof,
        })
    }
}

/// rpassword hidden read (terminal only); Ctrl-C → Interrupted, Ctrl-D → Eof.
pub(crate) fn rpassword_secret(prompt: &str) -> io::Result<SecretRead> {
    match rpassword::prompt_password(prompt) {
        Ok(secret) => Ok(SecretRead::Secret(SecretString::from(secret))),
        Err(err) if err.kind() == io::ErrorKind::Interrupted => Ok(SecretRead::Interrupted),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(SecretRead::Eof),
        Err(err) => Err(err),
    }
}

impl LineReader for PlainReader {
    fn read_command(&mut self, prompt: &str) -> std::io::Result<super::line::ReadOutcome> {
        let outcome = self.outcome(prompt)?;
        if let (ReadOutcome::Line(line), Some(history)) = (&outcome, self.history.as_mut()) {
            use reedline::History;
            // FileBackedHistory skips empty lines and repeats of the last entry, as
            // prompt_toolkit did; the filter answers Ok for secret lines without storing.
            let _ = history.save(reedline::HistoryItem::from_command_line(line.clone()));
            let _ = history.sync();
        }
        Ok(outcome)
    }
    fn read_param(
        &mut self,
        prompt: &str,
        choices: &[String],
    ) -> std::io::Result<super::line::ReadOutcome> {
        let _ = choices;
        self.outcome(prompt)
    }
    fn read_secret(&mut self, prompt: &str) -> std::io::Result<super::line::SecretRead> {
        if self.stdin_is_tty {
            // the tty driver would echo a plain-read secret
            return rpassword_secret(prompt);
        }
        // piped: one plain line, never echoed (rpassword would open /dev/tty)
        Ok(match self.read_line(prompt, true)? {
            Some(line) => SecretRead::Secret(SecretString::from(line)),
            None => SecretRead::Eof,
        })
    }
}
pub type PlainIo = LineIo<PlainReader>;
