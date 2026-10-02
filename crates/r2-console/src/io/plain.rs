// PlainReader / PlainIo (spec §4.9.7, §6, §11 D2; owner R7) — line reads from the global
// stdin handle for non-terminal sessions (pipes, files, CI), `TERM=dumb`, a redirected
// stdout, and degraded TerminalIo sessions.
use std::io::{self, BufRead, Write};

use r2_core::runtime::{interrupted, reset_interrupt};
use secrecy::SecretString;
use zeroize::Zeroizing;

use super::history::SecretFilteringHistory;
use super::line::{LineIo, LineReader, ReadOutcome, SecretRead};
use crate::parser::line_is_complete;

/// Plain line reads from the global stdin handle (rules below).
pub struct PlainReader {
    /// stdin is a terminal: the tty driver echoes (r2 does not echo again), secrets go
    /// through rpassword, and Ctrl-C is honored at the next Enter (§11 D2).
    stdin_is_tty: bool,
    /// The command history (c2's prompt_toolkit session kept its FileHistory in piped
    /// sessions too): every logical command is saved and synced, like reedline's (§11 D7);
    /// secret entries are dropped.
    history: Option<SecretFilteringHistory>,
    /// The physical lines of a command whose quote is still open (`…> ` continuations),
    /// joined with "\n" exactly as the REPL joins them; saved once the quote closes.
    pending: Option<String>,
    /// Piped stdin: the line read by a read that a SIGINT interrupted, returned by the next
    /// read (c2 never consumed it).
    stashed: Option<Zeroizing<String>>,
}

impl PlainReader {
    pub(crate) fn new(stdin_is_tty: bool, history: Option<SecretFilteringHistory>) -> Self {
        Self {
            stdin_is_tty,
            history,
            pending: None,
            stashed: None,
        }
    }

    /// Prompt to stdout, one byte-level line from the global stdin handle (never a second
    /// BufReader), trailing `\r`/`\n` stripped, lossy UTF-8; echo per the rules; at EOF a
    /// newline and Eof. The byte buffer is wiped once decoded (it may hold a secret).
    fn read_line(&mut self, prompt: &str, secret: bool) -> io::Result<ReadOutcome> {
        self.read_line_from(prompt, secret, &mut io::stdin().lock())
    }

    /// `read_line` over an explicit input (the global stdin lock; tests pass a cursor).
    ///
    /// Piped stdin (not a terminal): a SIGINT (the ctrlc handler's flag) set before the read
    /// reports Interrupted without reading; one that arrived while the read blocked reports
    /// Interrupted too, and the line read is kept (`stashed`) and returned, echoed, by the
    /// next read — c2's KeyboardInterrupt left the unread pipe data in place (§11 D2).
    fn read_line_from(
        &mut self,
        prompt: &str,
        secret: bool,
        input: &mut dyn BufRead,
    ) -> io::Result<ReadOutcome> {
        let mut out = io::stdout().lock();
        out.write_all(prompt.as_bytes())?;
        out.flush()?;
        if !self.stdin_is_tty && interrupted() {
            reset_interrupt();
            out.write_all(b"\n")?;
            out.flush()?;
            return Ok(ReadOutcome::Interrupted);
        }
        drop(out);
        let line = match self.stashed.take() {
            Some(line) => Some(line),
            None => {
                let mut buffer = Vec::new();
                let read = input.read_until(b'\n', &mut buffer)?;
                if read == 0 {
                    None
                } else {
                    while buffer.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                        buffer.pop();
                    }
                    let line = Zeroizing::new(String::from_utf8_lossy(&buffer).into_owned());
                    zeroize::Zeroize::zeroize(&mut buffer);
                    Some(line)
                }
            }
        };
        let mut out = io::stdout().lock();
        if !self.stdin_is_tty && interrupted() {
            reset_interrupt();
            self.stashed = line;
            out.write_all(b"\n")?;
            out.flush()?;
            return Ok(ReadOutcome::Interrupted);
        }
        let Some(line) = line else {
            out.write_all(b"\n")?;
            out.flush()?;
            return Ok(ReadOutcome::Eof);
        };
        if !self.stdin_is_tty {
            if secret {
                out.write_all(b"\n")?;
            } else {
                out.write_all(line.as_bytes())?;
                out.write_all(b"\n")?;
            }
            out.flush()?;
        }
        Ok(ReadOutcome::Line(String::clone(&line)))
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

    fn outcome(&mut self, prompt: &str, input: &mut dyn BufRead) -> io::Result<ReadOutcome> {
        let outcome = self.read_line_from(prompt, false, input)?;
        if self.interrupted_on_tty() {
            return Ok(ReadOutcome::Interrupted);
        }
        Ok(outcome)
    }
}

/// rpassword hidden read (terminal only); Ctrl-C → Interrupted, Ctrl-D → Eof.
pub(crate) fn rpassword_secret(prompt: &str) -> io::Result<SecretRead> {
    match rpassword::prompt_password(prompt) {
        Ok(secret) => Ok(SecretRead::Secret(SecretString::from(secret))),
        Err(err) if err.kind() == io::ErrorKind::Interrupted => {
            consume_raised_interrupt();
            Ok(SecretRead::Interrupted)
        }
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(SecretRead::Eof),
        Err(err) => Err(err),
    }
}

/// rpassword answers Ctrl-C by raising SIGINT, so the ctrlc handler thread sets the
/// interrupt flag shortly AFTER the read returned Interrupted. That interrupt is consumed
/// here (bounded wait for the handler, then reset) so it cannot discard the operator's next
/// plain read on a terminal.
fn consume_raised_interrupt() {
    for _ in 0..50 {
        if interrupted() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    reset_interrupt();
}

impl PlainReader {
    /// `read_command` over an explicit input (the global stdin lock; tests pass a cursor).
    pub(crate) fn read_command_from(
        &mut self,
        prompt: &str,
        input: &mut dyn BufRead,
    ) -> io::Result<ReadOutcome> {
        if self.stdin_is_tty {
            // only a Ctrl-C pressed during THIS read counts: a stale one (pressed while a
            // command ran that never checked the flag) must not swallow the next command
            reset_interrupt();
        }
        let outcome = match self.outcome(prompt, input) {
            Ok(outcome) => outcome,
            Err(err) => {
                self.pending = None;
                return Err(err);
            }
        };
        match &outcome {
            ReadOutcome::Line(line) => {
                let entry = match self.pending.take() {
                    Some(mut text) => {
                        text.push('\n');
                        text.push_str(line);
                        text
                    }
                    None => line.clone(),
                };
                if !line_is_complete(&entry) {
                    self.pending = Some(entry);
                } else if let Some(history) = self.history.as_mut() {
                    use reedline::History;
                    // one logical entry per command (reedline escapes the newlines);
                    // FileBackedHistory skips empty lines and repeats of the last entry, as
                    // prompt_toolkit did; the filter answers Ok for secret entries without
                    // storing them.
                    let _ = history.save(reedline::HistoryItem::from_command_line(entry));
                    let _ = history.sync();
                }
            }
            // the REPL drops the buffer too
            ReadOutcome::Interrupted | ReadOutcome::Eof => self.pending = None,
        }
        Ok(outcome)
    }
}

impl LineReader for PlainReader {
    fn read_command(&mut self, prompt: &str) -> std::io::Result<super::line::ReadOutcome> {
        self.read_command_from(prompt, &mut io::stdin().lock())
    }
    fn read_param(
        &mut self,
        prompt: &str,
        choices: &[String],
    ) -> std::io::Result<super::line::ReadOutcome> {
        let _ = choices;
        self.outcome(prompt, &mut io::stdin().lock())
    }
    fn read_secret(&mut self, prompt: &str) -> std::io::Result<super::line::SecretRead> {
        if self.stdin_is_tty {
            // the tty driver would echo a plain-read secret
            return rpassword_secret(prompt);
        }
        // piped: one plain line, never echoed (rpassword would open /dev/tty)
        Ok(match self.read_line(prompt, true)? {
            ReadOutcome::Line(line) => SecretRead::Secret(SecretString::from(line)),
            ReadOutcome::Interrupted => SecretRead::Interrupted,
            ReadOutcome::Eof => SecretRead::Eof,
        })
    }
}
pub type PlainIo = LineIo<PlainReader>;
