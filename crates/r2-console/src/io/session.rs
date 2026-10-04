// Interactive key sessions (spec §4.9.7, §11 D34; owner R7): the TerminalIo side of
// `ConsoleIo::interactive`. A `FrameSession` draws each `Frame` in place on the rows below
// the output so far — never the alternate screen — by moving the cursor back to the frame's
// first row and overwriting it; it tracks how many rows it drew and which row the cursor is
// on, so the next frame (or the final erase) starts at the right place. The terminal itself
// sits behind `TerminalDriver` (crossterm in TerminalIo, a recording double in the tests),
// so everything but the raw terminal calls is unit-tested.
use std::io;

use r2_core::error::{ConsoleError, Result};
use r2_core::io::{Frame, Key, KeySession, Line, Span};
use r2_core::text::os_error_text;
use unicode_width::UnicodeWidthChar;
use zeroize::Zeroizing;

/// One terminal operation of a frame update (the driver maps them to crossterm commands,
/// which pick ANSI or the Windows console API).
#[derive(Debug, PartialEq, Eq)]
pub enum TermOp {
    /// Cursor up this many rows (never 0: most terminals read `CSI 0 A` as one row).
    Up(u16),
    /// Cursor to this column of the current row (0-based).
    Column(u16),
    /// Erase from the cursor to the end of its row.
    ClearLineRight,
    /// Erase from the cursor to the end of the screen.
    ClearDown,
    /// Erase the whole screen and home the cursor (after the terminal narrowed: it may
    /// have re-wrapped the previous frame, so its rows can no longer be found).
    ClearScreen,
    /// Styled text of one row (it may carry template values: wiped on drop, D3).
    Text(Zeroizing<String>),
    /// CR LF: the next row, scrolling at the bottom of the screen.
    Newline,
    ShowCursor,
    HideCursor,
}

/// The raw terminal behind a `FrameSession` (R7-internal).
pub trait TerminalDriver {
    /// Raw mode on, auto-wrap off, bracketed paste on (best effort: legacy Windows consoles
    /// have none). An error leaves nothing to undo but what `leave` undoes.
    fn enter(&mut self) -> io::Result<()>;
    /// (columns, rows).
    fn size(&self) -> io::Result<(u16, u16)>;
    /// The next key the session uses (other events are skipped).
    fn read_key(&mut self) -> io::Result<Key>;
    /// Perform `ops` in order and flush.
    fn apply(&mut self, ops: &[TermOp]) -> io::Result<()>;
    /// Undo `enter` and show the cursor. Never fails, never panics.
    fn leave(&mut self);
}

/// Display width of `c` in terminal cells (control characters are shown as U+FFFD, width
/// 1).
pub(crate) fn char_cells(c: char) -> usize {
    if c.is_control() {
        1
    } else {
        c.width().unwrap_or(0)
    }
}

/// Display width of `text` in terminal cells (`char_cells` per character).
pub(crate) fn text_cells(text: &str) -> usize {
    text.chars().map(char_cells).sum()
}

/// `line` cut to at most `width` cells, control characters replaced by U+FFFD (a raw ESC
/// from a token label would otherwise reach the terminal and move the cursor).
pub(crate) fn clip_line(line: &Line, width: usize) -> Line {
    let mut out = Vec::new();
    let mut used = 0;
    for span in line {
        let mut text = String::new();
        for c in span.text.chars() {
            let cells = char_cells(c);
            if used + cells > width {
                if !text.is_empty() {
                    out.push(Span {
                        text,
                        tone: span.tone,
                    });
                }
                return out;
            }
            used += cells;
            text.push(if c.is_control() { '\u{fffd}' } else { c });
        }
        if !text.is_empty() {
            out.push(Span {
                text,
                tone: span.tone,
            });
        }
    }
    out
}

fn rows(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// The Generic error a failed terminal call becomes inside the session.
fn terminal_error(err: &io::Error) -> ConsoleError {
    ConsoleError::generic(format!("terminal error: {}", os_error_text(err)))
}

/// The in-place frame drawer behind `ConsoleIo::interactive` (R7-internal).
pub struct FrameSession<'a> {
    driver: Box<dyn TerminalDriver>,
    /// The sink's styled rendering of one row (no wrapping; §4.9.7).
    render: &'a dyn Fn(&Line) -> String,
    /// Rows of the frame currently on screen.
    drawn: usize,
    /// The frame row the terminal cursor is on.
    cursor_row: usize,
    /// The width the current frame was drawn at.
    width: Option<usize>,
    /// The first terminal error; after it the session draws and reads nothing more.
    failure: Option<io::Error>,
    open: bool,
}

impl<'a> FrameSession<'a> {
    /// `driver.enter()`; on its error the driver is left again and the error returned.
    pub fn open(
        mut driver: Box<dyn TerminalDriver>,
        render: &'a dyn Fn(&Line) -> String,
    ) -> io::Result<Self> {
        if let Err(err) = driver.enter() {
            driver.leave();
            return Err(err);
        }
        Ok(Self {
            driver,
            render,
            drawn: 0,
            cursor_row: 0,
            width: None,
            failure: None,
            open: true,
        })
    }

    fn fail(&mut self, err: io::Error) -> ConsoleError {
        let error = terminal_error(&err);
        if self.failure.is_none() {
            self.failure = Some(err);
        }
        error
    }

    fn failed(&self) -> Option<ConsoleError> {
        self.failure.as_ref().map(terminal_error)
    }

    /// Ops that put the cursor back on the frame's first row, column 0.
    fn to_top(&self, ops: &mut Vec<TermOp>) {
        if self.cursor_row > 0 {
            ops.push(TermOp::Up(rows(self.cursor_row)));
        }
        ops.push(TermOp::Column(0));
    }

    /// Erase the frame, show the cursor, leave the terminal; returns the first terminal
    /// error of the session (the reader then degrades).
    pub fn close(mut self) -> Option<io::Error> {
        self.shut();
        self.failure.take()
    }

    fn shut(&mut self) {
        if !self.open {
            return;
        }
        self.open = false;
        if self.failure.is_none() {
            let mut ops = Vec::new();
            if self.drawn > 0 {
                self.to_top(&mut ops);
                ops.push(TermOp::ClearDown);
            }
            ops.push(TermOp::ShowCursor);
            if let Err(err) = self.driver.apply(&ops) {
                self.failure = Some(err);
            }
        }
        self.drawn = 0;
        self.driver.leave();
    }
}

impl KeySession for FrameSession<'_> {
    fn size(&self) -> (usize, usize) {
        match self.driver.size() {
            Ok((columns, rows)) => (usize::from(columns).max(1), usize::from(rows).max(1)),
            Err(_) => (80, 24),
        }
    }

    fn draw(&mut self, frame: &Frame) -> Result<()> {
        if let Some(err) = self.failed() {
            return Err(err);
        }
        let (width, height) = self.size();
        let clip = width.saturating_sub(1).max(1);
        let lines: Vec<&Line> = frame
            .lines
            .iter()
            .take(height.saturating_sub(1).max(1))
            .collect();
        let mut ops = vec![TermOp::HideCursor];
        if self.drawn > 0 && self.width.is_some_and(|before| width < before) {
            ops.push(TermOp::ClearScreen);
        } else if self.drawn > 0 {
            self.to_top(&mut ops);
        } else {
            ops.push(TermOp::Column(0));
        }
        for (index, line) in lines.iter().enumerate() {
            if index > 0 {
                ops.push(TermOp::Newline);
            }
            let text = Zeroizing::new((self.render)(&clip_line(line, clip)));
            ops.push(TermOp::Text(text));
            ops.push(TermOp::ClearLineRight);
        }
        ops.push(TermOp::ClearDown);
        let last = lines.len().saturating_sub(1);
        self.cursor_row = last;
        if let Some((row, column)) = frame.cursor.filter(|_| !lines.is_empty()) {
            let row = row.min(last);
            if last > row {
                ops.push(TermOp::Up(rows(last - row)));
            }
            ops.push(TermOp::Column(rows(column.min(clip))));
            ops.push(TermOp::ShowCursor);
            self.cursor_row = row;
        }
        self.drawn = lines.len();
        self.width = Some(width);
        self.driver.apply(&ops).map_err(|err| self.fail(err))
    }

    fn read_key(&mut self) -> Result<Key> {
        if let Some(err) = self.failed() {
            return Err(err);
        }
        self.driver.read_key().map_err(|err| self.fail(err))
    }
}

impl Drop for FrameSession<'_> {
    fn drop(&mut self) {
        // Unwinding out of `f`: only restore the terminal (no drawing while panicking).
        if std::thread::panicking() {
            if self.open {
                self.open = false;
                self.driver.leave();
            }
            return;
        }
        self.shut();
    }
}
