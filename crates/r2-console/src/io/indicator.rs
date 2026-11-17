// The key cache prompt indicator (spec §5.19): "⠹ cache hsm 120/4800 · Ctrl+G stops",
// right-aligned on the prompt line while a cache loads.
//
// reedline 0.49 draws the right prompt only when it repaints (on input), so the text is
// also redrawn in place from reedline's idle callback (every 100 ms while it waits for a
// key). That redraw only happens when the whole input sits on the prompt row and leaves
// room for the text: the console records the layout reedline last painted (prompt, buffer,
// hint, search mode) and applies reedline's own fit rule, so the idle redraw only ever
// writes cells that hold the indicator or are blank. Everything runs on the REPL thread.
use std::cell::RefCell;
use std::io::{self, Write};

use unicode_width::UnicodeWidthStr;

#[derive(Default)]
struct Layout {
    /// The left prompt + indicator text of the last repaint.
    left: String,
    /// The buffer and hint of the last repaint.
    buffer: String,
    hint: String,
    /// Reverse history search is showing (its layout is not tracked: no idle redraw).
    search: bool,
    /// The right prompt text reedline painted last (set by `render_prompt_right`).
    painted: String,
    /// A repaint happened since the idle redraw last looked.
    repainted: bool,
    /// Where the indicator currently is on the prompt row: (start column, width).
    drawn: Option<(u16, u16)>,
    /// Draw in colour (dark grey), as reedline does with ANSI colours on.
    color: bool,
}

thread_local! {
    static LAYOUT: RefCell<Layout> = RefCell::new(Layout::default());
}

fn with<T>(f: impl FnOnce(&mut Layout) -> T) -> Option<T> {
    LAYOUT
        .try_with(|layout| layout.try_borrow_mut().ok().map(|mut l| f(&mut l)))
        .ok()
        .flatten()
}

pub(crate) fn set_color(color: bool) {
    with(|l| l.color = color);
}

/// `Prompt::render_prompt_right` of the command prompt: the text, recorded as painted.
pub(crate) fn right_prompt() -> String {
    let text = crate::cache::indicator_text();
    with(|l| {
        l.painted = text.clone();
        l.repainted = true;
    });
    text
}

/// The prompt's left part as painted (prompt text + mode indicator).
pub(crate) fn note_left(left: &str, search: bool) {
    with(|l| {
        l.left = left.to_owned();
        l.search = search;
    });
}

/// The buffer reedline highlights (= paints).
pub(crate) fn note_buffer(buffer: &str) {
    with(|l| buffer.clone_into(&mut l.buffer));
}

/// The hint reedline paints after the buffer.
pub(crate) fn note_hint(hint: &str) {
    with(|l| hint.clone_into(&mut l.hint));
}

/// A new read starts: nothing of ours is on screen yet.
pub(crate) fn reset() {
    with(|l| {
        l.drawn = None;
        l.repainted = false;
    });
}

/// Width of the input on the prompt row, or None when the input spans several rows.
fn input_width(l: &Layout) -> Option<usize> {
    let rest = format!("{}{}", l.buffer, l.hint);
    if l.search || rest.contains('\n') || l.left.contains('\n') {
        return None;
    }
    Some(l.left.width() + rest.width())
}

/// reedline's rule (`Painter::print_right_prompt`): the right prompt is painted when the
/// input fits before its start column.
fn fits(input: usize, text: &str, columns: u16) -> Option<u16> {
    let width = u16::try_from(text.width()).ok()?;
    let start = columns.checked_sub(width)?;
    (!text.is_empty() && input <= usize::from(start)).then_some(start)
}

/// reedline's idle callback: deliver notices of finished loads above the prompt (through
/// the external printer, which repaints) and redraw the indicator in place.
pub(crate) fn idle_tick(print: &dyn Fn(String)) {
    for line in crate::cache::take_notices(false) {
        print(line);
    }
    let Ok((columns, _)) = crossterm::terminal::size() else {
        return;
    };
    let text = crate::cache::indicator_text();
    let _ = with(|l| redraw(l, &text, columns));
}

fn redraw(l: &mut Layout, text: &str, columns: u16) -> io::Result<()> {
    let Some(input) = input_width(l) else {
        l.drawn = None;
        return Ok(());
    };
    if std::mem::take(&mut l.repainted) {
        // what reedline painted at its last repaint
        l.drawn = fits(input, &l.painted, columns)
            .and_then(|start| Some((start, u16::try_from(l.painted.width()).ok()?)));
    }
    let target = fits(input, text, columns);
    if target.is_none() && l.drawn.is_none() {
        return Ok(());
    }
    use crossterm::cursor::{MoveToColumn, RestorePosition, SavePosition};
    use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
    let mut out = io::stdout().lock();
    crossterm::queue!(out, SavePosition)?;
    // blank the old cells the new text will not cover (they were ours)
    if let Some((start, width)) = l.drawn {
        let keep_from = target.unwrap_or(start + width);
        if start < keep_from {
            let blank = usize::from(keep_from.min(start + width) - start);
            crossterm::queue!(out, MoveToColumn(start), Print(" ".repeat(blank)))?;
        }
    }
    match target {
        Some(start) => {
            crossterm::queue!(out, MoveToColumn(start))?;
            if l.color {
                crossterm::queue!(
                    out,
                    SetForegroundColor(Color::DarkGrey),
                    Print(text),
                    ResetColor
                )?;
            } else {
                crossterm::queue!(out, Print(text))?;
            }
            l.drawn = u16::try_from(text.width()).ok().map(|w| (start, w));
        }
        None => l.drawn = None,
    }
    crossterm::queue!(out, RestorePosition)?;
    out.flush()
}

/// The command editor's hinter: reedline's DefaultHinter, with the painted hint recorded.
pub(crate) struct RecordingHinter(pub(crate) reedline::DefaultHinter);

impl reedline::Hinter for RecordingHinter {
    fn handle(
        &mut self,
        line: &str,
        pos: usize,
        history: &dyn reedline::History,
        use_ansi_coloring: bool,
        cwd: &str,
    ) -> String {
        let styled = self.0.handle(line, pos, history, use_ansi_coloring, cwd);
        note_hint(&self.0.complete_hint());
        styled
    }
    fn complete_hint(&self) -> String {
        self.0.complete_hint()
    }
    fn next_hint_token(&self) -> String {
        self.0.next_hint_token()
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn fits_follows_reedlines_rule() {
        assert_eq!(fits(10, "abcde", 20), Some(15));
        assert_eq!(fits(15, "abcde", 20), Some(15));
        assert_eq!(fits(16, "abcde", 20), None);
        assert_eq!(fits(0, "", 20), None);
        assert_eq!(fits(0, "abcde", 3), None);
    }

    #[test]
    fn multi_row_input_is_never_redrawn() {
        let mut l = Layout {
            left: "r2> ".into(),
            buffer: "sign 'a\nb".into(),
            ..Layout::default()
        };
        assert_eq!(input_width(&l), None);
        l.buffer = "keys".into();
        l.hint = " hsm".into();
        assert_eq!(input_width(&l), Some(12));
        l.search = true;
        assert_eq!(input_width(&l), None);
    }
}
