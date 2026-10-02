// reedline ⇄ !Send console bridge (spec §4.9.7; owner R7).
//
// reedline 0.49 needs `Send` extension points (`Box<dyn Completer + Send>`, `Highlighter:
// Send`, …) while AppContext is `!Send` by design. The boxes handed to reedline are
// zero-sized `Send` shims that look up the real, Rc-based `LineAssist` in a thread-local the
// REPL installs. reedline calls them synchronously from `read_line` on the REPL thread; on
// any other thread they find nothing and degrade to "no suggestions" / unstyled text. Every
// `LineAssist` call runs inside `catch_unwind`, so a panic in a `Command::complete` never
// unwinds through reedline's raw-mode `read_line`. No `unsafe`.
use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;

use nu_ansi_term::Style;
use reedline::{StyledText, Suggestion};

/// What run_repl installs for completion and highlighting. Implementations never call
/// `ctx.io` and swallow every ConsoleError (no suggestions / unstyled text).
pub trait LineAssist {
    fn complete(&self, line: &str, pos: usize) -> Vec<reedline::Suggestion>;
    fn highlight(&self, line: &str) -> reedline::StyledText;
}

thread_local! {
    static ACTIVE: RefCell<Option<Rc<dyn LineAssist>>> = const { RefCell::new(None) };
}

/// The installed assist, cloned out of the slot (no RefCell borrow is held while it runs).
fn active() -> Option<Rc<dyn LineAssist>> {
    ACTIVE
        .try_with(|slot| slot.try_borrow().ok().and_then(|slot| slot.clone()))
        .ok()
        .flatten()
}

/// Unstyled text: one plain span.
pub(crate) fn plain_text(line: &str) -> StyledText {
    let mut styled = StyledText::new();
    styled.push((Style::new(), line.to_owned()));
    styled
}

/// A panic caught inside completion/highlighting is logged, and its report (recorded by
/// r2-cli's panic hook) is taken so it can never be mistaken for a later command's.
fn discard_panic_report(what: &str) {
    let report = r2_core::runtime::take_panic_report();
    tracing::error!(
        target: "r2::console",
        "{what} failed: {}",
        report.as_deref().unwrap_or("panic")
    );
}

/// Zero-sized `Send` shims handed to reedline; they reach the thread-local LineAssist.
pub struct BridgeCompleter;
pub struct BridgeHighlighter;
impl reedline::Completer for BridgeCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<reedline::Suggestion> {
        let Some(assist) = active() else {
            return Vec::new();
        };
        catch_unwind(AssertUnwindSafe(|| assist.complete(line, pos))).unwrap_or_else(|_| {
            discard_panic_report("completion");
            Vec::<Suggestion>::new()
        })
    }
}
impl reedline::Highlighter for BridgeHighlighter {
    fn highlight(&self, line: &str, cursor: usize) -> reedline::StyledText {
        let _ = cursor;
        let Some(assist) = active() else {
            return plain_text(line);
        };
        catch_unwind(AssertUnwindSafe(|| assist.highlight(line))).unwrap_or_else(|_| {
            discard_panic_report("highlighting");
            plain_text(line)
        })
    }
}
/// RAII guard of `install_line_assist`; restores the previous slot value on drop.
pub struct AssistGuard {
    previous: Option<Rc<dyn LineAssist>>,
}
impl Drop for AssistGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        // Never panics: a slot that cannot be reached (thread teardown) or is borrowed is
        // left alone.
        let _ = ACTIVE.try_with(|slot| {
            if let Ok(mut slot) = slot.try_borrow_mut() {
                *slot = previous;
            }
        });
    }
}
/// Installs `assist` in the thread-local `Option<Rc<dyn LineAssist>>` slot.
pub fn install_line_assist(assist: Rc<dyn LineAssist>) -> AssistGuard {
    let previous = ACTIVE
        .try_with(|slot| match slot.try_borrow_mut() {
            Ok(mut slot) => slot.replace(assist),
            Err(_) => None,
        })
        .ok()
        .flatten();
    AssistGuard { previous }
}
