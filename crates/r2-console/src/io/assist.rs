#![allow(dead_code)]
// R0 skeleton — owner R7 (generated from spec §4)
// ---- spec §4.9.7 block 6
use std::rc::Rc;

/// What run_repl installs for completion and highlighting. Implementations never call
/// `ctx.io` and swallow every ConsoleError (no suggestions / unstyled text).
pub trait LineAssist {
    fn complete(&self, line: &str, pos: usize) -> Vec<reedline::Suggestion>;
    fn highlight(&self, line: &str) -> reedline::StyledText;
}
/// Zero-sized `Send` shims handed to reedline; they reach the thread-local LineAssist.
pub struct BridgeCompleter;
pub struct BridgeHighlighter;
impl reedline::Completer for BridgeCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<reedline::Suggestion> {
        let _ = (line, pos);
        unimplemented!("R7")
    }
}
impl reedline::Highlighter for BridgeHighlighter {
    fn highlight(&self, line: &str, cursor: usize) -> reedline::StyledText {
        let _ = (line, cursor);
        unimplemented!("R7")
    }
}
/// RAII guard of `install_line_assist`; restores the previous slot value on drop.
pub struct AssistGuard {}
/// Installs `assist` in the thread-local `Option<Rc<dyn LineAssist>>` slot.
pub fn install_line_assist(assist: Rc<dyn LineAssist>) -> AssistGuard {
    let _ = assist;
    unimplemented!("R7")
}
