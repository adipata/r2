// R0 skeleton — owner R7 (generated from spec §4)
use crate::commands::Command;
use crate::context::AppContext;
use std::collections::BTreeMap;
use std::rc::Rc;

pub const PROMPT: &str = "r2> ";
pub const CONTINUATION_PROMPT: &str = "…> ";

/// What a command asks the REPL to do next. `Exit` replaces c2's `ReplExit` (raised by
/// `exit`/`quit`); it never crosses the console boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Exit,
}

/// Command name → command (sorted by name).
pub type CommandTable = BTreeMap<&'static str, Rc<dyn Command>>;

/// The interactive loop (algorithm below). r2-cli obtains `commands` from
/// `commands::all_commands()` BEFORE calling it (an Err there — e.g. a duplicate command
/// name — is a startup error: stderr "error: …", exit 2). Returns when the operator exits;
/// never returns an error (everything is rendered).
pub fn run_repl(ctx: &Rc<AppContext>, debug: bool, commands: Rc<CommandTable>) {
    let _ = (ctx, debug, commands);
    unimplemented!("R7")
}

/// One logical line through tokenize → lookup → bind_args → run (no rendering). Used by
/// run_repl and by tests (`testing::run_line`).
pub fn dispatch(ctx: &AppContext, commands: &CommandTable, line: &str) -> r2_core::Result<Flow> {
    let _ = (ctx, commands, line);
    Err(r2_core::ConsoleError::not_implemented("R7"))
}
