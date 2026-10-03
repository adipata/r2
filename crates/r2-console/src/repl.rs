// The REPL loop (spec §4.9.5; owner R7) — the port of c2 `console/repl.py`.
//
// The loop is the ONLY place errors are rendered (§4.2): UserAbort → `Aborted.`; Parse →
// caret echo + error panel; any other ConsoleError → error panel; a panic inside a command
// (caught per dispatch) → "unexpected error: …" with a log pointer (+ the backtrace with
// `--debug`). Commands and services return errors, never print them.
use std::any::Any;
use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;

use r2_core::error::{ConsoleError, ErrorKind};
use r2_core::io::{CommandInput, Renderable, caret};
use r2_core::runtime::{reset_interrupt, reset_operation_time, take_panic_report};

use crate::commands::Command;
use crate::completer::ConsoleAssist;
use crate::context::AppContext;
use crate::io::install_line_assist;
use crate::parser::{bind_args, line_is_complete, tokenize};
use crate::render::suggest;

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

/// The outcome of one read phase.
enum Read {
    Buffer(String),
    Aborted,
    Leave,
}

/// c2's read loop: one line, then `…> ` continuations while a quote is open.
fn read_buffer(ctx: &AppContext) -> Read {
    let mut prompt = PROMPT;
    let mut buffer: Option<String> = None;
    loop {
        match ctx.io.read_command(prompt) {
            Ok(CommandInput::Line(line)) => {
                let text = match buffer.take() {
                    Some(mut text) => {
                        text.push('\n');
                        text.push_str(&line);
                        text
                    }
                    None => line,
                };
                if line_is_complete(&text) {
                    return Read::Buffer(text);
                }
                buffer = Some(text);
                prompt = CONTINUATION_PROMPT;
            }
            Ok(CommandInput::Interrupted) => return Read::Aborted,
            Ok(CommandInput::Eof) => return Read::Leave,
            // only PlainReader I/O errors get here (§11 D12 (c))
            Err(err) => {
                ctx.io.print_error(&err);
                return Read::Leave;
            }
        }
    }
}

/// The text of a panic payload (`&str` / `String`), as `{err}` of c2's catch-all.
fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "Box<dyn Any>".to_owned()
    }
}

/// The interactive loop (algorithm below). r2-cli obtains `commands` from
/// `commands::all_commands()` BEFORE calling it (an Err there — e.g. a duplicate command
/// name — is a startup error: stderr "error: …", exit 2). Returns when the operator exits;
/// never returns an error (everything is rendered).
pub fn run_repl(ctx: &Rc<AppContext>, debug: bool, commands: Rc<CommandTable>) {
    let _assist = install_line_assist(Rc::new(ConsoleAssist::new(
        Rc::clone(ctx),
        Rc::clone(&commands),
    )));
    loop {
        let buffer = match read_buffer(ctx) {
            Read::Buffer(buffer) => buffer,
            Read::Aborted => {
                ctx.io.print(Renderable::Text("Aborted.".to_owned()));
                continue;
            }
            Read::Leave => break,
        };
        reset_interrupt();
        let outcome = catch_unwind(AssertUnwindSafe(|| dispatch(ctx, &commands, &buffer)));
        match outcome {
            Ok(Ok(Flow::Exit)) => break,
            Ok(Ok(Flow::Continue)) => {}
            Ok(Err(err)) => render_error(ctx, &err),
            Err(payload) => {
                let message = panic_message(payload.as_ref());
                let report = take_panic_report();
                tracing::error!(
                    target: "r2::console",
                    "unexpected error: {}",
                    report.as_deref().unwrap_or(&message)
                );
                if debug && let Some(report) = &report {
                    ctx.io.print(Renderable::Text(report.clone()));
                }
                ctx.io.print_error(
                    &ConsoleError::generic(format!("unexpected error: {message}")).with_hint(
                        format!("details logged to {}", ctx.cfg().app.log.file.display()),
                    ),
                );
            }
        }
    }
}

/// The single error-rendering boundary (§4.2).
fn render_error(ctx: &AppContext, err: &ConsoleError) {
    match &err.kind {
        ErrorKind::UserAbort => ctx.io.print(Renderable::Text("Aborted.".to_owned())),
        ErrorKind::Parse { line, pos } => {
            ctx.io.print(caret(line, *pos));
            ctx.io.print_error(err);
        }
        _ => {
            tracing::debug!(target: "r2::console", "command failed: {}", err.message);
            ctx.io.print_error(err);
        }
    }
}

/// One logical line through tokenize → lookup → bind_args → run (no rendering). Used by
/// run_repl and by tests (`testing::run_line`).
pub fn dispatch(ctx: &AppContext, commands: &CommandTable, line: &str) -> r2_core::Result<Flow> {
    let tokens = tokenize(line)?;
    let Some(first) = tokens.first() else {
        return Ok(Flow::Continue);
    };
    let name = first.text.as_str();
    let Some(command) = commands.get(name) else {
        let names: Vec<&str> = commands.keys().copied().collect();
        return Err(
            ConsoleError::unknown_operation(format!("unknown command '{name}'")).with_hint(
                suggest(name, &names)
                    .unwrap_or_else(|| "type 'help' for the command list".to_owned()),
            ),
        );
    };
    let args = bind_args(&tokens[1..], command.flags(), line)?;
    // the name only — the line may carry secrets (§6)
    tracing::debug!(target: "r2::console", "command: {name}");
    reset_operation_time(); // §11 D31: no provider time leaks into this command
    command.run(ctx, &args)
}
