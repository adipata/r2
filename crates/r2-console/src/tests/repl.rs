// REPL session tests (spec §4.9.5) — the port of c2 tests/unit/console/test_repl.py (R7).
// c2 fed prompt_toolkit pipe input through a full PromptToolkitIO REPL; r2 runs `run_repl`
// over LineIo with a scripted reader (one step per physical line, EOF when the script ends),
// capturing the sink output. The ScriptedIo fallback-path cases use ScriptedIo itself.
use std::rc::Rc;

use r2_core::error::ConsoleError;
use r2_core::io::{ConsoleIo, Renderable};
use r2_core::text::{py_bool, py_repr};
use r2_testkit::{ScriptedIo, global_state_lock};

use super::io::{Step, harness, line};
use crate::commands::{Command, all_commands};
use crate::context::AppContext;
use crate::parser::BoundArgs;
use crate::repl::{CommandTable, Flow, run_repl};
use crate::testing::CtxBuilder;

/// Test-only command: prints its first positional (repr) + quoted flag.
struct EchoCommand;
impl Command for EchoCommand {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn summary(&self) -> &'static str {
        "echo test command"
    }
    fn usage(&self) -> &'static str {
        "echo <data>"
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        ctx.io.print(Renderable::Text(format!(
            "echo:{}:quoted={}",
            py_repr(&args.positionals[0]),
            py_bool(args.positional_quoted[0])
        )));
        Ok(Flow::Continue)
    }
}

struct AbortCommand;
impl Command for AbortCommand {
    fn name(&self) -> &'static str {
        "abortme"
    }
    fn summary(&self) -> &'static str {
        "raises UserAbort"
    }
    fn usage(&self) -> &'static str {
        "abortme"
    }
    fn run(&self, _ctx: &AppContext, _args: &BoundArgs) -> r2_core::Result<Flow> {
        Err(ConsoleError::user_abort("operator hit Ctrl-C"))
    }
}

/// c2 BoomCommand raised a non-ConsoleError; the r2 analogue is a panic.
struct BoomCommand;
impl Command for BoomCommand {
    fn name(&self) -> &'static str {
        "boom"
    }
    fn summary(&self) -> &'static str {
        "panics"
    }
    fn usage(&self) -> &'static str {
        "boom"
    }
    fn run(&self, _ctx: &AppContext, _args: &BoundArgs) -> r2_core::Result<Flow> {
        panic!("kaputt")
    }
}

/// Checks the Ctrl-C flag at a step boundary (§4.9.8).
struct StepCommand;
impl Command for StepCommand {
    fn name(&self) -> &'static str {
        "step"
    }
    fn summary(&self) -> &'static str {
        "checks the interrupt flag"
    }
    fn usage(&self) -> &'static str {
        "step"
    }
    fn run(&self, ctx: &AppContext, _args: &BoundArgs) -> r2_core::Result<Flow> {
        r2_core::runtime::check_interrupt()?;
        ctx.io.print(Renderable::Text("step done".to_owned()));
        Ok(Flow::Continue)
    }
}

fn commands_with_extras() -> Rc<CommandTable> {
    let mut commands: CommandTable = (*all_commands().unwrap()).clone();
    let extras: [Rc<dyn Command>; 4] = [
        Rc::new(EchoCommand),
        Rc::new(AbortCommand),
        Rc::new(BoomCommand),
        Rc::new(StepCommand),
    ];
    for command in extras {
        commands.insert(command.name(), command);
    }
    Rc::new(commands)
}

/// Feed `steps` through a full LineIo REPL; return the sink output.
fn run_steps(steps: Vec<Step>, debug: bool) -> String {
    let h = harness(steps);
    let ctx = CtxBuilder::new(Rc::clone(&h.io) as Rc<dyn ConsoleIo>).build();
    run_repl(&ctx, debug, commands_with_extras());
    h.text()
}

/// c2 `run_session`: the input split into physical lines; the closed pipe reads as EOF.
fn run_session(user_input: &str, debug: bool) -> String {
    let steps = user_input
        .split_inclusive('\n')
        .map(|chunk| line(chunk.strip_suffix('\n').unwrap_or(chunk)))
        .collect();
    run_steps(steps, debug)
}

#[test]
fn test_help_then_exit() {
    let out = run_session("help\nexit\n", false);
    for name in ["help", "exit", "quit", "clear", "config"] {
        assert!(out.contains(name), "{name}");
    }
    assert!(out.contains("summary"));
}

#[test]
fn test_exit_via_repl_exit_ends_the_session() {
    let out = run_session("exit\nhelp\n", false);
    // the session ended at `exit`: the later `help` was never dispatched
    assert!(!out.contains("List commands"));
    assert_eq!(out, "");
}

#[test]
fn test_quit_is_an_alias() {
    assert_eq!(run_session("quit\n", false), ""); // returns without needing more input
}

#[test]
fn test_ctrl_d_exits_cleanly() {
    // the script ends without an exit command → EOF at the prompt → clean return
    assert_eq!(run_session("", false), "");
}

#[test]
fn test_unknown_command_gets_suggestion() {
    let out = run_session("helpp\nexit\n", false);
    assert!(out.contains("unknown command 'helpp'"));
    assert!(out.contains("did you mean"));
    assert!(out.contains("help"));
    assert!(out.contains("hint: did you mean: help"));
}

#[test]
fn test_quoted_multiline_paste_binds_one_positional() {
    let out = run_session("echo \"line one\nline two\"\nexit\n", false);
    assert!(out.contains("echo:'line one\\nline two':quoted=True"));
}

#[test]
fn test_empty_lines_are_ignored() {
    let out = run_session("\n   \nexit\n", false);
    assert!(!out.contains("unknown command"));
    assert_eq!(out, "");
}

#[test]
fn test_user_abort_renders_single_aborted_line() {
    let out = run_session("abortme\nexit\n", false);
    assert!(out.contains("Aborted."));
    assert!(!out.contains("operator hit Ctrl-C")); // not an error panel (§5.1)
    assert_eq!(out, "Aborted.\n");
}

#[test]
fn test_parse_error_echoes_caret() {
    let out = run_session("help --\nexit\n", false);
    assert!(out.contains("empty option name"));
    assert!(out.contains('^'));
    assert!(out.contains("help --"));
    // the caret echo comes before the panel, under the offending token
    assert!(out.starts_with("help --\n     ^\n"));
}

/// The r2-cli panic hook's shape (§4.9.11): records "{message} at {location}\n{backtrace}".
fn install_recording_hook() {
    std::panic::set_hook(Box::new(|info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        r2_core::runtime::record_panic_report(format!(
            "{message} at {location}\nstack backtrace:\n<frames>"
        ));
    }));
}

#[test]
fn test_unexpected_error_short_message_and_log_pointer() {
    let _lock = global_state_lock();
    install_recording_hook();
    let out = run_session("boom\nexit\n", false);
    let _ = std::panic::take_hook();
    assert!(out.contains("unexpected error: kaputt"));
    assert!(out.contains("details logged to"));
    assert!(!out.contains("stack backtrace")); // no traceback without --debug
    // the hint names the configured log file
    let config = crate::testing::make_config(None);
    assert!(out.contains(&format!(
        "hint: details logged to {}",
        config.app.log.file.display()
    )));
    // the session continued after the panic: `exit` ran and nothing else was printed
    assert!(r2_core::runtime::take_panic_report().is_none());
}

#[test]
fn test_unexpected_error_with_debug_prints_traceback() {
    let _lock = global_state_lock();
    install_recording_hook();
    let out = run_session("boom\nexit\n", true);
    let _ = std::panic::take_hook();
    assert!(out.contains("stack backtrace"));
    assert!(out.contains("kaputt at "));
    assert!(out.contains("src/tests/repl.rs"));
    // the report precedes the panel
    let report = out.find("kaputt at ").unwrap();
    let panel = out.find("unexpected error: kaputt").unwrap();
    assert!(report < panel);
}

#[test]
fn unexpected_error_without_a_hook_uses_the_payload() {
    let _lock = global_state_lock();
    let out = run_session("boom\nexit\n", true);
    assert!(out.contains("unexpected error: kaputt"));
}

#[test]
fn test_console_error_rendered_only_at_repl_boundary() {
    // `help nosuch` fails inside the command; the loop renders one panel
    let out = run_session("help nosuch\nexit\n", false);
    assert!(out.contains("unknown command 'nosuch'"));
    assert_eq!(out.matches("╭─ error").count(), 1);
}

#[test]
fn test_scripted_io_drives_the_repl_fallback_read_path() {
    let scripted = Rc::new(ScriptedIo::new(["help", "exit"]));
    let ctx = CtxBuilder::new(Rc::clone(&scripted) as Rc<dyn ConsoleIo>).build();
    run_repl(&ctx, false, all_commands().unwrap());
    assert_eq!(scripted.prompts()[0], "r2> ");
    assert!(scripted.output().iter().any(|line| line.contains("shows its usage")));
}

#[test]
fn test_scripted_io_multiline_continuation_prompt() {
    let scripted = Rc::new(ScriptedIo::new(["echo \"part one", "part two\"", "exit"]));
    let ctx = CtxBuilder::new(Rc::clone(&scripted) as Rc<dyn ConsoleIo>).build();
    run_repl(&ctx, false, commands_with_extras());
    assert_eq!(scripted.prompts()[..2], ["r2> ", "…> "]);
    assert!(
        scripted
            .output()
            .iter()
            .any(|line| line.contains("echo:'part one\\npart two':quoted=True"))
    );
}

#[test]
fn test_exit_command_raises_repl_exit_directly() {
    let ctx = CtxBuilder::new(Rc::new(ScriptedIo::empty()) as Rc<dyn ConsoleIo>).build();
    let exit = all_commands().unwrap()["exit"].clone();
    assert_eq!(exit.run(&ctx, &BoundArgs::default()).unwrap(), Flow::Exit);
}

// -- r2: the §5.1 Ctrl-C / Ctrl-D table and the read-error path ----------------

#[test]
fn ctrl_c_at_the_prompt_prints_aborted_and_reprompts() {
    let out = run_steps(vec![Step::CtrlC, line("echo x"), line("exit")], false);
    assert_eq!(out, "Aborted.\necho:'x':quoted=False\n");
}

#[test]
fn ctrl_c_in_a_continuation_aborts_the_whole_buffer() {
    let out = run_steps(
        vec![line("echo \"open"), Step::CtrlC, line("echo y"), line("exit")],
        false,
    );
    assert_eq!(out, "Aborted.\necho:'y':quoted=False\n");
}

#[test]
fn eof_in_a_continuation_leaves_the_repl() {
    let out = run_steps(vec![line("echo \"open"), Step::Eof, line("echo y")], false);
    assert_eq!(out, "");
}

#[test]
fn reader_errors_are_rendered_and_end_the_repl() {
    // §11 D12 (c): c2 let the exception escape as a traceback
    let out = run_steps(vec![Step::Fail, line("echo y")], false);
    assert!(out.contains("cannot read input: Input/output error"));
    assert!(!out.contains("echo:"));
}

#[test]
fn the_interrupt_flag_is_reset_before_every_dispatch() {
    let _lock = global_state_lock();
    r2_core::runtime::request_interrupt(); // stale flag (e.g. rpassword's raise(SIGINT))
    let out = run_session("step\nexit\n", false);
    assert_eq!(out, "step done\n");
    r2_core::runtime::reset_interrupt();
}

#[test]
fn a_user_abort_inside_a_prompt_flow_is_aborted_too() {
    struct AskCommand;
    impl Command for AskCommand {
        fn name(&self) -> &'static str {
            "ask"
        }
        fn summary(&self) -> &'static str {
            "x"
        }
        fn usage(&self) -> &'static str {
            "ask"
        }
        fn run(&self, ctx: &AppContext, _args: &BoundArgs) -> r2_core::Result<Flow> {
            ctx.io.prompt(&r2_core::params::ParamSpec::str("hash", "Hash"))?;
            Ok(Flow::Continue)
        }
    }
    let h = harness(vec![line("ask"), Step::Eof, line("exit")]);
    let ctx = CtxBuilder::new(Rc::clone(&h.io) as Rc<dyn ConsoleIo>).build();
    let mut commands: CommandTable = (*all_commands().unwrap()).clone();
    commands.insert("ask", Rc::new(AskCommand));
    run_repl(&ctx, false, Rc::new(commands));
    // EOF in a param prompt → UserAbort → "Aborted."; the session goes on until `exit`
    assert_eq!(h.text(), "Aborted.\n");
}
