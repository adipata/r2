// The `help` command (spec §5.1; owner R7) — c2 `console/commands/help_cmd.py`.
use r2_core::error::ConsoleError;
use r2_core::io::{Renderable, table};

use crate::cmdutil::completed_args;
use crate::commands::{Command, all_commands};
use crate::context::AppContext;
use crate::parser::BoundArgs;
use crate::render::suggest;
use crate::repl::Flow;

struct HelpCommand;

impl Command for HelpCommand {
    fn name(&self) -> &'static str {
        "help"
    }
    fn summary(&self) -> &'static str {
        "List commands, or show usage for one command"
    }
    fn usage(&self) -> &'static str {
        "help [<command>]"
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        let commands = all_commands()?;
        let Some(wanted) = args.positionals.first() else {
            let rows = commands
                .values()
                .map(|command| vec![command.name().to_owned(), command.summary().to_owned()])
                .collect();
            ctx.io
                .print(table(Some("commands"), &["command", "summary"], rows));
            ctx.io.print(Renderable::Text(
                "help <command> shows its usage".to_owned(),
            ));
            return Ok(Flow::Continue);
        };
        let Some(command) = commands.get(wanted.as_str()) else {
            let names: Vec<&str> = commands.keys().copied().collect();
            return Err(
                ConsoleError::unknown_operation(format!("unknown command '{wanted}'")).with_hint(
                    suggest(wanted, &names)
                        .unwrap_or_else(|| "type 'help' for the command list".to_owned()),
                ),
            );
        };
        ctx.io
            .print(Renderable::Text(format!("usage: {}", command.usage())));
        ctx.io.print(Renderable::Text(command.summary().to_owned()));
        let mut flags: Vec<&str> = command.flags().to_vec();
        if !flags.is_empty() {
            flags.sort_unstable();
            let flags: Vec<String> = flags.iter().map(|flag| format!("--{flag}")).collect();
            ctx.io
                .print(Renderable::Text(format!("flags: {}", flags.join(", "))));
        }
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        let _ = ctx;
        if completed_args(tokens, cursor_token) == 0 {
            return all_commands()
                .map(|commands| commands.keys().map(|name| (*name).to_owned()).collect())
                .unwrap_or_default();
        }
        Vec::new()
    }
}

/// §4.9.6: every command module exports exactly this.
pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(HelpCommand)]
}
