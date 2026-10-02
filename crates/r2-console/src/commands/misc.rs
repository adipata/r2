// `exit` / `quit` / `clear` / `config` (spec §5.1; owner R7) — c2
// `console/commands/misc_cmd.py`. `exit`/`quit` return `Flow::Exit` (c2 raised ReplExit);
// provider shutdown runs in r2-cli after the REPL.
use r2_config::loader::DEFAULTS_YAML;
use r2_config::model::CONFIG_SECTIONS;
use r2_config::yaml;
use r2_core::error::ConsoleError;
use r2_core::io::{Renderable, table};
use r2_core::text::is_py_space;

use crate::cmdutil::completed_args;
use crate::commands::Command;
use crate::context::AppContext;
use crate::parser::BoundArgs;
use crate::repl::Flow;

const EXIT_SUMMARY: &str = "Leave the console (providers are shut down)";

struct ExitCommand;
impl Command for ExitCommand {
    fn name(&self) -> &'static str {
        "exit"
    }
    fn summary(&self) -> &'static str {
        EXIT_SUMMARY
    }
    fn usage(&self) -> &'static str {
        "exit"
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        let _ = (ctx, args);
        Ok(Flow::Exit)
    }
}

struct QuitCommand;
impl Command for QuitCommand {
    fn name(&self) -> &'static str {
        "quit"
    }
    fn summary(&self) -> &'static str {
        EXIT_SUMMARY
    }
    fn usage(&self) -> &'static str {
        "quit"
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        let _ = (ctx, args);
        Ok(Flow::Exit)
    }
}

struct ClearCommand;
impl Command for ClearCommand {
    fn name(&self) -> &'static str {
        "clear"
    }
    fn summary(&self) -> &'static str {
        "Clear the screen"
    }
    fn usage(&self) -> &'static str {
        "clear"
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        let _ = args;
        ctx.io.clear();
        Ok(Flow::Continue)
    }
}

struct ConfigCommand;

const CONFIG_USAGE: &str = "config show [--defaults | --origin] | config path";

impl ConfigCommand {
    fn path(ctx: &AppContext) {
        match &ctx.config.source_path {
            None => {
                ctx.io.print(Renderable::Text(
                    "config file: (none — running on built-in defaults)".to_owned(),
                ));
                ctx.io.print(Renderable::Text(
                    "discovery order: --config PATH, $R2_CONFIG, ./r2.yaml, \
                     <user config dir>/r2/r2.yaml"
                        .to_owned(),
                ));
            }
            Some(source) => ctx.io.print(Renderable::Text(format!(
                "config file: {}",
                source.display()
            ))),
        }
    }

    /// The embedded annotated defaults.yaml, verbatim (never through the loader).
    fn show_defaults(ctx: &AppContext) {
        ctx.io.print(Renderable::Text(DEFAULTS_YAML.to_owned()));
    }

    fn show_origin(ctx: &AppContext) {
        let origins = &ctx.config.origins;
        let mut rows: Vec<Vec<String>> = CONFIG_SECTIONS
            .iter()
            .map(|section| {
                let origin = origins
                    .get(*section)
                    .cloned()
                    .unwrap_or_else(|| "default".to_owned());
                vec![(*section).to_owned(), origin]
            })
            .collect();
        rows.extend(
            origins
                .iter()
                .filter(|(section, _)| !CONFIG_SECTIONS.contains(&section.as_str()))
                .map(|(section, origin)| vec![section.clone(), origin.clone()]),
        );
        ctx.io
            .print(table(Some("config origins"), &["section", "origin"], rows));
    }

    /// PyYAML `safe_dump(sort_keys=False, default_flow_style=False).rstrip()` of the
    /// effective configuration.
    fn show_effective(ctx: &AppContext) {
        let dumped = yaml::dump(&ctx.cfg().to_value());
        let text = dumped.trim_end_matches(is_py_space);
        ctx.io.print(Renderable::Text(text.to_owned()));
    }
}

impl Command for ConfigCommand {
    fn name(&self) -> &'static str {
        "config"
    }
    fn summary(&self) -> &'static str {
        "Show the effective configuration and where it came from"
    }
    fn usage(&self) -> &'static str {
        CONFIG_USAGE
    }
    fn flags(&self) -> &'static [&'static str] {
        &["defaults", "origin"]
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        let sub = args.positionals.first().map_or("show", String::as_str);
        match sub {
            "path" => Self::path(ctx),
            "show" => {
                let defaults = args.flag("defaults");
                let origin = args.flag("origin");
                if defaults && origin {
                    return Err(ConsoleError::generic(
                        "--defaults and --origin are mutually exclusive",
                    )
                    .with_hint(format!("usage: {CONFIG_USAGE}")));
                }
                if defaults {
                    Self::show_defaults(ctx);
                } else if origin {
                    Self::show_origin(ctx);
                } else {
                    Self::show_effective(ctx);
                }
            }
            _ => {
                return Err(ConsoleError::generic(format!(
                    "unknown config subcommand '{sub}'"
                ))
                .with_hint(format!("usage: {CONFIG_USAGE}")));
            }
        }
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        let _ = ctx;
        let done = completed_args(tokens, cursor_token);
        if done == 0 {
            return vec!["show".to_owned(), "path".to_owned()];
        }
        if tokens.iter().any(|token| token == "show") {
            return vec!["--defaults".to_owned(), "--origin".to_owned()];
        }
        Vec::new()
    }
}

/// §4.9.6: every command module exports exactly this.
pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(ExitCommand),
        Box::new(QuitCommand),
        Box::new(ClearCommand),
        Box::new(ConfigCommand),
    ]
}
