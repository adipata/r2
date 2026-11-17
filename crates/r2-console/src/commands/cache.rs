// `cache` (spec §5.19, r2 addition): the key cache that `keys` and ref completion read on
// big HSMs. `cache` shows each provider's cache, `cache <provider>` (re)loads one in the
// background, `cache stop` stops every load (as Ctrl+G does at the prompt).
use r2_core::error::ConsoleError;
use r2_core::io::{Renderable, table};
use r2_core::text::py_repr;
use r2_provider::cache::CacheState;
use r2_provider::{AuthState, Provider};

use crate::cache::{STOP_KEY, Start};
use crate::cmdutil::{completed_args, reject_named};
use crate::commands::Command;
use crate::completer::complete_provider_names;
use crate::context::AppContext;
use crate::parser::BoundArgs;
use crate::repl::Flow;

/// §4.9.6: every command module exports exactly this.
pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(CacheCommand)]
}

const USAGE: &str = "cache [<provider> | stop]";

fn text(ctx: &AppContext, line: String) {
    ctx.io.print(Renderable::Text(line));
}

/// One status row: provider, state, objects, detail.
fn status_row(provider: &dyn Provider) -> Vec<String> {
    let name = provider.name().to_owned();
    let Some(cache) = provider.key_cache() else {
        return vec![name, "none".into(), "-".into(), "listed live".into()];
    };
    let status = cache.status();
    let logged_out = provider.status().auth != AuthState::LoggedIn;
    let (state, detail) = match status.state {
        CacheState::Empty if logged_out => ("empty", "not logged in".to_owned()),
        CacheState::Empty => ("empty", "run `cache <provider>`, `keys` or Tab".to_owned()),
        CacheState::Loading => (
            "loading",
            match status.progress {
                Some((loaded, Some(total))) => format!("{loaded} of {total} objects read"),
                _ => "counting objects".to_owned(),
            },
        ),
        CacheState::Complete => ("complete", String::new()),
        CacheState::Partial => (
            "partial",
            match &status.last_error {
                Some(error) => format!("last load failed: {error}"),
                None => "loading was stopped".to_owned(),
            },
        ),
    };
    vec![name, state.into(), status.count.to_string(), detail]
}

struct CacheCommand;

impl Command for CacheCommand {
    fn name(&self) -> &'static str {
        "cache"
    }
    fn summary(&self) -> &'static str {
        "Show the key caches, (re)load one in the background, or stop loading"
    }
    fn usage(&self) -> &'static str {
        USAGE
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        reject_named(args, self.usage(), "data")?;
        if let Some(name) = args.options.keys().next() {
            return Err(ConsoleError::generic(format!("unknown option --{name}"))
                .with_hint(format!("usage: {USAGE}")));
        }
        match args.positionals.as_slice() {
            [] => {
                let rows: Vec<Vec<String>> = ctx
                    .providers
                    .all()
                    .iter()
                    .map(|provider| status_row(provider.as_ref()))
                    .collect();
                ctx.io.print(table(
                    Some("key caches"),
                    &["provider", "state", "objects", "detail"],
                    rows,
                ));
            }
            [word] if word == "stop" => {
                let stopped = crate::cache::stop_all();
                if stopped.is_empty() {
                    text(ctx, "no key cache is loading".to_owned());
                } else {
                    text(
                        ctx,
                        format!("stopping the key cache loading of {}", stopped.join(", ")),
                    );
                }
            }
            [name] => {
                let provider = ctx.providers.get(name)?;
                if provider.key_cache().is_none() {
                    return Err(ConsoleError::unsupported(format!(
                        "{} keeps no key cache",
                        provider.name()
                    ))
                    .with_hint("its keys are always listed live"));
                }
                if provider.status().auth != AuthState::LoggedIn {
                    return Err(ConsoleError::auth_required(format!(
                        "login required: run `login {}`",
                        provider.name()
                    )));
                }
                match crate::cache::start(provider.as_ref())? {
                    Start::Started => text(
                        ctx,
                        format!(
                            "loading the key cache of {} in the background — {} or `cache stop` \
                             stops it",
                            provider.name(),
                            STOP_KEY
                        ),
                    ),
                    Start::AlreadyLoading => {
                        let detail = provider
                            .key_cache()
                            .and_then(|cache| cache.status().progress)
                            .map(|progress| match progress {
                                (loaded, Some(total)) => format!(" ({loaded} of {total})"),
                                _ => String::new(),
                            })
                            .unwrap_or_default();
                        text(
                            ctx,
                            format!(
                                "the key cache of {} is already loading{detail}",
                                provider.name()
                            ),
                        );
                    }
                    Start::NoCache => {}
                }
            }
            [_, extra, ..] => {
                return Err(ConsoleError::generic(format!(
                    "unexpected argument {}",
                    py_repr(extra)
                ))
                .with_hint(format!("usage: {USAGE}")));
            }
        }
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        if completed_args(tokens, cursor_token) == 0 {
            let mut names = complete_provider_names(ctx, cursor_token);
            names.push("stop".to_owned());
            return names;
        }
        Vec::new()
    }
}
