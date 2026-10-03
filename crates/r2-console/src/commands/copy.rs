// The `copy` command (spec §5.1/§5.5) — owner R10. Port of c2
// console/commands/copy_cmd.py.
//
// Thin console shim over `r2_services::transfer::copy_key`: resolves the source ref and
// the destination provider, parses `--label`/`--id`/`--template` (§5.16) and renders the
// one-line result. All decision-matrix logic (auth pre-probe, wrap ladder, refusal UX)
// lives in the service. copy keeps its own `--id` parser and `--template` text (c2's
// copy_cmd texts differ from keys_cmd's, §4.9.9).
use r2_core::error::ConsoleError;
use r2_core::text::{py_fromhex, py_path, py_repr};
use r2_services::templatefile::{EditorSeeding, load_seed_file};
use r2_services::transfer;

use crate::cmdutil::{completed_args, previous_token};
use crate::commands::Command;
use crate::completer::{complete_paths, complete_provider_names, complete_refs};
use crate::context::AppContext;
use crate::parser::{BoundArgs, OptValue};
use crate::render::{algo_text, class_text};
use crate::repl::Flow;

/// §4.9.6: every command module exports exactly this.
pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(CopyCommand)]
}

struct CopyCommand;

impl Command for CopyCommand {
    fn name(&self) -> &'static str {
        "copy"
    }
    fn summary(&self) -> &'static str {
        "Copy a key to another provider (wrapped in transit when possible)"
    }
    /// §5.1 grammar; source refs accept the full §4.3 form (#<id-hex>, :<class>,
    /// @<handle> suffixes).
    fn usage(&self) -> &'static str {
        "copy <src-provider>:<label>[:<class>] <dst-provider> [--label <l>] [--id <hex>] [--template <path>]"
    }

    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        if args.positionals.len() != 2 {
            return Err(ConsoleError::generic(
                "copy takes a source key reference and a destination provider",
            )
            .with_hint(format!("usage: {}", self.usage())));
        }
        let (source, key) = ctx.providers.resolve_ref(&args.positionals[0])?;
        let dest = ctx.providers.get(&args.positionals[1])?;
        let label = args.opt("label");
        let seeds = match args.opt("template") {
            Some(path) => {
                if dest.type_name() != "pkcs11" {
                    // §5.16: the editor never opens there
                    return Err(ConsoleError::param(
                        "--template applies only to PKCS#11 destinations",
                        "template",
                    )
                    .with_hint(format!(
                        "the template editor never opens for {}",
                        dest.name()
                    )));
                }
                Some(load_seed_file(
                    &py_path(path),
                    &ctx.cfg().templates.custom_attributes,
                )?)
            }
            None => None,
        };
        let key_id = parse_id(args.options.get("id"))?;
        let seeding = EditorSeeding {
            editor: ctx.template_editor.as_ref(),
            templates: &ctx.cfg().templates,
            seeds: seeds.as_ref(),
        };
        let result = transfer::copy_key(
            source.as_ref(),
            &key,
            dest.as_ref(),
            ctx.io.as_ref(),
            &seeding,
            label,
            key_id.as_deref(),
        )?;
        // same class/algorithm vocabulary as the `keys` table (§5.1)
        ctx.io.print(
            format!(
                "copied {} -> {} ({} {}){}",
                key.key_ref.display(),
                result.key_ref.display(),
                class_text(result.key_class),
                algo_text(&result),
                r2_core::runtime::timing_suffix() // §11 D31
            )
            .into(),
        );
        Ok(Flow::Continue)
    }

    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        if tokens.len() >= 2 && previous_token(tokens, cursor_token) == Some("--template") {
            return complete_paths(cursor_token); // §5.1 PathCompleter rule
        }
        match completed_args(tokens, cursor_token) {
            0 => complete_refs(ctx, cursor_token),
            1 => complete_provider_names(ctx, cursor_token),
            _ => vec!["--label".into(), "--id".into(), "--template".into()],
        }
    }
}

/// `--id` hex (optionally `0x`-prefixed, any case) → CKA_ID bytes (c2 `_parse_id`).
fn parse_id(raw: Option<&OptValue>) -> r2_core::Result<Option<Vec<u8>>> {
    let raw = match raw {
        None => return Ok(None),
        Some(OptValue::Value(raw)) => raw.as_str(),
        Some(OptValue::Flag) => {
            return Err(ConsoleError::param("--id expects a hex value", "id"));
        }
    };
    // Python `raw.lower().startswith("0x")`: only '0' + 'x'/'X' lower to "0x".
    let text = match raw.as_bytes() {
        [b'0', b'x' | b'X', ..] => &raw[2..],
        _ => raw,
    };
    let Some(data) = py_fromhex(text) else {
        return Err(
            ConsoleError::param(format!("--id is not valid hex: {}", py_repr(raw)), "id")
                .with_hint("whole bytes as hex, e.g. --id 0a1b"),
        );
    };
    if data.is_empty() {
        return Err(ConsoleError::param("--id must not be empty", "id"));
    }
    Ok(Some(data))
}
