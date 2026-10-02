// Shared command helpers (spec §4.9.9; owner R7) — c2's per-module private helpers of
// `keys_cmd.py` / `providers_cmd.py`, shared because R15's `kek.rs` is split out of
// `keys_cmd.py`. Texts are c2's verbatim.
use r2_core::error::ConsoleError;
use r2_core::params::ParamSpec;
use r2_core::text::{py_fromhex, py_path, py_repr, py_strip};
use r2_provider::{AuthState, Provider};
use r2_services::templatefile::{SeedTemplates, load_seed_file};

use crate::context::AppContext;
use crate::parser::BoundArgs;

/// Generic "missing <{what}> argument" (hint "usage: {usage}").
pub fn positional<'a>(
    args: &'a BoundArgs,
    index: usize,
    what: &str,
    usage: &str,
) -> r2_core::Result<&'a str> {
    match args.positionals.get(index) {
        Some(value) => Ok(value),
        None => Err(ConsoleError::generic(format!("missing <{what}> argument"))
            .with_hint(format!("usage: {usage}"))),
    }
}
/// First named token → Generic "unexpected name=value token '{name}=…'" (hint "usage:
/// {usage} (quote {noun} containing '=')"); noun = "data" (keys, kek) or "values" (providers).
pub fn reject_named(args: &BoundArgs, usage: &str, noun: &str) -> r2_core::Result<()> {
    match args.named.keys().next() {
        Some(name) => Err(ConsoleError::generic(format!(
            "unexpected name=value token '{name}=…'"
        ))
        .with_hint(format!("usage: {usage} (quote {noun} containing '=')"))),
        None => Ok(()),
    }
}
/// `--id`: optional lower-case "0x" prefix, Python `bytes.fromhex` semantics. Invalid → Param
/// "invalid key id {raw!r}" (param "id", hint "--id takes whole hex bytes, e.g. --id 0a1b");
/// empty → Param "key id must not be empty" (param "id").
pub fn parse_key_id(args: &BoundArgs) -> r2_core::Result<Option<Vec<u8>>> {
    let Some(raw) = args.opt("id") else {
        return Ok(None);
    };
    let text = raw.strip_prefix("0x").unwrap_or(raw);
    let Some(key_id) = py_fromhex(text) else {
        return Err(
            ConsoleError::param(format!("invalid key id {}", py_repr(raw)), "id")
                .with_hint("--id takes whole hex bytes, e.g. --id 0a1b"),
        );
    };
    if key_id.is_empty() {
        return Err(ConsoleError::param("key id must not be empty", "id"));
    }
    Ok(Some(key_id))
}
/// LoggedOut → AuthRequired "login required: run `login {name}`" (§5.5 auth-first order).
pub fn require_usable(provider: &dyn Provider) -> r2_core::Result<()> {
    if provider.status().auth == AuthState::LoggedOut {
        return Err(ConsoleError::auth_required(format!(
            "login required: run `login {}`",
            provider.name()
        )));
    }
    Ok(())
}
/// `io.prompt(&ParamSpec::str("label", "Key label"))`, trimmed; empty → Param "label must
/// not be empty" (param "label").
pub fn prompt_label(ctx: &AppContext) -> r2_core::Result<String> {
    let answer = ctx.io.prompt(&ParamSpec::str("label", "Key label"))?;
    let answer = py_strip(&answer);
    if answer.is_empty() {
        return Err(ConsoleError::param("label must not be empty", "label"));
    }
    Ok(answer.to_owned())
}
/// `--template <path>` → parsed §5.16 sections, parsed up front (fail before any prompt);
/// None when absent. Non-pkcs11 target → Param "--template applies only to PKCS#11 targets"
/// (param "template", hint "the template editor never opens for {name}").
pub fn parse_seed_templates(
    ctx: &AppContext,
    args: &BoundArgs,
    provider: &dyn Provider,
) -> r2_core::Result<Option<SeedTemplates>> {
    let Some(path) = args.opt("template") else {
        return Ok(None);
    };
    if provider.type_name() != "pkcs11" {
        return Err(ConsoleError::param(
            "--template applies only to PKCS#11 targets",
            "template",
        )
        .with_hint(format!(
            "the template editor never opens for {}",
            provider.name()
        )));
    }
    load_seed_file(&py_path(path), &ctx.cfg().templates.custom_attributes).map(Some)
}
/// len(tokens) − 1 − (1 if cursor_token non-empty).
pub fn completed_args(tokens: &[String], cursor_token: &str) -> usize {
    tokens
        .len()
        .saturating_sub(1)
        .saturating_sub(usize::from(!cursor_token.is_empty()))
}
/// The token before the one being completed (for `--opt <value>` completion).
pub fn previous_token<'a>(tokens: &'a [String], cursor_token: &str) -> Option<&'a str> {
    let back = if cursor_token.is_empty() { 1 } else { 2 };
    tokens
        .len()
        .checked_sub(back)
        .and_then(|index| tokens.get(index))
        .map(String::as_str)
}
