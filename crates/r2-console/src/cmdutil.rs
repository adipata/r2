// R0 skeleton — owner R7 (generated from spec §4)
// ---- spec §4.9.9 block 2
use r2_provider::Provider;
use r2_services::templatefile::SeedTemplates;

use crate::context::AppContext;
use crate::parser::BoundArgs;

/// Generic "missing <{what}> argument" (hint "usage: {usage}").
pub fn positional<'a>(
    args: &'a BoundArgs,
    index: usize,
    what: &str,
    usage: &str,
) -> r2_core::Result<&'a str> {
    let _ = (args, index, what, usage);
    Err(r2_core::ConsoleError::not_implemented("R7"))
}
/// First named token → Generic "unexpected name=value token '{name}=…'" (hint "usage:
/// {usage} (quote {noun} containing '=')"); noun = "data" (keys, kek) or "values" (providers).
pub fn reject_named(args: &BoundArgs, usage: &str, noun: &str) -> r2_core::Result<()> {
    let _ = (args, usage, noun);
    Err(r2_core::ConsoleError::not_implemented("R7"))
}
/// `--id`: optional lower-case "0x" prefix, Python `bytes.fromhex` semantics. Invalid → Param
/// "invalid key id {raw!r}" (param "id", hint "--id takes whole hex bytes, e.g. --id 0a1b");
/// empty → Param "key id must not be empty" (param "id").
pub fn parse_key_id(args: &BoundArgs) -> r2_core::Result<Option<Vec<u8>>> {
    let _ = args;
    Err(r2_core::ConsoleError::not_implemented("R7"))
}
/// LoggedOut → AuthRequired "login required: run `login {name}`" (§5.5 auth-first order).
pub fn require_usable(provider: &dyn Provider) -> r2_core::Result<()> {
    let _ = provider;
    Err(r2_core::ConsoleError::not_implemented("R7"))
}
/// `io.prompt(&ParamSpec::str("label", "Key label"))`, trimmed; empty → Param "label must
/// not be empty" (param "label").
pub fn prompt_label(ctx: &AppContext) -> r2_core::Result<String> {
    let _ = ctx;
    Err(r2_core::ConsoleError::not_implemented("R7"))
}
/// `--template <path>` → parsed §5.16 sections, parsed up front (fail before any prompt);
/// None when absent. Non-pkcs11 target → Param "--template applies only to PKCS#11 targets"
/// (param "template", hint "the template editor never opens for {name}").
pub fn parse_seed_templates(
    ctx: &AppContext,
    args: &BoundArgs,
    provider: &dyn Provider,
) -> r2_core::Result<Option<SeedTemplates>> {
    let _ = (ctx, args, provider);
    Err(r2_core::ConsoleError::not_implemented("R7"))
}
/// len(tokens) − 1 − (1 if cursor_token non-empty).
pub fn completed_args(tokens: &[String], cursor_token: &str) -> usize {
    let _ = (tokens, cursor_token);
    unimplemented!("R7")
}
/// The token before the one being completed (for `--opt <value>` completion).
pub fn previous_token<'a>(tokens: &'a [String], cursor_token: &str) -> Option<&'a str> {
    let _ = (tokens, cursor_token);
    unimplemented!("R7")
}
