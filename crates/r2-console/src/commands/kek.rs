// R0 skeleton — owner R15 (generated from spec §4)
// ---- spec §4.9.9 block 5
use r2_provider::Provider;
use std::rc::Rc;

use crate::context::AppContext;
use crate::parser::BoundArgs;

/// `load <provider> <aes|rsa|ec|generic> [<data>|--file] --kek …` (§5.4). Called by `load`
/// right after the provider lookup and `require_usable` and BEFORE `reject_named` (the
/// name=value tokens are the mechanism's params), whenever `args.opt("kek")` is Some.
pub fn run_load(
    ctx: &AppContext,
    args: &BoundArgs,
    provider: &Rc<dyn Provider>,
) -> r2_core::Result<()> {
    let _ = (ctx, args, provider);
    Err(r2_core::ConsoleError::not_implemented("R15"))
}
/// `export <ref> <path> --kek …` (§5.6). Called by `export` first thing (before
/// `reject_named` and the --outformat check) whenever `args.opt("kek")` is Some.
pub fn run_export(ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<()> {
    let _ = (ctx, args);
    Err(r2_core::ConsoleError::not_implemented("R15"))
}
/// Completion for `--kek`-specific positions of `load`/`export`: `option` = the previous
/// token. "--kek" → KEK labels (the line's provider refs via complete_refs with the
/// "<provider>:" prefix stripped); "--mech" → wrap cli names (kw, kwp, cbc, gcm, oaep,
/// pkcs1); "--outformat" → raw, hex, b64; anything else → None.
pub fn complete_option_value(
    ctx: &AppContext,
    tokens: &[String],
    option: &str,
) -> Option<Vec<String>> {
    let _ = (ctx, tokens, option);
    None
}
/// "<param>=" suggestions for the wrap mechanism named after `--mech` on the line (empty
/// when none/unknown).
pub fn param_name_candidates(tokens: &[String]) -> Vec<String> {
    let _ = tokens;
    Vec::new()
}

pub fn commands() -> Vec<Box<dyn crate::commands::Command>> {
    vec![]
}
