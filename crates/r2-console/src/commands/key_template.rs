// R0 skeleton — owner R14 (generated from spec §4)
// ---- spec §4.9.9 block 4
use crate::context::AppContext;
use crate::parser::BoundArgs;

/// `key template <ref> <path>` (§5.16). `args` = the `key` command's BoundArgs:
/// positionals[0] == "template", [1] = ref, [2] = path. Non-pkcs11 provider →
/// UnsupportedOperation "key template works only with PKCS#11 providers" (hint "{name} keys
/// have no PKCS#11 attribute template"). Prints the "wrote {class_key} template (…)" line
/// and the key-material note. R0 stub: Err(not_implemented("R14")).
pub fn run(ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<()> {
    let _ = (ctx, args);
    Err(r2_core::ConsoleError::not_implemented("R14"))
}

pub fn commands() -> Vec<Box<dyn crate::commands::Command>> {
    vec![]
}
