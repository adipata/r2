#![allow(dead_code)]
// R0 skeleton — owner R5a (generated from spec §4)
// ---- spec §4.5.6 block 1
use r2_core::error::ConsoleError;

use crate::backend::BackendError;

/// Implements the §5.2 table (names via `catalog::ckr_name`). `token_label` = the label in
/// the CKR_PIN_* texts: callers pass the logged-in token's label (or the token being
/// logged in to); None renders "?" (c2's default). The CALLER logs
/// "{provider}: {context} failed with {CKR}" at INFO (it knows the provider name).
pub(crate) fn translate(
    err: BackendError,
    context: &str,
    token_label: Option<&str>,
) -> ConsoleError {
    let _ = (err, context, token_label);
    unimplemented!("R5a")
}
