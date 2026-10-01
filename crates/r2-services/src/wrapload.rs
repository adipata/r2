// R0 skeleton — owner R15 (generated from spec §4)
// ---- spec §4.9.10 block 1
use r2_core::io::ConsoleIo;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo};
use r2_core::params::Params;
use r2_ops::OperationSpec;
use r2_provider::{Provider, ProviderRegistry};
use std::collections::BTreeSet;

use crate::templatefile::EditorSeeding;

/// Which side of the blob format a call is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Wrap,
    Unwrap,
}
/// One row of the §5.4/§5.6 wrap-mechanism table; `spec` is a synthetic OperationSpec
/// (id "load.unwrap.<cli>") read only for id + params by ParamResolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapMechEntry {
    pub spec: OperationSpec,
    pub kek_algorithm: KeyAlgorithm,
    pub unwrap_kek_class: KeyClass,
    pub wrap_kek_classes: BTreeSet<KeyClass>,
    pub result_classes: BTreeSet<KeyClass>,
}
/// The table in menu order: kw, kwp, cbc, gcm, oaep, pkcs1.
pub fn wrap_mechs() -> Vec<WrapMechEntry> {
    unimplemented!("R15")
}
/// "aes" → (Aes, Secret), "generic" → (Generic, Secret), "rsa" → (Rsa, Private),
/// "ec" → (Ec, Private); anything else None.
pub fn result_by_hint(hint: &str) -> Option<(KeyAlgorithm, KeyClass)> {
    let _ = hint;
    unimplemented!("R15")
}
pub fn resolve_kek(
    registry: &ProviderRegistry,
    provider: &dyn Provider,
    token: &str,
    direction: Direction,
) -> r2_core::Result<KeyInfo> {
    let _ = (registry, provider, token, direction);
    Err(r2_core::ConsoleError::not_implemented("R15"))
}
pub fn candidates(
    kek: &KeyInfo,
    provider: &dyn Provider,
    direction: Direction,
) -> Vec<WrapMechEntry> {
    let _ = (kek, provider, direction);
    unimplemented!("R15")
}
/// `--mech`: `text::py_strip(name).to_lowercase()` equals a cli_name or a lower-cased
/// canonical mechanism name (so "AES-KEY-WRAP" works). Unknown → Param "unknown wrap
/// mechanism {name!r}" (hint "did you mean: {close_matches(py_strip(name), cli names then
/// canonical names, 3) joined ', '}?" or "valid mechanisms: {cli names}"); not advertised →
/// UnsupportedOperation; wrong KEK → Param "{mechanism} {direction} needs a {classes} …",
/// where {classes} are the wanted class tokens sorted by `as_str()` and joined " or "
/// (e.g. "certificate or public" — c2 `sorted(c.value …)`, §4.3 note). c2 texts verbatim.
pub fn resolve_mech(
    name: &str,
    kek: &KeyInfo,
    provider: &dyn Provider,
    direction: Direction,
) -> r2_core::Result<WrapMechEntry> {
    let _ = (name, kek, provider, direction);
    Err(r2_core::ConsoleError::not_implemented("R15"))
}
pub fn select_mech(
    io: &dyn ConsoleIo,
    kek: &KeyInfo,
    provider: &dyn Provider,
    direction: Direction,
) -> r2_core::Result<WrapMechEntry> {
    let _ = (io, kek, provider, direction);
    Err(r2_core::ConsoleError::not_implemented("R15"))
}
/// What `load --kek` unwraps.
pub struct UnwrapJob<'a> {
    pub kek: &'a KeyInfo,
    pub entry: &'a WrapMechEntry,
    pub params: Params,
    pub wrapped: &'a [u8],
    pub result_algorithm: KeyAlgorithm,
    pub result_class: KeyClass,
    pub label: String,
    pub key_id: Option<Vec<u8>>,
}
pub fn load_wrapped(
    provider: &dyn Provider,
    job: UnwrapJob<'_>,
    seeding: &EditorSeeding<'_>,
) -> r2_core::Result<KeyInfo> {
    let _ = (provider, job, seeding);
    Err(r2_core::ConsoleError::not_implemented("R15"))
}
pub fn refuse_non_wrappable(key: &KeyInfo) -> r2_core::Result<()> {
    let _ = key;
    Err(r2_core::ConsoleError::not_implemented("R15"))
}
pub fn wrap_for_export(
    provider: &dyn Provider,
    kek: &KeyInfo,
    entry: &WrapMechEntry,
    params: Params,
    key: &KeyInfo,
) -> r2_core::Result<Vec<u8>> {
    let _ = (provider, kek, entry, params, key);
    Err(r2_core::ConsoleError::not_implemented("R15"))
}
