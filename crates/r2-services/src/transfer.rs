// R0 skeleton — owner R10 (generated from spec §4)
// ---- spec §4.9.10 block 1
use r2_core::io::ConsoleIo;
use r2_core::keys::KeyInfo;
use r2_provider::Provider;

use crate::templatefile::EditorSeeding;

pub const TRANSPORT_PREFIX: &str = "r2-transport-";
/// §5.5 decision matrix, ladder, refusal UX; transport keys are destroyed on success AND
/// failure (Drop guard) and their software bytes are `Zeroizing`.
pub fn copy_key(
    source: &dyn Provider,
    key: &KeyInfo,
    dest: &dyn Provider,
    io: &dyn ConsoleIo,
    seeding: &EditorSeeding<'_>,
    label: Option<&str>,
    key_id: Option<&[u8]>,
) -> r2_core::Result<KeyInfo> {
    let _ = (source, key, dest, io, seeding, label, key_id);
    Err(r2_core::ConsoleError::not_implemented("R10"))
}
