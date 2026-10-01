// R0 skeleton — owner R8 (generated from spec §4)
// ---- spec §4.9.10 block 1
use r2_core::io::ConsoleIo;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_provider::Provider;
use secrecy::SecretString;
use std::path::Path;
use zeroize::Zeroizing;

use crate::templatefile::EditorSeeding;

/// Key-type hints of `load` / `--format` (§4.4/§5.1).
pub const VALID_HINTS: [&str; 7] = ["auto", "aes", "rsa", "ec", "cert", "generic", "data"];
/// Verbatim-bytes hints (no sniffing): "generic" → (Generic, Secret), "data" → (None, Data).
pub fn verbatim_hint(hint: &str) -> Option<(KeyAlgorithm, KeyClass)> {
    let _ = hint;
    unimplemented!("R8")
}
/// DataIo "cannot read {path}: {err}".
pub fn read_key_file(path: &Path) -> r2_core::Result<Zeroizing<Vec<u8>>> {
    let _ = path;
    Err(r2_core::ConsoleError::not_implemented("R8"))
}
/// §4.4 parse with the typed hint; generic/data short-circuit to one verbatim material
/// (empty → Param "{hint} material must not be empty", param "data"); password = --password
/// else a hidden `prompt_secret(prompt)` per encrypted item.
pub fn parse_materials(
    data: &[u8],
    hint: &str,
    password: Option<&SecretString>,
    io: &dyn ConsoleIo,
) -> r2_core::Result<Vec<KeyMaterial>> {
    let _ = (data, hint, password, io);
    Err(r2_core::ConsoleError::not_implemented("R8"))
}
/// ★ (R15) Label precedence: --label (trimmed; empty → Param "label must not be empty") →
/// first material label_hint → prompt "Key label" (empty → same Param).
pub fn resolve_label(
    materials: &[KeyMaterial],
    label: Option<&str>,
    io: &dyn ConsoleIo,
) -> r2_core::Result<String> {
    let _ = (materials, label, io);
    Err(r2_core::ConsoleError::not_implemented("R8"))
}
/// "PKCS#11 template — {algorithm} {class} '{label}'" (data objects: "{class}" only).
pub fn editor_title(material: &KeyMaterial, label: &str) -> String {
    let _ = (material, label);
    unimplemented!("R8")
}
/// Import every material under one label; PKCS#11 targets get one editor per material via
/// `seeding`. PKCS#11 targets only (`type_name() == "pkcs11"`): multi-material inputs
/// (PKCS#12) share one fresh 4-byte CKA_ID when none was given; memory keeps `None`.
pub fn import_materials(
    provider: &dyn Provider,
    materials: &[KeyMaterial],
    label: &str,
    key_id: Option<&[u8]>,
    seeding: &EditorSeeding<'_>,
) -> r2_core::Result<Vec<KeyInfo>> {
    let _ = (provider, materials, label, key_id, seeding);
    Err(r2_core::ConsoleError::not_implemented("R8"))
}
