// R0 skeleton — owner R8 (generated from spec §4)
// ---- spec §4.9.10 block 1
use r2_core::keys::KeyInfo;
use r2_provider::Provider;
use secrecy::SecretString;
use std::path::Path;
use zeroize::Zeroizing;

/// `export --format` values; "p12" is routed to certops.
pub const VALID_FORMATS: [&str; 5] = ["auto", "raw", "der", "pem", "p12"];
/// §5.6 pre-flight refusal (KeyNotExportable "Refusing to export: key '{ref}' is marked
/// sensitive/non-extractable." with the c2 hints).
pub fn refuse_non_exportable(key: &KeyInfo) -> r2_core::Result<()> {
    let _ = key;
    Err(r2_core::ConsoleError::not_implemented("R8"))
}
pub fn find_public_part(
    provider: &dyn Provider,
    key: &KeyInfo,
) -> r2_core::Result<Option<KeyInfo>> {
    let _ = (provider, key);
    Err(r2_core::ConsoleError::not_implemented("R8"))
}
pub fn public_spki(provider: &dyn Provider, key: &KeyInfo) -> r2_core::Result<Vec<u8>> {
    let _ = (provider, key);
    Err(r2_core::ConsoleError::not_implemented("R8"))
}
/// §5.6 table → (payload, resolved format token).
pub fn export_bytes(
    provider: &dyn Provider,
    key: &KeyInfo,
    fmt: &str,
    public: bool,
    password: Option<&SecretString>,
) -> r2_core::Result<(Zeroizing<Vec<u8>>, &'static str)> {
    let _ = (provider, key, fmt, public, password);
    Err(r2_core::ConsoleError::not_implemented("R8"))
}
/// ★ (R14) Write a payload; DataIo "cannot write {path}: {err}".
pub fn write_output(path: &Path, data: &[u8]) -> r2_core::Result<()> {
    let _ = (path, data);
    Err(r2_core::ConsoleError::not_implemented("R8"))
}
