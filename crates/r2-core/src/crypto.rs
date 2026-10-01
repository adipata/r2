// R0 skeleton — owner R6 (generated from spec §4)
use crate::error::Result;
use zeroize::Zeroizing;

// The three bodies below are R0 mandated working bodies (§4.1.1), exactly as documented.
/// Constant-time equality that never panics: `a.len() == b.len() && openssl::memcmp::eq(a, b)`
/// (memcmp::eq asserts equal lengths). MAC verify and RSA-RAW verify use it.
#[allow(clippy::disallowed_methods)] // the one sanctioned openssl::memcmp::eq call (§4.1.3)
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a, b)
}
/// `openssl::rand::rand_bytes` into a zeroizing buffer (CKA_IDs, transport keys, AES/generic
/// keygen). Failure → Crypto "random number generation failed".
pub fn random_bytes(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    openssl::rand::rand_bytes(&mut buf)
        .map_err(|_| crate::error::ConsoleError::crypto("random number generation failed"))?;
    Ok(buf)
}
/// Load the OpenSSL "legacy" provider once per process:
/// `static LEGACY: OnceLock<Option<openssl::provider::Provider>>` initialized with
/// `Provider::try_load(None, "legacy", true)` (retain_fallbacks MUST be true; the Provider is
/// never dropped). Failure is non-fatal: logged at debug, only RC2/DES inputs then fail.
/// Called by keyparse before PKCS#12/traditional-PEM parsing and by r2-cli at startup.
pub fn ensure_legacy_provider() {
    static LEGACY: std::sync::OnceLock<Option<openssl::provider::Provider>> =
        std::sync::OnceLock::new();
    LEGACY.get_or_init(
        || match openssl::provider::Provider::try_load(None, "legacy", true) {
            Ok(provider) => Some(provider),
            Err(err) => {
                tracing::debug!("OpenSSL legacy provider not loaded: {err}");
                None
            }
        },
    );
}
