// R0 skeleton — owner R8 (generated from spec §4)
// ---- spec §4.9.10 block 1
use r2_core::keys::KeyInfo;
use r2_provider::Provider;
use secrecy::SecretString;

pub const CSR_HASHES: [&str; 3] = ["sha256", "sha384", "sha512"];
pub fn find_certificate(
    provider: &dyn Provider,
    key: &KeyInfo,
) -> r2_core::Result<Option<KeyInfo>> {
    let _ = (provider, key);
    Err(r2_core::ConsoleError::not_implemented("R8"))
}
/// §5.6 PKCS#12 export. Without `cert_der` and without a co-located certificate it builds
/// a self-signed one with CN = the key label, and FIRST (before exporting or building
/// anything) checks the label: outside 1..=64 UTF-8 bytes → Param "Attribute's length must
/// be >= 1 and <= 64, but it was {n}" (param_name "label", hint "pass an existing
/// certificate with --cert") — §11 D12.
pub fn export_pkcs12(
    provider: &dyn Provider,
    key: &KeyInfo,
    password: &SecretString,
    cert_der: Option<&[u8]>,
) -> r2_core::Result<Vec<u8>> {
    let _ = (provider, key, password, cert_der);
    Err(r2_core::ConsoleError::not_implemented("R8"))
}
/// §5.7: sign callback through provider.sign (RSA-PKCS1 / ECDSA r‖s → DER via
/// r2_core::der::ecdsa_rs_to_der / EDDSA raw). Returns PEM bytes.
pub fn generate_csr(
    provider: &dyn Provider,
    key: &KeyInfo,
    subject: &str,
    hash_name: &str,
) -> r2_core::Result<Vec<u8>> {
    let _ = (provider, key, subject, hash_name);
    Err(r2_core::ConsoleError::not_implemented("R8"))
}
