// R0 skeleton — owner R6 (generated from spec §4)
use crate::error::Result;
use secrecy::SecretString;
use zeroize::Zeroizing;

/// Token (`as_str()` only; no Display/FromStr): "pem" | "der".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Pem,
    Der,
}
impl Encoding {
    pub fn as_str(self) -> &'static str {
        unimplemented!("R6")
    }
}

/// PKCS#8 DER → PKCS#8 PEM/DER. `password` → encrypted PKCS#8 =
/// `private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), pw)` /
/// `private_key_to_pkcs8_passphrase` (PBES2, PBKDF2-HMAC-SHA256, 2048 iterations,
/// AES-256-CBC — pyca BestAvailableEncryption; salt length is OpenSSL's and not
/// normative). Errors: invalid input → KeyParse "exported private key is not valid
/// unencrypted PKCS#8 DER: {detail}"; empty password → Param "password must not be empty"
/// (param_name "password"); NUL in password → Param "password must not contain NUL
/// characters".
pub fn private_key_bytes(
    pkcs8_der: &[u8],
    encoding: Encoding,
    password: Option<&SecretString>,
) -> Result<Zeroizing<Vec<u8>>> {
    let _ = (pkcs8_der, encoding, password);
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
/// SPKI DER → PEM ("PUBLIC KEY") or DER. DER is returned verbatim WITHOUT validation (c2
/// `_serialize_spki`); only the PEM path parses: invalid → KeyParse "exported public key is
/// not valid DER SubjectPublicKeyInfo: {detail}".
pub fn public_key_bytes(spki_der: &[u8], encoding: Encoding) -> Result<Vec<u8>> {
    let _ = (spki_der, encoding);
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
/// Certificate DER → PEM or DER. DER is returned verbatim WITHOUT validation; only the PEM
/// path parses: invalid → KeyParse "exported certificate is not valid DER X.509: {detail}".
pub fn certificate_bytes(cert_der: &[u8], encoding: Encoding) -> Result<Vec<u8>> {
    let _ = (cert_der, encoding);
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
/// SPKI of a DER certificate (c2 keyexport `_cert_spki`). Errors → KeyParse "exported
/// certificate is not valid DER X.509: {detail}" / "certificate contains an invalid public
/// key: {detail}".
pub fn cert_spki(cert_der: &[u8]) -> Result<Vec<u8>> {
    let _ = cert_der;
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
/// SPKI derived in software from an unencrypted PKCS#8 (errors as private_key_bytes).
pub fn pkcs8_public_spki(pkcs8_der: &[u8]) -> Result<Vec<u8>> {
    let _ = pkcs8_der;
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
