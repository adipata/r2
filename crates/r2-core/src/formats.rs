//! Re-serialization of canonical bytes for keyexport (spec §4.4.6, §5.6; owner R6): ports
//! of c2 keyexport's pyca serializers (`_serialize_private`, `_serialize_spki`,
//! `_load_certificate`, `_cert_spki`).
use openssl::symm::Cipher;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::error::{ConsoleError, Result};
use crate::keyparse::{PrivateLoadError, load_private_der, load_public_der, ossl_detail};
use crate::x509info;

/// Token (`as_str()` only; no Display/FromStr): "pem" | "der".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Pem,
    Der,
}
impl Encoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Encoding::Pem => "pem",
            Encoding::Der => "der",
        }
    }
}

/// PKCS#8 DER → PKCS#8 PEM/DER. `password` → encrypted PKCS#8 =
/// `private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), pw)` /
/// `private_key_to_pkcs8_passphrase` (PBES2, PBKDF2-HMAC-SHA256, 2048 iterations,
/// AES-256-CBC — pyca BestAvailableEncryption; salt length is OpenSSL's and not
/// normative). Errors: invalid input → KeyParse "exported private key is not valid
/// unencrypted PKCS#8 DER: {detail}"; empty password → Param "password must not be empty"
/// (param_name "password"); a password over 1023 UTF-8 bytes → Param "Passwords longer
/// than 1023 bytes are not supported by this backend" (pyca's limit; c2 crashed, §11
/// D12(h)). A NUL byte is an ordinary password byte (pointer + length, no C string).
pub fn private_key_bytes(
    pkcs8_der: &[u8],
    encoding: Encoding,
    password: Option<&SecretString>,
) -> Result<Zeroizing<Vec<u8>>> {
    let key = load_private_der(pkcs8_der).map_err(|err| {
        let detail = match err {
            PrivateLoadError::Encrypted => {
                "Password was not given but private key is encrypted".to_owned()
            }
            PrivateLoadError::Invalid(detail) | PrivateLoadError::Unsupported(detail) => detail,
        };
        ConsoleError::key_parse(format!(
            "exported private key is not valid unencrypted PKCS#8 DER: {detail}"
        ))
    })?;
    let password = match password {
        Some(secret) => {
            let pw = secret.expose_secret();
            if pw.is_empty() {
                return Err(ConsoleError::param(
                    "password must not be empty",
                    "password",
                ));
            }
            // pyca's limit (c2 crashed on its ValueError, §11 D12(h)).
            if pw.len() > 1023 {
                return Err(ConsoleError::param(
                    "Passwords longer than 1023 bytes are not supported by this backend",
                    "password",
                ));
            }
            Some(pw.as_bytes())
        }
        None => None,
    };
    let out = match (encoding, password) {
        (Encoding::Pem, None) => key.private_key_to_pem_pkcs8(),
        (Encoding::Der, None) => key.private_key_to_pkcs8(),
        (Encoding::Pem, Some(pw)) => {
            key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), pw)
        }
        (Encoding::Der, Some(pw)) => key.private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), pw),
    };
    out.map(Zeroizing::new).map_err(|err| {
        ConsoleError::crypto(format!(
            "private key serialization failed: {}",
            ossl_detail(&err)
        ))
    })
}
/// SPKI DER → PEM ("PUBLIC KEY") or DER. DER is returned verbatim WITHOUT validation (c2
/// `_serialize_spki`); only the PEM path parses: invalid → KeyParse "exported public key is
/// not valid DER SubjectPublicKeyInfo: {detail}".
pub fn public_key_bytes(spki_der: &[u8], encoding: Encoding) -> Result<Vec<u8>> {
    if encoding == Encoding::Der {
        return Ok(spki_der.to_vec());
    }
    let invalid = |detail: &str| {
        ConsoleError::key_parse(format!(
            "exported public key is not valid DER SubjectPublicKeyInfo: {detail}"
        ))
    };
    let key = load_public_der(spki_der).map_err(|detail| invalid(&detail))?;
    key.public_key_to_pem()
        .map_err(|err| invalid(&ossl_detail(&err)))
}
/// Certificate DER → PEM or DER. DER is returned verbatim WITHOUT validation; only the PEM
/// path parses: invalid → KeyParse "exported certificate is not valid DER X.509: {detail}".
pub fn certificate_bytes(cert_der: &[u8], encoding: Encoding) -> Result<Vec<u8>> {
    if encoding == Encoding::Der {
        return Ok(cert_der.to_vec());
    }
    // c2 `_load_certificate` (pyca's strict load) then `public_bytes(PEM)`: the DER as
    // loaded, PEM-wrapped (OpenSSL's X509 decoder refuses Name encodings pyca loads).
    x509info::load_certificate(cert_der).map_err(|d| invalid_exported_cert(&d))?;
    Ok(crate::x509build::pem_encode(cert_der, "CERTIFICATE"))
}
/// SPKI of a DER certificate (c2 keyexport `_cert_spki`). Errors → KeyParse "exported
/// certificate is not valid DER X.509: {detail}" / "certificate contains an invalid public
/// key: {detail}".
pub fn cert_spki(cert_der: &[u8]) -> Result<Vec<u8>> {
    let cert = x509info::load_certificate(cert_der).map_err(|d| invalid_exported_cert(&d))?;
    let key = x509info::cert_public_key(cert.spki, "certificate")?;
    key.public_key_to_der().map_err(|err| {
        ConsoleError::key_parse(format!(
            "certificate contains an invalid public key: {}",
            ossl_detail(&err)
        ))
    })
}
/// SPKI derived in software from an unencrypted PKCS#8 (errors as private_key_bytes).
pub fn pkcs8_public_spki(pkcs8_der: &[u8]) -> Result<Vec<u8>> {
    let key = load_private_der(pkcs8_der).map_err(|err| {
        let detail = match err {
            PrivateLoadError::Encrypted => {
                "Password was not given but private key is encrypted".to_owned()
            }
            PrivateLoadError::Invalid(detail) | PrivateLoadError::Unsupported(detail) => detail,
        };
        ConsoleError::key_parse(format!(
            "exported private key is not valid unencrypted PKCS#8 DER: {detail}"
        ))
    })?;
    key.public_key_to_der().map_err(|err| {
        ConsoleError::key_parse(format!(
            "exported private key is not valid unencrypted PKCS#8 DER: {}",
            ossl_detail(&err)
        ))
    })
}

fn invalid_exported_cert(detail: &str) -> ConsoleError {
    ConsoleError::key_parse(format!(
        "exported certificate is not valid DER X.509: {detail}"
    ))
}
