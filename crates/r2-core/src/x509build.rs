// R0 skeleton — owner R6 (generated from spec §4)
use crate::error::Result;
use secrecy::SecretString;

pub const DEFAULT_CERT_DAYS: u32 = 3650;

/// Minimal self-signed X.509 (DER): Subject = Issuer = CN=<subject_cn> (UTF8String),
/// serial = BigNum::rand(159, MsbOption::MAYBE_ZERO, false), notBefore = now,
/// notAfter = now + days·86400, basicConstraints CA:FALSE critical, v3; signed with SHA-256
/// (RSA/EC) or no digest (Ed25519/Ed448).
pub fn build_self_signed_cert(
    private_key_pkcs8: &[u8],
    subject_cn: &str,
    days: u32,
) -> Result<Vec<u8>> {
    let _ = (private_key_pkcs8, subject_cn, days);
    Err(crate::error::ConsoleError::not_implemented("R6"))
}

/// Covers the csr command's --hash sha256|sha384|sha512. Token (`as_str()` only; no
/// Display/FromStr): the c2 enum values "sha256WithRSAEncryption",
/// "sha384WithRSAEncryption", "sha512WithRSAEncryption", "ecdsa-with-SHA256",
/// "ecdsa-with-SHA384", "ecdsa-with-SHA512", "ed25519", "ed448".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureAlg {
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    Ed25519,
    Ed448,
}
impl SignatureAlg {
    pub fn as_str(self) -> &'static str {
        unimplemented!("R6")
    }
    /// Dotted AlgorithmIdentifier OID: 1.2.840.113549.1.1.{11,12,13}, 1.2.840.10045.4.3.{2,3,4},
    /// 1.3.101.112, 1.3.101.113.
    pub fn oid(self) -> &'static str {
        unimplemented!("R6")
    }
    /// True (explicit NULL parameters) for the RSA PKCS#1 v1.5 algorithms; ECDSA/EdDSA: absent.
    pub fn null_params(self) -> bool {
        unimplemented!("R6")
    }
}

/// Signature callback of build_csr: receives the DER CertificationRequestInfo and returns
/// the signature in the ALGORITHM'S X.509 wire format (RSA: PKCS#1 v1.5 block; ECDSA: DER
/// SEQUENCE — callers converting from provider r‖s convert BEFORE returning, §4.4.7;
/// Ed: raw).
pub type SignCallback<'a> = &'a mut dyn FnMut(&[u8]) -> Result<Vec<u8>>;

/// Assemble a PEM CSR without a local private key (works for HSM keys). Returns PEM bytes
/// ("CERTIFICATE REQUEST", 64 columns, LF).
pub fn build_csr(
    public_key_spki: &[u8],
    subject: &str,
    sig_alg: SignatureAlg,
    sign: SignCallback<'_>,
) -> Result<Vec<u8>> {
    let _ = (public_key_spki, subject, sig_alg, sign);
    Err(crate::error::ConsoleError::not_implemented("R6"))
}

/// RFC 4514 subject → DER Name, a port of pyca 49.0 `Name.from_rfc4514_string`
/// (`_RFC4514NameParser` + NameAttribute validation). Error → Param "invalid subject
/// {subject!r}: {pyca text}" (the pyca text may be empty; param_name "subject", hint
/// 'RFC 4514 syntax, e.g. "CN=mykey,O=ACME"'), which build_csr propagates unchanged.
pub fn parse_rfc4514_subject(subject: &str) -> Result<Vec<u8>> {
    let _ = subject;
    Err(crate::error::ConsoleError::not_implemented("R6"))
}

/// Encrypted PKCS#12 (DER) from canonical materials, pyca BestAvailableEncryption profile.
pub fn build_pkcs12(
    private_key_pkcs8: &[u8],
    cert_der: &[u8],
    friendly_name: &str,
    password: &SecretString,
    extra_certs: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let _ = (
        private_key_pkcs8,
        cert_der,
        friendly_name,
        password,
        extra_certs,
    );
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
