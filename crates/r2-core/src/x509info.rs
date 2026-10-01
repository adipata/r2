// R0 skeleton — owner R6 (generated from spec §4)
use crate::error::Result;
use crate::keys::{Curve, KeyAlgorithm};
use crate::template::AttrValue;
use std::collections::BTreeMap;

/// Facts of a certificate used by every provider and the `key info` command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertFacts {
    pub algorithm: KeyAlgorithm,
    pub curve: Option<Curve>,
    pub size_bits: Option<u32>,
    /// DER SubjectPublicKeyInfo of the embedded key.
    pub spki_der: Vec<u8>,
    /// DER Name (exact bytes of the certificate) — CKA_SUBJECT / CKA_ISSUER.
    pub subject_der: Vec<u8>,
    pub issuer_der: Vec<u8>,
    /// DER INTEGER TLV of the serial — CKA_SERIAL_NUMBER.
    pub serial_der: Vec<u8>,
    /// First CN of the subject, UTF-8 (`label_hint`).
    pub subject_cn: Option<String>,
}

/// Which of c2's two key classifiers a caller mirrors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classifier {
    /// keyparse/memory (`_classify`): the §4.4.3 rules — the other pyca curves as
    /// `Curve::Other(name)`; unsupported → KeyParse "unsupported key algorithm: {X}" with
    /// hint "supported: AES, RSA, EC, Ed25519/Ed448, X25519/X448".
    KeyParse,
    /// the PKCS#11 certificate read path (`Pkcs11Provider._spki_facts`): only p256/p384/p521
    /// are named, any other EC curve → curve None (shown "-"); unsupported → KeyParse
    /// "unsupported public key type {pyca public class name}" (e.g. "DSAPublicKey"), no hint.
    /// (On that read path a certificate whose DER does not parse is skipped — not listed —
    /// while this error propagates, as in c2.)
    Pkcs11,
}

/// Parse a DER certificate. Errors → KeyParse "certificate is not valid DER X.509: {detail}",
/// "certificate contains an invalid public key: {detail}".
pub fn cert_facts(cert_der: &[u8], classifier: Classifier) -> Result<CertFacts> {
    let _ = (cert_der, classifier);
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
/// (algorithm, curve, size_bits) of a DER SPKI (classification rules of §4.4.3, per
/// `classifier`).
pub fn spki_facts(
    spki_der: &[u8],
    classifier: Classifier,
) -> Result<(KeyAlgorithm, Option<Curve>, Option<u32>)> {
    let _ = (spki_der, classifier);
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
/// Port of pyca `Name.rfc4514_string()`: RDNs reversed, '+' within an RDN, short names only
/// for CN L ST O OU C STREET DC UID (else dotted OID), `_escape_dn_value` escaping
/// (`\ " + , ; < >`, NUL → `\00`, leading `#`/space and trailing space), non-string
/// values as `#hex`. NOT x509-cert's Display.
pub fn rfc4514_string(name_der: &[u8]) -> Result<String> {
    let _ = name_der;
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
/// `key info` rows for a certificate: ("subject", rfc4514), ("issuer", rfc4514),
/// ("serial", lower-case hex without leading zeros, "0" for zero), ("not valid before",
/// "YYYY-MM-DDTHH:MM:SS+00:00"), ("not valid after", same) — via x509-cert
/// `Time::to_date_time`.
pub fn certificate_details(cert_der: &[u8]) -> Result<Vec<(String, String)>> {
    let _ = cert_der;
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
/// KeyInfo.attributes of a certificate on the PKCS#11 read path (c2 provider.py):
/// CKA_SUBJECT / CKA_ISSUER = Str(rfc4514), CKA_SERIAL_NUMBER = Str(serial hex as above).
pub fn cert_attributes(cert_der: &[u8]) -> Result<BTreeMap<String, AttrValue>> {
    let _ = cert_der;
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
/// KeyInfo.attributes of a MemoryProvider certificate (c2 memory.py `_cert_attributes`):
/// Str "subject", "issuer" (rfc4514), "serial_number" (hex as above), "not_valid_before",
/// "not_valid_after" ("YYYY-MM-DDTHH:MM:SS+00:00", pyca `isoformat()`).
pub fn memory_cert_attributes(cert_der: &[u8]) -> Result<BTreeMap<String, AttrValue>> {
    let _ = cert_der;
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
