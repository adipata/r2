//! X.509 building blocks (spec §4.4.4, §5.6, §5.7; owner R6): self-signed certificate,
//! sign-callback CSR (works for HSM-held keys), RFC 4514 subject parser (a port of pyca 49
//! `Name.from_rfc4514_string`), PKCS#12 assembly. Port of c2 `core/x509build.py`.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{Id, PKey, Private};
use openssl::stack::Stack;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::{X509, X509NameBuilder};
use secrecy::{ExposeSecret, SecretString};

use crate::error::{ConsoleError, Result};
use crate::keyparse::{PrivateLoadError, load_private_der, load_public_der, ossl_detail};
use crate::text::py_repr;
use crate::x509info;

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
    let key = load_private_pkcs8(private_key_pkcs8, "self-signed certificate key")?;
    let cn_len = subject_cn.len();
    if !(1..=64).contains(&cn_len) {
        return Err(ConsoleError::param(
            format!("Attribute's length must be >= 1 and <= 64, but it was {cn_len}"),
            "subject_cn",
        )
        .with_hint("the self-signed certificate uses the key label as its CN"));
    }
    let digest = match key.id() {
        Id::ED25519 | Id::ED448 => MessageDigest::null(),
        Id::RSA | Id::EC => MessageDigest::sha256(),
        _ => {
            return Err(ConsoleError::crypto(format!(
                "key type {} cannot sign a certificate",
                pyca_private_class(&key)
            ))
            .with_hint("self-signed certificates need an RSA, EC or Ed25519/Ed448 key"));
        }
    };
    let assemble = || -> std::result::Result<Vec<u8>, openssl::error::ErrorStack> {
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_nid_with_type(
            Nid::COMMONNAME,
            subject_cn,
            openssl::asn1::Asn1Type::UTF8STRING,
        )?;
        let name = name.build();
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        let serial = Asn1Integer::from_bn(&serial)?;
        builder.set_serial_number(&serial)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let now = i64::try_from(now).unwrap_or(i64::MAX);
        let not_after = now.saturating_add(i64::from(days).saturating_mul(86_400));
        builder.set_not_before(Asn1Time::from_unix(now)?.as_ref())?;
        builder.set_not_after(Asn1Time::from_unix(not_after)?.as_ref())?;
        builder.append_extension(BasicConstraints::new().critical().build()?)?;
        builder.set_pubkey(&key)?;
        builder.sign(&key, digest)?;
        builder.build().to_der()
    };
    assemble().map_err(|err| {
        ConsoleError::crypto(format!(
            "self-signed certificate assembly failed: {}",
            ossl_detail(&err)
        ))
    })
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
        match self {
            SignatureAlg::RsaPkcs1Sha256 => "sha256WithRSAEncryption",
            SignatureAlg::RsaPkcs1Sha384 => "sha384WithRSAEncryption",
            SignatureAlg::RsaPkcs1Sha512 => "sha512WithRSAEncryption",
            SignatureAlg::EcdsaSha256 => "ecdsa-with-SHA256",
            SignatureAlg::EcdsaSha384 => "ecdsa-with-SHA384",
            SignatureAlg::EcdsaSha512 => "ecdsa-with-SHA512",
            SignatureAlg::Ed25519 => "ed25519",
            SignatureAlg::Ed448 => "ed448",
        }
    }
    /// Dotted AlgorithmIdentifier OID: 1.2.840.113549.1.1.{11,12,13}, 1.2.840.10045.4.3.{2,3,4},
    /// 1.3.101.112, 1.3.101.113.
    pub fn oid(self) -> &'static str {
        match self {
            SignatureAlg::RsaPkcs1Sha256 => "1.2.840.113549.1.1.11",
            SignatureAlg::RsaPkcs1Sha384 => "1.2.840.113549.1.1.12",
            SignatureAlg::RsaPkcs1Sha512 => "1.2.840.113549.1.1.13",
            SignatureAlg::EcdsaSha256 => "1.2.840.10045.4.3.2",
            SignatureAlg::EcdsaSha384 => "1.2.840.10045.4.3.3",
            SignatureAlg::EcdsaSha512 => "1.2.840.10045.4.3.4",
            SignatureAlg::Ed25519 => "1.3.101.112",
            SignatureAlg::Ed448 => "1.3.101.113",
        }
    }
    /// True (explicit NULL parameters) for the RSA PKCS#1 v1.5 algorithms; ECDSA/EdDSA: absent.
    pub fn null_params(self) -> bool {
        matches!(
            self,
            SignatureAlg::RsaPkcs1Sha256
                | SignatureAlg::RsaPkcs1Sha384
                | SignatureAlg::RsaPkcs1Sha512
        )
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
    let subject_der = parse_rfc4514_subject(subject)?;
    load_public_der(public_key_spki).map_err(|detail| {
        ConsoleError::key_parse(format!(
            "public key is not a valid DER SubjectPublicKeyInfo: {detail}"
        ))
    })?;
    // CertificationRequestInfo ::= SEQUENCE { version INTEGER 0, subject Name,
    //   subjectPKInfo SubjectPublicKeyInfo, attributes [0] IMPLICIT SET OF Attribute }
    let mut cri_body = vec![0x02, 0x01, 0x00];
    cri_body.extend_from_slice(&subject_der);
    cri_body.extend_from_slice(public_key_spki);
    cri_body.extend_from_slice(&[0xa0, 0x00]);
    let cri = der_tlv(0x30, &cri_body);
    let signature = sign(&cri)?;
    let oid = oid_from_dotted(sig_alg.oid()).map_err(|detail| {
        ConsoleError::crypto(format!("assembled CSR failed to parse: {detail}"))
    })?;
    let mut alg_body = der_tlv(0x06, &oid);
    if sig_alg.null_params() {
        alg_body.extend_from_slice(&[0x05, 0x00]);
    }
    let mut bits = vec![0x00];
    bits.extend_from_slice(&signature);
    let mut csr_body = cri;
    csr_body.extend(der_tlv(0x30, &alg_body));
    csr_body.extend(der_tlv(0x03, &bits));
    let csr_der = der_tlv(0x30, &csr_body);
    // c2 re-parses the assembled CSR (pyca `load_der_x509_csr`, strict incl. Name values).
    x509info::load_csr(&csr_der).map_err(|detail| {
        ConsoleError::crypto(format!("assembled CSR failed to parse: {detail}"))
    })?;
    Ok(pem_encode(&csr_der, "CERTIFICATE REQUEST"))
}

/// PEM text: BEGIN line, base64 at 64 columns, END line, LF endings (pyca/OpenSSL layout).
fn pem_encode(der: &[u8], label: &str) -> Vec<u8> {
    let body = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out.into_bytes()
}

/// RFC 4514 subject → DER Name, a port of pyca 49.0 `Name.from_rfc4514_string`
/// (`_RFC4514NameParser` + NameAttribute validation). Error → Param "invalid subject
/// {subject!r}: {pyca text}" (the pyca text may be empty; param_name "subject", hint
/// 'RFC 4514 syntax, e.g. "CN=mykey,O=ACME"'), which build_csr propagates unchanged.
pub fn parse_rfc4514_subject(subject: &str) -> Result<Vec<u8>> {
    Rfc4514Parser::new(subject).parse().map_err(|text| {
        ConsoleError::param(
            format!("invalid subject {}: {text}", py_repr(subject)),
            "subject",
        )
        .with_hint("RFC 4514 syntax, e.g. \"CN=mykey,O=ACME\"")
    })
}

/// Encrypted PKCS#12 (DER) from canonical materials, pyca BestAvailableEncryption profile.
pub fn build_pkcs12(
    private_key_pkcs8: &[u8],
    cert_der: &[u8],
    friendly_name: &str,
    password: &SecretString,
    extra_certs: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let password = password.expose_secret();
    if password.is_empty() {
        return Err(
            ConsoleError::param("PKCS#12 password must not be empty", "password")
                .with_hint("PKCS#12 output is always encrypted (§5.6)"),
        );
    }
    let key = load_private_pkcs8(private_key_pkcs8, "PKCS#12 private key")?;
    if !matches!(key.id(), Id::RSA | Id::EC | Id::ED25519 | Id::ED448) {
        return Err(ConsoleError::crypto(format!(
            "key type {} cannot be stored in a PKCS#12",
            pyca_private_class(&key)
        ))
        .with_hint("PKCS#12 supports RSA, EC and Ed25519/Ed448 private keys"));
    }
    let cert = load_x509(cert_der).map_err(|detail| {
        ConsoleError::key_parse(format!("certificate is not valid DER X.509: {detail}"))
    })?;
    let mut extras = Vec::with_capacity(extra_certs.len());
    for (index, extra) in extra_certs.iter().enumerate() {
        extras.push(load_x509(extra).map_err(|detail| {
            ConsoleError::key_parse(format!(
                "extra certificate #{index} is not valid DER X.509: {detail}"
            ))
        })?);
    }
    // r2 guards: Pkcs12Builder::name / build2 would panic on an interior NUL (§11 D16).
    if password.contains('\0') {
        return Err(ConsoleError::param(
            "PKCS#12 password must not contain NUL characters",
            "password",
        ));
    }
    if friendly_name.contains('\0') {
        return Err(ConsoleError::param(
            "PKCS#12 friendly name must not contain NUL characters",
            "friendly_name",
        ));
    }
    let assemble = || -> std::result::Result<Vec<u8>, openssl::error::ErrorStack> {
        let mut builder = Pkcs12::builder();
        builder
            .name(friendly_name)
            .pkey(&key)
            .cert(&cert)
            .key_algorithm(Nid::AES_256_CBC)
            .cert_algorithm(Nid::AES_256_CBC)
            .key_iter(20_000)
            .mac_iter(2048)
            .mac_md(MessageDigest::sha256());
        if !extras.is_empty() {
            let mut stack = Stack::new()?;
            for extra in &extras {
                stack.push(extra.clone())?;
            }
            builder.ca(stack);
        }
        builder.build2(password)?.to_der()
    };
    assemble().map_err(|err| {
        ConsoleError::crypto(format!("PKCS#12 assembly failed: {}", ossl_detail(&err)))
    })
}

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

/// c2 `_load_private_pkcs8`: a canonical (unencrypted PKCS#8 DER) private key, pyca-loaded.
fn load_private_pkcs8(data: &[u8], what: &str) -> Result<PKey<Private>> {
    load_private_der(data).map_err(|err| match err {
        PrivateLoadError::Encrypted => ConsoleError::key_parse(format!(
            "{what} must be an unencrypted PKCS#8 private key"
        ))
        .with_hint(
            "decrypt the key first — the §4.3 canonical private-key format is unencrypted PKCS#8 DER",
        ),
        PrivateLoadError::Invalid(detail) => ConsoleError::key_parse(format!(
            "{what} is not a valid DER PKCS#8 private key: {detail}"
        )),
    })
}

/// pyca's class name of a private key type outside the signing/storable set.
fn pyca_private_class(key: &PKey<Private>) -> &'static str {
    match key.id() {
        Id::X25519 => "X25519PrivateKey",
        Id::X448 => "X448PrivateKey",
        Id::DSA => "DSAPrivateKey",
        Id::DH | Id::DHX => "DHPrivateKey",
        Id::RSA => "RSAPrivateKey",
        Id::EC => "ECPrivateKey",
        Id::ED25519 => "Ed25519PrivateKey",
        Id::ED448 => "Ed448PrivateKey",
        _ => "UnknownPrivateKey",
    }
}

/// pyca `load_der_x509_certificate` (strict) as an OpenSSL certificate.
fn load_x509(der: &[u8]) -> std::result::Result<X509, String> {
    x509info::load_certificate(der)?;
    X509::from_der(der).map_err(|err| ossl_detail(&err))
}

// ---------------------------------------------------------------------------------------
// RFC 4514 parser (pyca 49 `_RFC4514NameParser`)
// ---------------------------------------------------------------------------------------

/// CPython 3.12 `re` `\d` in a `str` pattern: Unicode decimal digits (Nd, Unicode 15.0).
const PY_DIGIT_RANGES: [(u32, u32); 64] = [
    (0x30, 0x39),
    (0x660, 0x669),
    (0x6F0, 0x6F9),
    (0x7C0, 0x7C9),
    (0x966, 0x96F),
    (0x9E6, 0x9EF),
    (0xA66, 0xA6F),
    (0xAE6, 0xAEF),
    (0xB66, 0xB6F),
    (0xBE6, 0xBEF),
    (0xC66, 0xC6F),
    (0xCE6, 0xCEF),
    (0xD66, 0xD6F),
    (0xDE6, 0xDEF),
    (0xE50, 0xE59),
    (0xED0, 0xED9),
    (0xF20, 0xF29),
    (0x1040, 0x1049),
    (0x1090, 0x1099),
    (0x17E0, 0x17E9),
    (0x1810, 0x1819),
    (0x1946, 0x194F),
    (0x19D0, 0x19D9),
    (0x1A80, 0x1A89),
    (0x1A90, 0x1A99),
    (0x1B50, 0x1B59),
    (0x1BB0, 0x1BB9),
    (0x1C40, 0x1C49),
    (0x1C50, 0x1C59),
    (0xA620, 0xA629),
    (0xA8D0, 0xA8D9),
    (0xA900, 0xA909),
    (0xA9D0, 0xA9D9),
    (0xA9F0, 0xA9F9),
    (0xAA50, 0xAA59),
    (0xABF0, 0xABF9),
    (0xFF10, 0xFF19),
    (0x104A0, 0x104A9),
    (0x10D30, 0x10D39),
    (0x11066, 0x1106F),
    (0x110F0, 0x110F9),
    (0x11136, 0x1113F),
    (0x111D0, 0x111D9),
    (0x112F0, 0x112F9),
    (0x11450, 0x11459),
    (0x114D0, 0x114D9),
    (0x11650, 0x11659),
    (0x116C0, 0x116C9),
    (0x11730, 0x11739),
    (0x118E0, 0x118E9),
    (0x11950, 0x11959),
    (0x11C50, 0x11C59),
    (0x11D50, 0x11D59),
    (0x11DA0, 0x11DA9),
    (0x11F50, 0x11F59),
    (0x16A60, 0x16A69),
    (0x16AC0, 0x16AC9),
    (0x16B50, 0x16B59),
    (0x1D7CE, 0x1D7FF),
    (0x1E140, 0x1E149),
    (0x1E2F0, 0x1E2F9),
    (0x1E4F0, 0x1E4F9),
    (0x1E950, 0x1E959),
    (0x1FBF0, 0x1FBF9),
];

fn py_digit(c: char) -> bool {
    let c = u32::from(c);
    PY_DIGIT_RANGES
        .iter()
        .any(|(lo, hi)| (*lo..=*hi).contains(&c))
}

/// `[\da-zA-Z]`
fn py_alnum(c: char) -> bool {
    c.is_ascii_alphabetic() || py_digit(c)
}

/// `_LUTF1 | _UTFMB`
fn is_lead(c: char) -> bool {
    matches!(u32::from(c), 0x01..=0x1f | 0x21 | 0x24..=0x2a | 0x2d..=0x3a | 0x3d | 0x3f..=0x5b | 0x5d..=0x7f)
        || u32::from(c) >= 0x80
}

/// `_SUTF1 | _UTFMB`
fn is_string_char(c: char) -> bool {
    matches!(u32::from(c), 0x01..=0x21 | 0x23..=0x2a | 0x2d..=0x3a | 0x3d | 0x3f..=0x5b | 0x5d..=0x7f)
        || u32::from(c) >= 0x80
}

/// `_TUTF1 | _UTFMB`
fn is_trail(c: char) -> bool {
    matches!(u32::from(c), 0x01..=0x1f | 0x21 | 0x23..=0x2a | 0x2d..=0x3a | 0x3d | 0x3f..=0x5b | 0x5d..=0x7f)
        || u32::from(c) >= 0x80
}

/// `_ESCAPE_SPECIAL`
fn is_escape_special(c: char) -> bool {
    matches!(
        c,
        '\\' | ' ' | '#' | '=' | '"' | '+' | ',' | ';' | '<' | '>'
    )
}

/// pyca's default string type per OID (`_NAMEOID_DEFAULT_TYPE`), as a DER tag.
fn default_string_tag(oid: &[u8]) -> u8 {
    const PRINTABLE: [&[u8]; 4] = [
        &[0x55, 0x04, 0x06], // countryName
        &[
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x03,
        ], // jurisdictionC
        &[0x55, 0x04, 0x05], // serialNumber
        &[0x55, 0x04, 0x2e], // dnQualifier
    ];
    const IA5: [&[u8]; 2] = [
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01], // emailAddress
        &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19], // domainComponent
    ];
    if PRINTABLE.contains(&oid) {
        0x13
    } else if IA5.contains(&oid) {
        0x16
    } else {
        0x0c
    }
}

/// pyca `_NAMEOID_LENGTH_LIMIT` (UTF-8 bytes).
fn length_limit(oid: &[u8]) -> Option<(usize, usize)> {
    match oid {
        [0x55, 0x04, 0x06]
        | [
            0x2b,
            0x06,
            0x01,
            0x04,
            0x01,
            0x82,
            0x37,
            0x3c,
            0x02,
            0x01,
            0x03,
        ] => Some((2, 2)),
        [0x55, 0x04, 0x03] => Some((1, 64)),
        _ => None,
    }
}

const ASN1_INVALID: &str = "error parsing asn1 value: ParseError { kind: InvalidValue }";

/// rust-asn1 `ObjectIdentifier::from_string` (u128 arcs, first ≤ 2, second < 40 under 0/1,
/// at most 63 content bytes) → DER content.
fn oid_from_dotted(dotted: &str) -> std::result::Result<Vec<u8>, String> {
    let invalid = || ASN1_INVALID.to_owned();
    let mut parts = dotted.split('.');
    let parse = |part: Option<&str>| -> std::result::Result<u128, String> {
        let part = part.ok_or_else(invalid)?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        part.parse::<u128>().map_err(|_| invalid())
    };
    let first = parse(parts.next())?;
    let second = parse(parts.next())?;
    if first > 2 || (first < 2 && second >= 40) {
        return Err(invalid());
    }
    let mut out = Vec::new();
    let push = |value: u128, out: &mut Vec<u8>| -> std::result::Result<(), String> {
        let mut chunks = vec![(value & 0x7f) as u8];
        let mut rest = value >> 7;
        while rest > 0 {
            chunks.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        chunks.reverse();
        if out.len() + chunks.len() > 63 {
            return Err(invalid());
        }
        out.extend(chunks);
        Ok(())
    };
    let head = first
        .checked_mul(40)
        .and_then(|v| v.checked_add(second))
        .ok_or_else(invalid)?;
    push(head, &mut out)?;
    for part in parts {
        push(parse(Some(part))?, &mut out)?;
    }
    Ok(out)
}

/// binascii.unhexlify of a str: ASCII required, then hex digits.
fn py_unhexlify(text: &str) -> std::result::Result<Vec<u8>, String> {
    if !text.is_ascii() {
        return Err("string argument should contain only ASCII characters".to_owned());
    }
    if !text.len().is_multiple_of(2) {
        return Err("Odd-length string".to_owned());
    }
    hex::decode(text).map_err(|_| "Non-hexadecimal digit found".to_owned())
}

/// `bytes.decode()` (UTF-8, strict) with CPython 3.12's UnicodeDecodeError text.
pub(crate) fn py_utf8_decode(data: &[u8]) -> std::result::Result<String, String> {
    match std::str::from_utf8(data) {
        Ok(text) => Ok(text.to_owned()),
        Err(err) => {
            let start = err.valid_up_to();
            let (len, reason) = match err.error_len() {
                Some(len) => {
                    let lead = data[start];
                    let reason = if (0xc2..=0xf4).contains(&lead) {
                        "invalid continuation byte"
                    } else {
                        "invalid start byte"
                    };
                    (len, reason)
                }
                None => (data.len() - start, "unexpected end of data"),
            };
            Err(if len == 1 {
                format!(
                    "'utf-8' codec can't decode byte 0x{:02x} in position {start}: {reason}",
                    data[start]
                )
            } else {
                format!(
                    "'utf-8' codec can't decode bytes in position {start}-{}: {reason}",
                    start + len - 1
                )
            })
        }
    }
}

/// One parsed NameAttribute: OID content, value, DER string tag.
struct ParsedAttr {
    oid: Vec<u8>,
    value: String,
    tag: u8,
}

struct Rfc4514Parser {
    data: Vec<char>,
    idx: usize,
}

impl Rfc4514Parser {
    fn new(data: &str) -> Self {
        Self {
            data: data.chars().collect(),
            idx: 0,
        }
    }

    fn has_data(&self) -> bool {
        self.idx < self.data.len()
    }

    fn peek(&self) -> Option<char> {
        self.data.get(self.idx).copied()
    }

    fn at(&self, i: usize) -> Option<char> {
        self.data.get(i).copied()
    }

    fn read_char(&mut self, ch: char) -> std::result::Result<(), String> {
        if self.peek() != Some(ch) {
            return Err(String::new());
        }
        self.idx += 1;
        Ok(())
    }

    fn parse(mut self) -> std::result::Result<Vec<u8>, String> {
        if !self.has_data() {
            return Ok(vec![0x30, 0x00]);
        }
        let mut rdns = vec![self.parse_rdn()?];
        while self.has_data() {
            self.read_char(',')?;
            rdns.push(self.parse_rdn()?);
        }
        // Name(reversed(rdns)) → DER: SEQUENCE OF SET OF (sorted) AttributeTypeAndValue.
        let mut body = Vec::new();
        for rdn in rdns.iter().rev() {
            let mut atvs: Vec<Vec<u8>> = rdn
                .iter()
                .map(|attr| {
                    let mut inner = der_tlv(0x06, &attr.oid);
                    inner.extend(der_tlv(attr.tag, attr.value.as_bytes()));
                    der_tlv(0x30, &inner)
                })
                .collect();
            atvs.sort();
            body.extend(der_tlv(0x31, &atvs.concat()));
        }
        Ok(der_tlv(0x30, &body))
    }

    fn parse_rdn(&mut self) -> std::result::Result<Vec<ParsedAttr>, String> {
        let mut nas = vec![self.parse_na()?];
        while self.peek() == Some('+') {
            self.read_char('+')?;
            nas.push(self.parse_na()?);
        }
        for (i, attr) in nas.iter().enumerate() {
            if nas[..i]
                .iter()
                .any(|other| other.oid == attr.oid && other.value == attr.value)
            {
                return Err("duplicate attributes are not allowed".to_owned());
            }
        }
        Ok(nas)
    }

    /// `_OID_RE` = `(0|([1-9]\d*))(\.(0|([1-9]\d*)))+` at the cursor: the match length.
    fn match_oid(&self) -> Option<usize> {
        let arc = |i: usize| -> Option<usize> {
            match self.at(i)? {
                '0' => Some(i + 1),
                '1'..='9' => {
                    let mut j = i + 1;
                    while self.at(j).is_some_and(py_digit) {
                        j += 1;
                    }
                    Some(j)
                }
                _ => None,
            }
        };
        let mut end = arc(self.idx)?;
        let mut repeats = 0;
        while self.at(end) == Some('.') {
            match arc(end + 1) {
                Some(next) => {
                    end = next;
                    repeats += 1;
                }
                None => break,
            }
        }
        (repeats > 0).then_some(end - self.idx)
    }

    /// `_DESCR_RE` = `[a-zA-Z][a-zA-Z\d-]*`
    fn match_descr(&self) -> Option<usize> {
        if !self.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
            return None;
        }
        let mut end = self.idx + 1;
        while self.at(end).is_some_and(|c| py_alnum(c) || c == '-') {
            end += 1;
        }
        Some(end - self.idx)
    }

    fn take(&mut self, len: usize) -> String {
        let text: String = self.data[self.idx..self.idx + len].iter().collect();
        self.idx += len;
        text
    }

    fn parse_na(&mut self) -> std::result::Result<ParsedAttr, String> {
        let oid = if let Some(len) = self.match_oid() {
            let dotted = self.take(len);
            oid_from_dotted(&dotted)?
        } else {
            let len = self.match_descr().ok_or_else(String::new)?;
            let name = self.take(len);
            x509info::SHORT_NAMES
                .iter()
                .find(|(short, _)| *short == name)
                .map(|(_, oid)| oid.to_vec())
                .ok_or_else(String::new)?
        };
        self.read_char('=')?;
        let value = if self.peek() == Some('#') {
            let len = self.match_hexstring().ok_or_else(String::new)?;
            let raw = self.take(len);
            py_utf8_decode(&py_unhexlify(&raw[1..])?)?
        } else {
            let len = self.match_string();
            let raw = self.take(len);
            unescape_dn_value(&raw)?
        };
        if let Some((min, max)) = length_limit(&oid) {
            let len = value.len();
            if len < min || len > max {
                return Err(format!(
                    "Attribute's length must be >= {min} and <= {max}, but it was {len}"
                ));
            }
        }
        let tag = default_string_tag(&oid);
        Ok(ParsedAttr { oid, value, tag })
    }

    /// `_HEXSTRING_RE` = `#([\da-zA-Z]{2})+` at the cursor.
    fn match_hexstring(&self) -> Option<usize> {
        let mut end = self.idx + 1;
        while self.at(end).is_some_and(py_alnum) && self.at(end + 1).is_some_and(py_alnum) {
            end += 2;
        }
        (end > self.idx + 1).then_some(end - self.idx)
    }

    /// Length of a `_PAIR` token at `i` (`\` + special, or `\` + two `[\da-zA-Z]`).
    fn pair_at(&self, i: usize) -> Option<usize> {
        if self.at(i) != Some('\\') {
            return None;
        }
        match self.at(i + 1) {
            Some(c) if is_escape_special(c) => Some(2),
            Some(c) if py_alnum(c) && self.at(i + 2).is_some_and(py_alnum) => Some(3),
            _ => None,
        }
    }

    /// `_STRING_RE` at the cursor (always matches, possibly empty): a lead token, then the
    /// longest run of string tokens whose last token is a trail char or a pair.
    fn match_string(&self) -> usize {
        let first = match self.peek() {
            Some(c) if is_lead(c) => 1,
            Some('\\') => match self.pair_at(self.idx) {
                Some(len) => len,
                None => return 0,
            },
            _ => return 0,
        };
        let mut end = self.idx + first;
        let mut best = end;
        loop {
            let (len, trailing_ok) = match self.at(end) {
                Some('\\') => match self.pair_at(end) {
                    Some(len) => (len, true),
                    None => break,
                },
                Some(c) if is_string_char(c) => (1, is_trail(c)),
                _ => break,
            };
            end += len;
            if trailing_ok {
                best = end;
            }
        }
        best - self.idx
    }
}

/// pyca `_unescape_dn_value`: `\` + special → the char; runs of `\XX` → UTF-8 decoded bytes.
fn unescape_dn_value(raw: &str) -> std::result::Result<String, String> {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' {
            if chars.get(i + 1).copied().is_some_and(is_escape_special) {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            let mut hex = String::new();
            let mut j = i;
            while chars.get(j) == Some(&'\\')
                && chars.get(j + 1).copied().is_some_and(py_alnum)
                && chars.get(j + 2).copied().is_some_and(py_alnum)
            {
                hex.push(chars[j + 1]);
                hex.push(chars[j + 2]);
                j += 3;
            }
            if j > i {
                out.push_str(&py_utf8_decode(&py_unhexlify(&hex)?)?);
                i = j;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    Ok(out)
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn py_utf8_decode_matches_cpython_texts() {
        assert_eq!(py_utf8_decode(b"ok").as_deref(), Ok("ok"));
        assert_eq!(
            py_utf8_decode(b"\xe2\x82\x28").unwrap_err(),
            "'utf-8' codec can't decode bytes in position 0-1: invalid continuation byte"
        );
        assert_eq!(
            py_utf8_decode(b"\xf0\x9f\x98").unwrap_err(),
            "'utf-8' codec can't decode bytes in position 0-2: unexpected end of data"
        );
    }

    #[test]
    fn oid_from_dotted_follows_rust_asn1() {
        assert_eq!(oid_from_dotted("2.5.4.3").unwrap(), vec![0x55, 0x04, 0x03]);
        assert!(oid_from_dotted("3.1").is_err());
        assert!(oid_from_dotted("1.40").is_err());
        assert_eq!(oid_from_dotted("2.999").unwrap(), vec![0x88, 0x37]);
        let long = format!("1.2{}", ".9999999".repeat(16));
        assert!(oid_from_dotted(&long).is_err());
    }
}
