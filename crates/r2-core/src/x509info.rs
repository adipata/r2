//! Certificate facts shared by memory, pkcs11 and services (spec §4.4.5, owner R6).
//!
//! Besides the §4.4.5 surface this module holds the crate-internal X.509 Name machinery
//! (strict DER walk, pyca's load-time value checks, `rfc4514_string`), which keyparse,
//! x509build and formats share so every caller sees pyca's (c2's) acceptance rules.
use std::collections::BTreeMap;

use openssl::pkey::PKey;

use crate::error::{ConsoleError, Result};
use crate::keyparse::{classify_key, load_public_der, ossl_detail};
use crate::keys::{Curve, KeyAlgorithm};
use crate::template::AttrValue;

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
    /// (On that read path a certificate c2 skipped — not listed — is told apart from one
    /// whose error propagates by `pkcs11_skips_certificate`.)
    Pkcs11,
}

/// Parse a DER certificate. Errors → KeyParse "certificate is not valid DER X.509: {detail}",
/// "certificate contains an invalid public key: {detail}".
pub fn cert_facts(cert_der: &[u8], classifier: Classifier) -> Result<CertFacts> {
    let cert = load_certificate(cert_der).map_err(invalid_cert)?;
    let pkey = cert_public_key(cert.spki, "certificate")?;
    let (algorithm, curve, size_bits) = classify_key(&pkey, classifier, false)?;
    let spki_der = pkey
        .public_key_to_der()
        .map_err(|err| invalid_public_key("certificate", &ossl_detail(&err)))?;
    Ok(CertFacts {
        algorithm,
        curve,
        size_bits,
        spki_der,
        subject_der: cert.subject.to_vec(),
        issuer_der: cert.issuer.to_vec(),
        serial_der: cert.serial.to_vec(),
        subject_cn: first_common_name(cert.subject),
    })
}
/// (algorithm, curve, size_bits) of a DER SPKI (classification rules of §4.4.3, per
/// `classifier`).
pub fn spki_facts(
    spki_der: &[u8],
    classifier: Classifier,
) -> Result<(KeyAlgorithm, Option<Curve>, Option<u32>)> {
    let invalid = |detail: &str| {
        ConsoleError::key_parse(format!(
            "public key is not a valid DER SubjectPublicKeyInfo: {detail}"
        ))
    };
    let pkey = load_public_der(spki_der).map_err(|detail| invalid(&detail))?;
    classify_key(&pkey, classifier, false)
}
/// c2's PKCS#11 certificate read path (provider.py `_key_info`) caught pyca's ValueError and
/// skipped the certificate (not listed) — while UnsupportedAlgorithm / TypeError / KeyError /
/// KeyParseError propagated (c2 crashed or failed `keys`; r2 propagates the error, §11
/// D12(b)). True when `err`, returned by `cert_facts` or `cert_attributes`, is of the skipped
/// kind: every "certificate is not valid DER X.509: …" except a BIT STRING value under an OID
/// other than x500UniqueIdentifier, an unknown Name value tag and pyca's InvalidVersion
/// ("{n} is not a valid X509 version"), and every "certificate
/// contains an invalid public key: …" except an unsupported curve ("Curve {oid} is not
/// supported", explicit parameters of another curve) or key type ("Unknown key type: {oid}",
/// "Unsupported key type."). "unsupported public key type …" propagates.
pub fn pkcs11_skips_certificate(err: &ConsoleError) -> bool {
    if err.kind != crate::error::ErrorKind::KeyParse {
        return false;
    }
    if let Some(detail) = err
        .message
        .strip_prefix("certificate contains an invalid public key: ")
    {
        let unsupported = (detail.starts_with("Curve ") && detail.ends_with(" is not supported"))
            || detail.starts_with("ECDSA keys with explicit parameters are only supported")
            || detail.starts_with("Unknown key type: ")
            || detail == "Unsupported key type.";
        return !unsupported;
    }
    if let Some(detail) = err
        .message
        .strip_prefix("certificate is not valid DER X.509: ")
    {
        return detail != BIT_STRING_OID_TEXT
            && !detail.starts_with(UNSUPPORTED_TAG_TEXT)
            && !is_invalid_version(detail);
    }
    false
}
/// Port of pyca `Name.rfc4514_string()`: RDNs reversed, '+' within an RDN, short names only
/// for CN L ST O OU C STREET DC UID (else dotted OID), `_escape_dn_value` escaping
/// (`\ " + , ; < >`, NUL → `\00`, leading `#`/space and trailing space), non-string
/// values (an x500UniqueIdentifier BIT STRING: its raw content) as `#hex` ("" when empty).
/// NOT x509-cert's Display.
pub fn rfc4514_string(name_der: &[u8]) -> Result<String> {
    let rdns = decode_name(name_der).map_err(|detail| {
        ConsoleError::key_parse(format!("name is not a valid DER X.509 Name: {detail}"))
    })?;
    Ok(format_rfc4514(&rdns))
}
/// `key info` rows for a certificate: ("subject", rfc4514), ("issuer", rfc4514),
/// ("serial", lower-case hex without leading zeros, "0" for zero), ("not valid before",
/// "YYYY-MM-DDTHH:MM:SS+00:00"), ("not valid after", same). Certificates are read by a
/// strict DER parser of pyca's whole `Certificate` structure with its load-time checks
/// (EXPLICIT [0] version DEFAULT v1 — an encoded v1 is EncodedDefault —, minimal INTEGERs,
/// both AlgorithmIdentifiers and the SPKI algorithm with pyca's DEFINED BY parameters, DER
/// UTCTime / GeneralizedTime, Name value alphabets, [1]/[2] unique IDs, [3] SEQUENCE OF
/// Extension { OID, BOOLEAN DEFAULT FALSE, OCTET STRING }, nothing after; then a version
/// other than v1/v3 is pyca's InvalidVersion "{n} is not a valid X509 version" — c2
/// crashed, §11 D12(b) — and CSRs likewise: version 0, [0] SET OF Attribute { OID, SET OF
/// ANY } in DER order), not x509-cert (whose const-oid rejects OIDs pyca reads); an
/// undecodable Name value → KeyParse "certificate is not valid DER X.509: {pyca
/// text}" and a GeneralizedTime in year 0 (which pyca loads) → "… X.509: year 0 is out of
/// range" (Python's datetime text; c2 crashed lazily in both cases, §11 D12(b)).
pub fn certificate_details(cert_der: &[u8]) -> Result<Vec<(String, String)>> {
    let facts = TextFacts::of(cert_der)?;
    Ok(vec![
        ("subject".to_owned(), facts.subject),
        ("issuer".to_owned(), facts.issuer),
        ("serial".to_owned(), facts.serial),
        (
            "not valid before".to_owned(),
            facts.not_before.iso().map_err(invalid_cert)?,
        ),
        (
            "not valid after".to_owned(),
            facts.not_after.iso().map_err(invalid_cert)?,
        ),
    ])
}
/// KeyInfo.attributes of a certificate on the PKCS#11 read path (c2 provider.py):
/// CKA_SUBJECT / CKA_ISSUER = Str(rfc4514), CKA_SERIAL_NUMBER = Str(serial hex as above).
pub fn cert_attributes(cert_der: &[u8]) -> Result<BTreeMap<String, AttrValue>> {
    let facts = TextFacts::of(cert_der)?;
    Ok(BTreeMap::from([
        ("CKA_SUBJECT".to_owned(), AttrValue::Str(facts.subject)),
        ("CKA_ISSUER".to_owned(), AttrValue::Str(facts.issuer)),
        ("CKA_SERIAL_NUMBER".to_owned(), AttrValue::Str(facts.serial)),
    ]))
}
/// KeyInfo.attributes of a MemoryProvider certificate (c2 memory.py `_cert_attributes`):
/// Str "subject", "issuer" (rfc4514), "serial_number" (hex as above), "not_valid_before",
/// "not_valid_after" ("YYYY-MM-DDTHH:MM:SS+00:00", pyca `isoformat()`).
pub fn memory_cert_attributes(cert_der: &[u8]) -> Result<BTreeMap<String, AttrValue>> {
    let facts = TextFacts::of(cert_der)?;
    Ok(BTreeMap::from([
        ("subject".to_owned(), AttrValue::Str(facts.subject)),
        ("issuer".to_owned(), AttrValue::Str(facts.issuer)),
        ("serial_number".to_owned(), AttrValue::Str(facts.serial)),
        (
            "not_valid_before".to_owned(),
            AttrValue::Str(facts.not_before.iso().map_err(invalid_cert)?),
        ),
        (
            "not_valid_after".to_owned(),
            AttrValue::Str(facts.not_after.iso().map_err(invalid_cert)?),
        ),
    ]))
}

// ---------------------------------------------------------------------------------------
// Certificate text facts
// ---------------------------------------------------------------------------------------

struct TextFacts {
    subject: String,
    issuer: String,
    serial: String,
    not_before: DerTime,
    not_after: DerTime,
}

impl TextFacts {
    fn of(cert_der: &[u8]) -> Result<Self> {
        let cert = load_certificate(cert_der).map_err(invalid_cert)?;
        let name_text = |der: &[u8]| -> Result<String> {
            let rdns = decode_name(der).map_err(invalid_cert)?;
            Ok(format_rfc4514(&rdns))
        };
        let (serial, _) = read_tlv(cert.serial).map_err(invalid_cert)?;
        Ok(Self {
            subject: name_text(cert.subject)?,
            issuer: name_text(cert.issuer)?,
            serial: py_int_hex(serial.content),
            not_before: cert.not_before,
            not_after: cert.not_after,
        })
    }
}

fn invalid_cert(detail: String) -> ConsoleError {
    ConsoleError::key_parse(format!("certificate is not valid DER X.509: {detail}"))
}

fn invalid_public_key(what: &str, detail: &str) -> ConsoleError {
    ConsoleError::key_parse(format!("{what} contains an invalid public key: {detail}"))
}

/// The embedded SPKI of a certificate / CSR as a normalized OpenSSL key (pyca
/// `public_key()` = `load_der_public_key` of the SPKI); failures → "{what} contains an
/// invalid public key: {detail}".
pub(crate) fn cert_public_key(spki_der: &[u8], what: &str) -> Result<PKey<openssl::pkey::Public>> {
    load_public_der(spki_der).map_err(|detail| invalid_public_key(what, &detail))
}

/// Python `format(n, "x")` of a DER INTEGER content (two's complement, big-endian).
fn py_int_hex(content: &[u8]) -> String {
    let negative = content.first().is_some_and(|b| b & 0x80 != 0);
    let magnitude: Vec<u8> = if negative {
        // two's complement → magnitude: invert and add one
        let mut out: Vec<u8> = content.iter().map(|b| !b).collect();
        for byte in out.iter_mut().rev() {
            let (value, carry) = byte.overflowing_add(1);
            *byte = value;
            if !carry {
                break;
            }
        }
        out
    } else {
        content.to_vec()
    };
    let hex = hex::encode(&magnitude);
    let trimmed = hex.trim_start_matches('0');
    let digits = if trimmed.is_empty() { "0" } else { trimmed };
    if negative {
        format!("-{digits}")
    } else {
        digits.to_owned()
    }
}

/// A UTC instant of a certificate's validity (UTCTime or GeneralizedTime, DER form).
pub(crate) struct DerTime {
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

impl DerTime {
    /// pyca `not_valid_*_utc.isoformat()`: "YYYY-MM-DDTHH:MM:SS+00:00". A GeneralizedTime
    /// in year 0 loads in pyca, but Python's `datetime` refuses it (c2 crashed in
    /// `certificate_details`; §11 D12(b)).
    fn iso(&self) -> std::result::Result<String, String> {
        if self.year == 0 {
            return Err("year 0 is out of range".to_owned());
        }
        Ok(format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        ))
    }

    /// UTCTime "YYMMDDHHMMSSZ" (RFC 5280: 50..=99 → 19xx) or GeneralizedTime
    /// "YYYYMMDDHHMMSSZ"; no fractions, no offsets (DER).
    fn parse(tlv: &Tlv<'_>) -> std::result::Result<Self, String> {
        let invalid = || ASN1_ERR.to_owned();
        let text = std::str::from_utf8(tlv.content).map_err(|_| invalid())?;
        let digits = text.strip_suffix('Z').ok_or_else(invalid)?;
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        let num = |range: std::ops::Range<usize>| -> std::result::Result<u32, String> {
            digits
                .get(range)
                .ok_or_else(invalid)?
                .parse()
                .map_err(|_| invalid())
        };
        let (year, rest) = match (tlv.tag, digits.len()) {
            (0x17, 12) => {
                let yy = num(0..2)?;
                (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
            }
            (0x18, 14) => (num(0..4)?, 4),
            _ => return Err(invalid()),
        };
        let time = Self {
            year,
            month: num(rest..rest + 2)?,
            day: num(rest + 2..rest + 4)?,
            hour: num(rest + 4..rest + 6)?,
            minute: num(rest + 6..rest + 8)?,
            second: num(rest + 8..rest + 10)?,
        };
        let leap = (time.year.is_multiple_of(4) && !time.year.is_multiple_of(100))
            || time.year.is_multiple_of(400);
        let days = match time.month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return Err(invalid()),
        };
        if time.day == 0
            || time.day > days
            || time.hour > 23
            || time.minute > 59
            || time.second > 59
        {
            return Err(invalid());
        }
        Ok(time)
    }
}

/// The parts of a certificate r2 reads (raw TLVs of the original encoding).
pub(crate) struct CertParts<'a> {
    /// The serial INTEGER TLV.
    pub(crate) serial: &'a [u8],
    pub(crate) issuer: &'a [u8],
    pub(crate) subject: &'a [u8],
    pub(crate) spki: &'a [u8],
    pub(crate) not_before: DerTime,
    pub(crate) not_after: DerTime,
}

// ---------------------------------------------------------------------------------------
// pyca's DER reader: a port of rust-asn1 0.24 (what cryptography 49 parses with) and of
// the structures pyca parses at load time (cryptography-x509 / cryptography-key-parsing)
// ---------------------------------------------------------------------------------------

/// rust-asn1's `ParseErrorKind` (location paths are not reproduced, §11 D11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Asn1Error {
    InvalidValue,
    InvalidTag,
    InvalidLength,
    InvalidSize { min: usize, actual: usize },
    UnexpectedTag(u8),
    ShortData(usize),
    IntegerOverflow,
    ExtraData,
    InvalidSetOrdering,
    EncodedDefault,
    OidTooLong,
    UnknownDefinedBy,
}

pub(crate) type Asn1Result<T> = std::result::Result<T, Asn1Error>;

impl Asn1Error {
    fn kind_debug(self) -> String {
        match self {
            Asn1Error::InvalidValue => "InvalidValue".to_owned(),
            Asn1Error::InvalidTag => "InvalidTag".to_owned(),
            Asn1Error::InvalidLength => "InvalidLength".to_owned(),
            Asn1Error::InvalidSize { min, actual } => format!(
                "InvalidSize {{ min: {min}, max: {}, actual: {actual} }}",
                usize::MAX
            ),
            Asn1Error::UnexpectedTag(tag) => {
                format!("UnexpectedTag {{ actual: {} }}", tag_debug(tag))
            }
            Asn1Error::ShortData(needed) => format!("ShortData {{ needed: {needed} }}"),
            Asn1Error::IntegerOverflow => "IntegerOverflow".to_owned(),
            Asn1Error::ExtraData => "ExtraData".to_owned(),
            Asn1Error::InvalidSetOrdering => "InvalidSetOrdering".to_owned(),
            Asn1Error::EncodedDefault => "EncodedDefault".to_owned(),
            Asn1Error::OidTooLong => "OidTooLong".to_owned(),
            Asn1Error::UnknownDefinedBy => "UnknownDefinedBy".to_owned(),
        }
    }

    /// pyca's `Asn1Parse` text: "error parsing asn1 value: ParseError { kind: … }".
    pub(crate) fn text(self) -> String {
        format!(
            "error parsing asn1 value: ParseError {{ kind: {} }}",
            self.kind_debug()
        )
    }

    /// rust-asn1's `Display` (pyca's key-parsing "Details: …").
    pub(crate) fn display(self) -> String {
        let detail = match self {
            Asn1Error::InvalidValue => "invalid value".to_owned(),
            Asn1Error::InvalidTag => "invalid tag".to_owned(),
            Asn1Error::InvalidLength => "invalid length".to_owned(),
            Asn1Error::InvalidSize { min, actual } => format!(
                "invalid container size (expected between {min} and {}, got {actual})",
                usize::MAX
            ),
            Asn1Error::UnexpectedTag(tag) => format!("unexpected tag (got {})", tag_debug(tag)),
            Asn1Error::ShortData(needed) => {
                format!("short data (needed at least {needed} additional bytes)")
            }
            Asn1Error::IntegerOverflow => "integer overflow".to_owned(),
            Asn1Error::ExtraData => "extra data".to_owned(),
            Asn1Error::InvalidSetOrdering => "SET value was ordered incorrectly".to_owned(),
            Asn1Error::EncodedDefault => "DEFAULT value was explicitly encoded".to_owned(),
            Asn1Error::OidTooLong => {
                "OBJECT IDENTIFIER was too large to be stored in rust-asn1's buffer".to_owned()
            }
            Asn1Error::UnknownDefinedBy => "DEFINED BY with unknown value".to_owned(),
        };
        format!("ASN.1 parsing error: {detail}")
    }
}

/// rust-asn1's `Parser`: TLVs read from the front (tags of any length — `Tlv::tag` keeps
/// the first byte —, definite lengths of at most 4 bytes, minimally encoded).
pub(crate) struct Der<'a> {
    data: &'a [u8],
}

impl<'a> Der<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.data.first().copied()
    }

    fn take(&mut self, n: usize) -> Asn1Result<&'a [u8]> {
        if n > self.data.len() {
            return Err(Asn1Error::ShortData(n - self.data.len()));
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(head)
    }

    /// Any one TLV.
    pub(crate) fn any(&mut self) -> Asn1Result<Tlv<'a>> {
        let start = self.data;
        let tag = self.take(1)?[0];
        if tag & 0x1f == 0x1f {
            // long-form tag: base-128, minimal, value >= 0x1f, fits in u32
            let mut value: u64 = 0;
            let mut first = true;
            loop {
                let byte = self.take(1)?[0];
                if first && byte == 0x80 {
                    return Err(Asn1Error::InvalidTag);
                }
                first = false;
                value = (value << 7) | u64::from(byte & 0x7f);
                if value > u64::from(u32::MAX) {
                    return Err(Asn1Error::InvalidTag);
                }
                if byte & 0x80 == 0 {
                    break;
                }
            }
            if value < 0x1f {
                return Err(Asn1Error::InvalidTag);
            }
        }
        let first = self.take(1)?[0];
        let len = match first {
            n if n & 0x80 == 0 => usize::from(n),
            0x81..=0x84 => {
                let count = usize::from(first & 0x7f);
                let bytes = self.take(count)?;
                let len = bytes
                    .iter()
                    .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
                let minimum = 1usize << (8 * (count - 1));
                if len < minimum.max(0x80) {
                    return Err(Asn1Error::InvalidLength);
                }
                len
            }
            _ => return Err(Asn1Error::InvalidLength),
        };
        let header = start.len() - self.data.len();
        let content = self.take(len)?;
        Ok(Tlv {
            tag,
            content,
            raw: &start[..header + len],
        })
    }

    /// One TLV with tag `tag` (rust-asn1 reads the whole TLV before comparing the tag).
    pub(crate) fn tagged(&mut self, tag: u8) -> Asn1Result<Tlv<'a>> {
        let tlv = self.any()?;
        if tlv.tag != tag {
            return Err(Asn1Error::UnexpectedTag(tlv.tag));
        }
        Ok(tlv)
    }

    /// `Option<T>`: present when the next tag is `tag`.
    pub(crate) fn opt(&mut self, tag: u8) -> Asn1Result<Option<Tlv<'a>>> {
        if self.peek() == Some(tag) {
            self.tagged(tag).map(Some)
        } else {
            Ok(None)
        }
    }

    pub(crate) fn finish(&self) -> Asn1Result<()> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(Asn1Error::ExtraData)
        }
    }
}

/// `parse_single` of a value with tag `tag` whose content needs no further parsing (or
/// whose content errors may be reported after trailing data — prefer `der_head`).
pub(crate) fn der_single(data: &[u8], tag: u8) -> Asn1Result<Tlv<'_>> {
    let mut der = Der::new(data);
    let tlv = der.tagged(tag)?;
    der.finish()?;
    Ok(tlv)
}

/// The first half of rust-asn1's `parse_single`: the TLV with tag `tag` plus the parser
/// positioned after it. rust-asn1 parses (and validates) the whole value's content BEFORE
/// it reports data after the value (`ExtraData`), so callers parse the content first and
/// call `rest.finish()` afterwards — e.g. a PKCS#8 key followed by a 0x00 fails pyca's last
/// attempt (EncryptedPrivateKeyInfo) with "unexpected tag (got Tag { value: 2, … })", not
/// "extra data".
pub(crate) fn der_head(data: &[u8], tag: u8) -> Asn1Result<(Tlv<'_>, Der<'_>)> {
    let mut der = Der::new(data);
    let tlv = der.tagged(tag)?;
    Ok((tlv, der))
}

/// rust-asn1 `validate_integer`.
fn der_integer(content: &[u8], signed: bool) -> Asn1Result<()> {
    if content.is_empty() {
        return Err(Asn1Error::InvalidValue);
    }
    if content.len() > 1
        && ((content[0] == 0 && content[1] & 0x80 == 0)
            || (content[0] == 0xff && content[1] & 0x80 != 0))
    {
        return Err(Asn1Error::InvalidValue);
    }
    if !signed && content[0] & 0x80 != 0 {
        return Err(Asn1Error::InvalidValue);
    }
    Ok(())
}

/// An unsigned rust-asn1 integer of `size` bytes (u8/u16/u32/u64).
pub(crate) fn der_uint(tlv: &Tlv<'_>, size: usize) -> Asn1Result<u64> {
    if tlv.tag != 0x02 {
        return Err(Asn1Error::UnexpectedTag(tlv.tag));
    }
    der_integer(tlv.content, false)?;
    let mut data = tlv.content;
    if data.len() == size + 1 && data[0] == 0 {
        data = &data[1..];
    }
    if data.len() > size {
        return Err(Asn1Error::IntegerOverflow);
    }
    Ok(data.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
}

/// `asn1::BigUint`: the content (with its sign octet).
pub(crate) fn der_biguint<'a>(tlv: &Tlv<'a>) -> Asn1Result<&'a [u8]> {
    if tlv.tag != 0x02 {
        return Err(Asn1Error::UnexpectedTag(tlv.tag));
    }
    der_integer(tlv.content, false)?;
    Ok(tlv.content)
}

/// `asn1::BitString`: the bytes (padding bits must be zero).
pub(crate) fn der_bits<'a>(tlv: &Tlv<'a>) -> Asn1Result<&'a [u8]> {
    let (unused, bits) = tlv.content.split_first().ok_or(Asn1Error::InvalidValue)?;
    let ok = *unused <= 7
        && (bits.is_empty() && *unused == 0
            || bits
                .last()
                .is_some_and(|last| last & ((1u8 << *unused) - 1) == 0));
    if ok {
        Ok(bits)
    } else {
        Err(Asn1Error::InvalidValue)
    }
}

/// `asn1::ObjectIdentifier`.
pub(crate) fn der_oid(tlv: &Tlv<'_>) -> Asn1Result<()> {
    if tlv.content.len() > 63 {
        return Err(Asn1Error::OidTooLong);
    }
    oid_dotted(tlv.content)
        .map(|_| ())
        .ok_or(Asn1Error::InvalidValue)
}

fn der_null(tlv: &Tlv<'_>) -> Asn1Result<()> {
    if tlv.content.is_empty() {
        Ok(())
    } else {
        Err(Asn1Error::InvalidValue)
    }
}

fn der_bool(tlv: &Tlv<'_>) -> Asn1Result<bool> {
    match tlv.content {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(Asn1Error::InvalidValue),
    }
}

/// `[u8; N]`: an OCTET STRING of exactly `n` bytes.
fn der_fixed<'a>(tlv: &Tlv<'a>, n: usize) -> Asn1Result<&'a [u8]> {
    if tlv.content.len() == n {
        Ok(tlv.content)
    } else {
        Err(Asn1Error::InvalidValue)
    }
}

/// `SET OF T`: DER ordering, every element parsed by `each`.
fn der_set_of<'a>(
    content: &'a [u8],
    mut each: impl FnMut(&Tlv<'a>) -> Asn1Result<()>,
) -> Asn1Result<()> {
    let mut der = Der::new(content);
    let mut last: Option<&[u8]> = None;
    while !der.is_empty() {
        let tlv = der.any()?;
        if last.is_some_and(|prev| tlv.raw < prev) {
            return Err(Asn1Error::InvalidSetOrdering);
        }
        last = Some(tlv.raw);
        each(&tlv)?;
    }
    Ok(())
}

/// `SEQUENCE OF T`: the element count (every element parsed by `each`).
fn der_sequence_of<'a>(
    content: &'a [u8],
    mut each: impl FnMut(&mut Der<'a>) -> Asn1Result<()>,
) -> Asn1Result<usize> {
    let mut der = Der::new(content);
    let mut count = 0;
    while !der.is_empty() {
        each(&mut der)?;
        count += 1;
    }
    Ok(count)
}

// OIDs of pyca's `AlgorithmParameters` table (DER content bytes).
pub(crate) const O_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const O_HASHES: [&[u8]; 13] = [
    O_SHA1,
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
    &[
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa4, 0x64, 0x03, 0x02, 0x01, 0x63, 0x07, 0x81, 0x60,
    ],
    &[
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa4, 0x64, 0x03, 0x02, 0x01, 0x63, 0x07, 0x82, 0x00,
    ],
    &[
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa4, 0x64, 0x03, 0x02, 0x01, 0x63, 0x07, 0x83, 0x00,
    ],
    &[
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa4, 0x64, 0x03, 0x02, 0x01, 0x63, 0x07, 0x84, 0x00,
    ],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a],
];
pub(crate) const O_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
pub(crate) const O_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
/// sha*WithRSAEncryption (incl. the SHA-3 ones and 1.3.14.3.2.29).
const O_RSA_SIGS: [&[u8]; 10] = [
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05],
    &[0x2b, 0x0e, 0x03, 0x02, 0x1d],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0d],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0e],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0f],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x10],
];
/// hmacWithSHA1/224/256/384/512.
pub(crate) const O_HMACS: [&[u8]; 5] = [
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x08],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b],
];
pub(crate) const O_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
pub(crate) const O_ED448: &[u8] = &[0x2b, 0x65, 0x71];
pub(crate) const O_X25519: &[u8] = &[0x2b, 0x65, 0x6e];
pub(crate) const O_X448: &[u8] = &[0x2b, 0x65, 0x6f];
/// Parameter-less algorithms: ML-DSA-44/65/87, ML-KEM-768/1024, ecdsa-with-SHA224..512,
/// ecdsa-with-SHA3-*, dsa-with-SHA224..512.
const O_NO_PARAMS: [&[u8]; 17] = [
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03],
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01],
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03],
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x09],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0a],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0b],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0c],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x01],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x03],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x04],
];
pub(crate) const O_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
pub(crate) const O_DSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01];
pub(crate) const O_DH: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x01];
pub(crate) const O_DH_KEY_AGREEMENT: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x01];
pub(crate) const O_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
pub(crate) const O_PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
pub(crate) const O_SCRYPT: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x04, 0x0b];
pub(crate) const O_AES128_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02];
pub(crate) const O_AES192_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16];
pub(crate) const O_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];
pub(crate) const O_DES_EDE3_CBC: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07];
pub(crate) const O_RC2_CBC: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02];
pub(crate) const O_PBE_MD5_DES: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x03];
pub(crate) const O_PBE_SHA_RC4_128: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x01];
pub(crate) const O_PBE_SHA_3DES: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03];
pub(crate) const O_PBE_SHA_RC2_40: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x06];
const O_PRIME_FIELD: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01];
const O_CHAR_TWO_FIELD: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x02];

/// DER of pyca's DEFAULT values: RSASSA-PSS hash (SHA-1, NULL), mask generation (MGF1 over
/// SHA-1, NULL) and PBKDF2 PRF (hmacWithSHA1, NULL).
const PSS_DEFAULT_HASH: &[u8] = &[
    0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
];
const PSS_DEFAULT_MGF: &[u8] = &[
    0x30, 0x16, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x09, 0x06,
    0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
];
const PBKDF2_DEFAULT_PRF: &[u8] = &[
    0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07, 0x05, 0x00,
];

/// pyca `EcParameters` (`raw` = the whole TLV, compared for equality).
#[derive(Clone, Copy)]
pub(crate) struct EcParams<'a> {
    pub(crate) kind: EcParamsKind<'a>,
    pub(crate) raw: &'a [u8],
}

#[derive(Clone, Copy)]
pub(crate) enum EcParamsKind<'a> {
    /// The curve OID's content.
    Named(&'a [u8]),
    Implicit,
    Specified,
}

/// The parameters r2 reads of pyca's `AlgorithmParameters` (others: `Other`).
pub(crate) enum AlgParams<'a> {
    Other,
    Ec(EcParams<'a>),
    Dss {
        p: &'a [u8],
        q: &'a [u8],
        g: &'a [u8],
    },
    Dh {
        p: &'a [u8],
        g: &'a [u8],
        q: Option<&'a [u8]>,
    },
    Pbes2 {
        kdf: Box<AlgId<'a>>,
        enc: Box<AlgId<'a>>,
    },
    Pbkdf2 {
        salt: &'a [u8],
        iterations: u64,
        /// The PRF's OID content (hmacWithSHA1 when absent).
        prf: &'a [u8],
    },
    Scrypt {
        salt: &'a [u8],
        n: u64,
        r: u64,
        p: u64,
    },
    Iv(&'a [u8]),
    Rc2 {
        version: Option<u64>,
        iv: &'a [u8],
    },
    Pbe {
        salt: &'a [u8],
        iterations: u64,
    },
}

/// pyca `AlgorithmIdentifier` (parameters parsed per its DEFINED BY table).
pub(crate) struct AlgId<'a> {
    pub(crate) oid: &'a [u8],
    pub(crate) params: AlgParams<'a>,
}

impl AlgId<'_> {
    pub(crate) fn dotted(&self) -> String {
        oid_dotted(self.oid).unwrap_or_default()
    }
}

/// `AlgorithmIdentifier` from a SEQUENCE TLV.
pub(crate) fn alg_id<'a>(tlv: &Tlv<'a>) -> Asn1Result<AlgId<'a>> {
    if tlv.tag != 0x30 {
        return Err(Asn1Error::UnexpectedTag(tlv.tag));
    }
    let mut der = Der::new(tlv.content);
    let oid_tlv = der.tagged(0x06)?;
    der_oid(&oid_tlv)?;
    let oid = oid_tlv.content;
    let params = if O_HASHES.contains(&oid)
        || oid == O_RSA
        || O_RSA_SIGS.contains(&oid)
        || O_HMACS.contains(&oid)
    {
        if let Some(null) = der.opt(0x05)? {
            der_null(&null)?;
        }
        AlgParams::Other
    } else if [O_ED25519, O_ED448, O_X25519, O_X448].contains(&oid) || O_NO_PARAMS.contains(&oid) {
        AlgParams::Other
    } else if oid == O_EC {
        AlgParams::Ec(ec_params(&der.any()?)?)
    } else if oid == O_RSA_PSS {
        if let Some(seq) = der.opt(0x30)? {
            pss_params(seq.content)?;
        }
        AlgParams::Other
    } else if oid == O_DSA {
        let seq = der.tagged(0x30)?;
        let mut inner = Der::new(seq.content);
        let p = der_biguint(&inner.any()?)?;
        let q = der_biguint(&inner.any()?)?;
        let g = der_biguint(&inner.any()?)?;
        inner.finish()?;
        AlgParams::Dss { p, q, g }
    } else if oid == O_DH {
        let seq = der.tagged(0x30)?;
        let mut inner = Der::new(seq.content);
        let p = der_biguint(&inner.any()?)?;
        let g = der_biguint(&inner.any()?)?;
        let q = der_biguint(&inner.any()?)?;
        if let Some(j) = inner.opt(0x02)? {
            der_biguint(&j)?;
        }
        inner.opt(0x30)?;
        inner.finish()?;
        AlgParams::Dh { p, g, q: Some(q) }
    } else if oid == O_DH_KEY_AGREEMENT {
        let seq = der.tagged(0x30)?;
        let mut inner = Der::new(seq.content);
        let p = der_biguint(&inner.any()?)?;
        let g = der_biguint(&inner.any()?)?;
        if let Some(length) = inner.opt(0x02)? {
            der_uint(&length, 4)?;
        }
        inner.finish()?;
        AlgParams::Dh { p, g, q: None }
    } else if oid == O_PBES2 {
        let seq = der.tagged(0x30)?;
        let mut inner = Der::new(seq.content);
        let kdf = alg_id(&inner.tagged(0x30)?)?;
        let enc = alg_id(&inner.tagged(0x30)?)?;
        inner.finish()?;
        AlgParams::Pbes2 {
            kdf: Box::new(kdf),
            enc: Box::new(enc),
        }
    } else if oid == O_PBKDF2 {
        let seq = der.tagged(0x30)?;
        let mut inner = Der::new(seq.content);
        let salt = inner.tagged(0x04)?.content;
        let iterations = der_uint(&inner.any()?, 8)?;
        if let Some(length) = inner.opt(0x02)? {
            der_uint(&length, 8)?;
        }
        let prf = match inner.opt(0x30)? {
            Some(prf) => {
                if prf.raw == PBKDF2_DEFAULT_PRF {
                    return Err(Asn1Error::EncodedDefault);
                }
                alg_id(&prf)?.oid
            }
            None => O_HMACS[0],
        };
        inner.finish()?;
        AlgParams::Pbkdf2 {
            salt,
            iterations,
            prf,
        }
    } else if oid == O_SCRYPT {
        let seq = der.tagged(0x30)?;
        let mut inner = Der::new(seq.content);
        let salt = inner.tagged(0x04)?.content;
        let n = der_uint(&inner.any()?, 8)?;
        let r = der_uint(&inner.any()?, 8)?;
        let p = der_uint(&inner.any()?, 8)?;
        if let Some(length) = inner.opt(0x02)? {
            der_uint(&length, 4)?;
        }
        inner.finish()?;
        AlgParams::Scrypt { salt, n, r, p }
    } else if [O_AES128_CBC, O_AES192_CBC, O_AES256_CBC].contains(&oid) {
        AlgParams::Iv(der_fixed(&der.tagged(0x04)?, 16)?)
    } else if oid == O_DES_EDE3_CBC {
        AlgParams::Iv(der_fixed(&der.tagged(0x04)?, 8)?)
    } else if oid == O_RC2_CBC {
        let seq = der.tagged(0x30)?;
        let mut inner = Der::new(seq.content);
        let version = match inner.opt(0x02)? {
            Some(version) => Some(der_uint(&version, 4)?),
            None => None,
        };
        let iv = der_fixed(&inner.tagged(0x04)?, 8)?;
        inner.finish()?;
        AlgParams::Rc2 { version, iv }
    } else if oid == O_PBE_MD5_DES {
        let seq = der.tagged(0x30)?;
        let mut inner = Der::new(seq.content);
        let salt = der_fixed(&inner.tagged(0x04)?, 8)?;
        let iterations = der_uint(&inner.any()?, 8)?;
        inner.finish()?;
        AlgParams::Pbe { salt, iterations }
    } else if [O_PBE_SHA_RC4_128, O_PBE_SHA_3DES, O_PBE_SHA_RC2_40].contains(&oid) {
        let seq = der.tagged(0x30)?;
        let mut inner = Der::new(seq.content);
        let salt = inner.tagged(0x04)?.content;
        let iterations = der_uint(&inner.any()?, 8)?;
        inner.finish()?;
        AlgParams::Pbe { salt, iterations }
    } else {
        // `Other(oid, Option<Tlv>)`
        if !der.is_empty() {
            der.any()?;
        }
        AlgParams::Other
    };
    der.finish()?;
    Ok(AlgId { oid, params })
}

/// pyca `EcParameters`: a CHOICE of a curve OID, NULL (implicitlyCA) or a
/// `SpecifiedECDomain`.
pub(crate) fn ec_params<'a>(tlv: &Tlv<'a>) -> Asn1Result<EcParams<'a>> {
    let kind = match tlv.tag {
        0x06 => {
            der_oid(tlv)?;
            EcParamsKind::Named(tlv.content)
        }
        0x05 => {
            der_null(tlv)?;
            EcParamsKind::Implicit
        }
        0x30 => {
            specified_domain(tlv.content)?;
            EcParamsKind::Specified
        }
        other => return Err(Asn1Error::UnexpectedTag(other)),
    };
    Ok(EcParams { kind, raw: tlv.raw })
}

/// `SpecifiedECDomain { version u8, FieldID, Curve { a, b, seed BIT STRING OPTIONAL }, base,
/// order BigUint, cofactor u8 OPTIONAL }`.
fn specified_domain(content: &[u8]) -> Asn1Result<()> {
    let mut der = Der::new(content);
    der_uint(&der.any()?, 1)?;
    let field = der.tagged(0x30)?;
    let mut inner = Der::new(field.content);
    let field_type = inner.tagged(0x06)?;
    der_oid(&field_type)?;
    if field_type.content == O_PRIME_FIELD {
        der_biguint(&inner.any()?)?;
    } else if field_type.content == O_CHAR_TWO_FIELD {
        inner.tagged(0x30)?;
    } else {
        return Err(Asn1Error::UnknownDefinedBy);
    }
    inner.finish()?;
    let curve = der.tagged(0x30)?;
    let mut inner = Der::new(curve.content);
    inner.tagged(0x04)?;
    inner.tagged(0x04)?;
    if let Some(seed) = inner.opt(0x03)? {
        der_bits(&seed)?;
    }
    inner.finish()?;
    der.tagged(0x04)?;
    der_biguint(&der.any()?)?;
    if let Some(cofactor) = der.opt(0x02)? {
        der_uint(&cofactor, 1)?;
    }
    der.finish()
}

/// `RsaPssParameters` (each field EXPLICIT; an encoded DEFAULT is refused).
fn pss_params(content: &[u8]) -> Asn1Result<()> {
    let mut der = Der::new(content);
    if let Some(hash) = der.opt(0xa0)? {
        let (inner, after) = der_head(hash.content, 0x30)?;
        alg_id(&inner)?;
        after.finish()?;
        if inner.raw == PSS_DEFAULT_HASH {
            return Err(Asn1Error::EncodedDefault);
        }
    }
    if let Some(mgf) = der.opt(0xa1)? {
        let (inner, after) = der_head(mgf.content, 0x30)?;
        let mut fields = Der::new(inner.content);
        der_oid(&fields.tagged(0x06)?)?;
        alg_id(&fields.tagged(0x30)?)?;
        fields.finish()?;
        after.finish()?;
        if inner.raw == PSS_DEFAULT_MGF {
            return Err(Asn1Error::EncodedDefault);
        }
    }
    if let Some(salt) = der.opt(0xa2)? {
        let mut inner = Der::new(salt.content);
        let value = der_uint(&inner.any()?, 2)?;
        inner.finish()?;
        if value == 20 {
            return Err(Asn1Error::EncodedDefault);
        }
    }
    if let Some(trailer) = der.opt(0xa3)? {
        let mut inner = Der::new(trailer.content);
        der_uint(&inner.any()?, 1)?;
        inner.finish()?;
    }
    der.finish()
}

/// pyca `SubjectPublicKeyInfo` (algorithm + key bits).
pub(crate) struct Spki<'a> {
    pub(crate) alg: AlgId<'a>,
    pub(crate) key: &'a [u8],
}

/// `SubjectPublicKeyInfo` from a SEQUENCE TLV.
pub(crate) fn spki_fields<'a>(tlv: &Tlv<'a>) -> Asn1Result<Spki<'a>> {
    if tlv.tag != 0x30 {
        return Err(Asn1Error::UnexpectedTag(tlv.tag));
    }
    let mut der = Der::new(tlv.content);
    let alg = alg_id(&der.tagged(0x30)?)?;
    let key = der_bits(&der.tagged(0x03)?)?;
    der.finish()?;
    Ok(Spki { alg, key })
}

/// CSR / PKCS#8 `Attributes`: SET OF Attribute { OID, SET OF ANY } (DER ordering).
pub(crate) fn der_attributes(content: &[u8]) -> Asn1Result<()> {
    der_set_of(content, |attribute| {
        if attribute.tag != 0x30 {
            return Err(Asn1Error::UnexpectedTag(attribute.tag));
        }
        let mut der = Der::new(attribute.content);
        der_oid(&der.tagged(0x06)?)?;
        let values = der.tagged(0x31)?;
        der_set_of(values.content, |_| Ok(()))?;
        der.finish()
    })
}

/// `SEQUENCE OF Sequence` with at least one element (RSA otherPrimeInfos).
pub(crate) fn der_nonempty_sequences(content: &[u8]) -> Asn1Result<()> {
    let count = der_sequence_of(content, |der| der.tagged(0x30).map(|_| ()))?;
    if count < 1 {
        return Err(Asn1Error::InvalidSize { min: 1, actual: 0 });
    }
    Ok(())
}

/// The text of pyca's InvalidVersion for a certificate (c2 crashed: not a ValueError).
fn invalid_cert_version(version: u64) -> String {
    format!("{version} is not a valid X509 version")
}

/// True when `detail` is pyca's InvalidVersion text (certificate or CSR): c2 crashed on it
/// (an `Exception`, not a ValueError), so r2 propagates it as a KeyParse error where c2's
/// `except ValueError` would have moved on (§11 D12(b)).
pub(crate) fn is_invalid_version(detail: &str) -> bool {
    detail.ends_with(" is not a valid X509 version")
        || detail.ends_with(" is not a valid CSR version")
}

/// The DER form check of a Time (CHOICE UTCTime / GeneralizedTime).
fn der_time(tlv: Tlv<'_>) -> std::result::Result<DerTime, String> {
    if tlv.tag != 0x17 && tlv.tag != 0x18 {
        return Err(Asn1Error::UnexpectedTag(tlv.tag).text());
    }
    DerTime::parse(&tlv)
}

/// Strict DER certificate load (pyca `load_der_x509_certificate`): the whole `Certificate`
/// structure as pyca parses it — EXPLICIT [0] version with DEFAULT v1 (an encoded 0 is
/// refused), INTEGER serial, both AlgorithmIdentifiers with their DEFINED BY parameters,
/// Names (with pyca's value checks), DER times, the SPKI (algorithm parameters parsed),
/// [1]/[2] IMPLICIT BIT STRING unique IDs, [3] EXPLICIT SEQUENCE OF Extension { OID,
/// BOOLEAN DEFAULT FALSE, OCTET STRING }, nothing else — then a version other than v1/v3 is
/// pyca's InvalidVersion ("{n} is not a valid X509 version", see `is_invalid_version`).
/// OIDs are read with unbounded arcs (rust-asn1), so names x509-cert/const-oid cannot hold
/// load too.
pub(crate) fn load_certificate(der: &[u8]) -> std::result::Result<CertParts<'_>, String> {
    let asn1 = |e: Asn1Error| e.text();
    let (cert, rest) = der_head(der, 0x30).map_err(asn1)?;
    let mut outer = Der::new(cert.content);
    let tbs = outer.tagged(0x30).map_err(asn1)?;
    let mut fields = Der::new(tbs.content);
    let version = match fields.opt(0xa0).map_err(asn1)? {
        Some(explicit) => {
            let mut inner = Der::new(explicit.content);
            let version = der_uint(&inner.any().map_err(asn1)?, 1).map_err(asn1)?;
            inner.finish().map_err(asn1)?;
            if version == 0 {
                return Err(asn1(Asn1Error::EncodedDefault));
            }
            version
        }
        None => 0,
    };
    let serial = fields.tagged(0x02).map_err(asn1)?;
    der_integer(serial.content, true).map_err(asn1)?;
    alg_id(&fields.any().map_err(asn1)?).map_err(asn1)?;
    let issuer = fields.tagged(0x30).map_err(asn1)?;
    validate_name_load(issuer.raw)?;
    let validity = fields.tagged(0x30).map_err(asn1)?;
    let mut times = Der::new(validity.content);
    let not_before = der_time(times.any().map_err(asn1)?)?;
    let not_after = der_time(times.any().map_err(asn1)?)?;
    times.finish().map_err(asn1)?;
    let subject = fields.tagged(0x30).map_err(asn1)?;
    validate_name_load(subject.raw)?;
    let spki = fields.any().map_err(asn1)?;
    spki_fields(&spki).map_err(asn1)?;
    for tag in [0x81, 0x82] {
        if let Some(unique_id) = fields.opt(tag).map_err(asn1)? {
            der_bits(&unique_id).map_err(asn1)?;
        }
    }
    if let Some(explicit) = fields.opt(0xa3).map_err(asn1)? {
        let (extensions, after) = der_head(explicit.content, 0x30).map_err(asn1)?;
        der_sequence_of(extensions.content, |der| {
            let extension = der.tagged(0x30)?;
            let mut inner = Der::new(extension.content);
            der_oid(&inner.tagged(0x06)?)?;
            if let Some(critical) = inner.opt(0x01)?
                && !der_bool(&critical)?
            {
                return Err(Asn1Error::EncodedDefault);
            }
            inner.tagged(0x04)?;
            inner.finish()
        })
        .map_err(asn1)?;
        after.finish().map_err(asn1)?;
    }
    fields.finish().map_err(asn1)?;
    alg_id(&outer.any().map_err(asn1)?).map_err(asn1)?;
    der_bits(&outer.tagged(0x03).map_err(asn1)?).map_err(asn1)?;
    outer.finish().map_err(asn1)?;
    rest.finish().map_err(asn1)?;
    if version != 2 && version != 0 {
        return Err(invalid_cert_version(version));
    }
    Ok(CertParts {
        serial: serial.raw,
        issuer: issuer.raw,
        subject: subject.raw,
        spki: spki.raw,
        not_before,
        not_after,
    })
}

/// The parts of a CSR r2 reads (raw TLVs of the original encoding).
pub(crate) struct CsrParts<'a> {
    pub(crate) subject: &'a [u8],
    pub(crate) spki: &'a [u8],
}

/// Strict DER CSR load (pyca `load_der_x509_csr`): CertificationRequest { info { version
/// u8, subject Name (value checks), SPKI (algorithm parameters parsed), [0] IMPLICIT SET OF
/// Attribute { OID, SET OF ANY } (DER SET ordering) }, AlgorithmIdentifier, BIT STRING };
/// then a version other than 0 is pyca's InvalidVersion ("{n} is not a valid CSR version").
pub(crate) fn load_csr(der: &[u8]) -> std::result::Result<CsrParts<'_>, String> {
    let asn1 = |e: Asn1Error| e.text();
    let (req, rest) = der_head(der, 0x30).map_err(asn1)?;
    let mut outer = Der::new(req.content);
    let info = outer.tagged(0x30).map_err(asn1)?;
    let mut fields = Der::new(info.content);
    let version = der_uint(&fields.any().map_err(asn1)?, 1).map_err(asn1)?;
    let subject = fields.tagged(0x30).map_err(asn1)?;
    validate_name_load(subject.raw)?;
    let spki = fields.any().map_err(asn1)?;
    spki_fields(&spki).map_err(asn1)?;
    let attributes = fields.tagged(0xa0).map_err(asn1)?;
    der_attributes(attributes.content).map_err(asn1)?;
    fields.finish().map_err(asn1)?;
    alg_id(&outer.any().map_err(asn1)?).map_err(asn1)?;
    der_bits(&outer.tagged(0x03).map_err(asn1)?).map_err(asn1)?;
    outer.finish().map_err(asn1)?;
    rest.finish().map_err(asn1)?;
    if version != 0 {
        return Err(format!("{version} is not a valid CSR version"));
    }
    Ok(CsrParts {
        subject: subject.raw,
        spki: spki.raw,
    })
}

/// c2 `_subject_cn`: the first CN of a DER Name, decoded as pyca does (the whole Name is
/// decoded, so an undecodable value anywhere fails with pyca's text — c2 crashed there).
pub(crate) fn subject_common_name(name_der: &[u8]) -> std::result::Result<Option<String>, String> {
    let rdns = decode_name(name_der)?;
    Ok(rdns
        .iter()
        .flatten()
        .filter(|attr| attr.oid == OID_CN)
        .find_map(|attr| match &attr.value {
            NameValue::Str(text) => Some(text.clone()),
            NameValue::Bytes(_) => None,
        }))
}

/// The first CN, or None when absent or the Name is undecodable.
pub(crate) fn first_common_name(name_der: &[u8]) -> Option<String> {
    subject_common_name(name_der).ok().flatten()
}

// ---------------------------------------------------------------------------------------
// DER Name walk (strict TLV reader)
// ---------------------------------------------------------------------------------------

/// DER content of the commonName OID (2.5.4.3).
pub(crate) const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

const ASN1_ERR: &str = "error parsing asn1 value: ParseError { kind: InvalidValue }";

/// One TLV: tag byte, content.
pub(crate) struct Tlv<'a> {
    pub(crate) tag: u8,
    pub(crate) content: &'a [u8],
    pub(crate) raw: &'a [u8],
}

/// Read one DER TLV (single-byte tag, definite minimal length) from the front of `input`.
pub(crate) fn read_tlv(input: &[u8]) -> std::result::Result<(Tlv<'_>, &[u8]), String> {
    let short = || "error parsing asn1 value: ParseError { kind: ShortData }".to_owned();
    let tag = *input.first().ok_or_else(short)?;
    if tag & 0x1f == 0x1f {
        return Err("Long-form tags are not supported in NameAttribute values".to_owned());
    }
    let first = *input.get(1).ok_or_else(short)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 8 {
            return Err("error parsing asn1 value: ParseError { kind: InvalidLength }".to_owned());
        }
        let bytes = input.get(2..2 + n).ok_or_else(short)?;
        if bytes[0] == 0 {
            return Err("error parsing asn1 value: ParseError { kind: InvalidLength }".to_owned());
        }
        let mut len: usize = 0;
        for byte in bytes {
            len = len
                .checked_mul(256)
                .and_then(|v| v.checked_add(usize::from(*byte)))
                .ok_or_else(short)?;
        }
        if len < 0x80 {
            return Err("error parsing asn1 value: ParseError { kind: InvalidLength }".to_owned());
        }
        (len, 2 + n)
    };
    let end = header
        .checked_add(len)
        .filter(|end| *end <= input.len())
        .ok_or_else(short)?;
    Ok((
        Tlv {
            tag,
            content: &input[header..end],
            raw: &input[..end],
        },
        &input[end..],
    ))
}

/// A decoded name attribute value: pyca's `str`, or `bytes` (an x500UniqueIdentifier
/// BIT STRING, whose value is the raw content including the unused-bits octet).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NameValue {
    Str(String),
    Bytes(Vec<u8>),
}

/// A decoded name attribute: OID content bytes + pyca's value.
pub(crate) struct NameAttr {
    pub(crate) oid: Vec<u8>,
    pub(crate) value: NameValue,
}

/// The raw structure: RDNs (DER order) of (OID content, value TLV) pairs.
type RawName<'a> = Vec<Vec<(&'a [u8], Tlv<'a>)>>;

fn walk_name(der: &[u8]) -> std::result::Result<RawName<'_>, String> {
    let (seq, rest) = read_tlv(der)?;
    if seq.tag != 0x30 {
        return Err(format!(
            "error parsing asn1 value: ParseError {{ kind: UnexpectedTag {{ actual: {} }} }}",
            tag_debug(seq.tag)
        ));
    }
    if !rest.is_empty() {
        return Err("error parsing asn1 value: ParseError { kind: ExtraData }".to_owned());
    }
    let mut rdns = Vec::new();
    let mut input = seq.content;
    while !input.is_empty() {
        let (set, next) = read_tlv(input)?;
        input = next;
        if set.tag != 0x31 {
            return Err(ASN1_ERR.to_owned());
        }
        let mut attrs = Vec::new();
        let mut previous: Option<&[u8]> = None;
        let mut inner = set.content;
        while !inner.is_empty() {
            let (atv, next) = read_tlv(inner)?;
            inner = next;
            if atv.tag != 0x30 {
                return Err(ASN1_ERR.to_owned());
            }
            if previous.is_some_and(|prev| prev > atv.raw) {
                return Err(format!(
                    "error parsing asn1 value: ParseError {{ kind: InvalidSetOrdering, location: [{}, {}] }}",
                    rdns.len(),
                    attrs.len()
                ));
            }
            previous = Some(atv.raw);
            let (oid, rest) = read_tlv(atv.content)?;
            if oid.tag != 0x06 || oid_dotted(oid.content).is_none() {
                return Err(ASN1_ERR.to_owned());
            }
            let (value, rest) = read_tlv(rest)?;
            if !rest.is_empty() {
                return Err("error parsing asn1 value: ParseError { kind: ExtraData }".to_owned());
            }
            attrs.push((oid.content, value));
        }
        rdns.push(attrs);
    }
    Ok(rdns)
}

fn tag_debug(tag: u8) -> String {
    let class = match tag >> 6 {
        0 => "Universal",
        1 => "Application",
        2 => "ContextSpecific",
        _ => "Private",
    };
    format!(
        "Tag {{ value: {}, constructed: {}, class: {class} }}",
        tag & 0x1f,
        tag & 0x20 != 0
    )
}

/// pyca's load-time checks of Name values (the typed `AttributeValue` variants): a
/// PrintableString must use the PrintableString alphabet, a BMPString must be valid UTF-16BE
/// and a UniversalString valid UTF-32BE. The error text is pyca's, with the RDN index (DER
/// order) and the index inside the SET.
pub(crate) fn validate_name_load(der: &[u8]) -> std::result::Result<(), String> {
    let rdns = walk_name(der)?;
    for (rdn_index, rdn) in rdns.iter().enumerate() {
        for (attr_index, (_oid, value)) in rdn.iter().enumerate() {
            let variant = match value.tag {
                0x13 if !value.content.iter().all(|b| is_printable_char(*b)) => {
                    Some("PrintableString")
                }
                0x1e if decode_bmp(value.content).is_none() => Some("BmpString"),
                0x1c if decode_universal(value.content).is_none() => Some("UniversalString"),
                _ => None,
            };
            if let Some(variant) = variant {
                return Err(format!(
                    "error parsing asn1 value: ParseError {{ kind: InvalidValue, location: [{rdn_index}, {attr_index}, \"AttributeTypeValue::value\", \"AttributeValue::{variant}\"] }}"
                ));
            }
        }
    }
    Ok(())
}

/// The PrintableString alphabet (X.680): A-Z a-z 0-9 space ' ( ) + , - . / : = ?
fn is_printable_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&byte)
}

fn decode_bmp(content: &[u8]) -> Option<String> {
    if !content.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = content
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    char::decode_utf16(units)
        .collect::<std::result::Result<String, _>>()
        .ok()
}

fn decode_universal(content: &[u8]) -> Option<String> {
    if !content.len().is_multiple_of(4) {
        return None;
    }
    content
        .chunks_exact(4)
        .map(|quad| char::from_u32(u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]])))
        .collect()
}

/// DER content of the x500UniqueIdentifier OID (2.5.4.45), the one OID pyca accepts with a
/// BIT STRING value.
const OID_UNIQUE_IDENTIFIER: &[u8] = &[0x55, 0x04, 0x2d];
/// pyca's TypeError for a BIT STRING value under any other OID (c2 crashed there).
pub(crate) const BIT_STRING_OID_TEXT: &str =
    "oid must be X500_UNIQUE_IDENTIFIER for BitString type.";
/// r2's text for a value tag outside pyca's `_ASN1Type` (c2 KeyError, a crash).
pub(crate) const UNSUPPORTED_TAG_TEXT: &str = "unsupported name attribute value tag ";

/// Decode a DER Name the way pyca's `Name.from_bytes` / `cert.subject` does: values become
/// `str` (BMP/Universal strings by their encodings, every other string type as UTF-8), an
/// x500UniqueIdentifier BIT STRING becomes `bytes` (its raw content); a BitString under any
/// other OID, a tag outside pyca's `_ASN1Type`, an empty RDN or a duplicate attribute in an
/// RDN fails with pyca's text.
pub(crate) fn decode_name(der: &[u8]) -> std::result::Result<Vec<Vec<NameAttr>>, String> {
    validate_name_load(der)?;
    let raw = walk_name(der)?;
    let mut rdns = Vec::with_capacity(raw.len());
    for rdn in raw {
        let mut attrs: Vec<NameAttr> = Vec::with_capacity(rdn.len());
        for (oid, value) in rdn {
            let value = match value.tag {
                0x03 if oid == OID_UNIQUE_IDENTIFIER => NameValue::Bytes(value.content.to_vec()),
                0x03 => return Err(BIT_STRING_OID_TEXT.to_owned()),
                0x1e => {
                    NameValue::Str(decode_bmp(value.content).ok_or_else(|| ASN1_ERR.to_owned())?)
                }
                0x1c => NameValue::Str(
                    decode_universal(value.content).ok_or_else(|| ASN1_ERR.to_owned())?,
                ),
                0x04 | 0x0c | 0x12 | 0x13 | 0x14 | 0x16 | 0x17 | 0x18 | 0x1a => NameValue::Str(
                    std::str::from_utf8(value.content)
                        .map_err(|_| ASN1_ERR.to_owned())?
                        .to_owned(),
                ),
                other => return Err(format!("{UNSUPPORTED_TAG_TEXT}{other}")),
            };
            attrs.push(NameAttr {
                oid: oid.to_vec(),
                value,
            });
        }
        if attrs.is_empty() {
            return Err("a relative distinguished name cannot be empty".to_owned());
        }
        for (i, attr) in attrs.iter().enumerate() {
            if attrs[..i]
                .iter()
                .any(|other| other.oid == attr.oid && other.value == attr.value)
            {
                return Err("duplicate attributes are not allowed".to_owned());
            }
        }
        rdns.push(attrs);
    }
    Ok(rdns)
}

/// RFC 4514 short names pyca knows (`_NAMEOID_TO_NAME`), by OID content bytes.
pub(crate) const SHORT_NAMES: [(&str, &[u8]); 9] = [
    ("CN", &[0x55, 0x04, 0x03]),
    ("L", &[0x55, 0x04, 0x07]),
    ("ST", &[0x55, 0x04, 0x08]),
    ("O", &[0x55, 0x04, 0x0a]),
    ("OU", &[0x55, 0x04, 0x0b]),
    ("C", &[0x55, 0x04, 0x06]),
    ("STREET", &[0x55, 0x04, 0x09]),
    (
        "DC",
        &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19],
    ),
    (
        "UID",
        &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01],
    ),
];

fn format_rfc4514(rdns: &[Vec<NameAttr>]) -> String {
    rdns.iter()
        .rev()
        .map(|rdn| {
            rdn.iter()
                .map(|attr| {
                    let name = SHORT_NAMES
                        .iter()
                        .find(|(_, oid)| *oid == attr.oid.as_slice())
                        .map_or_else(
                            || oid_dotted(&attr.oid).unwrap_or_default(),
                            |(name, _)| (*name).to_owned(),
                        );
                    let value = match &attr.value {
                        NameValue::Str(text) => escape_dn_value(text),
                        // pyca `_escape_dn_value`: "" for an empty value, else "#" + hex.
                        NameValue::Bytes(bytes) if bytes.is_empty() => String::new(),
                        NameValue::Bytes(bytes) => format!("#{}", hex::encode(bytes)),
                    };
                    format!("{name}={value}")
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// pyca `_escape_dn_value` for `str` values.
fn escape_dn_value(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let mut val = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => val.push_str("\\\\"),
            '"' => val.push_str("\\\""),
            '+' => val.push_str("\\+"),
            ',' => val.push_str("\\,"),
            ';' => val.push_str("\\;"),
            '<' => val.push_str("\\<"),
            '>' => val.push_str("\\>"),
            '\0' => val.push_str("\\00"),
            other => val.push(other),
        }
    }
    if val.starts_with('#') || (val.starts_with(' ') && val.chars().count() > 1) {
        val.insert(0, '\\');
    }
    if val.ends_with(' ') {
        val.pop();
        val.push_str("\\ ");
    }
    val
}

/// Dotted text of a DER OID content (u128 arcs, as rust-asn1); None when malformed.
pub(crate) fn oid_dotted(content: &[u8]) -> Option<String> {
    if content.is_empty() || content.last().is_some_and(|b| b & 0x80 != 0) {
        return None;
    }
    let mut arcs: Vec<u128> = Vec::new();
    let mut value: u128 = 0;
    let mut start = true;
    for byte in content {
        if start && *byte == 0x80 {
            return None; // non-minimal base-128
        }
        start = false;
        value = value
            .checked_mul(128)?
            .checked_add(u128::from(byte & 0x7f))?;
        if byte & 0x80 == 0 {
            arcs.push(value);
            value = 0;
            start = true;
        }
    }
    let first = arcs.first().copied()?;
    let (a, b) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };
    let mut out = format!("{a}.{b}");
    for arc in &arcs[1..] {
        out.push('.');
        out.push_str(&arc.to_string());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn py_int_hex_matches_python_format_x() {
        assert_eq!(py_int_hex(&[0x00]), "0");
        assert_eq!(py_int_hex(&[]), "0");
        assert_eq!(py_int_hex(&[0x00, 0xff]), "ff");
        assert_eq!(py_int_hex(&[0x0a, 0x00]), "a00");
        assert_eq!(py_int_hex(&[0xff]), "-1");
        assert_eq!(py_int_hex(&[0x80]), "-80");
        assert_eq!(py_int_hex(&[0xff, 0x00]), "-100");
    }

    #[test]
    fn oid_dotted_decodes_arcs() {
        assert_eq!(oid_dotted(&[0x55, 0x04, 0x03]).as_deref(), Some("2.5.4.3"));
        assert_eq!(oid_dotted(&[0x27]).as_deref(), Some("0.39"));
        assert_eq!(oid_dotted(&[0x88, 0x37]).as_deref(), Some("2.999"));
        assert_eq!(oid_dotted(&[0x2a, 0x86]), None);
        assert_eq!(oid_dotted(&[0x80, 0x01]), None);
        assert_eq!(oid_dotted(&[]), None);
    }

    #[test]
    fn escape_dn_value_is_pycas() {
        assert_eq!(escape_dn_value(""), "");
        assert_eq!(escape_dn_value(" "), "\\ ");
        assert_eq!(escape_dn_value("  "), "\\ \\ ");
        assert_eq!(escape_dn_value(" x"), "\\ x");
        assert_eq!(escape_dn_value("#a"), "\\#a");
        assert_eq!(escape_dn_value("a#"), "a#");
        assert_eq!(escape_dn_value("a\0b"), "a\\00b");
    }
}
