//! Certificate facts shared by memory, pkcs11 and services (spec §4.4.5, owner R6).
//!
//! Besides the §4.4.5 surface this module holds the crate-internal X.509 Name machinery
//! (strict DER walk, pyca's load-time value checks, `rfc4514_string`), which keyparse,
//! x509build and formats share so every caller sees pyca's (c2's) acceptance rules.
use std::collections::BTreeMap;

use openssl::pkey::PKey;

use crate::error::{ConsoleError, Result};
use crate::keyparse::{classify_key, normalize_public, ossl_detail};
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
    /// (On that read path a certificate whose DER does not parse is skipped — not listed —
    /// while this error propagates, as in c2.)
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
    let pkey = PKey::public_key_from_der(spki_der).map_err(|err| invalid(&ossl_detail(&err)))?;
    let pkey = normalize_public(pkey).map_err(|detail| invalid(&detail))?;
    classify_key(&pkey, classifier, false)
}
/// Port of pyca `Name.rfc4514_string()`: RDNs reversed, '+' within an RDN, short names only
/// for CN L ST O OU C STREET DC UID (else dotted OID), `_escape_dn_value` escaping
/// (`\ " + , ; < >`, NUL → `\00`, leading `#`/space and trailing space), non-string
/// values as `#hex`. NOT x509-cert's Display.
pub fn rfc4514_string(name_der: &[u8]) -> Result<String> {
    let rdns = decode_name(name_der).map_err(|detail| {
        ConsoleError::key_parse(format!("name is not a valid DER X.509 Name: {detail}"))
    })?;
    Ok(format_rfc4514(&rdns))
}
/// `key info` rows for a certificate: ("subject", rfc4514), ("issuer", rfc4514),
/// ("serial", lower-case hex without leading zeros, "0" for zero), ("not valid before",
/// "YYYY-MM-DDTHH:MM:SS+00:00"), ("not valid after", same) — via x509-cert
/// `Time::to_date_time`.
pub fn certificate_details(cert_der: &[u8]) -> Result<Vec<(String, String)>> {
    let facts = TextFacts::of(cert_der)?;
    Ok(vec![
        ("subject".to_owned(), facts.subject),
        ("issuer".to_owned(), facts.issuer),
        ("serial".to_owned(), facts.serial),
        ("not valid before".to_owned(), facts.not_before),
        ("not valid after".to_owned(), facts.not_after),
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
            AttrValue::Str(facts.not_before),
        ),
        (
            "not_valid_after".to_owned(),
            AttrValue::Str(facts.not_after),
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
    not_before: String,
    not_after: String,
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
            not_before: cert.not_before.iso(),
            not_after: cert.not_after.iso(),
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
/// `public_key()`); failures → "{what} contains an invalid public key: {detail}".
pub(crate) fn cert_public_key(spki_der: &[u8], what: &str) -> Result<PKey<openssl::pkey::Public>> {
    let pkey = PKey::public_key_from_der(spki_der)
        .map_err(|err| invalid_public_key(what, &ossl_detail(&err)))?;
    normalize_public(pkey).map_err(|detail| invalid_public_key(what, &detail))
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
    /// pyca `not_valid_*_utc.isoformat()`: "YYYY-MM-DDTHH:MM:SS+00:00".
    fn iso(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
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

fn expect<'a>(input: &'a [u8], tag: u8) -> std::result::Result<(Tlv<'a>, &'a [u8]), String> {
    let (tlv, rest) = read_tlv(input)?;
    if tlv.tag != tag {
        return Err(format!(
            "error parsing asn1 value: ParseError {{ kind: UnexpectedTag {{ actual: {} }} }}",
            tag_debug(tlv.tag)
        ));
    }
    Ok((tlv, rest))
}

fn no_extra(rest: &[u8]) -> std::result::Result<(), String> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err("error parsing asn1 value: ParseError { kind: ExtraData }".to_owned())
    }
}

/// A DER INTEGER: non-empty, minimally encoded.
fn check_integer(tlv: &Tlv<'_>) -> std::result::Result<(), String> {
    let c = tlv.content;
    let non_minimal =
        c.len() > 1 && ((c[0] == 0x00 && c[1] & 0x80 == 0) || (c[0] == 0xff && c[1] & 0x80 != 0));
    if c.is_empty() || non_minimal {
        return Err(ASN1_ERR.to_owned());
    }
    Ok(())
}

/// SubjectPublicKeyInfo shape: SEQUENCE { AlgorithmIdentifier SEQUENCE { OID, … }, BIT STRING }.
fn check_spki(spki: &[u8]) -> std::result::Result<(), String> {
    let (seq, rest) = expect(spki, 0x30)?;
    no_extra(rest)?;
    let (alg, rest) = expect(seq.content, 0x30)?;
    let (oid, _) = expect(alg.content, 0x06)?;
    oid_dotted(oid.content).ok_or_else(|| ASN1_ERR.to_owned())?;
    let (_bits, rest) = expect(rest, 0x03)?;
    no_extra(rest)
}

/// Every remaining element is a well-formed TLV.
fn check_tlvs(mut input: &[u8]) -> std::result::Result<(), String> {
    while !input.is_empty() {
        let (_, rest) = read_tlv(input)?;
        input = rest;
    }
    Ok(())
}

/// Strict DER certificate load (pyca `load_der_x509_certificate` acceptance: DER structure,
/// minimal INTEGERs, DER times, Name values checked as pyca checks them at load). OIDs are
/// read with unbounded arcs (rust-asn1), so names x509-cert/const-oid cannot hold load too.
pub(crate) fn load_certificate(der: &[u8]) -> std::result::Result<CertParts<'_>, String> {
    let (cert, rest) = expect(der, 0x30)?;
    no_extra(rest)?;
    let (tbs, rest) = expect(cert.content, 0x30)?;
    let (sig_alg, rest) = expect(rest, 0x30)?;
    let (_sig, rest) = expect(rest, 0x03)?;
    no_extra(rest)?;
    let (alg_oid, _) = expect(sig_alg.content, 0x06)?;
    oid_dotted(alg_oid.content).ok_or_else(|| ASN1_ERR.to_owned())?;
    let mut input = tbs.content;
    let (first, after) = read_tlv(input)?;
    if first.tag == 0xa0 {
        let (version, extra) = expect(first.content, 0x02)?;
        no_extra(extra)?;
        check_integer(&version)?;
        input = after;
    }
    let (serial, input) = expect(input, 0x02)?;
    check_integer(&serial)?;
    let (_signature, input) = expect(input, 0x30)?;
    let (issuer, input) = expect(input, 0x30)?;
    let (validity, input) = expect(input, 0x30)?;
    let (subject, input) = expect(input, 0x30)?;
    let (spki, input) = expect(input, 0x30)?;
    check_tlvs(input)?;
    let (before, rest) = read_tlv(validity.content)?;
    let (after, rest) = read_tlv(rest)?;
    no_extra(rest)?;
    let not_before = DerTime::parse(&before)?;
    let not_after = DerTime::parse(&after)?;
    validate_name_load(issuer.raw)?;
    validate_name_load(subject.raw)?;
    check_spki(spki.raw)?;
    Ok(CertParts {
        serial: serial.raw,
        issuer: issuer.raw,
        subject: subject.raw,
        spki: spki.raw,
        not_before,
        not_after,
    })
}

/// Strict DER CSR load (pyca `load_der_x509_csr`): CertificationRequest { info { version,
/// subject, SPKI, [0] attributes }, AlgorithmIdentifier, BIT STRING }, Name values checked.
pub(crate) fn load_csr(der: &[u8]) -> std::result::Result<(), String> {
    let (req, rest) = expect(der, 0x30)?;
    no_extra(rest)?;
    let (info, rest) = expect(req.content, 0x30)?;
    let (alg, rest) = expect(rest, 0x30)?;
    let (_sig, rest) = expect(rest, 0x03)?;
    no_extra(rest)?;
    let (alg_oid, _) = expect(alg.content, 0x06)?;
    oid_dotted(alg_oid.content).ok_or_else(|| ASN1_ERR.to_owned())?;
    let (version, rest) = expect(info.content, 0x02)?;
    check_integer(&version)?;
    let (subject, rest) = expect(rest, 0x30)?;
    let (spki, rest) = expect(rest, 0x30)?;
    let (_attributes, rest) = expect(rest, 0xa0)?;
    no_extra(rest)?;
    validate_name_load(subject.raw)?;
    check_spki(spki.raw)
}

/// First CN of a DER Name, decoded as pyca does (None when absent or undecodable).
pub(crate) fn first_common_name(name_der: &[u8]) -> Option<String> {
    let rdns = decode_name(name_der).ok()?;
    rdns.iter()
        .flatten()
        .find(|attr| attr.oid == OID_CN)
        .map(|attr| attr.value.clone())
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

/// A decoded name attribute: OID content bytes + pyca's `str` value.
pub(crate) struct NameAttr {
    pub(crate) oid: Vec<u8>,
    pub(crate) value: String,
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

/// Decode a DER Name the way pyca's `Name.from_bytes` / `cert.subject` does: values become
/// `str` (BMP/Universal strings by their encodings, every other string type as UTF-8); a
/// BitString, a tag outside pyca's `_ASN1Type`, an empty RDN or a duplicate attribute in an
/// RDN fails with pyca's text.
pub(crate) fn decode_name(der: &[u8]) -> std::result::Result<Vec<Vec<NameAttr>>, String> {
    validate_name_load(der)?;
    let raw = walk_name(der)?;
    let mut rdns = Vec::with_capacity(raw.len());
    for rdn in raw {
        let mut attrs: Vec<NameAttr> = Vec::with_capacity(rdn.len());
        for (oid, value) in rdn {
            let text = match value.tag {
                0x03 => {
                    return Err("oid must be X500_UNIQUE_IDENTIFIER for BitString type.".to_owned());
                }
                0x1e => decode_bmp(value.content).ok_or_else(|| ASN1_ERR.to_owned())?,
                0x1c => decode_universal(value.content).ok_or_else(|| ASN1_ERR.to_owned())?,
                0x04 | 0x0c | 0x12 | 0x13 | 0x14 | 0x16 | 0x17 | 0x18 | 0x1a => {
                    std::str::from_utf8(value.content)
                        .map_err(|_| ASN1_ERR.to_owned())?
                        .to_owned()
                }
                other => return Err(format!("unsupported name attribute value tag {other}")),
            };
            attrs.push(NameAttr {
                oid: oid.to_vec(),
                value: text,
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
                    format!("{name}={}", escape_dn_value(&attr.value))
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
