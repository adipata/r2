//! R6 test fixtures, generated at test time with OpenSSL (no key blobs are committed): the
//! counterparts of the pyca helpers in c2's test_keyparse.py / test_x509build.py.
#![allow(dead_code)]

use std::cell::RefCell;
use std::rc::Rc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder, X509Req};
use r2_core::Result;
use secrecy::SecretString;

pub fn rsa_key(bits: u32) -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap()
}

pub fn ec_key(nid: Nid) -> PKey<Private> {
    let group = EcGroup::from_curve_name(nid).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

pub fn p256() -> PKey<Private> {
    ec_key(Nid::X9_62_PRIME256V1)
}

pub fn ed25519() -> PKey<Private> {
    PKey::generate_ed25519().unwrap()
}

pub fn ed448() -> PKey<Private> {
    PKey::generate_ed448().unwrap()
}

pub fn x25519() -> PKey<Private> {
    PKey::generate_x25519().unwrap()
}

pub fn x448() -> PKey<Private> {
    PKey::generate_x448().unwrap()
}

/// pyca `private_bytes(DER, PKCS8, NoEncryption())`.
pub fn pkcs8_der(key: &PKeyRef<Private>) -> Vec<u8> {
    key.private_key_to_pkcs8().unwrap()
}

pub fn pkcs8_pem(key: &PKeyRef<Private>) -> Vec<u8> {
    key.private_key_to_pem_pkcs8().unwrap()
}

pub fn spki_der(key: &PKeyRef<Private>) -> Vec<u8> {
    key.public_key_to_der().unwrap()
}

pub fn spki_pem(key: &PKeyRef<Private>) -> Vec<u8> {
    key.public_key_to_pem().unwrap()
}

fn digest_for(key: &PKeyRef<Private>) -> MessageDigest {
    match key.id() {
        Id::ED25519 | Id::ED448 => MessageDigest::null(),
        _ => MessageDigest::sha256(),
    }
}

/// c2 test `make_cert`: self-signed, the given name entries (NID, value), valid from
/// now − 1 day to now + 365 days, SHA-256 (no digest for Ed keys).
pub fn make_cert(key: &PKeyRef<Private>, entries: &[(Nid, &str)]) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    for (nid, value) in entries {
        name.append_entry_by_nid_with_type(*nid, value, openssl::asn1::Asn1Type::UTF8STRING)
            .unwrap();
    }
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
    builder
        .set_serial_number(&Asn1Integer::from_bn(&serial).unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder.set_pubkey(key).unwrap();
    builder.sign(key, digest_for(key)).unwrap();
    builder.build()
}

pub fn cn_cert(key: &PKeyRef<Private>, cn: &str) -> X509 {
    make_cert(key, &[(Nid::COMMONNAME, cn)])
}

/// c2 test CSR: subject CN only, SHA-256.
pub fn make_csr(key: &PKeyRef<Private>, cn: &str) -> X509Req {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid_with_type(Nid::COMMONNAME, cn, openssl::asn1::Asn1Type::UTF8STRING)
        .unwrap();
    let mut builder = X509Req::builder().unwrap();
    builder.set_subject_name(&name.build()).unwrap();
    builder.set_pubkey(key).unwrap();
    builder.sign(key, digest_for(key)).unwrap();
    builder.build()
}

/// c2 test `pem_wrap`: base64 at 64 columns, LF, trailing newline.
pub fn pem_wrap(der: &[u8], label: &str) -> Vec<u8> {
    let body = STANDARD.encode(der);
    let mut lines = vec![format!("-----BEGIN {label}-----")];
    lines.extend(
        body.as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8(c.to_vec()).unwrap()),
    );
    lines.push(format!("-----END {label}-----"));
    lines.push(String::new());
    lines.join("\n").into_bytes()
}

/// c2 test `recording_cb`: answers `password`, recording every prompt.
pub fn recording_cb(
    password: &str,
    prompts: Rc<RefCell<Vec<String>>>,
) -> impl FnMut(&str) -> Result<SecretString> {
    let password = password.to_owned();
    move |prompt: &str| {
        prompts.borrow_mut().push(prompt.to_owned());
        Ok(SecretString::from(password.clone()))
    }
}

pub fn answer(password: &str) -> impl FnMut(&str) -> Result<SecretString> {
    let password = password.to_owned();
    move |_prompt: &str| Ok(SecretString::from(password.clone()))
}

pub fn secret(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// DER TLV (single-byte tag, minimal definite length).
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// A DER Name of single-attribute RDNs: (OID content hex, value tag, value bytes).
pub fn raw_name(rdns: &[(&str, u8, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (oid, tag, value) in rdns {
        let mut atv = tlv(0x06, &unhex(oid));
        atv.extend(tlv(*tag, value));
        body.extend(tlv(0x31, &tlv(0x30, &atv)));
    }
    tlv(0x30, &body)
}

/// A v3 certificate assembled byte by byte (OpenSSL's X509 encoder refuses some Name value
/// encodings pyca loads): serial 1, the given issuer/subject Name DER and validity times
/// (UTCTime "YYMMDDHHMMSSZ" or GeneralizedTime "YYYYMMDDHHMMSSZ"), ECDSA-SHA256 signed.
pub fn raw_cert(
    key: &PKeyRef<Private>,
    issuer: &[u8],
    subject: &[u8],
    not_before: &str,
    not_after: &str,
) -> Vec<u8> {
    let time = |t: &str| tlv(if t.len() == 13 { 0x17 } else { 0x18 }, t.as_bytes());
    let sig_alg = tlv(0x30, &tlv(0x06, &unhex("2a8648ce3d040302")));
    let mut tbs = tlv(0xa0, &tlv(0x02, &[2]));
    tbs.extend(tlv(0x02, &[1]));
    tbs.extend_from_slice(&sig_alg);
    tbs.extend_from_slice(issuer);
    let mut validity = time(not_before);
    validity.extend(time(not_after));
    tbs.extend(tlv(0x30, &validity));
    tbs.extend_from_slice(subject);
    tbs.extend(key.public_key_to_der().unwrap());
    let tbs = tlv(0x30, &tbs);
    let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), key).unwrap();
    signer.update(&tbs).unwrap();
    let mut bits = vec![0];
    bits.extend(signer.sign_to_vec().unwrap());
    let mut cert = tbs;
    cert.extend_from_slice(&sig_alg);
    cert.extend(tlv(0x03, &bits));
    tlv(0x30, &cert)
}

/// `raw_cert` self-issued, valid 2020-01-01 .. 2030-01-01.
pub fn name_cert(key: &PKeyRef<Private>, subject: &[u8]) -> Vec<u8> {
    raw_cert(key, subject, subject, "200101000000Z", "300101000000Z")
}

/// OID content hex of commonName / x500UniqueIdentifier.
pub const CN_OID: &str = "550403";
pub const UID_OID: &str = "55042d";

/// The element TLVs of a DER SEQUENCE (or any constructed value), definite lengths.
pub fn der_items(der: &[u8]) -> Vec<Vec<u8>> {
    let header = |data: &[u8]| -> (usize, usize) {
        if data[1] < 0x80 {
            (2, usize::from(data[1]))
        } else {
            let n = usize::from(data[1] & 0x7f);
            let len = data[2..2 + n]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
            (2 + n, len)
        }
    };
    let (start, len) = header(der);
    let mut content = &der[start..start + len];
    let mut items = Vec::new();
    while !content.is_empty() {
        let (h, l) = header(content);
        items.push(content[..h + l].to_vec());
        content = &content[h + l..];
    }
    items
}

/// A DER SEQUENCE of the given element TLVs.
pub fn der_seq(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &items.concat())
}
