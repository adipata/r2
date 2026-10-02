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
