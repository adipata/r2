// OpenSSL-generated key/cert fixtures (spec §4.10.3, owner R3) — generated at test time,
// cached per process (c2 tests/contract/base.py `_rsa_pkcs8_and_cert`, `functools.cache`).
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::{X509Builder, X509NameBuilder};

fn pkcs8(key: &PKey<Private>) -> Vec<u8> {
    key.private_key_to_pkcs8().expect("PKCS#8 serialization")
}

/// Unencrypted PKCS#8 DER of an RSA-2048 key.
pub fn rsa2048_pkcs8() -> Vec<u8> {
    static CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let rsa = Rsa::generate(2048).expect("RSA-2048 generation");
            pkcs8(&PKey::from_rsa(rsa).expect("RSA PKey"))
        })
        .clone()
}

/// Unencrypted PKCS#8 DER of a P-256 key (named curve).
pub fn ec_p256_pkcs8() -> Vec<u8> {
    static CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256 group");
            let key = EcKey::generate(&group).expect("P-256 generation");
            pkcs8(&PKey::from_ec_key(key).expect("EC PKey"))
        })
        .clone()
}

/// Unencrypted PKCS#8 DER of an Ed25519 key.
pub fn ed25519_pkcs8() -> Vec<u8> {
    static CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    CACHE
        .get_or_init(|| pkcs8(&PKey::generate_ed25519().expect("Ed25519 generation")))
        .clone()
}

/// Self-signed cert (CN = cn, SHA-256 / Ed: no digest, BasicConstraints CA:FALSE, notBefore
/// = now − 1 day, 3650 days) for the given PKCS#8 key; DER.
pub fn self_signed_cert(pkcs8: &[u8], cn: &str) -> Vec<u8> {
    let key = PKey::private_key_from_pkcs8(pkcs8).expect("fixture key is unencrypted PKCS#8");
    let mut name = X509NameBuilder::new().expect("X509 name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, cn)
        .expect("CN entry");
    let name = name.build();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs();
    let now = i64::try_from(now).expect("time fits i64");
    let day = 86_400;
    let mut builder = X509Builder::new().expect("X509 builder");
    builder.set_version(2).expect("v3");
    let mut serial = BigNum::new().expect("BigNum");
    serial
        .rand(159, MsbOption::MAYBE_ZERO, false)
        .expect("random serial");
    let serial: Asn1Integer = serial.to_asn1_integer().expect("serial");
    builder.set_serial_number(&serial).expect("serial");
    builder.set_subject_name(&name).expect("subject");
    builder.set_issuer_name(&name).expect("issuer");
    builder.set_pubkey(&key).expect("public key");
    let not_before = Asn1Time::from_unix(now - day).expect("notBefore");
    let not_after = Asn1Time::from_unix(now + 3650 * day).expect("notAfter");
    builder.set_not_before(&not_before).expect("notBefore");
    builder.set_not_after(&not_after).expect("notAfter");
    let constraints = BasicConstraints::new()
        .critical()
        .build()
        .expect("basicConstraints");
    builder.append_extension(constraints).expect("extension");
    let digest = match key.id() {
        Id::ED25519 | Id::ED448 => MessageDigest::null(),
        _ => MessageDigest::sha256(),
    };
    builder.sign(&key, digest).expect("self-signature");
    builder.build().to_der().expect("certificate DER")
}

/// (PKCS#8, cert) of the contract suite's RSA key, CN "r2-contract".
pub fn rsa_pkcs8_and_cert() -> (Vec<u8>, Vec<u8>) {
    static CACHE: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let pkcs8 = rsa2048_pkcs8();
            let cert = self_signed_cert(&pkcs8, "r2-contract");
            (pkcs8, cert)
        })
        .clone()
}
