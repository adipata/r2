// Shared helpers of the MemoryProvider integration tests (R4) — the r2 counterparts of the
// module-level helpers in c2's tests/unit/test_memory_*.py.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

pub mod c2_vectors;

use std::sync::OnceLock;

use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::{MessageDigest, hash};
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, PKey, PKeyRef, Private, Public};
use openssl::rsa::Rsa;
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::{ParamValue, Params};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_memory::MemoryProvider;
use r2_provider::{GenerateRequest, KeySelector, MechanismInvocation, Provider, UnwrapRequest};

pub fn make() -> MemoryProvider {
    MemoryProvider::new("mem")
}

/// c2 `mech(name, **params)`.
pub fn mech(name: &str, entries: &[(&str, ParamValue)]) -> MechanismInvocation {
    let params: Params = entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect();
    MechanismInvocation::new(name, params)
}

pub fn bytes(data: &[u8]) -> ParamValue {
    ParamValue::Bytes(data.to_vec())
}

/// An ENUM/STR param as the resolver types it (c2 passed plain str).
pub fn text(value: &str) -> ParamValue {
    ParamValue::Enum(value.to_owned())
}

pub fn int(value: i64) -> ParamValue {
    ParamValue::Int(value)
}

pub fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect()
}

pub fn template(extractable: bool, sensitive: bool) -> KeyTemplate {
    KeyTemplate::new(vec![
        TemplateAttr::new(
            "CKA_EXTRACTABLE",
            AttrKind::Bool,
            AttrValue::Bool(extractable),
        ),
        TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(sensitive)),
    ])
}

pub fn exportable() -> KeyTemplate {
    template(true, false)
}

/// The error of `result`, asserting its c2 class name ("ParamError", …).
#[track_caller]
pub fn err_class<T: std::fmt::Debug>(result: Result<T>, class: &str) -> ConsoleError {
    match result {
        Ok(value) => panic!("expected {class}, got Ok({value:?})"),
        Err(err) => {
            assert_eq!(
                err.kind.class_name(),
                class,
                "unexpected error: {} (hint {:?})",
                err.message,
                err.hint
            );
            err
        }
    }
}

pub fn import_aes(
    provider: &MemoryProvider,
    key: &[u8],
    label: &str,
    tpl: Option<&KeyTemplate>,
    key_id: Option<&[u8]>,
) -> KeyInfo {
    let material = KeyMaterial {
        size_bits: u32::try_from(key.len() * 8).ok(),
        ..KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, key.to_vec())
    };
    provider.import_key(&material, label, tpl, key_id).unwrap()
}

pub fn pkcs8(key: &PKeyRef<Private>) -> Vec<u8> {
    key.private_key_to_pkcs8().unwrap()
}

pub fn spki<T: HasPublic>(key: &PKeyRef<T>) -> Vec<u8> {
    key.public_key_to_der().unwrap()
}

pub fn import_private(
    provider: &MemoryProvider,
    key: &PKeyRef<Private>,
    algorithm: KeyAlgorithm,
    label: &str,
    tpl: Option<&KeyTemplate>,
    key_id: Option<&[u8]>,
) -> KeyInfo {
    let material = KeyMaterial::new(algorithm, KeyClass::Private, pkcs8(key));
    provider.import_key(&material, label, tpl, key_id).unwrap()
}

pub fn import_public<T: HasPublic>(
    provider: &MemoryProvider,
    key: &PKeyRef<T>,
    algorithm: KeyAlgorithm,
    label: &str,
    key_id: Option<&[u8]>,
) -> KeyInfo {
    let material = KeyMaterial::new(algorithm, KeyClass::Public, spki(key));
    provider.import_key(&material, label, None, key_id).unwrap()
}

pub fn public_half(provider: &MemoryProvider, label: &str) -> KeyInfo {
    provider
        .list_keys()
        .unwrap()
        .into_iter()
        .find(|k| k.key_ref.label == label && k.key_class == KeyClass::Public)
        .unwrap()
}

pub fn find(provider: &MemoryProvider, label: &str, key_id: Option<&[u8]>) -> Result<KeyInfo> {
    provider.find_key(&KeySelector::label(label).with_id(key_id.map(<[u8]>::to_vec)))
}

pub fn generate(
    provider: &MemoryProvider,
    algorithm: KeyAlgorithm,
    size_bits: Option<u32>,
    curve: Option<Curve>,
    label: &str,
    key_id: Option<&[u8]>,
) -> Result<KeyInfo> {
    let request = GenerateRequest {
        size_bits,
        curve,
        key_id: key_id.map(<[u8]>::to_vec),
        ..GenerateRequest::new(algorithm, label)
    };
    provider.generate_key(&request)
}

pub fn unwrap_req(
    algorithm: KeyAlgorithm,
    key_class: KeyClass,
    label: &str,
    tpl: Option<KeyTemplate>,
    key_id: Option<&[u8]>,
) -> UnwrapRequest {
    UnwrapRequest {
        template: tpl,
        key_id: key_id.map(<[u8]>::to_vec),
        ..UnwrapRequest::new(algorithm, key_class, label)
    }
}

fn cached(cell: &'static OnceLock<Vec<u8>>, make: fn() -> PKey<Private>) -> PKey<Private> {
    let der = cell.get_or_init(|| pkcs8(&make()));
    PKey::private_key_from_der(der).unwrap()
}

fn new_rsa_2048() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}

/// c2 `rsa_2048()` (functools.cache).
pub fn rsa_2048() -> PKey<Private> {
    static CELL: OnceLock<Vec<u8>> = OnceLock::new();
    cached(&CELL, new_rsa_2048)
}

/// c2 `rsa_2048_b()`.
pub fn rsa_2048_b() -> PKey<Private> {
    static CELL: OnceLock<Vec<u8>> = OnceLock::new();
    cached(&CELL, new_rsa_2048)
}

pub fn ec_p256() -> PKey<Private> {
    static CELL: OnceLock<Vec<u8>> = OnceLock::new();
    cached(&CELL, || {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    })
}

pub fn public_of(key: &PKeyRef<Private>) -> PKey<Public> {
    PKey::public_key_from_der(&spki(key)).unwrap()
}

/// c2 `import_rsa_pair`: (private_info, public_info) for the cached RSA-2048 key.
pub fn import_rsa_pair(provider: &MemoryProvider) -> (KeyInfo, KeyInfo) {
    let key = rsa_2048();
    let private = import_private(provider, &key, KeyAlgorithm::Rsa, "rsa", None, None);
    let public = import_public(provider, &key, KeyAlgorithm::Rsa, "rsa-pub", None);
    (private, public)
}

/// Self-signed X.509 (DER) over `key`, CN = `cn`, SHA-256, BasicConstraints CA:FALSE when
/// `basic_constraints` (c2 `ec_key_and_cert_der` / `_self_signed_rsa_cert_der`).
pub fn self_signed(key: &PKeyRef<Private>, cn: &str, basic_constraints: bool) -> Vec<u8> {
    use openssl::asn1::Asn1Time;
    use openssl::x509::extension::BasicConstraints;
    use openssl::x509::{X509Builder, X509NameBuilder};
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
    let name = name.build();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(0x1234_5678)
        .unwrap()
        .to_asn1_integer()
        .unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    if basic_constraints {
        builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
    }
    builder.sign(key, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    hash(MessageDigest::sha256(), data).unwrap().to_vec()
}

/// RSA numbers (n, e, d) as BigNums.
pub fn rsa_numbers(key: &PKeyRef<Private>) -> (BigNum, BigNum, BigNum) {
    let rsa = key.rsa().unwrap();
    (
        rsa.n().to_owned().unwrap(),
        rsa.e().to_owned().unwrap(),
        rsa.d().to_owned().unwrap(),
    )
}

/// Textbook `pow(m, e, n)` as k big-endian bytes (independent of the provider's modexp).
pub fn modexp(m: &[u8], e: &BigNum, n: &BigNum) -> Vec<u8> {
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let base = BigNum::from_slice(m).unwrap();
    let mut out = BigNum::new().unwrap();
    out.mod_exp(&base, e, n, &mut ctx).unwrap();
    let k = usize::try_from(n.num_bits()).unwrap().div_ceil(8);
    out.to_vec_padded(i32::try_from(k).unwrap()).unwrap()
}

pub fn left_pad(data: &[u8], k: usize) -> Vec<u8> {
    let mut out = vec![0u8; k - data.len()];
    out.extend_from_slice(data);
    out
}
