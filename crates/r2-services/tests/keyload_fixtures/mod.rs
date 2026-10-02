// Shared fixtures of R8's service tests (keyload / keyexport / certops) — the port of c2
// tests/unit/services/conftest.py plus the material helpers of test_keyexport.py. Key and
// certificate fixtures are generated at test time (r2-testkit's OpenSSL fixtures and
// r2-core's pyca-identical writers; r2-services may not depend on openssl itself, §4.1.2).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::sync::OnceLock;

use r2_config::loader::config_from_yaml;
use r2_config::model::TemplatesSection;
use r2_core::codec::decode_data;
use r2_core::formats::{self, Encoding};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_testkit::fixtures;
use secrecy::SecretString;

pub const AES_16: [u8; 16] = [0x01; 16];

/// The embedded §7 TemplatesSection (feeds `default_template`, §4.8).
pub fn make_templates() -> TemplatesSection {
    config_from_yaml(None).unwrap().templates
}

pub fn rsa_pkcs8_der() -> Vec<u8> {
    fixtures::rsa2048_pkcs8()
}

pub fn rsa_private_pem() -> Vec<u8> {
    formats::private_key_bytes(&rsa_pkcs8_der(), Encoding::Pem, None)
        .unwrap()
        .to_vec()
}

/// PKCS#8 PEM encrypted with pyca's BestAvailableEncryption profile.
pub fn rsa_encrypted_pem(password: &str) -> Vec<u8> {
    formats::private_key_bytes(
        &rsa_pkcs8_der(),
        Encoding::Pem,
        Some(&SecretString::from(password.to_owned())),
    )
    .unwrap()
    .to_vec()
}

pub fn rsa_spki_der() -> Vec<u8> {
    formats::pkcs8_public_spki(&rsa_pkcs8_der()).unwrap()
}

/// An independently built self-signed certificate (CN "unit-test-cert"), cached.
pub fn rsa_cert_der() -> Vec<u8> {
    static CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    CACHE
        .get_or_init(|| fixtures::self_signed_cert(&rsa_pkcs8_der(), "unit-test-cert"))
        .clone()
}

pub fn ec_pkcs8_der() -> Vec<u8> {
    fixtures::ec_p256_pkcs8()
}

pub fn ec_spki_der() -> Vec<u8> {
    formats::pkcs8_public_spki(&ec_pkcs8_der()).unwrap()
}

pub fn sensitive_template() -> KeyTemplate {
    KeyTemplate::new(vec![
        TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(true)),
        TemplateAttr::new("CKA_EXTRACTABLE", AttrKind::Bool, AttrValue::Bool(false)),
    ])
}

pub fn aes_32() -> Vec<u8> {
    (0u8..32).collect()
}

pub fn aes_material() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, aes_32());
    material.size_bits = Some(256);
    material
}

pub fn aes16_material(label_hint: Option<&str>) -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, AES_16.to_vec());
    material.size_bits = Some(128);
    material.label_hint = label_hint.map(str::to_owned);
    material
}

pub fn private_material() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, rsa_pkcs8_der());
    material.size_bits = Some(2048);
    material
}

pub fn public_material() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Public, rsa_spki_der());
    material.size_bits = Some(2048);
    material
}

pub fn cert_material() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, rsa_cert_der());
    material.size_bits = Some(2048);
    material
}

pub fn ec_public_material() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Public, ec_spki_der());
    material.curve = Some(Curve::P256);
    material
}

/// The DER body of the first PEM block of `pem` (base64 decoded through the §4.4 codec).
pub fn pem_der(pem: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(pem).unwrap();
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    decode_data(&format!("b64:{body}")).unwrap().0.to_vec()
}

/// One DER TLV at the start of `data`: (tag, header length, content length).
pub fn tlv(data: &[u8]) -> (u8, usize, usize) {
    let tag = data[0];
    let first = data[1];
    if first < 0x80 {
        return (tag, 2, usize::from(first));
    }
    let count = usize::from(first & 0x7f);
    let mut len = 0usize;
    for byte in &data[2..2 + count] {
        len = (len << 8) | usize::from(*byte);
    }
    (tag, 2 + count, len)
}

/// The consecutive TLVs (whole encodings) inside a constructed TLV's content.
pub fn children(der: &[u8]) -> Vec<Vec<u8>> {
    let (_, header, len) = tlv(der);
    let mut content = &der[header..header + len];
    let mut out = Vec::new();
    while !content.is_empty() {
        let (_, h, l) = tlv(content);
        out.push(content[..h + l].to_vec());
        content = &content[h + l..];
    }
    out
}

/// The parts of a DER CSR: (CertificationRequestInfo DER, subject Name DER, SPKI DER,
/// signature AlgorithmIdentifier DER, signature bytes).
pub struct CsrParts {
    pub cri: Vec<u8>,
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
    pub algorithm: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn csr_parts(pem: &[u8]) -> CsrParts {
    let der = pem_der(pem);
    let top = children(&der);
    assert_eq!(
        top.len(),
        3,
        "CSR = SEQUENCE {{ CRI, AlgorithmIdentifier, BIT STRING }}"
    );
    let cri_parts = children(&top[0]);
    let (_, header, _) = tlv(&top[2]);
    CsrParts {
        cri: top[0].clone(),
        subject: cri_parts[1].clone(),
        spki: cri_parts[2].clone(),
        algorithm: top[1].clone(),
        signature: top[2][header + 1..].to_vec(),
    }
}

/// DER of a dotted OID inside an AlgorithmIdentifier (e.g. `06 08 2a 86 48 ce 3d 04 03 03`).
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
