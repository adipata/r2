//! Canonical §4.3 material ↔ stored objects (c2 memory.py `_parse_material`, `_classify`,
//! `_canonical_bytes`, `_policy`).
//!
//! Key bytes are read by r2-core's port of pyca's key parsers (through the `formats` /
//! `x509info` surfaces, which return the normalized key exactly as pyca loads it), so the
//! memory provider accepts and refuses exactly what c2's `load_der_private_key` /
//! `load_der_public_key` / `load_der_x509_certificate` did. The normalized canonical bytes
//! are then handed to OpenSSL, which is never the parser of record.
use std::collections::BTreeMap;

use openssl::nid::Nid;
use openssl::pkey::{HasPublic, Id, PKey, PKeyRef, Private, Public};
use r2_core::error::{ConsoleError, Result};
use r2_core::formats::{self, Encoding};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::template::{AttrValue, KeyTemplate};
use r2_core::text::py_repr;
use r2_core::x509info::{self, Classifier};
use zeroize::Zeroizing;

use crate::ossl_reason;

/// One stored object's material: exactly one payload kind (c2 `_StoredKey`).
///
/// `Secret` holds AES and generic secret keys AND the opaque value of DATA objects — the
/// record's `KeyInfo` class/algorithm tell them apart, and every crypto path checks them
/// before touching the bytes.
#[derive(Clone)]
pub(crate) enum Payload {
    Secret(Zeroizing<Vec<u8>>),
    Private(PKey<Private>),
    Public(PKey<Public>),
    Certificate { der: Vec<u8>, public: PKey<Public> },
}

/// Canonical bytes parsed into OpenSSL objects + derived metadata (c2 `_ParsedMaterial`).
pub(crate) struct Parsed {
    pub(crate) algorithm: KeyAlgorithm,
    pub(crate) key_class: KeyClass,
    pub(crate) curve: Option<Curve>,
    pub(crate) size_bits: Option<u32>,
    pub(crate) payload: Payload,
}

const AES_KEY_BYTES: [usize; 3] = [16, 24, 32];
const UNSUPPORTED_HINT: &str = "supported: AES, RSA, EC, Ed25519/Ed448, X25519/X448";

fn bits_of(len: usize) -> Option<u32> {
    len.checked_mul(8).and_then(|bits| u32::try_from(bits).ok())
}

/// The error kind of a refused material: spec §4.5.2 makes NONE (outside DATA) and OTHER
/// material a `Param` error (param_name "material"); everything else keeps c2's
/// KeyParseError. The message is c2's in both cases.
fn material_error(algorithm: KeyAlgorithm, message: String) -> ConsoleError {
    if matches!(algorithm, KeyAlgorithm::None | KeyAlgorithm::Other) {
        ConsoleError::param(message, "material")
    } else {
        ConsoleError::key_parse(message)
    }
}

fn check_declared(declared: KeyAlgorithm, parsed: KeyAlgorithm) -> Result<()> {
    if declared == parsed {
        return Ok(());
    }
    Err(material_error(
        declared,
        format!(
            "material declares algorithm {} but data parses as {}",
            py_repr(declared.as_str()),
            py_repr(parsed.as_str())
        ),
    ))
}

/// Parse canonical §4.3 bytes; KeyParse on anything non-canonical (c2 `_parse_material`).
pub(crate) fn parse_material(material: &KeyMaterial) -> Result<Parsed> {
    let data: &[u8] = &material.data;
    match material.key_class {
        KeyClass::Secret => parse_secret(material.algorithm, data),
        KeyClass::Data => {
            // §4.3: opaque CKA_VALUE bytes, no algorithm — stored verbatim.
            if material.algorithm != KeyAlgorithm::None {
                return Err(material_error(
                    material.algorithm,
                    format!(
                        "data objects carry no algorithm (got {})",
                        py_repr(material.algorithm.as_str())
                    ),
                )
                .with_hint("data material uses KeyAlgorithm.NONE"));
            }
            if data.is_empty() {
                return Err(ConsoleError::key_parse(
                    "data object value must not be empty",
                ));
            }
            Ok(Parsed {
                algorithm: KeyAlgorithm::None,
                key_class: KeyClass::Data,
                curve: None,
                size_bits: bits_of(data.len()),
                payload: Payload::Secret(Zeroizing::new(data.to_vec())),
            })
        }
        KeyClass::Private => {
            let private = load_private(data)?;
            let (algorithm, curve, size_bits) = classify(&private, true)?;
            check_declared(material.algorithm, algorithm)?;
            Ok(Parsed {
                algorithm,
                key_class: KeyClass::Private,
                curve,
                size_bits,
                payload: Payload::Private(private),
            })
        }
        KeyClass::Public => {
            let public = load_public(data).map_err(|detail| {
                ConsoleError::key_parse(format!(
                    "cannot parse public key material (SPKI DER): {detail}"
                ))
            })?;
            let (algorithm, curve, size_bits) = classify(&public, false)?;
            check_declared(material.algorithm, algorithm)?;
            Ok(Parsed {
                algorithm,
                key_class: KeyClass::Public,
                curve,
                size_bits,
                payload: Payload::Public(public),
            })
        }
        KeyClass::Certificate => {
            let facts = x509info::cert_facts(data, Classifier::KeyParse).map_err(|err| {
                match err
                    .message
                    .strip_prefix("certificate is not valid DER X.509: ")
                {
                    Some(detail) => ConsoleError::key_parse(format!(
                        "cannot parse certificate material (X.509 DER): {detail}"
                    )),
                    // "certificate contains an invalid public key: …" and the classifier's
                    // "unsupported key algorithm: …" are c2's own texts.
                    None => err,
                }
            })?;
            check_declared(material.algorithm, facts.algorithm)?;
            let public = PKey::public_key_from_der(&facts.spki_der).map_err(|err| {
                ConsoleError::key_parse(format!(
                    "certificate contains an invalid public key: {}",
                    ossl_reason(&err)
                ))
            })?;
            Ok(Parsed {
                algorithm: facts.algorithm,
                key_class: KeyClass::Certificate,
                curve: facts.curve,
                size_bits: facts.size_bits,
                payload: Payload::Certificate {
                    der: data.to_vec(),
                    public,
                },
            })
        }
    }
}

fn parse_secret(algorithm: KeyAlgorithm, data: &[u8]) -> Result<Parsed> {
    if algorithm == KeyAlgorithm::Generic {
        if data.is_empty() {
            return Err(ConsoleError::key_parse(
                "generic secret key material must not be empty",
            ));
        }
    } else if algorithm != KeyAlgorithm::Aes {
        return Err(material_error(
            algorithm,
            format!(
                "unsupported secret key algorithm {}",
                py_repr(algorithm.as_str())
            ),
        )
        .with_hint("the memory provider supports AES and generic secret keys"));
    } else if !AES_KEY_BYTES.contains(&data.len()) {
        return Err(ConsoleError::key_parse(format!(
            "AES key must be 16, 24 or 32 bytes; got {}",
            data.len()
        )));
    }
    Ok(Parsed {
        algorithm,
        key_class: KeyClass::Secret,
        curve: None,
        size_bits: bits_of(data.len()),
        payload: Payload::Secret(Zeroizing::new(data.to_vec())),
    })
}

/// pyca `load_der_private_key(data, password=None)` (r2-core's port), normalized as pyca
/// normalizes (RSA-PSS → rsaEncryption, explicit EC parameters → named curve).
fn load_private(data: &[u8]) -> Result<PKey<Private>> {
    let canonical = formats::private_key_bytes(data, Encoding::Der, None).map_err(|err| {
        let detail = err
            .message
            .strip_prefix("exported private key is not valid unencrypted PKCS#8 DER: ")
            .unwrap_or(&err.message);
        if detail == "Password was not given but private key is encrypted" {
            // c2: pyca's TypeError branch.
            ConsoleError::key_parse("private key material must be UNENCRYPTED PKCS#8 DER (§4.3)")
        } else {
            ConsoleError::key_parse(format!("cannot parse private key material: {detail}"))
        }
    })?;
    PKey::private_key_from_der(&canonical).map_err(|err| {
        ConsoleError::key_parse(format!(
            "cannot parse private key material: {}",
            ossl_reason(&err)
        ))
    })
}

/// pyca `load_der_public_key(data)` (r2-core's port, normalized); Err = pyca's text.
pub(crate) fn load_public(data: &[u8]) -> std::result::Result<PKey<Public>, String> {
    let pem = formats::public_key_bytes(data, Encoding::Pem).map_err(|err| {
        err.message
            .strip_prefix("exported public key is not valid DER SubjectPublicKeyInfo: ")
            .unwrap_or(&err.message)
            .to_owned()
    })?;
    PKey::public_key_from_pem(&pem).map_err(|err| ossl_reason(&err))
}

/// pyca 49's curves: OpenSSL NID → (c2 curve, pyca `curve.name`).
fn curve_names(nid: Nid) -> Option<(Curve, &'static str)> {
    let other = |name: &str| Curve::Other(name.to_owned());
    Some(match nid {
        Nid::X9_62_PRIME256V1 => (Curve::P256, "secp256r1"),
        Nid::SECP384R1 => (Curve::P384, "secp384r1"),
        Nid::SECP521R1 => (Curve::P521, "secp521r1"),
        Nid::X9_62_PRIME192V1 => (other("secp192r1"), "secp192r1"),
        Nid::SECP224R1 => (other("secp224r1"), "secp224r1"),
        Nid::SECP256K1 => (other("secp256k1"), "secp256k1"),
        Nid::BRAINPOOL_P256R1 => (other("brainpoolp256r1"), "brainpoolP256r1"),
        Nid::BRAINPOOL_P384R1 => (other("brainpoolp384r1"), "brainpoolP384r1"),
        Nid::BRAINPOOL_P512R1 => (other("brainpoolp512r1"), "brainpoolP512r1"),
        _ => return None,
    })
}

/// pyca's `curve.name` of an EC key's group ("secp256r1", "brainpoolP256r1", …), used by
/// the ECDH curve-mismatch text; the OpenSSL short name for anything else.
pub(crate) fn pyca_curve_name<T: HasPublic>(pkey: &PKeyRef<T>) -> String {
    let nid = pkey.ec_key().ok().and_then(|ec| ec.group().curve_name());
    match nid {
        Some(nid) => curve_names(nid).map_or_else(
            || nid.short_name().unwrap_or("unknown").to_owned(),
            |(_, name)| name.to_owned(),
        ),
        None => "unknown".to_owned(),
    }
}

/// (algorithm, curve, size_bits) for a key (c2 memory `_classify`; §4.3 vocabulary).
pub(crate) fn classify<T: HasPublic>(
    pkey: &PKeyRef<T>,
    private: bool,
) -> Result<(KeyAlgorithm, Option<Curve>, Option<u32>)> {
    let unsupported = |base: &str| {
        let kind = if private { "Private" } else { "Public" };
        ConsoleError::key_parse(format!("unsupported key algorithm: {base}{kind}Key"))
            .with_hint(UNSUPPORTED_HINT)
    };
    match pkey.id() {
        Id::RSA | Id::RSA_PSS => {
            let bits = pkey
                .rsa()
                .ok()
                .and_then(|rsa| u32::try_from(rsa.n().num_bits()).ok());
            Ok((KeyAlgorithm::Rsa, None, bits))
        }
        Id::EC => {
            let curve = pkey
                .ec_key()
                .ok()
                .and_then(|ec| ec.group().curve_name())
                .and_then(curve_names)
                .map(|(curve, _)| curve);
            Ok((KeyAlgorithm::Ec, curve, None))
        }
        Id::ED25519 => Ok((KeyAlgorithm::EcEdwards, Some(Curve::Ed25519), None)),
        Id::ED448 => Ok((KeyAlgorithm::EcEdwards, Some(Curve::Ed448), None)),
        Id::X25519 => Ok((KeyAlgorithm::EcMontgomery, Some(Curve::X25519), None)),
        Id::X448 => Ok((KeyAlgorithm::EcMontgomery, Some(Curve::X448), None)),
        Id::DSA => Err(unsupported("DSA")),
        Id::DH | Id::DHX => Err(unsupported("DH")),
        _ => Err(unsupported("Unknown")),
    }
}

/// The §4.3 canonical bytes of a stored object (c2 `_canonical_bytes`).
pub(crate) fn canonical_bytes(payload: &Payload) -> Result<Zeroizing<Vec<u8>>> {
    match payload {
        Payload::Secret(bytes) => Ok(bytes.clone()),
        Payload::Private(pkey) => pkey.private_key_to_pkcs8().map(Zeroizing::new),
        Payload::Public(pkey) => pkey.public_key_to_der().map(Zeroizing::new),
        Payload::Certificate { der, .. } => Ok(Zeroizing::new(der.clone())),
    }
    .map_err(|err| ConsoleError::crypto(format!("key serialization failed: {}", ossl_reason(&err))))
}

/// Python truthiness of a template value (c2 `bool(attr.value)`).
fn truthy(value: &AttrValue) -> bool {
    match value {
        AttrValue::Bool(flag) => *flag,
        AttrValue::Ulong(number) => *number != 0,
        AttrValue::Str(text) | AttrValue::Symbol(text) => !text.is_empty(),
        AttrValue::Bytes(bytes) => !bytes.is_empty(),
    }
}

/// §5.5 semantics (c2 `_policy`): exportable = CKA_EXTRACTABLE ∧ ¬CKA_SENSITIVE. Secret/
/// private `KeyInfo.attributes` always carry both flags; certificates, public keys and
/// data objects are always exportable (§4.3) and carry none.
pub(crate) fn policy(
    template: Option<&KeyTemplate>,
    key_class: KeyClass,
) -> (bool, BTreeMap<String, AttrValue>) {
    if matches!(
        key_class,
        KeyClass::Public | KeyClass::Certificate | KeyClass::Data
    ) {
        return (true, BTreeMap::new());
    }
    let flag = |name: &str, default: bool| {
        template
            .and_then(|t| t.get(name))
            .filter(|attr| attr.enabled)
            .map_or(default, |attr| truthy(&attr.value))
    };
    let sensitive = flag("CKA_SENSITIVE", false);
    let extractable = flag("CKA_EXTRACTABLE", true);
    (
        extractable && !sensitive,
        BTreeMap::from([
            ("CKA_SENSITIVE".to_owned(), AttrValue::Bool(sensitive)),
            ("CKA_EXTRACTABLE".to_owned(), AttrValue::Bool(extractable)),
        ]),
    )
}
