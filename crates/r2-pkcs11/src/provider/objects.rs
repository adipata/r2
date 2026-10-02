//! list/find/import/generate/delete/export, KeyInfo building, identity resolution, the
//! twin guard, template assembly with material injection, and the certificate → public
//! key helpers the crypto verbs use (spec §4.3, §4.7, §5.4; c2 provider.py; owner R5a).
use std::collections::BTreeMap;

use cryptoki_sys as sys;
use indexmap::IndexMap;
use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::rsa::Rsa;
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial, KeyRef, display_refs};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate};
use r2_core::text::py_repr;
use r2_core::x509info::{self, Classifier};
use r2_provider::lookup;
use r2_provider::{GenerateRequest, KeySelector};
use zeroize::Zeroizing;

use super::{OResult, OpError, Pkcs11Provider};
use crate::attributes::{
    self, Pkcs11Attr, decode_ulong, encode_vendor_value, hex, template_identity, template_to_attrs,
    ulong_bytes,
};
use crate::backend::{MechSpec, RawAttr};

/// CKA codes of cryptoki-sys widened to u64 (`as u64` widens CK_ULONG on every target).
#[allow(
    dead_code,
    reason = "consumed by R5b's verbs (crypto/wrap/derive/edit)"
)]
pub(crate) mod cka {
    use cryptoki_sys as sys;
    macro_rules! codes {
        ($($name:ident = $sys:ident),* $(,)?) => {
            $(pub(crate) const $name: u64 = sys::$sys as u64;)*
        };
    }
    codes!(
        CLASS = CKA_CLASS,
        TOKEN = CKA_TOKEN,
        PRIVATE = CKA_PRIVATE,
        LABEL = CKA_LABEL,
        APPLICATION = CKA_APPLICATION,
        VALUE = CKA_VALUE,
        OBJECT_ID = CKA_OBJECT_ID,
        CERTIFICATE_TYPE = CKA_CERTIFICATE_TYPE,
        ISSUER = CKA_ISSUER,
        SERIAL_NUMBER = CKA_SERIAL_NUMBER,
        KEY_TYPE = CKA_KEY_TYPE,
        SUBJECT = CKA_SUBJECT,
        ID = CKA_ID,
        SENSITIVE = CKA_SENSITIVE,
        ENCRYPT = CKA_ENCRYPT,
        WRAP = CKA_WRAP,
        VERIFY = CKA_VERIFY,
        MODULUS = CKA_MODULUS,
        MODULUS_BITS = CKA_MODULUS_BITS,
        PUBLIC_EXPONENT = CKA_PUBLIC_EXPONENT,
        PRIVATE_EXPONENT = CKA_PRIVATE_EXPONENT,
        PRIME_1 = CKA_PRIME_1,
        PRIME_2 = CKA_PRIME_2,
        EXPONENT_1 = CKA_EXPONENT_1,
        EXPONENT_2 = CKA_EXPONENT_2,
        COEFFICIENT = CKA_COEFFICIENT,
        VALUE_LEN = CKA_VALUE_LEN,
        EXTRACTABLE = CKA_EXTRACTABLE,
        EC_PARAMS = CKA_EC_PARAMS,
        EC_POINT = CKA_EC_POINT,
        CERTIFICATE_CATEGORY = CKA_CERTIFICATE_CATEGORY,
    );
}

fn w(code: sys::CK_ULONG) -> u64 {
    crate::ulong_to_u64(code)
}

/// CKO code of a class (cryptoki-sys numerics, §5 [S]).
pub(crate) fn cko(class: KeyClass) -> u64 {
    w(match class {
        KeyClass::Secret => sys::CKO_SECRET_KEY,
        KeyClass::Private => sys::CKO_PRIVATE_KEY,
        KeyClass::Public => sys::CKO_PUBLIC_KEY,
        KeyClass::Certificate => sys::CKO_CERTIFICATE,
        KeyClass::Data => sys::CKO_DATA,
    })
}

/// CKK code of a creatable algorithm; None for `None`/`Other`.
pub(crate) fn ckk(algorithm: KeyAlgorithm) -> Option<u64> {
    let code = match algorithm {
        KeyAlgorithm::Aes => sys::CKK_AES,
        KeyAlgorithm::Generic => sys::CKK_GENERIC_SECRET,
        KeyAlgorithm::Rsa => sys::CKK_RSA,
        KeyAlgorithm::Ec => sys::CKK_EC,
        KeyAlgorithm::EcEdwards => sys::CKK_EC_EDWARDS,
        KeyAlgorithm::EcMontgomery => sys::CKK_EC_MONTGOMERY,
        KeyAlgorithm::None | KeyAlgorithm::Other => return None,
    };
    Some(w(code))
}

/// CKK code → KeyAlgorithm; HMAC key types fold into GENERIC, anything r2 cannot model is
/// OTHER (c2 `_algorithm_for_ckk`).
pub(crate) fn algorithm_for_ckk(code: u64) -> KeyAlgorithm {
    for algorithm in [
        KeyAlgorithm::Aes,
        KeyAlgorithm::Generic,
        KeyAlgorithm::Rsa,
        KeyAlgorithm::Ec,
        KeyAlgorithm::EcEdwards,
        KeyAlgorithm::EcMontgomery,
    ] {
        if ckk(algorithm) == Some(code) {
            return algorithm;
        }
    }
    let hmac = [
        sys::CKK_SHA_1_HMAC,
        sys::CKK_SHA224_HMAC,
        sys::CKK_SHA256_HMAC,
        sys::CKK_SHA384_HMAC,
        sys::CKK_SHA512_HMAC,
    ];
    if hmac.into_iter().any(|c| w(c) == code) {
        return KeyAlgorithm::Generic;
    }
    KeyAlgorithm::Other
}

fn bool_bytes(value: bool) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(vec![u8::from(value)])
}

fn bytes(value: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(value.to_vec())
}

/// c2 `_i2b`: minimal big-endian bytes, zero as one 0x00 byte.
fn i2b(value: &BigNumRef) -> Zeroizing<Vec<u8>> {
    let data = value.to_vec();
    Zeroizing::new(if data.is_empty() { vec![0] } else { data })
}

/// The first OpenSSL reason of an error stack (§11 D11).
/// A BIGNUM for secret key material on the secure heap: OpenSSL clears secure BIGNUMs
/// when they are freed (rust-openssl's `BigNum` drop is a plain `BN_free`), so the
/// private scalar / RSA components never linger in freed memory, also on error paths.
fn secret_bn(value: &[u8]) -> std::result::Result<BigNum, openssl::error::ErrorStack> {
    let mut bn = BigNum::new_secure()?;
    bn.copy_from_slice(value)?;
    Ok(bn)
}

fn reason(err: &openssl::error::ErrorStack) -> String {
    err.errors()
        .first()
        .and_then(|e| e.reason().map(str::to_string))
        .unwrap_or_else(|| "unknown error".to_string())
}

/// pyca's curve name of an OpenSSL group (for c2's "unsupported EC curve {name}").
fn curve_name(nid: Option<Nid>) -> String {
    match nid {
        Some(Nid::X9_62_PRIME192V1) => "secp192r1".to_string(),
        Some(nid) => nid
            .short_name()
            .map_or_else(|_| "unknown".to_string(), str::to_string),
        None => "unknown".to_string(),
    }
}

fn weierstrass(nid: Option<Nid>) -> Option<Curve> {
    match nid {
        Some(Nid::X9_62_PRIME256V1) => Some(Curve::P256),
        Some(Nid::SECP384R1) => Some(Curve::P384),
        Some(Nid::SECP521R1) => Some(Curve::P521),
        _ => None,
    }
}

fn curve_nid(curve: &Curve) -> Option<Nid> {
    match curve {
        Curve::P256 => Some(Nid::X9_62_PRIME256V1),
        Curve::P384 => Some(Nid::SECP384R1),
        Curve::P521 => Some(Nid::SECP521R1),
        _ => None,
    }
}

fn oid_der(curve: &Curve) -> Zeroizing<Vec<u8>> {
    bytes(r2_core::der::curve_oid_der(curve).unwrap_or_default())
}

/// pyca's public class name of a key type c2 cannot store (`type(key).__name__`).
fn pyca_class(id: Id, private: bool) -> String {
    let base = match id {
        Id::DSA => "DSA",
        Id::DH => "DH",
        _ => "",
    };
    format!("{base}{}", if private { "PrivateKey" } else { "PublicKey" })
}

fn edwards_or_montgomery(id: Id) -> Option<Curve> {
    match id {
        Id::ED25519 => Some(Curve::Ed25519),
        Id::ED448 => Some(Curve::Ed448),
        Id::X25519 => Some(Curve::X25519),
        Id::X448 => Some(Curve::X448),
        _ => None,
    }
}

fn raw_id(curve: &Curve) -> Option<Id> {
    match curve {
        Curve::Ed25519 => Some(Id::ED25519),
        Curve::Ed448 => Some(Id::ED448),
        Curve::X25519 => Some(Id::X25519),
        Curve::X448 => Some(Id::X448),
        _ => None,
    }
}

/// §5.4 material attribute rows of a key's material (CKA_VALUE / RSA CRT set / EC params +
/// point or scalar / certificate attrs).
pub(crate) fn material_attrs(material: &KeyMaterial) -> Result<Vec<RawAttr>> {
    let data: &[u8] = &material.data;
    match material.key_class {
        KeyClass::Secret | KeyClass::Data => Ok(vec![(cka::VALUE, bytes(data))]),
        KeyClass::Certificate => {
            let facts = x509info::cert_facts(data, Classifier::Pkcs11).map_err(|err| match err
                .message
                .strip_prefix("certificate is not valid DER X.509: ")
            {
                Some(detail) => ConsoleError::key_parse(format!(
                    "certificate material is not DER X.509: {detail}"
                )),
                None => err,
            })?;
            let x509 = crate::catalog::symbol_value("CKC_X_509").unwrap_or(0);
            let ckc = ulong_bytes(x509).map_err(|_| {
                ConsoleError::param("CKC_X_509 does not fit a CK_ULONG", "CKA_CERTIFICATE_TYPE")
            })?;
            Ok(vec![
                (cka::CERTIFICATE_TYPE, Zeroizing::new(ckc)),
                (cka::VALUE, bytes(data)),
                (cka::SUBJECT, bytes(&facts.subject_der)),
                (cka::ISSUER, bytes(&facts.issuer_der)),
                (cka::SERIAL_NUMBER, bytes(&facts.serial_der)),
            ])
        }
        KeyClass::Private => private_material_attrs(data),
        KeyClass::Public => public_material_attrs(data),
    }
}

/// c2's `load_der_*_key` gate: the r2-core pyca port decides acceptance and the detail
/// text (§4.4.3); r2's error prefix is replaced by c2's provider prefix.
fn pyca_gate(checked: Result<Vec<u8>>, r2_prefix: &str, c2_prefix: &str) -> Result<()> {
    checked.map(drop).map_err(|err| {
        let detail = err.message.strip_prefix(r2_prefix).unwrap_or(&err.message);
        ConsoleError::key_parse(format!("{c2_prefix}{detail}"))
    })
}

fn private_material_attrs(data: &[u8]) -> Result<Vec<RawAttr>> {
    pyca_gate(
        r2_core::formats::pkcs8_public_spki(data),
        "exported private key is not valid unencrypted PKCS#8 DER: ",
        "private key material is not DER PKCS#8: ",
    )?;
    let key = PKey::private_key_from_der(data).map_err(|err| {
        ConsoleError::key_parse(format!(
            "private key material is not DER PKCS#8: {}",
            reason(&err)
        ))
    })?;
    let invalid = |err: openssl::error::ErrorStack| {
        ConsoleError::key_parse(format!(
            "private key material is not DER PKCS#8: {}",
            reason(&err)
        ))
    };
    match key.id() {
        Id::RSA | Id::RSA_PSS => {
            let rsa = key.rsa().map_err(invalid)?;
            let missing = || {
                ConsoleError::key_parse(
                    "private key material is not DER PKCS#8: missing CRT components",
                )
            };
            Ok(vec![
                (cka::MODULUS, i2b(rsa.n())),
                (cka::PUBLIC_EXPONENT, i2b(rsa.e())),
                (cka::PRIVATE_EXPONENT, i2b(rsa.d())),
                (cka::PRIME_1, i2b(rsa.p().ok_or_else(missing)?)),
                (cka::PRIME_2, i2b(rsa.q().ok_or_else(missing)?)),
                (cka::EXPONENT_1, i2b(rsa.dmp1().ok_or_else(missing)?)),
                (cka::EXPONENT_2, i2b(rsa.dmq1().ok_or_else(missing)?)),
                (cka::COEFFICIENT, i2b(rsa.iqmp().ok_or_else(missing)?)),
            ])
        }
        Id::EC => {
            let ec = key.ec_key().map_err(invalid)?;
            let nid = ec.group().curve_name();
            let curve = weierstrass(nid).ok_or_else(|| {
                ConsoleError::key_parse(format!("unsupported EC curve {}", curve_name(nid)))
            })?;
            let width = i32::try_from(curve.field_bytes().unwrap_or(32)).unwrap_or(32);
            let scalar = ec.private_key().to_vec_padded(width).map_err(invalid)?;
            Ok(vec![
                (cka::EC_PARAMS, oid_der(&curve)),
                (cka::VALUE, Zeroizing::new(scalar)),
            ])
        }
        id => match edwards_or_montgomery(id) {
            Some(curve) => {
                let raw = key.raw_private_key().map_err(invalid)?;
                Ok(vec![
                    (cka::EC_PARAMS, oid_der(&curve)),
                    (cka::VALUE, Zeroizing::new(raw)),
                ])
            }
            None => Err(ConsoleError::key_parse(format!(
                "unsupported private key type {}",
                pyca_class(id, true)
            ))),
        },
    }
}

fn public_material_attrs(data: &[u8]) -> Result<Vec<RawAttr>> {
    let invalid = |err: openssl::error::ErrorStack| {
        ConsoleError::key_parse(format!(
            "public key material is not DER SPKI: {}",
            reason(&err)
        ))
    };
    pyca_gate(
        r2_core::formats::public_key_bytes(data, r2_core::formats::Encoding::Pem),
        "exported public key is not valid DER SubjectPublicKeyInfo: ",
        "public key material is not DER SPKI: ",
    )?;
    // pyca also loads a bare PKCS#1 RSAPublicKey
    let key = match PKey::public_key_from_der(data) {
        Ok(key) => key,
        Err(err) => openssl::rsa::Rsa::public_key_from_der_pkcs1(data)
            .and_then(PKey::from_rsa)
            .map_err(|_| invalid(err))?,
    };
    match key.id() {
        Id::RSA | Id::RSA_PSS => {
            let rsa = key.rsa().map_err(invalid)?;
            Ok(vec![
                (cka::MODULUS, i2b(rsa.n())),
                (cka::PUBLIC_EXPONENT, i2b(rsa.e())),
            ])
        }
        Id::EC => {
            let ec = key.ec_key().map_err(invalid)?;
            let nid = ec.group().curve_name();
            let curve = weierstrass(nid).ok_or_else(|| {
                ConsoleError::key_parse(format!("unsupported EC curve {}", curve_name(nid)))
            })?;
            let mut ctx = BigNumContext::new().map_err(invalid)?;
            let point = ec
                .public_key()
                .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
                .map_err(invalid)?;
            Ok(vec![
                (cka::EC_PARAMS, oid_der(&curve)),
                (
                    cka::EC_POINT,
                    bytes(&r2_core::der::wrap_octet_string(&point)),
                ),
            ])
        }
        id => match edwards_or_montgomery(id) {
            Some(curve) => {
                let raw = key.raw_public_key().map_err(invalid)?;
                Ok(vec![
                    (cka::EC_PARAMS, oid_der(&curve)),
                    (cka::EC_POINT, bytes(&r2_core::der::wrap_octet_string(&raw))),
                ])
            }
            None => Err(ConsoleError::key_parse(format!(
                "unsupported public key type {}",
                pyca_class(id, false)
            ))),
        },
    }
}

fn label_text(raw: Option<Zeroizing<Vec<u8>>>) -> String {
    raw.map(|v| String::from_utf8_lossy(&v).into_owned())
        .unwrap_or_default()
}

fn flag(raw: &Option<Zeroizing<Vec<u8>>>) -> bool {
    raw.as_ref().is_some_and(|v| v.iter().any(|b| *b != 0))
}

impl Pkcs11Provider {
    // ------------------------------------------------------------------
    // templates & attributes (§4.7 / §5.4)
    // ------------------------------------------------------------------

    /// A CKO_/CKK_/CKC_/CKM_ symbol → its value (PyKCS11 tables, c2 `_resolve_symbol`).
    pub(crate) fn resolve_symbol(&self, symbol: &str) -> Result<u64> {
        let known = attributes::is_symbol(symbol);
        let value = crate::catalog::symbol_value(symbol)
            .or_else(|| crate::capability::listed_vendor_symbol(symbol));
        match value {
            Some(value) if known => Ok(value),
            _ => Err(ConsoleError::param(
                format!("unknown PKCS#11 constant {}", py_repr(symbol)),
                symbol,
            )
            .with_hint("ULONG template values may be ints or CKO_/CKK_/CKC_/CKM_ names")),
        }
    }

    fn ulong(&self, value: u64, context: &str) -> Result<Zeroizing<Vec<u8>>> {
        ulong_bytes(value)
            .map(Zeroizing::new)
            .map_err(|err| self.translate(err, context))
    }

    /// Runtime encoding of one converted template entry (c2 `_entry_value`).
    pub(crate) fn entry_value(&self, entry: &Pkcs11Attr) -> Result<Zeroizing<Vec<u8>>> {
        if entry.vendor || entry.code == cka::CERTIFICATE_CATEGORY {
            return encode_vendor_value(entry.kind, &entry.value).map(Zeroizing::new);
        }
        match &entry.value {
            AttrValue::Symbol(symbol) => {
                self.ulong(self.resolve_symbol(symbol)?, "object creation")
            }
            AttrValue::Ulong(n) => self.ulong(*n, "object creation"),
            AttrValue::Bool(b) => Ok(bool_bytes(*b)),
            // c2 resolves every non-vendor str value that looks like a constant name,
            // whatever the attribute's kind: unknown → Param; known → the int, which
            // PyKCS11 stores in a string attribute as `str(int)`.
            AttrValue::Str(text) if attributes::is_symbol(text) => {
                Ok(bytes(self.resolve_symbol(text)?.to_string().as_bytes()))
            }
            AttrValue::Str(text) => Ok(bytes(text.as_bytes())),
            AttrValue::Bytes(data) => Ok(bytes(data)),
        }
    }

    fn locked_value(&self, entry: &Pkcs11Attr) -> Result<u64> {
        match &entry.value {
            AttrValue::Symbol(s) | AttrValue::Str(s) => self.resolve_symbol(s),
            AttrValue::Ulong(n) => Ok(*n),
            other => Ok(decode_ulong(&encode_vendor_value(AttrKind::Ulong, other)?)),
        }
    }

    /// Assemble the raw attribute list (c2 `_build_template`): enabled rows only; locked
    /// CKA_CLASS/CKA_KEY_TYPE validated and replaced; CKA_LABEL/CKA_ID and material/extra
    /// rows injected over same-code rows (first position kept, like a Python dict).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_template(
        &self,
        template: Option<&KeyTemplate>,
        key_class: KeyClass,
        algorithm: Option<KeyAlgorithm>,
        label: &str,
        key_id: Option<&[u8]>,
        material: &[RawAttr],
        extra: &[RawAttr],
        default_exportable: bool,
    ) -> Result<Vec<RawAttr>> {
        let mut assembled: IndexMap<u64, Zeroizing<Vec<u8>>> = IndexMap::new();
        let entries = match template {
            Some(t) => template_to_attrs(t, self.custom_attributes())?,
            None => Vec::new(),
        };
        let no_key_type = matches!(key_class, KeyClass::Certificate | KeyClass::Data);
        for entry in &entries {
            if entry.code == cka::CLASS {
                if self.locked_value(entry)? != cko(key_class) {
                    return Err(ConsoleError::param(
                        format!(
                            "template CKA_CLASS ({}) does not match the {} object being created",
                            entry.value.py_repr(),
                            key_class.as_str()
                        ),
                        "CKA_CLASS",
                    ));
                }
                continue;
            }
            if entry.code == cka::KEY_TYPE {
                let Some(algorithm) = algorithm.filter(|_| !no_key_type) else {
                    continue; // certs carry CKA_CERTIFICATE_TYPE instead (§4.7)
                };
                if Some(self.locked_value(entry)?) != ckk(algorithm) {
                    return Err(ConsoleError::param(
                        format!(
                            "template CKA_KEY_TYPE ({}) does not match the {} key being created",
                            entry.value.py_repr(),
                            algorithm.as_str()
                        ),
                        "CKA_KEY_TYPE",
                    ));
                }
                continue;
            }
            assembled.insert(entry.code, self.entry_value(entry)?);
        }
        assembled.insert(cka::CLASS, self.ulong(cko(key_class), "object creation")?);
        if !no_key_type && let Some(code) = algorithm.and_then(ckk) {
            assembled.insert(cka::KEY_TYPE, self.ulong(code, "object creation")?);
        }
        if default_exportable && matches!(key_class, KeyClass::Secret | KeyClass::Private) {
            // SoftHSM defaults both flags to false on import; a silent template gets the
            // §4.5 import semantics instead (an operator row always wins)
            assembled
                .entry(cka::SENSITIVE)
                .or_insert_with(|| bool_bytes(false));
            assembled
                .entry(cka::EXTRACTABLE)
                .or_insert_with(|| bool_bytes(true));
        }
        assembled.insert(cka::LABEL, bytes(label.as_bytes()));
        match key_id {
            Some(id) => {
                assembled.insert(cka::ID, bytes(id));
            }
            None => {
                assembled.shift_remove(&cka::ID); // DATA: no CKA_ID (§4.3)
            }
        }
        for (code, value) in material.iter().chain(extra) {
            assembled.insert(*code, value.clone());
        }
        Ok(assembled.into_iter().collect())
    }

    /// §4.7 identity resolution for the create flows (c2 `_resolve_identity`).
    pub(crate) fn resolve_identity(
        &self,
        label: &str,
        key_id: Option<&[u8]>,
        templates: &[Option<&KeyTemplate>],
        key_class: Option<KeyClass>,
    ) -> Result<(String, Option<Vec<u8>>)> {
        let (template_label, template_id) = template_identity(templates)?;
        let label = template_label.unwrap_or_else(|| label.to_string());
        if key_class == Some(KeyClass::Data) {
            if key_id.is_some() || template_id.is_some() {
                return Err(
                    ConsoleError::param("data objects carry no CKA_ID (§4.3)", "CKA_ID").with_hint(
                        "drop --id / the template CKA_ID row; data objects are identified by \
                         label alone",
                    ),
                );
            }
            return Ok((label, None));
        }
        if let (Some(k), Some(t)) = (key_id, &template_id)
            && k != t.as_slice()
        {
            return Err(ConsoleError::param(
                format!(
                    "template CKA_ID 0x{} conflicts with --id 0x{}",
                    hex(t),
                    hex(k)
                ),
                "CKA_ID",
            )
            .with_hint("drop one of the two — they must agree"));
        }
        let resolved = match (key_id, template_id) {
            (Some(k), _) => k.to_vec(),
            (None, Some(t)) => t,
            (None, None) => r2_core::crypto::random_bytes(4)?.to_vec(),
        };
        Ok((label, Some(resolved)))
    }

    // ------------------------------------------------------------------
    // object reading
    // ------------------------------------------------------------------

    fn attr(&self, handle: u64, kind: u64) -> OResult<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.backend().get_attr(handle, kind)?)
    }

    /// Build a KeyInfo snapshot; None for objects r2 cannot model (c2 `_key_info`).
    pub(crate) fn key_info(&self, handle: u64, key_class: KeyClass) -> OResult<Option<KeyInfo>> {
        let label = label_text(self.attr(handle, cka::LABEL)?);
        let key_id = self
            .attr(handle, cka::ID)?
            .map(|v| v.to_vec())
            .filter(|v| !v.is_empty());
        let name = self.provider_name().to_string();
        let key_ref = KeyRef::new(name.clone(), label.clone(), key_id);
        match key_class {
            KeyClass::Certificate => {
                let der = self.attr(handle, cka::VALUE)?.filter(|v| !v.is_empty());
                let mut info = KeyInfo {
                    key_ref,
                    key_class,
                    algorithm: KeyAlgorithm::Rsa,
                    size_bits: None,
                    curve: None,
                    exportable: true,
                    attributes: BTreeMap::new(),
                    handle: Some(handle),
                };
                if let Some(der) = der {
                    let facts = x509info::cert_facts(&der, Classifier::Pkcs11)
                        .and_then(|facts| Ok((facts, x509info::cert_attributes(&der)?)));
                    match facts {
                        Ok((facts, attributes)) => {
                            info.algorithm = facts.algorithm;
                            info.size_bits = facts.size_bits;
                            info.curve = facts.curve;
                            info.attributes = attributes;
                        }
                        Err(err) if x509info::pkcs11_skips_certificate(&err) => return Ok(None),
                        Err(err) => return Err(err.into()),
                    }
                }
                Ok(Some(info))
            }
            KeyClass::Data => {
                let value = self.attr(handle, cka::VALUE)?.map(|v| v.len()).unwrap_or(0);
                let mut attributes = BTreeMap::new();
                if let Some(app) = self
                    .attr(handle, cka::APPLICATION)?
                    .filter(|v| !v.is_empty())
                {
                    attributes.insert(
                        "CKA_APPLICATION".to_string(),
                        AttrValue::Str(String::from_utf8_lossy(&app).into_owned()),
                    );
                }
                if let Some(oid) = self.attr(handle, cka::OBJECT_ID)?.filter(|v| !v.is_empty()) {
                    attributes.insert("CKA_OBJECT_ID".to_string(), AttrValue::Bytes(oid.to_vec()));
                }
                Ok(Some(KeyInfo {
                    key_ref: KeyRef::new(name, label, None), // no CKA_ID (§4.3)
                    key_class,
                    algorithm: KeyAlgorithm::None,
                    size_bits: u32::try_from(value.saturating_mul(8)).ok(),
                    curve: None,
                    exportable: true,
                    attributes,
                    handle: Some(handle),
                }))
            }
            _ => {
                let ckk_raw = self.attr(handle, cka::KEY_TYPE)?;
                let ckk_code = ckk_raw.as_ref().map(|v| decode_ulong(v));
                let algorithm = ckk_code.map_or(KeyAlgorithm::Other, algorithm_for_ckk);
                let mut size_bits = None;
                let mut curve = None;
                let mut attributes = BTreeMap::new();
                let mut exportable = true;
                if matches!(key_class, KeyClass::Secret | KeyClass::Private) {
                    if key_class == KeyClass::Secret {
                        let vlen = self
                            .attr(handle, cka::VALUE_LEN)?
                            .map_or(0, |v| decode_ulong(&v));
                        if vlen != 0 {
                            size_bits = u32::try_from(vlen.saturating_mul(8)).ok();
                        }
                    }
                    let sensitive = flag(&self.attr(handle, cka::SENSITIVE)?);
                    let extractable = flag(&self.attr(handle, cka::EXTRACTABLE)?);
                    exportable = extractable && !sensitive;
                    attributes.insert("CKA_SENSITIVE".to_string(), AttrValue::Bool(sensitive));
                    attributes.insert("CKA_EXTRACTABLE".to_string(), AttrValue::Bool(extractable));
                }
                match algorithm {
                    KeyAlgorithm::Rsa => {
                        if let Some(modulus) =
                            self.attr(handle, cka::MODULUS)?.filter(|m| !m.is_empty())
                        {
                            let significant = modulus.iter().skip_while(|b| **b == 0).count();
                            size_bits = u32::try_from(significant.saturating_mul(8)).ok();
                        }
                    }
                    KeyAlgorithm::Ec | KeyAlgorithm::EcEdwards | KeyAlgorithm::EcMontgomery => {
                        if let Some(params) =
                            self.attr(handle, cka::EC_PARAMS)?.filter(|p| !p.is_empty())
                        {
                            curve = r2_core::der::curve_from_oid_der(&params);
                        }
                    }
                    KeyAlgorithm::Other => {
                        // §4.3 catch-all: listed with its raw key type, never operated on
                        exportable = false;
                        let symbol = ckk_code
                            .map_or_else(|| "unknown".to_string(), crate::catalog::ckk_symbol);
                        attributes.insert("CKA_KEY_TYPE".to_string(), AttrValue::Symbol(symbol));
                    }
                    _ => {}
                }
                Ok(Some(KeyInfo {
                    key_ref,
                    key_class,
                    algorithm,
                    size_bits,
                    curve,
                    exportable,
                    attributes,
                    handle: Some(handle),
                }))
            }
        }
    }

    pub(crate) fn class_of_handle(&self, handle: u64) -> OResult<Option<KeyClass>> {
        let Some(raw) = self.attr(handle, cka::CLASS)? else {
            return Ok(None);
        };
        let code = decode_ulong(&raw);
        Ok(lookup::CLASS_PREFERENCE
            .into_iter()
            .find(|class| cko(*class) == code))
    }

    fn class_template(
        &self,
        key_class: KeyClass,
        label: &str,
        key_id: Option<&[u8]>,
    ) -> OResult<Vec<RawAttr>> {
        let mut template = vec![
            (cka::CLASS, Zeroizing::new(ulong_bytes(cko(key_class))?)),
            (cka::LABEL, bytes(label.as_bytes())),
        ];
        if let Some(id) = key_id {
            template.push((cka::ID, bytes(id)));
        }
        Ok(template)
    }

    /// Re-resolve a KeyInfo to a live object handle (c2 `_find_handle`): a single match
    /// wins regardless of `key.handle` (handles renumber across re-login); among twins only
    /// the exact `key.handle` object is acceptable, else AmbiguousKey.
    pub(crate) fn find_handle(&self, key: &KeyInfo) -> OResult<u64> {
        let template = self.class_template(
            key.key_class,
            &key.key_ref.label,
            key.key_ref.key_id.as_deref(),
        )?;
        let handles = self.backend().find_objects(&template)?;
        let display = key.key_ref.display();
        match handles.len() {
            0 => {
                return Err(ConsoleError::key_not_found(format!(
                    "key '{display}' no longer available on {}",
                    self.provider_name()
                ))
                .with_hint("refresh with `keys`")
                .into());
            }
            1 => return Ok(handles[0]),
            _ => {}
        }
        if let Some(wanted) = key.handle {
            let exact: Vec<u64> = handles.iter().copied().filter(|h| *h == wanted).collect();
            if exact.len() == 1 {
                return Ok(exact[0]);
            }
        }
        let mut infos = Vec::new();
        for handle in &handles {
            if let Some(info) = self.key_info(*handle, key.key_class)? {
                infos.push(info);
            }
        }
        Err(ConsoleError::ambiguous_key(
            format!(
                "key '{display}' matches {} identical objects on {}: {}",
                handles.len(),
                self.provider_name(),
                display_refs(&infos).join(", ")
            ),
            infos.iter().map(|i| i.key_ref.clone()).collect(),
        )
        .with_hint("refresh with `keys` and re-select the object with its @<handle> suffix")
        .into())
    }

    /// Handles holding exactly the (class, label, CKA_ID) identity; `key_id` None = a
    /// label-only identity (only id-less objects are twins); `exclude` drops the edited
    /// object (rename guard).
    pub(crate) fn identity_twins(
        &self,
        key_class: KeyClass,
        label: &str,
        key_id: Option<&[u8]>,
        exclude: Option<u64>,
    ) -> OResult<Vec<u64>> {
        let template = self.class_template(key_class, label, key_id)?;
        let mut twins = Vec::new();
        for other in self.backend().find_objects(&template)? {
            if exclude == Some(other) {
                continue;
            }
            if key_id.is_none() && self.attr(other, cka::ID)?.is_some_and(|id| !id.is_empty()) {
                continue;
            }
            twins.push(other);
        }
        Ok(twins)
    }

    /// Refuse creating an exact (class, label, CKA_ID) twin (§4.7 guard; certificates
    /// exempt; DATA identity is (class, label)).
    pub(crate) fn ensure_identity_free(
        &self,
        key_classes: &[KeyClass],
        label: &str,
        key_id: Option<&[u8]>,
    ) -> OResult<()> {
        for key_class in key_classes {
            if *key_class == KeyClass::Certificate {
                continue;
            }
            if !self
                .identity_twins(*key_class, label, key_id, None)?
                .is_empty()
            {
                return Err(lookup::duplicate_identity(
                    self.provider_name(),
                    *key_class,
                    label,
                    key_id,
                    false,
                )
                .into());
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // key management (§4.5)
    // ------------------------------------------------------------------

    pub(crate) fn list_keys_impl(&self) -> Result<Vec<KeyInfo>> {
        self.op("key listing", || {
            let mut infos = Vec::new();
            for key_class in KeyClass::ALL {
                let template = vec![(cka::CLASS, Zeroizing::new(ulong_bytes(cko(key_class))?))];
                for handle in self.backend().find_objects(&template)? {
                    if let Some(info) = self.key_info(handle, key_class)? {
                        infos.push(info);
                    }
                }
            }
            Ok(infos)
        })
    }

    pub(crate) fn find_key_impl(&self, selector: &KeySelector) -> Result<KeyInfo> {
        self.op("key lookup", || {
            let mut template = vec![(cka::LABEL, bytes(selector.label.as_bytes()))];
            if let Some(id) = &selector.key_id {
                template.push((cka::ID, bytes(id)));
            }
            let mut matches = Vec::new();
            for handle in self.backend().find_objects(&template)? {
                let Some(class) = self.class_of_handle(handle)? else {
                    continue;
                };
                if selector.key_class.is_some_and(|wanted| wanted != class) {
                    continue;
                }
                let Some(info) = self.key_info(handle, class)? else {
                    continue;
                };
                if selector
                    .handle
                    .is_some_and(|wanted| info.handle != Some(wanted))
                {
                    continue;
                }
                matches.push(info);
            }
            Ok(lookup::select_match(
                self.provider_name(),
                selector,
                matches,
            )?)
        })
    }

    pub(crate) fn import_key_impl(
        &self,
        material: &KeyMaterial,
        label: &str,
        template: Option<&KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> Result<KeyInfo> {
        if material.algorithm == KeyAlgorithm::Other
            || (material.algorithm == KeyAlgorithm::None && material.key_class != KeyClass::Data)
        {
            return Err(ConsoleError::param(
                format!(
                    "cannot import {} {} material",
                    material.algorithm.as_str(),
                    material.key_class.as_str()
                ),
                "material",
            ));
        }
        let material_rows = material_attrs(material)?;
        let (label, resolved_id) =
            self.resolve_identity(label, key_id, &[template], Some(material.key_class))?;
        let algorithm = (!matches!(material.key_class, KeyClass::Certificate | KeyClass::Data))
            .then_some(material.algorithm);
        let attrs = self.build_template(
            template,
            material.key_class,
            algorithm,
            &label,
            resolved_id.as_deref(),
            &material_rows,
            &[],
            true,
        )?;
        tracing::info!(
            target: "r2::pkcs11",
            "{}: importing {}/{} object '{}' ({} bytes, {} attrs)",
            self.provider_name(),
            material.algorithm.as_str(),
            material.key_class.as_str(),
            label,
            material.data.len(),
            attrs.len()
        );
        self.op("object creation", || {
            self.ensure_identity_free(&[material.key_class], &label, resolved_id.as_deref())?;
            let handle = self.backend().create_object(&attrs)?;
            self.key_info(handle, material.key_class)?.ok_or_else(|| {
                OpError::Console(ConsoleError::key_not_found(format!(
                    "imported object '{label}' vanished"
                )))
            })
        })
    }

    pub(crate) fn generate_key_impl(&self, request: &GenerateRequest) -> Result<KeyInfo> {
        let (label, resolved_id) = self.resolve_identity(
            &request.label,
            request.key_id.as_deref(),
            &[request.template.as_ref(), request.public_template.as_ref()],
            None,
        )?;
        let algorithm = request.algorithm;
        if matches!(algorithm, KeyAlgorithm::None | KeyAlgorithm::Other) {
            return Err(ConsoleError::param(
                format!("cannot generate {} keys", algorithm.as_str()),
                "algorithm",
            ));
        }
        if matches!(algorithm, KeyAlgorithm::Aes | KeyAlgorithm::Generic) {
            let Some(size_bits) = request.size_bits else {
                return Err(ConsoleError::param(
                    format!("size_bits is required for {}", algorithm.as_str()),
                    "size_bits",
                ));
            };
            if algorithm == KeyAlgorithm::Generic
                && (size_bits % 8 != 0 || !(8..=8192).contains(&size_bits))
            {
                return Err(ConsoleError::param(
                    format!(
                        "invalid generic secret size {size_bits}; expected a multiple of 8 between 8 and \
                         8192 bits"
                    ),
                    "size_bits",
                ));
            }
            let extra = vec![(
                cka::VALUE_LEN,
                self.ulong(u64::from(size_bits / 8), "object creation")?,
            )];
            let attrs = self.build_template(
                request.template.as_ref(),
                KeyClass::Secret,
                Some(algorithm),
                &label,
                resolved_id.as_deref(),
                &[],
                &extra,
                false,
            )?;
            let (keygen, what) = if algorithm == KeyAlgorithm::Aes {
                (w(sys::CKM_AES_KEY_GEN), "AES")
            } else {
                (w(sys::CKM_GENERIC_SECRET_KEY_GEN), "generic secret")
            };
            tracing::info!(
                target: "r2::pkcs11",
                "{}: generating {}-{} key '{}'",
                self.provider_name(),
                what,
                size_bits,
                label
            );
            return self.op(&format!("{what} key generation"), || {
                self.ensure_identity_free(&[KeyClass::Secret], &label, resolved_id.as_deref())?;
                let handle = self
                    .backend()
                    .generate_key(&MechSpec::Plain { ckm: keygen }, &attrs)?;
                self.key_info(handle, KeyClass::Secret)?.ok_or_else(|| {
                    OpError::Console(ConsoleError::key_not_found(format!(
                        "generated key '{label}' vanished"
                    )))
                })
            });
        }
        let public_extra: Vec<RawAttr> = if algorithm == KeyAlgorithm::Rsa {
            let Some(size_bits) = request.size_bits else {
                return Err(ConsoleError::param(
                    "size_bits is required for RSA",
                    "size_bits",
                ));
            };
            vec![
                (
                    cka::MODULUS_BITS,
                    self.ulong(u64::from(size_bits), "object creation")?,
                ),
                (cka::PUBLIC_EXPONENT, bytes(&[0x01, 0x00, 0x01])),
            ]
        } else {
            let Some(curve) = &request.curve else {
                return Err(ConsoleError::param(
                    format!("curve is required for {}", algorithm.as_str()),
                    "curve",
                ));
            };
            if !Curve::KNOWN.contains(curve) {
                return Err(ConsoleError::param(
                    format!("unknown curve {}", py_repr(curve.as_str())),
                    "curve",
                )
                .with_hint("valid curves: ed25519, ed448, p256, p384, p521, x25519, x448"));
            }
            if curve.algorithm() != algorithm {
                return Err(ConsoleError::param(
                    format!(
                        "curve {} does not belong to algorithm {}",
                        py_repr(curve.as_str()),
                        algorithm.as_str()
                    ),
                    "curve",
                ));
            }
            vec![(cka::EC_PARAMS, oid_der(curve))]
        };
        let private_attrs = self.build_template(
            request.template.as_ref(),
            KeyClass::Private,
            Some(algorithm),
            &label,
            resolved_id.as_deref(),
            &[],
            &[],
            false,
        )?;
        let public_attrs = self.build_template(
            request.public_template.as_ref(),
            KeyClass::Public,
            Some(algorithm),
            &label,
            resolved_id.as_deref(),
            &[],
            &public_extra,
            false,
        )?;
        let gen_ckm = w(match algorithm {
            KeyAlgorithm::Rsa => sys::CKM_RSA_PKCS_KEY_PAIR_GEN,
            KeyAlgorithm::Ec => sys::CKM_EC_KEY_PAIR_GEN,
            KeyAlgorithm::EcEdwards => sys::CKM_EC_EDWARDS_KEY_PAIR_GEN,
            _ => sys::CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        });
        tracing::info!(
            target: "r2::pkcs11",
            "{}: generating {} keypair '{}' (size={:?} curve={:?})",
            self.provider_name(),
            algorithm.as_str(),
            label,
            request.size_bits,
            request.curve.as_ref().map(Curve::as_str)
        );
        self.op("keypair generation", || {
            // both halves checked up front — a collision never leaves a half-created pair
            self.ensure_identity_free(
                &[KeyClass::Public, KeyClass::Private],
                &label,
                resolved_id.as_deref(),
            )?;
            let (_public, private) = self.backend().generate_key_pair(
                &MechSpec::Plain { ckm: gen_ckm },
                &public_attrs,
                &private_attrs,
            )?;
            self.key_info(private, KeyClass::Private)?.ok_or_else(|| {
                OpError::Console(ConsoleError::key_not_found(format!(
                    "generated key '{label}' vanished"
                )))
            })
        })
    }

    pub(crate) fn delete_key_impl(&self, key: &KeyInfo) -> Result<()> {
        self.op("object deletion", || {
            let handle = self.find_handle(key)?;
            self.backend().destroy_object(handle)?;
            tracing::info!(target: "r2::pkcs11", "{}: deleted {}", self.provider_name(), key.key_ref.display());
            Ok(())
        })
    }

    // ------------------------------------------------------------------
    // export (§5.6)
    // ------------------------------------------------------------------

    pub(crate) fn export_key_impl(&self, key: &KeyInfo) -> Result<KeyMaterial> {
        reject_other_type(key, "export")?;
        if matches!(key.key_class, KeyClass::Secret | KeyClass::Private) && !key.exportable {
            return Err(ConsoleError::key_not_exportable(format!(
                "key '{}' is not exportable",
                key.key_ref.display()
            ))
            .with_hint("CKA_SENSITIVE/CKA_EXTRACTABLE forbid a plain-value read (§5.5)"));
        }
        self.op("key export", || {
            let handle = self.find_handle(key)?;
            let display = key.key_ref.display();
            let value = || -> OResult<Option<Zeroizing<Vec<u8>>>> {
                Ok(self.attr(handle, cka::VALUE)?.filter(|v| !v.is_empty()))
            };
            let material =
                |algorithm, key_class, data: Zeroizing<Vec<u8>>, curve, size_bits| KeyMaterial {
                    algorithm,
                    key_class,
                    data,
                    curve,
                    size_bits,
                    label_hint: Some(key.key_ref.label.clone()),
                };
            match key.key_class {
                KeyClass::Data => {
                    let data = value()?.ok_or_else(|| {
                        ConsoleError::key_not_exportable(format!(
                            "data object '{display}' has no readable CKA_VALUE"
                        ))
                    })?;
                    let bits = u32::try_from(data.len().saturating_mul(8)).ok();
                    Ok(material(
                        KeyAlgorithm::None,
                        KeyClass::Data,
                        data,
                        None,
                        bits,
                    ))
                }
                KeyClass::Certificate => {
                    let der = value()?.ok_or_else(|| {
                        ConsoleError::key_not_exportable(format!(
                            "certificate '{display}' has no readable CKA_VALUE"
                        ))
                    })?;
                    Ok(material(
                        key.algorithm,
                        KeyClass::Certificate,
                        der,
                        key.curve.clone(),
                        key.size_bits,
                    ))
                }
                KeyClass::Secret => {
                    let data = value()?.ok_or_else(|| refused(&display))?;
                    let bits = u32::try_from(data.len().saturating_mul(8)).ok();
                    Ok(material(key.algorithm, KeyClass::Secret, data, None, bits))
                }
                KeyClass::Public => {
                    let der = self.export_public(handle, key)?;
                    Ok(material(
                        key.algorithm,
                        KeyClass::Public,
                        der,
                        key.curve.clone(),
                        key.size_bits,
                    ))
                }
                KeyClass::Private => {
                    let der = self.export_private(handle, key)?;
                    Ok(material(
                        key.algorithm,
                        KeyClass::Private,
                        der,
                        key.curve.clone(),
                        key.size_bits,
                    ))
                }
            }
        })
    }

    fn export_public(&self, handle: u64, key: &KeyInfo) -> OResult<Zeroizing<Vec<u8>>> {
        let rebuild = |err: openssl::error::ErrorStack| {
            OpError::Console(ConsoleError::crypto(format!(
                "cannot rebuild the public key read from the token: {}",
                reason(&err)
            )))
        };
        let pkey: PKey<Public> = if key.algorithm == KeyAlgorithm::Rsa {
            let modulus = self.attr(handle, cka::MODULUS)?.filter(|v| !v.is_empty());
            let exponent = self
                .attr(handle, cka::PUBLIC_EXPONENT)?
                .filter(|v| !v.is_empty());
            let (Some(n), Some(e)) = (modulus, exponent) else {
                return Err(ConsoleError::key_not_exportable(
                    "public RSA attributes unreadable on token",
                )
                .into());
            };
            let rsa = Rsa::from_public_components(
                BigNum::from_slice(&n).map_err(rebuild)?,
                BigNum::from_slice(&e).map_err(rebuild)?,
            )
            .map_err(rebuild)?;
            PKey::from_rsa(rsa).map_err(rebuild)?
        } else {
            let point = self.attr(handle, cka::EC_POINT)?.filter(|v| !v.is_empty());
            let (Some(point), Some(curve)) = (point, key.curve.as_ref()) else {
                return Err(ConsoleError::key_not_exportable(
                    "public EC attributes unreadable on token",
                )
                .into());
            };
            let raw = r2_core::der::unwrap_octet_string(&point);
            if let Some(nid) = curve_nid(curve) {
                let group = EcGroup::from_curve_name(nid).map_err(rebuild)?;
                let mut ctx = BigNumContext::new().map_err(rebuild)?;
                let ec_point = EcPoint::from_bytes(&group, &raw, &mut ctx).map_err(rebuild)?;
                PKey::from_ec_key(EcKey::from_public_key(&group, &ec_point).map_err(rebuild)?)
                    .map_err(rebuild)?
            } else {
                let id = raw_id(curve).ok_or_else(|| {
                    ConsoleError::key_not_exportable("public EC attributes unreadable on token")
                })?;
                PKey::public_key_from_raw_bytes(&raw, id).map_err(rebuild)?
            }
        };
        Ok(Zeroizing::new(pkey.public_key_to_der().map_err(rebuild)?))
    }

    fn export_private(&self, handle: u64, key: &KeyInfo) -> OResult<Zeroizing<Vec<u8>>> {
        let display = key.key_ref.display();
        let rebuild = |err: openssl::error::ErrorStack| {
            OpError::Console(ConsoleError::crypto(format!(
                "cannot rebuild the private key read from the token: {}",
                reason(&err)
            )))
        };
        let pkey: PKey<Private> = if key.algorithm == KeyAlgorithm::Rsa {
            let mut parts = Vec::new();
            for code in [
                cka::MODULUS,
                cka::PUBLIC_EXPONENT,
                cka::PRIVATE_EXPONENT,
                cka::PRIME_1,
                cka::PRIME_2,
                cka::EXPONENT_1,
                cka::EXPONENT_2,
                cka::COEFFICIENT,
            ] {
                let part = self.attr(handle, code)?.filter(|v| !v.is_empty());
                parts.push(part.ok_or_else(|| refused(&display))?);
            }
            let bn = |i: usize| secret_bn(&parts[i]).map_err(rebuild);
            let rsa = Rsa::from_private_components(
                bn(0)?,
                bn(1)?,
                bn(2)?,
                bn(3)?,
                bn(4)?,
                bn(5)?,
                bn(6)?,
                bn(7)?,
            )
            .map_err(rebuild)?;
            PKey::from_rsa(rsa).map_err(rebuild)?
        } else {
            let value = self.attr(handle, cka::VALUE)?.filter(|v| !v.is_empty());
            let (Some(value), Some(curve)) = (value, key.curve.as_ref()) else {
                return Err(refused(&display).into());
            };
            if let Some(nid) = curve_nid(curve) {
                let group = EcGroup::from_curve_name(nid).map_err(rebuild)?;
                let mut ctx = BigNumContext::new_secure().map_err(rebuild)?;
                let scalar = secret_bn(&value).map_err(rebuild)?;
                let mut point = EcPoint::new(&group).map_err(rebuild)?;
                point
                    .mul_generator2(&group, &scalar, &mut ctx)
                    .map_err(rebuild)?;
                let ec =
                    EcKey::from_private_components(&group, &scalar, &point).map_err(rebuild)?;
                PKey::from_ec_key(ec).map_err(rebuild)?
            } else {
                let id = raw_id(curve).ok_or_else(|| refused(&display))?;
                PKey::private_key_from_raw_bytes(&value, id).map_err(rebuild)?
            }
        };
        Ok(Zeroizing::new(
            pkey.private_key_to_pkcs8().map_err(rebuild)?,
        ))
    }

    // ------------------------------------------------------------------
    // certificate → public-key resolution (§4.3), for the verbs (R5b)
    // ------------------------------------------------------------------

    /// (handle, created): a CKO_PUBLIC_KEY with the certificate's CKA_ID, else a session
    /// public-key object built from the certificate SPKI (c2 `_public_for_certificate`).
    #[allow(
        dead_code,
        reason = "consumed by R5b's verbs (crypto/wrap/derive/edit)"
    )]
    pub(crate) fn public_for_certificate(&self, cert_key: &KeyInfo) -> OResult<(u64, bool)> {
        if let Some(id) = &cert_key.key_ref.key_id {
            let template = vec![
                (
                    cka::CLASS,
                    Zeroizing::new(ulong_bytes(cko(KeyClass::Public))?),
                ),
                (cka::ID, bytes(id)),
            ];
            // twin publics under one CKA_ID are interchangeable SPKI carriers
            if let Some(first) = self.backend().find_objects(&template)?.first() {
                return Ok((*first, false));
            }
        }
        let cert_handle = self.find_handle(cert_key)?;
        let der = self
            .attr(cert_handle, cka::VALUE)?
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                ConsoleError::crypto(format!(
                    "certificate '{}' has no readable value",
                    cert_key.key_ref.display()
                ))
            })?;
        let facts = x509info::cert_facts(&der, Classifier::Pkcs11)?;
        let rows = material_attrs(&KeyMaterial::new(
            facts.algorithm,
            KeyClass::Public,
            facts.spki_der,
        ))?;
        let key_type = ckk(facts.algorithm).unwrap_or_default();
        let mut attrs = vec![
            (
                cka::CLASS,
                Zeroizing::new(ulong_bytes(cko(KeyClass::Public))?),
            ),
            (cka::KEY_TYPE, Zeroizing::new(ulong_bytes(key_type)?)),
            (cka::TOKEN, bool_bytes(false)),
            (cka::PRIVATE, bool_bytes(false)),
            (cka::LABEL, bytes(cert_key.key_ref.label.as_bytes())),
            (cka::ENCRYPT, bool_bytes(true)),
            (cka::VERIFY, bool_bytes(true)),
            (cka::WRAP, bool_bytes(true)),
        ];
        attrs.extend(rows);
        Ok((self.backend().create_object(&attrs)?, true))
    }

    /// Run `f` with the operative handle: certificates resolve to their public key, an
    /// on-the-fly session object is destroyed after use (c2 `_with_public_use_handle`).
    #[allow(
        dead_code,
        reason = "consumed by R5b's verbs (crypto/wrap/derive/edit)"
    )]
    pub(crate) fn with_public_use_handle<T>(
        &self,
        key: &KeyInfo,
        f: impl FnOnce(u64) -> OResult<T>,
    ) -> OResult<T> {
        if key.key_class != KeyClass::Certificate {
            return f(self.find_handle(key)?);
        }
        let (handle, created) = self.public_for_certificate(key)?;
        let result = f(handle);
        if created {
            let _ = self.backend().destroy_object(handle); // dies with the session anyway
        }
        result
    }
}

fn refused(display: &str) -> ConsoleError {
    ConsoleError::key_not_exportable(format!("token refused to reveal '{display}'"))
        .with_hint("key is marked sensitive/non-extractable on the token")
}

/// Certificates stand in for PUBLIC keys only (c2 `_reject_certificate`).
#[allow(
    dead_code,
    reason = "consumed by R5b's verbs (crypto/wrap/derive/edit)"
)]
pub(crate) fn reject_certificate(key: &KeyInfo, verb: &str) -> Result<()> {
    if key.key_class == KeyClass::Certificate {
        return Err(ConsoleError::unsupported(format!(
            "certificates cannot be used for {verb} (§4.3)"
        ))
        .with_hint("certificates stand in for PUBLIC keys only (encrypt/verify/wrap)"));
    }
    Ok(())
}

/// §4.3 catch-all objects are listed and deleted only (c2 `_reject_other_type`).
pub(crate) fn reject_other_type(key: &KeyInfo, verb: &str) -> Result<()> {
    if key.algorithm == KeyAlgorithm::Other {
        let key_type = key
            .attributes
            .get("CKA_KEY_TYPE")
            .map_or_else(|| "unknown".to_string(), AttrValue::render_info);
        return Err(ConsoleError::unsupported(format!(
            "key type {key_type} of '{}' is not supported by r2 for {verb}",
            key.key_ref.display()
        ))
        .with_hint("objects of unsupported key types can be listed and deleted only"));
    }
    Ok(())
}

/// DATA and OTHER objects take part in no crypto verb (c2 `_reject_non_key`).
#[allow(
    dead_code,
    reason = "consumed by R5b's verbs (crypto/wrap/derive/edit)"
)]
pub(crate) fn reject_non_key(key: &KeyInfo, verb: &str) -> Result<()> {
    if key.key_class == KeyClass::Data {
        return Err(ConsoleError::unsupported(format!(
            "data objects cannot be used for {verb} (§4.3)"
        ))
        .with_hint("data objects hold opaque bytes, not key material — export or copy them"));
    }
    reject_other_type(key, verb)
}
