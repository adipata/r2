//! Key material parsing (spec §4.4.3, §5.4; owner R6): bytes → `Vec<KeyMaterial>`.
//!
//! Port of c2 `core/keyparse.py` over OpenSSL. pyca's acceptance rules are reproduced on top
//! of OpenSSL (the classification/normalization helpers below are shared with x509build,
//! x509info and formats): RSA-PSS keys load as plain RSA, EC keys are re-encoded on their
//! named curve (uncompressed point), only pyca 49's curves load, explicit EC parameters only
//! when they are P-256/P-384/P-521, and encrypted inputs only with pyca's cipher set.
//! Passwords come through the caller's callback; OpenSSL never prompts (PEM blocks are
//! decoded here and loaded through the DER entry points).
use std::cell::Cell;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{Asn1Flag, EcGroup, EcGroupRef, EcKey, EcPoint, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{HasPublic, Id, PKey, PKeyRef, Private, Public};
use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use openssl::x509::{X509, X509Req};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::crypto::ensure_legacy_provider;
use crate::error::{ConsoleError, Result};
use crate::keys::{Curve, KeyAlgorithm, KeyClass, KeyMaterial};
use crate::text::py_repr;
use crate::x509info::{self, Classifier};

/// Type hint of `parse_key_material` (c2's frozen hint set). Token: "auto" | "aes" | "rsa" |
/// "ec" | "cert".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyHint {
    #[default]
    Auto,
    Aes,
    Rsa,
    Ec,
    Cert,
}
impl KeyHint {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyHint::Auto => "auto",
            KeyHint::Aes => "aes",
            KeyHint::Rsa => "rsa",
            KeyHint::Ec => "ec",
            KeyHint::Cert => "cert",
        }
    }
}
/// Exact tokens; else KeyParse "unknown key material hint {s!r}" (hint "valid hints: auto,
/// aes, rsa, ec, cert").
impl FromStr for KeyHint {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "auto" => Ok(KeyHint::Auto),
            "aes" => Ok(KeyHint::Aes),
            "rsa" => Ok(KeyHint::Rsa),
            "ec" => Ok(KeyHint::Ec),
            "cert" => Ok(KeyHint::Cert),
            other => Err(ConsoleError::key_parse(format!(
                "unknown key material hint {}",
                py_repr(other)
            ))
            .with_hint("valid hints: auto, aes, rsa, ec, cert")),
        }
    }
}

/// Password source. Argument = prompt text ("Password for encrypted {PEM label}",
/// "Password for encrypted private key", "Password for PKCS#12"). It may fail (e.g.
/// UserAbort from a prompt); the error propagates unchanged.
pub type PasswordCallback<'a> = &'a mut dyn FnMut(&str) -> Result<SecretString>;

/// Sniff and parse key material. Errors → KeyParse (listing attempted formats).
pub fn parse_key_material(
    data: &[u8],
    hint: KeyHint,
    password: Option<PasswordCallback<'_>>,
) -> Result<Vec<KeyMaterial>> {
    let mut password = password;
    if data.is_empty() {
        return Err(ConsoleError::key_parse("empty key material"));
    }
    let mut materials = if contains(data, PEM_MARKER) {
        Some(parse_pem(data, &mut password)?)
    } else if data[0] == 0x30 {
        parse_der(data, &mut password)?
    } else {
        None
    };
    if materials.is_none()
        && matches!(hint, KeyHint::Auto | KeyHint::Aes)
        && AES_LENGTHS.contains(&data.len())
    {
        let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, data.to_vec());
        material.size_bits = u32::try_from(data.len() * 8).ok();
        materials = Some(vec![material]);
    }
    let Some(materials) = materials else {
        return Err(ConsoleError::key_parse(format!(
            "could not parse key material (attempted: {ATTEMPTED})"
        ))
        .with_hint(
            "supported inputs: PEM/DER keys, certificates, CSRs, PKCS#12, raw AES keys of 16/24/32 bytes",
        ));
    };
    if hint != KeyHint::Auto {
        check_hint(&materials, hint)?;
    }
    Ok(materials)
}

// ---------------------------------------------------------------------------------------
// Constants and small helpers
// ---------------------------------------------------------------------------------------

const AES_LENGTHS: [usize; 3] = [16, 24, 32];
const PEM_MARKER: &[u8] = b"-----BEGIN ";
const PRIVATE_PEM_LABELS: [&str; 4] = [
    "PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
];
const PEM_LABELS_HINT: &str = "supported PEM blocks: PRIVATE KEY, ENCRYPTED PRIVATE KEY, RSA/EC PRIVATE KEY, PUBLIC KEY, CERTIFICATE, CERTIFICATE REQUEST";
const ATTEMPTED: &str =
    "PEM, DER (PKCS#8, SPKI, PKCS#1, SEC1, X.509, CSR, PKCS#12), raw AES (16/24/32 bytes)";
const PASSWORD_HINT: &str =
    "provide --password or run interactively so the password can be prompted";
const WRONG_KEY_PASSWORD: &str =
    "incorrect password for encrypted private key (or corrupt encrypted data)";
const WRONG_P12_PASSWORD: &str = "incorrect password for PKCS#12 (or corrupt PKCS#12 data)";
const UNSUPPORTED_HINT: &str = "supported: AES, RSA, EC, Ed25519/Ed448, X25519/X448";
const EXPLICIT_CURVE_TEXT: &str = "ECDSA keys with explicit parameters are only supported when they map to secp256r1, secp384r1, or secp521r1. No custom curves are supported.";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The detail text appended to a c2 prefix where c2 appended a pyca exception text (§11
/// D11): the reason of the first OpenSSL error, never the build-specific `Display`.
pub(crate) fn ossl_detail(err: &ErrorStack) -> String {
    err.errors()
        .first()
        .and_then(|e| e.reason())
        .map_or_else(|| "unknown error".to_owned(), str::to_owned)
}

fn wrong_key_password() -> ConsoleError {
    ConsoleError::key_parse(WRONG_KEY_PASSWORD)
}

/// c2 `_ask_password`: the callback's answer as UTF-8 bytes, or the "requires a password"
/// error without a callback.
fn ask_password(
    password: &mut Option<PasswordCallback<'_>>,
    prompt: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let Some(callback) = password.as_mut() else {
        return Err(
            ConsoleError::key_parse("encrypted key material requires a password")
                .with_hint(PASSWORD_HINT),
        );
    };
    let secret = callback(prompt)?;
    Ok(Zeroizing::new(secret.expose_secret().as_bytes().to_vec()))
}

/// OpenSSL password callback that fills in `password` (one call; OpenSSL caches it).
fn fill_password(
    password: &[u8],
) -> impl FnOnce(&mut [u8]) -> std::result::Result<usize, ErrorStack> + '_ {
    move |buf: &mut [u8]| {
        let n = password.len().min(buf.len());
        buf[..n].copy_from_slice(&password[..n]);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------------------
// Classification and pyca normalization (shared with x509build / x509info / formats)
// ---------------------------------------------------------------------------------------

/// pyca 49's curves: (OpenSSL NID, c2 curve).
fn curve_for_nid(nid: Nid) -> Option<Curve> {
    let other = |name: &str| Some(Curve::Other(name.to_owned()));
    match nid {
        Nid::X9_62_PRIME256V1 => Some(Curve::P256),
        Nid::SECP384R1 => Some(Curve::P384),
        Nid::SECP521R1 => Some(Curve::P521),
        Nid::X9_62_PRIME192V1 => other("secp192r1"),
        Nid::SECP224R1 => other("secp224r1"),
        Nid::SECP256K1 => other("secp256k1"),
        Nid::BRAINPOOL_P256R1 => other("brainpoolp256r1"),
        Nid::BRAINPOOL_P384R1 => other("brainpoolp384r1"),
        Nid::BRAINPOOL_P512R1 => other("brainpoolp512r1"),
        _ => None,
    }
}

/// (algorithm, curve, size_bits) of a normalized key, per c2 classifier (§4.4.3/§4.4.5).
pub(crate) fn classify_key<T: HasPublic>(
    pkey: &PKeyRef<T>,
    classifier: Classifier,
    private: bool,
) -> Result<(KeyAlgorithm, Option<Curve>, Option<u32>)> {
    let id = pkey.id();
    let unsupported = |base: &str| match classifier {
        Classifier::KeyParse => {
            let kind = if private { "Private" } else { "Public" };
            ConsoleError::key_parse(format!("unsupported key algorithm: {base}{kind}Key"))
                .with_hint(UNSUPPORTED_HINT)
        }
        Classifier::Pkcs11 => {
            ConsoleError::key_parse(format!("unsupported public key type {base}PublicKey"))
        }
    };
    match id {
        Id::RSA | Id::RSA_PSS => {
            let bits = pkey.rsa().ok().map(|rsa| rsa.n().num_bits());
            let bits = bits.and_then(|b| u32::try_from(b).ok());
            Ok((KeyAlgorithm::Rsa, None, bits))
        }
        Id::EC => {
            let curve = pkey
                .ec_key()
                .ok()
                .and_then(|ec| ec.group().curve_name())
                .and_then(curve_for_nid);
            let curve = match classifier {
                Classifier::KeyParse => curve,
                Classifier::Pkcs11 => {
                    curve.filter(|c| matches!(c, Curve::P256 | Curve::P384 | Curve::P521))
                }
            };
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

/// The dotted curve OID of an EC SPKI's named-curve parameter (pyca's "Curve {oid} is not
/// supported" text).
fn spki_curve_oid(spki: &[u8]) -> Option<String> {
    let (seq, _) = x509info::read_tlv(spki).ok()?;
    let (alg, _) = x509info::read_tlv(seq.content).ok()?;
    let (alg_oid, rest) = x509info::read_tlv(alg.content).ok()?;
    if alg_oid.content != OID_EC_PUBLIC_KEY {
        return None;
    }
    let (param, _) = x509info::read_tlv(rest).ok()?;
    (param.tag == 0x06)
        .then(|| x509info::oid_dotted(param.content))
        .flatten()
}

/// id-ecPublicKey (1.2.840.10045.2.1).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// pyca's refusal of a key type outside its set: EC keys on other curves (OpenSSL types
/// some, e.g. SM2, by their curve) name the curve; anything else is an unsupported type.
fn unsupported_type<T: HasPublic>(pkey: &PKeyRef<T>) -> String {
    pkey.public_key_to_der()
        .ok()
        .and_then(|spki| spki_curve_oid(&spki))
        .map_or_else(
            || "Unsupported key type.".to_owned(),
            |oid| format!("Curve {oid} is not supported"),
        )
}

fn unsupported_curve<T: HasPublic>(pkey: &PKeyRef<T>) -> String {
    let oid = pkey
        .public_key_to_der()
        .ok()
        .and_then(|spki| spki_curve_oid(&spki))
        .unwrap_or_else(|| "unknown".to_owned());
    format!("Curve {oid} is not supported")
}

fn same_group(a: &EcGroupRef, b: &EcGroupRef) -> std::result::Result<bool, ErrorStack> {
    let mut ctx = BigNumContext::new()?;
    let (mut pa, mut aa, mut ba) = (BigNum::new()?, BigNum::new()?, BigNum::new()?);
    let (mut pb, mut ab, mut bb) = (BigNum::new()?, BigNum::new()?, BigNum::new()?);
    if a.components_gfp(&mut pa, &mut aa, &mut ba, &mut ctx)
        .is_err()
    {
        return Ok(false);
    }
    b.components_gfp(&mut pb, &mut ab, &mut bb, &mut ctx)?;
    if pa != pb || aa != ab || ba != bb {
        return Ok(false);
    }
    let (mut oa, mut ob) = (BigNum::new()?, BigNum::new()?);
    a.order(&mut oa, &mut ctx)?;
    b.order(&mut ob, &mut ctx)?;
    let (mut ca, mut cb) = (BigNum::new()?, BigNum::new()?);
    a.cofactor(&mut ca, &mut ctx)?;
    b.cofactor(&mut cb, &mut ctx)?;
    if oa != ob || ca != cb {
        return Ok(false);
    }
    let (Some(ga), Some(gb)) = (a.generator_opt(), b.generator_opt()) else {
        return Ok(false);
    };
    let (mut xa, mut ya, mut xb, mut yb) = (
        BigNum::new()?,
        BigNum::new()?,
        BigNum::new()?,
        BigNum::new()?,
    );
    ga.affine_coordinates(a, &mut xa, &mut ya, &mut ctx)?;
    gb.affine_coordinates(b, &mut xb, &mut yb, &mut ctx)?;
    Ok(xa == xb && ya == yb)
}

/// The named group pyca accepts for an EC key, or pyca's refusal text.
fn pyca_ec_nid<T: HasPublic>(
    pkey: &PKeyRef<T>,
    group: &EcGroupRef,
) -> std::result::Result<Nid, String> {
    if group.asn1_flag() == Asn1Flag::EXPLICIT_CURVE || group.curve_name().is_none() {
        for nid in [Nid::X9_62_PRIME256V1, Nid::SECP384R1, Nid::SECP521R1] {
            let named = EcGroup::from_curve_name(nid).map_err(|e| ossl_detail(&e))?;
            if same_group(group, &named).map_err(|e| ossl_detail(&e))? {
                return Ok(nid);
            }
        }
        return Err(EXPLICIT_CURVE_TEXT.to_owned());
    }
    match group.curve_name() {
        Some(nid) if curve_for_nid(nid).is_some() => Ok(nid),
        _ => Err(unsupported_curve(pkey)),
    }
}

/// The key's public point on the named group `nid` (uncompressed round trip).
fn point_on(
    nid: Nid,
    ec_group: &EcGroupRef,
    point: &openssl::ec::EcPointRef,
) -> std::result::Result<(EcGroup, EcPoint), ErrorStack> {
    let group = EcGroup::from_curve_name(nid)?;
    let mut ctx = BigNumContext::new()?;
    let bytes = point.to_bytes(ec_group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
    let point = EcPoint::from_bytes(&group, &bytes, &mut ctx)?;
    Ok((group, point))
}

/// pyca's private-key acceptance on top of an OpenSSL key (`Err` = pyca's error text):
/// RSA-PSS → rsaEncryption RSA, RSA consistency check, EC on a supported (named) curve with
/// an uncompressed point, Ed/X/DSA/DH unchanged, anything else unsupported.
pub(crate) fn normalize_private(pkey: PKey<Private>) -> std::result::Result<PKey<Private>, String> {
    let detail = |e: ErrorStack| ossl_detail(&e);
    match pkey.id() {
        Id::RSA | Id::RSA_PSS => {
            let rsa = pkey.rsa().map_err(detail)?;
            if !rsa.check_key().unwrap_or(false) {
                return Err("Invalid private key".to_owned());
            }
            if pkey.id() == Id::RSA {
                return Ok(pkey);
            }
            let rebuilt = match (rsa.p(), rsa.q(), rsa.dmp1(), rsa.dmq1(), rsa.iqmp()) {
                (Some(p), Some(q), Some(dp), Some(dq), Some(qi)) => Rsa::from_private_components(
                    rsa.n().to_owned().map_err(detail)?,
                    rsa.e().to_owned().map_err(detail)?,
                    rsa.d().to_owned().map_err(detail)?,
                    p.to_owned().map_err(detail)?,
                    q.to_owned().map_err(detail)?,
                    dp.to_owned().map_err(detail)?,
                    dq.to_owned().map_err(detail)?,
                    qi.to_owned().map_err(detail)?,
                )
                .map_err(detail)?,
                _ => return Err("Invalid private key".to_owned()),
            };
            PKey::from_rsa(rebuilt).map_err(detail)
        }
        Id::EC => {
            let ec = pkey.ec_key().map_err(detail)?;
            let nid = pyca_ec_nid(&pkey, ec.group())?;
            let (group, point) = point_on(nid, ec.group(), ec.public_key()).map_err(detail)?;
            let key =
                EcKey::from_private_components(&group, ec.private_key(), &point).map_err(detail)?;
            if key.check_key().is_err() {
                return Err("Invalid EC key.".to_owned());
            }
            PKey::from_ec_key(key).map_err(detail)
        }
        Id::ED25519 | Id::ED448 | Id::X25519 | Id::X448 | Id::DSA | Id::DH | Id::DHX => Ok(pkey),
        _ => Err(unsupported_type(&pkey)),
    }
}

/// pyca's public-key acceptance (see `normalize_private`).
pub(crate) fn normalize_public(pkey: PKey<Public>) -> std::result::Result<PKey<Public>, String> {
    let detail = |e: ErrorStack| ossl_detail(&e);
    match pkey.id() {
        Id::RSA => Ok(pkey),
        Id::RSA_PSS => {
            let rsa = pkey.rsa().map_err(detail)?;
            let rebuilt = Rsa::from_public_components(
                rsa.n().to_owned().map_err(detail)?,
                rsa.e().to_owned().map_err(detail)?,
            )
            .map_err(detail)?;
            PKey::from_rsa(rebuilt).map_err(detail)
        }
        Id::EC => {
            let ec = pkey.ec_key().map_err(detail)?;
            let nid = pyca_ec_nid(&pkey, ec.group())?;
            let (group, point) = point_on(nid, ec.group(), ec.public_key()).map_err(detail)?;
            let key = EcKey::from_public_key(&group, &point).map_err(detail)?;
            if key.check_key().is_err() {
                return Err("Invalid EC key.".to_owned());
            }
            PKey::from_ec_key(key).map_err(detail)
        }
        Id::ED25519 | Id::ED448 | Id::X25519 | Id::X448 | Id::DSA | Id::DH | Id::DHX => Ok(pkey),
        _ => Err(unsupported_type(&pkey)),
    }
}

/// Outcome of pyca `load_der_private_key(data, password=None)`.
pub(crate) enum PrivateLoadError {
    /// pyca TypeError "Password was not given but private key is encrypted".
    Encrypted,
    /// pyca ValueError / UnsupportedAlgorithm: the detail text.
    Invalid(String),
}

/// pyca `load_der_private_key(data, None)` (PKCS#8 / PKCS#1 / SEC1), normalized.
pub(crate) fn load_private_der(
    data: &[u8],
) -> std::result::Result<PKey<Private>, PrivateLoadError> {
    match PKey::private_key_from_der(data) {
        Ok(pkey) => normalize_private(pkey).map_err(PrivateLoadError::Invalid),
        Err(err) => {
            if is_encrypted_pkcs8(data) {
                Err(PrivateLoadError::Encrypted)
            } else {
                Err(PrivateLoadError::Invalid(ossl_detail(&err)))
            }
        }
    }
}

/// The EncryptedPrivateKeyInfo probe: OpenSSL asks for a password only for encrypted
/// PKCS#8 (the callback answers with an empty password; only the "asked" flag counts).
fn is_encrypted_pkcs8(data: &[u8]) -> bool {
    let asked = Cell::new(false);
    let _probe = PKey::private_key_from_pkcs8_callback(data, |_buf: &mut [u8]| {
        asked.set(true);
        Ok(0)
    });
    asked.get()
}

/// pyca `load_der_public_key`: SPKI, or a PKCS#1 RSAPublicKey; normalized.
pub(crate) fn load_public_der(data: &[u8]) -> std::result::Result<PKey<Public>, String> {
    match PKey::public_key_from_der(data) {
        Ok(pkey) => normalize_public(pkey),
        Err(err) => Rsa::public_key_from_der_pkcs1(data)
            .and_then(PKey::from_rsa)
            .map_err(|_| ossl_detail(&err)),
    }
}

// ---------------------------------------------------------------------------------------
// Materials
// ---------------------------------------------------------------------------------------

fn private_material(pkey: &PKey<Private>, label_hint: Option<String>) -> Result<KeyMaterial> {
    let (algorithm, curve, size_bits) = classify_key(pkey, Classifier::KeyParse, true)?;
    let data = Zeroizing::new(pkey.private_key_to_pkcs8().map_err(|err| {
        ConsoleError::key_parse(format!(
            "private key cannot be encoded as PKCS#8: {}",
            ossl_detail(&err)
        ))
    })?);
    Ok(KeyMaterial {
        algorithm,
        key_class: KeyClass::Private,
        data,
        curve,
        size_bits,
        label_hint,
    })
}

fn public_material(pkey: &PKey<Public>, label_hint: Option<String>) -> Result<KeyMaterial> {
    let (algorithm, curve, size_bits) = classify_key(pkey, Classifier::KeyParse, false)?;
    let data = pkey.public_key_to_der().map_err(|err| {
        ConsoleError::key_parse(format!(
            "public key cannot be encoded as SubjectPublicKeyInfo: {}",
            ossl_detail(&err)
        ))
    })?;
    Ok(KeyMaterial {
        algorithm,
        key_class: KeyClass::Public,
        data: Zeroizing::new(data),
        curve,
        size_bits,
        label_hint,
    })
}

fn subject_cn_of(name_der: std::result::Result<Vec<u8>, ErrorStack>) -> Option<String> {
    name_der
        .ok()
        .and_then(|der| x509info::first_common_name(&der))
}

/// c2 `_cert_material`: the certificate's public key classifies the material; `data` = DER.
fn cert_material(cert: &openssl::x509::X509Ref, label_hint: Option<String>) -> Result<KeyMaterial> {
    let invalid = |detail: &str| {
        ConsoleError::key_parse(format!(
            "certificate contains an invalid public key: {detail}"
        ))
    };
    let pkey = cert
        .public_key()
        .map_err(|err| invalid(&ossl_detail(&err)))?;
    let pkey = normalize_public(pkey).map_err(|detail| invalid(&detail))?;
    let (algorithm, curve, size_bits) = classify_key(&pkey, Classifier::KeyParse, false)?;
    let label_hint = match label_hint {
        Some(label) => Some(label),
        None => subject_cn_of(cert.subject_name().to_der()),
    };
    let der = cert.to_der().map_err(|err| {
        ConsoleError::key_parse(format!(
            "certificate is not valid DER X.509: {}",
            ossl_detail(&err)
        ))
    })?;
    Ok(KeyMaterial {
        algorithm,
        key_class: KeyClass::Certificate,
        data: Zeroizing::new(der),
        curve,
        size_bits,
        label_hint,
    })
}

/// c2 `_csr_material`: the CSR's public key as a PUBLIC material, label = subject CN.
fn csr_material(req: &X509Req) -> Result<KeyMaterial> {
    let invalid = |detail: &str| {
        ConsoleError::key_parse(format!(
            "certificate request contains an invalid public key: {detail}"
        ))
    };
    let pkey = req
        .public_key()
        .map_err(|err| invalid(&ossl_detail(&err)))?;
    let pkey = normalize_public(pkey).map_err(|detail| invalid(&detail))?;
    public_material(&pkey, subject_cn_of(req.subject_name().to_der()))
}

/// OpenSSL + pyca-strict certificate load (pyca's parser is strict DER and checks Name
/// values at load).
fn load_cert_der(der: &[u8]) -> std::result::Result<X509, String> {
    let cert = X509::from_der(der).map_err(|err| ossl_detail(&err))?;
    x509info::load_certificate(der)?;
    Ok(cert)
}

fn load_csr_der(der: &[u8]) -> std::result::Result<X509Req, String> {
    let req = X509Req::from_der(der).map_err(|err| ossl_detail(&err))?;
    x509info::load_csr(der)?;
    Ok(req)
}

// ---------------------------------------------------------------------------------------
// PEM
// ---------------------------------------------------------------------------------------

/// One `_PEM_BLOCK_RE` match: labels (unstripped) and the whole block text.
struct PemMatch<'a> {
    begin: &'a str,
    end: &'a str,
    text: &'a str,
}

fn is_label_start(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn is_label_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b' '
}

/// `[A-Za-z0-9][A-Za-z0-9 ]*?-----` at `pos`: the label end (exclusive) when it matches.
fn label_at(bytes: &[u8], pos: usize) -> Option<usize> {
    if !bytes.get(pos).copied().is_some_and(is_label_start) {
        return None;
    }
    let mut end = pos + 1;
    while bytes.get(end).copied().is_some_and(is_label_char) {
        end += 1;
    }
    bytes[end..].starts_with(b"-----").then_some(end)
}

/// Port of c2's `_PEM_BLOCK_RE.finditer` (`-----BEGIN (L)-----.*?-----END (L)-----`, DOTALL,
/// labels lazy, leftmost-first, non-overlapping).
fn find_pem_blocks(text: &str) -> Vec<PemMatch<'_>> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(offset) = text.get(pos..).and_then(|rest| rest.find("-----BEGIN ")) {
        let start = pos + offset;
        let label_start = start + "-----BEGIN ".len();
        let matched = label_at(bytes, label_start).and_then(|label_end| {
            let body_start = label_end + 5;
            let mut search = body_start;
            while let Some(found) = text.get(search..).and_then(|rest| rest.find("-----END ")) {
                let end_marker = search + found;
                let end_label_start = end_marker + "-----END ".len();
                if let Some(end_label_end) = label_at(bytes, end_label_start) {
                    return Some(PemMatch {
                        begin: &text[label_start..label_end],
                        end: &text[end_label_start..end_label_end],
                        text: &text[start..end_label_end + 5],
                    });
                }
                search = end_marker + 1;
            }
            None
        });
        match matched {
            Some(m) => {
                pos = start + m.text.len();
                out.push(m);
            }
            None => pos = start + 1,
        }
    }
    out
}

/// A decoded PEM block: RFC 1421 headers (name, value) and the DER body.
struct PemBody {
    headers: Vec<(String, String)>,
    der: Zeroizing<Vec<u8>>,
}

/// Decode the text between the BEGIN and END lines: leading `Name: value` header lines up
/// to the first blank line, then the base64 body (whitespace ignored).
fn decode_pem_body(block: &str) -> std::result::Result<PemBody, String> {
    // `block` is one `find_pem_blocks` match: "-----BEGIN <label>-----" … "-----END <label>-----".
    let after_begin = "-----BEGIN ".len();
    let inner_start = block
        .get(after_begin..)
        .and_then(|rest| rest.find("-----"))
        .map_or(block.len(), |i| after_begin + i + 5);
    let inner_end = block.rfind("-----END ").unwrap_or(block.len());
    let inner = block
        .get(inner_start.min(inner_end)..inner_end)
        .unwrap_or("");
    let mut headers = Vec::new();
    let mut body = Zeroizing::new(String::new());
    let mut in_headers = true;
    for line in inner.split('\n') {
        let line = line.trim_matches(|c: char| c.is_ascii_whitespace());
        if in_headers {
            if line.is_empty() {
                if !headers.is_empty() {
                    in_headers = false;
                }
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_owned(), value.trim().to_owned()));
                continue;
            }
            in_headers = false;
        }
        body.extend(line.chars().filter(|c| !c.is_ascii_whitespace()));
    }
    let der = STANDARD
        .decode(body.as_bytes())
        .map_err(|err| err.to_string())?;
    Ok(PemBody {
        headers,
        der: Zeroizing::new(der),
    })
}

fn parse_pem(data: &[u8], password: &mut Option<PasswordCallback<'_>>) -> Result<Vec<KeyMaterial>> {
    let text = std::str::from_utf8(data)
        .map_err(|_| ConsoleError::key_parse("data contains a PEM marker but is not valid text"))?;
    let matches = find_pem_blocks(text);
    if matches.is_empty() {
        return Err(ConsoleError::key_parse("no complete PEM block found")
            .with_hint("a PEM block is '-----BEGIN <LABEL>----- … -----END <LABEL>-----'"));
    }
    let mut materials = Vec::with_capacity(matches.len());
    for m in matches {
        let begin = m.begin.trim_matches(' ');
        let end = m.end.trim_matches(' ');
        if begin != end {
            return Err(ConsoleError::key_parse(format!(
                "PEM block 'BEGIN {begin}' is closed by 'END {end}'"
            )));
        }
        let malformed = |detail: &str| {
            ConsoleError::key_parse(format!("malformed {begin} PEM block: {detail}"))
        };
        if PRIVATE_PEM_LABELS.contains(&begin) {
            materials.push(parse_pem_private(m.text, begin, password)?);
            continue;
        }
        match begin {
            "PUBLIC KEY" => {
                let body = decode_pem_body(m.text).map_err(|d| malformed(&d))?;
                let pkey = PKey::public_key_from_der(&body.der)
                    .map_err(|err| ossl_detail(&err))
                    .and_then(normalize_public)
                    .map_err(|d| malformed(&d))?;
                materials.push(public_material(&pkey, None)?);
            }
            "CERTIFICATE" => {
                let body = decode_pem_body(m.text).map_err(|d| malformed(&d))?;
                let cert = load_cert_der(&body.der).map_err(|d| malformed(&d))?;
                materials.push(cert_material(&cert, None)?);
            }
            "CERTIFICATE REQUEST" => {
                let body = decode_pem_body(m.text).map_err(|d| malformed(&d))?;
                let req = load_csr_der(&body.der).map_err(|d| malformed(&d))?;
                materials.push(csr_material(&req)?);
            }
            other => {
                return Err(ConsoleError::key_parse(format!(
                    "unsupported PEM block type {}",
                    py_repr(other)
                ))
                .with_hint(PEM_LABELS_HINT));
            }
        }
    }
    Ok(materials)
}

/// pyca's traditional-PEM ciphers (`DEK-Info`); anything else fails after the prompt.
fn traditional_cipher(name: &str) -> Option<Cipher> {
    match name {
        "AES-128-CBC" => Some(Cipher::aes_128_cbc()),
        "AES-256-CBC" => Some(Cipher::aes_256_cbc()),
        "DES-EDE3-CBC" => Some(Cipher::des_ede3_cbc()),
        _ => None,
    }
}

/// The label-specific unencrypted DER loader of pyca's PEM private-key parser.
fn load_private_by_label(der: &[u8], label: &str) -> std::result::Result<PKey<Private>, String> {
    let detail = |e: ErrorStack| ossl_detail(&e);
    let pkey = match label {
        "RSA PRIVATE KEY" => Rsa::private_key_from_der(der)
            .and_then(PKey::from_rsa)
            .map_err(detail)?,
        "EC PRIVATE KEY" => EcKey::private_key_from_der(der)
            .and_then(PKey::from_ec_key)
            .map_err(detail)?,
        _ => PKey::private_key_from_pkcs8(der).map_err(detail)?,
    };
    normalize_private(pkey)
}

/// Traditional (RFC 1421) decryption: EVP_BytesToKey(MD5, salt = IV[..8], count 1) + CBC.
fn decrypt_traditional(
    body: &PemBody,
    password: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, ()> {
    let dek = body
        .headers
        .iter()
        .find(|(name, _)| name == "DEK-Info")
        .map(|(_, value)| value.as_str())
        .ok_or(())?;
    let (cipher_name, iv_hex) = dek.split_once(',').ok_or(())?;
    let cipher = traditional_cipher(cipher_name.trim()).ok_or(())?;
    let iv = hex::decode(iv_hex.trim()).map_err(|_| ())?;
    if iv.len() != cipher.iv_len().unwrap_or(0) || iv.len() < 8 {
        return Err(());
    }
    let pair =
        openssl::pkcs5::bytes_to_key(cipher, MessageDigest::md5(), password, Some(&iv[..8]), 1)
            .map_err(|_| ())?;
    let key = Zeroizing::new(pair.key);
    openssl::symm::decrypt(cipher, &key, Some(&iv), &body.der)
        .map(Zeroizing::new)
        .map_err(|_| ())
}

fn parse_pem_private(
    block: &str,
    label: &str,
    password: &mut Option<PasswordCallback<'_>>,
) -> Result<KeyMaterial> {
    let malformed =
        |detail: &str| ConsoleError::key_parse(format!("malformed {label} PEM block: {detail}"));
    let body = decode_pem_body(block).map_err(|d| malformed(&d))?;
    if label == "ENCRYPTED PRIVATE KEY" {
        // pyca asks for the password only when the body is an EncryptedPrivateKeyInfo.
        if !is_encrypted_pkcs8(&body.der) {
            let detail = PKey::private_key_from_pkcs8(&body.der).err().map_or_else(
                || "not an EncryptedPrivateKeyInfo".to_owned(),
                |e| ossl_detail(&e),
            );
            return Err(malformed(&detail));
        }
        let secret = ask_password(password, &format!("Password for encrypted {label}"))?;
        let pkey = decrypt_pkcs8(&body.der, &secret).ok_or_else(wrong_key_password)?;
        return private_material(&pkey, None);
    }
    let traditional_encrypted = label != "PRIVATE KEY"
        && body
            .headers
            .iter()
            .any(|(name, value)| name == "Proc-Type" && value.replace(' ', "") == "4,ENCRYPTED");
    if traditional_encrypted {
        ensure_legacy_provider();
        let secret = ask_password(password, &format!("Password for encrypted {label}"))?;
        let der = decrypt_traditional(&body, &secret).map_err(|()| wrong_key_password())?;
        let pkey = load_private_by_label(&der, label).map_err(|_| wrong_key_password())?;
        return private_material(&pkey, None);
    }
    let pkey = load_private_by_label(&body.der, label).map_err(|d| malformed(&d))?;
    private_material(&pkey, None)
}

// ---------------------------------------------------------------------------------------
// Encrypted PKCS#8 (pyca's supported schemes)
// ---------------------------------------------------------------------------------------

const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
const OID_PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
const OID_SCRYPT: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x04, 0x0b];
/// PBES1 schemes pyca decrypts: pbeWithMD5AndDES-CBC, pbeWithSHAAnd128BitRC4,
/// pbeWithSHAAnd3-KeyTripleDES-CBC, pbeWithSHAAnd40BitRC2-CBC.
const PBES1_OK: [&[u8]; 4] = [
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x03],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x01],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x06],
];
/// PBKDF2 PRFs pyca accepts: hmacWithSHA1/224/256/384/512.
const PRF_OK: [&[u8]; 5] = [
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x08],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b],
];
/// PBES2 ciphers pyca accepts: aes128/192/256-cbc, des-ede3-cbc, rc2-cbc.
const PBES2_CIPHER_OK: [&[u8]; 5] = [
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02],
];

/// (OID content, parameters) of an AlgorithmIdentifier TLV content.
fn algorithm_identifier(content: &[u8]) -> Option<(&[u8], &[u8])> {
    let (oid, rest) = x509info::read_tlv(content).ok()?;
    (oid.tag == 0x06).then_some((oid.content, rest))
}

/// False when the EncryptedPrivateKeyInfo names a scheme pyca does not decrypt ("Unknown key
/// encryption algorithm", which c2 reports as a wrong password); true when supported or
/// unparseable (OpenSSL then decides).
fn pkcs8_scheme_supported(der: &[u8]) -> bool {
    let check = || -> Option<bool> {
        let (epki, _) = x509info::read_tlv(der).ok()?;
        let (alg, _) = x509info::read_tlv(epki.content).ok()?;
        let (oid, params) = algorithm_identifier(alg.content)?;
        if PBES1_OK.contains(&oid) {
            return Some(true);
        }
        if oid != OID_PBES2 {
            return Some(false);
        }
        let (pbes2, _) = x509info::read_tlv(params).ok()?;
        let (kdf, rest) = x509info::read_tlv(pbes2.content).ok()?;
        let (enc, _) = x509info::read_tlv(rest).ok()?;
        let (kdf_oid, kdf_params) = algorithm_identifier(kdf.content)?;
        if kdf_oid == OID_PBKDF2 {
            // PBKDF2-params ::= SEQUENCE { salt, iterationCount, keyLength OPTIONAL, prf DEFAULT sha1 }
            let (seq, _) = x509info::read_tlv(kdf_params).ok()?;
            let mut items = seq.content;
            while !items.is_empty() {
                let (item, next) = x509info::read_tlv(items).ok()?;
                items = next;
                if item.tag == 0x30 {
                    let (prf, _) = algorithm_identifier(item.content)?;
                    if !PRF_OK.contains(&prf) {
                        return Some(false);
                    }
                }
            }
        } else if kdf_oid != OID_SCRYPT {
            return Some(false);
        }
        let (enc_oid, _) = algorithm_identifier(enc.content)?;
        Some(PBES2_CIPHER_OK.contains(&enc_oid))
    };
    check().unwrap_or(true)
}

/// Decrypt an EncryptedPrivateKeyInfo with pyca's scheme set; None = c2's wrong-password
/// path (bad password, unsupported scheme, corrupt data, or a key pyca refuses).
fn decrypt_pkcs8(der: &[u8], password: &[u8]) -> Option<PKey<Private>> {
    ensure_legacy_provider();
    if !pkcs8_scheme_supported(der) {
        return None;
    }
    let pkey = PKey::private_key_from_pkcs8_callback(der, fill_password(password)).ok()?;
    normalize_private(pkey).ok()
}

// ---------------------------------------------------------------------------------------
// DER try-chain and PKCS#12
// ---------------------------------------------------------------------------------------

fn parse_der(
    data: &[u8],
    password: &mut Option<PasswordCallback<'_>>,
) -> Result<Option<Vec<KeyMaterial>>> {
    // 1. PKCS#8 / PKCS#1 / SEC1
    if let Ok(pkey) = PKey::private_key_from_der(data)
        && let Ok(pkey) = normalize_private(pkey)
    {
        return Ok(Some(vec![private_material(&pkey, None)?]));
    }
    // 2. EncryptedPrivateKeyInfo (the callback fires only for encrypted PKCS#8)
    if is_encrypted_pkcs8(data) {
        let secret = ask_password(password, "Password for encrypted private key")?;
        let pkey = decrypt_pkcs8(data, &secret).ok_or_else(wrong_key_password)?;
        return Ok(Some(vec![private_material(&pkey, None)?]));
    }
    // 3. SPKI, 4. PKCS#1 RSAPublicKey
    if let Ok(pkey) = PKey::public_key_from_der(data) {
        if let Ok(pkey) = normalize_public(pkey) {
            return Ok(Some(vec![public_material(&pkey, None)?]));
        }
    } else if let Ok(pkey) = Rsa::public_key_from_der_pkcs1(data).and_then(PKey::from_rsa) {
        return Ok(Some(vec![public_material(&pkey, None)?]));
    }
    // 5. X.509, 6. CSR
    if let Ok(cert) = load_cert_der(data) {
        return Ok(Some(vec![cert_material(&cert, None)?]));
    }
    if let Ok(req) = load_csr_der(data) {
        return Ok(Some(vec![csr_material(&req)?]));
    }
    // 7. PKCS#12
    if looks_like_pkcs12(data) {
        return parse_pkcs12(data, password).map(Some);
    }
    Ok(None)
}

/// c2 `_looks_like_pkcs12`: `SEQUENCE { INTEGER 3, … }`.
fn looks_like_pkcs12(data: &[u8]) -> bool {
    if data.len() < 5 || data[0] != 0x30 {
        return false;
    }
    let offset = if data[1] & 0x80 != 0 {
        2 + usize::from(data[1] & 0x7f)
    } else {
        2
    };
    data.get(offset..)
        .is_some_and(|rest| rest.starts_with(&[0x02, 0x01, 0x03]))
}

fn parse_pkcs12(
    data: &[u8],
    password: &mut Option<PasswordCallback<'_>>,
) -> Result<Vec<KeyMaterial>> {
    ensure_legacy_provider();
    let p12 = Pkcs12::from_der(data).ok();
    let parsed = match p12.as_ref().and_then(|p12| p12.parse2("").ok()) {
        Some(parsed) => parsed,
        None => {
            let Some(callback) = password.as_mut() else {
                return Err(ConsoleError::key_parse(
                    "PKCS#12 requires a password (or the PKCS#12 data is corrupt)",
                )
                .with_hint(PASSWORD_HINT));
            };
            let secret = callback("Password for PKCS#12")?;
            let wrong = || ConsoleError::key_parse(WRONG_P12_PASSWORD);
            let secret = secret.expose_secret();
            // Pkcs12::parse2 would panic on an interior NUL (CString); c2's answer is the
            // wrong-password text (§11 D16).
            if secret.contains('\0') {
                return Err(wrong());
            }
            p12.as_ref()
                .ok_or_else(wrong)?
                .parse2(secret)
                .map_err(|_| wrong())?
        }
    };
    let label_hint = parsed.cert.as_ref().and_then(|cert| match cert.alias() {
        Some(alias) => Some(String::from_utf8_lossy(alias).into_owned()),
        None => subject_cn_of(cert.subject_name().to_der()),
    });
    let mut materials = Vec::new();
    if let Some(pkey) = parsed.pkey {
        let pkey = normalize_private(pkey).map_err(|detail| {
            ConsoleError::key_parse(format!(
                "PKCS#12 contains an unsupported private key: {detail}"
            ))
        })?;
        materials.push(private_material(&pkey, label_hint.clone())?);
    }
    if let Some(cert) = parsed.cert.as_ref() {
        materials.push(cert_material(cert, label_hint.clone())?);
    }
    if let Some(chain) = parsed.ca.as_ref() {
        for cert in chain {
            materials.push(cert_material(cert, label_hint.clone())?);
        }
    }
    if materials.is_empty() {
        return Err(ConsoleError::key_parse(
            "PKCS#12 contains no key or certificates",
        ));
    }
    Ok(materials)
}

fn check_hint(materials: &[KeyMaterial], hint: KeyHint) -> Result<()> {
    for material in materials {
        let ok = match hint {
            KeyHint::Cert => material.key_class == KeyClass::Certificate,
            KeyHint::Aes => material.algorithm == KeyAlgorithm::Aes,
            KeyHint::Rsa => material.algorithm == KeyAlgorithm::Rsa,
            KeyHint::Ec | KeyHint::Auto => material.algorithm.is_ec_family(),
        };
        if !ok {
            return Err(ConsoleError::key_parse(format!(
                "parsed {} {} material but hint is {}",
                material.algorithm.as_str(),
                material.key_class.as_str(),
                py_repr(hint.as_str())
            ))
            .with_hint("use hint='auto' or the hint matching the pasted material"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_regex_port_matches_python_semantics() {
        let blocks = find_pem_blocks("x-----BEGIN A-----body-----END B----------END A-----y");
        assert_eq!(blocks.len(), 1);
        assert_eq!((blocks[0].begin, blocks[0].end), ("A", "B"));
        let blocks = find_pem_blocks(
            "-----BEGIN -----x-----END A----- -----BEGIN B C -----z-----END !----- -----END B -----",
        );
        assert_eq!(blocks.len(), 1);
        assert_eq!((blocks[0].begin, blocks[0].end), ("B C ", "B "));
        assert!(find_pem_blocks("-----BEGIN A-----AAAA").is_empty());
        let two =
            find_pem_blocks("-----BEGIN A-----1-----END A----------BEGIN B-----2-----END B-----");
        assert_eq!(two.len(), 2);
        assert_eq!(two[1].text, "-----BEGIN B-----2-----END B-----");
    }

    #[test]
    fn pkcs12_sniff_is_c2s() {
        assert!(looks_like_pkcs12(b"\x30\x82\x01\x00\x02\x01\x03"));
        assert!(looks_like_pkcs12(b"\x30\x10\x02\x01\x03"));
        assert!(!looks_like_pkcs12(b"\x30\x10\x02\x01"));
        assert!(!looks_like_pkcs12(b"\x30\x10\x02\x01\x02"));
        assert!(!looks_like_pkcs12(b"\x31\x10\x02\x01\x03"));
        assert!(!looks_like_pkcs12(b"\x30\x85\x02\x01\x03"));
    }
}
