//! Key material parsing (spec §4.4.3, §5.4; owner R6): bytes → `Vec<KeyMaterial>`.
//!
//! Port of c2 `core/keyparse.py`. Key material is read the way pyca 49 reads it: its own
//! parsers (`cryptography-key-parsing`: PKCS#8, SEC1, PKCS#1, DSA, SPKI, encrypted PKCS#8)
//! are ported over x509info's rust-asn1 reader, and keys are built from their components
//! with OpenSSL (OpenSSL's key decoders are never used), so pyca's structure and version
//! checks, its curve set (explicit parameters only when they are P-256/P-384/P-521), its
//! RSA/EC key checks and its encryption schemes apply. Passwords come through the caller's
//! callback and are used whole; OpenSSL never prompts (PEM blocks are decoded here — a port
//! of pyca's `pem` crate framing and `decrypt_pem`). Certificates and CSRs are read by
//! x509info's strict parser only; PKCS#12 is parsed by OpenSSL and its key and certificates
//! are then loaded as pyca loads them.
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use openssl::bn::{BigNum, BigNumContext};
use openssl::dh::Dh;
use openssl::dsa::Dsa;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::error::ErrorStack;
use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};
use openssl::pkey::{HasPublic, Id, PKey, PKeyRef, Private, Public};
use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use openssl::x509::X509Ref;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::crypto::ensure_legacy_provider;
use crate::error::{ConsoleError, Result};
use crate::keys::{Curve, KeyAlgorithm, KeyClass, KeyMaterial};
use crate::text::py_repr;
use crate::x509info::{
    self, AlgParams, Asn1Error, Classifier, Der, EcParams, EcParamsKind, O_AES128_CBC,
    O_AES192_CBC, O_AES256_CBC, O_DES_EDE3_CBC, O_ED448, O_ED25519, O_HMACS, O_PBE_MD5_DES,
    O_PBE_SHA_3DES, O_PBE_SHA_RC2_40, O_PBE_SHA_RC4_128, O_RSA, O_RSA_PSS, O_X448, O_X25519,
    alg_id, der_attributes, der_biguint, der_bits, der_nonempty_sequences, der_single, der_uint,
    ec_params, spki_fields,
};

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
/// SpecifiedECDomain DER (`openssl ecparam -param_enc explicit`; = pyca's `ec_constants`).
const P256_DOMAIN: &str = "3081f7020101302c06072a8648ce3d0101022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff305b0420ffffffff00000001000000000000000000000000fffffffffffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b031500c49d360886e704936a6678e1139d26b7819f7e900441046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101";
const P256_DOMAIN_NO_SEED: &str = "3081e0020101302c06072a8648ce3d0101022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff30440420ffffffff00000001000000000000000000000000fffffffffffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101";
const P384_DOMAIN: &str = "30820157020101303c06072a8648ce3d0101023100fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff307b0430fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc0430b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef031500a335926aa319a27a1d00896a6773a4827acdac73046104aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f023100ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973020101";
const P384_DOMAIN_NO_SEED: &str = "30820140020101303c06072a8648ce3d0101023100fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff30640430fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc0430b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef046104aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f023100ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973020101";
const P521_DOMAIN: &str = "308201c3020101304d06072a8648ce3d0101024201ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff30819f044201fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc04420051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00031500d09e8800291cb85396cc6717393284aaa0da64ba0481850400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650024201fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409020101";
const P521_DOMAIN_NO_SEED: &str = "308201ac020101304d06072a8648ce3d0101024201ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff308188044201fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc04420051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f000481850400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650024201fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409020101";
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
        return Err(requires_password());
    };
    let secret = callback(prompt)?;
    let bytes = secret.expose_secret().as_bytes();
    if bytes.is_empty() {
        // pyca treats an empty password as none ("Password was not given but private key is
        // encrypted", a TypeError that crashed c2): r2 answers with the no-password error
        // (§11 D12(f)).
        return Err(requires_password());
    }
    Ok(Zeroizing::new(bytes.to_vec()))
}

fn requires_password() -> ConsoleError {
    ConsoleError::key_parse("encrypted key material requires a password").with_hint(PASSWORD_HINT)
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

// ---------------------------------------------------------------------------------------
// pyca's key parsers: a port of cryptography 49's `cryptography-key-parsing` (PKCS#8,
// SEC1, PKCS#1, DSA, SPKI, EncryptedPrivateKeyInfo) over x509info's rust-asn1 reader. Keys
// are built from their components, as pyca builds them; OpenSSL's DER decoders are never
// used for key material.
// ---------------------------------------------------------------------------------------

/// pyca's `KeyParsingError`, as the Python exception c2 saw.
pub(crate) enum PycaError {
    /// ValueError for an ASN.1 parse error (the parsers' "try the next format" case).
    Parse(Asn1Error),
    /// Any other ValueError (its text).
    Value(String),
    /// UnsupportedAlgorithm (its text).
    Unsupported(String),
    /// TypeError "Password was not given but private key is encrypted".
    Encrypted,
    /// InternalError (an OpenSSL failure; c2 crashed — r2 treats it as a refusal).
    Internal(String),
}

pub(crate) type Pyca<T> = std::result::Result<T, PycaError>;

impl PycaError {
    /// The exception text (an OpenSSL failure: its first reason, §11 D11).
    pub(crate) fn text(&self) -> String {
        match self {
            PycaError::Parse(err) => format!(
                "Could not deserialize key data. The data may be in an incorrect format, it may be encrypted with an unsupported algorithm, or it may be an unsupported key type (e.g. EC curves with explicit parameters). Details: {}",
                err.display()
            ),
            PycaError::Value(text) | PycaError::Unsupported(text) | PycaError::Internal(text) => {
                text.clone()
            }
            PycaError::Encrypted => ENCRYPTED_TEXT.to_owned(),
        }
    }
}

impl From<Asn1Error> for PycaError {
    fn from(err: Asn1Error) -> Self {
        PycaError::Parse(err)
    }
}

impl From<ErrorStack> for PycaError {
    fn from(err: ErrorStack) -> Self {
        PycaError::Internal(ossl_detail(&err))
    }
}

const ENCRYPTED_TEXT: &str = "Password was not given but private key is encrypted";
const INCORRECT_PASSWORD_TEXT: &str = "Incorrect password, could not decrypt key";
const TRUNCATED_EC_TEXT: &str = "EC private key is not encoded properly: private key value is too short. Please file an issue at https://github.com/pyca/cryptography/issues explaining how your private key was created.";
const EC_INFINITY_TEXT: &str = "Cannot load an EC public key where the point is at infinity";

fn invalid_key() -> PycaError {
    PycaError::Value("Invalid key".to_owned())
}

fn bn(bytes: &[u8]) -> Pyca<BigNum> {
    Ok(BigNum::from_slice(bytes)?)
}

/// pyca's named curves: (OID content, OpenSSL NID).
const CURVE_OIDS: [(&[u8], Nid); 9] = [
    (
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01],
        Nid::X9_62_PRIME192V1,
    ),
    (&[0x2b, 0x81, 0x04, 0x00, 0x21], Nid::SECP224R1),
    (
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        Nid::X9_62_PRIME256V1,
    ),
    (&[0x2b, 0x81, 0x04, 0x00, 0x22], Nid::SECP384R1),
    (&[0x2b, 0x81, 0x04, 0x00, 0x23], Nid::SECP521R1),
    (&[0x2b, 0x81, 0x04, 0x00, 0x0a], Nid::SECP256K1),
    (
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
        Nid::BRAINPOOL_P256R1,
    ),
    (
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b],
        Nid::BRAINPOOL_P384R1,
    ),
    (
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d],
        Nid::BRAINPOOL_P512R1,
    ),
];

/// pyca's explicit-parameter domains it maps to a named curve (`ec_constants`: the
/// SpecifiedECDomain DER of P-256/P-384/P-521 with and without the seed).
const EXPLICIT_DOMAINS: [(&str, Nid); 6] = [
    (P256_DOMAIN, Nid::X9_62_PRIME256V1),
    (P256_DOMAIN_NO_SEED, Nid::X9_62_PRIME256V1),
    (P384_DOMAIN, Nid::SECP384R1),
    (P384_DOMAIN_NO_SEED, Nid::SECP384R1),
    (P521_DOMAIN, Nid::SECP521R1),
    (P521_DOMAIN_NO_SEED, Nid::SECP521R1),
];

/// pyca `ec_params_to_group`.
fn ec_group(params: &EcParams<'_>) -> Pyca<EcGroup> {
    let nid = match params.kind {
        EcParamsKind::Named(oid) => {
            let unsupported = || {
                PycaError::Unsupported(format!(
                    "Curve {} is not supported",
                    x509info::oid_dotted(oid).unwrap_or_default()
                ))
            };
            let nid = CURVE_OIDS
                .iter()
                .find(|(known, _)| *known == oid)
                .map(|(_, nid)| *nid)
                .ok_or_else(unsupported)?;
            return EcGroup::from_curve_name(nid).map_err(|_| unsupported());
        }
        EcParamsKind::Specified => EXPLICIT_DOMAINS
            .iter()
            .find(|(hex_der, _)| hex::decode(hex_der).is_ok_and(|der| der == params.raw))
            .map(|(_, nid)| *nid)
            .ok_or_else(|| PycaError::Unsupported(EXPLICIT_CURVE_TEXT.to_owned()))?,
        EcParamsKind::Implicit => {
            return Err(PycaError::Unsupported(EXPLICIT_CURVE_TEXT.to_owned()));
        }
    };
    EcGroup::from_curve_name(nid)
        .map_err(|_| PycaError::Unsupported(EXPLICIT_CURVE_TEXT.to_owned()))
}

/// pyca `pkcs8::parse_private_key` (PrivateKeyInfo { version u8, AlgorithmIdentifier,
/// OCTET STRING, [0] IMPLICIT Attributes OPTIONAL }; version 0 only).
fn pkcs8_private(data: &[u8]) -> Pyca<PKey<Private>> {
    let top = der_single(data, 0x30)?;
    let mut der = Der::new(top.content);
    let version = der_uint(&der.any()?, 1)?;
    let alg = alg_id(&der.any()?)?;
    let private = der.tagged(0x04)?.content;
    if let Some(attributes) = der.opt(0xa0)? {
        der_attributes(attributes.content)?;
    }
    der.finish()?;
    if version != 0 {
        return Err(invalid_key());
    }
    let raw = |id: Id| -> Pyca<PKey<Private>> {
        let key = der_single(private, 0x04)?;
        Ok(PKey::private_key_from_raw_bytes(key.content, id)?)
    };
    match &alg.params {
        _ if alg.oid == O_RSA || alg.oid == O_RSA_PSS => rsa_private(private),
        AlgParams::Ec(params) => sec1_private(private, Some(*params)),
        AlgParams::Dss { p, q, g } => {
            let x = der_biguint(&der_single(private, 0x02)?)?;
            let (p, q, g, x) = (bn(p)?, bn(q)?, bn(g)?, bn(x)?);
            let mut ctx = BigNumContext::new()?;
            let mut y = BigNum::new()?;
            y.mod_exp(&g, &x, &p, &mut ctx)?;
            let dsa = Dsa::from_private_components(p, q, g, x, y)?;
            Ok(PKey::from_dsa(dsa)?)
        }
        AlgParams::Dh { p, g, q } => {
            let x = der_biguint(&der_single(private, 0x02)?)?;
            let p = bn(p)?;
            if p.num_bits() < 512 {
                return Err(invalid_key());
            }
            let q = match q {
                Some(q) => Some(bn(q)?),
                None => None,
            };
            let dh = Dh::from_pqg(p, q, bn(g)?)?.set_private_key(bn(x)?)?;
            Ok(PKey::from_dh(dh)?)
        }
        _ if alg.oid == O_X25519 => raw(Id::X25519),
        _ if alg.oid == O_X448 => raw(Id::X448),
        _ if alg.oid == O_ED25519 => raw(Id::ED25519),
        _ if alg.oid == O_ED448 => raw(Id::ED448),
        _ => Err(PycaError::Unsupported(format!(
            "Unknown key type: {}",
            alg.dotted()
        ))),
    }
}

/// pyca `ec::parse_pkcs1_private_key` (SEC1 ECPrivateKey { version 1, OCTET STRING,
/// [0] EcParameters OPTIONAL, [1] BIT STRING OPTIONAL }), with the PKCS#8 parameters.
fn sec1_private(data: &[u8], outer: Option<EcParams<'_>>) -> Pyca<PKey<Private>> {
    let top = der_single(data, 0x30)?;
    let mut der = Der::new(top.content);
    let version = der_uint(&der.any()?, 1)?;
    let private = der.tagged(0x04)?.content;
    let inner = match der.opt(0xa0)? {
        Some(explicit) => {
            let mut params = Der::new(explicit.content);
            let parsed = ec_params(&params.any()?)?;
            params.finish()?;
            Some(parsed)
        }
        None => None,
    };
    let public = match der.opt(0xa1)? {
        Some(explicit) => Some(der_bits(&der_single(explicit.content, 0x03)?)?),
        None => None,
    };
    der.finish()?;
    if version != 1 {
        return Err(invalid_key());
    }
    let group = match (outer, inner) {
        (Some(outer), Some(inner)) => {
            if outer.raw != inner.raw {
                return Err(invalid_key());
            }
            ec_group(&outer)?
        }
        (Some(params), None) | (None, Some(params)) => ec_group(&params)?,
        (None, None) => return Err(invalid_key()),
    };
    let order_bytes = usize::try_from(group.order_bits().div_ceil(8)).unwrap_or(usize::MAX);
    if private.len() != order_bytes {
        return Err(PycaError::Value(TRUNCATED_EC_TEXT.to_owned()));
    }
    let d = bn(private)?;
    let mut ctx = BigNumContext::new()?;
    let point = match public {
        Some(bytes) => EcPoint::from_bytes(&group, bytes, &mut ctx).map_err(|_| invalid_key())?,
        None => {
            let mut point = EcPoint::new(&group)?;
            point
                .mul_generator2(&group, &d, &mut ctx)
                .map_err(|_| invalid_key())?;
            point
        }
    };
    let key = EcKey::from_private_components(&group, &d, &point).map_err(|_| invalid_key())?;
    key.check_key().map_err(|_| invalid_key())?;
    Ok(PKey::from_ec_key(key)?)
}

fn sec1_private_alone(data: &[u8]) -> Pyca<PKey<Private>> {
    sec1_private(data, None)
}

/// pyca `rsa::parse_pkcs1_private_key` (version 0, the eight BigUints, no
/// otherPrimeInfos).
fn rsa_private(data: &[u8]) -> Pyca<PKey<Private>> {
    let top = der_single(data, 0x30)?;
    let mut der = Der::new(top.content);
    let version = der_uint(&der.any()?, 1)?;
    let mut parts = Vec::with_capacity(8);
    for _ in 0..8 {
        parts.push(der_biguint(&der.any()?)?);
    }
    let other_primes = der.opt(0x30)?;
    if let Some(other) = &other_primes {
        der_nonempty_sequences(other.content)?;
    }
    der.finish()?;
    if version != 0 || other_primes.is_some() {
        return Err(invalid_key());
    }
    let rsa = Rsa::from_private_components(
        bn(parts[0])?,
        bn(parts[1])?,
        bn(parts[2])?,
        bn(parts[3])?,
        bn(parts[4])?,
        bn(parts[5])?,
        bn(parts[6])?,
        bn(parts[7])?,
    )?;
    Ok(PKey::from_rsa(rsa)?)
}

/// pyca `dsa::parse_pkcs1_private_key` (version 0, p, q, g, y, x).
fn dsa_private(data: &[u8]) -> Pyca<PKey<Private>> {
    let top = der_single(data, 0x30)?;
    let mut der = Der::new(top.content);
    let version = der_uint(&der.any()?, 1)?;
    let mut parts = Vec::with_capacity(5);
    for _ in 0..5 {
        parts.push(der_biguint(&der.any()?)?);
    }
    der.finish()?;
    if version != 0 {
        return Err(invalid_key());
    }
    let dsa = Dsa::from_private_components(
        bn(parts[0])?,
        bn(parts[1])?,
        bn(parts[2])?,
        bn(parts[4])?,
        bn(parts[3])?,
    )?;
    Ok(PKey::from_dsa(dsa)?)
}

/// pyca `rsa::parse_pkcs1_public_key` (RSAPublicKey { n, e } as BigUints).
fn rsa_public(data: &[u8]) -> Pyca<PKey<Public>> {
    let top = der_single(data, 0x30)?;
    let mut der = Der::new(top.content);
    let n = der_biguint(&der.any()?)?;
    let e = der_biguint(&der.any()?)?;
    der.finish()?;
    Ok(PKey::from_rsa(Rsa::from_public_components(
        bn(n)?,
        bn(e)?,
    )?)?)
}

/// pyca `spki::parse_public_key`.
fn spki_public(data: &[u8]) -> Pyca<PKey<Public>> {
    let top = der_single(data, 0x30)?;
    let spki = spki_fields(&top)?;
    let raw = |id: Id| -> Pyca<PKey<Public>> {
        PKey::public_key_from_raw_bytes(spki.key, id).map_err(|_| invalid_key())
    };
    match &spki.alg.params {
        AlgParams::Ec(params) => {
            let group = ec_group(params)?;
            let mut ctx = BigNumContext::new()?;
            let point =
                EcPoint::from_bytes(&group, spki.key, &mut ctx).map_err(|_| invalid_key())?;
            let key = EcKey::from_public_key(&group, &point).map_err(|_| invalid_key())?;
            Ok(PKey::from_ec_key(key)?)
        }
        _ if spki.alg.oid == O_ED25519 => raw(Id::ED25519),
        _ if spki.alg.oid == O_ED448 => raw(Id::ED448),
        _ if spki.alg.oid == O_X25519 => raw(Id::X25519),
        _ if spki.alg.oid == O_X448 => raw(Id::X448),
        _ if spki.alg.oid == O_RSA || spki.alg.oid == O_RSA_PSS => rsa_public(spki.key),
        AlgParams::Dss { p, q, g } => {
            let y = der_biguint(&der_single(spki.key, 0x02)?)?;
            let dsa = Dsa::from_public_components(bn(p)?, bn(q)?, bn(g)?, bn(y)?)?;
            Ok(PKey::from_dsa(dsa)?)
        }
        AlgParams::Dh { p, g, q } => {
            let q = match q {
                Some(q) => Some(bn(q)?),
                None => None,
            };
            let dh = Dh::from_pqg(bn(p)?, q, bn(g)?)?;
            let y = der_biguint(&der_single(spki.key, 0x02)?)?;
            Ok(PKey::from_dh(dh.set_public_key(bn(y)?)?)?)
        }
        _ => Err(PycaError::Unsupported(format!(
            "Unknown key type: {}",
            spki.alg.dotted()
        ))),
    }
}

/// pyca's `private_key_from_pkey` checks: RSA keys must pass `RSA_check_key` with odd p
/// and q ("Invalid private key"); an EC public point must not be at infinity.
fn private_checks(pkey: PKey<Private>) -> Pyca<PKey<Private>> {
    match pkey.id() {
        Id::RSA => {
            let rsa = pkey.rsa()?;
            let odd = |n: Option<&openssl::bn::BigNumRef>| n.is_some_and(|n| n.is_bit_set(0));
            if !rsa.check_key().unwrap_or(false) || !odd(rsa.p()) || !odd(rsa.q()) {
                return Err(PycaError::Value("Invalid private key".to_owned()));
            }
        }
        Id::EC => {
            let ec = pkey.ec_key()?;
            if ec.public_key().is_infinity(ec.group()) {
                return Err(PycaError::Value(EC_INFINITY_TEXT.to_owned()));
            }
        }
        _ => {}
    }
    Ok(pkey)
}

/// pyca `ECPublicKey::new`: the point must not be at infinity.
fn public_checks(pkey: PKey<Public>) -> Pyca<PKey<Public>> {
    if pkey.id() == Id::EC {
        let ec = pkey.ec_key()?;
        if ec.public_key().is_infinity(ec.group()) {
            return Err(PycaError::Value(EC_INFINITY_TEXT.to_owned()));
        }
    }
    Ok(pkey)
}

type PrivateParser = fn(&[u8]) -> Pyca<PKey<Private>>;

/// pyca `load_der_private_key(data, password)`: PKCS#8, SEC1, PKCS#1 and DSA in turn (an
/// ASN.1 parse error tries the next one, any other error is final), then an
/// EncryptedPrivateKeyInfo (no password → `Encrypted`).
pub(crate) fn load_der_private(data: &[u8], password: Option<&[u8]>) -> Pyca<PKey<Private>> {
    let parsers: [PrivateParser; 4] = [pkcs8_private, sec1_private_alone, rsa_private, dsa_private];
    for parser in parsers {
        match parser(data) {
            Ok(pkey) => return private_checks(pkey),
            Err(PycaError::Parse(_)) => {}
            Err(err) => return Err(err),
        }
    }
    private_checks(encrypted_pkcs8_private(data, password)?)
}

/// pyca `load_der_public_key`: an SPKI, else a PKCS#1 RSAPublicKey (the SPKI error is
/// kept when both fail).
pub(crate) fn load_der_public(data: &[u8]) -> Pyca<PKey<Public>> {
    let pkey = match spki_public(data) {
        Ok(pkey) => pkey,
        Err(err) => rsa_public(data).map_err(|_| err)?,
    };
    public_checks(pkey)
}

/// Outcome of pyca `load_der_private_key(data, password=None)`.
pub(crate) enum PrivateLoadError {
    /// pyca TypeError "Password was not given but private key is encrypted".
    Encrypted,
    /// pyca UnsupportedAlgorithm: the detail text.
    Unsupported(String),
    /// pyca ValueError (or an OpenSSL failure): the detail text.
    Invalid(String),
}

/// pyca `load_der_private_key(data, None)` (PKCS#8 / PKCS#1 / SEC1 / DSA).
pub(crate) fn load_private_der(
    data: &[u8],
) -> std::result::Result<PKey<Private>, PrivateLoadError> {
    load_der_private(data, None).map_err(|err| match err {
        PycaError::Encrypted => PrivateLoadError::Encrypted,
        PycaError::Unsupported(text) => PrivateLoadError::Unsupported(text),
        other => PrivateLoadError::Invalid(other.text()),
    })
}

/// pyca `load_der_public_key`: SPKI, or a PKCS#1 RSAPublicKey (`Err` = the detail text).
pub(crate) fn load_public_der(data: &[u8]) -> std::result::Result<PKey<Public>, String> {
    load_der_public(data).map_err(|err| err.text())
}

// ---------------------------------------------------------------------------------------
// Encrypted PKCS#8 (pyca `parse_encrypted_private_key`, decrypted here with the whole
// password — no OpenSSL password callback and its 1024-byte buffer)
// ---------------------------------------------------------------------------------------

/// pyca `cryptography_crypto::pkcs12::kdf` (RFC 7292 appendix B.2).
pub(crate) fn pkcs12_kdf(
    password: &str,
    salt: &[u8],
    id: u8,
    rounds: u64,
    key_len: usize,
    md: MessageDigest,
) -> std::result::Result<Zeroizing<Vec<u8>>, ErrorStack> {
    let pass: Zeroizing<Vec<u8>> = Zeroizing::new(
        password
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_be_bytes)
            .collect(),
    );
    let block = md.block_size();
    let s_len = block * salt.len().div_ceil(block);
    let p_len = block * pass.len().div_ceil(block);
    let mut init: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0; s_len + p_len]);
    for i in 0..s_len {
        init[i] = salt[i % salt.len()];
    }
    for i in 0..p_len {
        init[s_len + i] = pass[i % pass.len()];
    }
    let mut result: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0; key_len]);
    let mut pos = 0;
    loop {
        let mut hasher = Hasher::new(md)?;
        hasher.update(&vec![id; block])?;
        hasher.update(&init)?;
        let mut a = Zeroizing::new(hasher.finish()?.to_vec());
        for _ in 1..rounds {
            a = Zeroizing::new(openssl::hash::hash(md, &a)?.to_vec());
        }
        let take = a.len().min(key_len - pos);
        result[pos..pos + take].copy_from_slice(&a[..take]);
        pos += take;
        if pos == key_len {
            return Ok(result);
        }
        let b: Zeroizing<Vec<u8>> = Zeroizing::new((0..block).map(|i| a[i % a.len()]).collect());
        for chunk in init.chunks_mut(block) {
            let mut carry: u16 = 1;
            for k in (0..block).rev() {
                carry += u16::from(chunk[k]) + u16::from(b[k]);
                chunk[k] = carry as u8;
                carry >>= 8;
            }
        }
    }
}

/// pyca `pbkdf1` (PKCS#5 v1.5, PBES1 with MD5).
fn pbkdf1(
    md: MessageDigest,
    password: &[u8],
    salt: &[u8],
    iterations: u64,
    length: usize,
) -> Pyca<Zeroizing<Vec<u8>>> {
    if length > md.size() || iterations == 0 {
        return Err(PycaError::Internal("unknown error".to_owned()));
    }
    let mut hasher = Hasher::new(md)?;
    hasher.update(password)?;
    hasher.update(salt)?;
    let mut t = Zeroizing::new(hasher.finish()?.to_vec());
    for _ in 1..iterations {
        t = Zeroizing::new(openssl::hash::hash(md, &t)?.to_vec());
    }
    Ok(Zeroizing::new(t[..length].to_vec()))
}

fn incorrect_password() -> PycaError {
    PycaError::Value(INCORRECT_PASSWORD_TEXT.to_owned())
}

fn pbe_decrypt(cipher: Cipher, key: &[u8], iv: &[u8], data: &[u8]) -> Pyca<Zeroizing<Vec<u8>>> {
    openssl::symm::decrypt(cipher, key, Some(iv), data)
        .map(Zeroizing::new)
        .map_err(|_| incorrect_password())
}

/// pyca `pkcs8::parse_encrypted_private_key`: EncryptedPrivateKeyInfo { AlgorithmIdentifier,
/// OCTET STRING }; no (or an empty) password → `Encrypted`; then PBES1 (MD5-DES, SHA1-3DES,
/// SHA1-RC2-40, SHA1-RC4-128) or PBES2 (PBKDF2 over HMAC-SHA1..512 or scrypt; AES-*-CBC,
/// DES-EDE3-CBC, RC2-CBC version 58); anything else → "Unknown key encryption algorithm".
fn encrypted_pkcs8_private(data: &[u8], password: Option<&[u8]>) -> Pyca<PKey<Private>> {
    let top = der_single(data, 0x30)?;
    let mut der = Der::new(top.content);
    let alg = alg_id(&der.any()?)?;
    let encrypted = der.tagged(0x04)?.content;
    der.finish()?;
    let password = match password {
        None | Some([]) => return Err(PycaError::Encrypted),
        Some(password) => password,
    };
    let unknown =
        |oid: String| PycaError::Value(format!("Unknown key encryption algorithm: {oid}"));
    let pkcs12_pbe = |cipher: Cipher, salt: &[u8], iterations: u64| -> Pyca<Zeroizing<Vec<u8>>> {
        let text = std::str::from_utf8(password).map_err(|_| incorrect_password())?;
        let md = MessageDigest::sha1();
        let key = pkcs12_kdf(text, salt, 1, iterations, cipher.key_len(), md)?;
        let iv = pkcs12_kdf(text, salt, 2, iterations, cipher.block_size(), md)?;
        pbe_decrypt(cipher, &key, &iv, encrypted)
    };
    let plaintext = match &alg.params {
        AlgParams::Pbe { salt, iterations } if alg.oid == O_PBE_MD5_DES => {
            let cipher = Cipher::des_cbc();
            let key_len = cipher.key_len();
            let key_iv = pbkdf1(
                MessageDigest::md5(),
                password,
                salt,
                *iterations,
                key_len + cipher.iv_len().unwrap_or(0),
            )?;
            pbe_decrypt(cipher, &key_iv[..key_len], &key_iv[key_len..], encrypted)?
        }
        AlgParams::Pbe { salt, iterations } if alg.oid == O_PBE_SHA_3DES => {
            pkcs12_pbe(Cipher::des_ede3_cbc(), salt, *iterations)?
        }
        AlgParams::Pbe { salt, iterations } if alg.oid == O_PBE_SHA_RC2_40 => {
            pkcs12_pbe(Cipher::rc2_40_cbc(), salt, *iterations)?
        }
        AlgParams::Pbe { salt, iterations } if alg.oid == O_PBE_SHA_RC4_128 => {
            pkcs12_pbe(Cipher::rc4(), salt, *iterations)?
        }
        AlgParams::Pbes2 { kdf, enc } => {
            let (cipher, iv) = match &enc.params {
                AlgParams::Iv(iv) if enc.oid == O_DES_EDE3_CBC => (Cipher::des_ede3_cbc(), *iv),
                AlgParams::Iv(iv) if enc.oid == O_AES128_CBC => (Cipher::aes_128_cbc(), *iv),
                AlgParams::Iv(iv) if enc.oid == O_AES192_CBC => (Cipher::aes_192_cbc(), *iv),
                AlgParams::Iv(iv) if enc.oid == O_AES256_CBC => (Cipher::aes_256_cbc(), *iv),
                AlgParams::Rc2 { version, iv } => {
                    // 58 = a 128-bit effective key (RFC 8018 B.2.3); the default is 32.
                    if version.unwrap_or(32) != 58 {
                        return Err(invalid_key());
                    }
                    (Cipher::rc2_cbc(), *iv)
                }
                _ => return Err(unknown(enc.dotted())),
            };
            let mut key: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0; cipher.key_len()]);
            match &kdf.params {
                AlgParams::Pbkdf2 {
                    salt,
                    iterations,
                    prf,
                } => {
                    let digests = [
                        MessageDigest::sha1(),
                        MessageDigest::sha224(),
                        MessageDigest::sha256(),
                        MessageDigest::sha384(),
                        MessageDigest::sha512(),
                    ];
                    let md = O_HMACS
                        .iter()
                        .position(|oid| oid == prf)
                        .map(|i| digests[i])
                        .ok_or_else(|| unknown(x509info::oid_dotted(prf).unwrap_or_default()))?;
                    // OpenSSL takes a C int: rust-openssl's `try_into().unwrap()` panics above
                    // i32::MAX (so did pyca — c2 crashed, §11 D12(i)); r2 reports it as a
                    // ValueError (wrong password or corrupt data).
                    let iterations = usize::try_from(*iterations)
                        .ok()
                        .filter(|n| *n >= 1 && i32::try_from(*n).is_ok())
                        .ok_or_else(invalid_key)?;
                    openssl::pkcs5::pbkdf2_hmac(password, salt, iterations, md, &mut key)?;
                }
                AlgParams::Scrypt { salt, n, r, p } => {
                    let max_memory = u64::try_from(usize::MAX / 2).unwrap_or(u64::MAX);
                    openssl::pkcs5::scrypt(password, salt, *n, *r, *p, max_memory, &mut key)?;
                }
                _ => return Err(unknown(kdf.dotted())),
            }
            pbe_decrypt(cipher, &key, iv, encrypted)?
        }
        _ => return Err(unknown(alg.dotted())),
    };
    pkcs8_private(&plaintext)
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

/// c2 `_cert_material` over a certificate pyca's strict parser accepted (`x509info::
/// load_certificate`; OpenSSL's X509 decoder is not involved, it refuses Name encodings pyca
/// loads): the embedded key classifies the material, `data` = the DER, `label_hint` = the
/// given label else the subject CN.
fn cert_material(der: &[u8], label_hint: Option<String>) -> Result<KeyMaterial> {
    let parts = x509info::load_certificate(der).map_err(|detail| {
        ConsoleError::key_parse(format!("certificate is not valid DER X.509: {detail}"))
    })?;
    let pkey = x509info::cert_public_key(parts.spki, "certificate")?;
    let (algorithm, curve, size_bits) = classify_key(&pkey, Classifier::KeyParse, false)?;
    let label_hint = match label_hint {
        Some(label) => Some(label),
        None => x509info::subject_common_name(parts.subject).map_err(|detail| {
            ConsoleError::key_parse(format!("certificate is not valid DER X.509: {detail}"))
        })?,
    };
    Ok(KeyMaterial {
        algorithm,
        key_class: KeyClass::Certificate,
        data: Zeroizing::new(der.to_vec()),
        curve,
        size_bits,
        label_hint,
    })
}

/// c2 `_csr_material`: the CSR's public key as a PUBLIC material, label = subject CN.
fn csr_material(der: &[u8]) -> Result<KeyMaterial> {
    let parts = x509info::load_csr(der).map_err(|detail| {
        ConsoleError::key_parse(format!(
            "certificate request is not valid DER X.509: {detail}"
        ))
    })?;
    let pkey = x509info::cert_public_key(parts.spki, "certificate request")?;
    let label_hint = x509info::subject_common_name(parts.subject).map_err(|detail| {
        ConsoleError::key_parse(format!(
            "certificate request is not valid DER X.509: {detail}"
        ))
    })?;
    public_material(&pkey, label_hint)
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

// The `pem` 3.0 crate's framing (what pyca 49 parses a PEM block with), ported verbatim:
// the BEGIN tag up to the next "-----", [ \t\r\n]* skipped, the payload up to the first
// "-----END ", split at the first "\n\n" (else "\r\n\r\n") into header lines and data, the
// END tag up to the next "-----"; tags must be equal; every header line must contain ':';
// the data is base64 (STANDARD) after removing Unicode whitespace.

/// pyca's ValueError text for a `pem` crate error (`{e:?}` of `PemError`).
const PEM_ERROR_PREFIX: &str = "Unable to load PEM file. See https://cryptography.io/en/latest/faq/#why-can-t-i-import-my-pem-file for more details. ";

/// A decoded PEM block (`pem::Pem`): tag, RFC 1421 header lines, the DER body.
struct PemBody {
    tag: String,
    headers: Vec<String>,
    der: Zeroizing<Vec<u8>>,
}

impl PemBody {
    /// `HeaderMap::get`: the LAST header whose trimmed name is `key`, its value trimmed.
    fn header(&self, key: &str) -> Option<&str> {
        self.headers.iter().rev().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.trim() == key).then(|| value.trim())
        })
    }
}

/// `pem::parser::read_until` (including its naive restart on a partial match).
fn pem_read_until<'a>(input: &'a [u8], marker: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    let mut index = 0;
    let mut found = 0;
    while input.len() - index >= marker.len() - found {
        if input[index] == marker[found] {
            found += 1;
        } else {
            found = 0;
        }
        index += 1;
        if found == marker.len() {
            return Some((&input[index..], &input[..index - found]));
        }
    }
    None
}

fn pem_skip_whitespace(mut input: &[u8]) -> &[u8] {
    while let Some((b' ' | b'\t' | b'\n' | b'\r', rest)) = input.split_first() {
        input = rest;
    }
    input
}

/// `pem::parse` of one c2 block (`Err` = pyca's ValueError text).
fn decode_pem_body(block: &str) -> std::result::Result<PemBody, String> {
    let pem_error = |debug: String| format!("{PEM_ERROR_PREFIX}{debug}");
    let captures = (|| {
        let (input, _) = pem_read_until(block.as_bytes(), b"-----BEGIN ")?;
        let (input, begin) = pem_read_until(input, b"-----")?;
        let input = pem_skip_whitespace(input);
        let (input, payload) = pem_read_until(input, b"-----END ")?;
        let (headers, data) = if let Some((rest, headers)) = pem_read_until(payload, b"\n\n") {
            (headers, rest)
        } else if let Some((rest, headers)) = pem_read_until(payload, b"\r\n\r\n") {
            (headers, rest)
        } else {
            (&[][..], payload)
        };
        let (_, end) = pem_read_until(input, b"-----")?;
        Some((begin, headers, data, end))
    })();
    let Some((begin, headers, data, end)) = captures else {
        return Err(pem_error("MalformedFraming".to_owned()));
    };
    // `block` is valid UTF-8 and every split point is ASCII, so the parts are UTF-8 too.
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    let (tag, tag_end) = (text(begin), text(end));
    if tag.is_empty() {
        return Err(pem_error("MissingBeginTag".to_owned()));
    }
    if tag_end.is_empty() {
        return Err(pem_error("MissingEndTag".to_owned()));
    }
    if tag != tag_end {
        return Err(pem_error(format!("MismatchedTags({tag:?}, {tag_end:?})")));
    }
    let data = Zeroizing::new(text(data));
    let body: Zeroizing<String> =
        Zeroizing::new(data.chars().filter(|c| !c.is_whitespace()).collect());
    let der = STANDARD
        .decode(body.as_bytes())
        .map_err(|err| pem_error(format!("InvalidData({err:?})")))?;
    let headers: Vec<String> = text(headers).lines().map(str::to_owned).collect();
    if let Some(bad) = headers.iter().find(|line| !line.contains(':')) {
        return Err(pem_error(format!("InvalidHeader({bad:?})")));
    }
    Ok(PemBody {
        tag,
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
        // pyca's tag filters (`find_in_pem` / `load_pem_public_key`) see the raw tag.
        let (expected, wrong_tag) = match begin {
            "PUBLIC KEY" => (
                "PUBLIC KEY",
                "Valid PEM but no BEGIN PUBLIC KEY/END PUBLIC KEY delimiters. Are you sure this is a public key?",
            ),
            "CERTIFICATE" => (
                "CERTIFICATE",
                "Valid PEM but no BEGIN CERTIFICATE/END CERTIFICATE delimiters. Are you sure this is a certificate?",
            ),
            "CERTIFICATE REQUEST" => (
                "CERTIFICATE REQUEST",
                "Valid PEM but no BEGIN CERTIFICATE REQUEST/END CERTIFICATE REQUEST delimiters. Are you sure this is a CSR?",
            ),
            other => {
                return Err(ConsoleError::key_parse(format!(
                    "unsupported PEM block type {}",
                    py_repr(other)
                ))
                .with_hint(PEM_LABELS_HINT));
            }
        };
        let body = decode_pem_body(m.text).map_err(|d| malformed(&d))?;
        if body.tag != expected {
            return Err(malformed(wrong_tag));
        }
        match expected {
            "PUBLIC KEY" => {
                // pyca `load_pem_public_key` of a "PUBLIC KEY" block: an SPKI only.
                let pkey = spki_public(&body.der)
                    .and_then(public_checks)
                    .map_err(|err| malformed(&err.text()))?;
                materials.push(public_material(&pkey, None)?);
            }
            "CERTIFICATE" => {
                x509info::load_certificate(&body.der).map_err(|d| malformed(&d))?;
                materials.push(cert_material(&body.der, None)?);
            }
            _ => {
                x509info::load_csr(&body.der).map_err(|d| malformed(&d))?;
                materials.push(csr_material(&body.der)?);
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

/// pyca's PEM private-key dispatch on the block's tag (after `decrypt_pem`), then
/// `private_key_from_pkey`'s checks.
fn pem_private_by_tag(tag: &str, der: &[u8], password: Option<&[u8]>) -> Pyca<PKey<Private>> {
    let pkey = match tag {
        "PRIVATE KEY" => pkcs8_private(der)?,
        "RSA PRIVATE KEY" => rsa_private(der)?,
        "EC PRIVATE KEY" => sec1_private(der, None)?,
        _ => encrypted_pkcs8_private(der, password)?,
    };
    private_checks(pkey)
}

/// Traditional (RFC 1421) decryption, pyca's `decrypt_pem`: `DEK-Info` = "{cipher},{iv hex}"
/// split at the first ',' (neither part trimmed), EVP_BytesToKey(MD5, salt = IV[..8], one
/// round) + CBC with the first IV-length bytes of the IV (pyca's OpenSSL call ignores the
/// rest; a shorter IV fails). `Err` = c2's wrong-password path.
fn decrypt_traditional(
    body: &PemBody,
    dek_info: &str,
    password: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, ()> {
    let (cipher_name, iv_hex) = dek_info.split_once(',').ok_or(())?;
    let cipher = traditional_cipher(cipher_name).ok_or(())?;
    let iv = hex::decode(iv_hex).map_err(|_| ())?;
    let iv_len = cipher.iv_len().unwrap_or(0);
    if iv.len() < iv_len || iv.len() < 8 {
        return Err(());
    }
    let openssl::pkcs5::KeyIvPair {
        key,
        iv: derived_iv,
    } = openssl::pkcs5::bytes_to_key(cipher, MessageDigest::md5(), password, Some(&iv[..8]), 1)
        .map_err(|_| ())?;
    let key = Zeroizing::new(key);
    let _derived_iv = derived_iv.map(Zeroizing::new);
    openssl::symm::decrypt(cipher, &key, Some(&iv[..iv_len]), &body.der)
        .map(Zeroizing::new)
        .map_err(|_| ())
}

/// c2 `_parse_pem_private` over pyca's `load_pem_private_key` (first called without a
/// password; a TypeError — the key is encrypted — prompts and calls again).
fn parse_pem_private(
    block: &str,
    label: &str,
    password: &mut Option<PasswordCallback<'_>>,
) -> Result<KeyMaterial> {
    let malformed =
        |detail: &str| ConsoleError::key_parse(format!("malformed {label} PEM block: {detail}"));
    let body = decode_pem_body(block).map_err(|d| malformed(&d))?;
    if !PRIVATE_PEM_LABELS.contains(&body.tag.as_str()) {
        return Err(malformed(
            "Valid PEM but no BEGIN/END delimiters for a private key found. Are you sure this is a private key?",
        ));
    }
    let prompt = format!("Password for encrypted {label}");
    // pyca `decrypt_pem`: a Proc-Type header applies to every private label.
    match body.header("Proc-Type") {
        Some("4,ENCRYPTED") => {
            let dek_info = body
                .header("DEK-Info")
                .ok_or_else(|| malformed("Encrypted PEM doesn't have a DEK-Info header."))?;
            if !dek_info.contains(',') {
                return Err(malformed("Encrypted PEM's DEK-Info header is not valid."));
            }
            ensure_legacy_provider();
            let secret = ask_password(password, &prompt)?;
            let der =
                decrypt_traditional(&body, dek_info, &secret).map_err(|()| wrong_key_password())?;
            let pkey = pem_private_by_tag(&body.tag, &der, Some(&secret))
                .map_err(|_| wrong_key_password())?;
            return private_material(&pkey, None);
        }
        Some(_) => {
            return Err(malformed(
                "Proc-Type PEM header is not valid, key could not be decrypted.",
            ));
        }
        None => {}
    }
    match pem_private_by_tag(&body.tag, &body.der, None) {
        Ok(pkey) => private_material(&pkey, None),
        Err(PycaError::Encrypted) => {
            ensure_legacy_provider();
            let secret = ask_password(password, &prompt)?;
            let pkey = pem_private_by_tag(&body.tag, &body.der, Some(&secret))
                .map_err(|_| wrong_key_password())?;
            private_material(&pkey, None)
        }
        Err(err) => Err(malformed(&err.text())),
    }
}

// ---------------------------------------------------------------------------------------
// DER try-chain and PKCS#12
// ---------------------------------------------------------------------------------------

fn parse_der(
    data: &[u8],
    password: &mut Option<PasswordCallback<'_>>,
) -> Result<Option<Vec<KeyMaterial>>> {
    // 1. pyca `load_der_private_key(data, None)`: PKCS#8 / SEC1 / PKCS#1 / DSA; 2. an
    // EncryptedPrivateKeyInfo is its TypeError, which prompts and loads again.
    match load_der_private(data, None) {
        Ok(pkey) => return Ok(Some(vec![private_material(&pkey, None)?])),
        Err(PycaError::Encrypted) => {
            ensure_legacy_provider();
            let secret = ask_password(password, "Password for encrypted private key")?;
            let pkey = load_der_private(data, Some(&secret)).map_err(|_| wrong_key_password())?;
            return Ok(Some(vec![private_material(&pkey, None)?]));
        }
        Err(_) => {}
    }
    // 3. SPKI, 4. PKCS#1 RSAPublicKey
    if let Ok(pkey) = load_der_public(data) {
        return Ok(Some(vec![public_material(&pkey, None)?]));
    }
    // 5. X.509, 6. CSR (pyca's strict parsers; InvalidVersion was not a ValueError in c2)
    match x509info::load_certificate(data) {
        Ok(_) => return Ok(Some(vec![cert_material(data, None)?])),
        Err(detail) if x509info::is_invalid_version(&detail) => {
            return Err(ConsoleError::key_parse(format!(
                "certificate is not valid DER X.509: {detail}"
            )));
        }
        Err(_) => {}
    }
    match x509info::load_csr(data) {
        Ok(_) => return Ok(Some(vec![csr_material(data)?])),
        Err(detail) if x509info::is_invalid_version(&detail) => {
            return Err(ConsoleError::key_parse(format!(
                "certificate request is not valid DER X.509: {detail}"
            )));
        }
        Err(_) => {}
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

/// A PKCS#12 that one pyca `load_pkcs12` attempt accepted: the parse and its key loaded
/// as pyca loads it.
struct Pkcs12Contents {
    parsed: ParsedPkcs12_2,
    key: Option<PKey<Private>>,
}

/// One pyca `load_pkcs12(data, password)` attempt: `parse2`; the private key re-encoded as
/// PKCS#8 and loaded by pyca's DER loader; every certificate through pyca's strict loader.
/// `Ok(None)` = the attempt failed as with pyca's ValueError (wrong password, corrupt data,
/// a key pyca refuses with a ValueError — "Invalid private key", "Invalid key" —, an invalid
/// certificate): c2's loop moved on. A key pyca refuses with UnsupportedAlgorithm (curve or
/// key type) and a certificate with pyca's InvalidVersion escaped c2's `except ValueError`
/// (c2 crashed): `Err` (§11 D12(g), D12(b)).
/// A PFX without a MAC is retried with a MAC computed for `password` (OpenSSL 3.0's
/// PKCS12_parse refuses a non-empty password without a MAC; the OpenSSL pyca bundles, and
/// r2's vendored one, do not).
fn pkcs12_attempt(data: &[u8], p12: &Pkcs12, password: &str) -> Result<Option<Pkcs12Contents>> {
    let parsed = match p12.parse2(password) {
        Ok(parsed) => parsed,
        Err(_) if !password.is_empty() => {
            let retried = pkcs12_with_mac(data, password)
                .and_then(|with_mac| Pkcs12::from_der(&with_mac).ok())
                .and_then(|p12| p12.parse2(password).ok());
            match retried {
                Some(parsed) => parsed,
                None => return Ok(None),
            }
        }
        Err(_) => return Ok(None),
    };
    let key = match parsed.pkey.as_ref() {
        None => None,
        Some(pkey) => {
            let Ok(pkcs8) = pkey.private_key_to_pkcs8().map(Zeroizing::new) else {
                return Ok(None);
            };
            match load_private_der(&pkcs8) {
                Ok(key) => Some(key),
                Err(PrivateLoadError::Unsupported(detail)) => {
                    return Err(ConsoleError::key_parse(format!(
                        "PKCS#12 contains an unsupported private key: {detail}"
                    )));
                }
                Err(_) => return Ok(None),
            }
        }
    };
    let certs = parsed
        .cert
        .iter()
        .map(|cert| &**cert)
        .chain(parsed.ca.iter().flat_map(|stack| stack.iter()));
    for cert in certs {
        let Ok(der) = cert.to_der() else {
            return Ok(None);
        };
        match x509info::load_certificate(&der) {
            Ok(_) => {}
            Err(detail) if x509info::is_invalid_version(&detail) => {
                return Err(ConsoleError::key_parse(format!(
                    "certificate is not valid DER X.509: {detail}"
                )));
            }
            Err(_) => return Ok(None),
        }
    }
    Ok(Some(Pkcs12Contents { parsed, key }))
}

/// pkcs7-data (1.2.840.113549.1.7.1) and SHA-1 (1.3.14.3.2.26).
const OID_PKCS7_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
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

/// A MAC-less PFX (`SEQUENCE { version, authSafe pkcs7-data }`) with a password-integrity
/// MacData added (HMAC-SHA1, RFC 7292 key derivation, one iteration), so that `parse2`
/// verifies it and goes on to decrypt the bags with `password`. None for any other shape.
fn pkcs12_with_mac(data: &[u8], password: &str) -> Option<Vec<u8>> {
    let (pfx, rest) = x509info::read_tlv(data).ok()?;
    let (version, after) = x509info::read_tlv(pfx.content).ok()?;
    let (auth_safe, after) = x509info::read_tlv(after).ok()?;
    if !rest.is_empty() || pfx.tag != 0x30 || !after.is_empty() || auth_safe.tag != 0x30 {
        return None;
    }
    let (oid, content) = x509info::read_tlv(auth_safe.content).ok()?;
    let (explicit, _) = x509info::read_tlv(content).ok()?;
    let (octets, _) = x509info::read_tlv(explicit.content).ok()?;
    if oid.content != OID_PKCS7_DATA || explicit.tag != 0xa0 || octets.tag != 0x04 {
        return None;
    }
    let salt = *b"r2-nomac";
    // RFC 7292 B.2 (SHA-1: u = 20, v = 64), ID 3 (MAC key), one iteration, 20 key bytes.
    let mut bmp: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    for unit in password.encode_utf16().chain([0]) {
        bmp.extend_from_slice(&unit.to_be_bytes());
    }
    let mut input: Zeroizing<Vec<u8>> = Zeroizing::new(vec![3u8; 64]);
    input.extend((0..64).map(|i| salt[i % salt.len()]));
    let p_len = bmp.len().div_ceil(64) * 64;
    input.extend((0..p_len).map(|i| bmp[i % bmp.len()]));
    let key = Zeroizing::new(
        openssl::hash::hash(MessageDigest::sha1(), &input)
            .ok()?
            .to_vec(),
    );
    let hmac_key = PKey::hmac(&key).ok()?;
    let mut signer = openssl::sign::Signer::new(MessageDigest::sha1(), &hmac_key).ok()?;
    signer.update(octets.content).ok()?;
    let mac = signer.sign_to_vec().ok()?;
    let mut alg = der_tlv(0x06, OID_SHA1);
    alg.extend_from_slice(&[0x05, 0x00]);
    let mut digest_info = der_tlv(0x30, &alg);
    digest_info.extend(der_tlv(0x04, &mac));
    let mut mac_data = der_tlv(0x30, &digest_info);
    mac_data.extend(der_tlv(0x04, &salt));
    let mut body = version.raw.to_vec();
    body.extend_from_slice(auth_safe.raw);
    body.extend(der_tlv(0x30, &mac_data));
    Some(der_tlv(0x30, &body))
}

fn parse_pkcs12(
    data: &[u8],
    password: &mut Option<PasswordCallback<'_>>,
) -> Result<Vec<KeyMaterial>> {
    ensure_legacy_provider();
    let p12 = Pkcs12::from_der(data).ok();
    let first = match p12.as_ref() {
        Some(p12) => pkcs12_attempt(data, p12, "")?,
        None => None,
    };
    let Pkcs12Contents { parsed, key } = match first {
        Some(contents) => contents,
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
            // Pkcs12::parse2 would panic on an interior NUL (CString; so did pyca, c2
            // crashed): r2 answers with the wrong-password text (§11 D16).
            if secret.contains('\0') {
                return Err(wrong());
            }
            let retried = match p12.as_ref() {
                Some(p12) => pkcs12_attempt(data, p12, secret)?,
                None => None,
            };
            retried.ok_or_else(wrong)?
        }
    };
    let label_hint = match parsed.cert.as_ref() {
        None => None,
        Some(cert) => match cert.alias() {
            Some(alias) => Some(String::from_utf8_lossy(alias).into_owned()),
            None => {
                let der = cert_der(cert)?;
                let parts = x509info::load_certificate(&der).map_err(|detail| {
                    ConsoleError::key_parse(format!("certificate is not valid DER X.509: {detail}"))
                })?;
                x509info::subject_common_name(parts.subject).map_err(|detail| {
                    ConsoleError::key_parse(format!("certificate is not valid DER X.509: {detail}"))
                })?
            }
        },
    };
    let mut materials = Vec::new();
    if let Some(pkey) = key {
        materials.push(private_material(&pkey, label_hint.clone())?);
    }
    if let Some(cert) = parsed.cert.as_ref() {
        materials.push(cert_material(&cert_der(cert)?, label_hint.clone())?);
    }
    if let Some(chain) = parsed.ca.as_ref() {
        for cert in chain {
            materials.push(cert_material(&cert_der(cert)?, label_hint.clone())?);
        }
    }
    if materials.is_empty() {
        return Err(ConsoleError::key_parse(
            "PKCS#12 contains no key or certificates",
        ));
    }
    Ok(materials)
}

fn cert_der(cert: &X509Ref) -> Result<Vec<u8>> {
    cert.to_der().map_err(|err| {
        ConsoleError::key_parse(format!(
            "certificate is not valid DER X.509: {}",
            ossl_detail(&err)
        ))
    })
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
