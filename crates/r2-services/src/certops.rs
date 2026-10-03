// PKCS#12 export + CSR orchestration (spec §5.6/§5.7, §4.9.10; owner R8) — c2
// `services/certops.py` minus `certificate_details` / `ecdsa_rs_to_der` (moved to R6's
// `r2_core::x509info` / `r2_core::der`).
//
// PKCS#12 assembly is always software-side (the private key must be exportable); when no
// certificate exists a minimal self-signed one is built on the fly. CSR generation works
// for non-extractable HSM keys: the `build_csr` sign callback routes through
// `Provider::sign`, converting the canonical fixed-width ECDSA r‖s output (§4.5.4) to the
// DER SEQUENCE the X.509 wire format requires BEFORE returning (§4.4.4).
use r2_core::der::ecdsa_rs_to_der;
use r2_core::error::ConsoleError;
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo};
use r2_core::params::{ParamValue, Params};
use r2_core::runtime::timed;
use r2_core::text::py_repr;
use r2_core::x509build::{
    DEFAULT_CERT_DAYS, SignatureAlg, build_csr, build_pkcs12, build_self_signed_cert,
};
use r2_provider::mechanism::{ECDSA, EDDSA, RSA_PKCS1};
use r2_provider::{MechanismInvocation, Provider};
use secrecy::SecretString;

use crate::keyexport;

pub const CSR_HASHES: [&str; 3] = ["sha256", "sha384", "sha512"];

/// The CERTIFICATE object sharing the key's CKA_ID (preferred) or label (§5.6).
pub fn find_certificate(
    provider: &dyn Provider,
    key: &KeyInfo,
) -> r2_core::Result<Option<KeyInfo>> {
    let mut same_id: Option<KeyInfo> = None;
    let mut same_label: Option<KeyInfo> = None;
    for info in provider.list_keys()? {
        if info.key_class != KeyClass::Certificate {
            continue;
        }
        if key.key_ref.key_id.is_some() && info.key_ref.key_id == key.key_ref.key_id {
            same_id.get_or_insert(info);
        } else if info.key_ref.label == key.key_ref.label {
            same_label.get_or_insert(info);
        }
    }
    Ok(same_id.or(same_label))
}

/// §5.6 PKCS#12 export. Without `cert_der` and without a co-located certificate it builds
/// a self-signed one with CN = the key label, and FIRST (before exporting or building
/// anything) checks the label: outside 1..=64 UTF-8 bytes → Param "Attribute's length must
/// be >= 1 and <= 64, but it was {n}" (param_name "label", hint "pass an existing
/// certificate with --cert") — §11 D12.
pub fn export_pkcs12(
    provider: &dyn Provider,
    key: &KeyInfo,
    password: &SecretString,
    cert_der: Option<&[u8]>,
) -> r2_core::Result<Vec<u8>> {
    if key.key_class != KeyClass::Private {
        return Err(ConsoleError::unsupported(format!(
            "PKCS#12 export needs a private key, got {} '{}'",
            key.key_class.as_str(),
            key.key_ref.display()
        ))
        .with_hint("certificates and public keys export as pem/der instead"));
    }
    keyexport::refuse_non_exportable(key)?; // §5.6 pre-flight — before touching the token
    let label = key.key_ref.label.as_str();
    // Certificate precedence: explicit cert_der → the provider's CERTIFICATE sharing
    // label/CKA_ID → a self-signed certificate built on the fly.
    let co_located = match cert_der {
        Some(_) => None,
        None => find_certificate(provider, key)?,
    };
    let self_signed = cert_der.is_none() && co_located.is_none();
    if self_signed && !(1..=64).contains(&label.len()) {
        return Err(ConsoleError::param(
            format!(
                "Attribute's length must be >= 1 and <= 64, but it was {}",
                label.len()
            ),
            "label",
        )
        .with_hint("pass an existing certificate with --cert"));
    }
    let pkcs8 = timed(|| provider.export_key(key))?.data;
    let cert = match (cert_der, co_located) {
        (Some(der), _) => der.to_vec(),
        (None, Some(info)) => timed(|| provider.export_key(&info))?.data.to_vec(),
        (None, None) => build_self_signed_cert(&pkcs8, label, DEFAULT_CERT_DAYS)?,
    };
    build_pkcs12(&pkcs8, &cert, label, password, &[])
}

/// §5.7: sign callback through provider.sign (RSA-PKCS1 / ECDSA r‖s → DER via
/// r2_core::der::ecdsa_rs_to_der / EDDSA raw). Returns PEM bytes.
pub fn generate_csr(
    provider: &dyn Provider,
    key: &KeyInfo,
    subject: &str,
    hash_name: &str,
) -> r2_core::Result<Vec<u8>> {
    if !CSR_HASHES.contains(&hash_name) {
        return Err(ConsoleError::param(
            format!("unknown CSR hash {}", py_repr(hash_name)),
            "hash",
        )
        .with_hint(format!("valid hashes: {}", CSR_HASHES.join(", "))));
    }
    if key.key_class != KeyClass::Private {
        return Err(ConsoleError::unsupported(format!(
            "CSR generation needs a private key, got {} '{}'",
            key.key_class.as_str(),
            key.key_ref.display()
        ))
        .with_hint("reference the private key: csr <provider>:<label> <path>"));
    }
    let spki = keyexport::public_spki(provider, key)?;
    let hash_params = || {
        let mut params = Params::new();
        params.insert("hash".to_owned(), ParamValue::Enum(hash_name.to_owned()));
        params
    };

    match key.algorithm {
        KeyAlgorithm::Rsa => {
            let sig_alg = match hash_name {
                "sha384" => SignatureAlg::RsaPkcs1Sha384,
                "sha512" => SignatureAlg::RsaPkcs1Sha512,
                _ => SignatureAlg::RsaPkcs1Sha256,
            };
            let mech = MechanismInvocation::new(RSA_PKCS1, hash_params());
            // PKCS#1 block — already the X.509 wire format.
            let mut sign = |tbs: &[u8]| timed(|| provider.sign(key, &mech, tbs));
            build_csr(&spki, subject, sig_alg, &mut sign)
        }
        KeyAlgorithm::Ec => {
            let sig_alg = match hash_name {
                "sha384" => SignatureAlg::EcdsaSha384,
                "sha512" => SignatureAlg::EcdsaSha512,
                _ => SignatureAlg::EcdsaSha256,
            };
            let mech = MechanismInvocation::new(ECDSA, hash_params());
            // §5.7: providers emit fixed-width r‖s — convert BEFORE returning.
            let mut sign = |tbs: &[u8]| ecdsa_rs_to_der(&timed(|| provider.sign(key, &mech, tbs))?);
            build_csr(&spki, subject, sig_alg, &mut sign)
        }
        KeyAlgorithm::EcEdwards => {
            let sig_alg = match &key.curve {
                Some(Curve::Ed448) => SignatureAlg::Ed448,
                Some(Curve::Ed25519) => SignatureAlg::Ed25519,
                other => {
                    let shown = other
                        .as_ref()
                        .map_or_else(|| "None".to_owned(), |curve| py_repr(curve.as_str()));
                    return Err(ConsoleError::unsupported(format!(
                        "unknown Edwards curve {shown} for '{}'",
                        key.key_ref.display()
                    )));
                }
            };
            let mech = MechanismInvocation::new(EDDSA, Params::new());
            // raw Ed signature (§5.9)
            let mut sign = |tbs: &[u8]| timed(|| provider.sign(key, &mech, tbs));
            build_csr(&spki, subject, sig_alg, &mut sign)
        }
        other => Err(ConsoleError::unsupported(format!(
            "cannot build a CSR for {} keys",
            other.as_str()
        ))
        .with_hint("CSRs need an RSA, EC or Ed25519/Ed448 key")),
    }
}
