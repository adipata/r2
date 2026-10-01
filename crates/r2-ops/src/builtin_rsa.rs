// Built-in RSA operation specs (spec §4.6.6 rows 13–24, owner R3; c2 ops/builtin_rsa.py).
// Encrypt ops take PUBLIC (or CERTIFICATE, §4.3) keys and are mirrored to DECRYPT ops on
// PRIVATE keys; SIGN ops take PRIVATE keys and are mirrored to VERIFY ops on
// PUBLIC/CERTIFICATE keys — same cli_name/mechanism/params.
use r2_core::error::Result;
use r2_core::keys::{KeyAlgorithm, KeyClass};
use r2_provider::mechanism;

use crate::model::build::{bytes_empty, choice, int, mirror_choice, register_with_mirror, spec};
use crate::model::{OperationSpec, ParamSpec, Verb};
use crate::registry::OperationRegistry;

const PRIVATE: &[KeyClass] = &[KeyClass::Private];
const PUBLIC_OR_CERT: &[KeyClass] = &[KeyClass::Public, KeyClass::Certificate];
/// RAW decrypt also accepts PUBLIC (public-exponent modexp — signature recovery, §5.8).
/// CERTIFICATE stays excluded: §4.3 forbids certificates for the decrypt verb.
const PRIVATE_OR_PUBLIC: &[KeyClass] = &[KeyClass::Private, KeyClass::Public];

const HASHES_OAEP: &[&str] = &["sha1", "sha256", "sha384", "sha512"];
const HASHES_SIGN: &[&str] = &["sha1", "sha224", "sha256", "sha384", "sha512"];

fn rsa(
    id: &str,
    verb: Verb,
    classes: &[KeyClass],
    mech: &str,
    cli: &str,
    label: &str,
    params: Vec<ParamSpec>,
) -> OperationSpec {
    spec(
        id,
        verb,
        KeyAlgorithm::Rsa,
        classes,
        mech,
        cli,
        label,
        params,
    )
}

/// Registers rows 13–24 of the §4.6.6 table, in table order.
pub fn register_builtin(reg: &mut OperationRegistry) -> Result<()> {
    let oaep = rsa(
        "rsa.encrypt.oaep",
        Verb::Encrypt,
        PUBLIC_OR_CERT,
        mechanism::RSA_OAEP,
        "oaep",
        "RSA-OAEP encryption",
        vec![
            choice("hash", "Hash algorithm", "sha256", HASHES_OAEP),
            mirror_choice(
                "mgf_hash",
                "MGF1 hash algorithm (defaults to hash)",
                "hash",
                HASHES_OAEP,
            ),
            bytes_empty("label", "OAEP label (empty for none)"),
        ],
    );
    register_with_mirror(
        reg,
        oaep,
        Verb::Decrypt,
        "RSA-OAEP decryption",
        Some(PRIVATE),
    )?;
    let enc_pkcs1 = rsa(
        "rsa.encrypt.pkcs1",
        Verb::Encrypt,
        PUBLIC_OR_CERT,
        mechanism::RSA_PKCS1,
        "pkcs1",
        "RSA PKCS#1 v1.5 encryption",
        Vec::new(),
    );
    register_with_mirror(
        reg,
        enc_pkcs1,
        Verb::Decrypt,
        "RSA PKCS#1 v1.5 decryption",
        Some(PRIVATE),
    )?;
    let enc_raw = rsa(
        "rsa.encrypt.raw",
        Verb::Encrypt,
        PUBLIC_OR_CERT,
        mechanism::RSA_RAW,
        "raw",
        "Raw RSA (textbook) encryption — input left-padded to modulus length",
        Vec::new(),
    );
    register_with_mirror(
        reg,
        enc_raw,
        Verb::Decrypt,
        "Raw RSA (textbook) decryption — input left-padded to modulus length",
        Some(PRIVATE_OR_PUBLIC),
    )?;
    let sign_pkcs1 = rsa(
        "rsa.sign.pkcs1",
        Verb::Sign,
        PRIVATE,
        mechanism::RSA_PKCS1,
        "pkcs1",
        "RSA PKCS#1 v1.5 signature",
        vec![choice("hash", "Hash algorithm", "sha256", HASHES_SIGN)],
    );
    register_with_mirror(
        reg,
        sign_pkcs1,
        Verb::Verify,
        "RSA PKCS#1 v1.5 signature verification",
        Some(PUBLIC_OR_CERT),
    )?;
    let sign_pss = rsa(
        "rsa.sign.pss",
        Verb::Sign,
        PRIVATE,
        mechanism::RSA_PSS,
        "pss",
        "RSA-PSS signature",
        vec![
            choice("hash", "Hash algorithm", "sha256", HASHES_SIGN),
            mirror_choice(
                "mgf_hash",
                "MGF1 hash algorithm (defaults to hash)",
                "hash",
                HASHES_SIGN,
            ),
            // None → the provider uses the digest length; the sentinel -1 is resolved by
            // the provider to keylen - hashlen - 2 (maximum salt, §4.6).
            int(
                "salt_len",
                "Salt length in bytes (empty = digest length, -1 = maximum)",
                None,
            ),
        ],
    );
    register_with_mirror(
        reg,
        sign_pss,
        Verb::Verify,
        "RSA-PSS signature verification",
        Some(PUBLIC_OR_CERT),
    )?;
    let sign_raw = rsa(
        "rsa.sign.raw",
        Verb::Sign,
        PRIVATE,
        mechanism::RSA_RAW,
        "raw",
        "Raw RSA signature — caller supplies the padded block",
        Vec::new(),
    );
    register_with_mirror(
        reg,
        sign_raw,
        Verb::Verify,
        "Raw RSA signature verification — caller supplies the padded block",
        Some(PUBLIC_OR_CERT),
    )
}
