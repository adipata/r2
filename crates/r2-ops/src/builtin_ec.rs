// Built-in EC / EdDSA / ECDH operation specs (spec §4.6.6 rows 25–31, owner R3; c2
// ops/builtin_ec.py). SIGN ops are mirrored to VERIFY ops on PUBLIC/CERTIFICATE keys; the
// x25519/x448 derive rows carry `curves`, the other rows have none.
use r2_core::error::Result;
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass};
use r2_provider::mechanism;

use crate::model::build::{bytes, bytes_empty, choice, int, register_with_mirror, spec};
use crate::model::{OperationSpec, Verb};
use crate::registry::OperationRegistry;

const PRIVATE: &[KeyClass] = &[KeyClass::Private];
const PUBLIC_OR_CERT: &[KeyClass] = &[KeyClass::Public, KeyClass::Certificate];
const HASHES_SIGN: &[&str] = &["sha1", "sha224", "sha256", "sha384", "sha512"];

fn montgomery(id: &str, cli: &str, label: &str, prompt: &str, curve: Curve) -> OperationSpec {
    OperationSpec {
        curves: Some([curve].into_iter().collect()),
        ..spec(
            id,
            Verb::Derive,
            KeyAlgorithm::EcMontgomery,
            PRIVATE,
            mechanism::ECDH,
            cli,
            label,
            vec![bytes("peer", prompt)],
        )
    }
}

/// Registers rows 25–31 of the §4.6.6 table, in table order.
pub fn register_builtin(reg: &mut OperationRegistry) -> Result<()> {
    let ecdsa = spec(
        "ec.sign.ecdsa",
        Verb::Sign,
        KeyAlgorithm::Ec,
        PRIVATE,
        mechanism::ECDSA,
        "ecdsa",
        "ECDSA signature (canonical fixed-width r||s)",
        vec![choice("hash", "Hash algorithm", "sha256", HASHES_SIGN)],
    );
    register_with_mirror(
        reg,
        ecdsa,
        Verb::Verify,
        "ECDSA signature verification",
        Some(PUBLIC_OR_CERT),
    )?;
    let eddsa = spec(
        "ec.sign.eddsa",
        Verb::Sign,
        KeyAlgorithm::EcEdwards,
        PRIVATE,
        mechanism::EDDSA,
        "eddsa",
        "EdDSA signature (Ed25519/Ed448, raw)",
        Vec::new(),
    );
    register_with_mirror(
        reg,
        eddsa,
        Verb::Verify,
        "EdDSA signature verification",
        Some(PUBLIC_OR_CERT),
    )?;
    reg.register(spec(
        "ec.derive.ecdh",
        Verb::Derive,
        KeyAlgorithm::Ec,
        PRIVATE,
        mechanism::ECDH,
        "ecdh",
        "ECDH key agreement",
        vec![
            bytes("peer", "Peer public key (SPKI DER or raw point 0x04||X||Y)"),
            choice(
                "kdf",
                "KDF applied to the shared secret",
                "null",
                &["null", "sha1", "sha256", "sha384", "sha512"],
            ),
            bytes_empty("shared_data", "KDF shared data (empty for none)"),
            int(
                "out_len",
                "Output length in bytes (0 = curve size)",
                Some(0),
            ),
        ],
    ))?;
    reg.register(montgomery(
        "ec.derive.x25519",
        "x25519",
        "X25519 key agreement",
        "Peer public key (SPKI DER or raw 32-byte u-coordinate)",
        Curve::X25519,
    ))?;
    reg.register(montgomery(
        "ec.derive.x448",
        "x448",
        "X448 key agreement",
        "Peer public key (SPKI DER or raw 56-byte u-coordinate)",
        Curve::X448,
    ))
}
