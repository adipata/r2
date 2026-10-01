// Built-in AES operation specs (spec §4.6.6 rows 1–12, owner R3; c2 ops/builtin_aes.py).
// Every ENCRYPT row has a mirrored DECRYPT op and every SIGN row a mirrored VERIFY op
// (same cli_name/mechanism/params/key classes, id with the verb swapped).
use r2_core::error::Result;
use r2_core::keys::{KeyAlgorithm, KeyClass};
use r2_provider::mechanism;

use crate::model::build::{bytes, bytes_empty, choice, int, register_with_mirror, spec};
use crate::model::{OperationSpec, ParamSpec, Verb};
use crate::registry::OperationRegistry;

const SECRET: &[KeyClass] = &[KeyClass::Secret];
const PADDINGS: &[&str] = &["none", "pkcs7"];
const TAG_BITS: &[&str] = &["128", "120", "112", "104", "96"];

fn aes(
    id: &str,
    verb: Verb,
    mech: &str,
    cli: &str,
    label: &str,
    params: Vec<ParamSpec>,
) -> OperationSpec {
    spec(
        id,
        verb,
        KeyAlgorithm::Aes,
        SECRET,
        mech,
        cli,
        label,
        params,
    )
}

/// Registers rows 1–12 of the §4.6.6 table, in table order.
pub fn register_builtin(reg: &mut OperationRegistry) -> Result<()> {
    let ecb = aes(
        "aes.encrypt.ecb",
        Verb::Encrypt,
        mechanism::AES_ECB,
        "ecb",
        "AES-ECB encryption",
        vec![choice("padding", "Padding", "none", PADDINGS)],
    );
    register_with_mirror(reg, ecb, Verb::Decrypt, "AES-ECB decryption", None)?;
    let cbc = aes(
        "aes.encrypt.cbc",
        Verb::Encrypt,
        mechanism::AES_CBC,
        "cbc",
        "AES-CBC encryption",
        vec![
            bytes("iv", "IV (16 bytes)").length(16),
            choice("padding", "Padding", "pkcs7", PADDINGS),
        ],
    );
    register_with_mirror(reg, cbc, Verb::Decrypt, "AES-CBC decryption", None)?;
    let gcm = aes(
        "aes.encrypt.gcm",
        Verb::Encrypt,
        mechanism::AES_GCM,
        "gcm",
        "AES-GCM authenticated encryption",
        vec![
            bytes("iv", "IV / nonce (12 bytes typical)"),
            bytes_empty("aad", "Additional authenticated data (empty for none)"),
            choice("tag_bits", "Tag length in bits", "128", TAG_BITS),
        ],
    );
    register_with_mirror(
        reg,
        gcm,
        Verb::Decrypt,
        "AES-GCM authenticated decryption",
        None,
    )?;
    let ctr = aes(
        "aes.encrypt.ctr",
        Verb::Encrypt,
        mechanism::AES_CTR,
        "ctr",
        "AES-CTR encryption",
        vec![
            bytes("counter_block", "Initial counter block (16 bytes)").length(16),
            int("counter_bits", "Counter width in bits", Some(128)),
        ],
    );
    register_with_mirror(reg, ctr, Verb::Decrypt, "AES-CTR decryption", None)?;
    let cmac = aes(
        "aes.sign.cmac",
        Verb::Sign,
        mechanism::AES_CMAC,
        "cmac",
        "AES-CMAC MAC",
        vec![int("mac_len", "MAC length in bytes", Some(16))],
    );
    register_with_mirror(reg, cmac, Verb::Verify, "AES-CMAC MAC verification", None)?;
    let gmac = aes(
        "aes.sign.gmac",
        Verb::Sign,
        mechanism::AES_GMAC,
        "gmac",
        "AES-GMAC MAC",
        vec![
            bytes("iv", "IV (12 bytes)").length(12),
            int("mac_len", "MAC length in bytes", Some(16)),
        ],
    );
    register_with_mirror(reg, gmac, Verb::Verify, "AES-GMAC MAC verification", None)
}
