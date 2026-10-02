// Built-in generic-secret operation specs (spec §4.6.6 rows 32–33, owner R3; c2
// ops/builtin_generic.py). HMAC over a CKK_GENERIC_SECRET key: one canonical mechanism
// whose hash is a parameter; `mac_len` absent = the full digest (providers truncate
// locally — byte-identical to CKM_SHAx_HMAC_GENERAL by definition, §5.9).
use r2_core::error::Result;
use r2_core::keys::{KeyAlgorithm, KeyClass};
use r2_provider::mechanism;

use crate::model::Verb;
use crate::model::build::{choice, int, register_with_mirror, spec};
use crate::registry::OperationRegistry;

/// HMAC hash choices (§4.6.6 row 32) — shared with the providers' CKM selection.
const HMAC_HASHES: [&str; 5] = ["sha1", "sha224", "sha256", "sha384", "sha512"];

/// Registers rows 32–33 of the §4.6.6 table, in table order.
pub fn register_builtin(reg: &mut OperationRegistry) -> Result<()> {
    let hmac = spec(
        "generic.sign.hmac",
        Verb::Sign,
        KeyAlgorithm::Generic,
        &[KeyClass::Secret],
        mechanism::HMAC,
        "hmac",
        "HMAC (SHA-1/224/256/384/512) over a generic secret",
        vec![
            choice("hash", "Hash", "sha256", &HMAC_HASHES),
            int("mac_len", "MAC length in bytes (empty = full digest)", None),
        ],
    );
    register_with_mirror(reg, hmac, Verb::Verify, "HMAC verification", None)
}
