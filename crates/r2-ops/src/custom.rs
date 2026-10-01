// R0 skeleton — owner R3 (generated from spec §4)
// ---- spec §4.6.3 block 0
use r2_config::model::CustomMechanismConfig;
use r2_core::keys::{KeyAlgorithm, KeyClass};
use std::collections::BTreeSet;

use crate::model::{OperationSpec, ParamSpec, Verb};

/// Each custom_mechanisms[] entry → OperationSpec{ id, verb, algorithm, key_classes =
/// derive_key_classes(verb, algorithm), mechanism = entry.id, cli_name, label, params =
/// entry.params converted 1:1 (+ raw_mechparam_spec() appended when param_struct == Raw),
/// provider_types = entry.provider_types or {"pkcs11"} (vendor CKMs never target memory by
/// default), providers = entry.providers, curves = None, raw_ckm = Some(entry.ckm),
/// param_struct = entry.param_struct }.
pub fn spec_from_config(entry: &CustomMechanismConfig) -> OperationSpec {
    let _ = entry;
    unimplemented!("R3")
}
/// AES/GENERIC → {SECRET} for every verb; RSA/EC/EC_EDWARDS/EC_MONTGOMERY → encrypt and
/// verify: {PUBLIC, CERTIFICATE}; decrypt, sign, derive: {PRIVATE}. (The config loader
/// rejects algorithm none|other.)
pub fn derive_key_classes(verb: Verb, algorithm: KeyAlgorithm) -> BTreeSet<KeyClass> {
    let _ = (verb, algorithm);
    unimplemented!("R3")
}
/// ParamSpec::new("mechparam", ParamKind::Bytes, "Raw mechanism parameter bytes").
pub fn raw_mechparam_spec() -> ParamSpec {
    unimplemented!("R3")
}
