// Config-defined custom PKCS#11 mechanisms → OperationSpecs (spec §4.6.3, owner R3; c2
// ops/custom.py). Touches no provider table: the bootstrap hands {ckm: id} to each
// Pkcs11Provider, which folds it into `mechanisms()` (§4.6.5).
use std::collections::BTreeSet;

use r2_config::model::{CustomMechanismConfig, ParamSpecConfig};
use r2_core::keys::{KeyAlgorithm, KeyClass};

use crate::model::{OperationSpec, ParamKind, ParamSpec, ParamStruct, Verb};

/// Each custom_mechanisms[] entry → OperationSpec{ id, verb, algorithm, key_classes =
/// derive_key_classes(verb, algorithm), mechanism = entry.id, cli_name, label, params =
/// entry.params converted 1:1 (+ raw_mechparam_spec() appended when param_struct == Raw),
/// provider_types = entry.provider_types or {"pkcs11"} (vendor CKMs never target memory by
/// default), providers = entry.providers, curves = None, raw_ckm = Some(entry.ckm),
/// param_struct = entry.param_struct }.
pub fn spec_from_config(entry: &CustomMechanismConfig) -> OperationSpec {
    let mut params: Vec<ParamSpec> = entry.params.iter().map(param_from_config).collect();
    if entry.param_struct == ParamStruct::Raw {
        params.push(raw_mechparam_spec());
    }
    let provider_types = match &entry.provider_types {
        None => ["pkcs11".to_owned()].into_iter().collect(),
        Some(types) => types.iter().cloned().collect(),
    };
    OperationSpec {
        id: entry.id.clone(),
        verb: entry.verb,
        algorithm: entry.algorithm,
        key_classes: derive_key_classes(entry.verb, entry.algorithm),
        mechanism: entry.id.clone(),
        cli_name: entry.cli_name.clone(),
        label: entry.label.clone(),
        params,
        provider_types: Some(provider_types),
        providers: entry
            .providers
            .as_ref()
            .map(|names| names.iter().cloned().collect()),
        curves: None,
        raw_ckm: Some(entry.ckm),
        param_struct: entry.param_struct,
    }
}
/// AES/GENERIC → {SECRET} for every verb; RSA/EC/EC_EDWARDS/EC_MONTGOMERY → encrypt and
/// verify: {PUBLIC, CERTIFICATE}; decrypt, sign, derive: {PRIVATE}. (The config loader
/// rejects algorithm none|other.)
pub fn derive_key_classes(verb: Verb, algorithm: KeyAlgorithm) -> BTreeSet<KeyClass> {
    let classes: &[KeyClass] = if matches!(algorithm, KeyAlgorithm::Aes | KeyAlgorithm::Generic) {
        &[KeyClass::Secret]
    } else if matches!(verb, Verb::Encrypt | Verb::Verify) {
        &[KeyClass::Public, KeyClass::Certificate]
    } else {
        &[KeyClass::Private]
    };
    classes.iter().copied().collect()
}
/// ParamSpec::new("mechparam", ParamKind::Bytes, "Raw mechanism parameter bytes").
pub fn raw_mechparam_spec() -> ParamSpec {
    ParamSpec::new(
        "mechparam",
        ParamKind::Bytes,
        "Raw mechanism parameter bytes",
    )
}

/// 1:1 conversion of a YAML param entry (§4.8) into a ParamSpec (c2 `_param_from_config`):
/// name, kind, prompt, required, default (already typed at load), choices.
fn param_from_config(param: &ParamSpecConfig) -> ParamSpec {
    ParamSpec {
        name: param.name.clone(),
        kind: param.kind,
        prompt: param.prompt.clone(),
        required: param.required,
        default: param.default.clone(),
        default_from: None,
        choices: param.choices.clone(),
        length: None,
        validate: None,
        random: None, // §11 D30 covers the built-in rows only
    }
}
