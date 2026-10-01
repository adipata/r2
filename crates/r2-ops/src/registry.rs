#![allow(dead_code)]
// R0 skeleton — owner R3 (generated from spec §4)
// ---- spec §4.6.2 block 1
use r2_config::model::CustomMechanismConfig;
use r2_core::error::Result;
use r2_core::keys::KeyInfo;
use r2_provider::Provider;

use crate::model::{OperationSpec, Verb};

/// Insertion-ordered (registration order = iteration order of available_for).
#[derive(Clone, Debug, Default)]
pub struct OperationRegistry {}

impl OperationRegistry {
    pub fn new() -> Self {
        unimplemented!("R3")
    }
    /// Duplicate id → Config "operation '{id}' is already registered" (hint "operation ids
    /// (built-in and custom_mechanisms[].id) must be unique").
    pub fn register(&mut self, spec: OperationSpec) -> Result<()> {
        let _ = spec;
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    /// Unknown → UnknownOperation "unknown operation '{id}'" (hint = suggestion over all ids).
    pub fn get(&self, op_id: &str) -> Result<&OperationSpec> {
        let _ = op_id;
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    /// (verb, key.algorithm, cli_name) → the FIRST spec in registration order with that
    /// verb and algorithm whose `curves` admit key.curve and whose cli_name matches
    /// (key_class is NOT checked here; so a custom mechanism reusing a built-in cli_name for
    /// the same verb and algorithm is shadowed by the built-in, as in c2). Miss →
    /// UnknownOperation "no {verb} operation '{cli}' for {algorithm} keys" + " (curve {c})"
    /// when the key has a curve; hint = suggestion over those candidates' cli names.
    /// CERTIFICATE keys resolve as their public-key algorithm (their KeyInfo.algorithm).
    pub fn resolve_cli(&self, verb: Verb, key: &KeyInfo, cli_name: &str) -> Result<&OperationSpec> {
        let _ = (verb, key, cli_name);
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    /// Specs with this verb and key.algorithm, key.key_class ∈ key_classes,
    /// provider.type_name() ∈ provider_types (when set), provider.name() ∈ providers (when
    /// set), key.curve ∈ curves (when set) AND mechanism ∈ provider.mechanisms();
    /// registration order (consumers that present specs sort them — see below).
    pub fn available_for(
        &self,
        verb: Verb,
        key: &KeyInfo,
        provider: &dyn Provider,
    ) -> Vec<&OperationSpec> {
        let _ = (verb, key, provider);
        unimplemented!("R3")
    }
    /// Register every config-defined vendor mechanism (custom::spec_from_config).
    pub fn load_custom(&mut self, entries: &[CustomMechanismConfig]) -> Result<()> {
        let _ = entries;
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
}

/// Suggestion hint shared by get/resolve_cli: names sorted; none → "no operations are
/// registered for this verb and key type"; close matches (n=3) → "did you mean: a, b";
/// else "valid choices: {all joined ', '}".
pub fn suggest_hint(wanted: &str, known: &[&str]) -> String {
    let _ = (wanted, known);
    unimplemented!("R3")
}

/// Applies builtin_aes, builtin_rsa, builtin_ec, builtin_generic (in this order); each of
/// those modules exports `pub fn register_builtin(reg: &mut OperationRegistry) -> Result<()>`.
pub fn register_builtins(reg: &mut OperationRegistry) -> Result<()> {
    let _ = reg;
    Err(r2_core::ConsoleError::not_implemented("R3"))
}

/// The bootstrap sequence: register_builtins then load_custom(custom). Used by r2-cli and
/// by the console test support (§4.10.6).
pub fn build_operation_registry(custom: &[CustomMechanismConfig]) -> Result<OperationRegistry> {
    let _ = custom;
    Err(r2_core::ConsoleError::not_implemented("R3"))
}
