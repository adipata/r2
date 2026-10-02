// OperationRegistry and register_builtins (spec §4.6.2, owner R3; c2 ops/registry.py and
// `app.build_operation_registry`).
use std::collections::BTreeSet;

use indexmap::IndexMap;
use r2_config::model::CustomMechanismConfig;
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::KeyInfo;
use r2_core::text::close_matches;
use r2_provider::Provider;

use crate::model::{OperationSpec, Verb};

/// Insertion-ordered (registration order = iteration order of available_for).
#[derive(Clone, Debug, Default)]
pub struct OperationRegistry {
    specs: IndexMap<String, OperationSpec>,
}

impl OperationRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    /// Duplicate id → Config "operation '{id}' is already registered" (hint "operation ids
    /// (built-in and custom_mechanisms[].id) must be unique").
    pub fn register(&mut self, spec: OperationSpec) -> Result<()> {
        if self.specs.contains_key(&spec.id) {
            return Err(ConsoleError::config(format!(
                "operation '{}' is already registered",
                spec.id
            ))
            .with_hint("operation ids (built-in and custom_mechanisms[].id) must be unique"));
        }
        tracing::debug!(target: "r2::ops", id = %spec.id, "registered operation");
        self.specs.insert(spec.id.clone(), spec);
        Ok(())
    }
    /// Unknown → UnknownOperation "unknown operation '{id}'" (hint = suggestion over all ids).
    pub fn get(&self, op_id: &str) -> Result<&OperationSpec> {
        self.specs.get(op_id).ok_or_else(|| {
            let known: Vec<&str> = self.specs.keys().map(String::as_str).collect();
            ConsoleError::unknown_operation(format!("unknown operation '{op_id}'"))
                .with_hint(suggest_hint(op_id, &known))
        })
    }
    /// (verb, key.algorithm, cli_name) → the FIRST spec in registration order with that
    /// verb and algorithm whose `curves` admit key.curve and whose cli_name matches
    /// (key_class is NOT checked here; so a custom mechanism reusing a built-in cli_name for
    /// the same verb and algorithm is shadowed by the built-in, as in c2). Miss →
    /// UnknownOperation "no {verb} operation '{cli}' for {algorithm} keys" + " (curve {c})"
    /// when the key has a curve; hint = suggestion over those candidates' cli names.
    /// CERTIFICATE keys resolve as their public-key algorithm (their KeyInfo.algorithm).
    pub fn resolve_cli(&self, verb: Verb, key: &KeyInfo, cli_name: &str) -> Result<&OperationSpec> {
        let candidates: Vec<&OperationSpec> = self
            .specs
            .values()
            .filter(|spec| {
                spec.verb == verb && spec.algorithm == key.algorithm && curve_admitted(spec, key)
            })
            .collect();
        if let Some(spec) = candidates.iter().find(|spec| spec.cli_name == cli_name) {
            return Ok(spec);
        }
        let curve = key
            .curve
            .as_ref()
            .map(|curve| format!(" (curve {curve})"))
            .unwrap_or_default();
        let names: BTreeSet<&str> = candidates
            .iter()
            .map(|spec| spec.cli_name.as_str())
            .collect();
        let names: Vec<&str> = names.into_iter().collect();
        Err(ConsoleError::unknown_operation(format!(
            "no {} operation '{cli_name}' for {} keys{curve}",
            verb.as_str(),
            key.algorithm.as_str()
        ))
        .with_hint(suggest_hint(cli_name, &names)))
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
        let mechanisms = provider.mechanisms();
        let type_name = provider.type_name();
        let name = provider.name();
        self.specs
            .values()
            .filter(|spec| {
                spec.verb == verb
                    && spec.algorithm == key.algorithm
                    && spec.key_classes.contains(&key.key_class)
                    && spec
                        .provider_types
                        .as_ref()
                        .is_none_or(|types| types.contains(type_name))
                    && spec
                        .providers
                        .as_ref()
                        .is_none_or(|names| names.contains(name))
                    && curve_admitted(spec, key)
                    && mechanisms.contains(&spec.mechanism)
            })
            .collect()
    }
    /// Register every config-defined vendor mechanism (custom::spec_from_config).
    pub fn load_custom(&mut self, entries: &[CustomMechanismConfig]) -> Result<()> {
        for entry in entries {
            self.register(crate::custom::spec_from_config(entry))?;
        }
        Ok(())
    }
}

/// c2 `spec.curves is None or key.curve in spec.curves` (a key without a curve never
/// matches a curve-restricted spec).
fn curve_admitted(spec: &OperationSpec, key: &KeyInfo) -> bool {
    match &spec.curves {
        None => true,
        Some(curves) => key
            .curve
            .as_ref()
            .is_some_and(|curve| curves.contains(curve)),
    }
}

/// Suggestion hint shared by get/resolve_cli: names sorted; none → "no operations are
/// registered for this verb and key type"; close matches (n=3) → "did you mean: a, b";
/// else "valid choices: {all joined ', '}".
pub fn suggest_hint(wanted: &str, known: &[&str]) -> String {
    let mut names: Vec<&str> = known.to_vec();
    names.sort_unstable();
    if names.is_empty() {
        return "no operations are registered for this verb and key type".to_owned();
    }
    let matches = close_matches(wanted, &names, 3);
    if matches.is_empty() {
        format!("valid choices: {}", names.join(", "))
    } else {
        format!("did you mean: {}", matches.join(", "))
    }
}

/// Applies builtin_aes, builtin_rsa, builtin_ec, builtin_generic (in this order); each of
/// those modules exports `pub fn register_builtin(reg: &mut OperationRegistry) -> Result<()>`.
pub fn register_builtins(reg: &mut OperationRegistry) -> Result<()> {
    crate::builtin_aes::register_builtin(reg)?;
    crate::builtin_rsa::register_builtin(reg)?;
    crate::builtin_ec::register_builtin(reg)?;
    crate::builtin_generic::register_builtin(reg)
}

/// The bootstrap sequence: register_builtins then load_custom(custom). Used by r2-cli and
/// by the console test support (§4.10.6).
pub fn build_operation_registry(custom: &[CustomMechanismConfig]) -> Result<OperationRegistry> {
    let mut registry = OperationRegistry::new();
    register_builtins(&mut registry)?;
    registry.load_custom(custom)?;
    Ok(registry)
}
