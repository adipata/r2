#![allow(dead_code)]
// R0 skeleton — owner R7 (generated from spec §4)
// ---- spec §4.9.11 block 0
use r2_config::model::AppConfig;
use r2_provider::ProviderRegistry;
use std::collections::BTreeMap;
/// `{entry.ckm: entry.id}` handed to every Pkcs11Provider (§4.6).
pub fn custom_ckm_map(config: &AppConfig) -> BTreeMap<u64, String> {
    let _ = config;
    unimplemented!("R7")
}
/// Memory (when enabled), every providers.pkcs11 instance (`Pkcs11Provider::new`), then —
/// ONLY when `softhsm.autodetect` is true — the SoftHSM autodetect instance: skipped with
/// an info log "softhsm autodetect skipped: provider {name!r} already configured" when the
/// name is taken by a registered provider (never an error); else
/// `find_softhsm_module(search_paths)` → `Pkcs11Provider::new(name,
/// Pkcs11InstanceConfig::new(name, path), …)`, or a debug log "softhsm autodetect: no
/// module found in search paths" when it returns None. Never loads a library (§6).
pub fn build_provider_registry(config: &AppConfig) -> r2_core::Result<ProviderRegistry> {
    let _ = config;
    Err(r2_core::ConsoleError::not_implemented("R7"))
}
