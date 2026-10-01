#![allow(dead_code)]
// R0 skeleton — owner R3 (generated from spec §4)
// ---- spec §4.5.3 block 0
use std::rc::Rc;

use r2_core::error::Result;
use r2_core::keys::KeyInfo;

use crate::provider::Provider;

/// Every configured provider instance; the single place a textual ref is resolved.
#[derive(Default)]
pub struct ProviderRegistry {}

impl ProviderRegistry {
    pub fn new() -> Self {
        unimplemented!("R3")
    }
    /// Duplicate name → Config "provider '{name}' is already registered"
    /// (hint "provider names must be unique across the configuration").
    pub fn register(&self, provider: Rc<dyn Provider>) -> Result<()> {
        let _ = provider;
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    /// Unknown → ProviderNotFound "unknown provider '{name}'" (hint "known providers:
    /// {names joined ', '}" in REGISTRATION order — not `all()`'s memory-first order — or
    /// "known providers: (none registered)").
    pub fn get(&self, name: &str) -> Result<Rc<dyn Provider>> {
        let _ = name;
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    /// Registration (= config) order, stable-sorted so type "memory" comes first.
    pub fn all(&self) -> Vec<Rc<dyn Provider>> {
        unimplemented!("R3")
    }
    /// `r2_core::keys::parse_ref` + get + find_key; never a second parser.
    pub fn resolve_ref(&self, reference: &str) -> Result<(Rc<dyn Provider>, KeyInfo)> {
        let _ = reference;
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
}
