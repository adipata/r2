// ProviderRegistry (spec §4.5.3, c2 providers/registry.py): every configured provider
// instance; the single place a textual key reference is resolved.
use std::cell::RefCell;
use std::rc::Rc;

use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{KeyInfo, parse_ref};

use crate::provider::Provider;
use crate::types::KeySelector;

/// Every configured provider instance; the single place a textual ref is resolved.
#[derive(Default)]
pub struct ProviderRegistry {
    /// Registration order. Never borrowed across a call into a provider.
    providers: RefCell<Vec<Rc<dyn Provider>>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    /// Duplicate name → Config "provider '{name}' is already registered"
    /// (hint "provider names must be unique across the configuration").
    pub fn register(&self, provider: Rc<dyn Provider>) -> Result<()> {
        let name = provider.name().to_owned();
        let taken = self
            .snapshot()
            .iter()
            .any(|existing| existing.name() == name);
        if taken {
            return Err(
                ConsoleError::config(format!("provider '{name}' is already registered"))
                    .with_hint("provider names must be unique across the configuration"),
            );
        }
        self.providers.borrow_mut().push(provider);
        Ok(())
    }
    /// Unknown → ProviderNotFound "unknown provider '{name}'" (hint "known providers:
    /// {names joined ', '}" in REGISTRATION order — not `all()`'s memory-first order — or
    /// "known providers: (none registered)").
    pub fn get(&self, name: &str) -> Result<Rc<dyn Provider>> {
        let providers = self.snapshot();
        if let Some(found) = providers.iter().find(|provider| provider.name() == name) {
            return Ok(Rc::clone(found));
        }
        let known = if providers.is_empty() {
            "(none registered)".to_owned()
        } else {
            providers
                .iter()
                .map(|provider| provider.name().to_owned())
                .collect::<Vec<_>>()
                .join(", ")
        };
        Err(
            ConsoleError::provider_not_found(format!("unknown provider '{name}'"))
                .with_hint(format!("known providers: {known}")),
        )
    }
    /// Registration (= config) order, stable-sorted so type "memory" comes first.
    pub fn all(&self) -> Vec<Rc<dyn Provider>> {
        let mut providers = self.snapshot();
        providers.sort_by_key(|provider| provider.type_name() != "memory");
        providers
    }
    /// `r2_core::keys::parse_ref` + get + find_key; never a second parser.
    pub fn resolve_ref(&self, reference: &str) -> Result<(Rc<dyn Provider>, KeyInfo)> {
        let parsed = parse_ref(reference)?;
        let provider = self.get(&parsed.provider)?;
        let info = provider.find_key(&KeySelector::from(&parsed))?;
        Ok((provider, info))
    }

    /// A copy of the provider list, so no borrow is held while a provider is called.
    fn snapshot(&self) -> Vec<Rc<dyn Provider>> {
        self.providers.borrow().clone()
    }
}
