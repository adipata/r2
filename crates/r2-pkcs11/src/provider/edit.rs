// R0 skeleton — owner R5b (generated from spec §4)
use r2_core::Result;
use r2_core::keys::KeyInfo;
use r2_core::template::KeyTemplate;
use r2_provider::*;

use super::Pkcs11Provider;

impl Pkcs11Provider {
    pub(crate) fn read_key_template_impl(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        let _ = key;
        Err(r2_core::ConsoleError::not_implemented("R5b"))
    }
    pub(crate) fn update_key_impl(
        &self,
        key: &KeyInfo,
        changes: &KeyTemplate,
    ) -> Result<KeyEditResult> {
        let _ = (key, changes);
        Err(r2_core::ConsoleError::not_implemented("R5b"))
    }
    pub(crate) fn read_full_template_impl(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        let _ = key;
        Err(r2_core::ConsoleError::not_implemented("R5b"))
    }
}
