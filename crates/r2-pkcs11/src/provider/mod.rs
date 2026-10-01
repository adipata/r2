#![allow(dead_code)]
// R0 skeleton — owner R5a (generated from spec §4)
// ---- spec §4.5.5 block 1
use indexmap::IndexMap;
use r2_config::model::{CustomAttributeDef, Pkcs11InstanceConfig};
use std::collections::BTreeMap;

pub struct Pkcs11Provider {}
impl Pkcs11Provider {
    /// Never touches the library (lazy initialize, §6). `custom_mechanisms` = the plain map
    /// {entry.ckm: entry.id} from config (§4.6); `custom_attributes` =
    /// templates.custom_attributes (§4.8).
    pub fn new(
        name: &str,
        config: Pkcs11InstanceConfig,
        custom_mechanisms: BTreeMap<u64, String>,
        custom_attributes: IndexMap<String, CustomAttributeDef>,
    ) -> Self {
        let _ = (name, config, custom_mechanisms, custom_attributes);
        unimplemented!("R5a")
    }
    /// = TokenInit::init_token (kept inherent for parity with c2's surface).
    pub fn init_token(
        &self,
        slot: u64,
        label: &str,
        so_pin: &secrecy::SecretString,
        user_pin: &secrecy::SecretString,
    ) -> r2_core::Result<()> {
        let _ = (slot, label, so_pin, user_pin);
        Err(r2_core::ConsoleError::not_implemented("R5a"))
    }
    /// FakeBackend constructor for r2-pkcs11's own tests (§4.10.4).
    #[cfg(test)]
    pub(crate) fn with_backend(
        name: &str,
        config: Pkcs11InstanceConfig,
        custom_mechanisms: BTreeMap<u64, String>,
        custom_attributes: IndexMap<String, CustomAttributeDef>,
        backend: std::rc::Rc<dyn crate::backend::Backend>,
    ) -> Self {
        let _ = (name, config, custom_mechanisms, custom_attributes, backend);
        unimplemented!("R5a")
    }
}
impl r2_provider::Provider for Pkcs11Provider {
    fn name(&self) -> &str {
        unimplemented!("R5a")
    }
    fn type_name(&self) -> &str {
        unimplemented!("R5a")
    }
    fn initialize(&self) -> r2_core::Result<()> {
        Err(r2_core::ConsoleError::not_implemented("R5a"))
    }
    fn shutdown(&self) -> r2_core::Result<()> {
        Err(r2_core::ConsoleError::not_implemented("R5a"))
    }
    fn status(&self) -> r2_provider::ProviderStatus {
        unimplemented!("R5a")
    }
    fn mechanisms(&self) -> std::collections::BTreeSet<String> {
        unimplemented!("R5a")
    }
    fn list_keys(&self) -> r2_core::Result<Vec<r2_core::keys::KeyInfo>> {
        Err(r2_core::ConsoleError::not_implemented("R5a"))
    }
    fn find_key(
        &self,
        selector: &r2_provider::KeySelector,
    ) -> r2_core::Result<r2_core::keys::KeyInfo> {
        let _ = selector;
        Err(r2_core::ConsoleError::not_implemented("R5a"))
    }
    fn import_key(
        &self,
        material: &r2_core::keys::KeyMaterial,
        label: &str,
        template: Option<&r2_core::template::KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> r2_core::Result<r2_core::keys::KeyInfo> {
        let _ = (material, label, template, key_id);
        Err(r2_core::ConsoleError::not_implemented("R5a"))
    }
    fn generate_key(
        &self,
        request: &r2_provider::GenerateRequest,
    ) -> r2_core::Result<r2_core::keys::KeyInfo> {
        let _ = request;
        Err(r2_core::ConsoleError::not_implemented("R5a"))
    }
    fn delete_key(&self, key: &r2_core::keys::KeyInfo) -> r2_core::Result<()> {
        let _ = key;
        Err(r2_core::ConsoleError::not_implemented("R5a"))
    }
    fn export_key(
        &self,
        key: &r2_core::keys::KeyInfo,
    ) -> r2_core::Result<r2_core::keys::KeyMaterial> {
        let _ = key;
        Err(r2_core::ConsoleError::not_implemented("R5a"))
    }
    fn encrypt(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        data: &[u8],
    ) -> r2_core::Result<Vec<u8>> {
        self.encrypt_impl(key, mech, data)
    }
    fn decrypt(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        data: &[u8],
    ) -> r2_core::Result<zeroize::Zeroizing<Vec<u8>>> {
        self.decrypt_impl(key, mech, data)
    }
    fn sign(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        data: &[u8],
    ) -> r2_core::Result<Vec<u8>> {
        self.sign_impl(key, mech, data)
    }
    fn verify(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> r2_core::Result<bool> {
        self.verify_impl(key, mech, data, signature)
    }
    fn derive(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
    ) -> r2_core::Result<r2_provider::DeriveResult> {
        self.derive_impl(key, mech)
    }
    fn wrap_key(
        &self,
        wrapping_key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        target: &r2_core::keys::KeyInfo,
        options: &r2_provider::WrapOptions,
    ) -> r2_core::Result<Vec<u8>> {
        self.wrap_key_impl(wrapping_key, mech, target, options)
    }
    fn unwrap_key(
        &self,
        wrapping_key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        wrapped: &[u8],
        request: &r2_provider::UnwrapRequest,
    ) -> r2_core::Result<r2_core::keys::KeyInfo> {
        self.unwrap_key_impl(wrapping_key, mech, wrapped, request)
    }
    fn read_key_template(
        &self,
        key: &r2_core::keys::KeyInfo,
    ) -> r2_core::Result<r2_core::template::KeyTemplate> {
        self.read_key_template_impl(key)
    }
    fn update_key(
        &self,
        key: &r2_core::keys::KeyInfo,
        changes: &r2_core::template::KeyTemplate,
    ) -> r2_core::Result<r2_provider::KeyEditResult> {
        self.update_key_impl(key, changes)
    }
    fn read_full_template(
        &self,
        key: &r2_core::keys::KeyInfo,
    ) -> r2_core::Result<r2_core::template::KeyTemplate> {
        self.read_full_template_impl(key)
    }
    fn as_token_init(&self) -> Option<&dyn r2_provider::TokenInit> {
        Some(self)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
impl r2_provider::TokenInit for Pkcs11Provider {
    fn init_token(
        &self,
        slot: u64,
        label: &str,
        so_pin: &secrecy::SecretString,
        user_pin: &secrecy::SecretString,
    ) -> r2_core::Result<()> {
        Pkcs11Provider::init_token(self, slot, label, so_pin, user_pin)
    }
    fn set_env_and_reset(&self, key: &str, value: &str) -> r2_core::Result<()> {
        let _ = (key, value);
        Err(r2_core::ConsoleError::not_implemented("R5a"))
    }
}

mod crypto;
mod edit;
mod objects;
mod wrap;
