#![allow(dead_code)]
// R0 skeleton — owner R3 (generated from spec §4)
use r2_core::error::Result;
use r2_core::keys::{KeyInfo, KeyMaterial};
use r2_core::template::KeyTemplate;
use r2_provider::*;
use secrecy::SecretString;
use std::rc::Rc;
use zeroize::Zeroizing;

/// The project-wide standard Provider double (frozen surface). Builders are named
/// `with_*` / `starting_*` so they never shadow the `Provider` methods of the same name in
/// method-call syntax (`fake.type_name()` / `fake.mechanisms()` stay the trait calls).
pub struct FakeProvider {}
impl FakeProvider {
    /// type_name "memory", mechanisms = all CANONICAL_MECHANISMS.
    pub fn new(name: &str) -> Self {
        let _ = name;
        unimplemented!("R3")
    }
    /// Builder: present as another type (copy-flow tests use "pkcs11"). Any type other than
    /// "memory" is login-capable and starts LoggedIn against the synthetic token
    /// TokenInfo{slot_id: 0, label: "{name}-token", manufacturer: "r2", model:
    /// "FakeProvider", serial: "FAKE0001"}.
    pub fn with_type_name(self, type_name: &str) -> Self {
        let _ = type_name;
        unimplemented!("R3")
    }
    /// Builder: advertised canonical names (replaces the default set).
    pub fn with_mechanisms<I, S>(self, mechanisms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let _ = mechanisms;
        unimplemented!("R3")
    }
    /// Builder: start LoggedOut (login-capable presentations only).
    pub fn starting_logged_out(self) -> Self {
        unimplemented!("R3")
    }
    /// Builder: `list_tokens()` returns these and `as_token_init()` becomes Some (§4.5.2):
    /// init_token(slot, label, …) requires a free token at `slot` (label "" and serial "";
    /// else Provider "no free slot {slot}") and replaces it with TokenInfo{slot_id: slot,
    /// label, manufacturer: "SoftHSM project", model: "SoftHSM v2", serial: 16 lower-case hex
    /// digits of a counter}; set_env_and_reset(key, value) records the call and runs
    /// shutdown() — it never touches the real environment.
    pub fn with_tokens(self, tokens: Vec<TokenInfo>) -> Self {
        let _ = tokens;
        unimplemented!("R3")
    }
    /// Builder: install fault-injection / observation hooks (replaces c2's "subclass
    /// FakeProvider in your own test file").
    pub fn with_hooks(self, hooks: Rc<dyn FakeHooks>) -> Self {
        let _ = hooks;
        unimplemented!("R3")
    }
    /// Recorded calls, c2's frozen encoding: [method_name, summaries…] (rules below).
    pub fn calls(&self) -> Vec<Vec<String>> {
        unimplemented!("R3")
    }
    pub fn clear_calls(&self) {
        unimplemented!("R3")
    }
    /// The sanctioned twin-fixture backdoor (c2 `_store_key`): stores without the duplicate
    /// guard and without recording a call.
    pub fn store_key_unchecked(
        &self,
        material: &KeyMaterial,
        label: &str,
        template: Option<&KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> KeyInfo {
        let _ = (material, label, template, key_id);
        unimplemented!("R3")
    }
}
impl r2_provider::Provider for FakeProvider {
    fn name(&self) -> &str {
        unimplemented!("R3")
    }
    fn type_name(&self) -> &str {
        unimplemented!("R3")
    }
    fn initialize(&self) -> r2_core::Result<()> {
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn shutdown(&self) -> r2_core::Result<()> {
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn status(&self) -> r2_provider::ProviderStatus {
        unimplemented!("R3")
    }
    fn mechanisms(&self) -> std::collections::BTreeSet<String> {
        unimplemented!("R3")
    }
    fn list_keys(&self) -> r2_core::Result<Vec<r2_core::keys::KeyInfo>> {
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn find_key(
        &self,
        selector: &r2_provider::KeySelector,
    ) -> r2_core::Result<r2_core::keys::KeyInfo> {
        let _ = selector;
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn import_key(
        &self,
        material: &r2_core::keys::KeyMaterial,
        label: &str,
        template: Option<&r2_core::template::KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> r2_core::Result<r2_core::keys::KeyInfo> {
        let _ = (material, label, template, key_id);
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn generate_key(
        &self,
        request: &r2_provider::GenerateRequest,
    ) -> r2_core::Result<r2_core::keys::KeyInfo> {
        let _ = request;
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn delete_key(&self, key: &r2_core::keys::KeyInfo) -> r2_core::Result<()> {
        let _ = key;
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn export_key(
        &self,
        key: &r2_core::keys::KeyInfo,
    ) -> r2_core::Result<r2_core::keys::KeyMaterial> {
        let _ = key;
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn encrypt(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        data: &[u8],
    ) -> r2_core::Result<Vec<u8>> {
        let _ = (key, mech, data);
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn decrypt(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        data: &[u8],
    ) -> r2_core::Result<zeroize::Zeroizing<Vec<u8>>> {
        let _ = (key, mech, data);
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn sign(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        data: &[u8],
    ) -> r2_core::Result<Vec<u8>> {
        let _ = (key, mech, data);
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn verify(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> r2_core::Result<bool> {
        let _ = (key, mech, data, signature);
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn derive(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
    ) -> r2_core::Result<r2_provider::DeriveResult> {
        let _ = (key, mech);
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
impl r2_provider::TokenInit for FakeProvider {
    fn init_token(
        &self,
        slot: u64,
        label: &str,
        so_pin: &secrecy::SecretString,
        user_pin: &secrecy::SecretString,
    ) -> r2_core::Result<()> {
        let _ = (slot, label, so_pin, user_pin);
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
    fn set_env_and_reset(&self, key: &str, value: &str) -> r2_core::Result<()> {
        let _ = (key, value);
        Err(r2_core::ConsoleError::not_implemented("R3"))
    }
}

/// Per-method overrides. Each method returns None = "not overridden" (the fake's own
/// behavior runs, and records the call) or Some(result) (returned as is; nothing is
/// recorded unless the hook delegates). `next` is a borrowed un-hooked view of the same
/// fake, so a hook can observe and delegate (c2 `super().method(...)`); `next.as_any()`
/// returns the FakeProvider itself. Dispatch rules (c2 virtual-dispatch parity):
/// FakeProvider's own internal calls — `set_env_and_reset` → `shutdown`, `unwrap_key` →
/// the import path, capability checks → `mechanisms()`, also when they happen inside a
/// `next.*` call — go through the HOOKED surface (a hook overriding `shutdown` sees the
/// shutdown that `set_env_and_reset` triggers); no RefCell borrow is held while a hook or
/// `next` runs.
#[allow(unused_variables)]
pub trait FakeHooks {
    fn initialize(&self, next: &dyn Provider) -> Option<Result<()>> {
        None
    }
    fn shutdown(&self, next: &dyn Provider) -> Option<Result<()>> {
        None
    }
    fn status(&self, next: &dyn Provider) -> Option<ProviderStatus> {
        None
    }
    fn list_tokens(&self, next: &dyn Provider) -> Option<Result<Vec<TokenInfo>>> {
        None
    }
    fn login(
        &self,
        next: &dyn Provider,
        token: &TokenInfo,
        pin: &SecretString,
        keep_pin: bool,
    ) -> Option<Result<()>> {
        None
    }
    fn logout(&self, next: &dyn Provider) -> Option<Result<()>> {
        None
    }
    fn mechanisms(&self, next: &dyn Provider) -> Option<std::collections::BTreeSet<String>> {
        None
    }
    fn list_keys(&self, next: &dyn Provider) -> Option<Result<Vec<KeyInfo>>> {
        None
    }
    fn find_key(&self, next: &dyn Provider, selector: &KeySelector) -> Option<Result<KeyInfo>> {
        None
    }
    fn import_key(
        &self,
        next: &dyn Provider,
        material: &KeyMaterial,
        label: &str,
        template: Option<&KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> Option<Result<KeyInfo>> {
        None
    }
    fn generate_key(
        &self,
        next: &dyn Provider,
        request: &GenerateRequest,
    ) -> Option<Result<KeyInfo>> {
        None
    }
    fn delete_key(&self, next: &dyn Provider, key: &KeyInfo) -> Option<Result<()>> {
        None
    }
    fn export_key(&self, next: &dyn Provider, key: &KeyInfo) -> Option<Result<KeyMaterial>> {
        None
    }
    fn encrypt(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Option<Result<Vec<u8>>> {
        None
    }
    fn decrypt(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Option<Result<Zeroizing<Vec<u8>>>> {
        None
    }
    fn sign(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Option<Result<Vec<u8>>> {
        None
    }
    fn verify(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> Option<Result<bool>> {
        None
    }
    fn derive(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
        mech: &MechanismInvocation,
    ) -> Option<Result<DeriveResult>> {
        None
    }
    fn wrap_key(
        &self,
        next: &dyn Provider,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        target: &KeyInfo,
        options: &WrapOptions,
    ) -> Option<Result<Vec<u8>>> {
        None
    }
    fn unwrap_key(
        &self,
        next: &dyn Provider,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        wrapped: &[u8],
        request: &UnwrapRequest,
    ) -> Option<Result<KeyInfo>> {
        None
    }
    fn read_key_template(&self, next: &dyn Provider, key: &KeyInfo) -> Option<Result<KeyTemplate>> {
        None
    }
    fn update_key(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
        changes: &KeyTemplate,
    ) -> Option<Result<KeyEditResult>> {
        None
    }
    fn read_full_template(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
    ) -> Option<Result<KeyTemplate>> {
        None
    }
    fn init_token(
        &self,
        next: &dyn Provider,
        slot: u64,
        label: &str,
        so_pin: &SecretString,
        user_pin: &SecretString,
    ) -> Option<Result<()>> {
        None
    }
    fn set_env_and_reset(&self, next: &dyn Provider, key: &str, value: &str) -> Option<Result<()>> {
        None
    }
}
