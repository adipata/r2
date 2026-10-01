#![allow(dead_code)]
use secrecy::SecretString;
use zeroize::Zeroizing;

use super::{BResult, MechSpec, RawAttr, RawTokenInfo, UserKind};
// R0 skeleton — owner R5a (generated from spec §4)
// ---- spec §4.5.5 block 3
use cryptoki::mechanism::MechanismType;
use cryptoki::object::ObjectHandle;
use r2_config::model::Pkcs11InstanceConfig;

/// The real backend: cryptoki safe API + RawFns over the shared module of
/// `config.library`; never touches the library before `Backend::initialize`.
pub(crate) struct CryptokiBackend {}
impl CryptokiBackend {
    pub(crate) fn new(config: &Pkcs11InstanceConfig) -> Self {
        let _ = config;
        unimplemented!("R5a")
    }
}
impl super::Backend for CryptokiBackend {
    fn initialize(&self) -> BResult<()> {
        unimplemented!("R5a")
    }
    fn finalize(&self) -> BResult<()> {
        unimplemented!("R5a")
    }
    fn is_sole_module_user(&self) -> bool {
        unimplemented!("R5a")
    }
    fn slots_with_token(&self) -> BResult<Vec<u64>> {
        unimplemented!("R5a")
    }
    fn token_info(&self, slot: u64) -> BResult<RawTokenInfo> {
        let _ = slot;
        unimplemented!("R5a")
    }
    fn mechanism_list(&self, slot: u64) -> BResult<Vec<u64>> {
        let _ = slot;
        unimplemented!("R5a")
    }
    fn open_session(&self, slot: u64) -> BResult<()> {
        let _ = slot;
        unimplemented!("R5a")
    }
    fn close_session(&self) -> BResult<()> {
        unimplemented!("R5a")
    }
    fn has_session(&self) -> bool {
        unimplemented!("R5a")
    }
    fn login(&self, user: UserKind, pin: &SecretString) -> BResult<()> {
        let _ = (user, pin);
        unimplemented!("R5a")
    }
    fn logout(&self) -> BResult<()> {
        unimplemented!("R5a")
    }
    fn init_token(&self, slot: u64, so_pin: &SecretString, label: &str) -> BResult<()> {
        let _ = (slot, so_pin, label);
        unimplemented!("R5a")
    }
    fn init_pin(&self, pin: &SecretString) -> BResult<()> {
        let _ = pin;
        unimplemented!("R5a")
    }
    fn find_objects(&self, template: &[RawAttr]) -> BResult<Vec<u64>> {
        let _ = template;
        unimplemented!("R5a")
    }
    fn get_attr(&self, object: u64, attribute: u64) -> BResult<Option<Zeroizing<Vec<u8>>>> {
        let _ = (object, attribute);
        unimplemented!("R5a")
    }
    fn set_attrs(&self, object: u64, template: &[RawAttr]) -> BResult<()> {
        let _ = (object, template);
        unimplemented!("R5a")
    }
    fn create_object(&self, template: &[RawAttr]) -> BResult<u64> {
        let _ = template;
        unimplemented!("R5a")
    }
    fn destroy_object(&self, object: u64) -> BResult<()> {
        let _ = object;
        unimplemented!("R5a")
    }
    fn generate_key(&self, mech: &MechSpec, template: &[RawAttr]) -> BResult<u64> {
        let _ = (mech, template);
        unimplemented!("R5a")
    }
    fn generate_key_pair(
        &self,
        mech: &MechSpec,
        public: &[RawAttr],
        private: &[RawAttr],
    ) -> BResult<(u64, u64)> {
        let _ = (mech, public, private);
        unimplemented!("R5a")
    }
    fn encrypt(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Vec<u8>> {
        let _ = (mech, key, data);
        unimplemented!("R5a")
    }
    fn encrypt_multipart(&self, mech: &MechSpec, key: u64, parts: &[&[u8]]) -> BResult<Vec<u8>> {
        let _ = (mech, key, parts);
        unimplemented!("R5a")
    }
    fn decrypt(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Zeroizing<Vec<u8>>> {
        let _ = (mech, key, data);
        unimplemented!("R5a")
    }
    fn sign(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Vec<u8>> {
        let _ = (mech, key, data);
        unimplemented!("R5a")
    }
    fn verify(&self, mech: &MechSpec, key: u64, data: &[u8], signature: &[u8]) -> BResult<bool> {
        let _ = (mech, key, data, signature);
        unimplemented!("R5a")
    }
    fn wrap_key(&self, mech: &MechSpec, wrapping_key: u64, key: u64) -> BResult<Vec<u8>> {
        let _ = (mech, wrapping_key, key);
        unimplemented!("R5a")
    }
    fn unwrap_key(
        &self,
        mech: &MechSpec,
        unwrapping_key: u64,
        wrapped: &[u8],
        template: &[RawAttr],
    ) -> BResult<u64> {
        let _ = (mech, unwrapping_key, wrapped, template);
        unimplemented!("R5a")
    }
    fn derive_key(&self, mech: &MechSpec, base_key: u64, template: &[RawAttr]) -> BResult<u64> {
        let _ = (mech, base_key, template);
        unimplemented!("R5a")
    }
}
/// u64 → MechanismType: `CK_MECHANISM_TYPE::try_from(ckm)` (CK_ULONG is 32-bit on Windows;
/// overflow → `BackendError::Ckr(Ckr { code: CKR_MECHANISM_INVALID, function: "mech_type" })`),
/// then `transmute::<CK_MECHANISM_TYPE, MechanismType>` (audited unsafe site;
/// `MechanismType` is `#[repr(transparent)]` over `CK_MECHANISM_TYPE`).
pub(crate) fn mech_type(ckm: u64) -> BResult<MechanismType> {
    let _ = ckm;
    unimplemented!("R5a")
}
/// u64 → ObjectHandle: `CK_OBJECT_HANDLE::try_from(handle)` (overflow →
/// `Ckr { code: CKR_OBJECT_HANDLE_INVALID, function: "obj" }`), then the ONE
/// `ObjectHandle::new_from_raw` call (audited unsafe site, §4.1.3); every Backend method that
/// takes a handle goes through it. No handle cache.
pub(crate) fn obj(handle: u64) -> BResult<ObjectHandle> {
    let _ = handle;
    unimplemented!("R5a")
}
