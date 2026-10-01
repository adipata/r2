#![allow(dead_code)]
// R0 skeleton — owner R5a (generated from spec §4)
// ---- spec §4.10.4 block 0
use secrecy::SecretString;
use zeroize::Zeroizing;

use super::{BResult, Backend, MechSpec, RawAttr, RawTokenInfo, UserKind};

pub(crate) struct FakeBackend {}
impl FakeBackend {
    /// One slot 0 holding an initialized token (label "fake-token", serial "FAKE0001",
    /// user PIN "1234", SO PIN "4321") and DEFAULT_MECHANISMS.
    pub(crate) fn new() -> Self {
        unimplemented!("R5a")
    }
    /// Replace the slot set: (slot id, token info, mechanism codes).
    pub(crate) fn with_slots(slots: Vec<(u64, RawTokenInfo, Vec<u64>)>) -> Self {
        let _ = slots;
        unimplemented!("R5a")
    }
    /// Inject `rv` for the next call of the named Backend method (e.g. "login",
    /// "unwrap_key"); `fail_always` for every call until cleared.
    pub(crate) fn fail_next(&self, method: &'static str, rv: u64) {
        let _ = (method, rv);
        unimplemented!("R5a")
    }
    pub(crate) fn fail_always(&self, method: &'static str, rv: u64) {
        let _ = (method, rv);
        unimplemented!("R5a")
    }
    pub(crate) fn clear_failures(&self) {
        unimplemented!("R5a")
    }
    /// The next session-bound call fails with CKR_SESSION_HANDLE_INVALID (auto-recovery tests).
    pub(crate) fn invalidate_session(&self) {
        unimplemented!("R5a")
    }
    /// Attribute types that C_SetAttributeValue refuses with CKR_ATTRIBUTE_READ_ONLY
    /// (CKA_SENSITIVE true→false / CKA_EXTRACTABLE false→true one-direction rules are built in).
    pub(crate) fn set_read_only(&self, attrs: &[u64]) {
        let _ = attrs;
        unimplemented!("R5a")
    }
    /// Backend method names called, in order.
    pub(crate) fn calls(&self) -> Vec<&'static str> {
        unimplemented!("R5a")
    }
    /// Stored objects: (handle, attribute map) — copies for assertions (test-only data).
    pub(crate) fn objects(&self) -> Vec<(u64, std::collections::BTreeMap<u64, Vec<u8>>)> {
        unimplemented!("R5a")
    }
    /// The last MechSpec handed to a crypto call (packer tests).
    pub(crate) fn last_mechanism(&self) -> Option<MechSpec> {
        unimplemented!("R5a")
    }
}
impl Backend for FakeBackend {
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
/// SoftHSM-like CKM set (c2 fake_pykcs11 DEFAULT_MECHANISMS, as codes; numeric order).
pub(crate) const DEFAULT_MECHANISMS: &[u64] = &[
    0x0000, // CKM_RSA_PKCS_KEY_PAIR_GEN
    0x0001, // CKM_RSA_PKCS
    0x0003, // CKM_RSA_X_509
    0x0009, // CKM_RSA_PKCS_OAEP
    0x000D, // CKM_RSA_PKCS_PSS
    0x0040, // CKM_SHA256_RSA_PKCS
    0x0043, // CKM_SHA256_RSA_PKCS_PSS
    0x0221, // CKM_SHA_1_HMAC
    0x0251, // CKM_SHA256_HMAC
    0x0256, // CKM_SHA224_HMAC
    0x0261, // CKM_SHA384_HMAC
    0x0271, // CKM_SHA512_HMAC
    0x0350, // CKM_GENERIC_SECRET_KEY_GEN
    0x1040, // CKM_EC_KEY_PAIR_GEN
    0x1041, // CKM_ECDSA
    0x1044, // CKM_ECDSA_SHA256
    0x1050, // CKM_ECDH1_DERIVE
    0x1055, // CKM_EC_EDWARDS_KEY_PAIR_GEN
    0x1057, // CKM_EDDSA
    0x1080, // CKM_AES_KEY_GEN
    0x1081, // CKM_AES_ECB
    0x1082, // CKM_AES_CBC
    0x1085, // CKM_AES_CBC_PAD
    0x1086, // CKM_AES_CTR
    0x1087, // CKM_AES_GCM
    0x108A, // CKM_AES_CMAC
    0x2109, // CKM_AES_KEY_WRAP
    0x210A, // CKM_AES_KEY_WRAP_PAD
];
