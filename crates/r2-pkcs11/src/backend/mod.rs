//! The PKCS#11 backend seam (spec §4.5.6; crate-private, owner R5a): raw-shaped and
//! r2-owned, implemented by CryptokiBackend (real) and FakeBackend (tests).
use secrecy::SecretString;
use zeroize::Zeroizing;

/// One template entry: (CK_ATTRIBUTE_TYPE, value bytes). BOOL = 1 byte; ULONG =
/// native-endian CK_ULONG; STR = UTF-8; BYTES verbatim. Zeroizing: templates carry key
/// material on import/unwrap (D3).
pub(crate) type RawAttr = (u64, Zeroizing<Vec<u8>>);

/// The size-pass CKRs a one-attribute read reports as "no value" (`Ok(None)`) instead of
/// an error — PyKCS11 `getAttributeValue`/`getAttributeValue_fragmented` parity, which c2's
/// key listing, class/identity probes and export reads go through: TYPE_INVALID, SENSITIVE
/// and ARGUMENTS_BAD (§4.5.5 "Attribute reads").
pub(crate) fn is_attribute_refusal(code: u64) -> bool {
    matches!(
        code,
        crate::ckr::rv::CKR_ATTRIBUTE_TYPE_INVALID
            | crate::ckr::rv::CKR_ATTRIBUTE_SENSITIVE
            | crate::ckr::rv::CKR_ARGUMENTS_BAD
    )
}

/// A CK_RV failure with its call context (cryptoki `Function`, or the RawFns call name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ckr {
    pub code: u64,
    pub function: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BackendError {
    /// cryptoki `Error::Pkcs11(rv, function)` (code via the r2 RvError→CK_RV map: an
    /// exhaustive match or the reverse table built once from cryptoki-sys `CKR_*`;
    /// `RvError::VendorDefined(c)`/`UnknownErrorCode(c)` carry `c`), any RawFns CK_RV, and
    /// `Error::NullFunctionPointer` as CKR_FUNCTION_NOT_SUPPORTED.
    Ckr(Ckr),
    /// `Error::LibraryLoading` / `Error::MissingSymbol` → ProviderUnavailable "cannot load
    /// PKCS#11 library {library}: {detail}" (§5.2; detail = the libloading/cryptoki text, D11).
    LibraryUnavailable(String),
    /// Any other non-CKR cryptoki error (NotSupported, InvalidValue, conversion errors) →
    /// Pkcs11 "PKCS#11 {context} failed (CKR_0xFFFFFFFF)" with ckr_code 0xFFFF_FFFF — c2's
    /// rendering of PyKCS11's non-CKR errors (value −1); the detail is logged only.
    Binding(String),
}
pub(crate) type BResult<T> = std::result::Result<T, BackendError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawTokenInfo {
    pub slot_id: u64,
    /// label/manufacturer/model/serial: trailing ' ' and '\0' trimmed.
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    pub initialized: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UserKind {
    User,
    So,
}

/// r2-owned mechanism description; CryptokiBackend maps it per the S0 table:
/// native `Mechanism` variants for ECB, CBC, CBC_PAD, GCM, AesCMac, ShaXHmac, RsaPkcs,
/// ShaXRsaPkcs, RsaPkcsOaep, RsaPkcsPss/ShaXRsaPkcsPss, RsaX509, Ecdsa/EcdsaShaX, Eddsa,
/// Ecdh1Derive, AesKeyWrap, AesKeyWrapPad and the keygens; `Mechanism::VendorDefined(
/// VendorDefinedMechanism::new(mech_type(ckm), Some(&sized_struct)))` for AES-CTR
/// (CK_AES_CTR_PARAMS), CKM_AES_GMAC (GcmParams), CKM_AES_KEY_WRAP_KWP (no params),
/// CKM_SHA224_RSA_PKCS_PSS (PkcsPssParams) and the custom none/gcm/oaep packers; RawFns
/// crypto calls for `Bytes` (runtime-length parameters).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MechSpec {
    /// NULL pParameter.
    Plain { ckm: u64 },
    /// pParameter = `param` verbatim (CBC IV, custom `iv`/`raw` packers); empty → NULL.
    Bytes { ckm: u64, param: Vec<u8> },
    /// CK_GCM_PARAMS: owned IV copy, AAD always non-NULL (possibly empty; wiped on drop —
    /// the GCM-over-AAD GMAC carries the whole message here), ulTagBits, ulIvBits 0.
    Gcm {
        ckm: u64,
        iv: Vec<u8>,
        aad: Zeroizing<Vec<u8>>,
        tag_bits: u64,
    },
    /// CK_AES_CTR_PARAMS (CKM_AES_CTR): full 16-byte counter block.
    Ctr {
        counter_bits: u64,
        counter_block: [u8; 16],
    },
    /// CK_RSA_PKCS_OAEP_PARAMS, source = CKZ_DATA_SPECIFIED, empty label → NULL source data.
    Oaep {
        ckm: u64,
        hash_ckm: u64,
        mgf: u64,
        label: Vec<u8>,
    },
    /// CK_RSA_PKCS_PSS_PARAMS.
    Pss {
        ckm: u64,
        hash_ckm: u64,
        mgf: u64,
        salt_len: u64,
    },
    /// CK_ECDH1_DERIVE_PARAMS; `public_data` is the RAW point / u-coordinate (never DER).
    Ecdh1 {
        kdf: u64,
        shared_data: Vec<u8>,
        public_data: Vec<u8>,
    },
    /// Ed25519: NULL params (pure); Ed448: CK_EDDSA_PARAMS{phFlag=0, no context}.
    Eddsa { ckm: u64, ed448: bool },
}

/// One instance per Pkcs11Provider (it owns that provider's session). All `&self`.
pub(crate) trait Backend {
    /// Acquire the shared module for the library path (+ C_Initialize once). Idempotent.
    fn initialize(&self) -> BResult<()>;
    /// Drop this backend's session and release its module reference (last release
    /// finalizes). Safe when not initialized.
    fn finalize(&self) -> BResult<()>;
    /// True when no other backend holds the same module, keyed by canonical library path
    /// (§4.5.5; TokenInit::set_env_and_reset).
    fn is_sole_module_user(&self) -> bool;
    fn slots_with_token(&self) -> BResult<Vec<u64>>;
    fn token_info(&self, slot: u64) -> BResult<RawTokenInfo>;
    /// Unfiltered C_GetMechanismList (RawFns).
    fn mechanism_list(&self, slot: u64) -> BResult<Vec<u64>>;
    /// CKF_SERIAL_SESSION|CKF_RW_SESSION; replaces (closes) the current session.
    fn open_session(&self, slot: u64) -> BResult<()>;
    fn close_session(&self) -> BResult<()>;
    fn has_session(&self) -> bool;
    /// CKR_USER_ALREADY_LOGGED_IN is returned as an error; the provider swallows it.
    fn login(&self, user: UserKind, pin: &SecretString) -> BResult<()>;
    fn logout(&self) -> BResult<()>;
    /// `label` ≤ 32 bytes (validated by the provider), space-padded here.
    fn init_token(&self, slot: u64, so_pin: &SecretString, label: &str) -> BResult<()>;
    fn init_pin(&self, pin: &SecretString) -> BResult<()>;
    fn find_objects(&self, template: &[RawAttr]) -> BResult<Vec<u64>>;
    /// One attribute per call; None = sensitive, type-invalid, arguments-bad or unavailable.
    fn get_attr(&self, object: u64, attribute: u64) -> BResult<Option<Zeroizing<Vec<u8>>>>;
    /// One C_SetAttributeValue call (all-or-nothing).
    fn set_attrs(&self, object: u64, template: &[RawAttr]) -> BResult<()>;
    fn create_object(&self, template: &[RawAttr]) -> BResult<u64>;
    fn destroy_object(&self, object: u64) -> BResult<()>;
    fn generate_key(&self, mech: &MechSpec, template: &[RawAttr]) -> BResult<u64>;
    /// Returns (public handle, private handle).
    fn generate_key_pair(
        &self,
        mech: &MechSpec,
        public: &[RawAttr],
        private: &[RawAttr],
    ) -> BResult<(u64, u64)>;
    fn encrypt(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Vec<u8>>;
    /// C_EncryptInit + C_EncryptUpdate per part + C_EncryptFinal (GMAC-over-GCM fallback).
    fn encrypt_multipart(&self, mech: &MechSpec, key: u64, parts: &[&[u8]]) -> BResult<Vec<u8>>;
    fn decrypt(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Zeroizing<Vec<u8>>>;
    fn sign(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Vec<u8>>;
    /// CKR_SIGNATURE_INVALID / CKR_SIGNATURE_LEN_RANGE from C_Verify → Ok(false).
    fn verify(&self, mech: &MechSpec, key: u64, data: &[u8], signature: &[u8]) -> BResult<bool>;
    /// Always RawFns::wrap (second-call length truncation).
    fn wrap_key(&self, mech: &MechSpec, wrapping_key: u64, key: u64) -> BResult<Vec<u8>>;
    fn unwrap_key(
        &self,
        mech: &MechSpec,
        unwrapping_key: u64,
        wrapped: &[u8],
        template: &[RawAttr],
    ) -> BResult<u64>;
    fn derive_key(&self, mech: &MechSpec, base_key: u64, template: &[RawAttr]) -> BResult<u64>;
    /// C_GenerateRandom of `len` bytes on this backend's session, into a zeroizing buffer
    /// (§5.17). Never C_SeedRandom.
    fn generate_random(&self, len: usize) -> BResult<Zeroizing<Vec<u8>>>;
}

pub(crate) mod cryptoki;
#[cfg(test)]
pub(crate) mod fake;
pub(crate) mod raw;
