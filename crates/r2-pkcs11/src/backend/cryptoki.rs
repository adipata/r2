//! CryptokiBackend — the real `Backend` over cryptoki 0.12.1 + RawFns (spec §4.5.5/§4.5.6).
//! Together with `crate::ckr` this is the single CKR choke point: every cryptoki error is
//! converted here into a raw `BackendError`.
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::OnceLock;

use cryptoki::error::{Error, Rv, RvError};
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki_sys as sys;
use r2_config::model::Pkcs11InstanceConfig;
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

use super::raw::{self, RawOp, SharedModule};
use super::{BResult, BackendError, Ckr, MechSpec, RawAttr, RawTokenInfo, UserKind};
use crate::ckr::rv;

/// The r2-owned RvError → CK_RV map: the reverse table built once by probing cryptoki's
/// forward map `Rv::from` over every code below 0x400 (all standard CKRs); vendor and
/// unknown codes carry their raw value.
pub(crate) fn rv_code(err: &RvError) -> u64 {
    static TABLE: OnceLock<Vec<(RvError, u64)>> = OnceLock::new();
    match err {
        RvError::VendorDefined(code) | RvError::UnknownErrorCode(code) => {
            crate::ulong_to_u64(*code)
        }
        other => TABLE
            .get_or_init(|| {
                (1..0x400u64)
                    .filter_map(|code| {
                        let ck = sys::CK_RV::try_from(code).ok()?;
                        match Rv::from(ck) {
                            Rv::Error(RvError::UnknownErrorCode(_)) | Rv::Ok => None,
                            Rv::Error(e) => Some((e, code)),
                        }
                    })
                    .collect()
            })
            .iter()
            .find(|(e, _)| e == other)
            .map_or(crate::ckr::BINDING_ERROR_CODE, |(_, code)| *code),
    }
}

/// cryptoki error → backend error (§4.5.6): CKRs keep their code, a NULL function pointer
/// is CKR_FUNCTION_NOT_SUPPORTED, library-load failures are LibraryUnavailable and every
/// other non-CKR error is a Binding error (c2's −1 code; the detail is logged only).
pub(crate) fn convert(err: Error, function: &'static str) -> BackendError {
    match err {
        Error::Pkcs11(rv_error, _) => BackendError::Ckr(Ckr {
            code: rv_code(&rv_error),
            function,
        }),
        Error::NullFunctionPointer => BackendError::Ckr(Ckr {
            code: rv::CKR_FUNCTION_NOT_SUPPORTED,
            function,
        }),
        Error::LibraryLoading(inner) => BackendError::LibraryUnavailable(inner.to_string()),
        Error::MissingSymbol(_) => BackendError::LibraryUnavailable(err.to_string()),
        other => BackendError::Binding(format!("{function}: {other}")),
    }
}

fn ckr(code: u64, function: &'static str) -> BackendError {
    BackendError::Ckr(Ckr { code, function })
}

/// u64 → MechanismType: `CK_MECHANISM_TYPE::try_from(ckm)` (CK_ULONG is 32-bit on Windows;
/// overflow → `BackendError::Ckr(Ckr { code: CKR_MECHANISM_INVALID, function: "mech_type" })`),
/// then `transmute::<CK_MECHANISM_TYPE, MechanismType>` (audited unsafe site;
/// `MechanismType` is `#[repr(transparent)]` over `CK_MECHANISM_TYPE`).
pub(crate) fn mech_type(ckm: u64) -> BResult<MechanismType> {
    let raw = sys::CK_MECHANISM_TYPE::try_from(ckm)
        .map_err(|_| ckr(rv::CKR_MECHANISM_INVALID, "mech_type"))?;
    #[allow(unsafe_code)]
    // SAFETY: MechanismType is `#[repr(transparent)]` over CK_MECHANISM_TYPE (cryptoki
    // documents it so that Vec<MechanismType> == Vec<CK_MECHANISM_TYPE>) and carries no
    // invariant beyond the integer; any CKM value is a valid MechanismType bit pattern.
    let mechanism = unsafe { std::mem::transmute::<sys::CK_MECHANISM_TYPE, MechanismType>(raw) };
    Ok(mechanism)
}

/// u64 → ObjectHandle: `CK_OBJECT_HANDLE::try_from(handle)` (overflow →
/// `Ckr { code: CKR_OBJECT_HANDLE_INVALID, function: "obj" }`), then the ONE
/// `ObjectHandle::new_from_raw` call (audited unsafe site, §4.1.3); every Backend method that
/// takes a handle goes through it. No handle cache.
pub(crate) fn obj(handle: u64) -> BResult<ObjectHandle> {
    let raw = sys::CK_OBJECT_HANDLE::try_from(handle)
        .map_err(|_| ckr(rv::CKR_OBJECT_HANDLE_INVALID, "obj"))?;
    #[allow(unsafe_code)]
    // SAFETY: `new_from_raw` is unsafe only by API policy: the handle came from this
    // module's find/create/generate/unwrap/derive results, or is the operator's `@<handle>`,
    // which the token itself validates (a bogus one is CKR_OBJECT_HANDLE_INVALID).
    let object = unsafe { ObjectHandle::new_from_raw(raw) };
    Ok(object)
}

fn widen(code: sys::CK_ULONG) -> u64 {
    crate::ulong_to_u64(code)
}

/// Raw `(type, bytes)` entries → cryptoki attributes (`Attribute::VendorDefined` maps back
/// to the type verbatim for every type, S0).
fn attributes(template: &[RawAttr]) -> BResult<Vec<Attribute>> {
    template
        .iter()
        .map(|(kind, value)| {
            let t = sys::CK_ATTRIBUTE_TYPE::try_from(*kind)
                .map_err(|_| ckr(rv::CKR_ATTRIBUTE_TYPE_INVALID, "attribute"))?;
            Ok(Attribute::VendorDefined((
                AttributeType::VendorDefined(t),
                value.to_vec(),
            )))
        })
        .collect()
}

/// Zeroize the value copies a template made (they may hold key material, D3).
fn wipe(mut attrs: Vec<Attribute>) {
    for attr in &mut attrs {
        if let Attribute::VendorDefined((_, value)) = attr {
            value.zeroize();
        }
    }
}

fn param_ulong(value: u64) -> BResult<sys::CK_ULONG> {
    sys::CK_ULONG::try_from(value).map_err(|_| ckr(rv::CKR_MECHANISM_PARAM_INVALID, "mechanism"))
}

fn len_ulong(len: usize) -> BResult<sys::CK_ULONG> {
    sys::CK_ULONG::try_from(len).map_err(|_| ckr(rv::CKR_MECHANISM_PARAM_INVALID, "mechanism"))
}

/// Native cryptoki variant of a parameterless CKM, if cryptoki has one.
fn native_plain(ckm: u64) -> Option<Mechanism<'static>> {
    let table: [(sys::CK_MECHANISM_TYPE, Mechanism<'static>); 33] = [
        (sys::CKM_AES_KEY_GEN, Mechanism::AesKeyGen),
        (
            sys::CKM_GENERIC_SECRET_KEY_GEN,
            Mechanism::GenericSecretKeyGen,
        ),
        (sys::CKM_RSA_PKCS_KEY_PAIR_GEN, Mechanism::RsaPkcsKeyPairGen),
        (sys::CKM_EC_KEY_PAIR_GEN, Mechanism::EccKeyPairGen),
        (
            sys::CKM_EC_EDWARDS_KEY_PAIR_GEN,
            Mechanism::EccEdwardsKeyPairGen,
        ),
        (
            sys::CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
            Mechanism::EccMontgomeryKeyPairGen,
        ),
        (sys::CKM_AES_ECB, Mechanism::AesEcb),
        (sys::CKM_AES_CMAC, Mechanism::AesCMac),
        (sys::CKM_AES_KEY_WRAP, Mechanism::AesKeyWrap),
        (sys::CKM_AES_KEY_WRAP_PAD, Mechanism::AesKeyWrapPad),
        (sys::CKM_SHA_1_HMAC, Mechanism::Sha1Hmac),
        (sys::CKM_SHA224_HMAC, Mechanism::Sha224Hmac),
        (sys::CKM_SHA256_HMAC, Mechanism::Sha256Hmac),
        (sys::CKM_SHA384_HMAC, Mechanism::Sha384Hmac),
        (sys::CKM_SHA512_HMAC, Mechanism::Sha512Hmac),
        (sys::CKM_RSA_PKCS, Mechanism::RsaPkcs),
        (sys::CKM_SHA1_RSA_PKCS, Mechanism::Sha1RsaPkcs),
        (sys::CKM_SHA224_RSA_PKCS, Mechanism::Sha224RsaPkcs),
        (sys::CKM_SHA256_RSA_PKCS, Mechanism::Sha256RsaPkcs),
        (sys::CKM_SHA384_RSA_PKCS, Mechanism::Sha384RsaPkcs),
        (sys::CKM_SHA512_RSA_PKCS, Mechanism::Sha512RsaPkcs),
        (sys::CKM_RSA_X_509, Mechanism::RsaX509),
        (sys::CKM_ECDSA, Mechanism::Ecdsa),
        (sys::CKM_ECDSA_SHA1, Mechanism::EcdsaSha1),
        (sys::CKM_ECDSA_SHA224, Mechanism::EcdsaSha224),
        (sys::CKM_ECDSA_SHA256, Mechanism::EcdsaSha256),
        (sys::CKM_ECDSA_SHA384, Mechanism::EcdsaSha384),
        (sys::CKM_ECDSA_SHA512, Mechanism::EcdsaSha512),
        (sys::CKM_SHA_1, Mechanism::Sha1),
        (sys::CKM_SHA224, Mechanism::Sha224),
        (sys::CKM_SHA256, Mechanism::Sha256),
        (sys::CKM_SHA384, Mechanism::Sha384),
        (sys::CKM_SHA512, Mechanism::Sha512),
    ];
    table
        .into_iter()
        .find(|(code, _)| widen(*code) == ckm)
        .map(|(_, m)| m)
}

/// `Some((ckm, param))` when the spec must go through RawFns (a runtime-length raw
/// parameter that is not a 16-byte AES-CBC IV, S0 G3).
fn raw_bytes(spec: &MechSpec) -> Option<(u64, &[u8])> {
    match spec {
        MechSpec::Bytes { ckm, param } => {
            let cbc = *ckm == widen(sys::CKM_AES_CBC) || *ckm == widen(sys::CKM_AES_CBC_PAD);
            if cbc && param.len() == 16 {
                None
            } else {
                Some((*ckm, param.as_slice()))
            }
        }
        _ => None,
    }
}

/// CK_GCM_PARAMS over `iv`/`aad` (both must outlive the struct's use). `ulIvBits` is 0, as
/// PyKCS11's `AES_GCM_Mechanism` sent it (it never sets the field; c2 parity — SoftHSM
/// ignores it, a token reading it sees what it saw from c2).
pub(crate) fn gcm_params(iv: &mut [u8], aad: &[u8], tag_bits: u64) -> BResult<sys::CK_GCM_PARAMS> {
    Ok(sys::CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: len_ulong(iv.len())?,
        ulIvBits: 0,
        pAAD: aad.as_ptr() as *mut sys::CK_BYTE,
        ulAADLen: len_ulong(aad.len())?,
        ulTagBits: param_ulong(tag_bits)?,
    })
}

/// Build the cryptoki `Mechanism` of `spec` in this frame (owned parameter copies and
/// cryptoki-sys parameter structs live here) and run `f` with it. Structured parameters go
/// through `VendorDefinedMechanism::new(mech_type(ckm), Some(&sys_struct))` with Sized
/// `repr(C)` cryptoki-sys structs only (§4.5.5 review rule); the wire layout equals the
/// native variants'.
fn with_mechanism<R>(spec: &MechSpec, f: impl FnOnce(&Mechanism<'_>) -> BResult<R>) -> BResult<R> {
    match spec {
        MechSpec::Plain { ckm } => match native_plain(*ckm) {
            Some(native) => f(&native),
            None => f(&Mechanism::VendorDefined(
                VendorDefinedMechanism::new::<()>(mech_type(*ckm)?, None),
            )),
        },
        MechSpec::Bytes { ckm, param } => {
            let mut iv = [0u8; 16];
            if param.len() == 16 {
                iv.copy_from_slice(param);
            }
            if *ckm == widen(sys::CKM_AES_CBC) && param.len() == 16 {
                f(&Mechanism::AesCbc(iv))
            } else if *ckm == widen(sys::CKM_AES_CBC_PAD) && param.len() == 16 {
                f(&Mechanism::AesCbcPad(iv))
            } else {
                Err(BackendError::Binding(
                    "a runtime-length raw mechanism parameter needs the RawFns path".into(),
                ))
            }
        }
        MechSpec::Gcm {
            ckm,
            iv,
            aad,
            tag_bits,
        } => {
            let mut iv_copy = iv.clone();
            let aad_copy = aad.clone();
            let params = gcm_params(&mut iv_copy, &aad_copy, *tag_bits)?;
            let mechanism = VendorDefinedMechanism::new(mech_type(*ckm)?, Some(&params));
            let result = f(&Mechanism::VendorDefined(mechanism));
            drop(iv_copy);
            drop(aad_copy); // Zeroizing: the authenticated data (a GMAC message) is wiped
            result
        }
        MechSpec::Ctr {
            counter_bits,
            counter_block,
        } => {
            let params = sys::CK_AES_CTR_PARAMS {
                ulCounterBits: param_ulong(*counter_bits)?,
                cb: *counter_block,
            };
            let mechanism =
                VendorDefinedMechanism::new(mech_type(widen(sys::CKM_AES_CTR))?, Some(&params));
            f(&Mechanism::VendorDefined(mechanism))
        }
        MechSpec::Oaep {
            ckm,
            hash_ckm,
            mgf,
            label,
        } => {
            let label_copy = label.clone();
            let (source_data, source_len) = if label_copy.is_empty() {
                (std::ptr::null_mut(), 0)
            } else {
                (
                    label_copy.as_ptr() as *mut std::ffi::c_void,
                    len_ulong(label_copy.len())?,
                )
            };
            let params = sys::CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: param_ulong(*hash_ckm)?,
                mgf: param_ulong(*mgf)?,
                source: sys::CKZ_DATA_SPECIFIED,
                pSourceData: source_data,
                ulSourceDataLen: source_len,
            };
            let mechanism = VendorDefinedMechanism::new(mech_type(*ckm)?, Some(&params));
            let result = f(&Mechanism::VendorDefined(mechanism));
            drop(label_copy);
            result
        }
        MechSpec::Pss {
            ckm,
            hash_ckm,
            mgf,
            salt_len,
        } => {
            let params = sys::CK_RSA_PKCS_PSS_PARAMS {
                hashAlg: param_ulong(*hash_ckm)?,
                mgf: param_ulong(*mgf)?,
                sLen: param_ulong(*salt_len)?,
            };
            let mechanism = VendorDefinedMechanism::new(mech_type(*ckm)?, Some(&params));
            f(&Mechanism::VendorDefined(mechanism))
        }
        MechSpec::Ecdh1 {
            kdf,
            shared_data,
            public_data,
        } => {
            let shared = shared_data.clone();
            let public = public_data.clone();
            let (shared_ptr, shared_len) = if shared.is_empty() {
                (std::ptr::null_mut(), 0)
            } else {
                (
                    shared.as_ptr() as *mut sys::CK_BYTE,
                    len_ulong(shared.len())?,
                )
            };
            let params = sys::CK_ECDH1_DERIVE_PARAMS {
                kdf: param_ulong(*kdf)?,
                ulSharedDataLen: shared_len,
                pSharedData: shared_ptr,
                ulPublicDataLen: len_ulong(public.len())?,
                pPublicData: public.as_ptr() as *mut sys::CK_BYTE,
            };
            let mechanism = VendorDefinedMechanism::new(
                mech_type(widen(sys::CKM_ECDH1_DERIVE))?,
                Some(&params),
            );
            let result = f(&Mechanism::VendorDefined(mechanism));
            drop(shared);
            drop(public);
            result
        }
        MechSpec::Eddsa { ckm, ed448 } => {
            if *ed448 {
                let params = sys::CK_EDDSA_PARAMS {
                    phFlag: 0,
                    ulContextDataLen: 0,
                    pContextData: std::ptr::null_mut(),
                };
                let mechanism = VendorDefinedMechanism::new(mech_type(*ckm)?, Some(&params));
                f(&Mechanism::VendorDefined(mechanism))
            } else {
                let mechanism = VendorDefinedMechanism::new::<()>(mech_type(*ckm)?, None);
                f(&Mechanism::VendorDefined(mechanism))
            }
        }
    }
}

/// The real backend: cryptoki safe API + RawFns over the shared module of
/// `config.library`; never touches the library before `Backend::initialize`.
pub(crate) struct CryptokiBackend {
    library: PathBuf,
    module: RefCell<Option<(PathBuf, Rc<SharedModule>)>>,
    session: RefCell<Option<Session>>,
}

impl CryptokiBackend {
    pub(crate) fn new(config: &Pkcs11InstanceConfig) -> Self {
        Self {
            library: config.library.clone(),
            module: RefCell::new(None),
            session: RefCell::new(None),
        }
    }

    fn module(&self) -> BResult<Rc<SharedModule>> {
        self.module
            .borrow()
            .as_ref()
            .map(|(_, module)| Rc::clone(module))
            .ok_or_else(|| ckr(rv::CKR_CRYPTOKI_NOT_INITIALIZED, "module"))
    }

    fn with_session<R>(
        &self,
        function: &'static str,
        f: impl FnOnce(&Session) -> BResult<R>,
    ) -> BResult<R> {
        let guard = self.session.borrow();
        let session = guard
            .as_ref()
            .ok_or_else(|| ckr(rv::CKR_SESSION_HANDLE_INVALID, function))?;
        f(session)
    }

    fn slot(slot: u64) -> BResult<Slot> {
        Slot::try_from(slot).map_err(|_| ckr(rv::CKR_SLOT_ID_INVALID, "slot"))
    }

    fn raw_handle(handle: u64) -> BResult<sys::CK_OBJECT_HANDLE> {
        Ok(obj(handle)?.handle())
    }

    /// Single-part encrypt/decrypt/sign through cryptoki or RawFns. Empty input always goes
    /// through RawFns, which runs only the Init and answers CKR_ARGUMENTS_BAD without calling
    /// the token, as PyKCS11 did (the operation stays active — c2 parity on every token).
    fn crypt(
        &self,
        op: RawOp,
        mech: &MechSpec,
        key: u64,
        data: &[u8],
    ) -> BResult<Zeroizing<Vec<u8>>> {
        let module = self.module()?;
        let key_handle = obj(key)?;
        self.with_session("crypt", |session| {
            if let Some((ckm, param)) = raw_bytes(mech) {
                let mechanism = raw::bytes_mechanism(ckm, param)?;
                return module.raw.crypt(
                    op,
                    session.handle(),
                    &mechanism,
                    key_handle.handle(),
                    data,
                );
            }
            with_mechanism(mech, |m| {
                if data.is_empty() {
                    let mechanism = sys::CK_MECHANISM::from(m);
                    return module.raw.crypt(
                        op,
                        session.handle(),
                        &mechanism,
                        key_handle.handle(),
                        data,
                    );
                }
                let out = match op {
                    RawOp::Encrypt => session
                        .encrypt(m, key_handle, data)
                        .map_err(|e| convert(e, "C_Encrypt")),
                    RawOp::Decrypt => session
                        .decrypt(m, key_handle, data)
                        .map_err(|e| convert(e, "C_Decrypt")),
                    RawOp::Sign => session
                        .sign(m, key_handle, data)
                        .map_err(|e| convert(e, "C_Sign")),
                }?;
                Ok(Zeroizing::new(out))
            })
        })
    }
}

fn is_signature_failure(err: &BackendError) -> bool {
    matches!(err, BackendError::Ckr(Ckr { code, .. })
        if *code == rv::CKR_SIGNATURE_INVALID || *code == rv::CKR_SIGNATURE_LEN_RANGE)
}

impl super::Backend for CryptokiBackend {
    fn initialize(&self) -> BResult<()> {
        if self.module.borrow().is_some() {
            return Ok(());
        }
        let acquired = raw::acquire(&self.library)?;
        *self.module.borrow_mut() = Some(acquired);
        Ok(())
    }

    fn finalize(&self) -> BResult<()> {
        let session = self.session.borrow_mut().take();
        drop(session);
        let module = self.module.borrow_mut().take();
        match module {
            Some((key, module)) => raw::release(&key, module),
            None => Ok(()),
        }
    }

    fn is_sole_module_user(&self) -> bool {
        let key = match self.module.borrow().as_ref() {
            Some((key, _)) => key.clone(),
            None => raw::registry_key(&self.library),
        };
        let mine = usize::from(self.module.borrow().is_some());
        raw::module_users(&key) <= mine
    }

    fn slots_with_token(&self) -> BResult<Vec<u64>> {
        let module = self.module()?;
        let slots = module
            .ctx
            .get_slots_with_token()
            .map_err(|e| convert(e, "C_GetSlotList"))?;
        Ok(slots.into_iter().map(|s| s.id()).collect())
    }

    fn token_info(&self, slot: u64) -> BResult<RawTokenInfo> {
        // Raw C_GetTokenInfo: cryptoki's TokenInfo conversion parses `utcTime` when
        // CKF_CLOCK_ON_TOKEN is set and fails on a non-digit clock (PyKCS11 never does).
        self.module()?.raw.token_info(slot)
    }

    fn mechanism_list(&self, slot: u64) -> BResult<Vec<u64>> {
        self.module()?.raw.mechanism_list(slot)
    }

    fn open_session(&self, slot: u64) -> BResult<()> {
        let module = self.module()?;
        let session = module
            .ctx
            .open_rw_session(Self::slot(slot)?)
            .map_err(|e| convert(e, "C_OpenSession"))?;
        let old = self.session.borrow_mut().replace(session);
        drop(old);
        Ok(())
    }

    fn close_session(&self) -> BResult<()> {
        let session = self.session.borrow_mut().take();
        match session {
            Some(session) => session.close().map_err(|e| convert(e, "C_CloseSession")),
            None => Ok(()),
        }
    }

    fn has_session(&self) -> bool {
        self.session.borrow().is_some()
    }

    fn login(&self, user: UserKind, pin: &SecretString) -> BResult<()> {
        let user_type = match user {
            UserKind::User => UserType::User,
            UserKind::So => UserType::So,
        };
        // PyKCS11 passes pPin=NULL for an empty PIN (the token answers CKR_ARGUMENTS_BAD
        // or uses its protected authentication path); cryptoki's `Some("")` would pass a
        // non-NULL pointer and spend a retry on CKR_PIN_INCORRECT.
        let pin = (!pin.expose_secret().is_empty()).then_some(pin);
        self.with_session("C_Login", |session| {
            session
                .login(user_type, pin)
                .map_err(|e| convert(e, "C_Login"))
        })
    }

    fn logout(&self) -> BResult<()> {
        self.with_session("C_Logout", |session| {
            session.logout().map_err(|e| convert(e, "C_Logout"))
        })
    }

    fn init_token(&self, slot: u64, so_pin: &SecretString, label: &str) -> BResult<()> {
        let module = self.module()?;
        module
            .ctx
            .init_token(Self::slot(slot)?, so_pin, label)
            .map_err(|e| convert(e, "C_InitToken"))
    }

    fn init_pin(&self, pin: &SecretString) -> BResult<()> {
        self.with_session("C_InitPIN", |session| {
            session.init_pin(pin).map_err(|e| convert(e, "C_InitPIN"))
        })
    }

    fn find_objects(&self, template: &[RawAttr]) -> BResult<Vec<u64>> {
        let attrs = attributes(template)?;
        let result = self.with_session("C_FindObjects", |session| {
            session
                .find_objects(&attrs)
                .map_err(|e| convert(e, "C_FindObjects"))
        });
        wipe(attrs);
        Ok(result?.into_iter().map(|h| widen(h.handle())).collect())
    }

    fn get_attr(&self, object: u64, attribute: u64) -> BResult<Option<Zeroizing<Vec<u8>>>> {
        let module = self.module()?;
        let handle = Self::raw_handle(object)?;
        self.with_session("C_GetAttributeValue", |session| {
            module.raw.get_attr(session.handle(), handle, attribute)
        })
    }

    fn set_attrs(&self, object: u64, template: &[RawAttr]) -> BResult<()> {
        let handle = obj(object)?;
        let attrs = attributes(template)?;
        let result = self.with_session("C_SetAttributeValue", |session| {
            session
                .update_attributes(handle, &attrs)
                .map_err(|e| convert(e, "C_SetAttributeValue"))
        });
        wipe(attrs);
        result
    }

    fn create_object(&self, template: &[RawAttr]) -> BResult<u64> {
        let attrs = attributes(template)?;
        let result = self.with_session("C_CreateObject", |session| {
            session
                .create_object(&attrs)
                .map_err(|e| convert(e, "C_CreateObject"))
        });
        wipe(attrs);
        Ok(widen(result?.handle()))
    }

    fn destroy_object(&self, object: u64) -> BResult<()> {
        let handle = obj(object)?;
        self.with_session("C_DestroyObject", |session| {
            session
                .destroy_object(handle)
                .map_err(|e| convert(e, "C_DestroyObject"))
        })
    }

    fn generate_key(&self, mech: &MechSpec, template: &[RawAttr]) -> BResult<u64> {
        let attrs = attributes(template)?;
        let result = self.with_session("C_GenerateKey", |session| {
            with_mechanism(mech, |m| {
                session
                    .generate_key(m, &attrs)
                    .map_err(|e| convert(e, "C_GenerateKey"))
            })
        });
        wipe(attrs);
        Ok(widen(result?.handle()))
    }

    fn generate_key_pair(
        &self,
        mech: &MechSpec,
        public: &[RawAttr],
        private: &[RawAttr],
    ) -> BResult<(u64, u64)> {
        let public_attrs = attributes(public)?;
        let private_attrs = attributes(private)?;
        let result = self.with_session("C_GenerateKeyPair", |session| {
            with_mechanism(mech, |m| {
                session
                    .generate_key_pair(m, &public_attrs, &private_attrs)
                    .map_err(|e| convert(e, "C_GenerateKeyPair"))
            })
        });
        wipe(public_attrs);
        wipe(private_attrs);
        let (public_handle, private_handle) = result?;
        Ok((
            widen(public_handle.handle()),
            widen(private_handle.handle()),
        ))
    }

    fn encrypt(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Vec<u8>> {
        Ok(self.crypt(RawOp::Encrypt, mech, key, data)?.to_vec())
    }

    fn encrypt_multipart(&self, mech: &MechSpec, key: u64, parts: &[&[u8]]) -> BResult<Vec<u8>> {
        let key_handle = obj(key)?;
        self.with_session("C_EncryptInit", |session| {
            with_mechanism(mech, |m| {
                session
                    .encrypt_init(m, key_handle)
                    .map_err(|e| convert(e, "C_EncryptInit"))?;
                let mut out = Vec::new();
                for part in parts {
                    out.extend(
                        session
                            .encrypt_update(part)
                            .map_err(|e| convert(e, "C_EncryptUpdate"))?,
                    );
                }
                out.extend(
                    session
                        .encrypt_final()
                        .map_err(|e| convert(e, "C_EncryptFinal"))?,
                );
                Ok(out)
            })
        })
    }

    fn decrypt(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Zeroizing<Vec<u8>>> {
        self.crypt(RawOp::Decrypt, mech, key, data)
    }

    fn sign(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Vec<u8>> {
        Ok(self.crypt(RawOp::Sign, mech, key, data)?.to_vec())
    }

    fn verify(&self, mech: &MechSpec, key: u64, data: &[u8], signature: &[u8]) -> BResult<bool> {
        let module = self.module()?;
        let key_handle = obj(key)?;
        let result = self.with_session("C_Verify", |session| {
            if let Some((ckm, param)) = raw_bytes(mech) {
                let mechanism = raw::bytes_mechanism(ckm, param)?;
                return module.raw.verify(
                    session.handle(),
                    &mechanism,
                    key_handle.handle(),
                    data,
                    signature,
                );
            }
            with_mechanism(mech, |m| {
                if data.is_empty() || signature.is_empty() {
                    // Init only, then CKR_ARGUMENTS_BAD as PyKCS11 did (see `crypt`)
                    let mechanism = sys::CK_MECHANISM::from(m);
                    return module.raw.verify(
                        session.handle(),
                        &mechanism,
                        key_handle.handle(),
                        data,
                        signature,
                    );
                }
                session
                    .verify(m, key_handle, data, signature)
                    .map_err(|e| convert(e, "C_Verify"))
            })
        });
        match result {
            Ok(()) => Ok(true),
            Err(err) if is_signature_failure(&err) => Ok(false),
            Err(err) => Err(err),
        }
    }

    fn wrap_key(&self, mech: &MechSpec, wrapping_key: u64, key: u64) -> BResult<Vec<u8>> {
        let module = self.module()?;
        let wrapping = Self::raw_handle(wrapping_key)?;
        let target = Self::raw_handle(key)?;
        self.with_session("C_WrapKey", |session| {
            if let Some((ckm, param)) = raw_bytes(mech) {
                let mechanism = raw::bytes_mechanism(ckm, param)?;
                return module
                    .raw
                    .wrap(session.handle(), &mechanism, wrapping, target);
            }
            with_mechanism(mech, |m| {
                let mechanism = sys::CK_MECHANISM::from(m);
                module
                    .raw
                    .wrap(session.handle(), &mechanism, wrapping, target)
            })
        })
    }

    fn unwrap_key(
        &self,
        mech: &MechSpec,
        unwrapping_key: u64,
        wrapped: &[u8],
        template: &[RawAttr],
    ) -> BResult<u64> {
        let module = self.module()?;
        let unwrapping = obj(unwrapping_key)?;
        self.with_session("C_UnwrapKey", |session| {
            if let Some((ckm, param)) = raw_bytes(mech) {
                let mechanism = raw::bytes_mechanism(ckm, param)?;
                return module.raw.unwrap(
                    session.handle(),
                    &mechanism,
                    unwrapping.handle(),
                    wrapped,
                    template,
                );
            }
            if wrapped.is_empty() {
                // CKR_ARGUMENTS_BAD without a token call, as PyKCS11 did
                return with_mechanism(mech, |m| {
                    let mechanism = sys::CK_MECHANISM::from(m);
                    module.raw.unwrap(
                        session.handle(),
                        &mechanism,
                        unwrapping.handle(),
                        wrapped,
                        template,
                    )
                });
            }
            let attrs = attributes(template)?;
            let result = with_mechanism(mech, |m| {
                session
                    .unwrap_key(m, unwrapping, wrapped, &attrs)
                    .map_err(|e| convert(e, "C_UnwrapKey"))
            });
            wipe(attrs);
            Ok(widen(result?.handle()))
        })
    }

    fn derive_key(&self, mech: &MechSpec, base_key: u64, template: &[RawAttr]) -> BResult<u64> {
        let module = self.module()?;
        let base = obj(base_key)?;
        self.with_session("C_DeriveKey", |session| {
            if let Some((ckm, param)) = raw_bytes(mech) {
                let mechanism = raw::bytes_mechanism(ckm, param)?;
                return module
                    .raw
                    .derive(session.handle(), &mechanism, base.handle(), template);
            }
            let attrs = attributes(template)?;
            let result = with_mechanism(mech, |m| {
                session
                    .derive_key(m, base, &attrs)
                    .map_err(|e| convert(e, "C_DeriveKey"))
            });
            wipe(attrs);
            Ok(widen(result?.handle()))
        })
    }
    fn generate_random(&self, len: usize) -> BResult<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(vec![0u8; len]);
        self.with_session("C_GenerateRandom", |session| {
            session
                .generate_random_slice(&mut out)
                .map_err(|e| convert(e, "C_GenerateRandom"))
        })?;
        Ok(out)
    }
}
