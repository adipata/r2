//! RawFns — the second `dlopen` of a PKCS#11 module plus its `CK_FUNCTION_LIST` (audited
//! unsafe shim 2, spec §4.1.3 / §4.5.5) — and the thread-local registry of shared modules.
//!
//! RawFns covers what cryptoki 0.12.1 cannot do soundly (S0 spike gaps G1/G3/G4/G5): the
//! UNFILTERED `C_GetMechanismList`, `C_GetTokenInfo` without cryptoki's `utcTime`
//! parsing (it fails on tokens with CKF_CLOCK_ON_TOKEN and a non-digit clock), byte-level one-attribute `C_GetAttributeValue`, crypto
//! calls with a runtime-length raw mechanism parameter, and `C_WrapKey` with output
//! truncation. dlopen is refcounted, so the second open maps the module cryptoki already
//! loaded and initialized.
#![allow(
    dead_code,
    reason = "the crypto/wrap/derive shims are consumed by R5b's verbs"
)]
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::rc::Rc;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki_sys::{
    CK_ATTRIBUTE, CK_BYTE, CK_FUNCTION_LIST, CK_MECHANISM, CK_OBJECT_HANDLE, CK_RV,
    CK_SESSION_HANDLE, CK_SLOT_ID, CK_TOKEN_INFO, CK_ULONG, CK_UNAVAILABLE_INFORMATION,
};
use zeroize::Zeroizing;

use super::{BResult, BackendError, Ckr, RawAttr, RawTokenInfo};
use crate::ckr::rv;

/// A CK_RV of RawFns as a backend error (widening, `crate::ulong_to_u64`).
fn ckr(code: CK_RV, function: &'static str) -> BackendError {
    BackendError::Ckr(Ckr {
        code: crate::ulong_to_u64(code),
        function,
    })
}

fn check(code: CK_RV, function: &'static str) -> BResult<()> {
    if crate::ulong_to_u64(code) == rv::CKR_OK {
        Ok(())
    } else {
        Err(ckr(code, function))
    }
}

/// Checked usize/u64 → CK_ULONG (§4.5.5 narrowing rule).
pub(crate) fn ulong(value: usize, code: u64, function: &'static str) -> BResult<CK_ULONG> {
    CK_ULONG::try_from(value).map_err(|_| BackendError::Ckr(Ckr { code, function }))
}

/// A `CK_MECHANISM` whose `pParameter` points at `param` verbatim (empty → NULL, c2 parity).
/// The result borrows `param` through a raw pointer: build it in the frame of the call.
pub(crate) fn bytes_mechanism(ckm: u64, param: &[u8]) -> BResult<CK_MECHANISM> {
    let mechanism = cryptoki_sys::CK_MECHANISM_TYPE::try_from(ckm).map_err(|_| {
        BackendError::Ckr(Ckr {
            code: rv::CKR_MECHANISM_INVALID,
            function: "raw",
        })
    })?;
    if param.is_empty() {
        return Ok(CK_MECHANISM {
            mechanism,
            pParameter: null_mut(),
            ulParameterLen: 0,
        });
    }
    Ok(CK_MECHANISM {
        mechanism,
        pParameter: param.as_ptr() as *mut c_void,
        ulParameterLen: ulong(param.len(), rv::CKR_MECHANISM_PARAM_INVALID, "raw")?,
    })
}

/// Raw `CK_ATTRIBUTE`s pointing into `template` (which must outlive the call).
fn raw_template(template: &[RawAttr]) -> BResult<Vec<CK_ATTRIBUTE>> {
    template
        .iter()
        .map(|(kind, value)| {
            Ok(CK_ATTRIBUTE {
                type_: cryptoki_sys::CK_ATTRIBUTE_TYPE::try_from(*kind).map_err(|_| {
                    BackendError::Ckr(Ckr {
                        code: rv::CKR_ATTRIBUTE_TYPE_INVALID,
                        function: "raw",
                    })
                })?,
                pValue: value.as_ptr() as *mut c_void,
                ulValueLen: ulong(value.len(), rv::CKR_ATTRIBUTE_VALUE_INVALID, "raw")?,
            })
        })
        .collect()
}

/// A blank-padded CK_UTF8CHAR field: lossy UTF-8, trailing ' ' and '\0' trimmed.
fn padded(field: &[CK_BYTE]) -> String {
    String::from_utf8_lossy(field)
        .trim_end_matches(['\0', ' '])
        .to_string()
}

/// Decode a raw CK_TOKEN_INFO (PyKCS11 `getTokenInfo` parity): only the four text
/// fields and CKF_TOKEN_INITIALIZED are read; `utcTime` is never parsed.
pub(crate) fn decode_token_info(slot: u64, info: &CK_TOKEN_INFO) -> RawTokenInfo {
    RawTokenInfo {
        slot_id: slot,
        label: padded(&info.label),
        manufacturer: padded(&info.manufacturerID),
        model: padded(&info.model),
        serial: padded(&info.serialNumber),
        initialized: crate::ulong_to_u64(info.flags)
            & crate::ulong_to_u64(cryptoki_sys::CKF_TOKEN_INITIALIZED)
            != 0,
    }
}

/// Which single-part crypto function a raw call runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RawOp {
    Encrypt,
    Decrypt,
    Sign,
}

/// The raw function list of a module (see the module docs).
pub(crate) struct RawFns {
    /// Keeps the second dlopen handle (and so `list`) alive.
    _lib: cryptoki_sys::Pkcs11,
    list: *const CK_FUNCTION_LIST,
}

/// Fetch one entry of the function list, or CKR_FUNCTION_NOT_SUPPORTED when it is NULL.
macro_rules! entry {
    ($self:expr, $name:ident) => {{
        #[allow(unsafe_code)]
        // SAFETY: `list` is the non-NULL CK_FUNCTION_LIST returned by C_GetFunctionList of
        // the module `_lib` keeps mapped; reading one function-pointer field is a plain load.
        let function = unsafe { (*$self.list).$name };
        function.ok_or_else(|| ckr(cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED, stringify!($name)))?
    }};
}

#[allow(unsafe_code)]
impl RawFns {
    /// Second `dlopen` of `library` + `C_GetFunctionList`.
    pub(crate) fn open(library: &Path) -> Result<Self, String> {
        // SAFETY: loading a PKCS#11 module runs its initializers, exactly as cryptoki's own
        // `Pkcs11::new` on the same path did just before (dlopen is refcounted, so this maps
        // the already-loaded module).
        let lib = unsafe { cryptoki_sys::Pkcs11::new(library) }.map_err(|e| e.to_string())?;
        let mut list: *mut CK_FUNCTION_LIST = null_mut();
        // SAFETY: C_GetFunctionList writes one pointer through the valid out-parameter.
        let code = unsafe { lib.C_GetFunctionList(&mut list) };
        if crate::ulong_to_u64(code) != rv::CKR_OK || list.is_null() {
            return Err(format!(
                "C_GetFunctionList failed (0x{:08X})",
                crate::ulong_to_u64(code)
            ));
        }
        Ok(Self { _lib: lib, list })
    }

    /// Unfiltered C_GetMechanismList (cryptoki drops CKMs it has no MechanismType for).
    pub(crate) fn mechanism_list(&self, slot: u64) -> BResult<Vec<u64>> {
        let f = entry!(self, C_GetMechanismList);
        let slot = CK_SLOT_ID::try_from(slot).map_err(|_| {
            BackendError::Ckr(Ckr {
                code: rv::CKR_SLOT_ID_INVALID,
                function: "C_GetMechanismList",
            })
        })?;
        let mut count: CK_ULONG = 0;
        // SAFETY: size query: NULL list pointer and a valid count out-parameter.
        check(
            unsafe { f(slot, null_mut(), &mut count) },
            "C_GetMechanismList",
        )?;
        let mut codes: Vec<cryptoki_sys::CK_MECHANISM_TYPE> =
            vec![0; usize::try_from(count).unwrap_or(0)];
        let mut filled = count;
        // SAFETY: `codes` holds `count` writable entries, announced through `filled`.
        check(
            unsafe { f(slot, codes.as_mut_ptr(), &mut filled) },
            "C_GetMechanismList",
        )?;
        codes.truncate(usize::try_from(filled).unwrap_or(0));
        Ok(codes.into_iter().map(crate::ulong_to_u64).collect())
    }

    /// C_GetTokenInfo into a raw CK_TOKEN_INFO, decoded by [`decode_token_info`].
    pub(crate) fn token_info(&self, slot: u64) -> BResult<RawTokenInfo> {
        let f = entry!(self, C_GetTokenInfo);
        let slot_id = CK_SLOT_ID::try_from(slot).map_err(|_| {
            BackendError::Ckr(Ckr {
                code: rv::CKR_SLOT_ID_INVALID,
                function: "C_GetTokenInfo",
            })
        })?;
        let mut info = CK_TOKEN_INFO::default();
        // SAFETY: `info` is a valid, writable CK_TOKEN_INFO out-parameter.
        check(unsafe { f(slot_id, &mut info) }, "C_GetTokenInfo")?;
        Ok(decode_token_info(slot, &info))
    }

    /// One attribute, byte level. Ok(None) = sensitive, type-invalid or unavailable.
    pub(crate) fn get_attr(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        kind: u64,
    ) -> BResult<Option<Zeroizing<Vec<u8>>>> {
        let f = entry!(self, C_GetAttributeValue);
        let type_ = cryptoki_sys::CK_ATTRIBUTE_TYPE::try_from(kind).map_err(|_| {
            BackendError::Ckr(Ckr {
                code: rv::CKR_ATTRIBUTE_TYPE_INVALID,
                function: "C_GetAttributeValue",
            })
        })?;
        let mut attr = CK_ATTRIBUTE {
            type_,
            pValue: null_mut(),
            ulValueLen: 0,
        };
        // SAFETY: size pass: one attribute with a NULL value pointer.
        let code = crate::ulong_to_u64(unsafe { f(session, object, &mut attr, 1) });
        match code {
            rv::CKR_OK => {}
            refused if super::is_attribute_refusal(refused) => return Ok(None),
            other => {
                return Err(BackendError::Ckr(Ckr {
                    code: other,
                    function: "C_GetAttributeValue",
                }));
            }
        }
        if attr.ulValueLen == CK_UNAVAILABLE_INFORMATION {
            return Ok(None);
        }
        let len = usize::try_from(attr.ulValueLen).unwrap_or(0);
        let mut buffer = Zeroizing::new(vec![0u8; len]);
        attr.pValue = buffer.as_mut_ptr() as *mut c_void;
        // SAFETY: value pass: `buffer` holds exactly `ulValueLen` writable bytes.
        let code = crate::ulong_to_u64(unsafe { f(session, object, &mut attr, 1) });
        match code {
            rv::CKR_OK => {}
            rv::CKR_ATTRIBUTE_SENSITIVE | rv::CKR_ATTRIBUTE_TYPE_INVALID => return Ok(None),
            other => {
                return Err(BackendError::Ckr(Ckr {
                    code: other,
                    function: "C_GetAttributeValue",
                }));
            }
        }
        if attr.ulValueLen == CK_UNAVAILABLE_INFORMATION {
            return Ok(None);
        }
        buffer.truncate(usize::try_from(attr.ulValueLen).unwrap_or(0));
        Ok(Some(buffer))
    }

    /// The two-call output convention (size query, then the real call), truncated to the
    /// length the second call reports.
    fn two_call(
        call: &dyn Fn(*mut CK_BYTE, *mut CK_ULONG) -> CK_RV,
        function: &'static str,
    ) -> BResult<Zeroizing<Vec<u8>>> {
        let mut len: CK_ULONG = 0;
        check(call(null_mut(), &mut len), function)?;
        let mut out = Zeroizing::new(vec![0u8; usize::try_from(len).unwrap_or(0)]);
        check(call(out.as_mut_ptr(), &mut len), function)?;
        out.truncate(usize::try_from(len).unwrap_or(0));
        Ok(out)
    }

    /// C_{Encrypt,Decrypt,Sign}Init + the single-part call with a raw mechanism.
    pub(crate) fn crypt(
        &self,
        op: RawOp,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
        data: &[u8],
    ) -> BResult<Zeroizing<Vec<u8>>> {
        let data_len = ulong(data.len(), rv::CKR_DATA_LEN_RANGE, "raw")?;
        let mut mech = *mechanism;
        let input = data.as_ptr() as *mut CK_BYTE;
        match op {
            RawOp::Encrypt => {
                let (init, run) = (entry!(self, C_EncryptInit), entry!(self, C_Encrypt));
                // SAFETY: `mech` and its parameter live in the caller's frame for the call.
                check(unsafe { init(session, &mut mech, key) }, "C_EncryptInit")?;
                // SAFETY: input/output buffers are valid for the announced lengths.
                Self::two_call(
                    &|o, n| unsafe { run(session, input, data_len, o, n) },
                    "C_Encrypt",
                )
            }
            RawOp::Decrypt => {
                let (init, run) = (entry!(self, C_DecryptInit), entry!(self, C_Decrypt));
                // SAFETY: as above.
                check(unsafe { init(session, &mut mech, key) }, "C_DecryptInit")?;
                // SAFETY: as above.
                Self::two_call(
                    &|o, n| unsafe { run(session, input, data_len, o, n) },
                    "C_Decrypt",
                )
            }
            RawOp::Sign => {
                let (init, run) = (entry!(self, C_SignInit), entry!(self, C_Sign));
                // SAFETY: as above.
                check(unsafe { init(session, &mut mech, key) }, "C_SignInit")?;
                // SAFETY: as above.
                Self::two_call(
                    &|o, n| unsafe { run(session, input, data_len, o, n) },
                    "C_Sign",
                )
            }
        }
    }

    /// C_VerifyInit + C_Verify with a raw mechanism.
    pub(crate) fn verify(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
        data: &[u8],
        signature: &[u8],
    ) -> BResult<()> {
        let (init, run) = (entry!(self, C_VerifyInit), entry!(self, C_Verify));
        let data_len = ulong(data.len(), rv::CKR_DATA_LEN_RANGE, "raw")?;
        let sig_len = ulong(signature.len(), rv::CKR_SIGNATURE_LEN_RANGE, "raw")?;
        let mut mech = *mechanism;
        // SAFETY: `mech` and its parameter live in the caller's frame for the call.
        check(unsafe { init(session, &mut mech, key) }, "C_VerifyInit")?;
        // SAFETY: data and signature are valid for their announced lengths (read only).
        check(
            unsafe {
                run(
                    session,
                    data.as_ptr() as *mut CK_BYTE,
                    data_len,
                    signature.as_ptr() as *mut CK_BYTE,
                    sig_len,
                )
            },
            "C_Verify",
        )
    }

    /// C_WrapKey, truncated to the second call's length (cryptoki keeps the size query's).
    pub(crate) fn wrap(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        wrapping_key: CK_OBJECT_HANDLE,
        key: CK_OBJECT_HANDLE,
    ) -> BResult<Vec<u8>> {
        let f = entry!(self, C_WrapKey);
        let mech = *mechanism;
        let blob = Self::two_call(
            &|o, n| {
                let mut m = mech;
                // SAFETY: the mechanism parameter lives in the caller's frame; the output
                // buffer is valid for `*n` bytes (or NULL for the size query).
                unsafe { f(session, &mut m, wrapping_key, key, o, n) }
            },
            "C_WrapKey",
        )?;
        Ok(blob.to_vec())
    }

    /// C_UnwrapKey with a raw mechanism and a raw template.
    pub(crate) fn unwrap(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        unwrapping_key: CK_OBJECT_HANDLE,
        wrapped: &[u8],
        template: &[RawAttr],
    ) -> BResult<u64> {
        let f = entry!(self, C_UnwrapKey);
        let mut attrs = raw_template(template)?;
        let mut mech = *mechanism;
        let mut handle: CK_OBJECT_HANDLE = 0;
        let wrapped_len = ulong(wrapped.len(), rv::CKR_WRAPPED_KEY_LEN_RANGE, "raw")?;
        let count = ulong(attrs.len(), rv::CKR_TEMPLATE_INCONSISTENT, "raw")?;
        // SAFETY: every pointer refers to a buffer of this frame (mechanism parameter,
        // wrapped bytes, the template and the values it points into, the out handle).
        check(
            unsafe {
                f(
                    session,
                    &mut mech,
                    unwrapping_key,
                    wrapped.as_ptr() as *mut CK_BYTE,
                    wrapped_len,
                    attrs.as_mut_ptr(),
                    count,
                    &mut handle,
                )
            },
            "C_UnwrapKey",
        )?;
        Ok(crate::ulong_to_u64(handle))
    }

    /// C_DeriveKey with a raw mechanism and a raw template.
    pub(crate) fn derive(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        base_key: CK_OBJECT_HANDLE,
        template: &[RawAttr],
    ) -> BResult<u64> {
        let f = entry!(self, C_DeriveKey);
        let mut attrs = raw_template(template)?;
        let mut mech = *mechanism;
        let mut handle: CK_OBJECT_HANDLE = 0;
        let count = ulong(attrs.len(), rv::CKR_TEMPLATE_INCONSISTENT, "raw")?;
        // SAFETY: as for `unwrap`.
        check(
            unsafe {
                f(
                    session,
                    &mut mech,
                    base_key,
                    attrs.as_mut_ptr(),
                    count,
                    &mut handle,
                )
            },
            "C_DeriveKey",
        )?;
        Ok(crate::ulong_to_u64(handle))
    }
}

/// A module shared by every provider over one canonical library path (PyKCS11
/// `_loaded_libs` parity, §4.5.5 / §11 D21).
pub(crate) struct SharedModule {
    pub ctx: Pkcs11,
    pub raw: RawFns,
    users: Cell<usize>,
}

thread_local! {
    /// Canonical library path → shared module (one per path, refcounted by `users`).
    static MODULES: RefCell<HashMap<PathBuf, Rc<SharedModule>>> = RefCell::new(HashMap::new());
}

/// Registry key (normative): `std::fs::canonicalize` of the (already expanded) library
/// path; the path as given when that fails.
pub(crate) fn registry_key(library: &Path) -> PathBuf {
    std::fs::canonicalize(library).unwrap_or_else(|_| library.to_path_buf())
}

/// Number of backends holding the module of `key` (0 when not loaded).
pub(crate) fn module_users(key: &Path) -> usize {
    MODULES.with(|m| m.borrow().get(key).map_or(0, |module| module.users.get()))
}

/// The detail text of a module-load failure (libloading/cryptoki text, §11 D11).
fn load_detail(err: &Error) -> String {
    match err {
        Error::LibraryLoading(inner) => inner.to_string(),
        other => other.to_string(),
    }
}

/// Acquire the shared module of `library`: the first acquire on a path loads it and runs
/// `C_Initialize(CKF_OS_LOCKING_OK)` (CKR_CRYPTOKI_ALREADY_INITIALIZED = success; any other
/// CKR → LibraryUnavailable with PyKCS11's error text), later acquires share it.
pub(crate) fn acquire(library: &Path) -> BResult<(PathBuf, Rc<SharedModule>)> {
    let key = registry_key(library);
    let existing = MODULES.with(|m| m.borrow().get(&key).cloned());
    if let Some(module) = existing {
        module.users.set(module.users.get() + 1);
        return Ok((key, module));
    }
    let ctx =
        Pkcs11::new(library).map_err(|e| BackendError::LibraryUnavailable(load_detail(&e)))?;
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(Error::Pkcs11(rv_error, _)) => {
            let code = super::cryptoki::rv_code(&rv_error);
            return Err(BackendError::LibraryUnavailable(
                crate::ckr::pykcs11_error_text(code),
            ));
        }
        Err(other) => return Err(BackendError::LibraryUnavailable(load_detail(&other))),
    }
    let raw = match RawFns::open(library) {
        Ok(raw) => raw,
        Err(detail) => {
            let _ = ctx.finalize();
            return Err(BackendError::LibraryUnavailable(detail));
        }
    };
    let module = Rc::new(SharedModule {
        ctx,
        raw,
        users: Cell::new(1),
    });
    MODULES.with(|m| m.borrow_mut().insert(key.clone(), Rc::clone(&module)));
    // the provider logs c2's INFO "{provider}: loaded PKCS#11 library {library}"
    tracing::debug!(target: "r2::pkcs11", "acquired shared module {}", key.display());
    Ok((key, module))
}

/// Release one reference; the last release removes the entry (dropping the registry
/// borrow first), then finalizes, then drops `raw` and `ctx`. Sessions must already be
/// dropped by the caller.
pub(crate) fn release(key: &Path, module: Rc<SharedModule>) -> BResult<()> {
    let remaining = module.users.get().saturating_sub(1);
    module.users.set(remaining);
    if remaining > 0 {
        return Ok(());
    }
    let removed = MODULES.with(|m| m.borrow_mut().remove(key));
    drop(removed);
    let result = module.ctx.clone().finalize();
    drop(module);
    match result {
        Ok(()) => Ok(()),
        Err(err) => Err(super::cryptoki::convert(err, "C_Finalize")),
    }
}
