//! The CKR choke point (spec §4.5.6, §5.2 table). Every backend failure becomes a
//! `ConsoleError` here and only here.
use r2_core::error::ConsoleError;

use crate::backend::BackendError;
use crate::catalog::ckr_name;

/// CK_RV constants of cryptoki-sys widened to u64 (§4.5.5 narrowing rule).
#[allow(
    dead_code,
    reason = "the CK_RV vocabulary; some codes only appear in tests"
)]
pub(crate) mod rv {
    use cryptoki_sys as sys;
    macro_rules! rvs {
        ($($name:ident),* $(,)?) => {
            $(pub(crate) const $name: u64 = sys::$name as u64;)*
        };
    }
    // `as u64` is a widening conversion of CK_RV (c_ulong) on every target.
    rvs!(
        CKR_OK,
        CKR_PIN_INCORRECT,
        CKR_PIN_LOCKED,
        CKR_USER_ALREADY_LOGGED_IN,
        CKR_USER_NOT_LOGGED_IN,
        CKR_SESSION_HANDLE_INVALID,
        CKR_DEVICE_REMOVED,
        CKR_TOKEN_NOT_PRESENT,
        CKR_MECHANISM_INVALID,
        CKR_MECHANISM_PARAM_INVALID,
        CKR_KEY_HANDLE_INVALID,
        CKR_ATTRIBUTE_READ_ONLY,
        CKR_ATTRIBUTE_VALUE_INVALID,
        CKR_ATTRIBUTE_TYPE_INVALID,
        CKR_ATTRIBUTE_SENSITIVE,
        CKR_KEY_NOT_WRAPPABLE,
        CKR_KEY_UNEXTRACTABLE,
        CKR_KEY_SIZE_RANGE,
        CKR_FUNCTION_NOT_SUPPORTED,
        CKR_CRYPTOKI_ALREADY_INITIALIZED,
        CKR_CRYPTOKI_NOT_INITIALIZED,
        CKR_OBJECT_HANDLE_INVALID,
        CKR_SLOT_ID_INVALID,
        CKR_ARGUMENTS_BAD,
        CKR_DATA_LEN_RANGE,
        CKR_ENCRYPTED_DATA_INVALID,
        CKR_SIGNATURE_INVALID,
        CKR_SIGNATURE_LEN_RANGE,
        CKR_TEMPLATE_INCONSISTENT,
        CKR_TEMPLATE_INCOMPLETE,
        CKR_DEVICE_ERROR,
        CKR_GENERAL_ERROR,
        CKR_OPERATION_NOT_INITIALIZED,
        CKR_OPERATION_ACTIVE,
        CKR_KEY_TYPE_INCONSISTENT,
        CKR_VENDOR_DEFINED,
        CKR_WRAPPED_KEY_LEN_RANGE,
    );
}

/// The code PyKCS11 reported for its non-CKR errors (−1), as ckr_code (§4.5.6).
pub(crate) const BINDING_ERROR_CODE: u64 = 0xFFFF_FFFF;

/// The CK_RV of a backend error, if it is one (Binding errors count as c2's −1 code).
pub(crate) fn code_of(err: &BackendError) -> Option<u64> {
    match err {
        BackendError::Ckr(ckr) => Some(ckr.code),
        BackendError::Binding(_) => Some(BINDING_ERROR_CODE),
        BackendError::LibraryUnavailable(_) => None,
    }
}

/// PyKCS11's `str(PyKCS11Error(rv))` (the C_Initialize detail, §5.2): "{CKR name}
/// (0x%08X)" for a code in PyKCS11's table, "Vendor error (0x%08X)" (vendor bit masked
/// off) for vendor codes, else "Unknown error (0x%08X)".
pub(crate) fn pykcs11_error_text(code: u64) -> String {
    let low = code & 0xFFFF_FFFF;
    if let Some(name) = crate::catalog::ckr_name_known(code) {
        return format!("{name} (0x{low:08X})");
    }
    if code & rv::CKR_VENDOR_DEFINED != 0 {
        return format!("Vendor error (0x{:08X})", low & !rv::CKR_VENDOR_DEFINED);
    }
    format!("Unknown error (0x{low:08X})")
}

/// Implements the §5.2 table (names via `catalog::ckr_name`). `provider` = the provider
/// instance name (the `login <provider>` / `slots <provider>` texts). `token_label` = the
/// label in the CKR_PIN_* texts: callers pass the logged-in token's label (or the token
/// being logged in to); None renders "?" (c2's default). The CALLER logs
/// "{provider}: {context} failed with {CKR}" at INFO. For `LibraryUnavailable` the
/// `context` is the library path: ProviderUnavailable "cannot load PKCS#11 library
/// {context}: {detail}" (§5.2), as `Provider::initialize` renders every load failure.
pub(crate) fn translate(
    err: BackendError,
    provider: &str,
    context: &str,
    token_label: Option<&str>,
) -> ConsoleError {
    let code = match &err {
        BackendError::Ckr(ckr) => ckr.code,
        BackendError::Binding(detail) => {
            tracing::debug!(target: "r2::pkcs11", "{provider}: {context}: binding error: {detail}");
            BINDING_ERROR_CODE
        }
        BackendError::LibraryUnavailable(detail) => {
            // `context` is the library path here (§5.2 load-failure text)
            return ConsoleError::provider_unavailable(format!(
                "cannot load PKCS#11 library {context}: {detail}"
            ))
            .with_hint("check providers.pkcs11[].library in the configuration");
        }
    };
    let name = ckr_name(code);
    let label = token_label.unwrap_or("?");
    let pkcs11 = |message: String| ConsoleError::pkcs11(message, code, name.clone());
    match code {
        rv::CKR_PIN_INCORRECT => {
            pkcs11(format!("wrong PIN for token '{label}' ({name})")).with_hint("re-enter the PIN")
        }
        rv::CKR_PIN_LOCKED => pkcs11(format!("token locked — too many bad PINs ({name})"))
            .with_hint("unlock with the SO PIN"),
        rv::CKR_USER_NOT_LOGGED_IN => {
            ConsoleError::auth_required(format!("login required: run `login {provider}`"))
        }
        rv::CKR_SESSION_HANDLE_INVALID | rv::CKR_DEVICE_REMOVED => {
            ConsoleError::auth_required("session lost — login again")
        }
        rv::CKR_TOKEN_NOT_PRESENT => pkcs11(format!("no token in slot ({name})"))
            .with_hint(format!("re-insert the token and run `slots {provider}`")),
        rv::CKR_MECHANISM_INVALID | rv::CKR_MECHANISM_PARAM_INVALID => ConsoleError::unsupported(
            format!("token does not support {context} (or its parameters) ({name})"),
        ),
        rv::CKR_KEY_HANDLE_INVALID => pkcs11(format!("key no longer available on token ({name})"))
            .with_hint("refresh with `keys`"),
        rv::CKR_ATTRIBUTE_READ_ONLY => {
            pkcs11(format!("token forbids changing this attribute ({name})"))
                .with_hint("the attribute is fixed after object creation on this token")
        }
        rv::CKR_ATTRIBUTE_VALUE_INVALID | rv::CKR_ATTRIBUTE_TYPE_INVALID => {
            pkcs11(format!("template attribute rejected by token ({name})"))
                .with_hint("reopen the template editor and adjust the offending attribute")
        }
        rv::CKR_KEY_NOT_WRAPPABLE | rv::CKR_KEY_UNEXTRACTABLE => {
            pkcs11(format!("key cannot be exported or wrapped ({name})"))
                .with_hint("token policy forbids extracting this key")
        }
        rv::CKR_KEY_SIZE_RANGE => pkcs11(format!("key length unsuitable for {context} ({name})"))
            .with_hint(
                "HMAC keys must be at least the digest length on this token \
                 (e.g. 32 bytes for sha256, 64 for sha512)",
            ),
        rv::CKR_FUNCTION_NOT_SUPPORTED => {
            pkcs11(format!("token firmware lacks this function ({name})"))
                .with_hint(format!("capability missing for {context}"))
        }
        _ => pkcs11(format!("PKCS#11 {context} failed ({name})")),
    }
}
