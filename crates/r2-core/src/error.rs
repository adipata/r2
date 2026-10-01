// R0 skeleton — owner R1 (generated from spec §4)
// ---- spec §4.2 block 0
use std::borrow::Cow;
use std::fmt;

use crate::keys::KeyRef;

/// The single error type of every public r2 API. Rendered ONLY by the REPL loop (§4.9.5):
/// commands and services return it, never print it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsoleError {
    pub kind: ErrorKind,
    /// Operator-actionable text. PKCS#11 failures include the CKR name (§6).
    pub message: String,
    pub hint: Option<String>,
}

/// One variant per c2 exception class (c2 spec §4.2). Variant ↔ class:
/// Generic=ConsoleError, Config=ConfigError, Parse=ParseError, Codec=CodecError,
/// KeyParse=KeyParseError, DataIo=DataIOError, Provider=ProviderError,
/// ProviderUnavailable=ProviderUnavailableError, ProviderNotFound=ProviderNotFoundError,
/// AuthRequired=AuthRequiredError, AlreadyLoggedIn=AlreadyLoggedInError, Pkcs11=Pkcs11Error,
/// KeyLookup=KeyLookupError, KeyNotFound=KeyNotFoundError, AmbiguousKey=AmbiguousKeyError,
/// DuplicateKey=DuplicateKeyError, KeyNotExportable=KeyNotExportableError,
/// Operation=OperationError, UnknownOperation=UnknownOperationError,
/// UnsupportedOperation=UnsupportedOperationError, Param=ParamError, Crypto=CryptoError,
/// UserAbort=UserAbort.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Generic,
    Config,
    /// `line` = the text the caret is drawn under; `pos` = BYTE offset into `line`.
    Parse {
        line: String,
        pos: usize,
    },
    Codec,
    KeyParse,
    /// File read/write failure; the path is part of the message.
    DataIo,
    Provider,
    /// Library load / C_Initialize failed.
    ProviderUnavailable,
    /// Unknown provider name in a ref.
    ProviderNotFound,
    AuthRequired,
    AlreadyLoggedIn,
    /// Untranslated PKCS#11 failure. `ckr_name` is the symbolic name from PyKCS11's table
    /// (`"CKR_PIN_INCORRECT"`, `r2_pkcs11::catalog::ckr_name`, §4.5.5), or `"CKR_0x%08X"`
    /// (upper-case hex, 8 digits, low 32 bits) for codes without one.
    Pkcs11 {
        ckr_code: u64,
        ckr_name: Cow<'static, str>,
    },
    KeyLookup,
    KeyNotFound,
    /// Several objects matched; candidates are the matching refs in provider order.
    AmbiguousKey {
        candidates: Vec<KeyRef>,
    },
    /// Creating an exact (class, label, id) twin was refused (§4.7 guard).
    DuplicateKey,
    KeyNotExportable,
    Operation,
    UnknownOperation,
    /// Capability check failed for this provider/key.
    UnsupportedOperation,
    Param {
        param_name: String,
    },
    /// Backend failure mid-operation.
    Crypto,
    /// Ctrl-C / Ctrl-D inside a prompt flow, or the Ctrl-C flag at a step boundary. The REPL
    /// renders every UserAbort as the single line `Aborted.` (the message is not shown).
    UserAbort,
}

impl ErrorKind {
    /// The c2 class name ("ParamError", "Pkcs11Error", …) — for logs and test assertions.
    pub fn class_name(&self) -> &'static str {
        unimplemented!("R1")
    }
    /// ProviderError family: Provider, ProviderUnavailable, ProviderNotFound, AuthRequired,
    /// AlreadyLoggedIn, Pkcs11.
    pub fn is_provider(&self) -> bool {
        unimplemented!("R1")
    }
    /// KeyLookupError family: KeyLookup, KeyNotFound, AmbiguousKey, DuplicateKey.
    pub fn is_key_lookup(&self) -> bool {
        unimplemented!("R1")
    }
    /// OperationError family: Operation, UnknownOperation, UnsupportedOperation, Param, Crypto.
    pub fn is_operation(&self) -> bool {
        unimplemented!("R1")
    }
    /// UserAbort (c2's KeyboardInterrupt/EOFError/UserAbort path — never swallowed, below).
    pub fn is_user_abort(&self) -> bool {
        unimplemented!("R1")
    }
}

impl ConsoleError {
    // R0 mandated working bodies (§4.1.1): `new`, `with_hint`, `with_hint_opt`, `generic`,
    // `crypto` and `not_implemented`, so skeleton stubs return Err instead of panicking.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            hint: None,
        }
    }
    /// Builder: sets the hint (replaces an existing one).
    pub fn with_hint(self, hint: impl Into<String>) -> Self {
        Self {
            hint: Some(hint.into()),
            ..self
        }
    }
    /// Builder: sets or clears the hint.
    pub fn with_hint_opt(self, hint: Option<String>) -> Self {
        Self { hint, ..self }
    }

    // One constructor per kind (all take `impl Into<String>` for the message):
    pub fn generic(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Generic, message)
    }
    pub fn config(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn parse(message: impl Into<String>, line: impl Into<String>, pos: usize) -> Self {
        let _ = (message, line, pos);
        unimplemented!("R1")
    }
    pub fn codec(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn key_parse(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn data_io(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn provider(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn provider_unavailable(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn provider_not_found(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn auth_required(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn already_logged_in(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn pkcs11(
        message: impl Into<String>,
        ckr_code: u64,
        ckr_name: impl Into<Cow<'static, str>>,
    ) -> Self {
        let _ = (message, ckr_code, ckr_name);
        unimplemented!("R1")
    }
    pub fn key_lookup(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn key_not_found(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn ambiguous_key(message: impl Into<String>, candidates: Vec<KeyRef>) -> Self {
        let _ = (message, candidates);
        unimplemented!("R1")
    }
    pub fn duplicate_key(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn key_not_exportable(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn operation(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn unknown_operation(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn unsupported(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    pub fn param(message: impl Into<String>, param_name: impl Into<String>) -> Self {
        let _ = (message, param_name);
        unimplemented!("R1")
    }
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Crypto, message)
    }
    pub fn user_abort(message: impl Into<String>) -> Self {
        let _ = message;
        unimplemented!("R1")
    }
    /// R0 skeleton stub error: Generic, message `not implemented (<loop>)`, e.g. "not implemented (R4)".
    pub fn not_implemented(owner_loop: &str) -> Self {
        Self::generic(format!("not implemented ({owner_loop})"))
    }

    // Field accessors (None when the kind does not carry the field):
    pub fn param_name(&self) -> Option<&str> {
        unimplemented!("R1")
    }
    pub fn ckr(&self) -> Option<(u64, &str)> {
        unimplemented!("R1")
    }
    pub fn candidates(&self) -> Option<&[KeyRef]> {
        unimplemented!("R1")
    }
    pub fn parse_position(&self) -> Option<(&str, usize)> {
        unimplemented!("R1")
    }
}

/// Display = `message` only (c2 `str(exc)`); the hint is rendered separately.
impl fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for ConsoleError {}

pub type Result<T> = std::result::Result<T, ConsoleError>;
