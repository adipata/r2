// Errors (spec §4.2; owner R1).
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
        match self {
            ErrorKind::Generic => "ConsoleError",
            ErrorKind::Config => "ConfigError",
            ErrorKind::Parse { .. } => "ParseError",
            ErrorKind::Codec => "CodecError",
            ErrorKind::KeyParse => "KeyParseError",
            ErrorKind::DataIo => "DataIOError",
            ErrorKind::Provider => "ProviderError",
            ErrorKind::ProviderUnavailable => "ProviderUnavailableError",
            ErrorKind::ProviderNotFound => "ProviderNotFoundError",
            ErrorKind::AuthRequired => "AuthRequiredError",
            ErrorKind::AlreadyLoggedIn => "AlreadyLoggedInError",
            ErrorKind::Pkcs11 { .. } => "Pkcs11Error",
            ErrorKind::KeyLookup => "KeyLookupError",
            ErrorKind::KeyNotFound => "KeyNotFoundError",
            ErrorKind::AmbiguousKey { .. } => "AmbiguousKeyError",
            ErrorKind::DuplicateKey => "DuplicateKeyError",
            ErrorKind::KeyNotExportable => "KeyNotExportableError",
            ErrorKind::Operation => "OperationError",
            ErrorKind::UnknownOperation => "UnknownOperationError",
            ErrorKind::UnsupportedOperation => "UnsupportedOperationError",
            ErrorKind::Param { .. } => "ParamError",
            ErrorKind::Crypto => "CryptoError",
            ErrorKind::UserAbort => "UserAbort",
        }
    }
    /// ProviderError family: Provider, ProviderUnavailable, ProviderNotFound, AuthRequired,
    /// AlreadyLoggedIn, Pkcs11.
    pub fn is_provider(&self) -> bool {
        matches!(
            self,
            ErrorKind::Provider
                | ErrorKind::ProviderUnavailable
                | ErrorKind::ProviderNotFound
                | ErrorKind::AuthRequired
                | ErrorKind::AlreadyLoggedIn
                | ErrorKind::Pkcs11 { .. }
        )
    }
    /// KeyLookupError family: KeyLookup, KeyNotFound, AmbiguousKey, DuplicateKey.
    pub fn is_key_lookup(&self) -> bool {
        matches!(
            self,
            ErrorKind::KeyLookup
                | ErrorKind::KeyNotFound
                | ErrorKind::AmbiguousKey { .. }
                | ErrorKind::DuplicateKey
        )
    }
    /// OperationError family: Operation, UnknownOperation, UnsupportedOperation, Param, Crypto.
    pub fn is_operation(&self) -> bool {
        matches!(
            self,
            ErrorKind::Operation
                | ErrorKind::UnknownOperation
                | ErrorKind::UnsupportedOperation
                | ErrorKind::Param { .. }
                | ErrorKind::Crypto
        )
    }
    /// UserAbort (c2's KeyboardInterrupt/EOFError/UserAbort path — never swallowed, below).
    pub fn is_user_abort(&self) -> bool {
        matches!(self, ErrorKind::UserAbort)
    }
}

impl ConsoleError {
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
        Self::new(ErrorKind::Config, message)
    }
    pub fn parse(message: impl Into<String>, line: impl Into<String>, pos: usize) -> Self {
        Self::new(
            ErrorKind::Parse {
                line: line.into(),
                pos,
            },
            message,
        )
    }
    pub fn codec(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Codec, message)
    }
    pub fn key_parse(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::KeyParse, message)
    }
    pub fn data_io(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::DataIo, message)
    }
    pub fn provider(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Provider, message)
    }
    pub fn provider_unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::ProviderUnavailable, message)
    }
    pub fn provider_not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::ProviderNotFound, message)
    }
    pub fn auth_required(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::AuthRequired, message)
    }
    pub fn already_logged_in(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::AlreadyLoggedIn, message)
    }
    pub fn pkcs11(
        message: impl Into<String>,
        ckr_code: u64,
        ckr_name: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(
            ErrorKind::Pkcs11 {
                ckr_code,
                ckr_name: ckr_name.into(),
            },
            message,
        )
    }
    pub fn key_lookup(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::KeyLookup, message)
    }
    pub fn key_not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::KeyNotFound, message)
    }
    pub fn ambiguous_key(message: impl Into<String>, candidates: Vec<KeyRef>) -> Self {
        Self::new(ErrorKind::AmbiguousKey { candidates }, message)
    }
    pub fn duplicate_key(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::DuplicateKey, message)
    }
    pub fn key_not_exportable(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::KeyNotExportable, message)
    }
    pub fn operation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Operation, message)
    }
    pub fn unknown_operation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::UnknownOperation, message)
    }
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::UnsupportedOperation, message)
    }
    pub fn param(message: impl Into<String>, param_name: impl Into<String>) -> Self {
        Self::new(
            ErrorKind::Param {
                param_name: param_name.into(),
            },
            message,
        )
    }
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Crypto, message)
    }
    pub fn user_abort(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::UserAbort, message)
    }
    /// R0 skeleton stub error: Generic, message `not implemented (<loop>)`, e.g. "not implemented (R4)".
    pub fn not_implemented(owner_loop: &str) -> Self {
        Self::generic(format!("not implemented ({owner_loop})"))
    }

    // Field accessors (None when the kind does not carry the field):
    pub fn param_name(&self) -> Option<&str> {
        match &self.kind {
            ErrorKind::Param { param_name } => Some(param_name),
            _ => None,
        }
    }
    pub fn ckr(&self) -> Option<(u64, &str)> {
        match &self.kind {
            ErrorKind::Pkcs11 { ckr_code, ckr_name } => Some((*ckr_code, ckr_name.as_ref())),
            _ => None,
        }
    }
    pub fn candidates(&self) -> Option<&[KeyRef]> {
        match &self.kind {
            ErrorKind::AmbiguousKey { candidates } => Some(candidates),
            _ => None,
        }
    }
    pub fn parse_position(&self) -> Option<(&str, usize)> {
        match &self.kind {
            ErrorKind::Parse { line, pos } => Some((line, *pos)),
            _ => None,
        }
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
