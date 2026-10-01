// Provider-boundary data types (spec §4.5.1, R3).
use std::fmt;

use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, ParsedRef};
use r2_core::params::{ParamStruct, Params};
use r2_core::template::KeyTemplate;
use zeroize::Zeroizing;

/// Token: "not_required" (memory) | "logged_out" | "logged_in".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthState {
    NotRequired,
    LoggedOut,
    LoggedIn,
}
impl AuthState {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthState::NotRequired => "not_required",
            AuthState::LoggedOut => "logged_out",
            AuthState::LoggedIn => "logged_in",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenInfo {
    pub slot_id: u64,
    /// Trailing ' ' AND '\0' trimmed (c2 `_strip_padding`; cryptoki trims spaces only).
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderStatus {
    pub auth: AuthState,
    /// Some iff auth == LoggedIn.
    pub token: Option<TokenInfo>,
}

/// What a provider verb receives. Built by `OperationSpec::invocation` (§4.6) for
/// operations, or directly (`new`) by services for fixed mechanisms.
#[derive(Clone, Debug, PartialEq)]
pub struct MechanismInvocation {
    /// Canonical name (§4.6), e.g. "AES-GCM", or a custom mechanism id.
    pub mechanism: String,
    /// Typed values from ParamResolver (absent = c2's `None`).
    pub params: Params,
    /// Set for config-defined vendor mechanisms.
    pub raw_ckm: Option<u64>,
    pub param_struct: ParamStruct,
    /// Set when param_struct == Raw (the resolved `mechparam` bytes).
    pub raw_param_bytes: Option<Vec<u8>>,
}
impl MechanismInvocation {
    /// raw_ckm None, param_struct None, raw_param_bytes None.
    pub fn new(mechanism: impl Into<String>, params: Params) -> Self {
        Self {
            mechanism: mechanism.into(),
            params,
            raw_ckm: None,
            param_struct: ParamStruct::None,
            raw_param_bytes: None,
        }
    }
}

/// frozen-provisional (§4.11). `Debug` by hand: `raw` shown as "<N bytes>".
#[derive(Clone, PartialEq)]
pub struct DeriveResult {
    /// Provider-resident derived key (session object).
    pub key: Option<KeyInfo>,
    /// Shared secret bytes when extractable.
    pub raw: Option<Zeroizing<Vec<u8>>>,
}
impl fmt::Debug for DeriveResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self
            .raw
            .as_ref()
            .map(|raw| format!("<{} bytes>", raw.len()));
        f.debug_struct("DeriveResult")
            .field("key", &self.key)
            .field("raw", &raw)
            .finish()
    }
}

/// frozen-provisional (§4.11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttrEditOutcome {
    /// "CKA_LABEL".
    pub name: String,
    pub applied: bool,
    /// Failure reason incl. the CKR name when not applied.
    pub detail: Option<String>,
}

/// frozen-provisional (§4.11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEditResult {
    /// Re-read snapshot after the edits (new ref on an identity change).
    pub key: KeyInfo,
    pub outcomes: Vec<AttrEditOutcome>,
}

/// The §4.3 ref selectors as find_key filters (c2 `find_key(label, key_id, key_class, handle)`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeySelector {
    pub label: String,
    pub key_id: Option<Vec<u8>>,
    pub key_class: Option<KeyClass>,
    pub handle: Option<u64>,
}
impl KeySelector {
    pub fn label(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            ..Self::default()
        }
    }
    pub fn with_id(self, key_id: Option<Vec<u8>>) -> Self {
        Self { key_id, ..self }
    }
    pub fn with_class(self, key_class: Option<KeyClass>) -> Self {
        Self { key_class, ..self }
    }
    pub fn with_handle(self, handle: Option<u64>) -> Self {
        Self { handle, ..self }
    }
}
impl From<&ParsedRef> for KeySelector {
    fn from(parsed: &ParsedRef) -> Self {
        Self {
            label: parsed.label.clone(),
            key_id: parsed.key_id.clone(),
            key_class: parsed.key_class,
            handle: parsed.handle,
        }
    }
}

/// c2 `generate_key(algorithm, *, size_bits, curve, label, key_id, template, public_template)`.
/// Required arguments go through `new`; the keyword arguments with defaults are the public
/// fields (refinement of PLAN §5's "implements Default": an algorithm/label default would be
/// meaningless).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerateRequest {
    pub algorithm: KeyAlgorithm,
    pub size_bits: Option<u32>,
    pub curve: Option<Curve>,
    pub label: String,
    pub key_id: Option<Vec<u8>>,
    /// Secret key template, or the PRIVATE half of a keypair.
    pub template: Option<KeyTemplate>,
    /// PUBLIC half of a keypair.
    pub public_template: Option<KeyTemplate>,
}
impl GenerateRequest {
    pub fn new(algorithm: KeyAlgorithm, label: impl Into<String>) -> Self {
        Self {
            algorithm,
            size_bits: None,
            curve: None,
            label: label.into(),
            key_id: None,
            template: None,
            public_template: None,
        }
    }
}

/// The `options` escape hatch of wrap/unwrap (frozen-provisional, §4.11). No c2 call site
/// passes options (verified at 408d6f2), so it has no fields yet; additions go through
/// §4.11 and keep `Default`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct WrapOptions {}

/// c2 `unwrap_key(…, *, result_algorithm, result_class, label, key_id, template, options)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwrapRequest {
    pub result_algorithm: KeyAlgorithm,
    pub result_class: KeyClass,
    pub label: String,
    /// Same semantics as import/generate — how `copy --id` reaches the wrap routes.
    pub key_id: Option<Vec<u8>>,
    pub template: Option<KeyTemplate>,
    pub options: WrapOptions,
}
impl UnwrapRequest {
    pub fn new(
        result_algorithm: KeyAlgorithm,
        result_class: KeyClass,
        label: impl Into<String>,
    ) -> Self {
        Self {
            result_algorithm,
            result_class,
            label: label.into(),
            key_id: None,
            template: None,
            options: WrapOptions::default(),
        }
    }
}
