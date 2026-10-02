//! Pkcs11Provider: struct, construction, `impl Provider`, lifecycle, login, token
//! enumeration, init_token and §5.2 auto-recovery (spec §4.5.5; owner R5a). The object
//! verbs live in `objects.rs` (R5a) and the crypto/wrap/edit verbs in R5b's files.
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::{CustomAttributeDef, Pkcs11InstanceConfig};
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::KeyInfo;
use r2_provider::{AuthState, ProviderStatus, TokenInfo};
use secrecy::SecretString;

use crate::backend::cryptoki::CryptokiBackend;
use crate::backend::{Backend, BackendError, RawTokenInfo, UserKind};
use crate::ckr::{self, rv};

/// Errors inside a session operation: a raw backend failure (translated by `op`, after the
/// §5.2 recovery check) or an already translated console error (passed through).
#[derive(Debug)]
pub(crate) enum OpError {
    Backend(BackendError),
    Console(ConsoleError),
}
impl From<BackendError> for OpError {
    fn from(err: BackendError) -> Self {
        OpError::Backend(err)
    }
}
impl From<ConsoleError> for OpError {
    fn from(err: ConsoleError) -> Self {
        OpError::Console(err)
    }
}
pub(crate) type OResult<T> = std::result::Result<T, OpError>;

/// Session/login state (c2 `_session`/`_slot`/`_token`/`_auth`/`_pin`/`_keep_pin`/
/// `_mech_codes`; the session itself lives in the backend).
#[derive(Default)]
struct State {
    initialized: bool,
    slot: Option<u64>,
    token: Option<TokenInfo>,
    logged_in: bool,
    /// Held only with keep_pin = true (§5.2); never persisted or logged.
    pin: Option<SecretString>,
    keep_pin: bool,
    mech_codes: Vec<u64>,
}

pub struct Pkcs11Provider {
    name: String,
    config: Pkcs11InstanceConfig,
    custom_by_ckm: BTreeMap<u64, String>,
    custom_attributes: IndexMap<String, CustomAttributeDef>,
    backend: Rc<dyn Backend>,
    state: RefCell<State>,
}

fn token_from_raw(info: RawTokenInfo) -> TokenInfo {
    TokenInfo {
        slot_id: info.slot_id,
        label: info.label,
        manufacturer: info.manufacturer,
        model: info.model,
        serial: info.serial,
    }
}

fn is_recoverable(err: &BackendError) -> bool {
    matches!(
        ckr::code_of(err),
        Some(rv::CKR_SESSION_HANDLE_INVALID | rv::CKR_DEVICE_REMOVED)
    )
}

fn session_lost() -> ConsoleError {
    ConsoleError::auth_required("session lost — login again")
}

impl Pkcs11Provider {
    /// Never touches the library (lazy initialize, §6). `custom_mechanisms` = the plain map
    /// {entry.ckm: entry.id} from config (§4.6); `custom_attributes` =
    /// templates.custom_attributes (§4.8).
    pub fn new(
        name: &str,
        config: Pkcs11InstanceConfig,
        custom_mechanisms: BTreeMap<u64, String>,
        custom_attributes: IndexMap<String, CustomAttributeDef>,
    ) -> Self {
        let backend: Rc<dyn Backend> = Rc::new(CryptokiBackend::new(&config));
        Self::build(name, config, custom_mechanisms, custom_attributes, backend)
    }

    fn build(
        name: &str,
        config: Pkcs11InstanceConfig,
        custom_mechanisms: BTreeMap<u64, String>,
        custom_attributes: IndexMap<String, CustomAttributeDef>,
        backend: Rc<dyn Backend>,
    ) -> Self {
        Self {
            name: name.to_string(),
            config,
            custom_by_ckm: custom_mechanisms,
            custom_attributes,
            backend,
            state: RefCell::new(State::default()),
        }
    }

    /// = TokenInit::init_token (kept inherent for parity with c2's surface): C_InitToken on
    /// `slot` (label ≤ 32 UTF-8 bytes, space-padded by the backend), re-find the token by
    /// label, then on an RW session login(SO) + C_InitPIN + logout.
    pub fn init_token(
        &self,
        slot: u64,
        label: &str,
        so_pin: &SecretString,
        user_pin: &SecretString,
    ) -> Result<()> {
        if label.len() > 32 {
            return Err(ConsoleError::param(
                "token label must be at most 32 bytes",
                "label",
            ));
        }
        r2_provider::Provider::initialize(self)?;
        let context = "token initialization";
        let backend = Rc::clone(&self.backend);
        let had_session = backend.has_session();
        let replaced = std::cell::Cell::new(false);
        let result = (|| -> std::result::Result<u64, BackendError> {
            backend.init_token(slot, so_pin, label)?;
            // SoftHSM reassigns slot ids on init — find the token by label
            let mut new_slot = slot;
            for candidate in backend.slots_with_token()? {
                if backend.token_info(candidate)?.label == label {
                    new_slot = candidate;
                    break;
                }
            }
            replaced.set(true); // open_session closes the provider's session first
            backend.open_session(new_slot)?;
            let inner = (|| {
                backend.login(UserKind::So, so_pin)?;
                backend.init_pin(user_pin)?;
                backend.logout()
            })();
            let _ = backend.close_session(); // best-effort cleanup
            inner.map(|()| new_slot)
        })();
        if had_session && replaced.get() {
            // the backend owns ONE session: the init session replaced the provider's
            // (§11 D15(c)); a C_InitToken failure leaves the provider's session alone
            self.drop_session();
        }
        match result {
            Ok(new_slot) => {
                tracing::info!(
                    target: "r2::pkcs11",
                    "{}: initialized token '{}' (slot {})",
                    self.name,
                    label,
                    new_slot
                );
                Ok(())
            }
            Err(err) => Err(self.translate(err, context)),
        }
    }

    /// FakeBackend constructor for r2-pkcs11's own tests (§4.10.4).
    #[cfg(test)]
    pub(crate) fn with_backend(
        name: &str,
        config: Pkcs11InstanceConfig,
        custom_mechanisms: BTreeMap<u64, String>,
        custom_attributes: IndexMap<String, CustomAttributeDef>,
        backend: std::rc::Rc<dyn crate::backend::Backend>,
    ) -> Self {
        Self::build(name, config, custom_mechanisms, custom_attributes, backend)
    }

    // ------------------------------------------------------------------
    // crate-internal accessors (also used by R5b's verbs)
    // ------------------------------------------------------------------

    pub(crate) fn backend(&self) -> &dyn Backend {
        self.backend.as_ref()
    }

    pub(crate) fn provider_name(&self) -> &str {
        &self.name
    }

    pub(crate) fn custom_attributes(&self) -> &IndexMap<String, CustomAttributeDef> {
        &self.custom_attributes
    }

    /// The CKM codes the logged-in token listed (unfiltered).
    #[allow(
        dead_code,
        reason = "consumed by R5b's verbs (crypto/wrap/derive/edit)"
    )]
    pub(crate) fn mech_codes(&self) -> Vec<u64> {
        self.state.borrow().mech_codes.clone()
    }

    fn token_label(&self) -> Option<String> {
        self.state.borrow().token.as_ref().map(|t| t.label.clone())
    }

    /// The choke point as the provider uses it: translate (labels from the current token)
    /// and log "{provider}: {context} failed with {CKR}" at INFO.
    pub(crate) fn translate(&self, err: BackendError, context: &str) -> ConsoleError {
        let label = self.token_label();
        self.translate_for(err, context, label.as_deref())
    }

    fn translate_for(
        &self,
        err: BackendError,
        context: &str,
        token_label: Option<&str>,
    ) -> ConsoleError {
        if let Some(code) = ckr::code_of(&err) {
            tracing::info!(
                target: "r2::pkcs11",
                "{}: {} failed with {}",
                self.name,
                context,
                crate::catalog::ckr_name(code)
            );
        }
        ckr::translate(err, &self.name, context, token_label)
    }

    pub(crate) fn auth_required(&self) -> ConsoleError {
        ConsoleError::auth_required(format!("login required: run `login {}`", self.name))
    }

    fn require_session(&self) -> Result<()> {
        let logged_in = self.state.borrow().logged_in;
        if !logged_in || !self.backend.has_session() {
            return Err(self.auth_required());
        }
        Ok(())
    }

    /// c2 `_drop_session`: forget slot/login/PIN/mechanisms and close the session (errors
    /// suppressed — it is already gone, that is why it is dropped).
    pub(crate) fn drop_session(&self) {
        {
            let mut state = self.state.borrow_mut();
            state.slot = None;
            state.logged_in = false;
            state.pin = None;
            state.mech_codes.clear();
        }
        if self.backend.has_session() {
            let _ = self.backend.close_session();
        }
    }

    fn find_slot_by_serial(&self, serial: &str) -> std::result::Result<Option<u64>, BackendError> {
        for slot in self.backend.slots_with_token()? {
            if self.backend.token_info(slot)?.serial == serial {
                return Ok(Some(slot));
            }
        }
        Ok(None)
    }

    /// Keep-pin-gated §5.2 auto-recovery: reopen, re-login, refresh the mechanism list.
    fn recover_session(&self) -> Result<()> {
        tracing::info!(target: "r2::pkcs11", "{}: session dropped — attempting recovery", self.name);
        let (keep_pin, pin, token) = {
            let state = self.state.borrow();
            (state.keep_pin, state.pin.clone(), state.token.clone())
        };
        let (Some(pin), Some(token)) = (pin.filter(|_| keep_pin), token) else {
            self.drop_session();
            return Err(session_lost().with_hint(format!(
                "run `login {}` (use --keep-pin for auto-reconnect)",
                self.name
            )));
        };
        let _ = self.backend.close_session(); // stale handle; expected during recovery
        let attempt = (|| -> std::result::Result<Option<(u64, Vec<u64>)>, BackendError> {
            let Some(slot) = self.find_slot_by_serial(&token.serial)? else {
                return Ok(None);
            };
            self.backend.open_session(slot)?;
            self.login_session(&pin)?;
            let codes = self.backend.mechanism_list(slot)?;
            crate::capability::note_listed_mechanisms(&codes);
            Ok(Some((slot, codes)))
        })();
        match attempt {
            Ok(Some((slot, codes))) => {
                let mut state = self.state.borrow_mut();
                state.slot = Some(slot);
                state.token = Some(TokenInfo {
                    slot_id: slot,
                    ..token
                });
                state.mech_codes = codes;
                drop(state);
                tracing::info!(target: "r2::pkcs11", "{}: session recovered on slot {}", self.name, slot);
                Ok(())
            }
            Ok(None) => {
                self.drop_session();
                Err(ConsoleError::auth_required(format!(
                    "token '{}' is no longer present — login again",
                    token.label
                )))
            }
            Err(_) => {
                self.drop_session();
                Err(session_lost())
            }
        }
    }

    /// Run a session operation through the choke point with §5.2 auto-recovery: on
    /// CKR_SESSION_HANDLE_INVALID / CKR_DEVICE_REMOVED the session is recovered (keep-pin
    /// only) and `f` retried exactly once.
    pub(crate) fn op<T>(&self, context: &str, f: impl Fn() -> OResult<T>) -> Result<T> {
        self.require_session()?;
        match f() {
            Ok(value) => Ok(value),
            Err(OpError::Console(err)) => Err(err),
            Err(OpError::Backend(err)) if !is_recoverable(&err) => {
                Err(self.translate(err, context))
            }
            Err(OpError::Backend(_)) => {
                self.recover_session()?;
                match f() {
                    Ok(value) => Ok(value),
                    Err(OpError::Console(err)) => Err(err),
                    Err(OpError::Backend(err)) if is_recoverable(&err) => {
                        self.drop_session();
                        Err(session_lost())
                    }
                    Err(OpError::Backend(err)) => Err(self.translate(err, context)),
                }
            }
        }
    }

    /// C_Login(CKU_USER), swallowing a raw CKR_USER_ALREADY_LOGGED_IN (§5.2).
    fn login_session(&self, pin: &SecretString) -> std::result::Result<(), BackendError> {
        match self.backend.login(UserKind::User, pin) {
            Err(err) if ckr::code_of(&err) == Some(rv::CKR_USER_ALREADY_LOGGED_IN) => Ok(()),
            other => other,
        }
    }

    /// Canonical name advertised? Else UnsupportedOperation (c2 `_check_advertised`).
    #[allow(
        dead_code,
        reason = "consumed by R5b's verbs (crypto/wrap/derive/edit)"
    )]
    pub(crate) fn check_advertised(&self, mechanism: &str) -> Result<()> {
        if r2_provider::Provider::mechanisms(self).contains(mechanism) {
            return Ok(());
        }
        Err(ConsoleError::unsupported(format!(
            "{} does not support mechanism {mechanism}",
            self.name
        )))
    }

    /// Does the token list the CKM named `name` (PyKCS11 name table)?
    #[allow(
        dead_code,
        reason = "consumed by R5b's verbs (crypto/wrap/derive/edit)"
    )]
    pub(crate) fn has_ckm(&self, name: &str) -> bool {
        crate::catalog::symbol_value(name).is_some_and(|code| self.mech_codes().contains(&code))
    }

    /// The code of CKM `name`, or UnsupportedOperation "token lacks {name} for {context}".
    #[allow(
        dead_code,
        reason = "consumed by R5b's verbs (crypto/wrap/derive/edit)"
    )]
    pub(crate) fn require_ckm(&self, name: &str, context: &str) -> Result<u64> {
        match crate::catalog::symbol_value(name) {
            Some(code) if self.mech_codes().contains(&code) => Ok(code),
            _ => Err(ConsoleError::unsupported(format!(
                "token lacks {name} for {context}"
            ))),
        }
    }
}

impl r2_provider::Provider for Pkcs11Provider {
    fn name(&self) -> &str {
        &self.name
    }
    fn type_name(&self) -> &str {
        "pkcs11"
    }

    fn initialize(&self) -> Result<()> {
        if self.state.borrow().initialized {
            return Ok(());
        }
        // §5.2: the instance env is applied before C_Initialize, on every provider's own
        // first initialize (also when another provider already loaded the library)
        let vars: Vec<(&str, &str)> = self
            .config
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let library = self.config.library.display().to_string();
        if let Some((key, detail)) = vars
            .iter()
            .find_map(|(k, v)| env_refusal(k, v).map(|d| (*k, d)))
        {
            // §11 D12(n): c2's os.environ raised ValueError/OSError out of initialize
            return Err(ConsoleError::provider_unavailable(format!(
                "cannot load PKCS#11 library {library}: {detail}: {}",
                r2_core::text::py_repr(key)
            ))
            .with_hint("check providers.pkcs11[].env in the configuration"));
        }
        crate::env::apply_env(&vars);
        if let Err(err) = self.backend.initialize() {
            // every initialize failure is a load failure (§5.2), rendered at the choke point
            let detail = match err {
                BackendError::LibraryUnavailable(detail) | BackendError::Binding(detail) => detail,
                BackendError::Ckr(c) => ckr::pykcs11_error_text(c.code),
            };
            return Err(ckr::translate(
                BackendError::LibraryUnavailable(detail),
                &self.name,
                &library,
                None,
            ));
        }
        self.state.borrow_mut().initialized = true;
        tracing::info!(target: "r2::pkcs11", "{}: loaded PKCS#11 library {}", self.name, library);
        Ok(())
    }

    fn shutdown(&self) -> Result<()> {
        {
            let mut state = self.state.borrow_mut();
            state.pin = None;
            state.keep_pin = false;
        }
        if self.backend.has_session() {
            let _ = self.backend.logout(); // shutdown is best-effort
        }
        self.drop_session();
        let initialized = {
            let mut state = self.state.borrow_mut();
            state.token = None;
            std::mem::take(&mut state.initialized)
        };
        if initialized && let Err(err) = self.backend.finalize() {
            // refcounted; a failure must not block exit
            tracing::info!(target: "r2::pkcs11", "{}: finalize failed: {:?}", self.name, err);
        }
        Ok(())
    }

    fn status(&self) -> ProviderStatus {
        // never loads the library (§6: status must work for broken configs)
        let state = self.state.borrow();
        if state.logged_in {
            ProviderStatus {
                auth: AuthState::LoggedIn,
                token: state.token.clone(),
            }
        } else {
            ProviderStatus {
                auth: AuthState::LoggedOut,
                token: None,
            }
        }
    }

    fn list_tokens(&self) -> Result<Vec<TokenInfo>> {
        self.initialize()?;
        let tokens = (|| -> std::result::Result<Vec<TokenInfo>, BackendError> {
            let mut tokens = Vec::new();
            for slot in self.backend.slots_with_token()? {
                tokens.push(token_from_raw(self.backend.token_info(slot)?));
            }
            Ok(tokens)
        })();
        tokens.map_err(|err| self.translate(err, "token enumeration"))
    }

    fn login(&self, token: &TokenInfo, pin: &SecretString, keep_pin: bool) -> Result<()> {
        if self.state.borrow().logged_in {
            return Err(
                ConsoleError::already_logged_in("already logged in").with_hint("logout first")
            );
        }
        self.initialize()?;
        let current_slot = self.state.borrow().slot;
        if self.backend.has_session() && current_slot != Some(token.slot_id) {
            // one token of one device at a time per provider (§5.2)
            self.drop_session();
        }
        let reused = self.backend.has_session();
        let sequence = (|| -> std::result::Result<Vec<u64>, BackendError> {
            if !reused {
                self.backend.open_session(token.slot_id)?;
            }
            self.login_session(pin)?;
            let codes = self.backend.mechanism_list(token.slot_id)?;
            crate::capability::note_listed_mechanisms(&codes);
            Ok(codes)
        })();
        let codes = match sequence {
            Ok(codes) => codes,
            Err(err) => {
                if !reused && self.backend.has_session() {
                    // never leak a freshly opened session on a failed login
                    let _ = self.backend.close_session();
                }
                return Err(self.translate_for(err, "login", Some(&token.label)));
            }
        };
        // commit state only after the whole sequence succeeded
        let count = codes.len();
        {
            let mut state = self.state.borrow_mut();
            state.slot = Some(token.slot_id);
            state.token = Some(token.clone());
            state.logged_in = true;
            state.keep_pin = keep_pin;
            state.pin = keep_pin.then(|| pin.clone());
            state.mech_codes = codes;
        }
        tracing::info!(
            target: "r2::pkcs11",
            "{}: logged in to token '{}' (slot {}, keep_pin={}, {} mechanisms)",
            self.name,
            token.label,
            token.slot_id,
            r2_core::text::py_bool(keep_pin),
            count
        );
        Ok(())
    }

    fn logout(&self) -> Result<()> {
        let logged_in = {
            let mut state = self.state.borrow_mut();
            state.pin = None;
            state.keep_pin = false;
            state.logged_in
        };
        if self.backend.has_session()
            && logged_in
            && let Err(err) = self.backend.logout()
        {
            let ignorable = matches!(
                ckr::code_of(&err),
                Some(
                    rv::CKR_USER_NOT_LOGGED_IN
                        | rv::CKR_SESSION_HANDLE_INVALID
                        | rv::CKR_DEVICE_REMOVED
                )
            );
            if !ignorable {
                self.state.borrow_mut().logged_in = false;
                return Err(self.translate(err, "logout"));
            }
        }
        self.state.borrow_mut().logged_in = false;
        tracing::info!(target: "r2::pkcs11", "{}: logged out", self.name);
        Ok(())
    }

    fn mechanisms(&self) -> BTreeSet<String> {
        let codes = {
            let state = self.state.borrow();
            if !state.logged_in {
                return BTreeSet::new();
            }
            state.mech_codes.clone()
        };
        crate::capability::fold_mechanisms(&codes, &self.custom_by_ckm)
    }

    fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        self.list_keys_impl()
    }
    fn find_key(&self, selector: &r2_provider::KeySelector) -> Result<KeyInfo> {
        self.find_key_impl(selector)
    }
    fn import_key(
        &self,
        material: &r2_core::keys::KeyMaterial,
        label: &str,
        template: Option<&r2_core::template::KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> Result<KeyInfo> {
        self.import_key_impl(material, label, template, key_id)
    }
    fn generate_key(&self, request: &r2_provider::GenerateRequest) -> Result<KeyInfo> {
        self.generate_key_impl(request)
    }
    fn delete_key(&self, key: &KeyInfo) -> Result<()> {
        self.delete_key_impl(key)
    }
    fn export_key(&self, key: &KeyInfo) -> Result<r2_core::keys::KeyMaterial> {
        self.export_key_impl(key)
    }
    fn encrypt(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        data: &[u8],
    ) -> r2_core::Result<Vec<u8>> {
        self.encrypt_impl(key, mech, data)
    }
    fn decrypt(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        data: &[u8],
    ) -> r2_core::Result<zeroize::Zeroizing<Vec<u8>>> {
        self.decrypt_impl(key, mech, data)
    }
    fn sign(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        data: &[u8],
    ) -> r2_core::Result<Vec<u8>> {
        self.sign_impl(key, mech, data)
    }
    fn verify(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> r2_core::Result<bool> {
        self.verify_impl(key, mech, data, signature)
    }
    fn derive(
        &self,
        key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
    ) -> r2_core::Result<r2_provider::DeriveResult> {
        self.derive_impl(key, mech)
    }
    fn wrap_key(
        &self,
        wrapping_key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        target: &r2_core::keys::KeyInfo,
        options: &r2_provider::WrapOptions,
    ) -> r2_core::Result<Vec<u8>> {
        self.wrap_key_impl(wrapping_key, mech, target, options)
    }
    fn unwrap_key(
        &self,
        wrapping_key: &r2_core::keys::KeyInfo,
        mech: &r2_provider::MechanismInvocation,
        wrapped: &[u8],
        request: &r2_provider::UnwrapRequest,
    ) -> r2_core::Result<r2_core::keys::KeyInfo> {
        self.unwrap_key_impl(wrapping_key, mech, wrapped, request)
    }
    fn read_key_template(
        &self,
        key: &r2_core::keys::KeyInfo,
    ) -> r2_core::Result<r2_core::template::KeyTemplate> {
        self.read_key_template_impl(key)
    }
    fn update_key(
        &self,
        key: &r2_core::keys::KeyInfo,
        changes: &r2_core::template::KeyTemplate,
    ) -> r2_core::Result<r2_provider::KeyEditResult> {
        self.update_key_impl(key, changes)
    }
    fn read_full_template(
        &self,
        key: &r2_core::keys::KeyInfo,
    ) -> r2_core::Result<r2_core::template::KeyTemplate> {
        self.read_full_template_impl(key)
    }
    fn as_token_init(&self) -> Option<&dyn r2_provider::TokenInit> {
        Some(self)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl r2_provider::TokenInit for Pkcs11Provider {
    fn init_token(
        &self,
        slot: u64,
        label: &str,
        so_pin: &SecretString,
        user_pin: &SecretString,
    ) -> Result<()> {
        Pkcs11Provider::init_token(self, slot, label, so_pin, user_pin)
    }

    /// §5.13 step 2: set `key=value` at the single audited set_var site, then shut down
    /// (the last release finalizes) so the next lazy initialize re-reads the environment —
    /// refused when another provider holds the same module.
    fn set_env_and_reset(&self, key: &str, value: &str) -> Result<()> {
        if !self.backend.is_sole_module_user() {
            return Err(ConsoleError::provider(format!(
                "'{}' shares its PKCS#11 module with another provider",
                self.name
            ))
            .with_hint("restart r2 after the setup, or remove the other provider entry"));
        }
        if let Some(detail) = env_refusal(key, value) {
            return Err(ConsoleError::provider(format!(
                "cannot set environment variable {}: {detail}",
                r2_core::text::py_repr(key)
            )));
        }
        crate::env::apply_env(&[(key, value)]);
        r2_provider::Provider::shutdown(self)
    }
}

/// Why `std::env::set_var(key, value)` would panic (empty key, `=` or NUL in the key, NUL
/// in the value), in Python's `os.environ` wording; None = settable.
pub(crate) fn env_refusal(key: &str, value: &str) -> Option<&'static str> {
    if key.contains('\0') || value.contains('\0') {
        Some("embedded null byte")
    } else if key.is_empty() || key.contains('=') {
        Some("illegal environment variable name")
    } else {
        None
    }
}

mod crypto;
mod edit;
mod objects;
mod wrap;
