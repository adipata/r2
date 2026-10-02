//! FakeBackend — in-memory `Backend` double for r2-pkcs11's own tests (spec §4.10.4); a port
//! of c2's `tests/support/fake_pykcs11.py` behind the raw §4.5.6 seam. SoftHSM-flavored:
//! imported/generated keys default CKA_SENSITIVE=false, CKA_EXTRACTABLE=false; CKA_VALUE
//! reads return None unless extractable and not sensitive; one-shot encrypt of empty input
//! fails (multi-part works); OAEP accepts only SHA-1/MGF1-SHA1 with an empty label;
//! imported key objects read CKA_KEY_GEN_MECHANISM = CK_UNAVAILABLE_INFORMATION;
//! `find_objects` returns matches in creation order.
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use cryptoki_sys as sys;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use super::{BResult, Backend, BackendError, Ckr, MechSpec, RawAttr, RawTokenInfo, UserKind};
use crate::attributes::{decode_ulong, ulong_bytes};
use crate::ckr::rv;

fn w(code: sys::CK_ULONG) -> u64 {
    crate::ulong_to_u64(code)
}

fn fail(code: u64, function: &'static str) -> BackendError {
    BackendError::Ckr(Ckr { code, function })
}

fn ul(value: u64) -> Vec<u8> {
    ulong_bytes(value).unwrap_or_default()
}

fn keystream(secret: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 32);
    let mut counter: u32 = 0;
    while out.len() < length {
        let mut block = secret.to_vec();
        block.push(b'|');
        block.extend_from_slice(context);
        block.push(b'|');
        block.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&openssl::sha::sha256(&block));
        counter += 1;
    }
    out.truncate(length);
    out
}

fn xor(data: &[u8], stream: &[u8]) -> Vec<u8> {
    data.iter().zip(stream).map(|(a, b)| a ^ b).collect()
}

/// One fake token in one slot; login state is token-wide.
#[derive(Clone, Debug)]
struct Token {
    /// As stored by C_InitToken (32-byte space-padded) or as configured.
    label: String,
    manufacturer: String,
    model: String,
    serial: String,
    initialized: bool,
    user_pin: String,
    so_pin: String,
    mechanisms: Vec<u64>,
    pin_locked: bool,
    logged_in: bool,
    so_logged_in: bool,
}

impl Token {
    fn new(info: &RawTokenInfo, mechanisms: Vec<u64>) -> Self {
        Self {
            label: info.label.clone(),
            manufacturer: info.manufacturer.clone(),
            model: info.model.clone(),
            serial: info.serial.clone(),
            initialized: info.initialized,
            user_pin: "1234".into(),
            so_pin: "4321".into(),
            mechanisms,
            pin_locked: false,
            logged_in: false,
            so_logged_in: false,
        }
    }
}

#[derive(Clone, Debug)]
struct Object {
    slot: u64,
    attrs: BTreeMap<u64, Vec<u8>>,
    /// Hidden per-object transform secret (never a CKA).
    secret: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Session {
    slot: u64,
    invalidated: bool,
}

#[derive(Default)]
struct State {
    slots: BTreeMap<u64, Token>,
    objects: BTreeMap<u64, Object>,
    next_handle: u64,
    gen_counter: u64,
    initialized: bool,
    load_error: Option<String>,
    init_count: usize,
    finalize_count: usize,
    shared: bool,
    session: Option<Session>,
    sessions_opened: usize,
    invalidate_all: bool,
    forbid_extractable_secrets: bool,
    fail_next: Vec<(&'static str, u64)>,
    fail_always: Vec<(&'static str, u64)>,
    read_only: BTreeSet<u64>,
    /// (object, attribute) → the CKR its size pass reports.
    refused_reads: BTreeMap<(u64, u64), u64>,
    calls: Vec<&'static str>,
    last_mechanism: Option<MechSpec>,
    // ---- R5b knobs ----
    /// Invalidate the session right after the next successful `set_attrs` (the write
    /// landed, then the token dropped the session).
    invalidate_after_set: bool,
    /// `unwrap_key` fails with this CKR whenever its template carries this attribute.
    reject_unwrap_attr: Option<(u64, u64)>,
    /// The attribute types of every `unwrap_key` template, in call order.
    unwrap_templates: Vec<Vec<u64>>,
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

/// The CKM code a MechSpec invokes.
pub(crate) fn spec_ckm(spec: &MechSpec) -> u64 {
    match spec {
        MechSpec::Plain { ckm }
        | MechSpec::Bytes { ckm, .. }
        | MechSpec::Gcm { ckm, .. }
        | MechSpec::Oaep { ckm, .. }
        | MechSpec::Pss { ckm, .. }
        | MechSpec::Eddsa { ckm, .. } => *ckm,
        MechSpec::Ctr { .. } => w(sys::CKM_AES_CTR),
        MechSpec::Ecdh1 { .. } => w(sys::CKM_ECDH1_DERIVE),
    }
}

pub(crate) struct FakeBackend {
    state: RefCell<State>,
}

impl FakeBackend {
    /// One slot 0 holding an initialized token (label "fake-token", serial "FAKE0001",
    /// user PIN "1234", SO PIN "4321") and DEFAULT_MECHANISMS.
    pub(crate) fn new() -> Self {
        Self::with_slots(vec![(
            0,
            Self::token("fake-token", "FAKE0001"),
            DEFAULT_MECHANISMS.to_vec(),
        )])
    }

    /// A RawTokenInfo for `with_slots` (manufacturer "r2", model "FakeBackend",
    /// initialized; `slot_id` is replaced by the slot it is installed in).
    pub(crate) fn token(label: &str, serial: &str) -> RawTokenInfo {
        RawTokenInfo {
            slot_id: 0,
            label: label.into(),
            manufacturer: "r2".into(),
            model: "FakeBackend".into(),
            serial: serial.into(),
            initialized: true,
        }
    }

    /// Replace the slot set: (slot id, token info, mechanism codes).
    pub(crate) fn with_slots(slots: Vec<(u64, RawTokenInfo, Vec<u64>)>) -> Self {
        let state = State {
            slots: slots
                .into_iter()
                .map(|(slot, info, mechs)| (slot, Token::new(&info, mechs)))
                .collect(),
            next_handle: 1,
            shared: false,
            read_only: [
                sys::CKA_CLASS,
                sys::CKA_KEY_TYPE,
                sys::CKA_TOKEN,
                sys::CKA_LOCAL,
                sys::CKA_MODIFIABLE,
                sys::CKA_NEVER_EXTRACTABLE,
                sys::CKA_ALWAYS_SENSITIVE,
            ]
            .into_iter()
            .map(w)
            .collect(),
            ..State::default()
        };
        Self {
            state: RefCell::new(state),
        }
    }

    /// Inject `rv` for the next call of the named Backend method (e.g. "login",
    /// "unwrap_key"); `fail_always` for every call until cleared.
    pub(crate) fn fail_next(&self, method: &'static str, rv: u64) {
        self.state.borrow_mut().fail_next.push((method, rv));
    }
    /// Make the size pass of reading `attribute` on `object` answer `rv`.
    pub(crate) fn refuse_read(&self, object: u64, attribute: u64, rv: u64) {
        self.state
            .borrow_mut()
            .refused_reads
            .insert((object, attribute), rv);
    }
    pub(crate) fn fail_always(&self, method: &'static str, rv: u64) {
        self.state.borrow_mut().fail_always.push((method, rv));
    }
    pub(crate) fn clear_failures(&self) {
        let mut state = self.state.borrow_mut();
        state.fail_next.clear();
        state.fail_always.clear();
        state.invalidate_all = false;
    }
    /// The next session-bound call fails with CKR_SESSION_HANDLE_INVALID (auto-recovery tests):
    /// the current session is dropped by the "token" and stays invalid until replaced.
    pub(crate) fn invalidate_session(&self) {
        if let Some(session) = self.state.borrow_mut().session.as_mut() {
            session.invalidated = true;
        }
    }
    /// Attribute types that C_SetAttributeValue refuses with CKR_ATTRIBUTE_READ_ONLY
    /// (CKA_SENSITIVE true→false / CKA_EXTRACTABLE false→true one-direction rules are built in).
    pub(crate) fn set_read_only(&self, attrs: &[u64]) {
        self.state.borrow_mut().read_only = attrs.iter().copied().collect();
    }
    /// Backend method names called, in order.
    pub(crate) fn calls(&self) -> Vec<&'static str> {
        self.state.borrow().calls.clone()
    }
    /// Stored objects: (handle, attribute map) — copies for assertions (test-only data).
    pub(crate) fn objects(&self) -> Vec<(u64, BTreeMap<u64, Vec<u8>>)> {
        self.state
            .borrow()
            .objects
            .iter()
            .map(|(h, o)| (*h, o.attrs.clone()))
            .collect()
    }
    /// The last MechSpec handed to a crypto call (packer tests).
    pub(crate) fn last_mechanism(&self) -> Option<MechSpec> {
        self.state.borrow().last_mechanism.clone()
    }

    // ---- further test hooks (r2 additions to the frozen list; crate-private) ----

    /// `initialize` fails like a library that cannot be loaded.
    pub(crate) fn set_load_error(&self, detail: &str) {
        self.state.borrow_mut().load_error = Some(detail.into());
    }
    /// (initialize calls that loaded, finalize calls that unloaded).
    pub(crate) fn load_counts(&self) -> (usize, usize) {
        let state = self.state.borrow();
        (state.init_count, state.finalize_count)
    }
    /// Pretend another backend holds the same module (`is_sole_module_user` false).
    pub(crate) fn set_shared(&self, shared: bool) {
        self.state.borrow_mut().shared = shared;
    }
    /// Number of sessions ever opened.
    pub(crate) fn sessions_opened(&self) -> usize {
        self.state.borrow().sessions_opened
    }
    /// Slot of the open session, if any.
    pub(crate) fn session_slot(&self) -> Option<u64> {
        self.state.borrow().session.as_ref().map(|s| s.slot)
    }
    /// Every session-bound call fails with CKR_SESSION_HANDLE_INVALID (c2 `invalidate_ops`).
    pub(crate) fn invalidate_all(&self) {
        self.state.borrow_mut().invalidate_all = true;
    }
    /// The token in `slot` is pulled.
    pub(crate) fn remove_slot(&self, slot: u64) {
        self.state.borrow_mut().slots.remove(&slot);
    }
    pub(crate) fn set_pin_locked(&self, slot: u64, locked: bool) {
        if let Some(token) = self.state.borrow_mut().slots.get_mut(&slot) {
            token.pin_locked = locked;
        }
    }
    /// Token-wide login state as another client left it.
    pub(crate) fn set_logged_in(&self, slot: u64, logged_in: bool) {
        if let Some(token) = self.state.borrow_mut().slots.get_mut(&slot) {
            token.logged_in = logged_in;
        }
    }
    pub(crate) fn is_logged_in(&self, slot: u64) -> bool {
        self.state
            .borrow()
            .slots
            .get(&slot)
            .is_some_and(|t| t.logged_in)
    }
    /// The label as C_InitToken stored it (unpadded readback is `token_info`'s job).
    pub(crate) fn raw_label(&self, slot: u64) -> Option<String> {
        self.state
            .borrow()
            .slots
            .get(&slot)
            .map(|t| t.label.clone())
    }
    /// C_DeriveKey refuses extractable secret templates (§5.10 [U]).
    pub(crate) fn set_forbid_extractable_secrets(&self, forbid: bool) {
        self.state.borrow_mut().forbid_extractable_secrets = forbid;
    }
    /// Write an object straight into the token store (a foreign client), bypassing every
    /// provider guard; returns its handle.
    pub(crate) fn plant_object(&self, slot: u64, attrs: Vec<(u64, Vec<u8>)>, secret: &[u8]) -> u64 {
        let mut state = self.state.borrow_mut();
        let handle = state.next_handle;
        state.next_handle += 1;
        state.objects.insert(
            handle,
            Object {
                slot,
                attrs: attrs.into_iter().collect(),
                secret: secret.to_vec(),
            },
        );
        handle
    }
    /// Clone an object (an external twin writer); `value` replaces CKA_VALUE and the secret.
    pub(crate) fn clone_object(&self, handle: u64, value: Option<&[u8]>) -> u64 {
        let mut state = self.state.borrow_mut();
        let Some(mut object) = state.objects.get(&handle).cloned() else {
            return 0;
        };
        if let Some(value) = value {
            object.attrs.insert(w(sys::CKA_VALUE), value.to_vec());
            object.secret = value.to_vec();
        }
        let new_handle = state.next_handle;
        state.next_handle += 1;
        state.objects.insert(new_handle, object);
        new_handle
    }

    // ---- R5b knobs (crate-private test hooks) ----

    /// The next successful `set_attrs` lands, then the session is invalidated (c2's
    /// `set_then_drop` patch).
    pub(crate) fn invalidate_after_next_set(&self) {
        self.state.borrow_mut().invalidate_after_set = true;
    }
    /// `unwrap_key` answers `rv` whenever its template carries attribute `attr` (c2's
    /// "picky" unwrapKey patch).
    pub(crate) fn reject_unwrap_with(&self, attr: u64, rv: u64) {
        self.state.borrow_mut().reject_unwrap_attr = Some((attr, rv));
    }
    /// The attribute types of every `unwrap_key` template, in call order.
    pub(crate) fn unwrap_templates(&self) -> Vec<Vec<u64>> {
        self.state.borrow().unwrap_templates.clone()
    }

    // ---- internals ----

    /// Record the call and apply injected failures.
    fn enter(&self, method: &'static str) -> BResult<()> {
        let mut state = self.state.borrow_mut();
        state.calls.push(method);
        if let Some((_, code)) = state.fail_always.iter().find(|(m, _)| *m == method) {
            return Err(fail(*code, method));
        }
        if let Some(pos) = state.fail_next.iter().position(|(m, _)| *m == method) {
            let (_, code) = state.fail_next.remove(pos);
            return Err(fail(code, method));
        }
        Ok(())
    }

    /// c2 `_check`: the session must be live (else CKR_SESSION_HANDLE_INVALID) and, for
    /// object/crypto calls, the token logged in (else CKR_USER_NOT_LOGGED_IN).
    fn check(&self, method: &'static str, need_login: bool) -> BResult<u64> {
        self.enter(method)?;
        let state = self.state.borrow();
        let session = match &state.session {
            Some(s) if !s.invalidated && !state.invalidate_all => s,
            _ => return Err(fail(rv::CKR_SESSION_HANDLE_INVALID, method)),
        };
        let Some(token) = state.slots.get(&session.slot) else {
            return Err(fail(rv::CKR_SESSION_HANDLE_INVALID, method));
        };
        if need_login && !token.logged_in {
            return Err(fail(rv::CKR_USER_NOT_LOGGED_IN, method));
        }
        Ok(session.slot)
    }

    fn require_mechanism(&self, slot: u64, spec: &MechSpec, method: &'static str) -> BResult<u64> {
        let mut state = self.state.borrow_mut();
        state.last_mechanism = Some(spec.clone());
        let code = spec_ckm(spec);
        let listed = state
            .slots
            .get(&slot)
            .is_some_and(|t| t.mechanisms.contains(&code));
        if !listed {
            return Err(fail(rv::CKR_MECHANISM_INVALID, method));
        }
        if let MechSpec::Oaep {
            ckm,
            hash_ckm,
            mgf,
            label,
        } = spec
            && *ckm == w(sys::CKM_RSA_PKCS_OAEP)
            && (*hash_ckm != w(sys::CKM_SHA_1)
                || *mgf != w(sys::CKG_MGF1_SHA1)
                || !label.is_empty())
        {
            return Err(fail(rv::CKR_ARGUMENTS_BAD, method));
        }
        Ok(code)
    }

    fn secret_of(&self, handle: u64, method: &'static str) -> BResult<Vec<u8>> {
        self.state
            .borrow()
            .objects
            .get(&handle)
            .map(|o| {
                if o.secret.is_empty() {
                    vec![0]
                } else {
                    o.secret.clone()
                }
            })
            .ok_or_else(|| fail(rv::CKR_KEY_HANDLE_INVALID, method))
    }

    fn store(&self, slot: u64, attrs: BTreeMap<u64, Vec<u8>>, secret: Vec<u8>) -> u64 {
        let mut state = self.state.borrow_mut();
        let handle = state.next_handle;
        state.next_handle += 1;
        state.objects.insert(
            handle,
            Object {
                slot,
                attrs,
                secret,
            },
        );
        handle
    }

    fn attr_map(template: &[RawAttr]) -> BTreeMap<u64, Vec<u8>> {
        template.iter().map(|(t, v)| (*t, v.to_vec())).collect()
    }

    fn flag(attrs: &BTreeMap<u64, Vec<u8>>, kind: sys::CK_ATTRIBUTE_TYPE) -> bool {
        attrs
            .get(&w(kind))
            .is_some_and(|v| v.iter().any(|b| *b != 0))
    }

    fn value_readable(attrs: &BTreeMap<u64, Vec<u8>>) -> bool {
        let class = attrs.get(&w(sys::CKA_CLASS)).map(|v| decode_ulong(v));
        let key = class == Some(w(sys::CKO_SECRET_KEY)) || class == Some(w(sys::CKO_PRIVATE_KEY));
        !key || (Self::flag(attrs, sys::CKA_EXTRACTABLE) && !Self::flag(attrs, sys::CKA_SENSITIVE))
    }

    fn gcm_tag(secret: &[u8], iv: &[u8], aad: &[u8], data: &[u8], tag_len: usize) -> Vec<u8> {
        let mut block = secret.to_vec();
        block.extend_from_slice(b"|tag|");
        block.extend_from_slice(iv);
        block.push(b'|');
        block.extend_from_slice(aad);
        block.push(b'|');
        block.extend_from_slice(data);
        openssl::sha::sha256(&block)[..tag_len.min(32)].to_vec()
    }

    fn signature(secret: &[u8], code: u64, data: &[u8]) -> Vec<u8> {
        let mut block = secret.to_vec();
        block.extend_from_slice(b"|sig|");
        block.extend_from_slice(&code.to_be_bytes());
        block.push(b'|');
        block.extend_from_slice(data);
        let digest = openssl::sha::sha256(&block).to_vec();
        let doubled = [digest.clone(), digest.clone()].concat();
        let hmac_width = [
            (sys::CKM_SHA_1_HMAC, 20),
            (sys::CKM_SHA224_HMAC, 28),
            (sys::CKM_SHA256_HMAC, 32),
            (sys::CKM_SHA384_HMAC, 48),
            (sys::CKM_SHA512_HMAC, 64),
        ]
        .into_iter()
        .find(|(c, _)| w(*c) == code)
        .map(|(_, n)| n);
        if code == w(sys::CKM_AES_CMAC) {
            digest[..16].to_vec()
        } else if [sys::CKM_ECDSA, sys::CKM_ECDSA_SHA256, sys::CKM_EDDSA]
            .into_iter()
            .any(|c| w(c) == code)
        {
            doubled
        } else if let Some(width) = hmac_width {
            doubled[..width].to_vec()
        } else {
            digest
        }
    }

    fn cipher(&self, encrypt: bool, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Vec<u8>> {
        let method = if encrypt { "encrypt" } else { "decrypt" };
        let slot = self.check(method, true)?;
        let code = self.require_mechanism(slot, mech, method)?;
        if encrypt && data.is_empty() {
            return Err(fail(rv::CKR_ARGUMENTS_BAD, method));
        }
        let secret = self.secret_of(key, method)?;
        if let MechSpec::Gcm {
            iv, aad, tag_bits, ..
        } = mech
        {
            let tag_len = usize::try_from(*tag_bits / 8).unwrap_or(16);
            let stream_ctx = [b"gcm|".as_slice(), iv].concat();
            if encrypt {
                let mut out = xor(data, &keystream(&secret, &stream_ctx, data.len()));
                out.extend(Self::gcm_tag(&secret, iv, aad, data, tag_len));
                return Ok(out);
            }
            if data.len() < tag_len {
                return Err(fail(rv::CKR_ENCRYPTED_DATA_INVALID, method));
            }
            let (body, tag) = data.split_at(data.len() - tag_len);
            let plain = xor(body, &keystream(&secret, &stream_ctx, body.len()));
            if Self::gcm_tag(&secret, iv, aad, &plain, tag_len) != tag {
                return Err(fail(rv::CKR_ENCRYPTED_DATA_INVALID, method));
            }
            return Ok(plain);
        }
        let ctx = format!("enc|{code}");
        if encrypt {
            let mut payload = data.to_vec();
            if code == w(sys::CKM_AES_CBC_PAD) {
                let pad = 16 - payload.len() % 16;
                payload.extend(std::iter::repeat_n(u8::try_from(pad).unwrap_or(16), pad));
            } else if code == w(sys::CKM_AES_ECB) && !payload.len().is_multiple_of(16) {
                return Err(fail(rv::CKR_DATA_LEN_RANGE, method));
            }
            return Ok(xor(
                &payload,
                &keystream(&secret, ctx.as_bytes(), payload.len()),
            ));
        }
        let mut plain = xor(data, &keystream(&secret, ctx.as_bytes(), data.len()));
        if code == w(sys::CKM_AES_CBC_PAD) {
            let pad = usize::from(*plain.last().unwrap_or(&0));
            if !(1..=16).contains(&pad) || pad > plain.len() {
                return Err(fail(rv::CKR_ENCRYPTED_DATA_INVALID, method));
            }
            plain.truncate(plain.len() - pad);
        }
        Ok(plain)
    }
}

impl Backend for FakeBackend {
    fn initialize(&self) -> BResult<()> {
        self.enter("initialize")?;
        let mut state = self.state.borrow_mut();
        if let Some(detail) = &state.load_error {
            return Err(BackendError::LibraryUnavailable(detail.clone()));
        }
        if !state.initialized {
            state.initialized = true;
            state.init_count += 1;
        }
        Ok(())
    }

    fn finalize(&self) -> BResult<()> {
        self.enter("finalize")?;
        let mut state = self.state.borrow_mut();
        state.session = None;
        if state.initialized {
            state.initialized = false;
            state.finalize_count += 1;
        }
        Ok(())
    }

    fn is_sole_module_user(&self) -> bool {
        !self.state.borrow().shared
    }

    fn slots_with_token(&self) -> BResult<Vec<u64>> {
        self.enter("slots_with_token")?;
        Ok(self.state.borrow().slots.keys().copied().collect())
    }

    fn token_info(&self, slot: u64) -> BResult<RawTokenInfo> {
        self.enter("token_info")?;
        let state = self.state.borrow();
        let token = state
            .slots
            .get(&slot)
            .ok_or_else(|| fail(rv::CKR_SLOT_ID_INVALID, "token_info"))?;
        let trim = |t: &str| t.trim_end_matches(['\0', ' ']).to_string();
        Ok(RawTokenInfo {
            slot_id: slot,
            label: trim(&token.label),
            manufacturer: trim(&token.manufacturer),
            model: trim(&token.model),
            serial: trim(&token.serial),
            initialized: token.initialized,
        })
    }

    fn mechanism_list(&self, slot: u64) -> BResult<Vec<u64>> {
        self.enter("mechanism_list")?;
        let state = self.state.borrow();
        let token = state
            .slots
            .get(&slot)
            .ok_or_else(|| fail(rv::CKR_SLOT_ID_INVALID, "mechanism_list"))?;
        let mut codes = token.mechanisms.clone();
        codes.sort_unstable();
        Ok(codes)
    }

    fn open_session(&self, slot: u64) -> BResult<()> {
        self.enter("open_session")?;
        let mut state = self.state.borrow_mut();
        if !state.slots.contains_key(&slot) {
            return Err(fail(rv::CKR_SLOT_ID_INVALID, "open_session"));
        }
        state.session = Some(Session {
            slot,
            invalidated: false,
        });
        state.sessions_opened += 1;
        Ok(())
    }

    fn close_session(&self) -> BResult<()> {
        self.enter("close_session")?;
        self.state.borrow_mut().session = None;
        Ok(())
    }

    fn has_session(&self) -> bool {
        self.state.borrow().session.is_some()
    }

    fn login(&self, user: UserKind, pin: &SecretString) -> BResult<()> {
        self.enter("login")?;
        let mut state = self.state.borrow_mut();
        let slot = match &state.session {
            Some(s) if !s.invalidated => s.slot,
            _ => return Err(fail(rv::CKR_SESSION_HANDLE_INVALID, "login")),
        };
        let token = state
            .slots
            .get_mut(&slot)
            .ok_or_else(|| fail(rv::CKR_SESSION_HANDLE_INVALID, "login"))?;
        if token.pin_locked {
            return Err(fail(rv::CKR_PIN_LOCKED, "login"));
        }
        let pin = pin.expose_secret();
        if pin.is_empty() {
            // NULL pPin without a protected authentication path (SoftHSM parity)
            return Err(fail(rv::CKR_ARGUMENTS_BAD, "login"));
        }
        match user {
            UserKind::So => {
                if pin != token.so_pin {
                    return Err(fail(rv::CKR_PIN_INCORRECT, "login"));
                }
                token.so_logged_in = true;
            }
            UserKind::User => {
                if pin != token.user_pin {
                    return Err(fail(rv::CKR_PIN_INCORRECT, "login"));
                }
                if token.logged_in {
                    return Err(fail(rv::CKR_USER_ALREADY_LOGGED_IN, "login"));
                }
                token.logged_in = true;
            }
        }
        Ok(())
    }

    fn logout(&self) -> BResult<()> {
        self.enter("logout")?;
        let mut state = self.state.borrow_mut();
        let slot = match &state.session {
            Some(s) if !s.invalidated && !state.invalidate_all => s.slot,
            _ => return Err(fail(rv::CKR_SESSION_HANDLE_INVALID, "logout")),
        };
        let token = state
            .slots
            .get_mut(&slot)
            .ok_or_else(|| fail(rv::CKR_SESSION_HANDLE_INVALID, "logout"))?;
        if !(token.logged_in || token.so_logged_in) {
            return Err(fail(rv::CKR_USER_NOT_LOGGED_IN, "logout"));
        }
        token.logged_in = false;
        token.so_logged_in = false;
        Ok(())
    }

    fn init_token(&self, slot: u64, so_pin: &SecretString, label: &str) -> BResult<()> {
        self.enter("init_token")?;
        let mut state = self.state.borrow_mut();
        let token = state.slots.entry(slot).or_insert_with(|| {
            let mut info = Self::token("", "");
            info.initialized = false;
            Token::new(&info, DEFAULT_MECHANISMS.to_vec())
        });
        if so_pin.expose_secret() != token.so_pin {
            return Err(fail(rv::CKR_PIN_INCORRECT, "init_token"));
        }
        token.label = format!("{label:<32}");
        token.initialized = true;
        if token.serial.is_empty() {
            token.serial = format!("{:016x}", slot + 1);
        }
        state.objects.retain(|_, o| o.slot != slot);
        Ok(())
    }

    fn init_pin(&self, pin: &SecretString) -> BResult<()> {
        self.enter("init_pin")?;
        let mut state = self.state.borrow_mut();
        let slot = state
            .session
            .as_ref()
            .map(|s| s.slot)
            .ok_or_else(|| fail(rv::CKR_SESSION_HANDLE_INVALID, "init_pin"))?;
        let token = state
            .slots
            .get_mut(&slot)
            .ok_or_else(|| fail(rv::CKR_SESSION_HANDLE_INVALID, "init_pin"))?;
        if !token.so_logged_in {
            return Err(fail(rv::CKR_USER_NOT_LOGGED_IN, "init_pin"));
        }
        token.user_pin = pin.expose_secret().to_string();
        Ok(())
    }

    fn find_objects(&self, template: &[RawAttr]) -> BResult<Vec<u64>> {
        let slot = self.check("find_objects", true)?;
        let state = self.state.borrow();
        Ok(state
            .objects
            .iter()
            .filter(|(_, o)| o.slot == slot)
            .filter(|(_, o)| {
                template.iter().all(|(t, v)| {
                    o.attrs
                        .get(t)
                        .is_some_and(|stored| stored.as_slice() == v.as_slice())
                })
            })
            .map(|(h, _)| *h)
            .collect())
    }

    fn get_attr(&self, object: u64, attribute: u64) -> BResult<Option<Zeroizing<Vec<u8>>>> {
        self.check("get_attr", true)?;
        let state = self.state.borrow();
        let obj = state
            .objects
            .get(&object)
            .ok_or_else(|| fail(rv::CKR_OBJECT_HANDLE_INVALID, "get_attr"))?;
        if let Some(&code) = state.refused_reads.get(&(object, attribute)) {
            // RawFns::get_attr's size-pass classification
            return if super::is_attribute_refusal(code) {
                Ok(None)
            } else {
                Err(fail(code, "get_attr"))
            };
        }
        if attribute == w(sys::CKA_VALUE) && !Self::value_readable(&obj.attrs) {
            return Ok(None);
        }
        Ok(obj.attrs.get(&attribute).map(|v| Zeroizing::new(v.clone())))
    }

    fn set_attrs(&self, object: u64, template: &[RawAttr]) -> BResult<()> {
        self.check("set_attrs", true)?;
        let mut state = self.state.borrow_mut();
        let read_only = state.read_only.clone();
        let obj = state
            .objects
            .get_mut(&object)
            .ok_or_else(|| fail(rv::CKR_OBJECT_HANDLE_INVALID, "set_attrs"))?;
        for (code, value) in template {
            if read_only.contains(code) {
                return Err(fail(rv::CKR_ATTRIBUTE_READ_ONLY, "set_attrs"));
            }
            let new = value.iter().any(|b| *b != 0);
            if *code == w(sys::CKA_SENSITIVE) && Self::flag(&obj.attrs, sys::CKA_SENSITIVE) && !new
            {
                return Err(fail(rv::CKR_ATTRIBUTE_READ_ONLY, "set_attrs"));
            }
            if *code == w(sys::CKA_EXTRACTABLE)
                && !Self::flag(&obj.attrs, sys::CKA_EXTRACTABLE)
                && new
            {
                return Err(fail(rv::CKR_ATTRIBUTE_READ_ONLY, "set_attrs"));
            }
        }
        for (code, value) in template {
            obj.attrs.insert(*code, value.to_vec());
        }
        if std::mem::take(&mut state.invalidate_after_set)
            && let Some(session) = state.session.as_mut()
        {
            session.invalidated = true;
        }
        Ok(())
    }

    fn create_object(&self, template: &[RawAttr]) -> BResult<u64> {
        let slot = self.check("create_object", true)?;
        let mut attrs = Self::attr_map(template);
        let value = attrs.get(&w(sys::CKA_VALUE)).cloned().unwrap_or_default();
        let secret = if value.is_empty() {
            attrs.get(&w(sys::CKA_MODULUS)).cloned().unwrap_or_default()
        } else {
            value.clone()
        };
        let class = attrs.get(&w(sys::CKA_CLASS)).map(|v| decode_ulong(v));
        if class == Some(w(sys::CKO_SECRET_KEY))
            && attrs.contains_key(&w(sys::CKA_VALUE))
            && !attrs.contains_key(&w(sys::CKA_VALUE_LEN))
        {
            // SoftHSM derives CKA_VALUE_LEN for imported secret keys
            attrs.insert(
                w(sys::CKA_VALUE_LEN),
                ul(u64::try_from(value.len()).unwrap_or(0)),
            );
        }
        let key_class = [
            sys::CKO_SECRET_KEY,
            sys::CKO_PRIVATE_KEY,
            sys::CKO_PUBLIC_KEY,
        ]
        .into_iter()
        .any(|c| class == Some(w(c)));
        if key_class {
            // imported objects: CKA_KEY_GEN_MECHANISM = CK_UNAVAILABLE_INFORMATION (SoftHSM)
            attrs
                .entry(w(sys::CKA_KEY_GEN_MECHANISM))
                .or_insert_with(|| ul(w(sys::CK_UNAVAILABLE_INFORMATION)));
        }
        Ok(self.store(slot, attrs, secret))
    }

    fn destroy_object(&self, object: u64) -> BResult<()> {
        self.check("destroy_object", true)?;
        let mut state = self.state.borrow_mut();
        if state.objects.remove(&object).is_none() {
            return Err(fail(rv::CKR_OBJECT_HANDLE_INVALID, "destroy_object"));
        }
        Ok(())
    }

    fn generate_key(&self, mech: &MechSpec, template: &[RawAttr]) -> BResult<u64> {
        let slot = self.check("generate_key", true)?;
        self.require_mechanism(slot, mech, "generate_key")?;
        let mut attrs = Self::attr_map(template);
        let length = attrs
            .get(&w(sys::CKA_VALUE_LEN))
            .map_or(32, |v| usize::try_from(decode_ulong(v)).unwrap_or(32));
        let counter = {
            let mut state = self.state.borrow_mut();
            state.gen_counter += 1;
            state.gen_counter
        };
        let value = keystream(format!("genkey|{counter}").as_bytes(), b"value", length);
        attrs.insert(w(sys::CKA_VALUE), value.clone());
        attrs.insert(w(sys::CKA_LOCAL), vec![1]);
        Ok(self.store(slot, attrs, value))
    }

    fn generate_key_pair(
        &self,
        mech: &MechSpec,
        public: &[RawAttr],
        private: &[RawAttr],
    ) -> BResult<(u64, u64)> {
        let slot = self.check("generate_key_pair", true)?;
        self.require_mechanism(slot, mech, "generate_key_pair")?;
        let counter = {
            let mut state = self.state.borrow_mut();
            state.gen_counter += 1;
            state.gen_counter
        };
        let secret = keystream(format!("pair|{counter}").as_bytes(), b"secret", 32);
        let mut pub_attrs = Self::attr_map(public);
        let mut priv_attrs = Self::attr_map(private);
        let mut shared: Vec<(u64, Vec<u8>)> = Vec::new();
        if let Some(bits) = pub_attrs.get(&w(sys::CKA_MODULUS_BITS)) {
            let bytes = usize::try_from(decode_ulong(bits) / 8).unwrap_or(256);
            let mut modulus = vec![0x80];
            modulus.extend(keystream(&secret, b"modulus", bytes.saturating_sub(1)));
            shared.push((w(sys::CKA_MODULUS), modulus));
            shared.push((w(sys::CKA_PUBLIC_EXPONENT), vec![1, 0, 1]));
        }
        if let Some(params) = pub_attrs.get(&w(sys::CKA_EC_PARAMS)) {
            shared.push((w(sys::CKA_EC_PARAMS), params.clone()));
        }
        let mut point = vec![0x04];
        point.extend(keystream(&secret, b"point", 64));
        for (code, value) in &shared {
            pub_attrs.insert(*code, value.clone());
            priv_attrs.insert(*code, value.clone());
        }
        pub_attrs.insert(
            w(sys::CKA_EC_POINT),
            r2_core::der::wrap_octet_string(&point),
        );
        let public_handle = self.store(slot, pub_attrs, secret.clone());
        let private_handle = self.store(slot, priv_attrs, secret);
        Ok((public_handle, private_handle))
    }

    fn encrypt(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Vec<u8>> {
        self.cipher(true, mech, key, data)
    }

    fn encrypt_multipart(&self, mech: &MechSpec, key: u64, parts: &[&[u8]]) -> BResult<Vec<u8>> {
        let slot = self.check("encrypt_multipart", true)?;
        self.require_mechanism(slot, mech, "encrypt_multipart")?;
        let data = parts.concat();
        let secret = self.secret_of(key, "encrypt_multipart")?;
        if let MechSpec::Gcm {
            iv, aad, tag_bits, ..
        } = mech
        {
            let tag_len = usize::try_from(*tag_bits / 8).unwrap_or(16);
            let stream_ctx = [b"gcm|".as_slice(), iv].concat();
            let mut out = xor(&data, &keystream(&secret, &stream_ctx, data.len()));
            out.extend(Self::gcm_tag(&secret, iv, aad, &data, tag_len));
            return Ok(out);
        }
        Ok(xor(&data, &keystream(&secret, b"enc|final", data.len())))
    }

    fn decrypt(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Zeroizing<Vec<u8>>> {
        self.cipher(false, mech, key, data).map(Zeroizing::new)
    }

    fn sign(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Vec<u8>> {
        let slot = self.check("sign", true)?;
        let code = self.require_mechanism(slot, mech, "sign")?;
        let secret = self.secret_of(key, "sign")?;
        Ok(Self::signature(&secret, code, data))
    }

    fn verify(&self, mech: &MechSpec, key: u64, data: &[u8], signature: &[u8]) -> BResult<bool> {
        let slot = self.check("verify", true)?;
        let code = self.require_mechanism(slot, mech, "verify")?;
        let secret = self.secret_of(key, "verify")?;
        Ok(Self::signature(&secret, code, data) == signature)
    }

    fn wrap_key(&self, mech: &MechSpec, wrapping_key: u64, key: u64) -> BResult<Vec<u8>> {
        let slot = self.check("wrap_key", true)?;
        let code = self.require_mechanism(slot, mech, "wrap_key")?;
        let target = self
            .state
            .borrow()
            .objects
            .get(&key)
            .cloned()
            .ok_or_else(|| fail(rv::CKR_KEY_HANDLE_INVALID, "wrap_key"))?;
        if !Self::flag(&target.attrs, sys::CKA_EXTRACTABLE) {
            return Err(fail(rv::CKR_KEY_UNEXTRACTABLE, "wrap_key"));
        }
        let value = match target.attrs.get(&w(sys::CKA_VALUE)) {
            Some(v) if !v.is_empty() => v.clone(),
            _ => target.secret.clone(),
        };
        let stream = keystream(
            &self.secret_of(wrapping_key, "wrap_key")?,
            format!("wrap|{code}").as_bytes(),
            value.len(),
        );
        Ok(xor(&value, &stream))
    }

    fn unwrap_key(
        &self,
        mech: &MechSpec,
        unwrapping_key: u64,
        wrapped: &[u8],
        template: &[RawAttr],
    ) -> BResult<u64> {
        let slot = self.check("unwrap_key", true)?;
        let code = self.require_mechanism(slot, mech, "unwrap_key")?;
        {
            let mut state = self.state.borrow_mut();
            state
                .unwrap_templates
                .push(template.iter().map(|(t, _)| *t).collect());
            if let Some((attr, rv)) = state.reject_unwrap_attr
                && template.iter().any(|(t, _)| *t == attr)
            {
                return Err(fail(rv, "unwrap_key"));
            }
        }
        let stream = keystream(
            &self.secret_of(unwrapping_key, "unwrap_key")?,
            format!("wrap|{code}").as_bytes(),
            wrapped.len(),
        );
        let value = xor(wrapped, &stream);
        let mut attrs = Self::attr_map(template);
        attrs.insert(w(sys::CKA_VALUE), value.clone());
        Ok(self.store(slot, attrs, value))
    }

    fn derive_key(&self, mech: &MechSpec, base_key: u64, template: &[RawAttr]) -> BResult<u64> {
        let slot = self.check("derive_key", true)?;
        self.require_mechanism(slot, mech, "derive_key")?;
        let peer = match mech {
            MechSpec::Ecdh1 { public_data, .. } => public_data.clone(),
            _ => Vec::new(),
        };
        let mut attrs = Self::attr_map(template);
        if self.state.borrow().forbid_extractable_secrets
            && Self::flag(&attrs, sys::CKA_EXTRACTABLE)
        {
            return Err(fail(rv::CKR_TEMPLATE_INCONSISTENT, "derive_key"));
        }
        let length = attrs
            .get(&w(sys::CKA_VALUE_LEN))
            .map_or(32, |v| usize::try_from(decode_ulong(v)).unwrap_or(32));
        let mut block = self.secret_of(base_key, "derive_key")?;
        block.extend_from_slice(b"|ecdh|");
        block.extend_from_slice(&peer);
        let base = openssl::sha::sha256(&block);
        let value = keystream(&base, b"derive", length);
        attrs.insert(w(sys::CKA_VALUE), value.clone());
        Ok(self.store(slot, attrs, value))
    }
}
