// FakeProvider and FakeHooks (spec §4.10.2, owner R3) — the port of c2
// `tests/support/fake_provider.py`, the project-wide standard Provider double.
//
// Fully in-memory and deterministic: encrypt/decrypt and wrap/unwrap are length-preserving
// reversible XOR-keystream transforms keyed off the stored key material, so round-trips
// work and identical keys produce identical "ciphertexts" across instances (what the copy
// tests rely on). Generated keypairs share one transform secret, so encrypt-with-public /
// decrypt-with-private (and sign/verify, and symmetric two-party ECDH between two fakes)
// pair up like real asymmetric crypto.
//
// c2's "subclass FakeProvider in your own test file" fault injection becomes `FakeHooks`:
// every Provider/TokenInit method first offers the call to the hooks (with `next`, an
// un-hooked view of the same fake); internal calls (`mechanisms()` capability checks, the
// `shutdown()` run by `set_env_and_reset`) go through the HOOKED surface, as c2's virtual
// dispatch did. No RefCell borrow is held while a hook, `next` or `mechanisms()` runs.
use std::any::Any;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use r2_core::catalog::cka;
use r2_core::crypto::ct_eq;
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial, KeyRef};
use r2_core::params::{ParamValue, Params, param_int, param_str};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_core::text::py_bool;
use r2_provider::lookup::{duplicate_identity, matches_selector, select_match};
use r2_provider::mechanism::{AES_CMAC, AES_GMAC, CANONICAL_MECHANISMS, HMAC};
use r2_provider::*;
use secrecy::SecretString;
use zeroize::Zeroizing;

/// HMAC output length per hash param (§5.9) — mirrors the real providers.
const HMAC_DIGEST_LEN: [(&str, usize); 5] = [
    ("sha1", 20),
    ("sha224", 28),
    ("sha256", 32),
    ("sha384", 48),
    ("sha512", 64),
];

/// The project-wide standard Provider double (frozen surface). Builders are named
/// `with_*` / `starting_*` so they never shadow the `Provider` methods of the same name in
/// method-call syntax (`fake.type_name()` / `fake.mechanisms()` stay the trait calls).
pub struct FakeProvider {
    name: String,
    /// Fixed by the builders (which run before the provider is shared).
    type_name: String,
    hooks: Option<Rc<dyn FakeHooks>>,
    state: RefCell<State>,
}

struct StoredKey {
    info: KeyInfo,
    material: KeyMaterial,
    /// Transform secret (shared across the halves of a generated pair).
    secret: Zeroizing<Vec<u8>>,
}

struct State {
    login_capable: bool,
    start_logged_out: bool,
    auth: AuthState,
    /// The status token (the synthetic one, or the token of the last login).
    token: Option<TokenInfo>,
    mechanisms: BTreeSet<String>,
    keys: Vec<StoredKey>,
    calls: Vec<Vec<String>>,
    id_counter: u32,
    gen_counter: u64,
    handle_counter: u64,
    /// Draw number of `generate_random` (separate from `gen_counter`, so drawing random
    /// bytes never shifts generated key values).
    random_counter: u64,
    /// `.with_tokens(..)`: the slot list and the TokenInit seam.
    tokens: Option<Vec<TokenInfo>>,
    serial_counter: u64,
}

impl FakeProvider {
    /// type_name "memory", mechanisms = all CANONICAL_MECHANISMS.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            type_name: "memory".to_owned(),
            hooks: None,
            state: RefCell::new(State {
                login_capable: false,
                start_logged_out: false,
                auth: AuthState::NotRequired,
                token: None,
                mechanisms: CANONICAL_MECHANISMS
                    .iter()
                    .map(|mech| (*mech).to_owned())
                    .collect(),
                keys: Vec::new(),
                calls: Vec::new(),
                id_counter: 0,
                gen_counter: 0,
                handle_counter: 0,
                random_counter: 0,
                tokens: None,
                serial_counter: 0,
            }),
        }
    }
    /// Builder: present as another type (copy-flow tests use "pkcs11"). Any type other than
    /// "memory" is login-capable and starts LoggedIn against the synthetic token
    /// TokenInfo{slot_id: 0, label: "{name}-token", manufacturer: "r2", model:
    /// "FakeProvider", serial: "FAKE0001"}.
    pub fn with_type_name(self, type_name: &str) -> Self {
        {
            let mut state = self.state.borrow_mut();
            state.login_capable = type_name != "memory";
            if state.login_capable {
                state.auth = if state.start_logged_out {
                    AuthState::LoggedOut
                } else {
                    AuthState::LoggedIn
                };
                state.token = Some(TokenInfo {
                    slot_id: 0,
                    label: format!("{}-token", self.name),
                    manufacturer: "r2".to_owned(),
                    model: "FakeProvider".to_owned(),
                    serial: "FAKE0001".to_owned(),
                });
            } else {
                state.auth = AuthState::NotRequired;
                state.token = None;
            }
        }
        Self {
            type_name: type_name.to_owned(),
            ..self
        }
    }
    /// Builder: advertised canonical names (replaces the default set).
    pub fn with_mechanisms<I, S>(self, mechanisms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.state.borrow_mut().mechanisms = mechanisms.into_iter().map(Into::into).collect();
        self
    }
    /// Builder: start LoggedOut (login-capable presentations only).
    pub fn starting_logged_out(self) -> Self {
        {
            let mut state = self.state.borrow_mut();
            state.start_logged_out = true;
            if state.login_capable {
                state.auth = AuthState::LoggedOut;
            }
        }
        self
    }
    /// Builder: `list_tokens()` returns these and `as_token_init()` becomes Some (§4.5.2):
    /// init_token(slot, label, …) requires a free token at `slot` (label "" and serial "";
    /// else Provider "no free slot {slot}") and replaces it with TokenInfo{slot_id: slot,
    /// label, manufacturer: "SoftHSM project", model: "SoftHSM v2", serial: 16 lower-case hex
    /// digits of a counter}; set_env_and_reset(key, value) records the call and runs
    /// shutdown() — it never touches the real environment.
    pub fn with_tokens(self, tokens: Vec<TokenInfo>) -> Self {
        self.state.borrow_mut().tokens = Some(tokens);
        self
    }
    /// Builder: install fault-injection / observation hooks (replaces c2's "subclass
    /// FakeProvider in your own test file").
    pub fn with_hooks(self, hooks: Rc<dyn FakeHooks>) -> Self {
        Self {
            hooks: Some(hooks),
            ..self
        }
    }
    /// Recorded calls, c2's frozen encoding: [method_name, summaries…] (rules below).
    pub fn calls(&self) -> Vec<Vec<String>> {
        self.state.borrow().calls.clone()
    }
    pub fn clear_calls(&self) {
        self.state.borrow_mut().calls.clear();
    }
    /// The sanctioned twin-fixture backdoor (c2 `_store_key`): stores without the duplicate
    /// guard and without recording a call.
    pub fn store_key_unchecked(
        &self,
        material: &KeyMaterial,
        label: &str,
        template: Option<&KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> KeyInfo {
        self.store_key(
            material.clone(),
            label,
            template,
            normalize_id(key_id),
            None,
        )
    }

    // -- internals -------------------------------------------------------------------------

    fn hooks(&self) -> Option<&dyn FakeHooks> {
        self.hooks.as_deref()
    }

    fn record(&self, method: &str, args: Vec<String>) {
        let mut call = Vec::with_capacity(args.len() + 1);
        call.push(method.to_owned());
        call.extend(args);
        self.state.borrow_mut().calls.push(call);
    }

    fn require_login(&self) -> Result<()> {
        let state = self.state.borrow();
        if state.login_capable && state.auth != AuthState::LoggedIn {
            return Err(ConsoleError::auth_required(format!(
                "login required: run `login {}`",
                self.name
            )));
        }
        Ok(())
    }

    /// Capability check through the HOOKED `mechanisms()` (c2 `self.mechanisms()`).
    fn check_mechanism(&self, mech: &MechanismInvocation) -> Result<()> {
        if Provider::mechanisms(self).contains(&mech.mechanism) {
            return Ok(());
        }
        Err(ConsoleError::unsupported(format!(
            "{} does not support mechanism {}",
            self.name, mech.mechanism
        )))
    }

    fn next_key_id(&self, key_id: Option<Vec<u8>>) -> Option<Vec<u8>> {
        if key_id.is_some() {
            return key_id;
        }
        let mut state = self.state.borrow_mut();
        if !state.login_capable {
            return None; // memory presentation keeps None
        }
        state.id_counter += 1;
        Some(state.id_counter.to_be_bytes().to_vec())
    }

    /// DATA objects carry no CKA_ID (§4.3) — any id is a Param error; other classes get
    /// the usual pkcs11-presentation counter id when none is given.
    fn resolve_id(&self, key_class: KeyClass, key_id: Option<Vec<u8>>) -> Result<Option<Vec<u8>>> {
        if key_class == KeyClass::Data {
            if key_id.is_some() {
                return Err(
                    ConsoleError::param("data objects carry no CKA_ID (§4.3)", "key_id")
                        .with_hint("drop --id; data objects are identified by label alone"),
                );
            }
            return Ok(None);
        }
        Ok(self.next_key_id(key_id))
    }

    fn blob(&self, tag: &str, length: usize) -> Zeroizing<Vec<u8>> {
        keystream(format!("{}|{tag}", self.name).as_bytes(), b"blob", length)
    }

    /// Refuse creating an exact (class, label, key id) twin (§4.7 guard). CERTIFICATE is
    /// exempt (PKCS#12 chains, §5.4); `store_key` stays unguarded on purpose.
    fn ensure_identity_free(
        &self,
        label: &str,
        key_id: Option<&[u8]>,
        key_classes: &[KeyClass],
    ) -> Result<()> {
        let state = self.state.borrow();
        for key_class in key_classes.iter().copied() {
            if key_class == KeyClass::Certificate {
                continue;
            }
            let taken = state.keys.iter().any(|rec| {
                rec.info.key_ref.label == label
                    && rec.info.key_ref.key_id.as_deref() == key_id
                    && rec.info.key_class == key_class
            });
            if taken {
                return Err(duplicate_identity(
                    &self.name, key_class, label, key_id, false,
                ));
            }
        }
        Ok(())
    }

    fn store_key(
        &self,
        material: KeyMaterial,
        label: &str,
        template: Option<&KeyTemplate>,
        key_id: Option<Vec<u8>>,
        secret: Option<Zeroizing<Vec<u8>>>,
    ) -> KeyInfo {
        let (exportable, attributes) = policy(template, material.key_class);
        let mut size_bits = material.size_bits;
        if size_bits.is_none() && matches!(material.key_class, KeyClass::Secret | KeyClass::Data) {
            size_bits = u32::try_from(material.data.len() * 8).ok();
        }
        let mut state = self.state.borrow_mut();
        state.handle_counter += 1;
        let info = KeyInfo {
            key_ref: KeyRef::new(self.name.clone(), label, key_id),
            key_class: material.key_class,
            algorithm: material.algorithm,
            size_bits,
            curve: material.curve.clone(),
            exportable,
            attributes,
            handle: Some(state.handle_counter),
        };
        let secret = secret.unwrap_or_else(|| material.data.clone());
        state.keys.push(StoredKey {
            info: info.clone(),
            material,
            secret,
        });
        info
    }

    fn find_index(&self, key: &KeyInfo) -> Result<usize> {
        let state = self.state.borrow();
        state
            .keys
            .iter()
            .position(|rec| rec.info.key_ref == key.key_ref && rec.info.key_class == key.key_class)
            .ok_or_else(|| {
                ConsoleError::key_not_found(format!(
                    "no key '{}' on provider {}",
                    key.key_ref.display(),
                    self.name
                ))
            })
    }

    fn record_secret(&self, index: usize) -> Zeroizing<Vec<u8>> {
        self.state.borrow().keys[index].secret.clone()
    }

    /// §4.3: a CERTIFICATE passed to encrypt/verify/wrap_key resolves to its public key
    /// (matched by CKA_ID, then label); other classes resolve to their own record.
    fn resolve_for_public_use(&self, key: &KeyInfo) -> Result<usize> {
        let index = self.find_index(key)?;
        if key.key_class != KeyClass::Certificate {
            return Ok(index);
        }
        let state = self.state.borrow();
        let mut buckets: [Option<usize>; 4] = [None; 4];
        for (other_index, other) in state.keys.iter().enumerate() {
            if other_index == index {
                continue;
            }
            let same_id =
                key.key_ref.key_id.is_some() && other.info.key_ref.key_id == key.key_ref.key_id;
            let same_label = other.info.key_ref.label == key.key_ref.label;
            let bucket = if other.info.key_class == KeyClass::Public {
                if same_id {
                    Some(0)
                } else if same_label {
                    Some(1)
                } else {
                    None
                }
            } else if other.info.key_class != KeyClass::Certificate {
                if same_id {
                    Some(2)
                } else if same_label {
                    Some(3)
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(bucket) = bucket {
                buckets[bucket].get_or_insert(other_index);
            }
        }
        Ok(buckets.into_iter().flatten().next().unwrap_or(index))
    }

    fn transform(secret: &[u8], context: &str, data: &[u8]) -> Vec<u8> {
        let stream = keystream(secret, context.as_bytes(), data.len());
        data.iter().zip(stream.iter()).map(|(a, b)| a ^ b).collect()
    }

    fn mac(secret: &[u8], mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>> {
        let mut input = Vec::with_capacity(secret.len() + data.len() + mech.mechanism.len() + 6);
        input.extend_from_slice(secret);
        input.extend_from_slice(b"|mac|");
        input.extend_from_slice(mech.mechanism.as_bytes());
        input.push(b'|');
        input.extend_from_slice(data);
        let mut digest = openssl::sha::sha256(&input).to_vec();
        if mech.mechanism == HMAC {
            // §5.9 shape: the output length follows the hash param (default sha256).
            let hash = param_str(&mech.params, "hash", "sha256")?;
            let hash = if hash.is_empty() { "sha256" } else { hash };
            let width = HMAC_DIGEST_LEN
                .iter()
                .find(|(name, _)| *name == hash)
                .map_or(32, |(_, width)| *width);
            digest = digest.repeat(2);
            digest.truncate(width);
        }
        let mac_len = param_int(&mech.params, "mac_len", 0)?;
        if let Ok(mac_len) = usize::try_from(mac_len)
            && mac_len > 0
            && mac_len <= digest.len()
        {
            digest.truncate(mac_len);
        }
        Ok(digest)
    }

    fn reject_certificate(key: &KeyInfo, verb: &str) -> Result<()> {
        if key.key_class == KeyClass::Certificate {
            return Err(ConsoleError::unsupported(format!(
                "certificates cannot be used for {verb} (§4.3)"
            ))
            .with_hint("certificates stand in for PUBLIC keys only (encrypt/verify/wrap)"));
        }
        Ok(())
    }

    /// DATA objects / unmodelled key types never take part in a verb (§4.3).
    fn reject_non_key(key: &KeyInfo, verb: &str) -> Result<()> {
        if key.key_class == KeyClass::Data {
            return Err(ConsoleError::unsupported(format!(
                "data objects cannot be used for {verb} (§4.3)"
            ))
            .with_hint("data objects hold opaque bytes, not key material — export or copy them"));
        }
        if key.algorithm == KeyAlgorithm::Other {
            let key_type = key
                .attributes
                .get("CKA_KEY_TYPE")
                .map_or_else(|| "unknown".to_owned(), AttrValue::render_info);
            return Err(ConsoleError::unsupported(format!(
                "key type {key_type} of '{}' is not supported by r2 for {verb}",
                key.key_ref.display()
            ))
            .with_hint("objects of unsupported key types can be listed and deleted only"));
        }
        Ok(())
    }

    /// §5.9 key-type rule: HMAC ↔ generic secret, AES-CMAC/GMAC ↔ AES.
    fn check_mac_key(key: &KeyInfo, mech: &MechanismInvocation) -> Result<()> {
        if mech.mechanism == HMAC && key.algorithm != KeyAlgorithm::Generic {
            return Err(ConsoleError::unsupported(format!(
                "HMAC requires a generic secret key (got {} {})",
                key.algorithm.as_str(),
                key.key_class.as_str()
            ))
            .with_hint("generate/load a `generic` key (CKK_GENERIC_SECRET) for HMAC"));
        }
        if (mech.mechanism == AES_CMAC || mech.mechanism == AES_GMAC)
            && key.algorithm != KeyAlgorithm::Aes
        {
            return Err(ConsoleError::unsupported(format!(
                "{} requires an AES secret key (got {} {})",
                mech.mechanism,
                key.algorithm.as_str(),
                key.key_class.as_str()
            )));
        }
        Ok(())
    }

    // -- the un-hooked behavior (c2 FakeProvider's methods) ---------------------------------

    fn base_initialize(&self) -> Result<()> {
        self.record("initialize", Vec::new());
        Ok(())
    }

    fn base_shutdown(&self) -> Result<()> {
        self.record("shutdown", Vec::new());
        let mut state = self.state.borrow_mut();
        if state.login_capable {
            state.auth = AuthState::LoggedOut;
        }
        Ok(())
    }

    fn base_status(&self) -> ProviderStatus {
        let state = self.state.borrow();
        let token = if state.auth == AuthState::LoggedIn {
            state.token.clone()
        } else {
            None
        };
        ProviderStatus {
            auth: state.auth,
            token,
        }
    }

    fn base_list_tokens(&self) -> Result<Vec<TokenInfo>> {
        let state = self.state.borrow();
        if let Some(tokens) = &state.tokens {
            return Ok(tokens.clone());
        }
        Ok(state.token.iter().cloned().collect())
    }

    fn base_login(&self, token: &TokenInfo, keep_pin: bool) -> Result<()> {
        self.record(
            "login",
            vec![
                token.label.clone(),
                "***".to_owned(),
                py_bool(keep_pin).to_owned(),
            ],
        );
        let mut state = self.state.borrow_mut();
        if !state.login_capable {
            return Err(ConsoleError::unsupported(format!(
                "{} does not require login",
                self.name
            )));
        }
        if state.auth == AuthState::LoggedIn {
            return Err(
                ConsoleError::already_logged_in("already logged in").with_hint("logout first")
            );
        }
        state.token = Some(token.clone());
        state.auth = AuthState::LoggedIn;
        Ok(())
    }

    fn base_logout(&self) -> Result<()> {
        self.record("logout", Vec::new());
        let mut state = self.state.borrow_mut();
        if state.login_capable {
            state.auth = AuthState::LoggedOut;
        }
        Ok(())
    }

    fn base_mechanisms(&self) -> BTreeSet<String> {
        let state = self.state.borrow();
        if state.login_capable && state.auth != AuthState::LoggedIn {
            return BTreeSet::new();
        }
        state.mechanisms.clone()
    }

    fn base_list_keys(&self) -> Result<Vec<KeyInfo>> {
        self.record("list_keys", Vec::new());
        self.require_login()?;
        Ok(self
            .state
            .borrow()
            .keys
            .iter()
            .map(|rec| rec.info.clone())
            .collect())
    }

    fn base_find_key(&self, selector: &KeySelector) -> Result<KeyInfo> {
        self.record(
            "find_key",
            vec![
                selector.label.clone(),
                opt_bytes(selector.key_id.as_deref()),
                opt_class(selector.key_class),
                selector
                    .handle
                    .map_or_else(none, |handle| handle.to_string()),
            ],
        );
        self.require_login()?;
        let matches: Vec<KeyInfo> = self
            .state
            .borrow()
            .keys
            .iter()
            .filter(|rec| matches_selector(&rec.info, selector))
            .map(|rec| rec.info.clone())
            .collect();
        select_match(&self.name, selector, matches)
    }

    fn base_import_key(
        &self,
        material: &KeyMaterial,
        label: &str,
        template: Option<&KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> Result<KeyInfo> {
        self.record(
            "import_key",
            vec![
                material_summary(material),
                label.to_owned(),
                opt_template(template),
                opt_bytes(key_id),
            ],
        );
        self.require_login()?;
        if material.algorithm == KeyAlgorithm::Other
            || (material.algorithm == KeyAlgorithm::None && material.key_class != KeyClass::Data)
        {
            return Err(ConsoleError::param(
                format!(
                    "cannot import {} {} material",
                    material.algorithm.as_str(),
                    material.key_class.as_str()
                ),
                "material",
            ));
        }
        let resolved_id = self.resolve_id(material.key_class, normalize_id(key_id))?;
        self.ensure_identity_free(label, resolved_id.as_deref(), &[material.key_class])?;
        Ok(self.store_key(material.clone(), label, template, resolved_id, None))
    }

    fn base_generate_key(&self, request: &GenerateRequest) -> Result<KeyInfo> {
        let algorithm = request.algorithm;
        let label = request.label.as_str();
        self.record(
            "generate_key",
            vec![
                algorithm.py_name().to_owned(),
                request.size_bits.map_or_else(none, |bits| bits.to_string()),
                request
                    .curve
                    .as_ref()
                    .map_or_else(none, |curve| curve.as_str().to_owned()),
                label.to_owned(),
                opt_bytes(request.key_id.as_deref()),
                opt_template(request.template.as_ref()),
                opt_template(request.public_template.as_ref()),
            ],
        );
        self.require_login()?;
        let seq = {
            let mut state = self.state.borrow_mut();
            state.gen_counter += 1;
            state.gen_counter
        };
        let resolved_id = self.next_key_id(normalize_id(request.key_id.as_deref()));
        if matches!(algorithm, KeyAlgorithm::None | KeyAlgorithm::Other) {
            return Err(ConsoleError::param(
                format!("cannot generate {} keys", algorithm.as_str()),
                "algorithm",
            ));
        }
        if matches!(algorithm, KeyAlgorithm::Aes | KeyAlgorithm::Generic) {
            let Some(size_bits) = request.size_bits else {
                return Err(ConsoleError::param(
                    format!("size_bits is required for {}", algorithm.as_str()),
                    "size_bits",
                ));
            };
            if algorithm == KeyAlgorithm::Generic && (size_bits % 8 != 0 || size_bits == 0) {
                return Err(ConsoleError::param(
                    format!(
                        "invalid generic secret size {size_bits}; expected a positive multiple of 8"
                    ),
                    "size_bits",
                ));
            }
            let data = self.blob(&format!("secret|{label}|{seq}"), (size_bits / 8) as usize);
            let material = KeyMaterial {
                algorithm,
                key_class: KeyClass::Secret,
                data,
                curve: None,
                size_bits: Some(size_bits),
                label_hint: Some(label.to_owned()),
            };
            self.ensure_identity_free(label, resolved_id.as_deref(), &[KeyClass::Secret])?;
            return Ok(self.store_key(
                material,
                label,
                request.template.as_ref(),
                resolved_id,
                None,
            ));
        }
        if algorithm == KeyAlgorithm::Rsa {
            if request.size_bits.is_none() {
                return Err(ConsoleError::param(
                    "size_bits is required for RSA",
                    "size_bits",
                ));
            }
        } else if request.curve.is_none() {
            return Err(ConsoleError::param(
                format!("curve is required for {}", algorithm.as_str()),
                "curve",
            ));
        }
        // Keypair: both objects share label (and id); the pair's transform secret is the
        // public blob, so public-encrypt/private-decrypt pairs up.
        let public_data = self.blob(&format!("public|{label}|{seq}"), 64);
        let half = |key_class: KeyClass, data: Zeroizing<Vec<u8>>| KeyMaterial {
            algorithm,
            key_class,
            data,
            curve: request.curve.clone(),
            size_bits: request.size_bits,
            label_hint: Some(label.to_owned()),
        };
        let private_material = half(
            KeyClass::Private,
            self.blob(&format!("private|{label}|{seq}"), 64),
        );
        let public_material = half(KeyClass::Public, public_data.clone());
        // Both halves checked up front — a collision never leaves a half pair.
        self.ensure_identity_free(
            label,
            resolved_id.as_deref(),
            &[KeyClass::Private, KeyClass::Public],
        )?;
        let private_info = self.store_key(
            private_material,
            label,
            request.template.as_ref(),
            resolved_id.clone(),
            Some(public_data),
        );
        self.store_key(
            public_material,
            label,
            request.public_template.as_ref(),
            resolved_id,
            None,
        );
        Ok(private_info)
    }

    fn base_delete_key(&self, key: &KeyInfo) -> Result<()> {
        self.record("delete_key", vec![key.key_ref.display()]);
        self.require_login()?;
        let index = self.find_index(key)?;
        self.state.borrow_mut().keys.remove(index);
        Ok(())
    }

    fn base_export_key(&self, key: &KeyInfo) -> Result<KeyMaterial> {
        self.record("export_key", vec![key.key_ref.display()]);
        self.require_login()?;
        let index = self.find_index(key)?;
        let state = self.state.borrow();
        let rec = &state.keys[index];
        if !rec.info.exportable {
            return Err(ConsoleError::key_not_exportable(format!(
                "key '{}' is not exportable",
                key.key_ref.display()
            ))
            .with_hint("CKA_SENSITIVE/CKA_EXTRACTABLE forbid a plain-value read (§5.5)"));
        }
        Ok(rec.material.clone())
    }

    fn base_read_key_template(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        self.record("read_key_template", vec![key.key_ref.display()]);
        self.require_login()?;
        let index = self.find_index(key)?;
        let state = self.state.borrow();
        let info = &state.keys[index].info;
        let key_ref = &info.key_ref;
        let mut attrs = vec![TemplateAttr::new(
            "CKA_LABEL",
            AttrKind::Str,
            AttrValue::Str(key_ref.label.clone()),
        )];
        if info.key_class != KeyClass::Data {
            // data objects carry no CKA_ID (§4.3)
            let row = TemplateAttr::new(
                "CKA_ID",
                AttrKind::Bytes,
                AttrValue::Bytes(key_ref.key_id.clone().unwrap_or_default()),
            );
            attrs.push(if key_ref.key_id.is_some() {
                row
            } else {
                row.disabled()
            });
        }
        for name in ["CKA_SENSITIVE", "CKA_EXTRACTABLE"] {
            if let Some(value) = info.attributes.get(name) {
                attrs.push(TemplateAttr::new(name, AttrKind::Bool, value.clone()));
            }
        }
        Ok(KeyTemplate::new(attrs))
    }

    fn base_read_full_template(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        self.record("read_full_template", vec![key.key_ref.display()]);
        self.require_login()?;
        let index = self.find_index(key)?;
        let state = self.state.borrow();
        let info = &state.keys[index].info;
        let mut attrs = vec![TemplateAttr::new(
            "CKA_CLASS",
            AttrKind::Ulong,
            AttrValue::Symbol(info.key_class.cko_symbol().to_owned()),
        )];
        if info.key_class.has_key_type()
            && let Some(ckk) = info.algorithm.ckk_symbol()
        {
            attrs.push(TemplateAttr::new(
                "CKA_KEY_TYPE",
                AttrKind::Ulong,
                AttrValue::Symbol(ckk.to_owned()),
            ));
        }
        attrs.push(TemplateAttr::new(
            "CKA_LABEL",
            AttrKind::Str,
            AttrValue::Str(info.key_ref.label.clone()),
        ));
        if let Some(id) = &info.key_ref.key_id {
            attrs.push(TemplateAttr::new(
                "CKA_ID",
                AttrKind::Bytes,
                AttrValue::Bytes(id.clone()),
            ));
        }
        for (name, value) in &info.attributes {
            let kind = cka(name).map_or_else(|| kind_of_value(value), |entry| entry.kind);
            attrs.push(TemplateAttr::new(name.clone(), kind, value.clone()));
        }
        Ok(KeyTemplate::new(attrs))
    }

    fn base_update_key(&self, key: &KeyInfo, changes: &KeyTemplate) -> Result<KeyEditResult> {
        self.record(
            "update_key",
            vec![key.key_ref.display(), template_summary(changes)],
        );
        self.require_login()?;
        let index = self.find_index(key)?;
        let (old_ref, key_class, old_attributes) = {
            let state = self.state.borrow();
            let info = &state.keys[index].info;
            (
                info.key_ref.clone(),
                info.key_class,
                info.attributes.clone(),
            )
        };
        let mut outcomes = Vec::new();
        let mut new_label = old_ref.label.clone();
        let mut new_id = old_ref.key_id.clone();
        let mut flags: BTreeMap<String, AttrValue> = BTreeMap::new();
        for attr in changes.enabled_attrs() {
            let name = attr.name.as_str();
            if name == "CKA_CLASS" || name == "CKA_KEY_TYPE" {
                return Err(ConsoleError::param(
                    format!("{name} cannot be edited after creation"),
                    name,
                ));
            }
            if name == "CKA_LABEL" {
                match &attr.value {
                    AttrValue::Str(text) | AttrValue::Symbol(text) if !text.is_empty() => {
                        new_label = text.clone();
                    }
                    _ => {
                        return Err(ConsoleError::param(
                            "CKA_LABEL expects a non-empty string",
                            "CKA_LABEL",
                        ));
                    }
                }
                outcomes.push(applied("CKA_LABEL"));
            } else if name == "CKA_ID" {
                if key_class == KeyClass::Data {
                    return Err(ConsoleError::param(
                        "data objects carry no CKA_ID (§4.3)",
                        "CKA_ID",
                    )
                    .with_hint("data objects are identified by label alone"));
                }
                match &attr.value {
                    AttrValue::Bytes(bytes) if !bytes.is_empty() => new_id = Some(bytes.clone()),
                    _ => {
                        return Err(ConsoleError::param(
                            "CKA_ID expects non-empty bytes",
                            "CKA_ID",
                        )
                        .with_hint("use a 0x… hex value"));
                    }
                }
                outcomes.push(applied("CKA_ID"));
            } else if (name == "CKA_SENSITIVE" || name == "CKA_EXTRACTABLE")
                && matches!(key_class, KeyClass::Secret | KeyClass::Private)
            {
                flags.insert(name.to_owned(), AttrValue::Bool(truthy(&attr.value)));
                outcomes.push(applied(name));
            } else {
                outcomes.push(AttrEditOutcome {
                    name: name.to_owned(),
                    applied: false,
                    detail: Some("not supported by FakeProvider".to_owned()),
                });
            }
        }
        if (&new_label, &new_id) != (&old_ref.label, &old_ref.key_id) {
            self.ensure_rename_free(index, key_class, &new_label, new_id.as_deref())?;
        }
        let mut attributes = old_attributes;
        attributes.extend(flags);
        let mut state = self.state.borrow_mut();
        let info = &mut state.keys[index].info;
        if matches!(key_class, KeyClass::Secret | KeyClass::Private) {
            let extractable = attributes.get("CKA_EXTRACTABLE").is_none_or(truthy);
            let sensitive = attributes.get("CKA_SENSITIVE").is_some_and(truthy);
            info.exportable = extractable && !sensitive;
        }
        info.key_ref = KeyRef::new(self.name.clone(), new_label, new_id);
        info.attributes = attributes;
        Ok(KeyEditResult {
            key: info.clone(),
            outcomes,
        })
    }

    /// §4.7 duplicate-identity guard for renames — excludes the renamed record.
    fn ensure_rename_free(
        &self,
        index: usize,
        key_class: KeyClass,
        label: &str,
        key_id: Option<&[u8]>,
    ) -> Result<()> {
        if key_class == KeyClass::Certificate {
            return Ok(());
        }
        let state = self.state.borrow();
        let taken = state.keys.iter().enumerate().any(|(other_index, other)| {
            other_index != index
                && other.info.key_ref.label == label
                && other.info.key_ref.key_id.as_deref() == key_id
                && other.info.key_class == key_class
        });
        if taken {
            return Err(duplicate_identity(
                &self.name, key_class, label, key_id, true,
            ));
        }
        Ok(())
    }

    fn base_encrypt(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        self.record(
            "encrypt",
            vec![
                key.key_ref.display(),
                mech.mechanism.clone(),
                bytes_summary(data),
            ],
        );
        self.require_login()?;
        self.check_mechanism(mech)?;
        Self::reject_non_key(key, "encrypt")?;
        let index = self.resolve_for_public_use(key)?;
        let secret = self.record_secret(index);
        Ok(Self::transform(
            &secret,
            &format!("cipher|{}", mech.mechanism),
            data,
        ))
    }

    fn base_decrypt(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.record(
            "decrypt",
            vec![
                key.key_ref.display(),
                mech.mechanism.clone(),
                bytes_summary(data),
            ],
        );
        self.require_login()?;
        self.check_mechanism(mech)?;
        Self::reject_certificate(key, "decrypt")?;
        Self::reject_non_key(key, "decrypt")?;
        let index = self.find_index(key)?;
        let secret = self.record_secret(index);
        Ok(Zeroizing::new(Self::transform(
            &secret,
            &format!("cipher|{}", mech.mechanism),
            data,
        )))
    }

    fn base_sign(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>> {
        self.record(
            "sign",
            vec![
                key.key_ref.display(),
                mech.mechanism.clone(),
                bytes_summary(data),
            ],
        );
        self.require_login()?;
        self.check_mechanism(mech)?;
        Self::reject_certificate(key, "sign")?;
        Self::reject_non_key(key, "sign")?;
        Self::check_mac_key(key, mech)?;
        let index = self.find_index(key)?;
        let secret = self.record_secret(index);
        Self::mac(&secret, mech, data)
    }

    fn base_verify(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        self.record(
            "verify",
            vec![
                key.key_ref.display(),
                mech.mechanism.clone(),
                bytes_summary(data),
                bytes_summary(signature),
            ],
        );
        self.require_login()?;
        self.check_mechanism(mech)?;
        Self::reject_non_key(key, "verify")?;
        Self::check_mac_key(key, mech)?;
        let index = self.resolve_for_public_use(key)?;
        let secret = self.record_secret(index);
        Ok(ct_eq(&Self::mac(&secret, mech, data)?, signature))
    }

    fn base_derive(&self, key: &KeyInfo, mech: &MechanismInvocation) -> Result<DeriveResult> {
        self.record(
            "derive",
            vec![key.key_ref.display(), mech.mechanism.clone()],
        );
        self.require_login()?;
        self.check_mechanism(mech)?;
        Self::reject_certificate(key, "derive")?;
        if key.key_class == KeyClass::Public {
            return Err(ConsoleError::unsupported(
                "derive requires a private (or secret) key",
            ));
        }
        let index = self.find_index(key)?;
        let secret = self.record_secret(index);
        let peer = param_bytes(&mech.params, "peer");
        // Symmetric construction: both sides of a fake ECDH agree because a generated
        // private key's transform secret IS its public blob.
        let (low, high) = if secret.as_slice() <= peer.as_slice() {
            (secret.as_slice(), peer.as_slice())
        } else {
            (peer.as_slice(), secret.as_slice())
        };
        let mut input = Zeroizing::new(Vec::with_capacity(low.len() + high.len() + 6));
        input.extend_from_slice(b"ecdh|");
        input.extend_from_slice(low);
        input.push(b'|');
        input.extend_from_slice(high);
        let base = Zeroizing::new(openssl::sha::sha256(&input).to_vec());
        let out_len = param_int(&mech.params, "out_len", 0)?;
        let raw = match usize::try_from(out_len) {
            Ok(len) if len > 0 => keystream(&base, b"derive", len),
            _ => base,
        };
        Ok(DeriveResult {
            key: None,
            raw: Some(raw),
        })
    }

    fn base_wrap_key(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        target: &KeyInfo,
    ) -> Result<Vec<u8>> {
        self.record(
            "wrap_key",
            vec![
                wrapping_key.key_ref.display(),
                mech.mechanism.clone(),
                target.key_ref.display(),
            ],
        );
        self.require_login()?;
        self.check_mechanism(mech)?;
        Self::reject_non_key(wrapping_key, "wrap_key")?;
        Self::reject_non_key(target, "wrap_key (target)")?;
        let wrap_index = self.resolve_for_public_use(wrapping_key)?;
        let target_index = self.find_index(target)?;
        let state = self.state.borrow();
        let target_rec = &state.keys[target_index];
        if target_rec.info.attributes.get("CKA_EXTRACTABLE") == Some(&AttrValue::Bool(false)) {
            return Err(ConsoleError::key_not_exportable(format!(
                "key '{}' is not extractable and cannot be wrapped",
                target.key_ref.display()
            )));
        }
        Ok(Self::transform(
            &state.keys[wrap_index].secret,
            &format!("wrap|{}", mech.mechanism),
            &target_rec.material.data,
        ))
    }

    /// §5.17: recorded first, AuthRequired while a login-capable fake is logged out; the
    /// bytes are a deterministic keystream of (name, draw number) — two fakes with the same
    /// name yield the same sequence, successive draws differ.
    fn base_generate_random(&self, len: usize) -> Result<Zeroizing<Vec<u8>>> {
        self.record("generate_random", vec![len.to_string()]);
        self.require_login()?;
        let draw = {
            let mut state = self.state.borrow_mut();
            state.random_counter += 1;
            state.random_counter
        };
        Ok(self.blob(&format!("random|{draw}"), len))
    }

    fn base_unwrap_key(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        wrapped: &[u8],
        request: &UnwrapRequest,
    ) -> Result<KeyInfo> {
        self.record(
            "unwrap_key",
            vec![
                wrapping_key.key_ref.display(),
                mech.mechanism.clone(),
                bytes_summary(wrapped),
                request.result_algorithm.py_name().to_owned(),
                request.result_class.py_name().to_owned(),
                request.label.clone(),
                opt_bytes(request.key_id.as_deref()),
                opt_template(request.template.as_ref()),
            ],
        );
        self.require_login()?;
        self.check_mechanism(mech)?;
        Self::reject_certificate(wrapping_key, "unwrap_key")?;
        Self::reject_non_key(wrapping_key, "unwrap_key")?;
        if matches!(
            request.result_algorithm,
            KeyAlgorithm::None | KeyAlgorithm::Other
        ) {
            return Err(ConsoleError::param(
                format!(
                    "cannot unwrap into {} keys",
                    request.result_algorithm.as_str()
                ),
                "result_algorithm",
            ));
        }
        let wrap_index = self.find_index(wrapping_key)?;
        let secret = self.record_secret(wrap_index);
        let data = Self::transform(&secret, &format!("wrap|{}", mech.mechanism), wrapped);
        let material = KeyMaterial {
            algorithm: request.result_algorithm,
            key_class: request.result_class,
            data: Zeroizing::new(data),
            curve: None,
            size_bits: None,
            label_hint: Some(request.label.clone()),
        };
        let resolved_id = self.next_key_id(normalize_id(request.key_id.as_deref()));
        self.ensure_identity_free(
            &request.label,
            resolved_id.as_deref(),
            &[request.result_class],
        )?;
        Ok(self.store_key(
            material,
            &request.label,
            request.template.as_ref(),
            resolved_id,
            None,
        ))
    }

    fn tokens_configured(&self) -> bool {
        self.state.borrow().tokens.is_some()
    }

    fn base_init_token(&self, slot: u64, label: &str) -> Result<()> {
        self.record("init_token", vec![slot.to_string(), label.to_owned()]);
        if label.len() > 32 {
            return Err(ConsoleError::param(
                "token label must be at most 32 bytes",
                "label",
            ));
        }
        let mut state = self.state.borrow_mut();
        let serial = format!("{:016x}", state.serial_counter + 1);
        let free = state.tokens.as_mut().and_then(|tokens| {
            tokens.iter_mut().find(|token| {
                token.slot_id == slot && token.label.is_empty() && token.serial.is_empty()
            })
        });
        let Some(token) = free else {
            return Err(ConsoleError::provider(format!("no free slot {slot}")));
        };
        *token = TokenInfo {
            slot_id: slot,
            label: label.to_owned(),
            manufacturer: "SoftHSM project".to_owned(),
            model: "SoftHSM v2".to_owned(),
            serial,
        };
        state.serial_counter += 1;
        Ok(())
    }

    fn base_set_env_and_reset(&self, key: &str, value: &str) -> Result<()> {
        self.record("set_env_and_reset", vec![key.to_owned(), value.to_owned()]);
        // Through the hooked surface (a hook overriding shutdown sees this one).
        Provider::shutdown(self)
    }
}

// -- summaries (c2's frozen call encoding) -------------------------------------------------

fn none() -> String {
    "None".to_owned()
}

fn bytes_summary(data: &[u8]) -> String {
    format!("{}B", data.len())
}

fn opt_bytes(data: Option<&[u8]>) -> String {
    data.map_or_else(none, bytes_summary)
}

fn opt_class(key_class: Option<KeyClass>) -> String {
    key_class.map_or_else(none, |class| class.py_name().to_owned())
}

fn template_summary(template: &KeyTemplate) -> String {
    format!("template({} attrs)", template.attrs.len())
}

fn opt_template(template: Option<&KeyTemplate>) -> String {
    template.map_or_else(none, template_summary)
}

fn material_summary(material: &KeyMaterial) -> String {
    format!(
        "{}/{}:{}B",
        material.algorithm.as_str(),
        material.key_class.as_str(),
        material.data.len()
    )
}

// -- helpers ------------------------------------------------------------------------------

/// The §4.3 invariant: a zero-length key id is no id.
fn normalize_id(key_id: Option<&[u8]>) -> Option<Vec<u8>> {
    key_id.filter(|id| !id.is_empty()).map(<[u8]>::to_vec)
}

/// Concatenated SHA-256(secret ‖ 0x00 ‖ context ‖ 0x00 ‖ counter_be32), truncated.
fn keystream(secret: &[u8], context: &[u8], length: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(length + 32));
    let mut input = Zeroizing::new(Vec::with_capacity(secret.len() + context.len() + 6));
    let mut counter: u32 = 0;
    while out.len() < length {
        input.clear();
        input.extend_from_slice(secret);
        input.push(0);
        input.extend_from_slice(context);
        input.push(0);
        input.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&openssl::sha::sha256(&input));
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    out
}

/// Python truthiness of a c2 template value (`bool(attr.value)`).
fn truthy(value: &AttrValue) -> bool {
    match value {
        AttrValue::Bool(flag) => *flag,
        AttrValue::Ulong(number) => *number != 0,
        AttrValue::Str(text) | AttrValue::Symbol(text) => !text.is_empty(),
        AttrValue::Bytes(bytes) => !bytes.is_empty(),
    }
}

/// (exportable, attributes) per §5.5: exportable = extractable and not sensitive;
/// secret/private attributes always carry both flags.
fn policy(
    template: Option<&KeyTemplate>,
    key_class: KeyClass,
) -> (bool, BTreeMap<String, AttrValue>) {
    if matches!(
        key_class,
        KeyClass::Public | KeyClass::Certificate | KeyClass::Data
    ) {
        return (true, BTreeMap::new());
    }
    let flag = |name: &str, default: bool| {
        template
            .and_then(|template| template.get(name))
            .filter(|attr| attr.enabled)
            .map_or(default, |attr| truthy(&attr.value))
    };
    let sensitive = flag("CKA_SENSITIVE", false);
    let extractable = flag("CKA_EXTRACTABLE", true);
    let attributes = BTreeMap::from([
        ("CKA_SENSITIVE".to_owned(), AttrValue::Bool(sensitive)),
        ("CKA_EXTRACTABLE".to_owned(), AttrValue::Bool(extractable)),
    ]);
    (extractable && !sensitive, attributes)
}

/// Kind for fixture attrs outside CKA_CATALOG (c2 `_kind_of_value`: a symbol is a str).
fn kind_of_value(value: &AttrValue) -> AttrKind {
    match value {
        AttrValue::Bool(_) => AttrKind::Bool,
        AttrValue::Ulong(_) => AttrKind::Ulong,
        AttrValue::Bytes(_) => AttrKind::Bytes,
        AttrValue::Str(_) | AttrValue::Symbol(_) => AttrKind::Str,
    }
}

/// c2 `_as_bytes(params.get(name))`: bytes verbatim, absent → b"", else `str(value)`.
fn param_bytes(params: &Params, name: &str) -> Vec<u8> {
    match params.get(name) {
        None => Vec::new(),
        Some(ParamValue::Bytes(bytes)) => bytes.clone(),
        Some(ParamValue::Str(text) | ParamValue::Enum(text)) => text.as_bytes().to_vec(),
        Some(ParamValue::Int(number)) => number.to_string().into_bytes(),
        Some(ParamValue::Bool(flag)) => py_bool(*flag).as_bytes().to_vec(),
        Some(ParamValue::KeyRef(info)) => info.key_ref.display().into_bytes(),
    }
}

fn applied(name: &str) -> AttrEditOutcome {
    AttrEditOutcome {
        name: name.to_owned(),
        applied: true,
        detail: None,
    }
}

// -- the hooked surface -------------------------------------------------------------------

/// Runs `$hook` when hooks are installed and it overrides the method, else `$base`.
macro_rules! dispatch {
    ($self:ident, $hook:ident($($arg:expr),*), $base:expr) => {{
        if let Some(hooks) = $self.hooks()
            && let Some(result) = hooks.$hook(&Unhooked($self) $(, $arg)*)
        {
            return result;
        }
        $base
    }};
}

impl Provider for FakeProvider {
    fn name(&self) -> &str {
        &self.name
    }
    fn type_name(&self) -> &str {
        &self.type_name
    }
    fn initialize(&self) -> Result<()> {
        dispatch!(self, initialize(), self.base_initialize())
    }
    fn shutdown(&self) -> Result<()> {
        dispatch!(self, shutdown(), self.base_shutdown())
    }
    fn status(&self) -> ProviderStatus {
        dispatch!(self, status(), self.base_status())
    }
    fn list_tokens(&self) -> Result<Vec<TokenInfo>> {
        dispatch!(self, list_tokens(), self.base_list_tokens())
    }
    fn login(&self, token: &TokenInfo, pin: &SecretString, keep_pin: bool) -> Result<()> {
        dispatch!(
            self,
            login(token, pin, keep_pin),
            self.base_login(token, keep_pin)
        )
    }
    fn logout(&self) -> Result<()> {
        dispatch!(self, logout(), self.base_logout())
    }
    fn mechanisms(&self) -> BTreeSet<String> {
        dispatch!(self, mechanisms(), self.base_mechanisms())
    }
    fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        dispatch!(self, list_keys(), self.base_list_keys())
    }
    fn find_key(&self, selector: &KeySelector) -> Result<KeyInfo> {
        dispatch!(self, find_key(selector), self.base_find_key(selector))
    }
    fn import_key(
        &self,
        material: &KeyMaterial,
        label: &str,
        template: Option<&KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> Result<KeyInfo> {
        dispatch!(
            self,
            import_key(material, label, template, key_id),
            self.base_import_key(material, label, template, key_id)
        )
    }
    fn generate_key(&self, request: &GenerateRequest) -> Result<KeyInfo> {
        dispatch!(self, generate_key(request), self.base_generate_key(request))
    }
    fn delete_key(&self, key: &KeyInfo) -> Result<()> {
        dispatch!(self, delete_key(key), self.base_delete_key(key))
    }
    fn export_key(&self, key: &KeyInfo) -> Result<KeyMaterial> {
        dispatch!(self, export_key(key), self.base_export_key(key))
    }
    fn encrypt(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>> {
        dispatch!(
            self,
            encrypt(key, mech, data),
            self.base_encrypt(key, mech, data)
        )
    }
    fn decrypt(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        dispatch!(
            self,
            decrypt(key, mech, data),
            self.base_decrypt(key, mech, data)
        )
    }
    fn sign(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>> {
        dispatch!(self, sign(key, mech, data), self.base_sign(key, mech, data))
    }
    fn verify(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        dispatch!(
            self,
            verify(key, mech, data, signature),
            self.base_verify(key, mech, data, signature)
        )
    }
    fn derive(&self, key: &KeyInfo, mech: &MechanismInvocation) -> Result<DeriveResult> {
        dispatch!(self, derive(key, mech), self.base_derive(key, mech))
    }
    fn generate_random(&self, len: usize) -> Result<Zeroizing<Vec<u8>>> {
        dispatch!(self, generate_random(len), self.base_generate_random(len))
    }
    fn wrap_key(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        target: &KeyInfo,
        options: &WrapOptions,
    ) -> Result<Vec<u8>> {
        dispatch!(
            self,
            wrap_key(wrapping_key, mech, target, options),
            self.base_wrap_key(wrapping_key, mech, target)
        )
    }
    fn unwrap_key(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        wrapped: &[u8],
        request: &UnwrapRequest,
    ) -> Result<KeyInfo> {
        dispatch!(
            self,
            unwrap_key(wrapping_key, mech, wrapped, request),
            self.base_unwrap_key(wrapping_key, mech, wrapped, request)
        )
    }
    fn read_key_template(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        dispatch!(
            self,
            read_key_template(key),
            self.base_read_key_template(key)
        )
    }
    fn update_key(&self, key: &KeyInfo, changes: &KeyTemplate) -> Result<KeyEditResult> {
        dispatch!(
            self,
            update_key(key, changes),
            self.base_update_key(key, changes)
        )
    }
    fn read_full_template(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        dispatch!(
            self,
            read_full_template(key),
            self.base_read_full_template(key)
        )
    }
    fn as_token_init(&self) -> Option<&dyn TokenInit> {
        if self.tokens_configured() {
            Some(self)
        } else {
            None
        }
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl TokenInit for FakeProvider {
    fn init_token(
        &self,
        slot: u64,
        label: &str,
        so_pin: &SecretString,
        user_pin: &SecretString,
    ) -> Result<()> {
        dispatch!(
            self,
            init_token(slot, label, so_pin, user_pin),
            self.base_init_token(slot, label)
        )
    }
    fn set_env_and_reset(&self, key: &str, value: &str) -> Result<()> {
        dispatch!(
            self,
            set_env_and_reset(key, value),
            self.base_set_env_and_reset(key, value)
        )
    }
}

/// The un-hooked view handed to hooks as `next` (c2 `super().method(...)`).
struct Unhooked<'a>(&'a FakeProvider);

impl Provider for Unhooked<'_> {
    fn name(&self) -> &str {
        &self.0.name
    }
    fn type_name(&self) -> &str {
        &self.0.type_name
    }
    fn initialize(&self) -> Result<()> {
        self.0.base_initialize()
    }
    fn shutdown(&self) -> Result<()> {
        self.0.base_shutdown()
    }
    fn status(&self) -> ProviderStatus {
        self.0.base_status()
    }
    fn list_tokens(&self) -> Result<Vec<TokenInfo>> {
        self.0.base_list_tokens()
    }
    fn login(&self, token: &TokenInfo, _pin: &SecretString, keep_pin: bool) -> Result<()> {
        self.0.base_login(token, keep_pin)
    }
    fn logout(&self) -> Result<()> {
        self.0.base_logout()
    }
    fn mechanisms(&self) -> BTreeSet<String> {
        self.0.base_mechanisms()
    }
    // c2 `super().supports(m)` resolves `self.mechanisms()` virtually: the HOOKED surface.
    fn supports(&self, mechanism: &str) -> bool {
        Provider::mechanisms(self.0).contains(mechanism)
    }
    fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        self.0.base_list_keys()
    }
    fn find_key(&self, selector: &KeySelector) -> Result<KeyInfo> {
        self.0.base_find_key(selector)
    }
    fn import_key(
        &self,
        material: &KeyMaterial,
        label: &str,
        template: Option<&KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> Result<KeyInfo> {
        self.0.base_import_key(material, label, template, key_id)
    }
    fn generate_key(&self, request: &GenerateRequest) -> Result<KeyInfo> {
        self.0.base_generate_key(request)
    }
    fn delete_key(&self, key: &KeyInfo) -> Result<()> {
        self.0.base_delete_key(key)
    }
    fn export_key(&self, key: &KeyInfo) -> Result<KeyMaterial> {
        self.0.base_export_key(key)
    }
    fn encrypt(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>> {
        self.0.base_encrypt(key, mech, data)
    }
    fn decrypt(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.0.base_decrypt(key, mech, data)
    }
    fn sign(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>> {
        self.0.base_sign(key, mech, data)
    }
    fn verify(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        self.0.base_verify(key, mech, data, signature)
    }
    fn derive(&self, key: &KeyInfo, mech: &MechanismInvocation) -> Result<DeriveResult> {
        self.0.base_derive(key, mech)
    }
    fn generate_random(&self, len: usize) -> Result<Zeroizing<Vec<u8>>> {
        self.0.base_generate_random(len)
    }
    fn wrap_key(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        target: &KeyInfo,
        _options: &WrapOptions,
    ) -> Result<Vec<u8>> {
        self.0.base_wrap_key(wrapping_key, mech, target)
    }
    fn unwrap_key(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        wrapped: &[u8],
        request: &UnwrapRequest,
    ) -> Result<KeyInfo> {
        self.0.base_unwrap_key(wrapping_key, mech, wrapped, request)
    }
    fn read_key_template(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        self.0.base_read_key_template(key)
    }
    fn update_key(&self, key: &KeyInfo, changes: &KeyTemplate) -> Result<KeyEditResult> {
        self.0.base_update_key(key, changes)
    }
    fn read_full_template(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        self.0.base_read_full_template(key)
    }
    fn as_token_init(&self) -> Option<&dyn TokenInit> {
        if self.0.tokens_configured() {
            Some(self)
        } else {
            None
        }
    }
    /// The wrapped FakeProvider itself (a non-'static view cannot be `&dyn Any`).
    fn as_any(&self) -> &dyn Any {
        self.0
    }
}

impl TokenInit for Unhooked<'_> {
    fn init_token(
        &self,
        slot: u64,
        label: &str,
        _so_pin: &SecretString,
        _user_pin: &SecretString,
    ) -> Result<()> {
        self.0.base_init_token(slot, label)
    }
    fn set_env_and_reset(&self, key: &str, value: &str) -> Result<()> {
        self.0.base_set_env_and_reset(key, value)
    }
}

/// Per-method overrides. Each method returns None = "not overridden" (the fake's own
/// behavior runs, and records the call) or Some(result) (returned as is; nothing is
/// recorded unless the hook delegates). `next` is a borrowed un-hooked view of the same
/// fake, so a hook can observe and delegate (c2 `super().method(...)`); `next.as_any()`
/// returns the FakeProvider itself. Dispatch rules (c2 virtual-dispatch parity):
/// FakeProvider's own internal calls — `set_env_and_reset` → `shutdown`, capability checks
/// → `mechanisms()` (incl. `supports`), also when they happen inside a `next.*` call — go
/// through the HOOKED surface (a hook overriding `shutdown` sees the shutdown that
/// `set_env_and_reset` triggers); `unwrap_key` stores the unwrapped key through the fake's
/// internal store path (c2 `_store_key`: the duplicate guard runs, no `import_key` call is
/// made or recorded, an `import_key` hook is not consulted); no RefCell borrow is held
/// while a hook or `next` runs.
#[allow(unused_variables)]
pub trait FakeHooks {
    fn initialize(&self, next: &dyn Provider) -> Option<Result<()>> {
        None
    }
    fn shutdown(&self, next: &dyn Provider) -> Option<Result<()>> {
        None
    }
    fn status(&self, next: &dyn Provider) -> Option<ProviderStatus> {
        None
    }
    fn list_tokens(&self, next: &dyn Provider) -> Option<Result<Vec<TokenInfo>>> {
        None
    }
    fn login(
        &self,
        next: &dyn Provider,
        token: &TokenInfo,
        pin: &SecretString,
        keep_pin: bool,
    ) -> Option<Result<()>> {
        None
    }
    fn logout(&self, next: &dyn Provider) -> Option<Result<()>> {
        None
    }
    fn mechanisms(&self, next: &dyn Provider) -> Option<std::collections::BTreeSet<String>> {
        None
    }
    fn list_keys(&self, next: &dyn Provider) -> Option<Result<Vec<KeyInfo>>> {
        None
    }
    fn find_key(&self, next: &dyn Provider, selector: &KeySelector) -> Option<Result<KeyInfo>> {
        None
    }
    fn import_key(
        &self,
        next: &dyn Provider,
        material: &KeyMaterial,
        label: &str,
        template: Option<&KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> Option<Result<KeyInfo>> {
        None
    }
    fn generate_key(
        &self,
        next: &dyn Provider,
        request: &GenerateRequest,
    ) -> Option<Result<KeyInfo>> {
        None
    }
    fn delete_key(&self, next: &dyn Provider, key: &KeyInfo) -> Option<Result<()>> {
        None
    }
    fn export_key(&self, next: &dyn Provider, key: &KeyInfo) -> Option<Result<KeyMaterial>> {
        None
    }
    fn encrypt(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Option<Result<Vec<u8>>> {
        None
    }
    fn decrypt(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Option<Result<Zeroizing<Vec<u8>>>> {
        None
    }
    fn sign(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Option<Result<Vec<u8>>> {
        None
    }
    fn verify(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> Option<Result<bool>> {
        None
    }
    fn derive(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
        mech: &MechanismInvocation,
    ) -> Option<Result<DeriveResult>> {
        None
    }
    fn generate_random(
        &self,
        next: &dyn Provider,
        len: usize,
    ) -> Option<Result<Zeroizing<Vec<u8>>>> {
        None
    }
    fn wrap_key(
        &self,
        next: &dyn Provider,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        target: &KeyInfo,
        options: &WrapOptions,
    ) -> Option<Result<Vec<u8>>> {
        None
    }
    fn unwrap_key(
        &self,
        next: &dyn Provider,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        wrapped: &[u8],
        request: &UnwrapRequest,
    ) -> Option<Result<KeyInfo>> {
        None
    }
    fn read_key_template(&self, next: &dyn Provider, key: &KeyInfo) -> Option<Result<KeyTemplate>> {
        None
    }
    fn update_key(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
        changes: &KeyTemplate,
    ) -> Option<Result<KeyEditResult>> {
        None
    }
    fn read_full_template(
        &self,
        next: &dyn Provider,
        key: &KeyInfo,
    ) -> Option<Result<KeyTemplate>> {
        None
    }
    fn init_token(
        &self,
        next: &dyn Provider,
        slot: u64,
        label: &str,
        so_pin: &SecretString,
        user_pin: &SecretString,
    ) -> Option<Result<()>> {
        None
    }
    fn set_env_and_reset(&self, next: &dyn Provider, key: &str, value: &str) -> Option<Result<()>> {
        None
    }
}
