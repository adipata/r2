// The Provider trait (spec §4.5.2, owner R3; c2 providers/base.py).
use std::any::Any;
use std::collections::BTreeSet;

use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{KeyInfo, KeyMaterial};
use r2_core::template::KeyTemplate;
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::types::*;

pub trait Provider {
    /// Instance name ("mem", "softhsm").
    fn name(&self) -> &str;
    /// "memory" | "pkcs11" (FakeProvider presents either, per instance).
    fn type_name(&self) -> &str;

    // -- lifecycle --
    /// Load library / C_Initialize; no-op for memory. Idempotent. Called LAZILY by the
    /// provider itself on first real use — the bootstrap never calls it (§6: a broken
    /// configured library must not prevent startup).
    fn initialize(&self) -> Result<()>;
    /// Logout, close sessions, C_Finalize (via the shared-module release); safe when never
    /// initialized.
    fn shutdown(&self) -> Result<()>;

    // -- authentication (one token of one device at a time per provider) --
    /// Never triggers a library load or token I/O beyond the cached state.
    fn status(&self) -> ProviderStatus;
    /// Tokens present (`getSlotList(tokenPresent=True)` + token info). Memory: empty.
    fn list_tokens(&self) -> Result<Vec<TokenInfo>> {
        Ok(Vec::new())
    }
    /// keep_pin=true → the provider may hold the PIN in memory for session auto-recovery
    /// (§5.2); never persisted. Already logged in → AlreadyLoggedIn "already logged in"
    /// (hint "logout first"), checked before C_Login.
    fn login(&self, token: &TokenInfo, pin: &SecretString, keep_pin: bool) -> Result<()> {
        let _ = (token, pin, keep_pin);
        Err(ConsoleError::unsupported(format!(
            "{} does not require login",
            self.name()
        )))
    }
    /// No-op by default (memory has no session).
    fn logout(&self) -> Result<()> {
        Ok(())
    }

    // -- capability discovery --
    /// Canonical mechanism names usable RIGHT NOW (post-login for PKCS#11; empty while
    /// logged out). Never loads a library.
    fn mechanisms(&self) -> BTreeSet<String>;
    fn supports(&self, mechanism: &str) -> bool {
        self.mechanisms().contains(mechanism)
    }

    // -- key management --
    /// Every object incl. certificates and data objects; PKCS#11 lists unmodelled key
    /// types as OTHER. Order (observable: `keys` rows, the `key info` "related:" line, ref
    /// completion): Pkcs11Provider = for class in [Secret, Private, Public, Certificate,
    /// Data] (KeyClass declaration order) one `find_objects([CKA_CLASS = cko(class)])` pass
    /// in token order, each object classified as c2 `_key_info` (objects of other CKO
    /// classes never appear; never one unfiltered find + classify, which would give
    /// creation order); MemoryProvider / FakeProvider = insertion order. FakeBackend
    /// returns `find_objects` results in creation order so R5a tests pin this.
    fn list_keys(&self) -> Result<Vec<KeyInfo>>;
    /// KeyNotFound | AmbiguousKey (texts and the family collapse rule: §4.5.3
    /// `lookup::select_match`). `key_class`/`handle` are extra match filters; a given
    /// key_class also disables the keypair-family class-preference collapse. "Provider
    /// order" of the matches (it orders the AmbiguousKey message and candidates): PKCS#11 =
    /// the `C_FindObjects` order for the template {CKA_LABEL[, CKA_ID]}, with class and
    /// handle applied as post-filters — find_key never goes through `list_keys`;
    /// MemoryProvider / FakeProvider = insertion order.
    fn find_key(&self, selector: &KeySelector) -> Result<KeyInfo>;
    /// DuplicateKey when a non-certificate object with the same (class, label, id)
    /// identity exists (§4.7 guard). DATA material: key_id must be None (Param otherwise);
    /// identity is (class, label). NONE (outside DATA) / OTHER material → Param.
    fn import_key(
        &self,
        material: &KeyMaterial,
        label: &str,
        template: Option<&KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> Result<KeyInfo>;
    /// AES/GENERIC: size_bits required (GENERIC: any multiple of 8 in 8..=8192); template
    /// applies to the secret key. RSA: size_bits required. EC/EC_EDWARDS/EC_MONTGOMERY:
    /// curve required. NONE/OTHER → Param. Keypairs create BOTH objects sharing label (and
    /// CKA_ID on PKCS#11); `template` = private, `public_template` = public; returns the
    /// private (or secret) KeyInfo, the public object appears in list_keys(). key_id None
    /// on PKCS#11 → an enabled template CKA_ID row if present (§4.7), else a random 4-byte
    /// CKA_ID. DuplicateKey when the resolved identity is taken by an object of the
    /// created class — both keypair halves are checked up front (never a half pair).
    fn generate_key(&self, request: &GenerateRequest) -> Result<KeyInfo>;
    fn delete_key(&self, key: &KeyInfo) -> Result<()>;
    /// KeyNotExportable when `key.exportable` is false. Certificates: DER. PUBLIC always
    /// allowed (PKCS#11: rebuilt from public attributes). DATA: raw CKA_VALUE (always).
    /// OTHER → UnsupportedOperation.
    fn export_key(&self, key: &KeyInfo) -> Result<KeyMaterial>;

    // -- crypto verbs (mechanisms vary; verbs never do) --
    fn encrypt(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>>;
    /// The plaintext is held in a zeroizing buffer (D3).
    fn decrypt(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>>;
    fn sign(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>>;
    /// Ok(false) for a well-formed but wrong signature (PKCS#11 CKR_SIGNATURE_INVALID /
    /// CKR_SIGNATURE_LEN_RANGE); errors only for real failures.
    fn verify(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool>;
    /// Peer public key travels as `mech.params["peer"]` (SPKI DER or raw point).
    fn derive(&self, key: &KeyInfo, mech: &MechanismInvocation) -> Result<DeriveResult>;

    // -- random generation (§5.17, §11 D29) --
    /// `len` bytes from the provider's own RNG, in a zeroizing buffer (D3): memory = OpenSSL
    /// (`r2_core::crypto::random_bytes`), PKCS#11 = C_GenerateRandom on the logged-in session
    /// (AuthRequired while logged out). No seeding: C_SeedRandom is never called. The
    /// console bounds `len` (§5.17); providers return exactly `len` bytes.
    fn generate_random(&self, len: usize) -> Result<Zeroizing<Vec<u8>>> {
        let _ = len;
        Err(ConsoleError::unsupported(format!(
            "{} does not support random generation",
            self.name()
        )))
    }

    // -- wrap/unwrap (frozen-provisional, §4.11) --
    fn wrap_key(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        target: &KeyInfo,
        options: &WrapOptions,
    ) -> Result<Vec<u8>> {
        let _ = (wrapping_key, mech, target, options);
        Err(ConsoleError::unsupported(format!(
            "{} does not support key wrapping",
            self.name()
        )))
    }
    /// Same identity semantics and duplicate guard as import_key.
    fn unwrap_key(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        wrapped: &[u8],
        request: &UnwrapRequest,
    ) -> Result<KeyInfo> {
        let _ = (wrapping_key, mech, wrapped, request);
        Err(ConsoleError::unsupported(format!(
            "{} does not support key unwrapping",
            self.name()
        )))
    }

    // -- key editing (frozen-provisional, §4.11) --
    /// Editor-seedable snapshot of THIS object: locked CKA_CLASS/CKA_KEY_TYPE rows (no
    /// CKA_KEY_TYPE for certificates/data; the key-type row shows the ACTUAL CKK symbol),
    /// CKA_LABEL, CKA_ID (disabled-empty when absent; no row for data objects),
    /// class-appropriate policy attrs (data: CKA_APPLICATION/CKA_OBJECT_ID) and decoded
    /// templates.custom_attributes; attrs the token refuses are skipped (§5.15).
    fn read_key_template(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        let _ = key;
        Err(ConsoleError::unsupported(format!(
            "{} does not support key editing",
            self.name()
        )))
    }
    /// Applies the ENABLED rows of `changes` to exactly this object, one attribute per call
    /// (CKA_LABEL+CKA_ID batched into one all-or-nothing call), one AttrEditOutcome per
    /// attr — a token refusal (e.g. CKR_ATTRIBUTE_READ_ONLY) is an outcome, never an error.
    /// AuthRequired aborts. Identity rows run the §4.7 duplicate guard BEFORE anything is
    /// applied (DuplicateKey; certificates exempt; the edited object excluded). Locked
    /// names in `changes` → Param. Siblings sharing the identity are untouched (family
    /// renames are a console confirm() flow, §5.15).
    fn update_key(&self, key: &KeyInfo, changes: &KeyTemplate) -> Result<KeyEditResult> {
        let _ = (key, changes);
        Err(ConsoleError::unsupported(format!(
            "{} does not support key editing",
            self.name()
        )))
    }
    /// COMPLETE snapshot for `key template` (§5.16): every CKA_CATALOG attr plus every
    /// templates.custom_attributes attr the backend returns — readable key material
    /// included; refused attrs (CKR_ATTRIBUTE_SENSITIVE/_TYPE_INVALID…) skipped;
    /// CKA_CLASS/CKA_KEY_TYPE symbolic (no CKA_KEY_TYPE for certificates/data; the actual
    /// CKK symbol, also for OTHER). Consumed by the template-file serializer, never the editor.
    fn read_full_template(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        let _ = key;
        Err(ConsoleError::unsupported(format!(
            "{} does not support template dumps",
            self.name()
        )))
    }

    // -- seams --
    /// The SoftHSM-wizard seam (§4.9.9): Some for providers that can initialize tokens
    /// (Pkcs11Provider; FakeProvider configured with `.with_tokens(..)`).
    fn as_token_init(&self) -> Option<&dyn TokenInit> {
        None
    }
    /// Downcast seam (tests, r2-cli). Implementations return `self` (a borrowed wrapper view,
    /// such as FakeProvider's un-hooked `next`, returns the object it wraps — a non-'static
    /// view cannot be `&dyn Any`).
    fn as_any(&self) -> &dyn Any;
}

/// Token initialization (c2 `Pkcs11Provider.init_token`, kept behind a trait so the
/// console never names a pkcs11 type and the wizard is unit-testable on FakeProvider).
pub trait TokenInit {
    /// C_InitToken + C_InitPIN on the free slot `slot` (§5.13 step 3). The label must be
    /// ≤ 32 UTF-8 bytes (Param "token label must be at most 32 bytes" otherwise — r2
    /// validates because cryptoki silently truncates; §11 D15); it is space-padded to the 32-byte
    /// field and `list_tokens` returns it exactly. After C_InitToken the token is re-found
    /// by label, then login(SO) + C_InitPIN(user_pin) + logout on an RW session.
    fn init_token(
        &self,
        slot: u64,
        label: &str,
        so_pin: &SecretString,
        user_pin: &SecretString,
    ) -> Result<()>;
    /// §5.13 step 2: set `key=value` in the process environment at the single audited
    /// `set_var` site, then shut this provider down (drop its session, release the shared
    /// module — the last release finalizes) so the next lazy initialize re-reads the
    /// environment. When another provider instance holds the same module (same canonical library
    /// path, §4.5.5) →
    /// Provider "'{name}' shares its PKCS#11 module with another provider" (hint "restart
    /// r2 after the setup, or remove the other provider entry"); nothing is changed then.
    fn set_env_and_reset(&self, key: &str, value: &str) -> Result<()>;
}
