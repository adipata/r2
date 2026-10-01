// R0 skeleton — owner R1 (generated from spec §4)
// ---- spec §4.3 block 0
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use zeroize::Zeroizing;

use crate::error::{ConsoleError, Result};
use crate::template::AttrValue;

/// Object class. Token (Display/FromStr, exact, lower-case): "secret" | "private" |
/// "public" | "certificate" | "data". Ord = declaration order — NOT c2's text order: where
/// c2 sorts class values for a message (e.g. wrapload's "needs a certificate or public …
/// KEK" = `' or '.join(sorted(c.value …))`), r2 sorts by `as_str()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyClass {
    Secret,
    Private,
    Public,
    Certificate,
    /// CKO_DATA: opaque bytes, algorithm `None`, never a CKA_ID.
    Data,
}

impl KeyClass {
    pub const ALL: [KeyClass; 5] = [
        KeyClass::Secret,
        KeyClass::Private,
        KeyClass::Public,
        KeyClass::Certificate,
        KeyClass::Data,
    ];
    /// "secret" | "private" | "public" | "certificate" | "data".
    pub fn as_str(self) -> &'static str {
        unimplemented!("R1")
    }
    /// Short ref-selector token, the form `display_refs` emits (c2 CLASS_TOKENS):
    /// Private→"priv", Public→"pub", Certificate→"cert", Secret→"secret", Data→"data".
    pub fn token(self) -> &'static str {
        unimplemented!("R1")
    }
    /// Python `str()` of the c2 enum member, e.g. "KeyClass.PRIVATE" (FakeProvider call log).
    pub fn py_name(self) -> &'static str {
        unimplemented!("R1")
    }
    /// Symbolic CKO name: CKO_SECRET_KEY, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_CERTIFICATE, CKO_DATA.
    pub fn cko_symbol(self) -> &'static str {
        unimplemented!("R1")
    }
    /// True for Secret/Private/Public (the classes that carry CKA_KEY_TYPE).
    pub fn has_key_type(self) -> bool {
        unimplemented!("R1")
    }
}
impl fmt::Display for KeyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        unimplemented!("R1")
    }
}
/// Exact tokens only; anything else → Generic "unknown key class {s!r}".
impl FromStr for KeyClass {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        let _ = s;
        Err(crate::error::ConsoleError::not_implemented("R1"))
    }
}

/// Token: "aes" | "rsa" | "ec" | "ec-edwards" | "ec-montgomery" | "generic" | "none" | "other".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyAlgorithm {
    Aes,
    Rsa,
    /// Weierstrass curves (CKK_EC).
    Ec,
    /// Ed25519 / Ed448 (CKK_EC_EDWARDS).
    EcEdwards,
    /// X25519 / X448 (CKK_EC_MONTGOMERY).
    EcMontgomery,
    /// CKK_GENERIC_SECRET (HMAC keys); CKK_SHA*_HMAC key types fold here on read.
    Generic,
    /// Data objects carry no algorithm. Always written qualified (`KeyAlgorithm::None`).
    None,
    /// PKCS#11 key type r2 cannot model — listing/info/delete/edit only, never operated on.
    Other,
}

impl KeyAlgorithm {
    pub fn as_str(self) -> &'static str {
        unimplemented!("R1")
    }
    /// e.g. "KeyAlgorithm.EC_EDWARDS" (FakeProvider call log).
    pub fn py_name(self) -> &'static str {
        unimplemented!("R1")
    }
    /// CKK_AES, CKK_RSA, CKK_EC, CKK_EC_EDWARDS, CKK_EC_MONTGOMERY, CKK_GENERIC_SECRET;
    /// None for `None`/`Other`.
    pub fn ckk_symbol(self) -> Option<&'static str> {
        unimplemented!("R1")
    }
    /// False for `None` and `Other` (c2 NON_CREATABLE_ALGORITHMS).
    pub fn is_creatable(self) -> bool {
        unimplemented!("R1")
    }
    /// Ec | EcEdwards | EcMontgomery (the keyparse "ec" hint family).
    pub fn is_ec_family(self) -> bool {
        unimplemented!("R1")
    }
}
impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        unimplemented!("R1")
    }
}
/// Exact tokens only; anything else → Generic "unknown key algorithm {s!r}".
impl FromStr for KeyAlgorithm {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        let _ = s;
        Err(crate::error::ConsoleError::not_implemented("R1"))
    }
}

/// Curve names (c2 `curve: str`). Token: "p256" "p384" "p521" "ed25519" "ed448" "x25519"
/// "x448". `Other(name)` exists only for parity with c2's keyparse/memory classifier, which
/// reports the other Weierstrass curves pyca 49 supports by pyca's lower-cased name:
/// "secp192r1", "secp224r1", "secp256k1", "brainpoolp256r1", "brainpoolp384r1",
/// "brainpoolp512r1" (the exact set, §4.4.3); it is never produced by FromStr.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Curve {
    P256,
    P384,
    P521,
    Ed25519,
    Ed448,
    X25519,
    X448,
    Other(String),
}

impl Curve {
    /// The seven modelled curves, in the order above (generate/curve completion order).
    pub const KNOWN: [Curve; 7] = [
        Curve::P256,
        Curve::P384,
        Curve::P521,
        Curve::Ed25519,
        Curve::Ed448,
        Curve::X25519,
        Curve::X448,
    ];
    pub fn as_str(&self) -> &str {
        unimplemented!("R1")
    }
    /// P*/Other → Ec, Ed* → EcEdwards, X* → EcMontgomery.
    pub fn algorithm(&self) -> KeyAlgorithm {
        unimplemented!("R1")
    }
    /// Fixed scalar/field width in bytes: p256 32, p384 48, p521 66, ed25519 32, ed448 57,
    /// x25519 32, x448 56; Other: secp192r1 24, secp224r1 28, secp256k1 32, brainpoolp256r1
    /// 32, brainpoolp384r1 48, brainpoolp512r1 64 (= ceil(curve bits / 8), c2's
    /// `(curve.key_size + 7) // 8`); None for any other name. ECDSA r‖s halves use this
    /// width on every curve (§4.5.4).
    pub fn field_bytes(&self) -> Option<usize> {
        unimplemented!("R1")
    }
}
impl fmt::Display for Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        unimplemented!("R1")
    }
}
/// The seven tokens only (case-sensitive); else Generic "unknown curve {s!r}".
impl FromStr for Curve {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        let _ = s;
        Err(crate::error::ConsoleError::not_implemented("R1"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyRef {
    /// Provider instance name.
    pub provider: String,
    /// CKA_LABEL / memory key name.
    pub label: String,
    /// CKA_ID; disambiguates duplicate labels. Always None for data objects.
    /// Invariant: never `Some(empty)`. Every provider maps a zero-length CKA_ID to None when
    /// it builds a KeyInfo (c2 `self._attr_bytes(id_v) or None` — the normal case for
    /// objects created by pkcs11-tool/softhsm2-util without `--id`; MemoryProvider and
    /// FakeProvider normalize an empty `key_id` argument the same way), and `--id`
    /// rejects an empty value (c2 "key id must not be empty"), so
    /// `display()` never emits "prov:label#" (which `parse_ref` rejects) and the
    /// keypair-family collapse never sees `Some([])` ≠ `None`.
    pub key_id: Option<Vec<u8>>,
}
impl KeyRef {
    pub fn new(
        provider: impl Into<String>,
        label: impl Into<String>,
        key_id: Option<Vec<u8>>,
    ) -> Self {
        let _ = (provider, label, key_id);
        unimplemented!("R1")
    }
    /// "prov:label" or "prov:label#0a1b" (id lower-case hex).
    pub fn display(&self) -> String {
        unimplemented!("R1")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    pub key_ref: KeyRef,
    pub key_class: KeyClass,
    /// For CERTIFICATE: the algorithm of the embedded public key.
    pub algorithm: KeyAlgorithm,
    /// AES/generic key bits, RSA modulus bits, data value bits (8·len); None otherwise
    /// (always None for EC-family keys).
    pub size_bits: Option<u32>,
    pub curve: Option<Curve>,
    /// Certificates, public keys and data objects: always true. OTHER: always false.
    /// PKCS#11 secret/private: CKA_EXTRACTABLE ∧ ¬CKA_SENSITIVE (§5.5).
    pub exportable: bool,
    /// Read-only provider extras (CKA_* snapshot). PKCS#11 secret/private keys always
    /// carry Bool CKA_SENSITIVE and CKA_EXTRACTABLE (§5.5 guarantee); OTHER carries
    /// Symbol CKA_KEY_TYPE (`catalog::ckk_symbol` of the actual key type, or "unknown" when
    /// unreadable); certificates carry, on PKCS#11 (`x509info::cert_attributes`), Str
    /// CKA_SUBJECT / CKA_ISSUER (RFC 4514 display strings) and CKA_SERIAL_NUMBER (lower-case
    /// hex), and in memory (`x509info::memory_cert_attributes`, c2 `_cert_attributes`) Str
    /// "subject", "issuer", "serial_number", "not_valid_before", "not_valid_after";
    /// data objects may carry Str CKA_APPLICATION / Bytes CKA_OBJECT_ID.
    pub attributes: BTreeMap<String, AttrValue>,
    /// Provider-native object handle (PKCS#11: the numeric CK_OBJECT_HANDLE). Rendered as
    /// the session-transient `@<handle>` selector and the `key info` "handle" row; used by
    /// Pkcs11Provider to re-target the EXACT object among same-label/id/class twins (no
    /// unique match → AmbiguousKey, never a silent first match). Memory: None.
    pub handle: Option<u64>,
}

/// Parsed key material in a §4.3 canonical format. `Debug` is implemented by hand and
/// prints `data` as "<N bytes>" (key bytes never reach logs or panic messages).
#[derive(Clone, PartialEq, Eq)]
pub struct KeyMaterial {
    pub algorithm: KeyAlgorithm,
    pub key_class: KeyClass,
    pub data: Zeroizing<Vec<u8>>,
    pub curve: Option<Curve>,
    pub size_bits: Option<u32>,
    /// Suggested label (certificate CN, PKCS#12 friendly name).
    pub label_hint: Option<String>,
}
impl KeyMaterial {
    /// curve/size_bits/label_hint = None.
    pub fn new(algorithm: KeyAlgorithm, key_class: KeyClass, data: Vec<u8>) -> Self {
        let _ = (algorithm, key_class, data);
        unimplemented!("R1")
    }
}
impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        unimplemented!("R1")
    }
}

/// Decomposed key reference — output of `parse_ref`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedRef {
    pub provider: String,
    pub label: String,
    pub key_id: Option<Vec<u8>>,
    pub key_class: Option<KeyClass>,
    pub handle: Option<u64>,
}

/// Ref-grammar class selector tokens (matched case-insensitively), c2 CLASS_SELECTORS order.
pub const CLASS_SELECTORS: [(&str, KeyClass); 8] = [
    ("priv", KeyClass::Private),
    ("private", KeyClass::Private),
    ("pub", KeyClass::Public),
    ("public", KeyClass::Public),
    ("cert", KeyClass::Certificate),
    ("certificate", KeyClass::Certificate),
    ("secret", KeyClass::Secret),
    ("data", KeyClass::Data),
];

/// Case-insensitive lookup in CLASS_SELECTORS.
pub fn class_selector(token: &str) -> Option<KeyClass> {
    let _ = token;
    unimplemented!("R1")
}

/// THE ref-grammar parser (never reimplemented; ProviderRegistry::resolve_ref and the
/// `--kek` resolver use it). 'prov:label#0a1b:priv@7' →
/// ParsedRef{provider:"prov", label:"label", key_id:Some([0x0a,0x1b]), key_class:Some(Private), handle:Some(7)}.
pub fn parse_ref(reference: &str) -> Result<ParsedRef> {
    let _ = reference;
    Err(crate::error::ConsoleError::not_implemented("R1"))
}

/// Listing refs made unambiguous; see rules below.
pub fn display_refs(infos: &[KeyInfo]) -> Vec<String> {
    let _ = infos;
    unimplemented!("R1")
}
