// Key model and the ref grammar (spec §4.3; owner R1).
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::str::FromStr;

use zeroize::Zeroizing;

use crate::error::{ConsoleError, Result};
use crate::template::AttrValue;
use crate::text::py_repr;

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
        match self {
            KeyClass::Secret => "secret",
            KeyClass::Private => "private",
            KeyClass::Public => "public",
            KeyClass::Certificate => "certificate",
            KeyClass::Data => "data",
        }
    }
    /// Short ref-selector token, the form `display_refs` emits (c2 CLASS_TOKENS):
    /// Private→"priv", Public→"pub", Certificate→"cert", Secret→"secret", Data→"data".
    pub fn token(self) -> &'static str {
        match self {
            KeyClass::Secret => "secret",
            KeyClass::Private => "priv",
            KeyClass::Public => "pub",
            KeyClass::Certificate => "cert",
            KeyClass::Data => "data",
        }
    }
    /// Python `str()` of the c2 enum member, e.g. "KeyClass.PRIVATE" (FakeProvider call log).
    pub fn py_name(self) -> &'static str {
        match self {
            KeyClass::Secret => "KeyClass.SECRET",
            KeyClass::Private => "KeyClass.PRIVATE",
            KeyClass::Public => "KeyClass.PUBLIC",
            KeyClass::Certificate => "KeyClass.CERTIFICATE",
            KeyClass::Data => "KeyClass.DATA",
        }
    }
    /// Symbolic CKO name: CKO_SECRET_KEY, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_CERTIFICATE, CKO_DATA.
    pub fn cko_symbol(self) -> &'static str {
        match self {
            KeyClass::Secret => "CKO_SECRET_KEY",
            KeyClass::Private => "CKO_PRIVATE_KEY",
            KeyClass::Public => "CKO_PUBLIC_KEY",
            KeyClass::Certificate => "CKO_CERTIFICATE",
            KeyClass::Data => "CKO_DATA",
        }
    }
    /// True for Secret/Private/Public (the classes that carry CKA_KEY_TYPE).
    pub fn has_key_type(self) -> bool {
        matches!(
            self,
            KeyClass::Secret | KeyClass::Private | KeyClass::Public
        )
    }
}
impl fmt::Display for KeyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Exact tokens only; anything else → Generic "unknown key class {s!r}".
impl FromStr for KeyClass {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        KeyClass::ALL
            .into_iter()
            .find(|class| class.as_str() == s)
            .ok_or_else(|| ConsoleError::generic(format!("unknown key class {}", py_repr(s))))
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
        match self {
            KeyAlgorithm::Aes => "aes",
            KeyAlgorithm::Rsa => "rsa",
            KeyAlgorithm::Ec => "ec",
            KeyAlgorithm::EcEdwards => "ec-edwards",
            KeyAlgorithm::EcMontgomery => "ec-montgomery",
            KeyAlgorithm::Generic => "generic",
            KeyAlgorithm::None => "none",
            KeyAlgorithm::Other => "other",
        }
    }
    /// e.g. "KeyAlgorithm.EC_EDWARDS" (FakeProvider call log).
    pub fn py_name(self) -> &'static str {
        match self {
            KeyAlgorithm::Aes => "KeyAlgorithm.AES",
            KeyAlgorithm::Rsa => "KeyAlgorithm.RSA",
            KeyAlgorithm::Ec => "KeyAlgorithm.EC",
            KeyAlgorithm::EcEdwards => "KeyAlgorithm.EC_EDWARDS",
            KeyAlgorithm::EcMontgomery => "KeyAlgorithm.EC_MONTGOMERY",
            KeyAlgorithm::Generic => "KeyAlgorithm.GENERIC",
            KeyAlgorithm::None => "KeyAlgorithm.NONE",
            KeyAlgorithm::Other => "KeyAlgorithm.OTHER",
        }
    }
    /// CKK_AES, CKK_RSA, CKK_EC, CKK_EC_EDWARDS, CKK_EC_MONTGOMERY, CKK_GENERIC_SECRET;
    /// None for `None`/`Other`.
    pub fn ckk_symbol(self) -> Option<&'static str> {
        match self {
            KeyAlgorithm::Aes => Some("CKK_AES"),
            KeyAlgorithm::Rsa => Some("CKK_RSA"),
            KeyAlgorithm::Ec => Some("CKK_EC"),
            KeyAlgorithm::EcEdwards => Some("CKK_EC_EDWARDS"),
            KeyAlgorithm::EcMontgomery => Some("CKK_EC_MONTGOMERY"),
            KeyAlgorithm::Generic => Some("CKK_GENERIC_SECRET"),
            KeyAlgorithm::None | KeyAlgorithm::Other => None,
        }
    }
    /// False for `None` and `Other` (c2 NON_CREATABLE_ALGORITHMS).
    pub fn is_creatable(self) -> bool {
        !matches!(self, KeyAlgorithm::None | KeyAlgorithm::Other)
    }
    /// Ec | EcEdwards | EcMontgomery (the keyparse "ec" hint family).
    pub fn is_ec_family(self) -> bool {
        matches!(
            self,
            KeyAlgorithm::Ec | KeyAlgorithm::EcEdwards | KeyAlgorithm::EcMontgomery
        )
    }
}
impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Exact tokens only; anything else → Generic "unknown key algorithm {s!r}".
impl FromStr for KeyAlgorithm {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        KeyAlgorithm::ALL
            .into_iter()
            .find(|algorithm| algorithm.as_str() == s)
            .ok_or_else(|| ConsoleError::generic(format!("unknown key algorithm {}", py_repr(s))))
    }
}

impl KeyAlgorithm {
    /// Declaration order (c2 enum order) — the FromStr search space.
    const ALL: [KeyAlgorithm; 8] = [
        KeyAlgorithm::Aes,
        KeyAlgorithm::Rsa,
        KeyAlgorithm::Ec,
        KeyAlgorithm::EcEdwards,
        KeyAlgorithm::EcMontgomery,
        KeyAlgorithm::Generic,
        KeyAlgorithm::None,
        KeyAlgorithm::Other,
    ];
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
        match self {
            Curve::P256 => "p256",
            Curve::P384 => "p384",
            Curve::P521 => "p521",
            Curve::Ed25519 => "ed25519",
            Curve::Ed448 => "ed448",
            Curve::X25519 => "x25519",
            Curve::X448 => "x448",
            Curve::Other(name) => name,
        }
    }
    /// P*/Other → Ec, Ed* → EcEdwards, X* → EcMontgomery.
    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            Curve::P256 | Curve::P384 | Curve::P521 | Curve::Other(_) => KeyAlgorithm::Ec,
            Curve::Ed25519 | Curve::Ed448 => KeyAlgorithm::EcEdwards,
            Curve::X25519 | Curve::X448 => KeyAlgorithm::EcMontgomery,
        }
    }
    /// Fixed scalar/field width in bytes: p256 32, p384 48, p521 66, ed25519 32, ed448 57,
    /// x25519 32, x448 56; Other: secp192r1 24, secp224r1 28, secp256k1 32, brainpoolp256r1
    /// 32, brainpoolp384r1 48, brainpoolp512r1 64 (= ceil(curve bits / 8), c2's
    /// `(curve.key_size + 7) // 8`); None for any other name. ECDSA r‖s halves use this
    /// width on every curve (§4.5.4).
    pub fn field_bytes(&self) -> Option<usize> {
        match self {
            Curve::P256 | Curve::Ed25519 | Curve::X25519 => Some(32),
            Curve::P384 => Some(48),
            Curve::P521 => Some(66),
            Curve::Ed448 => Some(57),
            Curve::X448 => Some(56),
            Curve::Other(name) => match name.as_str() {
                "secp192r1" => Some(24),
                "secp224r1" => Some(28),
                "secp256k1" | "brainpoolp256r1" => Some(32),
                "brainpoolp384r1" => Some(48),
                "brainpoolp512r1" => Some(64),
                _ => None,
            },
        }
    }
}
impl fmt::Display for Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// The seven tokens only (case-sensitive); else Generic "unknown curve {s!r}".
impl FromStr for Curve {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        Curve::KNOWN
            .into_iter()
            .find(|curve| curve.as_str() == s)
            .ok_or_else(|| ConsoleError::generic(format!("unknown curve {}", py_repr(s))))
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
        Self {
            provider: provider.into(),
            label: label.into(),
            key_id,
        }
    }
    /// "prov:label" or "prov:label#0a1b" (id lower-case hex).
    pub fn display(&self) -> String {
        match &self.key_id {
            None => format!("{}:{}", self.provider, self.label),
            Some(id) => format!("{}:{}#{}", self.provider, self.label, hex::encode(id)),
        }
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
/// prints `data` as `"<N bytes>"` (key bytes never reach logs or panic messages).
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
        Self {
            algorithm,
            key_class,
            data: Zeroizing::new(data),
            curve: None,
            size_bits: None,
            label_hint: None,
        }
    }
}
impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("algorithm", &self.algorithm)
            .field("key_class", &self.key_class)
            .field("data", &format_args!("<{} bytes>", self.data.len()))
            .field("curve", &self.curve)
            .field("size_bits", &self.size_bits)
            .field("label_hint", &self.label_hint)
            .finish()
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
    let lowered = token.to_lowercase();
    CLASS_SELECTORS
        .iter()
        .find(|(name, _)| *name == lowered)
        .map(|(_, class)| *class)
}

/// THE ref-grammar parser (never reimplemented; ProviderRegistry::resolve_ref and the
/// `--kek` resolver use it). `'prov:label#0a1b:priv@7'` →
/// `ParsedRef{provider:"prov", label:"label", key_id:Some([0x0a,0x1b]), key_class:Some(Private), handle:Some(7)}`.
pub fn parse_ref(reference: &str) -> Result<ParsedRef> {
    let error = |message: String, pos: usize| ConsoleError::parse(message, reference, pos);
    let Some(colon) = reference.find(':') else {
        return Err(
            error("key reference is missing ':'".to_owned(), reference.len()).with_hint(REF_HINT),
        );
    };
    let provider = &reference[..colon];
    let mut provider_chars = provider.char_indices();
    let Some((_, first)) = provider_chars.next() else {
        return Err(error("missing provider name".to_owned(), 0).with_hint(REF_HINT));
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(error(
            format!(
                "invalid provider name start {}",
                py_repr(&first.to_string())
            ),
            0,
        )
        .with_hint(PROVIDER_HINT));
    }
    if let Some((offset, bad)) =
        provider_chars.find(|&(_, c)| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    {
        return Err(error(
            format!(
                "invalid character {} in provider name",
                py_repr(&bad.to_string())
            ),
            offset,
        )
        .with_hint(PROVIDER_HINT));
    }

    let mut handle = None;
    let mut key_class = None;
    let mut end = reference.len();

    // 1. A trailing `@<ASCII digits>` after the first ':' is the session handle.
    if let Some(at_pos) = reference.rfind('@').filter(|&at| at > colon) {
        let tail = &reference[at_pos + 1..];
        if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
            let value = tail.parse::<u64>().map_err(|_| {
                error("handle out of range".to_owned(), at_pos + 1).with_hint(REF_HINT)
            })?;
            handle = Some(value);
            end = at_pos;
        }
    }

    // 2. With a '#' (the last one before the handle): label#id[:class].
    let (label, id_hex, hash_pos) = match reference[..end].rfind('#').filter(|&h| h > colon) {
        Some(hash_pos) => {
            let label = &reference[colon + 1..hash_pos];
            let mut id_hex = &reference[hash_pos + 1..end];
            // ids never contain ':' — what follows one must be a class selector
            if let Some(sel) = id_hex.find(':') {
                let token = &id_hex[sel + 1..];
                let Some(class) = class_selector(token) else {
                    return Err(error(
                        format!("unknown class selector {}", py_repr(token)),
                        hash_pos + 1 + sel + 1,
                    )
                    .with_hint(CLASS_HINT));
                };
                key_class = Some(class);
                id_hex = &id_hex[..sel];
            }
            (label, Some(id_hex), hash_pos)
        }
        None => {
            // 3. Without '#': a trailing ':<class>' is a selector only when recognised.
            let mut label = &reference[colon + 1..end];
            if let Some(sel) = label.rfind(':')
                && let Some(class) = class_selector(&label[sel + 1..])
            {
                key_class = Some(class);
                label = &label[..sel];
            }
            (label, None, 0)
        }
    };

    if label.is_empty() {
        return Err(error("missing key label".to_owned(), colon + 1).with_hint(REF_HINT));
    }
    let Some(id_hex) = id_hex else {
        return Ok(ParsedRef {
            provider: provider.to_owned(),
            label: label.to_owned(),
            key_id: None,
            key_class,
            handle,
        });
    };
    if id_hex.is_empty() {
        return Err(error("empty key id after '#'".to_owned(), hash_pos + 1).with_hint(REF_HINT));
    }
    if let Some((offset, bad)) = id_hex.char_indices().find(|&(_, c)| !c.is_ascii_hexdigit()) {
        return Err(error(
            format!("invalid hex digit {} in key id", py_repr(&bad.to_string())),
            hash_pos + 1 + offset,
        )
        .with_hint("the id after '#' is lowercase hex, e.g. #0a1b"));
    }
    if !id_hex.len().is_multiple_of(2) {
        return Err(error(
            "odd number of hex digits in key id".to_owned(),
            hash_pos + 1 + id_hex.len(),
        )
        .with_hint("the id after '#' encodes whole bytes (2 hex digits each)"));
    }
    let key_id = hex::decode(id_hex)
        .map_err(|_| error("invalid hex digit in key id".to_owned(), hash_pos + 1))?;
    Ok(ParsedRef {
        provider: provider.to_owned(),
        label: label.to_owned(),
        key_id: Some(key_id),
        key_class,
        handle,
    })
}

const REF_HINT: &str = "expected '<provider>:<label>[#<id-hex>][:<class>][@<handle>]'";
const PROVIDER_HINT: &str = "provider names match [A-Za-z_][A-Za-z0-9_-]*";
const CLASS_HINT: &str =
    "class is one of priv, pub, cert, secret, data (long forms private/public/certificate too)";

/// Listing refs made unambiguous; see rules below.
pub fn display_refs(infos: &[KeyInfo]) -> Vec<String> {
    fn counts(texts: &[String]) -> HashMap<&str, usize> {
        let mut counts = HashMap::new();
        for text in texts {
            *counts.entry(text.as_str()).or_insert(0) += 1;
        }
        counts
    }
    let plain: Vec<String> = infos.iter().map(|info| info.key_ref.display()).collect();
    let plain_counts = counts(&plain);
    let classed: Vec<String> = plain
        .iter()
        .zip(infos)
        .map(|(text, info)| {
            if plain_counts.get(text.as_str()).copied().unwrap_or(0) == 1 {
                text.clone()
            } else {
                format!("{text}:{}", info.key_class.token())
            }
        })
        .collect();
    let classed_counts = counts(&classed);
    classed
        .iter()
        .zip(infos)
        .map(|(text, info)| match info.handle {
            Some(handle) if classed_counts.get(text.as_str()).copied().unwrap_or(0) > 1 => {
                format!("{text}@{handle}")
            }
            _ => text.clone(),
        })
        .collect()
}
