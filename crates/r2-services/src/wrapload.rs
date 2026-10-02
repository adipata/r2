// Wrapped-key interchange: `load --kek` (§5.4) and `export --kek` (§5.6). Owner R15 —
// port of c2 `services/wrapload.py`.
//
// Both directions of one blob format, so a key exported wrapped loads back. The KEK is
// ALWAYS a key ALREADY RESIDENT in the provider holding (or receiving) the key —
// C_WrapKey/C_UnwrapKey semantics, so the material never appears in plaintext. The
// mechanism table below is the contract: AES secret KEKs use kw/kwp/cbc/gcm; RSA KEKs use
// oaep/pkcs1 with the PRIVATE half to unwrap and the PUBLIC half (or a certificate, §4.3)
// to wrap — hence the direction-aware KEK classes on each row. Private-key payloads are
// unencrypted PKCS#8 DER inside the blob (the §5.5 transport convention).
//
// Wrappability differs from exportability on purpose (§5.5): wrapping needs
// CKA_EXTRACTABLE alone, so a sensitive key that plain `export` refuses can still leave
// the token wrapped.
//
// Mechanism params are declared as ParamSpecs on synthetic OperationSpecs so the command
// layer resolves them through ParamResolver (one code path for inline name=value tokens
// and prompts, §5.1). Services never print; key bytes are never logged.
use std::collections::BTreeSet;

use r2_core::error::ConsoleError;
use r2_core::io::ConsoleIo;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, ParsedRef, parse_ref};
use r2_core::params::{ParamKind, ParamSpec, ParamStruct, ParamValue, Params, Verb};
use r2_core::template::AttrValue;
use r2_core::text::{close_matches, py_repr, py_strip};
use r2_ops::OperationSpec;
use r2_provider::{
    KeySelector, MechanismInvocation, Provider, ProviderRegistry, UnwrapRequest, WrapOptions,
    mechanism,
};

use crate::templatefile::EditorSeeding;

/// Which side of the blob format a call is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Wrap,
    Unwrap,
}

impl Direction {
    /// c2's `Literal["wrap", "unwrap"]` token (used verbatim in messages).
    fn as_str(self) -> &'static str {
        match self {
            Direction::Wrap => "wrap",
            Direction::Unwrap => "unwrap",
        }
    }
}

/// One row of the §5.4/§5.6 wrap-mechanism table; `spec` is a synthetic OperationSpec
/// (id "load.unwrap.<cli>") read only for id + params by ParamResolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapMechEntry {
    pub spec: OperationSpec,
    pub kek_algorithm: KeyAlgorithm,
    pub unwrap_kek_class: KeyClass,
    pub wrap_kek_classes: BTreeSet<KeyClass>,
    pub result_classes: BTreeSet<KeyClass>,
}

/// The KEK classes usable in this direction (c2 `WrapMechEntry.kek_classes`).
fn kek_classes(entry: &WrapMechEntry, direction: Direction) -> BTreeSet<KeyClass> {
    match direction {
        Direction::Wrap => entry.wrap_kek_classes.clone(),
        Direction::Unwrap => BTreeSet::from([entry.unwrap_kek_class]),
    }
}

const PADDINGS: [&str; 2] = ["none", "pkcs7"];
const TAG_BITS: [&str; 5] = ["128", "120", "112", "104", "96"];
const OAEP_HASHES: [&str; 4] = ["sha1", "sha256", "sha384", "sha512"];

/// ParamSpec shapes pinned to the §4.6 built-in rows (aes.encrypt.cbc/gcm,
/// rsa.encrypt.oaep) — the spec table is the contract.
fn cbc_params() -> Vec<ParamSpec> {
    vec![
        ParamSpec::new("iv", ParamKind::Bytes, "IV (16 bytes)").length(16),
        ParamSpec::new("padding", ParamKind::Enum, "Padding")
            .optional(Some(ParamValue::Enum("pkcs7".to_owned())))
            .choices(&PADDINGS),
    ]
}

fn gcm_params() -> Vec<ParamSpec> {
    vec![
        ParamSpec::new("iv", ParamKind::Bytes, "IV / nonce (12 bytes typical)"),
        ParamSpec::new(
            "aad",
            ParamKind::Bytes,
            "Additional authenticated data (empty for none)",
        )
        .optional(Some(ParamValue::Bytes(Vec::new()))),
        ParamSpec::new("tag_bits", ParamKind::Enum, "Tag length in bits")
            .optional(Some(ParamValue::Enum("128".to_owned())))
            .choices(&TAG_BITS),
    ]
}

fn oaep_params() -> Vec<ParamSpec> {
    vec![
        ParamSpec::new("hash", ParamKind::Enum, "Hash algorithm")
            .optional(Some(ParamValue::Enum("sha256".to_owned())))
            .choices(&OAEP_HASHES),
        ParamSpec::new(
            "mgf_hash",
            ParamKind::Enum,
            "MGF1 hash algorithm (defaults to hash)",
        )
        .optional(None)
        .default_from("hash")
        .choices(&OAEP_HASHES),
        ParamSpec::new("label", ParamKind::Bytes, "OAEP label (empty for none)")
            .optional(Some(ParamValue::Bytes(Vec::new()))),
    ]
}

/// One table row; the KEK classes follow from the algorithm (§4.3). AES: the same secret
/// key both ways. RSA: PRIVATE unwraps, PUBLIC (or a certificate) wraps.
fn entry(
    cli_name: &str,
    mechanism: &str,
    label: &str,
    params: Vec<ParamSpec>,
    kek_algorithm: KeyAlgorithm,
) -> WrapMechEntry {
    let symmetric = kek_algorithm == KeyAlgorithm::Aes;
    WrapMechEntry {
        spec: OperationSpec {
            id: format!("load.unwrap.{cli_name}"),
            verb: Verb::Decrypt, // unused — the resolver reads only id + params
            algorithm: kek_algorithm,
            key_classes: BTreeSet::new(),
            mechanism: mechanism.to_owned(),
            cli_name: cli_name.to_owned(),
            label: label.to_owned(),
            params,
            provider_types: None,
            providers: None,
            curves: None,
            raw_ckm: None,
            param_struct: ParamStruct::None,
        },
        kek_algorithm,
        unwrap_kek_class: if symmetric {
            KeyClass::Secret
        } else {
            KeyClass::Private
        },
        wrap_kek_classes: if symmetric {
            BTreeSet::from([KeyClass::Secret])
        } else {
            BTreeSet::from([KeyClass::Public, KeyClass::Certificate])
        },
        result_classes: BTreeSet::from([KeyClass::Secret, KeyClass::Private]),
    }
}

/// The table in menu order: kw, kwp, cbc, gcm, oaep, pkcs1.
pub fn wrap_mechs() -> Vec<WrapMechEntry> {
    vec![
        entry(
            "kw",
            mechanism::AES_KEY_WRAP,
            "AES key wrap (RFC 3394)",
            Vec::new(),
            KeyAlgorithm::Aes,
        ),
        entry(
            "kwp",
            mechanism::AES_KEY_WRAP_PAD,
            "AES key wrap with padding (RFC 5649)",
            Vec::new(),
            KeyAlgorithm::Aes,
        ),
        entry(
            "cbc",
            mechanism::AES_CBC,
            "AES-CBC wrapped blob",
            cbc_params(),
            KeyAlgorithm::Aes,
        ),
        entry(
            "gcm",
            mechanism::AES_GCM,
            "AES-GCM wrapped blob (ct‖tag)",
            gcm_params(),
            KeyAlgorithm::Aes,
        ),
        entry(
            "oaep",
            mechanism::RSA_OAEP,
            "RSA-OAEP wrapped blob",
            oaep_params(),
            KeyAlgorithm::Rsa,
        ),
        entry(
            "pkcs1",
            mechanism::RSA_PKCS1,
            "RSA PKCS#1 v1.5 wrapped blob",
            Vec::new(),
            KeyAlgorithm::Rsa,
        ),
    ]
}

/// "aes" → (Aes, Secret), "generic" → (Generic, Secret), "rsa" → (Rsa, Private),
/// "ec" → (Ec, Private); anything else None.
pub fn result_by_hint(hint: &str) -> Option<(KeyAlgorithm, KeyClass)> {
    match hint {
        "aes" => Some((KeyAlgorithm::Aes, KeyClass::Secret)),
        "generic" => Some((KeyAlgorithm::Generic, KeyClass::Secret)),
        "rsa" => Some((KeyAlgorithm::Rsa, KeyClass::Private)),
        "ec" => Some((KeyAlgorithm::Ec, KeyClass::Private)),
        _ => None,
    }
}

/// The general KEK-requirements line per direction (c2 `_KEK_REQUIREMENTS_HINT`).
fn requirements_hint(direction: Direction) -> &'static str {
    match direction {
        Direction::Unwrap => {
            "AES secret KEKs unwrap via kw/kwp/cbc/gcm; RSA private KEKs via oaep/pkcs1"
        }
        Direction::Wrap => {
            "AES secret KEKs wrap via kw/kwp/cbc/gcm; RSA wraps with the PUBLIC half — \
             select it explicitly, e.g. `--kek <label>:pub` (a certificate also works)"
        }
    }
}

const KEK_GRAMMAR_HINT: &str = "expected <label>[#<id-hex>][:<class>]";

// ---------------------------------------------------------------------------------------
// KEK resolution (§5.4: the KEK lives INSIDE the target provider)
// ---------------------------------------------------------------------------------------

/// Resolve `--kek` inside the provider holding (or receiving) the key. The token is a
/// label with optional §4.3 selectors, parsed by prefixing that provider onto `parse_ref`
/// — never a second parser. A token that already names a REGISTERED provider is accepted
/// when it is the same one and refused otherwise; anything else keeps its ':' as part of
/// the label. KeyNotFound/AmbiguousKey from find_key propagate untouched; a bare keypair
/// label resolves to the PRIVATE half via the find_key class preference. `direction` only
/// shapes the cross-provider refusal wording.
pub fn resolve_kek(
    registry: &ProviderRegistry,
    provider: &dyn Provider,
    token: &str,
    direction: Direction,
) -> r2_core::Result<KeyInfo> {
    let text = py_strip(token);
    if text.is_empty() {
        return Err(ConsoleError::param("KEK must not be empty", "kek").with_hint(KEK_GRAMMAR_HINT));
    }
    let parsed = parse_kek(registry, provider, text, direction)?;
    provider.find_key(&KeySelector::from(&parsed))
}

fn parse_kek(
    registry: &ProviderRegistry,
    provider: &dyn Provider,
    text: &str,
    direction: Direction,
) -> r2_core::Result<ParsedRef> {
    if let Ok(as_ref) = parse_ref(text)
        && is_registered(registry, &as_ref.provider)
    {
        if as_ref.provider != provider.name() {
            let (verb, call) = match direction {
                Direction::Wrap => ("export", "C_WrapKey"),
                Direction::Unwrap => ("load", "C_UnwrapKey"),
            };
            return Err(ConsoleError::param(
                format!(
                    "KEK '{text}' is on provider '{}' but the {verb} targets '{}'",
                    as_ref.provider,
                    provider.name()
                ),
                "kek",
            )
            .with_hint(format!(
                "the KEK must already live in that provider ({call} semantics) — `copy \
                 {text} {}` first",
                provider.name()
            )));
        }
        return Ok(as_ref);
    }
    parse_ref(&format!("{}:{text}", provider.name())).map_err(|exc| {
        ConsoleError::param(
            format!("invalid KEK reference {}: {}", py_repr(text), exc.message),
            "kek",
        )
        .with_hint(KEK_GRAMMAR_HINT)
    })
}

fn is_registered(registry: &ProviderRegistry, name: &str) -> bool {
    // ProviderRegistry::get fails only with ProviderNotFound (c2 catches exactly that)
    registry.get(name).is_ok()
}

// ---------------------------------------------------------------------------------------
// mechanism selection (§5.1 pattern: explicit --mech or select() fallback)
// ---------------------------------------------------------------------------------------

/// Table entries usable with this KEK on this provider, in menu order.
pub fn candidates(
    kek: &KeyInfo,
    provider: &dyn Provider,
    direction: Direction,
) -> Vec<WrapMechEntry> {
    let available = provider.mechanisms();
    wrap_mechs()
        .into_iter()
        .filter(|entry| {
            kek.algorithm == entry.kek_algorithm
                && kek_classes(entry, direction).contains(&kek.key_class)
                && available.contains(&entry.spec.mechanism)
        })
        .collect()
}

/// `--mech`: `text::py_strip(name).to_lowercase()` equals a cli_name or a lower-cased
/// canonical mechanism name (so "AES-KEY-WRAP" works). Unknown → Param "unknown wrap
/// mechanism {name!r}" (hint "did you mean: {close_matches(py_strip(name), cli names then
/// canonical names, 3) joined ', '}?" or "valid mechanisms: {cli names}"); not advertised →
/// UnsupportedOperation; wrong KEK → Param "{mechanism} {direction} needs a {classes} …",
/// where {classes} are the wanted class tokens sorted by `as_str()` and joined " or "
/// (e.g. "certificate or public" — c2 `sorted(c.value …)`, §4.3 note). c2 texts verbatim.
pub fn resolve_mech(
    name: &str,
    kek: &KeyInfo,
    provider: &dyn Provider,
    direction: Direction,
) -> r2_core::Result<WrapMechEntry> {
    let table = wrap_mechs();
    let text = py_strip(name).to_lowercase();
    let Some(entry) = table
        .iter()
        .find(|e| e.spec.cli_name == text || e.spec.mechanism.to_lowercase() == text)
    else {
        let valid: Vec<&str> = table
            .iter()
            .map(|e| e.spec.cli_name.as_str())
            .chain(table.iter().map(|e| e.spec.mechanism.as_str()))
            .collect();
        let close = close_matches(py_strip(name), &valid, 3);
        let hint = if close.is_empty() {
            format!(
                "valid mechanisms: {}",
                table
                    .iter()
                    .map(|e| e.spec.cli_name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            format!("did you mean: {}?", close.join(", "))
        };
        return Err(ConsoleError::param(
            format!("unknown wrap mechanism {}", py_repr(name)),
            "mech",
        )
        .with_hint(hint));
    };
    if !provider.supports(&entry.spec.mechanism) {
        return Err(ConsoleError::unsupported(format!(
            "provider '{}' does not advertise {}",
            provider.name(),
            entry.spec.mechanism
        ))
        .with_hint(
            "wrap support varies by token and login state — omit --mech to pick from what \
             is available",
        ));
    }
    let wanted = kek_classes(entry, direction);
    if kek.algorithm != entry.kek_algorithm || !wanted.contains(&kek.key_class) {
        let mut tokens: Vec<&str> = wanted.iter().map(|c| c.as_str()).collect();
        tokens.sort_unstable();
        return Err(ConsoleError::param(
            format!(
                "{} {} needs a {} {} KEK; '{}' is a {} {} key",
                entry.spec.mechanism,
                direction.as_str(),
                tokens.join(" or "),
                entry.kek_algorithm.as_str(),
                kek.key_ref.display(),
                kek.key_class.as_str(),
                kek.algorithm.as_str()
            ),
            "mech",
        )
        .with_hint(kek_hint(kek, entry, direction)));
    }
    Ok(entry.clone())
}

/// The general requirements line, or the exact fix when we can name it.
fn kek_hint(kek: &KeyInfo, entry: &WrapMechEntry, direction: Direction) -> String {
    if direction == Direction::Wrap
        && kek.algorithm == entry.kek_algorithm
        && kek.key_class == KeyClass::Private
    {
        // A bare keypair label collapses to the PRIVATE half (§4.3 class preference) —
        // wrapping needs the public one, named explicitly.
        return format!(
            "wrapping uses the public half: `--kek {}:pub`",
            kek.key_ref.label
        );
    }
    requirements_hint(direction).to_owned()
}

/// §5.1 interactive fallback: `select()` over the KEK's candidates.
pub fn select_mech(
    io: &dyn ConsoleIo,
    kek: &KeyInfo,
    provider: &dyn Provider,
    direction: Direction,
) -> r2_core::Result<WrapMechEntry> {
    let mut entries = candidates(kek, provider, direction);
    if entries.is_empty() {
        return Err(ConsoleError::unsupported(format!(
            "no {} mechanisms available for KEK {} ({} {}) on {}",
            direction.as_str(),
            kek.key_ref.display(),
            kek.key_class.as_str(),
            kek.algorithm.as_str(),
            provider.name()
        ))
        .with_hint(requirements_hint(direction)));
    }
    let options: Vec<String> = entries
        .iter()
        .map(|entry| format!("{} — {}", entry.spec.cli_name, entry.spec.label))
        .collect();
    let index = io
        .select(
            &format!("Select wrap mechanism for KEK {}", kek.key_ref.display()),
            &options,
        )
        .map_err(|err| {
            if err.kind.is_user_abort() {
                ConsoleError::user_abort("aborted while selecting a wrap mechanism")
            } else {
                err
            }
        })?;
    if index >= entries.len() {
        return Err(ConsoleError::generic(format!(
            "invalid selection {index} for {} options",
            entries.len()
        )));
    }
    Ok(entries.swap_remove(index))
}

// ---------------------------------------------------------------------------------------
// unwrap orchestration
// ---------------------------------------------------------------------------------------

/// What `load --kek` unwraps.
pub struct UnwrapJob<'a> {
    pub kek: &'a KeyInfo,
    pub entry: &'a WrapMechEntry,
    pub params: Params,
    pub wrapped: &'a [u8],
    pub result_algorithm: KeyAlgorithm,
    pub result_class: KeyClass,
    pub label: String,
    pub key_id: Option<Vec<u8>>,
}

/// Unwrap the blob with the resident KEK into a new provider object. PKCS#11 targets get
/// the §5.12 editor first, seeded from the RESULT's class/algorithm via
/// `templatefile::build_seed` (§5.16 `--template` section when given, else the config
/// defaults); the edited template rides into `unwrap_key`. Returns the new KeyInfo.
pub fn load_wrapped(
    provider: &dyn Provider,
    job: UnwrapJob<'_>,
    seeding: &EditorSeeding<'_>,
) -> r2_core::Result<KeyInfo> {
    if !job.entry.result_classes.contains(&job.result_class) {
        return Err(ConsoleError::unsupported(format!(
            "{} cannot unwrap a {} key",
            job.entry.spec.mechanism,
            job.result_class.as_str()
        )));
    }
    let template = if provider.type_name() == "pkcs11" {
        Some(seeding.edit(
            job.result_class,
            job.result_algorithm,
            &format!(
                "PKCS#11 template — {} {} '{}'",
                job.result_algorithm.as_str(),
                job.result_class.as_str(),
                job.label
            ),
        )?)
    } else {
        None
    };
    let mech = MechanismInvocation::new(job.entry.spec.mechanism.clone(), job.params);
    let mut request = UnwrapRequest::new(job.result_algorithm, job.result_class, job.label);
    request.key_id = job.key_id;
    request.template = template;
    // §11 D13: a Ctrl-C raised while the editor was open (plain IO swallows SIGINT) must
    // never be followed by C_UnwrapKey.
    r2_core::runtime::check_interrupt()?;
    let info = provider.unwrap_key(job.kek, &mech, job.wrapped, &request)?;
    tracing::info!(
        "loaded wrapped {}-byte blob into {} via {} (KEK {})",
        job.wrapped.len(),
        info.key_ref.display(),
        job.entry.spec.mechanism,
        job.kek.key_ref.display()
    );
    Ok(info)
}

// ---------------------------------------------------------------------------------------
// wrap orchestration (§5.6 `export --kek`)
// ---------------------------------------------------------------------------------------

/// §5.5/§5.6 wrappability pre-flight — refuse before the token is asked. Callers run this
/// BEFORE the mechanism menu and any parameter prompt. Wrappable = CKA_EXTRACTABLE ALONE
/// (deliberately not `KeyInfo.exportable`): a sensitive-but-extractable key may leave the
/// token wrapped. Providers with no attribute view pass.
pub fn refuse_non_wrappable(key: &KeyInfo) -> r2_core::Result<()> {
    if !matches!(key.key_class, KeyClass::Secret | KeyClass::Private) {
        return Err(ConsoleError::unsupported(format!(
            "only secret and private keys are wrapped; '{}' is a {} object",
            key.key_ref.display(),
            key.key_class.as_str()
        ))
        .with_hint(
            "public keys, certificates and data objects export as plain material — drop --kek",
        ));
    }
    if key.algorithm == KeyAlgorithm::Other {
        let key_type = key
            .attributes
            .get("CKA_KEY_TYPE")
            .map_or_else(|| "unknown".to_owned(), AttrValue::render_info);
        return Err(ConsoleError::unsupported(format!(
            "key type {key_type} of '{}' is not supported by r2 and cannot be wrapped",
            key.key_ref.display()
        ))
        .with_hint("objects of unsupported key types can be listed and deleted only"));
    }
    if key.attributes.get("CKA_EXTRACTABLE") == Some(&AttrValue::Bool(false)) {
        return Err(ConsoleError::key_not_exportable(format!(
            "key '{}' is not extractable and cannot be wrapped",
            key.key_ref.display()
        ))
        .with_hint("CKA_EXTRACTABLE=false forbids the key leaving the token in any form"));
    }
    Ok(())
}

/// Wrap `key` under the resident `kek` and return the blob (§5.6) — exactly what
/// `load --kek` consumes: raw key bytes for secrets, unencrypted PKCS#8 DER for private
/// keys. The refusals repeat here so the service stays self-contained.
pub fn wrap_for_export(
    provider: &dyn Provider,
    kek: &KeyInfo,
    entry: &WrapMechEntry,
    params: Params,
    key: &KeyInfo,
) -> r2_core::Result<Vec<u8>> {
    refuse_non_wrappable(key)?;
    if !entry.result_classes.contains(&key.key_class) {
        return Err(ConsoleError::unsupported(format!(
            "{} cannot wrap a {} key",
            entry.spec.mechanism,
            key.key_class.as_str()
        )));
    }
    let mech = MechanismInvocation::new(entry.spec.mechanism.clone(), params);
    let blob = provider.wrap_key(kek, &mech, key, &WrapOptions::default())?;
    tracing::info!(
        "wrapped {} under {} via {} ({}-byte blob)",
        key.key_ref.display(),
        kek.key_ref.display(),
        entry.spec.mechanism,
        blob.len()
    );
    Ok(blob)
}
