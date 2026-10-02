// `encrypt` / `decrypt` / `sign` / `verify` / `derive` / `ops` (spec §5.1; owner R9) — the
// port of c2 `console/commands/crypto_cmd.py`.
//
// One-line syntax with interactive fallbacks, all through ParamResolver/ConsoleIo (§5.1 —
// never a second code path): omitted `<mech>` → `select()` over `available_for(verb, key,
// provider)`; missing `name=value` params → prompted in ParamSpec order; omitted `<data>`
// with no `--in` → multiline paste prompt. Positional disambiguation (§5.1): positional 1
// must parse as a key ref; positional 2 is a mechanism iff it is UNQUOTED
// (`BoundArgs::positional_quoted`) and matches `resolve_cli()` for that key, else it is
// data — quoting data forces it as data.
//
// Results default to a hex dump panel on the console (`ui.hex_group` / `ui.hex_width`,
// applied by the IO at render time); `--out` writes raw bytes unless `--outformat hex|b64`
// is given. Payload bytes travel through `r2_core::datainput` (§4.4). Commands return
// errors, never print them (§4.2).
//
// The `ops` table: the OperationRegistry deliberately has no global enumeration surface
// (§4.6), so the per-provider table is assembled by probing `available_for()` with one
// representative synthetic key per (algorithm, key class, curve) family — which also makes
// the table honor `provider.mechanisms()` (empty while a PKCS#11 provider is logged out).
use std::collections::BTreeMap;
use std::rc::Rc;

use r2_core::datainput::{DataInput, DataOutput, InFormat, OutFormat};
use r2_core::error::{ConsoleError, ErrorKind};
use r2_core::io::{Renderable, Span, Tone, busy_with, hex, table};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyRef, parse_ref};
use r2_core::params::{Params, Verb};
use r2_core::runtime::check_interrupt;
use r2_core::text::py_path;
use r2_ops::{OperationSpec, ParamResolver};
use r2_provider::{AuthState, KeySelector, MechanismInvocation, Provider};
use zeroize::Zeroizing;

use crate::cmdutil::{completed_args, previous_token};
use crate::commands::Command;
use crate::completer::{browsable, complete_paths, complete_provider_names, complete_refs};
use crate::context::AppContext;
use crate::parser::BoundArgs;
use crate::repl::Flow;

/// The `--outformat` tokens (c2 `_OUT_FORMATS`).
const OUT_FORMATS: [&str; 3] = ["raw", "hex", "b64"];
/// Options whose value is a filesystem path → PathCompleter rule (§5.1).
const PATH_OPTIONS: [&str; 3] = ["in", "out", "sig-file"];
/// The prompt of an omitted payload.
const DATA_PROMPT: &str = "Data (hex, base64 or PEM)";

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

/// c2 `_check_options`: the first `--option` not in `allowed` → Generic "unknown option
/// --{name}" (hint "usage: {usage}").
fn check_options(args: &BoundArgs, allowed: &[&str], usage: &str) -> r2_core::Result<()> {
    match args
        .options
        .keys()
        .find(|name| !allowed.contains(&name.as_str()))
    {
        Some(name) => Err(ConsoleError::generic(format!("unknown option --{name}"))
            .with_hint(format!("usage: {usage}"))),
        None => Ok(()),
    }
}

/// §5.1: `verify` on a private-key ref uses the co-located public half (c2
/// `_public_half_for_verify`, the L13 fold-back).
///
/// An unqualified ref to a keypair resolves to the PRIVATE half (class preference, §4.5)
/// while verify specs carry `key_classes = {PUBLIC, CERTIFICATE}` (§4.6) — so a PRIVATE
/// resolution falls back to the PUBLIC (preferred) or CERTIFICATE object with the same
/// label (and id, when the ref carried one). Operators can also target the half directly
/// with the §4.3 `:pub`/`:cert` selector. No match → the private key is kept and the
/// ordinary capability errors apply.
pub(crate) fn public_half_for_verify(
    provider: &dyn Provider,
    key: KeyInfo,
) -> r2_core::Result<KeyInfo> {
    if key.key_class != KeyClass::Private {
        return Ok(key);
    }
    let candidates: Vec<KeyInfo> = provider
        .list_keys()?
        .into_iter()
        .filter(|info| {
            info.key_ref.label == key.key_ref.label
                && matches!(info.key_class, KeyClass::Public | KeyClass::Certificate)
                && (key.key_ref.key_id.is_none() || info.key_ref.key_id == key.key_ref.key_id)
        })
        .collect();
    for wanted in [KeyClass::Public, KeyClass::Certificate] {
        if let Some(info) = candidates.iter().find(|info| info.key_class == wanted) {
            return Ok(info.clone());
        }
    }
    Ok(key)
}

/// The resolved positionals of a crypto verb (c2 `_operation`'s tuple).
struct Operation<'a> {
    provider: Rc<dyn Provider>,
    key: KeyInfo,
    /// None = the mechanism was omitted (callers fall back to `select()`).
    spec: Option<&'a OperationSpec>,
    /// The positionals after the key ref (and the mechanism, when one bound). Zeroized on
    /// drop: the inline data token may be plaintext to encrypt or sign.
    rest: Zeroizing<Vec<String>>,
}

/// Resolve positional 1 (key ref) and the §5.1 mech-vs-data positional 2 (c2 `_operation`).
fn operation<'a>(
    ctx: &'a AppContext,
    verb: Verb,
    args: &BoundArgs,
    usage: &str,
) -> r2_core::Result<Operation<'a>> {
    let Some(reference) = args.positionals.first() else {
        return Err(
            ConsoleError::generic("missing key reference").with_hint(format!("usage: {usage}"))
        );
    };
    let (provider, mut key) = ctx.providers.resolve_ref(reference)?;
    if verb == Verb::Verify {
        key = public_half_for_verify(provider.as_ref(), key)?;
    }
    let mut rest = Zeroizing::new(args.positionals[1..].to_vec());
    let mut spec = None;
    if !rest.is_empty() && !args.positional_quoted.get(1).copied().unwrap_or(false) {
        match ctx.operations.resolve_cli(verb, &key, &rest[0]) {
            Ok(found) => {
                spec = Some(found);
                rest.remove(0);
            }
            // not a mechanism for this key → it is data (§5.1)
            Err(err) if err.kind == ErrorKind::UnknownOperation => {}
            Err(err) => return Err(err),
        }
    }
    Ok(Operation {
        provider,
        key,
        spec,
        rest,
    })
}

/// §5.1 interactive fallback: `select()` over `available_for()`, sorted by (cli_name, id)
/// (§4.6.2 presentation order), options "{cli_name} — {label}".
fn select_mechanism<'a>(
    ctx: &'a AppContext,
    verb: Verb,
    key: &KeyInfo,
    provider: &dyn Provider,
) -> r2_core::Result<&'a OperationSpec> {
    let mut specs = ctx.operations.available_for(verb, key, provider);
    specs.sort_by(|a, b| (&a.cli_name, &a.id).cmp(&(&b.cli_name, &b.id)));
    if specs.is_empty() {
        return Err(ConsoleError::unsupported(format!(
            "no {} operations available for {}",
            verb.as_str(),
            key.key_ref.display()
        ))
        .with_hint(format!(
            "see `ops {}` — support depends on the provider capabilities and login state",
            provider.name()
        )));
    }
    let options: Vec<String> = specs
        .iter()
        .map(|spec| format!("{} — {}", spec.cli_name, spec.label))
        .collect();
    let title = format!(
        "Select {} mechanism for {}",
        verb.as_str(),
        key.key_ref.display()
    );
    let index = ctx.io.select(&title, &options)?;
    specs
        .get(index)
        .copied()
        .ok_or_else(|| ConsoleError::generic(format!("invalid selection {index} for: {title}")))
}

/// §5.1: omitted payload → multiline paste prompt, decoded via §4.4.
fn prompt_bytes(ctx: &AppContext, prompt: &str) -> r2_core::Result<Zeroizing<Vec<u8>>> {
    let text = Zeroizing::new(ctx.io.prompt_multiline(prompt)?);
    DataInput::inline(text.as_str()).resolve()
}

/// The payload: inline data token, `--in <path>`, or the paste prompt (c2 `_payload`).
fn payload(
    ctx: &AppContext,
    args: &BoundArgs,
    rest: &[String],
    prompt: &str,
) -> r2_core::Result<Zeroizing<Vec<u8>>> {
    let inline = rest.first();
    let in_path = args.opt("in");
    match (inline, in_path) {
        (Some(_), Some(_)) => Err(ConsoleError::generic(
            "give the data inline or with --in, not both",
        )
        .with_hint("remove the inline data token or the --in option")),
        (Some(token), None) => DataInput::inline(token.as_str()).resolve(),
        (None, Some(path)) => DataInput::file(py_path(path), InFormat::Auto).resolve(),
        (None, None) => prompt_bytes(ctx, prompt),
    }
}

/// `--out`/`--outformat` → DataOutput; None = console hex panel (c2 `_make_output`).
fn make_output(args: &BoundArgs) -> r2_core::Result<Option<DataOutput>> {
    let out = args.opt("out");
    let fmt = args.opt("outformat");
    if let Some(fmt) = fmt
        && !OUT_FORMATS.contains(&fmt)
    {
        return Err(
            ConsoleError::generic(format!("invalid --outformat '{fmt}'"))
                .with_hint("choose one of: raw, hex, b64"),
        );
    }
    let Some(out) = out else {
        if fmt.is_some() {
            return Err(ConsoleError::generic("--outformat requires --out")
                .with_hint("console output is always the grouped hex dump (§5.1)"));
        }
        return Ok(None);
    };
    let fmt: OutFormat = fmt.unwrap_or("raw").parse()?;
    Ok(Some(DataOutput::file(py_path(out), fmt)))
}

/// Console → hex panel titled `title`; file → write + "wrote {n} bytes to {path}".
fn emit(
    ctx: &AppContext,
    data: &[u8],
    output: Option<&DataOutput>,
    title: &str,
) -> r2_core::Result<()> {
    check_interrupt()?; // §11 D13: the flag is honored before writing output
    let Some(output) = output else {
        ctx.io.print(hex(data, Some(title)));
        return Ok(());
    };
    output.write(data, ctx.io.as_ref())?;
    let shown = output
        .path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    ctx.io.print(Renderable::Text(format!(
        "wrote {} bytes to {shown}",
        data.len()
    )));
    Ok(())
}

/// Ref resolution for completion — §6: never trigger a PKCS#11 library load; any error →
/// None (c2 `_completion_key`).
fn completion_key(ctx: &AppContext, reference: &str) -> Option<(Rc<dyn Provider>, KeyInfo)> {
    let parsed = parse_ref(reference).ok()?;
    let provider = ctx.providers.get(&parsed.provider).ok()?;
    if !browsable(provider.as_ref()) {
        return None;
    }
    let key = provider.find_key(&KeySelector::from(&parsed)).ok()?;
    Some((provider, key))
}

/// The provider verb inside the IO's busy section. §6: the idempotent
/// `Provider::initialize()` runs first, so no lazy initialization runs inside `busy()`.
/// §11 D13: the Ctrl-C flag is honored as soon as the provider verb returns, before any
/// result is rendered or written (c2's KeyboardInterrupt surfaced right after the C call).
fn busy<T>(
    ctx: &AppContext,
    provider: &dyn Provider,
    verb: Verb,
    mech: &MechanismInvocation,
    f: impl FnOnce() -> r2_core::Result<T>,
) -> r2_core::Result<T> {
    provider.initialize()?;
    let message = format!("{} — {}", verb.as_str(), mech.mechanism);
    let value = busy_with(ctx.io.as_ref(), &message, f)?;
    check_interrupt()?;
    Ok(value)
}

// ---------------------------------------------------------------------------
// crypto verb commands
// ---------------------------------------------------------------------------

/// The fully resolved invocation of a crypto verb (c2 `_resolve`'s tuple).
struct Resolved<'a> {
    provider: Rc<dyn Provider>,
    key: KeyInfo,
    spec: &'a OperationSpec,
    rest: Zeroizing<Vec<String>>,
    params: Params,
}

/// Shared §5.1 skeleton of the five crypto verbs (c2 `_CryptoVerbCommand`).
struct VerbShape {
    name: &'static str,
    verb: Verb,
    usage: &'static str,
    /// Sorted (c2 iterates `sorted(self.options)` for completion).
    options: &'static [&'static str],
    takes_data: bool,
}

impl VerbShape {
    /// Options check → key/mech resolution → ParamResolver (§4.6).
    fn resolve<'a>(&self, ctx: &'a AppContext, args: &BoundArgs) -> r2_core::Result<Resolved<'a>> {
        check_options(args, self.options, self.usage)?;
        let Operation {
            provider,
            key,
            spec,
            rest,
        } = operation(ctx, self.verb, args, self.usage)?;
        if self.takes_data {
            if rest.len() > 1 {
                return Err(ConsoleError::generic(
                    "too many arguments: give at most one data value",
                )
                .with_hint(format!("usage: {}", self.usage)));
            }
        } else if !rest.is_empty() {
            return Err(
                ConsoleError::generic(format!("{} takes no data argument", self.name)).with_hint(
                    format!(
                        "{} inputs are name=value parameters — usage: {}",
                        self.name, self.usage
                    ),
                ),
            );
        }
        let spec = match spec {
            Some(spec) => spec,
            None => select_mechanism(ctx, self.verb, &key, provider.as_ref())?,
        };
        let params =
            ParamResolver::new(ctx.io.as_ref(), &ctx.providers).resolve(spec, &args.named)?;
        Ok(Resolved {
            provider,
            key,
            spec,
            rest,
            params,
        })
    }

    /// c2 `_CryptoVerbCommand.complete`.
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        if completed_args(tokens, cursor_token) == 0 {
            return complete_refs(ctx, cursor_token);
        }
        if let Some(option) =
            previous_token(tokens, cursor_token).and_then(|t| t.strip_prefix("--"))
        {
            if PATH_OPTIONS.contains(&option) && self.options.contains(&option) {
                return complete_paths(cursor_token); // §5.1 PathCompleter rule
            }
            return Vec::new(); // the value of a non-path --option (data) — no candidates
        }
        let option_names: Vec<String> = self
            .options
            .iter()
            .map(|name| format!("--{name}"))
            .collect();
        let Some((provider, key)) = tokens.get(1).and_then(|r| completion_key(ctx, r)) else {
            return option_names;
        };
        let key = if self.verb == Verb::Verify {
            // §5.1 fallback, as in run()
            match public_half_for_verify(provider.as_ref(), key) {
                Ok(key) => key,
                // c2: the ConsoleError leaves complete() and the completer yields nothing
                Err(_) => return Vec::new(),
            }
        } else {
            key
        };
        let specs = ctx
            .operations
            .available_for(self.verb, &key, provider.as_ref());
        let mut names: Vec<String> = if completed_args(tokens, cursor_token) == 1 {
            specs.iter().map(|spec| spec.cli_name.clone()).collect()
        } else {
            let chosen: Vec<&&OperationSpec> = specs
                .iter()
                .filter(|spec| tokens.get(2).is_some_and(|mech| spec.cli_name == *mech))
                .collect();
            let pool: Vec<&&OperationSpec> = if chosen.is_empty() {
                specs.iter().collect()
            } else {
                chosen
            };
            pool.iter()
                .flat_map(|spec| spec.params.iter().map(|param| format!("{}=", param.name)))
                .collect()
        };
        names.sort();
        names.dedup();
        names.extend(option_names);
        names
    }
}

/// encrypt / decrypt / sign: payload in, bytes out (c2 `_DataResultCommand`).
#[derive(Clone, Copy)]
enum DataVerb {
    Encrypt,
    Decrypt,
    Sign,
}

const DATA_RESULT_OPTIONS: &[&str] = &["in", "out", "outformat"];

struct DataResultCommand {
    kind: DataVerb,
}

impl DataResultCommand {
    fn shape(&self) -> VerbShape {
        let (name, verb, usage) = match self.kind {
            DataVerb::Encrypt => (
                "encrypt",
                Verb::Encrypt,
                "encrypt <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>] [--out <path>] [--outformat raw|hex|b64]",
            ),
            DataVerb::Decrypt => (
                "decrypt",
                Verb::Decrypt,
                "decrypt <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>] [--out <path>] [--outformat raw|hex|b64]",
            ),
            DataVerb::Sign => (
                "sign",
                Verb::Sign,
                "sign <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>] [--out <path>] [--outformat raw|hex|b64]",
            ),
        };
        VerbShape {
            name,
            verb,
            usage,
            options: DATA_RESULT_OPTIONS,
            takes_data: true,
        }
    }

    fn result_title(&self) -> &'static str {
        match self.kind {
            DataVerb::Encrypt => "ciphertext",
            DataVerb::Decrypt => "plaintext",
            DataVerb::Sign => "signature",
        }
    }
}

impl Command for DataResultCommand {
    fn name(&self) -> &'static str {
        self.shape().name
    }
    fn summary(&self) -> &'static str {
        match self.kind {
            DataVerb::Encrypt => "Encrypt data with a key (mechanism prompted when omitted)",
            DataVerb::Decrypt => "Decrypt data with a key (mechanism prompted when omitted)",
            DataVerb::Sign => "Sign data or compute a MAC (mechanism prompted when omitted)",
        }
    }
    fn usage(&self) -> &'static str {
        self.shape().usage
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        let shape = self.shape();
        let output = make_output(args)?;
        let Resolved {
            provider,
            key,
            spec,
            rest,
            params,
        } = shape.resolve(ctx, args)?;
        let data = payload(ctx, args, &rest, DATA_PROMPT)?;
        let mech = spec.invocation(params);
        let result: Zeroizing<Vec<u8>> = busy(ctx, provider.as_ref(), shape.verb, &mech, || {
            match self.kind {
                DataVerb::Encrypt => provider.encrypt(&key, &mech, &data).map(Zeroizing::new),
                DataVerb::Decrypt => provider.decrypt(&key, &mech, &data),
                DataVerb::Sign => provider.sign(&key, &mech, &data).map(Zeroizing::new),
            }
        })?;
        let title = format!("{} — {}", self.result_title(), spec.mechanism);
        emit(ctx, &result, output.as_ref(), &title)?;
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        self.shape().complete(ctx, tokens, cursor_token)
    }
}

struct VerifyCommand;

impl VerifyCommand {
    const SHAPE: VerbShape = VerbShape {
        name: "verify",
        verb: Verb::Verify,
        usage: "verify <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>] (--sig <data> | --sig-file <path>)",
        options: &["in", "sig", "sig-file"],
        takes_data: true,
    };

    /// `--sig` | `--sig-file` | the prompt (c2 `VerifyCommand._signature`).
    fn signature(ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Zeroizing<Vec<u8>>> {
        match (args.opt("sig"), args.opt("sig-file")) {
            (Some(_), Some(_)) => Err(ConsoleError::generic(
                "give the signature with --sig or --sig-file, not both",
            )
            .with_hint("remove one of the two options")),
            (Some(inline), None) => DataInput::inline(inline).resolve(),
            (None, Some(path)) => DataInput::file(py_path(path), InFormat::Auto).resolve(),
            (None, None) => prompt_bytes(ctx, "Signature (hex or base64)"),
        }
    }
}

impl Command for VerifyCommand {
    fn name(&self) -> &'static str {
        Self::SHAPE.name
    }
    fn summary(&self) -> &'static str {
        "Verify a signature or MAC over data"
    }
    fn usage(&self) -> &'static str {
        Self::SHAPE.usage
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        let Resolved {
            provider,
            key,
            spec,
            rest,
            params,
        } = Self::SHAPE.resolve(ctx, args)?;
        let data = payload(ctx, args, &rest, DATA_PROMPT)?;
        let signature = Self::signature(ctx, args)?;
        let mech = spec.invocation(params);
        let ok = busy(ctx, provider.as_ref(), Verb::Verify, &mech, || {
            provider.verify(&key, &mech, &data, &signature)
        })?;
        let (text, tone) = if ok {
            ("signature VALID", Tone::Success)
        } else {
            ("signature INVALID", Tone::Error)
        };
        ctx.io.print(Renderable::Styled(vec![vec![Span {
            text: text.to_owned(),
            tone,
        }]]));
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        Self::SHAPE.complete(ctx, tokens, cursor_token)
    }
}

struct DeriveCommand;

impl DeriveCommand {
    const SHAPE: VerbShape = VerbShape {
        name: "derive",
        verb: Verb::Derive,
        usage: "derive <provider>:<label> [<mech>] [<name>=<value> ...] [--out <path>] [--outformat raw|hex|b64]",
        options: &["out", "outformat"],
        takes_data: false,
    };
}

impl Command for DeriveCommand {
    fn name(&self) -> &'static str {
        Self::SHAPE.name
    }
    fn summary(&self) -> &'static str {
        "Derive a shared secret (ECDH / X25519 / X448)"
    }
    fn usage(&self) -> &'static str {
        Self::SHAPE.usage
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        let output = make_output(args)?;
        let Resolved {
            provider,
            key,
            spec,
            params,
            ..
        } = Self::SHAPE.resolve(ctx, args)?;
        let mech = spec.invocation(params);
        let result = busy(ctx, provider.as_ref(), Verb::Derive, &mech, || {
            provider.derive(&key, &mech)
        })?;
        if let Some(raw) = &result.raw {
            let title = format!("derived secret — {}", spec.mechanism);
            emit(ctx, raw, output.as_ref(), &title)?;
        } else if let Some(resident) = &result.key {
            // §5.10: tokens that forbid extractable secrets return key-only — render the
            // resident-key ref instead of raw bytes.
            if output.is_some() {
                return Err(ConsoleError::generic(
                    "derived key is provider-resident — there is no raw secret to write",
                )
                .with_hint(format!("result key: {}", resident.key_ref.display())));
            }
            ctx.io.print(Renderable::Text(format!(
                "derived key (provider-resident): {}",
                resident.key_ref.display()
            )));
        } else {
            return Err(ConsoleError::crypto(
                "derive returned neither a raw secret nor a provider-resident key",
            ));
        }
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        Self::SHAPE.complete(ctx, tokens, cursor_token)
    }
}

// ---------------------------------------------------------------------------
// ops
// ---------------------------------------------------------------------------

/// One representative curve per name family (§5.3 curve list) — enough for the builtin
/// `curves` filters (x25519/x448) and custom per-curve restrictions (c2 `_PROBE_FAMILIES`).
fn probe_families() -> [(KeyAlgorithm, Vec<Option<Curve>>); 6] {
    [
        (KeyAlgorithm::Aes, vec![None]),
        (KeyAlgorithm::Generic, vec![None]),
        (KeyAlgorithm::Rsa, vec![None]),
        (
            KeyAlgorithm::Ec,
            vec![Some(Curve::P256), Some(Curve::P384), Some(Curve::P521)],
        ),
        (
            KeyAlgorithm::EcEdwards,
            vec![Some(Curve::Ed25519), Some(Curve::Ed448)],
        ),
        (
            KeyAlgorithm::EcMontgomery,
            vec![Some(Curve::X25519), Some(Curve::X448)],
        ),
    ]
}

/// Synthetic keys spanning every (algorithm, class, curve) family (c2 `_probe_keys`: the
/// registry has no enumeration surface, §4.6).
pub(crate) fn probe_keys(provider_name: &str) -> Vec<KeyInfo> {
    let key_ref = KeyRef::new(provider_name, "?", None);
    let mut probes = Vec::new();
    for (algorithm, curves) in probe_families() {
        let classes: &[KeyClass] = if matches!(algorithm, KeyAlgorithm::Aes | KeyAlgorithm::Generic)
        {
            &[KeyClass::Secret]
        } else {
            &[KeyClass::Private, KeyClass::Public]
        };
        for curve in curves {
            for &key_class in classes {
                probes.push(KeyInfo {
                    key_ref: key_ref.clone(),
                    key_class,
                    algorithm,
                    size_bits: None,
                    curve: curve.clone(),
                    exportable: true,
                    attributes: BTreeMap::new(),
                    handle: None,
                });
            }
        }
    }
    probes
}

/// `available_for` over every verb (`Verb::ALL` order) and every key, de-duplicated by id
/// (first occurrence wins), sorted by (verb declaration order, cli_name, id) (c2
/// `_merge_specs`, §4.6.2).
fn merge_specs<'a>(
    ctx: &'a AppContext,
    provider: &dyn Provider,
    keys: &[KeyInfo],
) -> Vec<&'a OperationSpec> {
    let mut merged: Vec<&OperationSpec> = Vec::new();
    for verb in Verb::ALL {
        for key in keys {
            for spec in ctx.operations.available_for(verb, key, provider) {
                if !merged.iter().any(|seen| seen.id == spec.id) {
                    merged.push(spec);
                }
            }
        }
    }
    merged.sort_by(|a, b| (a.verb, &a.cli_name, &a.id).cmp(&(b.verb, &b.cli_name, &b.id)));
    merged
}

const OPS_USAGE: &str = "ops [<provider>] [--key <provider>:<label>]";

struct OpsCommand;

impl OpsCommand {
    fn render(ctx: &AppContext, provider: &dyn Provider, specs: &[&OperationSpec], title: &str) {
        if specs.is_empty() {
            let note = if provider.status().auth == AuthState::LoggedOut {
                format!(" (logged out — run `login {}`)", provider.name())
            } else {
                String::new()
            };
            ctx.io.print(Renderable::Text(format!(
                "{}: no operations available{note}",
                provider.name()
            )));
            return;
        }
        let rows: Vec<Vec<String>> = specs
            .iter()
            .map(|spec| {
                let params: Vec<&str> = spec
                    .params
                    .iter()
                    .map(|param| param.name.as_str())
                    .collect();
                let params = if params.is_empty() {
                    "—".to_owned()
                } else {
                    params.join(", ")
                };
                vec![
                    spec.verb.as_str().to_owned(),
                    spec.cli_name.clone(),
                    spec.mechanism.clone(),
                    params,
                    spec.label.clone(),
                ]
            })
            .collect();
        ctx.io.print(table(
            Some(title),
            &["verb", "op", "mechanism", "params", "description"],
            rows,
        ));
    }
}

impl Command for OpsCommand {
    fn name(&self) -> &'static str {
        "ops"
    }
    fn summary(&self) -> &'static str {
        "List the operations each provider can perform right now"
    }
    fn usage(&self) -> &'static str {
        OPS_USAGE
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        check_options(args, &["key"], OPS_USAGE)?;
        if args.positionals.len() > 1 {
            return Err(ConsoleError::generic("too many arguments")
                .with_hint(format!("usage: {OPS_USAGE}")));
        }
        let provider_name = args.positionals.first();
        if let Some(key_ref) = args.opt("key") {
            let (provider, key) = ctx.providers.resolve_ref(key_ref)?;
            if let Some(name) = provider_name
                && name != provider.name()
            {
                return Err(ConsoleError::generic(format!(
                    "key {} does not live on provider '{name}'",
                    key.key_ref.display()
                ))
                .with_hint("omit the provider argument, or name the key's own provider"));
            }
            let specs = merge_specs(ctx, provider.as_ref(), std::slice::from_ref(&key));
            let title = format!("operations for {}", key.key_ref.display());
            Self::render(ctx, provider.as_ref(), &specs, &title);
            return Ok(Flow::Continue);
        }
        let providers = match provider_name {
            Some(name) => vec![ctx.providers.get(name)?],
            None => ctx.providers.all(),
        };
        for provider in providers {
            let specs = merge_specs(ctx, provider.as_ref(), &probe_keys(provider.name()));
            let title = format!("operations — {}", provider.name());
            Self::render(ctx, provider.as_ref(), &specs, &title);
        }
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        if previous_token(tokens, cursor_token) == Some("--key") {
            return complete_refs(ctx, cursor_token);
        }
        let mut candidates = vec!["--key".to_owned()];
        candidates.extend(complete_provider_names(ctx, cursor_token));
        candidates
    }
}

/// §4.9.6: every command module exports exactly this.
pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(DataResultCommand {
            kind: DataVerb::Encrypt,
        }),
        Box::new(DataResultCommand {
            kind: DataVerb::Decrypt,
        }),
        Box::new(DataResultCommand {
            kind: DataVerb::Sign,
        }),
        Box::new(VerifyCommand),
        Box::new(DeriveCommand),
        Box::new(OpsCommand),
    ]
}
