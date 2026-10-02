// `keys` / `key info|edit|template` / `generate` / `load` / `export` / `csr` / `delete`
// (spec §5.1, §5.3, §5.4, §5.6, §5.7, §5.15; owner R8) — port of c2
// `console/commands/keys_cmd.py`, minus the `--kek` paths (R15's `kek` hooks) and the
// `key template` body (R14's `key_template::run` hook).
//
// Commands return errors, never print them (§4.2). Template editing goes through the
// `ctx.template_editor` hook, seeded through `templatefile::build_seed` (the §4.8 default
// template, or with `--template` a §5.16 file section). Interactive fallbacks run through
// ParamResolver / ConsoleIo — never a second code path (§5.1).
use std::collections::{BTreeSet, HashMap};

use r2_core::codec::decode_data;
use r2_core::error::ConsoleError;
use r2_core::io::{Renderable, table};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, display_refs};
use r2_core::params::{ParamKind, ParamSpec, ParamStruct, ParamValue, Verb};
use r2_core::runtime::check_interrupt;
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_core::text::{py_fromhex, py_path, py_repr, py_strip};
use r2_core::x509info::certificate_details;
use r2_ops::{OperationSpec, ParamResolver};
use r2_provider::{AttrEditOutcome, AuthState, GenerateRequest, Provider};
use r2_services::templatefile::{EditorSeeding, build_seed};
use r2_services::{certops, keyexport, keyload};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::cmdutil::{
    completed_args, parse_key_id, parse_seed_templates, positional, previous_token, prompt_label,
    reject_named, require_usable,
};
use crate::commands::{Command, kek, key_template};
use crate::completer::{complete_paths, complete_provider_names, complete_refs};
use crate::context::AppContext;
use crate::parser::BoundArgs;
use crate::render::{algo_text, class_text};
use crate::repl::Flow;

/// §4.9.6: every command module exports exactly this.
pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(KeysCommand),
        Box::new(KeyCommand),
        Box::new(GenerateCommand),
        Box::new(LoadCommand),
        Box::new(ExportCommand),
        Box::new(CsrCommand),
        Box::new(DeleteCommand),
    ]
}

/// The keys-module reject_named noun (c2 keys_cmd `_reject_named`).
const NOUN: &str = "data";

const KEY_TABLE_COLUMNS: [&str; 5] = ["ref", "class", "algorithm", "size/curve", "exportable"];

/// §5.3 curve → KeyAlgorithm mapping (the curve implies the algorithm).
const CURVES: [&str; 7] = ["p256", "p384", "p521", "ed25519", "ed448", "x25519", "x448"];

/// `size=` completion suggestions for generic secrets (any multiple of 8 is legal).
const GENERIC_SIZE_SUGGESTIONS: [&str; 4] = ["128", "256", "384", "512"];

fn owned(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn text(ctx: &AppContext, line: String) {
    ctx.io.print(Renderable::Text(line));
}

/// A value-carrying option, treating an empty value like an absent one (c2 `_opt(..) or
/// default`).
fn opt_nonempty<'a>(args: &'a BoundArgs, name: &str) -> Option<&'a str> {
    args.opt(name).filter(|value| !value.is_empty())
}

// ---------------------------------------------------------------------------------------
// shared cell texts
// ---------------------------------------------------------------------------------------

fn size_or_curve(info: &KeyInfo) -> String {
    if let Some(bits) = info.size_bits {
        return bits.to_string();
    }
    match &info.curve {
        Some(curve) => curve.as_str().to_owned(),
        None => "-".to_owned(),
    }
}

fn key_row(ref_text: String, info: &KeyInfo) -> Vec<String> {
    vec![
        ref_text,
        class_text(info.key_class).to_owned(),
        algo_text(info).to_owned(),
        size_or_curve(info),
        if info.exportable { "yes" } else { "no" }.to_owned(),
    ]
}

/// A family-unambiguous object cell: display ref + class token (§4.3).
fn object_text(info: &KeyInfo) -> String {
    format!("{}:{}", info.key_ref.display(), info.key_class.token())
}

// ---------------------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------------------

struct KeysCommand;

impl Command for KeysCommand {
    fn name(&self) -> &'static str {
        "keys"
    }
    fn summary(&self) -> &'static str {
        "List keys and certificates (all providers or one), optionally filtered"
    }
    fn usage(&self) -> &'static str {
        "keys [<provider>] [<filter>]"
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        reject_named(args, self.usage(), NOUN)?;
        if let Some(extra) = args.positionals.get(2) {
            return Err(
                ConsoleError::generic(format!("unexpected argument {}", py_repr(extra)))
                    .with_hint(format!("usage: {}", self.usage())),
            );
        }
        let mut provider_name: Option<&str> = None;
        let mut ref_filter: Option<&str> = None;
        match args.positionals.as_slice() {
            [name, filter] => {
                provider_name = Some(name);
                ref_filter = Some(filter);
            }
            [token] => {
                // A lone argument naming a provider lists that provider; anything else
                // filters across all browsable providers (§5.1).
                if ctx.providers.all().iter().any(|p| p.name() == token) {
                    provider_name = Some(token);
                } else {
                    ref_filter = Some(token);
                }
            }
            _ => {}
        }

        let mut infos: Vec<KeyInfo> = Vec::new();
        let mut skipped: Vec<String> = Vec::new();
        if let Some(name) = provider_name {
            infos = ctx.providers.get(name)?.list_keys()?;
        } else {
            for provider in ctx.providers.all() {
                if provider.status().auth == AuthState::LoggedOut {
                    skipped.push(provider.name().to_owned()); // never force a library load
                    continue;
                }
                infos.extend(provider.list_keys()?);
            }
        }
        // display_refs suffixes colliding refs with :<class>/@<handle> (§4.3), so every
        // listed ref is unambiguous and pasteable; the filter matches the suffixed form.
        let mut pairs: Vec<(String, &KeyInfo)> =
            display_refs(&infos).into_iter().zip(infos.iter()).collect();
        if let Some(filter) = ref_filter {
            let needle = filter.to_lowercase();
            pairs.retain(|(text, _)| text.to_lowercase().contains(&needle));
        }
        let rows: Vec<Vec<String>> = pairs
            .into_iter()
            .map(|(text, info)| key_row(text, info))
            .collect();
        if !rows.is_empty() {
            ctx.io.print(table(Some("keys"), &KEY_TABLE_COLUMNS, rows));
        } else if let Some(filter) = ref_filter {
            text(ctx, format!("no keys match '{filter}'"));
        } else {
            text(ctx, "no keys".to_owned());
        }
        for name in skipped {
            text(
                ctx,
                format!("note: '{name}' is not logged in — run `login {name}` to list its keys"),
            );
        }
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        if completed_args(tokens, cursor_token) == 0 {
            return complete_provider_names(ctx, cursor_token);
        }
        Vec::new()
    }
}

// ---------------------------------------------------------------------------------------
// key info / edit / template
// ---------------------------------------------------------------------------------------

/// The `key` command's usage line (also quoted by `key template`, key_template.rs).
pub(crate) const KEY_USAGE: &str = "key info <provider>:<label>[#<id-hex>][:<class>]  |  key edit \
                         <provider>:<label>[#<id-hex>][:<class>] [--label <l>] [--id <hex>]  \
                         |  key template <provider>:<label>[#<id-hex>][:<class>] <path>";

struct KeyCommand;

impl Command for KeyCommand {
    fn name(&self) -> &'static str {
        "key"
    }
    fn summary(&self) -> &'static str {
        "Show details of one key, edit its attributes, or dump its template"
    }
    fn usage(&self) -> &'static str {
        KEY_USAGE
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        reject_named(args, KEY_USAGE, NOUN)?;
        match positional(args, 0, "subcommand", KEY_USAGE)? {
            "info" => run_info(ctx, args)?,
            "edit" => run_edit(ctx, args)?,
            "template" => key_template::run(ctx, args)?,
            sub => {
                return Err(
                    ConsoleError::generic(format!("unknown key subcommand '{sub}'"))
                        .with_hint(format!("usage: {KEY_USAGE}")),
                );
            }
        }
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        let completed = completed_args(tokens, cursor_token);
        if completed == 0 {
            return owned(&["info", "edit", "template"]);
        }
        if completed == 1 {
            return complete_refs(ctx, cursor_token);
        }
        match tokens.get(1).map(String::as_str) {
            Some("edit") => owned(&["--label", "--id"]),
            Some("template") if completed == 2 => complete_paths(cursor_token),
            _ => Vec::new(),
        }
    }
}

fn run_info(ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<()> {
    let reference = positional(args, 1, "provider:label", KEY_USAGE)?;
    let (provider, info) = ctx.providers.resolve_ref(reference)?;
    let mut rows: Vec<Vec<String>> = vec![
        vec!["ref".into(), info.key_ref.display()],
        vec!["provider type".into(), provider.type_name().to_owned()],
        vec!["class".into(), class_text(info.key_class).to_owned()],
        vec!["algorithm".into(), algo_text(&info).to_owned()],
        vec![
            "size (bits)".into(),
            info.size_bits
                .map_or_else(|| "-".to_owned(), |bits| bits.to_string()),
        ],
        vec![
            "curve".into(),
            info.curve
                .as_ref()
                .map_or_else(|| "-".to_owned(), |curve| curve.as_str().to_owned()),
        ],
        vec![
            "exportable".into(),
            if info.exportable { "yes" } else { "no" }.to_owned(),
        ],
    ];
    if let Some(handle) = info.handle {
        // session-transient '@<handle>' selector (§4.3)
        rows.push(vec!["handle".into(), handle.to_string()]);
    }
    for (name, value) in &info.attributes {
        rows.push(vec![name.clone(), value.render_info()]);
    }
    if info.key_class == KeyClass::Certificate {
        // §5.11: subject/issuer/serial/validity
        let material = provider.export_key(&info)?;
        for (name, value) in certificate_details(&material.data)? {
            rows.push(vec![name, value]);
        }
    }
    ctx.io.print(table(
        Some(&info.key_ref.display()),
        &["field", "value"],
        rows,
    ));
    let related: Vec<String> = provider
        .list_keys()?
        .iter()
        .filter(|other| {
            other.key_ref.label == info.key_ref.label
                && other.key_ref.key_id == info.key_ref.key_id
                && other.key_class != info.key_class
        })
        .map(object_text)
        .collect();
    if !related.is_empty() {
        // the family's other objects, as pasteable qualified refs
        text(ctx, format!("related: {}", related.join(", ")));
    }
    Ok(())
}

/// §5.15: flags → direct rename; else editor (pkcs11) / prompts (memory).
fn run_edit(ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<()> {
    let reference = positional(args, 1, "provider:label", KEY_USAGE)?;
    let (provider, key) = ctx.providers.resolve_ref(reference)?;
    require_usable(provider.as_ref())?;
    let label_opt = args.opt("label");
    let id_opt = parse_key_id(args)?;
    let changes = if label_opt.is_some() || id_opt.is_some() {
        changes_from_flags(&key, label_opt, id_opt)?
    } else if provider.type_name() == "pkcs11" {
        let original = provider.read_key_template(&key)?;
        let edited = ctx.template_editor.edit(
            original.clone(),
            &format!("PKCS#11 attributes — {}", key.key_ref.display()),
        )?;
        template_changes(&original, &edited)
    } else {
        prompt_identity(ctx, &key)?
    };
    if changes.attrs.is_empty() {
        text(ctx, "no changes".to_owned());
        return Ok(());
    }

    // §5.15 family rename: identity edits are single-object at the provider; siblings
    // sharing (label, id) are offered a confirm()-gated follow-up.
    let identity_rows: Vec<&TemplateAttr> = changes
        .attrs
        .iter()
        .filter(|attr| attr.name == "CKA_LABEL" || attr.name == "CKA_ID")
        .collect();
    let siblings = if identity_rows.is_empty() {
        Vec::new()
    } else {
        family_siblings(provider.as_ref(), &key)?
    };
    let rename_family = !siblings.is_empty()
        && ctx.io.confirm(
            &format!(
                "rename {} related object(s) sharing this label/id too?",
                siblings.len()
            ),
            true,
        )?;

    let result = provider.update_key(&key, &changes)?;
    let mut rows = outcome_rows(&object_text(&key), &changes, &result.outcomes);
    if rename_family {
        let applied: BTreeSet<&str> = result
            .outcomes
            .iter()
            .filter(|outcome| outcome.applied)
            .map(|outcome| outcome.name.as_str())
            .collect();
        // propagate only what the target applied
        let sibling_attrs: Vec<TemplateAttr> = identity_rows
            .iter()
            .filter(|attr| applied.contains(attr.name.as_str()))
            .map(|attr| TemplateAttr::new(attr.name.clone(), attr.kind, attr.value.clone()))
            .collect();
        if !sibling_attrs.is_empty() {
            let sibling_changes = KeyTemplate::new(sibling_attrs);
            for sibling in &siblings {
                check_interrupt()?; // §11 D13 step boundary between sibling renames
                rows.extend(edit_sibling(provider.as_ref(), sibling, &sibling_changes)?);
            }
        }
    }
    ctx.io.print(table(
        Some(&format!("edit {}", key.key_ref.display())),
        &["object", "attribute", "value", "result"],
        rows,
    ));
    if result.key.key_ref != key.key_ref {
        text(ctx, format!("now {}", result.key.key_ref.display()));
    }
    Ok(())
}

/// --label/--id → identity changes template; same-value rows are dropped.
fn changes_from_flags(
    key: &KeyInfo,
    label: Option<&str>,
    key_id: Option<Vec<u8>>,
) -> r2_core::Result<KeyTemplate> {
    let mut attrs = Vec::new();
    if let Some(label) = label {
        if label.is_empty() {
            return Err(ConsoleError::param("label must not be empty", "label"));
        }
        if label != key.key_ref.label {
            attrs.push(TemplateAttr::new(
                "CKA_LABEL",
                AttrKind::Str,
                AttrValue::Str(label.to_owned()),
            ));
        }
    }
    if let Some(key_id) = key_id
        && key.key_ref.key_id.as_ref() != Some(&key_id)
    {
        attrs.push(TemplateAttr::new(
            "CKA_ID",
            AttrKind::Bytes,
            AttrValue::Bytes(key_id),
        ));
    }
    Ok(KeyTemplate::new(attrs))
}

/// Diff the edited template against the seeded one (§5.15): a row travels when it is
/// enabled and new (editor `add`), re-enabled, or its value changed. Disabled rows mean
/// "don't change"; locked rows never travel.
fn template_changes(original: &KeyTemplate, edited: &KeyTemplate) -> KeyTemplate {
    let mut by_name: HashMap<&str, &TemplateAttr> = HashMap::new();
    for attr in &original.attrs {
        by_name.insert(attr.name.as_str(), attr); // Python dict: the last one wins
    }
    let changed = edited
        .attrs
        .iter()
        .filter(|attr| !attr.locked && attr.enabled)
        .filter(|attr| match by_name.get(attr.name.as_str()) {
            None => true,
            Some(previous) => !previous.enabled || previous.value != attr.value,
        })
        .map(|attr| TemplateAttr::new(attr.name.clone(), attr.kind, attr.value.clone()))
        .collect();
    KeyTemplate::new(changed)
}

/// Memory-key edit fallback: prompt new label/id, empty answer = keep.
fn prompt_identity(ctx: &AppContext, key: &KeyInfo) -> r2_core::Result<KeyTemplate> {
    let mut attrs = Vec::new();
    let spec = ParamSpec::str(
        "label",
        format!("New label (empty = keep '{}')", key.key_ref.label),
    )
    .optional(Some(ParamValue::Str(String::new())));
    let answer = ctx.io.prompt(&spec)?;
    let answer = py_strip(&answer);
    if !answer.is_empty() && answer != key.key_ref.label {
        attrs.push(TemplateAttr::new(
            "CKA_LABEL",
            AttrKind::Str,
            AttrValue::Str(answer.to_owned()),
        ));
    }
    if key.key_class == KeyClass::Data {
        return Ok(KeyTemplate::new(attrs)); // data objects carry no CKA_ID (§4.3)
    }
    let current = key
        .key_ref
        .key_id
        .as_ref()
        .map_or_else(|| "-".to_owned(), |id| hex_lower(id));
    let spec = ParamSpec::str("id", format!("New id hex (empty = keep {current})"))
        .optional(Some(ParamValue::Str(String::new())));
    let answer = ctx.io.prompt(&spec)?;
    let answer = py_strip(&answer);
    if !answer.is_empty() {
        let Some(new_id) = py_fromhex(answer.strip_prefix("0x").unwrap_or(answer)) else {
            return Err(
                ConsoleError::param(format!("invalid key id {}", py_repr(answer)), "id")
                    .with_hint("whole hex bytes, e.g. 0a1b"),
            );
        };
        if new_id.is_empty() {
            return Err(ConsoleError::param("key id must not be empty", "id"));
        }
        if key.key_ref.key_id.as_ref() != Some(&new_id) {
            attrs.push(TemplateAttr::new(
                "CKA_ID",
                AttrKind::Bytes,
                AttrValue::Bytes(new_id),
            ));
        }
    }
    Ok(KeyTemplate::new(attrs))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Other objects sharing the target's (label, id): keypair halves, certificates.
fn family_siblings(provider: &dyn Provider, key: &KeyInfo) -> r2_core::Result<Vec<KeyInfo>> {
    let mut family: Vec<KeyInfo> = provider
        .list_keys()?
        .into_iter()
        .filter(|info| {
            info.key_ref.label == key.key_ref.label && info.key_ref.key_id == key.key_ref.key_id
        })
        .collect();
    let wanted = key.handle;
    let self_index = family
        .iter()
        .position(|info| {
            info.key_class == key.key_class && (wanted.is_none() || info.handle == wanted)
        })
        // stale handle — fall back to the first same-class match
        .or_else(|| {
            family
                .iter()
                .position(|info| info.key_class == key.key_class)
        });
    if let Some(index) = self_index {
        family.remove(index);
    }
    Ok(family)
}

fn outcome_rows(
    object: &str,
    changes: &KeyTemplate,
    outcomes: &[AttrEditOutcome],
) -> Vec<Vec<String>> {
    outcomes
        .iter()
        .map(|outcome| {
            let value = changes
                .attrs
                .iter()
                .rev() // Python dict: the last row of a name wins
                .find(|attr| attr.name == outcome.name)
                .map_or_else(String::new, |attr| attr.value.render_value());
            let result = if outcome.applied {
                "applied".to_owned()
            } else {
                format!("failed — {}", outcome.detail.as_deref().unwrap_or("None"))
            };
            vec![object.to_owned(), outcome.name.clone(), value, result]
        })
        .collect()
}

/// Apply the identity change to one sibling; a failure is a row, not an abort (a
/// UserAbort still aborts, §4.2).
fn edit_sibling(
    provider: &dyn Provider,
    sibling: &KeyInfo,
    changes: &KeyTemplate,
) -> r2_core::Result<Vec<Vec<String>>> {
    match provider.update_key(sibling, changes) {
        Ok(result) => Ok(outcome_rows(
            &object_text(sibling),
            changes,
            &result.outcomes,
        )),
        Err(err) if err.kind.is_user_abort() => Err(err),
        Err(err) => {
            let names: Vec<&str> = changes.attrs.iter().map(|a| a.name.as_str()).collect();
            Ok(vec![vec![
                object_text(sibling),
                names.join("/"),
                String::new(),
                format!("failed — {}", err.message),
            ]])
        }
    }
}

// ---------------------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------------------

const GENERATE_USAGE: &str = "generate <provider> <aes|rsa|ec|generic> [size=<bits>] \
                              [curve=<name>] [--label <l>] [--id <hex>] [--template <path>]";

/// Generic secret size: whole bytes, 8..8192 bits (§5.3).
fn validate_generic_size(value: &ParamValue) -> r2_core::Result<()> {
    let ok = matches!(value, ParamValue::Int(v) if v % 8 == 0 && (8..=8192).contains(v));
    if ok {
        return Ok(());
    }
    let shown = match value {
        ParamValue::Int(v) => v.to_string(),
        ParamValue::Str(s) | ParamValue::Enum(s) => py_repr(s),
        other => format!("{other:?}"),
    };
    Err(ConsoleError::param(
        format!(
            "invalid generic secret size {shown}; expected a multiple of 8 between 8 and 8192 \
             bits"
        ),
        "size",
    ))
}

/// §5.3 size/curve parameter tables, resolved via ParamResolver (one code path). The
/// resolver reads only id + params; the other fields are inert.
fn generate_spec(kind: &str) -> Option<OperationSpec> {
    let (algorithm, label, param) = match kind {
        "aes" => (
            KeyAlgorithm::Aes,
            "AES key generation parameters",
            ParamSpec::new("size", ParamKind::Enum, "AES key size (bits)")
                .optional(Some(ParamValue::Enum("256".into())))
                .choices(&["128", "192", "256"]),
        ),
        "generic" => (
            KeyAlgorithm::Generic,
            "Generic secret (HMAC key) generation parameters",
            ParamSpec::new(
                "size",
                ParamKind::Int,
                "Generic secret size (bits, multiple of 8)",
            )
            .optional(Some(ParamValue::Int(256)))
            .validate(validate_generic_size),
        ),
        "rsa" => (
            KeyAlgorithm::Rsa,
            "RSA keypair generation parameters",
            ParamSpec::new("size", ParamKind::Enum, "RSA modulus size (bits)")
                .optional(Some(ParamValue::Enum("2048".into())))
                .choices(&["2048", "3072", "4096"]),
        ),
        "ec" => (
            KeyAlgorithm::Ec,
            "EC keypair generation parameters",
            ParamSpec::new("curve", ParamKind::Enum, "Curve")
                .optional(Some(ParamValue::Enum("p256".into())))
                .choices(&CURVES),
        ),
        _ => return None,
    };
    Some(OperationSpec {
        id: format!("generate.{kind}"),
        verb: Verb::Encrypt, // unused — the resolver reads only id + params
        algorithm,
        key_classes: BTreeSet::new(),
        mechanism: String::new(),
        cli_name: kind.to_owned(),
        label: label.to_owned(),
        params: vec![param],
        provider_types: None,
        providers: None,
        curves: None,
        raw_ckm: None,
        param_struct: ParamStruct::None,
    })
}

struct GenerateCommand;

impl Command for GenerateCommand {
    fn name(&self) -> &'static str {
        "generate"
    }
    fn summary(&self) -> &'static str {
        "Generate a key (AES / generic secret) or keypair (RSA/EC) on a provider"
    }
    fn usage(&self) -> &'static str {
        GENERATE_USAGE
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        let provider = ctx
            .providers
            .get(positional(args, 0, "provider", GENERATE_USAGE)?)?;
        let kind = positional(args, 1, "aes|rsa|ec|generic", GENERATE_USAGE)?;
        let Some(spec) = generate_spec(kind) else {
            return Err(
                ConsoleError::generic(format!("unknown key type '{kind}'")).with_hint(format!(
                    "valid types: aes, rsa, ec, generic — usage: {GENERATE_USAGE}"
                )),
            );
        };
        require_usable(provider.as_ref())?;
        let seeds = parse_seed_templates(ctx, args, provider.as_ref())?;
        let resolved =
            ParamResolver::new(ctx.io.as_ref(), &ctx.providers).resolve(&spec, &args.named)?;
        let label = match opt_nonempty(args, "label") {
            Some(label) => label.to_owned(),
            None => prompt_label(ctx)?, // §5.3: prompted if absent
        };
        let key_id = parse_key_id(args)?;

        let mut size_bits: Option<u32> = None;
        let mut curve: Option<Curve> = None;
        let algorithm = if kind == "ec" {
            let name = resolved
                .get("curve")
                .and_then(ParamValue::as_str)
                .unwrap_or("p256");
            let parsed: Curve = name.parse()?;
            let algorithm = parsed.algorithm();
            curve = Some(parsed);
            algorithm
        } else {
            size_bits = Some(resolved_size(resolved.get("size"))?);
            spec.algorithm
        };

        let mut template = None;
        let mut public_template = None;
        if provider.type_name() == "pkcs11" {
            // §5.3/§5.12: editor(s) first
            let templates = &ctx.cfg().templates;
            let seed = |class: KeyClass| build_seed(templates, seeds.as_ref(), class, algorithm);
            if matches!(algorithm, KeyAlgorithm::Aes | KeyAlgorithm::Generic) {
                let what = if algorithm == KeyAlgorithm::Aes {
                    "AES"
                } else {
                    "generic secret"
                };
                template = Some(ctx.template_editor.edit(
                    seed(KeyClass::Secret)?,
                    &format!("PKCS#11 template — {what} key '{label}'"),
                )?);
            } else {
                template = Some(ctx.template_editor.edit(
                    seed(KeyClass::Private)?,
                    &format!(
                        "PKCS#11 template — {} private key '{label}'",
                        algorithm.as_str()
                    ),
                )?);
                public_template = Some(ctx.template_editor.edit(
                    seed(KeyClass::Public)?,
                    &format!(
                        "PKCS#11 template — {} public key '{label}'",
                        algorithm.as_str()
                    ),
                )?);
            }
        }

        let mut request = GenerateRequest::new(algorithm, label);
        request.size_bits = size_bits;
        request.curve = curve.clone();
        request.key_id = key_id;
        request.template = template;
        request.public_template = public_template;
        let info = provider.generate_key(&request)?;
        let what = match (size_bits, &curve) {
            (Some(bits), _) if bits != 0 => format!("{bits}-bit {}", algorithm.as_str()),
            (_, Some(curve)) => format!("{} {}", curve.as_str(), algorithm.as_str()),
            _ => format!("None {}", algorithm.as_str()),
        };
        if info.key_class == KeyClass::Secret {
            text(
                ctx,
                format!("generated {} ({what})", info.key_ref.display()),
            );
        } else {
            text(
                ctx,
                format!(
                    "generated {what} keypair {} (public key shares the label/id)",
                    info.key_ref.display()
                ),
            );
        }
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        let completed = completed_args(tokens, cursor_token);
        if completed == 0 {
            return complete_provider_names(ctx, cursor_token);
        }
        if previous_token(tokens, cursor_token) == Some("--template") {
            return complete_paths(cursor_token); // §5.1 PathCompleter rule
        }
        if completed == 1 {
            return owned(&["aes", "rsa", "ec", "generic"]);
        }
        let mut candidates = owned(&["--label", "--id", "--template"]);
        match tokens.get(2).map(String::as_str) {
            Some("ec") => candidates.extend(CURVES.iter().map(|c| format!("curve={c}"))),
            Some("aes") => candidates.extend(["128", "192", "256"].map(|s| format!("size={s}"))),
            Some("rsa") => {
                candidates.extend(["2048", "3072", "4096"].map(|s| format!("size={s}")));
            }
            Some("generic") => {
                candidates.extend(GENERIC_SIZE_SUGGESTIONS.map(|s| format!("size={s}")));
            }
            _ => {}
        }
        candidates
    }
}

/// `int(str(resolved["size"]))` of c2 — an ENUM token or the generic INT.
fn resolved_size(value: Option<&ParamValue>) -> r2_core::Result<u32> {
    let parsed = match value {
        Some(ParamValue::Int(v)) => u32::try_from(*v).ok(),
        Some(ParamValue::Enum(s) | ParamValue::Str(s)) => s.parse::<u32>().ok(),
        _ => None,
    };
    parsed.ok_or_else(|| ConsoleError::param("invalid key size", "size"))
}

// ---------------------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------------------

const LOAD_USAGE: &str = "load <provider> <aes|rsa|ec|cert|generic|data|auto> [<data>] \
                          [--label <l>] [--id <hex>] [--template <path>]  |  load <provider> \
                          --file <path> [--format auto|aes|rsa|ec|cert|generic|data] \
                          [--password <pw>] [--label <l>] [--id <hex>] [--template <path>]  |  \
                          load <provider> <aes|rsa|ec|generic> [<data>] --kek <label> [--mech \
                          <name>] [<name>=<value> ...] [--label <l>] [--id <hex>] [--template \
                          <path>]";

fn check_hint(hint: &str) -> r2_core::Result<()> {
    if keyload::VALID_HINTS.contains(&hint) {
        return Ok(());
    }
    Err(
        ConsoleError::generic(format!("unknown key type hint '{hint}'"))
            .with_hint(format!("valid hints: {}", keyload::VALID_HINTS.join(", "))),
    )
}

struct LoadCommand;

impl Command for LoadCommand {
    fn name(&self) -> &'static str {
        "load"
    }
    fn summary(&self) -> &'static str {
        "Load pasted or file key material into a provider"
    }
    fn usage(&self) -> &'static str {
        LOAD_USAGE
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        // §5.5 probe order: auth first, before mechanisms()/find_key ever run.
        let provider = ctx
            .providers
            .get(positional(args, 0, "provider", LOAD_USAGE)?)?;
        require_usable(provider.as_ref())?;
        if args.opt("kek").is_some() {
            // §5.4 wrapped-key form (R15): name=value tokens are the mechanism's params,
            // so reject_named must NOT run here.
            kek::run_load(ctx, args, &provider)?;
            return Ok(Flow::Continue);
        }
        reject_named(args, LOAD_USAGE, NOUN)?;
        let seeds = parse_seed_templates(ctx, args, provider.as_ref())?;
        let (data, hint) = if let Some(file) = args.opt("file") {
            let hint = opt_nonempty(args, "format").unwrap_or("auto");
            check_hint(hint)?;
            if let Some(extra) = args.positionals.get(1) {
                return Err(ConsoleError::generic(format!(
                    "unexpected argument {}",
                    py_repr(extra)
                ))
                .with_hint(format!(
                    "the --file form takes no inline data — usage: {LOAD_USAGE}"
                )));
            }
            (keyload::read_key_file(&py_path(file))?, hint)
        } else {
            let hint = positional(args, 1, "aes|rsa|ec|cert|generic|data|auto", LOAD_USAGE)?;
            check_hint(hint)?;
            // The pasted text IS the key material in text form: keep it wiped on drop.
            let pasted: Zeroizing<String>;
            let token: &str = match args.positionals.get(2) {
                Some(token) => token,
                // §5.1 interactive fallback: multiline paste prompt
                None => {
                    pasted = Zeroizing::new(
                        ctx.io
                            .prompt_multiline("Paste key material (hex / base64 / PEM)")?,
                    );
                    &pasted
                }
            };
            (decode_data(token)?.0, hint)
        };

        let password = args
            .opt("password")
            .map(|pw| SecretString::from(pw.to_owned()));
        let materials = keyload::parse_materials(&data, hint, password.as_ref(), ctx.io.as_ref())?;
        let label = keyload::resolve_label(&materials, args.opt("label"), ctx.io.as_ref())?;
        let key_id = parse_key_id(args)?;
        let seeding = EditorSeeding {
            editor: ctx.template_editor.as_ref(),
            templates: &ctx.cfg().templates,
            seeds: seeds.as_ref(),
        };
        let infos = keyload::import_materials(
            provider.as_ref(),
            &materials,
            &label,
            key_id.as_deref(),
            &seeding,
        )?;
        let rows = infos
            .iter()
            .map(|info| {
                vec![
                    info.key_ref.display(),
                    class_text(info.key_class).to_owned(),
                    algo_text(info).to_owned(),
                ]
            })
            .collect();
        ctx.io.print(table(
            Some(&format!("loaded into {}", provider.name())),
            &["ref", "class", "algorithm"],
            rows,
        ));
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        let completed = completed_args(tokens, cursor_token);
        if completed == 0 {
            return complete_provider_names(ctx, cursor_token);
        }
        let previous = previous_token(tokens, cursor_token);
        match previous {
            Some("--file" | "--template") => return complete_paths(cursor_token),
            Some("--format") => return owned(&keyload::VALID_HINTS),
            Some(option @ ("--kek" | "--mech")) => {
                if let Some(values) = kek::complete_option_value(ctx, tokens, option) {
                    return values;
                }
            }
            _ => {}
        }
        if completed == 1 {
            let mut hints = owned(&keyload::VALID_HINTS);
            hints.push("--file".to_owned());
            return hints;
        }
        let mut candidates = owned(&[
            "--label",
            "--id",
            "--file",
            "--format",
            "--password",
            "--template",
            "--kek",
            "--mech",
        ]);
        candidates.extend(kek::param_name_candidates(tokens));
        candidates
    }
}

// ---------------------------------------------------------------------------------------
// export
// ---------------------------------------------------------------------------------------

const EXPORT_USAGE: &str = "export <provider>:<label>[:<class>] <path> [--format \
                            auto|raw|der|pem|p12] [--public] [--cert <provider>:<label>] \
                            [--password <pw>]  |  export <provider>:<label> <path> --kek \
                            <label>[:<class>] [--mech <name>] [<name>=<value> ...] \
                            [--outformat raw|hex|b64]";

struct ExportCommand;

impl Command for ExportCommand {
    fn name(&self) -> &'static str {
        "export"
    }
    fn summary(&self) -> &'static str {
        "Export a key, public part, certificate or PKCS#12 to a file"
    }
    fn usage(&self) -> &'static str {
        EXPORT_USAGE
    }
    fn flags(&self) -> &'static [&'static str] {
        &["public"]
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        if args.opt("kek").is_some() {
            // §5.6 wrapped form (R15): name=value tokens are the mechanism's params, so
            // reject_named must NOT run here.
            kek::run_export(ctx, args)?;
            return Ok(Flow::Continue);
        }
        reject_named(args, EXPORT_USAGE, NOUN)?;
        if args.opt("outformat").is_some() {
            return Err(
                ConsoleError::generic("--outformat applies only to wrapped exports").with_hint(
                    "plain exports are shaped by --format; add --kek <label> to write a \
                     wrapped blob",
                ),
            );
        }
        let reference = positional(args, 0, "provider:label", EXPORT_USAGE)?;
        let path = py_path(positional(args, 1, "path", EXPORT_USAGE)?);
        let fmt = opt_nonempty(args, "format").unwrap_or("auto");
        if !keyexport::VALID_FORMATS.contains(&fmt) {
            return Err(ConsoleError::param(
                format!("unknown export format {}", py_repr(fmt)),
                "format",
            )
            .with_hint(format!(
                "valid formats: {}",
                keyexport::VALID_FORMATS.join(", ")
            )));
        }
        let public = args.flag("public");
        let password = args
            .opt("password")
            .map(|pw| SecretString::from(pw.to_owned()));
        let cert_ref = args.opt("cert");
        let (provider, key) = ctx.providers.resolve_ref(reference)?;

        let (payload, resolved): (Zeroizing<Vec<u8>>, &str) = if fmt == "p12" {
            if public {
                return Err(
                    ConsoleError::generic("--public cannot be combined with --format p12")
                        .with_hint("a PKCS#12 contains the private key (§5.6)"),
                );
            }
            // §5.6 refusal pre-flight BEFORE any password prompt — never make the operator
            // type a password twice for a doomed export.
            keyexport::refuse_non_exportable(&key)?;
            let mut cert_der = None;
            if let Some(cert_ref) = cert_ref {
                let (cert_provider, cert_info) = ctx.providers.resolve_ref(cert_ref)?;
                if cert_info.key_class != KeyClass::Certificate {
                    return Err(ConsoleError::param(
                        format!(
                            "--cert must reference a certificate, got {} '{}'",
                            cert_info.key_class.as_str(),
                            cert_info.key_ref.display()
                        ),
                        "cert",
                    ));
                }
                cert_der = Some(cert_provider.export_key(&cert_info)?.data.to_vec());
            }
            let password = match password {
                Some(password) => password,
                None => prompt_p12_password(ctx)?,
            };
            let payload =
                certops::export_pkcs12(provider.as_ref(), &key, &password, cert_der.as_deref())?;
            (Zeroizing::new(payload), "p12")
        } else {
            if cert_ref.is_some() {
                return Err(ConsoleError::param(
                    "--cert applies only to --format p12 (§5.6)",
                    "cert",
                ));
            }
            // plaintext PKCS#8 / raw secret bytes: stays Zeroizing (§4.4, D3)
            keyexport::export_bytes(provider.as_ref(), &key, fmt, public, password.as_ref())?
        };

        check_interrupt()?; // §11 D13: step boundary before writing output
        keyexport::write_output(&path, &payload)?;
        text(
            ctx,
            format!(
                "wrote {} bytes to {} ({resolved})",
                payload.len(),
                path.display()
            ),
        );
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        let completed = completed_args(tokens, cursor_token);
        if completed == 0 {
            return complete_refs(ctx, cursor_token);
        }
        match previous_token(tokens, cursor_token) {
            Some("--format") => return owned(&keyexport::VALID_FORMATS),
            Some("--cert") => return complete_refs(ctx, cursor_token), // a ref (§5.1)
            Some("--password") => return Vec::new(),
            Some(option @ ("--mech" | "--outformat" | "--kek")) => {
                if let Some(values) = kek::complete_option_value(ctx, tokens, option) {
                    return values;
                }
            }
            _ => {}
        }
        if completed == 1 {
            return complete_paths(cursor_token); // <path> positional (§5.1)
        }
        let mut candidates = owned(&[
            "--format",
            "--public",
            "--cert",
            "--password",
            "--kek",
            "--mech",
            "--outformat",
        ]);
        candidates.extend(kek::param_name_candidates(tokens));
        candidates
    }
}

/// §5.6: PKCS#12 password prompted hidden, with confirmation.
fn prompt_p12_password(ctx: &AppContext) -> r2_core::Result<SecretString> {
    let password = ctx.io.prompt_secret("PKCS#12 password")?;
    let confirmed = ctx.io.prompt_secret("PKCS#12 password (again)")?;
    if password.expose_secret() != confirmed.expose_secret() {
        return Err(ConsoleError::param("passwords do not match", "password"));
    }
    Ok(password)
}

// ---------------------------------------------------------------------------------------
// csr
// ---------------------------------------------------------------------------------------

const CSR_USAGE: &str =
    "csr <provider>:<label>[:<class>] <path> [--subject \"<DN>\"] [--hash sha256|sha384|sha512]";

struct CsrCommand;

impl Command for CsrCommand {
    fn name(&self) -> &'static str {
        "csr"
    }
    fn summary(&self) -> &'static str {
        "Generate a PEM CSR signed by a provider-held key"
    }
    fn usage(&self) -> &'static str {
        CSR_USAGE
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        reject_named(args, CSR_USAGE, NOUN)?;
        let reference = positional(args, 0, "provider:label", CSR_USAGE)?;
        let path = py_path(positional(args, 1, "path", CSR_USAGE)?);
        let (provider, key) = ctx.providers.resolve_ref(reference)?;
        let subject = match opt_nonempty(args, "subject") {
            Some(subject) => subject.to_owned(),
            None => format!("CN={}", key.key_ref.label), // §5.7 default
        };
        let hash_name = opt_nonempty(args, "hash").unwrap_or("sha256");
        let pem = certops::generate_csr(provider.as_ref(), &key, &subject, hash_name)?;
        check_interrupt()?; // §11 D13: step boundary before writing output
        keyexport::write_output(&path, &pem)?;
        text(
            ctx,
            format!(
                "wrote CSR for {} to {} (subject: {subject})",
                key.key_ref.display(),
                path.display()
            ),
        );
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        let completed = completed_args(tokens, cursor_token);
        if completed == 0 {
            return complete_refs(ctx, cursor_token);
        }
        match previous_token(tokens, cursor_token) {
            Some("--hash") => return owned(&certops::CSR_HASHES),
            Some("--subject") => return Vec::new(),
            _ => {}
        }
        if completed == 1 {
            return complete_paths(cursor_token); // <path> positional (§5.1)
        }
        owned(&["--subject", "--hash"])
    }
}

// ---------------------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------------------

struct DeleteCommand;

impl Command for DeleteCommand {
    fn name(&self) -> &'static str {
        "delete"
    }
    fn summary(&self) -> &'static str {
        "Delete a key or certificate (confirmation per ui.confirm_delete)"
    }
    fn usage(&self) -> &'static str {
        "delete <provider>:<label>[#<id-hex>][:<class>]"
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        reject_named(args, self.usage(), NOUN)?;
        let reference = positional(args, 0, "provider:label", self.usage())?;
        let (provider, key) = ctx.providers.resolve_ref(reference)?;
        if ctx.cfg().ui.confirm_delete
            && !ctx.io.confirm(
                &format!(
                    "delete {} ({})?",
                    key.key_ref.display(),
                    class_text(key.key_class)
                ),
                false,
            )?
        {
            text(ctx, "delete cancelled".to_owned());
            return Ok(Flow::Continue);
        }
        provider.delete_key(&key)?;
        text(ctx, format!("deleted {}", key.key_ref.display()));
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        if completed_args(tokens, cursor_token) == 0 {
            return complete_refs(ctx, cursor_token);
        }
        Vec::new()
    }
}
