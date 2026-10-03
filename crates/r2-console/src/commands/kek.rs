// `load --kek` (§5.4) and `export --kek` (§5.6) — owner R15. Port of the `--kek` paths of
// c2 `console/commands/keys_cmd.py` (`LoadCommand._run_wrapped`,
// `ExportCommand._run_wrapped`, `_reject_unknown_params`, `_complete_kek_labels`,
// `_wrap_param_names`), filled into the hooks R8's `load`/`export` commands call.
//
// Commands return errors, never print them (§4.2). Mechanism params resolve through
// ParamResolver (one code path for inline name=value tokens and prompts, §5.1); blobs are
// read through DataInput (auto mode) and written through DataOutput (raw/hex/b64).
use std::rc::Rc;

use r2_core::codec::decode_data;
use r2_core::datainput::{DataInput, DataOutput, InFormat, OutFormat};
use r2_core::error::ConsoleError;
use r2_core::io::{Renderable, table};
use r2_core::runtime::{check_interrupt, timing_suffix};
use r2_core::text::{py_path, py_repr, py_strip};
use r2_ops::ParamResolver;
use r2_provider::Provider;
use r2_services::keyload;
use r2_services::templatefile::EditorSeeding;
use r2_services::wrapload::{self, Direction, UnwrapJob, WrapMechEntry};
use zeroize::Zeroizing;

use crate::cmdutil::{parse_key_id, parse_seed_templates, positional, require_usable};
use crate::completer::complete_refs;
use crate::context::AppContext;
use crate::parser::BoundArgs;
use crate::render::{algo_text, class_text};

/// The `load` command's usage text (c2 `LoadCommand.usage`, quoted by its errors).
pub(crate) const LOAD_USAGE: &str = "load <provider> <aes|rsa|ec|cert|generic|data|auto> \
                                     [<data>] [--label <l>] [--id <hex>] [--template <path>]  \
                                     |  load <provider> --file <path> [--format \
                                     auto|aes|rsa|ec|cert|generic|data] [--password <pw>] \
                                     [--label <l>] [--id <hex>] [--template <path>]  |  load \
                                     <provider> <aes|rsa|ec|generic> [<data>] --kek <label> \
                                     [--mech <name>] [<name>=<value> ...] [--label <l>] [--id \
                                     <hex>] [--template <path>]";

/// The `export` command's usage text (c2 `ExportCommand.usage`).
pub(crate) const EXPORT_USAGE: &str = "export <provider>:<label>[:<class>] <path> [--format \
                                       auto|raw|der|pem|p12] [--public] [--cert \
                                       <provider>:<label>] [--password <pw>]  |  export \
                                       <provider>:<label> <path> --kek <label>[:<class>] \
                                       [--mech <name>] [<name>=<value> ...] [--outformat \
                                       raw|hex|b64]";

/// §5.6 wrapped-export encodings (the §4.4 DataOutput file formats).
const OUT_FORMATS: [&str; 3] = ["raw", "hex", "b64"];

/// The §5.4 result-type hints, in c2's `RESULT_BY_HINT` order.
const RESULT_HINTS: [&str; 4] = ["aes", "generic", "rsa", "ec"];

/// `load <provider> <aes|rsa|ec|generic> [<data>|--file] --kek …` (§5.4). Called by `load`
/// right after the provider lookup and `require_usable` and BEFORE `reject_named` (the
/// name=value tokens are the mechanism's params), whenever `args.opt("kek")` is Some.
pub fn run_load(
    ctx: &AppContext,
    args: &BoundArgs,
    provider: &Rc<dyn Provider>,
) -> r2_core::Result<()> {
    let provider = provider.as_ref();
    let kek_token = args.opt("kek").unwrap_or("");
    let file_opt = args.opt("file");
    for name in ["format", "password"] {
        if args.opt(name).is_some() {
            return Err(
                ConsoleError::generic(format!("--{name} cannot be combined with --kek")).with_hint(
                    "a wrapped blob is opaque — it is never an encrypted container; declare the \
                 result type positionally",
                ),
            );
        }
    }
    if args.opt("outformat").is_some() {
        return Err(
            ConsoleError::generic("--outformat applies to `export --kek`, not to loading")
                .with_hint("hex/base64 blob files are detected automatically (§5.4)"),
        );
    }
    let hint = positional(args, 1, "aes|rsa|ec|generic", LOAD_USAGE)?;
    let Some((result_algorithm, result_class)) = wrapload::result_by_hint(hint) else {
        return Err(
            ConsoleError::generic(format!("type hint '{hint}' is invalid with --kek")).with_hint(
                format!(
                    "a wrapped blob is opaque — declare what comes out: {}",
                    RESULT_HINTS.join(", ")
                ),
            ),
        );
    };
    let seeds = parse_seed_templates(ctx, args, provider)?;

    let kek = wrapload::resolve_kek(&ctx.providers, provider, kek_token, Direction::Unwrap)?;
    let entry = match args.opt("mech") {
        Some(mech) => wrapload::resolve_mech(mech, &kek, provider, Direction::Unwrap)?,
        None => wrapload::select_mech(ctx.io.as_ref(), &kek, provider, Direction::Unwrap)?,
    };
    reject_unknown_params(args, &entry)?;
    let params =
        ParamResolver::new(ctx.io.as_ref(), &ctx.providers).resolve(&entry.spec, &args.named)?;

    let wrapped: Zeroizing<Vec<u8>> = if let Some(file) = file_opt {
        if let Some(extra) = args.positionals.get(2) {
            return Err(
                ConsoleError::generic(format!("unexpected argument {}", py_repr(extra))).with_hint(
                    format!("the --file form takes no inline data — usage: {LOAD_USAGE}"),
                ),
            );
        }
        // §4.4 auto: printable hex/base64 content is decoded, anything else read verbatim
        // — so `export --outformat hex|b64` blobs load back unchanged (§5.6 round-trip).
        DataInput::file(py_path(file), InFormat::Auto).resolve()?
    } else {
        let pasted: Zeroizing<String>;
        let token: &str = match args.positionals.get(2) {
            Some(token) => token,
            // §5.1 interactive fallback
            None => {
                pasted = Zeroizing::new(
                    ctx.io
                        .prompt_multiline("Paste wrapped key blob (hex / base64)")?,
                );
                &pasted
            }
        };
        decode_data(token)?.0
    };

    let label = keyload::resolve_label(&[], args.opt("label"), ctx.io.as_ref())?;
    let key_id = parse_key_id(args)?;
    let seeding = EditorSeeding {
        editor: ctx.template_editor.as_ref(),
        templates: &ctx.cfg().templates,
        seeds: seeds.as_ref(),
    };
    // §11 D13: a Ctrl-C during the KEK lookup / mechanisms() probe / blob read never
    // issues C_UnwrapKey (c2's KeyboardInterrupt surfaced right after the find_key call).
    check_interrupt()?;
    let info = wrapload::load_wrapped(
        provider,
        UnwrapJob {
            kek: &kek,
            entry: &entry,
            params,
            wrapped: &wrapped,
            result_algorithm,
            result_class,
            label,
            key_id,
        },
        &seeding,
    )?;
    check_interrupt()?; // §11 D13: step boundary after the provider verb
    ctx.io.print(table(
        Some(&format!(
            "unwrapped into {} ({})",
            provider.name(),
            entry.spec.mechanism
        )),
        &["ref", "class", "algorithm"],
        vec![vec![
            info.key_ref.display(),
            class_text(info.key_class).to_owned(),
            algo_text(&info).to_owned(),
        ]],
    ));
    // §11 D31: on its own line — a table title wraps at the table's width
    crate::commands::keys::print_timing(ctx, "unwrapped");
    Ok(())
}

/// `export <ref> <path> --kek …` (§5.6). Called by `export` first thing (before
/// `reject_named` and the --outformat check) whenever `args.opt("kek")` is Some.
pub fn run_export(ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<()> {
    for (name, why) in [
        ("format", "a wrapped blob is opaque, not a container format"),
        ("cert", "certificates belong to --format p12"),
        (
            "password",
            "the KEK protects the blob; there is nothing to encrypt with a password",
        ),
    ] {
        if args.opt(name).is_some() {
            return Err(
                ConsoleError::generic(format!("--{name} cannot be combined with --kek"))
                    .with_hint(why),
            );
        }
    }
    if args.flag("public") {
        return Err(
            ConsoleError::generic("--public cannot be combined with --kek")
                .with_hint("public keys are not wrapped — export them as plain material (§5.6)"),
        );
    }
    let reference = positional(args, 0, "provider:label", EXPORT_USAGE)?;
    let path = py_path(positional(args, 1, "path", EXPORT_USAGE)?);
    // c2 `_opt(args, "outformat") or "raw"`: an empty value is the default
    let outformat = args
        .opt("outformat")
        .filter(|value| !value.is_empty())
        .unwrap_or("raw");
    let fmt = match outformat {
        "raw" => OutFormat::Raw,
        "hex" => OutFormat::Hex,
        "b64" => OutFormat::B64,
        _ => {
            return Err(
                ConsoleError::generic(format!("invalid --outformat '{outformat}'"))
                    .with_hint(format!("choose one of: {}", OUT_FORMATS.join(", "))),
            );
        }
    };
    let (provider, key) = ctx.providers.resolve_ref(reference)?;
    let provider = provider.as_ref();
    require_usable(provider)?; // friendly auth error before mechanisms() probing
    // §5.6 refusal pre-flight BEFORE the mechanism menu and any param prompt — never walk
    // the operator through a doomed export.
    wrapload::refuse_non_wrappable(&key)?;

    let kek = wrapload::resolve_kek(
        &ctx.providers,
        provider,
        args.opt("kek").unwrap_or(""),
        Direction::Wrap,
    )?;
    let entry = match args.opt("mech") {
        Some(mech) => wrapload::resolve_mech(mech, &kek, provider, Direction::Wrap)?,
        None => wrapload::select_mech(ctx.io.as_ref(), &kek, provider, Direction::Wrap)?,
    };
    reject_unknown_params(args, &entry)?;
    // §11 D30: a CBC/GCM IV left empty at its prompt comes from the KEK provider's RNG
    // (`load --kek` never passes one — the unwrap needs the blob's own IV)
    let params = ParamResolver::new(ctx.io.as_ref(), &ctx.providers)
        .with_rng(provider)
        .resolve(&entry.spec, &args.named)?;

    check_interrupt()?; // §11 D13: never issue C_WrapKey after a Ctrl-C
    let blob = wrapload::wrap_for_export(provider, &kek, &entry, params, &key)?;
    check_interrupt()?; // §11 D13: step boundary before writing output
    DataOutput::file(path.clone(), fmt).write(&blob, ctx.io.as_ref())?;
    // the blob length, not the file size — hex/b64 files are larger
    let encoding = if fmt == OutFormat::Raw {
        String::new()
    } else {
        format!(", {outformat}-encoded")
    };
    ctx.io.print(Renderable::Text(format!(
        "wrote {}: {}-byte blob wrapped under {} with {}{encoding}{}",
        path.display(),
        blob.len(),
        kek.key_ref.display(),
        entry.spec.mechanism,
        timing_suffix() // §11 D31: last, so the wrap of the text before it is unchanged
    )));
    Ok(())
}

/// Unknown name=value tokens in the wrapped forms, with the quoting hint. ParamResolver
/// would reject these too, but a base64 blob pasted unquoted ends in '=' padding and is
/// bound as name=value by the §4.9 tokenizer — so the actionable advice is "quote it".
fn reject_unknown_params(args: &BoundArgs, entry: &WrapMechEntry) -> r2_core::Result<()> {
    let params = &entry.spec.params;
    let Some(unexpected) = args
        .named
        .keys()
        .find(|name| !params.iter().any(|param| &param.name == *name))
    else {
        return Ok(());
    };
    let base = if params.is_empty() {
        format!("{} takes no parameters", entry.spec.cli_name)
    } else {
        format!(
            "{} parameters: {}",
            entry.spec.cli_name,
            params
                .iter()
                .map(|param| param.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    Err(
        ConsoleError::generic(format!("unexpected name=value token '{unexpected}=…'")).with_hint(
            format!("{base} — quote a base64 blob so its '=' padding is not read as name=value"),
        ),
    )
}

/// Completion for `--kek`-specific positions of `load`/`export`: `option` = the previous
/// token. "--kek" → KEK labels (the line's provider refs via complete_refs with the
/// "<provider>:" prefix stripped); "--mech" → wrap cli names (kw, kwp, cbc, gcm, oaep,
/// pkcs1); "--outformat" → raw, hex, b64; anything else → None.
pub fn complete_option_value(
    ctx: &AppContext,
    tokens: &[String],
    option: &str,
) -> Option<Vec<String>> {
    match option {
        "--mech" => Some(
            wrapload::wrap_mechs()
                .into_iter()
                .map(|entry| entry.spec.cli_name)
                .collect(),
        ),
        "--outformat" => Some(OUT_FORMATS.iter().map(|f| (*f).to_owned()).collect()),
        "--kek" => Some(complete_kek_labels(ctx, tokens)),
        _ => None,
    }
}

/// `--kek` candidates: the provider's own refs, label-only (§5.4/§5.6). Routed through
/// `complete_refs` so the §6 "completion never loads a PKCS#11 library" rule is honored in
/// one place. Positional 1 is a bare provider name for `load` and a full key ref for
/// `export` — both start with the provider.
fn complete_kek_labels(ctx: &AppContext, tokens: &[String]) -> Vec<String> {
    let Some(first) = tokens.get(1) else {
        return Vec::new();
    };
    let provider = first.split(':').next().unwrap_or_default();
    let prefix = format!("{provider}:");
    complete_refs(ctx, &prefix)
        .into_iter()
        .filter(|candidate| *candidate != prefix)
        .map(|candidate| {
            candidate
                .strip_prefix(&prefix)
                .map_or_else(|| candidate.clone(), str::to_owned)
        })
        .collect()
}

/// "<param>=" suggestions for the wrap mechanism named after `--mech` on the line (empty
/// when none/unknown).
pub fn param_name_candidates(tokens: &[String]) -> Vec<String> {
    let Some(index) = tokens.iter().position(|token| token == "--mech") else {
        return Vec::new();
    };
    let Some(name) = tokens.get(index + 1) else {
        return Vec::new();
    };
    let wanted = py_strip(name).to_lowercase();
    wrapload::wrap_mechs()
        .into_iter()
        .find(|entry| entry.spec.cli_name == wanted)
        .map(|entry| {
            entry
                .spec
                .params
                .iter()
                .map(|param| format!("{}=", param.name))
                .collect()
        })
        .unwrap_or_default()
}

pub fn commands() -> Vec<Box<dyn crate::commands::Command>> {
    vec![]
}
