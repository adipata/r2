// `key template <ref> <path>` (spec §5.16, §4.9.9; owner R14) — c2 `keys_cmd.py`
// `KeyCommand._run_template`. Called by R8's `key` command for subcommand "template" (after
// its `reject_named`); dumps the COMPLETE attribute template of one PKCS#11 object to a
// class-keyed YAML file through `templatefile::dump_template_file`.
use r2_config::model::template_class_key;
use r2_core::error::ConsoleError;
use r2_core::io::Renderable;
use r2_core::keys::KeyClass;
use r2_core::text::py_path;
use r2_services::templatefile::{SECRET_MATERIAL_ATTRS, dump_template_file};

use crate::cmdutil::{positional, require_usable};
use crate::context::AppContext;
use crate::parser::BoundArgs;

/// The `key` command's usage line (c2 `self.usage` of KeyCommand; `key template`'s missing
/// argument hints quote it).
pub(crate) const KEY_USAGE: &str = "key info <provider>:<label>[#<id-hex>][:<class>]  |  key \
                                    edit <provider>:<label>[#<id-hex>][:<class>] [--label \
                                    <l>] [--id <hex>]  |  key template \
                                    <provider>:<label>[#<id-hex>][:<class>] <path>";

/// `key template <ref> <path>` (§5.16). `args` = the `key` command's BoundArgs:
/// positionals[0] == "template", [1] = ref, [2] = path. Non-pkcs11 provider →
/// UnsupportedOperation "key template works only with PKCS#11 providers" (hint "{name} keys
/// have no PKCS#11 attribute template"). Prints the "wrote {class_key} template (…)" line
/// and the key-material note.
pub fn run(ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<()> {
    let reference = positional(args, 1, "provider:label", KEY_USAGE)?;
    let path = py_path(positional(args, 2, "path", KEY_USAGE)?);
    let (provider, key) = ctx.providers.resolve_ref(reference)?;
    require_usable(provider.as_ref())?;
    if provider.type_name() != "pkcs11" {
        return Err(
            ConsoleError::unsupported("key template works only with PKCS#11 providers").with_hint(
                format!(
                    "{} keys have no PKCS#11 attribute template",
                    provider.name()
                ),
            ),
        );
    }
    let template = provider.read_full_template(&key)?;
    let class_key = template_class_key(key.key_class, key.algorithm)?;
    dump_template_file(&path, class_key, &template)?;
    tracing::info!(
        class_key,
        attributes = template.attrs.len(),
        "key template dumped"
    );
    ctx.io.print(Renderable::Text(format!(
        "wrote {class_key} template ({} attributes) for {} to {}",
        template.attrs.len(),
        key.key_ref.display(),
        path.display()
    )));
    if matches!(key.key_class, KeyClass::Secret | KeyClass::Private) {
        let mut material: Vec<&str> = template
            .attrs
            .iter()
            .map(|attr| attr.name.as_str())
            .filter(|name| SECRET_MATERIAL_ATTRS.contains(name))
            .collect();
        material.sort_unstable();
        if !material.is_empty() {
            ctx.io.print(Renderable::Text(format!(
                "note: the file contains key material ({}) — handle it like a private key",
                material.join(", ")
            )));
        }
    }
    Ok(())
}

pub fn commands() -> Vec<Box<dyn crate::commands::Command>> {
    vec![]
}
