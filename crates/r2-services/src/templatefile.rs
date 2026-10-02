// R0 skeleton — owner R14 (generated from spec §4)
// ---- spec §4.9.10 block 0
use indexmap::IndexMap;
use r2_config::model::{CustomAttributeDef, TemplatesSection};
use r2_core::io::TemplateEditor;
use r2_core::keys::{KeyAlgorithm, KeyClass};
use r2_core::template::KeyTemplate;
use std::path::Path;

/// §5.16 file sections: class key → template (kinds resolved by NAME).
pub type SeedTemplates = IndexMap<String, KeyTemplate>;
/// Read-only lifecycle + material attrs seeded DISABLED (§5.16).
pub const NON_CREATION_ATTRS: [&str; 27] = [
    "CKA_LOCAL",
    "CKA_ALWAYS_SENSITIVE",
    "CKA_NEVER_EXTRACTABLE",
    "CKA_KEY_GEN_MECHANISM",
    "CKA_MODULUS",
    "CKA_MODULUS_BITS",
    "CKA_PUBLIC_EXPONENT",
    "CKA_PRIVATE_EXPONENT",
    "CKA_PRIME_1",
    "CKA_PRIME_2",
    "CKA_EXPONENT_1",
    "CKA_EXPONENT_2",
    "CKA_COEFFICIENT",
    "CKA_PRIME",
    "CKA_SUBPRIME",
    "CKA_BASE",
    "CKA_EC_PARAMS",
    "CKA_EC_POINT",
    "CKA_VALUE",
    "CKA_VALUE_LEN",
    "CKA_CHECK_VALUE",
    "CKA_SERIAL_NUMBER",
    "CKA_ISSUER",
    "CKA_SUBJECT",
    "CKA_PUBLIC_KEY_INFO",
    "CKA_HASH_OF_SUBJECT_PUBLIC_KEY",
    "CKA_HASH_OF_ISSUER_PUBLIC_KEY",
];
/// Secret material a dump may carry — `key template` prints the handle-like-a-private-key note.
pub const SECRET_MATERIAL_ATTRS: [&str; 7] = [
    "CKA_VALUE",
    "CKA_PRIVATE_EXPONENT",
    "CKA_PRIME_1",
    "CKA_PRIME_2",
    "CKA_EXPONENT_1",
    "CKA_EXPONENT_2",
    "CKA_COEFFICIENT",
];
/// Write `template` as one class-keyed YAML section via `yaml::dump` + `keyexport::write_output`.
pub fn dump_template_file(
    path: &Path,
    class_key: &str,
    template: &KeyTemplate,
) -> r2_core::Result<()> {
    let _ = (path, class_key, template);
    Err(r2_core::ConsoleError::not_implemented("R14"))
}
/// ★ (R8, R10, R15 via cmdutil/copy) Parse a §5.16 file. Unreadable → DataIo "cannot read
/// {path}: {err}"; bad YAML → Param "invalid YAML in template file {path}: {err}" (param
/// "template", hint "template files are class-keyed YAML (spec §5.16)"); empty/non-mapping →
/// Param "template file {path} has no sections" (hint "valid sections: {TEMPLATE_CLASS_KEYS
/// joined ', '}"); unknown section → "unknown template section '{key}' in {path}"; section
/// not a mapping → "template section '{key}' in {path} is not a mapping" (hint "each section
/// maps CKA_* names to values"); unknown CKA name → Param "unknown PKCS#11 attribute
/// '{name}'" (hint "define it under templates.custom_attributes (code + kind)"); kind/value
/// mismatch (c2 `_value_from_yaml`, param_name = name) → BOOL: "{name} expects true/false";
/// ULONG: a bool → "{name} expects an integer", a non-int non-symbol → "{name} expects an
/// integer or CKO_/CKK_/CKC_/CKM_ constant", a negative int n ≥ −2^63 in a
/// NON_CREATION_ATTRS row → its 64-bit two's complement 2^64 + n (c2 dumped PyKCS11's signed
/// C long: `CKA_KEY_GEN_MECHANISM: -1` of an imported object loads as
/// 18446744073709551615 = CK_UNAVAILABLE_INFORMATION, what r2's own dump writes; the row
/// arrives disabled — §11 D18), any other negative int → "template attribute {name} must
/// not be negative" (c2 raised it later, at conversion — §11 D18); BYTES: "{name}
/// expects a 0x… hex string" | "{name} has invalid hex" (`text::py_fromhex`); STR: "{name}
/// expects a string". Values are typed by the §4.8.4 loader, so `CKA_TOKEN: yes` is a bool
/// and `CKA_LABEL: yes` fails "expects a string", exactly as in c2.
/// R0 stub: Err(not_implemented("R14")).
pub fn load_seed_file(
    path: &Path,
    custom_attributes: &IndexMap<String, CustomAttributeDef>,
) -> r2_core::Result<SeedTemplates> {
    let _ = (path, custom_attributes);
    Err(r2_core::ConsoleError::not_implemented("R14"))
}
/// ★ Editor seed for one (class, algorithm): the matching file section when present
/// (locked CKA_CLASS/CKA_KEY_TYPE rows from the FLOW via default_template, file entries for
/// them dropped; CKA_LABEL/CKA_ID and NON_CREATION_ATTRS rows disabled; everything else
/// enabled with its file value), else `templates.default_template(..)` unchanged.
/// R0 stub body (mandated): `seeds == None` → `templates.default_template(key_class,
/// algorithm)`; `Some` → Err(not_implemented("R14")) — so R8/R10/R15 work before R14 merges.
pub fn build_seed(
    templates: &TemplatesSection,
    seeds: Option<&SeedTemplates>,
    key_class: KeyClass,
    algorithm: KeyAlgorithm,
) -> r2_core::Result<KeyTemplate> {
    match seeds {
        None => templates.default_template(key_class, algorithm),
        Some(_) => Err(r2_core::ConsoleError::not_implemented("R14")),
    }
}

/// ★ The seeding context every create flow passes around (keyload, transfer, wrapload).
#[derive(Clone, Copy)]
pub struct EditorSeeding<'a> {
    pub editor: &'a dyn TemplateEditor,
    pub templates: &'a TemplatesSection,
    pub seeds: Option<&'a SeedTemplates>,
}
impl<'a> EditorSeeding<'a> {
    /// `build_seed(..)` then `editor.edit(seed, title)`.
    pub fn edit(
        &self,
        key_class: KeyClass,
        algorithm: KeyAlgorithm,
        title: &str,
    ) -> r2_core::Result<KeyTemplate> {
        let seed = build_seed(self.templates, self.seeds, key_class, algorithm)?;
        self.editor.edit(seed, title)
    }
}
