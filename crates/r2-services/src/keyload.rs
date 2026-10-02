// Key-load orchestration (spec §5.4, §4.9.10; owner R8) — c2 `services/keyload.py`.
//
// Pure orchestration: bytes → `parse_key_material` → per-material template editing
// (PKCS#11 targets only, §5.12) → `Provider::import_key`. Interactive needs go through the
// `r2_core::io` traits — no console import (§3.1). Services never print.
use std::path::Path;
use std::str::FromStr;

use r2_core::crypto::random_bytes;
use r2_core::error::ConsoleError;
use r2_core::io::ConsoleIo;
use r2_core::keyparse::{KeyHint, parse_key_material};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::ParamSpec;
use r2_core::text::{os_error_text, py_strip};
use r2_provider::Provider;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::templatefile::EditorSeeding;

/// Key-type hints of `load` / `--format` (§4.4/§5.1).
pub const VALID_HINTS: [&str; 7] = ["auto", "aes", "rsa", "ec", "cert", "generic", "data"];

/// Verbatim-bytes hints (no sniffing): "generic" → (Generic, Secret), "data" → (None, Data).
pub fn verbatim_hint(hint: &str) -> Option<(KeyAlgorithm, KeyClass)> {
    match hint {
        "generic" => Some((KeyAlgorithm::Generic, KeyClass::Secret)),
        "data" => Some((KeyAlgorithm::None, KeyClass::Data)),
        _ => None,
    }
}

/// DataIo "cannot read {path}: {err}".
pub fn read_key_file(path: &Path) -> r2_core::Result<Zeroizing<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(data) => Ok(Zeroizing::new(data)),
        Err(err) => Err(ConsoleError::data_io(format!(
            "cannot read {}: {}",
            path.display(),
            os_error_text(&err)
        ))),
    }
}

/// §4.4 parse with the typed hint; generic/data short-circuit to one verbatim material
/// (empty → Param "{hint} material must not be empty", param "data"); password = --password
/// else a hidden `prompt_secret(prompt)` per encrypted item.
pub fn parse_materials(
    data: &[u8],
    hint: &str,
    password: Option<&SecretString>,
    io: &dyn ConsoleIo,
) -> r2_core::Result<Vec<KeyMaterial>> {
    if let Some((algorithm, key_class)) = verbatim_hint(hint) {
        if data.is_empty() {
            return Err(ConsoleError::param(
                format!("{hint} material must not be empty"),
                "data",
            ));
        }
        let mut material = KeyMaterial::new(algorithm, key_class, data.to_vec());
        material.size_bits = u32::try_from(data.len().saturating_mul(8)).ok();
        return Ok(vec![material]);
    }
    let key_hint = KeyHint::from_str(hint)?;
    // c2 `make_password_cb`: --password when given, else a hidden prompt per item.
    let mut callback = |prompt: &str| -> r2_core::Result<SecretString> {
        match password {
            Some(given) => Ok(SecretString::from(given.expose_secret().to_owned())),
            None => io.prompt_secret(prompt),
        }
    };
    parse_key_material(data, key_hint, Some(&mut callback))
}

/// ★ (R15) Label precedence: --label (trimmed; empty → Param "label must not be empty") →
/// first material label_hint → prompt "Key label" (empty → same Param).
pub fn resolve_label(
    materials: &[KeyMaterial],
    label: Option<&str>,
    io: &dyn ConsoleIo,
) -> r2_core::Result<String> {
    if let Some(label) = label {
        let text = py_strip(label);
        if text.is_empty() {
            return Err(ConsoleError::param("label must not be empty", "label"));
        }
        return Ok(text.to_owned());
    }
    if let Some(hint) = materials
        .iter()
        .filter_map(|material| material.label_hint.as_deref())
        .find(|hint| !hint.is_empty())
    {
        return Ok(hint.to_owned());
    }
    let answer = io.prompt(&ParamSpec::str("label", "Key label"))?;
    let answer = py_strip(&answer);
    if answer.is_empty() {
        return Err(ConsoleError::param("label must not be empty", "label"));
    }
    Ok(answer.to_owned())
}

/// "PKCS#11 template — {algorithm} {class} '{label}'" (data objects: "{class}" only).
pub fn editor_title(material: &KeyMaterial, label: &str) -> String {
    let what = if material.key_class == KeyClass::Data {
        material.key_class.as_str().to_owned()
    } else {
        format!(
            "{} {}",
            material.algorithm.as_str(),
            material.key_class.as_str()
        )
    };
    format!("PKCS#11 template — {what} '{label}'")
}

/// Import every material under one label; PKCS#11 targets get one editor per material via
/// `seeding`. PKCS#11 targets only (`type_name() == "pkcs11"`): multi-material inputs
/// (PKCS#12) share one fresh 4-byte CKA_ID when none was given; memory keeps `None`.
pub fn import_materials(
    provider: &dyn Provider,
    materials: &[KeyMaterial],
    label: &str,
    key_id: Option<&[u8]>,
    seeding: &EditorSeeding<'_>,
) -> r2_core::Result<Vec<KeyInfo>> {
    let is_pkcs11 = provider.type_name() == "pkcs11";
    let generated;
    let key_id = match key_id {
        None if is_pkcs11 && materials.len() > 1 => {
            // §5.4: PKCS#12 members share label AND CKA_ID.
            generated = random_bytes(4)?;
            Some(generated.as_slice())
        }
        other => other,
    };
    let mut infos = Vec::with_capacity(materials.len());
    for (index, material) in materials.iter().enumerate() {
        if index > 0 {
            // §11 D13: step boundary between batched provider calls (a PKCS#12 is key +
            // cert + chain); c2's KeyboardInterrupt stopped between imports.
            r2_core::runtime::check_interrupt()?;
        }
        let template = if is_pkcs11 {
            Some(seeding.edit(
                material.key_class,
                material.algorithm,
                &editor_title(material, label),
            )?)
        } else {
            None
        };
        infos.push(provider.import_key(material, label, template.as_ref(), key_id)?);
    }
    Ok(infos)
}
