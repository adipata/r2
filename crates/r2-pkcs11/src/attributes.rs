//! Template → attribute conversion, identity extraction and the vendor value codec
//! (spec §4.7; c2 `providers/pkcs11/attributes.py`). Pure: no backend calls.
use indexmap::IndexMap;
use r2_config::model::CustomAttributeDef;
use r2_core::catalog::cka;
use r2_core::error::{ConsoleError, Result};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate};
use r2_core::text::py_repr;

use crate::backend::{BResult, BackendError, Ckr};
use crate::ckr::rv;

/// Size of a native `CK_ULONG` (4 bytes on Windows, 8 on LP64).
pub(crate) const ULONG_SIZE: usize = std::mem::size_of::<cryptoki_sys::CK_ULONG>();

/// The symbolic-constant prefixes a ULONG value may carry (c2 `_SYMBOL_PREFIXES`).
const SYMBOL_PREFIXES: [&str; 4] = ["CKO_", "CKK_", "CKC_", "CKM_"];

pub(crate) fn is_symbol(text: &str) -> bool {
    SYMBOL_PREFIXES.iter().any(|p| text.starts_with(p))
}

/// Native-endian CK_ULONG bytes; a value above CK_ULONG (32-bit Windows) is the token's
/// CKR_ATTRIBUTE_VALUE_INVALID (§4.5.5 narrowing rule).
pub(crate) fn ulong_bytes(value: u64) -> BResult<Vec<u8>> {
    let narrow = cryptoki_sys::CK_ULONG::try_from(value).map_err(|_| {
        BackendError::Ckr(Ckr { code: rv::CKR_ATTRIBUTE_VALUE_INVALID, function: "ulong" })
    })?;
    Ok(narrow.to_ne_bytes().to_vec())
}

/// Native-endian integer of any length (c2 `int.from_bytes(data, sys.byteorder)`), kept to
/// its low 64 bits.
pub(crate) fn decode_ulong(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    if cfg!(target_endian = "little") {
        for (dst, src) in buf.iter_mut().zip(data.iter()) {
            *dst = *src;
        }
        u64::from_le_bytes(buf)
    } else {
        let tail = &data[data.len().saturating_sub(8)..];
        buf[8 - tail.len()..].copy_from_slice(tail);
        u64::from_be_bytes(buf)
    }
}

/// One converted template attribute (c2 `Pkcs11Attr`): `value` normalized per `kind`
/// (BOOL → Bool, BYTES → Bytes, STR → Str, ULONG → Ulong or Symbol); `vendor` marks
/// templates.custom_attributes codes, byte-encoded explicitly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pkcs11Attr {
    pub name: String,
    pub code: u64,
    pub kind: AttrKind,
    pub value: AttrValue,
    pub vendor: bool,
}

/// c2 `_normalize`: coerce `value` to the shape `kind` demands; Param on mismatch.
pub(crate) fn normalize(name: &str, kind: AttrKind, value: &AttrValue) -> Result<AttrValue> {
    let type_name = value.py_type_name();
    match kind {
        AttrKind::Bool => match value {
            AttrValue::Bool(_) => Ok(value.clone()),
            _ => Err(ConsoleError::param(
                format!("template attribute {name} expects a boolean, got {type_name}"),
                name,
            )),
        },
        AttrKind::Ulong => match value {
            AttrValue::Bool(_) => Err(ConsoleError::param(
                format!("template attribute {name} expects an integer, got a boolean"),
                name,
            )),
            AttrValue::Ulong(_) => Ok(value.clone()),
            AttrValue::Str(text) | AttrValue::Symbol(text) if is_symbol(text) => {
                Ok(AttrValue::Symbol(text.clone()))
            }
            _ => Err(ConsoleError::param(
                format!(
                    "template attribute {name} expects an integer or a CKO_/CKK_/CKC_/CKM_ \
                     constant name, got {}",
                    value.py_repr()
                ),
                name,
            )),
        },
        AttrKind::Bytes => match value {
            AttrValue::Bytes(_) => Ok(value.clone()),
            _ => Err(ConsoleError::param(
                format!("template attribute {name} expects bytes, got {type_name}"),
                name,
            )
            .with_hint("use a 0x… hex value")),
        },
        AttrKind::Str => match value {
            AttrValue::Str(text) | AttrValue::Symbol(text) => Ok(AttrValue::Str(text.clone())),
            _ => Err(ConsoleError::param(
                format!("template attribute {name} expects a string, got {type_name}"),
                name,
            )),
        },
    }
}

/// Convert a KeyTemplate into ordered attribute entries (§4.7): ENABLED rows only; names
/// resolve through CKA_CATALOG first, then `custom` (kind from the definition); unknown →
/// Param "unknown PKCS#11 attribute {name!r}".
pub(crate) fn template_to_attrs(
    template: &KeyTemplate,
    custom: &IndexMap<String, CustomAttributeDef>,
) -> Result<Vec<Pkcs11Attr>> {
    let mut entries = Vec::new();
    for attr in template.enabled_attrs() {
        let (code, kind, vendor) = if let Some(entry) = cka(&attr.name) {
            (entry.code, entry.kind, false)
        } else if let Some(def) = custom.get(&attr.name) {
            (def.code, def.kind, true)
        } else {
            return Err(ConsoleError::param(
                format!("unknown PKCS#11 attribute {}", py_repr(&attr.name)),
                attr.name.clone(),
            )
            .with_hint("known names come from CKA_CATALOG or templates.custom_attributes"));
        };
        entries.push(Pkcs11Attr {
            name: attr.name.clone(),
            code,
            kind,
            value: normalize(&attr.name, kind, &attr.value)?,
            vendor,
        });
    }
    Ok(entries)
}

/// (CKA_LABEL, CKA_ID) from the ENABLED identity rows of the given templates (c2
/// `template_identity`); distinct values across templates and empty values → Param.
pub(crate) fn template_identity(
    templates: &[Option<&KeyTemplate>],
) -> Result<(Option<String>, Option<Vec<u8>>)> {
    let mut label: Option<String> = None;
    let mut key_id: Option<Vec<u8>> = None;
    for template in templates.iter().flatten() {
        for attr in template.enabled_attrs() {
            if attr.name == "CKA_LABEL" {
                let value = match &attr.value {
                    AttrValue::Str(text) | AttrValue::Symbol(text) if !text.is_empty() => text,
                    _ => {
                        return Err(ConsoleError::param(
                            "template CKA_LABEL expects a non-empty string",
                            "CKA_LABEL",
                        ));
                    }
                };
                if let Some(previous) = &label
                    && previous != value
                {
                    return Err(ConsoleError::param(
                        format!(
                            "templates disagree on CKA_LABEL ({} vs {}) — keypair objects share \
                             one label",
                            py_repr(previous),
                            py_repr(value)
                        ),
                        "CKA_LABEL",
                    ));
                }
                label = Some(value.clone());
            } else if attr.name == "CKA_ID" {
                let value = match &attr.value {
                    AttrValue::Bytes(bytes) if !bytes.is_empty() => bytes,
                    _ => {
                        return Err(ConsoleError::param(
                            "template CKA_ID expects non-empty bytes",
                            "CKA_ID",
                        )
                        .with_hint("use a 0x… hex value"));
                    }
                };
                if let Some(previous) = &key_id
                    && previous != value
                {
                    return Err(ConsoleError::param(
                        format!(
                            "templates disagree on CKA_ID (0x{} vs 0x{}) — keypair objects share \
                             one id",
                            hex(previous),
                            hex(value)
                        ),
                        "CKA_ID",
                    ));
                }
                key_id = Some(value.clone());
            }
        }
    }
    Ok((label, key_id))
}

/// Lower-case hex (c2 `bytes.hex()`).
pub(crate) fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// c2 `encode_vendor_value`: BOOL → one byte (truthiness), ULONG → native-endian CK_ULONG
/// (Ulong ONLY), STR → UTF-8, BYTES → verbatim (Bytes only).
pub(crate) fn encode_vendor_value(kind: AttrKind, value: &AttrValue) -> Result<Vec<u8>> {
    match kind {
        AttrKind::Bool => {
            let truthy = match value {
                AttrValue::Bool(b) => *b,
                AttrValue::Ulong(n) => *n != 0,
                AttrValue::Str(t) | AttrValue::Symbol(t) => !t.is_empty(),
                AttrValue::Bytes(b) => !b.is_empty(),
            };
            Ok(vec![u8::from(truthy)])
        }
        AttrKind::Ulong => match value {
            AttrValue::Ulong(n) => ulong_bytes(*n).map_err(|_| {
                ConsoleError::param(
                    format!("vendor ULONG attribute expects an integer, got {}", value.py_repr()),
                    value.render_info(),
                )
            }),
            _ => Err(ConsoleError::param(
                format!("vendor ULONG attribute expects an integer, got {}", value.py_repr()),
                value.render_info(),
            )),
        },
        AttrKind::Str => Ok(match value {
            AttrValue::Str(t) | AttrValue::Symbol(t) => t.as_bytes().to_vec(),
            other => other.render_info().into_bytes(),
        }),
        AttrKind::Bytes => match value {
            AttrValue::Bytes(b) => Ok(b.clone()),
            _ => Err(ConsoleError::param(
                format!("vendor BYTES attribute expects bytes, got {}", value.py_type_name()),
                value.render_info(),
            )),
        },
    }
}

/// Inverse of `encode_vendor_value`: BOOL → any nonzero byte, ULONG → native-endian,
/// STR → UTF-8 with replacement, BYTES → as-is.
pub(crate) fn decode_vendor_value(kind: AttrKind, data: &[u8]) -> AttrValue {
    match kind {
        AttrKind::Bool => AttrValue::Bool(data.iter().any(|b| *b != 0)),
        AttrKind::Ulong => AttrValue::Ulong(decode_ulong(data)),
        AttrKind::Str => AttrValue::Str(String::from_utf8_lossy(data).into_owned()),
        AttrKind::Bytes => AttrValue::Bytes(data.to_vec()),
    }
}
