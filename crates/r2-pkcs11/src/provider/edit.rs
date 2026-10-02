//! read_key_template, update_key, read_full_template (spec §5.15, §5.16; c2 provider.py
//! `read_key_template`, `read_full_template`, `update_key`, `_read_one_attr`,
//! `_coerce_attr`, `_apply_one_attr`, `_ensure_rename_free`, `_key_type_symbol`).
//! Owner R5b.
use r2_core::catalog::{CKA_CATALOG, cka as catalog_entry};
use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::keys::{KeyClass, KeyInfo, KeyRef};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_provider::*;
use zeroize::Zeroizing;

use super::crypto::console_kind;
use super::objects::{cka, ckk};
use super::{OResult, OpError, Pkcs11Provider};
use crate::attributes::{decode_ulong, decode_vendor_value, template_to_attrs, utf8_ignore};
use crate::backend::{BackendError, RawAttr};
use crate::ckr::{self, rv};

/// Attributes offered by read_key_template besides the identity rows (c2 `_EDIT_COMMON`
/// + `_EDIT_BY_CLASS`): the editable storage/policy surface per object class.
const EDIT_COMMON: [&str; 3] = ["CKA_TOKEN", "CKA_PRIVATE", "CKA_MODIFIABLE"];

fn edit_by_class(class: KeyClass) -> &'static [&'static str] {
    match class {
        KeyClass::Secret => &[
            "CKA_SENSITIVE",
            "CKA_EXTRACTABLE",
            "CKA_ENCRYPT",
            "CKA_DECRYPT",
            "CKA_SIGN",
            "CKA_VERIFY",
            "CKA_WRAP",
            "CKA_UNWRAP",
            "CKA_DERIVE",
        ],
        KeyClass::Private => &[
            "CKA_SENSITIVE",
            "CKA_EXTRACTABLE",
            "CKA_DECRYPT",
            "CKA_SIGN",
            "CKA_SIGN_RECOVER",
            "CKA_UNWRAP",
            "CKA_DERIVE",
            "CKA_ALWAYS_AUTHENTICATE",
        ],
        KeyClass::Public => &[
            "CKA_ENCRYPT",
            "CKA_VERIFY",
            "CKA_VERIFY_RECOVER",
            "CKA_WRAP",
            "CKA_DERIVE",
            "CKA_TRUSTED",
        ],
        KeyClass::Certificate => &["CKA_TRUSTED", "CKA_CERTIFICATE_CATEGORY"],
        KeyClass::Data => &["CKA_APPLICATION", "CKA_OBJECT_ID"],
    }
}

fn is_recoverable(err: &BackendError) -> bool {
    matches!(
        ckr::code_of(err),
        Some(rv::CKR_SESSION_HANDLE_INVALID | rv::CKR_DEVICE_REMOVED)
    )
}

/// PyKCS11 `CK_ATTRIBUTE_SMART::GetNum`: the native-endian CK_ULONG when the value is
/// exactly `sizeof(CK_ULONG)` bytes long, else 0. Kept unsigned: PyKCS11 returned a signed
/// C long, so c2 showed values ≥ 2^63 negative (CK_UNAVAILABLE_INFORMATION → `-1`) — §11
/// D18; `AttrValue::Ulong` is a u64.
fn pykcs11_num(raw: &[u8]) -> u64 {
    if raw.len() == std::mem::size_of::<std::ffi::c_ulong>() {
        decode_ulong(raw)
    } else {
        0
    }
}

/// c2 `_coerce_attr` over what PyKCS11's `getAttributeValue` decoded: BOOL is `GetBool`
/// (true only for a single nonzero byte), ULONG is `GetNum` (see [`pykcs11_num`]) — except
/// CKA_CERTIFICATE_CATEGORY, which PyKCS11 returns as bytes and c2 decoded natively
/// (`int.from_bytes`), an empty value reading as unreadable (None: no row) —, STR UTF-8
/// with invalid sequences dropped, BYTES verbatim.
fn coerce(name: &str, kind: AttrKind, raw: &[u8]) -> Option<AttrValue> {
    match kind {
        AttrKind::Bool => Some(AttrValue::Bool(raw.len() == 1 && raw[0] != 0)),
        AttrKind::Ulong if name == "CKA_CERTIFICATE_CATEGORY" => {
            (!raw.is_empty()).then(|| decode_vendor_value(AttrKind::Ulong, raw))
        }
        AttrKind::Ulong => Some(AttrValue::Ulong(pykcs11_num(raw))),
        AttrKind::Str => Some(AttrValue::Str(utf8_ignore(raw))),
        AttrKind::Bytes => Some(AttrValue::Bytes(raw.to_vec())),
    }
}

impl Pkcs11Provider {
    /// c2 `_read_one_attr`: one-attribute read; any non-recoverable failure reads as None
    /// (the token refuses it), a recoverable one propagates so `op` can recover.
    fn read_one_attr(&self, handle: u64, code: u64) -> OResult<Option<Zeroizing<Vec<u8>>>> {
        match self.backend().get_attr(handle, code) {
            Ok(value) => Ok(value),
            Err(err) if is_recoverable(&err) => Err(err.into()),
            Err(_) => Ok(None),
        }
    }

    /// Symbolic CKK_* name of the object's actual key type; None for classes without one
    /// (certificates, data) or when the token withholds it and the algorithm has no name
    /// (c2 `_key_type_symbol`).
    fn key_type_symbol(&self, handle: u64, key: &KeyInfo) -> OResult<Option<String>> {
        if matches!(key.key_class, KeyClass::Certificate | KeyClass::Data) {
            return Ok(None);
        }
        if let Some(raw) = self.read_one_attr(handle, cka::KEY_TYPE)? {
            // PyKCS11 decodes CKA_KEY_TYPE with GetNum: any readable value is an int
            return Ok(Some(crate::catalog::ckk_symbol(pykcs11_num(&raw))));
        }
        Ok(ckk(key.algorithm)
            .and_then(crate::catalog::ckk_name)
            .map(str::to_string))
    }

    /// The decoded templates.custom_attributes rows the token returns (non-empty values).
    fn vendor_rows(&self, handle: u64) -> OResult<Vec<TemplateAttr>> {
        let mut rows = Vec::new();
        for (name, definition) in self.custom_attributes() {
            let raw = self
                .read_one_attr(handle, definition.code)?
                .filter(|v| !v.is_empty());
            if let Some(raw) = raw {
                rows.push(TemplateAttr::new(
                    name.clone(),
                    definition.kind,
                    decode_vendor_value(definition.kind, &raw),
                ));
            }
        }
        Ok(rows)
    }

    /// Editor-seedable snapshot of the object's current attributes (§5.15).
    pub(crate) fn read_key_template_impl(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        self.op("attribute read", || {
            let handle = self.find_handle(key)?;
            let mut attrs = vec![
                TemplateAttr::new(
                    "CKA_CLASS",
                    AttrKind::Ulong,
                    AttrValue::Symbol(key.key_class.cko_symbol().to_string()),
                )
                .locked(),
            ];
            if let Some(key_type) = self.key_type_symbol(handle, key)? {
                attrs.push(
                    TemplateAttr::new("CKA_KEY_TYPE", AttrKind::Ulong, AttrValue::Symbol(key_type))
                        .locked(),
                );
            }
            attrs.push(TemplateAttr::new(
                "CKA_LABEL",
                AttrKind::Str,
                AttrValue::Str(key.key_ref.label.clone()),
            ));
            if key.key_class != KeyClass::Data {
                // data objects carry no CKA_ID (§4.3)
                let row = TemplateAttr::new(
                    "CKA_ID",
                    AttrKind::Bytes,
                    AttrValue::Bytes(key.key_ref.key_id.clone().unwrap_or_default()),
                );
                attrs.push(if key.key_ref.key_id.is_some() {
                    row
                } else {
                    row.disabled()
                });
            }
            for name in EDIT_COMMON.iter().chain(edit_by_class(key.key_class)) {
                let Some(entry) = catalog_entry(name) else {
                    continue;
                };
                let raw = self.read_one_attr(handle, entry.code)?;
                if let Some(value) = raw.and_then(|raw| coerce(name, entry.kind, &raw)) {
                    attrs.push(TemplateAttr::new(*name, entry.kind, value));
                }
            }
            attrs.extend(self.vendor_rows(handle)?);
            Ok(KeyTemplate::new(attrs))
        })
    }

    /// Complete attribute snapshot for `key template` (§5.16): every CKA_CATALOG attr the
    /// token returns (CKA_CLASS/CKA_KEY_TYPE symbolic) plus the vendor attrs.
    pub(crate) fn read_full_template_impl(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        self.op("full attribute read", || {
            let handle = self.find_handle(key)?;
            let mut attrs = Vec::new();
            for entry in CKA_CATALOG {
                match entry.name {
                    "CKA_CLASS" => attrs.push(TemplateAttr::new(
                        entry.name,
                        entry.kind,
                        AttrValue::Symbol(key.key_class.cko_symbol().to_string()),
                    )),
                    "CKA_KEY_TYPE" => {
                        if let Some(key_type) = self.key_type_symbol(handle, key)? {
                            attrs.push(TemplateAttr::new(
                                entry.name,
                                entry.kind,
                                AttrValue::Symbol(key_type),
                            ));
                        }
                    }
                    _ => {
                        let raw = self.read_one_attr(handle, entry.code)?;
                        if let Some(value) =
                            raw.and_then(|raw| coerce(entry.name, entry.kind, &raw))
                        {
                            attrs.push(TemplateAttr::new(entry.name, entry.kind, value));
                        }
                    }
                }
            }
            attrs.extend(self.vendor_rows(handle)?);
            Ok(KeyTemplate::new(attrs))
        })
    }

    /// One C_SetAttributeValue call → one outcome; refusals never raise (c2
    /// `_apply_one_attr`). Recoverable errors propagate so `op` reruns the whole edit; a
    /// not-logged-in translation aborts the edit.
    fn apply_one_attr(
        &self,
        handle: u64,
        name: &str,
        rows: &[RawAttr],
    ) -> OResult<AttrEditOutcome> {
        match self.backend().set_attrs(handle, rows) {
            Ok(()) => {
                tracing::info!(target: "r2::pkcs11", "{}: attribute {} updated on handle", self.provider_name(), name);
                Ok(AttrEditOutcome {
                    name: name.to_string(),
                    applied: true,
                    detail: None,
                })
            }
            Err(err) if is_recoverable(&err) => Err(err.into()),
            Err(err) => {
                let translated = self.translate(err, &format!("set {name}"));
                if translated.kind == ErrorKind::AuthRequired {
                    return Err(translated.into());
                }
                Ok(AttrEditOutcome {
                    name: name.to_string(),
                    applied: false,
                    detail: Some(translated.message),
                })
            }
        }
    }

    /// §4.7 duplicate-identity guard for renames — excludes the edited object (c2
    /// `_ensure_rename_free`).
    fn ensure_rename_free(
        &self,
        handle: u64,
        key_class: KeyClass,
        new_label: &str,
        new_id: Option<&[u8]>,
    ) -> OResult<()> {
        if key_class == KeyClass::Certificate {
            return Ok(());
        }
        if !self
            .identity_twins(key_class, new_label, new_id, Some(handle))?
            .is_empty()
        {
            return Err(r2_provider::lookup::duplicate_identity(
                self.provider_name(),
                key_class,
                new_label,
                new_id,
                true,
            )
            .into());
        }
        Ok(())
    }

    /// Per-attribute edit of this object; refusals are outcomes (§5.15).
    pub(crate) fn update_key_impl(
        &self,
        key: &KeyInfo,
        changes: &KeyTemplate,
    ) -> Result<KeyEditResult> {
        let entries = template_to_attrs(changes, self.custom_attributes())?;
        if let Some(locked) = entries
            .iter()
            .find(|e| e.name == "CKA_CLASS" || e.name == "CKA_KEY_TYPE")
        {
            return Err(ConsoleError::param(
                format!("{} cannot be edited after creation", locked.name),
                locked.name.clone(),
            ));
        }
        let label_entry = entries.iter().find(|e| e.name == "CKA_LABEL");
        let id_entry = entries.iter().find(|e| e.name == "CKA_ID");
        let mut new_label = key.key_ref.label.clone();
        if let Some(entry) = label_entry {
            match &entry.value {
                AttrValue::Str(text) | AttrValue::Symbol(text) if !text.is_empty() => {
                    new_label = text.clone();
                }
                _ => {
                    return Err(ConsoleError::param(
                        "CKA_LABEL expects a non-empty string",
                        "CKA_LABEL",
                    ));
                }
            }
        }
        let mut new_id = key.key_ref.key_id.clone();
        if let Some(entry) = id_entry {
            if key.key_class == KeyClass::Data {
                return Err(
                    ConsoleError::param("data objects carry no CKA_ID (§4.3)", "CKA_ID")
                        .with_hint("data objects are identified by label alone"),
                );
            }
            match &entry.value {
                AttrValue::Bytes(id) if !id.is_empty() => new_id = Some(id.clone()),
                _ => {
                    return Err(
                        ConsoleError::param("CKA_ID expects non-empty bytes", "CKA_ID")
                            .with_hint("use a 0x… hex value"),
                    );
                }
            }
        }
        let rest: Vec<_> = entries
            .iter()
            .filter(|e| e.name != "CKA_LABEL" && e.name != "CKA_ID")
            .collect();
        let identity_changed = new_label != key.key_ref.label || new_id != key.key_ref.key_id;

        self.op("key edit", || {
            let mut outcomes = Vec::new();
            let handle = match self.find_handle(key) {
                Ok(handle) => handle,
                Err(err)
                    if identity_changed && console_kind(&err) == Some(&ErrorKind::KeyNotFound) =>
                {
                    // A recovery retry may find the rename already applied by the first
                    // pass — re-resolve under the new identity (§5.15).
                    let mut renamed = key.clone();
                    renamed.key_ref =
                        KeyRef::new(self.provider_name(), new_label.clone(), new_id.clone());
                    renamed.handle = None;
                    self.find_handle(&renamed)?
                }
                Err(err) => return Err(err),
            };
            if identity_changed {
                self.ensure_rename_free(handle, key.key_class, &new_label, new_id.as_deref())?;
            }
            for entry in &rest {
                let value = self.entry_value(entry)?;
                outcomes.push(self.apply_one_attr(handle, &entry.name, &[(entry.code, value)])?);
            }
            if label_entry.is_some() || id_entry.is_some() {
                // One batched C_SetAttributeValue — all-or-nothing, so an object never
                // ends up with the label changed but the id refused (§5.15).
                let mut rows: Vec<RawAttr> = Vec::new();
                let mut names = Vec::new();
                if label_entry.is_some() {
                    rows.push((cka::LABEL, Zeroizing::new(new_label.as_bytes().to_vec())));
                    names.push("CKA_LABEL");
                }
                if id_entry.is_some() {
                    rows.push((cka::ID, Zeroizing::new(new_id.clone().unwrap_or_default())));
                    names.push("CKA_ID");
                }
                let batch = self.apply_one_attr(handle, &names.join("/"), &rows)?;
                outcomes.extend(names.iter().map(|name| AttrEditOutcome {
                    name: (*name).to_string(),
                    applied: batch.applied,
                    detail: batch.detail.clone(),
                }));
            }
            let info = self.key_info(handle, key.key_class)?.ok_or_else(|| {
                OpError::Console(
                    ConsoleError::key_not_found(format!(
                        "key '{}' no longer available on {}",
                        key.key_ref.display(),
                        self.provider_name()
                    ))
                    .with_hint("refresh with `keys`"),
                )
            })?;
            Ok(KeyEditResult {
                key: info,
                outcomes,
            })
        })
    }
}
