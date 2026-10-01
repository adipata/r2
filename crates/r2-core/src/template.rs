// Attribute template model (spec §4.7; owner R1).
use crate::error::{ConsoleError, Result};
use std::fmt;
use std::str::FromStr;

use crate::text::{py_bool, py_bytes_repr, py_repr};

/// Token: "bool" | "str" | "bytes" | "ulong".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttrKind {
    Bool,
    Str,
    Bytes,
    Ulong,
}
impl AttrKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AttrKind::Bool => "bool",
            AttrKind::Str => "str",
            AttrKind::Bytes => "bytes",
            AttrKind::Ulong => "ulong",
        }
    }
}
impl fmt::Display for AttrKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Exact tokens; else Generic "unknown attribute kind {s!r}".
impl FromStr for AttrKind {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        [
            AttrKind::Bool,
            AttrKind::Str,
            AttrKind::Bytes,
            AttrKind::Ulong,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == s)
        .ok_or_else(|| ConsoleError::generic(format!("unknown attribute kind {}", py_repr(s))))
    }
}

/// A template / attribute value (c2 `object`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AttrValue {
    Bool(bool),
    Str(String),
    Bytes(Vec<u8>),
    Ulong(u64),
    /// A symbolic ULONG constant name: "CKO_…", "CKK_…", "CKC_…" or "CKM_…" (resolved by
    /// the PKCS#11 provider at conversion; c2 kept such strings verbatim).
    Symbol(String),
}
impl AttrValue {
    /// The kind a config/YAML value infers (§4.7 rule): Bool→Bool, Ulong/Symbol→Ulong,
    /// Bytes→Bytes, Str→Str.
    pub fn inferred_kind(&self) -> AttrKind {
        match self {
            AttrValue::Bool(_) => AttrKind::Bool,
            AttrValue::Str(_) => AttrKind::Str,
            AttrValue::Bytes(_) => AttrKind::Bytes,
            AttrValue::Ulong(_) | AttrValue::Symbol(_) => AttrKind::Ulong,
        }
    }
    /// Editor / outcome-table cell (c2 `_display`/`_value_text`): Bool "true"/"false",
    /// Bytes "0x" + lower-case hex, Ulong decimal, Str/Symbol verbatim.
    pub fn render_value(&self) -> String {
        match self {
            AttrValue::Bool(true) => "true".to_owned(),
            AttrValue::Bool(false) => "false".to_owned(),
            AttrValue::Bytes(bytes) => format!("0x{}", hex::encode(bytes)),
            AttrValue::Ulong(value) => value.to_string(),
            AttrValue::Str(text) | AttrValue::Symbol(text) => text.clone(),
        }
    }
    /// `key info` attribute cell (c2 `_attr_text` = Python str()): Bool "True"/"False",
    /// Bytes "0x" + hex, Ulong decimal, Str/Symbol verbatim.
    pub fn render_info(&self) -> String {
        match self {
            AttrValue::Bool(value) => py_bool(*value).to_owned(),
            other => other.render_value(),
        }
    }
    /// Python `type(value).__name__` of the c2 value: Bool "bool", Ulong "int", Bytes
    /// "bytes", Str/Symbol "str" (the "got {T}" part of c2's mismatch texts).
    pub fn py_type_name(&self) -> &'static str {
        match self {
            AttrValue::Bool(_) => "bool",
            AttrValue::Ulong(_) => "int",
            AttrValue::Bytes(_) => "bytes",
            AttrValue::Str(_) | AttrValue::Symbol(_) => "str",
        }
    }
    /// Python `repr()` of the c2 value: Bool "True"/"False", Ulong decimal, Bytes
    /// `text::py_bytes_repr`, Str/Symbol `text::py_repr`.
    pub fn py_repr(&self) -> String {
        match self {
            AttrValue::Bool(value) => py_bool(*value).to_owned(),
            AttrValue::Ulong(value) => value.to_string(),
            AttrValue::Bytes(bytes) => py_bytes_repr(bytes),
            AttrValue::Str(text) | AttrValue::Symbol(text) => py_repr(text),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateAttr {
    /// "CKA_TOKEN".
    pub name: String,
    pub kind: AttrKind,
    pub value: AttrValue,
    /// false → the attribute is OMITTED from the PKCS#11 call entirely.
    pub enabled: bool,
    /// true → the operator cannot toggle/edit/disable it (CKA_CLASS / CKA_KEY_TYPE).
    pub locked: bool,
}
impl TemplateAttr {
    /// enabled = true, locked = false.
    pub fn new(name: impl Into<String>, kind: AttrKind, value: AttrValue) -> Self {
        Self {
            name: name.into(),
            kind,
            value,
            enabled: true,
            locked: false,
        }
    }
    pub fn disabled(self) -> Self {
        Self {
            enabled: false,
            ..self
        }
    }
    pub fn locked(self) -> Self {
        Self {
            locked: true,
            ..self
        }
    }
}

/// Ordered, as rendered by the editor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyTemplate {
    pub attrs: Vec<TemplateAttr>,
}
impl KeyTemplate {
    pub fn new(attrs: Vec<TemplateAttr>) -> Self {
        Self { attrs }
    }
    pub fn get(&self, name: &str) -> Option<&TemplateAttr> {
        self.attrs.iter().find(|attr| attr.name == name)
    }
    pub fn get_mut(&mut self, name: &str) -> Option<&mut TemplateAttr> {
        self.attrs.iter_mut().find(|attr| attr.name == name)
    }
    /// Set the value of an existing attribute (kind unchanged). Unknown name → Param
    /// "unknown template attribute {name!r}" (param_name = name, hint "known attributes:
    /// {names joined ', '}" or "known attributes: (no attributes)"). The editor's `add`
    /// flow appends a TemplateAttr built from CKA_CATALOG / templates.custom_attributes.
    pub fn set(&mut self, name: &str, value: AttrValue) -> Result<()> {
        if let Some(attr) = self.get_mut(name) {
            attr.value = value;
            return Ok(());
        }
        // c2: `", ".join(a.name for a in self.attrs) or "(no attributes)"`
        let mut known = self
            .attrs
            .iter()
            .map(|attr| attr.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if known.is_empty() {
            known = "(no attributes)".to_owned();
        }
        Err(ConsoleError::param(
            format!("unknown template attribute {}", py_repr(name)),
            name,
        )
        .with_hint(format!("known attributes: {known}")))
    }
    pub fn enabled_attrs(&self) -> Vec<&TemplateAttr> {
        self.attrs.iter().filter(|attr| attr.enabled).collect()
    }
}
