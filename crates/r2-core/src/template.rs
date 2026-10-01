// R0 skeleton — owner R1 (generated from spec §4)
use crate::error::{ConsoleError, Result};
use std::fmt;
use std::str::FromStr;

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
        unimplemented!("R1")
    }
}
impl fmt::Display for AttrKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        unimplemented!("R1")
    }
}
/// Exact tokens; else Generic "unknown attribute kind {s!r}".
impl FromStr for AttrKind {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        let _ = s;
        Err(crate::error::ConsoleError::not_implemented("R1"))
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
        unimplemented!("R1")
    }
    /// Editor / outcome-table cell (c2 `_display`/`_value_text`): Bool "true"/"false",
    /// Bytes "0x" + lower-case hex, Ulong decimal, Str/Symbol verbatim.
    pub fn render_value(&self) -> String {
        unimplemented!("R1")
    }
    /// `key info` attribute cell (c2 `_attr_text` = Python str()): Bool "True"/"False",
    /// Bytes "0x" + hex, Ulong decimal, Str/Symbol verbatim.
    pub fn render_info(&self) -> String {
        unimplemented!("R1")
    }
    /// Python `type(value).__name__` of the c2 value: Bool "bool", Ulong "int", Bytes
    /// "bytes", Str/Symbol "str" (the "got {T}" part of c2's mismatch texts).
    pub fn py_type_name(&self) -> &'static str {
        unimplemented!("R1")
    }
    /// Python `repr()` of the c2 value: Bool "True"/"False", Ulong decimal, Bytes
    /// `text::py_bytes_repr`, Str/Symbol `text::py_repr`.
    pub fn py_repr(&self) -> String {
        unimplemented!("R1")
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
        let _ = (name, kind, value);
        unimplemented!("R1")
    }
    pub fn disabled(self) -> Self {
        unimplemented!("R1")
    }
    pub fn locked(self) -> Self {
        unimplemented!("R1")
    }
}

/// Ordered, as rendered by the editor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyTemplate {
    pub attrs: Vec<TemplateAttr>,
}
impl KeyTemplate {
    pub fn new(attrs: Vec<TemplateAttr>) -> Self {
        let _ = attrs;
        unimplemented!("R1")
    }
    pub fn get(&self, name: &str) -> Option<&TemplateAttr> {
        let _ = name;
        unimplemented!("R1")
    }
    pub fn get_mut(&mut self, name: &str) -> Option<&mut TemplateAttr> {
        let _ = name;
        unimplemented!("R1")
    }
    /// Set the value of an existing attribute (kind unchanged). Unknown name → Param
    /// "unknown template attribute {name!r}" (param_name = name, hint "known attributes:
    /// {names joined ', '}" or "known attributes: (no attributes)"). The editor's `add`
    /// flow appends a TemplateAttr built from CKA_CATALOG / templates.custom_attributes.
    pub fn set(&mut self, name: &str, value: AttrValue) -> Result<()> {
        let _ = (name, value);
        Err(crate::error::ConsoleError::not_implemented("R1"))
    }
    pub fn enabled_attrs(&self) -> Vec<&TemplateAttr> {
        unimplemented!("R1")
    }
}
