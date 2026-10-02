//! In-crate FakeBackend test modules (spec §4.10.4; R5a creates, R5b appends its `mod` lines).
use std::collections::BTreeMap;
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::{CustomAttributeDef, Pkcs11InstanceConfig};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_provider::{Provider, TokenInfo};
use secrecy::SecretString;

use crate::Pkcs11Provider;
use crate::backend::fake::FakeBackend;

mod attributes;
mod capability;
mod catalog;
mod ckr;
mod objects;
mod session;
mod softhsm_detect;

pub(crate) const USER_PIN: &str = "1234";

pub(crate) fn pin(text: &str) -> SecretString {
    SecretString::from(text.to_string())
}

pub(crate) fn config(name: &str) -> Pkcs11InstanceConfig {
    Pkcs11InstanceConfig::new(name, "/fake/libfake.so")
}

/// A provider "hsm" over `backend` with the given custom maps.
pub(crate) fn provider_with(
    backend: &Rc<FakeBackend>,
    custom_mechanisms: BTreeMap<u64, String>,
    custom_attributes: IndexMap<String, CustomAttributeDef>,
) -> Pkcs11Provider {
    let shared: Rc<dyn crate::backend::Backend> = backend.clone();
    Pkcs11Provider::with_backend(
        "hsm",
        config("hsm"),
        custom_mechanisms,
        custom_attributes,
        shared,
    )
}

pub(crate) fn provider_over(backend: &Rc<FakeBackend>) -> Pkcs11Provider {
    provider_with(backend, BTreeMap::new(), IndexMap::new())
}

/// The token of `slot` as `list_tokens` reports it.
pub(crate) fn token_at(provider: &Pkcs11Provider, slot: u64) -> TokenInfo {
    provider
        .list_tokens()
        .unwrap()
        .into_iter()
        .find(|t| t.slot_id == slot)
        .unwrap()
}

/// c2's `provider` fixture: a FakeBackend (slot 0) and a provider logged in to it.
pub(crate) fn logged_in() -> (Rc<FakeBackend>, Pkcs11Provider) {
    let backend = Rc::new(FakeBackend::new());
    let provider = provider_over(&backend);
    let token = token_at(&provider, 0);
    provider.login(&token, &pin(USER_PIN), false).unwrap();
    (backend, provider)
}

pub(crate) fn tpl(attrs: Vec<TemplateAttr>) -> KeyTemplate {
    KeyTemplate::new(attrs)
}

pub(crate) fn boolean(name: &str, value: bool) -> TemplateAttr {
    TemplateAttr::new(name, AttrKind::Bool, AttrValue::Bool(value))
}

pub(crate) fn ulong_attr(name: &str, value: AttrValue) -> TemplateAttr {
    TemplateAttr::new(name, AttrKind::Ulong, value)
}

pub(crate) fn bytes_attr(name: &str, value: &[u8]) -> TemplateAttr {
    TemplateAttr::new(name, AttrKind::Bytes, AttrValue::Bytes(value.to_vec()))
}

pub(crate) fn str_attr(name: &str, value: &str) -> TemplateAttr {
    TemplateAttr::new(name, AttrKind::Str, AttrValue::Str(value.to_string()))
}

pub(crate) fn symbol(text: &str) -> AttrValue {
    AttrValue::Symbol(text.to_string())
}

/// SENSITIVE=false / EXTRACTABLE=true template (c2 `exportable()`).
pub(crate) fn exportable() -> KeyTemplate {
    tpl(vec![
        boolean("CKA_SENSITIVE", false),
        boolean("CKA_EXTRACTABLE", true),
    ])
}

/// The stored attribute map of the (first) object labelled `label`.
pub(crate) fn object_of(backend: &FakeBackend, label: &str) -> BTreeMap<u64, Vec<u8>> {
    backend
        .objects()
        .into_iter()
        .map(|(_, attrs)| attrs)
        .find(|attrs| attrs.get(&0x0003).map(Vec::as_slice) == Some(label.as_bytes()))
        .unwrap_or_else(|| panic!("no fake object labelled {label:?}"))
}

/// Native-endian CK_ULONG bytes.
pub(crate) fn ul(value: u64) -> Vec<u8> {
    crate::attributes::ulong_bytes(value).unwrap()
}
