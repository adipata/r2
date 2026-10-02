// Shared helpers of R8's console tests (providers_cmd, keys_cmd, keys_cmd_objects) — c2's
// `make_pair` / `RenderingIO` / `SpyEditor` helpers of tests/unit/console/test_keys_cmd.py
// and test_providers_cmd.py, plus the material fixtures of tests/unit/services/conftest.py
// (generated at test time: r2-testkit's OpenSSL fixtures and r2-core's writers).
#![allow(dead_code)]

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::OnceLock;

use r2_config::model::AppConfig;
use r2_core::error::Result;
use r2_core::formats::{self, Encoding};
use r2_core::io::{ConsoleIo, TemplateEditor};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_provider::{Provider, ProviderRegistry};
use r2_testkit::{FakeProvider, ScriptedIo, fixtures};

use crate::context::AppContext;
use crate::testing::CtxBuilder;

/// TemplateEditor double: records titles (and the seeds it was opened with); returns the
/// template unchanged, or applies a scripted mutation (c2 SpyEditor / EditingEditor /
/// CapturingEditor).
/// A scripted template mutation (c2 EditingEditor).
type Mutation = dyn Fn(&mut KeyTemplate);

#[derive(Default)]
pub(crate) struct SpyEditor {
    pub(crate) calls: RefCell<Vec<(KeyTemplate, String)>>,
    mutate: Option<Box<Mutation>>,
}
impl SpyEditor {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn editing(mutate: impl Fn(&mut KeyTemplate) + 'static) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            mutate: Some(Box::new(mutate)),
        }
    }
    pub(crate) fn titles(&self) -> Vec<String> {
        self.calls.borrow().iter().map(|(_, t)| t.clone()).collect()
    }
    pub(crate) fn seeds(&self) -> Vec<KeyTemplate> {
        self.calls.borrow().iter().map(|(t, _)| t.clone()).collect()
    }
}
impl TemplateEditor for SpyEditor {
    fn edit(&self, template: KeyTemplate, title: &str) -> Result<KeyTemplate> {
        self.calls
            .borrow_mut()
            .push((template.clone(), title.to_owned()));
        let mut working = template;
        if let Some(mutate) = &self.mutate {
            mutate(&mut working);
        }
        Ok(working)
    }
}

/// A wired test session: (ctx, io, mem-presenting fake, pkcs11-presenting fake, editor).
pub(crate) struct Pair {
    pub(crate) ctx: Rc<AppContext>,
    pub(crate) io: Rc<ScriptedIo>,
    pub(crate) mem: Rc<FakeProvider>,
    pub(crate) hsm: Rc<FakeProvider>,
    pub(crate) editor: Rc<SpyEditor>,
}

pub(crate) fn make_pair(answers: &[&str]) -> Pair {
    make_pair_with(answers, None, SpyEditor::new())
}

pub(crate) fn make_pair_with(
    answers: &[&str],
    config: Option<AppConfig>,
    editor: SpyEditor,
) -> Pair {
    let io = Rc::new(ScriptedIo::new(answers.iter().copied()));
    let mem = Rc::new(FakeProvider::new("mem"));
    let hsm = Rc::new(FakeProvider::new("hsm").with_type_name("pkcs11"));
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::clone(&mem) as Rc<dyn Provider>)
        .unwrap();
    registry
        .register(Rc::clone(&hsm) as Rc<dyn Provider>)
        .unwrap();
    let editor = Rc::new(editor);
    let mut builder = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .providers(registry)
        .editor(Rc::clone(&editor) as Rc<dyn TemplateEditor>);
    if let Some(config) = config {
        builder = builder.config(config);
    }
    Pair {
        ctx: builder.build(),
        io,
        mem,
        hsm,
        editor,
    }
}

/// A session over the given registry (c2 `make_ctx(io, providers=registry)`).
pub(crate) fn ctx_with(
    io: &Rc<ScriptedIo>,
    registry: ProviderRegistry,
    config: Option<AppConfig>,
) -> Rc<AppContext> {
    let mut builder = CtxBuilder::new(Rc::clone(io) as Rc<dyn ConsoleIo>).providers(registry);
    if let Some(config) = config {
        builder = builder.config(config);
    }
    builder.build()
}

/// Registry of the given fakes, in order.
pub(crate) fn registry_of(providers: &[Rc<FakeProvider>]) -> ProviderRegistry {
    let registry = ProviderRegistry::new();
    for provider in providers {
        registry
            .register(Rc::clone(provider) as Rc<dyn Provider>)
            .unwrap();
    }
    registry
}

/// Recorded calls of one method name.
pub(crate) fn calls_of(provider: &FakeProvider, method: &str) -> Vec<Vec<String>> {
    provider
        .calls()
        .into_iter()
        .filter(|call| call[0] == method)
        .collect()
}

// ---------------------------------------------------------------------------------------
// material fixtures
// ---------------------------------------------------------------------------------------

pub(crate) fn rsa_pkcs8_der() -> Vec<u8> {
    fixtures::rsa2048_pkcs8()
}

pub(crate) fn rsa_private_pem() -> Vec<u8> {
    formats::private_key_bytes(&rsa_pkcs8_der(), Encoding::Pem, None)
        .unwrap()
        .to_vec()
}

pub(crate) fn rsa_spki_der() -> Vec<u8> {
    formats::pkcs8_public_spki(&rsa_pkcs8_der()).unwrap()
}

/// An independently built self-signed certificate (CN "unit-test-cert"), cached.
pub(crate) fn rsa_cert_der() -> Vec<u8> {
    static CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    CACHE
        .get_or_init(|| fixtures::self_signed_cert(&rsa_pkcs8_der(), "unit-test-cert"))
        .clone()
}

pub(crate) fn sensitive_template() -> KeyTemplate {
    KeyTemplate::new(vec![
        TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(true)),
        TemplateAttr::new("CKA_EXTRACTABLE", AttrKind::Bool, AttrValue::Bool(false)),
    ])
}

pub(crate) fn aes_32() -> Vec<u8> {
    (0u8..32).collect()
}

pub(crate) fn aes_material() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, aes_32());
    material.size_bits = Some(256);
    material
}

pub(crate) fn private_material() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, rsa_pkcs8_der());
    material.size_bits = Some(2048);
    material
}

pub(crate) fn public_material() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Public, rsa_spki_der());
    material.size_bits = Some(2048);
    material
}

pub(crate) fn cert_material() -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, rsa_cert_der());
    material.size_bits = Some(2048);
    material
}

/// The (subject, issuer) rows of a DER certificate as `key info` shows them.
pub(crate) fn cert_subject(cert_der: &[u8]) -> String {
    r2_core::x509info::certificate_details(cert_der)
        .unwrap()
        .into_iter()
        .find(|(name, _)| name == "subject")
        .unwrap()
        .1
}

// ---------------------------------------------------------------------------------------
// DER helpers (CSR / PKCS#12 inspection without OpenSSL; r2-console may not use it)
// ---------------------------------------------------------------------------------------

/// The DER body of the first PEM block of `pem` (base64 decoded through the §4.4 codec).
pub(crate) fn pem_der(pem: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(pem).unwrap();
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    r2_core::codec::decode_data(&format!("b64:{body}"))
        .unwrap()
        .0
        .to_vec()
}

/// One DER TLV at the start of `data`: (header length, content length).
fn tlv(data: &[u8]) -> (usize, usize) {
    let first = data[1];
    if first < 0x80 {
        return (2, usize::from(first));
    }
    let count = usize::from(first & 0x7f);
    let len = data[2..2 + count]
        .iter()
        .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
    (2 + count, len)
}

/// The consecutive TLVs (whole encodings) inside a constructed TLV's content.
pub(crate) fn children(der: &[u8]) -> Vec<Vec<u8>> {
    let (header, len) = tlv(der);
    let mut content = &der[header..header + len];
    let mut out = Vec::new();
    while !content.is_empty() {
        let (h, l) = tlv(content);
        out.push(content[..h + l].to_vec());
        content = &content[h + l..];
    }
    out
}

/// (RFC 4514 subject, signature AlgorithmIdentifier DER) of a PEM CSR.
pub(crate) fn csr_subject_and_algorithm(pem: &[u8]) -> (String, Vec<u8>) {
    let der = pem_der(pem);
    let top = children(&der);
    let cri = children(&top[0]);
    (
        r2_core::x509info::rfc4514_string(&cri[1]).unwrap(),
        top[1].clone(),
    )
}

pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The members of a PKCS#12 as r2's pyca-port loads them (private, certificate, …).
pub(crate) fn load_p12(payload: &[u8], password: &str) -> Vec<KeyMaterial> {
    let password = password.to_owned();
    let mut cb = move |_: &str| Ok(secrecy::SecretString::from(password.clone()));
    r2_core::keyparse::parse_key_material(payload, r2_core::keyparse::KeyHint::Auto, Some(&mut cb))
        .unwrap()
}
