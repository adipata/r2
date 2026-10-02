//! The copy flow against a real SoftHSM2 token (R10, spec §5.5): port of c2
//! tests/integration/test_copy.py and the `copy_key` legs of
//! tests/integration/test_objects_softhsm.py. In-process MemoryProvider ⇄ Pkcs11Provider
//! (the r2-services ⇢ r2-memory / r2-pkcs11 dev edges). mem → SoftHSM, SoftHSM → mem and
//! SoftHSM → SoftHSM copies of an extractable AES key give identical ciphertexts; generic
//! (KWP), data and certificate copies work; a non-extractable copy offers the public part
//! and refuses on decline; a same-provider copy does not double-borrow.
//!
//! Feature `softhsm`; fails (never skips) without the fixture from
//! `scripts/softhsm-init.sh`. Every object is a session object (CKA_TOKEN=false) under a
//! unique label. Each test holds `global_state_lock` (a PKCS#11 module is process-global).
//! The SoftHSM → SoftHSM copy runs between two Pkcs11Provider instances holding separate
//! sessions on the shared token — the §5.5 transport-key protocol end to end (SoftHSM never
//! advertises RSA-AES-KEY-WRAP, so the route is AES-KEY-WRAP-PAD).
#![cfg(feature = "softhsm")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::BTreeMap;

use indexmap::IndexMap;
use r2_config::model::{Pkcs11InstanceConfig, TemplatesSection};
use r2_core::error::{ErrorKind, Result};
use r2_core::io::TemplateEditor;
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::{ParamValue, Params};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_memory::MemoryProvider;
use r2_pkcs11::Pkcs11Provider;
use r2_provider::{GenerateRequest, KeySelector, MechanismInvocation, Provider};
use r2_services::templatefile::EditorSeeding;
use r2_services::transfer::{TRANSPORT_PREFIX, copy_key};
use r2_testkit::softhsm::{softhsm_token, unique_label};
use r2_testkit::{ScriptedIo, fixtures, global_state_lock};
use secrecy::SecretString;
use std::cell::RefCell;

const IV: [u8; 16] = [
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
const PLAINTEXT: &[u8] = b"c2 copy acceptance data!!";
const GENERIC_KEY_LEN: u8 = 64; // >= every HMAC digest length (SoftHSM rule)
const DATA_VALUE: &[u8] = b"c2 data object \x00\x01\x02 -- opaque bytes";
const MESSAGE: &[u8] = b"what do ya want for nothing?";

fn key_bytes() -> Vec<u8> {
    (0u8..32).collect()
}

fn boolean(name: &str, value: bool) -> TemplateAttr {
    TemplateAttr::new(name, AttrKind::Bool, AttrValue::Bool(value))
}

fn templates_section() -> TemplatesSection {
    TemplatesSection {
        pkcs11: IndexMap::new(),
        pkcs11_raw: IndexMap::new(),
        custom_attributes: IndexMap::new(),
    }
}

/// Test TemplateEditor (c2 `SessionUsageEditor` / `SessionEditor`): makes every copy a
/// usable session object — CKA_TOKEN=false for all classes; secret/private objects also
/// get SENSITIVE=false, EXTRACTABLE=true and the given usages (public objects must not
/// carry those attributes — tokens reject them).
struct SessionEditor {
    usages: &'static [&'static str],
    titles: RefCell<Vec<String>>,
}

impl SessionEditor {
    /// test_copy.py's editor (encrypt/decrypt usage).
    fn crypt() -> Self {
        Self {
            usages: &["CKA_ENCRYPT", "CKA_DECRYPT"],
            titles: RefCell::new(Vec::new()),
        }
    }
    /// test_objects_softhsm.py's editor (sign/verify usage).
    fn mac() -> Self {
        Self {
            usages: &["CKA_SIGN", "CKA_VERIFY"],
            titles: RefCell::new(Vec::new()),
        }
    }
    fn titles(&self) -> Vec<String> {
        self.titles.borrow().clone()
    }
}

impl TemplateEditor for SessionEditor {
    fn edit(&self, mut template: KeyTemplate, title: &str) -> Result<KeyTemplate> {
        self.titles.borrow_mut().push(title.to_owned());
        let is_key = matches!(
            template.get("CKA_CLASS").map(|row| &row.value),
            Some(AttrValue::Symbol(cko)) if cko == "CKO_SECRET_KEY" || cko == "CKO_PRIVATE_KEY"
        );
        let mut wanted = vec![("CKA_TOKEN", false)];
        if is_key {
            wanted.extend([("CKA_SENSITIVE", false), ("CKA_EXTRACTABLE", true)]);
            wanted.extend(self.usages.iter().map(|usage| (*usage, true)));
        }
        for (name, value) in wanted {
            match template.get_mut(name) {
                Some(row) => {
                    row.value = AttrValue::Bool(value);
                    row.enabled = true;
                }
                None => template.attrs.push(boolean(name, value)),
            }
        }
        Ok(template)
    }
}

fn copy(
    source: &dyn Provider,
    key: &KeyInfo,
    dest: &dyn Provider,
    io: &ScriptedIo,
    editor: &SessionEditor,
    label: Option<&str>,
) -> Result<KeyInfo> {
    let templates = templates_section();
    let seeding = EditorSeeding {
        editor,
        templates: &templates,
        seeds: None,
    };
    copy_key(source, key, dest, io, &seeding, label, None)
}

fn cbc() -> MechanismInvocation {
    let mut params = Params::new();
    params.insert("iv".into(), ParamValue::Bytes(IV.to_vec()));
    params.insert("padding".into(), ParamValue::Enum("pkcs7".into()));
    MechanismInvocation::new("AES-CBC", params)
}

fn cbc_encrypt(provider: &dyn Provider, key: &KeyInfo) -> Vec<u8> {
    provider.encrypt(key, &cbc(), PLAINTEXT).unwrap()
}

fn hmac(hash: &str) -> MechanismInvocation {
    let mut params = Params::new();
    params.insert("hash".into(), ParamValue::Enum(hash.into()));
    MechanismInvocation::new("HMAC", params)
}

fn no_transport_left(providers: &[&dyn Provider]) -> bool {
    providers.iter().all(|provider| {
        provider
            .list_keys()
            .unwrap()
            .iter()
            .all(|info| !info.key_ref.label.starts_with(TRANSPORT_PREFIX))
    })
}

fn make_hsm(name: &str) -> Pkcs11Provider {
    let token = softhsm_token();
    let mut config = Pkcs11InstanceConfig::new(name, token.module_path.clone());
    config.slot = Some(token.slot);
    config.token_label = Some(token.token_label.clone());
    let provider = Pkcs11Provider::new(name, config, BTreeMap::new(), IndexMap::new());
    let info = provider
        .list_tokens()
        .unwrap()
        .into_iter()
        .find(|t| t.label == token.token_label)
        .expect("fixture token not found");
    provider
        .login(&info, &SecretString::from(token.user_pin.clone()), false)
        .unwrap();
    provider
}

/// Logged-in providers that shut down (log out, finalize) on drop, in reverse order.
struct Hsms(Vec<Pkcs11Provider>);
impl Drop for Hsms {
    fn drop(&mut self) {
        for provider in self.0.iter().rev() {
            let _ = provider.shutdown();
        }
    }
}

fn mem_key(mem: &MemoryProvider, label: &str) -> KeyInfo {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, key_bytes());
    material.size_bits = Some(256);
    mem.import_key(&material, label, None, None).unwrap()
}

/// Extractable (and sensitive → wrap-only) AES session key on the token.
fn hsm_key(provider: &Pkcs11Provider, label: &str) -> KeyInfo {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, key_bytes());
    material.size_bits = Some(256);
    let template = KeyTemplate::new(vec![
        boolean("CKA_TOKEN", false),
        boolean("CKA_SENSITIVE", true),
        boolean("CKA_EXTRACTABLE", true),
        boolean("CKA_ENCRYPT", true),
        boolean("CKA_DECRYPT", true),
    ]);
    provider
        .import_key(&material, label, Some(&template), None)
        .unwrap()
}

// ---------------------------------------------------------------------------------------
// extractable AES key: identical ciphertexts on every route (§5.5)
// ---------------------------------------------------------------------------------------

#[test]
fn test_mem_to_softhsm() {
    let _lock = global_state_lock();
    let hsms = Hsms(vec![make_hsm("hsm1")]);
    let hsm1 = &hsms.0[0];
    let mem = MemoryProvider::new("mem");
    let label = format!("{}-cp-mem2hsm", unique_label().as_str());
    let key = mem_key(&mem, &label);
    let baseline = cbc_encrypt(&mem, &key);
    let editor = SessionEditor::crypt();
    let copied = copy(&mem, &key, hsm1, &ScriptedIo::empty(), &editor, None).unwrap();
    assert_eq!(copied.key_ref.label, label); // destination label defaults to source
    assert_eq!(copied.key_ref.key_id.as_ref().map(Vec::len), Some(4));
    assert_eq!(cbc_encrypt(hsm1, &copied), baseline);
    assert!(!editor.titles().is_empty()); // §5.12: editor ran for the PKCS#11 destination
}

#[test]
fn test_softhsm_to_mem() {
    let _lock = global_state_lock();
    let hsms = Hsms(vec![make_hsm("hsm1")]);
    let hsm1 = &hsms.0[0];
    let mem = MemoryProvider::new("mem");
    let label = format!("{}-cp-hsm2mem", unique_label().as_str());
    let key = hsm_key(hsm1, &label);
    assert!(!key.exportable); // sensitive-but-extractable: wrap-only
    let baseline = cbc_encrypt(hsm1, &key);
    let editor = SessionEditor::crypt();
    let copied = copy(hsm1, &key, &mem, &ScriptedIo::empty(), &editor, None).unwrap();
    assert!(editor.titles().is_empty()); // memory destination → no editor (§5.12)
    // the copy IS the same key: exportable on memory, identical bytes
    assert_eq!(mem.export_key(&copied).unwrap().data.to_vec(), key_bytes());
    assert_eq!(cbc_encrypt(&mem, &copied), baseline);
    assert!(no_transport_left(&[hsm1, &mem]));
}

#[test]
fn test_softhsm_to_softhsm() {
    let _lock = global_state_lock();
    let hsms = Hsms(vec![make_hsm("hsm1"), make_hsm("hsm2")]);
    let (hsm1, hsm2) = (&hsms.0[0], &hsms.0[1]);
    let label = format!("{}-cp-hsm2hsm", unique_label().as_str());
    let key = hsm_key(hsm1, &label);
    let baseline = cbc_encrypt(hsm1, &key);
    let editor = SessionEditor::crypt();
    let copied = copy(hsm1, &key, hsm2, &ScriptedIo::empty(), &editor, None).unwrap();
    // hsm1/hsm2 share ONE SoftHSM token: the §5.5 same-token rule keeps a fresh CKA_ID
    // (no source-id inheritance), so label#id stays unambiguous
    assert_ne!(copied.key_ref.key_id, key.key_ref.key_id);
    let ciphertext = cbc_encrypt(hsm2, &copied);
    assert_eq!(ciphertext, baseline);
    // and the copy round-trips against the original
    assert_eq!(
        hsm2.decrypt(&copied, &cbc(), &ciphertext).unwrap().to_vec(),
        PLAINTEXT
    );
    assert!(no_transport_left(&[hsm1, hsm2]));
}

#[test]
fn test_all_three_routes_agree() {
    let _lock = global_state_lock();
    let hsms = Hsms(vec![make_hsm("hsm1"), make_hsm("hsm2")]);
    let (hsm1, hsm2) = (&hsms.0[0], &hsms.0[1]);
    let mem = MemoryProvider::new("mem");
    let label = format!("{}-cp-all", unique_label().as_str());
    let source = mem_key(&mem, &label);
    let baseline = cbc_encrypt(&mem, &source);
    let io = ScriptedIo::empty();
    let editor = SessionEditor::crypt();
    let on_hsm1 = copy(&mem, &source, hsm1, &io, &editor, None).unwrap(); // plain + editor
    let on_hsm2 = copy(hsm1, &on_hsm1, hsm2, &io, &editor, None).unwrap(); // wrap
    // fresh label — the original source still holds (label, no id) on mem and the §4.7
    // duplicate-identity guard refuses an exact twin
    let back_label = format!("{label}-back");
    let back_on_mem = copy(hsm2, &on_hsm2, &mem, &io, &editor, Some(&back_label)).unwrap();
    assert_eq!(cbc_encrypt(hsm1, &on_hsm1), baseline);
    assert_eq!(cbc_encrypt(hsm2, &on_hsm2), baseline);
    assert_eq!(cbc_encrypt(&mem, &back_on_mem), baseline);
    assert_eq!(
        mem.export_key(&back_on_mem).unwrap().data.to_vec(),
        key_bytes()
    );
    assert!(no_transport_left(&[&mem, hsm1, hsm2]));
}

#[test]
fn same_provider_copy_does_not_double_borrow_softhsm() {
    // §5.5/§4.5.2: `copy softhsm:x softhsm` — source and destination are ONE provider
    // (every method takes &self; no RefCell borrow is held across the calls)
    let _lock = global_state_lock();
    let hsms = Hsms(vec![make_hsm("hsm1")]);
    let hsm1 = &hsms.0[0];
    let label = format!("{}-cp-same", unique_label().as_str());
    let key = hsm_key(hsm1, &label);
    let baseline = cbc_encrypt(hsm1, &key);
    let copy_label = format!("{label}-twin");
    let editor = SessionEditor::crypt();
    let copied = copy(
        hsm1,
        &key,
        hsm1,
        &ScriptedIo::empty(),
        &editor,
        Some(&copy_label),
    )
    .unwrap();
    assert_eq!(copied.key_ref.label, copy_label);
    assert_ne!(copied.key_ref.key_id, key.key_ref.key_id); // same token: fresh id
    assert_eq!(cbc_encrypt(hsm1, &copied), baseline);
    assert!(no_transport_left(&[hsm1]));
}

// ---------------------------------------------------------------------------------------
// non-extractable key: public-part offer, then KeyNotExportable (§5.5)
// ---------------------------------------------------------------------------------------

fn non_extractable_keypair(provider: &Pkcs11Provider, label: &str) -> KeyInfo {
    let mut request = GenerateRequest::new(KeyAlgorithm::Ec, label);
    request.curve = Some(Curve::P256);
    request.template = Some(KeyTemplate::new(vec![
        boolean("CKA_TOKEN", false),
        boolean("CKA_SENSITIVE", true),
        boolean("CKA_EXTRACTABLE", false),
        boolean("CKA_SIGN", true),
    ]));
    request.public_template = Some(KeyTemplate::new(vec![
        boolean("CKA_TOKEN", false),
        boolean("CKA_VERIFY", true),
    ]));
    provider.generate_key(&request).unwrap()
}

fn count_label(provider: &dyn Provider, label: &str) -> usize {
    provider
        .list_keys()
        .unwrap()
        .iter()
        .filter(|info| info.key_ref.label == label)
        .count()
}

#[test]
fn test_decline_offer_raises_key_not_exportable() {
    let _lock = global_state_lock();
    let hsms = Hsms(vec![make_hsm("hsm1"), make_hsm("hsm2")]);
    let (hsm1, hsm2) = (&hsms.0[0], &hsms.0[1]);
    let label = format!("{}-cp-noexp", unique_label().as_str());
    let private = non_extractable_keypair(hsm1, &label);
    assert_eq!(
        private.attributes.get("CKA_EXTRACTABLE"),
        Some(&AttrValue::Bool(false))
    );
    // session objects on the shared token are visible to every session of this process —
    // count them before, to prove the decline created none
    let before = count_label(hsm2, &label);
    let io = ScriptedIo::new(["n"]);
    let err = copy(hsm1, &private, hsm2, &io, &SessionEditor::crypt(), None).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(err.message.contains("non-extractable"));
    // the public part WAS offered before raising (confirm-then-raise UX)
    assert!(
        io.prompts()
            .iter()
            .any(|prompt| prompt.contains("public part"))
    );
    // nothing landed on the destination
    assert_eq!(count_label(hsm2, &label), before);
}

#[test]
fn test_accept_offer_copies_public_part() {
    let _lock = global_state_lock();
    let hsms = Hsms(vec![make_hsm("hsm1"), make_hsm("hsm2")]);
    let (hsm1, hsm2) = (&hsms.0[0], &hsms.0[1]);
    let label = format!("{}-cp-puboff", unique_label().as_str());
    let private = non_extractable_keypair(hsm1, &label);
    let io = ScriptedIo::new(["y"]);
    let copied = copy(hsm1, &private, hsm2, &io, &SessionEditor::crypt(), None).unwrap();
    assert!(
        io.prompts()
            .iter()
            .any(|prompt| prompt.contains("public part"))
    );
    assert_eq!(copied.key_class, KeyClass::Public);
    assert_eq!(copied.key_ref.label, label);
    // the copied public key is real material: identical SPKI on both sides
    let source_public = hsm1
        .list_keys()
        .unwrap()
        .into_iter()
        .find(|info| info.key_ref.label == label && info.key_class == KeyClass::Public)
        .unwrap();
    let exported = hsm2.export_key(&copied).unwrap();
    assert_eq!(exported.key_class, KeyClass::Public);
    assert_eq!(exported.data, hsm1.export_key(&source_public).unwrap().data);
}

// ---------------------------------------------------------------------------------------
// object kinds (c2 test_objects_softhsm.py copy legs)
// ---------------------------------------------------------------------------------------

#[test]
fn test_generic_secret_copy_round_trip() {
    let _lock = global_state_lock();
    let hsms = Hsms(vec![make_hsm("softhsm")]);
    let hsm = &hsms.0[0];
    let mem = MemoryProvider::new("mem");
    let unique = unique_label();
    let generic_key: Vec<u8> = (0..GENERIC_KEY_LEN).collect();
    let source = mem
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, generic_key.clone()),
            &format!("{}-gsrc", unique.as_str()),
            None,
            None,
        )
        .unwrap();
    let io = ScriptedIo::empty();
    let editor = SessionEditor::mac();
    let gcopy = format!("{}-gcopy", unique.as_str());
    let on_token = copy(&mem, &source, hsm, &io, &editor, Some(&gcopy)).unwrap();
    assert_eq!(on_token.algorithm, KeyAlgorithm::Generic);
    let mac = hsm.sign(&on_token, &hmac("sha256"), MESSAGE).unwrap();
    assert_eq!(mac, mem.sign(&source, &hmac("sha256"), MESSAGE).unwrap());
    let gback = format!("{}-gback", unique.as_str());
    let back = copy(hsm, &on_token, &mem, &io, &editor, Some(&gback)).unwrap(); // wrap (KWP)
    assert_eq!(mem.export_key(&back).unwrap().data.to_vec(), generic_key);
}

#[test]
fn test_data_object_lifecycle_on_token() {
    let _lock = global_state_lock();
    let hsms = Hsms(vec![make_hsm("softhsm")]);
    let hsm = &hsms.0[0];
    let mem = MemoryProvider::new("mem");
    let label = format!("{}-data", unique_label().as_str());
    let template = KeyTemplate::new(vec![
        boolean("CKA_TOKEN", false),
        TemplateAttr::new(
            "CKA_APPLICATION",
            AttrKind::Str,
            AttrValue::Str("c2-test".into()),
        ),
        TemplateAttr::new(
            "CKA_OBJECT_ID",
            AttrKind::Bytes,
            AttrValue::Bytes(vec![0x2a, 0x2b]),
        ),
    ]);
    let info = hsm
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, DATA_VALUE.to_vec()),
            &label,
            Some(&template),
            None,
        )
        .unwrap();
    assert_eq!(
        (info.key_class, info.algorithm, info.key_ref.key_id.clone()),
        (KeyClass::Data, KeyAlgorithm::None, None)
    );
    assert_eq!(info.size_bits, Some(DATA_VALUE.len() as u32 * 8));
    assert!(info.exportable);
    assert_eq!(
        info.attributes.get("CKA_APPLICATION"),
        Some(&AttrValue::Str("c2-test".into()))
    );
    assert_eq!(
        info.attributes.get("CKA_OBJECT_ID"),
        Some(&AttrValue::Bytes(vec![0x2a, 0x2b]))
    );
    assert!(
        hsm.list_keys()
            .unwrap()
            .iter()
            .any(|k| k.key_ref == info.key_ref && k.key_class == KeyClass::Data)
    );
    let found = hsm
        .find_key(&KeySelector::label(label.clone()).with_class(Some(KeyClass::Data)))
        .unwrap();
    assert_eq!(found.key_ref, info.key_ref);
    assert_eq!(hsm.export_key(&info).unwrap().data.to_vec(), DATA_VALUE);
    let full = hsm.read_full_template(&info).unwrap();
    assert!(full.get("CKA_KEY_TYPE").is_none() && full.get("CKA_ID").is_none());
    assert_eq!(
        full.get("CKA_CLASS").unwrap().value,
        AttrValue::Symbol("CKO_DATA".into())
    );
    // plain-route copies both ways; the extras ride along into the editor seed
    let io = ScriptedIo::empty();
    let editor = SessionEditor::mac();
    let mem_label = format!("{label}-mem");
    let in_memory = copy(hsm, &info, &mem, &io, &editor, Some(&mem_label)).unwrap();
    assert_eq!(
        mem.export_key(&in_memory).unwrap().data.to_vec(),
        DATA_VALUE
    );
    let back_label = format!("{label}-back");
    let back = copy(&mem, &in_memory, hsm, &io, &editor, Some(&back_label)).unwrap();
    assert_eq!(back.key_class, KeyClass::Data);
    assert_eq!(hsm.export_key(&back).unwrap().data.to_vec(), DATA_VALUE);
    hsm.delete_key(&info).unwrap();
    hsm.delete_key(&back).unwrap();
    assert_eq!(count_label(hsm, &label), 0);
}

#[test]
fn data_object_extras_travel_token_to_token_softhsm() {
    // §5.5: the editor seed carries the source's CKA_APPLICATION/CKA_OBJECT_ID rows, so a
    // SoftHSM → SoftHSM data copy keeps them
    let _lock = global_state_lock();
    let hsms = Hsms(vec![make_hsm("hsm1"), make_hsm("hsm2")]);
    let (hsm1, hsm2) = (&hsms.0[0], &hsms.0[1]);
    let label = format!("{}-data2", unique_label().as_str());
    let template = KeyTemplate::new(vec![
        boolean("CKA_TOKEN", false),
        TemplateAttr::new(
            "CKA_APPLICATION",
            AttrKind::Str,
            AttrValue::Str("r2-app".into()),
        ),
        TemplateAttr::new(
            "CKA_OBJECT_ID",
            AttrKind::Bytes,
            AttrValue::Bytes(vec![0x06, 0x01]),
        ),
    ]);
    let info = hsm1
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, DATA_VALUE.to_vec()),
            &label,
            Some(&template),
            None,
        )
        .unwrap();
    let copy_label = format!("{label}-copy");
    let editor = SessionEditor::mac();
    let copied = copy(
        hsm1,
        &info,
        hsm2,
        &ScriptedIo::empty(),
        &editor,
        Some(&copy_label),
    )
    .unwrap();
    assert_eq!(
        editor.titles(),
        [format!("template for hsm2:{copy_label} (data)")]
    );
    assert_eq!(
        copied.attributes.get("CKA_APPLICATION"),
        Some(&AttrValue::Str("r2-app".into()))
    );
    assert_eq!(
        copied.attributes.get("CKA_OBJECT_ID"),
        Some(&AttrValue::Bytes(vec![0x06, 0x01]))
    );
    assert_eq!(hsm2.export_key(&copied).unwrap().data.to_vec(), DATA_VALUE);
}

#[test]
fn test_certificate_copy_round_trip() {
    let _lock = global_state_lock();
    let hsms = Hsms(vec![make_hsm("softhsm")]);
    let hsm = &hsms.0[0];
    let mem = MemoryProvider::new("mem");
    let (_pkcs8, cert_der) = fixtures::rsa_pkcs8_and_cert();
    let label = format!("{}-cert", unique_label().as_str());
    let source = mem
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert_der.clone()),
            &label,
            None,
            None,
        )
        .unwrap();
    let io = ScriptedIo::empty();
    let editor = SessionEditor::mac();
    let on_token = copy(&mem, &source, hsm, &io, &editor, Some(&label)).unwrap();
    assert_eq!(on_token.key_class, KeyClass::Certificate);
    assert_eq!(on_token.algorithm, KeyAlgorithm::Rsa);
    let listed: Vec<KeyClass> = hsm
        .list_keys()
        .unwrap()
        .into_iter()
        .filter(|k| k.key_ref.label == label)
        .map(|k| k.key_class)
        .collect();
    assert_eq!(listed, [KeyClass::Certificate]);
    assert_eq!(hsm.export_key(&on_token).unwrap().data.to_vec(), cert_der);
    let back_label = format!("{label}-back");
    let back = copy(hsm, &on_token, &mem, &io, &editor, Some(&back_label)).unwrap();
    assert_eq!(mem.export_key(&back).unwrap().data.to_vec(), cert_der); // DER identical
}

/// R13 (R5b hand-off): SoftHSM's C_Initialize (its failed `rdrand` engine load) and its
/// internal operations can leave errors on the process's shared libcrypto queue. After a
/// login and on-token work, MemoryProvider and the r2-core parsers must still report their
/// OWN first OpenSSL/pyca reason — e.g. the trailing-zero PKCS#8 of a 2.6.1
/// `copy softhsm:<priv> mem` gives c2's exact text.
#[test]
fn memory_reasons_are_not_polluted_by_softhsm_errors() {
    let _lock = global_state_lock();
    let hsm = make_hsm("hsm");
    let label = unique_label();
    let mut request = GenerateRequest::new(KeyAlgorithm::Rsa, label.as_str());
    request.size_bits = Some(2048);
    request.template = Some(KeyTemplate::new(vec![boolean("CKA_TOKEN", false)]));
    request.public_template = Some(KeyTemplate::new(vec![boolean("CKA_TOKEN", false)]));
    let private = hsm.generate_key(&request).unwrap();
    let mem = MemoryProvider::new("mem");
    // an OpenSSL-reported reason (§11 D11)
    let public = mem
        .import_key(
            &KeyMaterial::new(
                KeyAlgorithm::Rsa,
                KeyClass::Public,
                r2_core::formats::pkcs8_public_spki(&fixtures::rsa2048_pkcs8()).unwrap(),
            ),
            "pub",
            None,
            None,
        )
        .unwrap();
    let mut params = Params::new();
    params.insert("hash".into(), ParamValue::Enum("sha256".into()));
    let err = mem
        .encrypt(
            &public,
            &MechanismInvocation::new("RSA-OAEP", params),
            &[1; 250],
        )
        .unwrap_err();
    assert_eq!(
        err.message,
        "RSA-OAEP encryption failed: data too large for key size"
    );
    // a pyca-structured parse failure
    let mut data = fixtures::rsa2048_pkcs8();
    data.extend_from_slice(&[0; 8]);
    let err = mem
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, data),
            "x",
            None,
            None,
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert_eq!(
        err.message,
        "cannot parse private key material: Could not deserialize key data. The data may be in an incorrect format, it may be encrypted with an unsupported algorithm, or it may be an unsupported key type (e.g. EC curves with explicit parameters). Details: ASN.1 parsing error: unexpected tag (got Tag { value: 2, constructed: false, class: Universal })"
    );
    hsm.delete_key(&private).unwrap();
}

/// R13 (R5b ledger hand-off, c2 test_hmac_matches_stdlib_and_crosses_providers): the direct
/// token ⇄ memory HMAC exchange — the same generic secret on SoftHSM (copied from memory)
/// and in MemoryProvider: every hash's MAC is equal, and each side verifies the other's
/// MAC (full width and a truncated mac_len=12).
#[test]
fn hmac_crosses_token_and_memory_both_ways() {
    let _lock = global_state_lock();
    let hsms = Hsms(vec![make_hsm("softhsm")]);
    let hsm = &hsms.0[0];
    let mem = MemoryProvider::new("mem");
    let unique = unique_label();
    let source = mem
        .import_key(
            &KeyMaterial::new(
                KeyAlgorithm::Generic,
                KeyClass::Secret,
                (0..GENERIC_KEY_LEN).collect(),
            ),
            &format!("{}-hsrc", unique.as_str()),
            None,
            None,
        )
        .unwrap();
    let io = ScriptedIo::empty();
    let editor = SessionEditor::mac();
    let on_token = copy(
        &mem,
        &source,
        hsm,
        &io,
        &editor,
        Some(&format!("{}-hcopy", unique.as_str())),
    )
    .unwrap();
    for hash in ["sha1", "sha224", "sha256", "sha384", "sha512"] {
        let mech = hmac(hash);
        let token_mac = hsm.sign(&on_token, &mech, MESSAGE).unwrap();
        let mem_mac = mem.sign(&source, &mech, MESSAGE).unwrap();
        assert_eq!(token_mac, mem_mac, "{hash}");
        assert!(mem.verify(&source, &mech, MESSAGE, &token_mac).unwrap());
        assert!(hsm.verify(&on_token, &mech, MESSAGE, &mem_mac).unwrap());
        let mut short = mech.clone();
        short.params.insert("mac_len".into(), ParamValue::Int(12));
        let token_short = hsm.sign(&on_token, &short, MESSAGE).unwrap();
        assert_eq!(token_short, mem_mac[..12].to_vec(), "{hash}");
        assert!(mem.verify(&source, &short, MESSAGE, &token_short).unwrap());
        assert!(
            hsm.verify(&on_token, &short, MESSAGE, &mem_mac[..12])
                .unwrap()
        );
    }
}
