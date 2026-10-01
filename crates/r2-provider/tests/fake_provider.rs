// FakeProvider behavior beyond the c2 test_provider_base cases: the r2 FakeHooks seam,
// `.with_tokens(..)` / TokenInit, the call encoding of every recorded method, the editing
// surfaces and c2's error texts (spec §4.10.2; c2 tests/support/fake_provider.py) — R3.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::ParamValue;
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_provider::*;
use r2_testkit::fixtures::rsa_pkcs8_and_cert;
use r2_testkit::{FakeHooks, FakeProvider};
use secrecy::SecretString;

fn err<T>(result: Result<T>) -> ConsoleError {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(err) => err,
    }
}

fn call(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn mech(mechanism: &str) -> MechanismInvocation {
    MechanismInvocation::new(mechanism, Default::default())
}

fn aes() -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![1; 16])
}

fn data() -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, b"opaque".to_vec())
}

fn pin() -> SecretString {
    SecretString::from("1234")
}

fn free_token(slot: u64) -> TokenInfo {
    TokenInfo {
        slot_id: slot,
        label: String::new(),
        manufacturer: "SoftHSM project".to_owned(),
        model: "SoftHSM v2".to_owned(),
        serial: String::new(),
    }
}

// -- call encoding -------------------------------------------------------------------------

#[test]
fn call_encoding_of_every_recorded_method() {
    let fake = FakeProvider::new("hsm").with_type_name("pkcs11");
    fake.initialize().unwrap();
    let request = GenerateRequest {
        curve: Some(Curve::Ed25519),
        template: Some(KeyTemplate::default()),
        ..GenerateRequest::new(KeyAlgorithm::EcEdwards, "ed")
    };
    let private = fake.generate_key(&request).unwrap();
    let selector = KeySelector::label("ed")
        .with_id(Some(vec![0, 0, 0, 1]))
        .with_class(Some(KeyClass::Private))
        .with_handle(Some(1));
    fake.find_key(&selector).unwrap();
    fake.find_key(&KeySelector::label("ed").with_class(Some(KeyClass::Private)))
        .unwrap();
    let secret = fake
        .import_key(&aes(), "k", Some(&KeyTemplate::default()), Some(b"\x09"))
        .unwrap();
    let blob = fake
        .wrap_key(
            &secret,
            &mech("AES-KEY-WRAP"),
            &secret,
            &WrapOptions::default(),
        )
        .unwrap();
    let request = UnwrapRequest {
        key_id: Some(vec![7, 7]),
        ..UnwrapRequest::new(KeyAlgorithm::Generic, KeyClass::Secret, "u")
    };
    fake.unwrap_key(&secret, &mech("AES-KEY-WRAP"), &blob, &request)
        .unwrap();
    fake.sign(&secret, &mech("AES-CMAC"), b"abc").unwrap();
    fake.verify(&secret, &mech("AES-CMAC"), b"abc", b"xy")
        .unwrap();
    fake.decrypt(&secret, &mech("AES-ECB"), b"0123456789abcdef")
        .unwrap();
    fake.derive(&private, &mech("ECDH")).unwrap();
    fake.export_key(&secret).unwrap();
    fake.read_key_template(&secret).unwrap();
    fake.read_full_template(&secret).unwrap();
    fake.update_key(&secret, &KeyTemplate::default()).unwrap();
    fake.list_keys().unwrap();
    fake.delete_key(&secret).unwrap();
    fake.logout().unwrap();
    fake.shutdown().unwrap();
    // not recorded: status, mechanisms, supports, list_tokens
    fake.status();
    fake.mechanisms();
    fake.supports("AES-ECB");
    fake.list_tokens().unwrap();
    assert_eq!(
        fake.calls(),
        vec![
            call(&["initialize"]),
            call(&[
                "generate_key",
                "KeyAlgorithm.EC_EDWARDS",
                "None",
                "ed25519",
                "ed",
                "None",
                "template(0 attrs)",
                "None"
            ]),
            call(&["find_key", "ed", "4B", "KeyClass.PRIVATE", "1"]),
            call(&["find_key", "ed", "None", "KeyClass.PRIVATE", "None"]),
            call(&[
                "import_key",
                "aes/secret:16B",
                "k",
                "template(0 attrs)",
                "1B"
            ]),
            call(&["wrap_key", "hsm:k#09", "AES-KEY-WRAP", "hsm:k#09"]),
            call(&[
                "unwrap_key",
                "hsm:k#09",
                "AES-KEY-WRAP",
                "16B",
                "KeyAlgorithm.GENERIC",
                "KeyClass.SECRET",
                "u",
                "2B",
                "None"
            ]),
            call(&["sign", "hsm:k#09", "AES-CMAC", "3B"]),
            call(&["verify", "hsm:k#09", "AES-CMAC", "3B", "2B"]),
            call(&["decrypt", "hsm:k#09", "AES-ECB", "16B"]),
            call(&["derive", "hsm:ed#00000001", "ECDH"]),
            call(&["export_key", "hsm:k#09"]),
            call(&["read_key_template", "hsm:k#09"]),
            call(&["read_full_template", "hsm:k#09"]),
            call(&["update_key", "hsm:k#09", "template(0 attrs)"]),
            call(&["list_keys"]),
            call(&["delete_key", "hsm:k#09"]),
            call(&["logout"]),
            call(&["shutdown"]),
        ]
    );
    fake.clear_calls();
    assert!(fake.calls().is_empty());
}

// -- hooks ---------------------------------------------------------------------------------

#[derive(Default)]
struct Spy {
    seen: RefCell<Vec<String>>,
    fail_encrypt: bool,
    no_mechanisms: bool,
}

impl FakeHooks for Spy {
    fn shutdown(&self, next: &dyn Provider) -> Option<Result<()>> {
        self.seen.borrow_mut().push("shutdown".to_owned());
        Some(next.shutdown()) // observe and delegate
    }
    fn mechanisms(&self, _next: &dyn Provider) -> Option<BTreeSet<String>> {
        self.no_mechanisms.then(BTreeSet::new)
    }
    fn encrypt(
        &self,
        next: &dyn Provider,
        _key: &KeyInfo,
        _mech: &MechanismInvocation,
        _data: &[u8],
    ) -> Option<Result<Vec<u8>>> {
        let fake = next
            .as_any()
            .downcast_ref::<FakeProvider>()
            .expect("next is the fake");
        self.seen.borrow_mut().push(format!(
            "encrypt with {} recorded calls",
            fake.calls().len()
        ));
        self.fail_encrypt
            .then(|| Err(ConsoleError::crypto("injected failure")))
    }
    fn find_key(&self, next: &dyn Provider, selector: &KeySelector) -> Option<Result<KeyInfo>> {
        // re-entrant delegation: the hook calls back into the fake while it runs
        let keys = next.list_keys().ok()?;
        self.seen
            .borrow_mut()
            .push(format!("find {} among {}", selector.label, keys.len()));
        None
    }
}

#[test]
fn hooks_observe_override_and_delegate() {
    let spy = Rc::new(Spy {
        fail_encrypt: true,
        ..Spy::default()
    });
    let fake = FakeProvider::new("mem").with_hooks(spy.clone());
    let key = fake.import_key(&aes(), "k", None, None).unwrap();
    // an overriding hook returns its result; nothing is recorded for the call
    let error = err(fake.encrypt(&key, &mech("AES-ECB"), b"x"));
    assert_eq!(error.message, "injected failure");
    assert!(!fake.calls().iter().any(|c| c[0] == "encrypt"));
    // a hook returning None lets the fake run (and record)
    fake.find_key(&KeySelector::label("k")).unwrap();
    assert_eq!(
        *spy.seen.borrow(),
        ["encrypt with 1 recorded calls", "find k among 1"]
    );
    assert_eq!(
        fake.calls().last().unwrap(),
        &call(&["find_key", "k", "None", "None", "None"])
    );
}

#[test]
fn internal_capability_checks_use_the_hooked_mechanisms() {
    let spy = Rc::new(Spy {
        no_mechanisms: true,
        ..Spy::default()
    });
    let fake = FakeProvider::new("mem").with_hooks(spy);
    assert!(fake.mechanisms().is_empty());
    assert!(!fake.supports("AES-ECB"));
    let key = fake.import_key(&aes(), "k", None, None).unwrap();
    let error = err(fake.sign(&key, &mech("AES-CMAC"), b"x"));
    assert_eq!(error.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(error.message, "mem does not support mechanism AES-CMAC");
}

#[test]
fn set_env_and_reset_runs_the_hooked_shutdown() {
    let spy = Rc::new(Spy::default());
    let fake = FakeProvider::new("softhsm")
        .with_type_name("pkcs11")
        .with_tokens(vec![free_token(3)])
        .with_hooks(spy.clone());
    let init = fake.as_token_init().expect("token-init seam");
    init.set_env_and_reset("SOFTHSM2_CONF", "/tmp/x.conf")
        .unwrap();
    assert_eq!(*spy.seen.borrow(), ["shutdown"]);
    assert_eq!(
        fake.calls(),
        vec![
            call(&["set_env_and_reset", "SOFTHSM2_CONF", "/tmp/x.conf"]),
            call(&["shutdown"])
        ]
    );
    assert_eq!(fake.status().auth, AuthState::LoggedOut);
    // the real environment is never touched
    assert!(std::env::var("SOFTHSM2_CONF").map_or(true, |v| v != "/tmp/x.conf"));
}

// -- tokens / TokenInit --------------------------------------------------------------------

#[test]
fn token_init_seam_only_with_tokens() {
    assert!(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .as_token_init()
            .is_none()
    );
    assert!(FakeProvider::new("mem").as_token_init().is_none());
    let fake = FakeProvider::new("softhsm")
        .with_type_name("pkcs11")
        .starting_logged_out()
        .with_tokens(vec![free_token(0), free_token(5)]);
    assert_eq!(fake.status().auth, AuthState::LoggedOut);
    assert_eq!(
        fake.list_tokens().unwrap(),
        vec![free_token(0), free_token(5)]
    );
    let init = fake.as_token_init().unwrap();
    init.init_token(5, "r2", &pin(), &pin()).unwrap();
    let tokens = fake.list_tokens().unwrap();
    assert_eq!(tokens[0], free_token(0));
    assert_eq!(
        tokens[1],
        TokenInfo {
            slot_id: 5,
            label: "r2".to_owned(),
            manufacturer: "SoftHSM project".to_owned(),
            model: "SoftHSM v2".to_owned(),
            serial: "0000000000000001".to_owned(),
        }
    );
    // slot 5 is no longer free; an unknown slot is not free either
    let error = err(init.init_token(5, "again", &pin(), &pin()));
    assert_eq!(error.kind, ErrorKind::Provider);
    assert_eq!(error.message, "no free slot 5");
    assert_eq!(
        err(init.init_token(9, "x", &pin(), &pin())).message,
        "no free slot 9"
    );
    let error = err(init.init_token(0, &"x".repeat(33), &pin(), &pin()));
    assert_eq!(error.message, "token label must be at most 32 bytes");
    init.init_token(0, "second", &pin(), &pin()).unwrap();
    assert_eq!(fake.list_tokens().unwrap()[0].serial, "0000000000000002");
    assert_eq!(
        fake.calls()
            .iter()
            .filter(|c| c[0] == "init_token")
            .map(|c| c[1..].join(" "))
            .collect::<Vec<_>>(),
        [
            "5 r2",
            "5 again",
            "9 x",
            &format!("0 {}", "x".repeat(33)),
            "0 second"
        ]
    );
    // login stores the given token as the status token
    fake.login(&tokens[1], &pin(), false).unwrap();
    assert_eq!(fake.status().token.as_ref(), Some(&tokens[1]));
}

#[test]
fn starting_logged_out_order_independent_and_memory_unaffected() {
    let fake = FakeProvider::new("hsm")
        .starting_logged_out()
        .with_type_name("pkcs11");
    assert_eq!(fake.status().auth, AuthState::LoggedOut);
    assert!(fake.mechanisms().is_empty());
    let memory = FakeProvider::new("mem").starting_logged_out();
    assert_eq!(memory.status().auth, AuthState::NotRequired);
}

// -- creation rules --------------------------------------------------------------------------

#[test]
fn creation_error_texts() {
    let fake = FakeProvider::new("mem");
    let other = KeyMaterial::new(KeyAlgorithm::Other, KeyClass::Secret, vec![1]);
    let error = err(fake.import_key(&other, "o", None, None));
    assert_eq!(error.message, "cannot import other secret material");
    assert_eq!(error.param_name(), Some("material"));
    let none = KeyMaterial::new(KeyAlgorithm::None, KeyClass::Secret, vec![1]);
    assert_eq!(
        err(fake.import_key(&none, "n", None, None)).message,
        "cannot import none secret material"
    );
    let error = err(fake.import_key(&data(), "d", None, Some(b"\x01")));
    assert_eq!(error.message, "data objects carry no CKA_ID (§4.3)");
    assert_eq!(error.param_name(), Some("key_id"));
    assert_eq!(
        error.hint.as_deref(),
        Some("drop --id; data objects are identified by label alone")
    );
    let error = err(fake.generate_key(&GenerateRequest::new(KeyAlgorithm::None, "x")));
    assert_eq!(error.message, "cannot generate none keys");
    assert_eq!(error.param_name(), Some("algorithm"));
    let generic = |bits| {
        fake.generate_key(&GenerateRequest {
            size_bits: Some(bits),
            ..GenerateRequest::new(KeyAlgorithm::Generic, format!("g{bits}"))
        })
    };
    assert_eq!(
        err(generic(12)).message,
        "invalid generic secret size 12; expected a positive multiple of 8"
    );
    assert_eq!(
        err(generic(0)).message,
        "invalid generic secret size 0; expected a positive multiple of 8"
    );
    // no 8192 cap on the fake (§4.10.2)
    assert_eq!(generic(16384).unwrap().size_bits, Some(16384));
    let key = fake.import_key(&aes(), "kek", None, None).unwrap();
    let request = UnwrapRequest::new(KeyAlgorithm::Other, KeyClass::Secret, "u");
    let error = err(fake.unwrap_key(&key, &mech("AES-KEY-WRAP"), &[0; 16], &request));
    assert_eq!(error.message, "cannot unwrap into other keys");
    assert_eq!(error.param_name(), Some("result_algorithm"));
}

#[test]
fn empty_key_id_is_no_id() {
    let fake = FakeProvider::new("mem");
    let info = fake.import_key(&aes(), "k", None, Some(b"")).unwrap();
    assert_eq!(info.key_ref.key_id, None);
    let hsm = FakeProvider::new("hsm").with_type_name("pkcs11");
    let info = hsm.import_key(&aes(), "k", None, Some(b"")).unwrap();
    assert_eq!(info.key_ref.key_id, Some(vec![0, 0, 0, 1])); // counter id, as for None
}

#[test]
fn handles_are_a_counter_and_attributes_follow_the_policy() {
    let fake = FakeProvider::new("mem");
    let a = fake.import_key(&aes(), "a", None, None).unwrap();
    let d = fake.import_key(&data(), "d", None, None).unwrap();
    assert_eq!((a.handle, d.handle), (Some(1), Some(2)));
    assert_eq!(
        a.attributes.get("CKA_SENSITIVE"),
        Some(&AttrValue::Bool(false))
    );
    assert_eq!(
        a.attributes.get("CKA_EXTRACTABLE"),
        Some(&AttrValue::Bool(true))
    );
    assert!(d.attributes.is_empty());
    assert_eq!(d.size_bits, Some(48));
    // a disabled template row does not count
    let template = KeyTemplate::new(vec![
        TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(true)).disabled(),
    ]);
    let b = fake.import_key(&aes(), "b", Some(&template), None).unwrap();
    assert!(b.exportable);
}

// -- verbs -----------------------------------------------------------------------------------

#[test]
fn verb_refusals() {
    let fake = FakeProvider::new("mem");
    let d = fake.import_key(&data(), "d", None, None).unwrap();
    let error = err(fake.encrypt(&d, &mech("AES-ECB"), b"x"));
    assert_eq!(
        error.message,
        "data objects cannot be used for encrypt (§4.3)"
    );
    assert_eq!(
        error.hint.as_deref(),
        Some("data objects hold opaque bytes, not key material — export or copy them")
    );
    let (_, cert_der) = rsa_pkcs8_and_cert();
    let cert = fake
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert_der),
            "c",
            None,
            None,
        )
        .unwrap();
    let error = err(fake.decrypt(&cert, &mech("RSA-OAEP"), b"x"));
    assert_eq!(
        error.message,
        "certificates cannot be used for decrypt (§4.3)"
    );
    assert_eq!(
        error.hint.as_deref(),
        Some("certificates stand in for PUBLIC keys only (encrypt/verify/wrap)")
    );
    assert_eq!(
        err(fake.derive(&cert, &mech("ECDH"))).message,
        "certificates cannot be used for derive (§4.3)"
    );
    let unknown = fake.store_key_unchecked(
        &KeyMaterial::new(KeyAlgorithm::Other, KeyClass::Secret, vec![1; 24]),
        "des",
        None,
        None,
    );
    let error = err(fake.encrypt(&unknown, &mech("AES-ECB"), b"x"));
    assert_eq!(
        error.message,
        "key type unknown of 'mem:des' is not supported by r2 for encrypt"
    );
    assert_eq!(
        error.hint.as_deref(),
        Some("objects of unsupported key types can be listed and deleted only")
    );
    let aes_key = fake.import_key(&aes(), "a", None, None).unwrap();
    let error = err(fake.sign(&aes_key, &mech("HMAC"), b"x"));
    assert_eq!(
        error.message,
        "HMAC requires a generic secret key (got aes secret)"
    );
    assert_eq!(
        error.hint.as_deref(),
        Some("generate/load a `generic` key (CKK_GENERIC_SECRET) for HMAC")
    );
    let generic = fake
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, vec![2; 32]),
            "g",
            None,
            None,
        )
        .unwrap();
    let error = err(fake.sign(&generic, &mech("AES-GMAC"), b"x"));
    assert_eq!(
        error.message,
        "AES-GMAC requires an AES secret key (got generic secret)"
    );
    assert_eq!(error.hint, None);
    let pair = fake
        .generate_key(&GenerateRequest {
            curve: Some(Curve::P256),
            ..GenerateRequest::new(KeyAlgorithm::Ec, "p")
        })
        .unwrap();
    let public = fake
        .find_key(&KeySelector::label("p").with_class(Some(KeyClass::Public)))
        .unwrap();
    assert_eq!(pair.key_class, KeyClass::Private);
    assert_eq!(
        err(fake.derive(&public, &mech("ECDH"))).message,
        "derive requires a private (or secret) key"
    );
}

#[test]
fn certificate_resolves_to_its_public_key_buckets() {
    let fake = FakeProvider::new("hsm").with_type_name("pkcs11");
    let private = fake
        .generate_key(&GenerateRequest {
            size_bits: Some(2048),
            key_id: Some(vec![0xCC]),
            ..GenerateRequest::new(KeyAlgorithm::Rsa, "pair")
        })
        .unwrap();
    let (_, cert_der) = rsa_pkcs8_and_cert();
    // same id, other label → the PUBLIC with the same id wins
    let cert = fake
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert_der.clone()),
            "cert",
            None,
            Some(&[0xCC]),
        )
        .unwrap();
    let ciphertext = fake.encrypt(&cert, &mech("RSA-OAEP"), b"msg").unwrap();
    assert_eq!(
        *fake
            .decrypt(&private, &mech("RSA-OAEP"), &ciphertext)
            .unwrap(),
        b"msg"
    );
    // a lone certificate resolves to its own record
    let lone = fake
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert_der),
            "lone",
            None,
            Some(&[0xDD]),
        )
        .unwrap();
    assert!(fake.encrypt(&lone, &mech("RSA-OAEP"), b"msg").is_ok());
}

#[test]
fn hmac_truncation_and_derive_default_length() {
    let fake = FakeProvider::new("mem");
    let generic = fake
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, vec![3; 32]),
            "g",
            None,
            None,
        )
        .unwrap();
    let mut params = r2_core::params::Params::new();
    params.insert("hash".to_owned(), ParamValue::Enum("sha512".to_owned()));
    params.insert("mac_len".to_owned(), ParamValue::Int(70)); // > digest: ignored
    let full = fake
        .sign(&generic, &MechanismInvocation::new("HMAC", params), b"m")
        .unwrap();
    assert_eq!(full.len(), 64);
    let pair = fake
        .generate_key(&GenerateRequest {
            curve: Some(Curve::X25519),
            ..GenerateRequest::new(KeyAlgorithm::EcMontgomery, "x")
        })
        .unwrap();
    let raw = fake.derive(&pair, &mech("ECDH")).unwrap().raw.unwrap();
    assert_eq!(raw.len(), 32); // SHA-256 base without out_len
}

// -- editing ---------------------------------------------------------------------------------

#[test]
fn read_key_template_rows() {
    let fake = FakeProvider::new("mem");
    let secret = fake.import_key(&aes(), "k", None, None).unwrap();
    let template = fake.read_key_template(&secret).unwrap();
    let names: Vec<&str> = template.attrs.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(
        names,
        ["CKA_LABEL", "CKA_ID", "CKA_SENSITIVE", "CKA_EXTRACTABLE"]
    );
    let id = template.get("CKA_ID").unwrap();
    assert!(!id.enabled); // disabled-empty when absent
    assert_eq!(id.value, AttrValue::Bytes(Vec::new()));
    assert!(template.attrs.iter().all(|a| !a.locked));
    let d = fake.import_key(&data(), "d", None, None).unwrap();
    let names: Vec<String> = fake
        .read_key_template(&d)
        .unwrap()
        .attrs
        .into_iter()
        .map(|a| a.name)
        .collect();
    assert_eq!(names, ["CKA_LABEL"]);
}

#[test]
fn read_full_template_rows_and_kinds() {
    let fake = FakeProvider::new("hsm").with_type_name("pkcs11");
    let secret = fake.import_key(&aes(), "k", None, None).unwrap();
    let template = fake.read_full_template(&secret).unwrap();
    let rows: Vec<(String, AttrKind, AttrValue)> = template
        .attrs
        .into_iter()
        .map(|a| (a.name, a.kind, a.value))
        .collect();
    assert_eq!(
        rows,
        vec![
            (
                "CKA_CLASS".to_owned(),
                AttrKind::Ulong,
                AttrValue::Symbol("CKO_SECRET_KEY".to_owned())
            ),
            (
                "CKA_KEY_TYPE".to_owned(),
                AttrKind::Ulong,
                AttrValue::Symbol("CKK_AES".to_owned())
            ),
            (
                "CKA_LABEL".to_owned(),
                AttrKind::Str,
                AttrValue::Str("k".to_owned())
            ),
            (
                "CKA_ID".to_owned(),
                AttrKind::Bytes,
                AttrValue::Bytes(vec![0, 0, 0, 1])
            ),
            (
                "CKA_EXTRACTABLE".to_owned(),
                AttrKind::Bool,
                AttrValue::Bool(true)
            ),
            (
                "CKA_SENSITIVE".to_owned(),
                AttrKind::Bool,
                AttrValue::Bool(false)
            ),
        ]
    );
}

#[test]
fn update_key_rules() {
    let fake = FakeProvider::new("mem");
    let secret = fake.import_key(&aes(), "k", None, None).unwrap();
    let change = |attrs: Vec<TemplateAttr>| fake.update_key(&secret, &KeyTemplate::new(attrs));
    let error = err(change(vec![TemplateAttr::new(
        "CKA_CLASS",
        AttrKind::Ulong,
        AttrValue::Symbol("CKO_DATA".to_owned()),
    )]));
    assert_eq!(error.message, "CKA_CLASS cannot be edited after creation");
    assert_eq!(error.param_name(), Some("CKA_CLASS"));
    let error = err(change(vec![TemplateAttr::new(
        "CKA_LABEL",
        AttrKind::Str,
        AttrValue::Str(String::new()),
    )]));
    assert_eq!(error.message, "CKA_LABEL expects a non-empty string");
    let error = err(change(vec![TemplateAttr::new(
        "CKA_ID",
        AttrKind::Bytes,
        AttrValue::Bytes(Vec::new()),
    )]));
    assert_eq!(error.message, "CKA_ID expects non-empty bytes");
    assert_eq!(error.hint.as_deref(), Some("use a 0x… hex value"));
    // disabled rows are ignored entirely
    let result = change(vec![
        TemplateAttr::new("CKA_CLASS", AttrKind::Ulong, AttrValue::Ulong(0)).disabled(),
    ])
    .unwrap();
    assert!(result.outcomes.is_empty());
    // flags apply on secret keys and recompute exportable
    let result = change(vec![
        TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(true)),
        TemplateAttr::new("CKA_ID", AttrKind::Bytes, AttrValue::Bytes(vec![5])),
    ])
    .unwrap();
    assert!(!result.key.exportable);
    assert_eq!(result.key.key_ref.key_id, Some(vec![5]));
    assert_eq!(
        result.key.attributes.get("CKA_SENSITIVE"),
        Some(&AttrValue::Bool(true))
    );
    assert!(result.outcomes.iter().all(|o| o.applied));
    let found = fake.find_key(&KeySelector::label("k")).unwrap();
    assert_eq!(found, result.key);
    // data objects: CKA_ID refused, flags are failed outcomes
    let d = fake.import_key(&data(), "d", None, None).unwrap();
    let error = err(fake.update_key(
        &d,
        &KeyTemplate::new(vec![TemplateAttr::new(
            "CKA_ID",
            AttrKind::Bytes,
            AttrValue::Bytes(vec![1]),
        )]),
    ));
    assert_eq!(error.message, "data objects carry no CKA_ID (§4.3)");
    assert_eq!(error.param_name(), Some("CKA_ID"));
    assert_eq!(
        error.hint.as_deref(),
        Some("data objects are identified by label alone")
    );
    let result = fake
        .update_key(
            &d,
            &KeyTemplate::new(vec![TemplateAttr::new(
                "CKA_SENSITIVE",
                AttrKind::Bool,
                AttrValue::Bool(true),
            )]),
        )
        .unwrap();
    assert_eq!(
        result.outcomes,
        vec![AttrEditOutcome {
            name: "CKA_SENSITIVE".to_owned(),
            applied: false,
            detail: Some("not supported by FakeProvider".to_owned()),
        }]
    );
}

#[test]
fn rename_guard_texts_and_certificate_exemption() {
    let fake = FakeProvider::new("mem");
    fake.import_key(&aes(), "a", None, None).unwrap();
    let b = fake.import_key(&aes(), "b", None, None).unwrap();
    let error = err(fake.update_key(
        &b,
        &KeyTemplate::new(vec![TemplateAttr::new(
            "CKA_LABEL",
            AttrKind::Str,
            AttrValue::Str("a".to_owned()),
        )]),
    ));
    assert_eq!(
        error.message,
        "a secret object with label 'a' and no id already exists on mem"
    );
    assert_eq!(
        error.hint.as_deref(),
        Some("pick a different id or label, or delete the existing object first")
    );
    let (_, cert_der) = rsa_pkcs8_and_cert();
    let material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert_der);
    fake.import_key(&material, "c1", None, None).unwrap();
    let c2 = fake.import_key(&material, "c2", None, None).unwrap();
    let renamed = fake
        .update_key(
            &c2,
            &KeyTemplate::new(vec![TemplateAttr::new(
                "CKA_LABEL",
                AttrKind::Str,
                AttrValue::Str("c1".to_owned()),
            )]),
        )
        .unwrap();
    assert_eq!(renamed.key.key_ref.label, "c1");
}
