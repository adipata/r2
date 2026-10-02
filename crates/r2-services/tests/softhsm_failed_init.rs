//! R13 (R5b hand-off, review round 3): a FAILED SoftHSM `C_Initialize` (a bad
//! `$SOFTHSM2_CONF`, e.g. a nonexistent tokendir) still loads SoftHSM's OpenSSL engines and
//! leaves their errors ("could not load the shared library", "no such engine", …) on the
//! process's shared libcrypto queue. They must never become the reported reason of a later
//! MemoryProvider failure (§11 D11): c2 prints the same text before and after the failed
//! login.
//!
//! Its own test binary so the module is not already initialized in-process by another test
//! (under both nextest and the `cargo test` fallback). Feature `softhsm`; fails (never
//! skips) without the fixture from `scripts/softhsm-init.sh`.
#![cfg(feature = "softhsm")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use indexmap::IndexMap;
use r2_config::model::Pkcs11InstanceConfig;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::{ParamValue, Params};
use r2_memory::MemoryProvider;
use r2_pkcs11::Pkcs11Provider;
use r2_provider::{MechanismInvocation, Provider};
use r2_testkit::softhsm::softhsm_token;
use r2_testkit::{fixtures, global_state_lock, set_env};

fn oaep_too_large(mem: &MemoryProvider, public: &KeyInfo) -> String {
    let mut params = Params::new();
    params.insert("hash".into(), ParamValue::Enum("sha256".into()));
    mem.encrypt(
        public,
        &MechanismInvocation::new("RSA-OAEP", params),
        &[1; 250],
    )
    .unwrap_err()
    .message
}

#[test]
fn failed_softhsm_initialize_does_not_pollute_memory_reasons() {
    let _lock = global_state_lock();
    let token = softhsm_token();
    let mem = MemoryProvider::new("mem");
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
    let expected = "RSA-OAEP encryption failed: data too large for key size";
    assert_eq!(oaep_too_large(&mem, &public), expected);

    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("bad.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            dir.path().join("missing").display()
        ),
    )
    .unwrap();
    let _env = set_env("SOFTHSM2_CONF", Some(conf.to_str().unwrap()));
    let hsm = Pkcs11Provider::new(
        "hsm",
        Pkcs11InstanceConfig::new("hsm", token.module_path.clone()),
        BTreeMap::new(),
        IndexMap::new(),
    );
    let err = hsm.list_tokens().unwrap_err();
    assert!(
        err.message.contains("CKR_GENERAL_ERROR"),
        "C_Initialize must fail on the bad config: {}",
        err.message
    );
    assert_eq!(oaep_too_large(&mem, &public), expected);
}
