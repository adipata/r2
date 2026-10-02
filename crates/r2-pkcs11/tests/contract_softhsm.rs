//! The provider contract suite instantiated for Pkcs11Provider on the SoftHSM fixture token
//! (spec §4.10.3, R5b) — c2 tests/integration/test_pkcs11_provider.py
//! TestPkcs11ProviderContract. Feature `softhsm`; fails (never skips) without the fixture
//! from `scripts/softhsm-init.sh`. nextest runs it in the `softhsm` test group (one test at
//! a time), so each case owns the module and its logged-in provider (c2 shut its providers
//! down after each test; a nextest test is its own process).
#![cfg(feature = "softhsm")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::BTreeMap;
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::Pkcs11InstanceConfig;
use r2_pkcs11::Pkcs11Provider;
use r2_provider::Provider;
use r2_testkit::provider_contract_tests;
use r2_testkit::softhsm::softhsm_token;
use secrecy::SecretString;

/// A Pkcs11Provider logged in to the fixture token (c2 `make_provider`).
fn logged_in_provider() -> Rc<dyn Provider> {
    let token = softhsm_token();
    let mut config = Pkcs11InstanceConfig::new("softhsm", token.module_path.clone());
    config.slot = Some(token.slot);
    config.token_label = Some(token.token_label.clone());
    let provider = Pkcs11Provider::new("softhsm", config, BTreeMap::new(), IndexMap::new());
    let info = provider
        .list_tokens()
        .unwrap()
        .into_iter()
        .find(|t| t.label == token.token_label)
        .unwrap_or_else(|| panic!("token {:?} not found", token.token_label));
    provider
        .login(&info, &SecretString::from(token.user_pin.clone()), false)
        .unwrap();
    Rc::new(provider)
}

provider_contract_tests!(pkcs11_softhsm, logged_in_provider());
