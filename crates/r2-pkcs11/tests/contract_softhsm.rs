//! The provider contract suite instantiated for Pkcs11Provider on the SoftHSM fixture token
//! (spec §4.10.3, R5b) — c2 tests/integration/test_pkcs11_provider.py
//! TestPkcs11ProviderContract. Feature `softhsm`; fails (never skips) without the fixture
//! from `scripts/softhsm-init.sh`. Every case holds `r2_testkit::global_state_lock()` for
//! its whole run (taken by the factory, parked in a thread-local released when the test
//! thread exits, after the provider has dropped and finalized the module), so the
//! `cargo test` fallback serializes the cases like nextest's `softhsm` group does and no
//! thread C_Finalizes the module under another's sessions (c2 shut its providers down
//! after each test).
#![cfg(feature = "softhsm")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::MutexGuard;

use indexmap::IndexMap;
use r2_config::model::Pkcs11InstanceConfig;
use r2_pkcs11::Pkcs11Provider;
use r2_provider::Provider;
use r2_testkit::provider_contract_tests;
use r2_testkit::softhsm::softhsm_token;
use secrecy::SecretString;

thread_local! {
    /// The global-state guard of the running case (set by its first factory call).
    static GUARD: RefCell<Option<MutexGuard<'static, ()>>> = const { RefCell::new(None) };
}

/// Hold the process-global lock until this test thread exits (idempotent per thread).
fn hold_global_state_lock() {
    GUARD.with(|guard| {
        let mut guard = guard.borrow_mut();
        if guard.is_none() {
            *guard = Some(r2_testkit::global_state_lock());
        }
    });
}

/// A Pkcs11Provider logged in to the fixture token (c2 `make_provider`).
fn logged_in_provider() -> Rc<dyn Provider> {
    hold_global_state_lock();
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
