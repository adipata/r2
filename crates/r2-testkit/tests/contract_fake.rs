// FakeProvider runs the provider contract suite (spec §4.10.3, R3; c2
// tests/contract/test_fake_provider.py). Two presentations: the default "memory" one and
// the "pkcs11" one used by copy-flow tests (starts logged in against a synthetic token,
// honors the §5.5 attribute guarantee).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]
use std::rc::Rc;

use r2_provider::Provider;
use r2_testkit::FakeProvider;
use r2_testkit::provider_contract_tests;

provider_contract_tests!(
    fake_memory,
    Rc::new(FakeProvider::new("fake")) as Rc<dyn Provider>
);
provider_contract_tests!(
    fake_pkcs11,
    Rc::new(FakeProvider::new("fakehsm").with_type_name("pkcs11")) as Rc<dyn Provider>
);
