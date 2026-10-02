// The provider contract suite instantiated for MemoryProvider (spec §4.10.3, R4) — c2
// tests/unit/test_memory_provider.py::TestMemoryProviderContract.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::rc::Rc;

use r2_memory::MemoryProvider;
use r2_provider::Provider;
use r2_testkit::provider_contract_tests;

provider_contract_tests!(
    memory_contract,
    Rc::new(MemoryProvider::new("mem")) as Rc<dyn Provider>
);
