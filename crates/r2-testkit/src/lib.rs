// r2-testkit crate root (owner R0, spec §4.1.1; dev-dependency only, §4.10).
#![deny(unsafe_code)] // §4.1.3: the one allowed site is `env` (test-only set_var/remove_var)
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]
pub mod contract;
pub mod env;
pub mod fake_provider;
pub mod fixtures;
pub mod scripted_io;
#[cfg(feature = "softhsm")]
pub mod softhsm;

pub use env::{EnvGuard, set_env};
pub use fake_provider::{FakeHooks, FakeProvider};
pub use scripted_io::{RecordingEditor, ScriptedIo, global_state_lock};
