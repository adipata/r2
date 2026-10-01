// Test-only process-environment override (spec §4.10.1; owner R1) — the ONLY test-side env
// mutation site (§4.1.3 unsafe budget).
use std::ffi::OsString;

/// Test-only process-environment override (c2 `monkeypatch.setenv`/`delenv`). The caller
/// holds `global_state_lock()` for the whole test (edition 2024: `set_var`/`remove_var` are
/// `unsafe`; the SAFETY argument is that lock plus nextest's process-per-test model).
/// `Some(v)` sets `key` to `v`; `None` removes it. The guard remembers the previous value.
pub fn set_env(key: &str, value: Option<&str>) -> EnvGuard {
    let previous = std::env::var_os(key);
    apply(key, value.map(OsString::from));
    EnvGuard {
        key: key.to_owned(),
        previous,
    }
}

/// Restores the variable on drop: the previous value is set again, or the variable is
/// removed when it was absent. Guards drop in reverse creation order (nested overrides of
/// one key restore correctly). Never panics (§4 unwind safety).
#[must_use]
pub struct EnvGuard {
    key: String,
    previous: Option<OsString>,
}
impl Drop for EnvGuard {
    fn drop(&mut self) {
        // `set_env` already accepted this key (std panics on an invalid one there, never
        // here), and a value read back from the environment is always valid to set again.
        apply(&self.key, self.previous.take());
    }
}

#[allow(clippy::disallowed_methods)] // the sanctioned test-side env mutation site (§4.1.3)
fn apply(key: &str, value: Option<OsString>) {
    match value {
        // SAFETY: tests that change the environment hold `global_state_lock()` for their
        // whole body (§4.1.3), and nextest runs each test in its own process, so no other
        // thread reads or writes the environment concurrently.
        #[allow(unsafe_code)]
        Some(value) => unsafe { std::env::set_var(key, value) },
        // SAFETY: as above.
        #[allow(unsafe_code)]
        None => unsafe { std::env::remove_var(key) },
    }
}
