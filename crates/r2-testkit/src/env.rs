// R0 skeleton — owner R1 (generated from spec §4)
// ---- spec §4.10.1 block 1
/// Test-only process-environment override (c2 `monkeypatch.setenv`/`delenv`). The caller
/// holds `global_state_lock()` for the whole test (edition 2024: `set_var`/`remove_var` are
/// `unsafe`; the SAFETY argument is that lock plus nextest's process-per-test model).
/// `Some(v)` sets `key` to `v`; `None` removes it. The guard remembers the previous value.
pub fn set_env(key: &str, value: Option<&str>) -> EnvGuard {
    let _ = (key, value);
    unimplemented!("R1")
}

/// Restores the variable on drop: the previous value is set again, or the variable is
/// removed when it was absent. Guards drop in reverse creation order (nested overrides of
/// one key restore correctly). Never panics (§4 unwind safety).
#[must_use]
pub struct EnvGuard {}
impl Drop for EnvGuard {
    fn drop(&mut self) {}
}
