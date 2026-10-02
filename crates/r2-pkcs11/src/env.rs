//! THE single audited `std::env::set_var` site of r2 production code (spec §4.1.3, §4.5.5).

/// Sets each (key, value) in the process environment: `unsafe { std::env::set_var(k, v) }`
/// with `#[allow(unsafe_code)]` + `// SAFETY:` (single-threaded invariant, §6) and
/// `debug_assert!(!r2_core::runtime::spinner_active())`.
pub(crate) fn apply_env(vars: &[(&str, &str)]) {
    debug_assert!(!r2_core::runtime::spinner_active());
    for (key, value) in vars {
        tracing::debug!(target: "r2::pkcs11", "setting environment variable {key}");
        #[allow(unsafe_code, clippy::disallowed_methods)]
        // SAFETY: r2 is single-threaded (spec §6): the only other threads (the ctrlc handler
        // and the indicatif ticker) never read the environment, and the ticker runs only
        // inside `busy()` sections, which the debug assertion above excludes (providers are
        // initialized before any busy section). No other thread can observe a torn
        // environment while this call runs.
        unsafe {
            std::env::set_var(key, value)
        };
    }
}
