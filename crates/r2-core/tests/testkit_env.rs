//! r2_testkit::env (spec §4.10.1): the test-only environment override (c2
//! `monkeypatch.setenv`/`delenv`) restores what it changed, in reverse order.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use r2_testkit::{global_state_lock, set_env};

const KEY: &str = "R2_TESTKIT_ENV_PROBE";

#[test]
fn set_env_sets_and_restores_absent_variables() {
    let _lock = global_state_lock();
    assert_eq!(std::env::var_os(KEY), None);
    {
        let _guard = set_env(KEY, Some("one"));
        assert_eq!(std::env::var(KEY).unwrap(), "one");
    }
    assert_eq!(std::env::var_os(KEY), None);
}

#[test]
fn nested_guards_restore_in_reverse_order() {
    let _lock = global_state_lock();
    let outer = set_env(KEY, Some("outer"));
    {
        let _inner = set_env(KEY, Some("inner"));
        assert_eq!(std::env::var(KEY).unwrap(), "inner");
        let _removed = set_env(KEY, None);
        assert_eq!(std::env::var_os(KEY), None);
    }
    assert_eq!(std::env::var(KEY).unwrap(), "outer");
    drop(outer);
    assert_eq!(std::env::var_os(KEY), None);
}

#[test]
fn removing_an_existing_variable_restores_it() {
    let _lock = global_state_lock();
    let _base = set_env(KEY, Some("kept"));
    {
        let _gone = set_env(KEY, None);
        assert!(std::env::var(KEY).is_err());
    }
    assert_eq!(std::env::var(KEY).unwrap(), "kept");
    // An empty value is a value (set-but-empty), not removal.
    let _empty = set_env(KEY, Some(""));
    assert_eq!(std::env::var(KEY).unwrap(), "");
}

#[test]
fn guards_restore_during_unwinding() {
    let _lock = global_state_lock();
    let result = std::panic::catch_unwind(|| {
        let _guard = set_env(KEY, Some("during panic"));
        panic!("unwind through the guard");
    });
    assert!(result.is_err());
    assert_eq!(std::env::var_os(KEY), None);
}
