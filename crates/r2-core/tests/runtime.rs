//! Ctrl-C flag, spinner flag and panic-report slot (spec §4.9.8). r2 addition: c2 had
//! Python's KeyboardInterrupt instead (§11 D13). Every test holds the global-state lock and
//! restores the flags it changed (§4.1.3).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use r2_core::error::ErrorKind;
use r2_core::runtime::{
    check_interrupt, interrupted, record_panic_report, request_interrupt, reset_interrupt,
    set_spinner_active, spinner_active, take_panic_report,
};
use r2_testkit::global_state_lock;

#[test]
fn interrupt_flag_request_check_reset() {
    let _lock = global_state_lock();
    reset_interrupt();
    assert!(!interrupted());
    assert!(check_interrupt().is_ok());
    request_interrupt();
    assert!(interrupted());
    let err = check_interrupt().unwrap_err();
    assert_eq!(
        (err.kind, err.message.as_str()),
        (ErrorKind::UserAbort, "interrupted")
    );
    // check_interrupt does not reset the flag; only reset_interrupt does.
    assert!(interrupted());
    assert!(check_interrupt().is_err());
    reset_interrupt();
    assert!(!interrupted());
    assert!(check_interrupt().is_ok());
}

#[test]
fn spinner_flag_round_trip() {
    let _lock = global_state_lock();
    let before = spinner_active();
    set_spinner_active(true);
    assert!(spinner_active());
    set_spinner_active(false);
    assert!(!spinner_active());
    set_spinner_active(before);
}

#[test]
fn panic_report_is_taken_once() {
    let _lock = global_state_lock();
    let _ = take_panic_report();
    assert_eq!(take_panic_report(), None);
    record_panic_report("boom at src/x.rs:1:1\nbacktrace".to_owned());
    record_panic_report("second at src/y.rs:2:2\n".to_owned()); // the latest wins
    assert_eq!(
        take_panic_report().as_deref(),
        Some("second at src/y.rs:2:2\n")
    );
    assert_eq!(take_panic_report(), None);
}

/// The slot is filled from inside a panic hook on the panicking thread, then taken after
/// catch_unwind — the run_repl flow (§4.9.5).
#[test]
fn panic_report_from_a_hook() {
    let _lock = global_state_lock();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        record_panic_report(format!("hook saw a panic at {location}"));
    }));
    let result = std::panic::catch_unwind(|| panic!("inside a command"));
    std::panic::set_hook(previous);
    assert!(result.is_err());
    let report = take_panic_report().unwrap();
    assert!(report.starts_with("hook saw a panic at "), "{report}");
    assert!(report.contains("runtime.rs"), "{report}");
}
