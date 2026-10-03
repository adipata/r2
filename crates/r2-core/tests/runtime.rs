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
    check_interrupt, interrupted, record_panic_report, request_interrupt,
    request_interrupt_on_this_thread, reset_interrupt, set_spinner_active, spinner_active,
    take_panic_report,
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

/// R13: the in-process test Ctrl-C is seen only by the thread that requested it (the
/// `cargo test` fallback runs other tests concurrently on other threads), and
/// reset_interrupt clears it.
#[test]
fn thread_local_interrupt_is_invisible_to_other_threads() {
    let _lock = global_state_lock();
    reset_interrupt();
    request_interrupt_on_this_thread();
    assert!(interrupted());
    assert!(check_interrupt().is_err());
    let elsewhere = std::thread::scope(|scope| scope.spawn(interrupted).join().unwrap());
    assert!(!elsewhere);
    reset_interrupt();
    assert!(!interrupted());
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

// ---- operation timing (§11 D31) -----------------------------------------------------------

use std::time::Duration;

use r2_core::runtime::{
    format_elapsed, reset_operation_time, set_timing_shown, take_operation_time, timed,
    timing_shown, timing_suffix,
};

#[test]
fn format_elapsed_uses_adaptive_truncated_units() {
    let cases = [
        (Duration::ZERO, "0µs"),
        (Duration::from_nanos(999), "0µs"),
        (Duration::from_micros(412), "412µs"),
        (Duration::from_micros(999), "999µs"),
        (Duration::from_millis(1), "1ms"),
        (Duration::from_micros(4_999), "4ms"),
        (Duration::from_micros(999_999), "999ms"),
        (Duration::from_secs(1), "1.00s"),
        (Duration::from_millis(1_239), "1.23s"),
        (Duration::from_millis(61_505), "61.50s"),
    ];
    for (elapsed, expected) in cases {
        assert_eq!(format_elapsed(elapsed), expected, "{elapsed:?}");
    }
}

#[test]
fn timed_accumulates_until_taken_and_only_shows_when_on() {
    assert!(
        !timing_shown(),
        "off by default (in-process sessions keep c2's output)"
    );
    reset_operation_time();
    assert_eq!(timed(|| 7), 7);
    assert_eq!(take_operation_time(), None, "measured but not shown");
    assert_eq!(timing_suffix(), "");

    set_timing_shown(true);
    timed(|| std::thread::sleep(Duration::from_millis(2)));
    timed(|| std::thread::sleep(Duration::from_millis(2)));
    let total = take_operation_time().unwrap();
    assert!(total >= Duration::from_millis(4), "{total:?}");
    assert_eq!(take_operation_time(), None, "taken (emptied)");

    timed(|| ());
    let suffix = timing_suffix();
    assert!(
        suffix.starts_with(" in ") && suffix.ends_with("µs"),
        "{suffix:?}"
    );
    assert_eq!(timing_suffix(), "", "the suffix takes the time");

    timed(|| ());
    reset_operation_time();
    assert_eq!(take_operation_time(), None, "reset before every dispatch");
    set_timing_shown(false);
}

#[test]
fn operation_time_is_per_thread() {
    set_timing_shown(true);
    reset_operation_time();
    timed(|| ());
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                assert!(!timing_shown());
                set_timing_shown(true);
                assert_eq!(take_operation_time(), None);
            })
            .join()
            .unwrap();
    });
    assert!(take_operation_time().is_some());
    set_timing_shown(false);
}
