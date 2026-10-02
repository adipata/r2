// Ctrl-C flag, spinner flag, panic report (spec §4.9.8; owner R1) — the only process-global
// mutable state (two atomics), plus thread-local slots: the panic report and the in-process
// test emulation of Ctrl-C (R13).
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::ConsoleError;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static SPINNER_ACTIVE: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// The panic report of this thread (a `Cell`, so the panic hook can never hit a
    /// borrow conflict).
    static PANIC_REPORT: Cell<Option<String>> = const { Cell::new(None) };
    /// Ctrl-C requested for this thread only (`request_interrupt_on_this_thread`).
    static INTERRUPTED_HERE: Cell<bool> = const { Cell::new(false) };
}

/// Called by the ctrlc handler (r2-cli): one atomic store, nothing else.
pub fn request_interrupt() {
    INTERRUPTED.store(true, Ordering::SeqCst);
}
/// In-process tests' Ctrl-C (R13, §4.11): a flag only the calling thread observes, so a
/// test emulating Ctrl-C can never abort another test running concurrently in the same
/// process (the `cargo test` fallback runs tests as threads of one process; nextest runs
/// one process per test). Production code never calls it; the ctrlc handler uses
/// `request_interrupt`.
pub fn request_interrupt_on_this_thread() {
    let _ = INTERRUPTED_HERE.try_with(|flag| flag.set(true));
}
/// Called by run_repl immediately before every dispatch (a stale flag would abort the next
/// command — rpassword itself raise()s SIGINT). Also clears the calling thread's
/// `request_interrupt_on_this_thread` flag.
pub fn reset_interrupt() {
    INTERRUPTED.store(false, Ordering::SeqCst);
    let _ = INTERRUPTED_HERE.try_with(|flag| flag.set(false));
}
/// The process-wide flag OR the calling thread's own flag.
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst) || INTERRUPTED_HERE.try_with(Cell::get).unwrap_or(false)
}
/// Step-boundary check for commands and services (e.g. between copy-ladder rungs, between
/// sibling renames): Err(UserAbort "interrupted") when the flag is set (not reset).
pub fn check_interrupt() -> crate::Result<()> {
    if interrupted() {
        Err(ConsoleError::user_abort("interrupted"))
    } else {
        Ok(())
    }
}
/// Provisional (spinner): set by LineIo::busy while a spinner is shown; read by the
/// audited set_var site (`debug_assert!(!spinner_active())`).
pub fn set_spinner_active(active: bool) {
    SPINNER_ACTIVE.store(active, Ordering::SeqCst);
}
pub fn spinner_active() -> bool {
    SPINNER_ACTIVE.load(Ordering::SeqCst)
}
/// Called by r2-cli's panic hook (which must be `Send + Sync`, so it cannot capture
/// Rc/RefCell state): stores "{message} at {location}\n{backtrace}" in a THREAD-LOCAL slot
/// of the panicking thread (the REPL thread is the only one whose panics matter).
/// Never panics: during thread teardown (TLS already destroyed) the report is dropped.
pub fn record_panic_report(report: String) {
    let _ = PANIC_REPORT.try_with(|slot| slot.set(Some(report)));
}
/// Taken (slot emptied) by run_repl's catch_unwind branch (§4.9.5); None when no hook is
/// installed (tests) or nothing was recorded.
pub fn take_panic_report() -> Option<String> {
    PANIC_REPORT.try_with(Cell::take).ok().flatten()
}
