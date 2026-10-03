// Ctrl-C flag, spinner flag, panic report (spec §4.9.8; owner R1) — the only process-global
// mutable state (two atomics), plus thread-local slots: the panic report, the in-process
// test emulation of Ctrl-C (R13) and the operation timing of §11 D31.
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::error::ConsoleError;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static SPINNER_ACTIVE: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// The panic report of this thread (a `Cell`, so the panic hook can never hit a
    /// borrow conflict).
    static PANIC_REPORT: Cell<Option<String>> = const { Cell::new(None) };
    /// Ctrl-C requested for this thread only (`request_interrupt_on_this_thread`).
    static INTERRUPTED_HERE: Cell<bool> = const { Cell::new(false) };
    /// §11 D31: whether results show the provider time (the r2 binary turns it on).
    static TIMING_SHOWN: Cell<bool> = const { Cell::new(false) };
    /// §11 D31: provider time accumulated by `timed` since the last reset/take.
    static OPERATION_TIME: Cell<Option<Duration>> = const { Cell::new(None) };
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

// ---- operation timing (§11 D31) ---------------------------------------------------------

/// Turns the timing display of results on or off for this thread. Off by default, so
/// in-process sessions (tests, ScriptedIo) print c2's output unchanged; r2-cli turns it on
/// for the REPL thread.
pub fn set_timing_shown(shown: bool) {
    let _ = TIMING_SHOWN.try_with(|flag| flag.set(shown));
}
pub fn timing_shown() -> bool {
    TIMING_SHOWN.try_with(Cell::get).unwrap_or(false)
}
/// Runs ONE provider operation (encrypt, generate_key, import_key, export_key, wrap_key, …;
/// never a lookup, a prompt or file I/O) and adds its wall-clock time to this thread's
/// operation time. Always measures; `take_operation_time` decides whether it is shown.
pub fn timed<T>(f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = f();
    let elapsed = start.elapsed();
    let _ = OPERATION_TIME.try_with(|slot| {
        slot.set(Some(slot.get().unwrap_or_default().saturating_add(elapsed)));
    });
    value
}
/// Called by run_repl immediately before every dispatch (no time leaks into the next
/// command).
pub fn reset_operation_time() {
    let _ = OPERATION_TIME.try_with(|slot| slot.set(None));
}
/// The provider time accumulated since the last reset/take (emptied), or None when nothing
/// was timed or the timing display is off.
pub fn take_operation_time() -> Option<Duration> {
    let taken = OPERATION_TIME.try_with(Cell::take).ok().flatten();
    taken.filter(|_| timing_shown())
}
/// " in {elapsed}" for a text result line, from `take_operation_time` ("" when None).
pub fn timing_suffix() -> String {
    take_operation_time()
        .map(|elapsed| format!(" in {}", format_elapsed(elapsed)))
        .unwrap_or_default()
}
/// Adaptive units: under 1 ms in whole µs ("412µs"), under 1 s in whole ms ("4ms"), else
/// seconds with two decimals ("1.23s"). Truncated, never rounded up into the next unit.
pub fn format_elapsed(elapsed: Duration) -> String {
    if elapsed < Duration::from_millis(1) {
        format!("{}µs", elapsed.as_micros())
    } else if elapsed < Duration::from_secs(1) {
        format!("{}ms", elapsed.as_millis())
    } else {
        let hundredths = elapsed.as_millis() / 10;
        format!("{}.{:02}s", hundredths / 100, hundredths % 100)
    }
}
