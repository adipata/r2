// R0 skeleton — owner R1 (generated from spec §4)
// ---- spec §4.9.8 block 0
// plus one thread-local panic-report slot
/// Called by the ctrlc handler (r2-cli): one atomic store, nothing else.
pub fn request_interrupt() {
    unimplemented!("R1")
}
/// Called by run_repl immediately before every dispatch (a stale flag would abort the next
/// command — rpassword itself raise()s SIGINT).
pub fn reset_interrupt() {
    unimplemented!("R1")
}
pub fn interrupted() -> bool {
    unimplemented!("R1")
}
/// Step-boundary check for commands and services (e.g. between copy-ladder rungs, between
/// sibling renames): Err(UserAbort "interrupted") when the flag is set (not reset).
pub fn check_interrupt() -> crate::Result<()> {
    Err(crate::error::ConsoleError::not_implemented("R1"))
}
/// Provisional (spinner): set by LineIo::busy while a spinner is shown; read by the
/// audited set_var site (`debug_assert!(!spinner_active())`).
pub fn set_spinner_active(active: bool) {
    let _ = active;
    unimplemented!("R1")
}
pub fn spinner_active() -> bool {
    unimplemented!("R1")
}
/// Called by r2-cli's panic hook (which must be `Send + Sync`, so it cannot capture
/// Rc/RefCell state): stores "{message} at {location}\n{backtrace}" in a THREAD-LOCAL slot
/// of the panicking thread (the REPL thread is the only one whose panics matter).
pub fn record_panic_report(report: String) {
    let _ = report;
    unimplemented!("R1")
}
/// Taken (slot emptied) by run_repl's catch_unwind branch (§4.9.5); None when no hook is
/// installed (tests) or nothing was recorded.
pub fn take_panic_report() -> Option<String> {
    unimplemented!("R1")
}
