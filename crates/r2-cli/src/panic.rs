//! Panic hook (spec §4.9.8/§4.9.11; owner R7): records "{message} at {location}\n{backtrace}"
//! through `r2_core::runtime::record_panic_report` for the REPL's unexpected-error branch.
//! The hook is `Send + Sync`, captures no app state and never touches the terminal.
use std::backtrace::Backtrace;
use std::panic::PanicHookInfo;

/// The payload text of a panic (`&str` / `String`), else a placeholder.
pub(crate) fn payload_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "Box<dyn Any>".to_owned()
    }
}

/// "{message} at {file}:{line}:{column}\n{backtrace}".
pub(crate) fn format_report(info: &PanicHookInfo<'_>, backtrace: &Backtrace) -> String {
    let message = payload_text(info.payload());
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "<unknown location>".to_owned());
    format!("{message} at {location}\n{backtrace}")
}

/// Installs the hook (replacing the default one, which would print to stderr).
pub(crate) fn install() {
    std::panic::set_hook(Box::new(|info| {
        let backtrace = Backtrace::force_capture();
        r2_core::runtime::record_panic_report(format_report(info, &backtrace));
    }));
}
