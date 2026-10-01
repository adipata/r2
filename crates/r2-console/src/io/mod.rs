// R0 skeleton — owner R7 (generated from spec §4)
// ---- spec §4.9.7 block 1
use r2_config::model::{AppConfig, ColorMode};
use r2_core::io::ConsoleIo;
use std::rc::Rc;

/// How rendered output (always ANSI-styled, §4.9.2) reaches stdout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkStyle {
    /// Every escape sequence passes.
    Full,
    /// Colour SGR parameters are removed, bold/dim/italic/reset kept (rich `no_color`).
    NoColor,
    /// No escape sequences at all (rich: not a terminal, or a dumb one).
    Plain,
}

/// rich 15's `Console` decision under c2's mapping (`always` → force_terminal=True,
/// `never` → no_color=True): is_terminal = true for `always`; otherwise `TTY_COMPATIBLE`
/// "0" → false / "1" → true; otherwise `FORCE_COLOR` set → (its value is non-empty);
/// otherwise `stdout_is_tty`. Not is_terminal, or `TERM` dumb/unknown (case-insensitive)
/// → Plain; else `never` or a non-empty `NO_COLOR` → NoColor; else Full. `CLICOLOR` /
/// `CLICOLOR_FORCE` are ignored (rich ignores them).
pub fn resolve_color(
    ui: ColorMode,
    stdout_is_tty: bool,
    env: &dyn Fn(&str) -> Option<String>,
) -> SinkStyle {
    let _ = (ui, stdout_is_tty, env);
    unimplemented!("R7")
}

/// The session's ConsoleIo — called once by r2-cli (§4.9.11). TerminalIo iff
/// `crossterm::tty::IsTty` holds for stdin AND stdout and `TERM != "dumb"`; otherwise
/// PlainIo. Prints the one-line mintty/msys warning (hidden input unavailable; suggests
/// Windows Terminal or `winpty r2`) when `std::io::IsTerminal(stdin) && !IsTty(stdin)` —
/// the one allowed IsTerminal site. Sink style = `resolve_color(config.ui.color,
/// IsTty(stdout), env)`; hex layout from `config.ui`; command history at
/// `config.app.history_file` (parent directory created; unusable → in-memory).
pub fn open_console_io(config: &AppConfig) -> Rc<dyn ConsoleIo> {
    let _ = config;
    unimplemented!("R7")
}

pub mod assist;
pub mod history;
pub mod line;
pub mod plain;
pub mod terminal;

pub use assist::{
    AssistGuard, BridgeCompleter, BridgeHighlighter, LineAssist, install_line_assist,
};
pub use history::{SecretFilteringHistory, is_secret_line};
pub use line::{LineIo, LineReader, ReadOutcome, SecretRead};
pub use plain::{PlainIo, PlainReader};
pub use terminal::{DegradingReader, TerminalIo};
