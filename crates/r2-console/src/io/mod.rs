// Terminal I/O (spec §4.9.7, §6; owner R7): the color/terminal decision (rich 15 under c2's
// `ui.color` mapping) and the TerminalIo / PlainIo switch.
use std::rc::Rc;

use crossterm::tty::IsTty;
use r2_config::model::{AppConfig, ColorMode};
use r2_core::io::ConsoleIo;

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

/// rich 15's `is_terminal` under c2's mapping (`always` → force_terminal=True).
pub(crate) fn rich_is_terminal(
    ui: ColorMode,
    stdout_is_tty: bool,
    env: &dyn Fn(&str) -> Option<String>,
) -> bool {
    if ui == ColorMode::Always {
        return true;
    }
    match env("TTY_COMPATIBLE").as_deref() {
        Some("0") => return false,
        Some("1") => return true,
        _ => {}
    }
    if let Some(force) = env("FORCE_COLOR") {
        return !force.is_empty();
    }
    stdout_is_tty
}

/// rich 15's dumb-terminal test: `TERM` is dumb/unknown, case-insensitive.
fn dumb_term(env: &dyn Fn(&str) -> Option<String>) -> bool {
    env("TERM").is_some_and(|term| {
        let term = term.to_lowercase();
        term == "dumb" || term == "unknown"
    })
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
    if !rich_is_terminal(ui, stdout_is_tty, env) || dumb_term(env) {
        return SinkStyle::Plain;
    }
    if ui == ColorMode::Never || env("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return SinkStyle::NoColor;
    }
    SinkStyle::Full
}

/// The process environment as the `env` callback of `resolve_color` (lossy UTF-8).
pub(crate) fn process_env(key: &str) -> Option<String> {
    std::env::var_os(key).map(|value| value.to_string_lossy().into_owned())
}

/// The session's ConsoleIo — called once by r2-cli (§4.9.11). TerminalIo iff
/// `crossterm::tty::IsTty` holds for stdin AND stdout and `TERM != "dumb"`; otherwise
/// PlainIo. Prints the one-line mintty/msys warning (hidden input unavailable; suggests
/// Windows Terminal or `winpty r2`) when `std::io::IsTerminal(stdin) && !IsTty(stdin)` —
/// the one allowed IsTerminal site. Sink style = `resolve_color(config.ui.color,
/// IsTty(stdout), env)`; hex layout from `config.ui`; command history at
/// `config.app.history_file` (parent directory created; unusable → in-memory).
pub fn open_console_io(config: &AppConfig) -> Rc<dyn ConsoleIo> {
    let stdin_is_tty = std::io::stdin().is_tty();
    let stdout_is_tty = std::io::stdout().is_tty();
    let stderr_is_tty = std::io::stderr().is_tty();
    #[allow(clippy::disallowed_methods)] // the one sanctioned IsTerminal site (§4.1.3)
    let msys_pty = {
        use std::io::IsTerminal;
        std::io::stdin().is_terminal() && !stdin_is_tty
    };
    if msys_pty {
        use std::io::Write;
        // one of the two sanctioned stderr warnings (§4.1.3)
        let _ = writeln!(
            std::io::stderr().lock(),
            "warning: hidden input is unavailable in this terminal (mintty/msys); use Windows Terminal or run `winpty r2`"
        );
    }
    let env = process_env;
    let style = resolve_color(config.ui.color, stdout_is_tty, &env);
    let sink = line::Sink {
        style,
        target: line::SinkTarget::Stdout,
        width: line::WidthRule::Console {
            is_terminal: rich_is_terminal(config.ui.color, stdout_is_tty, &env),
        },
    };
    let term_dumb = std::env::var_os("TERM").is_some_and(|term| term == "dumb");
    if stdin_is_tty && stdout_is_tty && !term_dumb {
        let primary = terminal::ReedlineReader::new(
            Some(config.app.history_file.as_path()),
            style == SinkStyle::Full,
        );
        let fallback = plain::PlainReader::new(
            true,
            Some(history::SecretFilteringHistory::open(Some(
                config.app.history_file.as_path(),
            ))),
        );
        let reader = terminal::DegradingReader::new(primary, fallback);
        Rc::new(line::LineIo::new(
            reader,
            sink,
            config.ui.hex_group,
            config.ui.hex_width,
            stderr_is_tty,
        ))
    } else {
        Rc::new(line::LineIo::new(
            plain::PlainReader::new(
                stdin_is_tty,
                Some(history::SecretFilteringHistory::open(Some(
                    config.app.history_file.as_path(),
                ))),
            ),
            sink,
            config.ui.hex_group,
            config.ui.hex_width,
            false,
        ))
    }
}

pub mod assist;
pub mod history;
pub mod line;
pub mod plain;
pub mod session;
pub mod terminal;

pub use assist::{
    AssistGuard, BridgeCompleter, BridgeHighlighter, LineAssist, install_line_assist,
};
pub use history::{SecretFilteringHistory, is_secret_line};
pub use line::{LineIo, LineReader, ReadOutcome, SecretRead};
pub use plain::{PlainIo, PlainReader};
pub use session::{FrameSession, TermOp, TerminalDriver};
pub use terminal::{DegradingReader, TerminalIo};
