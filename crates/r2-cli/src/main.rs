//! The `r2` binary (spec §4.9.11; owner R7) — the port of c2 `app.main` / `__main__.py`.
//!
//! Startup order: args → subscriber (lastResort mode) → `load_config` → logging → panic hook → ctrlc handler →
//! `ensure_legacy_provider` → IO → providers → operations → template editor → commands →
//! AppContext → banner → REPL → shutdown of every provider. A ConsoleError before the REPL is
//! written to stderr as "error: {message}" (+ " (hint: {hint})"), exit status 2.
#![forbid(unsafe_code)]
mod args;
mod bootstrap;
mod logging;
mod panic;

use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::ExitCode;
use std::rc::Rc;

use clap::Parser;
use r2_config::loader::load_config;
use r2_config::model::{AppConfig, LoadedConfig};
use r2_console::AppContext;
use r2_console::commands::all_commands;
use r2_console::io::open_console_io;
use r2_console::template_editor::create_template_editor;
use r2_core::error::ConsoleError;
use r2_core::io::{ConsoleIo, Renderable};
use r2_core::text::py_repr;
use r2_ops::build_operation_registry;
use r2_provider::ProviderRegistry;

use crate::args::Args;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exit status of a startup error (c2 `return 2`).
const STARTUP_ERROR: u8 = 2;
/// Exit status of a startup panic (c2: an uncaught exception, status 1).
const STARTUP_PANIC: u8 = 1;

fn main() -> ExitCode {
    let args = Args::parse();
    ExitCode::from(run(&args, None, &bootstrap::build_provider_registry))
}

/// "error: {message}" + " (hint: {hint})" (c2 `_format_startup_error`).
fn format_startup_error(err: &ConsoleError) -> String {
    let mut line = format!("error: {}", err.message);
    if let Some(hint) = err.hint.as_deref().filter(|hint| !hint.is_empty()) {
        line.push_str(&format!(" (hint: {hint})"));
    }
    line.push('\n');
    line
}

/// A pre-REPL startup error (an allowed print site, §4.1.3): stderr, exit 2.
fn startup_error(err: &ConsoleError) -> u8 {
    let _ = std::io::stderr()
        .lock()
        .write_all(format_startup_error(err).as_bytes());
    STARTUP_ERROR
}

/// The ctrlc handler: one atomic store (installed before the first prompt — rpassword
/// raise()s SIGINT itself, §6).
fn install_ctrlc() {
    if let Err(err) = ctrlc::set_handler(r2_core::runtime::request_interrupt) {
        tracing::warn!(target: "r2::app", "cannot install the Ctrl-C handler: {err}");
    }
}

/// Whether stdout is a terminal, for the decorative banner only. The std check may accept
/// an msys pipe on Windows (why `IsTty` decides the real TerminalIo/PlainIo switch); for
/// a cosmetic banner that is harmless.
#[allow(clippy::disallowed_methods)] // the banner-only std terminal check
fn stdout_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

/// The dog shown above the startup line on a terminal (printed as is, no colors).
const DOG: &str = r"           ^\
 /        //o__o
/\       /  __/
\ \______\  /     -ARF!
 \         /
  \ \----\ \
   \_\_   \_\_";

/// The dog as plain text (no styling on any sink).
fn dog_banner() -> Renderable {
    Renderable::Text(DOG.to_owned())
}

/// The dog is decoration for a person at a terminal: never on an injected (test) IO, never
/// into a pipe, so scripted sessions and the parity harness keep c2's banner (§11 D33).
fn shows_banner(io_injected: bool, stdout_is_terminal: bool) -> bool {
    !io_injected && stdout_is_terminal
}

/// How the provider registry is built (`build_provider_registry`; tests inject stubs).
type BuildProviders<'a> = &'a dyn Fn(&AppConfig) -> r2_core::Result<ProviderRegistry>;

/// c2 `main(argv, io=…)`: `io` is the test seam (None → the terminal's ConsoleIo), and so
/// is `build_providers` (c2's tests injected stub provider modules).
fn run(args: &Args, io: Option<Rc<dyn ConsoleIo>>, build_providers: BuildProviders<'_>) -> u8 {
    // the subscriber exists before load_config: its warnings reach stderr as bare messages
    // until setup_logging (Python's lastResort handler, which printed them for c2)
    logging::install();
    let loaded = match load_config(args.config_path().as_deref()) {
        Ok(loaded) => loaded,
        Err(err) => return startup_error(&err),
    };
    if let Err(err) = logging::setup_logging(&loaded.config.app.log, args.debug) {
        return startup_error(&err);
    }
    panic::install();
    install_ctrlc();
    let log_file = loaded.config.app.log.file.clone();
    match catch_unwind(AssertUnwindSafe(|| {
        session(loaded, args.debug, io, build_providers)
    })) {
        Ok(code) => code,
        Err(payload) => {
            // a panic outside the REPL's per-command boundary (e.g. in a constructor)
            let message = panic::payload_text(payload.as_ref());
            let report = r2_core::runtime::take_panic_report();
            tracing::error!(
                target: "r2::app",
                "unexpected error: {}",
                report.as_deref().unwrap_or(&message)
            );
            let mut stderr = std::io::stderr().lock();
            if args.debug
                && let Some(report) = &report
            {
                let _ = writeln!(stderr, "{report}");
            }
            let err = ConsoleError::generic(format!("unexpected error: {message}"))
                .with_hint(format!("details logged to {}", log_file.display()));
            let _ = stderr.write_all(format_startup_error(&err).as_bytes());
            STARTUP_PANIC
        }
    }
}

/// Shuts every provider down when the REPL is left (c2's `finally`, which ran on an
/// exception too); errors are logged as warnings, a panicking shutdown is caught and logged.
fn shutdown_providers(ctx: &AppContext) {
    for provider in ctx.providers.all() {
        let name = provider.name().to_owned();
        match catch_unwind(AssertUnwindSafe(|| provider.shutdown())) {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::warn!(
                target: "r2::app",
                "shutdown of provider {} failed: {}",
                py_repr(&name),
                err.message
            ),
            Err(_) => {
                let report = r2_core::runtime::take_panic_report();
                tracing::error!(
                    target: "r2::app",
                    "shutdown of provider {} failed: {}",
                    py_repr(&name),
                    report.as_deref().unwrap_or("panic")
                );
            }
        }
    }
}

fn session(
    loaded: LoadedConfig,
    debug: bool,
    io: Option<Rc<dyn ConsoleIo>>,
    build_providers: BuildProviders<'_>,
) -> u8 {
    r2_core::crypto::ensure_legacy_provider();
    let config = &loaded.config;
    let show_dog = shows_banner(io.is_some(), stdout_is_terminal());
    // §11 D31: results of a real session show the provider time; an injected (test) IO
    // keeps c2's output
    r2_core::runtime::set_timing_shown(io.is_none());
    let io = io.unwrap_or_else(|| open_console_io(config));
    let startup = || -> r2_core::Result<_> {
        let providers = build_providers(config)?;
        let operations = build_operation_registry(&config.custom_mechanisms)?;
        let template_editor = create_template_editor(Rc::clone(&io), config);
        let commands = all_commands()?;
        Ok((providers, operations, template_editor, commands))
    };
    let (providers, operations, template_editor, commands) = match startup() {
        Ok(parts) => parts,
        Err(err) => {
            tracing::error!(target: "r2::app", "startup failed: {}", err.message);
            return startup_error(&err);
        }
    };
    let count = providers.all().len();
    let ctx = Rc::new(AppContext {
        config: Rc::new(loaded),
        providers,
        operations,
        io,
        template_editor,
    });
    tracing::info!(target: "r2::app", "r2 {VERSION} started ({count} providers)");
    if show_dog {
        ctx.io.print(dog_banner());
    }
    ctx.io.print(Renderable::Text(format!(
        "r2 {VERSION} — type 'help' for commands"
    )));
    repl_then_shutdown(&ctx, debug, commands);
    0
}

/// `run_repl`, then the providers' shutdown — also when a panic escapes the REPL
/// (outside its per-command boundary): the shutdown runs after every command frame and
/// borrow has been unwound, then the panic continues to run()'s startup-panic handler
/// with its own report.
fn repl_then_shutdown(ctx: &Rc<AppContext>, debug: bool, commands: Rc<r2_console::CommandTable>) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        r2_console::run_repl(ctx, debug, commands);
    }));
    let report = outcome
        .is_err()
        .then(r2_core::runtime::take_panic_report)
        .flatten();
    shutdown_providers(ctx);
    if let Err(payload) = outcome {
        if let Some(report) = report {
            r2_core::runtime::record_panic_report(report);
        }
        std::panic::resume_unwind(payload);
    }
}

#[cfg(test)]
mod tests {
    //! The port of c2 tests/unit/console/test_app.py's `main()` cases (stub providers) and
    //! the panic path through the real hook and log file.
    use std::path::Path;

    use clap::Parser;
    use r2_console::commands::Command;
    use r2_console::{BoundArgs, CommandTable, Flow};
    use r2_testkit::{ScriptedIo, global_state_lock};
    use tracing::level_filters::LevelFilter;

    use super::*;
    use crate::bootstrap::tests::{CUSTOM_MECH, StubProviders};

    #[test]
    fn dog_banner_render_is_the_art_verbatim_without_colors() {
        let cfg = r2_core::render::RenderConfig::CAPTURE;
        assert_eq!(DOG.lines().count(), 7);
        assert!(DOG.contains("-ARF!"));
        // every sink prints the art exactly: no SGR, nothing wrapped or stripped
        assert_eq!(r2_core::render::render_plain(&dog_banner(), &cfg), DOG);
        assert_eq!(r2_core::render::render(&dog_banner(), &cfg), DOG);
        assert_eq!(r2_core::render::render_no_color(&dog_banner(), &cfg), DOG);
    }

    #[test]
    fn dog_banner_shows_only_on_a_terminal_without_an_injected_io() {
        assert!(shows_banner(false, true));
        assert!(!shows_banner(true, true));
        assert!(!shows_banner(false, false));
        assert!(!shows_banner(true, false));
    }

    #[test]
    fn dog_banner_is_not_shown_on_an_injected_io() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        let config = write_isolated_config(dir.path(), "");
        let io = Rc::new(ScriptedIo::new(["exit"]));
        let code = run(
            &args(&["--config", &config.display().to_string()]),
            Some(Rc::clone(&io) as Rc<dyn ConsoleIo>),
            &|c: &AppConfig| crate::bootstrap::build_with(c, &StubProviders::default()),
        );
        assert_eq!(code, 0);
        assert!(!io.output().iter().any(|line| line.contains("-ARF!")));
    }

    /// An external config keeping history/log inside `dir` and autodetect off.
    fn write_isolated_config(dir: &Path, extra: &str) -> std::path::PathBuf {
        let path = dir.join("r2.yaml");
        let text = format!(
            "app:\n  history_file: {history}\n  log:\n    level: info\n    file: {log}\n    \
             max_bytes: 65536\n    backups: 1\nsofthsm:\n  autodetect: false\n{extra}",
            history = dir.join("history").display(),
            log = dir.join("cc.log").display(),
        );
        std::fs::write(&path, text).unwrap();
        path
    }

    fn args(argv: &[&str]) -> Args {
        Args::try_parse_from(std::iter::once("r2").chain(argv.iter().copied())).unwrap()
    }

    #[test]
    fn test_config_flag_missing_file_is_a_hard_error() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("absent.yaml");
        let code = run(
            &args(&["--config", &absent.display().to_string()]),
            Some(Rc::new(ScriptedIo::empty())),
            &|c: &AppConfig| crate::bootstrap::build_with(c, &StubProviders::default()),
        );
        assert_eq!(code, 2);
        let err = load_config(Some(&absent)).err().unwrap();
        assert_eq!(
            format_startup_error(&err),
            format!(
                "error: config file not found: {} (hint: --config must point to an existing file)\n",
                absent.display()
            )
        );
    }

    #[test]
    fn test_main_runs_a_scripted_session_with_stub_providers() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        let config = write_isolated_config(dir.path(), "");
        let io = Rc::new(ScriptedIo::new(["help", "exit"]));
        let stub = StubProviders::default();
        let code = run(
            &args(&["--config", &config.display().to_string()]),
            Some(Rc::clone(&io) as Rc<dyn ConsoleIo>),
            &|c: &AppConfig| crate::bootstrap::build_with(c, &stub),
        );
        assert_eq!(code, 0);
        let output = io.output();
        assert_eq!(
            output[0],
            format!("r2 {VERSION} — type 'help' for commands")
        ); // banner
        assert!(output.iter().any(|line| line.contains("shows its usage"))); // help ran
        assert_eq!(*stub.memory_created.borrow(), ["mem"]);
        assert!(dir.path().join("cc.log").exists());
        let log = std::fs::read_to_string(dir.path().join("cc.log")).unwrap();
        assert!(log.contains(&format!("r2 {VERSION} started (1 providers)")));
    }

    #[test]
    fn test_main_debug_flag_forces_debug_and_stderr_mirror() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        let config = write_isolated_config(dir.path(), "");
        let code = run(
            &args(&["--config", &config.display().to_string(), "--debug"]),
            Some(Rc::new(ScriptedIo::new(["exit"]))),
            &|c: &AppConfig| crate::bootstrap::build_with(c, &StubProviders::default()),
        );
        assert_eq!(code, 0);
        assert_eq!(logging::settings(), Some((LevelFilter::DEBUG, true)));
        // DEBUG records reach the file (the REPL logs dispatched command names)
        let log = std::fs::read_to_string(dir.path().join("cc.log")).unwrap();
        assert!(log.contains("DEBUG   r2::console: command: exit"));
    }

    #[test]
    fn test_main_shuts_providers_down_in_the_finally() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        let config = write_isolated_config(dir.path(), "");
        let stub = StubProviders::default();
        let code = run(
            &args(&["--config", &config.display().to_string()]),
            Some(Rc::new(ScriptedIo::new(["quit"]))),
            &|c: &AppConfig| crate::bootstrap::build_with(c, &stub),
        );
        assert_eq!(code, 0);
        let instances = stub.memory_instances.borrow();
        let [memory] = instances.as_slice() else {
            panic!("one memory provider expected");
        };
        assert!(memory.calls().contains(&vec!["shutdown".to_owned()]));
        // Ctrl-D at the prompt also shuts down (status 0)
        let stub = StubProviders::default();
        let code = run(
            &args(&["--config", &config.display().to_string()]),
            Some(Rc::new(ScriptedIo::new([ScriptedIo::CTRL_D]))),
            &|c: &AppConfig| crate::bootstrap::build_with(c, &stub),
        );
        assert_eq!(code, 0);
        assert!(
            stub.memory_instances.borrow()[0]
                .calls()
                .contains(&vec!["shutdown".to_owned()])
        );
    }

    /// A panic payload whose Drop panics: run_repl catches the command's panic, and the
    /// payload's drop then panics OUTSIDE the per-command boundary (c2: an exception out
    /// of run_repl, still inside `finally`).
    struct ExplodingPayload;
    impl Drop for ExplodingPayload {
        fn drop(&mut self) {
            panic!("renderer exploded");
        }
    }
    struct Escape;
    impl Command for Escape {
        fn name(&self) -> &'static str {
            "escape"
        }
        fn summary(&self) -> &'static str {
            "panics past the REPL"
        }
        fn usage(&self) -> &'static str {
            "escape"
        }
        fn run(&self, _ctx: &AppContext, _args: &BoundArgs) -> r2_core::Result<Flow> {
            std::panic::panic_any(ExplodingPayload)
        }
    }

    #[test]
    fn providers_are_shut_down_when_a_panic_escapes_the_repl() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_isolated_config(dir.path(), "");
        let loaded = load_config(Some(&config_path)).unwrap();
        logging::configure(&loaded.config.app.log, false, None).unwrap();
        panic::install();
        let stub = StubProviders::default();
        let config = loaded.config.clone();
        let io = Rc::new(ScriptedIo::new(["escape", "exit"]));
        let ctx = Rc::new(AppContext {
            config: Rc::new(loaded),
            providers: crate::bootstrap::build_with(&config, &stub).unwrap(),
            operations: build_operation_registry(&config.custom_mechanisms).unwrap(),
            io: Rc::clone(&io) as Rc<dyn ConsoleIo>,
            template_editor: create_template_editor(Rc::clone(&io) as Rc<dyn ConsoleIo>, &config),
        });
        let mut commands: CommandTable = (*all_commands().unwrap()).clone();
        commands.insert("escape", Rc::new(Escape));
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            repl_then_shutdown(&ctx, false, Rc::new(commands))
        }));
        let _ = std::panic::take_hook();
        let payload = outcome.unwrap_err();
        assert_eq!(panic::payload_text(payload.as_ref()), "renderer exploded");
        // the providers were shut down before the panic continued to run()'s handler,
        // whose report survived the shutdown
        assert!(
            stub.memory_instances.borrow()[0]
                .calls()
                .contains(&vec!["shutdown".to_owned()])
        );
        let report = r2_core::runtime::take_panic_report().unwrap();
        assert!(report.starts_with("renderer exploded at "), "{report}");
    }

    #[test]
    fn shutdown_failures_are_logged_as_warnings() {
        struct FailingShutdown;
        impl r2_testkit::FakeHooks for FailingShutdown {
            fn shutdown(&self, _next: &dyn r2_provider::Provider) -> Option<r2_core::Result<()>> {
                Some(Err(ConsoleError::provider("token went away")))
            }
        }
        struct Failing;
        impl crate::bootstrap::ProviderFactory for Failing {
            fn memory(&self, name: &str) -> Rc<dyn r2_provider::Provider> {
                Rc::new(r2_testkit::FakeProvider::new(name).with_hooks(Rc::new(FailingShutdown)))
            }
            fn pkcs11(
                &self,
                name: &str,
                _instance: r2_config::model::Pkcs11InstanceConfig,
                _ckm: std::collections::BTreeMap<u64, String>,
                _config: &r2_config::model::AppConfig,
            ) -> Rc<dyn r2_provider::Provider> {
                Rc::new(r2_testkit::FakeProvider::new(name))
            }
            fn find_softhsm(&self, _paths: &[std::path::PathBuf]) -> Option<std::path::PathBuf> {
                None
            }
        }
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        let config = write_isolated_config(dir.path(), "");
        let code = run(
            &args(&["--config", &config.display().to_string()]),
            Some(Rc::new(ScriptedIo::new(["exit"]))),
            &|c: &AppConfig| crate::bootstrap::build_with(c, &Failing),
        );
        assert_eq!(code, 0);
        let log = std::fs::read_to_string(dir.path().join("cc.log")).unwrap();
        assert!(
            log.contains("WARNING r2::app: shutdown of provider 'mem' failed: token went away")
        );
    }

    #[test]
    fn startup_errors_after_logging_exit_2() {
        // a custom mechanism naming an unknown provider fails at load; a duplicate operation
        // id fails at build_operation_registry (both are startup errors, exit 2)
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        let duplicate = format!(
            "{CUSTOM_MECH}  - id: aes.encrypt.gcm\n    verb: encrypt\n    \
             algorithm: aes\n    cli_name: x\n    label: X\n    ckm: 0x80000001\n"
        );
        let config = write_isolated_config(dir.path(), &duplicate);
        let io = Rc::new(ScriptedIo::empty());
        let code = run(
            &args(&["--config", &config.display().to_string()]),
            Some(Rc::clone(&io) as Rc<dyn ConsoleIo>),
            &|c: &AppConfig| crate::bootstrap::build_with(c, &StubProviders::default()),
        );
        assert_eq!(code, 2);
        assert!(io.output().is_empty()); // no banner, no REPL
        let log = std::fs::read_to_string(dir.path().join("cc.log")).unwrap();
        assert!(log.contains("startup failed: operation 'aes.encrypt.gcm' is already registered"));
    }

    struct Boom;
    impl Command for Boom {
        fn name(&self) -> &'static str {
            "boom"
        }
        fn summary(&self) -> &'static str {
            "panics"
        }
        fn usage(&self) -> &'static str {
            "boom"
        }
        fn run(&self, _ctx: &AppContext, _args: &BoundArgs) -> r2_core::Result<Flow> {
            panic!("kaputt")
        }
    }

    /// A panic inside a command: the hook records message, location and backtrace; the
    /// REPL logs it and renders "unexpected error: …" (+ the backtrace with --debug).
    fn panic_session(debug: bool) -> (Vec<String>, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_isolated_config(dir.path(), "");
        let loaded = load_config(Some(&config_path)).unwrap();
        logging::configure(&loaded.config.app.log, debug, None).unwrap();
        panic::install();
        let io = Rc::new(ScriptedIo::new(["boom", "exit"]));
        let config = loaded.config.clone();
        let ctx = Rc::new(AppContext {
            config: Rc::new(loaded),
            providers: r2_provider::ProviderRegistry::new(),
            operations: build_operation_registry(&config.custom_mechanisms).unwrap(),
            io: Rc::clone(&io) as Rc<dyn ConsoleIo>,
            template_editor: create_template_editor(Rc::clone(&io) as Rc<dyn ConsoleIo>, &config),
        });
        let mut commands: CommandTable = (*all_commands().unwrap()).clone();
        commands.insert("boom", Rc::new(Boom));
        r2_console::run_repl(&ctx, debug, Rc::new(commands));
        let _ = std::panic::take_hook();
        let log = std::fs::read_to_string(dir.path().join("cc.log")).unwrap();
        (io.output(), log, config.app.log.file.display().to_string())
    }

    #[test]
    fn a_panic_inside_a_command_renders_unexpected_error_and_is_logged() {
        let _lock = global_state_lock();
        let (output, log, log_file) = panic_session(false);
        assert_eq!(
            output,
            [format!(
                "error: unexpected error: kaputt (hint: details logged to {log_file})"
            )]
        );
        assert!(log.contains("ERROR   r2::console: unexpected error: kaputt at "));
        assert!(log.contains("src/main.rs"));
        assert!(log.contains("a_panic_inside_a_command") || log.contains("panic_session"));
    }

    #[test]
    fn debug_prints_the_backtrace_before_the_panel() {
        let _lock = global_state_lock();
        let (output, _log, _) = panic_session(true);
        assert_eq!(output.len(), 2);
        assert!(output[0].starts_with("kaputt at "));
        assert!(output[0].contains("src/main.rs"));
        assert!(output[0].lines().count() > 3); // the captured backtrace frames
        assert!(output[1].starts_with("error: unexpected error: kaputt"));
    }

    #[test]
    fn the_panic_hook_records_message_location_and_backtrace() {
        let _lock = global_state_lock();
        panic::install();
        let caught = std::panic::catch_unwind(|| panic!("boom {}", 7));
        let _ = std::panic::take_hook();
        assert!(caught.is_err());
        let report = r2_core::runtime::take_panic_report().unwrap();
        assert!(report.starts_with("boom 7 at "));
        assert!(report.contains("src/main.rs:"));
        assert!(r2_core::runtime::take_panic_report().is_none());
    }
}
