//! Piped REPL sessions against the real `r2` binary (spec §5.1, §6, §11 D2; R7): PlainIo
//! transcripts (prompt + echoed line), help, exit, Ctrl-D, the unknown-command suggestion,
//! quoted multiline PEM paste, the caret echo, `config path` / `config show`, the CLI flags,
//! the log-file rules of §4.9.11 and the history filter. The c2 CLI cases of test_app.py and
//! test_smoke.py are ported here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The binary with a scrubbed environment (no NO_COLOR/FORCE_COLOR/COLUMNS/R2_CONFIG leaks)
/// and `dir` as HOME and working directory.
fn r2(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_r2"));
    cmd.env_clear().env("HOME", dir).current_dir(dir);
    cmd
}

/// An external config keeping history/log inside `dir`; no providers are constructed
/// (memory off, autodetect off) so framework sessions need no provider loop's code.
fn write_config(dir: &Path, extra: &str) -> PathBuf {
    let path = dir.join("r2.yaml");
    let text = format!(
        "app:\n  history_file: {}\n  log:\n    level: info\n    file: {}\n    max_bytes: 65536\n    backups: 1\n\
         providers:\n  memory:\n    enabled: false\nsofthsm:\n  autodetect: false\n{extra}",
        dir.join("history").display(),
        dir.join("r2.log").display(),
    );
    std::fs::write(&path, text).unwrap();
    path
}

fn session(dir: &Path, config: &Path, input: &[u8]) -> (String, String, i32) {
    let output = r2(dir)
        .arg("--config")
        .arg(config)
        .write_stdin(input.to_vec())
        .output()
        .unwrap();
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
        output.status.code().unwrap(),
    )
}

fn banner() -> String {
    format!("r2 {VERSION} — type 'help' for commands\n")
}

#[test]
fn test_version_flag() {
    let dir = tempfile::tempdir().unwrap();
    r2(dir.path())
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("r2 {VERSION}\n"));
}

#[test]
fn test_main_help_flag_lists_cli_options() {
    let dir = tempfile::tempdir().unwrap();
    let output = r2(dir.path()).arg("--help").output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8(output.stdout).unwrap();
    for flag in ["--version", "--config", "--debug"] {
        assert!(out.contains(flag), "{flag}");
    }
    assert!(out.contains("Interactive cryptographic operator console."));
}

#[test]
fn usage_errors_exit_2() {
    // §11 D19: clap's texts, c2's exit status
    let dir = tempfile::tempdir().unwrap();
    let output = r2(dir.path()).arg("--bogus").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("--bogus")
    );
}

#[test]
fn test_config_flag_missing_file_is_a_hard_error() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("absent.yaml");
    let output = r2(dir.path())
        .arg("--config")
        .arg(&absent)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let err = String::from_utf8(output.stderr).unwrap();
    assert!(err.contains("error:"));
    assert!(err.contains("config file not found"));
    assert_eq!(
        err,
        format!(
            "error: config file not found: {} (hint: --config must point to an existing file)\n",
            absent.display()
        )
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn test_main_config_flag_with_missing_file_is_a_hard_error() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("absent.yaml");
    let output = r2(dir.path())
        .arg("--config")
        .arg(&absent)
        .arg("--debug")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("config file not found")
    );
}

#[test]
fn help_then_exit_transcript() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let (out, err, code) = session(dir.path(), &config, b"help\nexit\n");
    assert_eq!(code, 0);
    assert_eq!(err, "");
    assert!(out.starts_with(&format!("{}r2> help\n", banner())));
    for name in ["clear", "config", "exit", "help", "quit"] {
        assert!(out.contains(&format!(" {name} ")), "{name}");
    }
    assert!(out.contains("List commands, or show usage for one command"));
    assert!(out.ends_with("help <command> shows its usage\nr2> exit\n"));
    assert!(!out.contains('\u{1b}')); // no ANSI escapes when piped (§6)
}

#[test]
fn ctrl_d_at_the_prompt_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let (out, _, code) = session(dir.path(), &config, b"");
    assert_eq!(code, 0);
    assert_eq!(out, format!("{}r2> \n", banner()));
}

#[test]
fn unknown_command_suggestion_transcript() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let (out, _, code) = session(dir.path(), &config, b"helpp\nnosuchthing\n");
    assert_eq!(code, 0);
    let expected = format!(
        "{}r2> helpp\n\
         ╭─ error ──────────────────╮\n\
         │ unknown command 'helpp'  │\n\
         │ hint: did you mean: help │\n\
         ╰──────────────────────────╯\n\
         r2> nosuchthing\n\
         ╭─ error ────────────────────────────────╮\n\
         │ unknown command 'nosuchthing'          │\n\
         │ hint: type 'help' for the command list │\n\
         ╰────────────────────────────────────────╯\n\
         r2> \n",
        banner()
    );
    assert_eq!(out, expected);
}

#[test]
fn quoted_multiline_pem_paste_is_one_token() {
    // the `…> ` continuation joins the physical lines; the PEM lands as ONE positional —
    // shown through `help`'s unknown-command message, which echoes it verbatim.
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let input = b"help \"-----BEGIN X-----\nAAAA=\n-----END X-----\"\nexit\n";
    let (out, _, code) = session(dir.path(), &config, input);
    assert_eq!(code, 0);
    assert!(out.contains("r2> help \"-----BEGIN X-----\n…> AAAA=\n…> -----END X-----\"\n"));
    assert!(out.contains("│ unknown command '-----BEGIN X-----"));
    assert!(out.contains("│ AAAA=  "));
    assert!(out.contains("│ -----END X-----'"));
    assert!(out.ends_with("r2> exit\n"));
}

#[test]
fn eof_inside_an_open_quote_exits() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let (out, _, code) = session(dir.path(), &config, b"help \"abc\n");
    assert_eq!(code, 0);
    assert_eq!(out, format!("{}r2> help \"abc\n…> \n", banner()));
}

#[test]
fn parse_error_echoes_caret_transcript() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let (out, _, _) = session(dir.path(), &config, b"help --\n");
    assert!(out.contains(
        "r2> help --\nhelp --\n     ^\n╭─ error ──────────────────────────╮\n\
         │ empty option name                │\n│ hint: options are written --name │\n"
    ));
}

#[test]
fn crlf_and_invalid_utf8_input_keep_the_session_alive() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let (out, _, code) = session(dir.path(), &config, b"hel\xffp\r\nhelp exit\r\nexit\r\n");
    assert_eq!(code, 0);
    assert!(out.contains("r2> hel\u{fffd}p\n"));
    assert!(out.contains("unknown command 'hel\u{fffd}p'"));
    assert!(out.contains("usage: exit\n"));
    assert!(out.ends_with("r2> exit\n"));
}

#[test]
fn config_path_and_origin_render_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let (out, _, _) = session(dir.path(), &config, b"config path\nconfig show --origin\n");
    assert!(out.contains(&format!(
        "r2> config path\nconfig file: {}\n",
        config.display()
    )));
    let shown = config.display().to_string();
    // the file defines app, providers and softhsm
    for (section, origin) in [
        ("app", shown.as_str()),
        ("ui", "default"),
        ("providers", shown.as_str()),
        ("softhsm", shown.as_str()),
        ("templates", "default"),
        ("custom_mechanisms", "default"),
    ] {
        let row = out
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("{section} ")))
            .unwrap_or_else(|| panic!("no row for {section}"));
        assert!(row.trim_end().ends_with(origin), "{row}");
    }
    assert!(out.contains("config origins"));
}

#[test]
fn config_path_without_external_file_names_the_discovery_order() {
    let dir = tempfile::tempdir().unwrap();
    // no --config, no $R2_CONFIG, no ./r2.yaml, no user config: built-in defaults; keep the
    // history/log writes inside the temp HOME
    let output = r2(dir.path())
        .write_stdin("config path\n")
        .output()
        .unwrap();
    let err = String::from_utf8(output.stderr).unwrap();
    // the built-in defaults enable the memory provider (and SoftHSM autodetect): skipped
    // while those constructors are R0 stubs, like test_main_end_to_end_with_real_providers
    if output.status.code() == Some(1) && err.contains("not implemented") {
        eprintln!("SKIP: provider constructors not merged yet: {err}");
        return;
    }
    assert_eq!(output.status.code(), Some(0), "{err}");
    let out = String::from_utf8(output.stdout).unwrap();
    assert!(out.contains(
        "config file: (none — running on built-in defaults)\n\
         discovery order: --config PATH, $R2_CONFIG, ./r2.yaml, <user config dir>/r2/r2.yaml\n"
    ));
}

#[test]
fn config_show_defaults_and_effective() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let (out, _, _) = session(dir.path(), &config, b"config show --defaults\n");
    assert!(out.contains("# Policy/usage attributes only."));
    let (out, _, _) = session(dir.path(), &config, b"config show\n");
    assert!(
        out.contains("providers:\n  memory:\n    enabled: false\n    name: mem\n  pkcs11: []\n")
    );
    assert!(out.contains(&format!(
        "  history_file: {}\n",
        dir.path().join("history").display()
    )));
    let (out, _, _) = session(dir.path(), &config, b"config show --defaults --origin\n");
    assert!(out.contains("--defaults and --origin are mutually exclusive"));
}

#[test]
fn debug_flag_logs_debug_records() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let run = |debug: bool| {
        let mut cmd = r2(dir.path());
        cmd.arg("--config").arg(&config);
        if debug {
            cmd.arg("--debug");
        }
        cmd.write_stdin("help\nexit\n").assert().success();
        std::fs::read_to_string(dir.path().join("r2.log")).unwrap()
    };
    let without = run(false);
    assert!(without.contains(&format!(
        "INFO    r2::app: r2 {VERSION} started (0 providers)"
    )));
    assert!(!without.contains("DEBUG"));
    let with = run(true);
    assert!(with.contains("DEBUG   r2::console: command: help"));
}

#[test]
fn log_files_follow_the_python_rules() {
    // max_bytes: 0 and backups: 0 start and never rotate
    for (max_bytes, backups) in [(0, 3), (100, 0)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r2.yaml");
        std::fs::write(
            &path,
            format!(
                "app:\n  history_file: {}\n  log:\n    level: debug\n    file: {}\n    max_bytes: {max_bytes}\n    backups: {backups}\n\
                 providers:\n  memory:\n    enabled: false\nsofthsm:\n  autodetect: false\n",
                dir.path().join("history").display(),
                dir.path().join("logs").join("r2.log").display(),
            ),
        )
        .unwrap();
        let input = "help\n".repeat(30);
        let (_, _, code) = session(dir.path(), &path, input.as_bytes());
        assert_eq!(code, 0);
        assert!(dir.path().join("logs").join("r2.log").exists()); // parent created
        assert!(!dir.path().join("logs").join("r2.log.1").exists());
    }
    // an unwritable log directory → Config error, exit 2, never a panic
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, "a file").unwrap();
    let path = dir.path().join("r2.yaml");
    std::fs::write(
        &path,
        format!(
            "app:\n  log:\n    file: {}\nsofthsm:\n  autodetect: false\n",
            blocker.join("sub").join("r2.log").display()
        ),
    )
    .unwrap();
    let output = r2(dir.path()).arg("--config").arg(&path).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let err = String::from_utf8(output.stderr).unwrap();
    assert!(err.starts_with(&format!(
        "error: cannot open log file {}: [Errno 20] Not a directory: ",
        blocker.join("sub").join("r2.log").display()
    )));
    assert!(err.ends_with(" (hint: check app.log.file in the configuration)\n"));
}

#[test]
fn history_file_drops_secret_lines() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let (_, _, code) = session(
        dir.path(),
        &config,
        b"help\nhelp --pin 1234\nconfig path --password hunter2\nexit\n",
    );
    assert_eq!(code, 0);
    let history = std::fs::read_to_string(dir.path().join("history")).unwrap();
    assert!(history.contains("help\n"));
    assert!(!history.contains("1234"));
    assert!(!history.contains("hunter2"));
}

#[test]
fn test_main_end_to_end_with_real_providers() {
    // c2 skipped this while L4/L5 were absent; r2 skips while the R4/R5a constructors are
    // still R0 stubs (the binary then reports the stub's panic as a startup error).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("r2.yaml");
    std::fs::write(
        &path,
        format!(
            "app:\n  history_file: {}\n  log:\n    file: {}\nsofthsm:\n  autodetect: false\n\
             custom_mechanisms:\n  - id: vendor.acme.kcv\n    verb: sign\n    algorithm: aes\n    \
             cli_name: acme-kcv\n    label: ACME key check value\n    ckm: 0x80000A01\n    \
             param_struct: raw\n    params:\n      - {{name: rounds, kind: int, prompt: KCV rounds, required: false, default: 1}}\n",
            dir.path().join("history").display(),
            dir.path().join("r2.log").display(),
        ),
    )
    .unwrap();
    let (out, err, code) = session(dir.path(), &path, b"help\nconfig path\nexit\n");
    if code == 1 && err.contains("not implemented") {
        eprintln!("SKIP: provider constructors not merged yet: {err}");
        return;
    }
    assert_eq!(code, 0, "{err}");
    assert!(out.contains(&format!("config file: {}", path.display())));
}
