//! Optional pty smoke tests (spec §4.9.7, §11 D2/D9; R7): the binary on a pseudo-terminal
//! through util-linux `script`. Linux only (macOS/Windows have no util-linux `script`); on
//! Linux a missing `script` FAILS the tests (environment-dependent tests never skip). The pty never answers the `ESC[6n` cursor query, which is
//! exactly the degraded-terminal case: TERM=dumb must pick PlainIo up front, any other TERM
//! starts TerminalIo and degrades to plain reads with one warning.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

fn script_available() -> bool {
    Command::new("script")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn write_config(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("r2.yaml");
    std::fs::write(
        &path,
        format!(
            "app:\n  history_file: {}\n  log:\n    file: {}\nproviders:\n  memory:\n    enabled: false\nsofthsm:\n  autodetect: false\n",
            dir.join("history").display(),
            dir.join("r2.log").display()
        ),
    )
    .unwrap();
    path
}

/// Runs r2 under `script` with `term`; `chunks` are written to the pty with a pause before
/// each. Returns the raw pty transcript.
fn pty_session(term: &str, chunks: &[(u64, &str)]) -> String {
    assert!(
        script_available(),
        "util-linux `script` is required for the pty tests (install util-linux)"
    );
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    // `env -i` drops LLVM_PROFILE_FILE: forward it so a coverage run counts this child
    // and never writes default_*.profraw into the source tree (R13).
    let coverage: String = r2_testkit::coverage_env()
        .into_iter()
        .map(|(name, value)| format!("{name}='{}' ", value.to_string_lossy()))
        .collect();
    let inner = format!(
        "env -i {coverage}HOME={} TERM={term} {} --config {}",
        dir.path().display(),
        env!("CARGO_BIN_EXE_r2"),
        config.display()
    );
    let mut child = Command::new("script")
        .args(["-qec", &inner, "/dev/null"])
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for (pause_ms, text) in chunks {
        std::thread::sleep(Duration::from_millis(*pause_ms));
        stdin.write_all(text.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }
    std::thread::sleep(Duration::from_millis(500));
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn term_dumb_on_a_terminal_uses_plain_io_without_terminal_queries() {
    let out = pty_session("dumb", &[(300, "help\n"), (300, "exit\n")]);
    assert!(out.contains("type 'help' for commands"));
    assert!(out.contains("help <command> shows its usage"));
    assert!(out.contains("r2> "));
    // no cursor-position query, no bracketed paste, no colour on a dumb terminal
    assert!(!out.contains("\u{1b}[6n"));
    assert!(!out.contains("\u{1b}[?2004h"));
    assert!(!out.contains("\u{1b}[1m"));
    assert!(!out.contains("line editor unavailable"));
}

#[test]
fn a_terminal_that_never_answers_degrades_to_plain_input() {
    // reedline asks ESC[6n and gives up after 2 s; the session continues on plain reads
    let out = pty_session("xterm", &[(3000, "help\r"), (700, "exit\r")]);
    assert!(out.contains("\u{1b}[6n"));
    // exactly the one §4.9.7 stderr line (no blank line before it: the cursor is still at
    // column 0 after reedline's cursor query and its bracketed-paste reset), then the
    // plain prompt
    assert!(
        out.contains(
            "\u{1b}[6n\u{1b}[?2004lwarning: line editor unavailable (The cursor position could not be read within a normal duration); continuing with plain input\r\nr2> "
        ),
        "{out:?}"
    );
    assert!(out.contains("help <command> shows its usage"));
    // a real terminal gets styled output (bold table header)
    assert!(out.contains("\u{1b}[1m"));
}
