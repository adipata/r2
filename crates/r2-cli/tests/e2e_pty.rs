//! Optional pty smoke tests (spec §4.9.7, §11 D2/D9; R7): the binary on a pseudo-terminal
//! through util-linux `script` (skipped where `script` is unavailable, e.g. macOS/Windows
//! CI images without util-linux). The pty never answers the `ESC[6n` cursor query, which is
//! exactly the degraded-terminal case: TERM=dumb must pick PlainIo up front, any other TERM
//! starts TerminalIo and degrades to plain reads with one warning.
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
    cfg!(target_os = "linux")
        && Command::new("script")
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
fn pty_session(term: &str, chunks: &[(u64, &str)]) -> Option<String> {
    if !script_available() {
        eprintln!("SKIP: util-linux `script` not available");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    let inner = format!(
        "env -i HOME={} TERM={term} {} --config {}",
        dir.path().display(),
        env!("CARGO_BIN_EXE_r2"),
        config.display()
    );
    let mut child = Command::new("script")
        .args(["-qec", &inner, "/dev/null"])
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
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[test]
fn term_dumb_on_a_terminal_uses_plain_io_without_terminal_queries() {
    let Some(out) = pty_session("dumb", &[(300, "help\n"), (300, "exit\n")]) else {
        return;
    };
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
    let Some(out) = pty_session("xterm", &[(3000, "help\r"), (700, "exit\r")]) else {
        return;
    };
    assert!(out.contains("\u{1b}[6n"));
    assert!(out.contains(
        "warning: line editor unavailable (The cursor position could not be read within a normal duration); continuing with plain input"
    ));
    assert!(out.contains("help <command> shows its usage"));
    // a real terminal gets styled output (bold table header)
    assert!(out.contains("\u{1b}[1m"));
}
