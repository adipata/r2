//! R0 smoke tests (c2 tests/unit/test_smoke.py, version part): the `r2` binary exists and
//! `--version` prints `r2 <version>` from the workspace package metadata.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use assert_cmd::Command;

/// The package version cargo compiled into this crate (= `[workspace.package] version`).
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn r2() -> Command {
    Command::new(env!("CARGO_BIN_EXE_r2"))
}

#[test]
fn test_version_string() {
    // c2: `c2.__version__` is a non-empty str. r2: a non-empty dotted version.
    assert!(!VERSION.is_empty());
    let parts: Vec<&str> = VERSION.split(['.', '-', '+']).take(3).collect();
    assert_eq!(parts.len(), 3, "{VERSION:?} is not MAJOR.MINOR.PATCH");
    assert!(
        parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    );
}

#[test]
fn test_version_matches_distribution_metadata() {
    // c2: importlib.metadata.version("c2") == c2.__version__. r2: the version the binary
    // reports is the workspace manifest's `[workspace.package] version`.
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml"),
    )
    .unwrap();
    let section = manifest.split("[workspace.package]").nth(1).unwrap();
    let declared = section
        .lines()
        .take_while(|line| !line.starts_with('['))
        .find_map(|line| line.strip_prefix("version = "))
        .unwrap()
        .trim_matches('"');
    assert_eq!(declared, VERSION);
    let output = r2().arg("--version").output().unwrap();
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("r2 {declared}\n")
    );
}

#[test]
fn test_main_version_flag() {
    // c2: main(["--version"]) exits 0 and prints the version on stdout.
    r2().arg("--version")
        .assert()
        .success()
        .stdout(format!("r2 {VERSION}\n"))
        .stderr("");
}
