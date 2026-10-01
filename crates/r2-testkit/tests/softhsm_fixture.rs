//! R0 fixture self-test (c2 tests/integration/test_softhsm_fixture.py): the token that
//! `scripts/softhsm-init.sh` initialized is the one `softhsm_token()` describes, and
//! softhsm2-util lists it. Feature `softhsm`; fails (never skips) without the fixture.
//!
//! These tests only READ the environment the init script exported (they never change it)
//! and run under nextest only (process-per-test, spec §4.1.3), so they take no
//! `global_state_lock()`.
#![cfg(feature = "softhsm")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use r2_testkit::softhsm::{softhsm_token, unique_label};

/// Runs a tool and returns (success, stdout); panics when it cannot be started.
fn run(program: &str, args: &[&str]) -> (bool, String) {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("cannot run {program}: {err}"));
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

#[test]
fn test_softhsm_token_is_initialized_and_listed() {
    let token = softhsm_token();
    assert!(token.module_path.exists());
    assert_eq!(token.token_label, "R2TEST");
    assert_eq!(token.user_pin, "1234");
    assert_eq!(token.so_pin, "4321");

    let conf = std::env::var("SOFTHSM2_CONF").unwrap_or_default();
    assert!(
        !conf.is_empty(),
        "fixture must export SOFTHSM2_CONF for PKCS#11 consumers (spec §5.13)"
    );
    let conf_path = PathBuf::from(&conf);
    assert_eq!(conf_path, token.conf_path);
    assert!(conf_path.is_file());

    // The token store the fixture created is non-empty after --init-token.
    let text = std::fs::read_to_string(&conf_path).unwrap();
    let token_dir_lines: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("directories.tokendir"))
        .map(|line| line.split_once('=').unwrap().1.trim())
        .collect();
    assert_eq!(token_dir_lines.len(), 1);
    assert!(
        std::fs::read_dir(Path::new(token_dir_lines[0]))
            .unwrap()
            .next()
            .is_some(),
        "token dir empty: token not initialized"
    );

    // And softhsm2-util (inheriting SOFTHSM2_CONF) lists it in the expected slot.
    let (ok, stdout) = run("softhsm2-util", &["--show-slots"]);
    assert!(ok, "softhsm2-util --show-slots failed");
    assert!(stdout.contains(&token.token_label));
    assert!(stdout.contains(&format!("Slot {}", token.slot)));
}

#[test]
fn test_unique_label_is_fresh_per_use() {
    let label = unique_label();
    assert!(label.starts_with("r2test-"));
    assert_eq!(label.len(), "r2test-".len() + 12);
    // r2 additions: lower-case hex suffix, Deref == as_str, fresh per call.
    assert!(
        label["r2test-".len()..]
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    );
    assert_eq!(&*label, label.as_str());
    let other = unique_label();
    assert_ne!(label.as_str(), other.as_str());
}

/// pkcs11-tool arguments that address the fixture token as the user.
fn tool_args<'a>(token: &'a r2_testkit::softhsm::SofthsmToken, module: &'a str) -> Vec<&'a str> {
    vec![
        "--module",
        module,
        "--token-label",
        &token.token_label,
        "--login",
        "--pin",
        &token.user_pin,
    ]
}

/// Labels of the token's objects as `pkcs11-tool --list-objects` prints them.
fn listed_labels(token: &r2_testkit::softhsm::SofthsmToken) -> Vec<String> {
    let module = token.module_path.to_str().unwrap();
    let mut args = tool_args(token, module);
    args.push("--list-objects");
    let (ok, stdout) = run("pkcs11-tool", &args);
    assert!(ok, "pkcs11-tool --list-objects failed");
    stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("label:"))
        .map(|label| label.trim().to_owned())
        .collect()
}

#[test]
fn test_unique_label_drop_deletes_objects_created_under_it() {
    // spec §4.10.5: Drop deletes the objects created under the label (pkcs11-tool; CI
    // installs opensc), so a failing run leaves no residue on the shared token.
    let token = softhsm_token();
    let module = token.module_path.to_str().unwrap().to_owned();
    let label = unique_label();
    let kept = unique_label();
    for name in [label.as_str(), label.as_str(), kept.as_str()] {
        let mut args = tool_args(token, &module);
        args.extend(["--keygen", "--key-type", "AES:16", "--label", name]);
        let (ok, _) = run("pkcs11-tool", &args);
        assert!(ok, "pkcs11-tool --keygen failed");
    }
    let before = listed_labels(token);
    assert_eq!(before.iter().filter(|l| *l == label.as_str()).count(), 2);

    let deleted = label.to_string();
    drop(label);
    let after = listed_labels(token);
    assert!(
        !after.contains(&deleted),
        "objects under {deleted} survived the drop"
    );
    assert!(
        after.iter().any(|l| l == kept.as_str()),
        "another label's object was deleted"
    );
}
