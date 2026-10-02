//! Ports of c2 tests/unit/pkcs11/test_softhsm_detect.py — pure path detection.
use std::path::PathBuf;

use r2_testkit::{global_state_lock, set_env};

use crate::softhsm::{SOFTHSM2_LIB_ENV, find_softhsm_module};

fn touch(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, b"").unwrap();
    path
}

#[test]
fn env_override_wins() {
    let _lock = global_state_lock();
    let dir = tempfile::tempdir().unwrap();
    let module = touch(&dir, "libsofthsm2.so");
    let decoy = touch(&dir, "decoy.so");
    let _env = set_env(SOFTHSM2_LIB_ENV, Some(module.to_str().unwrap()));
    assert_eq!(find_softhsm_module(&[decoy]), Some(module));
}

#[test]
fn env_override_is_py_path_normalized() {
    let _lock = global_state_lock();
    let dir = tempfile::tempdir().unwrap();
    let module = touch(&dir, "libsofthsm2.so");
    let spelled = format!("{}//./libsofthsm2.so", dir.path().display());
    let _env = set_env(SOFTHSM2_LIB_ENV, Some(&spelled));
    assert_eq!(find_softhsm_module(&[]), Some(module));
}

#[test]
fn env_override_missing_never_falls_through() {
    let _lock = global_state_lock();
    let dir = tempfile::tempdir().unwrap();
    let existing = touch(&dir, "libsofthsm2.so");
    let missing = dir.path().join("nope.so");
    let _env = set_env(SOFTHSM2_LIB_ENV, Some(missing.to_str().unwrap()));
    assert_eq!(find_softhsm_module(&[existing]), None);
}

#[test]
fn first_existing_search_path() {
    let _lock = global_state_lock();
    let _env = set_env(SOFTHSM2_LIB_ENV, None);
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.so");
    let first = touch(&dir, "first.so");
    let second = touch(&dir, "second.so");
    assert_eq!(find_softhsm_module(&[missing, first.clone(), second]), Some(first));
}

#[test]
fn nothing_found() {
    let _lock = global_state_lock();
    let _env = set_env(SOFTHSM2_LIB_ENV, None);
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(find_softhsm_module(&[dir.path().join("a.so"), dir.path().join("b.so")]), None);
    assert_eq!(find_softhsm_module(&[]), None);
    // an empty override counts as unset
    let _empty = set_env(SOFTHSM2_LIB_ENV, Some(""));
    assert_eq!(find_softhsm_module(&[]), None);
}
