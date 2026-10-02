//! The checklist template editor through the real `r2` binary on the SoftHSM fixture token
//! (R10; feature `softhsm`) — the full-bootstrap leg of c2
//! tests/integration/test_console_keys.py::test_generate_honors_template_editor_cka_id:
//! a config file declares the `hsm` PKCS#11 instance, bootstrap wires
//! `create_template_editor`, the piped session answers the editor with `add CKA_ID=0xc0fe`
//! / `ok`, and the session ends with `exit` and status 0. Fails (never skips) without the
//! fixture of `scripts/softhsm-init.sh`.
#![cfg(feature = "softhsm")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::Path;

use assert_cmd::Command;
use r2_testkit::softhsm::{softhsm_token, unique_label};

/// c2 `_write_config`: history/log inside `dir`, no delete confirmation, autodetect off,
/// one pkcs11 instance `hsm` over the SoftHSM module.
fn write_config(dir: &Path, module: &Path) -> std::path::PathBuf {
    let path = dir.join("r2.yaml");
    let text = format!(
        "app:\n  history_file: {}\n  log:\n    file: {}\nui:\n  confirm_delete: false\n\
         providers:\n  pkcs11:\n    - name: hsm\n      library: {}\n\
         softhsm:\n  autodetect: false\n",
        dir.join("history").display(),
        dir.join("r2.log").display(),
        module.display(),
    );
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn test_generate_honors_template_editor_cka_id_e2e_softhsm() {
    let token = softhsm_token();
    let label = unique_label();
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &token.module_path);
    let input = [
        format!("login hsm {} --pin {}", token.token_label, token.user_pin),
        format!("generate hsm aes size=128 --label {}", label.as_str()),
        "add CKA_ID=0xc0fe".to_owned(),
        "ok".to_owned(),
        format!("delete hsm:{}", label.as_str()),
        "exit".to_owned(),
    ]
    .join("\n")
        + "\n";
    let output = Command::new(env!("CARGO_BIN_EXE_r2"))
        .env_clear()
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
        .env("HOME", dir.path())
        .env("SOFTHSM2_CONF", &token.conf_path)
        .current_dir(dir.path())
        .arg("--config")
        .arg(&config)
        .write_stdin(input.into_bytes())
        .output()
        .unwrap();
    let out = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(0), "{out}");
    assert!(!out.contains("─ error ─"), "{out}");
    assert!(!out.contains("Aborted."), "{out}");
    assert!(
        out.lines()
            .any(|line| line.trim_start().starts_with("note") && line.contains("--id")),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "generated hsm:{}#c0fe (128-bit aes)",
            label.as_str()
        )),
        "{out}"
    );
}
