//! Config-defined custom PKCS#11 mechanism on real SoftHSM (spec §5.14; owner R13) — the
//! port of c2 tests/integration/test_custom_mechanism.py::test_custom_ckm_passthrough_on_softhsm
//! through the real `r2` binary (piped stdin, PlainIo §11 D2). The YAML config entry is a
//! raw passthrough of `CKM_AES_CBC` (0x1082): the vendor op encrypts on token and the
//! ciphertext decrypts via the *built-in* AES-CBC op. The FakeProvider half lives in
//! r2-console `src/tests/custom_mechanism.rs`.
#![cfg(feature = "softhsm")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use assert_cmd::Command;
use r2_testkit::softhsm::{softhsm_token, unique_label};

const CKM_AES_CBC: u64 = 0x0000_1082;
const PT_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const IV_HEX: &str = "aabbccddeeff00112233445566778899";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_custom_ckm_passthrough_on_softhsm() {
    let token = softhsm_token();
    let label = unique_label();
    let label = label.as_str();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("r2.yaml");
    std::fs::write(
        &config,
        format!(
            "app:\n  history_file: {}\n  log:\n    file: {}\nui:\n  confirm_delete: false\n\
             providers:\n  pkcs11:\n    - name: hsm\n      library: {}\n\
             softhsm:\n  autodetect: false\n\
             custom_mechanisms:\n  - id: vendor.cbc.passthrough\n    verb: encrypt\n\
             \x20   algorithm: aes\n    cli_name: vcbc\n    label: vendor AES-CBC raw passthrough\n\
             \x20   ckm: {CKM_AES_CBC}\n    param_struct: iv\n    params:\n\
             \x20     - name: iv\n        kind: bytes\n        prompt: IV (16 bytes)\n",
            dir.path().join("history").display(),
            dir.path().join("r2.log").display(),
            token.module_path.display()
        ),
    )
    .unwrap();
    let ct_path = dir.path().join("vendor.ct");
    let pt_path = dir.path().join("roundtrip.pt");
    let lines = [
        format!("login hsm {} --pin {}", token.token_label, token.user_pin),
        format!("generate hsm aes size=256 --label {label}"),
        "ok".to_owned(),
        // the vendor op is listed for the logged-in provider
        "ops hsm".to_owned(),
        // dispatch with the iv PROMPTED (§5.14: prompted parameters)
        format!(
            "encrypt hsm:{label} vcbc 0x{PT_HEX} --out {}",
            ct_path.display()
        ),
        format!("0x{IV_HEX}"),
        // round-trip through the BUILT-IN AES-CBC decrypt — proves the vendor entry drove
        // the real CKM_AES_CBC on the token
        format!(
            "decrypt hsm:{label} cbc iv=0x{IV_HEX} padding=none --in {} --out {}",
            ct_path.display(),
            pt_path.display()
        ),
        format!("delete hsm:{label}"),
        "exit".to_owned(),
    ];
    let mut input = lines.join("\n");
    input.push('\n');
    let output = Command::new(env!("CARGO_BIN_EXE_r2"))
        .env_clear()
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
        .env("HOME", dir.path())
        .env("SOFTHSM2_CONF", &token.conf_path)
        // c2's RenderingIO width: the ops table row keeps `vendor.cbc.passthrough` on one
        // line (at 80 columns rich cropped it and r2 folds it, §11 D1)
        .env("COLUMNS", "200")
        .current_dir(dir.path())
        .arg("--config")
        .arg(&config)
        .write_stdin(input.into_bytes())
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(!text.contains("─ error ─"), "{text}");

    // the ops table row itself: c2 asserted on RenderingIO text, which never holds the typed
    // command, while r2's piped stdout echoes `r2> encrypt hsm:… vcbc …` (§11 D2)
    assert!(
        text.lines().any(|line| !line.starts_with("r2> ")
            && line.contains("vcbc")
            && line.contains("vendor.cbc.passthrough")),
        "{text}"
    ); // ops table row
    assert!(text.contains("IV (16 bytes)"), "{text}"); // config-declared param prompted

    let ciphertext = std::fs::read(&ct_path).unwrap();
    assert_eq!(ciphertext.len(), 32);
    assert_ne!(ciphertext, unhex(PT_HEX));
    assert_eq!(std::fs::read(&pt_path).unwrap(), unhex(PT_HEX));
}
