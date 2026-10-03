//! Operation timing (§11 D31) and the random IV fallback (§11 D30) end to end against the
//! real `r2` binary (r2 only, so no c2 test to port): piped REPL sessions (PlainIo, §11
//! D2) where the binary turns timing on, over the MemoryProvider (`mem`), plus a SoftHSM
//! session (feature `softhsm`) where an empty IV answer draws the IV from the token.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

/// The fixed AES-128 key of FIPS-197 appendix C.1.
const AES_KEY: &str = "000102030405060708090a0b0c0d0e0f";

/// The binary with a scrubbed environment (+ SOFTHSM2_CONF when given), `dir` as HOME and
/// working directory.
fn r2(dir: &Path, softhsm_conf: Option<&Path>) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_r2"));
    cmd.env_clear()
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
        .env("HOME", dir)
        .current_dir(dir);
    if let Some(conf) = softhsm_conf {
        cmd.env("SOFTHSM2_CONF", conf);
    }
    cmd
}

/// Minimal external config: history/log inside `dir`, autodetect off (the default memory
/// provider `mem` stays enabled), plus `extra` YAML (the pkcs11 instance under test).
fn write_config(dir: &Path, extra: &str) -> PathBuf {
    let path = dir.join("r2.yaml");
    let text = format!(
        "app:\n  history_file: {}\n  log:\n    file: {}\nui:\n  confirm_delete: false\n\
         softhsm:\n  autodetect: false\n{extra}",
        dir.join("history").display(),
        dir.join("r2.log").display(),
    );
    std::fs::write(&path, text).unwrap();
    path
}

/// Runs one piped session; returns (stdout, exit code).
fn session(
    dir: &Path,
    config: &Path,
    softhsm_conf: Option<&Path>,
    lines: &[String],
) -> (String, i32) {
    let mut input = lines.join("\n");
    input.push('\n');
    let output = r2(dir, softhsm_conf)
        .arg("--config")
        .arg(config)
        .write_stdin(input.into_bytes())
        .output()
        .unwrap();
    (
        String::from_utf8(output.stdout).unwrap(),
        output.status.code().unwrap(),
    )
}

fn lines(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn is_lower_hex(line: &str) -> bool {
    !line.is_empty()
        && line
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// §11 D31: the provider time a real session shows: "<n>µs", "<n>ms" or "<s>.<cc>s".
fn is_timing(text: &str) -> bool {
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    if let Some(n) = text.strip_suffix("µs").or_else(|| text.strip_suffix("ms")) {
        return digits(n);
    }
    match text.strip_suffix('s').and_then(|t| t.split_once('.')) {
        Some((secs, hundredths)) => digits(secs) && hundredths.len() == 2 && digits(hundredths),
        None => false,
    }
}

/// The bottom border of a timed `len`-byte hex result: "╰─… {len} bytes in {timing} ─╯".
fn is_timed_footer(line: &str, len: usize) -> bool {
    let Some((head, timing)) = line
        .strip_suffix(" ─╯")
        .and_then(|rest| rest.rsplit_once(" in "))
    else {
        return false;
    };
    head.starts_with('╰') && head.ends_with(&format!(" {len} bytes")) && is_timing(timing)
}

/// Whether `line` ends with the timing suffix " in <t>".
fn ends_timed(line: &str) -> bool {
    line.rsplit_once(" in ")
        .is_some_and(|(_, timing)| is_timing(timing))
}

/// The one output line (leading/trailing blanks trimmed) starting with `prefix`; it must
/// end with the timing suffix.
fn timed_line<'a>(out: &'a str, prefix: &str) -> &'a str {
    let found: Vec<&str> = out
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with(prefix))
        .collect();
    assert_eq!(found.len(), 1, "{prefix:?} in {out}");
    assert!(ends_timed(found[0]), "{:?} is not timed in {out}", found[0]);
    found[0]
}

/// The hex result line of the panel whose top border starts with `top` (`len` bytes, the
/// timed footer below it).
fn panel_hex<'a>(out: &'a str, top: &str, len: usize) -> &'a str {
    let all: Vec<&str> = out.lines().collect();
    let at = all
        .iter()
        .position(|l| l.starts_with(top))
        .unwrap_or_else(|| panic!("no panel {top:?} in {out}"));
    let line = all[at + 1];
    assert_eq!(line.len(), 2 * len, "{out}");
    assert!(is_lower_hex(line), "{out}");
    assert!(is_timed_footer(all[at + 2], len), "{out}");
    line
}

/// The `<hex>` of the output line "<label> (random): <hex>", which must be `len` bytes.
fn random_line<'a>(out: &'a str, label: &str, len: usize) -> &'a str {
    let prefix = format!("{label} (random): ");
    let found: Vec<&str> = out
        .lines()
        .filter_map(|l| l.strip_prefix(prefix.as_str()))
        .collect();
    assert_eq!(found.len(), 1, "{prefix:?} in {out}");
    assert_eq!(found[0].len(), 2 * len, "{out}");
    assert!(is_lower_hex(found[0]), "{out}");
    found[0]
}

fn no_error_panel(out: &str) {
    assert!(!out.contains("─ error ─"), "{out}");
}

/// The banner is decoration for a terminal: never printed into a pipe, so the session
/// opens with the startup line.
fn no_banner(out: &str) {
    assert!(!out.contains("-ARF!"), "{out}");
    assert!(!out.contains("//o__o"), "{out}");
    assert!(
        out.starts_with(&format!(
            "r2 {} — type 'help' for commands",
            env!("CARGO_PKG_VERSION")
        )),
        "{out}"
    );
}

// ---------------------------------------------------------------------------------------
// memory (runs without SoftHSM)
// ---------------------------------------------------------------------------------------

/// A real session shows the provider time on every timed result (§11 D31).
#[test]
fn memory_session_shows_operation_timing() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let input = lines(&[
        "generate mem aes --label a",
        "generate mem ec --label e",
        &format!("load mem aes {AES_KEY} --label k"),
        // FIPS-197 C.1
        "encrypt mem:k ecb 00112233445566778899aabbccddeeff",
        "sign mem:k cmac abcd --out mac.bin",
        "verify mem:k cmac abcd --sig-file mac.bin",
        "export mem:e e.pem",
        "copy mem:k mem --label k3",
        "csr mem:e e.csr --subject CN=e",
    ]);
    let (out, code) = session(dir.path(), &config, None, &input);
    assert_eq!(code, 0, "{out}");
    no_error_panel(&out);
    no_banner(&out);

    // generate (secret key and keypair lines)
    timed_line(&out, "generated mem:a (256-bit aes) in ");
    timed_line(
        &out,
        "generated p256 ec keypair mem:e (public key shares the label/id) in ",
    );
    // load: c2's table title, then the time on a line of its own
    assert!(out.lines().any(|l| l.trim() == "loaded into mem"), "{out}");
    timed_line(&out, "loaded in ");
    // encrypt: the timed hex footer
    assert_eq!(
        panel_hex(&out, "╭─ ciphertext — AES-ECB", 16),
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    );
    // sign --out / verify
    timed_line(&out, "wrote 16 bytes to mac.bin in ");
    timed_line(&out, "signature VALID in ");
    // export to a PEM file
    let export: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("wrote ") && l.contains(" bytes to e.pem (pem) in "))
        .collect();
    assert_eq!(export.len(), 1, "{out}");
    assert!(ends_timed(export[0]), "{out}");
    assert!(std::fs::read_to_string(dir.path().join("e.pem")).is_ok());
    // copy and csr
    timed_line(&out, "copied mem:k -> mem:k3 (secret aes) in ");
    timed_line(&out, "wrote CSR for mem:e to e.csr (subject: CN=e) in ");
    assert!(
        std::fs::read_to_string(dir.path().join("e.csr"))
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE REQUEST-----")
    );
}

/// §11 D30: an empty IV answer to an encrypt draws a random IV from the key's provider and
/// shows it; a second session (memory keys do not persist) decrypts with that IV.
#[test]
fn memory_random_iv_round_trip_across_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let load = format!("load mem aes {AES_KEY} --label k");

    // session 1: CBC and GCM encrypts with empty IV answers
    let input = vec![
        load.clone(),
        "encrypt mem:k cbc c0fe".to_owned(),
        String::new(),
        "encrypt mem:k gcm c0fe".to_owned(),
        String::new(),
    ];
    let (out, code) = session(dir.path(), &config, None, &input);
    assert_eq!(code, 0, "{out}");
    no_error_panel(&out);
    no_banner(&out);
    assert_eq!(out.matches("IV (16 bytes, empty = random): ").count(), 1);
    assert_eq!(
        out.matches("IV / nonce (12 bytes typical, empty = random): ")
            .count(),
        1,
        "{out}"
    );
    let cbc_iv = random_line(&out, "IV", 16).to_owned();
    let gcm_iv = random_line(&out, "IV / nonce", 12).to_owned();
    assert_ne!(cbc_iv, "0".repeat(32), "{out}");
    // the shown IV line comes before the ciphertext panel
    assert!(
        out.find(&format!("IV (random): {cbc_iv}")).unwrap()
            < out.find("╭─ ciphertext — AES-CBC").unwrap(),
        "{out}"
    );
    let cbc_ct = panel_hex(&out, "╭─ ciphertext — AES-CBC", 16).to_owned();
    let gcm_ct = panel_hex(&out, "╭─ ciphertext — AES-GCM", 18).to_owned(); // 2 + 16-byte tag

    // session 2: decrypt with the shown IVs (given inline, so no prompt)
    let input = vec![
        load,
        format!("decrypt mem:k cbc 0x{cbc_ct} iv=0x{cbc_iv}"),
        format!("decrypt mem:k gcm 0x{gcm_ct} iv=0x{gcm_iv}"),
    ];
    let (out, code) = session(dir.path(), &config, None, &input);
    assert_eq!(code, 0, "{out}");
    no_error_panel(&out);
    assert!(!out.contains("IV ("), "{out}");
    assert_eq!(panel_hex(&out, "╭─ plaintext — AES-CBC", 2), "c0fe");
    assert_eq!(panel_hex(&out, "╭─ plaintext — AES-GCM", 2), "c0fe");
}

/// The random fallback is for encryption only: an empty IV answer to a decrypt is still the
/// codec error with a re-prompt (EOF then aborts the command).
#[test]
fn memory_decrypt_empty_iv_is_not_random() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let input = vec![
        format!("load mem aes {AES_KEY} --label k"),
        "decrypt mem:k cbc 0x4b9d0c85df8aaf9a8d7ed290a64447b6".to_owned(),
        String::new(),
    ];
    let (out, code) = session(dir.path(), &config, None, &input);
    assert_eq!(code, 0, "{out}");
    no_banner(&out);
    assert_eq!(out.matches("IV (16 bytes): ").count(), 2, "{out}");
    assert!(!out.contains("empty = random"), "{out}");
    assert!(!out.contains("(random):"), "{out}");
    assert!(out.contains("─ error ─"), "{out}");
    assert!(out.contains("iv: empty input"), "{out}");
    assert!(out.contains("hint: paste hex, base64 or PEM data"), "{out}");
    assert!(out.contains("Aborted."), "{out}");
    assert!(!out.contains("plaintext"), "{out}");
}

// ---------------------------------------------------------------------------------------
// SoftHSM (feature `softhsm`; the fixture token of scripts/softhsm-init.sh)
// ---------------------------------------------------------------------------------------

#[cfg(feature = "softhsm")]
mod softhsm {
    use super::*;
    use r2_testkit::softhsm::{softhsm_token, unique_label};

    /// An empty IV answer to an encrypt with an on-token key draws the IV from the token's
    /// RNG (logged by length only); generate and encrypt are timed.
    #[test]
    fn softhsm_encrypt_empty_iv_draws_from_token() {
        let token = softhsm_token();
        let label = unique_label();
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(
            dir.path(),
            &format!(
                "providers:\n  pkcs11:\n    - name: hsm\n      library: {}\n",
                token.module_path.display()
            ),
        );
        let input = vec![
            format!("login hsm {}", token.token_label),
            token.user_pin.clone(),
            format!("generate hsm aes --label {}", label.as_str()),
            "ok".to_owned(), // the template editor (§7 defaults accepted)
            format!("encrypt hsm:{} cbc c0fe", label.as_str()),
            String::new(),
            format!("delete hsm:{}", label.as_str()),
            "logout hsm".to_owned(),
        ];
        let (out, code) = session(dir.path(), &config, Some(&token.conf_path), &input);
        assert_eq!(code, 0, "{out}");
        no_error_panel(&out);
        no_banner(&out);

        let generated = timed_line(&out, &format!("generated hsm:{}", label.as_str()));
        assert!(generated.contains("(256-bit aes) in "), "{out}");
        assert_eq!(out.matches("IV (16 bytes, empty = random): ").count(), 1);
        let iv = random_line(&out, "IV", 16).to_owned();
        panel_hex(&out, "╭─ ciphertext — AES-CBC", 16);
        assert!(
            out.contains(&format!("deleted hsm:{}", label.as_str())),
            "{out}"
        );

        // the IV came from the token: the provider logs the length, never the bytes
        let log = std::fs::read_to_string(dir.path().join("r2.log")).unwrap();
        assert!(log.contains("hsm: generated 16 random bytes"), "{log}");
        assert!(!log.contains(&iv), "{log}");
    }
}
