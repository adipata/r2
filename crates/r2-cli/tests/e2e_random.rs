//! `random` end-to-end sessions against the real `r2` binary (§5.17, §11 D29; r2 only, so
//! no c2 test to port): one piped REPL session (PlainIo, §11 D2) over the MemoryProvider
//! (`mem`) covering the console hex result, --out/--outformat files, the prompted length
//! and the error panels, plus a SoftHSM session (feature `softhsm`) where the bytes come
//! from the token's RNG once logged in.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

/// The binary with a scrubbed environment (+ SOFTHSM2_CONF when given), `dir` as HOME and
/// working directory.
fn r2(dir: &Path, softhsm_conf: Option<&Path>) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_r2"));
    cmd.env_clear()
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
        // Windows: the crypto APIs behind OpenSSL's entropy source fail in a process without
        // %SystemRoot% (random bytes, key generation and key checks would all fail)
        .envs(std::env::var_os("SYSTEMROOT").map(|v| ("SYSTEMROOT", v)))
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
    line.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The output lines that are exactly `2 * len` lowercase hex digits (a `len`-byte result).
fn hex_lines(out: &str, len: usize) -> Vec<&str> {
    out.lines()
        .filter(|l| l.len() == 2 * len && is_lower_hex(l))
        .collect()
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

/// The hex result line of the panel whose top border starts with `top`.
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

// ---------------------------------------------------------------------------------------
// memory (runs without SoftHSM)
// ---------------------------------------------------------------------------------------

#[test]
fn memory_random_console_files_prompt_and_errors() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let hex_path = dir.path().join("r.hex");
    let mut input = lines(&[
        "help random",
        "random mem 16",
        // prompted length: an out-of-range answer re-prompts with the error printed
        "random mem",
        "0",
        "4",
    ]);
    input.push(format!(
        "random mem 32 --out {} --outformat hex",
        hex_path.display()
    ));
    input.extend(lines(&[
        "random mem 8 --out r.bin",
        "random nosuch 4",
        "random mem 0",
        "random mem x",
        "random mem 4 --outformat hex",
    ]));
    let (out, code) = session(dir.path(), &config, None, &input);
    assert_eq!(code, 0, "{out}");

    // help (the usage line wraps at the 80-column PlainIo width)
    assert!(
        out.replace('\n', "").contains(
            "usage: random <provider> [<length> | length=<n>] [--out <path>] [--outformat raw|hex|b64]"
        ),
        "{out}"
    );
    assert!(
        out.contains("Generate random bytes with a provider's RNG"),
        "{out}"
    );

    // console result: the hex line between the titled borders
    panel_hex(&out, "╭─ random — mem", 16);
    assert_eq!(hex_lines(&out, 16).len(), 1, "{out}");

    // prompted length (re-prompt after the range error)
    assert_eq!(out.matches("Number of random bytes: ").count(), 2, "{out}");
    assert_eq!(hex_lines(&out, 4).len(), 1, "{out}");
    assert_eq!(
        out.lines().filter(|l| is_timed_footer(l, 4)).count(),
        1,
        "{out}"
    );

    // --out --outformat hex: 64 hex digits + newline
    let text = std::fs::read_to_string(&hex_path).unwrap();
    assert_eq!(text.len(), 65, "{text:?}");
    assert!(text.ends_with('\n'), "{text:?}");
    assert!(is_lower_hex(text.trim_end()), "{text:?}");
    // the absolute path may be wrapped at the console width
    assert!(
        out.replace('\n', "")
            .contains(&format!("wrote 32 bytes to {}", hex_path.display())),
        "{out}"
    );

    // --out (raw default): exactly the bytes
    assert_eq!(std::fs::read(dir.path().join("r.bin")).unwrap().len(), 8);
    let wrote = out
        .lines()
        .find_map(|l| l.strip_prefix("wrote 8 bytes to r.bin in "))
        .unwrap_or_else(|| panic!("{out}"));
    assert!(is_timing(wrote), "{out}"); // §11 D31: the provider time of the draw

    // errors
    assert!(out.contains("─ error ─"), "{out}");
    assert!(out.contains("unknown provider 'nosuch'"), "{out}");
    assert!(out.contains("hint: known providers: mem"), "{out}");
    assert_eq!(
        out.matches("invalid random length 0; expected 1 to 1048576 bytes")
            .count(),
        2,
        "{out}"
    );
    assert!(out.contains("length: invalid integer 'x'"), "{out}");
    assert!(out.contains("--outformat requires --out"), "{out}");
}

/// Successive draws differ (the memory RNG is OpenSSL's, not a fixed stream).
#[test]
fn memory_random_successive_draws_differ() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let input = lines(&["random mem 32", "random mem 32"]);
    let (out, code) = session(dir.path(), &config, None, &input);
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains("─ error ─"), "{out}");
    let draws = hex_lines(&out, 32);
    assert_eq!(draws.len(), 2, "{out}");
    assert_ne!(draws[0], draws[1], "{out}");
}

// ---------------------------------------------------------------------------------------
// SoftHSM (feature `softhsm`; the fixture token of scripts/softhsm-init.sh)
// ---------------------------------------------------------------------------------------

#[cfg(feature = "softhsm")]
mod softhsm {
    use super::*;
    use r2_testkit::softhsm::softhsm_token;

    /// `random hsm` needs a login (AuthRequired, no prompt), then draws from the token.
    #[test]
    fn softhsm_random_requires_login_then_draws_from_token() {
        let token = softhsm_token();
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(
            dir.path(),
            &format!(
                "providers:\n  pkcs11:\n    - name: hsm\n      library: {}\n",
                token.module_path.display()
            ),
        );
        let input = vec![
            "random hsm 4".to_owned(),
            format!("login hsm {}", token.token_label),
            token.user_pin.clone(),
            "random hsm 32".to_owned(),
        ];
        let (out, code) = session(dir.path(), &config, Some(&token.conf_path), &input);
        assert_eq!(code, 0, "{out}");

        // before login: the AuthRequired panel, no length prompt, no result
        let login_at = out
            .find("login required: run `login hsm`")
            .unwrap_or_else(|| panic!("{out}"));
        let logged_in = format!("logged in to '{}'", token.token_label);
        assert!(login_at < out.find(&logged_in).unwrap(), "{out}");
        assert!(!out.contains("Number of random bytes"), "{out}");
        assert!(hex_lines(&out, 4).is_empty(), "{out}");

        // after login: one 32-byte draw from the token's RNG
        let drawn = panel_hex(&out, "╭─ random — hsm", 32);
        assert_eq!(hex_lines(&out, 32).len(), 1, "{out}");

        // the log names the length of the draw, never the bytes
        let log = std::fs::read_to_string(dir.path().join("r2.log")).unwrap();
        assert!(log.contains("hsm: generated 32 random bytes"), "{log}");
        assert!(!log.contains(drawn), "{log}");
    }
}
