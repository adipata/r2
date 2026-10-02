//! SoftHSM first-run wizard end to end through the real `r2` binary (spec §5.13; R11): a
//! piped session (PlainIo, §11 D2) runs `login softhsm` against the autodetected SoftHSM
//! module with its OWN, empty token store, accepts the wizard, appends the provider entry
//! to the external config and logs in; a second session over the updated config logs in to
//! the new token without the wizard (the appended `env.SOFTHSM2_CONF` is applied before
//! C_Initialize), and a declined wizard leaves the session usable on the memory provider.
//! Feature `softhsm` (the module path comes from the fixture of `scripts/softhsm-init.sh`;
//! its token is never touched).
#![cfg(feature = "softhsm")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::PathBuf;

use assert_cmd::Command;
use r2_testkit::softhsm::softhsm_token;

const SO_PIN: &str = "so-wiz-1";
const USER_PIN: &str = "user-wiz-1";

/// A virgin SoftHSM environment inside `dir`: an empty pre-wizard token store (the
/// session's `$SOFTHSM2_CONF`) and the external config the wizard appends to.
struct Setup {
    dir: tempfile::TempDir,
    pre_conf: PathBuf,
    config: PathBuf,
    conf_dir: PathBuf,
    token_dir: PathBuf,
    module: PathBuf,
}

impl Setup {
    fn new() -> Self {
        let module = softhsm_token().module_path.clone();
        let dir = tempfile::tempdir().unwrap();
        let pre_tokens = dir.path().join("pre-tokens");
        std::fs::create_dir(&pre_tokens).unwrap();
        let pre_conf = dir.path().join("pre-softhsm2.conf");
        std::fs::write(
            &pre_conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
                pre_tokens.display()
            ),
        )
        .unwrap();
        let conf_dir = dir.path().join("wizard-conf");
        let token_dir = dir.path().join("wizard-tokens");
        let config = dir.path().join("r2.yaml");
        std::fs::write(
            &config,
            format!(
                "app:\n  history_file: '{}'\n  log:\n    file: '{}'\nsofthsm:\n  autodetect: true\n  \
                 provider_name: softhsm\n  search_paths:\n    - '{}'\n  conf_dir: '{}'\n  \
                 token_dir: '{}'\n",
                dir.path().join("history").display(),
                dir.path().join("r2.log").display(),
                module.display(),
                conf_dir.display(),
                token_dir.display(),
            ),
        )
        .unwrap();
        Self {
            dir,
            pre_conf,
            config,
            conf_dir,
            token_dir,
            module,
        }
    }

    /// One piped session with a scrubbed environment; returns (stdout, exit code).
    fn session(&self, lines: &[&str]) -> (String, i32) {
        let mut input = lines.join("\n");
        input.push('\n');
        let output = Command::new(env!("CARGO_BIN_EXE_r2"))
            .env_clear()
            .env("HOME", self.dir.path())
            .env("SOFTHSM2_CONF", &self.pre_conf)
            .current_dir(self.dir.path())
            .arg("--config")
            .arg(&self.config)
            .write_stdin(input.into_bytes())
            .output()
            .unwrap();
        (
            String::from_utf8(output.stdout).unwrap(),
            output.status.code().unwrap(),
        )
    }
}

#[test]
#[ignore = "needs R8's `login` command (merge checklist: drop this ignore when R11 merges after R8)"]
fn softhsm_wizard_e2e_first_login_sets_up_and_persists() {
    let setup = Setup::new();
    let (out, code) = setup.session(&[
        "login softhsm",
        "y", // set up now
        "WIZTOKEN",
        SO_PIN,
        SO_PIN,
        USER_PIN,
        USER_PIN,
        "y",      // append the entry to r2.yaml
        USER_PIN, // login's PIN prompt for the fresh token
        "exit",
    ]);
    assert_eq!(code, 0, "{out}");
    // long lines are word-wrapped at the session width (no spaces in the temp paths)
    let out = out.split_whitespace().collect::<Vec<_>>().join(" ");
    let conf_path = setup.conf_dir.join("softhsm2.conf");
    assert!(out.contains("Provider 'softhsm' has no initialized SoftHSM2 token."));
    assert!(out.contains(&format!("Wrote {}", conf_path.display())));
    assert!(out.contains("Token 'WIZTOKEN' initialized (slot "));
    assert!(out.contains(&format!("library: {}", setup.module.display())));
    assert!(out.contains(&format!("Updated {}.", setup.config.display())));
    assert!(out.contains("logged in to 'WIZTOKEN' (slot "), "{out}");
    assert!(!out.contains(SO_PIN) && !out.contains(USER_PIN));

    // §5.13 step 1 byte for byte; the token files live in the wizard's token dir.
    assert_eq!(
        std::fs::read(&conf_path).unwrap(),
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            setup.token_dir.display()
        )
        .into_bytes()
    );
    assert!(
        std::fs::read_dir(&setup.token_dir)
            .unwrap()
            .next()
            .is_some()
    );
    // §5.13 step 4: the textual block appended to the config (no providers section yet).
    let config = std::fs::read_to_string(&setup.config).unwrap();
    assert!(config.ends_with(&format!(
        "\n# SoftHSM provider added by the r2 first-run wizard (spec §5.13)\nproviders:\n  \
         pkcs11:\n  - name: softhsm\n    library: {}\n    token_label: WIZTOKEN\n    env:\n      \
         SOFTHSM2_CONF: {}\n",
        setup.module.display(),
        conf_path.display()
    )));

    // Second run: the configured instance (same name) wins over autodetect, its env points
    // the module at the wizard's conf, and the token is found without the wizard — while
    // the session's own $SOFTHSM2_CONF still names the empty pre-wizard store.
    let (out, code) = setup.session(&["login softhsm", USER_PIN, "exit"]);
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains("has no initialized SoftHSM2 token"), "{out}");
    assert!(out.contains("logged in to 'WIZTOKEN' (slot "), "{out}");
}

#[test]
#[ignore = "needs R8's `login` command (merge checklist: drop this ignore when R11 merges after R8)"]
fn softhsm_wizard_e2e_decline_keeps_memory_usable() {
    let setup = Setup::new();
    let original = std::fs::read_to_string(&setup.config).unwrap();
    let (out, code) = setup.session(&["login softhsm", "n", "providers", "exit"]);
    assert_eq!(code, 0, "{out}");
    // long lines are word-wrapped at the session width
    let flat = out.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains(
        "SoftHSM setup skipped — 'softhsm' stays listed but unusable until the wizard is \
         re-run; the memory provider is unaffected."
    ));
    assert!(flat.contains("SoftHSM setup declined — 'softhsm' stays unusable until you run"));
    // nothing touched: no conf, no token dir, config unchanged; both providers listed
    assert!(!setup.conf_dir.exists());
    assert!(!setup.token_dir.exists());
    assert_eq!(std::fs::read_to_string(&setup.config).unwrap(), original);
    let listing = out.split("providers\n").last().unwrap_or(&out);
    assert!(
        listing.contains("mem") && listing.contains("softhsm"),
        "{out}"
    );
}
