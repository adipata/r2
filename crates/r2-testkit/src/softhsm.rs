//! SoftHSM fixture (spec §4.10.5; owner R0).
//!
//! App-independent by contract: environment and subprocesses only, no r2 crate — it works
//! before (and without) any provider code. The token is initialized by
//! `scripts/softhsm-init.sh` BEFORE the test process starts (`eval "$(scripts/softhsm-init.sh)"`),
//! so tests never mutate the environment; this module only reads it. A missing or invalid
//! variable FAILS the test (panic), it never skips (stricter than c2's pytest skip).
//!
//! The fixture takes no lock itself: SoftHSM tests run under nextest only (process-per-test,
//! §4.1.3), and a test that also holds `global_state_lock()` must be able to call it.
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SofthsmToken {
    pub module_path: PathBuf,
    pub slot: u64,
    /// "R2TEST"
    pub token_label: String,
    /// "1234"
    pub user_pin: String,
    /// "4321"
    pub so_pin: String,
    /// $SOFTHSM2_CONF of the shared token.
    pub conf_path: PathBuf,
}

/// `$SOFTHSM2_CONF` (read by SoftHSM at C_Initialize, spec §5.13).
const CONF_VAR: &str = "SOFTHSM2_CONF";
const MODULE_VAR: &str = "R2_TEST_SOFTHSM_MODULE";
const SLOT_VAR: &str = "R2_TEST_SOFTHSM_SLOT";
const LABEL_VAR: &str = "R2_TEST_SOFTHSM_LABEL";
const USER_PIN_VAR: &str = "R2_TEST_SOFTHSM_USER_PIN";
const SO_PIN_VAR: &str = "R2_TEST_SOFTHSM_SO_PIN";

/// Read once (OnceLock) from the environment: SOFTHSM2_CONF, R2_TEST_SOFTHSM_MODULE,
/// R2_TEST_SOFTHSM_SLOT, R2_TEST_SOFTHSM_LABEL, R2_TEST_SOFTHSM_USER_PIN,
/// R2_TEST_SOFTHSM_SO_PIN. Any missing/invalid → panic "SoftHSM fixture not initialized:
/// run `eval \"$(scripts/softhsm-init.sh)\"` (missing {VAR})".
pub fn softhsm_token() -> &'static SofthsmToken {
    static TOKEN: OnceLock<SofthsmToken> = OnceLock::new();
    TOKEN.get_or_init(|| match token_from(&|name| std::env::var(name).ok()) {
        Ok(token) => token,
        Err(var) => panic!("{}", not_initialized(var)),
    })
}

/// The panic text of a missing or invalid fixture variable.
fn not_initialized(var: &str) -> String {
    format!(
        "SoftHSM fixture not initialized: run `eval \"$(scripts/softhsm-init.sh)\"` (missing {var})"
    )
}

/// Builds the token description from a variable lookup; Err = the first missing/invalid
/// variable. Empty values count as missing; the slot must be a decimal u64.
fn token_from(lookup: &dyn Fn(&str) -> Option<String>) -> Result<SofthsmToken, &'static str> {
    let get = |name: &'static str| match lookup(name) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(name),
    };
    let conf_path = PathBuf::from(get(CONF_VAR)?);
    let module_path = PathBuf::from(get(MODULE_VAR)?);
    let slot = get(SLOT_VAR)?.parse::<u64>().map_err(|_| SLOT_VAR)?;
    let token_label = get(LABEL_VAR)?;
    let user_pin = get(USER_PIN_VAR)?;
    let so_pin = get(SO_PIN_VAR)?;
    Ok(SofthsmToken {
        module_path,
        slot,
        token_label,
        user_pin,
        so_pin,
        conf_path,
    })
}

/// pkcs11-tool `--type` values tried by the teardown, in c2's order.
const OBJECT_TYPES: [&str; 5] = ["secrkey", "privkey", "pubkey", "cert", "data"];
/// pkcs11-tool deletes one object per call; the repeat is bounded defensively (c2).
const MAX_DELETES_PER_TYPE: usize = 8;

/// Per-test unique CKA_LABEL "r2test-{12 hex}". Drop deletes objects created under it,
/// best effort, via `pkcs11-tool --module … --token-label … --login --pin … --delete-object
/// --type {secrkey|privkey|pubkey|cert|data} --label …` (≤ 8 per type; silently skipped
/// when pkcs11-tool is absent). Uniqueness alone isolates tests.
pub struct UniqueLabel {
    label: String,
    token: &'static SofthsmToken,
}
impl UniqueLabel {
    pub fn as_str(&self) -> &str {
        &self.label
    }
}
impl std::ops::Deref for UniqueLabel {
    type Target = str;
    fn deref(&self) -> &str {
        &self.label
    }
}
impl Drop for UniqueLabel {
    /// Best effort; never panics (spawn and wait failures are ignored).
    fn drop(&mut self) {
        let Some(tool) = find_on_path("pkcs11-tool") else {
            return;
        };
        for object_type in OBJECT_TYPES {
            for _ in 0..MAX_DELETES_PER_TYPE {
                if !delete_one(&tool, self.token, object_type, &self.label) {
                    break;
                }
            }
        }
    }
}

/// A fresh label on the shared fixture token (requires the fixture: panics like
/// [`softhsm_token`] when it is not initialized).
pub fn unique_label() -> UniqueLabel {
    let token = softhsm_token();
    let mut random = [0u8; 6];
    assert!(
        openssl::rand::rand_bytes(&mut random).is_ok(),
        "unique_label: OpenSSL random number generation failed"
    );
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    UniqueLabel {
        label: format!("r2test-{hex}"),
        token,
    }
}

/// One `pkcs11-tool --delete-object` call; true when it deleted something (exit 0).
fn delete_one(tool: &Path, token: &SofthsmToken, object_type: &str, label: &str) -> bool {
    Command::new(tool)
        .arg("--module")
        .arg(&token.module_path)
        .args([
            "--token-label",
            &token.token_label,
            "--login",
            "--pin",
            &token.user_pin,
        ])
        .args(["--delete-object", "--type", object_type, "--label", label])
        .env(CONF_VAR, &token.conf_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// `shutil.which` for the teardown tool: the first executable file named `name` (plus
/// `.exe` on Windows) in `$PATH`.
fn find_on_path(name: &str) -> Option<PathBuf> {
    let path: OsString = std::env::var_os("PATH")?;
    let names: Vec<String> = if cfg!(windows) {
        vec![format!("{name}.exe"), name.to_owned()]
    } else {
        vec![name.to_owned()]
    };
    std::env::split_paths(&path)
        .flat_map(|dir| names.iter().map(move |n| dir.join(n)))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn complete_env() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            (CONF_VAR, "/tmp/hsm/softhsm2.conf"),
            (MODULE_VAR, "/usr/lib/softhsm/libsofthsm2.so"),
            (SLOT_VAR, "1182346269"),
            (LABEL_VAR, "R2TEST"),
            (USER_PIN_VAR, "1234"),
            (SO_PIN_VAR, "4321"),
        ])
    }

    fn token_with(env: &HashMap<&'static str, &'static str>) -> Result<SofthsmToken, &'static str> {
        token_from(&|name| env.get(name).map(|v| (*v).to_owned()))
    }

    #[test]
    fn token_from_reads_every_variable() {
        let token = token_with(&complete_env()).unwrap();
        assert_eq!(
            token,
            SofthsmToken {
                module_path: PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
                slot: 1_182_346_269,
                token_label: "R2TEST".to_owned(),
                user_pin: "1234".to_owned(),
                so_pin: "4321".to_owned(),
                conf_path: PathBuf::from("/tmp/hsm/softhsm2.conf"),
            }
        );
    }

    #[test]
    fn token_from_names_the_missing_or_invalid_variable() {
        for var in [
            CONF_VAR,
            MODULE_VAR,
            SLOT_VAR,
            LABEL_VAR,
            USER_PIN_VAR,
            SO_PIN_VAR,
        ] {
            let mut env = complete_env();
            env.remove(var);
            assert_eq!(token_with(&env), Err(var), "absent {var}");
            env.insert(var, "");
            assert_eq!(token_with(&env), Err(var), "empty {var}");
        }
        for bad_slot in ["-1", "x", "18446744073709551616", " 1"] {
            let mut env = complete_env();
            env.insert(SLOT_VAR, bad_slot);
            assert_eq!(token_with(&env), Err(SLOT_VAR), "slot {bad_slot:?}");
        }
    }

    #[test]
    fn not_initialized_text_is_the_spec_message() {
        assert_eq!(
            not_initialized("R2_TEST_SOFTHSM_SLOT"),
            "SoftHSM fixture not initialized: run `eval \"$(scripts/softhsm-init.sh)\"` \
             (missing R2_TEST_SOFTHSM_SLOT)"
        );
    }
}
