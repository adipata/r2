//! Console key-command end-to-end sessions against the real `r2` binary (spec §5.1-§5.7;
//! R8) — the port of c2 tests/integration/test_console_keys.py (R8 cases): one piped REPL
//! session (PlainIo, §11 D2) per scenario, `login → generate → load → keys → export →
//! csr` over a real Pkcs11Provider on the SoftHSM fixture token (feature `softhsm`), plus a
//! MemoryProvider session of the same flow that runs without SoftHSM.
//!
//! Template editor answers: c2 accepted the checklist editor (R10) with "ok" after every
//! editor-opening command. Whether this build's `create_template_editor` reads an answer
//! is probed at run time (`editor_answers`), so the transcripts hold on both sides of
//! R10's merge.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use r2_core::codec::decode_data;
use r2_core::der::ecdsa_der_to_rs;
use r2_core::formats::{self, Encoding};
use r2_core::io::ConsoleIo;
use r2_core::keyparse::{KeyHint, parse_key_material};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::params::{ParamValue, Params};
use r2_core::x509info::{certificate_details, rfc4514_string};
use r2_memory::MemoryProvider;
use r2_provider::{MechanismInvocation, Provider};
use r2_testkit::ScriptedIo;

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

/// Minimal external config: history/log inside `dir`, scripted cleanup without confirm
/// noise, autodetect off, plus `extra` YAML (the pkcs11 instance under test).
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

#[cfg(feature = "softhsm")]
/// Runs one piped session; returns (stdout, exit code).
fn session(
    dir: &Path,
    config: &Path,
    softhsm_conf: Option<&Path>,
    lines: &[String],
) -> (String, i32) {
    run_session(r2(dir, softhsm_conf), config, lines)
}

/// `session` on a 1000-column console (`$COLUMNS`): a result line carrying a temp path or
/// the module path never wraps, however long the platform's temp directory is (macOS
/// `$TMPDIR` under `/var/folders/…`, Windows `%TEMP%`) or the module's install prefix (CI's
/// SoftHSM 2.7.0 under `~/.local`); at the piped default of 80 columns such lines wrap.
fn wide_session(
    dir: &Path,
    config: &Path,
    softhsm_conf: Option<&Path>,
    lines: &[String],
) -> (String, i32) {
    let mut cmd = r2(dir, softhsm_conf);
    cmd.env("COLUMNS", "1000");
    run_session(cmd, config, lines)
}

fn run_session(mut cmd: Command, config: &Path, lines: &[String]) -> (String, i32) {
    let mut input = lines.join("\n");
    input.push('\n');
    let output = cmd
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

#[cfg(feature = "softhsm")]
/// The answers this build's template editor reads per editor opening: ["ok"] for R10's
/// checklist editor, [] for the identity editor of the R0 stub.
fn editor_answers() -> Vec<String> {
    let io = std::rc::Rc::new(ScriptedIo::new(["ok"]));
    let config = r2_config::loader::config_from_yaml(None).unwrap();
    let editor = r2_console::template_editor::create_template_editor(
        std::rc::Rc::clone(&io) as std::rc::Rc<dyn ConsoleIo>,
        &config,
    );
    let seed = config
        .templates
        .default_template(KeyClass::Secret, KeyAlgorithm::Aes)
        .unwrap();
    editor.edit(seed, "probe").unwrap();
    if io.remaining() == 0 {
        vec!["ok".to_owned()]
    } else {
        Vec::new()
    }
}

/// A software RSA key: (PKCS#8 DER, private PEM text, public SPKI PEM text).
fn software_rsa() -> (Vec<u8>, String, String) {
    let pkcs8 = r2_testkit::fixtures::rsa2048_pkcs8();
    let private_pem = formats::private_key_bytes(&pkcs8, Encoding::Pem, None).unwrap();
    let spki = formats::pkcs8_public_spki(&pkcs8).unwrap();
    let public_pem = formats::public_key_bytes(&spki, Encoding::Pem).unwrap();
    (
        pkcs8,
        String::from_utf8(private_pem.to_vec()).unwrap(),
        String::from_utf8(public_pem).unwrap(),
    )
}

/// The DER body of the first PEM block of `pem`.
fn pem_der(pem: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(pem).unwrap();
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    decode_data(&format!("b64:{body}")).unwrap().0.to_vec()
}

fn tlv(data: &[u8]) -> (usize, usize) {
    let first = data[1];
    if first < 0x80 {
        return (2, usize::from(first));
    }
    let count = usize::from(first & 0x7f);
    let len = data[2..2 + count]
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
    (2 + count, len)
}

fn children(der: &[u8]) -> Vec<Vec<u8>> {
    let (header, len) = tlv(der);
    let mut content = &der[header..header + len];
    let mut out = Vec::new();
    while !content.is_empty() {
        let (h, l) = tlv(content);
        out.push(content[..h + l].to_vec());
        content = &content[h + l..];
    }
    out
}

/// Parses a PEM CSR and checks its self-signature with MemoryProvider (a CSR that parses
/// AND verifies proves the ECDSA r‖s → DER conversion, §5.7). Returns (subject, SPKI).
fn verify_csr(
    pem: &[u8],
    algorithm: KeyAlgorithm,
    mechanism: &str,
    ecdsa_half: usize,
) -> (String, Vec<u8>) {
    let der = pem_der(pem);
    let top = children(&der);
    let cri = children(&top[0]);
    let (header, _) = tlv(&top[2]);
    let signature = top[2][header + 1..].to_vec();
    let verifier = MemoryProvider::new("verifier");
    let public = verifier
        .import_key(
            &KeyMaterial::new(algorithm, KeyClass::Public, cri[2].clone()),
            "csr",
            None,
            None,
        )
        .unwrap();
    let signature = if ecdsa_half > 0 {
        let rs = ecdsa_der_to_rs(&signature, ecdsa_half).unwrap(); // parses as DER
        assert!(
            rs[..ecdsa_half].iter().any(|b| *b != 0) && rs[ecdsa_half..].iter().any(|b| *b != 0)
        );
        rs
    } else {
        signature
    };
    let mut params = Params::new();
    params.insert("hash".into(), ParamValue::Enum("sha256".into()));
    let mech = MechanismInvocation::new(mechanism, params);
    assert!(
        verifier
            .verify(&public, &mech, &top[0], &signature)
            .unwrap()
    );
    (rfc4514_string(&cri[1]).unwrap(), cri[2].clone())
}

/// The members of a PKCS#12 (the password travels through a ScriptedIo secret: r2-cli has
/// no `secrecy` dependency, §4.1.2).
fn load_p12(payload: &[u8], password: &str) -> Vec<KeyMaterial> {
    let io = ScriptedIo::new([password]);
    let mut pw = |prompt: &str| io.prompt_secret(prompt);
    parse_key_material(payload, KeyHint::Auto, Some(&mut pw)).unwrap()
}

fn lines(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn no_error_panel(out: &str) {
    assert!(!out.contains("─ error ─"), "{out}");
    assert!(!out.contains("Aborted."), "{out}");
}

// ---------------------------------------------------------------------------------------
// memory (runs without SoftHSM)
// ---------------------------------------------------------------------------------------

/// The c2 flow over MemoryProvider: generate → load (multiline paste) → keys → key info →
/// export --public → csr (RSA + ECDSA, signed by the provider) → p12 → delete.
#[test]
fn memory_console_keys_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let (pkcs8, private_pem, _public_pem) = software_rsa();
    let pub_path = dir.path().join("pub.pem");
    let rsa_csr = dir.path().join("rsa.csr");
    let ec_csr = dir.path().join("ec.csr");
    let p12 = dir.path().join("bundle.p12");
    let mut input = lines(&[
        "providers",
        "generate mem aes size=256 --label aeskey",
        "generate mem ec curve=p256 --label eckey",
        "load mem rsa --label rsakey",
    ]);
    input.extend(private_pem.trim_end().lines().map(str::to_owned));
    input.push(String::new()); // ends the multiline paste
    input.extend([
        "keys mem".to_owned(),
        "key info mem:rsakey".to_owned(),
        format!("export mem:rsakey {} --public", pub_path.display()),
        format!(
            "csr mem:rsakey {} --subject \"CN=cctest,O=ACME\"",
            rsa_csr.display()
        ),
        format!("csr mem:eckey {} --hash sha256", ec_csr.display()),
        format!(
            "export mem:rsakey {} --format p12 --password pw12",
            p12.display()
        ),
        "delete mem:rsakey".to_owned(),
        "delete mem:eckey".to_owned(),
        "delete mem:eckey".to_owned(),
        "delete mem:aeskey".to_owned(),
        "keys mem".to_owned(),
        "exit".to_owned(),
    ]);
    let (out, code) = wide_session(dir.path(), &config, None, &input);
    assert_eq!(code, 0, "{out}");
    no_error_panel(&out);
    assert!(out.contains("ready"));
    assert!(out.contains("generated mem:aeskey (256-bit aes)"));
    assert!(out.contains("generated p256 ec keypair mem:eckey (public key shares the label/id)"));
    assert!(out.contains("Paste key material (hex / base64 / PEM) (finish with an empty line)"));
    assert!(out.contains("loaded into mem"));
    assert!(out.contains("mem:eckey:priv") && out.contains("mem:eckey:pub"));
    assert!(out.contains("mem:rsakey"));
    // export --public: the software key's SPKI
    assert_eq!(
        pem_der(&std::fs::read(&pub_path).unwrap()),
        formats::pkcs8_public_spki(&pkcs8).unwrap()
    );
    // RSA CSR: subject honored, signature made by the provider over the loaded key
    let (subject, spki) = verify_csr(
        &std::fs::read(&rsa_csr).unwrap(),
        KeyAlgorithm::Rsa,
        "RSA-PKCS1",
        0,
    );
    assert_eq!(subject, "CN=cctest,O=ACME");
    assert_eq!(spki, formats::pkcs8_public_spki(&pkcs8).unwrap());
    // ECDSA CSR: default subject, r‖s converted to DER before assembly
    let (subject, _) = verify_csr(
        &std::fs::read(&ec_csr).unwrap(),
        KeyAlgorithm::Ec,
        "ECDSA",
        32,
    );
    assert_eq!(subject, "CN=eckey");
    assert!(out.contains(&format!(
        "wrote CSR for mem:eckey to {} (subject: CN=eckey)",
        ec_csr.display()
    )));
    // PKCS#12 with the on-the-fly self-signed certificate
    let members = load_p12(&std::fs::read(&p12).unwrap(), "pw12");
    let subject = certificate_details(&members[1].data)
        .unwrap()
        .into_iter()
        .find(|(name, _)| name == "subject")
        .unwrap()
        .1;
    assert_eq!(subject, "CN=rsakey");
    assert!(out.contains("deleted mem:aeskey"));
    assert!(out.ends_with("r2> keys mem\nno keys\nr2> exit\n"), "{out}");
}

// ---------------------------------------------------------------------------------------
// SoftHSM (feature `softhsm`; the fixture token of scripts/softhsm-init.sh)
// ---------------------------------------------------------------------------------------

#[cfg(feature = "softhsm")]
mod softhsm {
    use super::*;
    use r2_testkit::softhsm::{softhsm_token, unique_label};

    fn hsm_config(dir: &Path) -> PathBuf {
        let token = softhsm_token();
        write_config(
            dir,
            &format!(
                "providers:\n  pkcs11:\n    - name: hsm\n      library: {}\n",
                token.module_path.display()
            ),
        )
    }

    /// c2 test_console_keys_end_to_end's session; `with_csr` adds the on-token CSRs.
    fn end_to_end(with_csr: bool) {
        let token = softhsm_token();
        let label = unique_label();
        let dir = tempfile::tempdir().unwrap();
        let config = hsm_config(dir.path());
        let rsa_label = format!("{}-rsa", label.as_str());
        let ec_label = format!("{}-ec", label.as_str());
        let (pkcs8, private_pem, public_pem) = software_rsa();
        let pub_path = dir.path().join("pub.pem");
        let rsa_csr_path = dir.path().join("rsa.csr");
        let ec_csr_path = dir.path().join("ec.csr");
        let ok = editor_answers();

        let mut input = lines(&["providers", "slots hsm"]);
        // login: PIN via hidden prompt (§5.2)
        input.push(format!("login hsm {}", token.token_label));
        input.push(token.user_pin.clone());
        // generate AES on-token (editor accepted with the §7 defaults)
        input.push(format!(
            "generate hsm aes size=256 --label {}",
            label.as_str()
        ));
        input.extend(ok.clone());
        // an EC P-256 keypair on-token for the ECDSA CSR (private then public editor)
        input.push(format!("generate hsm ec curve=p256 --label {ec_label}"));
        input.extend(ok.clone());
        input.extend(ok.clone());
        // load a software RSA key: data omitted → multiline paste prompt (§5.1); both
        // halves land under one label + CKA_ID; pkcs11 destination → per-material editor
        for pem in [&private_pem, &public_pem] {
            input.push(format!("load hsm rsa --label {rsa_label} --id aa01"));
            input.extend(pem.trim_end().lines().map(str::to_owned));
            input.push(String::new());
            input.extend(ok.clone());
        }
        input.push("keys hsm".to_owned());
        input.push(format!("key info hsm:{rsa_label}"));
        // export the public half (the private is sensitive per §7 defaults)
        input.push(format!(
            "export hsm:{rsa_label} {} --public",
            pub_path.display()
        ));
        if with_csr {
            // CSRs signed on-token (§5.7) — RSA and ECDSA (r‖s → DER conversion)
            input.push(format!(
                "csr hsm:{rsa_label} {} --subject \"CN=cctest,O=ACME\"",
                rsa_csr_path.display()
            ));
            input.push(format!(
                "csr hsm:{ec_label} {} --hash sha256",
                ec_csr_path.display()
            ));
        }
        // cleanup: keypair halves and the AES key (ui.confirm_delete=false)
        for target in [&rsa_label, &rsa_label, &ec_label, &ec_label] {
            input.push(format!("delete hsm:{target}"));
        }
        input.push(format!("delete hsm:{}", label.as_str()));
        input.push("logout hsm".to_owned());
        input.push("exit".to_owned());

        let (out, code) = wide_session(dir.path(), &config, Some(&token.conf_path), &input);
        assert_eq!(code, 0, "{out}");
        no_error_panel(&out);

        // providers / slots / login
        assert!(out.contains(&token.module_path.display().to_string()));
        assert!(out.contains(&token.token_label));
        assert!(out.contains(&format!("PIN for token '{}': ", token.token_label)));
        assert!(!out.contains(&format!(
            "PIN for token '{}': {}",
            token.token_label, token.user_pin
        )));
        assert!(out.contains(&format!("logged in to '{}'", token.token_label)));

        // generate + load + keys + key info
        assert!(out.contains(&format!("generated hsm:{}", label.as_str())));
        assert!(out.contains(&format!("generated p256 ec keypair hsm:{ec_label}")));
        assert!(out.contains(&format!("hsm:{rsa_label}#aa01"))); // load + keys tables
        // §7 defaults: the loaded private key is sensitive/non-extractable
        assert!(out.contains("CKA_SENSITIVE") && out.contains("True"));

        // export --public: SPKI PEM matching the software key
        assert_eq!(
            pem_der(&std::fs::read(&pub_path).unwrap()),
            formats::pkcs8_public_spki(&pkcs8).unwrap()
        );

        if with_csr {
            // RSA CSR: subject honored, signature made ON TOKEN by the loaded key
            let (subject, spki) = verify_csr(
                &std::fs::read(&rsa_csr_path).unwrap(),
                KeyAlgorithm::Rsa,
                "RSA-PKCS1",
                0,
            );
            assert_eq!(subject, "CN=cctest,O=ACME");
            assert_eq!(spki, formats::pkcs8_public_spki(&pkcs8).unwrap());
            // ECDSA CSR: the token emits fixed-width r‖s; a signature that parses AND
            // verifies proves certops converted it to DER before assembly
            let (subject, _) = verify_csr(
                &std::fs::read(&ec_csr_path).unwrap(),
                KeyAlgorithm::Ec,
                "ECDSA",
                32,
            );
            assert_eq!(subject, format!("CN={ec_label}")); // default subject
        }

        // cleanup happened inside the session
        assert!(out.contains(&format!("deleted hsm:{}", label.as_str())));
        assert!(out.contains("logged out of hsm"));
    }

    /// The full c2 session, CSRs included: on-token C_Sign is R5b's (merge checklist: the
    /// R5b merge deletes this ignore).
    #[test]
    fn test_console_keys_end_to_end_softhsm() {
        end_to_end(true);
    }

    /// The same session without the on-token CSRs — R5a's object surface only.
    #[test]
    fn console_keys_end_to_end_without_signing_softhsm() {
        end_to_end(false);
    }

    /// §5.6 error path + PKCS#12: the sensitive on-token AES key is refused with the
    /// pre-flight message (file never written); a loaded exportable memory key assembles a
    /// PKCS#12 with an on-the-fly self-signed certificate (cert-missing path).
    #[test]
    fn test_export_refusal_and_p12_self_signed_softhsm() {
        let token = softhsm_token();
        let label = unique_label();
        let dir = tempfile::tempdir().unwrap();
        let config = hsm_config(dir.path());
        let p12_label = format!("{}-p12", label.as_str());
        let (_pkcs8, private_pem, _public_pem) = software_rsa();
        let aes_out = dir.path().join("aes.bin");
        let p12_out = dir.path().join("bundle.p12");

        let mut input = vec![format!(
            "login hsm {} --pin {}",
            token.token_label, token.user_pin
        )];
        // sensitive AES key (§7 defaults accepted: EXTRACTABLE=false)
        input.push(format!(
            "generate hsm aes size=256 --label {}",
            label.as_str()
        ));
        input.extend(editor_answers());
        input.push(format!(
            "export hsm:{} {}",
            label.as_str(),
            aes_out.display()
        )); // refused
        // p12 assembly is software-side (§5.6) — the memory provider keeps the key exportable
        input.push(format!("load mem rsa --label {p12_label}"));
        input.extend(private_pem.trim_end().lines().map(str::to_owned));
        input.push(String::new());
        input.push(format!(
            "export mem:{p12_label} {} --format p12 --password pw12",
            p12_out.display()
        ));
        input.push(format!("delete hsm:{}", label.as_str()));
        input.push("exit".to_owned());

        let (out, code) = session(dir.path(), &config, Some(&token.conf_path), &input);
        assert_eq!(code, 0, "{out}");
        // the sensitive on-token key was refused with the §5.6 message…
        assert!(out.contains("Refusing to export"), "{out}");
        assert!(!aes_out.exists());
        // …and the PKCS#12 with the self-signed certificate loads
        let members = load_p12(&std::fs::read(&p12_out).unwrap(), "pw12");
        assert_eq!(members[0].key_class, KeyClass::Private);
        let subject = certificate_details(&members[1].data)
            .unwrap()
            .into_iter()
            .find(|(name, _)| name == "subject")
            .unwrap()
            .1;
        assert_eq!(subject, format!("CN={p12_label}"));
        // critical basicConstraints CA:FALSE
        assert!(members[1].data.windows(12).any(|w| w
            == [
                0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00
            ]));
        assert!(out.contains(&format!("deleted hsm:{}", label.as_str())));
    }
}
