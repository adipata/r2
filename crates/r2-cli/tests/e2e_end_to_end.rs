//! Cross-loop end-to-end scenarios (owner R13) — the port of c2
//! tests/integration/test_end_to_end.py, driven through the real `r2` binary with piped
//! stdin (PlainIo, §11 D2) and a temp `--config`.
//!
//! - `test_full_scenario_load_copy_sign_verify_export_csr` (feature `softhsm`): load PEM
//!   RSA key into mem → copy to SoftHSM (wrapless mem→pkcs11 route, checklist template
//!   editor) → sign RSA-PSS ON TOKEN → verify the signature in the memory provider
//!   (software PSS over the keypair's public half — the §5.1 verify fallback) → export a
//!   PKCS#12 with an on-the-fly self-signed certificate → CSR signed on token. The
//!   cross-provider sign/verify is the differentiator (§8): a signature the HSM produced
//!   must verify against the very key material that was pasted as PEM at the start.
//! - `test_encrypted_traditional_pem_paste_through_console` (memory only, runs in the unit
//!   job too): an OpenSSL traditional *encrypted* PEM — with its blank line after
//!   `DEK-Info:` — pasted as a quoted multi-line token arrives whole and its password is
//!   prompted for (§5.4).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

/// c2's encrypted traditional PEM (pyca `TraditionalOpenSSL` + `BestAvailableEncryption`
/// = AES-256-CBC, password `tr4d`), generated once with pyca in c2's venv (c2 generated a
/// fresh one per run; r2-cli has no OpenSSL dev-dependency to do the same).
const ENCRYPTED_PEM: &str = include_str!("fixtures/rsa2048_traditional_tr4d.pem");

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

/// The lines of a multiline paste answer: the text plus the empty line that ends it.
#[cfg(feature = "softhsm")]
fn paste(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text.trim_end().lines().map(str::to_owned).collect();
    lines.push(String::new());
    lines
}

fn no_error_panel(out: &str) {
    assert!(!out.contains("─ error ─"), "{out}");
    assert!(!out.contains("Aborted."), "{out}");
}

#[test]
fn test_encrypted_traditional_pem_paste_through_console() {
    let dir = tempfile::tempdir().unwrap();
    let config: PathBuf = dir.path().join("r2.yaml");
    std::fs::write(
        &config,
        format!(
            "app:\n  history_file: {}\n  log:\n    file: {}\nsofthsm:\n  autodetect: false\n",
            dir.path().join("history").display(),
            dir.path().join("cc.log").display()
        ),
    )
    .unwrap();
    assert!(ENCRYPTED_PEM.contains("DEK-Info: AES-256-CBC,"));
    assert!(ENCRYPTED_PEM.contains("\n\n")); // the blank line after DEK-Info
    // A piped session cannot carry the blank line after DEK-Info through the `| ` prompt
    // (an empty line ends the paste, in c2 and r2 alike), so the PEM travels as a quoted
    // multi-line command token; the ScriptedIo port that hands the whole PEM to the
    // multiline prompt as one answer (c2's mechanics) is r2-console
    // tests::end_to_end::test_encrypted_traditional_pem_paste_through_console.
    let mut input = vec![format!(
        "load mem rsa --label pasted \"{}\"",
        ENCRYPTED_PEM.trim_end()
    )];
    input.push("tr4d".to_owned()); // password prompt (§5.4, prompt_secret)
    input.push("keys mem".to_owned());
    input.push("exit".to_owned());
    let (out, code) = session(dir.path(), &config, None, &input);
    assert_eq!(code, 0, "{out}");
    no_error_panel(&out);
    assert!(out.contains("mem:pasted"), "{out}");
    assert!(out.contains("Password for encrypted"), "{out}");
    assert!(!out.contains("tr4d"), "{out}");
}

#[cfg(feature = "softhsm")]
mod softhsm {
    use super::*;
    use r2_core::codec::decode_data;
    use r2_core::formats::{self, Encoding};
    use r2_core::io::ConsoleIo;
    use r2_core::keyparse::{KeyHint, parse_key_material};
    use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
    use r2_core::params::{ParamValue, Params};
    use r2_core::x509info::{certificate_details, rfc4514_string};
    use r2_memory::MemoryProvider;
    use r2_provider::{MechanismInvocation, Provider};
    use r2_testkit::ScriptedIo;
    use r2_testkit::softhsm::{softhsm_token, unique_label};

    const DATA_HEX: &str = "00112233445566778899aabbccddeeff";

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

    fn sha256_params() -> Params {
        let mut params = Params::new();
        params.insert("hash".into(), ParamValue::Enum("sha256".into()));
        params
    }

    #[test]
    fn test_full_scenario_load_copy_sign_verify_export_csr() {
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
                 softhsm:\n  autodetect: false\n",
                dir.path().join("history").display(),
                dir.path().join("r2.log").display(),
                token.module_path.display()
            ),
        )
        .unwrap();
        let pkcs8 = r2_testkit::fixtures::rsa2048_pkcs8();
        let spki = formats::pkcs8_public_spki(&pkcs8).unwrap();
        let private_pem = String::from_utf8(
            formats::private_key_bytes(&pkcs8, Encoding::Pem, None)
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let public_pem =
            String::from_utf8(formats::public_key_bytes(&spki, Encoding::Pem).unwrap()).unwrap();

        let sig_path = dir.path().join("pss.sig");
        let p12_path = dir.path().join("bundle.p12");
        let csr_path = dir.path().join("token.csr");

        let mut input = vec![format!(
            "login hsm {} --pin {}",
            token.token_label, token.user_pin
        )];
        // 1. load the software RSA keypair into mem (PEM paste, both halves under one
        //    label — no template editor for memory)
        input.push(format!("load mem rsa --label {label}"));
        input.extend(paste(&private_pem));
        input.push(format!("load mem rsa --label {label}"));
        input.extend(paste(&public_pem));
        // 2. copy the private key to the token: mem→pkcs11 plain route, ONE checklist
        //    editor for the destination template (§5.5) — §7 defaults
        input.push(format!("copy mem:{label} hsm --id bb02"));
        input.push("ok".to_owned());
        // …and its public half (CSR/§5.7 needs a public object on token)
        input.push(format!("load hsm rsa --label {label} --id bb02"));
        input.extend(paste(&public_pem));
        input.push("ok".to_owned());
        // 3. sign RSA-PSS on token (sha256 defaults, salt=digest len)
        input.push(format!(
            "sign hsm:{label} pss 0x{DATA_HEX} --out {}",
            sig_path.display()
        ));
        // 4. verify in the memory provider — the ref resolves to the PRIVATE half; §5.1
        //    falls back to the co-located public half
        input.push(format!(
            "verify mem:{label} pss 0x{DATA_HEX} --sig-file {}",
            sig_path.display()
        ));
        // 5. PKCS#12 export from mem; no certificate under the label → self-signed (§5.6)
        input.push(format!(
            "export mem:{label} {} --format p12 --password pw12",
            p12_path.display()
        ));
        // 6. CSR signed ON TOKEN by the (sensitive) copied key (§5.7)
        input.push(format!(
            "csr hsm:{label} {} --subject \"CN=e2e,O=CCTEST\"",
            csr_path.display()
        ));
        // cleanup both token objects (find_key prefers the private half)
        input.push(format!("delete hsm:{label}"));
        input.push(format!("delete hsm:{label}"));
        input.push("logout hsm".to_owned());
        input.push("exit".to_owned());

        let (out, code) = session(dir.path(), &config, Some(&token.conf_path), &input);
        assert_eq!(code, 0, "{out}");
        no_error_panel(&out);

        // copy: went to the token under the same label with the requested CKA_ID
        assert!(
            out.contains(&format!("copied mem:{label} -> hsm:{label}#bb02")),
            "{out}"
        );

        // sign: signature file written by the on-token PSS operation
        let signature = std::fs::read(&sig_path).unwrap();
        assert_eq!(signature.len(), 256); // RSA-2048

        // the console's own cross-provider verify succeeded (§5.1 fallback)
        assert!(out.contains("signature VALID"), "{out}");
        assert!(!out.contains("signature INVALID"), "{out}");

        // independent check: the HSM signature verifies with the ORIGINAL pasted key
        let verifier = MemoryProvider::new("verifier");
        let public = verifier
            .import_key(
                &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Public, spki.clone()),
                "orig",
                None,
                None,
            )
            .unwrap();
        let pss = MechanismInvocation::new("RSA-PSS", sha256_params());
        assert!(
            verifier
                .verify(
                    &public,
                    &pss,
                    &decode_data(&format!("0x{DATA_HEX}")).unwrap().0,
                    &signature
                )
                .unwrap()
        );

        // export: PKCS#12 with on-the-fly self-signed certificate (§5.6)
        let io = ScriptedIo::new(["pw12"]);
        let mut pw = |prompt: &str| io.prompt_secret(prompt);
        let members = parse_key_material(
            &std::fs::read(&p12_path).unwrap(),
            KeyHint::Auto,
            Some(&mut pw),
        )
        .unwrap();
        let key = members
            .iter()
            .find(|m| m.key_class == KeyClass::Private)
            .expect("p12 key");
        assert_eq!(key.algorithm, KeyAlgorithm::Rsa);
        assert_eq!(*key.data, *pkcs8);
        let cert = members
            .iter()
            .find(|m| m.key_class == KeyClass::Certificate)
            .expect("p12 cert");
        let details = certificate_details(&cert.data).unwrap();
        let field = |name: &str| {
            details
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert_eq!(field("subject"), field("issuer")); // self-signed
        assert_eq!(field("subject"), format!("CN={label}"));
        // BasicConstraints (2.5.29.19), CA:FALSE = an empty SEQUENCE in the OCTET STRING
        let at = cert
            .data
            .windows(5)
            .position(|w| w == [0x06, 0x03, 0x55, 0x1d, 0x13])
            .expect("BasicConstraints extension");
        let rest = &cert.data[at + 5..];
        let value = if rest.starts_with(&[0x01, 0x01]) {
            &rest[3..]
        } else {
            rest
        };
        assert!(value.starts_with(&[0x04, 0x02, 0x30, 0x00]), "{value:02x?}");

        // csr: signed on token, subject honored, key matches the pasted keypair
        let der = pem_der(&std::fs::read(&csr_path).unwrap());
        let top = children(&der);
        let cri = children(&top[0]);
        assert_eq!(rfc4514_string(&cri[1]).unwrap(), "CN=e2e,O=CCTEST");
        assert_eq!(cri[2], spki);
        let (header, _) = tlv(&top[2]);
        let csr_sig = top[2][header + 1..].to_vec();
        let pkcs1 = MechanismInvocation::new("RSA-PKCS1", sha256_params());
        assert!(verifier.verify(&public, &pkcs1, &top[0], &csr_sig).unwrap());

        // cleanup happened inside the session
        assert!(out.contains(&format!("deleted hsm:{label}")), "{out}");
        assert!(out.contains("logged out of hsm"), "{out}");
    }
}
