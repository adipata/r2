// Console ↔ MemoryProvider integration for the crypto commands (spec §5.1; owner R9) — the
// port of c2 tests/integration/test_console_crypto.py.
//
// Full REPL round-trips — ScriptedIo command lines through `run_repl` (parser → binder →
// dispatch → crypto command → real MemoryProvider crypto), in-process over the permitted
// r2-console ⇢ r2-memory dev edge (§4.10.6 `CtxBuilder::providers`). Memory provider only,
// so these tests are NOT behind the `softhsm` feature. c2 recomputed the expected AES-GCM
// output with pyca's AESGCM and verified the PSS signature with pyca; r2-console may not
// depend on openssl, so the AESGCM vectors below were generated with pyca (c2's venv) and
// the PSS signature is re-verified by the provider with an explicit salt_len=32.
use std::rc::Rc;

use r2_core::codec::format_hex;
use r2_core::formats::pkcs8_public_spki;
use r2_core::io::ConsoleIo;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::params::{ParamValue, Params};
use r2_core::text::py_fromhex;
use r2_memory::MemoryProvider;
use r2_provider::{KeySelector, MechanismInvocation, Provider, ProviderRegistry};
use r2_testkit::ScriptedIo;
use r2_testkit::fixtures::rsa2048_pkcs8;

use crate::commands::all_commands;
use crate::repl::run_repl;
use crate::testing::CtxBuilder;

/// AES-256 key bytes(range(32)).
fn aes_key() -> Vec<u8> {
    (0..32).collect()
}
const IV: &str = "000102030405060708090a0b";

/// pyca `AESGCM(bytes(range(32))).encrypt(IV, bytes(range(32)), b"")`.
const GCM_32: &str = "4703d418c1e0c41c85489d80bde4766293c79527e46e496b207eff9e01741ead5edddc5074044e2282b432b3f2d8f673";
/// pyca `AESGCM(bytes(range(32))).encrypt(IV, bytes(range(48)), b"")`.
const GCM_48: &str = "4703d418c1e0c41c85489d80bde4766293c79527e46e496b207eff9e01741ead21318cdf8be434bf5c8d55c6a4aa06177aed1e902811aa78deaee41ecc797d58";
/// pyca `AESGCM(bytes(range(32))).encrypt(IV, b"\xde\xad\xbe\xef", b"")`.
const GCM_DEADBEEF: &str = "99af68f4601078f27799238e52313cb8411aa55d";

fn hex_of(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    py_fromhex(text).unwrap()
}

/// The memory provider of c2's `make_ctx`: "aeskey" (AES-256), "rsapriv" (RSA-2048 PKCS#8)
/// and "rsapub" (its SPKI) — distinct labels so `mem:rsapub` targets the public key.
fn memory_provider() -> Rc<MemoryProvider> {
    let pkcs8 = rsa2048_pkcs8();
    let spki = pkcs8_public_spki(&pkcs8).unwrap();
    let mem = MemoryProvider::new("mem");
    mem.import_key(
        &KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, aes_key()),
        "aeskey",
        None,
        None,
    )
    .unwrap();
    mem.import_key(
        &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, pkcs8),
        "rsapriv",
        None,
        None,
    )
    .unwrap();
    mem.import_key(
        &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Public, spki),
        "rsapub",
        None,
        None,
    )
    .unwrap();
    Rc::new(mem)
}

/// Feed command lines (and interleaved prompt answers) through the REPL (c2 `run_session`).
fn run_session(answers: &[&str]) -> (Rc<ScriptedIo>, Rc<MemoryProvider>) {
    // The verbs honor the process-global Ctrl-C flag (§11 D13): hold the global lock so a
    // concurrent test setting it cannot abort this session under `cargo test`.
    let _lock = r2_testkit::global_state_lock();
    let mut script: Vec<String> = answers.iter().map(|a| (*a).to_owned()).collect();
    script.push("exit".to_owned());
    let io = Rc::new(ScriptedIo::new(script));
    let mem = memory_provider();
    let providers = ProviderRegistry::new();
    providers
        .register(Rc::clone(&mem) as Rc<dyn Provider>)
        .unwrap();
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .providers(providers)
        .build();
    run_repl(&ctx, false, all_commands().unwrap());
    assert_eq!(io.remaining(), 0, "the session consumed every answer");
    (io, mem)
}

fn assert_clean(io: &ScriptedIo) {
    let errors: Vec<String> = io
        .output()
        .into_iter()
        .filter(|line| line.starts_with("error:"))
        .collect();
    assert!(errors.is_empty(), "session rendered errors: {errors:?}");
}

// ---------------------------------------------------------------------------
// AES-GCM full command round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_aes_gcm_command_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let plaintext: Vec<u8> = (0..32).collect();
    let ct_path = dir.path().join("ct.hex");
    let pt_path = dir.path().join("pt.bin");
    let (io, _) = run_session(&[
        &format!(
            "encrypt mem:aeskey gcm iv=0x{IV} 0x{} --out {} --outformat hex",
            hex_of(&plaintext),
            ct_path.display()
        ),
        &format!(
            "decrypt mem:aeskey gcm iv=0x{IV} --in {} --out {}",
            ct_path.display(),
            pt_path.display()
        ),
    ]);
    assert_clean(&io);
    let ciphertext = unhex(std::fs::read_to_string(&ct_path).unwrap().trim());
    // §5.8 GCM convention: providers emit and consume ct‖tag.
    assert_eq!(ciphertext.len(), plaintext.len() + 16);
    assert_eq!(ciphertext, unhex(GCM_32));
    assert_eq!(std::fs::read(&pt_path).unwrap(), plaintext);
}

#[test]
fn test_aes_gcm_interactive_fallbacks() {
    // Omitted mech → select list; missing iv → prompted; no data → paste.
    let plaintext: Vec<u8> = (0..48).collect();
    let iv = format!("0x{IV}");
    let data = format!("0x{}", hex_of(&plaintext));
    let (io, _) = run_session(&[
        "encrypt mem:aeskey",
        "3", // sorted encrypt cli names for AES: cbc, ctr, ecb, gcm
        &iv,
        &data, // the paste prompt takes one answer (ScriptedIo, as c2's ScriptedIO)
    ]);
    assert_clean(&io);
    let prompts = io.prompts();
    assert!(prompts.contains(&"Select encrypt mechanism for mem:aeskey".to_owned()));
    assert!(prompts.contains(&"IV / nonce (12 bytes typical)".to_owned()));
    assert!(prompts.contains(&"Data (hex, base64 or PEM)".to_owned()));
    let expected = unhex(GCM_48);
    let text = io.text();
    assert!(text.contains("64 bytes")); // ct‖tag length in the hex panel subtitle
    assert!(text.contains(&format!("\n{}\n", format_hex(&expected, 0, 0)))); // §11 D28
}

#[test]
fn test_aes_gcm_tampered_tag_renders_error_at_repl_boundary() {
    let mut bad = unhex(GCM_DEADBEEF);
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    let (io, _) = run_session(&[&format!(
        "decrypt mem:aeskey gcm iv=0x{IV} 0x{}",
        hex_of(&bad)
    )]);
    assert!(io.output().iter().any(|line| line.starts_with("error:")));
    // and the untampered blob decrypts in the same way
    let (io, _) = run_session(&[&format!(
        "decrypt mem:aeskey gcm iv=0x{IV} 0x{GCM_DEADBEEF}"
    )]);
    assert_clean(&io);
    assert!(io.text().contains("\ndeadbeef\n")); // c2: "dead beef" (§11 D28)
}

// ---------------------------------------------------------------------------
// RSA-PSS full command round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_rsa_pss_command_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let message: Vec<u8> = (0..64).collect(); // not printable ASCII → file read verbatim
    let mut tampered = message.clone();
    tampered[0] = 0xff; // message[0] is 0x00 — flip, don't repeat it
    let msg_path = dir.path().join("msg.bin");
    std::fs::write(&msg_path, &message).unwrap();
    let sig_path = dir.path().join("sig.hex");
    let (io, mem) = run_session(&[
        &format!(
            "sign mem:rsapriv pss hash=sha256 --in {} --out {} --outformat hex",
            msg_path.display(),
            sig_path.display()
        ),
        &format!(
            "verify mem:rsapub pss hash=sha256 --in {} --sig-file {}",
            msg_path.display(),
            sig_path.display()
        ),
        &format!(
            "verify mem:rsapub pss hash=sha256 0x{} --sig-file {}",
            hex_of(&tampered),
            sig_path.display()
        ),
    ]);
    assert_clean(&io);
    let output = io.output();
    let valid = output
        .iter()
        .filter(|line| line.contains("signature VALID"))
        .count();
    let invalid = output
        .iter()
        .filter(|line| line.contains("signature INVALID"))
        .count();
    assert_eq!(valid, 1);
    assert_eq!(invalid, 1);
    let signature = unhex(std::fs::read_to_string(&sig_path).unwrap().trim());
    assert_eq!(signature.len(), 256);
    // Default salt_len=None → digest length (§4.6): verifies with an explicit salt of 32.
    let public = mem.find_key(&KeySelector::label("rsapub")).unwrap();
    let mut params = Params::new();
    params.insert("hash".to_owned(), ParamValue::Enum("sha256".to_owned()));
    params.insert("salt_len".to_owned(), ParamValue::Int(32));
    let pss = MechanismInvocation::new("RSA-PSS", params);
    assert!(mem.verify(&public, &pss, &message, &signature).unwrap());
}

/// Accept (R9 card): the keypair-ref verify fallback over the real memory provider — a
/// generated EC pair signs and verifies through the same `mem:label` ref.
#[test]
fn verify_through_the_private_ref_uses_the_public_half() {
    let dir = tempfile::tempdir().unwrap();
    let sig = dir.path().join("sig.bin");
    let mem = memory_provider();
    let mut request = r2_provider::GenerateRequest::new(KeyAlgorithm::Ec, "pair");
    request.curve = Some(r2_core::keys::Curve::P256);
    mem.generate_key(&request).unwrap();
    let providers = ProviderRegistry::new();
    providers
        .register(Rc::clone(&mem) as Rc<dyn Provider>)
        .unwrap();
    let io = Rc::new(ScriptedIo::new([
        format!("sign mem:pair ecdsa 0xdeadbeef --out {}", sig.display()),
        format!(
            "verify mem:pair ecdsa 0xdeadbeef --sig-file {}",
            sig.display()
        ),
        format!(
            "verify mem:pair ecdsa 0xdeadbe00 --sig-file {}",
            sig.display()
        ),
        "exit".to_owned(),
    ]));
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .providers(providers)
        .build();
    run_repl(&ctx, false, all_commands().unwrap());
    assert_clean(&io);
    let output = io.output();
    assert_eq!(
        output[output.len() - 2..],
        ["signature VALID", "signature INVALID"]
    );
    assert_eq!(std::fs::read(&sig).unwrap().len(), 64); // canonical r‖s (§4.5.4)
}

// ---------------------------------------------------------------------------
// ops table over the real memory provider
// ---------------------------------------------------------------------------

#[test]
fn test_ops_table_for_memory_provider() {
    let (io, _) = run_session(&["ops mem"]);
    assert_clean(&io);
    let text = io.text();
    assert!(text.contains("operations — mem"));
    for cli_name in [
        "gcm", "cbc", "cmac", "gmac", "oaep", "pss", "ecdsa", "eddsa", "ecdh",
    ] {
        assert!(text.contains(cli_name), "{cli_name}");
    }
    for verb in ["encrypt", "decrypt", "sign", "verify", "derive"] {
        assert!(text.contains(verb), "{verb}");
    }
}

#[test]
fn test_ops_key_filter_restricts_to_the_key() {
    let (io, _) = run_session(&["ops --key mem:aeskey"]);
    assert_clean(&io);
    let text = io.text();
    assert!(text.contains("operations for mem:aeskey"));
    assert!(text.contains("gcm"));
    assert!(text.contains("cmac"));
    assert!(!text.contains("oaep"));
    assert!(!text.contains("ecdsa"));
}

/// Errors from a crypto command render at the REPL boundary with c2's hint text.
#[test]
fn command_errors_render_as_error_lines() {
    let (io, _) = run_session(&["encrypt mem:aeskey ecb 0xdeadbeef --outformat hex"]);
    assert!(io.output().contains(
        &"error: --outformat requires --out (hint: console output is always the grouped hex dump (§5.1))"
            .to_owned()
    ));
}
