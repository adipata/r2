// The checklist editor end to end against a real SoftHSM2 token (R10, spec §5.12/§4.7) —
// port of the editor case of c2 tests/integration/test_console_keys.py
// (`test_generate_honors_template_editor_cka_id`, a field-report repro): `add CKA_ID=0xc0fe`
// in the REAL editor becomes the on-token CKA_ID, not a random 4-byte id. Feature
// `softhsm`; fails (never skips) without the fixture of `scripts/softhsm-init.sh`. The
// session runs through `run_line` (the REPL's dispatch) with the editor answers queued
// on the same ScriptedIo, as c2's piped session did.
#![cfg(feature = "softhsm")]

use std::collections::BTreeMap;
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::Pkcs11InstanceConfig;
use r2_core::io::ConsoleIo;
use r2_pkcs11::Pkcs11Provider;
use r2_provider::{Provider, ProviderRegistry};
use r2_testkit::softhsm::{softhsm_token, unique_label};
use r2_testkit::{ScriptedIo, global_state_lock};

use crate::testing::{CtxBuilder, run_line};

#[test]
fn test_generate_honors_template_editor_cka_id_softhsm() {
    let _lock = global_state_lock();
    let token = softhsm_token();
    let label = unique_label();
    let mut config = Pkcs11InstanceConfig::new("hsm", token.module_path.clone());
    config.slot = Some(token.slot);
    config.token_label = Some(token.token_label.clone());
    let hsm = Rc::new(Pkcs11Provider::new(
        "hsm",
        config,
        BTreeMap::new(),
        IndexMap::new(),
    ));
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::clone(&hsm) as Rc<dyn Provider>)
        .unwrap();
    let io = Rc::new(ScriptedIo::new(["add CKA_ID=0xc0fe", "ok", "y"]));
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .providers(registry)
        .build();

    let lines = [
        format!("login hsm {} --pin {}", token.token_label, token.user_pin),
        format!("generate hsm aes size=128 --label {}", label.as_str()),
        format!("delete hsm:{}", label.as_str()),
    ];
    let mut errors = Vec::new();
    for line in &lines {
        if let Err(err) = run_line(&ctx, line) {
            errors.push(format!("{line}: {}", err.message));
        }
    }
    let _ = hsm.shutdown();
    assert!(errors.is_empty(), "{errors:?}");

    let output = io.output();
    let notes: Vec<&String> = output.iter().filter(|l| l.starts_with("note:")).collect();
    assert!(notes.iter().any(|line| line.contains("--id")), "{output:?}");
    assert!(
        io.text().contains(&format!(
            "generated hsm:{}#c0fe (128-bit aes)",
            label.as_str()
        )),
        "{}",
        io.text()
    );
    assert_eq!(io.remaining(), 0);
}
