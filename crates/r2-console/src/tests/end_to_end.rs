// Cross-loop console end-to-end (owner R13) — the in-process port of c2
// tests/integration/test_end_to_end.py::test_encrypted_traditional_pem_paste_through_console
// with c2's mechanics: the whole REPL (`run_repl`) over ScriptedIo + a real MemoryProvider,
// the encrypted traditional PEM handed to the multiline prompt as ONE answer (c2's
// RenderingIO did the same). The piped-binary twin (quoted multi-line token) is r2-cli
// tests/e2e_end_to_end.rs.
use std::rc::Rc;

use r2_core::io::ConsoleIo;
use r2_memory::MemoryProvider;
use r2_provider::{Provider, ProviderRegistry};
use r2_testkit::ScriptedIo;

use crate::commands::all_commands;
use crate::repl::run_repl;
use crate::testing::CtxBuilder;

/// pyca `TraditionalOpenSSL` + `BestAvailableEncryption(b"tr4d")` of an RSA-2048 key
/// (generated once in c2's venv; c2 generated a fresh one per run).
const ENCRYPTED_PEM: &str = include_str!("fixtures/rsa2048_traditional_tr4d.pem");

#[test]
fn test_encrypted_traditional_pem_paste_through_console() {
    let _lock = r2_testkit::global_state_lock();
    let io = Rc::new(ScriptedIo::new([
        "load mem rsa --label pasted",
        ENCRYPTED_PEM,
        "tr4d", // password prompt (§5.4, prompt_secret)
        "keys mem",
        "exit",
    ]));
    let providers = ProviderRegistry::new();
    providers
        .register(Rc::new(MemoryProvider::new("mem")) as Rc<dyn Provider>)
        .unwrap();
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .providers(providers)
        .build();
    run_repl(&ctx, false, all_commands().unwrap());
    assert_eq!(io.remaining(), 0);
    let errors: Vec<String> = io
        .output()
        .into_iter()
        .filter(|line| line.starts_with("error:"))
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    assert!(io.text().contains("mem:pasted"), "{}", io.text());
    assert!(
        io.prompts()
            .iter()
            .any(|prompt| prompt.contains("Password for encrypted")),
        "{:?}",
        io.prompts()
    );
}
