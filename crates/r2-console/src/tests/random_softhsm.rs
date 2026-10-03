// `random` (spec §5.17, §11 D29 — r2 only) against a real Pkcs11Provider on the SoftHSM
// fixture token: C_GenerateRandom on the logged-in session renders the hex result or writes
// --out, and a logged-out token is AuthRequired before any prompt. Feature `softhsm`; fails
// (never skips) without the fixture of `scripts/softhsm-init.sh`.
#![cfg(feature = "softhsm")]

use std::collections::BTreeMap;
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::Pkcs11InstanceConfig;
use r2_core::error::ErrorKind;
use r2_core::io::{ConsoleIo, Renderable};
use r2_pkcs11::Pkcs11Provider;
use r2_provider::{Provider, ProviderRegistry};
use r2_testkit::softhsm::softhsm_token;
use r2_testkit::{ScriptedIo, global_state_lock};

use crate::context::AppContext;
use crate::testing::{CtxBuilder, run_line};

struct Session {
    ctx: Rc<AppContext>,
    io: Rc<ScriptedIo>,
    provider: Rc<Pkcs11Provider>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl Session {
    /// A registry holding only "hsm" on the fixture token — not yet logged in.
    fn new(answers: &[&str]) -> Self {
        let lock = global_state_lock();
        let token = softhsm_token();
        let provider = Rc::new(Pkcs11Provider::new(
            "hsm",
            Pkcs11InstanceConfig::new("hsm", token.module_path.clone()),
            BTreeMap::new(),
            IndexMap::new(),
        ));
        let registry = ProviderRegistry::new();
        registry
            .register(Rc::clone(&provider) as Rc<dyn Provider>)
            .unwrap();
        let io = Rc::new(ScriptedIo::new(answers.iter().copied()));
        let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
            .providers(registry)
            .build();
        Self {
            ctx,
            io,
            provider,
            _lock: lock,
        }
    }
    fn login(&self) {
        let token = softhsm_token();
        self.run(&format!(
            "login hsm {} --pin {}",
            token.token_label, token.user_pin
        ));
    }
    fn run(&self, line: &str) {
        if let Err(err) = run_line(&self.ctx, line) {
            panic!("{line}: {} ({:?})", err.message, err.hint);
        }
    }
    /// The data of every Hex result printed so far, in order.
    fn hex_results(&self) -> Vec<Vec<u8>> {
        self.io
            .renderables()
            .into_iter()
            .filter_map(|renderable| match renderable {
                Renderable::Hex { data, title, .. } => {
                    assert_eq!(title.as_deref(), Some("random — hsm"));
                    Some(data.to_vec())
                }
                _ => None,
            })
            .collect()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.provider.shutdown();
    }
}

#[test]
fn random_on_the_logged_in_token_softhsm() {
    let s = Session::new(&[]);
    s.login();
    s.run("random hsm 32");
    s.run("random hsm 32");
    let results = s.hex_results();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].len(), 32);
    assert_eq!(results[1].len(), 32);
    assert_ne!(results[0], results[1]);
    let text = s.io.text();
    assert!(text.contains("32 bytes"), "{text}");
}

#[test]
fn random_out_file_on_the_token_softhsm() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rnd.hex");
    let s = Session::new(&[]);
    s.login();
    s.run(&format!(
        "random hsm 1024 --out {} --outformat hex",
        path.display()
    ));
    let text = std::fs::read_to_string(&path).unwrap();
    let bytes = r2_core::text::py_fromhex(text.trim()).unwrap();
    assert_eq!(bytes.len(), 1024);
    assert_eq!(
        s.io.output().last().unwrap(),
        &format!("wrote 1024 bytes to {}", path.display())
    );
}

#[test]
fn random_prompts_for_the_length_softhsm() {
    let s = Session::new(&["16"]);
    s.login();
    s.run("random hsm");
    assert_eq!(s.io.prompts().last().unwrap(), "Number of random bytes");
    assert_eq!(
        s.hex_results().iter().map(Vec::len).collect::<Vec<_>>(),
        [16]
    );
}

/// Logged out (never logged in, and after `logout`): AuthRequired with the login hint,
/// before the length prompt consumes an answer.
#[test]
fn random_requires_login_softhsm() {
    let s = Session::new(&["16"]);
    for phase in ["before login", "after logout"] {
        if phase == "after logout" {
            s.login();
            s.run("logout hsm");
        }
        let err = run_line(&s.ctx, "random hsm").unwrap_err();
        assert_eq!(err.kind, ErrorKind::AuthRequired, "{phase}: {err:?}");
        assert_eq!(err.message, "login required: run `login hsm`", "{phase}");
        assert_eq!(s.io.remaining(), 1, "{phase}");
        let err = run_line(&s.ctx, "random hsm 16").unwrap_err();
        assert_eq!(err.kind, ErrorKind::AuthRequired, "{phase}: {err:?}");
    }
    assert!(s.hex_results().is_empty());
}
