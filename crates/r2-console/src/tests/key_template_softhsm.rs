// `key template` / `--template` against a real Pkcs11Provider on the SoftHSM fixture token
// (spec §5.16; R14) — the port of c2 tests/integration/test_console_keys.py
// `test_key_template_dump_and_reseed`, plus the c2 ↔ r2 interop checks: r2's dump of an
// object imported exactly as in c2 is byte-identical to c2's dump of it (except the §11 D18
// unsigned CKA_KEY_GEN_MECHANISM), and c2's dump seeds an r2 generate. Feature `softhsm`;
// fails (never skips) without the fixture of `scripts/softhsm-init.sh`. The template editor
// is a SpyEditor that accepts every seed as-is (c2's piped "ok").
#![cfg(feature = "softhsm")]

use std::collections::BTreeMap;
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::Pkcs11InstanceConfig;
use r2_config::yaml::{self, Value};
use r2_core::io::{ConsoleIo, TemplateEditor};
use r2_core::template::AttrValue;
use r2_pkcs11::Pkcs11Provider;
use r2_provider::{Provider, ProviderRegistry};
use r2_testkit::softhsm::{softhsm_token, unique_label};
use r2_testkit::{ScriptedIo, global_state_lock};

use super::keys_cmd_support::SpyEditor;
use crate::context::AppContext;
use crate::testing::{CtxBuilder, run_line};

/// c2's `key template` dump of an AES key it imported on SoftHSM 2.6.1 (`load hsm aes
/// 000102030405060708090a0b0c0d0e0f --label imp --id 0a1b`, §7 default template accepted).
const C2_IMPORTED_AES: &str = "aes:\n  CKA_CLASS: CKO_SECRET_KEY\n  CKA_TOKEN: true\n  \
CKA_PRIVATE: true\n  CKA_LABEL: imp\n  CKA_TRUSTED: false\n  CKA_CHECK_VALUE: '0xc6a13b'\n  \
CKA_KEY_TYPE: CKK_AES\n  CKA_ID: '0x0a1b'\n  CKA_START_DATE: 0x\n  CKA_END_DATE: 0x\n  \
CKA_SENSITIVE: true\n  CKA_ENCRYPT: true\n  CKA_DECRYPT: true\n  CKA_WRAP: false\n  \
CKA_UNWRAP: false\n  CKA_SIGN: true\n  CKA_VERIFY: true\n  CKA_DERIVE: false\n  \
CKA_VALUE_LEN: 16\n  CKA_EXTRACTABLE: false\n  CKA_LOCAL: false\n  CKA_NEVER_EXTRACTABLE: false\n  \
CKA_ALWAYS_SENSITIVE: false\n  CKA_KEY_GEN_MECHANISM: -1\n  CKA_MODIFIABLE: true\n  \
CKA_COPYABLE: true\n  CKA_DESTROYABLE: true\n  CKA_WRAP_WITH_TRUSTED: false\n";

struct Session {
    ctx: Rc<AppContext>,
    io: Rc<ScriptedIo>,
    editor: Rc<SpyEditor>,
    provider: Rc<Pkcs11Provider>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl Session {
    /// `answers`: the delete confirmations ("y" each).
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
        let editor = Rc::new(SpyEditor::new());
        let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
            .providers(registry)
            .editor(Rc::clone(&editor) as Rc<dyn TemplateEditor>)
            .build();
        let session = Self {
            ctx,
            io,
            editor,
            provider,
            _lock: lock,
        };
        session.run(&format!(
            "login hsm {} --pin {}",
            token.token_label, token.user_pin
        ));
        session
    }
    fn run(&self, line: &str) {
        if let Err(err) = run_line(&self.ctx, line) {
            panic!("{line}: {} ({:?})", err.message, err.hint);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.provider.shutdown();
    }
}

#[test]
fn test_key_template_dump_and_reseed_softhsm() {
    // §5.16 round trip on a real token: dump a generated key's complete template to a
    // file, then seed a second generate's editor from that file.
    let label = unique_label();
    let second = format!("{}-reseed", label.as_str());
    let dir = tempfile::tempdir().unwrap();
    let dump_path = dir.path().join("tpl.yaml");
    let s = Session::new(&["y", "y"]);
    s.run(&format!(
        "generate hsm aes size=256 --label {}",
        label.as_str()
    ));
    s.run(&format!(
        "key template hsm:{} {}",
        label.as_str(),
        dump_path.display()
    ));
    s.run(&format!(
        "generate hsm aes size=256 --label {second} --template {}",
        dump_path.display()
    ));
    s.run(&format!("delete hsm:{}", label.as_str()));
    s.run(&format!("delete hsm:{second}"));

    let raw = yaml::parse(&std::fs::read_to_string(&dump_path).unwrap()).unwrap();
    let section = &raw["aes"];
    // symbolic values (§5.16)
    assert_eq!(section["CKA_CLASS"], Value::String("CKO_SECRET_KEY".into()));
    assert_eq!(section["CKA_KEY_TYPE"], Value::String("CKK_AES".into()));
    assert_eq!(section["CKA_LABEL"], Value::String(label.as_str().into()));
    assert_eq!(section["CKA_TOKEN"], Value::Bool(true));
    // §7 default template applied
    assert_eq!(section["CKA_SENSITIVE"], Value::Bool(true));
    // sensitive key → material refused, skipped
    assert!(section.get("CKA_VALUE").is_none());
    // a generated key's mechanism is CKM_AES_KEY_GEN
    assert_eq!(
        yaml::as_int(&section["CKA_KEY_GEN_MECHANISM"]),
        Some(0x1080)
    );
    let text = s.io.text();
    assert!(text.contains("wrote aes template"), "{text}");
    assert!(text.contains(&format!("generated hsm:{second}")), "{text}");
    assert!(!text.contains("key material"), "{text}");

    // the second editor was seeded from the file: identity + read-only rows disabled
    let seeds = s.editor.seeds();
    let seed = seeds.last().unwrap();
    for name in [
        "CKA_LABEL",
        "CKA_ID",
        "CKA_LOCAL",
        "CKA_KEY_GEN_MECHANISM",
        "CKA_VALUE_LEN",
    ] {
        assert!(!seed.get(name).unwrap().enabled, "{name}");
    }
    assert!(seed.get("CKA_SENSITIVE").unwrap().enabled);
}

#[test]
fn r2_dump_of_a_c2_style_import_matches_c2_and_c2_dump_seeds_r2_softhsm() {
    let label = unique_label();
    let dir = tempfile::tempdir().unwrap();
    let r2_path = dir.path().join("r2.yaml");
    let c2_path = dir.path().join("c2.yaml");
    let s = Session::new(&["y", "y"]);
    // the object c2 dumped: same material, id and (default) template
    s.run(&format!(
        "load hsm aes 000102030405060708090a0b0c0d0e0f --label {} --id 0a1b",
        label.as_str()
    ));
    s.run(&format!(
        "key template hsm:{} {}",
        label.as_str(),
        r2_path.display()
    ));
    let expected = C2_IMPORTED_AES
        .replace(
            "CKA_LABEL: imp\n",
            &format!("CKA_LABEL: {}\n", label.as_str()),
        )
        // §11 D18: c2 wrote PyKCS11's signed C long
        .replace(
            "CKA_KEY_GEN_MECHANISM: -1",
            "CKA_KEY_GEN_MECHANISM: 18446744073709551615",
        );
    assert_eq!(std::fs::read_to_string(&r2_path).unwrap(), expected);

    // c2's own dump (with its `-1`) seeds an r2 generate
    std::fs::write(&c2_path, C2_IMPORTED_AES).unwrap();
    let seeded = format!("{}-c2", label.as_str());
    s.run(&format!(
        "generate hsm aes size=128 --label {seeded} --template {}",
        c2_path.display()
    ));
    let seeds = s.editor.seeds();
    let seed = seeds.last().unwrap();
    let mech = seed.get("CKA_KEY_GEN_MECHANISM").unwrap();
    assert_eq!(mech.value, AttrValue::Ulong(u64::MAX));
    assert!(!mech.enabled);
    assert!(s.io.text().contains(&format!("generated hsm:{seeded}")));
    s.run(&format!("delete hsm:{}", label.as_str()));
    s.run(&format!("delete hsm:{seeded}"));
}
