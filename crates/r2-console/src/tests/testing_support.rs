// `r2_console::testing` itself (spec §4.10.6; R7): the defaults every console loop's tests
// rely on.
use std::path::PathBuf;
use std::rc::Rc;

use r2_core::io::{ConsoleIo, TemplateEditor};
use r2_core::keys::KeyClass;
use r2_core::template::KeyTemplate;
use r2_provider::{AuthState, ProviderRegistry};
use r2_testkit::{RecordingEditor, ScriptedIo};

use crate::testing::{CtxBuilder, make_config, make_loaded, make_providers, run_line};

#[test]
fn make_providers_holds_mem_and_hsm() {
    let registry = make_providers();
    let names: Vec<String> = registry.all().iter().map(|p| p.name().to_owned()).collect();
    assert_eq!(names, ["mem", "hsm"]);
    let mem = registry.get("mem").unwrap();
    assert_eq!(mem.type_name(), "memory");
    let keys = mem.list_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key_ref.display(), "mem:aeskey");
    assert_eq!(keys[0].key_class, KeyClass::Secret);
    let exported = mem.export_key(&keys[0]).unwrap();
    assert_eq!(exported.data.as_slice(), [0x01; 16]);
    let hsm = registry.get("hsm").unwrap();
    assert_eq!(hsm.type_name(), "pkcs11");
    assert_eq!(hsm.status().auth, AuthState::LoggedIn);
    assert!(hsm.list_keys().unwrap().is_empty());
}

#[test]
fn make_config_merges_overrides_and_make_loaded_defaults_origins() {
    let config = make_config(Some("ui:\n  hex_width: 16\n"));
    assert_eq!(config.ui.hex_width, 16);
    assert_eq!(config.ui.hex_group, 2);
    let loaded = make_loaded(config.clone(), None, None);
    assert_eq!(loaded.origins.len(), 6);
    assert!(loaded.origins.values().all(|origin| origin == "default"));
    assert_eq!(loaded.source_path, None);
    assert_eq!(loaded.config, config);
}

#[test]
#[should_panic(expected = "make_config")]
fn make_config_panics_on_a_config_error() {
    let _ = make_config(Some("ui:\n  hex_width: 0\n"));
}

#[test]
fn ctx_builder_overrides() {
    let io = Rc::new(ScriptedIo::empty());
    let editor = Rc::new(RecordingEditor::new());
    let providers = ProviderRegistry::new();
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .config(make_config(Some("providers:\n  memory:\n    name: ram\n")))
        .providers(providers)
        .source_path(PathBuf::from("/x/r2.yaml"))
        .editor(Rc::clone(&editor) as Rc<dyn TemplateEditor>)
        .build();
    assert_eq!(ctx.cfg().providers.memory.name, "ram");
    assert!(ctx.providers.all().is_empty());
    assert_eq!(ctx.config.source_path, Some(PathBuf::from("/x/r2.yaml")));
    ctx.template_editor
        .edit(KeyTemplate::default(), "title")
        .unwrap();
    assert_eq!(editor.titles(), ["title"]);
    // defaults: the R10 factory (identity until R10 merges) and the builtin operations
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>).build();
    assert!(ctx.operations.get("aes.encrypt.gcm").is_ok());
    assert!(run_line(&ctx, "  ").is_ok());
}
