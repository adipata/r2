// Console test support (spec §4.10.6; owner R7) — c2's per-file `make_ctx` helpers
// (tests/unit/console/conftest.py) and `_run` helpers, consolidated. cfg(test) only.
use std::path::PathBuf;
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::loader::config_from_yaml;
use r2_config::model::{AppConfig, CONFIG_SECTIONS, LoadedConfig};
use r2_core::io::{ConsoleIo, TemplateEditor};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_ops::build_operation_registry;
use r2_provider::{Provider, ProviderRegistry};
use r2_testkit::FakeProvider;

use crate::commands::all_commands;
use crate::context::AppContext;
use crate::repl::{Flow, dispatch};
use crate::template_editor::create_template_editor;

/// DEFAULTS_YAML deep-merged with `overrides_yaml` (§4.8 rules); panics on a config error.
pub fn make_config(overrides_yaml: Option<&str>) -> AppConfig {
    match config_from_yaml(overrides_yaml) {
        Ok(config) => config,
        Err(err) => panic!("make_config: {err:?}"),
    }
}
/// origins None → every CONFIG_SECTIONS entry "default".
pub fn make_loaded(
    config: AppConfig,
    source_path: Option<PathBuf>,
    origins: Option<IndexMap<String, String>>,
) -> LoadedConfig {
    let origins = origins.unwrap_or_else(|| {
        CONFIG_SECTIONS
            .iter()
            .map(|section| ((*section).to_owned(), "default".to_owned()))
            .collect()
    });
    LoadedConfig {
        config,
        source_path,
        origins,
    }
}
/// "mem" = FakeProvider (memory) holding AES key "aeskey" (16 × 0x01); "hsm" =
/// FakeProvider presenting "pkcs11" (logged in, empty).
pub fn make_providers() -> ProviderRegistry {
    let registry = ProviderRegistry::new();
    let mem = FakeProvider::new("mem");
    if let Err(err) = mem.import_key(
        &KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![0x01; 16]),
        "aeskey",
        None,
        None,
    ) {
        panic!("make_providers: {err:?}");
    }
    let hsm = FakeProvider::new("hsm").with_type_name("pkcs11");
    for provider in [Rc::new(mem) as Rc<dyn Provider>, Rc::new(hsm)] {
        if let Err(err) = registry.register(provider) {
            panic!("make_providers: {err:?}");
        }
    }
    registry
}

/// Fully wired AppContext over doubles (c2's per-file `make_ctx` helpers, consolidated).
pub struct CtxBuilder {
    io: Rc<dyn ConsoleIo>,
    config: Option<AppConfig>,
    providers: Option<ProviderRegistry>,
    source_path: Option<PathBuf>,
    origins: Option<IndexMap<String, String>>,
    editor: Option<Rc<dyn TemplateEditor>>,
}
impl CtxBuilder {
    /// Defaults: make_config(None), make_providers(), build_operation_registry(custom),
    /// create_template_editor(io, &config), origins all "default", no source path.
    pub fn new(io: Rc<dyn ConsoleIo>) -> Self {
        Self {
            io,
            config: None,
            providers: None,
            source_path: None,
            origins: None,
            editor: None,
        }
    }
    pub fn config(self, config: AppConfig) -> Self {
        Self {
            config: Some(config),
            ..self
        }
    }
    pub fn providers(self, providers: ProviderRegistry) -> Self {
        Self {
            providers: Some(providers),
            ..self
        }
    }
    pub fn source_path(self, path: PathBuf) -> Self {
        Self {
            source_path: Some(path),
            ..self
        }
    }
    pub fn origins(self, origins: IndexMap<String, String>) -> Self {
        Self {
            origins: Some(origins),
            ..self
        }
    }
    pub fn editor(self, editor: Rc<dyn TemplateEditor>) -> Self {
        Self {
            editor: Some(editor),
            ..self
        }
    }
    pub fn build(self) -> Rc<AppContext> {
        let config = self.config.unwrap_or_else(|| make_config(None));
        let operations = match build_operation_registry(&config.custom_mechanisms) {
            Ok(operations) => operations,
            Err(err) => panic!("CtxBuilder: {err:?}"),
        };
        let template_editor = self
            .editor
            .unwrap_or_else(|| create_template_editor(Rc::clone(&self.io), &config));
        Rc::new(AppContext {
            config: Rc::new(make_loaded(config, self.source_path, self.origins)),
            providers: self.providers.unwrap_or_else(make_providers),
            operations,
            io: self.io,
            template_editor,
        })
    }
}

/// `repl::dispatch(ctx, &all_commands()?, line)` — tokenize, bind and run exactly as the
/// REPL, without rendering (c2's per-file `_run` helpers).
pub fn run_line(ctx: &AppContext, line: &str) -> r2_core::Result<Flow> {
    dispatch(ctx, &*all_commands()?, line)
}
