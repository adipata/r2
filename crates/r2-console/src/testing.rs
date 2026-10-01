#![allow(dead_code)]
// R0 skeleton — owner R7 (generated from spec §4)
// ---- spec §4.10.6 block 0
use indexmap::IndexMap;
use r2_config::model::{AppConfig, LoadedConfig};
use r2_core::io::{ConsoleIo, TemplateEditor};
use r2_provider::ProviderRegistry;
use std::path::PathBuf;
use std::rc::Rc;

use crate::context::AppContext;
use crate::repl::Flow;

/// DEFAULTS_YAML deep-merged with `overrides_yaml` (§4.8 rules); panics on a config error.
pub fn make_config(overrides_yaml: Option<&str>) -> AppConfig {
    let _ = overrides_yaml;
    unimplemented!("R7")
}
/// origins None → every CONFIG_SECTIONS entry "default".
pub fn make_loaded(
    config: AppConfig,
    source_path: Option<PathBuf>,
    origins: Option<IndexMap<String, String>>,
) -> LoadedConfig {
    let _ = (config, source_path, origins);
    unimplemented!("R7")
}
/// "mem" = FakeProvider (memory) holding AES key "aeskey" (16 × 0x01); "hsm" =
/// FakeProvider presenting "pkcs11" (logged in, empty).
pub fn make_providers() -> ProviderRegistry {
    unimplemented!("R7")
}

/// Fully wired AppContext over doubles (c2's per-file `make_ctx` helpers, consolidated).
pub struct CtxBuilder {}
impl CtxBuilder {
    /// Defaults: make_config(None), make_providers(), build_operation_registry(custom),
    /// create_template_editor(io, &config), origins all "default", no source path.
    pub fn new(io: Rc<dyn ConsoleIo>) -> Self {
        let _ = io;
        unimplemented!("R7")
    }
    pub fn config(self, config: AppConfig) -> Self {
        let _ = config;
        unimplemented!("R7")
    }
    pub fn providers(self, providers: ProviderRegistry) -> Self {
        let _ = providers;
        unimplemented!("R7")
    }
    pub fn source_path(self, path: PathBuf) -> Self {
        let _ = path;
        unimplemented!("R7")
    }
    pub fn origins(self, origins: IndexMap<String, String>) -> Self {
        let _ = origins;
        unimplemented!("R7")
    }
    pub fn editor(self, editor: Rc<dyn TemplateEditor>) -> Self {
        let _ = editor;
        unimplemented!("R7")
    }
    pub fn build(self) -> Rc<AppContext> {
        unimplemented!("R7")
    }
}

/// `repl::dispatch(ctx, &all_commands()?, line)` — tokenize, bind and run exactly as the
/// REPL, without rendering (c2's per-file `_run` helpers).
pub fn run_line(ctx: &AppContext, line: &str) -> r2_core::Result<Flow> {
    let _ = (ctx, line);
    Err(r2_core::ConsoleError::not_implemented("R7"))
}
