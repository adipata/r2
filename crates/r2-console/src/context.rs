// AppContext (spec §4.9.4; owner R7) — c2 `console/repl.py` AppContext.
use r2_config::model::{AppConfig, LoadedConfig};
use r2_core::io::{ConsoleIo, TemplateEditor};
use r2_ops::OperationRegistry;
use r2_provider::ProviderRegistry;
use std::rc::Rc;

/// Built by r2-cli (or `testing::CtxBuilder`), passed to every command. `io` and
/// `template_editor` are `Rc` because the editor shares the IO. There is no logger field
/// (c2 `log: logging.Logger` → `tracing` macros, target "r2::…"), and `--debug` is a
/// parameter of `run_repl`, deliberately not a field.
pub struct AppContext {
    pub config: Rc<LoadedConfig>,
    pub providers: ProviderRegistry,
    pub operations: OperationRegistry,
    pub io: Rc<dyn ConsoleIo>,
    pub template_editor: Rc<dyn TemplateEditor>,
}
impl AppContext {
    /// `&self.config.config`.
    pub fn cfg(&self) -> &AppConfig {
        &self.config.config
    }
}
