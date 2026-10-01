// R0 skeleton — owner R10 (generated from spec §4)
use r2_config::model::AppConfig;
use r2_core::io::{ConsoleIo, TemplateEditor};
use std::rc::Rc;

/// The §5.12 checklist editor over the loaded configuration (it reads
/// `config.templates.custom_attributes`). Its mini-REPL line is read with
/// `io.prompt(&ParamSpec::str("template", "template> "))`.
/// R0 stub body (mandated): `Rc::new(r2_core::io::IdentityTemplateEditor)` — the r2
/// equivalent of c2's lazy-import identity fallback, so R7's bootstrap is correct on both
/// sides of R10's merge.
pub fn create_template_editor(io: Rc<dyn ConsoleIo>, config: &AppConfig) -> Rc<dyn TemplateEditor> {
    let _ = (io, config);
    Rc::new(r2_core::io::IdentityTemplateEditor)
}
