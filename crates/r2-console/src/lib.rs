// R0 skeleton — owner R7 (generated from spec §4)
#![forbid(unsafe_code)]
pub mod cmdutil;
pub mod commands;
pub mod completer;
pub mod context;
pub mod io;
pub mod parser;
pub mod render;
pub mod repl;
pub mod template_editor;
#[cfg(test)]
pub(crate) mod testing;
pub mod wizard;

pub use commands::Command;
pub use context::AppContext;
pub use parser::{BoundArgs, OptValue, Token};
pub use repl::{CommandTable, Flow, dispatch, run_repl};

#[cfg(test)]
mod tests {
    include!(concat!(env!("OUT_DIR"), "/test_modules.rs"));
}
