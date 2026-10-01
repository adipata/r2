#![allow(dead_code)]
// R0 skeleton — owner R7 (generated from spec §4)
// ---- spec §4.6.4 block 0
use indexmap::IndexMap;
use r2_core::error::Result;
use r2_core::io::ConsoleIo;
use r2_provider::ProviderRegistry;

use crate::model::{OperationSpec, ParamSpec, ParamValue, Params};

pub struct ParamResolver<'a> {
    io: &'a dyn ConsoleIo,
    providers: &'a ProviderRegistry,
}
impl<'a> ParamResolver<'a> {
    pub fn new(io: &'a dyn ConsoleIo, providers: &'a ProviderRegistry) -> Self {
        let _ = (io, providers);
        unimplemented!("R7")
    }
    /// Algorithm below. `given` = BoundArgs.named (name=value tokens, line order).
    pub fn resolve(
        &self,
        spec: &OperationSpec,
        given: &IndexMap<String, String>,
    ) -> Result<Params> {
        let _ = (spec, given);
        Err(r2_core::ConsoleError::not_implemented("R7"))
    }
    /// Parse + validate one textual value per its ParamSpec (rules below).
    pub fn parse_value(&self, param: &ParamSpec, text: &str) -> Result<ParamValue> {
        let _ = (param, text);
        Err(r2_core::ConsoleError::not_implemented("R7"))
    }
}
