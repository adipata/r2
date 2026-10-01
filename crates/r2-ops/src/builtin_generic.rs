// R0 skeleton — owner R3 (generated from spec §4)
use r2_core::error::Result;

use crate::registry::OperationRegistry;

pub fn register_builtin(reg: &mut OperationRegistry) -> Result<()> {
    let _ = reg;
    Err(r2_core::ConsoleError::not_implemented("R3"))
}
