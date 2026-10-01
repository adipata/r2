// R0 skeleton — owner R2 (generated from spec §4)
// ---- spec §4.8.5 block 0
use r2_core::error::Result;
pub use serde_yaml_ng::{Mapping, Number, Value};

/// Load one YAML document with PyYAML `safe_load` semantics (§4.8.4). Err = Generic whose
/// message is the parser's text; callers embed `err.message` in their own c2 message
/// ("invalid YAML in config file {path}: {text}", "invalid YAML in template file {path}:
/// {text}", …) with their own kind.
pub fn parse(text: &str) -> Result<Value> {
    let _ = text;
    Err(r2_core::ConsoleError::not_implemented("R2"))
}
/// PyYAML `safe_dump(sort_keys=False, default_flow_style=False)` port (§4.8.4); trailing "\n".
pub fn dump(value: &Value) -> String {
    let _ = value;
    unimplemented!("R2")
}
/// The integer of an int `Number` (i64/u64), else None — never coerces strings or bools
/// (c2 `_as_int`: `isinstance(v, int) and not isinstance(v, bool)`).
pub fn as_int(value: &Value) -> Option<i128> {
    let _ = value;
    unimplemented!("R2")
}
/// Python type name of the value PyYAML produced ("dict", "list", "str", "int", "float",
/// "bool", "NoneType", and for `Value::Tagged` `!!timestamp` "date"/"datetime", `!!binary`
/// "bytes").
pub fn python_type_name(value: &Value) -> &'static str {
    let _ = value;
    unimplemented!("R2")
}
