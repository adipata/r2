// R0 skeleton — owner R3 (generated from spec §4)
#![forbid(unsafe_code)]
pub mod builtin_aes;
pub mod builtin_ec;
pub mod builtin_generic;
pub mod builtin_rsa;
pub mod custom;
pub mod model;
pub mod params;
pub mod registry;

pub use model::{OperationSpec, ParamKind, ParamSpec, ParamStruct, ParamValue, Params, Verb};
pub use params::ParamResolver;
pub use registry::{OperationRegistry, build_operation_registry, register_builtins, suggest_hint};
