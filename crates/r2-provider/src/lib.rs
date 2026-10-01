// r2-provider crate root (spec §4.5, owner R3).
#![forbid(unsafe_code)]
pub mod lookup;
pub mod mechanism;
pub mod provider;
pub mod registry;
pub mod rsa_raw;
pub mod types;

pub use provider::{Provider, TokenInit};
pub use registry::ProviderRegistry;
pub use types::*;
