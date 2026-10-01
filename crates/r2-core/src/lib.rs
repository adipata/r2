// r2-core crate root (owner R1; R0 wrote the module list).
#![forbid(unsafe_code)]
//! r2-core (spec §4.2–§4.4, §4.6.1, §4.7, §4.9.1/§4.9.2/§4.9.8).
pub mod catalog;
pub mod codec;
pub mod crypto;
pub mod datainput;
pub mod der;
pub mod error;
pub mod formats;
pub mod io;
pub mod keyparse;
pub mod keys;
pub mod params;
pub mod render;
pub mod runtime;
pub mod template;
pub mod text;
pub mod x509build;
pub mod x509info;

pub use crypto::{ct_eq, ensure_legacy_provider};
pub use error::{ConsoleError, ErrorKind, Result};
