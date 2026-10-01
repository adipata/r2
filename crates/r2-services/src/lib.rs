// r2-services crate root (owner R0, spec §4.1.1; modules owned by R8, R10, R14, R15).
#![forbid(unsafe_code)]
pub mod certops;
pub mod keyexport;
pub mod keyload;
pub mod templatefile;
pub mod transfer;
pub mod wrapload;
