// R0 skeleton — owner R5a (generated from spec §4)
#![deny(unsafe_code)]
mod attributes;
mod backend;
mod capability;
pub mod catalog;
mod ckr;
mod env;
mod mechanisms;
mod provider;
pub mod softhsm;
#[cfg(test)]
mod tests;

pub use provider::Pkcs11Provider;
