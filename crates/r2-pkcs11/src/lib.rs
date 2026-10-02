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

/// `CK_ULONG` (and its aliases CK_RV, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, …) → u64.
/// A widening everywhere: `CK_ULONG` is u64 on Unix but u32 on Windows (§4.5.5), so the
/// conversion stays and clippy's same-type lint is silenced at this one site.
#[allow(clippy::useless_conversion)]
pub(crate) fn ulong_to_u64(value: cryptoki_sys::CK_ULONG) -> u64 {
    u64::from(value)
}
