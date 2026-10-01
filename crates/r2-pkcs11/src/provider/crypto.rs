// R0 skeleton — owner R5b (generated from spec §4)
use r2_core::Result;
use r2_core::keys::KeyInfo;
use r2_provider::*;

use super::Pkcs11Provider;

impl Pkcs11Provider {
    pub(crate) fn encrypt_impl(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let _ = (key, mech, data);
        Err(r2_core::ConsoleError::not_implemented("R5b"))
    }
    pub(crate) fn decrypt_impl(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let _ = (key, mech, data);
        Err(r2_core::ConsoleError::not_implemented("R5b"))
    }
    pub(crate) fn sign_impl(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let _ = (key, mech, data);
        Err(r2_core::ConsoleError::not_implemented("R5b"))
    }
    pub(crate) fn verify_impl(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let _ = (key, mech, data, signature);
        Err(r2_core::ConsoleError::not_implemented("R5b"))
    }
    pub(crate) fn derive_impl(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
    ) -> Result<DeriveResult> {
        let _ = (key, mech);
        Err(r2_core::ConsoleError::not_implemented("R5b"))
    }
}
