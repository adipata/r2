// R0 skeleton — owner R5b (generated from spec §4)
use r2_core::Result;
use r2_core::keys::KeyInfo;
use r2_provider::*;

use super::Pkcs11Provider;

impl Pkcs11Provider {
    pub(crate) fn wrap_key_impl(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        target: &KeyInfo,
        options: &WrapOptions,
    ) -> Result<Vec<u8>> {
        let _ = (wrapping_key, mech, target, options);
        Err(r2_core::ConsoleError::not_implemented("R5b"))
    }
    pub(crate) fn unwrap_key_impl(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        wrapped: &[u8],
        request: &UnwrapRequest,
    ) -> Result<KeyInfo> {
        let _ = (wrapping_key, mech, wrapped, request);
        Err(r2_core::ConsoleError::not_implemented("R5b"))
    }
}
