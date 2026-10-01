// R0 skeleton — owner R3 (generated from spec §4)
// ---- spec §4.6.2 block 0
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass};
pub use r2_core::params::{ParamKind, ParamSpec, ParamStruct, ParamValue, Params, Verb};
use r2_provider::MechanismInvocation;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationSpec {
    /// "<algo>.<verb>.<mode>", e.g. "aes.encrypt.gcm".
    pub id: String,
    pub verb: Verb,
    pub algorithm: KeyAlgorithm,
    /// CERTIFICATE is a member wherever PUBLIC is (§4.3).
    pub key_classes: BTreeSet<KeyClass>,
    /// Canonical mechanism name (§4.6.5) or a custom mechanism id.
    pub mechanism: String,
    /// Typed at the prompt: "gcm", "oaep", "ecdsa".
    pub cli_name: String,
    /// Human description (`ops` table, select menus).
    pub label: String,
    /// Excludes the payload (fixed per verb: encrypt/decrypt/sign take `data`, verify takes
    /// `data` + `signature`, derive takes none).
    pub params: Vec<ParamSpec>,
    /// None = any.
    pub provider_types: Option<BTreeSet<String>>,
    /// Restrict to named instances.
    pub providers: Option<BTreeSet<String>>,
    /// Restrict to KeyInfo.curve values (ec.derive.x25519 binds to x25519 keys only).
    pub curves: Option<BTreeSet<Curve>>,
    /// Custom mechanisms: vendor CKM code.
    pub raw_ckm: Option<u64>,
    pub param_struct: ParamStruct,
}
impl OperationSpec {
    /// The command-layer copy (§4.6): mechanism, params, raw_ckm, param_struct, and
    /// raw_param_bytes = params["mechparam"] bytes when param_struct == Raw.
    pub fn invocation(&self, params: Params) -> MechanismInvocation {
        let _ = params;
        unimplemented!("R3")
    }
    pub fn param(&self, name: &str) -> Option<&ParamSpec> {
        let _ = name;
        unimplemented!("R3")
    }
    /// The mirror rule: same cli_name/mechanism/params; id with `.{verb}.` swapped (first
    /// occurrence), the new verb and label, and `key_classes` replaced when given.
    pub fn mirrored(
        &self,
        verb: Verb,
        label: &str,
        key_classes: Option<BTreeSet<KeyClass>>,
    ) -> OperationSpec {
        let _ = (verb, label, key_classes);
        unimplemented!("R3")
    }
}
