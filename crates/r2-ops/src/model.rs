// Operation model (spec §4.6.2, owner R3; c2 ops/model.py).
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
        let raw_param_bytes = if self.param_struct == ParamStruct::Raw {
            params
                .get("mechparam")
                .and_then(ParamValue::as_bytes)
                .map(<[u8]>::to_vec)
        } else {
            None
        };
        MechanismInvocation {
            mechanism: self.mechanism.clone(),
            params,
            raw_ckm: self.raw_ckm,
            param_struct: self.param_struct,
            raw_param_bytes,
        }
    }
    pub fn param(&self, name: &str) -> Option<&ParamSpec> {
        self.params.iter().find(|param| param.name == name)
    }
    /// The mirror rule: same cli_name/mechanism/params; id with `.{verb}.` swapped (first
    /// occurrence), the new verb and label, and `key_classes` replaced when given.
    pub fn mirrored(
        &self,
        verb: Verb,
        label: &str,
        key_classes: Option<BTreeSet<KeyClass>>,
    ) -> OperationSpec {
        let from = format!(".{}.", self.verb.as_str());
        let to = format!(".{}.", verb.as_str());
        OperationSpec {
            id: self.id.replacen(&from, &to, 1),
            verb,
            label: label.to_owned(),
            key_classes: key_classes.unwrap_or_else(|| self.key_classes.clone()),
            ..self.clone()
        }
    }
}

/// Crate-private builders shared by the builtin_* tables (c2 wrote each row as an
/// `OperationSpec(...)` literal; the defaults are the c2 dataclass defaults).
pub(crate) mod build {
    use std::collections::BTreeSet;

    use r2_core::keys::{KeyAlgorithm, KeyClass};

    use super::{OperationSpec, ParamKind, ParamSpec, ParamStruct, ParamValue, Verb};

    /// Registers `original`, then its §4.6 mirror (the c2 `_SPECS` order).
    pub(crate) fn register_with_mirror(
        reg: &mut crate::registry::OperationRegistry,
        original: OperationSpec,
        verb: Verb,
        label: &str,
        key_classes: Option<&[KeyClass]>,
    ) -> r2_core::error::Result<()> {
        let mirror = original.mirrored(verb, label, key_classes.map(classes));
        reg.register(original)?;
        reg.register(mirror)
    }

    pub(crate) fn classes(classes: &[KeyClass]) -> BTreeSet<KeyClass> {
        classes.iter().copied().collect()
    }

    /// A row with provider_types/providers/curves/raw_ckm None and param_struct None (the
    /// argument list mirrors the §4.6.6 table columns).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spec(
        id: &str,
        verb: Verb,
        algorithm: KeyAlgorithm,
        key_classes: &[KeyClass],
        mechanism: &str,
        cli_name: &str,
        label: &str,
        params: Vec<ParamSpec>,
    ) -> OperationSpec {
        OperationSpec {
            id: id.to_owned(),
            verb,
            algorithm,
            key_classes: classes(key_classes),
            mechanism: mechanism.to_owned(),
            cli_name: cli_name.to_owned(),
            label: label.to_owned(),
            params,
            provider_types: None,
            providers: None,
            curves: None,
            raw_ckm: None,
            param_struct: ParamStruct::None,
        }
    }

    /// Required BYTES param.
    pub(crate) fn bytes(name: &str, prompt: &str) -> ParamSpec {
        ParamSpec::new(name, ParamKind::Bytes, prompt)
    }

    /// Optional BYTES param defaulting to b"".
    pub(crate) fn bytes_empty(name: &str, prompt: &str) -> ParamSpec {
        bytes(name, prompt).optional(Some(ParamValue::Bytes(Vec::new())))
    }

    /// Optional ENUM param with an `Enum` default (§4.6.1: every ENUM value is `Enum`).
    pub(crate) fn choice(name: &str, prompt: &str, default: &str, choices: &[&str]) -> ParamSpec {
        ParamSpec::new(name, ParamKind::Enum, prompt)
            .optional(Some(ParamValue::Enum(default.to_owned())))
            .choices(choices)
    }

    /// Optional ENUM param mirroring an earlier param (`default_from`, no own default).
    pub(crate) fn mirror_choice(
        name: &str,
        prompt: &str,
        from: &str,
        choices: &[&str],
    ) -> ParamSpec {
        ParamSpec::new(name, ParamKind::Enum, prompt)
            .optional(None)
            .default_from(from)
            .choices(choices)
    }

    /// Optional INT param; `None` = c2's `default=None` (absent when not given).
    pub(crate) fn int(name: &str, prompt: &str, default: Option<i64>) -> ParamSpec {
        ParamSpec::new(name, ParamKind::Int, prompt).optional(default.map(ParamValue::Int))
    }
}
