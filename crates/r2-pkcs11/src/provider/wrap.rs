//! wrap/unwrap: the KWP preference, the AES-CBC/AES-GCM/RSA-PKCS1 KEK branches, the
//! CKA_VALUE_LEN inject-and-retry and the software-OAEP fallbacks (spec §5.4, §5.5; c2
//! provider.py `_wrap_mechanism`, `wrap_key`, `unwrap_key`, `_unwrap_value_len`).
//! Owner R5b.
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::{param_int, param_str};
use r2_provider::*;
use zeroize::Zeroizing;

use super::crypto::{oaep_params, oaep_params_rejected, param_bytes};
use super::objects::{cka, material_attrs, reject_certificate, reject_non_key};
use super::{OResult, OpError, Pkcs11Provider};
use crate::attributes::ulong_bytes;
use crate::backend::{BackendError, MechSpec, RawAttr};
use crate::ckr::{self, rv};
use crate::mechanisms::{self as mechs, oaep_decode, unwrap_value_len};

/// CKRs meaning the auto-injected CKA_VALUE_LEN row upset the token — the unwrap is
/// retried once without it (c2 `_VALUE_LEN_REJECTED`, ported verbatim; SoftHSM's
/// CKR_ATTRIBUTE_READ_ONLY is deliberately not in the set, §4.5.6 field note).
fn value_len_rejected(err: &BackendError) -> bool {
    matches!(
        ckr::code_of(err),
        Some(
            rv::CKR_ATTRIBUTE_TYPE_INVALID
                | rv::CKR_ATTRIBUTE_VALUE_INVALID
                | rv::CKR_TEMPLATE_INCONSISTENT
        )
    )
}

impl Pkcs11Provider {
    /// c2 `_wrap_mechanism`: the MechSpec of a wrap/unwrap invocation.
    pub(crate) fn wrap_mechanism(&self, mech: &MechanismInvocation) -> OResult<MechSpec> {
        let name = mech.mechanism.as_str();
        if mech.raw_ckm.is_some() {
            return mechs::pack_custom(mech);
        }
        let require =
            |ckm: &str, context: &str| -> OResult<u64> { Ok(self.require_ckm(ckm, context)?) };
        match name {
            mechanism::AES_KEY_WRAP => Ok(mechs::simple(require("CKM_AES_KEY_WRAP", name)?, None)),
            mechanism::AES_KEY_WRAP_PAD => {
                // Prefer CKM_AES_KEY_WRAP_KWP: unambiguously RFC 5649. CKM_AES_KEY_WRAP_PAD is
                // RFC 5649 on some tokens (SoftHSM/OpenSSL) but RFC 3394 over a PKCS#7-padded
                // payload on others (e.g. Utimaco) — §5.5 dialect note.
                if self.has_ckm("CKM_AES_KEY_WRAP_KWP")
                    && let Some(kwp) = crate::catalog::symbol_value("CKM_AES_KEY_WRAP_KWP")
                {
                    return Ok(mechs::simple(kwp, None));
                }
                Ok(mechs::simple(require("CKM_AES_KEY_WRAP_PAD", name)?, None))
            }
            mechanism::AES_CBC => {
                let iv = param_bytes(&mech.params, "iv", None)?;
                let padding = param_str(&mech.params, "padding", "pkcs7")?;
                let ckm_name = if padding == "pkcs7" {
                    "CKM_AES_CBC_PAD"
                } else {
                    "CKM_AES_CBC"
                };
                let ckm = require(ckm_name, &format!("{name} padding={padding}"))?;
                Ok(mechs::simple(ckm, Some(&iv)))
            }
            mechanism::AES_GCM => {
                require("CKM_AES_GCM", name)?;
                mechs::gcm(
                    &param_bytes(&mech.params, "iv", None)?,
                    &param_bytes(&mech.params, "aad", Some(b""))?,
                    param_int(&mech.params, "tag_bits", 128)?,
                    None,
                )
            }
            mechanism::RSA_OAEP => {
                let (hash_name, mgf_hash, label) = oaep_params(&mech.params)?;
                require("CKM_RSA_PKCS_OAEP", name)?;
                Ok(mechs::oaep(&hash_name, &mgf_hash, &label, None)?)
            }
            mechanism::RSA_PKCS1 => Ok(mechs::simple(require("CKM_RSA_PKCS", name)?, None)),
            _ => {
                Err(ConsoleError::unsupported(format!("mechanism {name} cannot wrap keys")).into())
            }
        }
    }

    pub(crate) fn wrap_key_impl(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        target: &KeyInfo,
        options: &WrapOptions,
    ) -> Result<Vec<u8>> {
        let _ = options; // no c2 call site passes options (§4.5.1)
        self.check_advertised(&mech.mechanism)?;
        reject_non_key(wrapping_key, "wrap_key")?;
        reject_non_key(target, "wrap_key (target)")?;
        let result = self.op(&format!("wrap with {}", mech.mechanism), || {
            let target_handle = self.find_handle(target)?;
            self.with_public_use_handle(wrapping_key, |wrap_handle| {
                let built = self.wrap_mechanism(mech)?;
                match self.backend().wrap_key(&built, wrap_handle, target_handle) {
                    Ok(blob) => Ok(blob),
                    Err(err)
                        if mech.mechanism != mechanism::RSA_OAEP || !oaep_params_rejected(&err) =>
                    {
                        Err(err.into())
                    }
                    Err(_) => {
                        // OAEP parameter set rejected (SoftHSM: SHA-1 only): software OAEP
                        // over the target's plain value — only when it is plain-readable
                        // (§5.5 exportable semantics)
                        let value = self
                            .read_attr(target_handle, cka::VALUE)?
                            .filter(|v| !v.is_empty());
                        let Some(value) = value else {
                            let hash_name = param_str(&mech.params, "hash", "sha256")?;
                            return Err(ConsoleError::unsupported(format!(
                                "token rejects RSA-OAEP({hash_name}) wrapping parameters and \
                                 the target is not plain-readable"
                            ))
                            .with_hint("use hash=sha1 on this token, or an AES key-wrap route")
                            .into());
                        };
                        let (hash_name, mgf_hash, label) = oaep_params(&mech.params)?;
                        tracing::info!(
                            target: "r2::pkcs11",
                            "{}: OAEP wrap fallback in software for {}",
                            self.provider_name(),
                            target.key_ref.display()
                        );
                        self.software_oaep(wrap_handle, &value, &hash_name, &mgf_hash, &label)
                    }
                }
            })
        })?;
        tracing::info!(
            target: "r2::pkcs11",
            "{}: wrapped {} under {} ({} bytes)",
            self.provider_name(),
            target.key_ref.display(),
            wrapping_key.key_ref.display(),
            result.len()
        );
        Ok(result)
    }

    pub(crate) fn unwrap_key_impl(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        wrapped: &[u8],
        request: &UnwrapRequest,
    ) -> Result<KeyInfo> {
        self.check_advertised(&mech.mechanism)?;
        reject_certificate(wrapping_key, "unwrap_key")?;
        reject_non_key(wrapping_key, "unwrap_key")?;
        let result_class = request.result_class;
        let result_algorithm = request.result_algorithm;
        if matches!(result_algorithm, KeyAlgorithm::None | KeyAlgorithm::Other) {
            return Err(ConsoleError::param(
                format!("cannot unwrap into {} keys", result_algorithm.as_str()),
                "result_algorithm",
            ));
        }
        let template = request.template.as_ref();
        let (label, resolved_id) = self.resolve_identity(
            &request.label,
            request.key_id.as_deref(),
            &[template],
            Some(result_class),
        )?;
        let attrs = self.build_template(
            template,
            result_class,
            Some(result_algorithm),
            &label,
            resolved_id.as_deref(),
            &[],
            &[],
            true,
        )?;
        let value_len = unwrap_value_len(
            mech,
            wrapped.len(),
            result_class,
            result_algorithm,
            template,
        )?;
        let attrs_with_len: Option<Vec<RawAttr>> = match value_len {
            Some(length) => {
                let encoded = ulong_bytes(length).map_err(|err| self.translate(err, "unwrap"))?;
                let mut with = attrs.clone();
                with.push((cka::VALUE_LEN, Zeroizing::new(encoded)));
                Some(with)
            }
            None => None,
        };
        self.op(&format!("unwrap with {}", mech.mechanism), || {
            self.ensure_identity_free(&[result_class], &label, resolved_id.as_deref())?;
            let wrap_handle = self.find_handle(wrapping_key)?;
            let first = attrs_with_len.as_deref().unwrap_or(&attrs);
            let built = self.wrap_mechanism(mech)?;
            let handle = match self.backend().unwrap_key(&built, wrap_handle, wrapped, first) {
                Ok(handle) => handle,
                Err(err) if attrs_with_len.is_some() && value_len_rejected(&err) => {
                    // §5.4: the auto-injected CKA_VALUE_LEN upset this token — retry once
                    // without it before giving up
                    tracing::info!(
                        target: "r2::pkcs11",
                        "{}: token rejected the injected CKA_VALUE_LEN — retrying without",
                        self.provider_name()
                    );
                    let built = self.wrap_mechanism(mech)?;
                    self.backend().unwrap_key(&built, wrap_handle, wrapped, &attrs)?
                }
                Err(err)
                    if mech.mechanism != mechanism::RSA_OAEP || !oaep_params_rejected(&err) =>
                {
                    return Err(err.into());
                }
                Err(_) => {
                    // raw RSA + software OAEP decode, then create the recovered material
                    // under the same template (§5.8 fallback)
                    let (hash_name, mgf_hash, oaep_label) = oaep_params(&mech.params)?;
                    tracing::info!(target: "r2::pkcs11", "{}: OAEP unwrap fallback via raw RSA", self.provider_name());
                    let raw = self.require_ckm("CKM_RSA_X_509", "RSA-OAEP unwrap fallback")?;
                    let em = self
                        .backend()
                        .decrypt(&mechs::simple(raw, None), wrap_handle, wrapped)?;
                    let k = self.modulus_len(wrap_handle, wrapping_key)?;
                    let mut padded = Zeroizing::new(vec![0u8; k.saturating_sub(em.len())]);
                    padded.extend_from_slice(&em);
                    let value = oaep_decode(&padded, &hash_name, &mgf_hash, &oaep_label)?;
                    let material: Vec<RawAttr> = if result_class == KeyClass::Secret {
                        vec![(cka::VALUE, value)]
                    } else {
                        material_attrs(&KeyMaterial::new(
                            result_algorithm,
                            result_class,
                            value.to_vec(),
                        ))?
                    };
                    let mut full = attrs.clone();
                    full.extend(material);
                    self.backend().create_object(&full)?
                }
            };
            let info = self.key_info(handle, result_class)?.ok_or_else(|| {
                OpError::Console(ConsoleError::key_not_found(format!(
                    "unwrapped key '{label}' vanished"
                )))
            })?;
            tracing::info!(
                target: "r2::pkcs11",
                "{}: unwrapped {}-byte blob into {}",
                self.provider_name(),
                wrapped.len(),
                info.key_ref.display()
            );
            Ok(info)
        })
    }
}
