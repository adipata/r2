//! encrypt / decrypt / sign / verify / derive with c2's software fallbacks (spec §5.8–§5.10;
//! c2 provider.py `_do_cipher`, `_rsa_oaep_cipher`, `_do_sign`, `_gmac`, `_pss_setup`,
//! `_do_verify`, `derive`, `_peer_to_raw_point`). Owner R5b.
use cryptoki_sys as sys;
use openssl::bn::BigNumContext;
use openssl::ec::PointConversionForm;
use openssl::pkey::{Id, PKey};
use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyRef};
use r2_core::params::{ParamValue, Params, param_int, param_str};
use r2_core::template::AttrValue;
use r2_provider::*;
use zeroize::Zeroizing;

use super::objects::{cka, cko, reject_certificate, reject_non_key};
use super::{OResult, OpError, Pkcs11Provider};
use crate::attributes::ulong_bytes;
use crate::backend::{BackendError, Ckr, MechSpec, RawAttr};
use crate::ckr::{self, rv};
use crate::mechanisms::{self as mechs, oaep_decode, reason, software_oaep_encrypt};

fn w(code: sys::CK_ULONG) -> u64 {
    crate::ulong_to_u64(code)
}

/// The CKR codes that trigger the software-OAEP fallback (c2 `_OAEP_PARAM_REJECTED`).
pub(crate) fn oaep_params_rejected(err: &BackendError) -> bool {
    matches!(
        ckr::code_of(err),
        Some(rv::CKR_ARGUMENTS_BAD | rv::CKR_MECHANISM_PARAM_INVALID)
    )
}

/// Template-rejection CKRs that trigger the §5.10 [U] resident-key retry (c2
/// `_DERIVE_TEMPLATE_REJECTED_CKRS`).
fn derive_template_rejected(err: &BackendError) -> bool {
    matches!(
        ckr::code_of(err),
        Some(
            rv::CKR_ATTRIBUTE_VALUE_INVALID
                | rv::CKR_ATTRIBUTE_TYPE_INVALID
                | rv::CKR_ATTRIBUTE_READ_ONLY
                | rv::CKR_TEMPLATE_INCONSISTENT
                | rv::CKR_TEMPLATE_INCOMPLETE
        )
    )
}

/// c2 `_param_bytes`: absent with no default → Param "missing parameter {name!r}";
/// a non-bytes value → Param "parameter {name!r} must be bytes".
pub(crate) fn param_bytes(params: &Params, name: &str, default: Option<&[u8]>) -> Result<Vec<u8>> {
    match params.get(name) {
        Some(ParamValue::Bytes(value)) => Ok(value.clone()),
        Some(_) => Err(ConsoleError::param(
            format!("parameter {} must be bytes", r2_core::text::py_repr(name)),
            name,
        )),
        None => default.map(<[u8]>::to_vec).ok_or_else(|| {
            ConsoleError::param(
                format!("missing parameter {}", r2_core::text::py_repr(name)),
                name,
            )
        }),
    }
}

/// c2 `_oaep_params`: (hash, mgf_hash = hash by default, label = b"" by default).
pub(crate) fn oaep_params(params: &Params) -> Result<(String, String, Vec<u8>)> {
    let hash_name = param_str(params, "hash", "sha256")?.to_string();
    let mgf_hash = param_str(params, "mgf_hash", &hash_name)?.to_string();
    let label = param_bytes(params, "label", Some(b""))?;
    Ok((hash_name, mgf_hash, label))
}

fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad = 16 - data.len() % 16;
    let mut out = data.to_vec();
    out.extend(std::iter::repeat_n(u8::try_from(pad).unwrap_or(16), pad));
    out
}

fn pkcs7_unpad(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let invalid = || ConsoleError::crypto("invalid PKCS7 padding in decrypted data");
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return Err(invalid());
    }
    let pad = usize::from(data[data.len() - 1]);
    if !(1..=16).contains(&pad)
        || data[data.len() - pad..]
            .iter()
            .any(|b| usize::from(*b) != pad)
    {
        return Err(invalid());
    }
    Ok(Zeroizing::new(data[..data.len() - pad].to_vec()))
}

/// Field size of a curve for the ECDH default length (c2 `_CURVE_FIELD_BYTES`).
fn curve_field_bytes(curve: Option<&Curve>) -> Option<u64> {
    match curve? {
        Curve::P256 | Curve::Ed25519 | Curve::X25519 => Some(32),
        Curve::P384 => Some(48),
        Curve::P521 => Some(66),
        Curve::Ed448 => Some(57),
        Curve::X448 => Some(56),
        Curve::Other(_) => None,
    }
}

fn curve_text(curve: Option<&Curve>) -> String {
    curve.map_or_else(|| "None".to_string(), |c| c.as_str().to_string())
}

impl Pkcs11Provider {
    /// One attribute read (refusals → None; other CKRs propagate).
    pub(crate) fn read_attr(&self, handle: u64, code: u64) -> OResult<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.backend().get_attr(handle, code)?)
    }

    /// c2 `_modulus_len`: from size_bits, else the CKA_MODULUS length (leading zeros
    /// stripped).
    pub(crate) fn modulus_len(&self, handle: u64, key: &KeyInfo) -> OResult<usize> {
        if let Some(bits) = key.size_bits.filter(|b| *b != 0) {
            return Ok(usize::try_from(bits.div_ceil(8)).unwrap_or(0));
        }
        let modulus = self
            .read_attr(handle, cka::MODULUS)?
            .filter(|m| !m.is_empty());
        let Some(modulus) = modulus else {
            return Err(ConsoleError::crypto("cannot determine RSA modulus size").into());
        };
        Ok(modulus.iter().skip_while(|b| **b == 0).count())
    }

    fn left_pad_to_modulus(
        &self,
        handle: u64,
        key: &KeyInfo,
        data: &[u8],
    ) -> OResult<Zeroizing<Vec<u8>>> {
        let k = self.modulus_len(handle, key)?;
        if data.len() > k {
            return Err(ConsoleError::param(
                format!(
                    "input ({} bytes) exceeds the RSA modulus length ({k} bytes)",
                    data.len()
                ),
                "data",
            )
            .into());
        }
        let mut out = Zeroizing::new(vec![0u8; k - data.len()]);
        out.extend_from_slice(data);
        Ok(out)
    }

    /// c2 `_read_public_numbers` → (modulus, exponent) bytes.
    fn public_numbers(&self, handle: u64) -> OResult<(Vec<u8>, Vec<u8>)> {
        let modulus = self
            .read_attr(handle, cka::MODULUS)?
            .filter(|v| !v.is_empty());
        let exponent = self
            .read_attr(handle, cka::PUBLIC_EXPONENT)?
            .filter(|v| !v.is_empty());
        match (modulus, exponent) {
            (Some(n), Some(e)) => Ok((n.to_vec(), e.to_vec())),
            _ => Err(ConsoleError::crypto("cannot read RSA public attributes from token").into()),
        }
    }

    /// c2 `_software_oaep_encrypt` over the token's public numbers of `handle`.
    pub(crate) fn software_oaep(
        &self,
        handle: u64,
        data: &[u8],
        hash_name: &str,
        mgf_hash: &str,
        label: &[u8],
    ) -> OResult<Vec<u8>> {
        let (n, e) = self.public_numbers(handle)?;
        Ok(software_oaep_encrypt(
            &n, &e, data, hash_name, mgf_hash, label,
        )?)
    }

    /// The EdDSA CKM of the logged-in token (standard first, then the vendor probe).
    fn eddsa_ckm(&self) -> Option<u64> {
        crate::capability::eddsa_ckm(&self.mech_codes(), &crate::capability::EDDSA_VENDOR_CKMS)
    }

    fn require_code(&self, name: &str, context: &str) -> OResult<u64> {
        Ok(self.require_ckm(name, context)?)
    }

    // ------------------------------------------------------------------
    // encrypt / decrypt (§5.8)
    // ------------------------------------------------------------------

    pub(crate) fn encrypt_impl(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        self.check_advertised(&mech.mechanism)?;
        reject_non_key(key, "encrypt")?;
        self.op(&format!("encrypt with {}", mech.mechanism), || {
            self.with_public_use_handle(key, |h| {
                Ok(self.do_cipher(h, key, mech, data, true)?.to_vec())
            })
        })
    }

    pub(crate) fn decrypt_impl(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.check_advertised(&mech.mechanism)?;
        reject_certificate(key, "decrypt")?;
        reject_non_key(key, "decrypt")?;
        if mech.mechanism == mechanism::RSA_RAW
            && key.key_class == KeyClass::Public
            && key.algorithm == KeyAlgorithm::Rsa
        {
            // §5.8 signature recovery (`decrypt …:pub raw`): tokens don't C_Decrypt with
            // public handles — the public-exponent modexp runs in software from the
            // always-readable public attributes.
            return self.op("decrypt with RSA-RAW (public)", || {
                let handle = self.find_handle(key)?;
                let modulus = self
                    .read_attr(handle, cka::MODULUS)?
                    .filter(|v| !v.is_empty());
                let exponent = self
                    .read_attr(handle, cka::PUBLIC_EXPONENT)?
                    .filter(|v| !v.is_empty());
                let (Some(n), Some(e)) = (modulus, exponent) else {
                    return Err(ConsoleError::unsupported(
                        "public RSA attributes unreadable on token",
                    )
                    .into());
                };
                Ok(r2_provider::rsa_raw::rsa_raw_modexp(&n, &e, data)?)
            });
        }
        self.op(&format!("decrypt with {}", mech.mechanism), || {
            let handle = self.find_handle(key)?;
            self.do_cipher(handle, key, mech, data, false)
        })
    }

    fn crypt(
        &self,
        spec: &MechSpec,
        handle: u64,
        data: &[u8],
        encrypt: bool,
    ) -> OResult<Zeroizing<Vec<u8>>> {
        if encrypt {
            Ok(Zeroizing::new(self.backend().encrypt(spec, handle, data)?))
        } else {
            Ok(self.backend().decrypt(spec, handle, data)?)
        }
    }

    /// c2 `_do_cipher`.
    fn do_cipher(
        &self,
        handle: u64,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
        encrypt: bool,
    ) -> OResult<Zeroizing<Vec<u8>>> {
        let params = &mech.params;
        let name = mech.mechanism.as_str();
        if mech.raw_ckm.is_some() {
            let spec = mechs::pack_custom(mech)?;
            return self.crypt(&spec, handle, data, encrypt);
        }
        match name {
            mechanism::AES_ECB => {
                let padding = param_str(params, "padding", "none")?;
                let ckm = self.require_code("CKM_AES_ECB", name)?;
                let spec = mechs::simple(ckm, None);
                if encrypt {
                    let payload = if padding == "pkcs7" {
                        pkcs7_pad(data)
                    } else if !data.len().is_multiple_of(16) {
                        return Err(ConsoleError::param(
                            "data length must be a multiple of 16 with padding=none",
                            "padding",
                        )
                        .into());
                    } else {
                        data.to_vec()
                    };
                    let payload = Zeroizing::new(payload);
                    return self.crypt(&spec, handle, &payload, true);
                }
                let out = self.crypt(&spec, handle, data, false)?;
                if padding == "pkcs7" {
                    Ok(pkcs7_unpad(&out)?)
                } else {
                    Ok(out)
                }
            }
            mechanism::AES_CBC => {
                let iv = param_bytes(params, "iv", None)?;
                let padding = param_str(params, "padding", "pkcs7")?;
                let ckm_name = if padding == "pkcs7" {
                    "CKM_AES_CBC_PAD"
                } else {
                    "CKM_AES_CBC"
                };
                let ckm = self.require_code(ckm_name, &format!("{name} padding={padding}"))?;
                self.crypt(&mechs::simple(ckm, Some(&iv)), handle, data, encrypt)
            }
            mechanism::AES_GCM => {
                self.require_code("CKM_AES_GCM", name)?;
                let spec = mechs::gcm(
                    &param_bytes(params, "iv", None)?,
                    &param_bytes(params, "aad", Some(b""))?,
                    param_int(params, "tag_bits", 128)?,
                    None,
                )?;
                self.crypt(&spec, handle, data, encrypt) // ct‖tag native (§5.8)
            }
            mechanism::AES_CTR => {
                self.require_code("CKM_AES_CTR", name)?;
                let spec = mechs::ctr(
                    param_int(params, "counter_bits", 128)?,
                    &param_bytes(params, "counter_block", None)?,
                )?;
                self.crypt(&spec, handle, data, encrypt)
            }
            mechanism::RSA_OAEP => self.rsa_oaep_cipher(handle, key, params, data, encrypt),
            mechanism::RSA_PKCS1 => {
                let ckm = self.require_code("CKM_RSA_PKCS", name)?;
                self.crypt(&mechs::simple(ckm, None), handle, data, encrypt)
            }
            mechanism::RSA_RAW => {
                let ckm = self.require_code("CKM_RSA_X_509", name)?;
                let spec = mechs::simple(ckm, None);
                if encrypt {
                    let payload = self.left_pad_to_modulus(handle, key, data)?;
                    return self.crypt(&spec, handle, &payload, true);
                }
                self.crypt(&spec, handle, data, false)
            }
            _ => Err(
                ConsoleError::unsupported(format!("mechanism {name} cannot encrypt/decrypt"))
                    .into(),
            ),
        }
    }

    /// c2 `_rsa_oaep_cipher`: token OAEP, else (params rejected) raw RSA on the token +
    /// OAEP padding in software.
    fn rsa_oaep_cipher(
        &self,
        handle: u64,
        key: &KeyInfo,
        params: &Params,
        data: &[u8],
        encrypt: bool,
    ) -> OResult<Zeroizing<Vec<u8>>> {
        let (hash_name, mgf_hash, label) = oaep_params(params)?;
        self.require_code("CKM_RSA_PKCS_OAEP", "RSA-OAEP")?;
        let spec = mechs::oaep(&hash_name, &mgf_hash, &label, None)?;
        let attempt = if encrypt {
            self.backend()
                .encrypt(&spec, handle, data)
                .map(Zeroizing::new)
        } else {
            self.backend().decrypt(&spec, handle, data)
        };
        match attempt {
            Ok(out) => Ok(out),
            Err(err) if !oaep_params_rejected(&err) => Err(err.into()),
            Err(_) => {
                tracing::info!(
                    target: "r2::pkcs11",
                    "{}: token rejected OAEP({}) params — using raw-RSA fallback",
                    self.provider_name(),
                    hash_name
                );
                if encrypt {
                    return Ok(Zeroizing::new(
                        self.software_oaep(handle, data, &hash_name, &mgf_hash, &label)?,
                    ));
                }
                let raw = self.require_code("CKM_RSA_X_509", "RSA-OAEP fallback")?;
                let em = self
                    .backend()
                    .decrypt(&mechs::simple(raw, None), handle, data)?;
                let k = self.modulus_len(handle, key)?;
                let padded = left_pad(&em, k);
                Ok(oaep_decode(&padded, &hash_name, &mgf_hash, &label)?)
            }
        }
    }

    // ------------------------------------------------------------------
    // sign / verify (§5.9)
    // ------------------------------------------------------------------

    pub(crate) fn sign_impl(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        self.check_advertised(&mech.mechanism)?;
        reject_certificate(key, "sign")?;
        reject_non_key(key, "sign")?;
        self.op(&format!("sign with {}", mech.mechanism), || {
            let handle = self.find_handle(key)?;
            self.do_sign(handle, key, mech, data)
        })
    }

    pub(crate) fn verify_impl(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        self.check_advertised(&mech.mechanism)?;
        reject_non_key(key, "verify")?;
        self.op(&format!("verify with {}", mech.mechanism), || {
            self.with_public_use_handle(key, |h| self.do_verify(h, key, mech, data, signature))
        })
    }

    /// c2 `_do_sign`.
    fn do_sign(
        &self,
        handle: u64,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> OResult<Vec<u8>> {
        let params = &mech.params;
        let name = mech.mechanism.as_str();
        let backend = self.backend();
        if mech.raw_ckm.is_some() {
            return Ok(backend.sign(&mechs::pack_custom(mech)?, handle, data)?);
        }
        if (name == mechanism::AES_CMAC || name == mechanism::AES_GMAC)
            && key.algorithm != KeyAlgorithm::Aes
        {
            return Err(ConsoleError::unsupported(format!(
                "{name} requires an AES secret key (got {} {})",
                key.algorithm.as_str(),
                key.key_class.as_str()
            ))
            .into());
        }
        match name {
            mechanism::HMAC => {
                // §5.9: HMAC keys are CKK_GENERIC_SECRET (or the CKK_SHAx_HMAC types that
                // fold into GENERIC); AES keys would only draw CKR_KEY_TYPE_INCONSISTENT.
                if key.algorithm != KeyAlgorithm::Generic {
                    return Err(ConsoleError::unsupported(format!(
                        "HMAC requires a generic secret key (got {} {})",
                        key.algorithm.as_str(),
                        key.key_class.as_str()
                    ))
                    .with_hint("generate/load a `generic` key (CKK_GENERIC_SECRET) for HMAC")
                    .into());
                }
                let hash_name = param_str(params, "hash", "sha256")?;
                let Some(ckm_name) = mechs::hmac_ckm_name(hash_name) else {
                    return Err(ConsoleError::param(
                        format!("unknown hash {}", r2_core::text::py_repr(hash_name)),
                        "hash",
                    )
                    .into());
                };
                let digest_size = mechs::digest_size(hash_name)?;
                let size = i64::try_from(digest_size).unwrap_or(64);
                let mac_len = param_int(params, "mac_len", size)?;
                if !(1..=size).contains(&mac_len) {
                    return Err(ConsoleError::param(
                        format!("mac_len must be between 1 and {digest_size} for {hash_name}"),
                        "mac_len",
                    )
                    .into());
                }
                let ckm = self.require_code(ckm_name, &format!("{name} ({hash_name})"))?;
                // full-width HMAC, truncated locally — byte-identical to
                // CKM_SHAx_HMAC_GENERAL(mac_len) by definition (§5.9)
                let mut mac = backend.sign(&mechs::simple(ckm, None), handle, data)?;
                mac.truncate(usize::try_from(mac_len).unwrap_or(0));
                Ok(mac)
            }
            mechanism::AES_CMAC => {
                let mac_len = param_int(params, "mac_len", 16)?;
                if !(1..=16).contains(&mac_len) {
                    return Err(
                        ConsoleError::param("mac_len must be between 1 and 16", "mac_len").into(),
                    );
                }
                let ckm = self.require_code("CKM_AES_CMAC", name)?;
                let mut mac = backend.sign(&mechs::simple(ckm, None), handle, data)?;
                mac.truncate(usize::try_from(mac_len).unwrap_or(0));
                Ok(mac)
            }
            mechanism::AES_GMAC => self.gmac(handle, params, data),
            mechanism::RSA_PKCS1 => {
                let hash_name = mechs::check_hash(param_str(params, "hash", "sha256")?, "hash")?;
                let combined = mechs::combined_rsa_pkcs(hash_name).unwrap_or_default();
                if let Some(code) = self.listed_code(combined) {
                    return Ok(backend.sign(&mechs::simple(code, None), handle, data)?);
                }
                let ckm = self.require_code("CKM_RSA_PKCS", name)?;
                let info = mechs::digest_info(hash_name, data)?;
                Ok(backend.sign(&mechs::simple(ckm, None), handle, &info)?)
            }
            mechanism::RSA_PSS => {
                let (spec, payload) = self.pss_setup(handle, key, params, data)?;
                Ok(backend.sign(&spec, handle, &payload)?)
            }
            mechanism::RSA_RAW => {
                let ckm = self.require_code("CKM_RSA_X_509", name)?;
                let payload = self.left_pad_to_modulus(handle, key, data)?;
                Ok(backend.sign(&mechs::simple(ckm, None), handle, &payload)?)
            }
            mechanism::ECDSA => {
                let hash_name = mechs::check_hash(param_str(params, "hash", "sha256")?, "hash")?;
                let combined = mechs::combined_ecdsa(hash_name).unwrap_or_default();
                if let Some(code) = self.listed_code(combined) {
                    return Ok(backend.sign(&mechs::simple(code, None), handle, data)?);
                }
                let ckm = self.require_code("CKM_ECDSA", name)?;
                let digest = mechs::digest(hash_name, data)?;
                Ok(backend.sign(&mechs::simple(ckm, None), handle, &digest)?)
            }
            mechanism::EDDSA => {
                let Some(ckm) = self.eddsa_ckm() else {
                    return Err(ConsoleError::unsupported(format!(
                        "token lacks an EdDSA mechanism for {name}"
                    ))
                    .into());
                };
                let spec = mechs::eddsa(ckm, key.curve == Some(Curve::Ed448));
                Ok(backend.sign(&spec, handle, data)?)
            }
            _ => Err(
                ConsoleError::unsupported(format!("mechanism {name} cannot sign/verify")).into(),
            ),
        }
    }

    /// The code of a CKM name when the logged-in token lists it (c2 `_has_ckm` + `code`).
    fn listed_code(&self, name: &str) -> Option<u64> {
        if self.has_ckm(name) {
            crate::catalog::symbol_value(name)
        } else {
            None
        }
    }

    /// c2 `_gmac`: CKM_AES_GMAC when listed, else the GCM-over-AAD construction on the
    /// multi-part path (SoftHSM rejects one-shot empty input).
    fn gmac(&self, handle: u64, params: &Params, data: &[u8]) -> OResult<Vec<u8>> {
        let iv = param_bytes(params, "iv", None)?;
        let mac_len = param_int(params, "mac_len", 16)?;
        if !(4..=16).contains(&mac_len) {
            return Err(ConsoleError::param("mac_len must be between 4 and 16", "mac_len").into());
        }
        if let Some(code) = self.listed_code("CKM_AES_GMAC") {
            let spec = mechs::gcm(&iv, b"", mac_len * 8, Some(code))?;
            return Ok(self.backend().sign(&spec, handle, data)?);
        }
        self.require_code("CKM_AES_GCM", "AES-GMAC (GCM construction)")?;
        let spec = mechs::gcm(&iv, data, mac_len * 8, None)?;
        Ok(self.backend().encrypt_multipart(&spec, handle, &[])?)
    }

    /// c2 `_pss_setup`: (mechanism, payload) — the combined CKM over the data when listed,
    /// else bare CKM_RSA_PKCS_PSS over a local digest.
    fn pss_setup(
        &self,
        handle: u64,
        key: &KeyInfo,
        params: &Params,
        data: &[u8],
    ) -> OResult<(MechSpec, Vec<u8>)> {
        let hash_name = mechs::check_hash(param_str(params, "hash", "sha256")?, "hash")?;
        let mgf_hash = param_str(params, "mgf_hash", hash_name)?;
        let digest_size = i64::try_from(mechs::digest_size(hash_name)?).unwrap_or(64);
        let mut salt_len = param_int(params, "salt_len", digest_size)?;
        if salt_len == -1 {
            // §4.6 sentinel: provider resolves to the maximum
            let k = i64::try_from(self.modulus_len(handle, key)?).unwrap_or(0);
            salt_len = k - digest_size - 2;
        }
        if salt_len < 0 {
            return Err(ConsoleError::param("salt_len must be >= -1", "salt_len").into());
        }
        let combined = mechs::combined_rsa_pss(hash_name).unwrap_or_default();
        if let Some(code) = self.listed_code(combined) {
            return Ok((
                mechs::pss(code, hash_name, mgf_hash, salt_len)?,
                data.to_vec(),
            ));
        }
        let bare = self.require_code("CKM_RSA_PKCS_PSS", "RSA-PSS")?;
        Ok((
            mechs::pss(bare, hash_name, mgf_hash, salt_len)?,
            mechs::digest(hash_name, data)?,
        ))
    }

    /// c2 `_do_verify`: MACs recompute + constant-time compare; everything else C_Verify
    /// (CKR_SIGNATURE_INVALID / CKR_SIGNATURE_LEN_RANGE = false, at the backend).
    fn do_verify(
        &self,
        handle: u64,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> OResult<bool> {
        let params = &mech.params;
        let name = mech.mechanism.as_str();
        let backend = self.backend();
        if matches!(
            name,
            mechanism::AES_CMAC | mechanism::AES_GMAC | mechanism::HMAC
        ) {
            let expected = self.do_sign(handle, key, mech, data)?;
            return Ok(r2_core::crypto::ct_eq(&expected, signature));
        }
        if mech.raw_ckm.is_some() {
            return Ok(backend.verify(&mechs::pack_custom(mech)?, handle, data, signature)?);
        }
        match name {
            mechanism::RSA_PKCS1 => {
                let hash_name = mechs::check_hash(param_str(params, "hash", "sha256")?, "hash")?;
                let combined = mechs::combined_rsa_pkcs(hash_name).unwrap_or_default();
                if let Some(code) = self.listed_code(combined) {
                    return Ok(backend.verify(
                        &mechs::simple(code, None),
                        handle,
                        data,
                        signature,
                    )?);
                }
                let ckm = self.require_code("CKM_RSA_PKCS", name)?;
                let info = mechs::digest_info(hash_name, data)?;
                Ok(backend.verify(&mechs::simple(ckm, None), handle, &info, signature)?)
            }
            mechanism::RSA_PSS => {
                let (spec, payload) = self.pss_setup(handle, key, params, data)?;
                Ok(backend.verify(&spec, handle, &payload, signature)?)
            }
            mechanism::RSA_RAW => {
                let ckm = self.require_code("CKM_RSA_X_509", name)?;
                let payload = self.left_pad_to_modulus(handle, key, data)?;
                Ok(backend.verify(&mechs::simple(ckm, None), handle, &payload, signature)?)
            }
            mechanism::ECDSA => {
                let hash_name = mechs::check_hash(param_str(params, "hash", "sha256")?, "hash")?;
                let combined = mechs::combined_ecdsa(hash_name).unwrap_or_default();
                if let Some(code) = self.listed_code(combined) {
                    return Ok(backend.verify(
                        &mechs::simple(code, None),
                        handle,
                        data,
                        signature,
                    )?);
                }
                let ckm = self.require_code("CKM_ECDSA", name)?;
                let digest = mechs::digest(hash_name, data)?;
                Ok(backend.verify(&mechs::simple(ckm, None), handle, &digest, signature)?)
            }
            mechanism::EDDSA => {
                let Some(ckm) = self.eddsa_ckm() else {
                    return Err(ConsoleError::unsupported(format!(
                        "token lacks an EdDSA mechanism for {name}"
                    ))
                    .into());
                };
                let spec = mechs::eddsa(ckm, key.curve == Some(Curve::Ed448));
                Ok(backend.verify(&spec, handle, data, signature)?)
            }
            _ => Err(ConsoleError::unsupported(format!("mechanism {name} cannot verify")).into()),
        }
    }

    // ------------------------------------------------------------------
    // derive (§5.10)
    // ------------------------------------------------------------------

    pub(crate) fn derive_impl(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
    ) -> Result<DeriveResult> {
        self.check_advertised(&mech.mechanism)?;
        reject_certificate(key, "derive")?;
        reject_non_key(key, "derive")?;
        if key.key_class == KeyClass::Public {
            return Err(ConsoleError::unsupported("derive requires a private key"));
        }
        self.op(&format!("derive with {}", mech.mechanism), || {
            let handle = self.find_handle(key)?;
            let (spec, value_len) = if mech.raw_ckm.is_some() {
                let spec = mechs::pack_custom(mech)?;
                let out_len = param_int(&mech.params, "out_len", 32)?;
                (spec, if out_len == 0 { 32 } else { out_len })
            } else {
                let peer = self.peer_to_raw_point(key, &param_bytes(&mech.params, "peer", None)?)?;
                let kdf = param_str(&mech.params, "kdf", "null")?;
                let shared = param_bytes(&mech.params, "shared_data", Some(b""))?;
                let out_len = param_int(&mech.params, "out_len", 0)?;
                let default_len = curve_field_bytes(key.curve.as_ref()).unwrap_or(32);
                let value_len = if out_len == 0 {
                    i64::try_from(default_len).unwrap_or(32)
                } else {
                    out_len
                };
                (mechs::ecdh(&peer, kdf, &shared)?, value_len)
            };
            // CKA_VALUE_LEN is a CK_ULONG: a negative out_len is the token's
            // CKR_ATTRIBUTE_VALUE_INVALID (§4.5.5 narrowing rule; PyKCS11 crashed)
            let value_len = u64::try_from(value_len).map_err(|_| {
                OpError::Backend(BackendError::Ckr(Ckr {
                    code: rv::CKR_ATTRIBUTE_VALUE_INVALID,
                    function: "template",
                }))
            })?;
            let label = format!("{}.shared", key.key_ref.label);
            let key_id = r2_core::crypto::random_bytes(4)?.to_vec();
            let template = |extractable: bool| -> OResult<Vec<RawAttr>> {
                let ckk_generic = w(sys::CKK_GENERIC_SECRET);
                Ok(vec![
                    (cka::CLASS, Zeroizing::new(ulong_bytes(cko(KeyClass::Secret))?)),
                    (cka::KEY_TYPE, Zeroizing::new(ulong_bytes(ckk_generic)?)),
                    (cka::TOKEN, Zeroizing::new(vec![0])),
                    (cka::SENSITIVE, Zeroizing::new(vec![u8::from(!extractable)])),
                    (cka::EXTRACTABLE, Zeroizing::new(vec![u8::from(extractable)])),
                    (cka::VALUE_LEN, Zeroizing::new(ulong_bytes(value_len)?)),
                    (cka::LABEL, Zeroizing::new(label.as_bytes().to_vec())),
                    (cka::ID, Zeroizing::new(key_id.clone())),
                ])
            };
            let mut extractable = true;
            let derived = match self.backend().derive_key(&spec, handle, &template(true)?) {
                Ok(derived) => derived,
                Err(err) if derive_template_rejected(&err) => {
                    // §5.10 [U]: the token forbids extractable generic secrets — retry with
                    // a resident (sensitive) template; DeriveResult.raw stays None
                    tracing::info!(
                        target: "r2::pkcs11",
                        "{}: token refused an extractable derived secret ({}) — retrying as resident key",
                        self.provider_name(),
                        ckr::code_of(&err).map_or_else(String::new, |c| crate::catalog::ckr_name(c).into_owned())
                    );
                    extractable = false;
                    self.backend().derive_key(&spec, handle, &template(false)?)?
                }
                Err(err) => return Err(err.into()),
            };
            let raw = if extractable {
                self.read_attr(derived, cka::VALUE)?
            } else {
                None
            };
            let mut attributes = std::collections::BTreeMap::new();
            attributes.insert("CKA_SENSITIVE".to_string(), AttrValue::Bool(!extractable));
            attributes.insert("CKA_EXTRACTABLE".to_string(), AttrValue::Bool(extractable));
            let info = KeyInfo {
                key_ref: KeyRef::new(self.provider_name(), label.clone(), Some(key_id.clone())),
                key_class: KeyClass::Secret,
                // it IS a CKK_GENERIC_SECRET session key
                algorithm: KeyAlgorithm::Generic,
                size_bits: u32::try_from(value_len.saturating_mul(8)).ok(),
                curve: None,
                exportable: raw.is_some(),
                attributes,
                handle: Some(derived),
            };
            tracing::info!(
                target: "r2::pkcs11",
                "{}: derived {}-byte secret from {} (raw {})",
                self.provider_name(),
                value_len,
                key.key_ref.display(),
                if raw.is_some() { "available" } else { "withheld" }
            );
            Ok(DeriveResult {
                key: Some(info),
                raw,
            })
        })
    }

    /// c2 `_peer_to_raw_point`: SPKI DER or a raw point → the RAW (non-DER) point PKCS#11
    /// wants (§5.10).
    fn peer_to_raw_point(&self, key: &KeyInfo, peer: &[u8]) -> OResult<Vec<u8>> {
        if peer.first() == Some(&0x30) {
            return Ok(spki_peer_point(peer)?);
        }
        if key.algorithm == KeyAlgorithm::Ec {
            if peer.first() != Some(&0x04) {
                return Err(ConsoleError::param(
                    "EC peer must be SPKI DER or an uncompressed 0x04‖X‖Y point",
                    "peer",
                )
                .into());
            }
            return Ok(peer.to_vec());
        }
        if let Some(expected) = curve_field_bytes(key.curve.as_ref())
            && u64::try_from(peer.len()).ok() != Some(expected)
        {
            return Err(ConsoleError::param(
                format!(
                    "peer must be SPKI DER or {expected} raw bytes for {}",
                    curve_text(key.curve.as_ref())
                ),
                "peer",
            )
            .into());
        }
        Ok(peer.to_vec())
    }
}

/// Left-pad `data` with zero bytes to `k` (Python `bytes.rjust(k, b"\0")`).
fn left_pad(data: &[u8], k: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; k.saturating_sub(data.len())]);
    out.extend_from_slice(data);
    out
}

/// An SPKI peer (pyca `load_der_public_key`): EC → the uncompressed point, X25519/X448 →
/// the raw u-coordinate; anything else → Param.
fn spki_peer_point(peer: &[u8]) -> Result<Vec<u8>> {
    // stale queue entries (SoftHSM's init) must not become this parse's reason
    crate::mechanisms::clear_openssl_errors();
    let invalid = |detail: &str| {
        ConsoleError::param(
            format!("peer is not a valid SPKI public key: {detail}"),
            "peer",
        )
    };
    // pyca's loader decides acceptance and the detail text (r2-core's port, §4.4.3)
    if let Err(err) = r2_core::formats::public_key_bytes(peer, r2_core::formats::Encoding::Pem) {
        let detail = err
            .message
            .strip_prefix("exported public key is not valid DER SubjectPublicKeyInfo: ")
            .unwrap_or(&err.message)
            .to_string();
        return Err(invalid(&detail));
    }
    let not_agreement = || ConsoleError::param("peer SPKI is not an EC/X25519/X448 key", "peer");
    let Ok(key) = PKey::public_key_from_der(peer) else {
        // pyca also loads a bare PKCS#1 RSAPublicKey: an RSA key, not an agreement key
        return Err(not_agreement());
    };
    match key.id() {
        Id::EC => {
            let ec = key.ec_key().map_err(|e| invalid(&reason(&e)))?;
            let mut ctx = BigNumContext::new().map_err(|e| invalid(&reason(&e)))?;
            ec.public_key()
                .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
                .map_err(|e| invalid(&reason(&e)))
        }
        Id::X25519 | Id::X448 => key.raw_public_key().map_err(|e| invalid(&reason(&e))),
        _ => Err(not_agreement()),
    }
}

/// `ErrorKind` of an `OpError` carrying a console error (edit's KeyNotFound re-resolve).
pub(crate) fn console_kind(err: &OpError) -> Option<&ErrorKind> {
    match err {
        OpError::Console(e) => Some(&e.kind),
        OpError::Backend(_) => None,
    }
}
