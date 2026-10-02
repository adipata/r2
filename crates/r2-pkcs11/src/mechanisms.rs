//! Mechanism builders, hash helpers and the five custom `param_struct` packers
//! (MechanismInvocation → MechSpec; spec §4.6.3, §5.8–§5.10, §5.14; c2
//! `providers/pkcs11/mechanisms.py`). Crate-private; owner R5b.
//!
//! Builders return `OResult<MechSpec>`: a parameter error is a console error (c2 raised
//! ParamError inside the session operation), and a numeric field that does not fit its
//! `CK_ULONG` (a negative tag/counter width — PyKCS11 raised OverflowError there) is the
//! token's `CKR_MECHANISM_PARAM_INVALID` (§4.5.5 narrowing rule), translated with the
//! operation's context at the choke point.
use cryptoki_sys as sys;
use openssl::bn::BigNum;
use openssl::encrypt::Encrypter;
use openssl::hash::{MessageDigest, hash};
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{KeyAlgorithm, KeyClass};
use r2_core::params::{ParamStruct, ParamValue, Params, param_int, param_str};
use r2_core::template::KeyTemplate;
use r2_core::text::py_repr;
use r2_provider::{MechanismInvocation, mechanism};
use zeroize::Zeroizing;

use crate::backend::{BackendError, Ckr, MechSpec};
use crate::ckr::rv;
use crate::provider::{OResult, OpError};

fn w(code: sys::CK_ULONG) -> u64 {
    crate::ulong_to_u64(code)
}

/// The hash names c2 knows (`_HASH_NAMES`), in its order.
pub(crate) const HASH_NAMES: [&str; 5] = ["sha1", "sha224", "sha256", "sha384", "sha512"];

/// hash param value → the HMAC CKM name (c2 `HMAC_CKM_BY_HASH`, §5.9 HMAC row).
pub(crate) fn hmac_ckm_name(hash_name: &str) -> Option<&'static str> {
    Some(match hash_name {
        "sha1" => "CKM_SHA_1_HMAC",
        "sha224" => "CKM_SHA224_HMAC",
        "sha256" => "CKM_SHA256_HMAC",
        "sha384" => "CKM_SHA384_HMAC",
        "sha512" => "CKM_SHA512_HMAC",
        _ => return None,
    })
}

/// hash → the combined CKM_SHAx_RSA_PKCS name (c2 `_COMBINED_RSA_PKCS`).
pub(crate) fn combined_rsa_pkcs(hash_name: &str) -> Option<&'static str> {
    Some(match hash_name {
        "sha1" => "CKM_SHA1_RSA_PKCS",
        "sha224" => "CKM_SHA224_RSA_PKCS",
        "sha256" => "CKM_SHA256_RSA_PKCS",
        "sha384" => "CKM_SHA384_RSA_PKCS",
        "sha512" => "CKM_SHA512_RSA_PKCS",
        _ => return None,
    })
}

/// hash → the combined CKM_SHAx_RSA_PKCS_PSS name (c2 `_COMBINED_RSA_PSS`).
pub(crate) fn combined_rsa_pss(hash_name: &str) -> Option<&'static str> {
    Some(match hash_name {
        "sha1" => "CKM_SHA1_RSA_PKCS_PSS",
        "sha224" => "CKM_SHA224_RSA_PKCS_PSS",
        "sha256" => "CKM_SHA256_RSA_PKCS_PSS",
        "sha384" => "CKM_SHA384_RSA_PKCS_PSS",
        "sha512" => "CKM_SHA512_RSA_PKCS_PSS",
        _ => return None,
    })
}

/// hash → the combined CKM_ECDSA_SHAx name (c2 `_COMBINED_ECDSA`).
pub(crate) fn combined_ecdsa(hash_name: &str) -> Option<&'static str> {
    Some(match hash_name {
        "sha1" => "CKM_ECDSA_SHA1",
        "sha224" => "CKM_ECDSA_SHA224",
        "sha256" => "CKM_ECDSA_SHA256",
        "sha384" => "CKM_ECDSA_SHA384",
        "sha512" => "CKM_ECDSA_SHA512",
        _ => return None,
    })
}

/// c2 `_check_hash`: Param "unknown hash {name!r}" (hint "valid hashes: …").
pub(crate) fn check_hash<'a>(name: &'a str, param_name: &str) -> Result<&'a str> {
    if HASH_NAMES.contains(&name) {
        return Ok(name);
    }
    Err(
        ConsoleError::param(format!("unknown hash {}", py_repr(name)), param_name)
            .with_hint(format!("valid hashes: {}", HASH_NAMES.join(", "))),
    )
}

fn message_digest(hash_name: &str) -> MessageDigest {
    match hash_name {
        "sha1" => MessageDigest::sha1(),
        "sha224" => MessageDigest::sha224(),
        "sha384" => MessageDigest::sha384(),
        "sha512" => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    }
}

/// Digest size in bytes of a known hash (hashlib `digest_size`).
pub(crate) fn digest_size(hash_name: &str) -> Result<usize> {
    Ok(message_digest(check_hash(hash_name, "hash")?).size())
}

/// `"sha256"` → CKM_SHA256 (the digest-mechanism code).
pub(crate) fn hash_ckm(hash_name: &str) -> Result<u64> {
    Ok(w(match check_hash(hash_name, "hash")? {
        "sha1" => sys::CKM_SHA_1,
        "sha224" => sys::CKM_SHA224,
        "sha384" => sys::CKM_SHA384,
        "sha512" => sys::CKM_SHA512,
        _ => sys::CKM_SHA256,
    }))
}

/// `"sha256"` → CKG_MGF1_SHA256.
pub(crate) fn mgf1_code(hash_name: &str) -> Result<u64> {
    Ok(w(match check_hash(hash_name, "mgf_hash")? {
        "sha1" => sys::CKG_MGF1_SHA1,
        "sha224" => sys::CKG_MGF1_SHA224,
        "sha384" => sys::CKG_MGF1_SHA384,
        "sha512" => sys::CKG_MGF1_SHA512,
        _ => sys::CKG_MGF1_SHA256,
    }))
}

/// Local hashing for tokens that only offer the bare (non-hashing) CKM.
pub(crate) fn digest(hash_name: &str, data: &[u8]) -> Result<Vec<u8>> {
    let md = message_digest(check_hash(hash_name, "hash")?);
    hash(md, data)
        .map(|d| d.to_vec())
        .map_err(|_| ConsoleError::crypto(format!("{hash_name} digest failed")))
}

/// DER DigestInfo prefixes for the local-hash + CKM_RSA_PKCS fallback (§5.9).
fn digest_info_prefix(hash_name: &str) -> &'static [u8] {
    match hash_name {
        "sha1" => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ],
        "sha224" => &[
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x04, 0x05, 0x00, 0x04, 0x1c,
        ],
        "sha384" => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        "sha512" => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
        _ => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
    }
}

/// DER DigestInfo(hash, digest(data)) for the CKM_RSA_PKCS fallback (§5.9).
pub(crate) fn digest_info(hash_name: &str, data: &[u8]) -> Result<Vec<u8>> {
    let digest = digest(hash_name, data)?;
    let mut out = digest_info_prefix(hash_name).to_vec();
    out.extend_from_slice(&digest);
    Ok(out)
}

/// A numeric mechanism field outside `CK_ULONG` → the token's CKR_MECHANISM_PARAM_INVALID.
fn param_ulong(value: i64) -> OResult<u64> {
    u64::try_from(value).map_err(|_| {
        OpError::Backend(BackendError::Ckr(Ckr {
            code: rv::CKR_MECHANISM_PARAM_INVALID,
            function: "mechanism",
        }))
    })
}

// ---------------------------------------------------------------------------
// mechanism builders (c2 `simple`/`gcm`/`ctr`/`oaep`/`pss`/`ecdh`/`eddsa`)
// ---------------------------------------------------------------------------

/// Bare CK_MECHANISM with an optional byte-string pParameter (empty → NULL).
pub(crate) fn simple(ckm: u64, param: Option<&[u8]>) -> MechSpec {
    match param {
        Some(param) if !param.is_empty() => MechSpec::Bytes {
            ckm,
            param: param.to_vec(),
        },
        _ => MechSpec::Plain { ckm },
    }
}

/// CK_GCM_PARAMS mechanism; `ckm` overrides the code (custom packers, GMAC).
pub(crate) fn gcm(iv: &[u8], aad: &[u8], tag_bits: i64, ckm: Option<u64>) -> OResult<MechSpec> {
    Ok(MechSpec::Gcm {
        ckm: ckm.unwrap_or(w(sys::CKM_AES_GCM)),
        iv: iv.to_vec(),
        aad: Zeroizing::new(aad.to_vec()),
        tag_bits: param_ulong(tag_bits)?,
    })
}

/// CK_AES_CTR_PARAMS mechanism (a counter block that is not 16 bytes cannot be expressed:
/// the token's CKR_MECHANISM_PARAM_INVALID).
pub(crate) fn ctr(counter_bits: i64, counter_block: &[u8]) -> OResult<MechSpec> {
    let counter_bits = param_ulong(counter_bits)?;
    let block: [u8; 16] = counter_block.try_into().map_err(|_| {
        OpError::Backend(BackendError::Ckr(Ckr {
            code: rv::CKR_MECHANISM_PARAM_INVALID,
            function: "mechanism",
        }))
    })?;
    Ok(MechSpec::Ctr {
        counter_bits,
        counter_block: block,
    })
}

/// CK_RSA_PKCS_OAEP_PARAMS mechanism; `ckm` overrides the code.
pub(crate) fn oaep(
    hash_name: &str,
    mgf_hash_name: &str,
    label: &[u8],
    ckm: Option<u64>,
) -> Result<MechSpec> {
    Ok(MechSpec::Oaep {
        ckm: ckm.unwrap_or(w(sys::CKM_RSA_PKCS_OAEP)),
        hash_ckm: hash_ckm(hash_name)?,
        mgf: mgf1_code(mgf_hash_name)?,
        label: label.to_vec(),
    })
}

/// CK_RSA_PKCS_PSS_PARAMS mechanism.
pub(crate) fn pss(
    ckm: u64,
    hash_name: &str,
    mgf_hash_name: &str,
    salt_len: i64,
) -> OResult<MechSpec> {
    Ok(MechSpec::Pss {
        ckm,
        hash_ckm: hash_ckm(hash_name)?,
        mgf: mgf1_code(mgf_hash_name)?,
        salt_len: param_ulong(salt_len)?,
    })
}

/// PyKCS11's CKD value of an ECDH `kdf` param: "null" → CKD_NULL, else
/// `CKD_{kdf.upper()}_KDF` when PyKCS11 1.5.18 names it.
fn ckd_value(kdf_name: &str) -> Option<u64> {
    if kdf_name == "null" {
        return Some(1);
    }
    let constant = format!("CKD_{}_KDF", kdf_name.to_uppercase());
    let table: [(&str, u64); 14] = [
        ("CKD_SHA1_KDF", 2),
        ("CKD_SHA224_KDF", 5),
        ("CKD_SHA256_KDF", 6),
        ("CKD_SHA384_KDF", 7),
        ("CKD_SHA512_KDF", 8),
        ("CKD_CPDIVERSIFY_KDF", 9),
        ("CKD_SHA3_224_KDF", 10),
        ("CKD_SHA3_256_KDF", 11),
        ("CKD_SHA3_384_KDF", 12),
        ("CKD_SHA3_512_KDF", 13),
        ("CKD_BLAKE2B_160_KDF", 23),
        ("CKD_BLAKE2B_256_KDF", 24),
        ("CKD_BLAKE2B_384_KDF", 25),
        ("CKD_BLAKE2B_512_KDF", 26),
    ];
    table
        .into_iter()
        .find(|(name, _)| *name == constant)
        .map(|(_, value)| value)
}

/// CK_ECDH1_DERIVE_PARAMS mechanism; `peer_point` is the RAW point (§5.10).
pub(crate) fn ecdh(peer_point: &[u8], kdf_name: &str, shared_data: &[u8]) -> Result<MechSpec> {
    let kdf = ckd_value(kdf_name).ok_or_else(|| {
        ConsoleError::param(format!("unknown ECDH kdf {}", py_repr(kdf_name)), "kdf")
            .with_hint("valid values: null, sha1, sha256, sha384, sha512")
    })?;
    Ok(MechSpec::Ecdh1 {
        kdf,
        shared_data: shared_data.to_vec(),
        public_data: peer_point.to_vec(),
    })
}

/// EdDSA mechanism: bare for Ed25519 pure; CK_EDDSA_PARAMS(phFlag=0) for Ed448.
pub(crate) fn eddsa(ckm: u64, ed448: bool) -> MechSpec {
    MechSpec::Eddsa { ckm, ed448 }
}

// ---------------------------------------------------------------------------
// custom mechanism param packers (§4.6.3/§5.14 — the five param_struct kinds)
// ---------------------------------------------------------------------------

const PACKER_HINT: &str =
    "conventional packer param names: iv/aad/tag_bits, hash/mgf_hash/label, mechparam";

fn bytes_param<'a>(params: &'a Params, name: &str, default: Option<&'a [u8]>) -> Result<&'a [u8]> {
    match params.get(name) {
        Some(ParamValue::Bytes(value)) => Ok(value),
        None if default.is_some() => Ok(default.unwrap_or_default()),
        _ => Err(ConsoleError::param(
            format!("custom mechanism parameter {} must be bytes", py_repr(name)),
            name,
        )
        .with_hint(PACKER_HINT)),
    }
}

fn int_param(params: &Params, name: &str, default: i64) -> Result<i64> {
    match params.get(name) {
        None => Ok(default),
        Some(ParamValue::Int(value)) => Ok(*value),
        Some(_) => Err(ConsoleError::param(
            format!(
                "custom mechanism parameter {} must be an integer",
                py_repr(name)
            ),
            name,
        )),
    }
}

fn str_param<'a>(params: &'a Params, name: &str, default: &'a str) -> Result<&'a str> {
    match params.get(name) {
        None => Ok(default),
        Some(ParamValue::Str(text) | ParamValue::Enum(text)) => Ok(text),
        Some(_) => Err(ConsoleError::param(
            format!(
                "custom mechanism parameter {} must be a string",
                py_repr(name)
            ),
            name,
        )),
    }
}

/// Build the MechSpec of a config-defined vendor CKM (c2 `pack_custom`): `none` (NULL
/// pParameter), `iv` (pParameter = bytes of param `iv`), `gcm`/`oaep` (standard structs from
/// conventional param names), `raw` (`raw_param_bytes`, else param `mechparam`, verbatim).
pub(crate) fn pack_custom(invocation: &MechanismInvocation) -> OResult<MechSpec> {
    let Some(ckm) = invocation.raw_ckm else {
        return Err(ConsoleError::crypto(format!(
            "custom mechanism {} has no raw CKM code",
            py_repr(&invocation.mechanism)
        ))
        .with_hint("OperationSpec.raw_ckm must be copied into MechanismInvocation (§4.6)")
        .into());
    };
    let params = &invocation.params;
    Ok(match invocation.param_struct {
        ParamStruct::None => simple(ckm, None),
        ParamStruct::Iv => simple(ckm, Some(bytes_param(params, "iv", None)?)),
        ParamStruct::Gcm => gcm(
            bytes_param(params, "iv", None)?,
            bytes_param(params, "aad", Some(b""))?,
            int_param(params, "tag_bits", 128)?,
            Some(ckm),
        )?,
        ParamStruct::Oaep => {
            let hash_name = str_param(params, "hash", "sha256")?;
            oaep(
                hash_name,
                str_param(params, "mgf_hash", hash_name)?,
                bytes_param(params, "label", Some(b""))?,
                Some(ckm),
            )?
        }
        ParamStruct::Raw => {
            let raw = match &invocation.raw_param_bytes {
                Some(raw) => raw.as_slice(),
                None => bytes_param(params, "mechparam", None)?,
            };
            simple(ckm, Some(raw))
        }
    })
}

// ---------------------------------------------------------------------------
// software OAEP (the §5.8 raw-RSA fallback; c2 `_mgf1`/`_oaep_decode`/`_software_oaep_encrypt`)
// ---------------------------------------------------------------------------

fn md(hash_name: &str) -> MessageDigest {
    message_digest(hash_name)
}

fn digest_of(hash_name: &str, data: &[u8]) -> Result<Vec<u8>> {
    hash(md(hash_name), data)
        .map(|d| d.to_vec())
        .map_err(|_| ConsoleError::crypto(format!("{hash_name} digest failed")))
}

fn mgf1(seed: &[u8], length: usize, hash_name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(length + 64));
    let mut counter: u32 = 0;
    while out.len() < length {
        let mut block = seed.to_vec();
        block.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&digest_of(hash_name, &block)?);
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    Ok(out)
}

fn xor(a: &[u8], b: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(a.iter().zip(b).map(|(x, y)| x ^ y).collect())
}

/// EME-OAEP decoding (RFC 8017 §7.1.2 steps 3.b–3.g) for the raw-RSA fallback (c2
/// `_oaep_decode`).
pub(crate) fn oaep_decode(
    em: &[u8],
    hash_name: &str,
    mgf_hash: &str,
    label: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let h_len = md(hash_name).size();
    let failure = || {
        ConsoleError::crypto("OAEP decoding failed")
            .with_hint("wrong key, hash or label parameters?")
    };
    if em.len() < 2 * h_len + 2 || em[0] != 0 {
        return Err(failure());
    }
    let (masked_seed, masked_db) = (&em[1..=h_len], &em[1 + h_len..]);
    let seed = xor(masked_seed, &mgf1(masked_db, h_len, mgf_hash)?);
    let db = xor(masked_db, &mgf1(&seed, masked_db.len(), mgf_hash)?);
    if db[..h_len] != digest_of(hash_name, label)?[..] {
        return Err(failure());
    }
    let Some(sep) = db[h_len..].iter().position(|b| *b == 1).map(|p| p + h_len) else {
        return Err(failure());
    };
    if db[h_len..sep].iter().any(|b| *b != 0) {
        return Err(failure());
    }
    Ok(Zeroizing::new(db[sep + 1..].to_vec()))
}

/// Discard the calling thread's pending OpenSSL errors. rust-openssl's `ErrorStack::get`
/// drains the whole thread-local queue, and SoftHSM shares the process's libcrypto (its
/// C_Initialize leaves the failed `rdrand` engine load queued), so every OpenSSL operation
/// whose [`reason`] is reported clears the queue first: the reason is then its own.
pub(crate) fn clear_openssl_errors() {
    let _stale = openssl::error::ErrorStack::get();
}

/// The first OpenSSL reason of an error stack (§11 D11).
pub(crate) fn reason(err: &openssl::error::ErrorStack) -> String {
    err.errors()
        .first()
        .and_then(|e| e.reason().map(str::to_string))
        .unwrap_or_else(|| "unknown error".to_string())
}

/// pyca-style OAEP encryption with the public key (n, e) (c2 `_software_oaep_encrypt`).
/// c2 let pyca's ValueError escape here (§11 D12(q)); r2 reports Crypto "RSA-OAEP
/// encryption failed: {OpenSSL reason}" (the memory provider's text).
pub(crate) fn software_oaep_encrypt(
    modulus: &[u8],
    exponent: &[u8],
    data: &[u8],
    hash_name: &str,
    mgf_hash: &str,
    label: &[u8],
) -> Result<Vec<u8>> {
    clear_openssl_errors();
    let failed = |err: openssl::error::ErrorStack| {
        ConsoleError::crypto(format!("RSA-OAEP encryption failed: {}", reason(&err)))
    };
    let rsa = Rsa::from_public_components(
        BigNum::from_slice(modulus).map_err(failed)?,
        BigNum::from_slice(exponent).map_err(failed)?,
    )
    .map_err(failed)?;
    let pkey = PKey::from_rsa(rsa).map_err(failed)?;
    let mut encrypter = Encrypter::new(&pkey).map_err(failed)?;
    encrypter
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(failed)?;
    encrypter.set_rsa_oaep_md(md(hash_name)).map_err(failed)?;
    encrypter.set_rsa_mgf1_md(md(mgf_hash)).map_err(failed)?;
    if !label.is_empty() {
        encrypter.set_rsa_oaep_label(label).map_err(failed)?;
    }
    let mut out = vec![0u8; encrypter.encrypt_len(data).map_err(failed)?];
    let n = encrypter.encrypt(data, &mut out).map_err(failed)?;
    out.truncate(n);
    Ok(out)
}

/// CKA_VALUE_LEN to inject for a §5.4 secret unwrap, or None (c2 `_unwrap_value_len`):
/// only AES/GENERIC SECRET results, never over an enabled operator CKA_VALUE_LEN row, and
/// only where the length is client-computable — AES-GCM (blob minus tag) and AES-CBC
/// `padding=none` (blob length); AES results only at 16/24/32, generic at any positive
/// length.
pub(crate) fn unwrap_value_len(
    mech: &MechanismInvocation,
    wrapped_len: usize,
    result_class: KeyClass,
    result_algorithm: KeyAlgorithm,
    template: Option<&KeyTemplate>,
) -> Result<Option<u64>> {
    if result_class != KeyClass::Secret
        || !matches!(result_algorithm, KeyAlgorithm::Aes | KeyAlgorithm::Generic)
    {
        return Ok(None);
    }
    if template
        .and_then(|t| t.get("CKA_VALUE_LEN"))
        .is_some_and(|row| row.enabled)
    {
        return Ok(None);
    }
    let wrapped = i64::try_from(wrapped_len).unwrap_or(i64::MAX);
    let length = match mech.mechanism.as_str() {
        mechanism::AES_GCM => {
            // Python floor division of the tag bits
            wrapped - param_int(&mech.params, "tag_bits", 128)?.div_euclid(8)
        }
        mechanism::AES_CBC if param_str(&mech.params, "padding", "pkcs7")? == "none" => wrapped,
        _ => return Ok(None),
    };
    if result_algorithm == KeyAlgorithm::Generic {
        return Ok(u64::try_from(length).ok().filter(|l| *l > 0));
    }
    Ok(matches!(length, 16 | 24 | 32).then(|| u64::try_from(length).unwrap_or(0)))
}
