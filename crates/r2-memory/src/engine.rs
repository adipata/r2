//! The software crypto engine (c2 memory.py module helpers and `_aes_cipher`/`_gcm`/`_mac`,
//! pyca `keywrap`): §5.8–§5.10 mechanisms over OpenSSL with c2's parameter rules and
//! pyca's pre-validated texts.
use openssl::cipher::{Cipher as EvpCipher, CipherRef};
use openssl::cipher_ctx::{CipherCtx, CipherCtxFlags};
use openssl::error::ErrorStack;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};
use r2_core::crypto::ct_eq;
use r2_core::error::{ConsoleError, Result};
use r2_core::params::{ParamValue, Params, param_choice, param_int};
use zeroize::Zeroizing;

use crate::ossl_reason;

pub(crate) const HASH_NAMES: [&str; 5] = ["sha1", "sha224", "sha256", "sha384", "sha512"];
pub(crate) const KDF_NAMES: [&str; 6] = ["null", "sha1", "sha224", "sha256", "sha384", "sha512"];
const TAG_BITS_CHOICES: [&str; 5] = ["128", "120", "112", "104", "96"];
const PADDING_CHOICES: [&str; 2] = ["none", "pkcs7"];

/// The MessageDigest and digest size of a member of HASH_NAMES.
pub(crate) fn digest(name: &str) -> (MessageDigest, usize) {
    match name {
        "sha1" => (MessageDigest::sha1(), 20),
        "sha224" => (MessageDigest::sha224(), 28),
        "sha384" => (MessageDigest::sha384(), 48),
        "sha512" => (MessageDigest::sha512(), 64),
        _ => (MessageDigest::sha256(), 32),
    }
}

// ---------------------------------------------------------------------------------------
// parameter reads (c2 `_param_bytes`, `_param_int` → params::param_int, `_param_choice` →
// params::param_choice — spec §4.5.4)
// ---------------------------------------------------------------------------------------

/// c2 `_param_bytes`: absent → `default`, or Param "missing required parameter '{name}'";
/// a non-bytes value → Param "parameter '{name}' must be bytes".
pub(crate) fn param_bytes<'a>(
    params: &'a Params,
    name: &str,
    default: Option<&'a [u8]>,
) -> Result<&'a [u8]> {
    match params.get(name) {
        None => default.ok_or_else(|| {
            ConsoleError::param(format!("missing required parameter '{name}'"), name)
        }),
        Some(ParamValue::Bytes(bytes)) => Ok(bytes),
        Some(_) => Err(ConsoleError::param(
            format!("parameter '{name}' must be bytes"),
            name,
        )),
    }
}

/// c2 `_hash_param`: hash ∈ HASH_NAMES, default sha256.
pub(crate) fn hash_param(params: &Params) -> Result<String> {
    param_choice(params, "hash", &HASH_NAMES, "sha256")
}

/// c2 `_mgf_hash_name`: mgf_hash defaults to the (resolved) hash — the §4.6 `default_from`
/// rule when the resolver did not run.
pub(crate) fn mgf_hash_param(params: &Params, hash_name: &str) -> Result<String> {
    param_choice(params, "mgf_hash", &HASH_NAMES, hash_name)
}

/// RSA-OAEP parameters (c2 `_oaep_padding`): (hash, mgf_hash, label).
pub(crate) struct Oaep {
    pub(crate) hash: MessageDigest,
    pub(crate) mgf: MessageDigest,
    pub(crate) label: Vec<u8>,
}

pub(crate) fn oaep_params(params: &Params) -> Result<Oaep> {
    let hash_name = hash_param(params)?;
    let mgf_name = mgf_hash_param(params, &hash_name)?;
    let label = param_bytes(params, "label", Some(b""))?.to_vec();
    Ok(Oaep {
        hash: digest(&hash_name).0,
        mgf: digest(&mgf_name).0,
        label,
    })
}

/// RSA-PSS parameters (c2 `_pss_padding`), the §4.6 salt_len sentinels resolved HERE:
/// absent → digest length; -1 → ceil(bits/8) − hLen − 2; other negatives → Param.
pub(crate) struct Pss {
    pub(crate) hash: MessageDigest,
    pub(crate) mgf: MessageDigest,
    pub(crate) salt_len: i64,
}

pub(crate) fn pss_params(params: &Params, key_size_bits: u32) -> Result<Pss> {
    let hash_name = hash_param(params)?;
    let mgf_name = mgf_hash_param(params, &hash_name)?;
    let (hash, digest_size) = digest(&hash_name);
    let digest_size = i64::try_from(digest_size).unwrap_or(i64::MAX);
    let salt_len = if params.contains_key("salt_len") {
        let salt_len = param_int(params, "salt_len", digest_size)?;
        if salt_len == -1 {
            (i64::from(key_size_bits) + 7) / 8 - digest_size - 2
        } else if salt_len < 0 {
            return Err(ConsoleError::param(
                "salt_len must be >= 0 (or the -1 'maximum' sentinel)",
                "salt_len",
            ));
        } else {
            salt_len
        }
    } else {
        digest_size
    };
    Ok(Pss {
        hash,
        mgf: digest(&mgf_name).0,
        salt_len,
    })
}

// ---------------------------------------------------------------------------------------
// AES cipher engine (§5.8; c2 `_aes_cipher`, `_gcm`)
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum AesMode {
    Ecb,
    Cbc,
    Ctr,
    Gcm,
}

fn aes(mode: AesMode, key_len: usize) -> Result<Cipher> {
    Ok(match (mode, key_len) {
        (AesMode::Ecb, 16) => Cipher::aes_128_ecb(),
        (AesMode::Ecb, 24) => Cipher::aes_192_ecb(),
        (AesMode::Ecb, 32) => Cipher::aes_256_ecb(),
        (AesMode::Cbc, 16) => Cipher::aes_128_cbc(),
        (AesMode::Cbc, 24) => Cipher::aes_192_cbc(),
        (AesMode::Cbc, 32) => Cipher::aes_256_cbc(),
        (AesMode::Ctr, 16) => Cipher::aes_128_ctr(),
        (AesMode::Ctr, 24) => Cipher::aes_192_ctr(),
        (AesMode::Ctr, 32) => Cipher::aes_256_ctr(),
        (AesMode::Gcm, 16) => Cipher::aes_128_gcm(),
        (AesMode::Gcm, 24) => Cipher::aes_192_gcm(),
        (AesMode::Gcm, 32) => Cipher::aes_256_gcm(),
        // AES secrets are validated at import/generate (16/24/32 bytes).
        (_, len) => {
            return Err(ConsoleError::crypto(format!(
                "AES key must be 16, 24 or 32 bytes; got {len}"
            )));
        }
    })
}

/// One-shot Crypter run without padding; the output is zeroizing (it may be plaintext).
fn crypt(
    cipher: Cipher,
    mode: Mode,
    key: &[u8],
    iv: Option<&[u8]>,
    data: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, ErrorStack> {
    let mut crypter = Crypter::new(cipher, mode, key, iv)?;
    crypter.pad(false);
    let mut out = Zeroizing::new(vec![0u8; data.len() + cipher.block_size()]);
    let mut written = crypter.update(data, &mut out)?;
    written += crypter.finalize(&mut out[written..])?;
    out.truncate(written);
    Ok(out)
}

/// pyca PKCS7(128) padder.
fn pkcs7_pad(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let pad = 16 - data.len() % 16;
    let mut out = Zeroizing::new(Vec::with_capacity(data.len() + pad));
    out.extend_from_slice(data);
    out.extend(std::iter::repeat_n(u8::try_from(pad).unwrap_or(16), pad));
    out
}

/// pyca PKCS7(128) unpadder: the last byte n ∈ 1..=16 and the last n bytes all equal n.
fn pkcs7_unpad(mut data: Zeroizing<Vec<u8>>) -> Option<Zeroizing<Vec<u8>>> {
    let len = data.len();
    if len == 0 || !len.is_multiple_of(16) {
        return None;
    }
    let pad = usize::from(data[len - 1]);
    if !(1..=16).contains(&pad) || data[len - pad..].iter().any(|b| usize::from(*b) != pad) {
        return None;
    }
    data.truncate(len - pad);
    Some(data)
}

/// The AES encrypt/decrypt engine of encrypt/decrypt and the AES-CBC/AES-GCM wrap routes
/// (c2 `_aes_cipher`). `name` ∈ {AES-ECB, AES-CBC, AES-CTR, AES-GCM}.
pub(crate) fn aes_cipher(
    key: &[u8],
    name: &str,
    params: &Params,
    data: &[u8],
    encrypt: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    if name == "AES-GCM" {
        return gcm(key, params, data, encrypt);
    }
    if name == "AES-CTR" {
        let counter_block = param_bytes(params, "counter_block", None)?;
        let counter_bits = param_int(params, "counter_bits", 128)?;
        if counter_bits != 128 {
            return Err(ConsoleError::param(
                "the memory provider supports counter_bits=128 only (pyca CTR increments the full block, §5.8)",
                "counter_bits",
            ));
        }
        if counter_block.len() != 16 {
            return Err(ConsoleError::param(
                format!(
                    "counter_block must be the full 16-byte initial block; got {} bytes",
                    counter_block.len()
                ),
                "counter_block",
            ));
        }
        // CTR is symmetric: OpenSSL increments the whole block big-endian (= pyca).
        return crypt(
            aes(AesMode::Ctr, key.len())?,
            Mode::Encrypt,
            key,
            Some(counter_block),
            data,
        )
        .map_err(|err| ConsoleError::crypto(format!("{name} failed: {}", ossl_reason(&err))));
    }

    // ECB / CBC with provider-side PKCS7 (§5.8)
    let default_padding = if name == "AES-ECB" { "none" } else { "pkcs7" };
    let padding = param_choice(params, "padding", &PADDING_CHOICES, default_padding)?;
    let (cipher, iv) = if name == "AES-ECB" {
        (aes(AesMode::Ecb, key.len())?, None)
    } else {
        let iv = param_bytes(params, "iv", None)?;
        if iv.len() != 16 {
            return Err(ConsoleError::param(
                format!("iv must be 16 bytes for AES-CBC; got {}", iv.len()),
                "iv",
            ));
        }
        (aes(AesMode::Cbc, key.len())?, Some(iv))
    };
    if encrypt {
        let padded;
        let input: &[u8] = if padding == "pkcs7" {
            padded = pkcs7_pad(data);
            &padded
        } else if !data.len().is_multiple_of(16) {
            return Err(ConsoleError::param(
                "padding=none requires input length to be a multiple of 16 bytes",
                "padding",
            ));
        } else {
            data
        };
        return crypt(cipher, Mode::Encrypt, key, iv, input).map_err(|err| {
            ConsoleError::crypto(format!("{name} encryption failed: {}", ossl_reason(&err)))
        });
    }
    // pyca's decryptor.finalize ValueError, pre-validated (§5.8).
    if !data.len().is_multiple_of(16) {
        return Err(ConsoleError::crypto(format!(
            "{name} decryption failed: The length of the provided data is not a multiple of the block length."
        )));
    }
    let plaintext = crypt(cipher, Mode::Decrypt, key, iv, data).map_err(|err| {
        ConsoleError::crypto(format!("{name} decryption failed: {}", ossl_reason(&err)))
    })?;
    if padding == "pkcs7" {
        return pkcs7_unpad(plaintext)
            .ok_or_else(|| ConsoleError::crypto("invalid PKCS7 padding in decrypted data"));
    }
    Ok(plaintext)
}

/// pyca `modes.GCM(iv)` validation (OpenSSL accepts 1..=128-byte IVs).
fn check_gcm_iv(iv: &[u8]) -> Result<()> {
    if (8..=128).contains(&iv.len()) {
        Ok(())
    } else {
        Err(ConsoleError::param(
            "initialization_vector must be between 8 and 128 bytes (64 and 1024 bits).",
            "iv",
        ))
    }
}

/// (ciphertext, full 16-byte tag). AAD may be empty but is always passed (c2
/// `_gcm_encrypt_raw`).
pub(crate) fn gcm_encrypt_raw(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    check_gcm_iv(iv)?;
    let mut tag = [0u8; 16];
    let ciphertext = openssl::symm::encrypt_aead(
        aes(AesMode::Gcm, key.len())?,
        key,
        Some(iv),
        aad,
        plaintext,
        &mut tag,
    )
    .map_err(|err| {
        ConsoleError::crypto(format!("AES-GCM encryption failed: {}", ossl_reason(&err)))
    })?;
    Ok((ciphertext, tag))
}

fn gcm(key: &[u8], params: &Params, data: &[u8], encrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    let iv = param_bytes(params, "iv", None)?;
    let aad = param_bytes(params, "aad", Some(b""))?;
    let tag_bits: usize = param_choice(params, "tag_bits", &TAG_BITS_CHOICES, "128")?
        .parse()
        .unwrap_or(128);
    let tag_len = tag_bits / 8;
    if encrypt {
        let (mut ciphertext, tag) = gcm_encrypt_raw(key, iv, aad, data)?;
        ciphertext.extend_from_slice(&tag[..tag_len]); // ct‖tag convention (§5.8)
        return Ok(Zeroizing::new(ciphertext));
    }
    if data.len() < tag_len {
        return Err(ConsoleError::crypto(format!(
            "AES-GCM input is shorter than the {tag_len}-byte tag (ct‖tag expected)"
        )));
    }
    let (ciphertext, tag) = data.split_at(data.len() - tag_len);
    check_gcm_iv(iv)?;
    let auth_failed = || ConsoleError::crypto("AES-GCM authentication failed (tag mismatch)");
    let cipher = aes(AesMode::Gcm, key.len())?;
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).map_err(|err| {
        ConsoleError::crypto(format!("AES-GCM decryption failed: {}", ossl_reason(&err)))
    })?;
    crypter.aad_update(aad).map_err(|_| auth_failed())?;
    let mut out = Zeroizing::new(vec![0u8; ciphertext.len() + cipher.block_size()]);
    let written = crypter
        .update(ciphertext, &mut out)
        .map_err(|_| auth_failed())?;
    crypter.set_tag(tag).map_err(|_| auth_failed())?;
    let tail = crypter
        .finalize(&mut out[written..])
        .map_err(|_| auth_failed())?;
    out.truncate(written + tail);
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// MACs (§5.9; c2 `_mac`, `_mac_len_param`)
// ---------------------------------------------------------------------------------------

/// c2 `_mac_len_param`: mac_len (default = max, the full-width MAC), bounded 1..=max.
fn mac_len_param(params: &Params, max_len: usize) -> Result<usize> {
    let max = i64::try_from(max_len).unwrap_or(i64::MAX);
    let mac_len = param_int(params, "mac_len", max)?;
    if !(1..=max).contains(&mac_len) {
        return Err(ConsoleError::param(
            format!("mac_len must be between 1 and {max_len} bytes"),
            "mac_len",
        ));
    }
    Ok(usize::try_from(mac_len).unwrap_or(max_len))
}

/// HMAC / AES-CMAC / AES-GMAC over `key` (already checked against the mechanism).
pub(crate) fn mac(key: &[u8], name: &str, params: &Params, data: &[u8]) -> Result<Vec<u8>> {
    if name == "HMAC" {
        let (md, size) = digest(&hash_param(params)?);
        let mac_len = mac_len_param(params, size)?;
        let failed = |err: ErrorStack| {
            ConsoleError::crypto(format!("HMAC computation failed: {}", ossl_reason(&err)))
        };
        let pkey = PKey::hmac(key).map_err(failed)?;
        let mut signer = Signer::new(md, &pkey).map_err(failed)?;
        signer.update(data).map_err(failed)?;
        let mut full = signer.sign_to_vec().map_err(failed)?;
        full.truncate(mac_len);
        return Ok(full);
    }
    let mac_len = mac_len_param(params, 16)?;
    if name == "AES-CMAC" {
        let failed = |err: ErrorStack| {
            ConsoleError::crypto(format!(
                "AES-CMAC computation failed: {}",
                ossl_reason(&err)
            ))
        };
        let pkey = PKey::cmac(&aes(AesMode::Cbc, key.len())?, key).map_err(failed)?;
        let mut signer = Signer::new_without_digest(&pkey).map_err(failed)?;
        signer.update(data).map_err(failed)?;
        let mut full = signer.sign_to_vec().map_err(failed)?;
        full.truncate(mac_len);
        return Ok(full);
    }
    // AES-GMAC: GCM with empty plaintext, the message as AAD, output = tag (§5.9)
    let iv = param_bytes(params, "iv", None)?;
    let (_, tag) = gcm_encrypt_raw(key, iv, data, b"")?;
    Ok(tag[..mac_len].to_vec())
}

/// MAC verify = recompute + constant-time compare (c2 `hmac.compare_digest`).
pub(crate) fn mac_verify(
    key: &[u8],
    name: &str,
    params: &Params,
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let computed = mac(key, name, params, data)?;
    Ok(ct_eq(&computed, signature))
}

// ---------------------------------------------------------------------------------------
// AES key wrap (RFC 3394 / RFC 5649) — OpenSSL's EVP wrap ciphers with pyca's checks
// ---------------------------------------------------------------------------------------

/// pyca keywrap failure: `InvalidUnwrap(msg)` or a `ValueError(msg)`.
pub(crate) enum KwError {
    Invalid(String),
    Value(String),
}

impl KwError {
    pub(crate) fn text(&self) -> &str {
        match self {
            KwError::Invalid(text) | KwError::Value(text) => text,
        }
    }
}

fn wrap_cipher(key_len: usize, pad: bool) -> std::result::Result<&'static CipherRef, KwError> {
    Ok(match (key_len, pad) {
        (16, false) => EvpCipher::aes_128_wrap(),
        (24, false) => EvpCipher::aes_192_wrap(),
        (32, false) => EvpCipher::aes_256_wrap(),
        (16, true) => EvpCipher::aes_128_wrap_pad(),
        (24, true) => EvpCipher::aes_192_wrap_pad(),
        (32, true) => EvpCipher::aes_256_wrap_pad(),
        _ => {
            return Err(KwError::Value(
                "The wrapping key must be a valid AES key length".to_owned(),
            ));
        }
    })
}

/// One EVP wrap/unwrap pass (default IV) into a zeroizing buffer sized up front, so the
/// output never reallocates.
fn evp_wrap(
    cipher: &CipherRef,
    key: &[u8],
    data: &[u8],
    encrypt: bool,
) -> std::result::Result<Zeroizing<Vec<u8>>, ErrorStack> {
    let mut ctx = CipherCtx::new()?;
    ctx.set_flags(CipherCtxFlags::FLAG_WRAP_ALLOW);
    if encrypt {
        ctx.encrypt_init(Some(cipher), Some(key), None)?;
    } else {
        ctx.decrypt_init(Some(cipher), Some(key), None)?;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(data.len() + 64));
    ctx.cipher_update_vec(data, &mut out)?;
    ctx.cipher_final_vec(&mut out)?;
    Ok(out)
}

/// pyca `aes_key_wrap` (RFC 3394).
pub(crate) fn kw_wrap(kek: &[u8], payload: &[u8]) -> std::result::Result<Vec<u8>, KwError> {
    let cipher = wrap_cipher(kek.len(), false)?;
    if payload.len() < 16 {
        return Err(KwError::Value(
            "The key to wrap must be at least 16 bytes".to_owned(),
        ));
    }
    if !payload.len().is_multiple_of(8) {
        return Err(KwError::Value(
            "The key to wrap must be a multiple of 8 bytes".to_owned(),
        ));
    }
    evp_wrap(cipher, kek, payload, true)
        .map(|out| out.to_vec())
        .map_err(|err| KwError::Value(ossl_reason(&err)))
}

/// pyca `aes_key_wrap_with_padding` (RFC 5649).
pub(crate) fn kwp_wrap(kek: &[u8], payload: &[u8]) -> std::result::Result<Vec<u8>, KwError> {
    let cipher = wrap_cipher(kek.len(), true)?;
    if payload.is_empty() || u64::try_from(payload.len()).is_ok_and(|n| n > 1u64 << 32) {
        return Err(KwError::Value(
            "key_to_wrap must be between 1 and 2^32 bytes".to_owned(),
        ));
    }
    evp_wrap(cipher, kek, payload, true)
        .map(|out| out.to_vec())
        .map_err(|err| KwError::Value(ossl_reason(&err)))
}

/// pyca `aes_key_unwrap` (RFC 3394): InvalidUnwrap texts verbatim, an integrity failure is
/// pyca's message-less `InvalidUnwrap()`.
pub(crate) fn kw_unwrap(
    kek: &[u8],
    wrapped: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, KwError> {
    if wrapped.len() < 24 {
        return Err(KwError::Invalid("Must be at least 24 bytes".to_owned()));
    }
    if !wrapped.len().is_multiple_of(8) {
        return Err(KwError::Invalid(
            "The wrapped key must be a multiple of 8 bytes".to_owned(),
        ));
    }
    let cipher = wrap_cipher(kek.len(), false)?;
    evp_wrap(cipher, kek, wrapped, false).map_err(|_| KwError::Invalid(String::new()))
}

/// pyca `aes_key_unwrap_with_padding` (RFC 5649). A blob longer than 16 bytes that is not
/// a multiple of 8 is pyca's ECB-decryptor ValueError (raised before any integrity check).
pub(crate) fn kwp_unwrap(
    kek: &[u8],
    wrapped: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, KwError> {
    if wrapped.len() < 16 {
        return Err(KwError::Invalid("Must be at least 16 bytes".to_owned()));
    }
    let cipher = wrap_cipher(kek.len(), true)?;
    if !wrapped.len().is_multiple_of(8) {
        return Err(KwError::Value(
            "The length of the provided data is not a multiple of the block length.".to_owned(),
        ));
    }
    evp_wrap(cipher, kek, wrapped, false).map_err(|_| KwError::Invalid(String::new()))
}

/// AES-KEY-WRAP-PAD blob → payload, accepting both wire dialects (§5.5, c2
/// `_kw_pad_unwrap`): RFC 5649 KWP first; fallback RFC 3394 over a PKCS#7-padded payload
/// (the PKCS#11 spec-letter dialect, e.g. Utimaco CryptoServer) with a strict padding check.
pub(crate) fn kw_pad_unwrap(
    kek: &[u8],
    wrapped: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, KwError> {
    match kwp_unwrap(kek, wrapped) {
        Ok(payload) => return Ok(payload),
        Err(KwError::Invalid(_)) => {}
        Err(value) => return Err(value),
    }
    let mut padded = match kw_unwrap(kek, wrapped) {
        Ok(padded) => padded,
        Err(KwError::Invalid(_)) => {
            return Err(KwError::Invalid(
                "blob matches neither AES-KEY-WRAP-PAD dialect (RFC 5649 KWP / RFC 3394 over PKCS#7-padded payload)"
                    .to_owned(),
            ));
        }
        Err(value) => return Err(value),
    };
    let pad = padded.last().copied().map_or(0, usize::from);
    if !(1..=8).contains(&pad)
        || padded.len() < pad
        || padded[padded.len() - pad..]
            .iter()
            .any(|b| usize::from(*b) != pad)
    {
        return Err(KwError::Invalid(
            "RFC 3394 unwrap succeeded but the PKCS#7 padding is invalid".to_owned(),
        ));
    }
    tracing::info!(
        "AES-KEY-WRAP-PAD blob ({} bytes) unwrapped via the RFC 3394+PKCS#7 dialect",
        wrapped.len()
    );
    let len = padded.len() - pad;
    padded.truncate(len);
    Ok(padded)
}

// ---------------------------------------------------------------------------------------
// RSA helpers
// ---------------------------------------------------------------------------------------

/// RSA-OAEP encryption (c2 `public.encrypt(data, _oaep_padding(params))`); Err = reason.
pub(crate) fn oaep_encrypt(
    public: &PKeyRef<Public>,
    oaep: &Oaep,
    data: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    let run = || -> std::result::Result<Vec<u8>, ErrorStack> {
        let mut enc = openssl::encrypt::Encrypter::new(public)?;
        enc.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)?;
        enc.set_rsa_oaep_md(oaep.hash)?;
        enc.set_rsa_mgf1_md(oaep.mgf)?;
        if !oaep.label.is_empty() {
            enc.set_rsa_oaep_label(&oaep.label)?;
        }
        let mut out = vec![0u8; enc.encrypt_len(data)?];
        let n = enc.encrypt(data, &mut out)?;
        out.truncate(n);
        Ok(out)
    };
    run().map_err(|err| ossl_reason(&err))
}

/// RSA-OAEP decryption; any failure is detail-free (the caller's c2 text).
pub(crate) fn oaep_decrypt(
    private: &PKeyRef<Private>,
    oaep: &Oaep,
    data: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let run = || -> std::result::Result<Zeroizing<Vec<u8>>, ErrorStack> {
        let mut dec = openssl::encrypt::Decrypter::new(private)?;
        dec.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)?;
        dec.set_rsa_oaep_md(oaep.hash)?;
        dec.set_rsa_mgf1_md(oaep.mgf)?;
        if !oaep.label.is_empty() {
            dec.set_rsa_oaep_label(&oaep.label)?;
        }
        let mut out = Zeroizing::new(vec![0u8; dec.decrypt_len(data)?]);
        let n = dec.decrypt(data, &mut out)?;
        out.truncate(n);
        Ok(out)
    };
    run().ok()
}

/// RSA PKCS#1 v1.5 encryption; Err = reason.
pub(crate) fn pkcs1_encrypt(
    public: &PKeyRef<Public>,
    data: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    let run = || -> std::result::Result<Vec<u8>, ErrorStack> {
        let mut enc = openssl::encrypt::Encrypter::new(public)?;
        enc.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
        let mut out = vec![0u8; enc.encrypt_len(data)?];
        let n = enc.encrypt(data, &mut out)?;
        out.truncate(n);
        Ok(out)
    };
    run().map_err(|err| ossl_reason(&err))
}

/// RSA PKCS#1 v1.5 decryption; detail-free failure (Bleichenbacher hygiene).
pub(crate) fn pkcs1_decrypt(private: &PKeyRef<Private>, data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let run = || -> std::result::Result<Zeroizing<Vec<u8>>, ErrorStack> {
        let mut dec = openssl::encrypt::Decrypter::new(private)?;
        dec.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
        let mut out = Zeroizing::new(vec![0u8; dec.decrypt_len(data)?]);
        let n = dec.decrypt(data, &mut out)?;
        out.truncate(n);
        Ok(out)
    };
    run().ok()
}

// ---------------------------------------------------------------------------------------
// ECDH KDF (c2 `_x963_kdf`)
// ---------------------------------------------------------------------------------------

/// ANSI X9.63 KDF (the CKD_SHAx_KDF construction): Hash(Z ‖ counter ‖ shared).
pub(crate) fn x963_kdf(
    z: &[u8],
    shared_data: &[u8],
    hash_name: &str,
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let failed =
        |err: ErrorStack| ConsoleError::crypto(format!("X9.63 KDF failed: {}", ossl_reason(&err)));
    let (md, size) = digest(hash_name);
    let mut out = Zeroizing::new(Vec::with_capacity(length + size));
    let mut counter: u32 = 1;
    while out.len() < length {
        let mut hasher = Hasher::new(md).map_err(failed)?;
        hasher.update(z).map_err(failed)?;
        hasher.update(&counter.to_be_bytes()).map_err(failed)?;
        hasher.update(shared_data).map_err(failed)?;
        let block = hasher.finish().map_err(failed)?;
        out.extend_from_slice(&block);
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    Ok(out)
}
