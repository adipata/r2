//! CKM → canonical-name folding, custom ckm→id merge and the advisory EdDSA probe (spec
//! §4.6.5; c2 `mechanisms.py` folding parts). Codes come from the UNFILTERED
//! `RawFns::mechanism_list`, never cryptoki's filtered list.
use std::collections::{BTreeMap, BTreeSet};

use cryptoki_sys as sys;
use r2_provider::mechanism as m;

/// Advisory vendor EdDSA probe ids (Thales/SafeNet Luna CKM_EDDSA / CKM_EDDSA_NACL), in
/// preference order.
pub(crate) const EDDSA_VENDOR_CKMS: [u64; 2] = [0x8000_0C03, 0x8000_0C02];

/// cryptoki-sys CKM constant widened to u64.
pub(crate) fn ckm(code: sys::CK_MECHANISM_TYPE) -> u64 {
    crate::ulong_to_u64(code)
}

/// canonical name → the CKMs that advertise it (c2 `_FOLD_SOURCES`, §4.6.5 table).
/// EDDSA's standard CKM is here; the vendor probe is applied separately.
pub(crate) fn fold_sources() -> Vec<(&'static str, Vec<u64>)> {
    vec![
        (m::AES_ECB, vec![ckm(sys::CKM_AES_ECB)]),
        (
            m::AES_CBC,
            vec![ckm(sys::CKM_AES_CBC), ckm(sys::CKM_AES_CBC_PAD)],
        ),
        (m::AES_CTR, vec![ckm(sys::CKM_AES_CTR)]),
        (m::AES_GCM, vec![ckm(sys::CKM_AES_GCM)]),
        (m::AES_CMAC, vec![ckm(sys::CKM_AES_CMAC)]),
        (
            m::AES_GMAC,
            vec![ckm(sys::CKM_AES_GMAC), ckm(sys::CKM_AES_GCM)],
        ),
        (
            m::HMAC,
            vec![
                ckm(sys::CKM_SHA_1_HMAC),
                ckm(sys::CKM_SHA224_HMAC),
                ckm(sys::CKM_SHA256_HMAC),
                ckm(sys::CKM_SHA384_HMAC),
                ckm(sys::CKM_SHA512_HMAC),
            ],
        ),
        (m::RSA_OAEP, vec![ckm(sys::CKM_RSA_PKCS_OAEP)]),
        (
            m::RSA_PKCS1,
            vec![
                ckm(sys::CKM_RSA_PKCS),
                ckm(sys::CKM_SHA1_RSA_PKCS),
                ckm(sys::CKM_SHA224_RSA_PKCS),
                ckm(sys::CKM_SHA256_RSA_PKCS),
                ckm(sys::CKM_SHA384_RSA_PKCS),
                ckm(sys::CKM_SHA512_RSA_PKCS),
            ],
        ),
        (
            m::RSA_PSS,
            vec![
                ckm(sys::CKM_RSA_PKCS_PSS),
                ckm(sys::CKM_SHA1_RSA_PKCS_PSS),
                ckm(sys::CKM_SHA224_RSA_PKCS_PSS),
                ckm(sys::CKM_SHA256_RSA_PKCS_PSS),
                ckm(sys::CKM_SHA384_RSA_PKCS_PSS),
                ckm(sys::CKM_SHA512_RSA_PKCS_PSS),
            ],
        ),
        (m::RSA_RAW, vec![ckm(sys::CKM_RSA_X_509)]),
        (
            m::ECDSA,
            vec![
                ckm(sys::CKM_ECDSA),
                ckm(sys::CKM_ECDSA_SHA1),
                ckm(sys::CKM_ECDSA_SHA224),
                ckm(sys::CKM_ECDSA_SHA256),
                ckm(sys::CKM_ECDSA_SHA384),
                ckm(sys::CKM_ECDSA_SHA512),
            ],
        ),
        (m::EDDSA, vec![ckm(sys::CKM_EDDSA)]),
        (m::ECDH, vec![ckm(sys::CKM_ECDH1_DERIVE)]),
        (m::AES_KEY_WRAP, vec![ckm(sys::CKM_AES_KEY_WRAP)]),
        (
            m::AES_KEY_WRAP_PAD,
            vec![
                ckm(sys::CKM_AES_KEY_WRAP_PAD),
                ckm(sys::CKM_AES_KEY_WRAP_KWP),
            ],
        ),
        // RSA-AES-KEY-WRAP: never advertised (§4.5.5, §11 D6).
    ]
}

/// The table below + `custom` ({ckm: id}: the id is advertised when `codes` lists ckm).
pub(crate) fn fold_mechanisms(codes: &[u64], custom: &BTreeMap<u64, String>) -> BTreeSet<String> {
    fold_mechanisms_with(codes, custom, &EDDSA_VENDOR_CKMS)
}

/// `fold_mechanisms` with an explicit vendor EdDSA candidate list (c2's keyword argument).
pub(crate) fn fold_mechanisms_with(
    codes: &[u64],
    custom: &BTreeMap<u64, String>,
    eddsa_vendor_ckms: &[u64],
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for (canonical, sources) in fold_sources() {
        if sources.iter().any(|s| codes.contains(s)) {
            names.insert(canonical.to_string());
        }
    }
    if eddsa_ckm(codes, eddsa_vendor_ckms).is_some() {
        names.insert(m::EDDSA.to_string());
    }
    for (raw_ckm, op_id) in custom {
        if codes.contains(raw_ckm) {
            names.insert(op_id.clone());
        }
    }
    names
}

/// The CKM to use for EDDSA: the standard id first, then the advisory vendor candidates
/// (first listed wins); None → the op stays hidden.
pub(crate) fn eddsa_ckm(codes: &[u64], eddsa_vendor_ckms: &[u64]) -> Option<u64> {
    let standard = ckm(sys::CKM_EDDSA);
    if codes.contains(&standard) {
        return Some(standard);
    }
    eddsa_vendor_ckms
        .iter()
        .copied()
        .find(|c| codes.contains(c))
}
