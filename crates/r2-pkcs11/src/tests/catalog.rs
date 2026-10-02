//! The PyKCS11 1.5.18 name tables of `crate::catalog` (spec §4.5.5).
use crate::catalog::{ckc_name, ckk_name, ckk_symbol, ckm_name, cko_name, ckr_name, symbol_value};

#[test]
fn table_sizes_equal_pykcs11() {
    use crate::catalog::{CKC_NAMES, CKK_NAMES, CKM_NAMES, CKO_NAMES, CKR_NAMES, SYMBOLS};
    // forward: 10 CKO + 58 CKK + 3 CKC + 425 CKM names (aliases included)
    assert_eq!(SYMBOLS.len(), 496);
    let prefixed = |p: &str| SYMBOLS.iter().filter(|(n, _)| n.starts_with(p)).count();
    assert_eq!(
        (
            prefixed("CKO_"),
            prefixed("CKK_"),
            prefixed("CKC_"),
            prefixed("CKM_")
        ),
        (10, 58, 3, 425)
    );
    assert_eq!(
        (
            CKO_NAMES.len(),
            CKK_NAMES.len(),
            CKC_NAMES.len(),
            CKM_NAMES.len(),
            CKR_NAMES.len()
        ),
        (10, 56, 3, 416, 93)
    );
    // binary-search invariants
    assert!(SYMBOLS.windows(2).all(|w| w[0].0 < w[1].0));
    for table in [
        &CKO_NAMES[..],
        &CKK_NAMES[..],
        &CKC_NAMES[..],
        &CKM_NAMES[..],
        &CKR_NAMES[..],
    ] {
        assert!(table.windows(2).all(|w| w[0].0 < w[1].0));
    }
    // every reverse entry round-trips through the forward table
    for (code, name) in CKO_NAMES
        .iter()
        .chain(&CKK_NAMES)
        .chain(&CKC_NAMES)
        .chain(&CKM_NAMES)
    {
        assert_eq!(symbol_value(name), Some(*code), "{name}");
    }
}

#[test]
fn forward_values_are_pykcs11s() {
    assert_eq!(symbol_value("CKO_SECRET_KEY"), Some(4));
    assert_eq!(symbol_value("CKK_AES"), Some(0x1F));
    assert_eq!(symbol_value("CKK_EC"), Some(3));
    assert_eq!(symbol_value("CKK_ECDSA"), Some(3)); // alias
    assert_eq!(symbol_value("CKC_X_509"), Some(0));
    assert_eq!(symbol_value("CKM_AES_KEY_GEN"), Some(0x1080));
    assert_eq!(symbol_value("CKM_AES_KEY_WRAP_KWP"), Some(0x210B));
    // only CKO_/CKK_/CKC_/CKM_ names resolve
    assert_eq!(symbol_value("CKR_OK"), None);
    assert_eq!(symbol_value("CKA_LABEL"), None);
    assert_eq!(symbol_value("CKK_NOPE"), None);
}

#[test]
fn reverse_maps_keep_pykcs11s_alias_choice() {
    assert_eq!(ckk_name(3), Some("CKK_EC"));
    assert_eq!(cko_name(3), Some("CKO_PRIVATE_KEY"));
    assert_eq!(ckc_name(0), Some("CKC_X_509"));
    assert_eq!(ckm_name(0x1087), Some("CKM_AES_GCM"));
    assert_eq!(ckm_name(0x8000_0A01), None);
}

#[test]
fn ckr_names_and_fallback() {
    assert_eq!(ckr_name(0xA0), "CKR_PIN_INCORRECT");
    assert_eq!(ckr_name(0x30), "CKR_DEVICE_ERROR");
    // codes PyKCS11 cannot name render as c2 did (cryptoki-sys knows these, PyKCS11 not)
    assert_eq!(ckr_name(0x1B), "CKR_0x0000001B"); // CKR_ACTION_PROHIBITED
    assert_eq!(ckr_name(0x8000_0001), "CKR_0x80000001");
    assert_eq!(ckr_name(0x1_0000_0005), "CKR_0x00000005");
}

#[test]
fn ckk_symbol_falls_back_to_lower_hex() {
    assert_eq!(ckk_symbol(0x15), "CKK_DES3");
    assert_eq!(ckk_symbol(0x8000_1234), "0x80001234");
    assert_eq!(ckk_symbol(0x4B), "0x0000004b"); // a cryptoki-sys-only CKK (ML-DSA range)
}
