// R0 skeleton — owner R5a (generated from spec §4)
// ---- spec §4.5.5 block 6
pub use r2_core::catalog::{CKA_CATALOG, CatalogEntry, cka, cka_by_code};
use std::borrow::Cow;

/// Value of a `CKO_`/`CKK_`/`CKC_`/`CKM_` name in PyKCS11's dicts (symbolic template ULONGs
/// resolve here); None for any other name (→ Param at conversion, §4.7).
pub fn symbol_value(name: &str) -> Option<u64> {
    let _ = name;
    unimplemented!("R5a")
}
/// Reverse maps = PyKCS11's value→name entries (its alias choice, e.g. 0x3 → "CKK_EC").
pub fn cko_name(code: u64) -> Option<&'static str> {
    let _ = code;
    unimplemented!("R5a")
}
pub fn ckk_name(code: u64) -> Option<&'static str> {
    let _ = code;
    unimplemented!("R5a")
}
pub fn ckc_name(code: u64) -> Option<&'static str> {
    let _ = code;
    unimplemented!("R5a")
}
pub fn ckm_name(code: u64) -> Option<&'static str> {
    let _ = code;
    unimplemented!("R5a")
}
/// PyKCS11's CKR name, else "CKR_0x%08X" of the low 32 bits (c2 `_translate`).
pub fn ckr_name(code: u64) -> Cow<'static, str> {
    let _ = code;
    unimplemented!("R5a")
}
/// `KeyInfo.attributes["CKA_KEY_TYPE"]` / template rows: ckk_name, else "0x%08x" (lower-case,
/// c2 `_ckk_symbol`).
pub fn ckk_symbol(code: u64) -> String {
    let _ = code;
    unimplemented!("R5a")
}
