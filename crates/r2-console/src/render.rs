// R0 skeleton — owner R7 (generated from spec §4)
// ---- spec §4.9.9 block 1
use r2_core::keys::{KeyClass, KeyInfo};

/// difflib suggestion hint: Some("did you mean: a, b, c") over `known` sorted (n=3), or None.
pub fn suggest(wanted: &str, known: &[&str]) -> Option<String> {
    let _ = (wanted, known);
    unimplemented!("R7")
}
/// The `keys`-table class cell: "cert" for Certificate, else `KeyClass::as_str()`.
pub fn class_text(key_class: KeyClass) -> &'static str {
    let _ = key_class;
    unimplemented!("R7")
}
/// The `keys`-table algorithm cell: "-" for KeyAlgorithm::None, else `as_str()`.
pub fn algo_text(info: &KeyInfo) -> &'static str {
    let _ = info;
    unimplemented!("R7")
}
