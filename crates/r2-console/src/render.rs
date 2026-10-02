// Console render helpers (spec §4.9.9; owner R7) — the parts of c2 `console/render.py` that
// stay in the console (`suggest`) plus the shared `keys`-table cell texts. The renderer
// itself is R1's (`r2_core::render`); the Sink / color policy lives in `crate::io`.
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo};
use r2_core::text::close_matches;

/// difflib suggestion hint: Some("did you mean: a, b, c") over `known` sorted (n=3), or None.
pub fn suggest(wanted: &str, known: &[&str]) -> Option<String> {
    let mut sorted: Vec<&str> = known.to_vec();
    sorted.sort_unstable();
    let matches = close_matches(wanted, &sorted, 3);
    if matches.is_empty() {
        return None;
    }
    Some(format!("did you mean: {}", matches.join(", ")))
}
/// The `keys`-table class cell: "cert" for Certificate, else `KeyClass::as_str()`.
pub fn class_text(key_class: KeyClass) -> &'static str {
    match key_class {
        KeyClass::Certificate => "cert",
        other => other.as_str(),
    }
}
/// The `keys`-table algorithm cell: "-" for KeyAlgorithm::None, else `as_str()`.
pub fn algo_text(info: &KeyInfo) -> &'static str {
    match info.algorithm {
        KeyAlgorithm::None => "-",
        other => other.as_str(),
    }
}
