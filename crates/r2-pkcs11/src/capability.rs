#![allow(dead_code)]
// R0 skeleton — owner R5a (generated from spec §4)
// ---- spec §4.6.5 block 0
use std::collections::{BTreeMap, BTreeSet};

/// Advisory vendor EdDSA probe ids (Thales/SafeNet Luna CKM_EDDSA / CKM_EDDSA_NACL), in
/// preference order.
pub(crate) const EDDSA_VENDOR_CKMS: [u64; 2] = [0x8000_0C03, 0x8000_0C02];
/// The table below + `custom` ({ckm: id}: the id is advertised when `codes` lists ckm).
pub(crate) fn fold_mechanisms(codes: &[u64], custom: &BTreeMap<u64, String>) -> BTreeSet<String> {
    let _ = (codes, custom);
    unimplemented!("R5a")
}
