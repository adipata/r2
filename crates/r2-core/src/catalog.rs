// R0 skeleton — owner R5a (generated from spec §4)
// ---- spec §4.5.5 block 5
use crate::template::AttrKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogEntry {
    pub name: &'static str,
    pub code: u64,
    pub kind: AttrKind,
}

const fn e(name: &'static str, code: u64, kind: AttrKind) -> CatalogEntry {
    CatalogEntry { name, code, kind }
}
use crate::template::AttrKind::{Bool as B, Bytes as Y, Str as S, Ulong as U};

/// The static CKA dictionary (c2 attributes.py, same order). Codes are PKCS#11 v3.0
/// literals. No cryptoki dependency, so console/services/testkit may use it.
pub const CKA_CATALOG: &[CatalogEntry] = &[
    e("CKA_CLASS", 0x0000, U),
    e("CKA_TOKEN", 0x0001, B),
    e("CKA_PRIVATE", 0x0002, B),
    e("CKA_LABEL", 0x0003, S),
    e("CKA_APPLICATION", 0x0010, S),
    e("CKA_VALUE", 0x0011, Y),
    e("CKA_OBJECT_ID", 0x0012, Y),
    e("CKA_CERTIFICATE_TYPE", 0x0080, U),
    e("CKA_ISSUER", 0x0081, Y),
    e("CKA_SERIAL_NUMBER", 0x0082, Y),
    e("CKA_TRUSTED", 0x0086, B),
    e("CKA_CERTIFICATE_CATEGORY", 0x0087, U),
    e("CKA_URL", 0x0089, Y),
    e("CKA_HASH_OF_SUBJECT_PUBLIC_KEY", 0x008A, Y),
    e("CKA_HASH_OF_ISSUER_PUBLIC_KEY", 0x008B, Y),
    e("CKA_CHECK_VALUE", 0x0090, Y),
    e("CKA_KEY_TYPE", 0x0100, U),
    e("CKA_SUBJECT", 0x0101, Y),
    e("CKA_ID", 0x0102, Y),
    e("CKA_START_DATE", 0x0110, Y),
    e("CKA_END_DATE", 0x0111, Y),
    e("CKA_SENSITIVE", 0x0103, B),
    e("CKA_ENCRYPT", 0x0104, B),
    e("CKA_DECRYPT", 0x0105, B),
    e("CKA_WRAP", 0x0106, B),
    e("CKA_UNWRAP", 0x0107, B),
    e("CKA_SIGN", 0x0108, B),
    e("CKA_SIGN_RECOVER", 0x0109, B),
    e("CKA_VERIFY", 0x010A, B),
    e("CKA_VERIFY_RECOVER", 0x010B, B),
    e("CKA_DERIVE", 0x010C, B),
    e("CKA_MODULUS", 0x0120, Y),
    e("CKA_MODULUS_BITS", 0x0121, U),
    e("CKA_PUBLIC_EXPONENT", 0x0122, Y),
    e("CKA_PRIVATE_EXPONENT", 0x0123, Y),
    e("CKA_PRIME_1", 0x0124, Y),
    e("CKA_PRIME_2", 0x0125, Y),
    e("CKA_EXPONENT_1", 0x0126, Y),
    e("CKA_EXPONENT_2", 0x0127, Y),
    e("CKA_COEFFICIENT", 0x0128, Y),
    e("CKA_PUBLIC_KEY_INFO", 0x0129, Y),
    e("CKA_PRIME", 0x0130, Y),
    e("CKA_SUBPRIME", 0x0131, Y),
    e("CKA_BASE", 0x0132, Y),
    e("CKA_VALUE_BITS", 0x0160, U),
    e("CKA_VALUE_LEN", 0x0161, U),
    e("CKA_EXTRACTABLE", 0x0162, B),
    e("CKA_LOCAL", 0x0163, B),
    e("CKA_NEVER_EXTRACTABLE", 0x0164, B),
    e("CKA_ALWAYS_SENSITIVE", 0x0165, B),
    e("CKA_KEY_GEN_MECHANISM", 0x0166, U),
    e("CKA_MODIFIABLE", 0x0170, B),
    e("CKA_COPYABLE", 0x0171, B),
    e("CKA_DESTROYABLE", 0x0172, B),
    e("CKA_EC_PARAMS", 0x0180, Y),
    e("CKA_EC_POINT", 0x0181, Y),
    e("CKA_ALWAYS_AUTHENTICATE", 0x0202, B),
    e("CKA_WRAP_WITH_TRUSTED", 0x0210, B),
];

/// Lookup by name: `CKA_CATALOG.iter().find(|e| e.name == name)` (R0 mandated body).
pub fn cka(name: &str) -> Option<&'static CatalogEntry> {
    CKA_CATALOG.iter().find(|e| e.name == name)
}
/// Lookup by code: `CKA_CATALOG.iter().find(|e| e.code == code)` (R0 mandated body).
pub fn cka_by_code(code: u64) -> Option<&'static CatalogEntry> {
    CKA_CATALOG.iter().find(|e| e.code == code)
}
