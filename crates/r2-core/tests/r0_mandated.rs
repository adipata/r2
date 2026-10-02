//! R0: the mandated working bodies of r2-core's skeleton (spec §4.1.1 handoff 1) behave
//! exactly as their §4 doc comments state, so loops that call them before R5a/R6 merge get
//! the real behavior: `crypto::{ct_eq, random_bytes}`, `der::{curve_oid_der,
//! curve_from_oid_der, wrap_octet_string}` (§4.4.7/§4.4.8) and `catalog::{cka, cka_by_code}`
//! (§4.5.5), plus the `ConsoleError` constructors every stub's `Err(not_implemented(..))`
//! goes through (§4.2).
//!
//! Ownership: R0 seeds this file; the cases pass to the owners of the code they cover
//! (R1: ConsoleError; R6: crypto/der; R5a: catalog), who may edit, move or delete them.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use r2_core::catalog::{CKA_CATALOG, cka, cka_by_code};
use r2_core::crypto::random_bytes;
use r2_core::der::{curve_from_oid_der, curve_oid_der, wrap_octet_string};
use r2_core::keys::Curve;
use r2_core::template::AttrKind;

#[test]
fn ct_eq_compares_and_never_panics_on_length_mismatch() {
    assert!(r2_core::ct_eq(b"", b""));
    assert!(r2_core::ct_eq(b"abc", b"abc"));
    assert!(!r2_core::ct_eq(b"abc", b"abd"));
    assert!(!r2_core::ct_eq(b"abc", b"ab"));
    assert!(!r2_core::ct_eq(b"", b"a"));
}

#[test]
fn random_bytes_returns_the_requested_length() {
    assert!(random_bytes(0).unwrap().is_empty());
    let a = random_bytes(32).unwrap();
    let b = random_bytes(32).unwrap();
    assert_eq!(a.len(), 32);
    assert_ne!(*a, *b);
}

#[test]
fn ensure_legacy_provider_is_idempotent() {
    r2_core::ensure_legacy_provider();
    r2_core::ensure_legacy_provider();
}

/// The §4.4.7 table: p256 06082a8648ce3d030107, p384 06052b81040022, p521 06052b81040023,
/// ed25519 06032b6570, ed448 06032b6571, x25519 06032b656e, x448 06032b656f.
const CURVE_OIDS: [(Curve, &str); 7] = [
    (Curve::P256, "06082a8648ce3d030107"),
    (Curve::P384, "06052b81040022"),
    (Curve::P521, "06052b81040023"),
    (Curve::Ed25519, "06032b6570"),
    (Curve::Ed448, "06032b6571"),
    (Curve::X25519, "06032b656e"),
    (Curve::X448, "06032b656f"),
];

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn curve_oid_der_is_the_spec_table_and_inverts() {
    for (curve, oid) in CURVE_OIDS {
        let der = curve_oid_der(&curve).unwrap();
        assert_eq!(hex(der), oid, "{curve:?}");
        assert_eq!(curve_from_oid_der(der), Some(curve));
    }
    assert_eq!(curve_oid_der(&Curve::Other("secp256k1".to_owned())), None);
    assert_eq!(
        curve_from_oid_der(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a]),
        None
    );
    assert_eq!(curve_from_oid_der(&[]), None);
}

#[test]
fn wrap_octet_string_uses_der_definite_lengths() {
    assert_eq!(wrap_octet_string(&[]), vec![0x04, 0x00]);
    assert_eq!(
        wrap_octet_string(&[0xaa; 3]),
        vec![0x04, 0x03, 0xaa, 0xaa, 0xaa]
    );
    // 127 = the last short form; 128 and 255 take 0x81; 256 and 65 (P-256 point) as well.
    let short = wrap_octet_string(&[1; 127]);
    assert_eq!(&short[..2], &[0x04, 0x7f]);
    assert_eq!(short.len(), 2 + 127);
    let p256_point = wrap_octet_string(&[4; 65]);
    assert_eq!(&p256_point[..2], &[0x04, 0x41]);
    for (len, header) in [
        (128usize, vec![0x04, 0x81, 0x80]),
        (255, vec![0x04, 0x81, 0xff]),
        (256, vec![0x04, 0x82, 0x01, 0x00]),
        (65_536, vec![0x04, 0x83, 0x01, 0x00, 0x00]),
    ] {
        let out = wrap_octet_string(&vec![7; len]);
        assert_eq!(&out[..header.len()], header.as_slice(), "len {len}");
        assert_eq!(out.len(), header.len() + len);
        assert!(out[header.len()..].iter().all(|b| *b == 7));
    }
}

#[test]
fn catalog_lookups_find_entries_by_name_and_code() {
    let label = cka("CKA_LABEL").unwrap();
    assert_eq!((label.code, label.kind), (0x0003, AttrKind::Str));
    assert_eq!(cka_by_code(0x0162).unwrap().name, "CKA_EXTRACTABLE");
    assert_eq!(cka("CKA_NOPE"), None);
    assert_eq!(cka("cka_label"), None);
    assert_eq!(cka_by_code(0x8000_0001), None);
    // Every entry is reachable both ways (names and codes are unique in the table).
    for entry in CKA_CATALOG {
        assert_eq!(cka(entry.name), Some(entry));
        assert_eq!(cka_by_code(entry.code), Some(entry));
    }
    assert_eq!(CKA_CATALOG.len(), 58);
    assert_eq!(CKA_CATALOG[0].name, "CKA_CLASS");
    assert_eq!(
        CKA_CATALOG[CKA_CATALOG.len() - 1].name,
        "CKA_WRAP_WITH_TRUSTED"
    );
}

#[test]
fn random_bytes_reports_oversized_requests_as_crypto_error() {
    use r2_core::error::ErrorKind;
    // openssl::rand::rand_bytes asserts len <= c_int::MAX; no allocation happens here.
    let Some(len) = usize::try_from(i32::MAX)
        .ok()
        .and_then(|m| m.checked_add(1))
    else {
        return;
    };
    let err = random_bytes(len).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Crypto);
    assert_eq!(err.message, "random number generation failed");
    assert_eq!(err.hint, None);
}

#[test]
fn not_implemented_is_a_generic_error_not_a_panic() {
    use r2_core::error::{ConsoleError, ErrorKind};
    let err = ConsoleError::not_implemented("R4");
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(err.message, "not implemented (R4)");
    assert_eq!(err.hint, None);
    assert_eq!(err.to_string(), "not implemented (R4)");
}

#[test]
fn console_error_constructors_and_hint_builders() {
    use r2_core::error::{ConsoleError, ErrorKind};
    let err = ConsoleError::new(ErrorKind::Config, "bad").with_hint("fix it");
    assert_eq!(err.kind, ErrorKind::Config);
    assert_eq!(err.message, "bad");
    assert_eq!(err.hint.as_deref(), Some("fix it"));
    let err = err.with_hint("other").with_hint_opt(None);
    assert_eq!(err.hint, None);
    let err = ConsoleError::generic("g").with_hint_opt(Some("h".to_owned()));
    assert_eq!(
        (err.kind, err.hint.as_deref()),
        (ErrorKind::Generic, Some("h"))
    );
    assert_eq!(ConsoleError::crypto("c").kind, ErrorKind::Crypto);
}
