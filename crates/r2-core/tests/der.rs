//! EC/ECDSA DER helpers (spec §4.4.7) — port of c2 `test_certops.py`'s `ecdsa_rs_to_der`
//! cases (moved to R6, spec §4.1.1) and `_unwrap_octet_string` behavior.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use r2_core::der::{ecdsa_der_to_rs, ecdsa_rs_to_der, unwrap_octet_string, wrap_octet_string};
use r2_core::error::ErrorKind;

fn be(value: u128, width: usize) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    bytes[bytes.len() - width..].to_vec()
}

#[test]
fn test_rs_to_der_round_trip() {
    let (r, s) = (0x1234u128, 0x00FF_00FF_00FF_00FFu128);
    let mut raw = vec![0u8; 16];
    raw.extend(be(r, 16));
    raw.extend(vec![0u8; 16]);
    raw.extend(be(s, 16));
    assert_eq!(raw.len(), 64);
    let der = ecdsa_rs_to_der(&raw).unwrap();
    let sig = EcdsaSig::from_der(&der).unwrap(); // decode_dss_signature
    assert_eq!(
        sig.r().to_owned().unwrap(),
        BigNum::from_hex_str("1234").unwrap()
    );
    assert_eq!(
        sig.s().to_owned().unwrap(),
        BigNum::from_hex_str("00FF00FF00FF00FF").unwrap()
    );
    // minimal INTEGERs (encode_dss_signature)
    assert_eq!(
        der,
        [
            &[0x30, 0x0e, 0x02, 0x02, 0x12, 0x34, 0x02, 0x08, 0x00][..],
            &[0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff][..]
        ]
        .concat()
    );
    assert_eq!(ecdsa_der_to_rs(&der, 32).unwrap(), raw);
}

#[test]
fn test_rs_to_der_rejects_non_even_input() {
    for bad in [&b""[..], &b"\x01\x02\x03"[..]] {
        let err = ecdsa_rs_to_der(bad).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Crypto);
        assert!(err.message.contains("r‖s"));
        assert_eq!(
            err.message,
            format!(
                "ECDSA signature of {} bytes is not fixed-width r‖s",
                bad.len()
            )
        );
        assert_eq!(
            err.hint.as_deref(),
            Some("providers emit r‖s with each half ceil(curve_bits/8) bytes (§4.6)")
        );
    }
}

#[test]
fn rs_to_der_handles_zero_and_high_bit_halves() {
    let raw = [vec![0u8; 32], vec![0x80; 32]].concat();
    let der = ecdsa_rs_to_der(&raw).unwrap();
    let sig = EcdsaSig::from_der(&der).unwrap();
    assert_eq!(sig.r().num_bits(), 0);
    assert_eq!(sig.s().to_vec(), vec![0x80; 32]);
    assert_eq!(ecdsa_der_to_rs(&der, 32).unwrap(), raw);
    // P-521: 66-byte halves
    let raw = [vec![1u8; 66], vec![0u8; 65], vec![7]].concat();
    assert_eq!(
        ecdsa_der_to_rs(&ecdsa_rs_to_der(&raw).unwrap(), 66).unwrap(),
        raw
    );
}

#[test]
fn der_to_rs_rejects_malformed_and_oversized() {
    let malformed = |der: &[u8], half: usize| {
        let err = ecdsa_der_to_rs(der, half).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Crypto);
        assert_eq!(err.message, "malformed ECDSA DER signature");
    };
    malformed(b"", 32);
    malformed(b"\x30\x00", 32);
    malformed(b"\x30\x06\x02\x01\x01\x02\x01\x01\x00", 32); // trailing data
    malformed(b"\x30\x06\x02\x01\xff\x02\x01\x01", 32); // negative r
    let der = ecdsa_rs_to_der(&[0x11; 64]).unwrap();
    malformed(&der, 31); // oversized for the half width
}

#[test]
fn unwrap_octet_string_is_c2s() {
    let point = vec![0x04; 65];
    assert_eq!(unwrap_octet_string(&wrap_octet_string(&point)), point);
    let long = vec![0xab; 200];
    assert_eq!(unwrap_octet_string(&wrap_octet_string(&long)), long);
    // raw points and malformed headers pass through unchanged
    for input in [
        &b""[..],
        &b"\x04"[..],
        &b"\x04\x41\x04"[..],     // length mismatch
        &b"\x05\x01\x00"[..],     // not an OCTET STRING
        &b"\x04\x81"[..],         // truncated long form
        &b"\x04\x81\x02\xaa"[..], // long-form length mismatch
    ] {
        assert_eq!(unwrap_octet_string(input), input);
    }
    // c2's int.from_bytes semantics: a non-minimal long form still unwraps
    assert_eq!(unwrap_octet_string(b"\x04\x81\x01\xaa"), b"\xaa");
    assert_eq!(unwrap_octet_string(b"\x04\x82\x00\x01\xaa"), b"\xaa");
    assert_eq!(unwrap_octet_string(b"\x04\x80"), b"");
    assert_eq!(unwrap_octet_string(b"\x04\x00"), b"");
}
