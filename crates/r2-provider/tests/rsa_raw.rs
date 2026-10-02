// rsa_raw_modexp (spec §4.5.3; c2 providers/base.py `rsa_raw_modexp`) — R3.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]
use openssl::rsa::{Padding, Rsa};
use r2_core::error::ErrorKind;
use r2_provider::rsa_raw::rsa_raw_modexp;

// Textbook toy key: n = 61·53 = 3233 (12 bits → k = 2 bytes), e = 17, d = 2753.
const N: [u8; 2] = [0x0C, 0xA1];
const E: [u8; 1] = [17];
const D: [u8; 2] = [0x0A, 0xC1];

#[test]
fn textbook_round_trip_with_fixed_width_output() {
    let c = rsa_raw_modexp(&N, &E, &[65]).unwrap();
    assert_eq!(*c, vec![0x0A, 0xE6]); // 65^17 mod 3233 = 2790
    let m = rsa_raw_modexp(&N, &D, &c).unwrap();
    assert_eq!(*m, vec![0x00, 0x41]); // left-padded to k bytes
    assert_eq!(*rsa_raw_modexp(&N, &E, &[]).unwrap(), vec![0, 0]); // 0^e = 0, still k bytes
}

#[test]
fn modulus_width_ignores_leading_zero_bytes() {
    // c2: k = (n.bit_length() + 7) // 8 of the integer, not len(modulus bytes)
    let c = rsa_raw_modexp(&[0x00, 0x0C, 0xA1], &E, &[0x00, 0x00, 0x41]).unwrap_err();
    assert_eq!(
        c.message,
        "RSA-RAW input is longer than the modulus (3 > 2 bytes)"
    );
    assert_eq!(
        *rsa_raw_modexp(&[0x00, 0x0C, 0xA1], &E, &[65]).unwrap(),
        vec![0x0A, 0xE6]
    );
}

#[test]
fn error_texts() {
    let err = rsa_raw_modexp(&N, &E, &[1, 2, 3]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Crypto);
    assert_eq!(
        err.message,
        "RSA-RAW input is longer than the modulus (3 > 2 bytes)"
    );
    let err = rsa_raw_modexp(&N, &E, &N).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Crypto);
    assert_eq!(
        err.message,
        "RSA-RAW input is not numerically smaller than the modulus"
    );
    let err = rsa_raw_modexp(&N, &E, &[0xFF, 0xFF]).unwrap_err();
    assert_eq!(
        err.message,
        "RSA-RAW input is not numerically smaller than the modulus"
    );
}

#[test]
fn matches_openssl_raw_rsa_on_a_real_key() {
    let rsa = Rsa::generate(2048).unwrap();
    let n = rsa.n().to_vec();
    let e = rsa.e().to_vec();
    let d = rsa.d().to_vec();
    let mut block = vec![0u8; 256];
    block[1] = 0x42;
    block[255] = 0x17;
    let mut expected = vec![0u8; 256];
    let len = rsa
        .public_encrypt(&block, &mut expected, Padding::NONE)
        .unwrap();
    expected.truncate(len);
    let ours = rsa_raw_modexp(&n, &e, &block).unwrap();
    assert_eq!(*ours, expected);
    // a short input is left-padded to the modulus length
    let short = rsa_raw_modexp(&n, &e, &block[1..]).unwrap();
    assert_eq!(*short, expected);
    let back = rsa_raw_modexp(&n, &d, &ours).unwrap();
    assert_eq!(*back, block);
}
