//! Input codec tests (spec §4.4.1) — port of c2 `tests/unit/core/test_codec.py` (the
//! authoritative §4.4/§5.4 matrix) and the codec cases of `tests/unit/test_l13_hardening.py`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

#[path = "support/codec_vectors.rs"]
mod codec_vectors;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::symm::Cipher;
use r2_core::codec::{InputFormat, decode_data, format_hex};
use r2_core::error::ErrorKind;

// --- PEM fixtures -----------------------------------------------------------

/// base64 body = exactly one 64-char line.
fn der_small() -> Vec<u8> {
    (0..48).collect()
}
/// base64 body wraps to 64 + 64 + 4 chars.
fn der_big() -> Vec<u8> {
    (0..97).collect()
}

fn canonical_pem(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut lines = vec![format!("-----BEGIN {label}-----")];
    lines.extend(
        body.as_bytes()
            .chunks(64)
            .map(|chunk| String::from_utf8(chunk.to_vec()).unwrap()),
    );
    lines.push(format!("-----END {label}-----"));
    lines.join("\n") + "\n"
}

fn cert_pem() -> String {
    canonical_pem("CERTIFICATE", &der_big())
}
fn key_pem() -> String {
    canonical_pem("RSA PRIVATE KEY", &der_small())
}
fn bundle_pem() -> String {
    cert_pem() + &key_pem()
}

fn chunks_joined(text: &str, size: usize, sep: &str) -> String {
    text.as_bytes()
        .chunks(size)
        .map(|chunk| String::from_utf8(chunk.to_vec()).unwrap())
        .collect::<Vec<_>>()
        .join(sep)
}

// --- the input matrix (§4.4 / §5.4): decoded value + detected format --------

#[test]
fn test_decode_matrix() {
    use InputFormat::{Base64, Hex, Pem};
    let deadbeef = vec![0xde, 0xad, 0xbe, 0xef];
    let cert = cert_pem();
    let bundle = bundle_pem();
    let matrix: Vec<(&str, String, Vec<u8>, InputFormat)> = vec![
        // plain hex, case-insensitive
        ("hex-plain", "deadbeef".into(), deadbeef.clone(), Hex),
        ("hex-upper", "DEADBEEF".into(), deadbeef.clone(), Hex),
        ("hex-mixed-case", "DeAdBeEf".into(), deadbeef.clone(), Hex),
        // hex with spaces / tabs / newlines (multiline paste, quoted or not)
        ("hex-spaces", "de ad be ef".into(), deadbeef.clone(), Hex),
        ("hex-newlines", "dead\nbeef".into(), deadbeef.clone(), Hex),
        (
            "hex-mixed-ws",
            " de\tad\r\nbe ef\n".into(),
            deadbeef.clone(),
            Hex,
        ),
        (
            "hex-quoted-multiline",
            "de ad\nbe ef\n00 11\n".into(),
            vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x11],
            Hex,
        ),
        // forcing prefixes, incl. whitespace inside the prefixed value
        ("hex-prefix", "hex:deadbeef".into(), deadbeef.clone(), Hex),
        (
            "hex-prefix-ws",
            "hex: de ad\nbe ef".into(),
            deadbeef.clone(),
            Hex,
        ),
        ("0x-prefix", "0xdeadbeef".into(), deadbeef.clone(), Hex),
        (
            "0x-prefix-ws",
            "0x de ad be ef".into(),
            deadbeef.clone(),
            Hex,
        ),
        ("0x-outer-ws", "  0xdead  ".into(), vec![0xde, 0xad], Hex),
        // base64 (auto + forced)
        ("b64-auto", "SGVsbG8=".into(), b"Hello".to_vec(), Base64),
        ("b64-auto-ws", "SGVs bG8=".into(), b"Hello".to_vec(), Base64),
        (
            "b64-auto-multiline",
            "SGVs\nbG8=\n".into(),
            b"Hello".to_vec(),
            Base64,
        ),
        ("b64-no-padding", "TWFu".into(), b"Man".to_vec(), Base64),
        (
            "b64-prefix",
            "b64:SGVsbG8=".into(),
            b"Hello".to_vec(),
            Base64,
        ),
        (
            "b64-prefix-ws",
            "b64: SGVs bG8=\n".into(),
            b"Hello".to_vec(),
            Base64,
        ),
        // ambiguity rule: hex beats base64; b64: forces the other reading
        ("ambiguous-is-hex", "deadbeef".into(), deadbeef.clone(), Hex),
        (
            "ambiguous-forced-b64",
            "b64:deadbeef".into(),
            STANDARD.decode("deadbeef").unwrap(),
            Base64,
        ),
        // PEM: canonical, mangled line breaks, quoted multiline, surrounding chatter
        (
            "pem-canonical",
            cert.clone(),
            cert.clone().into_bytes(),
            Pem,
        ),
        (
            "pem-one-line",
            cert.replace('\n', " "),
            cert.clone().into_bytes(),
            Pem,
        ),
        (
            "pem-extra-blank-lines",
            cert.replace('\n', "\n\n"),
            cert.clone().into_bytes(),
            Pem,
        ),
        (
            "pem-leading-chatter",
            format!("here is my cert:\n{cert}"),
            cert.clone().into_bytes(),
            Pem,
        ),
        (
            "pem-multi-block",
            bundle.replace('\n', " "),
            bundle.clone().into_bytes(),
            Pem,
        ),
        (
            "pem-prefix",
            format!("pem:{}", cert.replace('\n', " ")),
            cert.clone().into_bytes(),
            Pem,
        ),
        // hex-wrapped and base64-wrapped PEM re-parse as PEM
        (
            "hex-wrapped-pem",
            hex::encode(&cert),
            cert.clone().into_bytes(),
            Pem,
        ),
        (
            "hex-wrapped-pem-ws",
            chunks_joined(&hex::encode(&cert), 32, "\n"),
            cert.clone().into_bytes(),
            Pem,
        ),
        (
            "b64-wrapped-pem",
            STANDARD.encode(&cert),
            cert.clone().into_bytes(),
            Pem,
        ),
        (
            "hex-wrapped-pem-bundle",
            hex::encode_upper(&bundle),
            bundle.clone().into_bytes(),
            Pem,
        ),
    ];
    assert_eq!(matrix.len(), 30);
    for (id, text, expected, format) in matrix {
        let (data, detected) = decode_data(&text).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        assert_eq!(*data, expected, "{id}");
        assert_eq!(detected, format, "{id}");
    }
}

// --- malformed inputs → CodecError -------------------------------------------

#[test]
fn test_decode_malformed_raises_codec_error() {
    let malformed: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("whitespace-only", " \t\r\n ".into()),
        ("odd-hex", "abc".into()),
        ("not-anything", "hello world!".into()),
        ("equals-only", "====".into()),
        ("b64-bad-length", "SGVsbG8".into()), // 7 chars: neither hex nor %4 base64
        ("hex-prefix-empty", "hex:".into()),
        ("hex-prefix-nonhex", "hex:xyz".into()),
        ("hex-prefix-odd", "hex:abc".into()),
        ("0x-odd", "0x123".into()),
        ("0x-empty", "0x".into()),
        ("b64-prefix-empty", "b64:".into()),
        ("b64-prefix-garbage", "b64:@@@@".into()),
        ("b64-prefix-bad-length", "b64:abc".into()),
        ("pem-prefix-no-block", "pem:not a pem at all".into()),
        (
            "pem-missing-end",
            "-----BEGIN CERTIFICATE-----\nAAAA".into(),
        ),
        (
            "pem-label-mismatch",
            "-----BEGIN FOO-----\nAAAA\n-----END BAR-----".into(),
        ),
        (
            "pem-bad-body",
            "-----BEGIN FOO-----\n@@@@\n-----END FOO-----".into(),
        ),
        (
            "pem-truncated-body",
            "-----BEGIN FOO-----\nAAA\n-----END FOO-----".into(),
        ),
        (
            "hex-wrapped-malformed-pem",
            hex::encode("-----BEGIN FOO----- not base64 @@ -----END FOO-----"),
        ),
    ];
    assert_eq!(malformed.len(), 20);
    for (id, text) in malformed {
        let err = decode_data(&text).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Codec, "{id}");
        assert_eq!(err.kind.class_name(), "CodecError", "{id}");
    }
}

#[test]
fn test_unrecognized_input_message_and_hint_are_frozen() {
    let err = decode_data("hello world!").unwrap_err();
    assert_eq!(err.message, "not hex, base64 or PEM");
    assert_eq!(
        err.hint.as_deref(),
        Some("force with hex:/b64:/pem: prefix")
    );
}

#[test]
fn test_prefix_failure_never_falls_back() {
    // "SGVsbG8=" would decode fine as base64, but the hex-forced reading fails and must NOT
    // fall back to any other branch.
    assert_eq!(
        decode_data("hex:SGVsbG8=").unwrap_err().kind,
        ErrorKind::Codec
    );
    assert_eq!(decode_data("b64:zz").unwrap_err().kind, ErrorKind::Codec);
}

/// Every codec message and hint of spec §4.4.1, verbatim.
#[test]
fn codec_messages_and_hints_are_c2_verbatim() {
    let pem_hint = "a PEM block is '-----BEGIN <LABEL>----- … -----END <LABEL>-----'";
    let cases: Vec<(String, &str, Option<&str>)> = vec![
        (
            "".into(),
            "empty input",
            Some("paste hex, base64 or PEM data"),
        ),
        ("hex:".into(), "hex prefix given but no data follows", None),
        ("0x  ".into(), "hex prefix given but no data follows", None),
        (
            "hex:abc".into(),
            "forced hex decode failed",
            Some("hex is an even number of [0-9a-fA-F] digits (whitespace ignored)"),
        ),
        ("b64:".into(), "b64 prefix given but no data follows", None),
        (
            "b64:abc".into(),
            "forced base64 decode failed",
            Some("base64 uses [A-Za-z0-9+/] with '=' padding to a multiple of 4"),
        ),
        (
            "pem:nothing".into(),
            "malformed PEM: no complete BEGIN/END block found",
            Some(pem_hint),
        ),
        (
            "-----BEGIN FOO-----\nAAAA\n-----END BAR-----".into(),
            "malformed PEM: 'BEGIN FOO' closed by 'END BAR'",
            None,
        ),
        (
            "-----BEGIN FOO-----\n@@@@\n-----END FOO-----".into(),
            "malformed PEM: body of the FOO block is not valid base64",
            None,
        ),
        (
            hex::encode("-----BEGIN X-----\u{e9}-----END X-----"),
            "data looks like hex-wrapped PEM but is not ASCII text",
            None,
        ),
        (
            STANDARD.encode("-----BEGIN X-----\u{e9}-----END X-----"),
            "data looks like base64-wrapped PEM but is not ASCII text",
            None,
        ),
    ];
    for (text, message, hint) in cases {
        let err = decode_data(&text).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Codec, "{text:?}");
        assert_eq!(err.message, message, "{text:?}");
        assert_eq!(err.hint.as_deref(), hint, "{text:?}");
    }
}

// --- PEM details --------------------------------------------------------------

#[test]
fn test_pem_returns_rewrapped_text_not_der() {
    let (data, format) = decode_data(&cert_pem().replace('\n', " ")).unwrap();
    assert_eq!(format, InputFormat::Pem);
    assert!(data.starts_with(b"-----BEGIN CERTIFICATE-----"));
    assert_ne!(*data, der_big()); // never the decoded DER
    let text = std::str::from_utf8(&data).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let body: String = lines[1..lines.len() - 1].concat();
    assert_eq!(STANDARD.decode(body).unwrap(), der_big());
    assert!(lines.iter().all(|line| line.len() <= 64));
}

#[test]
fn pem_body_with_a_long_padding_run_rewraps_like_c2() {
    // c2: `decode_data("-----BEGIN X-----\nAAAA" + "=" * 300 + "\n-----END X-----\n")`.
    let input = format!(
        "-----BEGIN X-----\nAAAA{}\n-----END X-----\n",
        "=".repeat(300)
    );
    let (data, format) = decode_data(&input).unwrap();
    assert_eq!(format, InputFormat::Pem);
    let expected = format!(
        "-----BEGIN X-----\nAAAA{}\n{}\n{}\n{}\n{}\n-----END X-----\n",
        "=".repeat(60),
        "=".repeat(64),
        "=".repeat(64),
        "=".repeat(64),
        "=".repeat(48),
    );
    assert_eq!(std::str::from_utf8(&data).unwrap(), expected);
    // A single data character before the run is malformed, as in c2.
    let bad = format!("-----BEGIN X-----\nA{}\n-----END X-----\n", "=".repeat(300));
    let err = decode_data(&bad).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Codec);
    assert_eq!(
        err.message,
        "malformed PEM: body of the X block is not valid base64"
    );
}

#[test]
fn test_pem_multi_block_bundle_survives_as_text() {
    let (data, format) = decode_data(&bundle_pem().replace('\n', " ")).unwrap();
    assert_eq!(format, InputFormat::Pem);
    let text = std::str::from_utf8(&data).unwrap();
    assert_eq!(text.matches("-----BEGIN ").count(), 2);
    assert!(text.contains("-----BEGIN CERTIFICATE-----"));
    assert!(text.contains("-----BEGIN RSA PRIVATE KEY-----"));
    // order preserved
    assert!(text.find("CERTIFICATE").unwrap() < text.find("RSA PRIVATE KEY").unwrap());
}

/// pem body of a PKCS#8 PEM → DER, without the (disallowed, TTY-prompting) PEM loaders.
fn pem_body_der(pem: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(pem).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    STANDARD.decode(lines[1..lines.len() - 1].concat()).unwrap()
}

#[test]
fn test_real_pyca_pem_survives_mangling_and_reloads() {
    let key = PKey::generate_ed25519().unwrap();
    let pem = key.private_key_to_pem_pkcs8().unwrap();
    let mangled = std::str::from_utf8(&pem).unwrap().replace('\n', "   ");
    let (data, format) = decode_data(&mangled).unwrap();
    assert_eq!(format, InputFormat::Pem);
    assert_eq!(*data, pem); // canonical re-wrap = OpenSSL's own PEM
    let reloaded = PKey::private_key_from_der(&pem_body_der(&data)).unwrap();
    assert_eq!(
        reloaded.raw_private_key().unwrap(),
        key.raw_private_key().unwrap()
    );
}

// --- l13 hardening: RFC 1421 headers --------------------------------------------

fn p256_key() -> PKey<openssl::pkey::Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

#[test]
fn test_headerless_pem_rewrap_unchanged_by_header_support() {
    let pem = p256_key().private_key_to_pem_pkcs8().unwrap();
    let mangled = std::str::from_utf8(&pem).unwrap().replace('\n', "  ");
    let (data, format) = decode_data(&mangled).unwrap();
    assert_eq!(format, InputFormat::Pem);
    let text = std::str::from_utf8(&data).unwrap();
    assert!(!text.contains("Proc-Type"));
    let lines: Vec<&str> = text.lines().collect();
    let body_lines = &lines[1..lines.len() - 1];
    assert!(body_lines.iter().all(|line| line.len() <= 64));
    assert!(!body_lines.contains(&"")); // no stray blank header separator
}

#[test]
fn test_headers_without_body_raise_codec_error() {
    let text = concat!(
        "-----BEGIN RSA PRIVATE KEY-----\n",
        "Proc-Type: 4,ENCRYPTED\n",
        "DEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n",
        "\n",
        "-----END RSA PRIVATE KEY-----\n",
    );
    let err = decode_data(text).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Codec);
    assert!(
        err.message.contains("headers but no base64 body"),
        "{}",
        err.message
    );
    assert_eq!(
        err.message,
        "malformed PEM: the RSA PRIVATE KEY block has encapsulated headers but no base64 body"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("paste the block with its line breaks intact")
    );
}

/// The decode half of c2's l13 encrypted-traditional-PEM cases (the keyparse half is R6's):
/// RFC 1421 headers survive the re-wrap, a blank line closes them, and an indented paste
/// re-wraps to the same canonical text.
#[test]
fn traditional_encrypted_pem_keeps_its_headers() {
    let ec = p256_key().ec_key().unwrap();
    let pem = ec
        .private_key_to_pem_passphrase(Cipher::aes_256_cbc(), b"s3cret")
        .unwrap();
    let pem = String::from_utf8(pem).unwrap();
    assert!(pem.contains("Proc-Type: 4,ENCRYPTED"));
    let (data, format) = decode_data(&pem).unwrap();
    assert_eq!(format, InputFormat::Pem);
    let text = std::str::from_utf8(&data).unwrap();
    assert_eq!(text, pem); // OpenSSL's layout is already canonical
    assert!(text.contains("Proc-Type: 4,ENCRYPTED"));
    assert!(text.contains("DEK-Info: "));
    let header_end = text.find("DEK-Info").unwrap();
    assert!(text[header_end..].contains("\n\n")); // RFC 1421: blank line closes headers

    let indented: String = pem
        .lines()
        .map(|line| format!("   {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    let (data, format) = decode_data(&indented).unwrap();
    assert_eq!(format, InputFormat::Pem);
    assert_eq!(std::str::from_utf8(&data).unwrap(), pem);
}

// --- format_hex ----------------------------------------------------------------

#[test]
fn test_format_hex_empty() {
    assert_eq!(format_hex(b"", 2, 32), "");
}

#[test]
fn test_format_hex_default_grouping() {
    let data = hex::decode("deadbeef00112233").unwrap();
    assert_eq!(format_hex(&data, 2, 32), "dead beef 0011 2233");
}

#[test]
fn test_format_hex_group_and_width() {
    let data = hex::decode("deadbeef00112233").unwrap();
    assert_eq!(format_hex(&data, 2, 4), "dead beef\n0011 2233");
    assert_eq!(format_hex(&data, 1, 0), "de ad be ef 00 11 22 33");
}

#[test]
fn test_format_hex_group_zero_is_continuous() {
    let data = hex::decode("deadbeef00112233").unwrap();
    assert_eq!(format_hex(&data, 0, 0), "deadbeef00112233");
    assert_eq!(format_hex(&data, 0, 4), "deadbeef\n00112233");
}

#[test]
fn test_format_hex_partial_tail_group() {
    assert_eq!(
        format_hex(&hex::decode("deadbeefaa").unwrap(), 2, 0),
        "dead beef aa"
    );
}

#[test]
fn test_format_hex_is_lowercase() {
    assert_eq!(format_hex(&[0xde, 0xad], 0, 0), "dead");
}

#[test]
fn input_format_tokens() {
    assert_eq!(InputFormat::Hex.as_str(), "hex");
    assert_eq!(InputFormat::Base64.as_str(), "base64");
    assert_eq!(InputFormat::Pem.as_str(), "pem");
}

/// Differential vectors: c2's decode_data outcome for tricky inputs (RFC 1421 header
/// shapes, CRLF, Unicode whitespace, strict base64 padding, label grammar, wrapped PEM).
/// c2 crashed (uncaught ValueError) on a non-ASCII PEM body; r2 reports it as the
/// "not valid base64" CodecError instead.
#[test]
fn decode_data_matches_c2_on_differential_vectors() {
    for (text, expected) in codec_vectors::DECODE {
        let got = decode_data(text);
        match expected {
            Ok((data_hex, format)) => {
                let (data, detected) = got.unwrap_or_else(|e| panic!("{text:?}: {e:?}"));
                assert_eq!(hex::encode(&*data), *data_hex, "{text:?}");
                assert_eq!(detected.as_str(), *format, "{text:?}");
            }
            Err((message, hint)) if message.starts_with("<c2 crash") => {
                let err = got.unwrap_err();
                assert_eq!(err.kind, ErrorKind::Codec, "{text:?}");
                assert_eq!(
                    err.message,
                    "malformed PEM: body of the X block is not valid base64"
                );
                assert_eq!(err.hint.as_deref(), *hint);
            }
            Err((message, hint)) => {
                let err = got.unwrap_err();
                assert_eq!(err.kind, ErrorKind::Codec, "{text:?}");
                assert_eq!(err.message, *message, "{text:?}");
                assert_eq!(err.hint.as_deref(), *hint, "{text:?}");
            }
        }
    }
}

/// §11 D12 (e): non-ASCII text in a PEM block. In the body it is invalid base64 (c2
/// crashed); in an RFC 1421 header line it is kept and the re-wrap is UTF-8 (c2 crashed).
#[test]
fn non_ascii_inside_pem_blocks() {
    let err = decode_data("-----BEGIN X-----\nAAAAé\n-----END X-----").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Codec);
    assert_eq!(
        err.message,
        "malformed PEM: body of the X block is not valid base64"
    );
    let (data, format) =
        decode_data("-----BEGIN X-----\nDEK-Info: é\n\nAA AA\n-----END X-----").unwrap();
    assert_eq!(format, InputFormat::Pem);
    assert_eq!(
        std::str::from_utf8(&data).unwrap(),
        "-----BEGIN X-----\nDEK-Info: é\n\nAAAA\n-----END X-----\n"
    );
}
