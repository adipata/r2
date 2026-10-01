//! DataInput / DataOutput tests (spec §4.4.2) — port of c2
//! `tests/unit/core/test_datainput.py`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use r2_core::datainput::{DataInput, DataOutput, InFormat, OutFormat};
use r2_core::error::ErrorKind;
use r2_core::io::Renderable;
use r2_testkit::ScriptedIo;

fn binary() -> Vec<u8> {
    (0..=255).collect()
}

fn temp_file(dir: &tempfile::TempDir, name: &str, content: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, content).unwrap();
    path
}

// --- DataInput: inline -------------------------------------------------------

#[test]
fn test_inline_hex() {
    let src = DataInput::inline("deadbeef");
    assert_eq!(src.origin, "inline");
    assert_eq!(*src.resolve().unwrap(), [0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn test_inline_goes_through_decode_data_prefixes() {
    assert_eq!(
        *DataInput::inline("hex: de ad").resolve().unwrap(),
        [0xde, 0xad]
    );
    assert_eq!(
        *DataInput::inline("b64:SGVsbG8=").resolve().unwrap(),
        *b"Hello"
    );
}

#[test]
fn test_inline_malformed_raises_codec_error() {
    let err = DataInput::inline("not decodable!").resolve().unwrap_err();
    assert_eq!(err.kind, ErrorKind::Codec);
}

// --- DataInput: file ---------------------------------------------------------

#[test]
fn test_file_defaults_to_auto_and_origin_is_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(&dir, "in.bin", b"\x00");
    let src = DataInput::file(&path, InFormat::default());
    assert_eq!(src.fmt, InFormat::Auto);
    assert_eq!(src.origin, path.display().to_string());
    assert_eq!(src.path.as_deref(), Some(path.as_path()));
    assert_eq!(src.token, None);
}

#[test]
fn test_file_raw_is_verbatim() {
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(&dir, "in.bin", &binary());
    assert_eq!(
        *DataInput::file(&path, InFormat::Raw).resolve().unwrap(),
        binary()
    );
}

#[test]
fn test_file_raw_even_for_decodable_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(&dir, "in.txt", b"deadbeef");
    assert_eq!(
        *DataInput::file(&path, InFormat::Raw).resolve().unwrap(),
        *b"deadbeef"
    );
}

#[test]
fn test_file_auto_decodes_hex_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(&dir, "in.txt", b"de ad be ef\n");
    assert_eq!(
        *DataInput::file(&path, InFormat::Auto).resolve().unwrap(),
        [0xde, 0xad, 0xbe, 0xef]
    );
}

#[test]
fn test_file_auto_decodes_base64_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(&dir, "in.txt", b"SGVsbG8=\n");
    assert_eq!(
        *DataInput::file(&path, InFormat::Auto).resolve().unwrap(),
        *b"Hello"
    );
}

#[test]
fn test_file_auto_pem_returns_rewrapped_text_bytes() {
    let body = STANDARD.encode([1u8, 2, 3]);
    let pem = format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n");
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(&dir, "cert.pem", pem.replace('\n', " ").as_bytes()); // mangled
    assert_eq!(
        *DataInput::file(&path, InFormat::Auto).resolve().unwrap(),
        *pem.as_bytes()
    );
}

#[test]
fn test_file_auto_binary_falls_back_to_raw() {
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(&dir, "in.bin", &binary());
    assert_eq!(
        *DataInput::file(&path, InFormat::Auto).resolve().unwrap(),
        binary()
    );
}

#[test]
fn test_file_auto_undecodable_text_falls_back_to_raw() {
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(&dir, "in.txt", b"hello world!\n");
    assert_eq!(
        *DataInput::file(&path, InFormat::Auto).resolve().unwrap(),
        *b"hello world!\n"
    );
}

/// r2: auto mode treats text with a non-printable ASCII byte (e.g. \x0b) as binary, and
/// a decodable-looking non-ASCII file as raw (c2 `_is_printable_ascii`).
#[test]
fn file_auto_requires_printable_ascii() {
    let dir = tempfile::tempdir().unwrap();
    let vt = temp_file(&dir, "vt.txt", b"dead\x0bbeef");
    assert_eq!(
        *DataInput::file(&vt, InFormat::Auto).resolve().unwrap(),
        *b"dead\x0bbeef"
    );
    let tabs = temp_file(&dir, "tabs.txt", b"de\tad\r\n");
    assert_eq!(
        *DataInput::file(&tabs, InFormat::Auto).resolve().unwrap(),
        [0xde, 0xad]
    );
    let utf8 = temp_file(&dir, "u.txt", "dead\u{a0}beef".as_bytes());
    assert_eq!(
        *DataInput::file(&utf8, InFormat::Auto).resolve().unwrap(),
        *"dead\u{a0}beef".as_bytes()
    );
}

#[test]
fn test_file_forced_hex() {
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(&dir, "in.hex", b"de ad\nbe ef\n");
    assert_eq!(
        *DataInput::file(&path, InFormat::Hex).resolve().unwrap(),
        [0xde, 0xad, 0xbe, 0xef]
    );
}

#[test]
fn test_file_forced_b64() {
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(&dir, "in.b64", b"SGVs bG8=\n");
    assert_eq!(
        *DataInput::file(&path, InFormat::B64).resolve().unwrap(),
        *b"Hello"
    );
}

#[test]
fn test_file_forced_hex_garbage_raises_codec_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(&dir, "in.hex", b"not hex at all!");
    let err = DataInput::file(&path, InFormat::Hex).resolve().unwrap_err();
    assert_eq!(err.kind, ErrorKind::Codec);
    assert_eq!(err.message, "forced hex decode failed");
}

#[test]
fn test_file_forced_hex_on_binary_raises_codec_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(&dir, "in.bin", b"\xff\xfe\x00");
    let err = DataInput::file(&path, InFormat::Hex).resolve().unwrap_err();
    assert_eq!(err.kind, ErrorKind::Codec);
    assert_eq!(
        err.message,
        format!("{}: file is not text, cannot decode as hex", path.display())
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("use --format raw for binary files")
    );
    let err = DataInput::file(&path, InFormat::B64).resolve().unwrap_err();
    assert!(
        err.message.ends_with("cannot decode as b64"),
        "{}",
        err.message
    );
}

#[test]
fn test_file_missing_raises_data_io_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nope.bin");
    let err = DataInput::file(&path, InFormat::Auto)
        .resolve()
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::DataIo);
    assert!(err.message.contains(&path.display().to_string()));
    #[cfg(unix)]
    assert_eq!(
        err.message,
        format!("cannot read {}: No such file or directory", path.display())
    );
}

#[test]
fn data_input_without_token_or_path_is_a_data_io_error() {
    let src = DataInput {
        origin: "inline".to_owned(),
        token: None,
        path: None,
        fmt: InFormat::Auto,
    };
    let err = src.resolve().unwrap_err();
    assert_eq!(err.kind, ErrorKind::DataIo);
    assert_eq!(
        err.message,
        "data input has neither an inline token nor a file path"
    );
}

// --- DataOutput: console -----------------------------------------------------

#[test]
fn test_console_write_renders_grouped_hex() {
    let io = ScriptedIo::empty();
    DataOutput::console(2, 4)
        .write(&hex::decode("deadbeef00112233").unwrap(), &io)
        .unwrap();
    assert_eq!(io.output(), ["dead beef\n0011 2233"]);
    assert_eq!(
        io.renderables(),
        [Renderable::Text("dead beef\n0011 2233".to_owned())]
    );
}

#[test]
fn test_console_defaults() {
    // c2 `DataOutput.console()` defaults = the ui.hex_group / ui.hex_width defaults.
    let out = DataOutput::console(2, 32);
    assert_eq!(out.path, None);
    assert_eq!(out.hex_group, 2);
    assert_eq!(out.hex_width, 32);
    let io = ScriptedIo::empty();
    out.write(&[0xde, 0xad], &io).unwrap();
    assert_eq!(io.output(), ["dead"]);
    // DataOutput::file keeps the same console defaults.
    let file = DataOutput::file("x", OutFormat::Raw);
    assert_eq!((file.hex_group, file.hex_width), (2, 32));
}

// --- DataOutput: file --------------------------------------------------------

#[test]
fn test_file_write_raw() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.bin");
    DataOutput::file(&path, OutFormat::Raw)
        .write(&binary(), &ScriptedIo::empty())
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), binary());
}

#[test]
fn test_file_write_hex_is_continuous_with_newline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.hex");
    let data = hex::decode("deadbeef00112233").unwrap();
    DataOutput::file(&path, OutFormat::Hex)
        .write(&data, &ScriptedIo::empty())
        .unwrap();
    // no grouping in files
    assert_eq!(std::fs::read(&path).unwrap(), b"deadbeef00112233\n");
}

#[test]
fn test_file_write_b64_with_newline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.b64");
    DataOutput::file(&path, OutFormat::B64)
        .write(b"Hello", &ScriptedIo::empty())
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"SGVsbG8=\n");
}

#[test]
fn test_file_write_failure_raises_data_io_error() {
    let dir = tempfile::tempdir().unwrap();
    // path is a directory
    let err = DataOutput::file(dir.path(), OutFormat::Raw)
        .write(b"x", &ScriptedIo::empty())
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::DataIo);
    assert!(err.message.contains(&dir.path().display().to_string()));
    #[cfg(unix)]
    assert_eq!(
        err.message,
        format!("cannot write {}: Is a directory", dir.path().display())
    );
}

#[test]
fn format_tokens_display_and_parse() {
    for (fmt, token) in [
        (InFormat::Auto, "auto"),
        (InFormat::Raw, "raw"),
        (InFormat::Hex, "hex"),
        (InFormat::B64, "b64"),
    ] {
        assert_eq!(fmt.as_str(), token);
        assert_eq!(fmt.to_string(), token);
        assert_eq!(token.parse::<InFormat>().unwrap(), fmt);
    }
    for (fmt, token) in [
        (OutFormat::Raw, "raw"),
        (OutFormat::Hex, "hex"),
        (OutFormat::B64, "b64"),
    ] {
        assert_eq!(fmt.as_str(), token);
        assert_eq!(fmt.to_string(), token);
        assert_eq!(token.parse::<OutFormat>().unwrap(), fmt);
    }
    assert_eq!(OutFormat::default(), OutFormat::Raw);
    let err = "auto".parse::<OutFormat>().unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(err.message, "unknown format 'auto'");
    assert_eq!(
        "HEX".parse::<InFormat>().unwrap_err().message,
        "unknown format 'HEX'"
    );
}
