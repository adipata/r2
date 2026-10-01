//! Message-parity helpers (spec §4.2 `r2_core::text`): every vector is CPython 3.12's
//! output (tests/support/gen_text_vectors.py, run in c2's interpreter). r2 addition — c2 had
//! no separate tests for these Python built-ins.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

#[path = "support/text_vectors.rs"]
mod text_vectors;

use std::path::Path;

use r2_core::text::{
    close_matches, is_py_space, os_error_text, py_bool, py_bytes_repr, py_fromhex, py_int,
    py_isdigit, py_os_error_str, py_path, py_repr, py_strip,
};

#[test]
fn py_repr_matches_cpython() {
    for (text, expected) in text_vectors::PY_REPR {
        assert_eq!(py_repr(text), *expected, "repr of {text:?}");
    }
}

/// Every non-printable range boundary of the committed table round-trips through repr as an
/// escape, and its printable neighbours verbatim (spot checks of the 712-range table).
#[test]
fn py_repr_escapes_by_the_cpython_printable_table() {
    // (code point, printable in CPython 3.12 / Unicode 15.0)
    let probes: &[(u32, bool)] = &[
        (0x20, true),
        (0x7e, true),
        (0xa1, true),
        (0xad, false),
        (0x377, true),
        (0x378, false),
        (0x61c, false),
        (0x1680, false),
        (0x2000, false),
        (0x2010, true),
        (0x2028, false),
        (0x3000, false),
        (0x3001, true),
        (0xd7a3, true),
        (0xe000, false),
        (0xfdd0, false),
        (0xfffd, true),
        (0xffff, false),
        (0x1f600, true),
        (0x1fbca, true),
        (0x1fbcb, false),
        (0x2a6df, true),
        (0x323af, true),
        (0x323b0, false),
        (0xe0100, true),
        (0xe01ef, true),
        (0xe01f0, false),
        (0x10ffff, false),
    ];
    for &(code, printable) in probes {
        let c = char::from_u32(code).unwrap();
        let repr = py_repr(&c.to_string());
        if printable {
            assert_eq!(repr, format!("'{c}'"), "U+{code:04X}");
        } else {
            let escaped = if code <= 0xff {
                format!("'\\x{code:02x}'")
            } else if code <= 0xffff {
                format!("'\\u{code:04x}'")
            } else {
                format!("'\\U{code:08x}'")
            };
            assert_eq!(repr, escaped, "U+{code:04X}");
        }
    }
}

#[test]
fn py_bytes_repr_matches_cpython() {
    for (data, expected) in text_vectors::PY_BYTES_REPR {
        assert_eq!(py_bytes_repr(data), *expected, "repr of {data:?}");
    }
}

#[test]
fn py_bool_is_python_str() {
    assert_eq!(py_bool(true), "True");
    assert_eq!(py_bool(false), "False");
}

/// `str.isspace()` over the whole code space = `char::is_whitespace` plus U+001C..=U+001F
/// (CPython: 0x9-0xd 0x1c-0x20 0x85 0xa0 0x1680 0x2000-0x200a 0x2028 0x2029 0x202f 0x205f
/// 0x3000).
#[test]
fn is_py_space_matches_str_isspace() {
    let expected: Vec<u32> = [
        0x9, 0xa, 0xb, 0xc, 0xd, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001,
        0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029,
        0x202f, 0x205f, 0x3000,
    ]
    .to_vec();
    let got: Vec<u32> = (0..=0x10ffffu32)
        .filter_map(char::from_u32)
        .filter(|&c| is_py_space(c))
        .map(u32::from)
        .collect();
    assert_eq!(got, expected);
}

#[test]
fn py_strip_trims_python_whitespace_only() {
    assert_eq!(py_strip("  a b \t\n"), "a b");
    assert_eq!(py_strip("\u{1c}x\u{1f}"), "x"); // str::trim keeps these
    assert_eq!(py_strip("\u{a0}\u{3000}x\u{2028}"), "x");
    assert_eq!(py_strip("\u{200b}x"), "\u{200b}x"); // ZWSP is not whitespace
    assert_eq!(py_strip(""), "");
    assert_eq!(py_strip(" \t "), "");
}

#[test]
fn py_fromhex_matches_bytes_fromhex() {
    for (text, expected) in text_vectors::PY_FROMHEX {
        assert_eq!(py_fromhex(text).as_deref(), *expected, "fromhex {text:?}");
    }
}

#[test]
fn py_int_matches_int_with_radix() {
    for &(text, decimal, hexadecimal) in text_vectors::PY_INT {
        assert_eq!(py_int(text, 10), decimal, "int({text:?}, 10)");
        assert_eq!(py_int(text, 16), hexadecimal, "int({text:?}, 16)");
    }
    // Only radix 10 and 16 are supported.
    assert_eq!(py_int("7", 8), None);
}

#[test]
fn py_isdigit_is_ascii_digits_only() {
    assert!(py_isdigit("0"));
    assert!(py_isdigit("02"));
    assert!(py_isdigit("1234567890"));
    for text in ["", "+2", "-0", "1_0", " 1", "1 ", "²", "٣", "0x1", "1.0"] {
        assert!(!py_isdigit(text), "{text:?}");
    }
}

#[test]
fn py_path_matches_pure_posix_path() {
    if cfg!(windows) {
        return; // POSIX vectors; the Windows flavor is unit-tested inside text.rs
    }
    for (text, expected) in text_vectors::PY_PATH_POSIX {
        assert_eq!(py_path(text), Path::new(expected), "Path({text:?})");
        assert_eq!(py_path(text).display().to_string(), *expected);
    }
}

/// The spec §4.2 vectors (generated with CPython) plus generator extras.
#[test]
fn close_matches_matches_difflib() {
    for &(word, possibilities, n, expected) in text_vectors::CLOSE_MATCHES {
        assert_eq!(
            close_matches(word, possibilities, n),
            expected.to_vec(),
            "get_close_matches({word:?}, …, n={n})"
        );
    }
    // The result does not depend on the order of the possibilities.
    let mut reversed = vec!["sha512", "sha384", "sha256", "sha224", "sha1"];
    assert_eq!(
        close_matches("sha", &reversed, 3),
        ["sha1", "sha512", "sha384"]
    );
    reversed.sort();
    assert_eq!(
        close_matches("sha", &reversed, 3),
        ["sha1", "sha512", "sha384"]
    );
    assert!(close_matches("sha", &reversed, 0).is_empty());
}

#[cfg(unix)]
#[test]
fn os_error_texts_match_python_oserror() {
    let err = std::io::Error::from_raw_os_error(2);
    assert_eq!(os_error_text(&err), "No such file or directory");
    assert_eq!(
        py_os_error_str(&err, Path::new("/p")),
        "[Errno 2] No such file or directory: '/p'"
    );
    let err = std::io::Error::from_raw_os_error(13);
    assert_eq!(
        py_os_error_str(&err, Path::new("it's")),
        "[Errno 13] Permission denied: \"it's\""
    );
    // Without an OS error code: the error text alone.
    let err = std::io::Error::other("custom failure");
    assert_eq!(os_error_text(&err), "custom failure");
    assert_eq!(py_os_error_str(&err, Path::new("/p")), "custom failure");
    // A real failure from the file system.
    let err = std::fs::read("/nonexistent/r2/path").unwrap_err();
    assert_eq!(os_error_text(&err), "No such file or directory");
}
