// Tokenizer + binder tables (spec §4.9.7) — the port of c2 tests/unit/console/test_parser.py
// (R7). Positions are BYTE offsets (identical to c2's char indices for ASCII; the non-ASCII
// cases below are r2 additions, converted explicitly).
use indexmap::IndexMap;
use r2_core::error::ErrorKind;

use crate::parser::{BoundArgs, OptValue, bind_args, line_is_complete, tokenize};

fn triples(line: &str) -> Vec<(String, bool, usize)> {
    tokenize(line)
        .unwrap()
        .into_iter()
        .map(|t| (t.text, t.quoted, t.pos))
        .collect()
}

fn owned(expected: &[(&str, bool, usize)]) -> Vec<(String, bool, usize)> {
    expected
        .iter()
        .map(|(text, quoted, pos)| ((*text).to_owned(), *quoted, *pos))
        .collect()
}

// ---------------------------------------------------------------------------
// tokenizer
// ---------------------------------------------------------------------------

#[test]
fn test_tokenize_table() {
    type Row<'a> = (&'a str, Vec<(&'a str, bool, usize)>);
    let table: Vec<Row<'_>> = vec![
        ("", vec![]),
        ("   \t \n ", vec![]),
        ("help", vec![("help", false, 0)]),
        ("keys mem", vec![("keys", false, 0), ("mem", false, 5)]),
        // newlines are unquoted whitespace
        ("a\nb", vec![("a", false, 0), ("b", false, 2)]),
        // quotes delimit one token preserving inner whitespace verbatim
        (
            "load \"de ad\"",
            vec![("load", false, 0), ("de ad", true, 5)],
        ),
        ("load 'de ad'", vec![("load", false, 0), ("de ad", true, 5)]),
        // newline INSIDE quotes stays in the token
        ("e \"l1\nl2\"", vec![("e", false, 0), ("l1\nl2", true, 2)]),
        // empty quoted token
        ("x \"\"", vec![("x", false, 0), ("", true, 2)]),
        // backslash escapes only the active quote char and backslash
        ("\"a\\\"b\"", vec![("a\"b", true, 0)]),
        ("\"a\\\\b\"", vec![("a\\b", true, 0)]),
        ("'don\\'t'", vec![("don't", true, 0)]),
        // non-escape backslash sequences stay verbatim
        ("\"a\\nb\"", vec![("a\\nb", true, 0)]),
        // the other quote char is literal inside quotes
        ("\"don't\"", vec![("don't", true, 0)]),
        // a quote char inside an unquoted token is literal
        ("don't", vec![("don't", false, 0)]),
        // a closing quote ends the token; the rest starts a new one
        ("\"abc\"def", vec![("abc", true, 0), ("def", false, 5)]),
        // positions with multiple spaces
        (
            "a  \"b c\"  d",
            vec![("a", false, 0), ("b c", true, 3), ("d", false, 10)],
        ),
    ];
    assert_eq!(table.len(), 17); // the 17 c2 parametrizations
    for (line, expected) in table {
        assert_eq!(triples(line), owned(&expected), "{line:?}");
    }
}

#[test]
fn tokenize_closing_quote_rules_and_token_ends() {
    // c2 parser.py: `"a"b` → [a quoted, b]; `"a""b"` → [a quoted, b quoted]; `x"y"` → one
    // unquoted token.
    assert_eq!(triples("\"a\"b"), owned(&[("a", true, 0), ("b", false, 3)]));
    assert_eq!(
        triples("\"a\"\"b\""),
        owned(&[("a", true, 0), ("b", true, 3)])
    );
    assert_eq!(triples("x\"y\""), owned(&[("x\"y\"", false, 0)]));
    // `end` is the byte offset after the raw token (closing quote included)
    let ends: Vec<(usize, usize)> = tokenize("ab  \"c d\" 'e'")
        .unwrap()
        .iter()
        .map(|t| (t.pos, t.end))
        .collect();
    assert_eq!(ends, [(0, 2), (4, 9), (10, 13)]);
    // Python str.isspace: U+001F and NBSP separate tokens, as in c2
    assert_eq!(
        triples("a\u{1f}b\u{a0}c"),
        owned(&[("a", false, 0), ("b", false, 2), ("c", false, 5)])
    );
}

#[test]
fn tokenize_positions_are_byte_offsets() {
    // c2 char indices 0, 5 ("ключ") and 10 → bytes 0, 9, 18.
    let line = "ключ \"é x\" z";
    let tokens = tokenize(line).unwrap();
    let got: Vec<(&str, usize, usize)> = tokens
        .iter()
        .map(|t| (t.text.as_str(), t.pos, t.end))
        .collect();
    assert_eq!(got, [("ключ", 0, 8), ("é x", 9, 15), ("z", 16, 17)]);
    assert_eq!(&line[tokens[1].pos..tokens[1].end], "\"é x\"");
}

#[test]
fn test_tokenize_unterminated_quote_caret_at_opening_quote() {
    let err = tokenize("load mem \"abc").unwrap_err();
    let (line, pos) = err.parse_position().unwrap();
    assert_eq!(pos, 9);
    assert_eq!(line, "load mem \"abc");
    assert!(err.message.contains("unterminated"));
    assert_eq!(err.message, "unterminated quote");
    assert_eq!(
        err.hint.as_deref(),
        Some("close the quote, or keep typing — unterminated quotes continue on the next line")
    );
    // byte offset of the opening quote after a multibyte label
    let err = tokenize("ключ 'x").unwrap_err();
    assert_eq!(err.parse_position(), Some(("ключ 'x", 9)));
}

#[test]
fn test_line_is_complete() {
    for (line, complete) in [
        ("help", true),
        ("load \"a b\"", true),
        ("load \"a b", false),
        ("load 'a", false),
        // escaped closing quote keeps the buffer open
        ("load \"a\\\"", false),
        // escaped backslash then quote closes
        ("load \"a\\\\\"", true),
        ("", true),
    ] {
        assert_eq!(line_is_complete(line), complete, "{line:?}");
    }
}

// ---------------------------------------------------------------------------
// binder
// ---------------------------------------------------------------------------

fn bind(line: &str, flags: &[&str]) -> r2_core::Result<BoundArgs> {
    bind_args(&tokenize(line)?, flags, line)
}

fn named(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn options(pairs: &[(&str, Option<&str>)]) -> IndexMap<String, OptValue> {
    pairs
        .iter()
        .map(|(k, v)| {
            let value = match v {
                Some(v) => OptValue::Value((*v).to_owned()),
                None => OptValue::Flag,
            };
            ((*k).to_owned(), value)
        })
        .collect()
}

#[test]
fn test_bind_positionals_in_order_with_quoted_flags() {
    let args = bind("mem:k gcm \"deadbeef\"", &[]).unwrap();
    assert_eq!(args.positionals, ["mem:k", "gcm", "deadbeef"]);
    assert_eq!(args.positional_quoted, [false, false, true]);
}

#[test]
fn test_bind_named_split_at_first_equals() {
    let args = bind("iv=00ff aad=a=b", &[]).unwrap();
    assert_eq!(args.named, named(&[("iv", "00ff"), ("aad", "a=b")]));
    assert!(args.positionals.is_empty());
}

#[test]
fn test_bind_flag_option_consumes_no_value() {
    let args = bind("show --origin", &["origin"]).unwrap();
    assert_eq!(args.options, options(&[("origin", None)]));
    assert_eq!(args.positionals, ["show"]);
    assert!(args.flag("origin"));
    assert_eq!(args.opt("origin"), None);
    assert!(args.has_option("origin"));
}

#[test]
fn test_bind_value_option_consumes_next_token() {
    let args = bind("--slot 3 --label mykey", &[]).unwrap();
    assert_eq!(
        args.options,
        options(&[("slot", Some("3")), ("label", Some("mykey"))])
    );
    assert!(args.positionals.is_empty());
    assert_eq!(args.opt("label"), Some("mykey"));
    assert!(!args.flag("label"));
    assert!(!args.has_option("pin"));
}

#[test]
fn test_bind_option_value_may_be_quoted() {
    let args = bind("--label \"my key\"", &[]).unwrap();
    assert_eq!(args.options, options(&[("label", Some("my key"))]));
}

#[test]
fn test_bind_option_value_may_be_option_shaped() {
    // mechanical rule: the next token is the value, whatever it looks like
    let args = bind("--label --slot", &[]).unwrap();
    assert_eq!(args.options, options(&[("label", Some("--slot"))]));
}

#[test]
fn test_bind_quoted_tokens_never_classified() {
    // quoted "--option" and "name=value" bind as positionals (§4.9)
    let args = bind("\"--pin\" \"iv=00ff\"", &["pin"]).unwrap();
    assert_eq!(args.positionals, ["--pin", "iv=00ff"]);
    assert_eq!(args.positional_quoted, [true, true]);
    assert!(args.options.is_empty());
    assert!(args.named.is_empty());
}

#[test]
fn test_bind_mixed_order_preserved() {
    let args = bind("enc gcm iv=00 --out f.bin \"data\" tag_bits=96", &[]).unwrap();
    assert_eq!(args.positionals, ["enc", "gcm", "data"]);
    assert_eq!(args.positional_quoted, [false, false, true]);
    assert_eq!(
        args.named.keys().map(String::as_str).collect::<Vec<_>>(),
        ["iv", "tag_bits"]
    );
    assert_eq!(args.options, options(&[("out", Some("f.bin"))]));
}

#[test]
fn test_bind_missing_option_value_caret() {
    let line = "login hsm --pin";
    let err = bind(line, &[]).unwrap_err();
    assert_eq!(err.parse_position(), Some((line, 10)));
    assert!(err.message.contains("--pin expects a value"));
    assert_eq!(err.message, "option --pin expects a value");
    assert_eq!(err.hint.as_deref(), Some("write: --pin <value>"));
}

#[test]
fn test_bind_empty_option_name_caret() {
    let err = bind("cmd --", &[]).unwrap_err();
    assert_eq!(err.parse_position(), Some(("cmd --", 4)));
    assert!(err.message.contains("empty option name"));
    assert_eq!(err.hint.as_deref(), Some("options are written --name"));
}

#[test]
fn test_bind_empty_parameter_name_caret() {
    let err = bind("cmd a =x", &[]).unwrap_err();
    // "=x" starts at offset 6
    assert_eq!(err.parse_position(), Some(("cmd a =x", 6)));
    assert!(err.message.contains("empty parameter name"));
    assert_eq!(err.message, "empty parameter name before '='");
    assert_eq!(
        err.hint.as_deref(),
        Some("parameters are written name=value")
    );
    assert!(matches!(err.kind, ErrorKind::Parse { .. }));
}

#[test]
fn test_bind_duplicate_named_last_wins() {
    let args = bind("iv=00 iv=ff", &[]).unwrap();
    assert_eq!(args.named, named(&[("iv", "ff")]));
    // Python dict semantics: a repeated name keeps its FIRST position
    let args = bind("a=1 b=2 a=3 --x 1 --y 2 --x 3", &[]).unwrap();
    assert_eq!(args.named, named(&[("a", "3"), ("b", "2")]));
    assert_eq!(args.options, options(&[("x", Some("3")), ("y", Some("2"))]));
}

#[test]
fn test_bind_pem_paste_inside_quotes_is_one_positional() {
    let pem = "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----";
    let line = format!("load mem cert \"{pem}\"");
    let args = bind(&line, &[]).unwrap();
    assert_eq!(args.positionals, ["load", "mem", "cert", pem]);
    assert_eq!(args.positional_quoted.last(), Some(&true));
    assert!(args.named.is_empty()); // the '=' inside the quoted PEM never binds
}

#[test]
fn bind_error_line_is_the_full_original_input() {
    // the binder sees tokens[1..] but carries the whole line into the caret
    let line = "login hsm --pin";
    let tokens = tokenize(line).unwrap();
    let err = bind_args(&tokens[1..], &[], line).unwrap_err();
    assert_eq!(err.parse_position(), Some((line, 10)));
}
