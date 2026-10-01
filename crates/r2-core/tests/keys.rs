//! Key model tests (spec §4.3) — port of c2 `tests/unit/core/test_keys.py` (enums,
//! KeyRef.display, the parse_ref grammar, display_refs) plus the r2 additions of §4.3/§11 D18.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::BTreeMap;

use r2_core::error::ErrorKind;
use r2_core::keys::{
    Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial, KeyRef, ParsedRef, display_refs, parse_ref,
};
use r2_core::template::AttrValue;

fn parsed(
    provider: &str,
    label: &str,
    key_id: Option<&[u8]>,
    key_class: Option<KeyClass>,
    handle: Option<u64>,
) -> ParsedRef {
    ParsedRef {
        provider: provider.to_owned(),
        label: label.to_owned(),
        key_id: key_id.map(<[u8]>::to_vec),
        key_class,
        handle,
    }
}

#[test]
fn test_key_class_values() {
    let values: Vec<&str> = KeyClass::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        values,
        ["secret", "private", "public", "certificate", "data"]
    );
}

#[test]
fn test_key_algorithm_values() {
    let all = [
        KeyAlgorithm::Aes,
        KeyAlgorithm::Rsa,
        KeyAlgorithm::Ec,
        KeyAlgorithm::EcEdwards,
        KeyAlgorithm::EcMontgomery,
        KeyAlgorithm::Generic,
        KeyAlgorithm::None,
        KeyAlgorithm::Other,
    ];
    let values: Vec<&str> = all.iter().map(|a| a.as_str()).collect();
    assert_eq!(
        values,
        [
            "aes",
            "rsa",
            "ec",
            "ec-edwards",
            "ec-montgomery",
            "generic",
            "none",
            "other"
        ]
    );
}

// --- KeyRef.display ---------------------------------------------------------

#[test]
fn test_display_without_id() {
    assert_eq!(KeyRef::new("mem", "mykey", None).display(), "mem:mykey");
}

#[test]
fn test_display_with_id_is_lowercase_hex() {
    let key_ref = KeyRef::new("hsm", "signer", Some(vec![0x0a, 0x1b]));
    assert_eq!(key_ref.display(), "hsm:signer#0a1b");
}

// --- parse_ref: valid refs --------------------------------------------------

#[test]
fn test_parse_ref_valid() {
    use KeyClass::{Certificate, Private, Public, Secret};
    let valid: Vec<(&str, ParsedRef)> = vec![
        ("mem:mykey", parsed("mem", "mykey", None, None, None)),
        (
            "hsm:signer#0a1b",
            parsed("hsm", "signer", Some(&[0x0a, 0x1b]), None, None),
        ),
        // id hex case-insensitive
        (
            "hsm:signer#0A1B",
            parsed("hsm", "signer", Some(&[0x0a, 0x1b]), None, None),
        ),
        ("pr-o_v2:k", parsed("pr-o_v2", "k", None, None, None)),
        ("_p:label", parsed("_p", "label", None, None, None)),
        // label may contain ':'
        ("mem:la:bel", parsed("mem", "la:bel", None, None, None)),
        // last '#' starts the id
        (
            "mem:a#b#0a1b",
            parsed("mem", "a#b", Some(&[0x0a, 0x1b]), None, None),
        ),
        (
            "mem:key with spaces",
            parsed("mem", "key with spaces", None, None, None),
        ),
        (
            "hsm:k#00ff",
            parsed("hsm", "k", Some(&[0x00, 0xff]), None, None),
        ),
        // class selectors (§4.3): after the id …
        (
            "hsm:t1#c0fe:priv",
            parsed("hsm", "t1", Some(&[0xc0, 0xfe]), Some(Private), None),
        ),
        (
            "hsm:t1#c0fe:pub",
            parsed("hsm", "t1", Some(&[0xc0, 0xfe]), Some(Public), None),
        ),
        (
            "hsm:t1#c0fe:cert",
            parsed("hsm", "t1", Some(&[0xc0, 0xfe]), Some(Certificate), None),
        ),
        (
            "hsm:t1#c0fe:secret",
            parsed("hsm", "t1", Some(&[0xc0, 0xfe]), Some(Secret), None),
        ),
        // … or directly after the label; long forms and any case accepted
        (
            "mem:pair:pub",
            parsed("mem", "pair", None, Some(Public), None),
        ),
        (
            "mem:pair:private",
            parsed("mem", "pair", None, Some(Private), None),
        ),
        (
            "mem:pair:PUB",
            parsed("mem", "pair", None, Some(Public), None),
        ),
        // last ':' wins
        (
            "mem:a:b:priv",
            parsed("mem", "a:b", None, Some(Private), None),
        ),
        (
            "mem:a#b#0a1b:pub",
            parsed("mem", "a#b", Some(&[0x0a, 0x1b]), Some(Public), None),
        ),
        // session-handle selector (§4.3): always the final suffix
        ("hsm:t1@7", parsed("hsm", "t1", None, None, Some(7))),
        (
            "hsm:t1#c0fe@12",
            parsed("hsm", "t1", Some(&[0xc0, 0xfe]), None, Some(12)),
        ),
        (
            "hsm:t1#c0fe:priv@12",
            parsed("hsm", "t1", Some(&[0xc0, 0xfe]), Some(Private), Some(12)),
        ),
        (
            "mem:pair:pub@3",
            parsed("mem", "pair", None, Some(Public), Some(3)),
        ),
        // non-digit '@' tail is part of the label (carve-out: needs #id to force)
        ("mem:x@12ab", parsed("mem", "x@12ab", None, None, None)),
        // '@' not final → label
        (
            "mem:x@7#0a1b",
            parsed("mem", "x@7", Some(&[0x0a, 0x1b]), None, None),
        ),
    ];
    assert_eq!(valid.len(), 24);
    for (reference, expected) in valid {
        assert_eq!(parse_ref(reference).unwrap(), expected, "{reference}");
    }
}

// --- parse_ref: malformed refs (pos points at the offending character) ------

#[test]
fn test_parse_ref_malformed() {
    let bad: &[(&str, usize)] = &[
        ("nolabel", 7),           // no ':' → caret at end where one was expected
        (":label", 0),            // empty provider
        ("9prov:label", 0),       // bad identifier start
        ("pr ov:label", 2),       // invalid char inside provider name
        ("pr.ov:label", 2),       //
        ("prov:", 5),             // empty label
        ("prov:label#", 11),      // empty id
        ("prov:label#0a1", 14),   // odd hex digit count → caret at end
        ("prov:label#0g", 12),    // invalid hex digit 'g'
        ("prov:label#xyz", 11),   // invalid hex digit 'x'
        ("prov:x#0a1b:frob", 12), // unknown class selector after the id
        ("prov:x#0a1b:", 12),     // empty class selector after the id
        ("prov::priv", 5),        // class selector with no label
        ("prov:x#:pub", 7),       // class selector but empty id
    ];
    for &(reference, pos) in bad {
        let err = parse_ref(reference).unwrap_err();
        assert_eq!(err.parse_position(), Some((reference, pos)), "{reference}");
        assert!(err.hint.is_some(), "{reference}");
    }
}

/// The verbatim c2 messages and hints of every malformed-ref branch (§4.3 steps 1-5).
#[test]
fn parse_ref_messages_and_hints_are_c2_verbatim() {
    const REF_HINT: &str = "expected '<provider>:<label>[#<id-hex>][:<class>][@<handle>]'";
    const PROVIDER_HINT: &str = "provider names match [A-Za-z_][A-Za-z0-9_-]*";
    let cases: &[(&str, &str, &str)] = &[
        ("nolabel", "key reference is missing ':'", REF_HINT),
        (":label", "missing provider name", REF_HINT),
        (
            "9prov:label",
            "invalid provider name start '9'",
            PROVIDER_HINT,
        ),
        (
            "pr ov:label",
            "invalid character ' ' in provider name",
            PROVIDER_HINT,
        ),
        ("prov:", "missing key label", REF_HINT),
        ("prov:label#", "empty key id after '#'", REF_HINT),
        (
            "prov:label#0a1",
            "odd number of hex digits in key id",
            "the id after '#' encodes whole bytes (2 hex digits each)",
        ),
        (
            "prov:label#0g",
            "invalid hex digit 'g' in key id",
            "the id after '#' is lowercase hex, e.g. #0a1b",
        ),
        (
            "prov:x#0a1b:frob",
            "unknown class selector 'frob'",
            "class is one of priv, pub, cert, secret, data (long forms private/public/certificate too)",
        ),
        (
            "prov:x#0a1b:",
            "unknown class selector ''",
            "class is one of priv, pub, cert, secret, data (long forms private/public/certificate too)",
        ),
    ];
    for &(reference, message, hint) in cases {
        let err = parse_ref(reference).unwrap_err();
        assert_eq!(err.kind.class_name(), "ParseError");
        assert_eq!(err.message, message, "{reference}");
        assert_eq!(err.hint.as_deref(), Some(hint), "{reference}");
    }
}

/// Positions are BYTE offsets (§4 conventions); c2's char indices are converted for
/// non-ASCII vectors. Error texts use Python repr of the offending character.
#[test]
fn parse_ref_positions_are_byte_offsets() {
    let err = parse_ref("ключ:x").unwrap_err();
    assert_eq!(err.message, "invalid provider name start 'к'");
    assert_eq!(err.parse_position(), Some(("ключ:x", 0)));
    let err = parse_ref("pé:x").unwrap_err();
    assert_eq!(err.message, "invalid character 'é' in provider name");
    assert_eq!(err.parse_position().unwrap().1, 1);
    let err = parse_ref("p:ключ#0é").unwrap_err();
    assert_eq!(err.message, "invalid hex digit 'é' in key id");
    assert_eq!(err.parse_position().unwrap().1, "p:ключ#0".len());
    let err = parse_ref("p:ключ#0a1").unwrap_err();
    assert_eq!(err.parse_position().unwrap().1, "p:ключ#0a1".len());
    let ok = parse_ref("p:ключ:pub@5").unwrap();
    assert_eq!(
        ok,
        parsed("p", "ключ", None, Some(KeyClass::Public), Some(5))
    );
}

/// §11 D18: a handle that overflows u64 is "handle out of range" at the '@'+1 offset.
#[test]
fn parse_ref_handle_out_of_range() {
    let max = parse_ref(&format!("hsm:k@{}", u64::MAX)).unwrap();
    assert_eq!(max.handle, Some(u64::MAX));
    let reference = "hsm:k@18446744073709551616";
    let err = parse_ref(reference).unwrap_err();
    assert_eq!(err.message, "handle out of range");
    assert_eq!(err.parse_position(), Some((reference, 6)));
    assert_eq!(
        err.hint.as_deref(),
        Some("expected '<provider>:<label>[#<id-hex>][:<class>][@<handle>]'")
    );
    // Leading zeros are digits too; a sign is not (the tail stays in the label).
    assert_eq!(parse_ref("hsm:k@007").unwrap().handle, Some(7));
    assert_eq!(parse_ref("hsm:k@+7").unwrap().label, "k@+7");
    // '@' before the first ':' is part of the provider name check.
    assert!(parse_ref("h@s:k").is_err());
}

// --- display() ↔ parse_ref round-trip ---------------------------------------

#[test]
fn test_display_parse_ref_round_trip() {
    let refs = [
        KeyRef::new("mem", "plain", None),
        KeyRef::new("hsm-1", "with spaces in label", None),
        KeyRef::new("hsm", "dup", Some(vec![0x00])),
        KeyRef::new("p_2", "a:b:c", Some(vec![0xde, 0xad, 0xbe, 0xef])),
        KeyRef::new("p", "has#hash", Some(vec![0x01, 0x02])),
    ];
    for key_ref in refs {
        let parsed = parse_ref(&key_ref.display()).unwrap();
        assert_eq!(
            (&parsed.provider, &parsed.label, &parsed.key_id),
            (&key_ref.provider, &key_ref.label, &key_ref.key_id)
        );
        assert_eq!((parsed.key_class, parsed.handle), (None, None));
        assert_eq!(
            KeyRef::new(parsed.provider, parsed.label, parsed.key_id),
            key_ref
        );
    }
}

// --- display_refs: listing disambiguation (§4.3) ------------------------------

fn info(label: &str, key_class: KeyClass, key_id: Option<&[u8]>, handle: Option<u64>) -> KeyInfo {
    KeyInfo {
        key_ref: KeyRef::new("hsm", label, key_id.map(<[u8]>::to_vec)),
        key_class,
        algorithm: KeyAlgorithm::Rsa,
        size_bits: Some(2048),
        curve: None,
        exportable: true,
        attributes: BTreeMap::new(),
        handle,
    }
}

#[test]
fn test_display_refs_plain_when_unique() {
    let infos = [
        info("solo", KeyClass::Secret, Some(&[0x0a]), None),
        info("other", KeyClass::Private, None, None),
    ];
    assert_eq!(display_refs(&infos), ["hsm:solo#0a", "hsm:other"]);
}

#[test]
fn test_display_refs_suffixes_colliding_family() {
    let infos = [
        info("pair", KeyClass::Private, Some(&[0xc0, 0xfe]), None),
        info("pair", KeyClass::Public, Some(&[0xc0, 0xfe]), None),
        info("pair", KeyClass::Certificate, Some(&[0xc0, 0xfe]), None),
        info("solo", KeyClass::Secret, None, None),
    ];
    let shown = display_refs(&infos);
    assert_eq!(
        shown,
        [
            "hsm:pair#c0fe:priv",
            "hsm:pair#c0fe:pub",
            "hsm:pair#c0fe:cert",
            "hsm:solo",
        ]
    );
    for text in shown {
        parse_ref(&text).unwrap(); // every emitted form parses back
    }
}

#[test]
fn test_display_refs_appends_handle_for_same_class_duplicates() {
    let infos = [
        info("dup", KeyClass::Secret, Some(&[0x01]), Some(41)),
        info("dup", KeyClass::Secret, Some(&[0x01]), Some(42)),
    ];
    assert_eq!(
        display_refs(&infos),
        ["hsm:dup#01:secret@41", "hsm:dup#01:secret@42"]
    );
    let parsed = parse_ref("hsm:dup#01:secret@42").unwrap();
    assert_eq!(parsed.key_class, Some(KeyClass::Secret));
    assert_eq!(parsed.handle, Some(42));
}

/// Twins without a handle (memory) keep the class-suffixed form.
#[test]
fn display_refs_without_handles_keep_the_class_suffix() {
    let infos = [
        info("dup", KeyClass::Secret, None, None),
        info("dup", KeyClass::Secret, None, Some(3)),
        info("dup", KeyClass::Public, None, None),
    ];
    assert_eq!(
        display_refs(&infos),
        ["hsm:dup:secret", "hsm:dup:secret@3", "hsm:dup:pub"]
    );
    assert!(display_refs(&[]).is_empty());
}

// --- KeyInfo / KeyMaterial value objects -------------------------------------

#[test]
fn test_key_info_is_frozen_with_defaults() {
    let mut attributes = BTreeMap::new();
    attributes.insert("CKA_TOKEN".to_owned(), AttrValue::Bool(true));
    let info = KeyInfo {
        key_ref: KeyRef::new("mem", "k", None),
        key_class: KeyClass::Secret,
        algorithm: KeyAlgorithm::Aes,
        size_bits: Some(256),
        curve: None,
        exportable: true,
        attributes,
        handle: None,
    };
    assert_eq!(info.handle, None);
    assert_eq!(info.attributes["CKA_TOKEN"], AttrValue::Bool(true));
}

#[test]
fn test_key_material_defaults() {
    let material = KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Private, vec![0x30, 0x2e]);
    assert_eq!(material.curve, None);
    assert_eq!(material.size_bits, None);
    assert_eq!(material.label_hint, None);
    assert_eq!(&*material.data, &[0x30, 0x2e]);
}

/// §4.3: KeyMaterial's Debug never shows key bytes.
#[test]
fn key_material_debug_hides_the_bytes() {
    let material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![0xab; 16]);
    let debug = format!("{material:?}");
    assert!(debug.contains("data: <16 bytes>"), "{debug}");
    assert!(
        !debug.contains("171") && !debug.contains("ab, ab"),
        "{debug}"
    );
    assert!(debug.starts_with("KeyMaterial { algorithm: Aes, key_class: Secret"));
}

/// The token tables of §4.3 (Display/FromStr, py_name, CKO/CKK symbols, curves).
#[test]
fn enum_tokens_symbols_and_curves() {
    for class in KeyClass::ALL {
        assert_eq!(class.to_string(), class.as_str());
        assert_eq!(class.as_str().parse::<KeyClass>().unwrap(), class);
    }
    assert_eq!(
        KeyClass::ALL.map(KeyClass::py_name),
        [
            "KeyClass.SECRET",
            "KeyClass.PRIVATE",
            "KeyClass.PUBLIC",
            "KeyClass.CERTIFICATE",
            "KeyClass.DATA"
        ]
    );
    assert_eq!(
        KeyClass::ALL.map(KeyClass::cko_symbol),
        [
            "CKO_SECRET_KEY",
            "CKO_PRIVATE_KEY",
            "CKO_PUBLIC_KEY",
            "CKO_CERTIFICATE",
            "CKO_DATA"
        ]
    );
    assert_eq!(
        KeyClass::ALL.map(KeyClass::has_key_type),
        [true, true, true, false, false]
    );
    let err = "priv".parse::<KeyClass>().unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(err.message, "unknown key class 'priv'");

    let algorithms = [
        (KeyAlgorithm::Aes, "KeyAlgorithm.AES", Some("CKK_AES")),
        (KeyAlgorithm::Rsa, "KeyAlgorithm.RSA", Some("CKK_RSA")),
        (KeyAlgorithm::Ec, "KeyAlgorithm.EC", Some("CKK_EC")),
        (
            KeyAlgorithm::EcEdwards,
            "KeyAlgorithm.EC_EDWARDS",
            Some("CKK_EC_EDWARDS"),
        ),
        (
            KeyAlgorithm::EcMontgomery,
            "KeyAlgorithm.EC_MONTGOMERY",
            Some("CKK_EC_MONTGOMERY"),
        ),
        (
            KeyAlgorithm::Generic,
            "KeyAlgorithm.GENERIC",
            Some("CKK_GENERIC_SECRET"),
        ),
        (KeyAlgorithm::None, "KeyAlgorithm.NONE", None),
        (KeyAlgorithm::Other, "KeyAlgorithm.OTHER", None),
    ];
    for (algorithm, py_name, ckk) in algorithms {
        assert_eq!(algorithm.py_name(), py_name);
        assert_eq!(algorithm.ckk_symbol(), ckk);
        assert_eq!(algorithm.is_creatable(), ckk.is_some());
        assert_eq!(algorithm.to_string(), algorithm.as_str());
        assert_eq!(
            algorithm.as_str().parse::<KeyAlgorithm>().unwrap(),
            algorithm
        );
        assert_eq!(
            algorithm.is_ec_family(),
            matches!(
                algorithm,
                KeyAlgorithm::Ec | KeyAlgorithm::EcEdwards | KeyAlgorithm::EcMontgomery
            )
        );
    }
    assert_eq!(
        "EC".parse::<KeyAlgorithm>().unwrap_err().message,
        "unknown key algorithm 'EC'"
    );

    let curves = [
        (Curve::P256, KeyAlgorithm::Ec, Some(32)),
        (Curve::P384, KeyAlgorithm::Ec, Some(48)),
        (Curve::P521, KeyAlgorithm::Ec, Some(66)),
        (Curve::Ed25519, KeyAlgorithm::EcEdwards, Some(32)),
        (Curve::Ed448, KeyAlgorithm::EcEdwards, Some(57)),
        (Curve::X25519, KeyAlgorithm::EcMontgomery, Some(32)),
        (Curve::X448, KeyAlgorithm::EcMontgomery, Some(56)),
    ];
    for (curve, algorithm, field) in curves {
        assert_eq!(curve.algorithm(), algorithm);
        assert_eq!(curve.field_bytes(), field);
        assert_eq!(curve.as_str().parse::<Curve>().unwrap(), curve);
        assert_eq!(curve.to_string(), curve.as_str());
    }
    assert_eq!(
        Curve::KNOWN.map(|c| c.as_str().to_owned()),
        ["p256", "p384", "p521", "ed25519", "ed448", "x25519", "x448"]
    );
    for (name, field) in [
        ("secp192r1", Some(24)),
        ("secp224r1", Some(28)),
        ("secp256k1", Some(32)),
        ("brainpoolp256r1", Some(32)),
        ("brainpoolp384r1", Some(48)),
        ("brainpoolp512r1", Some(64)),
        ("prime239v1", None),
    ] {
        let curve = Curve::Other(name.to_owned());
        assert_eq!(curve.field_bytes(), field, "{name}");
        assert_eq!(curve.algorithm(), KeyAlgorithm::Ec);
        assert_eq!(curve.as_str(), name);
    }
    // FromStr never produces Other, and is case-sensitive.
    for text in ["secp256k1", "P256", ""] {
        assert_eq!(
            text.parse::<Curve>().unwrap_err().message,
            format!("unknown curve '{text}'")
        );
    }
}
