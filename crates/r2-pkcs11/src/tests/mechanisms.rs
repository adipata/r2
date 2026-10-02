//! Ports of c2 tests/unit/pkcs11/test_mechanisms.py (TestHashHelpers, TestPackers) — the
//! hash helpers and the five custom `param_struct` packers (§4.6.3, §5.14) — plus the
//! r2 MechSpec builders the packers share.
use r2_core::error::ErrorKind;
use r2_core::params::{ParamStruct, ParamValue, Params};
use r2_provider::MechanismInvocation;

use crate::backend::MechSpec;
use crate::mechanisms as mechs;
use crate::provider::OpError;

const VENDOR: u64 = 0x8000_0A01;

fn invocation(
    param_struct: ParamStruct,
    params: Vec<(&str, ParamValue)>,
    raw_param_bytes: Option<Vec<u8>>,
) -> MechanismInvocation {
    let mut map = Params::new();
    for (name, value) in params {
        map.insert(name.to_string(), value);
    }
    let mut inv = MechanismInvocation::new("vendor.acme.op", map);
    inv.raw_ckm = Some(VENDOR);
    inv.param_struct = param_struct;
    inv.raw_param_bytes = raw_param_bytes;
    inv
}

fn bytes(value: &[u8]) -> ParamValue {
    ParamValue::Bytes(value.to_vec())
}

fn console(err: OpError) -> r2_core::ConsoleError {
    match err {
        OpError::Console(err) => err,
        OpError::Backend(err) => panic!("expected a console error, got {err:?}"),
    }
}

// ---- TestHashHelpers ----

#[test]
fn digest_info_sha256_prefix() {
    let blob = mechs::digest_info("sha256", b"data").unwrap();
    let prefix = super::unhex("3031300d060960864801650304020105000420");
    assert!(blob.starts_with(&prefix));
    assert_eq!(blob.len(), 19 + 32);
    // the digest part is SHA-256 of the data
    assert_eq!(&blob[19..], openssl::sha::sha256(b"data").as_slice());
}

#[test]
fn digest_info_prefixes_for_every_hash() {
    // DER DigestInfo prefixes of c2 `_DIGEST_INFO_PREFIX` (RFC 8017 §9.2 note 1)
    for (hash, prefix, len) in [
        ("sha1", "3021300906052b0e03021a05000414", 20),
        ("sha224", "302d300d06096086480165030402040500041c", 28),
        ("sha256", "3031300d060960864801650304020105000420", 32),
        ("sha384", "3041300d060960864801650304020205000430", 48),
        ("sha512", "3051300d060960864801650304020305000440", 64),
    ] {
        let blob = mechs::digest_info(hash, b"x").unwrap();
        let prefix = super::unhex(prefix);
        assert!(blob.starts_with(&prefix), "{hash}");
        assert_eq!(blob.len(), prefix.len() + len, "{hash}");
    }
}

#[test]
fn unknown_hash_rejected() {
    let err = mechs::hash_ckm("md5").unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(err.message, "unknown hash 'md5'");
    assert_eq!(err.param_name(), Some("hash"));
    assert_eq!(
        err.hint.as_deref(),
        Some("valid hashes: sha1, sha224, sha256, sha384, sha512")
    );
    let err = mechs::mgf1_code("md5").unwrap_err();
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(err.param_name(), Some("mgf_hash"));
}

#[test]
fn hash_and_mgf_codes_are_pkcs11_constants() {
    assert_eq!(mechs::hash_ckm("sha1").unwrap(), 0x220);
    assert_eq!(mechs::hash_ckm("sha224").unwrap(), 0x255);
    assert_eq!(mechs::hash_ckm("sha256").unwrap(), 0x250);
    assert_eq!(mechs::hash_ckm("sha384").unwrap(), 0x260);
    assert_eq!(mechs::hash_ckm("sha512").unwrap(), 0x270);
    assert_eq!(mechs::mgf1_code("sha1").unwrap(), 1);
    assert_eq!(mechs::mgf1_code("sha256").unwrap(), 2);
    assert_eq!(mechs::mgf1_code("sha384").unwrap(), 3);
    assert_eq!(mechs::mgf1_code("sha512").unwrap(), 4);
    assert_eq!(mechs::mgf1_code("sha224").unwrap(), 5);
}

// ---- TestPackers ----

#[test]
fn none_packer() {
    let spec = mechs::pack_custom(&invocation(ParamStruct::None, vec![], None)).unwrap();
    assert_eq!(spec, MechSpec::Plain { ckm: VENDOR }); // NULL pParameter
}

#[test]
fn iv_packer() {
    let spec = mechs::pack_custom(&invocation(
        ParamStruct::Iv,
        vec![("iv", bytes(&[1; 16]))],
        None,
    ))
    .unwrap();
    assert_eq!(
        spec,
        MechSpec::Bytes {
            ckm: VENDOR,
            param: vec![1; 16]
        }
    );
}

#[test]
fn iv_packer_requires_iv() {
    let err = console(mechs::pack_custom(&invocation(ParamStruct::Iv, vec![], None)).unwrap_err());
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(err.param_name(), Some("iv"));
    assert_eq!(err.message, "custom mechanism parameter 'iv' must be bytes");
    assert_eq!(
        err.hint.as_deref(),
        Some("conventional packer param names: iv/aad/tag_bits, hash/mgf_hash/label, mechparam")
    );
}

#[test]
fn gcm_packer_conventional_names() {
    let spec = mechs::pack_custom(&invocation(
        ParamStruct::Gcm,
        vec![
            ("iv", bytes(&[2; 12])),
            ("aad", bytes(b"aad")),
            ("tag_bits", ParamValue::Int(96)),
        ],
        None,
    ))
    .unwrap();
    // code overridden on the GCM struct
    assert_eq!(
        spec,
        MechSpec::Gcm {
            ckm: VENDOR,
            iv: vec![2; 12],
            aad: b"aad".to_vec(),
            tag_bits: 96
        }
    );
}

#[test]
fn gcm_packer_defaults() {
    let spec = mechs::pack_custom(&invocation(
        ParamStruct::Gcm,
        vec![("iv", bytes(&[2; 12]))],
        None,
    ))
    .unwrap();
    assert_eq!(
        spec,
        MechSpec::Gcm {
            ckm: VENDOR,
            iv: vec![2; 12],
            aad: Vec::new(),
            tag_bits: 128
        }
    );
}

#[test]
fn gcm_packer_integer_reads_are_strict() {
    // only ParamValue::Int is an integer (§4.6.3): an ENUM/STR tag_bits fails as in c2
    for value in [
        ParamValue::Enum("96".into()),
        ParamValue::Str("96".into()),
        ParamValue::Bool(true),
    ] {
        let err = console(
            mechs::pack_custom(&invocation(
                ParamStruct::Gcm,
                vec![("iv", bytes(&[2; 12])), ("tag_bits", value)],
                None,
            ))
            .unwrap_err(),
        );
        assert_eq!(
            err.message,
            "custom mechanism parameter 'tag_bits' must be an integer"
        );
        assert_eq!(err.param_name(), Some("tag_bits"));
        assert_eq!(err.hint, None);
    }
    // a negative width cannot be a CK_ULONG: the token's CKR_MECHANISM_PARAM_INVALID
    let err = mechs::pack_custom(&invocation(
        ParamStruct::Gcm,
        vec![("iv", bytes(&[2; 12])), ("tag_bits", ParamValue::Int(-8))],
        None,
    ))
    .unwrap_err();
    assert!(matches!(err, OpError::Backend(_)));
}

#[test]
fn oaep_packer() {
    let spec = mechs::pack_custom(&invocation(
        ParamStruct::Oaep,
        vec![
            ("hash", ParamValue::Enum("sha256".into())),
            ("mgf_hash", ParamValue::Str("sha256".into())),
            ("label", bytes(b"lbl")),
        ],
        None,
    ))
    .unwrap();
    assert_eq!(
        spec,
        MechSpec::Oaep {
            ckm: VENDOR,
            hash_ckm: mechs::hash_ckm("sha256").unwrap(),
            mgf: mechs::mgf1_code("sha256").unwrap(),
            label: b"lbl".to_vec()
        }
    );
}

#[test]
fn oaep_packer_mgf_defaults_to_hash() {
    let spec = mechs::pack_custom(&invocation(
        ParamStruct::Oaep,
        vec![("hash", ParamValue::Str("sha1".into()))],
        None,
    ))
    .unwrap();
    assert_eq!(
        spec,
        MechSpec::Oaep {
            ckm: VENDOR,
            hash_ckm: mechs::hash_ckm("sha1").unwrap(),
            mgf: mechs::mgf1_code("sha1").unwrap(),
            label: Vec::new()
        }
    );
    // a non-string hash is c2's `_str_param` error (no hint)
    let err = console(
        mechs::pack_custom(&invocation(
            ParamStruct::Oaep,
            vec![("hash", ParamValue::Int(1))],
            None,
        ))
        .unwrap_err(),
    );
    assert_eq!(
        err.message,
        "custom mechanism parameter 'hash' must be a string"
    );
    assert_eq!(err.hint, None);
}

#[test]
fn raw_packer_prefers_raw_param_bytes() {
    let spec = mechs::pack_custom(&invocation(
        ParamStruct::Raw,
        vec![("mechparam", bytes(b"ignored"))],
        Some(vec![0xaa, 0xbb]),
    ))
    .unwrap();
    assert_eq!(
        spec,
        MechSpec::Bytes {
            ckm: VENDOR,
            param: vec![0xaa, 0xbb]
        }
    );
}

#[test]
fn raw_packer_falls_back_to_mechparam() {
    let spec = mechs::pack_custom(&invocation(
        ParamStruct::Raw,
        vec![("mechparam", bytes(&[0xcc]))],
        None,
    ))
    .unwrap();
    assert_eq!(
        spec,
        MechSpec::Bytes {
            ckm: VENDOR,
            param: vec![0xcc]
        }
    );
}

#[test]
fn raw_packer_requires_bytes() {
    let err = console(mechs::pack_custom(&invocation(ParamStruct::Raw, vec![], None)).unwrap_err());
    assert_eq!(err.kind.class_name(), "ParamError");
    assert_eq!(err.param_name(), Some("mechparam"));
}

#[test]
fn empty_raw_bytes_are_a_null_parameter() {
    // c2 `simple(ckm, param if param else None)`: empty bytes → NULL pParameter
    let spec = mechs::pack_custom(&invocation(ParamStruct::Raw, vec![], Some(Vec::new()))).unwrap();
    assert_eq!(spec, MechSpec::Plain { ckm: VENDOR });
}

#[test]
fn missing_raw_ckm_is_a_bug() {
    let mut inv = MechanismInvocation::new("vendor.acme.op", Params::new());
    inv.param_struct = ParamStruct::None;
    let err = console(mechs::pack_custom(&inv).unwrap_err());
    assert_eq!(err.kind, ErrorKind::Crypto);
    assert_eq!(
        err.message,
        "custom mechanism 'vendor.acme.op' has no raw CKM code"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("OperationSpec.raw_ckm must be copied into MechanismInvocation (§4.6)")
    );
}

// ---- builders ----

#[test]
fn ecdh_kdf_names_resolve_like_pykcs11() {
    let kdf_of = |name: &str| match mechs::ecdh(b"\x04", name, b"").unwrap() {
        MechSpec::Ecdh1 { kdf, .. } => kdf,
        other => panic!("{other:?}"),
    };
    assert_eq!(kdf_of("null"), 1);
    assert_eq!(kdf_of("sha1"), 2);
    assert_eq!(kdf_of("sha256"), 6);
    assert_eq!(kdf_of("SHA512"), 8); // upper-cased into CKD_SHA512_KDF
    let err = mechs::ecdh(b"\x04", "md5", b"").unwrap_err();
    assert_eq!(err.message, "unknown ECDH kdf 'md5'");
    assert_eq!(err.param_name(), Some("kdf"));
    assert_eq!(
        err.hint.as_deref(),
        Some("valid values: null, sha1, sha256, sha384, sha512")
    );
    // "NULL" is not "null" (c2 compares exactly before upper-casing)
    assert!(mechs::ecdh(b"\x04", "NULL", b"").is_err());
}

#[test]
fn ctr_needs_a_full_counter_block() {
    assert_eq!(
        mechs::ctr(128, &[7; 16]).unwrap(),
        MechSpec::Ctr {
            counter_bits: 128,
            counter_block: [7; 16]
        }
    );
    assert!(matches!(
        mechs::ctr(128, &[7; 15]),
        Err(OpError::Backend(_))
    ));
    assert!(matches!(mechs::ctr(-1, &[7; 16]), Err(OpError::Backend(_))));
}
