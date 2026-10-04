// services::keyexport — port of c2 tests/unit/services/test_keyexport.py (the R8 cases;
// the pyca serializer cases moved to R6), the keyexport case of test_objects_services.py,
// and the services half of test_memory_wrap_kek.py's
// `test_sensitive_but_extractable_wraps_though_plain_export_refuses` (R4 hand-off).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod keyload_fixtures;

use keyload_fixtures::*;
use r2_core::error::ErrorKind;
use r2_core::keyparse::{KeyHint, parse_key_material};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_memory::MemoryProvider;
use r2_provider::{KeySelector, MechanismInvocation, Provider, UnwrapRequest, WrapOptions};
use r2_services::keyexport;
use r2_testkit::FakeProvider;
use secrecy::SecretString;

fn secret(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

fn hsm() -> FakeProvider {
    FakeProvider::new("hsm").with_type_name("pkcs11")
}

fn export(
    provider: &dyn Provider,
    key: &r2_core::keys::KeyInfo,
) -> r2_core::Result<(Vec<u8>, &'static str)> {
    keyexport::export_bytes(provider, key, "auto", false, None)
        .map(|(payload, fmt)| (payload.to_vec(), fmt))
}

// ---------------------------------------------------------------------------------------
// refuse_non_exportable (§5.6 sensitive-key rule)
// ---------------------------------------------------------------------------------------

#[test]
fn test_refusal_message_and_hint() {
    let provider = hsm();
    let info = provider
        .import_key(
            &private_material(),
            "locked",
            Some(&sensitive_template()),
            None,
        )
        .unwrap();
    let err = export(&provider, &info).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(err.message.contains("Refusing to export"));
    assert!(err.message.contains("sensitive/non-extractable"));
    assert_eq!(
        err.message,
        "Refusing to export: key 'hsm:locked#00000001' is marked sensitive/non-extractable."
    );
    let hint = err.hint.unwrap();
    assert!(hint.contains("--public"));
    // CKA_EXTRACTABLE=false: no wrapped-export hint
    assert_eq!(
        hint,
        "public key available with `export hsm:locked#00000001 <path> --public`"
    );
    // pre-flight: the provider was never asked to export (§5.6)
    assert!(!provider.calls().iter().any(|c| c[0] == "export_key"));
}

#[test]
fn test_refusal_applies_to_secret_keys_too() {
    let provider = hsm();
    let info = provider
        .import_key(&aes_material(), "locked", Some(&sensitive_template()), None)
        .unwrap();
    let err = export(&provider, &info).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(err.message.contains("Refusing to export"));
    assert_eq!(err.hint, None); // secret + not extractable: no hint at all
}

#[test]
fn refusal_of_a_sensitive_but_extractable_key_points_at_kek() {
    let provider = hsm();
    let template = KeyTemplate::new(vec![
        TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(true)),
        TemplateAttr::new("CKA_EXTRACTABLE", AttrKind::Bool, AttrValue::Bool(true)),
    ]);
    let info = provider
        .import_key(&private_material(), "wrappable", Some(&template), None)
        .unwrap();
    let err = keyexport::refuse_non_exportable(&info).unwrap_err();
    assert_eq!(
        err.hint.as_deref(),
        Some(
            "public key available with `export hsm:wrappable#00000001 <path> --public`; an \
             extractable key can leave wrapped: `export … --kek <kek>`"
        )
    );
    // public / certificate / exportable objects are never refused
    let public = provider
        .import_key(&public_material(), "pub", None, None)
        .unwrap();
    keyexport::refuse_non_exportable(&public).unwrap();
}

/// R4 hand-off (c2 test_memory_wrap_kek.py lines 347-370): a MemoryProvider key with
/// CKA_SENSITIVE=true + CKA_EXTRACTABLE=true is refused by the plain export, yet wraps.
#[test]
fn test_sensitive_but_extractable_wraps_though_plain_export_refuses() {
    let provider = MemoryProvider::new("mem");
    let kek = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, (0u8..32).collect()),
            "kek",
            None,
            None,
        )
        .unwrap();
    let mut target = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![0xab; 32]);
    target.size_bits = Some(256);
    let template = KeyTemplate::new(vec![
        TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(true)),
        TemplateAttr::new("CKA_EXTRACTABLE", AttrKind::Bool, AttrValue::Bool(true)),
    ]);
    let sensitive = provider
        .import_key(&target, "sensitive", Some(&template), None)
        .unwrap();
    assert!(!sensitive.exportable);

    let err = export(&provider, &sensitive).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(err.message.contains("Refusing to export"));

    let mech = MechanismInvocation::new("AES-KEY-WRAP-PAD", Default::default());
    let blob = provider
        .wrap_key(&kek, &mech, &sensitive, &WrapOptions::default())
        .unwrap();
    let restored = provider
        .unwrap_key(
            &kek,
            &mech,
            &blob,
            &UnwrapRequest::new(KeyAlgorithm::Aes, KeyClass::Secret, "restored"),
        )
        .unwrap();
    assert_eq!(
        provider.export_key(&restored).unwrap().data.as_slice(),
        &[0xab; 32]
    );
}

// ---------------------------------------------------------------------------------------
// export_bytes — §5.6 format table
// ---------------------------------------------------------------------------------------

#[test]
fn test_secret_auto_is_raw_bytes() {
    let provider = FakeProvider::new("mem");
    let info = provider
        .import_key(&aes_material(), "aes1", None, None)
        .unwrap();
    assert_eq!(export(&provider, &info).unwrap(), (aes_32(), "raw"));
    let (payload, fmt) = keyexport::export_bytes(&provider, &info, "raw", false, None).unwrap();
    assert_eq!((payload.to_vec(), fmt), (aes_32(), "raw"));
}

#[test]
fn test_secret_rejects_pem() {
    let provider = FakeProvider::new("mem");
    let info = provider
        .import_key(&aes_material(), "aes1", None, None)
        .unwrap();
    let err = keyexport::export_bytes(&provider, &info, "pem", false, None).unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "format".into()
        }
    );
    assert!(err.message.contains("raw"));
    assert_eq!(err.message, "secret objects export as raw bytes, not 'pem'");
    assert_eq!(
        err.hint.as_deref(),
        Some("use --format raw (or omit --format)")
    );
}

#[test]
fn private_pem_der_and_encrypted() {
    let provider = FakeProvider::new("mem");
    let info = provider
        .import_key(&private_material(), "rsa1", None, None)
        .unwrap();
    let (pem, fmt) = export(&provider, &info).unwrap();
    assert_eq!(fmt, "pem");
    assert!(pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
    let (der, fmt) = keyexport::export_bytes(&provider, &info, "der", false, None).unwrap();
    assert_eq!((der.to_vec(), fmt), (rsa_pkcs8_der(), "der"));
    let (enc, _) =
        keyexport::export_bytes(&provider, &info, "auto", false, Some(&secret("s3cret"))).unwrap();
    assert!(enc.windows(21).any(|w| w == b"ENCRYPTED PRIVATE KEY"));
    let mut pw = |_: &str| Ok(secret("s3cret"));
    let reloaded = parse_key_material(&enc, KeyHint::Auto, Some(&mut pw)).unwrap();
    assert_eq!(reloaded[0].data.as_slice(), rsa_pkcs8_der().as_slice());
    let err =
        keyexport::export_bytes(&provider, &info, "pem", false, Some(&secret(""))).unwrap_err();
    assert_eq!(err.message, "password must not be empty");
}

#[test]
fn test_private_raw_rejected() {
    let provider = FakeProvider::new("mem");
    let info = provider
        .import_key(&private_material(), "rsa1", None, None)
        .unwrap();
    let err = keyexport::export_bytes(&provider, &info, "raw", false, None).unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "format".into()
        }
    );
    assert!(err.message.contains("pem or der"));
    assert_eq!(err.message, "private objects export as pem or der, not raw");
}

#[test]
fn test_public_rejects_password() {
    let provider = FakeProvider::new("mem");
    let info = provider
        .import_key(&public_material(), "pub1", None, None)
        .unwrap();
    let err =
        keyexport::export_bytes(&provider, &info, "auto", false, Some(&secret("x"))).unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "password".into()
        }
    );
    assert_eq!(
        err.message,
        "--password applies only to private-key and p12 exports (§5.6)"
    );
}

#[test]
fn test_public_flag_rejects_password() {
    // --public + --password must error, never silently write unencrypted SPKI.
    let provider = FakeProvider::new("mem");
    let info = provider
        .import_key(&private_material(), "rsa1", None, None)
        .unwrap();
    let err = keyexport::export_bytes(&provider, &info, "auto", true, Some(&secret("sekrit")))
        .unwrap_err();
    assert!(err.message.contains("private-key and p12"));
}

#[test]
fn test_secret_raw_rejects_password() {
    // A secret/raw export must error on --password, never accept-and-ignore it.
    let provider = FakeProvider::new("mem");
    let info = provider
        .import_key(&aes_material(), "aes1", None, None)
        .unwrap();
    let err = keyexport::export_bytes(&provider, &info, "auto", false, Some(&secret("sekrit")))
        .unwrap_err();
    assert!(err.message.contains("private-key and p12"));
}

#[test]
fn test_certificate_rejects_password() {
    let provider = FakeProvider::new("mem");
    let info = provider
        .import_key(&cert_material(), "cert1", None, None)
        .unwrap();
    let err = keyexport::export_bytes(&provider, &info, "der", false, Some(&secret("sekrit")))
        .unwrap_err();
    assert!(err.message.contains("private-key and p12"));
}

#[test]
fn public_and_certificate_pem_and_der() {
    let provider = FakeProvider::new("mem");
    let public = provider
        .import_key(&public_material(), "pub1", None, None)
        .unwrap();
    let (pem, fmt) = export(&provider, &public).unwrap();
    assert_eq!(fmt, "pem");
    assert!(pem.starts_with(b"-----BEGIN PUBLIC KEY-----"));
    let cert = provider
        .import_key(&cert_material(), "cert1", None, None)
        .unwrap();
    let (pem, fmt) = export(&provider, &cert).unwrap();
    assert_eq!(fmt, "pem");
    assert!(pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
    assert_eq!(pem_der(&pem), rsa_cert_der());
    let (der, fmt) = keyexport::export_bytes(&provider, &cert, "der", false, None).unwrap();
    assert_eq!((der.to_vec(), fmt), (rsa_cert_der(), "der"));
}

#[test]
fn test_p12_format_is_not_handled_here() {
    let provider = FakeProvider::new("mem");
    let info = provider
        .import_key(&private_material(), "rsa1", None, None)
        .unwrap();
    let err = keyexport::export_bytes(&provider, &info, "p12", false, None).unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "format".into()
        }
    );
    assert!(err.message.contains("certops"));
}

#[test]
fn test_unknown_format_rejected() {
    let provider = FakeProvider::new("mem");
    let info = provider
        .import_key(&aes_material(), "aes1", None, None)
        .unwrap();
    let err = keyexport::export_bytes(&provider, &info, "jwk", false, None).unwrap_err();
    assert!(err.message.contains("unknown export format"));
    assert_eq!(err.message, "unknown export format 'jwk'");
    assert_eq!(
        err.hint.as_deref(),
        Some("valid formats: auto, raw, der, pem, p12")
    );
}

// ---------------------------------------------------------------------------------------
// public-part resolution (§5.6 --public / §5.7 step 1)
// ---------------------------------------------------------------------------------------

#[test]
fn test_public_flag_prefers_public_object_sharing_id() {
    let provider = hsm();
    let shared = [0x11, 0x22, 0x33, 0x44];
    let private = provider
        .import_key(
            &private_material(),
            "pair",
            Some(&sensitive_template()),
            Some(&shared),
        )
        .unwrap();
    provider
        .import_key(&public_material(), "pair", None, Some(&shared))
        .unwrap();
    // private itself is NOT exportable — the public half must be used
    let (payload, resolved) =
        keyexport::export_bytes(&provider, &private, "auto", true, None).unwrap();
    assert_eq!(resolved, "pem");
    assert!(payload.starts_with(b"-----BEGIN PUBLIC KEY-----"));
}

#[test]
fn test_public_flag_falls_back_to_certificate() {
    let provider = hsm();
    let shared = [0x01, 0x02, 0x03, 0x04];
    let private = provider
        .import_key(
            &private_material(),
            "pair",
            Some(&sensitive_template()),
            Some(&shared),
        )
        .unwrap();
    provider
        .import_key(&cert_material(), "pair", None, Some(&shared))
        .unwrap();
    let (payload, _) = keyexport::export_bytes(&provider, &private, "der", true, None).unwrap();
    assert_eq!(payload.to_vec(), rsa_spki_der()); // SPKI extracted from the certificate
}

#[test]
fn find_public_part_bucket_order() {
    let provider = hsm();
    let key = provider
        .import_key(&private_material(), "pair", None, Some(&[0xaa]))
        .unwrap();
    assert_eq!(keyexport::find_public_part(&provider, &key).unwrap(), None);
    let cert_by_label = provider
        .import_key(&cert_material(), "pair", None, Some(&[0xcc]))
        .unwrap();
    assert_eq!(
        keyexport::find_public_part(&provider, &key).unwrap(),
        Some(cert_by_label)
    );
    let cert_by_id = provider
        .import_key(&cert_material(), "other", None, Some(&[0xaa]))
        .unwrap();
    assert_eq!(
        keyexport::find_public_part(&provider, &key).unwrap(),
        Some(cert_by_id)
    );
    let public_by_label = provider
        .import_key(&public_material(), "pair", None, Some(&[0xdd]))
        .unwrap();
    assert_eq!(
        keyexport::find_public_part(&provider, &key).unwrap(),
        Some(public_by_label)
    );
    let public_by_id = provider
        .import_key(&public_material(), "x", None, Some(&[0xaa]))
        .unwrap();
    assert_eq!(
        keyexport::find_public_part(&provider, &key).unwrap(),
        Some(public_by_id)
    );
}

#[test]
fn test_public_flag_derives_spki_from_exportable_private() {
    let provider = FakeProvider::new("mem");
    let private = provider
        .import_key(&private_material(), "solo", None, None)
        .unwrap();
    let (payload, _) = keyexport::export_bytes(&provider, &private, "der", true, None).unwrap();
    assert_eq!(payload.to_vec(), rsa_spki_der());
}

#[test]
fn test_public_flag_without_any_public_part() {
    let provider = hsm();
    let private = provider
        .import_key(
            &private_material(),
            "solo",
            Some(&sensitive_template()),
            None,
        )
        .unwrap();
    let err = keyexport::export_bytes(&provider, &private, "auto", true, None).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotFound);
    assert!(err.message.contains("no public part"));
    assert_eq!(err.message, "no public part found for 'hsm:solo#00000001'");
    assert_eq!(
        err.hint.as_deref(),
        Some(
            "the private key is not exportable and no public key or certificate shares its \
             label/CKA_ID"
        )
    );
}

#[test]
fn test_public_flag_on_secret_key_unsupported() {
    let provider = FakeProvider::new("mem");
    let info = provider
        .import_key(&aes_material(), "aes1", None, None)
        .unwrap();
    let err = keyexport::export_bytes(&provider, &info, "auto", true, None).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("no public part"));
    assert_eq!(
        err.message,
        "'mem:aes1' is a secret object and has no public part"
    );
}

#[test]
fn test_public_flag_rejects_raw() {
    let provider = FakeProvider::new("mem");
    let info = provider
        .import_key(&public_material(), "pub1", None, None)
        .unwrap();
    let err = keyexport::export_bytes(&provider, &info, "raw", true, None).unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "format".into()
        }
    );
    assert!(err.message.contains("pem or der"));
    assert_eq!(
        err.hint.as_deref(),
        Some("use --format pem or --format der with --public")
    );
}

// ---------------------------------------------------------------------------------------
// write_output
// ---------------------------------------------------------------------------------------

#[test]
fn test_write_output_writes_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("out.bin");
    keyexport::write_output(&target, b"\x00\x01").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"\x00\x01");
}

#[test]
fn test_write_output_failure_is_dataioerror() {
    let dir = tempfile::tempdir().unwrap();
    let err =
        keyexport::write_output(&dir.path().join("missing-dir").join("out.bin"), b"x").unwrap_err();
    assert_eq!(err.kind, ErrorKind::DataIo);
    assert!(err.message.contains("cannot write"));
    // the OS wording is the system's on Windows (ERROR_PATH_NOT_FOUND)
    let missing = if cfg!(windows) {
        "The system cannot find the path specified."
    } else {
        "No such file or directory"
    };
    assert!(
        err.message.ends_with(&format!("out.bin: {missing}")),
        "{}",
        err.message
    );
}

// ---------------------------------------------------------------------------------------
// ambiguity propagates from find_key (command-level error path, §4.5)
// ---------------------------------------------------------------------------------------

#[test]
fn test_ambiguous_label_raises_from_find_key() {
    let provider = FakeProvider::new("mem");
    provider
        .import_key(&aes_material(), "dup", None, None)
        .unwrap();
    // twin via the backdoor — the §4.7 guard refuses API creation
    provider.store_key_unchecked(&aes_material(), "dup", None, None);
    let err = provider.find_key(&KeySelector::label("dup")).unwrap_err();
    assert_eq!(err.candidates().unwrap().len(), 2);
}

#[test]
fn test_key_info_export_matches_class() {
    // export_key on a KeyInfo resolves by ref AND class (keypair halves)
    let provider = FakeProvider::new("mem");
    provider
        .import_key(&private_material(), "pair", None, None)
        .unwrap();
    let public = provider
        .import_key(&public_material(), "pair", None, None)
        .unwrap();
    assert_eq!(
        keyexport::public_spki(&provider, &public).unwrap(),
        rsa_spki_der()
    );
}

// ---------------------------------------------------------------------------------------
// data objects / unmodelled key types (test_objects_services.py)
// ---------------------------------------------------------------------------------------

const VALUE: &[u8] = b"opaque bytes \x00\x01\x02 -- not a key";

#[test]
fn test_export_bytes_data_object_is_raw_only() {
    let mem = FakeProvider::new("mem");
    let info = mem
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, VALUE.to_vec()),
            "blob",
            None,
            None,
        )
        .unwrap();
    assert_eq!(export(&mem, &info).unwrap(), (VALUE.to_vec(), "raw"));
    let (payload, fmt) = keyexport::export_bytes(&mem, &info, "raw", false, None).unwrap();
    assert_eq!((payload.to_vec(), fmt), (VALUE.to_vec(), "raw"));
    let err = keyexport::export_bytes(&mem, &info, "pem", false, None).unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "format".into()
        }
    );
    assert_eq!(err.message, "data objects export as raw bytes, not 'pem'");
    let err = keyexport::export_bytes(&mem, &info, "auto", true, None).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
}

#[test]
fn export_refuses_unmodelled_key_types() {
    let mem = FakeProvider::new("mem");
    let info = mem.store_key_unchecked(
        &KeyMaterial::new(KeyAlgorithm::Other, KeyClass::Secret, vec![b'x'; 24]),
        "des3",
        None,
        Some(&[0x01]),
    );
    let err = export(&mem, &info).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("not supported"));
    let key_type = info
        .attributes
        .get("CKA_KEY_TYPE")
        .map_or_else(|| "unknown".to_owned(), AttrValue::render_info);
    assert_eq!(
        err.message,
        format!(
            "key type {key_type} of 'mem:des3#01' is not supported by r2 and cannot be exported"
        )
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("objects of unsupported key types can be listed and deleted only")
    );
}
