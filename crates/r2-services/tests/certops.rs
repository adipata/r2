// services::certops — port of c2 tests/unit/services/test_certops.py (R8 cases: PKCS#12
// export and the §5.7 CSR flow; certificate_details / ecdsa_rs_to_der moved to R6).
//
// The CSR tests prove the ECDSA r‖s → DER conversion (§4.4.4/§5.7): a FakeProvider hook
// returns a KNOWN fixed-width r‖s and the CSR must carry its DER SEQUENCE; MemoryProvider
// (real OpenSSL, genuine r‖s per §4.5.4) produces CSRs whose signature verifies.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod keyload_fixtures;

use std::cell::RefCell;
use std::rc::Rc;

use keyload_fixtures::*;
use r2_core::der::ecdsa_der_to_rs;
use r2_core::error::{ErrorKind, Result};
use r2_core::keyparse::{KeyHint, parse_key_material};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::{ParamValue, Params};
use r2_core::x509info::{certificate_details, rfc4514_string};
use r2_memory::MemoryProvider;
use r2_provider::{GenerateRequest, MechanismInvocation, Provider};
use r2_services::certops;
use r2_testkit::{FakeHooks, FakeProvider};
use secrecy::SecretString;

fn secret(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

/// The members of a PKCS#12 as r2's pyca-port loads them (private, certificate, …).
fn load_p12(payload: &[u8], password: &str) -> Vec<KeyMaterial> {
    let mut pw = |_: &str| Ok(secret(password));
    parse_key_material(payload, KeyHint::Auto, Some(&mut pw)).unwrap()
}

fn subject_of(cert_der: &[u8]) -> String {
    certificate_details(cert_der)
        .unwrap()
        .into_iter()
        .find(|(name, _)| name == "subject")
        .unwrap()
        .1
}

fn issuer_of(cert_der: &[u8]) -> String {
    certificate_details(cert_der)
        .unwrap()
        .into_iter()
        .find(|(name, _)| name == "issuer")
        .unwrap()
        .1
}

/// critical basicConstraints with an empty SEQUENCE (CA:FALSE).
const CA_FALSE_EXTENSION: [u8; 12] = [
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00,
];

// ---------------------------------------------------------------------------------------
// find_certificate
// ---------------------------------------------------------------------------------------

#[test]
fn test_find_certificate_prefers_shared_id_over_label() {
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    let key = provider
        .import_key(&private_material(), "pair", None, Some(&[0xaa, 0xbb]))
        .unwrap();
    provider
        .import_key(&cert_material(), "other-label", None, Some(&[0xaa, 0xbb]))
        .unwrap();
    provider
        .import_key(&cert_material(), "pair", None, Some(&[0xcc, 0xdd]))
        .unwrap();
    let found = certops::find_certificate(&provider, &key).unwrap().unwrap();
    assert_eq!(found.key_ref.key_id.as_deref(), Some(&[0xaa, 0xbb][..])); // id wins (§5.6)
}

#[test]
fn test_find_certificate_by_label_when_no_id_match() {
    let provider = FakeProvider::new("mem");
    let key = provider
        .import_key(&private_material(), "pair", None, None)
        .unwrap();
    provider
        .import_key(&cert_material(), "pair", None, None)
        .unwrap();
    let found = certops::find_certificate(&provider, &key).unwrap().unwrap();
    assert_eq!(found.key_class, KeyClass::Certificate);
}

#[test]
fn test_find_certificate_none() {
    let provider = FakeProvider::new("mem");
    let key = provider
        .import_key(&private_material(), "solo", None, None)
        .unwrap();
    assert_eq!(certops::find_certificate(&provider, &key).unwrap(), None);
}

// ---------------------------------------------------------------------------------------
// export_pkcs12 (§5.6)
// ---------------------------------------------------------------------------------------

#[test]
fn test_pkcs12_with_provider_certificate() {
    let provider = FakeProvider::new("mem");
    let key = provider
        .import_key(&private_material(), "bundle", None, None)
        .unwrap();
    provider
        .import_key(&cert_material(), "bundle", None, None)
        .unwrap();
    let payload = certops::export_pkcs12(&provider, &key, &secret("pw"), None).unwrap();
    let loaded = load_p12(&payload, "pw");
    assert_eq!(loaded[0].key_class, KeyClass::Private);
    assert_eq!(loaded[0].data.as_slice(), rsa_pkcs8_der().as_slice());
    assert_eq!(loaded[1].key_class, KeyClass::Certificate);
    assert_eq!(loaded[1].data.as_slice(), rsa_cert_der().as_slice());
    assert_eq!(loaded[1].label_hint.as_deref(), Some("bundle")); // friendly name
}

#[test]
fn test_pkcs12_missing_cert_builds_self_signed() {
    let provider = FakeProvider::new("mem");
    let key = provider
        .import_key(&private_material(), "lonely", None, None)
        .unwrap();
    let payload = certops::export_pkcs12(&provider, &key, &secret("pw"), None).unwrap();
    let loaded = load_p12(&payload, "pw");
    let cert = &loaded[1];
    assert_eq!(cert.key_class, KeyClass::Certificate);
    // §5.6: Subject = Issuer = CN=<key label>, CA:FALSE
    assert_eq!(subject_of(&cert.data), "CN=lonely");
    assert_eq!(issuer_of(&cert.data), "CN=lonely");
    assert!(contains(&cert.data, &CA_FALSE_EXTENSION));
    // signed with the exported key itself
    assert!(contains(&cert.data, &rsa_spki_der()));
}

#[test]
fn test_pkcs12_explicit_cert_der_wins() {
    let provider = FakeProvider::new("mem");
    let key = provider
        .import_key(&private_material(), "bundle", None, None)
        .unwrap();
    let cert = rsa_cert_der();
    let payload = certops::export_pkcs12(&provider, &key, &secret("pw"), Some(&cert)).unwrap();
    let loaded = load_p12(&payload, "pw");
    assert_eq!(subject_of(&loaded[1].data), "CN=unit-test-cert");
}

#[test]
fn test_pkcs12_non_exportable_key_refused_before_export() {
    let provider = FakeProvider::new("hsm").with_type_name("pkcs11");
    let key = provider
        .import_key(
            &private_material(),
            "locked",
            Some(&sensitive_template()),
            None,
        )
        .unwrap();
    let err = certops::export_pkcs12(&provider, &key, &secret("pw"), None).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(err.message.contains("Refusing to export"));
    assert!(!provider.calls().iter().any(|c| c[0] == "export_key"));
}

#[test]
fn test_pkcs12_needs_a_private_key() {
    let provider = FakeProvider::new("mem");
    let cert = provider
        .import_key(&cert_material(), "certonly", None, None)
        .unwrap();
    let err = certops::export_pkcs12(&provider, &cert, &secret("pw"), None).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("private key"));
    assert_eq!(
        err.message,
        "PKCS#12 export needs a private key, got certificate 'mem:certonly'"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("certificates and public keys export as pem/der instead")
    );
}

#[test]
fn test_pkcs12_empty_password_rejected() {
    let provider = FakeProvider::new("mem");
    let key = provider
        .import_key(&private_material(), "bundle", None, None)
        .unwrap();
    let err = certops::export_pkcs12(&provider, &key, &secret(""), None).unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "password".into()
        }
    );
    assert!(err.message.contains("password"));
}

/// §11 D12(a): the self-signed CN is checked (UTF-8 bytes) BEFORE anything is exported.
#[test]
fn pkcs12_label_outside_cn_limits_is_refused_before_export() {
    let provider = FakeProvider::new("mem");
    let label = "é".repeat(40);
    let key = provider
        .import_key(&private_material(), &label, None, None)
        .unwrap();
    provider.clear_calls();
    let err = certops::export_pkcs12(&provider, &key, &secret("pw"), None).unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "label".into()
        }
    );
    assert_eq!(
        err.message,
        "Attribute's length must be >= 1 and <= 64, but it was 80"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("pass an existing certificate with --cert")
    );
    assert!(!provider.calls().iter().any(|c| c[0] == "export_key"));
    // with an explicit certificate the label is irrelevant
    let cert = rsa_cert_der();
    certops::export_pkcs12(&provider, &key, &secret("pw"), Some(&cert)).unwrap();
}

// ---------------------------------------------------------------------------------------
// generate_csr — §5.7 flow
// ---------------------------------------------------------------------------------------

/// Deterministic fixed-width r‖s the fake HSM returns (P-256 width: 32+32).
fn fixed_rs() -> Vec<u8> {
    let mut r = vec![0x01];
    r.extend([0x00; 30]);
    r.push(0x2a);
    let mut s = vec![0x00; 30];
    s.extend([0x0b, 0xcd]);
    [r, s].concat()
}

/// DER ECDSA-Sig-Value of fixed_rs(), written out by hand.
fn fixed_rs_der() -> Vec<u8> {
    let mut der = vec![0x30, 0x26, 0x02, 0x20, 0x01];
    der.extend([0x00; 30]);
    der.extend([0x2a, 0x02, 0x02, 0x0b, 0xcd]);
    der
}

/// Presents like a PKCS#11 token: ECDSA sign returns fixed-width r‖s (§5.8-§5.10).
#[derive(Default)]
struct FixedRsSigner {
    sign_mechs: RefCell<Vec<MechanismInvocation>>,
}
impl FakeHooks for FixedRsSigner {
    fn sign(
        &self,
        _next: &dyn Provider,
        _key: &KeyInfo,
        mech: &MechanismInvocation,
        _data: &[u8],
    ) -> Option<Result<Vec<u8>>> {
        self.sign_mechs.borrow_mut().push(mech.clone());
        assert_eq!(mech.mechanism, "ECDSA");
        Some(Ok(fixed_rs()))
    }
}

/// An EC private key whose real SPKI is available via the shared-id public half.
fn ec_key_with_public(provider: &FakeProvider) -> KeyInfo {
    let shared = [0x77, 0x88];
    let mut private = KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Private, vec![0; 32]);
    private.curve = Some(Curve::P256);
    let key = provider
        .import_key(
            &private,
            "eckey",
            Some(&sensitive_template()),
            Some(&shared),
        )
        .unwrap(); // non-exportable: the SPKI MUST come from the public half
    provider
        .import_key(&ec_public_material(), "eckey", None, Some(&shared))
        .unwrap();
    key
}

#[test]
fn test_csr_ecdsa_signature_is_der_converted_rs() {
    let hooks = Rc::new(FixedRsSigner::default());
    let provider = FakeProvider::new("hsm")
        .with_type_name("pkcs11")
        .with_hooks(Rc::clone(&hooks) as Rc<dyn FakeHooks>);
    let key = ec_key_with_public(&provider);
    let pem = certops::generate_csr(&provider, &key, "CN=fixed", "sha256").unwrap();
    let csr = csr_parts(&pem);
    assert_ne!(csr.signature, fixed_rs()); // NOT the raw provider output
    assert_eq!(csr.signature, fixed_rs_der());
    assert_eq!(ecdsa_der_to_rs(&csr.signature, 32).unwrap(), fixed_rs());
    // the provider signed with the console mechanism + requested hash
    let mut expected = Params::new();
    expected.insert("hash".into(), ParamValue::Enum("sha256".into()));
    assert_eq!(hooks.sign_mechs.borrow()[0].params, expected);
    assert_eq!(csr.spki, ec_spki_der());
}

/// Verify a CSR's self-signature with MemoryProvider over its own SPKI.
fn verify_csr(csr: &CsrParts, algorithm: KeyAlgorithm, mech: MechanismInvocation, half: usize) {
    let verifier = MemoryProvider::new("verifier");
    let public = verifier
        .import_key(
            &KeyMaterial::new(algorithm, KeyClass::Public, csr.spki.clone()),
            "csr-key",
            None,
            None,
        )
        .unwrap();
    let signature = if half > 0 {
        ecdsa_der_to_rs(&csr.signature, half).unwrap() // parses as DER ECDSA-Sig-Value
    } else {
        csr.signature.clone()
    };
    assert!(
        verifier
            .verify(&public, &mech, &csr.cri, &signature)
            .unwrap()
    );
}

fn hash_mech(mechanism: &str, hash: &str) -> MechanismInvocation {
    let mut params = Params::new();
    params.insert("hash".into(), ParamValue::Enum(hash.into()));
    MechanismInvocation::new(mechanism, params)
}

fn generate(
    provider: &MemoryProvider,
    algorithm: KeyAlgorithm,
    curve: Curve,
    label: &str,
) -> KeyInfo {
    let mut request = GenerateRequest::new(algorithm, label);
    request.curve = Some(curve);
    provider.generate_key(&request).unwrap()
}

#[test]
fn test_csr_ecdsa_real_crypto_verifies() {
    let provider = MemoryProvider::new("mem");
    let key = generate(&provider, KeyAlgorithm::Ec, Curve::P256, "ec1");
    let pem = certops::generate_csr(&provider, &key, "CN=ec1,O=ACME", "sha384").unwrap();
    let csr = csr_parts(&pem);
    assert_eq!(rfc4514_string(&csr.subject).unwrap(), "CN=ec1,O=ACME");
    // ecdsa-with-SHA384
    assert!(contains(
        &csr.algorithm,
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]
    ));
    verify_csr(&csr, KeyAlgorithm::Ec, hash_mech("ECDSA", "sha384"), 32);
}

#[test]
fn test_csr_rsa_real_crypto_verifies() {
    let provider = MemoryProvider::new("mem");
    let key = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, rsa_pkcs8_der()),
            "rsa1",
            None,
            None,
        )
        .unwrap();
    let pem = certops::generate_csr(&provider, &key, "CN=rsa1", "sha256").unwrap();
    assert!(pem.starts_with(b"-----BEGIN CERTIFICATE REQUEST-----\n"));
    let csr = csr_parts(&pem);
    // sha256WithRSAEncryption + NULL
    assert!(contains(
        &csr.algorithm,
        &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00
        ]
    ));
    verify_csr(&csr, KeyAlgorithm::Rsa, hash_mech("RSA-PKCS1", "sha256"), 0);
}

#[test]
fn test_csr_ed25519_real_crypto_verifies() {
    let provider = MemoryProvider::new("mem");
    let key = generate(&provider, KeyAlgorithm::EcEdwards, Curve::Ed25519, "ed1");
    let pem = certops::generate_csr(&provider, &key, "CN=ed1", "sha256").unwrap();
    let csr = csr_parts(&pem);
    // id-Ed25519, no parameters (Ed keys hash internally)
    assert_eq!(csr.algorithm, [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    verify_csr(
        &csr,
        KeyAlgorithm::EcEdwards,
        MechanismInvocation::new("EDDSA", Params::new()),
        0,
    );
}

#[test]
fn csr_ed448_uses_the_ed448_algorithm() {
    let provider = MemoryProvider::new("mem");
    let key = generate(&provider, KeyAlgorithm::EcEdwards, Curve::Ed448, "ed2");
    let pem = certops::generate_csr(&provider, &key, "CN=ed2", "sha512").unwrap();
    let csr = csr_parts(&pem);
    assert_eq!(csr.algorithm, [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71]);
    verify_csr(
        &csr,
        KeyAlgorithm::EcEdwards,
        MechanismInvocation::new("EDDSA", Params::new()),
        0,
    );
}

#[test]
fn test_csr_hash_choices_enforced() {
    let provider = FakeProvider::new("mem");
    let key = provider
        .import_key(&private_material(), "rsa1", None, None)
        .unwrap();
    let err = certops::generate_csr(&provider, &key, "CN=x", "sha1").unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "hash".into()
        }
    );
    assert_eq!(err.message, "unknown CSR hash 'sha1'");
    assert_eq!(
        err.hint.as_deref(),
        Some("valid hashes: sha256, sha384, sha512")
    );
}

#[test]
fn test_csr_needs_private_key() {
    let provider = FakeProvider::new("mem");
    let cert = provider
        .import_key(&cert_material(), "certonly", None, None)
        .unwrap();
    let err = certops::generate_csr(&provider, &cert, "CN=x", "sha256").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("private key"));
    assert_eq!(
        err.message,
        "CSR generation needs a private key, got certificate 'mem:certonly'"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("reference the private key: csr <provider>:<label> <path>")
    );
}

#[test]
fn test_csr_montgomery_keys_unsupported() {
    let provider = MemoryProvider::new("mem");
    let key = generate(&provider, KeyAlgorithm::EcMontgomery, Curve::X25519, "x1");
    let err = certops::generate_csr(&provider, &key, "CN=x", "sha256").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("CSR"));
    assert_eq!(err.message, "cannot build a CSR for ec-montgomery keys");
    assert_eq!(
        err.hint.as_deref(),
        Some("CSRs need an RSA, EC or Ed25519/Ed448 key")
    );
}

#[test]
fn test_csr_invalid_subject_is_param_error() {
    let provider = MemoryProvider::new("mem");
    let key = generate(&provider, KeyAlgorithm::Ec, Curve::P256, "ec1");
    let err = certops::generate_csr(&provider, &key, "not-a-dn", "sha256").unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "subject".into()
        }
    );
    assert!(err.message.contains("subject"));
}
