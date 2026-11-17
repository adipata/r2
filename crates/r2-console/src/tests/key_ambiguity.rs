// A ref that fits several keys never silently picks one (r2 addition to the §4.5.3 family
// rule and the §5.1 verify public-half lookup): a secret key beside a keypair with the same
// label is ambiguous, and so is a private key with two public halves or certificates.
use r2_core::error::ErrorKind;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_provider::{KeySelector, Provider};
use r2_testkit::FakeProvider;
use r2_testkit::fixtures::{ec_p256_pkcs8, rsa_pkcs8_and_cert, self_signed_cert};

use crate::commands::crypto::public_half_for_verify;

fn material(algorithm: KeyAlgorithm, key_class: KeyClass, data: &[u8]) -> KeyMaterial {
    KeyMaterial::new(algorithm, key_class, data.to_vec())
}

#[test]
fn a_secret_key_beside_a_keypair_is_ambiguous() {
    let hsm = FakeProvider::new("hsm");
    let (pkcs8, cert) = rsa_pkcs8_and_cert();
    hsm.import_key(
        &material(KeyAlgorithm::Rsa, KeyClass::Private, &pkcs8),
        "k",
        None,
        None,
    )
    .unwrap();
    hsm.import_key(
        &material(KeyAlgorithm::Aes, KeyClass::Secret, &[7; 16]),
        "k",
        None,
        None,
    )
    .unwrap();
    let err = hsm.find_key(&KeySelector::label("k")).unwrap_err();
    assert!(
        matches!(err.kind, ErrorKind::AmbiguousKey { .. }),
        "{err:?}"
    );
    assert!(
        err.message.starts_with("'k' matches 2 keys on hsm"),
        "{}",
        err.message
    );
    // a class selector still picks one
    let secret = hsm
        .find_key(&KeySelector::label("k").with_class(Some(KeyClass::Secret)))
        .unwrap();
    assert_eq!(secret.key_class, KeyClass::Secret);

    // a keypair with its certificate is still one key: the private half wins
    let pair = FakeProvider::new("hsm");
    pair.import_key(
        &material(KeyAlgorithm::Rsa, KeyClass::Private, &pkcs8),
        "p",
        None,
        None,
    )
    .unwrap();
    pair.import_key(
        &material(KeyAlgorithm::Rsa, KeyClass::Certificate, &cert),
        "p",
        None,
        None,
    )
    .unwrap();
    let found = pair.find_key(&KeySelector::label("p")).unwrap();
    assert_eq!(found.key_class, KeyClass::Private);
}

#[test]
fn verify_with_two_certificates_for_one_private_key_is_ambiguous() {
    let hsm = FakeProvider::new("hsm");
    let pkcs8 = ec_p256_pkcs8();
    let mut ec = material(KeyAlgorithm::Ec, KeyClass::Private, &pkcs8);
    ec.curve = Some(r2_core::keys::Curve::P256);
    hsm.import_key(&ec, "v", None, None).unwrap();
    for cn in ["one", "two"] {
        let cert = self_signed_cert(&pkcs8, cn);
        hsm.import_key(
            &material(KeyAlgorithm::Ec, KeyClass::Certificate, &cert),
            "v",
            None,
            None,
        )
        .unwrap();
    }
    let private = hsm
        .find_key(&KeySelector::label("v").with_class(Some(KeyClass::Private)))
        .unwrap();
    let err = public_half_for_verify(&hsm, private).unwrap_err();
    assert!(
        matches!(err.kind, ErrorKind::AmbiguousKey { .. }),
        "{err:?}"
    );
    assert!(
        err.message
            .starts_with("'v' has 2 certificate objects to verify with on hsm: "),
        "{}",
        err.message
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("name the one to verify with: label#id, :pub/:cert, or @handle")
    );
}
