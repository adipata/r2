// MemoryProvider tests beyond c2's suite (R4 Accept list, spec §4.5.4/§5.4/§5.5/§5.8–§5.10):
// byte-compatibility with c2's RSA-AES-KEY-WRAP blobs (vectors produced by c2 itself,
// tests/support/gen_c2_vectors.py), the §5.8 pre-validated pyca texts, RFC 4231 / RFC 5649
// KATs, round-trips for every advertised mechanism, the non-P curves pyca supports, and
// the §4.3/§4.5.2 material and identity rules.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod support;

use openssl::cipher::Cipher as EvpCipher;
use openssl::cipher_ctx::{CipherCtx, CipherCtxFlags};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Padding;
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::params::ParamValue;
use r2_memory::MemoryProvider;
use r2_provider::mechanism::CANONICAL_MECHANISMS;
use r2_provider::{KeySelector, MechanismInvocation, Provider, WrapOptions};
use support::c2_vectors as c2;
use support::*;

fn opts() -> WrapOptions {
    WrapOptions::default()
}

fn rsa_kek(provider: &MemoryProvider) -> (r2_core::keys::KeyInfo, PKey<Private>) {
    let key = PKey::private_key_from_der(&hex(c2::RSA_PKCS8)).unwrap();
    let info = import_private(provider, &key, KeyAlgorithm::Rsa, "kek", None, None);
    (info, key)
}

fn kwp_unwrap_independent(kek: &[u8], blob: &[u8]) -> Vec<u8> {
    let cipher = match kek.len() {
        16 => EvpCipher::aes_128_wrap_pad(),
        24 => EvpCipher::aes_192_wrap_pad(),
        _ => EvpCipher::aes_256_wrap_pad(),
    };
    let mut ctx = CipherCtx::new().unwrap();
    ctx.set_flags(CipherCtxFlags::FLAG_WRAP_ALLOW);
    ctx.decrypt_init(Some(cipher), Some(kek), None).unwrap();
    let mut out = Vec::new();
    ctx.cipher_update_vec(blob, &mut out).unwrap();
    ctx.cipher_final_vec(&mut out).unwrap();
    out
}

fn oaep_decrypt_independent(
    key: &PKey<Private>,
    data: &[u8],
    md: MessageDigest,
    mgf: MessageDigest,
    label: &[u8],
) -> Vec<u8> {
    let mut dec = openssl::encrypt::Decrypter::new(key).unwrap();
    dec.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
    dec.set_rsa_oaep_md(md).unwrap();
    dec.set_rsa_mgf1_md(mgf).unwrap();
    if !label.is_empty() {
        dec.set_rsa_oaep_label(label).unwrap();
    }
    let mut out = vec![0u8; dec.decrypt_len(data).unwrap()];
    let n = dec.decrypt(data, &mut out).unwrap();
    out.truncate(n);
    out
}

// ---------------------------------------------------------------------------------------
// RSA-AES-KEY-WRAP: c2's blob format, both directions (§5.5)
// ---------------------------------------------------------------------------------------

#[test]
fn rsa_aes_key_wrap_unwraps_blobs_made_by_c2() {
    let provider = make();
    let (kek, _) = rsa_kek(&provider);
    let restored = provider
        .unwrap_key(
            &kek,
            &mech("RSA-AES-KEY-WRAP", &[]),
            &hex(c2::RSA_AES_KEY_WRAP_DEFAULT_BLOB),
            &unwrap_req(KeyAlgorithm::Aes, KeyClass::Secret, "aes", None, None),
        )
        .unwrap();
    assert_eq!(
        *provider.export_key(&restored).unwrap().data,
        hex(c2::AES_TARGET)
    );

    let params = mech(
        "RSA-AES-KEY-WRAP",
        &[
            ("hash", text("sha384")),
            ("mgf_hash", text("sha1")),
            ("label", bytes(b"r2-label")),
        ],
    );
    let restored = provider
        .unwrap_key(
            &kek,
            &params,
            &hex(c2::RSA_AES_KEY_WRAP_SHA384_MGF1_LABEL_BLOB),
            &unwrap_req(KeyAlgorithm::Ec, KeyClass::Private, "ec", None, None),
        )
        .unwrap();
    assert_eq!(restored.curve, Some(Curve::P256));
    assert_eq!(
        *provider.export_key(&restored).unwrap().data,
        hex(c2::EC_PKCS8)
    );
    // wrong OAEP parameters → detail-free failure
    let err = err_class(
        provider.unwrap_key(
            &kek,
            &mech("RSA-AES-KEY-WRAP", &[]),
            &hex(c2::RSA_AES_KEY_WRAP_SHA384_MGF1_LABEL_BLOB),
            &unwrap_req(KeyAlgorithm::Ec, KeyClass::Private, "ec2", None, None),
        ),
        "CryptoError",
    );
    assert_eq!(err.message, "RSA-AES-KEY-WRAP unwrap failed");
}

#[test]
fn rsa_aes_key_wrap_blob_is_c2s_format() {
    // OAEP(hash, mgf_hash, label)(32 random bytes) ‖ KWP(those 32 bytes, payload), split at
    // k = modulus bytes — decoded here without the provider.
    let provider = make();
    let (_, key) = rsa_kek(&provider);
    let public = import_public(&provider, &key, KeyAlgorithm::Rsa, "kek-pub", None);
    let target = import_aes(&provider, &hex(c2::AES_TARGET), "aes", None, None);
    for (entries, md, mgf, label) in [
        (
            vec![],
            MessageDigest::sha256(),
            MessageDigest::sha256(),
            &b""[..],
        ),
        (
            vec![
                ("hash", text("sha384")),
                ("mgf_hash", text("sha1")),
                ("label", bytes(b"r2-label")),
            ],
            MessageDigest::sha384(),
            MessageDigest::sha1(),
            &b"r2-label"[..],
        ),
    ] {
        let blob = provider
            .wrap_key(
                &public,
                &mech("RSA-AES-KEY-WRAP", &entries),
                &target,
                &opts(),
            )
            .unwrap();
        assert_eq!(blob.len(), 256 + 40); // k + KWP(32-byte payload)
        let ephemeral = oaep_decrypt_independent(&key, &blob[..256], md, mgf, label);
        assert_eq!(ephemeral.len(), 32);
        assert_eq!(
            kwp_unwrap_independent(&ephemeral, &blob[256..]),
            hex(c2::AES_TARGET)
        );
    }
}

#[test]
fn aes_key_wrap_pad_reads_both_dialects_made_by_pyca() {
    let provider = make();
    let kek = import_aes(&provider, &hex(c2::KEK), "kek", None, None);
    for (blob, label) in [
        (c2::UTIMACO_PAD_DIALECT_BLOB, "utimaco"),
        (c2::RFC5649_KWP_BLOB, "kwp"),
    ] {
        let restored = provider
            .unwrap_key(
                &kek,
                &mech("AES-KEY-WRAP-PAD", &[]),
                &hex(blob),
                &unwrap_req(KeyAlgorithm::Ec, KeyClass::Private, label, None, None),
            )
            .unwrap();
        assert_eq!(
            *provider.export_key(&restored).unwrap().data,
            hex(c2::EC_PKCS8)
        );
    }
    // the KWP blob c2 wrote is exactly what r2 writes for the same payload
    let target = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Private, hex(c2::EC_PKCS8)),
            "ec",
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        provider
            .wrap_key(&kek, &mech("AES-KEY-WRAP-PAD", &[]), &target, &opts())
            .unwrap(),
        hex(c2::RFC5649_KWP_BLOB)
    );
}

// ---------------------------------------------------------------------------------------
// KATs: RFC 4231 (HMAC), RFC 5649 (KWP)
// ---------------------------------------------------------------------------------------

#[test]
fn hmac_equals_rfc4231_test_case_1() {
    let provider = make();
    let info = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, vec![0x0b; 20]),
            "rfc4231",
            None,
            None,
        )
        .unwrap();
    for (hash, expected) in [
        (
            "sha224",
            "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
        ),
        (
            "sha256",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            "sha384",
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        ),
        (
            "sha512",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ),
    ] {
        let hmac = mech("HMAC", &[("hash", text(hash))]);
        assert_eq!(
            provider.sign(&info, &hmac, b"Hi There").unwrap(),
            hex(expected)
        );
        assert!(
            provider
                .verify(&info, &hmac, b"Hi There", &hex(expected))
                .unwrap()
        );
    }
}

#[test]
fn aes_key_wrap_pad_equals_rfc5649_section6() {
    let provider = make();
    let kek_bytes = hex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
    let kek = import_aes(&provider, &kek_bytes, "kek", None, None);
    let kwp = mech("AES-KEY-WRAP-PAD", &[]);
    for (label, key, wrapped) in [
        (
            "twenty",
            "c37b7e6492584340bed12207808941155068f738",
            "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
        ),
        (
            "seven",
            "466f7250617369",
            "afbeb0f07dfbf5419200f2ccb50bb24f",
        ),
    ] {
        let target = provider
            .import_key(
                &KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, hex(key)),
                label,
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            provider.wrap_key(&kek, &kwp, &target, &opts()).unwrap(),
            hex(wrapped)
        );
        let restored = provider
            .unwrap_key(
                &kek,
                &kwp,
                &hex(wrapped),
                &unwrap_req(
                    KeyAlgorithm::Generic,
                    KeyClass::Secret,
                    &format!("{label}-copy"),
                    None,
                    None,
                ),
            )
            .unwrap();
        assert_eq!(*provider.export_key(&restored).unwrap().data, hex(key));
    }
}

// ---------------------------------------------------------------------------------------
// §5.8 pre-validation: pyca's exact texts inside c2's rendering
// ---------------------------------------------------------------------------------------

#[test]
fn pre_validated_aes_texts_are_pycas() {
    let provider = make();
    let aes = import_aes(&provider, &[0u8; 16], "aes", None, None);
    for iv_len in [4usize, 7, 129] {
        let err = err_class(
            provider.encrypt(
                &aes,
                &mech("AES-GCM", &[("iv", bytes(&vec![0u8; iv_len]))]),
                b"x",
            ),
            "ParamError",
        );
        assert_eq!(
            err.message,
            "initialization_vector must be between 8 and 128 bytes (64 and 1024 bits)."
        );
        assert_eq!(err.param_name(), Some("iv"));
    }
    // OpenSSL accepts a 128-byte IV as pyca does
    provider
        .encrypt(&aes, &mech("AES-GCM", &[("iv", bytes(&[0u8; 128]))]), b"x")
        .unwrap();
    let err = err_class(
        provider.decrypt(&aes, &mech("AES-ECB", &[]), &[0u8; 20]),
        "CryptoError",
    );
    assert_eq!(
        err.message,
        "AES-ECB decryption failed: The length of the provided data is not a multiple of the block length."
    );
    // ECB/CBC pkcs7 of empty input: one padding block; decrypting empty with pkcs7 fails
    assert_eq!(
        provider
            .encrypt(&aes, &mech("AES-ECB", &[("padding", text("pkcs7"))]), b"")
            .unwrap()
            .len(),
        16
    );
    let err = err_class(
        provider.decrypt(&aes, &mech("AES-ECB", &[("padding", text("pkcs7"))]), b""),
        "CryptoError",
    );
    assert_eq!(err.message, "invalid PKCS7 padding in decrypted data");
    assert!(
        provider
            .decrypt(&aes, &mech("AES-ECB", &[]), b"")
            .unwrap()
            .is_empty()
    );
    for (mechanism, param) in [
        (mech("AES-CTR", &[]), "counter_block"),
        (mech("AES-GCM", &[]), "iv"),
        (mech("AES-GMAC", &[]), "iv"),
    ] {
        let result = if mechanism.mechanism == "AES-GMAC" {
            provider.sign(&aes, &mechanism, b"")
        } else {
            provider.encrypt(&aes, &mechanism, b"")
        };
        let err = err_class(result, "ParamError");
        assert_eq!(err.message, format!("missing required parameter '{param}'"));
    }
    let err = err_class(
        provider.sign(
            &aes,
            &mech(
                "AES-GMAC",
                &[("iv", bytes(&[0u8; 12])), ("mac_len", int(17))],
            ),
            b"",
        ),
        "ParamError",
    );
    assert_eq!(err.message, "mac_len must be between 1 and 16 bytes");
}

#[test]
fn pre_validated_key_wrap_texts_are_pycas() {
    let provider = make();
    let kek = import_aes(&provider, &[0u8; 16], "kek", None, None);
    let short = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, vec![0u8; 8]),
            "g8",
            None,
            None,
        )
        .unwrap();
    let err = err_class(
        provider.wrap_key(&kek, &mech("AES-KEY-WRAP", &[]), &short, &opts()),
        "CryptoError",
    );
    assert_eq!(
        err.message,
        "AES key wrap failed: The key to wrap must be at least 16 bytes"
    );
    // RFC 5649 single-block case (c2: fa7f4cd787a33af5cab11586ea5a5cb4)
    assert_eq!(
        provider
            .wrap_key(&kek, &mech("AES-KEY-WRAP-PAD", &[]), &short, &opts())
            .unwrap(),
        hex("fa7f4cd787a33af5cab11586ea5a5cb4")
    );
    let unwrap = |name: &str, blob: &[u8]| {
        provider.unwrap_key(
            &kek,
            &mech(name, &[]),
            blob,
            &unwrap_req(KeyAlgorithm::Aes, KeyClass::Secret, "u", None, None),
        )
    };
    let err = err_class(unwrap("AES-KEY-WRAP", &[0u8; 20]), "CryptoError");
    assert_eq!(
        err.message,
        "AES key unwrap failed: Must be at least 24 bytes"
    );
    let err = err_class(unwrap("AES-KEY-WRAP", &[0u8; 25]), "CryptoError");
    assert_eq!(
        err.message,
        "AES key unwrap failed: The wrapped key must be a multiple of 8 bytes"
    );
    assert_eq!(err.hint, None);
    // §5.5 dual-dialect outcomes 1 and 5
    let hint = "CKM_AES_KEY_WRAP_PAD has two wire dialects (RFC 5649 vs RFC 3394+PKCS#7) — both were tried";
    let err = err_class(unwrap("AES-KEY-WRAP-PAD", &[0u8; 20]), "CryptoError");
    assert_eq!(
        err.message,
        "AES key unwrap failed: The length of the provided data is not a multiple of the block length."
    );
    assert_eq!(err.hint.as_deref(), Some(hint));
    for len in [10usize, 16] {
        let err = err_class(unwrap("AES-KEY-WRAP-PAD", &vec![0u8; len]), "CryptoError");
        assert_eq!(
            err.message,
            "AES key unwrap failed: blob matches neither AES-KEY-WRAP-PAD dialect (RFC 5649 KWP / RFC 3394 over PKCS#7-padded payload)"
        );
        assert_eq!(err.hint.as_deref(), Some(hint));
    }
}

#[test]
fn pre_validated_rsa_keygen_and_ecdh_peer_texts_are_pycas() {
    let provider = make();
    for bits in [512u32, 1000] {
        let err = err_class(
            generate(
                &provider,
                KeyAlgorithm::Rsa,
                Some(bits),
                None,
                "small",
                None,
            ),
            "ParamError",
        );
        assert_eq!(
            err.message,
            format!("invalid RSA key size {bits}: key_size must be at least 1024-bits.")
        );
        assert_eq!(err.param_name(), Some("size_bits"));
    }
    let ec = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "e",
        None,
    )
    .unwrap();
    for first in [0x06u8, 0x07, 0x00] {
        let mut hybrid = vec![first];
        hybrid.extend([0u8; 64]);
        let err = err_class(
            provider.derive(&ec, &mech("ECDH", &[("peer", bytes(&hybrid))])),
            "ParamError",
        );
        assert_eq!(
            err.message,
            "peer is not SPKI DER or an uncompressed EC point (0x04‖X‖Y): Unsupported elliptic curve point type"
        );
    }
    // a point not on the curve: c2's prefix + OpenSSL's reason (§11 D11)
    let mut off_curve = vec![0x04u8];
    off_curve.extend([0u8; 64]);
    let err = err_class(
        provider.derive(&ec, &mech("ECDH", &[("peer", bytes(&off_curve))])),
        "ParamError",
    );
    assert!(
        err.message
            .starts_with("peer is not SPKI DER or an uncompressed EC point (0x04‖X‖Y): ")
    );
    // a compressed point is accepted and used as is (pyca from_encoded_point)
    let peer = EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let compressed = peer
        .public_key()
        .to_bytes(
            peer.group(),
            openssl::ec::PointConversionForm::COMPRESSED,
            &mut ctx,
        )
        .unwrap();
    let uncompressed = peer
        .public_key()
        .to_bytes(
            peer.group(),
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(
        provider
            .derive(&ec, &mech("ECDH", &[("peer", bytes(&compressed))]))
            .unwrap()
            .raw,
        provider
            .derive(&ec, &mech("ECDH", &[("peer", bytes(&uncompressed))]))
            .unwrap()
            .raw
    );
    // an X25519 SPKI against an EC key, and an EC SPKI against an X25519 key
    let x = generate(
        &provider,
        KeyAlgorithm::EcMontgomery,
        None,
        Some(Curve::X25519),
        "x",
        None,
    )
    .unwrap();
    let x_spki = provider
        .export_key(&public_half(&provider, "x"))
        .unwrap()
        .data;
    let e_spki = provider
        .export_key(&public_half(&provider, "e"))
        .unwrap()
        .data;
    let err = err_class(
        provider.derive(&ec, &mech("ECDH", &[("peer", bytes(&x_spki))])),
        "ParamError",
    );
    assert_eq!(err.message, "peer public key is not an EC key");
    let err = err_class(
        provider.derive(&x, &mech("ECDH", &[("peer", bytes(&e_spki))])),
        "ParamError",
    );
    assert_eq!(
        err.message,
        "peer public key does not match the x25519 private key"
    );
    // an all-zero (low-order) X25519 peer fails the exchange itself
    let err = err_class(
        provider.derive(&x, &mech("ECDH", &[("peer", bytes(&[0u8; 32]))])),
        "CryptoError",
    );
    assert!(
        err.message.starts_with("ECDH key exchange failed: "),
        "{}",
        err.message
    );
    let err = err_class(provider.derive(&ec, &mech("ECDH", &[])), "ParamError");
    assert_eq!(err.message, "missing required parameter 'peer'");
}

// ---------------------------------------------------------------------------------------
// round-trips for every advertised mechanism
// ---------------------------------------------------------------------------------------

#[test]
fn every_advertised_mechanism_round_trips() {
    let provider = make();
    let aes = generate(&provider, KeyAlgorithm::Aes, Some(256), None, "aes", None).unwrap();
    let aes128 = generate(
        &provider,
        KeyAlgorithm::Aes,
        Some(128),
        None,
        "aes128",
        None,
    )
    .unwrap();
    let generic = generate(&provider, KeyAlgorithm::Generic, Some(512), None, "g", None).unwrap();
    let rsa = generate(&provider, KeyAlgorithm::Rsa, Some(2048), None, "rsa", None).unwrap();
    let rsa_pub = public_half(&provider, "rsa");
    let mut covered = std::collections::BTreeSet::new();
    let data = b"round trip payload, 32 bytes...!";

    let ciphers: Vec<(
        &r2_core::keys::KeyInfo,
        &r2_core::keys::KeyInfo,
        MechanismInvocation,
    )> = vec![
        (&aes, &aes, mech("AES-ECB", &[("padding", text("pkcs7"))])),
        (
            &aes128,
            &aes128,
            mech("AES-CBC", &[("iv", bytes(&[7u8; 16]))]),
        ),
        (
            &aes,
            &aes,
            mech("AES-CTR", &[("counter_block", bytes(&[9u8; 16]))]),
        ),
        (
            &aes,
            &aes,
            mech(
                "AES-GCM",
                &[("iv", bytes(&[1u8; 12])), ("aad", bytes(b"a"))],
            ),
        ),
        (
            &rsa_pub,
            &rsa,
            mech("RSA-OAEP", &[("hash", text("sha512"))]),
        ),
        (&rsa_pub, &rsa, mech("RSA-PKCS1", &[])),
    ];
    for (enc_key, dec_key, mechanism) in ciphers {
        let ciphertext = provider.encrypt(enc_key, &mechanism, data).unwrap();
        assert_eq!(
            *provider.decrypt(dec_key, &mechanism, &ciphertext).unwrap(),
            data
        );
        covered.insert(mechanism.mechanism.clone());
    }
    let raw = mech("RSA-RAW", &[]);
    let ciphertext = provider.encrypt(&rsa_pub, &raw, data).unwrap();
    assert_eq!(
        *provider.decrypt(&rsa, &raw, &ciphertext).unwrap(),
        left_pad(data, 256)
    );
    covered.insert("RSA-RAW".to_owned());

    let mut signers: Vec<(
        r2_core::keys::KeyInfo,
        r2_core::keys::KeyInfo,
        MechanismInvocation,
    )> = vec![
        (
            aes.clone(),
            aes.clone(),
            mech("AES-CMAC", &[("mac_len", int(10))]),
        ),
        (
            aes.clone(),
            aes.clone(),
            mech("AES-GMAC", &[("iv", bytes(&[2u8; 12]))]),
        ),
        (
            generic.clone(),
            generic.clone(),
            mech("HMAC", &[("hash", text("sha384"))]),
        ),
        (
            rsa.clone(),
            rsa_pub.clone(),
            mech("RSA-PKCS1", &[("hash", text("sha224"))]),
        ),
        (
            rsa.clone(),
            rsa_pub.clone(),
            mech(
                "RSA-PSS",
                &[
                    ("hash", text("sha384")),
                    ("mgf_hash", text("sha1")),
                    ("salt_len", int(0)),
                ],
            ),
        ),
    ];
    for (curve, label) in [
        (Curve::P256, "p256"),
        (Curve::P384, "p384"),
        (Curve::P521, "p521"),
        (Curve::Ed25519, "ed25519"),
        (Curve::Ed448, "ed448"),
    ] {
        let private = generate(
            &provider,
            curve.algorithm(),
            None,
            Some(curve.clone()),
            label,
            None,
        )
        .unwrap();
        let mechanism = if curve.algorithm() == KeyAlgorithm::Ec {
            mech("ECDSA", &[("hash", text("sha512"))])
        } else {
            mech("EDDSA", &[])
        };
        signers.push((private, public_half(&provider, label), mechanism));
    }
    for (sign_key, verify_key, mechanism) in &signers {
        let signature = provider.sign(sign_key, mechanism, data).unwrap();
        assert!(
            provider
                .verify(verify_key, mechanism, data, &signature)
                .unwrap()
        );
        assert!(
            !provider
                .verify(verify_key, mechanism, b"other data", &signature)
                .unwrap()
        );
        covered.insert(mechanism.mechanism.clone());
    }
    let block = sha256(b"block");
    let signature = provider.sign(&rsa, &raw, &block).unwrap();
    assert!(provider.verify(&rsa_pub, &raw, &block, &signature).unwrap());

    for (curve, label) in [
        (Curve::P384, "ka"),
        (Curve::X25519, "kx"),
        (Curve::X448, "kxx"),
    ] {
        let a = generate(
            &provider,
            curve.algorithm(),
            None,
            Some(curve.clone()),
            label,
            None,
        )
        .unwrap();
        let b_label = format!("{label}-b");
        let b = generate(
            &provider,
            curve.algorithm(),
            None,
            Some(curve.clone()),
            &b_label,
            None,
        )
        .unwrap();
        let a_pub = provider
            .export_key(&public_half(&provider, label))
            .unwrap()
            .data;
        let b_pub = provider
            .export_key(&public_half(&provider, &b_label))
            .unwrap()
            .data;
        let z_ab = provider
            .derive(&a, &mech("ECDH", &[("peer", bytes(&b_pub))]))
            .unwrap();
        let z_ba = provider
            .derive(&b, &mech("ECDH", &[("peer", bytes(&a_pub))]))
            .unwrap();
        assert_eq!(z_ab.raw, z_ba.raw);
        covered.insert("ECDH".to_owned());
    }

    let target = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "target",
        None,
    )
    .unwrap();
    let wraps: Vec<(
        &r2_core::keys::KeyInfo,
        &r2_core::keys::KeyInfo,
        MechanismInvocation,
    )> = vec![
        (&aes, &aes, mech("AES-KEY-WRAP-PAD", &[])),
        (&aes, &aes, mech("AES-CBC", &[("iv", bytes(&[3u8; 16]))])),
        (&aes, &aes, mech("AES-GCM", &[("iv", bytes(&[4u8; 12]))])),
        (&rsa_pub, &rsa, mech("RSA-AES-KEY-WRAP", &[])),
    ];
    for (i, (wrap_key, unwrap_key, mechanism)) in wraps.into_iter().enumerate() {
        let blob = provider
            .wrap_key(wrap_key, &mechanism, &target, &opts())
            .unwrap();
        let restored = provider
            .unwrap_key(
                unwrap_key,
                &mechanism,
                &blob,
                &unwrap_req(
                    KeyAlgorithm::Ec,
                    KeyClass::Private,
                    &format!("w{i}"),
                    None,
                    None,
                ),
            )
            .unwrap();
        assert_eq!(
            provider.export_key(&restored).unwrap().data,
            provider.export_key(&target).unwrap().data
        );
        covered.insert(mechanism.mechanism.clone());
    }
    // AES-KEY-WRAP / RSA-OAEP / RSA-PKCS1 wrap a 32-byte secret
    let secret = generate(
        &provider,
        KeyAlgorithm::Aes,
        Some(256),
        None,
        "secret",
        None,
    )
    .unwrap();
    for (i, (wrap_key, unwrap_key, mechanism)) in [
        (&aes, &aes, mech("AES-KEY-WRAP", &[])),
        (&rsa_pub, &rsa, mech("RSA-OAEP", &[])),
        (&rsa_pub, &rsa, mech("RSA-PKCS1", &[])),
    ]
    .into_iter()
    .enumerate()
    {
        let blob = provider
            .wrap_key(wrap_key, &mechanism, &secret, &opts())
            .unwrap();
        let restored = provider
            .unwrap_key(
                unwrap_key,
                &mechanism,
                &blob,
                &unwrap_req(
                    KeyAlgorithm::Aes,
                    KeyClass::Secret,
                    &format!("s{i}"),
                    None,
                    None,
                ),
            )
            .unwrap();
        assert_eq!(
            provider.export_key(&restored).unwrap().data,
            provider.export_key(&secret).unwrap().data
        );
        covered.insert(mechanism.mechanism.clone());
    }
    let advertised: std::collections::BTreeSet<String> = CANONICAL_MECHANISMS
        .iter()
        .map(|m| (*m).to_owned())
        .collect();
    assert_eq!(covered, advertised);
    assert_eq!(provider.mechanisms(), advertised);
}

// ---------------------------------------------------------------------------------------
// pyca's other curves (Curve::Other) and generation shapes
// ---------------------------------------------------------------------------------------

#[test]
fn other_pyca_curves_classify_sign_and_report_pyca_names() {
    let provider = make();
    let mut infos = Vec::new();
    for (nid, name, width) in [
        (Nid::SECP256K1, "secp256k1", 32usize),
        (Nid::BRAINPOOL_P512R1, "brainpoolp512r1", 64),
        (Nid::X9_62_PRIME192V1, "secp192r1", 24),
    ] {
        let key =
            PKey::from_ec_key(EcKey::generate(&EcGroup::from_curve_name(nid).unwrap()).unwrap())
                .unwrap();
        let private = import_private(&provider, &key, KeyAlgorithm::Ec, name, None, None);
        assert_eq!(private.curve, Some(Curve::Other(name.to_owned())));
        assert_eq!(private.size_bits, None);
        let public = import_public(
            &provider,
            &key,
            KeyAlgorithm::Ec,
            &format!("{name}-pub"),
            None,
        );
        let ecdsa = mech("ECDSA", &[("hash", text("sha256"))]);
        let signature = provider.sign(&private, &ecdsa, b"m").unwrap();
        assert_eq!(signature.len(), 2 * width);
        assert!(provider.verify(&public, &ecdsa, b"m", &signature).unwrap());
        infos.push((private, provider.export_key(&public).unwrap().data.to_vec()));
    }
    // pyca's curve.name in the ECDH mismatch text
    let err = err_class(
        provider.derive(&infos[0].0, &mech("ECDH", &[("peer", bytes(&infos[1].1))])),
        "ParamError",
    );
    assert_eq!(
        err.message,
        "peer curve brainpoolP512r1 does not match key curve secp256k1"
    );
}

#[test]
fn generated_keys_have_c2_shapes() {
    let provider = make();
    for (curve, algorithm) in [
        (Curve::P384, KeyAlgorithm::Ec),
        (Curve::Ed25519, KeyAlgorithm::EcEdwards),
        (Curve::X448, KeyAlgorithm::EcMontgomery),
    ] {
        let label = curve.as_str().to_owned();
        let private = generate(
            &provider,
            algorithm,
            None,
            Some(curve.clone()),
            &label,
            None,
        )
        .unwrap();
        assert_eq!(
            (private.algorithm, private.curve.clone(), private.size_bits),
            (algorithm, Some(curve.clone()), None)
        );
        let public = public_half(&provider, &label);
        assert_eq!(public.curve, Some(curve));
        assert!(public.exportable && public.attributes.is_empty());
        // secret/private KeyInfo.attributes always carry both flags (§5.5)
        assert_eq!(
            private.attributes.get("CKA_EXTRACTABLE"),
            Some(&r2_core::template::AttrValue::Bool(true))
        );
        assert_eq!(
            private.attributes.get("CKA_SENSITIVE"),
            Some(&r2_core::template::AttrValue::Bool(false))
        );
        // exported material round-trips through import on a fresh provider
        let exported = provider.export_key(&private).unwrap();
        assert_eq!(exported.label_hint.as_deref(), Some(label.as_str()));
        let other = make();
        let again = other.import_key(&exported, "again", None, None).unwrap();
        assert_eq!(*other.export_key(&again).unwrap().data, *exported.data);
    }
    // RSA public exponent is 65537 and the twin guard covers both halves up front
    let rsa = generate(
        &provider,
        KeyAlgorithm::Rsa,
        Some(1024),
        None,
        "r1024",
        None,
    )
    .unwrap();
    assert_eq!(rsa.size_bits, Some(1024));
    let exported = PKey::private_key_from_der(&provider.export_key(&rsa).unwrap().data).unwrap();
    assert_eq!(
        exported
            .rsa()
            .unwrap()
            .e()
            .to_dec_str()
            .unwrap()
            .to_string(),
        "65537"
    );
    let before = provider.list_keys().unwrap().len();
    let err = err_class(
        generate(
            &provider,
            KeyAlgorithm::Rsa,
            Some(1024),
            None,
            "r1024",
            None,
        ),
        "DuplicateKeyError",
    );
    assert_eq!(
        err.message,
        "a private object with label 'r1024' and no id already exists on mem"
    );
    assert_eq!(provider.list_keys().unwrap().len(), before); // never a half pair
}

// ---------------------------------------------------------------------------------------
// material and identity rules (§4.3, §4.5.2, §4.7)
// ---------------------------------------------------------------------------------------

#[test]
fn none_and_other_material_is_a_param_error_with_c2_text() {
    let provider = make();
    let cases = [
        (
            KeyMaterial::new(KeyAlgorithm::Other, KeyClass::Secret, vec![0u8; 16]),
            "unsupported secret key algorithm 'other'",
        ),
        (
            KeyMaterial::new(KeyAlgorithm::None, KeyClass::Secret, vec![0u8; 16]),
            "unsupported secret key algorithm 'none'",
        ),
        (
            KeyMaterial::new(KeyAlgorithm::None, KeyClass::Private, pkcs8(&ec_p256())),
            "material declares algorithm 'none' but data parses as 'ec'",
        ),
        (
            KeyMaterial::new(KeyAlgorithm::Other, KeyClass::Public, spki(&ec_p256())),
            "material declares algorithm 'other' but data parses as 'ec'",
        ),
        (
            KeyMaterial::new(KeyAlgorithm::Other, KeyClass::Data, b"x".to_vec()),
            "data objects carry no algorithm (got 'other')",
        ),
    ];
    for (material, message) in cases {
        let err = err_class(
            provider.import_key(&material, "x", None, None),
            "ParamError",
        );
        assert_eq!(err.message, message);
        assert_eq!(err.param_name(), Some("material"));
    }
    // unwrap into OTHER goes through the same rule
    let kek = import_aes(&provider, &[1u8; 16], "kek", None, None);
    let target = import_aes(&provider, &[2u8; 16], "t", None, None);
    let blob = provider
        .wrap_key(&kek, &mech("AES-KEY-WRAP", &[]), &target, &opts())
        .unwrap();
    let err = err_class(
        provider.unwrap_key(
            &kek,
            &mech("AES-KEY-WRAP", &[]),
            &blob,
            &unwrap_req(KeyAlgorithm::Other, KeyClass::Secret, "o", None, None),
        ),
        "ParamError",
    );
    assert_eq!(err.message, "unsupported secret key algorithm 'other'");
}

#[test]
fn material_parse_errors_keep_c2s_prefixes() {
    let provider = make();
    let err = err_class(
        provider.import_key(
            &KeyMaterial::new(
                KeyAlgorithm::Ec,
                KeyClass::Certificate,
                b"\x30\x03\x02\x01\x00".to_vec(),
            ),
            "c",
            None,
            None,
        ),
        "KeyParseError",
    );
    assert!(
        err.message
            .starts_with("cannot parse certificate material (X.509 DER): "),
        "{}",
        err.message
    );
    let err = err_class(
        provider.import_key(
            &KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Public, b"zz".to_vec()),
            "p",
            None,
            None,
        ),
        "KeyParseError",
    );
    assert!(
        err.message.starts_with(
            "cannot parse public key material (SPKI DER): Could not deserialize key data."
        ),
        "{}",
        err.message
    );
    let err = err_class(
        provider.import_key(
            &KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Private, spki(&ec_p256())),
            "q",
            None,
            None,
        ),
        "KeyParseError",
    );
    assert!(
        err.message
            .starts_with("cannot parse private key material: "),
        "{}",
        err.message
    );
    // a declared/parsed mismatch on a certificate
    let cert = self_signed(&rsa_2048(), "c2-mem-rsa", false);
    let err = err_class(
        provider.import_key(
            &KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Certificate, cert),
            "c",
            None,
            None,
        ),
        "KeyParseError",
    );
    assert_eq!(
        err.message,
        "material declares algorithm 'ec' but data parses as 'rsa'"
    );
}

#[test]
fn certificates_resolve_to_their_public_key_and_export_verbatim() {
    let provider = make();
    let key = rsa_2048();
    let cert_der = self_signed(&key, "r2-cert", true);
    let private = import_private(&provider, &key, KeyAlgorithm::Rsa, "k", None, Some(b"\x01"));
    let cert = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert_der.clone()),
            "k",
            None,
            Some(b"\x01"),
        )
        .unwrap();
    assert_eq!(cert.size_bits, Some(2048));
    for name in [
        "subject",
        "issuer",
        "serial_number",
        "not_valid_before",
        "not_valid_after",
    ] {
        assert!(cert.attributes.contains_key(name), "{name}");
    }
    assert_eq!(*provider.export_key(&cert).unwrap().data, cert_der);
    // a second identical certificate is allowed (chain rule); the family collapses to the
    // private half, and RSA-RAW decrypt with a certificate is refused like any decrypt
    provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert_der),
            "k",
            None,
            Some(b"\x01"),
        )
        .unwrap();
    let err = err_class(
        provider.decrypt(&cert, &mech("RSA-RAW", &[]), b"x"),
        "UnsupportedOperationError",
    );
    assert_eq!(
        err.message,
        "certificates cannot be used for decrypt (§4.3)"
    );
    let raw_sig = provider
        .sign(&private, &mech("RSA-RAW", &[]), &sha256(b"x"))
        .unwrap();
    assert!(
        provider
            .verify(&cert, &mech("RSA-RAW", &[]), &sha256(b"x"), &raw_sig)
            .unwrap()
    );
    let err = err_class(
        provider.find_key(&KeySelector::label("k")),
        "AmbiguousKeyError",
    );
    assert_eq!(err.candidates().map(<[_]>::len), Some(3));
}

#[test]
fn empty_key_ids_are_no_key_id_and_unknown_records_are_not_found() {
    let provider = make();
    let info = import_aes(&provider, &[0u8; 16], "k", None, Some(b""));
    assert_eq!(info.key_ref.key_id, None); // §4.3 invariant: never Some(empty)
    let data = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, b"v".to_vec()),
            "d",
            None,
            Some(b""),
        )
        .unwrap();
    assert_eq!(data.key_ref.key_id, None);
    let mut ghost = info.clone();
    ghost.key_ref.label = "nope".to_owned();
    let err = err_class(provider.export_key(&ghost), "KeyNotFoundError");
    assert_eq!(err.message, "no key 'mem:nope' on provider mem");
    err_class(provider.delete_key(&ghost), "KeyNotFoundError");
    // a KeyInfo of another class is not this record
    let mut wrong_class = info.clone();
    wrong_class.key_class = KeyClass::Private;
    err_class(provider.delete_key(&wrong_class), "KeyNotFoundError");
    assert_eq!(provider.list_keys().unwrap().len(), 2);
    assert!(provider.status().token.is_none());
    assert_eq!(provider.type_name(), "memory");
    assert!(provider.list_tokens().unwrap().is_empty());
    let err = err_class(
        provider.read_full_template(&info),
        "UnsupportedOperationError",
    );
    assert_eq!(err.message, "mem does not support template dumps");
    let as_any: &dyn std::any::Any = provider.as_any();
    assert!(as_any.downcast_ref::<MemoryProvider>().is_some());
    let _unused: Option<ParamValue> = None;
}

#[test]
fn rename_guard_and_certificate_exemption() {
    let provider = make();
    let a = import_aes(&provider, &[0u8; 16], "a", None, Some(b"\x01"));
    let b = import_aes(&provider, &[0u8; 16], "b", None, Some(b"\x01"));
    let rename = |label: &str| {
        r2_core::template::KeyTemplate::new(vec![r2_core::template::TemplateAttr::new(
            "CKA_LABEL",
            r2_core::template::AttrKind::Str,
            r2_core::template::AttrValue::Str(label.to_owned()),
        )])
    };
    let err = err_class(provider.update_key(&b, &rename("a")), "DuplicateKeyError");
    assert_eq!(
        err.message,
        "a secret object with label 'a' and id 0x01 already exists on mem"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("pick a different id or label, or delete the existing object first")
    );
    // renaming to its own identity is a no-op success
    let same = provider.update_key(&a, &rename("a")).unwrap();
    assert_eq!(same.key.key_ref, a.key_ref);
    // certificates are exempt from the guard
    let cert_der = self_signed(&rsa_2048(), "c", false);
    let material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert_der);
    provider.import_key(&material, "c1", None, None).unwrap();
    let c2_info = provider.import_key(&material, "c2", None, None).unwrap();
    let renamed = provider.update_key(&c2_info, &rename("c1")).unwrap();
    assert_eq!(renamed.key.key_ref.label, "c1");
}

#[test]
fn pss_salt_edge_cases_follow_pyca() {
    let provider = make();
    let (private, public) = import_rsa_pair(&provider);
    let pss = |salt: i64| {
        mech(
            "RSA-PSS",
            &[("hash", text("sha256")), ("salt_len", int(salt))],
        )
    };
    // an oversized salt: signing fails (Crypto, c2 prefix), verification is just false
    let err = err_class(provider.sign(&private, &pss(1000), b"m"), "CryptoError");
    assert!(
        err.message.starts_with("RSA-PSS signing failed: "),
        "{}",
        err.message
    );
    assert!(
        !provider
            .verify(&public, &pss(1000), b"m", &[0x79; 256])
            .unwrap()
    );
    assert!(
        !provider
            .verify(&public, &pss(32), b"m", &[0x79; 10])
            .unwrap()
    );
    // the -1 sentinel resolving below zero on a tiny key is pyca's ValueError text
    let key = {
        // 512-bit modulus: (512 + 7) / 8 - 64 - 2 < 0 with sha512
        let rsa = openssl::rsa::Rsa::generate(512).unwrap();
        PKey::from_rsa(rsa).unwrap()
    };
    let tiny = import_private(&provider, &key, KeyAlgorithm::Rsa, "tiny", None, None);
    let tiny_pub = import_public(&provider, &key, KeyAlgorithm::Rsa, "tiny-pub", None);
    let max512 = mech(
        "RSA-PSS",
        &[("hash", text("sha512")), ("salt_len", int(-1))],
    );
    let err = err_class(provider.sign(&tiny, &max512, b"m"), "CryptoError");
    assert_eq!(
        err.message,
        "RSA-PSS signing failed: salt_length must be zero or greater."
    );
    let err = err_class(
        provider.verify(&tiny_pub, &max512, b"m", &[0u8; 64]),
        "CryptoError",
    );
    assert_eq!(
        err.message,
        "RSA-PSS verification failed: salt_length must be zero or greater."
    );
    // ECDSA: a wrong-length signature is false before the hash parameter is read (c2 order)
    let ec = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "e",
        None,
    )
    .unwrap();
    let ec_pub = public_half(&provider, "e");
    let _ = ec;
    assert!(
        !provider
            .verify(
                &ec_pub,
                &mech("ECDSA", &[("hash", text("md5"))]),
                b"m",
                b"short"
            )
            .unwrap()
    );
    let err = err_class(
        provider.verify(
            &ec_pub,
            &mech("ECDSA", &[("hash", text("md5"))]),
            b"m",
            &[1u8; 64],
        ),
        "ParamError",
    );
    assert_eq!(
        err.message,
        "parameter 'hash' must be one of sha1, sha224, sha256, sha384, sha512; got 'md5'"
    );
}

#[test]
fn unsupported_key_types_are_c2s_classifier_texts() {
    let provider = make();
    let dsa = PKey::from_dsa(openssl::dsa::Dsa::generate(1024).unwrap()).unwrap();
    let err = err_class(
        provider.import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, pkcs8(&dsa)),
            "dsa",
            None,
            None,
        ),
        "KeyParseError",
    );
    assert_eq!(err.message, "unsupported key algorithm: DSAPrivateKey");
    assert_eq!(
        err.hint.as_deref(),
        Some("supported: AES, RSA, EC, Ed25519/Ed448, X25519/X448")
    );
    let err = err_class(
        provider.import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Public, spki(&dsa)),
            "dsa-pub",
            None,
            None,
        ),
        "KeyParseError",
    );
    assert_eq!(err.message, "unsupported key algorithm: DSAPublicKey");
}

/// R13 (the R4/R6/R10 hand-off): a PKCS#8 with trailing zero bytes — what a token's
/// KW-PAD unwrap leaves when `copy softhsm:<private key> mem` crosses SoftHSM 2.6.1 —
/// fails to import with c2 memory's exact text (pyca's last attempt names the INTEGER).
#[test]
fn private_key_with_trailing_bytes_reports_c2s_unexpected_tag_text() {
    let provider = MemoryProvider::new("mem");
    let key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let mut data = key.private_key_to_pkcs8().unwrap();
    data.extend_from_slice(&[0; 8]);
    let err = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, data),
            "x",
            None,
            None,
        )
        .unwrap_err();
    assert_eq!(err.kind, r2_core::error::ErrorKind::KeyParse);
    assert_eq!(
        err.message,
        "cannot parse private key material: Could not deserialize key data. The data may be in an incorrect format, it may be encrypted with an unsupported algorithm, or it may be an unsupported key type (e.g. EC curves with explicit parameters). Details: ASN.1 parsing error: unexpected tag (got Tag { value: 2, constructed: false, class: Universal })"
    );
    assert_eq!(err.hint, None);
}

#[test]
fn rsa_ciphertext_not_the_modulus_size_fails_like_pycas_length_check() {
    // pyca raises ValueError("Ciphertext length must be equal to key size.") before
    // OpenSSL runs (so before PKCS#1 v1.5 implicit rejection), which c2 reports as its
    // detail-free failure — on decrypt and on unwrap, for both RSA paddings (§5.8).
    let provider = make();
    let (kek, key) = rsa_kek(&provider);
    assert_eq!(key.size(), 256); // RSA-2048
    for len in [1usize, 2, 255, 257] {
        let blob = vec![0x01u8; len];
        for (name, decrypt_text, unwrap_text) in [
            (
                "RSA-PKCS1",
                "RSA-PKCS1 decryption failed",
                "RSA-PKCS1 unwrap failed",
            ),
            (
                "RSA-OAEP",
                "RSA-OAEP decryption failed",
                "RSA-OAEP unwrap failed",
            ),
        ] {
            let err = err_class(
                provider.decrypt(&kek, &mech(name, &[]), &blob),
                "CryptoError",
            );
            assert_eq!(err.message, decrypt_text, "{name} decrypt of {len} bytes");
            let err = err_class(
                provider.unwrap_key(
                    &kek,
                    &mech(name, &[]),
                    &blob,
                    &unwrap_req(KeyAlgorithm::Aes, KeyClass::Secret, "short", None, None),
                ),
                "CryptoError",
            );
            assert_eq!(err.message, unwrap_text, "{name} unwrap of {len} bytes");
        }
    }
}
