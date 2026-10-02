// MemoryProvider tests (R4): port of c2 tests/unit/test_memory_provider.py — per-op
// round-trips and the §8 KATs (the contract suite is tests/contract.rs).
//
// KAT sources (copied verbatim from c2): NIST SP 800-38A (ECB/CBC/CTR), McGrew-Viega GCM
// test case 16 (AES-256-GCM), RFC 4493 (AES-CMAC), RFC 3394 (AES-KW), RFC 6979 A.2.5
// (deterministic ECDSA P-256 → verify-KAT), RFC 8032 (Ed25519), RFC 7748 §6.1 (X25519).
// RSA-PSS gets a verify-KAT whose known answer is built in-test from an independent RFC
// 8017 EMSA-PSS implementation (hash + textbook modexp — not the provider), plus
// round-trips. GMAC is checked against an independently computed GCM tag over the message
// as AAD (OpenSSL's one-shot AEAD API — a different code path than the provider's).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod support;

use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use openssl::rsa::Padding;
use openssl::sign::{Signer, Verifier};
use r2_core::der::{ecdsa_der_to_rs, ecdsa_rs_to_der};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_provider::{AttrEditOutcome, KeySelector, Provider, WrapOptions};
use support::*;

fn wrap_opts() -> WrapOptions {
    WrapOptions::default()
}

// ---------------------------------------------------------------------------------------
// capability surface & lifecycle
// ---------------------------------------------------------------------------------------

#[test]
fn test_advertises_every_canonical_mechanism() {
    let expected: std::collections::BTreeSet<String> = [
        "AES-ECB",
        "AES-CBC",
        "AES-CTR",
        "AES-GCM",
        "AES-CMAC",
        "AES-GMAC",
        "RSA-OAEP",
        "RSA-PKCS1",
        "RSA-PSS",
        "RSA-RAW",
        "ECDSA",
        "EDDSA",
        "ECDH",
        "AES-KEY-WRAP",
        "AES-KEY-WRAP-PAD",
        "RSA-AES-KEY-WRAP",
        "HMAC",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    assert_eq!(make().mechanisms(), expected);
}

#[test]
fn test_initialize_idempotent_and_shutdown_clears_keys() {
    let provider = make();
    provider.initialize().unwrap();
    provider.initialize().unwrap();
    import_aes(&provider, &[0u8; 16], "gone", None, None);
    provider.shutdown().unwrap();
    err_class(find(&provider, "gone", None), "KeyNotFoundError");
    provider.shutdown().unwrap(); // safe to call again
}

#[test]
fn test_unknown_mechanism_raises() {
    let provider = make();
    let info = import_aes(&provider, &[0u8; 16], "aes", None, None);
    let err = err_class(
        provider.encrypt(&info, &mech("NO-SUCH-MECHANISM", &[]), b"x"),
        "UnsupportedOperationError",
    );
    assert_eq!(
        err.message,
        "mem does not support mechanism NO-SUCH-MECHANISM"
    );
}

// ---------------------------------------------------------------------------------------
// AES KATs — NIST SP 800-38A / McGrew-Viega GCM / RFC 4493 CMAC
// ---------------------------------------------------------------------------------------

const K_SP800: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const PT4: &str = "6bc1bee22e409f96e93d7e117393172a\
                   ae2d8a571e03ac9c9eb76fac45af8e51\
                   30c81c46a35ce411e5fbc1191a0a52ef\
                   f69f2445df4f9b17ad2b417be66c3710";
const ECB_CT: &str = "3ad77bb40d7a3660a89ecaf32466ef97\
                      f5d3d58503b9699de785895a96fdbaaf\
                      43b1cd7f598ece23881b00e3ed030688\
                      7b0c785e27e8ad3f8223207104725dd4";
const CBC_IV: &str = "000102030405060708090a0b0c0d0e0f";
const CBC_CT: &str = "7649abac8119b246cee98e9b12e9197d\
                      5086cb9b507219ee95db113a917678b2\
                      73bed6b8e3c1743b7116e69e22229516\
                      3ff1caa1681fac09120eca307586e1a7";
const CTR_BLOCK: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const CTR_CT: &str = "874d6191b620e3261bef6864990db6ce\
                      9806f66b7970fdff8617187bb9fffdff\
                      5ae4df3edbd5d35e5b4f09020db03eab\
                      1e031dda2fbe03d1792170a0f3009cee";

const GCM_KEY: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
const GCM_IV: &str = "cafebabefacedbaddecaf888";
const GCM_PT: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                      1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
const GCM_AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
const GCM_CT: &str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                      8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
const GCM_TAG: &str = "76fc6ece0f4e1768cddf8853bb2d551b";

const CMAC_EMPTY: &str = "bb1d6929e95937287fa37d129b756746";
const CMAC_ONE_BLOCK: &str = "070a16b46b4d4144f79bdd9dd04a287c";

#[test]
fn test_kat_aes_ecb_sp800_38a() {
    let provider = make();
    let info = import_aes(&provider, &hex(K_SP800), "aes", None, None);
    let ecb = mech("AES-ECB", &[("padding", text("none"))]);
    assert_eq!(
        provider.encrypt(&info, &ecb, &hex(PT4)).unwrap(),
        hex(ECB_CT)
    );
    assert_eq!(
        *provider.decrypt(&info, &ecb, &hex(ECB_CT)).unwrap(),
        hex(PT4)
    );
}

#[test]
fn test_kat_aes_cbc_sp800_38a() {
    let provider = make();
    let info = import_aes(&provider, &hex(K_SP800), "aes", None, None);
    let cbc = mech(
        "AES-CBC",
        &[("iv", bytes(&hex(CBC_IV))), ("padding", text("none"))],
    );
    assert_eq!(
        provider.encrypt(&info, &cbc, &hex(PT4)).unwrap(),
        hex(CBC_CT)
    );
    assert_eq!(
        *provider.decrypt(&info, &cbc, &hex(CBC_CT)).unwrap(),
        hex(PT4)
    );
}

#[test]
fn test_aes_cbc_pkcs7_prefix_matches_kat_and_round_trips() {
    // Software PKCS7 must be byte-identical up to the padding block (§5.8).
    let provider = make();
    let info = import_aes(&provider, &hex(K_SP800), "aes", None, None);
    let padded = mech(
        "AES-CBC",
        &[("iv", bytes(&hex(CBC_IV))), ("padding", text("pkcs7"))],
    );
    let pt = hex(PT4);
    let ciphertext = provider.encrypt(&info, &padded, &pt[..16]).unwrap();
    assert_eq!(ciphertext[..16], hex(CBC_CT)[..16]); // first block unaffected by padding
    assert_eq!(ciphertext.len(), 32); // whole extra padding block appended
    assert_eq!(
        *provider.decrypt(&info, &padded, &ciphertext).unwrap(),
        pt[..16]
    );
}

#[test]
fn test_kat_aes_ctr_sp800_38a() {
    let provider = make();
    let info = import_aes(&provider, &hex(K_SP800), "aes", None, None);
    let ctr = mech(
        "AES-CTR",
        &[
            ("counter_block", bytes(&hex(CTR_BLOCK))),
            ("counter_bits", int(128)),
        ],
    );
    assert_eq!(
        provider.encrypt(&info, &ctr, &hex(PT4)).unwrap(),
        hex(CTR_CT)
    );
    assert_eq!(
        *provider.decrypt(&info, &ctr, &hex(CTR_CT)).unwrap(),
        hex(PT4)
    );
}

fn gcm_tc16() -> r2_provider::MechanismInvocation {
    mech(
        "AES-GCM",
        &[
            ("iv", bytes(&hex(GCM_IV))),
            ("aad", bytes(&hex(GCM_AAD))),
            ("tag_bits", text("128")),
        ],
    )
}

#[test]
fn test_kat_aes_gcm_mcgrew_viega_tc16() {
    let provider = make();
    let info = import_aes(&provider, &hex(GCM_KEY), "aes", None, None);
    let mut ct_tag = hex(GCM_CT);
    ct_tag.extend(hex(GCM_TAG)); // ct‖tag (§5.8)
    assert_eq!(
        provider.encrypt(&info, &gcm_tc16(), &hex(GCM_PT)).unwrap(),
        ct_tag
    );
    assert_eq!(
        *provider.decrypt(&info, &gcm_tc16(), &ct_tag).unwrap(),
        hex(GCM_PT)
    );
}

#[test]
fn test_aes_gcm_tamper_and_short_input() {
    let provider = make();
    let info = import_aes(&provider, &hex(GCM_KEY), "aes", None, None);
    let mut tampered = hex(GCM_CT);
    let mut tag = hex(GCM_TAG);
    *tag.last_mut().unwrap() ^= 0x01;
    tampered.extend(tag);
    let err = err_class(
        provider.decrypt(&info, &gcm_tc16(), &tampered),
        "CryptoError",
    );
    assert_eq!(err.message, "AES-GCM authentication failed (tag mismatch)");
    let err = err_class(
        provider.decrypt(&info, &gcm_tc16(), &hex(GCM_TAG)[..8]), // shorter than the tag
        "CryptoError",
    );
    assert_eq!(
        err.message,
        "AES-GCM input is shorter than the 16-byte tag (ct‖tag expected)"
    );
}

#[test]
fn test_aes_gcm_truncated_tag_round_trip() {
    let provider = make();
    let info = import_aes(&provider, &hex(GCM_KEY), "aes", None, None);
    let gcm = mech(
        "AES-GCM",
        &[
            ("iv", bytes(&hex(GCM_IV))),
            ("aad", bytes(b"")),
            ("tag_bits", text("96")),
        ],
    );
    let ciphertext = provider
        .encrypt(&info, &gcm, b"truncated tag payload")
        .unwrap();
    assert_eq!(ciphertext.len(), b"truncated tag payload".len() + 12);
    assert_eq!(
        *provider.decrypt(&info, &gcm, &ciphertext).unwrap(),
        b"truncated tag payload"
    );
    // tag_bits arriving as int (defensive ENUM handling) behaves identically
    let as_int = mech(
        "AES-GCM",
        &[
            ("iv", bytes(&hex(GCM_IV))),
            ("aad", bytes(b"")),
            ("tag_bits", int(96)),
        ],
    );
    assert_eq!(
        provider.encrypt(&info, &as_int, b"x").unwrap(),
        provider.encrypt(&info, &gcm, b"x").unwrap()
    );
}

#[test]
fn test_kat_aes_cmac_rfc4493() {
    let provider = make();
    let info = import_aes(&provider, &hex(K_SP800), "aes", None, None);
    let cmac = mech("AES-CMAC", &[("mac_len", int(16))]);
    let block = &hex(PT4)[..16];
    assert_eq!(provider.sign(&info, &cmac, b"").unwrap(), hex(CMAC_EMPTY));
    assert_eq!(
        provider.sign(&info, &cmac, block).unwrap(),
        hex(CMAC_ONE_BLOCK)
    );
    assert!(
        provider
            .verify(&info, &cmac, block, &hex(CMAC_ONE_BLOCK))
            .unwrap()
    );
    assert!(
        !provider
            .verify(&info, &cmac, block, &hex(CMAC_EMPTY))
            .unwrap()
    );
}

#[test]
fn test_aes_cmac_truncation() {
    let provider = make();
    let info = import_aes(&provider, &hex(K_SP800), "aes", None, None);
    let short = mech("AES-CMAC", &[("mac_len", int(8))]);
    let block = &hex(PT4)[..16];
    assert_eq!(
        provider.sign(&info, &short, block).unwrap(),
        hex(CMAC_ONE_BLOCK)[..8]
    );
    assert!(
        provider
            .verify(&info, &short, block, &hex(CMAC_ONE_BLOCK)[..8])
            .unwrap()
    );
    for bad in [0, 17] {
        let err = err_class(
            provider.sign(&info, &mech("AES-CMAC", &[("mac_len", int(bad))]), b"x"),
            "ParamError",
        );
        assert_eq!(err.message, "mac_len must be between 1 and 16 bytes");
        assert_eq!(err.param_name(), Some("mac_len"));
    }
}

// ---------------------------------------------------------------------------------------
// GMAC = GCM tag over AAD (§5.9 construction)
// ---------------------------------------------------------------------------------------

/// Independent computation: OpenSSL's one-shot AEAD API, empty plaintext, message as AAD.
fn aead_tag(key: &[u8], iv: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut tag = [0u8; 16];
    let ct = openssl::symm::encrypt_aead(
        openssl::symm::Cipher::aes_256_gcm(),
        key,
        Some(iv),
        aad,
        b"",
        &mut tag,
    )
    .unwrap();
    assert!(ct.is_empty());
    tag.to_vec()
}

#[test]
fn test_gmac_equals_independent_gcm_tag_over_aad() {
    let provider = make();
    let key: Vec<u8> = (0u8..32).collect();
    let info = import_aes(&provider, &key, "aes", None, None);
    let iv: Vec<u8> = (0u8..12).collect();
    let message = b"authenticate me via GMAC";
    let gmac = mech("AES-GMAC", &[("iv", bytes(&iv)), ("mac_len", int(16))]);
    let tag = provider.sign(&info, &gmac, message).unwrap();
    assert_eq!(tag, aead_tag(&key, &iv, message));
    // ... and the provider's own GCM path over an empty plaintext agrees.
    let gcm_empty = provider
        .encrypt(
            &info,
            &mech(
                "AES-GCM",
                &[
                    ("iv", bytes(&iv)),
                    ("aad", bytes(message)),
                    ("tag_bits", text("128")),
                ],
            ),
            b"",
        )
        .unwrap();
    assert_eq!(tag, gcm_empty);
    assert!(provider.verify(&info, &gmac, message, &tag).unwrap());
    assert!(!provider.verify(&info, &gmac, b"other", &tag).unwrap());
}

#[test]
fn test_gmac_truncation() {
    let provider = make();
    let key: Vec<u8> = (0u8..32).collect();
    let info = import_aes(&provider, &key, "aes", None, None);
    let iv = [0xabu8; 12];
    let full = aead_tag(&key, &iv, b"msg");
    let gmac = mech("AES-GMAC", &[("iv", bytes(&iv)), ("mac_len", int(12))]);
    assert_eq!(provider.sign(&info, &gmac, b"msg").unwrap(), full[..12]);
}

// ---------------------------------------------------------------------------------------
// RSA: OAEP / PKCS1 / PSS / RAW
// ---------------------------------------------------------------------------------------

fn oaep_sha256() -> r2_provider::MechanismInvocation {
    mech(
        "RSA-OAEP",
        &[
            ("hash", text("sha256")),
            ("mgf_hash", text("sha256")),
            ("label", bytes(b"")),
        ],
    )
}

#[test]
fn test_rsa_oaep_round_trip_and_pyca_cross_check() {
    let provider = make();
    let (private, public) = import_rsa_pair(&provider);
    let message = b"oaep payload";
    let ciphertext = provider.encrypt(&public, &oaep_sha256(), message).unwrap();
    assert_eq!(
        *provider
            .decrypt(&private, &oaep_sha256(), &ciphertext)
            .unwrap(),
        message
    );
    // cross-check: OpenSSL (outside the provider) decrypts what the provider encrypted
    let key = rsa_2048();
    let mut dec = openssl::encrypt::Decrypter::new(&key).unwrap();
    dec.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
    dec.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
    dec.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
    let mut out = vec![0u8; dec.decrypt_len(&ciphertext).unwrap()];
    let n = dec.decrypt(&ciphertext, &mut out).unwrap();
    assert_eq!(&out[..n], message);
    // ... and the provider decrypts what OpenSSL encrypted
    let public_key = public_of(&key);
    let mut enc = openssl::encrypt::Encrypter::new(&public_key).unwrap();
    enc.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
    enc.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
    enc.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
    let mut from_ossl = vec![0u8; enc.encrypt_len(message).unwrap()];
    let n = enc.encrypt(message, &mut from_ossl).unwrap();
    assert_eq!(
        *provider
            .decrypt(&private, &oaep_sha256(), &from_ossl[..n])
            .unwrap(),
        message
    );
}

#[test]
fn test_rsa_oaep_mgf_hash_defaults_to_hash() {
    let provider = make();
    let (private, public) = import_rsa_pair(&provider);
    let ciphertext = provider
        .encrypt(
            &public,
            &mech("RSA-OAEP", &[("hash", text("sha384"))]),
            b"defaulted mgf",
        )
        .unwrap();
    let explicit = mech(
        "RSA-OAEP",
        &[("hash", text("sha384")), ("mgf_hash", text("sha384"))],
    );
    assert_eq!(
        *provider.decrypt(&private, &explicit, &ciphertext).unwrap(),
        b"defaulted mgf"
    );
}

#[test]
fn test_rsa_oaep_wrong_key_and_oversize() {
    let provider = make();
    let (private, public) = import_rsa_pair(&provider);
    let oaep = mech("RSA-OAEP", &[("hash", text("sha256"))]);
    let err = err_class(
        provider.encrypt(&public, &oaep, &[0u8; 191]), // > k - 2*hLen - 2 = 190
        "CryptoError",
    );
    assert!(
        err.message.starts_with("RSA-OAEP encryption failed: "),
        "{}",
        err.message
    );
    let ciphertext = provider.encrypt(&public, &oaep, b"x").unwrap();
    let err = err_class(
        provider.decrypt(
            &private,
            &mech("RSA-OAEP", &[("hash", text("sha1"))]),
            &ciphertext,
        ),
        "CryptoError",
    );
    assert_eq!(err.message, "RSA-OAEP decryption failed"); // detail-free
}

#[test]
fn test_rsa_pkcs1_encrypt_round_trip() {
    let provider = make();
    let (private, public) = import_rsa_pair(&provider);
    let pkcs1 = mech("RSA-PKCS1", &[]);
    let ciphertext = provider.encrypt(&public, &pkcs1, b"pkcs1 payload").unwrap();
    assert_ne!(ciphertext, b"pkcs1 payload");
    assert_eq!(
        *provider.decrypt(&private, &pkcs1, &ciphertext).unwrap(),
        b"pkcs1 payload"
    );
}

#[test]
fn test_rsa_pkcs1_sign_is_deterministic_and_matches_pyca() {
    let provider = make();
    let (private, public) = import_rsa_pair(&provider);
    let pkcs1 = mech("RSA-PKCS1", &[("hash", text("sha256"))]);
    let message = b"sign me with pkcs1 v1.5";
    let signature = provider.sign(&private, &pkcs1, message).unwrap();
    // PKCS#1 v1.5 signatures are deterministic — equal to an independent signer's
    let key = rsa_2048();
    let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
    signer.update(message).unwrap();
    assert_eq!(signature, signer.sign_to_vec().unwrap());
    assert!(
        provider
            .verify(&public, &pkcs1, message, &signature)
            .unwrap()
    );
    assert!(
        !provider
            .verify(&public, &pkcs1, b"sign me with pkcs1 v1.5!", &signature)
            .unwrap()
    );
    assert!(
        !provider
            .verify(
                &public,
                &mech("RSA-PKCS1", &[("hash", text("sha512"))]),
                message,
                &signature
            )
            .unwrap()
    );
}

/// A fixed 512-bit RSA key from hardcoded primes (c2 `_legacy_rsa_512`): pyca refuses to
/// *generate* keys this small, but §4.3 canonical PKCS#8 imports of legacy material load.
fn legacy_rsa_512() -> PKey<Private> {
    let p =
        BigNum::from_hex_str("C3500DA1F9B380220EBFAD24167C9E644729ACA59452AF58D4BE9BFCFCBCBC7F")
            .unwrap();
    let q =
        BigNum::from_hex_str("C4F7CF8AC0C0FEB87AE0146A6C785DC228235032F499F80FD122F163FDDC215B")
            .unwrap();
    let e = BigNum::from_u32(65537).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let one = BigNum::from_u32(1).unwrap();
    let mut p1 = BigNum::new().unwrap();
    p1.checked_sub(&p, &one).unwrap();
    let mut q1 = BigNum::new().unwrap();
    q1.checked_sub(&q, &one).unwrap();
    let mut phi = BigNum::new().unwrap();
    phi.checked_mul(&p1, &q1, &mut ctx).unwrap();
    let mut d = BigNum::new().unwrap();
    d.mod_inverse(&e, &phi, &mut ctx).unwrap();
    let mut n = BigNum::new().unwrap();
    n.checked_mul(&p, &q, &mut ctx).unwrap();
    let mut dmp1 = BigNum::new().unwrap();
    dmp1.nnmod(&d, &p1, &mut ctx).unwrap();
    let mut dmq1 = BigNum::new().unwrap();
    dmq1.nnmod(&d, &q1, &mut ctx).unwrap();
    let mut iqmp = BigNum::new().unwrap();
    iqmp.mod_inverse(&q, &p, &mut ctx).unwrap();
    let rsa = openssl::rsa::Rsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

#[test]
fn test_rsa_pkcs1_sign_digest_too_long_raises_crypto_error() {
    // Regression: a backend failure (digest > key capacity) must surface as CryptoError —
    // a legacy 512-bit key cannot carry a SHA-512 DigestInfo under PKCS#1 v1.5.
    let provider = make();
    let key = legacy_rsa_512();
    let info = import_private(&provider, &key, KeyAlgorithm::Rsa, "legacy", None, None);
    assert_eq!(info.size_bits, Some(512));
    let err = err_class(
        provider.sign(
            &info,
            &mech("RSA-PKCS1", &[("hash", text("sha512"))]),
            b"data",
        ),
        "CryptoError",
    );
    assert!(
        err.message.starts_with("RSA-PKCS1 signing failed: "),
        "{}",
        err.message
    );
    // ... while a digest that fits still signs and verifies
    let sha256 = mech("RSA-PKCS1", &[("hash", text("sha256"))]);
    let signature = provider.sign(&info, &sha256, b"data").unwrap();
    let public = import_public(&provider, &key, KeyAlgorithm::Rsa, "legacy-pub", None);
    assert!(
        provider
            .verify(&public, &sha256, b"data", &signature)
            .unwrap()
    );
}

// --- RSA-PSS: verify-KAT from an independent RFC 8017 implementation ---------------------

fn mgf1_sha256(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter: u32 = 0;
    while out.len() < mask_len {
        let mut block = seed.to_vec();
        block.extend(counter.to_be_bytes());
        out.extend(sha256(&block));
        counter += 1;
    }
    out.truncate(mask_len);
    out
}

/// RFC 8017 §9.1.1, hash = MGF hash = SHA-256 (no provider code).
fn emsa_pss_encode_sha256(message: &[u8], em_bits: usize, salt: &[u8]) -> Vec<u8> {
    let h_len = 32;
    let m_hash = sha256(message);
    let em_len = em_bits.div_ceil(8);
    let mut m_prime = vec![0u8; 8];
    m_prime.extend(&m_hash);
    m_prime.extend(salt);
    let h = sha256(&m_prime);
    let mut db = vec![0u8; em_len - salt.len() - h_len - 2];
    db.push(0x01);
    db.extend(salt);
    let mask = mgf1_sha256(&h, em_len - h_len - 1);
    let mut masked: Vec<u8> = db.iter().zip(&mask).map(|(a, b)| a ^ b).collect();
    let clear_bits = 8 * em_len - em_bits;
    masked[0] &= 0xffu8 >> clear_bits;
    masked.extend(h);
    masked.push(0xbc);
    masked
}

#[test]
fn test_kat_rsa_pss_verify_independent_construction() {
    let key = rsa_2048();
    let (n, _e, d) = rsa_numbers(&key);
    let n_bits = usize::try_from(n.num_bits()).unwrap();
    let message = b"pss known answer, independently constructed";
    let salt: Vec<u8> = (0u8..32).collect();
    let em = emsa_pss_encode_sha256(message, n_bits - 1, &salt);
    let signature = modexp(&em, &d, &n);

    let provider = make();
    let public = import_public(&provider, &key, KeyAlgorithm::Rsa, "pss-pub", None);
    let pss = mech(
        "RSA-PSS",
        &[
            ("hash", text("sha256")),
            ("mgf_hash", text("sha256")),
            ("salt_len", int(32)),
        ],
    );
    assert!(provider.verify(&public, &pss, message, &signature).unwrap());
    assert!(
        !provider
            .verify(
                &public,
                &pss,
                b"pss known answer, independently constructed!",
                &signature
            )
            .unwrap()
    );
    let mut bad = signature.clone();
    *bad.last_mut().unwrap() ^= 0x01;
    assert!(!provider.verify(&public, &pss, message, &bad).unwrap());
}

#[test]
fn test_rsa_pss_salt_len_sentinels() {
    let provider = make();
    let (private, public) = import_rsa_pair(&provider);
    let message = b"salted";
    let pss = |salt: Option<i64>| {
        let mut entries = vec![("hash", text("sha256"))];
        if let Some(salt) = salt {
            entries.push(("salt_len", int(salt)));
        }
        mech("RSA-PSS", &entries)
    };
    // salt_len absent → digest length (32): verification with the explicit length
    // succeeds only if exactly that salt length was used.
    let sig_default = provider.sign(&private, &pss(None), message).unwrap();
    assert!(
        provider
            .verify(&public, &pss(Some(32)), message, &sig_default)
            .unwrap()
    );
    // salt_len=-1 → keylen - hashlen - 2 = 256 - 32 - 2 = 222 (max)
    let sig_max = provider.sign(&private, &pss(Some(-1)), message).unwrap();
    assert!(
        provider
            .verify(&public, &pss(Some(222)), message, &sig_max)
            .unwrap()
    );
    assert!(
        !provider
            .verify(&public, &pss(Some(32)), message, &sig_max)
            .unwrap()
    );
    // round trip with the same sentinel on both sides
    assert!(
        provider
            .verify(&public, &pss(Some(-1)), message, &sig_max)
            .unwrap()
    );
    let err = err_class(
        provider.sign(&private, &pss(Some(-2)), message),
        "ParamError",
    );
    assert_eq!(
        err.message,
        "salt_len must be >= 0 (or the -1 'maximum' sentinel)"
    );
    assert_eq!(err.param_name(), Some("salt_len"));
}

#[test]
fn test_rsa_raw_modexp_and_round_trip() {
    let provider = make();
    let (private, public) = import_rsa_pair(&provider);
    let (n, e, _d) = rsa_numbers(&rsa_2048());
    let k = usize::try_from(n.num_bits()).unwrap().div_ceil(8);
    let raw = mech("RSA-RAW", &[]);
    let message = b"raw diagnostic payload";
    let ciphertext = provider.encrypt(&public, &raw, message).unwrap();
    // hand-rolled modexp must equal textbook RSA computed in-test
    assert_eq!(ciphertext, modexp(message, &e, &n));
    // decrypt returns the fixed-width block (input left-padded to modulus len)
    assert_eq!(
        *provider.decrypt(&private, &raw, &ciphertext).unwrap(),
        left_pad(message, k)
    );

    let block = sha256(b"padded block");
    let signature = provider.sign(&private, &raw, &block).unwrap();
    assert_eq!(signature.len(), k);
    assert!(provider.verify(&public, &raw, &block, &signature).unwrap());
    let mut longer = block.clone();
    longer.push(b'!');
    assert!(!provider.verify(&public, &raw, &longer, &signature).unwrap());
    let err = err_class(
        provider.encrypt(&public, &raw, &vec![0xffu8; k]), // not smaller than the modulus
        "CryptoError",
    );
    assert_eq!(
        err.message,
        "RSA-RAW input is not numerically smaller than the modulus"
    );
}

#[test]
fn test_rsa_raw_decrypt_with_public_key_recovers_signature_block() {
    // §5.8: RAW decrypt with the PUBLIC key = public-exponent modexp, so a raw signature
    // "decrypts" back to its padded block (signature recovery).
    let provider = make();
    let (private, public) = import_rsa_pair(&provider);
    let (n, _, _) = rsa_numbers(&rsa_2048());
    let k = usize::try_from(n.num_bits()).unwrap().div_ceil(8);
    let raw = mech("RSA-RAW", &[]);
    let block = sha256(b"padded block");
    let signature = provider.sign(&private, &raw, &block).unwrap();
    assert_eq!(
        *provider.decrypt(&public, &raw, &signature).unwrap(),
        left_pad(&block, k)
    );
}

// ---------------------------------------------------------------------------------------
// ECDSA (canonical r‖s), EdDSA, KATs
// ---------------------------------------------------------------------------------------

const P256_D: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const P256_QX: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
const P256_QY: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
const P256_SIG_SAMPLE: &str = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
                               f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

fn p256() -> EcGroup {
    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()
}

#[test]
fn test_kat_ecdsa_p256_rfc6979_verify() {
    // RFC 6979 A.2.5: P-256, SHA-256, message "sample" — r‖s verify-KAT.
    let provider = make();
    let group = p256();
    let qx = BigNum::from_hex_str(P256_QX).unwrap();
    let qy = BigNum::from_hex_str(P256_QY).unwrap();
    let public_ec = EcKey::from_public_key_affine_coordinates(&group, &qx, &qy).unwrap();
    let public_key = PKey::from_ec_key(public_ec).unwrap();
    let public = import_public(&provider, &public_key, KeyAlgorithm::Ec, "p256-pub", None);
    let ecdsa = mech("ECDSA", &[("hash", text("sha256"))]);
    assert!(
        provider
            .verify(&public, &ecdsa, b"sample", &hex(P256_SIG_SAMPLE))
            .unwrap()
    );
    assert!(
        !provider
            .verify(&public, &ecdsa, b"Sample", &hex(P256_SIG_SAMPLE))
            .unwrap()
    );
    // signing with the matching private key round-trips (randomized k)
    let d = BigNum::from_hex_str(P256_D).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let mut point = EcPoint::new(&group).unwrap();
    point.mul_generator2(&group, &d, &mut ctx).unwrap();
    let private_ec = EcKey::from_private_components(&group, &d, &point).unwrap();
    let private_key = PKey::from_ec_key(private_ec).unwrap();
    let private = import_private(
        &provider,
        &private_key,
        KeyAlgorithm::Ec,
        "p256",
        None,
        None,
    );
    let signature = provider.sign(&private, &ecdsa, b"x").unwrap();
    assert!(provider.verify(&public, &ecdsa, b"x", &signature).unwrap());
}

#[test]
fn test_ecdsa_round_trip_and_signature_width() {
    for (curve, width) in [(Curve::P256, 32), (Curve::P384, 48), (Curve::P521, 66)] {
        let provider = make();
        let label = format!("ec-{curve}");
        let private = generate(
            &provider,
            KeyAlgorithm::Ec,
            None,
            Some(curve.clone()),
            &label,
            None,
        )
        .unwrap();
        assert_eq!(private.curve, Some(curve.clone()));
        assert_eq!(private.size_bits, None);
        let ecdsa = mech("ECDSA", &[("hash", text("sha256"))]);
        let signature = provider.sign(&private, &ecdsa, b"data").unwrap();
        assert_eq!(signature.len(), 2 * width); // fixed-width r‖s (§4.5.4)
        let public = public_half(&provider, &label);
        assert!(
            provider
                .verify(&public, &ecdsa, b"data", &signature)
                .unwrap()
        );
        assert!(
            !provider
                .verify(&public, &ecdsa, b"tampered", &signature)
                .unwrap()
        );
        assert!(
            !provider
                .verify(&public, &ecdsa, b"data", &signature[..signature.len() - 2])
                .unwrap()
        ); // bad length
    }
}

#[test]
fn test_ecdsa_rs_converts_to_der_for_pyca() {
    // Provider r‖s → DER verifies under OpenSSL directly (§4.5.4 conversion).
    let provider = make();
    let private = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "conv",
        None,
    )
    .unwrap();
    let signature = provider
        .sign(
            &private,
            &mech("ECDSA", &[("hash", text("sha256"))]),
            b"payload",
        )
        .unwrap();
    let exported = provider
        .export_key(&public_half(&provider, "conv"))
        .unwrap();
    let public = PKey::public_key_from_der(&exported.data).unwrap();
    assert_eq!(public.id(), Id::EC);
    let der = ecdsa_rs_to_der(&signature).unwrap();
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public).unwrap();
    verifier.update(b"payload").unwrap();
    assert!(verifier.verify(&der).unwrap());
}

#[test]
fn test_ecdsa_der_from_pyca_converts_to_rs_for_provider() {
    // An OpenSSL DER signature → fixed-width r‖s verifies through the provider.
    let key = PKey::from_ec_key(EcKey::generate(&p256()).unwrap()).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
    signer.update(b"payload").unwrap();
    let der_sig = signer.sign_to_vec().unwrap();
    let rs = ecdsa_der_to_rs(&der_sig, 32).unwrap();
    let provider = make();
    let public = import_public(&provider, &key, KeyAlgorithm::Ec, "from-pyca", None);
    assert!(
        provider
            .verify(
                &public,
                &mech("ECDSA", &[("hash", text("sha256"))]),
                b"payload",
                &rs
            )
            .unwrap()
    );
}

const ED25519_SEED: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const ED25519_PUB: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const ED25519_MSG: &str = "72";
const ED25519_SIG: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                           085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

#[test]
fn test_kat_ed25519_rfc8032() {
    let provider = make();
    let key = PKey::private_key_from_raw_bytes(&hex(ED25519_SEED), Id::ED25519).unwrap();
    let private = import_private(&provider, &key, KeyAlgorithm::EcEdwards, "ed", None, None);
    assert_eq!(private.curve, Some(Curve::Ed25519));
    // Ed25519 is deterministic: the signature must equal the RFC 8032 vector.
    assert_eq!(
        provider
            .sign(&private, &mech("EDDSA", &[]), &hex(ED25519_MSG))
            .unwrap(),
        hex(ED25519_SIG)
    );
    let public_key = PKey::public_key_from_raw_bytes(&hex(ED25519_PUB), Id::ED25519).unwrap();
    let public = import_public(
        &provider,
        &public_key,
        KeyAlgorithm::EcEdwards,
        "ed-pub",
        None,
    );
    assert!(
        provider
            .verify(
                &public,
                &mech("EDDSA", &[]),
                &hex(ED25519_MSG),
                &hex(ED25519_SIG)
            )
            .unwrap()
    );
    assert!(
        !provider
            .verify(&public, &mech("EDDSA", &[]), b"\x73", &hex(ED25519_SIG))
            .unwrap()
    );
}

#[test]
fn test_eddsa_ed448_round_trip() {
    let provider = make();
    let private = generate(
        &provider,
        KeyAlgorithm::EcEdwards,
        None,
        Some(Curve::Ed448),
        "ed448",
        None,
    )
    .unwrap();
    let signature = provider
        .sign(&private, &mech("EDDSA", &[]), b"ed448 msg")
        .unwrap();
    assert_eq!(signature.len(), 114); // raw Ed448 signature (§4.5.4)
    let public = public_half(&provider, "ed448");
    assert!(
        provider
            .verify(&public, &mech("EDDSA", &[]), b"ed448 msg", &signature)
            .unwrap()
    );
}

// ---------------------------------------------------------------------------------------
// derive: ECDH / X25519 / X448 (§5.10)
// ---------------------------------------------------------------------------------------

const X25519_ALICE_PRIV: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const X25519_BOB_PUB: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const X25519_SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

fn ecdh(peer: &[u8]) -> r2_provider::MechanismInvocation {
    mech("ECDH", &[("peer", bytes(peer))])
}

#[test]
fn test_kat_x25519_rfc7748() {
    let provider = make();
    let alice = PKey::private_key_from_raw_bytes(&hex(X25519_ALICE_PRIV), Id::X25519).unwrap();
    let private = import_private(
        &provider,
        &alice,
        KeyAlgorithm::EcMontgomery,
        "alice",
        None,
        None,
    );
    assert_eq!(private.curve, Some(Curve::X25519));
    // peer as raw 32-byte u-coordinate
    let result = provider
        .derive(&private, &ecdh(&hex(X25519_BOB_PUB)))
        .unwrap();
    assert_eq!(
        result.raw.as_deref().map(|z| z.to_vec()),
        Some(hex(X25519_SHARED))
    );
    assert!(result.key.is_none());
    // peer as SPKI DER
    let bob = PKey::public_key_from_raw_bytes(&hex(X25519_BOB_PUB), Id::X25519).unwrap();
    let raw = provider
        .derive(&private, &ecdh(&spki(&bob)))
        .unwrap()
        .raw
        .unwrap();
    assert_eq!(*raw, hex(X25519_SHARED));
    let err = err_class(
        provider.derive(&private, &ecdh(&hex(X25519_BOB_PUB)[..31])),
        "ParamError",
    );
    assert!(
        err.message
            .starts_with("peer is not a valid SPKI public key: "),
        "{}",
        err.message
    );
    assert_eq!(err.param_name(), Some("peer"));
}

/// Deterministic search for a keypair whose RAW public key starts with 0x30.
fn montgomery_peer_with_der_tag(id: Id, seed_len: usize) -> PKey<Private> {
    for i in 0..100_000u32 {
        let digest = openssl::hash::hash(
            if seed_len == 32 {
                MessageDigest::sha256()
            } else {
                MessageDigest::sha512()
            },
            format!(
                "{}-der-tag-{i}",
                if seed_len == 32 { "x25519" } else { "x448" }
            )
            .as_bytes(),
        )
        .unwrap();
        let candidate = PKey::private_key_from_raw_bytes(&digest[..seed_len], id).unwrap();
        if candidate.raw_public_key().unwrap()[0] == 0x30 {
            return candidate;
        }
    }
    panic!("no public key starting with 0x30 found");
}

fn exchange(private: &PKey<Private>, peer_raw: &[u8], id: Id) -> Vec<u8> {
    let peer = PKey::public_key_from_raw_bytes(peer_raw, id).unwrap();
    let mut deriver = Deriver::new(private).unwrap();
    deriver.set_peer(&peer).unwrap();
    deriver.derive_to_vec().unwrap()
}

#[test]
fn test_x25519_raw_peer_starting_with_der_tag() {
    // Regression: ~1/256 valid raw peers start with 0x30 (the DER SEQUENCE tag). Raw vs
    // SPKI is told apart by LENGTH (raw = 32, SPKI = 44 bytes), never by the first byte.
    let peer = montgomery_peer_with_der_tag(Id::X25519, 32);
    let raw_pub = peer.raw_public_key().unwrap();
    assert_eq!(raw_pub[0], 0x30);
    let provider = make();
    let alice = PKey::private_key_from_raw_bytes(&hex(X25519_ALICE_PRIV), Id::X25519).unwrap();
    let info = import_private(
        &provider,
        &alice,
        KeyAlgorithm::EcMontgomery,
        "alice",
        None,
        None,
    );
    let expected = exchange(&alice, &raw_pub, Id::X25519);
    assert_eq!(
        *provider
            .derive(&info, &ecdh(&raw_pub))
            .unwrap()
            .raw
            .unwrap(),
        expected
    );
}

#[test]
fn test_x448_raw_peer_starting_with_der_tag() {
    // Same regression as x25519: length-gated (raw = 56, SPKI = 68 bytes).
    let peer = montgomery_peer_with_der_tag(Id::X448, 56);
    let raw_pub = peer.raw_public_key().unwrap();
    assert_eq!(raw_pub[0], 0x30);
    let provider = make();
    let mine = generate(
        &provider,
        KeyAlgorithm::EcMontgomery,
        None,
        Some(Curve::X448),
        "mine",
        None,
    )
    .unwrap();
    let exported = PKey::private_key_from_der(&provider.export_key(&mine).unwrap().data).unwrap();
    assert_eq!(exported.id(), Id::X448);
    let expected = exchange(&exported, &raw_pub, Id::X448);
    assert_eq!(
        *provider
            .derive(&mine, &ecdh(&raw_pub))
            .unwrap()
            .raw
            .unwrap(),
        expected
    );
}

fn x963_sha256(z: &[u8], shared: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter: u32 = 1;
    while out.len() < length {
        let mut input = z.to_vec();
        input.extend(counter.to_be_bytes());
        input.extend(shared);
        out.extend(sha256(&input));
        counter += 1;
    }
    out.truncate(length);
    out
}

#[test]
fn test_ecdh_p256_agreement_and_kdf() {
    let provider = make();
    let a = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "a",
        None,
    )
    .unwrap();
    let b = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "b",
        None,
    )
    .unwrap();
    let a_pub_spki = provider
        .export_key(&public_half(&provider, "a"))
        .unwrap()
        .data;
    let b_pub_spki = provider
        .export_key(&public_half(&provider, "b"))
        .unwrap()
        .data;

    let null_kdf = |peer: &[u8]| mech("ECDH", &[("peer", bytes(peer)), ("kdf", text("null"))]);
    let z_ab = provider
        .derive(&a, &null_kdf(&b_pub_spki))
        .unwrap()
        .raw
        .unwrap();
    assert_eq!(z_ab.len(), 32);
    // other direction, peer as the UNWRAPPED uncompressed point 0x04‖X‖Y
    let a_pub = PKey::public_key_from_der(&a_pub_spki).unwrap();
    let a_ec = a_pub.ec_key().unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let a_point = a_ec
        .public_key()
        .to_bytes(a_ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
        .unwrap();
    assert_eq!(a_point[0], 0x04);
    assert_eq!(
        *provider.derive(&b, &ecdh(&a_point)).unwrap().raw.unwrap(),
        *z_ab
    );

    // cross-check against OpenSSL's own exchange with the exported private key
    let a_priv = PKey::private_key_from_der(&provider.export_key(&a).unwrap().data).unwrap();
    let b_pub = PKey::public_key_from_der(&b_pub_spki).unwrap();
    let mut deriver = Deriver::new(&a_priv).unwrap();
    deriver.set_peer(&b_pub).unwrap();
    assert_eq!(deriver.derive_to_vec().unwrap(), *z_ab);

    // X9.63 KDF (CKD_SHAx_KDF): an independent computation must agree
    let derived = provider
        .derive(
            &a,
            &mech(
                "ECDH",
                &[
                    ("peer", bytes(&b_pub_spki)),
                    ("kdf", text("sha256")),
                    ("shared_data", bytes(b"ctx")),
                    ("out_len", int(48)),
                ],
            ),
        )
        .unwrap();
    assert_eq!(*derived.raw.unwrap(), x963_sha256(&z_ab, b"ctx", 48));
    // out_len=0 with a KDF → curve-size output
    let derived_default = provider
        .derive(
            &a,
            &mech(
                "ECDH",
                &[("peer", bytes(&b_pub_spki)), ("kdf", text("sha256"))],
            ),
        )
        .unwrap();
    assert_eq!(*derived_default.raw.unwrap(), x963_sha256(&z_ab, b"", 32));
}

/// R4 fix round 1 (§11 D12(l)): an unbounded `out_len` with a hash KDF is a `Param`
/// error before anything is allocated — never a capacity-overflow panic or an abort.
#[test]
fn ecdh_kdf_out_len_above_the_x963_limit_is_a_param_error() {
    let provider = make();
    let a = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "a",
        None,
    )
    .unwrap();
    generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "b",
        None,
    )
    .unwrap();
    let b_pub_spki = provider
        .export_key(&public_half(&provider, "b"))
        .unwrap()
        .data;
    let limit_sha256 = 32 * u64::from(u32::MAX);
    for (kdf, out_len, limit) in [
        ("sha256", i64::MAX, limit_sha256),
        (
            "sha256",
            i64::try_from(limit_sha256 + 1).unwrap(),
            limit_sha256,
        ),
        ("sha1", i64::MAX, 20 * u64::from(u32::MAX)),
    ] {
        let err = err_class(
            provider.derive(
                &a,
                &mech(
                    "ECDH",
                    &[
                        ("peer", bytes(&b_pub_spki)),
                        ("kdf", text(kdf)),
                        ("out_len", int(out_len)),
                    ],
                ),
            ),
            "ParamError",
        );
        assert_eq!(
            err.message,
            format!("out_len {out_len} exceeds the X9.63 KDF limit of {limit} bytes for {kdf}")
        );
        assert_eq!(err.param_name(), Some("out_len"));
    }
}

#[test]
fn test_ecdh_null_kdf_out_len_rules() {
    let provider = make();
    let a = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "a",
        None,
    )
    .unwrap();
    generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "b",
        None,
    )
    .unwrap();
    let b_pub_spki = provider
        .export_key(&public_half(&provider, "b"))
        .unwrap()
        .data;
    let z = provider
        .derive(&a, &ecdh(&b_pub_spki))
        .unwrap()
        .raw
        .unwrap();
    let with = |extra: (&str, r2_core::params::ParamValue)| {
        mech("ECDH", &[("peer", bytes(&b_pub_spki)), extra])
    };
    assert_eq!(
        *provider
            .derive(&a, &with(("out_len", int(16))))
            .unwrap()
            .raw
            .unwrap(),
        z[..16]
    );
    let err = err_class(
        provider.derive(&a, &with(("out_len", int(64)))),
        "ParamError",
    );
    assert_eq!(
        err.message,
        "out_len 64 exceeds the shared-secret length 32 for kdf=null"
    );
    let err = err_class(
        provider.derive(&a, &with(("shared_data", bytes(b"x")))),
        "ParamError",
    );
    assert_eq!(
        err.message,
        "shared_data requires a KDF (set kdf to a hash)"
    );
    assert_eq!(err.param_name(), Some("shared_data"));
}

#[test]
fn test_ecdh_peer_curve_mismatch_and_bad_peer() {
    let provider = make();
    let a = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "a",
        None,
    )
    .unwrap();
    generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P384),
        "wrong",
        None,
    )
    .unwrap();
    let wrong_spki = provider
        .export_key(&public_half(&provider, "wrong"))
        .unwrap()
        .data;
    let err = err_class(provider.derive(&a, &ecdh(&wrong_spki)), "ParamError");
    assert_eq!(
        err.message,
        "peer curve secp384r1 does not match key curve secp256r1"
    );
    let mut bad = vec![0x05u8];
    bad.extend([0u8; 64]);
    let err = err_class(provider.derive(&a, &ecdh(&bad)), "ParamError");
    assert_eq!(
        err.message,
        "peer is not SPKI DER or an uncompressed EC point (0x04‖X‖Y): Unsupported elliptic curve point type"
    );
    let err = err_class(provider.derive(&a, &ecdh(b"")), "ParamError");
    assert_eq!(err.message, "peer public key must not be empty");
    assert_eq!(err.param_name(), Some("peer"));
}

#[test]
fn test_x448_agreement_both_directions() {
    let provider = make();
    let a = generate(
        &provider,
        KeyAlgorithm::EcMontgomery,
        None,
        Some(Curve::X448),
        "a448",
        None,
    )
    .unwrap();
    let b = generate(
        &provider,
        KeyAlgorithm::EcMontgomery,
        None,
        Some(Curve::X448),
        "b448",
        None,
    )
    .unwrap();
    let b_spki = provider
        .export_key(&public_half(&provider, "b448"))
        .unwrap()
        .data;
    let z_ab = provider.derive(&a, &ecdh(&b_spki)).unwrap().raw.unwrap();
    assert_eq!(z_ab.len(), 56);
    let a_pub = PKey::public_key_from_der(
        &provider
            .export_key(&public_half(&provider, "a448"))
            .unwrap()
            .data,
    )
    .unwrap();
    let a_raw = a_pub.raw_public_key().unwrap();
    assert_eq!(
        *provider.derive(&b, &ecdh(&a_raw)).unwrap().raw.unwrap(),
        *z_ab
    );
}

#[test]
fn test_derive_rejects_wrong_key_kinds() {
    let provider = make();
    let (private, _public) = import_rsa_pair(&provider);
    let mut point = vec![0x04u8];
    point.extend([0u8; 64]);
    let err = err_class(
        provider.derive(&private, &ecdh(&point)),
        "UnsupportedOperationError",
    );
    assert_eq!(
        err.message,
        "ECDH requires an EC (Weierstrass) or X25519/X448 private key"
    );
    let ec_private = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "ec",
        None,
    )
    .unwrap();
    let err = err_class(
        provider.derive(&public_half(&provider, "ec"), &ecdh(b"x")),
        "UnsupportedOperationError",
    );
    assert_eq!(err.message, "ECDH requires a private key");
    let ed = generate(
        &provider,
        KeyAlgorithm::EcEdwards,
        None,
        Some(Curve::Ed25519),
        "ed",
        None,
    )
    .unwrap();
    let err = err_class(
        provider.derive(&ed, &ecdh(&[0u8; 32])),
        "UnsupportedOperationError",
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("Ed25519/Ed448 keys sign; they do not derive")
    );
    let err = err_class(
        provider.derive(&ec_private, &mech("ECDSA", &[("hash", text("sha256"))])),
        "UnsupportedOperationError",
    );
    assert_eq!(err.message, "mechanism ECDSA does not support derive");
}

// ---------------------------------------------------------------------------------------
// wrap / unwrap (§5.5)
// ---------------------------------------------------------------------------------------

const KW_KEK: &str = "000102030405060708090a0b0c0d0e0f";
const KW_DATA: &str = "00112233445566778899aabbccddeeff";
const KW_WRAPPED: &str = "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5";

#[test]
fn test_kat_aes_key_wrap_rfc3394() {
    let provider = make();
    let kek = import_aes(&provider, &hex(KW_KEK), "kek", None, None);
    let target = import_aes(&provider, &hex(KW_DATA), "target", None, None);
    let kw = mech("AES-KEY-WRAP", &[]);
    let blob = provider.wrap_key(&kek, &kw, &target, &wrap_opts()).unwrap();
    assert_eq!(blob, hex(KW_WRAPPED));
    let request = unwrap_req(KeyAlgorithm::Aes, KeyClass::Secret, "unwrapped", None, None);
    let unwrapped = provider.unwrap_key(&kek, &kw, &blob, &request).unwrap();
    assert_eq!(*provider.export_key(&unwrapped).unwrap().data, hex(KW_DATA));
    let mut tampered = blob.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let err = err_class(
        provider.unwrap_key(
            &kek,
            &kw,
            &tampered,
            &unwrap_req(KeyAlgorithm::Aes, KeyClass::Secret, "bad", None, None),
        ),
        "CryptoError",
    );
    assert_eq!(err.message, "AES key unwrap failed: "); // pyca's message-less InvalidUnwrap
    assert_eq!(err.hint, None);
}

#[test]
fn test_aes_key_wrap_pad_private_key_round_trip() {
    let provider = make();
    let kek_bytes: Vec<u8> = (0u8..32).collect();
    let kek = import_aes(&provider, &kek_bytes, "kek", None, None);
    let private = import_private(&provider, &rsa_2048(), KeyAlgorithm::Rsa, "rsa", None, None);
    let kwp = mech("AES-KEY-WRAP-PAD", &[]);
    let blob = provider
        .wrap_key(&kek, &kwp, &private, &wrap_opts())
        .unwrap();
    let restored = provider
        .unwrap_key(
            &kek,
            &kwp,
            &blob,
            &unwrap_req(KeyAlgorithm::Rsa, KeyClass::Private, "rsa-copy", None, None),
        )
        .unwrap();
    assert_eq!(restored.key_class, KeyClass::Private);
    assert_eq!(
        provider.export_key(&restored).unwrap().data,
        provider.export_key(&private).unwrap().data
    );
}

/// RFC 3394 wrap through OpenSSL's EVP wrap cipher (outside the provider).
fn evp_kw(kek: &[u8], payload: &[u8]) -> Vec<u8> {
    use openssl::cipher::Cipher;
    use openssl::cipher_ctx::{CipherCtx, CipherCtxFlags};
    let mut ctx = CipherCtx::new().unwrap();
    ctx.set_flags(CipherCtxFlags::FLAG_WRAP_ALLOW);
    ctx.encrypt_init(Some(Cipher::aes_256_wrap()), Some(kek), None)
        .unwrap();
    let mut out = Vec::new();
    ctx.cipher_update_vec(payload, &mut out).unwrap();
    ctx.cipher_final_vec(&mut out).unwrap();
    out
}

#[test]
fn test_aes_key_wrap_pad_accepts_spec_letter_dialect() {
    // Utimaco regression (§5.5): CKM_AES_KEY_WRAP_PAD as RFC 3394 over a PKCS#7-padded
    // payload must unwrap too — OpenSSL/SoftHSM speak RFC 5649.
    let provider = make();
    let kek_bytes: Vec<u8> = (0u8..32).collect();
    let kek = import_aes(&provider, &kek_bytes, "kek", None, None);
    let private = import_private(&provider, &rsa_2048(), KeyAlgorithm::Rsa, "rsa", None, None);
    let payload = provider.export_key(&private).unwrap().data.to_vec();
    let pad = match 8 - payload.len() % 8 {
        0 => 8,
        n => n,
    };
    let mut padded = payload.clone();
    padded.extend(std::iter::repeat_n(u8::try_from(pad).unwrap(), pad));
    let blob = evp_kw(&kek_bytes, &padded);
    let restored = provider
        .unwrap_key(
            &kek,
            &mech("AES-KEY-WRAP-PAD", &[]),
            &blob,
            &unwrap_req(
                KeyAlgorithm::Rsa,
                KeyClass::Private,
                "rsa-utimaco",
                None,
                None,
            ),
        )
        .unwrap();
    assert_eq!(*provider.export_key(&restored).unwrap().data, payload);
}

#[test]
fn test_aes_key_wrap_pad_rejects_bad_pkcs7_tail() {
    // A 3394-unwrappable blob whose tail is not valid PKCS#7 must still fail.
    let provider = make();
    let kek_bytes: Vec<u8> = (0u8..32).collect();
    let kek = import_aes(&provider, &kek_bytes, "kek", None, None);
    let mut payload: Vec<u8> = (0u8..16).collect();
    payload.extend([0u8; 8]); // pad byte 0
    let blob = evp_kw(&kek_bytes, &payload);
    let err = err_class(
        provider.unwrap_key(
            &kek,
            &mech("AES-KEY-WRAP-PAD", &[]),
            &blob,
            &unwrap_req(KeyAlgorithm::Aes, KeyClass::Secret, "bad-pad", None, None),
        ),
        "CryptoError",
    );
    assert!(err.message.starts_with("AES key unwrap failed"));
    assert_eq!(
        err.message,
        "AES key unwrap failed: RFC 3394 unwrap succeeded but the PKCS#7 padding is invalid"
    );
}

#[test]
fn test_aes_key_wrap_pad_garbage_still_fails_with_dialect_hint() {
    let provider = make();
    let kek = import_aes(
        &provider,
        &(0u8..32).collect::<Vec<u8>>(),
        "kek",
        None,
        None,
    );
    let err = err_class(
        provider.unwrap_key(
            &kek,
            &mech("AES-KEY-WRAP-PAD", &[]),
            &[0u8; 40],
            &unwrap_req(KeyAlgorithm::Aes, KeyClass::Secret, "garbage", None, None),
        ),
        "CryptoError",
    );
    assert!(err.hint.as_deref().is_some_and(|h| h.contains("dialect")));
    assert_eq!(
        err.message,
        "AES key unwrap failed: blob matches neither AES-KEY-WRAP-PAD dialect (RFC 5649 KWP / RFC 3394 over PKCS#7-padded payload)"
    );
}

#[test]
fn test_aes_key_wrap_requires_aligned_payload() {
    // Ed448 PKCS#8 is 73 bytes (deterministic) — unaligned, so plain KW fails.
    let provider = make();
    let kek = import_aes(
        &provider,
        &(0u8..16).collect::<Vec<u8>>(),
        "kek",
        None,
        None,
    );
    let ed = generate(
        &provider,
        KeyAlgorithm::EcEdwards,
        None,
        Some(Curve::Ed448),
        "ed448",
        None,
    )
    .unwrap();
    let err = err_class(
        provider.wrap_key(&kek, &mech("AES-KEY-WRAP", &[]), &ed, &wrap_opts()),
        "CryptoError",
    );
    assert_eq!(
        err.message,
        "AES key wrap failed: The key to wrap must be a multiple of 8 bytes"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some(
            "AES-KEY-WRAP needs an 8-byte-aligned payload of >= 16 bytes; use AES-KEY-WRAP-PAD otherwise"
        )
    );
    let kwp = mech("AES-KEY-WRAP-PAD", &[]);
    let blob = provider.wrap_key(&kek, &kwp, &ed, &wrap_opts()).unwrap(); // padded variant works
    let restored = provider
        .unwrap_key(
            &kek,
            &kwp,
            &blob,
            &unwrap_req(
                KeyAlgorithm::EcEdwards,
                KeyClass::Private,
                "ed448-copy",
                None,
                None,
            ),
        )
        .unwrap();
    assert_eq!(
        provider.export_key(&restored).unwrap().data,
        provider.export_key(&ed).unwrap().data
    );
}

#[test]
fn test_rsa_oaep_wrap_including_cert_as_wrapping_key() {
    let provider = make();
    let (private, public) = import_rsa_pair(&provider);
    let secret: Vec<u8> = (0u8..32).collect();
    let target = import_aes(&provider, &secret, "target", None, None);
    let oaep = mech("RSA-OAEP", &[("hash", text("sha256"))]);
    let blob = provider
        .wrap_key(&public, &oaep, &target, &wrap_opts())
        .unwrap();
    let restored = provider
        .unwrap_key(
            &private,
            &oaep,
            &blob,
            &unwrap_req(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                "restored",
                None,
                Some(b"\x99"),
            ),
        )
        .unwrap();
    assert_eq!(restored.key_ref.key_id.as_deref(), Some(&b"\x99"[..]));
    assert_eq!(*provider.export_key(&restored).unwrap().data, secret);

    // §4.3: a CERTIFICATE stands in for the public key in wrap_key
    let cert_der = self_signed(&rsa_2048(), "c2-mem-rsa", false);
    let cert = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert_der),
            "rsa-cert",
            None,
            None,
        )
        .unwrap();
    let blob2 = provider
        .wrap_key(&cert, &oaep, &target, &wrap_opts())
        .unwrap();
    let restored2 = provider
        .unwrap_key(
            &private,
            &oaep,
            &blob2,
            &unwrap_req(KeyAlgorithm::Aes, KeyClass::Secret, "restored2", None, None),
        )
        .unwrap();
    assert_eq!(*provider.export_key(&restored2).unwrap().data, secret);
}

#[test]
fn test_rsa_aes_key_wrap_hybrid_private_target() {
    // Single-shot hybrid (§5.5): works for payloads beyond the OAEP limit.
    let provider = make();
    let wrapper_key = rsa_2048_b();
    let wrapper_private = import_private(
        &provider,
        &wrapper_key,
        KeyAlgorithm::Rsa,
        "kekpair",
        None,
        None,
    );
    let wrapper_public = import_public(
        &provider,
        &wrapper_key,
        KeyAlgorithm::Rsa,
        "kekpair-pub",
        None,
    );
    let target = import_private(
        &provider,
        &rsa_2048(),
        KeyAlgorithm::Rsa,
        "payload",
        None,
        None,
    );
    let hybrid = mech("RSA-AES-KEY-WRAP", &[]);
    let blob = provider
        .wrap_key(&wrapper_public, &hybrid, &target, &wrap_opts())
        .unwrap();
    assert!(blob.len() > 256); // OAEP part (k) plus the KW-PAD payload
    let restored = provider
        .unwrap_key(
            &wrapper_private,
            &hybrid,
            &blob,
            &unwrap_req(
                KeyAlgorithm::Rsa,
                KeyClass::Private,
                "payload-copy",
                None,
                None,
            ),
        )
        .unwrap();
    assert_eq!(
        provider.export_key(&restored).unwrap().data,
        provider.export_key(&target).unwrap().data
    );
    let err = err_class(
        provider.unwrap_key(
            &wrapper_private,
            &hybrid,
            &blob[..100],
            &unwrap_req(KeyAlgorithm::Rsa, KeyClass::Private, "short", None, None),
        ),
        "CryptoError",
    );
    assert_eq!(
        err.message,
        "RSA-AES-KEY-WRAP blob too short: 100 bytes (needs > 256-byte OAEP part plus the wrapped payload)"
    );
}

#[test]
fn test_wrap_semantics_exportable_vs_wrappable() {
    // §5.5: wrappable = CKA_EXTRACTABLE alone; exportable also needs ¬SENSITIVE.
    let provider = make();
    let kek = import_aes(
        &provider,
        &(0u8..32).collect::<Vec<u8>>(),
        "kek",
        None,
        None,
    );
    let secret: Vec<u8> = (16u8..48).collect();
    let sensitive_target = import_aes(
        &provider,
        &secret,
        "sens",
        Some(&template(true, true)),
        None,
    );
    let err = err_class(
        provider.export_key(&sensitive_target),
        "KeyNotExportableError",
    );
    assert_eq!(err.message, "key 'mem:sens' is not exportable");
    assert_eq!(
        err.hint.as_deref(),
        Some("CKA_SENSITIVE/CKA_EXTRACTABLE forbid a plain-value read (§5.5)")
    );
    let kwp = mech("AES-KEY-WRAP-PAD", &[]);
    let blob = provider
        .wrap_key(&kek, &kwp, &sensitive_target, &wrap_opts())
        .unwrap(); // wrappable
    let restored = provider
        .unwrap_key(
            &kek,
            &kwp,
            &blob,
            &unwrap_req(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                "sens-copy",
                Some(template(true, false)),
                None,
            ),
        )
        .unwrap();
    assert_eq!(*provider.export_key(&restored).unwrap().data, secret);

    let locked = import_aes(
        &provider,
        &[0u8; 32],
        "locked",
        Some(&template(false, false)),
        None,
    );
    let err = err_class(
        provider.wrap_key(&kek, &kwp, &locked, &wrap_opts()), // not extractable
        "KeyNotExportableError",
    );
    assert_eq!(
        err.message,
        "key 'mem:locked' is not extractable and cannot be wrapped"
    );
}

#[test]
fn test_wrap_rejects_public_targets_and_bad_mechs() {
    let provider = make();
    let kek = import_aes(
        &provider,
        &(0u8..32).collect::<Vec<u8>>(),
        "kek",
        None,
        None,
    );
    let (private, public) = import_rsa_pair(&provider);
    let err = err_class(
        provider.wrap_key(&kek, &mech("AES-KEY-WRAP-PAD", &[]), &public, &wrap_opts()),
        "UnsupportedOperationError",
    ); // publics copy as plain
    assert_eq!(err.message, "only secret and private keys are wrapped");
    // AES-ECB is advertised but not wrap-capable (AES-GCM became a §5.4 KEK-load
    // mechanism, so it is no longer a "bad mech" example)
    let err = err_class(
        provider.wrap_key(&kek, &mech("AES-ECB", &[]), &private, &wrap_opts()),
        "UnsupportedOperationError",
    );
    assert_eq!(
        err.message,
        "mechanism AES-ECB does not support key wrapping"
    );
    let err = err_class(
        provider.unwrap_key(
            &kek,
            &mech("AES-KEY-WRAP-PAD", &[]),
            &[0u8; 40],
            &unwrap_req(KeyAlgorithm::Rsa, KeyClass::Public, "nope", None, None),
        ),
        "UnsupportedOperationError",
    );
    assert_eq!(err.message, "unwrap produces secret or private keys only");
}

#[test]
fn test_unwrapped_garbage_fails_key_parse() {
    let provider = make();
    let kek = import_aes(
        &provider,
        &(0u8..32).collect::<Vec<u8>>(),
        "kek",
        None,
        None,
    );
    let junk = import_aes(
        &provider,
        &(0u8..16).collect::<Vec<u8>>(),
        "junk",
        None,
        None,
    );
    let kwp = mech("AES-KEY-WRAP-PAD", &[]);
    let blob = provider.wrap_key(&kek, &kwp, &junk, &wrap_opts()).unwrap();
    let err = err_class(
        provider.unwrap_key(
            &kek,
            &kwp,
            &blob,
            // 16 raw bytes are not a PKCS#8 key
            &unwrap_req(KeyAlgorithm::Rsa, KeyClass::Private, "mismatch", None, None),
        ),
        "KeyParseError",
    );
    assert!(
        err.message
            .starts_with("cannot parse private key material: "),
        "{}",
        err.message
    );
}

// ---------------------------------------------------------------------------------------
// certificates (§4.3 / §5.11)
// ---------------------------------------------------------------------------------------

#[test]
fn test_ec_certificate_verifies_and_carries_attributes() {
    let provider = make();
    let key = PKey::from_ec_key(EcKey::generate(&p256()).unwrap()).unwrap();
    let cert_der = self_signed(&key, "c2-mem-ec", true);
    let private = import_private(
        &provider,
        &key,
        KeyAlgorithm::Ec,
        "signer",
        None,
        Some(b"\x01"),
    );
    let cert = provider
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Certificate, cert_der),
            "signer-cert",
            None,
            Some(b"\x01"),
        )
        .unwrap();
    assert_eq!(cert.algorithm, KeyAlgorithm::Ec);
    assert_eq!(cert.curve, Some(Curve::P256));
    assert!(cert.exportable);
    assert_eq!(
        cert.attributes.get("subject"),
        Some(&AttrValue::Str("CN=c2-mem-ec".to_owned()))
    );
    assert_eq!(
        cert.attributes.get("serial_number"),
        Some(&AttrValue::Str("12345678".to_owned()))
    );
    let ecdsa = mech("ECDSA", &[("hash", text("sha256"))]);
    let signature = provider.sign(&private, &ecdsa, b"signed").unwrap();
    assert!(
        provider
            .verify(&cert, &ecdsa, b"signed", &signature)
            .unwrap()
    );
    let err = err_class(
        provider.sign(&cert, &ecdsa, b"signed"),
        "UnsupportedOperationError",
    );
    assert_eq!(err.message, "certificates cannot be used for sign (§4.3)");
    assert_eq!(
        err.hint.as_deref(),
        Some("certificates stand in for PUBLIC keys only (encrypt/verify/wrap)")
    );
    let err = err_class(
        provider.derive(&cert, &ecdh(&[0u8; 32])),
        "UnsupportedOperationError",
    );
    assert_eq!(err.message, "certificates cannot be used for derive (§4.3)");
}

// ---------------------------------------------------------------------------------------
// generation & import edge cases
// ---------------------------------------------------------------------------------------

#[test]
fn test_generate_keypair_shares_explicit_key_id() {
    let provider = make();
    let private = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "pair",
        Some(b"\x0a\x0b"),
    )
    .unwrap();
    assert_eq!(private.key_ref.key_id.as_deref(), Some(&b"\x0a\x0b"[..]));
    assert_eq!(
        public_half(&provider, "pair").key_ref.key_id.as_deref(),
        Some(&b"\x0a\x0b"[..])
    );
    // memory provider keeps key_id=None when not given (§4.5 randomizes on PKCS#11 only)
    let other = generate(
        &provider,
        KeyAlgorithm::Ec,
        None,
        Some(Curve::P256),
        "pair2",
        None,
    )
    .unwrap();
    assert_eq!(other.key_ref.key_id, None);
}

#[test]
fn test_generate_rsa_metadata() {
    let provider = make();
    let private = generate(&provider, KeyAlgorithm::Rsa, Some(2048), None, "meta", None).unwrap();
    assert_eq!(private.size_bits, Some(2048));
    assert_eq!(private.curve, None);
    assert_eq!(private.algorithm, KeyAlgorithm::Rsa);
}

#[test]
fn test_generate_rejects_bad_parameters() {
    let cases: [(KeyAlgorithm, Option<u32>, Option<Curve>, &str); 7] = [
        (
            KeyAlgorithm::Aes,
            None,
            None,
            "size_bits is required for aes",
        ),
        (
            KeyAlgorithm::Aes,
            Some(100),
            None,
            "invalid AES key size 100; expected 128, 192 or 256",
        ),
        (
            KeyAlgorithm::Rsa,
            None,
            None,
            "size_bits is required for RSA",
        ),
        (KeyAlgorithm::Ec, None, None, "curve is required for ec"),
        (
            KeyAlgorithm::Ec,
            None,
            Some(Curve::Ed25519),
            "unknown EC curve 'ed25519'",
        ), // family mismatch
        (
            KeyAlgorithm::EcEdwards,
            None,
            Some(Curve::P256),
            "unknown Edwards curve 'p256'",
        ),
        (
            KeyAlgorithm::EcMontgomery,
            None,
            Some(Curve::Other("banana".to_owned())),
            "unknown Montgomery curve 'banana'",
        ),
    ];
    for (algorithm, size_bits, curve, message) in cases {
        let err = err_class(
            generate(&make(), algorithm, size_bits, curve, "bad", None),
            "ParamError",
        );
        assert_eq!(err.message, message);
    }
}

#[test]
fn test_import_rejects_non_canonical_material() {
    let provider = make();
    let short = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![0u8; 15]);
    let err = err_class(
        provider.import_key(&short, "shortkey", None, None),
        "KeyParseError",
    );
    assert_eq!(err.message, "AES key must be 16, 24 or 32 bytes; got 15");
    let junk = KeyMaterial::new(
        KeyAlgorithm::Rsa,
        KeyClass::Private,
        b"\x30garbage".to_vec(),
    );
    let err = err_class(
        provider.import_key(&junk, "junk", None, None),
        "KeyParseError",
    );
    assert!(err.message.starts_with(
        "cannot parse private key material: Could not deserialize key data. The data may be in an incorrect format"
    ), "{}", err.message);
    // declared algorithm must match the parsed data
    let ec = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, pkcs8(&ec_p256()));
    let err = err_class(
        provider.import_key(&ec, "mismatch", None, None),
        "KeyParseError",
    );
    assert_eq!(
        err.message,
        "material declares algorithm 'rsa' but data parses as 'ec'"
    );
    // canonical PRIVATE is *unencrypted* PKCS#8 (§4.3)
    let encrypted = rsa_2048()
        .private_key_to_pkcs8_passphrase(openssl::symm::Cipher::aes_256_cbc(), b"pw")
        .unwrap();
    let material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, encrypted);
    let err = err_class(
        provider.import_key(&material, "encrypted", None, None),
        "KeyParseError",
    );
    assert_eq!(
        err.message,
        "private key material must be UNENCRYPTED PKCS#8 DER (§4.3)"
    );
}

// ---------------------------------------------------------------------------------------
// verb / key-class / parameter policing
// ---------------------------------------------------------------------------------------

#[test]
fn test_verb_mechanism_mismatches() {
    let provider = make();
    let aes = import_aes(
        &provider,
        &(0u8..32).collect::<Vec<u8>>(),
        "aes",
        None,
        None,
    );
    let (private, public) = import_rsa_pair(&provider);
    let cases: Vec<(r2_core::Result<Vec<u8>>, &str)> = vec![
        (
            provider.encrypt(&aes, &mech("ECDSA", &[("hash", text("sha256"))]), b"x"),
            "mechanism ECDSA does not support encrypt",
        ),
        (
            provider.sign(&aes, &mech("AES-GCM", &[("iv", bytes(&[0u8; 12]))]), b"x"),
            "mechanism AES-GCM does not support sign",
        ),
        (
            // not a secret key
            provider.encrypt(
                &public,
                &mech("AES-GCM", &[("iv", bytes(&[0u8; 12]))]),
                b"x",
            ),
            "encrypt with an AES mechanism requires a secret AES key (got rsa public)",
        ),
        (
            // needs private
            provider
                .decrypt(
                    &public,
                    &mech("RSA-OAEP", &[("hash", text("sha256"))]),
                    b"x",
                )
                .map(|z| z.to_vec()),
            "decrypt requires an RSA private key",
        ),
        (
            // RSA key, EC mechanism
            provider.sign(&private, &mech("ECDSA", &[("hash", text("sha256"))]), b"x"),
            "sign requires an EC private key",
        ),
        (
            provider.sign(&private, &mech("EDDSA", &[]), b"x"),
            "sign requires an Ed25519/Ed448 private key",
        ),
    ];
    for (result, message) in cases {
        let err = err_class(result, "UnsupportedOperationError");
        assert_eq!(err.message, message);
    }
    // needs public
    let err = err_class(
        provider.verify(
            &private,
            &mech("RSA-PKCS1", &[("hash", text("sha256"))]),
            b"x",
            b"y",
        ),
        "UnsupportedOperationError",
    );
    assert_eq!(err.message, "verify requires a public key or certificate");
}

#[test]
fn test_parameter_policing() {
    let provider = make();
    let aes = import_aes(
        &provider,
        &(0u8..32).collect::<Vec<u8>>(),
        "aes",
        None,
        None,
    );
    let cases: Vec<(r2_provider::MechanismInvocation, &[u8], &str, &str)> = vec![
        (
            mech("AES-ECB", &[("padding", text("none"))]),
            b"unaligned!",
            "padding=none requires input length to be a multiple of 16 bytes",
            "padding",
        ),
        (
            mech("AES-CBC", &[("iv", bytes(&[0u8; 8]))]),
            &[b'x'; 16],
            "iv must be 16 bytes for AES-CBC; got 8",
            "iv",
        ),
        (
            mech("AES-CBC", &[]),
            &[b'x'; 16],
            "missing required parameter 'iv'",
            "iv",
        ),
        (
            mech("AES-CTR", &[("counter_block", bytes(&[0u8; 8]))]),
            b"x",
            "counter_block must be the full 16-byte initial block; got 8 bytes",
            "counter_block",
        ),
        (
            mech(
                "AES-CTR",
                &[
                    ("counter_block", bytes(&[0u8; 16])),
                    ("counter_bits", int(64)),
                ],
            ),
            b"x",
            "the memory provider supports counter_bits=128 only (pyca CTR increments the full block, §5.8)",
            "counter_bits",
        ),
        (
            mech(
                "AES-GCM",
                &[("iv", bytes(&[0u8; 12])), ("tag_bits", text("99"))],
            ),
            b"x",
            "parameter 'tag_bits' must be one of 128, 120, 112, 104, 96; got '99'",
            "tag_bits",
        ),
        (
            mech("AES-CBC", &[("iv", text("not-bytes"))]),
            &[b'x'; 16],
            "parameter 'iv' must be bytes",
            "iv",
        ),
    ];
    for (mechanism, data, message, param) in cases {
        let err = err_class(provider.encrypt(&aes, &mechanism, data), "ParamError");
        assert_eq!(err.message, message);
        assert_eq!(err.param_name(), Some(param));
    }
    let err = err_class(
        provider.sign(&aes, &mech("AES-CMAC", &[("mac_len", text("lots"))]), b"x"),
        "ParamError",
    );
    assert_eq!(
        err.message,
        "parameter 'mac_len' must be an integer, got 'lots'"
    );
}

#[test]
fn test_cbc_decrypt_failures() {
    let provider = make();
    let aes = import_aes(
        &provider,
        &(0u8..32).collect::<Vec<u8>>(),
        "aes",
        None,
        None,
    );
    let cbc = mech(
        "AES-CBC",
        &[("iv", bytes(&[0u8; 16])), ("padding", text("pkcs7"))],
    );
    let err = err_class(
        provider.decrypt(&aes, &cbc, b"not a multiple of sixteen"),
        "CryptoError",
    );
    assert_eq!(
        err.message,
        "AES-CBC decryption failed: The length of the provided data is not a multiple of the block length."
    );
    let err = err_class(
        provider.decrypt(&aes, &cbc, &[0u8; 16]), // decrypts to garbage padding
        "CryptoError",
    );
    assert_eq!(err.message, "invalid PKCS7 padding in decrypted data");
}

// ---------------------------------------------------------------------------------------
// key editing (§5.15) — memory supports identity rows only
// ---------------------------------------------------------------------------------------

fn edit_tpl(attrs: Vec<TemplateAttr>) -> KeyTemplate {
    KeyTemplate::new(attrs)
}

#[test]
fn test_edit_read_template_id_row_disabled_for_none_id() {
    let provider = make();
    let info = import_aes(
        &provider,
        &(0u8..32).collect::<Vec<u8>>(),
        "edit-noid",
        None,
        None,
    );
    let template = provider.read_key_template(&info).unwrap();
    let id_row = template.get("CKA_ID").unwrap();
    assert!(!id_row.enabled);
    assert_eq!(id_row.value, AttrValue::Bytes(Vec::new()));
}

#[test]
fn test_edit_id_change_on_keypair_half_leaves_sibling() {
    let provider = make();
    let private = generate(
        &provider,
        KeyAlgorithm::Rsa,
        Some(2048),
        None,
        "edit-pair",
        Some(b"\x01"),
    )
    .unwrap();
    let result = provider
        .update_key(
            &private,
            &edit_tpl(vec![TemplateAttr::new(
                "CKA_ID",
                AttrKind::Bytes,
                AttrValue::Bytes(b"\x02".to_vec()),
            )]),
        )
        .unwrap();
    assert_eq!(result.key.key_ref.key_id.as_deref(), Some(&b"\x02"[..]));
    assert_eq!(
        find(&provider, "edit-pair", Some(b"\x02"))
            .unwrap()
            .key_class,
        KeyClass::Private
    );
    let public = find(&provider, "edit-pair", Some(b"\x01")).unwrap(); // sibling untouched (§5.15)
    assert_eq!(public.key_class, KeyClass::Public);
}

#[test]
fn test_edit_non_identity_row_is_failed_outcome() {
    let provider = make();
    let info = import_aes(
        &provider,
        &(0u8..32).collect::<Vec<u8>>(),
        "edit-flags",
        None,
        None,
    );
    let result = provider
        .update_key(
            &info,
            &edit_tpl(vec![TemplateAttr::new(
                "CKA_ENCRYPT",
                AttrKind::Bool,
                AttrValue::Bool(true),
            )]),
        )
        .unwrap();
    assert_eq!(
        result.outcomes,
        vec![AttrEditOutcome {
            name: "CKA_ENCRYPT".to_owned(),
            applied: false,
            detail: Some("not editable on the memory provider".to_owned()),
        }]
    );
    assert_eq!(result.key.key_ref, info.key_ref); // nothing changed
}

#[test]
fn test_edit_empty_identity_values_rejected() {
    let provider = make();
    let info = import_aes(
        &provider,
        &(0u8..32).collect::<Vec<u8>>(),
        "edit-empty",
        None,
        None,
    );
    let err = err_class(
        provider.update_key(
            &info,
            &edit_tpl(vec![TemplateAttr::new(
                "CKA_LABEL",
                AttrKind::Str,
                AttrValue::Str(String::new()),
            )]),
        ),
        "ParamError",
    );
    assert_eq!(err.message, "CKA_LABEL expects a non-empty string");
    let err = err_class(
        provider.update_key(
            &info,
            &edit_tpl(vec![TemplateAttr::new(
                "CKA_ID",
                AttrKind::Bytes,
                AttrValue::Bytes(Vec::new()),
            )]),
        ),
        "ParamError",
    );
    assert_eq!(err.message, "CKA_ID expects non-empty bytes");
    assert_eq!(err.hint.as_deref(), Some("use a 0x… hex value"));
    let err = err_class(
        provider.update_key(
            &info,
            &edit_tpl(vec![TemplateAttr::new(
                "CKA_CLASS",
                AttrKind::Ulong,
                AttrValue::Ulong(0),
            )]),
        ),
        "ParamError",
    );
    assert_eq!(err.message, "CKA_CLASS cannot be edited after creation");
    assert_eq!(err.param_name(), Some("CKA_CLASS"));
}

#[test]
fn test_edit_label_only_rename_keeps_id_and_passes_guard() {
    let provider = make();
    let key: Vec<u8> = (0u8..32).collect();
    import_aes(&provider, &key, "edit-other", None, Some(b"\x66"));
    let info = import_aes(&provider, &key, "edit-move", None, Some(b"\x07"));
    let result = provider
        .update_key(
            &info,
            &edit_tpl(vec![TemplateAttr::new(
                "CKA_LABEL",
                AttrKind::Str,
                AttrValue::Str("edit-other".to_owned()),
            )]),
        )
        .unwrap();
    assert_eq!(result.key.key_ref.key_id.as_deref(), Some(&b"\x07"[..])); // distinct ids → no twin
    assert_eq!(
        find(&provider, "edit-other", Some(b"\x07"))
            .unwrap()
            .key_ref
            .label,
        "edit-other"
    );
}

#[test]
fn test_edit_rename_can_assign_id_to_none_id_key() {
    let provider = make();
    let info = import_aes(
        &provider,
        &(0u8..32).collect::<Vec<u8>>(),
        "edit-gainid",
        None,
        None,
    );
    let result = provider
        .update_key(
            &info,
            &edit_tpl(vec![TemplateAttr::new(
                "CKA_ID",
                AttrKind::Bytes,
                AttrValue::Bytes(b"\x11".to_vec()),
            )]),
        )
        .unwrap();
    assert_eq!(result.key.key_ref.key_id.as_deref(), Some(&b"\x11"[..]));
    assert_eq!(
        provider
            .find_key(&KeySelector::label("edit-gainid").with_id(Some(b"\x11".to_vec())))
            .unwrap()
            .key_ref
            .key_id
            .as_deref(),
        Some(&b"\x11"[..])
    );
}
