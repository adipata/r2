//! Ports of c2 tests/unit/pkcs11/test_mechanisms.py folding / EdDSA probe / custom merge /
//! normalization cases (moved to R5a, spec §4.1.1) and the provider-level advertisement
//! cases of test_objects.py / test_provider_objects.py.
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use indexmap::IndexMap;
use r2_provider::Provider;

use super::{USER_PIN, logged_in, pin, provider_over, provider_with, token_at};
use crate::backend::fake::{DEFAULT_MECHANISMS, FakeBackend};
use crate::capability::{EDDSA_VENDOR_CKMS, eddsa_ckm, fold_mechanisms, fold_mechanisms_with};
use crate::catalog::symbol_value;

fn codes(names: &[&str]) -> Vec<u64> {
    names.iter().map(|n| symbol_value(n).unwrap()).collect()
}

fn fold(names: &[&str]) -> BTreeSet<String> {
    fold_mechanisms(&codes(names), &BTreeMap::new())
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| (*n).to_string()).collect()
}

// ---- TestFolding ----

#[test]
fn folding_hash_variants_fold() {
    assert_eq!(fold(&["CKM_ECDSA_SHA256"]), set(&["ECDSA"]));
    assert_eq!(fold(&["CKM_SHA384_RSA_PKCS"]), set(&["RSA-PKCS1"]));
    assert_eq!(fold(&["CKM_RSA_PKCS_PSS", "CKM_SHA1_RSA_PKCS_PSS"]), set(&["RSA-PSS"]));
}

#[test]
fn folding_cbc_and_cbc_pad_fold_to_one_name() {
    assert_eq!(fold(&["CKM_AES_CBC"]), set(&["AES-CBC"]));
    assert_eq!(fold(&["CKM_AES_CBC_PAD"]), set(&["AES-CBC"]));
}

#[test]
fn folding_gmac_advertised_via_gcm_fallback() {
    let folded = fold(&["CKM_AES_GCM"]);
    assert!(folded.contains("AES-GCM"));
    assert!(folded.contains("AES-GMAC")); // GCM construction (§5.9)
    assert_eq!(fold(&["CKM_AES_GMAC"]), set(&["AES-GMAC"]));
}

#[test]
fn folding_wrap_and_derive_names() {
    assert_eq!(
        fold(&["CKM_AES_KEY_WRAP", "CKM_AES_KEY_WRAP_PAD", "CKM_ECDH1_DERIVE"]),
        set(&["AES-KEY-WRAP", "AES-KEY-WRAP-PAD", "ECDH"])
    );
    // KWP folds into the PAD canonical name
    assert_eq!(fold(&["CKM_AES_KEY_WRAP_KWP"]), set(&["AES-KEY-WRAP-PAD"]));
}

#[test]
fn folding_rsa_aes_key_wrap_not_advertised() {
    // §4.5.5 / §11 D6: the fold stays honest — never advertised
    assert!(!fold(&["CKM_RSA_AES_KEY_WRAP"]).contains("RSA-AES-KEY-WRAP"));
}

#[test]
fn folding_empty_codes_fold_to_nothing() {
    assert_eq!(fold_mechanisms(&[], &BTreeMap::new()), BTreeSet::new());
}

#[test]
fn folding_table_codes_equal_pykcs11_names() {
    // the cryptoki-sys numerics of the fold table equal PyKCS11's names for them
    for (_, sources) in crate::capability::fold_sources() {
        for code in sources {
            assert!(crate::catalog::ckm_name(code).is_some(), "0x{code:x}");
        }
    }
    assert_eq!(symbol_value("CKM_AES_KEY_WRAP_KWP"), Some(0x210B));
    assert_eq!(symbol_value("CKM_AES_GMAC"), Some(0x108E));
}

// ---- TestCmacFolding ----

#[test]
fn cmac_general_alone_is_not_advertised() {
    assert_eq!(fold(&["CKM_AES_CMAC_GENERAL"]), BTreeSet::new());
}

#[test]
fn cmac_advertised_with_plain_ckm() {
    assert_eq!(fold(&["CKM_AES_CMAC"]), set(&["AES-CMAC"]));
}

// ---- TestEddsaProbe ----

#[test]
fn eddsa_standard_ckm_wins() {
    let codes = codes(&["CKM_EDDSA"]);
    assert_eq!(eddsa_ckm(&codes, &EDDSA_VENDOR_CKMS), symbol_value("CKM_EDDSA"));
    assert!(fold_mechanisms(&codes, &BTreeMap::new()).contains("EDDSA"));
}

#[test]
fn eddsa_vendor_probe_is_advisory() {
    let vendor = 0x8000_1057;
    let codes = [vendor];
    // not in the candidate list → hidden (§5.9: absent → op hidden)
    assert_eq!(eddsa_ckm(&codes, &EDDSA_VENDOR_CKMS), None);
    assert!(!fold_mechanisms(&codes, &BTreeMap::new()).contains("EDDSA"));
    // listed candidate present on the token → advertised and used
    assert_eq!(eddsa_ckm(&codes, &[vendor]), Some(vendor));
    assert!(fold_mechanisms_with(&codes, &BTreeMap::new(), &[vendor]).contains("EDDSA"));
}

#[test]
fn eddsa_default_candidates_only_when_token_lists_them() {
    for candidate in EDDSA_VENDOR_CKMS {
        assert!(candidate >= 0x8000_0000); // vendor-defined range
        assert_eq!(eddsa_ckm(&[candidate], &EDDSA_VENDOR_CKMS), Some(candidate));
    }
}

// ---- TestCustomMerge ----

#[test]
fn custom_ckm_advertised_when_token_lists_it() {
    let vendor_ckm = 0x8000_0A01;
    let custom = BTreeMap::from([(vendor_ckm, "vendor.acme.kcv".to_string())]);
    assert!(fold_mechanisms(&[vendor_ckm], &custom).contains("vendor.acme.kcv"));
    assert!(!fold_mechanisms(&codes(&["CKM_AES_GCM"]), &custom).contains("vendor.acme.kcv"));
}

#[test]
fn custom_and_builtin_coexist() {
    let vendor_ckm = 0x8000_0A01;
    let custom = BTreeMap::from([(vendor_ckm, "vendor.acme.kcv".to_string())]);
    let mut listed = codes(&["CKM_AES_GCM"]);
    listed.push(vendor_ckm);
    let folded = fold_mechanisms(&listed, &custom);
    assert!(folded.contains("AES-GCM") && folded.contains("vendor.acme.kcv"));
}

// ---- TestNormalize (r2: the unfiltered mechanism list) ----

#[test]
fn unknown_ckms_survive_the_unfiltered_mechanism_list() {
    // c2 normalized PyKCS11 names and raw ints; r2's backend reports raw codes, and codes no
    // binding names (vendor CKMs) must survive into the fold
    let vendor = 0x8000_0A01;
    let mut mechs = DEFAULT_MECHANISMS.to_vec();
    mechs.push(vendor);
    let backend = Rc::new(FakeBackend::with_slots(vec![(0, FakeBackend::token("fake-token", "FAKE0001"), mechs)]));
    let custom = BTreeMap::from([(vendor, "vendor.acme.kcv".to_string())]);
    let provider = provider_with(&backend, custom, IndexMap::new());
    let token = token_at(&provider, 0);
    provider.login(&token, &pin(USER_PIN), false).unwrap();
    assert!(provider.mech_codes().contains(&vendor));
    assert!(provider.mechanisms().contains("vendor.acme.kcv"));
}

// ---- provider-level advertisement ----

#[test]
fn mechanisms_fold_hmac() {
    let (_backend, provider) = logged_in();
    assert!(provider.mechanisms().contains("HMAC"));
    assert!(fold(&["CKM_SHA256_HMAC"]).contains("HMAC"));
    assert!(!fold(&["CKM_AES_CMAC"]).contains("HMAC"));
}

#[test]
fn default_fake_token_advertises_softhsm_like_names() {
    let (_backend, provider) = logged_in();
    let expected = set(&[
        "AES-CBC", "AES-CMAC", "AES-CTR", "AES-ECB", "AES-GCM", "AES-GMAC", "AES-KEY-WRAP",
        "AES-KEY-WRAP-PAD", "ECDH", "ECDSA", "EDDSA", "HMAC", "RSA-OAEP", "RSA-PKCS1", "RSA-PSS",
        "RSA-RAW",
    ]);
    assert_eq!(provider.mechanisms(), expected);
    assert!(provider.supports("AES-GCM"));
    assert!(!provider.supports("RSA-AES-KEY-WRAP"));
}

#[test]
fn custom_ckm_advertised() {
    let vendor = 0x8000_0A01;
    let mut mechs = DEFAULT_MECHANISMS.to_vec();
    mechs.push(vendor);
    let backend = Rc::new(FakeBackend::with_slots(vec![(0, FakeBackend::token("fake-token", "FAKE0001"), mechs)]));
    let provider = provider_with(
        &backend,
        BTreeMap::from([(vendor, "vendor.acme.kcv".to_string())]),
        IndexMap::new(),
    );
    let token = token_at(&provider, 0);
    provider.login(&token, &pin(USER_PIN), false).unwrap();
    assert!(provider.mechanisms().contains("vendor.acme.kcv"));
    assert!(provider.supports("vendor.acme.kcv"));
}

#[test]
fn custom_ckm_not_advertised_without_token_support() {
    let backend = Rc::new(FakeBackend::new());
    let provider = provider_with(
        &backend,
        BTreeMap::from([(0x8000_0A01, "vendor.acme.kcv".to_string())]),
        IndexMap::new(),
    );
    let token = token_at(&provider, 0);
    provider.login(&token, &pin(USER_PIN), false).unwrap();
    assert!(!provider.mechanisms().contains("vendor.acme.kcv"));
}

#[test]
fn mechanisms_empty_while_logged_out_and_never_load() {
    let backend = Rc::new(FakeBackend::new());
    let provider = provider_over(&backend);
    assert!(provider.mechanisms().is_empty());
    assert!(backend.calls().is_empty()); // status/mechanisms never touch the library
}
