//! The key cache over the FakeBackend (spec §5.19, r2 addition): the loader job lists what
//! `list_keys` lists, r2's own changes patch the cache in place, logout drops it, session
//! recovery drops and asks for a reload, and `find_objects` searches by label/id.
use r2_core::error::ErrorKind;
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_provider::cache::{CacheState, LoadOutcome, LoadSink};
use r2_provider::{GenerateRequest, KeySelector, ObjectQuery, Provider};

use super::{USER_PIN, logged_in, pin, provider_over, token_at};
use crate::Pkcs11Provider;
use crate::backend::fake::FakeBackend;
use crate::ckr::rv;

fn aes(byte: u8) -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![byte; 32])
}

fn ec_pair(label: &str) -> GenerateRequest {
    let mut request = GenerateRequest::new(KeyAlgorithm::Ec, label);
    request.curve = Some(Curve::P256);
    request
}

fn by_handle(mut keys: Vec<KeyInfo>) -> Vec<KeyInfo> {
    keys.sort_by_key(|k| k.handle);
    keys
}

/// Run one cache load to its end on this thread; returns its outcome.
fn load_now(provider: &Pkcs11Provider) -> LoadOutcome {
    let cache = provider.key_cache().unwrap();
    let job = provider.key_load_job().unwrap();
    let shared = cache.begin(provider.name()).unwrap();
    let sink = LoadSink::new(&shared);
    let result = job.run(&sink);
    shared.finish(result);
    cache.sync();
    shared.outcome().unwrap().0
}

fn cached(provider: &Pkcs11Provider) -> Vec<KeyInfo> {
    by_handle(provider.key_cache().unwrap().view().keys)
}

fn populated() -> (std::rc::Rc<FakeBackend>, Pkcs11Provider) {
    let (backend, provider) = logged_in();
    provider.import_key(&aes(1), "k1", None, None).unwrap();
    provider.import_key(&aes(2), "k2", None, None).unwrap();
    provider.generate_key(&ec_pair("pair")).unwrap();
    (backend, provider)
}

#[test]
fn load_lists_exactly_what_list_keys_lists() {
    let (_backend, provider) = populated();
    assert_eq!(load_now(&provider), LoadOutcome::Complete);
    let status = provider.key_cache().unwrap().status();
    assert_eq!(status.state, CacheState::Complete);
    assert_eq!(status.count, 4);
    assert_eq!(cached(&provider), by_handle(provider.list_keys().unwrap()));
}

#[test]
fn load_job_needs_a_login() {
    let backend = std::rc::Rc::new(FakeBackend::new());
    let provider = provider_over(&backend);
    let err = provider.key_load_job().unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
}

#[test]
fn loader_session_failure_is_translated() {
    let (backend, provider) = populated();
    backend.fail_always("loader_session", rv::CKR_DEVICE_ERROR);
    match load_now(&provider) {
        LoadOutcome::Failed(err) => assert!(err.message.contains("CKR_DEVICE_ERROR"), "{err:?}"),
        other => panic!("unexpected outcome {other:?}"),
    }
    let status = provider.key_cache().unwrap().status();
    assert_eq!(status.state, CacheState::Partial);
    assert_eq!(status.count, 0);
    assert!(status.last_error.is_some());
}

#[test]
fn a_stopped_load_reads_nothing_more() {
    let (_backend, provider) = populated();
    let cache = provider.key_cache().unwrap();
    let job = provider.key_load_job().unwrap();
    let shared = cache.begin(provider.name()).unwrap();
    shared.stop();
    let result = job.run(&LoadSink::new(&shared));
    shared.finish(result);
    assert_eq!(shared.outcome().unwrap().0, LoadOutcome::Stopped);
    assert_eq!(cache.status().state, CacheState::Partial);
    assert_eq!(cache.status().count, 0);
}

#[test]
fn own_changes_patch_the_cache_in_place() {
    let (_backend, provider) = populated();
    load_now(&provider);
    let added = provider.import_key(&aes(3), "k3", None, None).unwrap();
    assert!(cached(&provider).iter().any(|k| k.handle == added.handle));
    provider.generate_key(&ec_pair("pair2")).unwrap();
    let k1 = provider.find_key(&KeySelector::label("k1")).unwrap();
    provider.delete_key(&k1).unwrap();
    let cache = provider.key_cache().unwrap();
    assert_eq!(cache.status().state, CacheState::Complete);
    assert_eq!(cached(&provider), by_handle(provider.list_keys().unwrap()));
}

#[test]
fn logout_drops_the_cache() {
    let (_backend, provider) = populated();
    load_now(&provider);
    provider.logout().unwrap();
    let cache = provider.key_cache().unwrap();
    assert_eq!(cache.status().state, CacheState::Empty);
    assert!(!cache.take_reload_request());
}

#[test]
fn session_recovery_drops_the_cache_and_asks_for_a_reload() {
    let backend = std::rc::Rc::new(FakeBackend::new());
    let provider = provider_over(&backend);
    provider
        .login(&token_at(&provider, 0), &pin(USER_PIN), true)
        .unwrap();
    provider.import_key(&aes(1), "k1", None, None).unwrap();
    load_now(&provider);
    backend.invalidate_session();
    provider.find_key(&KeySelector::label("k1")).unwrap(); // recovered
    let cache = provider.key_cache().unwrap();
    assert_eq!(cache.status().state, CacheState::Empty);
    assert!(cache.take_reload_request());
    assert_eq!(load_now(&provider), LoadOutcome::Complete);
    assert_eq!(cache.status().count, 1);
}

#[test]
fn find_objects_searches_by_label_and_id() {
    let (_backend, provider) = populated();
    let pair = provider.find_objects(&ObjectQuery::label("pair")).unwrap();
    assert_eq!(pair.len(), 2);
    assert!(pair.iter().all(|k| k.key_ref.label == "pair"));
    let id = pair[0].key_ref.key_id.clone().unwrap();
    let by_id = provider.find_objects(&ObjectQuery::id(id.clone())).unwrap();
    assert_eq!(by_handle(by_id), by_handle(pair.clone()));
    let public = provider
        .find_objects(&ObjectQuery::label("pair").with_class(Some(KeyClass::Public)))
        .unwrap();
    assert_eq!(public.len(), 1);
    assert_eq!(public[0].key_class, KeyClass::Public);
    assert!(
        provider
            .find_objects(&ObjectQuery::label("none"))
            .unwrap()
            .is_empty()
    );
}
