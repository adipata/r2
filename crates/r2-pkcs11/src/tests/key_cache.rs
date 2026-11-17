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

#[test]
fn pkcs11_calls_are_serialized_across_threads_and_reentrant() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::backend::raw::serialize_calls;

    let outer = serialize_calls();
    let inner = serialize_calls(); // re-entrant on this thread: no deadlock
    let entered = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&entered);
    #[allow(clippy::disallowed_methods)] // stands in for the loader thread
    let loader = std::thread::spawn(move || {
        let _calls = serialize_calls();
        flag.store(true, Ordering::SeqCst);
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(
        !entered.load(Ordering::SeqCst),
        "the loader ran during a call"
    );
    drop(inner);
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert!(!entered.load(Ordering::SeqCst), "the outer call still runs");
    drop(outer);
    loader.join().unwrap();
    assert!(entered.load(Ordering::SeqCst));
}

#[test]
fn a_busy_loader_lets_waiting_commands_go_first() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use crate::backend::raw::{serialize_calls, serialize_loader_call};

    let done = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&done);
    #[allow(clippy::disallowed_methods)] // stands in for the loader thread
    let loader = std::thread::spawn(move || {
        // back-to-back calls of 2 ms each, re-taking the lock at once
        while !stop.load(Ordering::SeqCst) {
            let _call = serialize_loader_call();
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    std::thread::sleep(Duration::from_millis(20));
    let mut worst = Duration::ZERO;
    for _ in 0..20 {
        let start = Instant::now();
        let call = serialize_calls();
        worst = worst.max(start.elapsed());
        drop(call);
        std::thread::sleep(Duration::from_millis(3));
    }
    done.store(true, Ordering::SeqCst);
    loader.join().unwrap();
    // at most the one loader call already running (2 ms), with generous scheduling slack
    assert!(
        worst < Duration::from_millis(100),
        "a command waited {worst:?}"
    );
}

#[test]
fn related_lookups_fall_back_when_the_raw_label_is_not_the_decoded_one() {
    use r2_provider::lookup::{family_candidates, find_related};

    let (backend, provider) = logged_in();
    let ul = super::ul;
    let planted = |class: u64, label: Option<&[u8]>| {
        let mut attrs = vec![
            (0x0000, ul(class)), // CKA_CLASS
            (0x0100, ul(0x1F)),  // CKA_KEY_TYPE = CKK_AES (secret) — class decides the rest
            (0x0102, vec![7]),   // CKA_ID
            (0x0161, ul(16)),    // CKA_VALUE_LEN
        ];
        if let Some(label) = label {
            attrs.push((0x0003, label.to_vec())); // CKA_LABEL
        }
        backend.plant_object(0, attrs, &[1; 16])
    };
    // raw label "k\xfe" decodes to "k": a label search for "k" cannot find it
    let bad = planted(4, Some(b"k\xfe"));
    let anchor = provider
        .list_keys()
        .unwrap()
        .into_iter()
        .find(|k| k.handle == Some(bad))
        .unwrap();
    assert_eq!(anchor.key_ref.label, "k");
    let query = ObjectQuery::label("k");
    assert!(provider.find_objects(&query).unwrap().is_empty());
    let found = find_related(&provider, &query, &anchor).unwrap();
    assert_eq!(
        found.iter().map(|k| k.handle).collect::<Vec<_>>(),
        [Some(bad)]
    );

    // no CKA_LABEL at all reads as "": the empty-label query lists and filters
    let unlabeled = planted(4, None);
    let anchor = provider
        .list_keys()
        .unwrap()
        .into_iter()
        .find(|k| k.handle == Some(unlabeled))
        .unwrap();
    assert_eq!(anchor.key_ref.label, "");
    let found = find_related(&provider, &ObjectQuery::label(""), &anchor).unwrap();
    assert!(found.iter().any(|k| k.handle == Some(unlabeled)));
    // family_candidates goes through the same fallback
    let family = family_candidates(&provider, &anchor, &[KeyClass::Secret]).unwrap();
    assert!(family.iter().any(|k| k.handle == Some(unlabeled)));
}

/// The fallback rule of `RawFns::get_attrs`: a refused batch is read one attribute at a
/// time, and the first real error of those reads is the result.
#[test]
fn a_refused_batch_is_read_one_attribute_at_a_time() {
    use std::cell::RefCell;

    use zeroize::Zeroizing;

    use crate::backend::raw::batched_or_each;
    use crate::backend::{BackendError, Ckr};

    let kinds = [3u64, 0x11, 0x161];
    let value = |byte: u8| Some(Zeroizing::new(vec![byte]));
    // the batch answered: its values are the result and nothing is read again
    let reads = batched_or_each(Some(vec![value(1), None, value(3)]), &kinds, |_| {
        panic!("no per-attribute read after a batch that answered")
    })
    .unwrap();
    assert_eq!(reads, vec![value(1), None, value(3)]);
    // the batch was refused: one read per attribute, in order, refusals kept as None
    let asked = RefCell::new(Vec::new());
    let reads = batched_or_each(None, &kinds, |kind| {
        asked.borrow_mut().push(kind);
        Ok((kind != 0x11).then(|| Zeroizing::new(vec![9])))
    })
    .unwrap();
    assert_eq!(*asked.borrow(), kinds);
    assert_eq!(reads, vec![value(9), None, value(9)]);
    // a real error of a per-attribute read surfaces
    let err = batched_or_each(None, &kinds, |_| {
        Err(BackendError::Ckr(Ckr {
            code: rv::CKR_OBJECT_HANDLE_INVALID,
            function: "C_GetAttributeValue",
        }))
    })
    .unwrap_err();
    assert_eq!(
        crate::ckr::code_of(&err),
        Some(rv::CKR_OBJECT_HANDLE_INVALID)
    );
}

/// The batched C_GetAttributeValue of RawFns (the loader's and `key info`'s read) against
/// a real module: every attribute readable; a sensitive CKA_VALUE refused inside the batch
/// (its entry is None, the others are read); and a batch the token refuses as a whole (a
/// handle that names no object), which falls back to per-attribute reads and surfaces
/// their error.
#[cfg(feature = "softhsm")]
#[test]
fn softhsm_batched_attribute_reads_and_their_fallback() {
    use std::collections::BTreeMap;

    use r2_config::model::Pkcs11InstanceConfig;
    use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
    use r2_testkit::softhsm::{softhsm_token, unique_label};

    let _lock = r2_testkit::global_state_lock();
    let token = softhsm_token();
    let mut config = Pkcs11InstanceConfig::new("softhsm", token.module_path.clone());
    config.slot = Some(token.slot);
    config.token_label = Some(token.token_label.clone());
    let provider = Pkcs11Provider::new("softhsm", config, BTreeMap::new(), Default::default());
    let info = provider
        .list_tokens()
        .unwrap()
        .into_iter()
        .find(|t| t.label == token.token_label)
        .unwrap();
    provider.login(&info, &pin(&token.user_pin), false).unwrap();
    let flag =
        |name: &str, value: bool| TemplateAttr::new(name, AttrKind::Bool, AttrValue::Bool(value));
    let generate = |sensitive: bool| {
        let label = unique_label();
        let mut request = GenerateRequest::new(KeyAlgorithm::Aes, label.as_str());
        request.size_bits = Some(128);
        request.template = Some(KeyTemplate::new(vec![
            flag("CKA_TOKEN", false),
            flag("CKA_SENSITIVE", sensitive),
            flag("CKA_EXTRACTABLE", !sensitive),
        ]));
        (provider.generate_key(&request).unwrap(), label)
    };
    const CKA_LABEL: u64 = 0x03;
    const CKA_VALUE: u64 = 0x11;
    const CKA_VALUE_LEN: u64 = 0x161;
    let kinds = [CKA_LABEL, CKA_VALUE, CKA_VALUE_LEN];

    let (open, open_label) = generate(false);
    let reads = provider
        .backend()
        .get_attrs(open.handle.unwrap(), &kinds)
        .unwrap();
    assert_eq!(
        reads[0].as_deref().map(|v| v.as_slice()),
        Some(open_label.as_str().as_bytes())
    );
    assert_eq!(reads[1].as_ref().map(|v| v.len()), Some(16));
    assert!(reads[2].is_some());

    let (locked, locked_label) = generate(true);
    let reads = provider
        .backend()
        .get_attrs(locked.handle.unwrap(), &kinds)
        .unwrap();
    assert_eq!(
        reads[0].as_deref().map(|v| v.as_slice()),
        Some(locked_label.as_str().as_bytes())
    );
    assert!(reads[1].is_none(), "a sensitive CKA_VALUE is refused");
    assert!(reads[2].is_some());

    let err = provider
        .backend()
        .get_attrs(0x7fff_fff0, &kinds)
        .unwrap_err();
    assert_eq!(
        crate::ckr::code_of(&err),
        Some(rv::CKR_OBJECT_HANDLE_INVALID)
    );
    provider.shutdown().unwrap();
}
