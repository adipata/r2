// KeyCache (spec §5.19, r2 addition): load lifecycle, partial data, in-place patches,
// clearing, and the targeted ObjectQuery filter.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::collections::BTreeMap;
use std::sync::Arc;

use r2_core::error::ConsoleError;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyRef};
use r2_provider::ObjectQuery;
use r2_provider::cache::{CacheState, KeyCache, KeyLoadJob, LoadOutcome, LoadSink};

fn info(label: &str, class: KeyClass, handle: u64) -> KeyInfo {
    KeyInfo {
        key_ref: KeyRef::new("hsm", label, Some(vec![handle as u8])),
        key_class: class,
        algorithm: KeyAlgorithm::Aes,
        size_bits: Some(128),
        curve: None,
        exportable: false,
        attributes: BTreeMap::new(),
        handle: Some(handle),
    }
}

fn labels(cache: &KeyCache) -> Vec<String> {
    cache
        .view()
        .keys
        .into_iter()
        .map(|k| k.key_ref.label)
        .collect()
}

/// Run a load synchronously on this thread.
fn load(cache: &KeyCache, items: Vec<KeyInfo>, stop_after: Option<usize>) {
    let shared = cache.begin("hsm").expect("no load running");
    let sink = LoadSink::new(&shared);
    let job = KeyLoadJob::new(move |sink: &LoadSink<'_>| {
        sink.set_total(items.len());
        for (at, item) in items.into_iter().enumerate() {
            if stop_after == Some(at) {
                return Ok(());
            }
            sink.push(item);
        }
        Ok(())
    });
    let result = job.run(&sink);
    if stop_after.is_some() {
        shared.stop();
    }
    shared.finish(result);
    cache.sync();
}

#[test]
fn new_cache_is_empty() {
    let cache = KeyCache::new();
    let status = cache.status();
    assert_eq!(status.state, CacheState::Empty);
    assert_eq!(status.count, 0);
    assert!(!cache.is_active());
    assert!(cache.view().keys.is_empty());
}

#[test]
fn complete_load_serves_objects_in_class_order() {
    let cache = KeyCache::new();
    load(
        &cache,
        vec![
            info("cert", KeyClass::Certificate, 3),
            info("aes", KeyClass::Secret, 1),
            info("aes2", KeyClass::Secret, 2),
        ],
        None,
    );
    let status = cache.status();
    assert_eq!(status.state, CacheState::Complete);
    assert_eq!(status.count, 3);
    let classes: Vec<KeyClass> = cache.view().keys.iter().map(|k| k.key_class).collect();
    let rank = |c: &KeyClass| KeyClass::ALL.iter().position(|x| x == c).unwrap();
    assert!(classes.windows(2).all(|w| rank(&w[0]) <= rank(&w[1])));
    // token order kept within a class
    let order = labels(&cache);
    let at = |l: &str| order.iter().position(|x| x == l).unwrap();
    assert!(at("aes") < at("aes2"));
}

#[test]
fn only_one_load_at_a_time() {
    let cache = KeyCache::new();
    let first = cache.begin("hsm").unwrap();
    assert!(cache.is_loading());
    assert_eq!(cache.status().state, CacheState::Loading);
    assert!(cache.begin("hsm").is_none());
    first.finish(Ok(()));
    assert!(!cache.is_loading());
    assert!(cache.begin("hsm").is_some());
}

#[test]
fn stopped_load_keeps_partial_data() {
    let cache = KeyCache::new();
    load(
        &cache,
        vec![
            info("a", KeyClass::Secret, 1),
            info("b", KeyClass::Secret, 2),
            info("c", KeyClass::Secret, 3),
        ],
        Some(2),
    );
    let status = cache.status();
    assert_eq!(status.state, CacheState::Partial);
    assert_eq!(status.count, 2);
    assert_eq!(status.last_error, None);
    assert_eq!(labels(&cache), ["a", "b"]);
}

#[test]
fn failed_load_is_partial_with_the_error() {
    let cache = KeyCache::new();
    let shared = cache.begin("hsm").unwrap();
    let sink = LoadSink::new(&shared);
    sink.push(info("a", KeyClass::Secret, 1));
    shared.finish(Err(ConsoleError::generic("CKR_DEVICE_ERROR")));
    let status = cache.status();
    assert_eq!(status.state, CacheState::Partial);
    assert_eq!(status.count, 1);
    assert_eq!(status.last_error.as_deref(), Some("CKR_DEVICE_ERROR"));
    match shared.outcome() {
        Some((LoadOutcome::Failed(err), _)) => assert_eq!(err.message, "CKR_DEVICE_ERROR"),
        other => panic!("unexpected outcome {other:?}"),
    }
}

#[test]
fn reload_keeps_old_data_readable_until_complete() {
    let cache = KeyCache::new();
    load(
        &cache,
        vec![
            info("a", KeyClass::Secret, 1),
            info("b", KeyClass::Secret, 2),
        ],
        None,
    );
    let shared = cache.begin("hsm").unwrap();
    let sink = LoadSink::new(&shared);
    sink.push(info("a2", KeyClass::Secret, 1)); // handle 1 re-read with a new label
    // while loading: the new read of handle 1 plus the old object it has not reached
    assert_eq!(cache.status().state, CacheState::Loading);
    let mut seen = labels(&cache);
    seen.sort();
    assert_eq!(seen, ["a2", "b"]);
    shared.finish(Ok(()));
    // complete: the new load replaces the old one (b is gone from the token)
    assert_eq!(labels(&cache), ["a2"]);
    assert_eq!(cache.status().state, CacheState::Complete);
}

#[test]
fn patches_apply_in_place() {
    let cache = KeyCache::new();
    // an inactive cache ignores patches
    cache.upsert(info("x", KeyClass::Secret, 9));
    assert_eq!(cache.status().count, 0);

    load(&cache, vec![info("a", KeyClass::Secret, 1)], None);
    cache.upsert(info("new", KeyClass::Secret, 5));
    cache.upsert(info("renamed", KeyClass::Secret, 1));
    let mut seen = labels(&cache);
    seen.sort();
    assert_eq!(seen, ["new", "renamed"]);
    assert_eq!(cache.status().state, CacheState::Complete);
    cache.remove(5);
    assert_eq!(labels(&cache), ["renamed"]);
}

#[test]
fn patches_during_a_load_win_over_the_loaders_older_reads() {
    let cache = KeyCache::new();
    let shared = cache.begin("hsm").unwrap();
    cache.upsert(info("patched", KeyClass::Secret, 1));
    cache.remove(2);
    let sink = LoadSink::new(&shared);
    sink.push(info("stale", KeyClass::Secret, 1));
    sink.push(info("deleted", KeyClass::Secret, 2));
    sink.push(info("other", KeyClass::Secret, 3));
    shared.finish(Ok(()));
    let mut seen = labels(&cache);
    seen.sort();
    assert_eq!(seen, ["other", "patched"]);
}

#[test]
fn clear_drops_everything_and_stops_the_load() {
    let cache = KeyCache::new();
    load(&cache, vec![info("a", KeyClass::Secret, 1)], None);
    let shared = cache.begin("hsm").unwrap();
    cache.clear();
    assert!(shared.stop_requested());
    assert_eq!(cache.status().state, CacheState::Empty);
    assert!(!cache.is_active());
    // the abandoned load's late results are ignored, and nobody reports it
    LoadSink::new(&shared).push(info("late", KeyClass::Secret, 2));
    shared.finish(Ok(()));
    assert!(!shared.claim_report());
    assert!(cache.view().keys.is_empty());
    assert!(!cache.take_reload_request());
}

#[test]
fn invalidate_and_reload_asks_once_only_when_it_held_data() {
    let cache = KeyCache::new();
    cache.invalidate_and_reload();
    assert!(!cache.take_reload_request());

    load(&cache, vec![info("a", KeyClass::Secret, 1)], None);
    cache.invalidate_and_reload();
    assert_eq!(cache.status().state, CacheState::Empty);
    assert!(cache.take_reload_request());
    assert!(!cache.take_reload_request());
}

#[test]
fn stop_requests_and_progress() {
    let cache = KeyCache::new();
    assert!(!cache.stop());
    let shared = cache.begin("hsm").unwrap();
    let sink = LoadSink::new(&shared);
    assert_eq!(shared.progress(), (0, None));
    sink.set_total(10);
    sink.push(info("a", KeyClass::Secret, 1));
    sink.skip();
    assert_eq!(shared.progress(), (2, Some(10)));
    assert_eq!(cache.status().progress, Some((2, Some(10))));
    assert!(!sink.cancelled());
    assert!(cache.stop());
    assert!(sink.cancelled());
    assert!(!shared.is_finished());
    shared.finish(Ok(()));
    assert!(shared.is_finished());
    assert!(matches!(shared.outcome(), Some((LoadOutcome::Stopped, _))));
    // reported once
    assert!(shared.claim_report());
    assert!(!shared.claim_report());
}

#[test]
fn object_query_matches_every_set_field() {
    let key = info("k", KeyClass::Secret, 7);
    assert!(ObjectQuery::default().matches(&key));
    assert!(ObjectQuery::label("k").matches(&key));
    assert!(!ObjectQuery::label("j").matches(&key));
    assert!(ObjectQuery::id(vec![7]).matches(&key));
    assert!(!ObjectQuery::id(vec![8]).matches(&key));
    assert!(
        ObjectQuery::label("k")
            .with_id(Some(vec![7]))
            .with_class(Some(KeyClass::Secret))
            .matches(&key)
    );
    assert!(
        !ObjectQuery::label("k")
            .with_class(Some(KeyClass::Public))
            .matches(&key)
    );
    let mut no_id = key.clone();
    no_id.key_ref.key_id = None;
    assert!(!ObjectQuery::id(vec![7]).matches(&no_id));
}

#[test]
fn a_new_load_lets_a_stopping_one_go() {
    let cache = KeyCache::new();
    let old = cache.begin("hsm").unwrap();
    LoadSink::new(&old).push(info("a", KeyClass::Secret, 1));
    assert!(cache.begin("hsm").is_none()); // still running, not stopping
    old.stop();
    // the old load is still inside a call: a new one starts anyway, keeping what it read
    let new = cache.begin("hsm").unwrap();
    assert!(!Arc::ptr_eq(&old, &new));
    assert_eq!(labels(&cache), ["a"]);
    LoadSink::new(&old).push(info("late", KeyClass::Secret, 2)); // ignored
    old.finish(Ok(()));
    LoadSink::new(&new).push(info("b", KeyClass::Secret, 3));
    new.finish(Ok(()));
    assert_eq!(labels(&cache), ["b"]);
    assert_eq!(cache.status().state, CacheState::Complete);
}

#[test]
fn stopped_and_failed_are_told_apart() {
    let cache = KeyCache::new();
    load(&cache, vec![info("a", KeyClass::Secret, 1)], Some(0));
    assert!(cache.stopped() && !cache.failed());
    let shared = cache.begin("hsm").unwrap();
    shared.finish(Err(ConsoleError::generic("CKR_DEVICE_ERROR")));
    assert!(cache.failed() && !cache.stopped());
}
