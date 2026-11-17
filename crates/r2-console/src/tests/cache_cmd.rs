// The key cache in the console (spec §5.19, r2 addition): `keys` lists from the cache and
// waits for a running load, Tab completes from the cache without waiting, the `cache`
// command, and loading at login (`login --no-cache`, `cache.on_login`,
// `providers.pkcs11[].cache_on_login`). FakeProvider `.with_key_cache()` / LoadGate.
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use r2_core::error::ErrorKind;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_provider::Provider;
use r2_provider::cache::CacheState;
use r2_testkit::{FakeProvider, LoadGate, ScriptedIo};

use super::keys_cmd_support::{calls_of, ctx_with, registry_of};
use crate::completer::complete_refs;
use crate::context::AppContext;
use crate::testing::{make_config, run_line};

fn aes(byte: u8) -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![byte; 16])
}

fn cached_hsm(labels: &[&str]) -> Rc<FakeProvider> {
    with_keys(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .with_key_cache(),
        labels,
    )
}

fn with_keys(provider: FakeProvider, labels: &[&str]) -> Rc<FakeProvider> {
    for (at, label) in labels.iter().enumerate() {
        provider
            .import_key(&aes(u8::try_from(at).unwrap()), label, None, None)
            .unwrap();
    }
    Rc::new(provider)
}

fn session(hsm: &Rc<FakeProvider>, answers: &[&str]) -> (Rc<AppContext>, Rc<ScriptedIo>) {
    let io = Rc::new(ScriptedIo::new(answers.iter().copied()));
    let registry = registry_of(&[Rc::new(FakeProvider::new("mem")), Rc::clone(hsm)]);
    (ctx_with(&io, registry, None), io)
}

/// Poll the cache (on this thread, as the REPL does) until `done`, or fail after 5 s.
fn wait_until(hsm: &FakeProvider, done: impl Fn(&r2_provider::cache::CacheStatus) -> bool) {
    let cache = hsm.key_cache().unwrap();
    let start = Instant::now();
    while !done(&cache.status()) {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            cache.status()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn loads(hsm: &FakeProvider) -> usize {
    calls_of(hsm, "key_load_job").len()
}

/// Open `gate` from another thread after a short delay (the test thread is waiting).
fn open_later(gate: &Arc<LoadGate>) {
    let gate = Arc::clone(gate);
    #[allow(clippy::disallowed_methods)] // test helper thread
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        gate.open();
    });
}

// ---- keys ----

#[test]
fn keys_on_piped_input_waits_for_the_load_and_lists_everything() {
    let hsm = cached_hsm(&["k1", "k2", "k3"]);
    let (ctx, io) = session(&hsm, &[]);
    run_line(&ctx, "keys hsm").unwrap();
    let text = io.text();
    for label in ["hsm:k1", "hsm:k2", "hsm:k3"] {
        assert!(text.contains(label), "{text}");
    }
    assert!(text.contains("found 3 keys in hsm"), "{text}");
    assert!(!text.contains("partial"), "{text}");
    assert!(!text.contains("Ctrl+C"), "{text}");
    assert_eq!(loads(&hsm), 1);
    assert_eq!(
        hsm.key_cache().unwrap().status().state,
        CacheState::Complete
    );
}

#[test]
fn a_complete_cache_is_listed_without_loading_again_and_follows_own_changes() {
    let hsm = cached_hsm(&["k1", "k2"]);
    let (ctx, io) = session(&hsm, &[]);
    run_line(&ctx, "keys hsm").unwrap();
    hsm.clear_calls();
    hsm.import_key(&aes(9), "k3", None, None).unwrap(); // patched in place
    run_line(&ctx, "keys hsm").unwrap();
    assert_eq!(loads(&hsm), 0);
    assert!(calls_of(&hsm, "list_keys").is_empty());
    assert!(io.text().contains("found 3 keys in hsm"));
}

#[test]
fn keys_live_shows_the_cache_first_then_what_loaded_while_waiting() {
    let gate = LoadGate::new(2);
    let hsm = with_keys(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .with_load_gate(Arc::clone(&gate)),
        &["k1", "k2", "k3", "k4"],
    );
    let (ctx, io) = session(&hsm, &[]);
    io.set_live_progress(true);
    run_line(&ctx, "cache hsm").unwrap();
    wait_until(&hsm, |status| status.count == 2);
    open_later(&gate);
    run_line(&ctx, "keys hsm").unwrap();
    let text = io.text();
    let first = text.find("found 2 keys in hsm (partial: hsm 2 of 4 objects loaded)");
    let more = text.find("keys (loaded while waiting)");
    let last = text
        .find("found 4 keys in hsm\n")
        .or_else(|| text.rfind("found 4 keys in hsm"));
    assert!(
        first.is_some() && more.is_some() && last.is_some(),
        "{text}"
    );
    assert!(first < more && more < last, "{text}");
    assert!(!text.contains("stopped waiting"), "{text}");
    assert_eq!(loads(&hsm), 1); // `keys` joined the running load
}

#[test]
fn ctrl_c_stops_the_waiting_but_not_the_loading() {
    let gate = LoadGate::new(1);
    let hsm = with_keys(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .with_load_gate(Arc::clone(&gate)),
        &["k1", "k2"],
    );
    let (ctx, io) = session(&hsm, &[]);
    io.set_live_progress(true);
    run_line(&ctx, "cache hsm").unwrap();
    wait_until(&hsm, |status| status.count == 1);
    r2_core::runtime::request_interrupt_on_this_thread();
    run_line(&ctx, "keys hsm").unwrap();
    r2_core::runtime::reset_interrupt();
    let text = io.text();
    assert!(text.contains("found 1 key in hsm (partial"), "{text}");
    assert!(
        text.contains("stopped waiting — the key cache keeps loading in the background"),
        "{text}"
    );
    assert!(hsm.key_cache().unwrap().is_loading());
    gate.open();
    wait_until(&hsm, |status| status.state == CacheState::Complete);
    assert_eq!(hsm.key_cache().unwrap().status().count, 2);
}

#[test]
fn a_stopped_load_keeps_its_objects_and_keys_loads_again() {
    let gate = LoadGate::new(1);
    let hsm = with_keys(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .with_load_gate(Arc::clone(&gate)),
        &["k1", "k2"],
    );
    let (ctx, io) = session(&hsm, &[]);
    run_line(&ctx, "cache hsm").unwrap();
    wait_until(&hsm, |status| status.count == 1);
    run_line(&ctx, "cache stop").unwrap();
    assert!(io.text().contains("stopping the key cache loading of hsm"));
    wait_until(&hsm, |status| status.state == CacheState::Partial);
    assert_eq!(hsm.key_cache().unwrap().status().count, 1);
    gate.open();
    run_line(&ctx, "keys hsm").unwrap(); // piped: loads again and waits
    assert_eq!(loads(&hsm), 2);
    assert!(io.text().contains("found 2 keys in hsm"));
}

#[test]
fn logout_drops_the_cache() {
    let hsm = cached_hsm(&["k1"]);
    let (ctx, _io) = session(&hsm, &[]);
    run_line(&ctx, "keys hsm").unwrap();
    run_line(&ctx, "logout hsm").unwrap();
    assert_eq!(hsm.key_cache().unwrap().status().state, CacheState::Empty);
}

// ---- Tab ----

#[test]
fn tab_completes_from_the_cache_without_waiting_and_starts_a_load() {
    let gate = LoadGate::new(0);
    let hsm = with_keys(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .with_load_gate(Arc::clone(&gate)),
        &["alpha", "beta"],
    );
    let (ctx, _io) = session(&hsm, &[]);
    // nothing cached yet: no refs (and no live listing), a load starts
    assert!(complete_refs(&ctx, "hsm:a").is_empty());
    assert!(calls_of(&hsm, "list_keys").is_empty());
    assert_eq!(loads(&hsm), 1);
    // another Tab while loading starts nothing new
    let _ = complete_refs(&ctx, "hsm:");
    assert_eq!(loads(&hsm), 1);
    gate.open();
    wait_until(&hsm, |status| status.state == CacheState::Complete);
    assert_eq!(complete_refs(&ctx, "hsm:a"), ["hsm:alpha#00000001"]);
    assert_eq!(loads(&hsm), 1);
}

// ---- cache ----

#[test]
fn cache_shows_each_providers_state() {
    let hsm = cached_hsm(&["k1", "k2"]);
    let (ctx, io) = session(&hsm, &[]);
    run_line(&ctx, "cache").unwrap();
    run_line(&ctx, "keys hsm").unwrap();
    run_line(&ctx, "cache").unwrap();
    let text = io.text();
    assert!(text.contains("key caches"), "{text}");
    assert!(text.contains("listed live"), "{text}"); // mem
    assert!(text.contains("empty"), "{text}");
    assert!(text.contains("complete"), "{text}");
}

#[test]
fn cache_provider_loads_once_at_a_time() {
    let gate = LoadGate::new(0);
    let hsm = with_keys(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .with_load_gate(Arc::clone(&gate)),
        &["k1"],
    );
    let (ctx, io) = session(&hsm, &[]);
    run_line(&ctx, "cache hsm").unwrap();
    run_line(&ctx, "cache hsm").unwrap();
    let text = io.text();
    assert!(
        text.contains(
            "loading the key cache of hsm in the background — Ctrl+G or `cache stop` stops it"
        ),
        "{text}"
    );
    assert!(
        text.contains("the key cache of hsm is already loading"),
        "{text}"
    );
    assert_eq!(loads(&hsm), 1);
    gate.open();
    wait_until(&hsm, |status| status.state == CacheState::Complete);
    run_line(&ctx, "cache stop").unwrap();
    assert!(io.text().contains("no key cache is loading"));
    run_line(&ctx, "cache hsm").unwrap(); // reload
    assert_eq!(loads(&hsm), 2);
}

#[test]
fn cache_errors() {
    let hsm = Rc::new(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .starting_logged_out()
            .with_key_cache(),
    );
    let (ctx, _io) = session(&hsm, &[]);
    let err = run_line(&ctx, "cache mem").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(err.message, "mem keeps no key cache");
    let err = run_line(&ctx, "cache hsm").unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    let err = run_line(&ctx, "cache nope").unwrap_err();
    assert_eq!(err.kind, ErrorKind::ProviderNotFound);
    let err = run_line(&ctx, "cache hsm extra").unwrap_err();
    assert_eq!(err.message, "unexpected argument 'extra'");
}

#[test]
fn cache_completes_provider_names_and_stop() {
    let hsm = cached_hsm(&[]);
    let (ctx, _io) = session(&hsm, &[]);
    let commands = crate::commands::all_commands().unwrap();
    let got = commands["cache"].complete(&ctx, &["cache".to_owned()], "");
    assert!(
        got.contains(&"hsm".to_owned()) && got.contains(&"stop".to_owned()),
        "{got:?}"
    );
}

// ---- login ----

fn logged_out_cached() -> Rc<FakeProvider> {
    with_keys(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .starting_logged_out()
            .with_key_cache(),
        &[],
    )
}

fn login(hsm: &Rc<FakeProvider>, line: &str, config: Option<&str>) {
    let io = Rc::new(ScriptedIo::new(["1234"]));
    let registry = registry_of(&[Rc::clone(hsm)]);
    run_line(
        &ctx_with(&io, registry, config.map(|c| make_config(Some(c)))),
        line,
    )
    .unwrap();
}

#[test]
fn login_starts_loading_by_default() {
    let hsm = logged_out_cached();
    login(&hsm, "login hsm", None);
    assert_eq!(loads(&hsm), 1);
}

#[test]
fn login_no_cache_skips_loading() {
    let hsm = logged_out_cached();
    login(&hsm, "login hsm --no-cache", None);
    assert_eq!(loads(&hsm), 0);
    assert_eq!(hsm.key_cache().unwrap().status().state, CacheState::Empty);
}

#[test]
fn cache_on_login_config_turns_it_off_globally_and_per_hsm() {
    let hsm = logged_out_cached();
    login(&hsm, "login hsm", Some("cache:\n  on_login: false\n"));
    assert_eq!(loads(&hsm), 0);

    let hsm = logged_out_cached();
    login(
        &hsm,
        "login hsm",
        Some(
            "providers:\n  pkcs11:\n    - name: hsm\n      library: /x.so\n      cache_on_login: false\n",
        ),
    );
    assert_eq!(loads(&hsm), 0);

    let hsm = logged_out_cached();
    login(
        &hsm,
        "login hsm",
        Some(
            "cache:\n  on_login: false\nproviders:\n  pkcs11:\n    - name: hsm\n      library: /x.so\n      cache_on_login: true\n",
        ),
    );
    assert_eq!(loads(&hsm), 1);
}
