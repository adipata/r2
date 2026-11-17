// Key cache runtime (spec §5.19, r2 addition): starts the loader threads, keeps the list of
// running loads (read by the prompt indicator), and turns finished loads into one-line
// notices. Everything here runs on the REPL thread except the loader threads themselves,
// which only ever see their `LoadShared`.
use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Instant;

use r2_core::error::ConsoleError;
use r2_core::io::Renderable;
use r2_provider::cache::{CacheState, KeyLoadJob, LoadOutcome, LoadShared, LoadSink};
use r2_provider::{AuthState, Provider};

use crate::context::AppContext;

thread_local! {
    /// The loads started on this (REPL) thread that have not been reported yet.
    static LOADS: RefCell<Vec<Arc<LoadShared>>> = const { RefCell::new(Vec::new()) };
    /// When the indicator's spinner started (frame clock).
    static CLOCK: Instant = Instant::now();
}

/// The stop key, as the indicator and the messages name it.
pub(crate) const STOP_KEY: &str = "Ctrl+G";

/// What `start` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Start {
    Started,
    /// A load of this provider was already running (loading happens once at a time).
    AlreadyLoading,
    /// The provider keeps no cache (memory).
    NoCache,
}

fn loads() -> Vec<Arc<LoadShared>> {
    LOADS
        .try_with(|loads| loads.borrow().clone())
        .unwrap_or_default()
}

/// Start loading `provider`'s cache in the background. AuthRequired while logged out.
pub(crate) fn start(provider: &dyn Provider) -> r2_core::Result<Start> {
    let Some(cache) = provider.key_cache() else {
        return Ok(Start::NoCache);
    };
    if cache.is_loading() {
        return Ok(Start::AlreadyLoading);
    }
    let job = provider.key_load_job()?;
    let Some(load) = cache.begin(provider.name()) else {
        return Ok(Start::AlreadyLoading);
    };
    tracing::info!(target: "r2::cache", "{}: key cache loading started", provider.name());
    spawn(Arc::clone(&load), job);
    let _ = LOADS.try_with(|loads| loads.borrow_mut().push(load));
    Ok(Start::Started)
}

/// The text of a panic payload.
fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "panic".to_owned()
    }
}

/// The loader thread (spec §6 exception: one per running load; it touches nothing but its
/// `LoadShared` and its own PKCS#11 session).
fn spawn(load: Arc<LoadShared>, job: KeyLoadJob) {
    let thread_load = Arc::clone(&load);
    #[allow(clippy::disallowed_methods)] // the key cache loader thread (spec §5.19, §6)
    let spawned = std::thread::Builder::new()
        .name(format!("r2-cache-{}", load.provider()))
        .spawn(move || {
            let sink = LoadSink::new(&thread_load);
            let result = catch_unwind(AssertUnwindSafe(|| job.run(&sink))).unwrap_or_else(|p| {
                Err(ConsoleError::generic(format!(
                    "the key cache loader crashed: {}",
                    panic_text(p.as_ref())
                )))
            });
            if let Err(err) = &result {
                tracing::info!(
                    target: "r2::cache",
                    "{}: key cache loading failed: {}",
                    thread_load.provider(),
                    err.message
                );
            }
            thread_load.finish(result);
        });
    if let Err(err) = spawned {
        load.finish(Err(ConsoleError::generic(format!(
            "cannot start the key cache loader: {err}"
        ))));
    }
}

/// `keys` / Tab: start a load unless the cache is complete or already loading (a stopped or
/// failed cache loads again). Failures only log — the caller falls back or shows what it
/// has.
pub(crate) fn ensure_loading(provider: &dyn Provider) {
    let Some(cache) = provider.key_cache() else {
        return;
    };
    if provider.status().auth != AuthState::LoggedIn {
        return;
    }
    let state = cache.status().state;
    if matches!(state, CacheState::Complete | CacheState::Loading) {
        return;
    }
    if let Err(err) = start(provider) {
        tracing::info!(
            target: "r2::cache",
            "{}: cannot start key cache loading: {}",
            provider.name(),
            err.message
        );
    }
}

/// Stop every running load (Ctrl+G, `cache stop`, exit). Returns the providers stopped.
pub(crate) fn stop_all() -> Vec<String> {
    let mut stopped = Vec::new();
    for load in loads() {
        if !load.is_finished() && !load.stop_requested() {
            load.stop();
            stopped.push(load.provider().to_owned());
        }
    }
    stopped
}

/// Thousands are not grouped (the `keys` count line never groups either).
fn progress_text(load: &LoadShared) -> String {
    match load.progress() {
        (loaded, Some(total)) => format!("{loaded} of {total}"),
        (_, None) => "counting objects".to_owned(),
    }
}

/// The one-line notice of a finished load.
fn notice(load: &LoadShared) -> Option<(String, bool)> {
    let (outcome, elapsed) = load.outcome()?;
    let secs = elapsed.as_secs_f64();
    let name = load.provider();
    let (loaded, total) = load.progress();
    let noun = |n: usize| if n == 1 { "object" } else { "objects" };
    Some(match outcome {
        LoadOutcome::Complete => (
            format!(
                "cache: {name}: {loaded} {} loaded in {secs:.1} s",
                noun(loaded)
            ),
            false,
        ),
        LoadOutcome::Stopped => (
            match total {
                Some(total) => {
                    format!("cache: {name}: loading stopped ({loaded} of {total} objects loaded)")
                }
                None => format!("cache: {name}: loading stopped"),
            },
            false,
        ),
        LoadOutcome::Failed(err) => (
            format!(
                "cache: {name}: loading failed: {} ({})",
                err.message,
                progress_text(load)
            ),
            true,
        ),
    })
}

/// Take the notices of the loads that ended; with `failures_only` the others are dropped
/// silently (piped input: scripts get no timing-dependent lines).
pub(crate) fn take_notices(failures_only: bool) -> Vec<String> {
    let finished: Vec<Arc<LoadShared>> = LOADS
        .try_with(|loads| {
            let mut loads = loads.borrow_mut();
            let (done, running): (Vec<_>, Vec<_>) =
                loads.drain(..).partition(|load| load.is_finished());
            *loads = running;
            done
        })
        .unwrap_or_default();
    finished
        .iter()
        .filter(|load| load.claim_report())
        .filter_map(|load| notice(load))
        .filter(|(_, failure)| *failure || !failures_only)
        .map(|(text, _)| text)
        .collect()
}

/// Mark `provider`'s finished load as reported (`keys` waited for it and showed the
/// result, so the notice would only repeat it).
pub(crate) fn mark_reported(load: &LoadShared) {
    load.claim_report();
}

/// Before each prompt: settle the caches, start the reloads session recovery asked for,
/// and print the notices of loads that ended while a command ran.
pub(crate) fn service(ctx: &AppContext) {
    for provider in ctx.providers.all() {
        if let Some(cache) = provider.key_cache() {
            cache.sync();
            if cache.take_reload_request() && provider.status().auth == AuthState::LoggedIn {
                ensure_loading(provider.as_ref());
            }
        }
    }
    for line in take_notices(!ctx.io.live_progress()) {
        ctx.io.print(Renderable::Text(line));
    }
}

const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// The prompt indicator: "⠹ cache hsm 120/4800 · Ctrl+G stops", or "" when nothing loads.
/// The count is padded to the total's width so the text keeps its width while it runs.
pub(crate) fn indicator_text() -> String {
    let running: Vec<Arc<LoadShared>> = loads()
        .into_iter()
        .filter(|load| !load.is_finished())
        .collect();
    if running.is_empty() {
        return String::new();
    }
    let millis = CLOCK
        .try_with(|clock| clock.elapsed().as_millis())
        .unwrap_or(0);
    let frame = FRAMES[usize::try_from(millis / 100).unwrap_or(0) % FRAMES.len()];
    let parts: Vec<String> = running
        .iter()
        .map(|load| {
            let name = load.provider();
            if load.stop_requested() {
                return format!("{name} stopping");
            }
            match load.progress() {
                (loaded, Some(total)) => {
                    let width = total.to_string().len();
                    format!("{name} {loaded:>width$}/{total}")
                }
                (_, None) => format!("{name} counting"),
            }
        })
        .collect();
    format!("{frame} cache {} · {STOP_KEY} stops", parts.join(", "))
}
