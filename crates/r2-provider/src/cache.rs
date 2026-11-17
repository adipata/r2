// The key cache (spec §5.19, r2 addition): an in-memory snapshot of a provider's objects
// that `keys` and ref completion read instead of listing the whole token, filled by a
// background loader thread and patched in place by the provider's own changes.
//
// Threads: `KeyCache` lives in the (single-threaded) provider and is only touched on the
// REPL thread. The loader thread sees nothing but `LoadShared` (atomics + mutexes) through
// a `LoadSink`; it never touches a provider. Results reach the cache when the REPL thread
// next looks at it (`KeyCache::sync`, run by every accessor).
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{KeyClass, KeyInfo};

/// How a load ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadOutcome {
    /// Every object was read.
    Complete,
    /// Stopped by the operator (Ctrl+G / `cache stop`) or because the cache was dropped.
    Stopped,
    /// The loader hit an error; the objects read before it are kept.
    Failed(ConsoleError),
}

const UNKNOWN: usize = usize::MAX;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // a poisoned lock only means a loader thread panicked mid-push: the data is still usable
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The state one load shares between the loader thread and the REPL thread.
#[derive(Debug)]
pub struct LoadShared {
    provider: String,
    started: Instant,
    cancel: AtomicBool,
    total: AtomicUsize,
    loaded: AtomicUsize,
    inbox: Mutex<Vec<KeyInfo>>,
    outcome: Mutex<Option<(LoadOutcome, Duration)>>,
    finished: AtomicBool,
    /// Set by the console once it reported (or deliberately skipped) the end of this load.
    reported: AtomicBool,
}

impl LoadShared {
    fn new(provider: &str) -> Self {
        Self {
            provider: provider.to_owned(),
            started: Instant::now(),
            cancel: AtomicBool::new(false),
            total: AtomicUsize::new(UNKNOWN),
            loaded: AtomicUsize::new(0),
            inbox: Mutex::new(Vec::new()),
            outcome: Mutex::new(None),
            finished: AtomicBool::new(false),
            reported: AtomicBool::new(false),
        }
    }
    /// The provider instance name.
    pub fn provider(&self) -> &str {
        &self.provider
    }
    /// (objects read so far, total objects once the loader has counted them).
    pub fn progress(&self) -> (usize, Option<usize>) {
        let total = self.total.load(Ordering::Relaxed);
        (
            self.loaded.load(Ordering::Relaxed),
            (total != UNKNOWN).then_some(total),
        )
    }
    /// Ask the loader to stop after the object it is reading.
    pub fn stop(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
    pub fn stop_requested(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
    /// True once the loader thread has ended (`finish` ran).
    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
    /// The outcome and duration, once finished.
    pub fn outcome(&self) -> Option<(LoadOutcome, Duration)> {
        lock(&self.outcome).clone()
    }
    /// Record how the job ended (called once by the thread that ran it). A job that
    /// returned Ok after a stop request counts as stopped.
    pub fn finish(&self, result: Result<()>) {
        let outcome = match result {
            Ok(()) if self.stop_requested() => LoadOutcome::Stopped,
            Ok(()) => LoadOutcome::Complete,
            Err(err) => LoadOutcome::Failed(err),
        };
        *lock(&self.outcome) = Some((outcome, self.started.elapsed()));
        self.finished.store(true, Ordering::Release);
    }
    /// Claim the end-of-load report: true for the first caller only.
    pub fn claim_report(&self) -> bool {
        !self.reported.swap(true, Ordering::AcqRel)
    }
    fn take_inbox(&self) -> Vec<KeyInfo> {
        std::mem::take(&mut *lock(&self.inbox))
    }
}

/// The loader job's handle on its load (loader thread side).
pub struct LoadSink<'a> {
    shared: &'a LoadShared,
}

impl<'a> LoadSink<'a> {
    pub fn new(shared: &'a LoadShared) -> Self {
        Self { shared }
    }
    /// The number of objects the job is going to read.
    pub fn set_total(&self, total: usize) {
        self.shared.total.store(total, Ordering::Relaxed);
    }
    /// One object read.
    pub fn push(&self, info: KeyInfo) {
        lock(&self.shared.inbox).push(info);
        self.shared.loaded.fetch_add(1, Ordering::Relaxed);
    }
    /// One object read that r2 does not list (unmodelled, or gone meanwhile).
    pub fn skip(&self) {
        self.shared.loaded.fetch_add(1, Ordering::Relaxed);
    }
    /// True once a stop was requested: the job returns Ok(()) as soon as it can.
    pub fn cancelled(&self) -> bool {
        self.shared.stop_requested()
    }
}

type JobFn = Box<dyn for<'a, 'b> FnOnce(&'a LoadSink<'b>) -> Result<()> + Send>;

/// A provider's cache loader: runs on the loader thread (hence `Send`), lists every object
/// in `list_keys` order with `list_keys`' snapshots, on a session of its own.
pub struct KeyLoadJob(JobFn);

impl KeyLoadJob {
    pub fn new(
        job: impl for<'a, 'b> FnOnce(&'a LoadSink<'b>) -> Result<()> + Send + 'static,
    ) -> Self {
        Self(Box::new(job))
    }
    pub fn run(self, sink: &LoadSink<'_>) -> Result<()> {
        (self.0)(sink)
    }
}

impl std::fmt::Debug for KeyLoadJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyLoadJob")
    }
}

/// What the cache holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheState {
    /// Nothing loaded (never loaded, or dropped by logout / session recovery).
    Empty,
    /// A load is running (the view holds what is known so far).
    Loading,
    /// Every object was loaded; kept current by in-place patches.
    Complete,
    /// A load was stopped or failed; the objects read before are kept.
    Partial,
}

/// The cache state with its numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheStatus {
    pub state: CacheState,
    /// Objects in the view.
    pub count: usize,
    /// While loading: (objects read, total once counted).
    pub progress: Option<(usize, Option<usize>)>,
    /// Why the last load failed (Partial after a failure).
    pub last_error: Option<String>,
}

/// The cached objects (in `list_keys` order: class pass, then token order) and the status.
#[derive(Clone, Debug)]
pub struct CacheView {
    pub keys: Vec<KeyInfo>,
    pub status: CacheStatus,
}

/// Objects keyed by handle, in insertion order.
#[derive(Default)]
struct Entries {
    items: Vec<KeyInfo>,
    index: HashMap<u64, usize>,
}

impl Entries {
    fn key(info: &KeyInfo) -> Option<u64> {
        info.handle
    }
    fn upsert(&mut self, info: KeyInfo) {
        match Self::key(&info).and_then(|h| self.index.get(&h).copied()) {
            Some(at) => self.items[at] = info,
            None => {
                if let Some(handle) = Self::key(&info) {
                    self.index.insert(handle, self.items.len());
                }
                self.items.push(info);
            }
        }
    }
    fn remove(&mut self, handle: u64) {
        if self.index.remove(&handle).is_some() {
            self.items.retain(|info| info.handle != Some(handle));
            self.reindex();
        }
    }
    fn contains(&self, handle: u64) -> bool {
        self.index.contains_key(&handle)
    }
    fn reindex(&mut self) {
        self.index = self
            .items
            .iter()
            .enumerate()
            .filter_map(|(at, info)| info.handle.map(|h| (h, at)))
            .collect();
    }
    fn len(&self) -> usize {
        self.items.len()
    }
}

#[derive(Default)]
struct Inner {
    /// The served objects (the last complete or partial load, patched).
    entries: Entries,
    /// The running load's objects so far.
    incoming: Entries,
    loading: Option<Arc<LoadShared>>,
    /// Handles patched during the running load: its (older) reads of them are ignored.
    touched: HashSet<u64>,
    complete: bool,
    has_data: bool,
    last_error: Option<String>,
    reload_requested: bool,
}

fn class_rank(class: KeyClass) -> usize {
    KeyClass::ALL
        .iter()
        .position(|c| *c == class)
        .unwrap_or(KeyClass::ALL.len())
}

/// A provider's key cache (REPL thread only; all methods take `&self`).
#[derive(Default)]
pub struct KeyCache {
    inner: RefCell<Inner>,
}

impl KeyCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge what the loader delivered and, once it ended, settle the load: complete →
    /// the new objects replace the old; stopped/failed → old and new objects are merged
    /// (the newer read wins) and the cache is Partial.
    pub fn sync(&self) {
        let mut inner = self.inner.borrow_mut();
        let Some(load) = inner.loading.clone() else {
            return;
        };
        // read `finished` before draining, so nothing pushed before the end is missed
        let finished = load.is_finished();
        for info in load.take_inbox() {
            if info.handle.is_some_and(|h| inner.touched.contains(&h)) {
                continue;
            }
            inner.incoming.upsert(info);
        }
        if !finished {
            return;
        }
        let outcome = load.outcome().map(|(outcome, _)| outcome);
        inner.loading = None;
        inner.touched.clear();
        let incoming = std::mem::take(&mut inner.incoming);
        match outcome {
            Some(LoadOutcome::Complete) => {
                inner.entries = incoming;
                inner.complete = true;
                inner.last_error = None;
            }
            other => {
                for info in incoming.items {
                    inner.entries.upsert(info);
                }
                inner.complete = false;
                inner.last_error = match other {
                    Some(LoadOutcome::Failed(err)) => Some(err.message),
                    _ => None,
                };
            }
        }
        inner.has_data = true;
    }

    /// The current status (after `sync`).
    pub fn status(&self) -> CacheStatus {
        self.sync();
        let inner = self.inner.borrow();
        let state = if inner.loading.is_some() {
            CacheState::Loading
        } else if inner.complete {
            CacheState::Complete
        } else if inner.has_data {
            CacheState::Partial
        } else {
            CacheState::Empty
        };
        CacheStatus {
            state,
            count: Self::view_len(&inner),
            progress: inner.loading.as_ref().map(|load| load.progress()),
            last_error: inner.last_error.clone(),
        }
    }

    fn view_len(inner: &Inner) -> usize {
        let extra = inner
            .entries
            .items
            .iter()
            .filter(|info| !info.handle.is_some_and(|h| inner.incoming.contains(h)))
            .count();
        inner.incoming.len() + extra
    }

    /// The cached objects (while loading: what the running load read so far, plus the
    /// previous load's objects it has not reached yet).
    pub fn view(&self) -> CacheView {
        let status = self.status();
        let inner = self.inner.borrow();
        let mut keys: Vec<KeyInfo> = inner.incoming.items.clone();
        keys.extend(
            inner
                .entries
                .items
                .iter()
                .filter(|info| !info.handle.is_some_and(|h| inner.incoming.contains(h)))
                .cloned(),
        );
        keys.sort_by_key(|info| class_rank(info.key_class)); // stable: token order kept
        CacheView { keys, status }
    }

    /// True when the last load was stopped (and none runs): Tab then completes from what
    /// it read and does not load again; `keys` and `cache <provider>` do.
    pub fn stopped(&self) -> bool {
        let status = self.status();
        status.state == CacheState::Partial && status.last_error.is_none()
    }

    /// True when the last load failed (and none runs): the console then lists live and
    /// does not retry on its own — only `cache <provider>`, a login or a recovery load again.
    pub fn failed(&self) -> bool {
        let status = self.status();
        status.state == CacheState::Partial && status.last_error.is_some()
    }

    /// True while a load runs.
    pub fn is_loading(&self) -> bool {
        self.sync();
        self.inner.borrow().loading.is_some()
    }

    /// The running load, if any.
    pub fn current_load(&self) -> Option<Arc<LoadShared>> {
        self.sync();
        self.inner.borrow().loading.clone()
    }

    /// Start a load: None when one is already running (loading happens once at a time).
    /// A load that was asked to stop but is still finishing its current call does not
    /// count: it is let go (what it read so far is kept, as after any stop; its later
    /// results are ignored). The served objects stay readable until the new load completes.
    pub fn begin(&self, provider: &str) -> Option<Arc<LoadShared>> {
        self.sync();
        let mut inner = self.inner.borrow_mut();
        if let Some(old) = inner.loading.clone() {
            if !old.stop_requested() {
                return None;
            }
            inner.loading = None;
            inner.touched.clear();
            let incoming = std::mem::take(&mut inner.incoming);
            for info in incoming.items {
                inner.entries.upsert(info);
            }
            inner.complete = false;
            inner.has_data = true;
            inner.last_error = None;
        }
        let load = Arc::new(LoadShared::new(provider));
        inner.loading = Some(Arc::clone(&load));
        inner.incoming = Entries::default();
        inner.touched.clear();
        inner.reload_requested = false;
        Some(load)
    }

    /// Ask the running load to stop (its objects are kept). False when none runs.
    pub fn stop(&self) -> bool {
        match self.current_load() {
            Some(load) => {
                load.stop();
                true
            }
            None => false,
        }
    }

    /// Drop everything (logout, init-pin, a lost session): the running load is stopped
    /// and its results ignored.
    pub fn clear(&self) {
        let mut inner = self.inner.borrow_mut();
        if let Some(load) = inner.loading.take() {
            load.stop();
            if !load.is_finished() {
                // nobody else reports a load the cache let go of
                load.claim_report();
            }
        }
        *inner = Inner::default();
    }

    /// Drop everything and ask the console to load again (session auto-recovery: handles
    /// may have changed and session objects are gone).
    pub fn invalidate_and_reload(&self) {
        let had_data = {
            let inner = self.inner.borrow();
            inner.has_data || inner.loading.is_some()
        };
        self.clear();
        self.inner.borrow_mut().reload_requested = had_data;
    }

    /// True once after `invalidate_and_reload` dropped a cache that held something.
    pub fn take_reload_request(&self) -> bool {
        std::mem::take(&mut self.inner.borrow_mut().reload_requested)
    }

    /// True when the cache holds or is loading anything (patches are kept only then).
    pub fn is_active(&self) -> bool {
        let inner = self.inner.borrow();
        inner.has_data || inner.loading.is_some()
    }

    /// In-place patch: `info` was created or changed by r2 itself.
    pub fn upsert(&self, info: KeyInfo) {
        self.sync();
        let mut inner = self.inner.borrow_mut();
        if !(inner.has_data || inner.loading.is_some()) {
            return;
        }
        if let Some(handle) = info.handle {
            if inner.loading.is_some() {
                inner.touched.insert(handle);
                inner.incoming.upsert(info.clone());
            }
            // a partial cache gains the object too; a complete one stays complete
            inner.entries.upsert(info);
        }
    }

    /// In-place patch: the object `handle` was deleted by r2 itself.
    pub fn remove(&self, handle: u64) {
        self.sync();
        let mut inner = self.inner.borrow_mut();
        if inner.loading.is_some() {
            inner.touched.insert(handle);
        }
        inner.entries.remove(handle);
        inner.incoming.remove(handle);
    }
}

impl std::fmt::Debug for KeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyCache")
    }
}
