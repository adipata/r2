// Command history (spec §4.9.7, §5.1; owner R7) — c2 `SecretFilteringFileHistory` for
// reedline: a `History` wrapper over `FileBackedHistory` that never stores lines containing
// `--pin` / `--password` — neither on disk nor in the in-session list (Up-arrow, hints).
use std::path::Path;

use reedline::{
    FileBackedHistory, History, HistoryItem, HistoryItemId, HistorySessionId, SearchQuery,
};

/// Command-history capacity (c2: unbounded — §11 D7).
pub(crate) const HISTORY_CAPACITY: usize = 1000;

/// c2 parity: the line contains "--pin" or "--password" (§11 D8 records the open decision
/// on inline key material).
pub fn is_secret_line(line: &str) -> bool {
    line.contains("--pin") || line.contains("--password")
}
/// reedline History wrapper over `FileBackedHistory` (rules below).
pub struct SecretFilteringHistory {
    inner: FileBackedHistory,
}

impl SecretFilteringHistory {
    /// `FileBackedHistory::with_file(1000, path)` (parent directory created); an unusable
    /// path — or none — falls back to the in-memory `FileBackedHistory::new(1000)` (c2:
    /// "never let a bad history path block startup").
    pub(crate) fn open(path: Option<&Path>) -> Self {
        let file = path.and_then(|path| {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
                && std::fs::create_dir_all(parent).is_err()
            {
                return None;
            }
            FileBackedHistory::with_file(HISTORY_CAPACITY, path.to_path_buf()).ok()
        });
        let inner = match file {
            Some(history) => history,
            None => FileBackedHistory::new(HISTORY_CAPACITY).unwrap_or_default(),
        };
        Self { inner }
    }
}

impl History for SecretFilteringHistory {
    fn save(&mut self, h: HistoryItem) -> reedline::Result<HistoryItem> {
        if is_secret_line(&h.command_line) {
            // MUST be Ok: reedline `.expect()`s the result on submit. `id: None` is the
            // "not stored" answer FileBackedHistory itself gives for duplicates.
            return Ok(HistoryItem { id: None, ..h });
        }
        self.inner.save(h)
    }
    fn load(&self, id: HistoryItemId) -> reedline::Result<HistoryItem> {
        self.inner.load(id)
    }
    fn count(&self, query: SearchQuery) -> reedline::Result<i64> {
        self.inner.count(query)
    }
    fn search(&self, query: SearchQuery) -> reedline::Result<Vec<HistoryItem>> {
        self.inner.search(query)
    }
    fn update(
        &mut self,
        id: HistoryItemId,
        updater: &dyn Fn(HistoryItem) -> HistoryItem,
    ) -> reedline::Result<()> {
        // an update can never smuggle a secret line in
        let guarded = |item: HistoryItem| {
            let updated = updater(item.clone());
            if is_secret_line(&updated.command_line) {
                item
            } else {
                updated
            }
        };
        self.inner.update(id, &guarded)
    }
    fn clear(&mut self) -> reedline::Result<()> {
        self.inner.clear()
    }
    fn delete(&mut self, h: HistoryItemId) -> reedline::Result<()> {
        self.inner.delete(h)
    }
    fn sync(&mut self) -> std::io::Result<()> {
        self.inner.sync()
    }
    fn session(&self) -> Option<HistorySessionId> {
        self.inner.session()
    }
}
