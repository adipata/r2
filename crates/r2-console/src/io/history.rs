// Command history (spec §4.9.7, §5.1; owner R7) — c2 `SecretFilteringFileHistory` for
// reedline: a `History` wrapper over `FileBackedHistory` that never stores lines containing
// `--pin` / `--password` — neither on disk nor in the in-session list (Up-arrow, hints).
use std::path::Path;

use reedline::{
    FileBackedHistory, History, HistoryItem, HistoryItemId, HistorySessionId, SearchQuery,
};

/// Command-history capacity (c2: unbounded — §11 D7).
pub(crate) const HISTORY_CAPACITY: usize = 1000;

/// Lines never stored in the history (on disk or in the session list):
/// - c2's rule: the line contains "--pin" or "--password";
/// - §11 D8 (option B, adopted): lines carrying inline key material — anything containing
///   `-----BEGIN`, any quoted token spanning several physical lines (a pasted PEM/base64
///   block), and a `load` command with an inline data positional
///   (`load <provider> <hint> <data>`, plaintext or a `--kek` blob). `load --file …` stays.
pub fn is_secret_line(line: &str) -> bool {
    if line.contains("--pin") || line.contains("--password") || line.contains("-----BEGIN") {
        return true;
    }
    let Ok(tokens) = crate::parser::tokenize(line) else {
        // Not a parseable command line: keep it only when it cannot be a `load`.
        return line.trim_start().starts_with("load");
    };
    if tokens.iter().any(|t| t.quoted && t.text.contains('\n')) {
        return true;
    }
    if tokens.first().is_none_or(|t| t.quoted || t.text != "load") {
        return false;
    }
    // `load` has no boolean flags: every `--opt` consumes its value, `name=value` tokens are
    // mechanism parameters, and positionals are provider, hint and inline data.
    match crate::parser::bind_args(&tokens[1..], &[], line) {
        Ok(args) => args.positionals.len() >= 3,
        Err(_) => true,
    }
}
/// reedline History wrapper over `FileBackedHistory` (rules below).
pub struct SecretFilteringHistory {
    inner: FileBackedHistory,
}

impl SecretFilteringHistory {
    /// `FileBackedHistory::with_file(1000, path)` (parent directory created); an unusable
    /// path — or none — falls back to the in-memory `FileBackedHistory::new(1000)` (c2:
    /// "never let a bad history path block startup"), with a warning when a path was given.
    /// An existing file that is not valid UTF-8 (reedline's `sync` would refuse it for good)
    /// is first rewritten decoded with U+FFFD replacements — c2's FileHistory decoded with
    /// `errors="replace"` and kept appending.
    pub(crate) fn open(path: Option<&Path>) -> Self {
        let file = path.and_then(|path| {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
                && let Err(err) = std::fs::create_dir_all(parent)
            {
                warn_unusable(path, &err);
                return None;
            }
            repair_utf8(path);
            match FileBackedHistory::with_file(HISTORY_CAPACITY, path.to_path_buf()) {
                Ok(history) => Some(history),
                Err(err) => {
                    warn_unusable(path, &err);
                    None
                }
            }
        });
        let inner = match file {
            Some(history) => history,
            None => FileBackedHistory::new(HISTORY_CAPACITY).unwrap_or_default(),
        };
        Self { inner }
    }
}

fn warn_unusable(path: &Path, err: &dyn std::fmt::Display) {
    tracing::warn!(
        target: "r2::console",
        "history file {} unusable ({err}); history is not saved this session",
        path.display()
    );
}

/// Rewrites an existing history file that is not valid UTF-8 with the invalid bytes
/// replaced by U+FFFD (Python `errors="replace"`). Unreadable files are left alone.
fn repair_utf8(path: &Path) {
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    if std::str::from_utf8(&bytes).is_ok() {
        return;
    }
    let repaired = String::from_utf8_lossy(&bytes);
    match std::fs::write(path, repaired.as_bytes()) {
        Ok(()) => tracing::warn!(
            target: "r2::console",
            "history file {} was not valid UTF-8; invalid bytes replaced",
            path.display()
        ),
        Err(err) => warn_unusable(path, &err),
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
