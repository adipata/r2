//! Logging setup (spec §4.9.11, §6; owner R7) — the port of c2 `logging_setup.py`.
//!
//! A rotating log file only (the console belongs to the renderer); `--debug` forces DEBUG
//! and mirrors WARNING+ to stderr. Every record passes the redaction rule
//! `(?i)\b(pin|password)\s*=\s*\S+` → `${1}=***` (c2 `RedactingFilter`), so PIN/password
//! values never reach disk. The subscriber is installed once; `setup_logging` replaces its
//! sinks and level (idempotent re-setup, as c2's handler replacement). Record layout:
//! "{time} {LEVEL:<7} {target}: {message}" (c2's format with tracing targets, §11 D4).
//! Rotation is a port of Python's `RotatingFileHandler` (rollover BEFORE the record that
//! would reach `max_bytes`; rename chain `.n-1`→`.n` … base→`.1`); it never panics and
//! ignores I/O errors, so a stray or concurrently rotated backup can never take the
//! process down.
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once, OnceLock, PoisonError};

use r2_config::model::{LogLevel, LogSection};
use r2_core::error::ConsoleError;
use r2_core::text::py_os_error_str;
use regex::Regex;
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

/// Where WARNING+ records are mirrored under `--debug` (stderr; tests swap in a buffer).
pub(crate) type Mirror = Box<dyn Write + Send>;

struct LogState {
    level: LevelFilter,
    file: RotatingFile,
    mirror: Option<Mirror>,
}

/// Python `logging.handlers.RotatingFileHandler(path, maxBytes, backupCount)` — the parts
/// c2 used. Every I/O error is swallowed (Python's `handleError` printed a report and went
/// on); a failed open is retried at the next record.
pub(crate) struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    backups: u64,
    file: Option<File>,
}

impl RotatingFile {
    fn open_append(path: &Path) -> io::Result<File> {
        OpenOptions::new().create(true).append(true).open(path)
    }

    /// `shouldRollover`: only a regular (or not yet existing) base file rolls over, and only
    /// when `max_bytes > 0` and the current size plus the record (Python counts the
    /// formatted message's characters) reaches `max_bytes`.
    fn should_rollover(&mut self, record: &str) -> bool {
        if self.max_bytes == 0 {
            return false;
        }
        if std::fs::metadata(&self.path).is_ok_and(|meta| !meta.is_file()) {
            return false;
        }
        let Some(file) = self.file.as_mut() else {
            return false;
        };
        let Ok(size) = file.metadata().map(|meta| meta.len()) else {
            return false;
        };
        let chars = u64::try_from(record.chars().count()).unwrap_or(u64::MAX);
        size.saturating_add(chars) >= self.max_bytes
    }

    fn numbered(&self, index: u64) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(format!(".{index}"));
        PathBuf::from(name)
    }

    /// `doRollover`: close; when `backups > 0`, shift `.i` → `.i+1` for i = backups-1..1
    /// (an existing destination is removed first), remove `.1`, rename base → `.1`; reopen.
    fn rollover(&mut self) {
        self.file = None;
        if self.backups > 0 {
            for index in (1..self.backups).rev() {
                let source = self.numbered(index);
                if source.exists() {
                    let target = self.numbered(index + 1);
                    if target.exists() {
                        let _ = std::fs::remove_file(&target);
                    }
                    let _ = std::fs::rename(&source, &target);
                }
            }
            let first = self.numbered(1);
            if first.exists() {
                let _ = std::fs::remove_file(&first);
            }
            if self.path.exists() {
                let _ = std::fs::rename(&self.path, &first);
            }
        }
        self.file = Self::open_append(&self.path).ok();
    }

    /// `emit`: (re)open if needed, roll over if the record would reach the limit, write.
    pub(crate) fn write_record(&mut self, record: &str) {
        if self.file.is_none() {
            self.file = Self::open_append(&self.path).ok();
        }
        if self.should_rollover(record) {
            self.rollover();
        }
        if let Some(file) = self.file.as_mut()
            && (file.write_all(record.as_bytes()).is_err() || file.flush().is_err())
        {
            // reopen at the next record (e.g. the file was removed underneath us)
            self.file = None;
        }
    }
}

static STATE: Mutex<Option<LogState>> = Mutex::new(None);
static INSTALL: Once = Once::new();

/// c2 `_REDACT_RE`.
fn redaction() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(pin|password)\s*=\s*\S+").ok())
        .as_ref()
}

/// c2 `RedactingFilter`: `pin=…` / `password=…` → `{name}=***` (the name as written).
pub(crate) fn redact(message: &str) -> String {
    match redaction() {
        Some(re) => re.replace_all(message, "${1}=***").into_owned(),
        // the pattern is a constant; if it ever failed to compile, drop the line rather
        // than risk logging a secret
        None => "<log line withheld: redaction unavailable>".to_owned(),
    }
}

fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warning => LevelFilter::WARN,
        LogLevel::Error => LevelFilter::ERROR,
    }
}

/// Python's level names.
fn level_name(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARNING",
        Level::INFO => "INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    }
}

/// Collects an event's message and its other fields ("k=v").
#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}
impl Visit for MessageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

fn current_level() -> Option<LevelFilter> {
    STATE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .map(|state| state.level)
}

/// Test override of the lastResort sink (None → stderr).
#[cfg(test)]
static LAST_RESORT_SINK: Mutex<Option<Mirror>> = Mutex::new(None);

/// Python's `logging.lastResort` (level WARNING, format `%(message)s`, stderr): what c2
/// printed for records emitted before `setup_logging` installed a handler — e.g. the
/// config loader's "unknown config key …" and below-range CKM warnings.
fn last_resort(message: &str) {
    let line = format!("{message}\n");
    #[cfg(test)]
    if let Some(sink) = LAST_RESORT_SINK
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_mut()
    {
        let _ = sink.write_all(line.as_bytes());
        return;
    }
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(line.as_bytes());
    let _ = stderr.flush();
}

/// The one layer of the global subscriber; reads the replaceable state.
struct R2Layer;
impl<S: Subscriber> Layer<S> for R2Layer {
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::sometimes() // the level is re-read per record (re-setup changes it)
    }
    fn enabled(&self, metadata: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        // before setup_logging: Python's lastResort handler (WARNING+)
        *metadata.level() <= current_level().unwrap_or(LevelFilter::WARN)
    }
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let metadata = event.metadata();
        let message = redact(&format!("{}{}", visitor.message, visitor.fields));
        let mut guard = STATE.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(state) = guard.as_mut() else {
            drop(guard);
            if *metadata.level() <= Level::WARN {
                last_resort(&message);
            }
            return;
        };
        let mut time = String::new();
        let _ = SystemTime.format_time(&mut Writer::new(&mut time));
        let line = format!(
            "{time} {:<7} {}: {}\n",
            level_name(metadata.level()),
            metadata.target(),
            message
        );
        if *metadata.level() > state.level {
            return;
        }
        state.file.write_record(&line);
        if *metadata.level() <= Level::WARN
            && let Some(mirror) = state.mirror.as_mut()
        {
            let _ = mirror.write_all(line.as_bytes());
            let _ = mirror.flush();
        }
    }
}

/// Python `Path.mkdir(parents=True, exist_ok=True)`, reporting the path that failed (c2's
/// OSError carried it as `filename`).
fn mkdir_parents(path: &Path) -> Result<(), (io::Error, PathBuf)> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() && parent != path => {
                    mkdir_parents(parent)?;
                }
                _ => return Err((err, path.to_path_buf())),
            }
            match std::fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(_) if path.is_dir() => Ok(()),
                Err(err) => Err((err, path.to_path_buf())),
            }
        }
        Err(_) if path.is_dir() => Ok(()),
        Err(err) => Err((err, path.to_path_buf())),
    }
}

/// Steps (1)+(2) of §4.9.11, then (3): the rotating file.
fn open_log_file(section: &LogSection) -> r2_core::Result<RotatingFile> {
    let path = section.file.as_path();
    let fail = |err: &io::Error, failing: &Path| {
        ConsoleError::config(format!(
            "cannot open log file {}: {}",
            path.display(),
            py_os_error_str(err, failing)
        ))
        .with_hint("check app.log.file in the configuration")
    };
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        mkdir_parents(parent).map_err(|(err, failing)| fail(&err, &failing))?;
    }
    let file = RotatingFile::open_append(path).map_err(|err| fail(&err, path))?;
    // Python never rolls over when maxBytes is 0; with backupCount 0 a rollover only
    // closes and reopens the file, which just grows
    Ok(RotatingFile {
        path: path.to_path_buf(),
        max_bytes: section.max_bytes,
        backups: u64::from(section.backups),
        file: Some(file),
    })
}

/// Configure (or re-configure) the log sinks; `mirror` receives WARNING+ under `debug`.
pub(crate) fn configure(
    section: &LogSection,
    debug: bool,
    mirror: Option<Mirror>,
) -> r2_core::Result<()> {
    let file = open_log_file(section)?;
    let level = if debug {
        LevelFilter::DEBUG
    } else {
        level_filter(section.level)
    };
    let state = LogState {
        level,
        file,
        mirror: if debug { mirror } else { None },
    };
    *STATE.lock().unwrap_or_else(PoisonError::into_inner) = Some(state);
    install();
    tracing::callsite::rebuild_interest_cache();
    Ok(())
}

/// Installs the global subscriber (once). Called before `load_config`, so records emitted
/// before `setup_logging` reach the lastResort sink (stderr, bare messages, WARNING+), as
/// Python's logging did for c2.
pub(crate) fn install() {
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::registry().with(R2Layer);
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

/// `setup_logging(app.log, debug)`: level from the config unless `--debug` forces DEBUG;
/// `--debug` also mirrors WARNING+ to stderr. Errors: Config "cannot open log file …".
pub(crate) fn setup_logging(section: &LogSection, debug: bool) -> r2_core::Result<()> {
    configure(section, debug, Some(Box::new(io::stderr())))
}

/// (level, mirror installed) of the current setup — for tests.
#[cfg(test)]
pub(crate) fn settings() -> Option<(LevelFilter, bool)> {
    STATE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .map(|state| (state.level, state.mirror.is_some()))
}

/// Drops the current setup (back to the pre-setup lastResort mode) — for tests.
#[cfg(test)]
pub(crate) fn reset() {
    *STATE.lock().unwrap_or_else(PoisonError::into_inner) = None;
    tracing::callsite::rebuild_interest_cache();
}

#[cfg(test)]
mod tests {
    //! The port of c2 tests/unit/console/test_logging_setup.py (+ the §4.9.11 file rules).
    use std::sync::Arc;

    use r2_testkit::global_state_lock;

    use super::*;

    fn section(dir: &Path, level: LogLevel) -> LogSection {
        LogSection {
            level,
            file: dir.join("cc.log"),
            max_bytes: 4096,
            backups: 2,
        }
    }

    fn read(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("cc.log")).unwrap()
    }

    /// A shared in-memory mirror (stands in for stderr).
    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);
    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Buffer {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    #[test]
    fn test_log_lines_reach_the_rotating_file() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        configure(&section(dir.path(), LogLevel::Info), false, None).unwrap();
        tracing::info!(target: "r2::test", "generated key label={} len={}", "mykey", 32);
        let text = read(dir.path());
        assert!(text.contains("generated key label=mykey len=32"));
        assert!(text.contains("INFO"));
        assert!(text.contains(" INFO    r2::test: generated key label=mykey len=32\n"));
    }

    #[test]
    fn test_pin_and_password_values_are_redacted() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        configure(&section(dir.path(), LogLevel::Info), false, None).unwrap();
        tracing::info!("login attempt pin=1234 on slot 0");
        tracing::warn!("export used password=hunter2 for p12");
        tracing::info!("mixed PIN = 9999 and Password=abc");
        let text = read(dir.path());
        for secret in ["1234", "hunter2", "9999"] {
            assert!(!text.contains(secret), "{secret}");
        }
        assert!(text.contains("pin=***"));
        assert!(text.contains("password=***"));
        assert!(text.contains("PIN=***")); // case-insensitive, spaces around '=' collapsed
        assert!(text.contains("Password=***"));
        assert!(text.contains("WARNING"));
    }

    #[test]
    fn test_redaction_applies_to_percent_formatted_args() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        configure(&section(dir.path(), LogLevel::Info), false, None).unwrap();
        tracing::info!("login {} pin={}", "hsm", "8642");
        // structured fields are part of the record too
        tracing::info!(pin = "7531", "field-carried");
        let text = read(dir.path());
        assert!(!text.contains("8642"));
        assert!(!text.contains("7531"));
        assert!(text.contains("pin=***"));
    }

    #[test]
    fn test_level_comes_from_config() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        configure(&section(dir.path(), LogLevel::Warning), false, None).unwrap();
        assert_eq!(settings(), Some((LevelFilter::WARN, false)));
        tracing::info!("below the configured level");
        tracing::warn!("at the configured level");
        let text = read(dir.path());
        assert!(!text.contains("below the configured level"));
        assert!(text.contains("at the configured level"));
    }

    #[test]
    fn test_debug_forces_debug_and_adds_stderr_mirror() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        let mirror = Buffer::default();
        configure(
            &section(dir.path(), LogLevel::Error),
            true,
            Some(Box::new(mirror.clone())),
        )
        .unwrap();
        assert_eq!(settings(), Some((LevelFilter::DEBUG, true)));
        tracing::debug!("a debug record");
        tracing::warn!("a warning");
        tracing::error!("an error");
        // §6: the mirror gets WARNING+ only; the file everything
        assert_eq!(mirror.text().lines().count(), 2);
        assert!(mirror.text().contains("a warning"));
        assert!(mirror.text().contains("an error"));
        assert!(read(dir.path()).contains("a debug record"));
        // without --debug there is no mirror
        configure(
            &section(dir.path(), LogLevel::Error),
            false,
            Some(Box::new(mirror.clone())),
        )
        .unwrap();
        assert_eq!(settings(), Some((LevelFilter::ERROR, false)));
    }

    #[test]
    fn test_rotation_parameters_applied() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        configure(&section(dir.path(), LogLevel::Info), false, None).unwrap();
        let filler = "x".repeat(200);
        for _ in 0..80 {
            tracing::info!("{filler}");
        }
        // maxBytes=4096 rotates; backupCount=2 keeps two backups
        assert!(dir.path().join("cc.log.1").exists());
        assert!(dir.path().join("cc.log.2").exists());
        assert!(!dir.path().join("cc.log.3").exists());
        // Python rolls over BEFORE the record that would reach maxBytes
        for name in ["cc.log", "cc.log.1", "cc.log.2"] {
            let size = std::fs::metadata(dir.path().join(name)).unwrap().len();
            assert!(size < 4096, "{name}: {size}");
        }
    }

    fn rotating(dir: &Path, max_bytes: u64, backups: u64) -> RotatingFile {
        let path = dir.join("cc.log");
        RotatingFile {
            file: RotatingFile::open_append(&path).ok(),
            path,
            max_bytes,
            backups,
        }
    }

    #[test]
    fn rollover_matches_python_rotating_file_handler() {
        let dir = tempfile::tempdir().unwrap();
        let mut file = rotating(dir.path(), 10, 2);
        // "aaaa\n" (5) + "bbbb\n" (5) reaches 10: rolled over before the second record
        file.write_record("aaaa\n");
        file.write_record("bbbb\n");
        file.write_record("cccc\n");
        file.write_record("dddd\n");
        let text = |name: &str| std::fs::read_to_string(dir.path().join(name)).unwrap();
        assert_eq!(text("cc.log"), "dddd\n");
        assert_eq!(text("cc.log.1"), "cccc\n");
        assert_eq!(text("cc.log.2"), "bbbb\n");
        assert!(!dir.path().join("cc.log.3").exists());
    }

    #[test]
    fn stray_or_concurrently_rotated_backups_never_panic() {
        // file-rotate 0.8 asserted on its startup view of the backups; Python just renames
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cc.log.01"), "stray").unwrap();
        let mut first = rotating(dir.path(), 10, 3);
        let mut second = rotating(dir.path(), 10, 3);
        for round in 0..6 {
            first.write_record(&format!("first{round}\n"));
            second.write_record(&format!("second{round}\n"));
        }
        assert!(dir.path().join("cc.log.3").exists());
        assert!(!dir.path().join("cc.log.4").exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("cc.log.01")).unwrap(),
            "stray"
        );
        // the base file vanishing underneath is reopened at the next record
        std::fs::remove_file(dir.path().join("cc.log")).unwrap();
        first.write_record("again\n");
        first.write_record("again\n");
        assert!(dir.path().join("cc.log").exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_unlistable_log_directory_starts_normally() {
        // c2's RotatingFileHandler never lists the directory (file-rotate 0.8 panicked)
        use std::os::unix::fs::PermissionsExt;
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        std::fs::write(logs.join("cc.log"), "").unwrap();
        std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(0o300)).unwrap();
        let section = LogSection {
            file: logs.join("cc.log"),
            ..section(dir.path(), LogLevel::Info)
        };
        let result = configure(&section, false, None);
        tracing::info!("still logging");
        std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(0o700)).unwrap();
        result.unwrap();
        assert!(read(&logs).contains("still logging"));
    }

    #[test]
    fn zero_max_bytes_or_backups_never_rotate() {
        let _lock = global_state_lock();
        for (max_bytes, backups) in [(0, 3), (1024, 0)] {
            let dir = tempfile::tempdir().unwrap();
            let section = LogSection {
                level: LogLevel::Info,
                file: dir.path().join("cc.log"),
                max_bytes,
                backups,
            };
            configure(&section, false, None).unwrap();
            for _ in 0..40 {
                tracing::info!("{}", "y".repeat(100));
            }
            assert!(!dir.path().join("cc.log.1").exists());
            assert!(read(dir.path()).len() > 4000);
        }
    }

    #[test]
    fn test_setup_is_idempotent() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        configure(&section(dir.path(), LogLevel::Info), false, None).unwrap();
        configure(&section(dir.path(), LogLevel::Info), false, None).unwrap();
        tracing::info!("exactly once");
        // re-setup replaced the sink, not stacked a second one
        assert_eq!(read(dir.path()).matches("exactly once").count(), 1);
    }

    #[test]
    fn test_unwritable_log_path_raises_config_error() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, "a file, not a directory").unwrap();
        let bad = LogSection {
            level: LogLevel::Info,
            file: blocker.join("sub").join("cc.log"),
            max_bytes: 1024,
            backups: 1,
        };
        let err = configure(&bad, false, None).unwrap_err();
        assert_eq!(err.kind, r2_core::ErrorKind::Config);
        assert!(err.message.contains("cannot open log file"));
        if cfg!(unix) {
            assert_eq!(
                err.message,
                format!(
                    "cannot open log file {}: [Errno 20] Not a directory: {}",
                    bad.file.display(),
                    r2_core::text::py_repr(&blocker.join("sub").display().to_string())
                )
            );
        } else {
            // Windows: mkdir of `blocker\sub` is ERROR_PATH_NOT_FOUND, so pathlib's
            // mkdir(parents=True) recurses and fails on `blocker` itself (the OS wording is
            // the system's)
            assert!(
                err.message.starts_with(&format!(
                    "cannot open log file {}: [Errno ",
                    bad.file.display()
                )),
                "{}",
                err.message
            );
            assert!(
                err.message.ends_with(&format!(
                    ": {}",
                    r2_core::text::py_repr(&blocker.display().to_string())
                )),
                "{}",
                err.message
            );
        }
        assert_eq!(
            err.hint.as_deref(),
            Some("check app.log.file in the configuration")
        );
        // a log path that is a directory
        let as_dir = LogSection {
            file: dir.path().to_path_buf(),
            ..bad
        };
        let err = configure(&as_dir, false, None).unwrap_err();
        let shown = r2_core::text::py_repr(&dir.path().display().to_string());
        if cfg!(unix) {
            assert_eq!(
                err.message,
                format!(
                    "cannot open log file {}: [Errno 21] Is a directory: {shown}",
                    dir.path().display()
                )
            );
        } else {
            assert!(
                err.message.starts_with(&format!(
                    "cannot open log file {}: [Errno ",
                    dir.path().display()
                )),
                "{}",
                err.message
            );
            assert!(
                err.message.ends_with(&format!(": {shown}")),
                "{}",
                err.message
            );
        }
    }

    #[test]
    fn missing_parent_directories_are_created() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        let nested = LogSection {
            level: LogLevel::Info,
            file: dir.path().join("a").join("b").join("cc.log"),
            max_bytes: 1024,
            backups: 1,
        };
        configure(&nested, false, None).unwrap();
        assert!(nested.file.exists());
    }

    #[test]
    fn test_redacting_filter_leaves_clean_messages_untouched() {
        assert_eq!(
            redact("mechanism AES-GCM len=16"),
            "mechanism AES-GCM len=16"
        );
        assert_eq!(redact("spin=3 pinned=1 pin= x"), "spin=3 pinned=1 pin=***");
    }

    #[test]
    fn pre_setup_warnings_go_to_last_resort_as_bare_messages() {
        let _lock = global_state_lock();
        let sink = Buffer::default();
        install();
        reset();
        *LAST_RESORT_SINK.lock().unwrap() = Some(Box::new(sink.clone()));
        tracing::info!(target: "r2::config", "an info record");
        tracing::warn!(target: "r2::config", "unknown config key 'ui.hex_widht'");
        tracing::error!("an error pin=1234");
        *LAST_RESORT_SINK.lock().unwrap() = None;
        assert_eq!(
            sink.text(),
            "unknown config key 'ui.hex_widht'\nan error pin=***\n"
        );
    }

    #[test]
    fn config_loader_warnings_reach_last_resort() {
        let _lock = global_state_lock();
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("r2.yaml");
        std::fs::write(
            &cfg,
            "ui: {hex_widht: 3}\ncustom_mechanisms:\n  - {id: v.x, verb: encrypt, algorithm: aes, \
             cli_name: x, label: X, ckm: 5}\n",
        )
        .unwrap();
        let sink = Buffer::default();
        install();
        reset();
        *LAST_RESORT_SINK.lock().unwrap() = Some(Box::new(sink.clone()));
        let loaded = r2_config::loader::load_config(Some(&cfg));
        *LAST_RESORT_SINK.lock().unwrap() = None;
        let text = sink.text();
        assert!(
            text.contains("unknown config key 'ui.hex_widht' (did you mean 'hex_width'?)\n"),
            "{text} / {loaded:?}"
        );
        assert!(
            text.contains(
                "custom_mechanisms[0].ckm: CKM code 0x00000005 is below the vendor-defined \
                 range (>= 0x80000000)\n"
            ),
            "{text} / {loaded:?}"
        );
    }
}
