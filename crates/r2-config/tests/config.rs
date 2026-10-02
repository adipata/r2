#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! R2: configuration system (spec §4.8, §4.7 inference, §7 defaults) — the port of c2's
//! `tests/unit/test_config.py` and `tests/unit/test_config_objects.py`, plus the R2
//! acceptance cases the c2 tests do not cover (PyYAML-generated decoder vectors, `config
//! show` dumps, YAML 1.1 typing of a fixture config, discovery edge cases).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use r2_config::dirs::{expand_user, user_config_dir};
use r2_config::loader::{
    self, DEFAULTS_YAML, ENV_VAR, FILE_NAME, config_from_yaml, deep_merge, discover, load_config,
};
use r2_config::model::{
    AppConfig, CONFIG_SECTIONS, ColorMode, CustomAttributeDef, CustomMechanismConfig, LoadedConfig,
    LogLevel, ParamSpecConfig, Pkcs11InstanceConfig, TEMPLATE_CLASS_KEYS, TemplatesSection,
    template_class_key,
};
use r2_config::yaml::{self, Value};
use r2_core::ErrorKind;
use r2_core::keys::{KeyAlgorithm, KeyClass};
use r2_core::params::{ParamKind, ParamStruct, ParamValue, Verb};
use r2_core::template::{AttrKind, AttrValue};
use r2_testkit::{EnvGuard, global_state_lock, set_env};

mod vectors {
    #![allow(dead_code)]
    include!("support/yaml_vectors.rs");
}

// ---- fixtures ------------------------------------------------------------------------------

/// c2's autouse `_isolated_discovery`: no ambient config — clean env, empty CWD (a temp
/// dir), the user config dir under the temp dir. Holds the global-state lock throughout.
struct Isolated {
    tmp: tempfile::TempDir,
    old_cwd: PathBuf,
    _env: Vec<EnvGuard>,
    _lock: MutexGuard<'static, ()>,
}

impl Isolated {
    fn new() -> Self {
        let lock = global_state_lock();
        let tmp = tempfile::tempdir().unwrap();
        let mut env = vec![set_env(ENV_VAR, None)];
        let base = tmp.path().join("usercfg");
        if cfg!(windows) {
            env.push(set_env("LOCALAPPDATA", Some(base.to_str().unwrap())));
        } else if cfg!(target_os = "macos") {
            // platformdirs MacOS honors $XDG_CONFIG_HOME first (XDGMixin): clear it.
            env.push(set_env("XDG_CONFIG_HOME", None));
            env.push(set_env("HOME", Some(base.to_str().unwrap())));
        } else {
            env.push(set_env("XDG_CONFIG_HOME", Some(base.to_str().unwrap())));
        }
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        Self {
            tmp,
            old_cwd,
            _env: env,
            _lock: lock,
        }
    }

    /// The (absolute, canonical) temp dir that is the CWD.
    fn path(&self) -> PathBuf {
        std::env::current_dir().unwrap()
    }

    /// `<user config dir>/r2.yaml` under the isolated base.
    fn user_file(&self) -> PathBuf {
        user_config_dir().unwrap().join(FILE_NAME)
    }

    fn env(&mut self, key: &str, value: Option<&str>) {
        self._env.push(set_env(key, value));
    }
}

impl Drop for Isolated {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.old_cwd);
        let _ = &self.tmp;
    }
}

/// c2 `_write`: create parents, write the (already dedented) text.
fn write(path: &Path, text: &str) -> PathBuf {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
    path.to_path_buf()
}

fn home() -> PathBuf {
    std::env::home_dir().unwrap()
}

/// The `~`-expansion c2's tests compute with `Path(...).expanduser()`.
fn expanded(tail: &str) -> PathBuf {
    expand_user(&format!("~/{tail}"))
}

/// c2 `caplog` + `_config_warnings`: WARNING+ records of the `r2::config` target.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

struct MessageVisitor<'a>(&'a mut String);
impl tracing::field::Visit for MessageVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            *self.0 = format!("{value:?}");
        }
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let meta = event.metadata();
        if meta.target().starts_with("r2::config") && *meta.level() <= tracing::Level::WARN {
            let mut message = String::new();
            event.record(&mut MessageVisitor(&mut message));
            self.0.lock().unwrap().push(message);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Run `f` with a capturing subscriber; returns its result and the config warnings.
fn config_warnings<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    let capture = Capture::default();
    let result = tracing::subscriber::with_default(capture.clone(), f);
    let warnings = capture.0.lock().unwrap().clone();
    (result, warnings)
}

fn config_err(result: r2_core::Result<LoadedConfig>) -> r2_core::ConsoleError {
    let err = result.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Config, "{err:?}");
    err
}

/// c2 `re.search(pattern, message)` for the literal patterns the c2 tests use.
fn assert_contains(haystack: &str, needle: &str) {
    assert!(haystack.contains(needle), "{needle:?} not in {haystack:?}");
}

// ---- embedded defaults (§7) ------------------------------------------------------------------

mod embedded_defaults {
    use super::*;

    /// c2 checked the packaged resource; r2 embeds it with `include_str!` — and §7 requires
    /// it to be c2's file through exactly `sed 's#/c2/#/r2/#g; s#c2\.log#r2.log#'`.
    #[test]
    fn defaults_yaml_ships_inside_the_package() {
        let c2 = include_str!("support/c2_defaults.yaml");
        let transformed = c2.replace("/c2/", "/r2/").replacen("c2.log", "r2.log", 1);
        assert_eq!(DEFAULTS_YAML, transformed);
        assert!(!DEFAULTS_YAML.is_empty());
    }

    #[test]
    fn defaults_load_clean_without_warnings() {
        let _iso = Isolated::new();
        let (loaded, warnings) = config_warnings(|| load_config(None));
        let loaded = loaded.unwrap();
        assert_eq!(loaded.source_path, None);
        assert_eq!(warnings, Vec::<String>::new());
    }

    #[test]
    fn defaults_values_match_spec_section_7() {
        let _iso = Isolated::new();
        let config = load_config(None).unwrap().config;
        assert_eq!(config.app.history_file, expanded(".local/state/r2/history"));
        assert_eq!(config.app.log.level, LogLevel::Info);
        assert_eq!(config.app.log.file, expanded(".local/state/r2/r2.log"));
        assert_eq!(config.app.log.max_bytes, 1048576);
        assert_eq!(config.app.log.backups, 3);
        assert_eq!(config.ui.color, ColorMode::Auto);
        assert_eq!(config.ui.hex_group, 2);
        assert_eq!(config.ui.hex_width, 32);
        assert!(config.ui.confirm_delete);
        assert!(config.providers.memory.enabled);
        assert_eq!(config.providers.memory.name, "mem");
        assert_eq!(config.providers.pkcs11, vec![]);
        assert!(config.softhsm.autodetect);
        assert_eq!(config.softhsm.provider_name, "softhsm");
        assert_eq!(config.softhsm.search_paths.len(), 9);
        assert_eq!(
            config.softhsm.search_paths[0],
            PathBuf::from("/opt/homebrew/lib/softhsm/libsofthsm2.so")
        );
        assert_eq!(
            config.softhsm.search_paths[8],
            r2_core::text::py_path("C:/SoftHSM2/lib/softhsm2-x64.dll")
        );
        assert_eq!(config.softhsm.conf_dir, expanded(".config/r2/softhsm2"));
        assert_eq!(
            config.softhsm.token_dir,
            expanded(".local/state/r2/softhsm2/tokens")
        );
        let mut keys: Vec<&str> = config.templates.pkcs11.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "aes",
                "certificate",
                "data",
                "ec_private",
                "ec_public",
                "generic_secret",
                "rsa_private",
                "rsa_public",
            ]
        );
        assert!(config.templates.custom_attributes.is_empty());
        assert_eq!(config.custom_mechanisms, vec![]);
    }

    #[test]
    fn defaults_round_trip_through_typed_model() {
        let _iso = Isolated::new();
        let raw = yaml::parse(DEFAULTS_YAML).unwrap();
        let loaded = load_config(None).unwrap();
        let raw_sections: Vec<&str> = raw
            .as_mapping()
            .unwrap()
            .keys()
            .map(|k| k.as_str().unwrap())
            .collect();
        assert_eq!(
            loaded
                .origins
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            raw_sections
        );
        assert!(loaded.origins.values().all(|v| v == "default"));
        // dict(templates.pkcs11) == raw["templates"]["pkcs11"]: the raw mirror is the YAML.
        let raw_templates = &raw["templates"]["pkcs11"];
        for (class_key, attrs) in &loaded.config.templates.pkcs11_raw {
            for (name, value) in attrs {
                assert_eq!(&raw_templates[class_key.as_str()][name.as_str()], value);
            }
            assert_eq!(
                raw_templates[class_key.as_str()]
                    .as_mapping()
                    .unwrap()
                    .len(),
                attrs.len()
            );
        }
        assert_eq!(
            raw_templates.as_mapping().unwrap().len(),
            loaded.config.templates.pkcs11_raw.len()
        );
        // typed values: every §7 template value is a bool
        for attrs in loaded.config.templates.pkcs11.values() {
            assert!(attrs.values().all(|v| matches!(v, AttrValue::Bool(_))));
        }
        let search: Vec<PathBuf> = raw["softhsm"]["search_paths"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|entry| expand_user(entry.as_str().unwrap()))
            .collect();
        assert_eq!(loaded.config.softhsm.search_paths, search);
        assert_eq!(
            loaded.config.providers.memory.name,
            raw["providers"]["memory"]["name"].as_str().unwrap()
        );
    }

    /// Accept: "the embedded file loads clean and round-trips" — the typed model dumps back
    /// to the defaults' values (`config show` of the defaults, byte-compared with c2).
    #[test]
    fn defaults_config_show_matches_c2() {
        let _iso = Isolated::new();
        let mut iso = _iso;
        iso.env("HOME", Some("/home/tester"));
        let (text, expected) = vectors::CONFIG_SHOW[0];
        assert_eq!(text, "");
        let config = config_from_yaml(None).unwrap();
        assert_eq!(yaml::dump(&config.to_value()), expected);
    }
}

// ---- discovery + precedence (§4.8) -----------------------------------------------------------

mod discovery {
    use super::*;

    #[test]
    fn cli_path_wins_over_env() {
        let mut iso = Isolated::new();
        let cli_file = write(&iso.path().join("cli.yaml"), "ui: {hex_group: 4}\n");
        let env_file = write(&iso.path().join("env.yaml"), "ui: {hex_group: 8}\n");
        iso.env(ENV_VAR, Some(env_file.to_str().unwrap()));
        let loaded = load_config(Some(&cli_file)).unwrap();
        assert_eq!(loaded.source_path, Some(cli_file));
        assert_eq!(loaded.config.ui.hex_group, 4);
    }

    #[test]
    fn env_wins_over_cwd() {
        let mut iso = Isolated::new();
        write(&iso.path().join("r2.yaml"), "ui: {hex_group: 8}\n");
        let env_file = write(&iso.path().join("env.yaml"), "ui: {hex_group: 5}\n");
        iso.env(ENV_VAR, Some(env_file.to_str().unwrap()));
        let loaded = load_config(None).unwrap();
        assert_eq!(loaded.source_path, Some(env_file));
        assert_eq!(loaded.config.ui.hex_group, 5);
    }

    #[test]
    fn cwd_wins_over_user_dir() {
        let iso = Isolated::new();
        let cwd_file = write(&iso.path().join("r2.yaml"), "ui: {hex_group: 8}\n");
        write(&iso.user_file(), "ui: {hex_group: 9}\n");
        let loaded = load_config(None).unwrap();
        assert_eq!(loaded.source_path, Some(cwd_file));
        assert_eq!(loaded.config.ui.hex_group, 8);
    }

    #[test]
    fn user_dir_is_last_resort() {
        let iso = Isolated::new();
        let user_file = write(&iso.user_file(), "ui: {hex_group: 9}\n");
        let loaded = load_config(None).unwrap();
        assert_eq!(loaded.source_path, Some(user_file));
        assert_eq!(loaded.config.ui.hex_group, 9);
    }

    #[test]
    fn no_external_file_uses_embedded_defaults() {
        let _iso = Isolated::new();
        let loaded = load_config(None).unwrap();
        assert_eq!(loaded.source_path, None);
        assert_eq!(loaded.config.ui.hex_group, 2);
    }

    #[test]
    fn explicit_cli_path_missing_is_hard_error() {
        let iso = Isolated::new();
        let missing = iso.path().join("nope.yaml");
        let err = config_err(load_config(Some(&missing)));
        assert_contains(&err.message, "not found");
        assert_contains(&err.message, missing.to_str().unwrap());
        assert_eq!(
            err.message,
            format!("config file not found: {}", missing.display())
        );
        assert_eq!(
            err.hint.as_deref(),
            Some("--config must point to an existing file")
        );
    }

    #[test]
    fn explicit_env_path_missing_is_hard_error_even_with_cwd_file() {
        let mut iso = Isolated::new();
        write(&iso.path().join("r2.yaml"), "ui: {hex_group: 8}\n"); // must NOT fall through
        let gone = iso.path().join("gone.yaml");
        iso.env(ENV_VAR, Some(gone.to_str().unwrap()));
        let err = config_err(load_config(None));
        assert_contains(&err.message, "not found");
        assert_eq!(
            err.hint.as_deref(),
            Some("$R2_CONFIG must point to an existing file")
        );
    }

    #[test]
    fn empty_external_file_keeps_defaults() {
        let iso = Isolated::new();
        let empty = write(&iso.path().join("empty.yaml"), "");
        let loaded = load_config(Some(&empty)).unwrap();
        assert_eq!(loaded.source_path, Some(empty));
        assert_eq!(loaded.config.ui.hex_group, 2);
        assert!(loaded.origins.values().all(|v| v == "default"));
    }

    #[test]
    fn external_file_must_be_a_mapping() {
        let iso = Isolated::new();
        let bad = write(&iso.path().join("list.yaml"), "- a\n- b\n");
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "top-level mapping");
        assert_contains(&err.message, bad.to_str().unwrap());
        assert_eq!(
            err.message,
            format!(
                "config file {} must contain a top-level mapping",
                bad.display()
            )
        );
    }

    #[test]
    fn invalid_yaml_is_config_error_with_path() {
        let iso = Isolated::new();
        let bad = write(&iso.path().join("broken.yaml"), "ui: [unclosed\n");
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "invalid YAML");
        assert_contains(&err.message, bad.to_str().unwrap());
        assert!(
            err.message
                .starts_with(&format!("invalid YAML in config file {}: ", bad.display())),
            "{}",
            err.message
        );
    }

    /// c2: `ConfigError` derives from `ConsoleError`; r2 has one error type whose kind is
    /// Config.
    #[test]
    fn config_error_derives_from_console_error() {
        let iso = Isolated::new();
        let err: r2_core::ConsoleError =
            load_config(Some(&iso.path().join("missing.yaml"))).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Config);
        assert_eq!(err.kind.class_name(), "ConfigError");
    }

    // -- r2 additions (§4.8.1) --

    #[test]
    fn empty_env_var_counts_as_unset() {
        let mut iso = Isolated::new();
        let cwd_file = write(&iso.path().join("r2.yaml"), "ui: {hex_group: 8}\n");
        iso.env(ENV_VAR, Some(""));
        assert_eq!(discover(None).unwrap(), Some(cwd_file));
    }

    #[test]
    fn cli_and_env_paths_are_user_expanded() {
        let mut iso = Isolated::new();
        iso.env("HOME", Some(iso.path().to_str().unwrap()));
        let file = write(&iso.path().join("sub/c.yaml"), "ui: {hex_group: 6}\n");
        assert_eq!(home(), iso.path());
        let loaded = load_config(Some(Path::new("~/sub/./c.yaml"))).unwrap();
        assert_eq!(loaded.source_path, Some(file.clone()));
        iso.env(ENV_VAR, Some("~/sub/c.yaml"));
        assert_eq!(discover(None).unwrap(), Some(file));
        let err = discover(Some(Path::new("~/nope.yaml"))).unwrap_err();
        assert_eq!(
            err.message,
            format!(
                "config file not found: {}",
                iso.path().join("nope.yaml").display()
            )
        );
    }

    #[test]
    fn a_directory_is_not_a_config_file() {
        let iso = Isolated::new();
        std::fs::create_dir(iso.path().join("r2.yaml")).unwrap();
        // cwd candidate is a directory → skipped (Path.is_file()), defaults used
        assert_eq!(discover(None).unwrap(), None);
        let err = discover(Some(&iso.path().join("r2.yaml"))).unwrap_err();
        assert_contains(&err.message, "config file not found: ");
    }

    #[test]
    fn cwd_candidate_is_absolute() {
        let iso = Isolated::new();
        write(&iso.path().join("r2.yaml"), "{}\n");
        let found = discover(None).unwrap().unwrap();
        assert!(found.is_absolute());
        assert_eq!(found, std::env::current_dir().unwrap().join("r2.yaml"));
    }

    #[cfg(unix)]
    #[test]
    fn deleted_working_directory_skips_the_cwd_candidate() {
        let iso = Isolated::new();
        let user_file = write(&iso.user_file(), "ui: {hex_group: 9}\n");
        let doomed = iso.path().join("doomed");
        std::fs::create_dir(&doomed).unwrap();
        std::env::set_current_dir(&doomed).unwrap();
        std::fs::remove_dir(&doomed).unwrap();
        assert!(std::env::current_dir().is_err());
        assert_eq!(discover(None).unwrap(), Some(user_file));
    }

    #[test]
    fn top_level_keys_must_be_strings() {
        let iso = Isolated::new();
        let bad = write(&iso.path().join("k.yaml"), "1: a\n");
        let err = config_err(load_config(Some(&bad)));
        assert_eq!(
            err.message,
            format!(
                "config file {}: top-level keys must be strings, got 1",
                bad.display()
            )
        );
    }

    #[test]
    fn invalid_utf8_is_a_read_error() {
        let iso = Isolated::new();
        let bad = iso.path().join("bin.yaml");
        std::fs::write(&bad, b"ui: {hex_group: 4}\n\xff\n").unwrap();
        let err = config_err(load_config(Some(&bad)));
        assert_eq!(
            err.message,
            format!(
                "cannot read config file {}: 'utf-8' codec can't decode byte 0xff in \
                 position 19: invalid start byte",
                bad.display()
            )
        );
    }

    /// A truncated multi-byte sequence is a byte range in CPython's text (maximal subpart).
    #[test]
    fn invalid_utf8_multibyte_ranges() {
        let iso = Isolated::new();
        let cases: &[(&[u8], &str)] = &[
            (
                b"a: \xe2\x82\x41",
                "'utf-8' codec can't decode bytes in position 3-4: invalid continuation byte",
            ),
            (
                b"a: \xf0\x9f\x98A",
                "'utf-8' codec can't decode bytes in position 3-5: invalid continuation byte",
            ),
            (
                b"ab\xf0\x90\x80\x41",
                "'utf-8' codec can't decode bytes in position 2-4: invalid continuation byte",
            ),
            (
                b"\xe2\x82\x28",
                "'utf-8' codec can't decode bytes in position 0-1: invalid continuation byte",
            ),
            (
                b"\xed\xa0\x80",
                "'utf-8' codec can't decode byte 0xed in position 0: invalid continuation byte",
            ),
            (
                b"\xe0\x80\x80",
                "'utf-8' codec can't decode byte 0xe0 in position 0: invalid continuation byte",
            ),
            (
                b"a: \xf0\x90",
                "'utf-8' codec can't decode bytes in position 3-4: unexpected end of data",
            ),
        ];
        for (bytes, text) in cases {
            let bad = iso.path().join("bin.yaml");
            std::fs::write(&bad, bytes).unwrap();
            let err = config_err(load_config(Some(&bad)));
            assert_eq!(
                err.message,
                format!("cannot read config file {}: {text}", bad.display()),
                "{bytes:?}"
            );
        }
    }

    #[test]
    fn crlf_files_load() {
        let iso = Isolated::new();
        let file = iso.path().join("crlf.yaml");
        std::fs::write(&file, b"ui:\r\n  hex_group: 7\r\n").unwrap();
        assert_eq!(load_config(Some(&file)).unwrap().config.ui.hex_group, 7);
    }

    #[test]
    fn user_config_dir_follows_platformdirs() {
        let mut iso = Isolated::new();
        if cfg!(windows) {
            return;
        }
        // platformdirs 4.10.1 XDGMixin (Unix and MacOS): the STRIPPED $XDG_CONFIG_HOME.
        iso.env("XDG_CONFIG_HOME", Some("/xdg/base/"));
        assert_eq!(user_config_dir(), Some(PathBuf::from("/xdg/base/r2")));
        iso.env("XDG_CONFIG_HOME", Some("  /tmp/abc  "));
        assert_eq!(user_config_dir(), Some(PathBuf::from("/tmp/abc/r2")));
        iso.env("XDG_CONFIG_HOME", Some("/tmp/abc\n"));
        assert_eq!(user_config_dir(), Some(PathBuf::from("/tmp/abc/r2")));
        iso.env("XDG_CONFIG_HOME", Some("\u{1f}\u{a0}/tmp/a b\u{2003}\x0b"));
        assert_eq!(user_config_dir(), Some(PathBuf::from("/tmp/a b/r2")));
        let default = if cfg!(target_os = "macos") {
            "/home/tester/Library/Application Support/r2"
        } else {
            "/home/tester/.config/r2"
        };
        iso.env("XDG_CONFIG_HOME", Some("   "));
        iso.env("HOME", Some("/home/tester"));
        assert_eq!(user_config_dir(), Some(PathBuf::from(default)));
        iso.env("XDG_CONFIG_HOME", None);
        assert_eq!(user_config_dir(), Some(PathBuf::from(default)));
    }

    #[test]
    fn user_dir_discovery_uses_stripped_xdg_config_home() {
        let mut iso = Isolated::new();
        if cfg!(windows) {
            return;
        }
        let base = iso.path().join("xdg");
        let user_file = write(&base.join("r2").join(FILE_NAME), "ui: {hex_group: 9}\n");
        iso.env(
            "XDG_CONFIG_HOME",
            Some(&format!("  {}\n", base.to_str().unwrap())),
        );
        let loaded = load_config(None).unwrap();
        assert_eq!(loaded.source_path, Some(user_file));
        assert_eq!(loaded.config.ui.hex_group, 9);
    }

    #[test]
    fn expand_user_is_python_expanduser() {
        let mut iso = Isolated::new();
        iso.env("HOME", Some("/home/tester/"));
        assert_eq!(expand_user("~"), PathBuf::from("/home/tester"));
        assert_eq!(
            expand_user("~/a//b/./c/"),
            PathBuf::from("/home/tester/a/b/c")
        );
        assert_eq!(
            expand_user("~no-such-user-r2/x"),
            PathBuf::from("~no-such-user-r2/x")
        );
        assert_eq!(expand_user("./x/../y"), PathBuf::from("x/../y"));
        assert_eq!(expand_user("a/~/b"), PathBuf::from("a/~/b"));
        assert_eq!(expand_user(""), PathBuf::from("."));
        iso.env("HOME", Some("/"));
        assert_eq!(expand_user("~/x"), PathBuf::from("/x"));
        if cfg!(unix) {
            // posixpath.expanduser: a set-but-empty $HOME is used as is ('' → '/')
            iso.env("HOME", Some(""));
            assert_eq!(expand_user("~/x"), PathBuf::from("/x"));
            assert_eq!(expand_user("~"), PathBuf::from("/"));
            if !cfg!(target_os = "macos") {
                iso.env("XDG_CONFIG_HOME", None);
                assert_eq!(user_config_dir(), Some(PathBuf::from("/.config/r2")));
            }
            iso.env("HOME", Some("//srv//"));
            assert_eq!(expand_user("~/x"), PathBuf::from("//srv/x"));
            iso.env("HOME", Some("rel/home"));
            assert_eq!(expand_user("~/x"), PathBuf::from("rel/home/x"));
        }
    }

    /// `~name/…` is that user's home from /etc/passwd (`pwd.getpwnam`), as in c2.
    #[cfg(target_os = "linux")]
    #[test]
    fn expand_user_resolves_other_users() {
        let _iso = Isolated::new();
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap();
        let root_home = passwd
            .lines()
            .find_map(|line| line.strip_prefix("root:"))
            .map(|rest| rest.split(':').nth(4).unwrap().to_owned())
            .unwrap();
        assert_eq!(
            expand_user("~root/a//b/"),
            PathBuf::from(&root_home).join("a/b")
        );
        assert_eq!(expand_user("~root"), PathBuf::from(&root_home));
    }

    /// A non-UTF-8 `--config` / `$R2_CONFIG` path is used byte for byte (Python keeps the
    /// bytes through surrogateescape).
    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_are_kept() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let mut iso = Isolated::new();
        let file = iso.path().join(OsStr::from_bytes(b"cfg\xff.yaml"));
        std::fs::write(&file, "ui: {hex_width: 7}\n").unwrap();
        let loaded = load_config(Some(&file)).unwrap();
        assert_eq!(loaded.config.ui.hex_width, 7);
        assert_eq!(loaded.source_path.as_deref(), Some(file.as_path()));
        let dotted = iso.path().join(OsStr::from_bytes(b".//cfg\xff.yaml"));
        assert_eq!(discover(Some(&dotted)).unwrap(), Some(file.clone()));
        // `$R2_CONFIG` goes through the same expansion (r2_testkit::set_env takes UTF-8 only).
        iso.env(ENV_VAR, Some("~/missing.yaml"));
        iso.env("HOME", Some("/home/tester"));
        assert_eq!(
            discover(None).unwrap_err().message,
            "config file not found: /home/tester/missing.yaml"
        );
    }
}

// ---- deep merge (§4.8: maps merge, scalars replace, lists replace wholesale) ----------------

mod merge {
    use super::*;

    #[test]
    fn maps_merge_and_scalars_replace() {
        let iso = Isolated::new();
        let external = write(&iso.path().join("c.yaml"), "ui: {hex_group: 4}\n");
        let config = load_config(Some(&external)).unwrap().config;
        assert_eq!(config.ui.hex_group, 4); // replaced
        assert_eq!(config.ui.hex_width, 32); // sibling default survives
        assert_eq!(config.ui.color, ColorMode::Auto);
    }

    #[test]
    fn nested_maps_merge_recursively() {
        let iso = Isolated::new();
        let external = write(&iso.path().join("c.yaml"), "app: {log: {level: debug}}\n");
        let config = load_config(Some(&external)).unwrap().config;
        assert_eq!(config.app.log.level, LogLevel::Debug);
        assert_eq!(config.app.log.max_bytes, 1048576); // deep sibling survives
        assert_eq!(config.app.history_file, expanded(".local/state/r2/history"));
    }

    #[test]
    fn lists_replace_wholesale() {
        let iso = Isolated::new();
        let external = write(
            &iso.path().join("c.yaml"),
            "providers:\n  pkcs11:\n    - name: prodhsm\n      library: /usr/lib/libvendor_pkcs11.so\n\
             softhsm:\n  search_paths:\n    - /only/this/libsofthsm2.so\n",
        );
        let config = load_config(Some(&external)).unwrap().config;
        let names: Vec<&str> = config
            .providers
            .pkcs11
            .iter()
            .map(|inst| inst.name.as_str())
            .collect();
        assert_eq!(names, ["prodhsm"]);
        assert_eq!(config.providers.memory.name, "mem"); // sibling map merged, not replaced
        assert_eq!(
            config.softhsm.search_paths,
            [PathBuf::from("/only/this/libsofthsm2.so")]
        );
        assert_eq!(config.softhsm.provider_name, "softhsm");
    }

    #[test]
    fn template_class_maps_merge() {
        let iso = Isolated::new();
        let external = write(
            &iso.path().join("c.yaml"),
            "templates:\n  pkcs11:\n    aes:\n      CKA_EXTRACTABLE: true\n",
        );
        let config = load_config(Some(&external)).unwrap().config;
        let aes = &config.templates.pkcs11["aes"];
        assert_eq!(aes["CKA_EXTRACTABLE"], AttrValue::Bool(true)); // overridden
        assert_eq!(aes["CKA_TOKEN"], AttrValue::Bool(true)); // default sibling survives
        assert_eq!(config.templates.pkcs11["rsa_private"].len(), 7); // other classes untouched
    }

    #[test]
    fn pkcs11_instance_full_shape() {
        let iso = Isolated::new();
        let external = write(
            &iso.path().join("c.yaml"),
            "providers:\n  pkcs11:\n    - name: prodhsm\n      library: \"~/lib/libvendor.so\"\n\
             \x20     slot: 3\n      token_label: PROD\n      env: {VENDOR_HOME: /opt/vendor}\n",
        );
        let instance = load_config(Some(&external))
            .unwrap()
            .config
            .providers
            .pkcs11[0]
            .clone();
        assert_eq!(instance.name, "prodhsm");
        assert_eq!(instance.library, expanded("lib/libvendor.so"));
        assert_eq!(instance.slot, Some(3));
        assert_eq!(instance.token_label.as_deref(), Some("PROD"));
        assert_eq!(
            instance.env.into_iter().collect::<Vec<_>>(),
            [("VENDOR_HOME".to_owned(), "/opt/vendor".to_owned())]
        );
    }

    #[test]
    fn pkcs11_instance_optional_fields_default() {
        let iso = Isolated::new();
        let external = write(
            &iso.path().join("c.yaml"),
            "providers: {pkcs11: [{name: hsm1, library: /lib/p11.so}]}\n",
        );
        let instance = load_config(Some(&external))
            .unwrap()
            .config
            .providers
            .pkcs11[0]
            .clone();
        assert_eq!(instance.slot, None);
        assert_eq!(instance.token_label, None);
        assert!(instance.env.is_empty());
        assert_eq!(instance, Pkcs11InstanceConfig::new("hsm1", "/lib/p11.so"));
    }

    // -- r2 additions --

    #[test]
    fn deep_merge_semantics() {
        let base = yaml::parse("a: {x: 1, y: [1, 2], z: {k: v}}\nb: 2\n").unwrap();
        let overlay = yaml::parse("a: {y: [3], z: 5, n: new}\nc: 3\n").unwrap();
        let merged = deep_merge(&base, &overlay);
        assert_eq!(
            yaml::dump(&merged),
            "a:\n  x: 1\n  y:\n  - 3\n  z: 5\n  n: new\nb: 2\nc: 3\n"
        );
        // a mapping replaces a scalar wholesale, and vice versa
        let merged = deep_merge(
            &yaml::parse("a: 1").unwrap(),
            &yaml::parse("a: {b: 2}").unwrap(),
        );
        assert_eq!(yaml::dump(&merged), "a:\n  b: 2\n");
        let merged = deep_merge(
            &yaml::parse("a: {b: 2}").unwrap(),
            &yaml::parse("a: null").unwrap(),
        );
        assert_eq!(yaml::dump(&merged), "a: null\n");
    }

    #[test]
    fn config_from_yaml_has_no_file_suffix() {
        let config = config_from_yaml(Some("ui: {hex_group: 3}")).unwrap();
        assert_eq!(config.ui.hex_group, 3);
        let err = config_from_yaml(Some("ui: {hex_group: x}")).unwrap_err();
        assert_eq!(err.message, "ui.hex_group: expected an integer, got str");
        assert_eq!(
            config_from_yaml(Some("")).unwrap(),
            config_from_yaml(None).unwrap()
        );
        assert_eq!(
            config_from_yaml(Some("- a")).unwrap_err().message,
            "config text must contain a top-level mapping"
        );
    }
}

// ---- LoadedConfig.origins provenance (§4.8) --------------------------------------------------

mod origins {
    use super::*;

    #[test]
    fn overridden_sections_carry_source_path() {
        let iso = Isolated::new();
        let external = write(
            &iso.path().join("c.yaml"),
            "ui: {hex_group: 4}\nsofthsm: {autodetect: false}\n",
        );
        let loaded = load_config(Some(&external)).unwrap();
        let shown = external.to_str().unwrap();
        assert_eq!(loaded.source_path.as_deref(), Some(external.as_path()));
        assert_eq!(loaded.origins["ui"], shown);
        assert_eq!(loaded.origins["softhsm"], shown);
        for section in ["app", "providers", "templates", "custom_mechanisms"] {
            assert_eq!(loaded.origins[section], "default");
        }
    }

    #[test]
    fn origins_cover_every_top_level_section() {
        let _iso = Isolated::new();
        let loaded = load_config(None).unwrap();
        let mut sections: Vec<&str> = loaded.origins.keys().map(String::as_str).collect();
        // r2: in defaults order (= CONFIG_SECTIONS)
        assert_eq!(sections, CONFIG_SECTIONS);
        sections.sort_unstable();
        assert_eq!(
            sections,
            [
                "app",
                "custom_mechanisms",
                "providers",
                "softhsm",
                "templates",
                "ui"
            ]
        );
    }

    #[test]
    fn partial_section_override_still_attributed_to_file() {
        let iso = Isolated::new();
        let external = write(&iso.path().join("c.yaml"), "app: {log: {level: warning}}\n");
        let loaded = load_config(Some(&external)).unwrap();
        assert_eq!(loaded.origins["app"], external.to_str().unwrap()); // merged, but sourced from the file
    }

    #[test]
    fn unknown_top_level_sections_get_no_origin() {
        let iso = Isolated::new();
        let external = write(&iso.path().join("c.yaml"), "uii: {color: always}\n");
        let (loaded, _) = config_warnings(|| load_config(Some(&external)));
        let loaded = loaded.unwrap();
        assert_eq!(loaded.origins.len(), 6);
        assert!(!loaded.origins.contains_key("uii"));
    }
}

// ---- path-aware schema errors (§4.8) ---------------------------------------------------------

mod schema_errors {
    use super::*;

    #[test]
    fn error_carries_dotted_path_and_file() {
        let iso = Isolated::new();
        let bad = write(&iso.path().join("bad.yaml"), "ui: {hex_group: lots}\n");
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "ui.hex_group");
        assert_contains(&err.message, bad.to_str().unwrap());
        assert_eq!(
            err.message,
            format!(
                "ui.hex_group: expected an integer, got str (config file: {})",
                bad.display()
            )
        );
    }

    #[test]
    fn missing_required_key_lists_indexed_path() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("bad.yaml"),
            "providers: {pkcs11: [{name: hsm1}]}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "providers.pkcs11[0].library");
    }

    #[test]
    fn section_type_violation() {
        let iso = Isolated::new();
        let bad = write(&iso.path().join("bad.yaml"), "ui: 5\n");
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "ui: expected a mapping");
    }

    #[test]
    fn bad_enum_value_lists_choices() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("bad.yaml"),
            "app: {log: {level: chatty}}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "app.log.level");
        let hint = err.hint.expect("hint");
        assert_contains(&hint, "debug, info, warning, error");
    }

    #[test]
    fn invalid_template_hex_value() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("bad.yaml"),
            "templates: {pkcs11: {aes: {CKA_X: '0xzz'}}}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "templates.pkcs11.aes.CKA_X");
    }

    #[test]
    fn invalid_template_value_type() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("bad.yaml"),
            "templates: {pkcs11: {aes: {CKA_X: [1, 2]}}}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "templates.pkcs11.aes.CKA_X");
    }

    #[test]
    fn env_values_must_be_strings() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("bad.yaml"),
            "providers: {pkcs11: [{name: h, library: /l.so, env: {FOO: 1}}]}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "providers.pkcs11[0].env.FOO");
    }

    #[test]
    fn enum_param_requires_choices() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("bad.yaml"),
            "custom_mechanisms:\n  - id: vendor.x\n    verb: sign\n    algorithm: aes\n\
             \x20   cli_name: x\n    label: X\n    ckm: 0x80000001\n    params:\n\
             \x20     - {name: mode, kind: enum, prompt: \"Mode\"}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "custom_mechanisms[0].params[0].choices");
    }

    #[test]
    fn bad_verb_value() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("bad.yaml"),
            "custom_mechanisms:\n  - {id: v.x, verb: encipher, algorithm: aes, cli_name: x, label: X, ckm: 0x80000001}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "custom_mechanisms[0].verb");
    }

    #[test]
    fn defaults_only_error_has_no_file_suffix() {
        let err = AppConfig::from_value(&Value::Mapping(Default::default()), "").unwrap_err();
        assert!(!err.message.contains("config file")); // loader adds that, model doesn't
        assert_eq!(err.message, "custom_mechanisms: required key missing");
    }

    /// Every c2 decoder message + hint, generated by running c2's `AppConfig.from_dict` on
    /// the same merged documents (tests/support/gen_yaml_vectors.py).
    #[test]
    fn decoder_messages_match_c2() {
        for (text, message, hint) in vectors::CONFIG_ERRORS {
            let (result, _) = config_warnings(|| config_from_yaml(Some(text)));
            let err = result.unwrap_err();
            assert_eq!(err.kind, ErrorKind::Config, "{text:?}");
            assert_eq!(err.message, *message, "{text:?}");
            assert_eq!(err.hint.as_deref(), *hint, "{text:?}");
        }
    }

    #[test]
    fn decode_error_keeps_hint_with_file_suffix() {
        let iso = Isolated::new();
        let bad = write(&iso.path().join("bad.yaml"), "ui: {color: rainbow}\n");
        let err = config_err(load_config(Some(&bad)));
        assert_eq!(
            err.message,
            format!(
                "ui.color: invalid value 'rainbow' (config file: {})",
                bad.display()
            )
        );
        assert_eq!(
            err.hint.as_deref(),
            Some("valid values: auto, always, never")
        );
    }

    // -- §11 D18: r2's load-time range and typing guards --

    #[test]
    fn negative_slot_is_rejected() {
        let err = config_from_yaml(Some(
            "providers: {pkcs11: [{name: h, library: /l.so, slot: -1}]}",
        ))
        .unwrap_err();
        assert_eq!(
            err.message,
            "providers.pkcs11[0].slot: must not be negative"
        );
    }

    #[test]
    fn negative_template_ulong_is_rejected() {
        let err =
            config_from_yaml(Some("templates: {pkcs11: {aes: {CKA_VALUE_LEN: -1}}}")).unwrap_err();
        assert_eq!(
            err.message,
            "templates.pkcs11.aes.CKA_VALUE_LEN: must not be negative"
        );
    }

    #[test]
    fn out_of_range_unsigned_fields_are_rejected() {
        let err = config_from_yaml(Some("app: {log: {backups: 4294967296}}")).unwrap_err();
        assert_eq!(err.message, "app.log.backups: must be at most 4294967295");
        let config = config_from_yaml(Some("app: {log: {backups: 4294967295}}")).unwrap();
        assert_eq!(config.app.log.backups, u32::MAX);
    }

    #[test]
    fn integers_outside_u64_are_yaml_errors() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("big.yaml"),
            "app: {log: {max_bytes: 18446744073709551616}}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert_eq!(
            err.message,
            format!(
                "invalid YAML in config file {}: integer out of range: 18446744073709551616",
                bad.display()
            )
        );
    }

    /// PyYAML's reader rejects a NUL (and other non-printable characters) before parsing;
    /// the text after it is not silently dropped.
    #[test]
    fn non_printable_character_is_a_yaml_error() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("nul.yaml"),
            "ui: {hex_group: 5}\n\u{0}\nui: {hex_group: 9}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert_eq!(
            err.message,
            format!(
                "invalid YAML in config file {}: unacceptable character #x0000: special \
                 characters are not allowed\n  in \"<unicode string>\", position 19",
                bad.display()
            )
        );
    }

    /// A block-scalar template value on the last line of a file without a final newline
    /// has no trailing break (PyYAML), with or without one.
    #[test]
    fn block_scalar_at_end_of_file_keeps_pyyaml_value() {
        for text in [
            "templates:\n  pkcs11:\n    data:\n      CKA_LABEL: |\n        hello",
            "templates:\n  pkcs11:\n    data:\n      CKA_LABEL: |-\n        hello\n",
        ] {
            let config = config_from_yaml(Some(text)).unwrap();
            assert_eq!(
                config.templates.pkcs11_raw["data"]["CKA_LABEL"],
                Value::String("hello".to_owned()),
                "{text:?}"
            );
        }
    }

    #[test]
    fn library_existence_is_not_checked() {
        let config = config_from_yaml(Some(
            "providers: {pkcs11: [{name: h, library: /does/not/exist.so}]}",
        ))
        .unwrap();
        assert_eq!(
            config.providers.pkcs11[0].library,
            PathBuf::from("/does/not/exist.so")
        );
    }
}

// ---- unknown-key warnings with suggestions (§4.8) --------------------------------------------

mod unknown_key_warnings {
    use super::*;

    #[test]
    fn typo_warns_with_suggestion_and_is_ignored() {
        let iso = Isolated::new();
        let external = write(&iso.path().join("c.yaml"), "ui: {hex_widht: 16}\n");
        let (loaded, warnings) = config_warnings(|| load_config(Some(&external)));
        assert_eq!(loaded.unwrap().config.ui.hex_width, 32); // typo ignored, default kept
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("ui.hex_widht") && w.contains("hex_width")),
            "{warnings:?}"
        );
        assert_eq!(
            warnings,
            ["unknown config key 'ui.hex_widht' (did you mean 'hex_width'?)"]
        );
    }

    #[test]
    fn unknown_top_level_key_warns() {
        let iso = Isolated::new();
        let external = write(&iso.path().join("c.yaml"), "uii: {color: always}\n");
        let (_, warnings) = config_warnings(|| load_config(Some(&external)));
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("'uii'") && w.contains("'ui'")),
            "{warnings:?}"
        );
    }

    #[test]
    fn unknown_template_class_key_warns() {
        let iso = Isolated::new();
        let external = write(
            &iso.path().join("c.yaml"),
            "templates: {pkcs11: {rsa_privte: {CKA_X: true}}}\n",
        );
        let (loaded, warnings) = config_warnings(|| load_config(Some(&external)));
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("rsa_privte") && w.contains("'rsa_private'")),
            "{warnings:?}"
        );
        assert_eq!(
            warnings,
            [
                "unknown template class key 'templates.pkcs11.rsa_privte' (did you mean 'rsa_private'?)"
            ]
        );
        // unknown class keys are kept
        assert!(
            loaded
                .unwrap()
                .config
                .templates
                .pkcs11
                .contains_key("rsa_privte")
        );
    }

    #[test]
    fn unknown_key_without_close_match_has_no_suggestion() {
        let (_, warnings) = config_warnings(|| config_from_yaml(Some("ui: {zzzzzz: 1}")));
        assert_eq!(warnings, ["unknown config key 'ui.zzzzzz'"]);
    }
}

// ---- TemplatesSection.default_template (§4.8 via the §4.7 kind-inference rule) ---------------

/// (key_class, algorithm, expected CKA_CLASS, expected CKA_KEY_TYPE, §7 attr names)
type ClassCase = (
    KeyClass,
    KeyAlgorithm,
    &'static str,
    Option<&'static str>,
    &'static [&'static str],
);
const CLASS_CASES: &[ClassCase] = &[
    (
        KeyClass::Secret,
        KeyAlgorithm::Aes,
        "CKO_SECRET_KEY",
        Some("CKK_AES"),
        &[
            "CKA_TOKEN",
            "CKA_PRIVATE",
            "CKA_SENSITIVE",
            "CKA_EXTRACTABLE",
            "CKA_ENCRYPT",
            "CKA_DECRYPT",
            "CKA_SIGN",
            "CKA_VERIFY",
            "CKA_WRAP",
            "CKA_UNWRAP",
        ],
    ),
    (
        KeyClass::Private,
        KeyAlgorithm::Rsa,
        "CKO_PRIVATE_KEY",
        Some("CKK_RSA"),
        &[
            "CKA_TOKEN",
            "CKA_PRIVATE",
            "CKA_SENSITIVE",
            "CKA_EXTRACTABLE",
            "CKA_DECRYPT",
            "CKA_SIGN",
            "CKA_UNWRAP",
        ],
    ),
    (
        KeyClass::Public,
        KeyAlgorithm::Rsa,
        "CKO_PUBLIC_KEY",
        Some("CKK_RSA"),
        &[
            "CKA_TOKEN",
            "CKA_PRIVATE",
            "CKA_ENCRYPT",
            "CKA_VERIFY",
            "CKA_WRAP",
        ],
    ),
    (
        KeyClass::Private,
        KeyAlgorithm::Ec,
        "CKO_PRIVATE_KEY",
        Some("CKK_EC"),
        &[
            "CKA_TOKEN",
            "CKA_PRIVATE",
            "CKA_SENSITIVE",
            "CKA_EXTRACTABLE",
            "CKA_SIGN",
            "CKA_DERIVE",
        ],
    ),
    (
        KeyClass::Private,
        KeyAlgorithm::EcEdwards,
        "CKO_PRIVATE_KEY",
        Some("CKK_EC_EDWARDS"),
        &[
            "CKA_TOKEN",
            "CKA_PRIVATE",
            "CKA_SENSITIVE",
            "CKA_EXTRACTABLE",
            "CKA_SIGN",
            "CKA_DERIVE",
        ],
    ),
    (
        KeyClass::Private,
        KeyAlgorithm::EcMontgomery,
        "CKO_PRIVATE_KEY",
        Some("CKK_EC_MONTGOMERY"),
        &[
            "CKA_TOKEN",
            "CKA_PRIVATE",
            "CKA_SENSITIVE",
            "CKA_EXTRACTABLE",
            "CKA_SIGN",
            "CKA_DERIVE",
        ],
    ),
    (
        KeyClass::Public,
        KeyAlgorithm::Ec,
        "CKO_PUBLIC_KEY",
        Some("CKK_EC"),
        &["CKA_TOKEN", "CKA_PRIVATE", "CKA_VERIFY", "CKA_DERIVE"],
    ),
    (
        KeyClass::Secret,
        KeyAlgorithm::Generic,
        "CKO_SECRET_KEY",
        Some("CKK_GENERIC_SECRET"),
        &[
            "CKA_TOKEN",
            "CKA_PRIVATE",
            "CKA_SENSITIVE",
            "CKA_EXTRACTABLE",
            "CKA_SIGN",
            "CKA_VERIFY",
            "CKA_DERIVE",
        ],
    ),
    // certificates and data objects have no CKA_KEY_TYPE row (§4.8)
    (
        KeyClass::Certificate,
        KeyAlgorithm::Rsa,
        "CKO_CERTIFICATE",
        None,
        &["CKA_TOKEN", "CKA_PRIVATE"],
    ),
    (
        KeyClass::Data,
        KeyAlgorithm::None,
        "CKO_DATA",
        None,
        &["CKA_TOKEN", "CKA_PRIVATE"],
    ),
];

fn empty_templates() -> TemplatesSection {
    TemplatesSection {
        pkcs11: Default::default(),
        pkcs11_raw: Default::default(),
        custom_attributes: Default::default(),
    }
}

mod default_template {
    use super::*;

    #[test]
    fn every_spec7_class_builds_the_right_template() {
        let templates = config_from_yaml(None).unwrap().templates;
        for (key_class, algorithm, cko, ckk, names) in CLASS_CASES {
            let template = templates.default_template(*key_class, *algorithm).unwrap();
            let head = &template.attrs[0];
            assert_eq!(
                (head.name.as_str(), &head.value, head.kind),
                (
                    "CKA_CLASS",
                    &AttrValue::Symbol((*cko).to_owned()),
                    AttrKind::Ulong
                )
            );
            assert!(head.locked && head.enabled);
            let mut locked = 1;
            if let Some(ckk) = ckk {
                let key_type = &template.attrs[1];
                assert_eq!(
                    (key_type.name.as_str(), &key_type.value, key_type.kind),
                    (
                        "CKA_KEY_TYPE",
                        &AttrValue::Symbol((*ckk).to_owned()),
                        AttrKind::Ulong
                    )
                );
                assert!(key_type.locked && key_type.enabled);
                locked = 2;
            } else {
                // certificates / data objects: CKA_CLASS is the only locked row
                assert!(template.attrs.iter().all(|a| a.name != "CKA_KEY_TYPE"));
            }
            let tail: Vec<&str> = template.attrs[locked..]
                .iter()
                .map(|a| a.name.as_str())
                .collect();
            assert_eq!(tail, *names, "{key_class:?} {algorithm:?}");
            assert!(template.attrs.iter().all(|a| a.enabled));
            assert!(template.attrs[locked..].iter().all(|a| !a.locked));
            assert!(
                template.attrs[locked..]
                    .iter()
                    .all(|a| a.kind == AttrKind::Bool)
            ); // §7 bools
        }
    }

    #[test]
    fn secure_defaults_for_aes() {
        let templates = config_from_yaml(None).unwrap().templates;
        let template = templates
            .default_template(KeyClass::Secret, KeyAlgorithm::Aes)
            .unwrap();
        assert_eq!(
            template.get("CKA_EXTRACTABLE").unwrap().value,
            AttrValue::Bool(false)
        );
        assert_eq!(
            template.get("CKA_SENSITIVE").unwrap().value,
            AttrValue::Bool(true)
        );
    }

    #[test]
    fn kind_inference_rule() {
        let section = TemplatesSection::from_value(
            &yaml::parse(
                "pkcs11:\n  aes:\n    CKA_TOKEN: true\n    CKA_VALUE_LEN: 32\n    CKA_ID: '0x0a1b'\n\
                 \x20   CKA_LABEL: hello\ncustom_attributes: {}\n",
            )
            .unwrap(),
            "templates",
        )
        .unwrap();
        let template = section
            .default_template(KeyClass::Secret, KeyAlgorithm::Aes)
            .unwrap();
        let get = |name: &str| template.get(name).unwrap();
        assert_eq!(get("CKA_TOKEN").kind, AttrKind::Bool);
        assert_eq!(get("CKA_TOKEN").value, AttrValue::Bool(true));
        assert_eq!(get("CKA_VALUE_LEN").kind, AttrKind::Ulong);
        assert_eq!(get("CKA_VALUE_LEN").value, AttrValue::Ulong(32));
        assert_eq!(get("CKA_ID").kind, AttrKind::Bytes);
        assert_eq!(get("CKA_ID").value, AttrValue::Bytes(vec![0x0a, 0x1b]));
        assert_eq!(get("CKA_LABEL").kind, AttrKind::Str);
        assert_eq!(get("CKA_LABEL").value, AttrValue::Str("hello".to_owned()));
    }

    #[test]
    fn templates_are_fresh_per_call() {
        let templates = config_from_yaml(None).unwrap().templates;
        let mut first = templates
            .default_template(KeyClass::Secret, KeyAlgorithm::Aes)
            .unwrap();
        first.set("CKA_EXTRACTABLE", AttrValue::Bool(true)).unwrap();
        first.attrs[0].enabled = false;
        let second = templates
            .default_template(KeyClass::Secret, KeyAlgorithm::Aes)
            .unwrap();
        assert_eq!(
            second.get("CKA_EXTRACTABLE").unwrap().value,
            AttrValue::Bool(false)
        );
        assert!(second.attrs[0].enabled);
    }

    #[test]
    fn missing_class_key_yields_just_locked_rows() {
        let section = empty_templates();
        let template = section
            .default_template(KeyClass::Public, KeyAlgorithm::Rsa)
            .unwrap();
        let names: Vec<&str> = template.attrs.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["CKA_CLASS", "CKA_KEY_TYPE"]);
    }

    /// Accept: `default_template` is correct for all eight class keys, including the
    /// inferred kinds of non-bool values and the class keys of every (class, algorithm).
    #[test]
    fn all_eight_class_keys_take_their_section() {
        let mut text = String::from("templates:\n  pkcs11:\n");
        for key in TEMPLATE_CLASS_KEYS {
            text.push_str(&format!(
                "    {key}: {{CKA_LABEL: {key}, CKA_X: 0x01, CKA_N: 7}}\n"
            ));
        }
        let templates = config_from_yaml(Some(&text)).unwrap().templates;
        let cases = [
            (KeyClass::Secret, KeyAlgorithm::Aes, "aes"),
            (KeyClass::Private, KeyAlgorithm::Rsa, "rsa_private"),
            (KeyClass::Public, KeyAlgorithm::Rsa, "rsa_public"),
            (KeyClass::Private, KeyAlgorithm::EcMontgomery, "ec_private"),
            (KeyClass::Public, KeyAlgorithm::EcEdwards, "ec_public"),
            (KeyClass::Certificate, KeyAlgorithm::Other, "certificate"),
            (KeyClass::Secret, KeyAlgorithm::Generic, "generic_secret"),
            (KeyClass::Data, KeyAlgorithm::Aes, "data"),
        ];
        for (class, algorithm, key) in cases {
            assert_eq!(template_class_key(class, algorithm).unwrap(), key);
            let template = templates.default_template(class, algorithm).unwrap();
            assert_eq!(
                template.get("CKA_LABEL").unwrap().value,
                AttrValue::Str(key.to_owned())
            );
            // plain 0x01 is a YAML int (1) → ULONG; the class's §7 bools come first
            assert_eq!(template.get("CKA_X").unwrap().value, AttrValue::Ulong(1));
            assert_eq!(template.get("CKA_N").unwrap().kind, AttrKind::Ulong);
        }
    }
}

// ---- cross-checks + custom mechanisms (§4.8) -------------------------------------------------

mod cross_checks {
    use super::*;

    #[test]
    fn duplicate_provider_name_is_error() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("bad.yaml"),
            "providers: {pkcs11: [{name: mem, library: /l.so}]}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert!(err.message.starts_with("providers.pkcs11[0].name"));
        assert_contains(&err.message, "duplicate");
    }

    #[test]
    fn duplicate_between_pkcs11_instances_is_error() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("bad.yaml"),
            "providers: {pkcs11: [{name: h, library: /a.so}, {name: h, library: /b.so}]}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert!(err.message.starts_with("providers.pkcs11[1].name"));
        assert_contains(&err.message, "duplicate");
    }

    #[test]
    fn provider_name_grammar_enforced() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("bad.yaml"),
            "providers: {pkcs11: [{name: 1bad, library: /l.so}]}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "providers.pkcs11[0].name");
    }

    #[test]
    fn memory_name_grammar_enforced() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("bad.yaml"),
            "providers: {memory: {name: \"bad name\"}}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "providers.memory.name");
    }

    #[test]
    fn custom_mechanism_providers_must_be_defined() {
        let iso = Isolated::new();
        let bad = write(
            &iso.path().join("bad.yaml"),
            "custom_mechanisms:\n  - {id: v.x, verb: sign, algorithm: aes, cli_name: x, label: X,\n\
             \x20    ckm: 0x80000001, providers: [ghosthsm]}\n",
        );
        let err = config_err(load_config(Some(&bad)));
        assert_contains(&err.message, "custom_mechanisms[0].providers");
        assert_contains(&err.message, "ghosthsm");
    }

    #[test]
    fn softhsm_provider_name_counts_as_defined() {
        let iso = Isolated::new();
        let good = write(
            &iso.path().join("good.yaml"),
            "custom_mechanisms:\n  - {id: v.x, verb: sign, algorithm: aes, cli_name: x, label: X,\n\
             \x20    ckm: 0x80000001, providers: [softhsm]}\n",
        );
        let config = load_config(Some(&good)).unwrap().config;
        assert_eq!(
            config.custom_mechanisms[0].providers,
            Some(vec!["softhsm".to_owned()])
        );
    }

    #[test]
    fn disabled_memory_name_still_counts() {
        let err = config_from_yaml(Some(
            "providers: {memory: {enabled: false}, pkcs11: [{name: mem, library: /l.so}]}",
        ))
        .unwrap_err();
        assert_eq!(
            err.message,
            "providers.pkcs11[0].name: duplicate provider name 'mem'"
        );
    }
}

mod custom_mechanisms {
    use super::*;

    #[test]
    fn spec_5_14_example_parses() {
        let iso = Isolated::new();
        let good = write(
            &iso.path().join("good.yaml"),
            "providers:\n  pkcs11:\n    - name: prodhsm\n      library: /usr/lib/libvendor_pkcs11.so\n\
             custom_mechanisms:\n  - id: vendor.acme.kcv\n    verb: sign\n    algorithm: aes\n\
             \x20   cli_name: acme-kcv\n    label: \"ACME key check value\"\n    ckm: 0x80000A01\n\
             \x20   param_struct: none\n    params:\n\
             \x20     - {name: rounds, kind: int, prompt: \"KCV rounds\", required: false, default: 1}\n\
             \x20   providers: [prodhsm]\n",
        );
        let (loaded, warnings) = config_warnings(|| load_config(Some(&good)));
        let config = loaded.unwrap().config;
        let mech = &config.custom_mechanisms[0];
        assert_eq!(mech.id, "vendor.acme.kcv");
        assert_eq!(mech.verb, Verb::Sign);
        assert_eq!(mech.algorithm, KeyAlgorithm::Aes);
        assert_eq!(mech.cli_name, "acme-kcv");
        assert_eq!(mech.label, "ACME key check value");
        assert_eq!(mech.ckm, 0x80000A01);
        assert_eq!(mech.param_struct, ParamStruct::None);
        assert_eq!(mech.provider_types, None); // r2-ops defaults this to ["pkcs11"]
        assert_eq!(mech.providers, Some(vec!["prodhsm".to_owned()]));
        let param = &mech.params[0];
        assert_eq!(param.name, "rounds");
        assert_eq!(param.kind, ParamKind::Int);
        assert_eq!(param.prompt, "KCV rounds");
        assert!(!param.required);
        assert_eq!(param.default, Some(ParamValue::Int(1)));
        assert_eq!(param.choices, None);
        assert_eq!(warnings, Vec::<String>::new()); // vendor-range CKM: no warning
    }

    #[test]
    fn non_vendor_ckm_warns() {
        let iso = Isolated::new();
        let external = write(
            &iso.path().join("c.yaml"),
            "custom_mechanisms:\n  - {id: v.x, verb: sign, algorithm: aes, cli_name: x, label: X, ckm: 0x1234}\n",
        );
        let (loaded, warnings) = config_warnings(|| load_config(Some(&external)));
        let mech = loaded.unwrap().config.custom_mechanisms[0].clone();
        assert_eq!(mech.ckm, 0x1234);
        assert_eq!(mech.params, vec![]);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("custom_mechanisms[0].ckm") && w.contains("0x80000000")),
            "{warnings:?}"
        );
        assert_eq!(
            warnings,
            [
                "custom_mechanisms[0].ckm: CKM code 0x00001234 is below the vendor-defined range \
                 (>= 0x80000000)"
            ]
        );
    }

    #[test]
    fn custom_attributes_parse_with_explicit_kind() {
        let iso = Isolated::new();
        let external = write(
            &iso.path().join("c.yaml"),
            "templates: {custom_attributes: {CKA_ACME_USAGE: {code: 0x80000101, kind: bytes}}}\n",
        );
        let config = load_config(Some(&external)).unwrap().config;
        assert_eq!(
            config
                .templates
                .custom_attributes
                .into_iter()
                .collect::<Vec<_>>(),
            [(
                "CKA_ACME_USAGE".to_owned(),
                CustomAttributeDef {
                    code: 0x80000101,
                    kind: AttrKind::Bytes
                }
            )]
        );
    }

    fn param(extra: &str) -> r2_core::Result<ParamSpecConfig> {
        ParamSpecConfig::from_value(
            &yaml::parse(&format!("{{name: p, prompt: P, {extra}}}")).unwrap(),
            "custom_mechanisms[0].params[0]",
        )
    }

    /// §4.8.3 / §11 D18: defaults are typed at load by kind.
    #[test]
    fn param_defaults_are_typed_by_kind() {
        let p = param("kind: bytes, default: hex:0A0B").unwrap();
        assert_eq!(p.default, Some(ParamValue::Bytes(vec![0x0a, 0x0b])));
        assert_eq!(p.default_raw, Some(Value::from("hex:0A0B")));
        let p = param("kind: bytes, default: AQID").unwrap();
        assert_eq!(p.default, Some(ParamValue::Bytes(vec![1, 2, 3])));
        let p = param("kind: enum, choices: ['96', '128'], default: 128").unwrap();
        assert_eq!(p.default, Some(ParamValue::Int(128)));
        assert_eq!(p.default_raw, Some(Value::from(128)));
        let p = param("kind: enum, choices: [a], default: zzz").unwrap();
        assert_eq!(p.default, Some(ParamValue::Enum("zzz".to_owned()))); // not checked vs choices
        let p = param("kind: str, default: text").unwrap();
        assert_eq!(p.default, Some(ParamValue::Str("text".to_owned())));
        let p = param("kind: bool, default: yes").unwrap();
        assert_eq!(p.default, Some(ParamValue::Bool(true)));
        let p = param("kind: int, default: -3").unwrap();
        assert_eq!(p.default, Some(ParamValue::Int(-3)));
        for kind in ["bytes", "int", "str", "bool", "keyref"] {
            let p = param(&format!("kind: {kind}, default: null")).unwrap();
            assert_eq!((p.default, p.default_raw), (None, None), "{kind}");
            let p = param(&format!("kind: {kind}")).unwrap();
            assert_eq!(p.default, None);
            assert!(p.required);
        }
        let err = param("kind: keyref, default: mem:k").unwrap_err();
        assert_eq!(
            err.message,
            "custom_mechanisms[0].params[0].default: keyref parameters cannot have a default"
        );
        let err = param("kind: int, default: '1'").unwrap_err();
        assert_eq!(
            err.message,
            "custom_mechanisms[0].params[0].default: expected a int default, got str"
        );
        let err = param("kind: bool, default: 1").unwrap_err();
        assert_eq!(
            err.message,
            "custom_mechanisms[0].params[0].default: expected a bool default, got int"
        );
        let err = param("kind: bytes, default: 5").unwrap_err();
        assert_eq!(
            err.message,
            "custom_mechanisms[0].params[0].default: expected a bytes default, got int"
        );
        let err = param("kind: bytes, default: 'hex:zz'").unwrap_err();
        assert!(
            err.message
                .starts_with("custom_mechanisms[0].params[0].default: "),
            "{}",
            err.message
        );
        let codec = r2_core::codec::decode_data("hex:zz").unwrap_err();
        assert_eq!(
            err.message,
            format!("custom_mechanisms[0].params[0].default: {}", codec.message)
        );
        assert_eq!(err.kind, ErrorKind::Config);
    }
}

// ---- `config show` (AppConfig::to_value) ----------------------------------------------------

mod config_show {
    use super::*;

    /// `config show` of fixture configs, byte-compared with c2's `_to_plain` + safe_dump
    /// (raw mirrors: `CKA_ID: 0x0A 0B`, `default: hex:0A0B`, `default: AQID`, `default: 128`).
    #[test]
    fn to_value_dumps_like_c2() {
        let mut iso = Isolated::new();
        iso.env("HOME", Some("/home/tester"));
        for (text, expected) in vectors::CONFIG_SHOW {
            let (config, _) = config_warnings(|| config_from_yaml(Some(text)));
            let config = config.unwrap();
            assert_eq!(yaml::dump(&config.to_value()), *expected, "{text:?}");
        }
    }
}

// ---- YAML 1.1 typing of a fixture config (PyYAML parity) --------------------------------------

mod yaml11_fixture {
    use super::*;

    /// Accept: a config using `yes/no`/`on/off` and `0x` values decodes exactly as PyYAML
    /// does (c2 would read the same values).
    #[test]
    fn yes_no_on_off_and_hex_decode_like_pyyaml() {
        let config = config_from_yaml(Some(
            "app:\n  log: {level: warning, max_bytes: 0x100000, backups: 010}\n\
             ui: {color: never, hex_group: 0b100, hex_width: 1_6, confirm_delete: no}\n\
             providers:\n  memory: {enabled: off, name: m_1}\n  pkcs11:\n\
             \x20   - {name: h, library: /l.so, slot: 0x2, token_label: 'yes', env: {A: 'on'}}\n\
             softhsm: {autodetect: Off}\n\
             templates:\n  pkcs11:\n    aes: {CKA_TOKEN: Yes, CKA_X: '0x0A 0B', CKA_Y: 0x0A, CKA_Z: \"no\", CKA_W: 1:30}\n",
        ))
        .unwrap();
        assert_eq!(config.app.log.level, LogLevel::Warning);
        assert_eq!(config.app.log.max_bytes, 0x100000);
        assert_eq!(config.app.log.backups, 8); // YAML 1.1 octal
        assert_eq!(config.ui.color, ColorMode::Never);
        assert_eq!(config.ui.hex_group, 4);
        assert_eq!(config.ui.hex_width, 16);
        assert!(!config.ui.confirm_delete);
        assert!(!config.providers.memory.enabled);
        assert_eq!(config.providers.memory.name, "m_1");
        let inst = &config.providers.pkcs11[0];
        assert_eq!(inst.slot, Some(2));
        assert_eq!(inst.token_label.as_deref(), Some("yes"));
        assert_eq!(inst.env["A"], "on");
        assert!(!config.softhsm.autodetect);
        let aes = &config.templates.pkcs11["aes"];
        assert_eq!(aes["CKA_TOKEN"], AttrValue::Bool(true));
        assert_eq!(aes["CKA_X"], AttrValue::Bytes(vec![0x0a, 0x0b]));
        assert_eq!(aes["CKA_Y"], AttrValue::Ulong(10));
        assert_eq!(aes["CKA_Z"], AttrValue::Str("no".to_owned()));
        assert_eq!(aes["CKA_W"], AttrValue::Ulong(90));
    }

    #[test]
    fn python_type_names() {
        for (text, name) in [
            ("{}", "dict"),
            ("[]", "list"),
            ("a", "str"),
            ("1", "int"),
            ("1.5", "float"),
            ("yes", "bool"),
            ("~", "NoneType"),
            ("2001-01-01", "date"),
            ("2001-01-01 10:00:00", "datetime"),
            ("!!binary AQID", "bytes"),
        ] {
            assert_eq!(
                yaml::python_type_name(&yaml::parse(text).unwrap()),
                name,
                "{text}"
            );
        }
        let err = config_from_yaml(Some(
            "providers: {pkcs11: [{name: h, library: 2001-01-01}]}",
        ))
        .unwrap_err();
        assert_eq!(
            err.message,
            "providers.pkcs11[0].library: expected a string, got date"
        );
    }

    #[test]
    fn as_int_never_coerces() {
        assert_eq!(yaml::as_int(&yaml::parse("17").unwrap()), Some(17));
        assert_eq!(
            yaml::as_int(&yaml::parse("18446744073709551615").unwrap()),
            Some(i128::from(u64::MAX))
        );
        assert_eq!(yaml::as_int(&yaml::parse("-5").unwrap()), Some(-5));
        assert_eq!(yaml::as_int(&yaml::parse("'17'").unwrap()), None);
        assert_eq!(yaml::as_int(&yaml::parse("true").unwrap()), None);
        assert_eq!(yaml::as_int(&yaml::parse("1.0").unwrap()), None);
    }

    #[test]
    fn parse_errors_are_generic() {
        let err = yaml::parse("a: [1").unwrap_err();
        assert_eq!(err.kind, ErrorKind::Generic);
        let err = yaml::parse("!!foo x").unwrap_err();
        assert_eq!(
            err.message,
            "could not determine a constructor for the tag 'tag:yaml.org,2002:foo'"
        );
    }
}

// ---- model value helpers --------------------------------------------------------------------

mod model_values {
    use super::*;

    #[test]
    fn tokens_round_trip() {
        for level in ["debug", "info", "warning", "error"] {
            assert_eq!(level.parse::<LogLevel>().unwrap().to_string(), level);
        }
        for color in ["auto", "always", "never"] {
            assert_eq!(color.parse::<ColorMode>().unwrap().as_str(), color);
        }
        let err = "Info".parse::<LogLevel>().unwrap_err();
        assert_eq!(err.kind, ErrorKind::Config);
        assert_eq!(err.message, "invalid value 'Info'");
        assert_eq!(
            err.hint.as_deref(),
            Some("valid values: debug, info, warning, error")
        );
        let err = "rainbow".parse::<ColorMode>().unwrap_err();
        assert_eq!(
            err.hint.as_deref(),
            Some("valid values: auto, always, never")
        );
    }

    #[test]
    fn pkcs11_instance_new() {
        let inst = Pkcs11InstanceConfig::new("softhsm", "/usr/lib/softhsm/libsofthsm2.so");
        assert_eq!(inst.name, "softhsm");
        assert_eq!(inst.slot, None);
        assert_eq!(inst.token_label, None);
        assert!(inst.env.is_empty());
    }

    #[test]
    fn loader_constants() {
        assert_eq!(loader::ENV_VAR, "R2_CONFIG");
        assert_eq!(loader::FILE_NAME, "r2.yaml");
        assert_eq!(loader::APP_DIR, "r2");
    }
}

// ---- tests/unit/test_config_objects.py (L16: generic_secret / data) ---------------------------

mod config_objects {
    use super::*;

    #[test]
    fn template_class_keys_include_the_new_kinds() {
        assert!(TEMPLATE_CLASS_KEYS.contains(&"generic_secret"));
        assert!(TEMPLATE_CLASS_KEYS.contains(&"data"));
        // the pre-existing prefix order is untouched (hint texts stay stable)
        assert_eq!(
            TEMPLATE_CLASS_KEYS[..6],
            [
                "aes",
                "rsa_private",
                "rsa_public",
                "ec_private",
                "ec_public",
                "certificate",
            ]
        );
    }

    #[test]
    fn template_class_key_branches() {
        assert_eq!(
            template_class_key(KeyClass::Secret, KeyAlgorithm::Generic).unwrap(),
            "generic_secret"
        );
        assert_eq!(
            template_class_key(KeyClass::Data, KeyAlgorithm::None).unwrap(),
            "data"
        );
        // class is checked before algorithm — data objects never depend on it
        assert_eq!(
            template_class_key(KeyClass::Data, KeyAlgorithm::Generic).unwrap(),
            "data"
        );
        assert_eq!(
            template_class_key(KeyClass::Certificate, KeyAlgorithm::Ec).unwrap(),
            "certificate"
        );
        assert_eq!(
            template_class_key(KeyClass::Secret, KeyAlgorithm::Aes).unwrap(),
            "aes"
        );
        let err = template_class_key(KeyClass::Secret, KeyAlgorithm::Other).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
        assert_eq!(
            err.message,
            "other secret objects have no template class key"
        );
        assert_eq!(
            err.hint.as_deref(),
            Some("objects of unsupported key types can be listed and deleted only")
        );
        let err = template_class_key(KeyClass::Private, KeyAlgorithm::None).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
        assert_eq!(
            err.message,
            "none private objects have no template class key"
        );
        // default_template errors as template_class_key
        let err = empty_templates()
            .default_template(KeyClass::Public, KeyAlgorithm::Other)
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    }

    #[test]
    fn default_template_locks_key_type_only_for_key_classes() {
        let section = empty_templates();
        let data = section
            .default_template(KeyClass::Data, KeyAlgorithm::None)
            .unwrap();
        let rows: Vec<(&str, &AttrValue, bool)> = data
            .attrs
            .iter()
            .map(|a| (a.name.as_str(), &a.value, a.locked))
            .collect();
        assert_eq!(
            rows,
            [("CKA_CLASS", &AttrValue::Symbol("CKO_DATA".to_owned()), true)]
        );
        let cert = section
            .default_template(KeyClass::Certificate, KeyAlgorithm::Rsa)
            .unwrap();
        let names: Vec<&str> = cert.attrs.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["CKA_CLASS"]);
        let generic = section
            .default_template(KeyClass::Secret, KeyAlgorithm::Generic)
            .unwrap();
        let rows: Vec<(&str, &AttrValue)> = generic
            .attrs
            .iter()
            .map(|a| (a.name.as_str(), &a.value))
            .collect();
        assert_eq!(
            rows,
            [
                ("CKA_CLASS", &AttrValue::Symbol("CKO_SECRET_KEY".to_owned())),
                (
                    "CKA_KEY_TYPE",
                    &AttrValue::Symbol("CKK_GENERIC_SECRET".to_owned())
                ),
            ]
        );
        assert!(generic.attrs.iter().all(|a| a.locked));
    }

    #[test]
    fn embedded_defaults_carry_generic_and_data_sections() {
        let _iso = Isolated::new();
        let templates = load_config(None).unwrap().config.templates;
        let generic = templates
            .default_template(KeyClass::Secret, KeyAlgorithm::Generic)
            .unwrap();
        let value = |name: &str| generic.get(name).map(|a| a.value.clone());
        assert_eq!(value("CKA_SENSITIVE"), Some(AttrValue::Bool(true)));
        assert_eq!(value("CKA_EXTRACTABLE"), Some(AttrValue::Bool(false)));
        assert_eq!(value("CKA_SIGN"), Some(AttrValue::Bool(true)));
        assert_eq!(value("CKA_VERIFY"), Some(AttrValue::Bool(true)));
        assert_eq!(value("CKA_DERIVE"), Some(AttrValue::Bool(true)));
        assert_eq!(value("CKA_ENCRYPT"), None); // HMAC keys: no cipher usage by default
        let data = templates
            .default_template(KeyClass::Data, KeyAlgorithm::None)
            .unwrap();
        let names: Vec<&str> = data.attrs.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["CKA_CLASS", "CKA_TOKEN", "CKA_PRIVATE"]);
        assert_eq!(
            data.get("CKA_PRIVATE").unwrap().value,
            AttrValue::Bool(true)
        );
    }

    fn entry(algorithm: &str) -> r2_core::Result<CustomMechanismConfig> {
        CustomMechanismConfig::from_value(
            &yaml::parse(&format!(
                "{{id: vendor.acme.x, verb: sign, algorithm: {algorithm}, cli_name: acme-x, \
                 label: ACME X, ckm: 0x80000A01}}"
            ))
            .unwrap(),
            "custom_mechanisms[0]",
        )
    }

    #[test]
    fn custom_mechanism_rejects_listing_only_algorithms() {
        assert_eq!(entry("generic").unwrap().algorithm, KeyAlgorithm::Generic);
        for listing_only in ["none", "other"] {
            let err = entry(listing_only).unwrap_err();
            assert_eq!(err.kind, ErrorKind::Config);
        }
    }
}
