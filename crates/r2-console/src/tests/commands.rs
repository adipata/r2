// help / config / clear / exit command tests via ScriptedIo — the port of c2
// tests/unit/console/test_commands.py (R7). `config path` / `config show --origin` render
// LoadedConfig provenance including the six §7 section origins (spec §4.8/§5.1).
use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::loader::DEFAULTS_YAML;
use r2_config::model::CONFIG_SECTIONS;
use r2_config::yaml::{self, Value};
use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::io::{ConsoleIo, Renderable};
use r2_core::params::ParamSpec;
use r2_testkit::{ScriptedIo, global_state_lock, set_env};
use secrecy::SecretString;

use crate::repl::Flow;
use crate::testing::{CtxBuilder, make_config, run_line};

fn scripted() -> Rc<ScriptedIo> {
    Rc::new(ScriptedIo::empty())
}

fn ctx_for(io: &Rc<ScriptedIo>) -> Rc<crate::context::AppContext> {
    CtxBuilder::new(Rc::clone(io) as Rc<dyn ConsoleIo>).build()
}

// ---------------------------------------------------------------------------
// help
// ---------------------------------------------------------------------------

#[test]
fn test_help_lists_every_command() {
    let io = scripted();
    run_line(&ctx_for(&io), "help").unwrap();
    assert!(
        io.output()
            .iter()
            .any(|line| line.contains("shows its usage"))
    );
    let listing = &io.output()[0];
    assert!(listing.contains("commands"));
    for name in ["help", "exit", "quit", "clear", "config"] {
        assert!(listing.contains(name), "{name}");
    }
    assert!(listing.contains("List commands, or show usage for one command"));
    assert_eq!(io.output()[1], "help <command> shows its usage");
}

#[test]
fn test_help_detail_shows_usage_and_flags() {
    let io = scripted();
    run_line(&ctx_for(&io), "help config").unwrap();
    let output = io.output();
    assert!(
        output
            .iter()
            .any(|s| s.contains("usage: config show [--defaults | --origin] | config path"))
    );
    assert!(
        output
            .iter()
            .any(|s| s.contains("--defaults") && s.contains("--origin"))
    );
    assert_eq!(
        output,
        [
            "usage: config show [--defaults | --origin] | config path",
            "Show the effective configuration and where it came from",
            "flags: --defaults, --origin",
        ]
    );
    // a command without flags prints no flags line
    let io = scripted();
    run_line(&ctx_for(&io), "help exit").unwrap();
    assert_eq!(
        io.output(),
        ["usage: exit", "Leave the console (providers are shut down)"]
    );
}

#[test]
fn test_help_unknown_command_suggests() {
    let err = run_line(&ctx_for(&scripted()), "help confog").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnknownOperation);
    assert_eq!(err.message, "unknown command 'confog'");
    let hint = err.hint.unwrap();
    assert!(hint.contains("config"));
    assert_eq!(hint, "did you mean: config");
    let err = run_line(&ctx_for(&scripted()), "help zzzzzz").unwrap_err();
    assert_eq!(
        err.hint.as_deref(),
        Some("type 'help' for the command list")
    );
}

// ---------------------------------------------------------------------------
// exit / quit / clear
// ---------------------------------------------------------------------------

#[test]
fn test_exit_and_quit_raise_repl_exit() {
    for name in ["exit", "quit"] {
        assert_eq!(run_line(&ctx_for(&scripted()), name).unwrap(), Flow::Exit);
    }
}

#[test]
fn test_clear_falls_back_to_ansi_for_plain_io() {
    let io = scripted();
    run_line(&ctx_for(&io), "clear").unwrap();
    assert_eq!(io.output(), ["\u{1b}[2J\u{1b}[H"]);
}

/// ScriptedIo with its own `clear` (c2 ClearingIO).
struct ClearingIo {
    inner: ScriptedIo,
    cleared: Cell<bool>,
}
impl ConsoleIo for ClearingIo {
    fn prompt(&self, spec: &ParamSpec) -> Result<String> {
        self.inner.prompt(spec)
    }
    fn prompt_secret(&self, text: &str) -> Result<SecretString> {
        self.inner.prompt_secret(text)
    }
    fn prompt_multiline(&self, text: &str) -> Result<String> {
        self.inner.prompt_multiline(text)
    }
    fn select(&self, title: &str, options: &[String]) -> Result<usize> {
        self.inner.select(title, options)
    }
    fn confirm(&self, text: &str, default: bool) -> Result<bool> {
        self.inner.confirm(text, default)
    }
    fn print(&self, renderable: Renderable) {
        self.inner.print(renderable);
    }
    fn print_error(&self, err: &ConsoleError) {
        self.inner.print_error(err);
    }
    fn clear(&self) {
        self.cleared.set(true);
    }
}

#[test]
fn test_clear_uses_io_clear_when_available() {
    let io = Rc::new(ClearingIo {
        inner: ScriptedIo::empty(),
        cleared: Cell::new(false),
    });
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>).build();
    run_line(&ctx, "clear").unwrap();
    assert!(io.cleared.get());
    assert!(io.inner.output().is_empty());
}

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

#[test]
fn test_config_path_with_external_file() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("r2.yaml");
    let io = scripted();
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .source_path(source.clone())
        .build();
    run_line(&ctx, "config path").unwrap();
    assert_eq!(io.output(), [format!("config file: {}", source.display())]);
}

#[test]
fn test_config_path_defaults_only() {
    let io = scripted();
    run_line(&ctx_for(&io), "config path").unwrap();
    let output = io.output();
    assert!(output.contains(&"config file: (none — running on built-in defaults)".to_owned()));
    assert!(output.iter().any(|line| line.contains("$R2_CONFIG")));
    assert_eq!(
        output,
        [
            "config file: (none — running on built-in defaults)",
            "discovery order: --config PATH, $R2_CONFIG, ./r2.yaml, <user config dir>/r2/r2.yaml",
        ]
    );
}

fn mapping_keys(value: &Value) -> Vec<String> {
    value
        .as_mapping()
        .unwrap()
        .keys()
        .map(|k| k.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn test_config_show_dumps_effective_yaml() {
    let io = scripted();
    run_line(&ctx_for(&io), "config show").unwrap();
    let dumped = yaml::parse(&io.output()[0]).unwrap();
    assert_eq!(mapping_keys(&dumped), CONFIG_SECTIONS);
    let memory = &dumped["providers"]["memory"];
    assert_eq!(memory["enabled"], Value::Bool(true));
    assert_eq!(memory["name"], Value::String("mem".to_owned()));
    assert_eq!(mapping_keys(memory), ["enabled", "name"]);
    assert_eq!(yaml::as_int(&dumped["ui"]["hex_width"]), Some(32));
}

/// c2's text through the §7 rename (`/c2/` → `/r2/`, `c2.log` → `r2.log`).
fn c2_to_r2(text: &str) -> String {
    text.replace("/c2/", "/r2/").replace("c2.log", "r2.log")
}

#[test]
fn config_show_is_byte_identical_to_c2() {
    // Vectors: src/tests/fixtures/gen_config_show.py run in c2's venv with
    // HOME=/home/tester (c2's PyYAML safe_dump of `_to_plain(config)`, `.rstrip()`).
    let _lock = global_state_lock();
    let _home = set_env("HOME", Some("/home/tester"));
    let defaults = make_config(None);
    let overrides = make_config(Some(include_str!("fixtures/config_show_overrides.yaml")));
    for (config, expected) in [
        (
            defaults,
            include_str!("fixtures/config_show_defaults.c2.txt"),
        ),
        (
            overrides,
            include_str!("fixtures/config_show_overrides.c2.txt"),
        ),
    ] {
        let io = scripted();
        let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
            .config(config)
            .build();
        run_line(&ctx, "config show").unwrap();
        assert_eq!(io.renderables(), [Renderable::Text(c2_to_r2(expected))]);
    }
}

#[test]
fn test_config_show_origin_renders_all_six_sections() {
    let source = PathBuf::from("/etc/r2.yaml"); // short & never touched — display only
    let mut origins: IndexMap<String, String> = CONFIG_SECTIONS
        .iter()
        .map(|s| ((*s).to_owned(), "default".to_owned()))
        .collect();
    origins.insert("ui".to_owned(), source.display().to_string());
    origins.insert("providers".to_owned(), source.display().to_string());
    let io = scripted();
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .source_path(source.clone())
        .origins(origins)
        .build();
    run_line(&ctx, "config show --origin").unwrap();
    let text = io.text();
    for section in CONFIG_SECTIONS {
        assert!(text.contains(section), "{section}");
    }
    assert_eq!(text.matches("/etc/r2.yaml").count(), 2); // ui + providers overridden
    assert!(text.contains("default"));
    assert!(text.contains("config origins"));
    let Renderable::Table(table) = &io.renderables()[0] else {
        panic!("not a table");
    };
    assert_eq!(table.title.as_deref(), Some("config origins"));
    assert_eq!(table.columns, ["section", "origin"]);
    let rows: Vec<(&str, &str)> = table
        .rows
        .iter()
        .map(|r| (r[0].as_str(), r[1].as_str()))
        .collect();
    assert_eq!(
        rows,
        [
            ("app", "default"),
            ("ui", "/etc/r2.yaml"),
            ("providers", "/etc/r2.yaml"),
            ("softhsm", "default"),
            ("templates", "default"),
            ("custom_mechanisms", "default"),
        ]
    );
}

#[test]
fn config_show_origin_appends_unknown_sections_and_defaults_missing_ones() {
    // c2 `_show_origin`: missing sections → "default"; extra origin keys follow
    let mut origins = IndexMap::new();
    origins.insert("extra".to_owned(), "/x.yaml".to_owned());
    origins.insert("ui".to_owned(), "/x.yaml".to_owned());
    let io = scripted();
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .origins(origins)
        .build();
    run_line(&ctx, "config show --origin").unwrap();
    let Renderable::Table(table) = &io.renderables()[0] else {
        panic!("not a table");
    };
    let rows: Vec<(&str, &str)> = table
        .rows
        .iter()
        .map(|r| (r[0].as_str(), r[1].as_str()))
        .collect();
    assert_eq!(rows[1], ("ui", "/x.yaml"));
    assert_eq!(rows[0], ("app", "default"));
    assert_eq!(rows.last(), Some(&("extra", "/x.yaml")));
    assert_eq!(rows.len(), 7);
}

#[test]
fn test_config_show_defaults_prints_embedded_annotated_yaml() {
    let io = scripted();
    run_line(&ctx_for(&io), "config show --defaults").unwrap();
    let text = &io.output()[0];
    assert!(text.contains("# Policy/usage attributes only.")); // comments survive (§4.8)
    assert!(text.contains("softhsm:"));
    // verbatim: never through the loader
    assert_eq!(
        io.renderables(),
        [Renderable::Text(DEFAULTS_YAML.to_owned())]
    );
}

#[test]
fn test_config_show_defaults_and_origin_conflict() {
    let err = run_line(&ctx_for(&scripted()), "config show --defaults --origin").unwrap_err();
    assert!(err.message.contains("mutually exclusive"));
    assert_eq!(
        err.message,
        "--defaults and --origin are mutually exclusive"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("usage: config show [--defaults | --origin] | config path")
    );
    assert_eq!(err.kind, ErrorKind::Generic);
}

#[test]
fn test_config_unknown_subcommand() {
    let err = run_line(&ctx_for(&scripted()), "config frobnicate").unwrap_err();
    assert!(err.message.contains("unknown config subcommand"));
    assert_eq!(err.message, "unknown config subcommand 'frobnicate'");
    assert_eq!(
        err.hint.as_deref(),
        Some("usage: config show [--defaults | --origin] | config path")
    );
}

#[test]
fn test_config_bare_defaults_to_show() {
    let io = scripted();
    run_line(&ctx_for(&io), "config").unwrap();
    assert!(!yaml::parse(&io.output()[0]).unwrap().is_null());
    let shown = scripted();
    run_line(&ctx_for(&shown), "config show").unwrap();
    assert_eq!(io.output(), shown.output());
}
