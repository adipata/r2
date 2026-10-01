//! Interaction-trait tests (spec §4.9.1) — the c2 `tests/unit/core/test_io_protocols.py`
//! layering case. (Its two structural Protocol checks are compiler-enforced in Rust:
//! `impl ConsoleIo for ScriptedIo` / `impl TemplateEditor for IdentityTemplateEditor`, ledger
//! n/a; the identity editor's behavior is pinned in scripted_io.rs.)
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

/// The `[dependencies]` keys of r2-core's manifest.
fn core_dependencies() -> Vec<String> {
    let manifest = include_str!("../Cargo.toml");
    let mut in_section = false;
    let mut names = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line == "[dependencies]";
            continue;
        }
        if in_section && !line.is_empty() && !line.starts_with('#') {
            let name = line.split(['=', ' ', '.']).next().unwrap().trim();
            names.push(name.to_owned());
        }
    }
    names
}

/// c2 §3.1: core never imports prompt_toolkit/rich/console. In r2 the crate graph enforces
/// layering (§4.1.2): r2-core depends on exactly its third-party list — no terminal or
/// line-editor crate and no workspace crate (the renderer's comfy-table/anstream/anstyle/
/// unicode-width are permitted there because ScriptedIo stores rendered text, §4.1.2).
#[test]
fn test_core_stays_console_free() {
    let mut deps = core_dependencies();
    deps.sort();
    let mut allowed = vec![
        "openssl",
        "der",
        "spki",
        "x509-cert",
        "const-oid",
        "secrecy",
        "zeroize",
        "indexmap",
        "hex",
        "base64",
        "difflib",
        "comfy-table",
        "anstream",
        "anstyle",
        "unicode-width",
        "tracing",
    ];
    allowed.sort_unstable();
    assert_eq!(deps, allowed);
    for banned in [
        "reedline",
        "crossterm",
        "nu-ansi-term",
        "rpassword",
        "indicatif",
        "console",
        "clap",
        "r2-console",
        "r2-config",
        "r2-provider",
    ] {
        assert!(!deps.iter().any(|dep| dep == banned), "{banned}");
    }
}
