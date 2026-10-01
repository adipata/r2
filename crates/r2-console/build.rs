//! Command-module + test-module discovery (§4.9.6). Owner R7 — but R0 must ship a WORKING
//! version: `commands/mod.rs` and `lib.rs` include its output.

use std::fmt::Write as _;
use std::path::Path;

/// Rust keywords (strict + reserved, 2024 edition) — not usable as a `pub mod` name.
const KEYWORDS: &[&str] = &[
    "Self", "abstract", "as", "async", "await", "become", "box", "break", "const", "continue",
    "crate", "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if",
    "impl", "in", "let", "loop", "macro", "match", "mod", "move", "mut", "override", "priv", "pub",
    "ref", "return", "self", "static", "struct", "super", "trait", "true", "try", "type", "typeof",
    "unsafe", "unsized", "use", "virtual", "where", "while", "yield",
];

/// A file stem is a module only if it is a plain Rust identifier (ASCII letter or `_`, then
/// ASCII alphanumerics or `_`; not `_` alone, not a keyword — which also excludes `mod`).
/// Editor lock/backup files (`.#keys.rs`), dotfiles and names like `key-template.rs` or
/// `2fa.rs` are skipped, as c2's `pkgutil.iter_modules` skips dotted names.
pub(crate) fn is_module_stem(stem: &str) -> bool {
    let mut chars = stem.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && stem != "_"
        && !KEYWORDS.contains(&stem)
}

fn stems(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            match path.file_stem().and_then(|s| s.to_str()) {
                Some(stem) if is_module_stem(stem) => out.push(stem.to_owned()),
                Some("mod") => {}
                _ => println!(
                    "cargo::warning=skipping {}: not a Rust module name",
                    path.display()
                ),
            }
        }
    }
    out.sort();
    out
}

fn main() {
    let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") else {
        panic!("CARGO_MANIFEST_DIR unset")
    };
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        panic!("OUT_DIR unset")
    };
    let manifest = Path::new(&manifest);
    println!("cargo:rerun-if-changed=src/commands");
    println!("cargo:rerun-if-changed=src/tests");

    let mut cmds = String::new();
    let commands = stems(&manifest.join("src/commands"));
    for stem in &commands {
        let path = manifest.join("src/commands").join(format!("{stem}.rs"));
        let _ = writeln!(
            cmds,
            "#[path = {:?}]\npub mod {stem};",
            path.display().to_string()
        );
    }
    cmds.push_str("pub(crate) fn module_commands() -> Vec<(&'static str, Vec<Box<dyn Command>>)> {\n    vec![\n");
    for stem in &commands {
        let _ = writeln!(cmds, "        ({stem:?}, {stem}::commands()),");
    }
    cmds.push_str("    ]\n}\n");
    if let Err(err) = std::fs::write(Path::new(&out_dir).join("command_modules.rs"), cmds) {
        panic!("cannot write command_modules.rs: {err}");
    }

    let mut tests = String::new();
    for stem in stems(&manifest.join("src/tests")) {
        let path = manifest.join("src/tests").join(format!("{stem}.rs"));
        let _ = writeln!(
            tests,
            "#[path = {:?}]\nmod {stem};",
            path.display().to_string()
        );
    }
    if let Err(err) = std::fs::write(Path::new(&out_dir).join("test_modules.rs"), tests) {
        panic!("cannot write test_modules.rs: {err}");
    }
}
