// Command discovery (spec §4.9.6 convention) — the port of c2
// tests/unit/console/test_discovery.py (R7).
use std::rc::Rc;

use r2_core::error::ErrorKind;

use crate::commands::{Command, all_commands, collect_commands, discover_commands};
use crate::context::AppContext;
use crate::parser::BoundArgs;
use crate::repl::Flow;

#[test]
fn test_discovery_finds_the_l7_commands() {
    let commands = discover_commands().unwrap();
    for name in ["help", "exit", "quit", "clear", "config"] {
        assert!(commands.contains_key(name), "{name}");
    }
}

#[test]
fn test_command_metadata_is_complete() {
    for (name, command) in discover_commands().unwrap() {
        assert_eq!(command.name(), name);
        assert!(!command.name().is_empty());
        assert!(!command.summary().is_empty());
        assert!(!command.usage().is_empty());
        // flags are a set: no duplicates, never written with the dashes
        let mut flags = command.flags().to_vec();
        flags.sort_unstable();
        flags.dedup();
        assert_eq!(flags.len(), command.flags().len(), "{name}");
        assert!(command.flags().iter().all(|flag| !flag.starts_with('-')));
    }
}

#[test]
fn test_config_declares_its_boolean_flags() {
    let commands = discover_commands().unwrap();
    let mut flags = commands["config"].flags().to_vec();
    flags.sort_unstable();
    assert_eq!(flags, ["defaults", "origin"]);
}

#[test]
fn all_commands_is_cached_per_thread() {
    // c2 test_all_commands_is_cached (n/a in the ledger: Python caching); the r2 cache is
    // thread-local and hands out the same table.
    assert!(Rc::ptr_eq(
        &all_commands().unwrap(),
        &all_commands().unwrap()
    ));
}

#[test]
fn test_there_is_no_central_registration_table() {
    // §4.9: discovery is the only registration mechanism — commands/mod.rs includes the
    // build.rs-generated module list and keeps no hand-maintained name list.
    let source = include_str!("../commands/mod.rs");
    assert!(source.contains("include!(concat!(env!(\"OUT_DIR\"), \"/command_modules.rs\"));"));
    for name in ["\"help\"", "\"exit\"", "\"config\"", "\"keys\"", "\"misc\""] {
        assert!(
            !source.contains(name),
            "{name} hard-coded in commands/mod.rs"
        );
    }
    let build = include_str!("../../build.rs");
    assert!(build.contains("src/commands"));
    assert!(build.contains("command_modules.rs"));
}

struct Named(&'static str);
impl Command for Named {
    fn name(&self) -> &'static str {
        self.0
    }
    fn summary(&self) -> &'static str {
        "x"
    }
    fn usage(&self) -> &'static str {
        "x"
    }
    fn run(&self, _ctx: &AppContext, _args: &BoundArgs) -> r2_core::Result<Flow> {
        Ok(Flow::Continue)
    }
}

#[test]
fn duplicate_command_names_are_a_config_error() {
    let modules: Vec<(&'static str, Vec<Box<dyn Command>>)> = vec![
        ("alpha", vec![Box::new(Named("a")), Box::new(Named("b"))]),
        ("beta", vec![Box::new(Named("b"))]),
    ];
    let err = collect_commands(modules).err().unwrap();
    assert_eq!(err.kind, ErrorKind::Config);
    assert_eq!(err.message, "duplicate command name 'b' (module 'beta')");
    let table = collect_commands(vec![(
        "alpha",
        vec![Box::new(Named("z")), Box::new(Named("a"))],
    )])
    .unwrap();
    assert_eq!(table.keys().copied().collect::<Vec<_>>(), ["a", "z"]);
}
