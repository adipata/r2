// Grammar-aware completer tests (spec §4.9.7/§4.9.9, §5.1/§6 rules) — the port of c2
// tests/unit/console/test_completer.py and the completion cases of test_l13_hardening.py
// (R7). Completions are driven through `completer::complete_line` (the engine behind the
// reedline bridge) at the end of the text, like c2's `Document(text, len(text))`.
use std::rc::Rc;

use r2_core::error::ConsoleError;
use r2_core::io::ConsoleIo;
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyMaterial, display_refs, parse_ref};
use r2_provider::{GenerateRequest, Provider};
use r2_testkit::{FakeProvider, ScriptedIo};
use reedline::{Highlighter, Span};

use crate::commands::{Command, all_commands};
use crate::completer::{
    ConsoleAssist, browsable, complete_line, complete_paths, complete_provider_names, complete_refs,
};
use crate::context::AppContext;
use crate::io::{BridgeCompleter, BridgeHighlighter, LineAssist, install_line_assist};
use crate::parser::BoundArgs;
use crate::repl::{CommandTable, Flow};
use crate::testing::CtxBuilder;

fn make_ctx() -> Rc<AppContext> {
    CtxBuilder::new(Rc::new(ScriptedIo::empty()) as Rc<dyn ConsoleIo>).build()
}

fn table() -> CommandTable {
    (*all_commands().unwrap()).clone()
}

fn completions_with(ctx: &AppContext, text: &str, commands: &CommandTable) -> Vec<String> {
    complete_line(ctx, commands, text, text.len())
        .into_iter()
        .map(|(value, _)| value)
        .collect()
}

fn completions(ctx: &AppContext, text: &str) -> Vec<String> {
    completions_with(ctx, text, &table())
}

fn set(values: &[&str]) -> std::collections::BTreeSet<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}

fn as_set(values: Vec<String>) -> std::collections::BTreeSet<String> {
    values.into_iter().collect()
}

fn fake(ctx: &AppContext, name: &str) -> Rc<dyn Provider> {
    let provider = ctx.providers.get(name).unwrap();
    assert!(provider.as_any().downcast_ref::<FakeProvider>().is_some());
    provider
}

fn calls(provider: &Rc<dyn Provider>) -> Vec<Vec<String>> {
    provider
        .as_any()
        .downcast_ref::<FakeProvider>()
        .unwrap()
        .calls()
}

fn aes_material() -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![0x01; 16])
}

fn generate(
    provider: &Rc<dyn Provider>,
    algorithm: KeyAlgorithm,
    label: &str,
    key_id: Option<&[u8]>,
) {
    let mut request = GenerateRequest::new(algorithm, label);
    match algorithm {
        KeyAlgorithm::Rsa => request.size_bits = Some(2048),
        _ => request.curve = Some(Curve::P256),
    }
    request.key_id = key_id.map(<[u8]>::to_vec);
    provider.generate_key(&request).unwrap();
}

#[test]
fn test_first_token_completes_command_names() {
    let ctx = make_ctx();
    assert_eq!(completions(&ctx, "he"), ["help"]);
    assert!(
        as_set(completions(&ctx, ""))
            .is_superset(&set(&["help", "exit", "quit", "clear", "config"]))
    );
}

#[test]
fn test_second_token_delegates_to_command_complete() {
    let ctx = make_ctx();
    assert!(completions(&ctx, "help ").contains(&"config".to_owned()));
    assert_eq!(completions(&ctx, "help cl"), ["clear"]);
    assert_eq!(as_set(completions(&ctx, "config ")), set(&["show", "path"]));
    assert_eq!(
        as_set(completions(&ctx, "config show --")),
        set(&["--defaults", "--origin"])
    );
}

#[test]
fn test_no_completion_inside_open_quote() {
    let ctx = make_ctx();
    assert!(completions(&ctx, "load \"abc").is_empty());
}

#[test]
fn test_no_completion_for_unknown_command() {
    let ctx = make_ctx();
    assert!(completions(&ctx, "nosuchcmd ").is_empty());
}

/// A command whose `complete` fails (c2 Sabotage raised ConsoleError; an r2 `complete`
/// swallows errors by contract, and a panic is caught by the bridge).
struct Sabotage;
impl Command for Sabotage {
    fn name(&self) -> &'static str {
        "sabotage"
    }
    fn summary(&self) -> &'static str {
        "x"
    }
    fn usage(&self) -> &'static str {
        "x"
    }
    fn run(&self, _ctx: &AppContext, _args: &BoundArgs) -> r2_core::Result<Flow> {
        unreachable!()
    }
    fn complete(&self, _ctx: &AppContext, _tokens: &[String], _cursor: &str) -> Vec<String> {
        panic!("{}", ConsoleError::generic("completion exploded"))
    }
}

#[test]
fn test_command_complete_errors_are_swallowed() {
    let ctx = make_ctx();
    let mut commands = CommandTable::new();
    commands.insert("sabotage", Rc::new(Sabotage) as Rc<dyn Command>);
    let assist = Rc::new(ConsoleAssist::new(Rc::clone(&ctx), Rc::new(commands)));
    let _guard = install_line_assist(assist);
    let mut bridge = BridgeCompleter;
    assert!(reedline::Completer::complete(&mut bridge, "sabotage x", 10).is_empty());
    // the bridge with nothing installed degrades to no suggestions / plain text
    drop(_guard);
    assert!(reedline::Completer::complete(&mut bridge, "he", 2).is_empty());
    let styled = BridgeHighlighter.highlight("help", 4);
    assert_eq!(styled.raw_string(), "help");
}

#[test]
fn test_help_arg_completion_stops_after_first_arg() {
    let ctx = make_ctx();
    assert!(completions(&ctx, "help config ").is_empty());
}

#[test]
fn test_complete_provider_names() {
    let ctx = make_ctx();
    assert_eq!(
        as_set(complete_provider_names(&ctx, "")),
        set(&["mem", "hsm"])
    );
    assert_eq!(complete_provider_names(&ctx, "m"), ["mem"]);
}

#[test]
fn test_complete_refs_without_colon_yields_provider_prefixes() {
    let ctx = make_ctx();
    assert_eq!(as_set(complete_refs(&ctx, "")), set(&["mem:", "hsm:"]));
    assert_eq!(complete_refs(&ctx, "me"), ["mem:"]);
}

#[test]
fn test_complete_refs_lists_keys_of_browsable_provider() {
    let ctx = make_ctx();
    assert_eq!(complete_refs(&ctx, "mem:"), ["mem:aeskey"]);
    assert_eq!(complete_refs(&ctx, "mem:aes"), ["mem:aeskey"]);
    assert!(complete_refs(&ctx, "mem:zz").is_empty());
}

#[test]
fn test_complete_refs_suffixes_keypair_family() {
    // §4.3: colliding displays complete as distinct class-qualified candidates.
    let ctx = make_ctx();
    let mem = fake(&ctx, "mem");
    generate(&mem, KeyAlgorithm::Rsa, "pair", None);
    assert_eq!(
        as_set(complete_refs(&ctx, "mem:pair")),
        set(&["mem:pair:priv", "mem:pair:pub"])
    );
}

#[test]
fn test_complete_refs_logged_out_provider_completes_prefix_only() {
    let ctx = make_ctx();
    let hsm = fake(&ctx, "hsm");
    hsm.logout().unwrap(); // §5.1/§6: never browse a logged-out provider
    assert!(!browsable(hsm.as_ref()));
    assert_eq!(complete_refs(&ctx, "hsm:"), ["hsm:"]);
    let before = calls(&hsm);
    assert_eq!(complete_refs(&ctx, "hsm:any"), ["hsm:"]);
    // list_keys was never called on the logged-out provider
    let list_keys = |calls: Vec<Vec<String>>| {
        calls
            .into_iter()
            .filter(|call| call[0] == "list_keys")
            .count()
    };
    assert_eq!(list_keys(calls(&hsm)), list_keys(before));
    assert_eq!(list_keys(calls(&hsm)), 0);
}

#[test]
fn test_complete_refs_unknown_provider() {
    let ctx = make_ctx();
    assert!(complete_refs(&ctx, "nope:key").is_empty());
}

// -- §4.3 selector stages (#<id-hex> / :<class> continuations) ---------------

#[test]
fn test_complete_refs_class_stage_for_plain_label() {
    let ctx = make_ctx();
    assert_eq!(complete_refs(&ctx, "mem:aeskey:"), ["mem:aeskey:secret"]);
    assert!(complete_refs(&ctx, "mem:aeskey#").is_empty()); // memory key has no id
}

#[test]
fn test_complete_refs_id_selector_stages() {
    let ctx = make_ctx();
    fake(&ctx, "hsm")
        .import_key(&aes_material(), "tls", None, Some(&[0x0a, 0x1b]))
        .unwrap();
    assert_eq!(complete_refs(&ctx, "hsm:tls"), ["hsm:tls#0a1b"]); // keys-table menu only
    assert_eq!(
        complete_refs(&ctx, "hsm:tls#"),
        ["hsm:tls#0a1b", "hsm:tls#0a1b:secret"]
    );
    assert_eq!(
        complete_refs(&ctx, "hsm:tls#0a1b:"),
        ["hsm:tls#0a1b:secret"]
    );
    assert_eq!(complete_refs(&ctx, "hsm:tls:"), ["hsm:tls:secret"]);
}

#[test]
fn test_complete_refs_keypair_family_selector_stages() {
    let ctx = make_ctx();
    let hsm = fake(&ctx, "hsm");
    generate(&hsm, KeyAlgorithm::Rsa, "pair", Some(&[0x01, 0x02]));
    assert_eq!(
        as_set(complete_refs(&ctx, "hsm:pair")),
        set(&["hsm:pair#0102:priv", "hsm:pair#0102:pub"])
    );
    assert_eq!(
        as_set(complete_refs(&ctx, "hsm:pair:")),
        set(&["hsm:pair:priv", "hsm:pair:pub"])
    );
    // the bare id form resolves via the find_key class-preference rule → offered
    assert_eq!(
        as_set(complete_refs(&ctx, "hsm:pair#")),
        set(&["hsm:pair#0102", "hsm:pair#0102:priv", "hsm:pair#0102:pub"])
    );
}

#[test]
fn test_complete_refs_label_stage_matches_keys_table() {
    // anti-flooding guard: at the label stage the menu is exactly the keys table
    let ctx = make_ctx();
    let hsm = fake(&ctx, "hsm");
    hsm.import_key(&aes_material(), "tls", None, Some(&[0x0a, 0x1b]))
        .unwrap();
    generate(&hsm, KeyAlgorithm::Rsa, "pair", Some(&[0x01, 0x02]));
    assert_eq!(
        complete_refs(&ctx, "hsm:"),
        display_refs(&hsm.list_keys().unwrap())
    );
}

#[test]
fn test_complete_refs_ambiguous_selector_not_offered() {
    let ctx = make_ctx();
    let mem = fake(&ctx, "mem");
    mem.import_key(&aes_material(), "dup", None, None).unwrap();
    // twin via the store_key_unchecked backdoor — the §4.5 guard refuses API creation
    mem.as_any()
        .downcast_ref::<FakeProvider>()
        .unwrap()
        .store_key_unchecked(&aes_material(), "dup", None, None);
    // same-class collision: only the @handle-qualified keys-table forms appear — the
    // ambiguous 'mem:dup:secret' (would be AmbiguousKey) never does
    let offered = complete_refs(&ctx, "mem:dup:");
    assert_eq!(offered.len(), 2);
    assert!(
        offered
            .iter()
            .all(|text| text.starts_with("mem:dup:secret@"))
    );
    let hsm = fake(&ctx, "hsm");
    hsm.import_key(&aes_material(), "dup", None, Some(&[0x01]))
        .unwrap();
    hsm.import_key(&aes_material(), "dup", None, Some(&[0x02]))
        .unwrap();
    assert!(complete_refs(&ctx, "hsm:dup:").is_empty()); // distinct ids → no joint selector
}

#[test]
fn test_complete_refs_labels_containing_delimiters() {
    let ctx = make_ctx();
    let mem = fake(&ctx, "mem");
    mem.import_key(&aes_material(), "a", None, None).unwrap();
    mem.import_key(&aes_material(), "a#b", None, None).unwrap();
    mem.import_key(&aes_material(), "we:ird", None, None)
        .unwrap();
    assert_eq!(complete_refs(&ctx, "mem:a#"), ["mem:a#b"]);
    assert_eq!(complete_refs(&ctx, "mem:we:"), ["mem:we:ird"]);
    assert_eq!(complete_refs(&ctx, "mem:a:"), ["mem:a:secret"]);
}

#[test]
fn test_complete_refs_selector_stage_logged_out_prefix_only() {
    let ctx = make_ctx();
    let hsm = fake(&ctx, "hsm");
    hsm.logout().unwrap(); // §5.1/§6: never browse a logged-out provider
    assert_eq!(complete_refs(&ctx, "hsm:x#"), ["hsm:"]);
    assert_eq!(complete_refs(&ctx, "hsm:x:"), ["hsm:"]);
    assert!(calls(&hsm).iter().all(|call| call[0] != "list_keys"));
}

#[test]
fn test_complete_refs_candidates_always_parse() {
    let ctx = make_ctx();
    let hsm = fake(&ctx, "hsm");
    hsm.import_key(&aes_material(), "tls", None, Some(&[0x0a, 0x1b]))
        .unwrap();
    generate(&hsm, KeyAlgorithm::Ec, "pair", Some(&[0x01, 0x02]));
    for prefix in [
        "hsm:",
        "hsm:tls",
        "hsm:tls#",
        "hsm:tls:",
        "hsm:pair#",
        "hsm:pair:",
    ] {
        for candidate in complete_refs(&ctx, prefix) {
            assert_eq!(
                parse_ref(&candidate).unwrap().provider,
                "hsm",
                "{candidate}"
            );
        }
    }
}

/// Stand-in for R8's `delete` (its `<ref>` position completes refs, as c2's keys_cmd did):
/// R8's module is not merged here, so the console path is exercised with this double.
struct DeleteLike;
impl Command for DeleteLike {
    fn name(&self) -> &'static str {
        "delete"
    }
    fn summary(&self) -> &'static str {
        "test double"
    }
    fn usage(&self) -> &'static str {
        "delete <provider>:<label>"
    }
    fn run(&self, _ctx: &AppContext, _args: &BoundArgs) -> r2_core::Result<Flow> {
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        if crate::cmdutil::completed_args(tokens, cursor_token) == 0 {
            return complete_refs(ctx, cursor_token);
        }
        Vec::new()
    }
}

#[test]
fn test_selector_stage_through_console_completer() {
    let ctx = make_ctx();
    let mut commands = table();
    commands.insert("delete", Rc::new(DeleteLike) as Rc<dyn Command>);
    assert_eq!(
        completions_with(&ctx, "delete mem:aeskey:", &commands),
        ["mem:aeskey:secret"]
    );
}

// -- r2: byte spans, display override, highlighting ---------------------------

#[test]
fn suggestion_spans_are_byte_ranges_of_the_raw_token() {
    let ctx = make_ctx();
    let commands = table();
    // new token → empty span at the cursor
    let got = complete_line(&ctx, &commands, "config ", 7);
    assert!(got.iter().all(|(_, span)| *span == Span::new(7, 7)));
    // partial token → from its start
    let got = complete_line(&ctx, &commands, "config sh", 9);
    assert_eq!(got, [("show".to_owned(), Span::new(7, 9))]);
    // a just-closed quoted token: the span starts at the opening quote (§11 D9)
    let mut with_delete = table();
    with_delete.insert("delete", Rc::new(DeleteLike) as Rc<dyn Command>);
    let line = "delete \"mem:aes\"";
    let got = complete_line(&ctx, &with_delete, line, line.len());
    assert_eq!(got, [("mem:aeskey".to_owned(), Span::new(7, line.len()))]);
    // multibyte text before the cursor: byte offsets
    fake(&ctx, "mem")
        .import_key(&aes_material(), "ключ", None, None)
        .unwrap();
    let line = "delete mem:кл";
    let got = complete_line(&ctx, &with_delete, line, line.len());
    assert_eq!(got, [("mem:ключ".to_owned(), Span::new(7, line.len()))]);
    // completion only looks at the text before the cursor
    let got = complete_line(&ctx, &commands, "he trailing", 2);
    assert_eq!(got, [("help".to_owned(), Span::new(0, 2))]);
    // a cursor inside a multibyte char is not a char boundary → nothing, never a panic
    assert!(complete_line(&ctx, &with_delete, line, line.len() - 1).is_empty());
}

#[test]
fn suggestions_never_append_whitespace_and_paths_show_their_last_component() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("alpha.txt"), b"a").unwrap();
    std::fs::create_dir(dir.path().join("subdir")).unwrap();
    struct PathCmd;
    impl Command for PathCmd {
        fn name(&self) -> &'static str {
            "pathcmd"
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
        fn complete(&self, _ctx: &AppContext, _t: &[String], cursor: &str) -> Vec<String> {
            complete_paths(cursor)
        }
    }
    let ctx = make_ctx();
    let mut commands = CommandTable::new();
    commands.insert("pathcmd", Rc::new(PathCmd) as Rc<dyn Command>);
    let assist = ConsoleAssist::new(Rc::clone(&ctx), Rc::new(commands));
    let line = format!("pathcmd {}/", dir.path().display());
    let suggestions = assist.complete(&line, line.len());
    let shown: Vec<(Option<String>, bool)> = suggestions
        .iter()
        .map(|s| (s.display_override.clone(), s.append_whitespace))
        .collect();
    assert_eq!(
        shown,
        [
            (Some("alpha.txt".to_owned()), false),
            (Some("subdir/".to_owned()), false)
        ]
    );
    assert_eq!(
        suggestions[0].value,
        format!("{}/alpha.txt", dir.path().display())
    );
    // refs of registered providers are not path-like, even with a '/' in the label
    fake(&ctx, "mem")
        .import_key(&aes_material(), "a/b", None, None)
        .unwrap();
    let mut with_delete = table();
    with_delete.insert("delete", Rc::new(DeleteLike) as Rc<dyn Command>);
    let refs = ConsoleAssist::new(Rc::clone(&ctx), Rc::new(with_delete));
    let suggestions = refs.complete("delete mem:a/", 13);
    assert_eq!(suggestions.len(), 1);
    assert_eq!(suggestions[0].value, "mem:a/b");
    assert_eq!(suggestions[0].display_override, None);
}

#[test]
fn highlighting_styles_follow_the_grammar() {
    use nu_ansi_term::{Color, Style};
    let ctx = make_ctx();
    let assist = ConsoleAssist::new(Rc::clone(&ctx), Rc::new(table()));
    let styled = assist.highlight("help mem:aeskey --out f iv=00 \"q\" x");
    let spans: Vec<(Style, &str)> = styled
        .buffer
        .iter()
        .map(|(style, text)| (*style, text.as_str()))
        .collect();
    assert_eq!(
        spans,
        [
            (Style::new().fg(Color::Green).bold(), "help"),
            (Style::new(), " "),
            (Style::new().fg(Color::Cyan), "mem:aeskey"),
            (Style::new(), " "),
            (Style::new().fg(Color::Blue), "--out"),
            (Style::new(), " "),
            (Style::new(), "f"),
            (Style::new(), " "),
            (Style::new().fg(Color::Magenta), "iv=00"),
            (Style::new(), " "),
            (Style::new().fg(Color::Yellow), "\"q\""),
            (Style::new(), " "),
            (Style::new(), "x"),
        ]
    );
    // unknown command red; an unregistered provider prefix is not a ref
    let styled = assist.highlight("nope zz:k");
    assert_eq!(
        styled.buffer[0],
        (Style::new().fg(Color::Red), "nope".to_owned())
    );
    assert_eq!(styled.buffer[2], (Style::new(), "zz:k".to_owned()));
    // a still-open quote is a string to the end of the buffer
    let styled = assist.highlight("help 'abc\ndef");
    assert_eq!(styled.raw_string(), "help 'abc\ndef");
    assert_eq!(
        styled.buffer.last(),
        Some(&(Style::new().fg(Color::Yellow), "'abc\ndef".to_owned()))
    );
}

// -- test_l13_hardening: paths for file options and path positionals (§5.1) ---

fn tree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("alpha.txt"), b"a").unwrap();
    std::fs::write(dir.path().join("beta.bin"), b"b").unwrap();
    std::fs::create_dir(dir.path().join("subdir")).unwrap();
    std::fs::write(dir.path().join(".hidden"), b"h").unwrap();
    dir
}

#[test]
fn test_complete_paths_lists_directory() {
    let dir = tree();
    let tree = dir.path().display();
    let candidates = complete_paths(&format!("{tree}/"));
    assert!(candidates.contains(&format!("{tree}/alpha.txt")));
    assert!(candidates.contains(&format!("{tree}/beta.bin")));
    assert!(candidates.contains(&format!("{tree}/subdir/"))); // trailing / to descend
    assert!(!candidates.contains(&format!("{tree}/.hidden"))); // hidden only when asked
    assert_eq!(
        candidates,
        [
            format!("{tree}/alpha.txt"),
            format!("{tree}/beta.bin"),
            format!("{tree}/subdir/")
        ]
    );
}

#[test]
fn test_complete_paths_partial_and_hidden() {
    let dir = tree();
    let tree = dir.path().display();
    assert_eq!(
        complete_paths(&format!("{tree}/al")),
        [format!("{tree}/alpha.txt")]
    );
    assert_eq!(
        complete_paths(&format!("{tree}/.")),
        [format!("{tree}/.hidden")]
    );
    assert!(complete_paths(&format!("{tree}/nomatch")).is_empty());
    assert!(complete_paths(&format!("{tree}/subdir/")).is_empty());
}

#[test]
fn test_complete_paths_never_raises() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing").join("x");
    assert!(complete_paths(&missing.display().to_string()).is_empty());
    // a file used as a directory
    let file = dir.path().join("f");
    std::fs::write(&file, b"x").unwrap();
    assert!(complete_paths(&format!("{}/", file.display())).is_empty());
}

#[test]
fn complete_paths_keeps_the_typed_directory_part_and_expands_tilde() {
    let _lock = r2_testkit::global_state_lock();
    let dir = tree();
    let _home = r2_testkit::set_env("HOME", Some(&dir.path().display().to_string()));
    assert_eq!(complete_paths("~/al"), ["~/alpha.txt"]);
    assert_eq!(complete_paths("~/sub"), ["~/subdir/"]);
}
