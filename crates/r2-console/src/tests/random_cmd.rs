// `random` command tests (spec §5.17, §11 D29 — r2 only; no c2 counterpart to port).
//
// Everything runs against FakeProvider + ScriptedIo (spec §4.10): arg parsing, the
// `<length>` parameter (inline or prompted through ParamResolver, with the 1..=1048576
// validator), the console hex result and the --out/--outformat file output shared with the
// crypto verbs, AuthRequired before any prompt, error propagation, the §11 D13 Ctrl-C flag,
// completion and the help surface. The expected bytes come from a same-name twin
// FakeProvider: its draws are a deterministic keystream of (name, draw number).
use std::rc::Rc;

use r2_core::codec::format_hex;
use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::io::{ConsoleIo, Renderable};
use r2_provider::{Provider, ProviderRegistry};
use r2_testkit::{FakeHooks, FakeProvider, ScriptedIo};
use zeroize::Zeroizing;

use crate::context::AppContext;
use crate::testing::CtxBuilder;

const USAGE: &str =
    "random <provider> [<length> | length=<n>] [--out <path>] [--outformat raw|hex|b64]";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn scripted(answers: &[&str]) -> Rc<ScriptedIo> {
    Rc::new(ScriptedIo::new(answers.iter().copied()))
}

fn dyn_io(io: &Rc<ScriptedIo>) -> Rc<dyn ConsoleIo> {
    Rc::clone(io) as Rc<dyn ConsoleIo>
}

fn registry(providers: &[Rc<FakeProvider>]) -> ProviderRegistry {
    let registry = ProviderRegistry::new();
    for provider in providers {
        registry
            .register(Rc::clone(provider) as Rc<dyn Provider>)
            .unwrap();
    }
    registry
}

/// A memory-presented fake "mem" on a fresh context.
fn make_ctx(io: &Rc<ScriptedIo>) -> (Rc<AppContext>, Rc<FakeProvider>) {
    let mem = Rc::new(FakeProvider::new("mem"));
    let ctx = CtxBuilder::new(dyn_io(io))
        .providers(registry(&[Rc::clone(&mem)]))
        .build();
    (ctx, mem)
}

/// The first `len`-byte draw of a fresh fake named "mem" — what the command's first draw
/// on a fresh "mem" yields.
fn first_draw(len: usize) -> Vec<u8> {
    FakeProvider::new("mem")
        .generate_random(len)
        .unwrap()
        .to_vec()
}

fn call(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn random_calls(provider: &FakeProvider) -> Vec<Vec<String>> {
    provider
        .calls()
        .into_iter()
        .filter(|call| call.first().is_some_and(|m| m == "generate_random"))
        .collect()
}

/// `crate::testing::run_line` under the process-global state lock: the command honors the
/// process-global Ctrl-C flag (§11 D13), which concurrent tests may set under the
/// `cargo test` harness.
fn run_line(ctx: &AppContext, line: &str) -> Result<crate::repl::Flow> {
    let _lock = r2_testkit::global_state_lock();
    r2_core::runtime::reset_interrupt();
    crate::testing::run_line(ctx, line)
}

fn run_err(ctx: &AppContext, line: &str) -> ConsoleError {
    match run_line(ctx, line) {
        Ok(flow) => panic!("{line:?} succeeded with {flow:?}"),
        Err(err) => err,
    }
}

fn complete(ctx: &AppContext, tokens: &[&str], cursor: &str) -> Vec<String> {
    let table = crate::commands::all_commands().unwrap();
    let tokens: Vec<String> = tokens.iter().map(|t| (*t).to_owned()).collect();
    table.get("random").unwrap().complete(ctx, &tokens, cursor)
}

fn param_name(err: &ConsoleError) -> Option<&str> {
    match &err.kind {
        ErrorKind::Param { param_name } => Some(param_name),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// console and file output
// ---------------------------------------------------------------------------

#[test]
fn random_renders_the_hex_result() {
    let io = scripted(&[]);
    let (ctx, mem) = make_ctx(&io);
    run_line(&ctx, "random mem 16").unwrap();
    let expected = first_draw(16);
    assert_eq!(expected.len(), 16);
    // §4.9.2: a Hex renderable titled with what the bytes are
    assert_eq!(
        io.renderables(),
        [r2_core::io::hex(&expected, Some("random — mem"))]
    );
    let text = io.text();
    assert!(text.contains("random — mem"));
    assert!(text.contains("16 bytes"));
    // §11 D28: the hex on one unbroken line of its own
    assert!(text.contains(&format!("\n{}\n", format_hex(&expected, 0, 0))));
    // initialized first, then exactly one draw of the requested length
    let calls = mem.calls();
    let init = calls.iter().position(|c| *c == call(&["initialize"]));
    let draw = calls
        .iter()
        .position(|c| *c == call(&["generate_random", "16"]));
    assert!(init.is_some() && draw.is_some() && init < draw, "{calls:?}");
    assert_eq!(random_calls(&mem), [call(&["generate_random", "16"])]);
}

#[test]
fn successive_random_draws_differ() {
    let io = scripted(&[]);
    let (ctx, _) = make_ctx(&io);
    run_line(&ctx, "random mem 32").unwrap();
    run_line(&ctx, "random mem 32").unwrap();
    let data: Vec<Vec<u8>> = io
        .renderables()
        .into_iter()
        .map(|r| match r {
            Renderable::Hex { data, .. } => data.to_vec(),
            other => panic!("not a hex result: {other:?}"),
        })
        .collect();
    assert_eq!(data.len(), 2);
    assert_ne!(data[0], data[1]);
}

#[test]
fn random_out_raw_hex_and_b64_files() {
    let dir = tempfile::tempdir().unwrap();
    let raw_path = dir.path().join("rnd.raw");
    let default_path = dir.path().join("rnd.bin");
    let hex_path = dir.path().join("rnd.hex");
    let b64_path = dir.path().join("rnd.b64");
    let twin = FakeProvider::new("mem");
    let draws: Vec<Vec<u8>> = (0..4)
        .map(|_| twin.generate_random(16).unwrap().to_vec())
        .collect();
    let io = scripted(&[]);
    let (ctx, _) = make_ctx(&io);
    run_line(
        &ctx,
        &format!("random mem 16 --out {} --outformat raw", raw_path.display()),
    )
    .unwrap();
    run_line(
        &ctx,
        &format!("random mem 16 --out {}", default_path.display()),
    )
    .unwrap();
    run_line(
        &ctx,
        &format!("random mem 16 --out {} --outformat hex", hex_path.display()),
    )
    .unwrap();
    run_line(
        &ctx,
        &format!("random mem 16 --outformat b64 --out {}", b64_path.display()),
    )
    .unwrap();
    // raw is the default --outformat (§4.4)
    assert_eq!(std::fs::read(&raw_path).unwrap(), draws[0]);
    assert_eq!(std::fs::read(&default_path).unwrap(), draws[1]);
    // hex: continuous lower-case hex + "\n"
    let hex_text: String = draws[2].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        std::fs::read_to_string(&hex_path).unwrap(),
        format!("{hex_text}\n")
    );
    // b64: standard (padded) base64 + "\n" on one line
    let b64_text = std::fs::read_to_string(&b64_path).unwrap();
    assert_eq!(b64_text.len(), 25, "{b64_text:?}");
    assert!(b64_text.ends_with("==\n"), "{b64_text:?}");
    let (decoded, _) = r2_core::codec::decode_data(&format!("b64:{}", b64_text.trim())).unwrap();
    assert_eq!(*decoded, draws[3]);
    // no hex panel on the console — only the "wrote" lines
    assert_eq!(
        io.output(),
        [&raw_path, &default_path, &hex_path, &b64_path]
            .iter()
            .map(|path| format!("wrote 16 bytes to {}", path.display()))
            .collect::<Vec<_>>()
    );
    assert!(
        !io.renderables()
            .iter()
            .any(|r| matches!(r, Renderable::Hex { .. }))
    );
}

/// The written path is shown as Python's `Path(out)` (`r2_core::text::py_path`, §4.4).
#[test]
fn random_out_path_is_shown_normalized() {
    let dir = tempfile::tempdir().unwrap();
    let io = scripted(&[]);
    let (ctx, _) = make_ctx(&io);
    let typed = format!("{}//./r.bin", dir.path().display());
    run_line(&ctx, &format!("random mem 4 --out {typed}")).unwrap();
    let shown = r2_core::text::py_path(&typed);
    assert_eq!(shown, dir.path().join("r.bin"));
    assert_eq!(
        io.output(),
        [format!("wrote 4 bytes to {}", shown.display())]
    );
    assert_eq!(
        std::fs::read(dir.path().join("r.bin")).unwrap(),
        first_draw(4)
    );
}

// ---------------------------------------------------------------------------
// the <length> parameter
// ---------------------------------------------------------------------------

#[test]
fn random_length_is_prompted_and_reprompted_after_errors() {
    let io = scripted(&["0", "abc", "24"]);
    let (ctx, mem) = make_ctx(&io);
    run_line(&ctx, "random mem").unwrap();
    assert_eq!(
        io.prompts(),
        [
            "Number of random bytes",
            "Number of random bytes",
            "Number of random bytes"
        ]
    );
    assert_eq!(io.remaining(), 0);
    // each error is printed, then the length is prompted again
    assert_eq!(
        io.output()[..2],
        [
            "error: invalid random length 0; expected 1 to 1048576 bytes",
            "error: length: invalid integer 'abc' (hint: decimal digits with an optional \
             leading '-' only (§4.6))",
        ]
    );
    assert_eq!(io.output().len(), 3);
    assert_eq!(
        io.renderables()[2],
        r2_core::io::hex(&first_draw(24), Some("random — mem"))
    );
    // the rejected answers never reached the provider
    assert_eq!(random_calls(&mem), [call(&["generate_random", "24"])]);
}

#[test]
fn ctrl_c_at_the_length_prompt_aborts() {
    let io = scripted(&[ScriptedIo::CTRL_C]);
    let (ctx, mem) = make_ctx(&io);
    let err = run_err(&ctx, "random mem");
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert_eq!(io.prompts(), ["Number of random bytes"]);
    assert!(random_calls(&mem).is_empty());
    assert!(io.output().is_empty());
}

#[test]
fn random_inline_length_out_of_range_is_a_param_error() {
    let (ctx, mem) = make_ctx(&scripted(&[]));
    for (token, shown) in [("0", "0"), ("-1", "-1"), ("1048577", "1048577")] {
        let err = run_err(&ctx, &format!("random mem {token}"));
        assert!(matches!(err.kind, ErrorKind::Param { .. }), "{err:?}");
        assert_eq!(param_name(&err), Some("length"), "{token}");
        assert_eq!(
            err.message,
            format!("invalid random length {shown}; expected 1 to 1048576 bytes")
        );
    }
    assert!(random_calls(&mem).is_empty());
}

#[test]
fn random_inline_length_must_be_an_integer() {
    let (ctx, mem) = make_ctx(&scripted(&[]));
    let err = run_err(&ctx, "random mem abc");
    assert!(matches!(err.kind, ErrorKind::Param { .. }), "{err:?}");
    assert_eq!(param_name(&err), Some("length"));
    assert_eq!(err.message, "length: invalid integer 'abc'");
    assert_eq!(
        err.hint.as_deref(),
        Some("decimal digits with an optional leading '-' only (§4.6)")
    );
    assert!(random_calls(&mem).is_empty());
}

#[test]
fn random_accepts_the_maximum_length() {
    let io = scripted(&[]);
    let (ctx, mem) = make_ctx(&io);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("max.bin");
    run_line(
        &ctx,
        &format!("random mem 1048576 --out {}", path.display()),
    )
    .unwrap();
    assert_eq!(std::fs::read(&path).unwrap().len(), 1_048_576);
    assert_eq!(random_calls(&mem), [call(&["generate_random", "1048576"])]);
    assert_eq!(
        io.output(),
        [format!("wrote 1048576 bytes to {}", path.display())]
    );
}

// ---------------------------------------------------------------------------
// argument errors
// ---------------------------------------------------------------------------

#[test]
fn random_missing_provider() {
    let (ctx, _) = make_ctx(&scripted(&[]));
    let err = run_err(&ctx, "random");
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(err.message, "missing <provider> argument");
    assert_eq!(err.hint.as_deref(), Some(&*format!("usage: {USAGE}")));
}

#[test]
fn random_unknown_provider() {
    let (ctx, _) = make_ctx(&scripted(&[]));
    let err = run_err(&ctx, "random nope 16");
    assert_eq!(err.kind, ErrorKind::ProviderNotFound);
    assert_eq!(err.message, "unknown provider 'nope'");
    assert_eq!(err.hint.as_deref(), Some("known providers: mem"));
}

#[test]
fn random_too_many_arguments() {
    let (ctx, mem) = make_ctx(&scripted(&[]));
    let err = run_err(&ctx, "random mem 16 32");
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(err.message, "too many arguments");
    assert_eq!(err.hint.as_deref(), Some(&*format!("usage: {USAGE}")));
    assert!(random_calls(&mem).is_empty());
}

#[test]
fn random_takes_the_length_as_length_equals_n_too() {
    let io = scripted(&[]);
    let (ctx, mem) = make_ctx(&io);
    run_line(&ctx, "random mem length=16").unwrap();
    assert_eq!(
        io.renderables(),
        [r2_core::io::hex(&first_draw(16), Some("random — mem"))]
    );
    assert!(mem.calls().contains(&call(&["generate_random", "16"])));
}

#[test]
fn random_length_given_twice_is_an_error() {
    let (ctx, mem) = make_ctx(&scripted(&[]));
    let err = run_err(&ctx, "random mem 16 length=16");
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(err.message, "the length is given twice");
    assert_eq!(err.hint.as_deref(), Some(&*format!("usage: {USAGE}")));
    assert!(!mem.calls().iter().any(|c| c[0] == "generate_random"));
}

#[test]
fn random_rejects_other_name_value_tokens() {
    let (ctx, _) = make_ctx(&scripted(&[]));
    let err = run_err(&ctx, "random mem foo=1");
    assert_eq!(err.param_name(), Some("foo"));
    assert_eq!(err.message, "unknown parameter 'foo' for random");
    assert_eq!(err.hint.as_deref(), Some("valid parameters: length"));
}

/// The argument checks run in a fixed order (§5.17): options and arity first, then
/// --out/--outformat, then the provider (and its login state), then the length.
#[test]
fn random_argument_errors_come_in_order() {
    let hsm = Rc::new(FakeProvider::new("hsm").with_type_name("pkcs11"));
    hsm.logout().unwrap();
    let mem = Rc::new(FakeProvider::new("mem"));
    let io = scripted(&[]);
    let ctx = CtxBuilder::new(dyn_io(&io))
        .providers(registry(&[Rc::clone(&hsm), Rc::clone(&mem)]))
        .build();
    for (line, kind, message) in [
        // --outformat without --out is caught before the unknown provider
        (
            "random nosuch 16 --outformat hex",
            ErrorKind::Generic,
            "--outformat requires --out",
        ),
        // arity before the provider lookup
        (
            "random nosuch 1 2 3",
            ErrorKind::Generic,
            "too many arguments",
        ),
        // unknown options before the length
        (
            "random mem length=1 --in x",
            ErrorKind::Generic,
            "unknown option --in",
        ),
        // the --outformat value before the login check and the length range
        (
            "random hsm 0 --out x --outformat nope",
            ErrorKind::Generic,
            "invalid --outformat 'nope'",
        ),
        // login before the length range
        (
            "random hsm 0",
            ErrorKind::AuthRequired,
            "login required: run `login hsm`",
        ),
        // the double length before the provider is touched
        (
            "random mem 1 length=1",
            ErrorKind::Generic,
            "the length is given twice",
        ),
    ] {
        let err = run_err(&ctx, line);
        assert_eq!(
            (&err.kind, err.message.as_str()),
            (&kind, message),
            "{line}"
        );
    }
    assert!(random_calls(&hsm).is_empty());
    assert!(random_calls(&mem).is_empty());
    assert!(io.prompts().is_empty());
    assert!(io.output().is_empty());
}

/// A mistyped command name suggests `random` (difflib close match, §5.1).
#[test]
fn unknown_commands_suggest_random() {
    let (ctx, _) = make_ctx(&scripted(&[]));
    let err = run_err(&ctx, "randon 16");
    assert_eq!(err.kind, ErrorKind::UnknownOperation);
    assert_eq!(err.message, "unknown command 'randon'");
    assert_eq!(err.hint.as_deref(), Some("did you mean: random"));
    let err = run_err(&ctx, "read");
    assert_eq!(err.kind, ErrorKind::UnknownOperation);
    assert_eq!(err.message, "unknown command 'read'");
    assert_eq!(err.hint.as_deref(), Some("did you mean: random"));
    // and so does `help`
    let err = run_err(&ctx, "help rando");
    assert_eq!(err.kind, ErrorKind::UnknownOperation);
    assert_eq!(err.message, "unknown command 'rando'");
    assert_eq!(err.hint.as_deref(), Some("did you mean: random"));
}

#[test]
fn random_rejects_unknown_options() {
    let (ctx, _) = make_ctx(&scripted(&[]));
    let err = run_err(&ctx, "random mem 16 --in x");
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(err.message, "unknown option --in");
    assert_eq!(err.hint.as_deref(), Some(&*format!("usage: {USAGE}")));
}

#[test]
fn random_outformat_requires_out() {
    let (ctx, mem) = make_ctx(&scripted(&[]));
    let err = run_err(&ctx, "random mem 16 --outformat hex");
    assert_eq!(err.message, "--outformat requires --out");
    assert_eq!(
        err.hint.as_deref(),
        Some("console output is always the hex result (§5.1)")
    );
    assert!(random_calls(&mem).is_empty());
}

#[test]
fn random_invalid_outformat_rejected() {
    let (ctx, mem) = make_ctx(&scripted(&[]));
    let err = run_err(&ctx, "random mem 16 --out x --outformat nope");
    assert_eq!(err.message, "invalid --outformat 'nope'");
    assert_eq!(err.hint.as_deref(), Some("choose one of: raw, hex, b64"));
    assert!(random_calls(&mem).is_empty());
}

// ---------------------------------------------------------------------------
// provider state and failures
// ---------------------------------------------------------------------------

/// A logged-out PKCS#11-presented provider fails before the length prompt: no answer is
/// consumed and the RNG is never asked.
#[test]
fn random_logged_out_provider_raises_auth_required_before_prompting() {
    let hsm = Rc::new(FakeProvider::new("hsm").with_type_name("pkcs11"));
    hsm.logout().unwrap();
    let io = scripted(&["16"]);
    let ctx = CtxBuilder::new(dyn_io(&io))
        .providers(registry(&[Rc::clone(&hsm)]))
        .build();
    let err = run_err(&ctx, "random hsm");
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert_eq!(err.message, "login required: run `login hsm`");
    assert!(io.prompts().is_empty());
    assert_eq!(io.remaining(), 1);
    assert!(random_calls(&hsm).is_empty());
    // the inline form fails the same way
    let err = run_err(&ctx, "random hsm 16");
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert!(random_calls(&hsm).is_empty());
}

#[test]
fn random_on_a_logged_in_pkcs11_presented_provider() {
    let hsm = Rc::new(FakeProvider::new("hsm").with_type_name("pkcs11"));
    let io = scripted(&[]);
    let ctx = CtxBuilder::new(dyn_io(&io))
        .providers(registry(&[Rc::clone(&hsm)]))
        .build();
    run_line(&ctx, "random hsm 8").unwrap();
    let expected = FakeProvider::new("hsm")
        .with_type_name("pkcs11")
        .generate_random(8)
        .unwrap()
        .to_vec();
    assert_eq!(
        io.renderables(),
        [r2_core::io::hex(&expected, Some("random — hsm"))]
    );
}

/// CKR_RANDOM_NO_RNG (0x121) exactly as the §5.2 choke point reports it (message, CKR,
/// no hint — see r2-pkcs11 `generate_random_ckr_failures_go_through_the_choke_point`).
fn no_rng() -> ConsoleError {
    ConsoleError::pkcs11(
        "PKCS#11 random generation failed (CKR_RANDOM_NO_RNG)",
        0x121,
        "CKR_RANDOM_NO_RNG",
    )
}

/// A provider error from generate_random reaches the REPL unchanged; nothing is printed.
#[test]
fn random_provider_error_propagates_unchanged() {
    struct Failing;
    impl FakeHooks for Failing {
        fn generate_random(
            &self,
            _next: &dyn Provider,
            _len: usize,
        ) -> Option<Result<Zeroizing<Vec<u8>>>> {
            Some(Err(no_rng()))
        }
    }
    let mem = Rc::new(FakeProvider::new("mem").with_hooks(Rc::new(Failing)));
    let io = scripted(&[]);
    let ctx = CtxBuilder::new(dyn_io(&io))
        .providers(registry(&[Rc::clone(&mem)]))
        .build();
    let err = run_err(&ctx, "random mem 16");
    assert_eq!(err, no_rng());
    assert_eq!(err.ckr(), Some((0x121, "CKR_RANDOM_NO_RNG")));
    assert_eq!(err.hint, None);
    assert!(io.output().is_empty(), "{:?}", io.output());
}

/// §11 D13: a Ctrl-C flag set while the RNG ran is honored before any output.
#[test]
fn interrupt_flag_stops_the_random_output() {
    let _lock = r2_testkit::global_state_lock();
    struct Interrupting;
    impl FakeHooks for Interrupting {
        fn generate_random(
            &self,
            next: &dyn Provider,
            len: usize,
        ) -> Option<Result<Zeroizing<Vec<u8>>>> {
            r2_core::runtime::request_interrupt_on_this_thread();
            Some(next.generate_random(len))
        }
    }
    let mem = Rc::new(FakeProvider::new("mem").with_hooks(Rc::new(Interrupting)));
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("rnd.bin");
    let io = scripted(&[]);
    let ctx = CtxBuilder::new(dyn_io(&io))
        .providers(registry(&[Rc::clone(&mem)]))
        .build();
    for line in [
        "random mem 16".to_owned(),
        format!("random mem 16 --out {}", out.display()),
    ] {
        r2_core::runtime::reset_interrupt();
        let result = crate::testing::run_line(&ctx, &line);
        r2_core::runtime::reset_interrupt();
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorKind::UserAbort, "{line}");
    }
    assert_eq!(random_calls(&mem).len(), 2);
    assert!(!out.exists());
    assert!(io.output().is_empty(), "{:?}", io.output());
}

// ---------------------------------------------------------------------------
// completion and help
// ---------------------------------------------------------------------------

#[test]
fn random_completion() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("alpha.txt"), b"a").unwrap();
    let root = dir.path().display().to_string();
    let hsm = Rc::new(FakeProvider::new("hsm").with_type_name("pkcs11"));
    let mem = Rc::new(FakeProvider::new("mem"));
    let ctx = CtxBuilder::new(dyn_io(&scripted(&[])))
        .providers(registry(&[hsm, mem]))
        .build();
    // first argument: provider names
    let providers = complete(&ctx, &["random"], "");
    assert!(providers.contains(&"mem".to_owned()), "{providers:?}");
    assert!(providers.contains(&"hsm".to_owned()), "{providers:?}");
    assert_eq!(complete(&ctx, &["random", "m"], "m"), ["mem"]);
    // after the provider (and after the length): the options
    assert_eq!(
        complete(&ctx, &["random", "mem"], ""),
        ["--out", "--outformat"]
    );
    assert_eq!(
        complete(&ctx, &["random", "mem", "16"], ""),
        ["--out", "--outformat"]
    );
    // --out completes paths (§5.1 PathCompleter rule)
    let prefix = format!("{root}/al");
    assert_eq!(
        complete(&ctx, &["random", "mem", "16", "--out", &prefix], &prefix),
        [format!("{root}/alpha.txt")]
    );
    // the --outformat value: no candidates
    assert!(complete(&ctx, &["random", "mem", "--outformat"], "").is_empty());
    assert!(complete(&ctx, &["random", "mem", "--outformat", "h"], "h").is_empty());
}

#[test]
fn help_random_shows_usage_and_summary() {
    let io = scripted(&[]);
    let (ctx, _) = make_ctx(&io);
    run_line(&ctx, "help random").unwrap();
    assert_eq!(
        io.output(),
        [
            format!("usage: {USAGE}"),
            "Generate random bytes with a provider's RNG".to_owned(),
        ]
    );
    // and it is listed by bare `help`
    let io = scripted(&[]);
    let (ctx, _) = make_ctx(&io);
    run_line(&ctx, "help").unwrap();
    let listing = &io.output()[0];
    assert!(listing.contains("random"));
    assert!(listing.contains("Generate random bytes with a provider's RNG"));
}
