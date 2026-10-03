// Crypto command tests (spec §5.1; owner R9) — the port of c2 tests/unit/test_crypto_cmd.py,
// the `ops`/`sign`/`verify` cases of tests/unit/console/test_keys_cmd_objects.py and the R9
// cases of tests/unit/test_l13_hardening.py.
//
// Everything runs against FakeProvider + ScriptedIo (spec §4.10) — arg parsing, the §5.1
// positional-2 mech-vs-data disambiguation, the interactive fallbacks (mech select list,
// ParamResolver prompting, payload paste), DataInput/DataOutput wiring
// (--in/--out/--sig/--sig-file) and the capability-filtered `ops` table. c2's RenderingIO
// (rich at width 200, no terminal) is ScriptedIo itself: its output() is `render_plain` at
// RenderConfig::CAPTURE (§4.10.1).
use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use indexmap::IndexMap;
use r2_core::codec::format_hex;
use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::io::{CommandInput, ConsoleIo, Renderable, Span, Tone};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::{ParamSpec, ParamValue, Params, Verb};
use r2_core::render::{RenderConfig, render_plain};
use r2_provider::{
    DeriveResult, GenerateRequest, KeySelector, MechanismInvocation, Provider, ProviderRegistry,
};
use r2_testkit::{FakeHooks, FakeProvider, ScriptedIo};
use secrecy::SecretString;

use crate::commands::Command;
use crate::commands::crypto::{probe_keys, public_half_for_verify};
use crate::completer::complete_paths;
use crate::context::AppContext;
use crate::io::line::{Sink, SinkTarget, WidthRule};
use crate::io::{LineIo, LineReader, ReadOutcome, SecretRead, SinkStyle};
use crate::testing::{CtxBuilder, make_config};

const AES_KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const IV_12: &str = "000102030405060708090a0b";
const IV_16: &str = "000102030405060708090a0b0c0d0e0f";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// ScriptedIo that records the option lists offered to `select()` (c2 SelectRecordingIO).
struct SelectRecordingIo {
    inner: ScriptedIo,
    select_options: RefCell<Vec<Vec<String>>>,
}

impl SelectRecordingIo {
    fn new(answers: &[&str]) -> Self {
        Self {
            inner: ScriptedIo::new(answers.iter().copied()),
            select_options: RefCell::new(Vec::new()),
        }
    }
    fn select_options(&self) -> Vec<Vec<String>> {
        self.select_options.borrow().clone()
    }
}

impl ConsoleIo for SelectRecordingIo {
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
        self.select_options.borrow_mut().push(options.to_vec());
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
    fn read_command(&self, prompt: &str) -> Result<CommandInput> {
        self.inner.read_command(prompt)
    }
}

fn material(algorithm: KeyAlgorithm, key_class: KeyClass, data: &[u8]) -> KeyMaterial {
    KeyMaterial::new(algorithm, key_class, data.to_vec())
}

fn ec_material(data: &[u8]) -> KeyMaterial {
    let mut material = material(KeyAlgorithm::Ec, KeyClass::Private, data);
    material.curve = Some(Curve::P256);
    material
}

/// c2 `make_mem`: AES key "aeskey" (bytes 0..16) and P-256 private key "eckey" (0x11 × 32).
fn make_mem(mechanisms: Option<&[&str]>) -> Rc<FakeProvider> {
    let mut mem = FakeProvider::new("mem");
    if let Some(mechanisms) = mechanisms {
        mem = mem.with_mechanisms(mechanisms.iter().copied());
    }
    mem.import_key(
        &material(KeyAlgorithm::Aes, KeyClass::Secret, &AES_KEY),
        "aeskey",
        None,
        None,
    )
    .unwrap();
    mem.import_key(&ec_material(&[0x11; 32]), "eckey", None, None)
        .unwrap();
    Rc::new(mem)
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

/// c2 `make_ctx` with the default `make_mem()` registry.
fn make_ctx(io: Rc<dyn ConsoleIo>) -> (Rc<AppContext>, Rc<FakeProvider>) {
    let mem = make_mem(None);
    let ctx = CtxBuilder::new(io)
        .providers(registry(&[Rc::clone(&mem)]))
        .build();
    (ctx, mem)
}

fn ctx_with(io: Rc<dyn ConsoleIo>, providers: ProviderRegistry) -> Rc<AppContext> {
    CtxBuilder::new(io).providers(providers).build()
}

fn scripted(answers: &[&str]) -> Rc<ScriptedIo> {
    Rc::new(ScriptedIo::new(answers.iter().copied()))
}

fn dyn_io(io: &Rc<ScriptedIo>) -> Rc<dyn ConsoleIo> {
    Rc::clone(io) as Rc<dyn ConsoleIo>
}

fn call(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn has_call(provider: &FakeProvider, parts: &[&str]) -> bool {
    provider.calls().contains(&call(parts))
}

fn find(provider: &dyn Provider, label: &str) -> KeyInfo {
    provider.find_key(&KeySelector::label(label)).unwrap()
}

fn mech(name: &str) -> MechanismInvocation {
    MechanismInvocation::new(name, Params::new())
}

/// `crate::testing::run_line` under the process-global state lock: the verbs honor the
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

fn command(name: &str) -> Rc<dyn Command> {
    let table = crate::commands::all_commands().unwrap();
    Rc::clone(table.get(name).unwrap())
}

fn complete(ctx: &AppContext, name: &str, tokens: &[&str], cursor: &str) -> Vec<String> {
    let tokens: Vec<String> = tokens.iter().map(|t| (*t).to_owned()).collect();
    command(name).complete(ctx, &tokens, cursor)
}

fn is_param(err: &ConsoleError) -> bool {
    matches!(err.kind, ErrorKind::Param { .. })
}

// ---------------------------------------------------------------------------
// one-line syntax & arg parsing
// ---------------------------------------------------------------------------

#[test]
fn test_encrypt_one_line_renders_hex_panel() {
    let io = scripted(&[]);
    let (ctx, mem) = make_ctx(dyn_io(&io));
    run_line(
        &ctx,
        &format!("encrypt mem:aeskey gcm iv=0x{IV_12} 0xdeadbeef"),
    )
    .unwrap();
    assert!(has_call(&mem, &["encrypt", "mem:aeskey", "AES-GCM", "4B"]));
    let key = find(mem.as_ref(), "aeskey");
    let expected = mem
        .encrypt(&key, &mech("AES-GCM"), b"\xde\xad\xbe\xef")
        .unwrap();
    let text = io.text();
    assert!(text.contains("ciphertext — AES-GCM"));
    assert!(text.contains("4 bytes"));
    // §11 D28: the hex on one unbroken line of its own
    assert!(text.contains(&format!("\n{}\n", format_hex(&expected, 0, 0))));
    // the panel itself (§4.9.2): a Hex renderable titled with what the bytes are
    assert_eq!(
        io.renderables(),
        [Renderable::Hex {
            data: expected,
            title: Some("ciphertext — AES-GCM".to_owned()),
        }]
    );
}

#[test]
fn test_decrypt_round_trips_encrypt_inline() {
    let io = scripted(&[]);
    let (ctx, mem) = make_ctx(dyn_io(&io));
    let key = find(mem.as_ref(), "aeskey");
    let ct = mem
        .encrypt(&key, &mech("AES-ECB"), b"\xde\xad\xbe\xef")
        .unwrap();
    run_line(&ctx, &format!("decrypt mem:aeskey ecb 0x{}", hex_of(&ct))).unwrap();
    assert!(io.text().contains("\ndeadbeef\n"));
    assert!(io.text().contains("plaintext — AES-ECB"));
}

fn hex_of(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn test_decrypt_raw_with_public_half_ref() {
    // §4.3 ':pub' selector + §5.8: RAW decrypt with the public key resolves and dispatches
    // (signature recovery — real math covered in the provider tests).
    let io = scripted(&[]);
    let (ctx, mem) = make_ctx(dyn_io(&io));
    let mut request = GenerateRequest::new(KeyAlgorithm::Rsa, "pair");
    request.size_bits = Some(2048);
    mem.generate_key(&request).unwrap();
    run_line(&ctx, "decrypt mem:pair:pub raw 0xdeadbeef").unwrap();
    assert!(has_call(&mem, &["decrypt", "mem:pair", "RSA-RAW", "4B"]));
}

#[test]
fn test_inline_param_validation_failure() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let err = run_err(&ctx, "encrypt mem:aeskey cbc iv=0x00 0xdeadbeef");
    assert!(is_param(&err), "{err:?}");
    assert_eq!(err.message, "iv: expected exactly 16 bytes, got 1");
}

#[test]
fn test_unknown_param_name_raises() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let err = run_err(
        &ctx,
        &format!("encrypt mem:aeskey gcm iv=0x{IV_12} bogus=1 0xdeadbeef"),
    );
    assert!(is_param(&err), "{err:?}");
    assert_eq!(err.message, "unknown parameter 'bogus' for aes.encrypt.gcm");
    assert!(err.hint.as_deref().unwrap().contains("iv"));
}

#[test]
fn test_unknown_option_raises() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let err = run_err(
        &ctx,
        &format!("encrypt mem:aeskey gcm iv=0x{IV_12} 0xdd --sig 0x00"),
    );
    assert!(err.message.contains("--sig"));
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(err.message, "unknown option --sig");
    assert_eq!(
        err.hint.as_deref(),
        Some(
            "usage: encrypt <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>] [--out <path>] [--outformat raw|hex|b64]"
        )
    );
}

#[test]
fn test_missing_key_ref_raises_with_usage() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let err = run_err(&ctx, "encrypt");
    assert_eq!(err.message, "missing key reference");
    assert!(err.hint.as_deref().unwrap().contains("usage:"));
}

#[test]
fn test_too_many_data_positionals() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let err = run_err(
        &ctx,
        &format!("encrypt mem:aeskey gcm iv=0x{IV_12} 0xdd 0xee"),
    );
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(
        err.message,
        "too many arguments: give at most one data value"
    );
}

#[test]
fn test_inline_data_and_in_file_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.bin");
    std::fs::write(&path, b"\x00").unwrap();
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let err = run_err(
        &ctx,
        &format!(
            "encrypt mem:aeskey gcm iv=0x{IV_12} 0xdd --in {}",
            path.display()
        ),
    );
    assert_eq!(err.message, "give the data inline or with --in, not both");
    assert_eq!(
        err.hint.as_deref(),
        Some("remove the inline data token or the --in option")
    );
}

#[test]
fn test_logged_out_provider_raises_auth_required() {
    let hsm = Rc::new(FakeProvider::new("hsm").with_type_name("pkcs11"));
    hsm.import_key(
        &material(KeyAlgorithm::Aes, KeyClass::Secret, &AES_KEY),
        "aeskey",
        None,
        None,
    )
    .unwrap();
    hsm.logout().unwrap();
    let ctx = ctx_with(dyn_io(&scripted(&[])), registry(&[hsm]));
    let err = run_err(&ctx, &format!("encrypt hsm:aeskey gcm iv=0x{IV_12} 0xdd"));
    assert_eq!(err.kind, ErrorKind::AuthRequired);
}

// ---------------------------------------------------------------------------
// positional-2 mech-vs-data disambiguation (§5.1)
// ---------------------------------------------------------------------------

#[test]
fn test_unquoted_mech_name_binds_as_mechanism() {
    let io = scripted(&[]);
    let (ctx, mem) = make_ctx(dyn_io(&io));
    run_line(
        &ctx,
        &format!("encrypt mem:aeskey cbc iv=0x{IV_16} 0xdeadbeef"),
    )
    .unwrap();
    assert!(has_call(&mem, &["encrypt", "mem:aeskey", "AES-CBC", "4B"]));
    assert!(io.prompts().is_empty()); // fully inline — nothing prompted
}

#[test]
fn test_quoted_mech_shaped_token_is_data() {
    // Quoted "cbc" must NOT bind as a mechanism (§4.9 positional_quoted): the mech list is
    // prompted instead, and the token then fails to decode as data.
    let io = scripted(&["2"]); // sorted cli names: cbc, ctr, ecb, gcm → 2 = ecb
    let (ctx, _) = make_ctx(dyn_io(&io));
    let err = run_err(&ctx, "encrypt mem:aeskey \"cbc\"");
    assert_eq!(err.kind, ErrorKind::Codec);
    assert!(
        io.prompts()
            .iter()
            .any(|prompt| prompt.contains("Select encrypt mechanism"))
    );
}

#[test]
fn test_unquoted_non_mech_token_is_data_and_mech_prompted() {
    let iv = format!("0x{IV_12}");
    let io = scripted(&["3", &iv]); // select gcm, then the prompted IV
    let (ctx, mem) = make_ctx(dyn_io(&io));
    run_line(&ctx, "encrypt mem:aeskey deadbeef").unwrap();
    assert!(has_call(&mem, &["encrypt", "mem:aeskey", "AES-GCM", "4B"]));
}

#[test]
fn test_quoted_data_with_whitespace_is_decoded() {
    let io = scripted(&[]);
    let (ctx, mem) = make_ctx(dyn_io(&io));
    run_line(&ctx, "encrypt mem:aeskey ecb \"de ad be ef\"").unwrap();
    assert!(has_call(&mem, &["encrypt", "mem:aeskey", "AES-ECB", "4B"]));
}

/// r2 addition (§5.1): a positional-2 token that is no mechanism of THIS key is data even
/// when it names another key type's mechanism ("pss" for an AES key), and the select list
/// then runs.
#[test]
fn mechanism_of_another_key_type_is_data() {
    let io = scripted(&["2"]); // ecb: no prompted params
    let (ctx, _) = make_ctx(dyn_io(&io));
    let err = run_err(&ctx, "encrypt mem:aeskey pss");
    assert_eq!(err.kind, ErrorKind::Codec);
    assert_eq!(io.prompts(), ["Select encrypt mechanism for mem:aeskey"]);
}

// ---------------------------------------------------------------------------
// interactive fallbacks
// ---------------------------------------------------------------------------

#[test]
fn test_mech_select_list_filtered_by_capability() {
    let iv = format!("0x{IV_12}");
    let io = Rc::new(SelectRecordingIo::new(&["0", &iv]));
    let mem = make_mem(Some(&["AES-GCM", "AES-CMAC"]));
    let ctx = ctx_with(
        Rc::clone(&io) as Rc<dyn ConsoleIo>,
        registry(&[Rc::clone(&mem)]),
    );
    run_line(&ctx, "encrypt mem:aeskey 0xdeadbeef").unwrap();
    assert_eq!(
        io.select_options(),
        [["gcm — AES-GCM authenticated encryption"]]
    );
    assert!(has_call(&mem, &["encrypt", "mem:aeskey", "AES-GCM", "4B"]));
}

/// §4.6.2 presentation order: the select list is `available_for` sorted by (cli_name, id).
#[test]
fn select_list_is_sorted_by_cli_name() {
    let io = Rc::new(SelectRecordingIo::new(&["2"]));
    let mem = make_mem(None);
    let ctx = ctx_with(
        Rc::clone(&io) as Rc<dyn ConsoleIo>,
        registry(&[Rc::clone(&mem)]),
    );
    run_line(&ctx, "encrypt mem:aeskey 0xdeadbeef").unwrap();
    assert_eq!(
        io.select_options(),
        [[
            "cbc — AES-CBC encryption",
            "ctr — AES-CTR encryption",
            "ecb — AES-ECB encryption",
            "gcm — AES-GCM authenticated encryption",
        ]]
    );
    assert!(has_call(&mem, &["encrypt", "mem:aeskey", "AES-ECB", "4B"]));
}

#[test]
fn test_no_available_mechanism_raises() {
    let mem = make_mem(Some(&[]));
    let ctx = ctx_with(dyn_io(&scripted(&[])), registry(&[mem]));
    let err = run_err(&ctx, "encrypt mem:aeskey 0xdeadbeef");
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(
        err.message,
        "no encrypt operations available for mem:aeskey"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("see `ops mem` — support depends on the provider capabilities and login state")
    );
}

#[test]
fn test_missing_required_param_is_prompted() {
    let iv = format!("0x{IV_16}");
    let io = scripted(&[&iv]);
    let (ctx, mem) = make_ctx(dyn_io(&io));
    run_line(&ctx, "encrypt mem:aeskey cbc 0xdeadbeef").unwrap();
    assert!(io.prompts().contains(&"IV (16 bytes)".to_owned()));
    assert!(has_call(&mem, &["encrypt", "mem:aeskey", "AES-CBC", "4B"]));
}

#[test]
fn test_missing_data_prompts_multiline_paste() {
    let io = scripted(&["00 11 22 33"]);
    let (ctx, mem) = make_ctx(dyn_io(&io));
    run_line(&ctx, "encrypt mem:aeskey ecb").unwrap();
    assert!(
        io.prompts()
            .contains(&"Data (hex, base64 or PEM)".to_owned())
    );
    assert!(has_call(&mem, &["encrypt", "mem:aeskey", "AES-ECB", "4B"]));
}

/// Ctrl-C in the mechanism select / the paste prompt is the IO's UserAbort (`Aborted.`).
#[test]
fn ctrl_c_in_the_fallbacks_aborts() {
    let io = scripted(&[ScriptedIo::CTRL_C]);
    let (ctx, mem) = make_ctx(dyn_io(&io));
    let err = run_err(&ctx, "encrypt mem:aeskey 0xdeadbeef");
    assert_eq!(err.kind, ErrorKind::UserAbort);
    let io = scripted(&[ScriptedIo::CTRL_C]);
    let ctx = ctx_with(dyn_io(&io), registry(&[Rc::clone(&mem)]));
    let err = run_err(&ctx, "encrypt mem:aeskey ecb");
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert!(
        !mem.calls()
            .iter()
            .any(|call| call.first().is_some_and(|m| m == "encrypt"))
    );
}

// ---------------------------------------------------------------------------
// file in/out (§4.4 DataInput/DataOutput wiring)
// ---------------------------------------------------------------------------

#[test]
fn test_file_in_out_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let plaintext: Vec<u8> = (0..=255u8).collect(); // not printable ASCII → read verbatim
    let source = dir.path().join("pt.bin");
    std::fs::write(&source, &plaintext).unwrap();
    let ct_path = dir.path().join("ct.hex");
    let back = dir.path().join("back.bin");
    let io = scripted(&[]);
    let (ctx, _) = make_ctx(dyn_io(&io));
    run_line(
        &ctx,
        &format!(
            "encrypt mem:aeskey ecb --in {} --out {} --outformat hex",
            source.display(),
            ct_path.display()
        ),
    )
    .unwrap();
    let ct_text = std::fs::read_to_string(&ct_path).unwrap();
    let ct = r2_core::text::py_fromhex(ct_text.trim()).unwrap();
    assert_eq!(ct.len(), plaintext.len());
    run_line(
        &ctx,
        &format!(
            "decrypt mem:aeskey ecb --in {} --out {}",
            ct_path.display(),
            back.display()
        ),
    )
    .unwrap();
    assert_eq!(std::fs::read(&back).unwrap(), plaintext);
    assert!(
        io.output()
            .iter()
            .any(|line| line.contains("wrote 256 bytes"))
    );
    assert_eq!(
        io.output()[0],
        format!("wrote 256 bytes to {}", ct_path.display())
    );
}

/// The written path is shown as Python's `Path(out)` (`r2_core::text::py_path`, §4.4).
#[test]
fn out_path_is_shown_normalized() {
    let dir = tempfile::tempdir().unwrap();
    let io = scripted(&[]);
    let (ctx, _) = make_ctx(dyn_io(&io));
    let typed = format!("{}//./z.bin", dir.path().display());
    run_line(
        &ctx,
        &format!("encrypt mem:aeskey ecb 0xdeadbeef --out {typed}"),
    )
    .unwrap();
    assert_eq!(
        io.output(),
        [format!(
            "wrote 4 bytes to {}",
            dir.path().join("z.bin").display()
        )]
    );
}

#[test]
fn test_out_raw_is_default_and_b64_encodes() {
    let dir = tempfile::tempdir().unwrap();
    let raw_path = dir.path().join("out.raw");
    let b64_path = dir.path().join("out.b64");
    let (ctx, mem) = make_ctx(dyn_io(&scripted(&[])));
    let key = find(mem.as_ref(), "aeskey");
    let expected = mem
        .encrypt(&key, &mech("AES-ECB"), b"\xde\xad\xbe\xef")
        .unwrap();
    run_line(
        &ctx,
        &format!(
            "encrypt mem:aeskey ecb 0xdeadbeef --out {}",
            raw_path.display()
        ),
    )
    .unwrap();
    run_line(
        &ctx,
        &format!(
            "encrypt mem:aeskey ecb 0xdeadbeef --out {} --outformat b64",
            b64_path.display()
        ),
    )
    .unwrap();
    assert_eq!(std::fs::read(&raw_path).unwrap(), expected);
    let b64_text = std::fs::read_to_string(&b64_path).unwrap();
    let (decoded, _) = r2_core::codec::decode_data(&format!("b64:{}", b64_text.trim())).unwrap();
    assert_eq!(*decoded, expected);
}

#[test]
fn test_outformat_requires_out() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let err = run_err(&ctx, "encrypt mem:aeskey ecb 0xdeadbeef --outformat hex");
    assert_eq!(err.message, "--outformat requires --out");
    assert_eq!(
        err.hint.as_deref(),
        Some("console output is always the grouped hex dump (§5.1)")
    );
}

#[test]
fn test_invalid_outformat_rejected() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let err = run_err(
        &ctx,
        "encrypt mem:aeskey ecb 0xdeadbeef --out x --outformat nope",
    );
    assert_eq!(err.message, "invalid --outformat 'nope'");
    assert_eq!(err.hint.as_deref(), Some("choose one of: raw, hex, b64"));
}

/// A LineReader that never has input (the hex test only prints).
struct NoInput;
impl LineReader for NoInput {
    fn read_command(&mut self, _prompt: &str) -> io::Result<ReadOutcome> {
        Ok(ReadOutcome::Eof)
    }
    fn read_param(&mut self, _prompt: &str, _choices: &[String]) -> io::Result<ReadOutcome> {
        Ok(ReadOutcome::Eof)
    }
    fn read_secret(&mut self, _prompt: &str) -> io::Result<SecretRead> {
        Ok(SecretRead::Eof)
    }
}

/// c2 `test_hex_panel_honors_ui_config`, under §11 D28: the session IO built from a config
/// with its own `ui.hex_group`/`ui.hex_width` still prints the result as one unbroken line.
#[test]
fn test_hex_panel_ignores_ui_hex_layout() {
    let config = make_config(Some("ui: {hex_group: 4, hex_width: 8}\n"));
    let out = Rc::new(RefCell::new(Vec::new()));
    let sink = Sink {
        style: SinkStyle::Plain,
        target: SinkTarget::Capture(Rc::clone(&out)),
        width: WidthRule::Fixed(200),
    };
    let line_io = Rc::new(LineIo::new(
        NoInput,
        sink,
        config.ui.hex_group,
        config.ui.hex_width,
        false,
    ));
    let mem = make_mem(None);
    let ctx = CtxBuilder::new(line_io as Rc<dyn ConsoleIo>)
        .config(config)
        .providers(registry(&[Rc::clone(&mem)]))
        .build();
    run_line(
        &ctx,
        &format!("encrypt mem:aeskey ecb 0x{}", "00".repeat(16)),
    )
    .unwrap();
    let key = find(mem.as_ref(), "aeskey");
    let expected = mem.encrypt(&key, &mech("AES-ECB"), &[0u8; 16]).unwrap();
    let text = String::from_utf8(out.borrow().clone()).unwrap();
    let rows: Vec<&str> = text.lines().collect();
    assert_eq!(rows.len(), 3, "{text}");
    assert!(rows[0].starts_with("╭─ ciphertext — AES-ECB "), "{text}");
    assert_eq!(rows[1], format_hex(&expected, 0, 0));
    assert!(rows[2].ends_with(" 16 bytes ─╯"), "{text}");
}

// ---------------------------------------------------------------------------
// verify — signature sources (§5.1: --sig | --sig-file | prompt)
// ---------------------------------------------------------------------------

fn cmac(mem: &FakeProvider, data: &[u8]) -> Vec<u8> {
    let key = find(mem, "aeskey");
    let mut params = Params::new();
    params.insert("mac_len".to_owned(), ParamValue::Int(16));
    mem.sign(&key, &MechanismInvocation::new("AES-CMAC", params), data)
        .unwrap()
}

#[test]
fn test_verify_sig_inline_valid_and_tampered() {
    let io = scripted(&[]);
    let (ctx, mem) = make_ctx(dyn_io(&io));
    let mac = cmac(&mem, b"\xde\xad\xbe\xef");
    run_line(
        &ctx,
        &format!("verify mem:aeskey cmac 0xdeadbeef --sig 0x{}", hex_of(&mac)),
    )
    .unwrap();
    run_line(
        &ctx,
        &format!("verify mem:aeskey cmac 0xdeadbe00 --sig 0x{}", hex_of(&mac)),
    )
    .unwrap();
    assert_eq!(io.output(), ["signature VALID", "signature INVALID"]);
    // c2 styles: bold green / bold red
    assert_eq!(
        io.renderables(),
        [
            Renderable::Styled(vec![vec![Span {
                text: "signature VALID".to_owned(),
                tone: Tone::Success,
            }]]),
            Renderable::Styled(vec![vec![Span {
                text: "signature INVALID".to_owned(),
                tone: Tone::Error,
            }]]),
        ]
    );
}

#[test]
fn test_verify_sig_file() {
    let dir = tempfile::tempdir().unwrap();
    let sig_path = dir.path().join("sig.bin");
    let io = scripted(&[]);
    let (ctx, mem) = make_ctx(dyn_io(&io));
    run_line(
        &ctx,
        &format!(
            "sign mem:aeskey cmac 0xdeadbeef --out {}",
            sig_path.display()
        ),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(&sig_path).unwrap(),
        cmac(&mem, b"\xde\xad\xbe\xef")
    );
    run_line(
        &ctx,
        &format!(
            "verify mem:aeskey cmac 0xdeadbeef --sig-file {}",
            sig_path.display()
        ),
    )
    .unwrap();
    assert!(io.output().contains(&"signature VALID".to_owned()));
}

#[test]
fn test_verify_signature_prompted_when_no_source_given() {
    let (_ctx0, mem0) = make_ctx(dyn_io(&scripted(&[])));
    let mac = format!("0x{}", hex_of(&cmac(&mem0, b"\xde\xad\xbe\xef")));
    let io = scripted(&[&mac]);
    let (ctx, _) = make_ctx(dyn_io(&io));
    run_line(&ctx, "verify mem:aeskey cmac 0xdeadbeef").unwrap();
    assert!(
        io.prompts()
            .contains(&"Signature (hex or base64)".to_owned())
    );
    assert!(io.output().contains(&"signature VALID".to_owned()));
}

#[test]
fn test_verify_both_sig_sources_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let err = run_err(
        &ctx,
        &format!(
            "verify mem:aeskey cmac 0xdead --sig 0x00 --sig-file {}",
            dir.path().join("s").display()
        ),
    );
    assert_eq!(
        err.message,
        "give the signature with --sig or --sig-file, not both"
    );
    assert_eq!(err.hint.as_deref(), Some("remove one of the two options"));
}

/// verify's options are --in/--sig/--sig-file: --out is unknown there.
#[test]
fn verify_rejects_out() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let err = run_err(&ctx, "verify mem:aeskey cmac 0xdead --sig 0x00 --out x");
    assert_eq!(err.message, "unknown option --out");
    assert_eq!(
        err.hint.as_deref(),
        Some(
            "usage: verify <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>] (--sig <data> | --sig-file <path>)"
        )
    );
}

// ---------------------------------------------------------------------------
// derive
// ---------------------------------------------------------------------------

#[test]
fn test_derive_renders_raw_secret_hex() {
    let io = scripted(&[]);
    let (ctx, mem) = make_ctx(dyn_io(&io));
    run_line(&ctx, "derive mem:eckey ecdh peer=0x0411223344").unwrap();
    assert!(has_call(&mem, &["derive", "mem:eckey", "ECDH"]));
    let text = io.text();
    assert!(text.contains("derived secret — ECDH"));
    assert!(text.contains("32 bytes"));
}

#[test]
fn test_derive_rejects_data_positional() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let err = run_err(&ctx, "derive mem:eckey ecdh 0xdead");
    assert_eq!(err.message, "derive takes no data argument");
    assert_eq!(
        err.hint.as_deref(),
        Some(
            "derive inputs are name=value parameters — usage: derive <provider>:<label> [<mech>] [<name>=<value> ...] [--out <path>] [--outformat raw|hex|b64]"
        )
    );
    let err = run_err(&ctx, "derive mem:eckey 0xdead");
    assert_eq!(err.message, "derive takes no data argument");
}

/// §5.10 pkcs11 shape: token refuses extractable secrets → key-only result.
struct KeyOnlyDerive;
impl FakeHooks for KeyOnlyDerive {
    fn derive(
        &self,
        _next: &dyn Provider,
        key: &KeyInfo,
        _mech: &MechanismInvocation,
    ) -> Option<Result<DeriveResult>> {
        Some(Ok(DeriveResult {
            key: Some(key.clone()),
            raw: None,
        }))
    }
}

fn key_only_ctx(io: Rc<dyn ConsoleIo>) -> Rc<AppContext> {
    let hsm = FakeProvider::new("hsm")
        .with_type_name("pkcs11")
        .with_hooks(Rc::new(KeyOnlyDerive));
    hsm.import_key(&ec_material(&[0x22; 32]), "eckey", None, None)
        .unwrap();
    ctx_with(io, registry(&[Rc::new(hsm)]))
}

#[test]
fn test_derive_key_only_renders_resident_ref() {
    let io = scripted(&[]);
    let ctx = key_only_ctx(dyn_io(&io));
    run_line(&ctx, "derive hsm:eckey ecdh peer=0x04").unwrap();
    assert!(
        io.output()
            .iter()
            .any(|line| line.starts_with("derived key (provider-resident): hsm:eckey"))
    );
}

#[test]
fn test_derive_key_only_with_out_file_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = key_only_ctx(dyn_io(&scripted(&[])));
    let err = run_err(
        &ctx,
        &format!(
            "derive hsm:eckey ecdh peer=0x04 --out {}",
            dir.path().join("z.bin").display()
        ),
    );
    assert!(err.message.contains("provider-resident"));
    assert_eq!(
        err.message,
        "derived key is provider-resident — there is no raw secret to write"
    );
    assert!(
        err.hint
            .as_deref()
            .unwrap()
            .starts_with("result key: hsm:eckey")
    );
    assert!(!dir.path().join("z.bin").exists());
}

/// A provider returning neither raw nor key → Crypto (c2 CryptoError).
struct EmptyDerive;
impl FakeHooks for EmptyDerive {
    fn derive(
        &self,
        _next: &dyn Provider,
        _key: &KeyInfo,
        _mech: &MechanismInvocation,
    ) -> Option<Result<DeriveResult>> {
        Some(Ok(DeriveResult {
            key: None,
            raw: None,
        }))
    }
}

#[test]
fn derive_with_neither_result_is_a_crypto_error() {
    let mem = FakeProvider::new("mem").with_hooks(Rc::new(EmptyDerive));
    mem.import_key(&ec_material(&[0x11; 32]), "eckey", None, None)
        .unwrap();
    let ctx = ctx_with(dyn_io(&scripted(&[])), registry(&[Rc::new(mem)]));
    let err = run_err(&ctx, "derive mem:eckey ecdh peer=0x04");
    assert_eq!(err.kind, ErrorKind::Crypto);
    assert_eq!(
        err.message,
        "derive returned neither a raw secret nor a provider-resident key"
    );
}

// ---------------------------------------------------------------------------
// ops — capability-filtered table
// ---------------------------------------------------------------------------

fn ops_providers(hsm_mechanisms: &[&str]) -> (ProviderRegistry, Rc<FakeProvider>) {
    let hsm = Rc::new(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .with_mechanisms(hsm_mechanisms.iter().copied()),
    );
    (registry(&[make_mem(None), Rc::clone(&hsm)]), hsm)
}

#[test]
fn test_ops_lists_every_provider() {
    let io = scripted(&[]);
    let (providers, _) = ops_providers(&["AES-GCM"]);
    let ctx = ctx_with(dyn_io(&io), providers);
    run_line(&ctx, "ops").unwrap();
    let text = io.text();
    assert!(text.contains("operations — mem"));
    assert!(text.contains("operations — hsm"));
}

#[test]
fn test_ops_table_filtered_by_capability() {
    let io = scripted(&[]);
    let (providers, _) = ops_providers(&["AES-GCM", "RSA-PSS"]);
    let ctx = ctx_with(dyn_io(&io), providers);
    run_line(&ctx, "ops hsm").unwrap();
    let text = io.text();
    assert!(text.contains("gcm"));
    assert!(text.contains("pss"));
    assert!(!text.contains("cmac"));
    assert!(!text.contains("oaep"));
    assert!(!text.contains("ecdsa"));
}

#[test]
fn test_ops_full_capability_includes_curve_bound_ops() {
    let io = scripted(&[]);
    let (ctx, _) = make_ctx(dyn_io(&io));
    run_line(&ctx, "ops mem").unwrap();
    let text = io.text();
    for cli_name in [
        "gcm", "cmac", "oaep", "pss", "ecdsa", "eddsa", "ecdh", "x25519", "x448",
    ] {
        assert!(text.contains(cli_name), "{cli_name}");
    }
}

/// The table itself (§4.6.2 `_merge_specs`): every verb in declaration order, then
/// cli_name, then id; one row per spec id; params joined or "—".
#[test]
fn ops_table_rows_follow_merge_order() {
    let io = scripted(&[]);
    let (ctx, _) = make_ctx(dyn_io(&io));
    run_line(&ctx, "ops mem").unwrap();
    let renderables = io.renderables();
    let [Renderable::Table(table)] = renderables.as_slice() else {
        panic!("{renderables:?}");
    };
    assert_eq!(table.title.as_deref(), Some("operations — mem"));
    assert_eq!(
        table.columns,
        ["verb", "op", "mechanism", "params", "description"]
    );
    let ops: Vec<(String, String)> = table
        .rows
        .iter()
        .map(|row| (row[0].clone(), row[1].clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("encrypt", "cbc"),
        ("encrypt", "ctr"),
        ("encrypt", "ecb"),
        ("encrypt", "gcm"),
        ("encrypt", "oaep"),
        ("encrypt", "pkcs1"),
        ("encrypt", "raw"),
        ("decrypt", "cbc"),
        ("decrypt", "ctr"),
        ("decrypt", "ecb"),
        ("decrypt", "gcm"),
        ("decrypt", "oaep"),
        ("decrypt", "pkcs1"),
        ("decrypt", "raw"),
        ("sign", "cmac"),
        ("sign", "ecdsa"),
        ("sign", "eddsa"),
        ("sign", "gmac"),
        ("sign", "hmac"),
        ("sign", "pkcs1"),
        ("sign", "pss"),
        ("sign", "raw"),
        ("verify", "cmac"),
        ("verify", "ecdsa"),
        ("verify", "eddsa"),
        ("verify", "gmac"),
        ("verify", "hmac"),
        ("verify", "pkcs1"),
        ("verify", "pss"),
        ("verify", "raw"),
        ("derive", "ecdh"),
        ("derive", "x25519"),
        ("derive", "x448"),
    ]
    .iter()
    .map(|(verb, op)| ((*verb).to_owned(), (*op).to_owned()))
    .collect();
    assert_eq!(ops, expected);
    let pkcs1 = table
        .rows
        .iter()
        .find(|row| row[0] == "encrypt" && row[1] == "pkcs1")
        .unwrap();
    assert_eq!(
        pkcs1,
        &[
            "encrypt",
            "pkcs1",
            "RSA-PKCS1",
            "—",
            "RSA PKCS#1 v1.5 encryption"
        ]
    );
    let gcm = table
        .rows
        .iter()
        .find(|row| row[0] == "encrypt" && row[1] == "gcm")
        .unwrap();
    assert_eq!(gcm[3], "iv, aad, tag_bits");
}

/// c2 `_probe_keys`: AES/GENERIC secret, RSA/EC/EdDSA/X keys as private + public per curve.
#[test]
fn probe_keys_span_every_family() {
    let probes = probe_keys("mem");
    let shape: Vec<(KeyAlgorithm, KeyClass, Option<&str>)> = probes
        .iter()
        .map(|info| {
            (
                info.algorithm,
                info.key_class,
                info.curve.as_ref().map(Curve::as_str),
            )
        })
        .collect();
    use KeyAlgorithm::{Aes, Ec, EcEdwards, EcMontgomery, Generic, Rsa};
    use KeyClass::{Private, Public, Secret};
    assert_eq!(
        shape,
        [
            (Aes, Secret, None),
            (Generic, Secret, None),
            (Rsa, Private, None),
            (Rsa, Public, None),
            (Ec, Private, Some("p256")),
            (Ec, Public, Some("p256")),
            (Ec, Private, Some("p384")),
            (Ec, Public, Some("p384")),
            (Ec, Private, Some("p521")),
            (Ec, Public, Some("p521")),
            (EcEdwards, Private, Some("ed25519")),
            (EcEdwards, Public, Some("ed25519")),
            (EcEdwards, Private, Some("ed448")),
            (EcEdwards, Public, Some("ed448")),
            (EcMontgomery, Private, Some("x25519")),
            (EcMontgomery, Public, Some("x25519")),
            (EcMontgomery, Private, Some("x448")),
            (EcMontgomery, Public, Some("x448")),
        ]
    );
    assert!(probes.iter().all(|info| info.key_ref.display() == "mem:?"));
}

#[test]
fn test_ops_reflects_logged_out_provider() {
    let (providers, hsm) = ops_providers(&["AES-GCM"]);
    hsm.logout().unwrap();
    let io = scripted(&[]);
    let ctx = ctx_with(dyn_io(&io), providers);
    run_line(&ctx, "ops hsm").unwrap();
    assert!(
        io.output()
            .iter()
            .any(|line| line.contains("no operations available") && line.contains("logged out"))
    );
    assert_eq!(
        io.output(),
        ["hsm: no operations available (logged out — run `login hsm`)"]
    );
}

/// A logged-in provider without mechanisms gets the line without the login note.
#[test]
fn ops_without_mechanisms_has_no_login_note() {
    let (providers, _) = ops_providers(&[]);
    let io = scripted(&[]);
    let ctx = ctx_with(dyn_io(&io), providers);
    run_line(&ctx, "ops hsm").unwrap();
    assert_eq!(io.output(), ["hsm: no operations available"]);
}

#[test]
fn test_ops_key_filter_restricts_to_key_class_and_algorithm() {
    let io = scripted(&[]);
    let (ctx, _) = make_ctx(dyn_io(&io));
    run_line(&ctx, "ops --key mem:aeskey").unwrap();
    let text = io.text();
    assert!(text.contains("operations for mem:aeskey"));
    assert!(text.contains("gcm"));
    assert!(text.contains("cmac"));
    assert!(!text.contains("oaep"));
    assert!(!text.contains("ecdsa"));
}

#[test]
fn test_ops_key_and_mismatched_provider_conflict() {
    let (providers, _) = ops_providers(&[]);
    let ctx = ctx_with(dyn_io(&scripted(&[])), providers);
    let err = run_err(&ctx, "ops hsm --key mem:aeskey");
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(
        err.message,
        "key mem:aeskey does not live on provider 'hsm'"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("omit the provider argument, or name the key's own provider")
    );
}

#[test]
fn test_ops_unknown_provider() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let err = run_err(&ctx, "ops nosuch");
    assert_eq!(err.kind, ErrorKind::ProviderNotFound);
}

/// `ops` arity and options (c2 texts).
#[test]
fn ops_argument_errors() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let err = run_err(&ctx, "ops mem hsm");
    assert_eq!(err.message, "too many arguments");
    assert_eq!(
        err.hint.as_deref(),
        Some("usage: ops [<provider>] [--key <provider>:<label>]")
    );
    let err = run_err(&ctx, "ops --in x");
    assert_eq!(err.message, "unknown option --in");
}

// ---------------------------------------------------------------------------
// completion
// ---------------------------------------------------------------------------

#[test]
fn test_complete_ref_then_mech_then_params() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let refs = complete(&ctx, "encrypt", &["encrypt", "mem:a"], "mem:a");
    assert!(refs.contains(&"mem:aeskey".to_owned()));
    let mechs = complete(&ctx, "encrypt", &["encrypt", "mem:aeskey"], "");
    assert!(mechs.contains(&"gcm".to_owned()));
    assert!(mechs.contains(&"--out".to_owned()));
    assert_eq!(
        mechs,
        ["cbc", "ctr", "ecb", "gcm", "--in", "--out", "--outformat"]
    );
    let params = complete(&ctx, "encrypt", &["encrypt", "mem:aeskey", "gcm"], "");
    assert!(params.contains(&"iv=".to_owned()));
    assert_eq!(
        params,
        ["aad=", "iv=", "tag_bits=", "--in", "--out", "--outformat"]
    );
    // L13: file options complete filesystem paths (§5.1 PathCompleter rule); non-path
    // option values (e.g. inline data) still complete to nothing.
    assert_eq!(
        complete(
            &ctx,
            "encrypt",
            &["encrypt", "mem:aeskey", "gcm", "--in"],
            ""
        ),
        complete_paths("")
    );
}

/// Unknown mechanism on the line → the param names of every available spec.
#[test]
fn param_stage_without_a_known_mechanism_pools_every_spec() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let params = complete(&ctx, "sign", &["sign", "mem:aeskey", "0xdead"], "");
    assert_eq!(params, ["iv=", "mac_len=", "--in", "--out", "--outformat"]);
    // derive offers only its own options
    let derive = complete(&ctx, "derive", &["derive", "mem:eckey"], "");
    assert_eq!(derive, ["ecdh", "--out", "--outformat"]);
}

#[test]
fn test_complete_ref_selector_stages() {
    // §4.3 selector continuations reach the verbs through complete_refs
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    assert_eq!(
        complete(&ctx, "encrypt", &["encrypt", "mem:aeskey:"], "mem:aeskey:"),
        ["mem:aeskey:secret"]
    );
    assert_eq!(
        complete(&ctx, "sign", &["sign", "mem:eckey:"], "mem:eckey:"),
        ["mem:eckey:priv"]
    );
}

#[test]
fn test_complete_never_lists_keys_of_logged_out_provider() {
    let (providers, hsm) = ops_providers(&["AES-GCM"]);
    hsm.import_key(
        &material(KeyAlgorithm::Aes, KeyClass::Secret, &AES_KEY),
        "aeskey",
        None,
        None,
    )
    .unwrap();
    hsm.logout().unwrap();
    let ctx = ctx_with(dyn_io(&scripted(&[])), providers);
    let candidates = complete(&ctx, "encrypt", &["encrypt", "hsm:aeskey"], "");
    assert!(!candidates.contains(&"gcm".to_owned())); // §6: no browsing while logged out
    assert_eq!(candidates, ["--in", "--out", "--outformat"]);
}

#[test]
fn test_complete_ops() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let top = complete(&ctx, "ops", &["ops"], "");
    assert!(top.contains(&"--key".to_owned()));
    assert!(top.contains(&"mem".to_owned()));
    let prefixes = complete(&ctx, "ops", &["ops", "--key"], "");
    assert!(prefixes.contains(&"mem:".to_owned())); // no provider prefix yet → prefixes only
    let refs = complete(&ctx, "ops", &["ops", "--key", "mem:"], "mem:");
    assert!(refs.contains(&"mem:aeskey".to_owned()));
}

/// Through the REPL's completion engine (§4.9.7): prefix-filtered, sorted, byte spans.
#[test]
fn completion_through_the_console_engine() {
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let table = crate::commands::all_commands().unwrap();
    let line = "encrypt mem:aeskey g";
    let got = crate::completer::complete_line(&ctx, &table, line, line.len());
    let values: Vec<&str> = got.iter().map(|(value, _)| value.as_str()).collect();
    assert_eq!(values, ["gcm"]);
    assert_eq!(got[0].1.start, line.len() - 1);
}

// ---------------------------------------------------------------------------
// test_keys_cmd_objects.py (R9 cases): the `ops` HMAC rows, `verify … hmac`
// ---------------------------------------------------------------------------

/// c2 `make_pair`: a memory-presenting and a pkcs11-presenting FakeProvider.
fn make_pair(io: Rc<dyn ConsoleIo>) -> (Rc<AppContext>, Rc<FakeProvider>) {
    let mem = Rc::new(FakeProvider::new("mem"));
    let hsm = Rc::new(FakeProvider::new("hsm").with_type_name("pkcs11"));
    let ctx = ctx_with(io, registry(&[Rc::clone(&mem), hsm]));
    (ctx, mem)
}

#[test]
fn test_ops_lists_hmac_rows() {
    let io = scripted(&[]);
    let (ctx, _) = make_pair(dyn_io(&io));
    run_line(&ctx, "ops mem").unwrap();
    assert!(io.text().contains("hmac"));
}

#[test]
fn test_sign_verify_hmac_round_trip() {
    let io = scripted(&[]);
    let (ctx, mem) = make_pair(dyn_io(&io));
    let generic: Vec<u8> = (0..32).collect();
    let info = mem
        .import_key(
            &material(KeyAlgorithm::Generic, KeyClass::Secret, &generic),
            "mac",
            None,
            None,
        )
        .unwrap();
    let mut params = Params::new();
    params.insert("hash".to_owned(), ParamValue::Enum("sha256".to_owned()));
    let expected = mem
        .sign(
            &info,
            &MechanismInvocation::new("HMAC", params),
            b"\xde\xad\xbe\xef",
        )
        .unwrap();
    run_line(
        &ctx,
        &format!(
            "verify mem:mac hmac hash=sha256 0xdeadbeef --sig 0x{}",
            hex_of(&expected)
        ),
    )
    .unwrap();
    run_line(
        &ctx,
        &format!(
            "verify mem:mac hmac hash=sha256 0xdeadbe00 --sig 0x{}",
            hex_of(&expected)
        ),
    )
    .unwrap();
    let output = io.output();
    assert_eq!(
        output[output.len() - 2..],
        ["signature VALID", "signature INVALID"]
    );
    // HMAC never resolves for AES keys: `hmac` is not a mechanism for them (§4.6)
    let aes = mem
        .import_key(
            &material(KeyAlgorithm::Aes, KeyClass::Secret, &[0; 16]),
            "aeskey",
            None,
            None,
        )
        .unwrap();
    assert!(
        ctx.operations
            .available_for(Verb::Sign, &aes, mem.as_ref())
            .iter()
            .all(|spec| spec.cli_name != "hmac")
    );
    let err = ctx
        .operations
        .resolve_cli(Verb::Sign, &aes, "hmac")
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnknownOperation);
}

// ---------------------------------------------------------------------------
// test_l13_hardening.py (R9 cases)
// ---------------------------------------------------------------------------

/// c2 fixture `tree`: alpha.txt, beta.bin, subdir/, .hidden.
fn tree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("alpha.txt"), b"a").unwrap();
    std::fs::write(dir.path().join("beta.bin"), b"b").unwrap();
    std::fs::create_dir(dir.path().join("subdir")).unwrap();
    std::fs::write(dir.path().join(".hidden"), b"h").unwrap();
    dir
}

#[test]
fn test_crypto_file_options_complete_paths() {
    let tree = tree();
    let root = tree.path().display().to_string();
    let (ctx, _) = make_ctx(dyn_io(&scripted(&[])));
    let prefix = format!("{root}/al");
    let out = complete(
        &ctx,
        "encrypt",
        &["encrypt", "mem:aeskey", "gcm", "--in", &prefix],
        &prefix,
    );
    assert_eq!(out, [format!("{root}/alpha.txt")]);
    let out = complete(
        &ctx,
        "verify",
        &["verify", "mem:aeskey", "cmac", "--sig-file", &prefix],
        &prefix,
    );
    assert_eq!(out, [format!("{root}/alpha.txt")]);
    // non-path option values still complete to nothing
    assert!(
        complete(
            &ctx,
            "verify",
            &["verify", "mem:aeskey", "cmac", "--sig", "x"],
            "x"
        )
        .is_empty()
    );
    // --out completes paths for encrypt, but is not an option of verify
    let out = complete(
        &ctx,
        "encrypt",
        &["encrypt", "mem:aeskey", "gcm", "--out", &prefix],
        &prefix,
    );
    assert_eq!(out, [format!("{root}/alpha.txt")]);
    assert!(
        complete(
            &ctx,
            "verify",
            &["verify", "mem:aeskey", "cmac", "--out", &prefix],
            &prefix
        )
        .is_empty()
    );
}

fn keypair_provider() -> Rc<FakeProvider> {
    let mem = FakeProvider::new("mem");
    let mut request = GenerateRequest::new(KeyAlgorithm::Ec, "sigkey");
    request.curve = Some(Curve::P256);
    mem.generate_key(&request).unwrap();
    Rc::new(mem)
}

#[test]
fn test_public_half_fallback_prefers_public_then_cert() {
    let mem = keypair_provider();
    let keys = mem.list_keys().unwrap();
    let private = keys
        .iter()
        .find(|k| k.key_class == KeyClass::Private)
        .unwrap()
        .clone();
    let resolved = public_half_for_verify(mem.as_ref(), private).unwrap();
    assert_eq!(resolved.key_class, KeyClass::Public);
    assert_eq!(resolved.key_ref.label, "sigkey");

    let lonely = FakeProvider::new("mem2");
    lonely
        .import_key(&ec_material(&[0x11; 32]), "solo", None, None)
        .unwrap();
    let private_only = find(&lonely, "solo");
    assert_eq!(
        public_half_for_verify(&lonely, private_only.clone()).unwrap(),
        private_only
    );

    // non-private inputs pass through untouched
    let public = keys
        .iter()
        .find(|k| k.key_class == KeyClass::Public)
        .unwrap()
        .clone();
    assert_eq!(
        public_half_for_verify(mem.as_ref(), public.clone()).unwrap(),
        public
    );
}

/// A certificate sharing the label is the fallback when there is no public object.
#[test]
fn public_half_fallback_uses_a_certificate_when_no_public_key() {
    let (pkcs8, cert) = r2_testkit::fixtures::rsa_pkcs8_and_cert();
    let mem = FakeProvider::new("mem");
    mem.import_key(
        &material(KeyAlgorithm::Rsa, KeyClass::Private, &pkcs8),
        "signer",
        None,
        None,
    )
    .unwrap();
    mem.import_key(
        &material(KeyAlgorithm::Rsa, KeyClass::Certificate, &cert),
        "signer",
        None,
        None,
    )
    .unwrap();
    let private = mem
        .find_key(&KeySelector::label("signer").with_class(Some(KeyClass::Private)))
        .unwrap();
    let resolved = public_half_for_verify(&mem, private).unwrap();
    assert_eq!(resolved.key_class, KeyClass::Certificate);
}

#[test]
fn test_public_half_fallback_honors_key_id() {
    let mem = FakeProvider::new("mem");
    let mut request = GenerateRequest::new(KeyAlgorithm::Ec, "sigkey");
    request.curve = Some(Curve::P256);
    request.key_id = Some(vec![0xaa]);
    mem.generate_key(&request).unwrap();
    let other = FakeProvider::new("src");
    request.key_id = Some(vec![0xbb]);
    other.generate_key(&request).unwrap();
    let private = mem
        .find_key(&KeySelector::label("sigkey").with_id(Some(vec![0xaa])))
        .unwrap();
    let resolved = public_half_for_verify(&mem, private).unwrap();
    assert_eq!(resolved.key_class, KeyClass::Public);
    assert_eq!(resolved.key_ref.key_id, Some(vec![0xaa]));
}

/// A same-label public object with ANOTHER id is not the fallback when the ref carried one.
#[test]
fn public_half_fallback_skips_other_ids() {
    let mem = FakeProvider::new("mem");
    let mut request = GenerateRequest::new(KeyAlgorithm::Ec, "sigkey");
    request.curve = Some(Curve::P256);
    request.key_id = Some(vec![0xaa]);
    mem.generate_key(&request).unwrap();
    let public = mem
        .find_key(&KeySelector::label("sigkey").with_class(Some(KeyClass::Public)))
        .unwrap();
    mem.delete_key(&public).unwrap();
    request.key_id = Some(vec![0xbb]);
    request.label = "sigkey".to_owned();
    mem.generate_key(&request).unwrap();
    let private = mem
        .find_key(
            &KeySelector::label("sigkey")
                .with_id(Some(vec![0xaa]))
                .with_class(Some(KeyClass::Private)),
        )
        .unwrap();
    let resolved = public_half_for_verify(&mem, private.clone()).unwrap();
    assert_eq!(resolved, private);
}

#[test]
fn test_verify_on_keypair_ref_offers_mechanisms_and_verifies() {
    // End-to-end through the command: sign with the private half, verify via the same
    // `prov:label` ref with the mechanism omitted — before the L13 fix `available_for`
    // saw the PRIVATE class and offered nothing.
    let dir = tempfile::tempdir().unwrap();
    let sig = dir.path().join("sig.bin");
    let io = Rc::new(SelectRecordingIo::new(&["0"])); // the first offered verify mechanism
    let ctx = ctx_with(
        Rc::clone(&io) as Rc<dyn ConsoleIo>,
        registry(&[keypair_provider()]),
    );
    run_line(
        &ctx,
        &format!("sign mem:sigkey ecdsa 0xdeadbeef --out {}", sig.display()),
    )
    .unwrap();
    run_line(
        &ctx,
        &format!("verify mem:sigkey 0xdeadbeef --sig-file {}", sig.display()),
    )
    .unwrap();
    let options = io.select_options();
    assert!(!options.is_empty() && !options[0].is_empty()); // §5.1 select() fallback ran
    assert_eq!(options, [["ecdsa — ECDSA signature verification"]]);
    assert!(io.inner.output().iter().any(|line| line.contains("VALID")));
    // completion sees the same fallback
    let mechs = complete(&ctx, "verify", &["verify", "mem:sigkey"], "");
    assert_eq!(mechs, ["ecdsa", "--in", "--sig", "--sig-file"]);
}

// ---------------------------------------------------------------------------
// r2-only: the help surface and the Ctrl-C flag
// ---------------------------------------------------------------------------

/// The seven commands, their summaries and usages (c2 class attributes, verbatim; `random`
/// is r2-only, §11 D29).
#[test]
fn crypto_commands_name_summary_usage() {
    let table = crate::commands::all_commands().unwrap();
    let expected: IndexMap<&str, (&str, &str)> = [
        (
            "encrypt",
            (
                "Encrypt data with a key (mechanism prompted when omitted)",
                "encrypt <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>] [--out <path>] [--outformat raw|hex|b64]",
            ),
        ),
        (
            "decrypt",
            (
                "Decrypt data with a key (mechanism prompted when omitted)",
                "decrypt <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>] [--out <path>] [--outformat raw|hex|b64]",
            ),
        ),
        (
            "sign",
            (
                "Sign data or compute a MAC (mechanism prompted when omitted)",
                "sign <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>] [--out <path>] [--outformat raw|hex|b64]",
            ),
        ),
        (
            "verify",
            (
                "Verify a signature or MAC over data",
                "verify <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>] (--sig <data> | --sig-file <path>)",
            ),
        ),
        (
            "derive",
            (
                "Derive a shared secret (ECDH / X25519 / X448)",
                "derive <provider>:<label> [<mech>] [<name>=<value> ...] [--out <path>] [--outformat raw|hex|b64]",
            ),
        ),
        (
            "ops",
            (
                "List the operations each provider can perform right now",
                "ops [<provider>] [--key <provider>:<label>]",
            ),
        ),
        (
            "random",
            (
                "Generate random bytes with a provider's RNG",
                "random <provider> [<length>] [--out <path>] [--outformat raw|hex|b64]",
            ),
        ),
    ]
    .into_iter()
    .collect();
    let module: Vec<&str> = crate::commands::crypto::commands()
        .iter()
        .map(|command| command.name())
        .collect();
    assert_eq!(
        module,
        [
            "encrypt", "decrypt", "sign", "verify", "derive", "ops", "random"
        ]
    );
    for (name, (summary, usage)) in expected {
        let command = table.get(name).unwrap();
        assert_eq!(command.summary(), summary, "{name}");
        assert_eq!(command.usage(), usage, "{name}");
        assert!(command.flags().is_empty(), "{name}");
    }
}

/// §11 D13: a Ctrl-C flag set while the verb ran is honored before writing output.
#[test]
fn interrupt_flag_stops_before_the_output_is_written() {
    let _lock = r2_testkit::global_state_lock();
    struct Interrupting;
    impl FakeHooks for Interrupting {
        fn encrypt(
            &self,
            next: &dyn Provider,
            key: &KeyInfo,
            mech: &MechanismInvocation,
            data: &[u8],
        ) -> Option<Result<Vec<u8>>> {
            r2_core::runtime::request_interrupt_on_this_thread();
            Some(next.encrypt(key, mech, data))
        }
    }
    let mem = FakeProvider::new("mem").with_hooks(Rc::new(Interrupting));
    mem.import_key(
        &material(KeyAlgorithm::Aes, KeyClass::Secret, &AES_KEY),
        "aeskey",
        None,
        None,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("ct.bin");
    let io = scripted(&[]);
    let ctx = ctx_with(dyn_io(&io), registry(&[Rc::new(mem)]));
    r2_core::runtime::reset_interrupt();
    let result = crate::testing::run_line(
        &ctx,
        &format!("encrypt mem:aeskey ecb 0xdeadbeef --out {}", out.display()),
    );
    r2_core::runtime::reset_interrupt();
    let err = result.unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert!(!out.exists());
    assert!(io.output().is_empty());
}

/// The rendered verify lines keep c2's text at the capture width.
#[test]
fn verify_lines_render_as_plain_text() {
    let styled = Renderable::Styled(vec![vec![Span {
        text: "signature VALID".to_owned(),
        tone: Tone::Success,
    }]]);
    assert_eq!(
        render_plain(&styled, &RenderConfig::CAPTURE),
        "signature VALID"
    );
    // Bold green (rich `style="bold green"`), in the renderer's SGR form — the same form as
    // Error's bold red (one sequence per attribute; rich writes the visually identical
    // "\x1b[1;32m"). Under no_color the style keeps its bold attribute only.
    assert_eq!(
        r2_core::render::render(&styled, &RenderConfig::CAPTURE),
        "\x1b[1m\x1b[32msignature VALID\x1b[0m"
    );
    assert_eq!(
        r2_core::render::render_no_color(&styled, &RenderConfig::CAPTURE),
        "\x1b[1msignature VALID\x1b[0m"
    );
    let invalid = Renderable::Styled(vec![vec![Span {
        text: "signature INVALID".to_owned(),
        tone: Tone::Error,
    }]]);
    assert_eq!(
        r2_core::render::render(&invalid, &RenderConfig::CAPTURE),
        "\x1b[1m\x1b[31msignature INVALID\x1b[0m"
    );
}

/// §11 D13: a Ctrl-C during `verify` → UserAbort, no VALID/INVALID line.
#[test]
fn interrupt_flag_stops_the_verify_verdict() {
    let _lock = r2_testkit::global_state_lock();
    struct Interrupting;
    impl FakeHooks for Interrupting {
        fn verify(
            &self,
            next: &dyn Provider,
            key: &KeyInfo,
            mech: &MechanismInvocation,
            data: &[u8],
            signature: &[u8],
        ) -> Option<Result<bool>> {
            r2_core::runtime::request_interrupt_on_this_thread();
            Some(next.verify(key, mech, data, signature))
        }
    }
    let mem = FakeProvider::new("mem").with_hooks(Rc::new(Interrupting));
    mem.import_key(
        &material(KeyAlgorithm::Aes, KeyClass::Secret, &AES_KEY),
        "aeskey",
        None,
        None,
    )
    .unwrap();
    let mac = cmac(&mem, b"\xde\xad\xbe\xef");
    let io = scripted(&[]);
    let ctx = ctx_with(dyn_io(&io), registry(&[Rc::new(mem)]));
    r2_core::runtime::reset_interrupt();
    let result = crate::testing::run_line(
        &ctx,
        &format!("verify mem:aeskey cmac 0xdeadbeef --sig 0x{}", hex_of(&mac)),
    );
    r2_core::runtime::reset_interrupt();
    let err = result.unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert!(io.output().is_empty(), "{:?}", io.output());
}

/// §11 D13: a Ctrl-C during a key-only `derive` → UserAbort, no resident-key line.
#[test]
fn interrupt_flag_stops_the_resident_derive_line() {
    let _lock = r2_testkit::global_state_lock();
    struct InterruptingKeyOnly;
    impl FakeHooks for InterruptingKeyOnly {
        fn derive(
            &self,
            _next: &dyn Provider,
            key: &KeyInfo,
            _mech: &MechanismInvocation,
        ) -> Option<Result<DeriveResult>> {
            r2_core::runtime::request_interrupt_on_this_thread();
            Some(Ok(DeriveResult {
                key: Some(key.clone()),
                raw: None,
            }))
        }
    }
    let hsm = FakeProvider::new("hsm")
        .with_type_name("pkcs11")
        .with_hooks(Rc::new(InterruptingKeyOnly));
    hsm.import_key(&ec_material(&[0x22; 32]), "eckey", None, None)
        .unwrap();
    let io = scripted(&[]);
    let ctx = ctx_with(dyn_io(&io), registry(&[Rc::new(hsm)]));
    r2_core::runtime::reset_interrupt();
    let result = crate::testing::run_line(&ctx, "derive hsm:eckey ecdh peer=0x04");
    r2_core::runtime::reset_interrupt();
    let err = result.unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert!(io.output().is_empty(), "{:?}", io.output());
}

/// §11 D13: a Ctrl-C during ref resolution (the HSM lookup) → UserAbort, and the provider
/// verb is never issued (no signature, decrypt or resident derived object after a cancel).
#[test]
fn interrupt_flag_during_resolution_never_issues_the_verb() {
    let _lock = r2_testkit::global_state_lock();
    struct InterruptOnLookup(Rc<RefCell<Vec<&'static str>>>);
    impl FakeHooks for InterruptOnLookup {
        fn find_key(
            &self,
            _next: &dyn Provider,
            _selector: &KeySelector,
        ) -> Option<Result<KeyInfo>> {
            r2_core::runtime::request_interrupt_on_this_thread();
            None
        }
        fn encrypt(
            &self,
            _next: &dyn Provider,
            _key: &KeyInfo,
            _mech: &MechanismInvocation,
            _data: &[u8],
        ) -> Option<Result<Vec<u8>>> {
            self.0.borrow_mut().push("encrypt");
            None
        }
        fn decrypt(
            &self,
            _next: &dyn Provider,
            _key: &KeyInfo,
            _mech: &MechanismInvocation,
            _data: &[u8],
        ) -> Option<Result<zeroize::Zeroizing<Vec<u8>>>> {
            self.0.borrow_mut().push("decrypt");
            None
        }
        fn sign(
            &self,
            _next: &dyn Provider,
            _key: &KeyInfo,
            _mech: &MechanismInvocation,
            _data: &[u8],
        ) -> Option<Result<Vec<u8>>> {
            self.0.borrow_mut().push("sign");
            None
        }
        fn verify(
            &self,
            _next: &dyn Provider,
            _key: &KeyInfo,
            _mech: &MechanismInvocation,
            _data: &[u8],
            _signature: &[u8],
        ) -> Option<Result<bool>> {
            self.0.borrow_mut().push("verify");
            None
        }
        fn derive(
            &self,
            _next: &dyn Provider,
            _key: &KeyInfo,
            _mech: &MechanismInvocation,
        ) -> Option<Result<DeriveResult>> {
            self.0.borrow_mut().push("derive");
            None
        }
    }
    let calls = Rc::new(RefCell::new(Vec::new()));
    let hsm = FakeProvider::new("hsm")
        .with_type_name("pkcs11")
        .with_hooks(Rc::new(InterruptOnLookup(Rc::clone(&calls))));
    hsm.import_key(
        &material(KeyAlgorithm::Aes, KeyClass::Secret, &AES_KEY),
        "aeskey",
        None,
        None,
    )
    .unwrap();
    hsm.import_key(&ec_material(&[0x22; 32]), "eckey", None, None)
        .unwrap();
    let io = scripted(&[]);
    let ctx = ctx_with(dyn_io(&io), registry(&[Rc::new(hsm)]));
    for line in [
        "encrypt hsm:aeskey ecb 0xdeadbeef",
        "decrypt hsm:aeskey ecb 0x00112233445566778899aabbccddeeff",
        "sign hsm:aeskey cmac 0xdeadbeef",
        "verify hsm:aeskey cmac 0xdeadbeef --sig 0x00112233445566778899aabbccddeeff",
        "derive hsm:eckey ecdh peer=0x04",
    ] {
        r2_core::runtime::reset_interrupt();
        let result = crate::testing::run_line(&ctx, line);
        r2_core::runtime::reset_interrupt();
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorKind::UserAbort, "{line}: {err:?}");
    }
    assert!(
        calls.borrow().is_empty(),
        "verb ran after Ctrl-C: {:?}",
        calls.borrow()
    );
    assert!(io.output().is_empty(), "{:?}", io.output());
}

/// §6: the idempotent `Provider::initialize()` runs before the busy section.
#[test]
fn provider_is_initialized_before_the_busy_section() {
    struct CountingInit(Rc<RefCell<Vec<&'static str>>>);
    impl FakeHooks for CountingInit {
        fn initialize(&self, _next: &dyn Provider) -> Option<Result<()>> {
            self.0.borrow_mut().push("initialize");
            None
        }
        fn encrypt(
            &self,
            next: &dyn Provider,
            key: &KeyInfo,
            mech: &MechanismInvocation,
            data: &[u8],
        ) -> Option<Result<Vec<u8>>> {
            self.0.borrow_mut().push("encrypt");
            Some(next.encrypt(key, mech, data))
        }
    }
    let calls = Rc::new(RefCell::new(Vec::new()));
    let mem = FakeProvider::new("mem").with_hooks(Rc::new(CountingInit(Rc::clone(&calls))));
    mem.import_key(
        &material(KeyAlgorithm::Aes, KeyClass::Secret, &AES_KEY),
        "aeskey",
        None,
        None,
    )
    .unwrap();
    let io = scripted(&[]);
    let ctx = ctx_with(dyn_io(&io), registry(&[Rc::new(mem)]));
    calls.borrow_mut().clear();
    run_line(
        &ctx,
        "encrypt mem:aeskey ecb 0x00000000000000000000000000000000",
    )
    .unwrap();
    let calls = calls.borrow();
    let encrypt_at = calls.iter().position(|call| *call == "encrypt").unwrap();
    assert!(calls[..encrypt_at].contains(&"initialize"), "{calls:?}");
}

/// c2: a ConsoleError from the verify public-half fallback leaves `complete()` and the
/// completer yields no candidates at all.
#[test]
fn verify_completion_is_empty_when_the_public_half_lookup_fails() {
    struct FailingList;
    impl FakeHooks for FailingList {
        fn list_keys(&self, _next: &dyn Provider) -> Option<Result<Vec<KeyInfo>>> {
            Some(Err(ConsoleError::generic("boom")))
        }
    }
    let mem = FakeProvider::new("mem").with_hooks(Rc::new(FailingList));
    mem.import_key(&ec_material(&[0x11; 32]), "eckey", None, None)
        .unwrap();
    let ctx = ctx_with(dyn_io(&scripted(&[])), registry(&[Rc::new(mem)]));
    assert!(complete(&ctx, "verify", &["verify", "mem:eckey"], "").is_empty());
    assert!(complete(&ctx, "verify", &["verify", "mem:eckey", "ecdsa"], "").is_empty());
}
