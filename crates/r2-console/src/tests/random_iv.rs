// Random IV fallback tests (spec §11 D30 — r2 only; no c2 counterpart to port).
//
// An IV / nonce / initial counter block left EMPTY at its prompt is drawn from the key's
// provider RNG on the encrypt/sign side (and on `export --kek`), announced as
// "<label> (random): <hex>" before the operation runs. The decrypt/verify mirrors and
// `load --kek` need the original IV and keep c2's behavior (an empty answer is an error and
// the prompt repeats). FakeProvider + ScriptedIo throughout (§4.10): the expected bytes come
// from a same-name twin FakeProvider (its draws are a deterministic keystream of (name, draw
// number)), and FakeProvider's cipher is reversible, so the printed IV round-trips through
// the decrypt/verify verbs.
use std::cell::RefCell;
use std::rc::Rc;

use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::io::{ConsoleIo, Renderable, Span, Tone};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::{ParamValue, Params};
use r2_provider::{KeySelector, MechanismInvocation, Provider, ProviderRegistry};
use r2_testkit::{FakeHooks, FakeProvider, ScriptedIo};
use zeroize::Zeroizing;

use crate::context::AppContext;
use crate::testing::CtxBuilder;

const AES_KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const PLAINTEXT: &str = "00112233445566778899aabbccddeeff";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Records the parameters of every encrypt/decrypt/sign/verify/wrap/unwrap invocation, then
/// lets the fake run the call (or fails generate_random when `rng_error` is set).
#[derive(Default)]
struct Spy {
    params: RefCell<Vec<(String, Params)>>,
    rng_error: Option<ConsoleError>,
}

impl Spy {
    fn failing_rng(err: ConsoleError) -> Self {
        Self {
            params: RefCell::new(Vec::new()),
            rng_error: Some(err),
        }
    }
    fn note(&self, verb: &str, mech: &MechanismInvocation) {
        self.params
            .borrow_mut()
            .push((verb.to_owned(), mech.params.clone()));
    }
    /// The params of the only `verb` call.
    fn params_of(&self, verb: &str) -> Params {
        let found: Vec<Params> = self
            .params
            .borrow()
            .iter()
            .filter(|(seen, _)| seen == verb)
            .map(|(_, params)| params.clone())
            .collect();
        assert_eq!(found.len(), 1, "{verb} calls: {found:?}");
        found.into_iter().next().unwrap()
    }
}

impl FakeHooks for Spy {
    fn encrypt(
        &self,
        _next: &dyn Provider,
        _key: &KeyInfo,
        mech: &MechanismInvocation,
        _data: &[u8],
    ) -> Option<Result<Vec<u8>>> {
        self.note("encrypt", mech);
        None
    }
    fn decrypt(
        &self,
        _next: &dyn Provider,
        _key: &KeyInfo,
        mech: &MechanismInvocation,
        _data: &[u8],
    ) -> Option<Result<Zeroizing<Vec<u8>>>> {
        self.note("decrypt", mech);
        None
    }
    fn sign(
        &self,
        _next: &dyn Provider,
        _key: &KeyInfo,
        mech: &MechanismInvocation,
        _data: &[u8],
    ) -> Option<Result<Vec<u8>>> {
        self.note("sign", mech);
        None
    }
    fn verify(
        &self,
        _next: &dyn Provider,
        _key: &KeyInfo,
        mech: &MechanismInvocation,
        _data: &[u8],
        _signature: &[u8],
    ) -> Option<Result<bool>> {
        self.note("verify", mech);
        None
    }
    fn wrap_key(
        &self,
        _next: &dyn Provider,
        _wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        _target: &KeyInfo,
        _options: &r2_provider::WrapOptions,
    ) -> Option<Result<Vec<u8>>> {
        self.note("wrap_key", mech);
        None
    }
    fn generate_random(
        &self,
        _next: &dyn Provider,
        _len: usize,
    ) -> Option<Result<Zeroizing<Vec<u8>>>> {
        self.rng_error.clone().map(Err)
    }
}

struct Session {
    io: Rc<ScriptedIo>,
    ctx: Rc<AppContext>,
    provider: Rc<FakeProvider>,
    spy: Rc<Spy>,
}

fn aes_material(data: &[u8]) -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, data.to_vec());
    material.size_bits = Some(u32::try_from(data.len() * 8).unwrap());
    material
}

/// One fake named `name` (presented as `type_name`) holding AES key "aeskey", spied on.
fn session_with(answers: &[&str], name: &str, type_name: &str, spy: Spy) -> Session {
    let spy = Rc::new(spy);
    let provider = Rc::new(
        FakeProvider::new(name)
            .with_type_name(type_name)
            .with_hooks(Rc::clone(&spy) as Rc<dyn FakeHooks>),
    );
    provider
        .import_key(&aes_material(&AES_KEY), "aeskey", None, None)
        .unwrap();
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::clone(&provider) as Rc<dyn Provider>)
        .unwrap();
    let io = Rc::new(ScriptedIo::new(answers.iter().copied()));
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .providers(registry)
        .build();
    Session {
        io,
        ctx,
        provider,
        spy,
    }
}

fn session(answers: &[&str]) -> Session {
    session_with(answers, "mem", "memory", Spy::default())
}

/// The first `len`-byte draw of a fresh fake named `name` — what the command's first draw
/// on a fresh provider of that name yields.
fn first_draw(name: &str, type_name: &str, len: usize) -> Vec<u8> {
    FakeProvider::new(name)
        .with_type_name(type_name)
        .generate_random(len)
        .unwrap()
        .to_vec()
}

fn hex_of(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    r2_core::text::py_fromhex(text).unwrap()
}

fn methods(provider: &FakeProvider) -> Vec<String> {
    provider
        .calls()
        .into_iter()
        .map(|call| call[0].clone())
        .collect()
}

fn random_calls(provider: &FakeProvider) -> Vec<Vec<String>> {
    provider
        .calls()
        .into_iter()
        .filter(|call| call[0] == "generate_random")
        .collect()
}

fn position(provider: &FakeProvider, method: &str) -> usize {
    let methods = methods(provider);
    methods
        .iter()
        .position(|m| m == method)
        .unwrap_or_else(|| panic!("no {method} call in {methods:?}"))
}

/// `crate::testing::run_line` under the process-global state lock (the verbs honor the
/// process-global Ctrl-C flag, §11 D13).
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

/// The data of the only hex result printed.
fn hex_result(io: &ScriptedIo) -> Vec<u8> {
    let found: Vec<Vec<u8>> = io
        .renderables()
        .into_iter()
        .filter_map(|r| match r {
            Renderable::Hex { data, .. } => Some(data.to_vec()),
            _ => None,
        })
        .collect();
    assert_eq!(found.len(), 1, "{:?}", io.renderables());
    found.into_iter().next().unwrap()
}

fn bytes_param(params: &Params, name: &str) -> Vec<u8> {
    match params.get(name) {
        Some(ParamValue::Bytes(bytes)) => bytes.clone(),
        other => panic!("{name}: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// encrypt / sign: an empty answer draws the IV from the key's provider
// ---------------------------------------------------------------------------

/// (cli mech, mechanism, param name, shown prompt, announced label, length)
const ENCRYPT_ROWS: [(&str, &str, &str, &str, &str, usize); 3] = [
    (
        "cbc",
        "AES-CBC",
        "iv",
        "IV (16 bytes, empty = random)",
        "IV",
        16,
    ),
    (
        "gcm",
        "AES-GCM",
        "iv",
        "IV / nonce (12 bytes typical, empty = random)",
        "IV / nonce",
        12,
    ),
    (
        "ctr",
        "AES-CTR",
        "counter_block",
        "Initial counter block (16 bytes, empty = random)",
        "Initial counter block",
        16,
    ),
];

#[test]
fn encrypt_with_an_empty_iv_answer_uses_a_random_iv() {
    for (cli, mechanism, param, prompt, label, len) in ENCRYPT_ROWS {
        let s = session(&[""]);
        run_line(&s.ctx, &format!("encrypt mem:aeskey {cli} 0x{PLAINTEXT}")).unwrap();
        let iv = first_draw("mem", "memory", len);
        assert_eq!(s.io.prompts(), [prompt], "{cli}");
        assert_eq!(s.io.remaining(), 0, "{cli}");
        // the draw is announced before the result
        let output = s.io.output();
        assert_eq!(output.len(), 2, "{cli}: {output:?}");
        assert_eq!(
            output[0],
            format!("{label} (random): {}", hex_of(&iv)),
            "{cli}"
        );
        assert!(
            matches!(&s.io.renderables()[0], Renderable::Text(_)),
            "{cli}: the announcement is a plain text line"
        );
        // one draw of the right length, BEFORE the encrypt call
        assert_eq!(
            random_calls(&s.provider),
            [vec!["generate_random".to_owned(), len.to_string()]],
            "{cli}"
        );
        assert!(
            position(&s.provider, "generate_random") < position(&s.provider, "encrypt"),
            "{cli}: {:?}",
            s.provider.calls()
        );
        // the drawn bytes are the IV the provider was given
        assert_eq!(bytes_param(&s.spy.params_of("encrypt"), param), iv, "{cli}");
        assert!(
            s.provider.calls().contains(&vec![
                "encrypt".to_owned(),
                "mem:aeskey".to_owned(),
                mechanism.to_owned(),
                "16B".to_owned()
            ]),
            "{cli}: {:?}",
            s.provider.calls()
        );
    }
}

#[test]
fn encrypt_with_a_random_iv_round_trips_through_decrypt() {
    for (cli, _, param, _, label, _) in ENCRYPT_ROWS {
        let s = session(&[""]);
        run_line(&s.ctx, &format!("encrypt mem:aeskey {cli} 0x{PLAINTEXT}")).unwrap();
        let ciphertext = hex_result(&s.io);
        assert_ne!(ciphertext, unhex(PLAINTEXT), "{cli}");
        let shown = s.io.output()[0].clone();
        let iv_hex = shown
            .strip_prefix(&format!("{label} (random): "))
            .unwrap()
            .to_owned();
        // decrypt with the printed IV given inline: no prompt, no draw, the plaintext back
        run_line(
            &s.ctx,
            &format!(
                "decrypt mem:aeskey {cli} {param}=0x{iv_hex} 0x{}",
                hex_of(&ciphertext)
            ),
        )
        .unwrap();
        assert_eq!(s.io.prompts().len(), 1, "{cli}: only the encrypt IV prompt");
        let Some(Renderable::Hex { data, .. }) = s.io.renderables().pop() else {
            panic!("{cli}: no hex result: {:?}", s.io.renderables());
        };
        assert_eq!(*data, unhex(PLAINTEXT), "{cli}");
        assert_eq!(
            bytes_param(&s.spy.params_of("decrypt"), param),
            unhex(&iv_hex)
        );
        assert_eq!(
            random_calls(&s.provider).len(),
            1,
            "{cli}: decrypt never draws"
        );
    }
}

#[test]
fn sign_gmac_with_an_empty_iv_answer_uses_a_random_iv() {
    let s = session(&[""]);
    run_line(&s.ctx, "sign mem:aeskey gmac 0xdeadbeef").unwrap();
    let iv = first_draw("mem", "memory", 12);
    assert_eq!(s.io.prompts(), ["IV (12 bytes, empty = random)"]);
    assert_eq!(s.io.output()[0], format!("IV (random): {}", hex_of(&iv)));
    assert_eq!(
        random_calls(&s.provider),
        [vec!["generate_random".to_owned(), "12".to_owned()]]
    );
    assert!(position(&s.provider, "generate_random") < position(&s.provider, "sign"));
    assert_eq!(bytes_param(&s.spy.params_of("sign"), "iv"), iv);
    let mac = hex_result(&s.io);

    // the printed IV verifies the MAC
    run_line(
        &s.ctx,
        &format!(
            "verify mem:aeskey gmac iv=0x{} 0xdeadbeef --sig 0x{}",
            hex_of(&iv),
            hex_of(&mac)
        ),
    )
    .unwrap();
    assert_eq!(bytes_param(&s.spy.params_of("verify"), "iv"), iv);
    assert_eq!(
        s.io.renderables().last().unwrap(),
        &Renderable::Styled(vec![vec![Span {
            text: "signature VALID".to_owned(),
            tone: Tone::Success,
        }]])
    );
    assert_eq!(random_calls(&s.provider).len(), 1);
}

/// A non-empty answer is parsed as before: no draw, no announcement.
#[test]
fn a_given_iv_answer_is_used_as_is() {
    let iv = "000102030405060708090a0b0c0d0e0f";
    let answer = format!("0x{iv}");
    let s = session(&[&answer]);
    run_line(&s.ctx, &format!("encrypt mem:aeskey cbc 0x{PLAINTEXT}")).unwrap();
    assert_eq!(s.io.prompts(), ["IV (16 bytes, empty = random)"]);
    assert!(random_calls(&s.provider).is_empty());
    assert_eq!(bytes_param(&s.spy.params_of("encrypt"), "iv"), unhex(iv));
    assert!(!s.io.text().contains("(random)"));
    // an inline IV is never prompted
    let s = session(&[]);
    run_line(
        &s.ctx,
        &format!("encrypt mem:aeskey cbc iv=0x{iv} 0x{PLAINTEXT}"),
    )
    .unwrap();
    assert!(s.io.prompts().is_empty());
    assert!(random_calls(&s.provider).is_empty());
}

/// A whitespace-only answer counts as empty.
#[test]
fn a_blank_iv_answer_also_draws() {
    let s = session(&["   "]);
    run_line(&s.ctx, &format!("encrypt mem:aeskey cbc 0x{PLAINTEXT}")).unwrap();
    assert_eq!(
        bytes_param(&s.spy.params_of("encrypt"), "iv"),
        first_draw("mem", "memory", 16)
    );
}

/// The draw comes from the key's own provider (a logged-in PKCS#11-presented one here).
#[test]
fn the_draw_comes_from_the_keys_pkcs11_provider() {
    let s = session_with(&[""], "hsm", "pkcs11", Spy::default());
    run_line(&s.ctx, &format!("encrypt hsm:aeskey cbc 0x{PLAINTEXT}")).unwrap();
    let iv = first_draw("hsm", "pkcs11", 16);
    assert_ne!(iv, first_draw("mem", "memory", 16));
    assert_eq!(s.io.output()[0], format!("IV (random): {}", hex_of(&iv)));
    assert_eq!(
        random_calls(&s.provider),
        [vec!["generate_random".to_owned(), "16".to_owned()]]
    );
    assert_eq!(bytes_param(&s.spy.params_of("encrypt"), "iv"), iv);
}

/// Two providers: only the key's provider is asked.
#[test]
fn other_providers_are_never_asked() {
    let s = session_with(&[""], "hsm", "pkcs11", Spy::default());
    let mem = Rc::new(FakeProvider::new("mem"));
    s.ctx
        .providers
        .register(Rc::clone(&mem) as Rc<dyn Provider>)
        .unwrap();
    run_line(&s.ctx, &format!("encrypt hsm:aeskey gcm 0x{PLAINTEXT}")).unwrap();
    assert_eq!(random_calls(&s.provider).len(), 1);
    assert!(random_calls(&mem).is_empty());
}

#[test]
fn an_rng_failure_aborts_the_command_with_that_error() {
    let failure = ConsoleError::pkcs11(
        "PKCS#11 random generation failed (CKR_RANDOM_NO_RNG)",
        0x121,
        "CKR_RANDOM_NO_RNG",
    );
    let s = session_with(&[""], "mem", "memory", Spy::failing_rng(failure.clone()));
    let err = run_err(&s.ctx, &format!("encrypt mem:aeskey cbc 0x{PLAINTEXT}"));
    assert_eq!(err, failure);
    // asked once, not re-prompted, nothing encrypted or printed
    assert_eq!(s.io.prompts(), ["IV (16 bytes, empty = random)"]);
    assert!(!methods(&s.provider).contains(&"encrypt".to_owned()));
    assert!(s.spy.params.borrow().is_empty());
    assert!(s.io.output().is_empty(), "{:?}", s.io.output());
}

#[test]
fn ctrl_c_at_the_iv_prompt_aborts_without_a_draw() {
    let s = session(&[ScriptedIo::CTRL_C]);
    let err = run_err(&s.ctx, &format!("encrypt mem:aeskey cbc 0x{PLAINTEXT}"));
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert_eq!(s.io.prompts(), ["IV (16 bytes, empty = random)"]);
    assert!(random_calls(&s.provider).is_empty());
    assert!(!methods(&s.provider).contains(&"encrypt".to_owned()));
    assert!(s.io.output().is_empty());
}

// ---------------------------------------------------------------------------
// decrypt / verify: never random
// ---------------------------------------------------------------------------

/// c2's behavior unchanged: the old prompt, the empty input is an error shown at the
/// prompt, and the prompt repeats.
#[test]
fn decrypt_with_an_empty_iv_answer_is_an_error_and_reprompts() {
    let iv = "000102030405060708090a0b0c0d0e0f";
    let answer = format!("0x{iv}");
    let s = session(&["", &answer]);
    run_line(&s.ctx, &format!("decrypt mem:aeskey cbc 0x{PLAINTEXT}")).unwrap();
    assert_eq!(s.io.prompts(), ["IV (16 bytes)", "IV (16 bytes)"]);
    assert_eq!(
        s.io.output()[0],
        "error: iv: empty input (hint: paste hex, base64 or PEM data)"
    );
    assert!(random_calls(&s.provider).is_empty());
    assert_eq!(bytes_param(&s.spy.params_of("decrypt"), "iv"), unhex(iv));
}

#[test]
fn decrypt_mirrors_never_offer_random() {
    for (cli, prompt) in [
        ("gcm", "IV / nonce (12 bytes typical)"),
        ("ctr", "Initial counter block (16 bytes)"),
    ] {
        let s = session(&["", ScriptedIo::CTRL_C]);
        let err = run_err(&s.ctx, &format!("decrypt mem:aeskey {cli} 0x{PLAINTEXT}"));
        assert_eq!(err.kind, ErrorKind::UserAbort, "{cli}");
        assert_eq!(s.io.prompts(), [prompt, prompt], "{cli}");
        assert!(s.io.output()[0].starts_with("error: "), "{cli}");
        assert!(random_calls(&s.provider).is_empty(), "{cli}");
        assert!(!methods(&s.provider).contains(&"decrypt".to_owned()));
    }
}

#[test]
fn verify_gmac_with_an_empty_iv_answer_is_not_random() {
    let s = session(&["", ScriptedIo::CTRL_C]);
    let err = run_err(&s.ctx, "verify mem:aeskey gmac 0xdeadbeef --sig 0x00");
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert_eq!(s.io.prompts(), ["IV (12 bytes)", "IV (12 bytes)"]);
    assert_eq!(
        s.io.output(),
        ["error: iv: empty input (hint: paste hex, base64 or PEM data)"]
    );
    assert!(random_calls(&s.provider).is_empty());
    assert!(!methods(&s.provider).contains(&"verify".to_owned()));
}

// ---------------------------------------------------------------------------
// export --kek (wrap) draws; load --kek (unwrap) does not
// ---------------------------------------------------------------------------

fn kek_session(answers: &[&str]) -> Session {
    let s = session(answers);
    s.provider
        .import_key(&aes_material(&[0x5a; 32]), "kek", None, None)
        .unwrap();
    s.provider
        .import_key(&aes_material(&[0xab; 32]), "target", None, None)
        .unwrap();
    s
}

#[test]
fn export_kek_cbc_with_an_empty_iv_uses_a_random_iv() {
    let s = kek_session(&[""]);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("wrapped.bin");
    run_line(
        &s.ctx,
        &format!("export mem:target {} --kek kek --mech cbc", out.display()),
    )
    .unwrap();
    let iv = first_draw("mem", "memory", 16);
    assert_eq!(s.io.prompts(), ["IV (16 bytes, empty = random)"]);
    let blob = std::fs::read(&out).unwrap();
    assert_eq!(
        s.io.output(),
        [
            format!("IV (random): {}", hex_of(&iv)),
            format!(
                "wrote {}: {}-byte blob wrapped under mem:kek with AES-CBC",
                out.display(),
                blob.len()
            ),
        ]
    );
    assert!(position(&s.provider, "generate_random") < position(&s.provider, "wrap_key"));
    assert_eq!(bytes_param(&s.spy.params_of("wrap_key"), "iv"), iv);

    // the printed IV unwraps the blob back (load --kek with the IV inline)
    run_line(
        &s.ctx,
        &format!(
            "load mem aes --file {} --kek kek --mech cbc iv=0x{} --label back",
            out.display(),
            hex_of(&iv)
        ),
    )
    .unwrap();
    let back = s.provider.find_key(&KeySelector::label("back")).unwrap();
    assert_eq!(*s.provider.export_key(&back).unwrap().data, [0xab; 32]);
    assert_eq!(random_calls(&s.provider).len(), 1);
}

/// The real MemoryProvider (OpenSSL AES-CBC): the random IV the wrap used is the one
/// printed, so the printed IV unwraps the blob.
#[test]
fn export_kek_random_iv_round_trips_on_the_memory_provider() {
    use r2_memory::MemoryProvider;
    let mem = Rc::new(MemoryProvider::new("mem"));
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::clone(&mem) as Rc<dyn Provider>)
        .unwrap();
    let io = Rc::new(ScriptedIo::new([""]));
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .providers(registry)
        .build();
    mem.import_key(&aes_material(&[0x5a; 32]), "kek", None, None)
        .unwrap();
    mem.import_key(&aes_material(&[0xab; 32]), "target", None, None)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("wrapped.bin");
    run_line(
        &ctx,
        &format!("export mem:target {} --kek kek --mech cbc", out.display()),
    )
    .unwrap();
    let shown = io.output()[0].clone();
    let iv_hex = shown.strip_prefix("IV (random): ").unwrap();
    assert_eq!(iv_hex.len(), 32);
    assert!(
        iv_hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    run_line(
        &ctx,
        &format!(
            "load mem aes --file {} --kek kek --mech cbc iv=0x{iv_hex} --label back",
            out.display()
        ),
    )
    .unwrap();
    let back = mem.find_key(&KeySelector::label("back")).unwrap();
    assert_eq!(*mem.export_key(&back).unwrap().data, [0xab; 32]);
}

#[test]
fn load_kek_cbc_with_an_empty_iv_is_not_random() {
    let s = kek_session(&["", ScriptedIo::CTRL_C]);
    let err = run_err(
        &s.ctx,
        "load mem aes 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
         --kek kek --mech cbc --label back",
    );
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert_eq!(s.io.prompts(), ["IV (16 bytes)", "IV (16 bytes)"]);
    assert_eq!(
        s.io.output(),
        ["error: iv: empty input (hint: paste hex, base64 or PEM data)"]
    );
    assert!(random_calls(&s.provider).is_empty());
    assert!(!methods(&s.provider).contains(&"unwrap_key".to_owned()));
}
