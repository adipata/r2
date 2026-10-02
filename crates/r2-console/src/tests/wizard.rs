// SoftHSM first-run wizard (spec §4.9.9, §5.13; R11) — the port of c2
// tests/unit/console/test_wizard.py plus the real-wizard cases of
// tests/unit/console/test_providers_cmd.py.
//
// ScriptedIo drives every interactive path (§4.10); the provider is a FakeProvider whose
// hooks reproduce c2's `WizardProviderDouble` (a FakeProvider subclass) with the SoftHSM
// facts verified against the real module: free slots present as TokenInfo{label: "",
// serial: ""}; init_token guarantees the exact label round trip; slot ids get reassigned
// on init. c2 read `os.environ` inside `init_token`; in r2 the wizard never touches the
// environment itself — step 2 is `TokenInit::set_env_and_reset`, which the double records
// (and, for the softhsm2-util fallback tests, applies through `r2_testkit::set_env` so
// the subprocess really inherits it). c2's monkeypatched `shutil.which` / `subprocess.run`
// become a fake `softhsm2-util` script on a test-owned `$PATH`. No test here touches
// SoftHSM. Every test holds `global_state_lock` (the wizard reads `$SOFTHSM2_LIB` and
// `$PATH`).
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use r2_config::loader::load_config;
use r2_config::model::AppConfig;
use r2_config::yaml::{self, Value};
use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::io::ConsoleIo;
use r2_provider::{AuthState, Provider, ProviderRegistry, TokenInfo};
use r2_testkit::{EnvGuard, FakeHooks, FakeProvider, ScriptedIo, global_state_lock, set_env};
use secrecy::{ExposeSecret, SecretString};

use crate::context::AppContext;
use crate::testing::{CtxBuilder, make_config, run_line};
use crate::wizard;

const SO_PIN: &str = "so-pin-1";
const USER_PIN: &str = "user-pin-1";

/// Answers from the setup confirm through both PIN confirmations (no append prompt):
/// confirm, label, SO PIN twice, user PIN twice.
const HAPPY_ANSWERS: [&str; 6] = ["y", "tok1", SO_PIN, SO_PIN, USER_PIN, USER_PIN];

const TEST_LIBRARY: &str = "/opt/test/libsofthsm2.so";

// ---------------------------------------------------------------------------------------
// doubles & helpers
// ---------------------------------------------------------------------------------------

/// A free SoftHSM slot as verified against the real module.
fn free_token(slot_id: u64) -> TokenInfo {
    TokenInfo {
        slot_id,
        label: String::new(),
        manufacturer: "SoftHSM project".to_owned(),
        model: "SoftHSM v2".to_owned(),
        serial: String::new(),
    }
}

fn soft_token(slot_id: u64, label: &str, serial: &str) -> TokenInfo {
    TokenInfo {
        slot_id,
        label: label.to_owned(),
        manufacturer: "SoftHSM project".to_owned(),
        model: "SoftHSM v2".to_owned(),
        serial: serial.to_owned(),
    }
}

/// c2's `WizardProviderDouble` / `FailingInitProvider` as FakeHooks.
#[derive(Default)]
struct WizardDouble {
    tokens: RefCell<Vec<TokenInfo>>,
    init_calls: RefCell<Vec<(u64, String)>>,
    /// Kept out of FakeProvider.calls (c2 `init_pins`).
    init_pins: RefCell<Vec<(String, String)>>,
    /// The SOFTHSM2_CONF value step 2 handed to the provider when init_token ran (c2
    /// `env_at_init`, read from os.environ inside init_token).
    env_at_init: RefCell<Vec<Option<String>>>,
    conf_env: RefCell<Option<String>>,
    shutdowns: Cell<usize>,
    /// FailingInitProvider: init_token always fails at the choke point.
    fail_init: bool,
    /// Apply set_env_and_reset to the real environment (through set_env), so a
    /// softhsm2-util subprocess inherits it like the real provider's.
    apply_env: bool,
    env_guards: RefCell<Vec<EnvGuard>>,
    /// The fake softhsm2-util's argv record: once it exists, list_tokens shows the token
    /// the util "initialized" (c2's fake_run replaced `provider.tokens`).
    util_argv: Option<PathBuf>,
}

impl WizardDouble {
    fn new() -> Self {
        Self {
            tokens: RefCell::new(vec![free_token(0)]),
            ..Self::default()
        }
    }
    fn failing() -> Self {
        Self {
            fail_init: true,
            ..Self::new()
        }
    }
    fn set_tokens(&self, tokens: Vec<TokenInfo>) {
        *self.tokens.borrow_mut() = tokens;
    }
}

impl FakeHooks for WizardDouble {
    fn shutdown(&self, _next: &dyn Provider) -> Option<Result<()>> {
        self.shutdowns.set(self.shutdowns.get() + 1);
        None
    }
    fn list_tokens(&self, _next: &dyn Provider) -> Option<Result<Vec<TokenInfo>>> {
        if let Some(argv) = &self.util_argv
            && let Ok(text) = std::fs::read_to_string(argv)
        {
            let args: Vec<&str> = text.lines().collect();
            let label = args
                .iter()
                .position(|arg| *arg == "--label")
                .and_then(|i| args.get(i + 1))
                .copied()
                .unwrap_or_default();
            return Some(Ok(vec![soft_token(42, label, "0123456789abcdef")]));
        }
        Some(Ok(self.tokens.borrow().clone()))
    }
    fn init_token(
        &self,
        _next: &dyn Provider,
        slot: u64,
        label: &str,
        so_pin: &SecretString,
        user_pin: &SecretString,
    ) -> Option<Result<()>> {
        self.env_at_init
            .borrow_mut()
            .push(self.conf_env.borrow().clone());
        self.init_calls.borrow_mut().push((slot, label.to_owned()));
        if self.fail_init {
            return Some(Err(ConsoleError::pkcs11(
                "PKCS#11 token initialization failed (CKR_GENERAL_ERROR)",
                0x05,
                "CKR_GENERAL_ERROR",
            )));
        }
        self.init_pins.borrow_mut().push((
            so_pin.expose_secret().to_owned(),
            user_pin.expose_secret().to_owned(),
        ));
        // SoftHSM reassigns slot ids on init; the label round-trips exactly.
        self.set_tokens(vec![soft_token(slot + 7, label, "1a2b3c4d5e6f7a8b")]);
        Some(Ok(()))
    }
    fn set_env_and_reset(
        &self,
        _next: &dyn Provider,
        key: &str,
        value: &str,
    ) -> Option<Result<()>> {
        assert_eq!(key, wizard::SOFTHSM2_CONF_ENV);
        *self.conf_env.borrow_mut() = Some(value.to_owned());
        if self.apply_env {
            self.env_guards.borrow_mut().push(set_env(key, Some(value)));
        }
        None // the fake records the call and shuts down through the hooked surface
    }
}

fn provider_with(double: &Rc<WizardDouble>) -> FakeProvider {
    FakeProvider::new("softhsm")
        .with_type_name("pkcs11")
        .with_tokens(vec![free_token(0)])
        .with_hooks(Rc::clone(double) as Rc<dyn FakeHooks>)
}

/// c2's autouse `_guard_env` + `softhsm_dirs` fixtures: the global-state lock,
/// SOFTHSM2_CONF unset, SOFTHSM2_LIB pinned to a missing path (find_softhsm_module is
/// deterministic: a set-but-missing override returns None, §4.5.5), and a config whose
/// softhsm.conf_dir / token_dir point into a fresh temp dir.
struct Fixture {
    // drop order: env guards first, then the temp dir, then the lock
    _guards: Vec<EnvGuard>,
    dir: tempfile::TempDir,
    conf_dir: PathBuf,
    token_dir: PathBuf,
    config: AppConfig,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        let lock = global_state_lock();
        let guards = vec![
            set_env(wizard::SOFTHSM2_CONF_ENV, None),
            set_env("SOFTHSM2_LIB", Some("/nonexistent/libsofthsm2.so")),
        ];
        let dir = tempfile::tempdir().unwrap();
        let conf_dir = dir.path().join("conf");
        let token_dir = dir.path().join("tokens");
        let config = softhsm_config(&conf_dir, &token_dir, None);
        Self {
            _guards: guards,
            dir,
            conf_dir,
            token_dir,
            config,
            _lock: lock,
        }
    }
    fn path(&self) -> &Path {
        self.dir.path()
    }
    fn conf_path(&self) -> PathBuf {
        self.conf_dir.join("softhsm2.conf")
    }
    /// An external config file (c2 `_external`).
    fn external(&self, text: &str) -> PathBuf {
        let path = self.path().join("r2.yaml");
        std::fs::write(&path, text).unwrap();
        path
    }
}

/// YAML single-quoted scalar.
fn quoted(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "''"))
}

fn softhsm_config(conf_dir: &Path, token_dir: &Path, search_path: Option<&Path>) -> AppConfig {
    let mut text = format!(
        "softhsm:\n  conf_dir: {}\n  token_dir: {}\n",
        quoted(conf_dir),
        quoted(token_dir)
    );
    if let Some(path) = search_path {
        text.push_str(&format!("  search_paths:\n    - {}\n", quoted(path)));
    }
    make_config(Some(&text))
}

fn make_ctx(
    io: &Rc<ScriptedIo>,
    config: &AppConfig,
    source_path: Option<&Path>,
    providers: Option<ProviderRegistry>,
) -> Rc<AppContext> {
    let mut builder = CtxBuilder::new(Rc::clone(io) as Rc<dyn ConsoleIo>)
        .config(config.clone())
        .providers(providers.unwrap_or_default());
    if let Some(path) = source_path {
        builder = builder.source_path(path.to_path_buf());
    }
    builder.build()
}

fn scripted(answers: &[&str]) -> Rc<ScriptedIo> {
    Rc::new(ScriptedIo::new(answers.iter().copied()))
}

fn run(ctx: &AppContext, provider: &dyn Provider) -> Result<Option<TokenInfo>> {
    wizard::run_softhsm_wizard(ctx, provider, Some(Path::new(TEST_LIBRARY)))
}

/// Python `Path.read_text`: universal newlines.
fn read_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap().replace("\r\n", "\n")
}

fn any_output(io: &ScriptedIo, needle: &str) -> bool {
    io.output().iter().any(|line| line.contains(needle))
}

fn snippet_of(io: &ScriptedIo) -> String {
    io.output()
        .into_iter()
        .find(|line| line.contains("pkcs11:"))
        .unwrap()
}

fn expected_conf_text(token_dir: &Path) -> String {
    format!(
        "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
        token_dir.display()
    )
}

// ---------------------------------------------------------------------------------------
// decline path
// ---------------------------------------------------------------------------------------

#[test]
fn test_decline_touches_nothing() {
    let fx = Fixture::new();
    let io = scripted(&["n"]);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);
    let registry = ProviderRegistry::new();
    let memory = Rc::new(FakeProvider::new("mem"));
    registry
        .register(Rc::clone(&memory) as Rc<dyn Provider>)
        .unwrap();
    let ctx = make_ctx(&io, &fx.config, None, Some(registry));

    assert_eq!(run(&ctx, &provider).unwrap(), None);

    assert!(!fx.conf_dir.exists());
    assert!(!fx.token_dir.exists());
    assert!(std::env::var_os(wizard::SOFTHSM2_CONF_ENV).is_none());
    assert!(double.init_calls.borrow().is_empty());
    assert_eq!(double.shutdowns.get(), 0);
    assert!(provider.calls().is_empty(), "no set_env_and_reset, no init");
    // memory-only operation intact: the memory provider was never touched and is still
    // resolvable through the registry.
    assert!(memory.calls().is_empty());
    let resolved = ctx.providers.get("mem").unwrap();
    assert!(Rc::ptr_eq(
        &resolved,
        &(Rc::clone(&memory) as Rc<dyn Provider>)
    ));
    assert!(any_output(&io, "stays listed but unusable"));
}

#[test]
fn decline_works_on_a_provider_without_token_init_and_accept_refuses_it() {
    // c2 looked at the provider only in step 3: declining never needs init_token. r2
    // checks `as_token_init()` right after the confirm, before anything is touched.
    let fx = Fixture::new();
    let plain = FakeProvider::new("softhsm").with_type_name("pkcs11");
    let io = scripted(&["n"]);
    assert_eq!(
        run(&make_ctx(&io, &fx.config, None, None), &plain).unwrap(),
        None
    );

    let io = scripted(&["y"]);
    let err = run(&make_ctx(&io, &fx.config, None, None), &plain).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(err.message, "provider 'softhsm' cannot initialize tokens");
    assert!(!fx.conf_dir.exists());
    assert!(plain.calls().is_empty());
}

// ---------------------------------------------------------------------------------------
// happy path
// ---------------------------------------------------------------------------------------

#[test]
fn test_full_flow() {
    let fx = Fixture::new();
    let io = scripted(&HAPPY_ANSWERS);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);
    let ctx = make_ctx(&io, &fx.config, None, None);

    let token = run(&ctx, &provider).unwrap();

    // §5.13 step 1: conf/token dirs + the exact softhsm2.conf content.
    let conf_path = fx.conf_path();
    assert!(fx.token_dir.is_dir());
    assert_eq!(read_text(&conf_path), expected_conf_text(&fx.token_dir));
    // §5.13 step 2: env handed to the provider BEFORE init (captured inside init_token),
    // and the provider was reset so the next C_Initialize re-reads it. The wizard itself
    // never sets the variable (the provider's audited set_var site does).
    let conf_text = conf_path.display().to_string();
    assert_eq!(
        provider.calls().first().unwrap(),
        &vec![
            "set_env_and_reset".to_owned(),
            "SOFTHSM2_CONF".to_owned(),
            conf_text.clone()
        ]
    );
    assert_eq!(*double.env_at_init.borrow(), vec![Some(conf_text)]);
    assert!(std::env::var_os(wizard::SOFTHSM2_CONF_ENV).is_none());
    assert_eq!(double.shutdowns.get(), 1);
    // §5.13 step 3: init on the free slot with the confirmed PINs.
    assert_eq!(*double.init_calls.borrow(), vec![(0, "tok1".to_owned())]);
    assert_eq!(
        *double.init_pins.borrow(),
        vec![(SO_PIN.to_owned(), USER_PIN.to_owned())]
    );
    // exact label round trip through list_tokens.
    let token = token.unwrap();
    assert_eq!(token.label, "tok1");
    assert_eq!(token.slot_id, 7);
    assert_eq!(io.remaining(), 0);
}

#[test]
fn transcript_matches_c2() {
    // c2's ScriptedIO transcript of the same run (c2 → r2 only in the label prompt default),
    // captured from c2@408d6f2: short PIN, mismatch, then an accepted append.
    let fx = Fixture::new();
    let source = fx.external("ui:\n  hex_group: 4\n");
    let io = scripted(&[
        "y",
        "tok1",
        "abc",
        SO_PIN,
        "different",
        SO_PIN,
        SO_PIN,
        USER_PIN,
        USER_PIN,
        "y",
    ]);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);
    let ctx = make_ctx(&io, &fx.config, Some(&source), None);

    run(&ctx, &provider).unwrap().unwrap();

    let conf = fx.conf_path();
    assert_eq!(
        io.output(),
        vec![
            format!(
                "Provider 'softhsm' has no initialized SoftHSM2 token.\nFirst-run setup will:\n  \
                 1. create {} and {}\n  2. write softhsm2.conf there and point $SOFTHSM2_CONF \
                 at it\n  3. initialize a token (SO PIN and user PIN prompted hidden)",
                fx.conf_dir.display(),
                fx.token_dir.display()
            ),
            format!("Wrote {}", conf.display()),
            "SO PIN must be at least 4 characters.".to_owned(),
            "SO PIN entries do not match — try again.".to_owned(),
            "Token 'tok1' initialized (slot 7).".to_owned(),
            "Provider entry for your configuration:".to_owned(),
            format!(
                "providers:\n  pkcs11:\n  - name: softhsm\n    library: \
                 /opt/test/libsofthsm2.so\n    token_label: tok1\n    env:\n      \
                 SOFTHSM2_CONF: {}",
                conf.display()
            ),
            format!("Updated {}.", source.display()),
        ]
    );
    assert_eq!(
        io.prompts(),
        vec![
            "Set up a SoftHSM2 token for 'softhsm' now?".to_owned(),
            "Token label [r2]".to_owned(),
            "New SO PIN: ".to_owned(),
            "New SO PIN: ".to_owned(),
            "Repeat SO PIN: ".to_owned(),
            "New SO PIN: ".to_owned(),
            "Repeat SO PIN: ".to_owned(),
            "New user PIN: ".to_owned(),
            "Repeat user PIN: ".to_owned(),
            format!("Append this provider entry to {}?", source.display()),
        ]
    );
}

#[test]
fn test_report_snippet_matches_schema() {
    let fx = Fixture::new();
    let io = scripted(&HAPPY_ANSWERS);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);
    let ctx = make_ctx(&io, &fx.config, None, None);

    assert!(run(&ctx, &provider).unwrap().is_some());

    let data = yaml::parse(&snippet_of(&io)).unwrap();
    let expected = yaml::parse(&format!(
        "providers:\n  pkcs11:\n    - name: softhsm\n      library: /opt/test/libsofthsm2.so\n      \
         token_label: tok1\n      env:\n        SOFTHSM2_CONF: {}\n",
        quoted(&fx.conf_path())
    ))
    .unwrap();
    assert_eq!(data, expected);
    // No external config file → a persistence note instead of an append offer.
    assert!(any_output(&io, "No external config file"));
}

#[test]
fn test_pins_never_echoed() {
    let fx = Fixture::new();
    let io = scripted(&HAPPY_ANSWERS);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);

    assert!(
        run(&make_ctx(&io, &fx.config, None, None), &provider)
            .unwrap()
            .is_some()
    );

    let mut everything = io.output();
    everything.extend(io.prompts());
    let everything = everything.join("\n");
    assert!(!everything.contains(SO_PIN));
    assert!(!everything.contains(USER_PIN));
    for call in provider.calls() {
        // FakeProvider call summaries
        let args = call[1..].concat();
        assert!(!args.contains(SO_PIN), "{}", call[0]);
        assert!(!args.contains(USER_PIN), "{}", call[0]);
    }
}

#[test]
fn test_empty_label_uses_default() {
    let fx = Fixture::new();
    let io = scripted(&["y", "", SO_PIN, SO_PIN, USER_PIN, USER_PIN]);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);

    let token = run(&make_ctx(&io, &fx.config, None, None), &provider).unwrap();

    assert_eq!(token.unwrap().label, wizard::DEFAULT_TOKEN_LABEL);
    assert_eq!(wizard::DEFAULT_TOKEN_LABEL, "r2");
}

#[test]
fn test_overlong_label_reprompted() {
    let fx = Fixture::new();
    let long = "x".repeat(33);
    let io = scripted(&["y", &long, "short", SO_PIN, SO_PIN, USER_PIN, USER_PIN]);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);

    let token = run(&make_ctx(&io, &fx.config, None, None), &provider).unwrap();

    assert_eq!(token.unwrap().label, "short");
    assert!(any_output(&io, "32 characters"));
}

#[test]
fn label_limit_is_measured_in_utf8_bytes() {
    // §11 D15 (b): 17 × 'é' is 17 characters (c2 accepted it) but 34 bytes — re-asked; a
    // 32-byte label is accepted; the answer is py_strip-trimmed first.
    let fx = Fixture::new();
    let accented = "é".repeat(17);
    let exact = format!("  {}  ", "é".repeat(16));
    let io = scripted(&["y", &accented, &exact, SO_PIN, SO_PIN, USER_PIN, USER_PIN]);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);

    let token = run(&make_ctx(&io, &fx.config, None, None), &provider).unwrap();

    assert_eq!(token.unwrap().label, "é".repeat(16));
    assert_eq!(
        io.output()
            .iter()
            .filter(|line| *line
                == "Token labels are limited to 32 characters (CK_TOKEN_INFO) — use a shorter one.")
            .count(),
        1
    );
}

// ---------------------------------------------------------------------------------------
// PIN prompting
// ---------------------------------------------------------------------------------------

#[test]
fn test_short_then_mismatch_then_ok() {
    let fx = Fixture::new();
    let io = scripted(&[
        "y",
        "tok1",
        "abc",
        SO_PIN,
        "different",
        SO_PIN,
        SO_PIN,
        USER_PIN,
        USER_PIN,
    ]);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);

    let token = run(&make_ctx(&io, &fx.config, None, None), &provider).unwrap();

    assert!(token.is_some());
    assert_eq!(
        *double.init_pins.borrow(),
        vec![(SO_PIN.to_owned(), USER_PIN.to_owned())]
    );
    assert!(any_output(&io, "at least 4 characters"));
    assert!(any_output(&io, "do not match"));
}

#[test]
fn test_gives_up_after_three_attempts() {
    let fx = Fixture::new();
    let io = scripted(&["y", "tok1", "a", "b", "c"]); // three too-short SO PINs
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);

    let err = run(&make_ctx(&io, &fx.config, None, None), &provider).unwrap_err();

    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert!(err.message.contains("SO PIN not confirmed"));
    assert_eq!(err.message, "SO PIN not confirmed after 3 attempts");
    assert!(double.init_calls.borrow().is_empty());
}

#[test]
fn pin_length_counts_characters() {
    // c2 `len(pin)` counts characters: "éé€" is 3 characters (7 bytes) → too short.
    let fx = Fixture::new();
    let io = scripted(&["y", "tok1", "éé€", "éé€x", "éé€x", USER_PIN, USER_PIN]);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);

    run(&make_ctx(&io, &fx.config, None, None), &provider)
        .unwrap()
        .unwrap();

    assert_eq!(double.init_pins.borrow()[0].0, "éé€x");
    assert!(any_output(&io, "SO PIN must be at least 4 characters."));
}

// ---------------------------------------------------------------------------------------
// slot discovery
// ---------------------------------------------------------------------------------------

#[test]
fn test_token_needs_init() {
    let _fx = Fixture::new();
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);
    assert!(wizard::token_needs_init(&provider).unwrap());
    double.set_tokens(Vec::new());
    assert!(wizard::token_needs_init(&provider).unwrap());
    double.set_tokens(vec![free_token(0), free_token(1)]);
    assert!(wizard::token_needs_init(&provider).unwrap());
    provider
        .as_token_init()
        .unwrap()
        .init_token(
            0,
            "t",
            &SecretString::from(SO_PIN.to_owned()),
            &SecretString::from(USER_PIN.to_owned()),
        )
        .unwrap();
    assert!(!wizard::token_needs_init(&provider).unwrap());
}

#[test]
fn token_needs_init_counts_a_label_or_a_serial_and_propagates_errors() {
    let _fx = Fixture::new();
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);
    double.set_tokens(vec![free_token(0), soft_token(1, "", "0000000000000001")]);
    assert!(!wizard::token_needs_init(&provider).unwrap());
    double.set_tokens(vec![soft_token(1, "only-label", "")]);
    assert!(!wizard::token_needs_init(&provider).unwrap());

    struct Broken;
    impl FakeHooks for Broken {
        fn list_tokens(&self, _next: &dyn Provider) -> Option<Result<Vec<TokenInfo>>> {
            Some(Err(ConsoleError::provider_unavailable("cannot load")))
        }
    }
    let broken = FakeProvider::new("softhsm")
        .with_type_name("pkcs11")
        .with_hooks(Rc::new(Broken));
    let err = wizard::token_needs_init(&broken).unwrap_err();
    assert_eq!(err.kind, ErrorKind::ProviderUnavailable);
    // FakeProvider's synthetic token carries a label and a serial (the login case).
    let initialized = FakeProvider::new("softhsm").with_type_name("pkcs11");
    assert!(!wizard::token_needs_init(&initialized).unwrap());
}

#[test]
fn test_free_slot_picked_by_empty_label_and_serial() {
    let fx = Fixture::new();
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);
    double.set_tokens(vec![
        soft_token(3, "OLD", "feedface00000001"),
        free_token(9),
    ]);
    let io = scripted(&HAPPY_ANSWERS);

    assert!(
        run(&make_ctx(&io, &fx.config, None, None), &provider)
            .unwrap()
            .is_some()
    );
    assert_eq!(*double.init_calls.borrow(), vec![(9, "tok1".to_owned())]);
}

#[test]
fn test_no_free_slot_raises() {
    let fx = Fixture::new();
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);
    double.set_tokens(vec![soft_token(0, "FULL", "feedface00000002")]);
    let io = scripted(&HAPPY_ANSWERS);

    let err = run(&make_ctx(&io, &fx.config, None, None), &provider).unwrap_err();

    assert_eq!(err.kind, ErrorKind::Generic);
    assert!(err.message.contains("no free SoftHSM slot"));
    assert_eq!(
        err.message,
        "no free SoftHSM slot available for token initialization"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("every slot already holds a token — check `slots` and $SOFTHSM2_CONF")
    );
}

#[test]
fn token_missing_after_init_is_an_error() {
    // init_token "succeeded" but the store shows no such label (c2 `_find_token`).
    let fx = Fixture::new();
    struct Vanishing;
    impl FakeHooks for Vanishing {
        fn init_token(
            &self,
            _next: &dyn Provider,
            _slot: u64,
            _label: &str,
            _so_pin: &SecretString,
            _user_pin: &SecretString,
        ) -> Option<Result<()>> {
            Some(Ok(()))
        }
    }
    let provider = FakeProvider::new("softhsm")
        .with_type_name("pkcs11")
        .with_tokens(vec![free_token(0)])
        .with_hooks(Rc::new(Vanishing));
    let io = scripted(&HAPPY_ANSWERS);
    let err = run(&make_ctx(&io, &fx.config, None, None), &provider).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(err.message, "token 'tok1' not found after initialization");
    assert_eq!(
        err.hint.as_deref(),
        Some("the SoftHSM token store looks inconsistent — check $SOFTHSM2_CONF")
    );
}

#[test]
fn shared_module_refusal_keeps_the_conf_files_and_stops() {
    // §11 D15 (a): set_env_and_reset refuses (shared module) → the conf files of step 1
    // stay written; no prompt after the refusal, no init.
    let fx = Fixture::new();
    struct Shared;
    impl FakeHooks for Shared {
        fn set_env_and_reset(
            &self,
            _next: &dyn Provider,
            _key: &str,
            _value: &str,
        ) -> Option<Result<()>> {
            Some(Err(ConsoleError::provider(
                "'softhsm' shares its PKCS#11 module with another provider",
            )
            .with_hint(
                "restart r2 after the setup, or remove the other provider entry",
            )))
        }
    }
    let provider = FakeProvider::new("softhsm")
        .with_type_name("pkcs11")
        .with_tokens(vec![free_token(0)])
        .with_hooks(Rc::new(Shared));
    let io = scripted(&["y"]);
    let err = run(&make_ctx(&io, &fx.config, None, None), &provider).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Provider);
    assert_eq!(
        err.message,
        "'softhsm' shares its PKCS#11 module with another provider"
    );
    assert_eq!(
        read_text(&fx.conf_path()),
        expected_conf_text(&fx.token_dir)
    );
    assert_eq!(io.remaining(), 0);
    assert!(provider.calls().is_empty());
}

// ---------------------------------------------------------------------------------------
// softhsm2-util fallback
// ---------------------------------------------------------------------------------------

/// A `$PATH` directory holding a fake `softhsm2-util` shell script (c2 monkeypatched
/// `shutil.which` and `subprocess.run`). The script records its argv (one per line) and
/// the inherited SOFTHSM2_CONF next to itself, then runs `body`.
#[cfg(unix)]
fn fake_util(fx: &Fixture, body: &str) -> (PathBuf, PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let bin = fx.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let argv = fx.path().join("util-argv");
    let env = fx.path().join("util-env");
    let script = bin.join("softhsm2-util");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$0\" \"$@\" > {argv}\nprintf '%s' \"$SOFTHSM2_CONF\" > \
             {env}\n{body}\n",
            argv = quoted(&argv),
            env = quoted(&env),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    (bin, argv, env)
}

#[cfg(unix)]
#[test]
fn test_fallback_runs_util_and_reloads() {
    let fx = Fixture::new();
    let (bin, argv, env) = fake_util(&fx, "echo ok\nexit 0");
    let _path = set_env("PATH", Some(bin.to_str().unwrap()));
    let io = scripted(&HAPPY_ANSWERS);
    let double = Rc::new(WizardDouble {
        apply_env: true,
        util_argv: Some(argv.clone()),
        ..WizardDouble::failing()
    });
    let provider = provider_with(&double);

    let token = run(&make_ctx(&io, &fx.config, None, None), &provider)
        .unwrap()
        .unwrap();

    assert_eq!(token.label, "tok1");
    assert_eq!(token.slot_id, 42);
    let util = bin.join("softhsm2-util").display().to_string();
    assert_eq!(
        read_text(&argv).lines().collect::<Vec<_>>(),
        vec![
            util.as_str(),
            "--init-token",
            "--free",
            "--label",
            "tok1",
            "--so-pin",
            SO_PIN,
            "--pin",
            USER_PIN,
        ]
    );
    // the subprocess inherits the step-2 environment.
    assert_eq!(read_text(&env), fx.conf_path().display().to_string());
    // slot layout changed behind the module's back → forced re-init.
    assert_eq!(double.shutdowns.get(), 2);
    assert!(any_output(&io, "softhsm2-util"));
    assert!(
        io.output().contains(
            &"In-process token init failed (PKCS#11 token initialization failed \
          (CKR_GENERAL_ERROR)) — retrying via softhsm2-util."
                .to_owned()
        )
    );
    // the PINs travel in argv only — never printed
    assert!(!io.text().contains(SO_PIN) && !io.text().contains(USER_PIN));
}

#[test]
fn test_no_util_reraises_original() {
    let fx = Fixture::new();
    let empty = fx.path().join("empty-bin");
    std::fs::create_dir(&empty).unwrap();
    let _path = set_env("PATH", Some(empty.to_str().unwrap()));
    let io = scripted(&HAPPY_ANSWERS);
    let double = Rc::new(WizardDouble::failing());
    let provider = provider_with(&double);

    let err = run(&make_ctx(&io, &fx.config, None, None), &provider).unwrap_err();

    assert!(matches!(
        &err.kind,
        ErrorKind::Pkcs11 { ckr_name, .. } if ckr_name == "CKR_GENERAL_ERROR"
    ));
    assert!(err.message.contains("CKR_GENERAL_ERROR"));
    assert_eq!(double.shutdowns.get(), 1);
}

#[cfg(unix)]
#[test]
fn test_util_failure_raises_console_error() {
    let fx = Fixture::new();
    let (bin, _argv, _env) = fake_util(&fx, "echo boom >&2\nexit 1");
    let _path = set_env("PATH", Some(bin.to_str().unwrap()));
    let io = scripted(&HAPPY_ANSWERS);
    let double = Rc::new(WizardDouble::failing());
    let provider = provider_with(&double);

    let err = run(&make_ctx(&io, &fx.config, None, None), &provider).unwrap_err();

    assert_eq!(err.kind, ErrorKind::Generic);
    assert!(
        err.message
            .contains("softhsm2-util --init-token failed: boom")
    );
    assert_eq!(err.message, "softhsm2-util --init-token failed: boom");
    assert_eq!(
        err.hint.as_deref(),
        Some("check the SoftHSM2 installation and $SOFTHSM2_CONF")
    );
}

#[cfg(unix)]
#[test]
fn util_failure_detail_is_stderr_then_stdout_then_the_exit_code() {
    // c2: `stderr.strip() or stdout.strip() or f"exit code {returncode}"` (a signal is
    // Python's negative returncode).
    for (body, detail) in [
        ("echo '  out  '\nexit 3", "out"),
        ("echo ' '\necho ' ' >&2\nexit 3", "exit code 3"),
        ("kill -9 $$", "exit code -9"),
        // text=True: universal newlines before strip
        ("printf 'a\\r\\nb\\rc\\r\\n' >&2\nexit 1", "a\nb\nc"),
    ] {
        let fx = Fixture::new();
        let (bin, _argv, _env) = fake_util(&fx, body);
        let _path = set_env("PATH", Some(bin.to_str().unwrap()));
        let io = scripted(&HAPPY_ANSWERS);
        let provider = provider_with(&Rc::new(WizardDouble::failing()));
        let err = run(&make_ctx(&io, &fx.config, None, None), &provider).unwrap_err();
        assert_eq!(
            err.message,
            format!("softhsm2-util --init-token failed: {detail}"),
            "{body}"
        );
        drop(_path);
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_conf_dir_is_refused_before_anything_is_written() {
    // c2 carried such a path through os.environ via surrogateescape; r2 cannot set it
    // losslessly and refuses it up front (§11 D12 (q)).
    use std::os::unix::ffi::OsStrExt;
    let fx = Fixture::new();
    let bad = fx.path().join(std::ffi::OsStr::from_bytes(b"conf-\xff"));
    let mut config = fx.config.clone();
    config.softhsm.conf_dir = bad.clone();
    let provider = provider_with(&Rc::new(WizardDouble::new()));
    let io = scripted(&HAPPY_ANSWERS);
    let err = run(&make_ctx(&io, &config, None, None), &provider).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Config);
    assert_eq!(
        err.message,
        format!(
            "cannot create the SoftHSM configuration: {} is not valid UTF-8",
            bad.display()
        )
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("check softhsm.conf_dir / softhsm.token_dir in the configuration")
    );
    assert!(!bad.exists());
    assert!(!fx.token_dir.exists());
}

#[cfg(unix)]
#[test]
fn util_spawn_failure_is_an_error() {
    // §11 D12 (q): c2's subprocess.run raised OSError (a crash); r2 reports Python's
    // str(OSError) for the util path. A bad interpreter line makes exec fail with ENOENT.
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::new();
    let bin = fx.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let util = bin.join("softhsm2-util");
    std::fs::write(&util, "#!/nonexistent/interpreter\n").unwrap();
    std::fs::set_permissions(&util, std::fs::Permissions::from_mode(0o755)).unwrap();
    let _path = set_env("PATH", Some(bin.to_str().unwrap()));
    let io = scripted(&HAPPY_ANSWERS);
    let provider = provider_with(&Rc::new(WizardDouble::failing()));

    let err = run(&make_ctx(&io, &fx.config, None, None), &provider).unwrap_err();

    assert_eq!(err.kind, ErrorKind::Generic);
    assert_eq!(
        err.message,
        format!(
            "softhsm2-util --init-token failed: [Errno 2] No such file or directory: '{}'",
            util.display()
        )
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("check the SoftHSM2 installation and $SOFTHSM2_CONF")
    );
}

#[cfg(unix)]
#[test]
fn util_lookup_follows_shutil_which() {
    // A non-executable file and a directory named softhsm2-util are skipped; the first
    // executable one on $PATH wins (shutil.which).
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::new();
    let first = fx.path().join("first");
    let second = fx.path().join("second");
    std::fs::create_dir_all(first.join("softhsm2-util")).unwrap(); // a directory
    std::fs::create_dir(&second).unwrap();
    std::fs::write(second.join("softhsm2-util"), "#!/bin/sh\nexit 0\n").unwrap(); // mode 644
    std::fs::set_permissions(
        second.join("softhsm2-util"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let (bin, argv, _env) = fake_util(&fx, "exit 0");
    let path = std::env::join_paths([&first, &second, &bin]).unwrap();
    let _path = set_env("PATH", Some(path.to_str().unwrap()));
    let io = scripted(&HAPPY_ANSWERS);
    let double = Rc::new(WizardDouble {
        util_argv: Some(argv.clone()),
        ..WizardDouble::failing()
    });
    let provider = provider_with(&double);

    run(&make_ctx(&io, &fx.config, None, None), &provider)
        .unwrap()
        .unwrap();
    assert_eq!(
        read_text(&argv).lines().next().unwrap(),
        bin.join("softhsm2-util").display().to_string()
    );

    // An empty $PATH finds nothing (shutil.which), so the original error stands.
    let _empty = set_env("PATH", Some(""));
    let io = scripted(&HAPPY_ANSWERS);
    let config = softhsm_config(&fx.path().join("conf2"), &fx.path().join("tokens2"), None);
    let provider = provider_with(&Rc::new(WizardDouble::failing()));
    let err = run(&make_ctx(&io, &config, None, None), &provider).unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Pkcs11 { .. }));
}

// ---------------------------------------------------------------------------------------
// config entry reporting & appending (§5.13 step 4)
// ---------------------------------------------------------------------------------------

#[test]
fn test_textual_append_preserves_comments_and_loads() {
    let fx = Fixture::new();
    let source = fx.external("# my precious comment\nui:\n  hex_group: 4\n");
    let mut answers = HAPPY_ANSWERS.to_vec();
    answers.push("y"); // final: append offer
    let io = scripted(&answers);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);
    let ctx = make_ctx(&io, &fx.config, Some(&source), None);

    assert!(run(&ctx, &provider).unwrap().is_some());

    let text = read_text(&source);
    assert!(text.contains("# my precious comment"));
    assert!(text.contains("hex_group: 4"));
    // byte for byte c2's textual block (c2 → r2 in the comment line)
    assert_eq!(
        text,
        format!(
            "# my precious comment\nui:\n  hex_group: 4\n\n# SoftHSM provider added by the r2 \
             first-run wizard (spec §5.13)\nproviders:\n  pkcs11:\n  - name: softhsm\n    \
             library: /opt/test/libsofthsm2.so\n    token_label: tok1\n    env:\n      \
             SOFTHSM2_CONF: {}\n",
            fx.conf_path().display()
        )
    );
    // The appended file feeds the real loader (§4.8 merge) correctly.
    let loaded = load_config(Some(&source)).unwrap();
    assert_eq!(loaded.config.ui.hex_group, 4);
    let instances = &loaded.config.providers.pkcs11;
    assert_eq!(instances.len(), 1);
    let instance = &instances[0];
    assert_eq!(instance.name, "softhsm");
    assert_eq!(instance.library, PathBuf::from(TEST_LIBRARY));
    assert_eq!(instance.token_label.as_deref(), Some("tok1"));
    assert_eq!(
        instance.env.iter().collect::<Vec<_>>(),
        vec![(
            &"SOFTHSM2_CONF".to_owned(),
            &fx.conf_path().display().to_string()
        )]
    );
    // no backup on the textual path
    assert!(!fx.path().join("r2.yaml.bak").exists());
}

#[test]
fn test_structured_append_keeps_existing_instances() {
    let fx = Fixture::new();
    let original =
        "providers:\n  pkcs11:\n    - name: prodhsm\n      library: /usr/lib/libvendor.so\n";
    let source = fx.external(original);
    let mut answers = HAPPY_ANSWERS.to_vec();
    answers.push("y");
    let io = scripted(&answers);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);
    let ctx = make_ctx(&io, &fx.config, Some(&source), None);

    assert!(run(&ctx, &provider).unwrap().is_some());

    let loaded = load_config(Some(&source)).unwrap();
    let names: Vec<&str> = loaded
        .config
        .providers
        .pkcs11
        .iter()
        .map(|instance| instance.name.as_str())
        .collect();
    assert_eq!(names, vec!["prodhsm", "softhsm"]);
    // a .bak of the original text is kept (the structural rewrite drops comments).
    let backup = source.with_file_name("r2.yaml.bak");
    assert_eq!(read_text(&backup), original);
}

#[test]
fn test_append_declined_leaves_file_alone() {
    let fx = Fixture::new();
    let original = "ui:\n  hex_group: 8\n";
    let source = fx.external(original);
    let mut answers = HAPPY_ANSWERS.to_vec();
    answers.push("n");
    let io = scripted(&answers);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);
    let ctx = make_ctx(&io, &fx.config, Some(&source), None);

    assert!(run(&ctx, &provider).unwrap().is_some());

    assert_eq!(read_text(&source), original);
    assert!(any_output(&io, "not modified"));
    assert_eq!(
        io.output().last().unwrap(),
        &format!(
            "{} not modified — add the entry above manually to persist the setup.",
            source.display()
        )
    );
}

#[test]
fn test_duplicate_name_raises_config_error() {
    let fx = Fixture::new();
    let source =
        fx.external("providers:\n  pkcs11:\n    - name: softhsm\n      library: /elsewhere.so\n");
    let mut answers = HAPPY_ANSWERS.to_vec();
    answers.push("y");
    let io = scripted(&answers);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);
    let ctx = make_ctx(&io, &fx.config, Some(&source), None);

    let err = run(&ctx, &provider).unwrap_err();

    assert_eq!(err.kind, ErrorKind::Config);
    assert!(err.message.contains("already defined"));
    assert_eq!(
        err.message,
        format!(
            "provider 'softhsm' is already defined in {}",
            source.display()
        )
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("edit that entry by hand if its settings should change")
    );
    assert!(!source.with_file_name("r2.yaml.bak").exists());
}

#[test]
fn test_unresolved_library_skips_append_offer() {
    // $SOFTHSM2_LIB set-but-missing → find_softhsm_module returns None (§4.5.5).
    let fx = Fixture::new();
    let original = "ui:\n  hex_group: 8\n";
    let source = fx.external(original);
    let io = scripted(&HAPPY_ANSWERS); // NO append answer queued — the offer must not happen
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);
    let ctx = make_ctx(&io, &fx.config, Some(&source), None);

    let token = wizard::run_softhsm_wizard(&ctx, &provider, None).unwrap();

    assert!(token.is_some());
    assert_eq!(read_text(&source), original);
    assert!(any_output(&io, "fill in 'library' by hand"));
    assert!(snippet_of(&io).contains("library: <path-to-libsofthsm2>"));
    assert_eq!(io.remaining(), 0);
}

#[test]
fn test_library_redetected_from_search_paths() {
    let fx = Fixture::new();
    let _lib = set_env("SOFTHSM2_LIB", None);
    let fake_lib = fx.path().join("libsofthsm2.so");
    std::fs::write(&fake_lib, b"\x00").unwrap();
    let config = softhsm_config(&fx.conf_dir, &fx.token_dir, Some(&fake_lib));
    let io = scripted(&HAPPY_ANSWERS);
    let double = Rc::new(WizardDouble::new());
    let provider = provider_with(&double);

    let token =
        wizard::run_softhsm_wizard(&make_ctx(&io, &config, None, None), &provider, None).unwrap();

    assert!(token.is_some());
    let data = yaml::parse(&snippet_of(&io)).unwrap();
    let entry = &data["providers"]["pkcs11"][0];
    assert_eq!(
        entry["library"],
        Value::from(fake_lib.display().to_string())
    );
}

// ---------------------------------------------------------------------------------------
// pure helpers
// ---------------------------------------------------------------------------------------

#[test]
fn test_softhsm_conf_text_matches_spec() {
    let dir = tempfile::tempdir().unwrap();
    let token_dir = dir.path().join("t");
    assert_eq!(
        wizard::softhsm_conf_text(&token_dir),
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            token_dir.display()
        )
    );
}

#[test]
fn test_write_softhsm_conf_creates_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let conf_dir = dir.path().join("a").join("b");
    let token_dir = dir.path().join("c").join("d");
    let conf_path = wizard::write_softhsm_conf(&conf_dir, &token_dir).unwrap();
    assert_eq!(conf_path, conf_dir.join("softhsm2.conf"));
    assert!(token_dir.is_dir());
    assert!(read_text(&conf_path).contains("objectstore.backend = file"));
    // byte for byte (§5.13): LF line endings on POSIX (Python text mode)
    #[cfg(unix)]
    assert_eq!(
        std::fs::read(&conf_path).unwrap(),
        expected_conf_text(&token_dir).into_bytes()
    );
    // idempotent: existing directories are fine, the file is rewritten
    wizard::write_softhsm_conf(&conf_dir, &token_dir).unwrap();
}

#[test]
fn test_write_softhsm_conf_failure_is_config_error() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("file");
    std::fs::write(&blocker, "not a dir").unwrap();
    let err =
        wizard::write_softhsm_conf(&blocker.join("conf"), &dir.path().join("tokens")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Config);
    assert!(
        err.message
            .contains("cannot create the SoftHSM configuration")
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("check softhsm.conf_dir / softhsm.token_dir in the configuration")
    );
    // Python's str(OSError), naming the directory mkdir failed on
    #[cfg(unix)]
    assert_eq!(
        err.message,
        format!(
            "cannot create the SoftHSM configuration: [Errno 20] Not a directory: '{}'",
            blocker.join("conf").display()
        )
    );
}

fn helper_entry(dir: &Path) -> Value {
    wizard::provider_config_entry(
        "softhsm",
        Some(Path::new("/x.so")),
        &dir.join("softhsm2.conf"),
        "t",
    )
}

#[test]
fn test_append_rejects_non_mapping_file() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("r2.yaml");
    std::fs::write(&source, "- just\n- a\n- list\n").unwrap();
    let err = wizard::append_provider_entry(&source, &helper_entry(dir.path())).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Config);
    assert!(err.message.contains("top level is not a mapping"));
    assert_eq!(
        err.message,
        format!("{}: top level is not a mapping", source.display())
    );
}

#[test]
fn test_append_to_empty_file() {
    let _lock = global_state_lock(); // load_config expands `~` paths (reads $HOME)
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("r2.yaml");
    std::fs::write(&source, "").unwrap();
    wizard::append_provider_entry(&source, &helper_entry(dir.path())).unwrap();
    let loaded = load_config(Some(&source)).unwrap();
    assert_eq!(loaded.config.providers.pkcs11[0].name, "softhsm");
}

#[test]
fn test_append_treats_null_sections_as_empty() {
    // A bare `providers:` / `providers.pkcs11:` key is an empty section, not an error
    // (c2 ids null-providers, null-pkcs11).
    let _lock = global_state_lock();
    for original in [
        "ui:\n  hex_group: 8\nproviders:\n",
        "ui:\n  hex_group: 8\nproviders:\n  pkcs11:\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("r2.yaml");
        std::fs::write(&source, original).unwrap();

        wizard::append_provider_entry(&source, &helper_entry(dir.path())).unwrap();

        let text = read_text(&source);
        // exactly one top-level providers key (no shadowing duplicate appended)
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("providers:"))
                .count(),
            1,
            "{original:?}"
        );
        let loaded = load_config(Some(&source)).unwrap();
        assert_eq!(loaded.config.ui.hex_group, 8);
        let instances = &loaded.config.providers.pkcs11;
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].name, "softhsm");
        assert_eq!(instances[0].library, PathBuf::from("/x.so"));
        // structured rewrite path → the original is kept as a .bak
        let backup = source.with_file_name("r2.yaml.bak");
        assert_eq!(read_text(&backup), original);
    }
}

// ---- r2 additions: the c2 byte layouts and the remaining append rules -----------------

#[test]
fn snippet_and_entry_match_c2_bytes() {
    // c2@408d6f2 render_config_snippet output (PyYAML safe_dump, rstripped).
    let entry = wizard::provider_config_entry(
        "softhsm",
        Some(Path::new(TEST_LIBRARY)),
        Path::new("/tmp/x/softhsm2.conf"),
        "tok1",
    );
    assert_eq!(
        wizard::render_config_snippet(&entry),
        "providers:\n  pkcs11:\n  - name: softhsm\n    library: /opt/test/libsofthsm2.so\n    \
         token_label: tok1\n    env:\n      SOFTHSM2_CONF: /tmp/x/softhsm2.conf"
    );
    let entry =
        wizard::provider_config_entry("softhsm", None, Path::new("/tmp/x y/softhsm2.conf"), "yes");
    assert_eq!(
        wizard::render_config_snippet(&entry),
        "providers:\n  pkcs11:\n  - name: softhsm\n    library: <path-to-libsofthsm2>\n    \
         token_label: 'yes'\n    env:\n      SOFTHSM2_CONF: /tmp/x y/softhsm2.conf"
    );
    let keys: Vec<&str> = entry
        .as_mapping()
        .unwrap()
        .keys()
        .map(|key| key.as_str().unwrap())
        .collect();
    assert_eq!(keys, vec!["name", "library", "token_label", "env"]);
}

#[test]
fn appends_match_c2_bytes() {
    // c2@408d6f2 append_provider_entry results (c2 → r2 in the comment line): the textual
    // block strips trailing blank lines first; the structural rewrite keeps the section
    // order and drops comments.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("r2.yaml");
    let entry =
        wizard::provider_config_entry("softhsm", None, Path::new("/tmp/x y/softhsm2.conf"), "yes");
    let block = "providers:\n  pkcs11:\n  - name: softhsm\n    library: <path-to-libsofthsm2>\n    \
                 token_label: 'yes'\n    env:\n      SOFTHSM2_CONF: /tmp/x y/softhsm2.conf\n";

    std::fs::write(&source, "# my precious comment\nui:\n  hex_group: 4\n\n\n").unwrap();
    wizard::append_provider_entry(&source, &entry).unwrap();
    assert_eq!(
        read_text(&source),
        format!(
            "# my precious comment\nui:\n  hex_group: 4\n\n# SoftHSM provider added by the r2 \
             first-run wizard (spec §5.13)\n{block}"
        )
    );

    std::fs::write(
        &source,
        "ui:\n  hex_group: 8\nproviders:\n  memory:\n    enabled: true # c\n  pkcs11:\n",
    )
    .unwrap();
    wizard::append_provider_entry(&source, &entry).unwrap();
    assert_eq!(
        read_text(&source),
        format!(
            "ui:\n  hex_group: 8\nproviders:\n  memory:\n    enabled: true\n  {}",
            &block["providers:\n  ".len()..]
        )
    );
}

#[test]
fn append_section_shape_errors_and_falsy_pkcs11() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("r2.yaml");
    let entry = helper_entry(dir.path());
    let shown = source.display().to_string();

    std::fs::write(&source, "providers: [1]\n").unwrap();
    let err = wizard::append_provider_entry(&source, &entry).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Config);
    assert_eq!(
        err.message,
        format!("{shown}: 'providers' is not a mapping")
    );

    std::fs::write(&source, "providers:\n  pkcs11: {a: 1}\n").unwrap();
    let err = wizard::append_provider_entry(&source, &entry).unwrap_err();
    assert_eq!(
        err.message,
        format!("{shown}: 'providers.pkcs11' is not a list")
    );

    // c2 `providers.get("pkcs11") or []`: any falsy value counts as empty
    for falsy in ["{}", "[]", "''", "0", "false"] {
        std::fs::write(&source, format!("providers:\n  pkcs11: {falsy}\n")).unwrap();
        wizard::append_provider_entry(&source, &entry).unwrap();
        let data = yaml::parse(&read_text(&source)).unwrap();
        assert_eq!(
            data["providers"]["pkcs11"],
            Value::Sequence(vec![entry.clone()]),
            "{falsy}"
        );
    }

    // a non-mapping list item never matches the duplicate check
    std::fs::write(&source, "providers:\n  pkcs11:\n  - softhsm\n").unwrap();
    wizard::append_provider_entry(&source, &entry).unwrap();
    let data = yaml::parse(&read_text(&source)).unwrap();
    assert_eq!(
        data["providers"]["pkcs11"],
        Value::Sequence(vec![Value::from("softhsm"), entry.clone()])
    );

    std::fs::write(&source, "a: [\n").unwrap();
    let err = wizard::append_provider_entry(&source, &entry).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Config);
    assert!(
        err.message
            .starts_with(&format!("cannot parse config file {shown}: ")),
        "{}",
        err.message
    );
}

#[test]
fn append_io_errors_are_config_errors() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.yaml");
    let entry = helper_entry(dir.path());
    let err = wizard::append_provider_entry(&missing, &entry).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Config);
    assert_eq!(
        err.message,
        format!(
            "cannot read config file {}: [Errno 2] No such file or directory: '{}'",
            missing.display(),
            missing.display()
        )
    );

    // invalid UTF-8 (c2 crashed with UnicodeDecodeError): CPython's text (§11 D12 (q))
    let bad = dir.path().join("bad.yaml");
    std::fs::write(&bad, b"ui:\n  x: \xff\n").unwrap();
    let err = wizard::append_provider_entry(&bad, &entry).unwrap_err();
    assert_eq!(
        err.message,
        format!(
            "cannot read config file {}: 'utf-8' codec can't decode byte 0xff in position 9: \
             invalid start byte",
            bad.display()
        )
    );

    // the .bak cannot be written: a dangling symlink into a missing directory sits at its
    // path (c2: FileNotFoundError naming the backup); the config stays untouched
    #[cfg(unix)]
    {
        let source = dir.path().join("r2.yaml");
        std::fs::write(&source, "providers:\n").unwrap();
        let backup = dir.path().join("r2.yaml.bak");
        std::os::unix::fs::symlink("missing/x", &backup).unwrap();
        let err = wizard::append_provider_entry(&source, &entry).unwrap_err();
        assert_eq!(
            err.message,
            format!(
                "cannot write backup {}: [Errno 2] No such file or directory: '{}'",
                backup.display(),
                backup.display()
            )
        );
        assert_eq!(read_text(&source), "providers:\n");
    }
}

#[test]
fn append_backup_into_an_existing_directory() {
    // shutil.copy2 into a directory destination copies to `<dir>/<source name>`; c2 then
    // rewrites the config as usual.
    let dir = tempfile::tempdir().unwrap();
    let entry = helper_entry(dir.path());
    let source = dir.path().join("r2.yaml");
    std::fs::write(&source, "providers:\n").unwrap();
    let backup = dir.path().join("r2.yaml.bak");
    std::fs::create_dir(&backup).unwrap();
    wizard::append_provider_entry(&source, &entry).unwrap();
    assert_eq!(read_text(&backup.join("r2.yaml")), "providers:\n");
    assert!(read_text(&source).contains("pkcs11:"));
}

#[cfg(unix)]
#[test]
fn append_backup_that_is_the_config_itself_is_refused() {
    // shutil.SameFileError: a `.bak` symlinked (or hard-linked) to the config is refused
    // before anything is opened — the config is never truncated.
    let dir = tempfile::tempdir().unwrap();
    let entry = helper_entry(dir.path());
    let source = dir.path().join("r2.yaml");
    std::fs::write(&source, "providers:\n").unwrap();
    let backup = dir.path().join("r2.yaml.bak");
    std::os::unix::fs::symlink(&source, &backup).unwrap();
    let err = wizard::append_provider_entry(&source, &entry).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Config);
    assert_eq!(
        err.message,
        format!(
            "cannot write backup {b}: PosixPath('{s}') and PosixPath('{b}') are the same file",
            s = source.display(),
            b = backup.display()
        )
    );
    assert_eq!(read_text(&source), "providers:\n");

    std::fs::remove_file(&backup).unwrap();
    std::fs::hard_link(&source, &backup).unwrap();
    let err = wizard::append_provider_entry(&source, &entry).unwrap_err();
    assert!(
        err.message.ends_with("are the same file"),
        "{}",
        err.message
    );
    assert_eq!(read_text(&source), "providers:\n");
}

#[cfg(unix)]
#[test]
fn append_backup_that_is_a_named_pipe_is_refused() {
    // shutil.SpecialFileError (an OSError): a FIFO at `<config>.bak` is refused before
    // either file is opened, so the wizard never blocks on it.
    let dir = tempfile::tempdir().unwrap();
    let entry = helper_entry(dir.path());
    let source = dir.path().join("r2.yaml");
    std::fs::write(&source, "providers:\n").unwrap();
    let backup = dir.path().join("r2.yaml.bak");
    let status = std::process::Command::new("mkfifo")
        .arg(&backup)
        .status()
        .unwrap();
    assert!(status.success());
    let err = wizard::append_provider_entry(&source, &entry).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Config);
    assert_eq!(
        err.message,
        format!(
            "cannot write backup {b}: `{b}` is a named pipe",
            b = backup.display()
        )
    );
    assert_eq!(read_text(&source), "providers:\n");
}

#[test]
fn append_universal_newlines_and_backup_metadata() {
    // Python read_text: CRLF/CR → LF before the textual append.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("r2.yaml");
    let entry = helper_entry(dir.path());
    std::fs::write(&source, "ui:\r\n  hex_group: 4\r\n").unwrap();
    wizard::append_provider_entry(&source, &entry).unwrap();
    let text = std::fs::read_to_string(&source).unwrap();
    #[cfg(unix)]
    assert!(text.starts_with("ui:\n  hex_group: 4\n\n# SoftHSM provider added by the r2"));
    assert!(!text.contains('\r') || cfg!(windows));

    // shutil.copy2 keeps the original's permission bits and modification time
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&source, "providers:\n").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        std::fs::File::options()
            .write(true)
            .open(&source)
            .unwrap()
            .set_modified(old)
            .unwrap();
        wizard::append_provider_entry(&source, &entry).unwrap();
        let meta = std::fs::metadata(source.with_file_name("r2.yaml.bak")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(meta.modified().unwrap(), old);
    }
}

// ---------------------------------------------------------------------------------------
// the real wizard behind `login` (c2 test_providers_cmd.py, R8's command; R11's rows)
// ---------------------------------------------------------------------------------------

/// A logged-out pkcs11 FakeProvider named like config softhsm.provider_name.
fn softhsm_registry() -> (ProviderRegistry, Rc<FakeProvider>) {
    let registry = ProviderRegistry::new();
    let softhsm = Rc::new(
        FakeProvider::new("softhsm")
            .with_type_name("pkcs11")
            .starting_logged_out(),
    );
    registry
        .register(Rc::clone(&softhsm) as Rc<dyn Provider>)
        .unwrap();
    (registry, softhsm)
}

#[test]
#[ignore = "needs R8's `login` command (merge checklist: drop this ignore when R11 merges after R8)"]
fn test_login_softhsm_live_wizard_skips_for_initialized_token() {
    // No stubbing: the REAL wizard is consulted; the FakeProvider token carries
    // label+serial → token_needs_init is false and the normal login proceeds.
    let _fx = Fixture::new();
    let (registry, softhsm) = softhsm_registry();
    let io = scripted(&["1234"]);
    let config = make_config(None);
    run_line(
        &make_ctx(&io, &config, None, Some(registry)),
        "login softhsm",
    )
    .unwrap();
    assert_eq!(softhsm.status().auth, AuthState::LoggedIn);
}

#[test]
fn login_softhsm_live_wizard_skip_condition() {
    // The wizard half of the row above, through the API R8 calls: the synthetic token of
    // a logged-out pkcs11 FakeProvider is initialized → no wizard.
    let _fx = Fixture::new();
    let (_registry, softhsm) = softhsm_registry();
    assert!(!wizard::token_needs_init(softhsm.as_ref()).unwrap());
    assert_eq!(softhsm.status().auth, AuthState::LoggedOut);
}

/// Presents an uninitialized SoftHSM slot: blank label and serial (§5.13).
struct UninitializedToken;
impl FakeHooks for UninitializedToken {
    fn list_tokens(&self, _next: &dyn Provider) -> Option<Result<Vec<TokenInfo>>> {
        Some(Ok(vec![TokenInfo {
            slot_id: 0,
            label: String::new(),
            manufacturer: "SoftHSM".to_owned(),
            model: "v2".to_owned(),
            serial: String::new(),
        }]))
    }
}

fn uninitialized_registry() -> (ProviderRegistry, Rc<FakeProvider>) {
    let registry = ProviderRegistry::new();
    let softhsm = Rc::new(
        FakeProvider::new("softhsm")
            .with_type_name("pkcs11")
            .starting_logged_out()
            .with_hooks(Rc::new(UninitializedToken)),
    );
    registry
        .register(Rc::clone(&softhsm) as Rc<dyn Provider>)
        .unwrap();
    (registry, softhsm)
}

#[test]
#[ignore = "needs R8's `login` command (merge checklist: drop this ignore when R11 merges after R8)"]
fn test_login_softhsm_live_wizard_triggers_and_decline_stops() {
    // No stubbing: an uninitialized token triggers the REAL wizard; declining its confirm
    // stops the login cleanly (§5.13 — the provider stays listed).
    let _fx = Fixture::new();
    let (registry, softhsm) = uninitialized_registry();
    let io = scripted(&["n"]); // decline the wizard's setup confirm
    let config = make_config(None);
    run_line(
        &make_ctx(&io, &config, None, Some(registry)),
        "login softhsm",
    )
    .unwrap();
    assert_eq!(softhsm.status().auth, AuthState::LoggedOut);
    assert!(any_output(&io, "declined"));
}

#[test]
fn login_softhsm_live_wizard_trigger_and_decline() {
    // The wizard half of the row above, through the API R8 calls: the blank slot triggers
    // the wizard, declining returns None without touching the provider.
    let fx = Fixture::new();
    let (_registry, softhsm) = uninitialized_registry();
    assert!(wizard::token_needs_init(softhsm.as_ref()).unwrap());
    let io = scripted(&["n"]);
    let ctx = make_ctx(&io, &fx.config, None, None);
    assert_eq!(
        wizard::run_softhsm_wizard(&ctx, softhsm.as_ref(), None).unwrap(),
        None
    );
    assert_eq!(softhsm.status().auth, AuthState::LoggedOut);
    assert!(softhsm.calls().is_empty());
    assert!(!fx.conf_dir.exists());
}
