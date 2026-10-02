// providers / slots / login / logout command tests — port of c2
// tests/unit/console/test_providers_cmd.py (R8): FakeProvider (+ FakeHooks for c2's
// subclass doubles) and ScriptedIo. The §5.13 wizard-trigger cases stub the wizard API
// through `commands::providers::test_seam` (c2 stubbed `c2.console.wizard` via
// `sys.modules`).
use std::rc::Rc;

use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_provider::{AuthState, Provider, TokenInfo};
use r2_testkit::{FakeHooks, FakeProvider, ScriptedIo};
use secrecy::{ExposeSecret, SecretString};

use super::keys_cmd_support::{ctx_with, registry_of};
use crate::commands::providers::test_seam::{WizardStub, install};
use crate::testing::{CtxBuilder, make_config, run_line};

fn scripted(answers: &[&str]) -> Rc<ScriptedIo> {
    Rc::new(ScriptedIo::new(answers.iter().copied()))
}

/// The default session (mem + logged-in hsm, testing::make_providers).
fn default_ctx(io: &Rc<ScriptedIo>) -> Rc<crate::context::AppContext> {
    CtxBuilder::new(Rc::clone(io) as Rc<dyn r2_core::io::ConsoleIo>).build()
}

fn hsm_fake(name: &str) -> FakeProvider {
    FakeProvider::new(name).with_type_name("pkcs11")
}

fn logged_out(name: &str) -> FakeProvider {
    hsm_fake(name).starting_logged_out()
}

fn auth(provider: &FakeProvider) -> AuthState {
    provider.status().auth
}

// ---------------------------------------------------------------------------------------
// providers
// ---------------------------------------------------------------------------------------

#[test]
fn test_providers_table_lists_types_and_states() {
    let io = scripted(&[]);
    run_line(&default_ctx(&io), "providers").unwrap();
    let text = io.text();
    assert!(text.contains("mem") && text.contains("memory") && text.contains("ready"));
    assert!(text.contains("hsm") && text.contains("pkcs11") && text.contains("logged in"));
    assert!(text.contains("hsm-token")); // token column when logged in
    assert!(text.contains("hsm-token (slot 0, serial FAKE0001)"));
    assert_eq!(text.lines().next().unwrap().trim(), "providers"); // table title
    // a pkcs11 instance that is neither configured nor the autodetect name: "?"
    let hsm_row = text
        .lines()
        .find(|l| l.trim_start().starts_with("hsm "))
        .unwrap();
    assert!(hsm_row.contains(" ? "), "{hsm_row}");
}

#[test]
fn test_providers_logged_out_state() {
    let hsm = Rc::new(logged_out("hsm"));
    let io = scripted(&[]);
    run_line(&ctx_with(&io, registry_of(&[hsm]), None), "providers").unwrap();
    assert!(io.text().contains("logged out"));
}

#[test]
fn test_providers_missing_library_is_unavailable() {
    let config = make_config(Some(
        "providers:\n  pkcs11:\n    - name: broken\n      library: /nonexistent/libvendor.so\n",
    ));
    let broken = Rc::new(hsm_fake("broken"));
    let io = scripted(&[]);
    run_line(
        &ctx_with(&io, registry_of(&[broken]), Some(config)),
        "providers",
    )
    .unwrap();
    let text = io.text();
    assert!(text.contains("unavailable (library not found)"));
    assert!(text.contains("/nonexistent/libvendor.so"));
}

#[test]
fn providers_existing_configured_library_shows_the_auth_state() {
    let dir = tempfile::tempdir().unwrap();
    let library = dir.path().join("libvendor.so");
    std::fs::write(&library, b"").unwrap();
    let config = make_config(Some(&format!(
        "providers:\n  pkcs11:\n    - name: vendor\n      library: {}\n",
        library.display()
    )));
    let vendor = Rc::new(hsm_fake("vendor"));
    let io = scripted(&[]);
    run_line(
        &ctx_with(&io, registry_of(&[vendor]), Some(config)),
        "providers",
    )
    .unwrap();
    let text = io.text();
    assert!(text.contains(&library.display().to_string()));
    assert!(text.contains("logged in"));
    assert!(!text.contains("unavailable"));
}

// ---------------------------------------------------------------------------------------
// slots
// ---------------------------------------------------------------------------------------

#[test]
fn test_slots_lists_tokens() {
    let io = scripted(&[]);
    run_line(&default_ctx(&io), "slots hsm").unwrap();
    let text = io.text();
    assert!(text.contains("hsm-token") && text.contains("FAKE0001"));
    assert_eq!(text.lines().next().unwrap().trim(), "tokens on hsm");
}

#[test]
fn test_slots_no_tokens() {
    let io = scripted(&[]);
    run_line(&default_ctx(&io), "slots mem").unwrap();
    assert_eq!(io.output(), ["no tokens present on 'mem'"]);
}

#[test]
fn test_slots_missing_argument() {
    let err = run_line(&default_ctx(&scripted(&[])), "slots").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert!(err.message.contains("missing <provider>"));
    assert_eq!(err.hint.as_deref(), Some("usage: slots <provider>"));
}

#[test]
fn test_slots_unknown_provider() {
    let err = run_line(&default_ctx(&scripted(&[])), "slots nosuch").unwrap_err();
    assert_eq!(err.kind, ErrorKind::ProviderNotFound);
}

#[test]
fn slots_and_logout_reject_name_value_tokens() {
    let err = run_line(&default_ctx(&scripted(&[])), "slots hsm a=b").unwrap_err();
    assert_eq!(err.message, "unexpected name=value token 'a=…'");
    assert_eq!(
        err.hint.as_deref(),
        Some("usage: slots <provider> (quote values containing '=')")
    );
}

// ---------------------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------------------

/// (mem, logged-out hsm) registry.
fn logged_out_hsm() -> (Rc<FakeProvider>, r2_provider::ProviderRegistry) {
    let hsm = Rc::new(logged_out("hsm"));
    let registry = registry_of(&[Rc::new(FakeProvider::new("mem")), Rc::clone(&hsm)]);
    (hsm, registry)
}

#[test]
fn test_login_prompts_hidden_pin_and_logs_in() {
    let (hsm, registry) = logged_out_hsm();
    let io = scripted(&["1234"]);
    run_line(&ctx_with(&io, registry, None), "login hsm").unwrap();
    assert_eq!(auth(&hsm), AuthState::LoggedIn);
    assert_eq!(io.prompts(), ["PIN for token 'hsm-token'"]);
    let login = ["login", "hsm-token", "***", "False"]
        .map(String::from)
        .to_vec();
    assert!(hsm.calls().contains(&login)); // PIN never recorded
    assert!(
        io.output()
            .iter()
            .any(|line| line.contains("logged in to 'hsm-token'"))
    );
    assert_eq!(io.output(), ["logged in to 'hsm-token' (slot 0) on hsm"]);
}

#[test]
fn test_login_inline_pin_never_prompts() {
    let (hsm, registry) = logged_out_hsm();
    let io = scripted(&[]);
    run_line(&ctx_with(&io, registry, None), "login hsm --pin 1234").unwrap();
    assert_eq!(auth(&hsm), AuthState::LoggedIn);
    assert!(io.prompts().is_empty());
}

#[test]
fn test_login_keep_pin_flag_is_passed() {
    let (hsm, registry) = logged_out_hsm();
    let io = scripted(&["1234"]);
    run_line(&ctx_with(&io, registry, None), "login hsm --keep-pin").unwrap();
    let login = ["login", "hsm-token", "***", "True"]
        .map(String::from)
        .to_vec();
    assert!(hsm.calls().contains(&login));
    assert!(
        io.output()
            .iter()
            .any(|line| line.contains("auto-recovery"))
    );
    assert_eq!(
        io.output(),
        ["logged in to 'hsm-token' (slot 0) on hsm — PIN kept for session auto-recovery"]
    );
}

#[test]
fn test_login_when_already_logged_in() {
    let err = run_line(&default_ctx(&scripted(&[])), "login hsm --pin 1234").unwrap_err();
    assert_eq!(err.kind, ErrorKind::AlreadyLoggedIn);
    assert_eq!(err.message, "already logged in");
    assert_eq!(err.hint.as_deref(), Some("logout first"));
}

#[test]
fn test_login_memory_provider_unsupported() {
    let err = run_line(&default_ctx(&scripted(&[])), "login mem").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("does not require login"));
    assert_eq!(err.message, "provider 'mem' does not require login");
}

#[test]
fn test_login_token_label_selects() {
    let (hsm, registry) = logged_out_hsm();
    run_line(
        &ctx_with(&scripted(&["1234"]), registry, None),
        "login hsm hsm-token",
    )
    .unwrap();
    assert_eq!(auth(&hsm), AuthState::LoggedIn);
}

#[test]
fn test_login_unknown_token_label() {
    let (_hsm, registry) = logged_out_hsm();
    let err = run_line(&ctx_with(&scripted(&[]), registry, None), "login hsm wrong").unwrap_err();
    assert!(err.kind.is_provider());
    assert!(err.message.contains("no token with label 'wrong'"));
    assert_eq!(err.message, "no token with label 'wrong' on 'hsm'");
    let hint = err.hint.unwrap();
    assert!(hint.contains("hsm-token"));
    assert_eq!(hint, "present tokens: 'hsm-token' (slot 0)");
}

#[test]
fn test_login_slot_selects() {
    let (hsm, registry) = logged_out_hsm();
    run_line(
        &ctx_with(&scripted(&["1234"]), registry, None),
        "login hsm --slot 0",
    )
    .unwrap();
    assert_eq!(auth(&hsm), AuthState::LoggedIn);
}

#[test]
fn test_login_unknown_slot() {
    let (_hsm, registry) = logged_out_hsm();
    let err = run_line(
        &ctx_with(&scripted(&[]), registry, None),
        "login hsm --slot 9",
    )
    .unwrap_err();
    assert!(err.kind.is_provider());
    assert!(err.message.contains("no token with slot 9"));
}

#[test]
fn test_login_non_integer_slot() {
    let (_hsm, registry) = logged_out_hsm();
    let err = run_line(
        &ctx_with(&scripted(&[]), registry, None),
        "login hsm --slot abc",
    )
    .unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "slot".into()
        }
    );
    assert!(err.message.contains("invalid slot"));
    assert_eq!(err.message, "invalid slot 'abc'");
    assert_eq!(err.hint.as_deref(), Some("--slot takes an integer"));
}

#[test]
fn login_slot_beyond_i128_is_an_unknown_slot() {
    // c2 `int()` is unbounded: a well-formed integer too large for any slot parses and
    // then matches no token (Provider "no token with slot …", Python's str(int) form).
    for (text, shown) in [
        (
            "99999999999999999999999999999999999999999",
            "99999999999999999999999999999999999999999",
        ),
        (
            " -0_0999999999999999999999999999999999999999999 ",
            "-999999999999999999999999999999999999999999",
        ),
    ] {
        let (_hsm, registry) = logged_out_hsm();
        let err = run_line(
            &ctx_with(&scripted(&[]), registry, None),
            &format!("login hsm --slot '{text}'"),
        )
        .unwrap_err();
        assert!(err.kind.is_provider(), "{text}: {:?}", err.kind);
        assert_eq!(err.message, format!("no token with slot {shown} on 'hsm'"));
        assert!(
            err.hint
                .as_deref()
                .is_some_and(|hint| hint.starts_with("present tokens: ")),
            "{:?}",
            err.hint
        );
    }
    // malformed long text (double `_`) and non-ASCII digits (§11 D18) stay Param
    for text in ["9999999999999999999999999999999999999999__9", "\u{663}"] {
        let (_hsm, registry) = logged_out_hsm();
        let err = run_line(
            &ctx_with(&scripted(&[]), registry, None),
            &format!("login hsm --slot '{text}'"),
        )
        .unwrap_err();
        assert_eq!(
            err.message,
            format!("invalid slot {}", r2_core::text::py_repr(text))
        );
        assert_eq!(err.hint.as_deref(), Some("--slot takes an integer"));
    }
}

#[test]
fn login_slot_honours_python_int_digit_limit() {
    // CPython 3.12 `int(str)` raises ValueError beyond 4300 digits (leading zeros and the
    // digits between `_` count; sign and whitespace do not) → c2 ParamError.
    let over = [
        "0".repeat(4301),
        format!("{}1", "0".repeat(4300)),
        "1".repeat(4301),
        format!("{}1", "1_".repeat(4300)),
        format!(" -{} ", "1".repeat(4301)),
    ];
    for text in &over {
        let (hsm, registry) = logged_out_hsm();
        let err = run_line(
            &ctx_with(&scripted(&["1234"]), registry, None),
            &format!("login hsm --slot '{text}'"),
        )
        .unwrap_err();
        assert_eq!(
            err.kind,
            ErrorKind::Param {
                param_name: "slot".into()
            },
            "{} digits",
            text.len()
        );
        assert_eq!(
            err.message,
            format!("invalid slot {}", r2_core::text::py_repr(text))
        );
        assert_eq!(err.hint.as_deref(), Some("--slot takes an integer"));
        assert_eq!(auth(&hsm), AuthState::LoggedOut);
    }
    // exactly 4300 digits still parses: zeros select slot 0, ones match no token
    let (hsm, registry) = logged_out_hsm();
    run_line(
        &ctx_with(&scripted(&["1234"]), registry, None),
        &format!("login hsm --slot ' +{}'", "0".repeat(4300)),
    )
    .unwrap();
    assert_eq!(auth(&hsm), AuthState::LoggedIn);
    let ones = "1".repeat(4300);
    let (_hsm, registry) = logged_out_hsm();
    let err = run_line(
        &ctx_with(&scripted(&[]), registry, None),
        &format!("login hsm --slot -{ones}"),
    )
    .unwrap_err();
    assert!(err.kind.is_provider(), "{:?}", err.kind);
    assert_eq!(err.message, format!("no token with slot -{ones} on 'hsm'"));
}

#[test]
fn login_slot_is_python_int() {
    // c2 `int(slot_opt)`: surrounding whitespace, a sign and leading zeros are accepted
    let (hsm, registry) = logged_out_hsm();
    run_line(
        &ctx_with(&scripted(&["1234"]), registry, None),
        "login hsm --slot ' +00'",
    )
    .unwrap();
    assert_eq!(auth(&hsm), AuthState::LoggedIn);
}

#[test]
fn test_login_label_and_slot_conflict() {
    let (_hsm, registry) = logged_out_hsm();
    let err = run_line(
        &ctx_with(&scripted(&[]), registry, None),
        "login hsm hsm-token --slot 0",
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert!(err.message.contains("not both"));
    assert_eq!(err.message, "give either <token-label> or --slot, not both");
}

/// c2 TwoTokenProvider / NoTokenProvider / UninitializedTokenProvider: fixed list_tokens.
struct Tokens(Vec<TokenInfo>);
impl FakeHooks for Tokens {
    fn list_tokens(&self, _next: &dyn Provider) -> Option<Result<Vec<TokenInfo>>> {
        Some(Ok(self.0.clone()))
    }
}

fn token(slot_id: u64, label: &str, serial: &str) -> TokenInfo {
    TokenInfo {
        slot_id,
        label: label.into(),
        manufacturer: "m".into(),
        model: "f".into(),
        serial: serial.into(),
    }
}

fn two_token_provider() -> Rc<FakeProvider> {
    Rc::new(logged_out("hsm").with_hooks(Rc::new(Tokens(vec![
        token(0, "alpha", "S0"),
        token(3, "beta", "S3"),
    ]))))
}

#[test]
fn test_login_multiple_tokens_prompts_select() {
    let hsm = two_token_provider();
    let io = scripted(&["beta (slot 3, serial S3)", "1234"]);
    run_line(
        &ctx_with(&io, registry_of(&[Rc::clone(&hsm)]), None),
        "login hsm",
    )
    .unwrap();
    let status = hsm.status();
    assert_eq!(status.token.unwrap().label, "beta");
    assert_eq!(
        io.prompts(),
        ["Select a token on 'hsm'", "PIN for token 'beta'"]
    );
}

#[test]
fn test_login_config_default_token_label() {
    let config = make_config(Some(
        "providers:\n  pkcs11:\n    - name: hsm\n      library: /x/lib.so\n      token_label: beta\n",
    ));
    let hsm = two_token_provider();
    let io = scripted(&["1234"]); // no select answer queued — must not prompt
    run_line(
        &ctx_with(&io, registry_of(&[Rc::clone(&hsm)]), Some(config)),
        "login hsm",
    )
    .unwrap();
    assert_eq!(hsm.status().token.unwrap().label, "beta");
}

#[test]
fn login_config_default_slot() {
    let config = make_config(Some(
        "providers:\n  pkcs11:\n    - name: hsm\n      library: /x/lib.so\n      slot: 3\n",
    ));
    let hsm = two_token_provider();
    let io = scripted(&["1234"]);
    run_line(
        &ctx_with(&io, registry_of(&[Rc::clone(&hsm)]), Some(config)),
        "login hsm",
    )
    .unwrap();
    assert_eq!(hsm.status().token.unwrap().slot_id, 3);
}

/// First login attempt fails with CKR_PIN_INCORRECT, the next ones succeed (§5.2).
#[derive(Default)]
struct WrongPinOnce {
    attempts: std::cell::RefCell<Vec<String>>,
}
impl FakeHooks for WrongPinOnce {
    fn login(
        &self,
        next: &dyn Provider,
        token: &TokenInfo,
        pin: &SecretString,
        keep_pin: bool,
    ) -> Option<Result<()>> {
        self.attempts
            .borrow_mut()
            .push(pin.expose_secret().to_owned());
        if self.attempts.borrow().len() == 1 {
            return Some(Err(ConsoleError::pkcs11(
                "wrong PIN for token 'hsm-token' (CKR_PIN_INCORRECT)",
                0xA0,
                "CKR_PIN_INCORRECT",
            )
            .with_hint("re-enter the PIN")));
        }
        Some(next.login(token, pin, keep_pin))
    }
}

#[test]
fn test_login_reprompts_on_wrong_pin() {
    let hooks = Rc::new(WrongPinOnce::default());
    let hsm = Rc::new(logged_out("hsm").with_hooks(Rc::clone(&hooks) as Rc<dyn FakeHooks>));
    let io = scripted(&["bad", "1234"]);
    run_line(
        &ctx_with(&io, registry_of(&[Rc::clone(&hsm)]), None),
        "login hsm",
    )
    .unwrap();
    assert_eq!(*hooks.attempts.borrow(), ["bad", "1234"]);
    assert_eq!(auth(&hsm), AuthState::LoggedIn);
    // error rendered between tries
    assert!(io.output().iter().any(|line| line.contains("wrong PIN")));
    assert_eq!(
        io.output()[0],
        "error: wrong PIN for token 'hsm-token' (CKR_PIN_INCORRECT) (hint: re-enter the PIN)"
    );
}

#[test]
fn test_login_inline_wrong_pin_raises_without_reprompt() {
    let hooks = Rc::new(WrongPinOnce::default());
    let hsm = Rc::new(logged_out("hsm").with_hooks(Rc::clone(&hooks) as Rc<dyn FakeHooks>));
    let err = run_line(
        &ctx_with(&scripted(&[]), registry_of(&[hsm]), None),
        "login hsm --pin bad",
    )
    .unwrap_err();
    assert_eq!(err.ckr().map(|(_, name)| name), Some("CKR_PIN_INCORRECT"));
    assert_eq!(*hooks.attempts.borrow(), ["bad"]);
}

#[test]
fn test_login_without_tokens() {
    let hsm = Rc::new(logged_out("hsm").with_hooks(Rc::new(Tokens(Vec::new()))));
    let err = run_line(
        &ctx_with(&scripted(&[]), registry_of(&[hsm]), None),
        "login hsm",
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Provider);
    assert!(err.message.contains("no tokens present"));
    assert_eq!(
        err.hint.as_deref(),
        Some("insert/initialize a token, then run `slots hsm`")
    );
}

// ---------------------------------------------------------------------------------------
// login → §5.13 first-run wizard hook
// ---------------------------------------------------------------------------------------

fn wiz_token() -> TokenInfo {
    TokenInfo {
        slot_id: 7,
        label: "wiz-token".into(),
        manufacturer: "m".into(),
        model: "w".into(),
        serial: "WZ1".into(),
    }
}

/// A logged-out pkcs11 FakeProvider named like config softhsm.provider_name.
fn softhsm() -> Rc<FakeProvider> {
    Rc::new(logged_out("softhsm"))
}

fn stub(needs_init: bool, result: Option<TokenInfo>) -> Rc<WizardStub> {
    Rc::new(WizardStub {
        needs_init,
        result,
        ..WizardStub::default()
    })
}

#[test]
fn test_login_softhsm_triggers_wizard_and_uses_its_token() {
    let wizard = stub(true, Some(wiz_token()));
    let _guard = install(Rc::clone(&wizard));
    let softhsm = softhsm();
    let io = scripted(&["1234"]);
    run_line(
        &ctx_with(&io, registry_of(&[Rc::clone(&softhsm)]), None),
        "login softhsm",
    )
    .unwrap();
    assert_eq!(*wizard.calls.borrow(), (1, 1));
    let status = softhsm.status();
    assert_eq!(status.auth, AuthState::LoggedIn);
    assert_eq!(status.token.unwrap().label, "wiz-token");
    assert_eq!(io.prompts(), ["PIN for token 'wiz-token'"]);
}

#[test]
fn test_login_softhsm_wizard_declined_stops_cleanly() {
    let wizard = stub(true, None);
    let _guard = install(Rc::clone(&wizard));
    let softhsm = softhsm();
    let io = scripted(&[]);
    run_line(
        &ctx_with(&io, registry_of(&[Rc::clone(&softhsm)]), None),
        "login softhsm",
    )
    .unwrap();
    assert_eq!(*wizard.calls.borrow(), (1, 1));
    assert_eq!(auth(&softhsm), AuthState::LoggedOut); // §5.13: listed but unusable
    assert!(io.output().iter().any(|line| line.contains("declined")));
    assert_eq!(
        io.output(),
        ["SoftHSM setup declined — 'softhsm' stays unusable until you run `login softhsm` again"]
    );
}

#[test]
fn test_login_softhsm_initialized_token_skips_wizard() {
    let wizard = stub(false, None);
    let _guard = install(Rc::clone(&wizard));
    let softhsm = softhsm();
    run_line(
        &ctx_with(
            &scripted(&["1234"]),
            registry_of(&[Rc::clone(&softhsm)]),
            None,
        ),
        "login softhsm",
    )
    .unwrap();
    assert_eq!(*wizard.calls.borrow(), (1, 0));
    assert_eq!(auth(&softhsm), AuthState::LoggedIn);
}

#[test]
fn test_login_other_provider_never_consults_wizard() {
    let wizard = stub(true, Some(wiz_token()));
    let _guard = install(Rc::clone(&wizard));
    let (hsm, registry) = logged_out_hsm();
    run_line(&ctx_with(&scripted(&["1234"]), registry, None), "login hsm").unwrap();
    assert_eq!(*wizard.calls.borrow(), (0, 0));
    assert_eq!(auth(&hsm), AuthState::LoggedIn);
}

#[test]
fn login_softhsm_with_the_real_wizard_api_and_an_initialized_token() {
    // no stub: crate::wizard is consulted (the R0 stub answers "no init needed" before R11
    // merges; R11's real trigger answers the same for a token with label and serial)
    let softhsm = softhsm();
    run_line(
        &ctx_with(
            &scripted(&["1234"]),
            registry_of(&[Rc::clone(&softhsm)]),
            None,
        ),
        "login softhsm",
    )
    .unwrap();
    assert_eq!(auth(&softhsm), AuthState::LoggedIn);
}

// ---------------------------------------------------------------------------------------
// logout
// ---------------------------------------------------------------------------------------

#[test]
fn test_logout_drops_session_capabilities() {
    let hsm = Rc::new(hsm_fake("hsm"));
    let io = scripted(&[]);
    run_line(
        &ctx_with(&io, registry_of(&[Rc::clone(&hsm)]), None),
        "logout hsm",
    )
    .unwrap();
    assert_eq!(auth(&hsm), AuthState::LoggedOut);
    assert!(hsm.mechanisms().is_empty());
    assert_eq!(io.output(), ["logged out of hsm"]);
}

#[test]
fn test_logout_memory_unsupported() {
    let err = run_line(&default_ctx(&scripted(&[])), "logout mem").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("does not require login"));
}

#[test]
fn test_list_keys_after_logout_requires_auth() {
    // Not-logged-in error path for key operations (L8 acceptance).
    let hsm = Rc::new(logged_out("hsm"));
    let err = run_line(
        &ctx_with(&scripted(&[]), registry_of(&[hsm]), None),
        "keys hsm",
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert!(err.message.contains("login required"));
}

// ---------------------------------------------------------------------------------------
// completion
// ---------------------------------------------------------------------------------------

#[test]
fn provider_commands_complete_provider_names_then_options() {
    let io = scripted(&[]);
    let ctx = default_ctx(&io);
    let commands = crate::commands::all_commands().unwrap();
    let complete = |name: &str, tokens: &[&str], cursor: &str| {
        let tokens: Vec<String> = tokens.iter().map(|t| (*t).to_owned()).collect();
        commands[name].complete(&ctx, &tokens, cursor)
    };
    assert_eq!(complete("slots", &["slots", "h"], "h"), ["hsm"]);
    assert_eq!(complete("login", &["login"], ""), ["mem", "hsm"]);
    assert_eq!(
        complete("login", &["login", "hsm"], ""),
        ["--slot", "--pin", "--keep-pin"]
    );
    assert_eq!(complete("logout", &["logout", "m"], "m"), ["mem"]);
    assert!(complete("logout", &["logout", "hsm"], "").is_empty());
    assert!(complete("slots", &["slots", "hsm"], "").is_empty());
    assert!(io.prompts().is_empty() && io.output().is_empty()); // never touches ctx.io
}
