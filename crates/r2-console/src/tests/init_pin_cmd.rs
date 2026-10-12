// `init-pin` command tests (§5.18, §11 D35): FakeProvider with `.with_tokens(..)` (the
// TokenInit seam), FakeHooks for the SO-PIN failure paths, and ScriptedIo.
use std::cell::RefCell;
use std::rc::Rc;

use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_provider::{AuthState, Provider, TokenInfo};
use r2_testkit::{FakeHooks, FakeProvider, ScriptedIo};
use secrecy::{ExposeSecret, SecretString};

use super::keys_cmd_support::{calls_of, ctx_with, registry_of};
use crate::testing::run_line;

fn scripted(answers: &[&str]) -> Rc<ScriptedIo> {
    Rc::new(ScriptedIo::new(answers.iter().copied()))
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

/// A logged-out PKCS#11 fake with initialized tokens at slots 0 and 16.
fn hsm() -> FakeProvider {
    FakeProvider::new("hsm")
        .with_type_name("pkcs11")
        .starting_logged_out()
        .with_tokens(vec![token(0, "alpha", "S0"), token(16, "beta", "S16")])
}

fn run(provider: &Rc<FakeProvider>, io: &Rc<ScriptedIo>, line: &str) -> Result<()> {
    run_line(
        &ctx_with(io, registry_of(&[Rc::clone(provider)]), None),
        line,
    )
    .map(|_| ())
}

#[test]
fn init_pin_logs_in_as_so_and_sets_the_user_pin_of_the_chosen_slot() {
    let hsm = Rc::new(hsm());
    let io = scripted(&["so-secret", "4321", "4321"]);
    run(&hsm, &io, "init-pin hsm --slot 16").unwrap();
    assert_eq!(
        io.prompts(),
        [
            "SO PIN for token 'beta'",
            "New user PIN for token 'beta'",
            "Repeat the new user PIN",
        ]
    );
    // PINs are never recorded
    assert_eq!(
        calls_of(&hsm, "init_pin"),
        [["init_pin", "16", "beta", "***", "***"]
            .map(String::from)
            .to_vec()]
    );
    assert_eq!(io.output(), ["user PIN set on 'beta' (slot 16) on hsm"]);
    assert_eq!(hsm.status().auth, AuthState::LoggedOut);
}

#[test]
fn init_pin_inline_pins_never_prompt() {
    let hsm = Rc::new(hsm());
    let io = scripted(&[]);
    run(&hsm, &io, "init-pin hsm alpha --so-pin 0000 --new-pin 1111").unwrap();
    assert!(io.prompts().is_empty());
    assert_eq!(calls_of(&hsm, "init_pin")[0][2], "alpha");
    assert_eq!(io.output(), ["user PIN set on 'alpha' (slot 0) on hsm"]);
}

#[test]
fn init_pin_reprompts_a_mismatched_or_empty_new_pin() {
    let hsm = Rc::new(hsm());
    let io = scripted(&["so", "", "1111", "2222", "3333", "3333"]);
    run(&hsm, &io, "init-pin hsm alpha").unwrap();
    assert_eq!(
        io.output(),
        [
            "the new user PIN must not be empty — try again",
            "PIN entries do not match — try again",
            "user PIN set on 'alpha' (slot 0) on hsm",
        ]
    );
}

#[test]
fn init_pin_gives_up_after_three_unconfirmed_new_pins() {
    let hsm = Rc::new(hsm());
    let io = scripted(&["so", "1", "2", "1", "2", "1", "2"]);
    let err = run(&hsm, &io, "init-pin hsm alpha").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert_eq!(err.message, "new user PIN not confirmed after 3 attempts");
    assert!(calls_of(&hsm, "init_pin").is_empty());
}

#[test]
fn init_pin_refuses_an_empty_inline_new_pin() {
    let hsm = Rc::new(hsm());
    let err = run(
        &hsm,
        &scripted(&[]),
        "init-pin hsm alpha --so-pin 1 --new-pin \"\"",
    )
    .unwrap_err();
    assert_eq!(err.message, "the new user PIN must not be empty");
    assert_eq!(err.param_name(), Some("new-pin"));
    assert!(calls_of(&hsm, "init_pin").is_empty());
}

/// Fails the first SO login with CKR_PIN_INCORRECT, records every SO PIN tried.
#[derive(Default)]
struct WrongSoPinOnce {
    attempts: RefCell<Vec<String>>,
}
impl FakeHooks for WrongSoPinOnce {
    fn init_pin(
        &self,
        next: &dyn Provider,
        token: &TokenInfo,
        so_pin: &SecretString,
        user_pin: &SecretString,
    ) -> Option<Result<()>> {
        self.attempts
            .borrow_mut()
            .push(so_pin.expose_secret().to_owned());
        if self.attempts.borrow().len() == 1 {
            return Some(Err(ConsoleError::pkcs11(
                "wrong SO PIN for token 'alpha' (CKR_PIN_INCORRECT)",
                0xA0,
                "CKR_PIN_INCORRECT",
            )
            .with_hint("re-enter the SO PIN")));
        }
        next.as_token_init()
            .map(|init| init.init_pin(token, so_pin, user_pin))
    }
}

#[test]
fn init_pin_reprompts_only_the_so_pin_after_a_wrong_one() {
    let hooks = Rc::new(WrongSoPinOnce::default());
    let hsm = Rc::new(hsm().with_hooks(Rc::clone(&hooks) as Rc<dyn FakeHooks>));
    let io = scripted(&["bad", "1111", "1111", "good"]);
    run(&hsm, &io, "init-pin hsm alpha").unwrap();
    assert_eq!(*hooks.attempts.borrow(), ["bad", "good"]);
    assert_eq!(
        io.prompts(),
        [
            "SO PIN for token 'alpha'",
            "New user PIN for token 'alpha'",
            "Repeat the new user PIN",
            "SO PIN for token 'alpha'",
        ]
    );
    assert_eq!(
        io.output()[0],
        "error: wrong SO PIN for token 'alpha' (CKR_PIN_INCORRECT) (hint: re-enter the SO PIN)"
    );
}

#[test]
fn init_pin_inline_wrong_so_pin_fails_without_reprompt() {
    let hooks = Rc::new(WrongSoPinOnce::default());
    let hsm = Rc::new(hsm().with_hooks(Rc::clone(&hooks) as Rc<dyn FakeHooks>));
    let err = run(
        &hsm,
        &scripted(&[]),
        "init-pin hsm alpha --so-pin bad --new-pin 1111",
    )
    .unwrap_err();
    assert_eq!(err.ckr().map(|(_, name)| name), Some("CKR_PIN_INCORRECT"));
    assert_eq!(*hooks.attempts.borrow(), ["bad"]);
}

#[test]
fn init_pin_refuses_a_logged_in_provider_before_prompting() {
    let hsm = Rc::new(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .with_tokens(vec![token(0, "alpha", "S0")]),
    );
    assert_eq!(hsm.status().auth, AuthState::LoggedIn);
    let io = scripted(&[]);
    let err = run(&hsm, &io, "init-pin hsm").unwrap_err();
    assert_eq!(err.kind, ErrorKind::AlreadyLoggedIn);
    assert_eq!(err.hint.as_deref(), Some("logout first"));
    assert!(io.prompts().is_empty());
}

#[test]
fn init_pin_needs_a_provider_with_tokens() {
    let mem = Rc::new(FakeProvider::new("mem"));
    let err = run(&mem, &scripted(&[]), "init-pin mem").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(
        err.message,
        "provider 'mem' does not support PIN initialization"
    );
}

#[test]
fn init_pin_argument_errors() {
    let hsm = Rc::new(hsm());
    let usage = "usage: init-pin <provider> [<token-label> | --slot <n>] [--so-pin <pin>] [--new-pin <pin>]";
    for (line, message) in [
        ("init-pin hsm --pin 1", "unknown option --pin"),
        ("init-pin hsm a b", "too many arguments"),
        (
            "init-pin hsm alpha --slot 0",
            "give either <token-label> or --slot, not both",
        ),
    ] {
        let err = run(&hsm, &scripted(&[]), line).unwrap_err();
        assert_eq!(err.message, message, "{line}");
        assert_eq!(err.hint.as_deref(), Some(usage), "{line}");
    }
    let err = run(&hsm, &scripted(&[]), "init-pin hsm --slot 7").unwrap_err();
    assert_eq!(err.message, "no token with slot 7 on 'hsm'");
    let err = run(&hsm, &scripted(&[]), "init-pin").unwrap_err();
    assert!(err.message.contains("provider"), "{}", err.message);
    assert!(calls_of(&hsm, "init_pin").is_empty());
}

#[test]
fn init_pin_completes_provider_names_then_options() {
    let io = scripted(&[]);
    let hsm = Rc::new(hsm());
    let ctx = ctx_with(&io, registry_of(&[hsm]), None);
    let commands = crate::commands::all_commands().unwrap();
    let complete = |tokens: &[&str], cursor: &str| {
        let tokens: Vec<String> = tokens.iter().map(|t| (*t).to_owned()).collect();
        commands["init-pin"].complete(&ctx, &tokens, cursor)
    };
    assert_eq!(complete(&["init-pin", "h"], "h"), ["hsm"]);
    assert_eq!(
        complete(&["init-pin", "hsm"], ""),
        ["--slot", "--so-pin", "--new-pin"]
    );
    assert!(io.prompts().is_empty() && io.output().is_empty());
}
