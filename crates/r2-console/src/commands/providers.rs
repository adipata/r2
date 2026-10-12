// `providers` / `slots` / `login` / `logout` (spec §5.1/§5.2, §5.13 trigger; owner R8) —
// port of c2 `console/commands/providers_cmd.py` — and `init-pin` (§5.18, §11 D35; an r2
// addition).
//
// Commands return errors, never print them — the REPL renders (§4.2). The `providers`
// table never loads a PKCS#11 library (§6 startup resilience): availability is judged by a
// pure path check; real load failures surface on first use.
use std::path::Path;

use r2_core::error::ConsoleError;
use r2_core::io::{Renderable, table};
use r2_core::text::{py_int, py_repr};
use r2_pkcs11::softhsm::find_softhsm_module;
use r2_provider::{AuthState, Provider, ProviderStatus, TokenInfo};
use secrecy::{ExposeSecret, SecretString};

use crate::cmdutil::{completed_args, positional, reject_named};
use crate::commands::Command;
use crate::completer::complete_provider_names;
use crate::context::AppContext;
use crate::parser::BoundArgs;
use crate::repl::Flow;
use crate::wizard;

/// §4.9.6: every command module exports exactly this.
pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(ProvidersCommand),
        Box::new(SlotsCommand),
        Box::new(LoginCommand),
        Box::new(LogoutCommand),
        Box::new(InitPinCommand),
    ]
}

/// The `providers.rs` reject_named noun (c2 providers_cmd `_reject_named`).
const NOUN: &str = "values";

// ---------------------------------------------------------------------------------------
// providers
// ---------------------------------------------------------------------------------------

struct ProvidersCommand;

impl Command for ProvidersCommand {
    fn name(&self) -> &'static str {
        "providers"
    }
    fn summary(&self) -> &'static str {
        "List configured providers with type, library and auth state"
    }
    fn usage(&self) -> &'static str {
        "providers"
    }
    fn run(&self, ctx: &AppContext, _args: &BoundArgs) -> r2_core::Result<Flow> {
        let mut rows = Vec::new();
        for provider in ctx.providers.all() {
            let status = provider.status();
            let library = if provider.type_name() == "pkcs11" {
                ctx.cfg()
                    .providers
                    .pkcs11
                    .iter()
                    .find(|instance| instance.name == provider.name())
                    .map(|instance| instance.library.display().to_string())
                    .filter(|text| !text.is_empty())
                    .unwrap_or_else(|| autodetected_library(ctx, provider.as_ref()))
            } else {
                "-".to_owned()
            };
            let token = match &status.token {
                Some(token) => format!(
                    "{} (slot {}, serial {})",
                    token.label, token.slot_id, token.serial
                ),
                None => "-".to_owned(),
            };
            let state = state_text(&status, &library);
            rows.push(vec![
                provider.name().to_owned(),
                provider.type_name().to_owned(),
                library,
                state,
                token,
            ]);
        }
        ctx.io.print(table(
            Some("providers"),
            &["name", "type", "library", "status", "token"],
            rows,
        ));
        Ok(Flow::Continue)
    }
}

/// Library path for the §5.13 autodetected SoftHSM instance (pure path probe).
fn autodetected_library(ctx: &AppContext, provider: &dyn Provider) -> String {
    if provider.name() == ctx.cfg().softhsm.provider_name
        && let Some(path) = find_softhsm_module(&ctx.cfg().softhsm.search_paths)
    {
        return path.display().to_string();
    }
    "?".to_owned()
}

/// §5.2 "unavailable (<reason>)" without loading the library (§6): a configured path that
/// does not exist is judged from the filesystem.
fn state_text(status: &ProviderStatus, library: &str) -> String {
    if library != "-" && library != "?" && !Path::new(library).exists() {
        return "unavailable (library not found)".to_owned();
    }
    match status.auth {
        AuthState::NotRequired => "ready",
        AuthState::LoggedIn => "logged in",
        AuthState::LoggedOut => "logged out",
    }
    .to_owned()
}

// ---------------------------------------------------------------------------------------
// slots
// ---------------------------------------------------------------------------------------

struct SlotsCommand;

impl Command for SlotsCommand {
    fn name(&self) -> &'static str {
        "slots"
    }
    fn summary(&self) -> &'static str {
        "List the tokens of a PKCS#11 provider"
    }
    fn usage(&self) -> &'static str {
        "slots <provider>"
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        reject_named(args, self.usage(), NOUN)?;
        let provider = ctx
            .providers
            .get(positional(args, 0, "provider", self.usage())?)?;
        let tokens = provider.list_tokens()?;
        if tokens.is_empty() {
            ctx.io.print(Renderable::Text(format!(
                "no tokens present on '{}'",
                provider.name()
            )));
            return Ok(Flow::Continue);
        }
        let rows = tokens
            .iter()
            .map(|t| {
                vec![
                    t.slot_id.to_string(),
                    t.label.clone(),
                    t.manufacturer.clone(),
                    t.model.clone(),
                    t.serial.clone(),
                ]
            })
            .collect();
        ctx.io.print(table(
            Some(&format!("tokens on {}", provider.name())),
            &["slot", "label", "manufacturer", "model", "serial"],
            rows,
        ));
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        if completed_args(tokens, cursor_token) == 0 {
            return complete_provider_names(ctx, cursor_token);
        }
        Vec::new()
    }
}

// ---------------------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------------------

const LOGIN_USAGE: &str =
    "login <provider> [<token-label> | --slot <n>] [--pin <pin>] [--keep-pin]";

struct LoginCommand;

impl Command for LoginCommand {
    fn name(&self) -> &'static str {
        "login"
    }
    fn summary(&self) -> &'static str {
        "Open a session and log in to a PKCS#11 token"
    }
    fn usage(&self) -> &'static str {
        LOGIN_USAGE
    }
    fn flags(&self) -> &'static [&'static str] {
        &["keep-pin"]
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        reject_named(args, self.usage(), NOUN)?;
        let provider = ctx
            .providers
            .get(positional(args, 0, "provider", self.usage())?)?;
        let status = provider.status();
        match status.auth {
            AuthState::NotRequired => {
                return Err(ConsoleError::unsupported(format!(
                    "provider '{}' does not require login",
                    provider.name()
                )));
            }
            AuthState::LoggedIn => {
                return Err(
                    ConsoleError::already_logged_in("already logged in").with_hint("logout first")
                );
            }
            AuthState::LoggedOut => {}
        }
        let mut token: Option<TokenInfo> = None;
        if provider.name() == ctx.cfg().softhsm.provider_name {
            let (handled, wizard_token) = run_first_login_wizard(ctx, provider.as_ref())?;
            if handled && wizard_token.is_none() {
                // §5.13: declined — the provider stays listed
                ctx.io.print(Renderable::Text(format!(
                    "SoftHSM setup declined — '{name}' stays unusable until you run `login \
                     {name}` again",
                    name = provider.name()
                )));
                return Ok(Flow::Continue);
            }
            token = wizard_token;
        }
        let token = match token {
            Some(token) => token,
            None => select_token(ctx, provider.as_ref(), args, LOGIN_USAGE)?,
        };
        let keep_pin = args.flag("keep-pin");
        let given_pin = args.opt("pin");
        let prompted = given_pin.is_none();
        let mut pin = match given_pin {
            Some(pin) => SecretString::from(pin.to_owned()),
            None => prompt_pin(ctx, &token)?,
        };
        loop {
            match provider.login(&token, &pin, keep_pin) {
                Ok(()) => break,
                // §5.2 CKR table: wrong PIN → re-prompt (interactive PINs only).
                Err(err)
                    if prompted
                        && err
                            .ckr()
                            .is_some_and(|(_, name)| name == "CKR_PIN_INCORRECT") =>
                {
                    ctx.io.print_error(&err);
                    pin = prompt_pin(ctx, &token)?;
                }
                Err(err) => return Err(err),
            }
        }
        let kept = if keep_pin {
            " — PIN kept for session auto-recovery"
        } else {
            ""
        };
        ctx.io.print(Renderable::Text(format!(
            "logged in to '{}' (slot {}) on {}{kept}",
            token.label,
            token.slot_id,
            provider.name()
        )));
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        if completed_args(tokens, cursor_token) == 0 {
            return complete_provider_names(ctx, cursor_token);
        }
        ["--slot", "--pin", "--keep-pin"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }
}

fn prompt_pin(ctx: &AppContext, token: &TokenInfo) -> r2_core::Result<SecretString> {
    ctx.io
        .prompt_secret(&format!("PIN for token '{}'", token.label))
}

/// §5.13 first-run wizard trigger on `login <softhsm>`. Returns `(handled, token)`: not
/// handled → proceed with normal token selection; handled with a token → log in to it;
/// handled with None → the operator declined, stop cleanly. The wizard is R11's
/// (`crate::wizard`), always linked in r2 (c2's ImportError fallback is n/a).
fn run_first_login_wizard(
    ctx: &AppContext,
    provider: &dyn Provider,
) -> r2_core::Result<(bool, Option<TokenInfo>)> {
    #[cfg(test)]
    if let Some(result) = test_seam::stubbed(provider) {
        return Ok(result);
    }
    if !wizard::token_needs_init(provider)? {
        return Ok((false, None));
    }
    Ok((true, wizard::run_softhsm_wizard(ctx, provider, None)?))
}

/// §5.2 selection order: token-label arg → --slot → config default → prompt.
fn select_token(
    ctx: &AppContext,
    provider: &dyn Provider,
    args: &BoundArgs,
    usage: &str,
) -> r2_core::Result<TokenInfo> {
    let tokens = provider.list_tokens()?;
    if tokens.is_empty() {
        return Err(
            ConsoleError::provider(format!("no tokens present on '{}'", provider.name()))
                .with_hint(format!(
                    "insert/initialize a token, then run `slots {}`",
                    provider.name()
                )),
        );
    }
    let label_arg = args.positionals.get(1);
    let slot_opt = args.opt("slot");
    if label_arg.is_some() && slot_opt.is_some() {
        return Err(
            ConsoleError::generic("give either <token-label> or --slot, not both")
                .with_hint(format!("usage: {usage}")),
        );
    }
    if let Some(label) = label_arg {
        return match_token(&tokens, provider.name(), Wanted::Label(label));
    }
    if let Some(slot_text) = slot_opt {
        let invalid = || {
            ConsoleError::param(format!("invalid slot {}", py_repr(slot_text)), "slot")
                .with_hint("--slot takes an integer")
        };
        // CPython 3.12 `int(str)` refuses more than 4300 digits (leading zeros and `_`
        // separators' digits count; sign, `_` and whitespace do not) with ValueError.
        if is_well_formed_int(slot_text)
            && slot_text.chars().filter(char::is_ascii_digit).count() > PY_INT_MAX_STR_DIGITS
        {
            return Err(invalid());
        }
        let Some(slot) = py_int(slot_text, 10) else {
            if let Some(normalized) = overflowing_int_text(slot_text) {
                // c2 `int()` is unbounded: a well-formed integer outside i128 parses, and
                // no CK_SLOT_ID can equal it → "no token with slot {n}" (c2 parity).
                return match_token(&tokens, provider.name(), Wanted::Overflow(&normalized));
            }
            return Err(invalid());
        };
        return match_token(&tokens, provider.name(), Wanted::Slot(slot));
    }
    // config default (§5.2)
    if let Some(instance) = ctx
        .cfg()
        .providers
        .pkcs11
        .iter()
        .find(|instance| instance.name == provider.name())
    {
        if let Some(wanted) = &instance.token_label
            && let Some(token) = tokens.iter().find(|t| &t.label == wanted)
        {
            return Ok(token.clone());
        }
        if let Some(slot) = instance.slot
            && let Some(token) = tokens.iter().find(|t| t.slot_id == slot)
        {
            return Ok(token.clone());
        }
    }
    if tokens.len() == 1 {
        return Ok(tokens[0].clone());
    }
    let options: Vec<String> = tokens
        .iter()
        .map(|t| format!("{} (slot {}, serial {})", t.label, t.slot_id, t.serial))
        .collect();
    let index = ctx.io.select(
        &format!("Select a token on '{}'", provider.name()),
        &options,
    )?;
    tokens
        .get(index)
        .cloned()
        .ok_or_else(|| ConsoleError::generic(format!("token selection {index} is out of range")))
}

enum Wanted<'a> {
    Label(&'a str),
    Slot(i128),
    /// A well-formed integer outside i128 (its Python `str(int(text))` form): never matches.
    Overflow(&'a str),
}

/// CPython's default `sys.int_info.default_max_str_digits`: `int(str)` raises ValueError
/// for a decimal string with more digits than this.
const PY_INT_MAX_STR_DIGITS: usize = 4300;

/// Whether `text` is a well-formed Python decimal int literal, regardless of magnitude.
/// Zeroing every ASCII digit keeps the grammar (whitespace, sign, `_` placement) and
/// cannot overflow, so `py_int` on the zeroed text decides well-formedness.
fn is_well_formed_int(text: &str) -> bool {
    let zeroed: String = text
        .chars()
        .map(|c| if c.is_ascii_digit() { '0' } else { c })
        .collect();
    py_int(&zeroed, 10).is_some()
}

/// For text that `py_int(text, 10)` rejected: `Some(str(int(text)))` when the text is
/// still a well-formed Python decimal int literal (it overflowed i128), else None.
fn overflowing_int_text(text: &str) -> Option<String> {
    if !is_well_formed_int(text) {
        return None;
    }
    let digits: String = text.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return None; // zero never overflows; unreachable in practice
    }
    let sign = if text.contains('-') { "-" } else { "" };
    Some(format!("{sign}{digits}"))
}

fn match_token(
    tokens: &[TokenInfo],
    provider_name: &str,
    wanted: Wanted<'_>,
) -> r2_core::Result<TokenInfo> {
    let found = tokens.iter().find(|token| match wanted {
        Wanted::Label(label) => token.label == label,
        Wanted::Slot(slot) => i128::from(token.slot_id) == slot,
        Wanted::Overflow(_) => false,
    });
    if let Some(token) = found {
        return Ok(token.clone());
    }
    let wanted = match wanted {
        Wanted::Label(label) => format!("label '{label}'"),
        Wanted::Slot(slot) => format!("slot {slot}"),
        Wanted::Overflow(digits) => format!("slot {digits}"),
    };
    let known: Vec<String> = tokens
        .iter()
        .map(|t| format!("'{}' (slot {})", t.label, t.slot_id))
        .collect();
    Err(
        ConsoleError::provider(format!("no token with {wanted} on '{provider_name}'"))
            .with_hint(format!("present tokens: {}", known.join(", "))),
    )
}

// ---------------------------------------------------------------------------------------
// logout
// ---------------------------------------------------------------------------------------

struct LogoutCommand;

impl Command for LogoutCommand {
    fn name(&self) -> &'static str {
        "logout"
    }
    fn summary(&self) -> &'static str {
        "Log out of a PKCS#11 token (the session stays reusable)"
    }
    fn usage(&self) -> &'static str {
        "logout <provider>"
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        reject_named(args, self.usage(), NOUN)?;
        let provider = ctx
            .providers
            .get(positional(args, 0, "provider", self.usage())?)?;
        if provider.status().auth == AuthState::NotRequired {
            return Err(ConsoleError::unsupported(format!(
                "provider '{}' does not require login",
                provider.name()
            )));
        }
        provider.logout()?;
        ctx.io.print(Renderable::Text(format!(
            "logged out of {}",
            provider.name()
        )));
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        if completed_args(tokens, cursor_token) == 0 {
            return complete_provider_names(ctx, cursor_token);
        }
        Vec::new()
    }
}

// ---------------------------------------------------------------------------------------
// init-pin
// ---------------------------------------------------------------------------------------

const INIT_PIN_USAGE: &str =
    "init-pin <provider> [<token-label> | --slot <n>] [--so-pin <pin>] [--new-pin <pin>]";

/// The `--options` `init-pin` takes (all take a value).
const INIT_PIN_OPTIONS: [&str; 3] = ["slot", "so-pin", "new-pin"];

/// Attempts at the hidden + confirmed new-PIN prompt.
const NEW_PIN_ATTEMPTS: usize = 3;

/// `init-pin` (§5.18): log in as the Security Officer and set or reset the user PIN of a
/// token with C_InitPIN — `pkcs11-tool --login --login-type so --init-pin`. The token's
/// objects are untouched (this is not C_InitToken).
struct InitPinCommand;

impl Command for InitPinCommand {
    fn name(&self) -> &'static str {
        "init-pin"
    }
    fn summary(&self) -> &'static str {
        "Set or reset a token's user PIN as the Security Officer"
    }
    fn usage(&self) -> &'static str {
        INIT_PIN_USAGE
    }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow> {
        reject_named(args, self.usage(), NOUN)?;
        if let Some(name) = args
            .options
            .keys()
            .find(|name| !INIT_PIN_OPTIONS.contains(&name.as_str()))
        {
            return Err(ConsoleError::generic(format!("unknown option --{name}"))
                .with_hint(format!("usage: {INIT_PIN_USAGE}")));
        }
        if args.positionals.len() > 2 {
            return Err(ConsoleError::generic("too many arguments")
                .with_hint(format!("usage: {INIT_PIN_USAGE}")));
        }
        let provider = ctx
            .providers
            .get(positional(args, 0, "provider", self.usage())?)?;
        let Some(init) = provider.as_token_init() else {
            return Err(ConsoleError::unsupported(format!(
                "provider '{}' does not support PIN initialization",
                provider.name()
            )));
        };
        if provider.status().auth == AuthState::LoggedIn {
            // checked before any prompt; the provider refuses it again
            return Err(
                ConsoleError::already_logged_in("already logged in").with_hint("logout first")
            );
        }
        let token = select_token(ctx, provider.as_ref(), args, INIT_PIN_USAGE)?;
        let given_so_pin = args.opt("so-pin");
        let prompted = given_so_pin.is_none();
        let mut so_pin = match given_so_pin {
            Some(pin) => SecretString::from(pin.to_owned()),
            None => prompt_so_pin(ctx, &token)?,
        };
        let user_pin = match args.opt("new-pin") {
            Some("") => {
                return Err(ConsoleError::param(
                    "the new user PIN must not be empty",
                    "new-pin",
                ));
            }
            Some(pin) => SecretString::from(pin.to_owned()),
            None => prompt_new_pin(ctx, &token)?,
        };
        loop {
            match init.init_pin(&token, &so_pin, &user_pin) {
                Ok(()) => break,
                // wrong SO PIN → re-prompt (interactive SO PINs only), like `login`
                Err(err)
                    if prompted
                        && err
                            .ckr()
                            .is_some_and(|(_, name)| name == "CKR_PIN_INCORRECT") =>
                {
                    ctx.io.print_error(&err);
                    so_pin = prompt_so_pin(ctx, &token)?;
                }
                Err(err) => return Err(err),
            }
        }
        ctx.io.print(Renderable::Text(format!(
            "user PIN set on '{}' (slot {}) on {}",
            token.label,
            token.slot_id,
            provider.name()
        )));
        Ok(Flow::Continue)
    }
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        if completed_args(tokens, cursor_token) == 0 {
            return complete_provider_names(ctx, cursor_token);
        }
        ["--slot", "--so-pin", "--new-pin"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }
}

fn prompt_so_pin(ctx: &AppContext, token: &TokenInfo) -> r2_core::Result<SecretString> {
    ctx.io
        .prompt_secret(&format!("SO PIN for token '{}'", token.label))
}

/// Hidden + confirmed new user PIN; never echoed or logged. The token judges the length.
fn prompt_new_pin(ctx: &AppContext, token: &TokenInfo) -> r2_core::Result<SecretString> {
    for _ in 0..NEW_PIN_ATTEMPTS {
        let pin = ctx
            .io
            .prompt_secret(&format!("New user PIN for token '{}'", token.label))?;
        if pin.expose_secret().is_empty() {
            ctx.io.print(Renderable::Text(
                "the new user PIN must not be empty — try again".to_owned(),
            ));
            continue;
        }
        let repeat = ctx.io.prompt_secret("Repeat the new user PIN")?;
        if repeat.expose_secret() == pin.expose_secret() {
            return Ok(pin);
        }
        ctx.io.print(Renderable::Text(
            "PIN entries do not match — try again".to_owned(),
        ));
    }
    Err(ConsoleError::user_abort(format!(
        "new user PIN not confirmed after {NEW_PIN_ATTEMPTS} attempts"
    )))
}

/// Test-only replacement of the §5.13 wizard API (c2's tests stubbed `c2.console.wizard`
/// through `sys.modules`): while a stub is installed, `login` consults it instead of
/// `crate::wizard`, recording each consultation. Thread-local, so tests stay independent.
#[cfg(test)]
pub(crate) mod test_seam {
    use std::cell::RefCell;
    use std::rc::Rc;

    use r2_provider::{Provider, TokenInfo};

    /// What the stubbed wizard answers, and how often it was consulted.
    #[derive(Default)]
    pub(crate) struct WizardStub {
        pub(crate) needs_init: bool,
        pub(crate) result: Option<TokenInfo>,
        /// (token_needs_init calls, run_softhsm_wizard calls)
        pub(crate) calls: RefCell<(usize, usize)>,
    }

    thread_local! {
        static STUB: RefCell<Option<Rc<WizardStub>>> = const { RefCell::new(None) };
    }

    /// Install `stub` until the returned guard drops.
    pub(crate) fn install(stub: Rc<WizardStub>) -> Guard {
        STUB.with(|slot| *slot.borrow_mut() = Some(stub));
        Guard
    }

    pub(crate) struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            STUB.with(|slot| {
                if let Ok(mut slot) = slot.try_borrow_mut() {
                    *slot = None;
                }
            });
        }
    }

    pub(super) fn stubbed(_provider: &dyn Provider) -> Option<(bool, Option<TokenInfo>)> {
        let stub = STUB.with(|slot| slot.borrow().clone())?;
        stub.calls.borrow_mut().0 += 1;
        if !stub.needs_init {
            return Some((false, None));
        }
        stub.calls.borrow_mut().1 += 1;
        Some((true, stub.result.clone()))
    }
}
