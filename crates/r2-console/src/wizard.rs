// SoftHSM2 first-run wizard (spec §4.9.9, §5.13; owner R11) — c2 `console/wizard.py`.
//
// Flow (§5.13, triggered by R8's `login` on the SoftHSM provider when no initialized token
// exists — see `token_needs_init`):
//
// 1. create `softhsm.conf_dir` + `softhsm.token_dir`; write `softhsm2.conf`;
// 2. point `SOFTHSM2_CONF` at it BEFORE the module's C_Initialize — through
//    `TokenInit::set_env_and_reset`, which reaches r2-pkcs11's single audited `set_var`
//    site and resets the provider so the next lazy initialize re-reads the environment
//    (the wizard never touches the environment itself);
// 3. initialize the token: in-process `TokenInit::init_token`, falling back to
//    `softhsm2-util --init-token` (plain subprocess) when it is on PATH. SO PIN and user
//    PIN are prompted hidden + confirmed;
// 4. report the resulting provider entry and, when an external config file is in use,
//    offer to append it.
//
// Declining leaves the provider listed but unusable until the wizard is re-run;
// memory-only operation is untouched. Secret hygiene (§6): PINs travel through
// `prompt_secret` into `init_token` / the `softhsm2-util` argv only; never printed or logged.
use r2_config::yaml::{self, Mapping, Value};
use r2_core::error::{ConsoleError, Result};
use r2_core::io::{ConsoleIo, Renderable};
use r2_core::params::{ParamSpec, ParamValue};
use r2_core::text::{py_os_error_str, py_repr, py_strip};
use r2_pkcs11::softhsm::find_softhsm_module;
use r2_provider::{Provider, TokenInfo};
use secrecy::{ExposeSecret, SecretString};
use std::path::{Path, PathBuf};

use crate::context::AppContext;

pub const SOFTHSM2_CONF_ENV: &str = "SOFTHSM2_CONF";
/// Label offered when the operator just hits enter (c2: "c2" — §11 D7).
pub const DEFAULT_TOKEN_LABEL: &str = "r2";

/// SoftHSM2 enforces ulMinPinLen = 4; checked up front for a friendly message.
const MIN_PIN_LEN: usize = 4;
const PIN_ATTEMPTS: usize = 3;
/// CK_TOKEN_INFO label field width, in bytes (§11 D15).
const MAX_LABEL_BYTES: usize = 32;
/// Placeholder used in the reported config entry when the module path cannot be
/// re-detected (the config append is skipped in that case).
const LIBRARY_PLACEHOLDER: &str = "<path-to-libsofthsm2>";
/// The fallback tool (§5.13 step 3).
const SOFTHSM2_UTIL: &str = "softhsm2-util";
/// The comment line of the textual config append (§5.13; c2 named itself — §11 D7).
const APPEND_COMMENT: &str = "# SoftHSM provider added by the r2 first-run wizard (spec §5.13)";
const LOG_TARGET: &str = "r2::console";
/// Hint of every "cannot create the SoftHSM configuration" error.
const CONF_HINT: &str = "check softhsm.conf_dir / softhsm.token_dir in the configuration";

/// §5.13 trigger: true when no initialized token exists — free SoftHSM slots present as
/// TokenInfo{label: "", serial: ""}; an initialized token always has a label or serial.
pub fn token_needs_init(provider: &dyn Provider) -> r2_core::Result<bool> {
    Ok(!provider
        .list_tokens()?
        .iter()
        .any(|token| !token.label.is_empty() || !token.serial.is_empty()))
}
/// The §5.13 wizard end to end; Ok(None) = the operator declined (nothing touched).
/// Requires `provider.as_token_init()` (else UnsupportedOperation "provider '{name}' cannot
/// initialize tokens"). Step 1 writes the conf (`write_softhsm_conf`); step 2 is
/// `TokenInit::set_env_and_reset(SOFTHSM2_CONF_ENV, conf)` — the wizard never calls set_var
/// itself; when that refuses (shared module) the conf files of step 1 stay written and
/// nothing else changed. `library` = the module path for the reported
/// entry; None → re-detected with `find_softhsm_module(&cfg.softhsm.search_paths)`. Returns
/// the freshly initialized token (exact-label round trip) for the login flow.
pub fn run_softhsm_wizard(
    ctx: &AppContext,
    provider: &dyn Provider,
    library: Option<&Path>,
) -> r2_core::Result<Option<TokenInfo>> {
    let io = &*ctx.io;
    let section = &ctx.cfg().softhsm;
    let name = provider.name();
    let conf_dir = &section.conf_dir;
    let token_dir = &section.token_dir;

    say(
        io,
        format!(
            "Provider '{name}' has no initialized SoftHSM2 token.\n\
             First-run setup will:\n  \
             1. create {} and {}\n  \
             2. write softhsm2.conf there and point ${SOFTHSM2_CONF_ENV} at it\n  \
             3. initialize a token (SO PIN and user PIN prompted hidden)",
            conf_dir.display(),
            token_dir.display()
        ),
    );
    if !io.confirm(&format!("Set up a SoftHSM2 token for '{name}' now?"), true)? {
        say(
            io,
            format!(
                "SoftHSM setup skipped — '{name}' stays listed but unusable until the wizard \
                 is re-run; the memory provider is unaffected."
            ),
        );
        return Ok(None);
    }
    // Checked after the confirm: declining works on any provider (c2 never looked at the
    // provider before step 3), and nothing is touched when the provider cannot init tokens.
    let Some(init) = provider.as_token_init() else {
        return Err(ConsoleError::unsupported(format!(
            "provider '{name}' cannot initialize tokens"
        )));
    };

    // `SOFTHSM2_CONF` and the conf text carry these paths as text; a path that is not
    // valid UTF-8 cannot be passed through losslessly (§11 D12 (q)) — refused up front.
    utf8_path(conf_dir)?;
    utf8_path(token_dir)?;

    // §5.13 step 1: conf/token dirs + softhsm2.conf.
    let conf_path = write_softhsm_conf(conf_dir, token_dir)?;
    tracing::info!(
        target: LOG_TARGET,
        "wizard: wrote {} (tokendir {})",
        conf_path.display(),
        token_dir.display()
    );
    say(io, format!("Wrote {}", conf_path.display()));

    // §5.13 step 2: env BEFORE the module's C_Initialize; the provider resets itself so
    // the next lazy initialize re-reads it (refused when the module is shared, §11 D15).
    init.set_env_and_reset(SOFTHSM2_CONF_ENV, utf8_path(&conf_path)?)?;

    // §5.13 step 3: prompts, then in-process init with the subprocess fallback.
    let label = prompt_label(io)?;
    let so_pin = prompt_pin(io, "SO PIN")?;
    let user_pin = prompt_pin(io, "user PIN")?;
    let slot = free_slot(provider)?;
    if let Err(err) = init.init_token(slot, &label, &so_pin, &user_pin) {
        let Some(util) = which(SOFTHSM2_UTIL) else {
            return Err(err);
        };
        tracing::info!(
            target: LOG_TARGET,
            "wizard: in-process init_token failed ({}) — falling back to softhsm2-util",
            err.message
        );
        say(
            io,
            format!(
                "In-process token init failed ({}) — retrying via softhsm2-util.",
                err.message
            ),
        );
        init_via_softhsm2_util(&util, &label, &so_pin, &user_pin)?;
        // The util changed the slot layout behind the loaded module's back — force a
        // fresh C_Initialize before looking the token up.
        provider.shutdown()?;
    }
    let token = find_token(provider, &label)?;
    tracing::info!(
        target: LOG_TARGET,
        "wizard: initialized token '{}' (slot {})",
        token.label,
        token.slot_id
    );
    say(
        io,
        format!(
            "Token '{}' initialized (slot {}).",
            token.label, token.slot_id
        ),
    );

    // §5.13 step 4: report the provider entry (+ the config-append offer).
    let resolved = match library {
        Some(path) => Some(path.to_path_buf()),
        None => find_softhsm_module(&section.search_paths),
    };
    let entry = provider_config_entry(name, resolved.as_deref(), &conf_path, &token.label);
    say(io, "Provider entry for your configuration:".to_owned());
    say(io, render_config_snippet(&entry));
    if resolved.is_none() {
        say(
            io,
            "The SoftHSM module path could not be re-detected — fill in 'library' by hand \
             before adding the entry to a config file."
                .to_owned(),
        );
    } else if let Some(source) = &ctx.config.source_path {
        let shown = source.display();
        if io.confirm(&format!("Append this provider entry to {shown}?"), true)? {
            append_provider_entry(source, &entry)?;
            tracing::info!(target: LOG_TARGET, "wizard: appended provider entry to {shown}");
            say(io, format!("Updated {shown}."));
        } else {
            say(
                io,
                format!(
                    "{shown} not modified — add the entry above manually to persist the setup."
                ),
            );
        }
    } else {
        say(
            io,
            "No external config file is in use — save the entry above to a config file \
             (see `config path` for the discovery order) to persist the setup."
                .to_owned(),
        );
    }
    Ok(Some(token))
}
/// The exact softhsm2.conf text: "directories.tokendir = {token_dir}\nobjectstore.backend =
/// file\nlog.level = ERROR\n".
pub fn softhsm_conf_text(token_dir: &Path) -> String {
    format!(
        "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
        token_dir.display()
    )
}
/// Create conf_dir + token_dir, write softhsm2.conf; Config "cannot create the SoftHSM
/// configuration: {err}" ({err} = `text::py_os_error_str`, Python's `str(OSError)`; hint
/// "check softhsm.conf_dir / softhsm.token_dir in the configuration").
pub fn write_softhsm_conf(conf_dir: &Path, token_dir: &Path) -> r2_core::Result<PathBuf> {
    let conf_path = conf_dir.join("softhsm2.conf");
    let written = mkdir_parents(conf_dir)
        .and_then(|()| mkdir_parents(token_dir))
        .and_then(|()| {
            write_text(&conf_path, &softhsm_conf_text(token_dir))
                .map_err(|err| (err, conf_path.clone()))
        });
    if let Err((err, path)) = written {
        return Err(ConsoleError::config(format!(
            "cannot create the SoftHSM configuration: {}",
            py_os_error_str(&err, &path)
        ))
        .with_hint(CONF_HINT));
    }
    Ok(conf_path)
}
/// The providers.pkcs11[] entry {name, library (or "<path-to-libsofthsm2>"), token_label,
/// env: {SOFTHSM2_CONF: conf_path}} as a YAML mapping.
pub fn provider_config_entry(
    name: &str,
    library: Option<&Path>,
    conf_path: &Path,
    token_label: &str,
) -> r2_config::yaml::Value {
    let library = library.map_or_else(
        || LIBRARY_PLACEHOLDER.to_owned(),
        |path| path.display().to_string(),
    );
    let mut env = Mapping::new();
    env.insert(
        Value::from(SOFTHSM2_CONF_ENV),
        Value::from(conf_path.display().to_string()),
    );
    let mut entry = Mapping::new();
    entry.insert(Value::from("name"), Value::from(name));
    entry.insert(Value::from("library"), Value::from(library));
    entry.insert(Value::from("token_label"), Value::from(token_label));
    entry.insert(Value::from("env"), Value::Mapping(env));
    Value::Mapping(entry)
}
/// `yaml::dump({"providers": {"pkcs11": [entry]}})` without the trailing newline.
pub fn render_config_snippet(entry: &r2_config::yaml::Value) -> String {
    let mut pkcs11 = Mapping::new();
    pkcs11.insert(Value::from("pkcs11"), Value::Sequence(vec![entry.clone()]));
    let mut root = Mapping::new();
    root.insert(Value::from("providers"), Value::Mapping(pkcs11));
    // c2 `.rstrip()`: every trailing whitespace character.
    yaml::dump(&Value::Mapping(root))
        .trim_end_matches(r2_core::text::is_py_space)
        .to_owned()
}
/// c2's two-shape append (textual block with comment "# SoftHSM provider added by the r2
/// first-run wizard (spec §5.13)" when no `providers` key; else structural rewrite with a
/// `.bak` copy; an existing entry with the same name → Config "provider '{name}' is already
/// defined in {source}" (hint "edit that entry by hand if its settings should change")).
pub fn append_provider_entry(source: &Path, entry: &r2_config::yaml::Value) -> r2_core::Result<()> {
    let shown = source.display();
    let text = read_text(source)?;
    let data = yaml::parse(&text).map_err(|err| {
        ConsoleError::config(format!("cannot parse config file {shown}: {}", err.message))
    })?;
    let mut data = match data {
        Value::Null => Mapping::new(),
        Value::Mapping(map) => map,
        _ => {
            return Err(ConsoleError::config(format!(
                "{shown}: top level is not a mapping"
            )));
        }
    };

    let providers_key = Value::from("providers");
    let Some(providers) = data.get(&providers_key) else {
        // No providers section yet: a commented block appended textually (comments kept).
        let block = format!("\n{APPEND_COMMENT}\n{}\n", render_config_snippet(entry));
        let content = format!("{}\n{block}", text.trim_end_matches('\n'));
        return write_config(source, &content);
    };

    let mut providers = match providers {
        // a bare `providers:` key is an empty section, not an error
        Value::Null => Mapping::new(),
        Value::Mapping(map) => map.clone(),
        _ => {
            return Err(ConsoleError::config(format!(
                "{shown}: 'providers' is not a mapping"
            )));
        }
    };
    let pkcs11_key = Value::from("pkcs11");
    // c2 `providers.get("pkcs11") or []`: any falsy value (a null `pkcs11:` included) is empty.
    let mut instances = match providers.get(&pkcs11_key) {
        None => Vec::new(),
        Some(value) if !py_truthy(value) => Vec::new(),
        Some(Value::Sequence(items)) => items.clone(),
        Some(_) => {
            return Err(ConsoleError::config(format!(
                "{shown}: 'providers.pkcs11' is not a list"
            )));
        }
    };
    let entry_name = entry.get("name").cloned().unwrap_or(Value::Null);
    for existing in &instances {
        if let Value::Mapping(existing) = existing
            && existing.get("name") == Some(&entry_name)
        {
            let name = entry_name.as_str().unwrap_or_default();
            return Err(ConsoleError::config(format!(
                "provider '{name}' is already defined in {shown}"
            ))
            .with_hint("edit that entry by hand if its settings should change"));
        }
    }
    instances.push(entry.clone());
    providers.insert(pkcs11_key, Value::Sequence(instances));
    // reattach — `providers` may be a fresh mapping (the null case); position is kept
    data.insert(providers_key, Value::Mapping(providers));

    let mut backup_name = source.file_name().unwrap_or_default().to_os_string();
    backup_name.push(".bak");
    let backup = source.with_file_name(backup_name);
    copy2(source, &backup).map_err(|err| {
        let detail = match err {
            CopyError::Os(err, path) => py_os_error_str(&err, &path),
            CopyError::SameFile(text) | CopyError::Special(text) => text,
        };
        ConsoleError::config(format!(
            "cannot write backup {}: {detail}",
            backup.display()
        ))
    })?;
    write_config(source, &yaml::dump(&Value::Mapping(data)))
}

// ---------------------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------------------

/// The path as text, or Config "cannot create the SoftHSM configuration: {path} is not
/// valid UTF-8" (c2's surrogateescape str round trip has no lossless r2 equivalent).
fn utf8_path(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| {
        ConsoleError::config(format!(
            "cannot create the SoftHSM configuration: {} is not valid UTF-8",
            path.display()
        ))
        .with_hint(CONF_HINT)
    })
}

fn say(io: &dyn ConsoleIo, text: String) {
    io.print(Renderable::Text(text));
}

/// Token label via the blessed synthetic-STR-ParamSpec pattern (§5.12); empty → the
/// default; longer than 32 UTF-8 bytes → re-asked (§11 D15).
fn prompt_label(io: &dyn ConsoleIo) -> Result<String> {
    let spec = ParamSpec::str(
        "token_label",
        format!("Token label [{DEFAULT_TOKEN_LABEL}]"),
    )
    .optional(Some(ParamValue::Str(DEFAULT_TOKEN_LABEL.to_owned())));
    loop {
        let answer = io.prompt(&spec)?;
        let label = match py_strip(&answer) {
            "" => DEFAULT_TOKEN_LABEL,
            label => label,
        };
        if label.len() <= MAX_LABEL_BYTES {
            return Ok(label.to_owned());
        }
        say(
            io,
            "Token labels are limited to 32 characters (CK_TOKEN_INFO) — use a shorter one."
                .to_owned(),
        );
    }
}

/// Hidden + confirmed PIN prompt (§5.13 step 3); never echoed or logged.
fn prompt_pin(io: &dyn ConsoleIo, what: &str) -> Result<SecretString> {
    for _ in 0..PIN_ATTEMPTS {
        let pin = io.prompt_secret(&format!("New {what}: "))?;
        // c2 `len(pin)`: characters.
        if pin.expose_secret().chars().count() < MIN_PIN_LEN {
            say(
                io,
                format!("{what} must be at least {MIN_PIN_LEN} characters."),
            );
            continue;
        }
        let repeat = io.prompt_secret(&format!("Repeat {what}: "))?;
        if repeat.expose_secret() == pin.expose_secret() {
            return Ok(pin);
        }
        say(io, format!("{what} entries do not match — try again."));
    }
    Err(ConsoleError::user_abort(format!(
        "{what} not confirmed after {PIN_ATTEMPTS} attempts"
    )))
}

/// Slot id of the first uninitialized slot (label == serial == "").
fn free_slot(provider: &dyn Provider) -> Result<u64> {
    provider
        .list_tokens()?
        .iter()
        .find(|token| token.label.is_empty() && token.serial.is_empty())
        .map(|token| token.slot_id)
        .ok_or_else(|| {
            ConsoleError::generic("no free SoftHSM slot available for token initialization")
                .with_hint(format!(
                    "every slot already holds a token — check `slots` and ${SOFTHSM2_CONF_ENV}"
                ))
        })
}

/// The freshly initialized token; init_token guarantees the exact label round trip.
fn find_token(provider: &dyn Provider, label: &str) -> Result<TokenInfo> {
    provider
        .list_tokens()?
        .into_iter()
        .find(|token| token.label == label)
        .ok_or_else(|| {
            ConsoleError::generic(format!("token '{label}' not found after initialization"))
                .with_hint(format!(
                    "the SoftHSM token store looks inconsistent — check ${SOFTHSM2_CONF_ENV}"
                ))
        })
}

/// §5.13 step-3 fallback: `softhsm2-util --init-token` (plain subprocess). Inherits the
/// environment set in step 2 (`SOFTHSM2_CONF`). The command line is never logged — it
/// carries the PINs.
fn init_via_softhsm2_util(
    util: &Path,
    label: &str,
    so_pin: &SecretString,
    user_pin: &SecretString,
) -> Result<()> {
    let failed = |detail: String| {
        ConsoleError::generic(format!("softhsm2-util --init-token failed: {detail}")).with_hint(
            format!("check the SoftHSM2 installation and ${SOFTHSM2_CONF_ENV}"),
        )
    };
    let output = std::process::Command::new(util)
        .args(["--init-token", "--free", "--label", label, "--so-pin"])
        .arg(so_pin.expose_secret())
        .arg("--pin")
        .arg(user_pin.expose_secret())
        .stdin(std::process::Stdio::null())
        .output()
        // c2 let subprocess.run's OSError escape (a crash); r2 reports it (§11 D12 (q)).
        .map_err(|err| failed(py_os_error_str(&err, util)))?;
    if output.status.success() {
        return Ok(());
    }
    // c2 `text=True`: decoded, then universal newlines (`\r\n` / `\r` → `\n`). Output that
    // is not valid UTF-8 (c2: UnicodeDecodeError, a crash) is decoded lossily (§11 D12 (q)).
    let stderr = universal_newlines(&String::from_utf8_lossy(&output.stderr));
    let stdout = universal_newlines(&String::from_utf8_lossy(&output.stdout));
    let detail = match (py_strip(&stderr), py_strip(&stdout)) {
        ("", "") => format!("exit code {}", return_code(&output.status)),
        ("", out) => out.to_owned(),
        (err, _) => err.to_owned(),
    };
    Err(failed(detail))
}

/// Python text-mode newline translation (universal newlines).
fn universal_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// Python's `CompletedProcess.returncode`: the exit code, or −signal when killed.
fn return_code(status: &std::process::ExitStatus) -> i64 {
    if let Some(code) = status.code() {
        return i64::from(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return -i64::from(signal);
        }
    }
    -1
}

/// Python `shutil.which(name)` (3.12): `$PATH` (unset → `CS_PATH` "/bin:/usr/bin" on
/// POSIX; empty → not found), first executable regular file; on Windows the current
/// directory first and the `PATHEXT` extensions. "Executable" approximates Python's
/// `os.access(X_OK)` by any x bit (the real uid/gid and noexec mounts are not consulted —
/// no unsafe/libc here; §11 D12 (q)).
fn which(name: &str) -> Option<PathBuf> {
    let path = match std::env::var_os("PATH") {
        Some(path) => path,
        None if cfg!(windows) => std::ffi::OsString::from("."),
        None => std::ffi::OsString::from("/bin:/usr/bin"),
    };
    if path.is_empty() {
        return None;
    }
    let mut dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
    if cfg!(windows) {
        dirs.insert(0, PathBuf::from("."));
    }
    let names = executable_names(name);
    let mut seen = std::collections::HashSet::new();
    for dir in dirs {
        if !seen.insert(dir.clone()) {
            continue;
        }
        for candidate in &names {
            let full = dir.join(candidate);
            if is_executable_file(&full) {
                return Some(full);
            }
        }
    }
    None
}

#[cfg(windows)]
fn executable_names(name: &str) -> Vec<String> {
    let pathext = std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC".to_owned());
    let exts: Vec<&str> = pathext.split(';').filter(|e| !e.is_empty()).collect();
    let lower = name.to_lowercase();
    if exts.iter().any(|ext| lower.ends_with(&ext.to_lowercase())) {
        vec![name.to_owned()]
    } else {
        exts.iter().map(|ext| format!("{name}{ext}")).collect()
    }
}

#[cfg(not(windows))]
fn executable_names(name: &str) -> Vec<String> {
    vec![name.to_owned()]
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Python truthiness of a loaded YAML value (c2's `x or []`).
fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Sequence(items) => !items.is_empty(),
        Value::Mapping(map) => !map.is_empty(),
        // a date/datetime is always true; `!!binary` bytes are empty only for empty text
        Value::Tagged(tagged) => match &tagged.value {
            Value::String(s) if yaml::python_type_name(value) == "bytes" => !py_strip(s).is_empty(),
            _ => true,
        },
    }
}

/// `Path.mkdir(parents=True, exist_ok=True)`; Err carries the path Python's OSError names.
fn mkdir_parents(path: &Path) -> std::result::Result<(), (std::io::Error, PathBuf)> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // pathlib: the parent of a single relative component is `.` (whose parent is
            // itself) — `Path::parent` gives "" there.
            let parent = match path.parent() {
                Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
                Some(parent) => parent,
                None => return Err((err, path.to_path_buf())),
            };
            if parent == path {
                return Err((err, path.to_path_buf()));
            }
            mkdir_parents(parent)?;
            match std::fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(_) if path.is_dir() => Ok(()),
                Err(err) => Err((err, path.to_path_buf())),
            }
        }
        Err(_) if path.is_dir() => Ok(()),
        Err(err) => Err((err, path.to_path_buf())),
    }
}

/// Python `Path.write_text` (text mode: `\n` → `os.linesep`).
fn write_text(path: &Path, text: &str) -> std::io::Result<()> {
    if cfg!(windows) {
        std::fs::write(path, text.replace('\n', "\r\n"))
    } else {
        std::fs::write(path, text)
    }
}

fn write_config(source: &Path, content: &str) -> Result<()> {
    write_text(source, content).map_err(|err| {
        ConsoleError::config(format!(
            "cannot write config file {}: {}",
            source.display(),
            py_os_error_str(&err, source)
        ))
    })
}

/// Python `Path.read_text(encoding="utf-8")`: universal newlines. An OSError → Config
/// "cannot read config file {source}: {str(err)}"; invalid UTF-8 (c2 crashed with
/// UnicodeDecodeError) → the same message with CPython's UnicodeDecodeError text, as the
/// config loader reports it (§4.8.1, §11 D12 (q)).
fn read_text(source: &Path) -> Result<String> {
    let shown = source.display();
    let bytes = std::fs::read(source).map_err(|err| {
        ConsoleError::config(format!(
            "cannot read config file {shown}: {}",
            py_os_error_str(&err, source)
        ))
    })?;
    let text = String::from_utf8(bytes).map_err(|err| {
        ConsoleError::config(format!(
            "cannot read config file {shown}: {}",
            utf8_error_text(err.as_bytes(), &err.utf8_error())
        ))
    })?;
    Ok(universal_newlines(&text))
}

/// CPython's `UnicodeDecodeError` text for invalid UTF-8 (the loader's wording, §4.8.1).
fn utf8_error_text(bytes: &[u8], error: &std::str::Utf8Error) -> String {
    let start = error.valid_up_to();
    let byte = |index: usize| bytes.get(index).copied().unwrap_or_default();
    match error.error_len() {
        None => {
            let end = bytes.len().saturating_sub(1);
            if end == start {
                format!(
                    "'utf-8' codec can't decode byte 0x{:02x} in position {start}: unexpected \
                     end of data",
                    byte(start)
                )
            } else {
                format!(
                    "'utf-8' codec can't decode bytes in position {start}-{end}: unexpected \
                     end of data"
                )
            }
        }
        Some(len) if len > 1 => format!(
            "'utf-8' codec can't decode bytes in position {start}-{}: invalid continuation byte",
            start + len - 1
        ),
        Some(_) => {
            let first = byte(start);
            let reason = if (0x80..=0xc1).contains(&first) || first >= 0xf5 {
                "invalid start byte"
            } else {
                "invalid continuation byte"
            };
            format!("'utf-8' codec can't decode byte 0x{first:02x} in position {start}: {reason}")
        }
    }
}

/// `shutil.copy2(source, backup)`: a directory destination receives `source`'s file name;
/// the same file (link or symlink) → `shutil.SameFileError`; a named pipe at either path
/// (stat follows links; stat errors ignored) → `shutil.SpecialFileError`, checked before
/// either file is opened (opening a FIFO would block); then content, permission bits
/// and timestamps. Err names the path whose operation failed (source read vs backup
/// write), as Python's OSError does.
fn copy2(source: &Path, backup: &Path) -> std::result::Result<(), CopyError> {
    let joined;
    let backup = if backup.is_dir() {
        joined = backup.join(source.file_name().unwrap_or_default());
        joined.as_path()
    } else {
        backup
    };
    if same_file(source, backup) {
        return Err(CopyError::SameFile(format!(
            "{kind}({}) and {kind}({}) are the same file",
            py_repr(&source.to_string_lossy()),
            py_repr(&backup.to_string_lossy()),
            kind = if cfg!(windows) {
                "WindowsPath"
            } else {
                "PosixPath"
            }
        )));
    }
    for path in [source, backup] {
        if is_fifo(path) {
            return Err(CopyError::Special(format!(
                "`{}` is a named pipe",
                path.display()
            )));
        }
    }
    let os = |path: &Path| {
        let path = path.to_path_buf();
        move |err| CopyError::Os(err, path)
    };
    let mut reader = std::fs::File::open(source).map_err(os(source))?;
    let meta = reader.metadata().map_err(os(source))?;
    let mut writer = std::fs::File::create(backup).map_err(os(backup))?;
    std::io::copy(&mut reader, &mut writer).map_err(os(backup))?;
    let mut times = std::fs::FileTimes::new();
    if let Ok(accessed) = meta.accessed() {
        times = times.set_accessed(accessed);
    }
    if let Ok(modified) = meta.modified() {
        times = times.set_modified(modified);
    }
    writer.set_times(times).map_err(os(backup))?;
    writer
        .set_permissions(meta.permissions())
        .map_err(os(backup))?;
    Ok(())
}

/// A failed `copy2`: Python's `str(err)` is built by the caller from the OSError + path,
/// or is the ready `SameFileError` / `SpecialFileError` text.
enum CopyError {
    Os(std::io::Error, PathBuf),
    SameFile(String),
    Special(String),
}

/// `stat.S_ISFIFO(os.stat(path).st_mode)`, any stat error → false.
#[cfg(unix)]
fn is_fifo(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path).is_ok_and(|meta| meta.file_type().is_fifo())
}

#[cfg(not(unix))]
fn is_fifo(_path: &Path) -> bool {
    false
}

/// `shutil._samefile` → `os.path.samefile`: both stat (following links) and equal
/// (st_dev, st_ino); any stat error → not the same.
#[cfg(unix)]
fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// Windows: the stable std has no file index — canonical paths approximate it.
#[cfg(not(unix))]
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
