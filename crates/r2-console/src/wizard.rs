// R0 skeleton — owner R11 (generated from spec §4)
// ---- spec §4.9.9 block 3
use r2_provider::{Provider, TokenInfo};
use std::path::{Path, PathBuf};

use crate::context::AppContext;

pub const SOFTHSM2_CONF_ENV: &str = "SOFTHSM2_CONF";
/// Label offered when the operator just hits enter (c2: "c2" — §11 D7).
pub const DEFAULT_TOKEN_LABEL: &str = "r2";

/// §5.13 trigger: true when no initialized token exists — free SoftHSM slots present as
/// TokenInfo{label: "", serial: ""}; an initialized token always has a label or serial.
/// R0 stub body (mandated): `Ok(false)` (c2's ImportError fallback: login proceeds normally).
pub fn token_needs_init(provider: &dyn Provider) -> r2_core::Result<bool> {
    let _ = provider;
    Ok(false)
}
/// The §5.13 wizard end to end; Ok(None) = the operator declined (nothing touched).
/// Requires `provider.as_token_init()` (else UnsupportedOperation "provider '{name}' cannot
/// initialize tokens"). Step 1 writes the conf (`write_softhsm_conf`); step 2 is
/// `TokenInit::set_env_and_reset(SOFTHSM2_CONF_ENV, conf)` — the wizard never calls set_var
/// itself; when that refuses (shared module) the conf files of step 1 stay written and
/// nothing else changed. `library` = the module path for the reported
/// entry; None → re-detected with `find_softhsm_module(&cfg.softhsm.search_paths)`. Returns
/// the freshly initialized token (exact-label round trip) for the login flow.
/// R0 stub body (mandated): `Ok(None)`.
pub fn run_softhsm_wizard(
    ctx: &AppContext,
    provider: &dyn Provider,
    library: Option<&Path>,
) -> r2_core::Result<Option<TokenInfo>> {
    let _ = (ctx, provider, library);
    Ok(None)
}
/// The exact softhsm2.conf text: "directories.tokendir = {token_dir}\nobjectstore.backend =
/// file\nlog.level = ERROR\n".
pub fn softhsm_conf_text(token_dir: &Path) -> String {
    let _ = token_dir;
    unimplemented!("R11")
}
/// Create conf_dir + token_dir, write softhsm2.conf; Config "cannot create the SoftHSM
/// configuration: {err}" ({err} = `text::py_os_error_str`, Python's `str(OSError)`; hint
/// "check softhsm.conf_dir / softhsm.token_dir in the configuration").
pub fn write_softhsm_conf(conf_dir: &Path, token_dir: &Path) -> r2_core::Result<PathBuf> {
    let _ = (conf_dir, token_dir);
    Err(r2_core::ConsoleError::not_implemented("R11"))
}
/// The providers.pkcs11[] entry {name, library (or "<path-to-libsofthsm2>"), token_label,
/// env: {SOFTHSM2_CONF: conf_path}} as a YAML mapping.
pub fn provider_config_entry(
    name: &str,
    library: Option<&Path>,
    conf_path: &Path,
    token_label: &str,
) -> r2_config::yaml::Value {
    let _ = (name, library, conf_path, token_label);
    unimplemented!("R11")
}
/// `yaml::dump({"providers": {"pkcs11": [entry]}})` without the trailing newline.
pub fn render_config_snippet(entry: &r2_config::yaml::Value) -> String {
    let _ = entry;
    unimplemented!("R11")
}
/// c2's two-shape append (textual block with comment "# SoftHSM provider added by the r2
/// first-run wizard (spec §5.13)" when no `providers` key; else structural rewrite with a
/// `.bak` copy; an existing entry with the same name → Config "provider '{name}' is already
/// defined in {source}" (hint "edit that entry by hand if its settings should change")).
pub fn append_provider_entry(source: &Path, entry: &r2_config::yaml::Value) -> r2_core::Result<()> {
    let _ = (source, entry);
    Err(r2_core::ConsoleError::not_implemented("R11"))
}
