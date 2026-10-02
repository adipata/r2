// SoftHSM first-run wizard against a real SoftHSM2 module (spec §5.13; R11) — the port of
// c2 tests/integration/test_wizard.py. Feature `softhsm`; fails (never skips) without the
// fixture of `scripts/softhsm-init.sh`.
//
// Every test runs against a FRESH conf/token dir — never the shared fixture token (the
// fixture only provides the module path). SOFTHSM2_CONF first points at an EMPTY token
// store (a first run: `token_needs_init` is true); the wizard then re-points it at its own
// conf through the provider's audited `set_var` site. The `set_env` guard taken first
// restores the fixture's value when the test ends, after the provider was shut down
// (C_Finalize) — nextest runs each test in its own process, and the global-state lock keeps
// the `cargo test` fallback from sharing the module between tests.
#![cfg(feature = "softhsm")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::{AppConfig, Pkcs11InstanceConfig};
use r2_core::error::{ConsoleError, Result};
use r2_core::io::ConsoleIo;
use r2_core::keys::{KeyAlgorithm, KeyInfo, KeyMaterial};
use r2_core::params::{ParamValue, Params};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_pkcs11::Pkcs11Provider;
use r2_provider::{
    AuthState, DeriveResult, GenerateRequest, KeySelector, MechanismInvocation, Provider,
    ProviderStatus, TokenInfo, TokenInit,
};
use r2_testkit::softhsm::softhsm_token;
use r2_testkit::{EnvGuard, ScriptedIo, global_state_lock, set_env};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::context::AppContext;
use crate::testing::{CtxBuilder, make_config};
use crate::wizard;

const WIZ_SO_PIN: &str = "so-wiz-1";
const WIZ_USER_PIN: &str = "user-wiz-1";

/// c2's `wiz` fixture: a virgin SoftHSM environment with an empty pre-wizard token store
/// and fresh wizard dirs.
struct WizardEnv {
    provider: Pkcs11Provider,
    config: AppConfig,
    module_path: PathBuf,
    conf_dir: PathBuf,
    token_dir: PathBuf,
    // drop order: the provider is shut down explicitly by `finish`; then the env guard
    // restores SOFTHSM2_CONF, then the temp dir goes, then the lock is released
    _conf_guard: EnvGuard,
    _dir: tempfile::TempDir,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl WizardEnv {
    fn new() -> Self {
        let lock = global_state_lock();
        let fixture = softhsm_token();
        let dir = tempfile::tempdir().unwrap();
        let pre_tokens = dir.path().join("pre-tokens");
        std::fs::create_dir(&pre_tokens).unwrap();
        let pre_conf = dir.path().join("pre-softhsm2.conf");
        std::fs::write(
            &pre_conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
                pre_tokens.display()
            ),
        )
        .unwrap();
        let conf_guard = set_env(wizard::SOFTHSM2_CONF_ENV, Some(pre_conf.to_str().unwrap()));

        let conf_dir = dir.path().join("wizard-conf");
        let token_dir = dir.path().join("wizard-tokens");
        let config = make_config(Some(&format!(
            "softhsm:\n  conf_dir: '{}'\n  token_dir: '{}'\n",
            conf_dir.display(),
            token_dir.display()
        )));
        let provider = Pkcs11Provider::new(
            "softhsm",
            Pkcs11InstanceConfig::new("softhsm", fixture.module_path.clone()),
            BTreeMap::new(),
            IndexMap::new(),
        );
        Self {
            provider,
            config,
            module_path: fixture.module_path.clone(),
            conf_dir,
            token_dir,
            _conf_guard: conf_guard,
            _dir: dir,
            _lock: lock,
        }
    }
    fn answers(label: &str) -> Vec<String> {
        [
            "y",
            label,
            WIZ_SO_PIN,
            WIZ_SO_PIN,
            WIZ_USER_PIN,
            WIZ_USER_PIN,
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    }
    fn ctx(&self, io: &Rc<ScriptedIo>) -> Rc<AppContext> {
        CtxBuilder::new(Rc::clone(io) as Rc<dyn ConsoleIo>)
            .config(self.config.clone())
            .providers(r2_provider::ProviderRegistry::new())
            .build()
    }
}

impl Drop for WizardEnv {
    fn drop(&mut self) {
        // C_Finalize before SOFTHSM2_CONF is restored
        let _ = self.provider.shutdown();
    }
}

fn pin(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

/// Session object: dies with the session — no on-token litter.
fn session_template() -> KeyTemplate {
    KeyTemplate::new(vec![
        TemplateAttr::new("CKA_TOKEN", AttrKind::Bool, AttrValue::Bool(false)),
        TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(false)),
        TemplateAttr::new("CKA_EXTRACTABLE", AttrKind::Bool, AttrValue::Bool(true)),
    ])
}

fn token_dir_has_files(dir: &Path) -> bool {
    std::fs::read_dir(dir).unwrap().next().is_some()
}

fn generate_session_aes(provider: &dyn Provider) -> KeyInfo {
    let mut request = GenerateRequest::new(KeyAlgorithm::Aes, "wiz-aes");
    request.size_bits = Some(256);
    request.template = Some(session_template());
    provider.generate_key(&request).unwrap()
}

#[test]
fn softhsm_wizard_yields_working_provider() {
    let wiz = WizardEnv::new();
    let provider = &wiz.provider;

    // First-run trigger: the pre-wizard store has only a free slot
    // (TokenInfo{label: "", serial: ""}).
    assert!(wizard::token_needs_init(provider).unwrap());

    let io = Rc::new(ScriptedIo::new(WizardEnv::answers("WIZTOKEN")));
    let token =
        wizard::run_softhsm_wizard(&wiz.ctx(&io), provider, Some(&wiz.module_path)).unwrap();

    // exact label round trip through list_tokens (§4.5 init_token guarantee)
    let token = token.unwrap();
    assert_eq!(token.label, "WIZTOKEN");

    // §5.13 steps 1+2: conf written, env re-pointed, token files created.
    let conf_path = wiz.conf_dir.join("softhsm2.conf");
    assert_eq!(
        std::fs::read_to_string(&conf_path).unwrap(),
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            wiz.token_dir.display()
        )
    );
    assert_eq!(
        std::env::var_os(wizard::SOFTHSM2_CONF_ENV).unwrap(),
        conf_path.as_os_str()
    );
    assert!(
        token_dir_has_files(&wiz.token_dir),
        "SoftHSM wrote no token files into the wizard token dir"
    );
    assert!(!wizard::token_needs_init(provider).unwrap());

    // The §5.13 step-4 report names the module and the conf.
    let joined = io.text();
    assert!(joined.contains(&wiz.module_path.display().to_string()));
    assert!(joined.contains(&conf_path.display().to_string()));
    // PINs are never echoed.
    assert!(!joined.contains(WIZ_SO_PIN));
    assert!(!joined.contains(WIZ_USER_PIN));

    // "Yields a working provider": login by the returned token, mechanisms advertised,
    // and a fresh session key generated on the new token.
    provider.login(&token, &pin(WIZ_USER_PIN), false).unwrap();
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
    let mechanisms = provider.mechanisms();
    assert!(mechanisms.contains("AES-CBC") && mechanisms.contains("AES-GCM"));
    let info = generate_session_aes(provider);
    assert_eq!(info.key_ref.label, "wiz-aes");
}

#[test]
#[ignore = "needs R5b's Pkcs11Provider::encrypt/decrypt (merge checklist: drop this ignore when R11 merges after R5b)"]
fn softhsm_wizard_token_round_trips_aes_gcm() {
    // The GCM round trip of c2's test_wizard_yields_working_provider.
    let wiz = WizardEnv::new();
    let provider = &wiz.provider;
    let io = Rc::new(ScriptedIo::new(WizardEnv::answers("WIZTOKEN")));
    let token = wizard::run_softhsm_wizard(&wiz.ctx(&io), provider, Some(&wiz.module_path))
        .unwrap()
        .unwrap();
    provider.login(&token, &pin(WIZ_USER_PIN), false).unwrap();
    let info = generate_session_aes(provider);
    let iv = [0x5au8; 12]; // a fresh session key per run: a fixed IV never repeats a pair
    let mut params = Params::new();
    params.insert("iv".to_owned(), ParamValue::Bytes(iv.to_vec()));
    params.insert("aad".to_owned(), ParamValue::Bytes(Vec::new()));
    params.insert("tag_bits".to_owned(), ParamValue::Enum("128".to_owned()));
    let mech = MechanismInvocation::new("AES-GCM", params);
    let ciphertext = provider.encrypt(&info, &mech, b"wizard payload").unwrap();
    assert_eq!(
        provider
            .decrypt(&info, &mech, &ciphertext)
            .unwrap()
            .as_slice(),
        b"wizard payload"
    );
}

/// c2 monkeypatched `provider.init_token` to raise; r2 wraps the real provider and fails
/// its in-process init (everything else, set_env_and_reset included, is the real thing).
struct BrokenInit<'a>(&'a Pkcs11Provider);

impl TokenInit for BrokenInit<'_> {
    fn init_token(
        &self,
        _slot: u64,
        _label: &str,
        _so_pin: &SecretString,
        _user_pin: &SecretString,
    ) -> Result<()> {
        Err(ConsoleError::pkcs11(
            "simulated in-process init failure (CKR_GENERAL_ERROR)",
            0x05,
            "CKR_GENERAL_ERROR",
        ))
    }
    fn set_env_and_reset(&self, key: &str, value: &str) -> Result<()> {
        TokenInit::set_env_and_reset(self.0, key, value)
    }
}

impl Provider for BrokenInit<'_> {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn type_name(&self) -> &str {
        self.0.type_name()
    }
    fn initialize(&self) -> Result<()> {
        self.0.initialize()
    }
    fn shutdown(&self) -> Result<()> {
        self.0.shutdown()
    }
    fn status(&self) -> ProviderStatus {
        self.0.status()
    }
    fn list_tokens(&self) -> Result<Vec<TokenInfo>> {
        self.0.list_tokens()
    }
    fn login(&self, token: &TokenInfo, pin: &SecretString, keep_pin: bool) -> Result<()> {
        self.0.login(token, pin, keep_pin)
    }
    fn logout(&self) -> Result<()> {
        self.0.logout()
    }
    fn mechanisms(&self) -> BTreeSet<String> {
        self.0.mechanisms()
    }
    fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        self.0.list_keys()
    }
    fn find_key(&self, selector: &KeySelector) -> Result<KeyInfo> {
        self.0.find_key(selector)
    }
    fn import_key(
        &self,
        material: &KeyMaterial,
        label: &str,
        template: Option<&KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> Result<KeyInfo> {
        self.0.import_key(material, label, template, key_id)
    }
    fn generate_key(&self, request: &GenerateRequest) -> Result<KeyInfo> {
        self.0.generate_key(request)
    }
    fn delete_key(&self, key: &KeyInfo) -> Result<()> {
        self.0.delete_key(key)
    }
    fn export_key(&self, key: &KeyInfo) -> Result<KeyMaterial> {
        self.0.export_key(key)
    }
    fn encrypt(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>> {
        self.0.encrypt(key, mech, data)
    }
    fn decrypt(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.0.decrypt(key, mech, data)
    }
    fn sign(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>> {
        self.0.sign(key, mech, data)
    }
    fn verify(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        self.0.verify(key, mech, data, signature)
    }
    fn derive(&self, key: &KeyInfo, mech: &MechanismInvocation) -> Result<DeriveResult> {
        self.0.derive(key, mech)
    }
    fn as_token_init(&self) -> Option<&dyn TokenInit> {
        Some(self)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self.0
    }
}

#[test]
fn softhsm_wizard_falls_back_to_softhsm2_util() {
    // In-process init_token fails → the real `softhsm2-util --init-token` runs.
    let wiz = WizardEnv::new();
    let provider = BrokenInit(&wiz.provider);

    let io = Rc::new(ScriptedIo::new(WizardEnv::answers("WIZUTIL")));
    let token = wizard::run_softhsm_wizard(&wiz.ctx(&io), &provider, Some(&wiz.module_path))
        .unwrap()
        .unwrap();

    assert_eq!(token.label, "WIZUTIL");
    assert!(
        io.output()
            .iter()
            .any(|line| line.contains("softhsm2-util"))
    );
    assert!(token_dir_has_files(&wiz.token_dir));

    // The token initialized by the external util is fully usable in-process.
    provider.login(&token, &pin(WIZ_USER_PIN), false).unwrap();
    assert_eq!(provider.status().auth, AuthState::LoggedIn);
    assert!(provider.mechanisms().contains("AES-GCM"));
}

#[test]
fn softhsm_wizard_refuses_a_shared_module_and_keeps_the_conf() {
    // §11 D15 (a): another provider holds the same module → set_env_and_reset refuses;
    // the step-1 files stay, the environment and the module are untouched.
    let wiz = WizardEnv::new();
    let other = Pkcs11Provider::new(
        "other",
        Pkcs11InstanceConfig::new("other", wiz.module_path.clone()),
        BTreeMap::new(),
        IndexMap::new(),
    );
    other.initialize().unwrap();
    wiz.provider.initialize().unwrap();
    let before = std::env::var_os(wizard::SOFTHSM2_CONF_ENV);

    let io = Rc::new(ScriptedIo::new(["y"]));
    let err = wizard::run_softhsm_wizard(&wiz.ctx(&io), &wiz.provider, Some(&wiz.module_path))
        .unwrap_err();

    assert_eq!(
        err.message,
        "'softhsm' shares its PKCS#11 module with another provider"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("restart r2 after the setup, or remove the other provider entry")
    );
    assert!(wiz.conf_dir.join("softhsm2.conf").is_file());
    assert_eq!(std::env::var_os(wizard::SOFTHSM2_CONF_ENV), before);
    // the shared module still serves the other provider
    assert!(other.list_tokens().is_ok());
    other.shutdown().unwrap();
}
