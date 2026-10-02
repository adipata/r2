//! Provider bootstrap (spec §4.9.11; owner R7) — c2 `app.custom_ckm_map` and
//! `app.build_provider_registry`. Construction never loads a PKCS#11 library (§6): providers
//! initialize lazily on first use.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;

use r2_config::model::{AppConfig, Pkcs11InstanceConfig};
use r2_core::text::py_repr;
use r2_memory::MemoryProvider;
use r2_pkcs11::Pkcs11Provider;
use r2_pkcs11::softhsm::find_softhsm_module;
use r2_provider::{Provider, ProviderRegistry};

/// `{entry.ckm: entry.id}` handed to every Pkcs11Provider (§4.6).
pub fn custom_ckm_map(config: &AppConfig) -> BTreeMap<u64, String> {
    config
        .custom_mechanisms
        .iter()
        .map(|entry| (entry.ckm, entry.id.clone()))
        .collect()
}

/// The constructors the bootstrap calls — the seam c2's tests used by injecting stub
/// provider modules (test_app.py `stub_providers`).
pub(crate) trait ProviderFactory {
    fn memory(&self, name: &str) -> Rc<dyn Provider>;
    /// `custom_attributes` = `config.templates.custom_attributes`.
    fn pkcs11(
        &self,
        name: &str,
        instance: Pkcs11InstanceConfig,
        custom_mechanisms: BTreeMap<u64, String>,
        config: &AppConfig,
    ) -> Rc<dyn Provider>;
    fn find_softhsm(&self, search_paths: &[PathBuf]) -> Option<PathBuf>;
}

/// The real §4.5.5 constructors.
struct RealProviders;
impl ProviderFactory for RealProviders {
    fn memory(&self, name: &str) -> Rc<dyn Provider> {
        Rc::new(MemoryProvider::new(name))
    }
    fn pkcs11(
        &self,
        name: &str,
        instance: Pkcs11InstanceConfig,
        custom_mechanisms: BTreeMap<u64, String>,
        config: &AppConfig,
    ) -> Rc<dyn Provider> {
        Rc::new(Pkcs11Provider::new(
            name,
            instance,
            custom_mechanisms,
            config.templates.custom_attributes.clone(),
        ))
    }
    fn find_softhsm(&self, search_paths: &[PathBuf]) -> Option<PathBuf> {
        find_softhsm_module(search_paths)
    }
}

/// Memory (when enabled), every providers.pkcs11 instance (`Pkcs11Provider::new`), then —
/// ONLY when `softhsm.autodetect` is true — the SoftHSM autodetect instance: skipped with
/// an info log "softhsm autodetect skipped: provider {name!r} already configured" when the
/// name is taken by a registered provider (never an error); else
/// `find_softhsm_module(search_paths)` → `Pkcs11Provider::new(name,
/// Pkcs11InstanceConfig::new(name, path), …)`, or a debug log "softhsm autodetect: no
/// module found in search paths" when it returns None. Never loads a library (§6).
pub fn build_provider_registry(config: &AppConfig) -> r2_core::Result<ProviderRegistry> {
    build_with(config, &RealProviders)
}

pub(crate) fn build_with(
    config: &AppConfig,
    factory: &dyn ProviderFactory,
) -> r2_core::Result<ProviderRegistry> {
    let registry = ProviderRegistry::new();
    if config.providers.memory.enabled {
        registry.register(factory.memory(&config.providers.memory.name))?;
    }
    let ckm_map = custom_ckm_map(config);
    for instance in &config.providers.pkcs11 {
        registry.register(factory.pkcs11(
            &instance.name,
            instance.clone(),
            ckm_map.clone(),
            config,
        ))?;
    }
    if config.softhsm.autodetect {
        let name = config.softhsm.provider_name.as_str();
        let taken = registry
            .all()
            .iter()
            .any(|provider| provider.name() == name);
        if taken {
            // §5.13: the configured instance wins — never a startup error.
            tracing::info!(
                target: "r2::app",
                "softhsm autodetect skipped: provider {} already configured",
                py_repr(name)
            );
        } else {
            match factory.find_softhsm(&config.softhsm.search_paths) {
                None => {
                    tracing::debug!(target: "r2::app", "softhsm autodetect: no module found in search paths");
                }
                Some(module_path) => {
                    registry.register(factory.pkcs11(
                        name,
                        Pkcs11InstanceConfig::new(name, module_path.clone()),
                        ckm_map,
                        config,
                    ))?;
                    tracing::info!(
                        target: "r2::app",
                        "softhsm autodetected at {} -> provider {}",
                        module_path.display(),
                        py_repr(name)
                    );
                }
            }
        }
    }
    Ok(registry)
}

#[cfg(test)]
pub(crate) mod tests {
    //! The port of c2 tests/unit/console/test_app.py's bootstrap cases: c2 injected stub
    //! L4/L5 modules; r2 injects a stub ProviderFactory that builds FakeProviders.
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    use r2_config::loader::config_from_yaml;
    use r2_config::model::{AppConfig, CustomAttributeDef};
    use r2_core::template::AttrKind;
    use r2_testkit::FakeProvider;
    use tracing::Subscriber;
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

    use super::*;

    pub(crate) const CUSTOM_MECH: &str = "
custom_mechanisms:
  - id: vendor.acme.kcv
    verb: sign
    algorithm: aes
    cli_name: acme-kcv
    label: ACME key check value
    ckm: 0x80000A01
    param_struct: raw
    params:
      - {name: rounds, kind: int, prompt: KCV rounds, required: false, default: 1}
";
    const CUSTOM_ATTRS: &str = "
templates:
  custom_attributes:
    CKA_ACME_USAGE: {code: 0x80000101, kind: bytes}
";

    pub(crate) fn make_config(overrides: &str) -> AppConfig {
        config_from_yaml(Some(overrides)).unwrap()
    }

    fn config_with_customs(extra: &str) -> AppConfig {
        make_config(&format!("{CUSTOM_MECH}{CUSTOM_ATTRS}{extra}"))
    }

    /// One recorded Pkcs11Provider construction.
    #[derive(Clone, Debug, PartialEq)]
    pub(crate) struct Pkcs11Record {
        pub(crate) name: String,
        pub(crate) instance: Pkcs11InstanceConfig,
        pub(crate) custom_mechanisms: BTreeMap<u64, String>,
        pub(crate) custom_attributes: Vec<(String, CustomAttributeDef)>,
    }

    /// The stub factory (c2 `stub_providers` fixture).
    #[derive(Default)]
    pub(crate) struct StubProviders {
        pub(crate) softhsm_path: Option<PathBuf>,
        pub(crate) memory_created: RefCell<Vec<String>>,
        pub(crate) memory_instances: RefCell<Vec<Rc<FakeProvider>>>,
        pub(crate) pkcs11_created: RefCell<Vec<Pkcs11Record>>,
        pub(crate) find_calls: RefCell<Vec<Vec<PathBuf>>>,
    }
    impl ProviderFactory for StubProviders {
        fn memory(&self, name: &str) -> Rc<dyn Provider> {
            self.memory_created.borrow_mut().push(name.to_owned());
            let provider = Rc::new(FakeProvider::new(name));
            self.memory_instances
                .borrow_mut()
                .push(Rc::clone(&provider));
            provider
        }
        fn pkcs11(
            &self,
            name: &str,
            instance: Pkcs11InstanceConfig,
            custom_mechanisms: BTreeMap<u64, String>,
            config: &AppConfig,
        ) -> Rc<dyn Provider> {
            self.pkcs11_created.borrow_mut().push(Pkcs11Record {
                name: name.to_owned(),
                instance,
                custom_mechanisms,
                custom_attributes: config
                    .templates
                    .custom_attributes
                    .iter()
                    .map(|(k, v)| (k.clone(), *v))
                    .collect(),
            });
            Rc::new(FakeProvider::new(name).with_type_name("pkcs11"))
        }
        fn find_softhsm(&self, search_paths: &[PathBuf]) -> Option<PathBuf> {
            self.find_calls.borrow_mut().push(search_paths.to_vec());
            self.softhsm_path.clone()
        }
    }

    fn names(registry: &ProviderRegistry) -> Vec<String> {
        registry.all().iter().map(|p| p.name().to_owned()).collect()
    }

    fn pkcs11_instance_overrides() -> &'static str {
        "
providers:
  pkcs11:
    - {name: prodhsm, library: /opt/vendor/p11.so}
softhsm:
  autodetect: false
"
    }

    #[test]
    fn test_custom_ckm_map() {
        assert_eq!(
            custom_ckm_map(&config_with_customs("")),
            BTreeMap::from([(0x8000_0A01, "vendor.acme.kcv".to_owned())])
        );
        assert!(custom_ckm_map(&make_config("")).is_empty());
    }

    #[test]
    fn test_bootstrap_registers_memory_and_pkcs11_with_ckm_map() {
        let stub = StubProviders::default();
        let config = config_with_customs(pkcs11_instance_overrides());
        let registry = build_with(&config, &stub).unwrap();
        assert_eq!(names(&registry), ["mem", "prodhsm"]);
        assert_eq!(*stub.memory_created.borrow(), ["mem"]);
        let created = stub.pkcs11_created.borrow();
        let [record] = created.as_slice() else {
            panic!("{created:?}");
        };
        assert_eq!(record.name, "prodhsm");
        assert_eq!(record.instance, config.providers.pkcs11[0]);
        // the config-defined {ckm: id} map reaches the provider constructor (§4.6)
        assert_eq!(
            record.custom_mechanisms,
            BTreeMap::from([(0x8000_0A01, "vendor.acme.kcv".to_owned())])
        );
        assert_eq!(
            record.custom_attributes,
            [(
                "CKA_ACME_USAGE".to_owned(),
                CustomAttributeDef {
                    code: 0x8000_0101,
                    kind: AttrKind::Bytes
                }
            )]
        );
        assert!(stub.find_calls.borrow().is_empty()); // autodetect off → never probed
    }

    #[test]
    fn test_bootstrap_memory_disabled() {
        let stub = StubProviders::default();
        let config = make_config(
            "providers:\n  memory:\n    enabled: false\nsofthsm:\n  autodetect: false\n",
        );
        let registry = build_with(&config, &stub).unwrap();
        assert!(registry.all().is_empty());
        assert!(stub.memory_created.borrow().is_empty());
    }

    #[test]
    fn test_bootstrap_softhsm_autodetect_registers_provider() {
        let stub = StubProviders {
            softhsm_path: Some(PathBuf::from("/opt/homebrew/lib/softhsm/libsofthsm2.so")),
            ..StubProviders::default()
        };
        let config = config_with_customs("");
        let registry = build_with(&config, &stub).unwrap();
        assert_eq!(names(&registry), ["mem", "softhsm"]);
        let created = stub.pkcs11_created.borrow();
        let [record] = created.as_slice() else {
            panic!("{created:?}");
        };
        assert_eq!(record.name, "softhsm");
        assert_eq!(
            record.instance,
            Pkcs11InstanceConfig::new("softhsm", "/opt/homebrew/lib/softhsm/libsofthsm2.so")
        );
        assert_eq!(
            record.custom_mechanisms,
            BTreeMap::from([(0x8000_0A01, "vendor.acme.kcv".to_owned())])
        );
        // probed with the configured search paths (§5.13)
        assert_eq!(
            *stub.find_calls.borrow(),
            std::slice::from_ref(&config.softhsm.search_paths)
        );
    }

    #[test]
    fn test_bootstrap_softhsm_not_found() {
        let stub = StubProviders::default();
        let registry = build_with(&make_config(""), &stub).unwrap();
        assert_eq!(names(&registry), ["mem"]);
        assert_eq!(stub.find_calls.borrow().len(), 1);
    }

    /// Collects formatted tracing messages (c2 `caplog`).
    #[derive(Clone, Default)]
    pub(crate) struct Capture(pub(crate) Arc<Mutex<Vec<String>>>);
    impl<S: Subscriber> Layer<S> for Capture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            struct V(String);
            impl tracing::field::Visit for V {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = format!("{value:?}");
                    }
                }
            }
            let mut visitor = V(String::new());
            event.record(&mut visitor);
            if let Ok(mut messages) = self.0.lock() {
                messages.push(format!("{} {}", event.metadata().level(), visitor.0));
            }
        }
    }

    #[test]
    fn test_bootstrap_softhsm_name_collision_skips_autodetect() {
        let stub = StubProviders {
            softhsm_path: Some(PathBuf::from("/usr/lib/softhsm/libsofthsm2.so")),
            ..StubProviders::default()
        };
        let config = make_config(
            "providers:\n  pkcs11:\n    - {name: softhsm, library: /opt/custom/softhsm.so}\n",
        );
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let registry =
            tracing::subscriber::with_default(subscriber, || build_with(&config, &stub).unwrap());
        // the configured instance wins; autodetect never probed; no startup error (§5.13)
        assert_eq!(names(&registry), ["mem", "softhsm"]);
        let created = stub.pkcs11_created.borrow();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].instance, config.providers.pkcs11[0]);
        assert!(stub.find_calls.borrow().is_empty());
        let messages = capture.0.lock().unwrap().clone();
        assert!(messages.iter().any(|m| m.contains("autodetect skipped")));
        assert!(messages.contains(
            &"INFO softhsm autodetect skipped: provider 'softhsm' already configured".to_owned()
        ));
    }

    #[test]
    fn duplicate_provider_names_are_startup_errors() {
        // the config loader already refuses them; the registry check is the backstop
        struct Same;
        impl ProviderFactory for Same {
            fn memory(&self, _name: &str) -> Rc<dyn Provider> {
                Rc::new(FakeProvider::new("x"))
            }
            fn pkcs11(
                &self,
                _name: &str,
                _instance: Pkcs11InstanceConfig,
                _ckm: BTreeMap<u64, String>,
                _config: &AppConfig,
            ) -> Rc<dyn Provider> {
                Rc::new(FakeProvider::new("x"))
            }
            fn find_softhsm(&self, _paths: &[PathBuf]) -> Option<PathBuf> {
                None
            }
        }
        let config = make_config(pkcs11_instance_overrides());
        let err = build_with(&config, &Same).err().unwrap();
        assert_eq!(err.message, "provider 'x' is already registered");
    }
}
