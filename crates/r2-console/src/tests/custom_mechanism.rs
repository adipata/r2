// Config-defined custom PKCS#11 mechanisms end-to-end at command level (spec §5.14; owner
// R13) — the port of the FakeProvider half of c2 tests/integration/test_custom_mechanism.py.
// The SoftHSM half (`test_custom_ckm_passthrough_on_softhsm`) drives the real binary:
// r2-cli tests/e2e_custom_mechanism.rs.
//
// c2's RecordingFake (a FakeProvider subclass capturing every MechanismInvocation) is a
// FakeHooks observer here (§4.10.2); c2 dispatched through the command objects
// (`bind_args` + `run`), r2 through `run_line` (the same tokenize/bind/run path).
use std::cell::RefCell;
use std::rc::Rc;

use r2_core::io::ConsoleIo;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::{ParamStruct, ParamValue, Verb};
use r2_ops::build_operation_registry;
use r2_provider::{MechanismInvocation, Provider, ProviderRegistry};
use r2_testkit::{FakeHooks, FakeProvider, ScriptedIo};

use crate::testing::{CtxBuilder, make_config, run_line};

/// c2 `_KCV_ENTRY`, as a user config file would carry it.
const KCV_ENTRY: &str = "custom_mechanisms:
  - id: vendor.acme.kcv
    verb: sign
    algorithm: aes
    cli_name: acme-kcv
    label: ACME key check value
    ckm: 0x80000A01
    param_struct: raw
    params:
      - name: rounds
        kind: int
        prompt: KCV rounds
        required: false
        default: 1
";

/// c2 RecordingFake: captures full MechanismInvocations of `sign`.
#[derive(Default)]
struct RecordingSign {
    invocations: RefCell<Vec<MechanismInvocation>>,
}

impl FakeHooks for RecordingSign {
    fn sign(
        &self,
        _next: &dyn Provider,
        _key: &KeyInfo,
        mech: &MechanismInvocation,
        _data: &[u8],
    ) -> Option<r2_core::Result<Vec<u8>>> {
        self.invocations.borrow_mut().push(mech.clone());
        None
    }
}

fn aes_material(data: Vec<u8>) -> KeyMaterial {
    KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, data)
}

#[test]
fn test_custom_mechanism_ops_row_and_dispatch_with_prompts() {
    // answers: mechparam prompt (rounds has a default and is not prompted)
    let io = Rc::new(ScriptedIo::new(["0xa1b2"]));
    let recorder = Rc::new(RecordingSign::default());
    // the token "advertises" the vendor CKM: its op id is in mechanisms()
    let hsm = Rc::new(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .with_mechanisms(["AES-CBC", "vendor.acme.kcv"])
            .with_hooks(Rc::clone(&recorder) as Rc<dyn FakeHooks>),
    );
    hsm.import_key(&aes_material((0u8..16).collect()), "aeskey", None, None)
        .unwrap();
    let providers = ProviderRegistry::new();
    providers
        .register(Rc::clone(&hsm) as Rc<dyn Provider>)
        .unwrap();
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .config(make_config(Some(KCV_ENTRY)))
        .providers(providers)
        .build();

    // appears in `ops` for the advertising provider (§5.14)
    run_line(&ctx, "ops hsm").unwrap();
    let rendered = io.text();
    assert!(rendered.contains("acme-kcv"), "{rendered}");
    assert!(rendered.contains("vendor.acme.kcv"), "{rendered}");
    assert!(rendered.contains("ACME key check value"), "{rendered}");
    assert!(
        rendered.contains("rounds") && rendered.contains("mechparam"),
        "{rendered}"
    ); // params listed

    // dispatches: inline rounds=, prompted mechparam (§4.6 implicit raw param)
    run_line(&ctx, "sign hsm:aeskey acme-kcv rounds=3 0xdeadbeef").unwrap();
    assert!(
        io.prompts()
            .iter()
            .any(|p| p == "Raw mechanism parameter bytes"),
        "{:?}",
        io.prompts()
    );
    let invocations = recorder.invocations.borrow();
    let mech = invocations
        .last()
        .expect("custom op never reached the provider");
    assert_eq!(mech.mechanism, "vendor.acme.kcv");
    assert_eq!(mech.raw_ckm, Some(0x8000_0A01));
    assert_eq!(mech.param_struct, ParamStruct::Raw);
    assert_eq!(mech.raw_param_bytes.as_deref(), Some(&[0xa1, 0xb2][..]));
    assert_eq!(mech.params.get("rounds"), Some(&ParamValue::Int(3)));
    // pkcs11-mode FakeProvider appends counter CKA_IDs to refs (§4.10)
    assert!(
        hsm.calls()
            .iter()
            .any(|call| call[0] == "sign" && call[2] == "vendor.acme.kcv" && call[3] == "4B"),
        "{:?}",
        hsm.calls()
    );
}

#[test]
fn test_custom_mechanism_hidden_without_token_support() {
    // §5.14: the op only shows for providers whose token advertises the CKM.
    let config = make_config(Some(KCV_ENTRY));
    let operations = build_operation_registry(&config.custom_mechanisms).unwrap();
    let bare = FakeProvider::new("bare")
        .with_type_name("pkcs11")
        .with_mechanisms(["AES-CBC"]);
    let key = bare
        .import_key(&aes_material(vec![0; 16]), "aeskey", None, None)
        .unwrap();
    let specs = operations.available_for(Verb::Sign, &key, &bare);
    assert!(!specs.iter().any(|spec| spec.mechanism == "vendor.acme.kcv"));
    // ...while a token that advertises it does list it (the positive twin)
    let advertising = FakeProvider::new("adv")
        .with_type_name("pkcs11")
        .with_mechanisms(["AES-CBC", "vendor.acme.kcv"]);
    let key = advertising
        .import_key(&aes_material(vec![0; 16]), "aeskey", None, None)
        .unwrap();
    assert!(
        operations
            .available_for(Verb::Sign, &key, &advertising)
            .iter()
            .any(|spec| spec.mechanism == "vendor.acme.kcv")
    );
}
