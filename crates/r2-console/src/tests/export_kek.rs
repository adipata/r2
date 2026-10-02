// `export --kek` command tests (§5.6 wrapped export) — port of c2
// tests/unit/console/test_export_kek.py (R15), plus the export → load round-trips of the
// R15 Accept list. FakeProvider + ScriptedIo throughout (§4.10): FakeProvider's
// wrap/unwrap is a reversible transform, so a blob written by the command can be
// unwrapped back through the provider to prove its content.
use std::path::Path;
use std::rc::Rc;

use r2_core::codec::decode_data;
use r2_core::error::{ConsoleError, ErrorKind};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::Params;
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_provider::{
    GenerateRequest, KeySelector, MechanismInvocation, Provider, ProviderRegistry, UnwrapRequest,
};
use r2_testkit::{FakeProvider, ScriptedIo};

use super::keys_cmd_support::{ctx_with, make_pair, rsa_cert_der, rsa_pkcs8_der, rsa_spki_der};
use crate::commands::all_commands;
use crate::context::AppContext;
use crate::testing::run_line;

const TARGET: [u8; 32] = [0xab; 32];

fn aes_32() -> Vec<u8> {
    (0u8..32).collect()
}

fn iv12_hex() -> String {
    (0u8..12).map(|b| format!("{b:02x}")).collect()
}

fn aes_material(data: &[u8]) -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, data.to_vec());
    material.size_bits = Some(u32::try_from(data.len() * 8).unwrap());
    material
}

fn import_aes(
    provider: &dyn Provider,
    label: &str,
    data: &[u8],
    template: Option<&KeyTemplate>,
) -> KeyInfo {
    provider
        .import_key(&aes_material(data), label, template, None)
        .unwrap()
}

fn import_rsa_public(provider: &dyn Provider, label: &str) -> KeyInfo {
    let mut material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Public, rsa_spki_der());
    material.size_bits = Some(2048);
    provider.import_key(&material, label, None, None).unwrap()
}

fn policy(sensitive: bool, extractable: bool) -> KeyTemplate {
    KeyTemplate::new(vec![
        TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(sensitive)),
        TemplateAttr::new(
            "CKA_EXTRACTABLE",
            AttrKind::Bool,
            AttrValue::Bool(extractable),
        ),
    ])
}

fn generate_pair(provider: &dyn Provider, label: &str) {
    let mut request = GenerateRequest::new(KeyAlgorithm::Rsa, label);
    request.size_bits = Some(2048);
    provider.generate_key(&request).unwrap();
}

/// Round the blob back through the provider to recover the plaintext.
fn unwrap_back(provider: &dyn Provider, kek: &KeyInfo, blob: &[u8], mechanism: &str) -> Vec<u8> {
    let info = provider
        .unwrap_key(
            kek,
            &MechanismInvocation::new(mechanism, Params::new()),
            blob,
            &UnwrapRequest::new(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                format!("roundtrip-{}", mechanism.to_lowercase()),
            ),
        )
        .unwrap();
    provider.export_key(&info).unwrap().data.to_vec()
}

fn calls_of(provider: &FakeProvider, method: &str) -> Vec<Vec<String>> {
    provider
        .calls()
        .into_iter()
        .filter(|call| call[0] == method)
        .collect()
}

fn complete(ctx: &AppContext, tokens: &[&str], cursor: &str) -> Vec<String> {
    let commands = all_commands().unwrap();
    let tokens: Vec<String> = tokens.iter().map(|t| (*t).to_owned()).collect();
    commands["export"].complete(ctx, &tokens, cursor)
}

fn hint(err: &ConsoleError) -> &str {
    err.hint.as_deref().unwrap_or("")
}

fn at(dir: &Path, name: &str) -> String {
    dir.join(name).display().to_string()
}

// ---------------------------------------------------------------------------------------
// happy paths
// ---------------------------------------------------------------------------------------

#[test]
fn test_wrapped_export_writes_a_loadable_blob() {
    let p = make_pair(&[]);
    let kek = import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("wrapped.bin");
    run_line(
        &p.ctx,
        &format!("export mem:target {} --kek kek --mech kwp", out.display()),
    )
    .unwrap();
    let blob = std::fs::read(&out).unwrap();
    assert_eq!(
        unwrap_back(p.mem.as_ref(), &kek, &blob, "AES-KEY-WRAP-PAD"),
        TARGET
    );
    let text = p.io.text();
    assert!(
        text.contains("wrapped under mem:kek with AES-KEY-WRAP-PAD"),
        "{text}"
    );
    assert_eq!(
        p.io.output(),
        [format!(
            "wrote {}: {}-byte blob wrapped under mem:kek with AES-KEY-WRAP-PAD",
            out.display(),
            blob.len()
        )]
    );
}

#[test]
fn test_outformat_encodings() {
    for outformat in ["raw", "hex", "b64"] {
        let p = make_pair(&[]);
        let kek = import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
        import_aes(p.mem.as_ref(), "target", &TARGET, None);
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join(format!("wrapped.{outformat}"));
        run_line(
            &p.ctx,
            &format!(
                "export mem:target {} --kek kek --mech kwp --outformat {outformat}",
                out.display()
            ),
        )
        .unwrap();
        let written = std::fs::read(&out).unwrap();
        let blob = match outformat {
            "raw" => written,
            "hex" => {
                let text = String::from_utf8(written).unwrap();
                assert!(text.ends_with('\n'));
                r2_core::text::py_fromhex(text.trim()).unwrap()
            }
            _ => {
                let text = String::from_utf8(written).unwrap();
                assert!(text.ends_with('\n'));
                decode_data(&format!("b64:{}", text.trim()))
                    .unwrap()
                    .0
                    .to_vec()
            }
        };
        assert_eq!(
            unwrap_back(p.mem.as_ref(), &kek, &blob, "AES-KEY-WRAP-PAD"),
            TARGET,
            "{outformat}"
        );
    }
}

#[test]
fn test_mech_params_travel_as_name_value_tokens() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    run_line(
        &p.ctx,
        &format!(
            "export mem:target {} --kek kek --mech gcm iv=0x{} tag_bits=128",
            at(dir.path(), "wrapped.bin"),
            iv12_hex()
        ),
    )
    .unwrap();
    let call = &calls_of(&p.mem, "wrap_key")[0];
    assert_eq!(call[2], "AES-GCM");
}

#[test]
fn test_private_key_wraps_as_pkcs8() {
    let p = make_pair(&[]);
    let kek = import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    let mut material = KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, rsa_pkcs8_der());
    material.size_bits = Some(2048);
    p.mem.import_key(&material, "rsakey", None, None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("wrapped.bin");
    run_line(
        &p.ctx,
        &format!("export mem:rsakey {} --kek kek --mech kwp", out.display()),
    )
    .unwrap();
    let info = p
        .mem
        .unwrap_key(
            &kek,
            &MechanismInvocation::new("AES-KEY-WRAP-PAD", Params::new()),
            &std::fs::read(&out).unwrap(),
            &UnwrapRequest::new(KeyAlgorithm::Rsa, KeyClass::Private, "back"),
        )
        .unwrap();
    assert_eq!(*p.mem.export_key(&info).unwrap().data, rsa_pkcs8_der());
}

#[test]
fn test_rsa_public_kek_with_explicit_selector() {
    let p = make_pair(&[]);
    generate_pair(p.mem.as_ref(), "pair");
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    run_line(
        &p.ctx,
        &format!(
            "export mem:target {} --kek pair:pub --mech oaep",
            at(dir.path(), "wrapped.bin")
        ),
    )
    .unwrap();
    let public = p
        .mem
        .find_key(&KeySelector::label("pair").with_class(Some(KeyClass::Public)))
        .unwrap();
    let call = &calls_of(&p.mem, "wrap_key")[0];
    assert_eq!(call[1], public.key_ref.display());
}

#[test]
fn test_certificate_kek_is_accepted() {
    // §4.3: a certificate stands in wherever a public key is accepted.
    let p = make_pair(&[]);
    p.mem
        .import_key(
            &KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, rsa_cert_der()),
            "trust",
            None,
            None,
        )
        .unwrap();
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("wrapped.bin");
    run_line(
        &p.ctx,
        &format!(
            "export mem:target {} --kek trust --mech pkcs1",
            out.display()
        ),
    )
    .unwrap();
    assert!(!std::fs::read(&out).unwrap().is_empty());
}

// ---------------------------------------------------------------------------------------
// the §5.6 headline: sensitive-but-extractable keys leave wrapped
// ---------------------------------------------------------------------------------------

#[test]
fn test_sensitive_but_extractable_key_exports_wrapped() {
    let p = make_pair(&[]);
    let kek = import_aes(p.hsm.as_ref(), "kek", &aes_32(), Some(&policy(false, true)));
    let target = import_aes(p.hsm.as_ref(), "target", &TARGET, Some(&policy(true, true)));
    assert!(!target.exportable, "§5.6 plain export would refuse");

    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain.bin");
    let err = run_line(&p.ctx, &format!("export hsm:target {}", plain.display())).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(
        err.message.contains("Refusing to export"),
        "{}",
        err.message
    );
    assert!(!plain.exists());

    let wrapped = dir.path().join("wrapped.bin");
    run_line(
        &p.ctx,
        &format!(
            "export hsm:target {} --kek kek --mech kwp",
            wrapped.display()
        ),
    )
    .unwrap();
    assert_eq!(
        unwrap_back(
            p.hsm.as_ref(),
            &kek,
            &std::fs::read(&wrapped).unwrap(),
            "AES-KEY-WRAP-PAD"
        ),
        TARGET
    );
}

#[test]
fn test_plain_refusal_hint_points_at_kek() {
    let p = make_pair(&[]);
    import_aes(p.hsm.as_ref(), "target", &TARGET, Some(&policy(true, true)));
    let dir = tempfile::tempdir().unwrap();
    let err = run_line(
        &p.ctx,
        &format!("export hsm:target {}", at(dir.path(), "x.bin")),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(hint(&err).contains("--kek"), "{}", hint(&err));
}

#[test]
fn test_non_extractable_key_is_refused_in_both_forms() {
    let p = make_pair(&[]);
    import_aes(p.hsm.as_ref(), "kek", &aes_32(), Some(&policy(false, true)));
    import_aes(
        p.hsm.as_ref(),
        "locked",
        &TARGET,
        Some(&policy(true, false)),
    );
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("wrapped.bin");
    let err = run_line(
        &p.ctx,
        &format!("export hsm:locked {} --kek kek --mech kwp", out.display()),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(err.message.contains("not extractable"), "{}", err.message);
    assert!(!out.exists());
    // and the plain form (r2: the "both forms" of the test name)
    let err = run_line(&p.ctx, &format!("export hsm:locked {}", out.display())).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(!out.exists());
    assert!(calls_of(&p.hsm, "wrap_key").is_empty());
}

// ---------------------------------------------------------------------------------------
// interactive fallbacks
// ---------------------------------------------------------------------------------------

#[test]
fn test_omitted_mech_opens_the_select_menu() {
    let p = make_pair(&["kwp — AES key wrap with padding (RFC 5649)"]);
    let kek = import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("wrapped.bin");
    run_line(
        &p.ctx,
        &format!("export mem:target {} --kek kek", out.display()),
    )
    .unwrap();
    assert_eq!(
        unwrap_back(
            p.mem.as_ref(),
            &kek,
            &std::fs::read(&out).unwrap(),
            "AES-KEY-WRAP-PAD"
        ),
        TARGET
    );
}

#[test]
fn test_omitted_param_is_prompted() {
    let answer = format!("0x{}", iv12_hex());
    let p = make_pair(&[answer.as_str()]);
    import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    run_line(
        &p.ctx,
        &format!(
            "export mem:target {} --kek kek --mech gcm",
            at(dir.path(), "w.bin")
        ),
    )
    .unwrap();
    assert_eq!(p.io.prompts(), ["IV / nonce (12 bytes typical)"]);
}

// ---------------------------------------------------------------------------------------
// error paths
// ---------------------------------------------------------------------------------------

#[test]
fn test_bare_rsa_keypair_label_is_refused_with_a_pub_hint() {
    let p = make_pair(&[]);
    generate_pair(p.mem.as_ref(), "pair");
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "export mem:target {} --kek pair --mech oaep",
            at(dir.path(), "w.bin")
        ),
    )
    .unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
    assert!(
        err.message.contains("RSA-OAEP wrap needs"),
        "{}",
        err.message
    );
    assert!(hint(&err).contains("pair:pub"));
}

#[test]
fn test_public_and_certificate_targets_are_refused() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_rsa_public(p.mem.as_ref(), "pubkey");
    let dir = tempfile::tempdir().unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "export mem:pubkey {} --kek kek --mech kwp",
            at(dir.path(), "w.bin")
        ),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(
        err.message.contains("only secret and private"),
        "{}",
        err.message
    );
}

#[test]
fn test_conflicting_options() {
    for (option, expected, why) in [
        (
            "--format der",
            "--format cannot be combined",
            "a wrapped blob is opaque, not a container format",
        ),
        (
            "--cert mem:kek",
            "--cert cannot be combined",
            "certificates belong to --format p12",
        ),
        (
            "--password pw",
            "--password cannot be combined",
            "the KEK protects the blob; there is nothing to encrypt with a password",
        ),
        (
            "--public",
            "--public cannot be combined",
            "public keys are not wrapped — export them as plain material (§5.6)",
        ),
    ] {
        let p = make_pair(&[]);
        import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
        import_aes(p.mem.as_ref(), "target", &TARGET, None);
        let dir = tempfile::tempdir().unwrap();
        let err = run_line(
            &p.ctx,
            &format!(
                "export mem:target {} --kek kek --mech kwp {option}",
                at(dir.path(), "w.bin")
            ),
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Generic, "{option}");
        assert!(err.message.contains(expected), "{}", err.message);
        assert_eq!(hint(&err), why);
    }
}

#[test]
fn test_outformat_without_kek_is_refused() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "export mem:target {} --outformat hex",
            at(dir.path(), "w.bin")
        ),
    )
    .unwrap_err();
    assert!(
        err.message
            .contains("--outformat applies only to wrapped exports"),
        "{}",
        err.message
    );
}

#[test]
fn test_invalid_outformat() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "export mem:target {} --kek kek --mech kwp --outformat pem",
            at(dir.path(), "w.bin")
        ),
    )
    .unwrap_err();
    assert!(
        err.message.contains("invalid --outformat"),
        "{}",
        err.message
    );
    assert_eq!(err.message, "invalid --outformat 'pem'");
    assert_eq!(hint(&err), "choose one of: raw, hex, b64");
}

#[test]
fn test_unknown_kek() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "export mem:target {} --kek absent --mech kwp",
            at(dir.path(), "w.bin")
        ),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotFound);
}

#[test]
fn test_cross_provider_kek_is_refused() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_aes(p.hsm.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "export hsm:target {} --kek mem:kek --mech kwp",
            at(dir.path(), "w.bin")
        ),
    )
    .unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
    assert!(err.message.contains("targets 'hsm'"), "{}", err.message);
}

#[test]
fn test_logged_out_provider_fails_before_anything_else() {
    let hsm = Rc::new(FakeProvider::new("hsm").with_type_name("pkcs11"));
    import_aes(hsm.as_ref(), "kek", &aes_32(), None);
    import_aes(hsm.as_ref(), "target", &TARGET, None);
    hsm.logout().unwrap();
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::clone(&hsm) as Rc<dyn Provider>)
        .unwrap();
    let io = Rc::new(ScriptedIo::empty());
    let ctx = ctx_with(&io, registry, None);
    let dir = tempfile::tempdir().unwrap();
    let err = run_line(
        &ctx,
        &format!(
            "export hsm:target {} --kek kek --mech kwp",
            at(dir.path(), "w.bin")
        ),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
}

#[test]
fn test_classic_export_still_rejects_name_value_tokens() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    let err = run_line(
        &p.ctx,
        &format!("export mem:target {} iv=0x00", at(dir.path(), "w.bin")),
    )
    .unwrap_err();
    assert!(
        err.message.contains("unexpected name=value token"),
        "{}",
        err.message
    );
}

#[test]
fn unknown_param_on_export_gets_the_quoting_hint() {
    // r2 addition: the shared _reject_unknown_params path on the export side.
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "export mem:target {} --kek kek --mech oaep salt=1",
            at(dir.path(), "w.bin")
        ),
    );
    // oaep needs an RSA KEK — the KEK check runs before the param check (c2 order)
    assert!(matches!(err.unwrap_err().kind, ErrorKind::Param { .. }));
    let err = run_line(
        &p.ctx,
        &format!(
            "export mem:target {} --kek kek --mech cbc salt=1",
            at(dir.path(), "w.bin")
        ),
    )
    .unwrap_err();
    assert_eq!(err.message, "unexpected name=value token 'salt=…'");
    assert_eq!(
        hint(&err),
        "cbc parameters: iv, padding — quote a base64 blob so its '=' padding is not read as \
         name=value"
    );
}

// ---------------------------------------------------------------------------------------
// completion
// ---------------------------------------------------------------------------------------

#[test]
fn test_completion_offers_the_wrapped_options() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    let options = complete(&p.ctx, &["export", "mem:target", "out.bin"], "");
    for option in ["--kek", "--mech", "--outformat"] {
        assert!(options.contains(&option.to_owned()), "{options:?}");
    }
}

#[test]
fn test_completion_of_mech_and_outformat() {
    let p = make_pair(&[]);
    let mechs = complete(&p.ctx, &["export", "mem:t", "out.bin", "--mech"], "");
    assert_eq!(mechs, ["kw", "kwp", "cbc", "gcm", "oaep", "pkcs1"]);
    let fmts = complete(&p.ctx, &["export", "mem:t", "out.bin", "--outformat"], "");
    assert_eq!(fmts, ["raw", "hex", "b64"]);
}

#[test]
fn test_completion_of_kek_labels_uses_the_refs_provider() {
    // Export's positional 1 is a full ref — the KEK menu must still be the labels of that
    // ref's provider, not of a provider called 'mem:target'.
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_aes(p.mem.as_ref(), "other", &aes_32(), None);
    let labels = complete(&p.ctx, &["export", "mem:target", "out.bin", "--kek"], "");
    assert!(labels.contains(&"kek".to_owned()), "{labels:?}");
    assert!(labels.contains(&"other".to_owned()), "{labels:?}");
    assert!(labels.iter().all(|label| !label.starts_with("mem:")));
}

#[test]
fn test_refusal_fires_before_the_mech_menu_and_prompts() {
    // §5.6 pre-flight: a doomed export never opens a dialogue. The empty ScriptedIo is the
    // tripwire — any select()/prompt() would panic instead of the refusal we expect.
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_aes(
        p.mem.as_ref(),
        "locked",
        &TARGET,
        Some(&policy(true, false)),
    );
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("w.bin");
    // no --mech: the menu would open if the refusal came later
    let err = run_line(
        &p.ctx,
        &format!("export mem:locked {} --kek kek", out.display()),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(err.message.contains("not extractable"), "{}", err.message);
    assert!(p.io.prompts().is_empty());
    assert!(!out.exists());
}

#[test]
fn test_public_target_refused_before_the_mech_menu() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_rsa_public(p.mem.as_ref(), "pubkey");
    let dir = tempfile::tempdir().unwrap();
    let err = run_line(
        &p.ctx,
        &format!("export mem:pubkey {} --kek kek", at(dir.path(), "w.bin")),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(
        err.message.contains("only secret and private"),
        "{}",
        err.message
    );
    assert!(p.io.prompts().is_empty());
}

#[test]
fn test_cross_provider_message_is_worded_for_export() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_aes(p.hsm.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "export hsm:target {} --kek mem:kek --mech kwp",
            at(dir.path(), "w.bin")
        ),
    )
    .unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
    assert!(
        err.message.contains("the export targets 'hsm'"),
        "{}",
        err.message
    );
    assert!(hint(&err).contains("C_WrapKey"));
}

#[test]
fn test_success_line_reports_the_blob_length_not_the_file_size() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("w.hex");
    run_line(
        &p.ctx,
        &format!(
            "export mem:target {} --kek kek --mech kwp --outformat hex",
            out.display()
        ),
    )
    .unwrap();
    let blob_len = r2_core::text::py_fromhex(std::fs::read_to_string(&out).unwrap().trim())
        .unwrap()
        .len();
    let text = p.io.text();
    assert!(text.contains(&format!("{blob_len}-byte blob")), "{text}");
    assert!(text.contains("hex-encoded"), "{text}");
    // the FILE is ~2x the blob — the message deliberately reports the blob
    assert!(std::fs::metadata(&out).unwrap().len() > u64::try_from(blob_len).unwrap());
}

// ---------------------------------------------------------------------------------------
// r2 additions (R15 Accept): export → load round-trips in raw, hex and b64
// ---------------------------------------------------------------------------------------

#[test]
fn export_then_load_round_trips_in_every_outformat() {
    for outformat in ["raw", "hex", "b64"] {
        for (cli, kek_ref, unwrap_ref) in [
            ("kwp", "kek", "kek"),
            ("kw", "kek", "kek"),
            ("pkcs1", "pair:pub", "pair"),
        ] {
            let p = make_pair(&[]);
            import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
            generate_pair(p.mem.as_ref(), "pair");
            import_aes(p.mem.as_ref(), "target", &TARGET, None);
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join(format!("blob.{outformat}"));
            run_line(
                &p.ctx,
                &format!(
                    "export mem:target {} --kek {kek_ref} --mech {cli} --outformat {outformat}",
                    out.display()
                ),
            )
            .unwrap();
            run_line(
                &p.ctx,
                &format!(
                    "load mem aes --file {} --kek {unwrap_ref} --mech {cli} --label back",
                    out.display()
                ),
            )
            .unwrap();
            let back = p.mem.find_key(&KeySelector::label("back")).unwrap();
            assert_eq!(
                *p.mem.export_key(&back).unwrap().data,
                TARGET,
                "{outformat}/{cli}"
            );
        }
    }
}

#[test]
fn export_then_load_round_trips_on_the_memory_provider() {
    // The real MemoryProvider (OpenSSL): AES-KW/KWP/CBC/GCM and RSA OAEP/PKCS#1, through
    // the commands, every encoding.
    use r2_memory::MemoryProvider;
    let mem = Rc::new(MemoryProvider::new("mem"));
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::clone(&mem) as Rc<dyn Provider>)
        .unwrap();
    let io = Rc::new(ScriptedIo::empty());
    let ctx = ctx_with(&io, registry, None);
    import_aes(mem.as_ref(), "kek", &aes_32(), None);
    import_aes(mem.as_ref(), "target", &TARGET, None);
    run_line(&ctx, "generate mem rsa size=2048 --label pair").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let iv16: String = (0u8..16).map(|b| format!("{b:02x}")).collect();
    let mut n = 0;
    for (cli, params, kek_ref, unwrap_ref) in [
        ("kw", String::new(), "kek", "kek"),
        ("kwp", String::new(), "kek", "kek"),
        ("cbc", format!("iv=0x{iv16}"), "kek", "kek"),
        ("gcm", format!("iv=0x{}", iv12_hex()), "kek", "kek"),
        ("oaep", "hash=sha1".to_owned(), "pair:pub", "pair"),
        ("pkcs1", String::new(), "pair:pub", "pair"),
    ] {
        for outformat in ["raw", "hex", "b64"] {
            n += 1;
            let out = dir.path().join(format!("{cli}.{outformat}"));
            run_line(
                &ctx,
                &format!(
                    "export mem:target {} --kek {kek_ref} --mech {cli} {params} --outformat \
                     {outformat}",
                    out.display()
                ),
            )
            .unwrap();
            run_line(
                &ctx,
                &format!(
                    "load mem aes --file {} --kek {unwrap_ref} --mech {cli} {params} --label \
                     back{n}",
                    out.display()
                ),
            )
            .unwrap();
            let back = mem
                .find_key(&KeySelector::label(format!("back{n}")))
                .unwrap();
            assert_eq!(
                *mem.export_key(&back).unwrap().data,
                TARGET,
                "{cli}/{outformat}"
            );
        }
    }
}

/// §11 D13: a Ctrl-C pending before the wrap never issues C_WrapKey nor writes the file.
#[test]
fn interrupt_flag_stops_before_the_wrap() {
    let _lock = r2_testkit::global_state_lock();
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek", &aes_32(), None);
    import_aes(p.mem.as_ref(), "target", &TARGET, None);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("wrapped.bin");
    r2_core::runtime::reset_interrupt();
    r2_core::runtime::request_interrupt();
    let result = run_line(
        &p.ctx,
        &format!("export mem:target {} --kek kek --mech kwp", out.display()),
    );
    r2_core::runtime::reset_interrupt();
    let err = result.unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    assert!(calls_of(&p.mem, "wrap_key").is_empty());
    assert!(!out.exists());
    assert!(p.io.output().is_empty());
}
