// `load --kek` command tests (§5.4 wrapped-key load) — port of c2
// tests/unit/console/test_load_kek.py (R15). FakeProvider + ScriptedIo throughout
// (§4.10). FakeProvider's wrap/unwrap is a reversible transform keyed on the stored
// material and the mechanism name, so blobs produced by `wrap_key` round-trip through the
// command without any provider stubbing.
use std::rc::Rc;

use r2_core::error::{ConsoleError, ErrorKind};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::{ParamValue, Params};
use r2_provider::{
    GenerateRequest, KeySelector, MechanismInvocation, Provider, ProviderRegistry, WrapOptions,
};
use r2_testkit::{FakeProvider, ScriptedIo};

use super::keys_cmd_support::{SpyEditor, ctx_with, make_pair, make_pair_with, rsa_pkcs8_der};
use crate::commands::all_commands;
use crate::commands::kek;
use crate::context::AppContext;
use crate::testing::run_line;

const TARGET: [u8; 32] = [0xab; 32];

fn aes_32() -> Vec<u8> {
    (0u8..32).collect()
}

fn iv12() -> Vec<u8> {
    (0u8..12).collect()
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn aes_material(data: &[u8]) -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, data.to_vec());
    material.size_bits = Some(u32::try_from(data.len() * 8).unwrap());
    material
}

fn import_aes(provider: &dyn Provider, label: &str) -> KeyInfo {
    provider
        .import_key(&aes_material(&aes_32()), label, None, None)
        .unwrap()
}

fn find(provider: &dyn Provider, label: &str) -> KeyInfo {
    provider.find_key(&KeySelector::label(label)).unwrap()
}

fn exported(provider: &dyn Provider, label: &str) -> Vec<u8> {
    provider
        .export_key(&find(provider, label))
        .unwrap()
        .data
        .to_vec()
}

/// Hex blob produced by the provider itself (round-trippable by design).
fn wrapped_blob(
    provider: &dyn Provider,
    kek: &KeyInfo,
    mechanism: &str,
    data: &[u8],
    params: Params,
) -> String {
    let target = provider
        .import_key(
            &aes_material(data),
            &format!("src-{}", mechanism.to_lowercase()),
            None,
            None,
        )
        .unwrap();
    let blob = provider
        .wrap_key(
            kek,
            &MechanismInvocation::new(mechanism, params),
            &target,
            &WrapOptions::default(),
        )
        .unwrap();
    provider.delete_key(&target).unwrap();
    hex(&blob)
}

fn gcm_params() -> Params {
    let mut params = Params::new();
    params.insert("iv".into(), ParamValue::Bytes(iv12()));
    params.insert("aad".into(), ParamValue::Bytes(Vec::new()));
    params.insert("tag_bits".into(), ParamValue::Enum("128".into()));
    params
}

/// The blob a fresh "mem" fake holding the same KEK bytes produces (FakeProvider is keyed
/// on the material, so it is the blob any such fake unwraps) — for tests whose scripted
/// answers must exist before the session is built.
fn precomputed_blob(mechanism: &str, params: Params) -> String {
    let scratch = FakeProvider::new("mem");
    let kek = import_aes(&scratch, "kek");
    wrapped_blob(&scratch, &kek, mechanism, &TARGET, params)
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
    commands["load"].complete(ctx, &tokens, cursor)
}

fn hint(err: &ConsoleError) -> &str {
    err.hint.as_deref().unwrap_or("")
}

fn is_param(err: &ConsoleError) -> bool {
    matches!(err.kind, ErrorKind::Param { .. })
}

// ---------------------------------------------------------------------------------------
// happy paths
// ---------------------------------------------------------------------------------------

#[test]
fn test_inline_blob_with_explicit_mech() {
    let p = make_pair(&[]);
    let kek = import_aes(p.mem.as_ref(), "kek");
    let blob = wrapped_blob(
        p.mem.as_ref(),
        &kek,
        "AES-KEY-WRAP-PAD",
        &TARGET,
        Params::new(),
    );
    run_line(
        &p.ctx,
        &format!("load mem aes {blob} --kek kek --mech kwp --label restored"),
    )
    .unwrap();
    let text = p.io.text();
    assert!(text.contains("mem:restored"), "{text}");
    assert!(
        text.contains("AES-KEY-WRAP-PAD"),
        "table title names the mechanism"
    );
    assert!(text.contains("unwrapped into mem"), "{text}");
    assert_eq!(exported(p.mem.as_ref(), "restored"), TARGET);
}

#[test]
fn test_canonical_mech_name_also_accepted() {
    let p = make_pair(&[]);
    let kek = import_aes(p.mem.as_ref(), "kek");
    let blob = wrapped_blob(p.mem.as_ref(), &kek, "AES-KEY-WRAP", &TARGET, Params::new());
    run_line(
        &p.ctx,
        &format!("load mem aes {blob} --kek kek --mech AES-KEY-WRAP --label restored"),
    )
    .unwrap();
    assert!(p.io.text().contains("mem:restored"));
}

#[test]
fn test_mech_params_travel_as_name_value_tokens() {
    let p = make_pair(&[]);
    let kek = import_aes(p.mem.as_ref(), "kek");
    let blob = wrapped_blob(p.mem.as_ref(), &kek, "AES-GCM", &TARGET, gcm_params());
    run_line(
        &p.ctx,
        &format!(
            "load mem aes {blob} --kek kek --mech gcm iv=0x{} tag_bits=128 --label restored",
            hex(&iv12())
        ),
    )
    .unwrap();
    let call = &calls_of(&p.mem, "unwrap_key")[0];
    assert_eq!(call[2], "AES-GCM");
    assert!(p.io.text().contains("mem:restored"));
}

#[test]
fn test_file_form() {
    let p = make_pair(&[]);
    let kek = import_aes(p.mem.as_ref(), "kek");
    let blob = r2_core::text::py_fromhex(&wrapped_blob(
        p.mem.as_ref(),
        &kek,
        "AES-KEY-WRAP-PAD",
        &TARGET,
        Params::new(),
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wrapped.bin");
    std::fs::write(&path, &blob).unwrap();
    run_line(
        &p.ctx,
        &format!(
            "load mem aes --file {} --kek kek --mech kwp --label restored",
            path.display()
        ),
    )
    .unwrap();
    assert_eq!(exported(p.mem.as_ref(), "restored"), TARGET);
}

#[test]
fn test_hex_and_b64_blob_files_are_auto_detected() {
    // §5.6 round-trip: `export --outformat hex|b64` output loads unchanged.
    let p = make_pair(&[]);
    let kek = import_aes(p.mem.as_ref(), "kek");
    let blob_hex = wrapped_blob(
        p.mem.as_ref(),
        &kek,
        "AES-KEY-WRAP-PAD",
        &TARGET,
        Params::new(),
    );
    let blob = r2_core::text::py_fromhex(&blob_hex).unwrap();
    let dir = tempfile::tempdir().unwrap();

    let hex_file = dir.path().join("wrapped.hex");
    std::fs::write(&hex_file, format!("{blob_hex}\n")).unwrap();
    run_line(
        &p.ctx,
        &format!(
            "load mem aes --file {} --kek kek --mech kwp --label from-hex",
            hex_file.display()
        ),
    )
    .unwrap();
    assert_eq!(exported(p.mem.as_ref(), "from-hex"), TARGET);

    let b64_file = dir.path().join("wrapped.b64");
    let out = r2_core::datainput::DataOutput::file(&b64_file, r2_core::datainput::OutFormat::B64);
    out.write(&blob, p.io.as_ref()).unwrap();
    assert!(std::fs::read_to_string(&b64_file).unwrap().ends_with('\n'));
    run_line(
        &p.ctx,
        &format!(
            "load mem aes --file {} --kek kek --mech kwp --label from-b64",
            b64_file.display()
        ),
    )
    .unwrap();
    assert_eq!(exported(p.mem.as_ref(), "from-b64"), TARGET);
}

#[test]
fn test_rsa_kek_resolves_to_the_private_half() {
    let p = make_pair(&[]);
    let mut request = GenerateRequest::new(KeyAlgorithm::Rsa, "pair");
    request.size_bits = Some(2048);
    p.mem.generate_key(&request).unwrap();
    let private = p
        .mem
        .find_key(&KeySelector::label("pair").with_class(Some(KeyClass::Private)))
        .unwrap();
    let mut params = Params::new();
    params.insert("hash".into(), ParamValue::Enum("sha256".into()));
    params.insert("mgf_hash".into(), ParamValue::Enum("sha256".into()));
    params.insert("label".into(), ParamValue::Bytes(Vec::new()));
    let blob = wrapped_blob(p.mem.as_ref(), &private, "RSA-OAEP", &TARGET, params);
    run_line(
        &p.ctx,
        &format!("load mem aes {blob} --kek pair --mech oaep --label restored"),
    )
    .unwrap();
    let call = &calls_of(&p.mem, "unwrap_key")[0];
    assert_eq!(call[1], private.key_ref.display());
}

#[test]
fn test_id_flag_reaches_the_new_object() {
    let p = make_pair(&[]);
    let kek = import_aes(p.mem.as_ref(), "kek");
    let blob = wrapped_blob(
        p.mem.as_ref(),
        &kek,
        "AES-KEY-WRAP-PAD",
        &TARGET,
        Params::new(),
    );
    run_line(
        &p.ctx,
        &format!("load mem aes {blob} --kek kek --mech kwp --label restored --id 0a1b"),
    )
    .unwrap();
    assert_eq!(
        find(p.mem.as_ref(), "restored").key_ref.key_id,
        Some(vec![0x0a, 0x1b])
    );
}

#[test]
fn test_pkcs11_target_opens_the_editor_seeded_from_the_result() {
    let p = make_pair(&[]);
    let kek = import_aes(p.hsm.as_ref(), "kek");
    let blob = wrapped_blob(
        p.hsm.as_ref(),
        &kek,
        "AES-KEY-WRAP-PAD",
        &rsa_pkcs8_der(),
        Params::new(),
    );
    run_line(
        &p.ctx,
        &format!("load hsm rsa {blob} --kek kek --mech kwp --label restored"),
    )
    .unwrap();
    assert_eq!(
        p.editor.titles(),
        ["PKCS#11 template — rsa private 'restored'"]
    );
    // the edited template rides into unwrap_key
    let call = &calls_of(&p.hsm, "unwrap_key")[0];
    assert!(call[8].starts_with("template("), "{call:?}");
}

#[test]
fn edited_template_reaches_the_unwrapped_object() {
    // r2 addition: the operator's editor answer is what unwrap_key receives.
    let editor = SpyEditor::editing(|template| {
        for attr in &mut template.attrs {
            if attr.name == "CKA_SENSITIVE" {
                attr.value = r2_core::template::AttrValue::Bool(false);
                attr.enabled = true;
            }
            if attr.name == "CKA_EXTRACTABLE" {
                attr.value = r2_core::template::AttrValue::Bool(true);
                attr.enabled = true;
            }
        }
    });
    let p = make_pair_with(&[], None, editor);
    let kek = import_aes(p.hsm.as_ref(), "kek");
    let blob = wrapped_blob(
        p.hsm.as_ref(),
        &kek,
        "AES-KEY-WRAP-PAD",
        &TARGET,
        Params::new(),
    );
    run_line(
        &p.ctx,
        &format!("load hsm aes {blob} --kek kek --mech kwp --label restored"),
    )
    .unwrap();
    assert_eq!(exported(p.hsm.as_ref(), "restored"), TARGET);
}

// ---------------------------------------------------------------------------------------
// interactive fallbacks (§5.1: one code path, prompts fill the gaps)
// ---------------------------------------------------------------------------------------

#[test]
fn test_omitted_mech_opens_the_select_menu() {
    let p = make_pair(&["kwp — AES key wrap with padding (RFC 5649)"]);
    let kek = import_aes(p.mem.as_ref(), "kek");
    let blob = wrapped_blob(
        p.mem.as_ref(),
        &kek,
        "AES-KEY-WRAP-PAD",
        &TARGET,
        Params::new(),
    );
    run_line(
        &p.ctx,
        &format!("load mem aes {blob} --kek kek --label restored"),
    )
    .unwrap();
    assert_eq!(exported(p.mem.as_ref(), "restored"), TARGET);
    assert_eq!(p.io.prompts(), ["Select wrap mechanism for KEK mem:kek"]);
}

#[test]
fn test_omitted_param_is_prompted() {
    let answer = format!("0x{}", hex(&iv12()));
    let p = make_pair(&[answer.as_str()]); // answers the iv prompt
    let kek = import_aes(p.mem.as_ref(), "kek");
    let blob = wrapped_blob(p.mem.as_ref(), &kek, "AES-GCM", &TARGET, gcm_params());
    run_line(
        &p.ctx,
        &format!("load mem aes {blob} --kek kek --mech gcm --label restored"),
    )
    .unwrap();
    assert_eq!(p.io.prompts(), ["IV / nonce (12 bytes typical)"]);
    assert_eq!(exported(p.mem.as_ref(), "restored"), TARGET);
}

#[test]
fn test_omitted_blob_is_pasted() {
    // the blob must exist before the IO queue is built
    let blob = precomputed_blob("AES-KEY-WRAP-PAD", Params::new());
    let p = make_pair(&[blob.as_str()]);
    import_aes(p.mem.as_ref(), "kek");
    run_line(&p.ctx, "load mem aes --kek kek --mech kwp --label restored").unwrap();
    assert_eq!(exported(p.mem.as_ref(), "restored"), TARGET);
    assert_eq!(p.io.prompts(), ["Paste wrapped key blob (hex / base64)"]);
}

#[test]
fn test_omitted_label_is_prompted() {
    let p = make_pair(&["restored"]);
    let kek = import_aes(p.mem.as_ref(), "kek");
    let blob = wrapped_blob(
        p.mem.as_ref(),
        &kek,
        "AES-KEY-WRAP-PAD",
        &TARGET,
        Params::new(),
    );
    run_line(&p.ctx, &format!("load mem aes {blob} --kek kek --mech kwp")).unwrap();
    assert_eq!(find(p.mem.as_ref(), "restored").key_ref.label, "restored");
    assert_eq!(p.io.prompts(), ["Key label"]);
}

#[test]
fn prompts_come_in_c2_order() {
    // r2 addition: menu → params → blob → label (c2 _run_wrapped order).
    let blob = precomputed_blob("AES-GCM", gcm_params());
    let iv = format!("0x{}", hex(&iv12()));
    let p = make_pair(&[
        "gcm — AES-GCM wrapped blob (ct‖tag)",
        &iv,
        &blob,
        "restored",
    ]);
    import_aes(p.mem.as_ref(), "kek");
    run_line(&p.ctx, "load mem aes --kek kek").unwrap();
    assert_eq!(
        p.io.prompts(),
        [
            "Select wrap mechanism for KEK mem:kek",
            "IV / nonce (12 bytes typical)",
            "Paste wrapped key blob (hex / base64)",
            "Key label"
        ]
    );
    assert_eq!(exported(p.mem.as_ref(), "restored"), TARGET);
}

// ---------------------------------------------------------------------------------------
// error paths (§5.4 validation order)
// ---------------------------------------------------------------------------------------

#[test]
fn test_opaque_hints_are_refused() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    for hint_token in ["auto", "cert"] {
        let err = run_line(
            &p.ctx,
            &format!("load mem {hint_token} 00 --kek kek --mech kwp"),
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Generic);
        assert!(
            err.message.contains("is invalid with --kek"),
            "{}",
            err.message
        );
        assert_eq!(
            hint(&err),
            "a wrapped blob is opaque — declare what comes out: aes, generic, rsa, ec"
        );
    }
    let err = run_line(&p.ctx, "load mem data 00 --kek kek --mech kwp").unwrap_err();
    assert_eq!(err.message, "type hint 'data' is invalid with --kek");
}

#[test]
fn missing_hint_quotes_the_usage() {
    // r2 addition: `load mem --kek k` (no positional type) → c2's missing-argument error.
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, "load mem --kek kek").unwrap_err();
    assert_eq!(err.message, "missing <aes|rsa|ec|generic> argument");
    let usage = all_commands().unwrap()["load"].usage();
    assert_eq!(hint(&err), format!("usage: {usage}"));
}

#[test]
fn test_format_and_password_conflict_with_kek() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    let err = run_line(&p.ctx, "load mem aes 00 --kek kek --mech kwp --format aes").unwrap_err();
    assert!(
        err.message.contains("--format cannot be combined"),
        "{}",
        err.message
    );
    assert_eq!(
        hint(&err),
        "a wrapped blob is opaque — it is never an encrypted container; declare the result \
         type positionally"
    );
    let err = run_line(
        &p.ctx,
        "load mem aes 00 --kek kek --mech kwp --password s3cret",
    )
    .unwrap_err();
    assert!(
        err.message.contains("--password cannot be combined"),
        "{}",
        err.message
    );
}

#[test]
fn test_unknown_kek_raises_key_not_found() {
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, "load mem aes 00 --kek absent --mech kwp").unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotFound);
}

#[test]
fn test_cross_provider_kek_is_refused() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    let err = run_line(&p.ctx, "load hsm aes 00 --kek mem:kek --mech kwp").unwrap_err();
    assert!(is_param(&err));
    assert!(err.message.contains("targets 'hsm'"), "{}", err.message);
}

#[test]
fn test_unknown_mech_suggests() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    let err = run_line(&p.ctx, "load mem aes 00 --kek kek --mech kwpp").unwrap_err();
    assert!(is_param(&err));
    assert!(
        err.message.contains("unknown wrap mechanism"),
        "{}",
        err.message
    );
}

#[test]
fn test_mech_kek_mismatch_is_reported() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    let err = run_line(&p.ctx, "load mem aes 00 --kek kek --mech oaep").unwrap_err();
    assert!(is_param(&err));
    assert!(
        err.message.contains("needs a private rsa KEK"),
        "{}",
        err.message
    );
}

#[test]
fn test_mech_not_advertised() {
    let limited = Rc::new(FakeProvider::new("mem").with_mechanisms(["AES-KEY-WRAP-PAD"]));
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::clone(&limited) as Rc<dyn Provider>)
        .unwrap();
    let io = Rc::new(ScriptedIo::empty());
    let ctx = ctx_with(&io, registry, None);
    import_aes(limited.as_ref(), "kek");
    let err = run_line(&ctx, "load mem aes 00 --kek kek --mech gcm").unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(
        err.message.contains("does not advertise AES-GCM"),
        "{}",
        err.message
    );
}

#[test]
fn test_unquoted_base64_blob_gets_the_quoting_hint() {
    // An unquoted base64 blob ends in '=' padding, which the §4.9 tokenizer binds as
    // name=value — the error must point at quoting, not at params.
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    let err = run_line(
        &p.ctx,
        "load mem aes AAECAwQFBgcICQoLDA0ODw== --kek kek --mech kwp",
    )
    .unwrap_err();
    assert!(
        err.message.contains("unexpected name=value token"),
        "{}",
        err.message
    );
    assert!(hint(&err).contains("quote"));
    assert_eq!(
        err.message,
        "unexpected name=value token 'AAECAwQFBgcICQoLDA0ODw=…'"
    );
    assert_eq!(
        hint(&err),
        "kwp takes no parameters — quote a base64 blob so its '=' padding is not read as \
         name=value"
    );
}

#[test]
fn test_unknown_param_for_a_mech_with_params() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    let err = run_line(&p.ctx, "load mem aes 00 --kek kek --mech gcm nonce=0x00").unwrap_err();
    assert!(
        err.message.contains("unexpected name=value token"),
        "{}",
        err.message
    );
    assert!(hint(&err).contains("iv"));
    assert_eq!(
        hint(&err),
        "gcm parameters: iv, aad, tag_bits — quote a base64 blob so its '=' padding is not \
         read as name=value"
    );
}

#[test]
fn test_undecodable_blob() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    // neither hex nor base64 (length % 4 != 0 and non-alphabet chars)
    let err = run_line(&p.ctx, "load mem aes !!! --kek kek --mech kwp --label x").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Codec);
}

#[test]
fn test_missing_file() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    let dir = tempfile::tempdir().unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "load mem aes --file {} --kek kek --mech kwp",
            dir.path().join("absent.bin").display()
        ),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::DataIo);
}

#[test]
fn test_file_form_rejects_inline_data() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w.bin");
    std::fs::write(&path, [0u8; 40]).unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "load mem aes 00ff --file {} --kek kek --mech kwp",
            path.display()
        ),
    )
    .unwrap_err();
    assert!(
        err.message.contains("unexpected argument"),
        "{}",
        err.message
    );
    assert_eq!(err.message, "unexpected argument '00ff'");
}

#[test]
fn test_logged_out_provider_fails_before_anything_else() {
    let hsm = Rc::new(
        FakeProvider::new("hsm")
            .with_type_name("pkcs11")
            .starting_logged_out(),
    );
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::clone(&hsm) as Rc<dyn Provider>)
        .unwrap();
    let io = Rc::new(ScriptedIo::empty());
    let ctx = ctx_with(&io, registry, None);
    let err = run_line(&ctx, "load hsm aes 00 --kek kek --mech kwp").unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert!(hsm.calls().is_empty(), "{:?}", hsm.calls());
}

// ---------------------------------------------------------------------------------------
// the classic (plaintext) form must be untouched
// ---------------------------------------------------------------------------------------

#[test]
fn test_classic_form_still_rejects_name_value_tokens() {
    let p = make_pair(&[]);
    let err = run_line(
        &p.ctx,
        "load mem aes 00112233445566778899aabbccddeeff iv=0x00",
    )
    .unwrap_err();
    assert!(
        err.message.contains("unexpected name=value token"),
        "{}",
        err.message
    );
}

// ---------------------------------------------------------------------------------------
// completion
// ---------------------------------------------------------------------------------------

#[test]
fn test_completion_offers_kek_and_mech() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    let options = complete(&p.ctx, &["load", "mem", "aes", "00"], "");
    assert!(options.contains(&"--kek".to_owned()));
    assert!(options.contains(&"--mech".to_owned()));
}

#[test]
fn test_completion_of_mech_names_and_params() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    let mechs = complete(&p.ctx, &["load", "mem", "aes", "--mech"], "");
    assert_eq!(mechs, ["kw", "kwp", "cbc", "gcm", "oaep", "pkcs1"]);
    let params = complete(
        &p.ctx,
        &["load", "mem", "aes", "--mech", "gcm", "--kek", "kek"],
        "",
    );
    for name in ["iv=", "aad=", "tag_bits="] {
        assert!(params.contains(&name.to_owned()), "{params:?}");
    }
}

#[test]
fn test_completion_of_kek_labels_is_provider_local() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    import_aes(p.mem.as_ref(), "other");
    let labels = complete(&p.ctx, &["load", "mem", "aes", "--kek"], "");
    assert!(labels.contains(&"kek".to_owned()), "{labels:?}");
    assert!(labels.contains(&"other".to_owned()), "{labels:?}");
    assert!(labels.iter().all(|label| !label.starts_with("mem:")));
}

#[test]
fn test_kek_completion_never_browses_a_logged_out_provider() {
    // §6: completion must not trigger a login or a library load.
    let p = make_pair(&[]);
    import_aes(p.hsm.as_ref(), "kek");
    p.hsm.logout().unwrap();
    p.hsm.clear_calls();
    assert!(complete(&p.ctx, &["load", "hsm", "aes", "--kek"], "").is_empty());
    assert!(calls_of(&p.hsm, "list_keys").is_empty());
}

#[test]
fn hook_completion_surface() {
    // r2 addition: the frozen §4.9.9 completion hooks directly.
    let p = make_pair(&[]);
    let tokens =
        |items: &[&str]| -> Vec<String> { items.iter().map(|t| (*t).to_owned()).collect() };
    assert_eq!(
        kek::complete_option_value(&p.ctx, &tokens(&["load", "mem"]), "--outformat"),
        Some(vec!["raw".to_owned(), "hex".to_owned(), "b64".to_owned()])
    );
    assert_eq!(
        kek::complete_option_value(&p.ctx, &tokens(&["load", "mem"]), "--label"),
        None
    );
    assert_eq!(
        kek::complete_option_value(&p.ctx, &tokens(&["load"]), "--kek"),
        Some(Vec::new())
    );
    assert_eq!(
        kek::param_name_candidates(&tokens(&["load", "mem", "aes", "--mech", " OAEP "])),
        ["hash=", "mgf_hash=", "label="]
    );
    assert!(kek::param_name_candidates(&tokens(&["load", "mem", "--mech"])).is_empty());
    assert!(kek::param_name_candidates(&tokens(&["load", "mem", "--mech", "kw"])).is_empty());
    assert!(kek::param_name_candidates(&tokens(&["load", "mem", "--mech", "nope"])).is_empty());
    assert!(kek::param_name_candidates(&tokens(&["load", "mem"])).is_empty());
}

#[test]
fn test_outformat_is_rejected_on_load() {
    // `--outformat` belongs to `export --kek`; loading auto-detects (§5.4).
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    let err = run_line(
        &p.ctx,
        "load mem aes 00 --kek kek --mech kwp --outformat hex",
    )
    .unwrap_err();
    assert!(
        err.message
            .contains("--outformat applies to `export --kek`"),
        "{}",
        err.message
    );
    assert_eq!(
        hint(&err),
        "hex/base64 blob files are detected automatically (§5.4)"
    );
}

#[test]
fn test_cross_provider_message_is_worded_for_load() {
    let p = make_pair(&[]);
    import_aes(p.mem.as_ref(), "kek");
    let err = run_line(&p.ctx, "load hsm aes 00 --kek mem:kek --mech kwp").unwrap_err();
    assert!(is_param(&err));
    assert!(
        err.message.contains("the load targets 'hsm'"),
        "{}",
        err.message
    );
    assert!(hint(&err).contains("C_UnwrapKey"));
}

#[test]
fn usage_constants_match_the_commands() {
    // kek.rs quotes the load/export usage texts; they must stay R8's verbatim.
    let commands = all_commands().unwrap();
    assert_eq!(commands["load"].usage(), kek::LOAD_USAGE);
    assert_eq!(commands["export"].usage(), kek::EXPORT_USAGE);
}
