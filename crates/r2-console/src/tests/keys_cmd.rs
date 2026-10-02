// keys / key info / key edit / generate / load / export / csr / delete command tests —
// port of c2 tests/unit/console/test_keys_cmd.py (R8 cases; the `key template` /
// `--template` cases are R14's) and the keys_cmd completion cases of test_l13_hardening.py.
// FakeProvider + ScriptedIo throughout (spec §4.10); real material where the export/csr
// paths must produce parseable output.
use std::rc::Rc;

use r2_core::error::ErrorKind;
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_core::x509build::build_pkcs12;
use r2_provider::{GenerateRequest, KeySelector, Provider};
use secrecy::SecretString;

use super::keys_cmd_support::*;
use crate::commands::all_commands;
use crate::context::AppContext;
use crate::testing::{make_config, run_line};

const FILTER_ID_HEX: &str = "7aa59ce91623450083fa10270dabfb1e";
const AES_HEX: &str = "000102030405060708090a0b0c0d0e0f";

fn filter_id() -> Vec<u8> {
    r2_core::text::py_fromhex(FILTER_ID_HEX).unwrap()
}

fn complete(ctx: &AppContext, command: &str, tokens: &[&str], cursor: &str) -> Vec<String> {
    let commands = all_commands().unwrap();
    let tokens: Vec<String> = tokens.iter().map(|t| (*t).to_owned()).collect();
    commands[command].complete(ctx, &tokens, cursor)
}

fn generate(provider: &dyn Provider, algorithm: KeyAlgorithm, label: &str) {
    let mut request = GenerateRequest::new(algorithm, label);
    match algorithm {
        KeyAlgorithm::Rsa => request.size_bits = Some(2048),
        _ => request.curve = Some(Curve::P256),
    }
    provider.generate_key(&request).unwrap();
}

fn find(provider: &dyn Provider, label: &str) -> r2_core::keys::KeyInfo {
    provider.find_key(&KeySelector::label(label)).unwrap()
}

fn find_class(provider: &dyn Provider, label: &str, class: KeyClass) -> r2_core::keys::KeyInfo {
    provider
        .find_key(&KeySelector::label(label).with_class(Some(class)))
        .unwrap()
}

// ---------------------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------------------

#[test]
fn test_keys_lists_all_browsable_providers() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "aeskey", None, None)
        .unwrap();
    p.hsm
        .import_key(&cert_material(), "trust", None, None)
        .unwrap();
    run_line(&p.ctx, "keys").unwrap();
    let text = p.io.text();
    assert!(text.contains("mem:aeskey"));
    assert!(text.contains("cert")); // §5.11: certificates listed with class "cert"
    assert!(text.contains("256") && text.contains("yes"));
    let header = text.lines().nth(1).unwrap();
    for column in ["ref", "class", "algorithm", "size/curve", "exportable"] {
        assert!(header.contains(column), "{header}");
    }
    assert_eq!(text.lines().next().unwrap().trim(), "keys");
}

#[test]
fn test_keys_skips_logged_out_provider_with_note() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "aeskey", None, None)
        .unwrap();
    p.hsm.logout().unwrap();
    run_line(&p.ctx, "keys").unwrap();
    assert!(p.io.text().contains("mem:aeskey"));
    assert!(
        p.io.output()
            .iter()
            .any(|line| line.contains("'hsm' is not logged in"))
    );
    assert_eq!(
        p.io.output().last().unwrap(),
        "note: 'hsm' is not logged in — run `login hsm` to list its keys"
    );
}

#[test]
fn test_keys_single_provider() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "aeskey", None, None)
        .unwrap();
    p.hsm
        .import_key(&aes_material(), "hsmkey", None, None)
        .unwrap();
    run_line(&p.ctx, "keys hsm").unwrap();
    assert!(p.io.text().contains("hsm:hsmkey"));
    assert!(!p.io.text().contains("mem:aeskey"));
}

#[test]
fn test_keys_explicit_provider_logged_out_raises() {
    let p = make_pair(&[]);
    p.hsm.logout().unwrap();
    let err = run_line(&p.ctx, "keys hsm").unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert!(err.message.contains("login required"));
}

#[test]
fn test_keys_empty() {
    let p = make_pair(&[]);
    run_line(&p.ctx, "keys").unwrap();
    assert_eq!(p.io.output(), ["no keys"]);
}

#[test]
fn test_keys_provider_and_filter() {
    let p = make_pair(&[]);
    p.hsm
        .import_key(&aes_material(), "app-config", None, Some(&filter_id()))
        .unwrap();
    p.hsm
        .import_key(&aes_material(), "other", None, None)
        .unwrap();
    p.mem
        .import_key(&aes_material(), "app-config", None, Some(&filter_id()))
        .unwrap();
    run_line(&p.ctx, "keys hsm 7aa59ce").unwrap();
    let text = p.io.text();
    assert!(text.contains(&format!("hsm:app-config#{FILTER_ID_HEX}")));
    assert!(!text.contains("hsm:other"));
    assert!(!text.contains("mem:app-config"));
}

#[test]
fn test_keys_lone_filter_searches_all_browsable_providers() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "aeskey", None, None)
        .unwrap();
    p.hsm
        .import_key(&aes_material(), "app-config", None, Some(&filter_id()))
        .unwrap();
    run_line(&p.ctx, "keys 7aa59ce").unwrap();
    assert!(
        p.io.text()
            .contains(&format!("hsm:app-config#{FILTER_ID_HEX}"))
    );
    assert!(!p.io.text().contains("mem:aeskey"));
}

#[test]
fn test_keys_lone_filter_keeps_logged_out_note() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "app-config", None, Some(&filter_id()))
        .unwrap();
    p.hsm.logout().unwrap();
    run_line(&p.ctx, "keys 7aa59ce").unwrap();
    assert!(
        p.io.text()
            .contains(&format!("mem:app-config#{FILTER_ID_HEX}"))
    );
    assert!(
        p.io.output()
            .iter()
            .any(|line| line.contains("'hsm' is not logged in"))
    );
}

#[test]
fn test_keys_filter_is_case_insensitive() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "app-config", None, Some(&filter_id()))
        .unwrap();
    run_line(&p.ctx, "keys mem 7AA59CE").unwrap();
    assert!(
        p.io.text()
            .contains(&format!("mem:app-config#{FILTER_ID_HEX}"))
    );
}

#[test]
fn test_keys_filter_no_match() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "aeskey", None, None)
        .unwrap();
    run_line(&p.ctx, "keys mem nomatch").unwrap();
    assert_eq!(p.io.output(), ["no keys match 'nomatch'"]);
}

#[test]
fn test_keys_rejects_extra_arguments() {
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, "keys mem 7aa59ce extra").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert!(err.message.contains("unexpected argument"));
    assert_eq!(err.message, "unexpected argument 'extra'");
    assert_eq!(
        err.hint.as_deref(),
        Some("usage: keys [<provider>] [<filter>]")
    );
}

#[test]
fn test_keys_suffixes_keypair_family_refs() {
    let p = make_pair(&[]);
    generate(p.hsm.as_ref(), KeyAlgorithm::Rsa, "pair");
    p.mem
        .import_key(&aes_material(), "solo", None, None)
        .unwrap();
    run_line(&p.ctx, "keys").unwrap();
    let text = p.io.text();
    assert!(text.contains(":priv") && text.contains(":pub")); // §4.3 colliding refs suffixed
    assert!(text.contains("mem:solo") && !text.contains("mem:solo:")); // lone key plain
}

#[test]
fn test_keys_filter_matches_class_suffix() {
    let p = make_pair(&[]);
    generate(p.hsm.as_ref(), KeyAlgorithm::Rsa, "pair");
    run_line(&p.ctx, "keys hsm :pub").unwrap();
    assert!(p.io.text().contains(":pub"));
    assert!(!p.io.text().contains(":priv"));
}

#[test]
fn keys_display_refs_add_a_handle_suffix_for_exact_twins() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "dup", None, None)
        .unwrap();
    p.mem
        .store_key_unchecked(&aes_material(), "dup", None, None);
    run_line(&p.ctx, "keys mem").unwrap();
    let text = p.io.text();
    assert!(text.contains("mem:dup:secret@1"), "{text}");
    assert!(text.contains("mem:dup:secret@2"), "{text}");
}

#[test]
fn keys_rejects_name_value_tokens() {
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, "keys a=b").unwrap_err();
    assert_eq!(err.message, "unexpected name=value token 'a=…'");
    assert_eq!(
        err.hint.as_deref(),
        Some("usage: keys [<provider>] [<filter>] (quote data containing '=')")
    );
}

// ---------------------------------------------------------------------------------------
// key info
// ---------------------------------------------------------------------------------------

#[test]
fn test_key_info_shows_fields_and_attributes() {
    let p = make_pair(&[]);
    p.hsm
        .import_key(
            &private_material(),
            "rsa1",
            Some(&sensitive_template()),
            None,
        )
        .unwrap();
    run_line(&p.ctx, "key info hsm:rsa1").unwrap();
    let text = p.io.text();
    assert!(text.contains("private") && text.contains("rsa"));
    assert!(text.contains("CKA_SENSITIVE") && text.contains("CKA_EXTRACTABLE"));
    assert!(text.contains("exportable") && text.contains("no"));
    assert_eq!(text.lines().next().unwrap().trim(), "hsm:rsa1#00000001");
    let row = |name: &str| {
        text.lines()
            .find(|line| line.trim_start().starts_with(name))
            .unwrap()
            .split_whitespace()
            .last()
            .unwrap()
            .to_owned()
    };
    assert_eq!(row("provider type"), "pkcs11");
    assert_eq!(row("size (bits)"), "2048");
    assert_eq!(row("curve"), "-");
    assert_eq!(row("CKA_SENSITIVE"), "True");
    assert_eq!(row("CKA_EXTRACTABLE"), "False");
}

#[test]
fn test_key_info_certificate_shows_subject_issuer_serial_validity() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&cert_material(), "trust", None, None)
        .unwrap();
    run_line(&p.ctx, "key info mem:trust").unwrap();
    let text = p.io.text();
    assert!(text.contains("unit-test-cert")); // subject CN (§5.11)
    assert!(text.contains("not valid before") && text.contains("not valid after"));
    assert!(text.contains("CN=unit-test-cert"));
    assert!(
        text.lines()
            .any(|line| line.trim_start().starts_with("serial "))
    );
}

#[test]
fn test_key_info_unknown_subcommand() {
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, "key blah mem:x").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert!(err.message.contains("unknown key subcommand"));
    assert_eq!(err.message, "unknown key subcommand 'blah'");
}

#[test]
fn test_key_info_ambiguous_ref() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "dup", None, None)
        .unwrap();
    // twin via the backdoor — API creation is refused by the §4.7 duplicate guard
    p.mem
        .store_key_unchecked(&aes_material(), "dup", None, None);
    let err = run_line(&p.ctx, "key info mem:dup").unwrap_err();
    assert!(matches!(err.kind, ErrorKind::AmbiguousKey { .. }));
    assert!(err.message.contains("dup"));
}

#[test]
fn test_key_info_class_qualified_targets_half() {
    let p = make_pair(&[]);
    generate(p.hsm.as_ref(), KeyAlgorithm::Rsa, "pair");
    run_line(&p.ctx, "key info hsm:pair:pub").unwrap();
    let text = p.io.text();
    assert!(text.contains("public")); // class row shows the targeted half
    assert!(text.contains("handle")); // §4.3: session-transient selector rendered
    assert!(
        p.io.output()
            .iter()
            .any(|line| line.starts_with("related: ") && line.contains(":priv"))
    );
}

#[test]
fn test_key_info_unqualified_prefers_private_and_lists_related() {
    let p = make_pair(&[]);
    generate(p.mem.as_ref(), KeyAlgorithm::Rsa, "pair");
    run_line(&p.ctx, "key info mem:pair").unwrap();
    assert!(p.io.text().contains("private"));
    assert!(
        p.io.output()
            .iter()
            .any(|line| line.starts_with("related: ") && line.contains("mem:pair:pub"))
    );
    assert_eq!(p.io.output().last().unwrap(), "related: mem:pair:pub");
}

#[test]
fn key_info_missing_ref() {
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, "key info").unwrap_err();
    assert_eq!(err.message, "missing <provider:label> argument");
    let err = run_line(&p.ctx, "key").unwrap_err();
    assert_eq!(err.message, "missing <subcommand> argument");
}

// ---------------------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------------------

#[test]
fn test_generate_aes_defaults_prompt_only_label() {
    let p = make_pair(&["k1"]);
    run_line(&p.ctx, "generate mem aes").unwrap();
    assert_eq!(p.io.prompts(), ["Key label"]); // size defaulted (§5.3), label prompted
    let call = &calls_of(&p.mem, "generate_key")[0];
    assert_eq!(
        call[1..],
        [
            "KeyAlgorithm.AES",
            "256",
            "None",
            "k1",
            "None",
            "None",
            "None"
        ]
    );
    assert!(p.editor.titles().is_empty()); // memory target: no template editor (§5.12)
    assert_eq!(p.io.output(), ["generated mem:k1 (256-bit aes)"]);
}

#[test]
fn test_generate_aes_inline_size_and_label() {
    let p = make_pair(&[]);
    run_line(&p.ctx, "generate mem aes size=192 --label k2").unwrap();
    assert_eq!(calls_of(&p.mem, "generate_key")[0][2], "192");
    assert!(p.io.prompts().is_empty());
}

#[test]
fn test_generate_rejects_invalid_size() {
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, "generate mem aes size=123 --label x").unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "size".into()
        }
    );
    assert!(err.message.contains("size"));
}

#[test]
fn test_generate_rejects_unknown_param() {
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, "generate mem aes curve=p256 --label x").unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
    assert!(err.message.contains("curve"));
    assert_eq!(err.message, "unknown parameter 'curve' for generate.aes");
}

#[test]
fn test_generate_unknown_type() {
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, "generate mem dsa --label x").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert!(err.message.contains("unknown key type"));
    assert_eq!(err.message, "unknown key type 'dsa'");
    assert!(
        err.hint
            .unwrap()
            .starts_with("valid types: aes, rsa, ec, generic — usage: generate <provider>")
    );
}

#[test]
fn test_generate_curve_implies_algorithm() {
    for (curve, algorithm) in [
        ("p384", "KeyAlgorithm.EC"),
        ("ed25519", "KeyAlgorithm.EC_EDWARDS"),
        ("x448", "KeyAlgorithm.EC_MONTGOMERY"),
    ] {
        let p = make_pair(&[]);
        run_line(&p.ctx, &format!("generate mem ec curve={curve} --label k")).unwrap();
        let call = &calls_of(&p.mem, "generate_key")[0];
        assert_eq!((call[1].as_str(), call[3].as_str()), (algorithm, curve));
        assert_eq!(
            p.io.output(),
            [format!(
                "generated {curve} {} keypair mem:k (public key shares the label/id)",
                Curve::KNOWN
                    .iter()
                    .find(|c| c.as_str() == curve)
                    .unwrap()
                    .algorithm()
                    .as_str()
            )]
        );
    }
}

#[test]
fn test_generate_id_option() {
    let p = make_pair(&[]);
    run_line(&p.ctx, "generate mem aes size=256 --label k --id 0a1b").unwrap();
    assert_eq!(calls_of(&p.mem, "generate_key")[0][5], "2B"); // bytes summarized "{len}B"
    assert_eq!(
        find(p.mem.as_ref(), "k").key_ref.key_id.as_deref(),
        Some(&[0x0a, 0x1b][..])
    );
}

#[test]
fn test_generate_bad_id_hex() {
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, "generate mem aes size=256 --label k --id zz").unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "id".into()
        }
    );
    assert!(err.message.contains("invalid key id"));
}

#[test]
fn test_generate_aes_on_pkcs11_opens_one_editor() {
    let p = make_pair(&[]);
    run_line(&p.ctx, "generate hsm aes size=256 --label k").unwrap();
    let titles = p.editor.titles();
    assert_eq!(titles.len(), 1);
    assert!(titles[0].contains("AES key 'k'"));
    assert_eq!(titles[0], "PKCS#11 template — AES key 'k'");
    // edited template reached the provider
    assert!(calls_of(&p.hsm, "generate_key")[0][6].starts_with("template("));
    // the seed is the §7 aes default template with the locked class rows
    let seed = &p.editor.seeds()[0];
    assert_eq!(
        seed.get("CKA_CLASS").unwrap().value,
        AttrValue::Symbol("CKO_SECRET_KEY".into())
    );
}

#[test]
fn test_generate_keypair_on_pkcs11_opens_private_then_public_editor() {
    let p = make_pair(&[]);
    run_line(&p.ctx, "generate hsm rsa size=2048 --label pair").unwrap();
    let titles = p.editor.titles();
    assert_eq!(titles.len(), 2);
    assert!(titles[0].contains("private key 'pair'"));
    assert!(titles[1].contains("public key 'pair'"));
    assert_eq!(titles[0], "PKCS#11 template — rsa private key 'pair'");
    let call = &calls_of(&p.hsm, "generate_key")[0];
    assert!(call[6].starts_with("template(") && call[7].starts_with("template("));
    assert_eq!(
        p.io.output(),
        ["generated 2048-bit rsa keypair hsm:pair#00000001 (public key shares the label/id)"]
    );
}

#[test]
fn test_generate_not_logged_in_fails_before_prompts() {
    let p = make_pair(&[]); // empty queue: any prompt would panic instead
    p.hsm.logout().unwrap();
    let err = run_line(&p.ctx, "generate hsm aes size=256 --label k").unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert!(err.message.contains("login required"));
    assert!(p.editor.titles().is_empty());
}

#[test]
fn generate_prompts_for_the_label_when_given_empty() {
    // c2 `_opt(args, "label") or _prompt_label(ctx)`: an empty --label prompts
    let p = make_pair(&["named"]);
    run_line(&p.ctx, "generate mem aes --label ''").unwrap();
    assert_eq!(p.io.prompts(), ["Key label"]);
    find(p.mem.as_ref(), "named");
    let p = make_pair(&["  "]);
    let err = run_line(&p.ctx, "generate mem aes").unwrap_err();
    assert_eq!(err.message, "label must not be empty");
}

// ---------------------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------------------

#[test]
fn test_load_inline_hex_aes() {
    let p = make_pair(&[]);
    run_line(&p.ctx, &format!("load mem aes {AES_HEX} --label lk")).unwrap();
    let info = find(p.mem.as_ref(), "lk");
    assert_eq!(info.key_class, KeyClass::Secret);
    assert_eq!(info.size_bits, Some(128));
    let text = p.io.text();
    assert!(text.contains("mem:lk"));
    assert_eq!(text.lines().next().unwrap().trim(), "loaded into mem");
}

#[test]
fn test_load_prompts_multiline_when_data_omitted() {
    let p = make_pair(&[AES_HEX, "pasted"]); // data paste, then label prompt
    run_line(&p.ctx, "load mem aes").unwrap();
    assert!(p.io.prompts()[0].starts_with("Paste key material"));
    assert_eq!(p.io.prompts()[0], "Paste key material (hex / base64 / PEM)");
    assert_eq!(find(p.mem.as_ref(), "pasted").key_class, KeyClass::Secret);
}

#[test]
fn test_load_pem_via_multiline_paste_uses_label_prompt() {
    let pem = String::from_utf8(rsa_private_pem()).unwrap();
    let p = make_pair(&[pem.as_str(), "mykey"]);
    run_line(&p.ctx, "load mem rsa").unwrap();
    let info = find(p.mem.as_ref(), "mykey");
    assert_eq!(
        (info.key_class, info.algorithm),
        (KeyClass::Private, KeyAlgorithm::Rsa)
    );
}

#[test]
fn test_load_bad_data_is_codec_error() {
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, "load mem aes zz-not-data --label x").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Codec);
}

#[test]
fn test_load_hint_excludes_raw_aes() {
    // 16 raw bytes only parse as AES when the hint allows it (§4.4)
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, &format!("load mem rsa {AES_HEX} --label x")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyParse);
    assert!(err.message.contains("could not parse"));
}

#[test]
fn test_load_unknown_hint() {
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, &format!("load mem dsa {AES_HEX}")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert!(err.message.contains("unknown key type hint"));
    assert_eq!(err.message, "unknown key type hint 'dsa'");
    assert_eq!(
        err.hint.as_deref(),
        Some("valid hints: auto, aes, rsa, ec, cert, generic, data")
    );
}

#[test]
fn test_load_file_form_with_format_hint() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("key.pem");
    std::fs::write(&key_file, rsa_private_pem()).unwrap();
    let p = make_pair(&[]);
    run_line(
        &p.ctx,
        &format!(
            "load mem --file {} --format rsa --label filed",
            key_file.display()
        ),
    )
    .unwrap();
    assert_eq!(find(p.mem.as_ref(), "filed").algorithm, KeyAlgorithm::Rsa);
}

#[test]
fn test_load_file_missing_raises_dataioerror() {
    let dir = tempfile::tempdir().unwrap();
    let p = make_pair(&[]);
    let err = run_line(
        &p.ctx,
        &format!(
            "load mem --file {} --label x",
            dir.path().join("nope.pem").display()
        ),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::DataIo);
    assert!(err.message.contains("cannot read"));
}

#[test]
fn test_load_file_form_rejects_inline_data() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("key.pem");
    std::fs::write(&key_file, rsa_private_pem()).unwrap();
    let p = make_pair(&[]);
    let err = run_line(
        &p.ctx,
        &format!("load mem stray --file {}", key_file.display()),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert!(err.message.contains("unexpected argument"));
    assert_eq!(err.message, "unexpected argument 'stray'");
}

#[test]
fn test_load_encrypted_file_with_password_option() {
    let encrypted = r2_core::formats::private_key_bytes(
        &rsa_pkcs8_der(),
        r2_core::formats::Encoding::Pem,
        Some(&SecretString::from("pw".to_owned())),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("enc.pem");
    std::fs::write(&key_file, encrypted.as_slice()).unwrap();
    let p = make_pair(&[]); // empty prompt queue: --password must prevent prompting
    run_line(
        &p.ctx,
        &format!(
            "load mem --file {} --password pw --label enc",
            key_file.display()
        ),
    )
    .unwrap();
    assert_eq!(find(p.mem.as_ref(), "enc").key_class, KeyClass::Private);
}

#[test]
fn test_load_into_pkcs11_applies_edited_template() {
    let p = make_pair(&[]);
    run_line(&p.ctx, &format!("load hsm aes {AES_HEX} --label hk")).unwrap();
    assert_eq!(p.editor.titles().len(), 1);
    // default §7 aes template: SENSITIVE=true/EXTRACTABLE=false → not exportable
    assert!(!find(p.hsm.as_ref(), "hk").exportable);
}

#[test]
fn test_load_p12_creates_shared_label_and_id() {
    let p12 = build_pkcs12(
        &rsa_pkcs8_der(),
        &rsa_cert_der(),
        "bundle",
        &SecretString::from("pw".to_owned()),
        &[],
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let p12_file = dir.path().join("bundle.p12");
    std::fs::write(&p12_file, p12).unwrap();
    let p = make_pair(&[]);
    run_line(
        &p.ctx,
        &format!(
            "load hsm --file {} --password pw --label bundle",
            p12_file.display()
        ),
    )
    .unwrap();
    let infos: Vec<_> = p
        .hsm
        .list_keys()
        .unwrap()
        .into_iter()
        .filter(|i| i.key_ref.label == "bundle")
        .collect();
    let classes: Vec<KeyClass> = infos.iter().map(|i| i.key_class).collect();
    assert_eq!(classes, [KeyClass::Private, KeyClass::Certificate]);
    assert_eq!(infos[0].key_ref.key_id, infos[1].key_ref.key_id); // §5.4: one label/CKA_ID
    assert_eq!(p.editor.titles().len(), 2); // one editor per created object
    assert!(p.io.text().contains("hsm:bundle")); // lists what was created
}

#[test]
fn test_load_not_logged_in() {
    let p = make_pair(&[]);
    p.hsm.logout().unwrap();
    let err = run_line(&p.ctx, &format!("load hsm aes {AES_HEX} --label x")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert!(err.message.contains("login required"));
}

#[test]
fn load_rejects_name_value_tokens_and_kek_is_delegated() {
    let p = make_pair(&[]);
    let err = run_line(&p.ctx, "load mem aes a=b").unwrap_err();
    assert_eq!(err.message, "unexpected name=value token 'a=…'");
    // --kek goes to R15's hook BEFORE reject_named (the name=value tokens are its params)
    let err = run_line(&p.ctx, "load mem aes 00 --kek k iv=00").unwrap_err();
    assert_ne!(err.message, "unexpected name=value token 'iv=…'");
}

// ---------------------------------------------------------------------------------------
// export
// ---------------------------------------------------------------------------------------

#[test]
fn test_export_secret_raw_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("key.bin");
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "aes1", None, None)
        .unwrap();
    run_line(&p.ctx, &format!("export mem:aes1 {}", out.display())).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), aes_32());
    assert!(
        p.io.output()
            .iter()
            .any(|line| line.contains("32 bytes") && line.contains("(raw)"))
    );
    assert_eq!(
        p.io.output(),
        [format!("wrote 32 bytes to {} (raw)", out.display())]
    );
}

#[test]
fn test_export_private_pem_and_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let p = make_pair(&[]);
    p.mem
        .import_key(&private_material(), "rsa1", None, None)
        .unwrap();
    let plain = dir.path().join("k.pem");
    let enc = dir.path().join("k.enc.pem");
    run_line(&p.ctx, &format!("export mem:rsa1 {}", plain.display())).unwrap();
    run_line(
        &p.ctx,
        &format!("export mem:rsa1 {} --password pw", enc.display()),
    )
    .unwrap();
    assert!(
        std::fs::read(&plain)
            .unwrap()
            .starts_with(b"-----BEGIN PRIVATE KEY-----")
    );
    let encrypted = std::fs::read(&enc).unwrap();
    assert!(contains(&encrypted, b"ENCRYPTED"));
    let mut pw = |_: &str| Ok(SecretString::from("pw".to_owned()));
    let reloaded = r2_core::keyparse::parse_key_material(
        &encrypted,
        r2_core::keyparse::KeyHint::Auto,
        Some(&mut pw),
    )
    .unwrap();
    assert_eq!(reloaded[0].data.as_slice(), rsa_pkcs8_der().as_slice());
}

#[test]
fn test_export_public_flag_writes_spki() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("pub.der");
    let p = make_pair(&[]);
    p.mem
        .import_key(&private_material(), "rsa1", None, None)
        .unwrap();
    run_line(
        &p.ctx,
        &format!("export mem:rsa1 {} --public --format der", out.display()),
    )
    .unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), rsa_spki_der());
}

#[test]
fn test_export_non_exportable_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = make_pair(&[]);
    p.hsm
        .import_key(&aes_material(), "locked", Some(&sensitive_template()), None)
        .unwrap();
    let out = dir.path().join("x.bin");
    let err = run_line(&p.ctx, &format!("export hsm:locked {}", out.display())).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(err.message.contains("Refusing to export"));
    assert!(!out.exists());
}

#[test]
fn test_export_p12_with_prompted_password() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("bundle.p12");
    let p = make_pair(&["pw", "pw"]); // password + confirmation (§5.6)
    p.mem
        .import_key(&private_material(), "solo", None, None)
        .unwrap();
    run_line(
        &p.ctx,
        &format!("export mem:solo {} --format p12", out.display()),
    )
    .unwrap();
    assert_eq!(
        p.io.prompts(),
        ["PKCS#12 password", "PKCS#12 password (again)"]
    );
    let loaded = load_p12(&std::fs::read(&out).unwrap(), "pw");
    assert_eq!(loaded[1].key_class, KeyClass::Certificate);
    // cert-missing path → §5.6 on-the-fly self-signed CN=<label>
    assert_eq!(cert_subject(&loaded[1].data), "CN=solo");
    assert!(p.io.output()[0].ends_with("(p12)"));
}

#[test]
fn test_export_p12_password_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let p = make_pair(&["pw", "different"]);
    p.mem
        .import_key(&private_material(), "solo", None, None)
        .unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "export mem:solo {} --format p12",
            dir.path().join("x.p12").display()
        ),
    )
    .unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "password".into()
        }
    );
    assert!(err.message.contains("do not match"));
    assert_eq!(err.message, "passwords do not match");
}

#[test]
fn test_export_p12_refusal_fires_before_password_prompt() {
    // §5.6 pre-flight: a doomed p12 export must not prompt for a password (the empty queue
    // doubles as a tripwire).
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("x.p12");
    let p = make_pair(&[]);
    p.hsm
        .import_key(
            &private_material(),
            "locked",
            Some(&sensitive_template()),
            None,
        )
        .unwrap();
    let err = run_line(
        &p.ctx,
        &format!("export hsm:locked {} --format p12", out.display()),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(err.message.contains("Refusing to export"));
    assert!(p.io.prompts().is_empty()); // no password prompt for a refused export
    assert!(!out.exists());
}

#[test]
fn test_export_public_with_password_rejected() {
    // --public --password errors instead of silently writing unencrypted SPKI.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("pub.pem");
    let p = make_pair(&[]);
    p.mem
        .import_key(&private_material(), "rsa1", None, None)
        .unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "export mem:rsa1 {} --public --password sekrit",
            out.display()
        ),
    )
    .unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Param { .. }));
    assert!(err.message.contains("private-key and p12"));
    assert!(!out.exists());
}

#[test]
fn test_export_secret_with_password_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("key.bin");
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "aes1", None, None)
        .unwrap();
    let err = run_line(
        &p.ctx,
        &format!("export mem:aes1 {} --password sekrit", out.display()),
    )
    .unwrap_err();
    assert!(err.message.contains("private-key and p12"));
    assert!(!out.exists());
}

#[test]
fn test_export_p12_with_cert_ref_from_other_provider() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("bundle.p12");
    let p = make_pair(&[]);
    p.mem
        .import_key(&private_material(), "solo", None, None)
        .unwrap();
    p.hsm
        .import_key(&cert_material(), "trust", None, None)
        .unwrap();
    run_line(
        &p.ctx,
        &format!(
            "export mem:solo {} --format p12 --cert hsm:trust --password pw",
            out.display()
        ),
    )
    .unwrap();
    let loaded = load_p12(&std::fs::read(&out).unwrap(), "pw");
    assert_eq!(cert_subject(&loaded[1].data), "CN=unit-test-cert");
}

#[test]
fn test_export_p12_cert_ref_must_be_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let p = make_pair(&[]);
    p.mem
        .import_key(&private_material(), "solo", None, None)
        .unwrap();
    p.mem
        .import_key(&public_material(), "pub", None, None)
        .unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "export mem:solo {} --format p12 --cert mem:pub --password pw",
            dir.path().join("x.p12").display()
        ),
    )
    .unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "cert".into()
        }
    );
    assert!(err.message.contains("certificate"));
    assert_eq!(
        err.message,
        "--cert must reference a certificate, got public 'mem:pub'"
    );
}

#[test]
fn test_export_cert_option_without_p12() {
    let dir = tempfile::tempdir().unwrap();
    let p = make_pair(&[]);
    p.mem
        .import_key(&private_material(), "solo", None, None)
        .unwrap();
    p.mem
        .import_key(&cert_material(), "trust", None, None)
        .unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "export mem:solo {} --cert mem:trust",
            dir.path().join("x.pem").display()
        ),
    )
    .unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "cert".into()
        }
    );
    assert!(err.message.contains("p12"));
}

#[test]
fn test_export_public_with_p12_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let p = make_pair(&[]);
    p.mem
        .import_key(&private_material(), "solo", None, None)
        .unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "export mem:solo {} --format p12 --public",
            dir.path().join("x.p12").display()
        ),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert!(err.message.contains("--public"));
    assert_eq!(
        err.hint.as_deref(),
        Some("a PKCS#12 contains the private key (§5.6)")
    );
}

#[test]
fn test_export_missing_path_argument() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "aes1", None, None)
        .unwrap();
    let err = run_line(&p.ctx, "export mem:aes1").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Generic);
    assert!(err.message.contains("missing <path>"));
}

#[test]
fn export_option_errors() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("x");
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "aes1", None, None)
        .unwrap();
    let err = run_line(
        &p.ctx,
        &format!("export mem:aes1 {} --format jwk", out.display()),
    )
    .unwrap_err();
    assert_eq!(err.message, "unknown export format 'jwk'");
    let err = run_line(
        &p.ctx,
        &format!("export mem:aes1 {} --outformat hex", out.display()),
    )
    .unwrap_err();
    assert_eq!(err.message, "--outformat applies only to wrapped exports");
    assert_eq!(
        err.hint.as_deref(),
        Some("plain exports are shaped by --format; add --kek <label> to write a wrapped blob")
    );
}

#[test]
fn export_path_is_python_normalized() {
    let dir = tempfile::tempdir().unwrap();
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "aes1", None, None)
        .unwrap();
    let path = format!("{}//./key.bin", dir.path().display());
    run_line(&p.ctx, &format!("export mem:aes1 {path}")).unwrap();
    assert_eq!(
        p.io.output(),
        [format!(
            "wrote 32 bytes to {} (raw)",
            dir.path().join("key.bin").display()
        )]
    );
}

// ---------------------------------------------------------------------------------------
// csr
// ---------------------------------------------------------------------------------------

#[test]
fn test_csr_writes_pem_with_default_subject() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("req.csr");
    let p = make_pair(&[]);
    p.mem
        .import_key(&private_material(), "webkey", None, None)
        .unwrap();
    run_line(&p.ctx, &format!("csr mem:webkey {}", out.display())).unwrap();
    let data = std::fs::read(&out).unwrap();
    assert!(data.starts_with(b"-----BEGIN CERTIFICATE REQUEST-----"));
    let (subject, _) = csr_subject_and_algorithm(&data);
    assert_eq!(subject, "CN=webkey"); // §5.7 default subject
    assert!(p.io.output().iter().any(|line| line.contains("wrote CSR")));
    assert_eq!(
        p.io.output(),
        [format!(
            "wrote CSR for mem:webkey to {} (subject: CN=webkey)",
            out.display()
        )]
    );
}

#[test]
fn test_csr_subject_and_hash_options() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("req.csr");
    let p = make_pair(&[]);
    p.mem
        .import_key(&private_material(), "webkey", None, None)
        .unwrap();
    run_line(
        &p.ctx,
        &format!(
            "csr mem:webkey {} --subject \"CN=api,O=ACME\" --hash sha384",
            out.display()
        ),
    )
    .unwrap();
    let (subject, algorithm) = csr_subject_and_algorithm(&std::fs::read(&out).unwrap());
    assert_eq!(subject, "CN=api,O=ACME");
    // sha384WithRSAEncryption
    assert!(contains(
        &algorithm,
        &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c
        ]
    ));
}

#[test]
fn test_csr_bad_hash() {
    let dir = tempfile::tempdir().unwrap();
    let p = make_pair(&[]);
    p.mem
        .import_key(&private_material(), "webkey", None, None)
        .unwrap();
    let err = run_line(
        &p.ctx,
        &format!(
            "csr mem:webkey {} --hash md5",
            dir.path().join("x.csr").display()
        ),
    )
    .unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "hash".into()
        }
    );
    assert!(err.message.contains("hash"));
}

// ---------------------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------------------

#[test]
fn test_delete_confirms_then_deletes() {
    let p = make_pair(&["y"]);
    p.mem
        .import_key(&aes_material(), "gone", None, None)
        .unwrap();
    run_line(&p.ctx, "delete mem:gone").unwrap();
    assert!(p.mem.list_keys().unwrap().is_empty());
    assert!(
        p.io.output()
            .iter()
            .any(|line| line.contains("deleted mem:gone"))
    );
    assert_eq!(p.io.prompts(), ["delete mem:gone (secret)?"]);
}

#[test]
fn test_delete_declined_keeps_key() {
    let p = make_pair(&["n"]);
    p.mem
        .import_key(&aes_material(), "stays", None, None)
        .unwrap();
    run_line(&p.ctx, "delete mem:stays").unwrap();
    assert_eq!(p.mem.list_keys().unwrap().len(), 1);
    assert!(p.io.output().contains(&"delete cancelled".to_owned()));
}

#[test]
fn test_delete_without_confirmation_when_disabled() {
    let config = make_config(Some("ui:\n  confirm_delete: false\n"));
    let p = make_pair_with(&[], Some(config), SpyEditor::new()); // a confirm() would panic
    p.mem
        .import_key(&aes_material(), "gone", None, None)
        .unwrap();
    run_line(&p.ctx, "delete mem:gone").unwrap();
    assert!(p.mem.list_keys().unwrap().is_empty());
}

#[test]
fn test_delete_class_qualified_removes_only_that_half() {
    let p = make_pair(&["y"]);
    generate(p.mem.as_ref(), KeyAlgorithm::Rsa, "pair");
    run_line(&p.ctx, "delete mem:pair:pub").unwrap();
    let classes: Vec<KeyClass> = p
        .mem
        .list_keys()
        .unwrap()
        .iter()
        .map(|k| k.key_class)
        .collect();
    assert_eq!(classes, [KeyClass::Private]);
}

#[test]
fn test_delete_unqualified_keypair_still_takes_private_half() {
    let p = make_pair(&["y"]);
    generate(p.mem.as_ref(), KeyAlgorithm::Rsa, "pair");
    run_line(&p.ctx, "delete mem:pair").unwrap(); // class preference: the private
    let classes: Vec<KeyClass> = p
        .mem
        .list_keys()
        .unwrap()
        .iter()
        .map(|k| k.key_class)
        .collect();
    assert_eq!(classes, [KeyClass::Public]);
}

// ---------------------------------------------------------------------------------------
// completion
// ---------------------------------------------------------------------------------------

#[test]
fn test_export_and_csr_complete_selector_stages() {
    // §4.3 selector continuations reach every complete_refs consumer
    let p = make_pair(&[]);
    generate(p.mem.as_ref(), KeyAlgorithm::Ec, "pair");
    let family = ["mem:pair:priv", "mem:pair:pub"];
    let mut got = complete(&p.ctx, "csr", &["csr", "mem:pair:"], "mem:pair:");
    got.sort();
    assert_eq!(got, family);
    let mut got = complete(
        &p.ctx,
        "export",
        &["export", "mem:pair", "out.p12", "--cert", "mem:pair:"],
        "mem:pair:",
    );
    got.sort();
    assert_eq!(got, family);
}

/// alpha.txt, beta.bin, subdir/, .hidden (c2 test_l13_hardening `tree` fixture).
fn tree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("alpha.txt"), b"a").unwrap();
    std::fs::write(dir.path().join("beta.bin"), b"b").unwrap();
    std::fs::create_dir(dir.path().join("subdir")).unwrap();
    std::fs::write(dir.path().join(".hidden"), b"h").unwrap();
    dir
}

#[test]
fn test_export_and_csr_path_positionals_complete() {
    let tree = tree();
    let root = tree.path().display().to_string();
    let p = make_pair(&[]);
    let prefix = format!("{root}/be");
    assert_eq!(
        complete(
            &p.ctx,
            "export",
            &["export", "mem:aeskey", &prefix],
            &prefix
        ),
        [format!("{root}/beta.bin")]
    );
    assert_eq!(
        complete(&p.ctx, "csr", &["csr", "mem:eckey", &prefix], &prefix),
        [format!("{root}/beta.bin")]
    );
    // export --cert completes key refs, not paths
    let cert_refs = complete(
        &p.ctx,
        "export",
        &["export", "mem:x", "p.p12", "--cert"],
        "",
    );
    assert!(cert_refs.iter().any(|r| r.starts_with("mem:")));
}

#[test]
fn test_load_file_option_completes_paths() {
    let tree = tree();
    let root = tree.path().display().to_string();
    let p = make_pair(&[]);
    let prefix = format!("{root}/");
    let out = complete(&p.ctx, "load", &["load", "mem", "--file", &prefix], &prefix);
    assert!(out.contains(&format!("{root}/alpha.txt")));
    assert!(out.contains(&format!("{root}/subdir/")));
}

#[test]
fn key_commands_complete_their_stages() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "comp", None, None)
        .unwrap();
    assert_eq!(complete(&p.ctx, "keys", &["keys"], ""), ["mem", "hsm"]);
    assert!(complete(&p.ctx, "keys", &["keys", "mem"], "").is_empty());
    assert!(complete(&p.ctx, "delete", &["delete", "mem:"], "mem:").contains(&"mem:comp".into()));
    assert!(complete(&p.ctx, "delete", &["delete", "mem:comp"], "").is_empty());
    assert_eq!(
        complete(&p.ctx, "csr", &["csr", "mem:comp", "x.csr"], ""),
        ["--subject", "--hash"]
    );
    assert_eq!(
        complete(&p.ctx, "csr", &["csr", "mem:comp", "x.csr", "--hash"], ""),
        ["sha256", "sha384", "sha512"]
    );
    assert!(
        complete(
            &p.ctx,
            "csr",
            &["csr", "mem:comp", "x.csr", "--subject"],
            ""
        )
        .is_empty()
    );
    assert_eq!(
        complete(
            &p.ctx,
            "export",
            &["export", "mem:comp", "x", "--format"],
            ""
        ),
        ["auto", "raw", "der", "pem", "p12"]
    );
    assert!(
        complete(
            &p.ctx,
            "export",
            &["export", "mem:comp", "x", "--password"],
            ""
        )
        .is_empty()
    );
    let options = complete(&p.ctx, "export", &["export", "mem:comp", "x"], "");
    for option in [
        "--format",
        "--public",
        "--cert",
        "--password",
        "--kek",
        "--mech",
        "--outformat",
    ] {
        assert!(options.contains(&option.to_owned()), "{option}");
    }
    assert_eq!(
        complete(&p.ctx, "generate", &["generate", "mem", "aes"], ""),
        [
            "--label",
            "--id",
            "--template",
            "size=128",
            "size=192",
            "size=256"
        ]
    );
    assert!(
        complete(&p.ctx, "generate", &["generate", "mem", "ec"], "")
            .contains(&"curve=x448".to_owned())
    );
    assert!(
        complete(&p.ctx, "generate", &["generate", "mem", "rsa"], "")
            .contains(&"size=4096".to_owned())
    );
    let load = complete(&p.ctx, "load", &["load", "mem"], "");
    assert_eq!(load.last().unwrap(), "--file");
    let load = complete(&p.ctx, "load", &["load", "mem", "aes"], "");
    for option in [
        "--label",
        "--id",
        "--file",
        "--format",
        "--password",
        "--template",
        "--kek",
        "--mech",
    ] {
        assert!(load.contains(&option.to_owned()), "{option}");
    }
    assert!(p.io.prompts().is_empty() && p.io.output().is_empty()); // never touches ctx.io
}

// ---------------------------------------------------------------------------------------
// key edit (§5.15)
// ---------------------------------------------------------------------------------------

fn update_calls(provider: &r2_testkit::FakeProvider) -> Vec<Vec<String>> {
    calls_of(provider, "update_key")
}

#[test]
fn test_key_edit_flags_rename_on_memory() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "oldname", None, None)
        .unwrap();
    run_line(&p.ctx, "key edit mem:oldname --label newname").unwrap();
    let text = p.io.text();
    assert!(text.contains("CKA_LABEL"));
    assert!(text.contains("applied"));
    assert_eq!(text.lines().next().unwrap().trim(), "edit mem:oldname");
    assert!(
        p.io.output()
            .iter()
            .any(|line| line.contains("now mem:newname"))
    );
    assert_eq!(find(p.mem.as_ref(), "newname").key_ref.label, "newname");
    assert_eq!(update_calls(&p.mem).len(), 1);
}

#[test]
fn test_key_edit_flags_same_value_is_no_change() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "same", None, None)
        .unwrap();
    run_line(&p.ctx, "key edit mem:same --label same").unwrap();
    assert_eq!(p.io.output(), ["no changes"]);
    assert!(update_calls(&p.mem).is_empty());
}

#[test]
fn key_edit_flag_errors() {
    let p = make_pair(&[]);
    p.mem.import_key(&aes_material(), "k", None, None).unwrap();
    let err = run_line(&p.ctx, "key edit mem:k --label ''").unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::Param {
            param_name: "label".into()
        }
    );
    assert_eq!(err.message, "label must not be empty");
    let err = run_line(&p.ctx, "key edit mem:k --id zz").unwrap_err();
    assert_eq!(err.message, "invalid key id 'zz'");
}

#[test]
fn test_key_edit_editor_flow_passes_diff_only() {
    let editor = SpyEditor::editing(|template: &mut KeyTemplate| {
        template
            .set("CKA_SENSITIVE", AttrValue::Bool(true))
            .unwrap();
    });
    let p = make_pair_with(&[], None, editor);
    p.hsm
        .import_key(&aes_material(), "hkey", None, None)
        .unwrap();
    run_line(&p.ctx, "key edit hsm:hkey").unwrap();
    assert_eq!(
        p.editor.titles(),
        ["PKCS#11 attributes — hsm:hkey#00000001"]
    );
    let calls = update_calls(&p.hsm);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0][2], "template(1 attrs)"); // only the changed row travels
    let text = p.io.text();
    assert!(text.contains("CKA_SENSITIVE"));
    assert!(text.contains("true"));
    assert!(text.contains("applied"));
}

#[test]
fn test_key_edit_identity_editor_is_no_change() {
    let p = make_pair(&[]);
    p.hsm
        .import_key(&aes_material(), "hkey2", None, None)
        .unwrap();
    run_line(&p.ctx, "key edit hsm:hkey2").unwrap();
    assert_eq!(
        p.editor.titles(),
        ["PKCS#11 attributes — hsm:hkey2#00000001"]
    );
    assert_eq!(p.io.output(), ["no changes"]);
    assert!(update_calls(&p.hsm).is_empty());
}

#[test]
fn test_key_edit_editor_disabled_row_means_keep() {
    let editor = SpyEditor::editing(|template: &mut KeyTemplate| {
        template.get_mut("CKA_EXTRACTABLE").unwrap().enabled = false;
    });
    let p = make_pair_with(&[], None, editor);
    p.hsm
        .import_key(&aes_material(), "hkey3", None, None)
        .unwrap();
    run_line(&p.ctx, "key edit hsm:hkey3").unwrap();
    assert_eq!(p.io.output(), ["no changes"]);
    assert!(update_calls(&p.hsm).is_empty());
}

#[test]
fn test_key_edit_editor_added_row_travels_and_failure_renders() {
    let editor = SpyEditor::editing(|template: &mut KeyTemplate| {
        template.attrs.push(TemplateAttr::new(
            "CKA_WRAP",
            AttrKind::Bool,
            AttrValue::Bool(true),
        ));
    });
    let p = make_pair_with(&[], None, editor);
    p.hsm
        .import_key(&aes_material(), "hkey4", None, None)
        .unwrap();
    run_line(&p.ctx, "key edit hsm:hkey4").unwrap();
    let text = p.io.text();
    assert!(text.contains("CKA_WRAP"));
    assert!(text.contains("failed — not supported by FakeProvider"));
}

#[test]
fn key_edit_re_enabled_empty_id_row_assigns_an_id() {
    let p = make_pair_with(
        &[],
        None,
        SpyEditor::editing(|template: &mut KeyTemplate| {
            let row = template.get_mut("CKA_ID").unwrap();
            row.enabled = true;
            row.value = AttrValue::Bytes(vec![0xc0, 0xfe]);
        }),
    );
    // a pkcs11 object without CKA_ID (backdoor: FakeProvider would assign one)
    p.hsm
        .store_key_unchecked(&aes_material(), "noid", None, None);
    run_line(&p.ctx, "key edit hsm:noid").unwrap();
    assert!(p.io.text().contains("0xc0fe"));
    assert_eq!(p.io.output().last().unwrap(), "now hsm:noid#c0fe");
}

#[test]
fn test_key_edit_memory_prompt_flow() {
    let p = make_pair(&["promptname", ""]); // new label; empty = keep id
    p.mem
        .import_key(&aes_material(), "promptable", None, None)
        .unwrap();
    run_line(&p.ctx, "key edit mem:promptable").unwrap();
    assert_eq!(
        p.io.prompts(),
        [
            "New label (empty = keep 'promptable')",
            "New id hex (empty = keep -)"
        ]
    );
    assert_eq!(
        find(p.mem.as_ref(), "promptname").key_ref.label,
        "promptname"
    );
}

#[test]
fn key_edit_memory_prompted_id() {
    let p = make_pair(&["", "0x0a1b"]);
    p.mem
        .import_key(&aes_material(), "k", None, Some(&[0x01]))
        .unwrap();
    run_line(&p.ctx, "key edit mem:k").unwrap();
    assert_eq!(p.io.prompts()[1], "New id hex (empty = keep 01)");
    assert_eq!(p.io.output().last().unwrap(), "now mem:k#0a1b");
    let p = make_pair(&["", "zz"]);
    p.mem.import_key(&aes_material(), "k", None, None).unwrap();
    let err = run_line(&p.ctx, "key edit mem:k").unwrap_err();
    assert_eq!(err.message, "invalid key id 'zz'");
    assert_eq!(err.hint.as_deref(), Some("whole hex bytes, e.g. 0a1b"));
}

#[test]
fn test_key_edit_memory_prompts_all_empty_is_no_change() {
    let p = make_pair(&["", ""]);
    p.mem
        .import_key(&aes_material(), "keepme", None, None)
        .unwrap();
    run_line(&p.ctx, "key edit mem:keepme").unwrap();
    assert_eq!(p.io.output(), ["no changes"]);
    assert!(update_calls(&p.mem).is_empty());
}

#[test]
fn test_key_edit_family_rename_confirmed_renames_siblings() {
    let p = make_pair(&["y"]); // confirm: rename siblings too
    generate(p.hsm.as_ref(), KeyAlgorithm::Rsa, "pair");
    run_line(&p.ctx, "key edit hsm:pair:priv --label pair2").unwrap();
    assert!(
        p.io.prompts()
            .last()
            .unwrap()
            .contains("rename 1 related object(s)")
    );
    assert_eq!(
        p.io.prompts().last().unwrap(),
        "rename 1 related object(s) sharing this label/id too?"
    );
    assert_eq!(
        find_class(p.hsm.as_ref(), "pair2", KeyClass::Private)
            .key_ref
            .label,
        "pair2"
    );
    assert_eq!(
        find_class(p.hsm.as_ref(), "pair2", KeyClass::Public)
            .key_ref
            .label,
        "pair2"
    );
    assert_eq!(update_calls(&p.hsm).len(), 2); // target + one sibling
    assert!(p.io.text().contains(":pub")); // sibling outcome row names the object
}

#[test]
fn test_key_edit_family_rename_declined_touches_target_only() {
    let p = make_pair(&["n"]);
    generate(p.hsm.as_ref(), KeyAlgorithm::Rsa, "lone");
    run_line(&p.ctx, "key edit hsm:lone:priv --label lone2").unwrap();
    assert_eq!(
        find_class(p.hsm.as_ref(), "lone2", KeyClass::Private)
            .key_ref
            .label,
        "lone2"
    );
    assert_eq!(
        find_class(p.hsm.as_ref(), "lone", KeyClass::Public)
            .key_ref
            .label,
        "lone"
    );
    assert_eq!(update_calls(&p.hsm).len(), 1);
}

#[test]
fn test_key_edit_sibling_duplicate_becomes_failed_row() {
    let p = make_pair(&["y"]);
    generate(p.hsm.as_ref(), KeyAlgorithm::Rsa, "clash");
    let private = find_class(p.hsm.as_ref(), "clash", KeyClass::Private);
    let shared_id = private.key_ref.key_id.clone().unwrap();
    // a foreign PUBLIC object already occupies the target identity (backdoor fixture)
    p.hsm
        .store_key_unchecked(&public_material(), "clash2", None, Some(&shared_id));
    run_line(&p.ctx, "key edit hsm:clash:priv --label clash2").unwrap();
    assert_eq!(
        find_class(p.hsm.as_ref(), "clash2", KeyClass::Private)
            .key_ref
            .label,
        "clash2"
    );
    assert!(
        p.io.text()
            .contains("failed — a public object with label 'clash2'")
    );
    assert_eq!(
        find_class(p.hsm.as_ref(), "clash", KeyClass::Public)
            .key_ref
            .label,
        "clash"
    );
}

#[test]
fn test_key_edit_logged_out_hsm_raises() {
    let p = make_pair(&[]);
    p.hsm
        .import_key(&aes_material(), "locked", None, None)
        .unwrap();
    p.hsm.logout().unwrap();
    let err = run_line(&p.ctx, "key edit hsm:locked --label other").unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
}

#[test]
fn test_key_edit_duplicate_target_propagates() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "taken", None, None)
        .unwrap();
    p.mem
        .import_key(&aes_material(), "source", None, None)
        .unwrap();
    let err = run_line(&p.ctx, "key edit mem:source --label taken").unwrap_err();
    assert_eq!(err.kind, ErrorKind::DuplicateKey);
    assert_eq!(find(p.mem.as_ref(), "source").key_ref.label, "source");
}

#[test]
fn test_key_edit_completion() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "comp", None, None)
        .unwrap();
    let mut subs = complete(&p.ctx, "key", &["key"], "");
    subs.sort();
    assert_eq!(subs, ["edit", "info", "template"]);
    assert!(complete(&p.ctx, "key", &["key", "edit", "mem:"], "mem:").contains(&"mem:comp".into()));
    assert_eq!(
        complete(&p.ctx, "key", &["key", "edit", "mem:comp"], ""),
        ["--label", "--id"]
    );
    assert!(complete(&p.ctx, "key", &["key", "info", "mem:comp"], "").is_empty());
}

#[test]
fn key_template_is_delegated_to_the_r14_hook() {
    let p = make_pair(&[]);
    p.mem.import_key(&aes_material(), "k", None, None).unwrap();
    // memory keys are refused by R14's hook — the `key` command routes the subcommand
    // there and renders nothing itself
    let err = run_line(&p.ctx, "key template mem:k /dev/null").unwrap_err();
    assert_eq!(
        err.message, "key template works only with PKCS#11 providers",
        "{}",
        err.message
    );
    assert!(p.io.output().is_empty());
}

#[test]
fn sibling_rename_stops_at_the_interrupt_flag() {
    let _lock = r2_testkit::global_state_lock();
    let p = make_pair(&["y"]);
    generate(p.hsm.as_ref(), KeyAlgorithm::Rsa, "pair");
    r2_core::runtime::request_interrupt_on_this_thread();
    let err = run_line(&p.ctx, "key edit hsm:pair:priv --label pair2");
    r2_core::runtime::reset_interrupt();
    let err = err.unwrap_err();
    assert_eq!(err.kind, ErrorKind::UserAbort);
    // the target was renamed, the sibling was not (step boundary, §11 D13)
    assert_eq!(update_calls(&p.hsm).len(), 1);
}

#[test]
fn keys_command_has_no_flags_and_export_login_flags() {
    let commands = all_commands().unwrap();
    assert_eq!(commands["export"].flags(), ["public"]);
    assert_eq!(commands["login"].flags(), ["keep-pin"]);
    assert!(commands["keys"].flags().is_empty());
    for name in ["keys", "key", "generate", "load", "export", "csr", "delete"] {
        assert!(commands.contains_key(name), "{name}");
    }
    let _ = Rc::clone(&commands);
}

#[test]
fn export_public_on_a_lone_non_exportable_private_is_key_not_found() {
    // §5.6 shipped nuance: the public part comes from a co-located PUBLIC/CERTIFICATE
    // object; a lone sensitive private key has none
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("pub.pem");
    let p = make_pair(&[]);
    p.hsm
        .import_key(
            &private_material(),
            "lone",
            Some(&sensitive_template()),
            None,
        )
        .unwrap();
    let err = run_line(
        &p.ctx,
        &format!("export hsm:lone {} --public", out.display()),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotFound);
    assert_eq!(err.message, "no public part found for 'hsm:lone#00000001'");
    assert!(
        err.hint
            .unwrap()
            .contains("no public key or certificate shares its label/CKA_ID")
    );
    assert!(!out.exists());
    // the plain export of the same key is the §5.6 refusal, pointing at --public
    let err = run_line(&p.ctx, &format!("export hsm:lone {}", out.display())).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert_eq!(
        err.hint.as_deref(),
        Some("public key available with `export hsm:lone#00000001 <path> --public`")
    );
}

#[test]
fn ambiguous_refs_carry_their_candidates() {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "dup", None, None)
        .unwrap();
    p.mem
        .store_key_unchecked(&aes_material(), "dup", None, None);
    for line in [
        "key info mem:dup",
        "delete mem:dup",
        "export mem:dup x.bin",
        "csr mem:dup x.csr",
    ] {
        let err = run_line(&p.ctx, line).unwrap_err();
        let candidates: Vec<String> = err
            .candidates()
            .unwrap()
            .iter()
            .map(|r| r.display())
            .collect();
        assert_eq!(candidates, ["mem:dup", "mem:dup"], "{line}");
        assert_eq!(
            err.message,
            "'dup' matches 2 keys on mem: mem:dup:secret@1, mem:dup:secret@2"
        );
    }
}
