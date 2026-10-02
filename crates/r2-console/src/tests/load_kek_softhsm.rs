// `load --kek` (§5.4) and the `export --kek` → `load --kek` round-trip (§5.6) on a real
// SoftHSM2 token — port of c2 tests/integration/test_load_kek.py (R15). Feature
// `softhsm`; fails (never skips) without the fixture of `scripts/softhsm-init.sh`.
//
// c2 drove `app.main` with a §5.16 template file (`--template`) giving the KEKs
// CKA_WRAP/CKA_UNWRAP and keeping the results readable. r2 drives the same command lines
// through `run_line` on a session whose template editor applies exactly those sections
// (the §5.12 editor is the operator's other way to set the same attributes), so the ports
// run before R14's `--template` lands; one `--template` variant is kept for the merge
// checklist. Blobs are wrapped in software against key material the test knows — with the
// real MemoryProvider (OpenSSL) standing in for c2's pyca.
//
// AES-KW/KWP and the RSA rungs are hard-asserted. The AES-CBC and EC legs were
// `xfail(strict=False)` in c2: `mechanisms()` folds CKM presence, not CKF_WRAP, so a token
// may refuse them for C_UnwrapKey (§5.4 residual) — r2 tolerates exactly a PKCS#11 /
// unsupported-operation refusal there and checks the bytes otherwise.
#![cfg(feature = "softhsm")]

use std::collections::BTreeMap;
use std::path::Path;
use std::rc::Rc;

use indexmap::IndexMap;
use r2_config::model::Pkcs11InstanceConfig;
use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::formats;
use r2_core::io::{ConsoleIo, TemplateEditor};
use r2_core::keyparse::{KeyHint, parse_key_material};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_core::params::{ParamValue, Params};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_memory::MemoryProvider;
use r2_pkcs11::Pkcs11Provider;
use r2_provider::{MechanismInvocation, Provider, ProviderRegistry, WrapOptions};
use r2_testkit::softhsm::{softhsm_token, unique_label};
use r2_testkit::{ScriptedIo, global_state_lock};

use crate::context::AppContext;
use crate::testing::{CtxBuilder, make_config, run_line};

const KEK_BYTES: [u8; 32] = {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = i as u8;
        i += 1;
    }
    out
};
const TARGET_BYTES: [u8; 32] = {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = 32 + i as u8;
        i += 1;
    }
    out
};

type Section = &'static [(&'static str, bool)];

/// c2 `_template_file`: KEKs need CKA_WRAP/CKA_UNWRAP, and the unwrapped results must stay
/// readable so the test can compare key bytes (the §7 defaults are deliberately
/// sensitive/non-extractable).
const AES: Section = &[
    ("CKA_TOKEN", true),
    ("CKA_PRIVATE", true),
    ("CKA_SENSITIVE", false),
    ("CKA_EXTRACTABLE", true),
    ("CKA_ENCRYPT", true),
    ("CKA_DECRYPT", true),
    ("CKA_WRAP", true),
    ("CKA_UNWRAP", true),
];
const RSA_PRIVATE: Section = &[
    ("CKA_TOKEN", true),
    ("CKA_PRIVATE", true),
    ("CKA_SENSITIVE", true),
    ("CKA_EXTRACTABLE", false),
    ("CKA_DECRYPT", true),
    ("CKA_SIGN", true),
    ("CKA_UNWRAP", true),
];
const RSA_PUBLIC: Section = &[
    ("CKA_TOKEN", true),
    ("CKA_PRIVATE", false),
    ("CKA_ENCRYPT", true),
    ("CKA_VERIFY", true),
    ("CKA_WRAP", true),
];
const EC_PRIVATE: Section = &[
    ("CKA_TOKEN", true),
    ("CKA_PRIVATE", true),
    ("CKA_SENSITIVE", false),
    ("CKA_EXTRACTABLE", true),
    ("CKA_SIGN", true),
    ("CKA_DERIVE", true),
];
/// c2 `sensitive.yaml` of test_sensitive_key_exports_wrapped_but_not_plain.
const AES_SENSITIVE: Section = &[
    ("CKA_TOKEN", true),
    ("CKA_PRIVATE", true),
    ("CKA_SENSITIVE", true),
    ("CKA_EXTRACTABLE", true),
    ("CKA_ENCRYPT", true),
    ("CKA_DECRYPT", true),
];

/// The editor answers of c2's template-file sections: every opening applies the section
/// for the title's class (`aes` / `rsa_private` / `rsa_public` / `ec_private`); `override`
/// replaces the aes section for editor titles naming one label.
struct SectionEditor {
    aes_override: Option<(String, Section)>,
}

fn apply(template: &mut KeyTemplate, section: Section) {
    for (name, value) in section {
        if let Some(attr) = template.attrs.iter_mut().find(|a| a.name == *name) {
            attr.value = AttrValue::Bool(*value);
            attr.enabled = true;
        } else {
            template.attrs.push(TemplateAttr::new(
                *name,
                AttrKind::Bool,
                AttrValue::Bool(*value),
            ));
        }
    }
}

impl TemplateEditor for SectionEditor {
    fn edit(&self, mut template: KeyTemplate, title: &str) -> Result<KeyTemplate> {
        let section = if title.contains("AES key '") || title.contains("aes secret '") {
            match &self.aes_override {
                Some((label, section)) if title.contains(&format!("'{label}'")) => *section,
                _ => AES,
            }
        } else if title.contains("rsa private") {
            RSA_PRIVATE
        } else if title.contains("rsa public") {
            RSA_PUBLIC
        } else if title.contains("ec private") {
            EC_PRIVATE
        } else {
            return Err(ConsoleError::generic(format!("unexpected editor: {title}")));
        };
        apply(&mut template, section);
        Ok(template)
    }
}

struct Session {
    ctx: Rc<AppContext>,
    io: Rc<ScriptedIo>,
    hsm: Rc<Pkcs11Provider>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

fn session_with(aes_override: Option<(String, Section)>) -> Session {
    session_with_editor(Rc::new(SectionEditor { aes_override }))
}

fn session_with_editor(editor: Rc<dyn TemplateEditor>) -> Session {
    let lock = global_state_lock();
    let token = softhsm_token();
    let mut config = Pkcs11InstanceConfig::new("hsm", token.module_path.clone());
    config.slot = Some(token.slot);
    let hsm = Rc::new(Pkcs11Provider::new(
        "hsm",
        config,
        BTreeMap::new(),
        IndexMap::new(),
    ));
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::clone(&hsm) as Rc<dyn Provider>)
        .unwrap();
    let io = Rc::new(ScriptedIo::empty());
    let ctx = CtxBuilder::new(Rc::clone(&io) as Rc<dyn ConsoleIo>)
        .providers(registry)
        .config(make_config(Some("ui:\n  confirm_delete: false\n")))
        .editor(editor)
        .build();
    let session = Session {
        ctx,
        io,
        hsm,
        _lock: lock,
    };
    session.ok(&format!(
        "login hsm {} --pin {}",
        token.token_label, token.user_pin
    ));
    session
}

/// The editor of c2's literal `--template <file>` lines: it accepts the §5.16 seed
/// unchanged ("ok"), so only the file sets attributes.
struct Identity;

impl TemplateEditor for Identity {
    fn edit(&self, template: KeyTemplate, _title: &str) -> Result<KeyTemplate> {
        Ok(template)
    }
}

/// A session for c2's literal `--template <file>` form (§5.16 seeding, R14).
fn literal_session() -> Session {
    session_with_editor(Rc::new(Identity))
}

/// Writes a §5.16 template file holding the given c2 sections.
fn template_file(dir: &Path, name: &str, sections: &[(&str, Section)]) -> std::path::PathBuf {
    let mut text = String::new();
    for (class, entries) in sections {
        text.push_str(&format!("{class}:\n"));
        for (attr, value) in *entries {
            text.push_str(&format!("  {attr}: {value}\n"));
        }
    }
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

/// c2 `_template_file`: every section of `wrapload.yaml`.
fn c2_template_file(dir: &Path) -> std::path::PathBuf {
    template_file(
        dir,
        "wrapload.yaml",
        &[
            ("aes", AES),
            ("rsa_private", RSA_PRIVATE),
            ("rsa_public", RSA_PUBLIC),
            ("ec_private", EC_PRIVATE),
        ],
    )
}

fn session() -> Session {
    session_with(None)
}

impl Session {
    /// One line that must succeed (c2 `_no_errors`).
    fn ok(&self, line: &str) {
        if let Err(err) = run_line(&self.ctx, line) {
            panic!("{line}: {err:?}");
        }
    }
    fn run(&self, line: &str) -> Result<()> {
        run_line(&self.ctx, line).map(|_| ())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.hsm.shutdown();
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Software wrapping (c2: pyca keywrap / RSA encrypt) through the real MemoryProvider.
fn software_wrap(
    kek: &KeyMaterial,
    mechanism: &str,
    params: Params,
    payload: KeyMaterial,
) -> String {
    let soft = MemoryProvider::new("soft");
    let kek = soft.import_key(kek, "kek", None, None).unwrap();
    let target = soft.import_key(&payload, "target", None, None).unwrap();
    let blob = soft
        .wrap_key(
            &kek,
            &MechanismInvocation::new(mechanism, params),
            &target,
            &WrapOptions::default(),
        )
        .unwrap();
    hex(&blob)
}

fn aes(data: &[u8]) -> KeyMaterial {
    let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, data.to_vec());
    material.size_bits = Some(u32::try_from(data.len() * 8).unwrap());
    material
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

/// c2 xfail(strict=False) legs: a token refusal is tolerated, anything else fails.
fn tolerated(err: &ConsoleError) -> bool {
    matches!(
        err.kind,
        ErrorKind::Pkcs11 { .. } | ErrorKind::UnsupportedOperation
    )
}

#[test]
fn test_load_wrapped_aes_under_an_aes_kek_softhsm() {
    // The KW/KWP rungs, hard-asserted: the token unwraps blobs produced by OpenSSL's
    // RFC 3394 / RFC 5649 implementations.
    let label_guard = unique_label();
    let label = label_guard.as_str();
    let s = session();
    let dir = tempfile::tempdir().unwrap();
    let (kek_label, kwp_label, kw_label) = (
        format!("{label}-kek"),
        format!("{label}-kwp"),
        format!("{label}-kw"),
    );
    let kwp_out = dir.path().join("kwp.bin");
    let kw_out = dir.path().join("kw.bin");
    let kwp_blob = software_wrap(
        &aes(&KEK_BYTES),
        "AES-KEY-WRAP-PAD",
        Params::new(),
        aes(&TARGET_BYTES),
    );
    let kw_blob = software_wrap(
        &aes(&KEK_BYTES),
        "AES-KEY-WRAP",
        Params::new(),
        aes(&TARGET_BYTES),
    );

    // the KEK itself: loaded (not generated) so the test knows its bytes
    s.ok(&format!(
        "load hsm aes {} --label {kek_label}",
        hex(&KEK_BYTES)
    ));
    s.ok(&format!(
        "load hsm aes {kwp_blob} --kek {kek_label} --mech kwp --label {kwp_label}"
    ));
    s.ok(&format!(
        "load hsm aes {kw_blob} --kek {kek_label} --mech kw --label {kw_label}"
    ));
    s.ok(&format!("export hsm:{kwp_label} {}", kwp_out.display()));
    s.ok(&format!("export hsm:{kw_label} {}", kw_out.display()));
    for l in [&kwp_label, &kw_label, &kek_label] {
        s.ok(&format!("delete hsm:{l}"));
    }
    let text = s.io.text();
    assert!(text.contains(&format!("hsm:{kwp_label}")), "{text}");
    assert!(
        text.contains("AES-KEY-WRAP-PAD"),
        "the result table names the mechanism"
    );
    assert_eq!(read(&kwp_out), TARGET_BYTES);
    assert_eq!(read(&kw_out), TARGET_BYTES);
}

#[test]
fn test_load_wrapped_aes_under_an_rsa_kek_softhsm() {
    // The RSA rungs: an on-token keypair unwraps blobs built against its exported public
    // half (PKCS#1 v1.5 and OAEP-SHA1, which every SoftHSM build accepts).
    let label_guard = unique_label();
    let label = label_guard.as_str();
    let s = session();
    let dir = tempfile::tempdir().unwrap();
    let pair = format!("{label}-pair");
    let pub_path = dir.path().join("kek-pub.pem");

    // phase 1: create the KEK pair on the token and export its public half
    s.ok(&format!("generate hsm rsa size=2048 --label {pair}"));
    s.ok(&format!(
        "export hsm:{pair} {} --public",
        pub_path.display()
    ));
    let public = parse_key_material(&read(&pub_path), KeyHint::Auto, None)
        .unwrap()
        .remove(0);
    assert_eq!(public.key_class, KeyClass::Public);
    assert_eq!(public.algorithm, KeyAlgorithm::Rsa);

    let pkcs1_blob = software_wrap(&public, "RSA-PKCS1", Params::new(), aes(&TARGET_BYTES));
    let mut oaep = Params::new();
    oaep.insert("hash".into(), ParamValue::Enum("sha1".into()));
    oaep.insert("mgf_hash".into(), ParamValue::Enum("sha1".into()));
    oaep.insert("label".into(), ParamValue::Bytes(Vec::new()));
    let oaep_blob = software_wrap(&public, "RSA-OAEP", oaep, aes(&TARGET_BYTES));

    let (p1, oa) = (format!("{label}-p1"), format!("{label}-oaep"));
    let pkcs1_out = dir.path().join("pkcs1.bin");
    let oaep_out = dir.path().join("oaep.bin");
    // phase 2: unwrap both blobs with the resident private half
    s.ok(&format!(
        "load hsm aes {pkcs1_blob} --kek {pair} --mech pkcs1 --label {p1}"
    ));
    s.ok(&format!(
        "load hsm aes {oaep_blob} --kek {pair} --mech oaep hash=sha1 --label {oa}"
    ));
    s.ok(&format!("export hsm:{p1} {}", pkcs1_out.display()));
    s.ok(&format!("export hsm:{oa} {}", oaep_out.display()));
    s.ok(&format!("delete hsm:{p1}"));
    s.ok(&format!("delete hsm:{oa}"));
    s.ok(&format!("delete hsm:{pair}"));
    s.ok(&format!("delete hsm:{pair}")); // the public half
    assert_eq!(read(&pkcs1_out), TARGET_BYTES);
    assert_eq!(read(&oaep_out), TARGET_BYTES);
}

#[test]
fn test_load_wrapped_ec_private_key_softhsm() {
    // A private key travels as unencrypted PKCS#8 DER inside the blob (the §5.5
    // convention) — here KWP-wrapped under an AES KEK. c2: xfail(strict=False).
    let label_guard = unique_label();
    let label = label_guard.as_str();
    let s = session();
    let dir = tempfile::tempdir().unwrap();
    let (kek_label, key_label) = (format!("{label}-eckek"), format!("{label}-ec"));
    let out_path = dir.path().join("ec.der");
    let pkcs8 = r2_testkit::fixtures::ec_p256_pkcs8();
    let mut material = KeyMaterial::new(KeyAlgorithm::Ec, KeyClass::Private, pkcs8.clone());
    material.curve = Some(r2_core::keys::Curve::P256);
    let blob = software_wrap(
        &aes(&KEK_BYTES),
        "AES-KEY-WRAP-PAD",
        Params::new(),
        material,
    );

    s.ok(&format!(
        "load hsm aes {} --label {kek_label}",
        hex(&KEK_BYTES)
    ));
    let unwrapped = s.run(&format!(
        "load hsm ec {blob} --kek {kek_label} --mech kwp --label {key_label}"
    ));
    match unwrapped {
        Ok(()) => {
            s.ok(&format!(
                "export hsm:{key_label} {} --format der",
                out_path.display()
            ));
            s.ok(&format!("delete hsm:{key_label}"));
            // same private key ⇔ same public key
            assert_eq!(
                formats::pkcs8_public_spki(&read(&out_path)).unwrap(),
                formats::pkcs8_public_spki(&pkcs8).unwrap()
            );
        }
        Err(err) => assert!(tolerated(&err), "{err:?}"),
    }
    s.ok(&format!("delete hsm:{kek_label}"));
}

#[test]
fn test_load_wrapped_aes_via_cbc_softhsm() {
    // The legacy AES-CBC rung against a real token. c2: xfail(strict=False) — SoftHSM
    // unwraps CBC_PAD only on 2.7.0 (§5.4 field note).
    let label_guard = unique_label();
    let label = label_guard.as_str();
    let s = session();
    let dir = tempfile::tempdir().unwrap();
    let (kek_label, out_label) = (format!("{label}-cbckek"), format!("{label}-cbc"));
    let out_path = dir.path().join("cbc.bin");
    let iv: Vec<u8> = (0u8..16).collect();
    let mut params = Params::new();
    params.insert("iv".into(), ParamValue::Bytes(iv.clone()));
    params.insert("padding".into(), ParamValue::Enum("pkcs7".into()));
    let blob = software_wrap(&aes(&KEK_BYTES), "AES-CBC", params, aes(&TARGET_BYTES));

    s.ok(&format!(
        "load hsm aes {} --label {kek_label}",
        hex(&KEK_BYTES)
    ));
    let unwrapped = s.run(&format!(
        "load hsm aes {blob} --kek {kek_label} --mech cbc iv=0x{} padding=pkcs7 --label \
         {out_label}",
        hex(&iv)
    ));
    match unwrapped {
        Ok(()) => {
            s.ok(&format!("export hsm:{out_label} {}", out_path.display()));
            s.ok(&format!("delete hsm:{out_label}"));
            assert_eq!(read(&out_path), TARGET_BYTES);
        }
        Err(err) => assert!(tolerated(&err), "{err:?}"),
    }
    s.ok(&format!("delete hsm:{kek_label}"));
}

#[test]
fn load_wrapped_aes_via_gcm_is_tolerated_softhsm() {
    // r2 addition (R15 Accept: GCM tolerated where CKF_WRAP is absent — SoftHSM never
    // wraps/unwraps GCM, §5.4 field note).
    let label_guard = unique_label();
    let label = label_guard.as_str();
    let s = session();
    let kek_label = format!("{label}-gcmkek");
    let iv: Vec<u8> = (0u8..12).collect();
    let mut params = Params::new();
    params.insert("iv".into(), ParamValue::Bytes(iv.clone()));
    params.insert("aad".into(), ParamValue::Bytes(Vec::new()));
    params.insert("tag_bits".into(), ParamValue::Enum("128".into()));
    let blob = software_wrap(&aes(&KEK_BYTES), "AES-GCM", params, aes(&TARGET_BYTES));
    s.ok(&format!(
        "load hsm aes {} --label {kek_label}",
        hex(&KEK_BYTES)
    ));
    let result = s.run(&format!(
        "load hsm aes {blob} --kek {kek_label} --mech gcm iv=0x{} --label {label}-gcm",
        hex(&iv)
    ));
    match result {
        Ok(()) => {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("gcm.bin");
            s.ok(&format!("export hsm:{label}-gcm {}", out.display()));
            s.ok(&format!("delete hsm:{label}-gcm"));
            assert_eq!(read(&out), TARGET_BYTES);
        }
        Err(err) => assert!(tolerated(&err), "{err:?}"),
    }
    s.ok(&format!("delete hsm:{kek_label}"));
}

#[test]
fn test_wrong_kek_is_reported_not_silently_wrong_softhsm() {
    // A blob wrapped under a different key must fail loudly (the token's integrity
    // check, translated through the §5.2 choke point).
    let label_guard = unique_label();
    let label = label_guard.as_str();
    let s = session();
    let kek_label = format!("{label}-badkek");
    let blob = software_wrap(
        &aes(&[0u8; 32]),
        "AES-KEY-WRAP-PAD",
        Params::new(),
        aes(&TARGET_BYTES),
    );
    s.ok(&format!(
        "load hsm aes {} --label {kek_label}",
        hex(&KEK_BYTES)
    ));
    let err = s
        .run(&format!(
            "load hsm aes {blob} --kek {kek_label} --mech kwp --label {label}-nope"
        ))
        .expect_err("unwrapping with the wrong KEK must surface an error");
    assert!(matches!(err.kind, ErrorKind::Pkcs11 { .. }), "{err:?}");
    s.ok(&format!("delete hsm:{kek_label}"));
}

#[test]
fn test_export_wrapped_then_load_round_trip_softhsm() {
    // §5.6 → §5.4 on a real token: wrap an on-token key out to a file with `export --kek`,
    // then load it back with `load --kek` and compare.
    let label_guard = unique_label();
    let label = label_guard.as_str();
    let s = session();
    let dir = tempfile::tempdir().unwrap();
    let (kek, src, back) = (
        format!("{label}-rtkek"),
        format!("{label}-src"),
        format!("{label}-back"),
    );
    let wrapped = dir.path().join("roundtrip.bin");
    let src_out = dir.path().join("src.bin");
    let back_out = dir.path().join("back.bin");
    s.ok(&format!("load hsm aes {} --label {kek}", hex(&KEK_BYTES)));
    s.ok(&format!(
        "load hsm aes {} --label {src}",
        hex(&TARGET_BYTES)
    ));
    // wrap it out on the token, then bring it back under a new label
    s.ok(&format!(
        "export hsm:{src} {} --kek {kek} --mech kwp",
        wrapped.display()
    ));
    s.ok(&format!(
        "load hsm aes --file {} --kek {kek} --mech kwp --label {back}",
        wrapped.display()
    ));
    s.ok(&format!("export hsm:{src} {}", src_out.display()));
    s.ok(&format!("export hsm:{back} {}", back_out.display()));
    for l in [&back, &src, &kek] {
        s.ok(&format!("delete hsm:{l}"));
    }
    assert!(s.io.text().contains("wrapped under"));
    assert_eq!(read(&src_out), TARGET_BYTES);
    assert_eq!(read(&back_out), TARGET_BYTES);
    // the token's C_WrapKey blob is OpenSSL's RFC 5649 output byte for byte
    let expected = software_wrap(
        &aes(&KEK_BYTES),
        "AES-KEY-WRAP-PAD",
        Params::new(),
        aes(&TARGET_BYTES),
    );
    assert_eq!(hex(&read(&wrapped)), expected);
}

#[test]
fn test_export_wrapped_hex_round_trips_softhsm() {
    // `--outformat hex` output is auto-detected on the way back in (§5.4).
    let label_guard = unique_label();
    let label = label_guard.as_str();
    let s = session();
    let dir = tempfile::tempdir().unwrap();
    let (kek, src, back) = (
        format!("{label}-hexkek"),
        format!("{label}-hexsrc"),
        format!("{label}-hexback"),
    );
    let wrapped = dir.path().join("roundtrip.hex");
    let back_out = dir.path().join("back.bin");
    s.ok(&format!("load hsm aes {} --label {kek}", hex(&KEK_BYTES)));
    s.ok(&format!(
        "load hsm aes {} --label {src}",
        hex(&TARGET_BYTES)
    ));
    s.ok(&format!(
        "export hsm:{src} {} --kek {kek} --mech kwp --outformat hex",
        wrapped.display()
    ));
    s.ok(&format!(
        "load hsm aes --file {} --kek {kek} --mech kwp --label {back}",
        wrapped.display()
    ));
    s.ok(&format!("export hsm:{back} {}", back_out.display()));
    for l in [&back, &src, &kek] {
        s.ok(&format!("delete hsm:{l}"));
    }
    // the file really is text hex, and the key survived the trip
    let text = std::fs::read_to_string(&wrapped).unwrap();
    assert!(text.trim().chars().all(|c| "0123456789abcdef".contains(c)));
    assert_eq!(read(&back_out), TARGET_BYTES);
}

#[test]
fn test_sensitive_key_exports_wrapped_but_not_plain_softhsm() {
    // §5.6 headline on a real token: SENSITIVE+EXTRACTABLE is wrappable.
    let label_guard = unique_label();
    let label = label_guard.as_str();
    let key_label = format!("{label}-sens");
    let s = session_with(Some((key_label.clone(), AES_SENSITIVE)));
    let dir = tempfile::tempdir().unwrap();
    let kek_label = format!("{label}-senskek");
    let plain_out = dir.path().join("plain.bin");
    let wrapped_out = dir.path().join("wrapped.bin");
    s.ok(&format!(
        "load hsm aes {} --label {kek_label}",
        hex(&KEK_BYTES)
    ));
    s.ok(&format!("generate hsm aes size=256 --label {key_label}"));
    // → §5.6 refusal
    let err = s
        .run(&format!("export hsm:{key_label} {}", plain_out.display()))
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(
        err.message.contains("Refusing to export"),
        "{}",
        err.message
    );
    s.ok(&format!(
        "export hsm:{key_label} {} --kek {kek_label} --mech kwp",
        wrapped_out.display()
    ));
    s.ok(&format!("delete hsm:{key_label}"));
    s.ok(&format!("delete hsm:{kek_label}"));
    assert!(!plain_out.exists());
    assert!(!read(&wrapped_out).is_empty());
}

#[test]
fn rsa_public_kek_wraps_on_the_token_softhsm() {
    // r2 addition: `export --kek <pair>:pub` (C_WrapKey with the public half) on the token,
    // then `load --kek <pair>` (C_UnwrapKey with the private half), PKCS#1 and OAEP-SHA1.
    let label_guard = unique_label();
    let label = label_guard.as_str();
    let s = session();
    let dir = tempfile::tempdir().unwrap();
    let pair = format!("{label}-pair");
    let src = format!("{label}-src");
    s.ok(&format!("generate hsm rsa size=2048 --label {pair}"));
    s.ok(&format!(
        "load hsm aes {} --label {src}",
        hex(&TARGET_BYTES)
    ));
    for (cli, params) in [("pkcs1", ""), ("oaep", "hash=sha1")] {
        let wrapped = dir.path().join(format!("{cli}.b64"));
        let back = format!("{label}-{cli}");
        let out = dir.path().join(format!("{cli}.bin"));
        s.ok(&format!(
            "export hsm:{src} {} --kek {pair}:pub --mech {cli} {params} --outformat b64",
            wrapped.display()
        ));
        s.ok(&format!(
            "load hsm aes --file {} --kek {pair} --mech {cli} {params} --label {back}",
            wrapped.display()
        ));
        s.ok(&format!("export hsm:{back} {}", out.display()));
        s.ok(&format!("delete hsm:{back}"));
        assert_eq!(read(&out), TARGET_BYTES, "{cli}");
    }
    // the bare keypair label is the PRIVATE half: refused with the :pub hint
    let err = s
        .run(&format!(
            "export hsm:{src} {} --kek {pair} --mech oaep",
            dir.path().join("x.bin").display()
        ))
        .unwrap_err();
    assert_eq!(
        err.hint.as_deref(),
        Some(format!("wrapping uses the public half: `--kek {pair}:pub`").as_str())
    );
    s.ok(&format!("delete hsm:{src}"));
    s.ok(&format!("delete hsm:{pair}"));
    s.ok(&format!("delete hsm:{pair}")); // the public half
}

#[test]
#[ignore = "needs R14 (merge checklist): --template seeding (templatefile::build_seed)"]
fn test_load_wrapped_aes_under_an_aes_kek_with_template_file_softhsm() {
    // c2's literal form: the §5.16 template file gives the KEK CKA_WRAP/CKA_UNWRAP. Runs
    // with the editor that accepts the seed unchanged, so only the file sets attributes.
    let label_guard = unique_label();
    let label = label_guard.as_str();
    let s = literal_session();
    let dir = tempfile::tempdir().unwrap();
    let template = c2_template_file(dir.path());
    let out = dir.path().join("kwp.bin");
    let blob = software_wrap(
        &aes(&KEK_BYTES),
        "AES-KEY-WRAP-PAD",
        Params::new(),
        aes(&TARGET_BYTES),
    );
    let t = template.display();
    s.ok(&format!(
        "load hsm aes {} --label {label}-kek --template {t}",
        hex(&KEK_BYTES)
    ));
    s.ok(&format!(
        "load hsm aes {blob} --kek {label}-kek --mech kwp --label {label}-kwp --template {t}"
    ));
    s.ok(&format!("export hsm:{label}-kwp {}", out.display()));
    s.ok(&format!("delete hsm:{label}-kwp"));
    s.ok(&format!("delete hsm:{label}-kek"));
    assert_eq!(read(&out), TARGET_BYTES);
}

#[test]
#[ignore = "needs R14 (merge checklist): --template seeding (templatefile::build_seed)"]
fn test_load_wrapped_aes_under_an_rsa_kek_with_template_file_softhsm() {
    // c2's literal form of the RSA rung: the rsa_private/rsa_public sections of the
    // template file give the pair CKA_UNWRAP/CKA_WRAP; the aes section keeps the
    // unwrapped results readable.
    let label_guard = unique_label();
    let label = label_guard.as_str();
    let s = literal_session();
    let dir = tempfile::tempdir().unwrap();
    let template = c2_template_file(dir.path());
    let t = template.display();
    let pair = format!("{label}-pair");
    let pub_path = dir.path().join("kek-pub.pem");
    s.ok(&format!(
        "generate hsm rsa size=2048 --label {pair} --template {t}"
    ));
    s.ok(&format!(
        "export hsm:{pair} {} --public",
        pub_path.display()
    ));
    let public = parse_key_material(&read(&pub_path), KeyHint::Auto, None)
        .unwrap()
        .remove(0);
    let pkcs1_blob = software_wrap(&public, "RSA-PKCS1", Params::new(), aes(&TARGET_BYTES));
    let mut oaep = Params::new();
    oaep.insert("hash".into(), ParamValue::Enum("sha1".into()));
    oaep.insert("mgf_hash".into(), ParamValue::Enum("sha1".into()));
    oaep.insert("label".into(), ParamValue::Bytes(Vec::new()));
    let oaep_blob = software_wrap(&public, "RSA-OAEP", oaep, aes(&TARGET_BYTES));
    let (p1, oa) = (format!("{label}-p1"), format!("{label}-oaep"));
    let pkcs1_out = dir.path().join("pkcs1.bin");
    let oaep_out = dir.path().join("oaep.bin");
    s.ok(&format!(
        "load hsm aes {pkcs1_blob} --kek {pair} --mech pkcs1 --label {p1} --template {t}"
    ));
    s.ok(&format!(
        "load hsm aes {oaep_blob} --kek {pair} --mech oaep hash=sha1 --label {oa} --template {t}"
    ));
    s.ok(&format!("export hsm:{p1} {}", pkcs1_out.display()));
    s.ok(&format!("export hsm:{oa} {}", oaep_out.display()));
    s.ok(&format!("delete hsm:{p1}"));
    s.ok(&format!("delete hsm:{oa}"));
    s.ok(&format!("delete hsm:{pair}"));
    s.ok(&format!("delete hsm:{pair}")); // the public half
    assert_eq!(read(&pkcs1_out), TARGET_BYTES);
    assert_eq!(read(&oaep_out), TARGET_BYTES);
}

#[test]
#[ignore = "needs R14 (merge checklist): --template seeding (templatefile::build_seed)"]
fn test_sensitive_key_exports_wrapped_but_not_plain_with_template_file_softhsm() {
    // c2's literal form: `sensitive.yaml` replaces the default aes rows, so the generated
    // key is SENSITIVE+EXTRACTABLE with nothing else from the §7 defaults.
    let label_guard = unique_label();
    let label = label_guard.as_str();
    let s = literal_session();
    let dir = tempfile::tempdir().unwrap();
    let template = c2_template_file(dir.path());
    let sensitive = template_file(dir.path(), "sensitive.yaml", &[("aes", AES_SENSITIVE)]);
    let kek_label = format!("{label}-senskek");
    let key_label = format!("{label}-sens");
    let plain_out = dir.path().join("plain.bin");
    let wrapped_out = dir.path().join("wrapped.bin");
    s.ok(&format!(
        "load hsm aes {} --label {kek_label} --template {}",
        hex(&KEK_BYTES),
        template.display()
    ));
    s.ok(&format!(
        "generate hsm aes size=256 --label {key_label} --template {}",
        sensitive.display()
    ));
    let err = s
        .run(&format!("export hsm:{key_label} {}", plain_out.display()))
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyNotExportable);
    assert!(
        err.message.contains("Refusing to export"),
        "{}",
        err.message
    );
    s.ok(&format!(
        "export hsm:{key_label} {} --kek {kek_label} --mech kwp",
        wrapped_out.display()
    ));
    s.ok(&format!("delete hsm:{key_label}"));
    s.ok(&format!("delete hsm:{kek_label}"));
    assert!(!plain_out.exists());
    assert!(!read(&wrapped_out).is_empty());
}
