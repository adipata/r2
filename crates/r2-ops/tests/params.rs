// ParamResolver tests via ScriptedIo (spec §4.6.4) — the port of c2 tests/unit/test_params.py
// (R7). Covers inline-vs-prompted parity, defaults + default_from, ENUM completion data,
// per-kind parsing, unknown names, UserAbort on Ctrl-C / Ctrl-D, and the §11 D30 random fallback.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]
use std::collections::BTreeSet;
use std::rc::Rc;

use indexmap::IndexMap;
use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyMaterial};
use r2_ops::{
    OperationRegistry, OperationSpec, ParamKind, ParamResolver, ParamSpec, ParamStruct, ParamValue,
    Params, Verb, register_builtins,
};
use r2_provider::{Provider, ProviderRegistry};
use r2_testkit::{FakeProvider, ScriptedIo};

fn providers() -> ProviderRegistry {
    let registry = ProviderRegistry::new();
    let mem = FakeProvider::new("mem");
    mem.import_key(
        &KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, vec![0x02; 16]),
        "k1",
        None,
        None,
    )
    .unwrap();
    registry.register(Rc::new(mem)).unwrap();
    registry
}

fn builtins() -> OperationRegistry {
    let mut registry = OperationRegistry::new();
    register_builtins(&mut registry).unwrap();
    registry
}

fn given(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn params(pairs: Vec<(&str, ParamValue)>) -> Params {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

fn enum_value(text: &str) -> ParamValue {
    ParamValue::Enum(text.to_owned())
}

/// Minimal OperationSpec wrapping a single param (for kind-level tests).
fn one_param_spec(param: ParamSpec) -> OperationSpec {
    OperationSpec {
        id: "test.op".to_owned(),
        verb: Verb::Encrypt,
        algorithm: KeyAlgorithm::Aes,
        key_classes: BTreeSet::from([KeyClass::Secret]),
        mechanism: "AES-GCM".to_owned(),
        cli_name: "test".to_owned(),
        label: "test op".to_owned(),
        params: vec![param],
        provider_types: None,
        providers: None,
        curves: None,
        raw_ckm: None,
        param_struct: ParamStruct::None,
    }
}

fn resolve(
    registry: &ProviderRegistry,
    io: &ScriptedIo,
    spec: &OperationSpec,
    pairs: &[(&str, &str)],
) -> Result<Params> {
    ParamResolver::new(io, registry).resolve(spec, &given(pairs))
}

fn assert_param_error(err: &ConsoleError) {
    assert!(
        matches!(err.kind, ErrorKind::Param { .. }),
        "expected a ParamError, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// resolution algorithm: given / default_from / default / prompt
// ---------------------------------------------------------------------------

#[test]
fn test_inline_values_parse_without_prompting() {
    let registry = providers();
    let io = ScriptedIo::empty();
    let reg = builtins();
    let gcm = reg.get("aes.encrypt.gcm").unwrap();
    let iv = format!("0x{}", "0a".repeat(12));
    let values = resolve(&registry, &io, gcm, &[("iv", &iv), ("tag_bits", "120")]).unwrap();
    assert_eq!(
        values,
        params(vec![
            ("iv", ParamValue::Bytes(vec![0x0a; 12])),
            ("aad", ParamValue::Bytes(Vec::new())),
            ("tag_bits", enum_value("120")),
        ])
    );
    assert!(io.prompts().is_empty());
}

#[test]
fn test_prompted_value_equals_inline_value() {
    let registry = providers();
    let reg = builtins();
    let gcm = reg.get("aes.encrypt.gcm").unwrap();
    let iv = "0a".repeat(12);
    let inline = resolve(&registry, &ScriptedIo::empty(), gcm, &[("iv", &iv)]).unwrap();
    let io = ScriptedIo::new([iv.clone()]);
    let prompted = resolve(&registry, &io, gcm, &[]).unwrap();
    assert_eq!(prompted, inline); // ONE code path (§4.6)
    assert_eq!(io.prompts(), ["IV / nonce (12 bytes typical)"]);
}

#[test]
fn test_unknown_given_name_lists_valid_names() {
    let registry = providers();
    let reg = builtins();
    let gcm = reg.get("aes.encrypt.gcm").unwrap();
    let err = resolve(&registry, &ScriptedIo::empty(), gcm, &[("nonce", "00")]).unwrap_err();
    assert_eq!(err.param_name(), Some("nonce"));
    assert_eq!(err.message, "unknown parameter 'nonce' for aes.encrypt.gcm");
    let hint = err.hint.unwrap();
    assert_eq!(hint, "valid parameters: iv, aad, tag_bits");
    for name in ["iv", "aad", "tag_bits"] {
        assert!(hint.contains(name));
    }
    // an operation without parameters says so
    let pkcs1 = reg.get("rsa.encrypt.pkcs1").unwrap();
    let err = resolve(&registry, &ScriptedIo::empty(), pkcs1, &[("x", "1")]).unwrap_err();
    assert_eq!(
        err.hint.as_deref(),
        Some("this operation takes no parameters")
    );
}

#[test]
fn test_optional_defaults_apply_without_prompting() {
    let registry = providers();
    let io = ScriptedIo::empty();
    let reg = builtins();
    let cmac = reg.get("aes.sign.cmac").unwrap();
    assert_eq!(
        resolve(&registry, &io, cmac, &[]).unwrap(),
        params(vec![("mac_len", ParamValue::Int(16))])
    );
    assert!(io.prompts().is_empty());
}

#[test]
fn test_default_from_mirrors_earlier_param() {
    let registry = providers();
    let io = ScriptedIo::empty();
    let reg = builtins();
    let pss = reg.get("rsa.sign.pss").unwrap();
    let values = resolve(&registry, &io, pss, &[("hash", "sha384")]).unwrap();
    assert_eq!(values["hash"], enum_value("sha384"));
    assert_eq!(values["mgf_hash"], enum_value("sha384")); // mirrored, not defaulted
    // default=None → absent; the provider resolves it (§4.6.1)
    assert!(!values.contains_key("salt_len"));
    assert!(io.prompts().is_empty());
}

#[test]
fn test_default_from_loses_to_explicit_given() {
    let registry = providers();
    let reg = builtins();
    let pss = reg.get("rsa.sign.pss").unwrap();
    let values = resolve(
        &registry,
        &ScriptedIo::empty(),
        pss,
        &[("hash", "sha512"), ("mgf_hash", "sha1")],
    )
    .unwrap();
    assert_eq!(values["mgf_hash"], enum_value("sha1"));
}

#[test]
fn test_default_from_defaults_chain_from_defaults() {
    let registry = providers();
    let reg = builtins();
    let oaep = reg.get("rsa.encrypt.oaep").unwrap();
    let values = resolve(&registry, &ScriptedIo::empty(), oaep, &[]).unwrap();
    assert_eq!(values["hash"], enum_value("sha256"));
    assert_eq!(values["mgf_hash"], enum_value("sha256"));
    assert_eq!(values["label"], ParamValue::Bytes(Vec::new()));
}

#[test]
fn test_default_from_referencing_unresolved_param_is_a_spec_bug() {
    let registry = providers();
    let spec = one_param_spec(
        ParamSpec::new("mirror", ParamKind::Enum, "M")
            .default_from("ghost")
            .choices(&["a"]),
    );
    let err = resolve(&registry, &ScriptedIo::empty(), &spec, &[]).unwrap_err();
    assert_param_error(&err);
    assert_eq!(
        err.message,
        "parameter 'mirror' mirrors 'ghost', which is not resolved yet"
    );
    assert_eq!(
        err.hint.as_deref(),
        Some("default_from must reference an earlier parameter (§4.6)")
    );
}

#[test]
fn default_from_of_a_resolved_but_absent_param_stays_absent() {
    // r2: a None default is ABSENT (§4.6.1); a mirror of it is absent too, never an error.
    let registry = providers();
    let spec = OperationSpec {
        params: vec![
            ParamSpec::new("a", ParamKind::Int, "A").optional(None),
            ParamSpec::new("b", ParamKind::Int, "B").default_from("a"),
        ],
        ..one_param_spec(ParamSpec::str("x", "X"))
    };
    let values = resolve(&registry, &ScriptedIo::empty(), &spec, &[]).unwrap();
    assert!(values.is_empty());
    let values = resolve(&registry, &ScriptedIo::empty(), &spec, &[("a", "7")]).unwrap();
    assert_eq!(
        values,
        params(vec![("a", ParamValue::Int(7)), ("b", ParamValue::Int(7))])
    );
}

#[test]
fn test_required_param_prompts_and_reprompts_until_valid() {
    let registry = providers();
    let reg = builtins();
    let cbc = reg.get("aes.encrypt.cbc").unwrap();
    let io = ScriptedIo::new(["zz".to_owned(), "0b".repeat(16)]); // first answer: invalid hex
    let values = resolve(&registry, &io, cbc, &[]).unwrap();
    assert_eq!(values["iv"], ParamValue::Bytes(vec![0x0b; 16]));
    assert_eq!(values["padding"], enum_value("pkcs7"));
    assert_eq!(io.prompts(), ["IV (16 bytes)", "IV (16 bytes)"]);
    assert!(
        io.output()
            .iter()
            .any(|line| line.starts_with("error: iv:"))
    );
}

#[test]
fn test_ctrl_c_in_prompt_raises_user_abort() {
    let registry = providers();
    let reg = builtins();
    let io = ScriptedIo::new([ScriptedIo::CTRL_C]);
    let err = resolve(&registry, &io, reg.get("aes.encrypt.cbc").unwrap(), &[]).unwrap_err();
    assert!(err.kind.is_user_abort());
    assert_eq!(err.message, "aborted while entering 'iv'");
}

#[test]
fn test_eof_in_prompt_raises_user_abort() {
    let registry = providers();
    let reg = builtins();
    let io = ScriptedIo::new([ScriptedIo::CTRL_D]);
    let err = resolve(&registry, &io, reg.get("aes.encrypt.cbc").unwrap(), &[]).unwrap_err();
    assert!(err.kind.is_user_abort());
}

// ---------------------------------------------------------------------------
// per-kind parsing (§4.6 rules)
// ---------------------------------------------------------------------------

#[test]
fn test_int_accepts_decimal_and_negative_only() {
    let registry = providers();
    let io = ScriptedIo::empty();
    let spec = one_param_spec(ParamSpec::new("n", ParamKind::Int, "N"));
    assert_eq!(
        resolve(&registry, &io, &spec, &[("n", "42")]).unwrap(),
        params(vec![("n", ParamValue::Int(42))])
    );
    assert_eq!(
        resolve(&registry, &io, &spec, &[("n", "-1")]).unwrap(),
        params(vec![("n", ParamValue::Int(-1))])
    );
    // surrounding Python whitespace is stripped (c2 `text.strip()`)
    assert_eq!(
        resolve(&registry, &io, &spec, &[("n", " 7\u{1f}")]).unwrap(),
        params(vec![("n", ParamValue::Int(7))])
    );
    for bad in ["0x10", "12a", "max", "", "1.5", "+3", "-", "١٢"] {
        let err = resolve(&registry, &io, &spec, &[("n", bad)]).unwrap_err();
        assert_param_error(&err);
        assert_eq!(
            err.hint.as_deref(),
            Some("decimal digits with an optional leading '-' only (§4.6)")
        );
    }
    let err = resolve(&registry, &io, &spec, &[("n", "12a")]).unwrap_err();
    assert_eq!(err.message, "n: invalid integer '12a'");
    // §11 D18: outside i64 is rejected with the same message
    let err = resolve(&registry, &io, &spec, &[("n", "9223372036854775808")]).unwrap_err();
    assert_eq!(err.message, "n: invalid integer '9223372036854775808'");
    assert_eq!(
        resolve(&registry, &io, &spec, &[("n", "-9223372036854775808")]).unwrap(),
        params(vec![("n", ParamValue::Int(i64::MIN))])
    );
}

#[test]
fn test_bool_accepted_spellings() {
    let registry = providers();
    let spec = one_param_spec(ParamSpec::new("b", ParamKind::Bool, "B"));
    for (text, expected) in [
        ("true", true),
        ("YES", true),
        ("on", true),
        ("1", true),
        ("false", false),
        ("No", false),
        ("OFF", false),
        ("0", false),
    ] {
        assert_eq!(
            resolve(&registry, &ScriptedIo::empty(), &spec, &[("b", text)]).unwrap(),
            params(vec![("b", ParamValue::Bool(expected))]),
            "{text}"
        );
    }
}

#[test]
fn test_bool_rejects_other_spellings() {
    let registry = providers();
    let spec = one_param_spec(ParamSpec::new("b", ParamKind::Bool, "B"));
    let err = resolve(&registry, &ScriptedIo::empty(), &spec, &[("b", "jawohl")]).unwrap_err();
    assert_param_error(&err);
    assert_eq!(err.message, "b: invalid boolean 'jawohl'");
    assert_eq!(
        err.hint.as_deref(),
        Some("accepted: true/false, yes/no, on/off, 1/0")
    );
}

#[test]
fn test_enum_valid_invalid_and_choices_hint() {
    let registry = providers();
    let spec = one_param_spec(ParamSpec::new("e", ParamKind::Enum, "E").choices(&["aa", "bb"]));
    assert_eq!(
        resolve(&registry, &ScriptedIo::empty(), &spec, &[("e", "bb")]).unwrap(),
        params(vec![("e", enum_value("bb"))])
    );
    let err = resolve(&registry, &ScriptedIo::empty(), &spec, &[("e", "cc")]).unwrap_err();
    assert_param_error(&err);
    assert_eq!(err.message, "e: invalid choice 'cc'");
    assert_eq!(err.hint.as_deref(), Some("choices: aa, bb"));
}

#[test]
fn test_enum_prompt_reprompts_and_receives_choices() {
    // The re-prompt half; that the full ParamSpec (with choices) reaches the line reader as
    // completion choices is asserted over LineIo in r2-console
    // (tests::io::test_enum_prompt_reprompts_and_receives_choices).
    let registry = providers();
    let io = ScriptedIo::new(["nope", "aa"]);
    let spec =
        one_param_spec(ParamSpec::new("e", ParamKind::Enum, "Pick one").choices(&["aa", "bb"]));
    let values = resolve(&registry, &io, &spec, &[]).unwrap();
    assert_eq!(values, params(vec![("e", enum_value("aa"))]));
    assert_eq!(io.prompts(), ["Pick one", "Pick one"]);
    assert!(io.output().iter().any(|line| line.contains("error: e:")));
    assert_eq!(
        io.output(),
        ["error: e: invalid choice 'nope' (hint: choices: aa, bb)"]
    );
}

#[test]
fn test_str_kept_verbatim() {
    let registry = providers();
    let spec = one_param_spec(ParamSpec::new("s", ParamKind::Str, "S"));
    assert_eq!(
        resolve(
            &registry,
            &ScriptedIo::empty(),
            &spec,
            &[("s", "  CN=x, O=y  ")]
        )
        .unwrap(),
        params(vec![("s", ParamValue::Str("  CN=x, O=y  ".to_owned()))])
    );
}

#[test]
fn test_bytes_hex_base64_and_prefix() {
    let registry = providers();
    let spec = one_param_spec(ParamSpec::new("d", ParamKind::Bytes, "D"));
    for (text, expected) in [
        ("deadbeef", vec![0xde, 0xad, 0xbe, 0xef]),
        ("0xdeadbeef", vec![0xde, 0xad, 0xbe, 0xef]),
        ("b64:AAECAw==", vec![0x00, 0x01, 0x02, 0x03]),
    ] {
        assert_eq!(
            resolve(&registry, &ScriptedIo::empty(), &spec, &[("d", text)]).unwrap(),
            params(vec![("d", ParamValue::Bytes(expected))])
        );
    }
}

#[test]
fn test_bytes_exact_length_enforced() {
    let registry = providers();
    let spec = one_param_spec(ParamSpec::new("iv", ParamKind::Bytes, "IV").length(16));
    let err = resolve(
        &registry,
        &ScriptedIo::empty(),
        &spec,
        &[("iv", "deadbeef")],
    )
    .unwrap_err();
    assert_param_error(&err);
    assert_eq!(err.message, "iv: expected exactly 16 bytes, got 4");
    assert_eq!(err.hint, None);
}

#[test]
fn test_bytes_codec_failure_becomes_param_error() {
    let registry = providers();
    let spec = one_param_spec(ParamSpec::new("d", ParamKind::Bytes, "D"));
    let err = resolve(
        &registry,
        &ScriptedIo::empty(),
        &spec,
        &[("d", "!!!not-data!!!")],
    )
    .unwrap_err();
    assert_eq!(err.param_name(), Some("d"));
    // "{name}: {codec message}" with the codec's hint
    let codec = r2_core::codec::decode_data("!!!not-data!!!").err().unwrap();
    assert_eq!(err.message, format!("d: {}", codec.message));
    assert_eq!(err.hint, codec.hint);
}

#[test]
fn test_keyref_resolves_to_key_info() {
    let registry = providers();
    let spec = one_param_spec(ParamSpec::new("peer", ParamKind::KeyRef, "Peer"));
    let values = resolve(
        &registry,
        &ScriptedIo::empty(),
        &spec,
        &[("peer", "mem:k1")],
    )
    .unwrap();
    let info = values["peer"].as_key().unwrap();
    assert_eq!(info.key_ref.display(), "mem:k1");
    assert_eq!(info.algorithm, KeyAlgorithm::Aes);
}

#[test]
fn test_keyref_failures_become_param_errors() {
    let registry = providers();
    let spec = one_param_spec(ParamSpec::new("peer", ParamKind::KeyRef, "Peer"));
    for bad in ["nope:k1", "mem:missing", "not-a-ref"] {
        let err = resolve(&registry, &ScriptedIo::empty(), &spec, &[("peer", bad)]).unwrap_err();
        assert_param_error(&err);
        assert_eq!(err.param_name(), Some("peer"), "{bad}");
        // "{name}: {message}" with the original hint
        let original = registry.resolve_ref(bad).err().unwrap();
        assert_eq!(err.message, format!("peer: {}", original.message));
        assert_eq!(err.hint, original.hint);
    }
}

#[test]
fn keyref_user_abort_propagates_unchanged() {
    // §4.2: a UserAbort raised inside the provider lookup is never rewrapped.
    struct AbortingFind;
    impl r2_testkit::FakeHooks for AbortingFind {
        fn find_key(
            &self,
            _next: &dyn Provider,
            _selector: &r2_provider::KeySelector,
        ) -> Option<Result<r2_core::keys::KeyInfo>> {
            Some(Err(ConsoleError::user_abort("interrupted")))
        }
    }
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::new(
            FakeProvider::new("mem").with_hooks(Rc::new(AbortingFind)),
        ))
        .unwrap();
    let spec = one_param_spec(ParamSpec::new("peer", ParamKind::KeyRef, "Peer"));
    let err = resolve(&registry, &ScriptedIo::empty(), &spec, &[("peer", "mem:k")]).unwrap_err();
    assert_eq!(err, ConsoleError::user_abort("interrupted"));
}

fn no_small(value: &ParamValue) -> Result<()> {
    match value.as_int() {
        Some(n) if n < 8 => Err(ConsoleError::param("n: too small", "n")),
        _ => Ok(()),
    }
}

#[test]
fn test_validate_callback_runs_for_inline_and_prompted() {
    let registry = providers();
    let spec = one_param_spec(ParamSpec::new("n", ParamKind::Int, "N").validate(no_small));
    let err = resolve(&registry, &ScriptedIo::empty(), &spec, &[("n", "3")]).unwrap_err();
    assert_eq!(err.message, "n: too small");
    let io = ScriptedIo::new(["3", "9"]); // prompted: rejected once, then ok
    assert_eq!(
        resolve(&registry, &io, &spec, &[]).unwrap(),
        params(vec![("n", ParamValue::Int(9))])
    );
    assert_eq!(io.prompts().len(), 2);
}

#[test]
fn test_resolved_dict_covers_every_declared_param() {
    // r2: every declared param is resolved; one whose default is c2's None is ABSENT from
    // the map (§4.6.1) — for rsa.sign.pss that is salt_len.
    let registry = providers();
    let reg = builtins();
    let pss = reg.get("rsa.sign.pss").unwrap();
    let values = resolve(&registry, &ScriptedIo::empty(), pss, &[]).unwrap();
    let keys: BTreeSet<&str> = values.keys().map(String::as_str).collect();
    let declared: BTreeSet<&str> = pss
        .params
        .iter()
        .filter(|p| p.required || p.default.is_some() || p.default_from.is_some())
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(keys, declared);
    assert_eq!(keys, BTreeSet::from(["hash", "mgf_hash"]));
    let values = resolve(&registry, &ScriptedIo::empty(), pss, &[("salt_len", "-1")]).unwrap();
    let all: BTreeSet<&str> = pss.params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        values.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        all
    );
}

#[test]
fn parse_value_is_the_shared_parser() {
    let registry = providers();
    let io = ScriptedIo::empty();
    let resolver = ParamResolver::new(&io, &registry);
    let spec = ParamSpec::new("hash", ParamKind::Enum, "Hash").choices(&["sha1", "sha256"]);
    assert_eq!(
        resolver.parse_value(&spec, " sha1 ").unwrap(),
        enum_value("sha1")
    );
    assert_param_error(&resolver.parse_value(&spec, "md5").unwrap_err());
}

// ---------------------------------------------------------------------------
// §11 D30: random fallback for caller-chosen bytes (ParamResolver::with_rng)
// ---------------------------------------------------------------------------

const RNG: &str = "rng";

/// Resolve with `rng` attached as the resolver's RNG provider.
fn resolve_rng(
    registry: &ProviderRegistry,
    io: &ScriptedIo,
    rng: &FakeProvider,
    spec: &OperationSpec,
    pairs: &[(&str, &str)],
) -> Result<Params> {
    ParamResolver::new(io, registry)
        .with_rng(rng)
        .resolve(spec, &given(pairs))
}

/// The bytes the `n`-th draws of a fresh twin FakeProvider named RNG produce (deterministic).
fn twin_draws(lens: &[usize]) -> Vec<Vec<u8>> {
    let twin = FakeProvider::new(RNG);
    lens.iter()
        .map(|len| twin.generate_random(*len).unwrap().to_vec())
        .collect()
}

fn lower_hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn random_calls(lens: &[usize]) -> Vec<Vec<String>> {
    lens.iter()
        .map(|len| vec!["generate_random".to_owned(), len.to_string()])
        .collect()
}

#[test]
fn random_iv_cbc_empty_answer_draws_from_rng() {
    let registry = providers();
    let reg = builtins();
    let cbc = reg.get("aes.encrypt.cbc").unwrap();
    let rng = FakeProvider::new(RNG);
    let io = ScriptedIo::new([""]);
    let values = resolve_rng(&registry, &io, &rng, cbc, &[]).unwrap();
    let expected = twin_draws(&[16]).remove(0);
    assert_eq!(expected.len(), 16);
    assert_eq!(
        values,
        params(vec![
            ("iv", ParamValue::Bytes(expected.clone())),
            ("padding", enum_value("pkcs7")), // defaulted, never prompted
        ])
    );
    assert_eq!(io.prompts(), ["IV (16 bytes, empty = random)"]);
    assert_eq!(
        io.output(),
        [format!("IV (random): {}", lower_hex(&expected))]
    );
    assert_eq!(
        io.renderables(),
        [r2_core::io::Renderable::Text(format!(
            "IV (random): {}",
            lower_hex(&expected)
        ))]
    );
    assert_eq!(rng.calls(), random_calls(&[16]));
    assert_eq!(io.remaining(), 0);
}

#[test]
fn random_iv_whitespace_only_answer_counts_as_empty() {
    let registry = providers();
    let reg = builtins();
    let cbc = reg.get("aes.encrypt.cbc").unwrap();
    for blank in ["   ", "\t", " \u{1f} "] {
        let rng = FakeProvider::new(RNG);
        let io = ScriptedIo::new([blank]);
        let values = resolve_rng(&registry, &io, &rng, cbc, &[]).unwrap();
        let expected = twin_draws(&[16]).remove(0);
        assert_eq!(
            values["iv"],
            ParamValue::Bytes(expected.clone()),
            "{blank:?}"
        );
        assert_eq!(io.prompts(), ["IV (16 bytes, empty = random)"]);
        assert_eq!(
            io.output(),
            [format!("IV (random): {}", lower_hex(&expected))]
        );
        assert_eq!(rng.calls(), random_calls(&[16]));
    }
}

#[test]
fn random_iv_successive_draws_follow_the_rng_sequence() {
    let registry = providers();
    let reg = builtins();
    let cbc = reg.get("aes.encrypt.cbc").unwrap();
    let rng = FakeProvider::new(RNG);
    let io = ScriptedIo::new(["", ""]);
    let resolver = ParamResolver::new(&io, &registry).with_rng(&rng);
    let first = resolver.resolve(cbc, &given(&[])).unwrap();
    let second = resolver.resolve(cbc, &given(&[])).unwrap();
    let draws = twin_draws(&[16, 16]);
    assert_ne!(draws[0], draws[1]);
    assert_eq!(first["iv"], ParamValue::Bytes(draws[0].clone()));
    assert_eq!(second["iv"], ParamValue::Bytes(draws[1].clone()));
    assert_eq!(rng.calls(), random_calls(&[16, 16]));
}

#[test]
fn random_iv_non_empty_answer_is_parsed_without_drawing() {
    let registry = providers();
    let reg = builtins();
    let cbc = reg.get("aes.encrypt.cbc").unwrap();
    let rng = FakeProvider::new(RNG);
    let io = ScriptedIo::new(["0b".repeat(16)]);
    let values = resolve_rng(&registry, &io, &rng, cbc, &[]).unwrap();
    assert_eq!(values["iv"], ParamValue::Bytes(vec![0x0b; 16]));
    assert_eq!(io.prompts(), ["IV (16 bytes, empty = random)"]);
    assert!(io.output().is_empty());
    assert!(rng.calls().is_empty());
}

#[test]
fn random_iv_invalid_answer_reprompts_then_empty_draws() {
    // a non-empty answer goes through the normal parser (errors shown, prompt repeats); the
    // random fallback is still offered on the re-prompt
    let registry = providers();
    let reg = builtins();
    let cbc = reg.get("aes.encrypt.cbc").unwrap();
    let rng = FakeProvider::new(RNG);
    let io = ScriptedIo::new(["deadbeef", ""]);
    let values = resolve_rng(&registry, &io, &rng, cbc, &[]).unwrap();
    let expected = twin_draws(&[16]).remove(0);
    assert_eq!(values["iv"], ParamValue::Bytes(expected.clone()));
    assert_eq!(
        io.prompts(),
        [
            "IV (16 bytes, empty = random)",
            "IV (16 bytes, empty = random)"
        ]
    );
    assert_eq!(
        io.output(),
        [
            "error: iv: expected exactly 16 bytes, got 4".to_owned(),
            format!("IV (random): {}", lower_hex(&expected)),
        ]
    );
    assert_eq!(rng.calls(), random_calls(&[16]));
}

#[test]
fn without_rng_empty_iv_answer_is_an_error_and_reprompts() {
    // no with_rng: the pre-D30 prompt text and the codec's "empty input" ParamError
    let registry = providers();
    let reg = builtins();
    let cbc = reg.get("aes.encrypt.cbc").unwrap();
    let io = ScriptedIo::new(["".to_owned(), "0b".repeat(16)]);
    let values = resolve(&registry, &io, cbc, &[]).unwrap();
    assert_eq!(values["iv"], ParamValue::Bytes(vec![0x0b; 16]));
    assert_eq!(io.prompts(), ["IV (16 bytes)", "IV (16 bytes)"]);
    assert_eq!(
        io.output(),
        ["error: iv: empty input (hint: paste hex, base64 or PEM data)"]
    );
}

#[test]
fn mirrored_decrypt_and_verify_never_draw_random() {
    // decrypt/verify need the IV the data was made with: the mirror clears `random`, so an
    // attached RNG changes nothing
    let registry = providers();
    let reg = builtins();
    for (id, prompt, length) in [
        ("aes.decrypt.cbc", "IV (16 bytes)", 16),
        ("aes.verify.gmac", "IV (12 bytes)", 12),
        ("aes.decrypt.gcm", "IV / nonce (12 bytes typical)", 12),
        ("aes.decrypt.ctr", "Initial counter block (16 bytes)", 16),
    ] {
        let spec = reg.get(id).unwrap();
        let rng = FakeProvider::new(RNG);
        let io = ScriptedIo::new(["".to_owned(), "0c".repeat(length)]);
        let values = resolve_rng(&registry, &io, &rng, spec, &[]).unwrap();
        let name = &spec.params[0].name;
        assert_eq!(values[name], ParamValue::Bytes(vec![0x0c; length]), "{id}");
        assert_eq!(io.prompts(), [prompt, prompt], "{id}");
        assert_eq!(
            io.output(),
            [format!(
                "error: {name}: empty input (hint: paste hex, base64 or PEM data)"
            )],
            "{id}"
        );
        assert!(rng.calls().is_empty(), "{id}");
    }
}

#[test]
fn random_rows_gcm_ctr_gmac_prompts_labels_and_lengths() {
    let registry = providers();
    let reg = builtins();
    for (id, name, prompt, label, len) in [
        (
            "aes.encrypt.gcm",
            "iv",
            "IV / nonce (12 bytes typical, empty = random)",
            "IV / nonce",
            12,
        ),
        (
            "aes.encrypt.ctr",
            "counter_block",
            "Initial counter block (16 bytes, empty = random)",
            "Initial counter block",
            16,
        ),
        (
            "aes.sign.gmac",
            "iv",
            "IV (12 bytes, empty = random)",
            "IV",
            12,
        ),
    ] {
        let spec = reg.get(id).unwrap();
        let rng = FakeProvider::new(RNG);
        let io = ScriptedIo::new([""]);
        let values = resolve_rng(&registry, &io, &rng, spec, &[]).unwrap();
        let expected = twin_draws(&[len]).remove(0);
        assert_eq!(expected.len(), len, "{id}");
        assert_eq!(values[name], ParamValue::Bytes(expected.clone()), "{id}");
        assert_eq!(io.prompts(), [prompt], "{id}"); // the other params are defaulted
        assert_eq!(
            io.output(),
            [format!("{label} (random): {}", lower_hex(&expected))],
            "{id}"
        );
        assert_eq!(rng.calls(), random_calls(&[len]), "{id}");
    }
}

#[test]
fn random_rng_error_propagates_out_of_resolve() {
    // a login-capable provider that is logged out refuses generate_random: the error leaves
    // resolve as-is (no re-prompt, nothing printed)
    let registry = providers();
    let reg = builtins();
    let cbc = reg.get("aes.encrypt.cbc").unwrap();
    let rng = FakeProvider::new(RNG)
        .with_type_name("pkcs11")
        .starting_logged_out();
    let io = ScriptedIo::new([""]);
    let err = resolve_rng(&registry, &io, &rng, cbc, &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthRequired);
    assert_eq!(err.message, "login required: run `login rng`");
    assert_eq!(io.prompts(), ["IV (16 bytes, empty = random)"]);
    assert!(io.output().is_empty());
    assert_eq!(rng.calls(), random_calls(&[16]));
}

#[test]
fn random_prompt_without_trailing_parenthesis_gains_suffix() {
    let registry = providers();
    let spec = one_param_spec(ParamSpec::new("salt", ParamKind::Bytes, "Salt").random(8));
    let rng = FakeProvider::new(RNG);
    let io = ScriptedIo::new([""]);
    let values = resolve_rng(&registry, &io, &rng, &spec, &[]).unwrap();
    let expected = twin_draws(&[8]).remove(0);
    assert_eq!(
        values,
        params(vec![("salt", ParamValue::Bytes(expected.clone()))])
    );
    assert_eq!(io.prompts(), ["Salt (empty = random)"]);
    // the label is the whole prompt when it carries no parenthesized note
    assert_eq!(
        io.output(),
        [format!("Salt (random): {}", lower_hex(&expected))]
    );
    // a parenthesis that is not trailing does not count as the note
    let spec = one_param_spec(ParamSpec::new("n", ParamKind::Bytes, "Nonce (x) value").random(4));
    let io = ScriptedIo::new([""]);
    let rng = FakeProvider::new(RNG);
    resolve_rng(&registry, &io, &rng, &spec, &[]).unwrap();
    assert_eq!(io.prompts(), ["Nonce (x) value (empty = random)"]);
    assert!(io.output()[0].starts_with("Nonce (x) value (random): "));
}

#[test]
fn random_is_inert_on_non_bytes_params() {
    // `random` only applies to BYTES; on another kind the prompt and parsing are unchanged
    let registry = providers();
    let spec = one_param_spec(ParamSpec::new("n", ParamKind::Int, "N (count)").random(4));
    let rng = FakeProvider::new(RNG);
    let io = ScriptedIo::new(["", "5"]);
    let values = resolve_rng(&registry, &io, &rng, &spec, &[]).unwrap();
    assert_eq!(values, params(vec![("n", ParamValue::Int(5))]));
    assert_eq!(io.prompts(), ["N (count)", "N (count)"]);
    assert!(rng.calls().is_empty());
}

#[test]
fn random_inline_value_never_prompts_nor_draws() {
    let registry = providers();
    let reg = builtins();
    let rng = FakeProvider::new(RNG);
    let io = ScriptedIo::empty();
    let iv = format!("0x{}", "0d".repeat(16));
    let cbc = reg.get("aes.encrypt.cbc").unwrap();
    let values = resolve_rng(&registry, &io, &rng, cbc, &[("iv", &iv)]).unwrap();
    assert_eq!(values["iv"], ParamValue::Bytes(vec![0x0d; 16]));
    // an inline empty value is a parse error, never random (the fallback is prompt-only)
    let err = resolve_rng(&registry, &io, &rng, cbc, &[("iv", "")]).unwrap_err();
    assert_param_error(&err);
    assert_eq!(err.message, "iv: empty input");
    assert!(io.prompts().is_empty());
    assert!(io.output().is_empty());
    assert!(rng.calls().is_empty());
}
