// The reusable provider contract suite (spec §4.10.3, owner R3) — the port of c2
// `tests/contract/base.py` (ProviderContractTests). Each provider loop instantiates
// `provider_contract_tests!` in its own test file; the case bodies are never edited by
// other loops. Tests use realistic canonical material (§4.3 formats) so real providers
// pass unchanged; mechanism-dependent cases skip when the mechanism is not advertised.
use std::rc::Rc;

use r2_provider::Provider;

/// Factory handed to every case; called once per case (fresh provider, or a fresh view on
/// a shared token).
pub type MakeProvider<'a> = &'a dyn Fn() -> Rc<dyn Provider>;

/// One `pub fn <case>(make: MakeProvider<'_>)` per c2 ProviderContractTests method, same
/// names (34 cases). A mechanism-dependent case whose mechanism is not advertised returns
/// early after `skip(reason)` (never a failure).
pub mod cases {
    use r2_core::error::{ConsoleError, ErrorKind, Result};
    use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
    use r2_core::params::{ParamValue, Params};
    use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
    use r2_provider::{
        AuthState, GenerateRequest, KeySelector, MechanismInvocation, Provider, TokenInfo,
        UnwrapRequest, WrapOptions,
    };
    use secrecy::SecretString;

    use super::{MakeProvider, skip, unique_label};
    use crate::fixtures::rsa_pkcs8_and_cert;

    /// Any 32 bytes are a valid AES-256 key everywhere.
    fn aes_key() -> Vec<u8> {
        (0u8..32).collect()
    }
    /// 32-byte generic secret (>= SHA-256 digest length).
    fn generic_key() -> Vec<u8> {
        (40u8..72).collect()
    }
    const DATA_VALUE: &[u8] = b"hello, data object -- opaque bytes, not a key\x00\x01\x02";

    fn data_material() -> KeyMaterial {
        KeyMaterial::new(KeyAlgorithm::None, KeyClass::Data, DATA_VALUE.to_vec())
    }

    fn aes_material() -> KeyMaterial {
        KeyMaterial {
            size_bits: Some(256),
            ..KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, aes_key())
        }
    }

    fn generic_material() -> KeyMaterial {
        KeyMaterial::new(KeyAlgorithm::Generic, KeyClass::Secret, generic_key())
    }

    fn cert_material(cert_der: &[u8], size_bits: Option<u32>) -> KeyMaterial {
        KeyMaterial {
            size_bits,
            ..KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Certificate, cert_der.to_vec())
        }
    }

    fn template(extractable: bool, sensitive: bool) -> KeyTemplate {
        KeyTemplate::new(vec![
            TemplateAttr::new(
                "CKA_EXTRACTABLE",
                AttrKind::Bool,
                AttrValue::Bool(extractable),
            ),
            TemplateAttr::new("CKA_SENSITIVE", AttrKind::Bool, AttrValue::Bool(sensitive)),
        ])
    }

    fn label_change(label: &str) -> KeyTemplate {
        KeyTemplate::new(vec![TemplateAttr::new(
            "CKA_LABEL",
            AttrKind::Str,
            AttrValue::Str(label.to_owned()),
        )])
    }

    fn params(entries: Vec<(&str, ParamValue)>) -> Params {
        entries
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect()
    }

    fn enum_value(text: &str) -> ParamValue {
        ParamValue::Enum(text.to_owned())
    }

    fn mech(mechanism: &str, entries: Vec<(&str, ParamValue)>) -> MechanismInvocation {
        MechanismInvocation::new(mechanism, params(entries))
    }

    fn select(label: &str) -> KeySelector {
        KeySelector::label(label)
    }

    fn select_id(label: &str, key_id: &[u8]) -> KeySelector {
        KeySelector::label(label).with_id(Some(key_id.to_vec()))
    }

    fn select_class(label: &str, key_class: KeyClass) -> KeySelector {
        KeySelector::label(label).with_class(Some(key_class))
    }

    fn generate(
        provider: &dyn Provider,
        algorithm: KeyAlgorithm,
        size_bits: u32,
        label: &str,
        key_id: Option<&[u8]>,
        template: Option<KeyTemplate>,
    ) -> Result<KeyInfo> {
        let request = GenerateRequest {
            size_bits: Some(size_bits),
            key_id: key_id.map(<[u8]>::to_vec),
            template,
            ..GenerateRequest::new(algorithm, label)
        };
        provider.generate_key(&request)
    }

    #[track_caller]
    fn expect_kind<T: std::fmt::Debug>(result: Result<T>, kind: &ErrorKind) -> ConsoleError {
        match result {
            Ok(value) => panic!("expected {} error, got Ok({value:?})", kind.class_name()),
            Err(err) => {
                assert_eq!(
                    std::mem::discriminant(&err.kind),
                    std::mem::discriminant(kind),
                    "expected {}, got {} ({})",
                    kind.class_name(),
                    err.kind.class_name(),
                    err.message
                );
                err
            }
        }
    }

    /// Skips (returns false) unless the provider advertises `mechanism`.
    fn supports_or_skip(provider: &dyn Provider, mechanism: &str) -> bool {
        if provider.supports(mechanism) {
            return true;
        }
        skip(&format!(
            "{} does not advertise {mechanism}",
            provider.name()
        ));
        false
    }

    /// The symbolic text of a CKA_CLASS/CKA_KEY_TYPE dump row (a Symbol; c2 stored a str).
    fn symbol_text(value: &AttrValue) -> Option<&str> {
        match value {
            AttrValue::Symbol(text) | AttrValue::Str(text) => Some(text),
            _ => None,
        }
    }

    fn row<'t>(template: &'t KeyTemplate, name: &str) -> &'t TemplateAttr {
        template
            .get(name)
            .unwrap_or_else(|| panic!("template has no {name} row"))
    }

    // -- status / auth invariants ------------------------------------------------------

    pub fn test_status_token_iff_logged_in(make: MakeProvider<'_>) {
        let provider = make();
        let status = provider.status();
        assert_eq!(status.token.is_some(), status.auth == AuthState::LoggedIn);
    }

    pub fn test_login_rejected_when_not_required(make: MakeProvider<'_>) {
        let provider = make();
        if provider.status().auth != AuthState::NotRequired {
            skip("provider requires login");
            return;
        }
        let token = TokenInfo {
            slot_id: 0,
            label: "t".to_owned(),
            manufacturer: "m".to_owned(),
            model: "m".to_owned(),
            serial: "s".to_owned(),
        };
        expect_kind(
            provider.login(&token, &SecretString::from("0000"), false),
            &ErrorKind::UnsupportedOperation,
        );
    }

    pub fn test_supports_is_consistent_with_mechanisms(make: MakeProvider<'_>) {
        let provider = make();
        for mech in provider.mechanisms() {
            assert!(provider.supports(&mech), "{mech} listed but not supported");
        }
        assert!(!provider.supports("NO-SUCH-MECHANISM"));
    }

    // -- import / export / find ----------------------------------------------------------

    pub fn test_import_export_round_trip_secret(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-roundtrip");
        let info = provider
            .import_key(&aes_material(), &label, None, None)
            .unwrap();
        assert_eq!(info.key_ref.provider, provider.name());
        assert_eq!(info.key_ref.label, label);
        assert_eq!(info.key_class, KeyClass::Secret);
        assert_eq!(info.algorithm, KeyAlgorithm::Aes);
        assert_eq!(info.size_bits, Some(256));
        assert!(info.exportable);
        let exported = provider.export_key(&info).unwrap();
        assert_eq!(*exported.data, aes_key());
        assert_eq!(exported.key_class, KeyClass::Secret);
        assert_eq!(exported.algorithm, KeyAlgorithm::Aes);
    }

    pub fn test_imported_key_is_listed_and_found(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-find");
        let info = provider
            .import_key(&aes_material(), &label, None, Some(b"\x0a\x01"))
            .unwrap();
        assert!(
            provider
                .list_keys()
                .unwrap()
                .iter()
                .any(|k| k.key_ref == info.key_ref)
        );
        let found = provider.find_key(&select(&label)).unwrap();
        assert_eq!(found.key_ref.label, label);
        let found_by_id = provider.find_key(&select_id(&label, b"\x0a\x01")).unwrap();
        assert_eq!(
            found_by_id.key_ref.key_id.as_deref(),
            Some(&b"\x0a\x01"[..])
        );
    }

    pub fn test_find_key_not_found(make: MakeProvider<'_>) {
        let provider = make();
        expect_kind(
            provider.find_key(&select(&unique_label("cc-missing"))),
            &ErrorKind::KeyNotFound,
        );
    }

    pub fn test_find_key_ambiguity(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-dup");
        provider
            .import_key(&aes_material(), &label, None, Some(b"\x01"))
            .unwrap();
        provider
            .import_key(&aes_material(), &label, None, Some(b"\x02"))
            .unwrap();
        let err = expect_kind(
            provider.find_key(&select(&label)),
            &ErrorKind::AmbiguousKey {
                candidates: Vec::new(),
            },
        );
        assert_eq!(err.candidates().map(<[_]>::len), Some(2));
        // disambiguation by id still works
        let found = provider.find_key(&select_id(&label, b"\x02")).unwrap();
        assert_eq!(found.key_ref.key_id.as_deref(), Some(&b"\x02"[..]));
    }

    pub fn test_duplicate_identity_refused(make: MakeProvider<'_>) {
        // §4.7 guard: an exact (class, label, id) twin is refused at creation; duplicate
        // labels under distinct ids stay allowed (disambiguation design).
        let provider = make();
        let label = unique_label("cc-twin");
        provider
            .import_key(&aes_material(), &label, None, Some(b"\x77"))
            .unwrap();
        expect_kind(
            provider.import_key(&aes_material(), &label, None, Some(b"\x77")),
            &ErrorKind::DuplicateKey,
        );
        expect_kind(
            generate(
                &*provider,
                KeyAlgorithm::Aes,
                256,
                &label,
                Some(b"\x77"),
                None,
            ),
            &ErrorKind::DuplicateKey,
        );
        provider
            .import_key(&aes_material(), &label, None, Some(b"\x78"))
            .unwrap();
        let found = provider.find_key(&select_id(&label, b"\x78")).unwrap();
        assert_eq!(found.key_ref.key_id.as_deref(), Some(&b"\x78"[..]));
    }

    pub fn test_duplicate_identity_guard_exempts_families_and_certs(make: MakeProvider<'_>) {
        // Keypair halves share one label+id (§4.5) and PKCS#12 chain certs may repeat the
        // full identity (§5.4) — the guard must not block either.
        let provider = make();
        let label = unique_label("cc-family");
        let shared_id: &[u8] = b"\xcc\x02";
        generate(
            &*provider,
            KeyAlgorithm::Rsa,
            2048,
            &label,
            Some(shared_id),
            None,
        )
        .unwrap();
        let (_pkcs8, cert_der) = rsa_pkcs8_and_cert();
        let cert = cert_material(&cert_der, Some(2048));
        provider
            .import_key(&cert, &label, None, Some(shared_id))
            .unwrap();
        provider
            .import_key(&cert, &label, None, Some(shared_id))
            .unwrap(); // chain-cert rule
        expect_kind(
            generate(
                &*provider,
                KeyAlgorithm::Rsa,
                2048,
                &label,
                Some(shared_id),
                None,
            ),
            &ErrorKind::DuplicateKey,
        );
    }

    pub fn test_delete_key(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-delete");
        let info = provider
            .import_key(&aes_material(), &label, None, None)
            .unwrap();
        provider.delete_key(&info).unwrap();
        expect_kind(provider.find_key(&select(&label)), &ErrorKind::KeyNotFound);
    }

    pub fn test_find_key_class_selector_picks_keypair_half(make: MakeProvider<'_>) {
        // §4.3 ':<class>' selector: overrides the family class preference and addresses
        // the half directly; an absent class is a clean not-found.
        let provider = make();
        let label = unique_label("cc-classsel");
        let private = generate(&*provider, KeyAlgorithm::Rsa, 2048, &label, None, None).unwrap();
        let found = provider
            .find_key(&select_class(&label, KeyClass::Private))
            .unwrap();
        assert_eq!(found.key_ref, private.key_ref);
        let public = provider
            .find_key(&select_class(&label, KeyClass::Public))
            .unwrap();
        assert_eq!(public.key_class, KeyClass::Public);
        assert_eq!(public.key_ref.label, label);
        expect_kind(
            provider.find_key(&select_class(&label, KeyClass::Certificate)),
            &ErrorKind::KeyNotFound,
        );
    }

    // -- template-driven exportability (§5.5 semantics) ----------------------------------

    pub fn test_non_exportable_key_refuses_export(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-noexport");
        let info = provider
            .import_key(&aes_material(), &label, Some(&template(false, true)), None)
            .unwrap();
        assert!(!info.exportable);
        expect_kind(provider.export_key(&info), &ErrorKind::KeyNotExportable);
    }

    pub fn test_pkcs11_secret_attributes_carry_flags(make: MakeProvider<'_>) {
        let provider = make();
        if provider.type_name() != "pkcs11" {
            skip("§5.5 attribute guarantee applies to pkcs11 providers");
            return;
        }
        let label = unique_label("cc-flags");
        let info = provider
            .import_key(&aes_material(), &label, Some(&template(true, true)), None)
            .unwrap();
        assert_eq!(
            info.attributes.get("CKA_SENSITIVE"),
            Some(&AttrValue::Bool(true))
        );
        assert_eq!(
            info.attributes.get("CKA_EXTRACTABLE"),
            Some(&AttrValue::Bool(true))
        );
        assert!(!info.exportable); // sensitive wins over extractable
    }

    // -- generation ----------------------------------------------------------------------

    pub fn test_generate_secret_key(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-genaes");
        let info = generate(
            &*provider,
            KeyAlgorithm::Aes,
            256,
            &label,
            None,
            Some(template(true, false)),
        )
        .unwrap();
        assert_eq!(info.key_class, KeyClass::Secret);
        assert_eq!(info.algorithm, KeyAlgorithm::Aes);
        assert_eq!(info.size_bits, Some(256));
        assert!(
            provider
                .list_keys()
                .unwrap()
                .iter()
                .any(|k| k.key_ref.label == label)
        );
    }

    pub fn test_generate_keypair_shares_label(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-genrsa");
        let private = generate(&*provider, KeyAlgorithm::Rsa, 2048, &label, None, None).unwrap();
        assert_eq!(private.key_class, KeyClass::Private);
        assert_eq!(private.algorithm, KeyAlgorithm::Rsa);
        let publics: Vec<KeyInfo> = provider
            .list_keys()
            .unwrap()
            .into_iter()
            .filter(|k| k.key_ref.label == label && k.key_class == KeyClass::Public)
            .collect();
        assert_eq!(publics.len(), 1);
        assert_eq!(publics[0].key_ref.key_id, private.key_ref.key_id); // shared CKA_ID (§4.5)
        assert!(publics[0].exportable);
    }

    // -- crypto round trips --------------------------------------------------------------

    pub fn test_encrypt_decrypt_round_trip(make: MakeProvider<'_>) {
        let provider = make();
        if !supports_or_skip(&*provider, "AES-CBC") {
            return;
        }
        let label = unique_label("cc-cbc");
        let info = generate(
            &*provider,
            KeyAlgorithm::Aes,
            256,
            &label,
            None,
            Some(template(true, false)),
        )
        .unwrap();
        let mech = mech(
            "AES-CBC",
            vec![
                ("iv", ParamValue::Bytes(vec![0; 16])),
                ("padding", enum_value("pkcs7")),
            ],
        );
        let plaintext = b"attack at dawn - contract suite";
        let ciphertext = provider.encrypt(&info, &mech, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(
            *provider.decrypt(&info, &mech, &ciphertext).unwrap(),
            plaintext
        );
    }

    pub fn test_sign_verify_round_trip(make: MakeProvider<'_>) {
        let provider = make();
        if !supports_or_skip(&*provider, "AES-CMAC") {
            return;
        }
        let label = unique_label("cc-cmac");
        let info = generate(
            &*provider,
            KeyAlgorithm::Aes,
            256,
            &label,
            None,
            Some(template(true, false)),
        )
        .unwrap();
        let mech = mech("AES-CMAC", vec![("mac_len", ParamValue::Int(16))]);
        let data = b"message to authenticate";
        let signature = provider.sign(&info, &mech, data).unwrap();
        assert!(provider.verify(&info, &mech, data, &signature).unwrap());
        assert!(
            !provider
                .verify(&info, &mech, b"message to authenticate!", &signature)
                .unwrap()
        );
    }

    // -- wrap/unwrap where supported (§4.10) ---------------------------------------------

    fn wrap_mechanism(provider: &dyn Provider) -> Option<&'static str> {
        let found = ["AES-KEY-WRAP-PAD", "AES-KEY-WRAP"]
            .into_iter()
            .find(|mech| provider.supports(mech));
        if found.is_none() {
            skip(&format!(
                "{} advertises no AES key-wrap mechanism",
                provider.name()
            ));
        }
        found
    }

    pub fn test_wrap_unwrap_round_trip_where_supported(make: MakeProvider<'_>) {
        let provider = make();
        let Some(wrap_mech_name) = wrap_mechanism(&*provider) else {
            return;
        };
        let exportable = template(true, false);
        let wrapper = generate(
            &*provider,
            KeyAlgorithm::Aes,
            256,
            &unique_label("cc-kek"),
            None,
            Some(exportable.clone()),
        )
        .unwrap();
        let target = generate(
            &*provider,
            KeyAlgorithm::Aes,
            256,
            &unique_label("cc-target"),
            None,
            Some(exportable.clone()),
        )
        .unwrap();
        let mech = mech(wrap_mech_name, Vec::new());
        let blob = provider
            .wrap_key(&wrapper, &mech, &target, &WrapOptions::default())
            .unwrap();
        assert!(!blob.is_empty()); // non-empty opaque blob
        let request = UnwrapRequest {
            template: Some(exportable),
            ..UnwrapRequest::new(
                KeyAlgorithm::Aes,
                KeyClass::Secret,
                unique_label("cc-unwrapped"),
            )
        };
        let unwrapped = provider
            .unwrap_key(&wrapper, &mech, &blob, &request)
            .unwrap();
        assert_eq!(unwrapped.key_class, KeyClass::Secret);
        assert_eq!(
            provider.export_key(&unwrapped).unwrap().data,
            provider.export_key(&target).unwrap().data
        );
    }

    // -- certificate resolution (§4.3 / §5.11) ------------------------------------------

    pub fn test_certificate_acts_as_public_key(make: MakeProvider<'_>) {
        let provider = make();
        if !supports_or_skip(&*provider, "RSA-OAEP") || !supports_or_skip(&*provider, "RSA-PKCS1") {
            return;
        }
        let (pkcs8, cert_der) = rsa_pkcs8_and_cert();
        let shared_id: &[u8] = b"\xcc\x01";
        let priv_label = unique_label("cc-certpriv");
        let cert_label = unique_label("cc-cert");
        let private_material = KeyMaterial {
            size_bits: Some(2048),
            ..KeyMaterial::new(KeyAlgorithm::Rsa, KeyClass::Private, pkcs8)
        };
        let private = provider
            .import_key(
                &private_material,
                &priv_label,
                Some(&template(true, false)),
                Some(shared_id),
            )
            .unwrap();
        let cert = provider
            .import_key(
                &cert_material(&cert_der, Some(2048)),
                &cert_label,
                None,
                Some(shared_id),
            )
            .unwrap();
        assert_eq!(cert.key_class, KeyClass::Certificate);
        assert!(cert.exportable); // certificates: always exportable (§4.3)
        assert_eq!(*provider.export_key(&cert).unwrap().data, cert_der);

        let oaep = mech(
            "RSA-OAEP",
            vec![
                ("hash", enum_value("sha256")),
                ("mgf_hash", enum_value("sha256")),
                ("label", ParamValue::Bytes(Vec::new())),
            ],
        );
        let plaintext = b"certificate as public key";
        let ciphertext = provider.encrypt(&cert, &oaep, plaintext).unwrap(); // cert accepted
        assert_eq!(
            *provider.decrypt(&private, &oaep, &ciphertext).unwrap(),
            plaintext
        );

        let pkcs1 = mech("RSA-PKCS1", vec![("hash", enum_value("sha256"))]);
        let signature = provider.sign(&private, &pkcs1, plaintext).unwrap();
        assert!(
            provider
                .verify(&cert, &pkcs1, plaintext, &signature)
                .unwrap()
        ); // cert verifies

        expect_kind(
            provider.decrypt(&cert, &oaep, &ciphertext),
            &ErrorKind::UnsupportedOperation,
        );
        expect_kind(
            provider.sign(&cert, &pkcs1, plaintext),
            &ErrorKind::UnsupportedOperation,
        );
    }

    // -- key editing (§5.15) -------------------------------------------------------------

    /// The editable snapshot, or None after `skip` when the provider cannot edit keys.
    fn editable(provider: &dyn Provider, probe: &KeyInfo) -> Option<KeyTemplate> {
        match provider.read_key_template(probe) {
            Ok(template) => Some(template),
            Err(err) if err.kind == ErrorKind::UnsupportedOperation => {
                skip(&format!("{} does not support key editing", provider.name()));
                None
            }
            Err(err) => panic!("read_key_template failed: {err:?}"),
        }
    }

    pub fn test_read_key_template_seeds_identity(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-edit-seed");
        let info = provider
            .import_key(&aes_material(), &label, None, Some(b"\x0a\x01"))
            .unwrap();
        let Some(template) = editable(&*provider, &info) else {
            return;
        };
        let label_row = row(&template, "CKA_LABEL");
        assert!(label_row.enabled);
        assert_eq!(label_row.value, AttrValue::Str(label));
        let id_row = row(&template, "CKA_ID");
        assert_eq!(id_row.value, AttrValue::Bytes(b"\x0a\x01".to_vec()));
    }

    pub fn test_update_key_renames_key(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-edit-rename");
        let info = provider
            .import_key(&aes_material(), &label, None, Some(b"\xed\x01"))
            .unwrap();
        if editable(&*provider, &info).is_none() {
            return;
        }
        let new_label = unique_label("cc-edit-renamed");
        let result = provider
            .update_key(&info, &label_change(&new_label))
            .unwrap();
        let outcome = result
            .outcomes
            .iter()
            .find(|o| o.name == "CKA_LABEL")
            .expect("CKA_LABEL outcome");
        assert!(outcome.applied);
        assert_eq!(result.key.key_ref.label, new_label);
        let found = provider
            .find_key(&select_id(&new_label, b"\xed\x01"))
            .unwrap();
        assert_eq!(found.key_ref.label, new_label);
        expect_kind(provider.find_key(&select(&label)), &ErrorKind::KeyNotFound);
    }

    pub fn test_update_key_duplicate_identity_refused(make: MakeProvider<'_>) {
        // §4.7 guard on renames: refused BEFORE anything is applied.
        let provider = make();
        let label_a = unique_label("cc-edit-dupa");
        let label_b = unique_label("cc-edit-dupb");
        provider
            .import_key(&aes_material(), &label_a, None, Some(b"\xed\x02"))
            .unwrap();
        let info = provider
            .import_key(&aes_material(), &label_b, None, Some(b"\xed\x02"))
            .unwrap();
        if editable(&*provider, &info).is_none() {
            return;
        }
        expect_kind(
            provider.update_key(&info, &label_change(&label_a)),
            &ErrorKind::DuplicateKey,
        );
        let found = provider
            .find_key(&select_id(&label_b, b"\xed\x02"))
            .unwrap();
        assert_eq!(found.key_ref.label, label_b);
    }

    pub fn test_update_key_leaves_siblings_untouched(make: MakeProvider<'_>) {
        // §5.15: update_key is strictly single-object — family renames are a console-layer
        // confirm() flow, never provider magic.
        let provider = make();
        let label = unique_label("cc-edit-half");
        let private = generate(
            &*provider,
            KeyAlgorithm::Rsa,
            2048,
            &label,
            Some(b"\xed\x03"),
            None,
        )
        .unwrap();
        if editable(&*provider, &private).is_none() {
            return;
        }
        let new_label = unique_label("cc-edit-halfnew");
        provider
            .update_key(&private, &label_change(&new_label))
            .unwrap();
        let renamed = provider
            .find_key(&select_id(&new_label, b"\xed\x03"))
            .unwrap();
        assert_eq!(renamed.key_class, KeyClass::Private);
        // untouched under the old label
        let public = provider.find_key(&select_id(&label, b"\xed\x03")).unwrap();
        assert_eq!(public.key_class, KeyClass::Public);
    }

    pub fn test_update_key_refusal_is_outcome_not_exception(make: MakeProvider<'_>) {
        // §5.15: a refused attribute is a per-attr outcome; the rest still applies.
        let provider = make();
        let label = unique_label("cc-edit-refuse");
        let info = provider
            .import_key(&aes_material(), &label, None, Some(b"\xed\x04"))
            .unwrap();
        if editable(&*provider, &info).is_none() {
            return;
        }
        let new_label = unique_label("cc-edit-refnew");
        let changes = KeyTemplate::new(vec![
            // CKA_TOKEN is a storage attribute — uneditable on every backend (pkcs11 tokens
            // refuse it, memory/fake support identity only).
            TemplateAttr::new("CKA_TOKEN", AttrKind::Bool, AttrValue::Bool(false)),
            TemplateAttr::new(
                "CKA_LABEL",
                AttrKind::Str,
                AttrValue::Str(new_label.clone()),
            ),
        ]);
        let result = provider.update_key(&info, &changes).unwrap();
        let token_outcome = result
            .outcomes
            .iter()
            .find(|o| o.name == "CKA_TOKEN")
            .expect("CKA_TOKEN outcome");
        assert!(!token_outcome.applied);
        assert!(
            token_outcome
                .detail
                .as_deref()
                .is_some_and(|d| !d.is_empty())
        );
        let label_outcome = result
            .outcomes
            .iter()
            .find(|o| o.name == "CKA_LABEL")
            .expect("CKA_LABEL outcome");
        assert!(label_outcome.applied);
        let found = provider
            .find_key(&select_id(&new_label, b"\xed\x04"))
            .unwrap();
        assert_eq!(found.key_ref.label, new_label);
    }

    // -- full template dump (§5.16) ------------------------------------------------------

    /// The full dump, or None after `skip` when the provider cannot dump templates.
    fn full_template(provider: &dyn Provider, key: &KeyInfo) -> Option<KeyTemplate> {
        match provider.read_full_template(key) {
            Ok(template) => Some(template),
            Err(err) if err.kind == ErrorKind::UnsupportedOperation => {
                skip(&format!(
                    "{} does not support template dumps",
                    provider.name()
                ));
                None
            }
            Err(err) => panic!("read_full_template failed: {err:?}"),
        }
    }

    pub fn test_read_full_template_dumps_class_and_identity(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-full-tpl");
        let info = provider
            .import_key(&aes_material(), &label, None, Some(b"\x0f\x01"))
            .unwrap();
        let Some(template) = full_template(&*provider, &info) else {
            return;
        };
        // symbolic (§5.16)
        assert_eq!(
            symbol_text(&row(&template, "CKA_CLASS").value),
            Some("CKO_SECRET_KEY")
        );
        assert_eq!(
            symbol_text(&row(&template, "CKA_KEY_TYPE").value),
            Some("CKK_AES")
        );
        assert_eq!(row(&template, "CKA_LABEL").value, AttrValue::Str(label));
        assert_eq!(
            row(&template, "CKA_ID").value,
            AttrValue::Bytes(b"\x0f\x01".to_vec())
        );
        let identity = ["CKA_CLASS", "CKA_KEY_TYPE", "CKA_LABEL", "CKA_ID"];
        // the dump goes beyond identity — policy/state attrs included
        assert!(
            template
                .attrs
                .iter()
                .any(|attr| !identity.contains(&attr.name.as_str()))
        );
    }

    // -- generic secrets & HMAC (§4.3 / §5.9) --------------------------------------------

    pub fn test_generic_secret_round_trip(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-generic");
        let info = provider
            .import_key(
                &generic_material(),
                &label,
                Some(&template(true, false)),
                None,
            )
            .unwrap();
        assert_eq!(info.key_class, KeyClass::Secret);
        assert_eq!(info.algorithm, KeyAlgorithm::Generic);
        assert_eq!(info.size_bits, Some(32 * 8));
        assert!(info.exportable);
        assert!(
            provider
                .list_keys()
                .unwrap()
                .iter()
                .any(|k| k.key_ref == info.key_ref)
        );
        let exported = provider.export_key(&info).unwrap();
        assert_eq!(*exported.data, generic_key());
        assert_eq!(exported.algorithm, KeyAlgorithm::Generic);
    }

    pub fn test_generate_generic_secret(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-gen-generic");
        let info = generate(&*provider, KeyAlgorithm::Generic, 512, &label, None, None).unwrap();
        assert_eq!(info.key_class, KeyClass::Secret);
        assert_eq!(info.algorithm, KeyAlgorithm::Generic);
        assert_eq!(info.size_bits, Some(512));
        assert_eq!(
            provider.find_key(&select(&label)).unwrap().key_ref,
            info.key_ref
        );
    }

    pub fn test_hmac_sign_verify_round_trip(make: MakeProvider<'_>) {
        let provider = make();
        if !supports_or_skip(&*provider, "HMAC") {
            return;
        }
        let info = provider
            .import_key(&generic_material(), &unique_label("cc-hmac"), None, None)
            .unwrap();
        let data = b"the quick brown fox";
        let full = mech("HMAC", vec![("hash", enum_value("sha256"))]);
        let mac = provider.sign(&info, &full, data).unwrap();
        assert_eq!(mac.len(), 32); // full SHA-256 digest by default
        assert!(provider.verify(&info, &full, data, &mac).unwrap());
        assert!(
            !provider
                .verify(&info, &full, b"the quick brown fox!", &mac)
                .unwrap()
        );
        let truncated = mech(
            "HMAC",
            vec![
                ("hash", enum_value("sha256")),
                ("mac_len", ParamValue::Int(16)),
            ],
        );
        let short = provider.sign(&info, &truncated, data).unwrap();
        assert_eq!(short.len(), 16);
        assert_eq!(short, mac[..16]); // truncation == CKM_SHAx_HMAC_GENERAL(16) by definition
        assert!(provider.verify(&info, &truncated, data, &short).unwrap());
    }

    pub fn test_hmac_needs_a_generic_secret_and_cmac_an_aes_key(make: MakeProvider<'_>) {
        let provider = make();
        if !supports_or_skip(&*provider, "HMAC") {
            return;
        }
        let aes = provider
            .import_key(&aes_material(), &unique_label("cc-hmac-aes"), None, None)
            .unwrap();
        expect_kind(
            provider.sign(&aes, &mech("HMAC", Vec::new()), b"x"),
            &ErrorKind::UnsupportedOperation,
        );
        if provider.supports("AES-CMAC") {
            let generic = provider
                .import_key(
                    &generic_material(),
                    &unique_label("cc-cmac-generic"),
                    None,
                    None,
                )
                .unwrap();
            expect_kind(
                provider.sign(&generic, &mech("AES-CMAC", Vec::new()), b"x"),
                &ErrorKind::UnsupportedOperation,
            );
        }
    }

    pub fn test_generic_secret_wrap_unwrap_where_supported(make: MakeProvider<'_>) {
        let provider = make();
        let Some(wrap_mech_name) = wrap_mechanism(&*provider) else {
            return;
        };
        let exportable = template(true, false);
        let wrapper = generate(
            &*provider,
            KeyAlgorithm::Aes,
            256,
            &unique_label("cc-gkek"),
            None,
            Some(exportable.clone()),
        )
        .unwrap();
        let target = provider
            .import_key(
                &generic_material(),
                &unique_label("cc-gtarget"),
                Some(&exportable),
                None,
            )
            .unwrap();
        let mech = mech(wrap_mech_name, Vec::new());
        let blob = provider
            .wrap_key(&wrapper, &mech, &target, &WrapOptions::default())
            .unwrap();
        let request = UnwrapRequest {
            template: Some(exportable),
            ..UnwrapRequest::new(
                KeyAlgorithm::Generic,
                KeyClass::Secret,
                unique_label("cc-gunwrapped"),
            )
        };
        let unwrapped = provider
            .unwrap_key(&wrapper, &mech, &blob, &request)
            .unwrap();
        assert_eq!(unwrapped.key_class, KeyClass::Secret);
        assert_eq!(unwrapped.algorithm, KeyAlgorithm::Generic);
        assert_eq!(
            *provider.export_key(&unwrapped).unwrap().data,
            generic_key()
        );
    }

    // -- data objects (§4.3 CKO_DATA) ----------------------------------------------------

    pub fn test_data_object_round_trip(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-data");
        let info = provider
            .import_key(&data_material(), &label, None, None)
            .unwrap();
        assert_eq!(info.key_class, KeyClass::Data);
        assert_eq!(info.algorithm, KeyAlgorithm::None);
        assert_eq!(info.key_ref.key_id, None); // data objects carry no CKA_ID (§4.3)
        assert_eq!(info.size_bits, u32::try_from(DATA_VALUE.len() * 8).ok());
        assert!(info.exportable);
        assert!(
            provider
                .list_keys()
                .unwrap()
                .iter()
                .any(|k| k.key_ref == info.key_ref && k.key_class == KeyClass::Data)
        );
        assert_eq!(
            provider.find_key(&select(&label)).unwrap().key_class,
            KeyClass::Data
        );
        assert_eq!(
            provider
                .find_key(&select_class(&label, KeyClass::Data))
                .unwrap()
                .key_ref,
            info.key_ref
        );
        let exported = provider.export_key(&info).unwrap();
        assert_eq!(exported.key_class, KeyClass::Data);
        assert_eq!(*exported.data, DATA_VALUE);
        provider.delete_key(&info).unwrap();
        expect_kind(provider.find_key(&select(&label)), &ErrorKind::KeyNotFound);
    }

    pub fn test_data_object_identity_and_verbs(make: MakeProvider<'_>) {
        let provider = make();
        let label = unique_label("cc-data-id");
        expect_kind(
            provider.import_key(&data_material(), &label, None, Some(b"\x01")),
            &ErrorKind::Param {
                param_name: String::new(),
            },
        );
        let info = provider
            .import_key(&data_material(), &label, None, None)
            .unwrap();
        // (class, label) twin — no id to disambiguate
        expect_kind(
            provider.import_key(&data_material(), &label, None, None),
            &ErrorKind::DuplicateKey,
        );
        let cmac = mech("AES-CMAC", Vec::new());
        expect_kind(
            provider.sign(&info, &cmac, b"x"),
            &ErrorKind::UnsupportedOperation,
        );
        expect_kind(
            provider.encrypt(&info, &mech("AES-ECB", Vec::new()), &[b'x'; 16]),
            &ErrorKind::UnsupportedOperation,
        );
    }

    // -- certificates as plain objects (§4.3 / §5.4 / §5.6) ------------------------------

    pub fn test_certificate_import_list_export_delete(make: MakeProvider<'_>) {
        let provider = make();
        let (_pkcs8, cert_der) = rsa_pkcs8_and_cert();
        let label = unique_label("cc-cert-plain");
        let cert = provider
            .import_key(&cert_material(&cert_der, Some(2048)), &label, None, None)
            .unwrap();
        assert_eq!(cert.key_class, KeyClass::Certificate);
        assert_eq!(cert.algorithm, KeyAlgorithm::Rsa); // the embedded public key's algorithm
        assert_eq!(cert.size_bits, Some(2048));
        assert!(cert.exportable);
        assert!(
            provider
                .list_keys()
                .unwrap()
                .iter()
                .any(|k| k.key_ref == cert.key_ref && k.key_class == KeyClass::Certificate)
        );
        assert_eq!(
            provider.find_key(&select(&label)).unwrap().key_class,
            KeyClass::Certificate
        );
        assert_eq!(
            provider
                .find_key(&select_class(&label, KeyClass::Certificate))
                .unwrap()
                .key_ref,
            cert.key_ref
        );
        let exported = provider.export_key(&cert).unwrap();
        assert_eq!(exported.key_class, KeyClass::Certificate);
        assert_eq!(*exported.data, cert_der); // DER, byte-identical
        provider.delete_key(&cert).unwrap();
        expect_kind(provider.find_key(&select(&label)), &ErrorKind::KeyNotFound);
    }

    pub fn test_read_full_template_has_no_key_type_for_cert_and_data(make: MakeProvider<'_>) {
        let provider = make();
        let (_pkcs8, cert_der) = rsa_pkcs8_and_cert();
        let cert = provider
            .import_key(
                &cert_material(&cert_der, None),
                &unique_label("cc-full-cert"),
                None,
                None,
            )
            .unwrap();
        let data = provider
            .import_key(&data_material(), &unique_label("cc-full-data"), None, None)
            .unwrap();
        let Some(cert_template) = full_template(&*provider, &cert) else {
            return;
        };
        let data_template = provider.read_full_template(&data).unwrap();
        assert_eq!(
            symbol_text(&row(&cert_template, "CKA_CLASS").value),
            Some("CKO_CERTIFICATE")
        );
        // certs carry CKA_CERTIFICATE_TYPE instead
        assert!(cert_template.get("CKA_KEY_TYPE").is_none());
        assert_eq!(
            symbol_text(&row(&data_template, "CKA_CLASS").value),
            Some("CKO_DATA")
        );
        assert!(data_template.get("CKA_KEY_TYPE").is_none());
        assert!(data_template.get("CKA_ID").is_none()); // data objects carry no CKA_ID (§4.3)
        assert_eq!(
            row(&data_template, "CKA_LABEL").value,
            AttrValue::Str(data.key_ref.label.clone())
        );
    }
}

/// Prints "SKIP: {reason}" to stderr (an allowed print site, §4.1.3).
#[allow(clippy::print_stderr)] // the sanctioned contract-suite skip notice (§4.1.3)
pub fn skip(reason: &str) {
    eprintln!("SKIP: {reason}");
}

/// Per-case unique label "{prefix}-{8 hex}" (shared-token isolation).
pub fn unique_label(prefix: &str) -> String {
    let mut random = [0u8; 4];
    openssl::rand::rand_bytes(&mut random).expect("random label suffix");
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{prefix}-{suffix}")
}

/// Expands to `$(#[$attr])* mod $name { #[allow(unused_imports)] use super::*; #[test] fn
/// test_…() { $crate::contract::cases::test_…(&|| $make) } … }` — one #[test] per case. The
/// `use super::*;` is required: macro item paths are not hygienic, so `$make` resolves
/// inside the generated module and needs the caller's imports (`Rc`, `FakeProvider`,
/// `Provider`).
#[macro_export]
macro_rules! provider_contract_tests {
    ($(#[$attr:meta])* $name:ident, $make:expr) => {
        $(#[$attr])*
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            $crate::provider_contract_tests!(@cases $make;
                test_status_token_iff_logged_in,
                test_login_rejected_when_not_required,
                test_supports_is_consistent_with_mechanisms,
                test_import_export_round_trip_secret,
                test_imported_key_is_listed_and_found,
                test_find_key_not_found,
                test_find_key_ambiguity,
                test_duplicate_identity_refused,
                test_duplicate_identity_guard_exempts_families_and_certs,
                test_delete_key,
                test_find_key_class_selector_picks_keypair_half,
                test_non_exportable_key_refuses_export,
                test_pkcs11_secret_attributes_carry_flags,
                test_generate_secret_key,
                test_generate_keypair_shares_label,
                test_encrypt_decrypt_round_trip,
                test_sign_verify_round_trip,
                test_wrap_unwrap_round_trip_where_supported,
                test_certificate_acts_as_public_key,
                test_read_key_template_seeds_identity,
                test_update_key_renames_key,
                test_update_key_duplicate_identity_refused,
                test_update_key_leaves_siblings_untouched,
                test_update_key_refusal_is_outcome_not_exception,
                test_read_full_template_dumps_class_and_identity,
                test_generic_secret_round_trip,
                test_generate_generic_secret,
                test_hmac_sign_verify_round_trip,
                test_hmac_needs_a_generic_secret_and_cmac_an_aes_key,
                test_generic_secret_wrap_unwrap_where_supported,
                test_data_object_round_trip,
                test_data_object_identity_and_verbs,
                test_certificate_import_list_export_delete,
                test_read_full_template_has_no_key_type_for_cert_and_data,
            );
        }
    };
    (@cases $make:expr; $($case:ident),* $(,)?) => {
        $(
            #[test]
            fn $case() {
                $crate::contract::cases::$case(&|| $make)
            }
        )*
    };
}
