// R0 skeleton — owner R3 (generated from spec §4)
use r2_provider::Provider;
use std::rc::Rc;

/// Factory handed to every case; called once per case (fresh provider, or a fresh view on
/// a shared token).
pub type MakeProvider<'a> = &'a dyn Fn() -> Rc<dyn Provider>;

/// One `pub fn <case>(make: MakeProvider<'_>)` per c2 ProviderContractTests method, same
/// names (34 cases). A mechanism-dependent case whose mechanism is not advertised returns
/// early after `skip(reason)` (never a failure).
pub mod cases {
    pub fn test_status_token_iff_logged_in(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_login_rejected_when_not_required(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_supports_is_consistent_with_mechanisms(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_import_export_round_trip_secret(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_imported_key_is_listed_and_found(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_find_key_not_found(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_find_key_ambiguity(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_duplicate_identity_refused(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_duplicate_identity_guard_exempts_families_and_certs(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_delete_key(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_find_key_class_selector_picks_keypair_half(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_non_exportable_key_refuses_export(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_pkcs11_secret_attributes_carry_flags(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_generate_secret_key(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_generate_keypair_shares_label(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_encrypt_decrypt_round_trip(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_sign_verify_round_trip(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_wrap_unwrap_round_trip_where_supported(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_certificate_acts_as_public_key(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_read_key_template_seeds_identity(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_update_key_renames_key(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_update_key_duplicate_identity_refused(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_update_key_leaves_siblings_untouched(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_update_key_refusal_is_outcome_not_exception(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_read_full_template_dumps_class_and_identity(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_generic_secret_round_trip(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_generate_generic_secret(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_hmac_sign_verify_round_trip(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_hmac_needs_a_generic_secret_and_cmac_an_aes_key(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_generic_secret_wrap_unwrap_where_supported(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_data_object_round_trip(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_data_object_identity_and_verbs(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_certificate_import_list_export_delete(make: super::MakeProvider<'_>) {
        let _ = make;
        unimplemented!("R3")
    }
    pub fn test_read_full_template_has_no_key_type_for_cert_and_data(
        make: super::MakeProvider<'_>,
    ) {
        let _ = make;
        unimplemented!("R3")
    }
}
/// Prints "SKIP: {reason}" to stderr (an allowed print site, §4.1.3).
pub fn skip(reason: &str) {
    let _ = reason;
    unimplemented!("R3")
}
/// Per-case unique label "{prefix}-{8 hex}" (shared-token isolation).
pub fn unique_label(prefix: &str) -> String {
    let _ = prefix;
    unimplemented!("R3")
}

/// Expands to `$(#[$attr])* mod $name { #[allow(unused_imports)] use super::*; #[test] fn
/// test_…() { $crate::contract::cases::test_…(&|| $make) } … }` — one #[test] per case. The
/// `use super::*;` is required: macro item paths are not hygienic, so `$make` resolves
/// inside the generated module and needs the caller's imports (`Rc`, `FakeProvider`,
/// `Provider`).
#[macro_export]
macro_rules! provider_contract_tests {
    ($(#[$attr:meta])* $name:ident, $make:expr) => {
        /* R3 */
    };
}
