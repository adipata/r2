#!/usr/bin/env python3
"""Generate the r2 parity ledger (parity/ledger.csv) from c2's pytest collection.

One row per c2 test FUNCTION (parametrizations collapsed), assigned to exactly one
r2 loop (PLAN.md §8 loop cards; per-test overrides below for files split across
loops). Run from the r2 repo root:

    C2_DIR=../c2 python3 parity/generate_ledger.py            # (re)write the ledger
    C2_DIR=../c2 python3 parity/generate_ledger.py --check    # verify, write nothing

C2_DIR defaults to the sibling ``../c2`` checkout (frozen at 408d6f2). The c2 side
is collected with exactly:

    uv run pytest --collect-only -q -p no:cacheprovider            (all node IDs)
    uv run pytest --collect-only -q -p no:cacheprovider -m <mark>  (softhsm/xfail/skipif tags)

Regenerating is idempotent and merge-safe: for every row that already exists in
the ledger, a non-``todo`` status, the ``rust_test`` value and any note text a loop
appended after the generated note are preserved. Stdlib only.
"""

from __future__ import annotations

import argparse
import ast
import csv
import io
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

R2_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_C2 = R2_ROOT.parent / "c2"
LEDGER = R2_ROOT / "parity" / "ledger.csv"
COLUMNS = ["python_test", "params", "r_loop", "status", "rust_test", "note"]
LOOPS = [
    "R0", "R1", "R2", "R3", "R4", "R5a", "R5b", "R6", "R7",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
]  # fmt: skip
STATUS_RE = re.compile(r"^(todo|ported|n/a:\S.*)$")
TAG_MARKS = ("softhsm", "xfail", "skipif")
CONTRACT_BASE_FILE = "tests/contract/base.py"
CONTRACT_BASE_CLASS = "ProviderContractTests"

# ---------------------------------------------------------------------------
# 1. File-level mapping (PLAN.md §8 "Ports" lines)
# ---------------------------------------------------------------------------

FILE_LOOP: dict[str, str] = {
    # R0 — workspace, skeleton, softhsm fixture
    "tests/integration/test_softhsm_fixture.py": "R0",
    # R1 — core model & codec
    "tests/unit/core/test_codec.py": "R1",
    "tests/unit/core/test_datainput.py": "R1",
    "tests/unit/core/test_errors.py": "R1",
    "tests/unit/core/test_io_protocols.py": "R1",
    "tests/unit/core/test_keys.py": "R1",
    "tests/unit/core/test_keys_objects.py": "R1",
    "tests/unit/core/test_params.py": "R1",
    "tests/unit/core/test_scripted_io.py": "R1",
    "tests/unit/core/test_templates.py": "R1",
    # R2 — configuration
    "tests/unit/test_config.py": "R2",
    "tests/unit/test_config_objects.py": "R2",
    # R3 — provider & operation contracts (+ contract suite, FakeProvider)
    CONTRACT_BASE_FILE: "R3",
    "tests/contract/test_fake_provider.py": "R3",
    "tests/unit/test_provider_base.py": "R3",
    "tests/unit/test_ops_registry.py": "R3",
    "tests/unit/test_ops_objects.py": "R3",
    # R4 — memory provider
    "tests/unit/test_memory_provider.py": "R4",
    "tests/unit/test_memory_objects.py": "R4",
    "tests/unit/test_memory_wrap_kek.py": "R4",
    # R5a — PKCS#11 foundation
    "tests/unit/pkcs11/test_attributes.py": "R5a",
    "tests/unit/pkcs11/test_provider_session.py": "R5a",
    "tests/unit/pkcs11/test_softhsm_detect.py": "R5a",
    "tests/unit/pkcs11/test_objects.py": "R5a",
    "tests/unit/pkcs11/test_provider_objects.py": "R5a",
    # R5b — PKCS#11 crypto, wrap, derive, edit
    "tests/unit/pkcs11/test_mechanisms.py": "R5b",
    "tests/unit/pkcs11/test_provider_edit.py": "R5b",
    "tests/unit/pkcs11/test_wrap_kek.py": "R5b",
    "tests/integration/test_pkcs11_provider.py": "R5b",
    "tests/integration/test_objects_softhsm.py": "R5b",
    # R6 — key formats & X.509
    "tests/unit/test_keyparse.py": "R6",
    "tests/unit/test_x509build.py": "R6",
    # R7 — console shell, framework, ParamResolver, CLI
    "tests/unit/console/test_app.py": "R7",
    "tests/unit/console/test_io.py": "R7",
    "tests/unit/console/test_parser.py": "R7",
    "tests/unit/console/test_completer.py": "R7",
    "tests/unit/console/test_render.py": "R7",
    "tests/unit/console/test_repl.py": "R7",
    "tests/unit/console/test_discovery.py": "R7",
    "tests/unit/console/test_logging_setup.py": "R7",
    "tests/unit/console/test_commands.py": "R7",
    "tests/unit/test_params.py": "R7",
    "tests/unit/test_smoke.py": "R7",
    # R8 — provider & key commands, keyload/keyexport/certops
    "tests/unit/console/test_providers_cmd.py": "R8",
    "tests/unit/console/test_keys_cmd.py": "R8",
    "tests/unit/console/test_keys_cmd_objects.py": "R8",
    "tests/unit/services/test_keyload.py": "R8",
    "tests/unit/services/test_keyexport.py": "R8",
    "tests/unit/services/test_certops.py": "R8",
    "tests/unit/services/test_objects_services.py": "R8",
    "tests/integration/test_console_keys.py": "R8",
    # R9 — crypto commands
    "tests/unit/test_crypto_cmd.py": "R9",
    "tests/integration/test_console_crypto.py": "R9",
    # R10 — template editor & copy
    "tests/unit/console/test_template_editor.py": "R10",
    "tests/unit/console/test_copy_cmd.py": "R10",
    "tests/unit/test_transfer.py": "R10",
    "tests/integration/test_copy.py": "R10",
    # R11 — SoftHSM wizard
    "tests/unit/console/test_wizard.py": "R11",
    "tests/integration/test_wizard.py": "R11",
    # R13 — integration, parity sign-off
    "tests/integration/test_end_to_end.py": "R13",
    "tests/integration/test_custom_mechanism.py": "R13",
    "tests/unit/test_l13_hardening.py": "R13",
    # R14 — template files
    "tests/unit/services/test_templatefile.py": "R14",
    # R15 — wrapped-key load/export
    "tests/unit/services/test_wrapload.py": "R15",
    "tests/unit/console/test_load_kek.py": "R15",
    "tests/unit/console/test_export_kek.py": "R15",
    "tests/integration/test_load_kek.py": "R15",
}

FILE_NOTE: dict[str, str] = {
    "tests/unit/console/test_io.py": (
        "PromptToolkitIO over pipe input: port against the piped PlainIo where the "
        "behavior is reader-level; reedline-only behavior goes to the R13 manual "
        "terminal checklist"
    ),
    "tests/integration/test_load_kek.py": (
        "uses --template files (R14) to give KEKs CKA_WRAP/CKA_UNWRAP: needs R14 "
        "merged first (PLAN has no R15->R14 edge)"
    ),
    "tests/integration/test_objects_softhsm.py": (
        "PLAN R13 card lists this file but it holds no console e2e test: "
        "provider-level -> R5b, transfer::copy_key legs -> R10"
    ),
    "tests/unit/test_l13_hardening.py": (
        "L13 glue-fix regression (PLAN R13 card lists the file); assigned to the "
        "loop owning the code under test"
    ),
}

# ---------------------------------------------------------------------------
# 2. Per-test overrides for files split across loops: python_test -> (loop, note)
# ---------------------------------------------------------------------------

_KEYS = "tests/unit/console/test_keys_cmd.py::"
_KOBJ = "tests/unit/console/test_keys_cmd_objects.py::"
_COPY = "tests/unit/console/test_copy_cmd.py::"
_OSVC = "tests/unit/services/test_objects_services.py::"
_CKEYS = "tests/integration/test_console_keys.py::"
_OSOFT = "tests/integration/test_objects_softhsm.py::"
_IPK = "tests/integration/test_pkcs11_provider.py::"
_POBJ = "tests/unit/pkcs11/test_provider_objects.py::"
_PKOBJ = "tests/unit/pkcs11/test_objects.py::"
_L13 = "tests/unit/test_l13_hardening.py::"
_PROV = "tests/unit/console/test_providers_cmd.py::"
_REND = "tests/unit/console/test_render.py::"
_APP = "tests/unit/console/test_app.py::"
_CERT = "tests/unit/services/test_certops.py::"
_KEXP = "tests/unit/services/test_keyexport.py::"
_MECH = "tests/unit/pkcs11/test_mechanisms.py::"

_TEMPLATE_FILE = "--template / key template / templatefile -> R14"
_SEED = (
    "--template seeding (seed_templates) needs templatefile::build_seed (R14); "
    "R14 ports it into its own test file"
)
_R5B_MOVED = "moved from the R5a test file: exercises R5b-owned provider code"
_R1_RENDER = "renderer moved to R1 (spec §4.1.1): r2_core::render"
_R6_FORMATS = (
    "keyexport serializer moved to R6 (spec §4.1.1): port the byte assertions against "
    "r2_core::formats; the export_bytes format-resolution part is R8's keyexport dispatch"
)
_R5A_CAPABILITY = "moved to R5a (spec §4.1.1): capability.rs"
_CKEYS_EDITOR = (
    "drives the real checklist editor ('ok' answers, R10): port once R10 merges "
    "or script an accept-all editor until then"
)

OVERRIDES: dict[str, tuple[str, str]] = {
    # --- test_smoke: version part -> R0 (R0 card), rest -> R7 --------------------
    "tests/unit/test_smoke.py::test_subpackage_imports": ("R0", ""),
    "tests/unit/test_smoke.py::test_version_string": ("R0", "R0 card: test_smoke (version part)"),
    "tests/unit/test_smoke.py::test_version_matches_distribution_metadata": (
        "R0",
        "Rust: `r2 --version` prints CARGO_PKG_VERSION (workspace version)",
    ),
    "tests/unit/test_smoke.py::test_main_version_flag": (
        "R0",
        "R0 card: r2-cli stub --version",
    ),
    # --- test_keys_cmd: key template / --template -> R14 -------------------------
    _KEYS + "test_key_template_rejects_memory_provider": ("R14", _TEMPLATE_FILE),
    _KEYS + "test_key_template_dumps_class_keyed_file": ("R14", _TEMPLATE_FILE),
    _KEYS + "test_key_template_warns_when_material_dumped": ("R14", _TEMPLATE_FILE),
    _KEYS + "test_generate_template_seeds_editor_from_file": ("R14", _TEMPLATE_FILE),
    _KEYS + "test_generate_keypair_template_section_per_editor": ("R14", _TEMPLATE_FILE),
    _KEYS + "test_generate_template_on_memory_target_raises": ("R14", _TEMPLATE_FILE),
    _KEYS + "test_load_template_seeds_editor_from_file": ("R14", _TEMPLATE_FILE),
    # --- test_keys_cmd_objects: copy -> R10, ops/sign/verify -> R9 ----------------
    _KOBJ + "test_copy_output_uses_table_vocabulary": (
        "R10",
        "copy command output (commands/copy.rs is R10's)",
    ),
    _KOBJ + "test_ops_lists_hmac_rows": ("R9", "`ops` command (commands/crypto.rs is R9's)"),
    _KOBJ + "test_sign_verify_hmac_round_trip": (
        "R9",
        "`verify ... hmac` command (commands/crypto.rs is R9's)",
    ),
    # --- test_copy_cmd: --template -> R14 -----------------------------------------
    _COPY + "test_copy_template_seeds_destination_editor": ("R14", _TEMPLATE_FILE),
    _COPY + "test_copy_template_memory_destination_raises": ("R14", _TEMPLATE_FILE),
    # --- seed_templates through keyload / transfer / wrapload -> R14 --------------
    "tests/unit/services/test_keyload.py::test_import_seed_template_section_replaces_defaults": (
        "R14",
        _SEED,
    ),
    "tests/unit/services/test_keyload.py::test_import_pkcs12_picks_section_per_material": (
        "R14",
        _SEED,
    ),
    "tests/unit/test_transfer.py::TestTemplateFileSeeding::"
    "test_wrap_route_editor_seeded_from_matching_section": ("R14", _SEED),
    "tests/unit/test_transfer.py::TestTemplateFileSeeding::"
    "test_wrap_route_missing_section_falls_back_to_defaults": ("R14", _SEED),
    "tests/unit/services/test_wrapload.py::test_load_wrapped_seed_templates_reach_the_editor": (
        "R14",
        _SEED,
    ),
    # --- test_objects_services: keyload/keyexport -> R8 (file default),
    #     transfer -> R10, wrapload -> R15 ------------------------------------------
    _OSVC + "test_export_and_wrap_refuse_unmodelled_key_types": (
        "R15",
        "wrapload::refuse_non_wrappable (R15); also asserts the keyexport refusal (R8)",
    ),
    _OSVC + "test_copy_data_object_takes_the_plain_route": ("R10", "transfer part"),
    _OSVC + "test_copy_seeds_data_extras_into_the_editor": ("R10", "transfer part"),
    _OSVC + "test_copy_certificate_round_trip_is_plain_material": ("R10", "transfer part"),
    _OSVC + "test_copy_refuses_unmodelled_key_types": ("R10", "transfer part"),
    _OSVC + "test_wrapload_generic_hint_and_data_refusal": ("R15", "wrapload part"),
    # --- integration/test_console_keys ----------------------------------------------
    _CKEYS + "test_console_keys_end_to_end": ("R8", _CKEYS_EDITOR),
    _CKEYS + "test_export_refusal_and_p12_self_signed": ("R8", _CKEYS_EDITOR),
    _CKEYS + "test_generate_honors_template_editor_cka_id": (
        "R10",
        "editor `add CKA_ID=...` + identity-row note through the real checklist "
        "editor (R10); provider identity resolution is R5a",
    ),
    _CKEYS + "test_key_template_dump_and_reseed": ("R14", "SoftHSM dump -> reseed round trip"),
    # --- integration/test_objects_softhsm: copy legs -> R10 ------------------------
    _OSOFT + "test_generic_secret_copy_round_trip": ("R10", "transfer::copy_key mem<->SoftHSM"),
    _OSOFT + "test_data_object_lifecycle_on_token": (
        "R10",
        "provider data-object lifecycle (R5a/R5b) plus transfer::copy_key legs",
    ),
    _OSOFT + "test_certificate_copy_round_trip": ("R10", "transfer::copy_key mem<->SoftHSM"),
    # --- integration/test_pkcs11_provider: foundation classes -> R5a ---------------
    _IPK + "TestLogin::test_login_status_logout": ("R5a", "R5a accept: SoftHSM login"),
    _IPK + "TestLogin::test_wrong_pin": ("R5a", "R5a accept: SoftHSM login"),
    _IPK + "TestGenerate::test_generate_aes_applies_template": ("R5a", "R5a accept: generate"),
    _IPK + "TestGenerate::test_generate_rsa_keypair_shared_label_and_id": (
        "R5a",
        "R5a accept: generate",
    ),
    _IPK + "TestLoadObjects::test_load_aes_rsa_ec_and_cert": (
        "R5a",
        "R5a accept: import of every object kind",
    ),
    _IPK + "TestInitToken::test_init_token_label_round_trips_exactly": (
        "R5a",
        "init_token is R5a-owned",
    ),
    # --- unit/pkcs11/test_provider_objects: verbs/wrap/derive/full template -> R5b ---
    _POBJ + "TestKeyManagement::test_unwrap_honors_template_id": ("R5b", _R5B_MOVED + " (unwrap)"),
    _POBJ + "TestKeyManagement::test_rsa_raw_decrypt_with_public_key_runs_in_software": (
        "R5b",
        _R5B_MOVED + " (public-key RSA-RAW software fallback)",
    ),
    _POBJ + "TestCkrMapping::test_mechanism_invalid_maps_to_unsupported": (
        "R5b",
        _R5B_MOVED + " (encrypt path; CKR table itself is R5a)",
    ),
    _POBJ + "TestCustomMechanisms::test_custom_ckm_advertised": (
        "R5a",
        "custom ckm->id merge in mechanisms()/supports() (capability.rs, spec §4.1.1)",
    ),
    _POBJ + "TestCustomMechanisms::test_custom_ckm_not_advertised_without_token_support": (
        "R5a",
        "custom ckm->id merge in mechanisms() (capability.rs, spec §4.1.1)",
    ),
    _POBJ + "TestCustomMechanisms::test_custom_dispatch_uses_raw_ckm": (
        "R5b",
        _R5B_MOVED + " (raw packer dispatch)",
    ),
    _POBJ + "TestCustomMechanisms::test_unadvertised_mechanism_rejected": (
        "R5b",
        _R5B_MOVED + " (encrypt path)",
    ),
    _POBJ + "TestWrapUnwrap::test_wrap_pad_prefers_kwp_when_advertised": (
        "R5b",
        _R5B_MOVED + " (KWP preference)",
    ),
    _POBJ + "TestWrapUnwrap::test_wrap_pad_uses_pad_ckm_when_kwp_absent": (
        "R5b",
        _R5B_MOVED + " (KWP preference)",
    ),
    _POBJ + "TestWrapUnwrap::test_wrap_unwrap_round_trip": ("R5b", _R5B_MOVED + " (wrap/unwrap)"),
    _POBJ + "TestWrapUnwrap::test_wrap_refuses_unextractable_target": (
        "R5b",
        _R5B_MOVED + " (wrap/unwrap)",
    ),
    _POBJ + "TestDerive::test_derive_extractable_returns_raw": ("R5b", _R5B_MOVED + " (derive)"),
    _POBJ + "TestDerive::test_derive_degrades_to_resident_key_when_forbidden": (
        "R5b",
        _R5B_MOVED + " (derive resident fallback)",
    ),
    _POBJ + "TestTwinSafety::test_sign_with_twins_uses_selected_twin": (
        "R5b",
        _R5B_MOVED + " (sign; twin targeting itself is R5a)",
    ),
    _POBJ + "TestDuplicateGuard::test_unwrap_duplicate_identity_refused": (
        "R5b",
        _R5B_MOVED + " (unwrap; guard itself is R5a)",
    ),
    _POBJ + "TestReadFullTemplate::test_full_dump_covers_catalog_and_identity": (
        "R5b",
        _R5B_MOVED + " (read_full_template)",
    ),
    _POBJ + "TestReadFullTemplate::test_full_dump_skips_refused_value_on_sensitive_key": (
        "R5b",
        _R5B_MOVED + " (read_full_template)",
    ),
    _POBJ + "TestReadFullTemplate::test_full_dump_includes_vendor_attr": (
        "R5b",
        _R5B_MOVED + " (read_full_template)",
    ),
    # --- unit/pkcs11/test_objects: HMAC/verbs/edit surfaces -> R5b -------------------
    _PKOBJ + "TestGenericSecrets::test_mechanisms_fold_hmac": (
        "R5a",
        "HMAC CKM folding in mechanisms() (capability.rs, spec §4.1.1)",
    ),
    _PKOBJ + "TestGenericSecrets::test_hmac_key_types_fold_into_generic": (
        "R5b",
        _R5B_MOVED + " (read_key_template; the CKK fold on read is R5a)",
    ),
    _PKOBJ + "TestGenericSecrets::test_hmac_sign_selects_ckm_by_hash_and_truncates": (
        "R5b",
        _R5B_MOVED + " (HMAC sign/verify)",
    ),
    _PKOBJ + "TestGenericSecrets::test_hmac_requires_generic_and_cmac_requires_aes": (
        "R5b",
        _R5B_MOVED + " (HMAC/CMAC key-type rule)",
    ),
    _PKOBJ + "TestGenericSecrets::test_missing_hmac_ckm_is_an_unsupported_operation": (
        "R5b",
        _R5B_MOVED + " (HMAC sign)",
    ),
    _PKOBJ + "TestGenericSecrets::test_key_size_range_is_translated_with_a_hint": (
        "R5b",
        _R5B_MOVED + " (HMAC sign; CKR row itself is R5a)",
    ),
    _PKOBJ + "TestGenericSecrets::test_unwrap_into_generic_secret": (
        "R5b",
        _R5B_MOVED + " (unwrap + CKA_VALUE_LEN injection)",
    ),
    _PKOBJ + "TestDataObjects::test_verbs_refused": ("R5b", _R5B_MOVED + " (verb refusals)"),
    _PKOBJ + "TestDataObjects::test_edit_surfaces": (
        "R5b",
        _R5B_MOVED + " (read_key_template/read_full_template/update_key)",
    ),
    _PKOBJ + "TestOtherKeyTypes::test_listed_as_other_and_refused_elsewhere": (
        "R5b",
        _R5B_MOVED + " (verb refusals + read_full_template; listing part is R5a)",
    ),
    _PKOBJ + "test_certificate_category_round_trips_through_the_byte_path": (
        "R5b",
        _R5B_MOVED + " (read_full_template/read_key_template; import byte path is R5a)",
    ),
    # --- test_providers_cmd: tests driving the REAL wizard -> R11 ---------------------
    _PROV + "test_login_softhsm_live_wizard_skips_for_initialized_token": (
        "R11",
        "consults the REAL wizard (token_needs_init)",
    ),
    _PROV + "test_login_softhsm_live_wizard_triggers_and_decline_stops": (
        "R11",
        "drives the REAL wizard's decline path",
    ),
    # --- test_l13_hardening: owning loop of the code under test ----------------------
    _L13 + "test_encrypted_traditional_pem_paste_keeps_headers": (
        "R6",
        "decode_data (R1) + parse_key_material (R6)",
    ),
    _L13 + "test_encrypted_traditional_pem_survives_indented_paste": (
        "R6",
        "decode_data (R1) + parse_key_material (R6)",
    ),
    _L13 + "test_headerless_pem_rewrap_unchanged_by_header_support": ("R1", "codec"),
    _L13 + "test_headers_without_body_raise_codec_error": ("R1", "codec"),
    _L13 + "test_complete_paths_lists_directory": ("R7", "completer::complete_paths"),
    _L13 + "test_complete_paths_partial_and_hidden": ("R7", "completer::complete_paths"),
    _L13 + "test_complete_paths_never_raises": ("R7", "completer::complete_paths"),
    _L13 + "test_crypto_file_options_complete_paths": ("R9", "crypto command completion"),
    _L13 + "test_export_and_csr_path_positionals_complete": ("R8", "export/csr completion"),
    _L13 + "test_load_file_option_completes_paths": ("R8", "load --file completion"),
    _L13 + "test_public_half_fallback_prefers_public_then_cert": ("R9", "verify fallback"),
    _L13 + "test_public_half_fallback_honors_key_id": ("R9", "verify fallback"),
    _L13 + "test_verify_on_keypair_ref_offers_mechanisms_and_verifies": ("R9", "verify fallback"),
    _L13 + "test_prompttoolkitio_print_does_not_eat_markup_lookalikes": (
        "R7",
        "rich markup hazard: keep as a verbatim-render assertion on the r2 renderer (D1)",
    ),
    _L13 + "test_make_table_cells_render_verbatim": (
        "R1",
        "rich markup hazard: '[x]'/'[ ]' cells must render verbatim (D1)",
    ),
    _L13 + "test_hex_panel_title_renders_verbatim": (
        "R1",
        "rich markup hazard: panel title renders verbatim (D1)",
    ),
    # --- spec §4.1.1 code moves: test_render renderer cases -> R1 -------------------
    _REND + "test_error_panel_message_and_hint": ("R1", _R1_RENDER + "::error_panel"),
    _REND + "test_error_panel_without_hint": ("R1", _R1_RENDER + "::error_panel"),
    _REND + "test_caret_text_single_line": ("R1", _R1_RENDER + "::caret_text"),
    _REND + "test_caret_text_lands_on_the_right_physical_row": (
        "R1",
        _R1_RENDER + "::caret_text",
    ),
    _REND + "test_caret_text_clamps_out_of_range_pos": ("R1", _R1_RENDER + "::caret_text"),
    _REND + "test_hex_panel_groups_and_length": ("R1", _R1_RENDER + "::hex_panel"),
    _REND + "test_hex_panel_empty": ("R1", _R1_RENDER + "::hex_panel"),
    _REND + "test_make_table_cells_are_stringified": ("R1", _R1_RENDER + "::make_table"),
    # --- spec §4.1.1: app.build_operation_registry -> R3 ---------------------------
    _APP + "test_build_operation_registry_registers_builtins_and_customs": (
        "R3",
        "build_operation_registry moved to R3 (spec §4.1.1): r2_ops::registry",
    ),
    _APP + "test_custom_op_resolves_via_cli_name": (
        "R3",
        "build_operation_registry + resolve_cli moved to R3 (spec §4.1.1): r2_ops::registry",
    ),
    # --- spec §4.1.1: certops.certificate_details / ecdsa_rs_to_der -> R6 -----------
    _CERT + "test_certificate_details_rows": (
        "R6",
        "certificate_details moved to R6 (spec §4.1.1): r2_core::x509info",
    ),
    _CERT + "test_certificate_details_garbage": (
        "R6",
        "certificate_details moved to R6 (spec §4.1.1): r2_core::x509info",
    ),
    _CERT + "test_rs_to_der_round_trip": (
        "R6",
        "ecdsa_rs_to_der moved to R6 (spec §4.1.1): r2_core::der",
    ),
    _CERT + "test_rs_to_der_rejects_non_even_input": (
        "R6",
        "ecdsa_rs_to_der moved to R6 (spec §4.1.1): r2_core::der",
    ),
    # --- spec §4.1.1: keyexport's pyca serializers -> R6 ----------------------------
    _KEXP + "test_private_auto_is_pem_pkcs8": ("R6", _R6_FORMATS + " (private_key_bytes)"),
    _KEXP + "test_private_der_round_trips": ("R6", _R6_FORMATS + " (private_key_bytes)"),
    _KEXP + "test_private_password_encrypts_pkcs8": (
        "R6",
        _R6_FORMATS + " (private_key_bytes, encrypted PKCS#8)",
    ),
    _KEXP + "test_public_auto_is_pem_spki": ("R6", _R6_FORMATS + " (public_key_bytes)"),
    _KEXP + "test_certificate_pem_and_der": ("R6", _R6_FORMATS + " (certificate_bytes)"),
    # --- spec §4.1.1: CKM folding / custom merge / EdDSA probe -> R5a ---------------
    _MECH + "TestFolding::test_hash_variants_fold": ("R5a", _R5A_CAPABILITY + " (folding)"),
    _MECH + "TestFolding::test_cbc_and_cbc_pad_fold_to_one_name": (
        "R5a",
        _R5A_CAPABILITY + " (folding)",
    ),
    _MECH + "TestFolding::test_gmac_advertised_via_gcm_fallback": (
        "R5a",
        _R5A_CAPABILITY + " (folding)",
    ),
    _MECH + "TestFolding::test_wrap_and_derive_names": ("R5a", _R5A_CAPABILITY + " (folding)"),
    _MECH + "TestFolding::test_rsa_aes_key_wrap_not_advertised": (
        "R5a",
        _R5A_CAPABILITY + " (folding)",
    ),
    _MECH + "TestFolding::test_empty_codes_fold_to_nothing": (
        "R5a",
        _R5A_CAPABILITY + " (folding)",
    ),
    _MECH + "TestEddsaProbe::test_standard_ckm_wins": ("R5a", _R5A_CAPABILITY + " (EdDSA probe)"),
    _MECH + "TestEddsaProbe::test_vendor_probe_is_advisory": (
        "R5a",
        _R5A_CAPABILITY + " (EdDSA probe)",
    ),
    _MECH + "TestEddsaProbe::test_default_candidates_only_when_token_lists_them": (
        "R5a",
        _R5A_CAPABILITY + " (EdDSA probe)",
    ),
    _MECH + "TestCustomMerge::test_custom_ckm_advertised_when_token_lists_it": (
        "R5a",
        _R5A_CAPABILITY + " (custom merge)",
    ),
    _MECH + "TestCustomMerge::test_custom_and_builtin_coexist": (
        "R5a",
        _R5A_CAPABILITY + " (custom merge)",
    ),
    _MECH + "TestNormalize::test_names_and_ints_mix": (
        "R5a",
        "unfiltered mechanism-list normalization feeding the fold (R5a accept: unknown CKMs "
        "survive the unfiltered mechanism list)",
    ),
    _MECH + "TestCmacFolding::test_cmac_general_alone_is_not_advertised": (
        "R5a",
        _R5A_CAPABILITY + " (folding)",
    ),
    _MECH + "TestCmacFolding::test_cmac_advertised_with_plain_ckm": (
        "R5a",
        _R5A_CAPABILITY + " (folding)",
    ),
}

# ---------------------------------------------------------------------------
# 3. Pre-marked n/a (purely Python mechanics): python_test -> (reason slug, note)
# ---------------------------------------------------------------------------

_FROZEN = "FrozenInstanceError/AttributeError on assignment; Rust value objects are immutable behind & (no interior mutability)"  # noqa: E501
_PROTO = "mypy structural Protocol check; Rust `impl Trait for T` is compiler-checked"
_REPR = "PyKCS11 handle repr/coercion hazard; KeyInfo.handle is Option<u64> (PLAN §5)"

NA: dict[str, tuple[str, str]] = {
    "tests/unit/test_smoke.py::test_subpackage_imports": (
        "python-import-mechanics",
        "importlib of every c2 subpackage; Rust: the workspace build proves each crate exists",
    ),
    "tests/unit/core/test_io_protocols.py::test_scripted_io_passes_as_console_io_argument": (
        "protocol-conformance",
        _PROTO,
    ),
    "tests/unit/core/test_io_protocols.py::test_identity_editor_satisfies_template_editor_protocol": (  # noqa: E501
        "protocol-conformance",
        _PROTO,
    ),
    "tests/unit/core/test_scripted_io.py::test_scripted_io_satisfies_console_io_protocol": (
        "protocol-conformance",
        _PROTO,
    ),
    "tests/unit/core/test_keys.py::test_handle_int_never_calls_str_or_repr": (
        "pykcs11-repr-hazard",
        _REPR,
    ),
    "tests/unit/core/test_keys.py::test_handle_int_accepts_index_protocol": (
        "pykcs11-repr-hazard",
        _REPR + "; Python __index__ coercion",
    ),
    _POBJ + "TestKeyManagement::test_handle_value_uses_swig_accessor_never_repr": (
        "pykcs11-repr-hazard",
        _REPR + "; SWIG .value() vs __repr__ (Utimaco)",
    ),
    "tests/unit/console/test_discovery.py::test_every_module_exports_a_commands_list": (
        "pkgutil-discovery",
        "the build.rs-generated aggregator does not compile if a commands/*.rs lacks its export",
    ),
    "tests/unit/console/test_discovery.py::test_all_commands_is_cached": (
        "python-caching",
        "functools cache identity of the discovery result; the Rust aggregator is static",
    ),
    "tests/unit/console/test_io.py::test_prompt_secret_does_not_mask_later_prompts": (
        "prompt-toolkit-sticky-kwargs",
        "rpassword reads secrets outside reedline: no shared session state to leak",
    ),
    "tests/unit/console/test_io.py::test_param_completer_does_not_leak_to_later_prompts": (
        "prompt-toolkit-sticky-kwargs",
        "if TerminalIo reuses one Reedline across prompts, R7 adds a per-prompt "
        "completer-reset test",
    ),
    "tests/unit/console/test_app.py::test_template_editor_wiring_matches_l10_presence": (
        "lazy-import-wiring",
        "importlib.find_spec optional-module wiring; r2 constructs the editor directly "
        "(covered by test_template_editor.py::test_bootstrap_picks_up_the_real_editor)",
    ),
    "tests/unit/console/test_app.py::test_template_editor_uses_factory_when_module_present": (
        "lazy-import-wiring",
        "sys.modules factory injection; r2 constructs the editor directly",
    ),
    _PROV + "test_login_softhsm_without_wizard_module_falls_back": (
        "lazy-import-wiring",
        "ImportError fallback when the wizard module is absent; the wizard is always linked in r2",
    ),
    "tests/unit/console/test_repl.py::test_repl_exit_is_not_a_console_error": (
        "exception-hierarchy",
        "issubclass check; r2 exit is Flow::Exit, not an error, by type",
    ),
    "tests/unit/core/test_errors.py::test_console_error_hint_is_keyword_only": (
        "python-call-signature",
        "keyword-only TypeError; Rust constructors fix the signature at compile time",
    ),
    "tests/unit/core/test_errors.py::test_parse_error_extras_are_required_keyword_only": (
        "python-call-signature",
        "keyword-only/required TypeError; ErrorKind::Parse{line,pos} fields are required by type",
    ),
    "tests/unit/test_provider_base.py::TestDataTypes::test_value_objects_are_frozen": (
        "frozen-dataclass",
        _FROZEN,
    ),
    "tests/unit/core/test_params.py::test_param_spec_is_frozen": ("frozen-dataclass", _FROZEN),
    "tests/unit/console/test_parser.py::test_token_dataclass_is_frozen": (
        "frozen-dataclass",
        _FROZEN,
    ),
    "tests/unit/pkcs11/test_attributes.py::TestCatalog::test_read_only": (
        "python-readonly-mapping",
        "MappingProxyType assignment TypeError; the Rust CKA_CATALOG is an immutable static",
    ),
    "tests/unit/pkcs11/test_attributes.py::TestConversion::test_bytearray_normalized_to_bytes": (
        "python-bytearray",
        "bytes vs bytearray normalization; Rust has one byte type (Vec<u8>)",
    ),
    "tests/unit/pkcs11/test_attributes.py::TestTemplateIdentity::test_bytearray_id_normalized": (
        "python-bytearray",
        "bytes vs bytearray normalization; Rust has one byte type (Vec<u8>)",
    ),
}

# ---------------------------------------------------------------------------
# 4. Porting notes on rows that stay `todo`: python_test -> note
# ---------------------------------------------------------------------------

_WIZ_STUB = (
    "Python stubs c2.console.wizard via sys.modules: r2 needs an injectable wizard "
    "seam (skeleton hook) so R8 can test before R11 merges"
)
_STUB_PROVIDERS = (
    "Python stubs the provider modules via sys.modules: inject provider "
    "constructors / a fake library path in Rust"
)
_FROZEN_PART = "port the default-value asserts; the frozen-assignment part is Python-only"
_TYPEERR_PART = "port the positive asserts; the missing-kwarg TypeError part is Python-only"

NOTES: dict[str, str] = {
    "tests/unit/core/test_io_protocols.py::test_core_stays_console_free": (
        "layering is enforced by the crate graph; port as a cargo-metadata check that "
        "r2-core has no reedline/comfy-table/anstream/r2-console dependency, or n/a if "
        "R0's deny.toml bans cover it"
    ),
    "tests/unit/core/test_keys.py::test_key_info_is_frozen_with_defaults": _FROZEN_PART,
    "tests/unit/core/test_keys.py::test_key_material_defaults": _FROZEN_PART,
    "tests/unit/test_provider_base.py::TestDataTypes::test_key_edit_result_objects_are_frozen": (
        _FROZEN_PART
    ),
    "tests/unit/core/test_errors.py::test_hierarchy": (
        "isinstance hierarchy -> ErrorKind family predicates "
        "(is_provider/is_key_lookup/is_operation)"
    ),
    "tests/unit/core/test_errors.py::test_everything_catchable_as_console_error": (
        "every error is a ConsoleError by type in Rust; port as kind/predicate checks"
    ),
    "tests/unit/core/test_errors.py::test_pkcs11_error_extras": _TYPEERR_PART,
    "tests/unit/core/test_errors.py::test_ambiguous_key_error_extras": _TYPEERR_PART,
    "tests/unit/core/test_errors.py::test_param_error_extras": _TYPEERR_PART,
    _POBJ + "TestKeyManagement::test_key_info_handle_is_a_plain_int": (
        "Option<u64> by type; port as 'every KeyInfo from import/list_keys carries Some(handle)'"
    ),
    "tests/unit/console/test_discovery.py::test_there_is_no_central_registration_table": (
        "port as a check that commands/mod.rs include!s the build.rs-generated aggregator "
        "(no hand-maintained list)"
    ),
    "tests/unit/console/test_discovery.py::test_command_metadata_is_complete": (
        "the frozenset type check on flags is Python-only"
    ),
    "tests/unit/console/test_io.py::test_completer_for_enum_offers_choices": (
        "WordCompleter is prompt_toolkit: port as the per-ParamSpec completion word list"
    ),
    "tests/unit/console/test_io.py::test_completer_for_bool_and_plain_kinds": (
        "WordCompleter is prompt_toolkit: port as the per-ParamSpec completion word list"
    ),
    "tests/unit/console/test_io.py::test_history_filters_pin_and_password_lines": (
        "reedline History wrapper dropping --pin/--password lines (PLAN §6)"
    ),
    "tests/unit/console/test_repl.py::test_unexpected_error_with_debug_prints_traceback": (
        "D4: Rust backtrace instead of a Python traceback"
    ),
    "tests/unit/console/test_repl.py::test_exit_command_raises_repl_exit_directly": (
        "Rust: exit returns Ok(Flow::Exit)"
    ),
    "tests/unit/console/test_commands.py::test_exit_and_quit_raise_repl_exit": (
        "Rust: exit/quit return Ok(Flow::Exit)"
    ),
    "tests/unit/console/test_app.py::test_bootstrap_registers_memory_and_pkcs11_with_ckm_map": (
        _STUB_PROVIDERS
    ),
    "tests/unit/console/test_app.py::test_bootstrap_memory_disabled": _STUB_PROVIDERS,
    "tests/unit/console/test_app.py::test_bootstrap_softhsm_autodetect_registers_provider": (
        _STUB_PROVIDERS
    ),
    "tests/unit/console/test_app.py::test_bootstrap_softhsm_not_found": _STUB_PROVIDERS,
    "tests/unit/console/test_app.py::test_bootstrap_softhsm_name_collision_skips_autodetect": (
        _STUB_PROVIDERS
    ),
    "tests/unit/console/test_app.py::test_main_runs_a_scripted_session_with_stub_providers": (
        _STUB_PROVIDERS
    ),
    "tests/unit/console/test_app.py::test_main_debug_flag_forces_debug_and_stderr_mirror": (
        _STUB_PROVIDERS
    ),
    "tests/unit/console/test_app.py::test_main_shuts_providers_down_in_the_finally": (
        _STUB_PROVIDERS + "; Drop guard replaces the finally (PLAN §6)"
    ),
    "tests/unit/console/test_app.py::test_main_end_to_end_with_real_providers": (
        "skipped in c2 until L4/L5 merged; in r2 it always runs (R7 merges after R4/R5a)"
    ),
    "tests/unit/test_smoke.py::test_main_help_flag_lists_cli_options": (
        "clap --help lists --version/--config/--debug"
    ),
    _PROV + "test_login_softhsm_triggers_wizard_and_uses_its_token": _WIZ_STUB,
    _PROV + "test_login_softhsm_wizard_declined_stops_cleanly": _WIZ_STUB,
    _PROV + "test_login_softhsm_initialized_token_skips_wizard": _WIZ_STUB,
    _PROV + "test_login_other_provider_never_consults_wizard": _WIZ_STUB,
    _KEYS + "test_key_edit_completion": (
        "asserts `key` subcommands {info, edit, template}: `template` is R14's subcommand"
    ),
    _COPY + "test_complete_offers_refs_providers_and_options": (
        "asserts the --template option (R14 feature) in copy's completion"
    ),
    _COPY + "test_copy_is_auto_discovered": "Rust: the build.rs aggregator registers `copy`",
    "tests/unit/console/test_template_editor.py::test_create_template_editor_factory": (
        "r2 constructs the editor directly (no lazy import)"
    ),
    "tests/unit/console/test_template_editor.py::test_bootstrap_picks_up_the_real_editor": (
        "r2 constructs the editor directly: assert AppContext wires the checklist editor"
    ),
}

# Contract-suite instantiations: subclass node -> (loop, short name, description)
CONTRACT_INSTANCES: dict[str, tuple[str, str, str]] = {
    "tests/contract/test_fake_provider.py::TestFakeProviderContract": (
        "R3",
        "FakeProvider",
        "FakeProvider('fake'), memory presentation",
    ),
    "tests/contract/test_fake_provider.py::TestFakeProviderAsPkcs11Contract": (
        "R3",
        "FakeProvider-as-pkcs11",
        "FakeProvider('fakehsm', type_name='pkcs11') presentation",
    ),
    "tests/unit/test_memory_provider.py::TestMemoryProviderContract": (
        "R4",
        "MemoryProvider",
        "MemoryProvider('mem')",
    ),
    "tests/integration/test_pkcs11_provider.py::TestPkcs11ProviderContract": (
        "R5b",
        "Pkcs11Provider@SoftHSM",
        "Pkcs11Provider on SoftHSM (logged in, per-test shutdown)",
    ),
}


# ---------------------------------------------------------------------------
# machinery
# ---------------------------------------------------------------------------


@dataclass
class Row:
    python_test: str
    params: int = 0
    r_loop: str = ""
    status: str = "todo"
    rust_test: str = ""
    note: str = ""
    node_ids: list[str] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)
    instances: list[str] = field(default_factory=list)  # contract rows only


def collect(c2_dir: Path, mark: str | None = None) -> list[str]:
    cmd = ["uv", "run", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"]
    if mark:
        cmd += ["-m", mark]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}  # leave the frozen c2 tree untouched
    proc = subprocess.run(cmd, cwd=c2_dir, env=env, capture_output=True, text=True, check=False)
    if proc.returncode not in (0, 5):  # 5 = nothing collected (empty mark)
        sys.exit(f"collection failed ({' '.join(cmd)}):\n{proc.stdout}\n{proc.stderr}")
    return [line.strip() for line in proc.stdout.splitlines() if "::" in line]


def function_id(node_id: str) -> str:
    """'path::[Class::]func[params]' -> 'path::[Class::]func'."""
    base = node_id.split("[", 1)[0]
    if not re.fullmatch(r"[\w/.\-]+\.py(::\w+)+", base):
        sys.exit(f"unexpected node id shape: {node_id}")
    return base


class ContractIndex:
    """Finds collected tests that are inherited ProviderContractTests methods."""

    def __init__(self, c2_dir: Path) -> None:
        self.c2_dir = c2_dir
        self._modules: dict[str, ast.Module] = {}
        base = self._module(CONTRACT_BASE_FILE)
        cls = self._class(base, CONTRACT_BASE_CLASS)
        if cls is None:
            sys.exit(f"{CONTRACT_BASE_CLASS} not found in {CONTRACT_BASE_FILE}")
        self.base_tests = {
            n.name
            for n in cls.body
            if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")
        }

    def _module(self, path: str) -> ast.Module:
        if path not in self._modules:
            source = (self.c2_dir / path).read_text(encoding="utf-8")
            self._modules[path] = ast.parse(source)
        return self._modules[path]

    @staticmethod
    def _class(module: ast.Module, name: str) -> ast.ClassDef | None:
        for node in module.body:
            if isinstance(node, ast.ClassDef) and node.name == name:
                return node
        return None

    def base_row_for(self, func_id: str) -> tuple[str, str] | None:
        """(base.py row id, subclass node) if func_id is an inherited contract test."""
        parts = func_id.split("::")
        if len(parts) != 3:
            return None
        path, cls_name, func = parts
        if func not in self.base_tests:
            return None
        cls = self._class(self._module(path), cls_name)
        if cls is None:
            return None
        bases = {ast.unparse(b).split(".")[-1] for b in cls.bases}
        if CONTRACT_BASE_CLASS not in bases:
            return None
        overridden = any(isinstance(n, ast.FunctionDef) and n.name == func for n in cls.body)
        if overridden:
            return None
        return f"{CONTRACT_BASE_FILE}::{CONTRACT_BASE_CLASS}::{func}", f"{path}::{cls_name}"


def build_rows(c2_dir: Path, node_ids: list[str], tagged: dict[str, set[str]]) -> list[Row]:
    contracts = ContractIndex(c2_dir)
    rows: dict[str, Row] = {}

    for node in node_ids:
        func = function_id(node)
        hit = contracts.base_row_for(func)
        if hit is not None:
            base_id, instance = hit
            if instance not in rows:  # instantiation row at the subclass's first test
                rows[instance] = Row(python_test=instance)
            rows[instance].tags |= {t for t in TAG_MARKS if node in tagged[t]}
            func = base_id
        row = rows.setdefault(func, Row(python_test=func))
        row.node_ids.append(node)
        row.params += 1
        if hit is not None:
            if hit[1] not in row.instances:
                row.instances.append(hit[1])
        else:
            row.tags |= {t for t in TAG_MARKS if node in tagged[t]}

    for row in rows.values():
        path = row.python_test.split("::", 1)[0]
        notes: list[str] = []
        override_note = ""
        if row.python_test in CONTRACT_INSTANCES:
            loop, _short, desc = CONTRACT_INSTANCES[row.python_test]
            row.r_loop = loop
            notes.append(
                f"contract instantiation: provider_contract_tests! for {desc}; its "
                f"{len(contracts.base_tests)} tests are the {CONTRACT_BASE_FILE} rows "
                "(params=0: node IDs counted there)"
            )
        elif row.instances:
            row.r_loop = FILE_LOOP[CONTRACT_BASE_FILE]
            unknown = sorted(set(row.instances) - set(CONTRACT_INSTANCES))
            if unknown:
                sys.exit(f"contract subclasses missing from CONTRACT_INSTANCES: {unknown}")
            ordered = sorted(row.instances, key=lambda i: LOOPS.index(CONTRACT_INSTANCES[i][0]))
            who = ", ".join(
                f"{CONTRACT_INSTANCES[i][1]} ({CONTRACT_INSTANCES[i][0]})" for i in ordered
            )
            notes.append(f"contract suite (provider_contract_tests!); instantiated by {who}")
        elif row.python_test in OVERRIDES:
            row.r_loop, override_note = OVERRIDES[row.python_test]
        elif path in FILE_LOOP:
            row.r_loop = FILE_LOOP[path]
        else:
            sys.exit(f"no loop assignment for {row.python_test} (add {path} to FILE_LOOP)")

        if row.python_test in NA:
            slug, na_note = NA[row.python_test]
            row.status = f"n/a:{slug}"
            notes.append(na_note)  # the reason only: file-level porting notes don't apply
        elif not row.instances and row.python_test not in CONTRACT_INSTANCES:
            if path in FILE_NOTE:
                notes.append(FILE_NOTE[path])
            if override_note:
                notes.append(override_note)
        if row.python_test in NOTES:
            notes.append(NOTES[row.python_test])

        tags = []
        if "softhsm" in row.tags:
            tags.append("softhsm")
        if "xfail" in row.tags:
            tags.append("xfail(strict=False) in c2")
        if "skipif" in row.tags:
            tags.append("skipif in c2")
        row.note = "; ".join(tags + notes)

        if row.r_loop not in LOOPS:
            sys.exit(f"bad loop {row.r_loop!r} for {row.python_test}")
    return list(rows.values())


def validate(rows: list[Row], node_ids: list[str]) -> None:
    ids = {r.python_test for r in rows}
    for table_name, table in (("OVERRIDES", OVERRIDES), ("NA", NA), ("NOTES", NOTES)):
        stale = sorted(set(table) - ids)
        if stale:
            sys.exit(f"{table_name} entries match no collected test: {stale}")
    stale_instances = sorted(set(CONTRACT_INSTANCES) - ids)
    if stale_instances:
        sys.exit(f"CONTRACT_INSTANCES match no collected subclass: {stale_instances}")
    covered = [n for r in rows for n in r.node_ids]
    if sorted(covered) != sorted(node_ids) or sum(r.params for r in rows) != len(node_ids):
        sys.exit("row/node-id accounting mismatch")
    if len(ids) != len(rows):
        sys.exit("duplicate python_test rows")


def merge_existing(rows: list[Row], existing: dict[str, dict[str, str]]) -> list[str]:
    """Keep loop-maintained fields; return python_test IDs that disappeared from c2."""
    for row in rows:
        old = existing.get(row.python_test)
        if old is None:
            continue
        if old["status"] != "todo":
            row.status = old["status"]
        row.rust_test = old["rust_test"]
        if old["note"].startswith(row.note) and old["note"] != row.note:
            row.note = old["note"]  # a loop appended to the generated note
    return sorted(set(existing) - {r.python_test for r in rows})


def read_ledger(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != COLUMNS:
            sys.exit(f"{path}: header must be exactly {','.join(COLUMNS)}")
        out: dict[str, dict[str, str]] = {}
        for rec in reader:
            if not STATUS_RE.match(rec["status"]):
                sys.exit(f"{path}: bad status {rec['status']!r} for {rec['python_test']}")
            out[rec["python_test"]] = rec
        return out


def render(rows: list[Row]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(COLUMNS)
    for r in rows:
        writer.writerow([r.python_test, r.params, r.r_loop, r.status, r.rust_test, r.note])
    return buf.getvalue()


def summary(rows: list[Row]) -> str:
    lines = ["rows per loop: total (todo / ported / n/a)"]
    for loop in LOOPS:
        st = Counter(
            "n/a" if r.status.startswith("n/a") else r.status for r in rows if r.r_loop == loop
        )
        total = sum(st.values())
        lines.append(f"  {loop:<4} {total:>4}   ({st['todo']} / {st['ported']} / {st['n/a']})")
    lines.append(f"  total {len(rows)} rows, {sum(r.params for r in rows)} collected node IDs")
    return "\n".join(lines)


def rows_from_ledger(path: Path) -> list[Row]:
    """Load and lint the committed ledger (no c2 checkout needed)."""
    rows: list[Row] = []
    problems: list[str] = []
    for rec in read_ledger(path).values():
        row = Row(
            python_test=rec["python_test"],
            params=int(rec["params"]),
            r_loop=rec["r_loop"],
            status=rec["status"],
            rust_test=rec["rust_test"],
            note=rec["note"],
        )
        if row.r_loop not in LOOPS:
            problems.append(f"bad r_loop {row.r_loop!r}: {row.python_test}")
        if row.status == "ported" and not row.rust_test.strip():
            problems.append(f"ported without rust_test: {row.python_test}")
        rows.append(row)
    if problems:
        sys.exit("ledger lint failed:\n  " + "\n  ".join(problems))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--check", action="store_true", help="regenerate in memory; exit 1 on drift"
    )
    parser.add_argument(
        "--stats", action="store_true", help="lint + per-loop counts of the ledger only (no c2)"
    )
    parser.add_argument(
        "--gate",
        metavar="LOOP",
        help="with --stats: exit 1 while LOOP (or 'all', the R13 gate) has todo rows",
    )
    parser.add_argument("--out", type=Path, default=LEDGER, help="ledger path")
    args = parser.parse_args()

    if args.stats:
        rows = rows_from_ledger(args.out)
        print(summary(rows))
        if args.gate:
            if args.gate != "all" and args.gate not in LOOPS:
                sys.exit(f"--gate takes one of {', '.join(LOOPS)} or 'all'")
            todo = [
                r.python_test for r in rows if r.status == "todo" and args.gate in ("all", r.r_loop)
            ]
            if todo:
                print(f"gate {args.gate}: {len(todo)} todo rows, e.g. {todo[:5]}")
                return 1
            print(f"gate {args.gate}: no todo rows")
        return 0

    c2_dir = Path(os.environ.get("C2_DIR", DEFAULT_C2)).expanduser().resolve()
    if not (c2_dir / CONTRACT_BASE_FILE).exists():
        sys.exit(f"C2_DIR={c2_dir} does not look like a c2 checkout")

    node_ids = collect(c2_dir)
    tagged = {mark: set(collect(c2_dir, mark)) for mark in TAG_MARKS}
    rows = build_rows(c2_dir, node_ids, tagged)
    validate(rows, node_ids)
    existing = read_ledger(args.out)
    gone = merge_existing(rows, existing)
    text = render(rows)

    print(summary(rows))
    if gone:
        print(f"warning: {len(gone)} ledger rows no longer collected in c2: {gone}")
    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if current != text:
            print(f"{args.out} is out of date (re-run without --check)")
            return 1
        print(f"{args.out} is up to date")
        return 0
    args.out.write_text(text, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
