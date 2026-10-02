# loops.md — implementation decomposition for multi-agent work

This file splits the implementation of `r2` (see `spec.md`), the Rust rewrite of c2, into
**loops**: units of work sized for one agent in one context. Agents run in *separate,
independent contexts*. Each one sees only `spec.md`, `CLAUDE.md`, this file,
`parity/ledger.csv`, the repo at its current state, and the frozen Python reference
(c2@408d6f2, `../c2`, at `/home/user/c2` in this environment). Everything loops need from
each other is frozen in **spec §4**, and R0 turns all of §4 into a compiling skeleton, so
every loop builds against the real signatures from day one. Merge-order edges gate
*merging*, not development.

Loop IDs: `S0` (docs), `R0`–`R15`, with the PKCS#11 provider split into `R5a`/`R5b`.
Numbering follows c2's `L<n>` where a loop has a direct counterpart. There is no L16
counterpart: generic secrets/HMAC, data objects, `other`, template files and `--kek` are
part of the spec from the start and land in the loops that own the code. Sizes S/M/L =
one agent context of increasing load.

## STATUS

One row per loop. **Rows are single lines** so parallel PRs merge without conflict. A
loop's own PR (or its last `R<n>:` commit) flips its row to `done`. There is no
`in-progress` state on the integration branch; assignment and dispatch happen outside
this file. "Deviations / notes" records every §4.11 change, sanctioned foreign-file edit,
interpretation, and anything a later loop must know.

| ID | State | Commit/PR | Date | Deviations / notes |
|----|-------|-----------|------|--------------------|
| S0 | done | `S0:` commits | 2026-10-01 | spec.md, loops.md, CLAUDE.md, parity ledger; spikes recorded in spec |
| R0 | done | `R0:` commits | 2026-10-01 | §4.11 change (fix round 1; no merged loop affected): §4.1.1 map gains `.gitignore`/`.gitattributes` (R0); §4.1.1 mandated bodies gain `ConsoleError::{new, with_hint, with_hint_opt, generic, crypto, not_implemented}` (stubs return Err, not panic, before R1); §4.10.5 states softhsm-init.sh refuses a non-empty DIR/tokens. Skeleton = S0 generator re-run on the final spec §4 (identical to the seed modulo provenance comments; 640 §4 items checked present) + mandated bodies of §4.1.1; additions: `.gitignore` (/target), `.gitattributes` (LF everywhere incl. Windows CI; binary fixtures), workspace version 0.2.0 (= c2 0.2.0, so `r2 --version` matches c2's number), `license = "GPL-3.0-only"` in [workspace.package] (c2 LICENSE is the plain GPLv3 text), header comments in manifests/configs. SoftHSM fixture: `UniqueLabel { label, token }`; `unique_label()` requires the fixture; the fixture and its self-test take no `global_state_lock()` (env read-only, nextest-only; the lock is still R1's stub). softhsm-init.sh reads the probe list from defaults.yaml; it and build-softhsm.sh (opendnssec/SoftHSMv2 tag, cached prefix ~/.local/softhsm-<v>) verified locally on SoftHSM 2.6.1 and 2.7.0. deny: `der` deny-multiple-versions, other duplicates warn, GPL-compatible forward-looking license allow-list (`unused-allowed-license = "allow"`). r2-services `softhsm = ["r2-testkit/softhsm"]` (R10's in-process SoftHSM transfer suites). build.rs discovery skips stems that are not Rust identifiers (editor lock files `.#x.rs` etc., with a cargo warning). `random_bytes` returns the Crypto error for len > i32::MAX (openssl asserts). nextest: softhsm group = `test(/softhsm/) | binary(/softhsm/)`, max-threads 1. CI (not runnable here; actionlint + shellcheck clean): Windows OpenSSL via vcpkg x64-windows-static-md, msrv = pinned toolchain `--all-features`. Extra tests: `r2-core::r0_mandated` (mandated r2-core bodies; ownership of its cases passes to R1 (ConsoleError), R6 (crypto/der) and R5a (catalog), who may edit, move or delete them), build_discovery stem-filter test, softhsm.rs in-file env-parsing tests, teardown-deletion test. |
| R1 | done | `R1:` commits | 2026-10-01 | §4.11 change (no merged loop affected; R0 calls none of these): §4.2 `py_int` doc now states CPython `int()` whitespace = `py_strip`'s set minus U+001C..=U+001F (verified with CPython 3.12; "py_strip first" was not Python-exact); §11 D12 gains (e): non-ASCII inside a pasted PEM block — in the body → Codec "malformed PEM: body of the {label} block is not valid base64", in an RFC 1421 header line kept and returned as UTF-8 (c2 crashed with ValueError/UnicodeEncodeError). Interpretations: ScriptedIo `select([])` → Generic "nothing to select for: {title}" (ConsoleIo contract; title recorded, no answer consumed; c2 asserted); ScriptedIo select index via `py_int` (c2 `int()`), confirm via `py_strip`+`to_lowercase`; `error_panel`/`print_error` treat an empty hint as none (c2 `if err.hint:`); panels are a port of rich 15 Panel/Text layout (measure, greedy wrap with fold, rstrip_end, truncate, tab expansion, title/subtitle crop+fill), an empty `PanelData.body` renders one blank line (rich's empty Text) unless the content width is 0 (then no line, as rich); tables: comfy style = header_separator fill+junction `─` (junction ⇒ blank vertical line ⇒ rich's 3-space column gap), bold header cells, trailing blanks trimmed in the plain domain (`trim_fmt` cannot see padding inside a styled cell), title italic, wrapped (fold) at the table width and centered (floor), no columns and no rows → ""; Tone SGR via anstyle (Bold 1, Dim 2, Italic 3, Error 1+31, Danger 31); caret position inside a multi-byte char snaps back to its start; codec base64 = port of CPython 3.12 `a2b_base64(strict_mode=True)` (so a PEM body "AAAA=" is valid, as in c2), `_PEM_BLOCK_RE` emulated by hand (no regex dep), Python `splitlines` boundaries; `DataInput::file` origin = `path.display()`; `close_matches` = own port of CPython difflib incl. autojunk (difflib crate removed, see fix round 1). Added r2-core dev-dependency `tempfile` (§4.1.4 dev, permitted) + Cargo.lock. Tests: 13 r2-core integration files (errors, text, keys, keys_objects, codec, datainput, params, template, scripted_io, io, render, runtime, testkit_env) + in-file codec/text unit tests; vectors generated in c2's venv by `crates/r2-core/tests/support/gen_{rich_panels,text_vectors,codec_vectors}.py` (rich 15 panels, CPython repr/int/fromhex/PurePosixPath/difflib, 62 c2 `decode_data` differential cases). `r0_mandated.rs` left unchanged (its ConsoleError cases pass). Ledger: 98 rows ported, 8 n/a (pre-marked). **Fix round 1** (review R1-GATE-M1/M2, R1-SPEC-1/2, R1-PAR-1..7, R1-BUG-1..5), §4.11 change (no merged loop affected: R0's stubs and tests use none of these; only R1 files and R0's manifests are touched): §4.9.2 — Text and Styled are no longer verbatim but laid out by the rich Text model like every c2 `console.print` (BEL/BS/VT/FF/CR stripped, tabs to 8, `Text.wrap` fold at `cfg.width`; a 0 width leaves lines unwrapped); the same model (control-code stripping, rich 15 cell widths = rich's own Unicode 17.0.0 `CELL_WIDTHS` + `narrow_to_wide` tables generated into render.rs by `tests/support/gen_cell_widths.py`, ZWJ/VS16 graphemes ported from `rich.cells` incl. `split_graphemes`/`_split_text`/`chop_cells`) applies to panel bodies, titles, subtitles, table cells/headers/title and the caret; an empty (or all-control) panel title/subtitle or table title is none; a table with no columns and no rows renders "" title included; `caret` docs: column = width of the tab-expanded, control-stripped prefix; `Renderable::Text`/`Styled`/`table` docs; §4.4.2 `DataInput` loses `Debug` from its derive and gets a hand-written one (`token: Some("<N chars>")`); §4.1.2/§4.1.4 drop `difflib` (unused, `close_matches` is an own port) and r2-core's `unicode-width` (the renderer uses rich's table; r2-console keeps it), root `[workspace.dependencies]` + r2-core manifest + Cargo.lock follow (difflib stays in the lock only as assert_cmd→predicates' transitive dev dependency); §4.3 docs of `KeyMaterial`/`parse_ref` backticked (rustdoc `-D warnings` clean for r2-core); §11 D1 rewritten (rich-identical text/caret/panels at widths ≥ 2; residuals: rich's `UNICODE_VERSION` override not honoured, comfy-table cell widths; styling: plain-text `ReprHighlighter` colouring not reproduced), D14 reworded (caret differs from c2's char index for wide, zero-width/combining/control chars and TAB), new D23 (emoji shortcodes in printed text not replaced — c2 printed `generated mem❌ok:y`). Zeroization: `remove_whitespace` → pre-sized `Zeroizing<String>`, hex via `decode_to_slice` into a zeroizing buffer, PEM re-wrap intermediates (header-split body, blocks, output) zeroizing and allocated once, `DataInput::resolve` forced text built in place, `DataOutput::write` hex/b64 encoded straight into one zeroizing buffer (`encode_to_slice`/`encode_slice`). Vectors: `gen_rich_panels.py` now also emits generic panels (widths 2..80), plain text (`console.print(str, markup=False)`, asserted emoji- and highlight-independent), caret layouts and 1904 `cell_len` cases (every `CELL_WIDTHS` boundary, `narrow_to_wide`+VS16, ZWJ/flag/skin-tone/Indic sequences); 576 layout vectors in all, plus ~30k scratch differential fuzz cases (error/hex/generic panels, text, caret; widths 2..120; control, combining, ZWJ/VS16, CJK, Indic) with 0 mismatches against rich with its highlighter off (with it on: ~0.2% of exotic text cases, all ZWJ/combining marks at highlight-segment boundaries — D1). Ledger: `test_io_protocols` `test_scripted_io_passes_as_console_io_argument` / `test_identity_editor_satisfies_template_editor_protocol` → ported (new same-named `r2-core::io` tests through `&dyn` traits + the existing ScriptedIo tests); R1 now 100 ported, 6 n/a. **Fix round 3** (R1-PAR3-1, R1-BUG3-1), §4.11 change (no merged loop affected: R0 calls none of these; R7's Sink is not yet implemented): styling is chosen by the renderer, never by stripping rendered text — §4.9.2 `render_plain` = the same layout with no SGR (was `strip_str(render(..))`, which deleted content ESC/NUL/DEL bytes, swallowed text after an unterminated OSC and misaligned borders), new `render_no_color` (colour-free SGR, rich `no_color`) for the NoColor sink; §4.9.7 Sink writes the per-style rendering unchanged (Full/NoColor via AutoStream `ColorChoice::Always`, Plain straight to stdout; no SGR-parameter filtering, no `ColorChoice::Never`); §4.1.2/§4.1.4 r2-core drops `anstream` (r2-console keeps it); §4.9.2 rule text and §11 D1 "verified by" name the content-byte vectors. Tables lay out and measure on the unstyled comfy-table rendering; only header lines take the bold rendering, so row data that looks like SGR is never trimmed as styling. `gen_rich_panels.py` gains ESC/OSC/NUL/DEL error panels, generic panels and texts (rich keeps them verbatim); ScriptedIo now records `clear`'s default `\x1b[2J\x1b[H` verbatim (c2 `test_clear_falls_back_to_ansi_for_plain_io` parity). |
| R2 | done | `R2:` commits | 2026-10-01 | §4.11 change (spec text only, no signature change; no merged loop affected — R0/R1 call none of these): §4.8.1 loader messages gain the non-UTF-8 read error ("cannot read config file {path}: {CPython UnicodeDecodeError text}"), Python universal newlines, and `config_from_yaml`'s "config text" wording ("invalid YAML in config text: …", "config text must contain a top-level mapping", "config text: top-level keys must be strings, got …"); §4.8.3 table gains "must be at most {max}" for integers above the field's Rust type (app.log.backups > u32, ui.hex_group/hex_width > usize, INT/ENUM params[].default > i64); §11 D12 gains (f) (non-UTF-8 config file and ValueError-raising YAML constructions such as `2001-02-30` or a malformed explicit `!!int` — c2 crashed at startup; r2 Config errors with Python's texts), D17 gains (d) `!!set`/`!!omap`/`!!pairs` rejected and (e) aliases expanded into copies (recursive alias = error, duplicate anchor rebinds, nesting limit 400 — PyYAML hits CPython's recursion limit between 400 and 500 —, 1,000,000-value budget against "billion laughs", so `dump` never writes PyYAML's `&id001` anchors — visible only in the wizard's structural rewrite of a config aliasing a collection), D18 gains the "must be at most" guards. Interpretations: own composer over yaml-rust2 `Parser::next_token` events (not `Parser::load`, which asserts) building a node graph, then PyYAML SafeConstructor semantics (implicit resolvers in PyYAML order on plain scalars and on any scalar with the non-specific `!` tag, a leading BOM skipped, flatten_mapping merge order, Python dict-key equality so `1`/`1.0`/`true` collide, first position/last value); `!!timestamp`/`!!binary` are `Value::Tagged` over the source text, validated with Python's date/time range checks resp. lenient `base64.decodebytes`, dumped as isoformat / `encodebytes` literal block; explicit-tag construction failures use Python's ValueError texts; yaml-rust2 syntax-error texts as is (D17 a); emitter = a port of PyYAML 6.0.3 Representer/Serializer/Emitter (analyze_scalar, choose_scalar_style, write_plain/single/double/literal/folded, check_simple_key incl. the tag-length quirk, open-ended `...` after a root plain scalar); `{key!r}` and Python type names via crate-private `yaml::py_value_repr` (Python repr incl. float repr, date/datetime/timezone, bytes). Decoder keeps c2's check order (custom_mechanisms decoded before app; ParamSpecConfig prompt/required after choices; mechanism label after params) and c2's `data.get(k, default)` semantics (explicit `required: null`/`param_struct: null` are type errors, absent → default). `config_from_yaml` applies the external-file top-level rules. `dirs`: Linux $XDG_CONFIG_HOME (blank → ~/.config) + /r2, macOS ~/Library/Application Support/r2, Windows %LOCALAPPDATA%\r2\r2, all through `py_path`; `expand_user` expands only `~`/`~/…` (home joined like `Path(home) / tail`). `defaults.yaml` unchanged from R0 (already the §7 transform; a test diffs it against a verbatim copy of c2's file, tests/support/c2_defaults.yaml). Added r2-config dev-dependency `tempfile` (§4.1.4, permitted) + its Cargo.lock line. Tests: crates/r2-config/tests/config.rs (89: every c2 test of test_config.py/test_config_objects.py by name in class-named modules, plus discovery edge cases, D12/D18 guards, YAML 1.1 fixture config, `config show` dumps) + 8 in-file yaml tests; isolation = chdir to a tempdir + XDG_CONFIG_HOME/HOME/LOCALAPPDATA under it, all under `global_state_lock()`; warnings captured with an in-test `tracing::Subscriber` (no tracing-subscriber dependency). Vectors generated in the c2 venv by tests/support/gen_yaml_vectors.py (PyYAML 6.0.3): ~60 load cases (Python repr compared) + 5 r2-only errors, 399 seeded number-like plain scalars, 141 byte-compared dumps (wizard snippet, template-file dump, the whole defaults tree, 120 seeded random strings at several nesting levels for quoting/folding), 70 c2 decoder message+hint vectors, 3 `config show` outputs (raw mirrors `CKA_ID: 0x0A 0B`, `default: hex:0A0B`/`AQID`/`128`). Ledger: 56 ported, 0 n/a. Fix round 1 (§4.11 text-only again, no signature change): §4.8.1 `dirs` docs (`~` = `$HOME` as is when set, even empty, else getpwuid; `~name` from /etc/passwd; `$XDG_CONFIG_HOME` read as OsString; non-UTF-8 `--config`/`$R2_CONFIG` expanded byte for byte via crate-private `expand_user_path`); §4.8.4 anchor bullet now "resolved by copying" (+ NEL = line break, LS/PS = error); §11 D12 gains (g) (`~name` via /etc/passwd, unresolvable stays literal — c2 RuntimeError crash; NSS-only/macOS DS users and Windows `~name` unresolved), D17 (e) gains "merge lists count against the budget", D17 gains (f) (literal U+2028/U+2029 rejected, U+0085 normalized to `\n` = PyYAML), D18's params-default bullet states that mistyped defaults are rejected even where c2 never read them (required params) and lists the keyref/codec texts, D18's ASCII-digit bullet covers explicit `!!int`/`!!float`. Code: CPython's byte-range UnicodeDecodeError text for multi-byte sequences; explicit `!!int` follows Python `int()` (whitespace, inner sign, base prefix); `!!value` keys become their own text; `!`-tagged and explicit `!!merge` keys merge; Python dict key equality through a hashed index (O(1), exact int/float compare, one NaN); timestamp offset checked before the date; flattened merge pairs charged against the 1,000,000 budget. Fix round 2 (§4.11 text-only, no signature change): §4.8.4 gains PyYAML's `Reader.check_printable` (non-printable characters → PyYAML's "unacceptable character #x…" text; a NUL no longer truncates the text) and block scalars at the end of the text loading to PyYAML's value (no trailing break that was not read; empty-content `|`/`|+` = ""/its empty lines), validated by a 110,000-case PyYAML differential (0 value mismatches); §11 D17 (b) gains the rejected unindented top-level block-scalar content, (e) gains the 64 MiB budget on scalar text copied by alias expansion. Fix round 3 (§4.11 text-only, no signature change, no merged loop affected): §4.8.1 step 4 follows platformdirs 4.10.1 `XDGMixin` — `$XDG_CONFIG_HOME` is used STRIPPED of Python whitespace (bytes trimmed as surrogateescape `str.strip()`), and macOS honors it too before ~/Library/Application Support/r2. |
| R3 | done | `R3:` commits | 2026-10-01 | §4.11 change (fix round 1): spec §4.10.2 FakeHooks doc amended — `unwrap_key` stores through the fake's internal store path (c2 `_store_key`; duplicate guard runs, no `import_key` call made or recorded, an `import_key` hook is not consulted), and capability checks incl. `supports` (also via `next.supports`) use the hooked `mechanisms()`; affected merged loops: none (only R3 consumes FakeHooks so far). No foreign file touched, no new dependency (Cargo.lock unchanged). Implemented r2-provider (types, ProviderRegistry with a RefCell<Vec<Rc<dyn Provider>>> never borrowed across provider calls, lookup::{matches_selector, select_match, duplicate_identity} = the one find/twin implementation, rsa_raw_modexp, mechanism names), r2-ops (OperationSpec::{invocation, param, mirrored}, OperationRegistry over IndexMap, suggest_hint via text::close_matches, the 33-row §4.6.6 table in builtin_{aes,rsa,ec,generic}.rs through crate-private builders in model.rs `build`, custom::{spec_from_config, derive_key_classes, raw_mechparam_spec}, build_operation_registry), r2-testkit FakeProvider/FakeHooks, contract cases + provider_contract_tests!, fixtures. Interpretations: (1) FakeHooks dispatch: every Provider/TokenInit method offers the call to the hooks with `next` = an un-hooked view (`as_any` → the FakeProvider, `as_token_init` → un-hooked TokenInit); capability checks call the HOOKED `mechanisms()`, `set_env_and_reset` the HOOKED `shutdown()`; an overriding hook records nothing; `unwrap_key` stores through the fake's internal store path exactly like c2 (it never calls the hooked `import_key`, so `calls()` keeps c2's single `unwrap_key` entry) — now stated in §4.10.2 (§4.11 change above); the un-hooked `next` overrides `supports` to resolve the hooked `mechanisms()`. (2) FakeProvider builtin param reads go through params::param_int (mac_len, out_len; default 0 = c2 None) and param_str (hash, `or "sha256"`), per §4.5.4: a non-integer mac_len/out_len is now a Param error where c2's isinstance check silently ignored it (unreachable through ParamResolver). (3) Empty key_id arguments are normalized to None on import/generate/unwrap/store_key_unchecked (§4.3 invariant). (4) `with_tokens`: init_token records `[init_token, slot, label]` first, then refuses a label > 32 bytes with Param "token label must be at most 32 bytes" (param_name "label", the TokenInit contract) and a non-free slot with Provider "no free slot {slot}"; the serial counter advances only on success; `starting_logged_out` is builder-order independent and a no-op for "memory". (5) OTHER-key verb refusal names r2 (D7): "key type {CKA_KEY_TYPE|unknown} of '{ref}' is not supported by r2 for {verb}". (6) read_full_template rows CKA_CLASS/CKA_KEY_TYPE are AttrValue::Symbol (kind Ulong); attributes outside CKA_CATALOG get c2 `_kind_of_value` kinds (Symbol → Str); the contract cases accept a Symbol or Str with the c2 text so R4/R5b may use either. (7) rsa_raw_modexp: k = ceil(bit_length(n)/8) (leading zero bytes of the modulus ignored, c2 int semantics); an internal BigNum failure is Crypto "RSA-RAW modular exponentiation failed" (r2 text, not reachable with valid inputs); every BigNum holding the input, the exponent (may be d) or the result is BN_clear'ed on every path by a drop guard (openssl's BigNum Drop is BN_free, no wipe). (8) resolve_cli suggestion hints use the de-duplicated sorted cli names (c2 set); a key without a curve never matches a curve-restricted spec (c2 `None in frozenset`). (9) contract `skip` prints "SKIP: …" to stderr; `unique_label` = 4 random bytes as 8 lower-case hex; fixtures are OnceLock-cached (rsa2048/ec_p256/ed25519 PKCS#8, rsa_pkcs8_and_cert CN "r2-contract"); self_signed_cert: v3, 159-bit random serial, notBefore now−1d, notAfter now+3650d, BasicConstraints critical CA:FALSE, SHA-256 or no digest for Ed. Tests: r2-provider/tests/{provider_base (c2 test_provider_base), lookup, rsa_raw (incl. an OpenSSL Padding::NONE cross-check), fake_provider (hooks, tokens, full call encoding, editing, error texts)}.rs, r2-ops/tests/{ops_registry, ops_objects, build_registry (test_app registry cases; config values built directly, no YAML), ops_model (table row by row, shared param lists, invocation/mirror/suggest_hint)}.rs, r2-testkit/tests/contract_fake.rs (fake_memory + fake_pkcs11, 68 cases). test_full_builtin_id_set: c2 inspected `reg._specs`; r2 proves "nothing extra" by probing available_for over every verb/algorithm/class/curve against memory- and pkcs11-presented probe providers whose mechanisms are the canonical set widened by every table mechanism (no new pub API; residual gap, named in the test: a stray row restricted to a provider name or using a mechanism no expected row uses). Ledger: 106 rows ported (34 contract rows → both presentations; the two instantiation rows list their 34 tests), 1 n/a (pre-marked frozen-dataclass). |
| R4 | todo | | | |
| R5a | todo | | | |
| R5b | todo | | | |
| R6 | done | `R6:` commits | 2026-10-02 | §4.11 change (no merged loop affected: R0 calls none of these and no other loop has merged code that depends on the changed prose; only R6 prose + §11 are touched): §4.4.3 — OpenSSL never parses PEM: keyparse decodes the block (RFC 1421 headers + base64) and loads it through the BEGIN label's DER entry point (pyca dispatches on the label; avoids the FnOnce password callback being re-invoked by OpenSSL 3 decoders, a panic in rust-openssl), encrypted PKCS#8 is still detected with the `private_key_from_pkcs8_callback` "asked" probe and decrypted through it, traditional PEM is decrypted by keyparse (EVP_BytesToKey MD5 + CBC); pyca's cipher sets reproduced (verified against pyca 49): traditional `DEK-Info` only AES-128-CBC/AES-256-CBC/DES-EDE3-CBC (AES-192-CBC, DES-CBC, CAMELLIA, CFB… → wrong-password text after the prompt), encrypted PKCS#8 only PBES1 MD5-DES/SHA1-3DES/SHA1-RC2-40/SHA1-RC4-128 and PBES2 (PBKDF2 PRF SHA1..512 or scrypt) over AES-*-CBC/DES-EDE3-CBC/RC2-CBC; explicit EC parameters map only to P-256/P-384/P-521 (pyca text "ECDSA keys with explicit parameters are only supported when they map to secp256r1, secp384r1, or secp521r1. No custom curves are supported." — the spec said all nine curves); every EC key is rebuilt on its named group (uncompressed point, pyca re-encoding); RSA/EC private keys pass check_key; §4.4.4 `build_csr` assembles the DER as c2 does (not x509-cert `CertReq`: const-oid cannot hold OIDs pyca accepts, e.g. `2.999`, 128-bit `2.25.` arcs) and re-parses it as pyca (PrintableString alphabet → "assembled CSR failed to parse: error parsing asn1 value: ParseError { kind: InvalidValue, location: [r, a, …] }", c2 verbatim); §4.4.5 certificates are read by a strict DER walker with pyca's load-time checks instead of x509-cert (same reason; dates formatted by r2, not `Time::to_date_time`); §5.4/§5.11 prose follow; §11 D12(b) extended (keyexport `_cert_spki` on an unsupported curve and lazily-undecodable Name values in `certificate_details` crashed c2; r2 KeyParse). Interpretations: `rfc4514_string` errors → KeyParse "name is not a valid DER X.509 Name: {pyca text}", certificate callers wrap Name failures as "certificate is not valid DER X.509: {pyca text}"; a Name value with a tag outside pyca's `_ASN1Type` (c2 KeyError) → "unsupported name attribute value tag {n}"; `build_pkcs12` NUL guards — withdrawn in fix round 3; `private_key_bytes`/`pkcs8_public_spki` report an encrypted input with pyca's detail "Password was not given but private key is encrypted"; unknown OpenSSL key types → pyca "Unsupported key type." / "Curve {oid} is not supported" (SM2); pyca class names in texts: DSA/DH/X25519/X448/RSA/EC/Ed*; D11 details = first OpenSSL reason (or der/base64 text). Mechanical foreign-file fix (handoff from R0, sanctioned in R0's row): `crates/r2-core/tests/r0_mandated.rs` loses the two lines asserting the R6 `ecdsa_rs_to_der` stub error (the stub is gone). Tests: r2-core integration tests keyparse (61), x509build (35), x509info (10), formats (11), der (5) + in-file keyparse/x509build/x509info unit tests; fixtures generated at test time with OpenSSL (support/keygen.rs, incl. odd curves, explicit P-256, RSA-PSS, DSA, legacy PKCS#12); pyca vectors generated in c2's venv by `crates/r2-core/tests/support/gen_x509_vectors.py` (146 RFC 4514 subjects incl. CSR re-parse texts, 30 Name decodings). Scratch differential vs c2 (not committed): 341 OpenSSL-CLI inputs × {no callback, right, wrong password} → identical parse_key_material outcomes and bytes except c2 crash paths (D12) and D11 detail texts; certificate_details/formats writers/RSA+Ed CSR bytes identical. Ledger: 73 R6 rows ported. **Fix round 1** (§4.11, no merged loop affected): §4.4.5 gains `pub fn pkcs11_skips_certificate(&ConsoleError) -> bool` (R5a handoff: on the PKCS#11 certificate read path call `cert_facts`/`cert_attributes` and SKIP the certificate when this returns true — c2's `except ValueError` — else propagate the error; c2's UnsupportedAlgorithm/TypeError/KeyError/KeyParseError cases); §4.4.3/§4.4.5/§4.4.6/§4.4.8/§5.4/§5.11 prose: key DER must pass a strict DER check (one TLV, minimal lengths, no trailing bytes, recursive incl. PKCS#8 privateKey and RSA SPKI contents) before any OpenSSL key decoder; PEM framing is a port of pyca's `pem` 3.0 crate (raw tags compared, headers only before a blank line, pyca's `Unable to load PEM file … {PemError:?}` texts and tag-filter texts); RFC 1421 `Proc-Type`/`DEK-Info` follow pyca's `decrypt_pem` for every private label (exact `4,ENCRYPTED`, DEK-Info required and split untrimmed, errors before the prompt); certificates/CSRs are read by the strict parser alone (no `X509::from_der`/`X509Req::from_der` in keyparse/formats; certificate PEM = loaded DER base64 64/LF); x500UniqueIdentifier BIT STRING Name values are bytes rendered `#hex`; PBES2 RC2-CBC only with rc2ParameterVersion 58; a MAC-less PKCS#12 is retried with a MacData computed for the given password (OpenSSL 3.0 refuses it otherwise); PKCS#12 attempts also require every certificate to pass the strict load; `bytes_to_key`'s derived IV is zeroized. §11: D12(b) extended (keyparse `_subject_cn`/CSR subject crashes, unknown SPKI key types, GeneralizedTime year 0), D12(h) empty password at an encrypted-key prompt → "encrypted key material requires a password", D12(i) PKCS#12 private key pyca refuses → "PKCS#12 contains an unsupported private key: {detail}", new D24 (PKCS#12 export needs an OpenSSL-decodable certificate), new D25 (pyca warnings not printed). Tests: keyparse 68, x509info 13, formats 13, x509build 37; Name vectors regenerated (the old `bitstring_uid` vector used OID 2.5.4.69, now `bitstring_other_oid`; real 2.5.4.45 cases added). Scratch differential vs c2 (not committed): 9 237 cases (857 new mutation/encoding inputs × none/pw/bad/empty + the earlier corpus × 4 passwords + formats/details modes) → identical outcomes, prompts and bytes except D11 detail texts and c2 crash paths (D12). **Fix round 2** (R6-SPEC2-1/2, PAR-1..4, R6-BUG-1..3), §4.11 change (no merged loop affected: only R6 prose and §11 change; no §4 signature changes): §4.4.3/§4.4.5/§4.4.6/§5.4 prose — key material is read by a port of pyca 49's own parsers (`cryptography-key-parsing`: PKCS#8 version 0 only with [0] attributes, SEC1 version 1 with outer/inner curve equality, order-length private value and point check, PKCS#1 version 0 without otherPrimeInfos, unsigned key integers, DSA/DH, SPKI with pyca's DEFINED BY AlgorithmIdentifier parameter table, EncryptedPrivateKeyInfo decrypted by keyparse with the whole password — PBES1 via pyca's PBKDF1/RFC 7292 KDF, PBES2 via PBKDF2/scrypt) over a port of rust-asn1 0.24, keys built from components (no OpenSSL key DER decoder, no OpenSSL password callback, no strict-DER pre-check); certificates/CSRs parsed as pyca's whole `Certificate`/`CertificationRequest` structures (EXPLICIT version DEFAULT v1, AlgorithmIdentifier parameters, unique IDs, Extensions with BOOLEAN DEFAULT FALSE, CSR attributes SET OF in DER order, nothing extra) then pyca's InvalidVersion; PKCS#12 attempts load the key through pyca's DER loader (ValueError → failed attempt, UnsupportedAlgorithm → D12(i)); traditional PEM uses the first IV-length bytes of a longer DEK-Info IV; RSA keys also need odd p/q, EC infinity refused; §4.4.4/§5.6 `build_pkcs12` = a port of pyca's native PKCS#12 writer (same structure: PBES2-SHA256-AES256 bags at 20000, SHA-256 MAC at 2048, UTF-16 friendlyName incl. non-BMP, localKeyId; "Certificate public key and provided private key do not match" → Crypto "PKCS#12 assembly failed: …"); §4.4.6 `private_key_bytes` refuses passwords over 1023 bytes. §11: D12(b) + InvalidVersion (cert/CSR), D12(i) limited to UnsupportedAlgorithm, new D12(j) (export password over 1023 bytes), D24 withdrawn (PKCS#12 export takes every certificate pyca loads). Tests: keyparse +10 (certificate_structure_is_pycas, csr_structure_is_pycas, private/public_key_structures_are_pycas, invalid_rsa_private_keys_are_pycas_value_errors, ec_private_keys_must_match_their_public_point, pkcs12_with_a_key_pyca_does_not_support_is_d12i, long_passwords_decrypt_pkcs8_as_pyca, traditional_pem_iv_longer_than_the_cipher_iv_decrypts), x509info +1, formats +2, x509build +2 (D24 test now asserts the export works). Scratch differential vs c2 (not committed; pyca 49 sources read from its sdist): 64 000 parse cases (16 000 mutated inputs — certificate with extensions, CSR, EC/RSA/Ed25519/X25519 PKCS#8/SPKI/SEC1/PKCS#1, encrypted PKCS#8; 1–2 byte edits — × none/pw/bad/empty) + the earlier corpora (2 524 cases) + the reviewers' inputs + every new test input → identical outcomes, prompts and bytes except c2 crash paths (D12) and pyca's ASN.1 error locations (D11); `certificate_details`/`certspki`/`certpem`/`priv`/`pubpem` modes over the mutated inputs identical modulo D11 detail text; r2-built PKCS#12 have pyca's structure and lengths and reparse identically in c2. **Fix round 3** (R6-SPEC3-1/2, PAR3-1, R6-BUG3-1), §4.11 prose change (no signature change; no merged loop affected — only R6 prose and §11): §4.4.5 `pkcs11_skips_certificate` doc now lists pyca's InvalidVersion among the propagated cases (matching the code and D12(b)); the `certificate_details` code doc synced to its §4.4.5 text; §4.4.4/§4.4.6 — the build-path NUL guards are removed (`build_pkcs12` password and friendly name, `private_key_bytes` password): c2 accepts NUL there and neither r2 writer uses a C string, so a NUL is an ordinary character (U+0000 in the PKCS#12 BMPStrings, raw byte in PBKDF2); §11 D16 shrunk to the PKCS#12 parse path (and corrected: pyca panicked there too, c2 crashed); new §11 D12(k): an encrypted PKCS#8 with a PBKDF2 iterationCount above i32::MAX panicked in rust-openssl's `pbkdf2_hmac` (pyca PanicException, c2 crash; r2 panicked too) → now pyca's ValueError → "incorrect password for encrypted private key (or corrupt encrypted data)" after the prompt. Audit of other panicking OpenSSL wrappers on user input: pbkdf2 password/salt lengths and scrypt maxmem are bounded by input size/a constant; PKCS#12 parse2 NUL guarded. Tests: keyparse +1 (`pbkdf2_iteration_counts_above_c_int_are_the_wrong_password_text`, 2^31 and 2^40, DER and PEM), x509build `pkcs12_nul_guards` → `pkcs12_nul_bytes_are_ordinary_characters` (MAC verified under the NUL password, key bag decrypts with it, friendlyName `k\0x` reloads and is the label hint as in c2), formats `nul_in_the_password_is_an_ordinary_byte`; ledger row test_pkcs12_empty_password updated. |
| R7 | done (pending D8 decision) | `R7:` commits | 2026-10-02 | No §4.11 change; no §11 entry added. Sanctioned edits only: r2-console `[dev-dependencies]` gains `tempfile` (§4.1.4 dev, permitted) + Cargo.lock; `crates/r2-console/build.rs` and `src/tests/build_discovery.rs` taken over unchanged (header comment only). §11 D8 left OPEN with option A (parity): `is_secret_line` filters `--pin`/`--password` only — the D8 decision (orchestrator/user) is still required before R7 merges (one-function change). Interpretations: (1) PlainIo keeps c2's piped-session history too — `PlainReader` saves through `SecretFilteringHistory` into `app.history_file` and syncs (one logical entry per command since fix round 1, as TerminalIo — D7); (2) a PlainReader I/O error is the Generic "cannot read input: {os_error_text}" (rendered by the REPL, which then ends — D12 (c)); (3) a panic outside the per-command boundary (startup, e.g. an R0 constructor stub) is caught in r2-cli: logged, stderr "error: unexpected error: {payload} (hint: details logged to {log})" (+ the report with --debug), exit 1 (c2: uncaught traceback, status 1); (4) `--version` only, no clap `-V` (c2 argparse had none); `--config ""` = absent; (5) `select`/`confirm`/multiline prompts pass no completion choices (c2 attached none); ENUM/BOOL prompts pass `choices_for` (c2 `completer_for`); (6) highlighting precedence follows the binder: first token by its text (green/red), then quoted (yellow), `--opt` (blue), `name=value` (magenta), registered `provider:` ref (cyan); (7) path-like suggestions get `display_override` = last component unless the candidate is a registered `provider:` ref; (8) providers are shut down after `run_repl` (warnings "shutdown of provider {name!r} failed: {message}"; a panicking shutdown is caught and logged; since fix round 1 also when a panic escapes the REPL, then the panic continues to the startup-panic handler); (9) log layer: one global `tracing` subscriber installed once, sinks/level held in a replaceable state (idempotent re-setup like c2's handler swap), records "{time} {LEVEL:<7} {target}: {message}" with Python level names, structured fields appended as k=v and redacted with the message; mkdir follows Python `mkdir(parents=True, exist_ok=True)` so the Config error names the path that failed. Bootstrap seam: `bootstrap::build_with(config, &dyn ProviderFactory)` (c2's stub-module injection); `run()` takes the registry builder and an optional ConsoleIo (c2 `main(argv, io=…)`). Tests: r2-ops `tests/params.rs` (27), r2-console `src/tests/{parser,commands,completer,discovery,io,repl,render,testing_support}.rs` (+ c2 `config show` byte vectors `src/tests/fixtures/*.c2.txt` from `gen_config_show.py`, HOME=/home/tester), r2-cli bin unit tests (args/bootstrap/logging/main), `tests/e2e_repl.rs` (assert_cmd piped transcripts) and `tests/e2e_pty.rs` (Linux only, util-linux `script` pty: TERM=dumb → PlainIo, silent terminal → degrade warning; a missing `script` FAILS). Merge checklist: e2e `test_main_end_to_end_with_real_providers` and `config_path_without_external_file_names_the_discovery_order` are `#[ignore = "needs the R4/R5a provider constructors …"]` (nextest reports them skipped) while MemoryProvider/Pkcs11Provider/find_softhsm_module are R0 stubs — the R7 merge (after R4/R5a) MUST delete both ignores so they always run; `test_selector_stage_through_console_completer` uses a `delete` stand-in command until R8's keys module lands. Ledger: 142 ported, 8 n/a (pre-marked). **Fix round 1** (R7-GATE-1..3, R7-SPEC-1..7, R7-PAR-1..3, R7-BUG-1..3 + the bugs-lens R7-PAR-1/2), §4.11 change (no merged loop affected; only r2-cli/r2-console R7 files, the root and r2-cli manifests and Cargo.lock): §4.1.2/§4.1.4 drop `file-rotate` — r2-cli's log rotation is now an own port of Python's `RotatingFileHandler` (rollover before the record that reaches `max_bytes`, `.i`→`.i+1` rename chain, I/O errors ignored, never panics; file-rotate 0.8 panicked at startup on an unlistable log directory and inside the subscriber on stray/concurrently rotated backups), §4.9.11 log-setup text and §11 D4 (the "may exceed `max_bytes` by one record" residual is gone) follow; §4.9.7 (frozen-provisional R7-internal) PlainReader rules gain the interrupt reset before a terminal command read + rpassword's raised-SIGINT consumption, and the logical-entry history; DegradingReader: rpassword errors never degrade; §4.9.7/§5.1 highlighting classifies tokens as `bind_args` binds them (an option's value is never blue/magenta; `--`/`=x` unstyled); §11 D7 says PlainIo sessions store logical entries too. Code: clap `infer_long_args` + `args_override_self` (argparse `allow_abbrev` prefixes and last-wins repeats; `-V` still rejected); startup order providers → operations → template editor → commands (§4.9.11); the degrade warning has no leading CRLF (pty test pins the exact bytes). Rejected: R7-SPEC-4 (ASCII-only `select` numbers are already recorded in §11 D18). Ledger: c2 `test_prompt_secret_does_not_mask_later_prompts` / `test_param_completer_does_not_leak_to_later_prompts` → ported (same-named r2-console io tests); R7 now 144 ported, 6 n/a. **Fix round 2** (R7-PAR2-1, R7-BUG2-1), §4.11 change (R7-internal text only, no signature changed, no merged loop affected): §4.9.11 startup order — the global tracing subscriber is installed before `load_config` and, until `setup_logging`, writes WARN+ records to stderr as bare messages (Python's `logging.lastResort`), so the config loader's "unknown config key …" / below-range CKM warnings reach the operator as in c2 (they were dropped); §4.9.7 + the §5 Ctrl-C table — PlainReader with a NON-terminal stdin honours SIGINT like c2's KeyboardInterrupt: a read interrupted before or while it blocks reports Interrupted (`Aborted.` / param UserAbort) and the line it read is stashed and returned by the next read, so no piped line is lost (r2 ignored it). Tests: r2-cli logging `pre_setup_warnings_go_to_last_resort_as_bare_messages`, `config_loader_warnings_reach_last_resort`; e2e `config_loader_warnings_reach_stderr_before_logging_setup`, `sigint_with_piped_stdin_aborts_the_read_and_keeps_the_line`; r2-console io `piped_sigint_during_a_read_aborts_it_and_keeps_the_line`, `piped_sigint_before_a_read_aborts_it_without_consuming_input`. Ledger unchanged (144 ported, 6 n/a). **Fix round 3** (R7-GATE3-1, R7-SPEC3-1, BUG-1, BUG-2, R7-PAR3-1; R7-SPEC3-2 not actionable in-loop: the D8 decision still belongs to the orchestrator/user), §4.11 change (R7-internal text + §11 D1 wording, no signature changed, no merged loop affected): §4.9.7 — the line read by an interrupted piped secret read is zeroized and discarded, never stashed (it came back as a command: echoed, saved to the history, dispatched); §11 D1 records that a word longer than its table column is folded with its content whole (c2/rich `overflow="ellipsis"` cropped it to `…`, e.g. a long path in `config show --origin`) — R1's renderer is unchanged. Code: `SecretFilteringHistory::open` rewrites a history file that is not valid UTF-8 with U+FFFD replacements (c2 `errors="replace"`; reedline's sync refused it, silently disabling history for good) and warns on `r2::console` when a given path is unusable; `LineIo::clear` skips the reader's repaint for a Plain sink (reedline wrote its own clear sequence on TERM=unknown/TTY_COMPATIBLE=0 terminals). e2e `config_path_without_external_file_names_the_discovery_order` now asserts the 80-column wrap c2/rich also produce (verified on a trial merge of R4+R5a with both ignores deleted: r2-cli 63/63 pass). Tests: r2-console io `piped_sigint_during_a_secret_read_discards_the_secret`, `history_file_with_invalid_utf8_keeps_being_appended`, `clear_writes_the_sequence_unless_plain` (reader repaint), commands `config_show_origin_folds_a_long_path_keeping_it_whole`. Ledger unchanged (144 ported, 6 n/a). |
| R8 | todo | | | |
| R9 | todo | | | |
| R10 | todo | | | |
| R11 | todo | | | |
| R12 | todo | | | |
| R14 | todo | | | |
| R15 | todo | | | |
| R13 | todo | | | |

## Working agreement

0. **Preconditions for dispatching any loop.** `spec.md`, `loops.md`, `CLAUDE.md`,
   `PLAN.md` and `parity/ledger.csv` (plus `parity/README.md` and
   `parity/generate_ledger.py`) are committed on the integration branch. R0, the only
   wave-0 loop after S0, is merged before anything else starts, because every other loop
   compiles against its skeleton.
1. **Before starting.** Read spec §4 entirely, §11 (deviations), and every §5–§9 section
   your card cites. Read this STATUS table, then run `git log --oneline` and confirm that
   the merged loops match it. List your ledger rows
   (`python3 parity/generate_ledger.py --stats --gate <ID>`), and open the c2 source and
   test files your card names under **Ports**. c2 is the behavioral oracle: where the spec
   is silent, c2's code and tests at 408d6f2 decide.
2. **One loop = one branch = one PR**, branch `loop/R<nn>[a|b]-<slug>` (e.g.
   `loop/R05a-pkcs11-foundation`, `loop/R08-key-commands`). **Or**, during single-branch
   bring-up, one loop = a series of commits on the integration branch, each subject
   prefixed `R<n>:` (e.g. `R5a: CKR choke point`), with the last commit flipping the STATUS
   row. Never interleave two loops in one commit. A loop merges (or lands its final commit)
   only after all its merge-order dependencies are merged and the done gate is green. You
   may *develop* against the skeleton of unmerged loops: their stubs return
   `ErrorKind::Generic` "not implemented (Rn)", so your tests that need them stay red until
   they merge.
3. **Ownership.** Touch only the files your loop owns (spec §4.1.1 map, restated in the
   cards below), your own test files, your own STATUS row, and your own ledger rows.
   Ownership is exclusive between loops that can run concurrently. Test ownership follows
   code ownership, not c2's file layout (spec §4.1.1 "Test files"). In
   `crates/r2-console/src/tests/` and `crates/r2-pkcs11/src/tests/`, each `<topic>.rs` has
   exactly one owner, the loop that creates it.
4. **Sanctioned handoffs** (spec §4.1.1 "R0 skeleton handoff"; no §4.11 procedure needed):
   - Owning loops replace R0's stub bodies in their files.
   - `crates/r2-cli/src/main.rs` goes from R0 to R7. `crates/r2-console/build.rs` and
     `crates/r2-console/src/tests/build_discovery.rs` go from R0 to R7.
     `crates/r2-config/src/defaults.yaml` goes from R0 to R2.
     `crates/r2-core/src/catalog.rs` goes from R0 to R5a. Each crate's `lib.rs` goes from
     R0 to the crate's owner, except `crates/r2-services/src/lib.rs` and
     `crates/r2-testkit/src/lib.rs`, which stay R0's.
   - `crates/r2-pkcs11/src/backend/fake.rs` and `crates/r2-pkcs11/src/tests/mod.rs` go
     from R5a to R5b, which may extend them after R5a merged.
   - R12 owns the root `[profile.release]` table and the `vendored-openssl` lines in the
     `[features]` tables of `r2-cli` and `r2-core`.
   - Any loop owning files in a crate may add a dependency line (normal or dev) to that
     crate's `Cargo.toml` when the dependency is pinned in spec §4.1.4 and permitted for
     that crate by §4.1.2. Cargo may update `Cargo.lock` for already-declared
     dependencies.
5. **Cross-loop contract changes** go only through spec §4.11. Update spec §4 in your
   branch or commit series, make only the minimal mechanical call-site fixes in foreign
   files (including the skeleton items of unmerged loops), record the change in your STATUS
   row, and update the ledger rows you own. New third-party dependencies, new crate edges,
   new `unsafe` sites and new allowed threads are §4 changes. If you need anything else
   changed elsewhere, record it under Deviations and stop.
6. **Done gate** (run all, in order; spec §8):
   ```sh
   cargo fmt --check
   rustfmt --edition 2024 --check crates/r2-console/src/commands/*.rs crates/r2-console/src/tests/*.rs
   cargo clippy --workspace --all-targets -- -D warnings
   cargo nextest run --workspace
   cargo deny check
   python3 parity/generate_ledger.py --stats --gate <ID>
   ```
   When SoftHSM is present locally, also run
   `eval "$(scripts/softhsm-init.sh)" && cargo nextest run --workspace --features softhsm`.
   CI runs it regardless, on the SoftHSM 2.6.1 + 2.7.0 matrix. The STATUS row and ledger
   rows are updated in the same PR or commit series.
7. **Never delete or weaken another loop's tests.** New tests go in your own files. A
   foreign test may change only as a §4.11 mechanical fix that preserves its intent, and
   that change is recorded in your STATUS row.
8. **Port tests as the executable spec.** Each loop ports the c2 tests that the ledger
   assigns to it. Keep test vectors, inputs and asserted messages verbatim (c2 → r2 only
   where the text names the tool, §11 D7), and translate only the mechanics. Each loop
   ships its tests with its code. Tests pass with no SoftHSM installed. Anything that
   needs a real module sits behind cargo feature `softhsm` and fails hard (never skips)
   when the fixture is missing.
9. **The ledger is updated by the porting loop.** In the same PR or commit series, set
   your rows to `ported` (with the Rust test IDs as `cargo nextest list` prints them) or
   `n/a:<reason>` (pure-Python mechanics only). Edit only rows whose `r_loop` is yours.
   Never change `r_loop` by hand: a mis-assigned row moves through the generator's
   `OVERRIDES` table and a regeneration, recorded in both loops' STATUS rows
   (`parity/README.md`).
10. **Parity first, idiom second.** Anything observable that differs from c2 and is not in
    spec §11 is a parity bug. **c2 is frozen at 408d6f2** until M3. If c2 must change (a
    field fix from a real HSM), the same change adds a spec §11 row or a note here, plus a
    ledger entry.

## Dependency DAG

Waves (loops in the same wave may be developed in parallel; merge order per the edges
below):

```
Wave 0:  S0 → R0
Wave 1:  R1
Wave 2:  R2 ∥ R3 ∥ R6        (R3 merges after R2 — merge-order edge)
Wave 3:  R4 ∥ R5a ∥ R7       (R7 merges after R4 and R5a)
Wave 4:  R5b ∥ R8 ∥ R9 ∥ R11 ∥ R12
Wave 5:  R10 ∥ R14 ∥ R15     (develop from wave 4 on on FakeProvider; merge after R5b)
Wave 6:  R13                 (solo — owns everything)
```

Merge-order edges (authoritative; each card's "Depends on" line restates them):

```
S0  → R0
R0  → R1
R1  → R2, R3, R6
R2  → R3*, R5a, R7, R10, R11
R3  → R4, R5a, R7
R6  → R4*, R5a, R7*, R8
R4  → R7*, R8, R9, R10, R15
R5a → R5b, R7*, R8, R11
R5b → R10, R14, R15
R7  → R8, R9, R10, R11, R12, R14, R15
R8  → R14*, R15*
R8, R9, R10, R11, R12, R14, R15 → R13
```

`*` = merge-order-only edge. The dependent loop is developed in parallel against the
skeleton and merges after the dependency:
- **R2→R3\*:** `r2_ops::custom` consumes `r2_config::model` value types (§4.6.3).
- **R6→R4\*:** memory classifies certificates with `x509info` and uses the `der`/`formats`
  helpers.
- **R4/R5a/R6→R7\*:** R7's framework and tests use only §4 contracts and FakeProvider, but
  `r2-cli`'s bootstrap constructs `MemoryProvider` and `Pkcs11Provider`, calls
  `find_softhsm_module`, and calls `ensure_legacy_provider` (which has a mandated R0 body).
- **R8→R14\*/R15\*:** R14 and R15 fill in hooks that R8's `key`/`load`/`export` commands
  call (`commands::key_template::run`, `commands::kek::{run_load, run_export}`); their
  console tests drive those commands.

Edges added by the spec beyond PLAN §8 (spec §4.1.1): **R6 → R5a** (hard; the
certificate read path uses `x509info::cert_facts`/`cert_attributes` and the `der` EC
helpers) and **R6 → R7\***. The wave plan already satisfies both.

Critical path: **S0 → R0 → R1 → R3 → R5a → R5b → R10 → R13** (R1 → R6 → R5a is the same
length; R5a → R7 → R10 runs alongside R5b).

Milestones (PLAN §11): **M0** = S0 + R0 merged, CI green on the skeleton. **M1** (memory
console) = waves 1–3 + R8 + R9. **M2** (full surface) = waves 4–5. **M3** = R13 parity
sign-off.

---

## S0 — Spec port + API spikes (M) — docs only

Turns PLAN.md into the working documents: c2's spec ported to r2 (§4 rewritten as frozen
Rust contracts, §11 deviations), this file, CLAUDE.md, and the parity ledger. Three
half-day spikes (cryptoki coverage, OpenSSL coverage, terminal) whose results are recorded
in the spec before §4 froze. Spike code is throwaway and is not merged.

- **Owns**: `spec.md`, `CLAUDE.md`, `PLAN.md`, `loops.md` (the cards and dependency
  sections stay S0's; every loop edits only its own STATUS row), `parity/README.md`,
  `parity/generate_ledger.py`, `parity/ledger.csv` (S0 creates it; every loop edits only
  its own rows).
- **Ports**: c2 `spec.md` (whole); `pytest --collect-only` of c2@408d6f2 → the ledger.
- **Provides**: every frozen contract (spec §4), the deviation list (§11), the loop plan,
  and the ledger (1,284 rows, 1,600 c2 node IDs).
- **Depends on**: nothing.
- **Accept**: every c2 §4 item has an r2 counterpart or an `n/a` (spec §4.11.3); every c2
  test is assigned to exactly one loop (`generate_ledger.py --stats` clean); all spike
  outcomes are recorded.

## R0 — Workspace, contract skeleton, CI, SoftHSM fixture (M) — c2 L0

Turns spec §4 into a compiling workspace. All crates, every §4.2–§4.10 item written as
code (types, traits, constants and data tables complete; function bodies stubbed per
§4.1.1), workspace lints and `clippy.toml` per §4.1.3, `deny.toml`, `justfile`, nextest
config, CI, the `r2` binary stub (`--version`), and the app-independent SoftHSM fixture
and init script (§4.10.5).

- **Owns**: `Cargo.toml` (except `[profile.release]`, R12), `Cargo.lock` (creates it),
  `rust-toolchain.toml`, `clippy.toml`, `deny.toml`, `justfile`, `.config/nextest.toml`,
  `LICENSE`, `.github/workflows/ci.yml`, `scripts/softhsm-init.sh`,
  `scripts/build-softhsm.sh`, every `crates/*/Cargo.toml` (except R12's feature lines),
  `crates/r2-services/src/lib.rs`, `crates/r2-testkit/src/lib.rs`,
  `crates/r2-testkit/src/softhsm.rs`. It creates and hands off every other skeleton file
  of §4.1.1 (every `lib.rs`, `main.rs`, `mod.rs` and module stub) to its owner. These are
  written complete and working, then handed off: `crates/r2-console/build.rs` and
  `crates/r2-console/src/tests/build_discovery.rs` (→ R7),
  `crates/r2-config/src/defaults.yaml` (→ R2), `crates/r2-core/src/catalog.rs` (→ R5a),
  and the mandated working bodies of §4.1.1 (`create_template_editor`, `token_needs_init`,
  `run_softhsm_wizard`, `templatefile::build_seed`, `EditorSeeding::edit`, the
  `catalog::cka`/`cka_by_code` lookups, the R6 helpers `crypto::{ct_eq, random_bytes,
  ensure_legacy_provider}` and `der::{curve_oid_der, curve_from_oid_der,
  wrap_octet_string}`, and `commands()` → `vec![]` in every command module).
  Tests: `crates/r2-cli/tests/smoke.rs`, `crates/r2-testkit/tests/softhsm_fixture.rs`
  (feature `softhsm`).
- **Ports**: c2 `pyproject.toml`/CI config (as Rust equivalents), `tests/integration/conftest.py`
  (fixture → `r2_testkit::softhsm`); tests `unit/test_smoke.py` (version part),
  `integration/test_softhsm_fixture.py` (6 ledger rows).
- **Provides**: build/test/lint commands (CLAUDE.md); the skeleton every loop compiles
  against; `softhsm_token()`, `unique_label()`; `scripts/softhsm-init.sh` (§4.10.5
  contract); CI jobs `lint`, `test` (ubuntu/macos/windows + doc tests), `softhsm` (2.6.1
  distro + 2.7.0 from source), `msrv`. **Consumes**: spec §4.
- **Depends on**: S0.
- **Accept**: the done gate is green on the skeleton; `cargo run -p r2-cli -- --version`
  prints `r2 <version>`; the `build_discovery` seed test passes; every crate declares
  feature `softhsm`, so `cargo nextest run --workspace --features softhsm` is valid; CI
  is green, including the softhsm job's fixture self-test (the init script initializes
  `R2TEST` and the fixture reads it back and lists the token); the skeleton contains no
  invented fields or bodies (§4 materialization rules).

## R1 — Core model, codec, IO traits, renderer (M) — c2 L1 (+ L16 model parts)

The shared vocabulary in `r2-core`: errors and Python-faithful text helpers (§4.2), the
key model and the one ref-grammar parser (§4.3), the input codec and data I/O (§4.4.1–2),
param types (§4.6.1), the template model (§4.7), the interaction traits, Renderable model
and renderer (§4.9.1–2), the runtime flags (§4.9.8), and the test doubles `ScriptedIo` /
`RecordingEditor` plus the test-env helpers (§4.10.1). It has no console, provider or
terminal code.

- **Owns**: `crates/r2-core/src/{lib,error,text,keys,template,params,io,render,runtime,codec,datainput}.rs`,
  `crates/r2-testkit/src/{scripted_io,env}.rs`, its tests in `crates/r2-core/tests/<topic>.rs`
  (every test that uses r2-testkit MUST live here, not in-file — §4.1.1), and in-file
  `#[cfg(test)]` modules of its files.
- **Ports**: `core/{errors,keys,params,io,codec,datainput}.py`, `console/render.py`'s
  renderer (`make_table`, `hex_panel`, `error_panel`, `caret_text` → `r2_core::render`),
  `tests/support/scripted_io.py`; tests `unit/core/*` (`test_codec`, `test_datainput`,
  `test_errors`, `test_io_protocols`, `test_keys`, `test_keys_objects`, `test_params`,
  `test_scripted_io`, `test_templates`), the renderer cases of `unit/console/test_render`
  (moved per spec §4.1.1), and the R1 cases of `test_l13_hardening` (106 ledger rows incl.
  moved render cases).
- **Provides**: §4.2, §4.3, §4.4.1–2, §4.6.1, §4.7, §4.9.1, §4.9.2, §4.9.8, §4.10.1 —
  `ConsoleError`/`ErrorKind`/`Result`, `text::py_repr` & co., `parse_ref`/`display_refs`,
  `decode_data`, `DataInput`/`DataOutput`, `ConsoleIo`/`TemplateEditor`/
  `IdentityTemplateEditor`, `Renderable` + `render`/`render_plain`, `ScriptedIo`,
  `RecordingEditor`, `global_state_lock`, `set_env`/`EnvGuard`. **Consumes**: third-party
  crates only.
- **Depends on**: R0.
- **Accept**: c2's codec input matrix, table-driven: hex with spaces and newlines, base64,
  quoted multiline, PEM (re-wrapped, RFC 1421 headers kept), hex-wrapped PEM, forcing
  prefixes (with whitespace inside prefixed values), "hex beats base64", malformed →
  `Codec`. `parse_ref` grammar vectors (selector precedence, carve-outs, byte offsets) and
  `display_refs` suffixing are verbatim. Template enabled/disabled/locked semantics hold,
  and `set` of an unknown name → `Param`. Error/hint texts and `py_repr` outputs match
  Python. The error-panel and hex-panel renderers produce rich-identical text at 80
  columns (§11 D1). `ScriptedIo` drives a scripted prompt sequence and records rendered
  output.

## R2 — Configuration (M) — c2 L2

`defaults.yaml` (c2's file through the §7 rename transform), discovery with r2 names
(`--config`, `$R2_CONFIG`, `./r2.yaml`, user dir `r2/r2.yaml`), deep merge (maps merge,
scalars and lists replace), `origins`, the typed path-aware decoder with c2-verbatim
messages, unknown-key warnings with suggestions, platformdirs-compatible dirs, and the
PyYAML-faithful YAML loader/emitter (YAML 1.1 `yes/no/on/off`, `0x…`) used by every crate
that reads or writes YAML.

- **Owns**: `crates/r2-config/src/{lib,model,loader,decode,yaml,dirs}.rs`,
  `crates/r2-config/src/defaults.yaml` (from R0), `crates/r2-config/tests/<topic>.rs`
  (e.g. `config.rs`).
- **Ports**: `config/{loader,model}.py`, `config/defaults.yaml`; tests `unit/test_config.py`,
  `unit/test_config_objects.py` (56 ledger rows).
- **Provides**: §4.8 — `load_config`, `LoadedConfig` (with provenance), `AppConfig` and
  every section type, `TemplatesSection::default_template`, `template_class_key`,
  `Pkcs11InstanceConfig`, `CustomMechanismConfig`, `CustomAttributeDef`, `ParamSpecConfig`,
  `user_config_dir`, `expand_user`, the `r2_config::yaml` helpers (§4.8.5). The model
  types are importable by any crate; only `r2-cli` calls `load_config`. **Consumes**: R1.
- **Depends on**: R1. Parallel with R3 and R6.
- **Accept**: precedence (CLI > env > CWD > user dir; an explicit missing file is a hard
  error); merge semantics including list replacement; `origins` are correct;
  schema-violation messages carry the config path; unknown keys warn via `tracing` with
  "did you mean" (difflib cutoff as c2); the embedded file loads clean and round-trips;
  `default_template` is correct for all eight class keys; a fixture config using
  `yes/no`/`on/off` and `0x` values decodes exactly as PyYAML does; emitted YAML matches
  PyYAML's for the shapes the wizard and templatefile write.

## R3 — Provider & operation contracts, registries, FakeProvider, contract suite (M/L) — c2 L3 (+ `builtin_generic`)

The central frozen interfaces made real: the `Provider` trait, its data types, the
registry, shared lookup helpers, `rsa_raw_modexp` and the canonical mechanism names
(§4.5.1–4); the operation model, `OperationRegistry`, `register_builtins` with the full
built-in table (all four families), `build_operation_registry`, and custom-mechanism
loading (§4.6.2–3, §4.6.6). It also ships the project-wide `FakeProvider`/`FakeHooks`,
the `provider_contract_tests!` macro with its 34 cases, and the OpenSSL test fixtures
(§4.10.2–3). R3 does not wire config discovery (R7 does) and does not touch any pkcs11
table: custom CKM→id maps reach `Pkcs11Provider` at construction.

- **Owns**: `crates/r2-provider/src/{lib,provider,types,registry,lookup,rsa_raw,mechanism}.rs`,
  `crates/r2-ops/src/{lib,model,registry,custom,builtin_aes,builtin_rsa,builtin_ec,builtin_generic}.rs`,
  `crates/r2-testkit/src/{fake_provider,contract,fixtures}.rs`,
  `crates/r2-testkit/tests/contract_fake.rs`, `crates/r2-provider/tests/<topic>.rs`,
  `crates/r2-ops/tests/<topic>.rs` (not `params`, which is R7's).
- **Ports**: `providers/{base,registry}.py`,
  `ops/{model,registry,builtin_aes,builtin_rsa,builtin_ec,builtin_generic,custom}.py`,
  `app.build_operation_registry` (moved per spec §4.1.1), `tests/support/fake_provider.py`,
  `tests/contract/base.py`; tests `contract/base.py` (34 cases) + the two FakeProvider
  instantiation rows, `unit/test_ops_registry`, `unit/test_provider_base`,
  `unit/test_ops_objects`, and the registry cases of `unit/console/test_app` (moved) (107
  ledger rows incl. moved cases).
- **Provides**: §4.5.1–4, §4.6.2–3, §4.6.6, §4.10.2–3 — `Provider`, `TokenInit`,
  `ProviderRegistry`, `KeySelector`, `GenerateRequest`, `UnwrapRequest`, `WrapOptions`,
  `MechanismInvocation`, `DeriveResult`, `KeyEditResult`, `rsa_raw_modexp`,
  `OperationSpec`, `OperationRegistry`, `register_builtins`, `build_operation_registry`,
  `suggest_hint`, `custom::load_custom`, `FakeProvider`, `FakeHooks`,
  `provider_contract_tests!`, `fixtures::*`. **Consumes**: R1; R2's `r2_config::model`
  types (in `r2_ops::custom` only), coded against frozen §4.8.
- **Depends on**: R1; R2 merge-order-only. Parallel with R6.
- **Accept**: all 33 built-in op ids are registered with exact params (including
  `default_from` and `salt_len=-1`); `available_for` filtering (certificate-as-public,
  curve rules) works; registry lookup, dispatch and "did you mean" behave as in c2;
  `load_custom` derives key classes, `raw_ckm` and `param_struct` per c2 (AES/GENERIC →
  {SECRET}; `algorithm: none|other` rejected); FakeProvider's call-summary encoding
  matches c2 §4.10 (PINs redacted); the contract macro is green for FakeProvider in both
  presentations (`fake_memory`, `fake_pkcs11`), including the twin-guard, class-selector,
  same-provider re-entrancy and data/generic/certificate cases.

## R4 — Memory provider (L) — c2 L4 (+ L15/L16 memory parts)

The full `Provider` implementation over OpenSSL. It covers every §5.8–§5.10 mechanism
(including hand-rolled RSA-RAW with the public-key path, GMAC as GCM-over-AAD, CMAC, HMAC,
EdDSA/XDH), key generation, certificates and the cert-as-public-key rules, generic secrets
and data objects, the twin guard, and wrap/unwrap (AES-KW/KWP with both-dialect unwrap,
AES-CBC/AES-GCM, RSA-OAEP/PKCS1, RSA-AES-KEY-WRAP in c2's blob format) for copy and
`--kek`. Key material is zeroized on drop.

- **Owns**: `crates/r2-memory/src/lib.rs` and any private modules under
  `crates/r2-memory/src/`, `crates/r2-memory/tests/<topic>.rs` (including `contract.rs`).
- **Ports**: `providers/memory.py`; tests `unit/test_memory_provider`,
  `unit/test_memory_objects`, `unit/test_memory_wrap_kek`, and the MemoryProvider
  contract-instantiation row (88 ledger rows).
- **Provides**: `MemoryProvider` (§4.5.5). **Consumes**: R1, R3, R6 (`x509info`, `der`,
  `formats`, `crypto`).
- **Depends on**: R1, R3; R6 merge-order-only. Parallel with R5a and R7.
- **Accept**: `provider_contract_tests!(memory_contract, …)` is green. Every KAT is copied
  verbatim: SP 800-38A, GCM case 16, RFC 4493, RFC 3394, RFC 6979, RFC 8032, RFC 7748, the
  independent RFC 8017 PSS verify-KAT, RFC 4231, and the Utimaco PAD-dialect regression.
  Also: ECDSA r‖s conversion; GMAC equals GCM-over-AAD; HMAC equals RFC 4231; RSA-RAW
  works with private and public keys; the RSA-AES-KEY-WRAP blob is byte-compatible with
  c2's; round-trips pass for every advertised mechanism.

## R5a — PKCS#11 provider: foundation (L) — first half of c2 L5

Everything in `Pkcs11Provider` except the crypto verbs. That covers the `Backend` seam and
its two implementations (`CryptokiBackend` over cryptoki 0.12 plus the `RawFns` unsafe
shim, and `FakeBackend`, a port of `fake_pykcs11.py`), the single CKR choke point
(§5.2 table), and the one audited `set_var` site (`env` applied before `C_Initialize`).
It also covers lazy init, slots/tokens, login/logout with `keep_pin`, auto-recovery vs
`AuthRequired`, `init_token`, the static catalog and symbol tables, template conversion
with material injection (EC point DER, RSA CRT set, SENSITIVE/EXTRACTABLE injection), the
object read path (CKO_DATA, `other`, symbolic CKK, certificates through `x509info`),
import/generate/delete/export, identity resolution (`--id` > template row > random), the
twin guard, CKM folding, custom ckm→id merge, the advisory EdDSA probe (capability), and
`find_softhsm_module`.

- **Owns**: `crates/r2-core/src/catalog.rs` (from R0),
  `crates/r2-pkcs11/src/{lib,catalog,softhsm,env,ckr,attributes,capability}.rs`,
  `crates/r2-pkcs11/src/backend/{mod,cryptoki,raw,fake}.rs`,
  `crates/r2-pkcs11/src/provider/{mod,objects}.rs`, `crates/r2-pkcs11/src/tests/mod.rs`
  and R5a's `crates/r2-pkcs11/src/tests/<topic>.rs` files, and R5a's SoftHSM integration
  tests `crates/r2-pkcs11/tests/<topic>.rs` (feature `softhsm`).
- **Ports**: the foundation parts of `providers/pkcs11/provider.py`, all of
  `providers/pkcs11/{attributes,softhsm}.py`, the folding/merge/probe parts of
  `mechanisms.py`, and `tests/support/fake_pykcs11.py`; tests `unit/pkcs11/{test_attributes,
  test_provider_session, test_softhsm_detect}`, the non-verb parts of
  `unit/pkcs11/{test_objects, test_provider_objects}`, and the foundation classes of
  `integration/test_pkcs11_provider` (120 ledger rows incl. the folding/probe/custom-merge cases moved from R5b).
- **Provides**: `Pkcs11Provider::new` (custom mechanisms and attributes injected at
  construction), `Pkcs11Provider::init_token` / `TokenInit`, `find_softhsm_module`,
  `CKA_CATALOG` (`r2_core::catalog`, re-exported at `r2_pkcs11::catalog`), and the
  crate-private `Backend`/`FakeBackend` for R5b. **Consumes**: R1, R2
  (`Pkcs11InstanceConfig`, `CustomAttributeDef`), R3, R6.
- **Depends on**: R1, R2, R3, R6. Parallel with R4 and R7.
- **Accept**:
  - FakeBackend tests cover the session lifecycle, login states (keep-pin recovery vs
    `AuthRequired`, `AlreadyLoggedIn`), the CKR → ErrorKind mapping for every §5.2 row,
    disabled-attribute omission, material attribute sets, identity precedence and
    conflicts, twin refusal and exact-handle re-targeting, CKO_DATA/`other` listing,
    custom ckm→id advertisement, and that unknown CKMs survive the unfiltered mechanism
    list.
  - The `unsafe` sites are exactly the four of §4.1.3, each with a `// SAFETY:` comment.
    No cryptoki type appears in a `pub` item.
  - On SoftHSM: login, generate AES and an RSA keypair (template applied), and import
    every object kind (AES, RSA, EC, Ed25519, certificate, generic, data).

## R5b — PKCS#11 provider: crypto, wrap, derive, edit (L) — second half of c2 L5 (+ L8/L14/L15/L16 provider parts)

The provider's verbs with c2's software fallbacks:
- ECB with PKCS#7, non-SHA1 OAEP over raw RSA, CMAC/HMAC truncation, bare-ECDSA prehash,
  DigestInfo, public-key RSA-RAW;
- derive with the resident fallback (handle-only `DeriveResult` on template-rejecting
  tokens);
- wrap/unwrap with the KWP preference, both dialects, and the CKA_VALUE_LEN
  inject-and-retry, plus the AES-CBC/AES-GCM/RSA-PKCS1 wrap branches;
- `RSA-AES-KEY-WRAP` advertised only per spec §11 D6's resolution;
- `read_key_template`, `update_key` (per-attribute outcomes, `CKR_ATTRIBUTE_READ_ONLY`),
  `read_full_template`;
- the five custom `param_struct` packers and `MechanismInvocation → MechSpec`.

- **Owns**: `crates/r2-pkcs11/src/provider/{crypto,wrap,edit}.rs`,
  `crates/r2-pkcs11/src/mechanisms.rs`, R5b's `crates/r2-pkcs11/src/tests/<topic>.rs`
  files (appending their `mod` lines to `src/tests/mod.rs`; may extend `backend/fake.rs`,
  both after R5a merged), `crates/r2-pkcs11/tests/contract_softhsm.rs`, and R5b's SoftHSM
  integration tests `crates/r2-pkcs11/tests/<topic>.rs`.
- **Ports**: the remaining `providers/pkcs11/provider.py` (verbs, wrap, derive, edit),
  and the packers and invocation mapping of `mechanisms.py`; tests
  `unit/pkcs11/{test_mechanisms, test_provider_edit, test_wrap_kek}`, the verb, wrap,
  derive, custom-mechanism and full-template cases of
  `unit/pkcs11/{test_objects, test_provider_objects}`, the crypto classes of
  `integration/test_pkcs11_provider`, the provider-level cases of
  `integration/test_objects_softhsm`, and the Pkcs11Provider@SoftHSM contract
  instantiation (84 ledger rows after the moves to R5a).
- **Provides**: the complete `Pkcs11Provider` (the ten `*_impl` delegations of §4.5.5
  filled). **Consumes**: R5a (crate-internal), R1, R3, R6.
- **Depends on**: R5a. Parallel with R8, R9, R11 and R12.
- **Accept**:
  - FakeBackend tests cover packer bytes, advertisement and folding of verbs, each
    software fallback, KWP preference, CKA_VALUE_LEN retry, and every `update_key`
    outcome.
  - On SoftHSM (2.6.1 and 2.7.0): CBC/GCM round-trips, PKCS1v15/PSS/ECDSA/EdDSA/HMAC
    sign-verify, wrap/unwrap (KW/KWP/RSA hard-asserted; CBC/GCM tolerated where CKF_WRAP
    is absent), derive, `update_key`, and `read_full_template`.
  - Montgomery curves assert c2's translated errors.
  - `provider_contract_tests!(pkcs11_softhsm, …)` is green.

## R6 — Key formats, X.509, DER and crypto helpers (M) — c2 L6

Pure `r2-core` format code over OpenSSL and `der`/`x509-cert`/`spki`. It covers
`parse_key_material` (PEM/DER/PKCS#8 plain and encrypted/traditional encrypted PEM/SPKI/
PKCS#12 incl. legacy RC2-3DES/CSR/X.509, password via callback), the self-signed cert
builder, the CSR builder signing through the provider callback (works for non-extractable
HSM keys), the RFC 4514 subject parser, PKCS#12 assembly, the certificate facts shared by
memory/pkcs11/services (`x509info`), export re-serialization (`formats`), EC OID/point
encodings and r‖s ↔ DER (`der`), and `ct_eq`/`random_bytes`/`ensure_legacy_provider`
(`crypto`). Fixtures are generated at test time; no key blobs are committed.

- **Owns**: `crates/r2-core/src/{keyparse,x509build,x509info,formats,der,crypto}.rs`,
  their tests in `crates/r2-core/tests/<topic>.rs` (e.g. `keyparse.rs`, `x509build.rs`).
- **Ports**: `core/{keyparse,x509build}.py`, `certops.certificate_details` /
  `ecdsa_rs_to_der`, and keyexport's pyca serializers (moved per spec §4.1.1); tests
  `unit/test_keyparse`, `unit/test_x509build`, the R6 cases of `test_l13_hardening`, and
  the moved `unit/services/{test_certops, test_keyexport}` cases (73 ledger rows incl. moved
  cases).
- **Provides**: §4.4.3–§4.4.8. **Consumes**: R1.
- **Depends on**: R1. Parallel with R2 and R3. Its mandated helper bodies (R0) let R3, R4,
  R5a and R7 call `crypto`/`der` helpers before R6 merges.
- **Accept**:
  - Per-format parse round-trips pass, including hex-wrapped PEM and hint mismatches.
  - Wrong password or garbage input → `KeyParse` with c2's texts.
  - PKCS#12 multi-material output shares one label.
  - A CSR built through a software sign callback verifies under OpenSSL for RSA, ECDSA
    (r‖s → DER) and Ed25519.
  - The self-signed cert has subject == issuer == CN and CA:FALSE.
  - PKCS#12 output reloads.
  - A legacy PKCS#12 fixture (generated at test time with `openssl pkcs12 -legacy`)
    parses, or reports c2's message when the legacy provider is absent.
  - The disallowed OpenSSL APIs (§4.1.3) are not used.

## R7 — Console shell, framework, ParamResolver, CLI bootstrap (L) — c2 L7

The REPL and the framework every command plugs into:
- `LineIo` with `TerminalIo` (reedline 0.49 + rpassword: dropdown completion, history
  hints, highlighting, bracketed paste) and `PlainIo` (non-TTY / `TERM=dumb` /
  degraded), the history wrapper that drops `--pin`/`--password` lines, and the Sink and
  color policy;
- the tokenizer and binder (caret positions, flags-vs-value options), the grammar-aware
  completer and the shared `cmdutil` helpers, c2's `…>` continuation, and the `catch_unwind`
  panic path;
- `ParamResolver` (`r2_ops::params`, one code path for inline and prompted), command
  discovery via `build.rs`, `help`, `config`, `clear` and `exit`, and the in-crate test
  support `r2_console::testing`;
- the `r2` binary: clap args, logging with size rotation and redaction, the panic hook,
  the ctrlc handler, `build_provider_registry` (SoftHSM autodetect, custom CKM map) and the
  startup order of §4.9.11.

- **Owns**: `crates/r2-ops/src/params.rs`, `crates/r2-ops/tests/params.rs`;
  `crates/r2-console/build.rs` (from R0),
  `crates/r2-console/src/{lib,context,repl,parser,completer,render,cmdutil,testing}.rs`,
  `crates/r2-console/src/io/{mod,line,plain,terminal,history,assist}.rs`,
  `crates/r2-console/src/commands/{mod,help,misc}.rs`,
  `crates/r2-console/src/tests/build_discovery.rs` (from R0) and R7's
  `crates/r2-console/src/tests/<topic>.rs` files;
  `crates/r2-cli/src/{main,args,bootstrap,logging,panic}.rs` (`main.rs` from R0),
  `crates/r2-cli/tests/e2e_repl.rs` (+ R7's other `crates/r2-cli/tests/*.rs`, and any
  `insta` snapshots under them).
- **Ports**: `app.py` (minus `build_operation_registry`), `__main__.py`,
  `logging_setup.py`, `ops/params.py`, `console/{io,repl,parser,completer}.py`,
  `console/render.py` (Sink/color policy; the renderer is R1's),
  `console/commands/{__init__,help_cmd,misc_cmd}.py`; tests
  `unit/console/{test_app, test_commands, test_completer, test_discovery, test_io,
  test_logging_setup, test_parser, test_render, test_repl}` (minus the cases moved to R1
  and R3), `unit/test_params`, `unit/test_smoke` (CLI part), and the R7 cases of
  `test_l13_hardening` (150 ledger rows after the moves).
- **Provides**: §4.6.4, §4.9.4–§4.9.7, the §4.9.9 completer and `cmdutil` helpers (used
  by R8–R11, R14, R15), §4.9.11, and §4.10.6 (`make_config`, `make_providers`,
  `CtxBuilder`, `run_line`). **Consumes**: R1, R2 (`load_config`, `LoadedConfig`), R3
  (registries, FakeProvider), R4/R5a/R6 (bootstrap only).
- **Depends on**: R1, R2, R3; merge-order-only on R4, R5a and R6.
- **Accept**:
  - Tokenizer and binder tables pass, including caret positions (byte offsets).
  - ParamResolver behaves the same inline and prompted (defaults, `default_from`, ENUM
    choices, `UserAbort` → `Aborted.`).
  - `LineIo` tests run over a scripted `LineReader` (`Line`/`Interrupted`/`Eof`).
  - Piped REPL sessions via `assert_cmd` (PlainIo) cover help, exit, the unknown-command
    suggestion and quoted multiline PEM paste.
  - `config path` and `config show --origin/--defaults` render provenance.
  - The history filter drops secret lines.
  - `--version`, `--config`, `--debug` (backtrace) work, and a panic inside a command
    renders `unexpected error: …` and is logged.
  - The log-file rules of §4.9.11 hold (`max_bytes: 0`, `backups: 0`, unwritable path →
    Config error).
  - Bootstrap registers the real providers and config-defined custom ops, and passes the
    ckm→id map to `Pkcs11Provider`.
  - The identity template editor is active while R10's editor is a stub.

## R8 — Provider & key commands + keyload/keyexport/certops (L) — c2 L8 (+ `key edit`, L16 console parts)

The commands `providers`, `slots`, `login` (with the §5.13 wizard trigger through R11's
surfaces), `logout`, `keys [<provider>] [<filter>]`, `key info`, `key edit`, `generate`,
`load`, `export`, `csr` and `delete`, plus the orchestration services: `keyload`
(material parsing, label resolution, editor seeding through `EditorSeeding`, verbatim
`generic`/`data` hints), `keyexport` (format selection, `--public`, password guard,
non-exportable refusal) and `certops` (PKCS#12 export with an on-the-fly self-signed
cert, CSR flow through the provider sign callback). Template editing goes through
`ctx.template_editor`. `key template` and `--kek` are delegated to the R14/R15 hooks.
`--template` is parsed through `cmdutil::parse_seed_templates`.

- **Owns**: `crates/r2-console/src/commands/{providers,keys}.rs`,
  `crates/r2-services/src/{keyload,keyexport,certops}.rs`,
  `crates/r2-services/tests/{keyload,keyexport,certops}.rs` (+ R8-prefixed topics),
  `crates/r2-console/src/tests/{providers_cmd,keys_cmd,keys_cmd_objects}.rs` (+ other R8
  topics), `crates/r2-cli/tests/e2e_console_keys.rs`.
- **Ports**: `console/commands/providers_cmd.py`, `console/commands/keys_cmd.py` (minus the
  `--kek` and `key template` paths), `services/{keyload,keyexport,certops}.py` (minus the
  parts moved to R6); tests `unit/console/{test_providers_cmd, test_keys_cmd,
  test_keys_cmd_objects}`, `unit/services/{test_keyload, test_keyexport, test_certops}`, the
  R8 cases of `unit/services/test_objects_services` and `test_l13_hardening`, and
  `integration/test_console_keys` (R8 cases) (187 ledger rows after the moves to
  R6).
- **Provides**: the §5.1 provider/key command surface; the ★ service surfaces of §4.9.10 that
  other loops consume (`keyload::resolve_label` → R15, `keyexport::write_output` → R14).
  **Consumes**: R2 (`default_template`), R4, R5a, R6, R7; calls R11's
  `token_needs_init`/`run_softhsm_wizard`, R14's `key_template::run` /
  `templatefile::{load_seed_file, build_seed}`, and R15's `kek::{run_load, run_export,
  complete_option_value, param_name_candidates}` (all present in the skeleton).
- **Depends on**: R4, R5a, R6, R7. Parallel with R5b, R9, R11 and R12.
- **Accept**: FakeProvider tests cover every command form and error path (not logged in,
  ambiguous ref → candidates, non-exportable, `--public` on a lone private,
  `--password` guard, p12 refusal before the prompt, missing cert → self-signed
  generated), the `keys` filter and `display_refs` suffixes, `key info` related refs and
  the handle row, every `key edit` flow (flags, editor diff, prompts, confirm-gated
  sibling rename), the ECDSA r‖s → DER CSR path, and completion. On SoftHSM, an
  end-to-end `login → generate → load → keys → export → csr` passes.

## R9 — Crypto commands (M) — c2 L9

`encrypt`, `decrypt`, `sign`, `verify`, `derive`, `ops`: one-line syntax, the mechanism
select list when omitted, ParamResolver prompting fallback, and DataInput/DataOutput
wiring (`--in`, `--out`, `--sig`, `--sig-file`, `--outformat`) with hex console
rendering.

- **Owns**: `crates/r2-console/src/commands/crypto.rs`,
  `crates/r2-console/src/tests/{crypto_cmd,console_crypto}.rs` (+ other R9 topics).
- **Ports**: `console/commands/crypto_cmd.py`; tests `unit/test_crypto_cmd`, the
  `ops`/`sign`/`verify` cases of `unit/console/test_keys_cmd_objects`, the R9 cases of
  `test_l13_hardening`, and `integration/test_console_crypto` (in-process over real
  providers, §4.10.6 `CtxBuilder::providers`) (54 ledger rows).
- **Provides**: the §5.1 crypto verb commands. **Consumes**: R4, R7 (R5 via the trait only).
- **Depends on**: R4, R7. Parallel with R5b, R8, R11 and R12.
- **Accept**: positional-2 mechanism-vs-data disambiguation (quoting forces data), the
  select fallback, file in/out and `--outformat`, verify's signature sources and its
  public-half/certificate fallback, derive's resident-key rendering, `ops` capability
  filtering (probe families incl. GENERIC), and path completion. Memory-provider command
  round-trips for AES-GCM and RSA-PSS pass.

## R10 — Template editor & copy (M/L) — c2 L10 (+ the L16 data-copy route)

The checklist template editor (§5.12) behind the frozen `create_template_editor` factory.
It is a mini-REPL: toggle/set/±/add/ok/cancel, locked rows, `add` from `CKA_CATALOG` and
custom attributes, and the identity-row note. Plus `copy` (§5.5) and
`services::transfer`:
- the decision matrix on `type_name` and auth-then-ladder pre-probe;
- the transport-key protocol with a `Drop` guard that destroys and zeroizes on success
  and on failure;
- the ephemeral-RSA fallback, the RSA-AES-KEY-WRAP single shot and the plain-read last
  resort;
- the wrappable-vs-exportable rule (sensitive-but-extractable wraps);
- the data-object plain route with seeding, and the `other` refusal;
- the confirm-then-raise refusal UX and the label/CKA_ID defaults (cross-token copies
  keep the source id).

- **Owns**: `crates/r2-console/src/template_editor.rs`,
  `crates/r2-console/src/commands/copy.rs`, `crates/r2-services/src/transfer.rs`,
  `crates/r2-console/src/tests/{template_editor,copy_cmd}.rs` (+ other R10 topics),
  `crates/r2-services/tests/transfer*.rs` (the in-process memory ⇄ SoftHSM suites
  included, via the r2-services ⇢ r2-memory/r2-pkcs11 dev edges).
- **Ports**: `console/template_editor.py`, `console/commands/copy_cmd.py`,
  `services/transfer.py`; tests `unit/console/test_template_editor`,
  `unit/console/test_copy_cmd`, `unit/test_transfer`, the copy cases of
  `unit/console/test_keys_cmd_objects` and `unit/services/test_objects_services`, the
  editor case of `integration/test_console_keys`, `integration/test_copy`, and the
  `copy_key` legs of `integration/test_objects_softhsm` (80 ledger rows).
- **Provides**: the real `TemplateEditor` via `create_template_editor`;
  `transfer::copy_key`; `copy`. **Consumes**: R2, R4, R5b, R7 (+ R14's seeding through
  `cmdutil`).
- **Depends on**: R2, R4, R5b, R7. Parallel with R14 and R15.
- **Accept**:
  - Editor tests use ScriptedIo: toggle, set, disable → attribute omitted, locked rows
    immutable, add via catalog/custom attributes, cancel → `UserAbort`.
  - Copy tests with two FakeProviders (`with_type_name("pkcs11")`) prove the transport
    key is destroyed on success and on failure, the sensitive-but-extractable wrap path,
    the ladder order, and the refusal UX (public-part offer, then `KeyNotExportable` on
    decline).
  - On SoftHSM: mem → SoftHSM, SoftHSM → mem and SoftHSM → SoftHSM copies of an
    extractable AES key give identical ciphertexts; generic (KWP), data and certificate
    copies work; a same-provider copy does not double-borrow.

## R11 — SoftHSM first-run wizard (M) — c2 L11

§5.13: conf and token-dir creation, `softhsm2.conf` writing, `SOFTHSM2_CONF` applied
before init (through the provider's env path), token init via
`Provider::as_token_init()` with a `softhsm2-util` fallback, PIN prompts (minimum length,
3 attempts, 32-byte label limit), provider registration, the config-append offer, and
the decline path.

- **Owns**: `crates/r2-console/src/wizard.rs`, `crates/r2-console/src/tests/wizard.rs`
  (+ other R11 topics), `crates/r2-cli/tests/e2e_wizard.rs`.
- **Ports**: `console/wizard.py`; tests `unit/console/test_wizard`, the real-wizard cases
  of `unit/console/test_providers_cmd`, and `integration/test_wizard` (30 ledger rows).
- **Provides**: `token_needs_init`, `run_softhsm_wizard`, `softhsm_conf_text`,
  `write_softhsm_conf`, `provider_config_entry`, `render_config_snippet`,
  `append_provider_entry` (§4.9.9). **Consumes**: R2 (`r2_config::yaml`), R5a
  (`find_softhsm_module`, `TokenInit`), R7.
- **Depends on**: R2, R5a, R7. Parallel with R5b, R8, R9 and R12.
- **Accept**: a ScriptedIo wizard run against a fresh temp token dir (its own
  `SOFTHSM2_CONF`, env changed only through `set_env` under `global_state_lock`) yields a
  working provider. Declining leaves memory-only operation intact. The generated conf file
  and the appended config entry match §5.13 byte for byte. The `softhsm2-util` fallback
  works. The e2e test spawns the binary with its own conf.

## R12 — Packaging & release (M) — c2 L12

Release builds per spec §9: vendored OpenSSL, `[profile.release]`, and the release
workflow over the target matrix with smoke tests and `SHA256SUMS`.

- **Owns**: `.github/workflows/release.yml`, `scripts/release/**`, the root
  `[profile.release]` table, the `vendored-openssl` lines of the `[features]` tables in
  `crates/r2-cli/Cargo.toml` and `crates/r2-core/Cargo.toml`.
- **Ports**: c2 `packaging/` and its release workflow (as the Rust equivalent); no ledger
  rows.
- **Provides**: native binary artifacts. **Consumes**: R7 (runnable binary).
- **Depends on**: R7 (most useful after R8/R9 merge). Parallel with R5b, R8, R9 and R11.
- **Accept**: the release matrix builds (x86_64/aarch64 linux-gnu on a glibc 2.28
  baseline, x86_64/aarch64 darwin, x86_64 windows-msvc). Every binary passes `--version`
  and a piped `help` / `providers` / `exit` session on all OSes. The Linux binary also
  runs in `rockylinux:8`. The vendored build has the legacy provider compiled in.
  `SHA256SUMS` is published. A manual-dispatch dry-run is green.

## R14 — Template files: `key template`, `--template` (M) — c2 L14

The §5.16 dump and seed. `services::templatefile` holds the per-kind YAML codec (kind
resolved by NAME via the catalog and custom attributes, never by value inference), the
`build_seed` policy (CKA_CLASS/CKA_KEY_TYPE flow-locked; CKA_LABEL/CKA_ID and
`NON_CREATION_ATTRS` disabled on seed; per-section `default_template` fallback),
`dump_template_file`, `load_seed_file` and `EditorSeeding`. The `key template <ref>
<path>` hook command is pkcs11-only and prints the key-material note.

- **Owns**: `crates/r2-services/src/templatefile.rs`,
  `crates/r2-console/src/commands/key_template.rs`,
  `crates/r2-services/tests/templatefile.rs`, R14's
  `crates/r2-console/src/tests/<topic>.rs` files (e.g. `key_template.rs`,
  `template_seed.rs`).
- **Ports**: `services/templatefile.py` and the `key template`/`--template`/`seed_templates`
  paths of `keys_cmd.py`, `copy_cmd.py`, `keyload.py` and `transfer.py`; tests
  `unit/services/test_templatefile`, and the template-file cases of
  `unit/console/{test_keys_cmd, test_copy_cmd}`, `unit/services/{test_keyload,
  test_wrapload}`, `unit/test_transfer` and `integration/test_console_keys` (30 ledger
  rows).
- **Provides**: `SeedTemplates`, `NON_CREATION_ATTRS`, `dump_template_file`,
  `load_seed_file`, `build_seed`, `EditorSeeding` (real bodies replace R0's mandated
  ones), and `commands::key_template::run`. **Consumes**: R2 (`r2_config::yaml`,
  `TemplatesSection`), R5b (`read_full_template`), R7, R8.
- **Depends on**: R5b, R7; R8 merge-order-only. Parallel with R10 and R15.
- **Accept**: codec round-trips (symbolic ULONG, `0x…` bytes, a hex-looking STR label);
  the seeding policy; command and service seeding tests on FakeProvider; FakeBackend
  full-read with the refused-attribute skip; a SoftHSM dump → reseed round-trip. **A
  file dumped by c2 seeds r2, and vice versa.**

## R15 — Wrapped-key load & export, `--kek` (M/L) — c2 L15

Both directions of one blob format: `load --kek` (§5.4) and `export --kek` (§5.6).
`services::wrapload` holds the six-row direction-aware wrap-mechanism table
(kw/kwp/cbc/gcm/oaep/pkcs1 over synthetic OperationSpecs fed by ParamResolver), KEK
resolution (same-provider rule, §4.3 selectors, keypair → PRIVATE collapse, `:pub` hint),
candidate selection, `load_wrapped` (editor seeded from the result class/algorithm) and
`wrap_for_export` (the wrappable rule: CKA_EXTRACTABLE alone). `commands::kek` fills in
R8's hooks, including `--kek`/`--mech`/`--outformat`/param completion, with
raw/hex/b64 I/O through DataInput/DataOutput.

- **Owns**: `crates/r2-services/src/wrapload.rs`, `crates/r2-console/src/commands/kek.rs`,
  `crates/r2-services/tests/wrapload.rs`,
  `crates/r2-console/src/tests/{load_kek,export_kek}.rs` (+ other R15 topics), and R15's
  SoftHSM e2e test file (e.g. `crates/r2-console/src/tests/load_kek_softhsm.rs`).
- **Ports**: `services/wrapload.py` and the `--kek` paths of `keys_cmd.py`; tests
  `unit/services/test_wrapload`, `unit/console/{test_load_kek, test_export_kek}`, the
  `--kek` cases of `unit/services/test_objects_services`, and `integration/test_load_kek`
  (108 ledger rows).
- **Provides**: `wrapload::{Direction, WrapMechEntry, wrap_mechs, result_by_hint,
  resolve_kek, candidates, resolve_mech, select_mech, UnwrapJob, load_wrapped,
  refuse_non_wrappable, wrap_for_export}` and `commands::kek::{run_load, run_export,
  complete_option_value, param_name_candidates}`. **Consumes**: R4, R5b, R7, R8.
- **Depends on**: R4, R5b, R7; R8 merge-order-only. Parallel with R10 and R14.
- **Accept**:
  - Per-direction table, KEK resolution and selection tests run on FakeProvider +
    ScriptedIo.
  - Command tests cover every form, error path (including c2's auth-first probe order)
    and completion.
  - A sensitive-but-extractable key wraps while plain export refuses it.
  - Export → load round-trips pass in raw, hex and b64.
  - SoftHSM e2e: KW/KWP/RSA hard-asserted, CBC/GCM tolerated where CKF_WRAP is absent.
  - **c2-exported blobs load in r2, and vice versa.**

## R13 — Integration, parity sign-off & cutover (L) — c2 L13; runs alone, last

Cross-loop end-to-end scenarios, glue fixes, a consistency pass on messages and
rendering, the differential parity harness against c2@408d6f2 (transcript diff on the
memory provider, artifact interop for every file format, a shared SoftHSM token), the
coverage gate, folding recorded deviations back into spec.md, README, the lint flip and
the release candidate. It is the sole exception to the ownership rule: it owns everything,
because it is the only active loop.

- **Owns**: all files; adds `parity/harness/**`, `README.md`, the `coverage` and `parity`
  CI jobs, and the end-to-end suites.
- **Ports**: tests `integration/test_end_to_end`, `integration/test_custom_mechanism`
  (5 ledger rows); signs off the whole ledger.
- **Depends on**: R8, R9, R10, R11, R12, R14, R15 (that is, all loops).
- **Accept**:
  - Every STATUS row is `done`.
  - `python3 parity/generate_ledger.py --stats --gate all` reports zero `todo` rows.
  - The parity harness is green: transcript diff, artifact interop, and the shared-token
    run in both directions.
  - Line coverage ≥ 80% via `cargo llvm-cov`.
  - `clippy::todo`/`unimplemented` are flipped to deny, and no stub remains.
  - An e2e on SoftHSM passes: load a PEM RSA key into mem → copy to SoftHSM → sign PSS →
    verify in mem → export p12 (self-signed) → csr.
  - The custom-mechanism config test passes (the entry appears in `ops`, dispatches, and
    prompts its params).
  - The manual terminal checklist is done on macOS, Linux and Windows Terminal (including
    pasting a traditional encrypted PEM at the `| ` prompt).
  - All CI jobs are green, including a release dry-run.
  - Spec deviations are folded back (§4/§5/§11).
