# r2 — Specification

Interactive console application for cryptographic operators: load, generate, copy and export
keys across cryptographic providers (in-memory and PKCS#11), and perform AES/RSA/EC
operations with them. r2 is the Rust rewrite of c2 and is held to full behavioral parity with
it; every intentional difference is listed in §11.

This document is the single source of truth for the implementation. It is split into:

- **§4 Frozen contracts** — *normative*. Exact Rust signatures, crate and module paths,
  schemas. Implementation agents working in separate contexts code against these anchors
  ("spec §4.5"). R0 materializes all of §4 as a compiling skeleton, so every loop builds
  against the real signatures from day one; merge-order edges gate *merging*, not
  development. Changing anything in §4 requires the procedure in §4.11.
- **§11 Deviations from c2** — *normative*. The closed list of intentional, observable
  differences from c2. **Anything observable that differs from c2 and is not listed in §11
  is a parity bug.**
- **Everything else** — behavioral requirements and reference material. May be refined
  during implementation without cross-loop breakage, as long as §4 and §11 are honored.
  User-visible texts quoted in this spec (messages, hints, prompts, table headings, file
  comments) are part of the compatibility contract and are reproduced verbatim, with `c2` →
  `r2` substituted only where the text names the tool, its files or its directories (§11 D7).

Companion documents: `loops.md` (STATUS table, loop cards, working agreement), `CLAUDE.md`
(agent operating manual: Rust conventions, commands, done gate), `PLAN.md` (the approved
rewrite plan — technology choices, loop decomposition, decisions; superseded by this spec
where they differ), `parity/ledger.csv` (every c2 test mapped to the one R-loop that ports
it; rules and generator in `parity/README.md`).

**Reference implementation.** c2 lives at `/home/user/c2` (upstream
[`adipata/c2@408d6f2`](https://github.com/adipata/c2/commit/408d6f29aa968ad4afcd7888b5958ba4608c902c),
2026-08-21, L0–L16 done) and is **frozen at 408d6f2** for the duration of the rewrite
(PLAN §11). References of the form "c2 §5.5" point into c2's `spec.md`; a bare "§5.5"
points into this document, whose §1–§10 numbering deliberately mirrors c2's so that
section references stay valid across both. Where this spec is silent on a detail, c2's
source and tests at 408d6f2 are authoritative for behavior (ported verbatim with c2 → r2
naming); only §11 may override them. If c2 must change during the rewrite (for example a
field fix from a real HSM), the same change adds a §11 row (or a `loops.md` note) and a
parity-ledger entry here, so the two cannot silently diverge.

---

## 1. Overview & goals

`r2` is a Rust terminal application (edition 2024, pinned stable toolchain = MSRV),
shipped as one native binary named `r2`. An operator starts it, gets a REPL (`r2>` prompt),
and works with **providers**:

- **memory** — volatile, always present; backed by the `openssl` crate (OpenSSL 3,
  statically linked and vendored in release builds). Keys vanish on exit (and are zeroized
  on drop, §6).
- **pkcs11** — zero or more instances defined in configuration, each wrapping a vendor
  PKCS#11 library (HSM, smartcard, SoftHSM2) loaded by path at runtime through the
  `cryptoki` crate. Persistent, login-gated.
- A locally installed **SoftHSM2** is auto-detected and offered as a preconfigured pkcs11
  provider (first-run wizard initializes a token), giving persistence out of the box.

v1 capabilities (identical to c2's — the rewrite ports the final c2 spec, L0–L16, not its
history):

1. List providers and their login state; login/logout to PKCS#11 tokens.
2. Generate AES/RSA/EC keys and generic secrets (HMAC keys) in any provider (PKCS#11:
   attribute template editor shown first).
3. Load keys from pasted hex/base64/PEM data or from files (PKCS#8, traditional OpenSSL,
   SPKI, PKCS#12, CSR, X.509). Certificates are first-class objects usable as public keys.
4. Copy keys between providers — via wrap/unwrap with ephemeral transport keys when the
   source is a PKCS#11 token.
5. Export keys to files (AES raw, RSA/EC PKCS#8/SPKI, PKCS#12 with on-the-fly self-signed
   certificate); generate CSRs, including for non-extractable HSM keys.
6. Encrypt/decrypt, sign/verify, derive — AES (ECB/CBC/GCM/CTR, CMAC/GMAC), HMAC over
   generic secrets, RSA (OAEP/PKCS#1 v1.5/RAW/PSS), EC (ECDSA/EdDSA/ECDH/X25519/X448).
7. Extensible operation list: config-defined vendor PKCS#11 mechanisms appear as regular
   operations with prompted parameters, no code changes.
8. Data objects (CKO_DATA): load/export/copy/delete opaque values; `keys` lists every
   object class, including key types r2 cannot operate on (shown as `other`) (c2 L16).

Rewrite goals (PLAN §1), in priority order:

1. **Parity.** Command grammar, ref grammar, messages and hints, config schema and merge
   semantics, PKCS#11 object layouts and every data file format (exports, wrapped blobs,
   template YAML) are identical to c2. Tokens are shared freely: objects created by either
   implementation are fully usable by the other on the same token. A c2 config file works in
   r2 once renamed to `r2.yaml` (and its `c2` paths edited), except for the load-time range
   checks and YAML parser-level details of §11 D17/D18. c2 and r2 install side by side and
   share no config/state files by default (§11 D7).
2. **One native binary** with instant startup and no interpreter (c2: ~18 MiB PyInstaller
   one-file).
3. **Memory safety at the PKCS#11 FFI boundary**: the safe `cryptoki` API everywhere except
   a small, enumerated `unsafe` budget (§3.1).
4. **Real zeroization** of key material, PINs, passwords and transport keys (§11 D3).
5. **Compile-time enforcement** of the architecture: the crate graph *is* the layer graph
   (§3.1), and `!Send`/`!Sync` providers make the single-thread invariant (§6) a type error
   to violate.

Non-goals for v1: batch/non-interactive scripting mode, additional provider types (cloud
KMS), bundling SoftHSM2 inside the binary (deferred; see §10), CKU_SO workflows beyond
token initialization — and **no new features of any kind before parity sign-off** (M3,
PLAN §11). Improvements are allowed only where Rust gives them for free without changing
observable behavior, or where §11 records them.

Distribution: a single native binary per platform, built with `cargo build --release`
against a vendored, statically linked OpenSSL (§9); source builds via cargo.

## 2. Glossary

| Term | Meaning |
|---|---|
| provider | A named key store + crypto engine instance (`mem`, `softhsm`, `prodhsm`), implementing the `Provider` trait (§4.5) |
| token / slot | PKCS#11 concepts: a slot holds (at most) one token; login targets one token |
| session | A PKCS#11 session on a slot; lives inside the provider instance (`RefCell<Option<cryptoki::session::Session>>`), one per provider at a time |
| mechanism (canonical name) | Provider-independent algorithm identifier, e.g. `AES-GCM` (§4.6). Maps to an OpenSSL construct (memory) and/or a `CKM_*` code (pkcs11) |
| operation | A (verb, mechanism, parameter-schema) triple registered in the `OperationRegistry`, e.g. `aes.encrypt.gcm` |
| verb | One of encrypt / decrypt / sign / verify / derive — the stable crypto entry points |
| template | Ordered list of PKCS#11 attributes (`CKA_*`) applied when creating an object; editable in the checklist editor |
| transport key | Ephemeral key used only to wrap another key during a copy between providers |
| wrap / unwrap | Encrypting a key with another key so it can leave/enter a token without plaintext exposure |
| KAT | Known-answer test (fixed vectors from NIST CAVP / Wycheproof / RFCs) |
| crate | A Cargo package of the r2 workspace (`r2-core` … `r2-cli`, `r2-testkit`); the unit of layering (§3.1) |
| `ConsoleError` / `ErrorKind` | r2's single error type: `{ kind, message, hint }`, where the `ErrorKind` variant replaces c2's exception subclass and carries its extra fields (§4.2). Every fallible public fn returns `r2_core::Result<T>` |
| backend seam | The crate-private `trait Backend` inside `r2-pkcs11`: ~25 raw-shaped PKCS#11 calls (u64 CKM codes, `(CK_ATTRIBUTE_TYPE, bytes)` templates, `MechSpec` mechanisms, raw CKR errors). Implemented by `CryptokiBackend` (real) and `FakeBackend` (tests) |
| CKR choke point | The single place (`CryptokiBackend` + r2-pkcs11's `crate::ckr::translate`) where every cryptoki/RawFns failure becomes a `Ckr { code, function }` value (names looked up in PyKCS11's table, §4.5.5) and is translated per §5.2 |
| `RawFns` | r2-pkcs11's narrow `unsafe` shim: a second `dlopen` of the same module plus its `CK_FUNCTION_LIST`, used only where the safe cryptoki API is unsound or lossy (unfiltered mechanism list, token info without `utcTime` parsing, single-attribute reads, raw-parameter crypto, truncating `C_WrapKey`) |
| `MechSpec` | r2-owned enum describing one PKCS#11 mechanism invocation; mapped to cryptoki per the normative table in §5.8–§5.10 |
| TerminalIo / PlainIo | The two `ConsoleIo` implementations, chosen once by `r2_console::io::open_console_io`: `LineIo<DegradingReader>` (reedline + rpassword on an interactive terminal; a terminal that stops answering degrades to plain reads inside it) and `LineIo<PlainReader>` (line reads from stdin when stdin or stdout is not a terminal, or `TERM=dumb`). See §6 |
| `LineReader` / `LineIo` | Console-internal reader trait (`Line` / `Interrupted` / `Eof` outcomes) and the one generic type holding all prompt/select/confirm logic over it |
| `Renderable` | The closed enum of printable things (`Text`, `Styled`, `Table`, `Hex`, `Panel`) passed to `ConsoleIo::print` (§4.9) |
| parity ledger | `parity/ledger.csv`: every c2 test (1,284 rows / 1,600 node IDs at 408d6f2) with its owning R-loop and port status |
| differential harness | `parity/` (R13): runs identical piped sessions and file round-trips through c2 and r2, and both against one shared SoftHSM token |
| deviation | An intentional, recorded difference from c2 (§11, `D<n>`) |
| loop | A unit of implementation work with exclusive file ownership (`S0`, `R0`–`R15`, `R5a`/`R5b`); see `loops.md`. c2's loops are cited as `c2 L<n>` |
| c2 | The Python reference implementation, frozen at 408d6f2 |

## 3. Architecture

### 3.1 Crate map & dependency rules

Cargo workspace; binary `r2` (crate `r2-cli`). Every crate is `r2-*`; library crates are
imported as `r2_core`, `r2_config`, …. Layout (frozen in detail in §4.1):

```
r2/
  Cargo.toml                 workspace; [workspace.lints]; shared dependency versions
  rust-toolchain.toml        pinned stable (= MSRV), edition 2024
  clippy.toml  deny.toml  justfile
  .github/workflows/ci.yml  release.yml
  scripts/softhsm-init.sh    SoftHSM test-token bootstrap (§8)
  crates/
    r2-core/        error, text, keys (model + ref grammar), template, params, io (ConsoleIo,
                    TemplateEditor, Renderable), render, runtime, codec, datainput,
                    catalog (CKA_CATALOG), keyparse, x509build, x509info, formats, der, crypto
    r2-config/      model, loader, defaults.yaml (include_str!; §7)
    r2-provider/    Provider trait + data types, ProviderRegistry, shared helpers (rsa_raw_modexp)
    r2-ops/         OperationSpec, OperationRegistry, builtins (aes/rsa/ec/generic), custom,
                    ParamResolver
    r2-memory/      MemoryProvider (openssl)
    r2-pkcs11/      Pkcs11Provider, backend seam (CryptokiBackend + RawFns, FakeBackend),
                    capability (CKM folding), mechanisms (packers), catalog (PyKCS11
                    CKO/CKK/CKC/CKM/CKR name tables + CKA_CATALOG re-export), softhsm
    r2-services/    keyload, keyexport, certops, transfer, templatefile, wrapload
    r2-console/     repl, io (open_console_io, TerminalIo/PlainIo/LineIo, Sink), parser,
                    completer, render, commands/ (build.rs-discovered), template_editor, wizard
    r2-cli/         the `r2` binary: args (clap), logging, bootstrap, Ctrl-C handler, panic hook
    r2-testkit/     (dev-dependency only) ScriptedIo, FakeProvider, provider_contract_tests!,
                    softhsm_token() fixture
  parity/           ledger.csv + generator; differential harness vs c2 (R13)
  spec.md  loops.md  CLAUDE.md  README.md  PLAN.md
```

Crate dependency graph — c2 §3.1's layer graph made structural. A crate can only use the
crates its `Cargo.toml` declares, so code that crosses an edge not listed for it does not
compile; Cargo rejects cycles; adding an edge or a third-party dependency is a §4.11-level
change, not a review call. **The normative edge list, the per-crate third-party dependency
table and the restricted-crate table are §4.1.2; the lint, `unsafe` and naming rules are
§4.1.3.** This subsection is a summary of them:

```
r2-cli      → r2-console, r2-memory, r2-pkcs11, r2-ops, r2-provider, r2-config, r2-core
r2-console  → r2-services, r2-ops, r2-pkcs11 (only softhsm::find_softhsm_module),
              r2-provider, r2-config, r2-core
r2-services → r2-ops, r2-provider, r2-config, r2-core
r2-ops      → r2-provider, r2-config, r2-core
r2-memory   → r2-provider, r2-core
r2-pkcs11   → r2-provider, r2-config, r2-core
r2-provider → r2-core
r2-config   → r2-core
r2-core     → third-party only
r2-testkit  → r2-provider, r2-core; a dev-dependency only, never a normal dependency
(dev-only: r2-services ⇢ r2-memory, r2-pkcs11; r2-console ⇢ r2-memory)
```

Rules (summary of §4.1.2/§4.1.3):

- **cryptoki is confined to `r2-pkcs11`.** `cryptoki =0.12.1`, `cryptoki-sys =0.5.0` and
  `libloading` are dependencies of `r2-pkcs11` only, and no cryptoki type appears in its
  public API (c2's "PyKCS11 only inside `providers/pkcs11/`", enforced by the compiler).
  Inside `r2-pkcs11`, cryptoki calls are made only by the backend module (`CryptokiBackend`
  + `RawFns`); the provider logic above the seam (identity resolution, twin guard, CKM
  folding, software fallbacks, auto-recovery) is backend-agnostic and unit-tested against
  `FakeBackend`. Its only public modules are `catalog` (the PyKCS11 name tables) and
  `softhsm`.
- **The catalog is importable without r2-pkcs11.** `CKA_CATALOG` lives in
  `r2_core::catalog` (re-exported as `r2_pkcs11::catalog::CKA_CATALOG`) — the counterpart of
  c2's PyKCS11-free `attributes.py` — so `r2-testkit` (FakeProvider), `r2-services`
  (templatefile) and `r2-console` (template editor `add`) use it without an r2-pkcs11 edge.
  `r2-services` has no `r2-pkcs11` edge at all; `r2-console` uses only
  `softhsm::find_softhsm_module`, and the wizard reaches token initialization through
  `Provider::as_token_init()` (`r2_provider::TokenInit`, §4.5.2), never a pkcs11 type.
- **Nothing depends on `r2-console` except `r2-cli`.** `r2-config`'s model types are
  importable from any crate (c2's `config/model.py` rule); `load_config` is called only by
  `r2-cli` (review rule).
- **Interaction traits and the renderer live in `r2-core`.** `ConsoleIo`, `TemplateEditor`
  and `Renderable` are defined in `r2_core::io`, and `render`/`render_plain` in
  `r2_core::render` (comfy-table, anstyle; comfy-table's
  default `tty` feature pulls crossterm in transitively, but r2-core does no terminal I/O).
  The reedline/rpassword/crossterm/indicatif implementations, the Sink and the
  TerminalIo/PlainIo switch (`r2_console::io::open_console_io`) live in `r2-console`.
  Interactive needs reach r2-core only through these traits or plain callbacks (e.g. the
  password callback of `keyparse`, §4.4).
- **Third-party crates** (pinned workspace-wide in §4.1.4; per-crate table in §4.1.2):
  `openssl` only in r2-core, r2-provider, r2-memory, r2-pkcs11 and r2-testkit (never
  r2-config, r2-ops, r2-services, r2-console, r2-cli — export serialization lives in
  `r2_core::formats`); `der`/`spki`/`x509-cert`/`const-oid` in r2-core only;
  `serde_yaml_ng` and `yaml-rust2` in r2-config only; reedline, crossterm, nu-ansi-term,
  rpassword, indicatif, console in r2-console only; clap, ctrlc, tracing-subscriber,
  regex in r2-cli only; `tracing` anywhere; `secrecy`/`zeroize` wherever
  secrets are handled. Any `cryptoki`/`cryptoki-sys` bump must re-run the S0 cryptoki
  spike checks (unfiltered mechanism list, `MechanismType` `repr(transparent)`, `wrap_key`
  truncation, `get_attributes` decoding).

Compile-time and lint enforcement of c2's CLAUDE.md conventions (workspace lints +
`clippy.toml`, normative text in §4.1.3; the done gate runs clippy with `-D warnings`):

| c2 convention | r2 enforcement |
|---|---|
| no `print()` (ruff T20) | `clippy::print_stdout` / `print_stderr` = deny. Allowed sites (each `#[allow]`ed): r2-cli `--version` and pre-REPL startup errors; r2-console's two one-line stderr warnings (`DegradingReader` fallback, mintty/msys hidden-input warning); `r2_testkit::contract::skip`. Console output goes through `std::io::Write` on the Sink, never the print macros |
| no ad-hoc threads (§6) | `disallowed-methods`: `std::thread::spawn`. Allowed exceptions: the indicatif ticker (only inside `busy()`) and the `ctrlc` handler thread, which touch nothing but their own state / one `AtomicBool`. Providers are `!Send`/`!Sync` (`Rc`/`RefCell` inside), so moving one to another thread does not compile |
| env mutation only before `C_Initialize` | `disallowed-methods`: `std::env::set_var`/`remove_var`, with exactly one audited production `#[allow]` site in `r2-pkcs11` (`crate::env::apply_env`; edition 2024 makes it `unsafe`; the single-thread invariant is the safety argument; the site asserts no spinner is active) and one test-only site, `r2_testkit::env` (`set_env` + `EnvGuard`, used under `global_state_lock()`; c2 `monkeypatch.setenv`/`delenv`) |
| no bare `except`; every raised error is a `ConsoleError` | every fallible public fn returns `r2_core::Result<T>`; `clippy::unwrap_used` / `expect_used` = deny outside tests (test exemption mechanism: §4.1.3); panics that still occur are caught per command (§5.1, §11 D4) |
| mypy strict | the compiler; `#![forbid(unsafe_code)]` in every crate except `r2-pkcs11` and the dev-only `r2-testkit` (`#![deny(unsafe_code)]` + audited `#[allow]`s) |
| PyKCS11 only in `providers/pkcs11/` | crate graph above; `disallowed-methods` for the lossy cryptoki APIs: `Pkcs11::get_mechanism_list` (drops unknown CKMs), `Pkcs11::get_token_info` (parses `utcTime`; fails on a token with CKF_CLOCK_ON_TOKEN and a non-digit clock), `Session::get_attributes` (fails whole calls / omits refusals), `Session::wrap_key` (no truncation) — use the `RawFns` equivalents |
| pyca hazards (S0 OpenSSL spike) | `disallowed-methods`: `PKey`/`Rsa`/`EcKey::private_key_from_pem` (prompt on the TTY), every `*_from_pem_passphrase` and `PKey::private_key_from_pkcs8_passphrase` (panic on NUL), `openssl::aes::wrap_key`/`unwrap_key` (deprecated, RFC 3394 only), `openssl::memcmp::eq` (panics on a length mismatch; allowed only inside `r2_core::crypto::ct_eq`) |
| terminal hazards (S0 terminal spike) | `disallowed-methods`: `std::io::IsTerminal::is_terminal` — it must not decide the TerminalIo/PlainIo switch (it accepts msys/mintty pipes on Windows); `crossterm::tty::IsTty` does. One allowed site: the mintty/msys warning in `r2_console::io::open_console_io` |
| skeleton stubs are temporary | `clippy::todo` / `unimplemented` = allow until R13, deny from R13 (allow, not warn: `-D warnings` would fail on the skeleton's stubs) |
| command auto-discovery (no central table) | `r2-console/build.rs` globs `commands/*.rs` and generates the module list and the aggregator; adding a command = adding a module |

**`unsafe` budget** (the complete list; anything else is a review blocker): production code, in `r2-pkcs11`
only — (1) `backend::raw` (`RawFns`: second `dlopen` of the module + `CK_FUNCTION_LIST`,
driven by `Session::handle()` / `ObjectHandle::handle()` values); (2) the `mech_type(ckm)`
transmute fallback, after a checked `CK_MECHANISM_TYPE::try_from` (sound because `cryptoki::mechanism::MechanismType` is
`#[repr(transparent)]` over `CK_MECHANISM_TYPE`); (3) the single audited `std::env::set_var`
site; (4) `obj(handle)` in `backend/cryptoki.rs`, the ONE `ObjectHandle::new_from_raw` call
through which every `Backend` method turns a `u64` handle into an `ObjectHandle` (handles
come from the module's own results or the operator's `@<handle>`, which the token
validates; no handle cache). Test-only (in the dev-dependency `r2-testkit`, never linked
into `r2`): (5) `r2_testkit::env` (`set_env` / `EnvGuard::drop`, the only way tests change
the environment, §4.10.1). Review rule for the safe-but-sharp `VendorDefinedMechanism::new`: it takes only `Sized`
`#[repr(C)]`/`#[repr(transparent)]` parameter structs from cryptoki/cryptoki-sys — passing
`&Vec<u8>`/`&String` compiles and silently sends the container header — and nested
pointers (e.g. `CK_RSA_AES_KEY_WRAP_PARAMS.pOAEPParams`) are built in the same stack frame
as the call.

### 3.2 Data flow

```
operator input line
  └─ r2-console::io           TerminalIo (reedline; QuoteValidator keeps quotes open)
  │                           | PlainIo (stdin lines)            → ReadOutcome::{Line,Interrupted,Eof}
  └─ r2-console::repl         run_repl: "…> " continuation loop (line_is_complete), Ctrl-C flag reset,
      │                       catch_unwind, the ONLY error renderer
      └─ r2-console::parser   tokenize (quotes, multiline, byte offsets) + bind args → BoundArgs
          └─ r2-console::commands::*   resolve provider/key refs (ProviderRegistry::resolve_ref →
              │                        r2_core::keys::parse_ref → Provider::find_key),
              │                        pick OperationSpec (OperationRegistry::resolve_cli /
              │                        available_for)
              └─ r2-ops::params::ParamResolver   inline name=value + ConsoleIo prompts → typed params
                  └─ r2-services::* or a Provider verb (encrypt/sign/…; &self, RefCell state)
                      └─ r2-memory (openssl)
                       | r2-pkcs11: Pkcs11Provider → Backend seam → CryptokiBackend
                                    (cryptoki safe API + RawFns) → vendor module (dlopen)
          └─ r2-console::render   Renderable → comfy-table / panel / hex dump → Sink (anstream,
                                  color policy)  |  file write via r2_core::datainput::DataOutput
```

- **Payload data** enters through `r2_core::datainput::DataInput` (inline token or file),
  is decoded by `r2_core::codec`, and crosses the provider boundary only as bytes /
  `KeyMaterial` (`Zeroizing<Vec<u8>>` in the §4.3 canonical formats). The console layer never
  performs crypto transforms; it only decodes input and renders output.
- **Errors** travel back as `r2_core::Result<T>`; `run_repl` is the single rendering point
  (error panel, caret echo for `Parse`, `Aborted.` for `UserAbort`). `Command::run` returns
  `Result<Flow>`; `Flow::Exit` replaces c2's `ReplExit`.
- **Completion and highlighting** run synchronously inside reedline's `read_line` on the
  REPL thread: reedline holds only zero-sized `Send` shims (`BridgeCompleter`,
  `BridgeHighlighter`) that reach the `!Send` `AppContext` through a thread-local
  `Rc<dyn LineAssist>` installed by `run_repl` (RAII guard). They never call `ctx.io` and
  never trigger a PKCS#11 library load (§5.1, §6).
- **PKCS#11 modules** are shared per canonical library path (`fs::canonicalize`, §4.5.5, §11 D21) through a thread-local,
  refcounted registry of `Rc<SharedModule { ctx: Pkcs11, raw: RawFns }>` (PyKCS11
  `_loaded_libs` parity): first acquire loads and `C_Initialize`s, last release drops
  sessions, `C_Finalize`s, then unloads (§5.2).
- **Logging** goes from every crate through `tracing` to the size-rotated `app.log` file
  configured by `r2-cli` (redaction layer, §6); no `log`→`tracing` bridge is installed, so
  cryptoki's `log`-crate records are dropped (§4.1.3).
- **Shutdown** (`exit`/`quit`, Ctrl-D at `r2>`, end of piped input) runs every provider's
  `shutdown()` from `r2-cli`; transport keys and other temporaries are released by `Drop`
  guards on success, error and unwind paths alike (`panic = "unwind"` in release builds).

## 4. FROZEN CONTRACTS (normative)

Everything in §4 is binding: crate and module paths, type definitions (including derives
and field order), trait and function signatures, the listed constants, and the normative
prose next to each item. Parallel loops code **only** against this section, and loop R0
materializes it verbatim as a compiling skeleton (§4.1 "R0 skeleton handoff"). Changing
anything here requires the procedure in §4.11.

Conventions used in every code block of §4:

- Real Rust, edition 2024. A body written `{ .. }` is elided: the signature is the
  contract, the body is the owning loop's work. Everything else (types, derives, trait
  default bodies that are written out, constants) is literal and R0 copies it verbatim.
- A struct body written `{ /* … */ }` is private state chosen by the owning loop; the
  comment is informative only. R0 materializes it with no fields (`{}`); a struct with a
  type parameter gets exactly one field, `_marker: std::marker::PhantomData<R>` (`R` = its
  parameter). Every derive listed on such a struct holds for the empty form, and the
  owning loop keeps it holding when it adds fields.
- An item written `impl Trait for Type { .. }` is materialized with exactly the trait's
  REQUIRED methods: signatures copied from the trait, stub bodies per §4.1.1, no default
  method overridden (the owning loop adds overrides). Exceptions: `Provider::as_any` gets
  the working body `self`; `Drop::drop` stubs are empty (`{}`), never a panic;
  `Pkcs11Provider` gets `as_token_init → Some(self)`, the ten R5b delegations
  `self.<method>_impl(..)` (§4.5.5; five of them override trait defaults) and
  `TokenInit::init_token → Pkcs11Provider::init_token(self, ..)` (the inherent method).
- Paths are crate paths (`r2_core::keys::KeyInfo`). A `use` line at the top of a block only
  documents where names come from.
- "Error kinds raised" are `r2_core::error::ErrorKind` variants (§4.2). A sentence such as
  "→ `Param`" means "returns `Err(ConsoleError)` with that kind". Quoted messages and
  hints are verbatim c2 texts (with `c2`→`r2` where the text names the tool, D7) and are
  asserted by ported tests. `{x!r}` in a quoted text means Python `repr()` of `x`,
  produced by `r2_core::text::py_repr` (§4.2).
- Every fallible public function returns `r2_core::Result<T>`. There is no other error type
  across a crate boundary (the crate-private PKCS#11 backend seam, §4.5.6, is the only
  internal exception and is translated at one choke point). Functions that only produce a
  library's detail text for a caller's c2 message (`r2_config::yaml::parse`,
  `r2_core::x509build::parse_rfc4514_subject`) return `r2_core::Result` too; how the caller
  embeds the text is stated at each function.
- `Rc`/`RefCell` everywhere: the application is single-threaded (§6). `Provider`,
  `ConsoleIo`, `TemplateEditor`, `Command` and everything holding them are `!Send`/`!Sync`
  by construction; no trait in §4 has a `Send` or `Sync` bound.
- Re-entrancy rule (binding for every implementation in §4): no implementation holds a
  `RefCell` borrow across a call into another trait object (`Provider`, `ConsoleIo`,
  `TemplateEditor`, `FakeHooks`, `Command`, `LineAssist`, the `next` view of a hook) or across
  the `f` of `ConsoleIo::busy`. Take what you need out of the cell, drop the borrow, then
  call. A double borrow is a panic (§6), and same-provider flows (`copy softhsm:x softhsm`,
  hooks that delegate, prints inside `busy`) re-enter by design.
- Unwind safety: `Drop` guards (transport keys, sessions, spinners, the bridge install
  guard, the test-only `EnvGuard`) never panic; a failure inside `drop` is logged and
  swallowed. A panic during unwinding would abort the process. Every §4 `Drop` guard checks
  `std::thread::panicking()` before calling code that can panic on poisoned or borrowed
  state (a std `Mutex` poisoned by the panic being unwound, a `RefCell` still borrowed by
  the unwinding frame): while panicking it only resets plain flags/atomics and drops its
  handles (e.g. `LineIo::busy`, §4.9.7).
- Byte offsets: every position in §4 (`Token.pos`, `ErrorKind::Parse::pos`, `parse_ref`
  positions, completion spans) is a **byte** offset into the UTF-8 string. Ported c2
  vectors (char indices) are identical for ASCII; non-ASCII vectors are converted.

### 4.1 Workspace & module layout, file → loop ownership

#### 4.1.1 Repository map

Owner column = the loop that owns the file (exclusive write access; loops.md working
agreement). `S0` documents, `R0`..`R15` (incl. `R5a`/`R5b`) are the loops of PLAN §8.

```
Cargo.toml                    workspace manifest: members, [workspace.package],
                              [workspace.dependencies], [workspace.lints]          R0
                              ...except the [profile.release] table and the
                              [workspace.dependencies] openssl-src line            R12
Cargo.lock                    R0 creates; any loop may let cargo update it, but only
                              for dependencies already declared in §4.1.4
rust-toolchain.toml           pinned stable 1.94.1 (= MSRV), components rustfmt+clippy R0
clippy.toml  deny.toml  justfile  .config/nextest.toml                             R0
.gitignore  .gitattributes    `/target`; `* text=auto eol=lf` + binary fixtures    R0
LICENSE                       GPL-3.0 (c2's license, §9)                           R0
.github/workflows/ci.yml                                                           R0
.github/workflows/release.yml                                                      R12
scripts/softhsm-init.sh       §4.10.5 contract                                     R0
scripts/build-softhsm.sh      builds SoftHSM 2.7.0 from its tag for the CI matrix  R0
scripts/release/**            release build/smoke scripts used by release.yml      R12
spec.md  CLAUDE.md  PLAN.md                                                        S0
loops.md                      S0 creates; each loop edits ONLY its own STATUS row
                              (the cards and the dependency table stay S0's)
README.md                                                                          R13
parity/README.md  parity/generate_ledger.py                                        S0
parity/ledger.csv             S0 creates; each loop edits ONLY its own rows
parity/harness/**             differential harness (PLAN §9.6)                     R13

crates/r2-core/               (lib)
  Cargo.toml                                                                       R0
  src/lib.rs                  module list below; docs/re-exports                   R0→R1
  src/error.rs                ConsoleError, ErrorKind, Result (§4.2)               R1
  src/text.rs                 py_repr, py_bytes_repr, py_bool, os_error_text,
                              py_os_error_str, close_matches, is_py_space,
                              py_strip, py_fromhex, py_int, py_isdigit, py_path (§4.2) R1
  src/keys.rs                 key model + ref grammar (§4.3)                       R1
  src/template.rs             AttrKind, AttrValue, TemplateAttr, KeyTemplate (§4.7)R1
  src/params.rs               Verb, ParamKind, ParamSpec, ParamValue, ParamStruct,
                              Params (§4.6)                                        R1
  src/io.rs                   ConsoleIo, TemplateEditor, IdentityTemplateEditor,
                              CommandInput, Renderable model (§4.9.1/§4.9.2)       R1
  src/render.rs               render / render_plain / RenderConfig (§4.9.2)        R1
  src/runtime.rs              Ctrl-C flag + spinner flag (§4.9.8)                  R1
  src/codec.rs                InputFormat, decode_data, format_hex (§4.4.1)        R1
  src/datainput.rs            DataInput, DataOutput (§4.4.2)                       R1
  src/catalog.rs              CKA_CATALOG static table (§4.5.5); R0 materializes the
                              table verbatim from §4.5.5                           R5a
  src/keyparse.rs             parse_key_material (§4.4.3)                          R6
  src/x509build.rs            self-signed cert, CSR (+ RFC 4514 subject parser),
                              PKCS#12 build (§4.4.4)                               R6
  src/x509info.rs             rfc4514_string, certificate_details, cert_attributes,
                              memory_cert_attributes, Classifier (§4.4.5)          R6
  src/formats.rs              PEM/DER/encrypted-PKCS#8 writers, SPKI derivation
                              (§4.4.6)                                             R6
  src/der.rs                  EC OID / point DER, r‖s ↔ DER (§4.4.7)               R6
  src/crypto.rs               ct_eq, random_bytes, ensure_legacy_provider (§4.4.8) R6

crates/r2-config/             (lib)
  Cargo.toml                                                                       R0
  src/lib.rs                                                                       R0→R2
  src/defaults.yaml           c2@408d6f2 `src/c2/config/defaults.yaml` through exactly
                              `sed 's#/c2/#/r2/#g; s#c2\.log#r2.log#'` (spec §7);
                              R0 writes it, then                                   R2
  src/model.rs                every config value type, default_template,
                              template_class_key (§4.8.2)                          R2
  src/loader.rs               load_config, discovery, deep merge (§4.8.1)          R2
  src/decode.rs               typed path-aware decoder (§4.8.3)                    R2
  src/yaml.rs                 PyYAML-faithful loader + emitter used by every crate
                              that reads/writes YAML (§4.8.4, §4.8.5)              R2
  src/dirs.rs                 user_config_dir, expand_user (§4.8.1)                R2

crates/r2-provider/           (lib)
  Cargo.toml                                                                       R0
  src/lib.rs  src/provider.rs src/types.rs src/registry.rs src/lookup.rs
  src/rsa_raw.rs src/mechanism.rs                     (§4.5.1–§4.5.4)              R3

crates/r2-ops/                (lib)
  Cargo.toml                                                                       R0
  src/lib.rs  src/model.rs  src/registry.rs  src/custom.rs
  src/builtin_aes.rs src/builtin_rsa.rs src/builtin_ec.rs src/builtin_generic.rs
                                                       (§4.6)                      R3
  src/params.rs               ParamResolver (§4.6.4)                               R7

crates/r2-memory/             (lib)
  Cargo.toml                                                                       R0
  src/lib.rs + any private modules                     MemoryProvider (§4.5.5)     R4

crates/r2-pkcs11/             (lib; only `catalog` and `softhsm` are pub modules)
  Cargo.toml                                                                       R0
  src/lib.rs                  pub mod catalog; pub mod softhsm; pub use Pkcs11Provider;
                              every other module private (§4.1.3)                  R5a
  src/catalog.rs              CKO/CKK/CKC/CKM/CKR name tables + CKA re-export      R5a
  src/softhsm.rs              find_softhsm_module (§4.5.5)                         R5a
  src/env.rs        (crate-private) THE single audited std::env::set_var site      R5a
  src/ckr.rs        (crate-private) CKR choke point (§5.2 table)                   R5a
  src/attributes.rs (crate-private) template conversion, identity resolution,
                              vendor value codec                                   R5a
  src/capability.rs (crate-private) CKM folding, custom merge, EdDSA probe
                              (§4.6.5)                                             R5a
  src/backend/mod.rs (crate-private) Backend seam (§4.5.6)                         R5a
  src/backend/cryptoki.rs     CryptokiBackend (+ mech_type, obj = the one
                              ObjectHandle::new_from_raw site)                     R5a
  src/backend/raw.rs          RawFns (unsafe shim 2), SharedModule registry        R5a
  src/backend/fake.rs         FakeBackend (§4.10.4)                  R5a (R5b may extend)
  src/provider/mod.rs (crate-private) Pkcs11Provider struct, new, `impl Provider`,
                              lifecycle, login, tokens, init_token, auto-recovery  R5a
  src/provider/objects.rs     list/find/import/generate/delete/export, KeyInfo
                              building, identity resolution, twin guard            R5a
  src/provider/crypto.rs      encrypt/decrypt/sign/verify/derive + software
                              fallbacks                                            R5b
  src/provider/wrap.rs        wrap/unwrap, KWP preference, CKA_VALUE_LEN retry     R5b
  src/provider/edit.rs        read_key_template, update_key, read_full_template    R5b
  src/mechanisms.rs (crate-private) custom packers, MechanismInvocation → MechSpec R5b
  src/tests/mod.rs  (crate-private, cfg(test)) FakeBackend test modules  R5a (R5b appends)
  src/tests/<topic>.rs        one owner per file (the porting loop)            R5a / R5b

crates/r2-services/           (lib)
  Cargo.toml  src/lib.rs                                                           R0
  src/keyload.rs  src/keyexport.rs  src/certops.rs        (§4.9.10)                R8
  src/transfer.rs                                          (§4.9.10)               R10
  src/templatefile.rs                                      (§4.9.10)               R14
  src/wrapload.rs                                          (§4.9.10)               R15

crates/r2-console/            (lib)
  Cargo.toml                                                                       R0
  build.rs                    command-module + test-module discovery (§4.9.6);
                              R0 writes it complete and working, then              R7
  src/lib.rs  src/context.rs  src/repl.rs  src/parser.rs  src/completer.rs
  src/render.rs  src/cmdutil.rs  src/testing.rs (cfg(test), §4.10.6)
  src/io/mod.rs  src/io/line.rs  src/io/plain.rs  src/io/terminal.rs
  src/io/history.rs  src/io/assist.rs        (§4.9, item placement §4.9.7)         R7
  src/template_editor.rs                                   (§4.9.3, §5.12)         R10
  src/wizard.rs                                            (§4.9.9, §5.13)         R11
  src/commands/mod.rs         Command trait + generated module list (§4.9.6)       R7
  src/commands/help.rs  src/commands/misc.rs                                       R7
  src/commands/providers.rs  src/commands/keys.rs                                  R8
  src/commands/crypto.rs                                                           R9
  src/commands/copy.rs                                                             R10
  src/commands/key_template.rs                             (§4.9.9 hook)           R14
  src/commands/kek.rs                                      (§4.9.9 hooks)          R15
  src/tests/<topic>.rs        in-crate console tests (cfg(test), discovered by build.rs);
                              one owner per file (the porting loop)            R7…R15
  src/tests/build_discovery.rs  R0 seed test, written complete and working (asserts
                              the build.rs module list; keeps src/tests/ non-empty)   R0→R7

crates/r2-cli/                (bin `r2`)
  Cargo.toml                                                                       R0
  src/main.rs                 R0 stub (`--version` only) → R7
  src/args.rs  src/bootstrap.rs  src/logging.rs  src/panic.rs  (§4.9.11)           R7

crates/r2-testkit/            (lib; dev-dependency of every other crate)
  Cargo.toml  src/lib.rs                                                           R0
  src/scripted_io.rs          ScriptedIo, RecordingEditor (§4.10.1)                R1
  src/env.rs                  set_env, EnvGuard — test-only env override (§4.10.1) R1
  src/fake_provider.rs        FakeProvider, FakeHooks (§4.10.2)                    R3
  src/contract.rs             provider_contract_tests! + cases (§4.10.3)           R3
  src/fixtures.rs             OpenSSL-generated key/cert fixtures (§4.10.3)        R3
  src/softhsm.rs              SoftHSM fixture (§4.10.5)                            R0
```

Test files (the owner is always the owner of the code under test; a loop never edits
another loop's test file, loops.md rule 6):

- Test ownership follows CODE ownership, not c2's file layout: where a c2 module's code
  moved to another loop, that loop ports the matching c2 test cases (per case, through the
  ledger generator's `OVERRIDES`). Moves made by this spec: c2 `console/render.py`'s
  renderer (`make_table`/`hex_panel`/`error_panel`/`caret_text`) → R1 (`r2_core::io`,
  `r2_core::render`; test_render cases); `certops.certificate_details` /
  `ecdsa_rs_to_der` and keyexport's pyca serializers → R6 (`x509info`, `der`, `formats`;
  those test_certops/test_keyexport cases); `app.build_operation_registry` → R3
  (test_app's registry cases); CKM folding / custom merge / EdDSA probe → R5a
  (`capability.rs`; so test_provider_session.py's `mechanisms()` assertions stay R5a's),
  while every crypto/wrap/derive/edit verb case of c2's test_objects.py /
  test_provider_objects.py (encrypt/decrypt/sign/verify/derive, wrap/unwrap,
  read_key_template/update_key/read_full_template) is R5b's, in R5b's own
  `src/tests/<topic>.rs`. (S0 follow-up: the loops.md cards and the ledger's `OVERRIDES`
  carry these moves.)
- Unit tests inside a source file (`#[cfg(test)] mod tests`) belong to the file's owner.
- **r2-core and r2-provider tests that use r2-testkit** (`ScriptedIo`, `RecordingEditor`,
  `FakeProvider`, `fixtures`, `contract`) MUST be integration tests
  (`crates/r2-core/tests/<topic>.rs`, `crates/r2-provider/tests/<topic>.rs`). r2-testkit
  depends on these two crates, so inside their own `cfg(test)` build the testkit's impls
  target a different copy of the crate (E0277 "`ScriptedIo: ConsoleIo` is not satisfied").
  In-file `#[cfg(test)]` modules there use no testkit item.
- Integration tests (public API only): `crates/<crate>/tests/<topic>.rs`, the file name
  starting with the loop's module name (e.g. `crates/r2-services/tests/keyload.rs` R8,
  `crates/r2-services/tests/wrapload.rs` R15, `crates/r2-config/tests/config.rs` R2).
  c2's in-process suites that combine real providers (test_copy.py and
  test_objects_softhsm.py drive `copy_key` over MemoryProvider + Pkcs11Provider;
  test_console_crypto.py, test_custom_mechanism.py, test_wizard.py build an AppContext over
  them with ScriptedIO) are ported in-process, using the permitted dev-dependency edges of
  §4.1.2: services suites in `crates/r2-services/tests/<topic>.rs`, console suites in
  `crates/r2-console/src/tests/<topic>.rs` (§4.10.6 `CtxBuilder::providers`).
- In-crate test modules (tests that need crate-private items — `FakeBackend`,
  `r2_console::testing`): `crates/r2-console/src/tests/<topic>.rs` and
  `crates/r2-pkcs11/src/tests/<topic>.rs`, compiled only under `cfg(test)`.
  r2-console's `build.rs` also discovers `src/tests/*.rs` and generates the module list
  (`$OUT_DIR/test_modules.rs`, included by `#[cfg(test)] mod tests { include!(..); }` in
  `lib.rs`), so console loops add test files without a shared list (e.g. `keys_cmd.rs` R8,
  `crypto_cmd.rs` R9, `load_kek.rs` R15). r2-pkcs11's `src/tests/mod.rs` is created by
  R5a; R5b appends its own `mod` lines (sequential handoff).
- End-to-end tests that spawn the `r2` binary (assert_cmd): `crates/r2-cli/tests/`
  (`e2e_repl.rs` R7, `e2e_console_keys.rs` R8, `e2e_wizard.rs` R11, …).

**R0 skeleton handoff (the only sanctioned shared-file handoffs).**

1. R0 creates every `Cargo.toml` and every `lib.rs`/`main.rs`/`mod.rs` with the complete
   module list of §4.1.1 and every item of §4.2–§4.10 that is written as code, as
   compiling code. Types, traits, constants and data tables are complete; function bodies
   are stubs. A stub returns `Err(ConsoleError::not_implemented("Rn"))` (§4.2) when the
   return type allows it, and otherwise calls `unimplemented!("Rn")`, where `Rn` is the
   owning loop; stubs consume their parameters (`let _ = (a, b);`). Comment-bodied structs
   and whole-impl elisions follow the two materialization rules of the §4 conventions
   (empty struct / required methods only), so R0 invents no fields and no bodies. Every skeleton file
   whose items are unused in the skeleton (crate-private items, private fields, the private
   modules of the `r2` binary such as `bootstrap.rs`, the generated `module_commands()` in
   `commands/mod.rs`) starts with `#![allow(dead_code)]`, which the file's owner removes.
   Items described only in prose and marked internal (R5a: `RawFns`, `SharedModule` and
   its registry, §4.5.5; R7: `QuoteValidator`, `ChoiceCompleter`, `NarrowTerm`,
   `ReedlineReader`, §4.9.7) are NOT materialized by R0; the owner adds them. Exceptions with a mandated working body (the
   r2 equivalent of c2's lazy-import fallbacks, so dependent loops work on either side of
   the owner's merge):
   - `create_template_editor` (§4.9.3), `token_needs_init` / `run_softhsm_wizard`
     (§4.9.9), `templatefile::build_seed` and `EditorSeeding::edit` (§4.9.10), and the
     trivial bodies written out in §4 (trait default methods, `IdentityTemplateEditor`);
   - `ConsoleError::{new, with_hint, with_hint_opt, generic, crypto, not_implemented}`
     (§4.2; `new` sets `hint: None`, `not_implemented(l)` = `generic(format!("not
     implemented ({l})"))`), so a stub's `Err(not_implemented(..))` — and `random_bytes`'s
     Crypto error — is an error, not a panic, before R1 merges;
   - every command module's `pub fn commands() -> Vec<Box<dyn Command>>` returns `vec![]`
     until its owner fills it (R7's `discover_commands`/`run_line` iterate every module and
     merge before R8–R10);
   - `r2_core::catalog::cka` / `cka_by_code` = `CKA_CATALOG.iter().find(|e| e.name == name)`
     / `CKA_CATALOG.iter().find(|e| e.code == code)` (R3's FakeProvider needs them before
     R5a merges);
   - the small R6 helpers other loops call before or beside R6: `crypto::ct_eq`,
     `crypto::random_bytes`, `crypto::ensure_legacy_provider`, `der::curve_oid_der`,
     `der::curve_from_oid_der`, `der::wrap_octet_string` (bodies exactly as their doc
     comments state).
   R0 also writes, complete and working: (i) `crates/r2-console/build.rs` per §4.9.6
   (commands/mod.rs and lib.rs `include!` its output, so it cannot be a stub; R7 owns it
   afterwards); (ii) `crates/r2-config/src/defaults.yaml` = the exact §7 transform of c2's
   file (R2 owns it afterwards); (iii) the `#![allow(...)]` headers of §4.1.3 in r2-testkit's
   `lib.rs`; (iv) the seed test `crates/r2-console/src/tests/build_discovery.rs` (R7 owns it
   afterwards), so that `src/tests/` exists from R0 on: the done gate's rustfmt glob
   `crates/r2-console/src/tests/*.rs` expands, build.rs's `rerun-if-changed=src/tests` is
   not a permanently missing (always stale) path, and `cargo nextest run --workspace`
   (with or without `--features softhsm`) does not fail with "no tests to run" on the
   skeleton:
   ```rust
   #[test]
   fn build_rs_lists_every_command_module() {
       let stems: Vec<&str> = crate::commands::module_commands()
           .into_iter()
           .map(|(stem, _)| stem)
           .collect();
       assert_eq!(
           stems,
           [
               "copy",
               "crypto",
               "help",
               "kek",
               "key_template",
               "keys",
               "misc",
               "providers"
           ]
       );
   }
   ```
   (rustfmt-canonical as written.) The list is exactly the command modules of §4.1.1;
   adding a module is a §4.1.1 change (§4.11), which updates this test with it.
2. The owning loop replaces stub bodies in its files. That is the sanctioned handoff; no
   §4.11 procedure is needed for it.
3. `crates/r2-cli/src/main.rs`: R0 stub (prints `r2 <version>` for `--version`) → R7.
4. `crates/r2-pkcs11/src/backend/fake.rs` and `src/tests/mod.rs`: R5a → R5b may extend
   them after R5a merged.
5. `crates/r2-core/src/catalog.rs`: R0 writes the table verbatim from §4.5.5; R5a owns it.
6. Sub-file ownerships inside R0-owned manifests: R12 owns the root `[profile.release]`
   table, the `vendored-openssl` lines of the `[features]` tables of `r2-cli` and
   `r2-core`, the root `[workspace.dependencies]` `openssl-src` line, and r2-core's
   `[build-dependencies]` `openssl-src` entry (optional, enabled only by
   `vendored-openssl`; §4.1.4). Any loop owning files in a crate may add a dependency line (normal or dev) to
   that crate's `Cargo.toml` when the dependency is pinned in §4.1.4 and permitted for that
   crate by §4.1.2 — no §4.11 procedure; anything else is a §4 change.
7. Everything else has exactly one owner for the whole project (R13 owns everything
   during its solo wave).

Merge-order edges this spec adds to PLAN §8 (S0 carries them into loops.md): **R5a depends
on R6** (`x509info::cert_facts`/`cert_attributes` on the certificate read path, `der` EC
helpers; the mandated helper bodies above cover the rest) and **R7 depends on R6\***
(bootstrap's `ensure_legacy_provider` has a mandated body, so the edge only orders merges).
The wave plan already satisfies both (R6 is wave 2; R5a and R7 are wave 3).

`clippy::todo`/`clippy::unimplemented` are `allow` until R13 and `deny` from R13 on.
(Correction of PLAN §4's "warn": the done gate runs clippy with `-D warnings`, which would
turn the skeleton's stubs into errors.)

#### 4.1.2 Crate dependency graph and dependency table (the single normative source)

The graph is c2 §3.1 made structural. This subsection is the ONLY normative statement of
crate edges and third-party dependencies (§3.1 is a summary that points here). An edge or
a dependency not listed here is forbidden (it is a §4.11 change). `r2-testkit` is a
dev-dependency only.

```
r2-cli      → r2-console, r2-memory, r2-pkcs11, r2-ops, r2-provider, r2-config, r2-core
r2-console  → r2-services, r2-ops, r2-pkcs11 (only `softhsm::find_softhsm_module`),
              r2-provider, r2-config, r2-core
r2-services → r2-ops, r2-provider, r2-config, r2-core
r2-ops      → r2-provider, r2-config, r2-core
r2-memory   → r2-provider, r2-core
r2-pkcs11   → r2-provider, r2-config, r2-core
r2-provider → r2-core            (PLAN §4 permits r2-config (model); §4 needs no item from it)
r2-config   → r2-core
r2-core     → third-party only
r2-testkit  → r2-provider, r2-core      ([dev-dependencies] of every other crate)

Permitted dev-dependency edges between production crates (in-process ports of c2's
real-provider suites, §4.1.1 "Test files"; none of these crates is a dependency of
r2-testkit, so no crate is compiled twice):
r2-services ⇢ r2-memory, r2-pkcs11
r2-console  ⇢ r2-memory           (r2-pkcs11 is already a normal dependency)
```

Refinements of PLAN §4, both recorded here so nobody re-adds them:

- `r2-services → r2-pkcs11` is **dropped**. The static `CKA_CATALOG` lives in
  `r2_core::catalog` (re-exported as `r2_pkcs11::catalog::CKA_CATALOG`), because
  `r2-testkit` (FakeProvider, §4.10.2) needs it and may not depend on `r2-pkcs11` (a
  dev-dependency cycle would compile `r2-pkcs11` twice and split its types). The CKO/CKK/
  CKC/CKM/CKR name tables stay in `r2_pkcs11::catalog` and are used inside r2-pkcs11 only.
- The console's ConsoleIo renderer (`render`/`render_plain`) lives in `r2_core::render`,
  because `ScriptedIo` (r2-testkit) stores `render_plain` output and r2-testkit may not
  depend on r2-console for the same reason. The console keeps the Sink/color policy.
- The wizard reaches token initialization only through `Provider::as_token_init()`
  (`r2_provider::TokenInit`, §4.5.2); the console never names a pkcs11 type.

Third-party dependencies per crate (normal dependencies; versions in §4.1.4):

| crate | third-party dependencies |
|---|---|
| r2-core | `openssl`, `der`, `spki`, `x509-cert`, `const-oid`, `secrecy`, `zeroize`, `indexmap`, `hex`, `base64`, `comfy-table`, `anstyle`, `tracing`; optional build-dependency `openssl-src` (feature `vendored-openssl` only, §4.1.4) |
| r2-config | `serde_yaml_ng`, `yaml-rust2`, `indexmap`, `tracing` |
| r2-provider | `openssl`, `secrecy`, `zeroize`, `tracing` |
| r2-ops | `indexmap`, `tracing` |
| r2-memory | `openssl`, `secrecy`, `zeroize`, `tracing` |
| r2-pkcs11 | `cryptoki`, `cryptoki-sys`, `libloading`, `openssl`, `secrecy`, `zeroize`, `indexmap`, `tracing` |
| r2-services | `secrecy`, `zeroize`, `indexmap`, `tracing` |
| r2-console | `reedline`, `crossterm`, `nu-ansi-term`, `rpassword`, `indicatif`, `console`, `comfy-table`, `anstream`, `anstyle`, `unicode-width`, `secrecy`, `zeroize`, `indexmap`, `tracing` |
| r2-cli | `clap`, `ctrlc`, `tracing`, `tracing-subscriber`, `regex` |
| r2-testkit | `openssl`, `secrecy`, `zeroize`, `indexmap` |
| dev (any crate) | `tempfile`, `assert_cmd`, `insta` |

Restricted third-party crates (the table above already respects these; they are listed so
reviews can check a new line quickly):

| crate(s) | may be depended on by |
|---|---|
| `cryptoki`, `cryptoki-sys`, `libloading` | `r2-pkcs11` only. No cryptoki type appears in any `pub` item. |
| `openssl` | `r2-core`, `r2-provider`, `r2-memory`, `r2-pkcs11` (software fallbacks and attribute-material conversion, as c2's `provider.py` used pyca), `r2-testkit` — never `r2-config`, `r2-ops`, `r2-services`, `r2-console`, `r2-cli` |
| `der`, `spki`, `x509-cert`, `const-oid` | `r2-core` only |
| `openssl-src` | `r2-core` only, as an optional `[build-dependencies]` entry enabled by `vendored-openssl` (it is never called; it only unifies features with openssl-sys's own openssl-src build-dependency) |
| `serde_yaml_ng`, `yaml-rust2` | `r2-config` only (other crates use `r2_config::yaml`, §4.8.5) |
| `reedline`, `crossterm`, `nu-ansi-term`, `rpassword`, `indicatif`, `console` | `r2-console` only (`nu-ansi-term` is reedline 0.49's `Style` type: `StyledText`, `DefaultHinter::with_style`; reedline does not re-export it) |
| `comfy-table`, `anstyle` | `r2-core` (renderer), `r2-console` |
| `unicode-width` | `r2-console` (r2-core's renderer measures with rich's own cell table, §4.9.2) |
| `anstream` | `r2-console` (Sink) only |
| `clap`, `ctrlc`, `tracing-subscriber`, `regex` | `r2-cli` only |
| `tracing` | any crate |

`comfy-table` keeps its default `tty` feature (bold header cells and `enforce_styling`
need it), which pulls `crossterm` into r2-core's dependency tree transitively; r2-core
never calls crossterm itself and does no terminal I/O (`force_no_tty()`, §4.9.2).

#### 4.1.3 Workspace rules

- Every crate root starts with `#![forbid(unsafe_code)]`, except `r2-pkcs11` and
  `r2-testkit`, which use `#![deny(unsafe_code)]` with an `#[allow(unsafe_code)]` +
  `// SAFETY:` comment at exactly these sites (the unsafe budget, S0 spike 1; `forbid`
  could not be overridden by the sanctioned sites): `backend/raw.rs` (RawFns: second `dlopen`
  of the module and its `CK_FUNCTION_LIST`, driven by `Session::handle()` /
  `ObjectHandle::handle()`), `mech_type()` in `backend/cryptoki.rs` (`transmute` of the
  `try_from`-checked `CK_MECHANISM_TYPE`; sound because `MechanismType` is
  `#[repr(transparent)]` over it), `obj()` in `backend/cryptoki.rs` (after a checked
  `CK_OBJECT_HANDLE::try_from`) — the ONE `ObjectHandle::new_from_raw` call, through which every
  `Backend` method turns its `u64` handle into an `ObjectHandle` (SAFETY: the handle came
  from this module's find/create/generate/unwrap/derive results, or is the operator's
  `@<handle>`, which the token itself validates; no handle cache is kept) — and the single
  `std::env::set_var` call in `env.rs`; in `r2-testkit` (a dev-dependency only, never
  linked into the `r2` binary): the `set_var`/`remove_var` calls of `r2_testkit::env`
  (`set_env` and `EnvGuard`'s `Drop`, §4.10.1), the one sanctioned way for tests to change
  the process environment (c2 `monkeypatch.setenv`/`delenv`).
- `[workspace.lints]`: `clippy::print_stdout`, `clippy::print_stderr`,
  `clippy::unwrap_used`, `clippy::expect_used` = deny; `clippy::todo`,
  `clippy::unimplemented` = allow until R13, deny from R13 (§4.1.1). Allowed print sites,
  each with an `#[allow]` and a comment: `r2-cli` `--version` and pre-REPL startup errors;
  `r2-console`'s two one-line stderr warnings (the `DegradingReader` fallback and the
  mintty/msys hidden-input warning, §4.9.7); `r2_testkit::contract::skip`. Ordinary console
  output never uses the print macros: it goes through `std::io::Write` on the Sink /
  stdout handle (§4.9.7), which the lints do not cover.
- Test exemptions (the mechanism, so `cargo clippy --workspace --all-targets -- -D
  warnings` passes): `clippy.toml` sets `allow-unwrap-in-tests = true`,
  `allow-expect-in-tests = true`, `allow-print-in-tests = true` (these cover `#[test]` fns
  and `#[cfg(test)]` modules only). Every integration-test file (`crates/*/tests/*.rs`) and
  r2-testkit's `lib.rs` therefore start with `#![allow(clippy::unwrap_used,
  clippy::expect_used, clippy::print_stdout, clippy::print_stderr)]` (helper fns outside
  `#[test]` fns, and the testkit's library code, are otherwise linted).
- `clippy.toml` `disallowed-methods`: `std::thread::spawn` (allowed: the `ctrlc` handler in
  r2-cli and the indicatif ticker in r2-console, §4.9.8), `std::env::set_var` and
  `std::env::remove_var` (allowed only in r2-pkcs11's `crate::env` — production — and in
  `r2_testkit::env` — tests),
  `openssl::pkey::PKey::private_key_from_pem`, `openssl::rsa::Rsa::private_key_from_pem`,
  `openssl::ec::EcKey::private_key_from_pem`, every `*_from_pem_passphrase`,
  `openssl::pkey::PKey::private_key_from_pkcs8_passphrase` (the plain PEM loader prompts on
  the TTY; the passphrase variants panic on an interior NUL — §4.4.3),
  `openssl::aes::wrap_key`, `openssl::aes::unwrap_key` (deprecated; KWP is EVP-only),
  `openssl::memcmp::eq` (allowed only inside `r2_core::crypto::ct_eq`: it panics on a
  length mismatch), the lossy cryptoki APIs `cryptoki::context::Pkcs11::get_mechanism_list`
  (drops unknown CKMs), `cryptoki::context::Pkcs11::get_token_info` (parses `utcTime`;
  fails on a token with CKF_CLOCK_ON_TOKEN and a non-digit clock),
  `cryptoki::session::Session::get_attributes` (fails whole calls /
  omits refusals) and `cryptoki::session::Session::wrap_key` (no truncation) — use the
  `RawFns` equivalents (§4.5.5) — and `std::io::IsTerminal::is_terminal` (the
  TerminalIo/PlainIo switch uses `crossterm::tty::IsTty`, §4.9.7; one allowed site: the
  mintty/msys hidden-input warning in `r2_console::io::open_console_io`).
- Crate-root re-exports (R0 writes them; paths used throughout §4): `r2_core` →
  `ConsoleError`, `ErrorKind`, `Result`, `crypto::{ct_eq, ensure_legacy_provider}`; `r2_provider` → `Provider`, `TokenInit`
  (`provider`), `ProviderRegistry` (`registry`), `types::*`, plus `pub mod lookup`,
  `pub mod rsa_raw`, `pub mod mechanism`; `r2_ops` → `OperationSpec` + the
  `r2_core::params` re-exports of `model`, `OperationRegistry`, `register_builtins`,
  `build_operation_registry`, `suggest_hint` (`registry`), `ParamResolver` (`params`),
  plus `pub mod custom`; `r2_memory` → `MemoryProvider`; `r2_pkcs11` → `Pkcs11Provider`
  (its only `pub mod`s are `catalog` and `softhsm`); `r2_testkit` → `ScriptedIo`,
  `RecordingEditor`, `global_state_lock`, `FakeProvider`, `FakeHooks`, `set_env`, `EnvGuard`
  (and its modules);
  `r2_console` →
  §4.9.6. Every module named in §4.1.1 is `pub mod` unless marked crate-private there
  (a crate-private module's items are `pub(crate)`, so `-D warnings` raises no
  `private_interfaces` lint, and r2-pkcs11's `crate::env::apply_env` is not a public `set_var`
  entry point).
- `cryptoki` logs routine conditions at ERROR through the `log` crate. r2 installs **no**
  `log`→`tracing` bridge: `tracing-subscriber` is used with `default-features = false`
  (no `tracing-log`), so `log` records are dropped.
- Naming (D7): the product is `r2` everywhere — binary `r2`, prompt `r2> `, `r2.yaml`,
  `$R2_CONFIG`, `r2` config/state/log dirs, the SoftHSM wizard's default token label
  `r2`, transport-key labels `r2-transport-…`, the test token `R2TEST`, every message that
  names the tool. c2 → r2 renames in quoted texts below are already applied.
- Every workspace member declares a cargo feature `softhsm` (possibly empty;
  `softhsm = ["r2-testkit/softhsm"]` where it has SoftHSM tests) so that
  `cargo nextest run --workspace --features softhsm` is valid (§4.10.5).
- Test runner (normative): the done gate and CI run tests with `cargo nextest`
  (process-per-test). Tests that touch process-global state — the `r2_core::runtime` flags,
  the process environment (including tests that only READ it through env-reading code such
  as `discover`, `user_config_dir`, `find_softhsm_module`), a PKCS#11 module — hold
  `r2_testkit::global_state_lock()` (§4.10.1) for their whole body and restore what they
  changed, so plain `cargo test` stays correct too; doc tests never touch that state. Tests
  change the environment ONLY through `r2_testkit::set_env` (whose `EnvGuard` restores the
  previous value on drop); production code only through r2-pkcs11's
  `crate::env::apply_env`. SoftHSM tests (feature `softhsm`) are
  supported under nextest only: two test threads would each own a thread-local module
  registry and one's `C_Finalize` would kill the other's sessions (§4.5.5).

#### 4.1.4 Pinned third-party dependencies (`[workspace.dependencies]`)

```toml
openssl        = "0.10.81"          # minimum (KW-pad overflow fixes 0.10.79/80, unwrap assert fix
                                    # 0.10.78, mul_generator2, Asn1StringRef::to_string)
cryptoki       = "=0.12.1"          # any bump re-runs the S0 spike checks G1/G3/G4/G5 + repr(transparent)
cryptoki-sys   = "=0.5.0"
libloading     = "0.8"
der            = { version = "0.8.2", features = ["std", "pem", "oid"] }
spki           = { version = "0.8.0", features = ["std", "pem"] }
x509-cert      = { version = "0.3.0", features = ["std", "pem"] }
const-oid      = { version = "0.10.2", features = ["db"] }
secrecy        = "0.10"             # cryptoki::types::AuthPin = secrecy 0.10 SecretString
zeroize        = "1.8"
indexmap       = "2"
serde_yaml_ng  = "0.10"             # Value / Mapping tree only (r2 parses and emits itself, §4.8.4)
yaml-rust2     = { version = "0.13", default-features = false }   # event parser (scalar styles)
hex            = "0.4"
base64         = "0.22"
reedline       = "=0.49.0"
crossterm      = { version = "=0.29.0", features = ["use-dev-tty"] }   # burst-stall fix, S0 spike 3
nu-ansi-term   = "0.50"             # reedline 0.49's Style type (StyledText, DefaultHinter::with_style)
rpassword      = "=7.5.4"
comfy-table    = "=8.0.1"
anstream       = "1.0"
anstyle        = "1.0"
unicode-width  = "0.2"
indicatif      = "0.18"             # provisional (spinner, §4.9.8)
console        = "0.16"             # provisional (indicatif TermLike target)
ctrlc          = "3.5"
clap           = { version = "4", features = ["derive"] }
tracing        = "0.1"
tracing-subscriber = { version = "0.3", default-features = false, features = ["fmt", "registry", "std"] }
regex          = "1"              # r2-cli log redaction only
# vendored-openssl only (§9): openssl-sys's openssl-src build-dependency, with OpenSSL's
# default cipher set restored (openssl-src alone configures no-camellia/no-idea/no-seed)
openssl-src    = { version = "300.6.1", features = ["camellia", "idea", "seed"] }
# dev
tempfile       = "3"
assert_cmd     = "2"
insta          = "1"
```

Release builds enable `openssl/vendored` through the feature chain
`r2-cli/vendored-openssl → r2-core/vendored-openssl → openssl/vendored` (R12 owns the
feature definitions in those two manifests' `[features]` tables, the `openssl-src` line
above and r2-core's `[build-dependencies]` `openssl-src` entry; §4.1.1 item 6). The
`vendored-openssl` feature of r2-core also enables its optional build-dependency
`openssl-src` (§4.1.2) with the features `camellia`, `idea` and `seed`: Cargo unifies them
with openssl-sys's openssl-src build-dependency, so the vendored libcrypto keeps the cipher
set c2's pyca build has (openssl-src alone configures `no-camellia no-idea no-seed`).
CAMELLIA is a default-provider cipher; SEED and IDEA (like RC2) are legacy-provider
ciphers, usable because the vendored build compiles the legacy provider in. Without the
features, PKCS#12 files with PBES2 CAMELLIA, SEED or IDEA bags — which c2/pyca load — fail
in the release binary with the wrong-password text (R12; verified by the release smoke
test, §9). The system-OpenSSL development build loads the legacy-provider ones only when
the distro's `legacy` module is available and has the cipher (§5.4: non-fatal).

### 4.2 Errors (`r2_core::error`, `r2_core::text`)

c2's exception hierarchy becomes one value type: `ConsoleError { kind, message, hint }`,
where `ErrorKind` carries the extra fields of the attribute-carrying subclasses. Family
membership (`isinstance(e, ProviderError)` in c2) is a predicate. `ReplExit` is **not** an
error in r2: commands return `Flow::Exit` (§4.9.5), and Ctrl-D is a `CommandInput::Eof`.

```rust
// crates/r2-core/src/error.rs
use std::borrow::Cow;
use std::fmt;

use crate::keys::KeyRef;

/// The single error type of every public r2 API. Rendered ONLY by the REPL loop (§4.9.5):
/// commands and services return it, never print it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsoleError {
    pub kind: ErrorKind,
    /// Operator-actionable text. PKCS#11 failures include the CKR name (§6).
    pub message: String,
    pub hint: Option<String>,
}

/// One variant per c2 exception class (c2 spec §4.2). Variant ↔ class:
/// Generic=ConsoleError, Config=ConfigError, Parse=ParseError, Codec=CodecError,
/// KeyParse=KeyParseError, DataIo=DataIOError, Provider=ProviderError,
/// ProviderUnavailable=ProviderUnavailableError, ProviderNotFound=ProviderNotFoundError,
/// AuthRequired=AuthRequiredError, AlreadyLoggedIn=AlreadyLoggedInError, Pkcs11=Pkcs11Error,
/// KeyLookup=KeyLookupError, KeyNotFound=KeyNotFoundError, AmbiguousKey=AmbiguousKeyError,
/// DuplicateKey=DuplicateKeyError, KeyNotExportable=KeyNotExportableError,
/// Operation=OperationError, UnknownOperation=UnknownOperationError,
/// UnsupportedOperation=UnsupportedOperationError, Param=ParamError, Crypto=CryptoError,
/// UserAbort=UserAbort.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Generic,
    Config,
    /// `line` = the text the caret is drawn under; `pos` = BYTE offset into `line`.
    Parse { line: String, pos: usize },
    Codec,
    KeyParse,
    /// File read/write failure; the path is part of the message.
    DataIo,
    Provider,
    /// Library load / C_Initialize failed.
    ProviderUnavailable,
    /// Unknown provider name in a ref.
    ProviderNotFound,
    AuthRequired,
    AlreadyLoggedIn,
    /// Untranslated PKCS#11 failure. `ckr_name` is the symbolic name from PyKCS11's table
    /// (`"CKR_PIN_INCORRECT"`, `r2_pkcs11::catalog::ckr_name`, §4.5.5), or `"CKR_0x%08X"`
    /// (upper-case hex, 8 digits, low 32 bits) for codes without one.
    Pkcs11 { ckr_code: u64, ckr_name: Cow<'static, str> },
    KeyLookup,
    KeyNotFound,
    /// Several objects matched; candidates are the matching refs in provider order.
    AmbiguousKey { candidates: Vec<KeyRef> },
    /// Creating an exact (class, label, id) twin was refused (§4.7 guard).
    DuplicateKey,
    KeyNotExportable,
    Operation,
    UnknownOperation,
    /// Capability check failed for this provider/key.
    UnsupportedOperation,
    Param { param_name: String },
    /// Backend failure mid-operation.
    Crypto,
    /// Ctrl-C / Ctrl-D inside a prompt flow, or the Ctrl-C flag at a step boundary. The REPL
    /// renders every UserAbort as the single line `Aborted.` (the message is not shown).
    UserAbort,
}

impl ErrorKind {
    /// The c2 class name ("ParamError", "Pkcs11Error", …) — for logs and test assertions.
    pub fn class_name(&self) -> &'static str { .. }
    /// ProviderError family: Provider, ProviderUnavailable, ProviderNotFound, AuthRequired,
    /// AlreadyLoggedIn, Pkcs11.
    pub fn is_provider(&self) -> bool { .. }
    /// KeyLookupError family: KeyLookup, KeyNotFound, AmbiguousKey, DuplicateKey.
    pub fn is_key_lookup(&self) -> bool { .. }
    /// OperationError family: Operation, UnknownOperation, UnsupportedOperation, Param, Crypto.
    pub fn is_operation(&self) -> bool { .. }
    /// UserAbort (c2's KeyboardInterrupt/EOFError/UserAbort path — never swallowed, below).
    pub fn is_user_abort(&self) -> bool { .. }
}

impl ConsoleError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self { .. }
    /// Builder: sets the hint (replaces an existing one).
    pub fn with_hint(self, hint: impl Into<String>) -> Self { .. }
    /// Builder: sets or clears the hint.
    pub fn with_hint_opt(self, hint: Option<String>) -> Self { .. }

    // One constructor per kind (all take `impl Into<String>` for the message):
    pub fn generic(message: impl Into<String>) -> Self { .. }
    pub fn config(message: impl Into<String>) -> Self { .. }
    pub fn parse(message: impl Into<String>, line: impl Into<String>, pos: usize) -> Self { .. }
    pub fn codec(message: impl Into<String>) -> Self { .. }
    pub fn key_parse(message: impl Into<String>) -> Self { .. }
    pub fn data_io(message: impl Into<String>) -> Self { .. }
    pub fn provider(message: impl Into<String>) -> Self { .. }
    pub fn provider_unavailable(message: impl Into<String>) -> Self { .. }
    pub fn provider_not_found(message: impl Into<String>) -> Self { .. }
    pub fn auth_required(message: impl Into<String>) -> Self { .. }
    pub fn already_logged_in(message: impl Into<String>) -> Self { .. }
    pub fn pkcs11(message: impl Into<String>, ckr_code: u64, ckr_name: impl Into<Cow<'static, str>>) -> Self { .. }
    pub fn key_lookup(message: impl Into<String>) -> Self { .. }
    pub fn key_not_found(message: impl Into<String>) -> Self { .. }
    pub fn ambiguous_key(message: impl Into<String>, candidates: Vec<KeyRef>) -> Self { .. }
    pub fn duplicate_key(message: impl Into<String>) -> Self { .. }
    pub fn key_not_exportable(message: impl Into<String>) -> Self { .. }
    pub fn operation(message: impl Into<String>) -> Self { .. }
    pub fn unknown_operation(message: impl Into<String>) -> Self { .. }
    pub fn unsupported(message: impl Into<String>) -> Self { .. }
    pub fn param(message: impl Into<String>, param_name: impl Into<String>) -> Self { .. }
    pub fn crypto(message: impl Into<String>) -> Self { .. }
    pub fn user_abort(message: impl Into<String>) -> Self { .. }
    /// R0 skeleton stub error: Generic, message `not implemented (<loop>)`, e.g. "not implemented (R4)".
    pub fn not_implemented(owner_loop: &str) -> Self { .. }

    // Field accessors (None when the kind does not carry the field):
    pub fn param_name(&self) -> Option<&str> { .. }
    pub fn ckr(&self) -> Option<(u64, &str)> { .. }
    pub fn candidates(&self) -> Option<&[KeyRef]> { .. }
    pub fn parse_position(&self) -> Option<(&str, usize)> { .. }
}

/// Display = `message` only (c2 `str(exc)`); the hint is rendered separately.
impl fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.message) }
}
impl std::error::Error for ConsoleError {}

pub type Result<T> = std::result::Result<T, ConsoleError>;
```

`r2_core` re-exports `ConsoleError`, `ErrorKind` and `Result` at the crate root (full list: §4.1.3).

Normative rules:

- Every PKCS#11 failure is translated at the single choke point r2-pkcs11's `crate::ckr` (§4.5.6)
  into `Pkcs11` by default, `AuthRequired` / `UnsupportedOperation` for the CKR codes the
  §5.2 table maps that way, and `ProviderUnavailable` for library-load failures and for
  any CKR of `C_Initialize` other than `CKR_CRYPTOKI_ALREADY_INITIALIZED` (§5.2).
- No `From<std::io::Error>` exists: I/O failures become `DataIo`/`Config` with the c2
  message, which embeds the path and `text::os_error_text(&err)` where c2 wrote
  `{exc.strerror or exc}`, or `text::py_os_error_str(&err, path)` where c2 wrote `{exc}`
  / `{err}` of an `OSError` (e.g. "cannot open log file {path}: {err}", the wizard's
  "cannot create the SoftHSM configuration: {err}").
- A port of a c2 catch-all (`except ConsoleError`, `except Exception` around provider or
  IO calls — e.g. ops/params.py's KEYREF/BYTES wrapping, keys_cmd.py `_edit_sibling`,
  transfer.py `_destroy_quietly`, the wizard's softhsm2-util fallback) never swallows or
  rewraps `UserAbort`: it returns it unchanged (`err.kind.is_user_abort()`), because c2's
  Ctrl-C was a `KeyboardInterrupt`, outside `ConsoleError`. Porting note for tests:
  `pytest.raises(ProviderError | KeyLookupError | OperationError)` becomes the family
  predicate (`is_provider()` / `is_key_lookup()` / `is_operation()`), never `kind ==`.
- OpenSSL `ErrorStack` text (which embeds build-specific file:line) is never put into a
  message; where c2 appended a pyca exception text (`"…failed: {exc}"`) r2 appends
  `ErrorStack::errors()[0].reason()` (or an r2 text) — §11 D11, a deviation for the detail
  suffix only (S0 spike 2 §9). Texts that r2 pre-validates are pyca-verbatim (§4.4).
- A panic is never an error path: an unexpected panic inside a command is caught by the
  REPL (§4.9.5) and rendered like c2's "unexpected error" branch.

```rust
// crates/r2-core/src/text.rs — message-parity helpers used by every loop
/// Python `repr(str)` of CPython 3.12 (c2's interpreter; Unicode 15.0.0): single quotes
/// unless the text contains `'` and no `"`; escapes `\\`, the chosen quote, `\n` `\r` `\t`,
/// and every other code point for which CPython's `str.isprintable()` is false as
/// `\xNN` / `\uNNNN` / `\UNNNNNNNN` (lower-case hex). The non-printable set (categories
/// Cc, Cf, Cs, Co, Cn, Zl, Zp, Zs except U+0020 — 712 ranges at Unicode 15.0) is a static
/// range table committed in this file, generated once from CPython
/// (`not chr(c).isprintable()`); `char::is_control` is NOT a substitute. Every c2 message
/// written `{x!r}` uses this.
pub fn py_repr(text: &str) -> String { .. }
/// Python `repr(bytes)`: `b'…'` with the same quote choice, `\\`, `\t` `\n` `\r`,
/// printable ASCII 0x20..=0x7E verbatim, everything else `\xNN`.
pub fn py_bytes_repr(data: &[u8]) -> String { .. }
/// Python `str(bool)`: "True" / "False".
pub fn py_bool(value: bool) -> &'static str { .. }
/// Python `OSError.strerror` equivalent: `err.to_string()` without the trailing
/// " (os error N)" (c2 messages use `{exc.strerror or exc}`).
pub fn os_error_text(err: &std::io::Error) -> String { .. }
/// Python `str(OSError)` for a one-path error: "[Errno {n}] {strerror}: {py_repr(path)}"
/// (e.g. "[Errno 13] Permission denied: '/p'"); without a raw OS error code →
/// `os_error_text(err)`. (Windows prints `[WinError n]` for some calls in CPython; r2 always
/// uses the POSIX form — D18.)
pub fn py_os_error_str(err: &std::io::Error, path: &std::path::Path) -> String { .. }
/// Python `str.isspace()` for one char (`char::is_whitespace` plus U+001C..=U+001F).
pub fn is_py_space(c: char) -> bool { .. }
/// Python `str.strip()` (no argument): trims leading/trailing chars where `is_py_space`.
/// Every c2 `.strip()` site — including ParamResolver's "trimmed" — uses this, never
/// `str::trim` (which keeps U+001C..=U+001F).
pub fn py_strip(text: &str) -> &str { .. }
/// Python `bytes.fromhex`: pairs of hex digits (either case); ASCII whitespace is skipped
/// BETWEEN pairs only ("0a 1b" ok, "0 a" invalid); None on any error. c2 uses it in
/// `--id` parsing, config/template-file `0x…` values and the template editor.
pub fn py_fromhex(text: &str) -> Option<Vec<u8>> { .. }
/// Python `int(text, radix)` for radix 10 or 16: strip CPython `int()`'s whitespace first
/// (`py_strip`'s set minus U+001C..=U+001F, which `int()` keeps), optional `+`/`-`, for
/// radix 16 an optional `0x`/`0X` prefix (which may be followed by one `_`), digits with
/// single `_` separators between digits; ASCII digits only (CPython also accepts other
/// Unicode decimal digits — D18). None on any error or outside i128.
pub fn py_int(text: &str, radix: u32) -> Option<i128> { .. }
/// Python `str.isdigit()` as c2 uses it to gate `int()`: non-empty and every char an ASCII
/// digit `0`-`9` (no sign, no `_`, no whitespace — the caller strips first). CPython also
/// accepts other Unicode digits (superscripts, where c2's following `int()` then raised —
/// §11 D18). Used by `ConsoleIo::select` answers and template-editor row numbers, never
/// `py_int` there (which would accept "+2", "1_0", "-0").
pub fn py_isdigit(text: &str) -> bool { .. }
/// Python `pathlib.Path(text)` lexical normalization (PurePosixPath rules): repeated `/`
/// collapse to one; `.` components are dropped, including a leading one (`./x` → `x`,
/// `a/./b/` → `a/b`); a trailing `/` is dropped; exactly two leading slashes are kept
/// (`//x`), three or more become one (`///x` → `/x`); `..` is kept verbatim; empty → `.`.
/// Windows: the same rules with both `/` and `\` as separators and `\` as the output
/// separator; a drive (`C:`) or UNC/verbatim prefix (`\\server\share`, `\\?\`) is kept as
/// typed (PureWindowsPath differences there: §11 D22). Binding at every c2 `Path(x)` site:
/// every CLI path option and positional (`--in`, `--out`, `--sig-file`, `--template`,
/// export/csr/`key template` paths, file-backed `load` data), `--config`, `$R2_CONFIG`,
/// `$SOFTHSM2_LIB`, and every config `PathBuf` field (through `dirs::expand_user`). So every
/// message, `DataInput.origin` and `config show` value shows c2's normalized form
/// (`wrote 3 bytes to out.bin` for `--out ./out.bin`).
pub fn py_path(text: &str) -> std::path::PathBuf { .. }
/// `difflib.get_close_matches(word, possibilities, n, cutoff=0.6)` of CPython 3.12, exactly:
/// for each candidate compute SequenceMatcher(None, candidate, word).ratio() (seq1 =
/// candidate, seq2 = word; same matching-block algorithm as CPython, autojunk irrelevant
/// for these lengths) as f64; keep ratio >= 0.6; order by (ratio descending, candidate
/// descending) — `heapq.nlargest` over (score, word) tuples — and take n. The result
/// therefore does not depend on the order of `possibilities`. The `difflib` crate's
/// `get_close_matches` is NOT used (it keeps ties in input order); its `SequenceMatcher`
/// may compute the ratio. R1 vectors (generated with CPython): 'sha' over
/// sha1/224/256/384/512 → sha1, sha512, sha384; 'ebc' and 'cb' over the AES cli names →
/// ecb, cbc; over the command names: 'decrept' → decrypt, encrypt, derive; 'aecrypt' →
/// encrypt, decrypt; 'cps' → ops, csr.
pub fn close_matches(word: &str, possibilities: &[&str], n: usize) -> Vec<String> { .. }
```

Case-folding rule: where c2 calls `str.lower()`/`.upper()` (the `keys` filter, `--mech`,
BOOL words, the template editor's `0X` prefix), r2 uses `str::to_lowercase` /
`to_uppercase` (Unicode, like Python), never the ASCII variants.

### 4.3 Key model (`r2_core::keys`)

Canonical interchange formats — the ONLY byte formats that cross the provider boundary
(unchanged from c2):

| Kind | Format |
|---|---|
| AES / secret | raw key bytes |
| generic secret | raw key bytes (CKK_GENERIC_SECRET; any length ≥ 1 byte) |
| private key | DER PKCS#8 (unencrypted) |
| public key | DER SubjectPublicKeyInfo |
| certificate | DER X.509 |
| data object | raw bytes (CKO_DATA `CKA_VALUE`, opaque) |

```rust
// crates/r2-core/src/keys.rs
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use zeroize::Zeroizing;

use crate::error::{ConsoleError, Result};
use crate::template::AttrValue;

/// Object class. Token (Display/FromStr, exact, lower-case): "secret" | "private" |
/// "public" | "certificate" | "data". Ord = declaration order — NOT c2's text order: where
/// c2 sorts class values for a message (e.g. wrapload's "needs a certificate or public …
/// KEK" = `' or '.join(sorted(c.value …))`), r2 sorts by `as_str()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyClass {
    Secret,
    Private,
    Public,
    Certificate,
    /// CKO_DATA: opaque bytes, algorithm `None`, never a CKA_ID.
    Data,
}

impl KeyClass {
    pub const ALL: [KeyClass; 5] =
        [KeyClass::Secret, KeyClass::Private, KeyClass::Public, KeyClass::Certificate, KeyClass::Data];
    /// "secret" | "private" | "public" | "certificate" | "data".
    pub fn as_str(self) -> &'static str { .. }
    /// Short ref-selector token, the form `display_refs` emits (c2 CLASS_TOKENS):
    /// Private→"priv", Public→"pub", Certificate→"cert", Secret→"secret", Data→"data".
    pub fn token(self) -> &'static str { .. }
    /// Python `str()` of the c2 enum member, e.g. "KeyClass.PRIVATE" (FakeProvider call log).
    pub fn py_name(self) -> &'static str { .. }
    /// Symbolic CKO name: CKO_SECRET_KEY, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_CERTIFICATE, CKO_DATA.
    pub fn cko_symbol(self) -> &'static str { .. }
    /// True for Secret/Private/Public (the classes that carry CKA_KEY_TYPE).
    pub fn has_key_type(self) -> bool { .. }
}
impl fmt::Display for KeyClass { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { .. } }
/// Exact tokens only; anything else → Generic "unknown key class {s!r}".
impl FromStr for KeyClass { type Err = ConsoleError; fn from_str(s: &str) -> Result<Self> { .. } }

/// Token: "aes" | "rsa" | "ec" | "ec-edwards" | "ec-montgomery" | "generic" | "none" | "other".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyAlgorithm {
    Aes,
    Rsa,
    /// Weierstrass curves (CKK_EC).
    Ec,
    /// Ed25519 / Ed448 (CKK_EC_EDWARDS).
    EcEdwards,
    /// X25519 / X448 (CKK_EC_MONTGOMERY).
    EcMontgomery,
    /// CKK_GENERIC_SECRET (HMAC keys); CKK_SHA*_HMAC key types fold here on read.
    Generic,
    /// Data objects carry no algorithm. Always written qualified (`KeyAlgorithm::None`).
    None,
    /// PKCS#11 key type r2 cannot model — listing/info/delete/edit only, never operated on.
    Other,
}

impl KeyAlgorithm {
    pub fn as_str(self) -> &'static str { .. }
    /// e.g. "KeyAlgorithm.EC_EDWARDS" (FakeProvider call log).
    pub fn py_name(self) -> &'static str { .. }
    /// CKK_AES, CKK_RSA, CKK_EC, CKK_EC_EDWARDS, CKK_EC_MONTGOMERY, CKK_GENERIC_SECRET;
    /// None for `None`/`Other`.
    pub fn ckk_symbol(self) -> Option<&'static str> { .. }
    /// False for `None` and `Other` (c2 NON_CREATABLE_ALGORITHMS).
    pub fn is_creatable(self) -> bool { .. }
    /// Ec | EcEdwards | EcMontgomery (the keyparse "ec" hint family).
    pub fn is_ec_family(self) -> bool { .. }
}
impl fmt::Display for KeyAlgorithm { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { .. } }
/// Exact tokens only; anything else → Generic "unknown key algorithm {s!r}".
impl FromStr for KeyAlgorithm { type Err = ConsoleError; fn from_str(s: &str) -> Result<Self> { .. } }

/// Curve names (c2 `curve: str`). Token: "p256" "p384" "p521" "ed25519" "ed448" "x25519"
/// "x448". `Other(name)` exists only for parity with c2's keyparse/memory classifier, which
/// reports the other Weierstrass curves pyca 49 supports by pyca's lower-cased name:
/// "secp192r1", "secp224r1", "secp256k1", "brainpoolp256r1", "brainpoolp384r1",
/// "brainpoolp512r1" (the exact set, §4.4.3); it is never produced by FromStr.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Curve { P256, P384, P521, Ed25519, Ed448, X25519, X448, Other(String) }

impl Curve {
    /// The seven modelled curves, in the order above (generate/curve completion order).
    pub const KNOWN: [Curve; 7] =
        [Curve::P256, Curve::P384, Curve::P521, Curve::Ed25519, Curve::Ed448, Curve::X25519, Curve::X448];
    pub fn as_str(&self) -> &str { .. }
    /// P*/Other → Ec, Ed* → EcEdwards, X* → EcMontgomery.
    pub fn algorithm(&self) -> KeyAlgorithm { .. }
    /// Fixed scalar/field width in bytes: p256 32, p384 48, p521 66, ed25519 32, ed448 57,
    /// x25519 32, x448 56; Other: secp192r1 24, secp224r1 28, secp256k1 32, brainpoolp256r1
    /// 32, brainpoolp384r1 48, brainpoolp512r1 64 (= ceil(curve bits / 8), c2's
    /// `(curve.key_size + 7) // 8`); None for any other name. ECDSA r‖s halves use this
    /// width on every curve (§4.5.4).
    pub fn field_bytes(&self) -> Option<usize> { .. }
}
impl fmt::Display for Curve { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { .. } }
/// The seven tokens only (case-sensitive); else Generic "unknown curve {s!r}".
impl FromStr for Curve { type Err = ConsoleError; fn from_str(s: &str) -> Result<Self> { .. } }

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyRef {
    /// Provider instance name.
    pub provider: String,
    /// CKA_LABEL / memory key name.
    pub label: String,
    /// CKA_ID; disambiguates duplicate labels. Always None for data objects.
    /// Invariant: never `Some(empty)`. Every provider maps a zero-length CKA_ID to None when
    /// it builds a KeyInfo (c2 `self._attr_bytes(id_v) or None` — the normal case for
    /// objects created by pkcs11-tool/softhsm2-util without `--id`; MemoryProvider and
    /// FakeProvider normalize an empty `key_id` argument the same way), and `--id`
    /// rejects an empty value (c2 "key id must not be empty"), so
    /// `display()` never emits "prov:label#" (which `parse_ref` rejects) and the
    /// keypair-family collapse never sees `Some([])` ≠ `None`.
    pub key_id: Option<Vec<u8>>,
}
impl KeyRef {
    pub fn new(provider: impl Into<String>, label: impl Into<String>, key_id: Option<Vec<u8>>) -> Self { .. }
    /// "prov:label" or "prov:label#0a1b" (id lower-case hex).
    pub fn display(&self) -> String { .. }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    pub key_ref: KeyRef,
    pub key_class: KeyClass,
    /// For CERTIFICATE: the algorithm of the embedded public key.
    pub algorithm: KeyAlgorithm,
    /// AES/generic key bits, RSA modulus bits, data value bits (8·len); None otherwise
    /// (always None for EC-family keys).
    pub size_bits: Option<u32>,
    pub curve: Option<Curve>,
    /// Certificates, public keys and data objects: always true. OTHER: always false.
    /// PKCS#11 secret/private: CKA_EXTRACTABLE ∧ ¬CKA_SENSITIVE (§5.5).
    pub exportable: bool,
    /// Read-only provider extras (CKA_* snapshot). PKCS#11 secret/private keys always
    /// carry Bool CKA_SENSITIVE and CKA_EXTRACTABLE (§5.5 guarantee); OTHER carries
    /// Symbol CKA_KEY_TYPE (`catalog::ckk_symbol` of the actual key type, or "unknown" when
    /// unreadable); certificates carry, on PKCS#11 (`x509info::cert_attributes`), Str
    /// CKA_SUBJECT / CKA_ISSUER (RFC 4514 display strings) and CKA_SERIAL_NUMBER (lower-case
    /// hex), and in memory (`x509info::memory_cert_attributes`, c2 `_cert_attributes`) Str
    /// "subject", "issuer", "serial_number", "not_valid_before", "not_valid_after";
    /// data objects may carry Str CKA_APPLICATION / Bytes CKA_OBJECT_ID.
    pub attributes: BTreeMap<String, AttrValue>,
    /// Provider-native object handle (PKCS#11: the numeric CK_OBJECT_HANDLE). Rendered as
    /// the session-transient `@<handle>` selector and the `key info` "handle" row; used by
    /// Pkcs11Provider to re-target the EXACT object among same-label/id/class twins (no
    /// unique match → AmbiguousKey, never a silent first match). Memory: None.
    pub handle: Option<u64>,
}

/// Parsed key material in a §4.3 canonical format. `Debug` is implemented by hand and
/// prints `data` as `"<N bytes>"` (key bytes never reach logs or panic messages).
#[derive(Clone, PartialEq, Eq)]
pub struct KeyMaterial {
    pub algorithm: KeyAlgorithm,
    pub key_class: KeyClass,
    pub data: Zeroizing<Vec<u8>>,
    pub curve: Option<Curve>,
    pub size_bits: Option<u32>,
    /// Suggested label (certificate CN, PKCS#12 friendly name).
    pub label_hint: Option<String>,
}
impl KeyMaterial {
    /// curve/size_bits/label_hint = None.
    pub fn new(algorithm: KeyAlgorithm, key_class: KeyClass, data: Vec<u8>) -> Self { .. }
}
impl fmt::Debug for KeyMaterial { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { .. } }

/// Decomposed key reference — output of `parse_ref`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedRef {
    pub provider: String,
    pub label: String,
    pub key_id: Option<Vec<u8>>,
    pub key_class: Option<KeyClass>,
    pub handle: Option<u64>,
}

/// Ref-grammar class selector tokens (matched case-insensitively), c2 CLASS_SELECTORS order.
pub const CLASS_SELECTORS: [(&str, KeyClass); 8] = [
    ("priv", KeyClass::Private),
    ("private", KeyClass::Private),
    ("pub", KeyClass::Public),
    ("public", KeyClass::Public),
    ("cert", KeyClass::Certificate),
    ("certificate", KeyClass::Certificate),
    ("secret", KeyClass::Secret),
    ("data", KeyClass::Data),
];

/// Case-insensitive lookup in CLASS_SELECTORS.
pub fn class_selector(token: &str) -> Option<KeyClass> { .. }

/// THE ref-grammar parser (never reimplemented; ProviderRegistry::resolve_ref and the
/// `--kek` resolver use it). `'prov:label#0a1b:priv@7'` →
/// `ParsedRef{provider:"prov", label:"label", key_id:Some([0x0a,0x1b]), key_class:Some(Private), handle:Some(7)}`.
pub fn parse_ref(reference: &str) -> Result<ParsedRef> { .. }

/// Listing refs made unambiguous; see rules below.
pub fn display_refs(infos: &[KeyInfo]) -> Vec<String> { .. }
```

**Ref grammar** (normative, c2 §4.3): `<provider>:<label>[#<id-hex>][:<class>][@<handle>]`.
Provider names are identifiers `[A-Za-z_][A-Za-z0-9_-]*` (ASCII; enforced by config
validation too). Algorithm of `parse_ref` (positions are byte offsets; every error is
`Parse { line: reference, pos }`):

1. The first `:` splits provider from the rest. None → "key reference is missing ':'"
   (pos = len). Empty provider → "missing provider name" (pos 0). Bad first char →
   "invalid provider name start {c!r}" (pos 0); bad later char → "invalid character {c!r}
   in provider name" (pos = its offset); both with hint "provider names match
   [A-Za-z_][A-Za-z0-9_-]*". Other errors carry hint
   "expected '<provider>:<label>[#<id-hex>][:<class>][@<handle>]'" unless stated.
2. Selectors are stripped right to left. A trailing `@<ASCII digits>` after the first `:`
   is the handle. (r2: digits that overflow u64 → "handle out of range" at the `@`+1
   offset; c2 accepted arbitrary integers — §11 D18.)
3. With a `#` after the first `:` (the LAST `#` before the handle): label = text between
   `:` and `#`; the id segment may carry ONE `:<class>` (ids never contain `:`, so an
   unrecognised token there is an error: "unknown class selector {token!r}" at the token
   offset, hint "class is one of priv, pub, cert, secret, data (long forms
   private/public/certificate too)").
4. Without `#`: a trailing `:<class>` is a selector ONLY when the token is recognised
   (case-insensitive); otherwise the label keeps its `:`/`#` characters.
5. Empty label → "missing key label" (pos = first `:` + 1). Empty id → "empty key id
   after '#'" (pos = `#` + 1). Non-hex id char → "invalid hex digit {c!r} in key id"
   (its offset; hint "the id after '#' is lowercase hex, e.g. #0a1b"; upper case is
   accepted). Odd length → "odd number of hex digits in key id" (pos = end of the id; hint
   "the id after '#' encodes whole bytes (2 hex digits each)").

Documented carve-out: a literal label ending in a class token or `@<digits>` needs an
explicit `#id`.

**`display_refs`** (normative): `key_ref.display()` per info; displays that occur more than
once get a `:<class token>` suffix; displays that still collide (same label/id/class) get
an additional `@<handle>` suffix when the info has a handle. Every emitted form parses via
`parse_ref`. Used by the `keys` table, ref completion and the AmbiguousKey message. NOT
used by `key info`'s `related: …` line, which always prints `{ref.display()}:{class
token}` for each family member (same label and id, other class), in `list_keys()` order
(c2 keys_cmd.py).

**`handle_int`**: n/a (Python-only — `KeyInfo.handle` is already `Option<u64>`, so c2's
"never repr() a live PyKCS11 handle" hazard cannot occur).

**Certificate rules.** Certificates are provider objects like keys (memory: stored
certificate; PKCS#11: `CKO_CERTIFICATE` with `CKA_CERTIFICATE_TYPE=CKC_X_509`,
`CKA_VALUE`=DER, `CKA_SUBJECT`, `CKA_ISSUER`, `CKA_SERIAL_NUMBER`, `CKA_ID`, `CKA_LABEL`).
A CERTIFICATE passed to `encrypt`/`verify`/`wrap_key` is resolved to its public key by the
provider (memory: the certificate's public key; PKCS#11: a `CKO_PUBLIC_KEY` with the same
`CKA_ID`, else a **session** public-key object created from the certificate's SPKI).
Certificates are always exportable; passing one to `decrypt`/`sign`/`derive` →
`UnsupportedOperation`.

**Generic secrets, data objects, OTHER.** A generic secret is SECRET@GENERIC of any length
≥ 1 byte; it signs/verifies with `HMAC` only and otherwise follows the AES-secret rules
(§5.5 exportable/wrappable, copy and `--kek` routes). A data object is DATA@NONE: opaque
`CKA_VALUE` bytes that are listed, loaded, exported (raw), copied (plain route) and
deleted, never used by a crypto verb or wrap (`UnsupportedOperation`). Data objects carry
**no CKA_ID**: `key_ref.key_id` is None; every provider returns `Param` when a key id is
given for one, and the PKCS#11 provider also when an enabled template `CKA_ID` row is
(MemoryProvider ignores template identity rows on a data import, as c2's memory did); the §4.7 twin guard compares (class,
label); `size_bits = 8·len(value)`; optional `CKA_APPLICATION` (Str) / `CKA_OBJECT_ID`
(Bytes) appear in `attributes` and are set through the template editor. Documented edge: a
data object sharing a keypair's label makes the bare ref ambiguous — use `:data`. OTHER
is the PKCS#11 read-path catch-all for key types r2 cannot model (DES3, vendor types):
listed by `keys`/`key info` (with `attributes["CKA_KEY_TYPE"]` = Symbol of the actual CKK
name), deletable and editable; export/copy/`--kek`/crypto verbs/`key template` →
`UnsupportedOperation`; create flows never accept NONE (outside DATA) or OTHER material
(`Param`). Unknown CKO classes stay hidden (§10).

### 4.4 Input codec, data I/O, key parsing, X.509 and format helpers (`r2_core`)

Byte buffers that may hold key material or plaintext are `Zeroizing<Vec<u8>>` (D3); they
deref to `Vec<u8>`, so consumers of non-secret data are unaffected.

#### 4.4.1 `r2_core::codec`

```rust
use zeroize::Zeroizing;
use crate::error::Result;

/// `decode_data` outcomes only. Token (`as_str()` only; no Display/FromStr): "hex" |
/// "base64" | "pem".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputFormat { Hex, Base64, Pem }
impl InputFormat { pub fn as_str(self) -> &'static str { .. } }

/// Decode operator-pasted data (algorithm below). Errors → Codec (with hint).
pub fn decode_data(text: &str) -> Result<(Zeroizing<Vec<u8>>, InputFormat)> { .. }

/// Grouped lower-case hex for console display. `group` = bytes per space-separated group
/// (0 → continuous); `width` = bytes per line (0 → one line). Empty input → "".
/// Defaults are ui.hex_group=2 / ui.hex_width=32.
pub fn format_hex(data: &[u8], group: usize, width: usize) -> String { .. }
```

`decode_data` detection order (frozen, c2 verbatim; "whitespace" = `text::is_py_space`):

1. Strip leading/trailing whitespace. Explicit prefix wins: `hex:` or `0x` → hex; `b64:` →
   base64; `pem:` → PEM. Prefixed content is whitespace-normalized before the forced
   decode (for `pem:` inside the PEM re-wrapper, per block body, so RFC 1421 header spaces
   survive). Prefix + failure = error, no fallback: "hex prefix given but no data follows";
   "forced hex decode failed" (hint "hex is an even number of [0-9a-fA-F] digits
   (whitespace ignored)"); "b64 prefix given but no data follows"; "forced base64 decode
   failed" (hint "base64 uses [A-Za-z0-9+/] with '=' padding to a multiple of 4").
2. If `-----BEGIN ` occurs anywhere in the (unstripped) text → PEM.
3. Remove ALL whitespace. Empty → "empty input" (hint "paste hex, base64 or PEM data").
4. `^[0-9A-Fa-f]+$` with even length → hex; if the bytes start with `-----BEGIN` →
   re-parse as PEM ("data looks like hex-wrapped PEM but is not ASCII text" if not ASCII).
5. `^[A-Za-z0-9+/]+={0,2}$` with length % 4 == 0 → base64 (standard alphabet, padding
   required, **non-zero trailing bits accepted** — Python `binascii` parity, i.e. a
   `base64` GeneralPurpose engine with `with_decode_allow_trailing_bits(true)`); a
   decode failure falls through to step 6; decoded bytes starting with `-----BEGIN` →
   re-parse as PEM ("data looks like base64-wrapped PEM but is not ASCII text").
6. "not hex, base64 or PEM" (hint "force with hex:/b64:/pem: prefix").

PEM branches return the **re-wrapped PEM text as bytes** (never DER): every
`-----BEGIN L----- … -----END L-----` block (labels `[A-Za-z0-9][A-Za-z0-9 ]*`, minimal
match, `.` matches newlines) is kept in order; RFC 1421 encapsulated header lines
(`^[A-Za-z][A-Za-z0-9-]*:` at the start of the body, up to the first blank line —
`Proc-Type:`/`DEK-Info:` of traditional encrypted PEM) are preserved, followed by one blank
line; the base64 body has all whitespace removed, is validated, and is re-wrapped at 64
columns; blocks are joined with `\n` and the result ends with `\n`. Errors: "malformed
PEM: no complete BEGIN/END block found" (hint "a PEM block is '-----BEGIN <LABEL>----- …
-----END <LABEL>-----'"); "malformed PEM: 'BEGIN {b}' closed by 'END {e}'"; "malformed
PEM: the {label} block has encapsulated headers but no base64 body" (hint "paste the block
with its line breaks intact"); "malformed PEM: body of the {label} block is not valid
base64". Documented UX rule: hex beats base64 for ambiguous strings like `deadbeef` — use
`b64:` to force base64.

#### 4.4.2 `r2_core::datainput`

```rust
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use zeroize::Zeroizing;
use crate::error::{ConsoleError, Result};
use crate::io::ConsoleIo;

/// Token: "auto" | "raw" | "hex" | "b64".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InFormat { #[default] Auto, Raw, Hex, B64 }
/// Token: "raw" | "hex" | "b64" (the `--outformat` values).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutFormat { #[default] Raw, Hex, B64 }

impl InFormat { pub fn as_str(self) -> &'static str { .. } }
impl fmt::Display for InFormat { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { .. } }
/// Exact tokens; else Generic "unknown format {s!r}".
impl FromStr for InFormat { type Err = ConsoleError; fn from_str(s: &str) -> Result<Self> { .. } }
impl OutFormat { pub fn as_str(self) -> &'static str { .. } }
impl fmt::Display for OutFormat { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { .. } }
/// Exact tokens; else Generic "unknown format {s!r}".
impl FromStr for OutFormat { type Err = ConsoleError; fn from_str(s: &str) -> Result<Self> { .. } }

/// `Debug` by hand: `token` (the pasted payload — possibly key material or plaintext) is
/// shown as `Some("<N chars>")`.
#[derive(Clone, PartialEq, Eq)]
pub struct DataInput {
    /// "inline" | the file path as displayed — for messages.
    pub origin: String,
    /// Inline form only.
    pub token: Option<String>,
    /// File form only.
    pub path: Option<PathBuf>,
    pub fmt: InFormat,
}
impl DataInput {
    pub fn inline(token: impl Into<String>) -> Self { .. }
    pub fn file(path: impl Into<PathBuf>, fmt: InFormat) -> Self { .. }
    /// inline → decode_data; file raw → bytes verbatim; file hex/b64 → forced decode of the
    /// ASCII text (non-ASCII → Codec "{path}: file is not text, cannot decode as {fmt}",
    /// hint "use --format raw for binary files"); file auto → when the content is ASCII
    /// and every char is printable (0x20..=0x7E) or \t \r \n AND decode_data succeeds, the
    /// decoded bytes; otherwise the raw bytes. Read failure → DataIo
    /// "cannot read {path}: {os_error_text}". Neither token nor path → DataIo
    /// "data input has neither an inline token nor a file path".
    pub fn resolve(&self) -> Result<Zeroizing<Vec<u8>>> { .. }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataOutput {
    /// None = console.
    pub path: Option<PathBuf>,
    pub fmt: OutFormat,
    /// Console rendering (from ui config).
    pub hex_group: usize,
    pub hex_width: usize,
}
impl DataOutput {
    pub fn console(group: usize, width: usize) -> Self { .. }
    /// hex_group = 2, hex_width = 32.
    pub fn file(path: impl Into<PathBuf>, fmt: OutFormat) -> Self { .. }
    /// Console → `io.print(Renderable::Text(format_hex(data, group, width)))`. File: Raw →
    /// bytes verbatim; Hex → continuous lower-case hex + "\n"; B64 → standard base64 + "\n".
    /// Write failure → DataIo "cannot write {path}: {os_error_text}".
    pub fn write(&self, data: &[u8], io: &dyn ConsoleIo) -> Result<()> { .. }
}
```

#### 4.4.3 `r2_core::keyparse` (pure; passwords via callback)

```rust
use std::str::FromStr;
use secrecy::SecretString;
use crate::error::{ConsoleError, Result};
use crate::keys::KeyMaterial;

/// Type hint of `parse_key_material` (c2's frozen hint set). Token: "auto" | "aes" | "rsa" |
/// "ec" | "cert".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyHint { #[default] Auto, Aes, Rsa, Ec, Cert }
impl KeyHint { pub fn as_str(self) -> &'static str { .. } }
/// Exact tokens; else KeyParse "unknown key material hint {s!r}" (hint "valid hints: auto,
/// aes, rsa, ec, cert").
impl FromStr for KeyHint { type Err = ConsoleError; fn from_str(s: &str) -> Result<Self> { .. } }

/// Password source. Argument = prompt text ("Password for encrypted {PEM label}",
/// "Password for encrypted private key", "Password for PKCS#12"). It may fail (e.g.
/// UserAbort from a prompt); the error propagates unchanged.
pub type PasswordCallback<'a> = &'a mut dyn FnMut(&str) -> Result<SecretString>;

/// Sniff and parse key material. Errors → KeyParse (listing attempted formats).
pub fn parse_key_material(
    data: &[u8],
    hint: KeyHint,
    password: Option<PasswordCallback<'_>>,
) -> Result<Vec<KeyMaterial>> { .. }
```

Normative behavior (c2 §4.4 + S0 spike 2):

- Order: PEM header dispatch when the bytes contain `-----BEGIN ` (labels `PRIVATE KEY`,
  `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `PUBLIC KEY`,
  `CERTIFICATE`, `CERTIFICATE REQUEST`; every block of a bundle, in order; other labels →
  "unsupported PEM block type {label!r}" with hint "supported PEM blocks: PRIVATE KEY,
  ENCRYPTED PRIVATE KEY, RSA/EC PRIVATE KEY, PUBLIC KEY, CERTIFICATE, CERTIFICATE REQUEST")
  → DER try-chain when `data[0] == 0x30` → raw AES when the hint is auto/aes and
  `len ∈ {16, 24, 32}` → "could not parse key material (attempted: PEM, DER (PKCS#8, SPKI,
  PKCS#1, SEC1, X.509, CSR, PKCS#12), raw AES (16/24/32 bytes))" (hint "supported inputs:
  PEM/DER keys, certificates, CSRs, PKCS#12, raw AES keys of 16/24/32 bytes"). Empty data
  → "empty key material".
- DER try-chain (this order): pyca's `load_der_private_key` (PKCS#8 → SEC1 → PKCS#1
  RSAPrivateKey → DSA; an EncryptedPrivateKeyInfo is its TypeError, which prompts) → pyca's
  `load_der_public_key` (SPKI, else a PKCS#1 RSAPublicKey — pyca accepts it, so c2 does) →
  X.509 → CSR → PKCS#12 sniff (`SEQUENCE { INTEGER 3, … }`) + `Pkcs12::from_der`. Key
  material is read by a port of pyca 49's own parsers (`cryptography-key-parsing` over a
  port of rust-asn1 0.24: strict DER — one TLV, minimal definite lengths of at most 4
  bytes, nothing after it —, unsigned minimal INTEGERs for versions and key components,
  `AlgorithmIdentifier` parameters per pyca's DEFINED BY table: NULL or absent for RSA and
  the hashes, absent for Ed/X25519/448 and ECDSA signatures, an `EcParameters` CHOICE for
  EC, the PBES1/PBES2/PBKDF2/scrypt/cipher structures, one optional TLV for other OIDs, an
  encoded DEFAULT refused), and keys are BUILT from their components with OpenSSL
  (`Rsa::from_private_components`, `EcKey::from_private_components`,
  `PKey::private_key_from_raw_bytes`, …); OpenSSL's key DER decoders are not used. pyca's
  checks therefore apply: PrivateKeyInfo { version 0 only, AlgorithmIdentifier, OCTET
  STRING, [0] IMPLICIT Attributes OPTIONAL } (no OneAsymmetricKey [1] publicKey); SEC1
  ECPrivateKey version 1, the PKCS#8 and inner curve parameters equal when both present,
  the private value exactly the order's byte length ("EC private key is not encoded
  properly: private key value is too short. …"), the [1] public point the private key's
  (`EC_KEY_check_key`); RSAPrivateKey version 0 without otherPrimeInfos (multi-prime RSA
  is refused); RSA/RSAPublicKey integers non-negative; a parse error tries the next
  format, any other refusal ends the private step ("Invalid key" and the other pyca
  texts). A failing key step falls through (DER) or is "malformed …" (PEM) without a
  prompt. Certificates and CSRs are read by `x509info`'s strict pyca-style parser ALONE
  (§4.4.5) — OpenSSL's `X509`/`X509Req` decoders are not consulted (they refuse Name value
  encodings pyca loads, e.g. a VisibleString or OCTET STRING CN, or a BMPString with a
  non-BMP character). A certificate (CSR) whose only fault is pyca's InvalidVersion (not a
  ValueError: c2 crashed) → KeyParse "certificate is not valid DER X.509: {n} is not a
  valid X509 version" ("certificate request is not valid DER X.509: {n} is not a valid CSR
  version") instead of the next step (§11 D12(b)).
- PEM blocks (each `_PEM_BLOCK_RE` match c2 hands to pyca) are decoded by keyparse with a
  port of the `pem` 3.0 crate pyca 49 uses: BEGIN tag up to the next `-----`, `[ \t\r\n]*`
  skipped, payload up to the first `-----END ` (the crate's naive marker search, so
  `------END` is not found), split at the first `\n\n` (else `\r\n\r\n`) into header
  lines and data, END tag up to the next `-----`; the RAW tags must be equal; every header
  line must contain `:`; the data is STANDARD base64 after removing all Unicode whitespace.
  Failures → "malformed {label} PEM block: Unable to load PEM file. See
  https://cryptography.io/en/latest/faq/#why-can-t-i-import-my-pem-file for more details.
  {PemError:?}" (pyca's text, e.g. `MismatchedTags("PUBLIC KEY", "PUBLIC KEY ")`,
  `InvalidHeader("MIG…")`, `InvalidData(InvalidByte(3, 58))`, `MalformedFraming`). A raw
  tag that is not exactly the label (c2 compared stripped labels) → pyca's "Valid PEM but no
  BEGIN/END delimiters for a private key found. Are you sure this is a private key?" /
  "… no BEGIN PUBLIC KEY/END PUBLIC KEY delimiters. Are you sure this is a public key?" /
  "… no BEGIN CERTIFICATE/END CERTIFICATE delimiters. Are you sure this is a certificate?"
  / "… no BEGIN CERTIFICATE REQUEST/END CERTIFICATE REQUEST delimiters. Are you sure this
  is a CSR?". The decoded body is loaded by pyca's parser for its tag (PKCS#8 /
  PKCS#1 RSAPrivateKey / SEC1 / EncryptedPrivateKeyInfo; SPKI only for `PUBLIC KEY`).
- Encrypted private keys: OpenSSL never prompts. RFC 1421 encryption headers are pyca's
  `decrypt_pem` for EVERY private label (header names and values trimmed; the last
  occurrence wins): no `Proc-Type` → unencrypted (or encrypted PKCS#8 for `ENCRYPTED
  PRIVATE KEY`); `Proc-Type` other than exactly `4,ENCRYPTED` (e.g. `4,NONE`, `4,
  ENCRYPTED`) → "malformed {label} PEM block: Proc-Type PEM header is not valid, key could
  not be decrypted."; no `DEK-Info` → "malformed {label} PEM block: Encrypted PEM doesn't
  have a DEK-Info header."; `DEK-Info` without `,` → "malformed {label} PEM block:
  Encrypted PEM's DEK-Info header is not valid." — all before any prompt. Otherwise the
  password is asked and keyparse decrypts (cipher name and IV hex split at the first `,`,
  NOT trimmed; EVP_BytesToKey MD5, salt = IV[..8], one round + CBC with the first
  IV-length bytes of the IV — pyca's scheme: a LONGER IV decrypts, a shorter one fails), then
  loads the plaintext by label (`ENCRYPTED PRIVATE KEY`: an EncryptedPrivateKeyInfo
  decrypted again with the same password); any failure → the wrong-password text below.
  Encrypted PKCS#8 (the DER chain or the `ENCRYPTED PRIVATE KEY` label) is recognized by
  parsing pyca's EncryptedPrivateKeyInfo structure and decrypted by keyparse as pyca's
  `parse_encrypted_private_key` does, with the WHOLE password (PBKDF2/scrypt through
  `openssl::pkcs5`, PBES1 with pyca's PBKDF1 / RFC 7292 KDF; no OpenSSL password callback,
  whose 1024-byte buffer truncated longer passwords). Password needed and no callback
  → "encrypted key material requires a password" (hint "provide --password or run
  interactively so the password can be prompted") — even when an empty-password probe
  would have decrypted (pyca TypeError parity); the same error when the callback answers
  an EMPTY password (pyca treats `b""` as no password — c2 crashed, §11 D12(h)). Wrong
  password → "incorrect password for encrypted private key (or corrupt encrypted data)".
  `ensure_legacy_provider()` (§4.4.8) is called before any PKCS#12, traditional-PEM or
  encrypted-PKCS#8 parse. pyca's cipher sets are reproduced: traditional PEM decrypts only
  `DEK-Info` AES-128-CBC, AES-256-CBC and DES-EDE3-CBC; encrypted PKCS#8 only PBES1
  pbeWithMD5AndDES-CBC / pbeWithSHAAnd3-KeyTripleDES-CBC / pbeWithSHAAnd40BitRC2-CBC /
  pbeWithSHAAnd128BitRC4 and PBES2 with PBKDF2 (PRF hmacWithSHA1/224/256/384/512) or scrypt
  over AES-128/192/256-CBC, DES-EDE3-CBC or RC2-CBC with rc2ParameterVersion 58 (128-bit;
  pyca refuses RC2-40/64). Every other scheme (e.g. `DEK-Info: DES-CBC` or AES-192-CBC,
  PBES2 CAMELLIA/DES-CBC/RC2-40) is rejected AFTER the password prompt with the
  wrong-password text above (pyca parity, although OpenSSL — with its legacy provider —
  could load several; §5.4, §11 "resolved without deviation"). A key pyca refuses after
  decryption (curve, type) gets the same wrong-password text, as in c2.
- PKCS#12: `parse2("")` first (covers c2's `None`-then-`b""` loop); then, without a
  callback → "PKCS#12 requires a password (or the PKCS#12 data is corrupt)" (same hint as
  above); wrong password → "incorrect password for PKCS#12 (or corrupt PKCS#12 data)";
  nothing inside → "PKCS#12 contains no key or certificates". An attempt (pyca
  `load_pkcs12`) succeeds only when its private key (re-encoded as PKCS#8) loads through
  pyca's DER key loader and every certificate passes pyca's strict load; a ValueError
  there (e.g. "Invalid private key", "Invalid key", a malformed certificate) fails the
  attempt like a wrong password, as in c2's loop. A PFX WITHOUT a
  MAC (`openssl pkcs12 -nomac`) whose `parse2(pw)` fails is retried with a MacData computed
  for `pw` (HMAC-SHA1, RFC 7292 key derivation): OpenSSL 3.0's PKCS12_parse refuses a
  non-empty password without a MAC, the OpenSSL pyca bundles does not. Result =
  `[private, certificate, *chain-certs]` (chain from `ca`, in order), all sharing
  `label_hint` = the main certificate's `alias()` (friendly name, UTF-8 lossy) else its
  subject CN. A private key pyca refuses with UnsupportedAlgorithm (an unsupported curve or
  explicit parameters, an unknown key type) → KeyParse "PKCS#12 contains an unsupported
  private key: {detail}" (c2 crashed, §11 D12(i)), in the no-password attempts as after
  the prompt; a certificate with pyca's InvalidVersion → KeyParse "certificate is not valid
  DER X.509: {n} is not a valid X509 version" (§11 D12(b)). Passwords containing NUL →
  KeyParse "incorrect password for PKCS#12 (or corrupt PKCS#12 data)" without calling
  OpenSSL (r2 guard; `parse2` panics on NUL).
- Results: X.509 → one CERTIFICATE material (`data` = the DER as loaded, algorithm/curve/
  size of the embedded key, `label_hint` = subject CN; a subject pyca can only decode
  lazily — c2's `_subject_cn` crashed — → KeyParse "certificate is not valid DER X.509:
  {pyca text}", resp. "certificate request is not valid DER X.509: {pyca text}" for a CSR,
  §11 D12(b)). CSR → one PUBLIC material (SPKI, `label_hint`
  = the CSR's subject CN — c2 `_csr_material`, so `load mem auto <csr>` without `--label`
  takes the CN). Private → PRIVATE (canonical PKCS#8 DER re-encoded via
  `private_key_to_pkcs8`). Public → PUBLIC (SPKI via `public_key_to_der`). Errors per
  block: "malformed {label} PEM block: {detail}", "certificate contains an invalid public
  key: {detail}", "certificate request contains an invalid public key: {detail}", "data
  contains a PEM marker but is not valid text", "no complete PEM block found", "PEM block
  'BEGIN {b}' is closed by 'END {e}'".
- Classification (`x509info::spki_facts(.., Classifier::KeyParse)`, §4.4.5) by
  `PKey::id()`:
  - RSA → `Rsa`, size_bits = `rsa.n().num_bits()` (= pyca `key_size`; not
    `Rsa::size()*8`, which rounds up to whole bytes). `Id::RSA_PSS` (an rsassaPss key) is
    accepted as RSA exactly like pyca: the key is rebuilt as a plain RSA key
    (`PKey::from_rsa(pkey.rsa()?)`, or from its components) BEFORE classification and the
    canonical writers, so PRIVATE/PUBLIC data is `rsaEncryption` PKCS#8/SPKI (byte-equal to
    c2's re-encoding).
  - EC → the curve via a NID table covering exactly pyca 49's curves: prime256v1/secp256r1
    → P256, secp384r1 → P384, secp521r1 → P521, prime192v1 → `Other("secp192r1")`,
    secp224r1 → `Other("secp224r1")`, secp256k1 → `Other("secp256k1")`,
    brainpoolP256r1/P384r1/P512r1 → `Other("brainpoolp256r1")` etc. (pyca's lower-cased
    names). A key whose group carries EXPLICIT parameters is matched against P-256, P-384
    and P-521 only (pyca 49 maps explicit parameters to no other curve) by (p, a, b,
    generator, order, cofactor); on a match it is rebuilt on the named group
    (`EcKey::from_private_components` / `from_public_key` over
    `EcGroup::from_curve_name(nid)`, ASN.1 flag NAMED_CURVE) before the canonical writers,
    so the output names the curve (pyca/c2 parity, e.g. an explicit P-256 key → p256 and a
    named-curve PKCS#8). Every EC key is rebuilt that way, so the point is re-encoded
    UNCOMPRESSED as pyca does. Explicit parameters of any other curve are rejected with
    pyca's "ECDSA keys with explicit parameters are only supported when they map to
    secp256r1, secp384r1, or secp521r1. No custom curves are supported."; any other named
    curve (including OpenSSL's SM2 key type) is rejected where pyca rejects it, with pyca's
    detail text "Curve {dotted OID} is not supported": PEM → "malformed
    {label} PEM block: Curve … is not supported"; DER → that try-chain step fails and the
    chain continues (normally ending in "could not parse key material …"); certificate /
    CSR → "certificate contains an invalid public key: Curve … is not supported" /
    "certificate request contains …" (c2 crashed there — §11 D12).
  - ED25519/ED448 → EcEdwards, X25519/X448 → EcMontgomery.
  - size_bits None for every EC-family key (never `PKey::bits()`). Anything else →
    "unsupported key algorithm: {pyca class name}" (e.g. "DSAPrivateKey"; hint "supported:
    AES, RSA, EC, Ed25519/Ed448, X25519/X448").
  RSA private keys must pass `Rsa::check_key` with odd p and q (pyca's
  `private_key_from_pkey`; "Invalid private key"), SEC1 private keys `EcKey::check_key`
  ("Invalid key"); an EC public point at infinity → "Cannot load an EC public key where the
  point is at infinity". These are ValueErrors (§4.4.3 PKCS#12: a failed attempt).
  R6 fixtures: keys on prime192v1, secp224r1, secp256k1, brainpoolP256r1 (accepted),
  prime239v1, secp112r1, sect163k1 (rejected), an explicit-parameter P-256 key, an RSA-PSS
  key and a DSA key, each with c2's output recorded.
- Hint check after parsing (hint ≠ auto): cert → every material is CERTIFICATE; aes →
  algorithm AES; rsa → RSA; ec → EC family. Mismatch → "parsed {algorithm} {class}
  material but hint is {hint!r}" (hint "use hint='auto' or the hint matching the pasted
  material").

#### 4.4.4 `r2_core::x509build`

```rust
use secrecy::SecretString;
use crate::error::Result;

pub const DEFAULT_CERT_DAYS: u32 = 3650;

/// Minimal self-signed X.509 (DER): Subject = Issuer = CN=<subject_cn> (UTF8String),
/// serial = BigNum::rand(159, MsbOption::MAYBE_ZERO, false), notBefore = now,
/// notAfter = now + days·86400, basicConstraints CA:FALSE critical, v3; signed with SHA-256
/// (RSA/EC) or no digest (Ed25519/Ed448).
pub fn build_self_signed_cert(private_key_pkcs8: &[u8], subject_cn: &str, days: u32) -> Result<Vec<u8>> { .. }

/// Covers the csr command's --hash sha256|sha384|sha512. Token (`as_str()` only; no
/// Display/FromStr): the c2 enum values "sha256WithRSAEncryption",
/// "sha384WithRSAEncryption", "sha512WithRSAEncryption", "ecdsa-with-SHA256",
/// "ecdsa-with-SHA384", "ecdsa-with-SHA512", "ed25519", "ed448".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureAlg {
    RsaPkcs1Sha256, RsaPkcs1Sha384, RsaPkcs1Sha512,
    EcdsaSha256, EcdsaSha384, EcdsaSha512,
    Ed25519, Ed448,
}
impl SignatureAlg {
    pub fn as_str(self) -> &'static str { .. }
    /// Dotted AlgorithmIdentifier OID: 1.2.840.113549.1.1.{11,12,13}, 1.2.840.10045.4.3.{2,3,4},
    /// 1.3.101.112, 1.3.101.113.
    pub fn oid(self) -> &'static str { .. }
    /// True (explicit NULL parameters) for the RSA PKCS#1 v1.5 algorithms; ECDSA/EdDSA: absent.
    pub fn null_params(self) -> bool { .. }
}

/// Signature callback of build_csr: receives the DER CertificationRequestInfo and returns
/// the signature in the ALGORITHM'S X.509 wire format (RSA: PKCS#1 v1.5 block; ECDSA: DER
/// SEQUENCE — callers converting from provider r‖s convert BEFORE returning, §4.4.7;
/// Ed: raw).
pub type SignCallback<'a> = &'a mut dyn FnMut(&[u8]) -> Result<Vec<u8>>;

/// Assemble a PEM CSR without a local private key (works for HSM keys). Returns PEM bytes
/// ("CERTIFICATE REQUEST", 64 columns, LF).
pub fn build_csr(public_key_spki: &[u8], subject: &str, sig_alg: SignatureAlg, sign: SignCallback<'_>) -> Result<Vec<u8>> { .. }

/// RFC 4514 subject → DER Name, a port of pyca 49.0 `Name.from_rfc4514_string`
/// (`_RFC4514NameParser` + NameAttribute validation). Error → Param "invalid subject
/// {subject!r}: {pyca text}" (the pyca text may be empty; param_name "subject", hint
/// 'RFC 4514 syntax, e.g. "CN=mykey,O=ACME"'), which build_csr propagates unchanged.
pub fn parse_rfc4514_subject(subject: &str) -> Result<Vec<u8>> { .. }

/// Encrypted PKCS#12 (DER) from canonical materials, pyca BestAvailableEncryption profile.
pub fn build_pkcs12(
    private_key_pkcs8: &[u8],
    cert_der: &[u8],
    friendly_name: &str,
    password: &SecretString,
    extra_certs: &[Vec<u8>],
) -> Result<Vec<u8>> { .. }
```

Normative:

- Key loading (both builders): encrypted input → KeyParse "{what} must be an unencrypted
  PKCS#8 private key" (hint "decrypt the key first — the §4.3 canonical private-key format
  is unencrypted PKCS#8 DER"); invalid → KeyParse "{what} is not a valid DER PKCS#8 private
  key: {detail}"; `what` = "self-signed certificate key" / "PKCS#12 private key". A key type
  that cannot sign/be stored → Crypto "key type {pyca class name} cannot sign a
  certificate" (hint "self-signed certificates need an RSA, EC or Ed25519/Ed448 key") /
  "key type {…} cannot be stored in a PKCS#12" (hint "PKCS#12 supports RSA, EC and
  Ed25519/Ed448 private keys"); pyca class names: "X25519PrivateKey", "X448PrivateKey".
- Self-signed CN: pyca measures the CN in UTF-8 BYTES; outside 1..=64 bytes →
  `build_self_signed_cert` returns Param "Attribute's length must be >= 1 and <= 64, but
  it was {n}" ({n} = the byte length; param_name "subject_cn", hint "the self-signed
  certificate uses the key label as its CN"). This is the defensive check of the builder;
  the operator-facing check is `certops::export_pkcs12`'s pre-check (§4.9.10), which runs
  before anything is exported or built and raises the same text with param_name "label"
  and hint "pass an existing certificate with --cert". c2 raised a bare ValueError
  (unexpected-error path) — §11 D12.
- `build_csr`: subject via `parse_rfc4514_subject` (names CN L ST O OU C STREET DC UID plus
  dotted OIDs, case-sensitive; CN length 1..=64 UTF-8 bytes, C exactly 2 UTF-8 bytes; default string
  types C, serialNumber, dnQualifier, jurisdictionC → PrintableString; emailAddress, DC →
  IA5String; else UTF8String; `#hex` values double-wrapped as pyca does); its Param error
  ("invalid subject {subject!r}: {pyca text}") propagates unchanged.
  `x509_cert::name::Name::from_str` is never used
  unvalidated (it accepts a superset). Bad SPKI → KeyParse "public key is not a valid DER
  SubjectPublicKeyInfo: {detail}". The DER is assembled exactly as c2 assembles it (not
  through x509-cert's types, whose `const-oid` cannot hold every OID pyca accepts, e.g.
  `2.999` or 128-bit `2.25.…` arcs): CRI = `SEQUENCE { INTEGER 0, subject, SPKI (the input
  bytes), [0] {} }`; CSR = `SEQUENCE { CRI, AlgorithmIdentifier { oid, NULL iff
  null_params }, BIT STRING (0 unused bits ‖ sig) }`; PEM "CERTIFICATE REQUEST", 64
  columns, LF. Byte-identical to c2 for deterministic algorithms. The assembled CSR is
  re-parsed as pyca's `load_der_x509_csr` would (strict DER; PrintableString values must use
  the PrintableString alphabet); a failure → Crypto "assembled CSR failed to parse:
  {detail}" with pyca's detail, e.g. for `C=a*`.
- `build_pkcs12`: empty password → Param "PKCS#12 password must not be empty"
  (param_name "password", hint "PKCS#12 output is always encrypted (§5.6)"). A NUL in the
  password or friendly name is an ordinary character, as in pyca (U+0000 in the
  BMPStrings; the PBKDF2 password is the raw UTF-8). The PFX is written by a
  port of pyca 49's `serialize_key_and_certificates` with `BestAvailableEncryption` (pyca
  writes PKCS#12 natively): authSafe = [encryptedData { the cert bags }, data { the
  shroudedKeyBag }], each encrypted with PBES2 / PBKDF2-HMAC-SHA256 (20000 iterations,
  16-byte salt) / AES-256-CBC; the main cert bag and the key bag carry friendlyName (a
  BMPString in UTF-16, surrogate pairs included — OpenSSL's `PKCS12_add_friendlyname_utf8`
  refused non-BMP characters) and localKeyId (SHA-1 of the certificate DER), chain certs
  none; attribute SETs in DER order; MacData = HMAC-SHA256 under the RFC 7292 key (ID 3,
  2048 iterations, 8-byte salt), SHA-256 AlgorithmIdentifier with NULL. Bad cert (pyca's
  strict load only) → KeyParse "certificate is not valid DER X.509: {detail}"; bad extra →
  KeyParse "extra certificate #{index} is not valid DER X.509: {detail}"; a certificate
  whose key is not the private key's → Crypto "PKCS#12 assembly failed: Certificate public
  key and provided private key do not match" (pyca's ValueError, as c2 wrapped it); other
  assembly failures → Crypto "PKCS#12 assembly failed: {detail}".

#### 4.4.5 `r2_core::x509info` (certificate facts shared by memory, pkcs11, services; each caller picks c2's classifier and attribute set)

```rust
use std::collections::BTreeMap;
use crate::error::{ConsoleError, Result};
use crate::keys::{Curve, KeyAlgorithm};
use crate::template::AttrValue;

/// Facts of a certificate used by every provider and the `key info` command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertFacts {
    pub algorithm: KeyAlgorithm,
    pub curve: Option<Curve>,
    pub size_bits: Option<u32>,
    /// DER SubjectPublicKeyInfo of the embedded key.
    pub spki_der: Vec<u8>,
    /// DER Name (exact bytes of the certificate) — CKA_SUBJECT / CKA_ISSUER.
    pub subject_der: Vec<u8>,
    pub issuer_der: Vec<u8>,
    /// DER INTEGER TLV of the serial — CKA_SERIAL_NUMBER.
    pub serial_der: Vec<u8>,
    /// First CN of the subject, UTF-8 (`label_hint`).
    pub subject_cn: Option<String>,
}

/// Which of c2's two key classifiers a caller mirrors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classifier {
    /// keyparse/memory (`_classify`): the §4.4.3 rules — the other pyca curves as
    /// `Curve::Other(name)`; unsupported → KeyParse "unsupported key algorithm: {X}" with
    /// hint "supported: AES, RSA, EC, Ed25519/Ed448, X25519/X448".
    KeyParse,
    /// the PKCS#11 certificate read path (`Pkcs11Provider._spki_facts`): only p256/p384/p521
    /// are named, any other EC curve → curve None (shown "-"); unsupported → KeyParse
    /// "unsupported public key type {pyca public class name}" (e.g. "DSAPublicKey"), no hint.
    /// (On that read path a certificate c2 skipped — not listed — is told apart from one
    /// whose error propagates by `pkcs11_skips_certificate`.)
    Pkcs11,
}

/// Parse a DER certificate. Errors → KeyParse "certificate is not valid DER X.509: {detail}",
/// "certificate contains an invalid public key: {detail}".
pub fn cert_facts(cert_der: &[u8], classifier: Classifier) -> Result<CertFacts> { .. }
/// (algorithm, curve, size_bits) of a DER SPKI (classification rules of §4.4.3, per
/// `classifier`).
pub fn spki_facts(spki_der: &[u8], classifier: Classifier) -> Result<(KeyAlgorithm, Option<Curve>, Option<u32>)> { .. }
/// c2's PKCS#11 certificate read path (provider.py `_key_info`) caught pyca's ValueError and
/// skipped the certificate (not listed) — while UnsupportedAlgorithm / TypeError / KeyError /
/// KeyParseError propagated (c2 crashed or failed `keys`; r2 propagates the error, §11
/// D12(b)). True when `err`, returned by `cert_facts` or `cert_attributes`, is of the skipped
/// kind: every "certificate is not valid DER X.509: …" except a BIT STRING value under an OID
/// other than x500UniqueIdentifier, an unknown Name value tag and pyca's InvalidVersion
/// ("{n} is not a valid X509 version"), and every "certificate
/// contains an invalid public key: …" except an unsupported curve ("Curve {oid} is not
/// supported", explicit parameters of another curve) or key type ("Unknown key type: {oid}",
/// "Unsupported key type."). "unsupported public key type …" propagates.
pub fn pkcs11_skips_certificate(err: &ConsoleError) -> bool { .. }
/// Port of pyca `Name.rfc4514_string()`: RDNs reversed, '+' within an RDN, short names only
/// for CN L ST O OU C STREET DC UID (else dotted OID), `_escape_dn_value` escaping
/// (`\ " + , ; < >`, NUL → `\00`, leading `#`/space and trailing space), non-string
/// values (an x500UniqueIdentifier BIT STRING: its raw content) as `#hex` ("" when empty).
/// NOT x509-cert's Display.
pub fn rfc4514_string(name_der: &[u8]) -> Result<String> { .. }
/// `key info` rows for a certificate: ("subject", rfc4514), ("issuer", rfc4514),
/// ("serial", lower-case hex without leading zeros, "0" for zero), ("not valid before",
/// "YYYY-MM-DDTHH:MM:SS+00:00"), ("not valid after", same). Certificates are read by a
/// strict DER parser of pyca's whole `Certificate` structure with its load-time checks
/// (EXPLICIT [0] version DEFAULT v1 — an encoded v1 is EncodedDefault —, minimal INTEGERs,
/// both AlgorithmIdentifiers and the SPKI algorithm with pyca's DEFINED BY parameters, DER
/// UTCTime / GeneralizedTime, Name value alphabets, [1]/[2] unique IDs, [3] SEQUENCE OF
/// Extension { OID, BOOLEAN DEFAULT FALSE, OCTET STRING }, nothing after; then a version
/// other than v1/v3 is pyca's InvalidVersion "{n} is not a valid X509 version" — c2
/// crashed, §11 D12(b) — and CSRs likewise: version 0, [0] SET OF Attribute { OID, SET OF
/// ANY } in DER order), not x509-cert (whose const-oid rejects OIDs pyca reads); an
/// undecodable Name value → KeyParse "certificate is not valid DER X.509: {pyca
/// text}" and a GeneralizedTime in year 0 (which pyca loads) → "… X.509: year 0 is out of
/// range" (Python's datetime text; c2 crashed lazily in both cases, §11 D12(b)).
pub fn certificate_details(cert_der: &[u8]) -> Result<Vec<(String, String)>> { .. }
/// KeyInfo.attributes of a certificate on the PKCS#11 read path (c2 provider.py):
/// CKA_SUBJECT / CKA_ISSUER = Str(rfc4514), CKA_SERIAL_NUMBER = Str(serial hex as above).
pub fn cert_attributes(cert_der: &[u8]) -> Result<BTreeMap<String, AttrValue>> { .. }
/// KeyInfo.attributes of a MemoryProvider certificate (c2 memory.py `_cert_attributes`):
/// Str "subject", "issuer" (rfc4514), "serial_number" (hex as above), "not_valid_before",
/// "not_valid_after" ("YYYY-MM-DDTHH:MM:SS+00:00", pyca `isoformat()`).
pub fn memory_cert_attributes(cert_der: &[u8]) -> Result<BTreeMap<String, AttrValue>> { .. }
```

#### 4.4.6 `r2_core::formats` (re-serialization of canonical bytes; used by keyexport)

```rust
use secrecy::SecretString;
use zeroize::Zeroizing;
use crate::error::Result;

/// Token (`as_str()` only; no Display/FromStr): "pem" | "der".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding { Pem, Der }
impl Encoding { pub fn as_str(self) -> &'static str { .. } }

/// PKCS#8 DER → PKCS#8 PEM/DER. `password` → encrypted PKCS#8 =
/// `private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), pw)` /
/// `private_key_to_pkcs8_passphrase` (PBES2, PBKDF2-HMAC-SHA256, 2048 iterations,
/// AES-256-CBC — pyca BestAvailableEncryption; salt length is OpenSSL's and not
/// normative). Errors: invalid input → KeyParse "exported private key is not valid
/// unencrypted PKCS#8 DER: {detail}"; empty password → Param "password must not be empty"
/// (param_name "password"); a password over 1023 UTF-8 bytes → Param "Passwords longer
/// than 1023 bytes are not supported by this backend" (pyca's limit; c2 crashed, §11
/// D12(j)). A NUL byte is an ordinary password byte (pointer + length, no C string).
pub fn private_key_bytes(pkcs8_der: &[u8], encoding: Encoding, password: Option<&SecretString>) -> Result<Zeroizing<Vec<u8>>> { .. }
/// SPKI DER → PEM ("PUBLIC KEY") or DER. DER is returned verbatim WITHOUT validation (c2
/// `_serialize_spki`); only the PEM path parses: invalid → KeyParse "exported public key is
/// not valid DER SubjectPublicKeyInfo: {detail}".
pub fn public_key_bytes(spki_der: &[u8], encoding: Encoding) -> Result<Vec<u8>> { .. }
/// Certificate DER → PEM or DER. DER is returned verbatim WITHOUT validation; only the PEM
/// path parses: invalid → KeyParse "exported certificate is not valid DER X.509: {detail}".
pub fn certificate_bytes(cert_der: &[u8], encoding: Encoding) -> Result<Vec<u8>> { .. }
/// SPKI of a DER certificate (c2 keyexport `_cert_spki`). Errors → KeyParse "exported
/// certificate is not valid DER X.509: {detail}" / "certificate contains an invalid public
/// key: {detail}".
pub fn cert_spki(cert_der: &[u8]) -> Result<Vec<u8>> { .. }
/// SPKI derived in software from an unencrypted PKCS#8 (errors as private_key_bytes).
pub fn pkcs8_public_spki(pkcs8_der: &[u8]) -> Result<Vec<u8>> { .. }
```

The canonical writers are normative and byte-identical to c2: `private_key_to_pkcs8`
(PRIVATE), `public_key_to_der` (PUBLIC), the certificate DER as loaded by pyca's strict
parser (CERTIFICATE; OpenSSL's `X509` decoder is not used, it refuses Name encodings pyca
loads); PEM via `private_key_to_pem_pkcs8` / `public_key_to_pem` / the certificate DER in
base64 at 64 columns with LF (pyca's `pem` encoding) — applied to the normalized key of
§4.4.3 (RSA-PSS keys rebuilt as rsaEncryption RSA, explicit-parameter EC keys rebuilt on
their named group), which is what makes them byte-identical for those inputs too. Key
inputs are loaded by §4.4.3's port of pyca's key parsers (pyca re-parses them so).

#### 4.4.7 `r2_core::der` (pure `der`; no OpenSSL)

```rust
use crate::error::Result;
use crate::keys::Curve;

/// Named-curve OID DER (CKA_EC_PARAMS): p256 06082a8648ce3d030107, p384 06052b81040022,
/// p521 06052b81040023, ed25519 06032b6570, ed448 06032b6571, x25519 06032b656e,
/// x448 06032b656f. None for Curve::Other. (R0 mandated working body: this table.)
pub fn curve_oid_der(curve: &Curve) -> Option<&'static [u8]> { .. }
/// Inverse of curve_oid_der over the seven known curves. (R0 mandated working body.)
pub fn curve_from_oid_der(der: &[u8]) -> Option<Curve> { .. }
/// DER OCTET STRING around a raw EC point (CKA_EC_POINT — the classic gotcha): tag 0x04,
/// DER definite length (short form < 128, else 0x81/0x82/… long form), the bytes.
/// (R0 mandated working body.)
pub fn wrap_octet_string(raw: &[u8]) -> Vec<u8> { .. }
/// Strip a DER OCTET STRING header; input that is not exactly one well-formed OCTET STRING
/// TLV is returned unchanged (raw points pass through) — c2 `_unwrap_octet_string`.
pub fn unwrap_octet_string(der: &[u8]) -> Vec<u8> { .. }
/// Canonical fixed-width r‖s → DER ECDSA-Sig-Value SEQUENCE (minimal INTEGERs), via
/// `#[derive(der::Sequence)] struct { r: UintRef, s: UintRef }`. Empty or odd length →
/// Crypto "ECDSA signature of {n} bytes is not fixed-width r‖s" (hint "providers emit r‖s
/// with each half ceil(curve_bits/8) bytes (§4.6)").
pub fn ecdsa_rs_to_der(signature: &[u8]) -> Result<Vec<u8>> { .. }
/// DER ECDSA-Sig-Value → r‖s, each half left-padded to `half_len` bytes. Malformed or
/// oversized → Crypto "malformed ECDSA DER signature".
pub fn ecdsa_der_to_rs(der: &[u8], half_len: usize) -> Result<Vec<u8>> { .. }
```

#### 4.4.8 `r2_core::crypto`

```rust
use zeroize::Zeroizing;
use crate::error::Result;

// The three bodies below are R0 mandated working bodies (§4.1.1), exactly as documented.
/// Constant-time equality that never panics: `a.len() == b.len() && openssl::memcmp::eq(a, b)`
/// (memcmp::eq asserts equal lengths). MAC verify and RSA-RAW verify use it.
#[allow(clippy::disallowed_methods)] // the one sanctioned openssl::memcmp::eq call (§4.1.3)
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool { .. }
/// `openssl::rand::rand_bytes` into a zeroizing buffer (CKA_IDs, transport keys, AES/generic
/// keygen). Failure → Crypto "random number generation failed".
pub fn random_bytes(len: usize) -> Result<Zeroizing<Vec<u8>>> { .. }
/// Load the OpenSSL "legacy" provider once per process:
/// `static LEGACY: OnceLock<Option<openssl::provider::Provider>>` initialized with
/// `Provider::try_load(None, "legacy", true)` (retain_fallbacks MUST be true; the Provider is
/// never dropped). Failure is non-fatal: logged at debug, only RC2/DES inputs then fail.
/// Called by keyparse before PKCS#12, traditional-PEM and encrypted-PKCS#8 parsing and by
/// r2-cli at startup.
pub fn ensure_legacy_provider() { .. }
```

### 4.5 Provider trait, data types, registry, concrete providers

#### 4.5.1 Data types (`r2_provider::types`, re-exported at `r2_provider::*`)

```rust
use std::fmt;

use zeroize::Zeroizing;
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, ParsedRef};
use r2_core::params::{ParamStruct, Params};
use r2_core::template::KeyTemplate;

/// Token: "not_required" (memory) | "logged_out" | "logged_in".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthState { NotRequired, LoggedOut, LoggedIn }
impl AuthState { pub fn as_str(self) -> &'static str { .. } }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenInfo {
    pub slot_id: u64,
    /// Trailing ' ' AND '\0' trimmed (c2 `_strip_padding`; cryptoki trims spaces only).
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderStatus {
    pub auth: AuthState,
    /// Some iff auth == LoggedIn.
    pub token: Option<TokenInfo>,
}

/// What a provider verb receives. Built by `OperationSpec::invocation` (§4.6) for
/// operations, or directly (`new`) by services for fixed mechanisms.
#[derive(Clone, Debug, PartialEq)]
pub struct MechanismInvocation {
    /// Canonical name (§4.6), e.g. "AES-GCM", or a custom mechanism id.
    pub mechanism: String,
    /// Typed values from ParamResolver (absent = c2's `None`).
    pub params: Params,
    /// Set for config-defined vendor mechanisms.
    pub raw_ckm: Option<u64>,
    pub param_struct: ParamStruct,
    /// Set when param_struct == Raw (the resolved `mechparam` bytes).
    pub raw_param_bytes: Option<Vec<u8>>,
}
impl MechanismInvocation {
    /// raw_ckm None, param_struct None, raw_param_bytes None.
    pub fn new(mechanism: impl Into<String>, params: Params) -> Self { .. }
}

/// frozen-provisional (§4.11). `Debug` by hand: `raw` shown as "<N bytes>".
#[derive(Clone, PartialEq)]
pub struct DeriveResult {
    /// Provider-resident derived key (session object).
    pub key: Option<KeyInfo>,
    /// Shared secret bytes when extractable.
    pub raw: Option<Zeroizing<Vec<u8>>>,
}
impl fmt::Debug for DeriveResult { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { .. } }

/// frozen-provisional (§4.11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttrEditOutcome {
    /// "CKA_LABEL".
    pub name: String,
    pub applied: bool,
    /// Failure reason incl. the CKR name when not applied.
    pub detail: Option<String>,
}

/// frozen-provisional (§4.11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEditResult {
    /// Re-read snapshot after the edits (new ref on an identity change).
    pub key: KeyInfo,
    pub outcomes: Vec<AttrEditOutcome>,
}

/// The §4.3 ref selectors as find_key filters (c2 `find_key(label, key_id, key_class, handle)`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeySelector {
    pub label: String,
    pub key_id: Option<Vec<u8>>,
    pub key_class: Option<KeyClass>,
    pub handle: Option<u64>,
}
impl KeySelector {
    pub fn label(label: impl Into<String>) -> Self { .. }
    pub fn with_id(self, key_id: Option<Vec<u8>>) -> Self { .. }
    pub fn with_class(self, key_class: Option<KeyClass>) -> Self { .. }
    pub fn with_handle(self, handle: Option<u64>) -> Self { .. }
}
impl From<&ParsedRef> for KeySelector { fn from(parsed: &ParsedRef) -> Self { .. } }

/// c2 `generate_key(algorithm, *, size_bits, curve, label, key_id, template, public_template)`.
/// Required arguments go through `new`; the keyword arguments with defaults are the public
/// fields (refinement of PLAN §5's "implements Default": an algorithm/label default would be
/// meaningless).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerateRequest {
    pub algorithm: KeyAlgorithm,
    pub size_bits: Option<u32>,
    pub curve: Option<Curve>,
    pub label: String,
    pub key_id: Option<Vec<u8>>,
    /// Secret key template, or the PRIVATE half of a keypair.
    pub template: Option<KeyTemplate>,
    /// PUBLIC half of a keypair.
    pub public_template: Option<KeyTemplate>,
}
impl GenerateRequest {
    pub fn new(algorithm: KeyAlgorithm, label: impl Into<String>) -> Self { .. }
}

/// The `options` escape hatch of wrap/unwrap (frozen-provisional, §4.11). No c2 call site
/// passes options (verified at 408d6f2), so it has no fields yet; additions go through
/// §4.11 and keep `Default`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct WrapOptions {}

/// c2 `unwrap_key(…, *, result_algorithm, result_class, label, key_id, template, options)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwrapRequest {
    pub result_algorithm: KeyAlgorithm,
    pub result_class: KeyClass,
    pub label: String,
    /// Same semantics as import/generate — how `copy --id` reaches the wrap routes.
    pub key_id: Option<Vec<u8>>,
    pub template: Option<KeyTemplate>,
    pub options: WrapOptions,
}
impl UnwrapRequest {
    pub fn new(result_algorithm: KeyAlgorithm, result_class: KeyClass, label: impl Into<String>) -> Self { .. }
}
```

#### 4.5.2 The `Provider` trait (`r2_provider::provider`)

Object-safe; every method takes `&self` (session/login state lives in `RefCell`s inside the
provider, so same-provider flows such as `copy softhsm:x softhsm` never alias `&mut`).
Providers are `!Send`/`!Sync` and called from the REPL thread only (§6); the §4
re-entrancy rule applies (no `RefCell` borrow is held across a call out).

```rust
use std::any::Any;
use std::collections::BTreeSet;

use secrecy::SecretString;
use zeroize::Zeroizing;
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{KeyInfo, KeyMaterial};
use r2_core::template::KeyTemplate;

use crate::types::*;

pub trait Provider {
    /// Instance name ("mem", "softhsm").
    fn name(&self) -> &str;
    /// "memory" | "pkcs11" (FakeProvider presents either, per instance).
    fn type_name(&self) -> &str;

    // -- lifecycle --
    /// Load library / C_Initialize; no-op for memory. Idempotent. Called LAZILY by the
    /// provider itself on first real use — the bootstrap never calls it (§6: a broken
    /// configured library must not prevent startup).
    fn initialize(&self) -> Result<()>;
    /// Logout, close sessions, C_Finalize (via the shared-module release); safe when never
    /// initialized.
    fn shutdown(&self) -> Result<()>;

    // -- authentication (one token of one device at a time per provider) --
    /// Never triggers a library load or token I/O beyond the cached state.
    fn status(&self) -> ProviderStatus;
    /// Tokens present (`getSlotList(tokenPresent=True)` + token info). Memory: empty.
    fn list_tokens(&self) -> Result<Vec<TokenInfo>> { Ok(Vec::new()) }
    /// keep_pin=true → the provider may hold the PIN in memory for session auto-recovery
    /// (§5.2); never persisted. Already logged in → AlreadyLoggedIn "already logged in"
    /// (hint "logout first"), checked before C_Login.
    fn login(&self, token: &TokenInfo, pin: &SecretString, keep_pin: bool) -> Result<()> {
        let _ = (token, pin, keep_pin);
        Err(ConsoleError::unsupported(format!("{} does not require login", self.name())))
    }
    /// No-op by default (memory has no session).
    fn logout(&self) -> Result<()> { Ok(()) }

    // -- capability discovery --
    /// Canonical mechanism names usable RIGHT NOW (post-login for PKCS#11; empty while
    /// logged out). Never loads a library.
    fn mechanisms(&self) -> BTreeSet<String>;
    fn supports(&self, mechanism: &str) -> bool { self.mechanisms().contains(mechanism) }

    // -- key management --
    /// Every object incl. certificates and data objects; PKCS#11 lists unmodelled key
    /// types as OTHER. Order (observable: `keys` rows, the `key info` "related:" line, ref
    /// completion): Pkcs11Provider = for class in [Secret, Private, Public, Certificate,
    /// Data] (KeyClass declaration order) one `find_objects([CKA_CLASS = cko(class)])` pass
    /// in token order, each object classified as c2 `_key_info` (objects of other CKO
    /// classes never appear; never one unfiltered find + classify, which would give
    /// creation order); MemoryProvider / FakeProvider = insertion order. FakeBackend
    /// returns `find_objects` results in creation order so R5a tests pin this.
    fn list_keys(&self) -> Result<Vec<KeyInfo>>;
    /// KeyNotFound | AmbiguousKey (texts and the family collapse rule: §4.5.3
    /// `lookup::select_match`). `key_class`/`handle` are extra match filters; a given
    /// key_class also disables the keypair-family class-preference collapse. "Provider
    /// order" of the matches (it orders the AmbiguousKey message and candidates): PKCS#11 =
    /// the `C_FindObjects` order for the template {CKA_LABEL[, CKA_ID]}, with class and
    /// handle applied as post-filters — find_key never goes through `list_keys`;
    /// MemoryProvider / FakeProvider = insertion order.
    fn find_key(&self, selector: &KeySelector) -> Result<KeyInfo>;
    /// DuplicateKey when a non-certificate object with the same (class, label, id)
    /// identity exists (§4.7 guard). DATA material: key_id must be None (Param otherwise);
    /// identity is (class, label). NONE (outside DATA) / OTHER material → Param.
    fn import_key(
        &self,
        material: &KeyMaterial,
        label: &str,
        template: Option<&KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> Result<KeyInfo>;
    /// AES/GENERIC: size_bits required (GENERIC: any multiple of 8 in 8..=8192); template
    /// applies to the secret key. RSA: size_bits required. EC/EC_EDWARDS/EC_MONTGOMERY:
    /// curve required. NONE/OTHER → Param. Keypairs create BOTH objects sharing label (and
    /// CKA_ID on PKCS#11); `template` = private, `public_template` = public; returns the
    /// private (or secret) KeyInfo, the public object appears in list_keys(). key_id None
    /// on PKCS#11 → an enabled template CKA_ID row if present (§4.7), else a random 4-byte
    /// CKA_ID. DuplicateKey when the resolved identity is taken by an object of the
    /// created class — both keypair halves are checked up front (never a half pair).
    fn generate_key(&self, request: &GenerateRequest) -> Result<KeyInfo>;
    fn delete_key(&self, key: &KeyInfo) -> Result<()>;
    /// KeyNotExportable when `key.exportable` is false. Certificates: DER. PUBLIC always
    /// allowed (PKCS#11: rebuilt from public attributes). DATA: raw CKA_VALUE (always).
    /// OTHER → UnsupportedOperation.
    fn export_key(&self, key: &KeyInfo) -> Result<KeyMaterial>;

    // -- crypto verbs (mechanisms vary; verbs never do) --
    fn encrypt(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>>;
    /// The plaintext is held in a zeroizing buffer (D3).
    fn decrypt(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    fn sign(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>>;
    /// Ok(false) for a well-formed but wrong signature (PKCS#11 CKR_SIGNATURE_INVALID /
    /// CKR_SIGNATURE_LEN_RANGE); errors only for real failures.
    fn verify(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8], signature: &[u8]) -> Result<bool>;
    /// Peer public key travels as `mech.params["peer"]` (SPKI DER or raw point).
    fn derive(&self, key: &KeyInfo, mech: &MechanismInvocation) -> Result<DeriveResult>;

    // -- wrap/unwrap (frozen-provisional, §4.11) --
    fn wrap_key(&self, wrapping_key: &KeyInfo, mech: &MechanismInvocation, target: &KeyInfo, options: &WrapOptions) -> Result<Vec<u8>> {
        let _ = (wrapping_key, mech, target, options);
        Err(ConsoleError::unsupported(format!("{} does not support key wrapping", self.name())))
    }
    /// Same identity semantics and duplicate guard as import_key.
    fn unwrap_key(&self, wrapping_key: &KeyInfo, mech: &MechanismInvocation, wrapped: &[u8], request: &UnwrapRequest) -> Result<KeyInfo> {
        let _ = (wrapping_key, mech, wrapped, request);
        Err(ConsoleError::unsupported(format!("{} does not support key unwrapping", self.name())))
    }

    // -- key editing (frozen-provisional, §4.11) --
    /// Editor-seedable snapshot of THIS object: locked CKA_CLASS/CKA_KEY_TYPE rows (no
    /// CKA_KEY_TYPE for certificates/data; the key-type row shows the ACTUAL CKK symbol),
    /// CKA_LABEL, CKA_ID (disabled-empty when absent; no row for data objects),
    /// class-appropriate policy attrs (data: CKA_APPLICATION/CKA_OBJECT_ID) and decoded
    /// templates.custom_attributes; attrs the token refuses are skipped (§5.15).
    fn read_key_template(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        let _ = key;
        Err(ConsoleError::unsupported(format!("{} does not support key editing", self.name())))
    }
    /// Applies the ENABLED rows of `changes` to exactly this object, one attribute per call
    /// (CKA_LABEL+CKA_ID batched into one all-or-nothing call), one AttrEditOutcome per
    /// attr — a token refusal (e.g. CKR_ATTRIBUTE_READ_ONLY) is an outcome, never an error.
    /// AuthRequired aborts. Identity rows run the §4.7 duplicate guard BEFORE anything is
    /// applied (DuplicateKey; certificates exempt; the edited object excluded). Locked
    /// names in `changes` → Param. Siblings sharing the identity are untouched (family
    /// renames are a console confirm() flow, §5.15).
    fn update_key(&self, key: &KeyInfo, changes: &KeyTemplate) -> Result<KeyEditResult> {
        let _ = (key, changes);
        Err(ConsoleError::unsupported(format!("{} does not support key editing", self.name())))
    }
    /// COMPLETE snapshot for `key template` (§5.16): every CKA_CATALOG attr plus every
    /// templates.custom_attributes attr the backend returns — readable key material
    /// included; refused attrs (CKR_ATTRIBUTE_SENSITIVE/_TYPE_INVALID…) skipped;
    /// CKA_CLASS/CKA_KEY_TYPE symbolic (no CKA_KEY_TYPE for certificates/data; the actual
    /// CKK symbol, also for OTHER). Consumed by the template-file serializer, never the editor.
    fn read_full_template(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        let _ = key;
        Err(ConsoleError::unsupported(format!("{} does not support template dumps", self.name())))
    }

    // -- seams --
    /// The SoftHSM-wizard seam (§4.9.9): Some for providers that can initialize tokens
    /// (Pkcs11Provider; FakeProvider configured with `.with_tokens(..)`).
    fn as_token_init(&self) -> Option<&dyn TokenInit> { None }
    /// Downcast seam (tests, r2-cli). Implementations return `self` (a borrowed wrapper view,
    /// such as FakeProvider's un-hooked `next`, returns the object it wraps — a non-'static
    /// view cannot be `&dyn Any`).
    fn as_any(&self) -> &dyn Any;
}

/// Token initialization (c2 `Pkcs11Provider.init_token`, kept behind a trait so the
/// console never names a pkcs11 type and the wizard is unit-testable on FakeProvider).
pub trait TokenInit {
    /// C_InitToken + C_InitPIN on the free slot `slot` (§5.13 step 3). The label must be
    /// ≤ 32 UTF-8 bytes (Param "token label must be at most 32 bytes" otherwise — r2
    /// validates because cryptoki silently truncates; §11 D15); it is space-padded to the 32-byte
    /// field and `list_tokens` returns it exactly. After C_InitToken the token is re-found
    /// by label, then login(SO) + C_InitPIN(user_pin) + logout on an RW session. r2 runs that
    /// session in place of the provider's own: once that session is opened, a session the
    /// provider held (and a login on it) is gone (§11 D15(c)).
    fn init_token(&self, slot: u64, label: &str, so_pin: &SecretString, user_pin: &SecretString) -> Result<()>;
    /// §5.13 step 2: set `key=value` in the process environment at the single audited
    /// `set_var` site, then shut this provider down (drop its session, release the shared
    /// module — the last release finalizes) so the next lazy initialize re-reads the
    /// environment. When another provider instance holds the same module (same canonical library
    /// path, §4.5.5) →
    /// Provider "'{name}' shares its PKCS#11 module with another provider" (hint "restart
    /// r2 after the setup, or remove the other provider entry"); nothing is changed then.
    fn set_env_and_reset(&self, key: &str, value: &str) -> Result<()>;
}
```

#### 4.5.3 Registry, shared lookup helpers, RSA-RAW, mechanism names

```rust
// crates/r2-provider/src/registry.rs
use std::rc::Rc;

use r2_core::error::Result;
use r2_core::keys::KeyInfo;

use crate::provider::Provider;

/// Every configured provider instance; the single place a textual ref is resolved.
#[derive(Default)]
pub struct ProviderRegistry { /* RefCell<Vec<Rc<dyn Provider>>>, registration order */ }

impl ProviderRegistry {
    pub fn new() -> Self { .. }
    /// Duplicate name → Config "provider '{name}' is already registered"
    /// (hint "provider names must be unique across the configuration").
    pub fn register(&self, provider: Rc<dyn Provider>) -> Result<()> { .. }
    /// Unknown → ProviderNotFound "unknown provider '{name}'" (hint "known providers:
    /// {names joined ', '}" in REGISTRATION order — not `all()`'s memory-first order — or
    /// "known providers: (none registered)").
    pub fn get(&self, name: &str) -> Result<Rc<dyn Provider>> { .. }
    /// Registration (= config) order, stable-sorted so type "memory" comes first.
    pub fn all(&self) -> Vec<Rc<dyn Provider>> { .. }
    /// `r2_core::keys::parse_ref` + get + find_key; never a second parser.
    pub fn resolve_ref(&self, reference: &str) -> Result<(Rc<dyn Provider>, KeyInfo)> { .. }
}
```

```rust
// crates/r2-provider/src/lookup.rs — one implementation of the find/twin rules for every
// provider (memory, pkcs11, FakeProvider)
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{KeyClass, KeyInfo};

use crate::types::KeySelector;

/// Family collapse preference.
pub const CLASS_PREFERENCE: [KeyClass; 5] =
    [KeyClass::Private, KeyClass::Secret, KeyClass::Public, KeyClass::Certificate, KeyClass::Data];

/// True when `info` matches label, and key_id/key_class/handle when given.
pub fn matches_selector(info: &KeyInfo, selector: &KeySelector) -> bool { .. }

/// Pick the result of find_key from the matches (provider order). 0 matches → KeyNotFound
/// "no {class }key '{label}' on provider {provider}" ("{class} " = `key_class.as_str()`
/// plus a space when a class selector was given, else empty). 1 match → it. Several: when
/// `selector.key_class` is None AND all matches share one key_id AND their classes are
/// pairwise distinct (a keypair / key+certificate family) → the first match in
/// CLASS_PREFERENCE order; otherwise AmbiguousKey "'{label}' matches {n} keys on
/// {provider}: {display_refs(matches) joined ', '}" with candidates = their refs and hint
/// "disambiguate with label#id, a :priv/:pub/:cert/:secret/:data suffix, or @handle".
pub fn select_match(provider: &str, selector: &KeySelector, matches: Vec<KeyInfo>) -> Result<KeyInfo> { .. }

/// The §4.7 duplicate-identity error: DuplicateKey "a {class} object with label '{label}'
/// and {shown} already exists on {provider}" where shown = "id 0x{hex}" or "no id"; hint
/// "pick a different --id or label, or delete the existing object first" (create flows) or
/// "pick a different id or label, or delete the existing object first" (rename = true).
pub fn duplicate_identity(provider: &str, key_class: KeyClass, label: &str, key_id: Option<&[u8]>, rename: bool) -> ConsoleError { .. }
```

```rust
// crates/r2-provider/src/rsa_raw.rs
use zeroize::Zeroizing;
use r2_core::error::Result;

/// RSA-RAW (CKM_RSA_X_509 equivalent): textbook modexp with fixed-width I2OSP, shared by
/// MemoryProvider and Pkcs11Provider's software public-exponent decrypt. Inputs are
/// big-endian magnitudes. `data` is left-padded to k = modulus byte length. NOT
/// constant-time (diagnostic feature, §5.8). Implemented with openssl BigNum `mod_exp` +
/// `to_vec_padded(k)` — never `Padding::NONE` (it requires len == k). Errors → Crypto
/// "RSA-RAW input is longer than the modulus ({len} > {k} bytes)" /
/// "RSA-RAW input is not numerically smaller than the modulus". The output may be a
/// private-exponent result (decrypt/sign), so it is zeroizing (D3).
pub fn rsa_raw_modexp(modulus: &[u8], exponent: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> { .. }
```

```rust
// crates/r2-provider/src/mechanism.rs — the frozen canonical name list (§4.6)
pub const AES_ECB: &str = "AES-ECB";
pub const AES_CBC: &str = "AES-CBC";
pub const AES_CTR: &str = "AES-CTR";
pub const AES_GCM: &str = "AES-GCM";
pub const AES_CMAC: &str = "AES-CMAC";
pub const AES_GMAC: &str = "AES-GMAC";
pub const HMAC: &str = "HMAC";
pub const RSA_OAEP: &str = "RSA-OAEP";
pub const RSA_PKCS1: &str = "RSA-PKCS1";
pub const RSA_PSS: &str = "RSA-PSS";
pub const RSA_RAW: &str = "RSA-RAW";
pub const ECDSA: &str = "ECDSA";
pub const EDDSA: &str = "EDDSA";
pub const ECDH: &str = "ECDH";
pub const AES_KEY_WRAP: &str = "AES-KEY-WRAP";
pub const AES_KEY_WRAP_PAD: &str = "AES-KEY-WRAP-PAD";
pub const RSA_AES_KEY_WRAP: &str = "RSA-AES-KEY-WRAP";
pub const CANONICAL_MECHANISMS: [&str; 17] = [
    AES_ECB, AES_CBC, AES_CTR, AES_GCM, AES_CMAC, AES_GMAC, HMAC, RSA_OAEP, RSA_PKCS1,
    RSA_PSS, RSA_RAW, ECDSA, EDDSA, ECDH, AES_KEY_WRAP, AES_KEY_WRAP_PAD, RSA_AES_KEY_WRAP,
];
```

#### 4.5.4 Behavioral notes (binding)

- Session/login state lives **inside** the provider instance, never in the console.
- `status()`, `mechanisms()`, `list_tokens()` of a never-initialized PKCS#11 provider do
  not load the library except `list_tokens()`, which initializes lazily (it is called
  only by `slots`/`login`/the wizard). Completion and `providers` call only `status()`.
- Copyability semantics (§5.5): for PKCS#11 keys `exportable = CKA_EXTRACTABLE ∧
  ¬CKA_SENSITIVE`; **wrappable** = `CKA_EXTRACTABLE` alone. `KeyInfo.attributes` always
  carries both flags for PKCS#11 secret/private keys.
- Signature encoding (binding): the canonical ECDSA signature is **fixed-width r‖s**
  (each half = ceil(curve bits / 8) = `(group.degree() + 7) / 8` for EVERY curve,
  including the `Curve::Other` ones — c2's `(curve.key_size + 7) // 8`;
  `Curve::field_bytes()` is the same value as a table); MemoryProvider converts to/from OpenSSL's DER with
  `r2_core::der`; Pkcs11Provider uses r‖s natively. EdDSA signatures are raw on both
  (64 B Ed25519 / 114 B Ed448); EdDSA signs only with `Signer::new_without_digest` +
  `sign_oneshot_to_vec`.
- GCM ciphertext convention: providers emit and consume `ct‖tag` (tag = tag_bits/8).
- Builtin param reads (binding for MemoryProvider, Pkcs11Provider's non-custom paths and
  FakeProvider): numbers only via `r2_core::params::param_int` (c2 `_param_int`), strings
  via `param_str` (pkcs11) / `param_choice` (memory), each with the default the matching
  c2 call site passes (e.g. tag_bits 128, counter_bits 128, hash "sha256").
  `ParamValue::as_int()` on an ENUM param
  (tag_bits arrives as `Enum("96")`) is a bug: it yields None and silently selects the
  default. The custom packers keep their own strict reads (§4.6.3).
- MAC verify = recompute + `r2_core::crypto::ct_eq` where the token has no C_Verify path.

#### 4.5.5 Concrete provider surfaces (frozen so the bootstrap and tests compile early)

```rust
// crates/r2-memory/src/lib.rs (R4)
pub struct MemoryProvider { /* RefCell state */ }
impl MemoryProvider {
    /// type_name "memory"; AuthState::NotRequired; advertises every canonical mechanism
    /// incl. RSA-AES-KEY-WRAP (OAEP(eph-AES-256)‖KWP blob, c2 format) and the wrap-capable
    /// AES-CBC/AES-GCM/RSA-PKCS1 rows of §5.4. Certificates are classified with
    /// `x509info::cert_facts(.., Classifier::KeyParse)` and carry
    /// `x509info::memory_cert_attributes` (§4.4.5).
    pub fn new(name: &str) -> Self { .. }
}
impl r2_provider::Provider for MemoryProvider { .. }
```

```rust
// crates/r2-pkcs11/src/provider/mod.rs (R5a)
use std::collections::BTreeMap;
use indexmap::IndexMap;
use r2_config::model::{CustomAttributeDef, Pkcs11InstanceConfig};

pub struct Pkcs11Provider { /* name, config, Rc<dyn Backend>, RefCell session/login/token/PIN state */ }
impl Pkcs11Provider {
    /// Never touches the library (lazy initialize, §6). `custom_mechanisms` = the plain map
    /// {entry.ckm: entry.id} from config (§4.6); `custom_attributes` =
    /// templates.custom_attributes (§4.8).
    pub fn new(
        name: &str,
        config: Pkcs11InstanceConfig,
        custom_mechanisms: BTreeMap<u64, String>,
        custom_attributes: IndexMap<String, CustomAttributeDef>,
    ) -> Self { .. }
    /// = TokenInit::init_token (kept inherent for parity with c2's surface).
    pub fn init_token(&self, slot: u64, label: &str, so_pin: &secrecy::SecretString, user_pin: &secrecy::SecretString) -> r2_core::Result<()> { .. }
    /// FakeBackend constructor for r2-pkcs11's own tests (§4.10.4).
    #[cfg(test)]
    pub(crate) fn with_backend(
        name: &str,
        config: Pkcs11InstanceConfig,
        custom_mechanisms: BTreeMap<u64, String>,
        custom_attributes: IndexMap<String, CustomAttributeDef>,
        backend: std::rc::Rc<dyn crate::backend::Backend>,
    ) -> Self { .. }
}
impl r2_provider::Provider for Pkcs11Provider { .. }   // as_token_init() → Some(self)
impl r2_provider::TokenInit for Pkcs11Provider { .. }
```

`impl Provider for Pkcs11Provider` is a single block in `provider/mod.rs` (R5a). Its
crypto/wrap/edit methods delegate to `pub(crate)` inherent methods that the skeleton
places in R5b's files: `encrypt_impl`, `decrypt_impl`, `sign_impl`, `verify_impl`,
`derive_impl` (`provider/crypto.rs`), `wrap_key_impl`, `unwrap_key_impl`
(`provider/wrap.rs`), `read_key_template_impl`, `update_key_impl`,
`read_full_template_impl` (`provider/edit.rs`). Each `*_impl` has the corresponding trait
method's signature minus the trait. `mechanisms()` (and the default `supports()`) are
R5a's: they call `crate::capability::fold_mechanisms(codes, &custom)` (§4.6.5), an R5a
function, so post-login capability discovery works before R5b merges. The certificate read
path uses `x509info::cert_facts(.., Classifier::Pkcs11)` + `x509info::cert_attributes`.

```rust
// crates/r2-pkcs11/src/env.rs (R5a; crate-private) — THE single audited set_var site
/// Sets each (key, value) in the process environment: `unsafe { std::env::set_var(k, v) }`
/// with `#[allow(unsafe_code)]` + `// SAFETY:` (single-threaded invariant, §6) and
/// `debug_assert!(!r2_core::runtime::spinner_active())`.
pub(crate) fn apply_env(vars: &[(&str, &str)]) { .. }
```

```rust
// crates/r2-pkcs11/src/backend/cryptoki.rs (R5a; crate-private module)
use cryptoki::mechanism::MechanismType;
use cryptoki::object::ObjectHandle;
use r2_config::model::Pkcs11InstanceConfig;

/// The real backend: cryptoki safe API + RawFns over the shared module of
/// `config.library`; never touches the library before `Backend::initialize`.
pub(crate) struct CryptokiBackend { /* config, RefCell<Option<Rc<SharedModule>>>, RefCell<Option<Session>> */ }
impl CryptokiBackend {
    pub(crate) fn new(config: &Pkcs11InstanceConfig) -> Self { .. }
}
impl super::Backend for CryptokiBackend { .. }
/// u64 → MechanismType: `CK_MECHANISM_TYPE::try_from(ckm)` (CK_ULONG is 32-bit on Windows;
/// overflow → `BackendError::Ckr(Ckr { code: CKR_MECHANISM_INVALID, function: "mech_type" })`),
/// then `transmute::<CK_MECHANISM_TYPE, MechanismType>` (audited unsafe site;
/// `MechanismType` is `#[repr(transparent)]` over `CK_MECHANISM_TYPE`).
pub(crate) fn mech_type(ckm: u64) -> BResult<MechanismType> { .. }
/// u64 → ObjectHandle: `CK_OBJECT_HANDLE::try_from(handle)` (overflow →
/// `Ckr { code: CKR_OBJECT_HANDLE_INVALID, function: "obj" }`), then the ONE
/// `ObjectHandle::new_from_raw` call (audited unsafe site, §4.1.3); every Backend method that
/// takes a handle goes through it. No handle cache.
pub(crate) fn obj(handle: u64) -> BResult<ObjectHandle> { .. }
```

R5a-internal (prose only, not materialized by R0, §4.1.1): `backend/raw.rs` holds
`RawFns` — second `dlopen` of the module + its `CK_FUNCTION_LIST`, with at least
`mechanism_list(slot) -> BResult<Vec<u64>>`, `token_info(slot) -> BResult<RawTokenInfo>`,
`get_attr(session, object, type) ->
BResult<Option<Zeroizing<Vec<u8>>>>` and the truncating `wrap(...) -> BResult<Vec<u8>>` and
raw-parameter crypto calls — and the thread-local registry of `Rc<SharedModule { ctx:
cryptoki::context::Pkcs11, raw: RawFns }>`.

PKCS#11 environment and lifecycle rules (S0 spike 1, binding for R5a):

- `Pkcs11InstanceConfig.env` is applied by EVERY provider on its own first
  `initialize()`, before it acquires the shared module — whether or not another provider
  has already loaded and initialized that library (c2 provider.py sets the instance env on
  each provider's first initialize) — at the single audited site
  `crate::env::apply_env(&[(&str, &str)])`.
- One shared module per canonical library path: a thread-local refcounted registry of
  `Rc<SharedModule { ctx: cryptoki::context::Pkcs11, raw: RawFns }>` (PyKCS11
  `_loaded_libs` parity). Registry key (normative) = `std::fs::canonicalize(&library)` of
  the already `expand_user`-ed `Pkcs11InstanceConfig.library`; when canonicalize fails, the
  expanded path as given (the load then fails with ProviderUnavailable anyway).
  `Backend::is_sole_module_user` and the `TokenInit::set_env_and_reset` refusal use the same
  key. This is a deliberate hardening over PyKCS11's filename-string key (§11 D21): two
  spellings of one library — e.g. `/usr/lib/softhsm/libsofthsm2.so`, a symlink, and its
  target `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`, both in the §7 search paths —
  are one dlopen handle, so string keys would let one provider's last release
  `C_Finalize` the other's sessions. R5a SoftHSM test: two providers whose libraries are a
  symlink (in a temp dir) and its target share one `SharedModule`; shutting one down leaves
  the other's session usable (no C_Finalize under it: the survivor, logged in, still
  generates a key — the sibling shut down only loaded the module, since its C_Logout would
  end the token-wide login exactly as in c2), and `is_sole_module_user` is false for both
  while both are initialized (both `set_env_and_reset` calls are refused) and true for the
  survivor afterwards (its reset succeeds). First acquire: `Pkcs11::new` +
  `initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))` (the args PyKCS11
  passes); `CKR_CRYPTOKI_ALREADY_INITIALIZED` = success; any other CKR →
  ProviderUnavailable (§5.2). Last release: sessions already dropped; the entry is removed
  from the registry and the registry's `RefCell` borrow is dropped; THEN `finalize()`, then
  drop `raw` and `ctx` (re-entrancy rule). Never finalize while any `Session` on that path
  is alive.
- One session per provider: `RefCell<Option<cryptoki::session::Session>>` next to its
  `Rc<SharedModule>` (RW|SERIAL). Switching slot replaces the Option (Drop =
  C_CloseSession). `logout()` keeps the session. `shutdown()` drops the session before
  releasing the module. `C_Login` uses `UserType::User`; `CKR_USER_ALREADY_LOGGED_IN`
  from the token is swallowed (login state is token-wide). An empty PIN is sent as
  `pPin=NULL, ulPinLen=0` (cryptoki `login(user, None)`), as PyKCS11 does — never a
  non-NULL empty buffer, which tokens count as CKR_PIN_INCORRECT (SoftHSM answers
  CKR_ARGUMENTS_BAD → "PKCS#11 login failed (CKR_ARGUMENTS_BAD)", c2 parity).
- Capability discovery folds `RawFns::mechanism_list(slot) -> Vec<u64>`;
  `Pkcs11::get_mechanism_list` MUST NOT be used (it drops every CKM without a TryFrom
  arm, incl. all vendor CKMs).
- Token info is a raw `C_GetTokenInfo` through `RawFns::token_info(slot)`, which reads
  only label, manufacturerID, model, serialNumber (UTF-8 with invalid sequences dropped —
  PyKCS11 `errors="ignore"`, no U+FFFD — then trailing spaces and NULs trimmed) and
  `CKF_TOKEN_INITIALIZED`; `Pkcs11::get_token_info` MUST NOT be used — its
  `TokenInfo` conversion parses `utcTime` whenever CKF_CLOCK_ON_TOKEN is set and fails on
  a blank or non-digit clock, which would make `slots`/`login`/session recovery fail on
  such a token, while PyKCS11 never parses `utcTime` (c2 parity).
- Attribute reads are one attribute per call through `RawFns::get_attr` (None =
  the size pass answered CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID or
  CKR_ARGUMENTS_BAD — PyKCS11 `getAttributeValue`/`_fragmented` parity — or returned
  `ulValueLen == CK_UNAVAILABLE_INFORMATION`; any other CKR is an error); `Session::get_attributes` MUST NOT be used. ULONG values
  are native-endian `CK_ULONG` of `size_of::<CK_ULONG>()` bytes; a ULONG VALUE that happens
  to equal `CK_UNAVAILABLE_INFORMATION` is a real value and is reported numerically (e.g.
  `CKA_KEY_GEN_MECHANISM: 18446744073709551615`, §5.16 — c2/PyKCS11 parity); BOOL = 1 byte.
  A CKA_ID read of `Some(empty)` becomes `KeyRef.key_id = None` (c2 `or None`; the §4.3
  invariant) — `get_attr` itself still reports the bytes it got. CKA_LABEL and
  CKA_APPLICATION (PyKCS11's `isString` attributes) decode as UTF-8 with invalid sequences
  dropped (`errors="ignore"`); CKA_APPLICATION is reported only when the DECODED text is
  non-empty (c2 `if app_v:`). Vendor STR values keep c2's own `errors="replace"`.
- Templates cross the seam as `RawAttr = (u64, Zeroizing<Vec<u8>>)` (they carry
  CKA_VALUE / private RSA components on import and unwrap) and become
  `Attribute::VendorDefined((AttributeType::VendorDefined(CK_ATTRIBUTE_TYPE::try_from(t)?), bytes))`
  for every type. ULONGs are encoded with `CK_ULONG::to_ne_bytes()` (4 bytes on Windows).
- Narrowing rule (`CK_ULONG` is `c_ulong`: 32-bit on Windows, a CI and release target):
  every `u64` → `CK_ULONG`-family conversion in r2-pkcs11 is checked with `try_from`, never
  `as`; an overflow is a `BackendError::Ckr` with the CKR the token would give for a bad
  value — mechanism codes → `CKR_MECHANISM_INVALID` (`mech_type`), object handles →
  `CKR_OBJECT_HANDLE_INVALID` (`obj`; so `@4294967297` on Windows is "not found"-class,
  never silently handle 1), attribute types → `CKR_ATTRIBUTE_TYPE_INVALID`, ULONG
  attribute values → `CKR_ATTRIBUTE_VALUE_INVALID`, `MechSpec` numeric fields (tag bits,
  counter bits, salt length, KDF/MGF/hash codes) → `CKR_MECHANISM_PARAM_INVALID`, slot ids
  (`Slot::try_from`) → `CKR_SLOT_ID_INVALID`. Widening `CK_ULONG` → `u64` uses `u64::from`.
- Every `C_WrapKey` goes through `RawFns::wrap` (truncates to the second-call length).
- Review rule: `VendorDefinedMechanism::new` takes only `Sized` `repr(C)`/
  `repr(transparent)` parameter structs from cryptoki/cryptoki-sys (never `&Vec<u8>`/
  `&String`, which silently send the container header); nested pointers are built in the
  same stack frame as the call. Runtime-length raw parameters go through RawFns.
- `RSA-AES-KEY-WRAP` is NOT advertised by Pkcs11Provider (D6 resolved as "no deviation";
  the shim recipe and the SoftHSM 2.7.0 OAEP-SHA1 interop hazard are recorded in §10 and §11 D6).

```rust
// crates/r2-pkcs11/src/softhsm.rs (R5a) — pure path probing, never loads a library
use std::path::PathBuf;
/// Environment variable overriding the probe list.
pub const SOFTHSM2_LIB_ENV: &str = "SOFTHSM2_LIB";
/// `$SOFTHSM2_LIB` (non-empty; `text::py_path`-normalized, no `~` expansion — c2
/// `Path(override)`) wins: returned iff it exists (an explicit override never
/// falls through). Otherwise the first existing path of `search_paths` (the caller passes
/// `AppConfig.softhsm.search_paths`); None when nothing exists.
pub fn find_softhsm_module(search_paths: &[PathBuf]) -> Option<PathBuf> { .. }
```

```rust
// crates/r2-core/src/catalog.rs (owner R5a; R0 materializes this table verbatim)
use crate::template::AttrKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogEntry { pub name: &'static str, pub code: u64, pub kind: AttrKind }

const fn e(name: &'static str, code: u64, kind: AttrKind) -> CatalogEntry { CatalogEntry { name, code, kind } }
use crate::template::AttrKind::{Bool as B, Bytes as Y, Str as S, Ulong as U};

/// The static CKA dictionary (c2 attributes.py, same order). Codes are PKCS#11 v3.0
/// literals. No cryptoki dependency, so console/services/testkit may use it.
pub const CKA_CATALOG: &[CatalogEntry] = &[
    e("CKA_CLASS", 0x0000, U), e("CKA_TOKEN", 0x0001, B), e("CKA_PRIVATE", 0x0002, B),
    e("CKA_LABEL", 0x0003, S), e("CKA_APPLICATION", 0x0010, S), e("CKA_VALUE", 0x0011, Y),
    e("CKA_OBJECT_ID", 0x0012, Y), e("CKA_CERTIFICATE_TYPE", 0x0080, U), e("CKA_ISSUER", 0x0081, Y),
    e("CKA_SERIAL_NUMBER", 0x0082, Y), e("CKA_TRUSTED", 0x0086, B),
    e("CKA_CERTIFICATE_CATEGORY", 0x0087, U), e("CKA_URL", 0x0089, Y),
    e("CKA_HASH_OF_SUBJECT_PUBLIC_KEY", 0x008A, Y), e("CKA_HASH_OF_ISSUER_PUBLIC_KEY", 0x008B, Y),
    e("CKA_CHECK_VALUE", 0x0090, Y), e("CKA_KEY_TYPE", 0x0100, U), e("CKA_SUBJECT", 0x0101, Y),
    e("CKA_ID", 0x0102, Y), e("CKA_START_DATE", 0x0110, Y), e("CKA_END_DATE", 0x0111, Y),
    e("CKA_SENSITIVE", 0x0103, B), e("CKA_ENCRYPT", 0x0104, B), e("CKA_DECRYPT", 0x0105, B),
    e("CKA_WRAP", 0x0106, B), e("CKA_UNWRAP", 0x0107, B), e("CKA_SIGN", 0x0108, B),
    e("CKA_SIGN_RECOVER", 0x0109, B), e("CKA_VERIFY", 0x010A, B), e("CKA_VERIFY_RECOVER", 0x010B, B),
    e("CKA_DERIVE", 0x010C, B), e("CKA_MODULUS", 0x0120, Y), e("CKA_MODULUS_BITS", 0x0121, U),
    e("CKA_PUBLIC_EXPONENT", 0x0122, Y), e("CKA_PRIVATE_EXPONENT", 0x0123, Y), e("CKA_PRIME_1", 0x0124, Y),
    e("CKA_PRIME_2", 0x0125, Y), e("CKA_EXPONENT_1", 0x0126, Y), e("CKA_EXPONENT_2", 0x0127, Y),
    e("CKA_COEFFICIENT", 0x0128, Y), e("CKA_PUBLIC_KEY_INFO", 0x0129, Y), e("CKA_PRIME", 0x0130, Y),
    e("CKA_SUBPRIME", 0x0131, Y), e("CKA_BASE", 0x0132, Y), e("CKA_VALUE_BITS", 0x0160, U),
    e("CKA_VALUE_LEN", 0x0161, U), e("CKA_EXTRACTABLE", 0x0162, B), e("CKA_LOCAL", 0x0163, B),
    e("CKA_NEVER_EXTRACTABLE", 0x0164, B), e("CKA_ALWAYS_SENSITIVE", 0x0165, B),
    e("CKA_KEY_GEN_MECHANISM", 0x0166, U), e("CKA_MODIFIABLE", 0x0170, B), e("CKA_COPYABLE", 0x0171, B),
    e("CKA_DESTROYABLE", 0x0172, B), e("CKA_EC_PARAMS", 0x0180, Y), e("CKA_EC_POINT", 0x0181, Y),
    e("CKA_ALWAYS_AUTHENTICATE", 0x0202, B), e("CKA_WRAP_WITH_TRUSTED", 0x0210, B),
];

/// Lookup by name: `CKA_CATALOG.iter().find(|e| e.name == name)` (R0 mandated body).
pub fn cka(name: &str) -> Option<&'static CatalogEntry> { .. }
/// Lookup by code: `CKA_CATALOG.iter().find(|e| e.code == code)` (R0 mandated body).
pub fn cka_by_code(code: u64) -> Option<&'static CatalogEntry> { .. }
```

`CKA_CERTIFICATE_CATEGORY` is a ULONG row that cryptoki cannot decode; with the RawFns
one-attribute read path it is just a native-endian CK_ULONG (no special casing needed).

```rust
// crates/r2-pkcs11/src/catalog.rs (R5a) — name tables (no cryptoki CALLS; constants only)
use std::borrow::Cow;
pub use r2_core::catalog::{cka, cka_by_code, CatalogEntry, CKA_CATALOG};

/// Value of a `CKO_`/`CKK_`/`CKC_`/`CKM_` name in PyKCS11's dicts (symbolic template ULONGs
/// resolve here); None for any other name (→ Param at conversion, §4.7).
pub fn symbol_value(name: &str) -> Option<u64> { .. }
/// Reverse maps = PyKCS11's value→name entries (its alias choice, e.g. 0x3 → "CKK_EC").
pub fn cko_name(code: u64) -> Option<&'static str> { .. }
pub fn ckk_name(code: u64) -> Option<&'static str> { .. }
pub fn ckc_name(code: u64) -> Option<&'static str> { .. }
pub fn ckm_name(code: u64) -> Option<&'static str> { .. }
/// PyKCS11's CKR name, else "CKR_0x%08X" of the low 32 bits (c2 `_translate`).
pub fn ckr_name(code: u64) -> Cow<'static, str> { .. }
/// `KeyInfo.attributes["CKA_KEY_TYPE"]` / template rows: ckk_name, else "0x%08x" (lower-case,
/// c2 `_ckk_symbol`).
pub fn ckk_symbol(code: u64) -> String { .. }
```

Name tables (normative): every CKO/CKK/CKC/CKM/CKR table — forward (`symbol_value`) and
reverse — EQUALS PyKCS11's dictionaries at c2's pinned PyKCS11 1.5.18 (93 CKR, 58 CKK, 425
CKM, 10 CKO, 3 CKC names), as a static table committed in `catalog.rs` and generated once
(R5a; generator script kept next to the ledger generator). cryptoki-sys 0.5.0 is a strict
superset (12 more CKR names, e.g. CKR_ACTION_PROHIBITED, CKR_AEAD_DECRYPT_FAILED,
CKR_TOKEN_NOT_INITIALIZED; 11 more CKK such as CKK_ML_DSA; 55 more CKM; CKO_TRUST /
CKO_VALIDATION / CKO_VENDOR_DEFINED) and serves only as a numeric cross-check: codes that
PyKCS11 cannot name render with c2's fallbacks (`CKR_0x%08X`, `0x%08x`), so error texts,
`CKA_KEY_TYPE` cells and template dumps stay identical to c2's and stay loadable by c2.

#### 4.5.6 PKCS#11 backend seam (`r2_pkcs11::backend`, crate-private, R5a)

Raw-shaped and r2-owned: CKMs are `u64`, templates are `(u64, Zeroizing<Vec<u8>>)`,
attribute reads are `Option<Zeroizing<Vec<u8>>>`, errors are raw `CK_RV`s. `CryptokiBackend` implements it over
cryptoki (+ RawFns) and is the **single CKR choke point** together with `crate::ckr`;
`FakeBackend` (§4.10.4) implements it in memory. Everything else in the provider
(identity resolution, twin guard, CKM folding, software fallbacks, auto-recovery) is
backend-agnostic.

```rust
// crates/r2-pkcs11/src/backend/mod.rs
use secrecy::SecretString;
use zeroize::Zeroizing;

/// One template entry: (CK_ATTRIBUTE_TYPE, value bytes). BOOL = 1 byte; ULONG =
/// native-endian CK_ULONG; STR = UTF-8; BYTES verbatim. Zeroizing: templates carry key
/// material on import/unwrap (D3).
pub(crate) type RawAttr = (u64, Zeroizing<Vec<u8>>);

/// A CK_RV failure with its call context (cryptoki `Function`, or the RawFns call name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ckr { pub code: u64, pub function: &'static str }

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BackendError {
    /// cryptoki `Error::Pkcs11(rv, function)` (code via the r2 RvError→CK_RV map: an
    /// exhaustive match or the reverse table built once from cryptoki-sys `CKR_*`;
    /// `RvError::VendorDefined(c)`/`UnknownErrorCode(c)` carry `c`), any RawFns CK_RV, and
    /// `Error::NullFunctionPointer` as CKR_FUNCTION_NOT_SUPPORTED.
    Ckr(Ckr),
    /// `Error::LibraryLoading` / `Error::MissingSymbol` → ProviderUnavailable "cannot load
    /// PKCS#11 library {library}: {detail}" (§5.2; detail = the libloading/cryptoki text, D11).
    LibraryUnavailable(String),
    /// Any other non-CKR cryptoki error (NotSupported, InvalidValue, conversion errors) →
    /// Pkcs11 "PKCS#11 {context} failed (CKR_0xFFFFFFFF)" with ckr_code 0xFFFF_FFFF — c2's
    /// rendering of PyKCS11's non-CKR errors (value −1); the detail is logged only.
    Binding(String),
}
pub(crate) type BResult<T> = std::result::Result<T, BackendError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawTokenInfo {
    pub slot_id: u64,
    /// label/manufacturer/model/serial: trailing ' ' and '\0' trimmed.
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    pub initialized: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UserKind { User, So }

/// r2-owned mechanism description; CryptokiBackend maps it per the S0 table:
/// native `Mechanism` variants for ECB, CBC, CBC_PAD, GCM, AesCMac, ShaXHmac, RsaPkcs,
/// ShaXRsaPkcs, RsaPkcsOaep, RsaPkcsPss/ShaXRsaPkcsPss, RsaX509, Ecdsa/EcdsaShaX, Eddsa,
/// Ecdh1Derive, AesKeyWrap, AesKeyWrapPad and the keygens; `Mechanism::VendorDefined(
/// VendorDefinedMechanism::new(mech_type(ckm), Some(&sized_struct)))` for AES-CTR
/// (CK_AES_CTR_PARAMS), CKM_AES_GMAC (GcmParams), CKM_AES_KEY_WRAP_KWP (no params),
/// CKM_SHA224_RSA_PKCS_PSS (PkcsPssParams) and the custom none/gcm/oaep packers; RawFns
/// crypto calls for `Bytes` (runtime-length parameters).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MechSpec {
    /// NULL pParameter.
    Plain { ckm: u64 },
    /// pParameter = `param` verbatim (CBC IV, custom `iv`/`raw` packers); empty → NULL.
    Bytes { ckm: u64, param: Vec<u8> },
    /// CK_GCM_PARAMS: owned IV copy, AAD always non-NULL (possibly empty), ulTagBits.
    Gcm { ckm: u64, iv: Vec<u8>, aad: Vec<u8>, tag_bits: u64 },
    /// CK_AES_CTR_PARAMS (CKM_AES_CTR): full 16-byte counter block.
    Ctr { counter_bits: u64, counter_block: [u8; 16] },
    /// CK_RSA_PKCS_OAEP_PARAMS, source = CKZ_DATA_SPECIFIED, empty label → NULL source data.
    Oaep { ckm: u64, hash_ckm: u64, mgf: u64, label: Vec<u8> },
    /// CK_RSA_PKCS_PSS_PARAMS.
    Pss { ckm: u64, hash_ckm: u64, mgf: u64, salt_len: u64 },
    /// CK_ECDH1_DERIVE_PARAMS; `public_data` is the RAW point / u-coordinate (never DER).
    Ecdh1 { kdf: u64, shared_data: Vec<u8>, public_data: Vec<u8> },
    /// Ed25519: NULL params (pure); Ed448: CK_EDDSA_PARAMS{phFlag=0, no context}.
    Eddsa { ckm: u64, ed448: bool },
}

/// One instance per Pkcs11Provider (it owns that provider's session). All `&self`.
pub(crate) trait Backend {
    /// Acquire the shared module for the library path (+ C_Initialize once). Idempotent.
    fn initialize(&self) -> BResult<()>;
    /// Drop this backend's session and release its module reference (last release
    /// finalizes). Safe when not initialized.
    fn finalize(&self) -> BResult<()>;
    /// True when no other backend holds the same module, keyed by canonical library path
    /// (§4.5.5; TokenInit::set_env_and_reset).
    fn is_sole_module_user(&self) -> bool;
    fn slots_with_token(&self) -> BResult<Vec<u64>>;
    /// Raw C_GetTokenInfo (RawFns; `utcTime` never parsed).
    fn token_info(&self, slot: u64) -> BResult<RawTokenInfo>;
    /// Unfiltered C_GetMechanismList (RawFns).
    fn mechanism_list(&self, slot: u64) -> BResult<Vec<u64>>;
    /// CKF_SERIAL_SESSION|CKF_RW_SESSION; replaces (closes) the current session.
    fn open_session(&self, slot: u64) -> BResult<()>;
    fn close_session(&self) -> BResult<()>;
    fn has_session(&self) -> bool;
    /// CKR_USER_ALREADY_LOGGED_IN is returned as an error; the provider swallows it.
    fn login(&self, user: UserKind, pin: &SecretString) -> BResult<()>;
    fn logout(&self) -> BResult<()>;
    /// `label` ≤ 32 bytes (validated by the provider), space-padded here.
    fn init_token(&self, slot: u64, so_pin: &SecretString, label: &str) -> BResult<()>;
    fn init_pin(&self, pin: &SecretString) -> BResult<()>;
    fn find_objects(&self, template: &[RawAttr]) -> BResult<Vec<u64>>;
    /// One attribute per call; None = sensitive, type-invalid, arguments-bad or unavailable.
    fn get_attr(&self, object: u64, attribute: u64) -> BResult<Option<Zeroizing<Vec<u8>>>>;
    /// One C_SetAttributeValue call (all-or-nothing).
    fn set_attrs(&self, object: u64, template: &[RawAttr]) -> BResult<()>;
    fn create_object(&self, template: &[RawAttr]) -> BResult<u64>;
    fn destroy_object(&self, object: u64) -> BResult<()>;
    fn generate_key(&self, mech: &MechSpec, template: &[RawAttr]) -> BResult<u64>;
    /// Returns (public handle, private handle).
    fn generate_key_pair(&self, mech: &MechSpec, public: &[RawAttr], private: &[RawAttr]) -> BResult<(u64, u64)>;
    fn encrypt(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Vec<u8>>;
    /// C_EncryptInit + C_EncryptUpdate per part + C_EncryptFinal (GMAC-over-GCM fallback).
    fn encrypt_multipart(&self, mech: &MechSpec, key: u64, parts: &[&[u8]]) -> BResult<Vec<u8>>;
    fn decrypt(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Zeroizing<Vec<u8>>>;
    fn sign(&self, mech: &MechSpec, key: u64, data: &[u8]) -> BResult<Vec<u8>>;
    /// CKR_SIGNATURE_INVALID / CKR_SIGNATURE_LEN_RANGE from C_Verify → Ok(false).
    fn verify(&self, mech: &MechSpec, key: u64, data: &[u8], signature: &[u8]) -> BResult<bool>;
    /// Always RawFns::wrap (second-call length truncation).
    fn wrap_key(&self, mech: &MechSpec, wrapping_key: u64, key: u64) -> BResult<Vec<u8>>;
    fn unwrap_key(&self, mech: &MechSpec, unwrapping_key: u64, wrapped: &[u8], template: &[RawAttr]) -> BResult<u64>;
    fn derive_key(&self, mech: &MechSpec, base_key: u64, template: &[RawAttr]) -> BResult<u64>;
}
```

```rust
// crates/r2-pkcs11/src/ckr.rs (R5a; crate-private) — the CKR choke point
use r2_core::error::ConsoleError;

use crate::backend::BackendError;

/// Implements the §5.2 table (names via `catalog::ckr_name`). `provider` = the provider
/// instance name (the ``login <provider>`` / ``slots <provider>`` texts of the table).
/// `token_label` = the label in the CKR_PIN_* texts: callers pass the logged-in token's
/// label (or the token being logged in to); None renders "?" (c2's default). The CALLER
/// logs "{provider}: {context} failed with {CKR}" at INFO. For `LibraryUnavailable` the
/// `context` is the library path ("cannot load PKCS#11 library {context}: {detail}"):
/// `Provider::initialize` renders every load failure through it.
pub(crate) fn translate(err: BackendError, provider: &str, context: &str, token_label: Option<&str>) -> ConsoleError { .. }
```

`Backend::initialize` reports any `C_Initialize` CKR other than
`CKR_CRYPTOKI_ALREADY_INITIALIZED` as `BackendError::LibraryUnavailable` with PyKCS11's
error text as detail ("{CKR name} (0x%08X)", "Vendor error (0x%08X)" or "Unknown error
(0x%08X)", §5.2), so it surfaces as ProviderUnavailable exactly like c2. Field notes
carried as requirements: SoftHSM answers
`CKR_ATTRIBUTE_READ_ONLY` to `CKA_VALUE_LEN` in unwrap templates (outside c2's retry set,
which is ported verbatim: TYPE_INVALID, VALUE_INVALID, TEMPLATE_INCONSISTENT); the
non-SHA1 OAEP software fallback triggers on `CKR_ARGUMENTS_BAD` /
`CKR_MECHANISM_PARAM_INVALID`.

### 4.6 Operation model, registry, ParamResolver (`r2_core::params`, `r2_ops`)

`Verb`, `ParamKind`, `ParamSpec`, `ParamValue`, `ParamStruct` and `Params` live in
`r2_core::params` (so config and `r2_core::io` may use them without `r2-ops`);
`r2_ops::model` re-exports them next to `OperationSpec`.

#### 4.6.1 Core parameter types (`r2_core::params`, R1)

```rust
use std::fmt;
use std::str::FromStr;
use indexmap::IndexMap;
use crate::error::{ConsoleError, Result};
use crate::keys::KeyInfo;

/// Token: "encrypt" | "decrypt" | "sign" | "verify" | "derive".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Verb { Encrypt, Decrypt, Sign, Verify, Derive }
impl Verb {
    pub const ALL: [Verb; 5] = [Verb::Encrypt, Verb::Decrypt, Verb::Sign, Verb::Verify, Verb::Derive];
    pub fn as_str(self) -> &'static str { .. }
}

/// Token: "bytes" | "int" | "str" | "bool" | "enum" | "keyref".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParamKind {
    /// hex/base64 via decode_data; "0x…" accepted.
    Bytes,
    /// Decimal digits with an optional leading '-' only (no "max" tokens; sentinels such as
    /// salt_len=-1 are documented per param).
    Int,
    Str,
    /// true/false/yes/no/on/off/1/0, case-insensitive.
    Bool,
    /// `choices` required.
    Enum,
    /// Full §4.3 ref grammar, resolved via ProviderRegistry to the target's KeyInfo.
    KeyRef,
}
impl ParamKind { pub fn as_str(self) -> &'static str { .. } }

/// Custom-mechanism parameter packer selector. Token: "none" | "iv" | "gcm" | "oaep" | "raw".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ParamStruct { #[default] None, Iv, Gcm, Oaep, Raw }
impl ParamStruct { pub fn as_str(self) -> &'static str { .. } }

impl fmt::Display for Verb { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { .. } }
/// Exact tokens; else Generic "unknown verb {s!r}".
impl FromStr for Verb { type Err = ConsoleError; fn from_str(s: &str) -> Result<Self> { .. } }
impl fmt::Display for ParamKind { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { .. } }
/// Exact tokens; else Generic "unknown parameter kind {s!r}".
impl FromStr for ParamKind { type Err = ConsoleError; fn from_str(s: &str) -> Result<Self> { .. } }
impl fmt::Display for ParamStruct { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { .. } }
/// Exact tokens; else Generic "unknown param_struct {s!r}".
impl FromStr for ParamStruct { type Err = ConsoleError; fn from_str(s: &str) -> Result<Self> { .. } }

/// A resolved parameter value (c2 `object`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamValue {
    Bytes(Vec<u8>),
    Int(i64),
    Str(String),
    Bool(bool),
    /// The chosen ENUM token, verbatim (e.g. tag_bits "128"). Normative: EVERY value of an
    /// ENUM param is `Enum` — built-in and custom defaults, resolver output, `default_from`
    /// mirrors and maps that services build by hand (certops' `{"hash": …}`, the transfer
    /// OAEP defaults). Sole exception: a custom-mechanism ENUM default written as a YAML int
    /// stays `Int` (§4.8.3, c2 parity for the gcm packer's `tag_bits`). Providers read
    /// builtin params only through `param_int`/`param_str`/`param_choice` below (and
    /// `as_bytes()`/`as_bool()`/`as_key()`), never by matching a variant; `as_int()` is
    /// NEVER used for a builtin param of kind ENUM (tag_bits), whose value is `Enum("96")`.
    Enum(String),
    KeyRef(Box<KeyInfo>),
}
impl ParamValue {
    pub fn as_bytes(&self) -> Option<&[u8]> { .. }
    pub fn as_int(&self) -> Option<i64> { .. }
    /// Str or Enum.
    pub fn as_str(&self) -> Option<&str> { .. }
    pub fn as_bool(&self) -> Option<bool> { .. }
    pub fn as_key(&self) -> Option<&KeyInfo> { .. }
}

/// Resolved parameters in ParamSpec order. A non-required parameter whose default is
/// c2's `None` (e.g. salt_len, mac_len) is ABSENT from the map (c2 stored an explicit None;
/// the one observable consequence — custom packers — is §4.6.3 / §11 D18).
pub type Params = IndexMap<String, ParamValue>;

/// c2 `_param_int` (memory.py:403, pkcs11/provider.py:378), the ONE way MemoryProvider,
/// Pkcs11Provider (non-custom paths) and FakeProvider read a numeric builtin param
/// (tag_bits, counter_bits, mac_len, salt_len, out_len): absent → `default`; `Int(v)` → v;
/// `Str(s)`/`Enum(s)` → `text::py_int(s, 10)` (outside i64 counts as unparsable — §11
/// D18), else Param "parameter '{name}' must be an integer, got {py_repr(s)}"; `Bool`,
/// `Bytes`, `KeyRef` → Param "parameter '{name}' must be an integer". param_name = name.
pub fn param_int(params: &Params, name: &str, default: i64) -> Result<i64> { .. }
/// c2 pkcs11 `_param_str`: absent → `default`; `Str(s)`/`Enum(s)` → s; anything else →
/// Param "parameter '{name}' must be a string" (param_name = name). Pkcs11Provider and
/// FakeProvider read string builtin params (hash, mgf_hash, padding, kdf) through it.
pub fn param_str<'a>(params: &'a Params, name: &str, default: &'a str) -> Result<&'a str> { .. }
/// c2 memory `_param_choice`/`_validate_choice`: absent → `default`; else the value's text
/// (`Str`/`Enum` verbatim, `Int` decimal, `Bool` `text::py_bool`, `Bytes`
/// `text::py_bytes_repr`, `KeyRef` its `key_ref.display()` — unreachable in practice,
/// since the resolver types ENUM params) must be a member of `choices`, else
/// Param "parameter '{name}' must be one of {choices joined ', '}; got {py_repr(text)}"
/// (param_name = name). MemoryProvider reads its ENUM params (hash, mgf_hash, padding,
/// tag_bits, kdf) through it; `int(param_choice(.., "tag_bits", ..))` is then a plain parse
/// of a member of {128,120,112,104,96}.
pub fn param_choice(params: &Params, name: &str, choices: &[&str], default: &str) -> Result<String> { .. }

/// Per-param validator; returns Param itself on failure. Compared by function address
/// (`std::ptr::fn_addr_eq`); Debug prints "ParamValidator(..)".
#[derive(Clone, Copy)]
pub struct ParamValidator(pub fn(&ParamValue) -> Result<()>);
impl fmt::Debug for ParamValidator { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { .. } }
impl PartialEq for ParamValidator { fn eq(&self, other: &Self) -> bool { .. } }
impl Eq for ParamValidator {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamSpec {
    pub name: String,
    pub kind: ParamKind,
    /// Prompt text without the trailing ": " (the IO appends it).
    pub prompt: String,
    pub required: bool,
    pub default: Option<ParamValue>,
    /// Mirror another (earlier) param's resolved value when this one is not given.
    pub default_from: Option<String>,
    pub choices: Option<Vec<String>>,
    /// Exact byte length (BYTES).
    pub length: Option<usize>,
    pub validate: Option<ParamValidator>,
}
impl ParamSpec {
    /// required = true, everything else None.
    pub fn new(name: impl Into<String>, kind: ParamKind, prompt: impl Into<String>) -> Self { .. }
    /// The blessed synthetic STR spec (template-editor line, REPL fallback, labels).
    pub fn str(name: impl Into<String>, prompt: impl Into<String>) -> Self { .. }
    /// required = false with this default (None = c2's `default=None`).
    pub fn optional(self, default: Option<ParamValue>) -> Self { .. }
    pub fn default_from(self, name: impl Into<String>) -> Self { .. }
    pub fn choices(self, choices: &[&str]) -> Self { .. }
    pub fn length(self, length: usize) -> Self { .. }
    pub fn validate(self, validator: fn(&ParamValue) -> Result<()>) -> Self { .. }
}
```

#### 4.6.2 `OperationSpec` and `OperationRegistry` (`r2_ops`, R3)

```rust
// crates/r2-ops/src/model.rs
use std::collections::BTreeSet;
pub use r2_core::params::{ParamKind, ParamSpec, ParamStruct, ParamValue, Params, Verb};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass};
use r2_provider::MechanismInvocation;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationSpec {
    /// "<algo>.<verb>.<mode>", e.g. "aes.encrypt.gcm".
    pub id: String,
    pub verb: Verb,
    pub algorithm: KeyAlgorithm,
    /// CERTIFICATE is a member wherever PUBLIC is (§4.3).
    pub key_classes: BTreeSet<KeyClass>,
    /// Canonical mechanism name (§4.6.5) or a custom mechanism id.
    pub mechanism: String,
    /// Typed at the prompt: "gcm", "oaep", "ecdsa".
    pub cli_name: String,
    /// Human description (`ops` table, select menus).
    pub label: String,
    /// Excludes the payload (fixed per verb: encrypt/decrypt/sign take `data`, verify takes
    /// `data` + `signature`, derive takes none).
    pub params: Vec<ParamSpec>,
    /// None = any.
    pub provider_types: Option<BTreeSet<String>>,
    /// Restrict to named instances.
    pub providers: Option<BTreeSet<String>>,
    /// Restrict to KeyInfo.curve values (ec.derive.x25519 binds to x25519 keys only).
    pub curves: Option<BTreeSet<Curve>>,
    /// Custom mechanisms: vendor CKM code.
    pub raw_ckm: Option<u64>,
    pub param_struct: ParamStruct,
}
impl OperationSpec {
    /// The command-layer copy (§4.6): mechanism, params, raw_ckm, param_struct, and
    /// raw_param_bytes = params["mechparam"] bytes when param_struct == Raw.
    pub fn invocation(&self, params: Params) -> MechanismInvocation { .. }
    pub fn param(&self, name: &str) -> Option<&ParamSpec> { .. }
    /// The mirror rule: same cli_name/mechanism/params; id with `.{verb}.` swapped (first
    /// occurrence), the new verb and label, and `key_classes` replaced when given.
    pub fn mirrored(&self, verb: Verb, label: &str, key_classes: Option<BTreeSet<KeyClass>>) -> OperationSpec { .. }
}
```

```rust
// crates/r2-ops/src/registry.rs
use r2_config::model::CustomMechanismConfig;
use r2_core::error::Result;
use r2_core::keys::KeyInfo;
use r2_provider::Provider;

use crate::model::{OperationSpec, Verb};

/// Insertion-ordered (registration order = iteration order of available_for).
#[derive(Clone, Debug, Default)]
pub struct OperationRegistry { /* IndexMap<String, OperationSpec> */ }

impl OperationRegistry {
    pub fn new() -> Self { .. }
    /// Duplicate id → Config "operation '{id}' is already registered" (hint "operation ids
    /// (built-in and custom_mechanisms[].id) must be unique").
    pub fn register(&mut self, spec: OperationSpec) -> Result<()> { .. }
    /// Unknown → UnknownOperation "unknown operation '{id}'" (hint = suggestion over all ids).
    pub fn get(&self, op_id: &str) -> Result<&OperationSpec> { .. }
    /// (verb, key.algorithm, cli_name) → the FIRST spec in registration order with that
    /// verb and algorithm whose `curves` admit key.curve and whose cli_name matches
    /// (key_class is NOT checked here; so a custom mechanism reusing a built-in cli_name for
    /// the same verb and algorithm is shadowed by the built-in, as in c2). Miss →
    /// UnknownOperation "no {verb} operation '{cli}' for {algorithm} keys" + " (curve {c})"
    /// when the key has a curve; hint = suggestion over those candidates' cli names.
    /// CERTIFICATE keys resolve as their public-key algorithm (their KeyInfo.algorithm).
    pub fn resolve_cli(&self, verb: Verb, key: &KeyInfo, cli_name: &str) -> Result<&OperationSpec> { .. }
    /// Specs with this verb and key.algorithm, key.key_class ∈ key_classes,
    /// provider.type_name() ∈ provider_types (when set), provider.name() ∈ providers (when
    /// set), key.curve ∈ curves (when set) AND mechanism ∈ provider.mechanisms();
    /// registration order (consumers that present specs sort them — see below).
    pub fn available_for(&self, verb: Verb, key: &KeyInfo, provider: &dyn Provider) -> Vec<&OperationSpec> { .. }
    /// Register every config-defined vendor mechanism (custom::spec_from_config).
    pub fn load_custom(&mut self, entries: &[CustomMechanismConfig]) -> Result<()> { .. }
}

/// Suggestion hint shared by get/resolve_cli: names sorted; none → "no operations are
/// registered for this verb and key type"; close matches (n=3) → "did you mean: a, b";
/// else "valid choices: {all joined ', '}".
pub fn suggest_hint(wanted: &str, known: &[&str]) -> String { .. }

/// Applies builtin_aes, builtin_rsa, builtin_ec, builtin_generic (in this order); each of
/// those modules exports `pub fn register_builtin(reg: &mut OperationRegistry) -> Result<()>`.
pub fn register_builtins(reg: &mut OperationRegistry) -> Result<()> { .. }

/// The bootstrap sequence: register_builtins then load_custom(custom). Used by r2-cli and
/// by the console test support (§4.10.6).
pub fn build_operation_registry(custom: &[CustomMechanismConfig]) -> Result<OperationRegistry> { .. }
```

Presentation order (binding for R9; c2 `crypto_cmd.py`): `available_for` itself stays in
registration order, and consumers that present specs sort them. The crypto-verb mechanism
`select()` (omitted `<mech>`, §5.1) lists `available_for(..)` sorted by `(cli_name, id)`,
options `"{cli_name} — {label}"`, and maps the chosen index back into that sorted list (c2
`_select_mechanism`; ported tests answer by index, e.g. AES encrypt → cbc, ctr, ecb, gcm).
Completion of the `<mech>` stage offers the sorted, de-duplicated cli names. The `ops` table
merges `available_for` over every verb (`Verb::ALL` order) and every key (the `--key` key,
or c2's synthetic per-algorithm/curve/class probe keys, `_probe_keys`), de-duplicates by
`id` with the first occurrence winning, and sorts by (verb declaration order, cli_name,
id) (c2 `_merge_specs`).

#### 4.6.3 Custom mechanisms (`r2_ops::custom`, R3)

```rust
// crates/r2-ops/src/custom.rs
use std::collections::BTreeSet;
use r2_config::model::CustomMechanismConfig;
use r2_core::keys::{KeyAlgorithm, KeyClass};

use crate::model::{OperationSpec, ParamSpec, Verb};

/// Each custom_mechanisms[] entry → OperationSpec{ id, verb, algorithm, key_classes =
/// derive_key_classes(verb, algorithm), mechanism = entry.id, cli_name, label, params =
/// entry.params converted 1:1 (+ raw_mechparam_spec() appended when param_struct == Raw),
/// provider_types = entry.provider_types or {"pkcs11"} (vendor CKMs never target memory by
/// default), providers = entry.providers, curves = None, raw_ckm = Some(entry.ckm),
/// param_struct = entry.param_struct }.
pub fn spec_from_config(entry: &CustomMechanismConfig) -> OperationSpec { .. }
/// AES/GENERIC → {SECRET} for every verb; RSA/EC/EC_EDWARDS/EC_MONTGOMERY → encrypt and
/// verify: {PUBLIC, CERTIFICATE}; decrypt, sign, derive: {PRIVATE}. (The config loader
/// rejects algorithm none|other.)
pub fn derive_key_classes(verb: Verb, algorithm: KeyAlgorithm) -> BTreeSet<KeyClass> { .. }
/// ParamSpec::new("mechparam", ParamKind::Bytes, "Raw mechanism parameter bytes").
pub fn raw_mechparam_spec() -> ParamSpec { .. }
```

`r2-ops` never touches a provider table (§3.1). The bootstrap passes the plain map
`{entry.ckm: entry.id}` (`BTreeMap<u64, String>`) into every `Pkcs11Provider::new`; the
provider merges it into its CKM folding so `mechanisms()` advertises `entry.id` whenever
the token lists `entry.ckm` (the folding itself is `crate::capability`, R5a, §4.6.5).
`param_struct` selects one of five fixed packers in r2-pkcs11's `crate::mechanisms` (R5b),
producing a `MechSpec` (§4.5.6), with c2's `pack_custom` reads (`params.get(name,
default)`):
- `none` → `Plain{ckm}`;
- `iv` → `Bytes{ckm, param = bytes "iv"}` (no default);
- `gcm` → `Gcm{ckm, iv = bytes "iv" (no default), aad = bytes "aad" (default empty),
  tag_bits = INTEGER "tag_bits" (default 128)}` — only `ParamValue::Int` is an integer: an
  ENUM/STR-kind `tag_bits` value given by the operator (`Enum("96")`/`Str`) fails exactly
  as in c2, while an ENUM default written as a YAML int (`default: 128`) stays `Int`
  (§4.8.3) and is accepted, as in c2;
- `oaep` → `Oaep{ckm, hash = string "hash" (default "sha256"), mgf_hash = string
  "mgf_hash" (default = hash), label = bytes "label" (default empty)}` (a string is `Str`
  or `Enum`);
- `raw` → `Bytes{ckm, param = raw_param_bytes, else bytes "mechparam" (no default)}`.
A present value of the wrong type, or a missing one without default → Param "custom
mechanism parameter {name!r} must be bytes" (param_name = name, hint "conventional packer
param names: iv/aad/tag_bits, hash/mgf_hash/label, mechparam") / "… must be an integer" /
"… must be a string" (these two WITHOUT a hint — c2 `_int_param`/`_str_param`). A
declared-but-unset optional param with no default is ABSENT in r2 (§4.6.1), so the packer
default applies where c2 (which stored None) raised the type error — §11 D18. No raw_ckm →
Crypto "custom mechanism {id!r} has no raw CKM code" (hint "OperationSpec.raw_ckm must be
copied into MechanismInvocation (§4.6)"). Bespoke C structs beyond these five require code
(§10).

#### 4.6.4 `ParamResolver` (`r2_ops::params`, R7) — ONE code path for inline + interactive

```rust
// crates/r2-ops/src/params.rs
use indexmap::IndexMap;
use r2_core::error::Result;
use r2_core::io::ConsoleIo;
use r2_provider::ProviderRegistry;

use crate::model::{OperationSpec, ParamSpec, ParamValue, Params};

pub struct ParamResolver<'a> { io: &'a dyn ConsoleIo, providers: &'a ProviderRegistry }
impl<'a> ParamResolver<'a> {
    pub fn new(io: &'a dyn ConsoleIo, providers: &'a ProviderRegistry) -> Self { .. }
    /// Algorithm below. `given` = BoundArgs.named (name=value tokens, line order).
    pub fn resolve(&self, spec: &OperationSpec, given: &IndexMap<String, String>) -> Result<Params> { .. }
    /// Parse + validate one textual value per its ParamSpec (rules below).
    pub fn parse_value(&self, param: &ParamSpec, text: &str) -> Result<ParamValue> { .. }
}
```

Resolution (c2 verbatim): first, any name in `given` that is not a param →
Param "unknown parameter '{name}' for {spec.id}" (hint "valid parameters: {names joined
', '}" or "this operation takes no parameters"). Then per ParamSpec in declared order:
given → `parse_value`; else `default_from` set → copy that param's resolved value (absent
stays absent; a mirror of a param not yet resolved → Param "parameter '{name}' mirrors
'{other}', which is not resolved yet", hint "default_from must reference an earlier
parameter (§4.6)"; a resolved-but-absent param counts as resolved); else not required →
`default` (None → absent); else prompt: `io.prompt(param)` in a loop — a ParamError from
`parse_value` is shown with `io.print_error` and the prompt repeats; any other error
(UserAbort "aborted while entering '{name}'" from the IO) propagates.

Parsing ("trimmed" = `text::py_strip`, c2's `str.strip()`): STR → text verbatim. INT →
trimmed, `-?[0-9]+` (ASCII), parsed as i64 (an out-of-range value is rejected with the
same message — c2's int was unbounded, §11 D18) → "{name}: invalid integer {text!r}" (hint
"decimal digits with an optional leading '-' only (§4.6)"). BOOL → trimmed, lower-cased
(`to_lowercase`), true/yes/on/1 | false/no/off/0 → "{name}: invalid boolean {text!r}"
(hint "accepted: true/false, yes/no, on/off, 1/0"). ENUM → trimmed, exact member of
`choices` → `ParamValue::Enum` | "{name}: invalid choice {text!r}" (hint "choices: {choices
joined ', '}"). BYTES → `decode_data(trimmed)`; an error other than UserAbort becomes Param
"{name}: {message}" with the codec hint; `length` mismatch → "{name}: expected exactly {n}
bytes, got {m}". KEYREF → `providers.resolve_ref(trimmed)` → `ParamValue::KeyRef`; an
error other than UserAbort becomes Param "{name}: {message}" with the original hint (a
UserAbort — e.g. the Ctrl-C flag checked inside a provider — propagates unchanged, §4.2).
Then `validate` (its ParamError propagates and, for prompted values, re-prompts).

#### 4.6.5 Canonical mechanism names and CKM folding

Canonical names (frozen; extended only by custom-mechanism ids): `AES-ECB`, `AES-CBC`,
`AES-CTR`, `AES-GCM`, `AES-CMAC`, `AES-GMAC`, `HMAC`, `RSA-OAEP`, `RSA-PKCS1`, `RSA-PSS`,
`RSA-RAW`, `ECDSA`, `EDDSA`, `ECDH`, `AES-KEY-WRAP`, `AES-KEY-WRAP-PAD`, `RSA-AES-KEY-WRAP`
(wrap-only; how the §5.5 single-shot hybrid is probed) — `r2_provider::mechanism`.

CKM → name folding (R5a, so `Pkcs11Provider::mechanisms()` works before R5b merges;
codes from `RawFns::mechanism_list`, never cryptoki's filtered list):

```rust
// crates/r2-pkcs11/src/capability.rs (R5a; crate-private)
use std::collections::{BTreeMap, BTreeSet};

/// Advisory vendor EdDSA probe ids (Thales/SafeNet Luna CKM_EDDSA / CKM_EDDSA_NACL), in
/// preference order.
pub(crate) const EDDSA_VENDOR_CKMS: [u64; 2] = [0x8000_0C03, 0x8000_0C02];
/// The table below + `custom` ({ckm: id}: the id is advertised when `codes` lists ckm).
pub(crate) fn fold_mechanisms(codes: &[u64], custom: &BTreeMap<u64, String>) -> BTreeSet<String> { .. }
```

| canonical | advertised when the token lists any of |
|---|---|
| AES-ECB | CKM_AES_ECB |
| AES-CBC | CKM_AES_CBC, CKM_AES_CBC_PAD (padding chosen per param at invocation; the specific CKM missing at invocation → UnsupportedOperation) |
| AES-CTR | CKM_AES_CTR |
| AES-GCM | CKM_AES_GCM |
| AES-CMAC | CKM_AES_CMAC (only; computed full-width, truncated locally to mac_len) |
| AES-GMAC | CKM_AES_GMAC, CKM_AES_GCM (GCM-over-AAD fallback construction) |
| HMAC | CKM_SHA_1_HMAC, CKM_SHA224_HMAC, CKM_SHA256_HMAC, CKM_SHA384_HMAC, CKM_SHA512_HMAC (hash per param; plain CKM invoked, truncated locally; `_GENERAL` variants never advertised) |
| RSA-OAEP | CKM_RSA_PKCS_OAEP |
| RSA-PKCS1 | CKM_RSA_PKCS, CKM_SHA1_RSA_PKCS, CKM_SHA224_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS |
| RSA-PSS | CKM_RSA_PKCS_PSS, CKM_SHA1_RSA_PKCS_PSS, CKM_SHA224_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS |
| RSA-RAW | CKM_RSA_X_509 |
| ECDSA | CKM_ECDSA, CKM_ECDSA_SHA1, CKM_ECDSA_SHA224, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512 |
| EDDSA | CKM_EDDSA, else the advisory vendor probe `EDDSA_VENDOR_CKMS` (first listed wins; absent → hidden) |
| ECDH | CKM_ECDH1_DERIVE (EC, X25519, X448 key types) |
| AES-KEY-WRAP | CKM_AES_KEY_WRAP |
| AES-KEY-WRAP-PAD | CKM_AES_KEY_WRAP_PAD, CKM_AES_KEY_WRAP_KWP (KWP preferred at invocation — unambiguously RFC 5649) |
| RSA-AES-KEY-WRAP | never (Pkcs11Provider does not advertise it, §4.5.5) |
| custom id | the configured `ckm` |

#### 4.6.6 Built-in operation table (frozen; registered by `register_builtins`)

Param notation: `name:KIND "prompt"` then `req` (required) or `opt=<default>` (`opt=None`
→ absent when not given), `{choices}`, `len=N`, `from=<param>` (default_from, opt).
Shared param lists:

- **PAD_ECB**: `padding:ENUM "Padding" opt="none" {none,pkcs7}`
- **CBC**: `iv:BYTES "IV (16 bytes)" req len=16`; `padding:ENUM "Padding" opt="pkcs7" {none,pkcs7}`
- **GCM**: `iv:BYTES "IV / nonce (12 bytes typical)" req`; `aad:BYTES "Additional authenticated data (empty for none)" opt=b""`; `tag_bits:ENUM "Tag length in bits" opt="128" {128,120,112,104,96}`
- **CTR**: `counter_block:BYTES "Initial counter block (16 bytes)" req len=16`; `counter_bits:INT "Counter width in bits" opt=128`
- **CMAC**: `mac_len:INT "MAC length in bytes" opt=16`
- **GMAC**: `iv:BYTES "IV (12 bytes)" req len=12`; `mac_len:INT "MAC length in bytes" opt=16`
- **HMAC**: `hash:ENUM "Hash" opt="sha256" {sha1,sha224,sha256,sha384,sha512}`; `mac_len:INT "MAC length in bytes (empty = full digest)" opt=None` (1..digest length; provider truncates — byte-identical to CKM_SHAx_HMAC_GENERAL)
- **OAEP**: `hash:ENUM "Hash algorithm" opt="sha256" {sha1,sha256,sha384,sha512}`; `mgf_hash:ENUM "MGF1 hash algorithm (defaults to hash)" from=hash {sha1,sha256,sha384,sha512}`; `label:BYTES "OAEP label (empty for none)" opt=b""`
- **SIGNHASH**: `hash:ENUM "Hash algorithm" opt="sha256" {sha1,sha224,sha256,sha384,sha512}`
- **PSS**: SIGNHASH; `mgf_hash:ENUM "MGF1 hash algorithm (defaults to hash)" from=hash {sha1,sha224,sha256,sha384,sha512}`; `salt_len:INT "Salt length in bytes (empty = digest length, -1 = maximum)" opt=None` (absent → digest length; -1 → provider resolves ceil(bits/8) − hLen − 2)
- **ECDH**: `peer:BYTES "Peer public key (SPKI DER or raw point 0x04||X||Y)" req`; `kdf:ENUM "KDF applied to the shared secret" opt="null" {null,sha1,sha256,sha384,sha512}`; `shared_data:BYTES "KDF shared data (empty for none)" opt=b""`; `out_len:INT "Output length in bytes (0 = curve size)" opt=0`
- **X25519**: `peer:BYTES "Peer public key (SPKI DER or raw 32-byte u-coordinate)" req`
- **X448**: `peer:BYTES "Peer public key (SPKI DER or raw 56-byte u-coordinate)" req`

Rows, in registration order (all have provider_types/providers/raw_ckm = None,
param_struct = None; curves = None unless stated). S = {SECRET}, PRIV = {PRIVATE},
PUB = {PUBLIC, CERTIFICATE}, PRIV∪PUBK = {PRIVATE, PUBLIC}.

| # | id | verb | algorithm | key_classes | mechanism | cli | label | params |
|---|---|---|---|---|---|---|---|---|
| 1 | aes.encrypt.ecb | encrypt | aes | S | AES-ECB | ecb | AES-ECB encryption | PAD_ECB |
| 2 | aes.decrypt.ecb | decrypt | aes | S | AES-ECB | ecb | AES-ECB decryption | PAD_ECB |
| 3 | aes.encrypt.cbc | encrypt | aes | S | AES-CBC | cbc | AES-CBC encryption | CBC |
| 4 | aes.decrypt.cbc | decrypt | aes | S | AES-CBC | cbc | AES-CBC decryption | CBC |
| 5 | aes.encrypt.gcm | encrypt | aes | S | AES-GCM | gcm | AES-GCM authenticated encryption | GCM |
| 6 | aes.decrypt.gcm | decrypt | aes | S | AES-GCM | gcm | AES-GCM authenticated decryption | GCM |
| 7 | aes.encrypt.ctr | encrypt | aes | S | AES-CTR | ctr | AES-CTR encryption | CTR |
| 8 | aes.decrypt.ctr | decrypt | aes | S | AES-CTR | ctr | AES-CTR decryption | CTR |
| 9 | aes.sign.cmac | sign | aes | S | AES-CMAC | cmac | AES-CMAC MAC | CMAC |
| 10 | aes.verify.cmac | verify | aes | S | AES-CMAC | cmac | AES-CMAC MAC verification | CMAC |
| 11 | aes.sign.gmac | sign | aes | S | AES-GMAC | gmac | AES-GMAC MAC | GMAC |
| 12 | aes.verify.gmac | verify | aes | S | AES-GMAC | gmac | AES-GMAC MAC verification | GMAC |
| 13 | rsa.encrypt.oaep | encrypt | rsa | PUB | RSA-OAEP | oaep | RSA-OAEP encryption | OAEP |
| 14 | rsa.decrypt.oaep | decrypt | rsa | PRIV | RSA-OAEP | oaep | RSA-OAEP decryption | OAEP |
| 15 | rsa.encrypt.pkcs1 | encrypt | rsa | PUB | RSA-PKCS1 | pkcs1 | RSA PKCS#1 v1.5 encryption | — |
| 16 | rsa.decrypt.pkcs1 | decrypt | rsa | PRIV | RSA-PKCS1 | pkcs1 | RSA PKCS#1 v1.5 decryption | — |
| 17 | rsa.encrypt.raw | encrypt | rsa | PUB | RSA-RAW | raw | Raw RSA (textbook) encryption — input left-padded to modulus length | — |
| 18 | rsa.decrypt.raw | decrypt | rsa | PRIV∪PUBK | RSA-RAW | raw | Raw RSA (textbook) decryption — input left-padded to modulus length | — |
| 19 | rsa.sign.pkcs1 | sign | rsa | PRIV | RSA-PKCS1 | pkcs1 | RSA PKCS#1 v1.5 signature | SIGNHASH |
| 20 | rsa.verify.pkcs1 | verify | rsa | PUB | RSA-PKCS1 | pkcs1 | RSA PKCS#1 v1.5 signature verification | SIGNHASH |
| 21 | rsa.sign.pss | sign | rsa | PRIV | RSA-PSS | pss | RSA-PSS signature | PSS |
| 22 | rsa.verify.pss | verify | rsa | PUB | RSA-PSS | pss | RSA-PSS signature verification | PSS |
| 23 | rsa.sign.raw | sign | rsa | PRIV | RSA-RAW | raw | Raw RSA signature — caller supplies the padded block | — |
| 24 | rsa.verify.raw | verify | rsa | PUB | RSA-RAW | raw | Raw RSA signature verification — caller supplies the padded block | — |
| 25 | ec.sign.ecdsa | sign | ec | PRIV | ECDSA | ecdsa | ECDSA signature (canonical fixed-width r\|\|s) | SIGNHASH |
| 26 | ec.verify.ecdsa | verify | ec | PUB | ECDSA | ecdsa | ECDSA signature verification | SIGNHASH |
| 27 | ec.sign.eddsa | sign | ec-edwards | PRIV | EDDSA | eddsa | EdDSA signature (Ed25519/Ed448, raw) | — |
| 28 | ec.verify.eddsa | verify | ec-edwards | PUB | EDDSA | eddsa | EdDSA signature verification | — |
| 29 | ec.derive.ecdh | derive | ec | PRIV | ECDH | ecdh | ECDH key agreement | ECDH |
| 30 | ec.derive.x25519 | derive | ec-montgomery | PRIV | ECDH | x25519 | X25519 key agreement | X25519; curves={x25519} |
| 31 | ec.derive.x448 | derive | ec-montgomery | PRIV | ECDH | x448 | X448 key agreement | X448; curves={x448} |
| 32 | generic.sign.hmac | sign | generic | S | HMAC | hmac | HMAC (SHA-1/224/256/384/512) over a generic secret | HMAC |
| 33 | generic.verify.hmac | verify | generic | S | HMAC | hmac | HMAC verification | HMAC |

(The label of row 25 is literally `ECDSA signature (canonical fixed-width r||s)`; the
`\|` above is markdown escaping.) Notes: HMAC binds to GENERIC keys only — both providers
refuse HMAC on AES keys and CMAC/GMAC on generic secrets BEFORE any token call.
`rsa.decrypt.raw` accepts PUBLIC (public-exponent modexp = signature recovery, §5.8);
CERTIFICATE stays excluded there (§4.3). `resolve_cli`/`available_for` filter on
`curves`.

### 4.7 Attribute template model (`r2_core::template`, R1)

```rust
use std::fmt;
use std::str::FromStr;
use crate::error::{ConsoleError, Result};

/// Token: "bool" | "str" | "bytes" | "ulong".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttrKind { Bool, Str, Bytes, Ulong }
impl AttrKind { pub fn as_str(self) -> &'static str { .. } }
impl fmt::Display for AttrKind { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { .. } }
/// Exact tokens; else Generic "unknown attribute kind {s!r}".
impl FromStr for AttrKind { type Err = ConsoleError; fn from_str(s: &str) -> Result<Self> { .. } }

/// A template / attribute value (c2 `object`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AttrValue {
    Bool(bool),
    Str(String),
    Bytes(Vec<u8>),
    Ulong(u64),
    /// A symbolic ULONG constant name: "CKO_…", "CKK_…", "CKC_…" or "CKM_…" (resolved by
    /// the PKCS#11 provider at conversion; c2 kept such strings verbatim).
    Symbol(String),
}
impl AttrValue {
    /// The kind a config/YAML value infers (§4.7 rule): Bool→Bool, Ulong/Symbol→Ulong,
    /// Bytes→Bytes, Str→Str.
    pub fn inferred_kind(&self) -> AttrKind { .. }
    /// Editor / outcome-table cell (c2 `_display`/`_value_text`): Bool "true"/"false",
    /// Bytes "0x" + lower-case hex, Ulong decimal, Str/Symbol verbatim.
    pub fn render_value(&self) -> String { .. }
    /// `key info` attribute cell (c2 `_attr_text` = Python str()): Bool "True"/"False",
    /// Bytes "0x" + hex, Ulong decimal, Str/Symbol verbatim.
    pub fn render_info(&self) -> String { .. }
    /// Python `type(value).__name__` of the c2 value: Bool "bool", Ulong "int", Bytes
    /// "bytes", Str/Symbol "str" (the "got {T}" part of c2's mismatch texts).
    pub fn py_type_name(&self) -> &'static str { .. }
    /// Python `repr()` of the c2 value: Bool "True"/"False", Ulong decimal, Bytes
    /// `text::py_bytes_repr`, Str/Symbol `text::py_repr`.
    pub fn py_repr(&self) -> String { .. }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateAttr {
    /// "CKA_TOKEN".
    pub name: String,
    pub kind: AttrKind,
    pub value: AttrValue,
    /// false → the attribute is OMITTED from the PKCS#11 call entirely.
    pub enabled: bool,
    /// true → the operator cannot toggle/edit/disable it (CKA_CLASS / CKA_KEY_TYPE).
    pub locked: bool,
}
impl TemplateAttr {
    /// enabled = true, locked = false.
    pub fn new(name: impl Into<String>, kind: AttrKind, value: AttrValue) -> Self { .. }
    pub fn disabled(self) -> Self { .. }
    pub fn locked(self) -> Self { .. }
}

/// Ordered, as rendered by the editor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyTemplate { pub attrs: Vec<TemplateAttr> }
impl KeyTemplate {
    pub fn new(attrs: Vec<TemplateAttr>) -> Self { .. }
    pub fn get(&self, name: &str) -> Option<&TemplateAttr> { .. }
    pub fn get_mut(&mut self, name: &str) -> Option<&mut TemplateAttr> { .. }
    /// Set the value of an existing attribute (kind unchanged). Unknown name → Param
    /// "unknown template attribute {name!r}" (param_name = name, hint "known attributes:
    /// {names joined ', '}" or "known attributes: (no attributes)"). The editor's `add`
    /// flow appends a TemplateAttr built from CKA_CATALOG / templates.custom_attributes.
    pub fn set(&mut self, name: &str, value: AttrValue) -> Result<()> { .. }
    pub fn enabled_attrs(&self) -> Vec<&TemplateAttr> { .. }
}
```

Conversion and identity rules (binding, c2 §4.7 verbatim in substance; implemented by
r2-pkcs11's `crate::attributes`, R5a, and mirrored by MemoryProvider/FakeProvider where they
apply):

- Conversion emits **enabled attrs only**. Names resolve through `CKA_CATALOG`, then
  `templates.custom_attributes` (kind taken from the definition, regardless of the row's
  kind); unknown names → Param "unknown PKCS#11 attribute {name!r}" (hint "known names come
  from CKA_CATALOG or templates.custom_attributes"). Values are normalized per kind (c2
  `_normalize`, texts verbatim, param_name = name; `{T}` = `AttrValue::py_type_name`):
  - BOOL needs Bool, else "template attribute {name} expects a boolean, got {T}";
  - ULONG (catalog attrs) accepts Ulong, a Symbol, OR a Str starting with CKO_/CKK_/CKC_/
    CKM_ (config inference keeps `CKA_KEY_GEN_MECHANISM: CKM_AES_KEY_GEN` a STR row, as
    c2 does, and c2 still converts it); a Bool → "template attribute {name} expects an
    integer, got a boolean"; anything else → "template attribute {name} expects an integer
    or a CKO_/CKK_/CKC_/CKM_ constant name, got {value!r}" (`AttrValue::py_repr`). Symbols
    resolve via `r2_pkcs11::catalog::symbol_value`; an unknown one → Param. Test vector:
    `templates.pkcs11.aes.CKA_KEY_GEN_MECHANISM: CKM_AES_KEY_GEN` creates a key with
    CKA_KEY_GEN_MECHANISM = 0x1080;
  - BYTES needs Bytes, else "template attribute {name} expects bytes, got {T}" (hint "use a
    0x… hex value");
  - STR needs Str (or a Symbol, which is a string in c2), else "template attribute {name}
    expects a string, got {T}". At encoding (c2 `_entry_value`), a non-vendor STR value
    starting with CKO_/CKK_/CKC_/CKM_ is resolved like a ULONG symbol, whatever the
    attribute: an unknown name → the same Param "unknown PKCS#11 constant {v!r}" (also for
    the CKA_LABEL row the injected label later overwrites); a known one is stored as its
    decimal text (PyKCS11 `SetString(str(int))`), e.g. CKA_APPLICATION `CKM_SHA256` →
    `592`.
  Vendor (`custom_attributes`) values are byte-encoded explicitly after that check: BOOL →
  1 byte, ULONG → native-endian CK_ULONG — Ulong ONLY: a symbol or string fails with c2's
  "vendor ULONG attribute expects an integer, got {value!r}" (vendor ULONGs never resolve
  symbols), STR → UTF-8, BYTES → verbatim, a non-Bytes value → "vendor BYTES attribute
  expects bytes, got {T}" (both with c2's param_name = `str(value)`, i.e. the value's
  `render_info()`); decode is the inverse (any nonzero byte = true; STR decoded lossily).
- The locked CKA_CLASS/CKA_KEY_TYPE rows enter via `TemplatesSection::default_template`
  (§4.8) so the editor shows them; the provider validates them against the actual object
  and injects CKA_LABEL, CKA_ID (key classes and certificates — never data objects) and
  material attrs (CKA_VALUE, CKA_MODULUS, …). Config templates hold only policy/usage
  attributes (§7).
- `import_key`/`unwrap_key` inject `CKA_SENSITIVE=false, CKA_EXTRACTABLE=true` when the
  template does not state them (an operator row always wins). Data objects get no
  SENSITIVE/EXTRACTABLE/KEY_TYPE/ID injection.
- Identity resolution: an **enabled template identity row** (added in the editor) is
  honored, never silently replaced. CKA_ID precedence: explicit key_id (`--id`) > template
  row > random 4 bytes; a `--id`/template conflict → Param "template CKA_ID 0x{t} conflicts
  with --id 0x{k}" (param_name "CKA_ID", hint "drop one of the two — they must agree"). A
  template CKA_LABEL row wins over the label argument. Keypair private/public templates
  must agree on both (Param "templates disagree on CKA_LABEL ({a!r} vs {b!r}) — keypair
  objects share one label" / "templates disagree on CKA_ID (0x{a} vs 0x{b}) — keypair
  objects share one id"). Empty identity rows → Param "template CKA_LABEL expects a
  non-empty string" / "template CKA_ID expects non-empty bytes" (hint "use a 0x… hex
  value"). Data objects: a key id is refused with the message "data objects carry no
  CKA_ID (§4.3)" and per-provider param_name/hint (c2 verbatim): Pkcs11Provider
  create flows (key_id or an enabled CKA_ID row) → param_name "CKA_ID", hint "drop --id /
  the template CKA_ID row; data objects are identified by label alone"; MemoryProvider and
  FakeProvider create flows (key_id) → param_name "key_id", hint "drop --id; data objects
  are identified by label alone"; `update_key` with a CKA_ID row on a data object (all
  three providers) → param_name "CKA_ID", hint "data objects are identified by label
  alone".
- Duplicate guard: creating an exact (class, label, id) twin of an existing
  non-certificate object → DuplicateKey (`lookup::duplicate_identity`); certificates are
  exempt (PKCS#12 chains share one identity); duplicate labels under distinct ids stay
  allowed; data objects compare (class, label) only. Derive results are excluded
  (session objects with a provider-random id).
- Config kind inference (used by `default_template`, §4.8; c2 `_build_template_attr`),
  over the value as PyYAML types it (§4.8.4 — so plain `yes`/`017`/`0b1` are bool/int,
  quoted ones strings): bool → BOOL, int → ULONG (negative → load error, §11 D18), a
  string starting with `0x` → BYTES (`text::py_fromhex` of the rest; failure → "invalid hex
  bytes {raw!r}"), any other string → STR (including `CKO_…`/`CKK_…`/`CKC_…`/`CKM_…` names,
  which the editor shows as kind "str" and conversion still accepts for ULONG attrs);
  anything else → "template attribute values must be bool, int or string, got {T}".
  `custom_attributes` entries carry their kind explicitly. Template **files** (§5.16)
  never infer: kinds come from a NAME lookup (`CKA_CATALOG`, then custom attributes).

### 4.8 Configuration (`r2_config`, R2)

#### 4.8.1 Discovery, loading, merge (`r2_config::loader`, `r2_config::dirs`)

Exactly one external file, first match wins; a missing or unreadable explicit choice is a
hard error (never a silent fallthrough):

1. `--config <path>` CLI argument (`~` expanded, `dirs::expand_user`); an EMPTY value
   counts as absent (c2 `Path(args.config) if args.config else None`) — r2-cli maps
   `Some("")` from clap to `None` before calling `load_config`
2. `$R2_CONFIG` (`~` expanded; set-but-EMPTY counts as unset, c2 `if env_value:`)
3. `std::env::current_dir()?.join("r2.yaml")` (c2 `Path.cwd() / "c2.yaml"`): an ABSOLUTE
   path, which is what messages, `LoadedConfig.source_path`, origins and `config path`
   show; a `current_dir` failure (deleted working directory) skips this step (c2 crashed,
   §11 D12)
4. `<user config dir>/r2.yaml`, where the user config dir follows platformdirs
   `user_config_dir("r2")` (appauthor defaulting to appname; platformdirs 4.10.1, whose
   `XDGMixin` serves both Unix and MacOS): Linux/BSD and macOS `$XDG_CONFIG_HOME/r2`
   when the variable is set and non-blank, using the value STRIPPED of Python whitespace
   (`str.strip()`; on POSIX an undecodable byte is not whitespace), else Linux/BSD
   `~/.config/r2`, macOS `~/Library/Application Support/r2`; Windows
   `%LOCALAPPDATA%\r2\r2` (Local, not Roaming). So the file is e.g.
   `~/.config/r2/r2.yaml`.

Merge (deliberately boring): mappings merge recursively, scalars from the external file
replace defaults, **lists replace wholesale** (an external `providers.pkcs11` fully
defines the instance list). `load_config` is called only by `r2-cli` (review rule); the
model types are importable anywhere.

```rust
// crates/r2-config/src/loader.rs
use std::path::{Path, PathBuf};
use r2_core::error::Result;
use crate::model::{AppConfig, LoadedConfig};
use crate::yaml::Value;

pub const ENV_VAR: &str = "R2_CONFIG";
pub const FILE_NAME: &str = "r2.yaml";
pub const APP_DIR: &str = "r2";
/// The embedded defaults (spec §7 with `c2`→`r2` path renames). `config show --defaults`
/// prints this text verbatim; it never goes through the loader.
pub const DEFAULTS_YAML: &str = include_str!("defaults.yaml");

/// path = --config value or None (env/cwd/user-dir discovery).
pub fn load_config(path: Option<&Path>) -> Result<LoadedConfig> { .. }
/// Test/support helper (no discovery, no file): DEFAULTS_YAML deep-merged with `external`
/// (YAML text, same rules as a config file), decoded. Errors carry no "(config file: …)".
pub fn config_from_yaml(external: Option<&str>) -> Result<AppConfig> { .. }
/// Mappings merge recursively (keys of `overlay` appended in their order when new);
/// scalars and sequences from `overlay` replace.
pub fn deep_merge(base: &Value, overlay: &Value) -> Value { .. }
/// The first existing discovery candidate, applying the hard-error rules (exposed for
/// `config path` tests): `--config` / non-empty `$R2_CONFIG` are `expand_user`-ed, and a
/// path that is not an existing regular FILE (c2 `Path.is_file()`) → "config file not
/// found: {path}" (the expanded path).
pub fn discover(cli_path: Option<&Path>) -> Result<Option<PathBuf>> { .. }

// crates/r2-config/src/dirs.rs
use std::path::PathBuf;

/// platformdirs-compatible `user_config_dir("r2")` (rules above); no extra dependency:
/// home as in `expand_user` (`$XDG_CONFIG_HOME` read as an OsString, so a non-UTF-8 value
/// is used, not ignored), Windows base = `%LOCALAPPDATA%` (platformdirs' env fallback).
/// None when that lookup fails.
pub fn user_config_dir() -> Option<PathBuf> { .. }
/// Python `Path(p).expanduser()`: `text::py_path(p)` first (c2 always built the `Path`
/// before expanding), then a leading `~` or `~/…` (`~\…` on Windows) → home dir; anything
/// else is the normalized path. POSIX (`posixpath.expanduser`): the home of `~` is `$HOME`
/// used as is whenever it is set (even empty: `userhome.rstrip('/') or '/'`, so `~/x` →
/// `/x`), else `std::env::home_dir()` (getpwuid); `~name/…` is that user's home read from
/// `/etc/passwd`; an unresolvable `~…` stays literal (§11 D12 (g)). Windows: `~`/`~\…`
/// only, home = `std::env::home_dir()`. `discover` applies the same expansion to a
/// non-UTF-8 `--config`/`$R2_CONFIG` byte for byte (crate-private `expand_user_path`).
pub fn expand_user(path: &str) -> PathBuf { .. }
```

Loader messages (Config kind): `--config` missing → "config file not found: {path}"
(hint "--config must point to an existing file"); `$R2_CONFIG` missing → same message,
hint "$R2_CONFIG must point to an existing file"; "cannot read config file {path}:
{os_error_text}"; "invalid YAML in config file {path}: {parser text}" (`yaml::parse`'s
message; the parser text differs from PyYAML's — §11 D17); "config file {path} must
contain a top-level mapping"; "config
file {path}: top-level keys must be strings, got {key!r}"; a file that is not valid UTF-8 →
"cannot read config file {path}: {CPython UnicodeDecodeError text}" (e.g. "'utf-8' codec
can't decode byte 0xff in position 19: invalid start byte"; c2 crashed, §11 D12 (f)); the
text is read with Python's universal newlines (`\r\n`/`\r` → `\n`). An empty file means "no
overrides". `config_from_yaml` uses the same texts with "config text" in place of "config
file {path}" ("invalid YAML in config text: …", "config text must contain a top-level
mapping", "config text: top-level keys must be strings, got …"). When an external file is
in play, every decode error is re-raised as "{message} (config file: {path})" with the hint
kept. `LoadedConfig.origins` maps each
top-level section of the defaults, in defaults order, to `str(source_path)` when the
external file defines it, else "default".

#### 4.8.2 Model (`r2_config::model`)

All types are plain values (`Clone, Debug, PartialEq`; `Eq` where possible). Each struct
has `pub fn from_value(value: &yaml::Value, path: &str) -> Result<Self>` — the c2
`from_dict(data, path)` decoder, where `path` is the dotted key prefix of every message
("providers.pkcs11[0].library: …"; "" at the root). `AppConfig::to_value` feeds
`config show`. Every `PathBuf` field — `app.history_file`, `app.log.file`,
`providers.pkcs11[].library`, `softhsm.search_paths[i]`, `softhsm.conf_dir`,
`softhsm.token_dir` — is decoded as a string through `dirs::expand_user` (c2 `_as_path` =
`Path(..).expanduser()`), so the §7 defaults (`~/.local/state/r2/…`) never create literal
`./~/…` paths and every message showing a path (e.g. "details logged to {app.log.file}")
shows the expanded one.

```rust
use std::path::PathBuf;
use indexmap::IndexMap;
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{KeyAlgorithm, KeyClass};
use r2_core::params::{ParamKind, ParamStruct, ParamValue, Verb};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate};
use crate::yaml::Value;

/// The six top-level sections in defaults.yaml order (`config show --origin`).
pub const CONFIG_SECTIONS: [&str; 6] = ["app", "ui", "providers", "softhsm", "templates", "custom_mechanisms"];
/// Class keys of templates.pkcs11 (§7) and of template files (§5.16).
pub const TEMPLATE_CLASS_KEYS: [&str; 8] =
    ["aes", "rsa_private", "rsa_public", "ec_private", "ec_public", "certificate", "generic_secret", "data"];

/// Token: "debug" | "info" | "warning" | "error".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel { Debug, Info, Warning, Error }
/// Token: "auto" | "always" | "never".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorMode { Auto, Always, Never }

impl LogLevel { pub fn as_str(self) -> &'static str { .. } }
impl std::fmt::Display for LogLevel { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { .. } }
/// Exact tokens; else Config "invalid value {s!r}" (hint "valid values: debug, info,
/// warning, error"); the decoder prefixes "{path}: ".
impl std::str::FromStr for LogLevel { type Err = ConsoleError; fn from_str(s: &str) -> Result<Self> { .. } }
impl ColorMode { pub fn as_str(self) -> &'static str { .. } }
impl std::fmt::Display for ColorMode { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { .. } }
/// Exact tokens; else Config "invalid value {s!r}" (hint "valid values: auto, always,
/// never"); the decoder prefixes "{path}: ".
impl std::str::FromStr for ColorMode { type Err = ConsoleError; fn from_str(s: &str) -> Result<Self> { .. } }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogSection { pub level: LogLevel, pub file: PathBuf, pub max_bytes: u64, pub backups: u32 }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppSection { pub history_file: PathBuf, pub log: LogSection }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UiSection {
    pub color: ColorMode,
    /// Bytes per group in hex output; 0 = continuous.
    pub hex_group: usize,
    /// Bytes per line (≥ 1).
    pub hex_width: usize,
    pub confirm_delete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemorySection { pub enabled: bool, pub name: String }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pkcs11InstanceConfig {
    pub name: String,
    /// `~` expanded. Existence is NOT checked at load (§6: a broken library surfaces as
    /// ProviderUnavailable on first use).
    pub library: PathBuf,
    /// A negative YAML value is a load error in r2 (c2 accepted it) — §11 D18.
    pub slot: Option<u64>,
    pub token_label: Option<String>,
    /// Set in the process environment immediately before C_Initialize (§4.5.5).
    pub env: IndexMap<String, String>,
}
impl Pkcs11InstanceConfig {
    /// slot/token_label None, env empty (the SoftHSM autodetect instance).
    pub fn new(name: impl Into<String>, library: impl Into<PathBuf>) -> Self { .. }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvidersSection { pub memory: MemorySection, pub pkcs11: Vec<Pkcs11InstanceConfig> }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoftHsmSection {
    pub autodetect: bool,
    pub provider_name: String,
    /// Passed to `find_softhsm_module` (§4.5.5).
    pub search_paths: Vec<PathBuf>,
    pub conf_dir: PathBuf,
    pub token_dir: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustomAttributeDef {
    /// Vendor CKA_* code.
    pub code: u64,
    pub kind: AttrKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplatesSection {
    /// class key → attribute name → value, values already converted by the §4.7 kind
    /// inference rule (YAML order preserved). Unknown class keys are kept (and warned).
    pub pkcs11: IndexMap<String, IndexMap<String, AttrValue>>,
    /// The SOURCE YAML scalar of every `pkcs11` entry, same keys in the same order (c2
    /// kept `dict(attrs)` unconverted). Used only by `AppConfig::to_value`, so
    /// `config show` prints e.g. `CKA_ID: 0x0A 0B` verbatim, as c2 does.
    pub pkcs11_raw: IndexMap<String, IndexMap<String, Value>>,
    pub custom_attributes: IndexMap<String, CustomAttributeDef>,
}
impl TemplatesSection {
    /// The editable KeyTemplate for load/copy/generate (never reimplemented per command):
    /// locked enabled rows CKA_CLASS = Symbol(key_class.cko_symbol()) and — for
    /// Secret/Private/Public only — CKA_KEY_TYPE = Symbol(algorithm.ckk_symbol()),
    /// followed by the class key's config attrs (kind = value.inferred_kind()), all
    /// enabled, in config order; fresh (unshared) rows. Errors as template_class_key.
    pub fn default_template(&self, key_class: KeyClass, algorithm: KeyAlgorithm) -> Result<KeyTemplate> { .. }
}

/// (class, algorithm) → class key; class is checked first: Certificate → "certificate",
/// Data → "data"; algorithm None/Other → UnsupportedOperation "{algorithm} {class} objects
/// have no template class key" (hint "objects of unsupported key types can be listed and
/// deleted only"); Aes → "aes"; Generic → "generic_secret"; Rsa → "rsa_private" /
/// "rsa_public"; Ec/EcEdwards/EcMontgomery → "ec_private" / "ec_public" (Private →
/// "_private", any other class → "_public").
pub fn template_class_key(key_class: KeyClass, algorithm: KeyAlgorithm) -> Result<&'static str> { .. }

/// YAML param entry of a custom mechanism; converted 1:1 into a ParamSpec by r2-ops.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamSpecConfig {
    pub name: String,
    pub kind: ParamKind,
    pub prompt: String,
    pub required: bool,
    /// Typed at load by `kind` (§4.8.3).
    pub default: Option<ParamValue>,
    /// The source YAML value of `default` (c2 stored `data.get("default")` raw); None when
    /// the key is absent or null. Used only by `AppConfig::to_value` (`config show`).
    pub default_raw: Option<Value>,
    pub choices: Option<Vec<String>>,
}

/// Config-defined vendor mechanism (frozen-provisional, §4.11: param encoding v1 = the five
/// ParamStruct packers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomMechanismConfig {
    /// e.g. "vendor.acme.kcv".
    pub id: String,
    pub verb: Verb,
    /// Never None/Other (rejected at load).
    pub algorithm: KeyAlgorithm,
    pub cli_name: String,
    pub label: String,
    /// Raw CKM code (warning when < 0x80000000).
    pub ckm: u64,
    pub param_struct: ParamStruct,
    pub params: Vec<ParamSpecConfig>,
    /// None → {"pkcs11"} (applied by r2-ops).
    pub provider_types: Option<Vec<String>>,
    pub providers: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppConfig {
    pub app: AppSection,
    pub ui: UiSection,
    pub providers: ProvidersSection,
    pub softhsm: SoftHsmSection,
    pub templates: TemplatesSection,
    pub custom_mechanisms: Vec<CustomMechanismConfig>,
}
impl AppConfig {
    /// Typed decode of the merged tree + cross-checks (§4.8.3).
    pub fn from_value(value: &Value, path: &str) -> Result<Self> { .. }
    /// Plain tree for `config show` (c2 `_to_plain`): field order = struct order, paths as
    /// strings, enums as tokens, Option None as null. The raw mirrors are emitted IN PLACE
    /// of their typed fields and never as keys of their own: `templates.pkcs11` comes from
    /// `TemplatesSection::pkcs11_raw` and `params[].default` from
    /// `ParamSpecConfig::default_raw` (null when None), verbatim — never re-rendered from
    /// AttrValue/ParamValue (c2 printed the raw YAML objects; "0x…" lower-hex rendering
    /// would break byte identity for `'0x0A0B'`, `'0x0a 0b'`, `hex:0A0B`, `AQID`).
    pub fn to_value(&self) -> Value { .. }
}

/// Loader result: typed config + provenance (feeds `config path` / `config show --origin`
/// without re-running discovery).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedConfig {
    pub config: AppConfig,
    /// The external file actually loaded, if any.
    pub source_path: Option<PathBuf>,
    /// Top-level section → "default" | source path text, in CONFIG_SECTIONS order.
    pub origins: IndexMap<String, String>,
}
```

Every section type above also has `pub fn from_value(value: &Value, path: &str) ->
Result<Self>` (LogSection, AppSection, UiSection, MemorySection, Pkcs11InstanceConfig,
ProvidersSection, SoftHsmSection, CustomAttributeDef, TemplatesSection, ParamSpecConfig,
CustomMechanismConfig).

#### 4.8.3 Validation (decoder rules and messages, c2 verbatim)

Every error is Config "{path}: {problem}" (path = dotted key path, list items `[i]`).
Unknown keys never fail: they are logged with `tracing::warn!(target: "r2::config", …)`
as "unknown config key {path!r}" + " (did you mean {match!r}?)" when
`text::close_matches(key, known, 1)` finds one (for templates.pkcs11 class keys the noun
is "template class key"); never printed to stdout. Problems:

| check | problem text (hint) |
|---|---|
| type checks | "expected a mapping, got {T}", "expected a list, got {T}", "expected a string, got {T}", "expected a boolean, got {T}", "expected an integer, got {T}" — T = Python type name via `yaml::python_type_name` ("dict", "list", "str", "int", "float", "bool", "NoneType") |
| mapping keys | "mapping keys must be strings, got {key!r}" |
| required | "{path}.{key}: required key missing" |
| enums (level, color, kind, verb, algorithm, param_struct) | "invalid value {text!r}" (hint "valid values: {tokens joined ', '}"); `algorithm` offers only creatable algorithms (aes, rsa, ec, ec-edwards, ec-montgomery, generic) |
| identifiers (memory.name, pkcs11[].name, softhsm.provider_name) | "invalid provider name {name!r}" (hint "provider names match [A-Za-z_][A-Za-z0-9_-]*") |
| app.log.max_bytes, app.log.backups, custom_attributes.*.code, custom_mechanisms[].ckm, pkcs11[].slot | "must not be negative" (for `pkcs11[].slot` an r2 addition — c2 accepted a negative slot, §11 D18) |
| ui.hex_group / ui.hex_width | "must not be negative (0 = continuous)" / "must be at least 1" |
| integers above the field's Rust type (app.log.backups > u32, ui.hex_group/hex_width > usize, an INT/ENUM `params[].default` > i64) | "must be at most {max}" (r2 only: c2's int is unbounded — §11 D18; every other integer field is u64 and YAML ints stop at 2^64-1, §4.8.4) |
| empty strings (params[].name, custom_mechanisms[].id, cli_name) | "must not be empty" |
| ENUM param without choices | "{path}.choices: required for kind 'enum'" |
| template values | "invalid hex bytes {raw!r}" (hint "0x… values hold whole hex bytes"); "template attribute values must be bool, int or string, got {T}" (hint 'bool → BOOL, int → ULONG, "0x…" → BYTES, other string → STR (§4.7)'); negative int → "must not be negative" (r2: ULONG is unsigned; c2 failed later, at the first create flow, with "template attribute {name} must not be negative" — §11 D18) |
| ParamSpecConfig.default (r2: typed at load by kind; c2 passed the raw YAML object and failed at invocation — §11 D18) | INT ← int; STR ← string; BOOL ← bool; ENUM ← string → `Enum`, or a YAML int → `ParamValue::Int` kept as is (c2 passed the raw int, which its gcm packer's `_int_param` accepts; the one exception to §4.6.1's "every ENUM value is Enum"); ENUM defaults are NOT checked against `choices` (c2 parity); an absent key or an explicit `default: null` → `None` for every kind, including KEYREF (no error); BYTES ← string via `decode_data` (a CodecError becomes "{codec message}"); KEYREF → "keyref parameters cannot have a default"; mismatch → "expected a {kind} default, got {T}" |
| cross-check | "providers.pkcs11[{i}].name: duplicate provider name {name!r}" (hint "provider names must be unique across memory and pkcs11 instances") — memory.name counts even when memory is disabled; "custom_mechanisms[{i}].providers: unknown provider {name!r}" (hint "defined providers: {sorted names incl. softhsm.provider_name, joined ', '}") |

**Raw mirrors (`config show` parity).** c2 kept two places of the config unconverted:
`TemplatesSection.pkcs11` values (`dict(attrs)`; `default_template` re-ran the §4.7
conversion on every call) and `ParamSpecConfig.default` (`data.get("default")`), so its
`config show` printed them as written. r2 validates and converts both at load (rows above)
and ALSO stores the source YAML value: `TemplatesSection::pkcs11_raw` (same class keys and
attribute names, same order as `pkcs11`, filled only after the entry validated) and
`ParamSpecConfig::default_raw` (None for an absent key or `default: null`, else the YAML
value exactly as parsed — string, int or bool). Every constructor of these structs fills
both; `AppConfig::to_value` emits the raw mirror under the typed field's key and position
(`pkcs11`, `default`) and never emits a `pkcs11_raw`/`default_raw` key. Typed consumers
(`default_template`, r2-ops' ParamSpec conversion) read only the typed fields. R2 tests:
`templates.pkcs11.aes.CKA_ID: '0x0A 0B'` dumps through `config show` as `CKA_ID: 0x0A 0B`
and `'0x0A0B'` as `CKA_ID: 0x0A0B`; a BYTES param `default: hex:0A0B` and `default: AQID`
dump verbatim; an ENUM `default: 128` dumps as `128` (all byte-compared with c2's output).

`custom_mechanisms[].ckm < 0x80000000` → warn (target "r2::config") "{path}.ckm: CKM code
0x{ckm:08x} is below the vendor-defined range (>= 0x80000000)". The loader does NOT check
that `providers.pkcs11[].library` exists (§6).

#### 4.8.4 YAML loading and dumping — PyYAML parity (normative)

c2 reads every YAML file (config, template files, the wizard's config rewrite) with PyYAML
6.0.3 `safe_load` (YAML 1.1) and writes with `safe_dump(sort_keys=False,
default_flow_style=False)`. r2 reproduces both, so a c2 config or template file loads with
the same types in r2 and every r2-written file is byte-identical to c2's:

- **Loader** (`yaml::parse`): driven by the `yaml-rust2` EVENT parser (which reports each
  scalar's style; serde_yaml_ng's own deserializer cannot, and resolves YAML 1.2 core
  types), building a `serde_yaml_ng::Value` tree itself with PyYAML SafeLoader semantics:
  - PyYAML's YAML 1.1 implicit resolvers apply to PLAIN scalars only; quoted and block
    scalars are always strings (so `'yes'` is a string, plain `yes` a bool):
    bool `yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF`;
    int `[-+]?0b[0-1_]+ | [-+]?0[0-7_]+ | [-+]?(0|[1-9][0-9_]*) | [-+]?0x[0-9a-fA-F_]+ |
    [-+]?[1-9][0-9_]*(:[0-5]?[0-9])+` (binary, octal `017` = 15, decimal, hex, sexagesimal
    `1:30` = 90; underscores ignored); float PyYAML's regex (a `.` is required — `1e3`
    stays the string "1e3", `1.0e+3` is 1000.0; `.inf`/`.nan` forms); null `~`,
    `null|Null|NULL`, empty; timestamp PyYAML's regex → `Value::Tagged` with tag
    `!!timestamp` over the text (Python type `date`, or `datetime` with a time part);
    `<<` → merge key; a plain `=` → PyYAML's error "could not determine a constructor for
    the tag 'tag:yaml.org,2002:value'". Anything else (`08`, `0o17`, `1_000x`) is a string.
  - Explicit tags `!!str`, `!!int`, `!!float`, `!!bool`, `!!null` construct that type
    from the text; `!!binary` → `Value::Tagged` `!!binary` (Python type `bytes`); any other
    tag → "could not determine a constructor for the tag '{tag}'".
  - Integers become `Number` (i64 / u64); one outside -2^63..=2^64-1 → parse error
    "integer out of range: {text}" (c2's int is unbounded — §11 D17).
  - Mappings: a repeated key keeps its FIRST position and its LAST value (Python dict);
    `<<` merge keys follow PyYAML `flatten_mapping` (a mapping or a sequence of mappings;
    the node's own keys win; among merge sources the earlier wins; merged keys come first in
    order); a sequence/mapping used as a key → "found unhashable key".
  - First, PyYAML's `Reader.check_printable`: the first character outside
    `[\t\n\r\x20-\x7E\x85\xA0-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]` (C0 controls
    but TAB/LF/CR, DEL, C1 controls but NEL, U+FFFE/U+FFFF) → "unacceptable character
    #x{cp:04x}: special characters are not allowed\n  in \"<unicode string>\", position
    {char index}" (PyYAML's text verbatim; a NUL never truncates the text).
  - NEL (U+0085) is a line break everywhere (PyYAML's `scan_line_break` reads it as
    `\n`); a literal LS/PS (U+2028/U+2029) is an error (§11 D17 (f)).
  - Block scalars (`|`, `>`) keep only the line breaks PyYAML reads: one whose last line
    runs to the end of a text without a final line break gets no trailing `\n`
    (`a: |\n  x` → "x"), and one without content lines at the end of the text is "" (keep
    `|+`: its empty lines' breaks), where yaml-rust2 (YAML 1.2) adds a break.
  - Anchors/aliases are resolved by copying the anchored value (recursive alias = error;
    limits and residual differences in §11 D17 (e)); more than one
    document → "expected a single document in the stream"; empty text or an empty
    document → `Value::Null`.
  - Error texts are yaml-rust2's (syntax) or the PyYAML texts quoted above (construction);
    syntax-error wording and the exact set of malformed inputs each parser rejects differ
    from PyYAML (§11 D17).
- **Emitter** (`yaml::dump`): a port of PyYAML 6.0.3's `Emitter` for the subset r2 writes
  (block mappings and block sequences of str / int / float / bool / null scalars, `{}` /
  `[]` for empty collections): mapping order preserved, best_indent 2, sequences under a
  key not indented (`key:\n- a`), best_width 80, `allow_unicode=False`. Scalar style is
  PyYAML's `choose_scalar_style` over `analyze_scalar`: plain when allowed and the plain
  text resolves back to a string (otherwise single-quoted: `'yes'`, `'017'`, `''`),
  single-quoted for multi-line text (`'a\n\n  b'`), double-quoted with `\uXXXX` escapes for
  non-ASCII or non-printable text (`"ключ"`); plain and quoted scalars
  fold at spaces past column 80 exactly as `write_plain` / `write_single_quoted` /
  `write_double_quoted` do; ints decimal, bools `true`/`false`, null `null`; the document
  ends with "\n". Every r2 YAML writer goes through it: template-file dumps (§5.16), the
  wizard's config snippet and structural append (§5.13), `config show`. R2 tests assert
  BYTE equality against PyYAML-generated vectors (ASCII/non-ASCII labels, multi-line
  values, long space-separated text, YAML-1.1-ambiguous strings, empty collections, every
  `templates.pkcs11` default), and the R13 harness diffs dumps byte-for-byte.

#### 4.8.5 YAML helpers for other crates (`r2_config::yaml`)

`serde_yaml_ng` (the `Value` tree) and `yaml-rust2` (the event parser) are dependencies of
r2-config only; r2-services (templatefile) and r2-console (wizard, `config show`) use these
helpers.

```rust
// crates/r2-config/src/yaml.rs
use r2_core::error::Result;
pub use serde_yaml_ng::{Mapping, Number, Value};

/// Load one YAML document with PyYAML `safe_load` semantics (§4.8.4). Err = Generic whose
/// message is the parser's text; callers embed `err.message` in their own c2 message
/// ("invalid YAML in config file {path}: {text}", "invalid YAML in template file {path}:
/// {text}", …) with their own kind.
pub fn parse(text: &str) -> Result<Value> { .. }
/// PyYAML `safe_dump(sort_keys=False, default_flow_style=False)` port (§4.8.4); trailing "\n".
pub fn dump(value: &Value) -> String { .. }
/// The integer of an int `Number` (i64/u64), else None — never coerces strings or bools
/// (c2 `_as_int`: `isinstance(v, int) and not isinstance(v, bool)`).
pub fn as_int(value: &Value) -> Option<i128> { .. }
/// Python type name of the value PyYAML produced ("dict", "list", "str", "int", "float",
/// "bool", "NoneType", and for `Value::Tagged` `!!timestamp` "date"/"datetime", `!!binary`
/// "bytes").
pub fn python_type_name(value: &Value) -> &'static str { .. }
```

### 4.9 Command framework (`r2_core::io`, `r2_core::render`, `r2_console`, `r2_cli`)

#### 4.9.1 Interaction traits (`r2_core::io`, R1)

The two interaction traits live in r2-core so that core/ops/services can use them without
the console. Implementations: `r2_console::io::LineIo` (TerminalIo / PlainIo, §4.9.7) and
`r2_testkit::ScriptedIo` (§4.10.1). All methods take `&self` (interior mutability).

```rust
// crates/r2-core/src/io.rs
use secrecy::SecretString;
use crate::error::{ConsoleError, ErrorKind, Result};
use crate::params::ParamSpec;
use crate::template::KeyTemplate;

/// One REPL read at the command prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandInput {
    Line(String),
    /// Ctrl-C at the prompt: the REPL prints `Aborted.` and re-prompts.
    Interrupted,
    /// Ctrl-D on an empty line / end of piped input: the REPL exits (status 0).
    Eof,
}

/// frozen-provisional (§4.11).
pub trait ConsoleIo {
    /// One parameter value. Rendered "{spec.prompt}: "; ENUM choices / BOOL words
    /// (true,false,yes,no,on,off) complete. Answers never enter the command history.
    /// Ctrl-C / Ctrl-D → UserAbort "aborted while entering '{spec.name}'".
    fn prompt(&self, spec: &ParamSpec) -> Result<String>;
    /// Hidden input (PINs, passwords). Rendered "{text}: " (c2 parity, even when `text`
    /// already ends with ": "); never echoed, logged or stored in any history.
    /// Ctrl-C / Ctrl-D → UserAbort "aborted secret input".
    fn prompt_secret(&self, text: &str) -> Result<SecretString>;
    /// Prints "{text} (finish with an empty line)", then reads lines with the prompt "| "
    /// until an empty line or EOF (EOF ends the input, it is not an abort); returns the
    /// lines joined with "\n". Ctrl-C → UserAbort "aborted multiline input".
    fn prompt_multiline(&self, text: &str) -> Result<String>;
    /// Prints table(None, ["#", title], [[1-based index, option]…]), then asks
    /// "Select [1-{N}]: " and, on the `text::py_strip`-trimmed answer, in this order (c2):
    /// (1) equal to an option text → the index of the FIRST equal option (text wins over
    /// number, so an option "2" is picked by text); (2) else `text::py_isdigit(answer)` and
    /// its `u64` value (overflow = invalid) in 1..=N → value − 1 ("02" → index 1; "+2",
    /// "1_0", "-0" are NOT numbers); (3) else prints "invalid choice
    /// {answer!r} — enter 1-{N} or the option text" and asks again. Never `py_int` or
    /// `str::parse::<usize>` alone (both accept "+2").
    /// Returns the 0-based index. Empty `options` → Generic "nothing to select for: {title}".
    /// Ctrl-C / Ctrl-D → UserAbort "selection aborted".
    fn select(&self, title: &str, options: &[String]) -> Result<usize>;
    /// Asks "{text} [Y/n] " (default true) or "{text} [y/N] "; empty → default;
    /// y/yes → true, n/no → false (trimmed, case-insensitive); else prints "please answer y
    /// or n" and asks again. Ctrl-C / Ctrl-D → UserAbort "confirmation aborted".
    fn confirm(&self, text: &str, default: bool) -> Result<bool>;
    /// Render output. Content is data — never interpreted as markup.
    fn print(&self, renderable: Renderable);
    /// Render `error_panel(&err.message, err.hint.as_deref())`.
    fn print_error(&self, err: &ConsoleError);

    /// The REPL's command-line read (history, hints, completion, highlighting in
    /// TerminalIo). `prompt` ("r2> ", "…> ") is shown VERBATIM (no ": " appended):
    /// `LineIo` and `ScriptedIo` override this method; the default (the blessed
    /// synthetic-STR-ParamSpec pattern) exists for other implementations.
    fn read_command(&self, prompt: &str) -> Result<CommandInput> {
        match self.prompt(&ParamSpec::str("command", prompt)) {
            Ok(line) => Ok(CommandInput::Line(line)),
            Err(err) if matches!(err.kind, ErrorKind::UserAbort) => Ok(CommandInput::Interrupted),
            Err(err) => Err(err),
        }
    }
    /// The `clear` command.
    fn clear(&self) {
        self.print(Renderable::Text("\u{1b}[2J\u{1b}[H".to_owned()));
    }
    /// Run `f` while showing a spinner with `message` (provisional r2 addition, §4.9.8;
    /// c2 never had one). Default: just run `f`. Contract for every implementation: `f` is
    /// called exactly once, and no `RefCell` borrow of the IO is held while it runs (prints
    /// and prompts inside `f` re-enter the IO); a nested `busy` just runs its `f`. Callers
    /// use `busy_with`, which returns `f`'s value.
    fn busy(&self, message: &str, f: &mut dyn FnMut()) {
        let _ = message;
        f();
    }
}

/// Runs `f` through `io.busy(message, ..)` and returns its value; if the implementation
/// did not call the closure (a contract violation), runs `f` directly — never panics, never
/// loses `f`'s result. The only sanctioned way to call `busy` (it avoids the
/// `Option<Result<T>>` dance under `-D clippy::unwrap_used`).
pub fn busy_with<T>(io: &dyn ConsoleIo, message: &str, f: impl FnOnce() -> T) -> T { .. }

/// One-method hook (frozen-provisional, §4.11). Edits a copy; returns the edited template;
/// UserAbort "template edit cancelled" on cancel.
pub trait TemplateEditor {
    fn edit(&self, template: KeyTemplate, title: &str) -> Result<KeyTemplate>;
}

/// Returns the template unchanged (c2 `_IdentityTemplateEditor`; also the R0 stub of
/// `create_template_editor`).
#[derive(Clone, Copy, Debug, Default)]
pub struct IdentityTemplateEditor;
impl TemplateEditor for IdentityTemplateEditor {
    fn edit(&self, template: KeyTemplate, title: &str) -> Result<KeyTemplate> {
        let _ = title;
        Ok(template)
    }
}
```

#### 4.9.2 Renderable model and renderer (`r2_core::io`, `r2_core::render`, R1)

```rust
// crates/r2-core/src/io.rs (continued)
/// Text style. Error = bold red, Danger = red.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tone { #[default] Plain, Bold, Dim, Italic, Error, Danger }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span { pub text: String, pub tone: Tone }
pub type Line = Vec<Span>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableData { pub title: Option<String>, pub columns: Vec<String>, pub rows: Vec<Vec<String>> }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PanelData {
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub border: Tone,
    pub body: Vec<Line>,
}

/// Closed set of outputs. Nothing is ever parsed as markup (rich's `[#…]`/`[x]` eating
/// cannot happen).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Renderable {
    /// Plain text (may contain newlines); never markup. Laid out like rich's `Text`
    /// (control codes stripped, tabs expanded, fold-wrapped at the width; §4.9.2).
    Text(String),
    /// Pre-styled lines (caret echo, banners); laid out like `Text`.
    Styled(Vec<Line>),
    Table(TableData),
    /// Grouped hex dump panel; grouping/width from RenderConfig at render time.
    Hex { data: Vec<u8>, title: Option<String> },
    Panel(PanelData),
}
impl From<&str> for Renderable { fn from(text: &str) -> Self { Renderable::Text(text.to_owned()) } }
impl From<String> for Renderable { fn from(text: String) -> Self { Renderable::Text(text) } }

/// Red-bordered panel titled "error": message line (Tone::Error), then "hint: {hint}"
/// (Tone::Dim) when given.
pub fn error_panel(message: &str, hint: Option<&str>) -> Renderable { .. }
/// The physical row of `line` containing byte offset `pos` (clamped to 0..=len), then a
/// row of spaces + "^" (Tone::Error) whose column is the display width of the row prefix
/// before `pos` as the renderer lays the row out (rich cell widths, control codes stripped,
/// tabs expanded to 8 columns; §4.9.2, §11 D14).
pub fn caret(line: &str, pos: usize) -> Renderable { .. }
/// Uniform table used by every command (cells are data, never markup; control codes
/// stripped as in rich).
pub fn table(title: Option<&str>, columns: &[&str], rows: Vec<Vec<String>>) -> Renderable { .. }
/// Hex dump panel (c2 `render.hex_panel`).
pub fn hex(data: &[u8], title: Option<&str>) -> Renderable { .. }
```

```rust
// crates/r2-core/src/render.rs
use crate::io::Renderable;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenderConfig { pub width: usize, pub hex_group: usize, pub hex_width: usize }
impl RenderConfig {
    /// c2's test rendering console (rich, width 200) — used by ScriptedIo.
    pub const CAPTURE: RenderConfig = RenderConfig { width: 200, hex_group: 2, hex_width: 32 };
}
/// ALWAYS emits ANSI SGR styling (the Full sink). Lines joined with "\n", no trailing
/// newline.
pub fn render(renderable: &Renderable, cfg: &RenderConfig) -> String { .. }
/// The same layout with no SGR at all (tones ignored; rich writing to a non-terminal):
/// content bytes the rich Text model keeps (ESC, NUL, DEL, other C0) pass unchanged —
/// tests, ScriptedIo, snapshots, the Plain sink.
pub fn render_plain(renderable: &Renderable, cfg: &RenderConfig) -> String { .. }
/// The same layout with colour-free SGR (bold/dim/italic only; rich `no_color`) — the
/// NoColor sink. Content bytes pass unchanged.
pub fn render_no_color(renderable: &Renderable, cfg: &RenderConfig) -> String { .. }
```

Styling is chosen by the renderer per tone, never by stripping escape sequences from
rendered text afterwards (a stripper cannot tell the renderer's SGR from content bytes:
c2/rich wrote a label's ESC, NUL, DEL or a whole `ESC[…m`/OSC run verbatim, and layout
counted those characters with rich cell widths, so borders stay aligned).

Rendering rules (normative; layout differences from rich are D1):

- **rich Text model** (everything c2 held in a rich `Text`: printed strings, the caret
  echo, panel bodies, titles and subtitles, table cells, headers and title): BEL, BS, VT,
  FF and CR are stripped (rich `strip_control_codes`); every other character — ESC and
  whole escape sequences in the content, NUL, other C0, DEL — is kept and written verbatim
  by every rendering (`render`, `render_no_color`, `render_plain`); widths are rich 15
  cell widths — rich's own Unicode 17.0.0 table (C0/C1 controls 0), a ZWJ joins the next
  character into the preceding grapheme (adding no width), VS16 widens rich's
  `narrow_to_wide` characters to 2; tabs
  expand to the next multiple of 8 cells; wrapping is rich `Text.wrap` (greedy at
  whitespace, words wider than the width folded, `rstrip_end`, truncate).
- **Table**: comfy-table `TableStyle` with only a header separator (fill/junction `─`,
  rich `box.SIMPLE_HEAD` look), `force_no_tty()` + `enforce_styling()` +
  `set_width(cfg.width)` + `ContentArrangement::Dynamic`, bold header cells, `trim_fmt()`;
  the title is rendered by r2 as a centered italic line over the table body; an empty
  title is none, and a table with no columns and no rows renders "" (title included).
- **Panel**: own renderer — rounded box (`╭─╮│╰╯`), title in the top border
  (`╭─ title ───╮`), subtitle right-aligned in the bottom border (`── 40 bytes ─╯`), width =
  unwrapped content width capped at `cfg.width - 4` (rich `expand=False`), the body laid
  out by the rich Text model; an empty title or subtitle is none (rich `if self.title:`),
  a content width below 1 renders no body line. Error panel: Danger border, bold red
  message, dim hint — its text equals rich's.
- **Hex**: Panel with `format_hex(data, cfg.hex_group, cfg.hex_width)` body, the given
  title, subtitle "{n} bytes"; empty data → body "(empty — 0 bytes)", no subtitle.
  Byte-identical to c2/rich at 80 columns.
- **Text** and **Styled** (spans per line, their tones kept): laid out by the rich Text
  model at `cfg.width`, i.e. exactly what c2's `console.print(str, markup=False)` /
  `console.print(Text)` printed apart from §11 D1's highlighting and D23's emoji codes (a
  width of 0 — never produced by the width rule below — leaves the lines unwrapped).
- Width (rich 15 `Console.size`, recomputed per print): when the sink is a terminal
  (§4.9.7 `is_terminal`) and `TERM` is `dumb`/`unknown` (case-insensitive) → 80, unless
  BOTH `$COLUMNS` and `$LINES` are all ASCII digits (then `$COLUMNS`); otherwise `$COLUMNS`
  when it is all ASCII digits; otherwise the controlling terminal's width when any of
  stdin, stdout, stderr is a terminal (rich tries fd 0, 1, 2 in order;
  `crossterm::terminal::size()` queries that terminal); a 0 or missing width → 80.
  `ScriptedIo` always uses `RenderConfig::CAPTURE` (width 200).

#### 4.9.3 Template editor factory (`r2_console::template_editor`, R10)

```rust
use std::rc::Rc;
use r2_config::model::AppConfig;
use r2_core::io::{ConsoleIo, TemplateEditor};

/// The §5.12 checklist editor over the loaded configuration (it reads
/// `config.templates.custom_attributes`). Its mini-REPL line is read with
/// `io.prompt(&ParamSpec::str("template", "template> "))`.
/// R0 stub body (mandated): `Rc::new(r2_core::io::IdentityTemplateEditor)` — the r2
/// equivalent of c2's lazy-import identity fallback, so R7's bootstrap is correct on both
/// sides of R10's merge.
pub fn create_template_editor(io: Rc<dyn ConsoleIo>, config: &AppConfig) -> Rc<dyn TemplateEditor> { .. }
```

c2's lazy `importlib` wiring is n/a (direct construction).

#### 4.9.4 `AppContext` (`r2_console::context`, R7)

```rust
use std::rc::Rc;
use r2_config::model::{AppConfig, LoadedConfig};
use r2_core::io::{ConsoleIo, TemplateEditor};
use r2_ops::OperationRegistry;
use r2_provider::ProviderRegistry;

/// Built by r2-cli (or `testing::CtxBuilder`), passed to every command. `io` and
/// `template_editor` are `Rc` because the editor shares the IO. There is no logger field
/// (c2 `log: logging.Logger` → `tracing` macros, target "r2::…"), and `--debug` is a
/// parameter of `run_repl`, deliberately not a field.
pub struct AppContext {
    pub config: Rc<LoadedConfig>,
    pub providers: ProviderRegistry,
    pub operations: OperationRegistry,
    pub io: Rc<dyn ConsoleIo>,
    pub template_editor: Rc<dyn TemplateEditor>,
}
impl AppContext {
    /// `&self.config.config`.
    pub fn cfg(&self) -> &AppConfig { .. }
}
```

#### 4.9.5 REPL (`r2_console::repl`, R7)

```rust
use std::collections::BTreeMap;
use std::rc::Rc;
use crate::commands::Command;
use crate::context::AppContext;

pub const PROMPT: &str = "r2> ";
pub const CONTINUATION_PROMPT: &str = "…> ";

/// What a command asks the REPL to do next. `Exit` replaces c2's `ReplExit` (raised by
/// `exit`/`quit`); it never crosses the console boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow { Continue, Exit }

/// Command name → command (sorted by name).
pub type CommandTable = BTreeMap<&'static str, Rc<dyn Command>>;

/// The interactive loop (algorithm below). r2-cli obtains `commands` from
/// `commands::all_commands()` BEFORE calling it (an Err there — e.g. a duplicate command
/// name — is a startup error: stderr "error: …", exit 2). Returns when the operator exits;
/// never returns an error (everything is rendered).
pub fn run_repl(ctx: &Rc<AppContext>, debug: bool, commands: Rc<CommandTable>) { .. }

/// One logical line through tokenize → lookup → bind_args → run (no rendering). Used by
/// run_repl and by tests (`testing::run_line`).
pub fn dispatch(ctx: &AppContext, commands: &CommandTable, line: &str) -> r2_core::Result<Flow> { .. }
```

`run_repl` (normative):

1. Install the completion/highlighting bridge for `ctx` (§4.9.7) for the loop's lifetime.
2. Read phase: `buffer = io.read_command(PROMPT)`; while `!line_is_complete(&buffer)`:
   `buffer += "\n" + read_command(CONTINUATION_PROMPT)` (c2's loop; a no-op for TerminalIo,
   whose Validator only returns complete buffers). `Interrupted` anywhere → print
   `Aborted.` (Text) and start over. `Eof` anywhere → leave the loop. An `Err` from
   `read_command` (only PlainReader I/O errors can produce one; TerminalIo degrades
   instead) is printed with `print_error` and leaves the loop (c2 let the exception escape
   as a traceback — §11 D12).
3. `r2_core::runtime::reset_interrupt()` immediately before every dispatch.
4. Dispatch inside `std::panic::catch_unwind(AssertUnwindSafe(..))` — the single
   error-rendering boundary (§4.2):
   - `Ok(Flow::Exit)` → leave the loop; `Ok(Flow::Continue)` → next line.
   - `UserAbort` → print `Aborted.` only.
   - `Parse { line, pos }` → print `caret(line, pos)`, then `print_error`.
   - any other error → `tracing::debug!` "command failed: {message}", then `print_error`.
   - panic → `r2_core::runtime::take_panic_report()` (the message, location and
     backtrace recorded by r2-cli's panic hook, §4.9.8/§4.9.11; None in tests without a
     hook → the payload text only) is logged with `tracing::error!` "unexpected error";
     with `debug` the report's backtrace is also printed (Text); then `print_error(Generic
     "unexpected error: {panic message}", hint "details logged to {cfg.app.log.file}")`.
5. `dispatch`: `tokenize(line)?`; no tokens → `Ok(Continue)`; unknown first token →
   UnknownOperation "unknown command '{name}'" (hint `render::suggest(name, names)` or
   "type 'help' for the command list"); `bind_args(&tokens[1..], cmd.flags(), line)?`;
   `tracing::debug!("command: {name}")` (the name only — lines may carry secrets, §6);
   `cmd.run(ctx, &args)`.

Exit: `exit`/`quit` commands return `Flow::Exit`; Ctrl-D at the prompt exits with status
0. Provider shutdown runs in r2-cli (drop guard) for every provider after the loop.

#### 4.9.6 `Command` trait and module registration (`r2_console::commands`, R7)

```rust
// crates/r2-console/src/commands/mod.rs
use std::rc::Rc;
use crate::context::AppContext;
use crate::parser::BoundArgs;
use crate::repl::{CommandTable, Flow};

/// One console command. Object-safe.
pub trait Command {
    fn name(&self) -> &'static str;
    fn summary(&self) -> &'static str;
    fn usage(&self) -> &'static str;
    /// Boolean `--options` (they consume no value token).
    fn flags(&self) -> &'static [&'static str] { &[] }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<Flow>;
    /// Completion candidates. `tokens` = every token of the line (command name included,
    /// and the partial token under the cursor when there is one); `cursor_token` = that
    /// partial token ("" at a new token). Candidates are FULL replacement tokens, filtered by
    /// prefix and de-duplicated by the completer. Must never call `ctx.io`, must never load
    /// a PKCS#11 library (use `completer::browsable`), and swallows every error.
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor_token: &str) -> Vec<String> {
        let _ = (ctx, tokens, cursor_token);
        Vec::new()
    }
}

// Generated by build.rs (see below):
include!(concat!(env!("OUT_DIR"), "/command_modules.rs"));

/// Fresh scan of every command module. Duplicate name → Config "duplicate command name
/// '{name}' (module '{module}')".
pub fn discover_commands() -> r2_core::Result<CommandTable> { .. }
/// Cached `discover_commands()` (thread-local; the module set is fixed per build).
pub fn all_commands() -> r2_core::Result<Rc<CommandTable>> { .. }
```

Registration convention (frozen; the rule that lets command loops run in parallel): every
file `crates/r2-console/src/commands/<stem>.rs` other than `mod.rs` is a command module and
exports exactly

```rust
pub fn commands() -> Vec<Box<dyn Command>> { .. }
```

`build.rs` lists `src/commands/*.rs` (excluding `mod.rs`), sorts by stem (stems are
snake_case identifiers), prints `cargo:rerun-if-changed=src/commands`, and writes
`$OUT_DIR/command_modules.rs` containing, per stem,
`#[path = "<CARGO_MANIFEST_DIR>/src/commands/<stem>.rs"] pub mod <stem>;` and one function
`pub(crate) fn module_commands() -> Vec<(&'static str, Vec<Box<dyn Command>>)>` returning
`(stem, <stem>::commands())` in stem order. There is NO hand-maintained registration table;
adding a command = adding a module (or a `Box` to your own module's `commands()`). The same
`build.rs` lists `src/tests/*.rs` (excluding `mod.rs`; `cargo:rerun-if-changed=src/tests`)
into `$OUT_DIR/test_modules.rs` as `#[path = "…"] mod <stem>;` lines, included by
`#[cfg(test)] mod tests { include!(concat!(env!("OUT_DIR"), "/test_modules.rs")); }` in
`lib.rs` (§4.1.1).

These command and test modules are reachable only through `include!` of OUT_DIR files,
which rustfmt does not follow, so `cargo fmt --check` never sees them. The justfile's and
CI's fmt step therefore also runs `rustfmt --edition 2024 --check
crates/r2-console/src/commands/*.rs crates/r2-console/src/tests/*.rs`, and the done gate
(§8) includes it.

`r2_console`'s crate root re-exports `AppContext`, `Flow`, `CommandTable`, `run_repl`,
`dispatch`, `Command`, `BoundArgs`, `OptValue`, `Token`.

R0 stub of every command module: `commands()` returns `vec![]` (§4.1.1), so discovery,
`help` and `run_line` work on main before the owning loop merges.

| module (owner) | commands |
|---|---|
| help (R7) | help |
| misc (R7) | exit, quit, clear, config |
| providers (R8) | providers, slots, login, logout |
| keys (R8) | keys, key, generate, load, export, csr, delete |
| crypto (R9) | encrypt, decrypt, sign, verify, derive, ops |
| copy (R10) | copy |
| key_template (R14) | none — `commands()` returns `vec![]`; entry point is the §4.9.9 hook |
| kek (R15) | none — `commands()` returns `vec![]`; entry points are the §4.9.9 hooks |

#### 4.9.7 Parser, binding, terminal I/O (`r2_console::parser`, `r2_console::io`, R7)

```rust
// crates/r2-console/src/parser.rs
use indexmap::IndexMap;

/// One shell-style token. `pos`/`end` are byte offsets of the raw token in the line
/// (opening/closing quote included).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token { pub text: String, pub quoted: bool, pub pos: usize, pub end: usize }

/// Split per the rules below. Unterminated quote → Parse "unterminated quote" (pos at the
/// opening quote; hint "close the quote, or keep typing — unterminated quotes continue on
/// the next line").
pub fn tokenize(line: &str) -> r2_core::Result<Vec<Token>> { .. }
/// False while an unterminated quote keeps the buffer open.
pub fn line_is_complete(line: &str) -> bool { .. }

/// Value of a `--option`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptValue { Value(String), Flag }

/// parser output (c2 BoundArgs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BoundArgs {
    pub positionals: Vec<String>,
    /// Parallel to `positionals`: was the token quoted?
    pub positional_quoted: Vec<bool>,
    /// name=value tokens; insertion order; a repeated name keeps its first position and
    /// the last value (Python dict semantics).
    pub named: IndexMap<String, String>,
    /// --options (same repeat semantics).
    pub options: IndexMap<String, OptValue>,
}
impl BoundArgs {
    /// Value of a value-carrying option (c2 `_opt`); None when absent or a Flag.
    pub fn opt(&self, name: &str) -> Option<&str> { .. }
    /// True when the option is present as a Flag (c2 `options.get(name) is True`).
    pub fn flag(&self, name: &str) -> bool { .. }
    pub fn has_option(&self, name: &str) -> bool { .. }
}

/// Bind per the rules below; `flags` = the command's boolean options; `line` = the full
/// original input (carried into Parse errors).
pub fn bind_args(tokens: &[Token], flags: &[&str], line: &str) -> r2_core::Result<BoundArgs> { .. }
```

Tokenizer rules (frozen): split on unquoted whitespace including newlines
(`text::is_py_space`); a `"` or `'` opens a quoted token **only at a token boundary**
(inside an unquoted token quote chars are literal); `"…"`/`'…'` delimit one token preserving
inner whitespace verbatim; inside quotes a backslash escapes only the active quote char and
backslash (any other backslash sequence is kept verbatim); a closing quote always ENDS
the token, and the next non-space character starts a new token even without whitespace
(c2 parser.py: `"a"b` → [`a` quoted, `b`]; `"a""b"` → [`a` quoted, `b` quoted]; `x"y"` →
one unquoted token `x"y"`); an unterminated quote is a multiline continuation (`…> `), so
PEM blocks paste inside quotes. Each token carries `quoted`. Binding order — applied to **unquoted tokens only**; a quoted token is NEVER an
option or a name=value (that is what makes pasted base64/PEM with `=` safe inside quotes)
and binds as a positional or as the value of a preceding `--opt`:

1. `--name` — empty name → Parse "empty option name" (hint "options are written --name");
   listed in `flags` → `OptValue::Flag`; otherwise consumes the NEXT token (whatever it is)
   as `OptValue::Value`; none left → Parse "option --{name} expects a value" (hint "write:
   --{name} <value>"); error pos = the option token's `pos`.
2. `name=value` — split at the first `=`; empty name → Parse "empty parameter name before
   '='" (hint "parameters are written name=value").
3. Everything else → positionals, in order, with `positional_quoted`.

Terminal I/O (normative behavior decided by S0 spike 3). Item placement in
`crates/r2-console/src/io/`: `mod.rs` SinkStyle, resolve_color, open_console_io;
`line.rs` ReadOutcome, SecretRead, LineReader, LineIo; `plain.rs` PlainReader, PlainIo;
`terminal.rs` DegradingReader, TerminalIo and the R7-internal ReedlineReader,
QuoteValidator, ChoiceCompleter, NarrowTerm; `history.rs` SecretFilteringHistory,
is_secret_line; `assist.rs` LineAssist, BridgeCompleter, BridgeHighlighter, AssistGuard,
install_line_assist. Everything below except `open_console_io` (r2-cli's entry point) is
R7-internal and frozen-provisional (§4.11.2); private fields and helpers are R7's choice.

```rust
// crates/r2-console/src/io/mod.rs
use std::rc::Rc;
use r2_config::model::{AppConfig, ColorMode};
use r2_core::io::ConsoleIo;

/// How rendered output (always ANSI-styled, §4.9.2) reaches stdout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkStyle {
    /// Every escape sequence passes.
    Full,
    /// Colour SGR parameters are removed, bold/dim/italic/reset kept (rich `no_color`).
    NoColor,
    /// No escape sequences at all (rich: not a terminal, or a dumb one).
    Plain,
}

/// rich 15's `Console` decision under c2's mapping (`always` → force_terminal=True,
/// `never` → no_color=True): is_terminal = true for `always`; otherwise `TTY_COMPATIBLE`
/// "0" → false / "1" → true; otherwise `FORCE_COLOR` set → (its value is non-empty);
/// otherwise `stdout_is_tty`. Not is_terminal, or `TERM` dumb/unknown (case-insensitive)
/// → Plain; else `never` or a non-empty `NO_COLOR` → NoColor; else Full. `CLICOLOR` /
/// `CLICOLOR_FORCE` are ignored (rich ignores them).
pub fn resolve_color(ui: ColorMode, stdout_is_tty: bool, env: &dyn Fn(&str) -> Option<String>) -> SinkStyle { .. }

/// The session's ConsoleIo — called once by r2-cli (§4.9.11). TerminalIo iff
/// `crossterm::tty::IsTty` holds for stdin AND stdout and `TERM != "dumb"`; otherwise
/// PlainIo. Prints the one-line mintty/msys warning (hidden input unavailable; suggests
/// Windows Terminal or `winpty r2`) when `std::io::IsTerminal(stdin) && !IsTty(stdin)` —
/// the one allowed IsTerminal site. Sink style = `resolve_color(config.ui.color,
/// IsTty(stdout), env)`; hex layout from `config.ui`; command history at
/// `config.app.history_file` (parent directory created; unusable → in-memory).
pub fn open_console_io(config: &AppConfig) -> Rc<dyn ConsoleIo> { .. }
```

```rust
// crates/r2-console/src/io/line.rs
use std::io;
use secrecy::SecretString;

/// One non-secret read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadOutcome { Line(String), Interrupted, Eof }
/// One secret read — the reader wraps the text in `SecretString` itself, so a secret never
/// crosses the seam as a plain `String` (D3).
#[derive(Debug)]
pub enum SecretRead { Secret(SecretString), Interrupted, Eof }

/// Console-internal reader seam; LineIo's unit tests drive it with a scripted reader.
pub trait LineReader {
    /// `prompt` is shown verbatim ("r2> ", "…> ").
    fn read_command(&mut self, prompt: &str) -> io::Result<ReadOutcome>;
    /// `prompt` verbatim (LineIo has appended ": " where §4.9.1 says so); `choices` feed
    /// completion (ENUM choices / BOOL words).
    fn read_param(&mut self, prompt: &str, choices: &[String]) -> io::Result<ReadOutcome>;
    fn read_secret(&mut self, prompt: &str) -> io::Result<SecretRead>;
    /// Terminal side of `clear` (reedline repaint). Default: nothing.
    fn clear_screen(&mut self) {}
}

/// The ONE ConsoleIo over a LineReader: the §4.9.1 prompt/secret/multiline/select/confirm
/// logic and texts exist only here.
pub struct LineIo<R: LineReader> { /* reader: RefCell<R>, sink + SinkStyle, hex layout, spinner slot */ }
impl<R: LineReader> r2_core::io::ConsoleIo for LineIo<R> { .. }
```

```rust
// crates/r2-console/src/io/plain.rs
use super::line::{LineIo, LineReader};

/// Plain line reads from the global stdin handle (rules below).
pub struct PlainReader { /* stdin_is_tty, … */ }
impl LineReader for PlainReader { .. }
pub type PlainIo = LineIo<PlainReader>;
```

```rust
// crates/r2-console/src/io/terminal.rs
use super::line::{LineIo, LineReader};

/// reedline primary (R7-internal `ReedlineReader`), `PlainReader` fallback (rules below).
pub struct DegradingReader { /* primary: Option<ReedlineReader>, plain: PlainReader */ }
impl LineReader for DegradingReader { .. }
pub type TerminalIo = LineIo<DegradingReader>;
```

```rust
// crates/r2-console/src/io/history.rs
/// c2 parity: the line contains "--pin" or "--password" (§11 D8 records the open decision
/// on inline key material).
pub fn is_secret_line(line: &str) -> bool { .. }
/// reedline History wrapper over `FileBackedHistory` (rules below).
pub struct SecretFilteringHistory { /* inner: reedline::FileBackedHistory */ }
impl reedline::History for SecretFilteringHistory { .. }
```

```rust
// crates/r2-console/src/io/assist.rs
use std::rc::Rc;

/// What run_repl installs for completion and highlighting. Implementations never call
/// `ctx.io` and swallow every ConsoleError (no suggestions / unstyled text).
pub trait LineAssist {
    fn complete(&self, line: &str, pos: usize) -> Vec<reedline::Suggestion>;
    fn highlight(&self, line: &str) -> reedline::StyledText;
}
/// Zero-sized `Send` shims handed to reedline; they reach the thread-local LineAssist.
pub struct BridgeCompleter;
pub struct BridgeHighlighter;
impl reedline::Completer for BridgeCompleter { .. }
impl reedline::Highlighter for BridgeHighlighter { .. }
/// RAII guard of `install_line_assist`; restores the previous slot value on drop.
pub struct AssistGuard { /* previous: Option<Rc<dyn LineAssist>> */ }
/// Installs `assist` in the thread-local `Option<Rc<dyn LineAssist>>` slot.
pub fn install_line_assist(assist: Rc<dyn LineAssist>) -> AssistGuard { .. }
```

- `LineIo` overrides `read_command` and renders its prompt VERBATIM (never "r2> : ");
  `prompt` renders "{spec.prompt}: "; `prompt_secret` "{text}: ". It wraps nothing itself
  — `SecretRead::Secret` already holds a `SecretString`. `LineIo::clear` writes
  `\x1b[2J\x1b[H` through the sink iff the SinkStyle is not Plain (rich's
  `Console.clear()` rule: not a terminal or a dumb one → nothing) and lets the reader
  repaint (`clear_screen`). `LineIo::busy`: only TerminalIo with stderr a tty shows the
  spinner (§4.9.8); it clones the `ProgressBar` out of the spinner slot and drops the
  borrow before running `f`; a nested `busy` runs `f` without a second spinner. While busy,
  `ProgressBar::suspend` wraps ONLY the innermost terminal primitive — one Sink write, one
  `LineReader` call — and is never nested (indicatif 0.18 `suspend` holds the bar's std
  `Mutex` while its closure runs: nesting deadlocks, and a panic inside poisons it), so
  `select`/`confirm`/`print` never wrap their whole body. The busy guard's `Drop` always
  calls `set_spinner_active(false)`; when `std::thread::panicking()` it calls NO
  `ProgressBar` method (every one locks that possibly poisoned mutex and would panic during
  the unwind → abort) and just drops the handle (`BarState`'s own `Drop` needs no lock; the
  ticker holds only a `Weak`); otherwise it calls `finish_and_clear`.
- `DegradingReader`: the first `io::Error` from reedline (e.g. the 2 s timeout of an
  unanswered `ESC[6n`) disables raw mode, prints one stderr line `warning: line editor
  unavailable (<error>); continuing with plain input` and switches the session to plain
  reads permanently; the REPL never exits because of a terminal error. `ReedlineReader`
  wraps each `read_line` in a guard that calls `crossterm::terminal::disable_raw_mode()`
  when the thread is panicking (a panic inside reedline must not leave the terminal raw;
  the panic hook itself never touches the terminal).
- Reedline command editor: `SecretFilteringHistory` over
  `FileBackedHistory::with_file(1000, app.history_file)` (unusable path → in-memory
  `FileBackedHistory::new(1000)`), `DefaultHinter::default().with_style(
  nu_ansi_term::Style::new().fg(nu_ansi_term::Color::DarkGray))`, `BridgeCompleter`,
  `BridgeHighlighter`, `QuoteValidator` (Incomplete iff `!line_is_complete`), `IdeMenu`
  named "completion_menu" with `.with_marker("")` and a border, Emacs keybindings + Tab =
  `UntilFound[Menu("completion_menu"), MenuNext]` + Shift-Tab = `MenuPrevious`,
  `with_quick_completions(true)`, `with_partial_completions(true)`,
  `use_bracketed_paste(true)`, `with_ansi_colors(style == SinkStyle::Full)` (so `ui.color:
  never` and `NO_COLOR` switch the editor's colours off too, §5.1); prompt
  "r2> " with multiline indicator "…> "; `sync_history()` after every read_command.
  Param/select/confirm/multiline answers use a second Reedline (in-memory
  `FileBackedHistory::new(100)`, a ChoiceCompleter fed per prompt, the same menu, a plain
  highlighter, no hinter, no validator, `use_bracketed_paste(true)` so a paste at the `| `
  prompt — newlines and blank lines included, e.g. a traditional encrypted PEM — arrives as
  ONE answer, as in c2's param session). Choices open on Tab only (c2's param session
  completed while typing — §11 D9). Secrets: `rpassword::prompt_password` (TerminalIo, and
  PlainIo when stdin is a tty); piped PlainIo reads one plain line from `std::io::stdin()`
  and never echoes it; rpassword's reader mode is never used. Mapping: reedline
  `Signal::Success` → Line, `CtrlD` → Eof, `CtrlC` and anything else → Interrupted;
  rpassword `ErrorKind::Interrupted` → Interrupted, `UnexpectedEof` → Eof.
- `SecretFilteringHistory`: `save()` returns `Ok(HistoryItem { id: None, ..item })`
  without storing when `is_secret_line(&item.command_line)` and never returns `Err`
  (reedline `.expect()`s it); `update()` re-checks the updated line; everything else
  delegates. The history file stores one logical entry per command with reedline's
  escaping (D7).
- `PlainReader`: writes the prompt to stdout, reads one line with byte-level
  `read_until(b'\n')` on the global `std::io::stdin()` handle (never a second BufReader),
  strips trailing `\r`/`\n`, decodes with `String::from_utf8_lossy`; when stdin is NOT a
  terminal it then echoes the line plus "\n" (secrets: only "\n") — on a terminal (TERM=dumb,
  stdout redirected, or a degraded TerminalIo) the tty driver already echoed it. At EOF it
  writes "\n" and returns Eof. No ESC bytes when piped. On a terminal, Ctrl-C reaches the
  ctrlc handler (the blocking read restarts and the tty discards the partial line), so
  after every plain read on a terminal: if `runtime::interrupted()`, reset the flag,
  discard the line and return Interrupted (Ctrl-C there takes effect at the next Enter —
  §11 D2). When stdin is NOT a terminal, a SIGINT (the ctrlc handler's flag) set before a
  plain read makes it write "\n" after the prompt and return Interrupted without reading;
  one that arrives while the read blocks resets the flag, writes "\n" (no echo), keeps the
  line read in a one-slot stash and returns Interrupted — the next read returns the stashed
  line (echoed after its prompt) before touching stdin, so no script line is lost (c2's
  KeyboardInterrupt left the unread pipe data in place). The line read by an interrupted
  secret read (`read_secret`, piped) is never stashed: it is zeroized and discarded, so a
  PIN or password can never come back as a command (echoed, saved to the history,
  dispatched). A command read on a terminal resets the flag BEFORE it blocks (only a Ctrl-C
  pressed during that read counts; a stale one — pressed while a command ran, or the
  SIGINT rpassword raises for Ctrl-C at a hidden prompt — never swallows the next command),
  and `rpassword_secret` consumes the interrupt its own `raise(SIGINT)` causes (bounded
  wait for the ctrlc handler, then reset). History: PlainReader joins the physical lines
  of a command whose quote is open exactly as the REPL does ("\n") and saves the logical
  command once, when the quote closes (an entry still open at Ctrl-C/EOF is never saved),
  through `SecretFilteringHistory` + `sync` — the same file format as TerminalIo (D7).
  EOF in a param prompt → UserAbort ("Aborted."); EOF at `r2>` exits 0. R7's pty smoke
  test covers TERM=dumb.
- Completion/highlighting bridge: reedline requires `Send` extension points and
  AppContext is `!Send`, so `run_repl` installs its `LineAssist` with
  `install_line_assist` for the loop's lifetime; reedline only receives the zero-sized
  `Send` shims, which degrade to "no suggestions"/plain text when nothing is installed, and
  run every `LineAssist` call inside `std::panic::catch_unwind(AssertUnwindSafe(..))` (a
  panic in `Command::complete` → no suggestions / unstyled text; it must not unwind through
  reedline's raw-mode `read_line`). No `unsafe`.
- Completion contract: nothing is completed when `!line_is_complete(text before the
  cursor)`; first token → command names; later tokens → the command's `complete` with
  `tokens`/`cursor_token` as in §4.9.6; candidates sorted, de-duplicated, filtered by the
  cursor-token prefix; `Suggestion.span` = byte range from the raw cursor token's start
  (`Token.pos`, incl. an opening quote) to `pos`, or `(pos, pos)` at a new token;
  `append_whitespace = false`; path-like candidates get `display_override` = last path
  component. Highlighting (`reedline::StyledText` of `nu_ansi_term::Style`s): known command
  green bold, unknown red, `provider:` refs of registered providers cyan, `--options` blue,
  `name=value` magenta, quoted strings (incl. an open quote) yellow — classified as
  `parser::bind_args` binds them: the token after an unquoted `--name` that is not one of
  the command's `flags()` is that option's value (yellow if quoted, cyan if a registered
  ref, else unstyled — never blue or magenta), `--` alone and `=value` with an empty name
  (binder Parse errors) are unstyled.
- Sink: the text is rendered per style by `r2_core::render` — Full → `render`, NoColor →
  `render_no_color`, Plain → `render_plain` — and written unchanged (never filtered or
  stripped afterwards, so content bytes reach stdout as rich wrote them, §4.9.2): Full and
  NoColor through `anstream::AutoStream<Stdout>` with `ColorChoice::Always` (legacy
  Windows consoles: wincon fallback, §11 D1), Plain straight to `Stdout`. It is the only
  place output styling is decided; every print uses `std::io::Write` on it (never the
  print macros).

#### 4.9.8 Ctrl-C flag, spinner flag, panic report (`r2_core::runtime`, R1)

```rust
// crates/r2-core/src/runtime.rs — the only process-global mutable state (two atomics),
// plus one thread-local panic-report slot
/// Called by the ctrlc handler (r2-cli): one atomic store, nothing else.
pub fn request_interrupt() { .. }
/// Called by run_repl immediately before every dispatch (a stale flag would abort the next
/// command — rpassword itself raise()s SIGINT).
pub fn reset_interrupt() { .. }
pub fn interrupted() -> bool { .. }
/// Step-boundary check for commands and services (e.g. between copy-ladder rungs, between
/// sibling renames): Err(UserAbort "interrupted") when the flag is set (not reset).
pub fn check_interrupt() -> crate::Result<()> { .. }
/// Provisional (spinner): set by LineIo::busy while a spinner is shown; read by the
/// audited set_var site (`debug_assert!(!spinner_active())`).
pub fn set_spinner_active(active: bool) { .. }
pub fn spinner_active() -> bool { .. }
/// Called by r2-cli's panic hook (which must be `Send + Sync`, so it cannot capture
/// Rc/RefCell state): stores "{message} at {location}\n{backtrace}" in a THREAD-LOCAL slot
/// of the panicking thread (the REPL thread is the only one whose panics matter).
pub fn record_panic_report(report: String) { .. }
/// Taken (slot emptied) by run_repl's catch_unwind branch (§4.9.5); None when no hook is
/// installed (tests) or nothing was recorded.
pub fn take_panic_report() -> Option<String> { .. }
```

Threads: the `ctrlc` handler thread (r2-cli, touches only the atomic; installed before the
first prompt — mandatory, because rpassword raises SIGINT itself) and, if the spinner is
kept, the indicatif ticker inside `LineIo::busy` (TerminalIo with stderr a tty only; draw
target `term_like_with_hz(NarrowTerm(console::Term::stderr()), 20)` reporting width−3;
while busy, the innermost terminal primitive (one Sink write, one reader call) runs inside
`ProgressBar::suspend`, never nested; a Drop guard resets the spinner flag and calls
`finish_and_clear`, or only drops the bar while `std::thread::panicking()`, §4.9.7). A blocking PKCS#11 call cannot be interrupted; the flag is honored at
the next boundary.

#### 4.9.9 Cross-loop console surfaces and hooks

These are the console items one loop provides and another calls. All are in the R0
skeleton.

**Completer helpers** (`r2_console::completer`, R7; used by R8, R9, R10, R14, R15):

```rust
// crates/r2-console/src/completer.rs
use r2_provider::Provider;

use crate::context::AppContext;

/// Provider instance names starting with `prefix` (any state — names are config data).
pub fn complete_provider_names(ctx: &AppContext, prefix: &str) -> Vec<String> { .. }
/// `provider:label` candidates (§5.1/§6): no ':' yet → every "name:" matching the prefix;
/// with a provider prefix → that provider's `display_refs` starting with the prefix — only
/// when `browsable(provider)` and list_keys succeeds, else just "name:" — plus, once the
/// prefix extends past a full label with '#' or ':', the §4.3 selector continuations
/// (`prov:label:<class>`, and for keys with an id `prov:label#<idhex>` and
/// `prov:label#<idhex>:<class>`), keeping a string generated by several keys only when they
/// form one distinct-class family with one id. Order: refs first, then continuations,
/// de-duplicated.
pub fn complete_refs(ctx: &AppContext, prefix: &str) -> Vec<String> { .. }
/// Filesystem candidates (§5.1 PathCompleter rule): FULL replacement tokens re-carrying the
/// typed directory part verbatim (`~` stays unexpanded in the candidate, expanded for
/// listing); directories get a trailing '/'; hidden entries only when the partial name
/// starts with '.'; sorted; unreadable directories → empty. Never errors.
pub fn complete_paths(prefix: &str) -> Vec<String> { .. }
/// True when listing keys cannot trigger a login or a library load: status().auth is
/// NotRequired or LoggedIn.
pub fn browsable(provider: &dyn Provider) -> bool { .. }
```

**Render helpers** (`r2_console::render`, R7):

```rust
// crates/r2-console/src/render.rs
use r2_core::keys::{KeyClass, KeyInfo};

/// difflib suggestion hint: Some("did you mean: a, b, c") over `known` sorted (n=3), or None.
pub fn suggest(wanted: &str, known: &[&str]) -> Option<String> { .. }
/// The `keys`-table class cell: "cert" for Certificate, else `KeyClass::as_str()`.
pub fn class_text(key_class: KeyClass) -> &'static str { .. }
/// The `keys`-table algorithm cell: "-" for KeyAlgorithm::None, else `as_str()`.
pub fn algo_text(info: &KeyInfo) -> &'static str { .. }
```

**Command helpers** (`r2_console::cmdutil`, R7; c2's per-module private helpers, shared
because R15's `kek.rs` is split out of c2's `keys_cmd.py`; modules whose c2 texts differ
keep private variants — e.g. copy's `--id` parser):

```rust
// crates/r2-console/src/cmdutil.rs
use r2_provider::Provider;
use r2_services::templatefile::SeedTemplates;

use crate::context::AppContext;
use crate::parser::BoundArgs;

/// Generic "missing <{what}> argument" (hint "usage: {usage}").
pub fn positional<'a>(args: &'a BoundArgs, index: usize, what: &str, usage: &str) -> r2_core::Result<&'a str> { .. }
/// First named token → Generic "unexpected name=value token '{name}=…'" (hint "usage:
/// {usage} (quote {noun} containing '=')"); noun = "data" (keys, kek) or "values" (providers).
pub fn reject_named(args: &BoundArgs, usage: &str, noun: &str) -> r2_core::Result<()> { .. }
/// `--id`: optional lower-case "0x" prefix, Python `bytes.fromhex` semantics. Invalid → Param
/// "invalid key id {raw!r}" (param "id", hint "--id takes whole hex bytes, e.g. --id 0a1b");
/// empty → Param "key id must not be empty" (param "id").
pub fn parse_key_id(args: &BoundArgs) -> r2_core::Result<Option<Vec<u8>>> { .. }
/// LoggedOut → AuthRequired "login required: run `login {name}`" (§5.5 auth-first order).
pub fn require_usable(provider: &dyn Provider) -> r2_core::Result<()> { .. }
/// `io.prompt(&ParamSpec::str("label", "Key label"))`, trimmed; empty → Param "label must
/// not be empty" (param "label").
pub fn prompt_label(ctx: &AppContext) -> r2_core::Result<String> { .. }
/// `--template <path>` → parsed §5.16 sections, parsed up front (fail before any prompt);
/// None when absent. Non-pkcs11 target → Param "--template applies only to PKCS#11 targets"
/// (param "template", hint "the template editor never opens for {name}").
pub fn parse_seed_templates(ctx: &AppContext, args: &BoundArgs, provider: &dyn Provider) -> r2_core::Result<Option<SeedTemplates>> { .. }
/// len(tokens) − 1 − (1 if cursor_token non-empty).
pub fn completed_args(tokens: &[String], cursor_token: &str) -> usize { .. }
/// The token before the one being completed (for `--opt <value>` completion).
pub fn previous_token<'a>(tokens: &'a [String], cursor_token: &str) -> Option<&'a str> { .. }
```

**SoftHSM wizard API** (`r2_console::wizard`, R11; called by R8's `login`):

```rust
// crates/r2-console/src/wizard.rs
use std::path::{Path, PathBuf};
use r2_provider::{Provider, TokenInfo};

use crate::context::AppContext;

pub const SOFTHSM2_CONF_ENV: &str = "SOFTHSM2_CONF";
/// Label offered when the operator just hits enter (c2: "c2" — §11 D7).
pub const DEFAULT_TOKEN_LABEL: &str = "r2";

/// §5.13 trigger: true when no initialized token exists — free SoftHSM slots present as
/// TokenInfo{label: "", serial: ""}; an initialized token always has a label or serial.
/// R0 stub body (mandated): `Ok(false)` (c2's ImportError fallback: login proceeds normally).
pub fn token_needs_init(provider: &dyn Provider) -> r2_core::Result<bool> { .. }
/// The §5.13 wizard end to end; Ok(None) = the operator declined (nothing touched).
/// Requires `provider.as_token_init()` (else UnsupportedOperation "provider '{name}' cannot
/// initialize tokens"). Step 1 writes the conf (`write_softhsm_conf`); step 2 is
/// `TokenInit::set_env_and_reset(SOFTHSM2_CONF_ENV, conf)` — the wizard never calls set_var
/// itself; when that refuses (shared module) the conf files of step 1 stay written and
/// nothing else changed. `library` = the module path for the reported
/// entry; None → re-detected with `find_softhsm_module(&cfg.softhsm.search_paths)`. Returns
/// the freshly initialized token (exact-label round trip) for the login flow.
/// R0 stub body (mandated): `Ok(None)`.
pub fn run_softhsm_wizard(ctx: &AppContext, provider: &dyn Provider, library: Option<&Path>) -> r2_core::Result<Option<TokenInfo>> { .. }
/// The exact softhsm2.conf text: "directories.tokendir = {token_dir}\nobjectstore.backend =
/// file\nlog.level = ERROR\n".
pub fn softhsm_conf_text(token_dir: &Path) -> String { .. }
/// Create conf_dir + token_dir, write softhsm2.conf; Config "cannot create the SoftHSM
/// configuration: {err}" ({err} = `text::py_os_error_str`, Python's `str(OSError)`; hint
/// "check softhsm.conf_dir / softhsm.token_dir in the configuration").
pub fn write_softhsm_conf(conf_dir: &Path, token_dir: &Path) -> r2_core::Result<PathBuf> { .. }
/// The providers.pkcs11[] entry {name, library (or "<path-to-libsofthsm2>"), token_label,
/// env: {SOFTHSM2_CONF: conf_path}} as a YAML mapping.
pub fn provider_config_entry(name: &str, library: Option<&Path>, conf_path: &Path, token_label: &str) -> r2_config::yaml::Value { .. }
/// `yaml::dump({"providers": {"pkcs11": [entry]}})` without the trailing newline.
pub fn render_config_snippet(entry: &r2_config::yaml::Value) -> String { .. }
/// c2's two-shape append (textual block with comment "# SoftHSM provider added by the r2
/// first-run wizard (spec §5.13)" when no `providers` key; else structural rewrite with a
/// `.bak` copy; an existing entry with the same name → Config "provider '{name}' is already
/// defined in {source}" (hint "edit that entry by hand if its settings should change")).
pub fn append_provider_entry(source: &Path, entry: &r2_config::yaml::Value) -> r2_core::Result<()> { .. }
```

The wizard's prompts (label via `ParamSpec::str("token_label", "Token label [r2]")` with
optional default; PINs via `prompt_secret("New SO PIN: ")` / "Repeat SO PIN: " etc., min 4
chars, 3 attempts; labels longer than 32 UTF-8 bytes re-prompted with c2's "Token labels
are limited to 32 characters (CK_TOKEN_INFO) — use a shorter one." — c2 counted
characters; identical for ASCII, §11 D15) and the `softhsm2-util --init-token
--free --label … --so-pin … --pin …` fallback (inherits the environment set in step 2;
never logged) are §5.13 behavior.

**`key template` hook** (`r2_console::commands::key_template`, R14; called by R8's `key`
command for subcommand "template"):

```rust
// crates/r2-console/src/commands/key_template.rs
use crate::context::AppContext;
use crate::parser::BoundArgs;

/// `key template <ref> <path>` (§5.16). `args` = the `key` command's BoundArgs:
/// positionals[0] == "template", [1] = ref, [2] = path. Non-pkcs11 provider →
/// UnsupportedOperation "key template works only with PKCS#11 providers" (hint "{name} keys
/// have no PKCS#11 attribute template"). Prints the "wrote {class_key} template (…)" line
/// and the key-material note. R0 stub: Err(not_implemented("R14")).
pub fn run(ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<()> { .. }
```

**`--kek` hooks** (`r2_console::commands::kek`, R15; called by R8's `load`/`export`):

```rust
// crates/r2-console/src/commands/kek.rs
use std::rc::Rc;
use r2_provider::Provider;

use crate::context::AppContext;
use crate::parser::BoundArgs;

/// `load <provider> <aes|rsa|ec|generic> [<data>|--file] --kek …` (§5.4). Called by `load`
/// right after the provider lookup and `require_usable` and BEFORE `reject_named` (the
/// name=value tokens are the mechanism's params), whenever `args.opt("kek")` is Some.
pub fn run_load(ctx: &AppContext, args: &BoundArgs, provider: &Rc<dyn Provider>) -> r2_core::Result<()> { .. }
/// `export <ref> <path> --kek …` (§5.6). Called by `export` first thing (before
/// `reject_named` and the --outformat check) whenever `args.opt("kek")` is Some.
pub fn run_export(ctx: &AppContext, args: &BoundArgs) -> r2_core::Result<()> { .. }
/// Completion for `--kek`-specific positions of `load`/`export`: `option` = the previous
/// token. "--kek" → KEK labels (the line's provider refs via complete_refs with the
/// "<provider>:" prefix stripped); "--mech" → wrap cli names (kw, kwp, cbc, gcm, oaep,
/// pkcs1); "--outformat" → raw, hex, b64; anything else → None.
pub fn complete_option_value(ctx: &AppContext, tokens: &[String], option: &str) -> Option<Vec<String>> { .. }
/// "<param>=" suggestions for the wrap mechanism named after `--mech` on the line (empty
/// when none/unknown).
pub fn param_name_candidates(tokens: &[String]) -> Vec<String> { .. }
```

R0 stubs: `run_load`/`run_export` → `Err(not_implemented("R15"))`; completion stubs →
`None` / empty.

#### 4.9.10 Service surfaces (`r2_services`)

Services never print, never import the console, and take the interaction traits by
reference. ★ marks surfaces another loop consumes.

```rust
// crates/r2-services/src/templatefile.rs (R14)
use std::path::Path;
use indexmap::IndexMap;
use r2_config::model::{CustomAttributeDef, TemplatesSection};
use r2_core::io::TemplateEditor;
use r2_core::keys::{KeyAlgorithm, KeyClass};
use r2_core::template::KeyTemplate;

/// §5.16 file sections: class key → template (kinds resolved by NAME).
pub type SeedTemplates = IndexMap<String, KeyTemplate>;
/// Read-only lifecycle + material attrs seeded DISABLED (§5.16).
pub const NON_CREATION_ATTRS: [&str; 27] = [
    "CKA_LOCAL", "CKA_ALWAYS_SENSITIVE", "CKA_NEVER_EXTRACTABLE", "CKA_KEY_GEN_MECHANISM",
    "CKA_MODULUS", "CKA_MODULUS_BITS", "CKA_PUBLIC_EXPONENT", "CKA_PRIVATE_EXPONENT",
    "CKA_PRIME_1", "CKA_PRIME_2", "CKA_EXPONENT_1", "CKA_EXPONENT_2", "CKA_COEFFICIENT",
    "CKA_PRIME", "CKA_SUBPRIME", "CKA_BASE", "CKA_EC_PARAMS", "CKA_EC_POINT", "CKA_VALUE",
    "CKA_VALUE_LEN", "CKA_CHECK_VALUE", "CKA_SERIAL_NUMBER", "CKA_ISSUER", "CKA_SUBJECT",
    "CKA_PUBLIC_KEY_INFO", "CKA_HASH_OF_SUBJECT_PUBLIC_KEY", "CKA_HASH_OF_ISSUER_PUBLIC_KEY",
];
/// Secret material a dump may carry — `key template` prints the handle-like-a-private-key note.
pub const SECRET_MATERIAL_ATTRS: [&str; 7] = [
    "CKA_VALUE", "CKA_PRIVATE_EXPONENT", "CKA_PRIME_1", "CKA_PRIME_2", "CKA_EXPONENT_1",
    "CKA_EXPONENT_2", "CKA_COEFFICIENT",
];
/// Write `template` as one class-keyed YAML section via `yaml::dump` + `keyexport::write_output`.
pub fn dump_template_file(path: &Path, class_key: &str, template: &KeyTemplate) -> r2_core::Result<()> { .. }
/// ★ (R8, R10, R15 via cmdutil/copy) Parse a §5.16 file. Unreadable → DataIo "cannot read
/// {path}: {err}"; bad YAML → Param "invalid YAML in template file {path}: {err}" (param
/// "template", hint "template files are class-keyed YAML (spec §5.16)"); empty/non-mapping →
/// Param "template file {path} has no sections" (hint "valid sections: {TEMPLATE_CLASS_KEYS
/// joined ', '}"); unknown section → "unknown template section '{key}' in {path}"; section
/// not a mapping → "template section '{key}' in {path} is not a mapping" (hint "each section
/// maps CKA_* names to values"); unknown CKA name → Param "unknown PKCS#11 attribute
/// '{name}'" (hint "define it under templates.custom_attributes (code + kind)"); kind/value
/// mismatch (c2 `_value_from_yaml`, param_name = name) → BOOL: "{name} expects true/false";
/// ULONG: a bool → "{name} expects an integer", a non-int non-symbol → "{name} expects an
/// integer or CKO_/CKK_/CKC_/CKM_ constant", a negative int → "template attribute {name}
/// must not be negative" (c2 raised it later, at conversion — §11 D18); BYTES: "{name}
/// expects a 0x… hex string" | "{name} has invalid hex" (`text::py_fromhex`); STR: "{name}
/// expects a string". Values are typed by the §4.8.4 loader, so `CKA_TOKEN: yes` is a bool
/// and `CKA_LABEL: yes` fails "expects a string", exactly as in c2.
/// R0 stub: Err(not_implemented("R14")).
pub fn load_seed_file(path: &Path, custom_attributes: &IndexMap<String, CustomAttributeDef>) -> r2_core::Result<SeedTemplates> { .. }
/// ★ Editor seed for one (class, algorithm): the matching file section when present
/// (locked CKA_CLASS/CKA_KEY_TYPE rows from the FLOW via default_template, file entries for
/// them dropped; CKA_LABEL/CKA_ID and NON_CREATION_ATTRS rows disabled; everything else
/// enabled with its file value), else `templates.default_template(..)` unchanged.
/// R0 stub body (mandated): `seeds == None` → `templates.default_template(key_class,
/// algorithm)`; `Some` → Err(not_implemented("R14")) — so R8/R10/R15 work before R14 merges.
pub fn build_seed(templates: &TemplatesSection, seeds: Option<&SeedTemplates>, key_class: KeyClass, algorithm: KeyAlgorithm) -> r2_core::Result<KeyTemplate> { .. }

/// ★ The seeding context every create flow passes around (keyload, transfer, wrapload).
#[derive(Clone, Copy)]
pub struct EditorSeeding<'a> {
    pub editor: &'a dyn TemplateEditor,
    pub templates: &'a TemplatesSection,
    pub seeds: Option<&'a SeedTemplates>,
}
impl<'a> EditorSeeding<'a> {
    /// `build_seed(..)` then `editor.edit(seed, title)`.
    pub fn edit(&self, key_class: KeyClass, algorithm: KeyAlgorithm, title: &str) -> r2_core::Result<KeyTemplate> { .. }
}
```

```rust
// crates/r2-services/src/keyload.rs (R8)
use std::path::Path;
use secrecy::SecretString;
use zeroize::Zeroizing;
use r2_core::io::ConsoleIo;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_provider::Provider;

use crate::templatefile::EditorSeeding;

/// Key-type hints of `load` / `--format` (§4.4/§5.1).
pub const VALID_HINTS: [&str; 7] = ["auto", "aes", "rsa", "ec", "cert", "generic", "data"];
/// Verbatim-bytes hints (no sniffing): "generic" → (Generic, Secret), "data" → (None, Data).
pub fn verbatim_hint(hint: &str) -> Option<(KeyAlgorithm, KeyClass)> { .. }
/// DataIo "cannot read {path}: {err}".
pub fn read_key_file(path: &Path) -> r2_core::Result<Zeroizing<Vec<u8>>> { .. }
/// §4.4 parse with the typed hint; generic/data short-circuit to one verbatim material
/// (empty → Param "{hint} material must not be empty", param "data"); password = --password
/// else a hidden `prompt_secret(prompt)` per encrypted item.
pub fn parse_materials(data: &[u8], hint: &str, password: Option<&SecretString>, io: &dyn ConsoleIo) -> r2_core::Result<Vec<KeyMaterial>> { .. }
/// ★ (R15) Label precedence: --label (trimmed; empty → Param "label must not be empty") →
/// first material label_hint → prompt "Key label" (empty → same Param).
pub fn resolve_label(materials: &[KeyMaterial], label: Option<&str>, io: &dyn ConsoleIo) -> r2_core::Result<String> { .. }
/// "PKCS#11 template — {algorithm} {class} '{label}'" (data objects: "{class}" only).
pub fn editor_title(material: &KeyMaterial, label: &str) -> String { .. }
/// Import every material under one label; PKCS#11 targets get one editor per material via
/// `seeding`. PKCS#11 targets only (`type_name() == "pkcs11"`): multi-material inputs
/// (PKCS#12) share one fresh 4-byte CKA_ID when none was given; memory keeps `None`.
pub fn import_materials(provider: &dyn Provider, materials: &[KeyMaterial], label: &str, key_id: Option<&[u8]>, seeding: &EditorSeeding<'_>) -> r2_core::Result<Vec<KeyInfo>> { .. }

// crates/r2-services/src/keyexport.rs (R8)
use std::path::Path;
use secrecy::SecretString;
use zeroize::Zeroizing;
use r2_core::keys::KeyInfo;
use r2_provider::Provider;

/// `export --format` values; "p12" is routed to certops.
pub const VALID_FORMATS: [&str; 5] = ["auto", "raw", "der", "pem", "p12"];
/// §5.6 pre-flight refusal (KeyNotExportable "Refusing to export: key '{ref}' is marked
/// sensitive/non-extractable." with the c2 hints).
pub fn refuse_non_exportable(key: &KeyInfo) -> r2_core::Result<()> { .. }
pub fn find_public_part(provider: &dyn Provider, key: &KeyInfo) -> r2_core::Result<Option<KeyInfo>> { .. }
pub fn public_spki(provider: &dyn Provider, key: &KeyInfo) -> r2_core::Result<Vec<u8>> { .. }
/// §5.6 table → (payload, resolved format token).
pub fn export_bytes(provider: &dyn Provider, key: &KeyInfo, fmt: &str, public: bool, password: Option<&SecretString>) -> r2_core::Result<(Zeroizing<Vec<u8>>, &'static str)> { .. }
/// ★ (R14) Write a payload; DataIo "cannot write {path}: {err}".
pub fn write_output(path: &Path, data: &[u8]) -> r2_core::Result<()> { .. }

// crates/r2-services/src/certops.rs (R8)
use secrecy::SecretString;
use r2_core::keys::KeyInfo;
use r2_provider::Provider;

pub const CSR_HASHES: [&str; 3] = ["sha256", "sha384", "sha512"];
pub fn find_certificate(provider: &dyn Provider, key: &KeyInfo) -> r2_core::Result<Option<KeyInfo>> { .. }
/// §5.6 PKCS#12 export. Without `cert_der` and without a co-located certificate it builds
/// a self-signed one with CN = the key label, and FIRST (before exporting or building
/// anything) checks the label: outside 1..=64 UTF-8 bytes → Param "Attribute's length must
/// be >= 1 and <= 64, but it was {n}" (param_name "label", hint "pass an existing
/// certificate with --cert") — §11 D12.
pub fn export_pkcs12(provider: &dyn Provider, key: &KeyInfo, password: &SecretString, cert_der: Option<&[u8]>) -> r2_core::Result<Vec<u8>> { .. }
/// §5.7: sign callback through provider.sign (RSA-PKCS1 / ECDSA r‖s → DER via
/// r2_core::der::ecdsa_rs_to_der / EDDSA raw). Returns PEM bytes.
pub fn generate_csr(provider: &dyn Provider, key: &KeyInfo, subject: &str, hash_name: &str) -> r2_core::Result<Vec<u8>> { .. }

// crates/r2-services/src/transfer.rs (R10)
use r2_core::io::ConsoleIo;
use r2_core::keys::KeyInfo;
use r2_provider::Provider;

use crate::templatefile::EditorSeeding;

pub const TRANSPORT_PREFIX: &str = "r2-transport-";
/// §5.5 decision matrix, ladder, refusal UX; transport keys are destroyed on success AND
/// failure (Drop guard) and their software bytes are `Zeroizing`.
pub fn copy_key(source: &dyn Provider, key: &KeyInfo, dest: &dyn Provider, io: &dyn ConsoleIo, seeding: &EditorSeeding<'_>, label: Option<&str>, key_id: Option<&[u8]>) -> r2_core::Result<KeyInfo> { .. }

// crates/r2-services/src/wrapload.rs (R15; consumed only by R15's kek.rs)
use std::collections::BTreeSet;
use r2_core::io::ConsoleIo;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo};
use r2_core::params::Params;
use r2_ops::OperationSpec;
use r2_provider::{Provider, ProviderRegistry};

use crate::templatefile::EditorSeeding;

/// Which side of the blob format a call is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction { Wrap, Unwrap }
/// One row of the §5.4/§5.6 wrap-mechanism table; `spec` is a synthetic OperationSpec
/// (id "load.unwrap.<cli>") read only for id + params by ParamResolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapMechEntry {
    pub spec: OperationSpec,
    pub kek_algorithm: KeyAlgorithm,
    pub unwrap_kek_class: KeyClass,
    pub wrap_kek_classes: BTreeSet<KeyClass>,
    pub result_classes: BTreeSet<KeyClass>,
}
/// The table in menu order: kw, kwp, cbc, gcm, oaep, pkcs1.
pub fn wrap_mechs() -> Vec<WrapMechEntry> { .. }
/// "aes" → (Aes, Secret), "generic" → (Generic, Secret), "rsa" → (Rsa, Private),
/// "ec" → (Ec, Private); anything else None.
pub fn result_by_hint(hint: &str) -> Option<(KeyAlgorithm, KeyClass)> { .. }
pub fn resolve_kek(registry: &ProviderRegistry, provider: &dyn Provider, token: &str, direction: Direction) -> r2_core::Result<KeyInfo> { .. }
pub fn candidates(kek: &KeyInfo, provider: &dyn Provider, direction: Direction) -> Vec<WrapMechEntry> { .. }
/// `--mech`: `text::py_strip(name).to_lowercase()` equals a cli_name or a lower-cased
/// canonical mechanism name (so "AES-KEY-WRAP" works). Unknown → Param "unknown wrap
/// mechanism {name!r}" (hint "did you mean: {close_matches(py_strip(name), cli names then
/// canonical names, 3) joined ', '}?" or "valid mechanisms: {cli names}"); not advertised →
/// UnsupportedOperation; wrong KEK → Param "{mechanism} {direction} needs a {classes} …",
/// where {classes} are the wanted class tokens sorted by `as_str()` and joined " or "
/// (e.g. "certificate or public" — c2 `sorted(c.value …)`, §4.3 note). c2 texts verbatim.
pub fn resolve_mech(name: &str, kek: &KeyInfo, provider: &dyn Provider, direction: Direction) -> r2_core::Result<WrapMechEntry> { .. }
pub fn select_mech(io: &dyn ConsoleIo, kek: &KeyInfo, provider: &dyn Provider, direction: Direction) -> r2_core::Result<WrapMechEntry> { .. }
/// What `load --kek` unwraps.
pub struct UnwrapJob<'a> {
    pub kek: &'a KeyInfo,
    pub entry: &'a WrapMechEntry,
    pub params: Params,
    pub wrapped: &'a [u8],
    pub result_algorithm: KeyAlgorithm,
    pub result_class: KeyClass,
    pub label: String,
    pub key_id: Option<Vec<u8>>,
}
pub fn load_wrapped(provider: &dyn Provider, job: UnwrapJob<'_>, seeding: &EditorSeeding<'_>) -> r2_core::Result<KeyInfo> { .. }
pub fn refuse_non_wrappable(key: &KeyInfo) -> r2_core::Result<()> { .. }
pub fn wrap_for_export(provider: &dyn Provider, kek: &KeyInfo, entry: &WrapMechEntry, params: Params, key: &KeyInfo) -> r2_core::Result<Vec<u8>> { .. }
```


#### 4.9.11 Bootstrap (`r2-cli`, R7)

```rust
// crates/r2-cli/src/bootstrap.rs
use std::collections::BTreeMap;
use r2_config::model::AppConfig;
use r2_provider::ProviderRegistry;
/// `{entry.ckm: entry.id}` handed to every Pkcs11Provider (§4.6).
pub fn custom_ckm_map(config: &AppConfig) -> BTreeMap<u64, String> { .. }
/// Memory (when enabled), every providers.pkcs11 instance (`Pkcs11Provider::new`), then —
/// ONLY when `softhsm.autodetect` is true — the SoftHSM autodetect instance: skipped with
/// an info log "softhsm autodetect skipped: provider {name!r} already configured" when the
/// name is taken by a registered provider (never an error); else
/// `find_softhsm_module(search_paths)` → `Pkcs11Provider::new(name,
/// Pkcs11InstanceConfig::new(name, path), …)`, or a debug log "softhsm autodetect: no
/// module found in search paths" when it returns None. Never loads a library (§6).
pub fn build_provider_registry(config: &AppConfig) -> r2_core::Result<ProviderRegistry> { .. }
```

Startup order: parse args (clap: `--version` prints "r2 {version}", `--config PATH`,
`--debug`) → the global tracing subscriber is installed (`logging::install`; until
`setup_logging` stores its state, WARN+ records go to stderr as bare messages + "\n" — no
timestamp, level or target — as Python's `logging.lastResort` printed c2's pre-setup
warnings, e.g. the config loader's "unknown config key …" and below-range CKM warnings;
lower levels are dropped) → `load_config` → logging (rotating file at `app.log.file`, level from
`app.log.level` or DEBUG with `--debug`, which also mirrors WARN+ to stderr; a redaction
layer rewrites `(?i)\b(pin|password)\s*=\s*\S+` to `${1}=***` (regex crate syntax); file
setup below) → panic hook (`src/panic.rs`: `std::panic::set_hook` with a `Send + Sync` closure that
formats message + location + `std::backtrace::Backtrace::force_capture()` and calls
`r2_core::runtime::record_panic_report`; it never touches the terminal) → ctrlc handler
→ `ensure_legacy_provider()` → IO (`r2_console::io::open_console_io(&cfg)`, §4.9.7) →
`build_provider_registry` → `build_operation_registry(&cfg.custom_mechanisms)` →
`create_template_editor` → `commands::all_commands()` → `AppContext` → banner "r2 {version}
— type 'help' for commands" → `run_repl(&ctx, debug, commands)` → shutdown of every
provider (errors logged as warnings "shutdown of provider {name!r} failed: {message}"). A
ConsoleError before the REPL is written to stderr as "error: {message}" + " (hint:
{hint})" when present, exit code 2. Usage errors are clap's (exit 2; texts §11 D19).

Log file setup (c2 `setup_logging`, binding): (1) `std::fs::create_dir_all(parent)` when
`app.log.file` has a non-empty parent (c2 `log_path.parent.mkdir(parents=True,
exist_ok=True)`), then (2) `OpenOptions::new().create(true).append(true).open(path)` (c2's
`RotatingFileHandler` opens the file at construction). Either failure → Config "cannot
open log file {path}: {err}" ({path} = the expanded `app.log.file`, {err} =
`text::py_os_error_str(err, failing path)`; hint "check app.log.file in the
configuration") — before the subscriber is installed. (3) Rotation is r2-cli's own port
of Python's `RotatingFileHandler` (no rotation crate — file-rotate 0.8 listed the log
directory with `unwrap()` and `assert!`ed on a startup snapshot of the backups, so a
stray or concurrently rotated backup panicked inside the subscriber): before each record,
when `max_bytes > 0`, the base path is a regular file (or absent) and current size + the
record's character count ≥ `max_bytes`, roll over — close; when `backups > 0`, for i =
backups−1 … 1 rename `.i` → `.i+1` if `.i` exists (removing an existing `.i+1` first),
remove `.1` if it exists, rename the base file to `.1`; reopen in append mode (with
`backups == 0` the file just grows). Write errors and rename/remove/open failures are
ignored (a failed open is retried at the next record); nothing in the log path panics.
R7 tests: `max_bytes: 0` and `backups: 0` start and never rotate; the Python rename chain
and rollover-before-write; stray (`r2.log.01`) and concurrently rotated backups; an
unwritable log directory and a log path that is a directory raise the Config error (c2
test_logging_setup.py `test_unwritable_log_path_raises_config_error`), never a panic.

### 4.10 Test contracts

Doubles (unchanged policy): ScriptedIo for every interactive flow; FakeProvider for
console, ops and services tests; FakeBackend only inside `r2-pkcs11`; the contract macro
instantiated for FakeProvider (both presentations), MemoryProvider and Pkcs11Provider on
SoftHSM. `r2-testkit` is a dev-dependency only and depends on `r2-core` + `r2-provider`
(+ openssl for fixtures) and on no other workspace crate. Because r2-core and r2-provider
are its dependencies AND dev-depend on it, their tests that use any testkit item MUST be
integration tests (`crates/r2-core/tests/*.rs`, `crates/r2-provider/tests/*.rs`): inside
those crates' own `cfg(test)` build the testkit's impls target a different copy of the
crate (E0277). Their in-file `#[cfg(test)]` modules use no testkit item (§4.1.1).

#### 4.10.1 `ScriptedIo` and `RecordingEditor` (`r2_testkit::scripted_io`, R1)

```rust
// crates/r2-testkit/src/scripted_io.rs
use secrecy::SecretString;
use r2_core::error::{ConsoleError, Result};
use r2_core::io::{ConsoleIo, Renderable, TemplateEditor}; // + CommandInput for R1's read_command override
use r2_core::params::ParamSpec;
use r2_core::template::KeyTemplate;

/// The project-standard ConsoleIo double (frozen surface).
pub struct ScriptedIo { /* RefCell<VecDeque<String>> answers, RefCell<Vec<…>> output/prompts */ }
impl ScriptedIo {
    /// Sentinel answer: behaves like Ctrl-C at that read.
    pub const CTRL_C: &str = "\u{3}";
    /// Sentinel answer: behaves like Ctrl-D / end of input at that read.
    pub const CTRL_D: &str = "\u{4}";
    pub fn new<I, S>(answers: I) -> Self where I: IntoIterator<Item = S>, S: Into<String> { .. }
    /// No scripted answers (c2 `ScriptedIO([])`; `new([])` cannot infer its types).
    pub fn empty() -> Self { .. }
    /// Every print as `render_plain(r, &RenderConfig::CAPTURE)`; every print_error as
    /// "error: {message}" + " (hint: {hint})" when a hint exists (c2 ScriptedIO format).
    pub fn output(&self) -> Vec<String> { .. }
    /// `output()` joined with "\n".
    pub fn text(&self) -> String { .. }
    /// The raw Renderables passed to print (errors as `error_panel`), in order.
    pub fn renderables(&self) -> Vec<Renderable> { .. }
    /// Every prompt text (`spec.prompt`), secret text, multiline text, select title,
    /// confirm text AND `read_command` prompt ("r2> ", "…> " — c2's REPL read through
    /// `prompt(ParamSpec("command", "c2> "))`, so test_repl.py asserts them), in order.
    pub fn prompts(&self) -> Vec<String> { .. }
    /// Answers not yet consumed.
    pub fn remaining(&self) -> usize { .. }
}
impl ConsoleIo for ScriptedIo { .. }

/// Serializes tests that touch process-global state (the `r2_core::runtime` flags, the
/// process environment, a PKCS#11 module) under plain `cargo test`; hold the guard for the
/// whole test and restore what you changed (§4.1.3 test runner rule). A poisoned lock is
/// recovered (`into_inner`), never a panic.
pub fn global_state_lock() -> std::sync::MutexGuard<'static, ()> { .. }
```

```rust
// crates/r2-testkit/src/env.rs — the ONLY test-side env mutation site (§4.1.3 unsafe budget)
/// Test-only process-environment override (c2 `monkeypatch.setenv`/`delenv`). The caller
/// holds `global_state_lock()` for the whole test (edition 2024: `set_var`/`remove_var` are
/// `unsafe`; the SAFETY argument is that lock plus nextest's process-per-test model).
/// `Some(v)` sets `key` to `v`; `None` removes it. The guard remembers the previous value.
pub fn set_env(key: &str, value: Option<&str>) -> EnvGuard { .. }

/// Restores the variable on drop: the previous value is set again, or the variable is
/// removed when it was absent. Guards drop in reverse creation order (nested overrides of
/// one key restore correctly). Never panics (§4 unwind safety).
#[must_use]
pub struct EnvGuard { /* key: String, previous: Option<std::ffi::OsString> */ }
impl Drop for EnvGuard { .. }
```

Semantics (c2 ScriptedIO): every `prompt`/`prompt_secret`/`prompt_multiline`/`select`/
`confirm`/`read_command` pops the next answer; an exhausted queue **panics** with
"ScriptedIo: answer queue exhausted at {kind}({text:?})" (c2's AssertionError — the test
fails loudly). `select` matches the answer against the option texts, else parses it as a
**0-based** index (out of range / not a number → panic). `confirm`: "y"/"yes" → true,
"n"/"no" → false (trimmed, case-insensitive), "" → default, else panic. Sentinels: `CTRL_C`
→ the method's UserAbort (§4.9.1 texts; `read_command` → `CommandInput::Interrupted`);
`CTRL_D` → UserAbort as well, except `prompt_multiline` (ends the input, returns "") and
`read_command` (`CommandInput::Eof`). `read_command` records its prompt text verbatim
("r2> ", "…> ") in `prompts()`. `prompt_secret` returns the answer as SecretString
(recorded in `prompts()` by prompt text only). Use: keep an `Rc<ScriptedIo>` and put a
clone into `AppContext.io`.

```rust
/// TemplateEditor double: records titles and received templates; returns the template
/// unchanged, or `respond(template)` when built with `with`.
#[derive(Default)]
pub struct RecordingEditor { /* RefCell<Vec<…>>, Option<Box<dyn Fn(KeyTemplate) -> Result<KeyTemplate>>> */ }
impl RecordingEditor {
    pub fn new() -> Self { .. }
    pub fn with(respond: impl Fn(KeyTemplate) -> Result<KeyTemplate> + 'static) -> Self { .. }
    pub fn titles(&self) -> Vec<String> { .. }
    pub fn templates(&self) -> Vec<KeyTemplate> { .. }
}
impl TemplateEditor for RecordingEditor { .. }
```

#### 4.10.2 `FakeProvider` and `FakeHooks` (`r2_testkit::fake_provider`, R3)

```rust
use std::rc::Rc;
use secrecy::SecretString;
use zeroize::Zeroizing;
use r2_core::error::Result;
use r2_core::keys::{KeyInfo, KeyMaterial};
use r2_core::template::KeyTemplate;
use r2_provider::*;

/// The project-wide standard Provider double (frozen surface). Builders are named
/// `with_*` / `starting_*` so they never shadow the `Provider` methods of the same name in
/// method-call syntax (`fake.type_name()` / `fake.mechanisms()` stay the trait calls).
pub struct FakeProvider { /* RefCell state */ }
impl FakeProvider {
    /// type_name "memory", mechanisms = all CANONICAL_MECHANISMS.
    pub fn new(name: &str) -> Self { .. }
    /// Builder: present as another type (copy-flow tests use "pkcs11"). Any type other than
    /// "memory" is login-capable and starts LoggedIn against the synthetic token
    /// TokenInfo{slot_id: 0, label: "{name}-token", manufacturer: "r2", model:
    /// "FakeProvider", serial: "FAKE0001"}.
    pub fn with_type_name(self, type_name: &str) -> Self { .. }
    /// Builder: advertised canonical names (replaces the default set).
    pub fn with_mechanisms<I, S>(self, mechanisms: I) -> Self where I: IntoIterator<Item = S>, S: Into<String> { .. }
    /// Builder: start LoggedOut (login-capable presentations only).
    pub fn starting_logged_out(self) -> Self { .. }
    /// Builder: `list_tokens()` returns these and `as_token_init()` becomes Some (§4.5.2):
    /// init_token(slot, label, …) requires a free token at `slot` (label "" and serial "";
    /// else Provider "no free slot {slot}") and replaces it with TokenInfo{slot_id: slot,
    /// label, manufacturer: "SoftHSM project", model: "SoftHSM v2", serial: 16 lower-case hex
    /// digits of a counter}; set_env_and_reset(key, value) records the call and runs
    /// shutdown() — it never touches the real environment.
    pub fn with_tokens(self, tokens: Vec<TokenInfo>) -> Self { .. }
    /// Builder: install fault-injection / observation hooks (replaces c2's "subclass
    /// FakeProvider in your own test file").
    pub fn with_hooks(self, hooks: Rc<dyn FakeHooks>) -> Self { .. }
    /// Recorded calls, c2's frozen encoding: [method_name, summaries…] (rules below).
    pub fn calls(&self) -> Vec<Vec<String>> { .. }
    pub fn clear_calls(&self) { .. }
    /// The sanctioned twin-fixture backdoor (c2 `_store_key`): stores without the duplicate
    /// guard and without recording a call.
    pub fn store_key_unchecked(&self, material: &KeyMaterial, label: &str, template: Option<&KeyTemplate>, key_id: Option<&[u8]>) -> KeyInfo { .. }
}
impl Provider for FakeProvider { .. }
impl TokenInit for FakeProvider { .. }

/// Per-method overrides. Each method returns None = "not overridden" (the fake's own
/// behavior runs, and records the call) or Some(result) (returned as is; nothing is
/// recorded unless the hook delegates). `next` is a borrowed un-hooked view of the same
/// fake, so a hook can observe and delegate (c2 `super().method(...)`); `next.as_any()`
/// returns the FakeProvider itself. Dispatch rules (c2 virtual-dispatch parity):
/// FakeProvider's own internal calls — `set_env_and_reset` → `shutdown`, capability checks
/// → `mechanisms()` (incl. `supports`), also when they happen inside a `next.*` call — go
/// through the HOOKED surface (a hook overriding `shutdown` sees the shutdown that
/// `set_env_and_reset` triggers); `unwrap_key` stores the unwrapped key through the fake's
/// internal store path (c2 `_store_key`: the duplicate guard runs, no `import_key` call is
/// made or recorded, an `import_key` hook is not consulted); no RefCell borrow is held
/// while a hook or `next` runs.
#[allow(unused_variables)]
pub trait FakeHooks {
    fn initialize(&self, next: &dyn Provider) -> Option<Result<()>> { None }
    fn shutdown(&self, next: &dyn Provider) -> Option<Result<()>> { None }
    fn status(&self, next: &dyn Provider) -> Option<ProviderStatus> { None }
    fn list_tokens(&self, next: &dyn Provider) -> Option<Result<Vec<TokenInfo>>> { None }
    fn login(&self, next: &dyn Provider, token: &TokenInfo, pin: &SecretString, keep_pin: bool) -> Option<Result<()>> { None }
    fn logout(&self, next: &dyn Provider) -> Option<Result<()>> { None }
    fn mechanisms(&self, next: &dyn Provider) -> Option<std::collections::BTreeSet<String>> { None }
    fn list_keys(&self, next: &dyn Provider) -> Option<Result<Vec<KeyInfo>>> { None }
    fn find_key(&self, next: &dyn Provider, selector: &KeySelector) -> Option<Result<KeyInfo>> { None }
    fn import_key(&self, next: &dyn Provider, material: &KeyMaterial, label: &str, template: Option<&KeyTemplate>, key_id: Option<&[u8]>) -> Option<Result<KeyInfo>> { None }
    fn generate_key(&self, next: &dyn Provider, request: &GenerateRequest) -> Option<Result<KeyInfo>> { None }
    fn delete_key(&self, next: &dyn Provider, key: &KeyInfo) -> Option<Result<()>> { None }
    fn export_key(&self, next: &dyn Provider, key: &KeyInfo) -> Option<Result<KeyMaterial>> { None }
    fn encrypt(&self, next: &dyn Provider, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Option<Result<Vec<u8>>> { None }
    fn decrypt(&self, next: &dyn Provider, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Option<Result<Zeroizing<Vec<u8>>>> { None }
    fn sign(&self, next: &dyn Provider, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Option<Result<Vec<u8>>> { None }
    fn verify(&self, next: &dyn Provider, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8], signature: &[u8]) -> Option<Result<bool>> { None }
    fn derive(&self, next: &dyn Provider, key: &KeyInfo, mech: &MechanismInvocation) -> Option<Result<DeriveResult>> { None }
    fn wrap_key(&self, next: &dyn Provider, wrapping_key: &KeyInfo, mech: &MechanismInvocation, target: &KeyInfo, options: &WrapOptions) -> Option<Result<Vec<u8>>> { None }
    fn unwrap_key(&self, next: &dyn Provider, wrapping_key: &KeyInfo, mech: &MechanismInvocation, wrapped: &[u8], request: &UnwrapRequest) -> Option<Result<KeyInfo>> { None }
    fn read_key_template(&self, next: &dyn Provider, key: &KeyInfo) -> Option<Result<KeyTemplate>> { None }
    fn update_key(&self, next: &dyn Provider, key: &KeyInfo, changes: &KeyTemplate) -> Option<Result<KeyEditResult>> { None }
    fn read_full_template(&self, next: &dyn Provider, key: &KeyInfo) -> Option<Result<KeyTemplate>> { None }
    fn init_token(&self, next: &dyn Provider, slot: u64, label: &str, so_pin: &SecretString, user_pin: &SecretString) -> Option<Result<()>> { None }
    fn set_env_and_reset(&self, next: &dyn Provider, key: &str, value: &str) -> Option<Result<()>> { None }
}
```

FakeProvider behavior (binding for R3): R3 ports c2's `tests/support/fake_provider.py`
behavior and texts VERBATIM; the list below is a summary of what other loops' tests rely
on, not an exhaustive restatement.

- Fully in-memory and deterministic. encrypt/decrypt and wrap/unwrap are
  length-preserving reversible XOR-keystream transforms keyed off the stored material
  (keystream = concatenated SHA-256(secret ‖ 0x00 ‖ context ‖ 0x00 ‖ counter_be32),
  truncated), so round-trips work and identical keys give identical "ciphertexts" across
  instances; generated keypairs share one transform secret (encrypt-with-public/
  decrypt-with-private, sign/verify and two-party ECDH pair up). HMAC output lengths per
  hash: sha1 20, sha224 28, sha256 32, sha384 48, sha512 64. `wrap_key`/`unwrap_key` are
  FUNCTIONAL for every advertised wrap mechanism.
- "memory" presentation: NotRequired, login → the trait default UnsupportedOperation, key
  ids stay None when not given. Other presentations: LoggedIn at start; login/logout flip
  state (login while logged in → AlreadyLoggedIn "already logged in", hint "logout first");
  `mechanisms()` is empty while logged out and key/crypto calls → AuthRequired "login
  required: run `login {name}`"; key_id None → a counter-based 4-byte id (1, 2, …, big
  endian), reproducible; `shutdown()` drops to LoggedOut. `list_tokens()`: the synthetic
  token for login-capable presentations, `[]` for "memory" (unless `.with_tokens(..)` was
  given); login stores the given token as the status token.
- import/generate/unwrap honor templates: exportable = CKA_EXTRACTABLE ∧ ¬CKA_SENSITIVE
  (defaults extractable=true, sensitive=false); secret/private `attributes` always carry
  both flags. Handles are a counter starting at 1. find_key via
  `lookup::select_match` (insertion order); the duplicate guard via
  `lookup::duplicate_identity` (certificates exempt; data objects compare class+label);
  DATA/OTHER rules as §4.3. Texts: import of OTHER, or NONE outside DATA → Param "cannot
  import {algorithm} {class} material" (param_name "material"); generate NONE/OTHER →
  Param "cannot generate {algorithm} keys" (param_name "algorithm"); AES/GENERIC without
  size → Param "size_bits is required for {algorithm}"; GENERIC accepts ANY positive
  multiple of 8 (no 8192 cap), else Param "invalid generic secret size {n}; expected a
  positive multiple of 8"; unwrap into NONE/OTHER → Param "cannot unwrap into {algorithm}
  keys" (param_name "result_algorithm"); export of a non-exportable key → KeyNotExportable
  "key '{ref}' is not exportable" (hint "CKA_SENSITIVE/CKA_EXTRACTABLE forbid a plain-value
  read (§5.5)"); `wrap_key` of a target whose CKA_EXTRACTABLE is false → KeyNotExportable
  "key '{ref}' is not extractable and cannot be wrapped" (no hint). A CERTIFICATE passed to
  encrypt/verify/wrap_key resolves to the first other object of these buckets, in order:
  PUBLIC with the same id, PUBLIC with the same label, other non-certificate with the same
  id, other non-certificate with the same label (else the certificate's own record).
- read_key_template returns ONLY CKA_LABEL, CKA_ID (disabled-empty when absent; no row for
  data objects) and the stored CKA_SENSITIVE/CKA_EXTRACTABLE Bool rows — no locked class
  rows. update_key (§5.15): CKA_CLASS/CKA_KEY_TYPE in `changes` → Param "{name} cannot be
  edited after creation"; identity rows always editable (an empty CKA_LABEL → Param
  "CKA_LABEL expects a non-empty string"); CKA_SENSITIVE/CKA_EXTRACTABLE apply on
  secret/private keys (recomputing exportable); any other attr → failed outcome "not
  supported by FakeProvider". read_full_template: symbolic CKA_CLASS/
  CKA_KEY_TYPE rows (no key type for certificate/data) + identity + every stored
  `attributes` entry (kind from CKA_CATALOG, else inferred from the value).
- Call recording (`calls()`): one entry per recorded method, `[method, summaries…]` with
  c2's argument order: `initialize`; `shutdown`; `login(token, "***", keep_pin)`;
  `logout`; `list_keys`; `find_key(label, key_id, key_class, handle)`;
  `import_key(material, label, template, key_id)`; `generate_key(algorithm, size_bits,
  curve, label, key_id, template, public_template)`; `delete_key(key)`; `export_key(key)`;
  `read_key_template(key)`; `read_full_template(key)`; `update_key(key, changes)`;
  `encrypt|decrypt|sign(key, mech, data)`; `verify(key, mech, data, signature)`;
  `derive(key, mech)`; `wrap_key(wrapping_key, mech, target)`; `unwrap_key(wrapping_key,
  mech, wrapped, result_algorithm, result_class, label, key_id, template)`;
  `init_token(slot, label)`; `set_env_and_reset(key, value)`. Not recorded: status,
  mechanisms, supports, list_tokens. Summaries: KeyInfo/KeyRef → `display()`;
  MechanismInvocation → mechanism; byte slices → "{len}B"; KeyMaterial →
  "{algorithm}/{class}:{len}B"; KeyTemplate → "template({n} attrs)"; TokenInfo → label;
  PIN → "***"; None → "None"; bool → "True"/"False"; KeyClass/KeyAlgorithm → `py_name()`;
  Curve → token; integers decimal; strings verbatim.

#### 4.10.3 Provider contract suite (`r2_testkit::contract`, `r2_testkit::fixtures`, R3)

```rust
use std::rc::Rc;
use r2_provider::Provider;

/// Factory handed to every case; called once per case (fresh provider, or a fresh view on
/// a shared token).
pub type MakeProvider<'a> = &'a dyn Fn() -> Rc<dyn Provider>;

/// One `pub fn <case>(make: MakeProvider<'_>)` per c2 ProviderContractTests method, same
/// names (34 cases). A mechanism-dependent case whose mechanism is not advertised returns
/// early after `skip(reason)` (never a failure).
pub mod cases {
    pub fn test_status_token_iff_logged_in(make: super::MakeProvider<'_>) { .. }
    pub fn test_login_rejected_when_not_required(make: super::MakeProvider<'_>) { .. }
    pub fn test_supports_is_consistent_with_mechanisms(make: super::MakeProvider<'_>) { .. }
    pub fn test_import_export_round_trip_secret(make: super::MakeProvider<'_>) { .. }
    pub fn test_imported_key_is_listed_and_found(make: super::MakeProvider<'_>) { .. }
    pub fn test_find_key_not_found(make: super::MakeProvider<'_>) { .. }
    pub fn test_find_key_ambiguity(make: super::MakeProvider<'_>) { .. }
    pub fn test_duplicate_identity_refused(make: super::MakeProvider<'_>) { .. }
    pub fn test_duplicate_identity_guard_exempts_families_and_certs(make: super::MakeProvider<'_>) { .. }
    pub fn test_delete_key(make: super::MakeProvider<'_>) { .. }
    pub fn test_find_key_class_selector_picks_keypair_half(make: super::MakeProvider<'_>) { .. }
    pub fn test_non_exportable_key_refuses_export(make: super::MakeProvider<'_>) { .. }
    pub fn test_pkcs11_secret_attributes_carry_flags(make: super::MakeProvider<'_>) { .. }
    pub fn test_generate_secret_key(make: super::MakeProvider<'_>) { .. }
    pub fn test_generate_keypair_shares_label(make: super::MakeProvider<'_>) { .. }
    pub fn test_encrypt_decrypt_round_trip(make: super::MakeProvider<'_>) { .. }
    pub fn test_sign_verify_round_trip(make: super::MakeProvider<'_>) { .. }
    pub fn test_wrap_unwrap_round_trip_where_supported(make: super::MakeProvider<'_>) { .. }
    pub fn test_certificate_acts_as_public_key(make: super::MakeProvider<'_>) { .. }
    pub fn test_read_key_template_seeds_identity(make: super::MakeProvider<'_>) { .. }
    pub fn test_update_key_renames_key(make: super::MakeProvider<'_>) { .. }
    pub fn test_update_key_duplicate_identity_refused(make: super::MakeProvider<'_>) { .. }
    pub fn test_update_key_leaves_siblings_untouched(make: super::MakeProvider<'_>) { .. }
    pub fn test_update_key_refusal_is_outcome_not_exception(make: super::MakeProvider<'_>) { .. }
    pub fn test_read_full_template_dumps_class_and_identity(make: super::MakeProvider<'_>) { .. }
    pub fn test_generic_secret_round_trip(make: super::MakeProvider<'_>) { .. }
    pub fn test_generate_generic_secret(make: super::MakeProvider<'_>) { .. }
    pub fn test_hmac_sign_verify_round_trip(make: super::MakeProvider<'_>) { .. }
    pub fn test_hmac_needs_a_generic_secret_and_cmac_an_aes_key(make: super::MakeProvider<'_>) { .. }
    pub fn test_generic_secret_wrap_unwrap_where_supported(make: super::MakeProvider<'_>) { .. }
    pub fn test_data_object_round_trip(make: super::MakeProvider<'_>) { .. }
    pub fn test_data_object_identity_and_verbs(make: super::MakeProvider<'_>) { .. }
    pub fn test_certificate_import_list_export_delete(make: super::MakeProvider<'_>) { .. }
    pub fn test_read_full_template_has_no_key_type_for_cert_and_data(make: super::MakeProvider<'_>) { .. }
}
/// Prints "SKIP: {reason}" to stderr (an allowed print site, §4.1.3).
pub fn skip(reason: &str) { .. }
/// Per-case unique label "{prefix}-{8 hex}" (shared-token isolation).
pub fn unique_label(prefix: &str) -> String { .. }

/// Expands to `$(#[$attr])* mod $name { #[allow(unused_imports)] use super::*; #[test] fn
/// test_…() { $crate::contract::cases::test_…(&|| $make) } … }` — one #[test] per case. The
/// `use super::*;` is required: macro item paths are not hygienic, so `$make` resolves
/// inside the generated module and needs the caller's imports (`Rc`, `FakeProvider`,
/// `Provider`).
#[macro_export]
macro_rules! provider_contract_tests {
    ($(#[$attr:meta])* $name:ident, $make:expr) => { /* R3 */ };
}
```

Reuse convention (frozen): each provider loop invokes the macro **in its own test file**:
`provider_contract_tests!(fake_memory, Rc::new(FakeProvider::new("fake")) as Rc<dyn
Provider>);` and `fake_pkcs11` with `.with_type_name("pkcs11")` (R3,
`crates/r2-testkit/tests/contract_fake.rs`); `memory_contract` (R4,
`crates/r2-memory/tests/contract.rs`); `#[cfg(feature = "softhsm")] pkcs11_softhsm` (R5b,
`crates/r2-pkcs11/tests/contract_softhsm.rs`, a logged-in Pkcs11Provider on the fixture
token). R3's case bodies are never edited by other loops.

```rust
// crates/r2-testkit/src/fixtures.rs — generated at test time with OpenSSL, cached per process
pub fn rsa2048_pkcs8() -> Vec<u8> { .. }            // unencrypted PKCS#8 DER
pub fn ec_p256_pkcs8() -> Vec<u8> { .. }
pub fn ed25519_pkcs8() -> Vec<u8> { .. }
/// Self-signed cert (CN = cn, SHA-256 / Ed: no digest, BasicConstraints CA:FALSE, notBefore
/// = now − 1 day, 3650 days) for the given PKCS#8 key; DER.
pub fn self_signed_cert(pkcs8: &[u8], cn: &str) -> Vec<u8> { .. }
/// (PKCS#8, cert) of the contract suite's RSA key, CN "r2-contract".
pub fn rsa_pkcs8_and_cert() -> (Vec<u8>, Vec<u8>) { .. }
```

#### 4.10.4 `FakeBackend` (`r2_pkcs11::backend::fake`, crate-private, R5a)

Location `crates/r2-pkcs11/src/backend/fake.rs`, compiled only under `#[cfg(test)]`; the
tests using it are the in-crate modules `crates/r2-pkcs11/src/tests/*.rs` (§4.1.1). A port
of c2's `fake_pykcs11.py` behind the §4.5.6 seam (there is no `fake-backend` feature: a
crate-private double is useless to other crates and to `tests/*.rs`):

```rust
// crates/r2-pkcs11/src/backend/fake.rs (cfg(test))
use secrecy::SecretString;
use zeroize::Zeroizing;

use super::{BResult, Backend, MechSpec, RawAttr, RawTokenInfo, UserKind};

pub(crate) struct FakeBackend { /* RefCell state */ }
impl FakeBackend {
    /// One slot 0 holding an initialized token (label "fake-token", serial "FAKE0001",
    /// user PIN "1234", SO PIN "4321") and DEFAULT_MECHANISMS.
    pub(crate) fn new() -> Self { .. }
    /// Replace the slot set: (slot id, token info, mechanism codes).
    pub(crate) fn with_slots(slots: Vec<(u64, RawTokenInfo, Vec<u64>)>) -> Self { .. }
    /// Inject `rv` for the next call of the named Backend method (e.g. "login",
    /// "unwrap_key"); `fail_always` for every call until cleared.
    pub(crate) fn fail_next(&self, method: &'static str, rv: u64) { .. }
    pub(crate) fn fail_always(&self, method: &'static str, rv: u64) { .. }
    pub(crate) fn clear_failures(&self) { .. }
    /// The next session-bound call fails with CKR_SESSION_HANDLE_INVALID (auto-recovery tests).
    pub(crate) fn invalidate_session(&self) { .. }
    /// Attribute types that C_SetAttributeValue refuses with CKR_ATTRIBUTE_READ_ONLY
    /// (CKA_SENSITIVE true→false / CKA_EXTRACTABLE false→true one-direction rules are built in).
    pub(crate) fn set_read_only(&self, attrs: &[u64]) { .. }
    /// Backend method names called, in order.
    pub(crate) fn calls(&self) -> Vec<&'static str> { .. }
    /// Stored objects: (handle, attribute map) — copies for assertions (test-only data).
    pub(crate) fn objects(&self) -> Vec<(u64, std::collections::BTreeMap<u64, Vec<u8>>)> { .. }
    /// The last MechSpec handed to a crypto call (packer tests).
    pub(crate) fn last_mechanism(&self) -> Option<MechSpec> { .. }
}
impl Backend for FakeBackend { .. }
/// SoftHSM-like CKM set (c2 fake_pykcs11 DEFAULT_MECHANISMS, as codes; numeric order).
pub(crate) const DEFAULT_MECHANISMS: &[u64] = &[
    0x0000, // CKM_RSA_PKCS_KEY_PAIR_GEN
    0x0001, // CKM_RSA_PKCS
    0x0003, // CKM_RSA_X_509
    0x0009, // CKM_RSA_PKCS_OAEP
    0x000D, // CKM_RSA_PKCS_PSS
    0x0040, // CKM_SHA256_RSA_PKCS
    0x0043, // CKM_SHA256_RSA_PKCS_PSS
    0x0221, // CKM_SHA_1_HMAC
    0x0251, // CKM_SHA256_HMAC
    0x0256, // CKM_SHA224_HMAC
    0x0261, // CKM_SHA384_HMAC
    0x0271, // CKM_SHA512_HMAC
    0x0350, // CKM_GENERIC_SECRET_KEY_GEN
    0x1040, // CKM_EC_KEY_PAIR_GEN
    0x1041, // CKM_ECDSA
    0x1044, // CKM_ECDSA_SHA256
    0x1050, // CKM_ECDH1_DERIVE
    0x1055, // CKM_EC_EDWARDS_KEY_PAIR_GEN
    0x1057, // CKM_EDDSA
    0x1080, // CKM_AES_KEY_GEN
    0x1081, // CKM_AES_ECB
    0x1082, // CKM_AES_CBC
    0x1085, // CKM_AES_CBC_PAD
    0x1086, // CKM_AES_CTR
    0x1087, // CKM_AES_GCM
    0x108A, // CKM_AES_CMAC
    0x2109, // CKM_AES_KEY_WRAP
    0x210A, // CKM_AES_KEY_WRAP_PAD
];
```

SoftHSM-flavored behavior (c2 verified): imported/generated keys default
CKA_SENSITIVE=false, CKA_EXTRACTABLE=false unless the template says otherwise; CKA_VALUE
reads return None unless extractable and not sensitive; one-shot encrypt of empty input
fails (multi-part works); OAEP accepts SHA-1/MGF1-SHA1 with an empty label only
(CKR_ARGUMENTS_BAD otherwise); CKA_KEY_GEN_MECHANISM of imported objects reads as
CK_UNAVAILABLE_INFORMATION; `find_objects` returns matches in creation order (list_keys
order tests, §4.5.2); objects may be created with a zero-length CKA_ID (R5a test: it lists
and resolves with `key_id == None`, §4.3). Tests share the backend via
`Rc<FakeBackend>` (cloned into `Pkcs11Provider::with_backend` as `Rc<dyn Backend>`).

#### 4.10.5 SoftHSM fixture (`r2_testkit::softhsm`, R0) and `scripts/softhsm-init.sh`

SoftHSM tests compile only with cargo feature `softhsm` and **fail** (never skip) when the
fixture environment is missing — stricter than c2's skip + `--softhsm-required` (n/a).
The token is initialized by `scripts/softhsm-init.sh` BEFORE the test process starts, so
tests never mutate the environment.

```rust
// crates/r2-testkit/src/softhsm.rs (the whole file; lib.rs declares
// `#[cfg(feature = "softhsm")] pub mod softhsm;`)
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SofthsmToken {
    pub module_path: PathBuf,
    pub slot: u64,
    /// "R2TEST"
    pub token_label: String,
    /// "1234"
    pub user_pin: String,
    /// "4321"
    pub so_pin: String,
    /// $SOFTHSM2_CONF of the shared token.
    pub conf_path: PathBuf,
}

/// Read once (OnceLock) from the environment: SOFTHSM2_CONF, R2_TEST_SOFTHSM_MODULE,
/// R2_TEST_SOFTHSM_SLOT, R2_TEST_SOFTHSM_LABEL, R2_TEST_SOFTHSM_USER_PIN,
/// R2_TEST_SOFTHSM_SO_PIN. Any missing/invalid → panic "SoftHSM fixture not initialized:
/// run `eval \"$(scripts/softhsm-init.sh)\"` (missing {VAR})".
pub fn softhsm_token() -> &'static SofthsmToken { .. }

/// Per-test unique CKA_LABEL "r2test-{12 hex}". Drop deletes objects created under it,
/// best effort, via `pkcs11-tool --module … --token-label … --login --pin … --delete-object
/// --type {secrkey|privkey|pubkey|cert|data} --label …` (≤ 8 per type; silently skipped
/// when pkcs11-tool is absent). Uniqueness alone isolates tests.
pub struct UniqueLabel { /* label */ }
impl UniqueLabel { pub fn as_str(&self) -> &str { .. } }
impl std::ops::Deref for UniqueLabel { type Target = str; fn deref(&self) -> &str { .. } }
impl Drop for UniqueLabel { fn drop(&mut self) { .. } }
pub fn unique_label() -> UniqueLabel { .. }
```

`scripts/softhsm-init.sh [DIR] [--github-env]` contract: creates DIR (default `mktemp
-d`) with `DIR/tokens` and `DIR/softhsm2.conf` ("directories.tokendir = DIR/tokens",
"objectstore.backend = file", "log.level = ERROR"); locates the module via
`$SOFTHSM2_LIB` or the §7 `softhsm.search_paths` probe list; runs `softhsm2-util
--init-token --free --label R2TEST --so-pin 4321 --pin 1234` with that SOFTHSM2_CONF;
determines the slot from "reassigned to slot N" (fallback: `--show-slots`, the slot whose
Label is R2TEST); prints `export VAR=value` lines (shell-quoted) for SOFTHSM2_CONF and the
five R2_TEST_SOFTHSM_* variables, or appends `VAR=value` lines to `$GITHUB_ENV` with
`--github-env`; exits non-zero with a message on stderr when SoftHSM, softhsm2-util or the
slot cannot be found, and when `DIR/tokens` already exists and is not empty (a second
R2TEST token in one store would make the slot ambiguous). CI: `eval "$(scripts/softhsm-init.sh)"` then `cargo nextest run
--workspace --features softhsm`. `.config/nextest.toml` puts every test whose name contains
`softhsm` into a test group with `max-threads = 1` (shared token; R0 may relax once
verified). Wizard e2e tests spawn the binary with their own fresh SOFTHSM2_CONF.

#### 4.10.6 Console test support (`r2_console::testing`, R7)

`#[cfg(test)] pub(crate) mod testing` in `crates/r2-console/src/testing.rs`, used by the
in-crate console test modules `crates/r2-console/src/tests/*.rs` of every console loop
(R7–R11, R14, R15). `r2-testkit` is a dev-dependency of r2-console (no cycle: r2-testkit
never depends on r2-console).

```rust
// crates/r2-console/src/testing.rs
use std::path::PathBuf;
use std::rc::Rc;
use indexmap::IndexMap;
use r2_config::model::{AppConfig, LoadedConfig};
use r2_core::io::{ConsoleIo, TemplateEditor};
use r2_provider::ProviderRegistry;

use crate::context::AppContext;
use crate::repl::Flow;

/// DEFAULTS_YAML deep-merged with `overrides_yaml` (§4.8 rules); panics on a config error.
pub fn make_config(overrides_yaml: Option<&str>) -> AppConfig { .. }
/// origins None → every CONFIG_SECTIONS entry "default".
pub fn make_loaded(config: AppConfig, source_path: Option<PathBuf>, origins: Option<IndexMap<String, String>>) -> LoadedConfig { .. }
/// "mem" = FakeProvider (memory) holding AES key "aeskey" (16 × 0x01); "hsm" =
/// FakeProvider presenting "pkcs11" (logged in, empty).
pub fn make_providers() -> ProviderRegistry { .. }

/// Fully wired AppContext over doubles (c2's per-file `make_ctx` helpers, consolidated).
pub struct CtxBuilder { /* … */ }
impl CtxBuilder {
    /// Defaults: make_config(None), make_providers(), build_operation_registry(custom),
    /// create_template_editor(io, &config), origins all "default", no source path.
    pub fn new(io: Rc<dyn ConsoleIo>) -> Self { .. }
    pub fn config(self, config: AppConfig) -> Self { .. }
    pub fn providers(self, providers: ProviderRegistry) -> Self { .. }
    pub fn source_path(self, path: PathBuf) -> Self { .. }
    pub fn origins(self, origins: IndexMap<String, String>) -> Self { .. }
    pub fn editor(self, editor: Rc<dyn TemplateEditor>) -> Self { .. }
    pub fn build(self) -> Rc<AppContext> { .. }
}

/// `repl::dispatch(ctx, &all_commands()?, line)` — tokenize, bind and run exactly as the
/// REPL, without rendering (c2's per-file `_run` helpers).
pub fn run_line(ctx: &AppContext, line: &str) -> r2_core::Result<Flow> { .. }
```

### 4.11 Contract-change procedure & frozen-provisional list

#### 4.11.1 Procedure

A loop that must change §4:

1. Updates spec §4 **in its own branch**, in the same commit/PR as the code (a direct
   commit to `main` is allowed when the loop's merge itself is a commit; the change and
   its rationale are in the commit message), stating the change and the affected merged
   loops.
2. Makes only the minimal mechanical call-site fixes in foreign files (the sole ownership
   exception besides R13), including the R0 skeleton items of not-yet-merged loops.
3. Records the deviation in its `loops.md` STATUS row, and adds/updates the affected
   `parity/ledger.csv` rows it owns.

New third-party dependencies, new crate edges (§4.1.2), new `unsafe` sites (§4.1.3) and
new allowed threads are §4 changes.

#### 4.11.2 Frozen-provisional (expected to wobble; same procedure, without drama)

`Provider::wrap_key`/`unwrap_key` signatures and `WrapOptions`/`UnwrapRequest` (the
`WrapOptions` struct is the escape hatch), `DeriveResult`, `read_key_template`/
`update_key`/`read_full_template` and `AttrEditOutcome`/`KeyEditResult` (§5.15/§5.16),
`CustomMechanismConfig` param encoding (v1 = the five `ParamStruct` packers), the
`ConsoleIo`/`TemplateEditor` trait surfaces (incl. the provisional `busy` and the
spinner flag in `runtime`), the `FakeHooks` trait (methods may be added with a `None`
default), and the R7-internal terminal I/O items of §4.9.7.

#### 4.11.3 c2 §4 coverage map (every c2 §4 item has an r2 counterpart or an n/a)

| c2 §4 item | r2 |
|---|---|
| §4.1 package/module map, file→loop | §4.1 (crates, files, owners, handoffs) |
| `core/errors.py` hierarchy, constructor shape | `ConsoleError` + `ErrorKind` + per-kind constructors (§4.2) |
| `ReplExit` | `Flow::Exit` + `CommandInput::Eof` (§4.9.5) |
| `KeyClass`/`KeyAlgorithm`/`KeyRef`/`KeyInfo`/`KeyMaterial` | §4.3 (curve strings → `Curve`) |
| `ParsedRef`, `parse_ref`, `CLASS_SELECTORS`, `CLASS_TOKENS`, `display_refs` | §4.3 (`CLASS_TOKENS` → `KeyClass::token`) |
| `handle_int` | n/a — Python-only (`KeyInfo.handle: Option<u64>`) |
| `codec.py` `InputFormat`/`decode_data`/`format_hex` | §4.4.1 |
| `keyparse.parse_key_material` | §4.4.3 (`hint: str` → `KeyHint`, `password_cb` → `PasswordCallback`) |
| `x509build` (self-signed, `SignatureAlg`, `build_csr`, `build_pkcs12`) | §4.4.4 |
| `datainput` `DataInput`/`DataOutput` | §4.4.2 (`Literal` formats → `InFormat`/`OutFormat`) |
| `providers/base.py` types + `Provider` ABC + `rsa_raw_modexp` | §4.5.1–§4.5.3 (`options: dict` → `WrapOptions`, kwargs → `GenerateRequest`/`UnwrapRequest`, `find_key` args → `KeySelector`) |
| `ProviderRegistry` | §4.5.3 |
| `MemoryProvider.__init__`, `Pkcs11Provider.__init__`/`init_token`, `find_softhsm_module`, `CKA_CATALOG` | §4.5.5 (+ `TokenInit`) |
| `core/params.py` `Verb`/`ParamKind`/`ParamSpec` | §4.6.1 (+ `ParamValue`, `Params`, `ParamStruct`) |
| `OperationSpec`, `OperationRegistry`, `register_builtins`, `ParamResolver`, custom mechanisms, canonical names, folding, built-in table | §4.6 |
| `AttrKind`/`TemplateAttr`/`KeyTemplate`, conversion rules | §4.7 (`value: object` → `AttrValue`) |
| `load_config`, `LoadedConfig`, `AppConfig` + sections, `default_template`, `template_class_key`, `ParamSpecConfig`, `CustomMechanismConfig`, `CustomAttributeDef` | §4.8 |
| `ConsoleIO`/`TemplateEditor` Protocols, `create_template_editor` | §4.9.1, §4.9.3 |
| lazy `importlib` editor wiring / `_IdentityTemplateEditor` | n/a — direct construction; `IdentityTemplateEditor` is the R0 stub (§4.9.3) |
| `AppContext` (incl. `log`) | §4.9.4 (`log` → n/a, `tracing`) |
| `BoundArgs`, `Command`, tokenizer/binding rules | §4.9.6–§4.9.7 (`ClassVar`s → trait methods, `run → None` → `Result<Flow>`) |
| `pkgutil` auto-discovery, `COMMANDS` lists | `build.rs` + `pub fn commands()` per module (§4.9.6) |
| `--debug` as a parameter | `run_repl(ctx, debug, …)` (§4.9.5) |
| wizard `run_softhsm_wizard`/`token_needs_init`/`TokenInitProvider` | §4.9.9 (+ `Provider::as_token_init`) |
| `ScriptedIO` | `ScriptedIo` (§4.10.1) |
| `FakeProvider` + subclass-based fault injection | `FakeProvider` + `FakeHooks` (§4.10.2) |
| `ProviderContractTests` + `make_provider` | `provider_contract_tests!` (§4.10.3) |
| `fake_pykcs11.py` + `install(monkeypatch)` | `FakeBackend` (§4.10.4) |
| `softhsm_token` fixture, `unique_label`, `--softhsm-required` option, root conftest | §4.10.5 (cargo feature `softhsm`; the pytest option is n/a) |
| per-file console test helpers (`make_ctx`, `_run`/`run_session`, not in c2 §4) | consolidated as `r2_console::testing` (§4.10.6, r2 addition) |
| §4.11 procedure + frozen-provisional list | §4.11 |

## 5. Functional requirements

Verification-status flags used below: **[V]** verified against current sources during
design (c2), and — where the text says "S0" — re-verified for r2 against cryptoki 0.12.1,
OpenSSL 3.0.13 (system) / 3.6.3 (vendored) and SoftHSM 2.6.1 / 2.7.0 by the S0 spikes;
**[S]** stable PKCS#11 v3.0 / OpenSSL knowledge — CKM/CKG/CKK/CKR numerics come from
`cryptoki-sys` constants (resolved at compile time; c2 resolved them at runtime from
`PyKCS11.CKM/CKG/CKK`), never hand-typed (deliberate exceptions: the static `CKA_CATALOG`
in `r2_core::catalog`, a literal table so that `r2-testkit`/`r2-console` may use it; the
CKO/CKK/CKC/CKM/CKR name tables of `r2_pkcs11::catalog`, which are PyKCS11 1.5.18's
dictionaries committed as data, §4.5.5; and config-supplied vendor codes);
**[U]** provider-dependent — implement best-effort with capability probing.

**Message texts (binding).** Every user-visible message, hint and prompt of c2@408d6f2 —
whether quoted in this section or present only in c2's source and asserted by its tests —
is reproduced verbatim, with `c2` → `r2` only where the text names the tool (§11 D7). Where
c2 renders a value with Python's `{x!r}`, r2 renders exactly CPython 3.12's `repr(str)`
(`repr(bytes)` for byte values) through `r2_core::text::py_repr` / `py_bytes_repr`
(§4.2 — including the `\xNN`/`\uNNNN` escaping of every non-printable code point). Where
c2 appends a library exception text after its
own prefix (`AES key unwrap failed: {exc}`), r2 appends the OpenSSL / cryptoki equivalent
(§11 D11), except for the pre-validated cases listed in §5.8, which keep pyca's exact text.

**Backend vocabulary.** "cryptoki" = `cryptoki =0.12.1` + `cryptoki-sys =0.5.0`;
"RawFns" = the `r2-pkcs11` raw shim (§3.1); "openssl" = the `openssl` crate ≥ 0.10.81. The
constructions named in the PKCS#11 columns below are the normative MechSpec → cryptoki
mapping verified by the S0 cryptoki spike; those in the memory columns are the normative
OpenSSL mapping verified by the S0 OpenSSL spike.

### 5.1 Console UX

REPL: `r2> ` prompt; on start r2 prints `r2 <version> — type 'help' for commands`. The
command line is read through the console-internal `LineReader` of the active `ConsoleIo`
(TerminalIo or PlainIo; the mode switch is in §6):

- **TerminalIo** — a reedline `Reedline` command editor configured with:
  - **history:** `SecretFilteringHistory` over
    `FileBackedHistory::with_file(1000, app.history_file)`. The parent directory is created
    first; an unusable path falls back to an in-memory `FileBackedHistory::new(1000)` (a bad
    history path never blocks startup). reedline writes only on `sync()`, so the reader
    calls `sync_history()` after every `read_command` and the file is current while r2 runs
    (c2's `FileHistory` appended immediately).
  - **hints:** `DefaultHinter` in dark gray — the `AutoSuggestFromHistory` equivalent
    (prefix search over the same filtered history). Right/End/Ctrl-E/Ctrl-F accept the
    whole hint, Alt-F/Ctrl-Right/Alt-Right one word.
  - **bracketed paste** on (`use_bracketed_paste(true)`). Un-bracketed pastes (Windows
    consoles, terminals without the mode) arrive as keystrokes and yield byte-identical
    buffers through the validator below.
  - **grammar-aware completion, on Tab only** (c2: `complete_while_typing=False`):
    `BridgeCompleter` feeding an `IdeMenu` dropdown named `completion_menu` (no marker,
    bordered). Tab opens the menu or moves to the next entry, Shift-Tab to the previous
    one; Enter in an open menu accepts the selection without submitting the line; a single
    candidate is inserted directly (`with_quick_completions(true)`) and a common prefix
    partially (`with_partial_completions(true)`). Candidates: command names, provider
    names, `provider:label` refs, mechanism cli-names filtered by `available_for()`,
    `param=` names, ENUM choices, and filesystem paths for file options (`--in`, `--out`,
    `--sig-file`, `load --file`, export/csr/`key template` paths, `--template`; the menu
    shows the last path component, the inserted value is the full token); `export --cert`
    completes refs. Completion never appends a trailing space (prompt_toolkit parity).
  - **highlighting** via `BridgeHighlighter` (an r2 addition, §11 D9): known command green
    bold, unknown command red, `provider:` refs with a registered provider prefix cyan,
    `--option` blue, `name=value` magenta, quoted strings (including a still-open quote)
    yellow, each token classified as the binder binds it (an option's value is never
    `--option`/`name=value`, §4.9.7). `with_ansi_colors` follows the §6 color policy, so `ui.color: never` and
    `NO_COLOR` govern the editor too.
  - `QuoteValidator` (multi-line, below) and reedline's default emacs keybindings.
- **PlainIo** — writes the prompt, reads one line from stdin and echoes it when stdin is
  not a terminal (§6); it keeps the same command history file as TerminalIo, one logical
  entry per command (§4.9.7, D7).

Unterminated quotes keep the buffer open with a `…> ` continuation prompt (paste a PEM
across lines). In TerminalIo the `QuoteValidator` returns `Incomplete` exactly while
`!line_is_complete(buffer)`: Enter inside an open quote inserts a newline and reedline
draws `…> ` on each continuation row, so the buffer it returns is always complete.
`run_repl` keeps c2's own loop — `while !line_is_complete(buffer) { buffer += "\n" +
read_command("…> ") }` — which is the continuation mechanism for PlainIo and ScriptedIo
and a no-op for TerminalIo; both paths hand the dispatcher the identical buffer (S0: a
28-line PEM arrives byte-identical through bracketed paste, keystroke paste and pipe).

Lines containing `--pin` or `--password` are **not** persisted to history:
`SecretFilteringHistory::save` answers `Ok(HistoryItem { id: None, .. })` for them (never
`Err` — reedline `.expect()`s the result), `update` re-checks the edited line, and because
the hinter and Up-arrow search the same history object such lines are never offered as
hints or recalls either. (§11 D8 records the open decision on also filtering inline key
material.) Param, select, confirm and multiline (`| `) answers are read by a second
reedline instance with its own in-memory history (`FileBackedHistory::new(100)`; Up
recalls earlier answers within the session, as c2's param session did), a
`ChoiceCompleter` for ENUM/BOOL choices (opened with Tab; c2 completed while typing — §11
D9), the same menu, a plain highlighter, no hinter/validator, and bracketed paste ON (a
pasted block — newlines and blank lines included, e.g. a traditional encrypted PEM at the
`| ` prompt — arrives as one answer, as in c2); answers never enter the command history.
Secrets never enter any history.

Full command grammar:

```
help [<command>]
exit | quit                       # Ctrl-D at top prompt = exit (with provider shutdown)
clear
config show [--defaults | --origin]
config path

providers                         # table: name, type, library, auth state, token label/serial
slots <provider>                  # tokens of a PKCS#11 provider
login <provider> [<token-label> | --slot <n>] [--pin <pin>] [--keep-pin]
                                  # PIN prompted hidden if omitted; --keep-pin: §5.2
logout <provider>

keys [<provider>] [<filter>]      # table: ref, class (secret/private/public/cert/data), algorithm
                                  # (incl. generic, `-` for data, `other` for unmodelled types),
                                  # size/curve, exportable — every object the provider lists
                                  # <filter>: case-insensitive substring of the displayed ref;
                                  # a lone arg that isn't a provider name filters all browsable providers
key info <provider>:<label>[#<id-hex>][:<class>]
                                  # every <provider>:<label> ref in this grammar accepts the full
                                  # §4.3 form [#<id-hex>][:<class>][@<handle>]; `keys` and ref
                                  # completion suffix colliding displays the same way; `key info`
                                  # lists the family's other objects as `related:` qualified refs
key edit <provider>:<label>[#<id-hex>][:<class>] [--label <l>] [--id <hex>]
                                  # §5.15: flags → direct rename; no flags: pkcs11 → attribute
                                  # editor seeded from the object, memory → label/id prompts
key template <provider>:<label>[#<id-hex>][:<class>] <path>
                                  # §5.16: dump the COMPLETE attribute template to a
                                  # class-keyed YAML file; pkcs11 providers only
generate <provider> <aes|rsa|ec|generic> [size=<bits>] [curve=<name>] [--label <l>] [--id <hex>]
         [--template <path>]      # --template: §5.16 file seeds the editor(s);
                                  # generic: size = any multiple of 8 (default 256)
load <provider> <aes|rsa|ec|cert|generic|data|auto> <data> [--label <l>] [--id <hex>]
     [--template <path>]                       # generic/data: bytes stored verbatim (§5.4)
load <provider> --file <path> [--format auto|aes|rsa|ec|cert|generic|data] [--password <pw>]
                [--label <l>] [--id <hex>] [--template <path>]
                                               # --format = key-type hint (§4.4);
                                               # container (pem/der/p12/…) is auto-sniffed
load <provider> <aes|rsa|ec|generic> [<data>] --kek <label>[#<id-hex>][:<class>] [--mech <name>]
     [<name>=<value> ...] [--label <l>] [--id <hex>] [--template <path>]
load <provider> <aes|rsa|ec|generic> --file <path> --kek <label>[…] [--mech <name>]
     [<name>=<value> ...] [--label <l>] [--id <hex>] [--template <path>]
                                               # wrapped-blob load (§5.4): the KEK is
                                               # resolved INSIDE the target provider
                                               # (C_UnwrapKey semantics)
copy <src-provider>:<label> <dst-provider> [--label <l>] [--id <hex>] [--template <path>]
export <provider>:<label> <path> [--format auto|raw|der|pem|p12] [--public]
       [--cert <provider>:<label>] [--password <pw>]           # --cert/--password: p12 only
export <provider>:<label> <path> --kek <label>[#<id-hex>][:<class>] [--mech <name>]
       [<name>=<value> ...] [--outformat raw|hex|b64]
                                  # wrapped export (§5.6): the blob `load --kek` consumes
csr <provider>:<label> <path> [--subject "<DN>"] [--hash sha256|sha384|sha512]
delete <provider>:<label>         # confirmation per ui.confirm_delete

ops [<provider>] [--key <provider>:<label>]
encrypt <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>]
        [--out <path>] [--outformat raw|hex|b64]
decrypt <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>]
        [--out <path>] [--outformat raw|hex|b64]
sign    <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>]
        [--out <path>] [--outformat raw|hex|b64]
verify  <provider>:<label> [<mech>] [<name>=<value> ...] [<data>] [--in <path>]
                           (--sig <data> | --sig-file <path>)
derive  <provider>:<label> [<mech>] [<name>=<value> ...] [--out <path>]
        [--outformat raw|hex|b64]
```

Interactive fallbacks (all through `ParamResolver`/`ConsoleIo` — never a second code
path): omitted `<mech>` → `select()` over `available_for(verb, key, provider)`; omitted
`<data>` with no `--in` → multiline paste prompt; missing `name=value` params → prompted
in ParamSpec order; `load`/`copy`/`generate` into PKCS#11 → template editor (§5.12).
`verify` on a ref that resolves to a PRIVATE key uses the co-located PUBLIC (preferred) or
CERTIFICATE object sharing its label (and CKA_ID when the ref carries one) — there is no
ref grammar for a keypair's public half, and verify operations bind to
`{PUBLIC, CERTIFICATE}` (§4.6); with no co-located object the private resolution stands
and the ordinary capability errors apply (c2 L13 fold-back). Positional disambiguation for
crypto verbs: positional 1 must parse as a key ref; positional 2 is a mechanism iff it is
**unquoted** (`BoundArgs.positional_quoted`, §4.9) and matches `resolve_cli()` for that
key, else it is data — so quoting data forces it as data, and mech-name-shaped strings
aren't valid hex/base64 anyway. Completion never triggers a PKCS#11 library load (§6):
`provider:label` refs complete only for memory and logged-in providers; logged-out or
unavailable providers complete just the `provider:` prefix. Refs complete through the §4.3
selector stages: at the label stage the menu is exactly the `keys`-table refs; once a full
label is typed the `#<id-hex>` and `:<class>` continuations are offered, unambiguous forms
only (a candidate matching several keys is kept just for a distinct-class family, per the
§4.3 `find_key` collapse rule).

Completion mechanics (r2): reedline passes byte offsets; a `Suggestion`'s span runs from
the start of the raw token under the cursor (`Token.start`, including an opening quote) to
the cursor, or is empty at the cursor when a new token starts (this also fixes c2's
`start_position = -len(cursor_token)` miscount after a just-closed quoted token, §11 D9).
Nothing is completed while the text before the cursor is not `line_is_complete` (no
completion inside an open quote). `Command::complete` keeps returning full replacement
tokens. Completion and highlighting never call `ctx.io` and never surface an error: any
`ConsoleError` inside them yields no suggestions / unstyled text.

Results default to a hex dump on the console (`ui.hex_group`/`hex_width`; a panel titled
with what the bytes are and subtitled `<n> bytes`, or `(empty — 0 bytes)` with no subtitle;
`format_hex` is a verbatim port of c2's and the panel is byte-identical to c2/rich at 80
columns); `--out` writes raw bytes unless `--outformat hex|b64` is given. Errors: a panel
titled `error` with a red border, the message in bold red and a dim `hint: …` line;
unknown command/mechanism gets difflib suggestions (hint `did you mean: <a>, <b>, <c>` — at
most 3, exactly CPython's `difflib.get_close_matches` with its default cutoff, including its
tie order (equal ratios → candidate descending): `r2_core::text::close_matches`, §4.2 — the
`difflib` crate's own `get_close_matches` orders ties differently and is not used; an
unknown command without close matches gets
`type 'help' for the command list`); parse errors echo the offending physical line of the
buffer with a caret at `ParseError.pos` before the error panel (`pos` is a byte offset; the
caret column is the display width of the text before it, §11 D14); Ctrl-C in any flow →
single line `Aborted.`; unexpected failures — a panic inside a command, caught per dispatch
by `catch_unwind` (the panic hook logs message, location and backtrace) — → error panel
`unexpected error: <detail>` with hint `details logged to <app.log.file>`; `--debug` prints
the captured backtrace before the panel (c2: the Python traceback; §11 D4).

Ctrl-C / Ctrl-D / EOF (binding; TerminalIo keys, PlainIo end-of-input):

| where | input | effect |
|---|---|---|
| `r2>` | Ctrl-C | buffer discarded, `Aborted.`, re-prompt |
| `r2>` | Ctrl-D on an empty buffer; EOF on stdin | leave the REPL (provider shutdown), exit status 0 |
| `r2>` / `…>` | Ctrl-D on a non-empty buffer | delete-char (reedline emits no signal); keep editing |
| `…>` continuation | Ctrl-C | the whole multi-line buffer is aborted: `Aborted.` |
| `…>` continuation (PlainIo) | EOF | leave the REPL, as at `r2>` |
| param / select / confirm / secret prompt | Ctrl-C, Ctrl-D, EOF | `UserAbort` with c2's messages — `aborted while entering '<name>'`, `aborted secret input`, `selection aborted`, `confirmation aborted` — rendered by the REPL as `Aborted.` |
| multiline paste prompt (`\| `) | Ctrl-C; Ctrl-D, EOF | Ctrl-C → `UserAbort` (`aborted multiline input`); Ctrl-D / EOF → ends the paste like an empty line |
| while a command runs | Ctrl-C | the `ctrlc` handler sets the abort flag; commands/services check it at step boundaries and stop with `Aborted.` (§6, §11 D13) |
| any prompt of PlainIo with stdin a terminal (`TERM=dumb`, stdout redirected, a degraded TerminalIo) | Ctrl-C | the tty discards the partial line and the handler sets the flag; at the next Enter the line is discarded and the read reports Interrupted (`Aborted.` / UserAbort as above) — §11 D2 |
| any prompt of PlainIo with stdin NOT a terminal (pipe, file) | SIGINT | the read reports Interrupted (`Aborted.` / UserAbort as above) once data arrives (or at once when the flag was already set); the line read is not lost but returned by the next read (§4.9.7) |

reedline signals map as `Signal::Success(s)` → line, `Signal::CtrlD` → EOF (reedline emits
it only for an empty buffer), `Signal::CtrlC` and anything else → interrupted; rpassword's
`ErrorKind::Interrupted` → interrupted and `UnexpectedEof` → EOF.

Other console commands (shipped behavior, verbatim texts): `clear` writes the clear-screen
sequence whenever the output sink is not Plain — rich's `Console.clear()` rule: stdout a
terminal (or forced by `ui.color: always`, `FORCE_COLOR`, `TTY_COMPATIBLE=1`) and `TERM`
not dumb/unknown — in TerminalIo and PlainIo alike (§4.9.7), and nothing otherwise. `config path` prints `config file: <path>`, or
`config file: (none — running on built-in defaults)` followed by
`discovery order: --config PATH, $R2_CONFIG, ./r2.yaml, <user config dir>/r2/r2.yaml`
(c2's line with r2 names, §11 D7). `config show` prints the effective configuration as YAML
byte-identical to c2's PyYAML `safe_dump(sort_keys=False, default_flow_style=False)` output
(the §4.8.4 emitter port; `templates.pkcs11` values and custom-mechanism param defaults
are printed from the raw YAML mirrors exactly as written, §4.8.3); `config show --defaults` prints the embedded `defaults.yaml` (§7) verbatim, without
going through the loader; `config show --origin` prints the `config origins` table
(`section`, `origin`); `--defaults` and `--origin` together → `--defaults and --origin are
mutually exclusive`.

### 5.2 Provider management, PKCS#11 sessions & login

`providers` lists every configured provider with `AuthState` and, when logged in, the
token label/serial/slot. Memory shows `ready`. Unavailable PKCS#11 libs (load failure) are
listed with status `unavailable (<reason>)` — the app still starts. As shipped (c2 L8):
`providers` never loads a library (§6); a configured library path that does not exist is
judged from the filesystem and shown as `unavailable (library not found)`; other states are
`ready`, `logged in`, `logged out`.

Session model (per `Pkcs11Provider` instance): lazily, on its own first use, EVERY provider
applies its `Pkcs11InstanceConfig.env` to the process environment (the single audited
`set_var` site, §4.1.3) — also when another provider already loaded the same library (c2
parity) — and then acquires the **shared module** for the canonical library path
(`std::fs::canonicalize` of the expanded path; the path as given when that fails — §4.5.5,
D21) from the thread-local refcounted registry (§3.2). The first acquire on a path runs
`Pkcs11::new(path)` + `initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))` —
exactly the `C_Initialize` arguments PyKCS11 passes (flags `CKF_OS_LOCKING_OK`, no mutex
functions; captured in S0) — treating `CKR_CRYPTOKI_ALREADY_INITIALIZED` as success, and
opens `RawFns` on the same module; later acquires share it (PyKCS11 `_loaded_libs`
parity, keyed by canonical path rather than PyKCS11's filename string, D21). A load failure (`Error::LibraryLoading`, `Error::MissingSymbol`) raises
`ProviderUnavailable` `cannot load PKCS#11 library <library>: <detail>` with hint
`check providers.pkcs11[].library in the configuration` (detail = the libloading/cryptoki
text, §11 D11). Any CKR of `C_Initialize` other than `CKR_CRYPTOKI_ALREADY_INITIALIZED` is
the same `ProviderUnavailable` with PyKCS11's error rendering as detail — c2 called
`C_Initialize` inside `PyKCS11Lib.load()` — i.e. `<CKR name> (0x%08X)` for a code in
PyKCS11's table (e.g. `cannot load PKCS#11 library /usr/lib/softhsm/libsofthsm2.so:
CKR_GENERAL_ERROR (0x00000005)`, a SoftHSM with an unreadable `SOFTHSM2_CONF`), `Vendor
error (0x%08X)` (code with `CKR_VENDOR_DEFINED` masked off) for vendor codes, else
`Unknown error (0x%08X)`. One open session at a time
(`CKF_SERIAL_SESSION | CKF_RW_SESSION`, `open_rw_session`), held in
`RefCell<Option<Session>>` beside the provider's `Rc<SharedModule>`; `login` enumerates
tokens (`get_slots_with_token()` = `getSlotList(tokenPresent=True)`, plus
a raw `C_GetTokenInfo` through `RawFns::token_info`, never cryptoki's `get_token_info`,
which fails on a non-digit `utcTime` — §4.5.5; label, serial, model and manufacturer are
trimmed of trailing spaces **and** NULs — c2 `_strip_padding`), selects by token-label
arg / `--slot` (`Slot::try_from(u64)`) / config default (`slot`, `token_label`) /
`select()` prompt, opens the session and `C_Login(CKU_USER)`
(`Session::login(UserType::User, Some(&AuthPin))`, the PIN passing through as a
`secrecy::SecretString`). Opening a session on a new slot closes the previous one
(replacing the `Option` drops the old `Session`, whose `Drop` runs `C_CloseSession`) —
this enforces "one token of one device at a time per provider". Several providers may be
logged in concurrently. `logout` calls `C_Logout` but keeps the session reusable. Login
state is token-wide (PKCS#11 semantics): a session opened after login is already a user
session. Sessions persist across REPL commands. `shutdown()` (exit path, run by `r2-cli`
for every provider, also on error and unwind paths) logs out, drops the session and
releases the shared module; the **last** release on a path calls `C_Finalize` and unloads.
cryptoki never finalizes on drop, and one context's `C_Finalize` kills every session on
that path, so r2 always finalizes explicitly and never while any session on the path is
alive.

Login flow texts (shipped): the PIN prompt is `PIN for token '<label>'`; success prints
`logged in to '<label>' (slot <n>) on <provider>`, plus ` — PIN kept for session
auto-recovery` with `--keep-pin`; `login` on memory → `UnsupportedOperation`
`provider '<name>' does not require login`; `login` while logged in →
`AlreadyLoggedIn` `already logged in` (hint `logout first`); `logout` prints
`logged out of <provider>`.

CKR translation (single choke point; table is minimum-required, extend freely). The
"spec wording" column is c2's table; the "as shipped" column is the exact text of c2's
`_translate` at 408d6f2, which r2 reproduces:

| CKR | Message (spec wording) | As shipped: message / hint | Kind | Recovery |
|---|---|---|---|---|
| CKR_PIN_INCORRECT | Wrong PIN for token '<label>' | `wrong PIN for token '<label>' (<CKR>)` / `re-enter the PIN` | Pkcs11 | re-prompt (interactively prompted PINs only: the error panel is shown, then the PIN prompt again; a `--pin` value is not retried) |
| CKR_PIN_LOCKED | Token locked — too many bad PINs; unlock with SO PIN | `token locked — too many bad PINs (<CKR>)` / `unlock with the SO PIN` | Pkcs11 | abort |
| CKR_USER_ALREADY_LOGGED_IN | Already logged in | — (swallowed) | — | treat as success |
| CKR_USER_NOT_LOGGED_IN | Login required: run `login <provider>` | ``login required: run `login <provider>` `` | AuthRequired | raise AuthRequired |
| CKR_SESSION_HANDLE_INVALID | Session dropped — reconnecting | `session lost — login again` (when recovery is impossible) | AuthRequired | auto-recover (below) |
| CKR_DEVICE_REMOVED | Token removed; re-insert and login again | `session lost — login again` (when recovery is impossible) | AuthRequired | drop to logged_out |
| CKR_TOKEN_NOT_PRESENT | No token in slot | `no token in slot (<CKR>)` / ``re-insert the token and run `slots <provider>` `` | Pkcs11 | re-enumerate |
| CKR_MECHANISM_INVALID / _PARAM_INVALID | Token doesn't support <mech> (or its params) | `token does not support <context> (or its parameters) (<CKR>)` | UnsupportedOperation | UnsupportedOperation |
| CKR_KEY_HANDLE_INVALID | Key no longer available on token | `key no longer available on token (<CKR>)` / ``refresh with `keys` `` | Pkcs11 | refresh key list |
| CKR_ATTRIBUTE_VALUE_INVALID / _TYPE_INVALID | Template attribute <name> rejected by token | `template attribute rejected by token (<CKR>)` / `reopen the template editor and adjust the offending attribute` | Pkcs11 | reopen editor |
| CKR_ATTRIBUTE_READ_ONLY | Token forbids changing this attribute | `token forbids changing this attribute (<CKR>)` / `the attribute is fixed after object creation on this token` | Pkcs11 | per-attribute failure outcome in `key edit` (§5.15) |
| CKR_KEY_NOT_WRAPPABLE / CKR_KEY_UNEXTRACTABLE | Key can't be exported/wrapped | `key cannot be exported or wrapped (<CKR>)` / `token policy forbids extracting this key` | Pkcs11 | refuse (see §5.5/§5.6) |
| CKR_KEY_SIZE_RANGE | Key length unsuitable for <op> (HMAC keys must be ≥ the digest length on this token) | `key length unsuitable for <context> (<CKR>)` / `HMAC keys must be at least the digest length on this token (e.g. 32 bytes for sha256, 64 for sha512)` | Pkcs11 | pick a longer key / smaller hash |
| CKR_FUNCTION_NOT_SUPPORTED | Token firmware lacks this function | `token firmware lacks this function (<CKR>)` / `capability missing for <context>` | Pkcs11 | abort with capability note |
| any other CKR | — | `PKCS#11 <context> failed (<CKR>)` | Pkcs11 | — |

`<CKR>` is the symbolic name (`ckr_name`), or `CKR_0x%08X` of the low 32 bits for codes
without a name; `<context>` is the per-call context string, ported verbatim from c2's call
sites (`token initialization`, `wrap with <mech>`, `set <CKA_…>`, …). Each translation is
logged at INFO as `<provider>: <context> failed with <CKR>`.

Table notes: the choke point translates **raw CKR returns**. `AlreadyLoggedIn` comes from
the provider's own state check before calling `C_Login`; a raw `CKR_USER_ALREADY_LOGGED_IN`
from the token (`Error::Pkcs11(RvError::UserAlreadyLoggedIn, Function::Login)`) is
swallowed (treat as success). The `CKR_KEY_NOT_WRAPPABLE`/`CKR_KEY_UNEXTRACTABLE` "refuse"
rows are the backstop for the pre-flight checks in §5.5/§5.6 — the friendly
`KeyNotExportable` error is raised by commands/services before the token is ever asked, and
these CKRs surface as `Pkcs11` errors only if a token rejects what the attributes said was
allowed.

Choke point mechanics (r2): `CryptokiBackend` maps every
`cryptoki::error::Error::Pkcs11(rv, function)` to `Ckr { code, function }` (§4.5.6; the
name is looked up by `catalog::ckr_name` when translating). The
`RvError` → `CK_RV` map is r2-owned (an exhaustive `match` — `RvError` is not
`#[non_exhaustive]` — or a reverse table built once from the `cryptoki_sys::CKR_*`
constants via `Rv::from`; all 103 known codes round-trip, S0); `RvError::VendorDefined(c)`
and `RvError::UnknownErrorCode(c)` carry the raw code (10 PKCS#11 3.x codes, e.g.
`CKR_AEAD_DECRYPT_FAILED`, arrive this way). Names come from PyKCS11 1.5.18's CKR table
committed in `r2_pkcs11::catalog` (§4.5.5 — NOT from cryptoki-sys, which names 12 more
codes such as `CKR_ACTION_PROHIBITED` that c2 renders `CKR_0x%08X`). `RawFns` failures are
raw `CK_RV` values and use the same table. Non-CKR errors: `LibraryLoading` /
`MissingSymbol` → `ProviderUnavailable`; `NullFunctionPointer` (function absent from the
module's list) → treated as `CKR_FUNCTION_NOT_SUPPORTED`; every other non-CKR error
(`NotSupported`, `InvalidValue`, conversion errors) → `Pkcs11` `PKCS#11 <context> failed
(CKR_0xFFFFFFFF)` (ckr_code 0xFFFFFFFF) — c2's rendering of PyKCS11's non-CKR errors (value
−1); the cryptoki detail is logged only. cryptoki's `Display`/`Debug` texts are never shown
to the operator.
Verify is special-cased in §5.9 (`SignatureInvalid`/`SignatureLenRange` → `false`).

Auto-recovery: session ops are wrapped; on `CKR_SESSION_HANDLE_INVALID` /
`CKR_DEVICE_REMOVED` the provider re-enumerates slots and, if the same token (matched by
serial) is present **and** the operator logged in with `--keep-pin` (the `keep_pin = true`
arg of §4.5 `login()` — PIN held in provider memory only as a `SecretString`, never
persisted, zeroized on drop), it reopens the session, re-logs-in and retries the operation
**once**. Without `--keep-pin` (the default) there is no stored PIN and no mid-operation
prompting (providers have no IO, §3.1): the provider drops to `logged_out` and raises
`AuthRequired("session lost — login again")`. Any second failure likewise drops to
`logged_out` with the friendly message. Dropping the stale `Session` may make cryptoki log a
close failure at ERROR through the `log` crate; that record never reaches the console (§6).

### 5.3 Key generation

`generate <provider> <aes|rsa|ec|generic> …` — size/curve resolved via `ParamResolver`
(`aes: size∈{128,192,256}=256`; `generic: size:int=256`, any multiple of 8 in 8..8192 —
HMAC keys should be ≥ the digest length, §5.9; `rsa: size∈{2048,3072,4096}=2048`;
`ec: curve∈{p256,p384,p521,ed25519,ed448,x25519,x448}=p256` — curve implies KeyAlgorithm
EC / EC_EDWARDS / EC_MONTGOMERY). Default label prompted if `--label` absent.

- memory: AES/generic = `openssl::rand::rand_bytes` of `size/8` bytes (held in
  `Zeroizing`); RSA = `Rsa::generate(bits)` (e = 65537); EC = `EcKey::generate` over
  `EcGroup::from_curve_name(Nid::X9_62_PRIME256V1 | SECP384R1 | SECP521R1)`; Ed25519 /
  Ed448 / X25519 / X448 = `PKey::generate_ed25519()` / `generate_ed448()` /
  `generate_x25519()` / `generate_x448()` (public part derived, both listed). OpenSSL
  generates RSA keys below 1024 bits, pyca refuses them: r2 pre-validates (§5.8) and
  raises c2's `invalid RSA key size <n>: key_size must be at least 1024-bits.`
  (`Param`, `size_bits`).
- PKCS#11: template editor first — one template (from `templates.pkcs11.aes` /
  `templates.pkcs11.generic_secret`) for AES / generic secrets with `CKA_VALUE_LEN`
  enabled; **two** editors (private then public, from the respective class defaults) for
  keypairs. Mechanisms: `CKM_AES_KEY_GEN`, `CKM_GENERIC_SECRET_KEY_GEN`,
  `CKM_RSA_PKCS_KEY_PAIR_GEN`, `CKM_EC_KEY_PAIR_GEN`, `CKM_EC_EDWARDS_KEY_PAIR_GEN`,
  `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` [S] (cryptoki: `Mechanism::AesKeyGen`,
  `GenericSecretKeyGen`, `RsaPkcsKeyPairGen`, `EccKeyPairGen`, `EccEdwardsKeyPairGen`,
  `EccMontgomeryKeyPairGen`; templates cross the backend seam as raw `(type, bytes)` pairs,
  §4.5). Both keypair objects share `CKA_LABEL` and a generated random 4-byte `CKA_ID`
  (`openssl::rand`; unless `--id` given or the editor added a `CKA_ID` row — §4.7 identity
  resolution, including the duplicate-identity guard: regenerating over an existing
  (class, label, id) object raises `DuplicateKey`). EC needs `CKA_EC_PARAMS` = named-curve
  OID DER in the public template (injected from `curve`). Field note (S0): SoftHSM 2.6.1
  and 2.7.0 answer `CKR_MECHANISM_INVALID` to `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` and reject
  `CKK_EC_MONTGOMERY` objects. c2 has no keygen/import capability probe, so neither has r2:
  `generate softhsm ec curve=x25519` reaches `C_GenerateKeyPair` and surfaces the §5.2
  translation `token does not support keypair generation (or its parameters)
  (CKR_MECHANISM_INVALID)` (UnsupportedOperation), and importing a Montgomery key surfaces
  Pkcs11 `template attribute rejected by token (CKR_ATTRIBUTE_VALUE_INVALID)`. (The
  x25519/x448 derive operations gate on ECDH = `CKM_ECDH1_DERIVE`, not on the curve.)

### 5.4 Key loading

Inline form decodes via §4.4 (`decode_data` → `parse_key_material` with the typed hint).
File form reads bytes and parses with `--format` as hint. Requirements recap (from c2's
plan.md, all binding): multiline paste tolerated; spaces/newlines inside quoted data
stripped by the codec; hex that decodes to a PEM is treated as that PEM; PKCS#12/CSR/X.509
files supported; encrypted inputs prompt for the password (`prompt_secret`) unless
`--password` given.

Per-material behavior: private key → PRIVATE object (memory keeps the parsed key; PKCS#11
builds the material attribute set below and shows the template editor first). SPKI/CSR →
PUBLIC object. X.509 → CERTIFICATE object (cert retained; §4.3). PKCS#12 → imports
private + certificate (+ chain certs) under one label/CKA_ID; lists what was created. Chain
certs sharing the full identity is why CERTIFICATE objects are exempt from the §4.7
duplicate-identity guard. The `generic` and `data` hints (c2 L16) bypass
`parse_key_material` entirely — `r2-services::keyload` turns the decoded bytes verbatim into
one `KeyMaterial(GENERIC, SECRET)` / `KeyMaterial(NONE, DATA)` (a data blob may legitimately
look like PEM/DER and must not be sniffed or re-encoded; `parse_key_material` keeps its
frozen §4.4 hint set). Inline data still goes through `decode_data` (hex / base64 / PEM
text) — `--file` stores arbitrary file content verbatim. `--id` with `data` is a `Param`
error (§4.3).

Parsing backend (r2, normative; the OpenSSL counterpart of c2's pyca loaders):

- **No terminal prompting by OpenSSL.** OpenSSL never parses PEM: `r2-core::keyparse`
  decodes every PEM block itself (a port of pyca's `pem` 3.0 framing and of its
  `decrypt_pem` RFC 1421 handling, §4.4.3) and loads the body with the port of pyca's key
  parsers; encrypted PKCS#8 is recognized structurally and decrypted by keyparse with the
  whole password (no OpenSSL password callback). The plain `*_from_pem` loaders are banned (§3.1): with a NULL
  callback OpenSSL prompts `Enter PEM pass phrase:` on the controlling terminal. If the
  key is encrypted and no password was supplied, the result is c2's "password needed" path
  even if the empty password happened to decrypt (pyca `TypeError` parity): prompt
  `Password for encrypted <PEM block label>` (PEM; the block's BEGIN label) /
  `Password for encrypted private key` (DER) through the callback, or, with no callback,
  `KeyParse` `encrypted key material requires a password` with hint
  `provide --password or run interactively so the password can be prompted` (also when
  the callback answers an empty password — §11 D12(h)). A wrong password → `KeyParse`
  `incorrect password for encrypted private key (or corrupt encrypted data)`.
- **DER try-chain order** (c2 §4.4): pyca's `load_der_private_key` (PKCS#8 / SEC1 /
  PKCS#1 RSAPrivateKey / DSA; an `EncryptedPrivateKeyInfo` is its TypeError) → pyca's
  `load_der_public_key` (SPKI, else a PKCS#1 RSAPublicKey; pyca accepts it, so c2 does) →
  X.509 → CSR (both by `x509info`'s strict pyca-style parser, never `X509::from_der` /
  `X509Req::from_der`) → PKCS#12 sniff + `Pkcs12::from_der`. Keys are read by r2's port of
  pyca 49's key parsers and built from their components (§4.4.3), never by OpenSSL's d2i
  (which accepts trailing bytes, BER lengths, negative moduli, wrong versions and
  multi-prime RSA that pyca refuses).
- **Traditional encrypted PEM** (`Proc-Type: 4,ENCRYPTED` / `DEK-Info:`) with AES-128-CBC,
  AES-256-CBC or DES-EDE3-CBC loads exactly as in c2. Every other `DEK-Info` cipher
  (`DES-CBC`, `AES-192-CBC`, CAMELLIA, …) is **rejected** after the password prompt with
  c2's `incorrect password for encrypted private key (or corrupt encrypted data)` — pyca
  refuses those ciphers, although OpenSSL (with the legacy provider) would load several
  (parity decision, §11 "resolved"); the same holds for encrypted PKCS#8 outside pyca's
  scheme set (§4.4.3).
- **Legacy algorithms.** `r2_core::ensure_legacy_provider()` loads OpenSSL's `legacy`
  provider once per process (`Provider::try_load(None, "legacy", true)` —
  `retain_fallbacks` MUST be true, otherwise the default algorithms disappear; the
  `Provider` is kept for the process lifetime because dropping it unloads it). It runs
  before any PKCS#12, traditional-PEM or encrypted-PKCS#8 parse (and once at startup). A load failure is
  non-fatal and only logged; then only RC2/DES-based inputs fail. With it, legacy PKCS#12
  files (RC2-40 certificate bags, 3DES keys, SHA-1 MAC — `openssl pkcs12 -export -legacy`)
  parse, as they do in pyca (S0: vendored and system OpenSSL).
- **PKCS#12.** `Pkcs12::parse2("")` first (it covers c2's `None`-then-`b""` attempts,
  since OpenSSL tries both a NULL and an empty MAC password); then the
  `Password for PKCS#12` prompt; with no callback → `KeyParse`
  `PKCS#12 requires a password (or the PKCS#12 data is corrupt)` (hint as above); wrong →
  `KeyParse` `incorrect password for PKCS#12 (or corrupt PKCS#12 data)`. `label_hint` = the
  main certificate's friendlyName (`X509Ref::alias()`, UTF-8), else its subject CN; chain
  certificates come from `ca` in order and share the `label_hint`. A PFX without a MAC
  (`openssl pkcs12 -export -nomac`) loads with its password on every supported OpenSSL:
  when `parse2(pw)` fails on such a PFX, keyparse adds a MacData computed for `pw`
  (HMAC-SHA1, RFC 7292 key derivation) and parses that (OpenSSL 3.0's PKCS12_parse
  refuses a non-empty password without a MAC; pyca's bundled OpenSSL does not).
- **NUL bytes.** A PKCS#12 password containing NUL is answered with c2's wrong-password
  text (`incorrect password for PKCS#12 (or corrupt PKCS#12 data)`) without calling
  `Pkcs12::parse2`, which would `CString::new(..).unwrap()` it (pyca panicked in the same
  call and c2 crashed; §11 D16).
- **Classification** (normative rules in §4.4.3). `PKey::id()`
  (`Id::RSA/RSA_PSS/EC/ED25519/ED448/X25519/X448`); RSA `size_bits` =
  `rsa.n().num_bits()` (pyca `key_size`; never `Rsa::size() * 8`, which rounds up to whole
  bytes); an rsassaPss key loads as plain RSA (rebuilt as rsaEncryption, as pyca does).
  Curves via a NID table of exactly pyca 49's curves: prime256v1/secp384r1/secp521r1 → c2
  tokens `p256`/`p384`/`p521`; the other six keep pyca's lower-cased name (`secp192r1` —
  OpenSSL calls it prime192v1 —, `secp224r1`, `secp256k1`, `brainpoolp256r1`,
  `brainpoolp384r1`, `brainpoolp512r1`); explicit-parameter keys equal to P-256/P-384/P-521
  are re-encoded on the named curve (other explicit parameters: pyca's "ECDSA keys with
  explicit parameters are only supported when they map to secp256r1, secp384r1, or
  secp521r1. No custom curves are supported."); any other curve is rejected with pyca's
  `Curve <OID> is not supported`. `size_bits` is `None` for every EC-family key (c2 parity; `PKey::bits()`
  reports 456/253 for Ed448/X25519 and is never used for this).

PKCS#11 material attribute sets [S] (merged into the class template; loader-injected,
never operator-edited). Shipped behavior (c2 L5/L13 fold-back): `import_key`/`unwrap_key`
inject `CKA_SENSITIVE=false, CKA_EXTRACTABLE=true` when the template does not state them —
SoftHSM defaults both to false for imported objects, which would make freshly imported
(already-external) material non-copyable for no security gain; an operator template that
sets either attribute always wins.

| Key type | Material attrs |
|---|---|
| AES | CKA_VALUE |
| RSA public | CKA_MODULUS, CKA_PUBLIC_EXPONENT |
| RSA private | modulus + both exponents + full CRT set: CKA_PRIME_1/2, CKA_EXPONENT_1/2, CKA_COEFFICIENT (SoftHSM requires CRT) |
| EC public | CKA_EC_PARAMS (named-curve OID DER); CKA_EC_POINT = **DER OCTET STRING wrapping** 0x04‖X‖Y (must be DER-wrapped — classic gotcha) |
| EC private | CKA_EC_PARAMS; CKA_VALUE = fixed-width big-endian scalar |
| Ed25519/Ed448 | CKK_EC_EDWARDS; CKA_EC_PARAMS = OID DER 1.3.101.112/.113; priv CKA_VALUE = 32/57-B seed; pub CKA_EC_POINT = DER OCTET STRING of raw point |
| X25519/X448 | CKK_EC_MONTGOMERY; CKA_EC_PARAMS = OID DER 1.3.101.110/.111; priv CKA_VALUE = 32/56-B scalar; pub CKA_EC_POINT = DER OCTET STRING of u |
| Certificate | CKO_CERTIFICATE: CKA_CERTIFICATE_TYPE=CKC_X_509, CKA_VALUE=DER, CKA_SUBJECT, CKA_ISSUER, CKA_SERIAL_NUMBER |
| Generic secret | CKO_SECRET_KEY / CKK_GENERIC_SECRET: CKA_VALUE (any length) |
| Data object | CKO_DATA: CKA_VALUE (no CKA_KEY_TYPE, no CKA_ID, no SENSITIVE/EXTRACTABLE defaults); CKA_APPLICATION / CKA_OBJECT_ID only when the template carries them |

Material encoding (r2, byte-identical to c2; S0-verified): RSA integers come from the
`pkey.rsa()` accessors as minimal big-endian (`BigNumRef::to_vec`, except that zero encodes
as `[0x00]`, matching c2 `_i2b`); export rebuilds keys with
`Rsa::from_private_components` / `from_public_components`. The EC scalar is
`to_vec_padded(32 | 48 | 66)`; the EC point is the UNCOMPRESSED `EcPoint::to_bytes` wrapped
in a DER OCTET STRING (`der` crate); an exported EC private scalar is turned back into a
key by recomputing the public point with `EcPoint::mul_generator2`. Ed/X keys use
`raw_private_key` / `raw_public_key` and `PKey::private_key_from_raw_bytes` /
`public_key_from_raw_bytes(Id::…)`. CKA_EC_PARAMS is the `der` encoding of the curve OID.
ULONG attributes are native-endian `CK_ULONG` bytes of `size_of::<CK_ULONG>()` (4 bytes on
Windows, 8 on LP64 — never a hard-coded 8); BOOL attributes are one byte.

**Wrapped-key loading (`--kek`)** (c2 L15). `load <provider> <aes|rsa|ec> <blob> --kek
<ref>` unwraps a blob with a key-encryption key that **already resides in the target
provider** — `C_UnwrapKey` semantics, so the key material never appears in plaintext on its
way into a token. A KEK on another provider is refused (`Param`, hint: `copy` it over
first); `--kek` takes a label with the full §4.3 selector grammar (`#<id-hex>`,
`:<class>`, `@<handle>`), resolved through `parse_ref` prefixed with the target provider
name — a bare keypair label collapses to the PRIVATE half via the `find_key` class
preference, which is what RSA unwrapping needs.

The type hint is **mandatory and restricted to `aes|rsa|ec|generic`** — a wrapped blob is
opaque, so the operator declares what comes out (`auto`/`cert`/`data` are errors, as are
`--format` / `--password`, which only describe plaintext containers). Private-key payloads
are **unencrypted PKCS#8 DER inside the blob** — the same convention the §5.5 transport
protocol uses; AES payloads are raw key bytes.

| cli | mechanism | KEK | params |
|---|---|---|---|
| kw | AES-KEY-WRAP | SECRET@AES | — |
| kwp | AES-KEY-WRAP-PAD | SECRET@AES | — |
| cbc | AES-CBC | SECRET@AES | iv:bytes(16); padding:enum{none,pkcs7}=pkcs7 |
| gcm | AES-GCM | SECRET@AES | iv:bytes; aad:bytes=b""; tag_bits:enum{128,120,112,104,96}=128 (blob is ct‖tag, §5.8) |
| oaep | RSA-OAEP | PRIVATE@RSA | hash:enum=sha256; mgf_hash default_from=hash; label:bytes=b"" |
| pkcs1 | RSA-PKCS1 | PRIVATE@RSA | — |

The blob may be pasted inline (hex/base64/`0x…` via `decode_data`) or read with `--file`,
which resolves through the §4.4 `DataInput` in `auto` mode — printable hex/base64 files are
decoded, anything else is read verbatim, so `export --kek --outformat hex|b64` output (§5.6)
loads back unchanged.

`--mech` accepts a cli name or the canonical name; when omitted, `select()` offers exactly
the rows matching the KEK's class/algorithm **and** `provider.mechanisms()`. Params come from
`ParamResolver` — one code path for inline `name=value` and prompts (§5.1). PKCS#11 targets
still get the §5.12 editor, seeded from the **result's** class/algorithm (§5.16
`--template` honored), and the edited template rides into `unwrap_key`.

This makes `AES-CBC`, `AES-GCM` and `RSA-PKCS1` wrap/unwrap-capable in both providers; the
§5.5 copy ladder deliberately keeps using only KW/KWP/OAEP/RSA-AES-KEY-WRAP. Notes and
limitations: some tokens require `CKA_VALUE_LEN` on `C_UnwrapKey` — `Pkcs11Provider`
injects it for AES-secret results whenever the plaintext length is client-computable
(AES-GCM: blob minus tag; AES-CBC `padding=none`: blob length) and retries once without it
if the token objects with exactly `CKR_ATTRIBUTE_TYPE_INVALID`,
`CKR_ATTRIBUTE_VALUE_INVALID` or `CKR_TEMPLATE_INCONSISTENT` (c2's trigger set, ported
verbatim); for CBC-pkcs7 and RSA the length is unknowable up front, so operators add the
row in the always-shown editor (an enabled operator row always wins). Field note (S0):
SoftHSM 2.6.1/2.7.0 answer `CKR_ATTRIBUTE_READ_ONLY` to `CKA_VALUE_LEN` in unwrap templates
(KW, CBC_PAD) — outside the trigger set, and harmless on SoftHSM because the injection
happens only for GCM/CBC-none unwraps, which SoftHSM rejects earlier with
`CKR_MECHANISM_INVALID`; recorded for other tokens. The `ec` hint covers Weierstrass curves
only (Ed/X payloads cannot be declared). `mechanisms()` folds CKM *presence*, not
`CKF_WRAP`, so a token advertising e.g. AES-GCM for encryption may still refuse it for
`C_UnwrapKey` — that surfaces through the §5.2 CKR translation (documented residual, like
the §5.5 dialect note); SoftHSM (S0): CBC unwraps never, CBC_PAD unwraps only on 2.7.0, GCM
wraps/unwraps never. PKCS#1 v1.5 unwrap failures are reported detail-free
(Bleichenbacher-oracle hygiene). An RSA-OAEP unwrap whose parameters the token rejects
(`CKR_ARGUMENTS_BAD` / `CKR_MECHANISM_PARAM_INVALID`; SoftHSM accepts only
SHA-1/MGF1-SHA1 with an empty label) falls back to on-token raw RSA (`CKM_RSA_X_509`) +
software OAEP decoding, and the recovered material is created with `C_CreateObject` under
the same template (as shipped; the material transits process memory, zeroized afterwards).

### 5.5 Key copy

`copy <src>:<label> <dst>` — the method is chosen by `Provider::type_name()` per the
decision matrix. Probe order (binding): first check `AuthState` on both providers
(logged-out PKCS#11 → `AuthRequired` — never a misleading "lacks mechanism" error from an
empty `mechanisms()` set); then evaluate the **whole** ladder for the chosen route via
`mechanisms()`, and only when no path at all exists raise ONE clear error naming the best
missing mechanism (e.g. "cannot copy: prodhsm lacks AES-KEY-WRAP-PAD and RSA-OAEP wrap"),
not a mid-flow CKR. Destination label defaults to the source label. Destination CKA_ID: an
explicit `--id` wins, then an operator template CKA_ID row (§4.7); with neither, a
pkcs11→pkcs11 copy onto a **different** token (compared via `status().token`) inherits the
copied object's CKA_ID (the offered PUBLIC part's own id on the refusal path), and otherwise
a fresh random 4-byte CKA_ID is generated — same-token copies keep the fresh id so they stay
disambiguated via `label#id` or a `:<class>` suffix (§4.3). A repeated cross-token copy of
the same object therefore fails with `DuplicateKey` at the destination (§4.7 guard) — pass
`--id` (or a new `--label`) to keep a second copy.

| Source → Destination | Method |
|---|---|
| memory → memory | export/import of canonical material |
| memory → pkcs11 | `export_key` → template editor → `import_key` (C_CreateObject) |
| pkcs11 → memory | wrap on source under ephemeral AES → software AES-KW unwrap (MemoryProvider's `AES-KEY-WRAP(-PAD)` unwrap: openssl `Cipher::aes_256_wrap[_pad]` via `CipherCtx`) |
| pkcs11 → pkcs11 | transport-key protocol below |
| certificate / public / data object (any → any) | plain export/import, no wrapping (data: the editor seed carries the source's CKA_APPLICATION/CKA_OBJECT_ID rows) |
| `other` key type (any → any) | refused (`UnsupportedOperation`) — listing/delete only (§4.3) |

**KW-PAD dialect note** (field fix, 2026-07-20): `CKM_AES_KEY_WRAP_PAD` has two wire
dialects in the wild — RFC 5649 KWP (SoftHSM/OpenSSL; pyca's
`aes_key_unwrap_with_padding`; OpenSSL's `aes_*_wrap_pad`) vs the PKCS#11 spec-letter
reading, RFC 3394 over a PKCS#7-padded payload (e.g. Utimaco CryptoServer).
`Pkcs11Provider` therefore prefers `CKM_AES_KEY_WRAP_KWP` (unambiguously RFC 5649; cryptoki
has no variant for it: `VendorDefinedMechanism::new::<()>(mech_type(CKM_AES_KEY_WRAP_KWP),
None)`, S0 capture) whenever the token advertises it, and MemoryProvider's
`AES-KEY-WRAP-PAD` unwrap accepts BOTH dialects (c2 `_kw_pad_unwrap`; every failure carries
the hint `CKM_AES_KEY_WRAP_PAD has two wire dialects (RFC 5649 vs RFC 3394+PKCS#7) — both
were tried`), with exactly these outcomes:
  1. blob longer than 16 bytes and not a multiple of 8 → `AES key unwrap failed: The length
     of the provided data is not a multiple of the block length.` (pyca raises this
     ValueError from the KWP step before any dialect is tried; r2 pre-validates);
  2. RFC 5649 KWP succeeds → the payload;
  3. else RFC 3394 succeeds and the strict PKCS#7 check (last byte 1..=8, that many equal
     bytes) passes → the payload, logged at INFO as `AES-KEY-WRAP-PAD blob (<n> bytes)
     unwrapped via the RFC 3394+PKCS#7 dialect`;
  4. RFC 3394 succeeds but the padding is invalid → `AES key unwrap failed: RFC 3394 unwrap
     succeeded but the PKCS#7 padding is invalid`;
  5. otherwise (including every blob shorter than 24 bytes) → `AES key unwrap failed: blob
     matches neither AES-KEY-WRAP-PAD dialect (RFC 5649 KWP / RFC 3394 over PKCS#7-padded
     payload)`.
Residual limitation
(documented): two tokens that disagree on the PAD dialect and both lack KWP can still fail a
pkcs11→pkcs11 copy mid-ladder. Field note (S0): SoftHSM **2.6.1**'s `CKM_AES_KEY_WRAP_PAD`
zero-pads a non-8-aligned value to a multiple of 8 *before* RFC 5649 (MLI = padded length),
so unwrapping its own blob of a 20-byte secret yields 24 bytes; 8-aligned values (all AES
keys) are exact, and SoftHSM 2.7.0 is exact for every length. Neither version has
`CKM_AES_KEY_WRAP_KWP`.

Copyability semantics (binding; drives both this section and §5.6): for PKCS#11 keys,
`KeyInfo.exportable` = `CKA_EXTRACTABLE ∧ ¬CKA_SENSITIVE` (plain-value read allowed);
**wrappable** = `CKA_EXTRACTABLE` alone (sensitive-but-extractable keys may be copied via
wrapping, never plain-read). `KeyInfo.attributes` is guaranteed to contain `CKA_SENSITIVE`
and `CKA_EXTRACTABLE` for PKCS#11 secret/private keys so `r2-services::transfer` can
distinguish the two without extra provider calls.

Transport-key protocol (pkcs11 → pkcs11), preferred path:

1. Generate ephemeral AES-256 transport key `T` **in software** (`openssl::rand`, held in a
   `Zeroizing<Vec<u8>>`) and `C_CreateObject` it on BOTH tokens as a session object
   (`CKA_TOKEN=false`, source: `CKA_WRAP=true`; destination: `CKA_UNWRAP=true`).
   Acceptable because `T` is single-use; the *target* key never appears in plaintext.
2. Source: `wrap_key(T, AES-KEY-WRAP-PAD, target)` → blob (`AES-KEY-WRAP` without pad only
   for 8-byte-aligned secrets) [V: listed in SoftHSM NEWS since 2.6.1]. Every `C_WrapKey`
   goes through `RawFns::wrap`, which truncates the output to the length returned by the
   second call (cryptoki's `Session::wrap_key` keeps the size-query length, and tokens may
   legally over-estimate it).
3. Destination: template editor (seeded from
   `TemplatesSection::default_template(target class, algorithm)`, §4.8 — same seeding as
   load/generate) → `unwrap_key(T, blob, …, template)`.
4. On success AND error paths (a `Drop` guard): `C_DestroyObject(T)` on both sides and
   zeroize `T` (real zeroization, §11 D3; session objects also die with the session as a
   backstop).

Fallback ladder when a side lacks `AES-KEY-WRAP(-PAD)`:

- **Secret (AES) target, source has `RSA-OAEP` wrap**: generate an ephemeral RSA-2048
  **session** keypair on the DESTINATION (`CKA_UNWRAP=true` private), export its public key
  (retrieved via `list_keys()` filtered by the generated label + `KeyClass::Public` —
  `generate_key` returns only the private KeyInfo, §4.5), import it into the source as a
  session object (`CKA_WRAP=true`), then `wrap_key(rsa_pub, RSA-OAEP, target)` on the
  source and `unwrap_key(rsa_priv, …)` on the destination. Transport wraps use the RSA-OAEP
  op defaults (hash=sha256, mgf_hash=sha256, label=b""). No AES-KW needed on either side;
  OAEP payload limits (k − 2·hLen − 2, e.g. 190 B at RSA-2048/SHA-256) comfortably fit AES
  keys. The keypair is destroyed by the same guard as `T` would be. The rung requires
  RSA-OAEP on BOTH sides (pre-probe rule, c2 L10). On tokens that reject the SHA-256 OAEP
  parameters (SoftHSM: SHA-1 only) the provider wraps with software OAEP over the target's
  plain value when that value is plain-readable, else raises `UnsupportedOperation`
  `token rejects RSA-OAEP(<hash>) wrapping parameters and the target is not plain-readable`
  (hint `use hash=sha1 on this token, or an AES key-wrap route`); the unwrap side uses the
  raw-RSA fallback of §5.4 (as shipped).
- **Single-shot hybrid**: where BOTH sides advertise `RSA-AES-KEY-WRAP` (§4.6 name for
  `CKM_RSA_AES_KEY_WRAP` [V: in SoftHSM NEWS for 2.7.0] — gate on the `mechanisms()` probe,
  never on a version check) it may replace the whole ladder, including for private-key
  targets. As shipped in c2 (L5/L13 fold-back) PyKCS11 has no binding for
  `CK_RSA_AES_KEY_WRAP_PARAMS`; cryptoki has none either (no `Mechanism` variant, no
  `MechanismType` constant or `TryFrom` arm; it is even dropped from cryptoki's mechanism
  list). The S0 shim recipe (`mech_type` + `cryptoki_sys::CK_RSA_AES_KEY_WRAP_PARAMS`) works
  on SoftHSM 2.7.0, but that token ignores the OAEP hash in the params and always uses
  SHA-1, so its blobs do not interoperate with the MemoryProvider format (a SHA-256 blob →
  `CKR_GENERAL_ERROR`). Therefore `Pkcs11Provider` NEVER advertises `RSA-AES-KEY-WRAP` —
  the probe simply never fires and pkcs11-side copies always take the AES-KW /
  ephemeral-RSA rungs (§11 D6: resolved, no deviation). `MemoryProvider` does advertise it,
  keeping the rung live for mem↔provider pairs that support it. Its blob format is frozen
  as c2's: `OAEP(hash, mgf_hash, label)(32 random bytes) ‖ KWP(those 32 bytes, payload)`;
  unwrap splits at k = RSA modulus bytes and keeps c2's
  `RSA-AES-KEY-WRAP blob too short: <n> bytes (needs > <k>-byte OAEP part plus the wrapped
  payload)` check (interop with c2 verified both ways, S0).
- **Private-key target with no AES-KW on a side and no `CKM_RSA_AES_KEY_WRAP`**: no
  standard wrap path exists → fall through to plain read (below) or refuse.
- **Plain read (last resort)**: `export_key` (CKA_VALUE / private-attribute read) **only**
  if the key is exportable per the semantics above, with an explicit warning that key
  material transits process memory.

Refusal UX (ordering, consistent with "commands raise, errors render in the REPL"): when no
route exists, the copy command first — if a public part or certificate with the same
label/CKA_ID exists — asks via `confirm()` whether to copy the public part instead; on
decline, or when there is nothing public to offer, it raises
`KeyNotExportable("key '<label>' is non-extractable on this token and cannot be copied")`,
which the REPL renders.

### 5.6 Key export

| Object | `--format` default | Output |
|---|---|---|
| AES/secret, generic secret | raw | raw key bytes file |
| data object | raw | raw `CKA_VALUE` bytes file (always exportable; `--format pem\|der\|p12`, `--public`, `--kek` are errors) |
| `other` key type | — | refused (`UnsupportedOperation`) |
| private key | pem | PKCS#8 (PEM or DER); `--password` → encrypted PKCS#8 (pyca `BestAvailableEncryption` profile) |
| public key / `--public` | pem | SubjectPublicKeyInfo |
| certificate | pem | X.509 |
| any private + cert | p12 | PKCS#12, password prompted if not given |

Writers (normative, byte-identical to c2): PKCS#8 DER `private_key_to_pkcs8`, PEM
`private_key_to_pem_pkcs8`; SPKI `public_key_to_der` / `public_key_to_pem`; certificates
`X509::to_der` / `to_pem`. Encrypted PKCS#8 = `private_key_to_pem_pkcs8_passphrase(
symm::Cipher::aes_256_cbc(), pw)` (DER: `private_key_to_pkcs8_passphrase`) — PBES2 with
PBKDF2-HMAC-SHA256, 2048 iterations, AES-256-CBC, the same scheme as pyca; the salt length
(8 or 16 bytes) follows the OpenSSL build and is not normative. An explicitly empty
`--password` → `Param` `password must not be empty`; `--password` on anything but a
private-key or p12 export → `Param` `--password applies only to private-key and p12 exports
(§5.6)`.

Sensitive-key rule (binding): before any secret/private export from PKCS#11, read
`CKA_SENSITIVE`/`CKA_EXTRACTABLE`; if sensitive or non-extractable → refuse: "Refusing to
export: key is marked sensitive/non-extractable. Public key available with `export …
--public`." Public parts are always exportable (rebuilt from
CKA_MODULUS/CKA_PUBLIC_EXPONENT or CKA_EC_PARAMS/CKA_EC_POINT). Shipped nuance (c2 L8/L13
fold-back): the rebuild goes through the co-located PUBLIC (or CERTIFICATE) object sharing
label/CKA_ID — the `Provider` trait has no surface to read public attributes off a private
object — so `--public` on a *lone* non-exportable private key raises `KeyNotFound` with a
hint to load the public half.

**PKCS#12 export** (`--format p12`, `r2-services::certops`): needs a private key ref and a
certificate — `--cert <ref>` selects it; when omitted, the provider is searched for a
CERTIFICATE sharing label/CKA_ID; when none exists, a minimal self-signed certificate is
built on the fly (`build_self_signed_cert`: Subject = Issuer = `CN=<key label>`, ~10 years,
CA:FALSE). Since a PKCS#12 contains the private key, the key must be exportable — assembly
is therefore always software-side (`build_pkcs12` over the exported PKCS#8), and the
self-signed path signs with the already-exported key. Password: `--password` or
`prompt_secret` with confirmation; an empty password → `Param`
`PKCS#12 password must not be empty`.

- `build_pkcs12` is a port of pyca's `serialize_key_and_certificates` with the
  `BestAvailableEncryption` profile (§4.4.4): PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC for key
  and cert bags at 20000 iterations (16-byte salts); SHA-256 MAC at 2048 (8-byte salt);
  friendlyName (UTF-16 BMPString, any Unicode label) + localKeyID on key and cert bags,
  none on chain certs; the same structure and lengths as pyca's output.
- `build_self_signed_cert` = `X509Builder`, version 3; serial =
  `BigNum::rand(159, MsbOption::MAYBE_ZERO, false)` (pyca `random_serial_number()`
  semantics); subject = issuer = one CN entry (UTF8String); notBefore = now, notAfter =
  now + days·86400 (`Asn1Time::from_unix`); critical `BasicConstraints` CA:FALSE; signed
  with SHA-256 (RSA/EC) or `MessageDigest::null()` (Ed25519/Ed448). pyca measures the CN in
  UTF-8 BYTES: a key label outside 1..=64 bytes (e.g. 40 × `é` = 80 bytes) cannot be a CN.
  `certops::export_pkcs12` checks this before exporting or building anything and raises
  `Param` (`label`) with pyca's text `Attribute's length must be >= 1 and <= 64, but it was
  <n>` (`<n>` = the byte length) and hint `pass an existing certificate with --cert`;
  `build_self_signed_cert` keeps the same check as a defensive fallback (`subject_cn`,
  §4.4.4) (§11 D12).

**Wrapped export (`--kek`)** (c2 L15). `export <ref> <path> --kek <kek>` wraps the key
under a KEK **already resident in the same provider** (`C_WrapKey` semantics) and writes
the blob — byte-for-byte what `load --kek` consumes (§5.4), so keys round-trip. The
mechanism table, KEK grammar and param handling are §5.4's; `r2-services::wrapload` carries
both directions.

Binding rule — this is the point of the feature: wrapped export applies the §5.5
**wrappable** test (`CKA_EXTRACTABLE` alone), *not* the plain-export test (`CKA_EXTRACTABLE
∧ ¬CKA_SENSITIVE`). **A sensitive-but-extractable key can therefore be exported wrapped
even though a plain export of it is refused** — the material never appears in plaintext.
Plain export stays refused for such keys; its refusal hint now points at `--kek`. A
`CKA_EXTRACTABLE=false` key is refused in both forms (`KeyNotExportable`, pre-flight before
the token is asked).

Direction asymmetry: an RSA KEK **unwraps with its PRIVATE half and wraps with its PUBLIC
half**, so `--kek` on export must name the public object explicitly (`<label>:pub`, or a
certificate — §4.3). A bare keypair label resolves to the PRIVATE half (§4.3 class
preference) and is refused with a hint naming the fix; there is no silent half-flip. AES
KEKs use the same secret key both ways.

Only SECRET and PRIVATE keys are wrapped — public keys and certificates export as plain
material (`--kek` on one is an error). `--kek` is mutually exclusive with `--format`,
`--public`, `--cert` and `--password` (all plaintext-container concepts). Output encoding is
`--outformat raw|hex|b64` (default raw) through the §4.4 `DataOutput`; `--outformat`
without `--kek` is an error. Since `load --kek --file` reads through `DataInput` in `auto`
mode, hex and base64 blobs load back without extra flags.

### 5.7 CSR generation

`csr <provider>:<label> <path> [--subject "CN=…"] [--hash sha256]` — subject defaults to
`CN=<key label>`. Works for **non-extractable HSM keys**:

1. Read the public key from the provider (`export_key` of the public part — always
   allowed).
2. `build_csr(spki, subject=…, sig_alg=…, sign=cb)` where the callback signs the DER
   `CertificationRequestInfo` through `provider.sign()` — RSA: `rsa.sign.pkcs1` (hash per
   `--hash`); EC: `ec.sign.ecdsa` with the console's raw `r‖s` output **converted to DER**
   before returning (contract in §4.4; `r2-core::der`); Ed: `ec.sign.eddsa` raw.
3. Write PEM CSR to `<path>`.

For memory/exportable keys the same path is used (callback signs via the provider too — one
code path, no special case).

Assembly (r2, normative): the DER of c2's own construction — CRI `SEQUENCE { INTEGER 0,
subject, SPKI, [0] {} }` → sign callback → `SEQUENCE { CRI, AlgorithmIdentifier { oid, NULL
for RSA PKCS#1, absent for ECDSA/EdDSA }, BIT STRING }` → PEM (`CERTIFICATE REQUEST`,
64-column lines, LF), then pyca's strict re-parse (§4.4.4). The output is byte-identical to c2 for the deterministic algorithms (RSA PKCS#1,
Ed25519, Ed448) and the CertificationRequestInfo is identical for ECDSA (S0; all six
variants pass `openssl req -verify` and pyca `is_signature_valid`).

`--subject` parsing is a port of pyca's `_RFC4514NameParser` (`x509.Name.from_rfc4514_string`),
not `x509_cert`'s `Name::from_str`, which accepts a superset (lowercase names, `SN=`,
`emailAddress=`, empty values, oversize CN, 3-letter C, RFC-correct `#hex` decoding where
pyca double-wraps). Accepted names: `CN L ST O OU C STREET DC UID` (case-sensitive) plus
dotted OIDs; CN length 1..=64 UTF-8 bytes, C exactly 2 bytes; pyca's error texts
(including its empty one)
rendered as c2's `invalid subject <subject!r>: <exc>`. Values are encoded with pyca's default
string types (C, serialNumber, dnQualifier, jurisdictionC → PrintableString; emailAddress,
DC → IA5String; everything else UTF8String).

### 5.8 Encrypt / decrypt — provider mapping

| Mechanism | memory (openssl) | PKCS#11 (cryptoki) | Notes |
|---|---|---|---|
| AES-ECB | `symm::Crypter` over `Cipher::aes_{128,192,256}_ecb()` with `pad(false)`; PKCS7 (block 16) in r2 code when `padding=pkcs7` | `Mechanism::AesEcb` (`CKM_AES_ECB`); **no** `_PAD` variant exists → **Pkcs11Provider** applies/strips PKCS7 around the token call (padding is always provider-side, symmetric with memory) | `padding=none` requires 16-B-aligned input (checked, `Param`: `padding=none requires input length to be a multiple of 16 bytes`) |
| AES-CBC | `Crypter` over `aes_*_cbc()` with the IV and `pad(false)` + r2-owned PKCS7 | `padding=none` → `Mechanism::AesCbc(iv)` (`CKM_AES_CBC`); `padding=pkcs7` → `Mechanism::AesCbcPad(iv)` (`CKM_AES_CBC_PAD`) | memory-PKCS7 and `_PAD` must be byte-identical (KAT cross-check, §8; S0-verified); `iv` must be 16 bytes (`Param`) |
| AES-GCM | `symm::Crypter` over `Cipher::aes_*_gcm()` (the `symm::encrypt_aead` computation, with AAD and data fed in ≤ 2³⁰-byte updates, §11 D12(m)), output **ct‖tag** truncated to `tag_bits/8`; decrypt sets the tag before `finalize` (a bad tag is an error) | `Mechanism::AesGcm(GcmParams::new(&mut iv_copy, &aad, tag_bits))` [V, S0] returns ct‖tag natively (`GcmParams` needs an owned mutable IV copy) | AAD: always pass a non-NULL (possibly empty) buffer — SoftHSM builds reject NULL [V] (cryptoki passes a non-NULL pointer with length 0 for empty AAD, S0 capture). **[U]** FIPS HSMs may ignore the supplied IV and append their own — detect via output length, surface "HSM-generated IV" to the operator. Tamper on SoftHSM: `CKR_GENERAL_ERROR` (2.6.1) / `CKR_ENCRYPTED_DATA_INVALID` (2.7.0) |
| AES-CTR | `Cipher::aes_*_ctr()` with the full 16-B counter block as IV (OpenSSL increments the whole block big-endian, = pyca) | `Mechanism::VendorDefined(VendorDefinedMechanism::new(MechanismType::AES_CTR, Some(&CK_AES_CTR_PARAMS { ulCounterBits: counter_bits, cb: counter_block })))` [V, S0] (cryptoki has no CTR variant; no `unsafe`) | default `counter_bits=128` reproduces pyca's semantics; cross-provider KAT required. Memory accepts only `counter_bits=128` and a full 16-byte `counter_block` (`Param`, c2 texts). SoftHSM refuses a counter that would wrap within `counter_bits` (`CKR_DATA_LEN_RANGE`) |
| RSA-OAEP | `encrypt::Encrypter`/`Decrypter` with `Padding::PKCS1_OAEP`, `set_rsa_oaep_md(hash)`, `set_rsa_mgf1_md(mgf_hash)`, `set_rsa_oaep_label(label)` only when the label is non-empty | `Mechanism::RsaPkcsOaep(PkcsOaepParams::new(hash, mgf, PkcsOaepSource::empty() \| data_specified(&label)))` [V, S0]; tokens that reject non-SHA1 OAEP params (SoftHSM: SHA-1/MGF1-SHA1 with an empty label only) fall back to on-token raw RSA (`Mechanism::RsaX509`) + provider-side OAEP en/decoding (c2 L5/L13 fold-back), triggered by `CKR_ARGUMENTS_BAD` / `CKR_MECHANISM_PARAM_INVALID` | hash/MGF pair (CKM_SHAx, CKG_MGF1_SHAx); mgf_hash defaults to hash; an empty label is sent as NULL source data (c2 parity, S0 capture). Decrypt failures are detail-free (`RSA-OAEP decryption failed`) |
| RSA-PKCS1 | `Encrypter`/`Decrypter` with `Padding::PKCS1` | `Mechanism::RsaPkcs` (`CKM_RSA_PKCS`) | decrypt failures detail-free (`RSA-PKCS1 decryption failed`). A malformed ciphertext or wrong key follows the linked OpenSSL (§11 D26): an error on OpenSSL < 3.2 (the system 3.0 of source builds), implicit rejection (pseudo-random plaintext, no error) on 3.2+ (the vendored release build, as pyca/c2) |
| RSA-RAW | **hand-rolled** modexp: `BigNum::from_slice` + `mod_exp` + `to_vec_padded(k)` with `m ≥ n` refused (`r2-provider::rsa_raw_modexp`, shared) [S] — never OpenSSL `Padding::NONE`, which requires input length == k | `Mechanism::RsaX509` (`CKM_RSA_X_509`); decrypt with a PUBLIC ref (`…:pub`, §4.3) = software public-exponent modexp from CKA_MODULUS/CKA_PUBLIC_EXPONENT (signature recovery — tokens don't C_Decrypt with public handles: SoftHSM answers `CKR_KEY_FUNCTION_NOT_PERMITTED`, S0) | diagnostic feature; NOT constant-time in the memory provider (documented); input left-padded to modulus length (byte-identical to c2 for d and e, S0) |

Ciphertext convention: GCM output/input is `ct‖tag` — **providers** emit and consume that
format (MemoryProvider appends/splits the `tag_bits/8` tag internally; Pkcs11Provider gets
it natively). The console layer never performs crypto transforms (§3.2); it only decodes
input and renders output.

Pre-validation (binding). OpenSSL is more permissive than pyca or words its failures
differently, so r2 checks these cases **before** calling OpenSSL and emits pyca's exact
text inside c2's rendering:

| case (memory provider unless noted) | r2 emits (verbatim) |
|---|---|
| GCM IV outside 8..=128 bytes (OpenSSL accepts 1..=128) | `Param` (`iv`): `initialization_vector must be between 8 and 128 bytes (64 and 1024 bits).` |
| GCM tag | only the `tag_bits` choices 128/120/112/104/96 (OpenSSL accepts tags down to 4 bytes) |
| ECB/CBC decrypt, input not a multiple of 16 | `Crypto`: `AES-ECB decryption failed: The length of the provided data is not a multiple of the block length.` (resp. `AES-CBC …`) |
| KW wrap, payload < 16 bytes | `Crypto`: `AES key wrap failed: The key to wrap must be at least 16 bytes` (+ c2's hint `AES-KEY-WRAP needs an 8-byte-aligned payload of >= 16 bytes; use AES-KEY-WRAP-PAD otherwise`) |
| KW wrap, payload not a multiple of 8 | `Crypto`: `AES key wrap failed: The key to wrap must be a multiple of 8 bytes` (+ the same hint) |
| KWP wrap, empty payload (OpenSSL returns an empty Ok) | `Crypto`: `AES key wrap failed: key_to_wrap must be between 1 and 2^32 bytes` (+ the same hint — c2 attaches it to every KW/KWP wrap failure) |
| KW unwrap, blob < 24 bytes | `Crypto`: `AES key unwrap failed: Must be at least 24 bytes` |
| KW unwrap, blob not a multiple of 8 | `Crypto`: `AES key unwrap failed: The wrapped key must be a multiple of 8 bytes` |
| KW unwrap integrity failure | `Crypto`: `AES key unwrap failed: ` (pyca's `InvalidUnwrap()` has an empty message) |
| KWP unwrap failures | the five outcomes of the §5.5 dual-dialect list, verbatim (blob > 16 bytes and not a multiple of 8 → `The length of the provided data is not a multiple of the block length.`; bad padding after RFC 3394; else `… blob matches neither …`), all with the dual-dialect hint |
| KEK not 16/24/32 bytes | `The wrapping key must be a valid AES key length` (inside c2's wrap/unwrap prefix) |
| RSA keygen below 1024 bits (OpenSSL generates 512/1000) | `Param` (`size_bits`): `invalid RSA key size <n>: key_size must be at least 1024-bits.` |
| ECDH (memory) raw EC peer whose first byte is not `02`/`03`/`04` (OpenSSL accepts hybrid `06`/`07`) | `Param` (`peer`): `peer is not SPKI DER or an uncompressed EC point (0x04‖X‖Y): Unsupported elliptic curve point type` (§5.10) |
| self-signed CN length, `--subject` syntax | §5.6 / §5.7 |

Everything else that c2 renders as `<c2 prefix>: {exc}` carries OpenSSL's reason string
(`openssl::error::Error::reason()`), never `ErrorStack`'s `Display`, which embeds
build-specific source paths and line numbers (§11 D11).

### 5.9 Sign / verify — provider mapping

| Mechanism | memory (openssl) | PKCS#11 (cryptoki) | Notes |
|---|---|---|---|
| AES-CMAC | `PKey::cmac(&symm::Cipher::aes_{128,192,256}_cbc() by key length, key)` + `Signer::new_without_digest` → 16-B tag, truncated to `mac_len` by slicing | `Mechanism::AesCMac` (`CKM_AES_CMAC`); truncated tags: the provider computes the full 16-B CMAC on token and truncates to `mac_len` itself (byte-identical to `CKM_AES_CMAC_GENERAL(mac_len)` by definition — shipped this way, c2 L5/L13 fold-back; `_GENERAL` is never invoked) | SoftHSM ≥ 2.4.0 [V]; RFC 4493 KAT (S0) |
| AES-GMAC | AES-GCM with empty plaintext, message as AAD, output = tag (`encrypt_aead(gcm, key, iv, aad=data, b"", tag)`) | `CKM_AES_GMAC` **iff present** (`VendorDefinedMechanism::new(mech_type(CKM_AES_GMAC), Some(&GcmParams::new(&mut iv, &[], bits)))`, S0 capture); else the same GCM-AAD-only construction (`encrypt_init(AesGcm(iv, aad = message, bits))` + `encrypt_final()`, multi-part as in c2) | SoftHSM has **no CKM_AES_GMAC** [V, S0]; the GCM construction is byte-identical GMAC — both providers agree by definition |
| HMAC (c2 L16) | `PKey::hmac(key)` + `Signer::new(MessageDigest::sha{1,224,256,384,512}(), …)` over the generic secret, truncated to `mac_len` | `Mechanism::Sha1Hmac` / `Sha{224,256,384,512}Hmac` (`CKM_SHA_1_HMAC` / `CKM_SHA{224,256,384,512}_HMAC`) picked by the `hash` param, full-width on token, truncated locally (= `CKM_SHAx_HMAC_GENERAL(mac_len)` by definition); verify = recompute + `r2_core::ct_eq` | keys are `GENERIC` secrets only — both providers refuse HMAC on AES keys (and CMAC/GMAC on generic secrets) BEFORE any token call; SoftHSM enforces HMAC key ≥ digest length (`CKR_KEY_SIZE_RANGE`, §5.2) [S ~75% in c2; confirmed S0: a 32-byte key with sha384/sha512 → `CKR_KEY_SIZE_RANGE`] — the 256-bit default covers sha1/224/256, sha384/512 need ≥ 48/64-byte keys. `PKey::hmac` is never called with an empty key (generic secrets are ≥ 1 byte) |
| RSA-PKCS1 | `sign::Signer::new(md, &pkey)` (PKCS#1 v1.5 padding; byte-identical to pyca) | prefer combined `Mechanism::Sha{1,224,256,384,512}RsaPkcs` (token hashes); fallback: local hash + DigestInfo + `Mechanism::RsaPkcs` | `CKM_SHA224_RSA_PKCS` is visible only through the unfiltered RawFns mechanism list (§5.14) |
| RSA-PSS | `Signer`/`Verifier` with `Padding::PKCS1_PSS`, `set_rsa_mgf1_md(mgf_hash)`, `set_rsa_pss_saltlen(RsaPssSaltlen::custom(n))` | prefer combined `Mechanism::Sha{1,256,384,512}RsaPkcsPss(PkcsPssParams { hash_alg, mgf, s_len })` [V, S0]; SHA-224: `VendorDefinedMechanism::new(mech_type(CKM_SHA224_RSA_PKCS_PSS), Some(&PkcsPssParams))` (no cryptoki variant); else bare `Mechanism::RsaPkcsPss(..)` over a local digest | `salt_len=-1` resolved by the **provider** to keylen−hashlen−2 (c2's formula: ceil(bits/8) − hLen − 2; §4.6 sentinel; no "max" token); absent → digest length; memory always passes `custom(n)` so verify is exact. SoftHSM: mgf ≠ hash → `CKR_ARGUMENTS_BAD` |
| RSA-RAW | modexp as §5.8 | `Mechanism::RsaX509` (`CKM_RSA_X_509`) | caller supplies the padded block; verify compares with `ct_eq` |
| ECDSA | `Signer::new(md, &pkey)` → DER, converted to canonical r‖s (`r2-core::der`: `Sequence { r: UintRef, s: UintRef }`, identical to OpenSSL `EcdsaSig` and pyca `encode_dss_signature`) | prefer `Mechanism::EcdsaSha{1,224,256,384,512}` (token hashes) → r‖s native; tokens with only bare `CKM_ECDSA` (`Mechanism::Ecdsa`): hash locally, sign the digest | canonical format r‖s everywhere (§4.6); conversion at the provider boundary only. SoftHSM 2.6.1 has no `CKM_ECDSA_SHA*` (hash-locally path); 2.7.0 has them |
| EDDSA | `Signer::new_without_digest(&pkey)` + `sign_oneshot_to_vec(data)` (pure; streaming `update` is unsupported by OpenSSL for EdDSA); verify `verify_oneshot` | `CKM_EDDSA` [S]: `Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure))` (NULL params) for Ed25519, `EddsaSignatureScheme::Ed448(&[])` (`CK_EDDSA_PARAMS { phFlag = 0, empty context }`) for Ed448; **[U]** old SoftHSM (2.5.x) exposed a vendor-defined id — the advisory probe ids `0x80000C03`, `0x80000C02` (Thales/SafeNet Luna `CKM_EDDSA`/`CKM_EDDSA_NACL`) map to `EDDSA` only when the token lists them (no specific vendor constant is specced; absent → op hidden), invoked through `VendorDefinedMechanism` | raw signatures both sides (64 B Ed25519 / 114 B Ed448; RFC 8032 KATs byte-identical, S0) |

MAC verify on providers lacking `C_Verify` for the CKM: compute the MAC and compare with
`r2_core::ct_eq` (`a.len() == b.len() && openssl::memcmp::eq(a, b)` — constant-time;
`memcmp::eq` alone panics on a length mismatch, unlike `hmac.compare_digest`), same result
semantics. A PKCS#11 `C_Verify` failing with `CKR_SIGNATURE_INVALID` or
`CKR_SIGNATURE_LEN_RANGE` (`RvError::SignatureInvalid` / `SignatureLenRange` from
`Function::Verify`) is a `false` result, not an error (c2 parity).

### 5.10 Derive (key agreement)

Memory: `derive::Deriver::new(&pkey)` + `set_peer(&peer)` + `derive_to_vec()` for ECDH and
X25519/X448 → raw shared secret Z (identical to pyca's `exchange`, RFC 7748 vectors pass).
Peer handling is c2's, texts verbatim, all `Param` with param_name `peer` and checked
BEFORE the exchange: empty → `peer public key must not be empty`; EC: a peer starting with
0x30 is SPKI (`peer is not a valid SPKI public key: <detail>`, `peer public key is not an
EC key`, `peer curve <a> does not match key curve <b>`); anything else is an X9.62-encoded
point on the key's curve as pyca's `from_encoded_point` accepts it: `0x04` uncompressed or
`0x02`/`0x03` compressed (accepted and used as is — c2 derives with a compressed peer). Any
other leading byte, including the hybrid forms `0x06`/`0x07` that OpenSSL's
`EcPoint::from_bytes` would accept, is pre-validated (§5.8) and raises `peer is not SPKI DER
or an uncompressed EC point (0x04‖X‖Y): Unsupported elliptic curve point type` (pyca's
text; the c2 wording stays even for compressed input); other decoding failures (bad
length, point not on the curve) carry OpenSSL's reason as `<detail>` (D11, pyca: `Invalid
EC key.`); X25519/X448: exactly 32/56 bytes = the raw u-coordinate, otherwise
SPKI (same SPKI text; `peer public key does not match the x25519 private key` / `… x448
private key`). Only a failure of the exchange itself (e.g. an all-zero / low-order X25519
peer) is `Crypto` `ECDH key exchange failed: <detail>` (OpenSSL's reason, §11 D11). Then
c2's KDF rules: `kdf=null` with non-empty `shared_data` → `Param` `shared_data requires a
KDF (set kdf to a hash)`; `out_len < 0` → `out_len must be >= 0 (0 = curve size)`; null KDF
truncates Z to `out_len` (or `out_len {n} exceeds the shared-secret length {m} for
kdf=null`); otherwise the X9.63 KDF is computed in software with `openssl::hash` exactly as
c2's `_x963_kdf`.
PKCS#11: `Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null() | EcKdf::sha*(&shared_data),
&public_data))` [V, S0] via `C_DeriveKey` (`Session::derive_key`) → session generic-secret
object whose `CKA_VALUE` is read (RawFns single-attribute read) to produce
`DeriveResult.raw` matching OpenSSL's/pyca's Z. The derive template is c2's, exactly:
`CKA_CLASS=CKO_SECRET_KEY`, `CKA_KEY_TYPE=CKK_GENERIC_SECRET`, `CKA_TOKEN=false`,
`CKA_SENSITIVE=¬extractable`, `CKA_EXTRACTABLE=extractable` (true on the first attempt),
`CKA_VALUE_LEN` = `out_len`, or when it is 0 the curve's field size (p256 32, p384 48, p521
66, x25519 32, x448 56; unknown 32) — ALWAYS present —, `CKA_LABEL="<key label>.shared"`,
`CKA_ID` = 4 random bytes; a custom-CKM derive uses `out_len` or 32. **[U]** tokens that forbid
extractable generic secrets: return `DeriveResult { key: Some(..), raw: None }` and render
the resident-key ref instead (the spec's KDF params `kdf/shared_data/out_len`
(CKA_VALUE_LEN) cover tokens that require a KDF). Implemented (c2 L5/L13 fold-back): when
the extractable template is refused with exactly one of `CKR_ATTRIBUTE_VALUE_INVALID`,
`CKR_ATTRIBUTE_TYPE_INVALID`, `CKR_ATTRIBUTE_READ_ONLY`, `CKR_TEMPLATE_INCONSISTENT`,
`CKR_TEMPLATE_INCOMPLETE` (c2 `_DERIVE_TEMPLATE_REJECTED_CKRS`, ported verbatim) the
provider logs it at INFO, retries the derive with the resident template
(`extractable=false`) and returns the handle-only `DeriveResult`; the
`derive` command renders the resident-key ref and refuses `--out` with a clear error.
`peer` accepts SPKI DER or the raw point (EC: `0x04‖X‖Y` — passed to PKCS#11
**unwrapped**, i.e. not DER-encased [V]; X25519/X448: raw 32/56-byte u-coordinate).
X448/Ed448: SoftHSM ≥ 2.6.1 OpenSSL builds only [V] — capability probe hides them when
absent. Field notes (S0): SoftHSM accepts only `kdf=null` (`CKR_MECHANISM_PARAM_INVALID`
otherwise); with an empty `shared_data` cryptoki sends a non-NULL pointer of length 0 where
c2 sent NULL (harmless on SoftHSM; a token that objects surfaces through §5.2).

### 5.11 Certificates as public keys

Covered normatively in §4.3. Behavioral recap: `encrypt`/`verify`/`wrap` accept a
CERTIFICATE ref anywhere a PUBLIC key is accepted; `keys` lists certificates with class
`cert`; `key info` on a certificate shows subject/issuer/serial/validity; `export` yields
PEM/DER X.509.

Display rules (byte-identical to c2's pyca output; r2 code, not library `Display`): subject
and issuer use a port of pyca's `rfc4514_string()` — RDNs in reverse order, `+` inside a
multi-valued RDN, short names only for `CN L ST O OU C STREET DC UID` and the dotted OID
otherwise (e.g. `2.5.4.5=…`, `1.2.840.113549.1.9.1=…`), pyca `_escape_dn_value` escaping
(`\ " + , ; < >`, NUL → `\00`, a leading `#`/space and a trailing space), non-string values
as `#<hex>`; `x509_cert`'s `Display` (`SERIALNUMBER=`, `EMAIL=`) is not used. The serial is
lowercase hex without leading zeros (`0` for zero; OpenSSL's `to_hex_str` is uppercase and
keeps a leading zero nibble). Validity is `YYYY-MM-DDTHH:MM:SS+00:00`, formatted by r2
from the strict DER walker's UTCTime / GeneralizedTime (§4.4.5; OpenSSL's `Asn1Time`
`Display` has the wrong format). The CN for `label_hint` is the first commonName of the
subject as pyca decodes it (`x509info`'s Name decoder: BMP/Universal strings by their
encodings, other string types as UTF-8), the whole Name being decoded as c2's
`_subject_cn` did (§4.4.3).

### 5.12 Template editor UX

Line-based checklist (works in every terminal, scriptable via `ScriptedIo` — deliberately
not a full-screen dialog). Rendered as a table (comfy-table, §11 D1): index, state glyph
(`[x]`/`[ ]` bool, `(-)` disabled, `(*)` locked), attribute, kind, value. Cell content is
never interpreted as markup, so the glyphs render verbatim (c2 needed an L13 fix for rich
eating `[x]`). Mini-REPL:

```
3             toggle boolean attr #3
5=0xAABBCC    set value of attr #5 (BYTES/STR/ULONG; bytes as 0x…)
-7  /  +7     disable / re-enable attr #7   (disabled = omitted from the PKCS#11 call)
add CKA_X=v   add an attribute known to the CKA dictionary (incl. templates.custom_attributes)
ok            accept      cancel      abort (UserAbort)
```

Locked rows (CKA_CLASS/CKA_KEY_TYPE) cannot be toggled, edited or disabled. `add` accepts
only names found in `CKA_CATALOG` (§4.5.5 — a static table in `r2_core::catalog`,
re-exported by `r2_pkcs11::catalog`, so the console needs no pkcs11 item) or in
`templates.custom_attributes`, which also supply the
`AttrKind` used to parse the value. Adding `CKA_ID`/`CKA_LABEL` is accepted and honored by
the provider (§4.7 identity resolution); the editor prints a note pointing at the
`--id`/`--label` flags, the normal channel. The mini-REPL grammar is index-only (c2 L10).
A row token (the whole line; the `text::py_strip`ped text after the one `-`/`+` prefix;
or the `py_strip`ped text before the first `=`) must pass `text::py_isdigit` (c2 `str.isdigit()`: "1_0", "--3", "+-3" would pass `py_int` but are
rejected here), else Param "{token!r} is not a row number" (param_name "row", hint the
editor help); its value outside 1..=rows (a `u64` overflow included) → "row {n} is out
of range (1..{rows})", where {n} is the decimal value (leading zeros dropped; on overflow the token
with leading zeros stripped).
The mini-REPL line is read through `ConsoleIo::prompt` with a synthetic STR `ParamSpec`
(blessed pattern — no extra IO method). Initial content is seeded from
`TemplatesSection::default_template` (§4.8) or, when `--template <path>` was given, from the
matching section of a §5.16 template file — the editor itself is always shown either way.
The editor is created by `create_template_editor` (§4.9) and invoked through the
`TemplateEditor` hook before every `load`/`copy`/`generate` targeting a PKCS#11 provider.
The bootstrap constructs it directly (a Rust binary has no optional modules, so c2's lazy
import with an identity fallback has no counterpart).

### 5.13 SoftHSM auto-detection & first-run wizard

Detection (at startup when `softhsm.autodetect`), via
`find_softhsm_module(config.softhsm.search_paths)` (§4.5): `$SOFTHSM2_LIB` env override →
first existing path from `softhsm.search_paths` (§7 lists brew ARM/Intel, Debian/Ubuntu
multi-arch, Fedora, generic, Windows). **Pure path detection** — no cryptoki call (§6: no
PKCS#11 library loads until first use; a broken module surfaces as `ProviderUnavailable` on
first use, like any other pkcs11 instance). Found → register a provider named
`softhsm.provider_name` like any pkcs11 instance. If a configured pkcs11 instance already
uses that name, the configured instance wins and autodetect registration is skipped with a
log line (never a startup error).

First-run wizard (triggered on first `login softhsm` when no initialized token exists;
declining leaves the provider listed but unusable until re-run):

1. Create `softhsm.conf_dir` + `softhsm.token_dir`; write `softhsm2.conf`
   (`directories.tokendir`, `objectstore.backend = file`, `log.level = ERROR`).
2. Set `SOFTHSM2_CONF` env **before** the module's `C_Initialize` (env read at init). In
   r2 this is `TokenInit::set_env_and_reset(SOFTHSM2_CONF, conf)` (§4.5.2), which reaches
   `r2-pkcs11`'s single audited `set_var` site (§4.1.3; `r2-console` is
   `forbid(unsafe_code)` and never names a pkcs11 type) and asserts that no spinner is
   active. A module already loaded in this session has read its old conf, so the provider
   then drops its session and finalizes the shared module, and the next lazy
   `initialize()` runs `C_Initialize` again — SoftHSM re-reads its conf on re-initialization
   even while it stays mapped (S0). Because `C_Finalize` would kill every other provider's
   sessions on the same library path, this is allowed only while the wizard's provider
   holds the module's sole reference; otherwise `set_env_and_reset` refuses, without
   touching the environment or the module, with `Provider` `'<name>' shares its PKCS#11
   module with another provider` and hint `restart r2 after the setup, or remove the other
   provider entry` (logging out would not help: logout keeps the session and the module).
   The conf files written in step 1 stay in place (§11 D15).
3. Initialize: prefer in-process `Pkcs11Provider::init_token(slot, label, so_pin,
   user_pin)` (frozen in §4.5 — keeps cryptoki inside `r2-pkcs11`; no external binary
   needed): `Pkcs11::init_token(slot, &so_pin, label)` (cryptoki space-pads the label to the
   32-byte field), re-find the token by label (SoftHSM may reassign slot ids), then on an RW
   session `login(UserType::So)` + `init_pin(user_pin)` + `logout`. Fall back to
   `softhsm2-util --init-token --free --label <label> --so-pin … --pin …` (plain
   subprocess) when available, then re-initialize the module before looking the token up.
   SO PIN and user PIN prompted hidden + confirmed.
4. Report the resulting provider entry (and, when an external config file is in use, offer
   to append it).

Implementation notes (shipped, c2 L11/L5/L13 fold-back): the `login` command triggers the
wizard through the console-internal API `r2_console::wizard::run_softhsm_wizard(ctx,
provider, library) -> Result<Option<TokenInfo>>` (`None` = declined) and
`token_needs_init(provider)` (free SoftHSM slots present as `TokenInfo { label: "",
serial: "" }`; S0: they also report `token_initialized() == false`).
`Pkcs11Provider::init_token` space-pads the label to the 32-byte PKCS#11 field and
`list_tokens` trims it (spaces and NULs), so the wizard's chosen label round-trips exactly
and the fresh token is found by label after init. The label prompt is `Token label [r2]`
(`DEFAULT_TOKEN_LABEL = "r2"`; c2 offered `c2` — §11 D7) and re-asks with c2's
`Token labels are limited to 32 characters (CK_TOKEN_INFO) — use a shorter one.`; r2
measures the limit in UTF-8 bytes, because `Pkcs11::init_token` silently truncates longer
labels (§11 D15). The appended config block keeps c2's shape (a commented block when the
file has no `providers` section — comment line `# SoftHSM provider added by the r2
first-run wizard (spec §5.13)`; otherwise a structural rewrite of `providers.pkcs11` with a
`.bak` copy of the original) and all other wizard texts are c2's verbatim.

### 5.14 Custom PKCS#11 mechanisms

Normative model in §4.6/§4.8. Behavioral requirements: a config entry is enough to make a
vendor mechanism appear in `ops` and be invocable with prompted params — no code. The op
only shows for providers whose token advertises the CKM (the **unfiltered**
`RawFns::mechanism_list(slot)` contains `entry.ckm` — cryptoki's own `get_mechanism_list`
silently drops every CKM it has no `TryFrom` arm for, including all vendor CKMs, S0) and
which pass the `providers`/`provider_types` filter. Example:

```yaml
custom_mechanisms:
  - id: vendor.acme.kcv
    verb: sign
    algorithm: aes
    cli_name: acme-kcv
    label: "ACME key check value"
    ckm: 0x80000A01
    param_struct: none
    params:
      - {name: rounds, kind: int, prompt: "KCV rounds", required: false, default: 1}
    providers: [prodhsm]
```

Packers → cryptoki (normative, S0 capture-verified): `none` →
`VendorDefinedMechanism::new::<()>(mech_type(ckm), None)` (NULL `pParameter`); `gcm` →
`VendorDefinedMechanism::new(mech_type(ckm), Some(&GcmParams))`; `oaep` →
`VendorDefinedMechanism::new(mech_type(ckm), Some(&PkcsOaepParams))` (standard structs from
conventional param names); `iv` and `raw` → RawFns crypto calls with a hand-built
`CK_MECHANISM` carrying the runtime-length bytes (`iv` param, resp. `mechparam`) verbatim,
empty bytes as a NULL `pParameter` (c2 parity) — cryptoki cannot express a runtime-length
parameter (`VendorDefinedMechanism::new(&Vec<u8>)` compiles but sends the 24-byte `Vec`
header; S0 echo module: 1/37/300-byte and NULL parameters arrive exactly via RawFns). A
`ckm` below `0x80000000` is accepted with a config warning (§4.8) and named through the
`mech_type` shim.

### 5.15 Key editing

`key edit <ref> [--label <l>] [--id <hex>]` changes properties of an existing object via
the §4.5 `read_key_template`/`update_key` surfaces (frozen-provisional). Three input paths
produce one changes-template shape:

- **Flags** (`--label`/`--id`, any provider type): a direct rename; rows equal to the
  current identity are dropped.
- **PKCS#11, no flags**: the checklist editor (§5.12) opens seeded from
  `read_key_template` — the object's *current* attributes (locked CKA_CLASS/CKA_KEY_TYPE
  display rows; CKA_LABEL; CKA_ID, disabled-empty when the object has none;
  class-appropriate storage/policy attrs the token returns; decoded
  `templates.custom_attributes` vendor attrs). The command diffs edited vs seeded: a row
  travels when enabled and new (`add`), re-enabled (enabling the empty CKA_ID row and
  setting a value assigns an id), or changed; a row the operator *disables* means "don't
  change"; locked rows never travel. An unchanged template → "no changes", no provider
  call.
- **memory, no flags**: two prompts (new label / new id hex; empty answer = keep) — memory
  objects carry identity only; any other attr row yields a failed outcome.

`update_key` applies enabled rows to exactly the referenced object, **one attribute per
C_SetAttributeValue call** (`Session::update_attributes` with one raw
`(type, bytes)` attribute), collecting an `AttrEditOutcome` per attribute: a token refusal
(typically `CKR_ATTRIBUTE_READ_ONLY` — e.g. the one-direction CKA_SENSITIVE/CKA_EXTRACTABLE
rules, or storage attrs like CKA_TOKEN; all three confirmed on SoftHSM, S0) is a **failure
outcome, never an error**, and later attributes still apply; the outcome's detail is the
§5.2 translated message. Exceptions: `AuthRequired` aborts the edit (every later attr would
fail identically); locked names in the changes → `Param`
(`<CKA_…> cannot be edited after creation`). CKA_LABEL+CKA_ID are batched into ONE call
(C_SetAttributeValue is all-or-nothing per call — S0: a batch with one read-only attribute
leaves the label unchanged — so an object never ends up with the label changed but the id
refused). Identity changes run the §4.7 duplicate-identity guard BEFORE anything is applied
(`DuplicateKey`; certificates exempt; the edited object excluded from the collision scan).
The command renders one outcome table (object / attribute / value / applied-or-failed +
reason) and the new ref on a rename. Clearing CKA_ID is not supported in v1 (the ref grammar
cannot express an empty id). Certificates are editable (identity + storage attrs;
subject/issuer/serial are material, never offered).

**Family renames.** Keypair halves and PKCS#12-imported certificates share (label, CKA_ID)
— that co-location drives `verify`'s public-half fallback (§5.1), `export --public` (§5.6)
and p12 cert discovery. `update_key` is strictly single-object; when an identity edit
targets an object with identity-sharing siblings, the **command** asks via `confirm()`
(default yes) whether to rename the siblings too, then applies the identity rows the target
actually accepted to each sibling in turn — a failing sibling (e.g. `DuplicateKey`) becomes a
failed table row, not an abort.

### 5.16 Template files (`key template` / `--template`)

`key template <ref> <path>` dumps the COMPLETE attribute template of one PKCS#11 object to
a YAML file; a non-pkcs11 provider raises `UnsupportedOperation`. "Complete" =
`read_full_template` (§4.5): every `CKA_CATALOG` attr plus every
`templates.custom_attributes` vendor attr the token returns — **including readable key
material** (CKA_VALUE, RSA CRT components …) of extractable objects; attrs the token refuses
(CKR_ATTRIBUTE_SENSITIVE/_TYPE_INVALID …) are skipped. When secret material of a
SECRET/PRIVATE key lands in the file the command prints a handle-like-a-private-key note.
Codec + seeding policy live in `r2-services::templatefile` (§4.1).

Attribute reads (r2, normative): one attribute per call through
`RawFns::get_attr(session, object, type) -> Option<Vec<u8>>` (size pass, then value pass;
`None` = sensitive, type-invalid, arguments-bad (the three codes PyKCS11's
`getAttributeValue` turns into a None value) or otherwise unavailable — the counterpart of c2's
one-by-one `_read_one_attr`). cryptoki's typed `Session::get_attributes` is not used: it
silently omits refused attributes and fails the **whole** call with `Error::NotSupported`
when a value has no typed decoding — SoftHSM returns two such values on ordinary objects
(`CKA_CERTIFICATE_CATEGORY`, and `CKA_KEY_GEN_MECHANISM = CK_UNAVAILABLE_INFORMATION` on
every imported object; S0). Values are decoded by the attribute's catalog kind only: ULONG
= native-endian `CK_ULONG`, BOOL = one byte, BYTES/STR as read. A ULONG is reported
numerically even when it equals `CK_UNAVAILABLE_INFORMATION` (e.g.
`CKA_KEY_GEN_MECHANISM: 18446744073709551615` on 64-bit platforms), exactly as PyKCS11
decoded it for c2 — the R14 shared-token test confirms the dump matches c2's.

**File format** — class-keyed sections mirroring `templates.pkcs11` (§7); section keys =
the §4.8 class keys (`aes`, `rsa_private`, `rsa_public`, `ec_private`, `ec_public`,
`certificate`, `generic_secret`, `data`). A dump writes the object's one section (objects
of `other` key types have no class key — `key template` refuses them); extra sections may be
hand-added so one file covers a keypair or a PKCS#12 bundle. Value encoding per AttrKind:
BOOL → YAML bool; ULONG → int, except symbolic `CKO_/CKK_/CKC_/CKM_` names kept verbatim
(CKA_CLASS/CKA_KEY_TYPE are always symbolic; no CKA_KEY_TYPE row for certificates); BYTES →
`"0x…"` hex string; STR → plain string. On load, the AttrKind comes from a NAME lookup
(`CKA_CATALOG`, then `templates.custom_attributes`) — **never inferred from the value** (a
hex-looking CKA_LABEL stays STR; contrast the §4.7 config kind-inference rule). Unknown
section keys, unknown CKA_* names, kind/value mismatches and files without sections →
`Param` (unknown names: `unknown PKCS#11 attribute '<name>'`, hint
`define it under templates.custom_attributes (code + kind)`); unreadable/unwritable paths →
`DataIo`. The file is emitted byte-identical to PyYAML `safe_dump(sort_keys=False,
default_flow_style=False)` (the §4.8.4 emitter port: block style, insertion order, PyYAML's
quoting choices, `\uXXXX` escapes for non-ASCII text, width-80 folding), and it is loaded
with PyYAML's YAML 1.1 typing (§4.8.4 loader: plain `yes` is a bool, `'yes'` a string): a
file dumped by c2 seeds r2 and vice versa (R14 acceptance; the differential harness diffs
dumps byte-for-byte).

**Seeding** — `generate`/`load`/`copy` accept `--template <path>`; the file is parsed up
front (fail before any prompt), and a non-pkcs11 target raises `Param` (the editor never
opens there). Each editor the flow opens is seeded via `build_seed`: the section matching
the editor's `(key_class, algorithm)` class key when present, else `default_template` (§4.8)
unchanged. Section rows are transformed: the two locked CKA_CLASS/CKA_KEY_TYPE rows always
come from the FLOW (file entries dropped); CKA_LABEL/CKA_ID arrive **disabled** (enabled
template identity rows are honored per §4.7 — a dump carries the source's identity, an
instant duplicate footgun); read-only / material attrs (CKA_LOCAL, CKA_ALWAYS_SENSITIVE,
CKA_NEVER_EXTRACTABLE, CKA_KEY_GEN_MECHANISM, key material, CKA_CHECK_VALUE, cert
subject/issuer/serial — `NON_CREATION_ATTRS`) arrive **disabled** (enabled they would only
draw CKR failures at creation); everything else arrives enabled with its file value. The
operator re-enables rows deliberately in the always-shown editor (§5.12).

## 6. Non-functional requirements

- **Single-threaded invariant**: every cryptoki call happens on the REPL thread. PKCS#11
  sessions are not treated as thread-safe. Providers, the registry and the IO are `!Send` /
  `!Sync` (`Rc`/`RefCell` inside; `cryptoki::session::Session` is `!Sync` itself), so
  moving them to another thread does not compile; a `RefCell` double borrow is a bug that
  panics, and the contract suite exercises the same-provider flows where it could happen.
  Exactly two auxiliary threads exist, both touching no app state: the `ctrlc` handler
  (sets one `AtomicBool`) and the indicatif ticker, which lives only inside `busy()`.
  Future background work requires an explicit event queue — no ad-hoc threads (§3.1
  `disallowed-methods`).
- **Spinner** (an r2 addition, §11 D10; c2 §6 specified a `rich.status` spinner that c2
  never shipped): long HSM calls run inside `LineIo::busy(msg, f)`, which shows an
  indicatif spinner only in TerminalIo and only when stderr is a terminal. Draw target
  `ProgressDrawTarget::term_like_with_hz(NarrowTerm(console::Term::stderr()), 20)`, where
  `NarrowTerm` reports `width − 3` so the tty's `^C` echo cannot wrap and leave spinner
  residue; a `Drop` guard calls `finish_and_clear` on success and error, and on unwind only
  drops the bar (no `ProgressBar` call while `std::thread::panicking()`: a poisoned bar
  mutex would turn the unwind into an abort); while busy, every terminal write and every
  reader call runs inside `ProgressBar::suspend` (innermost primitive only, never nested —
  §4.9.7), so no frame is ever drawn over a prompt. Because the ticker is a second thread, the audited `set_var` site
  asserts that no `busy()` section is active (through the process-wide spinner flag
  `r2_core::runtime::{set_spinner_active, spinner_active}`, §4.9.8, since `r2-pkcs11` has
  no IO); a provider's lazy initialization
  therefore never runs inside `busy()` — commands call the idempotent
  `Provider::initialize()` before entering a busy section.
- **Ctrl-C**: `r2-cli` installs the `ctrlc` handler before the first prompt. This is
  mandatory, not cosmetic: rpassword `raise(SIGINT)`s on Ctrl-C (Windows:
  `GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)`, which reaches every process attached to the
  console) and without a handler the process is killed. `run_repl` resets the flag
  immediately before every dispatch (a stale flag would abort the next command); commands
  and services check it at step boundaries (e.g. between copy-ladder rungs) and stop with
  `UserAbort`. Inside prompts Ctrl-C is a key (raw mode) mapped per §5.1. A blocking
  PKCS#11 call cannot be interrupted — also true in c2, where `KeyboardInterrupt` landed
  only after the C call returned.
- **Secret hygiene**: PINs/passwords via `prompt_secret` (hidden: rpassword in TerminalIo
  and in PlainIo whenever stdin is a terminal — nothing is echoed, where c2's prompt_toolkit
  echoed one `*` per character, §11 D20; piped stdin: one plain line that is never
  echoed), wrapped in `secrecy::SecretString` by the reader itself (`SecretRead`, §4.9.7;
  redacted `Debug`, zeroized on drop); never logged, never stored (reconnect cache is
  opt-in, memory-only); history lines with `--pin`/`--password` not persisted (§5.1);
  logging passes through a redaction layer that rewrites `(?i)\b(pin|password)\s*=\s*\S+`
  to `<name>=***` (c2 `RedactingFilter`); key bytes are never logged — log lengths, labels,
  mechanism names, CKR codes. Key material (`KeyMaterial.data`), transport keys, decrypted
  payloads (`Provider::decrypt`), RSA-RAW results, PKCS#11 attribute reads and raw
  templates live in `zeroize::Zeroizing` buffers and are wiped on drop; template snapshots
  (`KeyTemplate`/`AttrValue`, e.g. a `key template` dump the operator writes to a file)
  are plain buffers (§11 D3).
- **Error style**: every `ConsoleError` carries an operator-actionable message, optionally a
  hint; PKCS#11 failures append the CKR name. OpenSSL `ErrorStack` `Display` (it embeds
  build-specific source paths and line numbers) and cryptoki `Display`/`Debug` texts are
  never shown to the operator (§5.8, §11 D11).
- **Logging**: rotating file only (`tracing` + `tracing-subscriber` + r2-cli's port of
  Python's `RotatingFileHandler`, size-based with `app.log.max_bytes` and `app.log.backups`
  — either 0 disables rotation —, parent directory created and file opened by r2 first,
  §4.9.11; level
  `app.log.level`); the
  console belongs to the renderer. `--debug` forces DEBUG and mirrors WARNING+ to stderr.
  Config unknown-key warnings go to the log, never stdout (c2 L2/L13 fold-back).
  cryptoki logs routine conditions at ERROR through the `log` crate (every unknown CKM on
  each mechanism listing, unknown CKRs, `try_from` misses, `Session` drop-close failures):
  r2 installs NO `log` → `tracing` bridge (`tracing-subscriber` with `default-features =
  false`; its default `tracing-log` feature would install one on `.init()`), so those
  records are dropped — they never reach the console or the file (§4.1.3).
- **Terminal I/O** (the mode switch is decided once, by `r2_console::io::open_console_io`,
  which `r2-cli` calls at startup; crossterm is an `r2-console` dependency only):
  - **TerminalIo** iff `crossterm::tty::IsTty` holds for stdin **and** stdout and
    `TERM != "dumb"`; otherwise **PlainIo**. `std::io::IsTerminal` must not make this
    decision (on Windows it accepts msys/mintty pipes, where crossterm would then read a
    hidden `CONIN$` and appear to hang). When `IsTerminal(stdin) && !IsTty(stdin)`
    (mintty / Git Bash), r2 prints one warning that hidden input is unavailable and
    suggests Windows Terminal or `winpty r2`. stdout redirected to a file → PlainIo
    (reedline paints to stdout).
  - reedline and rpassword never read piped stdin: crossterm opens `/dev/tty` (Windows:
    `CONIN$`), so with a controlling terminal they would read the keyboard and ignore the
    pipe, and without one (CI, `assert_cmd`) they fail with `ENXIO`. PlainIo is therefore
    mandatory on every OS (§11 D2).
  - **TerminalIo** = `LineIo<DegradingReader { primary: Option<ReedlineReader>,
    plain: PlainReader }>`: the first `io::Error` from reedline (an rpassword secret-read
    error is returned as is and never degrades the session; e.g. the 2-second timeout
    when a terminal never answers the `ESC[6n` cursor-position query — emacs shell-mode,
    some serial/remote consoles) disables raw mode, prints one stderr line
    `warning: line editor unavailable (<error>); continuing with plain input` and switches
    the session to plain reads permanently. The REPL never exits because of a terminal
    error. `TERM=dumb` selects PlainIo up front, so no query is ever sent.
  - **PlainIo** transcript format: write the prompt to stdout, read one line (byte-level
    `read_until(b'\n')` on `std::io::stdin()`'s global handle — never a second
    `BufReader` — strip trailing `\r`/`\n`, decode with `String::from_utf8_lossy`, so
    invalid UTF-8 becomes U+FFFD instead of ending the session), then — only when stdin is
    not a terminal (on a terminal the tty already echoed it) — echo the line plus a
    newline; for secrets write only a newline (the secret never appears in the output). At
    EOF write a newline and report EOF (§5.1 table). On a terminal stdin, Ctrl-C takes
    effect at the next Enter (§4.9.7, §11 D2). No ANSI escapes when stdout is not a
    terminal unless `ui.color: always` / `FORCE_COLOR` / `TTY_COMPATIBLE=1` force them
    (color policy below, rich parity). Command lines, answers and secrets interleave
    correctly in one pipe.
  - Prompt texts are c2's verbatim and live once, in `LineIo`: `Select [1-<n>]: `,
    `invalid choice <answer!r> — enter 1-<n> or the option text`, `<text> [Y/n] ` /
    `<text> [y/N] ` (empty answer = default; `y`/`yes`/`n`/`no`), `please answer y or n`,
    `<text> (finish with an empty line)` then `| ` per line, `<prompt>: ` for params,
    `<text>: ` for secrets; `select` with no options → `nothing to select for: <title>`.
  - **Rendering**: `render(&Renderable, &RenderConfig) -> String` always emits ANSI styling;
    styling is decided only by the output sink (§4.9.7 `SinkStyle`). Width = rich 15's
    `Console.size` rule (§4.9.2): `$COLUMNS` when it is all digits (a dumb terminal uses 80
    unless `$LINES` is set too), else the terminal size when any of stdin/stdout/stderr is a
    terminal, else 80. Style = rich 15's rule under c2's mapping
    (`resolve_color(ui.color, IsTty(stdout), env)`): is_terminal = true for `always`, else
    `TTY_COMPATIBLE=0/1`, else `FORCE_COLOR` set (true iff non-empty), else IsTty(stdout);
    not is_terminal or `TERM` dumb/unknown (any case) → no escapes at all; else `never` or
    a non-empty `NO_COLOR` → colour stripped but bold/dim/italic kept; else full styling.
    `CLICOLOR`/`CLICOLOR_FORCE` are ignored, as rich ignores them (§11 D1 keeps only the
    legacy-Windows-console difference).
- **Cross-platform**: macOS (arm64 and x86_64), Linux (x86_64 and aarch64, glibc), Windows
  (x86_64 MSVC). `crossterm` is pinned `=0.29.0` with feature `use-dev-tty`
  (level-triggered `poll`, `select()` on macOS): its default mio source stalls un-bracketed
  input bursts larger than 1 KiB until the next keystroke; Cargo feature unification
  applies the fix to reedline's crossterm. Windows has no bracketed paste (crossterm returns
  `Unsupported` and has no paste event), so PEM paste there relies on the validator
  keystroke path, at the cost of a full repaint per character; `load … --file` is the
  documented route for large material. Bracketed-paste/multiline flows, hidden PIN entry
  and Ctrl-C at a PIN prompt must be smoke-tested manually (R13) in Windows Terminal and
  conhost, including a paste of a 4096-bit RSA PEM. Box-drawing glyphs and the braille
  spinner need a TrueType console font (raster fonts may show `?`, as with rich).
- **Startup**: no PKCS#11 library is loaded until first use of its provider; a broken
  configured library must not prevent startup. `providers`, `status()`, completion and
  SoftHSM autodetection never load a library.

## 7. Default configuration (embedded `defaults.yaml` of `r2-config`)

Embedded with `include_str!` and printed verbatim by `config show --defaults`. The
normative source is c2@408d6f2's `src/c2/config/defaults.yaml` transformed with exactly
`sed 's#/c2/#/r2/#g; s#c2\.log#r2.log#'` — the four path renames (history file, log
file, SoftHSM conf dir, SoftHSM token dir); every other byte, comments included, is
identical (the block below reproduces it; on any difference the transformed file wins). An
R2 test diffs the embedded file against that transform. The loader types user files with
PyYAML's YAML 1.1 rules (§4.8.4), so c2 configs keep their meaning once renamed to
`r2.yaml` — except the load-time range checks of §11 D18 and the parser-level differences
of §11 D17 — and once any explicit c2 paths in them (`app.history_file`, `app.log.file`,
`softhsm.conf_dir`/`token_dir`) are edited (§11 D7).

```yaml
app:
  history_file: "~/.local/state/r2/history"
  log:
    level: info            # debug|info|warning|error
    file: "~/.local/state/r2/r2.log"
    max_bytes: 1048576
    backups: 3

ui:
  color: auto              # auto|always|never
  hex_group: 2             # bytes per group in hex output; 0 = continuous
  hex_width: 32            # bytes per line
  confirm_delete: true

providers:
  memory:
    enabled: true
    name: mem
  pkcs11: []               # external config typically overrides this list wholesale:
  # pkcs11:
  #   - name: prodhsm
  #     library: /usr/lib/libvendor_pkcs11.so
  #     slot: null           # optional: preselect slot id
  #     token_label: null    # optional: preselect token by label
  #     env: {}              # extra env vars set before C_Initialize

softhsm:
  autodetect: true
  provider_name: softhsm
  search_paths:
    - /opt/homebrew/lib/softhsm/libsofthsm2.so                 # macOS brew (ARM)
    - /usr/local/lib/softhsm/libsofthsm2.so                    # macOS brew (Intel) / generic
    - /opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so
    - /usr/lib/softhsm/libsofthsm2.so                          # Debian/Ubuntu (legacy)
    - /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so         # Debian/Ubuntu
    - /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so
    - /usr/lib64/softhsm/libsofthsm2.so                        # Fedora/RHEL
    - /usr/lib64/pkcs11/libsofthsm2.so
    - "C:/SoftHSM2/lib/softhsm2-x64.dll"                       # Windows
  conf_dir: "~/.config/r2/softhsm2"     # wizard writes softhsm2.conf here
  token_dir: "~/.local/state/r2/softhsm2/tokens"

# Policy/usage attributes only. CKA_CLASS/CKA_KEY_TYPE (locked rows), CKA_LABEL/CKA_ID
# (from --label/--id; an identity row added in the editor is honored, spec §4.7) and
# material attributes are injected by the loader — never listed here. Secure defaults:
# operators consciously enable extractability in the always-shown template editor.
templates:
  pkcs11:
    aes:
      CKA_TOKEN: true
      CKA_PRIVATE: true
      CKA_SENSITIVE: true
      CKA_EXTRACTABLE: false
      CKA_ENCRYPT: true
      CKA_DECRYPT: true
      CKA_SIGN: true         # CMAC/GMAC
      CKA_VERIFY: true
      CKA_WRAP: false
      CKA_UNWRAP: false
    generic_secret:          # CKK_GENERIC_SECRET (HMAC / KDF input keys)
      CKA_TOKEN: true
      CKA_PRIVATE: true
      CKA_SENSITIVE: true
      CKA_EXTRACTABLE: false
      CKA_SIGN: true         # HMAC
      CKA_VERIFY: true
      CKA_DERIVE: true
    rsa_private:
      CKA_TOKEN: true
      CKA_PRIVATE: true
      CKA_SENSITIVE: true
      CKA_EXTRACTABLE: false
      CKA_DECRYPT: true
      CKA_SIGN: true
      CKA_UNWRAP: false
    rsa_public:
      CKA_TOKEN: true
      CKA_PRIVATE: false
      CKA_ENCRYPT: true
      CKA_VERIFY: true
      CKA_WRAP: false
    ec_private:
      CKA_TOKEN: true
      CKA_PRIVATE: true
      CKA_SENSITIVE: true
      CKA_EXTRACTABLE: false
      CKA_SIGN: true
      CKA_DERIVE: true
    ec_public:
      CKA_TOKEN: true
      CKA_PRIVATE: false
      CKA_VERIFY: true
      CKA_DERIVE: true
    certificate:
      CKA_TOKEN: true
      CKA_PRIVATE: false
    data:                    # CKO_DATA objects (CKA_VALUE + optional CKA_APPLICATION/CKA_OBJECT_ID)
      CKA_TOKEN: true
      CKA_PRIVATE: true
  # Vendor attributes added to the standard CKA_* list everywhere attributes
  # are handled by name: the template editor's `add`, `key template` dumps and
  # `--template` file seeding (§5.16). Each entry: NAME: {code, kind}, e.g.
  #   CKA_ACME_USAGE: {code: 0x80000101, kind: bytes}   # kind: bool|str|bytes|ulong
  custom_attributes: {}

custom_mechanisms: []      # entry schema: spec §4.8 / example §5.14
```

## 8. Testing strategy

- **Doubles** (§4.10): `ScriptedIo` (`r2-testkit`) for every interactive flow — each
  `prompt`/`prompt_secret`/`prompt_multiline`/`select`/`confirm` pops the next queued answer
  (selects match by option text or index, confirm by `y`/`n`; an exhausted queue fails the
  test), and `.output()` collects rendered output as plain strings (`render_plain` at width
  200, c2's `RenderingIO` width). `FakeProvider` (`r2-testkit`) at the trait level
  everywhere in console/ops/services tests — deterministic, call-recording with c2's frozen
  call-summary encoding, functional wrap/unwrap, presentable as `"pkcs11"`; fault injection
  through `FakeHooks` (§4.10.2) in the consuming loop's own tests. `FakeBackend` only
  inside `r2-pkcs11` (`cfg(test)` only; there is no `fake-backend` feature, §4.10.4): the
  port of c2's `fake_pykcs11.py`
  over the raw-shaped seam (u64 CKM lists, `(u64, bytes)` templates, `Option<Vec<u8>>`
  single-attribute reads, raw `CK_RV` errors, read-only / one-direction
  `C_SetAttributeValue` simulation, HMAC CKMs with real digest widths). Real behavior via
  SoftHSM integration tests.
- **Contract suite**: `provider_contract_tests!(make_provider_expr)` (R3) expands c2's
  `ProviderContractTests` (34 tests) into `#[test]` functions. Each provider instantiates it
  in its own test file: FakeProvider in both presentations (R3), MemoryProvider (R4),
  Pkcs11Provider on SoftHSM (R5b, feature `softhsm`). Other loops never edit the macro body
  except through §4.11.
- **KATs** (fixtures in-repo, c2's vectors copied verbatim): NIST CAVP/SP 800-38A/B/D
  vectors for AES ECB/CBC/CTR/GCM/CMAC (incl. McGrew–Viega GCM test case 16); Wycheproof
  for OAEP/PKCS1v15 decrypt, PSS verify, ECDSA, ECDH; RFC 4493 (CMAC), RFC 4231 (HMAC),
  RFC 3394 and RFC 5649 (KW/KWP, incl. the Utimaco PAD-dialect regression), RFC 6979,
  RFC 8017 (independent PSS verify-KAT), RFC 8032 (Ed25519/Ed448) and RFC 7748
  (X25519/X448). Randomized schemes (PSS, ECDSA, OAEP) get verify-KATs + round-trips.
- **Round-trips/properties**: encrypt→decrypt, sign→verify, wrap→unwrap identity for every
  advertised mechanism per provider; signature-format conversion stability (r‖s ↔ DER).
- **Cross-provider** (the differentiator): encrypt in memory / decrypt in SoftHSM and vice
  versa for CBC(pkcs7), CTR, GCM (pinned IV), CMAC, GMAC-construction, OAEP, PKCS1,
  PSS-verify, ECDSA-verify, EdDSA-verify; ECDH/X25519 shared-secret equality; copy flows
  mem→SoftHSM (C_CreateObject), SoftHSM→mem (AES-KW), SoftHSM→SoftHSM (transport protocol)
  with post-copy identical-output assertions AND ephemeral-object-destroyed assertions.
  Mechanism-gated cases (X448/Ed448, native GMAC, KWP, ECDSA_SHA*, RSA-AES-KEY-WRAP,
  CKK_EC_MONTGOMERY — c2 marked some `xfail(strict=False)`) branch on the capability probe
  and assert **both** ways: advertised → the round-trip must pass; not advertised → the op
  is hidden / `UnsupportedOperation`. Nothing hides behind a skip.
- **SoftHSM-version notes** for test authors (S0): assert CKR *classes*, not exact codes,
  where versions differ (GCM tamper: `CKR_GENERAL_ERROR` on 2.6.1 vs
  `CKR_ENCRYPTED_DATA_INVALID` on 2.7.0). On 2.6.1: don't round-trip non-8-aligned generic
  secrets via AES-KEY-WRAP-PAD (§5.5 field note); OAEP is SHA-1/MGF1-SHA1 with an empty
  label only, so the raw-RSA + software-OAEP fallback is exercised; there is no
  `CKM_ECDSA_SHA*` (hash-locally path). Neither 2.6.1 nor 2.7.0 supports
  `CKK_EC_MONTGOMERY`, so c2-style X25519/X448 PKCS#11 round-trips cannot run on SoftHSM;
  assert c2's translated errors instead (§5.3: keypair generation → UnsupportedOperation
  `… (CKR_MECHANISM_INVALID)`, Montgomery import → Pkcs11 `… (CKR_ATTRIBUTE_VALUE_INVALID)`)
  — there is no capability probe for curves.
- **SoftHSM integration tests** live behind cargo feature `softhsm`, so they don't compile
  otherwise, and they **fail hard** when SoftHSM is missing (stricter than c2's pytest skip
  plus `--softhsm-required`). `scripts/softhsm-init.sh` initializes the shared token
  *before* the test process starts and exports `SOFTHSM2_CONF` and the `R2_TEST_SOFTHSM_*`
  variables read by the `softhsm_token()` fixture (§4.10), so tests never mutate the
  environment. They run under nextest only (normative, §4.1.3): its process-per-test model
  plus `unique_label()` and teardown deletion keep tests isolated on the shared token, and
  no two test threads ever share (and finalize) one module. Wizard e2e tests spawn the `r2`
  binary with their own fresh `SOFTHSM2_CONF`; in-process wizard tests (c2 test_wizard.py
  ports, `crates/r2-console/src/tests/`) hold `r2_testkit::global_state_lock()` and change
  the environment only through `r2_testkit::set_env` (its guard restores it).
- **Console flows**: `ScriptedIo` for params/template editor/wizard; c2's `test_io.py`
  ports to `LineIo` driven by a scripted `LineReader` yielding `Line` / `Interrupted` /
  `Eof` (replacing prompt_toolkit pipe input with `\x03`/`\x04`). c2's in-process suites
  over real providers (test_copy.py, test_objects_softhsm.py, test_console_crypto.py,
  test_custom_mechanism.py, test_wizard.py) port in-process through the permitted
  dev-dependency edges of §4.1.2 (`crates/r2-services/tests/`,
  `crates/r2-console/src/tests/`). REPL-level tests use
  `assert_cmd` to run the real binary with piped stdin (PlainIo) and a temp `--config`
  (help/exit/unknown/quoted-multiline paste, `config path`/`config show --origin/--defaults`,
  history filter, `--debug`); `insta` snapshots cover help, tables, error panels and other
  rendered layouts. An optional pty smoke test (Linux/macOS) covers the TerminalIo/reedline
  wiring and PlainIo on a terminal (`TERM=dumb`: no double echo, Ctrl-C at the next Enter);
  it must answer `ESC[6n` (the S0 pexpect + pyte harness is the template). The R13 manual
  checklist adds: pasting a traditional encrypted PEM (with its blank line after
  `DEK-Info:`) at the `| ` multiline prompt arrives as one answer.
- **Parity ledger**: `parity/ledger.csv` maps every c2 test (1,600 node IDs collected at
  408d6f2, collapsed to 1,284 rows: 1,280 test functions + 4 contract-instantiation rows) to
  exactly one R-loop with status `todo | ported | n/a:<reason>` (`n/a` only for pure-Python
  mechanics such as mypy Protocol conformance, importlib discovery, prompt_toolkit
  sticky-kwargs regressions). A loop is done only when its rows are `ported` (with the Rust
  test path) or `n/a`; `parity/generate_ledger.py --stats --gate <loop>` checks it, and R13
  requires zero `todo` rows (`--gate all`). Ported tests keep c2's vectors, inputs and
  asserted messages verbatim and translate only the mechanics.
- **Differential parity harness** (`parity/`, R13; optional CI job that checks out
  c2@408d6f2 and runs `uv sync`): both sides get equivalent configs (`c2.yaml`/`r2.yaml`),
  and the prompt and tool name are normalized, as is c2's prompt_toolkit non-TTY noise
  (`Warning: Input is not a terminal (fd=0).`, CR padding, the doubled prompt echo) and the
  run of `*` c2 prints after a secret prompt (§11 D20).
  - *Transcript diff*: identical scripted sessions piped into both binaries on the memory
    provider, restricted to deterministic operations (AES-ECB/CBC/CTR/GCM with pinned IVs,
    CMAC, GMAC, HMAC, RSA-PKCS1 and Ed25519 signatures, loads, exports); hex result blocks,
    error messages and hints are compared after normalizing table glyphs (§11 D1).
  - *Artifact interop*: every file format is exported by one implementation and loaded by
    the other (PKCS#8 plain and encrypted, SPKI, X.509, PKCS#12, CSR, wrapped blobs in
    three encodings, template YAML, user config files renamed to `r2.yaml`).
  - *Shared token*: both implementations run against **one** SoftHSM token dir; objects
    created by each (every kind, keypairs, PKCS#12 imports, data objects) are listed, used
    and copied by the other — the strongest check that attribute layouts match.
- **Coverage**: `cargo llvm-cov` with an 80% line floor on the workspace, enforced from R13
  (as c2's floor was wired in L13).
- **CI** (GitHub Actions, `ci.yml` from R0): `lint` (`cargo fmt --check` plus `rustfmt
  --edition 2024 --check crates/r2-console/src/commands/*.rs
  crates/r2-console/src/tests/*.rs` — those modules are `include!`-only and invisible to
  `cargo fmt`, §4.9.6 —, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo
  deny check`); `test`
  (`cargo nextest run --workspace` on ubuntu, macos and windows, plus doc tests); `softhsm`
  (ubuntu; `apt install softhsm2 opensc`, `scripts/softhsm-init.sh`,
  `cargo nextest run --workspace --features softhsm`) as a SoftHSM version matrix — distro
  2.6.1 **and** 2.7.0 built from its tag (CMake, `-DENABLE_P11_KIT=OFF -DBUILD_TESTS=OFF`,
  about a minute, cached), because Ubuntu 22.04 and 24.04 both ship 2.6.1, so c2's
  "runner version = SoftHSM version" premise does not hold; the matrix catches the 2.6/2.7
  EdDSA, AES-KW-PAD, CBC_PAD, ECDSA_SHA* and RSA-AES-KW differences; `msrv` (build with the
  pinned toolchain); `coverage` and `parity` added in R13; a release dry-run before
  sign-off.
- **Done gate** (every loop): `cargo fmt --check` && the `rustfmt --check` of the
  `include!`-only console modules (above) && `cargo clippy --workspace --all-targets -- -D
  warnings` && `cargo nextest run --workspace` (nextest is normative; plain `cargo test` is
  not the gate) && `cargo deny check`,
  plus `--features softhsm` when SoftHSM is present locally (CI always runs it), plus the
  loop's STATUS row and ledger rows updated in the same PR.

## 9. Packaging & distribution

- **Workspace and binary**: a Cargo workspace (`Cargo.lock` committed); the `r2` binary is
  built from `r2-cli`; `r2 --version` prints `r2 <version>`. `[profile.release]`:
  `lto = "fat"`, `codegen-units = 1`, `strip = true`, `panic = "unwind"` (the per-command
  `catch_unwind` and the `Drop`-based provider shutdown and transport-key cleanup rely on
  unwinding). Dependency versions are pinned workspace-wide; the exact pins that encode
  spike findings are `cryptoki =0.12.1`, `cryptoki-sys =0.5.0`, `reedline =0.49.0`,
  `crossterm =0.29.0` (feature `use-dev-tty`), `rpassword =7.5.4`, `comfy-table =8.0.1`,
  `openssl >= 0.10.81` (minimum: the wrap-pad heap-overflow fixes of 0.10.79/0.10.80, the
  unwrap-assert fix of 0.10.78, `mul_generator2`, `Asn1StringRef::to_string`), `der 0.8.2`,
  `spki 0.8.0`, `x509-cert 0.3.0`, `const-oid 0.10.2`, `secrecy 0.10`; exactly one `der`
  version in the tree.
- **OpenSSL**: release builds enable the workspace feature `vendored-openssl`
  (→ `openssl/vendored`: openssl-src 300.x — OpenSSL 3.6.3 at S0 — built `no-shared
  no-module` and statically linked; openssl-sys's vendored feature already enables
  openssl-src's `legacy`, so the legacy provider is compiled into libcrypto and needs no
  runtime module file, even with `OPENSSL_MODULES` pointing nowhere; r2-core's optional
  `openssl-src` build-dependency adds openssl-src's `camellia`, `idea` and `seed`
  features, restoring OpenSSL's default cipher set, §4.1.4). The vendored build
  needs Perl and make (Windows: Strawberry Perl). Development and CI test builds may link
  the system OpenSSL 3 dynamically; there the legacy provider is the distro's `legacy`
  module, and its absence is non-fatal (§5.4). OpenSSL 4 (openssl-src 400.x) is not used
  until openssl-sys supports it.
- **Not bundled**: vendor PKCS#11 libraries are loaded by path from config at runtime;
  SoftHSM2 is not bundled in v1 (§10). The binary has no interpreter or data-file
  dependencies (`defaults.yaml` is compiled in).
- **`release.yml`** (R12): tag + manual dispatch, per-target matrix, build, smoke test,
  upload with `SHA256SUMS`:

  | Target | Notes |
  |---|---|
  | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` | **glibc, never musl-static**: a static musl binary cannot `dlopen` vendor PKCS#11 libraries, which are glibc shared objects. Built against an old glibc baseline (manylinux_2_28 container or `cargo zigbuild --target <triple>.2.28`) so it runs on RHEL/Rocky 8-class HSM hosts; smoke-tested inside `rockylinux:8` |
  | `x86_64-apple-darwin`, `aarch64-apple-darwin` | both arches (§11 D5); an optional `lipo` universal binary |
  | `x86_64-pc-windows-msvc` | vendored OpenSSL (the runner provides Perl); the piped smoke session works (§11 D2) |

  Every target's binary passes `--version` **and** a piped `help` / `providers` / `exit`
  session on **all** OSes (c2's Windows leg could smoke `--version` only, because
  prompt_toolkit's Win32 input reads the console device, not piped stdin). Code signing and
  notarization are out of scope, as in c2.

  As built (R12): the steps live in `scripts/release/` (`build.sh` — `cargo zigbuild
  --target <triple>.2.28` on Linux, native `cargo build` elsewhere; `check-binary.sh` —
  vendored OpenSSL ≥ 3.2 with the built-in default and legacy providers, no shared
  libssl/libcrypto, and on Linux a dynamically linked glibc ELF needing no `GLIBC_*` symbol
  version above 2.28; `smoke.sh` — `--version`, the piped `help`/`providers`/`exit`
  session, and a piped `load` of the legacy RC2-40/3DES, PBES2-CAMELLIA, PBES2-SEED and
  PBES2-IDEA PKCS#12 fixtures with `OPENSSL_MODULES`/`OPENSSL_CONF` pointing nowhere;
  `package.sh`; `sha256sums.sh`). Native runners per target (`ubuntu-24.04`,
  `ubuntu-24.04-arm`, `macos-15-intel`, `macos-15`, `windows-2025`); the Linux archives are
  smoke-tested again inside `rockylinux:8`. Assets are `r2-<version>-<target>.tar.gz`
  (`.zip` on Windows; the binary plus `LICENSE`), the optional
  `r2-<version>-universal-apple-darwin.tar.gz`, and `SHA256SUMS` over them. The five
  per-target archives and the `rockylinux:8` smoke are required; a failed universal job
  only drops its asset (the publish job still runs). The smoke uses R8's `providers`,
  `load` and `keys` commands, so the release workflow is green only once R8 is merged. A pushed tag `v<version>` must equal `[workspace.package]
  version` and publishes a GitHub release; a manual dispatch is a dry run (workflow
  artifacts only).
- **Supply chain**: `cargo deny` checks advisories, bans (single `der`) and licenses
  compatible with GPL-3.0 — r2 keeps c2's GPL-3.0; OpenSSL 3 is Apache-2.0, rust-openssl
  Apache-2.0/MIT.

## 10. Out of scope / future

- Bundling SoftHSM2 inside the binary (design intent: ship the platform `libsofthsm2` next
  to the binary with a generated conf; deferred to a post-v1 loop).
- Additional provider types (cloud KMS, TPM); the `Provider` trait is the extension point.
- Non-interactive/batch mode (a `NonInteractiveIo` failing on missing params is the planned
  seam — the §4.6 `ParamResolver` design already permits it). PlainIo makes piped sessions
  work on every OS (§11 D2), but they remain interactive transcripts: a missing param is
  still prompted for and read from stdin; no batch semantics are added before parity.
- A modal "current provider" context (`use <provider>`).
- Vendor mechanism parameter C-structs beyond the five `param_struct` packers.
- CKU_SO operations beyond wizard token-init; PIN change/unlock flows.
- Session-key (CKA_TOKEN=false) lifecycle management UI.
- Object classes beyond keys/certificates/data (CKO_DOMAIN_PARAMETERS, CKO_HW_FEATURE,
  vendor classes) stay hidden from `keys`; unmodelled key types are listed as `other` but
  never operated on (§4.3) — vendor mechanisms over vendor key types would need an
  `algorithm: other` custom-mechanism contract (currently rejected by the config loader).
- **No new features before parity sign-off (M3).** Anything not in c2@408d6f2 and not
  recorded in §11 is listed for post-parity loops instead of being built. Known candidates:
  - advertising `RSA-AES-KEY-WRAP` on PKCS#11 through the S0 shim recipe
    (`mech_type(CKM_RSA_AES_KEY_WRAP)` + `cryptoki_sys::CK_RSA_AES_KEY_WRAP_PARAMS`, with
    the nested OAEP pointer built in the calling frame) — blocked on token interop (SoftHSM
    2.7.0 ignores the OAEP hash and always uses SHA-1), §11 D6;
  - X25519/X448 on PKCS#11 tokens that model them as `CKK_EC_EDWARDS` + the X25519 OID
    (SoftHSM derives the correct Z that way; c2 does not model it);
  - code signing / notarization of release binaries.

## 11. Deviations from c2

**Rule.** r2 reproduces every observable behavior of c2@408d6f2 — command grammar and
completion stages, ref grammar, messages and hints, prompts, config schema, discovery and
merge semantics (with r2 names), PKCS#11 object layouts, and every file format — except
the deviations listed here. **Anything observable that differs from c2 and is not listed in
this section is a parity bug**, to be fixed in r2. Entries are added or changed only through
the §4.11 procedure (and, for c2 changes under the freeze rule, together with a ledger
entry). IDs are stable; a resolved entry keeps its ID with its resolution. "Verified by"
names the test or harness check that pins the deviation.

**D1 — Rendering glyphs and layout.**
- *Description*: tables are drawn by comfy-table with a header rule only (c2: rich
  `box.SIMPLE_HEAD`): same columns, same cell content (control codes stripped as rich did),
  but no outer edge spaces or blank edge rows, the header rule spans the computed width, a
  table title is an r2-rendered, centered italic line, and comfy-table measures cells with
  unicode-width (column widths may differ where that differs from rich's cell table). A
  word longer than its column is folded onto further lines of the cell, its content kept
  whole; c2's rich columns (default `overflow="ellipsis"`) cropped it to the column width
  minus one and appended `…` (e.g. a long config path in `config show --origin`; text with
  spaces word-wraps in both). Printed text, the caret echo and panels (error panel, hex dump, any `PanelData`) are an
  own port of rich 15's Text/Panel layout (§4.9.2) and equal rich's output at every console
  width of 2 or more; residuals: cell widths are rich's Unicode 17.0.0 table (rich's
  `UNICODE_VERSION` environment override is not honoured), and below width 2 (never
  produced by the width rule) rich cropped to the console. The colour/terminal decision and
  the width rule are NOT deviations: they reproduce rich 15 exactly (§4.9.7 `resolve_color`:
  `never`/`NO_COLOR` keep bold/dim/italic, `TTY_COMPATIBLE`, `FORCE_COLOR` incl.
  set-but-empty, `TERM` dumb/unknown in any case, `CLICOLOR*` ignored; §4.9.2 width:
  `$COLUMNS` first). The remaining styling differences: (a) c2 printed every plain string
  with rich's default `highlight=True`, so on a colour terminal rich's `ReprHighlighter`
  coloured numbers, quoted strings, `True`/`False`/`None`, paths, URLs, UUIDs and brackets
  inside ordinary output lines; r2 prints plain text unstyled (rich measured each
  highlighted segment on its own, so a ZWJ or combining mark right at a highlight boundary
  could also shift a line break or crop a character in c2 — layout otherwise identical);
  (b) on a legacy Windows console without VT support, rich used its Win32 renderer while
  anstream falls back to wincon colours.
- *Reason*: different renderer (decision PLAN §3/§13).
- *Verified by*: `insta` snapshots; the parity harness compares content after normalizing
  table glyphs (and folded over-long words against rich's `…` crop); the R1 renderer tests assert rich-identical text for error, hex and generic
  panels, printed text (content ESC/NUL/DEL/OSC bytes included), caret layouts and
  `cell_len` (vectors generated with rich 15,
  `crates/r2-core/tests/support/gen_rich_panels.py`); `resolve_color` unit tests over the
  rich 15 truth table.

**D2 — Plain line I/O for non-terminal and degraded sessions, on every OS.**
- *Description*: when stdin or stdout is not a terminal (crossterm `IsTty`), or
  `TERM=dumb`, r2 uses PlainIo: it prints the prompt, reads one line from stdin and echoes
  it; secrets are read as one unechoed plain line when stdin is not a terminal. c2 ran
  prompt_toolkit in these cases (warning `Input is not a terminal`, CR padding, doubled
  prompt echo; stdout-redirected sessions still used the full editor; on Windows piped
  stdin could not be read at all). A terminal that stops answering `ESC[6n` degrades the
  session to plain input with one warning (`warning: line editor unavailable (<error>);
  continuing with plain input`) instead of failing; under mintty/msys r2 warns once that
  hidden input is unavailable. Invalid UTF-8 on stdin becomes U+FFFD. When PlainIo reads a
  TERMINAL stdin (`TERM=dumb`, stdout redirected, a degraded session), the tty driver
  echoes (r2 does not echo again) and Ctrl-C takes effect at the next Enter: the tty drops
  the partial line, the line typed after Ctrl-C is discarded and the read reports
  Interrupted (`Aborted.`), where c2's prompt_toolkit reacted to the key immediately.
- *Reason*: reedline/rpassword never read piped stdin (they open `/dev/tty`/`CONIN$`, and
  fail with `ENXIO` without one) — S0 terminal spike; this also fixes c2's Windows piped
  limitation. A blocking cooked-mode read cannot be interrupted without unsafe code
  (`SA_RESTART`).
- *Verified by*: `assert_cmd` piped sessions on all three OSes in CI and in the release
  smoke tests; S0 degrade checks ported to the optional pty smoke test.

**D3 — Real zeroization.**
- *Description*: exactly these buffers are `Zeroizing` / `SecretString` and wiped on drop:
  key material (`KeyMaterial.data`), transport keys, derive results (`DeriveResult.raw`),
  decrypted payloads (`Provider::decrypt`, `Backend::decrypt`), RSA-RAW results
  (`rsa_raw_modexp`), PKCS#11 attribute reads (`Backend::get_attr`) and raw templates
  (`RawAttr`), decoded `DataInput` bytes, PINs and passwords (secrets are wrapped by the
  line reader itself, `SecretRead`). Template snapshots (`KeyTemplate`/`AttrValue`, e.g. the
  `read_full_template` dump the operator writes to a file) are ordinary buffers. c2 §5.5
  documented only best-effort zeroization (CPython may keep transient copies).
- *Reason*: Rust makes the caveat obsolete (PLAN §1 goal). Not observable at the console.
- *Verified by*: code review; R10 transfer tests assert the transport-key guard runs on
  success and failure.

**D4 — Debug output, unexpected errors and the log format.**
- *Description*: `--debug` prints a Rust backtrace instead of a Python traceback. An
  unexpected failure is a panic caught per command (`catch_unwind` + panic hook); it renders
  as `unexpected error: <panic message>` with hint `details logged to <log file>`, like
  c2's catch-all, but the detail text is Rust's. The log file keeps c2's path semantics
  (parent directory created, open failures as c2's Config error), rotation (`max_bytes`,
  `backups`, either 0 = never rotate), levels and redaction (rotation is a port of Python's
  `RotatingFileHandler`, rollover before the record that would reach `max_bytes`,
  §4.9.11). The line format and logger
  names differ (`tracing` targets such as `r2_config`/`r2_pkcs11` instead of `c2.config.*`,
  `c2.providers.*`).
- *Reason*: runtime difference (PLAN §7.2).
- *Verified by*: R7 tests for the panic path, `--debug`, `max_bytes: 0` and the unwritable log path; log-format tests assert only
  content, not layout.

**D5 — Release targets.**
- *Description*: r2 ships macOS for both x86_64 and arm64 (c2: arm64 only), adds Linux
  aarch64, and builds Linux binaries against a glibc 2.28 baseline (c2: whatever the
  runner's glibc was). All targets get the piped smoke session (c2: not on Windows).
- *Reason*: free with cargo targets; HSM hosts are often RHEL/Rocky 8-class.
- *Verified by*: R12 release matrix and smoke tests (`rockylinux:8` container).

**D6 — `RSA-AES-KEY-WRAP` on PKCS#11 — RESOLVED: no deviation.**
- *Resolution*: PLAN's D6 made advertising conditional on cryptoki binding
  `CK_RSA_AES_KEY_WRAP_PARAMS`. The S0 spike showed it does not (no `Mechanism` variant, no
  `MechanismType` constant or `TryFrom` arm, dropped from the mechanism list). The shim
  recipe works on SoftHSM 2.7.0, but the token ignores the OAEP hash and always uses SHA-1,
  so its blobs don't interoperate with the MemoryProvider (c2) format. `Pkcs11Provider`
  therefore never advertises it, exactly as c2 (§5.5). The recipe and evidence are kept as
  a post-parity option (§10).
- *Verified by*: R5b test asserting `RSA-AES-KEY-WRAP ∉ mechanisms()` on SoftHSM 2.6.1 and
  2.7.0.

**D7 — Renamed to r2; own config, state and history files.**
- *Description*: binary `r2`, prompt `r2>` (continuation `…>` unchanged), startup line
  `r2 <version> — type 'help' for commands`, `--version` → `r2 <version>`, config discovery
  `--config` → `$R2_CONFIG` → `./r2.yaml` → `<user config dir>/r2/r2.yaml` (platformdirs
  layout with app name `r2`), default paths `~/.local/state/r2/history`,
  `~/.local/state/r2/r2.log`, `~/.config/r2/softhsm2`, `~/.local/state/r2/softhsm2/tokens`
  (§7), every message, hint or file comment that names the tool (e.g. the wizard's appended
  `# SoftHSM provider added by the r2 first-run wizard (spec §5.13)`, the `config path`
  discovery line), and the labels of the ephemeral session objects of the §5.5 copy
  protocol (`r2-transport-<hex>`; c2: `c2-transport-<hex>`), and the SoftHSM wizard's
  default token label (`Token label [r2]`, `DEFAULT_TOKEN_LABEL = "r2"`; c2 offered and
  wrote `c2` — the label lands on tokens shared with c2). The history file is
  reedline's format, in TerminalIo and PlainIo sessions alike: one logical entry per command (a multi-line command is stored once,
  with reedline's `<\n>` escaping — c2's prompt_toolkit file stored each physical line,
  with `# <timestamp>` and `+` prefixes), capped at the newest 1000 entries (c2:
  unbounded), and written by `sync` after every command. With its defaults, r2 never reads
  or writes c2's config, state, log or history files; tokens and data files are shared
  freely. A c2 config renamed to `r2.yaml` that still names c2 paths (`app.history_file`,
  `app.log.file`, `softhsm.conf_dir`/`token_dir`) makes r2 use those files — in particular
  reedline would rewrite c2's prompt_toolkit history file in its own format — so explicit c2
  paths must be edited when migrating (§1, §7).
- *Reason*: decision PLAN §13.2 (c2 and r2 install side by side); reedline's history
  backend (S0 terminal spike).
- *Verified by*: R2 discovery tests, R7 history tests, `config show --defaults` snapshot.

**D8 — History filter for inline key material — OPEN (decision required before R7
merges).**
- *Issue*: c2@408d6f2 persists inline key material to its history file — e.g. the raw AES
  key of `load mem aes 00112233…` and every physical line of a quoted PEM paste; only
  `--pin`/`--password` lines are dropped (verified, S0 terminal spike).
- *Option A (parity, the default until decided)*: filter `--pin`/`--password` only; no
  deviation.
- *Option B (recommended by S0)*: additionally drop entries that carry inline key data — a
  `load` with a positional data value, any entry containing a quoted multi-line token, any
  entry containing `-----BEGIN`. Cheap (`is_secret_line` grows) and consistent with c2's own
  "never echo key bytes" rule; observable only in the history file and in hints/recalls.
- *Implementation rule*: the predicate lives in one function (`is_secret_line`), so
  switching is a one-function change. If B is chosen, this entry becomes an adopted
  deviation.

**D9 — Line-editor UX (reedline instead of prompt_toolkit).**
- *Description*: the command line is highlighted (§5.1 colors; c2 had no highlighting).
  Completion shows an IdeMenu dropdown with quick (single-candidate) and partial
  (common-prefix) insertion; path candidates display only their last component. Key
  bindings are reedline's emacs defaults (the common ones match prompt_toolkit's; others,
  e.g. the reverse-search prompt `(reverse-search: <term>)`, may differ). The completion
  replacement span is the raw token under the cursor (c2's `-len(cursor_token)` was off
  after a just-closed quoted token). Param-answer history holds the last 100 answers per
  session (c2: unbounded in-memory). Param / select / confirm prompts open their choices
  (ENUM choices, BOOL words) with Tab; c2's param session (prompt_toolkit default
  `complete_while_typing=True`) popped them up while typing. A multi-line command is one
  reedline buffer, so inside
  it Up/Down move between rows and Ctrl-D on an empty continuation row deletes nothing and
  does not exit (c2 read each `…>` row as a separate prompt, where Ctrl-D on an empty row
  left the REPL and Up recalled history); Ctrl-C still discards the whole buffer.
- *Reason*: decision PLAN §13.3 (reedline for the nicer TUI); S0 terminal spike.
- *Verified by*: optional pty smoke test; completer unit tests over byte spans (incl.
  multibyte labels).

**D10 — Spinner during blocking provider calls.**
- *Description*: in TerminalIo, with stderr on a terminal, long HSM calls show an indicatif
  spinner on stderr (§6). c2 §6 specified a `rich.status` spinner, but c2 never shipped
  one. Never shown in PlainIo or when stderr is redirected.
- *Reason*: kept from c2's own spec; S0 verified it never collides with prompts.
- *Verified by*: optional pty smoke test; the `busy()` unit tests.

**D11 — Library error-detail texts.**
- *Description*: where c2 appends a library exception text to a c2-owned prefix — e.g.
  `RSA-OAEP encryption failed: <exc>`, `ECDH key exchange failed: <exc>`,
  `malformed <label> PEM block: <exc>` (pyca) or `cannot load PKCS#11 library <path>:
  <exc>` (PyKCS11) — r2 appends OpenSSL's reason string (`openssl::error::Error::reason()`)
  or the libloading/cryptoki error text: `data too large for key size` where pyca said
  `Encryption failed`, `point is not on curve` where pyca said `Invalid EC key.`, and so on.
  The c2-owned prefixes and all hints are unchanged. The pre-validated cases of §5.8 and the
  RFC 4514 subject and CN-length texts (§5.6/§5.7) keep pyca's exact text. `ErrorStack`'s
  `Display` (build-specific file paths and line numbers) is never shown.
- *Reason*: different crypto/FFI libraries (S0 OpenSSL spike §9); c2's tests assert only
  the c2-owned prefixes.
- *Verified by*: ported c2 tests (prefix assertions); §5.8 pre-validation tests assert the
  full pyca texts.

**D12 — c2 crash paths become ordinary errors.**
- *Description*: where c2 let an exception escape into the REPL's unexpected-error path
  (`unexpected error: …` + log hint) or out of the REPL as a traceback, r2 raises a
  `ConsoleError`:
  - (a) `export … --format p12` without `--cert` and with no co-located certificate builds
    a self-signed certificate with `CN=<key label>`; a label outside 1..=64 UTF-8 BYTES
    (pyca's unit — 40 × `é` is 80) made pyca raise a bare `ValueError`. r2's
    `certops::export_pkcs12` checks first and raises `Param` (`label`) `Attribute's length
    must be >= 1 and <= 64, but it was <n>` (`<n>` = byte length) with hint `pass an
    existing certificate with --cert`, before anything is exported or built;
    `build_self_signed_cert` keeps the same text as a defensive check (`subject_cn`, hint
    `the self-signed certificate uses the key label as its CN`, §4.4.4).
  - (b) a certificate or CSR whose key is on a curve pyca does not support (e.g.
    prime239v1): pyca's lazy `public_key()` raised `UnsupportedAlgorithm` uncaught in c2's
    keyparse (and listing such a certificate on a token aborted `keys`; keyexport's
    `_cert_spki` crashed the same way); r2 raises KeyParse
    `certificate contains an invalid public key: Curve 1.2.840.10045.3.1.4 is not
    supported` (resp. `certificate request contains …`); the same holds for an SPKI
    algorithm pyca does not know (`Unknown key type: <oid>`). Likewise a certificate Name
    value pyca can only decode lazily (invalid UTF-8, an IA5/Teletex string with a byte
    above 0x7F, a BIT STRING under any OID but x500UniqueIdentifier, an unknown string tag)
    made `key info` crash in `certificate_details` and `load` crash in keyparse's
    `_subject_cn` (a certificate, or a CSR, loaded without a label); r2 raises KeyParse
    `certificate is not valid DER X.509: <pyca text>` (resp. `certificate request is not
    valid DER X.509: <pyca text>`). A GeneralizedTime in year 0 loads in pyca but Python's
    `datetime` refused it in `certificate_details` and the memory attributes; r2 raises
    KeyParse `certificate is not valid DER X.509: year 0 is out of range`. A certificate
    whose TBS version is v2 or above v3 (a CSR whose version is not 0) made pyca raise
    `InvalidVersion` (an `Exception`, not a ValueError) out of `load_der_x509_certificate`
    / `load_der_x509_csr`, past c2's `except ValueError` (DER chain, PEM blocks, PKCS#12
    certificates, `key info`, export, the PKCS#11 listing); r2 raises KeyParse
    `certificate is not valid DER X.509: <n> is not a valid X509 version` (resp.
    `certificate request is not valid DER X.509: <n> is not a valid CSR version`; in a PEM
    block `malformed CERTIFICATE PEM block: …`). On the PKCS#11
    read path these errors propagate (c2 crashed) while c2's ValueError cases skip the
    certificate (`x509info::pkcs11_skips_certificate`).
  - (c) an I/O error from the command-line reader (only PlainIo can produce one): c2 let
    it escape as a traceback; r2 renders it with the error panel and ends the REPL
    normally (provider shutdown runs).
  - (d) config discovery in a deleted working directory: c2's `Path.cwd()` raised
    `FileNotFoundError` out of startup; r2 skips the `./r2.yaml` candidate and continues
    with the user config dir (§4.8.1).
  - (e) a non-ASCII character inside a pasted PEM block (`decode_data`, §4.4.1): in the
    base64 body, c2's `b64decode` raised a bare `ValueError` (only `binascii.Error` was
    caught); r2 raises CodecError `malformed PEM: body of the <label> block is not valid
    base64`. In an RFC 1421 header line, c2's final `.encode("ascii")` raised
    `UnicodeEncodeError`; r2 keeps the line and returns the re-wrapped text as UTF-8
    (the key parser then rejects the block).
  - (f) a config file that is not valid UTF-8 (`Path.read_text` raised
    `UnicodeDecodeError`), or whose YAML construction raised a plain `ValueError` (an
    impossible timestamp such as `2001-02-30` or `2001-13-01`, a malformed explicit
    `!!int`/`!!float`/`!!bool` scalar): c2's `_read_external` caught only `OSError` and
    `yaml.YAMLError`, so startup crashed with a traceback. r2 raises Config `cannot read
    config file <path>: <CPython UnicodeDecodeError text>` resp. `invalid YAML in config
    file <path>: <Python's ValueError text>` (`day is out of range for month`, `month must
    be in 1..12`, `invalid literal for int() with base 10: 'x'`, …; §4.8.1).
  - (g) `~name/…` (another user's home) in `--config`, `$R2_CONFIG` or a config path
    field: c2's `Path.expanduser()` resolved it with `pwd.getpwnam` and raised
    `RuntimeError: Could not determine home directory.` (startup crash) for an unknown
    user. r2 resolves it from `/etc/passwd` and keeps an unresolvable `~name/…` literally
    (`--config ~nosuch/x` → `config file not found: ~nosuch/x`). Residual differences:
    users known only to other NSS sources (LDAP, sssd) or to macOS Directory Services are
    not resolved, and on Windows `~name` is not expanded (ntpath guessed a sibling of
    `%USERPROFILE%`).
  - (h) an EMPTY password answered at an encrypted-key prompt (encrypted PKCS#8, PEM or
    DER, and traditional encrypted PEM): pyca treats `b""` as no password and raised
    `TypeError` "Password was not given but private key is encrypted", which c2 did not
    catch; r2 raises KeyParse `encrypted key material requires a password` (hint `provide
    --password or run interactively so the password can be prompted`) — the answer c2 gave
    when no password could be asked — and never loads such a key, even one encrypted with
    the empty password. (An empty PKCS#12 password is c2's ordinary wrong-password path.)
  - (i) a PKCS#12 whose private key pyca refuses with `UnsupportedAlgorithm` (a curve pyca
    does not support, explicit parameters of another curve, an unknown key type):
    `load_pkcs12` raised it past c2's `except ValueError` loop; r2 raises KeyParse
    `PKCS#12 contains an unsupported private key: <detail>` (without a callback as after
    the prompt). A key pyca refuses with a ValueError (`Invalid private key`, `Invalid
    key`) is NOT this case: it fails the attempt as in c2 ("PKCS#12 requires a password …"
    / "incorrect password for PKCS#12 …").
  - (j) `export … --password` with a password over 1023 UTF-8 bytes: pyca's
    `BestAvailableEncryption` raised `ValueError` "Passwords longer than 1023 bytes are not
    supported by this backend" out of c2's keyexport; r2's `formats::private_key_bytes`
    raises Param (`password`) with that text before encrypting. (Import decrypts with the
    whole password, as pyca does.)
  - (k) an encrypted PKCS#8 (DER, or a PEM `ENCRYPTED PRIVATE KEY` block) whose PBES2
    PBKDF2 iterationCount exceeds OpenSSL's C int (above 2^31 − 1): rust-openssl's
    `pbkdf2_hmac` unwraps the conversion, so pyca panicked (`PanicException`, past c2's
    `except ValueError`) once the password was given; r2 treats the count as pyca's
    ValueError → KeyParse `incorrect password for encrypted private key (or corrupt
    encrypted data)` after the prompt.
  - (l) memory `derive … ECDH kdf=<hash> out_len=<n>` with a huge `<n>` (`out_len` has no
    upper bound, §4.6.6): c2's `_x963_kdf` looped `out += digest` until `MemoryError` (or,
    past 2³² − 1 blocks, `counter.to_bytes(4, "big")` raised `OverflowError`). r2 raises
    Param (`out_len`) `out_len <n> exceeds the X9.63 KDF limit of <hashlen·(2³²−1)> bytes for
    <hash>` before allocating, and Param (`out_len`) `out_len <n> is too large: cannot
    allocate the KDF output` when the allocator refuses the buffer (never a
    capacity-overflow panic or an allocation-failure abort). A length that is allocatable
    but exceeds physical memory still exhausts it, as in c2.
  - (m) memory AES payloads of 2 GiB or more: rust-openssl panics when one cipher update
    exceeds `c_int::MAX` bytes, so the memory engine feeds AES-ECB/CBC/CTR/GCM data and
    GCM AAD to OpenSSL in chunks of 2³⁰ bytes (as pyca chunks its updates). AES
    encrypt/decrypt therefore succeeds as in c2, and AES-GMAC / AES-GCM over an AAD of
    2³¹ bytes or more, where c2 raised a pyo3 `PanicException` from
    `authenticate_additional_data`, returns the tag. Key wrap cannot be chunked: an
    AES-KEY-WRAP(-PAD) unwrap blob over 2³¹ − 1 bytes is pyca's message-less
    `InvalidUnwrap` (the integrity failure c2 reached), and a wrap payload over 2³¹ − 1
    bytes is the ValueError `The key to wrap must be at most 2147483647 bytes (OpenSSL key
    wrap limit)` where c2's pure-Python RFC 3394/5649 loop would have wrapped it.
  - (n) a `providers.pkcs11[].env` entry Python's `os.environ` cannot set (an empty name,
    a name containing `=`, a NUL in the name or value): c2's initialize let `ValueError`
    (`OSError` for the empty name) escape on the provider's first use; `std::env::set_var`
    would panic. r2 checks every entry before setting any and raises ProviderUnavailable
    `cannot load PKCS#11 library {library}: {detail}: {py_repr(name)}` (detail `illegal
    environment variable name` or `embedded null byte`; hint `check providers.pkcs11[].env
    in the configuration`); the wizard's `set_env_and_reset` refuses such a pair with
    Provider `cannot set environment variable {py_repr(name)}: {detail}`.
  - (o) a token whose C_GetMechanismList includes a code below CKM_VENDOR_DEFINED that
    PyKCS11's `CKM` table does not name (a CKM newer than PyKCS11): `getMechanismList`
    raised `KeyError` out of c2's `login` (and session recovery); r2 keeps the code (the
    unfiltered list, §4.5.5) and the login succeeds. Listed vendor codes are named
    `CKM_VENDOR_DEFINED_0x<HEX>` and accepted by template ULONG symbol resolution for the
    rest of the process, as PyKCS11's global table did.
  - (p) PKCS#11 import (`load`/`copy` to a pkcs11 provider) of private key material pyca
    loads only as `UnsupportedAlgorithm` (e.g. a curve pyca does not support): c2's
    `_private_material_attrs` caught only ValueError/TypeError, so it crashed; r2 raises
    KeyParse `private key material is not DER PKCS#8: {pyca detail}` (likewise
    `public key material is not DER SPKI: …`).
- *Reason*: every expected failure must be a `ConsoleError`; OpenSSL would reject the CN
  with a different text anyway.
- *Verified by*: R8 certops test (a), R6 keyparse/x509info/formats fixtures (b, h, i, j:
  `lazily_undecodable_subject_names_are_keyparse_errors`,
  `year_zero_validity_fails_only_where_c2_formatted_it`,
  `pkcs11_skip_classification_mirrors_pycas_exception_classes`,
  `certificate_structure_is_pycas`, `csr_structure_is_pycas`,
  `certificates_get_pycas_load_time_structure_checks`,
  `encrypted_with_empty_password_still_requires_a_password`,
  `pkcs12_with_a_key_pyca_does_not_support_is_d12i`,
  `invalid_rsa_private_keys_are_pycas_value_errors`,
  `passwords_over_1023_bytes_are_refused_as_pyca`, k:
  `pbkdf2_iteration_counts_above_c_int_are_the_wrong_password_text`), R4 memory test (l:
  `ecdh_kdf_out_len_above_the_x963_limit_is_a_param_error`; m: engine
  `chunked_crypt_matches_a_single_update`, `chunked_gcm_matches_one_shot_aead`, and the
  opt-in `test_aes_payloads_past_2_gib_are_chunked_not_a_panic`), R7 repl test (c), R1
  codec differential vectors (e), R2 loader tests (d, f: `invalid_utf8_is_a_read_error`,
  `deleted_working_directory_skips_the_cwd_candidate`, the `LOAD` vectors; g:
  `discovery::expand_user_is_python_expanduser`,
  `discovery::expand_user_resolves_other_users`), R5a session test (l:
  `unsettable_env_entries_are_errors_not_panics`), R5a capability/objects tests (m:
  `unknown_ckms_survive_the_unfiltered_mechanism_list`,
  `listed_vendor_mechanisms_resolve_by_pykcs11_name`; n: the pyca gate of
  `key_material_is_gated_by_pycas_der_loaders`).

**D13 — Ctrl-C while a command runs is honored at step boundaries.**
- *Description*: c2's `KeyboardInterrupt` surfaced at the next Python bytecode after the
  current C call returned. r2's `ctrlc` handler only sets a flag, which commands and
  services check at step boundaries (between copy-ladder rungs, between batched provider
  calls, before writing output), so a long pure-software computation (e.g. an RSA-4096
  generation in memory) completes before `Aborted.` is printed. A blocking PKCS#11 call is
  uninterruptible in both.
- *Reason*: Rust has no asynchronous exceptions; the flag design is the single-thread-safe
  equivalent (S0 terminal spike).
- *Verified by*: R7/R10 tests that set the flag between steps.

**D14 — Parse-error caret column measured in display width.**
- *Description*: `ParseError.pos` and token positions are byte offsets into the UTF-8 line;
  the caret is placed at the display width of the row text before the offset as the
  echoed row is laid out (rich cell widths, BEL/BS/VT/FF/CR stripped, tabs expanded to 8
  columns; the row itself is echoed exactly as c2's rich did). c2 used the character
  index. The caret lands in the same column wherever every preceding character is one
  cell wide (ASCII text, Cyrillic labels); it differs when wide characters (CJK, emoji:
  2 cells), zero-width ones (combining marks, ZWJ/VS16 sequences, ZWSP, C0/C1 controls
  incl. the stripped CR) or a TAB (expanded to the next multiple of 8) precede the error —
  in every such case r2's caret sits under the offending character on screen, c2's did
  not.
- *Reason*: byte offsets are the native Rust string index; display width is the correct
  column (S0 terminal spike).
- *Verified by*: R7 parser/render tests; ported c2 vectors with non-ASCII text are converted
  explicitly.

**D15 — SoftHSM wizard: shared-module guard and byte-measured label limit.**
- *Description*: (a) re-pointing `SOFTHSM2_CONF` requires finalizing and re-initializing the
  SoftHSM module; when another configured provider shares the same library path and holds
  the module (same canonical path, §4.5.5 / D21), r2 stops the wizard instead of finalizing: after step 1 (the conf files are
  written and stay), `TokenInit::set_env_and_reset` refuses — touching neither the
  environment nor the module — with `Provider` `'<name>' shares its PKCS#11 module with
  another provider`, hint `restart r2 after the setup, or remove the other provider entry`
  (c2 shut down only its own provider: PyKCS11's refcounted unload then skipped
  `C_Finalize`, the module kept its old conf, and the fresh token was not found). (b) The
  32-label limit (prompt text unchanged: `Token labels are limited to 32 characters
  (CK_TOKEN_INFO) — use a shorter one.`) is measured in UTF-8 bytes; c2 counted characters,
  so a non-ASCII label of ≤ 32 characters but > 32 bytes was accepted by c2 and is re-asked
  by r2 (cryptoki's `init_token` would silently truncate it). As a backstop,
  `TokenInit::init_token` itself refuses such a label with `Param` `token label must be at
  most 32 bytes` (an r2 text; unreachable through the wizard). (c) `TokenInit::init_token`
  runs its SO session (login SO, C_InitPIN, logout) on the provider's one backend session:
  once that session is opened (after C_InitToken succeeded), a session the provider held — kept after `logout`, or a
  user login — is closed and the provider reports logged out; c2 opened a separate
  PyKCS11 session and left its own session and login untouched. A failure before that
  (e.g. C_InitToken with a wrong SO PIN) leaves the provider's session as it was. Unobservable through the
  wizard, which only runs from `login` while logged out (where a fresh login opens a new
  session anyway).
- *Reason*: cryptoki module-state semantics (one context's `C_Finalize` kills every session
  on the path) and label truncation, S0 cryptoki spike.
- *Verified by*: R11 wizard tests (shared-path case, multibyte label); R5a session tests
  (c: `init_token_on_a_logged_in_provider_ends_its_login`,
  `failed_init_token_keeps_the_provider_session`).

**D16 — NUL bytes in OpenSSL C-string parameters (PKCS#12 parse path only).**
- *Description*: rust-openssl's `Pkcs12::parse2` `CString::new(..).unwrap()`s the
  password, so r2 checks it first: a PKCS#12 password containing NUL gets c2's
  wrong-password text `incorrect password for PKCS#12 (or corrupt PKCS#12 data)` without
  calling OpenSSL (pyca's own `load_pkcs12` panicked in the same call; c2 crashed). The
  build paths have no such guard: `build_pkcs12` is r2's native writer (no OpenSSL
  builder, no C string) and the encrypted-PKCS#8 writers pass pointer + length, so a NUL
  in an export password or a PKCS#12 friendly name works as in c2. Only reachable through
  piped input or files, since a terminal cannot type NUL.
- *Reason*: rust-openssl would panic (S0 OpenSSL spike); OpenSSL's `PKCS12_parse` takes a
  C string, so such a password cannot be passed to it.
- *Verified by*: R6 keyparse test `pkcs12_password_with_nul_is_the_wrong_password_text`;
  the build paths' parity by R6 x509build/formats tests
  (`pkcs12_nul_bytes_are_ordinary_characters`, `nul_in_the_password_is_an_ordinary_byte`).

**D17 — YAML parser-level differences.**
- *Description*: r2 types YAML exactly like PyYAML 6.0.3 `safe_load` and writes it
  byte-identically to `safe_dump` (§4.8.4), but its syntax parser is `yaml-rust2` (YAML
  1.2), not PyYAML's: (a) the parser text inside `invalid YAML in config file <path>:
  <text>` / `invalid YAML in template file <path>: <text>` differs (construction errors —
  unknown tag, unhashable key, several documents — use PyYAML's wording); (b) inputs that
  only one of the two parsers rejects (exotic or malformed syntax: tabs in indentation,
  YAML-1.2-only escapes, directives) may load in one and fail in the other — among them,
  a top-level block scalar with unindented content is rejected (`unindented block scalar
  content at line <l>, column 1`; PyYAML's minimum indentation is 1, so such a line ends
  the scalar, and YAML 1.2 would load it as content); (c) an integer
  literal outside -2^63..=2^64-1 is a parse error `integer out of range: <text>`, where
  Python's int is unbounded; (d) the explicit collection tags `!!set`, `!!omap` and
  `!!pairs` (which PyYAML's SafeLoader constructs as `set` / list of pairs) are rejected
  with `could not determine a constructor for the tag 'tag:yaml.org,2002:set'` (resp.
  `omap`, `pairs`); (e) aliases are expanded into copies: a recursive alias (an anchored
  collection that contains its own alias) is an error, a duplicate anchor name silently
  rebinds (PyYAML: `found duplicate anchor`), and a document is rejected beyond a nesting
  depth of 400 (PyYAML hits CPython's recursion limit, a crash in c2, between 400 and 500)
  or beyond 1,000,000 values after alias expansion, or beyond 64 MiB (67,108,864 bytes) of
  scalar text copied by alias expansion (`document too large: …`; PyYAML shares the
  aliased object, so a "billion laughs" document, or many aliases of a large scalar,
  loads there); consequently `yaml::dump` never emits the
  `&id001`/`*id001` anchors that PyYAML writes for a collection object shared twice — this
  is visible only when the wizard's structural rewrite (§5.13) re-dumps a user config that
  aliases a mapping or list (r2 writes the copies); nested `<<` merge lists count against
  the same 1,000,000-value budget while they are flattened; (f) a literal LS or PS
  character (U+2028/U+2029) anywhere in the text is rejected with `unsupported line break
  character U+2028 at line <l>, column <c>` (PyYAML treats both as line breaks, keeping the
  character itself in folded content; yaml-rust2 treats them as ordinary characters, so the
  same text would load to a different value). NEL (U+0085), PyYAML's third extra break, is
  normalized to `\n` before parsing and loads exactly like PyYAML.
- *Reason*: no maintained Rust YAML 1.1 parser exists; the event parser is the only way to
  see scalar styles (§4.8.4).
- *Verified by*: R2 loader tests (typing vectors generated with PyYAML, the cases above:
  `yaml::tests::load_r2_errors`, `yaml::tests::alias_expansion_rules`,
  `yaml::tests::nested_merges_hit_the_value_budget`,
  `yaml::tests::aliased_large_scalar_hits_the_byte_budget`), R14 template-file
  tests, the R13 config interop check.

**D18 — Numeric range and load-time typing guards.**
- *Description*: Rust's fixed-width integers and typed config make r2 reject some values
  earlier or differently than c2:
  - a ref's `@<digits>` that overflows u64 → Parse `handle out of range` at the `@`+1
    offset (c2 accepted any integer; the lookup then found nothing);
  - an INT parameter outside i64 → `<name>: invalid integer <text!r>` (c2: unbounded);
  - a negative template ULONG → config: Config `<path>: must not be negative` at load;
    template file: Param `template attribute <name> must not be negative` at load (c2
    raised the latter only at the first create flow);
  - `custom_mechanisms[].params[].default` is typed by its `kind` at load (`expected a
    <kind> default, got <T>`, `keyref parameters cannot have a default`, or a BYTES
    default's `decode_data` CodecError text) — also where c2 never read the default (a
    `required` param, the default: c2's ParamResolver uses `default` only when not
    required; or a name the packer ignores), so a c2 config carrying such a mistyped
    default ran in c2 and fails to load in r2; where c2 did read it, c2 failed at
    invocation; an explicit `default: null` is
    absent for every kind, and an ENUM default written as a YAML int stays an integer
    (`ParamValue::Int`), so c2's gcm-packer behaviour is unchanged (§4.8.3);
  - a numeric builtin param read through `params::param_int` whose text is outside i64
    → `parameter '<name>' must be an integer, got <text!r>` (c2: unbounded int);
  - `providers.pkcs11[].slot` must not be negative (c2 accepted it);
  - an integer config value above its field's Rust type — `app.log.backups` above
    4294967295, `ui.hex_group`/`ui.hex_width` above `usize::MAX`, an INT or ENUM
    `params[].default` above 9223372036854775807 — is a load error `<path>: must be at most
    <max>` (c2 accepted any int; §4.8.3);
  - a custom-mechanism parameter declared `required: false` without a default is ABSENT
    when not given, so the packer default applies (c2 stored `None` and the packer raised
    `custom mechanism parameter <name!r> must be …`, §4.6.3);
  - numeric text read through `text::py_int` (template-editor ULONG values, `param_int`)
    and an explicit `!!int`/`!!float` YAML scalar (`yaml::parse`, which otherwise follows
    Python's `int()`/`float()`: surrounding whitespace, sign, base prefix) accept ASCII
    digits only (CPython's `int()` also accepts other Unicode decimal digits); `select`
    answers and template-editor row numbers are gated by `text::py_isdigit` (c2
    `str.isdigit()`), which is ASCII-only too: CPython's `isdigit()` also accepts e.g.
    superscript digits, for which c2's following `int()` then raised (unexpected-error
    path) and r2 answers "invalid choice …" / "… is not a row number";
  - `text::py_os_error_str` always renders the POSIX `[Errno n] …` form (CPython on Windows
    prints `[WinError n] …` for some calls).
- *Reason*: `u64`/`i64`/`u32` types at the API boundary; typed config.
- *Verified by*: R1 parse_ref/text tests, R2 decoder tests, R3 packer tests, R7 resolver
  tests, R10 editor tests, R14 template-file tests.

**D19 — Command-line parser texts (clap).**
- *Description*: `r2 --help`, the usage line and argument-error texts are clap's (c2:
  argparse — `usage: c2 [-h] [--version] [--config PATH] [--debug]`, `c2: error:
  unrecognized arguments: …`). The options and their semantics (`--version` → `r2
  <version>`, `--config PATH`, `--debug`) and exit status 2 for usage errors are unchanged.
- *Reason*: decision PLAN §13 (clap).
- *Verified by*: R7 `assert_cmd` tests (exit status, `--version`).

**D20 — Hidden input shows nothing.**
- *Description*: secret prompts (PIN, passwords) echo nothing while typing (rpassword) and,
  in piped PlainIo, write only a newline; c2's prompt_toolkit `is_password` session echoed
  one `*` per character — on a terminal and in piped transcripts — revealing the length.
- *Reason*: rpassword cannot mask; not revealing the length is the safer behavior.
- *Verified by*: R7 PlainIo tests; the parity harness normalizes c2's `*` run (§8).

**D21 — PKCS#11 modules are shared by canonical library path.**
- *Description*: r2 keys its per-thread module registry by `std::fs::canonicalize` of the
  expanded library path (§4.5.5); PyKCS11 keyed `_loaded_libs` by the filename string. Two
  providers naming one library through different spellings (a symlink and its target, a relative
  and an absolute path) share one module and one `C_Initialize` in r2. In c2 they
  held two registry entries over one dlopen handle, so the first `shutdown` (or the wizard's
  re-init) called `C_Finalize` and silently killed the other provider's sessions, and the
  wizard's shared-module guard (D15) could not see the sharing. With identical spellings
  both behave the same.
- *Reason*: cryptoki module-state semantics (one context's `C_Finalize` breaks every
  session of that module, S0 cryptoki spike 1 R.6); Debian/Ubuntu ship
  `/usr/lib/softhsm/libsofthsm2.so` as a symlink and both spellings are in §7's search
  paths.
- *Verified by*: R5a SoftHSM symlink test (§4.5.5); R11 wizard shared-path test.

**D22 — Windows path normalization.**
- *Description*: r2 reproduces `pathlib.Path(text)`'s lexical normalization at every c2
  path site (`r2_core::text::py_path`, §4.2): exactly on POSIX. On Windows it applies the
  same rules with `/` and `\` both as separators and `\` on output, but keeps a drive
  (`C:`), UNC (`\\server\share`) or verbatim (`\\?\`) prefix as typed, where
  `PureWindowsPath` also normalizes prefixes by its own rules (e.g.
  `//server/share/x` → `\\server\share\x`, drive-relative `C:x`). Such paths may print
  differently in messages; they open the same files.
- *Reason*: a full `PureWindowsPath` port buys nothing for operators; c2 did not test
  Windows path rendering.
- *Verified by*: R1 `py_path` unit tests (POSIX vectors generated with CPython; Windows
  vectors under `cfg(windows)` for the plain cases).

**D23 — Emoji shortcodes in printed text are not replaced.**
- *Description*: c2 printed every plain string with rich's default `emoji=True`, so any
  `:name:` that is a rich emoji code was replaced in the output — on terminals and in
  piped sessions alike (e.g. `generate mem aes --label x:ok:y` printed `generated mem❌ok:y
  (256-bit aes)`; `:key:`, `:id:`, `:lock:`, `:a:` … are emoji codes too). Labels, refs,
  paths and data are data: r2 prints them verbatim. Panels, tables, titles and the caret
  echo were never affected in c2 (they were rich `Text`).
- *Reason*: a c2 bug — output must not alter labels or refs the operator copies back into
  commands.
- *Verified by*: R1 renderer tests (`Renderable::Text` keeps `:x:`; the generated
  plain-text vectors assert that no input depends on emoji replacement).

**D24 — (withdrawn).** r2 writes PKCS#12 with a port of pyca's own writer (§4.4.4), so
`export … --format p12` takes every certificate pyca loads, as c2 did (it previously needed
one OpenSSL's `X509` decoder accepts). Verified by R6 x509build tests
`pkcs12_of_a_certificate_openssl_cannot_decode_is_built_as_pyca`,
`pkcs12_friendly_names_outside_the_bmp_are_utf16`.

**D25 — Library warnings are not printed.**
- *Description*: pyca emitted Python warnings that c2 did not filter, so they reached the
  operator's stderr (once per call site): `CryptographyDeprecationWarning: Parsed a serial
  number which wasn't positive …` when loading a certificate with a zero or negative
  serial (`load`, `key info`, `export`), `UserWarning: Attribute's length must be >= 1 and
  <= 64 …` when decoding a Name with an out-of-range CN/C length, and `UserWarning: PKCS#12
  bundle could not be parsed as DER, falling back to parsing as BER …`. r2 loads, shows and
  exports the same objects with the same output, without the warning text.
- *Reason*: library diagnostics with source paths, not c2 output; nothing is refused.
- *Verified by*: R6 differential runs (identical results, c2's stderr warnings ignored).

**D26 — RSA PKCS#1 v1.5 decrypt failures follow the linked OpenSSL.**
- *Description*: c2's pyca bundles OpenSSL ≥ 3.2, whose PKCS#1 v1.5 decryption uses
  implicit rejection: a malformed ciphertext or a wrong key yields pseudo-random plaintext
  and no exception (memory `decrypt … pkcs1`; the RSA-PKCS1 unwrap then goes on with the
  pseudo-random payload and fails, if at all, in the material checks). r2's MemoryProvider uses the linked OpenSSL: the
  vendored release build (3.6.3, §9) behaves as c2; a source build against OpenSSL < 3.2
  (e.g. the system 3.0.13) raises Crypto `RSA-PKCS1 decryption failed` resp. `RSA-PKCS1
  unwrap failed` instead. Valid ciphertexts decrypt identically everywhere.
- *Reason*: the failure semantics are OpenSSL's, not r2's; implementing implicit rejection
  in r2 code would duplicate a constant-time OpenSSL routine.
- *Verified by*: R4 `memory_wrap_kek::test_pkcs1_unwrap_of_a_bogus_blob_leaks_no_padding_detail`
  (accepts both outcomes, as c2's test does).

**D27 — Memory: NONE (outside DATA) and OTHER material is a `Param` error.**
- *Description*: c2's MemoryProvider raised KeyParseError for material whose algorithm is
  NONE outside a data object, OTHER, or declared NONE/OTHER but parsing as something else
  (`unsupported secret key algorithm 'other'`, `material declares algorithm 'none' but data
  parses as 'ec'`, `data objects carry no algorithm (got 'other')`), on import and unwrap.
  r2 follows the §4.3/§4.5.2 contract (which c2's own spec also stated): kind `Param`
  (`material`), with c2's messages, hints and check order unchanged. Unreachable from the
  console (hints never produce NONE/OTHER material); visible only to API callers.
- *Reason*: c2 internal inconsistency (spec vs memory code) resolved in favour of the spec.
- *Verified by*: R4 `memory_parity::none_and_other_material_is_a_param_error_with_c2_text`.

**Resolved without deviation** (recorded so they are not mistaken for gaps):

- `DEK-Info: DES-CBC` traditional encrypted PEM: OpenSSL with the legacy provider could load
  it, pyca/c2 refuse it — r2 rejects it explicitly with c2's message (§5.4).
- Legacy PKCS#12 (RC2-40, 3DES, SHA-1 MAC): loads in both (pyca also enables OpenSSL's
  legacy provider); r2's vendored build has the provider compiled in (§5.4, §9).
- `CKA_VALUE_LEN` unwrap retry: c2's trigger set is ported verbatim; SoftHSM's
  `CKR_ATTRIBUTE_READ_ONLY` answer stays outside it (§5.4 field note).
- ULONG attribute values equal to `CK_UNAVAILABLE_INFORMATION` are reported numerically, as
  PyKCS11 did (§5.16).
- `C_Initialize` arguments (`CKF_OS_LOCKING_OK`, no mutex functions) and per-path module
  sharing match PyKCS11 (§5.2); only the sharing key differs (canonical path, D21).
- Random and salt-dependent encodings are not normative and may differ byte-wise between
  runs and builds in both implementations: PBKDF2 salt length of encrypted PKCS#8 (8 or 16
  bytes by OpenSSL version) and PKCS#12 MAC salt, OAEP/PSS/ECDSA outputs, certificate serial
  numbers. Their algorithms, iteration counts and parameters are normative (§5.6).
- Wire-level mechanism-parameter details invisible at the console: an empty GCM AAD and an
  empty ECDH `shared_data` are passed as non-NULL zero-length pointers (c2: non-NULL resp.
  NULL); SoftHSM accepts both (§5.8, §5.10).
- Piped/plain transcripts are compared after normalizing c2's prompt_toolkit non-TTY noise
  and its `*` secret masks; the remaining content (prompts, echoed lines, results, errors)
  is identical (D2 covers the noise itself, D20 the masks).
- YAML typing (plain vs quoted `yes`, `017`, `0b…`, `1:30`, `1e3`, timestamps, merge keys,
  duplicate keys) and YAML output bytes match PyYAML (§4.8.4); only parser-level details
  remain (D17).
- CKO/CKK/CKC/CKM/CKR names are PyKCS11 1.5.18's tables (§4.5.5), so error texts,
  `CKA_KEY_TYPE` cells and template dumps name exactly what c2 names (codes PyKCS11 cannot
  name keep c2's `CKR_0x%08X` / `0x%08x` fallbacks).
- Terminal/colour detection and console width follow rich 15 exactly (§4.9.2, §4.9.7); only
  plain-text highlighting and the legacy-Windows-console renderer differ (D1).
- Text layout (control-code stripping, tab expansion, fold wrapping at the console width)
  and rich's cell widths (ZWJ/VS16 graphemes) are reproduced for printed strings, the caret
  echo and panels (§4.9.2).
- `difflib` suggestions match CPython including tie order (§4.2).
