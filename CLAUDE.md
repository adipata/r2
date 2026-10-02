# r2 — agent guide

r2 is the Rust rewrite of c2, an interactive cryptographic operator console, held to full
behavioral parity with c2. It runs a REPL (`r2>`; reedline + rpassword on a TTY, a plain
line reader otherwise) over pluggable providers: memory (via the `openssl` crate) and
PKCS#11 (via `cryptoki` 0.12, including auto-detected SoftHSM2). It ships as a single
binary, `r2`. It is a Cargo workspace on edition 2024, with the toolchain pinned in
`rust-toolchain.toml`, licensed GPL-3.0.

## Before you write code

1. **Read `spec.md` §4.** Every cross-crate interface is FROZEN there: crate and module
   paths, exact signatures, derives, constants and schemas. Never invent or alter one. If
   §4 must change, follow spec §4.11. Spec §11 is the closed list of deviations from c2;
   any other observable difference is a parity bug.
2. **Read `loops.md`.** Check the STATUS table (and `git log --oneline` against it), then
   your loop's card: Owns, Ports, Depends on, Accept. Touch only the files your loop owns,
   plus your tests, your STATUS row and your ledger rows.
3. **List your rows in `parity/ledger.csv`** with
   `python3 parity/generate_ledger.py --stats --gate <ID>`. These are the c2 tests you
   must port (or mark `n/a:<reason>` for pure-Python mechanics). Rules are in
   `parity/README.md`.
4. **The Python reference is the behavioral oracle.** It lives at `../c2` (`/home/user/c2`
   in this environment), frozen at 408d6f2. Never modify it. Read the c2 source and tests
   your card names. Port test vectors, inputs and asserted messages/hints **verbatim**
   (c2 → r2 only where the text names the tool), and translate only the mechanics. To
   check what c2 actually does, run it: `cd ../c2 && uv run c2` or
   `uv run pytest tests/...::test_x`.

## Commands

- Build:              `cargo build --workspace`
- Run app:            `cargo run -p r2-cli -- --version` (binary `r2`; flags `--version`,
                      `--config PATH`, `--debug`)
- Unit tests:         `cargo nextest run --workspace` (nextest is normative; `cargo test
                      --workspace` is only a fallback and not the gate)
- SoftHSM tests:      `eval "$(scripts/softhsm-init.sh)"` then
                      `cargo nextest run --workspace --features softhsm`
- Single test:        `cargo nextest run -p r2-core --test keys parse_ref_` (or
                      `cargo nextest run -E 'test(=module::test_name)'`)
- Format:             `cargo fmt` and `rustfmt --edition 2024 crates/r2-console/src/commands/*.rs crates/r2-console/src/tests/*.rs`
                      (those modules are `include!`-only, so `cargo fmt` cannot see them)
- Lint:               `cargo clippy --workspace --all-targets -- -D warnings`
- Supply chain:       `cargo deny check`
- Ledger gate:        `python3 parity/generate_ledger.py --stats --gate <ID>`
- Coverage (≥ 80%):   `cargo llvm-cov nextest --workspace --fail-under-lines 80` (CI adds
                      `--features softhsm`)
- Parity vs c2:       `python3 parity/harness/run_parity.py [--softhsm]` (c2 at `../c2` with
                      `uv sync`; see `parity/harness/README.md`)

The `justfile` wraps these. Keep builds lean (4 CPUs): reuse the target dir, and don't
run parallel cargo invocations.

## Layout

```
crates/r2-core      errors, text (py_repr…), key model + ref grammar, template, params,
                    ConsoleIo/TemplateEditor traits, Renderable + renderer, runtime flags,
                    codec, datainput, keyparse, x509build, x509info, formats, der, crypto,
                    CKA_CATALOG (third-party only: openssl, der/x509-cert/spki, …)
crates/r2-config    defaults.yaml (include_str!), loader, model (importable anywhere),
                    decoder, PyYAML-faithful yaml, dirs
crates/r2-provider  Provider trait + types, ProviderRegistry, lookup, rsa_raw, mechanism names
crates/r2-ops       OperationSpec/Registry, builtins (aes/rsa/ec/generic), custom, ParamResolver
crates/r2-memory    MemoryProvider (openssl)
crates/r2-pkcs11    Pkcs11Provider; Backend seam (CryptokiBackend + FakeBackend); only
                    `catalog` and `softhsm` are pub modules; the ONLY cryptoki user
crates/r2-services  keyload, keyexport, certops, transfer, templatefile, wrapload
crates/r2-console   REPL, io (TerminalIo/PlainIo), parser, completer, render (Sink),
                    commands/ (discovered by build.rs), template_editor, wizard
crates/r2-cli       the `r2` binary: args, bootstrap, logging, panic hook
crates/r2-testkit   dev-dependency only: ScriptedIo, RecordingEditor, FakeProvider,
                    provider_contract_tests!, fixtures, softhsm fixture, set_env
parity/             ledger.csv + generator (S0); differential harness vs c2 (R13)
scripts/            softhsm-init.sh, build-softhsm.sh, release/
```

## Conventions

- **Layering is the crate graph** (spec §4.1.2). An edge or third-party dependency not
  listed there is forbidden (adding one is a §4.11 change). Nothing depends on
  `r2-console` except `r2-cli`, and only `r2-cli` calls `load_config`.
- **Errors.** Every fallible public fn returns `r2_core::Result<T>` (one `ConsoleError {
  kind, message, hint }`). The only exception is the crate-private PKCS#11 backend seam,
  translated at one choke point. `Command::run` returns `Result<Flow>`; exit is
  `Flow::Exit`, not an error. Errors are rendered ONLY by the REPL loop: commands and
  services return `Err`, never print.
- **No `println!`/`eprintln!`** (`clippy::print_stdout`/`print_stderr` = deny). All output
  goes through `ctx.io` (the `ConsoleIo` trait). The few allowed print sites are listed in
  spec §4.1.3.
- **No `unwrap`/`expect` outside tests** (deny). No panics as control flow. `Drop` guards
  never panic.
- **Single-threaded** (spec §6). `std::thread::spawn` is disallowed: the ctrlc handler and
  the indicatif ticker are the only threads. Providers, IO and the registry are
  `!Send`/`!Sync` and use `Rc`/`RefCell` with `&self` methods. Never hold a `RefCell`
  borrow across a call into another trait object (spec §4 re-entrancy rule).
- **`unsafe`.** `#![forbid(unsafe_code)]` everywhere except `r2-pkcs11` and the dev-only
  `r2-testkit`, which use `deny` with an `#[allow]` + `// SAFETY:` only at the audited
  sites of spec §4.1.3 (raw shim, `mech_type`, `obj`, the one `set_var` in
  `r2_pkcs11::env`, and `r2_testkit::env`). A new site is a §4 change.
- **cryptoki only inside `r2-pkcs11`'s backend** (the PyKCS11 rule). No cryptoki type
  appears in a `pub` item. Every call is translated at the single CKR choke point per the
  spec §5.2 table. Respect the `disallowed-methods` in `clippy.toml` (the lossy cryptoki
  APIs, the OpenSSL PEM/passphrase/`aes::wrap_key` hazards, `is_terminal`, env mutation).
- **Secrets** use `secrecy::SecretString` for PINs and passwords, and
  `zeroize::Zeroizing<Vec<u8>>` for key material, transport keys, decrypted data and
  derive results. Never log or echo PINs, passwords, key bytes or plaintext. Log lengths,
  labels, mechanism names and CKR codes (via `tracing`).
- **Commands.** Each `crates/r2-console/src/commands/<stem>.rs` exports
  `pub fn commands() -> Vec<Box<dyn Command>>` and is discovered by `build.rs`. Never add a
  central registration table.
- **Naming** is `r2` everywhere (binary, prompt, `r2.yaml`, `$R2_CONFIG`, dirs, token
  `R2TEST`), and messages naming the tool say r2 (§11 D7). Byte offsets everywhere (§4).

## Testing rules

- Never a real HSM in tests. SoftHSM tests are behind cargo feature `softhsm`, use
  `r2_testkit::softhsm::{softhsm_token, unique_label}`, and **fail** (never skip) when the
  fixture env from `scripts/softhsm-init.sh` is missing. Default-feature tests need no
  PKCS#11 module.
- Console, ops and services tests use `r2_testkit::FakeProvider`. `FakeBackend` exists
  only for `r2-pkcs11` internals (`crates/r2-pkcs11/src/tests/`). Each provider
  instantiates `provider_contract_tests!` in its own test file.
- Interactive flows use `ScriptedIo` (queued answers) / `RecordingEditor`, not terminal
  automation. Console in-crate tests use `r2_console::testing::CtxBuilder` and `run_line`.
  REPL-level tests drive the real binary with `assert_cmd` (piped stdin), with `insta`
  snapshots for layouts.
- Tests touching process-global state (env, runtime flags, a PKCS#11 module) hold
  `r2_testkit::global_state_lock()`, and change env only via `r2_testkit::set_env`.
- r2-core and r2-provider tests that use r2-testkit must be integration tests
  (`crates/<crate>/tests/`), not in-file modules (spec §4.1.1).
- Don't modify or delete tests owned by other loops.

## Definition of done (every loop)

```sh
cargo fmt --check
rustfmt --edition 2024 --check crates/r2-console/src/commands/*.rs crates/r2-console/src/tests/*.rs
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
cargo deny check
python3 parity/generate_ledger.py --stats --gate <ID>
```

All of these must be green, plus `cargo nextest run --workspace --features softhsm` when
SoftHSM is present (CI runs it regardless, on 2.6.1 and 2.7.0). Your STATUS row in
`loops.md` and your `parity/ledger.csv` rows (`ported` + Rust test IDs, or
`n/a:<reason>`) are updated in the same PR, or in the same `R<n>:` commit series.
