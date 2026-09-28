# r2 — plan for rewriting the c2 console in Rust

Status: **draft for review** · Baseline: [`adipata/c2@408d6f2`](https://github.com/adipata/c2/commit/408d6f29aa968ad4afcd7888b5958ba4608c902c)
(2026-08-21, "Manage certificates, generic keys and data objects" — L0–L16 all `done`).

This document plans the Rust rewrite. Its first execution step (S0, §8) turns it into
the working documents that agents code against: a Rust `spec.md` (frozen contracts), a
`loops.md` (STATUS + loop cards) and a `CLAUDE.md`, the same workflow that built c2.

---

## 0. Summary

- **Scope:** full feature parity with c2 as specified in its `spec.md`, in its final
  state (L0–L16 merged). The rewrite ports the **final spec, not the history**: generic
  secrets/HMAC, data objects, `other`, template files and `--kek` are designed in from the
  start rather than retrofitted. No new features until parity is signed off.
- **Compatibility contract:** the command grammar, ref grammar, messages and hints,
  config schema, discovery and `defaults.yaml`, PKCS#11 object layouts, and every file
  format (exports, wrapped blobs, template YAML, history) stay identical. A token or
  config file used by Python c2 works unchanged with Rust c2, in both directions.
- **Stack:** `cryptoki` (PKCS#11), `openssl` (memory provider, key formats, PKCS#12),
  `der`/`x509-cert` (CSR assembly with an external signer), `rustyline` + `rpassword`
  (REPL), `comfy-table` + `anstream` (rendering), `serde_yaml_ng` behind a hand-written
  typed decoder (config), `tracing` (logging), `clap` (CLI).
- **Architecture:** a Cargo workspace whose crate graph is exactly spec §3.1's layer
  graph, so the compiler enforces the layering that code review enforces in c2. Providers
  are `!Send`/`!Sync`, so the type system also enforces spec §6's single-thread invariant.
- **Execution:** 18 loops (S0, R0–R15, with the PKCS#11 provider split into R5a/R5b)
  in 7 waves. Numbering mirrors c2's L-numbers where a loop has a direct counterpart.
  Critical path: S0 → R0 → R1 → R3 → R5a → R5b → R10 → R13.
- **Contract-first skeleton:** R0 turns the frozen §4 signatures into compiling stubs.
  This replaces Python's "code against unmerged interfaces", which Rust can't do because
  it needs the code to compile.
- **Verification:** each of c2's ~1,280 tests is mapped to the R-loop that ports it
  (a parity ledger). The Python implementation also serves as a live **differential
  oracle**: the same piped sessions and cross-loaded artifacts, plus a shared SoftHSM
  token that both implementations read and write.

## 1. Scope and baseline

| c2 today (measured at 408d6f2) | |
|---|---|
| Source | ~15,000 lines Python (largest: `pkcs11/provider.py` 2,889, `memory.py` 1,504, `keys_cmd.py` 1,210) |
| Tests | ~23,500 lines, ~1,280 test functions (core 94, console 382, pkcs11 185, services 132, contract 34, integration 54, top-level unit ~400) |
| Spec | `spec.md` 2,127 lines; §4 frozen contracts, §5 behavior, §7 embedded defaults |
| Distribution | PyInstaller one-file binary (~18 MiB), per-OS release matrix |

**In scope:** everything in c2 `spec.md` §1–§9, including the L13–L16 fold-backs and
field fixes recorded in `loops.md` (Utimaco handle/KWP-dialect fixes, CKA_VALUE_LEN
injection, the twin guard, identity-row precedence, and so on). These encode hard-won
token behavior and are ported as requirements.

**Out of scope for the rewrite:** everything in c2 §10 (batch mode, SoftHSM bundling,
new provider types, CKU_SO flows), and any new feature. Improvements are allowed only
where Rust gives them for free and they don't change observable behavior (§7.2).

**Rust c2 goals:** a single native binary with instant startup and a smaller size,
memory safety at the PKCS#11 FFI boundary, real zeroization of key material, PINs and
transport keys, and compile-time enforcement of the architecture rules.

## 2. Approach

1. **The spec stays the single source of truth.** S0 ports c2 `spec.md` to r2: §1–§3
   are adapted, §4 is rewritten as Rust signatures (§5 below gives the shapes), §5–§10
   are carried over with backend substitutions (pyca → OpenSSL, PyKCS11 → cryptoki,
   prompt_toolkit → rustyline, rich → comfy-table), and a new **§11 "Deviations from
   c2"** lists every intentional difference. Anything not listed there is a parity bug.
2. **Same multi-agent working agreement as c2.** One loop = one branch = one PR,
   exclusive file ownership, a STATUS table with single-line rows, and the §4.11
   contract-change procedure. Branch naming: `loop/R05a-pkcs11-foundation`.
3. **Contract-first skeleton.** R0 materializes every frozen §4 item (types,
   traits, free functions, plus the cross-loop hook functions in §8) as compiling code.
   Stub bodies return `ConsoleError` "not implemented (Rn)" rather than panicking, where
   a return type allows it. Owning loops replace the bodies, which is a sanctioned
   handoff, like c2's stub `app.py`. Every loop compiles against real signatures from
   day one, and merge-order edges still gate *merging*, not development.
4. **Port tests as the executable spec.** Each loop ports the Python tests it owns
   (per the parity ledger), keeping test vectors, inputs and asserted messages verbatim,
   and translating only the mechanics.
5. **Parity first, idiom second.** Where Python idiom and Rust idiom disagree, the Rust
   shape changes (enums instead of `object`, `Result` instead of exceptions) but
   observable behavior does not.

## 3. Technology mapping

| Concern | c2 (Python) | r2 (Rust) | Why |
|---|---|---|---|
| PKCS#11 | PyKCS11 (SWIG) | **`cryptoki`** (+ `cryptoki-sys` constants; a narrowly scoped `unsafe` shim only for proven gaps) | Safe wrapper, dynamic loading, typed CKR errors, `VendorDefined` attributes and mechanisms. Constants resolve at compile time from `cryptoki-sys`, the equivalent of "resolve CKM numerics from PyKCS11, never hardcode". |
| Memory-provider crypto, key parsing, PKCS#12, X.509 | pyca/cryptography (OpenSSL-backed) | **`openssl`** crate, with the `vendored` feature for release builds | pyca *is* OpenSSL, so behavior is byte-identical (both KWP dialects, traditional encrypted PEM, legacy PKCS#12, Ed448/X448, OAEP with separate MGF hash and label, PSS salt lengths, CMAC, raw RSA). Pure-Rust RustCrypto has gaps here (Ed448/X448 maturity, PKCS#12 building, traditional encrypted PEM) and an open RSA timing advisory. |
| CSR with external signer | pyca builder + callback | **`der` + `x509-cert` + `spki` + `const-oid`** | Assemble `CertificationRequestInfo` and sign through the provider callback, which works for non-extractable HSM keys (c2 §5.7). OpenSSL's `X509ReqBuilder` needs a local private key. |
| REPL line editing | prompt_toolkit | **`rustyline`** (history hints, completion, bracketed paste) + **`rpassword`** (hidden input) | Mature, and falls back to plain stdin reads when not on a TTY, which piped tests and Windows piped smoke tests need. History is added explicitly, so filtering `--pin`/`--password` lines is trivial. c2's `…>` continuation already lives in the REPL loop, not the editor. `reedline` is the alternative if dropdown completion menus become a requirement. |
| Rendering | rich | **`comfy-table`**, **`anstream`/`anstyle`** (color policy, `NO_COLOR`), an own panel/hex-dump renderer, **`indicatif`** spinner | Same columns and content. rich's markup-eating bugs (`[#…]`, `[x]`) disappear by construction. |
| Config | PyYAML + dataclasses `from_dict` | **`serde_yaml_ng`** `Value` for parse, merge and emit, plus a hand-written typed decoder (path-aware errors) | Mirrors c2's explicit `from_dict(data, path)` design: deep merge on untyped trees, `origins`, unknown-key warnings. `serde_yaml` itself is archived. |
| "Did you mean" suggestions | `difflib.get_close_matches` | **`difflib`** crate | Same algorithm and cutoff, so the same suggestions. |
| Platform dirs | platformdirs | small own function replicating platformdirs' paths exactly | `dirs::config_dir()` differs on Windows (Roaming versus Local). Config discovery must find the same files. |
| CLI args | argparse | **`clap`** (derive) | `--version`, `--config PATH`, `--debug`. |
| Logging | stdlib logging, size-rotating file, `RedactingFilter` | **`tracing`** + `tracing-subscriber` + **`file-rotate`** (size-based, N backups) + a redaction layer | Keeps `app.log.max_bytes`/`backups` semantics (`tracing-appender` only rotates by time). |
| Secrets | `str`/`bytearray`, best-effort zeroization | **`secrecy`** (`SecretString` PINs/passwords, redacted `Debug`), **`zeroize`** (`Zeroizing<Vec<u8>>` for key material and transport keys) | Real zeroization, which is an improvement over c2 §5.5's CPython caveat. |
| Hex/base64 | stdlib | `hex`, `base64` (strict) | c2 §4.4 detection order is ported verbatim. |
| Tests | pytest, markers, fixtures | `cargo nextest`, `insta` (snapshots), `assert_cmd` (spawn the binary with piped stdin), `tempfile`, a cargo feature `softhsm` | See §9. |
| Coverage | pytest-cov, 80% floor | `cargo llvm-cov`, 80% floor | Same gate as c2 §8. |
| Packaging | PyInstaller | `cargo build --release`, vendored OpenSSL, glibc-baseline Linux builds | See §10. |
| Supply chain | uv.lock | `Cargo.lock` + **`cargo deny`** (advisories, licenses compatible with GPL-3.0, bans) | c2 is GPL-3.0 and r2 keeps that license. |

## 4. Workspace and layering

```
r2/
  Cargo.toml                 workspace; [workspace.lints]; shared dep versions
  rust-toolchain.toml        pinned stable (= MSRV), edition 2024
  clippy.toml  deny.toml  justfile
  .github/workflows/ci.yml  release.yml
  crates/
    c2-core/        error, keys (model + ref grammar), template, params, io (ConsoleIo,
                    TemplateEditor, Renderable), codec, datainput, keyparse, x509build, der
    c2-config/      model, loader, defaults.yaml (include_str!, byte-identical to c2 §7)
    c2-provider/    Provider trait + data types, ProviderRegistry, shared helpers (rsa_raw_modexp)
    c2-ops/         OperationSpec, OperationRegistry, builtins (aes/rsa/ec/generic), custom, ParamResolver
    c2-memory/      MemoryProvider (openssl)
    c2-pkcs11/      Pkcs11Provider, backend seam (cryptoki impl + fake), mechanisms, catalog, softhsm
    c2-services/    keyload, keyexport, certops, transfer, templatefile, wrapload
    c2-console/     repl, io (terminal + plain), parser, completer, render, commands/,
                    template_editor, wizard
    c2-cli/         the `c2` binary: args, logging, bootstrap
    c2-testkit/     (dev-dependency only) ScriptedIo, FakeProvider, provider_contract_tests!,
                    softhsm fixture
  parity/           differential harness vs Python c2 (R13; optional CI job)
  spec.md  loops.md  CLAUDE.md  README.md  PLAN.md
```

Crate dependency graph, which is c2 §3.1 made structural (no cycles possible; an edge
not listed doesn't compile):

```
c2-cli      → c2-console, c2-memory, c2-pkcs11, c2-config (incl. loader)
c2-console  → c2-services, c2-ops, c2-pkcs11 (catalog, wizard's init_token), c2-provider, c2-config, c2-core
c2-services → c2-ops, c2-pkcs11 (catalog only), c2-provider, c2-config, c2-core
c2-ops      → c2-provider, c2-config, c2-core
c2-memory   → c2-provider, c2-core
c2-pkcs11   → c2-provider, c2-config, c2-core, cryptoki
c2-provider → c2-config (model), c2-core
c2-config   → c2-core
c2-core     → std, openssl, der / x509-cert / spki
```

- `cryptoki` is a dependency of **`c2-pkcs11` only**, and no cryptoki type appears in
  its public API. This is c2's "PyKCS11 only inside `providers/pkcs11/`" rule, enforced by
  the compiler. The static `CKA_CATALOG` (plus the CKO/CKK/CKC/CKM symbol tables that
  `templatefile` needs) is a public module of `c2-pkcs11` with no cryptoki calls, so
  services and console may use it, as they use `attributes.py` today.
- Nothing depends on `c2-console` except `c2-cli`. `c2-config`'s `load_config` is called
  only by `c2-cli` (review rule; the model types are importable anywhere, as in c2).
- `openssl` is used by `c2-core` (keyparse, x509build), `c2-provider` (raw RSA modexp)
  and `c2-memory`, mirroring "core → stdlib + pyca".

Workspace lints and `clippy.toml` encode the c2 CLAUDE.md conventions:

| c2 convention | r2 enforcement |
|---|---|
| no `print()` (ruff T20) | `clippy::print_stdout`/`print_stderr` = deny (one allowed site: `--version`/early-startup errors in `c2-cli`) |
| no ad-hoc threads (spec §6) | `disallowed-methods`: `std::thread::spawn`. Allowed exceptions: the indicatif ticker and the Ctrl-C flag handler, which touch no app state. Providers are `!Send`/`!Sync` (`Rc`/`RefCell` inside), so misuse doesn't compile. |
| env mutation only before C_Initialize | `disallowed-methods`: `std::env::set_var`, with one audited `#[allow]` site in `c2-pkcs11` (edition 2024 makes it `unsafe`; the single-thread invariant is the safety argument) |
| no bare `except` / everything is a `ConsoleError` | every fallible public fn returns `c2_core::Result<T>`; `clippy::unwrap_used`/`expect_used` deny outside tests |
| mypy strict | the compiler, plus `#![forbid(unsafe_code)]` in every crate except `c2-pkcs11` (`deny`, audited `allow`s) |
| skeleton stubs are temporary | `clippy::todo`/`unimplemented` = warn until R13, deny from R13 |

## 5. Translating the frozen contracts (spec §4)

S0 writes these in full. The shapes below are binding decisions for S0. Python idioms map as follows:

| c2 construct | r2 translation |
|---|---|
| exception hierarchy + `isinstance` | one `ConsoleError { kind, message, hint }` with `ErrorKind` variants carrying the extra fields, plus family predicates (`is_provider()`, `is_key_lookup()`, `is_operation()`) |
| `ReplExit` (the documented exemption) | not an error: `Command::run` returns `Result<Flow>` with `Flow::{Continue, Exit}` |
| ABC with default methods | object-safe trait with default methods returning `UnsupportedOperation` |
| `Protocol` (ConsoleIO, TemplateEditor) | object-safe traits in `c2-core::io` |
| keyword arguments with defaults | request structs implementing `Default` (`GenerateRequest`, `UnwrapRequest`) |
| `object`-typed values | closed enums: `AttrValue`, `ParamValue` |
| `options: dict` escape hatch (wrap/unwrap) | typed `WrapOptions` struct; S0 enumerates fields from current call sites |
| frozen dataclass | `#[derive(Clone, Debug, PartialEq, Eq)]` struct, no interior mutability |
| string enums (`"p256"`, `"sha256"`, class tokens) | enums with `FromStr`/`Display` round-tripping the **exact** c2 tokens |
| `KeyInfo.handle: object` (plain int by rule) | `Option<u64>`. The Utimaco `repr` hazard can't occur. |
| `pkgutil` command auto-discovery | `build.rs` globs `commands/*.rs` and generates the `mod` list and aggregator. There is still no hand-maintained registration table. |
| lazy `importlib` editor wiring | direct construction; there are no optional modules in a Rust binary |
| `importlib.resources` defaults | `include_str!("defaults.yaml")` |

Core shapes (abridged; S0 fills in every item):

```rust
// c2-core::error
pub struct ConsoleError { pub kind: ErrorKind, pub message: String, pub hint: Option<String> }
pub enum ErrorKind {
    Generic, Config, Parse { line: String, pos: usize }, Codec, KeyParse, DataIo,
    Provider, ProviderUnavailable, ProviderNotFound, AuthRequired, AlreadyLoggedIn,
    Pkcs11 { ckr_code: u64, ckr_name: &'static str },
    KeyLookup, KeyNotFound, AmbiguousKey { candidates: Vec<KeyRef> }, DuplicateKey,
    KeyNotExportable,
    Operation, UnknownOperation, UnsupportedOperation, Param { param_name: String }, Crypto,
    UserAbort,
}
pub type Result<T> = std::result::Result<T, ConsoleError>;

// c2-core::keys
pub enum KeyClass { Secret, Private, Public, Certificate, Data }
pub enum KeyAlgorithm { Aes, Rsa, Ec, EcEdwards, EcMontgomery, Generic, None, Other }
pub struct KeyRef { pub provider: String, pub label: String, pub key_id: Option<Vec<u8>> }
pub struct KeyInfo {
    pub key_ref: KeyRef, pub key_class: KeyClass, pub algorithm: KeyAlgorithm,
    pub size_bits: Option<u32>, pub curve: Option<Curve>, pub exportable: bool,
    pub attributes: BTreeMap<String, AttrValue>, pub handle: Option<u64>,
}
pub struct KeyMaterial {
    pub algorithm: KeyAlgorithm, pub key_class: KeyClass,
    pub data: Zeroizing<Vec<u8>>,                 // canonical formats, c2 §4.3 table
    pub curve: Option<Curve>, pub size_bits: Option<u32>, pub label_hint: Option<String>,
}
pub struct ParsedRef { pub provider: String, pub label: String, pub key_id: Option<Vec<u8>>,
                       pub key_class: Option<KeyClass>, pub handle: Option<u64> }
pub fn parse_ref(s: &str) -> Result<ParsedRef>;          // the ONE grammar parser (c2 §4.3)
pub fn display_refs(infos: &[KeyInfo]) -> Vec<String>;

// c2-core::template
pub enum AttrKind { Bool, Str, Bytes, Ulong }
pub enum AttrValue { Bool(bool), Str(String), Bytes(Vec<u8>), Ulong(u64), Symbol(String) }
pub struct TemplateAttr { pub name: String, pub kind: AttrKind, pub value: AttrValue,
                          pub enabled: bool, pub locked: bool }
pub struct KeyTemplate { pub attrs: Vec<TemplateAttr> }  // get / set (unknown → Param) / enabled_attrs

// c2-core::params
pub enum ParamValue { Bytes(Vec<u8>), Int(i64), Str(String), Bool(bool), Enum(String), KeyRef(KeyInfo) }
pub struct ParamSpec { pub name: &'static str, pub kind: ParamKind, pub prompt: String,
                       pub required: bool, pub default: Option<ParamValue>,
                       pub default_from: Option<&'static str>, pub choices: Option<Vec<String>>,
                       pub length: Option<usize>, pub validate: Option<fn(&ParamValue) -> Result<()>> }

// c2-core::io — all &self: implementations use interior mutability (single thread)
pub trait ConsoleIo {
    fn prompt(&self, spec: &ParamSpec) -> Result<String>;        // Ctrl-C → UserAbort
    fn prompt_secret(&self, text: &str) -> Result<SecretString>;
    fn prompt_multiline(&self, text: &str) -> Result<String>;
    fn select(&self, title: &str, options: &[String]) -> Result<usize>;
    fn confirm(&self, text: &str, default: bool) -> Result<bool>;
    fn print(&self, r: Renderable);                  // Text | Table | HexDump | Panel | …
    fn print_error(&self, err: &ConsoleError);
}
pub trait TemplateEditor { fn edit(&self, t: KeyTemplate, title: &str) -> Result<KeyTemplate>; }
```

```rust
// c2-provider — &self everywhere; session/login state in RefCell inside the provider.
// This makes same-provider flows (`copy softhsm:x softhsm`) borrow-safe: no &mut aliasing.
pub trait Provider {
    fn name(&self) -> &str;
    fn type_name(&self) -> &str;                               // "memory" | "pkcs11" | fake-set
    fn initialize(&self) -> Result<()>;                        // lazy, idempotent (c2 §6)
    fn shutdown(&self) -> Result<()>;
    fn status(&self) -> ProviderStatus;
    fn list_tokens(&self) -> Result<Vec<TokenInfo>> { Ok(vec![]) }
    fn login(&self, token: &TokenInfo, pin: SecretString, keep_pin: bool) -> Result<()> { /* Unsupported */ }
    fn logout(&self) -> Result<()> { Ok(()) }
    fn mechanisms(&self) -> BTreeSet<String>;
    fn supports(&self, mech: &str) -> bool { self.mechanisms().contains(mech) }
    fn list_keys(&self) -> Result<Vec<KeyInfo>>;
    fn find_key(&self, sel: &KeySelector) -> Result<KeyInfo>;  // label, id, class, handle
    fn import_key(&self, m: &KeyMaterial, label: &str, t: Option<&KeyTemplate>, id: Option<&[u8]>) -> Result<KeyInfo>;
    fn generate_key(&self, req: &GenerateRequest) -> Result<KeyInfo>;
    fn delete_key(&self, k: &KeyInfo) -> Result<()>;
    fn export_key(&self, k: &KeyInfo) -> Result<KeyMaterial>;
    fn encrypt(&self, k: &KeyInfo, m: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, k: &KeyInfo, m: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>>;
    fn sign(&self, k: &KeyInfo, m: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, k: &KeyInfo, m: &MechanismInvocation, data: &[u8], sig: &[u8]) -> Result<bool>;
    fn derive(&self, k: &KeyInfo, m: &MechanismInvocation) -> Result<DeriveResult>;
    // frozen-provisional (c2 §4.11), defaults → UnsupportedOperation:
    fn wrap_key(&self, wk: &KeyInfo, m: &MechanismInvocation, target: &KeyInfo, o: &WrapOptions) -> Result<Vec<u8>>;
    fn unwrap_key(&self, wk: &KeyInfo, m: &MechanismInvocation, blob: &[u8], req: &UnwrapRequest) -> Result<KeyInfo>;
    fn read_key_template(&self, k: &KeyInfo) -> Result<KeyTemplate>;
    fn update_key(&self, k: &KeyInfo, changes: &KeyTemplate) -> Result<KeyEditResult>;
    fn read_full_template(&self, k: &KeyInfo) -> Result<KeyTemplate>;
    fn as_any(&self) -> &dyn Any;    // downcast seam, e.g. wizard → Pkcs11Provider::init_token
}
pub struct ProviderRegistry { /* RefCell<Vec<Rc<dyn Provider>>>, config order, memory first */ }
impl ProviderRegistry {
    pub fn register(&self, p: Rc<dyn Provider>) -> Result<()>;
    pub fn get(&self, name: &str) -> Result<Rc<dyn Provider>>;
    pub fn all(&self) -> Vec<Rc<dyn Provider>>;
    pub fn resolve_ref(&self, s: &str) -> Result<(Rc<dyn Provider>, KeyInfo)>;  // parse_ref + get + find_key
}
```

```rust
// c2-console — command framework
pub struct BoundArgs { pub positionals: Vec<String>, pub positional_quoted: Vec<bool>,
                       pub named: IndexMap<String, String>,
                       pub options: IndexMap<String, OptValue> }   // Value(String) | Flag
pub enum Flow { Continue, Exit }
pub trait Command {
    fn name(&self) -> &'static str;
    fn summary(&self) -> &'static str;
    fn usage(&self) -> &'static str;
    fn flags(&self) -> &'static [&'static str] { &[] }
    fn run(&self, ctx: &AppContext, args: &BoundArgs) -> Result<Flow>;
    fn complete(&self, ctx: &AppContext, tokens: &[String], cursor: &str) -> Vec<String> { vec![] }
}
pub struct AppContext { pub config: Rc<LoadedConfig>, pub providers: ProviderRegistry,
                        pub operations: OperationRegistry, pub io: Box<dyn ConsoleIo>,
                        pub template_editor: Box<dyn TemplateEditor> }
```

Test contracts (c2 §4.10) become `c2-testkit` items: `ScriptedIo::new(answers)` with
`.output(): Vec<String>`; `FakeProvider::new(name).type_name("pkcs11").mechanisms(..)`
with `.calls()` using c2's frozen call-summary encoding; a
`provider_contract_tests!(make_provider_expr)` macro that expands the ABC-semantics suite
into `#[test]` functions (replacing the pytest mixin); and a `softhsm_token()` fixture (§9).

## 6. Rust-specific design notes

- **State and borrowing.** Everything runs on the REPL thread. Providers, IO and the
  registry take `&self` and keep mutable state in `RefCell`. A `RefCell` double borrow
  is a bug that panics; the contract suite and same-provider copy tests exercise the paths
  where this could happen (a provider calling back into itself).
- **PKCS#11 backend seam.** `Pkcs11Provider` talks to a crate-private
  `trait Backend` of about 25 raw-shaped calls: slots, token info, mechanism list,
  sessions, login, find/get/set/create/destroy, generate (key or pair),
  encrypt/decrypt/sign/verify, wrap/unwrap/derive, init token/PIN. Attributes cross it as
  `(CK_ATTRIBUTE_TYPE, bytes)`, and mechanisms as an r2-owned `MechSpec` enum.
  - `CryptokiBackend` implements the seam over `cryptoki`. It is the **single CKR choke
    point**, mapping errors into a `Ckr` value that the provider translates per c2 §5.2.
  - `FakeBackend`, a port of `fake_pykcs11.py` behind `cfg(test)`/feature `fake-backend`,
    replaces PyKCS11 monkeypatching.

  The rest of the provider (identity resolution, twin guard, CKM folding, software
  fallbacks, auto-recovery) is backend-agnostic and fully unit-testable.
- **Terminal I/O.** `TerminalIo` (rustyline + rpassword) when stdin is a TTY, `PlainIo`
  (line reads from stdin, secrets read as plain lines) otherwise. Both share the
  renderer. Piped sessions work identically on all OSes, which fixes c2's Windows
  release-smoke limitation (c2 §9). The REPL loop keeps c2's own `…>` continuation logic
  (`line_is_complete`), so it stays editor-agnostic.
- **History.** Own persistence in prompt_toolkit's `FileHistory` format
  (`# <timestamp>` / `+<line>`) at the same `app.history_file`, fed into rustyline's
  in-memory history. The file stays shared with Python c2, and the
  `--pin`/`--password` filter is r2's own (it mirrors `SecretFilteringFileHistory`).
- **Ctrl-C.** Inside prompts it is a key, which maps to `UserAbort` and prints
  `Aborted.`. During operations, a `ctrlc` handler sets an atomic flag that commands and
  services check at step boundaries (for example between copy-ladder rungs).
  - A blocking PKCS#11 call can't be interrupted; this is also true in Python, where
    `KeyboardInterrupt` lands only after the C call returns.
  - `finally` cleanup (transport-key destruction, provider shutdown) becomes `Drop`
    guards, so `panic = "unwind"` stays on in release builds.
- **Errors and unexpected failures.** The REPL loop is still the only renderer. A panic
  hook plus `catch_unwind` around each command gives c2's "short message + details logged
  to <logfile>" behavior; `--debug` prints the backtrace, which replaces the traceback.
- **Env before `C_Initialize`.** `Pkcs11InstanceConfig.env` and the wizard's
  `SOFTHSM2_CONF` are applied at one audited `unsafe { set_var }` site, which asserts no
  spinner is active.
- **Randomness and bigints.** `openssl::rand` provides CKA_IDs and transport keys, and
  `openssl::bn` provides the raw-RSA modexp. No extra crates are needed.

## 7. Behavior parity

### 7.1 Must stay identical (asserted by ported tests and the parity harness)

- Every c2 §5.1 command form, flag, positional-disambiguation rule and completion stage.
- `parse_ref` grammar incl. selector precedence and carve-outs; `display_refs` suffixing.
- `decode_data` detection order, PEM re-wrap incl. RFC 1421 headers, "hex beats base64".
- Error messages and hints (copied verbatim from c2; tests assert text), CKR table.
- Config: discovery order, `C2_CONFIG`, deep merge (lists replace), `origins`,
  validation messages with config paths, unknown-key warnings via logging.
  `defaults.yaml` is byte-identical. The decoder accepts **YAML 1.1** spellings PyYAML
  accepts in existing user files (`yes/no/on/off` booleans, `0x…` integers), because
  YAML-1.2 parsers read those as strings.
- PKCS#11 object layouts: attribute sets, 4-byte random CKA_IDs, EC params/point DER
  encodings, SENSITIVE/EXTRACTABLE injection, identity precedence, twin guard. The test is
  that objects created by either implementation are fully usable by the other on the
  same token.
- File formats: exports (PEM/DER/PKCS#8 encrypted, SPKI, X.509, PKCS#12), CSRs,
  wrapped blobs (raw/hex/b64), `key template` YAML, the history file.
- Copy decision matrix, ladder order, refusal UX; KWP preference and both-dialect unwrap.

### 7.2 Deliberate deviations (recorded in r2 spec §11)

| # | Deviation | Reason |
|---|---|---|
| D1 | Table/panel glyphs differ (comfy-table vs rich); same columns and content | different renderer; tests assert content, snapshots cover layout |
| D2 | Piped/non-TTY stdin uses a plain reader on every OS | fixes the Windows piped limitation; release smoke runs the piped session on all OSes |
| D3 | Real zeroization of key material, PINs, transport keys | Rust makes the c2 §5.5 "best-effort" caveat obsolete |
| D4 | `--debug` shows a Rust backtrace instead of a Python traceback; log line format differs (same path and rotation) | runtime difference |
| D5 | macOS ships x86_64 and arm64 (c2: arm64 only) | free with cargo targets |
| D6 | `RSA-AES-KEY-WRAP` on PKCS#11 is advertised **only if** the S0 spike shows `cryptoki` binds `CK_RSA_AES_KEY_WRAP_PARAMS`; otherwise it stays unadvertised, as in c2 | capability improvement, gated on the `mechanisms()` probe as c2 §5.5 requires |

## 8. Loop decomposition

Sizes follow c2's convention (S/M/L = one agent context of increasing load). "Ports"
names the Python sources and tests the loop translates. Every loop's done gate:
`cargo fmt --check` && `cargo clippy --workspace --all-targets -- -D warnings` &&
`cargo nextest run --workspace` && `cargo deny check`, plus the `softhsm` suite when
SoftHSM is present (CI always runs it), plus the loop's STATUS row and ledger rows updated.

| ID | Loop | Size | Depends on (merge order) |
|---|---|---|---|
| S0 | Spec port + API spikes (docs only) | M | — |
| R0 | Workspace, contract skeleton, CI, softhsm fixture | M | S0 |
| R1 | Core model & codec | M | R0 |
| R2 | Configuration | M | R1 |
| R3 | Provider & operation contracts, registries, FakeProvider, contract suite | M/L | R1, R2* |
| R4 | Memory provider | L | R1, R3, R6* |
| R5a | PKCS#11 provider — foundation | L | R1, R2, R3 |
| R5b | PKCS#11 provider — crypto, wrap, derive, edit | L | R5a |
| R6 | Key formats & X.509 building | M | R1 |
| R7 | Console shell, framework, ParamResolver, CLI bootstrap | L | R1, R2, R3; R4*, R5a* |
| R8 | Provider & key commands + keyload/keyexport/certops | L | R4, R5a, R6, R7 |
| R9 | Crypto commands | M | R4, R7 |
| R10 | Template editor & copy | M/L | R2, R4, R5b, R7 |
| R11 | SoftHSM first-run wizard | M | R2, R5a, R7 |
| R12 | Packaging & release | M | R7 |
| R14 | Template files (`key template`, `--template`) | M | R5b, R7, R8* |
| R15 | Wrapped-key load/export (`--kek`) | M/L | R4, R5b, R7, R8* |
| R13 | Integration, parity sign-off, cutover | L | all |

`*` = merge-order-only edge (develop in parallel against the skeleton).

```
Wave 0:  S0 → R0
Wave 1:  R1
Wave 2:  R2 ∥ R3 ∥ R6
Wave 3:  R4 ∥ R5a ∥ R7            (R7 merges after R4 and R5a)
Wave 4:  R5b ∥ R8 ∥ R9 ∥ R11 ∥ R12
Wave 5:  R10 ∥ R14 ∥ R15          (develop from wave 4 on FakeProvider; merge after R5b)
Wave 6:  R13 (solo, owns everything)
```

There is no L16 counterpart. Its model, ops, provider and console pieces land natively
in R1/R2/R3/R4/R5/R8/R10, because the ported spec already describes the final state.

### Loop cards

**S0 — Spec port + API spikes** (solo; docs, plus throwaway spike code that is not merged)
- Produces: `spec.md` (c2 spec with §4 in Rust per §5 here, §11 deviations), `loops.md`
  (STATUS + these cards), `CLAUDE.md` (Rust conventions + done gate), and
  `parity/ledger.csv`. The ledger comes from `pytest --collect-only -q` on c2@408d6f2,
  with columns `python_test, r_loop, rust_test, status`, where status is
  `todo|ported|n/a:<reason>`.
- Spikes, each half a day, with results written into the spec before §4 freezes:
  1. **cryptoki coverage.** Check param bindings for every c2 §5.8–§5.10 mechanism
     (GCM, CTR, OAEP, PSS, ECDH1, EdDSA/Ed448 params, CMAC, HMAC, KW/KWP), raw vendor
     parameter bytes (the `raw` packer), `C_InitToken`/`C_InitPIN`,
     `C_SetAttributeValue`, and `CK_RSA_AES_KEY_WRAP_PARAMS`. Each gap is resolved by an
     `unsafe` shim or an explicit deviation.
  2. **OpenSSL coverage.** Check KWP plus RFC 3394 over PKCS#7 padding, CMAC,
     OAEP/PSS knobs, Ed448/X448, encrypted traditional PEM, PKCS#12 build and parse, and
     legacy PKCS#12 (RC2/3DES) under a *vendored* OpenSSL 3, which needs the `legacy`
     provider, on Linux, macOS and Windows.
  3. **Terminal.** Check rustyline + rpassword on macOS, Linux and Windows Terminal:
     bracketed paste of a PEM, the non-TTY fallback, hint and completion behavior.
- Accept: every c2 §4 item has a Rust counterpart or an `n/a: Python-only` note (for
  example the `handle_int` repr rule and lazy imports). Every c2 test is assigned to
  exactly one loop in the ledger. All spike outcomes are recorded.

**R0 — Workspace, contract skeleton, CI** (c2 L0)
- Owns: workspace `Cargo.toml`, toolchain/lint/deny/clippy config, `justfile`, `ci.yml`,
  every crate's `lib.rs` skeleton (**handed off** to the owning loops, like c2's stub
  `app.py`), the `c2-cli` stub (`--version`), `c2-testkit::softhsm`,
  `scripts/softhsm-init.sh`.
- Skeleton: all §4 types and traits with real definitions; function bodies stubbed. This
  includes the cross-loop hooks: `services::templatefile::load_seed_file` (R14) and
  `console::commands::kek::{run_load, run_export}` (R15), which R8 and R10 call.
- Ports: `test_smoke` (version part), `integration/test_softhsm_fixture`.
- Accept: done gate green on the skeleton; the CI softhsm job's fixture self-test
  initializes and lists a token.

**R1 — Core model & codec** (c2 L1, plus L16 model parts)
- Owns `c2-core`: `error`, `keys`, `template`, `params`, `io` (incl. `Renderable`),
  `codec`, `datainput`; `c2-testkit::scripted_io`.
- Ports `core/{errors,keys,params,io,codec,datainput}.py`; `tests/unit/core/*` (94 tests,
  incl. `test_keys_objects`, `test_scripted_io`).
- Accept: c2's codec input matrix (L1 accept list) table-driven; `parse_ref` and
  `display_refs` vectors verbatim; template semantics; ScriptedIo drives a scripted
  sequence.

**R2 — Configuration** (c2 L2)
- Owns `c2-config`: `defaults.yaml` (byte-identical copy), `loader`, `model`
  (`default_template`, `template_class_key`, all sections), platformdirs-compatible
  user-dir resolution, YAML 1.1 compatibility shims.
- Ports `config/*.py`; `test_config.py`, `test_config_objects.py`.
- Accept: precedence, merge, origins, path-carrying errors, unknown-key suggestions; the
  embedded file round-trips; `default_template` correct for all eight class keys; a
  fixture config using `yes/no` and `0x` values decodes identically to PyYAML.

**R3 — Provider & operation contracts** (c2 L3, plus `builtin_generic`)
- Owns `c2-provider` (trait, types, registry, `rsa_raw_modexp`); `c2-ops` except
  `params` (model, registry, `builtin_{aes,rsa,ec,generic}`, `custom`);
  `c2-testkit::{fake_provider, contract}`.
- Ports `providers/{base,registry}.py`, `ops/{model,registry,builtin_*,custom}.py`,
  `tests/support/fake_provider.py`, `tests/contract/base.py` (34 contract tests);
  `test_ops_registry`, `test_provider_base`, `test_ops_objects`.
- Accept: all 33 built-in op ids with exact params, including
  `default_from`/`salt_len=-1`; `available_for` filtering (cert-as-public, curves);
  `load_custom` derivation rules; FakeProvider passes the contract macro in both
  presentations.

**R4 — Memory provider** (c2 L4, plus L15/L16 memory parts)
- Owns `c2-memory`.
- Ports `providers/memory.py`; `test_memory_provider`, `test_memory_objects`,
  `test_memory_wrap_kek`, including every KAT (SP 800-38A, GCM case 16, RFC 4493, RFC 3394,
  RFC 6979, RFC 8032, RFC 7748, the independent RFC 8017 PSS verify-KAT, and the Utimaco
  PAD-dialect regression).
- Accept: contract suite passes; ECDSA r‖s conversion; GMAC equals GCM-over-AAD; HMAC
  equals RFC 4231; hand-rolled RSA-RAW; the RSA-AES-KEY-WRAP blob format matches c2's.

**R5a — PKCS#11 foundation** (first half of c2 L5)
- Owns `c2-pkcs11`: `backend` (trait, `CryptokiBackend`, `FakeBackend`), `catalog`
  (`CKA_CATALOG` + symbol tables), `softhsm` (`find_softhsm_module`), and in the provider
  the lazy init with `env`, slots/tokens/login/logout, keep-PIN auto-recovery, the CKR
  choke point, template conversion with material injection, the object read path
  (CKO_DATA, OTHER, symbolic CKK), import/generate/delete/export, identity resolution and
  twin guard, `init_token`.
- Ports the matching parts of `pkcs11/{provider,attributes,softhsm}.py` and
  `tests/support/fake_pykcs11.py`; `unit/pkcs11/{test_attributes,test_provider_session,
  test_softhsm_detect,test_objects,test_provider_objects}`.
- Accept: fake-backend tests for sessions, login states incl. recovery vs
  `AuthRequired`, CKR mapping, disabled-attr omission, material sets (EC point DER
  wrapping, RSA CRT set); SoftHSM login, generate, and import of every object kind.

**R5b — PKCS#11 crypto, wrap, derive, edit** (second half of c2 L5, plus L8/L14/L15/L16 provider parts)
- Owns `c2-pkcs11::mechanisms` (CKM↔name folding, custom ckm→id merge, advisory EdDSA
  probe, the five `param_struct` packers) and the provider's verbs with software
  fallbacks:
  - ECB PKCS#7, non-SHA1 OAEP over raw RSA, CMAC/HMAC truncation, bare-ECDSA prehash,
    DigestInfo, and public-key RSA-RAW;
  - derive with the resident fallback;
  - wrap/unwrap with the KWP preference and the CKA_VALUE_LEN inject-and-retry;
  - `read_key_template`, `update_key`, `read_full_template`.
- Ports the remaining `provider.py` and `mechanisms.py`; `unit/pkcs11/{test_mechanisms,
  test_provider_edit,test_wrap_kek}`; `integration/test_pkcs11_provider`; the SoftHSM
  contract subclass.
- Accept: fake-backend packer and advertisement tests; SoftHSM CBC/GCM round-trips,
  PKCS1v15/ECDSA/HMAC, wrap/unwrap, `update_key` outcomes; the contract suite green on
  SoftHSM.

**R6 — Key formats & X.509** (c2 L6)
- Owns `c2-core::{keyparse, x509build, der}`. The `der` module holds the EC OID/point
  encodings and r‖s↔DER conversion shared by memory, pkcs11 and certops.
- Ports `core/{keyparse,x509build}.py`; `test_keyparse`, `test_x509build`.
- Accept: per-format parse round-trips incl. hex-wrapped PEM and hint mismatches;
  wrong password → `KeyParse`; the PKCS#12 multi-material shared label; the CSR built via
  a sign callback verifies under OpenSSL for RSA, ECDSA (DER conversion) and Ed25519;
  a legacy PKCS#12 fixture (generated at test time with `openssl pkcs12 -legacy`)
  parses.

**R7 — Console shell & framework** (c2 L7)
- Owns `c2-console::{io, repl, parser, completer, render, commands/mod + build.rs,
  commands/{help,misc}}`, `c2-ops::params` (ParamResolver), and `c2-cli` (args,
  bootstrap incl. SoftHSM autodetect and custom-CKM map into `Pkcs11Provider`, logging
  with size rotation and redaction, panic hook).
- Ports `app.py`, `logging_setup.py`, `ops/params.py`,
  `console/{io,repl,parser,completer,render}.py`, `commands/{__init__,help_cmd,misc_cmd}.py`;
  `unit/console/{test_app,test_io,test_parser,test_completer,test_render,test_repl,
  test_discovery,test_logging_setup,test_commands}`, `test_params`, `test_smoke`.
- Accept: tokenizer and binder tables incl. caret positions; ParamResolver
  inline/prompt parity; piped REPL sessions via `assert_cmd` (help, exit, unknown-command
  suggestion, quoted multiline PEM); `config path` / `config show --origin/--defaults`;
  history filter; `--debug`.

**R8 — Provider & key commands** (c2 L8, plus `key edit`, L16 console parts)
- Owns `commands/{providers,keys}.rs` (providers, slots, login with the wizard trigger,
  logout, keys, key info, key edit, generate, load, export, csr, delete) and
  `c2-services::{keyload, keyexport, certops}`. It calls the R14/R15 hooks for
  `--template`/`--kek`.
- Ports `providers_cmd.py`, `keys_cmd.py` (minus the `--kek`/`key template` paths),
  `services/{keyload,keyexport,certops}.py`; `unit/console/{test_providers_cmd,
  test_keys_cmd,test_keys_cmd_objects}`, `unit/services/{test_keyload,test_keyexport,
  test_certops}`, the matching part of `test_objects_services`,
  `integration/test_console_keys`.
- Accept: every command form and error path on FakeProvider; the p12 self-signed path;
  the ECDSA r‖s→DER CSR path; SoftHSM login → generate → load → keys → export → csr.

**R9 — Crypto commands** (c2 L9)
- Owns `commands/crypto.rs` (encrypt/decrypt/sign/verify/derive/ops).
- Ports `crypto_cmd.py`; `test_crypto_cmd`, `integration/test_console_crypto`.
- Accept: positional-2 mech-vs-data disambiguation (quoting forces data), the select
  fallback, file in/out and `--outformat`, verify's public-half fallback, derive's
  resident-key rendering, `ops` capability filtering.

**R10 — Template editor & copy** (c2 L10, plus the L16 data-copy route)
- Owns `c2-console::template_editor`, `commands/copy.rs`, `c2-services::transfer`.
- Ports `template_editor.py`, `copy_cmd.py`, `services/transfer.py`;
  `test_template_editor`, `test_copy_cmd`, `test_transfer`, the transfer part of
  `test_objects_services`, `integration/test_copy`.
- Accept: the editor mini-REPL (toggle/set/±/add/ok/cancel, locked rows, identity-row
  note); the decision matrix and ladder with two FakeProviders; transport keys destroyed
  on success **and** failure (Drop guard) and zeroized; the sensitive-but-extractable wrap
  path; SoftHSM mem↔SoftHSM↔SoftHSM copies give identical ciphertexts; the refusal UX.

**R11 — SoftHSM wizard** (c2 L11)
- Owns `c2-console::wizard`.
- Ports `wizard.py`; `unit/console/test_wizard`, `integration/test_wizard`.
- Accept: a ScriptedIo run against a fresh temp token dir gives a working provider; the
  decline path; the conf file and appended config entry match c2 §5.13; the
  `softhsm2-util` fallback.

**R12 — Packaging & release** (c2 L12)
- Owns `release.yml`, `[profile.release]`, the `vendored-openssl` feature and build
  scripts.
- Accept: the release matrix of §10 builds; each binary passes `--version` and a piped
  `help` / `providers` / `exit` session on **all** OSes; the Linux binary also runs in an
  old-glibc container; SHA256SUMS published.

**R14 — Template files** (c2 L14)
- Owns `c2-services::templatefile` (codec + `build_seed`, NAME-based kind resolution,
  `NON_CREATION_ATTRS`) and `commands/key_template.rs`, and fills in the
  `load_seed_file` hook.
- Ports `services/templatefile.py`; `unit/services/test_templatefile` and the
  template-file cases from the command and integration suites.
- Accept: codec round-trips (symbolic ULONG, `0x…` bytes, hex-looking STR label);
  seeding policy; a SoftHSM dump → reseed round-trip; **a file dumped by Python c2 seeds
  Rust c2, and vice versa.**

**R15 — Wrapped-key load/export** (c2 L15)
- Owns `c2-services::wrapload` (the six-row direction-aware table, KEK resolution,
  `load_wrapped`, `wrap_for_export`) and `commands/kek.rs`, and fills in the R8 hooks.
- Ports `services/wrapload.py` plus the `--kek` paths of `keys_cmd.py`;
  `test_wrapload`, `test_load_kek`, `test_export_kek`, `integration/test_load_kek`.
- Accept: per-direction table and selection tests; sensitive-but-extractable wraps while
  plain export refuses; raw/hex/b64 export→load round-trips; **Python-exported blobs load
  in Rust, and vice versa.**

**R13 — Integration, parity sign-off & cutover** (c2 L13; solo)
- Owns everything: `parity/`, the e2e suites, the coverage gate, spec fold-back, README,
  release candidate.
- Ports `integration/{test_end_to_end,test_custom_mechanism,test_objects_softhsm}`,
  `test_l13_hardening`.
- Accept: the parity ledger has no `todo` rows; the parity harness is green (§9); line
  coverage ≥ 80%; `todo!`/`unimplemented!` denied; manual terminal checklist done on
  macOS, Linux and Windows Terminal; all CI jobs green incl. a release dry-run.

## 9. Verification strategy

1. **Parity ledger.** `parity/ledger.csv` lists every c2 test ID (about 1,280, before
   parametrization). A loop is done only when its rows are `ported` (with the Rust test
   path) or `n/a:<reason>`. Examples of `n/a`: mypy Protocol conformance, importlib
   discovery, prompt_toolkit sticky-kwargs regressions. R13 requires zero `todo` rows.
2. **Doubles, as in c2 §4.10.** ScriptedIo for every interactive flow; FakeProvider for
   console, ops and services; FakeBackend only inside `c2-pkcs11`; the contract macro
   instantiated for FakeProvider (both presentations), MemoryProvider and Pkcs11Provider
   on SoftHSM.
3. **KATs and properties.** c2's vectors are copied verbatim. Round-trips cover every
   advertised mechanism per provider; cross-provider checks (memory ⇄ SoftHSM) follow c2 §8.
4. **SoftHSM tests.** They live behind cargo feature `softhsm`, so they don't compile
   otherwise, and they fail hard when SoftHSM is missing. This is stricter than pytest's
   skip plus `--softhsm-required`, and nothing can hide behind a skip.
   - `scripts/softhsm-init.sh` initializes the shared token *before* the test process
     starts. It exports `SOFTHSM2_CONF` and `C2_TEST_SOFTHSM_*`, so tests never mutate
     the environment.
   - nextest's process-per-test model plus `unique_label()` keeps the tests isolated.
   - Wizard tests spawn the binary with their own fresh `SOFTHSM2_CONF`.
5. **Console end-to-end.** `assert_cmd` drives the real binary with piped stdin and a
   temp `--config`; `insta` snapshots cover help, tables and error panels.
6. **Differential parity harness** (`parity/`, R13, optional CI job that checks out
   c2@408d6f2 and runs `uv sync`):
   - *Transcript diff:* identical scripted sessions piped into both binaries on the
     memory provider, restricted to deterministic operations (AES-ECB/CBC/CTR/GCM with
     pinned IVs, CMAC, GMAC, HMAC, RSA-PKCS1 and Ed25519 signatures, loads, exports).
     Hex result blocks, error messages and hints are compared after normalizing table
     glyphs.
   - *Artifact interop:* every file format is exported by one implementation and loaded
     by the other (PKCS#8 plain and encrypted, SPKI, X.509, PKCS#12, CSR, wrapped blobs in
     three encodings, template YAML, history file, user config files).
   - *Shared token:* both implementations run against **one** SoftHSM token dir. Objects
     created by each (every kind, keypairs, PKCS#12 imports, data objects) are listed,
     used and copied by the other. This is the strongest check that attribute layouts
     match.
7. **Coverage.** `cargo llvm-cov` with an 80% line floor, enforced from R13 on (as
   c2's floor was wired in L13).

## 10. CI and release

`ci.yml` (from R0):
- `lint` runs fmt, clippy with `-D warnings`, and `cargo deny`.
- `test` runs nextest on ubuntu, macos and windows, plus doc tests.
- `softhsm` runs on ubuntu-22.04 and ubuntu-24.04 (SoftHSM 2.6 vs 2.7, as c2 §8), with
  `apt install softhsm2 opensc`, the init script, and `--features softhsm`.
- `msrv` builds with the pinned toolchain.
- `coverage` and `parity` are added in R13.

`release.yml` (R12), triggered by a tag or manually:

| Target | Notes |
|---|---|
| `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` | **glibc, never musl-static.** A static musl binary can't `dlopen` vendor PKCS#11 libraries, which are glibc shared objects. Build against an old glibc baseline (manylinux_2_28 container or `cargo zigbuild --target …gnu.2.28`) so it runs on RHEL/Rocky 8-class HSM hosts; smoke-test inside `rockylinux:8`. |
| `x86_64-apple-darwin`, `aarch64-apple-darwin` | Both arches (D5); optional `lipo` universal binary. |
| `x86_64-pc-windows-msvc` | Vendored OpenSSL (the runner provides Perl). Piped smoke works now (D2). |

Build settings:
- OpenSSL is linked statically via `vendored`, with the `legacy` provider available for
  old PKCS#12 files (confirmed in the S0 spike).
- `[profile.release]`: `lto = "fat"`, `codegen-units = 1`, `strip = true`,
  `panic = "unwind"` (Drop-based provider shutdown).
- Vendor PKCS#11 libraries and SoftHSM stay unbundled and are loaded by path at runtime
  (c2 §9/§10).
- Artifacts ship with SHA256SUMS. Code signing and notarization are out of scope, as
  in c2.

## 11. Milestones and cutover

| Milestone | Contents | Usable for |
|---|---|---|
| M0 — contracts frozen | S0 + R0 merged; CI green on the skeleton | parallel loop dispatch |
| M1 — memory console | waves 1–3 + R8 + R9 | `generate`/`load`/`keys`/`encrypt`/`sign` on `mem`, config, help, piped sessions |
| M2 — full surface | waves 4–5 | all c2 commands incl. SoftHSM, copy, wizard, `--template`, `--kek` |
| M3 — parity sign-off | R13 | release candidate; parity harness green on CI |
| Cutover | tag r2 `v1.0.0` | README in c2 points to r2; c2 archived or kept in maintenance-only mode |

**During the rewrite, c2 is frozen at 408d6f2 as the reference.** If c2 must change
(for example a field fix from a real HSM), the same PR adds a row to r2's `spec.md`
§11 or `loops.md` and a parity-ledger entry, so the two can't silently diverge.

## 12. Risks and mitigations

| Risk | Likelihood / impact | Mitigation |
|---|---|---|
| `cryptoki` lacks a param binding (raw vendor params, RSA-AES-KW, Ed448 params, GMAC) | M / M | S0 spike; a narrow `unsafe` shim over `cryptoki-sys` inside `backend` only; otherwise a recorded deviation |
| Vendored OpenSSL issues (Windows build, missing `legacy` provider for old PKCS#12) | M / M | S0 spike on all 3 OSes; release dry-run from R0; a legacy-p12 fixture test |
| Linux binary won't start on older HSM hosts (glibc) | H if ignored / H | glibc-baseline build + `rockylinux:8` smoke test in R12 |
| Subtle behavior drift (ref grammar, codec ambiguity, twin guard, copy ladder, identity precedence) | M / H | verbatim test vectors, the ledger, the differential harness, the shared-token test |
| YAML 1.1 vs 1.2 differences break existing user configs | M / M | decoder accepts 1.1 spellings; fixture test against PyYAML-decoded values |
| Terminal UX regressions (completion, paste, hidden input on Windows) | M / M | S0 terminal spike; R13 manual checklist; plain-reader fallback |
| Borrow-model surprises (`RefCell` double borrow in same-provider flows) | L / M | `&self` design; same-provider copy/wrap tests in the contract suite |
| Agent context overload on the biggest modules (`provider.py` is 2.9k lines) | M / M | R5 split into R5a/R5b; loop cards cite exact Python sections |
| c2 keeps evolving and the targets diverge | M / H | freeze rule in §11; any c2 change carries its r2 spec and ledger entry |
| Scope creep (for example batch mode, because the plain reader makes it tempting) | M / M | no features before M3; list them for post-parity loops |

## 13. Decisions to confirm

These are the defaults this plan assumes. Changing one changes S0.

1. **Crypto backend: OpenSSL (`openssl` crate, vendored)** — recommended for
   byte-identical parity with pyca. The alternative, pure-Rust RustCrypto, gives an
   easier static build but has gaps (Ed448/X448 maturity, PKCS#12 building, traditional
   encrypted PEM) and an open RSA timing advisory.
2. **Binary and config identity: keep `c2`** (binary name, `c2.yaml`, `C2_CONFIG`,
   config/state dirs), as a drop-in replacement. `r2` stays the repository name only.
3. **Line editor: `rustyline`** — recommended for its non-TTY fallback and explicit
   history control. `reedline` is the alternative if dropdown completion menus are wanted.
4. **c2 freeze** at 408d6f2 until M3, with the mirror rule in §11.
