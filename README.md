# r2

r2 is an interactive cryptographic operator console written in Rust: a REPL for working
with keys and crypto operations across pluggable providers — an in-memory software
provider (always on, backed by OpenSSL) and any PKCS#11 module (HSMs, smartcards; SoftHSM2
is auto-detected). It ships as a single binary, `r2`.

This is a quick start; the full behavior, command set and configuration schema live in
[`spec.md`](spec.md).

## Install & run

Download a release archive (`r2-<version>-<target>.tar.gz`, `.zip` on Windows) for
Linux (x86_64/aarch64, glibc ≥ 2.28), macOS (x86_64/arm64/universal) or Windows (x86_64),
check it against `SHA256SUMS`, and put `r2` on your `PATH`. OpenSSL is linked in; nothing
else is needed. Or build from source (below).

```console
$ r2 --version
r2 0.2.0
$ r2
r2 0.2.0 — type 'help' for commands
r2>
```

(On a terminal a small plain-text ASCII-art dog is printed above the startup line; never
into a pipe.)

Flags: `--version`, `--config PATH` (explicit config file), `--debug` (debug logging,
warnings mirrored to stderr, full backtraces for unexpected errors).

On a terminal r2 uses a line editor (history, Tab completion, highlighting); with piped
stdin it reads plain lines, so scripted sessions work on every OS:

```console
$ printf 'providers\nexit\n' | r2
```

## First session

The memory provider (`mem`) works immediately, no configuration:

```text
r2> generate mem aes size=256 --label demo
r2> encrypt mem:demo gcm iv=0x000102030405060708090a0b deadbeef   # footer: "<n> bytes in <t>"
r2> generate mem generic size=256 --label mac     # CKK_GENERIC_SECRET (HMAC key)
r2> sign mem:mac hmac hash=sha256 deadbeef
r2> random mem 32                                 # 32 bytes from the provider's RNG
r2> load mem data 48656c6c6f --label note        # CKO_DATA: opaque bytes
r2> load mem --file server.pem --format cert --label srv   # X.509 certificate
r2> keys mem                                      # every object: keys, certs, data
r2> ops mem
r2> help
r2> exit
```

Missing mechanism parameters are prompted for (`encrypt mem:demo gcm deadbeef` asks for
the IV; an empty answer there draws a random IV from the provider and prints it);
omitted data opens a paste prompt that ends with an empty line. Results show how long the
provider operation took (`in 4ms` after a result line, `<n> bytes in <t>` under a hex
result).

Objects are keys (AES, generic secret, RSA, EC incl. Ed25519/Ed448/X25519/X448),
certificates and data objects; `keys` lists every object a provider holds — on PKCS#11
tokens, key types r2 cannot operate on are still listed (algorithm `other`) and can be
deleted.

With SoftHSM2 installed (`brew install softhsm` / `apt install softhsm2`), a `softhsm`
provider appears automatically. The first `login softhsm` starts a one-time wizard that
creates the token directory, initializes a token (you pick the PINs), and offers to save
the provider entry to your config:

```text
r2> providers
r2> login softhsm          # first run: wizard, then PIN prompt
r2> generate softhsm aes size=256 --label mykey   # template editor opens; OK row accepts
r2> copy mem:demo softhsm
r2> key template softhsm:mykey mykey.yaml         # dump the object's attribute template
r2> logout softhsm
```

Keys on PKCS#11 tokens go through a checklist template editor before creation — defaults
are conservative (sensitive, non-extractable); flip rows deliberately. On a terminal it is
an inline panel: ↑/↓ move, Space toggles a checkbox or edits a value (hex for bytes such as
CKA_ID, text for CKA_LABEL), `-`/`+` disable/enable a row, `a` adds an attribute from a
list filtered as you type, `:` takes a line of the typed grammar (`5=0xc0fe`, `add
CKA_X=v`), Enter on `[ OK ]` accepts, Esc cancels. Piped sessions use the typed grammar
(`3`, `5=0xc0fe`, `-7`/`+7`, `add CKA_X=v`, `ok`, `cancel`) at the `template> ` prompt.

## Configuration

Everything runs on built-in defaults without a config file. To customize, create an
`r2.yaml`; it is discovered in this order:

1. `--config PATH`
2. `$R2_CONFIG`
3. `./r2.yaml`
4. the platform user config dir: `~/.config/r2/r2.yaml` on Linux (`$XDG_CONFIG_HOME`
   honoured), `~/Library/Application Support/r2/r2.yaml` on macOS,
   `%LOCALAPPDATA%\r2\r2\r2.yaml` on Windows

Your file is deep-merged over the defaults — set only what you change (lists replace). The
most common addition is a real PKCS#11 module:

```yaml
providers:
  pkcs11:
    - name: prodhsm
      library: /usr/lib/libvendor_pkcs11.so
      token_label: PROD-TOKEN     # optional; slot: <id> also works
```

`config path` and `config show --origin` inside the REPL show which file each setting
came from; `config show --defaults` prints the embedded defaults. The full schema
(templates, custom attributes, custom mechanisms) is in spec §4.8 and §7; the embedded
defaults are in [`crates/r2-config/src/defaults.yaml`](crates/r2-config/src/defaults.yaml).

## Development

The workspace pins its toolchain in `rust-toolchain.toml` (rustup installs it). Tests run
under [cargo-nextest](https://nexte.st); the [`justfile`](justfile) wraps the commands.

```console
$ cargo build --workspace
$ cargo nextest run --workspace                     # unit + integration tests
$ eval "$(scripts/softhsm-init.sh)"                 # a fresh SoftHSM2 test token…
$ cargo nextest run --workspace --features softhsm  # …for the SoftHSM suites
$ cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings
$ cargo deny check                                  # supply chain
$ cargo llvm-cov nextest --workspace --fail-under-lines 80   # coverage floor
```

See [`CLAUDE.md`](CLAUDE.md) for conventions and [`loops.md`](loops.md) for how the
implementation was decomposed.

## Building the binary

A development build is `cargo build -p r2-cli` (binary `target/debug/r2`), linking the
system OpenSSL 3. Release builds link a vendored, static OpenSSL 3 (legacy provider
compiled in, so old PKCS#12 files load anywhere):

```console
$ cargo build -p r2-cli --release --locked --features vendored-openssl
$ target/release/r2 --version
```

That needs Perl and make (Windows: Strawberry Perl and NASM). The release pipeline
(`.github/workflows/release.yml`) does the same per target through
[`scripts/release/`](scripts/release): `build.sh <target-triple>` (Linux via
`cargo zigbuild` against glibc 2.28, so the binary runs on RHEL/Rocky 8-class HSM hosts),
`check-binary.sh` (static OpenSSL ≥ 3.2 with the default and legacy providers, glibc
baseline), `smoke.sh` (`--version`, a piped `help`/`providers`/`exit` session and the
legacy PKCS#12 fixtures), `package.sh` and `sha256sums.sh`. A pushed tag `v<version>`
publishes a GitHub release; a manual dispatch is a dry run.

What's in (and not in) the binary:

- The embedded `defaults.yaml` is compiled in, so the binary works with no config file.
- Vendor PKCS#11 libraries — including SoftHSM2 — are **not** bundled; they are loaded at
  runtime from the library path in your config (or the SoftHSM probe list).
- Code signing and notarization are out of scope.

Packaging decisions are documented in spec §9.

## License

GPL-3.0 (see [`LICENSE`](LICENSE)).
