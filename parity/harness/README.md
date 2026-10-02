# Differential parity harness (c2 ⇄ r2)

The harness runs identical piped sessions through the Python reference **c2@408d6f2** and
the **r2** binary, normalizes only the differences that spec §11 records (plus c2's
prompt_toolkit non-TTY noise), and fails on anything else (spec §8 "Differential parity
harness", PLAN §9.6). It needs Python 3.10+ (standard library only), a c2 checkout with its
virtualenv (`uv sync`), and an r2 debug build.

```sh
# from the r2 root
cargo build -p r2-cli
(cd ../c2 && git checkout 408d6f2 && uv sync)          # once
python3 parity/harness/run_parity.py                    # transcript + interop
python3 parity/harness/run_parity.py --softhsm          # + the shared SoftHSM token
python3 parity/harness/run_parity.py --suite token -v   # one suite, print transcripts
```

Options: `--c2-dir` (default `../c2`, or `$C2_DIR`), `--r2-bin` (default
`$CARGO_TARGET_DIR/debug/r2`, else `target/debug/r2`, or `$R2_BIN`), `--keep` (keep the
work dir; it is always kept when something differs). `just parity` and the optional `parity`
CI job run the same command. Exit status 0 means no unlisted difference.

## Suites

| suite | what runs | what must hold |
|---|---|---|
| `transcript` | `sessions/transcript_*.session`, once per tool, on the memory provider | normalized transcripts equal line for line; files named in `## same-files:` byte-identical (DER/PEM exports, CSRs, deterministic signatures, ciphertexts, derived secrets) |
| `interop` | `sessions/interop_*_export.session` by each tool, then `…_import.session` by each tool over each producer's files | the four import transcripts (c2→c2, c2→r2, r2→c2, r2→r2) are equal: every format one tool writes, the other loads to the same keys (PKCS#8 plain/encrypted PEM+DER, SPKI, X.509 PEM+DER, PKCS#12 incl. on-the-fly self-signed, CSRs, raw secrets, wrapped blobs raw/hex/b64 under KW/KWP/CBC/GCM/OAEP/PKCS1) |
| `token` (`--softhsm`) | one fresh SoftHSM token (`scripts/softhsm-init.sh`) shared by both tools: `token_*_create.session` by the creator, `token_*_use.session` by the user | the four (creator, user) transcripts are equal: objects of every kind (secret, generic, keypairs, EC, certificates, PKCS#12 imports, data objects, generated keys) are listed, inspected, used, exported, wrapped/unwrapped, copied (token→mem, mem→token, token→token), dumped with `key template` and re-seeded from the CREATOR's dump, renamed and deleted by the other tool |

The user config file case (`transcript_user_config`) appends `fixtures/user_config.yaml`
(YAML 1.1 spellings, custom attributes and mechanisms, unknown keys) to both tools' config
— a c2 user file renamed to `r2.yaml` must behave the same.

## Normalization (`normalize.py`) — the complete list

- **Input echo** (§11 D2, D20): c2 renders each prompt and its answer twice through
  prompt_toolkit on a pipe (lines carrying `\r`, wrapped at 80 columns, plus `Warning:
  Input is not a terminal (fd=0).`); r2's PlainIo prints the prompt followed by the line it
  read (nothing after a hidden-input prompt). Both are dropped; only command output is
  compared.
- **Tool name** (§11 D7): `c2` → `r2` as a word, except inside hex dump lines.
- **Glyphs** (§11 D1): box-drawing characters become spaces, whitespace runs collapse,
  blank lines are dropped. Both tools run with `COLUMNS=200` (the token suite with 1000, so
  no long attribute value is cropped by rich or folded by r2 — the D1 overflow rule).
- **ULONG ≥ 2^63** (§11 D18): `18446744073709551615` is compared as c2's `-1`.
- **Token enumeration** (token suite): `handle <n>` loses its number and consecutive table
  rows starting with `<provider>:` are sorted — SoftHSM's handle numbers and find order
  depend on its token file names, which differ between runs of either tool.
- The work and fixture directories become `{WORK}`, `{SRC}`, `{FIX}`.

Nothing else is normalized. A difference is fixed in r2, or — if it must stay — recorded
in spec §11 through the §4.11 procedure and only then normalized here.

## Session files

One input line per line, exactly as typed (template editor answers such as `ok`, select
answers, pasted PEM lines and the empty line that ends a paste included). `## key: value`
lines are headers (`same-files`, `config`), other `##` lines are comments.
`{WORK}`/`{FIX}`/`{SRC}` are substituted; a line `{PASTE:<fixture>}` expands to the
lines of that fixture file. Fixtures in `fixtures/` were generated once with pyca in c2's
virtualenv (fixed keys, so signatures and exports are deterministic).

## Results at R13 sign-off (2026-10-02, SoftHSM 2.6.1)

All suites green: `transcript_memory_core` (350 normalized lines, 16 files
byte-identical), `transcript_memory_errors` (159), `transcript_memory_interactive` (313),
`transcript_user_config` (167), `interop_memory` (328 lines × 4), `token_objects`
(560 lines × 4). Differences the harness found and R13 fixed: table titles one or two
cells wider than r2's body wrapped where rich kept them on one line (r2 now wraps at
rich's table width); a private key DER with trailing bytes (SoftHSM 2.6.1's zero-padded
KW-PAD unwrap of a PKCS#8, `copy hsm:<priv> mem`) reported pyca's `extra data` instead of
`unexpected tag (got Tag { value: 2, … })`.
