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
CI job run the same command. Exit status 0 means no unlisted difference. The CI job checks
out c2 by its full commit SHA (`408d6f29aa968ad4afcd7888b5958ba4608c902c`); its repository
is `vars.C2_REPOSITORY` (default `<owner>/c2`), and a private c2 needs a read token in the
`C2_TOKEN` secret.

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

- **Input echo** (§11 D2, D20): what was typed is not output, but the prompt it answered
  is, so each echo becomes one `PROMPT: <prompt><answer>` line in place and prompt texts
  are compared like any other line (password, PIN, select, confirm, parameter, `| `
  multiline and template-editor prompts alike). c2 renders each prompt and its answer
  twice through prompt_toolkit on a pipe (`<echo><pad><echo>\r`, wrapped at 80 columns,
  sometimes a partial render first, plus `Warning: Input is not a terminal (fd=0).`): the
  wrap is rejoined and the copy reduced to one; a carriage-return run that cannot be
  reduced stays in the diff as `PROMPT?:` lines. r2's PlainIo prints the prompt followed
  by the line it read, matched in order against the session's inputs. Hidden input is
  keyed on the session's `## secret:` answers only: c2's `*` run is kept and r2's bare
  prompt gets the same run (r2 echoes nothing, D20; an r2 line that echoes a secret is a
  difference). Only the REPL prompt's echo (`c2> <command>` / `r2> <command>`) is
  dropped. `test_normalize.py` (`python3 -B -m unittest discover -s parity/harness`)
  proves a changed prompt, an extra output line ending in `: ` and an echoed secret are
  all reported.
- **Tool name** (§11 D7): `c2` → `r2` as a word, except inside hex dump lines.
- **Hex result** (§11 D28): the body rows of a c2 hex panel (`│ dead beef │` rows between
  its top border and its `─ <n> bytes ─╯` bottom border) are joined into one line of
  continuous hex, r2's layout; the title and the byte count are compared as they are
  (`test_normalize.py` `HexResult`: a changed digit or count is still reported, other
  panels are untouched).
- **Glyphs** (§11 D1): box-drawing characters become spaces, whitespace runs collapse,
  blank lines are dropped. Both tools run with `COLUMNS=200` (the token suite with 1000) by
  default. That width steps around the ONE remaining table difference, the D1 overflow
  rule (a word longer than its column: rich crops it with `…`, r2 folds it); it is not
  needed for the column allocation, which is rich's own (`_calculate_column_widths`) in
  r2 and is compared at narrower widths through the `## columns:` header below
  (`transcript_help` at 60/80/200, `transcript_narrow` at 80/100).
- **ULONG ≥ 2^63** (§11 D18): `18446744073709551615` is compared as c2's `-1`.
- **Token enumeration** (token suite only; `normalize(..., token_provider="hsm")`):
  `handle <n>` loses its number and consecutive table rows starting with `hsm:` are
  sorted — SoftHSM's handle numbers and find order depend on its token file names, which
  differ between runs of either tool. The transcript and interop suites reorder nothing:
  memory listing order is compared (`test_normalize.py` checks that a swapped `keys mem`
  row pair is reported).
- The work and fixture directories become `{WORK}`, `{SRC}`, `{FIX}`.

Nothing else is normalized.

`pty_paste_check.py` (same requirements, POSIX only) is the automated part of the R13
terminal checklist (`parity/terminal-checklist.md`): r2 on a pseudo-terminal as a real
terminal session, a bracketed paste of a traditional encrypted PEM at the `| ` prompt,
hidden passwords and Ctrl-C at a password prompt. The `parity` CI job runs it too. A difference is fixed in r2, or — if it must stay — recorded
in spec §11 through the §4.11 procedure and only then normalized here.

## Session files

One input line per line, exactly as typed (template editor answers such as `ok`, select
answers, pasted PEM lines and the empty line that ends a paste included). `## key: value`
lines are headers (`same-files`, `config`, `secret` = the answers typed at hidden-input
prompts; transcript suite only: `columns` = the console widths to run the session at,
each compared on its own as `<session>@<width>`, default 200, and `final-newline: no` =
pipe the session without the newline after its last line, as in the
`transcript_unterminated_*` sessions), other `##` lines are comments.
`{WORK}`/`{FIX}`/`{SRC}` are substituted; a line `{PASTE:<fixture>}` expands to the
lines of that fixture file. Fixtures in `fixtures/` were generated once with pyca in c2's
virtualenv (fixed keys, so signatures and exports are deterministic).

## Results at R13 sign-off (2026-10-02, SoftHSM 2.6.1)

All suites green, with the debug build (system OpenSSL 3) and with the release dry-run
binary (vendored OpenSSL 3.6.3, glibc 2.28 zigbuild): `transcript_help`,
`transcript_memory_core` (16 files byte-identical), `transcript_memory_errors`,
`transcript_memory_interactive`, `transcript_user_config`, `interop_memory` (× 4) and
`token_objects` (× 4); `pty_paste_check.py` passes on both binaries. (Line counts are
printed by each run; they vary slightly with c2's prompt_toolkit render timing and are not
recorded here.)

Differences found and fixed in r2 during R13:

- (fix round 4) at everyday widths r2's tables (comfy-table's `Dynamic` arrangement)
  split the width between columns differently from rich, so multi-word cells wrapped at
  other points (`help` at 80 columns: `copy … (wrapped in transit when` / `possible)`);
  r2 now ports rich's column-width algorithm (§4.9.2) and `transcript_help`/
  `transcript_narrow` run at 60–100 columns;
- (fix round 4) a final piped line without its newline ran in r2; c2's prompt_toolkit
  treated it as EOF (the command never ran; at a prompt, `Aborted.`) — r2 now does the
  same (`transcript_unterminated_command`/`_prompt`). `normalize.py` splits a c2
  carriage-return run holding two echoes (command echo, then the prompt echo) into its
  render chains so the prompt line is compared, not dropped;

- a table title one or two cells wider than r2's table body wrapped where rich (whose
  `SIMPLE_HEAD` table counts two edge columns) kept it on one line — e.g. `unwrapped into
  mem (RSA-PKCS1)`; r2 now wraps titles at rich's table width (§11 D1);
- a private key DER with trailing bytes — what SoftHSM 2.6.1's KW-PAD unwrap leaves on a
  PKCS#8 in `copy hsm:<extractable private key> mem` (pinned by `token_objects`) — reported
  pyca's `extra data` instead of `unexpected tag (got Tag { value: 2, … })`: r2-core now
  parses a value's content before reporting data after it, as rust-asn1 does.
