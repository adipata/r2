# Parity ledger

`ledger.csv` maps every c2 test (c2@408d6f2) to the r2 loop that ports it (PLAN.md §8, §9.1).
It is the checklist behind "parity": a loop is done only when its rows are no longer `todo`,
and R13 signs off only when no row in the whole file is `todo`.

## Columns

| column | meaning |
|---|---|
| `python_test` | c2 test function as `path::[Class::]func`, parametrizations collapsed |
| `params` | c2 node IDs folded into the row: the parametrization count (1 if none). Contract rows count their provider instantiations (4). Contract-instantiation rows are 0 (see below). The column sums to the c2 collection total (1600) |
| `r_loop` | the one loop that ports the row (`R0`…`R15`, `R5a`/`R5b`) |
| `status` | `todo`, `ported`, or `n/a:<reason>` |
| `rust_test` | the Rust test(s) that cover the row, as `cargo nextest list` prints them (`<binary-id> <test path>`), separated by ` ; `. Several rows may point at one table-driven test |
| `note` | porting hints: markers (`softhsm`, c2 `xfail`/`skipif`), split decisions, Python-only parts to drop |

The provider contract suite is listed once, as the 34 `tests/contract/base.py::ProviderContractTests::*`
rows, all assigned to R3, which owns the `provider_contract_tests!` macro. Four rows with
`params=0` record who instantiates the suite: the two FakeProvider presentations (R3),
`MemoryProvider` (R4), and `Pkcs11Provider` on SoftHSM (R5b). An instantiation row is `ported`
once that loop invokes the macro and the suite is green for its provider.

## How loops update rows

In the same PR as the port, the owning loop edits only its own rows:

- **Ported:** set `status=ported` and fill `rust_test`. Keep test vectors, inputs and asserted messages verbatim (PLAN §2.4). A parametrized row needs every c2 case covered, usually as one table-driven test.
- **Not applicable:** set `status=n/a:<reason>` and give the reason in `note`. Only use this for tests that check pure Python mechanics. If the behavior still matters in Rust, port it.
- **Notes:** you may append to `note` after ` | `. The generator keeps appended text.
- **Wrong owner:** don't change `r_loop` by hand. Move the row in the generator's `OVERRIDES` table, regenerate, and record the change in `loops.md`.

Lint the ledger and check your gate (no c2 checkout needed):

```sh
python3 parity/generate_ledger.py --stats --gate R8    # exit 1 while R8 has todo rows
python3 parity/generate_ledger.py --stats --gate all   # the R13 sign-off gate: zero todo rows
```

`--stats` also fails a `ported` row that has no `rust_test`.

## How it was generated

From the r2 root, with a c2 checkout at 408d6f2 that has had `uv sync`:

```sh
C2_DIR=../c2 python3 parity/generate_ledger.py           # write parity/ledger.csv
C2_DIR=../c2 python3 parity/generate_ledger.py --check   # exit 1 if the file has drifted
```

`C2_DIR` defaults to `../c2`. Inside `C2_DIR` the script runs exactly
`uv run pytest --collect-only -q -p no:cacheprovider`, which collects 1600 node IDs. It runs the
same command again with `-m softhsm`, `-m xfail` and `-m skipif` to get the note tags. It then
collapses the node IDs to 1280 functions plus the 4 instantiation rows (1284 rows) and assigns
each row to a loop:

1. `FILE_LOOP`: the file-level mapping, from the "Ports" lines of the PLAN §8 loop cards.
2. `OVERRIDES`: per-test decisions for files split across loops, made by reading each test body.
3. `NA` / `NOTES`: the pre-marked `n/a` rows and porting notes.

The script fails on any unassigned test, any stale table entry, or any node-ID accounting
mismatch. Regenerating merges with the existing file, keeping every non-`todo` status, every
`rust_test`, and any note text appended after the generated note. If c2 ever changes under the
freeze rule (PLAN §11), regenerate in the same PR.

## Split decisions beyond the PLAN §8 "Ports" lines

These are recorded in `OVERRIDES`, and each one is explained in the row's note.

- **`--template` / `key template` / `seed_templates` → R14.** These cases depend on `templatefile::build_seed`, so they move out of the files owned by R8, R10 and R15.
- **`--kek` / wrapload → R15.**
- **Copy cases → R10, `ops`/`sign`/`verify` cases → R9.** These come out of `test_keys_cmd_objects` and `test_objects_services`.
- **R5a/R5b split.** Tests in the R5a files that exercise verbs, wrap/unwrap, derive, custom mechanisms or `read_full_template` → R5b. The foundation classes of `integration/test_pkcs11_provider` → R5a, which satisfies R5a's "SoftHSM login, generate, import" acceptance.
- **`integration/test_objects_softhsm`.** It holds no console end-to-end test. Provider-level tests → R5b, `copy_key` legs → R10.
- **`test_l13_hardening`.** Each case goes to the loop that owns the code under test (R1, R6, R7, R8, R9).
- **Tests that drive the real wizard → R11.** These come from `test_providers_cmd`. The test that drives the editor's `add CKA_ID` → R10.
