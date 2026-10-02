# Manual terminal checklist (R13; spec §6 "Cross-platform", §8)

Interactive terminal behaviour that the automated suites cannot fully reach. Run each item
on a real terminal with a release (or debug) build and a scratch config
(`app.history_file`/`app.log.file` in a temp dir). Record the result, OS, terminal and
r2 commit in the table at the end.

| # | item | how | pass when |
|---|------|-----|-----------|
| 1 | Traditional encrypted PEM paste at the `\| ` prompt | `load mem rsa --label p`, paste `crates/r2-cli/tests/fixtures/rsa2048_traditional_tr4d.pem` (it has a blank line after `DEK-Info:`), Enter, empty line; password `tr4d` | one answer: the password prompt follows, the key loads |
| 2 | 4096-bit RSA PEM paste | `load mem rsa --label big`, paste a 4096-bit PKCS#8 PEM | loads; no stall until the next keystroke (crossterm `use-dev-tty`) |
| 3 | Hidden PIN / password entry | `export mem:p x.p12 --format p12`, type the password twice | nothing echoed (§11 D20), the file is written |
| 4 | Ctrl-C at a PIN / password prompt | as 3, press Ctrl-C at the prompt | `Aborted.`, the REPL continues; the next command is not aborted |
| 5 | Ctrl-C while editing a command / Ctrl-D on an empty line | type a partial command, Ctrl-C; then Ctrl-D | the line is discarded; Ctrl-D leaves r2 with status 0 |
| 6 | Tab completion and the dropdown menu | `enc<Tab>`, `encrypt mem:<Tab>`, `load mem --file <Tab>` | commands, refs and paths complete (§11 D9) |
| 7 | History | Up after a few commands; a `--pin`/`--password` line is never recalled | recall works, secrets are not stored (§11 D8 option A) |
| 8 | Glyphs | `keys`, `help`, an error | box drawing and panel borders render (TrueType console font) |
| 9 | Spinner | `login` on a slow PKCS#11 module (or SoftHSM keygen of RSA-4096) with stderr on the terminal | braille spinner on stderr, cleared before the next prompt (§11 D10) |
| 10 | `TERM=dumb` / piped stdin | `TERM=dumb r2`, and `printf 'providers\nexit\n' \| r2` | plain prompts, no double echo; piped session exits 0 (§11 D2) |

## Results

| item | Linux (xterm-compatible pty) | macOS (Terminal.app / iTerm2) | Windows Terminal | conhost |
|------|------------------------------|-------------------------------|------------------|---------|
| 1 | pass — automated: `python3 parity/harness/pty_paste_check.py` (bracketed paste, `ESC[6n` answered), 2026-10-02 | not run | not run (no bracketed paste on Windows: keystroke path) | not run |
| 2, 3, 4 | pass — automated by the same pty script (4096-bit RSA PEM in one bracketed paste loads; hidden confirmed p12 password not echoed; Ctrl-C at the password prompt → `Aborted.`, nothing written, the next command runs) | not run | not run | not run |
| 5–9 | partly automated: r2-console io/repl/completer tests (LineIo over scripted readers), r2-cli `e2e_pty` (`TERM=dumb`, degraded terminal) | not run | not run | not run |
| 10 | pass — r2-cli `e2e_pty`, `e2e_repl` and the parity harness (every session is piped) | not run | not run | not run |

The macOS and Windows columns need a person at those terminals; they are open at R13
sign-off (no macOS/Windows host in the R13 environment) and are tracked as the remaining
M3 cutover item in `loops.md` (R13 STATUS row).
