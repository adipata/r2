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
| 7 | History | Up after a few commands; a `--pin`/`--password` line, a `load` with inline data and a pasted PEM are never recalled (§11 D8) | recall works, secrets are not stored (§11 D8 option B) |
| 8 | Glyphs | `keys`, `help`, an error | box drawing and panel borders render (TrueType console font) |
| 9 | Spinner | `login` on a slow PKCS#11 module (or SoftHSM keygen of RSA-4096) with stderr on the terminal | braille spinner on stderr, cleared before the next prompt (§11 D10) |
| 10 | `TERM=dumb` / piped stdin | `TERM=dumb r2`, and `printf 'providers\nexit\n' \| r2` | plain prompts, no double echo; piped session exits 0 (§11 D2) |
| 11 | Startup dog (§11 D33) | start `r2` on the terminal; then `printf 'exit\n' \| r2` | on the terminal the 7-line dog (`-ARF!`) is printed above `r2 <version> — type 'help' for commands`, plain text in the terminal's default colour (no bold, dim or colour); the piped run starts with the startup line, no dog |
| 12 | Operation timing and random IV (§11 D30, D31) | `generate mem aes size=256 --label t`, `encrypt mem:t cbc 00112233445566778899aabbccddeeff` and press Enter at the `IV (16 bytes, empty = random)` prompt | the generate line ends with ` in <t>` (e.g. `in 1ms`); `IV (random): <32 hex digits>` is printed, then the hex result whose bottom border reads `32 bytes in <t>` (µs/ms/s units); the time stays on the same line as the text before it unless the terminal is too narrow |
| 13 | Template panel (§5.12, §11 D34) | log in to a PKCS#11 provider (SoftHSM), `generate hsm aes size=128 --label p`; ↑/↓, Space on a boolean, Enter on a bytes row (type hex; a non-hex key is refused), `a` + `id` + Enter + `c0fe` + Enter, `:` + `add CKA_COPYABLE=false`, End + Enter; then a second `generate` and Esc; resize the window while the panel is open | the panel is drawn below the command (no alternate screen, the scrollback stays) and redrawn in place without flicker or leftover rows; Enter on `[ OK ]` replaces it with the accepted table and `generated hsm:p#c0fe …`; Esc erases it and prints `Aborted.`; after a resize the panel is redrawn whole (narrowing redraws from a cleared screen) |

## Results

| item | Linux (xterm-compatible pty) | macOS (Terminal.app / iTerm2) | Windows Terminal | conhost |
|------|------------------------------|-------------------------------|------------------|---------|
| 1 | pass — automated: `python3 parity/harness/pty_paste_check.py` (bracketed paste, `ESC[6n` answered), 2026-10-02 | not run | not run (no bracketed paste on Windows: keystroke path) | not run |
| 2, 3, 4 | pass — automated by the same pty script (4096-bit RSA PEM in one bracketed paste loads; hidden confirmed p12 password not echoed; Ctrl-C at the password prompt → `Aborted.`, nothing written, the next command runs) | not run | not run | not run |
| 5–9 | partly automated: r2-console io/repl/completer tests (LineIo over scripted readers), r2-cli `e2e_pty` (`TERM=dumb`, degraded terminal) | not run | not run | not run |
| 10 | pass — r2-cli `e2e_pty`, `e2e_repl` and the parity harness (every session is piped) | not run | not run | not run |
| 11, 12 | partly automated: r2-cli `main.rs` tests `dog_banner_render_is_the_art_verbatim_without_colors`, `dog_banner_is_not_shown_on_an_injected_io`; `e2e_timing_iv` (no dog in a pipe, timed results, random IV round trip); console `timing.rs`, `random_iv.rs`; the dog on a real terminal not yet checked | not run | not run | not run |
| 13 | pass — automated: `eval "$(scripts/softhsm-init.sh)" && python3 parity/harness/pty_template_panel_check.py` (SoftHSM 2.6.1, real crossterm driver on a pty: open, toggle, hex input, add list, `:` line, accept, Esc, exit 0), 2026-10-04; the screens rendered through a terminal emulator model (pyte) during development; the resize check not yet done on a real terminal | not run | not run | not run |

The macOS and Windows columns need a person at those terminals; they are open at R13
sign-off (no macOS/Windows host in the R13 environment) and are tracked as the remaining
M3 cutover item in `loops.md` (R13 STATUS row).
