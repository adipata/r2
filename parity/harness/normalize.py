"""Transcript normalization for the c2 ⇄ r2 differential harness (spec §8; owner R13).

Both tools run the same piped session. Before comparing, every difference the spec
records as a deviation (§11) or as non-TTY noise is normalized away, nothing else:

- Input echo. What was typed is not command output, but the PROMPT it answered is: each
  echo is replaced by a ``PROMPT: <prompt><answer>`` line in place, and the prompt lines
  are compared like any other line. c2's echo is prompt_toolkit's non-TTY rendering
  (``Warning: Input is not a terminal (fd=0).``, the doubled ``<prompt><answer><pad>
  <prompt><answer>`` copy ending in a carriage return, padding lines, wraps at 80
  columns, §11 D2): the doubled copy is reduced to one; c2 lines carrying a carriage
  return that are not a clean doubled copy are the REPL command echo mangled by the
  80-column wrap and are dropped (the REPL prompt is the tool name, the command is the
  input). r2 (PlainIo, §11 D2) prints each prompt followed by the line it read, matched in
  order against the session's input lines. A hidden-input answer (the session's
  ``## secret:`` values) is shown as c2's ``*`` run on both sides; r2 echoes nothing after
  a hidden prompt (§11 D20). The REPL prompt (``c2> ``/``r2> ``) echo is dropped.
- The tool name (§11 D7): ``c2`` → ``r2`` as a word (banner, ``c2.yaml``, ``c2.log``,
  messages naming the tool); hex dump lines are left alone.
- The hex result (§11 D28): the body rows of c2's hex panel (``│ dead beef │`` … between a
  top border and a ``─ <n> bytes ─╯`` bottom border) become one line of continuous hex,
  r2's layout; the title and byte count are compared as they are.
- Table and panel glyphs (§11 D1): box-drawing characters become spaces, runs of
  whitespace collapse, blank lines are dropped — cell CONTENT, order and wording remain.
- r2-only commands (§11 D29): c2 has no ``random``, so r2's ``help`` table has one extra
  row; that row is dropped from r2's output when it normalizes to exactly
  ``random Generate random bytes with a provider's RNG`` (``R2_ONLY_HELP_ROWS``), so a
  changed summary, or any other extra row, is still reported.
- The random-IV fallback (§11 D30): r2's encrypt/sign/wrap IV prompts note it as
  ``IV (16 bytes, empty = random)``; the note (``_RANDOM_NOTE``) is removed from r2's raw
  output, so the prompt texts compare as c2's. (No session leaves an IV empty, so the
  ``IV (random): <hex>`` line never appears.)
- Operation timing (§11 D31): r2 appends the provider time to results (`` in 4ms`` after
  a text result, ``16 bytes in 412µs`` in a hex result's footer, ``in 1.23s`` as an empty
  result's footer). ``_TIMING_RE`` removes it from r2's raw output wherever rich wrapped
  it (``… in`` / ``4ms`` on separate lines), before the lines are compared.
- RSA 8192 (§11 D32): r2's RSA size list offers 8192 too, so the invalid-size hint
  ``choices: 2048, 3072, 4096, 8192`` (``_RSA_CHOICES_R2``) compares as c2's list.
- PKCS#11 ULONG values >= 2^63 (§11 D18): r2 shows CK_UNAVAILABLE_INFORMATION unsigned
  (``18446744073709551615``) where c2 showed PyKCS11's signed ``-1``.
- Token enumeration order (shared-token suite ONLY, opt-in via ``token_provider``):
  SoftHSM hands out object handles and find order from its token files, which differ
  between runs, so ``handle <n>`` loses its number and each run of consecutive table rows
  starting with ``<token_provider>:`` is sorted. Transcript and interop runs keep both:
  memory listing order (insertion order) is c2 behavior the harness compares.
- The per-run work directory (``{WORK}``) and the fixture directory (``{FIX}``).
"""

from __future__ import annotations

import re

BOX = "─│╭╮╰╯━┃┏┓┗┛┌┐└┘├┤┬┴┼═║╔╗╚╝╞╡╪╤╧"
_BOX_RE = re.compile(f"[{BOX}]")
_WS_RE = re.compile(r"\s+")
_HEX_LINE_RE = re.compile(r"^[│ ]*[0-9a-f]{2,4}( [0-9a-f]{2,4})*[│ ]*$|^[0-9a-f]+$")
_HEX_BODY_RE = re.compile(r"^│ ([0-9a-f]+(?: [0-9a-f]+)*) *│$")
_HEX_BOTTOM_RE = re.compile(r"^╰─* \d+ bytes ─╯$")
_TOOL_RE = re.compile(r"\bc2\b")
_HANDLE_RE = re.compile(r"^handle \d+$")
_ROW_RE = re.compile(r"^[a-z][a-z0-9_-]*:\S+ ")
_PROMPT_ENDS = (": ", "? ", "] ", "> ", "| ")
_DOUBLED_RE = re.compile(r" *(\S.*?) +\1 *")
_C2_WRAP_RE = re.compile(r"\r {79}(.)\r\n")
PROMPT = "PROMPT: "
# r2's help rows for commands c2 does not have (§11 D29), in their normalized form.
R2_ONLY_HELP_ROWS = frozenset({"random Generate random bytes with a provider's RNG"})
# §11 D30: the note r2's encrypt/sign/wrap IV prompts carry.
_RANDOM_NOTE = ", empty = random)"
# §11 D32: r2's RSA size choices and c2's.
_RSA_CHOICES_R2 = "choices: 2048, 3072, 4096, 8192"
_RSA_CHOICES_C2 = "choices: 2048, 3072, 4096"
# §11 D31: " in 412µs" / " in 4ms" / " in 1.23s" after a result, possibly wrapped by rich
# between any two of its words (centered table titles indent the continuation line).
_TIMING_RE = re.compile(r"[ \n]+in[ \n]+\d+(?:µs|ms|\.\d{2}s)(?= |\n|$)")


def _is_echo(line: str, want: str) -> bool:
    """``line`` is an r2 prompt followed by the input ``want`` (PlainIo echo)."""
    if want and not line.endswith(want):
        return False
    prefix = line[: len(line) - len(want)]
    return prefix.endswith(_PROMPT_ENDS)


def _r2_echo(lines: list[str], inputs: list[str], secrets: set[str]) -> list[str]:
    """r2's echo lines replaced by ``PROMPT:`` lines (REPL prompt echoes dropped)."""
    out: list[str] = []
    i = 0
    for line in lines:
        if i < len(inputs):
            want = inputs[i]
            if want in secrets:
                # hidden input (PIN/password): the prompt alone, nothing echoed (§11 D20);
                # an echoed secret is NOT an echo and stays in the transcript as a diff
                if line.endswith(_PROMPT_ENDS) and not (want and want in line):
                    out.append(PROMPT + line + "*" * len(want))
                    i += 1
                    continue
            elif _is_echo(line, want):
                prompt = line[: len(line) - len(want)]
                if prompt != "r2> ":
                    out.append(PROMPT + line)
                i += 1
                continue
        elif line == "r2> ":
            continue  # the REPL prompt answered by end of input
        out.append(line)
    return out


def _c2_echo(lines: list[str]) -> list[str]:
    """c2's prompt_toolkit echo reduced to ``PROMPT:`` lines (REPL echoes dropped).

    A clean echo is one line ``<echo><pad><echo>\\r``. prompt_toolkit may also render an
    answer incrementally (a partial copy, then the full one on a later line, each ending
    in a carriage return) or wrap it at 80 columns; such a run of carriage-return lines is
    a group: dropped when it is the REPL command echo (any piece starts with ``c2>``),
    reduced to its final copy when every earlier piece is a prefix of it (the partial
    renders, at whatever point the read was split), and otherwise kept verbatim
    as ``PROMPT?:`` lines so that it shows up in the diff instead of passing silently.
    """
    out: list[str] = []
    group: list[str] = []

    def flush_one(pieces: list[str]) -> None:
        if pieces and not any(piece.startswith("c2>") for piece in pieces):
            if len(pieces) >= 2 and all(pieces[-1].startswith(piece) for piece in pieces):
                out.append(PROMPT + pieces[-1])
            else:
                out.extend("PROMPT?: " + piece for piece in pieces)

    def flush() -> None:
        # A run may hold several echoes back to back (e.g. the command echo and then the
        # prompt it opened, when the piped answer ended without a newline: no clean
        # doubled line). Split it into chains of renders each extending the previous one;
        # a lone piece stays with the chain before it (an unparsed wrap stays visible).
        chains: list[list[str]] = []
        for piece in group:
            if chains and piece.startswith(chains[-1][-1]):
                chains[-1].append(piece)
            else:
                chains.append([piece])
        merged: list[list[str]] = []
        for chain in chains:
            if merged and len(chain) == 1:
                merged[-1].extend(chain)
            else:
                merged.append(chain)
        for chain in merged:
            flush_one(chain)
        group.clear()

    for line in lines:
        if line.startswith("Warning: Input is not a terminal"):
            continue
        if "\r" not in line:
            flush()
            out.append(line)
            continue
        head = line.split("\r", 1)[0]
        match = _DOUBLED_RE.fullmatch(head)
        if match:
            flush()
            if not match.group(1).startswith("c2>"):
                out.append(PROMPT + match.group(1))
            continue
        for piece in line.split("\r"):
            if piece.strip():
                group.append(piece.strip())
    flush()
    return out


def _c2_hex(lines: list[str]) -> list[str]:
    """c2's grouped hex panel body as r2's one unbroken hex line (§11 D28).

    Only the rows between a top border and the ``─ <n> bytes ─╯`` bottom border of the same
    panel are joined, and only when every one of them is ``│ <hex groups> │``."""
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        if not line.startswith("╭"):
            continue
        end = i
        while end < len(lines) and _HEX_BODY_RE.match(lines[end]):
            end += 1
        if end > i and end < len(lines) and _HEX_BOTTOM_RE.match(lines[end]):
            rows = (_HEX_BODY_RE.match(row) for row in lines[i:end])
            out.append("".join(row.group(1).replace(" ", "") for row in rows if row))
            i = end
    return out


def normalize(
    text: str,
    tool: str,
    work: str,
    fixtures: str,
    inputs: list[str] | None = None,
    secrets: set[str] | None = None,
    token_provider: str | None = None,
) -> list[str]:
    """Normalized, comparable lines of one tool's stdout.

    ``token_provider`` (shared-token suite only) names the PKCS#11 provider whose handle
    numbers and table-row order are run-dependent; without it nothing is reordered."""
    if tool == "c2":
        # prompt_toolkit's 80-column wrap: the 80th cell is written after ``\r`` + 79
        # blanks, then the line breaks; rejoin it so the doubled echo is one line again
        text = _C2_WRAP_RE.sub(r"\1", text)
    else:
        text = _TIMING_RE.sub("", text)  # §11 D31
        text = text.replace(_RANDOM_NOTE, ")")  # §11 D30
        text = text.replace(_RSA_CHOICES_R2, _RSA_CHOICES_C2)  # §11 D32
    lines = text.split("\n")
    if tool == "c2":
        lines = _c2_hex(_c2_echo(lines))
    else:
        lines = _r2_echo(lines, inputs or [], secrets or set())
    out: list[str] = []
    for line in lines:
        line = line.replace(work, "{WORK}").replace(fixtures, "{FIX}")
        if tool == "c2" and not _HEX_LINE_RE.match(line):
            line = _TOOL_RE.sub("r2", line)
        line = line.replace("18446744073709551615", "-1")  # §11 D18
        line = _BOX_RE.sub(" ", line)
        line = _WS_RE.sub(" ", line).strip()
        if token_provider:
            line = _HANDLE_RE.sub("handle N", line)
        if tool == "r2" and line in R2_ONLY_HELP_ROWS:
            continue  # §11 D29: an r2-only command's help row
        if line:
            out.append(line)
    return _sort_rows(out, token_provider) if token_provider else out


def _sort_rows(lines: list[str], provider: str) -> list[str]:
    out: list[str] = []
    run: list[str] = []
    for line in lines + [""]:
        if line.startswith(provider + ":") and _ROW_RE.match(line):
            run.append(line)
            continue
        out.extend(sorted(run))
        run = []
        if line:
            out.append(line)
    return out
