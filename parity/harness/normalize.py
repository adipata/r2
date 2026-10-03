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
