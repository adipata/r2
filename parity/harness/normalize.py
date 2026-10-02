"""Transcript normalization for the c2 ⇄ r2 differential harness (spec §8; owner R13).

Both tools run the same piped session. Before comparing, every difference the spec
records as a deviation (§11) or as non-TTY noise is normalized away, nothing else:

- Input echo. Neither tool's echo of what was typed is output of a command, and c2's is
  prompt_toolkit's non-TTY rendering (``Warning: Input is not a terminal (fd=0).``, the
  doubled ``c2> cmd<pad>c2> cmd`` echo wrapped at 80 columns, padding lines, the ``*``
  run after a hidden-input prompt, §11 D20): every c2 line carrying a carriage return is
  echo; r2 (PlainIo, §11 D2) prints each prompt followed by the line it read (nothing for
  hidden input), matched in order against the session's input lines. Both are dropped.
- The tool name (§11 D7): ``c2`` → ``r2`` as a word (banner, ``c2.yaml``, ``c2.log``,
  messages naming the tool); hex dump lines are left alone.
- Table and panel glyphs (§11 D1): box-drawing characters become spaces, runs of
  whitespace collapse, blank lines are dropped — cell CONTENT, order and wording remain.
- PKCS#11 ULONG values >= 2^63 (§11 D18): r2 shows CK_UNAVAILABLE_INFORMATION unsigned
  (``18446744073709551615``) where c2 showed PyKCS11's signed ``-1``.
- Token enumeration order (shared-token suite): SoftHSM hands out object handles and
  find order from its token files, which differ between runs, so ``handle <n>`` loses its
  number and each run of consecutive table rows starting with ``<provider>:`` is sorted.
- The per-run work directory (``{WORK}``) and the fixture directory (``{FIX}``).
"""

from __future__ import annotations

import re

BOX = "─│╭╮╰╯━┃┏┓┗┛┌┐└┘├┤┬┴┼═║╔╗╚╝╞╡╪╤╧"
_BOX_RE = re.compile(f"[{BOX}]")
_WS_RE = re.compile(r"\s+")
_HEX_LINE_RE = re.compile(r"^[│ ]*[0-9a-f]{2,4}( [0-9a-f]{2,4})*[│ ]*$")
_TOOL_RE = re.compile(r"\bc2\b")
_HANDLE_RE = re.compile(r"^handle \d+$")
_ROW_RE = re.compile(r"^[a-z][a-z0-9_-]*:\S+ ")
_PROMPT_ENDS = (": ", "? ", "] ", "> ", "| ")


def _is_echo(line: str, want: str) -> bool:
    """``line`` is an r2 prompt followed by the input ``want`` (PlainIo echo)."""
    if want and not line.endswith(want):
        return False
    prefix = line[: len(line) - len(want)]
    return prefix.endswith(_PROMPT_ENDS)


def _drop_r2_echo(lines: list[str], inputs: list[str]) -> list[str]:
    out: list[str] = []
    i = 0
    for line in lines:
        if i < len(inputs):
            want = inputs[i]
            if _is_echo(line, want):
                i += 1
                continue
            if want and line.endswith(": "):
                # hidden input (PIN/password): the prompt alone, nothing echoed (§11 D20)
                i += 1
                continue
        elif _is_echo(line, ""):
            continue  # a prompt answered by end of input
        out.append(line)
    return out


def normalize(
    text: str, tool: str, work: str, fixtures: str, inputs: list[str] | None = None
) -> list[str]:
    """Normalized, comparable lines of one tool's stdout."""
    lines = text.replace("\r\n", "\r\n").split("\n")
    if tool == "c2":
        lines = [
            line
            for line in lines
            if "\r" not in line and not line.startswith("Warning: Input is not a terminal")
        ]
    else:
        lines = _drop_r2_echo(lines, inputs or [])
    out: list[str] = []
    for line in lines:
        line = line.replace(work, "{WORK}").replace(fixtures, "{FIX}")
        if tool == "c2" and not _HEX_LINE_RE.match(line):
            line = _TOOL_RE.sub("r2", line)
        line = line.replace("18446744073709551615", "-1")  # §11 D18
        line = _BOX_RE.sub(" ", line)
        line = _WS_RE.sub(" ", line).strip()
        line = _HANDLE_RE.sub("handle N", line)
        if line:
            out.append(line)
    return _sort_rows(out)


def _sort_rows(lines: list[str]) -> list[str]:
    out: list[str] = []
    run: list[str] = []
    for line in lines + [""]:
        if _ROW_RE.match(line):
            run.append(line)
            continue
        out.extend(sorted(run))
        run = []
        if line:
            out.append(line)
    return out
