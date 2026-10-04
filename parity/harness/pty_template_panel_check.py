#!/usr/bin/env python3
"""Terminal check of the template panel (spec §5.12, §11 D34; terminal checklist item 13).

Runs ``r2`` on a pseudo-terminal as a real terminal session (TerminalIo/reedline: the
cursor-position query ``ESC[6n`` is answered like a terminal does) against the SoftHSM
test token, and drives the inline panel that ``generate`` opens with real keystrokes
through crossterm:

1. the panel opens below the command (rows, the ``[ OK ]`` row, the key help);
2. Down ×3 + Space checks CKA_EXTRACTABLE;
3. ``a`` + ``id`` + Enter opens the CKA_ID value input: a non-hex key is refused, then
   ``c0fe`` + Enter adds the row and shows the identity note;
4. ``:`` + a bad grammar line shows the line editor's error; Ctrl-U + a good line applies;
5. End + Enter accepts: the accepted table is printed once and the key is generated with
   the panel's CKA_ID (``generated hsm:<label>#c0fe``), extractable (``key info``);
6. a second ``generate``: Esc cancels at once (``Aborted.``);
7. the key is deleted and r2 exits with status 0.

Needs the SoftHSM fixture environment: ``eval "$(scripts/softhsm-init.sh)"`` (it exports
SOFTHSM2_CONF and the R2_TEST_SOFTHSM_* variables). Fails (never skips) without it.
Usage: python3 parity/harness/pty_template_panel_check.py [--r2-bin PATH]
Standard library only (``pty``, ``select``); POSIX only. Exit status 0 = pass.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import shutil
import struct
import sys
import tempfile
import termios
import time
from pathlib import Path

from pty_paste_check import Term as PasteTerm

HERE = Path(__file__).resolve().parent
R2_ROOT = HERE.parent.parent
DOWN = b"\x1b[B"
END = b"\x1b[F"
ESC = b"\x1b"
CTRL_U = b"\x15"


class Term(PasteTerm):
    """The paste check's pty driver, on a 100×34 window."""

    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        super().__init__(argv, env)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 34, 100, 0, 0))

    def keys(self, data: bytes, settle: float = 0.3) -> None:
        """Send keys and let the panel redraw (a lone ESC must not merge with what follows)."""
        self.send(data)
        self.pump(settle)


def expect_re(term: Term, pattern: bytes, after: int, timeout: float = 15.0) -> None:
    end = time.time() + timeout
    while not re.search(pattern, term.buffer[after:]):
        if term.eof or time.time() > end:
            raise AssertionError(f"no match for {pattern!r}; tail {term.buffer[-900:]!r}")
        term.pump(0.2)


def require_env() -> dict[str, str]:
    missing = [
        name
        for name in ("SOFTHSM2_CONF", "R2_TEST_SOFTHSM_MODULE", "R2_TEST_SOFTHSM_LABEL",
                     "R2_TEST_SOFTHSM_USER_PIN")
        if not os.environ.get(name)
    ]
    if missing:
        raise SystemExit(
            f"FAIL: SoftHSM fixture environment missing ({', '.join(missing)}); "
            'run: eval "$(scripts/softhsm-init.sh)"'
        )
    return dict(os.environ)


def main() -> int:
    parser = argparse.ArgumentParser()
    target = Path(os.environ.get("CARGO_TARGET_DIR", R2_ROOT / "target"))
    parser.add_argument("--r2-bin", default=os.environ.get("R2_BIN", str(target / "debug" / "r2")))
    args = parser.parse_args()
    fixture = require_env()
    work = Path(tempfile.mkdtemp(prefix="r2-panel-"))
    term = None
    try:
        config = work / "r2.yaml"
        config.write_text(
            f"app:\n  history_file: {work / 'history'}\n  log:\n    file: {work / 'r2.log'}\n"
            "ui:\n  confirm_delete: false\n"
            f"providers:\n  pkcs11:\n    - name: hsm\n"
            f"      library: {fixture['R2_TEST_SOFTHSM_MODULE']}\n"
            "softhsm:\n  autodetect: false\n"
        )
        env = {
            "HOME": str(work),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "TERM": "xterm-256color",
            "SOFTHSM2_CONF": fixture["SOFTHSM2_CONF"],
        }
        label = f"panel{os.getpid()}"
        term = Term([args.r2_bin, "--config", str(config)], env)
        term.expect(b"r2> ")
        term.send(
            f"login hsm {fixture['R2_TEST_SOFTHSM_LABEL']} "
            f"--pin {fixture['R2_TEST_SOFTHSM_USER_PIN']}\r".encode()
        )
        term.expect(b"logged in")

        # 1. the panel opens
        mark = term.mark()
        term.send(f"generate hsm aes size=128 --label {label}\r".encode())
        term.expect(b"[ OK ]", after=mark)
        term.expect(b"esc cancel", after=mark)
        print("ok   panel opened below the command")

        # 2. check CKA_EXTRACTABLE
        mark = term.mark()
        term.keys(DOWN * 3 + b" ")
        expect_re(term, rb"\[x\]\s+CKA_EXTRACTABLE\s+bool\s+true", mark)
        print("ok   Down x3 + Space checked CKA_EXTRACTABLE")

        # 3. add CKA_ID through the list; a non-hex key is refused
        term.keys(b"a")
        term.keys(b"id")
        term.keys(b"\r")
        mark = term.mark()
        term.keys(b"g")
        term.expect(b"CKA_ID takes hex digits (0-9, a-f)", after=mark)
        mark = term.mark()
        term.keys(b"c0fe\r")
        term.expect(b"note: CKA_ID is normally set with --id", after=mark)
        print("ok   CKA_ID added from the list (hex input, identity note)")

        # 4. the ':' line: the line editor's error, then a good line
        mark = term.mark()
        term.keys(b":add CKA_COPYABLE=maybe\r")
        term.expect(b"CKA_COPYABLE: invalid boolean 'maybe'", after=mark)
        mark = term.mark()
        term.keys(CTRL_U + b"add CKA_COPYABLE=false\r")
        expect_re(term, rb"\[ \]\s+CKA_COPYABLE\s+bool\s+false", mark)
        print("ok   ':' line reports the grammar's error and applies a good line")

        # 5. accept on the OK row
        mark = term.mark()
        term.keys(END + b"\r", settle=1.0)
        term.expect(f"generated hsm:{label}#c0fe".encode(), after=mark, timeout=30)
        expect_re(term, rb"CKA_EXTRACTABLE\s+bool\s+true", mark)
        mark = term.mark()
        term.send(f"key info hsm:{label}\r".encode())
        # the token's view: extractable (the default template says false) under id c0fe
        expect_re(term, rb"CKA_EXTRACTABLE\s+True", mark)
        print("ok   Enter on OK: table printed, key generated with the panel's template")

        # 6. Esc cancels at once
        mark = term.mark()
        term.send(f"generate hsm aes size=128 --label {label}x\r".encode())
        term.expect(b"[ OK ]", after=mark)
        term.keys(b" ")
        term.keys(ESC, settle=1.0)
        term.expect(b"Aborted.", after=mark)
        print("ok   Esc cancelled the second generate")

        # 7. clean up and exit
        mark = term.mark()
        term.send(f"delete hsm:{label}\r".encode())
        term.expect(b"r2> ", after=mark)
        term.send(b"exit\r")
        status = term.wait()
        assert status == 0, f"exit status {status}"
        print("ok   exit status 0")
        return 0
    except AssertionError as err:
        print(f"FAIL: {err}", file=sys.stderr)
        return 1
    finally:
        if term is not None:
            term.close()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
