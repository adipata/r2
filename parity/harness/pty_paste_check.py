#!/usr/bin/env python3
"""Terminal check (spec §8 R13 manual checklist, automated for Linux/macOS ptys).

Runs ``r2`` on a pseudo-terminal as a real terminal session (TerminalIo/reedline: the
cursor-position query ``ESC[6n`` is answered like a terminal does) and

1. pastes an OpenSSL traditional *encrypted* PEM — with its blank line after
   ``DEK-Info:`` — at the ``| `` multiline prompt as one bracketed paste: it must arrive
   as ONE answer (the password prompt follows, the key loads);
2. types the password at the hidden prompt (nothing echoed, §11 D20);
3. pastes a 4096-bit RSA PEM in one bracketed paste (it loads, no input stall);
4. exports a PKCS#12 with a hidden, confirmed password; presses Ctrl-C at the next
   password prompt (``Aborted.``, nothing written, the following command runs);
5. lists the keys and exits with status 0.

Usage: python3 parity/harness/pty_paste_check.py [--r2-bin PATH]
Standard library only (``pty``, ``select``); POSIX only. Exit status 0 = pass.
"""

from __future__ import annotations

import argparse
import os
import pty
import re
import select
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
R2_ROOT = HERE.parent.parent
PEM = R2_ROOT / "crates" / "r2-cli" / "tests" / "fixtures" / "rsa2048_traditional_tr4d.pem"
CPR_QUERY = b"\x1b[6n"


class Term:
    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        self.pid, self.fd = pty.fork()
        if self.pid == 0:  # child
            os.execve(argv[0], argv, env)
        self.buffer = b""

    def pump(self, timeout: float) -> None:
        end = time.time() + timeout
        while time.time() < end:
            ready, _, _ = select.select([self.fd], [], [], 0.05)
            if not ready:
                continue
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.buffer += chunk
            # answer every cursor-position query as a terminal would (row 1, col 1)
            while CPR_QUERY in chunk:
                os.write(self.fd, b"\x1b[1;1R")
                chunk = chunk.replace(CPR_QUERY, b"", 1)

    def expect(self, needle: bytes, timeout: float = 15.0) -> None:
        end = time.time() + timeout
        while needle not in self.buffer:
            if time.time() > end:
                raise AssertionError(f"timed out waiting for {needle!r}; got tail {self.buffer[-600:]!r}")
            self.pump(0.2)

    def send(self, data: bytes) -> None:
        os.write(self.fd, data)

    def wait(self) -> int:
        for _ in range(600):
            self.pump(0.1)
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                return os.waitstatus_to_exitcode(status)
        raise AssertionError(f"r2 did not exit; tail {self.buffer[-800:]!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    target = Path(os.environ.get("CARGO_TARGET_DIR", R2_ROOT / "target"))
    parser.add_argument("--r2-bin", default=os.environ.get("R2_BIN", str(target / "debug" / "r2")))
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="r2-pty-"))
    config = work / "r2.yaml"
    config.write_text(
        f"app:\n  history_file: {work / 'history'}\n  log:\n    file: {work / 'r2.log'}\n"
        "softhsm:\n  autodetect: false\n",
        encoding="utf-8",
    )
    env = {
        "HOME": str(work),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "TERM": "xterm-256color",
        "COLUMNS": "120",
        "LINES": "40",
        "NO_COLOR": "1",
    }
    pem = PEM.read_bytes().replace(b"\r\n", b"\n")
    assert b"DEK-Info:" in pem and b"\n\n" in pem, "fixture must be a traditional encrypted PEM"
    term = Term([args.r2_bin, "--config", str(config)], env)
    term.expect(b"r2>")
    term.send(b"load mem rsa --label pasted\r")
    term.expect(b"finish with an empty line")
    term.expect(b"| ")
    # one bracketed paste (terminals send ESC[200~ … ESC[201~ around pasted text)
    term.send(b"\x1b[200~" + pem.rstrip(b"\n").replace(b"\n", b"\r") + b"\x1b[201~")
    time.sleep(0.3)
    term.send(b"\r")  # Enter submits the pasted answer
    term.expect(b"\r")
    time.sleep(0.3)
    term.send(b"\r")  # the empty line that ends the paste
    term.expect(b"Password for encrypted RSA PRIVATE KEY")
    term.send(b"tr4d\r")
    term.expect(b"loaded into mem")
    term.send(b"keys mem\r")
    term.expect(b"exportable")
    deadline = time.time() + 15
    # the next prompt after the table: `keys` has finished
    while b"r2>" not in term.buffer[term.buffer.rfind(b"exportable") :]:
        if time.time() > deadline:
            raise AssertionError(f"no prompt after `keys`; tail {term.buffer[-600:]!r}")
        term.pump(0.2)
    # a 4096-bit RSA PEM (3.2 KiB) in one bracketed paste (item 2: no input stall)
    big = (HERE / "fixtures" / "rsa4096.pem").read_bytes()
    term.send(b"load mem rsa --label big\r")
    mark = len(term.buffer)
    while b"finish with an empty line" not in term.buffer[mark:]:
        term.pump(0.2)
    time.sleep(0.3)
    term.send(b"\x1b[200~" + big.rstrip(b"\n").replace(b"\n", b"\r") + b"\x1b[201~")
    time.sleep(0.3)
    term.send(b"\r")
    time.sleep(0.3)
    term.send(b"\r")
    mark = len(term.buffer)
    deadline = time.time() + 15
    while b"mem:big" not in term.buffer[mark:]:
        if time.time() > deadline:
            raise AssertionError(f"4096-bit paste did not load; tail {term.buffer[-600:]!r}")
        term.pump(0.2)
    # hidden password entry (item 3) and Ctrl-C at a password prompt (item 4)
    p12 = work / "p.p12"
    term.send(f"export mem:pasted {p12} --format p12\r".encode())
    term.expect(b"PKCS#12 password")
    term.send(b"s3cr3t-pw\r")
    term.expect(b"(again)")
    term.send(b"s3cr3t-pw\r")
    term.expect(b"wrote")
    term.send(f"export mem:pasted {work / 'q.p12'} --format p12\r".encode())
    mark = len(term.buffer)
    while b"PKCS#12 password" not in term.buffer[mark:]:
        term.pump(0.2)
    time.sleep(0.3)
    term.send(b"\x03")  # Ctrl-C at the hidden prompt
    term.expect(b"Aborted.")
    time.sleep(0.3)
    term.send(b"keys mem\r")  # the next command is not aborted
    mark = len(term.buffer)
    while b"exportable" not in term.buffer[mark:]:
        term.pump(0.2)
    time.sleep(0.5)
    term.send(b"exit\r")
    status = term.wait()
    if not p12.exists() or (work / "q.p12").exists():
        print("FAIL: the hidden-password export or the Ctrl-C abort misbehaved")
        return 1
    text = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", term.buffer).decode("utf-8", "replace")
    if status != 0:
        print(text[-2000:])
        print(f"FAIL: exit status {status}")
        return 1
    if "tr4d" in text or "s3cr3t" in text:
        print("FAIL: a password was echoed")
        return 1
    if "error" in text.lower():
        print(text[-2000:])
        print("FAIL: an error was rendered")
        return 1
    print(
        "pty check ok: encrypted traditional PEM pasted at `| ` arrived as one answer; "
        "hidden passwords not echoed; Ctrl-C at a password prompt aborted only that command"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
