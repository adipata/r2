"""Regenerate the c2-side wrapped-key interop vectors (R15, spec §5.4/§5.6).

Run from the c2 checkout (c2@408d6f2, its venv):

    cd /home/user/c2 && uv run python \
        /home/user/r2/crates/r2-console/src/tests/fixtures/kek_interop/gen_kek_interop.py

Part 1 drives a real c2 REPL session on the memory provider: it loads the fixed KEK
(bytes 00..1f), the AES target (bytes 20..3f), the fixed RSA KEK pair (rsa_kek.pem /
rsa_kek_pub.pem) and the EC target (ec_target.pem), then writes `export --kek` blobs as
`c2_<name>` files. kw/kwp/cbc/gcm are deterministic (fixed IVs), so r2 must produce the
same bytes; oaep/pkcs1 are randomized, so r2 must load them.

Part 2 (when the files exist) loads the r2-produced randomized blobs `r2_oaep.b64` /
`r2_pkcs1.bin` (written by the ignored r2 test `kek_interop::write_r2_blobs`) back into
c2 and checks that the unwrapped key equals the AES target — the "vice versa" direction.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
KEK = bytes(range(32)).hex()
TARGET = bytes(range(32, 64)).hex()
CBC_IV = bytes(range(16)).hex()
GCM_IV = bytes(range(12)).hex()


def run_c2(lines: list[str]) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "c2.yaml"
        config.write_text(
            f"app:\n  history_file: {tmp}/history\n  log:\n    file: {tmp}/c2.log\n"
            "softhsm:\n  autodetect: false\nui:\n  confirm_delete: false\n",
            encoding="utf-8",
        )
        out = subprocess.run(
            ["c2", "--config", str(config)],
            input="\n".join([*lines, "exit"]) + "\n",
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    if "error:" in out:
        sys.exit(f"c2 reported an error:\n{out}")
    return out


SETUP = [
    f"load mem aes {KEK} --label kek",
    f"load mem aes {TARGET} --label target",
    f"load mem --file {HERE / 'rsa_kek.pem'} --label rsakek",
    f"load mem --file {HERE / 'rsa_kek_pub.pem'} --label rsakek",
    f"load mem --file {HERE / 'ec_target.pem'} --label ectarget",
]


def part1() -> None:
    lines = [
        *SETUP,
        f"export mem:target {HERE / 'c2_kw.bin'} --kek kek --mech kw",
        f"export mem:target {HERE / 'c2_kwp.hex'} --kek kek --mech kwp --outformat hex",
        f"export mem:target {HERE / 'c2_cbc.b64'} --kek kek --mech cbc iv=0x{CBC_IV} "
        "--outformat b64",
        f"export mem:target {HERE / 'c2_gcm.bin'} --kek kek --mech gcm iv=0x{GCM_IV}",
        f"export mem:ectarget {HERE / 'c2_ec_kwp.bin'} --kek kek --mech kwp",
        f"export mem:target {HERE / 'c2_oaep.bin'} --kek rsakek:pub --mech oaep",
        f"export mem:target {HERE / 'c2_pkcs1.b64'} --kek rsakek:pub --mech pkcs1 "
        "--outformat b64",
    ]
    print(run_c2(lines))


def part2() -> None:
    oaep, pkcs1 = HERE / "r2_oaep.b64", HERE / "r2_pkcs1.bin"
    if not (oaep.exists() and pkcs1.exists()):
        print("part 2 skipped: run the r2 test kek_interop::write_r2_blobs first")
        return
    with tempfile.TemporaryDirectory() as tmp:
        lines = [
            *SETUP,
            f"load mem aes --file {oaep} --kek rsakek --mech oaep --label from-r2-oaep",
            f"load mem aes --file {pkcs1} --kek rsakek --mech pkcs1 --label from-r2-pkcs1",
            f"export mem:from-r2-oaep {tmp}/oaep.out",
            f"export mem:from-r2-pkcs1 {tmp}/pkcs1.out",
        ]
        run_c2(lines)
        for name in ("oaep", "pkcs1"):
            got = (Path(tmp) / f"{name}.out").read_bytes().hex()
            assert got == TARGET, (name, got)
    print("part 2: c2 loaded the r2-produced oaep/pkcs1 blobs")


if __name__ == "__main__":
    part1()
    part2()
