#!/usr/bin/env python3
"""Differential parity harness: c2@408d6f2 ⇄ r2 (spec §8 "Differential parity harness";
PLAN §9.6; owner R13). Python 3.10+ standard library only.

Three suites, each a set of identical piped sessions run through BOTH tools with
equivalent configs (``c2.yaml`` / ``r2.yaml``), compared after ``normalize.normalize``:

- ``transcript``: memory-provider sessions restricted to deterministic operations; the
  normalized transcripts must be equal line for line, and the files a session lists under
  ``## same-files:`` must be byte-identical between the two tools' work dirs.
- ``interop``: an export session writes every file format ``export`` produces (PKCS#8
  plain/encrypted PEM+DER, SPKI, X.509 PEM+DER, PKCS#12 incl. on-the-fly self-signed,
  CSRs, raw secrets, wrapped blobs raw/hex/b64 under KW/KWP/CBC/GCM/OAEP/PKCS1) and an
  import session loads them. Each tool's export is imported by BOTH tools; the four import
  transcripts (c2→c2, c2→r2, r2→c2, r2→r2) must be equal. ``key template`` YAML dumps are
  exchanged by the ``token`` suite (dumped by one tool, re-seeded by the other) and the
  renamed c2 user config by ``transcript_user_config``.
- ``token`` (``--softhsm``): both tools share ONE SoftHSM token dir. A create session puts
  objects of every kind on the token, a use session lists, uses, copies, dumps and deletes
  them; the four (creator, user) transcripts must be equal.

Exit status 0 = no unlisted difference. ``--update-expected`` is deliberately absent:
differences are fixed in r2 or recorded in spec §11, never accepted here.

Usage (from the r2 root):

    cargo build -p r2-cli
    python3 parity/harness/run_parity.py [--c2-dir ../c2] [--r2-bin PATH] [--softhsm]
        [--suite transcript|interop|token ...] [--keep] [-v]
"""

from __future__ import annotations

import argparse
import difflib
import filecmp
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, str(Path(__file__).resolve().parent))
from normalize import normalize  # noqa: E402

HERE = Path(__file__).resolve().parent
R2_ROOT = HERE.parent.parent
SESSIONS = HERE / "sessions"
FIXTURES = HERE / "fixtures"
TOOLS = ("c2", "r2")


@dataclass
class Ctx:
    c2_cmd: list[str]
    r2_cmd: list[str]
    base: Path
    verbose: bool
    softhsm_lib: str | None = None
    softhsm_conf: Path | None = None
    failures: list[str] = field(default_factory=list)


# the shared-token suite's PKCS#11 provider name (sessions use ``hsm:<label>`` refs)
TOKEN_PROVIDER = "hsm"


def config_text(tool: str, work: Path, softhsm_lib: str | None, extra: str = "") -> str:
    text = (
        "app:\n"
        f"  history_file: {work / 'history'}\n"
        "  log:\n"
        f"    file: {work / (tool + '.log')}\n"
        "ui:\n"
        "  confirm_delete: false\n"
        "softhsm:\n"
        "  autodetect: false\n"
    )
    if softhsm_lib:
        text += f"providers:\n  pkcs11:\n    - name: {TOKEN_PROVIDER}\n      library: {softhsm_lib}\n"
    return text + extra


def load_session(path: Path, subst: dict[str, str]) -> tuple[list[str], dict[str, list[str]]]:
    """Session lines (placeholders substituted) and its ``## key: values`` headers."""
    lines: list[str] = []
    headers: dict[str, list[str]] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.startswith("## "):
            key, _, value = raw[3:].partition(":")
            headers.setdefault(key.strip(), []).extend(value.split())
            continue
        if raw.startswith("##"):
            continue
        if raw.startswith("{PASTE:") and raw.endswith("}"):
            # the lines of a fixture file, pasted at a multiline prompt
            lines.extend((FIXTURES / raw[7:-1]).read_text(encoding="utf-8").splitlines())
            continue
        for key, value in subst.items():
            raw = raw.replace("{" + key + "}", value)
        lines.append(raw)
    return lines, headers


def run_tool(
    ctx: Ctx,
    tool: str,
    work: Path,
    lines: list[str],
    env_extra: dict[str, str],
    extra_config: str = "",
    columns: str = "200",
    final_newline: bool = True,
) -> str:
    work.mkdir(parents=True, exist_ok=True)
    home = work / "home"
    home.mkdir(exist_ok=True)
    config = work / f"{tool}.yaml"
    config.write_text(config_text(tool, work, ctx.softhsm_lib, extra_config), encoding="utf-8")
    env = {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "COLUMNS": columns,
        "LINES": "50",
        "LANG": "C.UTF-8",
        "PYTHONIOENCODING": "utf-8",
        "NO_COLOR": "1",
    }
    for var in ("UV_CACHE_DIR", "XDG_CACHE_HOME", "SSL_CERT_FILE"):
        if var in os.environ:
            env[var] = os.environ[var]
    if ctx.softhsm_conf:
        env["SOFTHSM2_CONF"] = str(ctx.softhsm_conf)
    env.update(env_extra)
    cmd = (ctx.c2_cmd if tool == "c2" else ctx.r2_cmd) + ["--config", str(config)]
    stdin = "\n".join(lines) + ("\n" if final_newline else "")
    proc = subprocess.run(
        cmd,
        input=stdin.encode(),
        cwd=work,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=600,
        check=False,
    )
    out = proc.stdout.decode("utf-8", "replace")
    (work / f"{tool}.stdout.txt").write_text(out, encoding="utf-8")
    if proc.returncode != 0:
        out += f"\n<exit status {proc.returncode}>\n"
    return out


def compare(
    ctx: Ctx,
    name: str,
    outputs: dict[str, str],
    works: dict[str, Path],
    inputs: dict[str, list[str]],
    secrets: set[str] | None = None,
    token_provider: str | None = None,
) -> bool:
    """``outputs``/``works``/``inputs`` are keyed by label ``[<producer>->]<consumer>``
    whose last ``:``-separated part is the tool that produced the transcript.
    ``token_provider`` (token suite only) enables the token-enumeration normalization."""
    norm = {
        label: normalize(
            text,
            label.split(":")[-1],
            str(works[label]),
            str(FIXTURES),
            inputs[label],
            secrets or set(),
            token_provider,
        )
        for label, text in outputs.items()
    }
    labels = list(norm)
    reference = labels[0]
    ok = True
    for other in labels[1:]:
        if norm[other] != norm[reference]:
            ok = False
            diff = "\n".join(
                difflib.unified_diff(
                    norm[reference], norm[other], reference, other, lineterm="", n=2
                )
            )
            ctx.failures.append(f"[{name}] {reference} vs {other}:\n{diff}")
    print(f"{'ok  ' if ok else 'FAIL'} {name} ({', '.join(labels)}; {len(norm[reference])} lines)")
    if ctx.verbose:
        for line in norm[reference]:
            print(f"     | {line}")
    return ok


def same_files(ctx: Ctx, name: str, files: list[str], a: Path, b: Path) -> None:
    for rel in files:
        fa, fb = a / rel, b / rel
        if not fa.exists() or not fb.exists():
            ctx.failures.append(f"[{name}] missing file {rel}: c2={fa.exists()} r2={fb.exists()}")
        elif not filecmp.cmp(fa, fb, shallow=False):
            ctx.failures.append(f"[{name}] file {rel} differs between c2 and r2")
    if files:
        print(f"     {name}: {len(files)} files compared byte-for-byte")


# ------------------------------------------------------------------------------ suites


def suite_transcript(ctx: Ctx) -> None:
    for path in sorted(SESSIONS.glob("transcript_*.session")):
        _, headers = load_session(path, {})
        # ``## columns: 80 200`` runs the session once per console width (default 200);
        # ``## final-newline: no`` pipes it without the newline after its last line
        widths = headers.get("columns") or ["200"]
        final_newline = headers.get("final-newline", ["yes"]) != ["no"]
        for width in widths:
            name = path.stem if widths == ["200"] else f"{path.stem}@{width}"
            outputs: dict[str, str] = {}
            works: dict[str, Path] = {}
            inputs: dict[str, list[str]] = {}
            for tool in TOOLS:
                work = ctx.base / "transcript" / name / tool
                lines, headers = load_session(path, {"WORK": str(work), "FIX": str(FIXTURES)})
                extra = "".join(
                    (FIXTURES / fixture).read_text(encoding="utf-8")
                    for fixture in headers.get("config", [])
                )
                outputs[tool] = run_tool(
                    ctx, tool, work, lines, {}, extra, columns=width, final_newline=final_newline
                )
                works[tool] = work
                inputs[tool] = lines
            compare(ctx, name, outputs, works, inputs, set(headers.get("secret", [])))
            same_files(ctx, name, headers.get("same-files", []), works["c2"], works["r2"])


def suite_interop(ctx: Ctx) -> None:
    exports = sorted(SESSIONS.glob("interop_*_export.session"))
    for export in exports:
        stem = export.stem.removesuffix("_export")
        importer = SESSIONS / f"{stem}_import.session"
        produced: dict[str, Path] = {}
        for tool in TOOLS:
            work = ctx.base / "interop" / stem / f"export-{tool}"
            lines, _ = load_session(export, {"WORK": str(work), "FIX": str(FIXTURES)})
            run_tool(ctx, tool, work, lines, {})
            produced[tool] = work
        outputs: dict[str, str] = {}
        works: dict[str, Path] = {}
        inputs: dict[str, list[str]] = {}
        for producer in TOOLS:
            for consumer in TOOLS:
                work = ctx.base / "interop" / stem / f"import-{producer}-by-{consumer}"
                src = str(produced[producer])
                lines, headers = load_session(
                    importer, {"WORK": str(work), "SRC": src, "FIX": str(FIXTURES)}
                )
                label = f"{producer}->{consumer}:{consumer}"
                outputs[label] = run_tool(ctx, consumer, work, lines, {}).replace(src, "{SRC}")
                works[label] = work
                inputs[label] = [line.replace(src, "{SRC}") for line in lines]
        compare(ctx, stem, outputs, works, inputs, set(headers.get("secret", [])))


def suite_token(ctx: Ctx) -> None:
    for create in sorted(SESSIONS.glob("token_*_create.session")):
        stem = create.stem.removesuffix("_create")
        use = SESSIONS / f"{stem}_use.session"
        outputs: dict[str, str] = {}
        works: dict[str, Path] = {}
        inputs: dict[str, list[str]] = {}
        for creator in TOOLS:
            for user in TOOLS:
                cwork = ctx.base / "token" / stem / f"create-{creator}-for-{user}"
                lines, _ = load_session(create, {"WORK": str(cwork), "FIX": str(FIXTURES)})
                run_tool(ctx, creator, cwork, lines, {}, columns="1000")
                uwork = ctx.base / "token" / stem / f"use-{creator}-by-{user}"
                lines, headers = load_session(
                    use, {"WORK": str(uwork), "SRC": str(cwork), "FIX": str(FIXTURES)}
                )
                label = f"{creator}->{user}:{user}"
                outputs[label] = run_tool(ctx, user, uwork, lines, {}, columns="1000").replace(
                    str(cwork), "{SRC}"
                )
                works[label] = uwork
                inputs[label] = [line.replace(str(cwork), "{SRC}") for line in lines]
        compare(
            ctx, stem, outputs, works, inputs, set(headers.get("secret", [])), TOKEN_PROVIDER
        )


SUITES = {"transcript": suite_transcript, "interop": suite_interop, "token": suite_token}


def softhsm_setup(base: Path) -> tuple[str, Path]:
    token_dir = base / "softhsm"
    proc = subprocess.run(
        [str(R2_ROOT / "scripts" / "softhsm-init.sh"), str(token_dir)],
        capture_output=True,
        text=True,
        check=True,
    )
    exports = {}
    for line in proc.stdout.splitlines():
        if line.startswith("export "):
            key, _, value = line[len("export ") :].partition("=")
            exports[key] = value.strip("'\"")
    return exports["R2_TEST_SOFTHSM_MODULE"], Path(exports["SOFTHSM2_CONF"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--c2-dir", default=os.environ.get("C2_DIR", str(R2_ROOT.parent / "c2")))
    parser.add_argument("--r2-bin", default=os.environ.get("R2_BIN"))
    parser.add_argument("--suite", action="append", choices=sorted(SUITES))
    parser.add_argument("--softhsm", action="store_true", help="also run the shared-token suite")
    parser.add_argument("--keep", action="store_true", help="keep the work dir")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    c2_dir = Path(args.c2_dir).resolve()
    venv_c2 = c2_dir / ".venv" / "bin" / "c2"
    c2_cmd = [str(venv_c2)] if venv_c2.exists() else ["uv", "run", "--project", str(c2_dir), "c2"]
    r2_bin = args.r2_bin
    if not r2_bin:
        target = Path(os.environ.get("CARGO_TARGET_DIR", R2_ROOT / "target"))
        r2_bin = str(target / "debug" / ("r2.exe" if os.name == "nt" else "r2"))
    if not Path(r2_bin).exists():
        print(f"r2 binary not found at {r2_bin} (cargo build -p r2-cli, or --r2-bin)", file=sys.stderr)
        return 2
    suites = args.suite or (["transcript", "interop"] + (["token"] if args.softhsm else []))
    if "token" in suites:
        args.softhsm = True

    # the normalization's own self-tests first: a harness that cannot see a changed prompt
    # must not report "no unlisted difference"
    selftest = unittest.TextTestRunner(stream=sys.stderr, verbosity=0).run(
        unittest.defaultTestLoader.discover(str(HERE), pattern="test_normalize.py")
    )
    if not selftest.wasSuccessful():
        print("harness self-test failed (test_normalize.py)", file=sys.stderr)
        return 2

    base = Path(tempfile.mkdtemp(prefix="r2-parity-"))
    ctx = Ctx(c2_cmd=c2_cmd, r2_cmd=[r2_bin], base=base, verbose=args.verbose)
    if args.softhsm:
        ctx.softhsm_lib, ctx.softhsm_conf = softhsm_setup(base)
    print(f"c2: {' '.join(c2_cmd)}\nr2: {r2_bin}\nwork: {base}")
    try:
        for suite in suites:
            print(f"== {suite}")
            SUITES[suite](ctx)
    finally:
        if not args.keep and not ctx.failures:
            shutil.rmtree(base, ignore_errors=True)
    if ctx.failures:
        print(f"\n{len(ctx.failures)} difference(s):", file=sys.stderr)
        for failure in ctx.failures:
            print(failure, file=sys.stderr)
        print(f"\nwork dir kept: {base}", file=sys.stderr)
        return 1
    print("parity: no unlisted difference")
    return 0


if __name__ == "__main__":
    sys.exit(main())
