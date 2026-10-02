#!/usr/bin/env python3
"""Generate r2-pkcs11's PyKCS11 name tables (spec §4.5.5, owner R5a).

Run inside c2's venv (PyKCS11 1.5.18, c2@408d6f2):

    cd ../c2 && uv run python ../r2/parity/generate_pkcs11_names.py ../r2/crates/r2-pkcs11/src/catalog.rs

It rewrites the region between the `// BEGIN GENERATED PyKCS11 tables` and
`// END GENERATED PyKCS11 tables` markers of catalog.rs. `--check` exits 1 when the
committed region differs. The forward table holds every CKO_/CKK_/CKC_/CKM_ name of
PyKCS11's dictionaries (aliases included); the reverse tables are PyKCS11's value→name
entries (its alias choice), negative codes (PyKCS11's own load errors) excluded.
"""

from __future__ import annotations

import sys

import PyKCS11

BEGIN = "// BEGIN GENERATED PyKCS11 tables"
END = "// END GENERATED PyKCS11 tables"


def table() -> str:
    out = [BEGIN, f"// PyKCS11 {getattr(PyKCS11, '__version__', '1.5.18')}; do not edit by hand."]
    forward: list[tuple[str, int]] = []
    for prefix in ("CKO", "CKK", "CKC", "CKM"):
        d = getattr(PyKCS11, prefix)
        forward += [(k, v) for k, v in d.items() if isinstance(k, str)]
    forward.sort()
    out.append(f"pub(crate) const SYMBOLS: [(&str, u64); {len(forward)}] = [")
    out += [f'    ("{k}", 0x{v:X}),' for k, v in forward]
    out.append("];")
    for prefix in ("CKO", "CKK", "CKC", "CKM", "CKR"):
        d = getattr(PyKCS11, prefix)
        rev = sorted((k, v) for k, v in d.items() if isinstance(k, int) and k >= 0)
        out.append(f"pub(crate) const {prefix}_NAMES: [(u64, &str); {len(rev)}] = [")
        out += [f'    (0x{k:X}, "{v}"),' for k, v in rev]
        out.append("];")
    out.append(END)
    return "\n".join(out)


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--check"]
    path = args[0]
    text = open(path, encoding="utf-8").read()
    start, end = text.index(BEGIN), text.index(END) + len(END)
    new = text[:start] + table() + text[end:]
    if "--check" in sys.argv:
        return 0 if new == text else 1
    open(path, "w", encoding="utf-8").write(new)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
