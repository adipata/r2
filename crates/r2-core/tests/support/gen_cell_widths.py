"""Regenerate the rich 15 cell-width tables inside crates/r2-core/src/render.rs (R1).

Run in the c2@408d6f2 venv (rich 15.0.0), from the r2 root:
`cd ../c2 && uv run python ../r2/crates/r2-core/tests/support/gen_cell_widths.py ../r2/crates/r2-core/src/render.rs`.
It rewrites the block between the BEGIN/END GENERATED markers in place: rich's
`_unicode_data.load("latest")` table (`CellTable.widths` ranges, `narrow_to_wide`), which is
what rich's "auto" lookup uses when `UNICODE_VERSION` is unset.
"""
import sys
from importlib.metadata import version

from rich._unicode_data import load

BEGIN = "// BEGIN GENERATED rich cell tables"
END = "// END GENERATED rich cell tables"


def block() -> str:
    table = load("latest")
    out = [
        f"{BEGIN} (gen_cell_widths.py; rich {version('rich')}, Unicode {table.unicode_version}):",
        "// do not edit by hand.",
        "/// rich `CellTable.widths`: sorted, disjoint, inclusive code-point ranges of width 0 or 2;",
        "/// every other code point is 1 cell wide (after the C0/C1 rule of `char_width`).",
        "#[rustfmt::skip]",
        "const CELL_WIDTHS: &[(u32, u32, u8)] = &[",
    ]
    entries = [f"(0x{a:x}, 0x{b:x}, {w})," for a, b, w in table.widths]
    for i in range(0, len(entries), 4):
        out.append("    " + " ".join(entries[i : i + 4]))
    out.append("];")
    out.append("/// rich `CellTable.narrow_to_wide`: characters that a following U+FE0F (VS16) widens by")
    out.append("/// one cell (sorted, for binary search).")
    out.append("#[rustfmt::skip]")
    out.append("const NARROW_TO_WIDE: &[u32] = &[")
    chars = [f"0x{ord(c):x}," for c in sorted(table.narrow_to_wide, key=ord)]
    for i in range(0, len(chars), 10):
        out.append("    " + " ".join(chars[i : i + 10]))
    out.append("];")
    out.append(END)
    return "\n".join(out)


def main() -> None:
    path = sys.argv[1]
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    start = source.index(BEGIN)
    end = source.index(END) + len(END)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(source[:start] + block() + source[end:])


if __name__ == "__main__":
    main()
