"""Generate rich-15 table vectors for r2's table renderer (§4.9.2, §11 D1): c2's
`render.make_table` printed by rich at several console widths, converted to r2's D1 form
(no blank SIMPLE_HEAD edge columns or edge rows, trailing blanks trimmed).

Run in the c2@408d6f2 venv:
  cd ../c2 && uv run python ../r2/crates/r2-core/tests/support/gen_rich_tables.py \
      > ../r2/crates/r2-core/tests/support/rich_tables.rs && cd ../r2 && cargo fmt
"""
import io, random, unicodedata
from rich.console import Console
from c2.console import render
from c2.console.commands import all_commands


def rich_lines(table, width):
    buf = io.StringIO()
    Console(file=buf, force_terminal=False, width=width).print(table)
    out = buf.getvalue()
    assert out.endswith("\n")
    return out[:-1].split("\n")


def d1_form(title, columns, rows, width):
    """rich's output for `make_table(...)` at `width`, as r2 draws it."""
    full = rich_lines(render.make_table(columns, rows, title=title), width)
    body = rich_lines(render.make_table(columns, rows), width)
    titles = full[: len(full) - len(body)]
    assert body[0].strip() == "" and body[-1].strip() == "", body
    out = []
    for line in titles:
        out.append((line[1:] if line.startswith(" ") else line).rstrip(" "))
    for line in body[1:-1]:
        assert line.startswith(" "), line
        out.append(line[1:].rstrip(" "))
    return "\n".join(out)


def rs(s):
    out = []
    for ch in s:
        if ch == "\\": out.append("\\\\")
        elif ch == '"': out.append('\\"')
        elif ch == "\n": out.append("\\n")
        elif ch == "\t": out.append("\\t")
        elif ord(ch) < 0x20 or ord(ch) == 0x7f: out.append("\\u{%x}" % ord(ch))
        elif ord(ch) > 0x7f and unicodedata.category(ch)[0] in "MCZ": out.append("\\u{%x}" % ord(ch))
        else: out.append(ch)
    return '"' + "".join(out) + '"'


help_rows = [
    (cmd.name, cmd.summary)
    for cmd in sorted(all_commands().values(), key=lambda c: c.name)
]
ops_rows = [
    ("encrypt", "cbc", "AES-CBC", "iv, padding", "AES-CBC encryption"),
    ("encrypt", "ctr", "AES-CTR", "counter_block, counter_bits", "AES-CTR encryption"),
    ("encrypt", "gcm", "AES-GCM", "iv, aad, tag_bits", "AES-GCM authenticated encryption"),
    ("encrypt", "pkcs1", "RSA-PKCS1", "—", "RSA PKCS#1 v1.5 encryption"),
    ("encrypt", "raw", "RSA-RAW", "—",
     "Raw RSA (textbook) encryption — input left-padded to modulus length"),
    ("sign", "pss", "RSA-PSS", "hash, mgf_hash, salt_len", "RSA-PSS signature"),
    ("verify", "pkcs1", "RSA-PKCS1", "hash", "RSA PKCS#1 v1.5 signature verification"),
    ("sign", "hmac", "HMAC", "hash",
     "HMAC (SHA-1/224/256/384/512) over a generic secret"),
]
keys_rows = [
    ("mem:k1", "private", "rsa", "2048", "yes"),
    ("mem:k1", "public", "rsa", "2048", "yes"),
    ("mem:some-long-label-name", "secret", "aes", "256", "yes"),
    ("softhsm:a label with spaces", "secret", "generic", "160", "no (sensitive)"),
]
fixed = [
    ("commands", ("command", "summary"), help_rows),
    ("operations — mem", ("verb", "op", "mechanism", "params", "description"), ops_rows),
    ("keys", ("ref", "class", "algorithm", "size/curve", "exportable"), keys_rows),
    ("mem:k1", ("field", "value"), [
        ("ref", "mem:k1"), ("class", "private"), ("algorithm", "rsa"),
        ("usage", "decrypt, sign, unwrap"),
        ("attributes", "CKA_SENSITIVE=False CKA_EXTRACTABLE=True CKA_TOKEN=False"),
    ]),
    (None, ("h\tx", "b"), [("a\tb", "abc\td\nq\tw")]),
    (None, ("a", "bb"), [("xyz", "hello world")]),
    (None, ("a", "b"), [("x",), ("1", "2", "3")]),
    (None, ("name", "値"), [("日本語 テキスト", "ключ значение длинное"), ("éte", "🔑 key")]),
    ("a title much longer than the table body itself", ("n",), [("1",)]),
]

rng = random.Random(408)
WORDS = ["a", "an", "key", "label", "wrap", "token", "modulus", "provider", "x509",
         "PKCS#11", "日本", "—", "ab-cd", "q"]
generated = []
for _ in range(120):
    ncols = rng.randint(1, 5)
    columns = tuple(rng.choice(["ref", "class", "c", "description", "value", "n"])
                    for _ in range(ncols))
    rows = []
    for _ in range(rng.randint(0, 4)):
        rows.append(tuple(" ".join(rng.choice(WORDS) for _ in range(rng.randint(0, 9)))
                          for _ in range(ncols)))
    generated.append((rng.choice([None, "t", "random table"]), columns, rows))

WIDTHS = [20, 30, 40, 50, 60, 70, 80, 100, 120]
full, rules = [], []
for title, columns, rows in fixed + generated:
    for width in WIDTHS:
        expected = d1_form(title, columns, rows, width)
        source = (title or "") + "".join(columns) + "".join("".join(r) for r in rows)
        rule = next(line for line in expected.split("\n") if line and set(line) == {"─"})
        case = (title, columns, [list(r) for r in rows], width)
        if "…" in expected and "…" not in source:
            rules.append((case, rule))  # rich cropped a cell (D1): only the widths compare
        else:
            full.append((case, expected))


def case_rs(case):
    title, columns, rows, width = case
    t = "None" if title is None else f"Some({rs(title)})"
    cols = "&[" + ", ".join(rs(c) for c in columns) + "]"
    rws = "&[" + ", ".join("&[" + ", ".join(rs(c) for c in r) + "]" for r in rows) + "]"
    return f"{t}, {cols}, {rws}, {width}"


print("// Generated by gen_rich_tables.py (this directory) with rich 15.0.0 in the c2@408d6f2")
print("// venv. Expected = c2 `render.make_table(columns, rows, title=title)` printed by")
print("// `Console(file=StringIO(), force_terminal=False, width=W)`, in r2's §11 D1 form (the")
print("// blank SIMPLE_HEAD edge columns and edge rows dropped, trailing blanks trimmed).")
print("// Do not edit by hand (regenerate, then `cargo fmt`).")
print("/// (title, columns, rows, console width, expected)")
print("pub type TableCase = (")
print("    Option<&'static str>,")
print("    &'static [&'static str],")
print("    &'static [&'static [&'static str]],")
print("    usize,")
print("    &'static str,")
print(");")
print("/// Tables rich laid out without cropping a word: r2's output equals rich's.")
print("pub const TABLES: &[TableCase] = &[")
for case, expected in full:
    print(f"    ({case_rs(case)}, {rs(expected)}),")
print("];")
print("/// Tables where rich cropped a word with `…` (r2 folds it, §11 D1): the column widths")
print("/// still equal rich's, so the header rule (expected) does.")
print("pub const TABLE_RULES: &[TableCase] = &[")
for case, rule in rules:
    print(f"    ({case_rs(case)}, {rs(rule)}),")
print("];")
