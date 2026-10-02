"""PyYAML 6.0.3 vectors for r2_config::yaml and the r2_config decoder (spec §4.8.3/§4.8.4).

Run in the c2@408d6f2 venv; writes Rust to stdout:

    cd ../c2 && uv run python ../r2/crates/r2-config/tests/support/gen_yaml_vectors.py \
        > ../r2/crates/r2-config/tests/support/yaml_vectors.rs && cd ../r2 && cargo fmt

LOAD:   (yaml text, Ok(repr(yaml.safe_load(text))) | Err(PyYAML problem text or None))
DUMP:   (yaml text, yaml.safe_dump(yaml.safe_load(text), sort_keys=False, default_flow_style=False))
CONFIG_ERRORS: (external yaml, message, hint) of c2 `AppConfig.from_dict(_deep_merge(defaults, ext), "")`
CONFIG_SHOW: c2 `config show` text (`_to_plain` + safe_dump) for fixture configs, HOME=/home/tester,
             with the §7 c2→r2 path renames applied to the expected text.
"""

import datetime
import os
import sys

os.environ["HOME"] = "/home/tester"

import yaml

from c2.config import loader
from c2.config.model import AppConfig
from c2.core.errors import ConsoleError


def rs(s):
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20 or 0x7F <= o < 0xA0 or o > 0x7E:
            out.append("\\u{%x}" % o)
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def dq(s):
    """A YAML double-quoted scalar for any str."""
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif 0x20 <= o <= 0x7E:
            out.append(ch)
        elif o <= 0xFF:
            out.append("\\x%02X" % o)
        elif o <= 0xFFFF:
            out.append("\\u%04X" % o)
        else:
            out.append("\\U%08X" % o)
    return '"' + "".join(out) + '"'


def to_src(obj):
    """Flow-style YAML text that safe_loads back to obj."""
    if isinstance(obj, dict):
        return "{" + ", ".join(f"{to_src(k)}: {to_src(v)}" for k, v in obj.items()) + "}"
    if isinstance(obj, list):
        return "[" + ", ".join(to_src(v) for v in obj) + "]"
    if isinstance(obj, str):
        return dq(obj)
    if isinstance(obj, bytes):
        import base64

        return "!!binary " + dq(base64.b64encode(obj).decode())
    if obj is None or isinstance(obj, (bool, int, float, datetime.date)):
        text = yaml.safe_dump(obj)
        return text[: -len("\n...\n")] if text.endswith("\n...\n") else text.strip()
    raise TypeError(obj)


def dump(obj):
    return yaml.safe_dump(obj, sort_keys=False, default_flow_style=False)


# ---- LOAD vectors ---------------------------------------------------------------------------

LOAD = [
    "",
    "# only a comment\n",
    "---\n",
    "~",
    "a: 1\n",
    # YAML 1.1 bools (plain only) vs quoted
    "[yes, Yes, YES, no, No, NO, true, True, TRUE, false, False, FALSE, on, On, ON, off, Off, OFF]",
    "[yEs, y, n, 'yes', \"no\", 'on', oN]",
    # ints
    "[0, 7, -7, +7, 017, 0_17, 08, 0o17, 0x1F, -0x1f, 0x_1F, 0b101, -0b1_01, 1_000, 1:30, -1:30:00, 1:60, 190:20:30, 00, 0_, 1__0]",
    "[9223372036854775807, -9223372036854775808, 18446744073709551615]",
    # floats
    "[1.0, -1.5, +.5, .5, 1., 1.e+5, 1.0e+3, 1.0E-3, 1e3, 1.0e3, 6.8523015e+5, 685.230_15e+03, 190:20:30.15, 1_0.5, 0.1]",
    "[.inf, -.Inf, +.INF, .nan, .NaN, .NAN, +.nan, .Nan]",
    "[1.0e+400, -1.0e+400, 1.0e-400]",
    # null
    "[~, null, Null, NULL, nULL, '', \"null\", '~']",
    "a:\nb: ~\nc: !!null x\n",
    # strings
    "[abc, 'it''s', \"tab\\there\", \"\\u00e9\\U0001F600\", 'multi\n  line', 1_000x, 0x, 0b, 12:34:56:78, a=b]",
    "- |\n  literal\n  text\n- >\n  folded\n  text\n\n  next\n- |-\n  strip\n- |+\n  keep\n\n- >2\n   indented\n",
    "key: plain value with: colon\nother: 'single # not comment' # comment\n",
    # timestamps
    "[2001-12-14, 2001-12-14t21:59:43.10-05:00, 2001-12-14 21:59:43.10 -5, 2001-12-15T02:59:43.1Z, 2001-12-15 2:59:43.10, 2002-12-14 01:02:03, 2001-12-14 21:59:43.1234567+01:30, 2001-1-1, '2001-12-14']",
    "x: 2000-02-29 00:00:00\ny: 1999-12-31 23:59:59.999999 +23:59\n",
    # explicit tags
    "- !!str 1\n- !!str yes\n- !!int '42'\n- !!float '1'\n- !!bool 'yes'\n- !!null ''\n- !!str\n- ! 12\n- !!int 0x10\n- !!float 1_0\n",
    "a: !!binary AQID\nb: !!binary |\n  SGVsbG8gd29y\n  bGQ=\nc: !!binary ''\n",
    "!!map {a: 1}",
    "!!seq [1, 2]",
    # mappings: duplicates, non-string keys, merges
    "a: 1\nb: 2\na: 3\n",
    "{1: a, 1.0: b, true: c, 2: d, false: e, 0: f, null: g, ~: h}",
    "{3: x, 2.5: y, 2001-01-01: z, yes: w, '1': v}",
    "base: &b {x: 1, y: 2}\nderived:\n  <<: *b\n  y: 3\n  z: 4\n",
    "a: &a {k: a, ka: 1}\nb: &b {k: b, kb: 2}\nc:\n  <<: [*a, *b]\n  own: 3\n",
    "a: &a {x: 1}\nb: &b {<<: *a, y: 2}\nc: {<<: *b, z: 3}\n",
    "c: {z: 0, <<: {z: 1, w: 2}}\n",
    "'<<': {a: 1}\n",
    "a: &x [1, 2]\nb: *x\nc: &s scalar\nd: *s\n",
    "{=: 1}",
    "nested:\n  - {a: [1, {b: c}]}\n  - - x\n    - y\n",
    "[a, [b, [c, [d]]]]",
    "\ufeffa: 1\n",
    "a: \"\\x41\\u00e9\\t\"\n",
    # errors (construction: PyYAML problem text; syntax: any error)
    "a: 1\n---\nb: 2\n",
    "---\na\n---\n",
    "!!foo x",
    "!local x",
    "a: =",
    "[a]: 1",
    "? {a: 1}\n: x\n",
    "<<: 1",
    "<<: [1]",
    "a: <<",
    "ui: [unclosed\n",
    "a: b: c\n",
    "[1, 2",
    "x: 2001-02-30",
    "x: 2001-13-01",
    "x: !!binary '*'",
    "x: !!binary 'AQ'",
    # NEL is a line break to PyYAML (YAML 1.1) everywhere
    "# c\x85a: 1\n",
    "a: 1 # c\x85b: 2\n",
    "a: 1\x85b: 2\n",
    "a: \"x\x85  y\"",
    "a: 'x\x85\x85  y'",
    "a: x\x85  y",
    "a: |\n  x\x85  y\n",
    "k: ':2[ -\x85  \u00e9#,-'",
    "a: \"x\\\x85  y\"",
    # datetime: the offset is checked before the date
    "a: 2001-13-01 00:00:00 +24",
    "a: 2001-02-30 00:00:00 -24:00",
    # explicit !!int / !!float: Python int()/float() strip whitespace, accept a sign and
    # a base prefix
    "- !!int ' 12'\n- !!int '12 '\n- !!int '\u00a012'\n- !!int '- 12'\n- !!int ' -12'\n- !!int ' 017'\n- !!int '0o17'\n- !!int '0x0x1f'\n- !!int '0b0B1'\n- !!int '0x-1f'\n- !!int ' 1:30'\n- !!int '1:-30'\n- !!float ' 1.5 '\n",
    "a: !!int ' 0x1f'",
    "a: !!int '\u300012\u2000'",
    "a: !!float '\u30001.5'",
    "a: !!int '08'",
    # explicit !!value key → str of its text; `!`-tagged merge keys
    "? !!value x\n: 1\n",
    "? !!value [a]\n: 1\n",
    "! <<: {a: 1}",
    "a: 1\n! <<: {b: 2}\n",
    "! '<<': {a: 1}",
    "a: 1\n!!merge <<: {b: 2}\n",
    "? !!merge {a: 1}\n: x\n",
    # Python dict key equality
    ".nan: 1\n.NaN: 2\n",
    "{0: a, -0.0: b, 0.0: c, false: d, .inf: e, +.inf: f, -.inf: g}",
    "{9223372036854775809: a, 9.223372036854775808e+18: b, 9223372036854775808: c}",
    "{1.5: a, 1.50: b, 3: c, 3.0: d, 0x3: e}",
    # PyYAML Reader.check_printable: non-printable characters are rejected up front
    "a: 1\x00\nb: 2\nc: 3",
    "a: x\x01y",
    "a: x\x1by",
    "a: \"x\x7fy\"",
    "a: \"x\x90y\"",
    "a: x\ufffey",
    "a: x\uffffy",
    "\ufeffa: [ok, \x08]",
    "# \x00 in a comment\n",
    "a: \"x\xa0\ud7ff\ue000\ufffd\U00010000\U0010ffff\ty\"",
    # block scalars at the end of a text without a final line break: PyYAML keeps only the
    # breaks it read
    "a: |\n  x",
    "a: |+\n  x",
    "a: |-\n  x",
    "a: >\n  x\n  y",
    "a: |2\n   x",
    "- |\n  x",
    "--- |\n  x",
    "- |\n  x\n- |\n  y",
    "a: |\n  x\n  ",
    "a: |+\n  x\n\n  ",
    "a: |\n  x\n    ",
    "a: |\n    x\n  ",
    "a: |\n  x\n# c",
    "a: |\n    x\n  # c",
    "a: |\n  \u00e9\u00e9",
    "a: >\n  x\r\n  y",
    "templates:\n  pkcs11:\n    aes:\n      CKA_X: |\n        a\n        b",
    # block scalars without content lines at the end of the text
    "a: |",
    "a: |\n",
    "a: |+\n",
    "a: |+\n\n",
    "a: |+\n\n\n  ",
    "a: >\n  ",
    "|+\n",
    "- >-\n",
]
# r2 deviations (§11 D17): texts PyYAML loads but r2 rejects, with r2's message.
R2_ERRORS = [
    ("x: 99999999999999999999", "integer out of range: 99999999999999999999"),
    ("x: -9223372036854775809", "integer out of range: -9223372036854775809"),
    ("!!set {a, b}", "could not determine a constructor for the tag 'tag:yaml.org,2002:set'"),
    ("!!omap [a: 1]", "could not determine a constructor for the tag 'tag:yaml.org,2002:omap'"),
    ("!!pairs [a: 1]", "could not determine a constructor for the tag 'tag:yaml.org,2002:pairs'"),
    # (f) LS/PS are line breaks to PyYAML; r2 rejects them
    ("a: x\u2028  y", "unsupported line break character U+2028 at line 1, column 5"),
    ("a: 1\nb: 'x\u2029y'", "unsupported line break character U+2029 at line 2, column 6"),
    ("# c\u2028a: 1\n", "unsupported line break character U+2028 at line 1, column 4"),
    ("a: 1\x85b: |\n  x\u2028\n", "unsupported line break character U+2028 at line 3, column 4"),
    # (b) YAML 1.2 lets a top-level block scalar have unindented content; PyYAML ends the
    # scalar at such a line
    ("--- |\n# c", "unindented block scalar content at line 2, column 1"),
]

print("// Generated by gen_yaml_vectors.py (this directory) with PyYAML %s in the c2@408d6f2" % yaml.__version__)
print("// venv. Do not edit by hand (regenerate, then `cargo fmt`).")
print()
print("/// (yaml, Ok(repr(safe_load)) | Err(Some(PyYAML problem text)) | Err(None) = any error)")
print("pub const LOAD: &[(&str, Result<&str, Option<&str>>)] = &[")
for text in LOAD:
    try:
        value = yaml.safe_load(text)
        expected = f"Ok({rs(repr(value))})"
    except yaml.MarkedYAMLError as exc:
        if isinstance(exc, (yaml.composer.ComposerError, yaml.constructor.ConstructorError)) and (
            exc.problem.startswith(("could not determine", "found unhashable", "expected a mapping"))
        ):
            expected = f"Err(Some({rs(exc.problem)}))"
        elif exc.context == "expected a single document in the stream":
            expected = f"Err(Some({rs(exc.context)}))"
        else:
            expected = "Err(None)"
    except yaml.reader.ReaderError as exc:
        expected = f"Err(Some({rs(str(exc))}))"
    except ValueError as exc:
        expected = f"Err(Some({rs(str(exc))}))"
    print(f"    ({rs(text)}, {expected}),")
print("];")
# r2 deviations (§11 D17 (c)): integers outside -2^63..=2^64-1 are parse errors.
print("/// §11 D17 (c)/(d)/(f): texts PyYAML loads but r2 rejects, with r2's message.")
print("pub const LOAD_R2_ERRORS: &[(&str, &str)] = &[")
for text, message in R2_ERRORS:
    yaml.safe_load(text)  # PyYAML accepts it
    print(f"    ({rs(text)}, {rs(message)}),")
print("];")

LOAD_FUZZ = []

# ---- DUMP vectors -----------------------------------------------------------------------------

defaults_text = open(os.path.join(os.path.dirname(loader.__file__), "defaults.yaml")).read()
DUMP_OBJECTS = [
    {},
    [],
    {"a": {}, "b": [], "c": [{}], "d": [[]]},
    "abc",
    "",
    None,
    True,
    17,
    -1.5,
    [1, "two", None, True, 1.5e16, float("inf"), float("-inf")],
    {"providers": {"pkcs11": [{"name": "softhsm", "library": "/usr/lib/softhsm/libsofthsm2.so",
                               "token_label": "r2", "env": {"SOFTHSM2_CONF": "/home/tester/.config/r2/softhsm2/softhsm2.conf"}}]}},
    {"providers": {"pkcs11": [{"name": "softhsm", "library": "<path to libsofthsm2>",
                               "token_label": None, "env": {}}]}},
    {"aes": {"CKA_CLASS": "CKO_SECRET_KEY", "CKA_KEY_TYPE": "CKK_AES", "CKA_TOKEN": True, "CKA_PRIVATE": True,
             "CKA_LABEL": "ключ", "CKA_ID": "0x0a0b", "CKA_VALUE_LEN": 32, "CKA_EXTRACTABLE": False,
             "CKA_KEY_GEN_MECHANISM": 18446744073709551615, "CKA_VALUE": "0x" + "ab" * 40,
             "CKA_START_DATE": "", "CKA_APPLICATION": "my app"}},
    {"labels": ["yes", "no", "on", "off", "true", "Yes", "null", "~", "017", "08", "0x10", "1e3", "1.0", "1_000",
                "1:30", "2001-12-14", "=", "<<", "-", "- a", "a -", "?", "? x", ":", "a: b", "a:b", "#x", "a #b", "a#b",
                "[x", "x]", "{x", "x,y", "&a", "*a", "!a", "|", ">", "'q", "\"q", "%x", "@x", "`x", "---", "...", "--- x",
                " lead", "trail ", "a  b", "tab\there", "nl\nx", "\n", "x\n", "\nx", "a\n\nb", "a \nb", "a\n b",
                "é", "ключ", "日本語", "\U0001F600", "\x00", "\x07\x1b", "\x7f", "\x85", "\xa0", "\u2028", "\ufeff",
                "back\\slash", "say \"hi\"", "it's", "''", "\r", "a\rb"]},
    {"long_plain": "word " * 30 + "end",
     "long_single": "'quoted' " + "word " * 30 + "end",
     "long_double": "é " + "word " * 30 + "end",
     "long_nospace": "x" * 120,
     "long_multi": "first line\n" + "word " * 25 + "\nlast",
     "spaces_at_wrap": "a" * 78 + "   " + "b" * 10,
     "double_spaces": "é" + " x" * 60,
     "esc_at_wrap": ("ab\x01" * 40)},
    {"k" * 130: "long key", "short": "v", 3: "int key", None: "null key", True: "bool key", 1.5: "float key",
     "multi\nline key": 1, "": "empty key", "é": "unicode key"},
    {"nested": [{"a": [1, [2, [3]]], "b": {"c": {"d": None}}}, [[["deep"]]], {"x": [{}]}]},
    {"seq_in_seq": [[1, 2], [], [[]]], "map_in_seq": [{"a": 1, "b": 2}, {}]},
    {"dates": [datetime.date(2001, 12, 14), datetime.datetime(2001, 12, 14, 21, 59, 43, 100000),
               datetime.datetime(2001, 12, 14, 21, 59, 43, tzinfo=datetime.timezone(datetime.timedelta(hours=-5))),
               datetime.datetime(2001, 12, 15, 2, 59, tzinfo=datetime.timezone.utc)]},
    {"blob": b"\x00\x01\x02" * 30, "empty": b"", "short": b"hi"},
    yaml.safe_load(defaults_text),
]

# Seeded differential cases: random strings at several nesting levels (emitter style choice,
# quoting and width-80 folding) and random number-like plain scalars (implicit resolvers).
import random

rng = random.Random(20261001)
ALPHABET = list("abcxyz ") * 6 + list("  '\"#:-?,[]{}&*!|>%@`.\\\n\t") + ["é", "ж", "\x01", "\u2028", "\U0001F600", "\xa0"]


def rand_text():
    n = rng.choice([0, 1, 2, 3, 5, 8, 20, 40, 79, 80, 81, 90, 120, 200])
    return "".join(rng.choice(ALPHABET) for _ in range(n))


for _ in range(120):
    shape = rng.randrange(4)
    text = rand_text()
    if shape == 0:
        DUMP_OBJECTS.append({"k": text})
    elif shape == 1:
        DUMP_OBJECTS.append({"outer": {"inner": [text, {"deep": text}]}})
    elif shape == 2:
        DUMP_OBJECTS.append({text: 1})
    else:
        DUMP_OBJECTS.append([[text]])

TOKEN_CHARS = list("0123456789") * 3 + list("_:.eE+-xbo") + ["inf", "nan", "Inf", "NaN"]
for _ in range(400):
    token = "".join(rng.choice(TOKEN_CHARS) for _ in range(rng.randrange(1, 9)))
    text = "- " + token + "\n"
    try:
        yaml.safe_load(text)
    except Exception:
        continue
    LOAD_FUZZ.append(text)

print()
print("/// Seeded random plain scalars (implicit resolver differential).")
print("pub const LOAD_FUZZ: &[(&str, &str)] = &[")
for text in LOAD_FUZZ:
    print(f"    ({rs(text)}, {rs(repr(yaml.safe_load(text)))}),")
print("];")

print()
print("/// (yaml text, PyYAML dump of its safe_load)")
print("pub const DUMP: &[(&str, &str)] = &[")
for obj in DUMP_OBJECTS:
    src = to_src(obj)
    loaded = yaml.safe_load(src)
    assert loaded == obj or (obj != obj), (src, loaded, obj)
    print(f"    ({rs(src)}, {rs(dump(obj))}),")
print("];")

# ---- CONFIG_ERRORS: c2 decoder messages -----------------------------------------------------

defaults = yaml.safe_load(defaults_text)
MECH = "{id: v.x, verb: sign, algorithm: aes, cli_name: x, label: X, ckm: 0x80000001%s}"
CONFIG_ERRORS = [
    "ui: 5\n",
    "ui: {hex_group: lots}\n",
    "ui: {hex_group: -1}\n",
    "ui: {hex_width: 0}\n",
    "ui: {hex_width: 1.5}\n",
    "ui: {color: rainbow}\n",
    "ui: {confirm_delete: 'yes'}\n",
    "ui: {1: x}\n",
    "app: {log: {level: chatty}}\n",
    "app: {log: {level: 1}}\n",
    "app: {log: {max_bytes: -1}}\n",
    "app: {log: {backups: -2}}\n",
    "app: {log: {file: 3}}\n",
    "app: {history_file: [a]}\n",
    "app: {log: 5}\n",
    "providers: {pkcs11: [{name: hsm1}]}\n",
    "providers: {pkcs11: {name: hsm1}}\n",
    "providers: {pkcs11: [5]}\n",
    "providers: {pkcs11: [{name: 1bad, library: /l.so}]}\n",
    "providers: {pkcs11: [{name: h, library: /l.so, env: {FOO: 1}}]}\n",
    "providers: {pkcs11: [{name: h, library: /l.so, env: [a]}]}\n",
    "providers: {pkcs11: [{name: h, library: /l.so, env: {1: a}}]}\n",
    "providers: {pkcs11: [{name: h, library: /l.so, slot: abc}]}\n",
    "providers: {pkcs11: [{name: h, library: /l.so, token_label: 7}]}\n",
    "providers: {pkcs11: [{name: mem, library: /l.so}]}\n",
    "providers: {pkcs11: [{name: h, library: /a.so}, {name: h, library: /b.so}]}\n",
    "providers: {memory: {name: \"bad name\"}}\n",
    "providers: {memory: {enabled: maybe}}\n",
    "providers: {memory: {name: ''}}\n",
    "softhsm: {provider_name: 'soft hsm'}\n",
    "softhsm: {search_paths: /x}\n",
    "softhsm: {search_paths: [1]}\n",
    "softhsm: {autodetect: 1}\n",
    "templates: {pkcs11: {aes: {CKA_X: '0xzz'}}}\n",
    "templates: {pkcs11: {aes: {CKA_X: '0x0'}}}\n",
    "templates: {pkcs11: {aes: {CKA_X: [1, 2]}}}\n",
    "templates: {pkcs11: {aes: {CKA_X: 1.5}}}\n",
    "templates: {pkcs11: {aes: {CKA_X: null}}}\n",
    "templates: {pkcs11: {aes: 5}}\n",
    "templates: {pkcs11: {aes: {1: true}}}\n",
    "templates: {pkcs11: []}\n",
    "templates: {custom_attributes: {CKA_X: {code: -1, kind: bytes}}}\n",
    "templates: {custom_attributes: {CKA_X: {code: 1, kind: blob}}}\n",
    "templates: {custom_attributes: {CKA_X: {kind: bool}}}\n",
    "templates: {custom_attributes: {CKA_X: 3}}\n",
    "custom_mechanisms: {a: 1}\n",
    "custom_mechanisms: [5]\n",
    "custom_mechanisms:\n  - {id: v.x, verb: encipher, algorithm: aes, cli_name: x, label: X, ckm: 0x80000001}\n",
    "custom_mechanisms:\n  - {id: '', verb: sign, algorithm: aes, cli_name: x, label: X, ckm: 1}\n",
    "custom_mechanisms:\n  - {id: v.x, verb: sign, algorithm: none, cli_name: x, label: X, ckm: 1}\n",
    "custom_mechanisms:\n  - {id: v.x, verb: sign, algorithm: other, cli_name: x, label: X, ckm: 1}\n",
    "custom_mechanisms:\n  - {id: v.x, verb: sign, algorithm: aes, cli_name: '', label: X, ckm: 1}\n",
    "custom_mechanisms:\n  - {id: v.x, verb: sign, algorithm: aes, cli_name: x, label: X, ckm: -1}\n",
    "custom_mechanisms:\n  - {id: v.x, verb: sign, algorithm: aes, cli_name: x, label: X, ckm: '1'}\n",
    "custom_mechanisms:\n  - {id: v.x, verb: sign, algorithm: aes, cli_name: x, ckm: 0x80000001}\n",
    "custom_mechanisms:\n  - " + MECH % ", param_struct: cbc" + "\n",
    "custom_mechanisms:\n  - " + MECH % ", param_struct: null" + "\n",
    "custom_mechanisms:\n  - " + MECH % ", params: {a: 1}" + "\n",
    "custom_mechanisms:\n  - " + MECH % ", params: [{name: mode, kind: enum, prompt: Mode}]" + "\n",
    "custom_mechanisms:\n  - " + MECH % ", params: [{name: mode, kind: enum, prompt: Mode, choices: []}]" + "\n",
    "custom_mechanisms:\n  - " + MECH % ", params: [{name: mode, kind: enum, prompt: Mode, choices: [1]}]" + "\n",
    "custom_mechanisms:\n  - " + MECH % ", params: [{name: '', kind: int, prompt: P}]" + "\n",
    "custom_mechanisms:\n  - " + MECH % ", params: [{name: n, kind: float, prompt: P}]" + "\n",
    "custom_mechanisms:\n  - " + MECH % ", params: [{name: n, kind: int}]" + "\n",
    "custom_mechanisms:\n  - " + MECH % ", params: [{name: n, kind: int, prompt: P, required: null}]" + "\n",
    "custom_mechanisms:\n  - " + MECH % ", params: [{name: n, kind: int, prompt: P, required: 'no'}]" + "\n",
    "custom_mechanisms:\n  - " + MECH % ", providers: [ghosthsm]" + "\n",
    "custom_mechanisms:\n  - " + MECH % ", providers: ghosthsm" + "\n",
    "custom_mechanisms:\n  - " + MECH % ", provider_types: [1]" + "\n",
    "providers: {pkcs11: [{name: hsm2, library: /l.so}]}\ncustom_mechanisms:\n  - " + MECH % ", providers: [hsm2, mem, ghost]" + "\n",
]
print()
print("/// (external yaml, c2 message, c2 hint) of the typed decode of defaults deep-merged with it")
print("pub const CONFIG_ERRORS: &[(&str, &str, Option<&str>)] = &[")
for text in CONFIG_ERRORS:
    merged = loader._deep_merge(defaults, yaml.safe_load(text))
    try:
        AppConfig.from_dict(merged, "")
    except ConsoleError as exc:
        hint = "None" if exc.hint is None else f"Some({rs(exc.hint)})"
        print(f"    ({rs(text)}, {rs(exc.message)}, {hint}),")
        continue
    raise SystemExit(f"no error for {text!r}")
print("];")

# ---- CONFIG_SHOW: c2 `config show` output -----------------------------------------------------

from c2.console.commands.misc_cmd import _to_plain  # noqa: E402

SHOW = [
    "",
    "templates:\n  pkcs11:\n    aes:\n      CKA_ID: '0x0A 0B'\n      CKA_X: '0x0A0B'\n      CKA_Y: '0x0a 0b'\n"
    "      CKA_LABEL: ключ\n      CKA_VALUE_LEN: 32\n  custom_attributes:\n"
    "    CKA_ACME_USAGE: {code: 0x80000101, kind: bytes}\n",
    "providers:\n  pkcs11:\n    - name: prodhsm\n      library: ~/lib/libvendor.so\n      slot: 3\n"
    "      token_label: PROD\n      env: {VENDOR_HOME: /opt/vendor}\n    - {name: hsm2, library: ./x/../y.so}\n"
    "custom_mechanisms:\n  - id: vendor.acme.kcv\n    verb: sign\n    algorithm: aes\n    cli_name: acme-kcv\n"
    "    label: ACME key check value\n    ckm: 0x80000A01\n    param_struct: gcm\n    params:\n"
    "      - {name: iv, kind: bytes, prompt: IV, default: hex:0A0B}\n"
    "      - {name: aad, kind: bytes, prompt: AAD, required: false, default: AQID}\n"
    "      - {name: tag_bits, kind: enum, prompt: Tag bits, choices: ['96', '128'], default: 128}\n"
    "      - {name: rounds, kind: int, prompt: Rounds, required: false, default: 1}\n"
    "      - {name: flag, kind: bool, prompt: Flag, default: yes}\n"
    "      - {name: who, kind: str, prompt: Who, default: null}\n"
    "      - {name: key, kind: keyref, prompt: Key}\n"
    "    provider_types: [pkcs11]\n    providers: [prodhsm]\n",
]
print()
print("/// (external yaml, c2 `config show` output with the §7 renames)")
print("pub const CONFIG_SHOW: &[(&str, &str)] = &[")
for text in SHOW:
    merged = loader._deep_merge(defaults, yaml.safe_load(text) or {})
    config = AppConfig.from_dict(merged, "")
    out = yaml.safe_dump(_to_plain(config), sort_keys=False, default_flow_style=False)
    out = out.replace("/c2/", "/r2/").replace("c2.log", "r2.log")
    print(f"    ({rs(text)}, {rs(out)}),")
print("];")
