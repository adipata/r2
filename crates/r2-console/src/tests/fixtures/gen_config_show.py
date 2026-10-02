"""Generates c2's `config show` text (PyYAML safe_dump of _to_plain) for R7's parity test.

Run from the c2 checkout: HOME=/home/tester uv run python gen_config_show.py OUTDIR
"""
import sys
import yaml
from importlib import resources
from c2.config.model import AppConfig
from c2.console.commands.misc_cmd import _to_plain

OVERRIDES = """
app:
  log:
    level: debug
    max_bytes: 0
providers:
  memory:
    name: ram
  pkcs11:
    - name: prodhsm
      library: ~/lib/p11.so
      slot: 3
      token_label: "Main HSM: ключ"
      env:
        VENDOR_CONF: /etc/vendor.conf
templates:
  pkcs11:
    aes:
      CKA_ID: '0x0A 0B'
      CKA_LABEL: "yes"
      CKA_TOKEN: false
    data:
      CKA_APPLICATION: a very long application name that goes on and on and on beyond the eighty column limit of the emitter
  custom_attributes:
    CKA_ACME_USAGE: {code: 0x80000101, kind: bytes}
custom_mechanisms:
  - id: vendor.acme.kcv
    verb: sign
    algorithm: aes
    cli_name: acme-kcv
    label: ACME key check value
    ckm: 0x80000A01
    param_struct: raw
    params:
      - {name: rounds, kind: int, prompt: KCV rounds, required: false, default: 1}
      - {name: blob, kind: bytes, prompt: Blob, required: false, default: "hex:0A0B"}
      - {name: tag, kind: enum, prompt: Tag, choices: ["96", "128"], required: false, default: 128}
"""


def deep_merge(base, override):
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def show(data):
    cfg = AppConfig.from_dict(data, "")
    return yaml.safe_dump(_to_plain(cfg), sort_keys=False, default_flow_style=False).rstrip()


text = resources.files("c2.config").joinpath("defaults.yaml").read_text("utf-8")
defaults = yaml.safe_load(text)
out = sys.argv[1]
open(f"{out}/config_show_defaults.c2.txt", "w", encoding="utf-8").write(show(defaults))
open(f"{out}/config_show_overrides.yaml", "w", encoding="utf-8").write(OVERRIDES.lstrip())
merged = deep_merge(defaults, yaml.safe_load(OVERRIDES))
open(f"{out}/config_show_overrides.c2.txt", "w", encoding="utf-8").write(show(merged))
