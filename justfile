# r2 task runner (owner R0). The recipes wrap the commands of CLAUDE.md; `just gate R7` is
# the done gate of loop R7 (spec §8, loops.md working agreement 6).
# Builds share one target dir: export CARGO_TARGET_DIR to reuse it across checkouts.

set shell := ["bash", "-euo", "pipefail", "-c"]

include_only := "crates/r2-console/src/commands/*.rs crates/r2-console/src/tests/*.rs"

# List the recipes.
default:
    @just --list

# Build every crate.
build:
    cargo build --workspace

# Run the r2 binary, e.g. `just run --version`.
run *ARGS:
    cargo run -p r2-cli -- {{ARGS}}

# Format everything, including the include!-only console modules (spec §4.9.6).
fmt:
    cargo fmt --all
    rustfmt --edition 2024 {{include_only}}

# Check formatting (done gate steps 1-2).
fmt-check:
    cargo fmt --all --check
    rustfmt --edition 2024 --check {{include_only}}

# Lint with warnings denied (done gate step 3).
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Unit and integration tests under nextest, the normative runner (done gate step 4).
test *ARGS:
    cargo nextest run --workspace {{ARGS}}

# Doc tests (nextest does not run them; CI's test job does).
doctest:
    cargo test --workspace --doc

# Initialize a fresh SoftHSM fixture token and run the softhsm-feature suite.
softhsm-test *ARGS:
    eval "$(scripts/softhsm-init.sh)" && cargo nextest run --workspace --features softhsm {{ARGS}}

# Supply-chain checks (done gate step 5).
deny:
    cargo deny check

# Parity-ledger gate of one loop, e.g. `just ledger R7` (done gate step 6).
ledger LOOP:
    python3 parity/generate_ledger.py --stats --gate {{LOOP}}

# The whole done gate of one loop, in order.
gate LOOP: fmt-check clippy test deny (ledger LOOP)

# Differential parity harness against c2@408d6f2 (../c2 with `uv sync`), e.g.
# `just parity --softhsm` (spec §8; parity/harness/README.md).
parity *ARGS:
    cargo build -p r2-cli
    python3 parity/harness/run_parity.py {{ARGS}}

# Line coverage with the 80% floor (spec §8; needs cargo-llvm-cov). Pass `--features softhsm`
# after `eval "$(scripts/softhsm-init.sh)"` to include the SoftHSM suites, as CI does.
coverage *ARGS:
    cargo llvm-cov nextest --workspace --fail-under-lines 80 {{ARGS}}
