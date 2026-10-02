#!/usr/bin/env bash
# Smoke test of a release binary (spec §9, §11 D2/D5; owner R12). Runs on every OS
# (Linux incl. the rockylinux:8 container, macOS, Windows Git Bash).
#
#   scripts/release/smoke.sh <binary> [<expected-version>]
#
# 1. `--version` prints exactly `r2 <version>` (default: the workspace version).
# 2. A piped `help` / `providers` / `exit` session exits 0, shows the banner, the help
#    table and the providers table with the built-in `mem` memory provider, and no error.
# 3. Vendored OpenSSL cipher set (spec §4.1.4, §9): with OPENSSL_MODULES and OPENSSL_CONF
#    pointing nowhere, a piped session loads into `mem` (as c2/pyca do; password
#    `r2-smoke`): fixtures/legacy-rc2-3des.p12 (RC2-40 certificate bag, 3DES key bag, SHA-1
#    MAC; `openssl pkcs12 -export -legacy`), fixtures/pbes2-camellia.p12,
#    fixtures/pbes2-seed.p12 and fixtures/pbes2-idea.p12 (PBES2/PBKDF2 bags with
#    CAMELLIA-256-CBC / SEED-CBC / IDEA-CBC). CAMELLIA is a default-provider cipher; RC2,
#    SEED and IDEA are legacy-provider ciphers. openssl-src compiles CAMELLIA, SEED and
#    IDEA out unless its camellia/seed/idea features are set, so these fixtures prove those
#    three features AND the compiled-in legacy provider (no module is loadable here). The
#    system-OpenSSL development build loads RC2/SEED/IDEA only when the distro `legacy`
#    module is available and has the cipher (§5.4: its absence is non-fatal).
#    Needs R8's `providers`, `load` and `keys` commands (merge R12 after R8).
#
# Sessions run in a scratch HOME/XDG/APPDATA so no user config, history or log is used or
# written, with R2_CONFIG and SOFTHSM2_LIB unset.
set -euo pipefail

binary="${1:?usage: scripts/release/smoke.sh <binary> [<expected-version>]}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
version="${2:-$("$here/version.sh")}"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

[[ -f "$binary" ]] || fail "no such file: $binary"
binary="$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")"

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/home" "$scratch/work"
cp "$here/fixtures/"*.p12 "$scratch/work/"

# GNU timeout when present (not on stock macOS; the workflow job has its own timeout).
run_limited() {
    if timeout --version > /dev/null 2>&1; then
        timeout 120 "$@"
    else
        "$@"
    fi
}

# r2 <args> with stdin from $1 (a file), in the scratch environment; stdout+stderr → $2.
# Prints the exit status.
session() {
    local input="$1" output="$2"
    shift 2
    local status=0
    (
        cd "$scratch/work"
        unset R2_CONFIG SOFTHSM2_LIB SOFTHSM2_CONF XDG_CONFIG_HOME XDG_STATE_HOME XDG_DATA_HOME XDG_CACHE_HOME
        export HOME="$scratch/home" USERPROFILE="$scratch/home" \
            APPDATA="$scratch/home/AppData/Roaming" LOCALAPPDATA="$scratch/home/AppData/Local" \
            NO_COLOR=1 RUST_BACKTRACE=1
        local assignment
        for assignment in "$@"; do
            export "${assignment?}"
        done
        run_limited "$binary" < "$input"
    ) > "$output" 2>&1 || status=$?
    echo "$status"
}

expect_fixed() {
    local file="$1" what="$2" text="$3"
    if ! LC_ALL=C grep -a -q -F -- "$text" "$file"; then
        echo "---- session output ($file) ----" >&2
        cat "$file" >&2
        fail "$what: no line contains '$text'"
    fi
    echo "ok: $what"
}

expect() {
    local file="$1" what="$2" pattern="$3"
    if ! LC_ALL=C grep -a -q -E -- "$pattern" "$file"; then
        echo "---- session output ($file) ----" >&2
        cat "$file" >&2
        fail "$what: no line matches /$pattern/"
    fi
    echo "ok: $what"
}

reject() {
    local file="$1" what="$2" pattern="$3"
    if LC_ALL=C grep -a -q -E -- "$pattern" "$file"; then
        echo "---- session output ($file) ----" >&2
        cat "$file" >&2
        fail "$what: found /$pattern/"
    fi
}

reject_fixed() {
    local file="$1" what="$2" text="$3"
    if LC_ALL=C grep -a -q -F -- "$text" "$file"; then
        echo "---- session output ($file) ----" >&2
        cat "$file" >&2
        fail "$what: found '$text'"
    fi
}

no_errors() {
    local file="$1"
    # The REPL renders errors only as the `error` panel (r2_core::io::error_panel, top
    # border `╭─ error ─…`); startup errors are a stderr line `error: …`. Anchored to those
    # so a command summary or key label containing the word "error" is not a failure.
    reject_fixed "$file" "no error panel" '╭─ error '
    reject "$file" "no startup error" '^error: '
    reject "$file" "no unknown command" 'unknown command'
    reject "$file" "no panic" 'panicked|internal error'
}

echo "== $binary"

# 1. --version --------------------------------------------------------------------------
got="$("$binary" --version | tr -d '\r')"
[[ "$got" == "r2 $version" ]] || fail "--version printed '$got', expected 'r2 $version'"
echo "ok: --version → $got"

# 2. piped help / providers / exit --------------------------------------------------------
printf 'help\nproviders\nexit\n' > "$scratch/session.in"
status="$(session "$scratch/session.in" "$scratch/session.out")"
[[ "$status" == 0 ]] || { cat "$scratch/session.out" >&2; fail "piped session exited with status $status"; }
# Literal match: the version may carry SemVer metadata (`+`, `-`), ERE metacharacters.
expect_fixed "$scratch/session.out" "banner" "r2 $version — type 'help' for commands"
expect "$scratch/session.out" "help table" "^[[:space:]]*providers[[:space:]]+List configured providers"
expect "$scratch/session.out" "help footer" "help <command> shows its usage"
expect "$scratch/session.out" "providers table: mem/memory" "^[[:space:]]*mem[[:space:]]+memory[[:space:]]"
expect "$scratch/session.out" "exit echoed" "r2> exit"
no_errors "$scratch/session.out"

# 3. vendored OpenSSL: legacy provider compiled in, camellia/seed/idea kept ----------------
{
    for fixture in legacy-rc2-3des pbes2-camellia pbes2-seed pbes2-idea; do
        printf 'load mem --file %s.p12 --password r2-smoke\n' "$fixture"
    done
    printf 'keys mem\nexit\n'
} > "$scratch/legacy.in"
status="$(session "$scratch/legacy.in" "$scratch/legacy.out" \
    OPENSSL_MODULES="$scratch/no-such-modules-dir" OPENSSL_CONF="$scratch/no-such-openssl.cnf")"
[[ "$status" == 0 ]] || { cat "$scratch/legacy.out" >&2; fail "PKCS#12 session exited with status $status"; }
for label in r2-legacy-smoke r2-camellia-smoke r2-seed-smoke r2-idea-smoke; do
    expect "$scratch/legacy.out" "$label: private key loaded" "mem:$label:priv[[:space:]]+private[[:space:]]+ec"
    expect "$scratch/legacy.out" "$label: certificate loaded" "mem:$label:cert[[:space:]]+cert[[:space:]]+ec"
done
no_errors "$scratch/legacy.out"

echo "smoke: $binary passed"
