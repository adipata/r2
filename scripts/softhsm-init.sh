#!/usr/bin/env bash
# SoftHSM2 test-token bootstrap (spec §4.10.5 contract; owner R0).
#
#   eval "$(scripts/softhsm-init.sh)"              # fresh temp dir, exports for this shell
#   scripts/softhsm-init.sh DIR                    # use (and create) DIR
#   scripts/softhsm-init.sh [DIR] --github-env     # CI: append VAR=value lines to $GITHUB_ENV
#
# Creates DIR/tokens and DIR/softhsm2.conf, locates the SoftHSM2 module ($SOFTHSM2_LIB, else
# the spec §7 softhsm.search_paths probe list), initializes the token R2TEST
# (SO PIN 4321, user PIN 1234) with softhsm2-util and prints `export VAR=value` lines for
# SOFTHSM2_CONF and the five R2_TEST_SOFTHSM_* variables read by
# r2_testkit::softhsm::softhsm_token(). Exits non-zero with a message on stderr when
# SoftHSM, softhsm2-util or the slot cannot be found. Only the export lines go to stdout.
set -euo pipefail

readonly TOKEN_LABEL="R2TEST"
readonly SO_PIN="4321"
readonly USER_PIN="1234"

die() {
    printf 'softhsm-init: %s\n' "$*" >&2
    exit 1
}

usage() {
    printf 'usage: %s [DIR] [--github-env]\n' "$0" >&2
    exit 2
}

dir=""
github_env=0
for arg in "$@"; do
    case "$arg" in
        --github-env) github_env=1 ;;
        -h | --help) usage ;;
        -*) usage ;;
        *)
            [[ -z "$dir" ]] || usage
            dir="$arg"
            ;;
    esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
defaults_yaml="$script_dir/../crates/r2-config/src/defaults.yaml"

# The spec §7 probe list, read from the embedded defaults (single source of truth):
# the `- path` items under `softhsm:` → `search_paths:`, comments and quotes stripped.
search_paths() {
    [[ -f "$defaults_yaml" ]] || die "cannot read $defaults_yaml (run from an r2 checkout)"
    awk '
        /^softhsm:/ { in_softhsm = 1; next }
        /^[^ #]/ { in_softhsm = 0 }
        in_softhsm && /^  search_paths:/ { in_paths = 1; next }
        in_paths && /^    - / {
            line = $0
            sub(/^    - /, "", line)
            sub(/[ \t]+#.*$/, "", line)
            gsub(/^"|"$/, "", line)
            print line
            next
        }
        in_paths { in_paths = 0 }
    ' "$defaults_yaml"
}

find_module() {
    if [[ -n "${SOFTHSM2_LIB:-}" ]]; then
        # An explicit override never falls through (spec §4.5.5 find_softhsm_module).
        [[ -e "$SOFTHSM2_LIB" ]] || die "\$SOFTHSM2_LIB=$SOFTHSM2_LIB does not exist"
        printf '%s\n' "$SOFTHSM2_LIB"
        return
    fi
    local count=0 candidate
    while IFS= read -r candidate; do
        count=$((count + 1))
        if [[ -e "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    done < <(search_paths)
    [[ "$count" -gt 0 ]] || die "no softhsm.search_paths found in $defaults_yaml"
    die "no SoftHSM2 PKCS#11 module found (\$SOFTHSM2_LIB or softhsm.search_paths); install softhsm2"
}

module="$(find_module)"
util="$(command -v softhsm2-util || true)"
[[ -n "$util" ]] || die "softhsm2-util not found on PATH; install softhsm2"

if [[ -z "$dir" ]]; then
    dir="$(mktemp -d "${TMPDIR:-/tmp}/r2-softhsm.XXXXXX")"
fi
mkdir -p "$dir"
dir="$(cd "$dir" && pwd)"
tokens="$dir/tokens"
mkdir -p "$tokens"
if [[ -n "$(ls -A "$tokens")" ]]; then
    die "$tokens is not empty; pass a fresh directory (or none for a temporary one)"
fi
conf="$dir/softhsm2.conf"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
    "$tokens" >"$conf"

export SOFTHSM2_CONF="$conf"
if ! init_out="$("$util" --init-token --free --label "$TOKEN_LABEL" \
    --so-pin "$SO_PIN" --pin "$USER_PIN" 2>&1)"; then
    die "softhsm2-util --init-token failed: $init_out"
fi

slot=""
if [[ "$init_out" =~ reassigned\ to\ slot\ ([0-9]+) ]]; then
    slot="${BASH_REMATCH[1]}"
else
    # Fallback: the slot whose token Label is R2TEST in --show-slots.
    current=""
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"
        if [[ "$line" =~ ^Slot\ ([0-9]+) ]]; then
            current="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^Label:[[:space:]]+${TOKEN_LABEL}[[:space:]]*$ ]]; then
            slot="$current"
            break
        fi
    done < <("$util" --show-slots 2>/dev/null || true)
fi
[[ -n "$slot" ]] || die "could not determine the slot of token $TOKEN_LABEL from: $init_out"

emit() {
    local name="$1" value="$2"
    if [[ "$github_env" -eq 1 ]]; then
        [[ -n "${GITHUB_ENV:-}" ]] || die "--github-env given but \$GITHUB_ENV is not set"
        printf '%s=%s\n' "$name" "$value" >>"$GITHUB_ENV"
    else
        printf 'export %s=%q\n' "$name" "$value"
    fi
}

emit SOFTHSM2_CONF "$conf"
emit R2_TEST_SOFTHSM_MODULE "$module"
emit R2_TEST_SOFTHSM_SLOT "$slot"
emit R2_TEST_SOFTHSM_LABEL "$TOKEN_LABEL"
emit R2_TEST_SOFTHSM_USER_PIN "$USER_PIN"
emit R2_TEST_SOFTHSM_SO_PIN "$SO_PIN"
printf 'softhsm-init: token %s initialized in slot %s (%s)\n' "$TOKEN_LABEL" "$slot" "$dir" >&2
