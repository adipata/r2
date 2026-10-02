#!/usr/bin/env bash
# Release build of the `r2` binary for one target (spec §9; owner R12).
#
#   scripts/release/build.sh <target-triple>
#
# Builds `-p r2-cli --release --locked --features vendored-openssl` (OpenSSL 3 from
# openssl-src, statically linked, legacy provider compiled in) with the root
# `[profile.release]`, and prints the path of the built binary on stdout (the last line).
#
# Linux (`*-linux-gnu`): glibc, never musl-static (a static musl binary cannot dlopen
# vendor PKCS#11 libraries). The binary is linked against the glibc $R2_GLIBC_BASELINE
# (default 2.28, RHEL/Rocky 8) with `cargo zigbuild --target <triple>.<glibc>`, which needs
# `cargo-zigbuild` and zig (`zig` on PATH or the `ziglang` Python package).
#
# Environment: CARGO_TARGET_DIR is honoured; R2_GLIBC_BASELINE overrides the baseline;
# Windows needs a native Perl for openssl-src (set OPENSSL_SRC_PERL, e.g. Strawberry Perl).
set -euo pipefail

target="${1:?usage: scripts/release/build.sh <target-triple>}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
glibc="${R2_GLIBC_BASELINE:-2.28}"
target_dir="${CARGO_TARGET_DIR:-$root/target}"

common=(--release --locked -p r2-cli --features vendored-openssl)

cd "$root"
case "$target" in
    *-linux-gnu)
        if ! cargo zigbuild --help > /dev/null 2>&1; then
            echo "error: cargo-zigbuild is required for the glibc $glibc baseline build" >&2
            exit 1
        fi
        echo "building $target against glibc $glibc (cargo zigbuild)" >&2
        cargo zigbuild "${common[@]}" --target "$target.$glibc" >&2
        ;;
    *-linux-musl*)
        echo "error: musl targets are not released: a static musl binary cannot dlopen glibc PKCS#11 libraries (spec §9)" >&2
        exit 1
        ;;
    *)
        echo "building $target (cargo build)" >&2
        cargo build "${common[@]}" --target "$target" >&2
        ;;
esac

exe=r2
case "$target" in
    *-windows-*) exe=r2.exe ;;
esac
binary="$target_dir/$target/release/$exe"
if [[ ! -f "$binary" ]]; then
    echo "error: expected binary not found: $binary" >&2
    exit 1
fi
echo "$binary"
