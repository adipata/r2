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
# Windows needs a native Perl for openssl-src (set OPENSSL_SRC_PERL, e.g. Strawberry Perl)
# and NASM on PATH: without NASM openssl-src silently configures `no-asm` (portable C,
# table-based non-constant-time AES/GHASH, no AES-NI/PCLMUL), so an MSVC build requires
# `nasm` and exports OPENSSL_RUST_USE_NASM=1 (a broken NASM then fails the build).
set -euo pipefail

target="${1:?usage: scripts/release/build.sh <target-triple>}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
glibc="${R2_GLIBC_BASELINE:-2.28}"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
if [[ ! "$glibc" =~ ^[0-9]+\.[0-9]+$ ]]; then
    echo "error: R2_GLIBC_BASELINE must be <major>.<minor> (got '$glibc')" >&2
    exit 1
fi

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
    *-windows-msvc)
        if ! command -v nasm > /dev/null 2>&1; then
            echo "error: nasm is required for the $target OpenSSL assembly (openssl-src would build no-asm)" >&2
            exit 1
        fi
        echo "building $target (cargo build, OpenSSL asm via $(nasm -v))" >&2
        OPENSSL_RUST_USE_NASM=1 cargo build "${common[@]}" --target "$target" >&2
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
