#!/usr/bin/env bash
# Build SoftHSM2 from its release tag for the CI version matrix (spec §8; owner R0).
#
#   scripts/build-softhsm.sh [PREFIX]
#
# Ubuntu 22.04 and 24.04 both ship SoftHSM 2.6.1, so CI builds 2.7.0 itself:
# CMake, -DENABLE_P11_KIT=OFF -DBUILD_TESTS=OFF, installed under PREFIX (default
# $HOME/.local/softhsm-$SOFTHSM_VERSION). A PREFIX that already holds the module (a CI cache
# hit) is reused as is. Needs git, cmake, a C++ compiler and the OpenSSL headers
# (Debian/Ubuntu: cmake g++ libssl-dev). Prints the module path on stdout; point
# $SOFTHSM2_LIB at it and put PREFIX/bin first on PATH (softhsm2-util) before running
# scripts/softhsm-init.sh.
set -euo pipefail

version="${SOFTHSM_VERSION:-2.7.0}"
repo="${SOFTHSM_REPO:-https://github.com/opendnssec/SoftHSMv2.git}"
prefix="${1:-$HOME/.local/softhsm-$version}"
module="$prefix/lib/softhsm/libsofthsm2.so"

die() {
    printf 'build-softhsm: %s\n' "$*" >&2
    exit 1
}

if [[ -f "$module" && -x "$prefix/bin/softhsm2-util" ]]; then
    printf 'build-softhsm: reusing %s\n' "$prefix" >&2
    printf '%s\n' "$module"
    exit 0
fi

for tool in git cmake; do
    command -v "$tool" >/dev/null || die "$tool not found on PATH"
done

work="$(mktemp -d "${TMPDIR:-/tmp}/softhsm-build.XXXXXX")"
trap 'rm -rf "$work"' EXIT

git clone --quiet --depth 1 --branch "$version" "$repo" "$work/src" >&2 ||
    die "cannot clone $repo at tag $version"
cmake -S "$work/src" -B "$work/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DENABLE_P11_KIT=OFF \
    -DBUILD_TESTS=OFF >&2 || die "cmake configure failed"
jobs="${SOFTHSM_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"
cmake --build "$work/build" --parallel "$jobs" >&2 || die "build failed"
cmake --install "$work/build" >&2 || die "install failed"

[[ -f "$module" ]] || die "build finished but $module is missing"
printf 'build-softhsm: SoftHSM %s installed in %s\n' "$version" "$prefix" >&2
printf '%s\n' "$module"
