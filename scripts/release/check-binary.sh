#!/usr/bin/env bash
# Static checks of a release binary (spec §9; owner R12).
#
#   scripts/release/check-binary.sh <binary> <target-triple>
#
# Every target: the binary embeds the vendored OpenSSL 3 (>= 3.2, §11 D26: implicit
# rejection for RSA-PKCS1 decryption, as pyca/c2) with the legacy provider compiled in, and
# links no shared libssl/libcrypto.
# Linux: a dynamically linked glibc ELF (never musl-static) of the target's machine whose
# required GLIBC_* symbol versions are all <= $R2_GLIBC_BASELINE (default 2.28, RHEL/Rocky
# 8), and whose NEEDED entries are glibc/libgcc only. macOS: the target's architecture and
# only system libraries. Needs readelf (binutils) on Linux and otool/lipo on macOS.
set -euo pipefail

binary="${1:?usage: scripts/release/check-binary.sh <binary> <target-triple>}"
target="${2:?usage: scripts/release/check-binary.sh <binary> <target-triple>}"
baseline="${R2_GLIBC_BASELINE:-2.28}"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

[[ -f "$binary" ]] || fail "no such file: $binary"

# "a.b" → a*1000+b, for numeric comparison of glibc versions.
version_key() {
    local major="${1%%.*}" rest="${1#*.}"
    local minor="${rest%%.*}"
    echo $((10#$major * 1000 + 10#$minor))
}

# --- OpenSSL: vendored, >= 3.2, statically linked ------------------------------------------
# The vendored OpenSSL is the openssl-src locked in Cargo.lock (`300.x+3.y.z`). LTO drops
# OpenSSL_version()'s text, but the built-in provider names stay: libcrypto 3 is linked in
# (a dynamic libcrypto keeps them in the .so) with the legacy provider compiled in.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
openssl_src="$(awk '/^name = "openssl-src"$/ { getline; gsub(/^version = "|"$/, ""); print; exit }' "$root/Cargo.lock")"
[[ "$openssl_src" =~ ^300\.[0-9]+\.[0-9]+\+3\.([0-9]+)\.[0-9]+$ ]] ||
    fail "Cargo.lock locks no openssl-src 300.x (got '${openssl_src:-none}'): is the vendored-openssl feature defined?"
((BASH_REMATCH[1] >= 2)) || fail "openssl-src $openssl_src is older than OpenSSL 3.2 (spec §9, §11 D26)"
echo "ok: Cargo.lock vendors openssl-src $openssl_src"
for marker in 'OpenSSL Default Provider' 'OpenSSL Legacy Provider'; do
    LC_ALL=C grep -a -q -F "$marker" "$binary" ||
        fail "'$marker' not in the binary: OpenSSL is not vendored or the legacy provider is not compiled in"
done
echo "ok: built-in default and legacy providers are linked in"

case "$target" in
    *-linux-gnu)
        command -v readelf > /dev/null || fail "readelf (binutils) is required"
        header="$(LC_ALL=C readelf -h "$binary")"
        case "$target" in
            x86_64-*) machine='Advanced Micro Devices X86-64' ;;
            aarch64-*) machine='AArch64' ;;
            *) fail "unsupported linux target $target" ;;
        esac
        grep -q "Machine:.*$machine" <<< "$header" || fail "not an ELF for $target: $(grep 'Machine:' <<< "$header")"
        echo "ok: ELF machine $machine"

        # glibc, dynamically linked: a program interpreter (ld-linux) is present.
        interp="$(LC_ALL=C readelf -l "$binary" | sed -n 's/.*\[Requesting program interpreter: \(.*\)\]/\1/p')"
        [[ "$interp" == */ld-linux* ]] || fail "not a dynamically linked glibc binary (interpreter: '${interp:-none}')"
        echo "ok: interpreter $interp"

        needed="$(LC_ALL=C readelf -d "$binary" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')"
        while IFS= read -r lib; do
            [[ -z "$lib" ]] && continue
            case "$lib" in
                libc.so.6 | libm.so.6 | libdl.so.2 | libpthread.so.0 | librt.so.1 | libutil.so.1 | libgcc_s.so.1 | ld-linux*.so.*) ;;
                *) fail "unexpected shared library dependency $lib (OpenSSL must be vendored and static)" ;;
            esac
        done <<< "$needed"
        echo "ok: NEEDED $(echo "$needed" | tr '\n' ' ')"

        versions="$(LC_ALL=C readelf -W -V "$binary" | grep -o 'Name: GLIBC_[0-9][0-9.]*' | sed 's/Name: GLIBC_//' | sort -u -V)"
        [[ -n "$versions" ]] || fail "no GLIBC_* symbol versions found"
        newest="$(echo "$versions" | tail -n 1)"
        if (($(version_key "$newest") > $(version_key "$baseline"))); then
            fail "requires GLIBC_$newest, newer than the glibc $baseline baseline (spec §9); required: $(echo "$versions" | tr '\n' ' ')"
        fi
        echo "ok: newest required symbol version GLIBC_$newest <= $baseline"
        ;;
    *-apple-darwin)
        command -v lipo > /dev/null || fail "lipo is required"
        archs="$(lipo -archs "$binary")"
        case "$target" in
            x86_64-*) want=x86_64 ;;
            aarch64-*) want=arm64 ;;
            universal-*) want='x86_64 arm64' ;;
            *) fail "unsupported darwin target $target" ;;
        esac
        for arch in $want; do
            [[ " $archs " == *" $arch "* ]] || fail "missing architecture $arch (has: $archs)"
        done
        echo "ok: architectures $archs"
        libs="$(otool -L "$binary" | tail -n +2 | awk '{print $1}')"
        while IFS= read -r lib; do
            [[ -z "$lib" ]] && continue
            case "$lib" in
                /usr/lib/* | /System/Library/*) ;;
                *) fail "unexpected shared library dependency $lib (OpenSSL must be vendored and static)" ;;
            esac
        done <<< "$libs"
        echo "ok: system libraries only"
        ;;
    *-windows-msvc)
        # The import table names every DLL; a dynamic OpenSSL would import libcrypto-3*.dll.
        if LC_ALL=C grep -a -i -q 'libcrypto-3\|libssl-3' "$binary"; then
            fail "imports a shared OpenSSL DLL (OpenSSL must be vendored and static)"
        fi
        echo "ok: no OpenSSL DLL import"
        ;;
    *)
        fail "unsupported target $target"
        ;;
esac
echo "check-binary: $binary ($target) passed"
