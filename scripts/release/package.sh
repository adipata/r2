#!/usr/bin/env bash
# Package a release binary (spec §9; owner R12).
#
#   scripts/release/package.sh <binary> <target> <version> <out-dir>
#
# Writes <out-dir>/r2-<version>-<target>.tar.gz (Linux, macOS; keeps the executable bit)
# or <out-dir>/r2-<version>-<target>.zip (Windows), holding one directory
# r2-<version>-<target>/ with the binary and LICENSE (GPL-3.0). Prints the archive path.
set -euo pipefail

binary="${1:?usage: scripts/release/package.sh <binary> <target> <version> <out-dir>}"
target="${2:?usage: scripts/release/package.sh <binary> <target> <version> <out-dir>}"
version="${3:?usage: scripts/release/package.sh <binary> <target> <version> <out-dir>}"
out="${4:?usage: scripts/release/package.sh <binary> <target> <version> <out-dir>}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

[[ -f "$binary" ]] || { echo "error: no such file: $binary" >&2; exit 1; }
mkdir -p "$out"
out="$(cd "$out" && pwd)"

name="r2-$version-$target"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/$name"
case "$target" in
    *-windows-*) exe=r2.exe ;;
    *) exe=r2 ;;
esac
cp "$binary" "$stage/$name/$exe"
chmod 755 "$stage/$name/$exe"
cp "$root/LICENSE" "$stage/$name/LICENSE"

case "$target" in
    *-windows-*)
        archive="$out/$name.zip"
        rm -f "$archive"
        if command -v 7z > /dev/null; then
            (cd "$stage" && 7z a -tzip -bd "$archive" "$name" > /dev/null)
        else
            (cd "$stage" && zip -q -r "$archive" "$name")
        fi
        ;;
    *)
        archive="$out/$name.tar.gz"
        (cd "$stage" && tar -czf "$archive" "$name")
        ;;
esac
echo "$archive"
