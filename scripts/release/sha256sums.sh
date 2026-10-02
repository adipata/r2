#!/usr/bin/env bash
# Write and verify <dir>/SHA256SUMS over every release archive in <dir> (spec §9; owner R12).
#
#   scripts/release/sha256sums.sh <dir>
#
# The format is `sha256sum`'s (`<hex>  <file>`, sorted by file name), so users verify with
# `sha256sum -c SHA256SUMS` (or `shasum -a 256 -c SHA256SUMS` on macOS).
set -euo pipefail

dir="${1:?usage: scripts/release/sha256sums.sh <dir>}"
cd "$dir"

if command -v sha256sum > /dev/null; then
    sum=(sha256sum)
else
    sum=(shasum -a 256)
fi

files=()
while IFS= read -r file; do
    files+=("$file")
done < <(find . -maxdepth 1 -type f \( -name 'r2-*.tar.gz' -o -name 'r2-*.zip' \) -print | sed 's|^\./||' | LC_ALL=C sort)
((${#files[@]} > 0)) || { echo "error: no r2-*.tar.gz / r2-*.zip archives in $dir" >&2; exit 1; }

"${sum[@]}" "${files[@]}" > SHA256SUMS
"${sum[@]}" -c SHA256SUMS >&2
cat SHA256SUMS
