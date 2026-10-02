#!/usr/bin/env bash
# Print the release version (spec §9; owner R12): the `[workspace.package] version` of the
# root Cargo.toml, which is what `r2 --version` reports.
#
#   scripts/release/version.sh            → prints e.g. `0.2.0`
#   scripts/release/version.sh v0.2.0     → also checks that the git tag is `v<version>`
#   scripts/release/version.sh --github-output [<tag>]
#                                         → appends `version=<version>` to $GITHUB_OUTPUT
#
# Exits non-zero when the version cannot be read or the tag does not match it.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

github_output=0
if [[ "${1:-}" == "--github-output" ]]; then
    github_output=1
    shift
fi
tag="${1:-}"

# The first `version = "…"` line inside the [workspace.package] table.
version="$(
    awk '
        /^\[/ { in_pkg = ($0 == "[workspace.package]"); next }
        in_pkg && /^version[[:space:]]*=/ {
            line = $0
            sub(/^version[[:space:]]*=[[:space:]]*"/, "", line)
            sub(/".*$/, "", line)
            print line
            exit
        }
    ' "$root/Cargo.toml"
)"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]]; then
    echo "error: cannot read [workspace.package] version from $root/Cargo.toml (got '$version')" >&2
    exit 1
fi

if [[ -n "$tag" && "$tag" != "v$version" ]]; then
    echo "error: tag '$tag' does not match the workspace version $version (expected 'v$version')" >&2
    exit 1
fi

if [[ "$github_output" == 1 ]]; then
    echo "version=$version" >> "${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"
fi
echo "$version"
