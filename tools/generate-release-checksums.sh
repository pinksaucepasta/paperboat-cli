#!/bin/sh
set -eu

usage() {
  echo "usage: $0 DIST_DIRECTORY" >&2
  exit 64
}

[ "$#" -eq 1 ] || usage
dist=$1
[ -d "$dist" ] || { echo "release checksums: directory does not exist: $dist" >&2; exit 1; }

output="$dist/SHA256SUMS"
temporary=$(mktemp "${TMPDIR:-/tmp}/paperboat-release-checksums.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM

(
  cd "$dist"
  # Release artifact names are a flat, controlled namespace. Strip find's
  # implementation-facing ./ prefix so installers consume one canonical form.
  find . -maxdepth 1 -type f ! -name SHA256SUMS -print |
    sed 's#^\./##' |
    LC_ALL=C sort |
    while IFS= read -r file; do
      sha256sum "$file"
    done
) > "$temporary"

mv -f "$temporary" "$output"
trap - EXIT HUP INT TERM
