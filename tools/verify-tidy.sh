#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-tidy.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

mkdir "$work/repository"
cp -R "$root/." "$work/repository"
rm -rf "$work/repository/.git" "$work/repository/bin" "$work/repository/dist"

cd "$work/repository"
GOTOOLCHAIN=local go mod tidy

status=0
for file in go.mod go.sum; do
  if ! cmp -s "$root/$file" "$file"; then
    echo "tidy: $file is stale; run make tidy" >&2
    diff -u "$root/$file" "$file" || true
    status=1
  fi
done
[ "$status" -eq 0 ] || exit "$status"

echo "tidy: module files are current"
