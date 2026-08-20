#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-tidy.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

mkdir "$work/repository"
(
	cd "$root"
	git ls-files -z --cached --others --exclude-standard |
		xargs -0 -n 1 sh -c 'test ! -e "$1" || printf "%s\0" "$1"' sh >"$work/files"
	tar --null -T "$work/files" -cf "$work/repository.tar"
)
tar -xf "$work/repository.tar" -C "$work/repository"

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
