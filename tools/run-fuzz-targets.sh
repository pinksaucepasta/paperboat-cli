#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

fuzz_time=${FUZZ_TIME:-2s}
case "$fuzz_time" in
  *[!0-9smh.]*)
    echo "fuzz: invalid FUZZ_TIME: $fuzz_time" >&2
    exit 2
    ;;
esac

targets_file=$(mktemp "${TMPDIR:-/tmp}/paperboat-fuzz-targets.XXXXXX")
trap 'rm -f "$targets_file"' EXIT HUP INT TERM

GOTOOLCHAIN=local go list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./... |
while IFS= read -r package; do
  [ -n "$package" ] || continue
  GOTOOLCHAIN=local go test -list '^Fuzz' "$package" |
  awk -v package="$package" '/^Fuzz[[:alnum:]_]*$/ { print package, $0 }'
done >"$targets_file"

target_count=$(wc -l <"$targets_file" | tr -d ' ')
[ "$target_count" -gt 0 ] || {
  echo "fuzz: no targets discovered" >&2
  exit 1
}

echo "fuzz: running $target_count targets for $fuzz_time each"
while read -r package target; do
  echo "fuzz: $package $target"
  GOTOOLCHAIN=local go test -run '^$' -fuzz "^${target}$" -fuzztime "$fuzz_time" "$package"
done <"$targets_file"

echo "fuzz: all $target_count targets passed"
