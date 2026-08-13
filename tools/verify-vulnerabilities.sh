#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
snapshot=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-vulnerability.XXXXXX")

cleanup() {
	status=$?
	if ! cmp -s "$root/go.mod" "$snapshot/go.mod" || ! cmp -s "$root/go.sum" "$snapshot/go.sum"; then
		echo "vulnerability analysis changed go.mod or go.sum" >&2
		status=1
	fi
	rm -rf "$snapshot"
	exit "$status"
}
trap cleanup EXIT HUP INT TERM

cp "$root/go.mod" "$snapshot/go.mod"
cp "$root/go.sum" "$snapshot/go.sum"

cd "$root"
GOTOOLCHAIN=local go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
