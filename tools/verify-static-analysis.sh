#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
snapshot=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-analysis.XXXXXX")

cleanup() {
	status=$?
	if ! cmp -s "$root/go.mod" "$snapshot/go.mod" || ! cmp -s "$root/go.sum" "$snapshot/go.sum"; then
		echo "static analysis changed go.mod or go.sum" >&2
		status=1
	fi
	rm -rf "$snapshot"
	exit "$status"
}
trap cleanup EXIT HUP INT TERM

cp "$root/go.mod" "$snapshot/go.mod"
cp "$root/go.sum" "$snapshot/go.sum"

cd "$root"
GOTOOLCHAIN=local go run honnef.co/go/tools/cmd/staticcheck@v0.8.0-rc.1 -checks='all,-ST1000,-ST1005' ./...
GOTOOLCHAIN=local go run golang.org/x/tools/cmd/deadcode@v0.47.0 -test ./cmd/pb ./internal/...
