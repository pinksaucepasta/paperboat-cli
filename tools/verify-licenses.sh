#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
snapshot=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-license.XXXXXX")

cleanup() {
	status=$?
	if ! cmp -s "$root/go.mod" "$snapshot/go.mod" || ! cmp -s "$root/go.sum" "$snapshot/go.sum"; then
		echo "license analysis changed go.mod or go.sum" >&2
		status=1
	fi
	rm -rf "$snapshot"
	exit "$status"
}
trap cleanup EXIT HUP INT TERM

cp "$root/go.mod" "$snapshot/go.mod"
cp "$root/go.sum" "$snapshot/go.sum"

cd "$root"
mathutil_version=$(GOTOOLCHAIN=local go list -m -f '{{.Version}}' modernc.org/mathutil)
test "$mathutil_version" = "v1.7.1" || {
	echo "modernc.org/mathutil license exception requires v1.7.1, found $mathutil_version" >&2
	exit 1
}
mathutil_license=$(GOTOOLCHAIN=local go env GOMODCACHE)/modernc.org/mathutil@v1.7.1/LICENSE
test -f "$mathutil_license" || {
	echo "modernc.org/mathutil v1.7.1 LICENSE is missing from the module cache" >&2
	exit 1
}
mathutil_hash=$(shasum -a 256 "$mathutil_license" | awk '{print $1}')
test "$mathutil_hash" = "bfa9bf72a72ca009fd62a8f84fca3dca67e51d93af96352723646599898b6cf5" || {
	echo "modernc.org/mathutil v1.7.1 LICENSE hash is unexpected: $mathutil_hash" >&2
	exit 1
}

GOTOOLCHAIN=local go run github.com/google/go-licenses@v1.6.0 check \
	--disallowed_types=forbidden,restricted,unknown \
	--ignore=modernc.org/mathutil \
	./cmd/pb
