#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
baseline=$root/tools/binary-size-baseline.tsv
output=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-binary-size.XXXXXX")
trap 'rm -rf "$output"' EXIT HUP INT TERM

test -f "$baseline" || {
	echo "binary size baseline is missing: $baseline" >&2
	exit 1
}

cd "$root"
tab=$(printf '\t')
while IFS="$tab" read -r platform architecture baseline_bytes; do
	case "$platform" in ''|'#'*) continue ;; esac
	case "$baseline_bytes" in ''|*[!0-9]*)
		echo "invalid binary size baseline for $platform/$architecture: $baseline_bytes" >&2
		exit 1
		;;
	esac

	artifact=$output/pb-$platform-$architecture
	CGO_ENABLED=0 GOOS=$platform GOARCH=$architecture GOTOOLCHAIN=local go build \
		-trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$artifact" ./cmd/pb
	actual_bytes=$(wc -c < "$artifact" | tr -d ' ')
	growth_bytes=$((actual_bytes - baseline_bytes))
	growth_percent=$(awk -v actual="$actual_bytes" -v baseline="$baseline_bytes" \
		'BEGIN { printf "%.2f", ((actual - baseline) * 100) / baseline }')

	if test "$growth_bytes" -gt 1048576 && \
		awk -v actual="$actual_bytes" -v baseline="$baseline_bytes" \
			'BEGIN { exit !((actual - baseline) * 100 > baseline * 5) }'; then
		echo "pb $platform/$architecture is $actual_bytes bytes, up $growth_bytes bytes ($growth_percent%) from $baseline_bytes" >&2
		echo "growth exceeds both 1 MiB and 5%; update the reviewed baseline with package/dependency attribution" >&2
		exit 1
	fi
	printf 'pb %s/%s: %s bytes (%s%% from baseline)\n' \
		"$platform" "$architecture" "$actual_bytes" "$growth_percent"
done < "$baseline"
