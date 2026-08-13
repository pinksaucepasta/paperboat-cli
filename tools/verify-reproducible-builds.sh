#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

version=${VERSION:?VERSION is required}
commit=${COMMIT:?COMMIT is required}
protocol_version=${PROTOCOL_VERSION:?PROTOCOL_VERSION is required}
package=./cmd/pb
module=github.com/pinksaucepasta/paperboat/internal/buildinfo
ldflags="-s -w -X $module.Version=$version -X $module.Commit=$commit -X $module.ProtocolVersion=$protocol_version"

work=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-reproducible.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

if command -v sha256sum >/dev/null 2>&1; then
  checksum() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  checksum() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "reproducible builds: sha256sum or shasum is required" >&2
  exit 2
fi

build_set() {
  output_dir=$1
  mkdir -p "$output_dir"
  for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do
    os=${target%/*}
    arch=${target#*/}
    output="$output_dir/pb-$os-$arch"
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOTOOLCHAIN=local SOURCE_DATE_EPOCH=0 \
      go build -buildvcs=false -trimpath -ldflags "$ldflags" -o "$output" "$package"
  done
}

build_set "$work/first"
build_set "$work/second"

for first in "$work/first"/*; do
  name=${first##*/}
  second="$work/second/$name"
  cmp -s "$first" "$second" || {
    echo "reproducible builds: $name differs between builds" >&2
    exit 1
  }
  digest=$(checksum "$first")
  echo "$digest  $name"
done

echo "reproducible builds: all supported artifacts are identical"
