#!/bin/sh
set -eu

usage() {
  echo "usage: $0 --binary FILE --output FILE --version VERSION --signing-identity IDENTITY" >&2
  exit 64
}

binary=
output=
version=
identity=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary|--output|--version|--signing-identity)
      [ "$#" -ge 2 ] || usage
      case "$1" in
        --binary) binary=$2 ;;
        --output) output=$2 ;;
        --version) version=$2 ;;
        --signing-identity) identity=$2 ;;
      esac
      shift 2
      ;;
    *) usage ;;
  esac
done

[ -f "$binary" ] && [ ! -L "$binary" ] || { echo "macOS package input is missing or not a regular file" >&2; exit 1; }
[ -n "$output" ] || usage
[ -n "$version" ] || usage
[ -n "$identity" ] || usage

case "$version" in
  20[0-9][0-9].[0-9][0-9].[0-9][0-9].* ) ;;
  *) echo "invalid release version: $version" >&2; exit 1 ;;
esac

output_dir=$(dirname -- "$output")
mkdir -p "$output_dir"
if [ -e "$output" ] || [ -L "$output" ]; then
  echo "refusing to overwrite release package: $output" >&2
  exit 1
fi

root=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-pkg.XXXXXX")
unsigned="$root/pb-darwin-arm64-unsigned.pkg"
cleanup() { rm -rf "$root"; }
trap cleanup EXIT HUP INT TERM

mkdir -p "$root/payload/usr/local/bin"
install -m 0755 "$binary" "$root/payload/usr/local/bin/pb"

pkgbuild \
  --root "$root/payload" \
  --identifier dev.pprbt.paperboat \
  --version "$version" \
  --install-location / \
  --ownership recommended \
  --sign "$identity" \
  "$unsigned"

productsign --sign "$identity" "$unsigned" "$output"
pkgutil --check-signature "$output"
