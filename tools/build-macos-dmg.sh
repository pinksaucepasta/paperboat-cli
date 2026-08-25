#!/bin/sh
set -eu
usage() { echo "usage: $0 --binary FILE --output FILE --version VERSION" >&2; exit 64; }
binary= output= version=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary|--output|--version) [ "$#" -ge 2 ] || usage; case "$1" in --binary) binary=$2;; --output) output=$2;; --version) version=$2;; esac; shift 2;;
    *) usage;;
  esac
done
[ -f "$binary" ] && [ ! -L "$binary" ] || { echo 'macOS DMG input is missing or not a regular file' >&2; exit 1; }
[ -n "$output" ] && [ -n "$version" ] || usage
case "$version" in 20[0-9][0-9].[0-9][0-9].[0-9][0-9].*) ;; *) echo "invalid release version: $version" >&2; exit 1;; esac
mkdir -p "$(dirname -- "$output")"
[ ! -e "$output" ] && [ ! -L "$output" ] || { echo "refusing to overwrite release DMG: $output" >&2; exit 1; }
root=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-dmg.XXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM
install -m 0755 "$binary" "$root/pb"
hdiutil create -quiet -volname "Paperboat $version" -srcfolder "$root" -format UDZO -ov "$output"
