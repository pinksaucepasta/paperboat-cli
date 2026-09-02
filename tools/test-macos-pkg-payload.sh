#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
  echo 'macOS PKG payload: skipped (requires Darwin)'
  exit 0
fi

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=2026.09.02.999
temporary=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-macos-pkg.XXXXXX")
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT HUP INT TERM

input="$temporary/pb"
package="$temporary/pb.pkg"
expanded="$temporary/expanded"
payload="$temporary/payload"

# Build a release-shaped Mach-O fixture so the test does not depend on an
# existing checkout artifact. The package builder replaces its linker-only
# signature with the complete ad-hoc signature required by launchd.
(
  cd "$repository_root"
  CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
    go build -buildvcs=false -trimpath \
      -ldflags "-s -w -X github.com/pinksaucepasta/paperboat/internal/buildinfo.Version=$version -X github.com/pinksaucepasta/paperboat/internal/buildinfo.Commit=package-test -X github.com/pinksaucepasta/paperboat/internal/buildinfo.ProtocolVersion=1 -X github.com/pinksaucepasta/paperboat/internal/buildinfo.DefaultServerURL=https://api.example -X github.com/pinksaucepasta/paperboat/internal/buildinfo.DefaultReleaseURL=https://api.example" \
      -o "$input" ./cmd/pb
)

version_output=$($input --version)
version_line=$(printf '%s\n' "$version_output" | grep -Eo 'Version[[:space:]]+[0-9A-Za-z._-]+' | tail -n 1 || true)
test "$version_line" = "Version $version"

"$repository_root/tools/build-macos-pkg.sh" \
  --binary "$input" \
  --output "$package" \
  --version "$version"

pkgutil --expand "$package" "$expanded"
package_version=$(sed -nE 's/.*<pkg-info[^>]* version="([^"]*)".*/\1/p' "$expanded/PackageInfo")
test "$package_version" = "$version"
test ! -e "$expanded/Scripts"

payload_files=$(pkgutil --payload-files "$package")
for expected in \
  './usr/local/bin/pb' \
  './Library/PrivilegedHelperTools/Paperboat/pb'
do
  if ! printf '%s\n' "$payload_files" | grep -Fqx "$expected"; then
    echo "macOS PKG payload is missing $expected" >&2
    exit 1
  fi
done
if printf '%s\n' "$payload_files" | grep -Eq '(^|/)(Application Support|LaunchDaemons)(/|$)|\.plist$'; then
  echo 'macOS PKG payload contains state or launchd plist files' >&2
  exit 1
fi

# Inspect the actual archived payload, rather than only the package BOM. This
# proves both destinations contain the same release bytes and independently
# verify as complete ad-hoc Mach-O signatures.
mkdir -p "$payload"
(
  cd "$payload"
  gzip -dc "$expanded/Payload" | cpio -idm >/dev/null 2>&1
)

cli="$payload/usr/local/bin/pb"
helper="$payload/Library/PrivilegedHelperTools/Paperboat/pb"
test -f "$cli" && test ! -L "$cli"
test -f "$helper" && test ! -L "$helper"
cmp -s "$cli" "$helper"

for executable in "$cli" "$helper"; do
  codesign --verify --strict "$executable"
  signature=$(codesign -dvvv "$executable" 2>&1)
  printf '%s\n' "$signature" | grep -Fqx 'Signature=adhoc'
  if printf '%s\n' "$signature" | grep -Fq 'linker-signed'; then
    echo "macOS PKG payload retained a linker-only signature: $executable" >&2
    exit 1
  fi
done

echo 'macOS PKG payload: both destinations, version, and ad-hoc signatures verified'
