#!/bin/sh
set -eu

usage() {
  echo "usage: $0 --platform PLATFORM --architecture ARCH --output FILE --version VERSION --server-url URL --release-url URL" >&2
  exit 64
}

platform=
architecture=
output=
version=
server_url=
release_url=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --platform|--architecture|--output|--version|--server-url|--release-url)
      [ "$#" -ge 2 ] || usage
      case "$1" in
        --platform) platform=$2 ;;
        --architecture) architecture=$2 ;;
        --output) output=$2 ;;
        --version) version=$2 ;;
        --server-url) server_url=$2 ;;
        --release-url) release_url=$2 ;;
      esac
      shift 2
      ;;
    *) usage ;;
  esac
done

case "$platform/$architecture" in
  linux/amd64|linux/arm64|darwin/arm64|windows/amd64|windows/arm64) ;;
  *) echo "unsupported release target: $platform/$architecture" >&2; exit 1 ;;
esac

[ -n "$output" ] || usage
[ -n "$version" ] || usage
case "$version" in
  20[0-9][0-9].[0-9][0-9].[0-9][0-9].* ) ;;
  *) echo "invalid release version: $version" >&2; exit 1 ;;
esac
case "$server_url" in
  https://*) ;;
  *) echo "release server URL must use HTTPS" >&2; exit 1 ;;
esac
case "$release_url" in
  https://*) ;;
  *) echo "release metadata URL must use HTTPS" >&2; exit 1 ;;
esac

output_dir=$(dirname -- "$output")
mkdir -p "$output_dir"
if [ -e "$output" ] || [ -L "$output" ]; then
  echo "refusing to overwrite release asset: $output" >&2
  exit 1
fi

ldflags="-s -w -X github.com/pinksaucepasta/paperboat/internal/buildinfo.Version=$version -X github.com/pinksaucepasta/paperboat/internal/buildinfo.Commit=${GITHUB_SHA:-unknown} -X github.com/pinksaucepasta/paperboat/internal/buildinfo.ProtocolVersion=1 -X github.com/pinksaucepasta/paperboat/internal/buildinfo.DefaultServerURL=$server_url -X github.com/pinksaucepasta/paperboat/internal/buildinfo.DefaultReleaseURL=$release_url"
CGO_ENABLED=0 GOOS="$platform" GOARCH="$architecture" go build \
  -buildvcs=false \
  -trimpath \
  -ldflags "$ldflags" \
  -o "$output" \
  ./cmd/pb

[ -f "$output" ] && [ ! -L "$output" ] || { echo "release build did not produce a regular file: $output" >&2; exit 1; }
chmod 0755 "$output"
