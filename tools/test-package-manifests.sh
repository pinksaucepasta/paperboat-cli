#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
generator="$repository_root/tools/package-manifests.sh"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-package-manifests.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

native_sha256sum=$(command -v sha256sum || true)
native_shasum=$(command -v shasum || true)
if [ -z "$native_sha256sum" ] && [ -z "$native_shasum" ]; then
  echo 'package manifest test: sha256sum or shasum is required' >&2
  exit 1
fi

# Make both command names available even when the host only ships one. The
# generator is then forced through each backend and the complete manifests
# must remain byte-for-byte identical.
checksum_bin="$temporary/checksum-bin"
mkdir -p "$checksum_bin"
if [ -n "$native_sha256sum" ]; then
  cat > "$checksum_bin/sha256sum" <<EOF
#!/bin/sh
exec "$native_sha256sum" "\$@"
EOF
else
  cat > "$checksum_bin/sha256sum" <<EOF
#!/bin/sh
exec "$native_shasum" -a 256 "\$@"
EOF
fi
if [ -n "$native_shasum" ]; then
  cat > "$checksum_bin/shasum" <<EOF
#!/bin/sh
exec "$native_shasum" "\$@"
EOF
else
  cat > "$checksum_bin/shasum" <<EOF
#!/bin/sh
set -eu
if [ "\${1:-}" = -a ] && [ "\${2:-}" = 256 ]; then
  shift 2
fi
exec "$native_sha256sum" "\$@"
EOF
fi
chmod 0700 "$checksum_bin/sha256sum" "$checksum_bin/shasum"

make_dist() {
  dist=$1
  mkdir -p "$dist"
  printf 'darwin archive fixture\n' > "$dist/paperboat_2026.08.22.23_darwin_arm64.tar.gz"
  printf 'linux amd64 archive fixture\n' > "$dist/paperboat_2026.08.22.23_linux_amd64.tar.gz"
  printf 'linux arm64 archive fixture\n' > "$dist/paperboat_2026.08.22.23_linux_arm64.tar.gz"
}

preferred="$temporary/preferred"
fallback="$temporary/fallback"
automatic="$temporary/automatic"
make_dist "$preferred"
make_dist "$fallback"
make_dist "$automatic"

PAPERBOAT_CHECKSUM_BACKEND=sha256sum PATH="$checksum_bin:$PATH" \
  sh "$generator" "$preferred" pinksaucepasta/paperboat-cli 2026.08.22.23
PAPERBOAT_CHECKSUM_BACKEND=shasum PATH="$checksum_bin:$PATH" \
  sh "$generator" "$fallback" pinksaucepasta/paperboat-cli 2026.08.22.23
PATH="$checksum_bin:$PATH" \
  sh "$generator" "$automatic" pinksaucepasta/paperboat-cli 2026.08.22.23

for manifest in "$preferred/paperboat.rb" "$fallback/paperboat.rb" "$automatic/paperboat.rb"; do
  test -s "$manifest"
done
cmp -s "$preferred/paperboat.rb" "$fallback/paperboat.rb"
cmp -s "$preferred/paperboat.rb" "$automatic/paperboat.rb"
