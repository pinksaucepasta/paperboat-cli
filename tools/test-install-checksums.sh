#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
generator="$repository_root/tools/generate-release-checksums.sh"
installer="$repository_root/tools/install.sh"
windows_installer="$repository_root/tools/install.ps1"
windows_test="$repository_root/tools/test-install-checksums.ps1"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-install-checksums.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

dist="$temporary/dist"
mkdir -p "$dist"
printf 'linux installer checksum fixture\n' > "$dist/pb-linux-amd64"
printf 'windows installer checksum fixture\n' > "$dist/pb-windows-amd64.exe"
"$generator" "$dist"

# The release workflow must emit bare artifact names. This is the manifest that
# both installer parser contracts consume below.
if grep -q ' \./' "$dist/SHA256SUMS"; then
  echo 'installer checksum test: generated SHA256SUMS must use bare artifact names' >&2
  exit 1
fi

# Extract and execute the exact POSIX parser that the installer ships.
parser=$(sed -n '/^release_checksum() {/,/^}/p' "$installer")
[ -n "$parser" ] || { echo 'installer checksum test: install.sh parser is missing' >&2; exit 1; }
eval "$parser"
for asset in pb-linux-amd64 pb-windows-amd64.exe; do
  expected=$(sha256sum "$dist/$asset" | awk '{print $1}')
  actual=$(release_checksum "$dist/SHA256SUMS" "$asset")
  [ "$actual" = "$expected" ] || { echo "installer checksum test: install.sh rejected generated checksum for $asset" >&2; exit 1; }
done

# Existing releases used find's ./ path form. Keep that parser compatibility.
legacy="$temporary/SHA256SUMS.legacy"
for asset in pb-linux-amd64 pb-windows-amd64.exe; do
  sha256sum "$dist/$asset" | awk -v asset="$asset" '{print $1 " *./" asset}'
done > "$legacy"
for asset in pb-linux-amd64 pb-windows-amd64.exe; do
  expected=$(sha256sum "$dist/$asset" | awk '{print $1}')
  actual=$(release_checksum "$legacy" "$asset")
  [ "$actual" = "$expected" ] || { echo "installer checksum test: install.sh rejected legacy checksum for $asset" >&2; exit 1; }
done

if command -v pwsh >/dev/null 2>&1; then
  exec pwsh -NoProfile -NonInteractive -File "$windows_test" -Installer "$windows_installer" -ChecksumFile "$dist/SHA256SUMS" -LegacyChecksumFile "$legacy"
fi

# macOS local preflight intentionally does not require PowerShell. Check the
# Windows parser's exact grammar against the same generated manifests here;
# test-install-checksums.ps1 executes the shipped function on Windows.
python3 - "$windows_installer" "$dist/SHA256SUMS" "$legacy" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
required = (
    "function Get-ReleaseChecksum([string]$Path, [string]$Asset)",
    "'^(?<hash>[0-9A-Fa-f]{64})[ \\t]+\\*?(?<name>(?:\\./)?[^ \\t]+)$'",
    "$expected = Get-ReleaseChecksum $sums $asset",
)
for value in required:
    if value not in source:
        raise SystemExit(f"installer checksum test: Windows parser contract is missing {value!r}")

pattern = re.compile(r"^(?P<hash>[0-9A-Fa-f]{64})[ \t]+\*?(?P<name>(?:\./)?[^ \t]+)$")
for manifest in map(pathlib.Path, sys.argv[2:]):
    entries = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = pattern.fullmatch(line)
        if match:
            entries[match.group("name")] = match.group("hash").lower()
    for asset in ("pb-linux-amd64", "pb-windows-amd64.exe"):
        actual = entries.get(asset) or entries.get("./" + asset)
        if actual is None:
            raise SystemExit(f"installer checksum test: Windows parser rejected {manifest.name} checksum for {asset}")
PY
