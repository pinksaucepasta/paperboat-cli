#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: publish-tuf-origin.sh STAGED_BUNDLE RELEASE_ROOT VERSION EXPECTED_SHA256" >&2
  exit 2
fi

bundle=$1
release_root=$2
version=$3
expected_sha=$4

[[ "$release_root" == /opt/paperboat/releases ]] || { echo "unexpected release root" >&2; exit 1; }
[[ "$version" =~ ^20[0-9]{2}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$ ]] || { echo "invalid release version" >&2; exit 1; }
[[ "$expected_sha" =~ ^[a-f0-9]{64}$ ]] || { echo "invalid bundle digest" >&2; exit 1; }
[[ -f "$bundle" && ! -L "$bundle" ]] || { echo "staged bundle is unavailable" >&2; exit 1; }

actual_sha=$(sha256sum "$bundle" | awk '{print $1}')
[[ "$actual_sha" == "$expected_sha" ]] || { echo "staged bundle digest mismatch" >&2; exit 1; }

stage=$(mktemp -d "$release_root/staging/${version}.XXXXXX")
trap 'rm -rf "$stage"' EXIT
tar -xzf "$bundle" -C "$stage" --no-same-owner --no-same-permissions

python3 - "$stage/current.json" "$version" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text())
if value != {"schema": "paperboat.release-current/v1", "version": sys.argv[2]}:
    raise SystemExit("current.json does not match the release")
PY

for required in install tuf/metadata/root.json tuf/metadata/targets.json tuf/metadata/snapshot.json tuf/metadata/timestamp.json; do
  [[ -s "$stage/$required" && ! -L "$stage/$required" ]] || { echo "release bundle is missing $required" >&2; exit 1; }
done

live="$release_root/current"
mkdir -p "$live/tuf/metadata" "$live/tuf/targets"

atomic_install() {
  local source=$1 destination=$2 mode=${3:-0644}
  local temporary
  temporary=$(mktemp "$(dirname "$destination")/.paperboat-release.XXXXXX")
  install -m "$mode" "$source" "$temporary"
  mv -f "$temporary" "$destination"
}

# Consistent targets and versioned metadata are immutable and become visible
# before any top-level metadata points at them.
find "$stage/tuf/targets" -maxdepth 1 -type f -print0 | while IFS= read -r -d '' source; do
  atomic_install "$source" "$live/tuf/targets/$(basename "$source")"
done
find "$stage/tuf/metadata" -maxdepth 1 -type f ! -name root.json ! -name targets.json ! -name snapshot.json ! -name timestamp.json -print0 | while IFS= read -r -d '' source; do
  atomic_install "$source" "$live/tuf/metadata/$(basename "$source")"
done

atomic_install "$stage/install" "$live/install" 0755
atomic_install "$stage/tuf/metadata/root.json" "$live/tuf/metadata/root.json"
atomic_install "$stage/tuf/metadata/targets.json" "$live/tuf/metadata/targets.json"
atomic_install "$stage/tuf/metadata/snapshot.json" "$live/tuf/metadata/snapshot.json"
# Timestamp is the TUF repository commit point.
atomic_install "$stage/tuf/metadata/timestamp.json" "$live/tuf/metadata/timestamp.json"
# current.json is an unsigned discovery hint and is always committed last.
atomic_install "$stage/current.json" "$live/current.json"

chown -R 501:root "$live"
chmod 0700 "$live"
echo "published $version"
