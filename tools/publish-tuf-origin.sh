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

verify_live_mount_contract() {
  local release_root=$1
  local live="$release_root/current"
  local staging="$release_root/staging"
  [[ -d "$release_root" && ! -L "$release_root" ]] || { echo "release root is unavailable" >&2; return 1; }
  [[ -d "$live" && ! -L "$live" ]] || { echo "live release is unavailable" >&2; return 1; }
  [[ -d "$staging" && ! -L "$staging" ]] || { echo "release staging directory is unavailable" >&2; return 1; }
  [[ -d "$live/tuf/metadata" && ! -L "$live/tuf/metadata" ]] || { echo "live TUF metadata is unavailable" >&2; return 1; }
  [[ -d "$live/tuf/targets" && ! -L "$live/tuf/targets" ]] || { echo "live TUF targets are unavailable" >&2; return 1; }
  mapfile -t containers < <(docker ps -q)
  ((${#containers[@]} > 0)) || { echo "no running containers are available to verify the release mount" >&2; return 1; }
  local inspect
  inspect=$(mktemp) || return 1
  if ! docker inspect "${containers[@]}" > "$inspect"; then
    rm -f -- "$inspect"
    return 1
  fi
  if ! python3 - "$release_root" "$inspect" <<'PY'
import json
import sys

containers = json.load(open(sys.argv[2], encoding="utf-8"))
parent_source = sys.argv[1]
old_source = parent_source + "/current"
destination = "/srv/paperboat-releases"
runtime = destination + "/current"
ready = False
for container in containers:
    mounts = container.get("Mounts", [])
    if any(mount.get("Source") == old_source for mount in mounts):
        raise SystemExit("a running container still bind-mounts the old current release directory")
    parent_mount = any(
        mount.get("Source") == parent_source
        and mount.get("Destination") == destination
        and mount.get("Type") == "bind"
        and mount.get("RW") is False
        for mount in mounts
    )
    runtime_env = runtime in {
        value.split("=", 1)[1]
        for value in container.get("Config", {}).get("Env", [])
        if value.startswith("PAPERBOAT_RELEASE_DIRECTORY=")
    }
    ready = ready or (parent_mount and runtime_env)
if not ready:
    raise SystemExit("no single running container exposes the read-only releases parent mount and current runtime directory")
PY
  then
    rm -f -- "$inspect"
    return 1
  fi
  rm -f -- "$inspect"
}

atomic_exchange() {
  python3 - "$1" "$2" <<'PY'
import ctypes
import os
import sys

libc = ctypes.CDLL(None, use_errno=True)
renameat2 = getattr(libc, "renameat2", None)
if renameat2 is None:
    raise SystemExit("renameat2 is unavailable")
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int
if renameat2(-100, os.fsencode(sys.argv[1]), -100, os.fsencode(sys.argv[2]), 2) != 0:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error))
PY
}

live="$release_root/current"
staging="$release_root/staging"
[[ -d "$live" && ! -L "$live" ]] || { echo "live release is unavailable" >&2; exit 1; }
[[ -d "$staging" && ! -L "$staging" ]] || { echo "release staging directory is unavailable" >&2; exit 1; }

# A successful prior activation deliberately retains its exchanged-out tree.
# It is safe to remove only now, before this release creates its transaction.
find "$staging" -mindepth 1 -maxdepth 1 -type d -name 'activation-*' -print0 | while IFS= read -r -d '' previous; do
  rm -rf -- "$previous"
done

transaction=$(mktemp -d "$staging/activation-${version}.XXXXXX")
next="$transaction/next"
mkdir "$next"
tar -xzf "$bundle" -C "$next" --no-same-owner --no-same-permissions

# Keep immutable content-addressed targets referenced by metadata already
# cached by older clients. New candidate targets win; missing historical
# blobs are hard-linked from the current tree without network transfer or
# duplicate disk allocation. Both trees live under the same release root.
historical_targets="$live/tuf/targets"
[[ -d "$historical_targets" && ! -L "$historical_targets" ]] || { echo "historical TUF targets are unavailable" >&2; exit 1; }
[[ -z "$(find "$historical_targets" -mindepth 1 -type d -print -quit)" ]] || { echo "historical TUF targets contain nested paths" >&2; exit 1; }
[[ -z "$(find "$historical_targets" -mindepth 1 ! -type f -print -quit)" ]] || { echo "historical TUF targets contain a non-regular file" >&2; exit 1; }
while IFS= read -r -d '' historical; do
  name=${historical#"$historical_targets/"}
  destination="$next/tuf/targets/$name"
  if [[ ! -e "$destination" ]]; then
    ln "$historical" "$destination"
  fi
done < <(find "$historical_targets" -mindepth 1 -maxdepth 1 -type f -print0)

[[ -z "$(find "$next" -type l -print -quit)" ]] || { echo "staged release contains a symlink" >&2; exit 1; }

python3 - "$next/current.json" "$version" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text())
if value != {"schema": "paperboat.release-current/v1", "version": sys.argv[2]}:
    raise SystemExit("current.json does not match the release")
PY

for required in install windows tuf/metadata/root.json tuf/metadata/targets.json tuf/metadata/snapshot.json tuf/metadata/timestamp.json; do
  [[ -s "$next/$required" && ! -L "$next/$required" ]] || { echo "release bundle is missing $required" >&2; exit 1; }
done
for directory in "$next/tuf/metadata" "$next/tuf/targets"; do
  [[ -d "$directory" && ! -L "$directory" ]] || { echo "release bundle is missing a TUF directory" >&2; exit 1; }
  [[ -z "$(find "$directory" -mindepth 1 -type d -print -quit)" ]] || { echo "release bundle contains nested TUF paths" >&2; exit 1; }
  [[ -z "$(find "$directory" -mindepth 1 ! -type f -print -quit)" ]] || { echo "release bundle contains a non-regular TUF file" >&2; exit 1; }
done

chown -R 501:root "$next"
chmod 0700 "$next"
verify_live_mount_contract "$release_root"

# This must remain the final command. The server resolves current through the
# releases-parent mount on every request, so the exchange exposes TUF,
# installers, and current.json together. The old tree stays in transaction/next
# until a later release performs its pre-activation cleanup.
atomic_exchange "$live" "$next"
