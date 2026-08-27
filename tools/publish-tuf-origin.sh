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

[[ -z "$(find "$next" -type l -print -quit)" ]] || { echo "staged release contains a symlink" >&2; exit 1; }

python3 - "$next/current.json" "$next/tuf/metadata/targets.json" "$version" <<'PY'
import json, pathlib, re, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text())
targets_path = pathlib.Path(sys.argv[2])
version = sys.argv[3]
if value.get("schema") != "paperboat.release-current/v1" or value.get("version") != version:
    raise SystemExit("current.json does not match the release")
repository = value.get("repository")
if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
    raise SystemExit("current.json has an invalid GitHub repository")
assets = value.get("assets")
expected = {
    "pb-darwin-arm64.pkg": ("darwin", "arm64", "pkg"),
    "pb-linux-amd64": ("linux", "amd64", "elf"),
    "pb-linux-arm64": ("linux", "arm64", "elf"),
    "pb-windows-amd64.exe": ("windows", "amd64", "pe"),
    "pb-windows-arm64.exe": ("windows", "arm64", "pe"),
}
if not isinstance(assets, dict) or set(assets) != set(expected):
    raise SystemExit("current.json does not contain the exact release asset set")
for name, (platform, architecture, format_) in expected.items():
    asset = assets[name]
    if not isinstance(asset, dict) or set(asset) != {"platform", "architecture", "format", "url", "sha256", "length"}:
        raise SystemExit(f"current.json asset metadata is invalid for {name}")
    if asset["platform"] != platform or asset["architecture"] != architecture or asset["format"] != format_:
        raise SystemExit(f"current.json asset identity is invalid for {name}")
    if asset["url"] != f"https://github.com/{repository}/releases/download/{version}/{name}":
        raise SystemExit(f"current.json asset URL is invalid for {name}")
    if not isinstance(asset["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]):
        raise SystemExit(f"current.json asset digest is invalid for {name}")
    if isinstance(asset["length"], bool) or not isinstance(asset["length"], int) or asset["length"] < 1:
        raise SystemExit(f"current.json asset length is invalid for {name}")

# current.json is the release selector consumed by installers. TUF carries
# the authenticated copy of the same asset coordinates, so both documents
# must agree before the directory exchange. This closes the gap where two
# independently generated documents could otherwise publish different
# versions, URLs, digests, or lengths together.
try:
    targets_document = json.loads(targets_path.read_text())
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"TUF targets metadata is invalid: {error}")
signed = targets_document.get("signed")
if not isinstance(signed, dict):
    raise SystemExit("TUF targets metadata has no signed object")
targets = signed.get("targets")
if not isinstance(targets, dict) or set(targets) != set(expected):
    raise SystemExit("TUF targets metadata does not contain the exact release asset set")

def require_equal(actual, wanted, message):
    if type(actual) is not type(wanted) or actual != wanted:
        raise SystemExit(message)

for name, (platform, architecture, format_) in expected.items():
    asset = assets[name]
    target = targets.get(name)
    if not isinstance(target, dict):
        raise SystemExit(f"TUF target metadata is invalid for {name}")
    hashes = target.get("hashes")
    require_equal(target.get("length"), asset["length"], f"TUF target length does not match current.json for {name}")
    if not isinstance(hashes, dict):
        raise SystemExit(f"TUF target hashes are invalid for {name}")
    require_equal(hashes.get("sha256"), asset["sha256"], f"TUF target digest does not match current.json for {name}")

    custom = target.get("custom")
    if not isinstance(custom, dict):
        raise SystemExit(f"TUF target custom metadata is invalid for {name}")
    for key, wanted in {
        "schema": "paperboat.tuf-asset/v1",
        "kind": "github-release-asset",
        "version": version,
        "platform": platform,
        "architecture": architecture,
        "format": format_,
        "asset_name": name,
        "repository": repository,
        "url": asset["url"],
        "sha256": asset["sha256"],
        "length": asset["length"],
    }.items():
        require_equal(custom.get(key), wanted, f"TUF custom metadata does not match current.json for {name}: {key}")

    release_index = custom.get("release_index")
    if not isinstance(release_index, dict):
        raise SystemExit(f"TUF release index is invalid for {name}")
    require_equal(release_index.get("schema"), "paperboat.release-index/v1", f"TUF release index schema is invalid for {name}")
    require_equal(release_index.get("release_id"), "rel_" + version, f"TUF release index ID does not match current.json for {name}")
    require_equal(release_index.get("version"), version, f"TUF release index version does not match current.json for {name}")
    index_targets = release_index.get("targets")
    if not isinstance(index_targets, list) or len(index_targets) != 1 or not isinstance(index_targets[0], dict):
        raise SystemExit(f"TUF release index target is invalid for {name}")
    index_target = index_targets[0]
    for key, wanted in {
        "component": "pb",
        "target_path": name,
        "asset_name": name,
        "repository": repository,
        "download_url": asset["url"],
        "sha256": asset["sha256"],
        "length": asset["length"],
        "platform": platform,
        "architecture": architecture,
        "binary_format": format_,
    }.items():
        require_equal(index_target.get(key), wanted, f"TUF release index target does not match current.json for {name}: {key}")
PY

for required in install windows tuf/metadata/root.json tuf/metadata/targets.json tuf/metadata/snapshot.json tuf/metadata/timestamp.json; do
  [[ -s "$next/$required" && ! -L "$next/$required" ]] || { echo "release bundle is missing $required" >&2; exit 1; }
done
for directory in "$next/tuf/metadata" "$next/tuf/targets"; do
  [[ -d "$directory" && ! -L "$directory" ]] || { echo "release bundle is missing a TUF directory" >&2; exit 1; }
  [[ -z "$(find "$directory" -mindepth 1 -type d -print -quit)" ]] || { echo "release bundle contains nested TUF paths" >&2; exit 1; }
  [[ -z "$(find "$directory" -mindepth 1 ! -type f -print -quit)" ]] || { echo "release bundle contains a non-regular TUF file" >&2; exit 1; }
done
[[ -z "$(find "$next/tuf/targets" -mindepth 1 -print -quit)" ]] || { echo "release bundle must not contain TUF target blobs" >&2; exit 1; }

chown -R 501:root "$next"
chmod 0700 "$next"
verify_live_mount_contract "$release_root"

# This must remain the final command. The server resolves current through the
# releases-parent mount on every request, so the exchange exposes TUF,
# installers, and current.json together. The old tree stays in transaction/next
# until a later release performs its pre-activation cleanup.
atomic_exchange "$live" "$next"
