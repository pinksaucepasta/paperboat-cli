#!/usr/bin/env bash
set -euo pipefail

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
publisher="$repository_root/tools/publish-tuf-origin.sh"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-publish-tuf.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
release_root="$temporary/releases"
mkdir -p "$release_root/current/tuf/metadata" "$release_root/current/tuf/targets" "$release_root/staging"
printf 'previous current\n' > "$release_root/current/current.json"
printf 'previous timestamp\n' > "$release_root/current/tuf/metadata/timestamp.json"

# The production script deliberately pins its release root. Substitute only
# that guard for this local failure-atomicity test; no activation is attempted.
test_publisher="$temporary/publish-tuf-origin.sh"
sed "s|/opt/paperboat/releases|$release_root|g" "$publisher" > "$test_publisher"
chmod 0700 "$test_publisher"
test "$(awk 'NF { line=$0 } END { print line }' "$publisher")" = 'atomic_exchange "$live" "$next"'

write_current_manifest() {
  local path=$1
  local version=$2
  python3 - "$path" "$version" <<'PY'
import json
import pathlib
import sys

version = sys.argv[2]
assets = {
    "pb-darwin-arm64.pkg": ("darwin", "arm64", "pkg"),
    "pb-linux-amd64": ("linux", "amd64", "elf"),
    "pb-linux-arm64": ("linux", "arm64", "elf"),
    "pb-windows-amd64.exe": ("windows", "amd64", "pe"),
    "pb-windows-arm64.exe": ("windows", "arm64", "pe"),
}
body = {
    "schema": "paperboat.release-current/v1",
    "version": version,
    "repository": "pinksaucepasta/paperboat-cli",
    "assets": {
        name: {
            "platform": platform,
            "architecture": architecture,
            "format": format_,
            "url": f"https://github.com/pinksaucepasta/paperboat-cli/releases/download/{version}/{name}",
            "sha256": "0" * 64,
            "length": 1,
        }
        for name, (platform, architecture, format_) in assets.items()
    },
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(body, separators=(",", ":")) + "\n")
PY
}

write_matching_targets_metadata() {
  local current_path=$1
  local targets_path=$2
  python3 - "$current_path" "$targets_path" <<'PY'
import json
import pathlib
import sys

current = json.loads(pathlib.Path(sys.argv[1]).read_text())
targets = {}
for name, asset in current["assets"].items():
    index_target = {
        "component": "pb",
        "target_path": name,
        "asset_name": name,
        "repository": current["repository"],
        "download_url": asset["url"],
        "sha256": asset["sha256"],
        "length": asset["length"],
        "platform": asset["platform"],
        "architecture": asset["architecture"],
        "binary_format": asset["format"],
    }
    targets[name] = {
        "hashes": {"sha256": asset["sha256"]},
        "length": asset["length"],
        "custom": {
            "schema": "paperboat.tuf-asset/v1",
            "kind": "github-release-asset",
            "version": current["version"],
            "platform": asset["platform"],
            "architecture": asset["architecture"],
            "format": asset["format"],
            "asset_name": name,
            "repository": current["repository"],
            "url": asset["url"],
            "sha256": asset["sha256"],
            "length": asset["length"],
            "release_index": {
                "schema": "paperboat.release-index/v1",
                "release_id": "rel_" + current["version"],
                "version": current["version"],
                "targets": [index_target],
            },
        },
    }
pathlib.Path(sys.argv[2]).write_text(json.dumps({"signed": {"targets": targets}}) + "\n")
PY
}

select_checksum_backend() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' sha256sum
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s\n' shasum
  else
    echo 'publisher test: sha256sum or shasum is required' >&2
    return 1
  fi
}

checksum_backend=$(select_checksum_backend)
checksum_sha256sum=$(command -v sha256sum || true)
checksum_shasum=$(command -v shasum || true)
if test -z "$checksum_sha256sum" && test -z "$checksum_shasum"; then
  echo 'publisher test: sha256sum or shasum is required' >&2
  exit 1
fi

run_checksum() {
  local backend=$1
  shift
  case "$backend" in
    sha256sum)
      test -n "$CHECKSUM_SHA256SUM_COMMAND"
      "$CHECKSUM_SHA256SUM_COMMAND" "$@"
      ;;
    shasum)
      test -n "$CHECKSUM_SHASUM_COMMAND"
      "$CHECKSUM_SHASUM_COMMAND" -a 256 "$@"
      ;;
    *)
      echo "publisher test: unsupported checksum backend: $backend" >&2
      return 1
      ;;
  esac
}

# Build command shims so both checksum branches are exercised even when the
# host only ships one of the two platform-specific command names. The shim
# delegates to the real command available on this host and only translates
# the shasum -a 256 argument shape.
checksum_test_bin="$temporary/checksum-bin"
mkdir -p "$checksum_test_bin"
if test -n "$checksum_sha256sum"; then
  cat > "$checksum_test_bin/sha256sum" <<EOF
#!/bin/sh
exec "$checksum_sha256sum" "\$@"
EOF
else
  cat > "$checksum_test_bin/sha256sum" <<EOF
#!/bin/sh
exec "$checksum_shasum" -a 256 "\$@"
EOF
fi
if test -n "$checksum_shasum"; then
  cat > "$checksum_test_bin/shasum" <<EOF
#!/bin/sh
exec "$checksum_shasum" "\$@"
EOF
else
  cat > "$checksum_test_bin/shasum" <<EOF
#!/bin/sh
set -eu
if test "\${1:-}" = -a && test "\${2:-}" = 256; then
  shift 2
fi
exec "$checksum_sha256sum" "\$@"
EOF
fi
chmod 0700 "$checksum_test_bin/sha256sum" "$checksum_test_bin/shasum"

# Keep the shim commands selected for the entire test. In particular, do not
# restore an absent host command after exercising the alternate branch: Git
# Bash on Windows normally provides sha256sum but not shasum, and doing so
# would make the later snapshot test call an empty command path.
CHECKSUM_SHA256SUM_COMMAND="$checksum_test_bin/sha256sum"
CHECKSUM_SHASUM_COMMAND="$checksum_test_bin/shasum"

run_test_publisher() {
  # The production publisher intentionally requires sha256sum on its Linux
  # deployment host. Supply the deterministic shim while this test simulates
  # a shasum-only development host, so its validation paths still execute
  # instead of passing early because a deployment-only command is absent.
  PATH="$checksum_test_bin:$PATH" "$test_publisher" "$@"
}

assert_isolated_checksum_backend() {
  local path=$1
  local expected=$2
  local unexpected
  if test "$expected" = sha256sum; then
    unexpected=shasum
  else
    unexpected=sha256sum
  fi

  test "$(PATH="$path" select_checksum_backend)" = "$expected"
  if PATH="$path" command -v "$unexpected" >/dev/null 2>&1; then
    echo "publisher test: isolated $expected host unexpectedly exposes $unexpected" >&2
    return 1
  fi
}

# Model both supported host environments explicitly. These directories each
# contain exactly one checksum command, so backend selection is tested without
# relying on which tools happen to be installed on the developer or runner.
sha256sum_only_path="$temporary/checksum-sha256sum-only"
shasum_only_path="$temporary/checksum-shasum-only"
mkdir -p "$sha256sum_only_path" "$shasum_only_path"
cp "$checksum_test_bin/sha256sum" "$sha256sum_only_path/sha256sum"
cp "$checksum_test_bin/shasum" "$shasum_only_path/shasum"
chmod 0700 "$sha256sum_only_path/sha256sum" "$shasum_only_path/shasum"
assert_isolated_checksum_backend "$sha256sum_only_path" sha256sum
assert_isolated_checksum_backend "$shasum_only_path" shasum

checksum_fixture="$temporary/checksum-fixture"
printf 'paperboat checksum fixture\n' > "$checksum_fixture"
CHECKSUM_SHA256SUM_COMMAND="$checksum_test_bin/sha256sum"
CHECKSUM_SHASUM_COMMAND="$checksum_test_bin/shasum"
checksum_sha256sum_digest=$(run_checksum sha256sum "$checksum_fixture" | awk '{print $1}')
checksum_shasum_digest=$(run_checksum shasum "$checksum_fixture" | awk '{print $1}')
test "$checksum_sha256sum_digest" = "$checksum_shasum_digest"
checksum_sha256sum_digest=$(printf 'paperboat checksum stream\n' | run_checksum sha256sum | awk '{print $1}')
checksum_shasum_digest=$(printf 'paperboat checksum stream\n' | run_checksum shasum | awk '{print $1}')
test "$checksum_sha256sum_digest" = "$checksum_shasum_digest"

snapshot_directory_with_backend() {
  local backend=$1
  local directory=$2
  (
    cd "$directory"
    while IFS= read -r -d '' file; do
      run_checksum "$backend" "$file"
    done < <(find . -type f -print0 | LC_ALL=C sort -z)
  )
}

run_native_checksum() {
  local backend=$1
  shift
  case "$backend" in
    sha256sum)
      "$checksum_sha256sum" "$@"
      ;;
    shasum)
      "$checksum_shasum" -a 256 "$@"
      ;;
    *)
      echo "publisher test: unsupported checksum backend: $backend" >&2
      return 1
      ;;
  esac
}

snapshot_directory_with_native_backend() {
  local backend=$1
  local directory=$2
  (
    cd "$directory"
    while IFS= read -r -d '' file; do
      run_native_checksum "$backend" "$file"
    done < <(find . -type f -print0 | LC_ALL=C sort -z)
  )
}

checksum_snapshot_fixture="$temporary/checksum-snapshot"
mkdir -p "$checksum_snapshot_fixture/nested directory"
printf 'first snapshot file\n' > "$checksum_snapshot_fixture/first"
printf 'second snapshot file\n' > "$checksum_snapshot_fixture/nested directory/second"
test "$(snapshot_directory_with_backend sha256sum "$checksum_snapshot_fixture")" = \
  "$(snapshot_directory_with_backend shasum "$checksum_snapshot_fixture")"

snapshot() {
  snapshot_directory_with_native_backend "$checksum_backend" "$release_root/current"
}
snapshot_directory() {
  snapshot_directory_with_native_backend "$checksum_backend" "$1"
}
before=$(snapshot)

if run_test_publisher "$temporary/missing.tgz" "$release_root" 2026.08.22.23 "$(printf x | run_checksum "$checksum_backend" | awk '{print $1}')" >/dev/null 2>&1; then
  echo 'publisher accepted a missing bundle' >&2
  exit 1
fi
test "$before" = "$(snapshot)"

candidate="$temporary/candidate"
mkdir -p "$candidate/tuf/metadata" "$candidate/tuf/targets"
write_current_manifest "$candidate/current.json" wrong
printf x > "$candidate/install"
printf x > "$candidate/windows"
for name in root targets snapshot timestamp; do printf x > "$candidate/tuf/metadata/$name.json"; done
bundle="$temporary/candidate.tgz"
tar -C "$candidate" -czf "$bundle" current.json install windows tuf
digest=$(run_checksum "$checksum_backend" "$bundle" | awk '{print $1}')
if run_test_publisher "$bundle" "$release_root" 2026.08.22.23 "$digest" >/dev/null 2>&1; then
  echo 'publisher accepted an invalid current.json' >&2
  exit 1
fi
test "$before" = "$(snapshot)"

candidate_version=2026.08.22.23
write_current_manifest "$candidate/current.json" "$candidate_version"
write_matching_targets_metadata "$candidate/current.json" "$candidate/tuf/metadata/targets.json"
python3 - "$candidate/tuf/metadata/targets.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
body = json.loads(path.read_text())
body["signed"]["targets"]["pb-linux-amd64"]["custom"]["version"] = "2026.08.22.24"
path.write_text(json.dumps(body) + "\n")
PY
mismatch_bundle="$temporary/mismatch.tgz"
tar -C "$candidate" -czf "$mismatch_bundle" current.json install windows tuf
mismatch_digest=$(run_checksum "$checksum_backend" "$mismatch_bundle" | awk '{print $1}')
if run_test_publisher "$mismatch_bundle" "$release_root" "$candidate_version" "$mismatch_digest" >/dev/null 2>&1; then
  echo 'publisher accepted current.json and TUF version drift' >&2
  exit 1
fi
test "$before" = "$(snapshot)"
write_matching_targets_metadata "$candidate/current.json" "$candidate/tuf/metadata/targets.json"
bundle="$temporary/candidate.tgz"
tar -C "$candidate" -czf "$bundle" current.json install windows tuf
digest=$(run_checksum "$checksum_backend" "$bundle" | awk '{print $1}')

# renameat2(RENAME_EXCHANGE) is a Linux deployment requirement. Exercise the
# success path there with a fake Docker CLI that proves the parent RO mount;
# other development hosts still execute the two pre-activation failure tests.
if [ "$(uname -s)" = Linux ]; then
  mkdir -p "$temporary/bin"
  cat > "$temporary/bin/docker" <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in
  ps)
    test "${2:-}" = -q
    echo test-container
    ;;
  inspect)
    case "${PAPERBOAT_TEST_DOCKER_MODE:?}" in
      good)
        printf '[{"Mounts":[{"Type":"bind","Source":"%s","Destination":"/srv/paperboat-releases","RW":false}],"Config":{"Env":["PAPERBOAT_RELEASE_DIRECTORY=/srv/paperboat-releases/current"]}}]\n' "$PAPERBOAT_TEST_RELEASE_ROOT"
        ;;
      wrong-env)
        printf '[{"Mounts":[{"Type":"bind","Source":"%s","Destination":"/srv/paperboat-releases","RW":false}],"Config":{"Env":["PAPERBOAT_RELEASE_DIRECTORY=/srv/other"]}}]\n' "$PAPERBOAT_TEST_RELEASE_ROOT"
        ;;
      split)
        printf '[{"Mounts":[{"Type":"bind","Source":"%s","Destination":"/srv/paperboat-releases","RW":false}],"Config":{"Env":[]}}, {"Mounts":[],"Config":{"Env":["PAPERBOAT_RELEASE_DIRECTORY=/srv/paperboat-releases/current"]}}]\n' "$PAPERBOAT_TEST_RELEASE_ROOT"
        ;;
      stale)
        printf '[{"Mounts":[{"Type":"bind","Source":"%s/current","Destination":"/srv/paperboat-releases","RW":false}],"Config":{"Env":["PAPERBOAT_RELEASE_DIRECTORY=/srv/paperboat-releases/current"]}}]\n' "$PAPERBOAT_TEST_RELEASE_ROOT"
        ;;
      *) exit 2 ;;
    esac
    ;;
  *) exit 2 ;;
esac
EOF
  cat > "$temporary/bin/chown" <<'EOF'
#!/bin/sh
exit 0
EOF
  chmod 0700 "$temporary/bin/docker" "$temporary/bin/chown"

  expected="$temporary/expected"
  cp -R "$candidate" "$expected"
  expected_candidate=$(snapshot_directory "$expected")
  PATH="$temporary/bin:$PATH" PAPERBOAT_TEST_DOCKER_MODE=good PAPERBOAT_TEST_RELEASE_ROOT="$release_root" run_test_publisher "$bundle" "$release_root" "$candidate_version" "$digest"
  set -- "$release_root"/staging/activation-*
  test "$#" -eq 1 && test -d "$1"
  transaction=$1
  test "$expected_candidate" = "$(snapshot)"
  test "$before" = "$(snapshot_directory "$transaction/next")"

  next="$temporary/next"
  mkdir -p "$next/tuf/metadata" "$next/tuf/targets"
  write_current_manifest "$next/current.json" 2026.08.22.24
  printf x > "$next/install"
  printf x > "$next/windows"
  for name in root targets snapshot timestamp; do printf x > "$next/tuf/metadata/$name.json"; done
  write_matching_targets_metadata "$next/current.json" "$next/tuf/metadata/targets.json"
  next_bundle="$temporary/next.tgz"
  tar -C "$next" -czf "$next_bundle" current.json install windows tuf
  next_digest=$(run_checksum "$checksum_backend" "$next_bundle" | awk '{print $1}')
  live_before_wrong_env=$(snapshot)
  if PATH="$temporary/bin:$PATH" PAPERBOAT_TEST_DOCKER_MODE=wrong-env PAPERBOAT_TEST_RELEASE_ROOT="$release_root" run_test_publisher "$next_bundle" "$release_root" 2026.08.22.24 "$next_digest" >/dev/null 2>&1; then
    echo 'publisher accepted a release mount with the wrong runtime directory' >&2
    exit 1
  fi
  test "$live_before_wrong_env" = "$(snapshot)"
  if PATH="$temporary/bin:$PATH" PAPERBOAT_TEST_DOCKER_MODE=split PAPERBOAT_TEST_RELEASE_ROOT="$release_root" run_test_publisher "$next_bundle" "$release_root" 2026.08.22.24 "$next_digest" >/dev/null 2>&1; then
    echo 'publisher accepted split release mount and runtime configuration containers' >&2
    exit 1
  fi
  test "$live_before_wrong_env" = "$(snapshot)"
  live_before_stale=$(snapshot)
  if PATH="$temporary/bin:$PATH" PAPERBOAT_TEST_DOCKER_MODE=stale PAPERBOAT_TEST_RELEASE_ROOT="$release_root" run_test_publisher "$next_bundle" "$release_root" 2026.08.22.24 "$next_digest" >/dev/null 2>&1; then
    echo 'publisher accepted a stale current-directory bind mount' >&2
    exit 1
  fi
  test ! -e "$transaction"
  test "$live_before_stale" = "$(snapshot)"
fi
