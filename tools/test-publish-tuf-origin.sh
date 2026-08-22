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

snapshot() {
  (cd "$release_root/current" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256)
}
snapshot_directory() {
  (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256)
}
before=$(snapshot)

if "$test_publisher" "$temporary/missing.tgz" "$release_root" 2026.08.22.23 "$(printf x | shasum -a 256 | awk '{print $1}')" >/dev/null 2>&1; then
  echo 'publisher accepted a missing bundle' >&2
  exit 1
fi
test "$before" = "$(snapshot)"

candidate="$temporary/candidate"
mkdir -p "$candidate/tuf/metadata" "$candidate/tuf/targets"
printf '{"schema":"paperboat.release-current/v1","version":"wrong"}\n' > "$candidate/current.json"
printf x > "$candidate/install"
printf x > "$candidate/windows"
for name in root targets snapshot timestamp; do printf x > "$candidate/tuf/metadata/$name.json"; done
bundle="$temporary/candidate.tgz"
tar -C "$candidate" -czf "$bundle" current.json install windows tuf
digest=$(shasum -a 256 "$bundle" | awk '{print $1}')
if "$test_publisher" "$bundle" "$release_root" 2026.08.22.23 "$digest" >/dev/null 2>&1; then
  echo 'publisher accepted an invalid current.json' >&2
  exit 1
fi
test "$before" = "$(snapshot)"

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
      parent)
        printf '[{"Mounts":[{"Type":"bind","Source":"%s","Destination":"/srv/paperboat-releases","RW":false}]}]\n' "$PAPERBOAT_TEST_RELEASE_ROOT"
        ;;
      stale)
        printf '[{"Mounts":[{"Type":"bind","Source":"%s/current","Destination":"/srv/paperboat-releases","RW":false}]}]\n' "$PAPERBOAT_TEST_RELEASE_ROOT"
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

  candidate_version=2026.08.22.23
  printf '{"schema":"paperboat.release-current/v1","version":"%s"}\n' "$candidate_version" > "$candidate/current.json"
  tar -C "$candidate" -czf "$bundle" current.json install windows tuf
  digest=$(shasum -a 256 "$bundle" | awk '{print $1}')
  expected_candidate=$(snapshot_directory "$candidate")
  PATH="$temporary/bin:$PATH" PAPERBOAT_TEST_DOCKER_MODE=parent PAPERBOAT_TEST_RELEASE_ROOT="$release_root" "$test_publisher" "$bundle" "$release_root" "$candidate_version" "$digest"
  set -- "$release_root"/staging/activation-*
  test "$#" -eq 1 && test -d "$1"
  transaction=$1
  test "$expected_candidate" = "$(snapshot)"
  test "$before" = "$(snapshot_directory "$transaction/next")"

  next="$temporary/next"
  mkdir -p "$next/tuf/metadata" "$next/tuf/targets"
  printf '{"schema":"paperboat.release-current/v1","version":"2026.08.22.24"}\n' > "$next/current.json"
  printf x > "$next/install"
  printf x > "$next/windows"
  for name in root targets snapshot timestamp; do printf x > "$next/tuf/metadata/$name.json"; done
  next_bundle="$temporary/next.tgz"
  tar -C "$next" -czf "$next_bundle" current.json install windows tuf
  next_digest=$(shasum -a 256 "$next_bundle" | awk '{print $1}')
  live_before_stale=$(snapshot)
  if PATH="$temporary/bin:$PATH" PAPERBOAT_TEST_DOCKER_MODE=stale PAPERBOAT_TEST_RELEASE_ROOT="$release_root" "$test_publisher" "$next_bundle" "$release_root" 2026.08.22.24 "$next_digest" >/dev/null 2>&1; then
    echo 'publisher accepted a stale current-directory bind mount' >&2
    exit 1
  fi
  test ! -e "$transaction"
  test "$live_before_stale" = "$(snapshot)"
fi
