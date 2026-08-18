#!/bin/sh
# This launcher is intentionally stable. The root-owned updater replaces only
# the target in the persistent release volume, so existing invocations keep
# their mapped binary while later invocations use the new CLI.
set -eu

target=/var/lib/paperboat/releases/cli-current/pb
[ -f "$target" ] && [ ! -L "$target" ] || {
  echo "pb: container CLI is not initialized" >&2
  exit 126
}
exec "$target" "$@"
