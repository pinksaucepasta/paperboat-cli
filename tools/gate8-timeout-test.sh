#!/usr/bin/env bash

set -eu

temporary="$(mktemp -d)"
leader=""
child=""
cleanup() {
  test -z "$leader" || kill -KILL "$leader" 2>/dev/null || true
  test -z "$child" || kill -KILL "$child" 2>/dev/null || true
  rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

set +e
timeout --signal=TERM --kill-after=1 1 sh -c '
  echo "$$" >"$1/leader.pid"
  sleep 30 &
  echo "$!" >"$1/child.pid"
  wait
' sh "$temporary"
status=$?
set -e

test "$status" -eq 124
leader="$(cat "$temporary/leader.pid")"
child="$(cat "$temporary/child.pid")"
if kill -0 "$leader" 2>/dev/null || kill -0 "$child" 2>/dev/null; then
  echo "Gate 8 timeout retained a command process" >&2
  exit 1
fi
