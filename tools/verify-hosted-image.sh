#!/bin/sh
set -eu

dockerfile=deploy/hosted/Dockerfile
entrypoint=deploy/hosted/entrypoint.sh

test -f "$dockerfile"
test -f "$entrypoint"
sh -n "$entrypoint"

test "$(grep -c '^FROM .*@sha256:[0-9a-f]\{64\}' "$dockerfile")" -eq 2
grep -F 'openssh-server' "$dockerfile" >/dev/null
grep -F 'ListenAddress 127.0.0.1' "$entrypoint" >/dev/null
grep -F 'HostKey $ssh_state/ssh_host_ed25519_key' "$entrypoint" >/dev/null
grep -F '/usr/sbin/sshd -t' "$entrypoint" >/dev/null
grep -F 'install -m 0644 -o root -g root' "$entrypoint" >/dev/null
if grep -F '0.0.0.0' "$entrypoint" >/dev/null; then
  echo "hosted sshd must not bind a public address" >&2
  exit 1
fi

echo "hosted image: valid"
