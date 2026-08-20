#!/bin/sh
set -eu

dockerfile=deploy/hosted/Dockerfile
entrypoint=deploy/hosted/entrypoint.sh
launcher=deploy/hosted/pb-launcher.sh
hosted_compose=deploy/hosted/compose.yaml
self_hosted_compose=deploy/self-hosted/compose.yaml

test -f "$dockerfile"
test -f "$entrypoint"
test -f "$launcher"
test -f "$hosted_compose"
test -f "$self_hosted_compose"
sh -n "$entrypoint"
sh -n "$launcher"

test "$(grep -c '^FROM .*@sha256:[0-9a-f]\{64\}' "$dockerfile")" -eq 2
grep -F 'openssh-server' "$dockerfile" >/dev/null
grep -F 'paperboat-hostd' "$dockerfile" >/dev/null
grep -F 'paperboat-updated' "$dockerfile" >/dev/null
grep -F 'paperboat-runtime.bootstrap' "$dockerfile" >/dev/null
grep -F 'useradd --uid 10001' "$dockerfile" >/dev/null
grep -F 'COPY deploy/hosted/pb-launcher.sh /usr/local/bin/pb' "$dockerfile" >/dev/null
if grep -E '^CMD' "$dockerfile" >/dev/null; then
  echo "hosted image must not accept an arbitrary command in place of hostd" >&2
  exit 1
fi
grep -F 'ListenAddress 127.0.0.1' "$entrypoint" >/dev/null
grep -F 'HostKey $ssh_state/ssh_host_ed25519_key' "$entrypoint" >/dev/null
grep -F 'ssh-keygen -q -y -f "$ssh_state/ssh_host_ed25519_key"' "$entrypoint" >/dev/null
grep -F 'install -m 0644 -o root -g root "$temporary_public" "$ssh_host_public"' "$entrypoint" >/dev/null
grep -F '/usr/sbin/sshd -t' "$entrypoint" >/dev/null
grep -F 'PAPERBOAT_CONTAINER_MODE must be hosted or self-hosted' "$entrypoint" >/dev/null
grep -F 'PAPERBOAT_RELEASE_REPOSITORY must use https' "$entrypoint" >/dev/null
grep -F 'PAPERBOAT_RUNTIME_CURRENT="$release_root/runtime-current/paperboat-runtime"' "$entrypoint" >/dev/null
grep -F 'PAPERBOAT_UPDATE_STATE_ROOT="$updated_root"' "$entrypoint" >/dev/null
grep -F 'PAPERBOAT_HOSTD_TOKEN_FILE="$token_root/token"' "$entrypoint" >/dev/null
grep -F 'export HOME=/workspace' "$entrypoint" >/dev/null
grep -F '/usr/bin/setpriv --reuid="$runtime_uid" --regid="$runtime_gid" --init-groups' "$entrypoint" >/dev/null
grep -F 'paperboat-hostd __runtime-hostd &' "$entrypoint" >/dev/null
grep -F 'paperboat-updated __runtime-updated' "$entrypoint" >/dev/null
grep -F 'target=/var/lib/paperboat/releases/cli-current/pb' "$launcher" >/dev/null
if grep -F '0.0.0.0' "$entrypoint" >/dev/null; then
  echo "hosted sshd must not bind a public address" >&2
  exit 1
fi

for compose in "$hosted_compose" "$self_hosted_compose"; do
  grep -F 'read_only: true' "$compose" >/dev/null
  grep -F 'paperboat-state:/var/lib/paperboat' "$compose" >/dev/null
  grep -F 'paperboat-workspace:/workspace' "$compose" >/dev/null
  grep -F '/run:mode=755,nosuid,nodev' "$compose" >/dev/null
done
grep -F 'PAPERBOAT_CONTAINER_MODE: hosted' "$hosted_compose" >/dev/null
grep -F 'PAPERBOAT_SSH_USER: paperboat' "$hosted_compose" >/dev/null
grep -F 'PAPERBOAT_CONTAINER_MODE: self-hosted' "$self_hosted_compose" >/dev/null
if grep -E '^    ports:' "$hosted_compose" "$self_hosted_compose" >/dev/null; then
  echo "container deployments must not publish Paperboat ports" >&2
  exit 1
fi

echo "hosted image: valid"
