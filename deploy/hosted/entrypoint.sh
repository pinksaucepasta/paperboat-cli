#!/bin/sh
# The container supervisor has only two long-lived children. paperboat-hostd
# owns every workload and paperboat-updated only verifies and rotates release
# artifacts. A runtime update never replaces either the container or hostd.
set -eu

runtime_user=paperboat
runtime_uid=10001
runtime_gid=10001
state_root=/var/lib/paperboat
release_root="$state_root/releases"
updated_root="$state_root/updated"
runtime_root="$state_root/runtime"
token_root="$state_root/hostd"
hostd_socket=/run/paperboat-hostd/hostd.sock
updated_socket=/run/paperboat-updated/control.sock

fail() {
  echo "paperboat container: $*" >&2
  exit 78
}

require_value() {
  key=$1
  eval "value=\${$key-}"
  [ -n "$value" ] || fail "$key is required"
}

safe_root_dir() {
  path=$1
  install -d -m 0755 -o root -g root "$path"
  [ ! -L "$path" ] || fail "unsafe root-owned path"
  [ "$(stat -c '%u:%g:%a' "$path")" = "0:0:755" ] || fail "unsafe root-owned path"
}

safe_private_root_dir() {
  path=$1
  install -d -m 0700 -o root -g root "$path"
  [ ! -L "$path" ] || fail "unsafe private root-owned path"
  [ "$(stat -c '%u:%g:%a' "$path")" = "0:0:700" ] || fail "unsafe private root-owned path"
}

safe_runtime_dir() {
  path=$1
  install -d -m 0700 -o "$runtime_uid" -g "$runtime_gid" "$path"
  [ ! -L "$path" ] || fail "unsafe runtime-owned path"
  [ "$(stat -c '%u:%g:%a' "$path")" = "$runtime_uid:$runtime_gid:700" ] || fail "unsafe runtime-owned path"
}

safe_release_dir() {
  path=$1
  install -d -m 0755 -o root -g root "$path"
  [ ! -L "$path" ] || fail "unsafe release path"
  [ "$(stat -c '%u:%g:%a' "$path")" = "0:0:755" ] || fail "unsafe release path"
}

ensure_bootstrap_file() {
  source=$1
  target=$2
  if [ -e "$target" ]; then
    [ ! -L "$target" ] && [ -f "$target" ] || fail "unsafe bootstrap target"
    [ "$(stat -c '%u:%g:%a' "$target")" = "0:0:755" ] || fail "unsafe bootstrap target"
    return
  fi
  install -m 0755 -o root -g root "$source" "$target"
  sync -f "$target"
}

container_mode=${PAPERBOAT_CONTAINER_MODE:-hosted}
case "$container_mode" in
  hosted|self-hosted) ;;
  *) fail "PAPERBOAT_CONTAINER_MODE must be hosted or self-hosted" ;;
esac

if [ "$container_mode" = hosted ]; then
  require_value PAPERBOAT_SSH_PORT
  require_value PAPERBOAT_SSH_USER
  [ "$PAPERBOAT_SSH_USER" = "$runtime_user" ] || fail "PAPERBOAT_SSH_USER must be paperboat"
  case "$PAPERBOAT_SSH_PORT" in
    *[!0-9]*|'') fail "invalid PAPERBOAT_SSH_PORT" ;;
  esac
  [ "$PAPERBOAT_SSH_PORT" -ge 1 ] && [ "$PAPERBOAT_SSH_PORT" -le 65535 ] || fail "invalid PAPERBOAT_SSH_PORT"
  : "${PAPERBOAT_RUNTIME_PROFILE:=hosted}"
  [ "$PAPERBOAT_RUNTIME_PROFILE" = hosted ] || fail "hosted container requires hosted runtime profile"
else
  : "${PAPERBOAT_RUNTIME_PROFILE:=byod}"
  [ "$PAPERBOAT_RUNTIME_PROFILE" = byod ] || fail "self-hosted container requires byod runtime profile"
fi

require_value PAPERBOAT_RELEASE_REPOSITORY
require_value PAPERBOAT_MACHINE_ID
case "$PAPERBOAT_RELEASE_REPOSITORY" in
  https://*) ;;
  *) fail "PAPERBOAT_RELEASE_REPOSITORY must use https" ;;
esac

# Mutable locations are fixed. A deployment cannot select a socket, journal,
# capability token, or binary path through its environment.
export PAPERBOAT_RUNTIME_STATE_ROOT="$runtime_root"
export PAPERBOAT_RUNTIME_CURRENT="$release_root/runtime-current/paperboat-runtime"
export PAPERBOAT_RUNTIME_ROLLBACK="$release_root/runtime-rollback/paperboat-runtime"
export PAPERBOAT_RUNTIME_STAGED="$release_root/runtime-staged/paperboat-runtime"
export PAPERBOAT_CLI_CURRENT="$release_root/cli-current/pb"
export PAPERBOAT_CLI_ROLLBACK="$release_root/cli-rollback/pb"
export PAPERBOAT_RELEASE_ROOT="$release_root"
export PAPERBOAT_UPDATE_STATE_ROOT="$updated_root"
export PAPERBOAT_HOSTD_SOCKET="$hostd_socket"
export PAPERBOAT_HOSTD_TOKEN_FILE="$token_root/token"
export PAPERBOAT_UPDATED_SOCKET="$updated_socket"
export PAPERBOAT_ENROLLED_UID="$runtime_uid"
export PAPERBOAT_ENROLLED_GID="$runtime_gid"
export PAPERBOAT_UPDATE_HEALTH_URL=http://127.0.0.1:8080/healthz
export PAPERBOAT_WORKSPACE_ROOT=/workspace
export PAPERBOAT_WORKSPACE=${PAPERBOAT_WORKSPACE:-/workspace}
export HOME=/workspace
[ "$PAPERBOAT_WORKSPACE" = /workspace ] || fail "PAPERBOAT_WORKSPACE must be /workspace"

safe_root_dir "$state_root"
safe_release_dir "$release_root"
safe_release_dir "$release_root/runtime-current"
safe_release_dir "$release_root/runtime-rollback"
safe_release_dir "$release_root/runtime-staged"
safe_release_dir "$release_root/cli-current"
safe_release_dir "$release_root/cli-rollback"
safe_private_root_dir "$updated_root"
safe_runtime_dir "$runtime_root"
safe_runtime_dir "$token_root"
safe_runtime_dir /workspace
safe_root_dir /run/paperboat-updated

if [ ! -f "$PAPERBOAT_HOSTD_TOKEN_FILE" ]; then
  umask 077
  dd if=/dev/urandom of="$PAPERBOAT_HOSTD_TOKEN_FILE" bs=32 count=1 status=none
  chown "$runtime_uid:$runtime_gid" "$PAPERBOAT_HOSTD_TOKEN_FILE"
  chmod 0600 "$PAPERBOAT_HOSTD_TOKEN_FILE"
fi
[ ! -L "$PAPERBOAT_HOSTD_TOKEN_FILE" ] && [ -f "$PAPERBOAT_HOSTD_TOKEN_FILE" ] || fail "unsafe hostd capability token"
[ "$(stat -c '%u:%g:%a' "$PAPERBOAT_HOSTD_TOKEN_FILE")" = "$runtime_uid:$runtime_gid:600" ] || fail "unsafe hostd capability token"
[ "$(wc -c < "$PAPERBOAT_HOSTD_TOKEN_FILE")" -eq 32 ] || fail "invalid hostd capability token"

ensure_bootstrap_file /usr/local/libexec/paperboat/bootstrap/paperboat-runtime "$PAPERBOAT_RUNTIME_CURRENT"
ensure_bootstrap_file /usr/local/libexec/paperboat/bootstrap/pb "$PAPERBOAT_CLI_CURRENT"

start_sshd() {
  [ "$container_mode" = hosted ] || return 0
  ssh_state=/workspace/.paperboat/ssh
  [ ! -L /workspace/.paperboat ] && [ ! -L "$ssh_state" ] || fail "unsafe hosted SSH state path"
  install -d -m 0700 -o "$runtime_uid" -g "$runtime_gid" /workspace/.paperboat "$ssh_state"
  [ "$(stat -c '%u:%g:%a' /workspace/.paperboat)" = "$runtime_uid:$runtime_gid:700" ] || fail "unsafe hosted SSH state ownership"
  [ "$(stat -c '%u:%g:%a' "$ssh_state")" = "$runtime_uid:$runtime_gid:700" ] || fail "unsafe hosted SSH state ownership"
  [ ! -L "$ssh_state/ssh_host_ed25519_key" ] || fail "unsafe hosted SSH host-key path"
  if [ ! -f "$ssh_state/ssh_host_ed25519_key" ]; then
    temporary_key="$ssh_state/.ssh_host_ed25519_key.$$"
    trap 'rm -f "$temporary_key" "$temporary_key.pub"' EXIT HUP INT TERM
    ssh-keygen -q -t ed25519 -N '' -f "$temporary_key"
    mv "$temporary_key" "$ssh_state/ssh_host_ed25519_key"
    rm -f "$temporary_key.pub"
    trap - EXIT HUP INT TERM
  fi
  [ -f "$ssh_state/ssh_host_ed25519_key" ] && [ "$(stat -c '%u:%g:%a' "$ssh_state/ssh_host_ed25519_key")" = "0:0:600" ] || fail "unsafe hosted SSH private host key"
  install -d -m 0755 /run/sshd
  ssh_config=/run/paperboat-sshd_config
  cat >"$ssh_config" <<EOF
Port $PAPERBOAT_SSH_PORT
ListenAddress 127.0.0.1
AddressFamily inet
HostKey $ssh_state/ssh_host_ed25519_key
PidFile /run/sshd-paperboat.pid
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no
AllowUsers $runtime_user
Subsystem sftp internal-sftp
EOF
  chmod 0600 "$ssh_config"
  /usr/sbin/sshd -t -f "$ssh_config"
  /usr/sbin/sshd -f "$ssh_config"
}

wait_for_hostd() {
  attempts=0
  while [ "$attempts" -lt 300 ]; do
    [ -S "$hostd_socket" ] && return 0
    kill -0 "$hostd_pid" 2>/dev/null || return 1
    attempts=$((attempts + 1))
    sleep 0.1
  done
  return 1
}

run_updater() {
  delay=5
  while :; do
    /usr/local/libexec/paperboat/components/paperboat-updated __runtime-updated || true
    sleep "$delay"
    if [ "$delay" -lt 3600 ]; then
      delay=$((delay * 2))
      [ "$delay" -le 3600 ] || delay=3600
    fi
  done
}

shutdown() {
  trap - EXIT HUP INT TERM
  if [ -n "${updater_pid:-}" ]; then
    kill -TERM "$updater_pid" 2>/dev/null || true
    wait "$updater_pid" 2>/dev/null || true
  fi
  if [ -n "${hostd_pid:-}" ]; then
    kill -TERM "$hostd_pid" 2>/dev/null || true
    wait "$hostd_pid" 2>/dev/null || true
  fi
  exit 0
}

start_sshd
/usr/bin/setpriv --reuid="$runtime_uid" --regid="$runtime_gid" --init-groups \
  /usr/local/libexec/paperboat/components/paperboat-hostd __runtime-hostd &
hostd_pid=$!
trap shutdown EXIT HUP INT TERM
wait_for_hostd || fail "paperboat-hostd did not become ready"
run_updater &
updater_pid=$!
if wait "$hostd_pid"; then
  hostd_status=0
else
  hostd_status=$?
fi
kill -TERM "$updater_pid" 2>/dev/null || true
wait "$updater_pid" 2>/dev/null || true
trap - EXIT HUP INT TERM
exit "$hostd_status"
