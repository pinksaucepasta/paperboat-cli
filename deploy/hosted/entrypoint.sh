#!/bin/sh
set -eu

ssh_user=${PAPERBOAT_SSH_USER:?PAPERBOAT_SSH_USER is required}
ssh_port=${PAPERBOAT_SSH_PORT:?PAPERBOAT_SSH_PORT is required}

case "$ssh_user" in
  [a-z_]* ) ;;
  * ) echo "invalid PAPERBOAT_SSH_USER" >&2; exit 64 ;;
esac
if [ "$ssh_user" = root ]; then
  echo "invalid PAPERBOAT_SSH_USER" >&2
  exit 64
fi
case "$ssh_user" in
  *[!a-z0-9_-]* | ?????????????????????????????????* )
    echo "invalid PAPERBOAT_SSH_USER" >&2
    exit 64
    ;;
esac
case "$ssh_port" in
  '' | *[!0-9]* ) echo "invalid PAPERBOAT_SSH_PORT" >&2; exit 64 ;;
esac
if [ "$ssh_port" -lt 1 ] || [ "$ssh_port" -gt 65535 ]; then
  echo "invalid PAPERBOAT_SSH_PORT" >&2
  exit 64
fi

if ! getent passwd "$ssh_user" >/dev/null; then
  useradd --create-home --shell /bin/bash "$ssh_user"
  passwd -d "$ssh_user" >/dev/null
fi

ssh_state=/workspace/.paperboat/ssh
if [ -L /workspace/.paperboat ] || [ -L "$ssh_state" ]; then
  echo "unsafe hosted SSH state path" >&2
  exit 78
fi
install -d -m 0700 -o root -g root /workspace/.paperboat "$ssh_state"
if [ "$(stat -c '%u:%g:%a' /workspace/.paperboat)" != "0:0:700" ] || [ "$(stat -c '%u:%g:%a' "$ssh_state")" != "0:0:700" ]; then
  echo "unsafe hosted SSH state ownership" >&2
  exit 78
fi
if [ -L "$ssh_state/ssh_host_ed25519_key" ] || [ -L "$ssh_state/ssh_host_ed25519_key.pub" ]; then
  echo "unsafe hosted SSH host-key path" >&2
  exit 78
fi
if [ ! -f "$ssh_state/ssh_host_ed25519_key" ]; then
  temporary_key="$ssh_state/.ssh_host_ed25519_key.$$"
  trap 'rm -f "$temporary_key" "$temporary_key.pub"' EXIT HUP INT TERM
  ssh-keygen -q -t ed25519 -N '' -f "$temporary_key"
  mv "$temporary_key" "$ssh_state/ssh_host_ed25519_key"
  rm -f "$temporary_key.pub"
  trap - EXIT HUP INT TERM
fi
if [ ! -f "$ssh_state/ssh_host_ed25519_key" ] || [ "$(stat -c '%u:%g:%a' "$ssh_state/ssh_host_ed25519_key")" != "0:0:600" ]; then
  echo "unsafe hosted SSH private host key" >&2
  exit 78
fi
temporary_public="$ssh_state/.ssh_host_ed25519_key.pub.$$"
trap 'rm -f "$temporary_public"' EXIT HUP INT TERM
ssh-keygen -y -f "$ssh_state/ssh_host_ed25519_key" >"$temporary_public"
chmod 0644 "$temporary_public"
mv "$temporary_public" "$ssh_state/ssh_host_ed25519_key.pub"
trap - EXIT HUP INT TERM
chown root:root "$ssh_state/ssh_host_ed25519_key.pub"
chmod 0600 "$ssh_state/ssh_host_ed25519_key"
chmod 0644 "$ssh_state/ssh_host_ed25519_key.pub"
install -m 0644 -o root -g root "$ssh_state/ssh_host_ed25519_key.pub" /etc/ssh/ssh_host_ed25519_key.pub

install -d -m 0755 /run/sshd
ssh_config=/run/paperboat-sshd_config
cat >"$ssh_config" <<EOF
Port $ssh_port
ListenAddress 127.0.0.1
AddressFamily inet
HostKey $ssh_state/ssh_host_ed25519_key
PidFile /run/sshd-paperboat.pid
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM yes
AllowUsers $ssh_user
Subsystem sftp internal-sftp
EOF
chmod 0600 "$ssh_config"
/usr/sbin/sshd -t -f "$ssh_config"
/usr/sbin/sshd -f "$ssh_config"

exec "$@"
