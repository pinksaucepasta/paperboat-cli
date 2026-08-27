#!/bin/sh
set -eu

# Paperboat has one executable per native platform. This bootstrap script is
# intentionally small: the release origin supplies only current.json and TUF
# metadata; the immutable bytes always come from the GitHub release asset.
repository=${PAPERBOAT_GITHUB_REPOSITORY:-pinksaucepasta/paperboat-cli}
version=${PAPERBOAT_VERSION:-latest}
release_metadata_url=${PAPERBOAT_RELEASE_METADATA_URL:-https://api.pprbt.dev/current.json}
install_dir=${PAPERBOAT_INSTALL_DIR:-"${HOME}/.local/bin"}
setup_mode=
pair_mode=host
pair=false
enrollment_token=
enrollment_token_file=
machine_name=
ssh_port=
recovery_output=
install_dir_requested=false

if [ -n "${PAPERBOAT_ENROLLMENT_TOKEN:-}" ]; then enrollment_token=$PAPERBOAT_ENROLLMENT_TOKEN; pair=true; fi
if [ -n "${PAPERBOAT_MACHINE_NAME:-}" ]; then machine_name=$PAPERBOAT_MACHINE_NAME; fi

usage() {
  cat <<'EOF'
Install the current Paperboat release.

Usage:
  install.sh [options]

Options:
  --version VERSION             Install the version named by current.json
  --install-dir DIRECTORY       Install Linux pb here (default: ~/.local/bin)
  --setup MODE                  Run setup after install: client or host
  --pair                        Pair this machine after install
  --enrollment-token TOKEN      Use a dashboard-issued single-use pairing token
  --enrollment-token-file FILE  Read the token from an absolute owner-only file
  --setup-mode MODE             Pair as host or client (default: host)
  --name NAME                   Set the machine name
  --ssh-port PORT               Existing SSH port; valid only with --setup host
  --recovery-output FILE        Save the account recovery key during setup
  --no-setup                    Install only (the default)
  -h, --help                    Show this help

Examples:
  curl -fsSL https://get.pprbt.dev/install | sh
  curl -fsSL https://get.pprbt.dev/install | sh -s -- --pair --enrollment-token TOKEN
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version|--install-dir|--setup|--setup-mode|--enrollment-token|--enrollment-token-file|--name|--ssh-port|--recovery-output)
      [ "$#" -ge 2 ] || { echo "pb installer: $1 requires a value" >&2; exit 2; }
      case "$1" in
        --version) version=$2 ;;
        --install-dir) install_dir=$2; install_dir_requested=true ;;
        --setup) setup_mode=$2 ;;
        --setup-mode) pair_mode=$2 ;;
        --enrollment-token) enrollment_token=$2 ;;
        --enrollment-token-file) enrollment_token_file=$2 ;;
        --name) machine_name=$2 ;;
        --ssh-port) ssh_port=$2 ;;
        --recovery-output) recovery_output=$2 ;;
      esac
      shift 2
      ;;
    --pair) pair=true; shift ;;
    --no-setup) setup_mode=; pair=false; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "pb installer: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$setup_mode" in
  ""|client|host) ;;
  *) echo "pb installer: --setup must be client or host" >&2; exit 2 ;;
esac
case "$pair_mode" in
  host|client) ;;
  *) echo "pb installer: --setup-mode must be host or client" >&2; exit 2 ;;
esac
if [ -n "$ssh_port" ] && [ "$setup_mode" != host ]; then
  echo "pb installer: --ssh-port is valid only with --setup host" >&2
  exit 2
fi
if [ -n "$recovery_output" ] && [ -z "$setup_mode" ]; then
  echo "pb installer: --recovery-output requires --setup" >&2
  exit 2
fi
if [ -n "$enrollment_token" ] && [ "$pair" != true ]; then
  echo "pb installer: --enrollment-token requires --pair" >&2
  exit 2
fi
if [ -n "$enrollment_token_file" ] && [ "$pair" != true ]; then
  echo "pb installer: --enrollment-token-file requires --pair" >&2
  exit 2
fi
if [ -n "$enrollment_token" ] && [ -n "$enrollment_token_file" ]; then
  echo "pb installer: use only one enrollment token source" >&2
  exit 2
fi
if [ "$pair" = true ] && [ -n "$setup_mode" ]; then
  echo "pb installer: use either --pair or --setup, not both" >&2
  exit 2
fi

case $(uname -s) in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) echo "pb installer: only macOS and Linux are supported" >&2; exit 1 ;;
esac
case $(uname -m) in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "pb installer: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

case "$repository" in
  */*)
    repository_owner=${repository%%/*}
    repository_name=${repository#*/}
    case "$repository_owner$repository_name" in
      ""|*[!A-Za-z0-9_.-]*) echo "pb installer: invalid GitHub repository" >&2; exit 1 ;;
    esac
    [ "$repository" = "$repository_owner/$repository_name" ] || { echo "pb installer: invalid GitHub repository" >&2; exit 1; }
    ;;
  *) echo "pb installer: invalid GitHub repository" >&2; exit 1 ;;
esac
case "$release_metadata_url" in
  https://*) ;;
  *) echo "pb installer: release metadata URL must use HTTPS" >&2; exit 1 ;;
esac
command -v curl >/dev/null 2>&1 || { echo "pb installer: curl is required" >&2; exit 1; }

# Always start from a clean local state.  Dashboard commands are one-shot
# enrollment commands, so a stale daemon/config must never survive into the
# new installation.  Cleanup is deliberately best-effort for paths that do
# not exist and never touches user files outside Paperboat's own locations.
remove_privileged_file() {
  cleanup_path=$1
  if [ "$(id -u)" -eq 0 ]; then
    rm -f "$cleanup_path" 2>/dev/null || true
  elif command -v sudo >/dev/null 2>&1; then
    if ! sudo -n rm -f "$cleanup_path" 2>/dev/null; then
      rm -f "$cleanup_path" 2>/dev/null || true
    fi
  else
    rm -f "$cleanup_path" 2>/dev/null || true
  fi
  if [ -e "$cleanup_path" ] || [ -L "$cleanup_path" ]; then
    echo "pb installer: warning: could not remove privileged path $cleanup_path; continuing" >&2
  fi
}

cleanup_existing() {
  old=/usr/local/bin/pb
  if [ "$(id -u)" -eq 0 ]; then
    launchctl bootout system/com.pinksaucepasta.paperboat.runtime-host 2>/dev/null || true
    rm -f /Library/LaunchDaemons/com.pinksaucepasta.paperboat.runtime-host.plist
    rm -rf "/Library/PrivilegedHelperTools/Paperboat" "/Library/Application Support/Paperboat"
    rm -f "$old"
  elif [ "$os" = darwin ]; then
    sudo -n launchctl bootout system/com.pinksaucepasta.paperboat.runtime-host 2>/dev/null || true
    sudo -n rm -f /Library/LaunchDaemons/com.pinksaucepasta.paperboat.runtime-host.plist "$old" 2>/dev/null || true
    sudo -n rm -rf "/Library/PrivilegedHelperTools/Paperboat" "/Library/Application Support/Paperboat" 2>/dev/null || true
  fi
  if [ "$os" = darwin ]; then
    launchctl bootout "gui/$(id -u)/com.pinksaucepasta.paperboat.local-daemon" 2>/dev/null || true
    rm -f "$HOME/Library/LaunchAgents/com.pinksaucepasta.paperboat.local-daemon.plist"
  else
    systemctl --user disable --now paperboat-local-daemon.service 2>/dev/null || true
    sudo -n systemctl disable --now paperboat-runtime-host.service 2>/dev/null || true
    sudo -n rm -f /etc/systemd/system/paperboat-runtime-host.service 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/paperboat-local-daemon.service"
    rm -f "$HOME/.local/bin/pb"
  fi
  # Cover both the packaged macOS layout and the development layout used by
  # deploy-mac.sh. These are Paperboat-owned paths only.
  rm -rf "$HOME/Library/Application Support/paperboat" "$HOME/.paperboat/runtime" "$HOME/.paperboat/state" "$HOME/.config/paperboat" "$HOME/.local/share/paperboat" "$HOME/.local/state/paperboat"
  # Remove the managed SSH include and selector key so a reinstall cannot
  # retain stale aliases, ports, or an agent socket from an older enrollment.
  if [ -f "$HOME/.ssh/config" ]; then
    ssh_config_tmp=$(mktemp "${TMPDIR:-/tmp}/paperboat-ssh-config.XXXXXX")
    awk '!index($0, "# paperboat-managed-ssh-include-v1")' "$HOME/.ssh/config" > "$ssh_config_tmp"
    chmod 600 "$ssh_config_tmp"
    mv -f "$ssh_config_tmp" "$HOME/.ssh/config"
  fi
  rm -f "$HOME/.ssh/paperboat_config" "$HOME/.ssh/paperboat-managed-ssh.pub" \
    "$HOME/.ssh/.paperboat-config-install-v1.json" "$HOME/.ssh/.paperboat-config-transaction-v1.json"
  if [ "$os" = darwin ]; then
    remove_privileged_file /usr/local/libexec/paperboat/pb
  else
    # The packaged runtime may be owned by root even when the dashboard
    # command is run as an unprivileged user. Best-effort removal must never
    # abort the installer before the user-owned replacement is installed.
    remove_privileged_file "$old"
    remove_privileged_file /usr/local/libexec/paperboat/pb
  fi
}

asset="pb-${os}-${arch}"
[ "$os" != windows ] || asset="$asset.exe"
[ "$os" != darwin ] || asset="$asset.pkg"
format=elf
[ "$os" != darwin ] || format=pkg

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-install.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
current_file="$tmp_dir/current.json"
curl -fLsS --proto '=https' --tlsv1.2 "$release_metadata_url" -o "$current_file"

# The release publisher writes compact JSON with stable struct field order.
# Keep the parser dependency-free so a clean macOS install does not require
# Python, jq, or a package manager. Values are validated again below before
# they are used as URLs or paths.
compact=$(tr -d '\r\n\t ' < "$current_file")
metadata_version=$(printf '%s' "$compact" | sed -n 's|.*"schema":"paperboat.release-current/v1","version":"\([^"]*\)".*|\1|p')
metadata_repository=$(printf '%s' "$compact" | sed -n 's|.*"repository":"\([^"]*\)".*|\1|p')
[ -n "$metadata_version" ] && [ -n "$metadata_repository" ] || { echo "pb installer: current.json is invalid" >&2; exit 1; }
case "$metadata_version" in
  *[!0-9A-Za-z._-]*|/*|"") echo "pb installer: current.json contains an invalid version" >&2; exit 1 ;;
esac
[ "$metadata_repository" = "$repository" ] || { echo "pb installer: current.json repository does not match the configured release repository" >&2; exit 1; }
if [ "$version" = latest ]; then
  version=$metadata_version
elif [ "$version" != "$metadata_version" ]; then
  echo "pb installer: requested version is not the current signed release" >&2
  exit 1
fi

asset_metadata=$(printf '%s' "$compact" | sed -n 's|.*"'"$asset"'":{"platform":"\([^"]*\)","architecture":"\([^"]*\)","format":"\([^"]*\)","url":"\([^"]*\)","sha256":"\([0-9a-f]\{64\}\)","length":\([0-9][0-9]*\)}.*|\1 \2 \3 \4 \5 \6|p')
set -- $asset_metadata
[ "$#" -eq 6 ] || { echo "pb installer: current.json has no metadata for $asset" >&2; exit 1; }
asset_platform=$1
asset_architecture=$2
asset_format=$3
asset_url=$4
expected=$5
expected_length=$6
[ "$asset_platform" = "$os" ] && [ "$asset_architecture" = "$arch" ] && [ "$asset_format" = "$format" ] || { echo "pb installer: current.json asset metadata does not match this host" >&2; exit 1; }
expected_url="https://github.com/${repository}/releases/download/${version}/${asset}"
[ "$asset_url" = "$expected_url" ] || { echo "pb installer: release asset URL is not an immutable GitHub release URL" >&2; exit 1; }

download="$tmp_dir/$asset"
echo "Downloading Paperboat for ${os}/${arch}..." >&2
curl --fail --location --show-error --silent --retry 5 --retry-delay 2 --connect-timeout 15 --max-time 900 --proto '=https' --tlsv1.2 "$asset_url" -o "$download"
actual_length=$(wc -c < "$download" | tr -d ' ')
[ "$actual_length" = "$expected_length" ] || { echo "pb installer: release asset length verification failed" >&2; exit 1; }
if command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$download" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$download" | awk '{print $1}')
elif command -v openssl >/dev/null 2>&1; then
  actual=$(openssl dgst -sha256 "$download" | awk '{print $NF}')
else
  echo "pb installer: shasum, sha256sum, or openssl is required" >&2
  exit 1
fi
[ "$actual" = "$expected" ] || { echo "pb installer: release asset digest verification failed" >&2; exit 1; }

# Preserve the existing installation if download or verification fails.
cleanup_existing

if [ "$os" = darwin ]; then
  command -v installer >/dev/null 2>&1 || { echo "pb installer: macOS installer is required" >&2; exit 1; }
  if [ "$install_dir_requested" = true ] || [ -n "${PAPERBOAT_INSTALL_DIR:-}" ]; then
    echo "pb installer: --install-dir is not supported for the macOS PKG; it installs /usr/local/bin/pb" >&2
    exit 2
  fi
  sudo installer -pkg "$download" -target /
  target=/usr/local/bin/pb
else
  mkdir -p "$install_dir"
  target="$install_dir/pb"
  staged="$install_dir/.pb.installing.$$"
  cp "$download" "$staged"
  chmod 0755 "$staged"
  mv -f "$staged" "$target"
fi
echo "Installed pb to $target" >&2

case ":${PATH}:" in
  *":${install_dir}:"*) ;;
  *) [ "$os" = darwin ] || echo "Add ${install_dir} to PATH to run pb from a new shell." >&2 ;;
esac

set --
if [ -n "$machine_name" ]; then set -- "$@" --name "$machine_name"; fi
if [ "$pair" = true ]; then
  first=${enrollment_token%${enrollment_token#?}}
  case "$first" in 0|2|4|6|8|B|D|F|H|J|L|N|P|R|T|V|X|Z) pair_mode=host ;; *) pair_mode=client ;; esac
  set -- "$@" --setup-mode "$pair_mode"
  [ -z "$enrollment_token" ] || set -- "$@" --enrollment-token "$enrollment_token"
  [ -z "$enrollment_token_file" ] || set -- "$@" --enrollment-token-file "$enrollment_token_file"
  exec "$target" pair "$@"
fi
if [ -n "$setup_mode" ]; then
  set -- "$@" --mode "$setup_mode"
  [ -z "$ssh_port" ] || set -- "$@" --ssh-port "$ssh_port"
  [ -z "$recovery_output" ] || set -- "$@" --recovery-output "$recovery_output"
  exec "$target" setup "$@"
fi

"$target" --version
