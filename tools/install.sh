#!/bin/sh
set -eu

repository=${PAPERBOAT_GITHUB_REPOSITORY:-pinksaucepasta/paperboat-cli}
version=${PAPERBOAT_VERSION:-latest}
install_dir=${PAPERBOAT_INSTALL_DIR:-"${HOME}/.local/bin"}
setup_mode=
pair=false
enrollment_token=
machine_name=
ssh_port=
recovery_output=

usage() {
  cat <<'EOF'
Install Paperboat from GitHub Releases.

Usage:
  install.sh [options]

Options:
  --version VERSION          Install a specific release (default: latest)
  --install-dir DIRECTORY    Install pb here (default: ~/.local/bin)
  --setup MODE               Run setup after install: receive, session, or host
  --pair                     Pair this machine as a host after install
  --enrollment-token TOKEN   Use a dashboard-issued single-use pairing token
  --name NAME                Set the machine name
  --ssh-port PORT            Existing SSH port; valid only with --setup host
  --recovery-output FILE     Save the account recovery key during setup
  --no-setup                 Install only (the default)
  -h, --help                 Show this help

Examples:
  curl -fsSL https://get.pprbt.dev/install | bash
  curl -fsSL https://get.pprbt.dev/install | bash -s -- --pair --enrollment-token TOKEN
  curl -fsSL https://get.pprbt.dev/install | bash -s -- --setup receive
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version|--install-dir|--setup|--enrollment-token|--name|--ssh-port|--recovery-output)
      [ "$#" -ge 2 ] || { echo "pb installer: $1 requires a value" >&2; exit 2; }
      case "$1" in
        --version) version=$2 ;;
        --install-dir) install_dir=$2 ;;
        --setup) setup_mode=$2 ;;
        --enrollment-token) enrollment_token=$2 ;;
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
  ""|receive|session|host) ;;
  *) echo "pb installer: --setup must be receive, session, or host" >&2; exit 2 ;;
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

if ! command -v curl >/dev/null 2>&1; then
  echo "pb installer: curl is required" >&2
  exit 1
fi

asset="pb-${os}-${arch}"
if [ "$version" = latest ]; then
  latest_url="https://github.com/${repository}/releases/latest"
  tag_url=$(curl -fLsS --proto '=https' --tlsv1.2 -o /dev/null -w '%{url_effective}' "$latest_url")
  version=${tag_url##*/}
fi
case "$version" in
  ""|*/*|*[!0-9A-Za-z._-]*) echo "pb installer: invalid release version" >&2; exit 1 ;;
esac
release_base="https://github.com/${repository}/releases/download/${version}"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-install.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

echo "Downloading Paperboat for ${os}/${arch}..." >&2
curl -fL --proto '=https' --tlsv1.2 "$release_base/$asset" -o "$tmp_dir/$asset"
curl -fL --proto '=https' --tlsv1.2 "$release_base/SHA256SUMS" -o "$tmp_dir/SHA256SUMS"
expected=$(awk -v file="$asset" '$2 == file || $2 == "*" file { print $1; exit }' "$tmp_dir/SHA256SUMS")
[ -n "$expected" ] || { echo "pb installer: checksum for $asset is missing" >&2; exit 1; }
if command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp_dir/$asset" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp_dir/$asset" | awk '{print $1}')
else
  echo "pb installer: shasum or sha256sum is required" >&2
  exit 1
fi
[ "$actual" = "$expected" ] || { echo "pb installer: checksum verification failed" >&2; exit 1; }

mkdir -p "$install_dir"
target="$install_dir/pb"
staged="$install_dir/.pb.installing.$$"
cp "$tmp_dir/$asset" "$staged"
chmod 0755 "$staged"
mv -f "$staged" "$target"
echo "Installed pb to $target" >&2

case ":${PATH}:" in
  *":${install_dir}:"*) ;;
  *) echo "Add ${install_dir} to PATH to run pb from a new shell." >&2 ;;
esac

set --
if [ -n "$machine_name" ]; then set -- "$@" --name "$machine_name"; fi
if [ "$pair" = true ]; then
  if [ -n "$enrollment_token" ]; then set -- "$@" --enrollment-token "$enrollment_token"; fi
  exec "$target" pair "$@"
fi
if [ -n "$setup_mode" ]; then
  set -- "$@" --mode "$setup_mode"
  if [ -n "$ssh_port" ]; then set -- "$@" --ssh-port "$ssh_port"; fi
  if [ -n "$recovery_output" ]; then set -- "$@" --recovery-output "$recovery_output"; fi
  exec "$target" setup "$@"
fi

"$target" --version
