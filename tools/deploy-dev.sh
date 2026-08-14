#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 YYYY.MM.DD.X" >&2
  exit 64
}

test "$#" -eq 1 || usage
version="$1"
if ! [[ "$version" =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$ ]]; then
  echo "invalid version: $version (expected YYYY.MM.DD.X)" >&2
  exit 64
fi
release_date="${version%.*}"
calendar_date="${release_date//./-}"
normalized_date="$(date -u -d "$calendar_date" +%Y-%m-%d 2>/dev/null || date -j -u -f %Y-%m-%d "$calendar_date" +%Y-%m-%d 2>/dev/null || true)"
test "$normalized_date" = "$calendar_date" || {
  echo "invalid version date: $release_date" >&2
  exit 64
}

repository_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
build_root="$repository_root/.codex-build/deploy-dev-$version"
commit="$(git -C "$repository_root" rev-parse --verify HEAD)"
ldflags="-X github.com/pinksaucepasta/paperboat/internal/buildinfo.Version=$version -X github.com/pinksaucepasta/paperboat/internal/buildinfo.Commit=$commit -X github.com/pinksaucepasta/paperboat/internal/buildinfo.ProtocolVersion=1"

: "${DADAPE_HOST:=152.67.0.60}"
: "${DADAPE_PORT:=6000}"
: "${DADAPE_USER:=anvit}"
: "${DADAPE_KEY:=$HOME/.ssh/id_ed25519}"
: "${HETZNER_HOST:=157.180.74.88}"
: "${HETZNER_USER:=root}"
: "${HETZNER_KEY:=/Users/pujan.pm/keys/def.pem}"

for command in date git go awk mkdir shasum ssh scp; do
  command -v "$command" >/dev/null || { echo "required command not found: $command" >&2; exit 69; }
done
test -r "$DADAPE_KEY" || { echo "Dadape SSH key is not readable: $DADAPE_KEY" >&2; exit 66; }
test -r "$HETZNER_KEY" || { echo "Hetzner SSH key is not readable: $HETZNER_KEY" >&2; exit 66; }

dadape_target="$DADAPE_USER@$DADAPE_HOST"
hetzner_target="$HETZNER_USER@$HETZNER_HOST"
dadape_ssh=(ssh -o BatchMode=yes -o ConnectTimeout=10 -p "$DADAPE_PORT" -i "$DADAPE_KEY" "$dadape_target")
dadape_scp=(scp -q -o BatchMode=yes -o ConnectTimeout=10 -P "$DADAPE_PORT" -i "$DADAPE_KEY")
hetzner_ssh=(ssh -o BatchMode=yes -o ConnectTimeout=10 -i "$HETZNER_KEY" "$hetzner_target")
hetzner_scp=(scp -q -o BatchMode=yes -o ConnectTimeout=10 -i "$HETZNER_KEY")

echo "Checking deployment targets"
"${dadape_ssh[@]}" 'set -eu; test "$(uname -m)" = aarch64; command -v sha256sum >/dev/null; command -v systemctl >/dev/null; sudo -n /usr/local/sbin/paperboat-deploy-dev check; test "$(systemctl --user is-active paperboat-local-daemon.service)" = active'
"${hetzner_ssh[@]}" 'set -eu; test "$(uname -m)" = x86_64; command -v sha256sum >/dev/null; command -v systemctl >/dev/null; test "$(systemctl is-active paperboat-runtime-host.service)" = active; test "$(systemctl is-active paperboat-runtime-privileged.service)" = active'

mkdir -p "$build_root"
echo "Building Paperboat $version for Linux ARM64 and AMD64"
(
  cd "$repository_root"
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOTOOLCHAIN=local go build -trimpath -ldflags "$ldflags" -o "$build_root/pb-linux-arm64" ./cmd/pb
) &
arm_build=$!
(
  cd "$repository_root"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local go build -trimpath -ldflags "$ldflags" -o "$build_root/pb-linux-amd64" ./cmd/pb
) &
amd_build=$!
arm_status=0
amd_status=0
wait "$arm_build" || arm_status=$?
wait "$amd_build" || amd_status=$?
test "$arm_status" -eq 0 || { echo "ARM64 build failed (exit $arm_status)" >&2; exit "$arm_status"; }
test "$amd_status" -eq 0 || { echo "AMD64 build failed (exit $amd_status)" >&2; exit "$amd_status"; }

arm_hash="$(shasum -a 256 "$build_root/pb-linux-arm64" | awk '{print $1}')"
amd_hash="$(shasum -a 256 "$build_root/pb-linux-amd64" | awk '{print $1}')"
arm_size="$(stat -f '%z' "$build_root/pb-linux-arm64" 2>/dev/null || stat -c '%s' "$build_root/pb-linux-arm64")"
amd_size="$(stat -f '%z' "$build_root/pb-linux-amd64" 2>/dev/null || stat -c '%s' "$build_root/pb-linux-amd64")"
dadape_artifact="/home/anvit/pb-dev-$version-arm64"
hetzner_artifact="/root/pb-dev-$version-amd64"

test -s "$build_root/pb-linux-arm64" || { echo "ARM64 artifact is empty" >&2; exit 70; }
test -s "$build_root/pb-linux-amd64" || { echo "AMD64 artifact is empty" >&2; exit 70; }

echo "Uploading and installing Dadape ARM64"
"${dadape_scp[@]}" "$build_root/pb-linux-arm64" "$dadape_target:$dadape_artifact.new"
"${dadape_ssh[@]}" bash -s -- "$version" "$arm_hash" "$arm_size" "$dadape_artifact" <<'REMOTE'
set -euo pipefail
version="$1"; expected="$2"; expected_size="$3"; artifact="$4"
actual="$(sha256sum "$artifact.new" | awk '{print $1}')"
test "$actual" = "$expected" || { echo "Dadape upload hash mismatch: expected=$expected actual=$actual" >&2; exit 1; }
test "$(stat -c '%s' "$artifact.new")" = "$expected_size" || { echo "Dadape upload size mismatch" >&2; exit 1; }
test "$(uname -m)" = "aarch64" || { echo "Dadape target is not ARM64: $(uname -m)" >&2; exit 1; }
mv "$artifact.new" "$artifact"; chmod 0755 "$artifact"
host_installed=false
user_installed=false
user_bin=/home/anvit/.local/bin/pb
user_backup="$user_bin.rollback-$version"
finish() {
  status=$?
  trap - EXIT
  set +e
  if test "$status" -ne 0 && test "$host_installed" = true; then
    sudo -n /usr/local/sbin/paperboat-deploy-dev rollback "$version"
  fi
  if test "$status" -ne 0 && test "$user_installed" = true; then
    mv -f "$user_backup" "$user_bin"
  fi
  systemctl --user start paperboat-local-daemon.service
  user_start=$?
  rm -f "$artifact.new"
  if test "$status" -eq 0 && test "$user_start" -ne 0; then
    status=1
  fi
  exit "$status"
}
trap finish EXIT
systemctl --user stop paperboat-local-daemon.service
cp -p "$user_bin" "$user_backup"
install -m 0755 "$artifact" "$user_bin.installing"
mv -f "$user_bin.installing" "$user_bin"
user_installed=true
sudo -n /usr/local/sbin/paperboat-deploy-dev "$version" "$expected" "$expected_size" "$artifact"
host_installed=true
systemctl --user start paperboat-local-daemon.service
test "$(systemctl --user is-active paperboat-local-daemon.service)" = active
sudo -n /usr/local/sbin/paperboat-deploy-dev check
sudo -n /usr/local/sbin/paperboat-deploy-dev commit "$version"
host_installed=false
user_installed=false
rm -f "$user_backup"
REMOTE

echo "Verifying installed Dadape ARM64 runtime"
"${dadape_ssh[@]}" bash -s -- "$version" "$arm_hash" <<'REMOTE'
set -euo pipefail
version="$1"; expected="$2"
for path in /usr/local/bin/pb /usr/local/libexec/paperboat/pb /home/anvit/.local/bin/pb /home/anvit/pb-dev-"$version"-arm64; do
  test "$(sha256sum "$path" | awk '{print $1}')" = "$expected"
done
/usr/local/bin/pb --version | grep -F "Version $version" >/dev/null
test "$(systemctl --user is-active paperboat-local-daemon.service)" = active
pid="$(systemctl --user show -p MainPID --value paperboat-local-daemon.service)"
test "$pid" -gt 1
case "$(readlink "/proc/$pid/exe")" in
  /usr/local/bin/pb|/home/anvit/.local/bin/pb) ;;
  *) echo "Dadape service is running an unexpected executable" >&2; exit 1 ;;
esac
test "$(sha256sum "/proc/$pid/exe" | awk '{print $1}')" = "$expected"
REMOTE

echo "Uploading and installing Hetzner AMD64"
"${hetzner_scp[@]}" "$build_root/pb-linux-amd64" "$hetzner_target:$hetzner_artifact.new"
"${hetzner_ssh[@]}" bash -s -- "$version" "$amd_hash" "$amd_size" "$hetzner_artifact" <<'REMOTE'
set -euo pipefail
version="$1"; expected="$2"; expected_size="$3"; artifact="$4"
bin=/usr/local/bin/pb
runtime=/usr/local/libexec/paperboat/pb
bin_backup="$bin.rollback-$version"
runtime_backup="$runtime.rollback-$version"
actual="$(sha256sum "$artifact.new" | awk '{print $1}')"
test "$actual" = "$expected" || { echo "Hetzner upload hash mismatch: expected=$expected actual=$actual" >&2; exit 1; }
test "$(stat -c '%s' "$artifact.new")" = "$expected_size" || { echo "Hetzner upload size mismatch" >&2; exit 1; }
test "$(uname -m)" = "x86_64" || { echo "Hetzner target is not AMD64: $(uname -m)" >&2; exit 1; }
mv "$artifact.new" "$artifact"; chmod 0755 "$artifact"
installed=false
finish() {
  status=$?
  trap - EXIT
  set +e
  if test "$status" -ne 0 && test "$installed" = true; then
    mv -f "$bin_backup" "$bin"
    mv -f "$runtime_backup" "$runtime"
  fi
  systemctl start paperboat-runtime-host.service paperboat-runtime-privileged.service
  start_status=$?
  rm -f "$artifact.new"
  if test "$status" -eq 0 && test "$start_status" -ne 0; then
    status=1
  fi
  exit "$status"
}
trap finish EXIT
systemctl stop paperboat-runtime-host.service paperboat-runtime-privileged.service
cp -p "$bin" "$bin_backup"
cp -p "$runtime" "$runtime_backup"
installed=true
install -m 0755 "$artifact" "$bin.installing"
install -m 0755 "$artifact" "$runtime.installing"
mv -f "$bin.installing" "$bin"
mv -f "$runtime.installing" "$runtime"
test "$(sha256sum "$bin" | awk '{print $1}')" = "$expected"
test "$(sha256sum "$runtime" | awk '{print $1}')" = "$expected"
"$bin" --version | grep -F "Version $version" >/dev/null
systemctl start paperboat-runtime-host.service paperboat-runtime-privileged.service
test "$(systemctl is-active paperboat-runtime-host.service)" = active
test "$(systemctl is-active paperboat-runtime-privileged.service)" = active
installed=false
rm -f "$bin_backup" "$runtime_backup"
REMOTE

echo "Verifying installed Hetzner AMD64 runtime"
"${hetzner_ssh[@]}" bash -s -- "$version" "$amd_hash" <<'REMOTE'
set -euo pipefail
version="$1"; expected="$2"
for path in /usr/local/bin/pb /usr/local/libexec/paperboat/pb /root/pb-dev-"$version"-amd64; do
  test "$(sha256sum "$path" | awk '{print $1}')" = "$expected"
done
/usr/local/bin/pb --version | grep -F "Version $version" >/dev/null
for unit in paperboat-runtime-host.service paperboat-runtime-privileged.service; do
  test "$(systemctl is-active "$unit")" = active
  pid="$(systemctl show -p MainPID --value "$unit")"
  test "$pid" -gt 1
  test "$(readlink "/proc/$pid/exe")" = /usr/local/libexec/paperboat/pb
  test "$(sha256sum "/proc/$pid/exe" | awk '{print $1}')" = "$expected"
done
REMOTE

printf 'Installed %s\nDadape ARM64 SHA-256: %s\nHetzner AMD64 SHA-256: %s\n' "$version" "$arm_hash" "$amd_hash"
