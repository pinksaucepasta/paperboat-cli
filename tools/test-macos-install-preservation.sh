#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
installer="$repository_root/tools/install.sh"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-macos-install.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
mkdir -p "$temporary/bin" "$temporary/home" "$temporary/state"

cat > "$temporary/bin/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -s) echo Darwin ;;
  -m) echo arm64 ;;
  *) exit 2 ;;
esac
EOF
cat > "$temporary/bin/curl" <<'EOF'
#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|--output) output=$2; shift 2 ;;
    --proto|--retry|--retry-delay|--connect-timeout|--max-time) shift 2 ;;
    --*) shift ;;
    *) url=$1; shift ;;
  esac
done
printf '%s\n' "$url" >> "$PAPERBOAT_TEST_CURL_LOG"
case "$url" in
  https://release.example/current.json)
    body='{"schema":"paperboat.release-current/v1","version":"2026.09.02.0","repository":"example/paperboat-cli","assets":{"pb-darwin-arm64.pkg":{"platform":"darwin","architecture":"arm64","format":"pkg","url":"https://github.com/example/paperboat-cli/releases/download/2026.09.02.0/pb-darwin-arm64.pkg","sha256":"f238df2ae16f95a3461bb262b8db52df5808bb03a6f2d85471442835bb31c65b","length":4}}}'
    ;;
  https://github.com/example/paperboat-cli/releases/download/2026.09.02.0/pb-darwin-arm64.pkg)
    body='pkg'
    ;;
  *) echo "unexpected curl URL: $url" >&2; exit 1 ;;
esac
if [ -n "$output" ]; then
  printf '%s\n' "$body" > "$output"
else
  printf '%s\n' "$body"
fi
EOF
cat > "$temporary/bin/id" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -u) echo 1000 ;;
  *) exec /usr/bin/id "$@" ;;
esac
EOF
cat > "$temporary/bin/launchctl" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$PAPERBOAT_TEST_LAUNCHCTL_LOG"
for argument do
  case "$argument" in
    system/com.pinksaucepasta.paperboat.hostd) /bin/rm -f "$PAPERBOAT_TEST_STATE/hostd.plist" ;;
    system/com.pinksaucepasta.paperboat.updated) /bin/rm -f "$PAPERBOAT_TEST_STATE/updated.plist" ;;
  esac
done
exit 0
EOF
cat > "$temporary/bin/rm" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$PAPERBOAT_TEST_RM_LOG"
protected=false
for argument do
  case "$argument" in
    /Library/LaunchDaemons/com.pinksaucepasta.paperboat.hostd.plist|/Library/LaunchDaemons/com.pinksaucepasta.paperboat.updated.plist|/Library/PrivilegedHelperTools/Paperboat|/Library/Application\ Support/Paperboat|/usr/local/bin/pb|/usr/local/libexec/paperboat/pb|/var/run/paperboat-hostd/hostd.sock|/var/run/paperboat-updated/control.sock)
      protected=true
      ;;
  esac
done
if [ "$protected" = true ]; then
  for argument do
    case "$argument" in
      /Library/LaunchDaemons/com.pinksaucepasta.paperboat.hostd.plist) /bin/rm -f "$PAPERBOAT_TEST_STATE/hostd.plist" ;;
      /Library/LaunchDaemons/com.pinksaucepasta.paperboat.updated.plist) /bin/rm -f "$PAPERBOAT_TEST_STATE/updated.plist" ;;
      /Library/PrivilegedHelperTools/Paperboat) /bin/rm -rf "$PAPERBOAT_TEST_STATE/helper" ;;
      /Library/Application\ Support/Paperboat) /bin/rm -rf "$PAPERBOAT_TEST_STATE/application-support" ;;
      /usr/local/bin/pb) /bin/rm -f "$PAPERBOAT_TEST_STATE/cli" ;;
      /usr/local/libexec/paperboat/pb) /bin/rm -f "$PAPERBOAT_TEST_STATE/legacy-helper" ;;
      /var/run/paperboat-hostd/hostd.sock) /bin/rm -f "$PAPERBOAT_TEST_STATE/hostd.sock" ;;
      /var/run/paperboat-updated/control.sock) /bin/rm -f "$PAPERBOAT_TEST_STATE/updated.sock" ;;
    esac
  done
  exit 0
fi
exec /bin/rm "$@"
EOF
cat > "$temporary/bin/sudo" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$PAPERBOAT_TEST_SUDO_LOG"
if [ "${1:-}" = -n ]; then
  shift
fi
case "${1:-}" in
  true) exit 0 ;;
  launchctl) exec "$PAPERBOAT_TEST_FAKE_BIN/launchctl" "$@" ;;
  rm) exec "$PAPERBOAT_TEST_FAKE_BIN/rm" "$@" ;;
  installer) exit 97 ;;
  *) echo "unexpected sudo command: $*" >&2; exit 1 ;;
esac
EOF
chmod 0700 "$temporary/bin/uname" "$temporary/bin/curl" "$temporary/bin/id" "$temporary/bin/launchctl" "$temporary/bin/rm" "$temporary/bin/sudo"

export PAPERBOAT_TEST_STATE="$temporary/state"
export PAPERBOAT_TEST_FAKE_BIN="$temporary/bin"

seed_managed_state() {
  /bin/rm -rf "$PAPERBOAT_TEST_STATE"
  mkdir -p "$PAPERBOAT_TEST_STATE/helper" "$PAPERBOAT_TEST_STATE/application-support"
  touch "$PAPERBOAT_TEST_STATE/hostd.plist" "$PAPERBOAT_TEST_STATE/updated.plist" \
    "$PAPERBOAT_TEST_STATE/helper/pb" "$PAPERBOAT_TEST_STATE/application-support/config" \
    "$PAPERBOAT_TEST_STATE/cli" "$PAPERBOAT_TEST_STATE/legacy-helper" \
    "$PAPERBOAT_TEST_STATE/hostd.sock" "$PAPERBOAT_TEST_STATE/updated.sock"
}

run_installer() {
  scenario=$1
  shift
  PAPERBOAT_TEST_CURL_LOG="$temporary/$scenario-curl.log" \
  PAPERBOAT_TEST_LAUNCHCTL_LOG="$temporary/$scenario-launchctl.log" \
  PAPERBOAT_TEST_RM_LOG="$temporary/$scenario-rm.log" \
  PAPERBOAT_TEST_SUDO_LOG="$temporary/$scenario-sudo.log" \
  PAPERBOAT_RELEASE_METADATA_URL=https://release.example/current.json \
  PAPERBOAT_GITHUB_REPOSITORY=example/paperboat-cli \
  PAPERBOAT_INSTALL_DIR="$temporary/install-$scenario" \
  HOME="$temporary/home" \
  PATH="$temporary/bin:/usr/bin:/bin" \
  "$installer" "$@" >"$temporary/$scenario-output" 2>"$temporary/$scenario-error"
}

seed_managed_state
if run_installer install-only; then
  echo 'install-only test expected the fake package installer to fail' >&2
  exit 1
fi
for marker in hostd.plist updated.plist cli legacy-helper hostd.sock updated.sock; do
  test -e "$PAPERBOAT_TEST_STATE/$marker" || { echo "install-only removed $marker" >&2; exit 1; }
done
test -d "$PAPERBOAT_TEST_STATE/helper"
test -f "$PAPERBOAT_TEST_STATE/helper/pb"
test -d "$PAPERBOAT_TEST_STATE/application-support"
test -f "$PAPERBOAT_TEST_STATE/application-support/config"
if grep -Eq 'launchctl bootout|com\.pinksaucepasta\.paperboat\.(hostd|updated)|/Library/PrivilegedHelperTools/Paperboat|/Library/Application Support/Paperboat|/var/run/paperboat-(hostd|updated)|/usr/local/bin/pb' "$temporary/install-only-sudo.log" "$temporary/install-only-rm.log" "$temporary/install-only-launchctl.log" 2>/dev/null; then
  echo 'install-only called macOS service cleanup' >&2
  exit 1
fi

seed_managed_state
if run_installer explicit-setup --setup client; then
  echo 'explicit setup test expected the fake package installer to fail' >&2
  exit 1
fi
grep -q 'launchctl bootout system/com.pinksaucepasta.paperboat.hostd' "$temporary/explicit-setup-sudo.log"
grep -q 'launchctl bootout system/com.pinksaucepasta.paperboat.updated' "$temporary/explicit-setup-sudo.log"
grep -q '/Library/LaunchDaemons/com.pinksaucepasta.paperboat.hostd.plist' "$temporary/explicit-setup-sudo.log"
grep -q '/Library/LaunchDaemons/com.pinksaucepasta.paperboat.updated.plist' "$temporary/explicit-setup-sudo.log"
test ! -e "$PAPERBOAT_TEST_STATE/hostd.plist"
test ! -e "$PAPERBOAT_TEST_STATE/updated.plist"
test ! -e "$PAPERBOAT_TEST_STATE/helper"
test ! -e "$PAPERBOAT_TEST_STATE/application-support"

echo 'macOS install preservation: ok'
