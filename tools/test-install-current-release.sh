#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
installer="$repository_root/tools/install.sh"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-install-current.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
mkdir -p "$temporary/bin" "$temporary/home"

cat > "$temporary/bin/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -s) echo Linux ;;
  -m) echo x86_64 ;;
  *) exit 2 ;;
esac
EOF
cat > "$temporary/bin/curl" <<'EOF'
#!/bin/sh
set -eu
output=
last=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|--output) output=$2; shift 2 ;;
    *) last=$1; shift ;;
  esac
done
printf '%s\n' "$last" >> "$PAPERBOAT_TEST_CURL_LOG"
  case "$last" in
  https://release.example/current.json)
    body='{"schema":"paperboat.release-current/v1","version":"2026.08.22.23","repository":"example/paperboat-cli","assets":{"pb-darwin-arm64.pkg":{"platform":"darwin","architecture":"arm64","format":"pkg","url":"https://github.com/example/paperboat-cli/releases/download/2026.08.22.23/pb-darwin-arm64.pkg","sha256":"0000000000000000000000000000000000000000000000000000000000000000","length":1},"pb-linux-amd64":{"platform":"linux","architecture":"amd64","format":"elf","url":"https://github.com/example/paperboat-cli/releases/download/2026.08.22.23/pb-linux-amd64","sha256":"c50bc50bd29910b420d0ce8606bd34caab06e2904bd3f709bce65b2ecb74f1df","length":30},"pb-linux-arm64":{"platform":"linux","architecture":"arm64","format":"elf","url":"https://github.com/example/paperboat-cli/releases/download/2026.08.22.23/pb-linux-arm64","sha256":"0000000000000000000000000000000000000000000000000000000000000000","length":1},"pb-windows-amd64.exe":{"platform":"windows","architecture":"amd64","format":"pe","url":"https://github.com/example/paperboat-cli/releases/download/2026.08.22.23/pb-windows-amd64.exe","sha256":"0000000000000000000000000000000000000000000000000000000000000000","length":1},"pb-windows-arm64.exe":{"platform":"windows","architecture":"arm64","format":"pe","url":"https://github.com/example/paperboat-cli/releases/download/2026.08.22.23/pb-windows-arm64.exe","sha256":"0000000000000000000000000000000000000000000000000000000000000000","length":1}}}'
    ;;
https://github.com/example/paperboat-cli/releases/download/2026.08.22.23/pb-linux-amd64)
    body='#!/bin/sh
echo paperboat-test'
    ;;
  *) echo "unexpected curl URL: $last" >&2; exit 1 ;;
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
cat > "$temporary/bin/sudo" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$PAPERBOAT_TEST_SUDO_LOG"
case "${1:-}" in
  -n)
    shift
    [ "${1:-}" = true ] && exit 0
    ;;
esac
"$@"
EOF
cat > "$temporary/bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$PAPERBOAT_TEST_SYSTEMCTL_LOG"
exit 0
EOF
cat > "$temporary/bin/rm" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$PAPERBOAT_TEST_RM_LOG"
for argument do
  case "$argument" in
    /usr/local/bin/pb|/usr/local/libexec/paperboat/pb)
      echo "rm: cannot remove $argument: Permission denied" >&2
      exit 1
      ;;
  esac
done
exec /bin/rm "$@"
EOF
chmod 0700 "$temporary/bin/uname" "$temporary/bin/curl" "$temporary/bin/id" "$temporary/bin/sudo" "$temporary/bin/systemctl" "$temporary/bin/rm"

PAPERBOAT_TEST_CURL_LOG="$temporary/curl.log" \
PAPERBOAT_TEST_RM_LOG="$temporary/rm.log" \
PAPERBOAT_TEST_SUDO_LOG="$temporary/sudo.log" \
PAPERBOAT_TEST_SYSTEMCTL_LOG="$temporary/systemctl.log" \
PAPERBOAT_RELEASE_METADATA_URL=https://release.example/current.json \
PAPERBOAT_GITHUB_REPOSITORY=example/paperboat-cli \
PAPERBOAT_INSTALL_DIR="$temporary/install" \
HOME="$temporary/home" \
PATH="$temporary/bin:/usr/bin:/bin" \
"$installer" >"$temporary/output" 2>"$temporary/error"

grep -qx 'https://release.example/current.json' "$temporary/curl.log"
grep -qx 'https://github.com/example/paperboat-cli/releases/download/2026.08.22.23/pb-linux-amd64' "$temporary/curl.log"
if grep -q '/releases/latest' "$temporary/curl.log"; then
  echo 'installer resolved GitHub latest instead of current.json' >&2
  exit 1
fi
grep -qx 'paperboat-test' "$temporary/output"
if { test -s "$temporary/sudo.log" && grep -vq '^\(-n true\|installer -pkg .* -target /\)$' "$temporary/sudo.log"; } || test -s "$temporary/systemctl.log"; then
  echo 'install-only upgrade mutated enrolled runtime or service state' >&2
  exit 1
fi

if PAPERBOAT_RELEASE_METADATA_URL=http://release.example/current.json PATH="$temporary/bin:/usr/bin:/bin" "$installer" >/dev/null 2>"$temporary/insecure-error"; then
  echo 'installer accepted an insecure release metadata URL' >&2
  exit 1
fi
grep -q 'release metadata URL must use HTTPS' "$temporary/insecure-error"
