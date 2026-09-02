#!/bin/sh
set -eu

# Deterministic MAC-003 regression: a fresh pair process can create user state
# and then fail. The installer must keep control of the child process, remove
# that state, and remove the exact requested payload path before returning the
# original exit status.
repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
installer="$repository_root/tools/install.sh"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-pair-rollback.XXXXXX")
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
cat > "$temporary/bin/id" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -u) echo 1000 ;;
  *) exec /usr/bin/id "$@" ;;
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
case "$url" in
  https://release.example/current.json)
    body='{"schema":"paperboat.release-current/v1","version":"2026.09.03.4","repository":"example/paperboat-cli","assets":{"pb-linux-amd64":{"platform":"linux","architecture":"amd64","format":"elf","url":"https://github.com/example/paperboat-cli/releases/download/2026.09.03.4/pb-linux-amd64","sha256":"fa015e4084b08bebc97cb584af702c5f1d81f69e9e0001939aecc0e787d7dfa8","length":91}}}'
    ;;
  https://github.com/example/paperboat-cli/releases/download/2026.09.03.4/pb-linux-amd64)
    body='#!/bin/sh
mkdir -p "$HOME/.paperboat/state"
touch "$HOME/.paperboat/state/created"
exit 42'
    ;;
  *) echo "unexpected curl URL: $url" >&2; exit 1 ;;
esac
printf '%s\n' "$body" > "$output"
EOF
cat > "$temporary/bin/sudo" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = -n ]; then shift; fi
case "${1:-}" in
  true) exit 0 ;;
esac
"$@"
EOF
cat > "$temporary/bin/systemctl" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0700 "$temporary/bin/uname" "$temporary/bin/id" "$temporary/bin/curl" "$temporary/bin/sudo" "$temporary/bin/systemctl"

if HOME="$temporary/home" \
  PATH="$temporary/bin:/usr/bin:/bin" \
  PAPERBOAT_RELEASE_METADATA_URL=https://release.example/current.json \
  PAPERBOAT_GITHUB_REPOSITORY=example/paperboat-cli \
  PAPERBOAT_INSTALL_DIR="$temporary/install" \
  "$installer" --pair --enrollment-token AAAAAAAAAAAAAAAAAAAAAAAAAA \
  >"$temporary/output" 2>"$temporary/error"; then
  echo 'pair rollback test expected the fake pair command to fail' >&2
  exit 1
else
  status=$?
fi

test "$status" -eq 42 || { echo "pair returned $status, want 42" >&2; exit 1; }
test ! -e "$temporary/install/pb" || { echo 'failed pair left the requested payload' >&2; exit 1; }
test ! -e "$temporary/home/.paperboat/state/created" || { echo 'failed pair left user state' >&2; exit 1; }
grep -q 'rolling back the fresh installation' "$temporary/error"

echo 'fresh pair rollback: ok'
