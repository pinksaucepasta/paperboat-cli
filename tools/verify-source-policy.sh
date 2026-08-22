#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

metadata_files=$(find . -path './.git' -prune -o -type f \( -name '._*' -o -name '.DS_Store' \) -print)
if [ -n "$metadata_files" ]; then
	printf 'source-metadata: macOS metadata files are not allowed:\n%s\n' "$metadata_files" >&2
	exit 1
fi

check() {
	rule=$1
	pattern=$2
	matches=$(rg -n --no-heading --glob '*.go' --glob '!**/*_test.go' "$pattern" . || true)
	[ -z "$matches" ] && return 0
	violations=$(printf '%s\n' "$matches" | while IFS=: read -r file line rest; do
		previous=$((line - 1))
		annotation=$(sed -n "${previous}p" "$file")
		if ! printf '%s\n' "$annotation" | rg -q "^[[:space:]]*//paperboat:allow-source-policy $rule owner=[^[:space:]]+ reason=[^[:space:]]+$"; then
			echo "$rule: unreviewed occurrence at ${file#./}:$line"
		fi
	done)
	[ -z "$violations" ] || { printf '%s\n' "$violations" >&2; return 1; }
}

check sleep '\btime\.Sleep\('
check proxy-header 'Header\.(Get|Values)\("(Forwarded|X-Forwarded-For|X-Real-IP|Fly-Client-IP)"'
check default-http 'http\.Default(Client|Transport)'
check sensitive-log '(slog\.|log\.(Print|Printf|Println))[^\n]*(candidate|payload|credential|token|private.?key)'
check metric-label 'WithLabelValues\('
check tailscale-import '"tailscale\.com/'
check raw-peercred 'Getsockopt(Ucred|Xucred)|SO_PEERCRED|LOCAL_PEERCRED'
check raw-user-path 'os\.User(Config|Cache)Dir\('
check atomic-replacement 'os\.CreateTemp\(|os\.Rename\('
