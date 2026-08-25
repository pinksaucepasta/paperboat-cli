#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-release-version.XXXXXX")
trap 'rm -rf "$fixture"' EXIT HUP INT TERM

mkdir "$fixture/tools"
cp "$repository_root/tools/release-version.sh" "$fixture/tools/release-version.sh"
git -C "$fixture" init -q
git -C "$fixture" config user.email paperboat-release-version@test.invalid
git -C "$fixture" config user.name paperboat-release-version-test
git -C "$fixture" add tools/release-version.sh
git -C "$fixture" commit -qm fixture

git -C "$fixture" tag 2026.08.25.0
"$fixture/tools/release-version.sh" validate 2026.08.25.0

git -C "$fixture" tag -d 2026.08.25.0 >/dev/null
git -C "$fixture" tag 2026.08.25.1
if "$fixture/tools/release-version.sh" validate 2026.08.25.1 >"$fixture/stdout" 2>"$fixture/stderr"; then
	echo 'release version validation accepted .1 without the required new-day .0 tag' >&2
	exit 1
fi
grep -F 'missing release tag 2026.08.25.0' "$fixture/stderr" >/dev/null
