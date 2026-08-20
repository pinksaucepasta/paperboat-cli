#!/bin/sh

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/../../.." && pwd)
resource_compiler=${PAPERBOAT_RC:-llvm-rc}
resource_converter=${PAPERBOAT_CVTRES:-llvm-cvtres}
resource_directory="$repository_root/packaging/windows/resources"
resource_temp=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-manifest.XXXXXX")

cleanup() {
	rm -f "$resource_temp/paperboat.res" "$resource_temp/paperboat-amd64.syso" "$resource_temp/paperboat-arm64.syso"
	rmdir "$resource_temp" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

command -v "$resource_compiler" >/dev/null 2>&1 || {
	echo "resource compiler not found: $resource_compiler" >&2
	exit 1
}
command -v "$resource_converter" >/dev/null 2>&1 || {
	echo "resource converter not found: $resource_converter" >&2
	exit 1
}

(CDPATH= cd -- "$resource_directory" && "$resource_compiler" /fo "$resource_temp/paperboat.res" paperboat.rc)
"$resource_converter" /MACHINE:X64 /OUT:"$resource_temp/paperboat-amd64.syso" "$resource_temp/paperboat.res"
"$resource_converter" /MACHINE:ARM64 /OUT:"$resource_temp/paperboat-arm64.syso" "$resource_temp/paperboat.res"

for package_directory in "$repository_root/cmd/pb" "$repository_root/cmd/pb-launcher"; do
	cp "$resource_temp/paperboat-amd64.syso" "$package_directory/windows_manifest_windows_amd64.syso"
	cp "$resource_temp/paperboat-arm64.syso" "$package_directory/windows_manifest_windows_arm64.syso"
done
