#!/usr/bin/env bash
set -euo pipefail

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
workspace_root=$(CDPATH='' cd -- "$repository_root/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-trk35-release.XXXXXX")
temporary=$(CDPATH='' cd -- "$temporary" && pwd)
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT INT TERM

export PAPERBOAT_TUF_CI=1
export PAPERBOAT_GITHUB_REPOSITORY=example/paperboat

roles=(root-1 root-2 root-3 targets-1 targets-2 snapshot-1 timestamp-1)
for index in "${!roles[@]}"; do
  role=${roles[$index]}
  variable="PAPERBOAT_TUF_KEY_$(printf '%s' "$role" | tr '[:lower:].-' '[:upper:]__')"
  seed=$(python3 - "$((index + 1))" <<'PY'
import base64
import sys
print(base64.b64encode(bytes([int(sys.argv[1])]) * 32).decode().rstrip("="))
PY
)
  export "$variable=$seed"
done

version=2026.09.01.999
artifacts="$temporary/artifacts"
tuf_repository="$temporary/tuf-repository"
release_tree="$temporary/release"
mkdir -p "$artifacts" "$release_tree/tuf"

assets=(
  pb-darwin-arm64.pkg
  pb-linux-amd64
  pb-linux-arm64
  pb-windows-amd64.exe
  pb-windows-arm64.exe
)
for name in "${assets[@]}"; do
  printf 'TRK-35 signed release candidate: %s\n' "$name" > "$artifacts/$name"
done

for architecture in amd64 arm64; do
  cat > "$temporary/windows-$architecture.json" <<JSON
{"schema":"paperboat.windows-native-qualification/v1","release_version":"$version","platform":"windows","architecture":"$architecture","status":"passed","native_tested":true,"windows_build":"26100","runner":"windows-$architecture-test"}
JSON
done

manifest="$temporary/manifest.json"
plan="$temporary/deployment-plan.json"
(
  cd "$repository_root"
  go run ./tools/release-plan manifest \
    -version "$version" \
    -source-commit 1111111111111111111111111111111111111111 \
    -toolchain go1.27.1 \
    -artifacts "$artifacts" \
    -output "$manifest"
  go run ./tools/release-plan plan \
    -manifest "$manifest" \
    -policy-revision 999 \
    -severity routine \
    -cohort-seed release-$version \
    -output "$plan"
  go run ./tools/release-plan validate \
    -manifest "$manifest" \
    -plan "$plan" \
    -artifacts "$artifacts"
  go run ./tools/tuf-repository init -repository "$tuf_repository"
  go run ./tools/tuf-repository publish \
    -repository "$tuf_repository" \
    -version "$version" \
    -artifacts "$artifacts" \
    -manifest "$manifest" \
    -deployment-plan "$plan" \
    -windows-amd64-native-evidence "$temporary/windows-amd64.json" \
    -windows-arm64-native-evidence "$temporary/windows-arm64.json" \
    -rollout-revision 999 \
    -severity routine
  go run ./tools/tuf-repository verify-published -repository "$tuf_repository"
)

cp -R "$tuf_repository/metadata" "$tuf_repository/targets" "$release_tree/tuf/"
printf '#!/bin/sh\nexit 0\n' > "$release_tree/install"
printf 'exit 0\r\n' > "$release_tree/windows"
chmod 0755 "$release_tree/install"

python3 - "$release_tree/current.json" "$version" "$artifacts" <<'PY'
import hashlib
import json
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
version = sys.argv[2]
artifacts = pathlib.Path(sys.argv[3])
expected = {
    "pb-darwin-arm64.pkg": ("darwin", "arm64", "pkg"),
    "pb-linux-amd64": ("linux", "amd64", "elf"),
    "pb-linux-arm64": ("linux", "arm64", "elf"),
    "pb-windows-amd64.exe": ("windows", "amd64", "pe"),
    "pb-windows-arm64.exe": ("windows", "arm64", "pe"),
}
assets = {}
for name, (platform, architecture, format_) in expected.items():
    body = (artifacts / name).read_bytes()
    assets[name] = {
        "platform": platform,
        "architecture": architecture,
        "format": format_,
        "url": f"https://github.com/example/paperboat/releases/download/{version}/{name}",
        "sha256": hashlib.sha256(body).hexdigest(),
        "length": len(body),
    }
output.write_text(json.dumps({
    "schema": "paperboat.release-current/v1",
    "version": version,
    "repository": "example/paperboat",
    "assets": assets,
}, separators=(",", ":")) + "\n", encoding="utf-8")
PY

(
  cd "$workspace_root/paperboat-server"
  PAPERBOAT_TRK35_RELEASE_BUNDLE="$release_tree" \
    PAPERBOAT_TRK35_RELEASE_VERSION="$version" \
    GOTOOLCHAIN=go1.27.1 \
    go test -tags trk35_release_candidate ./internal/releases \
      -run '^TestTRK35ExternalBundleReady$' -count=1
  PAPERBOAT_TRK35_RELEASE_BUNDLE="$release_tree" \
    PAPERBOAT_TRK35_RELEASE_VERSION="$version" \
    GOTOOLCHAIN=go1.27.1 \
    go test -race -tags trk35_release_candidate ./internal/releases \
      -run '^TestTRK35ExternalBundleReady$' -count=1
)

tampered="$temporary/tampered-repository"
cp -R "$tuf_repository" "$tampered"
python3 - "$tampered/metadata/targets.json" <<'PY'
import hashlib
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
target = document["signed"]["targets"]["pb-linux-arm64"]
index = target["custom"]["release_index"]
index["deployment_plan"]["rollout_state"] = "paused"
plan = json.dumps(index["deployment_plan"], separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
index["deployment_plan_sha256"] = hashlib.sha256(plan).hexdigest()
path.write_text(json.dumps(document, separators=(",", ":")) + "\n", encoding="utf-8")
PY
if (cd "$repository_root" && go run ./tools/tuf-repository verify-published -repository "$tampered" >/dev/null 2>&1); then
  echo 'signature-invalid coordinated policy mutation was accepted' >&2
  exit 1
fi

echo 'TRK-35 release candidate: publisher, runtime contract, server readiness, and tamper gate passed'
