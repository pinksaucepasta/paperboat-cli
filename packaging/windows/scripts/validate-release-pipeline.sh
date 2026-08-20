#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/../../.." && pwd)
workflow="$repository_root/.github/workflows/release.yml"

test -f "$workflow"

if command -v rg >/dev/null 2>&1; then
    text_search() { rg "$@"; }
    fixed_search() { rg -F "$@"; }
else
    text_search() { grep -R "$@"; }
    fixed_search() { grep -R -F "$@"; }
fi

require_text() {
    needle=$1
    if ! fixed_search -- "$needle" "$workflow" >/dev/null; then
        echo "release workflow is missing: $needle" >&2
        exit 1
    fi
}

require_text 'runs-on: windows-2025'
require_text 'architecture: amd64'
require_text 'architecture: arm64'
require_text 'channel: stable'
require_text 'channel: beta'
require_text 'dotnet tool install --global wix --version 5.0.2'
require_text 'sign-and-verify.ps1'
require_text 'generate-signing-handoff.ps1'
require_text 'render-winget.ps1'
require_text 'actions/upload-artifact'
require_text 'actions/download-artifact'
require_text 'actions/attest-build-provenance'
require_text 'merge-signing-manifests.py'
require_text 'pb-windows-{0}.exe'
require_text 'convert-native-qualification-evidence.py'
require_text 'windows-amd64-native-qualification'
require_text 'windows-amd64-native-release-qualification'
require_text 'needs: [release-unix, windows-package, windows-winget, windows-amd64-native-qualification]'

if text_search -n "Add-WindowsCapability|winget install ['\"]openssh preview|for target in .*windows/" "$workflow" >/dev/null; then
    echo 'release workflow contains a forbidden Windows packaging path' >&2
    exit 1
fi

python_command=python3
if ! command -v "$python_command" >/dev/null 2>&1; then
    python_command=python
fi
"$python_command" - "$workflow" <<'PY'
import pathlib
import re
import sys

workflow = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")

def job(name: str) -> str:
    match = re.search(rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:|\Z)", workflow, re.MULTILINE | re.DOTALL)
    if not match:
        raise SystemExit(f"missing job {name}")
    return match.group("body")

unix = job("release-unix")
if "runs-on: ubuntu-latest" not in unix:
    raise SystemExit("release-unix must run on Ubuntu")
for forbidden in ("windows/amd64", "windows/arm64", "package-zip", "paperboat_.*windows"):
    if re.search(forbidden, unix):
        raise SystemExit(f"release-unix still owns Windows assets: {forbidden}")

windows = job("windows-package")
if "runs-on: windows-2025" not in windows:
    raise SystemExit("windows-package must run natively on windows-2025")
if "stable" not in windows or "beta" not in windows:
    raise SystemExit("windows-package must declare stable and beta channels")

publication = job("publication")
if "if: always()" not in publication:
    raise SystemExit("publication must run its explicit dependency gate")
if "needs: [release-unix, windows-package, windows-winget, windows-amd64-native-qualification]" not in workflow:
    raise SystemExit("publication dependencies do not include all Windows handoffs")
if "windows-amd64-native-qualification.result" not in publication:
    raise SystemExit("publication does not gate on native Windows amd64 qualification")
if "--verify-evidence native-qualification/windows-amd64-native-qualification.json" not in publication:
    raise SystemExit("publication does not verify native qualification against final signed artifacts")
if "paperboat-tuf-published" not in publication or "TestProductionTUFRepository" not in publication:
    raise SystemExit("publication is not blocked on public offline-signed TUF metadata")

qualification = job("windows-amd64-native-qualification")
if "needs: windows-package" not in qualification or "runner: windows-2025" not in qualification or "runner: [self-hosted, windows, amd64, paperboat-windows-11-iot-ltsc]" not in qualification or "runs-on: ${{ matrix.runner }}" not in qualification:
    raise SystemExit("native Windows amd64 qualification must consume the signed package on standard Windows 11 and the registered IoT LTSC runner")
for required in (
    "Invoke-NativeWindowsQualification.ps1",
    "convert-native-qualification-evidence.py",
    "--artifacts-dir (Join-Path $env:GITHUB_WORKSPACE 'input')",
    "windows-amd64-native-release-qualification",
):
    if required not in qualification:
        raise SystemExit(f"native Windows amd64 qualification is missing {required}")
PY

"$python_command" "$script_directory/test_convert_native_qualification_evidence.py"

for script in "$script_directory"/*.sh; do
    sh -n "$script"
done

if command -v pwsh >/dev/null 2>&1; then
    for script in "$script_directory"/*.ps1; do
        pwsh -NoLogo -NoProfile -NonInteractive -Command \
            '$path = $args[0]; [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)' \
            -- "$script"
    done
fi

if text_search -n 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|PAPERBOAT_WINDOWS_SIGNING_PFX_B64[[:space:]]*=' "$repository_root/packaging/windows/scripts" >/dev/null; then
    echo 'Windows packaging scripts contain private key material or an assigned PFX secret' >&2
    exit 1
fi

echo 'Windows release pipeline contract and script syntax are valid.'
