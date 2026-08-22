#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
workflow="$repository_root/.github/workflows/release.yml"
qualification="$repository_root/.github/workflows/platform-qualification.yml"
ci="$repository_root/.github/workflows/ci.yml"
test -f "$workflow"
test -f "$qualification"
test -f "$ci"

python3 - "$workflow" "$qualification" "$ci" <<'PY'
import pathlib
import sys

release = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
qualification = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
ci = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
winget_renderer = (pathlib.Path(sys.argv[1]).parents[2] / "packaging/windows/scripts/render-winget.ps1").read_text(encoding="utf-8")

for required in (
    "release-linux:", "release-macos:", "release-windows:",
    "runner: blacksmith-2vcpu-ubuntu-2404",
    "runner: blacksmith-2vcpu-ubuntu-2404-arm",
    "runner: blacksmith-2vcpu-windows-2025", "runner: windows-11-arm",
    "architecture: amd64", "architecture: arm64",
    "channel: stable", "windows-winget:",
    "Validate rendered WinGet manifest contract", "validate-winget", "--manifest-directory dist/stable",
    "--amd64-msi $amd64Msi", "--arm64-msi $arm64Msi",
    "candidate-assembly:", "release-publication:",
    "needs: [platform-qualification, release-linux, release-macos, release-windows, windows-winget]",
    "release-candidate.json", "release-candidate-${{ env.RELEASE_VERSION }}",
    "actions/attest-build-provenance",
    "PAPERBOAT_TUF_KEY_TARGETS_1", "PAPERBOAT_TUF_KEY_TARGETS_2",
    "PAPERBOAT_TUF_KEY_SNAPSHOT_1", "PAPERBOAT_TUF_KEY_TIMESTAMP_1",
    "paperboat-tuf", "publish-tuf-origin.sh", "PAPERBOAT_RELEASE_SSH_KEY",
    "windows-amd64-native-qualification.json", "windows-arm64-native-qualification.json",
    "Publish immutable GitHub release assets", "Atomically publish TUF and current.json to Hetzner",
    "Verify public updater and current release", "Mark verified GitHub release latest",
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
    "actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
):
    if required not in release:
        raise SystemExit(f"release workflow is missing {required!r}")

for required in (
    "workflow_call:", "platform-contract:",
    "runner: blacksmith-2vcpu-ubuntu-2404",
    "runner: blacksmith-2vcpu-ubuntu-2404-arm",
    "runner: blacksmith-6vcpu-macos-latest",
    "runner: blacksmith-2vcpu-windows-2025", "runner: windows-11-arm",
    "architecture: amd64", "architecture: arm64",
    'actual="$(go env GOOS)/$(go env GOARCH)"',
):
    if required not in qualification:
        raise SystemExit(f"platform qualification is missing {required!r}")

qualification_triggers = qualification[qualification.index("on:"):qualification.index("permissions:")]
if "pull_request:" in qualification_triggers or "push:" in qualification_triggers:
    raise SystemExit("native platform qualification must run from the tag release workflow or explicit manual dispatch only")

ci_triggers = ci[ci.index("on:"):ci.index("permissions:")]
if "pull_request:" not in ci_triggers or "push:" in ci_triggers:
    raise SystemExit("CI must validate pull requests without duplicating the locally preflighted main push")

if "qemu" in release.lower() or "qemu" in qualification.lower():
    raise SystemExit("release workflows must not use QEMU")
if "publish-release.yml" in release or "update-assurance.yml" in release:
    raise SystemExit("release workflow references a deleted workflow")

linux_job = release[release.index("  release-linux:"):release.index("  release-macos:")]
assembly_job = release[release.index("  candidate-assembly:"):release.index("  release-publication:")]
winget_job = release[release.index("  windows-winget:"):release.index("  candidate-assembly:")]
manifest_command = 'bash tools/package-manifests.sh dist "${GITHUB_REPOSITORY}" "${RELEASE_VERSION}"'
if "package-manifests.sh" in linux_job:
    raise SystemExit("per-architecture Linux jobs cannot generate a manifest that requires every Unix archive")
if manifest_command not in assembly_job:
    raise SystemExit("candidate assembly must generate the package manifest after downloading every Unix archive")
for forbidden in ("Install-Module", "Repair-WinGetPackageManager", "Add-AppxPackage", "winget.exe"):
    if forbidden in winget_job:
        raise SystemExit(f"WinGet manifest validation must not bootstrap external tooling: {forbidden}")
if "[void]$view.Execute()" not in winget_renderer or "StringData(1)).Trim()" not in winget_renderer or "MSI property $PropertyName is empty" not in winget_renderer:
    raise SystemExit("WinGet renderer must suppress COM output, trim, and validate Windows Installer property values")

ordered = (
    "Publish immutable GitHub release assets",
    "Sign and verify production TUF release",
    "Atomically publish TUF and current.json to Hetzner",
    "Verify public updater and current release",
    "Mark verified GitHub release latest",
)
positions = [release.index(item) for item in ordered]
if positions != sorted(positions):
    raise SystemExit("release publication transaction is out of order")
PY

for script in "$(dirname -- "$0")"/*.sh; do sh -n "$script"; done
