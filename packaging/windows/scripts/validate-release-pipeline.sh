#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
workflow="$repository_root/.github/workflows/release.yml"
qualification="$repository_root/.github/workflows/platform-qualification.yml"
ci="$repository_root/.github/workflows/ci.yml"
active_signing_state="$repository_root/tools/tuf-repository/active-signing-state.json"
test -f "$workflow"
test -f "$qualification"
test -f "$ci"
test -f "$active_signing_state"

python3 - "$workflow" "$qualification" "$ci" "$active_signing_state" <<'PY'
import json
import pathlib
import sys

release = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
qualification = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
ci = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
active_state_path = pathlib.Path(sys.argv[4])
active_state = json.loads(active_state_path.read_text(encoding="utf-8"))
winget_renderer = (pathlib.Path(sys.argv[1]).parents[2] / "packaging/windows/scripts/render-winget.ps1").read_text(encoding="utf-8")

for required in (
    "release-authority:", "release-linux:", "release-macos:", "release-windows:",
    "runner: blacksmith-2vcpu-ubuntu-2404",
    "runner: blacksmith-2vcpu-ubuntu-2404-arm",
    "runner: blacksmith-2vcpu-windows-2025", "runner: windows-11-arm",
    "architecture: amd64", "architecture: arm64",
    "channel: stable", "windows-winget:",
    "Validate rendered WinGet manifest contract", "validate-winget", "--manifest-directory dist/stable",
    "--amd64-msi $amd64Msi", "--arm64-msi $arm64Msi",
    "candidate-assembly:", "release-publication:",
    "needs: [release-authority, platform-qualification, release-linux, release-macos, release-windows, windows-winget]",
    "release-candidate.json", "release-candidate-${{ env.RELEASE_VERSION }}",
    "actions/attest-build-provenance",
    "PAPERBOAT_TUF_KEY_TARGETS_1", "PAPERBOAT_TUF_KEY_TARGETS_2",
    "PAPERBOAT_TUF_KEY_SNAPSHOT_1", "PAPERBOAT_TUF_KEY_TIMESTAMP_2",
    "validate-signers", "active-signing-state.json", "trusted-root.json",
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
authority_job = release[release.index("  release-authority:"):release.index("  platform-qualification:")]
qualification_job = release[release.index("  platform-qualification:"):release.index("  release-linux:")]
macos_job = release[release.index("  release-macos:"):release.index("  release-windows:")]
windows_job = release[release.index("  release-windows:"):release.index("  windows-winget:")]
assembly_job = release[release.index("  candidate-assembly:"):release.index("  release-publication:")]
winget_job = release[release.index("  windows-winget:"):release.index("  candidate-assembly:")]
publication_job = release[release.index("  release-publication:"):]
expected_active_state = {"schema": "paperboat.tuf-signing-state/v1", "roles": {"root": ["root-1", "root-2", "root-3"], "targets": ["targets-1", "targets-2"], "snapshot": ["snapshot-1"], "timestamp": ["timestamp-2"]}}
manifest_command = 'bash tools/package-manifests.sh dist "${GITHUB_REPOSITORY}" "${RELEASE_VERSION}"'
if active_state != expected_active_state:
    raise SystemExit("active TUF signing state does not match the current root-v2 role aliases")
for name, job in (("platform qualification", qualification_job), ("Linux release", linux_job), ("macOS release", macos_job), ("Windows release", windows_job)):
    if "needs: release-authority" not in job:
        raise SystemExit(f"{name} must wait for protected release authority validation")
for required in ("environment: paperboat-tuf-published", "timeout-minutes: 5", "Validate release version", "release-version.sh validate", "Fetch public current root chain", "PAPERBOAT_DEFAULT_RELEASE_URL", "--proto '=https'", "--max-filesize 1048576", "1 through 64", "Validate online signer authorization", "validate-signers"):
    if required not in authority_job:
        raise SystemExit(f"release authority gate is missing {required!r}")
if authority_job.index("release-version.sh validate") > authority_job.index("Fetch public current root chain") or authority_job.index("release-version.sh validate") > authority_job.index("actions/setup-go@"):
    raise SystemExit("release version validation must run before network/toolchain work in the authority gate")
for forbidden in ("PAPERBOAT_RELEASE_SSH_KEY", "PAPERBOAT_RELEASE_KNOWN_HOSTS", "PAPERBOAT_RELEASE_HOST", "root@$RELEASE_HOST"):
    if forbidden in authority_job:
        raise SystemExit(f"read-only release authority gate must not receive publication credential {forbidden!r}")
if "needs: [release-authority," not in assembly_job or "always()" in assembly_job:
    raise SystemExit("candidate assembly must skip without allocating a runner unless release authority and all handoffs succeed")
for dependency in ("release-authority", "platform-qualification", "release-linux", "release-macos", "release-windows", "windows-winget"):
    if f"needs.{dependency}.result == 'success'" not in assembly_job:
        raise SystemExit(f"candidate assembly must require successful {dependency}")
if "package-manifests.sh" in linux_job:
    raise SystemExit("per-architecture Linux jobs cannot generate a manifest that requires every Unix archive")
if manifest_command not in assembly_job:
    raise SystemExit("candidate assembly must generate the package manifest after downloading every Unix archive")
for forbidden in ("Install-Module", "Repair-WinGetPackageManager", "Add-AppxPackage", "winget.exe"):
    if forbidden in winget_job:
        raise SystemExit(f"WinGet manifest validation must not bootstrap external tooling: {forbidden}")
if "[void]$view.Execute()" not in winget_renderer or "StringData(1)).Trim()" not in winget_renderer or "MSI property $PropertyName is empty" not in winget_renderer:
    raise SystemExit("WinGet renderer must suppress COM output, trim, and validate Windows Installer property values")
if "actions/setup-go@" not in publication_job or publication_job.index("actions/setup-go@") > publication_job.index("Sign and verify production TUF release"):
    raise SystemExit("release publication must set up Go before building the TUF signer")
if 'install -m 0600 tools/tuf-repository/active-signing-state.json "$repository/.signing-state.json"' not in publication_job:
    raise SystemExit("release publication must use the validated active signing-state source")
if "PAPERBOAT_TUF_KEY_TIMESTAMP_1" in publication_job:
    raise SystemExit("release publication must not use the revoked root-v1 timestamp key")
publication_validate = publication_job.index('"$signer" validate-signers')
publication_publish = publication_job.index('"$signer" publish')
publication_fetch = publication_job.index("Fetch current production TUF repository")
if publication_validate < publication_fetch or publication_validate > publication_publish or "internal/hostruntime/bootstrap/trusted-root.json" not in publication_job[publication_validate:publication_publish]:
    raise SystemExit("release publication must revalidate its freshly fetched root chain immediately before signing")

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
