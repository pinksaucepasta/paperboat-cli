#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
workflow="$repository_root/.github/workflows/release.yml"
qualification="$repository_root/.github/workflows/platform-qualification.yml"
ci="$repository_root/.github/workflows/ci.yml"
active_signing_state="$repository_root/tools/tuf-repository/active-signing-state.json"
installer="$repository_root/tools/install.sh"
windows_installer="$repository_root/tools/install.ps1"
publisher="$repository_root/tools/publish-tuf-origin.sh"
checksum_generator="$repository_root/tools/generate-release-checksums.sh"
checksum_test="$repository_root/tools/test-install-checksums.sh"
current_release_test="$repository_root/tools/test-install-current-release.sh"
publisher_test="$repository_root/tools/test-publish-tuf-origin.sh"
manifest_generator="$repository_root/tools/package-manifests.sh"
manifest_test="$repository_root/tools/test-package-manifests.sh"
test -f "$workflow"
test -f "$qualification"
test -f "$ci"
test -f "$active_signing_state"
test -f "$installer"
test -f "$windows_installer"
test -f "$publisher"
test -f "$checksum_generator"
test -f "$checksum_test"
test -f "$current_release_test"
test -f "$publisher_test"
test -f "$manifest_generator"
test -f "$manifest_test"

python3 - "$workflow" "$qualification" "$ci" "$active_signing_state" "$installer" "$windows_installer" "$publisher" <<'PY'
import json
import pathlib
import sys

release = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
qualification = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
ci = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
active_state_path = pathlib.Path(sys.argv[4])
active_state = json.loads(active_state_path.read_text(encoding="utf-8"))
installer = pathlib.Path(sys.argv[5]).read_text(encoding="utf-8")
installer_path = pathlib.Path(sys.argv[5])
windows_installer_path = pathlib.Path(sys.argv[6])
windows_installer = windows_installer_path.read_text(encoding="utf-8")
publisher = pathlib.Path(sys.argv[7]).read_text(encoding="utf-8")
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
    "Publish immutable GitHub release assets", "Download and verify immutable GitHub release bytes",
    "Assemble isolated release origin", "Verify staged release consumers before activation",
    "Mark verified GitHub release latest", "Activate verified release atomically on Hetzner",
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
for required in ('"dist/pb-${os}-${arch}"', '"dist/pb-darwin-arm64"', '("pb-windows-{0}.exe" -f $env:PAPERBOAT_ARCH)'):
    if required not in release:
        raise SystemExit(f"release workflow is missing direct installer asset {required!r}")
for required in ("--setup MODE               Run setup after install: client or host", "--setup client", '""|client|host)'):
    if required not in installer:
        raise SystemExit(f"installer is missing canonical setup contract {required!r}")
for forbidden in ("--setup receive", "receive, session, or host", '""|receive|session|host)'):
    if forbidden in installer:
        raise SystemExit(f"installer retains retired setup vocabulary {forbidden!r}")
for required in ("$role = if", "{ 'host' } else { 'client' }", "$setupMode = $role", '"--setup-mode=$setupMode"', 'pb-windows-$arch.exe'):
    if required not in windows_installer:
        raise SystemExit(f"Windows installer is missing canonical enrollment contract {required!r}")
for forbidden in ("{ 'receive' }", "{ 'session' }", "--setup-mode=receive", "--setup-mode=session"):
    if forbidden in windows_installer:
        raise SystemExit(f"Windows installer retains retired setup-mode mapping {forbidden!r}")
sibling_server_installer = windows_installer_path.parents[2] / "paperboat-server/deploy/releases/windows"
if sibling_server_installer.is_file() and sibling_server_installer.read_bytes() != windows_installer_path.read_bytes():
    raise SystemExit("client-owned Windows installer differs from the checked-out server compatibility copy")
sibling_server_posix_installer = installer_path.parents[2] / "paperboat-server/deploy/releases/install"
if sibling_server_posix_installer.is_file() and sibling_server_posix_installer.read_bytes() != installer_path.read_bytes():
    raise SystemExit("client-owned POSIX installer differs from the checked-out server compatibility copy")
for required in ("install -m 0755 tools/install.sh dist/install.sh", "install -m 0644 tools/install.ps1 dist/install.ps1", 'install -m 0644 "$PAPERBOAT_GITHUB_RELEASE_ASSETS/install.ps1" "$publish/windows"', 'tar -C "$publish" -czf "$bundle" current.json install windows tuf', "dist/install.ps1", "GitHub release asset differs from the immutable candidate"):
    if required not in release:
        raise SystemExit(f"release workflow does not carry Windows installer contract {required!r}")
for required in ("atomic_exchange", "renameat2", "current.json", "verify_live_mount_contract", "/opt/paperboat/releases", "/srv/paperboat-releases", "docker inspect", "pre-activation cleanup", "atomic_exchange \"$live\" \"$next\""):
    if required not in publisher:
        raise SystemExit(f"release publisher is missing transaction contract {required!r}")
if "rollback" in publisher:
    raise SystemExit("release publisher must never roll back an observed TUF timestamp")
for required in ("environment: paperboat-tuf-published", "timeout-minutes: 5", "Validate release version", "release-version.sh validate", "Validate release endpoints", "PAPERBOAT_INSTALL_URL", "PAPERBOAT_INSTALL_URL must use https", "Fetch public current root chain", "PAPERBOAT_DEFAULT_RELEASE_URL", "--proto '=https'", "--max-filesize 1048576", "1 through 64", "Validate online signer authorization", "validate-signers"):
    if required not in authority_job:
        raise SystemExit(f"release authority gate is missing {required!r}")
if authority_job.index("release-version.sh validate") > authority_job.index("Fetch public current root chain") or authority_job.index("release-version.sh validate") > authority_job.index("actions/setup-go@"):
    raise SystemExit("release version validation must run before network/toolchain work in the authority gate")
if authority_job.index("Validate release endpoints") > authority_job.index("Fetch public current root chain") or authority_job.index("Validate release endpoints") > authority_job.index("actions/setup-go@"):
    raise SystemExit("release endpoint validation must run before network/toolchain work in the authority gate")
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
if release.count("tools/generate-release-checksums.sh dist") != 2:
    raise SystemExit("release workflow must use the canonical checksum generator before and after SBOM generation")
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
    "Download and verify immutable GitHub release bytes",
    "Sign and verify production TUF release",
    "Assemble isolated release origin",
    "Verify staged release consumers before activation",
    "Activate verified release atomically on Hetzner",
    "Mark verified GitHub release latest",
)
positions = [release.index(item) for item in ordered]
if positions != sorted(positions):
    raise SystemExit("release publication transaction is out of order")
if "--latest=false" not in publication_job or "Publish immutable GitHub release assets" not in publication_job:
    raise SystemExit("immutable GitHub release must be non-latest before public activation")
for forbidden in ("--clobber", 'gh release edit "$RELEASE_VERSION" --draft=false --latest=false'):
    if forbidden in publication_job:
        raise SystemExit(f"immutable GitHub release path contains forbidden mutation {forbidden!r}")
if "gh release download \"$RELEASE_VERSION\"" not in publication_job or "GitHub release asset set differs from the immutable candidate" not in publication_job:
    raise SystemExit("published GitHub assets must be downloaded and byte-verified")
if "go test ./internal/hostruntime/bootstrap -run '^TestStagedTUFRepository$' -count=1" not in publication_job:
    raise SystemExit("release publication must verify every staged consumer before activation")
for required in ("PAPERBOAT_TEST_REQUIRE_STAGED=1", 'PAPERBOAT_TEST_RELEASE_DIRECTORY="$PAPERBOAT_STAGED_RELEASE"', 'PAPERBOAT_TEST_GITHUB_RELEASE_DIRECTORY="$PAPERBOAT_GITHUB_RELEASE_ASSETS"', "staged TUF metadata is unavailable"):
    if required not in publication_job:
        raise SystemExit(f"staged consumer verification is not fail-closed: missing {required!r}")
if "${{ env.PAPERBOAT_TUF_REPOSITORY }}" in publication_job:
    raise SystemExit("staged consumer verification must not rely on step-time expression expansion of GITHUB_ENV")
activation = publication_job.index("- name: Activate verified release atomically on Hetzner")
mark_latest = publication_job.index("- name: Mark verified GitHub release latest")
if "\n      - name:" in publication_job[activation + 1:mark_latest]:
    raise SystemExit("origin activation must be immediately followed only by the GitHub latest pointer update")
if "\n      - name:" in publication_job[mark_latest + 1:]:
    raise SystemExit("GitHub latest pointer update must be the final workflow step")
if "gh release edit" in publication_job[:activation]:
    raise SystemExit("GitHub latest must not be changed before origin activation")
for required in ("continue-on-error: true", "for attempt in 1 2 3 4 5", "sleep \"$delay\"", "GitHub latest pointer remains stale"):
    if required not in publication_job[mark_latest:]:
        raise SystemExit(f"GitHub latest pointer update must be retryable and non-blocking: missing {required!r}")
activation_job = publication_job[activation:mark_latest]
if "atomic_exchange" in activation_job or "Finalize" in activation_job or "finalize" in activation_job:
    raise SystemExit("origin activation step must delegate one atomic exchange and contain no cleanup/finalization")
for forbidden in ("Verify public updater and current release", "Finalize verified release activation", "finalize /opt/paperboat/releases"):
    if forbidden in publication_job:
        raise SystemExit(f"post-activation workflow action is forbidden: {forbidden}")
if "group: release-publication-${{ github.repository }}" not in release:
    raise SystemExit("release workflow must serialize publication globally across versions")
if "/releases/latest" in installer or "PAPERBOAT_RELEASE_METADATA_URL" not in installer or "https://api.pprbt.dev/current.json" not in installer:
    raise SystemExit("Unix installer must resolve its default release through current.json")
PY

for required in select_checksum_backend run_checksum sha256sum shasum; do
  grep -Fq -- "$required" "$publisher_test" || {
    echo "publisher checksum contract is missing $required" >&2
    exit 1
  }
done
if grep -Fq -- 'xargs -0 shasum' "$publisher_test"; then
  echo 'publisher checksum contract must not depend on a host-specific xargs shasum command' >&2
  exit 1
fi
for required in PAPERBOAT_CHECKSUM_BACKEND sha256sum shasum; do
  grep -Fq -- "$required" "$manifest_generator" || {
    echo "package manifest checksum contract is missing $required" >&2
    exit 1
  }
done

"$checksum_test"
"$current_release_test"
"$publisher_test"
"$manifest_test"

for script in "$(dirname -- "$0")"/*.sh; do sh -n "$script"; done
