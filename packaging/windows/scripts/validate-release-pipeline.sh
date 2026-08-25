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
staged_verifier="$repository_root/internal/hostruntime/bootstrap/artifact_staged_test.go"
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
test -f "$staged_verifier"

python3 - "$workflow" "$qualification" "$ci" "$active_signing_state" "$installer" "$windows_installer" "$publisher" "$staged_verifier" <<'PY'
import json
import os
import pathlib
import subprocess
import sys
import textwrap

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
repository_root = pathlib.Path(sys.argv[1]).parents[2]
winget_renderer = (repository_root / "packaging/windows/scripts/render-winget.ps1").read_text(encoding="utf-8")
native_artifact_builder = (repository_root / "packaging/windows/scripts/Build-NativeQualificationArtifacts.ps1").read_text(encoding="utf-8")
native_qualification = (repository_root / "packaging/windows/scripts/Invoke-NativeWindowsQualification.ps1").read_text(encoding="utf-8")
staged_verifier = pathlib.Path(sys.argv[8]).read_text(encoding="utf-8")

for required in (
    "release-authority:", "release-linux:", "release-macos:", "release-windows:",
    "windows-release-contract:",
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
    "dist/windows-*-native-qualification.json", "dist/windows-*-native-qualification-report.json",
    "Build native Windows upgrade fixture and service fixture", "Execute full native Windows MSI qualification",
    "Require passed native Windows qualification report", "Build-NativeQualificationArtifacts.ps1",
    "Invoke-NativeWindowsQualification.ps1", "-FreshMsiPath", "PAPERBOAT_WINDOWS_NATIVE_REPORT",
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
    "description: Native platform qualification target", "type: choice", "type: string",
    "default: all", "options:", "- all", "- windows-arm64", "- macos-arm64",
    "include: >-", "${{ fromJSON(", "inputs.target == 'windows-arm64'", "inputs.target == 'macos-arm64'",
    "timeout-minutes: 30",
    '"runner":"blacksmith-2vcpu-ubuntu-2404"',
    '"runner":"blacksmith-2vcpu-ubuntu-2404-arm"',
    '"runner":"blacksmith-6vcpu-macos-latest"',
    '"runner":"blacksmith-2vcpu-windows-2025"', '"runner":"windows-11-arm"',
    '"architecture":"amd64"', '"architecture":"arm64"',
    "'[{\"os\":\"macos\",\"architecture\":\"arm64\",\"runner\":\"blacksmith-6vcpu-macos-latest\"}]'",
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
qualification_job = release[release.index("  platform-qualification:"):release.index("  windows-release-contract:")]
windows_contract_job = release[release.index("  windows-release-contract:"):release.index("  release-linux:")]
macos_job = release[release.index("  release-macos:"):release.index("  release-windows:")]
windows_job = release[release.index("  release-windows:"):release.index("  windows-winget:")]
assembly_job = release[release.index("  candidate-assembly:"):release.index("  release-publication:")]
winget_job = release[release.index("  windows-winget:"):release.index("  candidate-assembly:")]
publication_job = release[release.index("  release-publication:"):]
required_events_start = windows_job.index("$requiredEvents")
required_events_end = windows_job.index(")", required_events_start)
required_events = windows_job[required_events_start:required_events_end]
for event_name in ("preexisting_state_snapshot", "native_runtime_current_fixture", "native_go_preview_e2e", "native_runtime_current_fixture_cleanup", "msi_payload_assertions"):
    if f"'{event_name}'" not in required_events:
        raise SystemExit(f"Windows release report gate must require passed event {event_name!r}")
for required_text in (
    "$report.failure -ne $null",
    "$preexistingStateEvents = @(",
    "$preexistingStateEvents.Count -ne 1",
    "$preexistingStateDetail -notmatch",
    "root_present=(true|false)",
    r"entries=\d+",
    "security=owner_dacl_descriptor",
    "reparse=false",
    "PAPERBOAT_WINDOWS_E2E_NATIVE_TEST",
    "-NativeTestExecutable",
    "$report.native_test_sha256 -ne $nativeTestHash",
    "[int64]$report.native_test_length -ne [int64]$nativeTest.Length",
    "paperboat.windows-native-qualification-result-binding/v1",
    '"windows-$env:PAPERBOAT_ARCH-native-qualification-report.json"',
    "qualification_result = @{",
    "native_test_sha256 = [string]$report.native_test_sha256",
    "native_test_length = [int64]$report.native_test_length",
):
    if required_text not in windows_job:
        raise SystemExit(f"Windows release report gate is missing {required_text!r}")
for required_text in (
    "paperboat-windows-native-e2e.test.exe",
    "native_test_executable",
    "PAPERBOAT_WINDOWS_E2E_NATIVE_TEST",
    "./packaging/windows/e2e",
):
    if required_text not in native_artifact_builder:
        raise SystemExit(f"native Windows artifact builder is missing {required_text!r}")
for required_text in (
    '{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}',
    'for _, component := range []string{"cli", "runtime", "hostd", "updater", "launcher"}',
    "stagedBootstrapAssetName",
    'return targetPath + ".exe"',
    'evidence := "windows-" + target.architecture + "-native-qualification.json"',
    "assertSignedTargetMatchesFile",
    "assertWindowsQualificationResultBinding",
    "paperboat.windows-native-qualification-result-binding/v1",
    'expectedReport := "windows-" + architecture + "-native-qualification-report.json"',
    "assertStagedFileEquals",
):
    if required_text not in staged_verifier:
        raise SystemExit(f"staged release verifier is missing Windows alias/component coverage {required_text!r}")
for forbidden_text in ("[string] $NativeTestExecutable = ''", "-ExecutablePath 'go'"):
    if forbidden_text in native_qualification:
        raise SystemExit(f"native Windows qualification retains an optional source-build fallback {forbidden_text!r}")
for required_text in ("$reportJSON = $report | ConvertTo-Json -Depth 10", '[IO.File]::WriteAllText($reportPath, $reportJSON + "`n", [Text.UTF8Encoding]::new($false))'):
    if required_text not in native_qualification:
        raise SystemExit(f"native Windows qualification report is not canonical UTF-8: missing {required_text!r}")
if "$report | ConvertTo-Json -Depth 10 | Set-Content" in native_qualification:
    raise SystemExit("native Windows qualification report retains PowerShell 5.1 BOM-producing output")
invoke_msi_start = native_qualification.index("function Invoke-Msi")
invoke_msi_end = native_qualification.index("function Get-PaperboatServices", invoke_msi_start)
invoke_msi = native_qualification[invoke_msi_start:invoke_msi_end]
for required_text in (
    "$script:msiOperationTimeoutMilliseconds = 5 * 60 * 1000",
    "$script:msiTerminationGraceMilliseconds = 15 * 1000",
    "$process.WaitForExit($script:msiOperationTimeoutMilliseconds)",
    "$process.Kill()",
    "$process.WaitForExit($script:msiTerminationGraceMilliseconds)",
):
    if required_text not in native_qualification:
        raise SystemExit(f"native Windows qualification is missing bounded MSI process handling {required_text!r}")
if "Start-Process" not in invoke_msi or "-PassThru" not in invoke_msi or "-Wait" in invoke_msi:
    raise SystemExit("native Windows qualification must launch msiexec with a process handle and no unbounded Start-Process wait")
for required_text in (
    "$script:preflightPassed = $true",
    "A Paperboat MSI product already exists; refusing to overwrite an unmanaged test state.",
    "if ($script:preflightPassed)",
    "-Operation 'failure_cleanup'",
):
    if required_text not in native_qualification:
        raise SystemExit(f"native Windows qualification is missing fail-closed MSI cleanup handling {required_text!r}")
if "$script:installedByHarness" in native_qualification or "$script:upgradeInstalled" in native_qualification:
    raise SystemExit("native Windows qualification still gates cleanup on post-success MSI flags")
if "$process.WaitForExit()" in native_qualification:
    raise SystemExit("native Windows qualification retains an unbounded process wait")
for required_text in (
    "$script:nativeCommandTimeoutMilliseconds = 30 * 1000",
    "$script:nativeTestTimeoutMilliseconds = 5 * 60 * 1000 + 30 * 1000",
    "$script:streamDrainTimeoutMilliseconds = 15 * 1000",
    "function Stop-QualificationProcess",
    "function Register-QualificationProcess",
    "function Complete-QualificationProcess",
    '$script:launchedQualificationProcesses = @()',
    '$script:qualificationProcessRegistrationFailures = @()',
    "$script:qualificationProcessContract = 'synchronous_descendants_required'",
    '$processRecord = Register-QualificationProcess -Process $process',
    'Complete-QualificationProcess -Record $processRecord -Process $process',
    '[uint32]$candidate.ParentProcessId -ne [uint32]$record.ProcessId',
    '([DateTime]$candidate.CreationDate).ToUniversalTime()',
    '$utcTicks - ($utcTicks % 10)',
    'launch_identity=pid_creation_image; direct_children=parent_lifetime; contract=',
    'state=nonterminal_identity_missing',
    "$process.WaitForExit($TimeoutMilliseconds)",
    '$processHandle = $process.Handle',
    '$handlePinned = $true',
    'Assert-Qualification $HandlePinned',
    "$process.StandardOutput.ReadToEndAsync()",
    "$process.StandardError.ReadToEndAsync()",
    "[Threading.Tasks.Task]::WaitAll($streamTasks, $script:streamDrainTimeoutMilliseconds)",
    "Invoke-NativeCommandCapture -ExecutablePath $script:icacls",
    "Invoke-NativeCommandCapture -ExecutablePath $script:serviceControl",
    "Invoke-NativeCommandCapture -ExecutablePath (Join-Path $script:binaryRoot 'pb.exe')",
    "function Get-QualificationOwnedProcesses",
    "function Assert-NoQualificationProcessResidue",
    "Assert-NoQualificationProcessResidue -Phase 'preflight'",
    "Assert-NoQualificationProcessResidue -Phase 'uninstall'",
    "Assert-NoQualificationProcessResidue -Phase 'final_cleanup'",
):
    if required_text not in native_qualification:
        raise SystemExit(f"native Windows qualification is missing bounded native-command handling {required_text!r}")
if native_qualification.count("Stop-QualificationProcess -Process $process") < 3:
    raise SystemExit("native Windows qualification must terminate native and owner processes by pinned handle on failure")
if native_qualification.count('$processHandle = $process.Handle') != 3:
    raise SystemExit("native Windows qualification must pin every launched process handle before waiting or termination")
if native_qualification.count('$handlePinned = $true') != 3:
    raise SystemExit("native Windows qualification must mark exactly three successfully pinned launch handles")
if native_qualification.count('$processRecord = Register-QualificationProcess -Process $process') != 3:
    raise SystemExit("native Windows qualification must record exactly the MSI, native, and owner launch identities")
if native_qualification.count('Complete-QualificationProcess -Record $processRecord -Process $process') != 3:
    raise SystemExit("native Windows qualification must close exactly the MSI, native, and owner launch identities")
for forbidden_text in ("taskkill.exe", '"/PID $targetProcessId /T /F"', "Stop-QualificationProcessTree"):
    if forbidden_text in native_qualification:
        raise SystemExit(f"native Windows qualification retains raw-PID process-tree termination {forbidden_text!r}")
for forbidden_text in ('$candidate.CommandLine', '$ownedArguments'):
    if forbidden_text in native_qualification:
        raise SystemExit(f"native Windows qualification retains command-line substring process ownership {forbidden_text!r}")
for forbidden_text in ("& icacls.exe", "& sc.exe", "@(& (Join-Path $script:binaryRoot 'pb.exe')"):
    if forbidden_text in native_qualification:
        raise SystemExit(f"native Windows qualification retains an unbounded native invocation {forbidden_text!r}")
expected_active_state = {"schema": "paperboat.tuf-signing-state/v1", "roles": {"root": ["root-1", "root-2", "root-3"], "targets": ["targets-1", "targets-2"], "snapshot": ["snapshot-1"], "timestamp": ["timestamp-2"]}}
manifest_command = 'bash tools/package-manifests.sh dist "${GITHUB_REPOSITORY}" "${RELEASE_VERSION}"'
if active_state != expected_active_state:
    raise SystemExit("active TUF signing state does not match the current root-v2 role aliases")
if "needs: [release-authority, windows-release-contract]" not in qualification_job:
    raise SystemExit("platform qualification must wait for protected release authority and the Windows contract gate")
if "uses: ./.github/workflows/platform-qualification.yml" not in qualification_job:
    raise SystemExit("release must call the platform qualification reusable workflow")
if "with:" in qualification_job:
    raise SystemExit("release must leave the platform qualification target at its all-platform default")
for name, job in (("Linux release", linux_job), ("macOS release", macos_job), ("Windows release", windows_job)):
    if "needs: [release-authority, windows-release-contract, platform-qualification]" not in job:
        raise SystemExit(f"{name} must wait for protected authority, the Windows contract gate, and native platform qualification")
for name, job, server_binding, release_binding in (
    ("Linux release", linux_job, "DEFAULT_SERVER_URL: ${{ needs.release-authority.outputs.server_url }}", "DEFAULT_RELEASE_URL: ${{ needs.release-authority.outputs.release_url }}"),
    ("macOS release", macos_job, "DEFAULT_SERVER_URL: ${{ needs.release-authority.outputs.server_url }}", "DEFAULT_RELEASE_URL: ${{ needs.release-authority.outputs.release_url }}"),
    ("Windows release", windows_job, "PAPERBOAT_DEFAULT_SERVER_URL: ${{ needs.release-authority.outputs.server_url }}", "PAPERBOAT_DEFAULT_RELEASE_URL: ${{ needs.release-authority.outputs.release_url }}"),
):
    if server_binding not in job or release_binding not in job:
        raise SystemExit(f"{name} must embed only the server and release URLs validated by release authority")
    if "vars.PAPERBOAT_DEFAULT_SERVER_URL" in job or "vars.PAPERBOAT_DEFAULT_RELEASE_URL" in job:
        raise SystemExit(f"{name} must not re-read mutable server or release URL variables")
for required in (
    "runs-on: blacksmith-2vcpu-windows-2025", "timeout-minutes: 15",
    "Validate Windows release pipeline contract",
    '"C:\\\\Program Files\\\\Git\\\\bin\\\\bash.exe" --noprofile --norc -e -o pipefail -c "./packaging/windows/scripts/validate-release-pipeline.sh"',
    "Validate first-party Windows packaging contract",
    "go run ./packaging/windows/cmd/validate --root packaging/windows",
    "go test -count=1 ./packaging/windows/cmd/... ./packaging/windows/manifest/...",
):
    if required not in windows_contract_job:
        raise SystemExit(f"Windows release contract gate is missing {required!r}")
for forbidden in ("Validate Windows release pipeline contract", "Validate first-party Windows packaging contract"):
    if forbidden in windows_job:
        raise SystemExit(f"Windows package matrix must not repeat the early contract gate: {forbidden}")
if "internal/buildinfo.WindowsArtifactRole=$($role.Value)" not in windows_job:
    raise SystemExit("Windows package matrix must stamp each service artifact role")
for role in ("runtime", "hostd", "updater"):
    if f"Value = '{role}'" not in windows_job:
        raise SystemExit(f"Windows package matrix must build a distinct {role} role artifact")
for name, job in (
    ("release authority", authority_job),
    ("Windows release contract", windows_contract_job),
    ("Linux release", linux_job),
    ("macOS release", macos_job),
    ("Windows release", windows_job),
    ("WinGet", winget_job),
    ("candidate assembly", assembly_job),
    ("release publication", publication_job),
):
    if "timeout-minutes:" not in job:
        raise SystemExit(f"{name} must have a bounded job timeout")
for required in ('"dist/pb-${os}-${arch}"', '"dist/pb-darwin-arm64"', '("pb-windows-{0}.exe" -f $env:PAPERBOAT_ARCH)'):
    if required not in release:
        raise SystemExit(f"release workflow is missing direct installer asset {required!r}")
for required in ("--setup MODE               Run setup after install: client or host", "--setup client", '""|client|host)'):
    if required not in installer:
        raise SystemExit(f"installer is missing canonical setup contract {required!r}")
for forbidden in ("--setup receive", "receive, session, or host", '""|receive|session|host)'):
    if forbidden in installer:
        raise SystemExit(f"installer retains retired setup vocabulary {forbidden!r}")
for required in ("$role = if", "{ 'host' } else { 'client' }", "$setupMode = $role", '"--setup-mode=$setupMode"', '$asset = "paperboat_${version}_windows_${arch}.msi"', "[Environment]::GetFolderPath([Environment+SpecialFolder]::System)", "'msiexec.exe'", "'/i'", "'/qn'", "'/norestart'", "'/L*v'", 'WaitForExit(1200000)', 'function Assert-InstalledVersion', r"'Paperboat\bin\pb.exe'", '& $installedPb pair --server $server --enrollment-token $token --name $name "--setup-mode=$setupMode"'):
    if required not in windows_installer:
        raise SystemExit(f"Windows installer is missing canonical enrollment contract {required!r}")
if 'pb-windows-$arch.exe' in windows_installer:
    raise SystemExit('Windows installer must not bootstrap pairing through a downloaded direct executable')
if '-Verb RunAs' not in windows_installer:
    raise SystemExit('Windows installer must explicitly elevate the per-machine MSI')
if r"\\bVersion\\s+" in windows_installer or r"\\s*$" in windows_installer:
    raise SystemExit('Windows installer contains doubled regex escapes that do not match version output')
if r"(?m)^.*\bVersion\s+" not in windows_installer:
    raise SystemExit('Windows installer version assertion regex is missing')
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
for required in ("atomic_exchange", "renameat2", "current.json", "verify_live_mount_contract", "/opt/paperboat/releases", "/srv/paperboat-releases", "PAPERBOAT_RELEASE_DIRECTORY", "no single running container exposes the read-only releases parent mount and current runtime directory", "docker inspect", "pre-activation cleanup", "atomic_exchange \"$live\" \"$next\""):
    if required not in publisher:
        raise SystemExit(f"release publisher is missing transaction contract {required!r}")
if "rollback" in publisher:
    raise SystemExit("release publisher must never roll back an observed TUF timestamp")
for required in ("environment: paperboat-tuf-published", "timeout-minutes: 5", "Validate release version", "release-version.sh validate", "Validate release endpoints", "id: origin_topology", "PAPERBOAT_INSTALL_URL", "PAPERBOAT_DEFAULT_SERVER_URL", "PAPERBOAT_DEFAULT_SERVER_URL must be an HTTPS origin with no path", "PAPERBOAT_DEFAULT_RELEASE_URL", "must use the exact {required_path} path", "or '?' in value or '#' in value", "PAPERBOAT_RELEASE_HOST", "PAPERBOAT_RELEASE_ORIGIN_HOSTS_JSON", "must be a canonical literal IPv4 address", "atomic activation requires exactly one authoritative release origin host", "PAPERBOAT_INSTALL_URL and PAPERBOAT_DEFAULT_RELEASE_URL must use one public release origin", "PAPERBOAT_RELEASE_HOST must equal the sole authoritative origin host", "release_host: ${{ steps.origin_topology.outputs.release_host }}", "install_url: ${{ steps.origin_topology.outputs.install_url }}", "server_url: ${{ steps.origin_topology.outputs.server_url }}", "release_url: ${{ steps.origin_topology.outputs.release_url }}", "INSTALL_URL: ${{ steps.origin_topology.outputs.install_url }}", "SERVER_URL: ${{ steps.origin_topology.outputs.server_url }}", "RELEASE_URL: ${{ steps.origin_topology.outputs.release_url }}", "Configure protected release origin read-only identity", "Verify read-only publication origin readiness", "Verify public server and installer readiness", '"${INSTALL_URL}?p=00000000000000000000000000"', '"${INSTALL_URL%/install}/current.json"', '"${SERVER_URL%/}/current.json"', '"${SERVER_URL%/}/healthz"', "server_current_hash", "public server current.json does not match the authoritative release origin", "public current.json is not served by the authoritative release origin", "public TUF root is not served by the authoritative release origin", "PAPERBOAT_RELEASE_SSH_KEY", "PAPERBOAT_RELEASE_KNOWN_HOSTS", "root@$RELEASE_HOST", "/opt/paperboat/releases", "/srv/paperboat-releases", "PAPERBOAT_RELEASE_DIRECTORY", "no single running container exposes the read-only releases parent mount and current runtime directory", "Fetch public current root chain", "--proto '=https'", "--max-filesize 1048576", "1 through 64", "Validate online signer authorization", "validate-signers"):
    if required not in authority_job:
        raise SystemExit(f"release authority gate is missing {required!r}")
if authority_job.index("release-version.sh validate") > authority_job.index("Fetch public current root chain") or authority_job.index("release-version.sh validate") > authority_job.index("actions/setup-go@"):
    raise SystemExit("release version validation must run before network/toolchain work in the authority gate")
if authority_job.index("Validate release endpoints") > authority_job.index("Configure protected release origin read-only identity") or authority_job.index("Validate release endpoints") > authority_job.index("Fetch public current root chain") or authority_job.index("Validate release endpoints") > authority_job.index("actions/setup-go@"):
    raise SystemExit("release endpoint validation must run before network/toolchain work in the authority gate")
if authority_job.index("Verify read-only publication origin readiness") > authority_job.index("Fetch public current root chain"):
    raise SystemExit("release origin readiness must run before TUF/network work in the authority gate")
if authority_job.index("Verify public server and installer readiness") > authority_job.index("Fetch public current root chain") or authority_job.index("Verify public server and installer readiness") > authority_job.index("actions/setup-go@"):
    raise SystemExit("public server and installer readiness must run before TUF/toolchain work in the authority gate")
if 'RELEASE_HOST: ${{ steps.origin_topology.outputs.release_host }}' not in authority_job:
    raise SystemExit("release origin readiness must consume the exact host proven by the topology gate")
endpoint_parser_start = authority_job.index("          import ipaddress\n")
endpoint_parser_end = authority_job.index("\n          PY\n", endpoint_parser_start)
endpoint_parser = textwrap.dedent(authority_job[endpoint_parser_start:endpoint_parser_end])
valid_endpoint_environment = os.environ.copy()
valid_endpoint_environment.update({
    "INSTALL_URL": "https://get.pprbt.dev/install",
    "SERVER_URL": "https://api.pprbt.dev",
    "RELEASE_URL": "https://get.pprbt.dev/tuf",
    "RELEASE_HOST": "192.0.2.10",
    "RELEASE_ORIGIN_HOSTS_JSON": '["192.0.2.10"]',
})
valid_endpoint_result = subprocess.run(
    [sys.executable, "-c", endpoint_parser],
    env=valid_endpoint_environment,
    capture_output=True,
    text=True,
    timeout=5,
    check=False,
)
expected_endpoint_output = "\n".join(("192.0.2.10", "https://get.pprbt.dev/install", "https://api.pprbt.dev", "https://get.pprbt.dev/tuf"))
if valid_endpoint_result.returncode != 0 or valid_endpoint_result.stdout.strip() != expected_endpoint_output:
    raise SystemExit(f"release endpoint parser rejected the valid contract: {valid_endpoint_result.stderr.strip()}")
valid_ipv4_endpoint_environment = valid_endpoint_environment.copy()
valid_ipv4_endpoint_environment.update({
    "INSTALL_URL": "https://192.0.2.20/install",
    "SERVER_URL": "https://192.0.2.30",
    "RELEASE_URL": "https://192.0.2.20/tuf",
})
valid_ipv4_endpoint_result = subprocess.run(
    [sys.executable, "-c", endpoint_parser],
    env=valid_ipv4_endpoint_environment,
    capture_output=True,
    text=True,
    timeout=5,
    check=False,
)
expected_ipv4_endpoint_output = "\n".join(("192.0.2.10", "https://192.0.2.20/install", "https://192.0.2.30", "https://192.0.2.20/tuf"))
if valid_ipv4_endpoint_result.returncode != 0 or valid_ipv4_endpoint_result.stdout.strip() != expected_ipv4_endpoint_output:
    raise SystemExit(f"release endpoint parser rejected canonical dotted IPv4 endpoints: {valid_ipv4_endpoint_result.stderr.strip()}")
for variable, path in (
    ("INSTALL_URL", "/install"),
    ("SERVER_URL", ""),
    ("RELEASE_URL", "/tuf"),
):
    for legacy_host in ("127.1", "0177.0.0.1", "0x7f000001"):
        invalid_endpoint_environment = valid_endpoint_environment.copy()
        invalid_endpoint_environment[variable] = f"https://{legacy_host}{path}"
        invalid_endpoint_result = subprocess.run(
            [sys.executable, "-c", endpoint_parser],
            env=invalid_endpoint_environment,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if invalid_endpoint_result.returncode == 0 or "release endpoint host must use canonical DNS or IP spelling" not in invalid_endpoint_result.stderr:
            raise SystemExit(f"release endpoint parser accepted or ambiguously rejected legacy numeric IPv4: {variable}={legacy_host}")
for variable, value in (
    ("INSTALL_URL", "https://get.pprbt.dev/install?"),
    ("INSTALL_URL", "https://get.pprbt.dev/install#"),
    ("SERVER_URL", "https://api.pprbt.dev?"),
    ("SERVER_URL", "https://api.pprbt.dev#"),
    ("RELEASE_URL", "https://get.pprbt.dev/tuf?"),
    ("RELEASE_URL", "https://get.pprbt.dev/tuf#"),
):
    invalid_endpoint_environment = valid_endpoint_environment.copy()
    invalid_endpoint_environment[variable] = value
    invalid_endpoint_result = subprocess.run(
        [sys.executable, "-c", endpoint_parser],
        env=invalid_endpoint_environment,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if invalid_endpoint_result.returncode == 0:
        raise SystemExit(f"release endpoint parser accepted an empty query or fragment delimiter: {variable}={value}")
for name, overrides in (
    ("DNS release host", {"RELEASE_HOST": "release.example.test"}),
    ("IPv6 release host", {"RELEASE_HOST": "2001:db8::10"}),
    ("noncanonical IPv4 release host", {"RELEASE_HOST": "192.000.002.010"}),
    ("DNS inventory host", {"RELEASE_ORIGIN_HOSTS_JSON": '["release.example.test"]'}),
    ("IPv6 inventory host", {"RELEASE_ORIGIN_HOSTS_JSON": '["2001:db8::10"]'}),
    ("noncanonical IPv4 inventory host", {"RELEASE_ORIGIN_HOSTS_JSON": '["192.000.002.010"]'}),
    ("multiple release hosts", {"RELEASE_ORIGIN_HOSTS_JSON": '["192.0.2.10","192.0.2.11"]'}),
    ("mismatched release host", {"RELEASE_ORIGIN_HOSTS_JSON": '["192.0.2.11"]'}),
):
    invalid_topology_environment = valid_endpoint_environment.copy()
    invalid_topology_environment.update(overrides)
    invalid_topology_result = subprocess.run(
        [sys.executable, "-c", endpoint_parser],
        env=invalid_topology_environment,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if invalid_topology_result.returncode == 0:
        raise SystemExit(f"release endpoint parser accepted invalid topology: {name}")
for forbidden in ("scp ", "publish-tuf-origin.sh", "atomic_exchange", "gh release"):
    if forbidden in authority_job:
        raise SystemExit(f"read-only release authority gate contains a publication mutation {forbidden!r}")
if "needs: [release-authority," not in assembly_job or "always()" in assembly_job:
    raise SystemExit("candidate assembly must skip without allocating a runner unless release authority and all handoffs succeed")
for dependency in ("release-authority", "platform-qualification", "release-linux", "release-macos", "release-windows", "windows-winget"):
    if f"needs.{dependency}.result == 'success'" not in assembly_job:
        raise SystemExit(f"candidate assembly must require successful {dependency}")
if "needs: [release-authority, candidate-assembly]" not in publication_job or "needs.release-authority.result == 'success'" not in publication_job or "needs.candidate-assembly.result == 'success'" not in publication_job:
    raise SystemExit("release publication must retain the proven authority host and require the immutable candidate")
if publication_job.count('RELEASE_HOST: ${{ needs.release-authority.outputs.release_host }}') != 2 or "vars.PAPERBOAT_RELEASE_HOST" in publication_job:
    raise SystemExit("release publication must fetch and activate only the exact origin host proven by the authority gate")
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
if 'mkdir -p "$repository/targets"' not in publication_job or "-cf - metadata targets" in publication_job:
    raise SystemExit("release publication must fetch only small TUF metadata and create an empty target staging directory")
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

for required in select_checksum_backend run_checksum run_test_publisher assert_isolated_checksum_backend run_native_checksum snapshot_directory_with_native_backend sha256sum_only_path shasum_only_path; do
  grep -Fq -- "$required" "$publisher_test" || {
    echo "publisher checksum contract is missing $required" >&2
    exit 1
  }
done
if grep -Fq -- 'xargs -0 shasum' "$publisher_test"; then
  echo 'publisher checksum contract must not depend on a host-specific xargs shasum command' >&2
  exit 1
fi
for forbidden in 'CHECKSUM_SHA256SUM_COMMAND=$checksum_sha256sum' 'CHECKSUM_SHASUM_COMMAND=$checksum_shasum'; do
  if grep -Fq -- "$forbidden" "$publisher_test"; then
    echo "publisher checksum contract must not restore an absent host command: $forbidden" >&2
    exit 1
  fi
done
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
