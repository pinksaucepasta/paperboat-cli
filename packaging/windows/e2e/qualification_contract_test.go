package e2e

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func packagingWindowsRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func TestWindowsRuntimeACLContractUsesConcreteFileRights(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join(packagingWindowsRoot(t), "..", ".."))
	contracts := map[string][]string{
		"internal/hostruntime/hostinstall/install_windows.go": {
			"(A;;FR;;;\" + ownerSID + \")",
			"(A;OICI;0x1200a9;;;\" + ownerSID + \")",
			"windowsCLIEntrypointDACL = \"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)\"",
			"SecurityDescriptor: \"O:SY\" + windowsCLIEntrypointDACL",
		},
		"internal/hostruntime/updated/activation_windows.go": {
			"Mode: 0o755, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: \"O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)\"",
			"Mode: 0o644, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: \"O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)\"",
			"applyWindowsReleaseACL(config.InstallState, \"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;\"+config.OwnerSID+\")\")",
		},
		"internal/hostruntime/updated/service_windows.go": {
			"want := \"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;\" + ownerSID + \")\"",
		},
		"internal/hostruntimecmd/runtime_windows.go": {
			"want += \"(A;;FR;;;\" + enrolledSID + \")\"",
		},
		"internal/selfupdate/selfupdate_windows.go": {
			"Mode: 0o755, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: \"O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)\"",
			"Mode: 0o644, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: \"O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)\"",
		},
		"internal/launcher/target_windows.go": {
			"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)",
			"windowssecurity.OwnerMatchesSID(path, system)",
		},
	}
	for relative, required := range contracts {
		body, err := os.ReadFile(filepath.Join(repositoryRoot, relative))
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		if strings.Contains(text, "GRGX") || strings.Contains(text, "(A;;GR;;;") {
			t.Fatalf("%s uses generic rights that Windows remaps during secure creation", relative)
		}
		for _, fragment := range required {
			if !strings.Contains(text, fragment) {
				t.Fatalf("%s is missing concrete ACL contract %q", relative, fragment)
			}
		}
	}
}

func TestQualificationHarnessFilesAndLifecycleContract(t *testing.T) {
	root := packagingWindowsRoot(t)
	required := []string{
		"scripts/Build-NativeQualificationArtifacts.ps1",
		"scripts/Invoke-NativeWindowsQualification.ps1",
		"scripts/Invoke-InterruptedMsiQualification.ps1",
		"scripts/Invoke-MsiRollbackQualification.ps1",
		"e2e/service-fixture/main.go",
		"e2e/service_windows_test.go",
		"e2e/conpty_windows_test.go",
	}
	for _, relative := range required {
		if info, err := os.Stat(filepath.Join(root, relative)); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("required qualification file %s is missing: %v", relative, err)
		}
	}
	harness, err := os.ReadFile(filepath.Join(root, "scripts", "Invoke-NativeWindowsQualification.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	harnessText := normalizeQualificationText(string(harness))
	for _, requiredText := range []string{
		"msiexec.exe",
		"/i",
		"/fa",
		"/x",
		"PaperboatHostd",
		"PaperboatUpdated",
		"PaperboatHostd.json",
		"PaperboatUpdated.json",
		"Fixed Paperboat service declaration remains after uninstall",
		"refusing to overwrite an unmanaged service declaration",
		"Get-PaperboatPreviewDeclarations",
		"Paperboat preview declaration is a directory",
		"Paperboat preview declaration is a reparse point",
		"Paperboat service declaration root is a reparse point",
		"Paperboat state root is a reparse point",
		"Get-CimInstance -ClassName Win32_Service -ErrorAction Stop",
		"HKLM:\\Software\\Paperboat\\OpenSSH",
		"stale Paperboat OpenSSH ownership state",
		"SHA256",
		"$instance = $nameHash.Substring(0, 16)",
		"$descriptorRoot = Join-Path $script:stateRoot 'previews\\active'",
		"'--descriptor', $descriptorPath",
		"'--port', '38123'",
		"'--indefinite'",
		"service_generation",
		"New-OwnedPreviewCleanupFixture",
		"Assert-OwnedPreviewCleanupFixturePresent",
		"PaperboatSshd",
		"ReleaseVersion",
		"cli-current",
		"--version",
		"Stable CLI target is missing",
		"repair",
		"upgrade",
		"uninstall",
		"native_s4u_dpapi",
		"native_msi_cleanup",
		"TestNativePrepareS4UDPAPIQualification",
		"TestNativeLoggedOutS4UDPAPIQualification",
		"MsiCleanupTestExecutable",
		"[Parameter(Mandatory = $true)]\n    [string] $NativeTestExecutable",
		"$resolvedNativeTestExecutable = [IO.Path]::GetFullPath($NativeTestExecutable)",
		"runtime-current",
		"qualification_output_directory_invalid",
		"$outputDirectoryItem = Get-Item -Force -LiteralPath $resolvedOutputDirectory -ErrorAction Stop",
		"$outputDirectoryItem.PSIsContainer",
		"[IO.Directory]::Exists($resolvedOutputDirectory)",
		"$outputDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint",
		"Assert-PaperboatSshdAbsent",
		"Set-QualificationRuntimeCurrentACL",
		"TestNativeApplyQualificationRuntimeCurrentACL",
		"PAPERBOAT_WINDOWS_E2E_ACL_PATH",
		"PAPERBOAT_WINDOWS_E2E_ACL_SID",
		"Assert-QualificationRuntimeCurrentACL",
		"Stage-PreMsiRuntimeCurrentFixture",
		"Remove-PreMsiRuntimeCurrentFixture",
		"Invoke-NativeGoTests",
		"Invoke-NativeTestPattern",
		"New-NativeTestExecutionEvidence",
		"Assert-NativeTestExecutionEvidence",
		"paperboat.windows-native-test-execution/v1",
		"machine_readable",
		"tests_run_count",
		"matched zero tests",
		"$reportJSON = $report | ConvertTo-Json -Depth 10",
		"[IO.File]::WriteAllText($reportPath, $reportJSON + \"`n\", [Text.UTF8Encoding]::new($false))",
		"native_go_preview_e2e",
		"^TestNativeDurablePreviewServiceLifecycle$",
		"Assert-PreMsiRuntimeCurrentFixtureIntegrity",
		"0x1200a9",
		"$script:preMsiRuntimeCurrentHash",
		"$resolvedFixturePath.StartsWith($outputRootWithSeparator",
		"$destinationHash -eq $sourceHash",
		"$actualHash -eq $script:preMsiRuntimeCurrentHash",
		"exact_file=true; empty_directories=true; install_root_absent=true",
		"New-LocalUser",
		"Invoke-OwnerQualificationTest",
		"Get-OwnerQualificationStages",
		"[Parameter(Mandatory = $true)][AllowEmptyString()][string] $Output",
		"paperboat-s4u-action-stage:",
		"paperboat-s4u-cleanup-stage:",
		"paperboat-s4u-cleanup-failure:",
		"action_stage=$ownerActionStage",
		"cleanup_stage=$ownerCleanupStage",
		"cleanup_failure=$ownerCleanupFailure",
		"$actionStage = 'unreported'",
		"$cleanupStage = 'not-started'",
		"$allowedActionStages -contains $Matches[1]",
		"$allowedCleanupStages -contains $Matches[1]",
		"[Diagnostics.ProcessStartInfo]::new()",
		"$start.CreateNoWindow = $true",
		"$start.RedirectStandardInput = $false",
		"$start.FileName = $ExecutablePath",
		"Quote-WindowsArgument ([string]$_)",
		"$start.Domain = $OwnerAccount.Substring(0, $accountSeparator)",
		"$start.UserName = $OwnerAccount.Substring($accountSeparator + 1)",
		"$passwordProperty = 'Pass' + 'word'",
		"$start.$passwordProperty = $CredentialSecret",
		"$start.LoadUserProfile = $true",
		"$qualificationOwnerTest",
		"Copy-Item -LiteralPath $resolvedS4UTestExecutable -Destination $qualificationOwnerTest -Force",
		"-paperboat-owner-sid",
		"-paperboat-report-path",
		"-paperboat-fixture-path",
		"-paperboat-fixture-sha256",
		"$process.WaitForExit(90000)",
		"-WorkingDirectory $workRoot",
		"Copy-Item -LiteralPath $resolvedS4UFixturePath",
		"TestNativeOwnerCannotMutateS4UFixture",
		"PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE_SHA256",
		"$trustedRoot",
		"$workRoot",
		"(OI)(CI)RX",
		"Get-FileHash -Algorithm SHA256",
		"PaperboatQualification",
		"Assert-QualificationAncestorTrusted",
		"New-QualificationTrustedRootAtomic",
		"Assert-QualificationTrustedRoot",
		"Assert-QualificationTransactionDirectory",
		"Test-QualificationTrustValidation",
		"foreign-owned ancestor",
		"reparse ancestor",
		"untrusted Delete ACE",
		"inherit-only-ace",
		"CommonApplicationData",
		"Get-Item -Force -LiteralPath $Path",
		"[IO.Directory]::CreateDirectory($Path, $security)",
		"ScriptStackTrace",
		"PAPERBOAT_WINDOWS_E2E_S4U_REPORT_PATH",
		"PAPERBOAT_WINDOWS_E2E_S4U_SERVICE_NAME",
		"RedirectStandardOutput",
		"RedirectStandardError",
		"sc.exe delete",
		"TestNativeLegacyOwnerFullSecurityMigration",
		"native_legacy_security_migration",
		"role_artifact_allowlist",
		"Invoke-NativeCommandCapture",
		"$previousErrorActionPreference = $ErrorActionPreference",
		"$ErrorActionPreference = 'Continue'",
		"$ErrorActionPreference = $previousErrorActionPreference",
		"$roleProbe = Invoke-NativeCommandCapture -ExecutablePath $rolePath -Arguments $roleArguments",
		"$nativeResult = Invoke-NativeCommandCapture -ExecutablePath $ExecutablePath -Arguments $Arguments",
		"Assert-InstalledMachineACL -Path $versionsRoot -Directory $true",
		"Assert-InstalledMachineACL -Path $immutableReleaseRoot -Directory $true",
		"Assert-InstalledMachineACL -Path $path -Directory $false",
		"ConvertTo-PaperboatStateRelativePath",
		"Get-PaperboatStateSecuritySnapshot",
		"New-PaperboatStateSnapshotEntry",
		"Get-PaperboatStateSnapshot",
		"$script:preexistingPaperboatState = Get-PaperboatStateSnapshot",
		"preexisting_state_snapshot",
		"RelativePath",
		"OwnerSID",
		"DaclSddl",
		"SecurityDescriptor",
		"Assert-PaperboatStateSnapshotEntryUnchanged",
		"Pre-existing Paperboat state disappeared after uninstall",
		"Pre-existing Paperboat state SHA256 changed",
		"Pre-existing Paperboat state length changed",
		"Pre-existing Paperboat state security descriptor changed",
		"Pre-existing Paperboat state root disappeared after uninstall",
		"allowedNewEmptyOwnedDirectories",
		"Assert-PaperboatStateResidue",
		"Unknown Paperboat state residue remains after uninstall",
		"Paperboat state path is a reparse point",
		"New Paperboat state residue is not an empty owned directory placeholder",
		"-test.run', '^TestNativeMSIPreview",
		"runtime-current service/declaration removal and ownership-conflict preservation cases passed",
	} {
		if !strings.Contains(harnessText, requiredText) {
			t.Fatalf("native MSI harness is missing %q", requiredText)
		}
	}
	previewDeclarations := harnessText
	if strings.Contains(previewDeclarations, "Get-ChildItem -Force -File -LiteralPath $definitionRoot") {
		t.Fatal("preview declaration preflight must inspect directories and reparse entries, not only regular files")
	}
	if strings.Contains(harnessText, "$output = @(& $rolePath @roleArguments 2>&1)") {
		t.Fatal("role-artifact allowlist probes must use the scoped PowerShell 5.1-safe native capture helper")
	}
	for _, forbiddenText := range []string{"Start-Process -FilePath $ownerPreparationExecutable", "-Credential $credential", "-LoadUserProfile", "^TestNativeMSIPreviewCleanup$", "Set-Acl -LiteralPath $Path -AclObject $security", "$security.SetOwner($system)", "[string] $NativeTestExecutable = ''", "-ExecutablePath 'go'", "$report | ConvertTo-Json -Depth 10 | Set-Content"} {
		if strings.Contains(harnessText, forbiddenText) {
			t.Fatalf("native MSI harness retains Session 0 alternate-credential launch %q", forbiddenText)
		}
	}
	artifactBuilder, err := os.ReadFile(filepath.Join(root, "scripts", "Build-NativeQualificationArtifacts.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, requiredText := range []string{"paperboat-windows-msi-cleanup.test.exe", "msi_cleanup_test_executable", "PAPERBOAT_WINDOWS_E2E_MSI_CLEANUP_TEST", "paperboat-windows-hostinstall.test.exe", "hostinstall_test_executable", "paperboat-windows-native-e2e.test.exe", "native_test_executable", "PAPERBOAT_WINDOWS_E2E_NATIVE_TEST", "./packaging/windows/e2e"} {
		if !strings.Contains(string(artifactBuilder), requiredText) {
			t.Fatalf("native qualification artifact builder is missing %q", requiredText)
		}
	}
	wixSource, err := os.ReadFile(filepath.Join(root, "wix", "Paperboat.wxs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, requiredText := range []string{
		"CleanupPaperboatDynamicServices",
		"FileRef=\"CLICurrentSeedBinary\"",
		"ReleaseVersionsSecurityComponent",
		"ActiveReleaseSecurityComponent",
		"O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)",
		"Source=\"$(var.StagingDir)\\pb-launcher.exe\" Name=\"pb.exe\"",
		"CLIReleaseComponents",
		"Directory Id=\"CLICURRENTSLOT\" Name=\"cli-current\"",
		"Source=\"$(var.StagingDir)\\pb.exe\" Name=\"pb.exe\"",
		"O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)",
		"__msi-cleanup --full-uninstall",
		"Execute=\"deferred\"",
		"Impersonate=\"no\"",
		"Return=\"check\"",
		"Before=\"RemoveFiles\"",
		"REMOVE=&quot;ALL&quot; AND NOT UPGRADINGPRODUCTCODE",
		"Name=\"StateRoot\"",
		"ExistingPaperboatHostdService",
		"ExistingPaperboatUpdatedService",
		"WIX_UPGRADE_DETECTED",
		"pb doctor --repair",
		"QualificationInjectedRollback",
		"PAPERBOAT_QUALIFY_ROLLBACK = 1",
	} {
		if !strings.Contains(string(wixSource), requiredText) {
			t.Fatalf("WiX uninstall cleanup contract is missing %q", requiredText)
		}
	}
	if strings.Contains(string(wixSource), "FileRef=\"RuntimeBinary\"") {
		t.Fatal("WiX uninstall cleanup incorrectly invokes the runtime-role artifact")
	}
	workflowPath := filepath.Join(root, "..", "..", ".github", "workflows", "platform-qualification.yml")
	workflow, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, requiredText := range []string{
		"description: Native platform qualification target",
		"type: choice",
		"type: string",
		"default: all",
		"options:",
		"- all",
		"- windows-arm64",
		"- macos-arm64",
		"include: >-",
		"${{ fromJSON(",
		"inputs.target == 'windows-arm64'",
		"inputs.target == 'macos-arm64'",
		`'[{"os":"windows","architecture":"arm64","runner":"windows-11-arm"}]'`,
		`'[{"os":"macos","architecture":"arm64","runner":"blacksmith-6vcpu-macos-latest"}]'`,
		`'[{"os":"linux","architecture":"amd64","runner":"blacksmith-2vcpu-ubuntu-2404"}`,
		"windows-2025",
		"windows-11-arm",
		`"architecture":"amd64"`,
		`"architecture":"arm64"`,
		"blacksmith-2vcpu-ubuntu-2404-arm",
	} {
		if !strings.Contains(string(workflow), requiredText) {
			t.Fatalf("platform qualification is missing %q", requiredText)
		}
	}
	releaseWorkflow, err := os.ReadFile(filepath.Join(root, "..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	releaseText := string(releaseWorkflow)
	releaseQualificationStart := strings.Index(releaseText, "  platform-qualification:")
	releaseQualificationEnd := strings.Index(releaseText, "  windows-release-contract:")
	if releaseQualificationStart < 0 || releaseQualificationEnd <= releaseQualificationStart {
		t.Fatal("release workflow platform qualification call is missing")
	}
	releaseQualification := releaseText[releaseQualificationStart:releaseQualificationEnd]
	if !strings.Contains(releaseQualification, "uses: ./.github/workflows/platform-qualification.yml") {
		t.Fatal("release workflow must call the platform qualification reusable workflow")
	}
	if strings.Contains(releaseQualification, "with:") {
		t.Fatal("release workflow must leave the platform qualification target at its all-platform default")
	}
	for _, requiredText := range []string{
		"platform-qualification",
		"release-windows",
		"windows_qualification_only:",
		"Run both Windows package and native MSI qualification jobs without candidate assembly or publication",
		"(needs.platform-qualification.result == 'success' || inputs.windows_qualification_only)",
		"!inputs.windows_qualification_only && needs.release-windows.result == 'success'",
		"needs: [release-authority, windows-release-contract, platform-qualification]",
		"PAPERBOAT_RELEASE_ORIGIN_HOSTS_JSON",
		"atomic activation requires exactly one authoritative release origin host",
		"must be a canonical literal IPv4 address",
		"PAPERBOAT_INSTALL_URL and PAPERBOAT_DEFAULT_RELEASE_URL must use one public release origin",
		"or '?' in value or '#' in value",
		"legacy_ipv4_component",
		"socket.inet_aton(value)",
		"release endpoint host must use canonical DNS or IP spelling",
		"release_host: ${{ steps.origin_topology.outputs.release_host }}",
		"install_url: ${{ steps.origin_topology.outputs.install_url }}",
		"server_url: ${{ steps.origin_topology.outputs.server_url }}",
		"release_url: ${{ steps.origin_topology.outputs.release_url }}",
		"DEFAULT_SERVER_URL: ${{ needs.release-authority.outputs.server_url }}",
		"DEFAULT_RELEASE_URL: ${{ needs.release-authority.outputs.release_url }}",
		"PAPERBOAT_DEFAULT_SERVER_URL: ${{ needs.release-authority.outputs.server_url }}",
		"PAPERBOAT_DEFAULT_RELEASE_URL: ${{ needs.release-authority.outputs.release_url }}",
		"RELEASE_HOST: ${{ needs.release-authority.outputs.release_host }}",
		"Verify public server and installer readiness",
		"${INSTALL_URL}?p=00000000000000000000000000",
		"${INSTALL_URL%/install}/current.json",
		"${SERVER_URL%/}/current.json",
		"${SERVER_URL%/}/healthz",
		"public server current.json does not match the authoritative release origin",
		"public current.json is not served by the authoritative release origin",
		"public TUF root is not served by the authoritative release origin",
		"windows-winget",
		"windows-amd64",
		"windows-arm64",
		"Build native Windows upgrade fixture and service fixture",
		"Execute full native Windows MSI qualification",
		"Require passed native Windows qualification report",
		"Build-NativeQualificationArtifacts.ps1",
		"Invoke-NativeWindowsQualification.ps1",
		"-FreshMsiPath",
		"PAPERBOAT_WINDOWS_NATIVE_REPORT",
		"PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE",
		"PAPERBOAT_WINDOWS_E2E_S4U_TEST",
		"PAPERBOAT_WINDOWS_E2E_HOSTINSTALL_TEST",
		"PAPERBOAT_WINDOWS_E2E_MSI_CLEANUP_TEST",
		"PAPERBOAT_WINDOWS_E2E_NATIVE_TEST",
		"-MsiCleanupTestExecutable",
		"-NativeTestExecutable",
		"native_legacy_security_migration",
		"native_s4u_dpapi",
		"native_runtime_current_fixture",
		"native_go_preview_e2e",
		"native_runtime_current_fixture_cleanup",
		"role_artifact_allowlist",
		"preexisting_state_snapshot",
		"msi_payload_assertions",
		"$report.failure -ne $null",
		"$report.native_test_sha256 -ne $nativeTestHash",
		"[int64]$report.native_test_length -ne [int64]$nativeTest.Length",
		"paperboat.windows-native-qualification-result-binding/v1",
		"windows-$env:PAPERBOAT_ARCH-native-qualification-report.json",
		"qualification_result = @{",
		"$preexistingStateEvents = @(",
		"$preexistingStateEvents.Count -ne 1",
		"$preexistingStateDetail -notmatch",
		"root_present=(true|false)",
		"entries=\\d+",
		"security=owner_dacl_descriptor",
		"reparse=false",
	} {
		if !strings.Contains(string(releaseWorkflow), requiredText) {
			t.Fatalf("release candidate qualification is missing %q", requiredText)
		}
	}
}

func TestS4UOwnerQualificationStagesAreBoundedLiterals(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join(packagingWindowsRoot(t), "..", ".."))
	testBody, err := os.ReadFile(filepath.Join(repositoryRoot, "internal", "hostruntime", "service", "s4u_qualification_windows_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	harnessBody, err := os.ReadFile(filepath.Join(packagingWindowsRoot(t), "scripts", "Invoke-NativeWindowsQualification.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	testText := string(testBody)
	harnessText := normalizeQualificationText(string(harnessBody))
	stages := []string{
		"owner-process-validate", "thread-token-absent", "effective-owner",
		"profile-ready", "local-app-data",
		"working-directory", "owner-access", "atomic-file",
		"file-secret-store", "keyring-write", "credential-manager-write",
		"credential-manager-migrate", "identity-create", "identity-control",
		"identity-open", "identity-registration-read", "identity-control-read",
		"security-assertions", "body-complete",
	}
	for _, stage := range stages {
		if !strings.Contains(testText, `reportS4UQualificationActionStage("`+stage+`")`) {
			t.Fatalf("S4U owner test is missing literal stage %q", stage)
		}
		if !strings.Contains(harnessText, "'"+stage+"'") {
			t.Fatalf("qualification harness does not allow literal stage %q", stage)
		}
	}
	if got, want := strings.Count(testText, "reportS4UQualificationActionStage("), len(stages)+1; got != want {
		t.Fatalf("S4U stage reporter has %d call sites, want exactly %d fixed literal calls plus its declaration", got, want)
	}
	if !strings.Contains(harnessText, "^paperboat-s4u-action-stage:([a-z0-9-]+)$") ||
		!strings.Contains(harnessText, "$allowedActionStages -contains $Matches[1]") ||
		!strings.Contains(harnessText, "$Output.Length -gt 8192") {
		t.Fatal("qualification harness must accept only a bounded allowlisted stage marker")
	}
	for _, forbidden := range []string{
		"qualificationLogonUser", "qualificationProfilePrivilegeScope", "loadOwnerProfile(",
		"windows.SetThreadToken", "windows.ImpersonateSelf", "readQualificationPassword",
		"KnownFolderPath(",
	} {
		if strings.Contains(testText, forbidden) {
			t.Fatalf("owner preparation retains fixture-only bootstrap %q", forbidden)
		}
	}
	ownerStart := strings.Index(harnessText, "function Invoke-OwnerQualificationTest {")
	ownerEnd := strings.Index(harnessText, "\nfunction Invoke-S4UDPAPIQualification {")
	if ownerStart < 0 || ownerEnd <= ownerStart {
		t.Fatal("could not isolate owner-account qualification function")
	}
	ownerHarness := harnessText[ownerStart:ownerEnd]
	for _, forbidden := range []string{
		"RedirectStandardInput = $true", "$process.StandardInput", "StandardInput.BaseStream", "SecureStringToBSTR",
		"PtrToString", "Marshal]::Copy", "ZeroFreeBSTR", "credentialBytes",
		"EnvironmentVariables",
	} {
		if strings.Contains(ownerHarness, forbidden) {
			t.Fatalf("owner-account launcher exposes a forbidden credential path %q", forbidden)
		}
	}
}

func TestOwnerQualificationCleanupCannotMaskPrimaryFailure(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(packagingWindowsRoot(t), "scripts", "Invoke-NativeWindowsQualification.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	text := normalizeQualificationText(string(body))
	start := strings.Index(text, "function Invoke-OwnerQualificationTest {")
	end := strings.Index(text, "\nfunction Invoke-S4UDPAPIQualification {")
	if start < 0 || end <= start {
		t.Fatal("could not isolate owner qualification function")
	}
	owner := text[start:end]
	catchIndex := strings.Index(owner, "$primaryException = $_")
	cleanupIndex := strings.Index(owner, "\n    finally {")
	rethrowIndex := strings.LastIndex(owner, "if ($null -ne $primaryException) {")
	if catchIndex < 0 || cleanupIndex <= catchIndex || rethrowIndex <= cleanupIndex {
		t.Fatal("owner qualification must retain the first body exception across cleanup and rethrow it afterward")
	}
	cleanupBody := owner[cleanupIndex:rethrowIndex]
	if strings.Contains(cleanupBody, "Assert-Qualification") {
		t.Fatal("owner qualification cleanup must record failures without throwing over the primary error")
	}
	for _, required := range []string{
		"$cleanupFailureKinds += 'completion'",
		"$cleanupFailureKinds += 'stream-drain'",
		"$cleanupFailureKinds += 'termination'",
		"throw $primaryException",
	} {
		if !strings.Contains(owner, required) {
			t.Fatalf("owner qualification failure preservation is missing %q", required)
		}
	}
}

func normalizeQualificationText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	return strings.ReplaceAll(value, "\r", "\n")
}

func TestNormalizeQualificationTextAcceptsWindowsAndUnixLineEndings(t *testing.T) {
	want := "first\nsecond\nthird"
	for name, input := range map[string]string{
		"LF":   "first\nsecond\nthird",
		"CRLF": "first\r\nsecond\r\nthird",
		"CR":   "first\rsecond\rthird",
	} {
		t.Run(name, func(t *testing.T) {
			if got := normalizeQualificationText(input); got != want {
				t.Fatalf("normalized text = %q, want %q", got, want)
			}
		})
	}
}

func TestQualificationNativeTestPatternUsesScopedStderrCapture(t *testing.T) {
	root := packagingWindowsRoot(t)
	harnessBytes, err := os.ReadFile(filepath.Join(root, "scripts", "Invoke-NativeWindowsQualification.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	harness := string(harnessBytes)
	start := strings.Index(harness, "function Invoke-NativeTestPattern")
	if start < 0 {
		t.Fatal("native test pattern capture seam is missing")
	}
	end := strings.Index(harness[start:], "function Assert-QualificationRegularFile")
	if end < 0 {
		t.Fatal("native test pattern capture boundary is missing")
	}
	body := harness[start : start+end]
	if !strings.Contains(body, "$nativeResult = Invoke-NativeCommandCapture -ExecutablePath $ExecutablePath -Arguments $Arguments") {
		t.Fatal("native test patterns do not use the scoped PS5-safe native capture helper")
	}
	if strings.Contains(body, "2>&1") || strings.Contains(body, "& $ExecutablePath @Arguments") {
		t.Fatal("native test patterns still invoke native stderr directly under global ErrorActionPreference Stop")
	}
}

func TestQualificationOutputDirectoryIsValidatedAfterCreation(t *testing.T) {
	root := packagingWindowsRoot(t)
	harnessBytes, err := os.ReadFile(filepath.Join(root, "scripts", "Invoke-NativeWindowsQualification.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	harness := string(harnessBytes)
	resolved := strings.Index(harness, "$resolvedOutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)")
	created := strings.Index(harness, "$null = New-Item -ItemType Directory -Force -Path $resolvedOutputDirectory -ErrorAction Stop")
	inspected := strings.Index(harness, "$outputDirectoryItem = Get-Item -Force -LiteralPath $resolvedOutputDirectory -ErrorAction Stop")
	if resolved < 0 || created < 0 || inspected < 0 || resolved > created || created > inspected {
		t.Fatalf("output directory is not resolved, created, and inspected in order: resolved=%d created=%d inspected=%d", resolved, created, inspected)
	}
	validation := harness[inspected:]
	for _, required := range []string{
		"$outputDirectoryItem.PSIsContainer",
		"[IO.Directory]::Exists($resolvedOutputDirectory)",
		"[IO.FileAttributes]::ReparsePoint",
		"qualification_output_directory_invalid",
	} {
		if !strings.Contains(validation, required) {
			t.Fatalf("output directory validation is missing %q", required)
		}
	}
}

func TestQualificationReportGateRequiresExactPreexistingStateEvent(t *testing.T) {
	root := packagingWindowsRoot(t)
	workflowBytes, err := os.ReadFile(filepath.Join(root, "..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(workflowBytes)
	gate := strings.Index(workflow, "Require passed native Windows qualification report")
	if gate < 0 {
		t.Fatal("native qualification report gate is missing")
	}
	body := workflow[gate:]
	for _, required := range []string{
		"$report.failure -ne $null",
		"$preexistingStateEvents = @(",
		"$preexistingStateEvents.Count -ne 1",
		"$preexistingStateDetail -notmatch",
		"root_present=(true|false)",
		"entries=\\d+",
		"security=owner_dacl_descriptor",
		"reparse=false",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("native qualification report gate is missing %q", required)
		}
	}
}

func TestReleaseWorkflowUsesPowerShellStatusForQualificationScript(t *testing.T) {
	root := packagingWindowsRoot(t)
	workflowBytes, err := os.ReadFile(filepath.Join(root, "..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(workflowBytes)
	start := strings.Index(workflow, "      - name: Execute full native Windows MSI qualification")
	end := strings.Index(workflow, "      - name: Require passed native Windows qualification report")
	if start < 0 || end <= start {
		t.Fatal("native Windows qualification workflow step is missing")
	}
	step := workflow[start:end]
	if !strings.Contains(step, "if (-not $?) { throw 'Full native Windows MSI qualification failed.' }") {
		t.Fatal("PowerShell qualification script invocation must use its PowerShell success status")
	}
	if strings.Contains(step, "$LASTEXITCODE") {
		t.Fatal("PowerShell qualification script invocation must not use stale native-process LASTEXITCODE")
	}
}

func TestQualificationPreexistingStateSnapshotIsBeforeMutationAndExact(t *testing.T) {
	root := packagingWindowsRoot(t)
	harnessBytes, err := os.ReadFile(filepath.Join(root, "scripts", "Invoke-NativeWindowsQualification.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	harness := string(harnessBytes)
	snapshot := strings.Index(harness, "$script:preexistingPaperboatState = Get-PaperboatStateSnapshot")
	s4u := strings.Index(harness, "\n    Invoke-S4UDPAPIQualification")
	uninstall := strings.Index(harness, "function Assert-Uninstalled")
	if snapshot < 0 || s4u < 0 || snapshot > s4u {
		t.Fatalf("pre-existing state snapshot is not established before qualification mutation: snapshot=%d s4u=%d", snapshot, s4u)
	}
	if uninstall < 0 {
		t.Fatal("uninstall assertion seam is missing")
	}
	if strings.Contains(harness, "Get-ChildItem -Force -LiteralPath $script:stateRoot -Recurse") {
		t.Fatal("state residue validation must use the non-reparse snapshot traversal, not broad recursive enumeration")
	}
	for _, required := range []string{
		"RootPresent",
		"RelativePath",
		"Type",
		"ReparsePoint",
		"SHA256",
		"Length",
		"OwnerSID",
		"DaclSddl",
		"SecurityDescriptor",
		"Pre-existing Paperboat state root disappeared after uninstall",
		"allowedNewEmptyOwnedDirectories",
		"Unknown Paperboat state residue remains after uninstall",
	} {
		if !strings.Contains(harness, required) {
			t.Fatalf("pre-existing state contract is missing %q", required)
		}
	}
	if strings.Contains(harness, "Paperboat state root presence changed after uninstall") {
		t.Fatal("qualification must allow an absent baseline to become only the explicitly validated empty owned directory skeleton")
	}
}

func TestQualificationStateSnapshotAcceptsRootRelativePath(t *testing.T) {
	root := packagingWindowsRoot(t)
	harnessBytes, err := os.ReadFile(filepath.Join(root, "scripts", "Invoke-NativeWindowsQualification.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	harness := string(harnessBytes)
	const signature = "[Parameter(Mandatory = $true)][AllowEmptyString()][string] $RelativePath"
	if !strings.Contains(harness, signature) {
		t.Fatalf("qualification state snapshot must accept the root entry's empty relative path")
	}
}

func TestQualificationRuntimeCurrentFixtureIsIsolatedBeforeMsi(t *testing.T) {
	root := packagingWindowsRoot(t)
	harnessBytes, err := os.ReadFile(filepath.Join(root, "scripts", "Invoke-NativeWindowsQualification.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	harness := string(harnessBytes)
	stage := strings.LastIndex(harness, "Stage-PreMsiRuntimeCurrentFixture")
	preview := strings.Index(harness, "Invoke-NativeGoTests -RunPattern '^TestNativeDurablePreviewServiceLifecycle$'")
	cleanup := strings.LastIndex(harness, "Remove-PreMsiRuntimeCurrentFixture")
	msiPathFixtures := strings.LastIndex(harness, "Stage-MsiPathFixtures")
	if stage < 0 || preview < 0 || cleanup < 0 || msiPathFixtures < 0 {
		t.Fatal("native qualification harness is missing the RuntimeCurrent fixture lifecycle")
	}
	if stage >= preview || preview >= cleanup || cleanup >= msiPathFixtures {
		t.Fatalf("RuntimeCurrent fixture is not isolated before MSI: stage=%d preview=%d cleanup=%d msi_path_fixtures=%d", stage, preview, cleanup, msiPathFixtures)
	}
	if !strings.Contains(harness, "preMsiRunPattern = '^(TestNativeSCMHostdAndUpdaterLifecycle|") {
		t.Fatal("pre-MSI native test invocation is not explicitly disjoint from durable preview")
	}
}

func TestQualificationIsDisjointFromOpenSSHAndHostInstall(t *testing.T) {
	root := packagingWindowsRoot(t)
	paths := []string{
		"scripts/Invoke-NativeWindowsQualification.ps1",
		"scripts/Invoke-InterruptedMsiQualification.ps1",
		"scripts/Invoke-MsiRollbackQualification.ps1",
		"e2e/service-fixture/main.go",
		"e2e/service_windows_test.go",
		"e2e/conpty_windows_test.go",
	}
	for _, relative := range paths {
		body, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"internal/windowsopenssh", "internal/hostruntime/hostinstall", "Add-WindowsCapability"} {
			if strings.Contains(strings.ToLower(string(body)), strings.ToLower(forbidden)) {
				t.Fatalf("qualification file %s crosses forbidden boundary %q", relative, forbidden)
			}
		}
	}
}
