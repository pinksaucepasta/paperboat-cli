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
	for _, requiredText := range []string{
		"msiexec.exe",
		"/i",
		"/fa",
		"/x",
		"PaperboatHostd",
		"PaperboatUpdated",
		"PaperboatHostd.json",
		"PaperboatUpdated.json",
		"refusing to overwrite an unmanaged service declaration",
		"Get-PaperboatPreviewDeclarations",
		"Get-CimInstance -ClassName Win32_Service -ErrorAction Stop",
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
		"runtime-current",
		"Assert-PaperboatSshdAbsent",
		"Set-QualificationRuntimeCurrentACL",
		"TestNativeApplyQualificationRuntimeCurrentACL",
		"PAPERBOAT_WINDOWS_E2E_ACL_PATH",
		"PAPERBOAT_WINDOWS_E2E_ACL_SID",
		"Assert-QualificationRuntimeCurrentACL",
		"Stage-PreMsiRuntimeCurrentFixture",
		"Remove-PreMsiRuntimeCurrentFixture",
		"Invoke-NativeGoTests",
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
		"[Diagnostics.ProcessStartInfo]::new()",
		"$start.CreateNoWindow = $true",
		"$start.RedirectStandardInput = $true",
		"$process.StandardInput.BaseStream.Write",
		"[Runtime.InteropServices.Marshal]::SecureStringToBSTR",
		"[Runtime.InteropServices.Marshal]::ReadInt32($credentialPointer, -4)",
		"[Runtime.InteropServices.Marshal]::Copy",
		"[Runtime.InteropServices.Marshal]::ZeroFreeBSTR",
		"[Array]::Clear($credentialBytes",
		"$process.WaitForExit(90000)",
		"PAPERBOAT_WINDOWS_E2E_S4U_OWNER_ACCOUNT",
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
		"Assert-InstalledMachineACL -Path $versionsRoot -Directory $true",
		"Assert-InstalledMachineACL -Path $immutableReleaseRoot -Directory $true",
		"Assert-InstalledMachineACL -Path $path -Directory $false",
		"-test.run', '^TestNativeMSIPreview",
		"runtime-current service/declaration removal and ownership-conflict preservation cases passed",
	} {
		if !strings.Contains(string(harness), requiredText) {
			t.Fatalf("native MSI harness is missing %q", requiredText)
		}
	}
	for _, forbiddenText := range []string{"Start-Process -FilePath $ownerPreparationExecutable", "-Credential $credential", "-LoadUserProfile", "^TestNativeMSIPreviewCleanup$", "Set-Acl -LiteralPath $Path -AclObject $security", "$security.SetOwner($system)"} {
		if strings.Contains(string(harness), forbiddenText) {
			t.Fatalf("native MSI harness retains Session 0 alternate-credential launch %q", forbiddenText)
		}
	}
	artifactBuilder, err := os.ReadFile(filepath.Join(root, "scripts", "Build-NativeQualificationArtifacts.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, requiredText := range []string{"paperboat-windows-msi-cleanup.test.exe", "msi_cleanup_test_executable", "PAPERBOAT_WINDOWS_E2E_MSI_CLEANUP_TEST", "paperboat-windows-hostinstall.test.exe", "hostinstall_test_executable"} {
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
		"windows-2025",
		"windows-11-arm",
		"architecture: amd64",
		"architecture: arm64",
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
	for _, requiredText := range []string{
		"platform-qualification",
		"release-windows",
		"needs: [release-authority, windows-release-contract, platform-qualification]",
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
		"-MsiCleanupTestExecutable",
		"native_legacy_security_migration",
		"native_s4u_dpapi",
		"role_artifact_allowlist",
	} {
		if !strings.Contains(string(releaseWorkflow), requiredText) {
			t.Fatalf("release candidate qualification is missing %q", requiredText)
		}
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
