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
		"PaperboatPreview-0123456789abcdef",
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
		"TestNativePrepareS4UDPAPIQualification",
		"TestNativeLoggedOutS4UDPAPIQualification",
		"New-LocalUser",
		"Start-Process",
		"-Credential",
		"-LoadUserProfile",
		"-WorkingDirectory $workRoot",
		"s4u-owner-prepare.test.exe",
		"Copy-Item -LiteralPath $resolvedS4UTestExecutable",
		"Copy-Item -LiteralPath $resolvedS4UFixturePath",
		"TestNativeOwnerCannotMutateS4UFixture",
		"PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE_SHA256",
		"$trustedRoot",
		"$workRoot",
		"(OI)(CI)RX",
		"Get-FileHash -Algorithm SHA256",
		"PaperboatQualification",
		"Assert-QualificationAncestorTrusted",
		"Set-QualificationTrustedRoot",
		"Assert-QualificationTransactionDirectory",
		"Test-QualificationTrustValidation",
		"foreign-owned ancestor",
		"reparse ancestor",
		"untrusted Delete ACE",
		"inherit-only-ace",
		"CommonApplicationData",
		"PAPERBOAT_WINDOWS_E2E_S4U_REPORT_PATH",
		"PAPERBOAT_WINDOWS_E2E_S4U_SERVICE_NAME",
		"RedirectStandardOutput",
		"RedirectStandardError",
		"sc.exe delete",
		"TestNativeLegacyOwnerFullSecurityMigration",
		"native_legacy_security_migration",
		"role_artifact_allowlist",
	} {
		if !strings.Contains(string(harness), requiredText) {
			t.Fatalf("native MSI harness is missing %q", requiredText)
		}
	}
	wixSource, err := os.ReadFile(filepath.Join(root, "wix", "Paperboat.wxs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, requiredText := range []string{
		"CleanupPaperboatDynamicServices",
		"FileRef=\"RuntimeBinary\"",
		"Source=\"$(var.StagingDir)\\pb-launcher.exe\" Name=\"pb.exe\"",
		"CLIReleaseComponents",
		"Directory Id=\"CLICURRENTSLOT\" Name=\"cli-current\"",
		"Source=\"$(var.StagingDir)\\pb.exe\" Name=\"pb.exe\"",
		"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)",
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
		"native_legacy_security_migration",
		"native_s4u_dpapi",
		"role_artifact_allowlist",
	} {
		if !strings.Contains(string(releaseWorkflow), requiredText) {
			t.Fatalf("release candidate qualification is missing %q", requiredText)
		}
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
