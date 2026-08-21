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
		"scripts/convert-native-qualification-evidence.py",
		"scripts/write-arm64-native-evidence.py",
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
		"repair",
		"upgrade",
		"uninstall",
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
		"FileRef=\"CliBinary\"",
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
		"native_windows_arm64_e2e: blocked_no_hardware",
		"architecture: amd64",
		"architecture: arm64",
		"windows_arm64_stability: beta",
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
		"Invoke-NativeWindowsQualification.ps1",
		"write-arm64-native-evidence.py",
		"PAPERBOAT_WINDOWS_E2E_SERVICE_FIXTURE",
		"windows-amd64-native-release-qualification",
		"windows-arm64-beta-release-qualification",
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
		"scripts/convert-native-qualification-evidence.py",
		"scripts/write-arm64-native-evidence.py",
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
