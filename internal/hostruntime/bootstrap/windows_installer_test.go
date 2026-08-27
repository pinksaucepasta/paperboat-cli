package bootstrap

import (
	"os"
	"strings"
	"testing"
)

func TestWindowsInstallerDoesNotRequestUACFromElevatedSession(t *testing.T) {
	body, err := os.ReadFile("../../../tools/install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	adminBranch := strings.Index(script, "if (Test-Administrator) {")
	directStart := strings.Index(script, "& $download @arguments")
	runAsStart := strings.Index(script, "$process = Start-Process -FilePath $download -ArgumentList $arguments -Verb RunAs -PassThru")
	if adminBranch < 0 || directStart < adminBranch || runAsStart < directStart {
		t.Fatal("Windows installer does not separate elevated direct execution from desktop UAC elevation")
	}
	if !strings.Contains(script, "Assert-InstalledVersion $download $version") {
		t.Fatal("Windows installer does not verify the downloaded executable reports current.json's version")
	}
	unblock := strings.Index(script, "Unblock-File -LiteralPath $download")
	versionProbe := strings.Index(script, "if (-not (Assert-InstalledVersion $download $version))")
	if unblock < 0 || versionProbe < 0 || unblock > versionProbe {
		t.Fatal("Windows installer must clear Zone.Identifier before probing the downloaded executable")
	}
	if strings.Contains(script, "\n  if (-not $process.WaitForExit(1200000))") && strings.Index(script, "\n  if (-not $process.WaitForExit(1200000))") < runAsStart {
		t.Fatal("Windows installer waits for an elevation process before creating it")
	}
	if !strings.Contains(script, "$name = [string]$env:COMPUTERNAME") || !strings.Contains(script, "$name = $name.Trim().ToLowerInvariant()") {
		t.Fatal("Windows installer does not normalize the default machine name")
	}
	cleanup := strings.Index(script, "foreach ($statePath in @(")
	installedCheck := strings.LastIndex(script, "if (-not (Assert-InstalledVersion $installedPb $version))")
	if cleanup < 0 || installedCheck < 0 || cleanup < installedCheck {
		t.Fatal("Windows fresh installer clears user state before verified elevated installation")
	}
}
