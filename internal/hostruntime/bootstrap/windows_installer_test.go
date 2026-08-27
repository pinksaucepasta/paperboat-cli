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
	directStart := strings.Index(script, "$process = Start-Process -FilePath $download -ArgumentList $arguments -PassThru")
	runAsStart := strings.Index(script, "$process = Start-Process -FilePath $download -ArgumentList $arguments -Verb RunAs -PassThru")
	if adminBranch < 0 || directStart < adminBranch || runAsStart < directStart {
		t.Fatal("Windows installer does not separate elevated direct execution from desktop UAC elevation")
	}
	cleanup := strings.Index(script, "foreach ($statePath in @(")
	installedCheck := strings.LastIndex(script, "if (-not (Assert-InstalledVersion $installedPb $version))")
	if cleanup < 0 || installedCheck < 0 || cleanup < installedCheck {
		t.Fatal("Windows fresh installer clears user state before verified elevated installation")
	}
}
