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
	runAsStart := strings.Index(script, "$process = Start-Process -FilePath $runAsPath -ArgumentList $arguments -Verb RunAs -PassThru")
	if adminBranch < 0 || runAsStart < adminBranch {
		t.Fatal("Windows installer must launch the bootstrap through RunAs even from an SSH session")
	}
	if strings.Contains(script, "& $installerExecutable @arguments") {
		t.Fatal("Windows installer must not invoke the bootstrap directly with a potentially filtered token")
	}
	unblock := strings.Index(script, "Unblock-File -LiteralPath $download")
	if unblock < 0 {
		t.Fatal("Windows installer must clear Zone.Identifier before executing the downloaded executable")
	}
	if !strings.Contains(script, "$trustedBootstrapDirectory = Join-Path ${env:ProgramFiles} 'Paperboat\\bootstrap'") || !strings.Contains(script, "pb-' + [guid]::NewGuid().ToString('N') + '.exe'") || !strings.Contains(script, "Stage-TrustedBootstrap $download") {
		t.Fatal("Windows installer must stage the verified bootstrap in a trusted administrator-owned path")
	}
	if !strings.Contains(script, "New-Item -ItemType File -Path $probe -Force") || !strings.Contains(script, "catch { $installerExecutable = $null }") || !strings.Contains(script, "-FilePath $runAsPath -ArgumentList $arguments -Verb RunAs") {
		t.Fatal("Windows installer must verify effective staging privileges and fall back through RunAs without leaking Access Denied")
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
