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
	adminStart := strings.Index(script, "& $download @arguments")
	runAsStart := strings.Index(script, "$process = Start-Process -FilePath $runAsPath -ArgumentList $elevatedArguments -Verb RunAs -PassThru -Wait -WindowStyle Hidden")
	if adminBranch < 0 || adminStart < adminBranch || runAsStart < adminStart {
		t.Fatal("Windows installer must execute directly for administrators and use UAC for non-administrators")
	}
	if !strings.Contains(script, "$arguments[2] = $installerExecutable") {
		t.Fatal("Windows installer must pass the trusted staged source path to the elevated child")
	}
	unblock := strings.Index(script, "Unblock-File -LiteralPath $download")
	if unblock < 0 {
		t.Fatal("Windows installer must clear Zone.Identifier before executing the downloaded executable")
	}
	if !strings.Contains(script, "$trustedBootstrapDirectory = Join-Path ${env:ProgramFiles} 'Paperboat\\bootstrap'") || !strings.Contains(script, "pb-' + [guid]::NewGuid().ToString('N') + '.exe'") || !strings.Contains(script, "Stage-TrustedBootstrap $download") {
		t.Fatal("Windows installer must stage the verified bootstrap in a trusted administrator-owned path")
	}
	if !strings.Contains(script, "New-Item -ItemType Directory -Force -Path $trustedBootstrapDirectory") || !strings.Contains(script, "catch { $installerExecutable = $null }") || !strings.Contains(script, "-FilePath $runAsPath -ArgumentList $elevatedArguments -Verb RunAs") {
		t.Fatal("Windows installer must verify effective staging privileges and fall back through RunAs without leaking Access Denied")
	}
	if !strings.Contains(script, "& $installedPb pair --server $server --enrollment-token $token") || strings.Contains(script, "$pairProcess = Start-Process") {
		t.Fatal("Windows installer must pair in the original user's process")
	}
	if strings.Contains(script, "\n  if (-not $process.WaitForExit(1200000))") && strings.Index(script, "\n  if (-not $process.WaitForExit(1200000))") < runAsStart {
		t.Fatal("Windows installer waits for an elevation process before creating it")
	}
	if !strings.Contains(script, "$name = [string]$env:COMPUTERNAME") || !strings.Contains(script, "$name = $name.Trim().ToLowerInvariant()") {
		t.Fatal("Windows installer does not normalize the default machine name")
	}
	if !strings.Contains(script, "function Invoke-FreshPairRollback") || !strings.Contains(script, "rolling back the fresh installation") || !strings.Contains(script, "-EncodedCommand' $encodedPayload") {
		t.Fatal("Windows fresh pairing failure must invoke the fixed-path elevated rollback")
	}
	if !strings.Contains(script, "Remove-Item -LiteralPath $programRoot -Recurse -Force -ErrorAction Stop") || !strings.Contains(script, "Test-Path -LiteralPath $programRoot") || !strings.Contains(script, "Start-Process -FilePath $installed -ArgumentList @('purge') -Wait") {
		t.Fatal("Windows fresh pairing rollback must purge services before removing the installed payload")
	}
	cleanup := strings.LastIndex(script, "foreach ($statePath in @(")
	installedCheck := strings.LastIndex(script, "if (-not (Assert-InstalledVersion $installedPb $version))")
	if cleanup < 0 || installedCheck < 0 || cleanup < installedCheck {
		t.Fatal("Windows fresh installer clears user state before verified elevated installation")
	}
}
