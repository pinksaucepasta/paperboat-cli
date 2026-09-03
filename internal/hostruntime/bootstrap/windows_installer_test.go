package bootstrap

import (
	"os"
	"strings"
	"testing"
)

func windowsInstallerScript(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("../../../tools/install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestWindowsInstallerUsesBoundedElevationForInteractiveAndUnattendedSessions(t *testing.T) {
	script := windowsInstallerScript(t)
	if !strings.Contains(script, "function Test-InteractiveUac") ||
		!strings.Contains(script, "[System.Environment]::UserInteractive") ||
		!strings.Contains(script, "$env:SSH_CONNECTION") ||
		!strings.Contains(script, "$env:SSH_CLIENT") {
		t.Fatal("Windows installer must detect sessions where a UAC prompt cannot be answered")
	}
	if !strings.Contains(script, "if (-not $administrator -and -not (Test-InteractiveUac))") ||
		!strings.Contains(script, "Run PowerShell as Administrator for unattended or SSH execution") {
		t.Fatal("Windows installer must fail closed before RunAs in noninteractive non-admin sessions")
	}
	adminBranch := strings.Index(script, "if ($administrator) {")
	directStart := strings.Index(script, "& $runAsPath @arguments")
	runAsStart := strings.Index(script, "$process = Start-Process -FilePath $runAsPath -ArgumentList $elevatedArguments -Verb RunAs -PassThru -WindowStyle Hidden")
	if adminBranch < 0 || directStart < adminBranch || runAsStart < directStart {
		t.Fatal("Windows installer must execute directly for administrators and retain RunAs for interactive non-administrators")
	}
	if strings.Contains(script, "-Verb RunAs -PassThru -Wait") {
		t.Fatal("Windows installer must not wait on the RunAs process tree")
	}
	waitStart := strings.Index(script, "$installExitCode = Wait-InstallerProcess $process 'Paperboat self-install'")
	if waitStart < runAsStart {
		t.Fatal("Windows installer must create the elevated process before waiting for its root")
	}
	if !strings.Contains(script, "function Wait-InstallerProcess") ||
		!strings.Contains(script, "$Process.WaitForExit(1200000)") ||
		!strings.Contains(script, "$Process.Kill()") {
		t.Fatal("Windows installer must use a bounded wait on the returned elevated process")
	}
}

func TestWindowsInstallerVerifiesTheInstalledVersionAndDigest(t *testing.T) {
	script := windowsInstallerScript(t)
	if !strings.Contains(script, "function Assert-InstalledRelease") ||
		!strings.Contains(script, "Assert-InstalledVersion $Path $ExpectedVersion") ||
		!strings.Contains(script, "Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop") ||
		!strings.Contains(script, "return $hash -eq $ExpectedHash") {
		t.Fatal("Windows installer must verify both the installed version and exact SHA-256 digest")
	}
	installStart := strings.Index(script, "if ($freshEnrollment -or -not (Assert-InstalledRelease $installedPb $version $actual))")
	postCheck := strings.LastIndex(script, "if (-not (Assert-InstalledRelease $installedPb $version $actual))")
	if installStart < 0 || postCheck < installStart {
		t.Fatal("Windows installer must verify the installed release after the elevation boundary")
	}
	if !strings.Contains(script, "Paperboat self-install failed with exit code $installExitCode") ||
		!strings.Contains(script, "Installed Paperboat does not match verified release $version") {
		t.Fatal("Windows installer must propagate child failure and reject false success")
	}
}

func TestWindowsInstallerRollbackUsesTheSameBoundedElevationContract(t *testing.T) {
	script := windowsInstallerScript(t)
	if !strings.Contains(script, "function Invoke-FreshPairRollback") ||
		!strings.Contains(script, "function Wait-RollbackProcess") ||
		!strings.Contains(script, "$purgeExitCode = Wait-RollbackProcess $purge 'Paperboat runtime purge'") ||
		!strings.Contains(script, "$rollbackExitCode = Wait-InstallerProcess $rollback 'Paperboat fresh-install rollback'") {
		t.Fatal("fresh pairing rollback must wait on each returned process with a bounded direct wait")
	}
	if strings.Contains(script, "-ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedPayload) -Verb RunAs -PassThru -Wait") {
		t.Fatal("fresh pairing rollback must not wait on the RunAs process tree")
	}
	if !strings.Contains(script, "requires an elevated administrator PowerShell session when no interactive UAC desktop is available") ||
		!strings.Contains(script, "Remove-Item -LiteralPath $programRoot -Recurse -Force -ErrorAction Stop") ||
		!strings.Contains(script, "Test-Path -LiteralPath $programRoot") {
		t.Fatal("fresh pairing rollback must fail closed and prove payload removal")
	}
	if !strings.Contains(script, "$name = [string]$env:COMPUTERNAME") || !strings.Contains(script, "$name = $name.Trim().ToLowerInvariant()") {
		t.Fatal("Windows installer does not normalize the default machine name")
	}
	if !strings.Contains(script, "& $installedPb pair --server $server --enrollment-token $token") || strings.Contains(script, "$pairProcess = Start-Process") {
		t.Fatal("Windows installer must pair in the original user's process")
	}
	cleanup := strings.LastIndex(script, "foreach ($statePath in @(")
	installedCheck := strings.LastIndex(script, "if (-not (Assert-InstalledRelease $installedPb $version $actual))")
	if cleanup < 0 || installedCheck < 0 || cleanup < installedCheck {
		t.Fatal("Windows fresh installer clears user state only after verified elevated installation")
	}
}

func TestWindowsInstallerStagesAndUnblocksTheVerifiedBootstrap(t *testing.T) {
	script := windowsInstallerScript(t)
	if !strings.Contains(script, "Unblock-File -LiteralPath $download") {
		t.Fatal("Windows installer must clear Zone.Identifier before executing the downloaded executable")
	}
	if !strings.Contains(script, "$trustedBootstrapDirectory = Join-Path ${env:ProgramFiles} 'Paperboat\\bootstrap'") ||
		!strings.Contains(script, "pb-' + [guid]::NewGuid().ToString('N') + '.exe'") ||
		!strings.Contains(script, "Stage-TrustedBootstrap $download") {
		t.Fatal("Windows installer must stage the verified bootstrap in an administrator-owned path")
	}
	if !strings.Contains(script, "New-Item -ItemType Directory -Force -Path $trustedBootstrapDirectory") ||
		!strings.Contains(script, "catch { $installerExecutable = $null }") ||
		!strings.Contains(script, "$arguments[2] = $installerExecutable") {
		t.Fatal("Windows installer must retain a safe staged source fallback")
	}
}
