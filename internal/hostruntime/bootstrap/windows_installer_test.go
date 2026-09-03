package bootstrap

import (
	"os"
	"path/filepath"
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

func windowsSourceFile(t *testing.T, relativePath string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("../../../", relativePath))
	if err != nil {
		t.Fatalf("read %s: %v", relativePath, err)
	}
	return string(body)
}

func requireSourceOrder(t *testing.T, source, description string, markers ...string) {
	t.Helper()
	previous := -1
	for _, marker := range markers {
		position := strings.Index(source, marker)
		if position < 0 {
			t.Fatalf("%s is missing %q", description, marker)
		}
		if position <= previous {
			t.Fatalf("%s has incorrect order at %q", description, marker)
		}
		previous = position
	}
}

func TestWindowsFreshInstallPurgesInterruptedActivationBeforeStaging(t *testing.T) {
	command := windowsSourceFile(t, "cmd/pb/install_command_windows.go")
	hostInstall := windowsSourceFile(t, "internal/hostruntime/hostinstall/install_windows.go")
	activation := windowsSourceFile(t, "internal/hostruntime/updated/activation_windows.go")
	updatedService := windowsSourceFile(t, "internal/hostruntime/updated/service_windows.go")

	// The dashboard command must enter the supported cleanup boundary before
	// the privileged fresh install. This prevents an expired uninstall helper
	// from being confused with the activation journal it is about to remove.
	requireSourceOrder(t, command, "fresh Windows command",
		"if fresh {",
		"recoverWindowsUninstall()",
		"hostinstall.InstallStandaloneBinary(command.Context(), source, version, fresh)",
	)

	// InstallStandaloneBinary delegates fresh replacement to Purge before it
	// creates or stages any new release files. Purge owns both the updater state
	// root (where activation/journal.json lives) and the release root (where
	// versions/<version> and rollback slots live).
	installStart := strings.Index(hostInstall, "func InstallStandaloneBinary")
	purgeStart := strings.Index(hostInstall, "func Purge(ctx context.Context)")
	if installStart < 0 || purgeStart < 0 || purgeStart <= installStart {
		t.Fatal("Windows fresh-install and purge boundaries are missing")
	}
	installBody := hostInstall[installStart:purgeStart]
	requireSourceOrder(t, installBody, "fresh standalone install",
		"if fresh {",
		"if err := Purge(ctx); err != nil",
		"layout, err := service.DefaultLayout(\"windows\")",
		"return stageWindowsBinary(ctx, source, layout.Binary, rollback, artifact, \"\")",
	)
	purgeBody := hostInstall[purgeStart:]
	requireSourceOrder(t, purgeBody, "fresh purge cleanup",
		"removeWindowsActivatorService(ctx, layout)",
		"uninstallWindows(ctx, true)",
		"layout.ReleasesRoot, filepath.Join(WindowsProgramDataRoot(), \"services\"), filepath.Join(WindowsProgramDataRoot(), \"service-lifecycle\"), layout.UpdateStateRoot",
	)
	if !strings.Contains(purgeBody, "terminatePaperboatProcesses(ctx)") {
		t.Fatal("fresh purge must terminate stale Paperboat processes before returning")
	}

	// Assert that the path removed by fresh Purge is exactly the updater state
	// root used by the activation journal, rather than an unrelated user path.
	if !strings.Contains(activation, "filepath.Join(stateRoot, \"activation\", \"journal.json\")") {
		t.Fatal("Windows activation journal path is not rooted in its supplied state root")
	}
	if !strings.Contains(updatedService, "config.StateRoot == layout.UpdateStateRoot") {
		t.Fatal("Windows updater state root is not bound to the fixed layout")
	}
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
	adminStart := strings.Index(script, "$process = Start-IsolatedInstallerProcess -FilePath $runAsPath -ArgumentList $processArguments -StandardInputPath $installInput")
	runAsStart := strings.Index(script, "$process = Start-IsolatedInstallerProcess -FilePath $runAsPath -ArgumentList $processArguments -Elevated")
	if adminBranch < 0 || adminStart < adminBranch || runAsStart < adminStart {
		t.Fatal("Windows installer must isolate administrator launches and retain RunAs for interactive non-administrators")
	}
	if strings.Contains(script, "& $runAsPath @arguments") || strings.Contains(script, "& $installedPb pair") {
		t.Fatal("Windows installer must not directly invoke a child through the caller's pipes")
	}
	if strings.Contains(script, "-Verb RunAs -PassThru -Wait") || strings.Contains(script, "Start-Process -FilePath $runAsPath -ArgumentList $processArguments -Wait") {
		t.Fatal("Windows installer must not wait on the RunAs process tree")
	}
	waitStart := strings.Index(script, "$installExitCode = Wait-InstallerProcess $process 'Paperboat self-install'")
	if waitStart < runAsStart {
		t.Fatal("Windows installer must create the elevated process before waiting for its root")
	}
	if !strings.Contains(script, "function Start-IsolatedInstallerProcess") ||
		!strings.Contains(script, "$parameters.Verb = 'RunAs'") ||
		!strings.Contains(script, "-Elevated") ||
		!strings.Contains(script, "RedirectStandardInput") ||
		!strings.Contains(script, "RedirectStandardOutput") ||
		!strings.Contains(script, "RedirectStandardError") ||
		!strings.Contains(script, "function Wait-InstallerProcess") ||
		!strings.Contains(script, "$Process.WaitForExit(1200000)") ||
		!strings.Contains(script, "Stop-IsolatedInstallerProcess") {
		t.Fatal("Windows installer must use a bounded wait on the returned elevated process")
	}
}

func TestWindowsInstallerPropagatesChildExitAndCleansTimeout(t *testing.T) {
	script := windowsInstallerScript(t)
	for _, required := range []string{
		"return [int]$Process.ExitCode",
		"if ($installExitCode -ne 0)",
		"if ($pairExitCode -ne 0)",
		"exit $pairExitCode",
		"try { $Process.Kill($true) } catch { $Process.Kill() }",
		"if (-not $Process.WaitForExit(5000))",
		"exceeded the 20 minute limit and could not be stopped",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("Windows installer is missing bounded child result handling: %q", required)
		}
	}
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, "Start-Process -Wait") {
			t.Fatal("Windows installer must use the explicit root wait for every installer child")
		}
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
		!strings.Contains(script, "-ArgumentList @('__runtime-service', 'purge')") ||
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
	if !strings.Contains(script, "$pairProcess = Start-IsolatedInstallerProcess -FilePath $installedPb -ArgumentList $pairArguments") ||
		!strings.Contains(script, "-StandardInputPath $pairInput") ||
		!strings.Contains(script, "-StandardOutputPath $pairOutput") ||
		!strings.Contains(script, "-StandardErrorPath $pairError") {
		t.Fatal("Windows installer must pair in the original user context with isolated standard handles")
	}
	cleanup := strings.LastIndex(script, "foreach ($statePath in @(")
	installedCheck := strings.LastIndex(script, "if (-not (Assert-InstalledRelease $installedPb $version $actual))")
	if cleanup < 0 || installedCheck < 0 || cleanup < installedCheck {
		t.Fatal("Windows fresh installer clears user state only after verified elevated installation")
	}
}

func TestWindowsInstallerUsesAProtectedOneShotEnrollmentTokenFile(t *testing.T) {
	script := windowsInstallerScript(t)
	if strings.Contains(script, "'--enrollment-token', $token") || strings.Contains(script, "--enrollment-token $token") {
		t.Fatal("Windows installer must never pass the enrollment token in process arguments")
	}
	for _, required := range []string{
		"$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())",
		"function Test-RegularNonReparseFile",
		"[IO.FileMode]::CreateNew",
		"[IO.FileAccess]::Write",
		"[IO.FileShare]::None",
		"function New-EnrollmentTokenFile",
		"Set-Acl -LiteralPath $path -AclObject $security -ErrorAction Stop",
		"D:P(A;;FA;;;SY)(A;;FA;;;",
		"'--enrollment-token-file', $tokenFile",
		"function Remove-EnrollmentTokenFile",
		"finally {",
		"Remove-EnrollmentTokenFile $tokenFile",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("Windows installer is missing protected token-file handling: %q", required)
		}
	}
	pairStart := strings.Index(script, "$tokenFile = New-EnrollmentTokenFile $token")
	cleanupStart := strings.Index(script[pairStart:], "Remove-EnrollmentTokenFile $tokenFile")
	if pairStart < 0 || cleanupStart < 0 {
		t.Fatal("Windows installer must clean the token file after pairing")
	}
}

func TestWindowsInstallerReportsFreshRollbackUserStateFailures(t *testing.T) {
	script := windowsInstallerScript(t)
	suppressedStateRemoval := "Remove-Item -LiteralPath $statePath -Recurse -Force -ErrorAction SilentlyContinue"
	if strings.Contains(script, suppressedStateRemoval) {
		t.Fatal("Windows fresh-install state rollback must not suppress user-state deletion failures")
	}
	if !strings.Contains(script, "Remove-Item -LiteralPath $statePath -Recurse -Force -ErrorAction Stop") ||
		!strings.Contains(script, "user state remains after rollback") ||
		!strings.Contains(script, "if ($null -eq $rollbackError) { $rollbackError = $_ }") ||
		!strings.Contains(script, "Write-Warning \"Paperboat fresh-install rollback did not complete") {
		t.Fatal("Windows fresh-install rollback must report user-state cleanup failures")
	}
	if !strings.Contains(script, "exit $pairExitCode") {
		t.Fatal("Windows fresh-install rollback must preserve the primary pairing exit code")
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
	verification := strings.LastIndex(script, "Installed Paperboat does not match verified release $version")
	cleanup := strings.LastIndex(script, "Remove-Item -LiteralPath $installerExecutable -Force -ErrorAction SilentlyContinue")
	if verification < 0 || cleanup < verification {
		t.Fatal("Windows installer must remove the trusted bootstrap only after proving the installed release")
	}
}
