//go:build windows

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnerQualificationStageParserPowerShell(t *testing.T) {
	harnessPath := filepath.Join(packagingWindowsRoot(t), "scripts", "Invoke-NativeWindowsQualification.ps1")
	body, err := os.ReadFile(harnessPath)
	if err != nil {
		t.Fatal(err)
	}
	text := normalizeQualificationText(string(body))
	start := strings.Index(text, "function Get-OwnerQualificationStages {")
	end := strings.Index(text, "\nfunction Invoke-NativeTestPattern {")
	if start < 0 || end <= start {
		t.Fatal("could not isolate Get-OwnerQualificationStages from qualification harness")
	}
	functionBody := text[start:end]
	selfTest := functionBody + `
$ErrorActionPreference = 'Stop'
function Assert-Stages([string] $name, [string] $inputValue, [string] $action, [string] $cleanup, [string] $cleanupFailure) {
    $actual = Get-OwnerQualificationStages -Output $inputValue
    if ($actual.ActionStage -ne $action -or $actual.CleanupStage -ne $cleanup -or $actual.CleanupFailure -ne $cleanupFailure) {
        throw "$name action=$($actual.ActionStage) cleanup=$($actual.CleanupStage) cleanupFailure=$($actual.CleanupFailure)"
    }
}
Assert-Stages 'body-preserved' ([string]::Join([Environment]::NewLine, @('paperboat-s4u-action-stage:credential-manager-write', 'paperboat-s4u-cleanup-stage:impersonation-reverted', 'paperboat-s4u-cleanup-stage:profile-unloaded'))) 'credential-manager-write' 'profile-unloaded' 'none'
Assert-Stages 'cleanup-failure-preserved' ([string]::Join([Environment]::NewLine, @('paperboat-s4u-action-stage:credential-manager-write', 'paperboat-s4u-cleanup-stage:impersonation-revert', 'paperboat-s4u-cleanup-failure:impersonation-revert', 'paperboat-s4u-cleanup-stage:impersonation-token-closed', 'paperboat-s4u-cleanup-stage:interactive-token-closed'))) 'credential-manager-write' 'interactive-token-closed' 'impersonation-revert'
Assert-Stages 'first-cleanup-failure' ([string]::Join([Environment]::NewLine, @('paperboat-s4u-cleanup-failure:profile-unload', 'paperboat-s4u-cleanup-failure:interactive-token-close'))) 'unreported' 'not-started' 'profile-unload'
Assert-Stages 'last-per-channel' ([string]::Join([Environment]::NewLine, @('paperboat-s4u-action-stage:owner-access', 'paperboat-s4u-action-stage:identity-open', 'paperboat-s4u-cleanup-stage:profile-unload', 'paperboat-s4u-cleanup-stage:profile-unloaded'))) 'identity-open' 'profile-unloaded' 'none'
Assert-Stages 'unknown' ([string]::Join([Environment]::NewLine, @('paperboat-s4u-action-stage:secret-value', 'paperboat-s4u-cleanup-stage:unknown', 'paperboat-s4u-cleanup-failure:secret-value'))) 'unreported' 'not-started' 'none'
Assert-Stages 'empty' '' 'unreported' 'not-started' 'none'
$longPrefix = 'x' * 9000
Assert-Stages 'bounded-tail' ([string]::Join([Environment]::NewLine, @($longPrefix, 'paperboat-s4u-action-stage:profile-ready', 'paperboat-s4u-cleanup-stage:profile-load-cleaned'))) 'profile-ready' 'profile-load-cleaned' 'none'
`
	scriptPath := filepath.Join(t.TempDir(), "qualification-stage-parser.ps1")
	if err := os.WriteFile(scriptPath, []byte(selfTest), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("PowerShell stage parser self-test failed: %v: %s", err, output)
	}
}
