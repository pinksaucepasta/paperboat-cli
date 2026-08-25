//go:build windows

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPaperboatStateResiduePowerShell(t *testing.T) {
	harnessPath := filepath.Join(packagingWindowsRoot(t), "scripts", "Invoke-NativeWindowsQualification.ps1")
	body, err := os.ReadFile(harnessPath)
	if err != nil {
		t.Fatal(err)
	}
	text := normalizeQualificationText(string(body))
	snapshotStart := strings.Index(text, "function ConvertTo-PaperboatStateRelativePath {")
	snapshotEnd := strings.Index(text, "\nfunction Assert-Preflight {")
	residueStart := strings.Index(text, "function Assert-PaperboatStateSnapshotEntryUnchanged {")
	residueEnd := strings.Index(text, "\nfunction Assert-Uninstalled {")
	if snapshotStart < 0 || snapshotEnd <= snapshotStart || residueStart < 0 || residueEnd <= residueStart {
		t.Fatal("could not isolate state residue functions from qualification harness")
	}

	root := filepath.Join(t.TempDir(), "Paperboat")
	selfTest := `
$ErrorActionPreference = 'Stop'
function Assert-Qualification([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "qualification_assertion_failed: $Message" }
}
` + text[snapshotStart:snapshotEnd] + "\n" + text[residueStart:residueEnd] + `
$script:stateRoot = $env:PAPERBOAT_STATE_TEST_ROOT

function Assert-Rejected([string] $Name, [scriptblock] $Action) {
    try { & $Action } catch { return }
    throw "$Name was accepted"
}

$script:preexistingPaperboatState = Get-PaperboatStateSnapshot
Assert-PaperboatStateResidue
New-Item -ItemType Directory -Force -Path (Join-Path $script:stateRoot 'ssh'), (Join-Path $script:stateRoot 'updates\current'), (Join-Path $script:stateRoot 'previews\active') | Out-Null
Assert-PaperboatStateResidue

[IO.File]::WriteAllText((Join-Path $script:stateRoot 'ssh\unexpected.txt'), 'residue')
Assert-Rejected 'file residue' { Assert-PaperboatStateResidue }
Remove-Item -LiteralPath (Join-Path $script:stateRoot 'ssh\unexpected.txt') -Force

New-Item -ItemType Directory -Path (Join-Path $script:stateRoot 'unknown') | Out-Null
Assert-Rejected 'unknown directory residue' { Assert-PaperboatStateResidue }
Remove-Item -LiteralPath (Join-Path $script:stateRoot 'unknown') -Force

$script:preexistingPaperboatState = Get-PaperboatStateSnapshot
New-Item -ItemType Directory -Force -Path (Join-Path $script:stateRoot 'logs') | Out-Null
[IO.File]::WriteAllText((Join-Path $script:stateRoot 'logs\existing.log'), 'before')
$script:preexistingPaperboatState = Get-PaperboatStateSnapshot
[IO.File]::WriteAllText((Join-Path $script:stateRoot 'logs\existing.log'), 'after')
Assert-Rejected 'modified pre-existing file' { Assert-PaperboatStateResidue }
`

	scriptPath := filepath.Join(t.TempDir(), "qualification-state-residue.ps1")
	if err := os.WriteFile(scriptPath, []byte(selfTest), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	command.Env = append(withoutEnvironmentVariable(os.Environ(), "PSModulePath"), "PAPERBOAT_STATE_TEST_ROOT="+root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("PowerShell state residue self-test failed: %v: %s", err, output)
	}
}

func TestWithoutEnvironmentVariableIsCaseInsensitive(t *testing.T) {
	environment := []string{
		`Path=C:\\Windows`,
		`PSModulePath=C:\\Program Files\\PowerShell\\Modules`,
		`psmodulepath=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules`,
		`=C:=C:\\runner`,
	}
	got := withoutEnvironmentVariable(environment, "PSModulePath")
	want := []string{`Path=C:\\Windows`, `=C:=C:\\runner`}
	if len(got) != len(want) {
		t.Fatalf("filtered environment length = %d, want %d: %q", len(got), len(want), got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("filtered environment[%d] = %q, want %q", index, got[index], want[index])
		}
	}
}

func withoutEnvironmentVariable(environment []string, name string) []string {
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, found := strings.Cut(entry, "=")
		if found && strings.EqualFold(key, name) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}
