package tools

import (
	"os"
	"strings"
	"testing"
)

func TestWindowsReleaseTemplateUsesCanonicalModes(t *testing.T) {
	body, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	template := strings.ToLower(string(body))
	for _, required := range []string{
		"'host'", "'client'", "--setup-mode=$setupmode",
		"$server -notmatch '^https://'", "paperboat.release-current/v1", "pb-windows-$arch.exe", "__install", "releases/download",
		"function assert-installedversion", "function test-administrator", "if ($freshenrollment) { $arguments += '--fresh' }", "'paperboat\\bin\\pb.exe'", "assert-installedversion $download $version",
		"$name = [string]$env:computername", "$name = $name.trim().tolowerinvariant()",
		"$pairarguments = @('pair', '--server', $server, '--enrollment-token-file', $tokenfile, '--name', $name, \"--setup-mode=$setupmode\")",
		"function invoke-freshpairrollback", "function start-isolatedinstallerprocess", "--enrollment-token-file", "wait-installerprocess",
	} {
		if !strings.Contains(template, required) {
			t.Fatalf("Windows release template is missing canonical mode contract %q", required)
		}
	}
	for _, removed := range []string{"'receive'", "'session'", "--setup-mode=receive", "--setup-mode=session"} {
		if strings.Contains(template, removed) {
			t.Fatalf("Windows release template contains removed mode %q", removed)
		}
	}
	pairInvocation := strings.Index(template, "$pairarguments = @('pair'")
	if pairInvocation < 0 || strings.Index(template, "__install") > pairInvocation {
		t.Fatal("Windows enrollment pairs before the final installed executable is staged")
	}
	adminBranch := strings.Index(template, "if ($administrator) {")
	directStart := strings.Index(template, "$process = start-isolatedinstallerprocess -filepath $runaspath -argumentlist $processarguments -standardinputpath")
	runAsStart := strings.Index(template, "$process = start-isolatedinstallerprocess -filepath $runaspath -argumentlist $processarguments -elevated")
	if adminBranch < 0 || directStart < adminBranch || runAsStart < directStart {
		t.Fatal("Windows release template does not separate elevated direct execution from desktop UAC elevation")
	}
	pairStart := strings.Index(template, "$pairarguments = @('pair'")
	if pairStart < 0 || strings.Contains(template[pairStart:], "-verb runas") || strings.Contains(template[pairStart:], "-elevated") {
		t.Fatal("Windows enrollment does not pair in the original user process")
	}
	if strings.Contains(template, "clear-existingpaperboat") || strings.Contains(template, "sc.exe stop") {
		t.Fatal("Windows release template eagerly deletes the existing enrollment before verified installation")
	}
	freshCleanup := strings.LastIndex(template, "foreach ($statepath in @(")
	verifiedInstall := strings.LastIndex(template, "if (-not (assert-installedrelease $installedpb $version $actual))")
	if freshCleanup < 0 || verifiedInstall < 0 || freshCleanup < verifiedInstall {
		t.Fatal("Windows fresh enrollment does not clear user state after verified installation")
	}
}
