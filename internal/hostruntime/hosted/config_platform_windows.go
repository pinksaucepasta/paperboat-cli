//go:build windows

package hosted

import (
	"os"

	"golang.org/x/sys/windows"
)

func validatePlatformConfig(config Config) error {
	// Config is also used with an injected Runner in contract tests and by
	// callers that do not execute subprocesses. The production ExecRunner is
	// the fail-closed boundary and requires this value before any process starts.
	if config.OwnerSID == "" {
		return nil
	}
	sid, err := windows.StringToSid(config.OwnerSID)
	if err != nil || sid == nil || !sid.IsValid() || sid.String() != config.OwnerSID {
		return ErrInvalid
	}
	return nil
}

func defaultRunner(config Config) Runner { return ExecRunner{OwnerSID: config.OwnerSID} }

func hostedDefaultVolume() string          { return `C:\ProgramData\Paperboat\workspace` }
func hostedDefaultPresetDirectory() string { return `C:\ProgramData\Paperboat\presets.d` }
func hostedDefaultGitPath() string         { return `C:\Program Files\Git\cmd\git.exe` }
func hostedDefaultShellPath() string {
	return `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
}
func hostedPresetExtension() string { return ".ps1" }
func hostedScriptArguments(body string) []string {
	return []string{"-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest; " + body}
}

func securePresetFile(path string, info os.FileInfo, maximum int64) bool {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maximum {
		return false
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	return err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}
