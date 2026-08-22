//go:build windows

package managedssh

import (
	"os"
	"path/filepath"
	"strings"
)

// The Windows inbox and machine-scoped OpenSSH installations are the only
// supported clients for Paperboat. In particular, Git for Windows ships an
// unrelated ssh.exe that can win PATH lookup and does not implement the
// native configuration contract we require.
var windowsOpenSSHCandidatePaths = []string{
	`C:\Windows\System32\OpenSSH\ssh.exe`,
	`C:\Program Files\OpenSSH\ssh.exe`,
	`C:\Program Files\OpenSSH-Win64\ssh.exe`,
}

func resolveOpenSSHExecutable(value string) (string, error) {
	if value == "" {
		value = "ssh.exe"
	}
	if isBareWindowsOpenSSHName(value) {
		// The workflow supplies the exact machine OpenSSH path because hosted
		// Windows shells can put Git for Windows ahead of native OpenSSH in
		// PATH. Accept it only when it is one of the trusted native locations.
		if configured := strings.TrimSpace(os.Getenv("PAPERBOAT_OPENSSH_PATH")); configured != "" {
			if path, ok := validWindowsOpenSSHPath(configured); ok && isTrustedWindowsOpenSSHPath(path) {
				return path, nil
			}
			return "", ErrOpenSSHExecution
		}
		return resolveBareWindowsOpenSSHExecutable(windowsOpenSSHCandidatePaths)
	}
	// Explicit absolute paths remain allowed, but are validated strictly and
	// never silently replaced with a PATH result.
	if filepath.IsAbs(value) {
		if path, ok := validWindowsOpenSSHPath(value); ok {
			return path, nil
		}
		return "", ErrOpenSSHExecution
	}
	return "", ErrOpenSSHExecution
}

func resolveBareWindowsOpenSSHExecutable(candidates []string) (string, error) {
	for _, candidate := range candidates {
		if isGitBundledWindowsOpenSSH(candidate) {
			continue
		}
		if path, ok := validWindowsOpenSSHPath(candidate); ok {
			return path, nil
		}
	}
	return "", ErrOpenSSHExecution
}

func isTrustedWindowsOpenSSHPath(path string) bool {
	cleanPath := strings.ToLower(filepath.Clean(path))
	for _, candidate := range windowsOpenSSHCandidatePaths {
		candidatePath, err := filepath.Abs(candidate)
		if err == nil && strings.EqualFold(filepath.Clean(candidatePath), cleanPath) {
			return true
		}
	}
	return false
}

func isGitBundledWindowsOpenSSH(path string) bool {
	cleanPath := strings.ToLower(strings.ReplaceAll(filepath.Clean(path), "/", `\`))
	return strings.Contains(cleanPath, `\git\`) || strings.HasSuffix(cleanPath, `\usr\bin\ssh.exe`)
}

func isBareWindowsOpenSSHName(value string) bool {
	return strings.EqualFold(value, "ssh") || strings.EqualFold(value, "ssh.exe")
}

func validWindowsOpenSSHPath(value string) (string, bool) {
	path, err := filepath.Abs(value)
	if err != nil || filepath.Clean(path) != path || !strings.EqualFold(filepath.Ext(path), ".exe") {
		return "", false
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || windowsReparsePoint(path) {
		return "", false
	}
	return path, true
}
