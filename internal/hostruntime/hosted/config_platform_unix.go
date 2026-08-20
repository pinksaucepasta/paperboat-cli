//go:build darwin || linux

package hosted

import "os"

func validatePlatformConfig(Config) error { return nil }

func defaultRunner(Config) Runner { return ExecRunner{} }

func hostedDefaultVolume() string          { return "/workspace" }
func hostedDefaultPresetDirectory() string { return "/etc/paperboat/presets.d" }
func hostedDefaultGitPath() string         { return "/usr/bin/git" }
func hostedDefaultShellPath() string       { return "/bin/sh" }
func hostedPresetExtension() string        { return ".sh" }
func hostedScriptArguments(body string) []string {
	return []string{"-eu", "-c", body}
}

func securePresetFile(_ string, info os.FileInfo, maximum int64) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0 && info.Size() <= maximum
}
