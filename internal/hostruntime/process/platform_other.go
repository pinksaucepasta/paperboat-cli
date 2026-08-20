//go:build !windows

package process

import "io/fs"

func platformExecutable(_ string, info fs.FileInfo) bool {
	return info.Mode().Perm()&0o111 != 0 && info.Mode().Perm()&0o022 == 0
}

func platformShellArguments(string) []string { return []string{"-l"} }
