//go:build darwin || linux

package identity

import (
	"os"
	"syscall"
)

func secureIdentityFile(info os.FileInfo, requirePrivateMode bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Nlink != 1 {
		return false
	}
	return !requirePrivateMode || info.Mode().Perm() == 0o600
}
