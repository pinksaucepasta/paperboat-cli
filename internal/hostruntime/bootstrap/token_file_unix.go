//go:build !windows

package bootstrap

import (
	"os"
	"syscall"
)

func secureEnrollmentTokenFile(_ string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o600 && stat.Nlink == 1 && info.Size() > 0 && info.Size() <= 512
}
