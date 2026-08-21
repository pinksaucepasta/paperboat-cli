//go:build unix

package servelease

import (
	"os"
	"syscall"
)

func secureStateFile(_ string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm() == 0o600 && stat.Nlink == 1 && info.Size() <= 64<<10
}
