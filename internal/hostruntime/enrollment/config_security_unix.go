//go:build !windows

package enrollment

import (
	"os"
	"syscall"
)

func secureEnrollmentConfigFile(_ string, info os.FileInfo, maximum int64) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm() == 0o600 && stat.Nlink == 1 && info.Size() <= maximum
}
