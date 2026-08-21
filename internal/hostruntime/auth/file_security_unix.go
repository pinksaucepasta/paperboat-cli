//go:build unix

package auth

import (
	"os"
	"syscall"
)

func secureJWKSFile(_ string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && stat.Nlink == 1 && info.Mode().Perm() == 0o600
}
