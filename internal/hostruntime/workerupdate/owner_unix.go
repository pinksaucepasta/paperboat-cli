//go:build darwin || linux

package workerupdate

import (
	"os"
	"syscall"
)

func fileOwner(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}
