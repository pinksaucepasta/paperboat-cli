//go:build darwin || linux

package hostdproto

import (
	"os"
	"syscall"
)

func fileOwnerUID(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}
