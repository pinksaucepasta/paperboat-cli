//go:build linux || darwin

package atomicfile

import (
	"io/fs"
	"syscall"
)

func fileOwnerUID(info fs.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}
