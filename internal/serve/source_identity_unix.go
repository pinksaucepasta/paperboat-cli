//go:build darwin || linux

package serve

import (
	"fmt"
	"os"
	"syscall"
)

func sourceIdentity(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("unix:%d:%d", uint64(stat.Dev), uint64(stat.Ino))
}
