//go:build !unix && !windows

package configsync

import "os"

func privateControlFile(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0
}
