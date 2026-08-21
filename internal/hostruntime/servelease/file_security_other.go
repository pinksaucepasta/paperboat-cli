//go:build !unix && !windows

package servelease

import "os"

func secureStateFile(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm() == 0o600 && info.Size() <= 64<<10
}
