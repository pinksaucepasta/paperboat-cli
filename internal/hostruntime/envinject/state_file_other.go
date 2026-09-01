//go:build !windows

package envinject

import (
	"io/fs"
	"os"
)

func secureStateFile(_ string, info fs.FileInfo, maximum int64) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm() == 0o600 && info.Size() >= 1 && info.Size() <= maximum
}
