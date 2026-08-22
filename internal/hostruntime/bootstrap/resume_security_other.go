//go:build !darwin && !linux && !windows

package bootstrap

import "os"

func secureResumeFile(_ string, info os.FileInfo, maximum int64) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Size() <= maximum
}
