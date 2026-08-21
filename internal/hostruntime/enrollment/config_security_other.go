//go:build !windows && !darwin && !linux

package enrollment

import "os"

func secureEnrollmentConfigFile(_ string, info os.FileInfo, maximum int64) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0 && info.Size() <= maximum
}
