//go:build !darwin && !linux

package identity

import "os"

func secureIdentityFile(info os.FileInfo, _ bool) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
