//go:build !darwin && !linux

package managedssh

import (
	"os"
)

func openOwnedPublicFile(path string, _ uint32) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, ErrHostKeyInventory
	}
	return os.Open(path)
}
