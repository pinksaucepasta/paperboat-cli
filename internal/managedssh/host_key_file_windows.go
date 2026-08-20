//go:build windows

package managedssh

import (
	"os"
	"path/filepath"
)

func openOwnedPublicFile(path string, _ uint32) (*os.File, error) {
	if !filepath.IsAbs(path) || rejectWindowsReparseAncestors(path) != nil {
		return nil, ErrHostKeyInventory
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || windowsReparsePoint(path) {
		return nil, ErrHostKeyInventory
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, ErrHostKeyInventory
	}
	return file, nil
}
