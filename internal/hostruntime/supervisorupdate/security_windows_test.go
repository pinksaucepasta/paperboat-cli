//go:build windows

package supervisorupdate

import (
	"os"
	"path/filepath"
)

func prepareSupervisorUpdateTestRoot(root string) error {
	if err := applySupervisorDescriptor(root, true); err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if entry.IsDir() {
			return applySupervisorDescriptor(path, true)
		}
		return applySupervisorDescriptor(path, false)
	})
}
