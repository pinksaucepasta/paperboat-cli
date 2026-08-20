//go:build !unix && !windows

package configsync

import (
	"io/fs"
	"os"
)

func safeSnapshotPermissions(_ string, info fs.FileInfo) bool { return info.Mode().Perm()&0o002 == 0 }
func snapshotFileMode(info fs.FileInfo) os.FileMode           { return info.Mode().Perm() }
