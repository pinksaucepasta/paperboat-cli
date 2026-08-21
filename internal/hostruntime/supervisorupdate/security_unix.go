//go:build unix

package supervisorupdate

import (
	"os"
)

func supervisorFileIsSecure(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0
}

func supervisorFileIsUsable(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func supervisorDirectoryIsSecure(_ string, info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0
}

func setSupervisorDirectoryOwner(path string, uid, gid int) error {
	return os.Chown(path, uid, gid)
}

func prepareSupervisorArtifact(_ string, file *os.File, uid, gid int) error {
	if err := file.Chmod(0o700); err != nil {
		return err
	}
	return file.Chown(uid, gid)
}
