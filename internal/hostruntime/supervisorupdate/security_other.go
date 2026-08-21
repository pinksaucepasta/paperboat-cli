//go:build !unix && !windows

package supervisorupdate

import "os"

func supervisorFileIsSecure(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0
}

func supervisorFileIsUsable(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func supervisorDirectoryIsSecure(_ string, info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0
}

func setSupervisorDirectoryOwner(_ string, _, _ int) error { return nil }

func prepareSupervisorArtifact(_ string, file *os.File, _, _ int) error {
	return file.Chmod(0o700)
}
