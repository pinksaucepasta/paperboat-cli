//go:build !unix && !windows

package releaseeligibility

import "os"

func createTemporaryFile(directory, base string) (*os.File, string, error) {
	//paperboat:allow-source-policy atomic-replacement owner=release-eligibility reason=same-directory-private-state-staging
	file, err := os.CreateTemp(directory, "."+base+".tmp-*")
	if err != nil {
		return nil, "", err
	}
	return file, file.Name(), nil
}

// Unsupported platforms retain the bounded file checks but do not claim a
// portable ownership model. A platform-specific implementation must be added
// before this store is used for privileged update eligibility there.
func validateParentSecurity(path string, _ os.FileInfo) error {
	info, err := os.Lstat(path)
	if err != nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return ErrUnsafePath
	}
	return nil
}

func validateRecordSecurity(_ string, info os.FileInfo) error {
	if info == nil || info.Mode().Perm()&0o077 != 0 {
		return ErrUnsafePath
	}
	return nil
}

func secureRecordFile(string) error { return nil }
