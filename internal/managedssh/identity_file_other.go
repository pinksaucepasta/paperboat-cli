//go:build !darwin && !linux && !windows

package managedssh

func InstallManagedIdentityPublicKey(string, uint32, string) error {
	return ErrManagedIdentityFileConflict
}

func ValidateManagedIdentityPublicKey(string, uint32, string) error {
	return ErrManagedIdentityFileConflict
}

func UninstallManagedIdentityPublicKey(string, uint32) error {
	return nil
}
