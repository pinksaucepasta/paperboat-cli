//go:build windows

package config

// Windows does not inherit the protected DACL used for the credential root.
// Apply the owner-only descriptor explicitly to each profile namespace before
// creating locks or atomically replacing profile files.
func ensureProfileDirectory(path string) error {
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		return err
	}
	return ensureDPAPIDirectory(path, sddl)
}
