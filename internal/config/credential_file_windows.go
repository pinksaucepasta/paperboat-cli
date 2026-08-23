//go:build windows

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func validateCredentialDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrCredentialStoreUnavailable
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(ErrCredentialStoreUnavailable, err)
	}
	return nil
}

func writeCredentialFile(path string, value []byte) error {
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		return err
	}
	if err := ensureDPAPIDirectory(filepath.Dir(path), sddl); err != nil {
		return err
	}
	plain := make([]byte, len(value)+1)
	plain[0] = 1
	copy(plain[1:], value)
	defer clear(plain)
	protected, err := dpapiTransform(plain, true)
	if err != nil {
		return fmt.Errorf("%w: protect credential file: %v", ErrCredentialStoreUnavailable, err)
	}
	defer clear(protected)
	if err := atomicfile.Write(path, protected, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: sddl}); err != nil {
		return err
	}
	ownerSID, err := currentUserSID()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, ownerSID, nil, nil, nil); err != nil {
		return fmt.Errorf("%w: set credential file owner: %v", ErrCredentialStoreUnavailable, err)
	}
	if !credentialFilePrivate(path) {
		return fmt.Errorf("%w: written credential file owner or ACL is invalid", ErrCredentialStoreUnavailable)
	}
	return nil
}

func readCredentialFile(path string) ([]byte, error) {
	if err := validateCredentialDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, err
	}
	if !credentialFilePrivate(path) {
		return nil, fmt.Errorf("credential file must have a protected owner-only ACL")
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.Join(ErrCredentialStoreUnavailable, err)
	}
	protected, err := os.ReadFile(path)
	if err != nil || len(protected) == 0 || len(protected) > windowsCredentialBlobMaxBytes*4 {
		return nil, errors.Join(ErrCredentialStoreUnavailable, err)
	}
	defer clear(protected)
	plain, err := dpapiTransform(protected, false)
	if err != nil || len(plain) == 0 || plain[0] != 1 || len(plain)-1 > windowsCredentialBlobMaxBytes {
		clear(plain)
		return nil, fmt.Errorf("%w: decrypt credential file: %v", ErrCredentialStoreUnavailable, err)
	}
	result := append([]byte(nil), plain[1:]...)
	clear(plain)
	return result, nil
}

func credentialFilePrivate(path string) bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !windowssecurity.OwnerMatchesSID(path, user.User.Sid) {
		return false
	}
	wantSDDL, err := currentUserCredentialSDDL()
	if err != nil {
		return false
	}
	want, err := windows.SecurityDescriptorFromString(wantSDDL)
	if err != nil {
		return false
	}
	return windowssecurity.ProtectedDACLMatches(path, want.String())
}
