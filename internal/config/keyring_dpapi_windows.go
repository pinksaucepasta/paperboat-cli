//go:build windows

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"golang.org/x/sys/windows"
)

const cryptProtectUIForbidden = 1

func dpapiSecretPath(ref string) (string, string, error) {
	if ref == "" || len(ref) > 1024 || strings.ContainsAny(ref, "\x00\r\n") {
		return "", "", ErrCredentialStoreUnavailable
	}
	base := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if base == "" || !filepath.IsAbs(base) {
		return "", "", ErrCredentialStoreUnavailable
	}
	directory := filepath.Join(filepath.Clean(base), "Paperboat", "credentials")
	digest := sha256.Sum256([]byte(ref))
	return filepath.Join(directory, hex.EncodeToString(digest[:])+".dpapi"), directory, nil
}

func currentUserCredentialSDDL() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return "", fmt.Errorf("%w: resolve current Windows SID: %v", ErrCredentialStoreUnavailable, err)
	}
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")", nil
}

func ensureDPAPIDirectory(path, sddl string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrCredentialStoreUnavailable, err)
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(ErrCredentialStoreUnavailable, err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	abs, err := descriptor.ToAbsolute()
	if err != nil {
		return err
	}
	dacl, _, err := abs.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func dpapiTransform(value []byte, protect bool) ([]byte, error) {
	input := windows.DataBlob{Size: uint32(len(value))}
	if len(value) > 0 {
		input.Data = &value[0]
	}
	entropyBytes := []byte("paperboat/windows-keyring/v1")
	entropy := windows.DataBlob{Size: uint32(len(entropyBytes)), Data: &entropyBytes[0]}
	var output windows.DataBlob
	var err error
	if protect {
		err = windows.CryptProtectData(&input, nil, &entropy, 0, nil, cryptProtectUIForbidden, &output)
	} else {
		err = windows.CryptUnprotectData(&input, nil, &entropy, 0, nil, cryptProtectUIForbidden, &output)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(output.Data))))
	if output.Size > windowsCredentialBlobMaxBytes*4 || output.Size > 0 && output.Data == nil {
		return nil, ErrCredentialStoreUnavailable
	}
	result := append([]byte(nil), unsafe.Slice(output.Data, int(output.Size))...)
	return result, nil
}

func setDPAPISecret(ref, value string, credentialErr error) error {
	path, directory, err := dpapiSecretPath(ref)
	if err != nil {
		return errors.Join(windowsCredentialError("write", credentialErr), err)
	}
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		return errors.Join(windowsCredentialError("write", credentialErr), err)
	}
	if err := ensureDPAPIDirectory(directory, sddl); err != nil {
		return errors.Join(windowsCredentialError("write", credentialErr), err)
	}
	plain := make([]byte, len(value)+1)
	plain[0] = 1
	copy(plain[1:], value)
	defer clear(plain)
	protected, err := dpapiTransform(plain, true)
	if err != nil {
		return errors.Join(windowsCredentialError("write", credentialErr), err)
	}
	defer clear(protected)
	if err := atomicfile.Write(path, protected, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: sddl}); err != nil {
		return fmt.Errorf("%w: write DPAPI credential: %v", ErrCredentialStoreUnavailable, err)
	}
	return nil
}

func getDPAPISecret(ref string, credentialErr error) (string, error) {
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		return "", err
	}
	protected, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrSecretNotFound
	}
	if err != nil || len(protected) == 0 || len(protected) > windowsCredentialBlobMaxBytes*4 {
		return "", fmt.Errorf("%w: read DPAPI credential: %v", ErrCredentialStoreUnavailable, err)
	}
	defer clear(protected)
	plain, err := dpapiTransform(protected, false)
	if err != nil || len(plain) == 0 || plain[0] != 1 || len(plain)-1 > windowsCredentialBlobMaxBytes {
		return "", fmt.Errorf("%w: decrypt DPAPI credential: %v", ErrCredentialStoreUnavailable, err)
	}
	defer clear(plain)
	return string(plain[1:]), nil
}

func deleteDPAPISecret(ref string) error {
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
