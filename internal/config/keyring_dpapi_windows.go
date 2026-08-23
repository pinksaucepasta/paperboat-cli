//go:build windows

package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

const (
	cryptProtectUIForbidden  = 1
	cryptProtectLocalMachine = 4
)

var keyringDPAPIV2Magic = []byte{'P', 'B', 'K', 'R'}

const keyringDPAPIV2FixedHeaderSize = 4 + 1 + 1 + sha256.Size

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
	sid, err := currentUserSID()
	if err != nil {
		return "", err
	}
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sid.String() + ")", nil
}

func currentUserSID() (*windows.SID, error) {
	token, err := currentEffectiveUserToken()
	if err != nil {
		return nil, fmt.Errorf("%w: open current Windows token: %v", ErrCredentialStoreUnavailable, err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, fmt.Errorf("%w: resolve current Windows SID: %v", ErrCredentialStoreUnavailable, err)
	}
	return user.User.Sid, nil
}

func currentEffectiveUserToken() (windows.Token, error) {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if err == nil {
		return token, nil
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		return 0, err
	}
	return windows.OpenCurrentProcessToken()
}

func ensureDPAPIDirectory(path, sddl string) error {
	_, statErr := os.Lstat(path)
	existed := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
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
	ownerSID, err := currentUserSID()
	if err != nil {
		return err
	}
	if !windowssecurity.OwnerMatchesSID(path, ownerSID) && existed {
		return fmt.Errorf("%w: refusing to change a foreign-owned credential directory", ErrCredentialStoreUnavailable)
	}
	if !windowssecurity.OwnerMatchesSID(path, ownerSID) {
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, ownerSID, nil, nil, nil); err != nil {
			return err
		}
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
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	if !credentialFilePrivate(path) {
		return fmt.Errorf("%w: credential directory owner or ACL is invalid", ErrCredentialStoreUnavailable)
	}
	return nil
}

func dpapiTransformWithEntropy(value, entropyBytes []byte, protect bool, protectFlags uint32) ([]byte, error) {
	input := windows.DataBlob{Size: uint32(len(value))}
	if len(value) > 0 {
		input.Data = &value[0]
	}
	entropy := windows.DataBlob{Size: uint32(len(entropyBytes)), Data: &entropyBytes[0]}
	var output windows.DataBlob
	var err error
	if protect {
		err = windows.CryptProtectData(&input, nil, &entropy, 0, nil, cryptProtectUIForbidden|protectFlags, &output)
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

func dpapiTransform(value []byte, protect bool) ([]byte, error) {
	return dpapiTransformWithEntropy(value, []byte("paperboat/windows-keyring/v1"), protect, 0)
}

func keyringDPAPIV2Entropy(ref string) []byte {
	return append([]byte("paperboat/windows-keyring/v2\x00machine\x00"), keyringDPAPIV2RefHash(ref)...)
}

func keyringDPAPIV2RefHash(ref string) []byte {
	digest := sha256.Sum256([]byte(ref))
	return digest[:]
}

func keyringDPAPIV2Header(ref string, inner bool) []byte {
	magic := keyringDPAPIV2Magic
	if inner {
		magic = []byte{'P', 'B', 'K', 'I'}
	}
	header := make([]byte, 0, keyringDPAPIV2FixedHeaderSize)
	header = append(header, magic...)
	header = append(header, 2, 1) // schema v2, CRYPTPROTECT_LOCAL_MACHINE scope
	header = append(header, keyringDPAPIV2RefHash(ref)...)
	return header
}

func protectKeyringDPAPIV2(ref, value string) ([]byte, error) {
	innerHeader := keyringDPAPIV2Header(ref, true)
	plain := make([]byte, 0, len(innerHeader)+4+len(value))
	plain = append(plain, innerHeader...)
	plain = binary.LittleEndian.AppendUint32(plain, uint32(len(value)))
	plain = append(plain, value...)
	defer clear(plain)
	protected, err := dpapiTransformWithEntropy(plain, keyringDPAPIV2Entropy(ref), true, cryptProtectLocalMachine)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, keyringDPAPIV2FixedHeaderSize+len(protected))
	result = append(result, keyringDPAPIV2Header(ref, false)...)
	result = append(result, protected...)
	clear(protected)
	return result, nil
}

func unprotectKeyringDPAPIV2(ref string, protected []byte) (string, error) {
	outerHeader := keyringDPAPIV2Header(ref, false)
	if len(protected) <= len(outerHeader) || !bytes.Equal(protected[:len(outerHeader)], outerHeader) {
		return "", fmt.Errorf("%w: unsupported DPAPI credential scope or schema", ErrCredentialStoreUnavailable)
	}
	plain, err := dpapiTransformWithEntropy(protected[len(outerHeader):], keyringDPAPIV2Entropy(ref), false, 0)
	if err != nil {
		return "", fmt.Errorf("%w: decrypt machine-scope DPAPI credential: %v", ErrCredentialStoreUnavailable, err)
	}
	defer clear(plain)
	innerHeader := keyringDPAPIV2Header(ref, true)
	if len(plain) < len(innerHeader)+4 || !bytes.Equal(plain[:len(innerHeader)], innerHeader) {
		return "", fmt.Errorf("%w: invalid machine-scope DPAPI credential envelope", ErrCredentialStoreUnavailable)
	}
	valueLength := int(binary.LittleEndian.Uint32(plain[len(innerHeader) : len(innerHeader)+4]))
	value := plain[len(innerHeader)+4:]
	if valueLength == 0 || valueLength != len(value) || valueLength > windowsCredentialBlobMaxBytes {
		return "", fmt.Errorf("%w: invalid machine-scope DPAPI credential length", ErrCredentialStoreUnavailable)
	}
	return string(value), nil
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
	if err := ensureDPAPIDirectory(filepath.Dir(directory), sddl); err != nil {
		return errors.Join(windowsCredentialError("write", credentialErr), err)
	}
	if err := ensureDPAPIDirectory(directory, sddl); err != nil {
		return errors.Join(windowsCredentialError("write", credentialErr), err)
	}
	protected, err := protectKeyringDPAPIV2(ref, value)
	if err != nil {
		return errors.Join(windowsCredentialError("write", credentialErr), err)
	}
	defer clear(protected)
	if err := atomicfile.Write(path, protected, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: sddl}); err != nil {
		return fmt.Errorf("%w: write DPAPI credential: %v", ErrCredentialStoreUnavailable, err)
	}
	ownerSID, err := currentUserSID()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, ownerSID, nil, nil, nil); err != nil {
		return fmt.Errorf("%w: set DPAPI credential owner: %v", ErrCredentialStoreUnavailable, err)
	}
	if !credentialFilePrivate(path) {
		return fmt.Errorf("%w: written DPAPI credential owner or ACL is invalid", ErrCredentialStoreUnavailable)
	}
	return nil
}

func getDPAPISecret(ref string, credentialErr error) (string, error) {
	path, directory, err := dpapiSecretPath(ref)
	if err != nil {
		return "", err
	}
	if err := validateCredentialDirectory(directory); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrSecretNotFound
		}
		return "", errors.Join(ErrCredentialStoreUnavailable, err)
	}
	if err := validateCredentialDirectory(filepath.Dir(directory)); err != nil {
		return "", errors.Join(ErrCredentialStoreUnavailable, err)
	}
	// v1 protected only the credentials directory. On upgrade, an ordinary
	// owner-owned, non-reparse Paperboat root can be hardened in place before
	// decrypting the legacy blob. ensureDPAPIDirectory checks ownership before
	// changing the DACL, so foreign-owned roots remain untouched and rejected.
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		return "", err
	}
	if err := ensureDPAPIDirectory(filepath.Dir(directory), sddl); err != nil {
		return "", errors.Join(ErrCredentialStoreUnavailable, err)
	}
	if !credentialFilePrivate(filepath.Dir(directory)) {
		return "", fmt.Errorf("%w: DPAPI credential root has an invalid owner or ACL", ErrCredentialStoreUnavailable)
	}
	if !credentialFilePrivate(directory) {
		return "", fmt.Errorf("%w: DPAPI credential directory has an invalid owner or ACL", ErrCredentialStoreUnavailable)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrSecretNotFound
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !credentialFilePrivate(path) {
		return "", errors.Join(ErrCredentialStoreUnavailable, err)
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", errors.Join(ErrCredentialStoreUnavailable, err)
	}
	protected, err := os.ReadFile(path)
	if err != nil || len(protected) == 0 || len(protected) > windowsCredentialBlobMaxBytes*4 {
		return "", fmt.Errorf("%w: read DPAPI credential: %v", ErrCredentialStoreUnavailable, err)
	}
	defer clear(protected)
	if bytes.HasPrefix(protected, []byte{'P', 'B', 'K', 'R'}) {
		return unprotectKeyringDPAPIV2(ref, protected)
	}
	plain, err := dpapiTransform(protected, false)
	if err != nil {
		return "", errors.Join(ErrCredentialStoreUnavailable, ErrCredentialRequiresInteractiveLogin, fmt.Errorf("decrypt legacy user-scope DPAPI credential: %w", err))
	}
	defer clear(plain)
	if len(plain) <= 1 || plain[0] != 1 || len(plain)-1 > windowsCredentialBlobMaxBytes {
		return "", fmt.Errorf("%w: invalid legacy user-scope DPAPI credential envelope", ErrCredentialStoreUnavailable)
	}
	value := string(plain[1:])
	if err := setDPAPISecret(ref, value, credentialErr); err != nil {
		return "", errors.Join(ErrCredentialStoreUnavailable, fmt.Errorf("migrate legacy user-scope DPAPI credential: %w", err))
	}
	return value, nil
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
