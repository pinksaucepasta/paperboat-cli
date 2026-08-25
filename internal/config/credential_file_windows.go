//go:build windows

package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

const windowsFileSecretV2FixedHeaderSize = 4 + 1 + 1 + sha256.Size

var windowsFileSecretV2Magic = []byte{'P', 'B', 'F', 'S'}

func windowsFileSecretBinding(path string) ([sha256.Size]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	// Windows paths are case-insensitive. Bind the envelope to one canonical
	// spelling so the same FileSecretStore can read it across process sessions,
	// while moving the blob to another secret reference fails closed.
	canonical := strings.ToLower(filepath.Clean(absolute))
	return sha256.Sum256([]byte(canonical)), nil
}

func windowsFileSecretV2Header(path string, inner bool) ([]byte, error) {
	binding, err := windowsFileSecretBinding(path)
	if err != nil {
		return nil, err
	}
	magic := windowsFileSecretV2Magic
	if inner {
		magic = []byte{'P', 'B', 'F', 'I'}
	}
	header := make([]byte, 0, windowsFileSecretV2FixedHeaderSize)
	header = append(header, magic...)
	header = append(header, 2, 1) // schema v2, CRYPTPROTECT_LOCAL_MACHINE scope
	header = append(header, binding[:]...)
	return header, nil
}

func windowsFileSecretV2Entropy(path string) ([]byte, error) {
	binding, err := windowsFileSecretBinding(path)
	if err != nil {
		return nil, err
	}
	return append([]byte("paperboat/windows-file-secret/v2\x00machine\x00"), binding[:]...), nil
}

func protectWindowsFileSecretV2(path string, value []byte) ([]byte, error) {
	if len(value) > windowsCredentialBlobMaxBytes {
		return nil, ErrCredentialStoreUnavailable
	}
	outer, err := windowsFileSecretV2Header(path, false)
	if err != nil {
		return nil, err
	}
	inner, err := windowsFileSecretV2Header(path, true)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, 0, len(inner)+4+len(value))
	plain = append(plain, inner...)
	plain = binary.LittleEndian.AppendUint32(plain, uint32(len(value)))
	plain = append(plain, value...)
	defer clear(plain)
	entropy, err := windowsFileSecretV2Entropy(path)
	if err != nil {
		return nil, err
	}
	defer clear(entropy)
	protected, err := dpapiTransformWithEntropy(plain, entropy, true, cryptProtectLocalMachine)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(outer)+len(protected))
	result = append(result, outer...)
	result = append(result, protected...)
	clear(protected)
	return result, nil
}

func unprotectWindowsFileSecretV2(path string, protected []byte) ([]byte, error) {
	outer, err := windowsFileSecretV2Header(path, false)
	if err != nil {
		return nil, err
	}
	if len(protected) <= len(outer) || !bytes.Equal(protected[:len(outer)], outer) {
		return nil, fmt.Errorf("%w: unsupported file-secret DPAPI scope, reference, or schema", ErrCredentialStoreUnavailable)
	}
	entropy, err := windowsFileSecretV2Entropy(path)
	if err != nil {
		return nil, err
	}
	defer clear(entropy)
	plain, err := dpapiTransformWithEntropy(protected[len(outer):], entropy, false, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt machine-scope file secret: %v", ErrCredentialStoreUnavailable, err)
	}
	defer clear(plain)
	inner, err := windowsFileSecretV2Header(path, true)
	if err != nil {
		return nil, err
	}
	if len(plain) < len(inner)+4 || !bytes.Equal(plain[:len(inner)], inner) {
		return nil, fmt.Errorf("%w: invalid machine-scope file-secret envelope", ErrCredentialStoreUnavailable)
	}
	valueLength := int(binary.LittleEndian.Uint32(plain[len(inner) : len(inner)+4]))
	value := plain[len(inner)+4:]
	if valueLength != len(value) || valueLength > windowsCredentialBlobMaxBytes {
		return nil, fmt.Errorf("%w: invalid machine-scope file-secret length", ErrCredentialStoreUnavailable)
	}
	return append([]byte(nil), value...), nil
}

func windowsFileSecretLegacyMigrationAllowed() bool {
	var sessionID uint32
	// Since Windows Vista, interactive console and RDP users run outside
	// Session 0. SCM, S4U, scheduled service, and OpenSSH network workloads run
	// in Session 0 and must never attempt user-scope DPAPI migration.
	return windows.ProcessIdToSessionId(uint32(os.Getpid()), &sessionID) == nil && sessionID != 0 && sessionID != ^uint32(0)
}

func migrateLegacyWindowsFileSecret(path string, protected []byte, allowed bool) ([]byte, error) {
	if !allowed {
		return nil, errors.Join(ErrCredentialStoreUnavailable, ErrCredentialRequiresInteractiveLogin, errors.New("legacy user-scope file secret requires an interactive Windows session for migration"))
	}
	plain, err := dpapiTransform(protected, false)
	if err != nil {
		clear(plain)
		return nil, errors.Join(ErrCredentialStoreUnavailable, ErrCredentialRequiresInteractiveLogin, fmt.Errorf("decrypt legacy user-scope file secret: %w", err))
	}
	if len(plain) == 0 || plain[0] != 1 || len(plain)-1 > windowsCredentialBlobMaxBytes {
		clear(plain)
		return nil, fmt.Errorf("%w: invalid legacy user-scope file-secret envelope", ErrCredentialStoreUnavailable)
	}
	result := append([]byte(nil), plain[1:]...)
	clear(plain)
	if err := writeCredentialFile(path, result); err != nil {
		clear(result)
		return nil, errors.Join(ErrCredentialStoreUnavailable, fmt.Errorf("migrate legacy user-scope file secret: %w", err))
	}
	return result, nil
}

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
	protected, err := protectWindowsFileSecretV2(path, value)
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
	if err != nil || len(protected) == 0 || len(protected) > windowsCredentialBlobMaxBytes*4+windowsFileSecretV2FixedHeaderSize {
		return nil, errors.Join(ErrCredentialStoreUnavailable, err)
	}
	defer clear(protected)
	if bytes.HasPrefix(protected, windowsFileSecretV2Magic) {
		return unprotectWindowsFileSecretV2(path, protected)
	}
	return migrateLegacyWindowsFileSecret(path, protected, windowsFileSecretLegacyMigrationAllowed())
}

func credentialFilePrivate(path string) bool {
	token, err := currentEffectiveUserToken()
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
