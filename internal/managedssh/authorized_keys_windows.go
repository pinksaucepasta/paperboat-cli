//go:build windows

package managedssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

const (
	managedAuthorizedKeyMarker = "paperboat-managed-ssh-v1:"
	maxAuthorizedKeysBytes     = 4 << 20
)

var ErrAuthorizedKeysConflict = errors.New("managed SSH authorized_keys reconciliation conflict")

type AuthorizedKeysResult struct {
	Changed bool
	Count   int
}

// ReconcileAuthorizedKeys only replaces Paperboat-marked entries. Existing
// keys, comments, and administrator-managed entries remain byte-for-byte
// unchanged. Existing content must be owned by the enrolled user; an
// administrator-owned file is never modified by Paperboat.
func ReconcileAuthorizedKeys(home string, _ uint32, publicKeys []string) (AuthorizedKeysResult, error) {
	if !filepath.IsAbs(home) || len(publicKeys) > MaxAgentIdentities {
		return AuthorizedKeysResult{}, ErrAuthorizedKeysConflict
	}
	sid, err := currentManagedSSHSID()
	if err != nil {
		return AuthorizedKeysResult{}, err
	}
	home = filepath.Clean(home)
	if err := verifyCurrentUserProfileRoot(home, sid); err != nil {
		return AuthorizedKeysResult{}, ErrAuthorizedKeysConflict
	}
	directory := filepath.Join(home, ".ssh")
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		if err := ensureManagedSSHDirectory(directory, sid); err != nil {
			return AuthorizedKeysResult{}, err
		}
	} else if err != nil {
		return AuthorizedKeysResult{}, err
	} else if err := verifyCurrentUserOwnedPath(directory, sid, true); err != nil {
		return AuthorizedKeysResult{}, ErrAuthorizedKeysConflict
	}
	unlock, err := lockWindowsSSHConfig(directory, sid)
	if err != nil {
		return AuthorizedKeysResult{}, err
	}
	defer unlock()
	existing, exists, err := readWindowsSSHFile(directory, "authorized_keys", sid, false)
	if err != nil {
		return AuthorizedKeysResult{}, ErrAuthorizedKeysConflict
	}
	if !exists {
		existing = nil
	}
	managed, err := canonicalManagedAuthorizedKeys(publicKeys)
	if err != nil {
		return AuthorizedKeysResult{}, err
	}
	next, err := replaceManagedAuthorizedKeys(existing, managed)
	if err != nil {
		return AuthorizedKeysResult{}, err
	}
	result := AuthorizedKeysResult{Changed: !bytes.Equal(existing, next), Count: len(managed)}
	if !result.Changed {
		return result, nil
	}
	if err := writeWindowsAuthorizedKeys(directory, sid, next); err != nil {
		return AuthorizedKeysResult{}, err
	}
	verified, _, err := readWindowsSSHFile(directory, "authorized_keys", sid, false)
	if err != nil || !bytes.Equal(verified, next) {
		return AuthorizedKeysResult{}, errors.Join(ErrAuthorizedKeysConflict, err)
	}
	return result, nil
}

func canonicalManagedAuthorizedKeys(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[[32]byte]bool, len(values))
	for _, value := range values {
		public, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(value))
		if err != nil || public.Type() != ssh.KeyAlgoED25519 || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 || strings.ContainsAny(comment, "\r\n\x00") {
			return nil, ErrAuthorizedKeysConflict
		}
		fingerprint := sha256.Sum256(public.Marshal())
		if seen[fingerprint] {
			return nil, ErrAuthorizedKeysConflict
		}
		seen[fingerprint] = true
		result = append(result, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))+" "+managedAuthorizedKeyMarker+hex.EncodeToString(fingerprint[:]))
	}
	slices.Sort(result)
	return result, nil
}
func replaceManagedAuthorizedKeys(existing []byte, managed []string) ([]byte, error) {
	result := make([]byte, 0, len(existing)+len(managed)*128)
	for _, line := range bytes.SplitAfter(existing, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		if !bytes.Contains(line, []byte(managedAuthorizedKeyMarker)) {
			result = append(result, line...)
			continue
		}
		trimmed := bytes.TrimSuffix(bytes.TrimSuffix(line, []byte{'\n'}), []byte{'\r'})
		public, comment, options, rest, err := ssh.ParseAuthorizedKey(trimmed)
		if err != nil || public.Type() != ssh.KeyAlgoED25519 || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
			return nil, ErrAuthorizedKeysConflict
		}
		fingerprint := sha256.Sum256(public.Marshal())
		if comment != managedAuthorizedKeyMarker+hex.EncodeToString(fingerprint[:]) {
			return nil, ErrAuthorizedKeysConflict
		}
	}
	if len(managed) > 0 {
		if len(result) > 0 && result[len(result)-1] != '\n' {
			result = append(result, '\n')
		}
		for _, line := range managed {
			result = append(result, line...)
			result = append(result, '\n')
		}
	}
	return result, nil
}

func writeWindowsAuthorizedKeys(directory, sid string, value []byte) error {
	path := filepath.Join(directory, "authorized_keys")
	_, exists, err := readWindowsSSHFile(directory, "authorized_keys", sid, false)
	if err != nil {
		return err
	}
	if !exists {
		return writeWindowsOwnedSSHFile(directory, "authorized_keys", sid, value)
	}
	return withManagedSSHOwner(sid, func() error {
		return replaceWindowsAuthorizedKeys(directory, path, sid, value)
	})
}

func replaceWindowsAuthorizedKeys(directory, path, sid string, value []byte) error {
	//paperboat:allow-source-policy atomic-replacement owner=managed-ssh-windows reason=same-directory-acl-protected-authority-staging
	temporary, err := os.CreateTemp(directory, ".paperboat-authorized-keys-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := copyWindowsFileSecurity(path, temporaryPath); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(value); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	verified, exists, err := readWindowsSSHFile(directory, "authorized_keys", sid, false)
	if err != nil || !exists || !bytes.Equal(verified, value) {
		return errors.Join(ErrAuthorizedKeysConflict, err)
	}
	return nil
}

// Keep io imported in this Windows implementation's API surface checks. The
// read path intentionally uses the same bounded reader contract as Unix.
var _ = io.LimitReader
