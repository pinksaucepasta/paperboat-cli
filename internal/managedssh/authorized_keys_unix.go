//go:build darwin || linux

package managedssh

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
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

func ReconcileAuthorizedKeys(home string, ownerUID uint32, publicKeys []string) (AuthorizedKeysResult, error) {
	if !filepath.IsAbs(home) || len(publicKeys) > MaxAgentIdentities {
		return AuthorizedKeysResult{}, ErrAuthorizedKeysConflict
	}
	home = filepath.Clean(home)
	if err := validateOwnedDirectory(home, ownerUID, false); err != nil {
		return AuthorizedKeysResult{}, err
	}
	sshDirectory := filepath.Join(home, ".ssh")
	createdDirectory := false
	if err := os.Mkdir(sshDirectory, 0o700); err == nil {
		createdDirectory = true
	} else if !os.IsExist(err) {
		return AuthorizedKeysResult{}, fmt.Errorf("create .ssh directory: %w", err)
	}
	if createdDirectory {
		if err := os.Chown(sshDirectory, int(ownerUID), -1); err != nil {
			return AuthorizedKeysResult{}, fmt.Errorf("own .ssh directory: %w", err)
		}
	}
	if err := validateOwnedDirectory(sshDirectory, ownerUID, true); err != nil {
		return AuthorizedKeysResult{}, err
	}
	directoryFD, err := unix.Open(sshDirectory, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return AuthorizedKeysResult{}, fmt.Errorf("open .ssh directory: %w", err)
	}
	defer unix.Close(directoryFD)
	lockFD, createdLock, err := openAuthorizedKeysLock(directoryFD)
	if err != nil {
		return AuthorizedKeysResult{}, fmt.Errorf("open authorized_keys lock: %w", err)
	}
	defer unix.Close(lockFD)
	if createdLock {
		if err := unix.Fchown(lockFD, int(ownerUID), -1); err != nil {
			return AuthorizedKeysResult{}, fmt.Errorf("own authorized_keys lock: %w", err)
		}
		if err := unix.Fchmod(lockFD, 0o600); err != nil {
			return AuthorizedKeysResult{}, fmt.Errorf("protect authorized_keys lock: %w", err)
		}
	}
	if err := secureOwnedFileDescriptor(lockFD, ownerUID); err != nil {
		return AuthorizedKeysResult{}, fmt.Errorf("validate authorized_keys lock: %w", err)
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX); err != nil {
		return AuthorizedKeysResult{}, fmt.Errorf("lock authorized_keys: %w", err)
	}
	defer unix.Flock(lockFD, unix.LOCK_UN)

	existing, err := readAuthorizedKeysAt(directoryFD, ownerUID)
	if err != nil {
		return AuthorizedKeysResult{}, err
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
	if err := writeAuthorizedKeysAt(directoryFD, ownerUID, next); err != nil {
		return AuthorizedKeysResult{}, err
	}
	verified, err := readAuthorizedKeysAt(directoryFD, ownerUID)
	if err != nil || !bytes.Equal(verified, next) {
		return AuthorizedKeysResult{}, errors.Join(ErrAuthorizedKeysConflict, err)
	}
	return result, nil
}

func openAuthorizedKeysLock(directoryFD int) (int, bool, error) {
	fd, err := unix.Openat(directoryFD, ".paperboat-authorized-keys.lock", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err == nil {
		return fd, true, nil
	}
	if !errors.Is(err, unix.EEXIST) {
		return -1, false, err
	}
	fd, err = unix.Openat(directoryFD, ".paperboat-authorized-keys.lock", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	return fd, false, err
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
		canonical := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
		result = append(result, canonical+" "+managedAuthorizedKeyMarker+hex.EncodeToString(fingerprint[:]))
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
		trimmed := bytes.TrimSuffix(line, []byte{'\n'})
		trimmed = bytes.TrimSuffix(trimmed, []byte{'\r'})
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

func validateOwnedDirectory(path string, ownerUID uint32, strictMode bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	modeValid := info.Mode().Perm()&0o022 == 0
	if strictMode {
		modeValid = info.Mode().Perm() == 0o700
	}
	if !ok || !info.IsDir() || stat.Uid != ownerUID || !modeValid {
		return ErrAuthorizedKeysConflict
	}
	return nil
}

func secureOwnedFileDescriptor(fd int, ownerUID uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid != ownerUID || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 {
		return ErrAuthorizedKeysConflict
	}
	return nil
}

func readAuthorizedKeysAt(directoryFD int, ownerUID uint32) ([]byte, error) {
	fd, err := unix.Openat(directoryFD, "authorized_keys", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open authorized_keys: %w", err)
	}
	file := os.NewFile(uintptr(fd), "authorized_keys")
	defer file.Close()
	if err := secureOwnedFileDescriptor(fd, ownerUID); err != nil {
		return nil, fmt.Errorf("validate authorized_keys: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAuthorizedKeysBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read authorized_keys: %w", err)
	}
	if len(data) > maxAuthorizedKeysBytes || bytes.IndexByte(data, 0) >= 0 {
		return nil, ErrAuthorizedKeysConflict
	}
	return data, nil
}

func writeAuthorizedKeysAt(directoryFD int, ownerUID uint32, value []byte) error {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := ".paperboat-authorized-keys-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(directoryFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create authorized_keys replacement: %w", err)
	}
	cleanup := true
	defer func() {
		_ = unix.Close(fd)
		if cleanup {
			_ = unix.Unlinkat(directoryFD, temporary, 0)
		}
	}()
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return err
	}
	if err := unix.Fchown(fd, int(ownerUID), -1); err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	if _, err := file.Write(value); err != nil {
		return fmt.Errorf("write authorized_keys replacement: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync authorized_keys replacement: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	fd = -1
	if err := unix.Renameat(directoryFD, temporary, directoryFD, "authorized_keys"); err != nil {
		return fmt.Errorf("publish authorized_keys replacement: %w", err)
	}
	cleanup = false
	if err := unix.Fsync(directoryFD); err != nil {
		return fmt.Errorf("sync .ssh directory: %w", err)
	}
	return nil
}
