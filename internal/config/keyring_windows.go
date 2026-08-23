//go:build windows

package config

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsCredentialTypeGeneric         = 1
	windowsCredentialPersistLocalMachine = 2
	windowsCredentialBlobMaxBytes        = 5120
)

var (
	advapi32        = windows.NewLazySystemDLL("advapi32.dll")
	procCredWriteW  = advapi32.NewProc("CredWriteW")
	procCredReadW   = advapi32.NewProc("CredReadW")
	procCredDeleteW = advapi32.NewProc("CredDeleteW")
	procCredFree    = advapi32.NewProc("CredFree")
)

// windowsCredential is CREDENTIALW. CredentialBlob is allocated by the caller
// for writes and by Credential Manager for reads; CredFree releases the latter.
type windowsCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         unsafe.Pointer
	TargetAlias        *uint16
	UserName           *uint16
}

type KeyringStore struct{}

func windowsCredentialTarget(ref string) string {
	return keyringService + ":" + ref
}

func windowsCredentialError(operation string, err error) error {
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return ErrSecretNotFound
	}
	return fmt.Errorf("%w: Credential Manager %s: %v", ErrCredentialStoreUnavailable, operation, err)
}

func windowsUTF16(value string) (*uint16, error) {
	encoded, err := windows.UTF16FromString(value)
	if err != nil {
		return nil, windowsCredentialError("encode credential name", err)
	}
	return &encoded[0], nil
}

func (KeyringStore) Set(ref, value string) error {
	if value == "" {
		return fmt.Errorf("%w: refusing to store an empty credential", ErrCredentialStoreUnavailable)
	}
	if len(value) > windowsCredentialBlobMaxBytes {
		return fmt.Errorf("%w: credential exceeds %d bytes", ErrCredentialStoreUnavailable, windowsCredentialBlobMaxBytes)
	}
	// DPAPI is the sole write authority. Credential Manager is read only as a
	// one-time migration source in Get. A Set therefore has one atomic replace
	// and cannot expose different old/new values to interactive and S4U logons.
	return setDPAPISecret(ref, value, nil)
}

func (KeyringStore) Get(ref string) (string, error) {
	// Prefer the machine-scope DPAPI copy protected by the enrolled owner's
	// exact filesystem ownership and owner/SY/BA ACL so interactive commands,
	// scheduled tasks and the S4U owner workload resolve one durable value.
	// Fall back to Credential Manager for credentials written by older clients.
	value, dpapiErr := getDPAPISecret(ref, nil)
	if dpapiErr == nil {
		if value == "" {
			return "", fmt.Errorf("%w: DPAPI credential is empty", ErrCredentialStoreUnavailable)
		}
		// A previous migration may have published and verified the DPAPI
		// authority before legacy cleanup failed. Retry cleanup on every
		// successful read. Credential Manager is unavailable to logged-out S4U
		// tokens, so cleanup remains best effort and never blocks the authority.
		_ = deleteLegacyWindowsCredential(ref)
		return value, nil
	}
	// Credential Manager is only a migration source for an absent DPAPI
	// credential. Never let a stale legacy value replace a DPAPI file that is
	// present but corrupt, unreadable, or has an invalid ACL.
	if !errors.Is(dpapiErr, ErrSecretNotFound) {
		return "", dpapiErr
	}
	target, err := windowsUTF16(windowsCredentialTarget(ref))
	if err != nil {
		return "", err
	}
	var credential *windowsCredential
	result, _, callErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(target)),
		windowsCredentialTypeGeneric,
		0,
		uintptr(unsafe.Pointer(&credential)),
	)
	if result == 0 {
		return "", windowsCredentialError("read", callErr)
	}
	if credential == nil || credential.CredentialBlobSize > windowsCredentialBlobMaxBytes || (credential.CredentialBlobSize > 0 && credential.CredentialBlob == nil) {
		if credential != nil {
			procCredFree.Call(uintptr(unsafe.Pointer(credential)))
		}
		return "", fmt.Errorf("%w: Credential Manager returned an invalid credential", ErrCredentialStoreUnavailable)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(credential)))
	secretBytes := unsafe.Slice(credential.CredentialBlob, int(credential.CredentialBlobSize))
	defer clear(secretBytes)
	value = string(secretBytes)
	if value == "" {
		return "", fmt.Errorf("%w: Credential Manager credential is empty", ErrCredentialStoreUnavailable)
	}
	// Migrate credentials written by older clients on first successful read.
	// Fail closed if the cross-logon DPAPI copy cannot be established; returning
	// a value that the owner service cannot subsequently read recreates the
	// split-brain profile state this fallback is intended to prevent.
	if err := setDPAPISecret(ref, value, nil); err != nil {
		return "", err
	}
	verified, err := getDPAPISecret(ref, nil)
	if err != nil || verified != value {
		return "", errors.Join(ErrCredentialStoreUnavailable, err)
	}
	// Publishing and verifying v2 commits the migration. Cleanup is retried on
	// every later successful DPAPI read and cannot turn a committed migration
	// into a false failure.
	_ = deleteLegacyWindowsCredential(ref)
	return value, nil
}

func deleteLegacyWindowsCredential(ref string) error {
	target, err := windowsUTF16(windowsCredentialTarget(ref))
	if err != nil {
		return err
	}
	result, _, callErr := procCredDeleteW.Call(
		uintptr(unsafe.Pointer(target)),
		windowsCredentialTypeGeneric,
		0,
	)
	if result == 0 && !errors.Is(callErr, windows.ERROR_NOT_FOUND) {
		return windowsCredentialError("delete migrated credential", callErr)
	}
	return nil
}

func (KeyringStore) Delete(ref string) error {
	target, err := windowsUTF16(windowsCredentialTarget(ref))
	if err != nil {
		return err
	}
	result, _, callErr := procCredDeleteW.Call(
		uintptr(unsafe.Pointer(target)),
		windowsCredentialTypeGeneric,
		0,
	)
	if result == 0 && !errors.Is(callErr, windows.ERROR_NOT_FOUND) {
		// Keep the authoritative DPAPI value when legacy cleanup is uncertain.
		// A retry can safely complete deletion without resurrecting old state.
		return windowsCredentialError("delete", callErr)
	}
	return deleteDPAPISecret(ref)
}
