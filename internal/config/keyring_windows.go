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
	if len(value) > windowsCredentialBlobMaxBytes {
		return fmt.Errorf("%w: credential exceeds %d bytes", ErrCredentialStoreUnavailable, windowsCredentialBlobMaxBytes)
	}
	target, err := windowsUTF16(windowsCredentialTarget(ref))
	if err != nil {
		return err
	}
	username, err := windowsUTF16(keyringService)
	if err != nil {
		return err
	}
	blob := []byte(value)
	defer clear(blob)
	credential := windowsCredential{
		Type:               windowsCredentialTypeGeneric,
		TargetName:         target,
		CredentialBlobSize: uint32(len(blob)),
		Persist:            windowsCredentialPersistLocalMachine,
		UserName:           username,
	}
	if len(blob) > 0 {
		credential.CredentialBlob = &blob[0]
	}
	result, _, callErr := procCredWriteW.Call(uintptr(unsafe.Pointer(&credential)), 0)
	if result == 0 {
		return setDPAPISecret(ref, value, callErr)
	}
	_ = deleteDPAPISecret(ref)
	return nil
}

func (KeyringStore) Get(ref string) (string, error) {
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
		return getDPAPISecret(ref, callErr)
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
	return string(secretBytes), nil
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
	dpapiErr := deleteDPAPISecret(ref)
	if result != 0 || errors.Is(callErr, windows.ERROR_NOT_FOUND) || dpapiErr == nil {
		return dpapiErr
	}
	return errors.Join(windowsCredentialError("delete", callErr), dpapiErr)
}
