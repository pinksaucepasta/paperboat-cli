//go:build windows

package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsCredentialTargetUsesPrivateNamespace(t *testing.T) {
	if got, want := windowsCredentialTarget("access-token-v1-123"), "paperboat:access-token-v1-123"; got != want {
		t.Fatalf("credential target = %q, want %q", got, want)
	}
}

func TestWindowsFileFallbackIsDPAPIProtected(t *testing.T) {
	directory := t.TempDir()
	store := FileSecretStore{Dir: directory}
	ref, secret := "fallback-native", "must-not-appear-in-plaintext-नौका"
	if err := store.Set(ref, secret); err != nil {
		t.Fatalf("set protected fallback: %v", err)
	}
	body, err := os.ReadFile(store.path(ref))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(secret)) {
		t.Fatal("protected credential contains plaintext")
	}
	actual, err := store.Get(ref)
	if err != nil || actual != secret {
		t.Fatalf("get protected fallback = %q, %v", actual, err)
	}
}

func TestWindowsDPAPIAuthorityRoundTrip(t *testing.T) {
	ref := fmt.Sprintf("native-test-%d", time.Now().UnixNano())
	store := KeyringStore{}
	t.Cleanup(func() { _ = store.Delete(ref) })
	for _, value := range []string{"paperboat windows credential", "Unicode: नौका 🚤"} {
		if err := store.Set(ref, value); err != nil {
			t.Fatalf("set credential: %v", err)
		}
		actual, err := store.Get(ref)
		if err != nil || actual != value {
			t.Fatalf("get credential = %q, %v; want %q", actual, err, value)
		}
	}
	if err := store.Delete(ref); err != nil {
		t.Fatalf("delete credential: %v", err)
	}
	if _, err := store.Get(ref); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("read deleted credential: %v", err)
	}
	if err := store.Delete(ref); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestWindowsDPAPIAuthorityRejectsEmptyCredential(t *testing.T) {
	ref := fmt.Sprintf("native-empty-%d", time.Now().UnixNano())
	store := KeyringStore{}
	if err := store.Set(ref, ""); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("empty credential error = %v", err)
	}
	if _, err := store.Get(ref); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("empty credential was persisted: %v", err)
	}
}

func writeLegacyWindowsCredential(t *testing.T, ref, value string) {
	t.Helper()
	target, err := windowsUTF16(windowsCredentialTarget(ref))
	if err != nil {
		t.Fatal(err)
	}
	username, err := windowsUTF16(keyringService)
	if err != nil {
		t.Fatal(err)
	}
	blob := []byte(value)
	defer clear(blob)
	credential := windowsCredential{Type: windowsCredentialTypeGeneric, TargetName: target, CredentialBlobSize: uint32(len(blob)), Persist: windowsCredentialPersistLocalMachine, UserName: username}
	if len(blob) > 0 {
		credential.CredentialBlob = &blob[0]
	}
	if result, _, callErr := procCredWriteW.Call(uintptr(unsafe.Pointer(&credential)), 0); result == 0 {
		t.Fatalf("write legacy Credential Manager value: %v", callErr)
	}
}

func TestWindowsCredentialFallsBackAcrossCredentialManagerContexts(t *testing.T) {
	ref := fmt.Sprintf("native-context-fallback-%d", time.Now().UnixNano())
	store := KeyringStore{}
	t.Cleanup(func() { _ = store.Delete(ref) })
	if err := store.Set(ref, "owner-scoped-secret"); err != nil {
		t.Fatalf("set credential: %v", err)
	}
	target, err := windowsUTF16(windowsCredentialTarget(ref))
	if err != nil {
		t.Fatal(err)
	}
	result, _, callErr := procCredDeleteW.Call(uintptr(unsafe.Pointer(target)), windowsCredentialTypeGeneric, 0)
	if result == 0 && !errors.Is(callErr, windows.ERROR_NOT_FOUND) {
		t.Fatalf("remove Credential Manager copy: %v", callErr)
	}
	actual, err := store.Get(ref)
	if err != nil || actual != "owner-scoped-secret" {
		t.Fatalf("DPAPI fallback = %q, %v", actual, err)
	}
}

func TestWindowsLegacyCredentialManagerReadBackfillsDPAPI(t *testing.T) {
	ref := fmt.Sprintf("native-legacy-migration-%d", time.Now().UnixNano())
	store := KeyringStore{}
	t.Cleanup(func() { _ = store.Delete(ref) })
	writeLegacyWindowsCredential(t, ref, "legacy-secret")
	actual, err := store.Get(ref)
	if err != nil || actual != "legacy-secret" {
		t.Fatalf("legacy Credential Manager read = %q, %v", actual, err)
	}
	if migrated, err := getDPAPISecret(ref, nil); err != nil || migrated != actual {
		t.Fatalf("migrated DPAPI value = %q, %v", migrated, err)
	}
	target, err := windowsUTF16(windowsCredentialTarget(ref))
	if err != nil {
		t.Fatal(err)
	}
	var credential *windowsCredential
	result, _, callErr := procCredReadW.Call(uintptr(unsafe.Pointer(target)), windowsCredentialTypeGeneric, 0, uintptr(unsafe.Pointer(&credential)))
	if result != 0 {
		procCredFree.Call(uintptr(unsafe.Pointer(credential)))
		t.Fatal("legacy Credential Manager value remained after migration")
	}
	if !errors.Is(callErr, windows.ERROR_NOT_FOUND) {
		t.Fatalf("read migrated Credential Manager value: %v", callErr)
	}
}

func TestWindowsCredentialManagerCannotReplaceInvalidDPAPIAuthority(t *testing.T) {
	ref := fmt.Sprintf("native-invalid-authority-%d", time.Now().UnixNano())
	store := KeyringStore{}
	t.Cleanup(func() { _ = store.Delete(ref) })
	if err := store.Set(ref, "authoritative-secret"); err != nil {
		t.Fatal(err)
	}
	writeLegacyWindowsCredential(t, ref, "stale-legacy-secret")
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := store.Get(ref); value != "" || !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("invalid DPAPI authority returned value=%q error=%v", value, err)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "corrupt" {
		t.Fatalf("invalid DPAPI authority was overwritten: body=%q error=%v", body, err)
	}
}

func TestWindowsLegacyEmptyCredentialIsNotMigrated(t *testing.T) {
	ref := fmt.Sprintf("native-empty-legacy-%d", time.Now().UnixNano())
	store := KeyringStore{}
	t.Cleanup(func() { _ = store.Delete(ref) })
	writeLegacyWindowsCredential(t, ref, "")
	if _, err := store.Get(ref); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("empty legacy credential error = %v", err)
	}
	if _, err := getDPAPISecret(ref, nil); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("empty legacy credential was migrated: %v", err)
	}
}

func TestWindowsCredentialErrorClassification(t *testing.T) {
	if err := windowsCredentialError("read", windows.ERROR_NOT_FOUND); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("not-found error = %v, want ErrSecretNotFound", err)
	}
	if err := windowsCredentialError("read", windows.ERROR_ACCESS_DENIED); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("service error = %v, want ErrCredentialStoreUnavailable", err)
	}
}
