//go:build windows

package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWindowsFileSecretUsesMachineScopeReferenceBoundEnvelope(t *testing.T) {
	store := FileSecretStore{Dir: t.TempDir()}
	ref := fmt.Sprintf("machine-file-secret-%d", time.Now().UnixNano())
	want := "paperboat logged-out S4U transfer key"
	if err := store.Set(ref, want); err != nil {
		t.Fatal(err)
	}
	path := store.path(ref)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	header, err := windowsFileSecretV2Header(path, false)
	if err != nil || !bytes.HasPrefix(body, header) || bytes.Contains(body, []byte(want)) {
		t.Fatalf("file-secret v2 envelope header=%t plaintext=%t err=%v", bytes.HasPrefix(body, header), bytes.Contains(body, []byte(want)), err)
	}
	if got, err := store.Get(ref); err != nil || got != want {
		t.Fatalf("machine-scope round trip value=%q err=%v", got, err)
	}

	otherRef := ref + "-other"
	if err := store.Set(otherRef, "placeholder"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.path(otherRef), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(otherRef); got != "" || !errors.Is(err, ErrCredentialStoreUnavailable) || errors.Is(err, ErrCredentialRequiresInteractiveLogin) {
		t.Fatalf("wrong-reference envelope value=%q err=%v", got, err)
	}

	tampered := append([]byte(nil), body...)
	tampered[len(tampered)-1] ^= 0xff
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(ref); got != "" || !errors.Is(err, ErrCredentialStoreUnavailable) || errors.Is(err, ErrCredentialRequiresInteractiveLogin) {
		t.Fatalf("tampered v2 envelope value=%q err=%v", got, err)
	}
}

func TestWindowsFileSecretMigratesReadableUserScopeV1(t *testing.T) {
	store := FileSecretStore{Dir: t.TempDir()}
	ref := fmt.Sprintf("legacy-file-secret-%d", time.Now().UnixNano())
	if err := store.Set(ref, "placeholder"); err != nil {
		t.Fatal(err)
	}
	want := "legacy interactive secret"
	plain := append([]byte{1}, []byte(want)...)
	legacy, err := dpapiTransform(plain, true)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(legacy)
	path := store.path(ref)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := migrateLegacyWindowsFileSecret(path, legacy, true)
	if err != nil || string(got) != want {
		t.Fatalf("legacy migration value=%q err=%v", got, err)
	}
	clear(got)
	body, err := os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(body, windowsFileSecretV2Magic) {
		t.Fatalf("legacy file secret was not rewritten as machine-scope v2: %v", err)
	}
	if got, err := store.Get(ref); err != nil || got != want {
		t.Fatalf("migrated machine-scope value=%q err=%v", got, err)
	}
}

func TestWindowsFileSecretUnreadableV1RequiresInteractiveLogin(t *testing.T) {
	store := FileSecretStore{Dir: t.TempDir()}
	ref := fmt.Sprintf("unreadable-file-secret-%d", time.Now().UnixNano())
	if err := store.Set(ref, "placeholder"); err != nil {
		t.Fatal(err)
	}
	path := store.path(ref)
	legacy := []byte("legacy-user-scope-ciphertext")
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := migrateLegacyWindowsFileSecret(path, legacy, true)
	if len(got) != 0 || !errors.Is(err, ErrCredentialStoreUnavailable) || !errors.Is(err, ErrCredentialRequiresInteractiveLogin) || !strings.Contains(err.Error(), "legacy user-scope file secret") {
		t.Fatalf("unreadable v1 value=%q err=%v", got, err)
	}
}

func TestWindowsFileSecretNonInteractiveV1FailsClosed(t *testing.T) {
	store := FileSecretStore{Dir: t.TempDir()}
	ref := fmt.Sprintf("noninteractive-file-secret-%d", time.Now().UnixNano())
	if err := store.Set(ref, "placeholder"); err != nil {
		t.Fatal(err)
	}
	plain := append([]byte{1}, []byte("legacy-must-not-open-under-s4u")...)
	legacy, err := dpapiTransform(plain, true)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(legacy)
	path := store.path(ref)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := migrateLegacyWindowsFileSecret(path, legacy, false)
	if len(got) != 0 || !errors.Is(err, ErrCredentialStoreUnavailable) || !errors.Is(err, ErrCredentialRequiresInteractiveLogin) {
		t.Fatalf("noninteractive v1 value=%q err=%v", got, err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(after, legacy) {
		t.Fatalf("rejected noninteractive v1 credential was changed: %v", readErr)
	}
}
