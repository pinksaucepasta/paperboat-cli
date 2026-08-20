//go:build windows

package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

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

func TestWindowsCredentialManagerRoundTrip(t *testing.T) {
	ref := fmt.Sprintf("native-test-%d", time.Now().UnixNano())
	store := KeyringStore{}
	t.Cleanup(func() { _ = store.Delete(ref) })
	for _, value := range []string{"", "paperboat windows credential", "Unicode: नौका 🚤"} {
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

func TestWindowsCredentialErrorClassification(t *testing.T) {
	if err := windowsCredentialError("read", windows.ERROR_NOT_FOUND); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("not-found error = %v, want ErrSecretNotFound", err)
	}
	if err := windowsCredentialError("read", windows.ERROR_ACCESS_DENIED); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("service error = %v, want ErrCredentialStoreUnavailable", err)
	}
}
