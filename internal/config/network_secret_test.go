package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type failingCredentialLock struct{ unlock error }

func (f failingCredentialLock) Lock() error   { return nil }
func (f failingCredentialLock) Unlock() error { return f.unlock }

func TestNetworkFingerprintSecretIsDurableAndConcurrent(t *testing.T) {
	root := t.TempDir()
	store := ProfileStore{Path: root, Secrets: FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	const callers = 32
	values := make(chan []byte, callers)
	errs := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, err := store.NetworkFingerprintSecret()
			values <- value
			errs <- err
		}()
	}
	wait.Wait()
	close(values)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var expected []byte
	for value := range values {
		if len(value) != networkFingerprintSecretBytes {
			t.Fatalf("secret length=%d", len(value))
		}
		if expected == nil {
			expected = value
		} else if !bytes.Equal(value, expected) {
			t.Fatal("concurrent callers observed different secrets")
		}
	}
	reloaded, err := store.NetworkFingerprintSecret()
	if err != nil || !bytes.Equal(reloaded, expected) {
		t.Fatalf("reloaded secret differs: %v", err)
	}
}

func TestNetworkFingerprintSecretRejectsCorruptStoredValue(t *testing.T) {
	root := t.TempDir()
	secrets := FileSecretStore{Dir: filepath.Join(root, "secrets")}
	store := ProfileStore{Path: root, Secrets: secrets}
	refDigest := sha256Sum(root)
	ref := "network-fingerprint-v1-" + refDigest
	if err := secrets.Set(ref, base64.RawURLEncoding.EncodeToString(make([]byte, networkFingerprintSecretBytes-1))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.NetworkFingerprintSecret(); err == nil {
		t.Fatal("corrupt secret was replaced instead of rejected")
	}
	entries, err := os.ReadDir(secrets.Dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("secret files=%d err=%v", len(entries), err)
	}
}

func TestNetworkFingerprintSecretErasesResultWhenUnlockFails(t *testing.T) {
	root := t.TempDir()
	secrets := FileSecretStore{Dir: filepath.Join(root, "secrets")}
	store := ProfileStore{Path: root, Secrets: secrets}
	want := errors.New("unlock failed")

	created, err := store.networkFingerprintSecret(root, failingCredentialLock{unlock: want})
	if !errors.Is(err, want) || created != nil {
		t.Fatalf("created=%x error=%v", created, err)
	}
	loaded, err := store.networkFingerprintSecret(root, failingCredentialLock{unlock: want})
	if !errors.Is(err, want) || loaded != nil {
		t.Fatalf("loaded=%x error=%v", loaded, err)
	}
}

func sha256Sum(root string) string {
	digest := sha256.Sum256([]byte(filepath.Clean(root)))
	return hex.EncodeToString(digest[:16])
}
