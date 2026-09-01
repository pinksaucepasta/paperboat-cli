//go:build linux

package environmentkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type reversibleCredentialRunner struct{}

func (reversibleCredentialRunner) Run(_ context.Context, arguments []string, stdin []byte, _ int64) ([]byte, error) {
	if len(arguments) == 1 && arguments[0] == "setup" {
		return []byte("ok"), nil
	}
	if len(arguments) > 0 && arguments[0] == "encrypt" {
		return []byte("opaque:" + base64.RawURLEncoding.EncodeToString(stdin)), nil
	}
	if len(arguments) > 0 && arguments[0] == "decrypt" && bytes.HasPrefix(stdin, []byte("opaque:")) {
		return base64.RawURLEncoding.Strict().DecodeString(string(bytes.TrimPrefix(stdin, []byte("opaque:"))))
	}
	return nil, errors.New("unexpected credential command")
}

type failingCredentialWriter struct{ calls int }

func (w *failingCredentialWriter) Write(string, []byte) error {
	w.calls++
	return errors.New("injected atomic replacement failure")
}

func TestSystemdCredentialGenerationReplacementHasOneAtomicWriteBoundary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership is part of the system credential contract")
	}
	directory := t.TempDir()
	ciphertextPath := filepath.Join(directory, "host-key.cred")
	metadataPath := filepath.Join(directory, "host-key.json")
	config := ProvisionConfig{
		CiphertextPath: ciphertextPath, MachineID: "machine_1", Generation: 1,
		Random: bytes.NewReader(bytes.Repeat([]byte{0x11}, privateKeySize)), Runner: reversibleCredentialRunner{},
	}
	created, err := EnsureSystemdCredential(context.Background(), config)
	if err != nil || !created {
		t.Fatalf("initial provision created=%v err=%v", created, err)
	}
	oldCiphertext, err := os.ReadFile(ciphertextPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(metadataPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plaintext metadata sidecar still exists: %v", err)
	}
	failing := &failingCredentialWriter{}
	config.Generation = 2
	config.Random = bytes.NewReader(bytes.Repeat([]byte{0x22}, privateKeySize))
	config.Writer = failing
	if _, err := EnsureSystemdCredential(context.Background(), config); err == nil || failing.calls != 1 {
		t.Fatalf("replacement failure=%v write calls=%d", err, failing.calls)
	}
	unchanged, err := os.ReadFile(ciphertextPath)
	if err != nil || !bytes.Equal(unchanged, oldCiphertext) {
		t.Fatalf("failed replacement damaged active credential: %v", err)
	}
	config.Writer = rootCredentialWriter{}
	created, err = EnsureSystemdCredential(context.Background(), config)
	if err != nil || !created {
		t.Fatalf("replacement created=%v err=%v", created, err)
	}
	material, err := loadProvisioned(context.Background(), config)
	if err != nil || material.Generation != 2 {
		t.Fatalf("replacement material generation=%d err=%v", material.Generation, err)
	}
	material.Destroy()
}
