//go:build darwin || linux

package environmentkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemdCredentialSourceHasNoRawFileFallback(t *testing.T) {
	directory := t.TempDir()
	for _, path := range []string{
		filepath.Join(directory, CredentialName),
		filepath.Join(directory, "environment-host-key"),
		filepath.Join(directory, "host-key.json"),
	} {
		if err := os.WriteFile(path, make([]byte, privateKeySize), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(directory)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv("PAPERBOAT_ENVIRONMENT_HOST_KEY_FILE", filepath.Join(directory, CredentialName))
	if _, err := (SystemdCredentialSource{Generation: 1, MachineID: "machine_1"}).Load(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("raw key file fallback was accepted: %v", err)
	}
}

func TestSystemdCredentialSourceReadsOnlyFixedRuntimeCredential(t *testing.T) {
	directory := t.TempDir()
	private := make([]byte, privateKeySize)
	for index := range private {
		private[index] = byte(index + 1)
	}
	record, err := json.Marshal(credentialMetadata{Schema: linuxCredentialMetadataSchema, MachineID: "machine_1", Generation: 4, PrivateKey: base64.RawURLEncoding.EncodeToString(private)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, CredentialName), record, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	material, err := (SystemdCredentialSource{Generation: 4, MachineID: "machine_1"}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer material.Destroy()
	if material.Generation != 4 || string(material.Private[:]) != string(private) {
		t.Fatal("fixed systemd runtime credential was not loaded exactly")
	}
}
