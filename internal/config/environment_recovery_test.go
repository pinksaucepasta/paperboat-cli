package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

func TestEnvironmentRecoveryTemporaryCustodyIsSecureStoreOnlyAndRestartSafe(t *testing.T) {
	path := t.TempDir()
	secrets := &environmentSecureMemoryStore{}
	store := ProfileStore{Path: path, Secrets: secrets}
	private, _, err := environmente2ee.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	encoded, err := environmente2ee.EncodeRecoveryBytes(private)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	handle, err := store.ImportEnvironmentRecoveryTemporary("https://api.example.test", "account_1", encoded)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(handle), private) || bytes.Contains([]byte(handle), encoded) {
		t.Fatal("opaque recovery handle contains secret material")
	}
	restarted := ProfileStore{Path: path, Secrets: secrets}
	loaded, err := restarted.LoadEnvironmentRecoveryTemporary("https://api.example.test", "account_1", handle)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(loaded[:])
	if !bytes.Equal(loaded[:], private) {
		t.Fatal("temporary recovery did not survive a process restart")
	}
	if err := filepath.Walk(path, func(file string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		raw, readErr := os.ReadFile(file)
		if readErr != nil {
			return readErr
		}
		defer clear(raw)
		if bytes.Contains(raw, private) || bytes.Contains(raw, encoded) {
			t.Fatalf("recovery plaintext persisted outside secure storage: %s", file)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.DeleteEnvironmentRecoveryTemporary("https://api.example.test", "account_1", handle); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadEnvironmentRecoveryTemporary("https://api.example.test", "account_1", handle); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("deleted import error = %v", err)
	}
}

func TestEnvironmentReplacementRecoveryRequiresExactExportConfirmation(t *testing.T) {
	secrets := &environmentSecureMemoryStore{}
	store := ProfileStore{Path: t.TempDir(), Secrets: secrets}
	replacement, err := store.BeginEnvironmentReplacementRecovery("https://api.example.test", "account_1")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Clear()
	if replacement.Handle == "" || len(replacement.Recovery) == 0 || len(replacement.RecipientPublic) != 32 || replacement.RecipientKeyID == "" {
		t.Fatalf("replacement = %#v", replacement)
	}
	if _, err := store.LoadConfirmedEnvironmentReplacementRecovery("https://api.example.test", "account_1", replacement.Handle); err == nil {
		t.Fatal("unconfirmed recovery was loadable")
	}
	wrongPrivate, _, err := environmente2ee.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wrongPrivate)
	wrong, err := environmente2ee.EncodeRecoveryBytes(wrongPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wrong)
	if err := store.ConfirmEnvironmentReplacementRecoveryExport("https://api.example.test", "account_1", replacement.Handle, wrong); err == nil {
		t.Fatal("mismatched recovery export was confirmed")
	}
	if err := store.ConfirmEnvironmentReplacementRecoveryExport("https://api.example.test", "account_1", replacement.Handle, replacement.Recovery); err != nil {
		t.Fatal(err)
	}
	restarted := ProfileStore{Path: store.Path, Secrets: secrets}
	loaded, err := restarted.LoadConfirmedEnvironmentReplacementRecovery("https://api.example.test", "account_1", replacement.Handle)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(loaded[:])
	expected, err := environmente2ee.DecodeRecoveryBytes(replacement.Recovery)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(expected)
	if !bytes.Equal(loaded[:], expected) {
		t.Fatal("confirmed replacement did not round trip")
	}
	if err := restarted.CompleteEnvironmentReplacementRecovery("https://api.example.test", "account_1", replacement.Handle); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadConfirmedEnvironmentReplacementRecovery("https://api.example.test", "account_1", replacement.Handle); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("completed replacement error = %v", err)
	}
}

func TestEnvironmentRecoveryCustodyRejectsFileFallback(t *testing.T) {
	private, _, err := environmente2ee.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	encoded, err := environmente2ee.EncodeRecoveryBytes(private)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	store := ProfileStore{Path: t.TempDir(), Secrets: FileSecretStore{Dir: t.TempDir()}}
	if _, err := store.ImportEnvironmentRecoveryTemporary("https://api.example.test", "account_1", encoded); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("temporary recovery file fallback error = %v", err)
	}
	if _, err := store.BeginEnvironmentReplacementRecovery("https://api.example.test", "account_1"); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("replacement recovery file fallback error = %v", err)
	}
}

func TestEnvironmentRecoveryPreparationIsDeterministicallyResumableAcrossEveryBoundary(t *testing.T) {
	secrets := &environmentSecureMemoryStore{}
	store := ProfileStore{Path: t.TempDir(), Secrets: secrets}
	oldPrivate, _, err := environmente2ee.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(oldPrivate)
	oldRecovery, err := environmente2ee.EncodeRecoveryBytes(oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(oldRecovery)
	prepared, err := store.BeginEnvironmentRecoveryPreparation("https://api.example.test", "account_1", "cli_1", oldRecovery)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Clear()
	restarted := ProfileStore{Path: store.Path, Secrets: secrets}
	resumed, err := restarted.ResumeEnvironmentRecoveryPreparation("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Clear()
	if resumed.ImportedHandle != prepared.ImportedHandle || resumed.ReplacementHandle != prepared.ReplacementHandle || resumed.RecipientKeyID != prepared.RecipientKeyID || !bytes.Equal(resumed.Recovery, prepared.Recovery) || resumed.ExportConfirmed {
		t.Fatalf("resumed preparation differs: %#v %#v", prepared, resumed)
	}
	if err := restarted.ConfirmEnvironmentRecoveryPreparationExport("https://api.example.test", "account_1", "cli_1", prepared.Recovery); err != nil {
		t.Fatal(err)
	}
	confirmed, err := store.ResumeEnvironmentRecoveryPreparation("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	defer confirmed.Clear()
	if !confirmed.ExportConfirmed || confirmed.ImportedHandle != prepared.ImportedHandle || confirmed.ReplacementHandle != prepared.ReplacementHandle {
		t.Fatalf("confirmed preparation = %#v", confirmed)
	}
	if err := store.CancelEnvironmentRecoveryPreparation("https://api.example.test", "account_1", "cli_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResumeEnvironmentRecoveryPreparation("https://api.example.test", "account_1", "cli_1"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("completed preparation resume error = %v", err)
	}
}
