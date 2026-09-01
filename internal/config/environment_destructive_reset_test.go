package config

import (
	"bytes"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

func TestEnvironmentDestructiveResetPreparationRoundTripsRecoveryExport(t *testing.T) {
	secrets := &environmentSecureMemoryStore{}
	store := ProfileStore{Path: t.TempDir(), Secrets: secrets}
	prepared, err := store.BeginEnvironmentDestructiveResetPreparation("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Clear()
	if prepared.Handle == "" || len(prepared.Recovery) == 0 || prepared.ExportConfirmed {
		t.Fatalf("prepared reset = %#v", prepared)
	}
	decoded, err := environmente2ee.DecodeRecoveryBytes(prepared.Recovery)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(decoded)
	if err := store.ConfirmEnvironmentDestructiveResetExport("https://api.example.test", "account_1", "cli_1", prepared.Handle, prepared.Recovery); err != nil {
		t.Fatal(err)
	}
	resumed, err := store.ResumeEnvironmentDestructiveResetPreparation("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Clear()
	if !resumed.ExportConfirmed || len(resumed.Recovery) != 0 || !bytes.Equal(resumed.RecoveryRecipientPublic, prepared.RecoveryRecipientPublic) {
		t.Fatalf("confirmed reset = %#v", resumed)
	}
}
