//go:build windows

package updated

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func acceptRecoveryFixture(_ context.Context, path, architecture string) error {
	if architecture != "amd64" {
		return errors.New("wrong architecture")
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) == 0 || string(body) == "untrusted" {
		return errors.New("untrusted executable")
	}
	return nil
}

func TestRecoverWindowsSlotsRestoresRollbackAndDiscardsStaged(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "runtime-current.exe")
	rollback := filepath.Join(root, "runtime-rollback.exe")
	staged := filepath.Join(root, "runtime-staged.exe")
	cliCurrent := filepath.Join(root, "pb-current.exe")
	cliRollback := filepath.Join(root, "pb-rollback.exe")
	if err := os.WriteFile(rollback, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("uncommitted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cliRollback, []byte("previous-cli"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverWindowsSlots(context.Background(), WindowsConfig{RuntimeCurrent: current, RuntimeRollback: rollback, RuntimeStaged: staged, CLICurrent: cliCurrent, CLIRollback: cliRollback, Architecture: "amd64", VerifyExecutable: acceptRecoveryFixture}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(current)
	if err != nil || string(body) != "previous" {
		t.Fatalf("current=%q err=%v", body, err)
	}
	if _, err := os.Stat(rollback); !os.IsNotExist(err) {
		t.Fatalf("rollback err=%v", err)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("staged err=%v", err)
	}
	cliBody, err := os.ReadFile(cliCurrent)
	if err != nil || string(cliBody) != "previous-cli" {
		t.Fatalf("cli current=%q err=%v", cliBody, err)
	}
	if _, err := os.Stat(cliRollback); !os.IsNotExist(err) {
		t.Fatalf("cli rollback err=%v", err)
	}
}

func TestRecoverWindowsSlotsKeepsCurrent(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "runtime-current.exe")
	rollback := filepath.Join(root, "runtime-rollback.exe")
	staged := filepath.Join(root, "runtime-staged.exe")
	cliCurrent := filepath.Join(root, "pb-current.exe")
	cliRollback := filepath.Join(root, "pb-rollback.exe")
	if err := os.WriteFile(current, []byte("active"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rollback, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cliCurrent, []byte("active-cli"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cliRollback, []byte("previous-cli"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverWindowsSlots(context.Background(), WindowsConfig{RuntimeCurrent: current, RuntimeRollback: rollback, RuntimeStaged: staged, CLICurrent: cliCurrent, CLIRollback: cliRollback, Architecture: "amd64", VerifyExecutable: acceptRecoveryFixture}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(current)
	if err != nil || string(body) != "active" {
		t.Fatalf("current=%q err=%v", body, err)
	}
	cliBody, err := os.ReadFile(cliCurrent)
	if err != nil || string(cliBody) != "active-cli" {
		t.Fatalf("cli current=%q err=%v", cliBody, err)
	}
}

func TestRecoverWindowsSlotsRejectsUntrustedRollbackAndDiscardsStaged(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "runtime-current.exe")
	rollback := filepath.Join(root, "runtime-rollback.exe")
	staged := filepath.Join(root, "runtime-staged.exe")
	cliCurrent := filepath.Join(root, "pb-current.exe")
	cliRollback := filepath.Join(root, "pb-rollback.exe")
	for path, body := range map[string]string{rollback: "untrusted", staged: "uncommitted", cliRollback: "previous-cli"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := recoverWindowsSlots(context.Background(), WindowsConfig{RuntimeCurrent: current, RuntimeRollback: rollback, RuntimeStaged: staged, CLICurrent: cliCurrent, CLIRollback: cliRollback, Architecture: "amd64", VerifyExecutable: acceptRecoveryFixture}); err == nil {
		t.Fatal("untrusted rollback was activated")
	}
	if _, err := os.Stat(current); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("untrusted rollback became current: %v", err)
	}
	if body, err := os.ReadFile(rollback); err != nil || string(body) != "untrusted" {
		t.Fatalf("untrusted rollback was modified: %q %v", body, err)
	}
	if _, err := os.Stat(cliCurrent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("CLI rollback was partially activated: %v", err)
	}
	if body, err := os.ReadFile(cliRollback); err != nil || string(body) != "previous-cli" {
		t.Fatalf("CLI rollback was modified during failed transaction: %q %v", body, err)
	}
	if _, err := os.Stat(staged); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged file survived failed recovery: %v", err)
	}
}

func TestRecoverWindowsSlotsRejectsUntrustedCurrentWithoutFallingBack(t *testing.T) {
	root := t.TempDir()
	config := WindowsConfig{
		RuntimeCurrent:   filepath.Join(root, "runtime-current.exe"),
		RuntimeRollback:  filepath.Join(root, "runtime-rollback.exe"),
		RuntimeStaged:    filepath.Join(root, "runtime-staged.exe"),
		CLICurrent:       filepath.Join(root, "pb-current.exe"),
		CLIRollback:      filepath.Join(root, "pb-rollback.exe"),
		Architecture:     "amd64",
		VerifyExecutable: acceptRecoveryFixture,
	}
	for path, body := range map[string]string{config.RuntimeCurrent: "untrusted", config.RuntimeRollback: "previous", config.CLICurrent: "active-cli"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := recoverWindowsSlots(context.Background(), config); err == nil {
		t.Fatal("untrusted current executable was accepted")
	}
	if body, _ := os.ReadFile(config.RuntimeCurrent); string(body) != "untrusted" {
		t.Fatalf("untrusted current was silently replaced: %q", body)
	}
	if body, _ := os.ReadFile(config.RuntimeRollback); string(body) != "previous" {
		t.Fatalf("rollback changed after current validation failure: %q", body)
	}
}
