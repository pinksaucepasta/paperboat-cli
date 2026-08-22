//go:build windows

package updated

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
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

func TestWindowsControllerStatusAndSignedCheck(t *testing.T) {
	controller, err := newWindowsController(WindowsConfig{
		ActiveVersion: "2026.08.22.27",
		OwnerSID:      "S-1-5-21-1-2-3-1001",
		ControlSocket: `\\.\pipe\PaperboatUpdatedControl-Test`,
		ResolveRelease: func(context.Context) (workerupdate.Release, bool, error) {
			return workerupdate.Release{Version: "2026.08.22.28"}, true, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := controller.invoke(context.Background(), ControlRequest{Schema: ControlProtocolV1, Operation: "status"})
	if err != nil || status.Version != "2026.08.22.27" || status.Updated {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	checked, err := controller.invoke(context.Background(), ControlRequest{Schema: ControlProtocolV1, Operation: "check"})
	if err != nil || checked.Version != "2026.08.22.28" || checked.Updated || checked.Observation.CheckedAt.IsZero() {
		t.Fatalf("check=%#v err=%v", checked, err)
	}
}

func TestWindowsControllerActivationFailsClosed(t *testing.T) {
	controller, err := newWindowsController(WindowsConfig{
		ActiveVersion: "2026.08.22.27",
		OwnerSID:      "S-1-5-21-1-2-3-1001",
		ControlSocket: `\\.\pipe\PaperboatUpdatedControl-Test`,
		ResolveRelease: func(context.Context) (workerupdate.Release, bool, error) {
			return workerupdate.Release{}, false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"update", "approve-maintenance"} {
		_, err := controller.invoke(context.Background(), ControlRequest{Schema: ControlProtocolV1, Operation: operation, Release: map[string]string{"approve-maintenance": "2026.08.22.28"}[operation]})
		if !errors.Is(err, ErrWindowsActivationUnavailable) {
			t.Fatalf("%s err=%v", operation, err)
		}
	}
}

func TestWindowsControllerRespondsWithoutClientHalfClose(t *testing.T) {
	controller, err := newWindowsController(WindowsConfig{
		ActiveVersion: "2026.08.22.27",
		OwnerSID:      "S-1-5-21-1-2-3-1001",
		ControlSocket: `\\.\pipe\PaperboatUpdatedControl-Test`,
		ResolveRelease: func(context.Context) (workerupdate.Release, bool, error) {
			return workerupdate.Release{}, false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		done <- controller.handle(server)
		_ = server.Close()
	}()
	if err := json.NewEncoder(client).Encode(ControlRequest{Schema: ControlProtocolV1, Operation: "status"}); err != nil {
		t.Fatal(err)
	}
	var response ControlResponse
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "ok" || response.Version != "2026.08.22.27" {
		t.Fatalf("response=%#v", response)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWindowsControllerSerializesTUFChecks(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	entered := make(chan struct{}, 2)
	release := make(chan struct{}, 2)
	controller, err := newWindowsController(WindowsConfig{
		ActiveVersion: "2026.08.22.27",
		OwnerSID:      "S-1-5-21-1-2-3-1001",
		ControlSocket: `\\.\pipe\PaperboatUpdatedControl-Test`,
		ResolveRelease: func(context.Context) (workerupdate.Release, bool, error) {
			current := active.Add(1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			entered <- struct{}{}
			<-release
			active.Add(-1)
			return workerupdate.Release{Version: "2026.08.22.28"}, true, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	group.Add(2)
	for range 2 {
		go func() {
			defer group.Done()
			_, _ = controller.checkRelease(context.Background())
		}()
	}
	<-entered
	select {
	case <-entered:
		t.Fatal("TUF resolver calls overlapped")
	default:
	}
	release <- struct{}{}
	<-entered
	release <- struct{}{}
	group.Wait()
	if maximum.Load() != 1 {
		t.Fatalf("maximum concurrent TUF resolvers=%d", maximum.Load())
	}
}
