package privateproxyconfig

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type fakeAdapter struct {
	mu                 sync.Mutex
	state              string
	installs, restores int
}

func (f *fakeAdapter) Name() string { return "fake" }
func (f *fakeAdapter) Snapshot(context.Context) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.state)
}
func (f *fakeAdapter) Install(_ context.Context, pac string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = pac
	f.installs++
	return nil
}
func (f *fakeAdapter) Owns(_ context.Context, pac string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state == pac, nil
}
func (f *fakeAdapter) Matches(_ context.Context, raw json.RawMessage) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var want string
	if err := json.Unmarshal(raw, &want); err != nil {
		return false, err
	}
	return f.state == want, nil
}
func (f *fakeAdapter) Restore(_ context.Context, raw json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := json.Unmarshal(raw, &f.state); err != nil {
		return err
	}
	f.restores++
	return nil
}

func TestManagerInstallRemoveExactState(t *testing.T) {
	f := &fakeAdapter{state: "http://previous.example/proxy.pac"}
	path := filepath.Join(t.TempDir(), "proxy.json")
	m, _ := New(path, f)
	pac := "http://127.0.0.1:37491/private/token.pac"
	if err := m.Install(context.Background(), pac); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode: %v %v", info, err)
	}
	if err := m.Install(context.Background(), pac); err != nil {
		t.Fatal(err)
	}
	if f.installs != 1 {
		t.Fatalf("installs=%d", f.installs)
	}
	if err := m.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.state != "http://previous.example/proxy.pac" {
		t.Fatalf("state=%q", f.state)
	}
	if err := m.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestManagerRejectsUntrustedAndExternalChange(t *testing.T) {
	f := &fakeAdapter{state: "off"}
	m, _ := New(filepath.Join(t.TempDir(), "j"), f)
	for _, pac := range []string{"http://proxy.example/p.pac", "https://127.0.0.1:1/p.pac", "http://localhost:1/p.pac", "http://127.0.0.1:1/"} {
		if !errors.Is(m.Install(context.Background(), pac), ErrUntrustedPAC) {
			t.Fatalf("accepted %q", pac)
		}
	}
	if err := m.Install(context.Background(), "http://[::1]:99/a.pac"); err != nil {
		t.Fatal(err)
	}
	f.state = "user-change"
	if !errors.Is(m.Remove(context.Background()), ErrConflict) {
		t.Fatal("expected conflict")
	}
	if f.state != "user-change" {
		t.Fatal("overwrote external change")
	}
}

func TestManagerRecoverPreparedJournal(t *testing.T) {
	f := &fakeAdapter{state: "http://127.0.0.1:9/a.pac"}
	path := filepath.Join(t.TempDir(), "j")
	m, _ := New(path, f)
	prior, _ := json.Marshal("exact-prior")
	if err := m.write(journal{Version: 1, Adapter: "fake", PACURL: "http://127.0.0.1:9/a.pac", Phase: "prepared", Prior: prior}); err != nil {
		t.Fatal(err)
	}
	if err := m.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.state != "exact-prior" {
		t.Fatalf("state=%q", f.state)
	}
}

func TestManagerRecoverRemovesAppliedJournalAfterPriorStateWasRestored(t *testing.T) {
	f := &fakeAdapter{state: "exact-prior"}
	path := filepath.Join(t.TempDir(), "j")
	m, _ := New(path, f)
	prior, _ := json.Marshal("exact-prior")
	if err := m.write(journal{Version: 1, Adapter: "fake", PACURL: "http://127.0.0.1:9/a.pac", Phase: "applied", Prior: prior}); err != nil {
		t.Fatal(err)
	}
	if err := m.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale journal remains: %v", err)
	}
}

func TestManagerConcurrentInstallIsIdempotent(t *testing.T) {
	f := &fakeAdapter{state: "off"}
	m, _ := New(filepath.Join(t.TempDir(), "j"), f)
	pac := "http://127.0.0.1:1/a.pac"
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- m.Install(context.Background(), pac) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.installs != 1 {
		t.Fatalf("installs=%d", f.installs)
	}
}
