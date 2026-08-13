//go:build darwin || linux

package managedssh

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestReconcileAuthorizedKeysPreservesUnrelatedBytesAndIsIdempotent(t *testing.T) {
	home := managedSSHTestHome(t)
	directory := filepath.Join(home, ".ssh")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	unrelated := "# user comment\nfrom=\"10.0.0.0/8\" " + authorizedPublicLine(t) + " existing-key\n\n"
	path := filepath.Join(directory, "authorized_keys")
	if err := os.WriteFile(path, []byte(unrelated), 0o600); err != nil {
		t.Fatal(err)
	}
	firstKey, secondKey := authorizedPublicLine(t), authorizedPublicLine(t)
	result, err := ReconcileAuthorizedKeys(home, uint32(os.Getuid()), []string{secondKey, firstKey})
	if err != nil || !result.Changed || result.Count != 2 {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(updated), unrelated) || strings.Count(string(updated), managedAuthorizedKeyMarker) != 2 {
		t.Fatalf("updated authorized_keys=%q", updated)
	}
	replay, err := ReconcileAuthorizedKeys(home, uint32(os.Getuid()), []string{firstKey, secondKey})
	if err != nil || replay.Changed || replay.Count != 2 {
		t.Fatalf("replay=%+v error=%v", replay, err)
	}
	removed, err := ReconcileAuthorizedKeys(home, uint32(os.Getuid()), nil)
	if err != nil || !removed.Changed || removed.Count != 0 {
		t.Fatalf("removed=%+v error=%v", removed, err)
	}
	final, err := os.ReadFile(path)
	if err != nil || string(final) != unrelated {
		t.Fatalf("final=%q error=%v", final, err)
	}
}

func TestReconcileAuthorizedKeysRejectsMarkerConflictSymlinkAndPermissions(t *testing.T) {
	home := managedSSHTestHome(t)
	directory := filepath.Join(home, ".ssh")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "authorized_keys")
	original := "# " + managedAuthorizedKeyMarker + "forged\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileAuthorizedKeys(home, uint32(os.Getuid()), []string{authorizedPublicLine(t)}); !errors.Is(err, ErrAuthorizedKeysConflict) {
		t.Fatalf("marker conflict error=%v", err)
	}
	unchanged, _ := os.ReadFile(path)
	if string(unchanged) != original {
		t.Fatal("conflicting authorized_keys was modified")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "target")
	if err := os.WriteFile(target, []byte("unrelated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := ReconcileAuthorizedKeys(home, uint32(os.Getuid()), nil); err == nil {
		t.Fatal("symlinked authorized_keys was accepted")
	}
	targetValue, _ := os.ReadFile(target)
	if string(targetValue) != "unrelated\n" {
		t.Fatal("symlink target was modified")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("unrelated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileAuthorizedKeys(home, uint32(os.Getuid()), nil); err == nil {
		t.Fatal("permissive authorized_keys was accepted")
	}
}

func TestReconcileAuthorizedKeysSerializesConcurrentRepair(t *testing.T) {
	home := managedSSHTestHome(t)
	keys := []string{authorizedPublicLine(t), authorizedPublicLine(t)}
	var group sync.WaitGroup
	errorsFound := make(chan error, 12)
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := ReconcileAuthorizedKeys(home, uint32(os.Getuid()), keys)
			errorsFound <- err
		}()
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	value, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil || strings.Count(string(value), managedAuthorizedKeyMarker) != 2 {
		t.Fatalf("authorized_keys=%q error=%v", value, err)
	}
}

func managedSSHTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}
