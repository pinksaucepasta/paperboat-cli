//go:build darwin || linux

package hoststate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTRK35HostStateTruncatedOrTamperedPrimaryPreservesEvidenceAndLKG(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "truncated",
			mutate: func(raw []byte) []byte {
				return append([]byte(nil), raw[:len(raw)/2]...)
			},
		},
		{
			name: "checksum_tampered",
			mutate: func(raw []byte) []byte {
				tampered := append([]byte(nil), raw...)
				prefix := []byte(`"checksum":"sha256:`)
				index := bytes.Index(tampered, prefix)
				if index < 0 {
					return []byte(`{"checksum":"sha256:tampered"}`)
				}
				checksumDigit := index + len(prefix)
				if tampered[checksumDigit] == '0' {
					tampered[checksumDigit] = '1'
				} else {
					tampered[checksumDigit] = '0'
				}
				return tampered
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "host-state")
			store, _, err := Open(Config{Root: root, Clock: func() time.Time { return testNow }})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Commit(1, validState(t, 2, 1)); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			primaryPath := filepath.Join(root, primaryFile)
			backupPath := filepath.Join(root, backupFile)
			primary, err := os.ReadFile(primaryPath)
			if err != nil {
				t.Fatal(err)
			}
			// Keep a current backup so recovery can prove that LKG survives
			// even when the primary is unreadable or fails its checksum.
			if err := os.WriteFile(backupPath, primary, 0o600); err != nil {
				t.Fatal(err)
			}
			corrupt := test.mutate(primary)
			if bytes.Equal(corrupt, primary) {
				t.Fatal("fault did not alter primary state")
			}
			if err := os.WriteFile(primaryPath, corrupt, 0o600); err != nil {
				t.Fatal(err)
			}

			recovered, status, err := Open(Config{Root: root, Clock: func() time.Time { return testNow.Add(time.Minute) }})
			if err != nil {
				t.Fatal(err)
			}
			defer recovered.Close()
			if !status.Degraded || status.Code != "primary_corrupt_recovered_from_backup" || status.Source != "backup" || len(status.PreservedPaths) != 1 {
				t.Fatalf("recovery status=%+v", status)
			}
			preserved, err := os.ReadFile(status.PreservedPaths[0])
			if err != nil || !bytes.Equal(preserved, corrupt) {
				t.Fatalf("preserved primary err=%v bytes_equal=%v", err, bytes.Equal(preserved, corrupt))
			}
			state, revision, err := recovered.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if revision != 2 || len(state.Tunnels) != 1 || state.Tunnels[0].DesiredGeneration != 2 || state.Tunnels[0].LastKnownGood == nil || state.Tunnels[0].LastKnownGood.Generation != 1 {
				t.Fatalf("recovered LKG revision=%d state=%+v", revision, state)
			}
			if len(state.UpdateJournal) != 1 || state.UpdateJournal[0].ID != "jrn_01" {
				t.Fatalf("recovered update journal=%+v", state.UpdateJournal)
			}
		})
	}
}

func TestTRK35HostStateStaleBackupIsPreservedAndRepaired(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	store, _, err := Open(Config{Root: root, Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	initialBackup, err := os.ReadFile(filepath.Join(root, backupFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(1, validState(t, 1, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(2, validState(t, 2, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, backupFile), initialBackup, 0o600); err != nil {
		t.Fatal(err)
	}

	recovered, status, err := Open(Config{Root: root, Clock: func() time.Time { return testNow.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if !status.Degraded || status.Code != "backup_stale_repaired" || status.Source != "primary" || len(status.PreservedPaths) != 1 {
		t.Fatalf("stale-backup status=%+v", status)
	}
	preserved, err := os.ReadFile(status.PreservedPaths[0])
	if err != nil || !bytes.Equal(preserved, initialBackup) {
		t.Fatalf("stale backup evidence err=%v bytes_equal=%v", err, bytes.Equal(preserved, initialBackup))
	}
	state, revision, err := recovered.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if revision != 3 || len(state.Tunnels) != 1 || state.Tunnels[0].DesiredGeneration != 2 || state.Tunnels[0].LastKnownGood == nil || state.Tunnels[0].LastKnownGood.Generation != 1 {
		t.Fatalf("stale-backup recovery revision=%d state=%+v", revision, state)
	}
	repaired, err := os.ReadFile(filepath.Join(root, backupFile))
	if err != nil {
		t.Fatal(err)
	}
	primary, err := os.ReadFile(filepath.Join(root, primaryFile))
	if err != nil || !bytes.Equal(repaired, primary) {
		t.Fatalf("stale backup was not repaired err=%v equal=%v", err, bytes.Equal(repaired, primary))
	}
}

func TestTRK35HostStatePermissionDeniedPrimaryFailsClosedWithoutTouchingBackup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	store, _, err := Open(Config{Root: root, Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(1, validState(t, 2, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	primaryPath := filepath.Join(root, primaryFile)
	backupPath := filepath.Join(root, backupFile)
	primary, err := os.ReadFile(primaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, primary, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(primaryPath, 0); err != nil {
		t.Fatal(err)
	}

	opened, status, err := Open(Config{Root: root, Clock: func() time.Time { return testNow.Add(time.Minute) }})
	if opened != nil {
		_ = opened.Close()
	}
	if !errors.Is(err, ErrCorrupt) || !status.Degraded || status.Code != "primary_unreadable" || status.Source != "none" {
		t.Fatalf("permission-denied primary opened=%v status=%+v err=%v", opened != nil, status, err)
	}
	unchanged, err := os.ReadFile(backupPath)
	if err != nil || !bytes.Equal(unchanged, primary) {
		t.Fatalf("permission-denied recovery touched backup err=%v equal=%v", err, bytes.Equal(unchanged, primary))
	}
}

func TestTRK35HostStatePermissionDeniedBackupRetainsLKG(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	store, _, err := Open(Config{Root: root, Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(1, validState(t, 2, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	primaryPath := filepath.Join(root, primaryFile)
	backupPath := filepath.Join(root, backupFile)
	primary, err := os.ReadFile(primaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(backupPath, 0); err != nil {
		t.Fatal(err)
	}

	recovered, status, err := Open(Config{Root: root, Clock: func() time.Time { return testNow.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if !status.Degraded || status.Code != "backup_corrupt_repaired" || status.Source != "primary" || len(status.PreservedPaths) != 1 {
		t.Fatalf("permission-denied backup status=%+v", status)
	}
	state, revision, err := recovered.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if revision != 2 || len(state.Tunnels) != 1 || state.Tunnels[0].LastKnownGood == nil || state.Tunnels[0].LastKnownGood.Generation != 1 {
		t.Fatalf("permission-denied backup lost LKG revision=%d state=%+v", revision, state)
	}
	repaired, err := os.ReadFile(backupPath)
	if err != nil || !bytes.Equal(repaired, primary) {
		t.Fatalf("permission-denied backup was not repaired err=%v equal=%v", err, bytes.Equal(repaired, primary))
	}
}

func TestTRK35HostStateJournalRecoveryPreservesTruncatedEvidenceAndLKG(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	store, _, err := Open(Config{Root: root, Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(1, validState(t, 2, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	primary, err := os.ReadFile(filepath.Join(root, primaryFile))
	if err != nil {
		t.Fatal(err)
	}
	truncated := append([]byte(nil), primary[:len(primary)/3]...)
	stagingPath := filepath.Join(root, stagingFile)
	if err := os.WriteFile(stagingPath, truncated, 0o600); err != nil {
		t.Fatal(err)
	}

	recovered, status, err := Open(Config{Root: root, Clock: func() time.Time { return testNow.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if !status.Degraded || status.Code != "incomplete_commit_preserved" || len(status.PreservedPaths) != 1 {
		t.Fatalf("journal recovery status=%+v", status)
	}
	preserved, err := os.ReadFile(status.PreservedPaths[0])
	if err != nil || !bytes.Equal(preserved, truncated) {
		t.Fatalf("truncated journal evidence err=%v bytes_equal=%v", err, bytes.Equal(preserved, truncated))
	}
	if _, err := os.Stat(stagingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("incomplete journal staging remains: %v", err)
	}
	state, revision, err := recovered.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if revision != 2 || len(state.Tunnels) != 1 || state.Tunnels[0].LastKnownGood == nil || state.Tunnels[0].LastKnownGood.Generation != 1 || len(state.UpdateJournal) != 1 || state.UpdateJournal[0].ID != "jrn_01" {
		t.Fatalf("journal recovery lost LKG or update journal revision=%d state=%+v", revision, state)
	}
}
