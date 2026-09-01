package hoststate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

var testNow = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

func TestStoreCommitReopenAndLastKnownGood(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	store, status, err := Open(Config{Root: root, Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	if status.Degraded || status.Code != "initialized" || status.Source != "initial" {
		t.Fatalf("unexpected initial status: %+v", status)
	}
	statusCopy := store.StartupStatus()
	statusCopy.PreservedPaths = append(statusCopy.PreservedPaths, "caller-mutation")
	if len(store.StartupStatus().PreservedPaths) != 0 {
		t.Fatal("StartupStatus returned mutable internal state")
	}
	empty, revision, err := store.Snapshot()
	if err != nil || revision != 1 || len(empty.Tunnels) != 0 {
		t.Fatalf("unexpected initial snapshot: revision=%d state=%+v err=%v", revision, empty, err)
	}
	want := validState(t, 2, 1)
	committed, err := store.Commit(revision, want)
	if err != nil || committed != 2 {
		t.Fatalf("commit: revision=%d err=%v", committed, err)
	}
	if _, err := store.Commit(revision, want); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale commit error = %v, want ErrConflict", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, status, err := Open(Config{Root: root, Clock: func() time.Time { return testNow.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if status.Degraded || status.Code != "ready" || status.Source != "primary" {
		t.Fatalf("unexpected reopen status: %+v", status)
	}
	got, revision, err := reopened.Snapshot()
	if err != nil || revision != 2 {
		t.Fatalf("reopen snapshot: revision=%d err=%v", revision, err)
	}
	if len(got.Tunnels) != 1 || got.Tunnels[0].LastKnownGood == nil || got.Tunnels[0].LastKnownGood.Generation != 1 || got.Tunnels[0].DesiredSnapshot.Generation != 2 {
		t.Fatalf("last-known-good was not preserved independently: %+v", got.Tunnels)
	}
	got.Tunnels[0].DesiredSnapshot.Payload[0] = 'x'
	again, _, err := reopened.Snapshot()
	if err != nil || again.Tunnels[0].DesiredSnapshot.Payload[0] == 'x' {
		t.Fatal("Snapshot returned mutable internal state")
	}
	for _, name := range []string{primaryFile, backupFile, lockFile} {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s permissions = %o, want owner-only", name, info.Mode().Perm())
		}
	}
}

func TestStoreCloseIsIdempotentAndRejectsUse(t *testing.T) {
	store, _, err := Open(Config{Root: filepath.Join(t.TempDir(), "host-state")})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, _, err := store.Snapshot(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Snapshot after Close = %v", err)
	}
	if _, err := store.Commit(1, State{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Commit after Close = %v", err)
	}
}

func TestStoreHoldsExclusiveProcessLock(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	first, _, err := Open(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, _, err := Open(Config{Root: root})
	if second != nil {
		second.Close()
	}
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open error = %v, want ErrLocked", err)
	}
}

func TestCommitFaultAtEveryDurabilityPhase(t *testing.T) {
	phases := []Phase{PhaseCommitStaged, PhaseCommitBackupSynced, PhaseCommitPrimarySynced, PhaseCommitCleanupSynced}
	for _, target := range phases {
		t.Run(string(target), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "host-state")
			armed := false
			store, _, err := Open(Config{
				Root: root, Clock: func() time.Time { return testNow },
				FailureHook: func(phase Phase) error {
					if armed && phase == target {
						return fmt.Errorf("simulated crash at %s", phase)
					}
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			armed = true
			_, err = store.Commit(1, validState(t, 1, 1))
			var commitErr *CommitError
			if !errors.As(err, &commitErr) || commitErr.Phase != target {
				t.Fatalf("commit error = %v, want phase %s", err, target)
			}
			published := target == PhaseCommitPrimarySynced || target == PhaseCommitCleanupSynced
			if commitErr.Changed != published || errors.Is(err, ErrUncertain) != published {
				t.Fatalf("phase %s changed=%v uncertain=%v", target, commitErr.Changed, errors.Is(err, ErrUncertain))
			}
			if published {
				if _, _, snapshotErr := store.Snapshot(); !errors.Is(snapshotErr, ErrUncertain) {
					t.Fatalf("snapshot after uncertain publish = %v", snapshotErr)
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			reopened, status, err := Open(Config{Root: root, Clock: func() time.Time { return testNow.Add(time.Minute) }})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			state, revision, err := reopened.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			wantRevision := uint64(1)
			wantTunnels := 0
			if published {
				wantRevision, wantTunnels = 2, 1
			}
			if revision != wantRevision || len(state.Tunnels) != wantTunnels {
				t.Fatalf("recovered revision=%d tunnels=%d, want %d/%d", revision, len(state.Tunnels), wantRevision, wantTunnels)
			}
			if target != PhaseCommitCleanupSynced {
				if !status.Degraded || status.Code != "incomplete_commit_preserved" || len(status.PreservedPaths) != 1 {
					t.Fatalf("incomplete commit was not explicit: %+v", status)
				}
				assertFileContains(t, status.PreservedPaths[0], `"checksum":"sha256:`)
			} else if status.Degraded {
				t.Fatalf("fully cleaned commit reopened degraded: %+v", status)
			}
		})
	}
}

func TestMigrationFaultAtEveryDurabilityPhase(t *testing.T) {
	phases := []Phase{
		PhaseMigrationSourcePreserved,
		PhaseMigrationStaged,
		PhaseMigrationPrimarySynced,
		PhaseMigrationBackupSynced,
		PhaseMigrationCleanupSynced,
	}
	for _, target := range phases {
		t.Run(string(target), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "host-state")
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			legacy := legacyDocumentV0{Schema: Schema, SchemaVersion: 0, Revision: 7, WrittenAt: testNow, State: validState(t, 1, 1)}
			raw, err := json.Marshal(legacy)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, '\n')
			if err := atomicfile.Write(filepath.Join(root, primaryFile), raw, atomicfile.CurrentOwnerOptions(0o600)); err != nil {
				t.Fatal(err)
			}
			_, status, err := Open(Config{
				Root: root, Clock: func() time.Time { return testNow.Add(time.Minute) },
				FailureHook: func(phase Phase) error {
					if phase == target {
						return fmt.Errorf("simulated migration crash at %s", phase)
					}
					return nil
				},
			})
			var commitErr *CommitError
			if !errors.As(err, &commitErr) || commitErr.Phase != target {
				t.Fatalf("migration error=%v status=%+v, want phase %s", err, status, target)
			}
			migrationCopies, err := filepath.Glob(filepath.Join(root, "state.migration-v0.*.preserved.json"))
			if err != nil || len(migrationCopies) != 1 {
				t.Fatalf("migration source copies=%v err=%v", migrationCopies, err)
			}
			preserved, err := os.ReadFile(migrationCopies[0])
			if err != nil || !bytes.Equal(preserved, raw) {
				t.Fatalf("migration source was not preserved exactly: err=%v", err)
			}

			reopened, reopenedStatus, err := Open(Config{Root: root, Clock: func() time.Time { return testNow.Add(2 * time.Minute) }})
			if err != nil {
				t.Fatalf("restart after %s: %v (status %+v)", target, err, reopenedStatus)
			}
			defer reopened.Close()
			state, revision, err := reopened.Snapshot()
			if err != nil || revision != 7 || len(state.Tunnels) != 1 {
				t.Fatalf("migrated snapshot revision=%d tunnels=%d err=%v", revision, len(state.Tunnels), err)
			}
			primaryRaw, err := os.ReadFile(filepath.Join(root, primaryFile))
			if err != nil {
				t.Fatal(err)
			}
			current, migratedLegacy, err := decodeAnyDocument(primaryRaw)
			if err != nil || migratedLegacy != nil || current.SchemaVersion != SchemaVersion {
				t.Fatalf("primary was not migrated: doc=%+v legacy=%v err=%v", current, migratedLegacy != nil, err)
			}
		})
	}
}

func TestCorruptPrimaryUsesValidBackupAndPreservesEvidence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	store, _, err := Open(Config{Root: root, Clock: func() time.Time { return testNow }})
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
	corrupt := []byte("{\"schema\":\"paperboat.host-state\",\"schema_version\":1,\"broken\":true}\n")
	if err := os.WriteFile(filepath.Join(root, primaryFile), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	recovered, status, err := Open(Config{Root: root, Clock: func() time.Time { return testNow.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if !status.Degraded || status.Code != "primary_corrupt_recovered_from_backup" || status.Source != "backup" || len(status.PreservedPaths) != 1 {
		t.Fatalf("unexpected recovery status: %+v", status)
	}
	preserved, err := os.ReadFile(status.PreservedPaths[0])
	if err != nil || !bytes.Equal(preserved, corrupt) {
		t.Fatalf("corrupt primary was not preserved: err=%v", err)
	}
	state, revision, err := recovered.Snapshot()
	if err != nil || revision != 2 || len(state.Tunnels) != 1 || state.Tunnels[0].DesiredGeneration != 1 {
		t.Fatalf("backup recovery state revision=%d state=%+v err=%v", revision, state, err)
	}
}

func TestCorruptPrimaryAndBackupRefusesEmptyStartup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	store, _, err := Open(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	primaryCorrupt := []byte("bad primary\n")
	backupCorrupt := []byte("bad backup\n")
	if err := os.WriteFile(filepath.Join(root, primaryFile), primaryCorrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, backupFile), backupCorrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	opened, status, err := Open(Config{Root: root})
	if opened != nil {
		opened.Close()
	}
	if !errors.Is(err, ErrCorrupt) || !status.Degraded || status.Code != "primary_and_backup_unusable" || len(status.PreservedPaths) != 2 {
		t.Fatalf("corrupt startup opened=%v status=%+v err=%v", opened != nil, status, err)
	}
	contents := make([]string, 0, 2)
	for _, name := range status.PreservedPaths {
		body, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		contents = append(contents, string(body))
	}
	if !slices.Contains(contents, string(primaryCorrupt)) || !slices.Contains(contents, string(backupCorrupt)) {
		t.Fatalf("preserved corrupt contents = %q", contents)
	}
}

func TestValidPrimaryRepairsAndPreservesCorruptBackup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	store, _, err := Open(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(1, validState(t, 1, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("corrupt backup\n")
	if err := os.WriteFile(filepath.Join(root, backupFile), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, status, err := Open(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !status.Degraded || status.Code != "backup_corrupt_repaired" || len(status.PreservedPaths) != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
	preserved, err := os.ReadFile(status.PreservedPaths[0])
	if err != nil || !bytes.Equal(preserved, corrupt) {
		t.Fatalf("corrupt backup not preserved: err=%v", err)
	}
	backupRaw, err := os.ReadFile(filepath.Join(root, backupFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, legacy, err := decodeAnyDocument(backupRaw); err != nil || legacy != nil {
		t.Fatalf("backup was not repaired: legacy=%v err=%v", legacy != nil, err)
	}
}

func TestMissingPrimaryRestoresBackup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	store, _, err := Open(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(1, validState(t, 1, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, primaryFile)); err != nil {
		t.Fatal(err)
	}
	reopened, status, err := Open(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !status.Degraded || status.Code != "primary_missing_recovered_from_backup" || status.Source != "backup" {
		t.Fatalf("unexpected status: %+v", status)
	}
	state, revision, err := reopened.Snapshot()
	if err != nil || revision != 1 || len(state.Tunnels) != 0 {
		t.Fatalf("restored backup revision=%d state=%+v err=%v", revision, state, err)
	}
}

func TestValidPrimaryRepairsMissingBackupExplicitly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	store, _, err := Open(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(1, validState(t, 1, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, backupFile)); err != nil {
		t.Fatal(err)
	}
	reopened, status, err := Open(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !status.Degraded || status.Code != "backup_missing_repaired" || status.Source != "primary" {
		t.Fatalf("unexpected status: %+v", status)
	}
	backupRaw, err := os.ReadFile(filepath.Join(root, backupFile))
	if err != nil {
		t.Fatal(err)
	}
	if backup, legacy, err := decodeAnyDocument(backupRaw); err != nil || legacy != nil || backup.Revision != 2 {
		t.Fatalf("repaired backup revision=%d legacy=%v err=%v", backup.Revision, legacy != nil, err)
	}
}

func TestBackupRevisionAheadRefusesDestructiveRollback(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	store, _, err := Open(Config{Root: root, Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	_, futureBackup, err := sealDocument(validState(t, 1, 1), 2, testNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicfile.Write(filepath.Join(root, backupFile), futureBackup, atomicfile.CurrentOwnerOptions(0o600)); err != nil {
		t.Fatal(err)
	}
	opened, status, err := Open(Config{Root: root})
	if opened != nil {
		opened.Close()
	}
	if !errors.Is(err, ErrCorrupt) || !status.Degraded || status.Code != "backup_revision_ahead" {
		t.Fatalf("ahead backup opened=%v status=%+v err=%v", opened != nil, status, err)
	}
	got, readErr := os.ReadFile(filepath.Join(root, backupFile))
	if readErr != nil || !bytes.Equal(got, futureBackup) {
		t.Fatalf("ahead backup was modified: err=%v", readErr)
	}
}

func TestFutureSchemaRefusesRollback(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-state")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	future := []byte(`{"schema":"paperboat.host-state","schema_version":2,"revision":9,"written_at":"2026-08-30T12:00:00Z","state":{},"checksum":"sha256:future"}` + "\n")
	if err := atomicfile.Write(filepath.Join(root, primaryFile), future, atomicfile.CurrentOwnerOptions(0o600)); err != nil {
		t.Fatal(err)
	}
	opened, status, err := Open(Config{Root: root})
	if opened != nil {
		opened.Close()
	}
	if !errors.Is(err, ErrIncompatible) || status.Degraded {
		t.Fatalf("future schema opened=%v status=%+v err=%v", opened != nil, status, err)
	}
	got, readErr := os.ReadFile(filepath.Join(root, primaryFile))
	if readErr != nil || !bytes.Equal(got, future) {
		t.Fatalf("future state was modified: err=%v", readErr)
	}
}

func TestChecksumTamperIsCorruption(t *testing.T) {
	state := validState(t, 1, 1)
	_, raw, err := sealDocument(state, 3, testNow)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte(`"desired_state":"active"`), []byte(`"desired_state":"paused"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("test did not alter document")
	}
	if _, _, err := decodeAnyDocument(tampered); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered document error = %v, want ErrCorrupt", err)
	}
}

func TestStateRejectsReusableCredentialsAndPreviewPersistence(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    error
	}{
		{name: "token", payload: `{"tunnel_id":"tun_01","token":"reusable-secret"}`, want: ErrCredentialMaterial},
		{name: "authorization header", payload: `{"headers":{"Authorization":"Bearer reusable-secret"}}`, want: ErrCredentialMaterial},
		{name: "private key", payload: `{"private_key":"reusable-secret"}`, want: ErrCredentialMaterial},
		{name: "preview lease", payload: `{"kind":"preview_lease","id":"prv_01"}`, want: ErrInvalidState},
		{name: "duplicate", payload: `{"tunnel_id":"tun_01","tunnel_id":"tun_02"}`, want: ErrInvalidState},
		{name: "secret disguised as reference", payload: `{"schema":"paperboat.preview-tunnel/v1","kind":"config_generation","tunnel_id":"tun_01","generation":1,"credential_reference":"reusable-secret"}`, want: ErrCredentialMaterial},
		{name: "token disguised as reference", payload: `{"schema":"paperboat.preview-tunnel/v1","kind":"config_generation","tunnel_id":"tun_01","generation":1,"token_reference":"reusable-secret"}`, want: ErrCredentialMaterial},
		{name: "excessive nesting", payload: `{"value":` + strings.Repeat(`[`, maxJSONDepth+1) + `0` + strings.Repeat(`]`, maxJSONDepth+1) + `}`, want: ErrInvalidState},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewConfigSnapshot("tun_01", 1, []byte(test.payload)); !errors.Is(err, test.want) {
				t.Fatalf("NewConfigSnapshot error = %v, want %v", err, test.want)
			}
		})
	}
	if _, err := NewConfigSnapshot("tun_01", 1, []byte(`{"schema":"paperboat.preview-tunnel/v1","kind":"tunnel_config_snapshot","tunnel_id":"tun_01","generation":1,"name":"demo","desired_state":"active","access_mode":"public","stable_endpoint":"https://123e4567-e89b-12d3-a456-426614174000.tunnels.example.test","expires_at":null,"routes":[{"id":"rte_01","name":"default","protocol":"http","match_type":"catch_all","path_prefix":null,"origin_scheme":"http","origin_address":"127.0.0.1:3000","preserve_host":true,"host_override":null,"tls_verification":"not_applicable","tls_server_name":null,"ca_reference":null,"mtls_credential_reference":null,"connect_timeout_ms":10000,"idle_timeout_ms":90000,"max_concurrent_streams":128,"desired_state":"active"}]}`)); err != nil {
		t.Fatalf("optional null credential reference: %v", err)
	}

	state := validState(t, 1, 1)
	state.Connectors[0].Credential.Reference = "keychain://paperboat/connectors/con_01?token=reusable-secret"
	if err := state.Validate(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("credential reference with query error = %v", err)
	}
	state = validState(t, 1, 1)
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("reusable-secret")) || bytes.Contains(raw, []byte(`"token"`)) || bytes.Contains(raw, []byte(`"secret"`)) {
		t.Fatalf("durable state contains reusable credential material: %s", raw)
	}
	state.Tunnels[0].LastKnownGood = nil
	if err := state.Validate(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("applied generation without last-known-good error = %v", err)
	}
}

func TestStateRejectsStableEndpointIdentityMismatch(t *testing.T) {
	state := validState(t, 1, 1)
	state.Tunnels[0].StableEndpointID = "123e4567-e89b-12d3-a456-426614174001"
	if !errors.Is(state.Validate(), ErrInvalidState) {
		t.Fatalf("mismatched stable endpoint identity was accepted: %v", state.Validate())
	}
	state = validState(t, 1, 1)
	state.Tunnels[0].StableEndpointID = "tep_0123456789abcdef"
	if !errors.Is(state.Validate(), ErrInvalidState) {
		t.Fatalf("noncanonical stable endpoint identity was accepted: %v", state.Validate())
	}
}

func TestAtomicWriteOutcomeClassification(t *testing.T) {
	for _, test := range []struct {
		stage   atomicfile.Stage
		changed bool
	}{
		{stage: atomicfile.StageValidate},
		{stage: atomicfile.StageCreate},
		{stage: atomicfile.StageWrite},
		{stage: atomicfile.StageOwner},
		{stage: atomicfile.StageReplace},
		{stage: atomicfile.StageSyncDir, changed: true},
	} {
		err := &atomicfile.Error{Stage: test.stage, Path: "/state.json", Err: errors.New("fault")}
		if got := atomicWriteMayHaveChanged(err); got != test.changed {
			t.Fatalf("stage %s changed=%v, want %v", test.stage, got, test.changed)
		}
	}
}

func validState(t *testing.T, desiredGeneration, appliedGeneration uint64) State {
	t.Helper()
	desired := mustSnapshot(t, desiredGeneration)
	var lastKnownGood *ConfigSnapshot
	if appliedGeneration > 0 {
		value := mustSnapshot(t, appliedGeneration)
		lastKnownGood = &value
	}
	updated := testNow.Add(time.Duration(desiredGeneration) * time.Minute)
	return State{
		Tunnels: []Tunnel{{
			ID: "tun_01", StableEndpointID: "123e4567-e89b-12d3-a456-426614174000", DesiredState: "active",
			DesiredGeneration: desiredGeneration, AppliedGeneration: appliedGeneration,
			DesiredSnapshot: desired, LastKnownGood: lastKnownGood, UpdatedAt: updated,
		}},
		RouteGenerations: []RouteGeneration{{TunnelID: "tun_01", RouteID: "rte_01", Generation: desiredGeneration}},
		Connectors: []Connector{{
			ID: "con_01", TunnelID: "tun_01", HostID: "host_01",
			Credential:         CredentialReference{Reference: "keychain://paperboat/connectors/con_01", Generation: 4},
			RotationGeneration: 4, LastAppliedGeneration: appliedGeneration,
		}},
		UpdateJournal: []UpdateJournalEntry{{
			ID: "jrn_01", TunnelID: "tun_01", Phase: "persisted", State: "pending",
			TargetGeneration: desiredGeneration, StartedAt: testNow, UpdatedAt: updated,
		}},
	}
}

func mustSnapshot(t *testing.T, generation uint64) ConfigSnapshot {
	t.Helper()
	payload := fmt.Sprintf(`{"schema":"paperboat.preview-tunnel/v1","kind":"tunnel_config_snapshot","tunnel_id":"tun_01","generation":%d,"name":"demo","desired_state":"active","access_mode":"public","stable_endpoint":"https://123e4567-e89b-12d3-a456-426614174000.tunnels.example.test","expires_at":null,"routes":[{"id":"rte_01","name":"default","protocol":"http","match_type":"catch_all","path_prefix":null,"origin_scheme":"http","origin_address":"127.0.0.1:3000","preserve_host":true,"host_override":null,"tls_verification":"not_applicable","tls_server_name":null,"ca_reference":null,"mtls_credential_reference":null,"connect_timeout_ms":10000,"idle_timeout_ms":90000,"max_concurrent_streams":128,"desired_state":"active"}]}`, generation)
	snapshot, err := NewConfigSnapshot("tun_01", generation, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertFileContains(t *testing.T, name, fragment string) {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), fragment) {
		t.Fatalf("%s does not contain %q", name, fragment)
	}
}
