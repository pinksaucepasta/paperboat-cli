package connectorprotocol

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

func hostStatePayload(generation uint64) []byte {
	return hostStatePayloadWithState(generation, "active")
}

func hostStatePayloadWithState(generation uint64, desiredState string) []byte {
	return []byte(`{"schema":"paperboat.preview-tunnel/v1","kind":"tunnel_config_snapshot","tunnel_id":"tun_01","generation":` +
		formatUint(generation) + `,"name":"demo","desired_state":"` + desiredState + `","access_mode":"public","stable_endpoint":"https://123e4567-e89b-12d3-a456-426614174000.tunnels.example.test","expires_at":null,"routes":[{"id":"rte_01","name":"default","protocol":"http","match_type":"catch_all","path_prefix":null,"origin_scheme":"http","origin_address":"127.0.0.1:3000","preserve_host":true,"host_override":null,"tls_verification":"not_applicable","tls_server_name":null,"ca_reference":null,"mtls_credential_reference":null,"connect_timeout_ms":10000,"idle_timeout_ms":90000,"max_concurrent_streams":128,"desired_state":"active"}]}`)
}

func formatUint(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	index := len(buf)
	for value > 0 {
		index--
		buf[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[index:])
}

func TestHostStateApplierStagesThenPromotesLKG(t *testing.T) {
	clock := ClockFunc(func() time.Time { return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC) })
	store, _, err := hoststate.Open(hoststate.Config{Root: filepath.Join(t.TempDir(), "state"), Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	applier := &HostStateApplier{Store: store, Clock: clock, StableEndpointID: "123e4567-e89b-12d3-a456-426614174000"}
	first, err := NewSnapshot("tun_01", 1, hostStatePayload(1))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := applier.PrepareSnapshot(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	state, revision, err := store.Snapshot()
	if err != nil || revision != 1 || len(state.Tunnels) != 0 {
		t.Fatalf("prepare mutated durable state: revision=%d tunnels=%d err=%v", revision, len(state.Tunnels), err)
	}
	if err := prepared.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, revision, err = store.Snapshot()
	if err != nil || revision != 2 || len(state.Tunnels) != 1 || state.Tunnels[0].AppliedGeneration != 1 || state.Tunnels[0].LastKnownGood == nil {
		t.Fatalf("first promotion: revision=%d state=%+v err=%v", revision, state, err)
	}

	second, err := NewSnapshot("tun_01", 2, hostStatePayload(2))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = applier.PrepareSnapshot(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	state, revision, err = store.Snapshot()
	if err != nil || revision != 2 || state.Tunnels[0].AppliedGeneration != 1 || state.Tunnels[0].DesiredGeneration != 1 {
		t.Fatalf("candidate changed LKG before activation: revision=%d tunnel=%+v err=%v", revision, state.Tunnels[0], err)
	}
	if err := prepared.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, revision, err = store.Snapshot()
	if err != nil || revision != 3 || state.Tunnels[0].AppliedGeneration != 2 || state.Tunnels[0].LastKnownGood.Generation != 2 {
		t.Fatalf("second promotion: revision=%d tunnel=%+v err=%v", revision, state.Tunnels[0], err)
	}
}

func TestHostStateApplierRequiresCanonicalStableEndpointIdentity(t *testing.T) {
	cases := []struct {
		name             string
		stableEndpointID string
		endpointReplace  string
	}{
		{name: "missing", stableEndpointID: ""},
		{name: "hash-like fallback", stableEndpointID: "tep_0123456789abcdef"},
		{name: "mismatched", stableEndpointID: "123e4567-e89b-12d3-a456-426614174001"},
		{name: "endpoint hostname", stableEndpointID: "123e4567-e89b-12d3-a456-426614174000", endpointReplace: "demo.tunnels.example.test"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			clock := ClockFunc(func() time.Time { return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC) })
			store, _, err := hoststate.Open(hoststate.Config{Root: filepath.Join(t.TempDir(), "state"), Clock: clock.Now})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			payload := hostStatePayload(1)
			if test.endpointReplace != "" {
				payload = []byte(strings.Replace(string(payload), "123e4567-e89b-12d3-a456-426614174000.tunnels.example.test", test.endpointReplace, 1))
			}
			snapshot, err := NewSnapshot("tun_01", 1, payload)
			if err != nil {
				t.Fatal(err)
			}
			applier := &HostStateApplier{Store: store, Clock: clock, StableEndpointID: test.stableEndpointID}
			if _, err := applier.PrepareSnapshot(context.Background(), snapshot); !errors.Is(err, hoststate.ErrInvalidState) {
				t.Fatalf("PrepareSnapshot error = %v, want hoststate.ErrInvalidState", err)
			}
			state, revision, err := store.Snapshot()
			if err != nil || revision != 1 || len(state.Tunnels) != 0 {
				t.Fatalf("rejected identity mutated state: revision=%d state=%+v err=%v", revision, state, err)
			}
		})
	}
}

func TestHostStateApplierRejectsHashAndDeltaBaseMismatch(t *testing.T) {
	clock := ClockFunc(func() time.Time { return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC) })
	store, _, err := hoststate.Open(hoststate.Config{Root: filepath.Join(t.TempDir(), "state"), Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	applier := &HostStateApplier{Store: store, Clock: clock, StableEndpointID: "123e4567-e89b-12d3-a456-426614174000"}
	first, err := NewSnapshot("tun_01", 1, hostStatePayload(1))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := applier.PrepareSnapshot(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	badHash := first
	badHash.ContentHash = "sha256:" + strings.Repeat("a", 64)
	if _, err := applier.PrepareSnapshot(context.Background(), badHash); !errors.Is(err, ErrContentHashMismatch) {
		t.Fatalf("bad snapshot hash error=%v", err)
	}
	second, err := NewSnapshot("tun_01", 2, hostStatePayload(2))
	if err != nil {
		t.Fatal(err)
	}
	delta, err := NewDelta("tun_01", first, 2, second.Payload)
	if err != nil {
		t.Fatal(err)
	}
	delta.PreviousContentHash = "sha256:" + strings.Repeat("b", 64)
	if _, err := applier.PrepareDelta(context.Background(), delta); !errors.Is(err, ErrGenerationGap) {
		t.Fatalf("bad delta base error=%v", err)
	}
}

func TestHostStateApplierStagesIsolatedStateAndPromotesBoundConnector(t *testing.T) {
	clock := ClockFunc(func() time.Time { return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC) })
	store, _, err := hoststate.Open(hoststate.Config{Root: filepath.Join(t.TempDir(), "state"), Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	applier := &HostStateApplier{Store: store, Clock: clock, StableEndpointID: "123e4567-e89b-12d3-a456-426614174000"}
	first, err := NewSnapshot("tun_01", 1, hostStatePayload(1))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := applier.PrepareSnapshot(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, revision, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	state.Connectors = append(state.Connectors, hoststate.Connector{
		ID: "con_01", TunnelID: "tun_01", HostID: "host_01",
		Credential:         hoststate.CredentialReference{Reference: "keychain://paperboat/connectors/con_01", Generation: 1},
		RotationGeneration: 1, LastAppliedGeneration: 1,
	})
	if _, err := store.Commit(revision, state); err != nil {
		t.Fatal(err)
	}
	second, err := NewSnapshot("tun_01", 2, hostStatePayload(2))
	if err != nil {
		t.Fatal(err)
	}
	second.AccountID = "acct_01"
	second.ConnectorID = "con_01"
	second.SessionID = "sess_01"
	second.ProcessGeneration = 3
	prepared, err = applier.PrepareSnapshot(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	staged, ok := prepared.(interface {
		StagedState() (hoststate.State, error)
	})
	if !ok {
		t.Fatal("prepared host state does not expose its isolated candidate")
	}
	candidate, err := staged.StagedState()
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Tunnels[0].DesiredGeneration != 2 || candidate.Connectors[0].LastAppliedGeneration != 1 {
		t.Fatalf("staged state = %+v", candidate)
	}
	candidate.Tunnels[0].DesiredState = "deleted"
	again, err := staged.StagedState()
	if err != nil || again.Tunnels[0].DesiredState != "active" {
		t.Fatalf("staged state was mutable: state=%+v err=%v", again, err)
	}
	if err := prepared.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	committed, _, err := store.Snapshot()
	if err != nil || committed.Connectors[0].LastAppliedGeneration != 2 || committed.Tunnels[0].AppliedGeneration != 2 {
		t.Fatalf("bound promotion did not advance connector atomically: state=%+v err=%v", committed, err)
	}
}

func TestHostStatePreparedDurablyStagesDesiredBeforeManagerReadiness(t *testing.T) {
	clock := ClockFunc(func() time.Time { return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC) })
	store, _, err := hoststate.Open(hoststate.Config{Root: filepath.Join(t.TempDir(), "state"), Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	applier := &HostStateApplier{Store: store, Clock: clock, StableEndpointID: "123e4567-e89b-12d3-a456-426614174000"}
	first, err := NewSnapshot("tun_01", 1, hostStatePayload(1))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := applier.PrepareSnapshot(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, revision, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	state.Connectors = append(state.Connectors, hoststate.Connector{
		ID: "con_01", TunnelID: "tun_01", HostID: "host_01",
		Credential:         hoststate.CredentialReference{Reference: "keychain://paperboat/connectors/con_01", Generation: 1},
		RotationGeneration: 1, LastAppliedGeneration: 1,
	})
	if _, err := store.Commit(revision, state); err != nil {
		t.Fatal(err)
	}
	second, err := NewSnapshot("tun_01", 2, hostStatePayload(2))
	if err != nil {
		t.Fatal(err)
	}
	second.AccountID, second.ConnectorID, second.SessionID, second.ProcessGeneration = "acct_01", "con_01", "sess_01", 3
	prepared, err = applier.PrepareSnapshot(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	stager, ok := prepared.(interface{ Stage(context.Context) error })
	if !ok {
		t.Fatal("prepared host state has no durable desired-state boundary")
	}
	if err := stager.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	staged, revision, err := store.Snapshot()
	if err != nil || staged.Tunnels[0].DesiredGeneration != 2 || staged.Tunnels[0].AppliedGeneration != 1 || staged.Tunnels[0].LastKnownGood.Generation != 1 || staged.Connectors[0].LastAppliedGeneration != 1 {
		t.Fatalf("desired staging changed active LKG: state=%+v err=%v", staged, err)
	}
	if err := prepared.Activate(context.Background()); !errors.Is(err, ErrNotReady) {
		t.Fatalf("activation before manager readiness error = %v, want %v", err, ErrNotReady)
	}
	lkg := staged.Tunnels[0].DesiredSnapshot
	staged.Tunnels[0].AppliedGeneration = 2
	staged.Tunnels[0].LastKnownGood = &lkg
	staged.Connectors[0].LastAppliedGeneration = 2
	if _, err := store.Commit(revision, staged); err != nil {
		t.Fatal(err)
	}
	if err := prepared.Activate(context.Background()); err != nil {
		t.Fatalf("activation after exact manager readiness: %v", err)
	}
}

func TestHostStateApplierPersistsPausedStateAndRemovesDeletedTunnel(t *testing.T) {
	clock := ClockFunc(func() time.Time { return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC) })
	store, _, err := hoststate.Open(hoststate.Config{Root: filepath.Join(t.TempDir(), "state"), Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	applier := &HostStateApplier{Store: store, Clock: clock, StableEndpointID: "123e4567-e89b-12d3-a456-426614174000"}
	for _, test := range []struct {
		generation   uint64
		desiredState string
	}{
		{generation: 1, desiredState: "active"},
		{generation: 2, desiredState: "paused"},
	} {
		snapshot, err := NewSnapshot("tun_01", test.generation, hostStatePayloadWithState(test.generation, test.desiredState))
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := applier.PrepareSnapshot(context.Background(), snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if err := prepared.Activate(context.Background()); err != nil {
			t.Fatal(err)
		}
		state, _, err := store.Snapshot()
		if err != nil || len(state.Tunnels) != 1 || state.Tunnels[0].DesiredState != test.desiredState || state.Tunnels[0].AppliedGeneration != test.generation {
			t.Fatalf("state after %s: state=%+v err=%v", test.desiredState, state, err)
		}
	}
	deleted, err := NewSnapshot("tun_01", 3, hostStatePayloadWithState(3, "deleted"))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := applier.PrepareSnapshot(context.Background(), deleted)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, _, err := store.Snapshot()
	if err != nil || len(state.Tunnels) != 0 || len(state.RouteGenerations) != 0 {
		t.Fatalf("deleted tunnel remained in durable state: state=%+v err=%v", state, err)
	}
}
