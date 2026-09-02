package tunnelmanager

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

type updateGateSession struct{ done chan struct{} }

func (s *updateGateSession) OpenStream(context.Context) (connector.DataCarrierStreamLink, error) {
	return nil, errors.New("unused")
}
func (s *updateGateSession) AcceptStream(context.Context) (connector.DataCarrierStreamLink, error) {
	<-s.done
	return nil, io.EOF
}
func (s *updateGateSession) Ping(context.Context) error { return nil }
func (s *updateGateSession) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return nil
}
func (s *updateGateSession) CloseChan() <-chan struct{} { return s.done }

func updateGateActive(t *testing.T, tunnelID string, generation uint64) Active {
	t.Helper()
	identity := connector.DataCarrierIdentity{AccountID: "account_01", HostID: "host_01", TunnelID: tunnelID, ConnectorID: "connector_01", SessionID: "session_01", SessionGeneration: 7, ProcessGeneration: 8, Generation: generation}
	config := connector.DefaultDataCarrierPoolConfig()
	config.MaximumCarriers, config.SingleTransport, config.Preferred, config.Fallback = 1, true, connector.TCPMux, connector.TCPMux
	config.EdgeID, config.FailureDomains = "edge_01", []string{"hel1-a"}
	config.Session = connector.DataCarrierIdentity{}
	prepared, err := connector.PrepareDataCarrierRequest(context.Background(), connector.DataCarrierPrepareRequest{Identity: identity, Config: config, Dialer: func(_ context.Context, request connector.DataCarrierDialRequest) (connector.DataCarrierDialResult, error) {
		return connector.DataCarrierDialResult{Session: &updateGateSession{done: make(chan struct{})}, Transport: request.Transport, EdgeID: request.EdgeID, FailureDomain: request.FailureDomain, PeerIdentity: request.Identity}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := prepared.Activate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	path := "/"
	return &runtimeActive{request: ApplyRequest{Tunnel: hoststate.Tunnel{ID: tunnelID}, Connector: hoststate.Connector{ID: "connector_01", HostID: "host_01"}, Snapshot: hoststate.ConfigSnapshot{TunnelID: tunnelID, Generation: generation, ContentHash: "sha256:test"}, Decoded: hoststate.TunnelConfigSnapshot{TunnelID: tunnelID, Generation: generation, StableEndpoint: tunnelID + ".example.test", Routes: []hoststate.TunnelConfigRoute{{ID: "route_01", Protocol: "http", MatchType: "exact", MatchHostname: tunnelID + ".example.test", PathPrefix: &path, DesiredState: "active"}}}}, running: dataCarrierRunning{active: carrier}}
}

func TestUpdateGateRejectsEveryStaleLiveTargetFence(t *testing.T) {
	current := hostdproto.UpdateGateTargetBinding{Scope: hostdproto.UpdateGateScopeTunnel, MachineID: "machine_01", AccountID: "account_01", HostID: "host_01", TunnelID: "tunnel_01", ConnectorID: "connector_01", EdgeNodeID: "edge_01", ProcessEpoch: 2, SessionGeneration: 3, ConfigGeneration: 4, RouteGeneration: 5, FailureDomain: "hel1-a"}
	request := hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateCandidate, ExpectedTarget: &current}
	if !matchesUpdateGateTarget(request, current) {
		t.Fatal("exact target rejected")
	}
	mutations := []func(*hostdproto.UpdateGateTargetBinding){
		func(v *hostdproto.UpdateGateTargetBinding) { v.MachineID = "machine_02" },
		func(v *hostdproto.UpdateGateTargetBinding) { v.EdgeNodeID = "edge_02" },
		func(v *hostdproto.UpdateGateTargetBinding) { v.ProcessEpoch++ },
		func(v *hostdproto.UpdateGateTargetBinding) { v.SessionGeneration++ },
		func(v *hostdproto.UpdateGateTargetBinding) { v.ConfigGeneration++ },
		func(v *hostdproto.UpdateGateTargetBinding) { v.RouteGeneration++ },
		func(v *hostdproto.UpdateGateTargetBinding) { v.FailureDomain = "hel1-b" },
	}
	for index, mutate := range mutations {
		stale := current
		mutate(&stale)
		request.ExpectedTarget = &stale
		if matchesUpdateGateTarget(request, current) {
			t.Fatalf("stale case %d accepted", index)
		}
	}
}

func TestUpdateGateSelectsMultiTunnelCandidatesDeterministically(t *testing.T) {
	values := map[string]Active{"tunnel_z": &fakeActive{}, "tunnel_a": &fakeActive{}, "tunnel_m": &fakeActive{}}
	got := sortedActiveKeys(values)
	want := []string{"tunnel_a", "tunnel_m", "tunnel_z"}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("keys=%q", got)
		}
	}
}

func TestUpdateGateMultiTunnelTargetAndManifestLedger(t *testing.T) {
	manager := &Manager{active: map[string]Active{"tunnel_z": updateGateActive(t, "tunnel_z", 3), "tunnel_a": updateGateActive(t, "tunnel_a", 4)}, started: true, networkStates: map[string]networkRecoveryState{}}
	gate, err := NewUpdateGate(UpdateGateConfig{MachineID: "machine_01", Manager: manager, StatePath: filepath.Join(t.TempDir(), "update-gate.json")})
	if err != nil {
		t.Fatal(err)
	}
	request := hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateTarget, TransactionID: "transaction_01", Version: "2026.08.31.1", ManifestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	response, err := gate.HandleUpdateGate(context.Background(), request)
	if err != nil || response.Target.TunnelID != "tunnel_a" {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	request.ManifestSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := gate.HandleUpdateGate(context.Background(), request); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("conflict=%v", err)
	}
	gate.transactions["expired"] = updateGateTransaction{created: time.Now().Add(-3 * time.Hour)}
	gate.purgeTransactions(time.Now())
	if _, ok := gate.transactions["expired"]; ok {
		t.Fatal("expired transaction retained")
	}
}

func TestUpdateGateCommitIsTerminalAndIdempotent(t *testing.T) {
	manager := &Manager{active: map[string]Active{"tunnel_a": updateGateActive(t, "tunnel_a", 4)}, started: true, networkStates: map[string]networkRecoveryState{}}
	gate, err := NewUpdateGate(UpdateGateConfig{MachineID: "machine_01", Manager: manager, StatePath: filepath.Join(t.TempDir(), "update-gate.json")})
	if err != nil {
		t.Fatal(err)
	}
	manifest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	targetResponse, err := gate.HandleUpdateGate(context.Background(), hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateTarget, TransactionID: "transaction_commit", Version: "2026.08.31.1", ManifestSHA256: manifest})
	if err != nil {
		t.Fatal(err)
	}
	transaction := gate.transactions["transaction_commit"]
	transaction.path, transaction.status, transaction.samples = "/canary", 204, 3
	transaction.policyBound, transaction.drainStarted = true, true
	gate.transactions["transaction_commit"] = transaction
	gate.drained["transaction_commit"] = targetResponse.Target
	if err := gate.persist(); err != nil {
		t.Fatal(err)
	}
	commit := hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateCommit, TransactionID: "transaction_commit", Version: "2026.08.31.1", ManifestSHA256: manifest, ExpectedTarget: &targetResponse.Target}
	response, err := gate.HandleUpdateGate(context.Background(), commit)
	if err != nil || response.Target != targetResponse.Target {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	if !gate.transactions["transaction_commit"].committed || gate.transactions["transaction_commit"].drainStarted {
		t.Fatalf("terminal transaction=%+v", gate.transactions["transaction_commit"])
	}
	if _, ok := gate.drained["transaction_commit"]; ok {
		t.Fatal("committed transaction remains in drained recovery set")
	}
	// A replay is served from the terminal ledger even if the live carrier has
	// since moved to a different generation.
	manager.active["tunnel_a"] = updateGateActive(t, "tunnel_a", 5)
	replay, err := gate.HandleUpdateGate(context.Background(), commit)
	if err != nil || replay.Target != targetResponse.Target {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	wrong := commit
	wrong.ManifestSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := gate.HandleUpdateGate(context.Background(), wrong); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("wrong replay=%v", err)
	}
}

func TestUpdateGateReloadsDrainedAndCommittedTransactions(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "update-gate.json")
	manager := &Manager{active: map[string]Active{"tunnel_a": updateGateActive(t, "tunnel_a", 4)}, started: true, networkStates: map[string]networkRecoveryState{}}
	first, err := NewUpdateGate(UpdateGateConfig{MachineID: "machine_01", Manager: manager, StatePath: statePath})
	if err != nil {
		t.Fatal(err)
	}
	manifest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	initial, err := first.HandleUpdateGate(context.Background(), hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateTarget, TransactionID: "transaction_restart", Version: "2026.08.31.1", ManifestSHA256: manifest})
	if err != nil {
		t.Fatal(err)
	}
	transaction := first.transactions["transaction_restart"]
	transaction.path, transaction.status, transaction.samples = "/canary", 204, 3
	transaction.policyBound, transaction.drainStarted = true, true
	first.transactions["transaction_restart"] = transaction
	first.drained["transaction_restart"] = initial.Target
	if err := first.persist(); err != nil {
		t.Fatal(err)
	}
	second, err := NewUpdateGate(UpdateGateConfig{MachineID: "machine_01", Manager: manager, StatePath: statePath})
	if err != nil {
		t.Fatal(err)
	}
	if !second.transactions["transaction_restart"].drainStarted || second.drained["transaction_restart"] != initial.Target {
		t.Fatalf("reloaded=%+v drained=%+v", second.transactions["transaction_restart"], second.drained["transaction_restart"])
	}
	commit := hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateCommit, TransactionID: "transaction_restart", Version: "2026.08.31.1", ManifestSHA256: manifest, ExpectedTarget: &initial.Target}
	if _, err := second.HandleUpdateGate(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	third, err := NewUpdateGate(UpdateGateConfig{MachineID: "machine_01", Manager: manager, StatePath: statePath})
	if err != nil {
		t.Fatal(err)
	}
	if !third.transactions["transaction_restart"].committed || third.transactions["transaction_restart"].drainStarted {
		t.Fatalf("committed reload=%+v", third.transactions["transaction_restart"])
	}
	if _, err := third.HandleUpdateGate(context.Background(), commit); err != nil {
		t.Fatalf("committed replay after restart: %v", err)
	}
}

func TestUpdateGateRejectsCorruptPersistedTarget(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "update-gate.json")
	state := updateGateDiskState{Schema: updateGateStateSchema, Transactions: map[string]updateGateDiskTransaction{
		"transaction_bad": {Version: "2026.08.31.1", Manifest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Created: time.Now(), Target: hostdproto.UpdateGateTargetBinding{MachineID: "machine_01"}},
	}}
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = NewUpdateGate(UpdateGateConfig{MachineID: "machine_01", Manager: &Manager{}, StatePath: statePath})
	if !errors.Is(err, ErrUpdateGateUnavailable) {
		t.Fatalf("corrupt state error=%v", err)
	}
}
