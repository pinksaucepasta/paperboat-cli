package hoststate_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

type snapshotRegressionFactory struct{}

func (snapshotRegressionFactory) Prepare(context.Context, tunnelmanager.ApplyRequest) (tunnelmanager.Candidate, error) {
	return nil, errors.New("snapshot regression factory must not be invoked")
}

func TestInitialSnapshotAcceptsServerConnectorIDWithOpaqueLocalCredentialReference(t *testing.T) {
	const (
		serverConnectorID = "con_server_assigned"
		localReference    = "protected-file://paperboat/connectors/credential_local_01"
		stableEndpointID  = "123e4567-e89b-12d3-a456-426614174000"
	)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	manager, _, err := tunnelmanager.OpenProduction(tunnelmanager.ProductionConfig{
		StateRoot: root,
		HostID:    "host_01",
		Factory:   snapshotRegressionFactory{},
		Report:    func(tunnelmanager.Observation) {},
		Clock:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	applier, err := manager.ConfigApplier(connectorprotocol.ClockFunc(func() time.Time { return now }), stableEndpointID)
	if err != nil {
		_ = manager.Shutdown(context.Background())
		t.Fatal(err)
	}
	applier.InitialConnector = &hoststate.Connector{
		ID: serverConnectorID, TunnelID: "tunnel_01", HostID: "host_01",
		Credential:         hoststate.CredentialReference{Reference: localReference, Generation: 4},
		RotationGeneration: 4,
	}
	payload := []byte(`{"schema":"paperboat.preview-tunnel/v1","kind":"tunnel_config_snapshot","tunnel_id":"tunnel_01","generation":1,"name":"demo","desired_state":"active","access_mode":"public","stable_endpoint":"https://123e4567-e89b-12d3-a456-426614174000.tunnels.pprbt.dev","expires_at":null,"routes":[{"id":"route_01","name":"default","protocol":"http","match_type":"managed_exact","match_hostname":"preview.example.test","wildcard_suffix":"","path_prefix":null,"origin_scheme":"http","origin_address":"127.0.0.1:3000","preserve_host":true,"host_override":null,"tls_verification":"not_applicable","tls_server_name":null,"ca_reference":null,"mtls_credential_reference":null,"connect_timeout_ms":10000,"idle_timeout_ms":90000,"max_concurrent_streams":128,"desired_state":"active"}]}`)
	snapshot, err := connectorprotocol.NewSnapshot("tunnel_01", 1, payload)
	if err != nil {
		_ = manager.Shutdown(context.Background())
		t.Fatal(err)
	}
	snapshot.AccountID = "account_01"
	snapshot.ConnectorID = serverConnectorID
	snapshot.SessionID = "session_01"
	snapshot.ProcessGeneration = 2
	prepared, err := applier.PrepareSnapshot(context.Background(), snapshot)
	if err != nil {
		_ = manager.Shutdown(context.Background())
		if errors.Is(err, connectorprotocol.ErrSnapshotRejected) {
			t.Fatalf("initial snapshot was rejected after server connector assignment: %v", err)
		}
		t.Fatal(err)
	}
	if prepared == nil {
		_ = manager.Shutdown(context.Background())
		t.Fatal("initial snapshot returned nil prepared configuration")
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	store, _, err := hoststate.Open(hoststate.Config{Root: filepath.Join(root, "tunnels"), Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	state, _, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Connectors) != 1 || state.Connectors[0].ID != serverConnectorID || state.Connectors[0].Credential.Reference != localReference {
		t.Fatalf("seeded connector = %+v, want server ID %q with local reference %q", state.Connectors, serverConnectorID, localReference)
	}
}
