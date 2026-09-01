package tunnelmanager

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
)

type dataCarrierSessionSourceFunc func(context.Context, ApplyRequest) (connector.DataCarrierPrepareRequest, error)

func (f dataCarrierSessionSourceFunc) PrepareDataCarrier(ctx context.Context, request ApplyRequest) (connector.DataCarrierPrepareRequest, error) {
	return f(ctx, request)
}

func TestDataCarrierBuilderRetriesUntilStagedAdmissionIsPublished(t *testing.T) {
	request := ApplyRequest{Tunnel: tunnelState(t, 3, 2).Tunnels[0], Connector: tunnelState(t, 3, 2).Connectors[0], Snapshot: tunnelSnapshot(t, 3)}
	identity := connector.DataCarrierIdentity{AccountID: "account_01", HostID: request.Connector.HostID, TunnelID: request.Tunnel.ID, ConnectorID: request.Connector.ID, SessionID: "session_01", ProcessGeneration: 8, Generation: request.Snapshot.Generation}
	config := connector.DefaultDataCarrierPoolConfig()
	config.MaximumCarriers = 1
	config.FailureDomains = []string{"domain-a"}
	config.Session = identity
	var attempts atomic.Int32
	var edge *connector.DataCarrier
	source := dataCarrierSessionSourceFunc(func(context.Context, ApplyRequest) (connector.DataCarrierPrepareRequest, error) {
		return connector.DataCarrierPrepareRequest{Identity: identity, Config: config, Dialer: func(_ context.Context, dial connector.DataCarrierDialRequest) (connector.DataCarrierDialResult, error) {
			if attempts.Add(1) < 3 {
				return connector.DataCarrierDialResult{}, connector.ErrDataCarrierClosed
			}
			local, remote := net.Pipe()
			var err error
			edge, err = connector.NewDataCarrierServer(context.Background(), remote, config.Carrier, connector.DataCarrierAdmission{Identity: identity, Authorize: func(context.Context, connector.StreamOpen) error { return nil }})
			if err != nil {
				_ = local.Close()
				_ = remote.Close()
				return connector.DataCarrierDialResult{}, err
			}
			return connector.DataCarrierDialResult{Link: local, PeerIdentity: identity, Transport: dial.Transport, EdgeID: dial.EdgeID, FailureDomain: dial.FailureDomain}, nil
		}}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	prepared, err := (DataCarrierBuilder{Sessions: source}).PrepareCarrier(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("attempts = %d, want 3", attempts.Load())
	}
	if err := prepared.Abort(context.Background()); err != nil {
		t.Fatal(err)
	}
	if edge != nil {
		_ = edge.Close()
	}
}

func TestDataCarrierBuilderDoesNotRetryPermanentCarrierFailure(t *testing.T) {
	request := ApplyRequest{Tunnel: tunnelState(t, 3, 2).Tunnels[0], Connector: tunnelState(t, 3, 2).Connectors[0], Snapshot: tunnelSnapshot(t, 3)}
	identity := connector.DataCarrierIdentity{AccountID: "account_01", HostID: request.Connector.HostID, TunnelID: request.Tunnel.ID, ConnectorID: request.Connector.ID, SessionID: "session_01", ProcessGeneration: 8, Generation: request.Snapshot.Generation}
	for _, failure := range []error{connector.ErrDataCarrierAdmission, connector.ErrInvalidDataCarrierEndpoint, errors.New("permanent carrier failure")} {
		t.Run(failure.Error(), func(t *testing.T) {
			config := connector.DefaultDataCarrierPoolConfig()
			config.Session = identity
			var attempts atomic.Int32
			source := dataCarrierSessionSourceFunc(func(context.Context, ApplyRequest) (connector.DataCarrierPrepareRequest, error) {
				return connector.DataCarrierPrepareRequest{Identity: identity, Config: config, Dialer: func(context.Context, connector.DataCarrierDialRequest) (connector.DataCarrierDialResult, error) {
					attempts.Add(1)
					return connector.DataCarrierDialResult{}, failure
				}}, nil
			})
			started := time.Now()
			_, err := (DataCarrierBuilder{Sessions: source}).PrepareCarrier(context.Background(), request)
			if !errors.Is(err, ErrConnectorUnavailable) {
				t.Fatalf("error = %v, want ErrConnectorUnavailable", err)
			}
			if got := attempts.Load(); got != 1 {
				t.Fatalf("dial attempts = %d, want 1", got)
			}
			if elapsed := time.Since(started); elapsed >= 100*time.Millisecond {
				t.Fatalf("permanent failure took %s; retry loop did not stop promptly", elapsed)
			}
		})
	}
}

func TestDataCarrierBuilderBindsLiveSessionToApplyGeneration(t *testing.T) {
	request := ApplyRequest{Tunnel: tunnelState(t, 3, 2).Tunnels[0], Connector: tunnelState(t, 3, 2).Connectors[0], Snapshot: tunnelSnapshot(t, 3)}
	identity := connector.DataCarrierIdentity{AccountID: "account_01", HostID: request.Connector.HostID, TunnelID: request.Tunnel.ID, ConnectorID: request.Connector.ID, SessionID: "session_01", ProcessGeneration: 8, Generation: request.Snapshot.Generation}
	config := connector.DefaultDataCarrierPoolConfig()
	config.MaximumCarriers = 1
	config.FailureDomains = []string{"domain-a"}
	config.Session = identity
	var edge *connector.DataCarrier
	source := dataCarrierSessionSourceFunc(func(context.Context, ApplyRequest) (connector.DataCarrierPrepareRequest, error) {
		return connector.DataCarrierPrepareRequest{Identity: identity, Config: config, Dialer: func(_ context.Context, dial connector.DataCarrierDialRequest) (connector.DataCarrierDialResult, error) {
			local, remote := net.Pipe()
			var err error
			edge, err = connector.NewDataCarrierServer(context.Background(), remote, config.Carrier, connector.DataCarrierAdmission{Identity: identity, Authorize: func(context.Context, connector.StreamOpen) error { return nil }})
			if err != nil {
				_ = local.Close()
				_ = remote.Close()
				return connector.DataCarrierDialResult{}, err
			}
			return connector.DataCarrierDialResult{Link: local, PeerIdentity: identity, Transport: dial.Transport, EdgeID: dial.EdgeID, FailureDomain: dial.FailureDomain}, nil
		}}, nil
	})
	prepared, err := (DataCarrierBuilder{Sessions: source}).PrepareCarrier(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	running, err := prepared.Activate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := running.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := running.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if edge != nil {
		_ = edge.Close()
	}
}

func TestDataCarrierBuilderRejectsStaleOrWrongSessionIdentityBeforeDial(t *testing.T) {
	request := ApplyRequest{Tunnel: tunnelState(t, 3, 2).Tunnels[0], Connector: tunnelState(t, 3, 2).Connectors[0], Snapshot: tunnelSnapshot(t, 3)}
	for _, mutate := range []func(*connector.DataCarrierIdentity){
		func(value *connector.DataCarrierIdentity) { value.HostID = "host_other" },
		func(value *connector.DataCarrierIdentity) { value.TunnelID = "tunnel_other" },
		func(value *connector.DataCarrierIdentity) { value.ConnectorID = "connector_other" },
		func(value *connector.DataCarrierIdentity) { value.Generation-- },
		func(value *connector.DataCarrierIdentity) { value.SessionID = "" },
		func(value *connector.DataCarrierIdentity) { value.ProcessGeneration = 0 },
	} {
		identity := connector.DataCarrierIdentity{AccountID: "account_01", HostID: request.Connector.HostID, TunnelID: request.Tunnel.ID, ConnectorID: request.Connector.ID, SessionID: "session_01", ProcessGeneration: 8, Generation: request.Snapshot.Generation}
		mutate(&identity)
		dialed := false
		source := dataCarrierSessionSourceFunc(func(context.Context, ApplyRequest) (connector.DataCarrierPrepareRequest, error) {
			config := connector.DefaultDataCarrierPoolConfig()
			config.Session = identity
			return connector.DataCarrierPrepareRequest{Identity: identity, Config: config, Dialer: func(context.Context, connector.DataCarrierDialRequest) (connector.DataCarrierDialResult, error) {
				dialed = true
				return connector.DataCarrierDialResult{}, errors.New("unexpected dial")
			}}, nil
		})
		_, err := (DataCarrierBuilder{Sessions: source}).PrepareCarrier(context.Background(), request)
		if !errors.Is(err, ErrGenerationConflict) || errors.Is(err, ErrConnectorUnavailable) || dialed {
			t.Fatalf("identity=%+v err=%v dialed=%v", identity, err, dialed)
		}
	}
}
