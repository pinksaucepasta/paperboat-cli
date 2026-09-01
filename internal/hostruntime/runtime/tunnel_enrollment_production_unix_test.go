package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connectorrotation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelenrollment"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

type reconnectAssemblyTestSource struct {
	mu       sync.Mutex
	requests []tunnelenrollment.ActivationRequest
}

func (s *reconnectAssemblyTestSource) ResolveProductionAssembly(_ context.Context, request tunnelenrollment.ActivationRequest, _ tunnelenrollment.CredentialSigner) (tunnelmanager.ProductionAssemblyConfig, error) {
	s.mu.Lock()
	s.requests = append(s.requests, request)
	s.mu.Unlock()
	hello := connectorprotocol.Hello{
		Protocol: connectorprotocol.ProtocolName, MinVersion: connectorprotocol.ProtocolVersion, MaxVersion: connectorprotocol.ProtocolVersion,
		AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID, HostID: request.HostID,
		ProcessGeneration: request.ProcessGeneration,
		Auth:              connectorprotocol.AuthRequest{AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID, HostID: request.HostID, ProcessGeneration: request.ProcessGeneration},
	}
	return tunnelmanager.ProductionAssemblyConfig{
		Control: connectorrotation.ControlSessionConfig{Hello: hello},
		ControlSessionFactory: func(context.Context, *tunnelmanager.CoordinatedConfigApplier) (connectorrotation.ControlSessionConfig, error) {
			return connectorrotation.ControlSessionConfig{Hello: hello}, nil
		},
		CarrierDescriptorSource: func(context.Context, connectorprotocol.Welcome, tunnelmanager.ApplyRequest) (connector.DataCarrierSessionSource, error) {
			return connector.DataCarrierSessionSource{}, nil
		},
	}, nil
}

type fakeProcessGenerationClaimer struct {
	mu      sync.Mutex
	latest  map[string]uint64
	claimed []tunnelenrollment.ActivationRequest
}

func (c *fakeProcessGenerationClaimer) ClaimProcessGeneration(_ context.Context, expected tunnelenrollment.ActivationRequest) (tunnelenrollment.ActivationRequest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.latest == nil {
		c.latest = make(map[string]uint64)
	}
	if latest, ok := c.latest[expected.TunnelID]; ok && expected.ProcessGeneration != latest {
		return tunnelenrollment.ActivationRequest{}, tunnelenrollment.ErrConflict
	}
	next := expected
	next.ProcessGeneration++
	c.latest[expected.TunnelID] = next.ProcessGeneration
	c.claimed = append(c.claimed, next)
	return next, nil
}

func testReconnectActivationRequest() tunnelenrollment.ActivationRequest {
	return tunnelenrollment.ActivationRequest{
		AccountID: "account_reconnect_01", TunnelID: "tunnel_reconnect_01", HostID: "host_reconnect_01", ConnectorID: "connector_reconnect_01",
		OperationID: "operation_reconnect_01", StableEndpointID: "123e4567-e89b-12d3-a456-426614174000",
		CredentialReference: "protected-file://paperboat/connectors/reconnect-credential-01", CredentialKeyID: "ed25519:thumbprint_reconnect_01",
		CredentialThumbprint: "thumbprint_reconnect_01", CredentialPublicKey: make([]byte, 32), CredentialGeneration: 3, ProcessGeneration: 2,
	}
}

func TestReconnectSafeProductionAssemblySourceClaimsFreshProcessGeneration(t *testing.T) {
	inner := &reconnectAssemblyTestSource{}
	claimer := &fakeProcessGenerationClaimer{}
	wrapper := &reconnectSafeProductionAssemblySource{inner: inner, credentials: claimer}
	request := testReconnectActivationRequest()
	config, err := wrapper.ResolveProductionAssembly(context.Background(), request, func(context.Context, []byte) ([]byte, error) {
		return []byte("signature"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	applier := &tunnelmanager.CoordinatedConfigApplier{}
	first, err := config.ControlSessionFactory(context.Background(), applier)
	if err != nil {
		t.Fatal(err)
	}
	if first.Hello.ProcessGeneration != request.ProcessGeneration+1 || first.Hello.Auth.ProcessGeneration != first.Hello.ProcessGeneration {
		t.Fatalf("first reconnect hello process_generation=%d auth_process_generation=%d", first.Hello.ProcessGeneration, first.Hello.Auth.ProcessGeneration)
	}
	second, err := config.ControlSessionFactory(context.Background(), applier)
	if err != nil {
		t.Fatal(err)
	}
	if second.Hello.ProcessGeneration != request.ProcessGeneration+2 || second.Hello.Auth.ProcessGeneration != second.Hello.ProcessGeneration {
		t.Fatalf("second reconnect hello process_generation=%d auth_process_generation=%d", second.Hello.ProcessGeneration, second.Hello.Auth.ProcessGeneration)
	}
	claimer.mu.Lock()
	defer claimer.mu.Unlock()
	if len(claimer.claimed) != 2 || claimer.claimed[0].ProcessGeneration != 3 || claimer.claimed[1].ProcessGeneration != 4 {
		t.Fatalf("claimed requests=%+v", claimer.claimed)
	}
	inner.mu.Lock()
	defer inner.mu.Unlock()
	if len(inner.requests) != 3 || inner.requests[1].ProcessGeneration != 3 || inner.requests[2].ProcessGeneration != 4 {
		t.Fatalf("resolved requests=%+v", inner.requests)
	}
}

func TestReconnectSafeProductionAssemblySourceRejectsCompetingStaleClaim(t *testing.T) {
	claimer := &fakeProcessGenerationClaimer{}
	request := testReconnectActivationRequest()
	first := &reconnectSafeProductionAssemblySource{inner: &reconnectAssemblyTestSource{}, credentials: claimer}
	second := &reconnectSafeProductionAssemblySource{inner: &reconnectAssemblyTestSource{}, credentials: claimer}
	firstConfig, err := first.ResolveProductionAssembly(context.Background(), request, func(context.Context, []byte) ([]byte, error) { return []byte("signature"), nil })
	if err != nil {
		t.Fatal(err)
	}
	secondConfig, err := second.ResolveProductionAssembly(context.Background(), request, func(context.Context, []byte) ([]byte, error) { return []byte("signature"), nil })
	if err != nil {
		t.Fatal(err)
	}
	applier := &tunnelmanager.CoordinatedConfigApplier{}
	if _, err := firstConfig.ControlSessionFactory(context.Background(), applier); err != nil {
		t.Fatal(err)
	}
	if _, err := secondConfig.ControlSessionFactory(context.Background(), applier); !errors.Is(err, tunnelenrollment.ErrConflict) {
		t.Fatalf("competing stale claim error=%v, want ErrConflict", err)
	}
	claimer.mu.Lock()
	defer claimer.mu.Unlock()
	if len(claimer.claimed) != 1 || claimer.claimed[0].ProcessGeneration != request.ProcessGeneration+1 {
		t.Fatalf("competing claims=%+v", claimer.claimed)
	}
}
