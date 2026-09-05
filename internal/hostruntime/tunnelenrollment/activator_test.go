package tunnelenrollment

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

type activatorCredentials struct {
	mu        sync.Mutex
	reference string
	payload   []byte
}

func (*activatorCredentials) CreateKey(context.Context, string) (Credential, error) {
	return Credential{}, errors.New("not used")
}
func (c *activatorCredentials) Sign(_ context.Context, reference string, payload []byte) ([]byte, error) {
	c.mu.Lock()
	c.reference = reference
	c.payload = append([]byte(nil), payload...)
	c.mu.Unlock()
	return []byte("reference-backed-signature"), nil
}
func (*activatorCredentials) PutEnrollmentToken(context.Context, string, string) (string, error) {
	return "", errors.New("not used")
}
func (*activatorCredentials) EnrollmentToken(context.Context, string) (string, error) {
	return "", errors.New("not used")
}
func (*activatorCredentials) DeleteEnrollmentToken(context.Context, string) error { return nil }

type invalidAssemblySource struct {
	request ActivationRequest
}

func (s *invalidAssemblySource) ResolveProductionAssembly(ctx context.Context, request ActivationRequest, signer CredentialSigner) (tunnelmanager.ProductionAssemblyConfig, error) {
	s.request = request
	if _, err := signer(ctx, []byte("connector-hello-transcript")); err != nil {
		return tunnelmanager.ProductionAssemblyConfig{}, err
	}
	return tunnelmanager.ProductionAssemblyConfig{}, nil
}

func TestProductionAssemblyActivatorRequiresStableLifecycleAndReferenceSigner(t *testing.T) {
	credentials := &activatorCredentials{}
	source := &invalidAssemblySource{}
	activator, err := NewProductionAssemblyActivator(ProductionAssemblyActivatorConfig{Credentials: credentials, Source: source})
	if err != nil {
		t.Fatal(err)
	}
	request := activationRequestFixture()
	_, err = activator.Activate(context.Background(), request)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("activation before stable start error = %v", err)
	}
	var lifecycleDiagnostic *ActivationDiagnostic
	if !errors.As(err, &lifecycleDiagnostic) || lifecycleDiagnostic.Code != ActivationDiagnosticLifecycleUnavailable {
		t.Fatalf("activation lifecycle diagnostic = %+v, err=%v", lifecycleDiagnostic, err)
	}
	if err := activator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := activator.Activate(context.Background(), request); !errors.Is(err, ErrActivation) {
		t.Fatalf("invalid resolved assembly error = %v", err)
	}
	credentials.mu.Lock()
	if credentials.reference != request.CredentialReference || string(credentials.payload) != "connector-hello-transcript" {
		t.Fatalf("reference signer call = ref %q payload %q", credentials.reference, credentials.payload)
	}
	credentials.mu.Unlock()
	if !reflect.DeepEqual(source.request, request) {
		t.Fatalf("source request = %+v", source.request)
	}
	if err := activator.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := activator.Shutdown(context.Background()); err != nil {
		t.Fatalf("idempotent shutdown: %v", err)
	}
	if _, err := activator.Activate(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("activation after shutdown error = %v", err)
	}
}

func TestResolvedAssemblyRequiresLazyWelcomeBoundCarrierAndExactCredential(t *testing.T) {
	request := activationRequestFixture()
	config := tunnelmanager.ProductionAssemblyConfig{
		StableEndpointID: request.StableEndpointID,
		ControlStream:    func(context.Context) (io.ReadWriteCloser, error) { return nil, errors.New("not opened") },
		CarrierDescriptorSource: func(context.Context, connectorprotocol.Welcome, tunnelmanager.ApplyRequest) (connector.DataCarrierSessionSource, error) {
			return connector.DataCarrierSessionSource{}, errors.New("not resolved")
		},
		InitialConnector: &hoststate.Connector{
			ID: request.ConnectorID, TunnelID: request.TunnelID, HostID: request.HostID,
			Credential: hoststate.CredentialReference{Reference: request.CredentialReference, Generation: 3}, RotationGeneration: 3,
		},
	}
	config.Control.Hello = connectorprotocol.Hello{
		AccountID: request.AccountID, TunnelID: request.TunnelID, HostID: request.HostID, ConnectorID: request.ConnectorID, ProcessGeneration: request.ProcessGeneration,
		Auth: connectorprotocol.AuthRequest{AccountID: request.AccountID, IdentityKeyID: request.CredentialKeyID, IdentityKeyThumbprint: request.CredentialThumbprint, CredentialGeneration: 3},
	}
	if err := validateResolvedAssembly(request, config); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
	config.Control.Hello.Auth.IdentityKeyThumbprint = "wrong-thumbprint"
	if err := validateResolvedAssembly(request, config); !errors.Is(err, ErrConflict) {
		t.Fatalf("credential mismatch error = %v", err)
	}
}

func activationRequestFixture() ActivationRequest {
	return ActivationRequest{
		AccountID: "account_01", TunnelID: "tunnel_01", HostID: "host_01", ConnectorID: "connector_01", OperationID: "operation_01", StableEndpointID: "123e4567-e89b-12d3-a456-426614174000",
		CredentialReference: "protected-file://paperboat/connectors/credential_01",
		CredentialKeyID:     "ed25519:thumbprint-01", CredentialThumbprint: "thumbprint-01",
		CredentialPublicKey: make([]byte, 32), CredentialGeneration: 3, ProcessGeneration: 2,
	}
}
