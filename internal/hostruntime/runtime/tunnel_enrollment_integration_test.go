package runtime

import (
	"context"
	"net/http"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelenrollment"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

type inertMachineAuth struct{}

func (inertMachineAuth) Token(context.Context) (string, error) {
	return "", tunnelenrollment.ErrAuthentication
}
func (inertMachineAuth) Proof(context.Context, string, string, string, []byte) ([]byte, error) {
	return nil, tunnelenrollment.ErrAuthentication
}

func TestProductionTunnelEnrollmentRequiresRealActivator(t *testing.T) {
	if _, err := NewProductionTunnelEnrollmentHandler(ProductionTunnelEnrollmentConfig{StateRoot: t.TempDir(), ControlURL: "https://api.example.test", HostID: "host_01", ControlToken: "local-token", Auth: inertMachineAuth{}}); err == nil {
		t.Fatal("missing activator accepted")
	}
}

func TestHostDependenciesExposeTunnelEnrollmentOnlyWhenExplicit(t *testing.T) {
	var _ http.Handler = (http.HandlerFunc)(func(http.ResponseWriter, *http.Request) {})
}

type unavailableAssemblySource struct{}

func (unavailableAssemblySource) ResolveProductionAssembly(context.Context, tunnelenrollment.ActivationRequest, tunnelenrollment.CredentialSigner) (tunnelmanager.ProductionAssemblyConfig, error) {
	return tunnelmanager.ProductionAssemblyConfig{}, tunnelenrollment.ErrUnavailable
}

func TestProductionTunnelEnrollmentOwnsStableAssemblyLifecycle(t *testing.T) {
	service, err := NewProductionTunnelEnrollment(ProductionTunnelEnrollmentConfig{
		StateRoot: t.TempDir(), ControlURL: "https://api.example.test", HostID: "host_01", ControlToken: "local-token", Auth: inertMachineAuth{},
		AssemblySource: unavailableAssemblySource{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if counts := service.ResourceCounts(); counts["tunnels"] != 0 || counts["active"] != 0 {
		t.Fatalf("initial counts = %#v", counts)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
