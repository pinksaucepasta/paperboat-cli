//go:build darwin || linux

package runtime

import (
	"context"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelenrollment"
)

// TestPOSIXProductionTunnelEnrollmentRetainsLifecycle protects Linux and
// macOS client mode. The local endpoint is useful only when the same stable
// daemon starts its activator and recovery loop.
func TestPOSIXProductionTunnelEnrollmentRetainsLifecycle(t *testing.T) {
	service, err := NewProductionTunnelEnrollment(ProductionTunnelEnrollmentConfig{
		ControlURL:   "https://api.example.test",
		StateRoot:    t.TempDir(),
		HostID:       "host_posix_composition",
		ControlToken: "local-control-token",
		Auth:         posixCompositionMachineAuth{},
		Activator:    posixCompositionActivator{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := platformTunnelEnrollmentLifecycle(service); got != service {
		t.Fatalf("POSIX tunnel enrollment lifecycle = %T, want production service", got)
	}
}

type posixCompositionMachineAuth struct{}

func (posixCompositionMachineAuth) Token(context.Context) (string, error) {
	return "posix-composition-token", nil
}

func (posixCompositionMachineAuth) Proof(context.Context, string, string, string, []byte) ([]byte, error) {
	return []byte("posix-composition-proof"), nil
}

type posixCompositionActivator struct{}

func (posixCompositionActivator) Activate(context.Context, tunnelenrollment.ActivationRequest) (tunnelenrollment.Projection, error) {
	return tunnelenrollment.Projection{}, tunnelenrollment.ErrActivation
}
