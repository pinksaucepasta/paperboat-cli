package tunnelenrollment

import (
	"errors"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

func TestActivationDiagnosticCodeOfUsesOnlyTypedFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "lifecycle", err: tunnelmanager.ErrProductionControlMissing, want: string(ActivationDiagnosticLifecycleUnavailable)},
		{name: "protocol", err: connectorprotocol.ErrIdentityMismatch, want: string(ActivationDiagnosticInvalidSessionConfig)},
		{name: "unknown", err: errors.New("wss://control.example/?token=secret"), want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ActivationDiagnosticCodeOf(test.err); got != test.want {
				t.Fatalf("diagnostic code = %q, want %q", got, test.want)
			}
		})
	}
}

func TestActivationDiagnosticErrorDoesNotExposeCause(t *testing.T) {
	err := &ActivationDiagnostic{Code: ActivationDiagnosticControlNetworkTLS, Cause: errors.New("wss://control.example/control?token=secret")}
	if got := err.Error(); got != "activation diagnostic: control_network_tls" {
		t.Fatalf("safe diagnostic error = %q", got)
	}
	if !errors.Is(err, ErrActivation) || !errors.Is(err, err.Cause) {
		t.Fatalf("typed cause was not retained: %v", err)
	}
}
