package tunnelenrollment

import (
	"errors"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connectorrotation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

// ActivationDiagnosticCode is a small, local-safe classification for an
// activation failure. It deliberately contains no provider message, URL, or
// credential material.
type ActivationDiagnosticCode string

const (
	ActivationDiagnosticLifecycleUnavailable   ActivationDiagnosticCode = "lifecycle_unavailable"
	ActivationDiagnosticControlHTTPDenied      ActivationDiagnosticCode = "control_http_denied"
	ActivationDiagnosticControlHTTPUnavailable ActivationDiagnosticCode = "control_http_unavailable"
	ActivationDiagnosticControlNetworkTLS      ActivationDiagnosticCode = "control_network_tls"
	ActivationDiagnosticInvalidSessionConfig   ActivationDiagnosticCode = "invalid_session_config"
)

// ActivationDiagnostic retains the typed cause for local callers while its
// Error method remains safe to expose through the local enrollment endpoint.
// The cause is never serialized by the HTTP adapter.
type ActivationDiagnostic struct {
	Code  ActivationDiagnosticCode
	Cause error
}

func (e *ActivationDiagnostic) Error() string {
	if e == nil || !validActivationDiagnosticCode(e.Code) {
		return "activation diagnostic unavailable"
	}
	return "activation diagnostic: " + string(e.Code)
}

func (e *ActivationDiagnostic) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *ActivationDiagnostic) Is(target error) bool {
	return target == ErrActivation
}

func validActivationDiagnosticCode(code ActivationDiagnosticCode) bool {
	switch code {
	case ActivationDiagnosticLifecycleUnavailable,
		ActivationDiagnosticControlHTTPDenied,
		ActivationDiagnosticControlHTTPUnavailable,
		ActivationDiagnosticControlNetworkTLS,
		ActivationDiagnosticInvalidSessionConfig:
		return true
	default:
		return false
	}
}

func activationDiagnosticCodeOf(err error) string {
	var diagnostic *ActivationDiagnostic
	if errors.As(err, &diagnostic) && diagnostic != nil && validActivationDiagnosticCode(diagnostic.Code) {
		return string(diagnostic.Code)
	}
	switch {
	case errors.Is(err, tunnelmanager.ErrProductionIdentityMissing),
		errors.Is(err, tunnelmanager.ErrProductionControlMissing):
		return string(ActivationDiagnosticLifecycleUnavailable)
	case connectorprotocol.CodeOf(err) != "",
		errors.Is(err, connectorrotation.ErrControlSessionInvalid),
		errors.Is(err, tunnelmanager.ErrProductionAssemblyInvalid),
		errors.Is(err, tunnelmanager.ErrProductionControlRestartRequired):
		return string(ActivationDiagnosticInvalidSessionConfig)
	default:
		return ""
	}
}

// ActivationDiagnosticCodeOf returns only a finite, local-safe diagnostic
// code. It is intended for production observation; callers must not log the
// original error alongside it.
func ActivationDiagnosticCodeOf(err error) string { return activationDiagnosticCodeOf(err) }
