// Package tunnelenrollment owns stable-hostd connector enrollment.
//
// Enrollment bearers and Ed25519 private keys never cross the package API.
// Durable state contains only references, public identity material, and
// idempotency metadata needed to resume an interrupted exchange.
package tunnelenrollment

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
)

const Schema = "paperboat.tunnel-connector-enrollment/v1"

var (
	ErrInvalid             = errors.New("invalid tunnel connector enrollment")
	ErrAuthentication      = errors.New("tunnel connector enrollment authentication required")
	ErrForbidden           = errors.New("tunnel connector enrollment forbidden")
	ErrConflict            = errors.New("tunnel connector enrollment conflicts with durable state")
	ErrEnrollmentExpired   = errors.New("tunnel connector enrollment expired")
	ErrEnrollmentRetryable = errors.New("tunnel connector enrollment requires retry")
	ErrUnavailable         = errors.New("tunnel connector enrollment temporarily unavailable")
	ErrActivation          = errors.New("tunnel connector activation unavailable")
	ErrSecretStore         = errors.New("tunnel connector protected credential store unavailable")
)

type MachineAuth interface {
	Token(context.Context) (string, error)
	Proof(context.Context, string, string, string, []byte) ([]byte, error)
}

// CredentialStore is reference-only. Private bytes and enrollment tokens are
// write-only to enrollment orchestration and can only be used for signing or
// the exact pending exchange.
type CredentialStore interface {
	CreateKey(context.Context, string) (Credential, error)
	Sign(context.Context, string, []byte) ([]byte, error)
	PutEnrollmentToken(context.Context, string, string) (string, error)
	EnrollmentToken(context.Context, string) (string, error)
	DeleteEnrollmentToken(context.Context, string) error
}

type Credential struct {
	Reference  string `json:"reference"`
	KeyID      string `json:"key_id"`
	Thumbprint string `json:"thumbprint"`
	PublicKey  []byte `json:"public_key"`
}

func (c Credential) valid() bool {
	if c.Reference == "" || c.KeyID != "ed25519:"+c.Thumbprint || len(c.PublicKey) != ed25519.PublicKeySize || connectorprotocol.ValidateCredentialReference(c.Reference) != nil {
		return false
	}
	thumbprint, err := connectorprotocol.IdentityThumbprint(ed25519.PublicKey(c.PublicKey))
	return err == nil && thumbprint == c.Thumbprint
}

// Activator is the exact missing server/runtime composition boundary. It must
// obtain a server-authenticated connector session, initial snapshot, bootstrap
// control stream, and carrier endpoints, then start the canonical production
// assembly. Returning nil or a projection before readiness is forbidden.
type Activator interface {
	Activate(context.Context, ActivationRequest) (Projection, error)
}

type ActivationRequest struct {
	AccountID   string
	TunnelID    string
	HostID      string
	ConnectorID string
	OperationID string
	// StableEndpointID is the server-owned canonical UUID for the tunnel's
	// managed endpoint. It is never derived from a name, host, or URL.
	StableEndpointID     string
	CredentialReference  string
	CredentialKeyID      string
	CredentialThumbprint string
	CredentialPublicKey  []byte
	CredentialGeneration uint64
	ProcessGeneration    uint64
}

type Projection struct {
	Schema               string     `json:"schema"`
	Kind                 string     `json:"kind"`
	TunnelID             string     `json:"tunnel_id"`
	HostID               string     `json:"host_id"`
	ConnectorID          string     `json:"connector_id"`
	OperationID          string     `json:"operation_id"`
	State                string     `json:"state"`
	CredentialReference  string     `json:"credential_reference"`
	CredentialGeneration uint64     `json:"credential_generation"`
	ReadyAt              *time.Time `json:"ready_at,omitempty"`
}

func (p Projection) valid() bool {
	return p.Schema == Schema && p.Kind == "tunnel_connector" && p.TunnelID != "" && p.HostID != "" && p.ConnectorID != "" && p.OperationID != "" && p.State == "ready" && p.CredentialReference != "" && p.CredentialGeneration > 0 && p.ReadyAt != nil && !p.ReadyAt.IsZero()
}

type serverEnrollment struct {
	Schema       string              `json:"schema"`
	Kind         string              `json:"kind"`
	ID           string              `json:"id"`
	TunnelID     string              `json:"tunnel_id"`
	HostID       string              `json:"host_id"`
	Operation    api.TunnelOperation `json:"operation"`
	Token        string              `json:"enrollment_token"`
	ExpiresAt    time.Time           `json:"expires_at"`
	Capabilities []string            `json:"capabilities"`
	Replayed     bool                `json:"replayed"`
}

type serverActivation struct {
	Schema               string              `json:"schema"`
	Kind                 string              `json:"kind"`
	AccountID            string              `json:"account_id"`
	TunnelID             string              `json:"tunnel_id"`
	ConnectorID          string              `json:"connector_id"`
	HostID               string              `json:"host_id"`
	StableEndpointID     string              `json:"stable_endpoint_id"`
	CredentialGeneration uint64              `json:"credential_generation"`
	ProcessGeneration    uint64              `json:"process_generation"`
	Operation            api.TunnelOperation `json:"operation"`
}
