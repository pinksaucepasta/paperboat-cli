package connectorprotocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
)

const CarrierIdentityURNPrefix = "urn:paperboat:connector-v1:carrier:"

const (
	MinOpaqueEpochBytes = 8
	MaxOpaqueEpochBytes = 128
)

var ErrCarrierIdentityBinding = errors.New("invalid connector carrier identity binding")

// ValidateOpaqueEpoch validates random base64url process epochs. Unlike a
// resource identifier, a valid opaque epoch may begin with '-' or '_'.
func ValidateOpaqueEpoch(value string) error {
	if len(value) < MinOpaqueEpochBytes || len(value) > MaxOpaqueEpochBytes {
		return ErrInvalidInput
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return ErrInvalidInput
	}
	return nil
}

// CarrierIdentityBinding is the exact non-secret identity authenticated by a
// connector data-carrier TLS leaf. It deliberately excludes route IDs so one
// carrier can multiplex many authorized routes.
type CarrierIdentityBinding struct {
	AccountID         string `json:"account_id"`
	HostID            string `json:"host_id"`
	TunnelID          string `json:"tunnel_id"`
	ConnectorID       string `json:"connector_id"`
	SessionID         string `json:"session_id"`
	ProcessGeneration uint64 `json:"process_generation"`
	ConfigGeneration  uint64 `json:"config_generation"`
	EdgeProcessEpoch  string `json:"edge_process_epoch"`
}

func (b CarrierIdentityBinding) Validate() error {
	if ValidateIdentifier(b.AccountID) != nil || ValidateIdentifier(b.HostID) != nil ||
		ValidateIdentifier(b.TunnelID) != nil || ValidateIdentifier(b.ConnectorID) != nil ||
		ValidateIdentifier(b.SessionID) != nil || b.TunnelID == b.ConnectorID ||
		b.ProcessGeneration == 0 || b.ConfigGeneration == 0 || ValidateOpaqueEpoch(b.EdgeProcessEpoch) != nil {
		return ErrCarrierIdentityBinding
	}
	return nil
}

// CarrierIdentityURN returns the one URI SAN placed in the short-lived
// machine client certificate. encoding/json preserves the declared field
// order, so every language can reproduce the same SHA-256 transcript.
func CarrierIdentityURN(binding CarrierIdentityBinding) (*url.URL, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		return nil, ErrCarrierIdentityBinding
	}
	digest := sha256.Sum256(encoded)
	value, err := url.Parse(CarrierIdentityURNPrefix + base64.RawURLEncoding.EncodeToString(digest[:]))
	if err != nil || value.String() == "" {
		return nil, ErrCarrierIdentityBinding
	}
	return value, nil
}

// MatchCarrierIdentityURN rejects missing, duplicate, unrelated, or stale
// carrier identity SANs. A replacement process using the same machine key
// therefore cannot be mistaken for the old carrier session.
func MatchCarrierIdentityURN(uris []*url.URL, binding CarrierIdentityBinding) error {
	want, err := CarrierIdentityURN(binding)
	if err != nil {
		return err
	}
	if len(uris) != 1 || uris[0] == nil || uris[0].String() != want.String() {
		return ErrCarrierIdentityBinding
	}
	return nil
}
