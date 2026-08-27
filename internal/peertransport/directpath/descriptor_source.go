package directpath

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/signaling"
)

type PeerAttemptClient interface {
	CreatePeerAttempt(context.Context, api.PeerAttemptInput) (api.PeerAttemptDescriptor, error)
}

type APIDescriptorSourceConfig struct {
	Client                            PeerAttemptClient
	EnvironmentID                     string
	Purpose                           string
	Consumer                          string
	AccountID                         string
	TrustedKeys                       []endpointidentity.TrustedKey
	RootPublicKey                     ed25519.PublicKey // internal adapter for existing callers
	ControllingEndpointID             string
	ControlledEndpointID              string
	ControllingCertificateFingerprint string
	ControlledCertificateFingerprint  string
	OperationID                       func(Generation) string
	AllowedPaths                      []string
	Transfer                          *api.PeerAttemptTransfer
	RelayLatency                      func() *api.RelayLatencyVector
	OnAcquire                         func(AttemptDescriptor)
}

type APIDescriptorSource struct{ config APIDescriptorSourceConfig }

func cloneTrustedKeys(values []endpointidentity.TrustedKey) []endpointidentity.TrustedKey {
	result := make([]endpointidentity.TrustedKey, len(values))
	for index, value := range values {
		result[index] = value
		result[index].PublicKey = append([]byte(nil), value.PublicKey...)
	}
	return result
}

func NewAPIDescriptorSource(config APIDescriptorSourceConfig) (*APIDescriptorSource, error) {
	if nilInterface(config.Client) || !boundedDescriptorValue(config.EnvironmentID, 1, 128) || config.Purpose != "peer_transport" && config.Purpose != "interactive" && config.Purpose != "private_preview" && config.Purpose != "codex" && config.Purpose != "health_probe" && config.Purpose != "direct_probe" && config.Purpose != "file_transfer_key" || !validPurposeConsumer(config.Purpose, config.Consumer) || !validDescriptorTransfer(config.Purpose, config.Transfer) || !boundedDescriptorValue(config.AccountID, 1, 128) || !boundedDescriptorValue(config.ControllingEndpointID, 1, 128) || !boundedDescriptorValue(config.ControlledEndpointID, 1, 128) || config.ControllingEndpointID == config.ControlledEndpointID || !canonicalHexFingerprint(config.ControllingCertificateFingerprint) || !canonicalHexFingerprint(config.ControlledCertificateFingerprint) || config.OperationID == nil {
		return nil, ErrFactoryInvalid
	}
	if len(config.TrustedKeys) == 0 && len(config.RootPublicKey) == ed25519.PublicKeySize {
		fingerprint := sha256.Sum256(config.RootPublicKey)
		config.TrustedKeys = []endpointidentity.TrustedKey{{KeyID: "aek_" + hex.EncodeToString(fingerprint[:]), PublicKey: append(ed25519.PublicKey(nil), config.RootPublicKey...), Fingerprint: fingerprint, Generation: 1}}
	}
	trusted, err := endpointidentity.ValidateTrustedKeySet(config.TrustedKeys)
	if err != nil {
		return nil, ErrFactoryInvalid
	}
	config.TrustedKeys = trusted
	return &APIDescriptorSource{config: config}, nil
}

func (s *APIDescriptorSource) Acquire(ctx context.Context, generation Generation) (AttemptDescriptor, error) {
	if s == nil || ctx == nil || !generation.valid() {
		return AttemptDescriptor{}, ErrFactoryInvalid
	}
	operationID := s.config.OperationID(generation)
	if !boundedDescriptorValue(operationID, 16, 256) {
		return AttemptDescriptor{}, ErrFactoryInvalid
	}
	allowedPaths := requestedAllowedPaths(s.config.Purpose, s.config.AllowedPaths)
	input := api.PeerAttemptInput{OperationID: operationID, EnvironmentID: s.config.EnvironmentID, Purpose: s.config.Purpose, Consumer: s.config.Consumer, ControllingCertificateFingerprint: s.config.ControllingCertificateFingerprint, ControlledCertificateFingerprint: s.config.ControlledCertificateFingerprint, AttemptGeneration: generation.Attempt, NetworkGeneration: generation.Network, AllowedPaths: allowedPaths, Transfer: s.config.Transfer, RelayLatency: relayLatencyVector(s.config.RelayLatency)}
	document, err := s.config.Client.CreatePeerAttempt(ctx, input)
	if shouldRetryWithoutRelayLatency(err, input.RelayLatency) {
		// Relay selection is advisory. Older control planes can reject a fresh
		// vector when their persisted peer-selection state is unusable. Retry the
		// same idempotent operation once without the vector so that route tuning
		// can never block authenticated peer authority.
		input.RelayLatency = nil
		document, err = s.config.Client.CreatePeerAttempt(ctx, input)
	}
	if err != nil {
		return AttemptDescriptor{}, classifyDescriptorAPIError(err)
	}
	certificates, err := validateAPIDescriptor(document, s.config, operationID, generation)
	if err != nil {
		return AttemptDescriptor{}, err
	}
	relay := document.Relays[0]
	result := AttemptDescriptor{Document: document, IntentID: document.IntentID, AttemptGeneration: document.AttemptGeneration, NetworkGeneration: document.NetworkGeneration, Role: signaling.Role(document.Role), InitiatorEndpointID: document.InitiatorEndpointID, ResponderEndpointID: document.ResponderEndpointID, InitiatorCertificate: certificates[document.InitiatorEndpointID], ResponderCertificate: certificates[document.ResponderEndpointID], TrustedKeys: cloneTrustedKeys(s.config.TrustedKeys), RootPublicKey: append(ed25519.PublicKey(nil), s.config.RootPublicKey...), SignalingURL: document.Signaling.URL, SignalingCredential: document.Signaling.Credential, RelayRegion: relay.Region, RelayQUICURL: relay.QUICURL, RelayWSSURL: relay.WSSURL, RelayCredential: relay.RouteToken, RelayPMTUCredential: relay.PMTUToken, RelayPMTUURL: relay.PMTUURL, RouteGeneration: relay.RouteGeneration, STUNURLs: append([]string(nil), document.Direct.STUNURLs...), LocalUfrag: document.Direct.ICEUfrag, LocalPassword: document.Direct.ICEPassword, IssuedAt: document.IssuedAt, ExpiresAt: document.ExpiresAt}
	if s.config.OnAcquire != nil {
		s.config.OnAcquire(result)
	}
	return result, nil
}

func shouldRetryWithoutRelayLatency(err error, vector *api.RelayLatencyVector) bool {
	if err == nil || vector == nil {
		return false
	}
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusBadRequest && apiErr.Code == "invalid_request"
}

func relayLatencyVector(source func() *api.RelayLatencyVector) *api.RelayLatencyVector {
	if source == nil {
		return nil
	}
	return source()
}

func validateAPIDescriptor(value api.PeerAttemptDescriptor, config APIDescriptorSourceConfig, operationID string, generation Generation) (map[string][]byte, error) {
	allowedPaths := requestedAllowedPaths(config.Purpose, config.AllowedPaths)
	if reason := invalidAPIDescriptorDocumentReason(value, config, operationID, generation, allowedPaths); reason != "" {
		return nil, fmt.Errorf("%w: %s", ErrDescriptorInvalid, reason)
	}
	relay := value.Relays[0]
	if reason := invalidAPIDescriptorRelayReason(relay, value.ExpiresAt); reason != "" {
		return nil, fmt.Errorf("%w: %s", ErrDescriptorInvalid, reason)
	}
	wantRoles := map[string]endpointidentity.Role{value.InitiatorEndpointID: endpointidentity.RoleCLI, value.ResponderEndpointID: endpointidentity.RoleMachine}
	wantFingerprints := map[string]string{value.InitiatorEndpointID: config.ControllingCertificateFingerprint, value.ResponderEndpointID: config.ControlledCertificateFingerprint}
	seen := make(map[string]bool, 2)
	certificates := make(map[string][]byte, 2)
	for _, document := range value.EndpointCertificates {
		if seen[document.EndpointID] || wantRoles[document.EndpointID] == 0 {
			return nil, fmt.Errorf("%w: endpoint certificate identity", ErrDescriptorInvalid)
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(document.Certificate)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != document.Certificate {
			return nil, fmt.Errorf("%w: endpoint certificate encoding", ErrDescriptorInvalid)
		}
		keyID := document.KeyID
		if keyID == "" && len(config.TrustedKeys) == 1 {
			keyID = config.TrustedKeys[0].KeyID
		}
		certificate, err := endpointidentity.VerifyWithTrustedKey(raw, keyID, config.TrustedKeys, endpointidentity.Expected{AccountID: config.AccountID, Role: wantRoles[document.EndpointID], EndpointID: document.EndpointID}, value.IssuedAt)
		fingerprint := sha256.Sum256(raw)
		if err != nil || certificate.Claims.EndpointID != document.EndpointID || certificate.Claims.Role != wantRoles[document.EndpointID] || certificate.Claims.ExpiresAt.Before(value.ExpiresAt) || hex.EncodeToString(fingerprint[:]) != wantFingerprints[document.EndpointID] {
			return nil, fmt.Errorf("%w: endpoint certificate authority", ErrDescriptorInvalid)
		}
		seen[document.EndpointID] = true
		certificates[document.EndpointID] = append([]byte(nil), raw...)
	}
	if machineRaw := certificates[value.ResponderEndpointID]; len(machineRaw) > 0 {
		machine, err := endpointidentity.Parse(machineRaw)
		if err != nil || machine.Claims.Generation != value.HostGeneration {
			return nil, fmt.Errorf("%w: machine certificate generation", ErrDescriptorInvalid)
		}
	}
	if len(seen) != 2 {
		return nil, fmt.Errorf("%w: endpoint certificate count", ErrDescriptorInvalid)
	}
	return certificates, nil
}

func invalidAPIDescriptorDocumentReason(value api.PeerAttemptDescriptor, config APIDescriptorSourceConfig, operationID string, generation Generation, allowedPaths []string) string {
	switch {
	case value.Version != 1:
		return "version"
	case value.AccountID != config.AccountID:
		return "account binding"
	case value.DeviceID != config.ControllingEndpointID:
		return "device binding"
	case value.OperationID != operationID:
		return "operation binding"
	case value.EnvironmentID != config.EnvironmentID:
		return "environment binding"
	case value.Purpose != config.Purpose:
		return "purpose binding"
	case value.Consumer != config.Consumer:
		return "consumer binding"
	case !validAPIDescriptorStreamPolicy(config.Purpose, value.StreamPolicy):
		return "stream policy"
	case !equalDescriptorTransfer(value.Transfer, config.Transfer):
		return "transfer binding"
	case value.Role != string(signaling.RoleControlling):
		return "signaling role"
	case value.AttemptGeneration != generation.Attempt:
		return "attempt generation"
	case value.NetworkGeneration != generation.Network:
		return "network generation"
	case value.HostGeneration == 0:
		return "host generation"
	case value.AuthorizationGeneration == 0:
		return "authorization generation"
	case value.InitiatorEndpointID != config.ControllingEndpointID:
		return "initiator binding"
	case value.ResponderEndpointID != config.ControlledEndpointID:
		return "responder binding"
	case value.Signaling.Subprotocol != "paperboat.peer-signaling.v1":
		return "signaling subprotocol"
	case len(value.EndpointCertificates) != 2:
		return "endpoint certificate count"
	case len(value.Relays) != 1:
		return "relay count"
	case !slices.Equal(value.Policy.AllowedPaths, allowedPaths):
		return "allowed paths"
	case value.Policy.RelayDeadlineMS < 100 || value.Policy.RelayDeadlineMS > 60000:
		return "relay deadline"
	case value.Policy.HealthIntervalMS < 1000 || value.Policy.HealthIntervalMS > 300000:
		return "health interval"
	case value.Policy.MaxCandidates < 1 || value.Policy.MaxCandidates > 64:
		return "candidate limit"
	default:
		return ""
	}
}

func invalidAPIDescriptorRelayReason(relay api.PeerAttemptRelay, expiresAt time.Time) string {
	switch {
	case !boundedDescriptorValue(relay.Region, 1, 128):
		return "relay region"
	case relay.RouteGeneration == 0:
		return "relay generation"
	case !exactHTTPSURL(relay.QUICURL, "/v1/peer-relay"):
		return "relay QUIC URL"
	case !exactWSSURL(relay.WSSURL, "/v1/peer-relay"):
		return "relay WSS URL"
	case !compactToken(relay.RouteToken):
		return "relay route credential"
	case !compactToken(relay.PMTUToken):
		return "relay PMTU credential"
	case !exactUDPURL(relay.PMTUURL):
		return "relay PMTU URL"
	case !relay.ExpiresAt.Equal(expiresAt):
		return "relay expiry"
	default:
		return ""
	}
}

func requestedAllowedPaths(purpose string, configured []string) []string {
	if len(configured) > 0 {
		return append([]string(nil), configured...)
	}
	if purpose == "direct_probe" {
		return []string{"direct_quic"}
	}
	return []string{"direct_quic", "relay_quic", "relay_wss"}
}

func validAPIDescriptorStreamPolicy(purpose string, policy *api.PeerAttemptStreamPolicy) bool {
	if purpose != "peer_transport" {
		return policy == nil
	}
	return policy != nil && policy.Protocol == "paperboat.peer-stream.v1" && slices.Equal(policy.AllowedConsumers, []string{"terminal", "exec", "ssh", "private_preview", "codex"}) && policy.MaximumStreams == 64
}

func validPurposeConsumer(purpose, consumer string) bool {
	switch purpose {
	case "peer_transport":
		return consumer == "peer_transport"
	case "interactive":
		return consumer == "terminal" || consumer == "exec" || consumer == "ssh"
	case "private_preview", "codex", "health_probe", "file_transfer_key":
		return consumer == purpose
	case "direct_probe":
		return consumer == "terminal"
	default:
		return false
	}
}

func validDescriptorTransfer(purpose string, value *api.PeerAttemptTransfer) bool {
	if purpose != "file_transfer_key" {
		return value == nil
	}
	return value != nil && boundedDescriptorValue(value.TransferID, 1, 128) && value.Generation > 0 && !value.ExpiresAt.IsZero() && value.ExpiresAt.Nanosecond() == 0
}

func equalDescriptorTransfer(left, right *api.PeerAttemptTransfer) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.TransferID == right.TransferID && left.Generation == right.Generation && left.ExpiresAt.Equal(right.ExpiresAt)
}

func exactWSSURL(value, path string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "wss" && parsed.Host != "" && parsed.User == nil && parsed.Path == path && parsed.RawPath == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func exactHTTPSURL(value, path string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Path == path && parsed.RawPath == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func exactUDPURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "udp" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	port, err := net.LookupPort("udp", parsed.Port())
	return err == nil && port > 0
}

func compactToken(value string) bool {
	if len(value) == 0 || len(value) > 8192 || strings.TrimSpace(value) != value {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, character := range part {
			alphaNumeric := character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
			if !alphaNumeric && character != '-' && character != '_' {
				return false
			}
		}
	}
	return true
}

func classifyDescriptorAPIError(err error) error {
	if errors.Is(err, api.ErrUnauthenticated) {
		return errors.Join(ErrDescriptorUnauthorized, err)
	}
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return errors.Join(ErrDescriptorUnavailable, err)
	}
	switch apiErr.Code {
	case "route_unavailable", "udp_blocked", "reachability_failed", "temporarily_unavailable", "rate_limited":
		return errors.Join(ErrDescriptorUnavailable, err)
	case "certificate_revoked", "intent_revoked":
		return errors.Join(ErrDescriptorRevoked, err)
	case "authentication_required", "permission_denied", "insufficient_scope":
		return errors.Join(ErrDescriptorUnauthorized, err)
	default:
		if apiErr.Status >= http.StatusInternalServerError {
			return errors.Join(ErrDescriptorUnavailable, err)
		}
		return errors.Join(fmt.Errorf("%w: peer API status %d code %s", ErrDescriptorInvalid, apiErr.Status, apiErr.Code), err)
	}
}

func canonicalHexFingerprint(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func boundedDescriptorValue(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}
