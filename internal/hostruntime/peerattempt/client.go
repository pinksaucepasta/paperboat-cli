package peerattempt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	identitystore "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

var (
	ErrInvalid = errors.New("controlled peer attempt is invalid")
	ErrNone    = errors.New("no controlled peer attempt is pending")
)

type Config struct {
	ControlURL string
	StateRoot  string
	Transport  http.RoundTripper
	Timeout    time.Duration
	Clock      func() time.Time
}

type CredentialSource interface {
	Token(context.Context) (string, error)
	Proof(context.Context, string, string, string, []byte) ([]byte, error)
}

type Client struct {
	config     Config
	url        string
	http       *http.Client
	creds      CredentialSource
	identityMu sync.Mutex
}

func New(config Config, credentials CredentialSource) (*Client, error) {
	base, err := url.Parse(strings.TrimSpace(config.ControlURL))
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || config.StateRoot == "" || credentials == nil {
		return nil, ErrInvalid
	}
	if config.Timeout <= 0 || config.Timeout > 30*time.Second {
		config.Timeout = 15 * time.Second
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	endpoint := base.ResolveReference(&url.URL{Path: "/v1/machine-peer-attempts/next"})
	return &Client{config: config, url: endpoint.String(), creds: credentials, http: &http.Client{Transport: config.Transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalid }}}, nil
}

func (c *Client) Next(ctx context.Context) (api.PeerAttemptDescriptor, error) {
	c.identityMu.Lock()
	defer c.identityMu.Unlock()
	store, err := identitystore.Open(identitystore.Config{StateRoot: c.config.StateRoot})
	if err != nil {
		return api.PeerAttemptDescriptor{}, err
	}
	registration, err := store.Registration()
	if err != nil {
		return api.PeerAttemptDescriptor{}, err
	}
	endpoint, err := store.PeerEndpoint()
	if err != nil || len(endpoint.Certificate) == 0 || uint64(registration.InstallationGeneration) != endpoint.Generation {
		return api.PeerAttemptDescriptor{}, ErrInvalid
	}
	operationID := pollOperationID(registration.MachineID, endpoint.Generation)
	body, _ := json.Marshal(struct {
		OperationID string `json:"operation_id"`
		Generation  uint64 `json:"generation"`
	}{operationID, endpoint.Generation})
	token, err := c.creds.Token(ctx)
	if err != nil {
		return api.PeerAttemptDescriptor{}, err
	}
	proof, err := c.creds.Proof(ctx, operationID, http.MethodPost, "/v1/machine-peer-attempts/next", body)
	if err != nil {
		return api.PeerAttemptDescriptor{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return api.PeerAttemptDescriptor{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return api.PeerAttemptDescriptor{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return api.PeerAttemptDescriptor{}, ErrNone
	}
	if response.StatusCode != http.StatusOK {
		_, _ = io.CopyN(io.Discard, response.Body, 32<<10)
		return api.PeerAttemptDescriptor{}, ErrInvalid
	}
	var envelope struct {
		Data api.PeerAttemptDescriptor `json:"data"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return api.PeerAttemptDescriptor{}, ErrInvalid
	}
	if err := validate(envelope.Data, registration.MachineID, endpoint, c.config.Clock().UTC()); err != nil {
		return api.PeerAttemptDescriptor{}, err
	}
	return envelope.Data, nil
}

// Reject revokes a descriptor that was delivered while the host's bounded
// attempt set was full. This keeps the machine poller live and gives the
// controlling operation a deterministic retryable outcome instead of leaving
// a delivered intent stranded until expiry.
func (c *Client) Reject(ctx context.Context, descriptor api.PeerAttemptDescriptor) error {
	if c == nil || ctx == nil || descriptor.IntentID == "" || descriptor.AttemptGeneration == 0 {
		return ErrInvalid
	}
	path := "/v1/peer-attempts/" + url.PathEscape(descriptor.IntentID) + "/" + strconv.FormatUint(descriptor.AttemptGeneration, 10)
	operationDigest := sha256.Sum256([]byte("peer-attempt-reject\x00" + descriptor.IntentID + "\x00" + strconv.FormatUint(descriptor.AttemptGeneration, 10)))
	operationID := "op_peer_reject_" + hex.EncodeToString(operationDigest[:16])
	token, err := c.creds.Token(ctx)
	if err != nil {
		return err
	}
	proof, err := c.creds.Proof(ctx, operationID, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	base, err := url.Parse(c.config.ControlURL)
	if err != nil {
		return ErrInvalid
	}
	endpoint := base.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint.String(), nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Idempotency-Key", operationID)
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.CopyN(io.Discard, response.Body, 32<<10)
		return ErrInvalid
	}
	return nil
}

func validate(value api.PeerAttemptDescriptor, machineID string, local identitystore.PeerEndpoint, now time.Time) error {
	localCertificate, err := endpointidentity.Verify(local.Certificate, local.RootPublicKey, endpointidentity.Expected{Role: endpointidentity.RoleMachine, EndpointID: machineID, Generation: local.Generation}, now)
	if err != nil || value.Version != 1 || value.AccountID != localCertificate.Claims.AccountID || value.DeviceID != value.InitiatorEndpointID || value.OperationID == "" || value.IntentID == "" || value.EnvironmentID == "" || value.Purpose != "peer_transport" && value.Purpose != "interactive" && value.Purpose != "private_preview" && value.Purpose != "codex" && value.Purpose != "health_probe" && value.Purpose != "direct_probe" && value.Purpose != "file_transfer_key" || value.Purpose == "peer_transport" && value.Consumer != "peer_transport" || !validStreamPolicy(value.Purpose, value.StreamPolicy) || !validTransfer(value.Purpose, value.Transfer, now) || !validAllowedPaths(value.Purpose, value.Policy.AllowedPaths) || value.InitiatorEndpointID == "" || value.ResponderEndpointID != machineID || value.Role != "controlled" || value.AttemptGeneration == 0 || value.NetworkGeneration == 0 || value.HostGeneration != local.Generation || value.AuthorizationGeneration == 0 || value.IssuedAt.After(now.Add(30*time.Second)) || !value.ExpiresAt.After(now) || value.ExpiresAt.Sub(value.IssuedAt) > 5*time.Minute || len(value.EndpointCertificates) != 2 || len(value.Relays) != 1 || value.Signaling.Subprotocol != "paperboat.peer-signaling.v1" || !exactWSS(value.Signaling.URL, "/v1/peer-signaling") || !token(value.Signaling.Credential) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, document := range value.EndpointCertificates {
		raw, decodeErr := base64.RawURLEncoding.Strict().DecodeString(document.Certificate)
		role := endpointidentity.RoleCLI
		if document.EndpointID == machineID {
			role = endpointidentity.RoleMachine
		}
		certificate, verifyErr := endpointidentity.Verify(raw, local.RootPublicKey, endpointidentity.Expected{AccountID: value.AccountID, Role: role, EndpointID: document.EndpointID}, value.IssuedAt)
		if decodeErr != nil || base64.RawURLEncoding.EncodeToString(raw) != document.Certificate || verifyErr != nil || certificate.Claims.ExpiresAt.Before(value.ExpiresAt) || seen[document.EndpointID] || document.EndpointID != value.InitiatorEndpointID && document.EndpointID != machineID || document.EndpointID == machineID && !bytes.Equal(raw, local.Certificate) {
			return ErrInvalid
		}
		seen[document.EndpointID] = true
	}
	relay := value.Relays[0]
	if len(seen) != 2 || relay.RouteGeneration == 0 || !exactHTTPS(relay.QUICURL, "/v1/peer-relay") || !exactWSS(relay.WSSURL, "/v1/peer-relay") || !token(relay.RouteToken) || !token(relay.PMTUToken) || !exactUDP(relay.PMTUURL) || !relay.ExpiresAt.Equal(value.ExpiresAt) {
		return ErrInvalid
	}
	return nil
}

func validAllowedPaths(purpose string, paths []string) bool {
	if purpose == "direct_probe" || purpose == "private_preview" {
		return slices.Equal(paths, []string{"direct_quic"})
	}
	for _, allowed := range [][]string{{"direct_quic", "relay_quic", "relay_wss"}, {"direct_quic", "relay_quic"}, {"direct_quic"}, {"relay_quic"}, {"relay_quic", "relay_wss"}, {"relay_wss"}} {
		if slices.Equal(paths, allowed) {
			return true
		}
	}
	return false
}

func validStreamPolicy(purpose string, policy *api.PeerAttemptStreamPolicy) bool {
	if purpose != "peer_transport" {
		return policy == nil
	}
	return policy != nil && policy.Protocol == "paperboat.peer-stream.v1" && slices.Equal(policy.AllowedConsumers, []string{"terminal", "exec", "ssh", "private_preview", "codex"}) && policy.MaximumStreams == 64
}

func validTransfer(purpose string, value *api.PeerAttemptTransfer, now time.Time) bool {
	if purpose != "file_transfer_key" {
		return value == nil
	}
	return value != nil && value.TransferID != "" && len(value.TransferID) <= 128 && value.Generation > 0 && value.ExpiresAt.After(now) && value.ExpiresAt.Before(now.Add(8*24*time.Hour)) && value.ExpiresAt.Nanosecond() == 0
}

func pollOperationID(machineID string, generation uint64) string {
	h := sha256.New()
	h.Write([]byte(machineID))
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], generation)
	h.Write(encoded[:])
	return "op_peer_attempt_poll_" + hex.EncodeToString(h.Sum(nil)[:16])
}

func exactWSS(value, path string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "wss" && parsed.Host != "" && parsed.User == nil && parsed.Path == path && parsed.RawPath == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func exactHTTPS(value, path string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Path == path && parsed.RawPath == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func exactUDP(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "udp" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	port, err := strconv.Atoi(parsed.Port())
	return err == nil && port > 0 && port <= 65535
}

func token(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || len(value) > 8192 || strings.TrimSpace(value) != value {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
	}
	return true
}
