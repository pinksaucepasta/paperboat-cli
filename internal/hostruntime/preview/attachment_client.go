package preview

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
)

const (
	PreviewCarrierAttachmentKind = "preview_carrier_attachment"
	attachmentRequestMaxBytes    = 64 << 10
	attachmentResponseMaxBytes   = 64 << 10
	attachmentProofMaxBytes      = 16 << 10
	attachmentIdentityMaxBytes   = 16 << 10
	attachmentAdmissionPoll      = 250 * time.Millisecond
)

var (
	ErrAttachmentClientInvalid     = errors.New("invalid preview carrier attachment client")
	ErrAttachmentClientUnavailable = errors.New("preview carrier attachment service unavailable")
	ErrAttachmentClientRejected    = errors.New("preview carrier attachment request rejected")
	ErrAttachmentBinding           = errors.New("preview carrier attachment binding is invalid")
	ErrAttachmentSessionInvalid    = errors.New("preview carrier attachment session is invalid")
	ErrAttachmentLeaseETagStale    = errors.New("preview lease ETag is stale")
	ErrAttachmentAdmissionPending  = errors.New("preview carrier attachment is waiting for edge admission")
)

// AttachmentAdmissionWaiter is implemented by an attachment transport that
// can replay the same durable allocation until the server has accepted the
// edge admission. The request and proof envelope remain unchanged; only the
// server-issued attachment state/generation may advance. It returns as soon
// as the server reports admitted, edge_ready, or ready. A carrier must use
// AttachmentEdgeReadyWaiter after it has connected when it needs to wait for
// the edge to observe that carrier.
type AttachmentAdmissionWaiter interface {
	WaitForAdmission(context.Context, AttachmentRequest, Attachment) (Attachment, error)
}

// AttachmentEdgeReadyWaiter waits for the edge-side observation of an
// already-admitted carrier. This is a separate phase because the host must
// connect the carrier while the attachment is only admitted; waiting for
// edge_ready before dialing creates a circular handshake.
type AttachmentEdgeReadyWaiter interface {
	WaitForEdgeReady(context.Context, AttachmentRequest, Attachment) (Attachment, error)
}

// AttachmentReadinessObserver records the owner's origin probe after the
// edge has accepted the server-issued admission. It is deliberately
// separate from Allocation so a pending/admitted response can never be
// mistaken for lease readiness.
type AttachmentReadinessObserver interface {
	ObserveOrigin(context.Context, AttachmentRequest, Attachment, bool) (Attachment, error)
}

// AttachmentRequest is the secret-free operation envelope accepted by the
// server's POST /v1/previews/{preview_id}/carrier-attachment endpoint.
// OperationID and IdempotencyKey are intentionally the same value. The
// machine proof is bound to that exact operation so a retry cannot be
// repurposed for another attachment.
type AttachmentRequest struct {
	PreviewID      string `json:"preview_id"`
	OperationID    string `json:"operation_id"`
	OwnerDeviceID  string `json:"owner_device_id"`
	OwnerSessionID string `json:"owner_session_id"`
	IdempotencyKey string `json:"idempotency_key"`
	RequestID      string `json:"request_id"`
	CorrelationID  string `json:"correlation_id"`
	// LeaseETag is transport metadata for the lease precondition. It is
	// intentionally excluded from the signed request body and must be sent
	// verbatim as If-Match by AttachmentClient.
	LeaseETag string `json:"-"`
}

// AttachmentRequestForLease builds the attachment request from the immutable
// server create operation retained on Lease. It intentionally refuses to
// substitute a client idempotency key or preview ID when that operation is
// unavailable.
func AttachmentRequestForLease(lease Lease, requestID, correlationID string) (AttachmentRequest, error) {
	if !validLeaseID(lease.ID) || !validLeaseID(lease.OwnerDeviceID) || !validLeaseID(lease.OwnerSessionID) || !validLeaseID(lease.CreateOperationID) {
		return AttachmentRequest{}, fmt.Errorf("%w: lease has no durable create operation", ErrAttachmentBinding)
	}
	request := AttachmentRequest{
		PreviewID: lease.ID, OperationID: lease.CreateOperationID,
		OwnerDeviceID: lease.OwnerDeviceID, OwnerSessionID: lease.OwnerSessionID,
		IdempotencyKey: lease.CreateOperationID, RequestID: requestID, CorrelationID: correlationID,
		LeaseETag: strings.TrimSpace(lease.ETag),
	}
	if err := request.Validate(); err != nil {
		return AttachmentRequest{}, err
	}
	if strings.TrimSpace(lease.ETag) == "" {
		return AttachmentRequest{}, errors.Join(ErrAttachmentBinding, api.ErrPreviewLeaseETagRequired)
	}
	if err := api.ValidatePreviewLeaseETag(lease.ID, lease.ETag); err != nil {
		return AttachmentRequest{}, fmt.Errorf("%w: lease ETag: %v", ErrAttachmentBinding, err)
	}
	return request, nil
}

func (r AttachmentRequest) Validate() error {
	if !validAttachmentID(r.PreviewID) || !validAttachmentID(r.OperationID) || !validAttachmentID(r.OwnerDeviceID) || !validAttachmentID(r.OwnerSessionID) {
		return fmt.Errorf("%w: incomplete attachment request", ErrAttachmentClientInvalid)
	}
	if r.OperationID != r.IdempotencyKey || !validAttachmentID(r.IdempotencyKey) {
		return fmt.Errorf("%w: operation and idempotency keys must match", ErrAttachmentClientInvalid)
	}
	if len(r.RequestID) < 3 || len(r.RequestID) > 128 || len(r.CorrelationID) < 3 || len(r.CorrelationID) > 128 || hasAttachmentControl(r.RequestID) || hasAttachmentControl(r.CorrelationID) {
		return fmt.Errorf("%w: invalid request or correlation ID", ErrAttachmentClientInvalid)
	}
	if r.LeaseETag != "" {
		if err := api.ValidatePreviewLeaseETag(r.PreviewID, r.LeaseETag); err != nil {
			return fmt.Errorf("%w: lease ETag: %v", ErrAttachmentBinding, err)
		}
	}
	return nil
}

// Hash is the server-compatible canonical request hash. It binds the
// authoritative account returned in the attachment to every request field,
// without ever including a credential or proof.
func (r AttachmentRequest) Hash(accountID string) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	if !validAttachmentID(accountID) {
		return "", fmt.Errorf("%w: invalid account ID", ErrAttachmentClientInvalid)
	}
	envelope := struct {
		AccountID      string `json:"account_id"`
		PreviewID      string `json:"preview_id"`
		OperationID    string `json:"operation_id"`
		OwnerDeviceID  string `json:"owner_device_id"`
		OwnerSessionID string `json:"owner_session_id"`
		IdempotencyKey string `json:"idempotency_key"`
		RequestID      string `json:"request_id"`
		CorrelationID  string `json:"correlation_id"`
	}{accountID, r.PreviewID, r.OperationID, r.OwnerDeviceID, r.OwnerSessionID, r.IdempotencyKey, r.RequestID, r.CorrelationID}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("%w: canonical request: %v", ErrAttachmentClientInvalid, err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// Binding is the server-authenticated identity and generation projection.
// It contains no bearer, private-key, or renewable credential material.
type Binding struct {
	AccountID                            string `json:"account_id"`
	PreviewID                            string `json:"preview_id"`
	OperationID                          string `json:"operation_id"`
	OwnerDeviceID                        string `json:"owner_device_id"`
	OwnerSessionID                       string `json:"owner_session_id"`
	HostID                               string `json:"host_id"`
	LeaseGeneration                      uint64 `json:"lease_generation"`
	TunnelID                             string `json:"tunnel_id"`
	ConnectorID                          string `json:"connector_id"`
	SessionID                            string `json:"session_id"`
	ProcessGeneration                    uint64 `json:"process_generation"`
	ConfigGeneration                     uint64 `json:"config_generation"`
	RouteID                              string `json:"route_id"`
	RouteGeneration                      uint64 `json:"route_generation"`
	EdgeNodeID                           string `json:"edge_node_id"`
	EdgeProcessEpoch                     string `json:"edge_process_epoch"`
	EdgeCarrierServerSPKISHA256          string `json:"edge_carrier_server_spki_sha256"`
	EdgeCarrierServerCertificateChainPEM string `json:"edge_carrier_server_certificate_chain_pem"`
	MachineIdentityPublicKey             string `json:"machine_identity_public_key"`
	MachineIdentityThumbprint            string `json:"machine_identity_thumbprint"`
}

func (b Binding) Validate() error {
	for name, value := range map[string]string{
		"account_id": b.AccountID, "preview_id": b.PreviewID, "operation_id": b.OperationID,
		"owner_device_id": b.OwnerDeviceID, "owner_session_id": b.OwnerSessionID,
		"host_id": b.HostID, "tunnel_id": b.TunnelID, "connector_id": b.ConnectorID,
		"session_id": b.SessionID, "route_id": b.RouteID,
		"edge_node_id": b.EdgeNodeID, "edge_process_epoch": b.EdgeProcessEpoch,
	} {
		if !validAttachmentID(value) {
			return fmt.Errorf("%w: invalid %s", ErrAttachmentBinding, name)
		}
	}
	if b.HostID != b.OwnerDeviceID {
		return fmt.Errorf("%w: host and owner device differ", ErrAttachmentBinding)
	}
	if b.TunnelID == b.ConnectorID {
		return fmt.Errorf("%w: tunnel and connector identities must differ", ErrAttachmentBinding)
	}
	if b.LeaseGeneration == 0 || b.ProcessGeneration == 0 || b.ConfigGeneration == 0 || b.RouteGeneration == 0 {
		return fmt.Errorf("%w: carrier generations must be positive", ErrAttachmentBinding)
	}
	if connectorprotocol.ValidateOpaqueEpoch(b.EdgeProcessEpoch) != nil {
		return fmt.Errorf("%w: invalid edge process epoch", ErrAttachmentBinding)
	}
	if !validEdgeCarrierServerSPKISHA256(b.EdgeCarrierServerSPKISHA256) || !validEdgeCarrierServerCertificateChainPEM(b.EdgeCarrierServerCertificateChainPEM, b.EdgeCarrierServerSPKISHA256) {
		return fmt.Errorf("%w: invalid edge carrier server trust", ErrAttachmentBinding)
	}
	if !validMachineIdentityPublicKey(b.MachineIdentityPublicKey) {
		return fmt.Errorf("%w: invalid machine identity public key", ErrAttachmentBinding)
	}
	if !validMachineIdentityThumbprint(b.MachineIdentityThumbprint) {
		return fmt.Errorf("%w: invalid machine identity thumbprint", ErrAttachmentBinding)
	}
	if got := machineIdentityThumbprint(b.MachineIdentityPublicKey); got != b.MachineIdentityThumbprint {
		return fmt.Errorf("%w: machine identity thumbprint does not match public key", ErrAttachmentBinding)
	}
	return nil
}

func validEdgeCarrierServerSPKISHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func validEdgeCarrierServerCertificateChainPEM(value, pin string) bool {
	if len(value) == 0 || len(value) > 64<<10 || !validEdgeCarrierServerSPKISHA256(pin) {
		return false
	}
	rest := []byte(value)
	count := 0
	for len(bytes.TrimSpace(rest)) != 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) == 0 {
			return false
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false
		}
		if count == 0 {
			digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
			if pin != "sha256:"+hex.EncodeToString(digest[:]) {
				return false
			}
		}
		count++
		if count > 8 {
			return false
		}
		rest = remaining
	}
	return count > 0
}

// Attachment is the server response. It deliberately mirrors only the
// secret-free previewattachment wire projection. Strict decoding below means
// a future response containing token/private-key/bearer fields is rejected,
// never silently accepted or persisted.
type Attachment struct {
	Schema string `json:"schema"`
	Kind   string `json:"kind"`
	Binding
	IdempotencyKey       string      `json:"idempotency_key"`
	RequestID            string      `json:"request_id"`
	CorrelationID        string      `json:"correlation_id"`
	RequestHash          string      `json:"request_hash"`
	Endpoint             string      `json:"endpoint"`
	Target               LeaseTarget `json:"target"`
	AccessMode           string      `json:"access_mode"`
	ConfigContentHash    string      `json:"config_content_hash"`
	EdgeEndpoints        []string    `json:"edge_endpoints"`
	AttachmentGeneration uint64      `json:"attachment_generation"`
	IssuedAt             time.Time   `json:"issued_at"`
	ExpiresAt            time.Time   `json:"expires_at"`
	State                string      `json:"state"`
	EdgeReady            bool        `json:"edge_ready"`
	OriginReady          bool        `json:"origin_ready"`
	ReadyAt              *time.Time  `json:"ready_at,omitempty"`
	ReleasedAt           *time.Time  `json:"released_at,omitempty"`
}

// CarrierAdmission is the write-only safe projection used to acquire an
// authenticated carrier. It contains identity, route, generation, and
// endpoint metadata only.
type CarrierAdmission struct {
	Schema               string    `json:"schema"`
	Kind                 string    `json:"kind"`
	Binding              Binding   `json:"binding"`
	AccessMode           string    `json:"access_mode"`
	AttachmentGeneration uint64    `json:"attachment_generation"`
	ConfigContentHash    string    `json:"config_content_hash"`
	EdgeEndpoints        []string  `json:"edge_endpoints"`
	Endpoint             string    `json:"endpoint"`
	ExpiresAt            time.Time `json:"expires_at"`
}

func (a Attachment) Validate(now time.Time) error {
	if a.Schema != PreviewTunnelSchemaV1 || a.Kind != PreviewCarrierAttachmentKind {
		return fmt.Errorf("%w: invalid attachment schema or kind", ErrAttachmentBinding)
	}
	if err := a.Binding.Validate(); err != nil {
		return err
	}
	if a.AccessMode != "public" && a.AccessMode != "private" {
		return fmt.Errorf("%w: unsupported access mode %q", ErrAttachmentBinding, a.AccessMode)
	}
	if a.IdempotencyKey != a.OperationID || !validAttachmentID(a.IdempotencyKey) || len(a.RequestID) < 3 || len(a.RequestID) > 128 || len(a.CorrelationID) < 3 || len(a.CorrelationID) > 128 || hasAttachmentControl(a.RequestID) || hasAttachmentControl(a.CorrelationID) {
		return fmt.Errorf("%w: invalid trace fields", ErrAttachmentBinding)
	}
	if len(a.RequestHash) != sha256.Size*2 {
		return fmt.Errorf("%w: invalid request hash", ErrAttachmentBinding)
	}
	if _, err := hex.DecodeString(a.RequestHash); err != nil {
		return fmt.Errorf("%w: invalid request hash encoding", ErrAttachmentBinding)
	}
	if err := validateAttachmentEndpoint(a.Endpoint, false); err != nil {
		return err
	}
	if err := validateAttachmentTarget(a.Target); err != nil {
		return err
	}
	if !validAttachmentContentHash(a.ConfigContentHash) {
		return fmt.Errorf("%w: invalid config content hash", ErrAttachmentBinding)
	}
	if len(a.EdgeEndpoints) == 0 || len(a.EdgeEndpoints) > 8 {
		return fmt.Errorf("%w: invalid edge endpoint count", ErrAttachmentBinding)
	}
	for _, endpoint := range a.EdgeEndpoints {
		if err := validateAttachmentEndpoint(endpoint, true); err != nil {
			return err
		}
	}
	if a.AttachmentGeneration == 0 || a.IssuedAt.IsZero() || a.ExpiresAt.IsZero() || !a.ExpiresAt.After(a.IssuedAt) {
		return fmt.Errorf("%w: invalid attachment lifetime", ErrAttachmentBinding)
	}
	if !now.IsZero() && !a.ExpiresAt.After(now.UTC()) && a.State != "released" && a.State != "failed" {
		return fmt.Errorf("%w: attachment expired", ErrAttachmentBinding)
	}
	switch a.State {
	case "pending", "admitted":
		if a.EdgeReady || a.OriginReady || a.ReadyAt != nil || a.ReleasedAt != nil {
			return fmt.Errorf("%w: origin cannot be ready before edge", ErrAttachmentBinding)
		}
	case "edge_ready":
		if !a.EdgeReady || a.OriginReady || a.ReadyAt != nil || a.ReleasedAt != nil {
			return fmt.Errorf("%w: invalid edge-ready state", ErrAttachmentBinding)
		}
	case "ready":
		if !a.EdgeReady || !a.OriginReady || a.ReadyAt == nil || a.ReleasedAt != nil {
			return fmt.Errorf("%w: ready requires edge and origin", ErrAttachmentBinding)
		}
	case "failed":
		if a.ReadyAt != nil || a.ReleasedAt != nil {
			return fmt.Errorf("%w: failed attachment cannot be ready or released", ErrAttachmentBinding)
		}
	case "released":
		if a.ReadyAt != nil || a.ReleasedAt == nil || a.EdgeReady || a.OriginReady {
			return fmt.Errorf("%w: released attachment must be terminal and not ready", ErrAttachmentBinding)
		}
	default:
		return fmt.Errorf("%w: unknown attachment state", ErrAttachmentBinding)
	}
	return nil
}

func (a Attachment) Admission() (CarrierAdmission, error) {
	if err := a.Validate(time.Time{}); err != nil {
		return CarrierAdmission{}, err
	}
	if a.State != "admitted" && a.State != "edge_ready" && a.State != "ready" {
		return CarrierAdmission{}, fmt.Errorf("%w: attachment is not edge-admitted", ErrAttachmentBinding)
	}
	admission := CarrierAdmission{
		Schema: PreviewTunnelSchemaV1, Kind: PreviewCarrierAttachmentKind, Binding: a.Binding,
		AccessMode:           a.AccessMode,
		AttachmentGeneration: a.AttachmentGeneration, ConfigContentHash: a.ConfigContentHash,
		EdgeEndpoints: append([]string(nil), a.EdgeEndpoints...), Endpoint: a.Endpoint, ExpiresAt: a.ExpiresAt,
	}
	if err := admission.Validate(time.Time{}); err != nil {
		return CarrierAdmission{}, err
	}
	return admission, nil
}

func (a CarrierAdmission) Validate(now time.Time) error {
	if a.Schema != PreviewTunnelSchemaV1 || a.Kind != PreviewCarrierAttachmentKind {
		return fmt.Errorf("%w: invalid admission schema or kind", ErrAttachmentBinding)
	}
	if err := a.Binding.Validate(); err != nil {
		return err
	}
	if a.AttachmentGeneration == 0 || !validAttachmentContentHash(a.ConfigContentHash) || a.ExpiresAt.IsZero() || !now.IsZero() && !a.ExpiresAt.After(now.UTC()) {
		return fmt.Errorf("%w: invalid admission lifetime or content hash", ErrAttachmentBinding)
	}
	if err := validateAttachmentEndpoint(a.Endpoint, false); err != nil {
		return err
	}
	if len(a.EdgeEndpoints) == 0 || len(a.EdgeEndpoints) > 8 {
		return fmt.Errorf("%w: invalid admission edge endpoints", ErrAttachmentBinding)
	}
	for _, endpoint := range a.EdgeEndpoints {
		if err := validateAttachmentEndpoint(endpoint, true); err != nil {
			return err
		}
	}
	return nil
}

// AttachmentHTTPError intentionally exposes only status and retryability.
// Response bodies are bounded and never included in Error, preventing server
// error text from becoming a secret exfiltration channel.
type AttachmentHTTPError struct {
	StatusCode int
	Retryable  bool
}

func (e *AttachmentHTTPError) Error() string {
	if e == nil {
		return ErrAttachmentClientRejected.Error()
	}
	return fmt.Sprintf("%s: status %d", ErrAttachmentClientRejected, e.StatusCode)
}

// AttachmentClient is the authenticated host-side HTTP boundary for the
// server previewattachment contract. It does not store or return bearer or
// private material; TokenSource and ProofSource retain ownership of those.
type AttachmentClient struct {
	base             *url.URL
	tokens           TokenSource
	identities       TokenSource
	proofs           ProofSource
	client           *http.Client
	maxResponseBytes int64
	admissionPoll    time.Duration
}

type AttachmentClientConfig struct {
	ControlURL   string
	AllowedHosts []string
	// Tokens supplies the renewable bearer credential. When omitted, the
	// identity source is reused for deployments where the machine credential
	// intentionally authenticates both headers.
	Tokens                TokenSource
	Identities            TokenSource
	Proofs                ProofSource
	Transport             http.RoundTripper
	Timeout               time.Duration
	MaxResponseBytes      int64
	AdmissionPollInterval time.Duration
}

func NewAttachmentClient(config AttachmentClientConfig) (*AttachmentClient, error) {
	if config.Timeout == 0 {
		config.Timeout = 15 * time.Second
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = attachmentResponseMaxBytes
	}
	if config.AdmissionPollInterval == 0 {
		config.AdmissionPollInterval = attachmentAdmissionPoll
	}
	base, err := url.Parse(strings.TrimSpace(config.ControlURL))
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Path != "" && base.Path != "/" || config.Identities == nil || config.Proofs == nil || config.Timeout <= 0 || config.Timeout > 30*time.Second || config.MaxResponseBytes < 1 || config.MaxResponseBytes > attachmentResponseMaxBytes || config.AdmissionPollInterval <= 0 || config.AdmissionPollInterval > 5*time.Second {
		return nil, ErrAttachmentClientInvalid
	}
	allowed := false
	for _, host := range config.AllowedHosts {
		if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(host), "."), strings.TrimSuffix(base.Hostname(), ".")) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, ErrAttachmentClientInvalid
	}
	transport := config.Transport
	if transport == nil {
		transport = httptransport.Default()
	}
	base.Path, base.RawPath = "", ""
	return &AttachmentClient{base: base, tokens: config.Tokens, identities: config.Identities, proofs: config.Proofs, maxResponseBytes: config.MaxResponseBytes, admissionPoll: config.AdmissionPollInterval, client: &http.Client{Transport: transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrAttachmentClientInvalid }}}, nil
}

// Allocate posts one exact operation. Replaying the same request is safe at
// the server idempotency boundary; changing any binding field is rejected
// before a proof or HTTP request is sent.
func (c *AttachmentClient) Allocate(ctx context.Context, request AttachmentRequest) (Attachment, error) {
	if c == nil || c.base == nil || ctx == nil {
		return Attachment{}, ErrAttachmentClientInvalid
	}
	if err := request.Validate(); err != nil {
		return Attachment{}, err
	}
	if strings.TrimSpace(request.LeaseETag) == "" {
		return Attachment{}, api.ErrPreviewLeaseETagRequired
	}
	if err := api.ValidatePreviewLeaseETag(request.PreviewID, request.LeaseETag); err != nil {
		return Attachment{}, fmt.Errorf("%w: lease ETag: %v", ErrAttachmentBinding, err)
	}
	path := "/v1/previews/" + url.PathEscape(request.PreviewID) + "/carrier-attachment"
	body, err := json.Marshal(request)
	if err != nil || len(body) == 0 || len(body) > attachmentRequestMaxBytes {
		return Attachment{}, fmt.Errorf("%w: request body is invalid", ErrAttachmentClientInvalid)
	}
	tokenSource := c.tokens
	if tokenSource == nil {
		tokenSource = c.identities
	}
	token, err := tokenSource.Token(ctx)
	if err != nil || token == "" || len(token) > attachmentIdentityMaxBytes || hasAttachmentControl(token) {
		return Attachment{}, errors.Join(ErrAttachmentClientUnavailable, err)
	}
	identity, err := c.identities.Token(ctx)
	if err != nil || identity == "" || len(identity) > attachmentIdentityMaxBytes || hasAttachmentControl(identity) {
		return Attachment{}, errors.Join(ErrAttachmentClientUnavailable, err)
	}
	proof, err := c.proofs.Proof(ctx, request.OperationID, http.MethodPost, path, body)
	if err != nil || len(proof) == 0 || len(proof) > attachmentProofMaxBytes {
		return Attachment{}, errors.Join(ErrAttachmentClientUnavailable, err)
	}
	endpoint := *c.base
	endpoint.Path, endpoint.RawPath = path, ""
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return Attachment{}, errors.Join(ErrAttachmentClientInvalid, err)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	httpRequest.Header.Set("X-Paperboat-Machine-Identity", identity)
	httpRequest.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Idempotency-Key", request.IdempotencyKey)
	httpRequest.Header.Set("If-Match", request.LeaseETag)
	httpRequest.Header.Set("Request-Id", request.RequestID)
	httpRequest.Header.Set("Correlation-Id", request.CorrelationID)
	response, err := c.client.Do(httpRequest)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Attachment{}, err
		}
		return Attachment{}, errors.Join(ErrAttachmentClientUnavailable, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return Attachment{}, errors.Join(ErrAttachmentClientUnavailable, err)
	}
	if int64(len(data)) > c.maxResponseBytes {
		return Attachment{}, fmt.Errorf("%w: response exceeds %d bytes", ErrAttachmentClientInvalid, c.maxResponseBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.StatusCode == http.StatusPreconditionFailed || response.StatusCode == http.StatusPreconditionRequired {
			return Attachment{}, errors.Join(ErrAttachmentLeaseETagStale, &AttachmentHTTPError{StatusCode: response.StatusCode})
		}
		retryable := response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500
		return Attachment{}, &AttachmentHTTPError{StatusCode: response.StatusCode, Retryable: retryable}
	}
	attachment, err := decodeAttachmentEnvelope(data, time.Now().UTC())
	if err != nil {
		return Attachment{}, err
	}
	if err := validateAttachmentForRequest(attachment, request); err != nil {
		return Attachment{}, err
	}
	return attachment, nil
}

// WaitForAdmission replays the same idempotent allocation until the server
// accepts the edge publication. It returns for admitted, edge_ready, or ready
// and never marks any state locally. A context deadline is the caller's bound
// for an edge that has not accepted the admission yet.
func (c *AttachmentClient) WaitForAdmission(ctx context.Context, request AttachmentRequest, initial Attachment) (Attachment, error) {
	if c == nil || ctx == nil {
		return Attachment{}, ErrAttachmentClientInvalid
	}
	if err := request.Validate(); err != nil {
		return Attachment{}, err
	}
	if strings.TrimSpace(request.LeaseETag) == "" {
		return Attachment{}, api.ErrPreviewLeaseETagRequired
	}
	if err := validateAttachmentForRequest(initial, request); err != nil {
		return Attachment{}, err
	}
	current := initial
	for {
		if current.State == "admitted" || (current.State == "edge_ready" || current.State == "ready") && current.EdgeReady {
			return current, nil
		}
		if current.State != "pending" {
			return Attachment{}, fmt.Errorf("%w: attachment cannot become admitted from %s", ErrAttachmentBinding, current.State)
		}
		timer := time.NewTimer(c.admissionPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Attachment{}, ctx.Err()
		case <-timer.C:
		}
		next, err := c.Allocate(ctx, request)
		if err != nil {
			return Attachment{}, err
		}
		current = next
	}
}

// WaitForEdgeReady replays the same idempotent allocation after the host has
// connected the admitted carrier. The server's edge observation is the only
// source of edge readiness; this method never promotes an admitted response
// locally.
func (c *AttachmentClient) WaitForEdgeReady(ctx context.Context, request AttachmentRequest, initial Attachment) (Attachment, error) {
	if c == nil || ctx == nil {
		return Attachment{}, ErrAttachmentClientInvalid
	}
	if err := request.Validate(); err != nil {
		return Attachment{}, err
	}
	if strings.TrimSpace(request.LeaseETag) == "" {
		return Attachment{}, api.ErrPreviewLeaseETagRequired
	}
	if err := validateAttachmentForRequest(initial, request); err != nil {
		return Attachment{}, err
	}
	current := initial
	for {
		if (current.State == "edge_ready" || current.State == "ready") && current.EdgeReady {
			return current, nil
		}
		if current.State != "pending" && current.State != "admitted" {
			return Attachment{}, fmt.Errorf("%w: attachment cannot become edge-ready from %s", ErrAttachmentBinding, current.State)
		}
		timer := time.NewTimer(c.admissionPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Attachment{}, ctx.Err()
		case <-timer.C:
		}
		next, err := c.Allocate(ctx, request)
		if err != nil {
			return Attachment{}, err
		}
		current = next
	}
}

// ObserveOrigin records the result of the local origin probe through the
// machine-proof readiness endpoint. The response remains attachment state;
// the caller must separately invoke the preview lease readiness callback.
func (c *AttachmentClient) ObserveOrigin(ctx context.Context, request AttachmentRequest, attachment Attachment, originReady bool) (Attachment, error) {
	if c == nil || c.base == nil || ctx == nil {
		return Attachment{}, ErrAttachmentClientInvalid
	}
	if err := request.Validate(); err != nil {
		return Attachment{}, err
	}
	if strings.TrimSpace(request.LeaseETag) == "" {
		return Attachment{}, api.ErrPreviewLeaseETagRequired
	}
	if err := validateAttachmentForRequest(attachment, request); err != nil {
		return Attachment{}, err
	}
	if _, err := attachment.Admission(); err != nil {
		return Attachment{}, err
	}
	type mutation struct {
		Request              AttachmentRequest `json:"request"`
		Binding              Binding           `json:"binding"`
		AttachmentGeneration uint64            `json:"attachment_generation"`
		OriginReady          bool              `json:"origin_ready"`
	}
	body, err := json.Marshal(mutation{Request: request, Binding: attachment.Binding, AttachmentGeneration: attachment.AttachmentGeneration, OriginReady: originReady})
	if err != nil || len(body) == 0 || len(body) > attachmentRequestMaxBytes {
		return Attachment{}, fmt.Errorf("%w: readiness body is invalid", ErrAttachmentClientInvalid)
	}
	path := "/v1/previews/" + url.PathEscape(request.PreviewID) + "/carrier-attachment/readiness"
	tokenSource := c.tokens
	if tokenSource == nil {
		tokenSource = c.identities
	}
	token, err := tokenSource.Token(ctx)
	if err != nil || token == "" || len(token) > attachmentIdentityMaxBytes || hasAttachmentControl(token) {
		return Attachment{}, errors.Join(ErrAttachmentClientUnavailable, err)
	}
	identity, err := c.identities.Token(ctx)
	if err != nil || identity == "" || len(identity) > attachmentIdentityMaxBytes || hasAttachmentControl(identity) {
		return Attachment{}, errors.Join(ErrAttachmentClientUnavailable, err)
	}
	proof, err := c.proofs.Proof(ctx, request.OperationID, http.MethodPost, path, body)
	if err != nil || len(proof) == 0 || len(proof) > attachmentProofMaxBytes {
		return Attachment{}, errors.Join(ErrAttachmentClientUnavailable, err)
	}
	endpoint := *c.base
	endpoint.Path, endpoint.RawPath = path, ""
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return Attachment{}, errors.Join(ErrAttachmentClientInvalid, err)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	httpRequest.Header.Set("X-Paperboat-Machine-Identity", identity)
	httpRequest.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Idempotency-Key", request.IdempotencyKey)
	httpRequest.Header.Set("If-Match", request.LeaseETag)
	httpRequest.Header.Set("Request-Id", request.RequestID)
	httpRequest.Header.Set("Correlation-Id", request.CorrelationID)
	response, err := c.client.Do(httpRequest)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Attachment{}, err
		}
		return Attachment{}, errors.Join(ErrAttachmentClientUnavailable, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return Attachment{}, errors.Join(ErrAttachmentClientUnavailable, err)
	}
	if int64(len(data)) > c.maxResponseBytes {
		return Attachment{}, fmt.Errorf("%w: response exceeds %d bytes", ErrAttachmentClientInvalid, c.maxResponseBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.StatusCode == http.StatusPreconditionFailed || response.StatusCode == http.StatusPreconditionRequired {
			return Attachment{}, errors.Join(ErrAttachmentLeaseETagStale, &AttachmentHTTPError{StatusCode: response.StatusCode})
		}
		retryable := response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500
		return Attachment{}, &AttachmentHTTPError{StatusCode: response.StatusCode, Retryable: retryable}
	}
	next, err := decodeAttachmentEnvelope(data, time.Now().UTC())
	if err != nil {
		return Attachment{}, err
	}
	if err := validateAttachmentForRequest(next, request); err != nil {
		return Attachment{}, err
	}
	if next.Binding != attachment.Binding {
		return Attachment{}, fmt.Errorf("%w: readiness response binding changed", ErrAttachmentBinding)
	}
	// A failed origin probe is a durable, idempotent observation. The server
	// may already have recorded the same false result while this carrier was
	// reconnecting, so an unchanged edge_ready generation is a valid replay.
	// Successful readiness must still advance the generation before it can be
	// accepted by the host.
	if !originReady && next.AttachmentGeneration == attachment.AttachmentGeneration && next.State == "edge_ready" && next.EdgeReady && !next.OriginReady {
		return next, nil
	}
	if next.AttachmentGeneration <= attachment.AttachmentGeneration {
		return Attachment{}, fmt.Errorf("%w: readiness response did not advance the current attachment", ErrAttachmentBinding)
	}
	return next, nil
}

func decodeAttachmentEnvelope(data []byte, now time.Time) (Attachment, error) {
	if len(data) == 0 || len(data) > attachmentResponseMaxBytes {
		return Attachment{}, ErrAttachmentClientInvalid
	}
	if err := rejectAttachmentDuplicateFields(data); err != nil {
		return Attachment{}, fmt.Errorf("%w: response JSON: %v", ErrAttachmentClientInvalid, err)
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || len(envelope.Data) == 0 {
		return Attachment{}, fmt.Errorf("%w: invalid response envelope", ErrAttachmentClientInvalid)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Attachment{}, fmt.Errorf("%w: response has trailing data", ErrAttachmentClientInvalid)
	}
	if err := rejectAttachmentDuplicateFields(envelope.Data); err != nil {
		return Attachment{}, fmt.Errorf("%w: attachment JSON: %v", ErrAttachmentClientInvalid, err)
	}
	var attachment Attachment
	attachmentDecoder := json.NewDecoder(bytes.NewReader(envelope.Data))
	attachmentDecoder.DisallowUnknownFields()
	if err := attachmentDecoder.Decode(&attachment); err != nil {
		return Attachment{}, fmt.Errorf("%w: invalid attachment", ErrAttachmentClientInvalid)
	}
	if err := attachmentDecoder.Decode(&struct{}{}); err != io.EOF {
		return Attachment{}, fmt.Errorf("%w: attachment has trailing data", ErrAttachmentClientInvalid)
	}
	if err := attachment.Validate(now); err != nil {
		return Attachment{}, err
	}
	return attachment, nil
}

func validateAttachmentForRequest(attachment Attachment, request AttachmentRequest) error {
	if attachment.PreviewID != request.PreviewID || attachment.OperationID != request.OperationID || attachment.OwnerDeviceID != request.OwnerDeviceID || attachment.OwnerSessionID != request.OwnerSessionID || attachment.IdempotencyKey != request.IdempotencyKey || attachment.RequestID != request.RequestID || attachment.CorrelationID != request.CorrelationID {
		return fmt.Errorf("%w: response identity differs from request", ErrAttachmentBinding)
	}
	if attachment.Binding.PreviewID != request.PreviewID || attachment.Binding.OperationID != request.OperationID || attachment.Binding.OwnerDeviceID != request.OwnerDeviceID || attachment.Binding.OwnerSessionID != request.OwnerSessionID || leaseGenerationForID(request.PreviewID, request.LeaseETag) != int64(attachment.Binding.LeaseGeneration) {
		return fmt.Errorf("%w: response binding differs from request", ErrAttachmentBinding)
	}
	want, err := request.Hash(attachment.AccountID)
	if err != nil || attachment.RequestHash != want {
		return fmt.Errorf("%w: response request hash differs from request", ErrAttachmentBinding)
	}
	return nil
}

func validateAttachmentTarget(target LeaseTarget) error {
	if len(target.Scheme) == 0 || len(target.Scheme) > 32 || len(target.Address) == 0 || len(target.Address) > 512 || hasAttachmentControl(target.Scheme) || hasAttachmentControl(target.Address) {
		return fmt.Errorf("%w: invalid attachment target", ErrAttachmentBinding)
	}
	switch strings.ToLower(target.Scheme) {
	case "http", "https", "h2c", "tcp", "unix":
		return nil
	default:
		return fmt.Errorf("%w: unsupported attachment target scheme", ErrAttachmentBinding)
	}
}

func validateAttachmentEndpoint(value string, edge bool) error {
	if len(value) == 0 || len(value) > 2048 || hasAttachmentControl(value) {
		return fmt.Errorf("%w: invalid attachment endpoint", ErrAttachmentBinding)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: endpoint must be an absolute URL without credentials or query", ErrAttachmentBinding)
	}
	if edge {
		switch strings.ToLower(parsed.Scheme) {
		case "tls", "quic":
		default:
			return fmt.Errorf("%w: unsupported edge endpoint scheme", ErrAttachmentBinding)
		}
	} else if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("%w: endpoint must use https", ErrAttachmentBinding)
	}
	return nil
}

func validAttachmentContentHash(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

// validMachineIdentityPublicKey and machineIdentityThumbprint mirror the
// previewattachment server contract. The binding uses the raw Ed25519 public
// key hash (rather than the local identity store's RFC 7638 key thumbprint)
// because the edge uses the same bytes to bind the mTLS peer.
func validMachineIdentityPublicKey(value string) bool {
	if value == "" {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == ed25519.PublicKeySize && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validMachineIdentityThumbprint(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*4/3+1 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == strings.TrimPrefix(value, prefix)
}

func machineIdentityThumbprint(publicKey string) string {
	decoded, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return ""
	}
	digest := sha256.Sum256(decoded)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func validAttachmentID(value string) bool {
	if len(value) < 3 || len(value) > 256 {
		return false
	}
	for _, char := range value {
		if char < 0x21 || char > 0x7e || strings.ContainsRune("/?#\\", char) {
			return false
		}
	}
	return true
}

func hasAttachmentControl(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}
	return false
}

func rejectAttachmentDuplicateFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrAttachmentClientInvalid
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate field")
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrAttachmentClientInvalid
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrAttachmentClientInvalid
	}
	return nil
}

var _ interface {
	Allocate(context.Context, AttachmentRequest) (Attachment, error)
} = (*AttachmentClient)(nil)
