package tunnelenrollment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connectorrotation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

const (
	carrierBootstrapSchema = "paperboat.connector-bootstrap/v1"
	controlSubprotocol     = "paperboat.connector.v1"
	bootstrapResponseLimit = 320 << 10
)

// ControlIdentity is the safe, server-authoritative identity returned by the
// enrollment exchange plus the registered account binding held by hostd.
type ControlIdentity struct {
	AccountID            string
	ProcessGeneration    uint64
	CredentialGeneration uint64
}

type HTTPSProductionAssemblySourceConfig struct {
	ControlURL    string
	StateRoot     string
	HostID        string
	Transport     http.RoundTripper
	Auth          MachineAuth
	Clock         connectorprotocol.Clock
	Origins       tunnelmanager.OriginProber
	OriginStreams *tunnelmanager.OriginStreamForwarder
	Drainer       connectorprotocol.Drainer
	Renewal       connectorrotation.CredentialRenewalSource
	Report        func(tunnelmanager.Observation)
}

// HTTPSProductionAssemblySource is the production control/bootstrap client.
// Control authentication lives exclusively in signed Hello over WSS. Carrier
// bootstrap uses renewable machine proof and returns only bounded public
// endpoint/certificate material.
type HTTPSProductionAssemblySource struct {
	base          *url.URL
	stateRoot     string
	hostID        string
	http          *http.Client
	auth          MachineAuth
	clock         connectorprotocol.Clock
	origins       tunnelmanager.OriginProber
	originStreams *tunnelmanager.OriginStreamForwarder
	drainer       connectorprotocol.Drainer
	renewal       connectorrotation.CredentialRenewalSource
	report        func(tunnelmanager.Observation)
	mu            sync.Mutex
	drainers      map[string]*assemblyDrainer
	credentials   *FileCredentialStore
	rotations     map[string]*productionRotationRuntime
	lifetime      context.Context
	cancel        context.CancelFunc
	started       bool
	closed        bool
}

func NewHTTPSProductionAssemblySource(config HTTPSProductionAssemblySourceConfig) (*HTTPSProductionAssemblySource, error) {
	base, err := url.Parse(strings.TrimSpace(config.ControlURL))
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || !filepath.IsAbs(config.StateRoot) || filepath.Clean(config.StateRoot) != config.StateRoot || connectorprotocol.ValidateIdentifier(config.HostID) != nil || config.Auth == nil || config.Clock == nil || config.Origins == nil {
		return nil, ErrInvalid
	}
	client := &http.Client{Transport: config.Transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalid }}
	if config.Report == nil {
		config.Report = func(tunnelmanager.Observation) {}
	}
	return &HTTPSProductionAssemblySource{base: base, stateRoot: config.StateRoot, hostID: config.HostID, http: client, auth: config.Auth, clock: config.Clock, origins: config.Origins, originStreams: config.OriginStreams, drainer: config.Drainer, renewal: config.Renewal, report: config.Report, drainers: make(map[string]*assemblyDrainer), rotations: make(map[string]*productionRotationRuntime)}, nil
}

func (s *HTTPSProductionAssemblySource) BindCredentialStore(store *FileCredentialStore) error {
	if s == nil || store == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.credentials != nil && s.credentials != store || s.started {
		return ErrConflict
	}
	s.credentials = store
	return nil
}

func (s *HTTPSProductionAssemblySource) Start(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.credentials == nil {
		return ErrUnavailable
	}
	if s.started {
		return nil
	}
	s.lifetime, s.cancel = context.WithCancel(context.Background())
	s.started = true
	return nil
}

func (s *HTTPSProductionAssemblySource) Shutdown(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	rotations := make([]*productionRotationRuntime, 0, len(s.rotations))
	for _, runtime := range s.rotations {
		rotations = append(rotations, runtime)
	}
	s.mu.Unlock()
	var result error
	for _, runtime := range rotations {
		result = errors.Join(result, runtime.shutdown(ctx))
	}
	return result
}

func (s *HTTPSProductionAssemblySource) ResolveProductionAssembly(ctx context.Context, request ActivationRequest, signer CredentialSigner) (tunnelmanager.ProductionAssemblyConfig, error) {
	return s.resolveProductionAssembly(ctx, request, signer, nil)
}

func (s *HTTPSProductionAssemblySource) resolveProductionAssembly(ctx context.Context, request ActivationRequest, signer CredentialSigner, rotationOverride *productionRotationRuntime) (tunnelmanager.ProductionAssemblyConfig, error) {
	if s == nil || ctx == nil || signer == nil || request.HostID != s.hostID || !validActivationRequest(request) || hoststate.ValidateStableEndpointID(request.StableEndpointID) != nil {
		return tunnelmanager.ProductionAssemblyConfig{}, ErrInvalid
	}
	identity := ControlIdentity{AccountID: request.AccountID, ProcessGeneration: request.ProcessGeneration, CredentialGeneration: request.CredentialGeneration}
	rotation := rotationOverride
	if rotation == nil {
		var err error
		rotation, err = s.rotationFor(request)
		if err != nil {
			return tunnelmanager.ProductionAssemblyConfig{}, err
		}
	}
	drainer := s.drainer
	if drainer == nil {
		drainer = s.drainerFor(request)
	}
	renewalSigner := connectorrotation.RenewalProofSignerFunc(func(signCtx context.Context, payload []byte) ([]byte, error) {
		return signer(signCtx, payload)
	})
	hello, err := s.newHello(ctx, request, identity, signer)
	if err != nil {
		return tunnelmanager.ProductionAssemblyConfig{}, err
	}
	controlStream := func(streamCtx context.Context) (io.ReadWriteCloser, error) {
		return s.openControlStream(streamCtx, request)
	}
	descriptors := func(descriptorCtx context.Context, welcome connectorprotocol.Welcome, apply tunnelmanager.ApplyRequest) (connector.DataCarrierSessionSource, error) {
		return s.carrierSessionSource(descriptorCtx, request, identity, hello, welcome, apply, signer)
	}
	controlFactory := func(factoryCtx context.Context, _ *tunnelmanager.CoordinatedConfigApplier) (connectorrotation.ControlSessionConfig, error) {
		fresh, freshErr := s.newHello(factoryCtx, request, identity, signer)
		if freshErr != nil {
			return connectorrotation.ControlSessionConfig{}, freshErr
		}
		currentRotation := rotation
		if rotationOverride != nil && rotationOverride.isCommitted() {
			currentRotation, freshErr = s.rotationFor(request)
			if freshErr != nil {
				return connectorrotation.ControlSessionConfig{}, freshErr
			}
		}
		return connectorrotation.ControlSessionConfig{Hello: fresh, Drainer: drainer, Rotation: currentRotation.manager, Readiness: currentRotation, AutomaticRotationReadiness: true, RotationRevokeCommitter: currentRotation, Renewal: s.renewal, RenewalSigner: renewalSignerIfNeeded(s.renewal, renewalSigner), Clock: s.clock}, nil
	}
	return tunnelmanager.ProductionAssemblyConfig{
		Production: tunnelmanager.ProductionConfig{
			StateRoot: filepath.Join(s.stateRoot, "tunnel-connectors", request.ConnectorID, "process-"+strconv.FormatUint(request.ProcessGeneration, 10)), HostID: request.HostID,
			Report: s.report,
		},
		StableEndpointID: request.StableEndpointID,
		Clock:            s.clock, Origins: s.origins, OriginStreams: s.originStreams,
		CarrierDescriptorSource: descriptors,
		InitialConnector: &hoststate.Connector{
			ID: request.ConnectorID, TunnelID: request.TunnelID, HostID: request.HostID,
			Credential:         hoststate.CredentialReference{Reference: request.CredentialReference, Generation: identity.CredentialGeneration},
			RotationGeneration: identity.CredentialGeneration,
		},
		Control:               connectorrotation.ControlSessionConfig{Hello: hello, Drainer: drainer, Rotation: rotation.manager, Readiness: rotation, AutomaticRotationReadiness: true, RotationRevokeCommitter: rotation, Renewal: s.renewal, RenewalSigner: renewalSignerIfNeeded(s.renewal, renewalSigner), Clock: s.clock},
		ControlSessionFactory: controlFactory,
		ControlStream:         controlStream,
		HelloRequestID:        request.OperationID,
	}, nil
}

func (s *HTTPSProductionAssemblySource) bindReplacementProductionAssembly(request ActivationRequest, assembly *tunnelmanager.ProductionAssembly, rotation *productionRotationRuntime) error {
	if s == nil || assembly == nil || rotation == nil || !validActivationRequest(request) {
		return ErrActivation
	}
	if s.drainer == nil {
		if err := s.drainerFor(request).bind(assembly); err != nil {
			return err
		}
	}
	return nil
}

func renewalSignerIfNeeded(source connectorrotation.CredentialRenewalSource, signer connectorrotation.RenewalProofSigner) connectorrotation.RenewalProofSigner {
	if source != nil {
		return nil
	}
	return signer
}

func activationBindingKey(request ActivationRequest) string {
	return request.AccountID + "\x00" + request.TunnelID + "\x00" + request.ConnectorID + "\x00" + request.StableEndpointID + "\x00" + strconv.FormatUint(request.ProcessGeneration, 10) + "\x00" + strconv.FormatUint(request.CredentialGeneration, 10)
}

func (s *HTTPSProductionAssemblySource) drainerFor(request ActivationRequest) *assemblyDrainer {
	key := activationBindingKey(request)
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.drainers[key]; current != nil {
		return current
	}
	created := newAssemblyDrainer(request.TunnelID, request.ConnectorID)
	s.drainers[key] = created
	return created
}

func (s *HTTPSProductionAssemblySource) BindProductionAssembly(request ActivationRequest, assembly *tunnelmanager.ProductionAssembly) error {
	if s == nil || assembly == nil || !validActivationRequest(request) {
		return ErrActivation
	}
	if s.drainer == nil {
		if err := s.drainerFor(request).bind(assembly); err != nil {
			return err
		}
	}
	rotation, err := s.rotationFor(request)
	if err != nil {
		return err
	}
	return rotation.bind(assembly)
}

func (s *HTTPSProductionAssemblySource) newHello(ctx context.Context, request ActivationRequest, identity ControlIdentity, signer CredentialSigner) (connectorprotocol.Hello, error) {
	now := s.clock.Now().UTC()
	nonce, err := randomID("control-auth")
	if err != nil {
		return connectorprotocol.Hello{}, err
	}
	auth := connectorprotocol.AuthRequest{
		AccountID: identity.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID, HostID: request.HostID,
		IdentityKeyID: request.CredentialKeyID, IdentityKeyThumbprint: request.CredentialThumbprint,
		ProcessGeneration: identity.ProcessGeneration, CredentialGeneration: identity.CredentialGeneration,
		Nonce: nonce, IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	var signErr error
	auth, err = connectorprotocol.SignAuthProof(auth, func(payload []byte) []byte {
		var signature []byte
		signature, signErr = signer(ctx, payload)
		return signature
	})
	if err != nil || signErr != nil {
		return connectorprotocol.Hello{}, errors.Join(ErrActivation, err, signErr)
	}
	hello := connectorprotocol.Hello{
		Protocol: connectorprotocol.ProtocolName, MinVersion: connectorprotocol.ProtocolVersion, MaxVersion: connectorprotocol.ProtocolVersion,
		AccountID: identity.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID, HostID: request.HostID,
		ProcessGeneration: identity.ProcessGeneration,
		Capabilities:      connectorprotocol.ProductionCapabilities(),
		Auth:              auth,
	}
	if err := hello.Validate(now); err != nil {
		return connectorprotocol.Hello{}, errors.Join(ErrActivation, err)
	}
	return hello, nil
}

func (s *HTTPSProductionAssemblySource) openControlStream(ctx context.Context, request ActivationRequest) (io.ReadWriteCloser, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	endpoint := *s.base
	endpoint.Scheme = "wss"
	endpoint.Path = strings.TrimRight(s.base.Path, "/") + "/v1/tunnels/" + url.PathEscape(request.TunnelID) + "/connectors/" + url.PathEscape(request.ConnectorID) + "/control"
	endpoint.RawPath = ""
	websocketClient := *s.http
	// The stream lifetime is owned by stable hostd's context. An ordinary HTTP
	// response timeout would tear down a healthy long-lived control session.
	websocketClient.Timeout = 0
	connection, response, err := websocket.Dial(ctx, endpoint.String(), &websocket.DialOptions{HTTPClient: &websocketClient, Subprotocols: []string{controlSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.Join(ErrUnavailable, err)
	}
	if connection.Subprotocol() != controlSubprotocol {
		_ = connection.Close(websocket.StatusPolicyViolation, "connector subprotocol required")
		return nil, ErrUnavailable
	}
	connection.SetReadLimit(connectorprotocol.MaxFrameBytes + 4)
	return websocket.NetConn(ctx, connection, websocket.MessageBinary), nil
}

type carrierBootstrapRequest struct {
	Schema            string `json:"schema"`
	Kind              string `json:"kind"`
	SessionID         string `json:"session_id"`
	ProcessGeneration uint64 `json:"process_generation"`
	ConfigGeneration  uint64 `json:"config_generation"`
	ConfigContentHash string `json:"config_content_hash"`
}

type carrierBootstrapNode struct {
	EdgeNodeID                string   `json:"edge_node_id"`
	EdgeProcessEpoch          string   `json:"edge_process_epoch"`
	FailureDomain             string   `json:"failure_domain"`
	Endpoints                 []string `json:"endpoints"`
	ServerSPKISHA256          string   `json:"server_spki_sha256"`
	ServerCertificateChainPEM string   `json:"server_certificate_chain_pem"`
}

type carrierBootstrapDescriptor struct {
	Schema               string                 `json:"schema"`
	Kind                 string                 `json:"kind"`
	AccountID            string                 `json:"account_id"`
	TunnelID             string                 `json:"tunnel_id"`
	ConnectorID          string                 `json:"connector_id"`
	HostID               string                 `json:"host_id"`
	StableEndpointID     string                 `json:"stable_endpoint_id"`
	SessionID            string                 `json:"session_id"`
	ProcessGeneration    uint64                 `json:"process_generation"`
	CredentialGeneration uint64                 `json:"credential_generation"`
	ConfigGeneration     uint64                 `json:"config_generation"`
	ConfigContentHash    string                 `json:"config_content_hash"`
	Carriers             []carrierBootstrapNode `json:"carriers"`
	IssuedAt             time.Time              `json:"issued_at"`
	ExpiresAt            time.Time              `json:"expires_at"`
}

func (s *HTTPSProductionAssemblySource) carrierSessionSource(ctx context.Context, request ActivationRequest, controlIdentity ControlIdentity, hello connectorprotocol.Hello, welcome connectorprotocol.Welcome, apply tunnelmanager.ApplyRequest, signer CredentialSigner) (connector.DataCarrierSessionSource, error) {
	bootstrapRequest := carrierBootstrapRequest{Schema: carrierBootstrapSchema, Kind: "carrier_bootstrap_request", SessionID: welcome.SessionID, ProcessGeneration: hello.ProcessGeneration, ConfigGeneration: apply.Snapshot.Generation, ConfigContentHash: apply.Snapshot.ContentHash}
	body, err := json.Marshal(bootstrapRequest)
	if err != nil {
		return connector.DataCarrierSessionSource{}, ErrActivation
	}
	descriptor, err := s.fetchCarrierDescriptor(ctx, request, body)
	if err != nil {
		return connector.DataCarrierSessionSource{}, err
	}
	if err := validateCarrierDescriptor(descriptor, s.clock.Now().UTC(), request, controlIdentity, welcome, apply); err != nil {
		return connector.DataCarrierSessionSource{}, err
	}
	identity := connector.DataCarrierIdentity{AccountID: descriptor.AccountID, HostID: descriptor.HostID, TunnelID: descriptor.TunnelID, ConnectorID: descriptor.ConnectorID, SessionID: descriptor.SessionID, SessionGeneration: descriptor.CredentialGeneration, ProcessGeneration: descriptor.ProcessGeneration, Generation: descriptor.ConfigGeneration}
	endpoints := make(map[string]connector.NetworkDialerConfig, len(descriptor.Carriers))
	failureDomains := make([]string, 0, len(descriptor.Carriers))
	for _, node := range descriptor.Carriers {
		configs, err := carrierNodeEndpoints(ctx, descriptor, node, request, signer, identity, s.clock.Now().UTC())
		if err != nil {
			return connector.DataCarrierSessionSource{}, err
		}
		endpoints[node.FailureDomain] = configs
		failureDomains = append(failureDomains, node.FailureDomain)
	}
	pool := connector.DefaultDataCarrierPoolConfig()
	pool.MaximumCarriers = len(failureDomains)
	pool.EdgeID = descriptor.Carriers[0].EdgeNodeID
	pool.FailureDomains = failureDomains
	pool.Preferred = connector.QUIC
	pool.Fallback = connector.TCPMux
	pool.SingleTransport = false
	pool.Session = connector.DataCarrierIdentity{}
	dialer := connector.DataCarrierDialer(func(dialCtx context.Context, dialRequest connector.DataCarrierDialRequest) (connector.DataCarrierDialResult, error) {
		configured, ok := endpoints[dialRequest.FailureDomain]
		if !ok {
			return connector.DataCarrierDialResult{}, connector.ErrInvalidDataCarrierEndpoint
		}
		return connector.NewNetworkDialer(configured)(dialCtx, dialRequest)
	})
	return connector.NewDataCarrierSessionSource(identity, pool, dialer)
}

func (s *HTTPSProductionAssemblySource) fetchCarrierDescriptor(ctx context.Context, request ActivationRequest, body []byte) (carrierBootstrapDescriptor, error) {
	operationID, err := randomID("carrier-bootstrap")
	if err != nil {
		return carrierBootstrapDescriptor{}, err
	}
	token, err := s.auth.Token(ctx)
	if err != nil || strings.TrimSpace(token) == "" {
		return carrierBootstrapDescriptor{}, ErrAuthentication
	}
	path := "/v1/tunnels/" + url.PathEscape(request.TunnelID) + "/connectors/" + url.PathEscape(request.ConnectorID) + "/carrier-bootstrap"
	endpoint := *s.base
	endpoint.Path = strings.TrimRight(s.base.Path, "/") + path
	endpoint.RawPath = ""
	proof, err := s.auth.Proof(ctx, operationID, http.MethodPost, endpoint.Path, body)
	if err != nil || len(proof) == 0 {
		return carrierBootstrapDescriptor{}, ErrAuthentication
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return carrierBootstrapDescriptor{}, err
	}
	httpRequest.Header.Set("X-Paperboat-Machine-Identity", token)
	httpRequest.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	httpRequest.Header.Set("Idempotency-Key", operationID)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := s.http.Do(httpRequest)
	if err != nil {
		if ctx.Err() != nil {
			return carrierBootstrapDescriptor{}, ctx.Err()
		}
		return carrierBootstrapDescriptor{}, errors.Join(ErrUnavailable, err)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, bootstrapResponseLimit+1))
	if readErr != nil || len(raw) == 0 || len(raw) > bootstrapResponseLimit {
		return carrierBootstrapDescriptor{}, ErrUnavailable
	}
	if response.StatusCode != http.StatusOK {
		switch response.StatusCode {
		case http.StatusUnauthorized:
			return carrierBootstrapDescriptor{}, ErrAuthentication
		case http.StatusForbidden:
			return carrierBootstrapDescriptor{}, ErrForbidden
		case http.StatusConflict:
			return carrierBootstrapDescriptor{}, ErrConflict
		default:
			return carrierBootstrapDescriptor{}, ErrUnavailable
		}
	}
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" || rejectDuplicateJSON(raw) != nil {
		return carrierBootstrapDescriptor{}, ErrUnavailable
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(envelope.Data) == 0 {
		return carrierBootstrapDescriptor{}, ErrUnavailable
	}
	var descriptor carrierBootstrapDescriptor
	decoder = json.NewDecoder(bytes.NewReader(envelope.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&descriptor) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return carrierBootstrapDescriptor{}, ErrUnavailable
	}
	return descriptor, nil
}

func validateCarrierDescriptor(descriptor carrierBootstrapDescriptor, now time.Time, request ActivationRequest, identity ControlIdentity, welcome connectorprotocol.Welcome, apply tunnelmanager.ApplyRequest) error {
	if descriptor.Schema != carrierBootstrapSchema || descriptor.Kind != "carrier_bootstrap_descriptor" || descriptor.AccountID != identity.AccountID || descriptor.TunnelID != request.TunnelID || descriptor.ConnectorID != request.ConnectorID || descriptor.HostID != request.HostID || descriptor.StableEndpointID != request.StableEndpointID || hoststate.ValidateStableEndpointID(descriptor.StableEndpointID) != nil || descriptor.SessionID != welcome.SessionID || descriptor.ProcessGeneration != identity.ProcessGeneration || descriptor.CredentialGeneration != identity.CredentialGeneration || descriptor.ConfigGeneration != apply.Snapshot.Generation || descriptor.ConfigContentHash != apply.Snapshot.ContentHash || len(descriptor.Carriers) == 0 || len(descriptor.Carriers) > 4 || descriptor.IssuedAt.IsZero() || descriptor.ExpiresAt.IsZero() || !descriptor.ExpiresAt.After(descriptor.IssuedAt) || descriptor.ExpiresAt.Sub(descriptor.IssuedAt) > 2*time.Minute || descriptor.IssuedAt.After(now.Add(connectorprotocol.MaxClockSkew)) || !descriptor.ExpiresAt.After(now) {
		return ErrConflict
	}
	seenNodes, seenDomains := map[string]bool{}, map[string]bool{}
	for _, node := range descriptor.Carriers {
		if connectorprotocol.ValidateIdentifier(node.EdgeNodeID) != nil || connectorprotocol.ValidateOpaqueEpoch(node.EdgeProcessEpoch) != nil || connectorprotocol.ValidateIdentifier(node.FailureDomain) != nil || len(node.Endpoints) != 2 || seenNodes[node.EdgeNodeID+"\x00"+node.EdgeProcessEpoch] || seenDomains[node.FailureDomain] {
			return ErrConflict
		}
		seenNodes[node.EdgeNodeID+"\x00"+node.EdgeProcessEpoch] = true
		seenDomains[node.FailureDomain] = true
		if _, _, _, err := parseCarrierNode(node); err != nil {
			return err
		}
	}
	return nil
}

func parseCarrierNode(node carrierBootstrapNode) (map[string]*url.URL, *x509.CertPool, []*x509.Certificate, error) {
	parsedEndpoints := make(map[string]*url.URL, 2)
	for _, raw := range node.Endpoints {
		parsed, err := url.Parse(raw)
		if err != nil || (parsed.Scheme != "tls" && parsed.Scheme != "quic") || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsedEndpoints[parsed.Scheme] != nil {
			return nil, nil, nil, ErrConflict
		}
		parsedEndpoints[parsed.Scheme] = parsed
	}
	if parsedEndpoints["tls"] == nil || parsedEndpoints["quic"] == nil || !strings.HasPrefix(node.ServerSPKISHA256, "sha256:") || len(node.ServerSPKISHA256) != 71 {
		return nil, nil, nil, ErrConflict
	}
	decodedSPKI, err := hex.DecodeString(strings.TrimPrefix(node.ServerSPKISHA256, "sha256:"))
	if err != nil || len(decodedSPKI) != sha256.Size || "sha256:"+hex.EncodeToString(decodedSPKI) != node.ServerSPKISHA256 {
		return nil, nil, nil, ErrConflict
	}
	if len(node.ServerCertificateChainPEM) == 0 || len(node.ServerCertificateChainPEM) > 64<<10 || !strings.HasPrefix(node.ServerCertificateChainPEM, "-----BEGIN CERTIFICATE-----") || strings.ContainsRune(node.ServerCertificateChainPEM, '\x00') {
		return nil, nil, nil, ErrConflict
	}
	pool := x509.NewCertPool()
	var certificates []*x509.Certificate
	rest := []byte(node.ServerCertificateChainPEM)
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, nil, ErrConflict
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, nil, ErrConflict
		}
		pool.AddCert(certificate)
		certificates = append(certificates, certificate)
		rest = next
	}
	if len(certificates) == 0 {
		return nil, nil, nil, ErrConflict
	}
	return parsedEndpoints, pool, certificates, nil
}

func carrierNodeEndpoints(ctx context.Context, descriptor carrierBootstrapDescriptor, node carrierBootstrapNode, request ActivationRequest, signer CredentialSigner, identity connector.DataCarrierIdentity, now time.Time) (connector.NetworkDialerConfig, error) {
	parsed, roots, _, err := parseCarrierNode(node)
	if err != nil {
		return connector.NetworkDialerConfig{}, err
	}
	binding := connectorprotocol.CarrierIdentityBinding{AccountID: identity.AccountID, HostID: identity.HostID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration, ConfigGeneration: identity.Generation, EdgeProcessEpoch: node.EdgeProcessEpoch}
	uri, err := connectorprotocol.CarrierIdentityURN(binding)
	if err != nil {
		return connector.NetworkDialerConfig{}, err
	}
	certificate, err := connectorCredentialTLSCertificate(ctx, request, signer, uri, now, descriptor.ExpiresAt)
	if err != nil {
		return connector.NetworkDialerConfig{}, err
	}
	newEndpoint := func(parsed *url.URL) connector.DataCarrierEndpointConfig {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}, ServerName: parsed.Hostname(),
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
					return connector.ErrDataCarrierTLS
				}
				digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
				if "sha256:"+hex.EncodeToString(digest[:]) != node.ServerSPKISHA256 {
					return connector.ErrDataCarrierTLS
				}
				return nil
			},
		}
		return connector.DataCarrierEndpointConfig{Address: parsed.Host, TLS: tlsConfig, ExpectedIdentity: identity, PeerBinding: func(tls.ConnectionState) (connector.DataCarrierIdentity, error) { return identity, nil }}
	}
	return connector.NetworkDialerConfig{TCPMux: newEndpoint(parsed["tls"]), QUIC: newEndpoint(parsed["quic"])}, nil
}

type referenceCryptoSigner struct {
	ctx    context.Context
	public ed25519.PublicKey
	sign   CredentialSigner
}

func (s referenceCryptoSigner) Public() crypto.PublicKey { return s.public }
func (s referenceCryptoSigner) Sign(_ io.Reader, payload []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.Hash(0) {
		return nil, ErrActivation
	}
	return s.sign(s.ctx, payload)
}

func connectorCredentialTLSCertificate(ctx context.Context, request ActivationRequest, signer CredentialSigner, uri *url.URL, now, expiresAt time.Time) (tls.Certificate, error) {
	if len(request.CredentialPublicKey) != ed25519.PublicKeySize || uri == nil || !expiresAt.After(now) {
		return tls.Certificate{}, ErrActivation
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	private := referenceCryptoSigner{ctx: ctx, public: ed25519.PublicKey(append([]byte(nil), request.CredentialPublicKey...)), sign: signer}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: request.CredentialKeyID},
		NotBefore: now.Add(-30 * time.Second), NotAfter: expiresAt,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, URIs: []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.public, private)
	if err != nil {
		return tls.Certificate{}, errors.Join(ErrActivation, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, ErrActivation
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: leaf}, nil
}

var _ ProductionAssemblySource = (*HTTPSProductionAssemblySource)(nil)
