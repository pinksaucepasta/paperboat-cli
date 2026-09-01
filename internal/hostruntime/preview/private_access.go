package preview

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/machinecontrol"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
	"github.com/pinksaucepasta/paperboat/internal/privatepreviewproxy"
	"golang.org/x/net/idna"
)

const (
	privateAccessGrantPath = "/v1/edge/private-access/grants"
	privateAccessMaxBody   = 64 << 10
	privateAccessGrantTTL  = 2 * time.Minute
)

var ErrPrivateAccessInvalid = errors.New("invalid private preview access configuration")

type privateAccessGrantIssue struct {
	ResourceKind         string    `json:"resource_kind"`
	ResourceID           string    `json:"resource_id"`
	RouteID              string    `json:"route_id"`
	Audience             string    `json:"audience"`
	ExpiresAt            time.Time `json:"expires_at"`
	Nonce                string    `json:"nonce"`
	OperationID          string    `json:"operation_id,omitempty"`
	ConnectorID          string    `json:"connector_id,omitempty"`
	CarrierSessionID     string    `json:"carrier_session_id"`
	RouteGeneration      uint64    `json:"route_generation"`
	ProcessGeneration    uint64    `json:"process_generation"`
	ConfigGeneration     uint64    `json:"config_generation"`
	SessionGeneration    uint64    `json:"session_generation"`
	AssignmentGeneration uint64    `json:"assignment_generation"`
	EdgeNodeID           string    `json:"edge_node_id"`
	EdgeProcessEpoch     string    `json:"edge_process_epoch"`
	Protocol             string    `json:"protocol"`
	Method               string    `json:"method,omitempty"`
	Host                 string    `json:"host,omitempty"`
	Path                 string    `json:"path,omitempty"`
	IdempotencyKey       string    `json:"idempotency_key"`
	RequestID            string    `json:"request_id"`
	CorrelationID        string    `json:"correlation_id"`
}

type privateAccessGrantResponse struct {
	Schema        string                                 `json:"schema"`
	Kind          string                                 `json:"kind"`
	Grant         string                                 `json:"grant"`
	ExpiresAt     time.Time                              `json:"expires_at"`
	RequestID     string                                 `json:"request_id"`
	CorrelationID string                                 `json:"correlation_id"`
	Request       connectorprotocol.PrivateAccessRequest `json:"request"`
}

type privateAccessGrantClient struct {
	endpoint *url.URL
	auth     privateAccessMachineAuth
	client   *http.Client
	now      func() time.Time
}

type privateAccessMachineAuth interface {
	Token(context.Context) (string, error)
	Proof(context.Context, string, string, string, []byte) ([]byte, error)
}

func newPrivateAccessGrantClient(controlURL string, auth privateAccessMachineAuth, transport http.RoundTripper) (*privateAccessGrantClient, error) {
	endpoint, err := url.Parse(strings.TrimSpace(controlURL))
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || auth == nil {
		return nil, ErrPrivateAccessInvalid
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + privateAccessGrantPath
	if transport == nil {
		transport = httptransport.Default()
	}
	return &privateAccessGrantClient{
		endpoint: endpoint, auth: auth, now: func() time.Time { return time.Now().UTC() },
		client: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrPrivateAccessInvalid }},
	}, nil
}

func (c *privateAccessGrantClient) issue(ctx context.Context, request privateAccessGrantIssue) (privateAccessGrantResponse, error) {
	if c == nil || ctx == nil {
		return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	body, err := json.Marshal(request)
	if err != nil {
		return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	token, err := c.auth.Token(ctx)
	if err != nil {
		if errors.Is(err, machinecontrol.ErrInvalid) || errors.Is(err, ErrPrivateAccessInvalid) {
			return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessAuthentication
		}
		return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	proof, err := c.auth.Proof(ctx, request.IdempotencyKey, http.MethodPost, c.endpoint.Path, body)
	if err != nil {
		if errors.Is(err, machinecontrol.ErrInvalid) || errors.Is(err, ErrPrivateAccessInvalid) {
			return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessAuthentication
		}
		return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	httpRequest.Header.Set("X-Paperboat-Machine-Identity", token)
	httpRequest.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := c.client.Do(httpRequest)
	if err != nil {
		return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.CopyN(io.Discard, response.Body, privateAccessMaxBody)
		switch response.StatusCode {
		case http.StatusUnauthorized:
			return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessAuthentication
		case http.StatusForbidden:
			return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessForbidden
		default:
			return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessTemporarilyUnavailable
		}
	}
	if response.Header.Get("Content-Type") != "application/json" {
		return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, privateAccessMaxBody+1))
	if readErr != nil || len(raw) == 0 || len(raw) > privateAccessMaxBody {
		return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result privateAccessGrantResponse
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || result.Schema != connectorprotocol.PrivateAccessSchema || result.Kind != connectorprotocol.PrivateAccessKind || result.Request.Validate(c.now()) != nil || result.Grant == "" || result.ExpiresAt != result.Request.ExpiresAt || result.RequestID != request.RequestID || result.CorrelationID != request.CorrelationID {
		return privateAccessGrantResponse{}, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	return result, nil
}

type privateAccessRoute struct {
	lease     Lease
	admission CarrierAdmission
	active    *connector.ActiveDataCarrier
	identity  connector.DataCarrierIdentity
	token     uint64
	accessor  *accessorAdmission
	matchType string
}

// PrivateAccessSource is the stable hostd-owned PAC and CONNECT source. It
// publishes only currently attached private names and reauthorizes every
// opened stream with the renewable machine credential.
type PrivateAccessSource struct {
	grants    *privateAccessGrantClient
	discovery *accessorDiscoveryClient
	sessions  *MachineAttachmentSessionSource
	now       func() time.Time

	mu               sync.RWMutex
	closed           bool
	next             uint64
	ownerRoutes      map[string]privateAccessRoute
	discoveredRoutes map[string]privateAccessRoute
}

func (s *PrivateAccessSource) configureAccessor(discovery *accessorDiscoveryClient, sessions *MachineAttachmentSessionSource) error {
	if s == nil || discovery == nil || sessions == nil {
		return ErrPrivateAccessInvalid
	}
	s.discovery = discovery
	s.sessions = sessions
	return nil
}

func newPrivateAccessSource(grants *privateAccessGrantClient) (*PrivateAccessSource, error) {
	if grants == nil {
		return nil, ErrPrivateAccessInvalid
	}
	return &PrivateAccessSource{
		grants: grants, now: func() time.Time { return time.Now().UTC() },
		ownerRoutes: make(map[string]privateAccessRoute), discoveredRoutes: make(map[string]privateAccessRoute),
	}, nil
}

func (s *PrivateAccessSource) register(lease Lease, admission CarrierAdmission, active *connector.ActiveDataCarrier, identity connector.DataCarrierIdentity) (uint64, error) {
	if s == nil || lease.AccessMode != "private" || active == nil || admission.AccessMode != "private" || admission.Binding.PreviewID != lease.ID || admission.Binding.AccountID != lease.AccountID || admission.Binding.LeaseGeneration != uint64(lease.Generation) {
		return 0, ErrPrivateAccessInvalid
	}
	host, err := privateAccessEndpointHost(lease.Endpoint)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrPrivateAccessInvalid
	}
	s.next++
	entry := privateAccessRoute{lease: lease, admission: admission, active: active, identity: identity, token: s.next}
	if _, conflict := s.discoveredRoutes[host]; conflict {
		return 0, ErrPrivateAccessInvalid
	}
	s.ownerRoutes[host] = entry
	return entry.token, nil
}

func (s *PrivateAccessSource) unregister(host string, token uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.ownerRoutes[host]; ok && current.token == token {
		delete(s.ownerRoutes, host)
	}
}

// mergedRoutesLocked preserves the two authority sources independently. A
// hostname collision is an invalid control-plane state, never last-writer
// wins. Callers must hold at least s.mu.RLock.
func (s *PrivateAccessSource) mergedRoutesLocked() (map[string]privateAccessRoute, error) {
	merged := make(map[string]privateAccessRoute, len(s.ownerRoutes)+len(s.discoveredRoutes))
	for key, route := range s.ownerRoutes {
		merged[key] = route
	}
	for key, route := range s.discoveredRoutes {
		if _, exists := merged[key]; exists {
			return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
		}
		merged[key] = route
	}
	return merged, nil
}

func (s *PrivateAccessSource) Snapshot(ctx context.Context) ([]privatepreviewproxy.AccessRoute, error) {
	if s == nil {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	if s.discovery != nil {
		admissions, err := s.discovery.snapshot(ctx)
		if err != nil {
			return nil, err
		}
		next := make(map[string]privateAccessRoute, len(admissions))
		for _, a := range admissions {
			if a.Protocol != "http" {
				continue
			}
			rawHost := a.Hostname
			matchType := privatepreviewproxy.AccessMatchExact
			if strings.HasPrefix(rawHost, "*.") {
				matchType = privatepreviewproxy.AccessMatchOneLabelWildcard
				rawHost = strings.TrimPrefix(rawHost, "*.")
			}
			host, err := privateAccessEndpointHost("https://" + rawHost)
			if err != nil || !a.ExpiresAt.After(s.now()) {
				return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
			}
			copy := a
			key := host
			if matchType == privatepreviewproxy.AccessMatchOneLabelWildcard {
				key = "*." + host
			}
			if _, exists := next[key]; exists {
				return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
			}
			next[key] = privateAccessRoute{accessor: &copy, matchType: matchType}
		}
		s.mu.Lock()
		if !s.closed {
			for key := range next {
				if _, conflict := s.ownerRoutes[key]; conflict {
					s.mu.Unlock()
					return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
				}
			}
			s.discoveredRoutes = next
		}
		s.mu.Unlock()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	merged, err := s.mergedRoutesLocked()
	if err != nil {
		return nil, err
	}
	routes := make([]privatepreviewproxy.AccessRoute, 0, len(merged))
	for host, entry := range merged {
		matchType := entry.matchType
		if matchType == "" {
			matchType = privatepreviewproxy.AccessMatchExact
		}
		routes = append(routes, privatepreviewproxy.AccessRoute{MatchType: matchType, Hostname: strings.TrimPrefix(host, "*.")})
	}
	return routes, nil
}

// OpenPrivateTCP opens one freshly authorized private_access_tcp stream for
// the exact server-discovered durable route. The route ID is safe metadata;
// no origin address or reusable credential crosses this seam.
func (s *PrivateAccessSource) OpenPrivateTCP(ctx context.Context, routeID string) (io.ReadWriteCloser, error) {
	if s == nil || ctx == nil || routeID == "" || s.discovery == nil || s.sessions == nil {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	admissions, err := s.discovery.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	selected, err := privateTCPAdmission(admissions, routeID, s.now())
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	closed = s.closed
	s.mu.RUnlock()
	if closed {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	return s.openAccessorProtocol(ctx, "", selected, "tcp")
}

func privateTCPAdmission(admissions []accessorAdmission, routeID string, now time.Time) (accessorAdmission, error) {
	var selected *accessorAdmission
	for i := range admissions {
		a := &admissions[i]
		if a.RouteID == routeID && a.ResourceKind == "tunnel" && a.Protocol == "private_tcp" && a.ExpiresAt.After(now) {
			if selected != nil {
				return accessorAdmission{}, privatepreviewproxy.ErrAccessTemporarilyUnavailable
			}
			selected = a
		}
	}
	if selected == nil {
		return accessorAdmission{}, privatepreviewproxy.ErrAccessForbidden
	}
	return *selected, nil
}

func (s *PrivateAccessSource) Open(ctx context.Context, host string) (io.ReadWriteCloser, error) {
	if s == nil || ctx == nil {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	normalized, err := privateAccessEndpointHost("https://" + host)
	if err != nil {
		return nil, privatepreviewproxy.ErrAccessForbidden
	}
	s.mu.RLock()
	merged, mergeErr := s.mergedRoutesLocked()
	entry, ok := merged[normalized]
	if !ok {
		for key, candidate := range merged {
			if candidate.matchType == privatepreviewproxy.AccessMatchOneLabelWildcard && oneLabelPrivateMatch(normalized, strings.TrimPrefix(key, "*.")) {
				entry, ok = candidate, true
				break
			}
		}
	}
	closed := s.closed
	s.mu.RUnlock()
	if mergeErr != nil {
		return nil, mergeErr
	}
	if closed {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	if !ok || !entry.admission.ExpiresAt.After(s.now()) {
		if entry.accessor == nil {
			return nil, privatepreviewproxy.ErrAccessForbidden
		}
	}
	if entry.accessor != nil {
		return s.openAccessor(ctx, normalized, *entry.accessor)
	}
	identifier, err := newPrivateAccessIdentifier()
	if err != nil {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	expires := s.now().Add(privateAccessGrantTTL)
	if entry.admission.ExpiresAt.Before(expires) {
		expires = entry.admission.ExpiresAt
	}
	binding := entry.admission.Binding
	issue := privateAccessGrantIssue{
		ResourceKind: "preview", ResourceID: binding.PreviewID, RouteID: binding.RouteID, Audience: "paperboat-preview-http",
		ExpiresAt: expires, Nonce: "nonce_" + identifier, OperationID: binding.OperationID, CarrierSessionID: binding.SessionID,
		RouteGeneration: binding.RouteGeneration, ProcessGeneration: binding.ProcessGeneration, ConfigGeneration: binding.ConfigGeneration,
		SessionGeneration: binding.LeaseGeneration, AssignmentGeneration: binding.LeaseGeneration,
		EdgeNodeID: binding.EdgeNodeID, EdgeProcessEpoch: binding.EdgeProcessEpoch, Protocol: "http", Method: http.MethodConnect,
		Host: normalized, Path: "/", IdempotencyKey: "access_" + identifier, RequestID: "request_" + identifier, CorrelationID: "correlation_" + identifier,
	}
	grant, err := s.grants.issue(ctx, issue)
	if err != nil {
		return nil, err
	}
	if !privateAccessRequestMatchesIssue(grant.Request, issue) || grant.Request.AccountID != entry.identity.AccountID || grant.Request.DeviceID != entry.identity.HostID {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	s.mu.RLock()
	current, currentOK := s.ownerRoutes[normalized]
	s.mu.RUnlock()
	if !currentOK || current.token != entry.token || current.active != entry.active || current.identity != entry.identity {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	stream, err := entry.active.OpenStream(ctx, connector.StreamOpen{
		Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion,
		AccountID: entry.identity.AccountID, TunnelID: entry.identity.TunnelID, ConnectorID: entry.identity.ConnectorID,
		SessionID: entry.identity.SessionID, ProcessGeneration: entry.identity.ProcessGeneration, Generation: entry.identity.Generation,
		RouteID: binding.RouteID, RequestID: issue.RequestID, Kind: connectorprotocol.PrivateAccessHTTP,
	})
	if err != nil {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	if err := connectorprotocol.WritePrivateAccessOpen(stream, connectorprotocol.PrivateAccessOpen{Schema: connectorprotocol.PrivateAccessSchema, Kind: connectorprotocol.PrivateAccessKind, Grant: grant.Grant, Request: grant.Request}); err != nil {
		_ = stream.Close()
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	result, err := connectorprotocol.ReadPrivateAccessResult(stream, s.now())
	if err != nil {
		_ = stream.Close()
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	switch result.Status {
	case http.StatusOK:
		if result.ExpiresAt.After(grant.Request.ExpiresAt) {
			_ = stream.Close()
			return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
		}
		return stream, nil
	case http.StatusUnauthorized:
		_ = stream.Close()
		return nil, privatepreviewproxy.ErrAccessAuthentication
	case http.StatusForbidden:
		_ = stream.Close()
		return nil, privatepreviewproxy.ErrAccessForbidden
	default:
		_ = stream.Close()
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
}

func oneLabelPrivateMatch(host, suffix string) bool {
	prefix, ok := strings.CutSuffix(host, "."+suffix)
	return ok && prefix != "" && !strings.Contains(prefix, ".")
}

func (s *PrivateAccessSource) openAccessor(ctx context.Context, host string, a accessorAdmission) (io.ReadWriteCloser, error) {
	admissionHost := a.Hostname
	hostMatches := admissionHost == host
	if strings.HasPrefix(admissionHost, "*.") {
		hostMatches = oneLabelPrivateMatch(host, strings.TrimPrefix(admissionHost, "*."))
	}
	if s.sessions == nil || a.Protocol != "http" || !hostMatches || !a.ExpiresAt.After(s.now()) {
		return nil, privatepreviewproxy.ErrAccessForbidden
	}
	return s.openAccessorProtocol(ctx, host, a, "http")
}

func (s *PrivateAccessSource) openAccessorProtocol(ctx context.Context, host string, a accessorAdmission, protocol string) (io.ReadWriteCloser, error) {
	if protocol != "http" && protocol != "tcp" || a.Protocol != map[string]string{"http": "http", "tcp": "private_tcp"}[protocol] {
		return nil, privatepreviewproxy.ErrAccessForbidden
	}
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	session, err := s.sessions.AcquirePrivateAccessCarrier(ctx, AccessorCarrierAdmission{AccountID: a.AccountID, DeviceID: a.DeviceID, AccessorPublicKey: a.AccessorPublicKey, AccessorThumbprint: a.AccessorThumbprint, TunnelID: a.TunnelID, CarrierConnectorID: a.CarrierConnectorID, CarrierSessionID: a.CarrierSessionID, ProcessGeneration: a.ProcessGeneration, ConfigGeneration: a.ConfigGeneration, EdgeNodeID: a.EdgeNodeID, EdgeProcessEpoch: a.EdgeProcessEpoch, EdgeCarrierServerSPKISHA256: a.EdgeCarrierServerSPKISHA256, EdgeCarrierServerCertificateChainPEM: a.EdgeCarrierServerCertificateChainPEM, EdgeEndpoints: a.EdgeEndpoints, ExpiresAt: a.ExpiresAt})
	if err != nil {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	id, err := newPrivateAccessIdentifier()
	if err != nil {
		_ = session.Release(context.WithoutCancel(ctx))
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	expires := s.now().Add(privateAccessGrantTTL)
	if a.ExpiresAt.Before(expires) {
		expires = a.ExpiresAt
	}
	audience, method, path, kind := "paperboat-tunnel-http", http.MethodConnect, "/", connectorprotocol.PrivateAccessHTTP
	if protocol == "tcp" {
		audience, method, path, kind = "paperboat-tunnel-tcp", "", "", connectorprotocol.PrivateAccessTCP
	}
	issue := privateAccessGrantIssue{ResourceKind: a.ResourceKind, ResourceID: a.ResourceID, RouteID: a.RouteID, Audience: audience, ExpiresAt: expires, Nonce: "nonce_" + id, OperationID: a.OperationID, ConnectorID: a.ConnectorID, CarrierSessionID: a.CarrierSessionID, RouteGeneration: a.RouteGeneration, ProcessGeneration: a.ProcessGeneration, ConfigGeneration: a.ConfigGeneration, SessionGeneration: a.SessionGeneration, AssignmentGeneration: a.AssignmentGeneration, EdgeNodeID: a.EdgeNodeID, EdgeProcessEpoch: a.EdgeProcessEpoch, Protocol: protocol, Method: method, Host: host, Path: path, IdempotencyKey: "access_" + id, RequestID: "request_" + id, CorrelationID: "correlation_" + id}
	grant, err := s.grants.issue(ctx, issue)
	if err != nil {
		_ = session.Release(context.WithoutCancel(ctx))
		return nil, err
	}
	if !privateAccessRequestMatchesIssue(grant.Request, issue) || grant.Request.AccountID != a.AccountID || grant.Request.DeviceID != a.DeviceID {
		_ = session.Release(context.WithoutCancel(ctx))
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	stream, err := session.Active.OpenStream(ctx, connector.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: session.Identity.AccountID, TunnelID: session.Identity.TunnelID, ConnectorID: session.Identity.ConnectorID, SessionID: session.Identity.SessionID, ProcessGeneration: session.Identity.ProcessGeneration, Generation: session.Identity.Generation, RouteID: a.RouteID, RequestID: issue.RequestID, Kind: kind})
	if err != nil {
		_ = session.Release(context.WithoutCancel(ctx))
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	if err = connectorprotocol.WritePrivateAccessOpen(stream, connectorprotocol.PrivateAccessOpen{Schema: connectorprotocol.PrivateAccessSchema, Kind: connectorprotocol.PrivateAccessKind, Grant: grant.Grant, Request: grant.Request}); err != nil {
		_ = stream.Close()
		_ = session.Release(context.WithoutCancel(ctx))
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	result, err := connectorprotocol.ReadPrivateAccessResult(stream, s.now())
	if err != nil || result.Status != http.StatusOK || result.ExpiresAt.After(grant.Request.ExpiresAt) {
		_ = stream.Close()
		_ = session.Release(context.WithoutCancel(ctx))
		if result.Status == 401 {
			return nil, privatepreviewproxy.ErrAccessAuthentication
		}
		if result.Status == 403 {
			return nil, privatepreviewproxy.ErrAccessForbidden
		}
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	return &privateAccessorStream{ReadWriteCloser: stream, release: session.Release}, nil
}

type privateAccessorStream struct {
	io.ReadWriteCloser
	once    sync.Once
	release func(context.Context) error
}

func (s *privateAccessorStream) Close() error {
	var result error
	s.once.Do(func() {
		result = s.ReadWriteCloser.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = errors.Join(result, s.release(ctx))
	})
	return result
}

func (s *PrivateAccessSource) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.ownerRoutes = make(map[string]privateAccessRoute)
	s.discoveredRoutes = make(map[string]privateAccessRoute)
	s.mu.Unlock()
}

func privateAccessEndpointHost(endpoint string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Port() != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return "", ErrPrivateAccessInvalid
	}
	host := parsed.Hostname()
	if strings.TrimSpace(host) != host || strings.ContainsAny(host, "\r\n\x00 /?#:*") || net.ParseIP(host) != nil {
		return "", ErrPrivateAccessInvalid
	}
	host = strings.TrimSuffix(host, ".")
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" || len(ascii) > 253 || strings.Contains(ascii, "..") {
		return "", ErrPrivateAccessInvalid
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrPrivateAccessInvalid
		}
	}
	return strings.ToLower(ascii), nil
}

func newPrivateAccessIdentifier() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func privateAccessRequestMatchesIssue(got connectorprotocol.PrivateAccessRequest, want privateAccessGrantIssue) bool {
	return got.ResourceKind == want.ResourceKind && got.ResourceID == want.ResourceID && got.RouteID == want.RouteID && got.Audience == want.Audience && got.ExpiresAt.Equal(want.ExpiresAt) && got.Nonce == want.Nonce && got.OperationID == want.OperationID && got.ConnectorID == want.ConnectorID && got.CarrierSessionID == want.CarrierSessionID && got.RouteGeneration == want.RouteGeneration && got.ProcessGeneration == want.ProcessGeneration && got.ConfigGeneration == want.ConfigGeneration && got.SessionGeneration == want.SessionGeneration && got.AssignmentGeneration == want.AssignmentGeneration && got.EdgeNodeID == want.EdgeNodeID && got.EdgeProcessEpoch == want.EdgeProcessEpoch && got.Protocol == want.Protocol && got.Method == want.Method && got.Host == want.Host && got.Path == want.Path && got.IdempotencyKey == want.IdempotencyKey && got.RequestID == want.RequestID && got.CorrelationID == want.CorrelationID
}

var _ privatepreviewproxy.AccessSource = (*PrivateAccessSource)(nil)
