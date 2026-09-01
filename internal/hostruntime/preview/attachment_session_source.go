package preview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
)

var (
	ErrMachineAttachmentSessionInvalid     = errors.New("invalid machine preview attachment session")
	ErrMachineAttachmentSessionUnavailable = errors.New("machine preview attachment session unavailable")
	ErrMachineAttachmentTrustRequired      = errors.New("preview edge server trust binding is required")
)

// DataCarrierSessionSourceFactory is the narrow test and deployment seam for
// turning an admitted, TLS-configured endpoint set into a staged connector
// carrier. Production uses connector.NewNetworkDataCarrierSessionSource.
// Tests may inject a deterministic source without replacing admission or
// machine-key validation.
type DataCarrierSessionSourceFactory func(connector.DataCarrierIdentity, connector.DataCarrierPoolConfig, connector.NetworkDialerConfig) (connector.DataCarrierSessionSource, error)

// MachineAttachmentSessionSourceConfig contains only local machine state and
// edge trust policy. The server admission supplies the endpoint and exact
// route/session binding; no bearer or private credential is accepted here.
type MachineAttachmentSessionSourceConfig struct {
	StateRoot string

	Carrier         connector.DataCarrierPoolConfig
	TLSLeafLifetime time.Duration
	Clock           func() time.Time
	SessionFactory  DataCarrierSessionSourceFactory
}

// MachineAttachmentSessionSource authenticates ephemeral preview carrier
// admissions with the registered machine identity and shares one active
// machine/runtime carrier among routes for the exact connector identity.
// Each caller receives a reference-counted release handle. A replacement
// process/session/config generation gets a distinct entry and fences the old
// carrier without allowing it to consume new route streams.
type MachineAttachmentSessionSource struct {
	stateRoot       string
	carrier         connector.DataCarrierPoolConfig
	tlsLeafLifetime time.Duration
	clock           func() time.Time
	factory         DataCarrierSessionSourceFactory

	acquireMu sync.Mutex
	mu        sync.Mutex
	closed    bool
	entries   map[machineAttachmentSessionKey]*machineAttachmentSessionEntry
}

type machineAttachmentSessionKey struct {
	accountID         string
	hostID            string
	tunnelID          string
	connectorID       string
	sessionID         string
	processGeneration uint64
	configGeneration  uint64
	edgeNodeID        string
	edgeProcessEpoch  string
	endpoints         string
}

type machineAttachmentSessionEntry struct {
	active   *connector.ActiveDataCarrier
	identity connector.DataCarrierIdentity
	refs     int
}

// AccessorCarrierAdmission is the server-issued, short-lived authority for an
// enrolled accessor machine. It is independent of preview ownership.
type AccessorCarrierAdmission struct {
	AccountID, DeviceID, AccessorPublicKey, AccessorThumbprint string
	TunnelID, CarrierConnectorID, CarrierSessionID             string
	ProcessGeneration, ConfigGeneration                        uint64
	EdgeNodeID, EdgeProcessEpoch                               string
	EdgeCarrierServerSPKISHA256                                string
	EdgeCarrierServerCertificateChainPEM                       string
	EdgeEndpoints                                              []string
	ExpiresAt                                                  time.Time
}

func NewMachineAttachmentSessionSource(config MachineAttachmentSessionSourceConfig) (*MachineAttachmentSessionSource, error) {
	if !filepath.IsAbs(strings.TrimSpace(config.StateRoot)) {
		return nil, ErrMachineAttachmentSessionInvalid
	}
	if config.TLSLeafLifetime == 0 {
		config.TLSLeafLifetime = identity.DefaultTLSCertificateLifetime
	}
	if config.TLSLeafLifetime <= 0 || config.TLSLeafLifetime > identity.MaxTLSCertificateLifetime {
		return nil, ErrMachineAttachmentSessionInvalid
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.SessionFactory == nil {
		config.SessionFactory = connector.NewNetworkDataCarrierSessionSource
	}
	if config.Carrier.MaximumCarriers != 0 && config.Carrier.MaximumCarriers != 1 {
		return nil, fmt.Errorf("%w: preview source requires one shared carrier", ErrMachineAttachmentSessionInvalid)
	}
	config.Carrier.MaximumCarriers = 1
	return &MachineAttachmentSessionSource{
		stateRoot: config.StateRoot, carrier: config.Carrier, tlsLeafLifetime: config.TLSLeafLifetime, clock: config.Clock,
		factory: config.SessionFactory, entries: make(map[machineAttachmentSessionKey]*machineAttachmentSessionEntry),
	}, nil
}

// AcquirePreviewDataCarrier obtains or shares the active carrier bound to the
// complete server admission. The server's machine public key is checked
// against the secure local identity store before a TLS leaf is minted.
func (s *MachineAttachmentSessionSource) AcquirePreviewDataCarrier(ctx context.Context, admission CarrierAdmission) (AttachmentSession, error) {
	if s == nil || ctx == nil {
		return AttachmentSession{}, ErrMachineAttachmentSessionInvalid
	}
	if err := ctx.Err(); err != nil {
		return AttachmentSession{}, err
	}
	now := s.clock().UTC()
	if err := admission.Validate(now); err != nil {
		return AttachmentSession{}, fmt.Errorf("%w: admission: %v", ErrMachineAttachmentSessionInvalid, err)
	}
	key, localIdentity, leaf, endpoints, poolConfig, err := s.prepareAdmission(admission, now)
	if err != nil {
		return AttachmentSession{}, err
	}

	// Serializing construction prevents two simultaneous previews from
	// dialing duplicate machine carriers for the same session generation.
	s.acquireMu.Lock()
	defer s.acquireMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return AttachmentSession{}, ErrMachineAttachmentSessionUnavailable
	}
	if existing := s.entries[key]; existing != nil && machineAttachmentEntryReady(existing, localIdentity) {
		existing.refs++
		s.mu.Unlock()
		return s.sessionForEntry(key, existing), nil
	}
	stale := s.entries[key]
	if stale != nil {
		delete(s.entries, key)
	}
	s.mu.Unlock()
	if stale != nil && stale.active != nil {
		_ = stale.active.Close(context.WithoutCancel(ctx))
	}

	// The TLS leaf is created before dialing and is held only in the in-memory
	// endpoint configs for this carrier lifetime.
	_ = leaf
	source, err := s.factory(localIdentity, poolConfig, endpoints)
	if err != nil {
		return AttachmentSession{}, errors.Join(ErrMachineAttachmentSessionUnavailable, err)
	}
	prepared, err := source.Prepare(ctx)
	if err != nil {
		return AttachmentSession{}, errors.Join(ErrMachineAttachmentSessionUnavailable, err)
	}
	active, err := prepared.Activate(ctx)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = prepared.Abort(cleanupCtx)
		cancel()
		return AttachmentSession{}, errors.Join(ErrMachineAttachmentSessionUnavailable, err)
	}
	entry := &machineAttachmentSessionEntry{active: active, identity: localIdentity, refs: 1}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = active.Close(context.WithoutCancel(ctx))
		return AttachmentSession{}, ErrMachineAttachmentSessionUnavailable
	}
	if existing := s.entries[key]; existing != nil && machineAttachmentEntryReady(existing, localIdentity) {
		existing.refs++
		s.mu.Unlock()
		_ = active.Close(context.WithoutCancel(ctx))
		return s.sessionForEntry(key, existing), nil
	}
	s.entries[key] = entry
	s.mu.Unlock()
	return s.sessionForEntry(key, entry), nil
}

func (s *MachineAttachmentSessionSource) AcquirePrivateAccessCarrier(ctx context.Context, admission AccessorCarrierAdmission) (AttachmentSession, error) {
	if s == nil || ctx == nil || admission.AccountID == "" || admission.DeviceID == "" || admission.TunnelID == "" || admission.CarrierConnectorID == "" || admission.CarrierSessionID == "" || admission.ProcessGeneration == 0 || admission.ConfigGeneration == 0 || admission.EdgeNodeID == "" || admission.EdgeProcessEpoch == "" || len(admission.EdgeEndpoints) == 0 || !admission.ExpiresAt.After(s.clock().UTC()) {
		return AttachmentSession{}, ErrMachineAttachmentSessionInvalid
	}
	key, localIdentity, _, endpoints, poolConfig, err := s.prepareCarrier(admission.AccountID, admission.DeviceID, admission.AccessorPublicKey, admission.AccessorThumbprint, admission.TunnelID, admission.CarrierConnectorID, admission.CarrierSessionID, admission.ProcessGeneration, admission.ConfigGeneration, admission.EdgeNodeID, admission.EdgeProcessEpoch, admission.EdgeCarrierServerSPKISHA256, admission.EdgeCarrierServerCertificateChainPEM, admission.EdgeEndpoints, admission.ExpiresAt, s.clock().UTC())
	if err != nil {
		return AttachmentSession{}, err
	}
	return s.acquirePrepared(ctx, key, localIdentity, endpoints, poolConfig)
}

func (s *MachineAttachmentSessionSource) acquirePrepared(ctx context.Context, key machineAttachmentSessionKey, localIdentity connector.DataCarrierIdentity, endpoints connector.NetworkDialerConfig, poolConfig connector.DataCarrierPoolConfig) (AttachmentSession, error) {
	s.acquireMu.Lock()
	defer s.acquireMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return AttachmentSession{}, ErrMachineAttachmentSessionUnavailable
	}
	if existing := s.entries[key]; existing != nil && machineAttachmentEntryReady(existing, localIdentity) {
		existing.refs++
		s.mu.Unlock()
		return s.sessionForEntry(key, existing), nil
	}
	stale := s.entries[key]
	delete(s.entries, key)
	s.mu.Unlock()
	if stale != nil && stale.active != nil {
		_ = stale.active.Close(context.WithoutCancel(ctx))
	}
	source, err := s.factory(localIdentity, poolConfig, endpoints)
	if err != nil {
		return AttachmentSession{}, errors.Join(ErrMachineAttachmentSessionUnavailable, err)
	}
	prepared, err := source.Prepare(ctx)
	if err != nil {
		return AttachmentSession{}, errors.Join(ErrMachineAttachmentSessionUnavailable, err)
	}
	active, err := prepared.Activate(ctx)
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = prepared.Abort(cleanup)
		cancel()
		return AttachmentSession{}, errors.Join(ErrMachineAttachmentSessionUnavailable, err)
	}
	entry := &machineAttachmentSessionEntry{active: active, identity: localIdentity, refs: 1}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = active.Close(context.WithoutCancel(ctx))
		return AttachmentSession{}, ErrMachineAttachmentSessionUnavailable
	}
	s.entries[key] = entry
	s.mu.Unlock()
	return s.sessionForEntry(key, entry), nil
}

// Close releases every source-owned active carrier. It is idempotent and does
// not use a process-global background context; callers supply the shutdown
// deadline that bounds transport cleanup.
func (s *MachineAttachmentSessionSource) Close(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrMachineAttachmentSessionInvalid
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	entries := make([]*machineAttachmentSessionEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		entries = append(entries, entry)
	}
	s.entries = make(map[machineAttachmentSessionKey]*machineAttachmentSessionEntry)
	s.mu.Unlock()
	var result error
	for _, entry := range entries {
		if entry != nil && entry.active != nil {
			result = errors.Join(result, entry.active.Close(ctx))
		}
	}
	return result
}

func (s *MachineAttachmentSessionSource) sessionForEntry(key machineAttachmentSessionKey, entry *machineAttachmentSessionEntry) AttachmentSession {
	var once sync.Once
	var releaseErr error
	return AttachmentSession{
		Active: entry.active, Identity: entry.identity,
		Release: func(ctx context.Context) error {
			once.Do(func() { releaseErr = s.release(key, entry, ctx) })
			return releaseErr
		},
	}
}

func (s *MachineAttachmentSessionSource) release(key machineAttachmentSessionKey, entry *machineAttachmentSessionEntry, ctx context.Context) error {
	if ctx == nil {
		return ErrMachineAttachmentSessionInvalid
	}
	s.mu.Lock()
	current := s.entries[key]
	if current != entry {
		s.mu.Unlock()
		return nil
	}
	if current.refs > 0 {
		current.refs--
	}
	if current.refs != 0 {
		s.mu.Unlock()
		return nil
	}
	delete(s.entries, key)
	active := current.active
	s.mu.Unlock()
	if active == nil {
		return nil
	}
	return active.Close(ctx)
}

func machineAttachmentEntryReady(entry *machineAttachmentSessionEntry, identity connector.DataCarrierIdentity) bool {
	if entry == nil || entry.active == nil || entry.identity != identity {
		return false
	}
	pool := entry.active.Pool()
	if pool == nil || pool.State() != connector.DataCarrierPoolReady {
		return false
	}
	for _, info := range entry.active.Snapshot() {
		if info.Identity == identity && info.State == connector.DataCarrierReady {
			return true
		}
	}
	return false
}

func (s *MachineAttachmentSessionSource) prepareAdmission(admission CarrierAdmission, now time.Time) (machineAttachmentSessionKey, connector.DataCarrierIdentity, tls.Certificate, connector.NetworkDialerConfig, connector.DataCarrierPoolConfig, error) {
	binding := admission.Binding
	return s.prepareCarrier(binding.AccountID, binding.HostID, binding.MachineIdentityPublicKey, binding.MachineIdentityThumbprint, binding.TunnelID, binding.ConnectorID, binding.SessionID, binding.ProcessGeneration, binding.ConfigGeneration, binding.EdgeNodeID, binding.EdgeProcessEpoch, binding.EdgeCarrierServerSPKISHA256, binding.EdgeCarrierServerCertificateChainPEM, admission.EdgeEndpoints, admission.ExpiresAt, now)
}

func (s *MachineAttachmentSessionSource) prepareCarrier(accountID, hostID, machinePublicKey, machineThumbprint, tunnelID, connectorID, sessionID string, processGeneration, configGeneration uint64, edgeNodeID, edgeProcessEpoch, edgeCarrierServerSPKISHA256, edgeCarrierServerCertificateChainPEM string, edgeEndpoints []string, expiresAt, now time.Time) (machineAttachmentSessionKey, connector.DataCarrierIdentity, tls.Certificate, connector.NetworkDialerConfig, connector.DataCarrierPoolConfig, error) {
	store, err := identity.Open(identity.Config{StateRoot: s.stateRoot})
	if err != nil {
		return machineAttachmentSessionKey{}, connector.DataCarrierIdentity{}, tls.Certificate{}, connector.NetworkDialerConfig{}, connector.DataCarrierPoolConfig{}, errors.Join(ErrMachineAttachmentSessionUnavailable, err)
	}
	registration, err := store.Registration()
	if err != nil {
		return machineAttachmentSessionKey{}, connector.DataCarrierIdentity{}, tls.Certificate{}, connector.NetworkDialerConfig{}, connector.DataCarrierPoolConfig{}, errors.Join(ErrMachineAttachmentSessionUnavailable, err)
	}
	key := store.Current()
	publicKey := base64.RawURLEncoding.EncodeToString(key.Public())
	if registration.MachineID != hostID || registration.PublicKeyID != key.ID || registration.PublicIdentityKey != publicKey || publicKey != machinePublicKey || machineIdentityThumbprint(publicKey) != machineThumbprint {
		return machineAttachmentSessionKey{}, connector.DataCarrierIdentity{}, tls.Certificate{}, connector.NetworkDialerConfig{}, connector.DataCarrierPoolConfig{}, fmt.Errorf("%w: admission machine identity does not match local registration", ErrMachineAttachmentSessionInvalid)
	}
	lifetime := s.tlsLeafLifetime
	if remaining := expiresAt.Sub(now); remaining < lifetime {
		lifetime = remaining
	}
	liveIdentity := connector.DataCarrierIdentity{
		AccountID: accountID, HostID: hostID, TunnelID: tunnelID,
		ConnectorID: connectorID, SessionID: sessionID,
		ProcessGeneration: processGeneration, Generation: configGeneration,
	}
	if err := validatePreviewCarrierIdentity(liveIdentity); err != nil {
		return machineAttachmentSessionKey{}, connector.DataCarrierIdentity{}, tls.Certificate{}, connector.NetworkDialerConfig{}, connector.DataCarrierPoolConfig{}, fmt.Errorf("%w: live identity: %v", ErrMachineAttachmentSessionInvalid, err)
	}
	carrierURN, err := connectorprotocol.CarrierIdentityURN(connectorprotocol.CarrierIdentityBinding{
		AccountID: liveIdentity.AccountID, HostID: liveIdentity.HostID, TunnelID: liveIdentity.TunnelID,
		ConnectorID: liveIdentity.ConnectorID, SessionID: liveIdentity.SessionID,
		ProcessGeneration: liveIdentity.ProcessGeneration, ConfigGeneration: liveIdentity.Generation,
		EdgeProcessEpoch: edgeProcessEpoch,
	})
	if err != nil {
		return machineAttachmentSessionKey{}, connector.DataCarrierIdentity{}, tls.Certificate{}, connector.NetworkDialerConfig{}, connector.DataCarrierPoolConfig{}, fmt.Errorf("%w: carrier identity URI: %v", ErrMachineAttachmentSessionInvalid, err)
	}
	leaf, err := store.CurrentTLSCertificateWithURIs(now, lifetime, []*url.URL{carrierURN})
	if err != nil {
		return machineAttachmentSessionKey{}, connector.DataCarrierIdentity{}, tls.Certificate{}, connector.NetworkDialerConfig{}, connector.DataCarrierPoolConfig{}, errors.Join(ErrMachineAttachmentSessionInvalid, err)
	}
	endpoints, hasTCP, hasQUIC, err := s.endpointConfigsValues(edgeEndpoints, liveIdentity, edgeNodeID, edgeProcessEpoch, edgeCarrierServerSPKISHA256, edgeCarrierServerCertificateChainPEM, leaf)
	if err != nil {
		return machineAttachmentSessionKey{}, connector.DataCarrierIdentity{}, tls.Certificate{}, connector.NetworkDialerConfig{}, connector.DataCarrierPoolConfig{}, err
	}
	poolConfig := s.carrier
	poolConfig.MaximumCarriers = 1
	poolConfig.EdgeID = edgeNodeID
	poolConfig.FailureDomains = []string{edgeNodeID}
	poolConfig.Session = liveIdentity
	switch {
	case hasQUIC && hasTCP:
		poolConfig.Preferred, poolConfig.Fallback, poolConfig.SingleTransport = connector.QUIC, connector.TCPMux, false
	case hasQUIC:
		poolConfig.Preferred, poolConfig.Fallback, poolConfig.SingleTransport = connector.QUIC, connector.QUIC, true
	case hasTCP:
		poolConfig.Preferred, poolConfig.Fallback, poolConfig.SingleTransport = connector.TCPMux, connector.TCPMux, true
	default:
		return machineAttachmentSessionKey{}, connector.DataCarrierIdentity{}, tls.Certificate{}, connector.NetworkDialerConfig{}, connector.DataCarrierPoolConfig{}, ErrMachineAttachmentSessionInvalid
	}
	if err := poolConfig.Validate(); err != nil {
		return machineAttachmentSessionKey{}, connector.DataCarrierIdentity{}, tls.Certificate{}, connector.NetworkDialerConfig{}, connector.DataCarrierPoolConfig{}, fmt.Errorf("%w: carrier config: %v", ErrMachineAttachmentSessionInvalid, err)
	}
	keyValue := machineAttachmentSessionKey{
		accountID: accountID, hostID: hostID, tunnelID: tunnelID, connectorID: connectorID,
		sessionID: sessionID, processGeneration: processGeneration, configGeneration: configGeneration,
		edgeNodeID: edgeNodeID, edgeProcessEpoch: edgeProcessEpoch,
		endpoints: strings.Join(edgeEndpoints, "\x00"),
	}
	return keyValue, liveIdentity, leaf, endpoints, poolConfig, nil
}

func (s *MachineAttachmentSessionSource) endpointConfigs(admission CarrierAdmission, expected connector.DataCarrierIdentity, leaf tls.Certificate) (connector.NetworkDialerConfig, bool, bool, error) {
	return s.endpointConfigsValues(admission.EdgeEndpoints, expected, admission.Binding.EdgeNodeID, admission.Binding.EdgeProcessEpoch, admission.Binding.EdgeCarrierServerSPKISHA256, admission.Binding.EdgeCarrierServerCertificateChainPEM, leaf)
}

func (s *MachineAttachmentSessionSource) endpointConfigsValues(edgeEndpoints []string, expected connector.DataCarrierIdentity, edgeNodeID, edgeProcessEpoch, edgeCarrierServerSPKISHA256, edgeCarrierServerCertificateChainPEM string, leaf tls.Certificate) (connector.NetworkDialerConfig, bool, bool, error) {
	roots, err := edgeCarrierServerRoots(edgeCarrierServerCertificateChainPEM, edgeCarrierServerSPKISHA256)
	if err != nil {
		return connector.NetworkDialerConfig{}, false, false, err
	}
	var result connector.NetworkDialerConfig
	var hasTCP, hasQUIC bool
	seen := make(map[connector.Transport]struct{}, 2)
	for _, raw := range edgeEndpoints {
		scheme, address, serverName, err := normalizeCarrierEndpoint(raw)
		if err != nil {
			return connector.NetworkDialerConfig{}, false, false, fmt.Errorf("%w: edge endpoint: %v", ErrMachineAttachmentSessionInvalid, err)
		}
		transport := connector.TCPMux
		if scheme == "quic" {
			transport = connector.QUIC
		}
		if _, exists := seen[transport]; exists {
			return connector.NetworkDialerConfig{}, false, false, fmt.Errorf("%w: duplicate %s endpoint", ErrMachineAttachmentSessionInvalid, transport)
		}
		seen[transport] = struct{}{}
		peerBinding := func(state tls.ConnectionState) (connector.DataCarrierIdentity, error) {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
				return connector.DataCarrierIdentity{}, ErrMachineAttachmentTrustRequired
			}
			digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if edgeCarrierServerSPKISHA256 != "sha256:"+hex.EncodeToString(digest[:]) {
				return connector.DataCarrierIdentity{}, ErrMachineAttachmentTrustRequired
			}
			return expected, nil
		}
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{leaf}, RootCAs: roots, ServerName: serverName,
			NextProtos: []string{connector.DataCarrierALPN}, InsecureSkipVerify: false,
		}
		endpoint := connector.DataCarrierEndpointConfig{Address: address, TLS: tlsConfig, PeerBinding: peerBinding, ExpectedIdentity: expected}
		if transport == connector.QUIC {
			result.QUIC, hasQUIC = endpoint, true
		} else {
			result.TCPMux, hasTCP = endpoint, true
		}
	}
	return result, hasTCP, hasQUIC, nil
}

func edgeCarrierServerRoots(chainPEM, pin string) (*x509.CertPool, error) {
	if !validEdgeCarrierServerCertificateChainPEM(chainPEM, pin) {
		return nil, ErrMachineAttachmentTrustRequired
	}
	roots := x509.NewCertPool()
	rest := []byte(chainPEM)
	for len(bytes.TrimSpace(rest)) != 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, ErrMachineAttachmentTrustRequired
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrMachineAttachmentTrustRequired
		}
		roots.AddCert(certificate)
		rest = remaining
	}
	return roots, nil
}

func normalizeCarrierEndpoint(raw string) (string, string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return "", "", "", ErrMachineAttachmentSessionInvalid
	}
	scheme := strings.ToLower(parsed.Scheme)
	// Edge carrier endpoints are raw authenticated carrier transports. They
	// are not HTTP or WebSocket URLs: TCPMux is TLS-over-TCP and QUIC is QUIC
	// with the same connector-v1 admission. Keeping the schemes explicit
	// prevents accidentally treating an HTTP endpoint as a carrier socket.
	if scheme != "tls" && scheme != "quic" {
		return "", "", "", ErrMachineAttachmentSessionInvalid
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", "", ErrMachineAttachmentSessionInvalid
	}
	host := parsed.Hostname()
	if net.ParseIP(host) == nil && strings.ContainsAny(host, " \t\r\n") {
		return "", "", "", ErrMachineAttachmentSessionInvalid
	}
	return scheme, net.JoinHostPort(host, strconv.Itoa(portNumber)), host, nil
}

var _ AttachmentSessionSource = (*MachineAttachmentSessionSource)(nil)
