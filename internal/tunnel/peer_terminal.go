package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/diagnosticlog"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/localobservation"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/candidatelease"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/clientauthority"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/directpath"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/iceagent"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/nativepeer"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkcheck"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peersession"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/portmapping"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaycarrier"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaypmtu"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/resumablestream"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/signaling"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/streamauth"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transportmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transportstage"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/udpsocket"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
	"github.com/quic-go/quic-go/http3"
)

var ErrPeerTerminalInvalid = errors.New("invalid peer terminal tunnel configuration")
var ErrPeerCarrierConsumed = errors.New("peer carrier has already served its single application")
var ErrPeerCarrierExpired = errors.New("peer carrier authority expired")
var ErrPeerStreamPromotion = errors.New("peer logical stream promotion failed")

const terminalGenerationHistory = 64

type PeerTerminalConfig struct {
	Issuer             string
	Store              config.ProfileStore
	Auth               config.AuthSource
	TLS                *tls.Config
	HTTPClient         *http.Client
	OutputQueueChunks  int
	Race               connectionmanager.Config
	Mode               connectionmanager.Mode
	Now                func() time.Time
	PublishLocalStatus bool
	TransportManager   *transportmanager.Manager
}

type PeerTerminalTunnel struct {
	config               PeerTerminalConfig
	operationSeed        [16]byte
	attempt              atomic.Uint64
	operation            atomic.Uint64
	network              atomic.Uint64
	pmtu                 *networkadaptation.PMTUCache
	relayPMTU            *networkadaptation.AsyncPMTU
	lifetime             *networkadaptation.LifetimeCache
	networkCheckMu       sync.Mutex
	networkChecks        map[networkadaptation.Fingerprint]networkcheck.STUNObservation
	ipv6Mu               sync.RWMutex
	ipv6Viable           map[networkadaptation.Fingerprint]bool
	ipv6Known            map[networkadaptation.Fingerprint]bool
	ipv6Active           map[networkadaptation.Fingerprint]bool
	networkFingerprintMu sync.Mutex
	networkFingerprint   networkadaptation.Fingerprint
	networkFingerprintOK bool
	regionalCache        *networkcheck.RegionalCache
	regionalVector       atomic.Uint64
	regionalMu           sync.Mutex
	sharedRegional       *networkcheck.RegionalMonitor
	signalingSubstrate   *signaling.SubstrateManager
	relaySuccessMu       sync.RWMutex
	relaySuccessRegion   string
	relaySuccessAt       time.Time
	authorities          *clientauthority.Cache
	networkMu            sync.Mutex
	sharedMonitor        *networkmonitor.Monitor
	sharedFingerprint    networkadaptation.Fingerprint
	sharedFingerprintOK  bool
}

func NewPeerTerminalTunnel(config PeerTerminalConfig) (*PeerTerminalTunnel, error) {
	if config.Issuer == "" || config.Store.Path == "" || config.Store.Secrets == nil || config.Auth == nil || config.TLS == nil {
		return nil, ErrPeerTerminalInvalid
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.Race.ConnectTimeout == 0 {
		// Direct ICE/QUIC reaches authenticated readiness in under a second on
		// the supported path. Give its final publication/health handoff a
		// bounded margin before preferring relay.
		config.Race = connectionmanager.Config{RelayDelay: time.Second, WSSDelay: time.Second, ConnectTimeout: 20 * time.Second}
	}
	if config.Mode == 0 {
		config.Mode = connectionmanager.ModeAuto
	}
	if config.Mode < connectionmanager.ModeAuto || config.Mode > connectionmanager.ModeRelayRace {
		return nil, ErrPeerTerminalInvalid
	}
	if err := config.Race.Validate(); err != nil {
		return nil, ErrPeerTerminalInvalid
	}
	pmtu, err := networkadaptation.NewPMTUCache(networkadaptation.DevelopmentPMTUPolicy())
	if err != nil {
		return nil, err
	}
	relayPMTU, err := networkadaptation.NewAsyncPMTU(networkadaptation.AsyncPMTUConfig{Policy: networkadaptation.DevelopmentPMTUPolicy(), Cache: pmtu, Now: config.Now})
	if err != nil {
		return nil, err
	}
	lifetime, err := networkadaptation.NewLifetimeCache(networkadaptation.DevelopmentLifetimePolicy(), nil)
	if err != nil {
		return nil, err
	}
	result := &PeerTerminalTunnel{config: config, pmtu: pmtu, relayPMTU: relayPMTU, lifetime: lifetime, networkChecks: make(map[networkadaptation.Fingerprint]networkcheck.STUNObservation), ipv6Viable: make(map[networkadaptation.Fingerprint]bool), ipv6Known: make(map[networkadaptation.Fingerprint]bool), ipv6Active: make(map[networkadaptation.Fingerprint]bool), regionalCache: networkcheck.NewRegionalCache(), authorities: clientauthority.NewCache(), signalingSubstrate: &signaling.SubstrateManager{}}
	if _, err := rand.Read(result.operationSeed[:]); err != nil {
		return nil, err
	}
	result.network.Store(1)
	return result, nil
}

// Start establishes the daemon-owned network substrate. It is intentionally
// independent of any machine session; machine carriers are still created only
// while an application has an active lease.
func (t *PeerTerminalTunnel) Start(ctx context.Context) error {
	if t == nil || ctx == nil {
		return ErrPeerTerminalInvalid
	}
	t.networkMu.Lock()
	if t.sharedMonitor != nil {
		t.networkMu.Unlock()
		return nil
	}
	t.networkMu.Unlock()
	secret, err := t.config.Store.NetworkFingerprintSecret()
	if err != nil {
		return err
	}
	defer clear(secret)
	monitor, err := networkmonitor.NewFingerprinting(secret, nil, func(event networkmonitor.Event) {
		if !event.Rebind {
			return
		}
		t.networkMu.Lock()
		t.sharedFingerprint, t.sharedFingerprintOK = event.Fingerprint, event.FingerprintValid && event.Fingerprint.Valid()
		t.networkMu.Unlock()
		if !t.observeNetworkFingerprint(event.Fingerprint, event.FingerprintValid) {
			return
		}
		t.advanceNetwork()
		if t.relayPMTU != nil {
			t.relayPMTU.Invalidate()
		}
		if t.config.TransportManager != nil {
			t.config.TransportManager.NetworkChanged()
		}
		t.regionalMu.Lock()
		regional := t.sharedRegional
		t.regionalMu.Unlock()
		if regional != nil {
			regional.NetworkChanged()
		}
	})
	if err != nil {
		return err
	}
	if err := monitor.Start(); err != nil {
		_ = monitor.Close()
		return err
	}
	_, err = monitor.NewPortMappingManager(networkmonitor.PortMappingConfig{
		SocketVerifier: networkcheck.MappingVerifier{Resolver: net.DefaultResolver, Timeout: 500 * time.Millisecond},
		ProbeTimeout:   500 * time.Millisecond, CreateTimeout: 3 * time.Second, EnableUPnP: true,
	})
	if err != nil {
		_ = monitor.Close()
		return err
	}
	fingerprint, fingerprintErr := monitor.CurrentFingerprint()
	t.networkMu.Lock()
	if t.sharedMonitor != nil {
		t.networkMu.Unlock()
		_ = monitor.Close()
		return nil
	}
	t.sharedMonitor, t.sharedFingerprint, t.sharedFingerprintOK = monitor, fingerprint, fingerprintErr == nil && fingerprint.Valid()
	t.networkMu.Unlock()
	t.observeNetworkFingerprint(fingerprint, fingerprintErr == nil && fingerprint.Valid())
	credential, err := t.config.Auth.Credential()
	if err != nil {
		_ = t.Close()
		return err
	}
	client := api.New(t.config.Issuer, credential, t.config.HTTPClient)
	regionsDocument, err := client.NetworkCheckRegions(ctx)
	if err != nil || len(regionsDocument.Regions) == 0 {
		_ = t.Close()
		return errors.Join(ErrPeerTerminalInvalid, err)
	}
	var warmWait sync.WaitGroup
	var warmMu sync.Mutex
	var warmErr error
	for _, region := range regionsDocument.Regions[:min(len(regionsDocument.Regions), 16)] {
		signalingURL, urlErr := signalingURLFromProbe(region.HTTPSURL)
		if urlErr != nil {
			_ = t.Close()
			return urlErr
		}
		warmWait.Add(1)
		go func() {
			defer warmWait.Done()
			warmCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			if currentErr := t.signalingSubstrate.Warm(warmCtx, signalingURL, t.config.TLS); currentErr != nil {
				warmMu.Lock()
				warmErr = errors.Join(warmErr, currentErr)
				warmMu.Unlock()
			}
		}()
	}
	warmWait.Wait()
	if warmErr != nil {
		_ = t.Close()
		return warmErr
	}
	regional, err := t.regionalLatencyMonitor(client, func() string {
		t.relaySuccessMu.RLock()
		defer t.relaySuccessMu.RUnlock()
		return t.relaySuccessRegion
	})
	if err != nil {
		_ = t.Close()
		return err
	}
	// Readiness includes control-plane TLS, relay discovery, and reachability.
	// This scan does not create a machine data carrier.
	_ = regional.Scan(ctx, true)
	t.regionalMu.Lock()
	t.sharedRegional = regional
	t.regionalMu.Unlock()
	go func() { _ = regional.RunAfterInitialScan(ctx) }()
	return nil
}

// WarmMachines fills reusable endpoint authority metadata from the daemon's
// authoritative inventory. It never creates an attempt or a data carrier.
func (t *PeerTerminalTunnel) WarmMachines(ctx context.Context, machines []api.UserMachine) error {
	if t == nil || ctx == nil {
		return ErrPeerTerminalInvalid
	}
	credential, err := t.config.Auth.Credential()
	if err != nil {
		return err
	}
	profile, err := t.config.Store.Load(t.config.Issuer)
	if err != nil {
		return err
	}
	client := api.New(t.config.Issuer, credential, t.config.HTTPClient)
	warmCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	const maximumConcurrentAuthorityLookups = 8
	semaphore := make(chan struct{}, maximumConcurrentAuthorityLookups)
	var wait sync.WaitGroup
	var result error
	var resultMu sync.Mutex
	for _, machine := range machines {
		if !machine.Online || machine.InstallationGeneration <= 0 || machine.State == "revoked" || machine.State == "deleted" {
			continue
		}
		machine := machine
		wait.Add(1)
		go func() {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-warmCtx.Done():
				return
			}
			authority, resolveErr := t.authorities.Resolve(warmCtx, clientauthority.Request{Store: t.config.Store, Client: client, Issuer: t.config.Issuer, AccountID: profile.Account.ID, CLIClientSessionID: profile.CLIClientSessionID, MachineID: machine.ID, MachineGeneration: uint64(machine.InstallationGeneration), Now: t.config.Now().UTC()})
			if resolveErr == nil {
				authority.Clear()
				return
			}
			resultMu.Lock()
			result = errors.Join(result, resolveErr)
			resultMu.Unlock()
		}()
	}
	wait.Wait()
	if result == nil && warmCtx.Err() != nil {
		return warmCtx.Err()
	}
	return result
}

// Close releases only the daemon-wide substrate. Active machine leases remain
// owned by the transport manager and are closed by the daemon owner.
func (t *PeerTerminalTunnel) Close() error {
	if t == nil {
		return nil
	}
	t.networkMu.Lock()
	monitor := t.sharedMonitor
	t.sharedMonitor = nil
	t.networkMu.Unlock()
	t.regionalMu.Lock()
	t.sharedRegional = nil
	t.regionalMu.Unlock()
	if monitor != nil {
		err := errors.Join(monitor.Close(), t.signalingSubstrate.Close())
		if t.authorities != nil {
			t.authorities.Close()
		}
		return err
	}
	if t.authorities != nil {
		t.authorities.Close()
	}
	return t.signalingSubstrate.Close()
}

// InvalidateMachine clears only cached authority metadata for one machine.
// Carrier invalidation remains owned by transportmanager.
func (t *PeerTerminalTunnel) InvalidateMachine(machineID string) {
	if t == nil || machineID == "" {
		return
	}
	if t.authorities != nil {
		t.authorities.InvalidateMachine(machineID)
	}
}

func (t *PeerTerminalTunnel) Dial(ctx context.Context, info resolver.ConnectInfo) (Conn, error) {
	return t.dial(ctx, info, "terminal", peerApplication{helper: func(attachCtx context.Context, message helperMessageConnection, target *resolver.TerminalTarget) (Conn, error) {
		return newInitializedHelperTerminalConn(attachCtx, message, target, t.outputQueueChunks())
	}}, nil)
}

type peerTransferKeyDelivery struct {
	binding  transfercrypto.KeyControlBinding
	material transfercrypto.KeyMaterial
	vault    *transfercrypto.KeyVault
	mu       sync.Mutex
	context  peercontext.Context
}

func (d *peerTransferKeyDelivery) exchange(stream io.ReadWriter, context peercontext.Context) error {
	if d == nil || context.OperationID == "" || context.Consumer != "file_transfer_key" {
		return ErrPeerTerminalInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	binding := d.binding
	// The file transfer binding identifies the encrypted transfer, while the
	// peer descriptor has a fresh idempotency operation for each attempt. The
	// authenticated descriptor context is authoritative for the control frame;
	// reusing the transfer operation ID would make fallback attempts conflict
	// at the server.
	binding.OperationID = context.OperationID
	var err error
	if d.vault != nil {
		err = transfercrypto.ReceiveKey(stream, binding, context, d.vault)
	} else {
		err = transfercrypto.DeliverKey(stream, binding, d.material)
	}
	if err != nil {
		return err
	}
	// Path-scoped candidates have distinct authenticated contexts. Bind the
	// manifest to the candidate that actually completed the key exchange, not
	// whichever descriptor happened to finish acquisition last.
	d.context = context
	return nil
}

func (d *peerTransferKeyDelivery) exchangedContext() (peercontext.Context, error) {
	if d == nil {
		return peercontext.Context{}, ErrPeerTerminalInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.context.MarshalBinary(); err != nil {
		return peercontext.Context{}, ErrPeerTerminalInvalid
	}
	return d.context, nil
}

type completedPeerConn struct{}

func (completedPeerConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (completedPeerConn) Write([]byte) (int, error)   { return 0, net.ErrClosed }
func (completedPeerConn) Close() error                { return nil }
func (completedPeerConn) Resize(uint16, uint16) error { return net.ErrClosed }
func (completedPeerConn) Wait() (int, error)          { return 0, nil }

func (t *PeerTerminalTunnel) DeliverTransferKey(ctx context.Context, info resolver.ConnectInfo, binding transfercrypto.KeyControlBinding, material transfercrypto.KeyMaterial) (peercontext.Context, error) {
	peerContext, direct, err := t.PrepareTransferKey(ctx, info, binding, material)
	if closer, ok := direct.(io.Closer); ok {
		err = errors.Join(err, closer.Close())
	}
	return peerContext, err
}

// ReceiveTransferKey opens the same bounded file_transfer_key control attempt as
// delivery, but receives host-owned key material into the initiating endpoint's vault.
func (t *PeerTerminalTunnel) ReceiveTransferKey(ctx context.Context, info resolver.ConnectInfo, binding transfercrypto.KeyControlBinding, vault *transfercrypto.KeyVault) (peercontext.Context, error) {
	peerContext, direct, err := t.PrepareReceiveTransferKey(ctx, info, binding, vault)
	if closer, ok := direct.(io.Closer); ok {
		err = errors.Join(err, closer.Close())
	}
	return peerContext, err
}

func (t *PeerTerminalTunnel) PrepareReceiveTransferKey(ctx context.Context, info resolver.ConnectInfo, binding transfercrypto.KeyControlBinding, vault *transfercrypto.KeyVault) (peercontext.Context, http.RoundTripper, error) {
	delivery := &peerTransferKeyDelivery{binding: binding, vault: vault}
	connection, err := t.dial(ctx, info, "file_transfer_key", peerApplication{}, delivery)
	if err != nil {
		return peercontext.Context{}, nil, err
	}
	peerContext, err := delivery.exchangedContext()
	if err != nil {
		return peercontext.Context{}, nil, errors.Join(err, connection.Close())
	}
	owned, ownedOK := connection.(*ownedPeerTerminalConn)
	direct, directOK := func() (*directTransferPeerConn, bool) {
		if !ownedOK {
			return nil, false
		}
		value, ok := owned.Conn.(*directTransferPeerConn)
		return value, ok
	}()
	if !directOK {
		if err := connection.Close(); err != nil {
			return peercontext.Context{}, nil, err
		}
		// Relay QUIC/WSS authenticates and delivers the E2EE key only. A nil
		// transport explicitly selects the qualified H3/H2 origin data path.
		return peerContext, nil, nil
	}
	transport, err := newDirectTransferRoundTripper(owned, direct)
	if err != nil {
		return peercontext.Context{}, nil, errors.Join(err, connection.Close())
	}
	return peerContext, transport, nil
}

func (t *PeerTerminalTunnel) PrepareTransferKey(ctx context.Context, info resolver.ConnectInfo, binding transfercrypto.KeyControlBinding, material transfercrypto.KeyMaterial) (peercontext.Context, http.RoundTripper, error) {
	delivery := &peerTransferKeyDelivery{binding: binding, material: material}
	connection, err := t.dial(ctx, info, "file_transfer_key", peerApplication{}, delivery)
	if err != nil {
		return peercontext.Context{}, nil, err
	}
	peerContext, err := delivery.exchangedContext()
	if err != nil {
		return peercontext.Context{}, nil, errors.Join(err, connection.Close())
	}
	owned, ownedOK := connection.(*ownedPeerTerminalConn)
	direct, directOK := func() (*directTransferPeerConn, bool) {
		if !ownedOK {
			return nil, false
		}
		value, ok := owned.Conn.(*directTransferPeerConn)
		return value, ok
	}()
	if !directOK {
		if err := connection.Close(); err != nil {
			return peercontext.Context{}, nil, err
		}
		// Relay QUIC/WSS authenticates and delivers the E2EE key only. A nil
		// transport explicitly selects the qualified H3/H2 origin data path.
		return peerContext, nil, nil
	}
	transport, err := newDirectTransferRoundTripper(owned, direct)
	if err != nil {
		return peercontext.Context{}, nil, errors.Join(err, connection.Close())
	}
	return peerContext, transport, nil
}

type directTransferPeerConn struct{ group *peerQUICNativeStreamGroup }

func (*directTransferPeerConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (*directTransferPeerConn) Write([]byte) (int, error)   { return 0, net.ErrClosed }
func (c *directTransferPeerConn) Close() error              { return c.group.Close() }
func (*directTransferPeerConn) Resize(uint16, uint16) error { return net.ErrClosed }
func (*directTransferPeerConn) Wait() (int, error)          { return 0, nil }

type directTransferRoundTripper struct {
	owner     Conn
	direct    *directTransferPeerConn
	transport *http.Transport
	once      sync.Once
	err       error
}

// DirectTransferStreamOpener exposes only the stream capability retained by
// the daemon. It does not expose the underlying peer session or credentials.
type DirectTransferStreamOpener interface {
	OpenTransferStream(context.Context) (net.Conn, error)
}

func newDirectTransferRoundTripper(owner Conn, direct *directTransferPeerConn) (*directTransferRoundTripper, error) {
	if owner == nil || direct == nil || direct.group == nil {
		return nil, ErrPeerTerminalInvalid
	}
	roundTripper := &directTransferRoundTripper{owner: owner, direct: direct}
	roundTripper.transport = &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     false,
		MaxConnsPerHost:       2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		DialTLSContext:        roundTripper.dial,
	}
	return roundTripper, nil
}

func (t *directTransferRoundTripper) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	stream, err := t.direct.group.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	bound, ok := stream.(interface{ WriteFirst([]byte) error })
	if !ok {
		return nil, errors.Join(ErrPeerTerminalInvalid, stream.Close())
	}
	if err := bound.WriteFirst(nil); err != nil {
		return nil, errors.Join(err, stream.Close())
	}
	deadline, ok := stream.(interface {
		SetDeadline(time.Time) error
		SetReadDeadline(time.Time) error
	})
	if !ok {
		return nil, errors.Join(ErrPeerTerminalInvalid, stream.Close())
	}
	return &directTransferStreamConn{nativeStream: stream, deadline: deadline}, nil
}

func (t *directTransferRoundTripper) OpenTransferStream(ctx context.Context) (net.Conn, error) {
	if t == nil {
		return nil, ErrPeerTerminalInvalid
	}
	return t.dial(ctx, "", "")
}

func (t *directTransferRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(request)
}

func (t *directTransferRoundTripper) CloseIdleConnections() { t.transport.CloseIdleConnections() }

func (t *directTransferRoundTripper) Close() error {
	t.once.Do(func() {
		t.transport.CloseIdleConnections()
		t.err = t.owner.Close()
	})
	return t.err
}

type directTransferStreamConn struct {
	nativeStream
	deadline interface {
		SetDeadline(time.Time) error
		SetReadDeadline(time.Time) error
	}
}

func (*directTransferStreamConn) LocalAddr() net.Addr  { return transferPeerAddr("client") }
func (*directTransferStreamConn) RemoteAddr() net.Addr { return transferPeerAddr("machine") }
func (c *directTransferStreamConn) SetDeadline(value time.Time) error {
	return c.deadline.SetDeadline(value)
}
func (c *directTransferStreamConn) SetReadDeadline(value time.Time) error {
	return c.deadline.SetReadDeadline(value)
}

type transferPeerAddr string

func (transferPeerAddr) Network() string  { return "paperboat-peer-quic" }
func (a transferPeerAddr) String() string { return string(a) }

type peerApplicationFactory func(context.Context, helperMessageConnection, *resolver.TerminalTarget) (Conn, error)

type peerRawApplicationFactory func(context.Context, io.ReadWriteCloser) (Conn, error)

type peerApplication struct {
	helper      peerApplicationFactory
	raw         peerRawApplicationFactory
	quic        func(context.Context, *http3.ClientConn, func() error) (Conn, error)
	stream      string
	health      bool
	operationID string
	consumer    string
}

func (a peerApplication) authorizationHeader(target *resolver.TerminalTarget, consumer, fallbackOperation, streamID string, now time.Time) (streamauth.Header, error) {
	if target == nil || target.Auth.Token == "" {
		return streamauth.Header{}, ErrPeerTerminalInvalid
	}
	operationID := a.operationID
	if operationID == "" {
		operationID = fallbackOperation
	}
	deadline, err := time.Parse(time.RFC3339, target.Auth.ExpiresAt)
	if err != nil || !deadline.After(now) {
		return streamauth.Header{}, ErrPeerTerminalInvalid
	}
	header, err := streamauth.New(operationID, consumer, streamID, target.Auth.Token, deadline, 1<<40)
	if err == nil {
		header.Resumable = true
	}
	return header, err
}

type PingResult struct {
	Path        connectionmanager.Path
	RelayRegion string
	Connection  time.Duration
	RTT         time.Duration
	PTOs        uint32
}

type PathReachability struct {
	Reachable   bool
	RTT         time.Duration
	PTOs        uint32
	RelayRegion string
}

const (
	cachedPeerAcquireTimeout    = 2 * time.Second
	cachedPeerAttachmentTimeout = 8 * time.Second
)

// ProbePathReachability performs independent authenticated attempts. It is
// intentionally separate from the production race: a failed path must not
// cancel or be hidden by another path's success.
func (t *PeerTerminalTunnel) ProbePathReachability(ctx context.Context, info resolver.ConnectInfo) map[connectionmanager.Path]PathReachability {
	result := make(map[connectionmanager.Path]PathReachability, 3)
	if t == nil || ctx == nil {
		return result
	}
	paths := []struct {
		path connectionmanager.Path
		mode connectionmanager.Mode
	}{
		{connectionmanager.PathDirectQUIC, connectionmanager.ModeDirectQUIC},
		{connectionmanager.PathRelayQUIC, connectionmanager.ModeRelayQUIC},
		{connectionmanager.PathWSS, connectionmanager.ModeWSS},
	}
	type outcome struct {
		path  connectionmanager.Path
		value PathReachability
	}
	outcomes := make(chan outcome, len(paths))
	for _, item := range paths {
		go func(item struct {
			path connectionmanager.Path
			mode connectionmanager.Mode
		}) {
			probe, err := NewPeerTerminalTunnel(PeerTerminalConfig{Issuer: t.config.Issuer, Store: t.config.Store, Auth: t.config.Auth, TLS: t.config.TLS, HTTPClient: t.config.HTTPClient, Race: t.config.Race, Mode: item.mode, Now: t.config.Now})
			if err != nil {
				outcomes <- outcome{path: item.path}
				return
			}
			ping, pingErr := probe.PingOnce(ctx, info)
			value := PathReachability{}
			if pingErr == nil && ping.Path == item.path {
				value = PathReachability{Reachable: true, RTT: ping.RTT, PTOs: ping.PTOs, RelayRegion: ping.RelayRegion}
			}
			outcomes <- outcome{path: item.path, value: value}
		}(item)
	}
	for range paths {
		item := <-outcomes
		result[item.path] = item.value
	}
	return result
}

func (t *PeerTerminalTunnel) PingOnce(ctx context.Context, info resolver.ConnectInfo) (PingResult, error) {
	connectionStarted := time.Now()
	connection, err := t.dial(ctx, info, "health_probe", peerApplication{health: true}, nil)
	if err != nil {
		return PingResult{}, err
	}
	owned, ok := connection.(*ownedPeerTerminalConn)
	if !ok || owned.health == nil {
		_ = connection.Close()
		return PingResult{}, ErrPeerTerminalInvalid
	}
	connectionDuration := time.Since(connectionStarted)
	defer connection.Close()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return PingResult{}, err
	}
	started := time.Now()
	ptos, err := owned.health.HealthExchange(ctx, nonce)
	if err != nil {
		return PingResult{}, err
	}
	return PingResult{Path: owned.path, RelayRegion: owned.health.RelayRegion(), Connection: connectionDuration, RTT: time.Since(started), PTOs: ptos}, nil
}

// PingTransport runs one authenticated production-path probe without allowing
// another transport policy to hide the requested policy's result.
func (t *PeerTerminalTunnel) PingTransport(ctx context.Context, info resolver.ConnectInfo, transport string) (PingResult, error) {
	if _, ok := peerModeForPath(transport); !ok {
		return PingResult{}, ErrPeerTerminalInvalid
	}
	info.Transport = transport
	if info.Terminal != nil && info.Terminal.Auth.Token == "" && t.config.Auth != nil {
		credential, err := t.config.Auth.Credential()
		if err != nil {
			return PingResult{}, err
		}
		info.Terminal.Auth.Token = credential.AccessToken
		info.Terminal.Auth.ExpiresAt = credential.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return t.PingOnce(ctx, info)
}

func (t *PeerTerminalTunnel) dial(ctx context.Context, info resolver.ConnectInfo, consumer string, application peerApplication, keyDelivery *peerTransferKeyDelivery) (Conn, error) {
	started := time.Now()
	timing := map[string]int64{}
	mark := func(stage string) { timing[stage] = time.Since(started).Milliseconds() }
	defer func() {
		diagnosticlog.TryInfo("peer application dial timing", "machine_id", info.ProjectID, "consumer", consumer, "milestones_ms", timing, "elapsed_ms", time.Since(started).Milliseconds())
	}()
	if t == nil || ctx == nil || info.TargetKind != "machine" && info.TargetKind != "project" || info.ProjectID == "" || info.MachineGeneration == 0 || info.Terminal == nil || info.Terminal.EnvironmentID == "" {
		return nil, ErrPeerTerminalInvalid
	}
	applicationCount := 0
	if application.helper != nil {
		applicationCount++
	}
	if application.raw != nil {
		applicationCount++
	}
	if application.quic != nil {
		applicationCount++
	}
	if application.health {
		applicationCount++
	}
	if keyDelivery != nil {
		applicationCount++
	}
	if consumer == "" || applicationCount != 1 || application.raw != nil && application.stream == "" || application.raw == nil && application.stream != "" || application.quic != nil && application.stream != "" {
		return nil, ErrPeerTerminalInvalid
	}
	mode, transportClass, ok := peerApplicationMode(t.config.Mode, info.Transport, consumer)
	if !ok {
		return nil, ErrPeerTerminalInvalid
	}
	application.consumer = consumer
	operationScope := t.operation.Add(1)
	if operationScope == 0 || operationScope > math.MaxInt64 {
		return nil, ErrPeerTerminalInvalid
	}
	dialCtx, cancel := context.WithCancel(ctx)
	ownerCtx := dialCtx
	ownerCancel := func() {}
	sharedTransport := t.config.TransportManager != nil && keyDelivery == nil && !application.health
	managerKey := fmt.Sprintf("%s:%d:interactive:%d", info.ProjectID, info.MachineGeneration, mode)
	if sharedTransport {
		ownerCtx, ownerCancel = context.WithCancel(context.Background())
		cachedAcquireCtx, cancelCachedAcquire := context.WithTimeout(dialCtx, cachedPeerAcquireTimeout)
		managedLease, cachedErr := t.config.TransportManager.AcquireCached(cachedAcquireCtx, managerKey, transportClass, mode, connectionmanager.NetworkUnknown)
		cancelCachedAcquire()
		if cachedErr == nil {
			attachCached := func(lease *transportmanager.Lease) (Conn, connectionmanager.State, error) {
				candidate, ok := lease.Connection().(*terminalPathCandidate)
				if !ok {
					return nil, connectionmanager.StateFailed, ErrPeerTerminalInvalid
				}
				configureCandidatePromotion(candidate, lease.Pool())
				state := candidate.State()
				attachCtx, cancelAttach := context.WithTimeout(dialCtx, cachedPeerAttachmentTimeout)
				attached, attachErr := candidate.Attach(attachCtx, terminalAttachment{target: info.Terminal, application: application})
				cancelAttach()
				return attached, state, attachErr
			}
			attachStarted := time.Now()
			attached, cachedState, attachErr := attachCached(managedLease)
			diagnosticlog.TryInfo("peer cached attachment timing", "machine_id", info.ProjectID, "consumer", consumer, "path", managedLease.Path(), "elapsed_ms", time.Since(attachStarted).Milliseconds(), "error", attachErr)
			if attachErr != nil {
				diagnosticlog.TryInfo("peer cached attachment failed", "machine_id", info.ProjectID, "consumer", consumer, "path", managedLease.Path(), "error", attachErr)
				// An application-open failure is definitive evidence that the
				// cached carrier is unusable, even if health has not observed the
				// close yet. Force retirement and reacquire before reporting it.
				if errors.Is(attachErr, ErrPeerStreamOpen) {
					cachedState = connectionmanager.StateFailed
				}
				// Retire while the manager lease still owns the pool. Releasing the
				// final manager reference first closes the whole machine session,
				// including an authenticated relay standby that could serve this
				// consumer without rebuilding authority.
				pool := managedLease.Pool()
				retired := pool != nil && pool.Retire(transportClass, managedLease.Connection())
				if cachedAttachmentPreservesCarrier(cachedState, attachErr) {
					managedLease.Release()
					cancel()
					ownerCancel()
					return nil, attachErr
				}
				if retired {
					promotionCtx, cancelPromotion := context.WithTimeout(dialCtx, cachedPeerAcquireTimeout)
					retryLease, retryErr := t.config.TransportManager.AcquireCached(promotionCtx, managerKey, transportClass, mode, connectionmanager.NetworkUnknown)
					cancelPromotion()
					// Keep the manager entry alive until the replacement lease has
					// reserved the promoted standby; otherwise releasing the failed
					// lease would close the pool before AcquireCached can use it.
					managedLease.Release()
					if retryErr == nil {
						retryStarted := time.Now()
						attached, retryState, retryErr := attachCached(retryLease)
						diagnosticlog.TryInfo("peer promoted attachment timing", "machine_id", info.ProjectID, "consumer", consumer, "path", retryLease.Path(), "elapsed_ms", time.Since(retryStarted).Milliseconds(), "error", retryErr)
						if retryErr == nil {
							ownerCancel()
							return ownPeerConnection(&ownedPeerTerminalConn{Conn: attached, cancel: cancel, lease: retryLease, path: retryLease.Path()}), nil
						}
						retryLease.Release()
						if cachedAttachmentPreservesCarrier(retryState, retryErr) {
							cancel()
							ownerCancel()
							return nil, retryErr
						}
					}
				} else {
					managedLease.Release()
				}
				ownerCtx, ownerCancel = context.WithCancel(context.Background())
				cachedErr = transportmanager.ErrUnavailable
			} else {
				ownerCancel()
				return ownPeerConnection(&ownedPeerTerminalConn{Conn: attached, cancel: cancel, lease: managedLease, path: managedLease.Path()}), nil
			}
		}
		if !errors.Is(cachedErr, transportmanager.ErrUnavailable) {
			diagnosticlog.TryInfo("peer cached acquisition failed; rebuilding machine session", "machine_id", info.ProjectID, "consumer", consumer, "error", cachedErr)
		}
	}
	monitor, fingerprint, networkEvents, sharedNetwork := t.networkOwner()
	mark("network_ready")
	cleanup := true
	defer func() {
		if cleanup {
			cancel()
			ownerCancel()
			if monitor != nil && !sharedNetwork {
				_ = monitor.Close()
			}
		}
	}()
	credential, err := t.config.Auth.Credential()
	if err != nil {
		return nil, err
	}
	mark("credential_ready")
	profile, err := t.config.Store.Load(t.config.Issuer)
	if err != nil {
		return nil, err
	}
	client := api.New(t.config.Issuer, credential, t.config.HTTPClient)
	attempts := &peerAttemptTracker{client: client, refresh: func() *api.Client {
		fresh, refreshErr := t.config.Auth.Credential()
		if refreshErr != nil || strings.TrimSpace(fresh.AccessToken) == "" {
			return nil
		}
		return api.New(t.config.Issuer, fresh, t.config.HTTPClient)
	}, attempts: make(map[string]directpath.AttemptDescriptor)}
	mark("profile_ready")
	var pool *connectionmanager.Pool
	regionalMonitor, _ := t.regionalLatencyMonitor(client, func() string {
		if pool == nil {
			return ""
		}
		snapshot, snapshotErr := pool.Snapshot(transportClass)
		if snapshotErr != nil || !snapshot.Selected {
			return ""
		}
		return snapshot.RelayRegion
	})
	authority, err := t.authorities.Resolve(dialCtx, clientauthority.Request{Store: t.config.Store, Client: client, Issuer: t.config.Issuer, AccountID: profile.Account.ID, CLIClientSessionID: profile.CLIClientSessionID, MachineID: info.ProjectID, MachineGeneration: info.MachineGeneration, Now: t.config.Now().UTC()})
	if err != nil {
		if dialCtx.Err() != nil {
			return nil, dialCtx.Err()
		}
		if retryablePeerAPIError(err) {
			return nil, &terminalTransportError{transport: "peer authority", cause: err}
		}
		return nil, err
	}
	mark("authority_ready")
	authorityOwned := false
	defer func() {
		if !authorityOwned {
			authority.Clear()
		}
	}()
	localFingerprint := sha256.Sum256(authority.LocalCertificateRaw)
	peerFingerprint := sha256.Sum256(authority.MachineCertificateRaw)
	purpose, descriptorConsumer := peerDescriptorScope(consumer, application, keyDelivery != nil)
	var transfer *api.PeerAttemptTransfer
	if keyDelivery != nil {
		transfer = &api.PeerAttemptTransfer{TransferID: keyDelivery.binding.TransferID, Generation: keyDelivery.binding.Generation, ExpiresAt: keyDelivery.binding.ExpiresAt}
	}
	sourceConfig := directpath.APIDescriptorSourceConfig{Client: client, EnvironmentID: info.Terminal.EnvironmentID, Purpose: purpose, Consumer: descriptorConsumer, Transfer: transfer, AccountID: profile.Account.ID, TrustedKeys: authority.TrustedKeys, ControllingEndpointID: profile.CLIClientSessionID, ControlledEndpointID: info.ProjectID, ControllingCertificateFingerprint: hex.EncodeToString(localFingerprint[:]), ControlledCertificateFingerprint: hex.EncodeToString(peerFingerprint[:]), OperationID: func(generation directpath.Generation) string {
		return peerOperationID(profile.CLIClientSessionID, info.ProjectID, purpose, t.operationSeed, operationScope, generation)
	}}
	sourceConfig.AllowedPaths = peerAllowedPaths(mode)
	sourceConfig.RelayLatency = func() *api.RelayLatencyVector { return t.relayLatencyVector() }
	sourceConfig.OnAcquire = attempts.Track
	descriptors, err := directpath.NewAPIDescriptorSource(sourceConfig)
	if err != nil {
		return nil, err
	}
	mark("descriptor_source_ready")
	var oneShotDescriptors map[connectionmanager.Path]*directpath.APIDescriptorSource
	if oneShotPeerOperation(application, keyDelivery) && (mode == connectionmanager.ModeAuto || mode == connectionmanager.ModeRelayRace) {
		oneShotDescriptors = make(map[connectionmanager.Path]*directpath.APIDescriptorSource, 3)
		for _, path := range oneShotDescriptorPaths(mode) {
			allowedPaths, ok := peerDescriptorAllowedPaths(path)
			if !ok {
				return nil, ErrPeerTerminalInvalid
			}
			candidateConfig := sourceConfig
			candidateConfig.AllowedPaths = allowedPaths
			oneShotDescriptors[path], err = directpath.NewAPIDescriptorSource(candidateConfig)
			if err != nil {
				return nil, err
			}
		}
	}
	var probes *directpath.APIDescriptorSource
	var directRecovery, relayRecovery, wssRecovery *directpath.APIDescriptorSource
	if keyDelivery == nil && !application.health {
		sourceConfig.Purpose = "direct_probe"
		sourceConfig.Consumer = "terminal"
		sourceConfig.AllowedPaths = []string{"direct_quic"}
		sourceConfig.OperationID = func(generation directpath.Generation) string {
			return peerOperationID(profile.CLIClientSessionID, info.ProjectID, "direct_probe", t.operationSeed, operationScope, generation)
		}
		probes, err = directpath.NewAPIDescriptorSource(sourceConfig)
		if err != nil {
			return nil, err
		}
		recoveryConfig := sourceConfig
		recoveryConfig.Purpose = "peer_transport"
		recoveryConfig.Consumer = "peer_transport"
		recoveryConfig.OperationID = func(generation directpath.Generation) string {
			return peerOperationID(profile.CLIClientSessionID, info.ProjectID, "peer_recovery", t.operationSeed, operationScope, generation)
		}
		recoveryConfig.AllowedPaths = []string{"direct_quic"}
		directRecovery, err = directpath.NewAPIDescriptorSource(recoveryConfig)
		if err != nil {
			return nil, err
		}
		recoveryConfig.AllowedPaths = []string{"relay_quic"}
		relayRecovery, err = directpath.NewAPIDescriptorSource(recoveryConfig)
		if err != nil {
			return nil, err
		}
		recoveryConfig.AllowedPaths = []string{"relay_wss"}
		wssRecovery, err = directpath.NewAPIDescriptorSource(recoveryConfig)
		if err != nil {
			return nil, err
		}
	}
	network := t.network.Load()
	if network == 0 || network > math.MaxInt64 {
		return nil, ErrPeerTerminalInvalid
	}
	quality, err := newTerminalHealthRecorder(fingerprint, info.ProjectID)
	if err != nil {
		return nil, err
	}
	var mapping directpath.SocketMappingSource
	if monitor != nil && !sharedNetwork {
		mapping = observedSocketMapping{source: monitor, record: func(protocol, result string) { t.recordRouterMapping(fingerprint, protocol, result) }}
	}
	connector := &terminalRaceConnector{owner: t, lifetime: ownerCtx, target: info.Terminal, consumer: consumer, application: application, keyDelivery: keyDelivery, descriptors: descriptors, oneShotDescriptors: oneShotDescriptors, probes: probes, directRecovery: directRecovery, relayRecovery: relayRecovery, wssRecovery: wssRecovery, attempts: attempts, clientAuthority: &authority, descriptorCalls: make(map[terminalDescriptorKey]*terminalDescriptorCall), health: quality, mapping: mapping}
	connector.networkGeneration.Store(network)
	raceConfig := peerRaceConfig(t.config.Race, application.health, keyDelivery != nil, mode)
	racer, err := connectionmanager.NewRacer(raceConfig, connector)
	if err != nil {
		return nil, err
	}
	health, err := connectionmanager.NewActiveHealthMonitor(connectionmanager.DevelopmentActiveHealthPolicy(), quality)
	if err != nil {
		return nil, err
	}
	poolConfig := connectionmanager.DevelopmentPoolConfig()
	poolConfig.Health = health
	poolConfig.CloseWhenIdle = true
	// Authenticated preview QUIC is handed to HTTP/3. Paperboat health streams
	// are not valid HTTP/3 streams; HTTP/3 and QUIC own liveness after handoff.
	poolConfig.DisablePreviewActiveHealth = transportClass == peerquic.ClassPreview
	poolConfig.CandidateSource = connector
	pool, err = connectionmanager.NewPool(racer, poolConfig)
	if err != nil {
		return nil, err
	}
	var sharedObserver *localobservation.Publisher
	if sharedTransport && t.config.PublishLocalStatus {
		sharedObserver = newPeerPoolObserver(info.ProjectID, pool, t.config.Now, func() networkcheck.STUNObservation { return t.networkCheck(fingerprint) })
	}
	var supervisor *connectionmanager.RecoverySupervisor
	var probeScheduler *connectionmanager.ProbeScheduler
	if !application.health && keyDelivery == nil && (mode == connectionmanager.ModeAuto || mode == connectionmanager.ModeRelayRace) {
		var probeErr error
		probeRecorder := connectionmanager.HealthSampleRecorder(connectionmanager.DiscardHealthSamples{})
		probeDecider := connectionmanager.ProbePromotionDecider(connectionmanager.VerifiedProbePromotionDecider{})
		probe, probeErr := connectionmanager.NewAuthenticatedHealthProbe(connector, connectionmanager.DevelopmentHealthProbePolicy(), probeRecorder, probeDecider)
		if probeErr != nil {
			_ = pool.Close()
			return nil, probeErr
		}
		probeScheduler, probeErr = connectionmanager.NewProbeScheduler(connectionmanager.DevelopmentProbePolicy(), probe, connectionmanager.PoolProbePromoter{Pool: pool, Class: transportClass})
		if probeErr != nil {
			_ = pool.Close()
			return nil, probeErr
		}
		if mode == connectionmanager.ModeRelayRace {
			if probeErr = probeScheduler.SetPath(connectionmanager.PathRelayQUIC); probeErr != nil {
				_ = pool.Close()
				return nil, probeErr
			}
		}
		supervisor, probeErr = connectionmanager.NewRecoverySupervisor(connectionmanager.RecoverySupervisorConfig{Pool: pool, Interactive: adaptiveRecoveryScheduler{pool: pool, scheduler: probeScheduler, mode: mode}, Preview: idleRecoveryScheduler{}})
		if probeErr != nil {
			_ = pool.Close()
			return nil, probeErr
		}
		if probeErr = supervisor.Start(ownerCtx); probeErr != nil {
			_ = pool.Close()
			return nil, probeErr
		}
	}
	if regionalMonitor != nil {
		go func() {
			_ = regionalMonitor.Scan(ownerCtx, true)
			_ = regionalMonitor.RunAfterInitialScan(ownerCtx)
		}()
	}
	var lease interface{ Release() }
	var leaseConnection connectionmanager.Connection
	var leasePath connectionmanager.Path
	factoryUsed := false
	if sharedTransport {
		mark("machine_session_acquire_started")
		managedLease, acquireErr := t.config.TransportManager.AcquireOwned(dialCtx, managerKey, transportClass, mode, connectionmanager.NetworkUnknown, func(context.Context) (*connectionmanager.Pool, func() error, error) {
			factoryUsed = true
			return pool, func() error {
				ownerCancel()
				var cleanupErr error
				if supervisor != nil {
					shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
					cleanupErr = errors.Join(cleanupErr, supervisor.Shutdown(shutdownCtx))
					shutdownCancel()
				}
				if monitor != nil && !sharedNetwork {
					cleanupErr = errors.Join(cleanupErr, monitor.Close())
				}
				if sharedObserver != nil {
					observationCtx, cancelObservation := context.WithTimeout(context.Background(), time.Second)
					cleanupErr = errors.Join(cleanupErr, sharedObserver.Close(observationCtx))
					cancelObservation()
				}
				authority.Clear()
				cleanupErr = errors.Join(cleanupErr, attempts.Revoke())
				return cleanupErr
			}, nil
		})
		if acquireErr != nil {
			acquireErr = fmt.Errorf("machine session acquisition failed (caller_context=%v owner_context=%v): %w", dialCtx.Err(), ownerCtx.Err(), acquireErr)
			if factoryUsed {
				// AcquireOwned already releases and closes a failed creator entry.
				// Invalidating by key here can race a concurrent caller that has
				// installed the next healthy generation under the same key.
				cleanup = false
				authorityOwned = true
			} else {
				_ = pool.Close()
				ownerCancel()
				_ = attempts.Revoke()
			}
			return nil, acquireErr
		}
		if !factoryUsed {
			sharedObserver = nil
			_ = pool.Close()
			ownerCancel()
			if supervisor != nil {
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
				_ = supervisor.Shutdown(shutdownCtx)
				shutdownCancel()
			}
			if monitor != nil && !sharedNetwork {
				_ = monitor.Close()
				monitor = nil
			}
			authority.Clear()
		}
		if factoryUsed && sharedObserver != nil {
			go runPeerPoolObserver(ownerCtx, sharedObserver, info.ProjectID, "shared")
		}
		pool = managedLease.Pool()
		lease, leaseConnection, leasePath = managedLease, managedLease.Connection(), managedLease.Path()
		mark("carrier_ready")
		authorityOwned = true
		cleanup = false
	} else {
		localLease, acquireErr := pool.Acquire(dialCtx, transportClass, mode, connectionmanager.NetworkUnknown)
		if acquireErr != nil {
			_ = pool.Close()
			_ = attempts.Revoke()
			return nil, acquireErr
		}
		lease, leaseConnection, leasePath = localLease, localLease.Connection, localLease.Path
		mark("carrier_ready")
	}
	closeFailed := func() {
		closeFailedPeerApplication(sharedTransport, lease, pool)
	}
	if snapshot, snapshotErr := pool.Snapshot(transportClass); snapshotErr == nil && snapshot.Selected && snapshot.RelayRegion != "" {
		t.observeRelaySuccess(snapshot.RelayRegion)
		go t.observeRelayPromotions(ownerCtx, pool, snapshot.Generation, snapshot.RelayRegion)
	}
	if application.health {
		candidate, ok := leaseConnection.(*terminalPathCandidate)
		if !ok {
			lease.Release()
			_ = pool.Close()
			return nil, ErrPeerTerminalInvalid
		}
		cleanup = false
		authorityOwned = true
		return ownPeerConnection(&ownedPeerTerminalConn{Conn: completedPeerConn{}, cancel: cancel, monitor: monitor, fingerprint: fingerprint, lease: lease, path: leasePath, pool: pool, authority: &authority, health: candidate, revoke: attempts.Revoke}), nil
	}
	if keyDelivery != nil {
		candidate, ok := leaseConnection.(*terminalPathCandidate)
		if !ok {
			lease.Release()
			_ = pool.Close()
			return nil, ErrPeerTerminalInvalid
		}
		result, attachErr := candidate.Attach(dialCtx, terminalAttachment{target: info.Terminal, application: application, keyDelivery: keyDelivery})
		if attachErr != nil {
			lease.Release()
			_ = pool.Close()
			return nil, attachErr
		}
		cleanup = false
		authorityOwned = true
		return ownPeerConnection(&ownedPeerTerminalConn{Conn: result, cancel: cancel, monitor: monitor, fingerprint: fingerprint, lease: lease, path: leasePath, pool: pool, authority: &authority, revoke: attempts.Revoke}), nil
	}
	if networkEvents != nil && (!sharedTransport || factoryUsed) {
		go func() {
			for {
				select {
				case event := <-networkEvents:
					connector.networkGeneration.Store(t.network.Load())
					quality.applyNetworkEvent(event)
					if event.Rebind {
						t.relayPMTU.Invalidate()
					}
					probeScheduler.NetworkChanged()
					pool.NetworkChanged()
				case <-ownerCtx.Done():
					return
				}
			}
		}()
	}
	candidate, ok := leaseConnection.(*terminalPathCandidate)
	if !ok {
		closeFailed()
		return nil, ErrPeerTerminalInvalid
	}
	configureCandidatePromotion(candidate, pool)
	attachment := terminalAttachment{target: info.Terminal, application: application}
	attachApplication := func(candidate *terminalPathCandidate) (Conn, error) {
		attachCtx, cancelAttach := context.WithTimeout(dialCtx, cachedPeerAttachmentTimeout)
		attached, attachErr := candidate.Attach(attachCtx, attachment)
		attachTimedOut := errors.Is(attachErr, context.DeadlineExceeded) && dialCtx.Err() == nil
		cancelAttach()
		if attachTimedOut {
			return nil, errors.Join(ErrPeerStreamOpen, attachErr)
		}
		return attached, attachErr
	}
	terminal, err := attachApplication(candidate)
	if retryablePeerAttachment(err) {
		// A carrier can close between pool selection and the first application
		// stream. Retire that entry and give an already-authenticated standby a
		// single opportunity before failing the consumer.
		retired := pool.Retire(peerquic.ClassInteractive, candidate)
		var retry peerReplacementLease
		var retryErr error
		if retired {
			retry, retryErr = acquirePeerReplacementLease(dialCtx, sharedTransport, t.config.TransportManager, managerKey, pool, mode)
		} else {
			retryErr = errors.New("failed peer carrier was not selected for retirement")
		}
		if retryErr == nil {
			retryCandidate, retryOK := retry.connection.(*terminalPathCandidate)
			if retryOK {
				configureCandidatePromotion(retryCandidate, pool)
				terminal, err = attachApplication(retryCandidate)
				if err == nil {
					lease.Release()
					lease = retry.lease
					leasePath = retry.path
					candidate = retryCandidate
				} else {
					retry.lease.Release()
				}
			} else {
				retry.lease.Release()
			}
		}
		if retry.lease == nil || err != nil {
			lease.Release()
		}
	}
	if err != nil {
		diagnosticlog.TryInfo("peer attachment failed", "machine_id", info.ProjectID, "consumer", consumer, "path", leasePath, "error", err)
		closeFailed()
		return nil, err
	}
	mark("application_attached")
	cleanup = false
	authorityOwned = true
	var observer *localobservation.Publisher
	if t.config.PublishLocalStatus && !sharedTransport {
		observer = newPeerPoolObserver(info.ProjectID, pool, t.config.Now, func() networkcheck.STUNObservation { return t.networkCheck(fingerprint) })
	}
	if observer != nil {
		go runPeerPoolObserver(dialCtx, observer, info.ProjectID, "application")
	}
	connectionMonitor, connectionPool, connectionSupervisor, connectionAuthority, connectionRevoke := monitor, pool, supervisor, &authority, attempts.Revoke
	if sharedTransport {
		connectionMonitor, connectionPool, connectionSupervisor, connectionAuthority, connectionRevoke = nil, nil, nil, nil, nil
	}
	return ownPeerConnection(&ownedPeerTerminalConn{Conn: terminal, cancel: cancel, monitor: connectionMonitor, fingerprint: fingerprint, lease: lease, path: leasePath, pool: connectionPool, supervisor: connectionSupervisor, authority: connectionAuthority, observer: observer, revoke: connectionRevoke}), nil
}

func closeFailedPeerApplication(shared bool, lease interface{ Release() }, pool *connectionmanager.Pool) {
	if lease != nil {
		lease.Release()
	}
	if !shared && pool != nil {
		_ = pool.Close()
	}
}

func peerApplicationMode(configured connectionmanager.Mode, requested, consumer string) (connectionmanager.Mode, peerquic.Class, bool) {
	if consumer == "private_preview" {
		return connectionmanager.ModeDirectQUIC, peerquic.ClassPreview, true
	}
	if requested == "" {
		return configured, peerquic.ClassInteractive, true
	}
	mode, ok := peerModeForPath(requested)
	return mode, peerquic.ClassInteractive, ok
}

type peerReplacementLease struct {
	lease      interface{ Release() }
	connection connectionmanager.Connection
	path       connectionmanager.Path
}

func acquirePeerReplacementLease(ctx context.Context, shared bool, manager *transportmanager.Manager, managerKey string, pool *connectionmanager.Pool, mode connectionmanager.Mode) (peerReplacementLease, error) {
	if shared {
		lease, err := manager.AcquireCached(ctx, managerKey, peerquic.ClassInteractive, mode, connectionmanager.NetworkUnknown)
		if err != nil {
			return peerReplacementLease{}, err
		}
		return peerReplacementLease{lease: lease, connection: lease.Connection(), path: lease.Path()}, nil
	}
	lease, err := pool.Acquire(ctx, peerquic.ClassInteractive, mode, connectionmanager.NetworkUnknown)
	if err != nil {
		return peerReplacementLease{}, err
	}
	return peerReplacementLease{lease: lease, connection: lease.Connection, path: lease.Path}, nil
}

func oneShotPeerOperation(application peerApplication, keyDelivery *peerTransferKeyDelivery) bool {
	return application.health || keyDelivery != nil
}

func peerRaceConfig(config connectionmanager.Config, health, keyDelivery bool, mode connectionmanager.Mode) connectionmanager.Config {
	if health && (mode == connectionmanager.ModeAuto || mode == connectionmanager.ModeRelayRace) {
		// These one-off operations own a monotonic descriptor admission. Acquire
		// the next candidate descriptor only after the prior carrier has failed.
		// Relay reachability is proved independently, so avoid direct admission
		// until both relay paths have been exhausted.
		config.SequentialFallback = true
		config.RelayFirst = true
		config.OneShot = true
	} else if keyDelivery && (mode == connectionmanager.ModeAuto || mode == connectionmanager.ModeRelayRace) {
		// Transfer-key exchanges perform authenticated carrier setup. Do not
		// give relay candidates the health probe's small sequential budget; let
		// the overall connect deadline bound each candidate instead. The
		// application exchange happens after carrier selection, so racer-level
		// one-shot cancellation must not close the carrier before that exchange.
		config.RelayFirst = true
	}
	return config
}

func retryablePeerAttachment(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, ErrPeerStreamOpen) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var transportErr *terminalTransportError
	return errors.As(err, &transportErr)
}

func configureCandidatePromotion(candidate *terminalPathCandidate, pool *connectionmanager.Pool) {
	if candidate == nil || pool == nil {
		return
	}
	candidate.mu.Lock()
	candidate.pool = pool
	candidate.mu.Unlock()
	candidate.setPromotion(func(ctx context.Context) (*terminalPathCandidate, error) {
		pool.Retire(peerquic.ClassInteractive, candidate)
		connection, _, ok := pool.Selected(peerquic.ClassInteractive)
		if !ok {
			return nil, ErrPeerStreamOpen
		}
		target, ok := connection.(*terminalPathCandidate)
		if !ok || target == candidate || target.openAuthorized == nil {
			return nil, ErrPeerStreamOpen
		}
		configureCandidatePromotion(target, pool)
		return target, nil
	})
}

func cachedAttachmentPreservesCarrier(state connectionmanager.State, err error) bool {
	if state != connectionmanager.StateTrusted || err == nil || errors.Is(err, ErrPeerCarrierExpired) || errors.Is(err, ErrPeerCarrierConsumed) || errors.Is(err, ErrPeerStreamOpen) {
		return false
	}
	// An attached application stream is the carrier's liveness proof. EOF or a
	// cancelled/deadlined protocol exchange means the cached carrier can no
	// longer be trusted, even when its health state has not caught up yet.
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed)
}

func peerAllowedPaths(mode connectionmanager.Mode) []string {
	switch mode {
	case connectionmanager.ModeQUIC:
		return []string{"direct_quic", "relay_quic"}
	case connectionmanager.ModeWSS:
		return []string{"relay_wss"}
	case connectionmanager.ModeDirectQUIC:
		return []string{"direct_quic"}
	case connectionmanager.ModeRelayQUIC:
		return []string{"relay_quic"}
	case connectionmanager.ModeRelayRace:
		return []string{"relay_quic", "relay_wss"}
	default:
		return []string{"direct_quic", "relay_quic", "relay_wss"}
	}
}

func peerDescriptorAllowedPaths(path connectionmanager.Path) ([]string, bool) {
	switch path {
	case connectionmanager.PathDirectQUIC:
		return []string{"direct_quic"}, true
	case connectionmanager.PathRelayQUIC:
		return []string{"relay_quic"}, true
	case connectionmanager.PathWSS:
		return []string{"relay_wss"}, true
	default:
		return nil, false
	}
}

func oneShotDescriptorPaths(mode connectionmanager.Mode) []connectionmanager.Path {
	switch mode {
	case connectionmanager.ModeAuto:
		return []connectionmanager.Path{connectionmanager.PathRelayQUIC, connectionmanager.PathWSS, connectionmanager.PathDirectQUIC}
	case connectionmanager.ModeRelayRace:
		return []connectionmanager.Path{connectionmanager.PathRelayQUIC, connectionmanager.PathWSS}
	default:
		return nil
	}
}

func peerModeForPath(path string) (connectionmanager.Mode, bool) {
	switch path {
	case "a":
		return connectionmanager.ModeAuto, true
	case "d":
		return connectionmanager.ModeDirectQUIC, true
	case "q":
		return connectionmanager.ModeRelayQUIC, true
	case "w":
		return connectionmanager.ModeWSS, true
	case "r":
		return connectionmanager.ModeRelayRace, true
	default:
		return 0, false
	}
}

func peerPurpose(consumer string, application peerApplication) string {
	if application.health {
		return "health_probe"
	}
	switch consumer {
	case "private_preview", "codex", "file_transfer_key":
		return consumer
	default:
		return "interactive"
	}
}

func peerDescriptorScope(consumer string, application peerApplication, keyDelivery bool) (string, string) {
	if consumer == "private_preview" && application.quic != nil {
		return "private_preview", consumer
	}
	if !keyDelivery && !application.health {
		return "peer_transport", "peer_transport"
	}
	return peerPurpose(consumer, application), consumer
}

type observedSocketMapping struct {
	source directpath.SocketMappingSource
	record func(string, string)
}

func (m observedSocketMapping) AcquireSocketMapping(ctx context.Context, generation uint64, localPort uint16, connection net.PacketConn, stunURLs []string) (portmapping.VerifiedMapping, netip.Addr, error) {
	mapping, related, err := m.source.AcquireSocketMapping(ctx, generation, localPort, connection, stunURLs)
	category := "verified"
	switch {
	case errors.Is(err, portmapping.ErrUntrusted):
		category = "untrusted"
	case errors.Is(err, portmapping.ErrUnreachable):
		category = "unreachable"
	case errors.Is(err, portmapping.ErrUnavailable):
		category = "unavailable"
	case err != nil:
		category = "unknown"
	}
	if m.record != nil {
		protocol := "unknown"
		if err == nil {
			protocol = mapping.Protocol()
		}
		m.record(protocol, category)
	}
	return mapping, related, err
}

func newPeerPoolObserver(machineID string, pool *connectionmanager.Pool, clock func() time.Time, network func() networkcheck.STUNObservation) *localobservation.Publisher {
	paths, err := localapi.CurrentPaths(os.Geteuid())
	if err != nil {
		return nil
	}
	client, err := localapi.NewClient(paths.SocketPath, time.Second)
	if err != nil {
		return nil
	}
	publisher, err := localobservation.New(localobservation.Config{Client: client, Pool: pool, MachineID: machineID, Classes: []peerquic.Class{peerquic.ClassInteractive}, Clock: clock, Network: network})
	if err != nil {
		return nil
	}
	return publisher
}

func runPeerPoolObserver(ctx context.Context, observer *localobservation.Publisher, machineID, ownership string) {
	if observer == nil {
		return
	}
	err := observer.Run(ctx)
	diagnosticlog.TryInfo("peer local observation stopped", "machine_id", machineID, "ownership", ownership, "error", err, "context_error", ctx.Err(), "context_cause", context.Cause(ctx))
}

func (t *PeerTerminalTunnel) dialRelayQUIC(ctx, lifetime context.Context, target *resolver.TerminalTarget, descriptor directpath.AttemptDescriptor, authority peersession.Authority, fingerprint networkadaptation.Fingerprint, application peerApplication, keyDelivery *peerTransferKeyDelivery) (*terminalPathCandidate, error) {
	maximumDeadline := descriptor.ExpiresAt.Sub(t.config.Now().UTC())
	if maximumDeadline <= 0 {
		return nil, ErrPeerTerminalInvalid
	}
	carrierLifetime, cancelCarrier := retainedRelayCarrierLifetime(lifetime, descriptor.Document.Purpose == "peer_transport")
	carrierLifetimeOwned := false
	defer func() {
		if cancelCarrier != nil && !carrierLifetimeOwned {
			cancelCarrier()
		}
	}()
	initialPacketSize := t.relayPacketSize(lifetime, descriptor, fingerprint)
	connection, err := relaycarrier.DialQUIC(ctx, relaycarrier.QUICDialConfig{URL: descriptor.RelayQUICURL, Credential: descriptor.RelayCredential, EndpointID: authority.LocalEndpointID(), Role: "initiator", StreamHandle: authority.RouteHandle, TLS: t.config.TLS.Clone(), Lifetime: carrierLifetime, MaximumDeadline: maximumDeadline, Carrier: relaycarrier.DevelopmentConfig(), InitialPacketSize: initialPacketSize})
	if err != nil {
		diagnosticlog.TryInfo("peer relay candidate admission stage", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "stage", "carrier_dialed", "error", err)
		return nil, err
	}
	diagnosticlog.TryInfo("peer relay candidate admission stage", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "stage", "carrier_dialed", "error", nil)
	health, initial, err := newPeerRelayHealthConnection(connection, authority)
	if err != nil {
		diagnosticlog.TryInfo("peer relay candidate admission stage", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "stage", "health_created", "error", err)
		return nil, errors.Join(err, connection.Close())
	}
	if err := admitPeerRelayHealth(ctx, health, initial); err != nil {
		diagnosticlog.TryInfo("peer relay candidate admission stage", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "stage", "health_admitted", "error", err)
		return nil, errors.Join(err, connection.Close())
	}
	diagnosticlog.TryInfo("peer relay candidate admission stage", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "stage", "health_admitted", "error", nil)
	initiator := nativepeer.Initiator{Connection: connection, Authority: authority}
	var candidate *terminalPathCandidate
	candidate, candidateErr := newRelayTerminalPathCandidate(descriptor.RelayRegion, health, func(attachCtx context.Context, attachment terminalAttachment) (Conn, error) {
		target, application, keyDelivery := attachment.target, attachment.application, attachment.keyDelivery
		var authorizedGroup nativeStreamGroup
		if descriptor.Document.Purpose == "peer_transport" {
			authorizedGroup = &authorizedPeerRelayStreamGroup{initiator: initiator, authority: authority, lifetime: lifetime, target: target, application: application, fallbackOperation: descriptor.Document.OperationID, now: t.config.Now, candidate: candidate}
		}
		if keyDelivery != nil {
			stream, openErr := initiator.Open(attachCtx, "transfer-key-control")
			if openErr != nil {
				return nil, errors.Join(ErrPeerStreamOpen, openErr)
			}
			deliverErr := keyDelivery.exchange(stream, authority.Context)
			closeErr := stream.Close()
			if deliverErr != nil || closeErr != nil {
				return nil, errors.Join(deliverErr, closeErr)
			}
			return completedPeerConn{}, nil
		}
		if application.raw != nil {
			var stream io.ReadWriteCloser
			var openErr error
			if authorizedGroup != nil {
				stream, openErr = authorizedGroup.OpenStream(attachCtx)
			} else {
				stream, openErr = initiator.Open(attachCtx, application.stream)
			}
			if openErr != nil {
				return nil, errors.Join(ErrPeerStreamOpen, openErr)
			}
			result, attachErr := application.raw(attachCtx, stream)
			if attachErr != nil {
				return nil, errors.Join(attachErr, stream.Close())
			}
			return result, nil
		}
		var message *nativeMessageConnection
		var attachErr error
		if authorizedGroup != nil {
			message, attachErr = authenticateUnifiedNativeStream(attachCtx, authorizedGroup, target, "relay QUIC")
		} else {
			message, attachErr = authenticatePeerRelay(attachCtx, initiator, target, "relay QUIC")
		}
		if attachErr != nil {
			return nil, attachErr
		}
		result, attachErr := application.helper(attachCtx, message, target)
		if attachErr != nil {
			return nil, errors.Join(attachErr, message.Close())
		}
		return result, nil
	})
	if candidateErr != nil {
		return nil, candidateErr
	}
	candidate.singleUse = descriptor.Document.Purpose != "peer_transport" && descriptor.Document.Purpose != "private_preview"
	candidate.openAuthorized = func(openCtx context.Context, header streamauth.Header) (net.Conn, error) {
		return initiator.OpenAuthorized(openCtx, header)
	}
	if descriptor.Document.Purpose != "peer_transport" {
		candidate.expiresAt, candidate.now = descriptor.ExpiresAt, t.config.Now
	} else {
		if err := adoptRelayCandidate(ctx, candidate, health, initiator, descriptor, "relay_quic"); err != nil {
			diagnosticlog.TryInfo("peer relay candidate admission stage", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "stage", "candidate_adopted", "error", err)
			return nil, errors.Join(err, candidate.health.Close())
		}
		candidate.bindRetainedCarrierLifetime(lifetime, carrierLifetime, cancelCarrier)
		carrierLifetimeOwned = true
		diagnosticlog.TryInfo("peer relay candidate admission stage", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "stage", "candidate_adopted", "error", nil)
	}
	return candidate, nil
}

func (t *PeerTerminalTunnel) relayPacketSize(lifetime context.Context, descriptor directpath.AttemptDescriptor, fingerprint networkadaptation.Fingerprint) uint16 {
	if t == nil || lifetime == nil || !fingerprint.Valid() || descriptor.RelayRegion == "" || descriptor.RelayPMTUURL == "" || descriptor.RelayPMTUCredential == "" {
		return 1200
	}
	key := networkadaptation.PMTUKey{Fingerprint: fingerprint, PathID: "relay:" + descriptor.RelayRegion, NetworkGeneration: descriptor.NetworkGeneration}
	return t.relayPMTU.PacketSize(lifetime, key, func(ctx context.Context) (networkadaptation.PMTUMeasurement, error) {
		return t.measureRelayPMTU(ctx, descriptor)
	})
}

func (t *PeerTerminalTunnel) measureRelayPMTU(ctx context.Context, descriptor directpath.AttemptDescriptor) (networkadaptation.PMTUMeasurement, error) {
	policy := networkadaptation.DevelopmentPMTUPolicy()
	prober, err := relaypmtu.Open(ctx, descriptor.RelayPMTUURL, descriptor.RelayPMTUCredential, policy.MaximumPayload)
	if err != nil {
		return networkadaptation.PMTUMeasurement{}, err
	}
	defer prober.Close()
	measurer, err := networkadaptation.NewPMTUMeasurer(policy, prober)
	if err != nil {
		return networkadaptation.PMTUMeasurement{}, err
	}
	return measurer.Measure(ctx)
}

func (t *PeerTerminalTunnel) dialDirect(ctx, lifetime context.Context, target *resolver.TerminalTarget, descriptor directpath.AttemptDescriptor, sessionAuthority peersession.Authority, authority clientauthority.Authority, fingerprint networkadaptation.Fingerprint, mapping directpath.SocketMappingSource, application peerApplication, keyDelivery *peerTransferKeyDelivery) (*terminalPathCandidate, error) {
	started := time.Now()
	timing := map[string]int64{}
	mark := func(name string) { timing[name] = time.Since(started).Milliseconds() }
	defer func() {
		diagnosticlog.TryInfo("peer direct transport timing", "side", "client", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "network_generation", descriptor.NetworkGeneration, "milestones_ms", timing, "elapsed_ms", time.Since(started).Milliseconds())
	}()
	directCtx, cancel := context.WithDeadline(ctx, descriptor.ExpiresAt)
	defer cancel()
	pmtuKey := sessionAuthority.PMTUKey()
	source := directpath.DescriptorSourceFunc(func(context.Context, directpath.Generation) (directpath.AttemptDescriptor, error) {
		return descriptor, nil
	})
	t.observeNetworkAsync(lifetime, fingerprint, descriptor.STUNURLs)
	sockets := udpsocket.DevelopmentConfig(true, true)
	if viable, known := t.cachedIPv6Viability(fingerprint); known {
		sockets.IPv6Viable = func(context.Context) bool { return viable }
	} else {
		// Start the reachability probe before the signaling/ICE assembly so
		// the probe latency overlaps the signaling dial instead of blocking
		// socket creation serially. The result is recorded for future dials
		// on the same network fingerprint.
		probeResult := make(chan bool, 1)
		go func() {
			probeCtx, cancelProbe := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancelProbe()
			viable := networkcheck.ProbeSTUNReachability(probeCtx, "ip6", descriptor.STUNURLs, net.DefaultResolver, 250*time.Millisecond)
			t.recordIPv6Viability(fingerprint, viable)
			probeResult <- viable
		}()
		var probeOnce sync.Once
		var probedViable bool
		sockets.IPv6Viable = func(probeCtx context.Context) bool {
			probeOnce.Do(func() {
				select {
				case probedViable = <-probeResult:
				case <-probeCtx.Done():
				}
			})
			return probedViable
		}
	}
	// Pion dispatches post-ICE packets by remote address. Independent direct
	// QUIC sessions to one machine therefore require independent UDP ports.
	factory, err := directpath.NewSignalingFactory(directpath.SignalingFactoryConfig{Descriptors: source, SocketMapping: mapping, Lifetime: lifetime, TLS: t.config.TLS.Clone(), Dial: func(dialCtx context.Context, config signaling.WebSocketConfig) (directpath.SignalingTransport, error) {
		return t.signalingSubstrate.Open(dialCtx, config)
	}, Assembly: directpath.Config{Sockets: sockets, PMTUKey: pmtuKey[:], MaximumPMTU: networkadaptation.DevelopmentPMTUPolicy().MaximumPayload, ApplicationQueue: 64, PMTUResponseLimit: time.Second}})
	if err != nil {
		return nil, err
	}
	generation := directpath.Generation{Attempt: descriptor.AttemptGeneration, Network: descriptor.NetworkGeneration}
	assembly, err := factory.Create(directCtx, generation)
	if err != nil {
		return nil, err
	}
	mark("ice_ready")
	localLeaf, err := endpointidentity.NewTLSCertificate(authority.LocalCertificate, authority.RootPublic, authority.LocalKeys.QUICPrivate, t.config.Now().UTC(), descriptor.ExpiresAt.Sub(t.config.Now().UTC()))
	if err != nil {
		return nil, errors.Join(err, assembly.Close())
	}
	mark("local_certificate_ready")
	clientTLS, err := endpointidentity.ClientTLS(localLeaf, endpointidentity.PeerExpectation{RootPublic: authority.RootPublic, TrustedKeys: authority.TrustedKeys, CertificateKeyID: authority.MachineCertificateKeyID, Certificate: authority.MachineCertificateRaw, Expected: endpointidentity.Expected{AccountID: descriptor.Document.AccountID, Role: endpointidentity.RoleMachine, EndpointID: descriptor.ResponderEndpointID, Generation: descriptor.Document.HostGeneration}}, peerquic.ALPN, t.config.Now)
	if err != nil {
		return nil, errors.Join(err, assembly.Close())
	}
	mark("tls_config_ready")
	class := peerquic.ClassInteractive
	pathSuffix := "interactive"
	if descriptor.Document.Purpose == "private_preview" {
		class = peerquic.ClassPreview
		pathSuffix = "preview"
	}
	pathID := descriptor.IntentID + ":" + pathSuffix
	pmtuCacheKey := networkadaptation.PMTUKey{Fingerprint: fingerprint, PathID: pathID, NetworkGeneration: descriptor.NetworkGeneration}
	var session *peerquic.Session
	if descriptor.Document.Purpose == "direct_probe" {
		maximumIdle := descriptor.ExpiresAt.Sub(t.config.Now().UTC())
		session, err = assembly.DialProbeQUIC(directCtx, clientTLS, maximumIdle)
	} else {
		session, err = assembly.DialQUIC(directCtx, clientTLS, peerquic.DevelopmentSessionConfig(class), directpath.PMTUConfig{Policy: networkadaptation.DevelopmentPMTUPolicy(), Cache: t.pmtu, Key: pmtuCacheKey, Lifetime: &directpath.LifetimeConfig{Cache: t.lifetime, Fingerprint: fingerprint, Now: t.config.Now}})
		t.recordPMTU(fingerprint, pmtuCacheKey)
	}
	if err != nil {
		return nil, errors.Join(err, assembly.Close())
	}
	mark("quic_handshake_complete")
	health, err := directpath.NewHealthConnection(assembly, session)
	if err != nil {
		return nil, errors.Join(err, session.Close(), assembly.Close())
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.Join(err, health.Close())
	}
	if err := health.AdmitInitialHealth(directCtx, nonce); err != nil {
		return nil, err
	}
	mark("initial_health_complete")
	var binding [32]byte
	if descriptor.Document.Purpose != "peer_transport" {
		binding, err = peerquic.ExporterBinding(session.Connection.ConnectionState().TLS, sessionAuthority.Context)
		if err != nil {
			return nil, errors.Join(err, health.Close())
		}
	}
	var previewOnce sync.Once
	var previewClient *http3.ClientConn
	var previewErr error
	var candidate *terminalPathCandidate
	candidate, candidateErr := newTerminalPathCandidate(health, func(attachCtx context.Context, attachment terminalAttachment) (Conn, error) {
		target, application, keyDelivery := attachment.target, attachment.application, attachment.keyDelivery
		if application.quic != nil {
			if descriptor.Document.Purpose != "private_preview" {
				return nil, ErrPeerTerminalInvalid
			}
			previewOnce.Do(func() {
				previewClient = (&http3.Transport{}).NewClientConn(session.Connection)
			})
			if previewErr != nil || previewClient == nil {
				return nil, errors.Join(previewErr, health.Close())
			}
			return application.quic(attachCtx, previewClient, health.Close)
		}
		baseGroup := newPeerQUICNativeStreamGroup(lifetime, session, health.Close, binding)
		var group nativeStreamGroup = baseGroup
		if descriptor.Document.Purpose == "peer_transport" {
			group = &authorizedPeerQUICStreamGroup{peerQUICNativeStreamGroup: baseGroup, lifetime: lifetime, authority: sessionAuthority, target: target, application: application, consumer: application.consumer, fallbackOperation: descriptor.Document.OperationID, now: t.config.Now, candidate: candidate}
		}
		if keyDelivery != nil {
			stream, openErr := group.OpenStream(attachCtx)
			if openErr != nil {
				return nil, errors.Join(ErrPeerStreamOpen, openErr, group.Close())
			}
			if descriptor.Document.Purpose != "peer_transport" {
				bound, ok := stream.(interface{ WriteFirst([]byte) error })
				if !ok {
					return nil, errors.Join(ErrPeerTerminalInvalid, stream.Close(), group.Close())
				}
				if firstErr := bound.WriteFirst(nil); firstErr != nil {
					return nil, errors.Join(firstErr, stream.Close(), group.Close())
				}
			}
			deliverErr := keyDelivery.exchange(stream, sessionAuthority.Context)
			closeErr := stream.Close()
			if deliverErr != nil || closeErr != nil {
				return nil, errors.Join(deliverErr, closeErr)
			}
			return &directTransferPeerConn{group: baseGroup}, nil
		}
		if application.raw != nil {
			stream, openErr := group.OpenStream(attachCtx)
			if openErr != nil {
				return nil, errors.Join(ErrPeerStreamOpen, openErr, group.Close())
			}
			if descriptor.Document.Purpose != "peer_transport" {
				bound, ok := stream.(interface{ WriteFirst([]byte) error })
				if !ok {
					return nil, errors.Join(ErrPeerTerminalInvalid, stream.Close(), group.Close())
				}
				if firstErr := bound.WriteFirst(nil); firstErr != nil {
					return nil, errors.Join(firstErr, stream.Close(), group.Close())
				}
			}
			result, attachErr := application.raw(attachCtx, stream)
			if attachErr != nil {
				return nil, errors.Join(attachErr, stream.Close(), group.Close())
			}
			return result, nil
		}
		message, attachErr := authenticateUnifiedNativeStream(attachCtx, group, target, "direct QUIC")
		if attachErr != nil {
			return nil, attachErr
		}
		result, attachErr := application.helper(attachCtx, message, target)
		if attachErr != nil {
			return nil, errors.Join(attachErr, message.Close())
		}
		return result, nil
	})
	if candidateErr != nil {
		return nil, candidateErr
	}
	// A private preview owns one preview-class QUIC connection and multiplexes
	// every accepted loopback TCP connection as an independent HTTP/3 CONNECT
	// stream. Operation-scoped one-shot carriers remain single use.
	candidate.singleUse = descriptor.Document.Purpose != "peer_transport" && descriptor.Document.Purpose != "private_preview"
	candidate.openAuthorized = func(openCtx context.Context, header streamauth.Header) (net.Conn, error) {
		streamAuthority, openErr := sessionAuthority.InitiatorStream(header.Grant())
		if openErr != nil {
			return nil, openErr
		}
		streamBinding, openErr := peerquic.ExporterBindingForStream(session.Connection.ConnectionState().TLS, sessionAuthority.Transport, streamAuthority.Stream)
		if openErr != nil {
			return nil, openErr
		}
		stream, openErr := session.Connection.OpenStreamSync(openCtx)
		if openErr != nil {
			return nil, openErr
		}
		bound := &boundNativeStream{nativeStream: stream, binding: streamBinding}
		encoded, openErr := header.MarshalBinary()
		if openErr == nil {
			openErr = bound.WriteFirst(encoded)
		}
		if openErr != nil {
			return nil, errors.Join(openErr, stream.Close())
		}
		return asResumableCarrier(stream), nil
	}
	if descriptor.Document.Purpose != "private_preview" && descriptor.Document.Purpose != "peer_transport" {
		candidate.expiresAt, candidate.now = descriptor.ExpiresAt, t.config.Now
	} else if descriptor.Document.Purpose == "peer_transport" {
		if err := adoptDirectCandidate(ctx, candidate, session, sessionAuthority, descriptor); err != nil {
			return nil, errors.Join(err, candidate.health.Close())
		}
	}
	return candidate, nil
}

func (t *PeerTerminalTunnel) observeNetworkAsync(lifetime context.Context, fingerprint networkadaptation.Fingerprint, stunURLs []string) {
	if t == nil || lifetime == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(lifetime, 2*time.Second)
		defer cancel()
		var ipv4, ipv6 net.PacketConn
		if connection, err := net.ListenPacket("udp4", "0.0.0.0:0"); err == nil {
			ipv4 = connection
			defer connection.Close()
		}
		if connection, err := net.ListenPacket("udp6", "[::]:0"); err == nil {
			ipv6 = connection
			defer connection.Close()
		}
		observer := networkcheck.STUNObserver{Resolver: net.DefaultResolver, Timeout: 500 * time.Millisecond, HTTPClient: t.config.HTTPClient, PortalEndpoint: networkCheckEndpoint(t.config.Issuer), OnObservation: func(value networkcheck.STUNObservation) { t.recordNetworkCheck(fingerprint, value) }}
		observer.Observe(ctx, ipv4, ipv6, append([]string(nil), stunURLs...))
	}()
}

type terminalPathCandidate struct {
	health          connectionmanager.ActiveHealthConnection
	transport       connectionmanager.ActiveHealthTransport
	attach          func(context.Context, terminalAttachment) (Conn, error)
	relayRegion     string
	mu              sync.Mutex
	attachments     uint64
	singleUse       bool
	closed          bool
	poolReleased    bool
	intentID        string
	attempt         uint64
	expiresAt       time.Time
	now             func() time.Time
	openAuthorized  func(context.Context, streamauth.Header) (net.Conn, error)
	streamsMu       sync.Mutex
	streams         map[*resumablestream.Conn]*streamCoordinator
	standby         *terminalPathCandidate
	standbyRevision uint64
	promote         func(context.Context) (*terminalPathCandidate, error)
	pool            *connectionmanager.Pool
	sourceRefs      uint64
	closePending    bool
	leaseID         candidatelease.ID
	leaseGeneration uint64
	releaseLease    func(context.Context) error
	cancelCarrier   context.CancelFunc
	releaseOnce     sync.Once
	releaseErr      error
}

type streamCoordinator struct {
	ctx              context.Context
	cancel           context.CancelFunc
	stream           *resumablestream.Conn
	header           streamauth.Header
	mu               sync.Mutex
	current          *terminalPathCandidate
	desired          *terminalPathCandidate
	prepared         *terminalPathCandidate
	handle           resumablestream.CarrierHandle
	detached         time.Time
	availability     <-chan connectionmanager.AvailabilitySnapshot
	reconcileWake    chan struct{}
	unsubscribe      func()
	snapshot         connectionmanager.AvailabilitySnapshot
	available        []*terminalPathCandidate
	observedRevision uint64
	settledRevision  uint64
	committedEpoch   uint64
	promoteDesired   bool
	promoting        bool
	desiredRevision  uint64
}

var terminalPublicationRevision atomic.Uint64

type peerAttemptTracker struct {
	client   *api.Client
	refresh  func() *api.Client
	mu       sync.Mutex
	attempts map[string]directpath.AttemptDescriptor
	closed   bool
	once     sync.Once
	err      error
}

func (t *peerAttemptTracker) Track(descriptor directpath.AttemptDescriptor) {
	if t == nil || descriptor.IntentID == "" || descriptor.AttemptGeneration == 0 {
		return
	}
	key := descriptor.IntentID + ":" + fmt.Sprint(descriptor.AttemptGeneration)
	t.mu.Lock()
	if !t.closed {
		t.attempts[key] = descriptor
		t.mu.Unlock()
		return
	}
	t.mu.Unlock()
	go func() { _ = revokePeerAttempt(t.client, descriptor) }()
}

// Release revokes one descriptor that failed before becoming an owned carrier.
// It removes tracker ownership first so session cleanup cannot race a duplicate
// revocation while the next recovery generation is being issued.
func (t *peerAttemptTracker) Release(descriptor directpath.AttemptDescriptor) error {
	if t == nil || descriptor.IntentID == "" || descriptor.AttemptGeneration == 0 {
		return nil
	}
	key := descriptor.IntentID + ":" + fmt.Sprint(descriptor.AttemptGeneration)
	t.mu.Lock()
	_, tracked := t.attempts[key]
	if tracked {
		delete(t.attempts, key)
	}
	closed := t.closed
	t.mu.Unlock()
	if !tracked || closed {
		return nil
	}
	err := revokePeerAttempt(t.client, descriptor)
	if errors.Is(err, api.ErrUnauthenticated) && t.refresh != nil {
		if fresh := t.refresh(); fresh != nil {
			err = revokePeerAttempt(fresh, descriptor)
		}
	}
	return err
}

func (t *peerAttemptTracker) Revoke() error {
	if t == nil || t.client == nil {
		return nil
	}
	t.once.Do(func() {
		t.mu.Lock()
		t.closed = true
		attempts := make([]directpath.AttemptDescriptor, 0, len(t.attempts))
		for _, descriptor := range t.attempts {
			attempts = append(attempts, descriptor)
		}
		t.attempts = nil
		t.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		const maximumConcurrentRevocations = 8
		semaphore := make(chan struct{}, maximumConcurrentRevocations)
		var wait sync.WaitGroup
		var resultMu sync.Mutex
		for _, descriptor := range attempts {
			descriptor := descriptor
			wait.Add(1)
			go func() {
				defer wait.Done()
				select {
				case semaphore <- struct{}{}:
					defer func() { <-semaphore }()
				case <-ctx.Done():
					return
				}
				err := revokePeerAttemptContext(ctx, t.client, descriptor)
				if errors.Is(err, api.ErrUnauthenticated) && t.refresh != nil {
					if fresh := t.refresh(); fresh != nil {
						err = revokePeerAttemptContext(ctx, fresh, descriptor)
					}
				}
				if err != nil {
					resultMu.Lock()
					t.err = errors.Join(t.err, err)
					resultMu.Unlock()
				}
			}()
		}
		wait.Wait()
	})
	return t.err
}

func revokePeerAttempt(client *api.Client, descriptor directpath.AttemptDescriptor) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return revokePeerAttemptContext(ctx, client, descriptor)
}

func revokePeerAttemptContext(ctx context.Context, client *api.Client, descriptor directpath.AttemptDescriptor) error {
	if client == nil || descriptor.IntentID == "" || descriptor.AttemptGeneration == 0 {
		return nil
	}
	digest := sha256.Sum256([]byte("peer-attempt-close\x00" + descriptor.IntentID))
	operationID := "op_peer_revoke_" + hex.EncodeToString(digest[:16])
	return client.RevokePeerAttempt(ctx, operationID, descriptor.IntentID, descriptor.AttemptGeneration)
}

type terminalAttachment struct {
	target      *resolver.TerminalTarget
	application peerApplication
	keyDelivery *peerTransferKeyDelivery
}

func newRelayTerminalPathCandidate(region string, health connectionmanager.ActiveHealthConnection, attach func(context.Context, terminalAttachment) (Conn, error)) (*terminalPathCandidate, error) {
	candidate, err := newTerminalPathCandidate(health, attach)
	if err != nil {
		return nil, err
	}
	candidate.relayRegion = region
	return candidate, nil
}

func (c *terminalPathCandidate) RelayRegion() string {
	if c == nil {
		return ""
	}
	return c.relayRegion
}

func newTerminalPathCandidate(health connectionmanager.ActiveHealthConnection, attach func(context.Context, terminalAttachment) (Conn, error)) (*terminalPathCandidate, error) {
	if health == nil || health.State() != connectionmanager.StateTrusted || attach == nil {
		return nil, ErrPeerTerminalInvalid
	}
	capability, err := health.ActiveHealthCapability()
	if err != nil || capability.Transport == nil {
		return nil, errors.Join(ErrPeerTerminalInvalid, err)
	}
	return &terminalPathCandidate{health: health, transport: capability.Transport, attach: attach, streams: make(map[*resumablestream.Conn]*streamCoordinator)}, nil
}

func adoptRelayCandidate(ctx context.Context, candidate *terminalPathCandidate, health *relaycarrier.HealthConnection, initiator nativepeer.Initiator, descriptor directpath.AttemptDescriptor, path string) error {
	binding, err := health.CandidateBinding()
	if err != nil {
		return err
	}
	id, err := candidatelease.NewID(binding[:], descriptor.IntentID, descriptor.AttemptGeneration, path)
	if err != nil {
		return err
	}
	adopt := candidatelease.Message{Version: 1, Type: candidatelease.Adopt, Candidate: id, LeaseGeneration: descriptor.AttemptGeneration}
	payload, err := adopt.Marshal()
	if err != nil {
		return err
	}
	control, response, err := initiator.OpenCandidateControl(ctx, payload)
	if err != nil {
		return err
	}
	ack, err := candidatelease.Parse(response)
	if err != nil || ack.Type != candidatelease.AdoptAck || ack.Candidate != id || ack.LeaseGeneration != descriptor.AttemptGeneration {
		return errors.Join(candidatelease.ErrProtocol, err, control.Close())
	}
	candidate.leaseID, candidate.leaseGeneration = id, descriptor.AttemptGeneration
	candidate.releaseLease = func(releaseCtx context.Context) error {
		frame, frameErr := candidatelease.Frame(candidatelease.Message{Version: 1, Type: candidatelease.Release, Candidate: id, LeaseGeneration: descriptor.AttemptGeneration})
		if frameErr == nil {
			_ = control.SetDeadline(time.Now().Add(2 * time.Second))
			_, frameErr = control.Write(frame)
		}
		if frameErr == nil {
			var releaseAck candidatelease.Message
			releaseAck, frameErr = candidatelease.FrameReader(control)
			if frameErr == nil && (releaseAck.Type != candidatelease.ReleaseAck || releaseAck.Candidate != id || releaseAck.LeaseGeneration != descriptor.AttemptGeneration) {
				frameErr = candidatelease.ErrProtocol
			}
		}
		return errors.Join(frameErr, control.Close())
	}
	return nil
}

func adoptDirectCandidate(ctx context.Context, candidate *terminalPathCandidate, session *peerquic.Session, authority peersession.Authority, descriptor directpath.AttemptDescriptor) error {
	binding, err := peerquic.CandidateBinding(session.Connection.ConnectionState().TLS, authority.Transport)
	if err != nil {
		return err
	}
	id, err := candidatelease.NewID(binding[:], descriptor.IntentID, descriptor.AttemptGeneration, "direct_quic")
	if err != nil {
		return err
	}
	send := func(controlCtx context.Context, message candidatelease.Message) error {
		frame, frameErr := candidatelease.Frame(message)
		if frameErr != nil {
			return frameErr
		}
		stream, openErr := session.OpenCandidateControl(controlCtx, frame)
		if openErr != nil {
			return openErr
		}
		stopCancel := context.AfterFunc(controlCtx, func() { _ = stream.Close() })
		ack, readErr := candidatelease.FrameReader(stream)
		stopCancel()
		closeErr := stream.Close()
		if readErr != nil || ack.Candidate != id || ack.LeaseGeneration != descriptor.AttemptGeneration || message.Type == candidatelease.Adopt && ack.Type != candidatelease.AdoptAck || message.Type == candidatelease.Release && ack.Type != candidatelease.ReleaseAck {
			return errors.Join(candidatelease.ErrProtocol, readErr, closeErr)
		}
		return closeErr
	}
	if err := send(ctx, candidatelease.Message{Version: 1, Type: candidatelease.Adopt, Candidate: id, LeaseGeneration: descriptor.AttemptGeneration}); err != nil {
		return err
	}
	candidate.leaseID, candidate.leaseGeneration = id, descriptor.AttemptGeneration
	candidate.releaseLease = func(releaseCtx context.Context) error {
		return send(releaseCtx, candidatelease.Message{Version: 1, Type: candidatelease.Release, Candidate: id, LeaseGeneration: descriptor.AttemptGeneration})
	}
	return nil
}

func (c *terminalPathCandidate) SetStandby(connection connectionmanager.Connection) {
	if c == nil {
		return
	}
	target, _ := connection.(*terminalPathCandidate)
	if target == c || target != nil && target.openAuthorized == nil {
		target = nil
	}
	revision := terminalPublicationRevision.Add(1)
	c.streamsMu.Lock()
	if c.standby == target {
		c.standbyRevision = revision
		c.streamsMu.Unlock()
		return
	}
	c.standby = target
	c.standbyRevision = revision
	coordinators := make([]*streamCoordinator, 0, len(c.streams))
	for _, coordinator := range c.streams {
		coordinators = append(coordinators, coordinator)
	}
	c.streamsMu.Unlock()
	for _, coordinator := range coordinators {
		coordinator.setDesiredRevision(target, false, revision)
	}
}

func (c *terminalPathCandidate) SetPreferred(connection connectionmanager.Connection) {
	target, _ := connection.(*terminalPathCandidate)
	if c == nil || target == nil || target == c || target.openAuthorized == nil {
		return
	}
	revision := terminalPublicationRevision.Add(1)
	c.streamsMu.Lock()
	coordinators := make([]*streamCoordinator, 0, len(c.streams))
	for _, coordinator := range c.streams {
		coordinators = append(coordinators, coordinator)
	}
	c.streamsMu.Unlock()
	for _, coordinator := range coordinators {
		coordinator.setDesiredRevision(target, true, revision)
	}
}

func (c *terminalPathCandidate) CommittedApplications() uint64 {
	if c == nil {
		return 0
	}
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	return uint64(len(c.streams))
}

func (c *terminalPathCandidate) setPromotion(fn func(context.Context) (*terminalPathCandidate, error)) {
	if c == nil {
		return
	}
	c.promote = fn
}

func (c *terminalPathCandidate) trackStream(header streamauth.Header, stream *resumablestream.Conn) {
	if c == nil || stream == nil {
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(header.DeadlineUnix, 0))
	c.mu.Lock()
	pool := c.pool
	c.mu.Unlock()
	coordinator := &streamCoordinator{ctx: ctx, cancel: cancel, stream: stream, header: header, current: c, committedEpoch: 1, reconcileWake: make(chan struct{}, 1)}
	if pool != nil {
		coordinator.availability, coordinator.unsubscribe = pool.SubscribeAvailability(peerquic.ClassInteractive)
	}
	c.retainSource()
	c.streamsMu.Lock()
	c.streams[stream] = coordinator
	standby := c.standby
	revision := c.standbyRevision
	c.streamsMu.Unlock()
	go coordinator.run()
	if pool == nil {
		coordinator.setDesiredRevision(standby, false, revision)
	}
}

func (c *streamCoordinator) setDesiredRevision(source *terminalPathCandidate, promote bool, revision uint64) {
	if c == nil || source == nil || source.openAuthorized == nil {
		return
	}
	c.mu.Lock()
	if c.availability != nil {
		c.mu.Unlock()
		return
	}
	if revision < c.desiredRevision {
		c.mu.Unlock()
		return
	}
	if c.desired == source {
		c.promoteDesired = c.promoteDesired || promote
		c.desiredRevision = revision
		promotePrepared := promote && c.prepared == source && !c.promoting
		handle := c.handle
		c.mu.Unlock()
		if promotePrepared {
			go c.promotePrepared(source, handle)
		}
		return
	}
	source.retainSource()
	old := c.desired
	var superseded *terminalPathCandidate
	var supersededHandle resumablestream.CarrierHandle
	if promote && c.prepared != nil && c.prepared != source {
		superseded, supersededHandle = c.prepared, c.handle
		c.prepared = nil
		c.handle = resumablestream.CarrierHandle{}
	}
	c.desired = source
	c.promoteDesired = promote
	c.desiredRevision = revision
	c.mu.Unlock()
	if superseded != nil {
		if err := c.stream.DropPrepared(c.ctx, supersededHandle); err != nil {
			diagnosticlog.TryInfo("peer logical stream discard superseded source failed", "consumer", c.header.Consumer, "operation_id", c.header.OperationID, "stream_id", c.header.StreamID, "error", err)
		}
	}
	if old != nil {
		old.releaseSource()
	}
	go c.prepareDesired()
}

func (c *streamCoordinator) prepareDesired() {
	c.mu.Lock()
	if c.prepared != nil || c.desired == nil || c.desired == c.current {
		c.mu.Unlock()
		return
	}
	source := c.desired
	c.mu.Unlock()
	carrier, err := source.openAuthorized(c.ctx, c.header)
	if err != nil {
		diagnosticlog.TryInfo("peer logical stream prepare desired failed", "consumer", c.header.Consumer, "operation_id", c.header.OperationID, "stream_id", c.header.StreamID, "source", fmt.Sprintf("%p", source), "error", err)
		diagnosticlog.TryInfo("peer logical stream prepare source failed", "consumer", c.header.Consumer, "operation_id", c.header.OperationID, "stream_id", c.header.StreamID, "error", err)
		return
	}
	handle, err := c.stream.PrepareCarrier(c.ctx, carrier)
	if err != nil {
		diagnosticlog.TryInfo("peer logical stream prepare desired carrier failed", "consumer", c.header.Consumer, "operation_id", c.header.OperationID, "stream_id", c.header.StreamID, "source", fmt.Sprintf("%p", source), "error", err)
		_ = carrier.Close()
		return
	}
	c.mu.Lock()
	if c.desired != source || c.prepared != nil {
		c.mu.Unlock()
		_ = c.stream.DropPrepared(c.ctx, handle)
		return
	}
	c.prepared, c.handle = source, handle
	promote := c.promoteDesired
	c.mu.Unlock()
	if promote {
		c.promotePrepared(source, handle)
	}
}

func (c *streamCoordinator) promotePrepared(source *terminalPathCandidate, handle resumablestream.CarrierHandle) {
	c.mu.Lock()
	if c.promoting || c.prepared != source || c.handle != handle || !c.promoteDesired {
		c.mu.Unlock()
		return
	}
	c.promoting = true
	c.mu.Unlock()
	err := c.stream.PromoteCarrier(c.ctx, handle)
	if err != nil {
		diagnosticlog.TryInfo("peer logical stream promote desired failed", "consumer", c.header.Consumer, "operation_id", c.header.OperationID, "stream_id", c.header.StreamID, "source", fmt.Sprintf("%p", source), "epoch", handle.Epoch, "error", err)
	}
	c.mu.Lock()
	c.promoting = false
	committed := err == nil && c.prepared == source && c.handle == handle
	c.mu.Unlock()
	if committed {
		c.commitSource(source)
	}
}

func (c *streamCoordinator) run() {
	defer c.close()
	for {
		select {
		case snapshot, ok := <-c.availability:
			if !ok {
				c.availability = nil
				continue
			}
			if c.observeSnapshot(snapshot) {
				c.reconcileLatestSnapshot()
			}
		case <-c.reconcileWake:
			c.reconcileLatestSnapshot()
		case event := <-c.stream.Events():
			switch event.Type {
			case resumablestream.EventDetached:
				if c.acceptsProtocolEvent(event) {
					c.recoverDetached()
					c.wakeUnsettledSnapshot()
				}
			case resumablestream.EventCarrierFailed:
				if c.acceptsProtocolEvent(event) {
					c.clearFailedPrepared(event)
					c.wakeUnsettledSnapshot()
				}
			case resumablestream.EventAborted:
				return
			}
		case <-c.stream.Done():
			return
		case <-c.ctx.Done():
			c.stream.Abort(context.Cause(c.ctx))
			return
		}
	}
}

func (c *streamCoordinator) reconcileSnapshot(snapshot connectionmanager.AvailabilitySnapshot) {
	if !c.observeSnapshot(snapshot) {
		return
	}
	c.reconcileLatestSnapshot()
}

func (c *streamCoordinator) observeSnapshot(snapshot connectionmanager.AvailabilitySnapshot) bool {
	c.mu.Lock()
	if snapshot.Revision == 0 || snapshot.Revision <= c.observedRevision {
		c.mu.Unlock()
		return false
	}
	c.mu.Unlock()
	available := make([]*terminalPathCandidate, 0, len(snapshot.Available))
	for _, source := range snapshot.Available {
		candidate, ok := source.Connection.(*terminalPathCandidate)
		if !ok || candidate == nil || candidate.openAuthorized == nil {
			continue
		}
		candidate.retainSource()
		available = append(available, candidate)
	}
	c.mu.Lock()
	oldAvailable := c.available
	c.snapshot, c.available, c.observedRevision = snapshot, available, snapshot.Revision
	c.mu.Unlock()
	for _, source := range oldAvailable {
		source.releaseSource()
	}
	return true
}

func (c *streamCoordinator) reconcileLatestSnapshot() {
	c.mu.Lock()
	snapshot := c.snapshot
	available := append([]*terminalPathCandidate(nil), c.available...)
	if snapshot.Revision == 0 || snapshot.Revision <= c.settledRevision {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	preferred, _ := snapshot.Preferred.Connection.(*terminalPathCandidate)
	c.mu.Lock()
	current := c.current
	detached := !c.detached.IsZero()
	c.mu.Unlock()
	if detached && preferred == current {
		preferred = firstDifferentCandidate(available, current)
	}
	if preferred != nil && preferred.openAuthorized != nil && preferred != current {
		if err := c.reconcileCarrier(preferred, true, snapshot.Revision); err != nil {
			diagnosticlog.TryInfo("peer logical stream reconcile preferred failed", "consumer", c.header.Consumer, "operation_id", c.header.OperationID, "stream_id", c.header.StreamID, "pool_revision", snapshot.Revision, "error", err)
			return
		}
	}
	c.mu.Lock()
	current = c.current
	c.mu.Unlock()
	fallback := firstDifferentCandidate(available, current)
	if fallback != nil {
		if err := c.reconcileCarrier(fallback, false, snapshot.Revision); err != nil {
			diagnosticlog.TryInfo("peer logical stream reconcile fallback failed", "consumer", c.header.Consumer, "operation_id", c.header.OperationID, "stream_id", c.header.StreamID, "pool_revision", snapshot.Revision, "error", err)
			return
		}
	}
	c.mu.Lock()
	c.settledRevision = snapshot.Revision
	c.mu.Unlock()
}

func (c *streamCoordinator) wakeUnsettledSnapshot() {
	c.mu.Lock()
	unsettled := c.settledRevision < c.observedRevision
	c.mu.Unlock()
	if !unsettled {
		return
	}
	select {
	case c.reconcileWake <- struct{}{}:
	default:
	}
}

func firstDifferentCandidate(available []*terminalPathCandidate, current *terminalPathCandidate) *terminalPathCandidate {
	for _, candidate := range available {
		if candidate != nil && candidate != current {
			return candidate
		}
	}
	return nil
}

func (c *streamCoordinator) reconcileCarrier(source *terminalPathCandidate, promote bool, revision uint64) error {
	c.mu.Lock()
	prepared, handle := c.prepared, c.handle
	c.mu.Unlock()
	if prepared != nil && prepared != source {
		if err := c.stream.DropPrepared(c.ctx, handle); err != nil {
			return err
		}
		c.mu.Lock()
		c.prepared = nil
		c.handle = resumablestream.CarrierHandle{}
		c.mu.Unlock()
		prepared = nil
	}
	if prepared == nil {
		carrier, err := source.openAuthorized(c.ctx, c.header)
		if err != nil {
			diagnosticlog.TryInfo("peer logical stream reconcile open failed", "consumer", c.header.Consumer, "operation_id", c.header.OperationID, "stream_id", c.header.StreamID, "pool_revision", revision, "promote", promote, "source", fmt.Sprintf("%p", source), "error", err)
			return err
		}
		handle, err := c.stream.PrepareCarrier(c.ctx, carrier)
		if err != nil {
			diagnosticlog.TryInfo("peer logical stream reconcile prepare failed", "consumer", c.header.Consumer, "operation_id", c.header.OperationID, "stream_id", c.header.StreamID, "pool_revision", revision, "promote", promote, "source", fmt.Sprintf("%p", source), "error", err)
			_ = carrier.Close()
			return err
		}
		c.mu.Lock()
		c.prepared, c.handle = source, handle
		c.mu.Unlock()
		prepared = source
	}
	if !promote {
		return nil
	}
	c.mu.Lock()
	handle = c.handle
	c.mu.Unlock()
	if err := c.stream.PromoteCarrier(c.ctx, handle); err != nil {
		diagnosticlog.TryInfo("peer logical stream reconcile promote failed", "consumer", c.header.Consumer, "operation_id", c.header.OperationID, "stream_id", c.header.StreamID, "pool_revision", revision, "source", fmt.Sprintf("%p", source), "epoch", handle.Epoch, "error", err)
		c.clearPreparedHandle(source, handle)
		return err
	}
	// COMMIT is authoritative even when a newer snapshot arrived while it was
	// in flight. Record ownership first; the next reconcile may move it again.
	// Snapshot membership and committed-current ownership are independent
	// references: a later snapshot may omit this source while its old carrier
	// remains active during the next transition.
	source.retainSource()
	c.mu.Lock()
	c.committedEpoch = handle.Epoch
	c.mu.Unlock()
	c.commitSource(source)
	return nil
}

func (c *streamCoordinator) clearPreparedHandle(source *terminalPathCandidate, handle resumablestream.CarrierHandle) {
	c.mu.Lock()
	if c.prepared == source && c.handle == handle {
		c.prepared = nil
		c.handle = resumablestream.CarrierHandle{}
	}
	c.mu.Unlock()
}

func (c *streamCoordinator) recoverDetached() {
	c.mu.Lock()
	if c.detached.IsZero() {
		c.detached = time.Now()
	}
	prepared, handle := c.prepared, c.handle
	c.mu.Unlock()
	if prepared == nil {
		return
	}
	if err := c.stream.PromoteCarrier(c.ctx, handle); err != nil {
		c.clearPreparedHandle(prepared, handle)
		return
	}
	c.mu.Lock()
	c.committedEpoch = handle.Epoch
	c.mu.Unlock()
	c.commitSource(prepared)
}

func (c *streamCoordinator) acceptsProtocolEvent(event resumablestream.Event) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return event.CommittedEpoch >= c.committedEpoch
}

func (c *streamCoordinator) clearFailedPrepared(event resumablestream.Event) {
	c.mu.Lock()
	if c.prepared != nil && c.handle.ID != (resumablestream.CarrierID{}) && c.handle.ID == event.FailedCarrier {
		c.prepared = nil
		c.handle = resumablestream.CarrierHandle{}
	}
	c.mu.Unlock()
}

func (c *streamCoordinator) commitSource(source *terminalPathCandidate) {
	c.mu.Lock()
	old := c.current
	c.current = source
	if c.desired == source {
		c.desired = nil
	}
	c.prepared = nil
	c.handle = resumablestream.CarrierHandle{}
	c.detached = time.Time{}
	c.mu.Unlock()
	if old != nil && old != source {
		old.streamsMu.Lock()
		delete(old.streams, c.stream)
		old.streamsMu.Unlock()
		source.streamsMu.Lock()
		source.streams[c.stream] = c
		fallback := source.standby
		revision := source.standbyRevision
		source.streamsMu.Unlock()
		c.setDesiredRevision(fallback, false, revision)
		old.releaseSource()
	}
}

func (c *streamCoordinator) close() {
	c.cancel()
	if c.unsubscribe != nil {
		c.unsubscribe()
	}
	c.mu.Lock()
	current, desired, available := c.current, c.desired, c.available
	c.current, c.desired, c.prepared = nil, nil, nil
	c.available = nil
	c.mu.Unlock()
	if current != nil {
		current.streamsMu.Lock()
		delete(current.streams, c.stream)
		current.streamsMu.Unlock()
		current.releaseSource()
	}
	if desired != nil {
		desired.releaseSource()
	}
	for _, source := range available {
		source.releaseSource()
	}
}

func (c *terminalPathCandidate) retainSource() {
	c.mu.Lock()
	c.sourceRefs++
	c.mu.Unlock()
}

func (c *terminalPathCandidate) releaseSource() {
	c.mu.Lock()
	if c.sourceRefs > 0 {
		c.sourceRefs--
	}
	closeNow := c.sourceRefs == 0 && c.closePending
	if closeNow {
		c.closed = true
	}
	c.mu.Unlock()
	if closeNow {
		go func() { _ = c.closePhysical() }()
	}
}

func (c *terminalPathCandidate) closePhysical() error {
	if c == nil {
		return nil
	}
	c.releaseOnce.Do(func() {
		if c.releaseLease != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			c.releaseErr = c.releaseLease(ctx)
			cancel()
		}
		c.releaseErr = errors.Join(c.releaseErr, c.health.Close())
		if c.cancelCarrier != nil {
			c.cancelCarrier()
		}
	})
	return c.releaseErr
}

func retainedRelayCarrierLifetime(parent context.Context, retained bool) (context.Context, context.CancelFunc) {
	if !retained {
		return parent, nil
	}
	return context.WithCancel(context.Background())
}

// Retained relay candidates use an end-to-end lease over a separate relay
// connection on each peer. Keep the local carrier alive while logical stream
// references drain so candidate_release can reach and close the host carrier.
func (c *terminalPathCandidate) bindRetainedCarrierLifetime(parent, carrier context.Context, cancel context.CancelFunc) {
	if c == nil || parent == nil || carrier == nil || cancel == nil {
		return
	}
	c.cancelCarrier = cancel
	go func() {
		select {
		case <-parent.Done():
			_ = c.Close()
		case <-carrier.Done():
		}
	}()
}

func (c *terminalPathCandidate) Attach(ctx context.Context, attachment terminalAttachment) (Conn, error) {
	if c == nil || ctx == nil || c.attach == nil {
		return nil, ErrPeerTerminalInvalid
	}
	c.mu.Lock()
	expired := !c.expiresAt.IsZero() && c.now != nil && !c.now().UTC().Before(c.expiresAt)
	consumed := c.singleUse && c.attachments > 0
	if c.closed || expired || c.health.State() != connectionmanager.StateTrusted || consumed {
		c.mu.Unlock()
		if expired {
			return nil, ErrPeerCarrierExpired
		}
		if consumed {
			return nil, ErrPeerCarrierConsumed
		}
		return nil, ErrPeerTerminalInvalid
	}
	c.attachments++
	c.mu.Unlock()
	connection, err := c.attach(ctx, attachment)
	if err != nil {
		c.mu.Lock()
		if c.attachments > 0 {
			c.attachments--
		}
		if c.singleUse {
			c.closed = true
		}
		c.mu.Unlock()
		if c.singleUse {
			_ = c.health.Close()
		}
	}
	return connection, err
}

func (c *terminalPathCandidate) State() connectionmanager.State {
	if c == nil || c.health == nil {
		return connectionmanager.StateFailed
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return connectionmanager.StateFailed
	}
	return c.health.State()
}

func (c *terminalPathCandidate) ActiveHealthCapability() (connectionmanager.ActiveHealthCapability, error) {
	if c == nil || c.health == nil {
		return connectionmanager.ActiveHealthCapability{}, ErrPeerTerminalInvalid
	}
	capability, err := c.health.ActiveHealthCapability()
	if err != nil {
		return connectionmanager.ActiveHealthCapability{}, err
	}
	capability.Transport = c
	return capability, nil
}

func (c *terminalPathCandidate) HealthExchange(ctx context.Context, nonce [16]byte) (uint32, error) {
	if c == nil || c.transport == nil {
		return 0, ErrPeerTerminalInvalid
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, ErrPeerTerminalInvalid
	}
	return c.transport.HealthExchange(ctx, nonce)
}

type terminalPTOObserver interface {
	PTOCount() uint32
	PTOChanged() <-chan struct{}
}

func (c *terminalPathCandidate) PTOCount() uint32 {
	observer, _ := c.transport.(terminalPTOObserver)
	if observer == nil {
		return 0
	}
	return observer.PTOCount()
}

func (c *terminalPathCandidate) PTOChanged() <-chan struct{} {
	observer, _ := c.transport.(terminalPTOObserver)
	if observer == nil {
		return nil
	}
	return observer.PTOChanged()
}

func (c *terminalPathCandidate) PathSuspect() {
	// Suspicion is policy input. Coordinators migrate through PREPARE/COMMIT;
	// resumablestream never sends application bytes on an uncommitted carrier.
}

func (c *terminalPathCandidate) PathTrusted() {}

func (c *terminalPathCandidate) AbortApplications(reason error) {
	if c == nil {
		return
	}
	c.streamsMu.Lock()
	streams := make([]*resumablestream.Conn, 0, len(c.streams))
	for stream := range c.streams {
		streams = append(streams, stream)
	}
	c.streams = make(map[*resumablestream.Conn]*streamCoordinator)
	c.streamsMu.Unlock()
	for _, stream := range streams {
		stream.Abort(reason)
	}
}

func (c *terminalPathCandidate) Close() error {
	if c == nil || c.health == nil {
		return nil
	}
	c.mu.Lock()
	if c.poolReleased {
		c.mu.Unlock()
		return nil
	}
	c.poolReleased = true
	if c.sourceRefs > 0 {
		c.closePending = true
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	return c.closePhysical()
}

type terminalRaceConnector struct {
	owner              *PeerTerminalTunnel
	lifetime           context.Context
	target             *resolver.TerminalTarget
	consumer           string
	application        peerApplication
	keyDelivery        *peerTransferKeyDelivery
	descriptors        *directpath.APIDescriptorSource
	oneShotDescriptors map[connectionmanager.Path]*directpath.APIDescriptorSource
	probes             *directpath.APIDescriptorSource
	directRecovery     *directpath.APIDescriptorSource
	relayRecovery      *directpath.APIDescriptorSource
	wssRecovery        *directpath.APIDescriptorSource
	attempts           *peerAttemptTracker
	clientAuthority    *clientauthority.Authority
	networkGeneration  atomic.Uint64
	descriptorMu       sync.Mutex
	descriptorCalls    map[terminalDescriptorKey]*terminalDescriptorCall
	health             *terminalHealthRecorder
	mapping            directpath.SocketMappingSource
}

type terminalDescriptorCall struct {
	ready      chan struct{}
	descriptor directpath.AttemptDescriptor
	authority  peersession.Authority
	err        error
}

type terminalDescriptorKey struct {
	generation uint64
	path       connectionmanager.Path
}

func newTerminalDescriptorKey(generation uint64, path connectionmanager.Path, pathScoped bool) (terminalDescriptorKey, error) {
	if generation == 0 || path != connectionmanager.PathDirectQUIC && path != connectionmanager.PathRelayQUIC && path != connectionmanager.PathWSS {
		return terminalDescriptorKey{}, ErrPeerTerminalInvalid
	}
	key := terminalDescriptorKey{generation: generation}
	if pathScoped {
		key.path = path
	}
	return key, nil
}

func (c *terminalRaceConnector) descriptorSource(path connectionmanager.Path, oneShot bool) (*directpath.APIDescriptorSource, bool) {
	if c == nil {
		return nil, false
	}
	// Multi-path one-shot races need a separate server operation and allowed
	// path policy per candidate. Explicit single-path modes already constrain
	// the shared source to that one path, so no path-scoped map is allocated.
	if oneShot && c.oneShotDescriptors != nil {
		return c.oneShotDescriptors[path], true
	}
	return c.descriptors, false
}

func (c *terminalRaceConnector) descriptor(ctx context.Context, generation uint64, path connectionmanager.Path) (directpath.AttemptDescriptor, peersession.Authority, error) {
	if c == nil || ctx == nil || generation == 0 || c.descriptors == nil || c.owner == nil || c.clientAuthority == nil {
		return directpath.AttemptDescriptor{}, peersession.Authority{}, ErrPeerTerminalInvalid
	}
	// Ordinary transport races retain their established shared-attempt policy.
	// Health probes and transfer-key exchanges use path-scoped descriptors.
	// Each candidate must have its own server-side operation and allowed-path
	// policy. The encrypted transfer binding remains separate and is rebound to
	// the authenticated descriptor context during key exchange.
	oneShot := oneShotPeerOperation(c.application, c.keyDelivery)
	source, pathScoped := c.descriptorSource(path, oneShot)
	key, err := newTerminalDescriptorKey(generation, path, pathScoped)
	if err != nil {
		return directpath.AttemptDescriptor{}, peersession.Authority{}, err
	}
	if source == nil {
		return directpath.AttemptDescriptor{}, peersession.Authority{}, ErrPeerTerminalInvalid
	}
	c.descriptorMu.Lock()
	if call := c.descriptorCalls[key]; call != nil {
		c.descriptorMu.Unlock()
		select {
		case <-call.ready:
			return call.descriptor, call.authority, call.err
		case <-ctx.Done():
			return directpath.AttemptDescriptor{}, peersession.Authority{}, ctx.Err()
		}
	}
	call := &terminalDescriptorCall{ready: make(chan struct{})}
	c.descriptorCalls[key] = call
	c.descriptorMu.Unlock()

	attempt, network := c.owner.attempt.Add(1), c.networkGeneration.Load()
	if attempt == 0 || attempt > math.MaxInt64 || network == 0 || network > math.MaxInt64 {
		call.err = ErrPeerTerminalInvalid
	} else {
		call.descriptor, call.err = source.Acquire(ctx, directpath.Generation{Attempt: attempt, Network: network})
		if call.err == nil {
			call.authority, call.err = peersession.New(peersession.Config{Descriptor: call.descriptor.Document, LocalCertificate: c.clientAuthority.LocalCertificate, PeerCertificate: c.clientAuthority.MachineCertificate, LocalNoisePrivate: c.clientAuthority.LocalKeys.NoisePrivate, Consumer: call.descriptor.Document.Consumer})
		}
		if call.err == nil {
			call.err = c.health.observe(generation, c.networkGeneration.Load(), call.descriptor)
		}
	}
	if errors.Is(call.err, directpath.ErrDescriptorUnavailable) {
		call.err = &terminalTransportError{transport: "peer descriptor", cause: call.err}
	}
	close(call.ready)
	c.descriptorMu.Lock()
	for len(c.descriptorCalls) > terminalGenerationHistory {
		oldest := key
		for candidate := range c.descriptorCalls {
			if candidate.generation < oldest.generation || candidate.generation == oldest.generation && candidate.path < oldest.path {
				oldest = candidate
			}
		}
		if oldest == key {
			break
		}
		delete(c.descriptorCalls, oldest)
	}
	c.descriptorMu.Unlock()
	return call.descriptor, call.authority, call.err
}

func (c *terminalRaceConnector) freshProbeDescriptor(ctx context.Context) (directpath.AttemptDescriptor, peersession.Authority, error) {
	if c == nil || ctx == nil || c.probes == nil || c.owner == nil || c.clientAuthority == nil {
		return directpath.AttemptDescriptor{}, peersession.Authority{}, ErrPeerTerminalInvalid
	}
	attempt, network := c.owner.attempt.Add(1), c.networkGeneration.Load()
	if attempt == 0 || attempt > math.MaxInt64 || network == 0 || network > math.MaxInt64 {
		return directpath.AttemptDescriptor{}, peersession.Authority{}, ErrPeerTerminalInvalid
	}
	descriptor, err := c.probes.Acquire(ctx, directpath.Generation{Attempt: attempt, Network: network})
	if err != nil {
		if errors.Is(err, directpath.ErrDescriptorUnavailable) {
			err = &terminalTransportError{transport: "peer descriptor", cause: err}
		}
		return directpath.AttemptDescriptor{}, peersession.Authority{}, err
	}
	authority, err := peersession.New(peersession.Config{Descriptor: descriptor.Document, LocalCertificate: c.clientAuthority.LocalCertificate, PeerCertificate: c.clientAuthority.MachineCertificate, LocalNoisePrivate: c.clientAuthority.LocalKeys.NoisePrivate, Consumer: "terminal"})
	return descriptor, authority, err
}

func (c *terminalRaceConnector) freshRecoveryDescriptor(ctx context.Context, path connectionmanager.Path) (directpath.AttemptDescriptor, peersession.Authority, error) {
	source := c.directRecovery
	if path == connectionmanager.PathRelayQUIC {
		source = c.relayRecovery
	} else if path == connectionmanager.PathWSS {
		source = c.wssRecovery
	} else if path != connectionmanager.PathDirectQUIC {
		return directpath.AttemptDescriptor{}, peersession.Authority{}, ErrPeerTerminalInvalid
	}
	return c.freshDescriptorFrom(ctx, source, "peer recovery descriptor")
}

func (c *terminalRaceConnector) OpenCandidate(ctx context.Context, attempt connectionmanager.Attempt) (connectionmanager.Connection, error) {
	if c == nil || ctx == nil || attempt.Generation == 0 || attempt.Path != connectionmanager.PathWSS {
		return nil, ErrPeerTerminalInvalid
	}
	started := time.Now()
	descriptor, authority, err := c.freshRecoveryDescriptor(ctx, attempt.Path)
	if err != nil {
		return nil, transportstage.Wrap("descriptor_acquired", err)
	}
	c.logWSSStage(ctx, descriptor, "descriptor_acquired", started, nil)
	c.logWSSStage(ctx, descriptor, "authority_created", started, nil)
	if descriptor.Document.Purpose != "peer_transport" {
		c.releaseRecoveryDescriptor(descriptor, "peer replenishment descriptor revoke failed")
		return nil, transportstage.Wrap("descriptor_acquired", ErrPeerTerminalInvalid)
	}
	attemptCtx, cancel, err := peerRecoveryAttemptContext(ctx, descriptor, c.owner.config.Now())
	if err != nil {
		c.releaseRecoveryDescriptor(descriptor, "peer replenishment descriptor revoke failed")
		return nil, transportstage.Wrap("wss_dial_started", err)
	}
	defer cancel()
	c.logWSSStage(attemptCtx, descriptor, "wss_dial_started", started, nil)
	candidate, err := c.owner.dialWSS(attemptCtx, c.lifetime, c.target, descriptor, authority, c.application, nil)
	if err != nil {
		c.logWSSStage(attemptCtx, descriptor, wssFailureStage(err), started, err)
		c.releaseRecoveryDescriptor(descriptor, "peer replenishment descriptor revoke failed")
		if relayFallbackEligible(c.lifetime, err) {
			err = &connectionmanager.Failure{Class: connectionmanager.FailureTransient, Path: attempt.Path, Cause: err}
		}
		return nil, err
	}
	c.logWSSStage(attemptCtx, descriptor, "candidate_created", started, nil)
	candidate.intentID = descriptor.IntentID
	candidate.attempt = descriptor.AttemptGeneration
	return candidate, nil
}

func (c *terminalRaceConnector) logWSSStage(ctx context.Context, descriptor directpath.AttemptDescriptor, stage string, started time.Time, err error) {
	deadline, _ := ctx.Deadline()
	diagnosticlog.TryInfo("peer WSS setup stage", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration,
		"network_generation", descriptor.NetworkGeneration, "path", "relay_wss", "stage", stage,
		"elapsed_ms", time.Since(started).Milliseconds(), "context_deadline", deadline.UTC().Format(time.RFC3339Nano), "error", err)
}

func wssFailureStage(err error) string {
	var stageErr *transportstage.Error
	if errors.As(err, &stageErr) && stageErr.Stage != "" {
		return stageErr.Stage
	}
	return "candidate_created"
}

func (c *terminalRaceConnector) freshDescriptorFrom(ctx context.Context, source *directpath.APIDescriptorSource, transport string) (directpath.AttemptDescriptor, peersession.Authority, error) {
	if c == nil || ctx == nil || source == nil || c.owner == nil || c.clientAuthority == nil {
		return directpath.AttemptDescriptor{}, peersession.Authority{}, ErrPeerTerminalInvalid
	}
	if source == nil {
		return directpath.AttemptDescriptor{}, peersession.Authority{}, ErrPeerTerminalInvalid
	}
	attempt, network := c.owner.attempt.Add(1), c.networkGeneration.Load()
	if attempt == 0 || attempt > math.MaxInt64 || network == 0 || network > math.MaxInt64 {
		return directpath.AttemptDescriptor{}, peersession.Authority{}, ErrPeerTerminalInvalid
	}
	descriptor, err := source.Acquire(ctx, directpath.Generation{Attempt: attempt, Network: network})
	if err != nil {
		if errors.Is(err, directpath.ErrDescriptorUnavailable) {
			err = &terminalTransportError{transport: transport, cause: err}
		}
		return directpath.AttemptDescriptor{}, peersession.Authority{}, err
	}
	authority, err := peersession.New(peersession.Config{Descriptor: descriptor.Document, LocalCertificate: c.clientAuthority.LocalCertificate, PeerCertificate: c.clientAuthority.MachineCertificate, LocalNoisePrivate: c.clientAuthority.LocalKeys.NoisePrivate, Consumer: descriptor.Document.Consumer})
	return descriptor, authority, err
}

type terminalHealthRecorder struct {
	cache       *connectionmanager.QualityCache
	fingerprint networkadaptation.Fingerprint
	machineID   string
	mu          sync.Mutex
	authority   *connectionmanager.QualityKeyAuthority
	probeKeys   map[connectionmanager.ProbeAttempt]connectionmanager.QualityKey
}

func newTerminalHealthRecorder(fingerprint networkadaptation.Fingerprint, machineID string) (*terminalHealthRecorder, error) {
	if machineID == "" {
		return nil, ErrPeerTerminalInvalid
	}
	cache, err := connectionmanager.NewQualityCache(connectionmanager.DevelopmentQualityPolicy())
	if err != nil {
		return nil, err
	}
	return &terminalHealthRecorder{cache: cache, fingerprint: fingerprint, machineID: machineID, probeKeys: make(map[connectionmanager.ProbeAttempt]connectionmanager.QualityKey)}, nil
}

func (r *terminalHealthRecorder) observeProbe(attempt connectionmanager.ProbeAttempt, descriptor directpath.AttemptDescriptor) error {
	if r == nil || attempt.Generation == 0 || attempt.NetworkGeneration == 0 || descriptor.Document.HostGeneration == 0 || descriptor.Document.AuthorizationGeneration == 0 || descriptor.NetworkGeneration == 0 {
		return ErrPeerTerminalInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.fingerprint.Valid() {
		return ErrPeerTerminalInvalid
	}
	key := connectionmanager.QualityKey{NetworkFingerprint: [32]byte(r.fingerprint), MachineID: r.machineID, HostNetworkGeneration: descriptor.NetworkGeneration, HostProcessGeneration: descriptor.Document.HostGeneration, AuthorizationGeneration: descriptor.Document.AuthorizationGeneration}
	if err := r.publishQualityKeyLocked(key, attempt.NetworkGeneration); err != nil {
		return err
	}
	r.probeKeys[attempt] = key
	for len(r.probeKeys) > terminalGenerationHistory {
		oldest := attempt
		for candidate := range r.probeKeys {
			if candidate.Generation < oldest.Generation {
				oldest = candidate
			}
		}
		if oldest == attempt {
			break
		}
		delete(r.probeKeys, oldest)
	}
	return nil
}

func (r *terminalHealthRecorder) QualityKey(attempt connectionmanager.ProbeAttempt) (connectionmanager.QualityKey, error) {
	if r == nil || attempt.Generation == 0 || attempt.NetworkGeneration == 0 {
		return connectionmanager.QualityKey{}, ErrPeerTerminalInvalid
	}
	r.mu.Lock()
	key, ok := r.probeKeys[attempt]
	r.mu.Unlock()
	if !ok {
		return connectionmanager.QualityKey{}, ErrPeerTerminalInvalid
	}
	return key, nil
}

func (r *terminalHealthRecorder) currentFingerprint() networkadaptation.Fingerprint {
	if r == nil {
		return networkadaptation.Fingerprint{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fingerprint
}

func (r *terminalHealthRecorder) observe(generation, networkGeneration uint64, descriptor directpath.AttemptDescriptor) error {
	if r == nil || generation == 0 || networkGeneration == 0 || descriptor.Document.HostGeneration == 0 || descriptor.Document.AuthorizationGeneration == 0 || descriptor.NetworkGeneration == 0 {
		return ErrPeerTerminalInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.fingerprint.Valid() {
		return ErrPeerTerminalInvalid
	}
	key := connectionmanager.QualityKey{NetworkFingerprint: [32]byte(r.fingerprint), MachineID: r.machineID, HostNetworkGeneration: descriptor.NetworkGeneration, HostProcessGeneration: descriptor.Document.HostGeneration, AuthorizationGeneration: descriptor.Document.AuthorizationGeneration}
	return r.publishQualityKeyLocked(key, networkGeneration)
}

func (r *terminalHealthRecorder) publishQualityKeyLocked(key connectionmanager.QualityKey, networkGeneration uint64) error {
	if r.authority == nil {
		authority, err := connectionmanager.NewQualityKeyAuthority(key, networkGeneration)
		if err != nil {
			return err
		}
		r.authority = authority
		return nil
	}
	return r.authority.Replace(key, networkGeneration)
}

func (r *terminalHealthRecorder) RecordActiveHealth(sample connectionmanager.ActiveHealthSample) error {
	if r == nil {
		return ErrPeerTerminalInvalid
	}
	if sample.Binding.Path == connectionmanager.PathWSS {
		return nil
	}
	r.mu.Lock()
	authority := r.authority
	r.mu.Unlock()
	if authority == nil {
		return ErrPeerTerminalInvalid
	}
	key, err := authority.ActiveHealthQualityKey(sample.Binding)
	if err != nil {
		return err
	}
	return r.cache.Record(key, connectionmanager.QualityObservation{Path: sample.Binding.Path, At: sample.At, Completion: sample.Completed, Succeeded: sample.Succeeded, PTOs: sample.PTOs})
}

func (r *terminalHealthRecorder) applyNetworkEvent(event networkmonitor.Event) {
	if r == nil || !event.Rebind {
		return
	}
	r.mu.Lock()
	r.cache.Invalidate()
	r.probeKeys = make(map[connectionmanager.ProbeAttempt]connectionmanager.QualityKey)
	if r.authority != nil {
		r.authority.ApplyNetworkEvent(event)
	}
	if event.FingerprintValid {
		r.fingerprint = event.Fingerprint
	} else {
		r.fingerprint = networkadaptation.Fingerprint{}
	}
	r.mu.Unlock()
}

type idleRecoveryScheduler struct{}

func (idleRecoveryScheduler) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrPeerTerminalInvalid
	}
	<-ctx.Done()
	return ctx.Err()
}

// adaptiveRecoveryScheduler verifies only the next higher-priority path for
// the currently selected carrier. A successful promotion ends one run; the
// supervisor reconciles and starts the next rung without touching consumers.
type adaptiveRecoveryScheduler struct {
	pool      *connectionmanager.Pool
	scheduler *connectionmanager.ProbeScheduler
	mode      connectionmanager.Mode
}

func (s adaptiveRecoveryScheduler) Run(ctx context.Context) error {
	if s.pool == nil || s.scheduler == nil || ctx == nil {
		return ErrPeerTerminalInvalid
	}
	snapshot, err := s.pool.Snapshot(peerquic.ClassInteractive)
	if err != nil || !snapshot.Selected {
		return err
	}
	path := connectionmanager.PathDirectQUIC
	if snapshot.Path == connectionmanager.PathWSS {
		path = connectionmanager.PathRelayQUIC
	} else if snapshot.Path == connectionmanager.PathRelayQUIC && s.mode == connectionmanager.ModeRelayRace {
		<-ctx.Done()
		return ctx.Err()
	}
	if err := s.scheduler.SetPath(path); err != nil {
		return err
	}
	return s.scheduler.Run(ctx)
}

func (c *terminalRaceConnector) Connect(ctx context.Context, attempt connectionmanager.Attempt) (connectionmanager.Connection, error) {
	if c == nil || c.owner == nil || ctx == nil || c.lifetime == nil || attempt.Generation == 0 {
		return nil, ErrPeerTerminalInvalid
	}
	descriptor, sessionAuthority, err := c.descriptor(ctx, attempt.Generation, attempt.Path)
	if err != nil {
		return nil, err
	}
	var connection *terminalPathCandidate
	switch attempt.Path {
	case connectionmanager.PathDirectQUIC:
		fingerprint := c.health.currentFingerprint()
		if !fingerprint.Valid() {
			return nil, &connectionmanager.Failure{Class: connectionmanager.FailureReachability, Path: attempt.Path, Cause: errors.New("network fingerprint unavailable")}
		}
		connection, err = c.owner.dialDirect(ctx, c.lifetime, c.target, descriptor, sessionAuthority, *c.clientAuthority, fingerprint, c.mapping, c.application, c.keyDelivery)
		err = classifyDirectFailure(c.lifetime, attempt.Path, err)
	case connectionmanager.PathRelayQUIC:
		fingerprint := c.health.currentFingerprint()
		if !fingerprint.Valid() {
			return nil, &connectionmanager.Failure{Class: connectionmanager.FailureReachability, Path: attempt.Path, Cause: errors.New("network fingerprint unavailable")}
		}
		relayCtx, cancel := context.WithTimeout(ctx, time.Duration(descriptor.Document.Policy.RelayDeadlineMS)*time.Millisecond)
		connection, err = c.owner.dialRelayQUIC(relayCtx, c.lifetime, c.target, descriptor, sessionAuthority, fingerprint, c.application, c.keyDelivery)
		cancel()
		if err != nil && relayFallbackEligible(c.lifetime, err) {
			err = &connectionmanager.Failure{Class: connectionmanager.FailureTransient, Path: attempt.Path, Cause: err}
		}
	case connectionmanager.PathWSS:
		relayCtx, cancel := context.WithTimeout(ctx, time.Duration(descriptor.Document.Policy.RelayDeadlineMS)*time.Millisecond)
		connection, err = c.owner.dialWSS(relayCtx, c.lifetime, c.target, descriptor, sessionAuthority, c.application, c.keyDelivery)
		cancel()
		if err != nil && relayFallbackEligible(c.lifetime, err) {
			err = &connectionmanager.Failure{Class: connectionmanager.FailureTransient, Path: attempt.Path, Cause: err}
		}
	default:
		return nil, ErrPeerTerminalInvalid
	}
	if err != nil {
		return nil, err
	}
	connection.intentID = descriptor.IntentID
	connection.attempt = descriptor.AttemptGeneration
	// Lifetime measurement is diagnostic-only. It must never run as part of
	// application carrier admission: a probe endpoint may legitimately close
	// after its bounded exchange, and that failure must not poison direct and
	// force the auto race to reject a usable relay fallback.
	return connection, nil
}

// DialLifetimeProbe supplies the authenticated direct probe used by the
// network-adaptation lifetime measurer. Each attempt receives a fresh
// descriptor and is closed after one bounded idle observation.
func (c *terminalRaceConnector) DialLifetimeProbe(ctx context.Context, idle time.Duration) (networkadaptation.QUICProbeSession, error) {
	if c == nil || ctx == nil || idle <= 0 || c.health == nil {
		return nil, ErrPeerTerminalInvalid
	}
	fingerprint := c.health.currentFingerprint()
	if !fingerprint.Valid() {
		return nil, ErrPeerTerminalInvalid
	}
	descriptor, authority, err := c.freshProbeDescriptor(ctx)
	if err != nil {
		return nil, err
	}
	if descriptor.Document.Purpose != "direct_probe" {
		return nil, ErrPeerTerminalInvalid
	}
	candidate, err := c.owner.dialDirect(ctx, c.lifetime, c.target, descriptor, authority, *c.clientAuthority, fingerprint, c.mapping, c.application, nil)
	if err != nil {
		return nil, err
	}
	return lifetimeProbeCandidate{candidate: candidate}, nil
}

type lifetimeProbeCandidate struct{ candidate *terminalPathCandidate }

func (p lifetimeProbeCandidate) ProbeAfterIdle(ctx context.Context, idle time.Duration) (time.Time, error) {
	if p.candidate == nil || ctx == nil || idle <= 0 {
		return time.Time{}, ErrPeerTerminalInvalid
	}
	health, ok := p.candidate.health.(*directpath.HealthConnection)
	if !ok || health.Session == nil {
		return time.Time{}, ErrPeerTerminalInvalid
	}
	return health.Session.ProbeAfterIdle(ctx, idle)
}

func (p lifetimeProbeCandidate) Close() error {
	if p.candidate == nil {
		return nil
	}
	return p.candidate.Close()
}

func (c *terminalRaceConnector) DialProbe(ctx context.Context, attempt connectionmanager.ProbeAttempt) (connectionmanager.ProbeTransport, error) {
	if c == nil || ctx == nil || attempt.Generation == 0 || attempt.NetworkGeneration == 0 || c.health == nil {
		return nil, ErrPeerTerminalInvalid
	}
	fingerprint := c.health.currentFingerprint()
	if !fingerprint.Valid() {
		return nil, &connectionmanager.Failure{Class: connectionmanager.FailureReachability, Path: connectionmanager.PathDirectQUIC, Cause: errors.New("network fingerprint unavailable")}
	}
	path := attempt.Path
	if path == 0 {
		path = connectionmanager.PathDirectQUIC
	}
	descriptor, authority, err := c.freshRecoveryDescriptor(ctx, path)
	if err != nil {
		return nil, err
	}
	logStage := func(stage string, stageErr error) {
		diagnosticlog.TryInfo("peer recovery candidate stage", "path", uint8(path), "probe_generation", attempt.Generation, "network_generation", attempt.NetworkGeneration, "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "stage", stage, "error", stageErr)
	}
	logStage("descriptor_acquired", nil)
	if descriptor.Document.Purpose != "peer_transport" {
		c.releaseRecoveryDescriptor(descriptor, "peer recovery descriptor revoke failed")
		return nil, ErrPeerTerminalInvalid
	}
	if err := c.health.observeProbe(attempt, descriptor); err != nil {
		logStage("quality_bound", err)
		return nil, err
	}
	probeCtx, cancelProbe, err := peerRecoveryAttemptContext(ctx, descriptor, c.owner.config.Now())
	if err != nil {
		logStage("attempt_context", err)
		c.releaseRecoveryDescriptor(descriptor, "peer recovery descriptor revoke failed")
		return nil, err
	}
	defer cancelProbe()
	var candidate *terminalPathCandidate
	switch path {
	case connectionmanager.PathDirectQUIC:
		candidate, err = c.owner.dialDirect(probeCtx, c.lifetime, c.target, descriptor, authority, *c.clientAuthority, fingerprint, c.mapping, c.application, nil)
		err = classifyDirectFailure(c.lifetime, path, err)
	case connectionmanager.PathRelayQUIC:
		candidate, err = c.owner.dialRelayQUIC(probeCtx, c.lifetime, c.target, descriptor, authority, fingerprint, c.application, nil)
		if err != nil && relayFallbackEligible(c.lifetime, err) {
			err = &connectionmanager.Failure{Class: connectionmanager.FailureTransient, Path: path, Cause: err}
		}
	default:
		c.releaseRecoveryDescriptor(descriptor, "peer recovery descriptor revoke failed")
		return nil, ErrPeerTerminalInvalid
	}
	if err != nil {
		logStage("candidate_dialed", err)
		c.releaseRecoveryDescriptor(descriptor, "peer recovery descriptor revoke failed")
		return nil, err
	}
	candidate.intentID = descriptor.IntentID
	candidate.attempt = descriptor.AttemptGeneration
	logStage("candidate_dialed", nil)
	return candidate, nil
}

func peerRecoveryAttemptContext(parent context.Context, descriptor directpath.AttemptDescriptor, now time.Time) (context.Context, context.CancelFunc, error) {
	if parent == nil || descriptor.Document.Policy.RelayDeadlineMS < 100 || descriptor.ExpiresAt.IsZero() {
		return nil, nil, ErrPeerTerminalInvalid
	}
	deadline := now.Add(time.Duration(descriptor.Document.Policy.RelayDeadlineMS) * time.Millisecond)
	if descriptor.ExpiresAt.Before(deadline) {
		deadline = descriptor.ExpiresAt
	}
	if !deadline.After(now) {
		return nil, nil, ErrPeerCarrierExpired
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	return ctx, cancel, nil
}

func (c *terminalRaceConnector) releaseRecoveryDescriptor(descriptor directpath.AttemptDescriptor, code string) {
	if c == nil || c.attempts == nil {
		return
	}
	if err := c.attempts.Release(descriptor); err != nil {
		diagnosticlog.TryInfo(code, "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "error", err)
	}
}

func (t *PeerTerminalTunnel) dialWSS(ctx, lifetime context.Context, target *resolver.TerminalTarget, descriptor directpath.AttemptDescriptor, authority peersession.Authority, application peerApplication, keyDelivery *peerTransferKeyDelivery) (*terminalPathCandidate, error) {
	maximumDeadline := descriptor.ExpiresAt.Sub(t.config.Now().UTC())
	if maximumDeadline <= 0 {
		return nil, ErrPeerTerminalInvalid
	}
	carrierLifetime, cancelCarrier := retainedRelayCarrierLifetime(lifetime, descriptor.Document.Purpose == "peer_transport")
	carrierLifetimeOwned := false
	defer func() {
		if cancelCarrier != nil && !carrierLifetimeOwned {
			cancelCarrier()
		}
	}()
	connection, err := relaycarrier.DialWSS(ctx, relaycarrier.WSSDialConfig{URL: descriptor.RelayWSSURL, Credential: descriptor.RelayCredential, StreamHandle: authority.RouteHandle, EndpointID: authority.LocalEndpointID(), Role: "initiator", RelayID: descriptor.RelayRegion, TLS: t.config.TLS.Clone(), HTTPClient: t.config.HTTPClient, Lifetime: carrierLifetime, MaximumDeadline: maximumDeadline, Carrier: relaycarrier.DevelopmentConfig()})
	if err != nil {
		if certificateError(err) {
			return nil, fmt.Errorf("verify peer WSS relay certificate: %w", err)
		}
		return nil, transportstage.Wrap("wss_dial_authenticated", err)
	}
	diagnosticlog.TryInfo("peer WSS setup stage", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "network_generation", descriptor.NetworkGeneration, "path", "relay_wss", "stage", "wss_dial_authenticated")
	health, initial, err := newPeerRelayHealthConnection(connection, authority)
	if err != nil {
		return nil, transportstage.Wrap("noise_started", errors.Join(err, connection.Close()))
	}
	diagnosticlog.TryInfo("peer WSS setup stage", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "network_generation", descriptor.NetworkGeneration, "path", "relay_wss", "stage", "noise_started")
	if err := admitPeerRelayHealth(ctx, health, initial); err != nil {
		return nil, transportstage.Wrap("health_admission_started", errors.Join(err, connection.Close()))
	}
	diagnosticlog.TryInfo("peer WSS setup stage", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "network_generation", descriptor.NetworkGeneration, "path", "relay_wss", "stage", "noise_authenticated")
	diagnosticlog.TryInfo("peer WSS setup stage", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "network_generation", descriptor.NetworkGeneration, "path", "relay_wss", "stage", "health_admission_succeeded")
	initiator := nativepeer.Initiator{Connection: connection, Authority: authority}
	var candidate *terminalPathCandidate
	candidate, candidateErr := newRelayTerminalPathCandidate(descriptor.RelayRegion, health, func(attachCtx context.Context, attachment terminalAttachment) (Conn, error) {
		target, application, keyDelivery := attachment.target, attachment.application, attachment.keyDelivery
		var authorizedGroup nativeStreamGroup
		if descriptor.Document.Purpose == "peer_transport" {
			authorizedGroup = &authorizedPeerRelayStreamGroup{initiator: initiator, authority: authority, lifetime: lifetime, target: target, application: application, fallbackOperation: descriptor.Document.OperationID, now: t.config.Now, candidate: candidate}
		}
		if keyDelivery != nil {
			stream, openErr := initiator.Open(attachCtx, "transfer-key-control")
			if openErr != nil {
				return nil, errors.Join(ErrPeerStreamOpen, openErr)
			}
			deliverErr := keyDelivery.exchange(stream, authority.Context)
			closeErr := stream.Close()
			if deliverErr != nil || closeErr != nil {
				return nil, errors.Join(deliverErr, closeErr)
			}
			return completedPeerConn{}, nil
		}
		if application.raw != nil {
			var stream io.ReadWriteCloser
			var openErr error
			if authorizedGroup != nil {
				stream, openErr = authorizedGroup.OpenStream(attachCtx)
			} else {
				stream, openErr = initiator.Open(attachCtx, application.stream)
			}
			if openErr != nil {
				return nil, errors.Join(ErrPeerStreamOpen, openErr)
			}
			result, attachErr := application.raw(attachCtx, stream)
			if attachErr != nil {
				return nil, errors.Join(attachErr, stream.Close())
			}
			return result, nil
		}
		var message *nativeMessageConnection
		var attachErr error
		if authorizedGroup != nil {
			message, attachErr = authenticateUnifiedNativeStream(attachCtx, authorizedGroup, target, "WSS")
		} else {
			message, attachErr = AuthenticatePeerWSS(attachCtx, initiator, target)
		}
		if attachErr != nil {
			return nil, attachErr
		}
		result, attachErr := application.helper(attachCtx, message, target)
		if attachErr != nil {
			return nil, errors.Join(attachErr, message.Close())
		}
		return result, nil
	})
	if candidateErr != nil {
		return nil, candidateErr
	}
	candidate.singleUse = descriptor.Document.Purpose != "peer_transport"
	candidate.openAuthorized = func(openCtx context.Context, header streamauth.Header) (net.Conn, error) {
		return initiator.OpenAuthorized(openCtx, header)
	}
	if descriptor.Document.Purpose != "peer_transport" {
		candidate.expiresAt, candidate.now = descriptor.ExpiresAt, t.config.Now
	} else {
		if err := adoptRelayCandidate(ctx, candidate, health, initiator, descriptor, "relay_wss"); err != nil {
			return nil, errors.Join(err, candidate.health.Close())
		}
		candidate.bindRetainedCarrierLifetime(lifetime, carrierLifetime, cancelCarrier)
		carrierLifetimeOwned = true
	}
	return candidate, nil
}

func directFallbackEligible(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	for _, terminal := range []error{signaling.ErrTransportAuthentication, signaling.ErrTransportCertificate, signaling.ErrTransportProtocol, signaling.ErrInvalid, signaling.ErrStale, signaling.ErrSequence, signaling.ErrLimit, directpath.ErrDescriptorInvalid, directpath.ErrDescriptorUnauthorized, directpath.ErrDescriptorRevoked, peerquic.ErrBinding, peerquic.ErrRecord} {
		if errors.Is(err, terminal) {
			return false
		}
	}
	var failure *connectionmanager.Failure
	if errors.As(err, &failure) {
		return failure.AllowsFallback()
	}
	if errors.Is(err, directpath.ErrReachability) || errors.Is(err, directpath.ErrDescriptorUnavailable) || errors.Is(err, iceagent.ErrConnectionFailed) || errors.Is(err, iceagent.ErrConnectionClosed) || errors.Is(err, signaling.ErrTransportUnavailable) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func classifyDirectFailure(ctx context.Context, path connectionmanager.Path, err error) error {
	if !directFallbackEligible(ctx, err) {
		return err
	}
	var failure *connectionmanager.Failure
	if errors.As(err, &failure) {
		return err
	}
	class := connectionmanager.FailureReachability
	if errors.Is(err, directpath.ErrReachability) || errors.Is(err, iceagent.ErrConnectionFailed) || errors.Is(err, iceagent.ErrConnectionClosed) {
		class = connectionmanager.FailureNAT
	} else {
		var networkError net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout() {
			class = connectionmanager.FailureTimeout
		}
	}
	return &connectionmanager.Failure{Class: class, Path: path, Cause: err}
}

func relayFallbackEligible(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	var failure *connectionmanager.Failure
	if errors.As(err, &failure) {
		return failure.AllowsFallback()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return true
	}
	// A relay QUIC dial can fail synchronously when local policy blocks UDP.
	// net.OpError preserves that this was a network operation even when the
	// underlying syscall (for example EPERM) doesn't implement net.Error.
	var operationError *net.OpError
	return errors.As(err, &operationError)
}

type peerQUICNativeStreamGroup struct {
	session *peerquic.Session
	close   func() error
	binding [32]byte
	done    chan struct{}
	once    sync.Once
	err     error
}

type authorizedPeerQUICStreamGroup struct {
	*peerQUICNativeStreamGroup
	lifetime          context.Context
	authority         peersession.Authority
	target            *resolver.TerminalTarget
	application       peerApplication
	consumer          string
	fallbackOperation string
	now               func() time.Time
	mu                sync.Mutex
	streams           []io.Closer
	closed            bool
	candidate         *terminalPathCandidate
}

type authorizedPeerRelayStreamGroup struct {
	initiator         nativepeer.Initiator
	authority         peersession.Authority
	lifetime          context.Context
	target            *resolver.TerminalTarget
	application       peerApplication
	fallbackOperation string
	now               func() time.Time
	mu                sync.Mutex
	streams           []io.Closer
	closed            bool
	candidate         *terminalPathCandidate
}

func (g *authorizedPeerRelayStreamGroup) OpenStream(ctx context.Context) (nativeStream, error) {
	if g == nil || g.now == nil {
		return nil, ErrPeerTerminalInvalid
	}
	streamID, err := nextAuthorizedStreamID()
	if err != nil {
		return nil, err
	}
	header, err := g.application.authorizationHeader(g.target, g.application.consumer, g.fallbackOperation, streamID, g.now().UTC())
	if err != nil {
		return nil, err
	}
	diagnosticlog.TryInfo("peer relay authorized stream opening", "consumer", header.Consumer, "operation_id", header.OperationID, "stream_id", header.StreamID)
	stream, err := g.initiator.OpenAuthorized(ctx, header)
	if err != nil {
		return nil, err
	}
	diagnosticlog.TryInfo("peer relay authorized stream opened", "consumer", header.Consumer, "operation_id", header.OperationID, "stream_id", header.StreamID)
	resumable, err := g.newResumableStream(header)
	if err != nil {
		return nil, errors.Join(err, stream.Close())
	}
	if err := resumable.AttachInitial(ctx, asResumableCarrier(stream)); err != nil {
		return nil, errors.Join(err, resumable.Close())
	}
	diagnosticlog.TryInfo("peer relay resumable stream attached", "consumer", header.Consumer, "operation_id", header.OperationID, "stream_id", header.StreamID)
	g.candidate.trackStream(header, resumable)
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, errors.Join(net.ErrClosed, resumable.Close())
	}
	g.streams = append(g.streams, resumable)
	g.mu.Unlock()
	return resumable, nil
}

func (g *authorizedPeerRelayStreamGroup) newResumableStream(header streamauth.Header) (*resumablestream.Conn, error) {
	if g == nil {
		return nil, ErrPeerTerminalInvalid
	}
	return resumablestream.New(g.lifetime, resumablestream.Config{WindowBytes: 512 << 10, Role: resumablestream.RoleInitiator, Identity: resumablestream.StreamIdentity{Principal: g.authority.LocalEndpointID(), OperationID: header.OperationID, Consumer: header.Consumer, StreamID: header.StreamID}})
}

func (g *authorizedPeerRelayStreamGroup) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	streams := append([]io.Closer(nil), g.streams...)
	g.streams = nil
	g.mu.Unlock()
	var result error
	for _, stream := range streams {
		result = errors.Join(result, stream.Close())
	}
	return result
}

func (g *authorizedPeerQUICStreamGroup) OpenStream(ctx context.Context) (nativeStream, error) {
	if g == nil || g.peerQUICNativeStreamGroup == nil || g.now == nil {
		return nil, ErrPeerTerminalInvalid
	}
	streamID, err := nextAuthorizedStreamID()
	if err != nil {
		return nil, err
	}
	header, err := g.application.authorizationHeader(g.target, g.consumer, g.fallbackOperation, streamID, g.now().UTC())
	if err != nil {
		return nil, err
	}
	streamAuthority, err := g.authority.InitiatorStream(header.Grant())
	if err != nil {
		return nil, err
	}
	binding, err := peerquic.ExporterBindingForStream(g.session.Connection.ConnectionState().TLS, g.authority.Transport, streamAuthority.Stream)
	if err != nil {
		return nil, err
	}
	stream, err := g.session.Connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	bound := &boundNativeStream{nativeStream: stream, binding: binding}
	encoded, err := header.MarshalBinary()
	if err != nil {
		return nil, errors.Join(err, stream.Close())
	}
	if err := bound.WriteFirst(encoded); err != nil {
		return nil, errors.Join(err, stream.Close())
	}
	resumable, err := g.newResumableStream(header)
	if err != nil {
		return nil, errors.Join(err, stream.Close())
	}
	if err := resumable.AttachInitial(ctx, asResumableCarrier(stream)); err != nil {
		return nil, errors.Join(err, resumable.Close())
	}
	g.candidate.trackStream(header, resumable)
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, errors.Join(net.ErrClosed, resumable.Close())
	}
	g.streams = append(g.streams, resumable)
	g.mu.Unlock()
	return resumable, nil
}

func (g *authorizedPeerQUICStreamGroup) newResumableStream(header streamauth.Header) (*resumablestream.Conn, error) {
	if g == nil {
		return nil, ErrPeerTerminalInvalid
	}
	return resumablestream.New(g.lifetime, resumablestream.Config{WindowBytes: 512 << 10, Role: resumablestream.RoleInitiator, Identity: resumablestream.StreamIdentity{Principal: g.authority.LocalEndpointID(), OperationID: header.OperationID, Consumer: header.Consumer, StreamID: header.StreamID}})
}

func asResumableCarrier(stream nativeStream) net.Conn {
	if connection, ok := stream.(net.Conn); ok {
		return connection
	}
	return &nativeStreamCarrier{nativeStream: stream}
}

type nativeStreamCarrier struct{ nativeStream }

func (c *nativeStreamCarrier) LocalAddr() net.Addr  { return peerStreamAddr("local") }
func (c *nativeStreamCarrier) RemoteAddr() net.Addr { return peerStreamAddr("peer") }
func (c *nativeStreamCarrier) SetDeadline(value time.Time) error {
	if stream, ok := c.nativeStream.(interface{ SetDeadline(time.Time) error }); ok {
		return stream.SetDeadline(value)
	}
	return nil
}
func (c *nativeStreamCarrier) SetReadDeadline(value time.Time) error {
	if stream, ok := c.nativeStream.(interface{ SetReadDeadline(time.Time) error }); ok {
		return stream.SetReadDeadline(value)
	}
	return nil
}
func (c *nativeStreamCarrier) SetWriteDeadline(value time.Time) error {
	if stream, ok := c.nativeStream.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return stream.SetWriteDeadline(value)
	}
	return nil
}

type peerStreamAddr string

func (peerStreamAddr) Network() string  { return "paperboat-peer-stream" }
func (a peerStreamAddr) String() string { return string(a) }

func nextAuthorizedStreamID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errors.Join(ErrPeerTerminalInvalid, err)
	}
	return hex.EncodeToString(value[:]), nil
}

func (g *authorizedPeerQUICStreamGroup) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	streams := append([]io.Closer(nil), g.streams...)
	g.streams = nil
	g.mu.Unlock()
	var result error
	for _, stream := range streams {
		result = errors.Join(result, stream.Close())
	}
	return result
}

func newPeerQUICNativeStreamGroup(ctx context.Context, session *peerquic.Session, close func() error, binding [32]byte) *peerQUICNativeStreamGroup {
	group := &peerQUICNativeStreamGroup{session: session, close: close, binding: binding, done: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = group.Close()
		case <-group.done:
		}
	}()
	return group
}

func (g *peerQUICNativeStreamGroup) OpenStream(ctx context.Context) (nativeStream, error) {
	if g == nil || g.session == nil || g.session.Connection == nil {
		return nil, ErrPeerTerminalInvalid
	}
	stream, err := g.session.Connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &boundNativeStream{nativeStream: stream, binding: g.binding}, nil
}

func (g *peerQUICNativeStreamGroup) Close() error {
	if g == nil {
		return nil
	}
	g.once.Do(func() {
		if g.close != nil {
			g.err = g.close()
		} else {
			g.err = g.session.Close()
		}
		close(g.done)
	})
	return g.err
}

func (t *PeerTerminalTunnel) networkOwner() (*networkmonitor.Monitor, networkadaptation.Fingerprint, <-chan networkmonitor.Event, bool) {
	t.networkMu.Lock()
	if t.sharedMonitor != nil {
		monitor, fingerprint := t.sharedMonitor, t.sharedFingerprint
		t.networkMu.Unlock()
		return monitor, fingerprint, nil, true
	}
	t.networkMu.Unlock()
	secret, err := t.config.Store.NetworkFingerprintSecret()
	if err != nil {
		return nil, networkadaptation.Fingerprint{}, nil, false
	}
	defer clear(secret)
	events := make(chan networkmonitor.Event, 16)
	monitor, err := networkmonitor.NewFingerprinting(secret, nil, func(event networkmonitor.Event) {
		if !event.Rebind {
			return
		}
		if !t.observeNetworkFingerprint(event.Fingerprint, event.FingerprintValid) {
			return
		}
		t.advanceNetwork()
		select {
		case events <- event:
		default:
		}
	})
	if err != nil || monitor.Start() != nil {
		if monitor != nil {
			_ = monitor.Close()
		}
		return nil, networkadaptation.Fingerprint{}, nil, false
	}
	_, _ = monitor.NewPortMappingManager(networkmonitor.PortMappingConfig{
		SocketVerifier: networkcheck.MappingVerifier{Resolver: net.DefaultResolver, Timeout: 500 * time.Millisecond},
		ProbeTimeout:   500 * time.Millisecond, CreateTimeout: 3 * time.Second, EnableUPnP: true,
	})
	fingerprint, fingerprintErr := monitor.CurrentFingerprint()
	t.observeNetworkFingerprint(fingerprint, fingerprintErr == nil && fingerprint.Valid())
	return monitor, fingerprint, events, false
}

// observeNetworkFingerprint suppresses the initial callback from each per-dial
// monitor. Only a real network identity change may fence other attempts.
func (t *PeerTerminalTunnel) observeNetworkFingerprint(fingerprint networkadaptation.Fingerprint, valid bool) bool {
	if !valid {
		return true
	}
	t.networkFingerprintMu.Lock()
	defer t.networkFingerprintMu.Unlock()
	changed := t.networkFingerprintOK && t.networkFingerprint != fingerprint
	t.networkFingerprint = fingerprint
	t.networkFingerprintOK = true
	return changed
}

func (t *PeerTerminalTunnel) advanceNetwork() {
	for {
		current := t.network.Load()
		if current == math.MaxUint64 || t.network.CompareAndSwap(current, current+1) {
			t.networkCheckMu.Lock()
			t.networkChecks = make(map[networkadaptation.Fingerprint]networkcheck.STUNObservation)
			t.networkCheckMu.Unlock()
			t.ipv6Mu.Lock()
			t.ipv6Viable = make(map[networkadaptation.Fingerprint]bool)
			t.ipv6Known = make(map[networkadaptation.Fingerprint]bool)
			t.ipv6Active = make(map[networkadaptation.Fingerprint]bool)
			t.ipv6Mu.Unlock()
			if t.regionalCache != nil {
				t.regionalCache.Invalidate()
			}
			return
		}
	}
}

func (t *PeerTerminalTunnel) cachedIPv6Viability(fingerprint networkadaptation.Fingerprint) (bool, bool) {
	if t == nil || !fingerprint.Valid() {
		return false, false
	}
	t.ipv6Mu.RLock()
	defer t.ipv6Mu.RUnlock()
	return t.ipv6Viable[fingerprint], t.ipv6Known[fingerprint]
}

func (t *PeerTerminalTunnel) recordIPv6Viability(fingerprint networkadaptation.Fingerprint, viable bool) {
	if t == nil || !fingerprint.Valid() {
		return
	}
	t.ipv6Mu.Lock()
	t.ipv6Viable[fingerprint], t.ipv6Known[fingerprint], t.ipv6Active[fingerprint] = viable, true, false
	t.ipv6Mu.Unlock()
}

func (t *PeerTerminalTunnel) warmIPv6Viability(ctx context.Context, regions []networkcheck.ProbeRegion) {
	if t == nil || ctx == nil || len(regions) == 0 {
		return
	}
	_, fingerprint, _, shared := t.networkOwner()
	if !shared || !fingerprint.Valid() {
		return
	}
	t.ipv6Mu.Lock()
	if t.ipv6Known[fingerprint] || t.ipv6Active[fingerprint] {
		t.ipv6Mu.Unlock()
		return
	}
	t.ipv6Active[fingerprint] = true
	t.ipv6Mu.Unlock()
	urls := make([]string, 0, min(len(regions), 8))
	for _, region := range regions {
		if region.STUNURL != "" && len(urls) < 8 {
			urls = append(urls, region.STUNURL)
		}
	}
	go func() {
		probeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		viable := networkcheck.ProbeSTUNReachability(probeCtx, "ip6", urls, net.DefaultResolver, 250*time.Millisecond)
		t.recordIPv6Viability(fingerprint, viable)
	}()
}

func (t *PeerTerminalTunnel) regionalLatencyMonitor(client *api.Client, currentRegion func() string) (*networkcheck.RegionalMonitor, error) {
	if t == nil || client == nil || currentRegion == nil || t.regionalCache == nil {
		return nil, ErrPeerTerminalInvalid
	}
	httpClient := t.config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 3 * time.Second}
	}
	probe, err := networkcheck.NewRegionalProbe(networkcheck.RegionalProbeConfig{Timeout: 3 * time.Second, STUN: networkcheck.STUNRegionalLatency(net.DefaultResolver, 1500*time.Millisecond), HTTPS: networkcheck.HTTPSRegionalLatency(t.config.Now, httpClient)})
	if err != nil {
		return nil, err
	}
	monitor, err := networkcheck.NewRegionalMonitor(networkcheck.RegionalMonitorConfig{
		Inventory: func(ctx context.Context) ([]networkcheck.ProbeRegion, error) {
			document, inventoryErr := client.NetworkCheckRegions(ctx)
			if inventoryErr != nil {
				return nil, inventoryErr
			}
			regions := make([]networkcheck.ProbeRegion, 0, len(document.Regions))
			for _, region := range document.Regions {
				regions = append(regions, networkcheck.ProbeRegion{Region: region.Region, STUNURL: region.STUNURL, HTTPSURL: region.HTTPSURL})
			}
			if len(regions) > 0 {
				t.networkMu.Lock()
				networkOwner := t.sharedMonitor
				t.networkMu.Unlock()
				if networkOwner != nil {
					warmMappingCtx, cancelMapping := context.WithTimeout(ctx, time.Second)
					_ = networkOwner.WarmSocketMapping(warmMappingCtx, t.network.Load(), regions[0].STUNURL)
					cancelMapping()
				}
				var signalingWarm sync.WaitGroup
				var signalingWarmMu sync.Mutex
				var signalingWarmErr error
				for _, region := range regions[:min(len(regions), 16)] {
					signalingURL, urlErr := signalingURLFromProbe(region.HTTPSURL)
					if urlErr != nil {
						continue
					}
					signalingWarm.Add(1)
					go func() {
						defer signalingWarm.Done()
						warmCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
						defer cancel()
						if warmErr := t.signalingSubstrate.Warm(warmCtx, signalingURL, t.config.TLS); warmErr != nil {
							signalingWarmMu.Lock()
							signalingWarmErr = errors.Join(signalingWarmErr, warmErr)
							signalingWarmMu.Unlock()
						}
					}()
				}
				signalingWarm.Wait()
				if signalingWarmErr != nil {
					return nil, signalingWarmErr
				}
			}
			t.warmIPv6Viability(ctx, regions)
			return regions, nil
		},
		Probe: probe, Cache: t.regionalCache, Clock: t.config.Now, CurrentRegion: currentRegion,
		FullInterval: 5 * time.Minute, IncrementalInterval: time.Minute, Jitter: func(value time.Duration) time.Duration { return value },
	})
	if err != nil {
		return nil, err
	}
	return monitor, nil
}

func signalingURLFromProbe(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", ErrPeerTerminalInvalid
	}
	parsed.Scheme = "wss"
	parsed.Path, parsed.RawPath, parsed.RawQuery, parsed.Fragment = "/v1/peer-signaling", "", "", ""
	return parsed.String(), nil
}

func (t *PeerTerminalTunnel) relayLatencyVector() *api.RelayLatencyVector {
	if t == nil || t.regionalCache == nil {
		return nil
	}
	now := t.config.Now().UTC()
	vector := t.regionalCache.Vector(now)
	if len(vector.Samples) == 0 {
		return nil
	}
	t.relaySuccessMu.RLock()
	successRegion, successAt := t.relaySuccessRegion, t.relaySuccessAt
	t.relaySuccessMu.RUnlock()
	if successAt.IsZero() || successAt.After(now) || now.Sub(successAt) > 30*time.Second {
		successRegion, successAt = "", time.Time{}
	}
	result := &api.RelayLatencyVector{Generation: t.regionalVector.Add(1), ObservedAt: now, Samples: make([]api.RelayLatencySample, 0, len(vector.Samples)), RelaySuccessRegion: successRegion, RelaySuccessAt: successAt}
	for _, sample := range vector.Samples {
		milliseconds := (sample.RTT + time.Millisecond - 1) / time.Millisecond
		if milliseconds < 1 || milliseconds > 60_000 {
			return nil
		}
		result.Samples = append(result.Samples, api.RelayLatencySample{Region: sample.Region, RTTMS: int64(milliseconds)})
	}
	return result
}

func (t *PeerTerminalTunnel) observeRelaySuccess(region string) {
	if region == "" {
		return
	}
	t.relaySuccessMu.Lock()
	t.relaySuccessRegion, t.relaySuccessAt = region, t.config.Now().UTC()
	t.relaySuccessMu.Unlock()
}

func (t *PeerTerminalTunnel) observeRelayPromotions(ctx context.Context, pool *connectionmanager.Pool, generation uint64, region string) {
	if t == nil || ctx == nil || pool == nil {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snapshot, err := pool.Snapshot(peerquic.ClassInteractive)
			if err != nil || snapshot.Closed {
				return
			}
			if !snapshot.Selected || snapshot.RelayRegion == "" || snapshot.Generation == generation && snapshot.RelayRegion == region {
				continue
			}
			generation, region = snapshot.Generation, snapshot.RelayRegion
			t.observeRelaySuccess(region)
		}
	}
}

func (t *PeerTerminalTunnel) recordNetworkCheck(fingerprint networkadaptation.Fingerprint, observation networkcheck.STUNObservation) {
	if t == nil || !fingerprint.Valid() || observation.Validate() != nil {
		return
	}
	t.networkCheckMu.Lock()
	if len(t.networkChecks) >= 16 {
		t.networkChecks = make(map[networkadaptation.Fingerprint]networkcheck.STUNObservation)
	}
	if current, ok := t.networkChecks[fingerprint]; ok && current.Validate() == nil {
		if observation.PMTU == "unknown" {
			observation.PMTU = current.PMTU
		}
		if observation.RouterProtocol == "unknown" {
			observation.RouterProtocol = current.RouterProtocol
		}
		if observation.RouterMapping == "unknown" {
			observation.RouterMapping = current.RouterMapping
		}
		if observation.MappingLifetime == "unknown" {
			observation.MappingLifetime = current.MappingLifetime
		}
	}
	t.networkChecks[fingerprint] = observation
	t.networkCheckMu.Unlock()
}

func (t *PeerTerminalTunnel) networkCheck(fingerprint networkadaptation.Fingerprint) networkcheck.STUNObservation {
	unknown := networkcheck.STUNObservation{IPv4: "unknown", IPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	if t == nil || !fingerprint.Valid() {
		return unknown
	}
	t.networkCheckMu.Lock()
	observation, found := t.networkChecks[fingerprint]
	t.networkCheckMu.Unlock()
	if !found || observation.Validate() != nil {
		return unknown
	}
	return observation
}

func (t *PeerTerminalTunnel) recordPMTU(fingerprint networkadaptation.Fingerprint, key networkadaptation.PMTUKey) {
	if t == nil || !fingerprint.Valid() || t.pmtu == nil || !key.Valid() {
		return
	}
	measurement, ok := t.pmtu.Lookup(key, t.config.Now().UTC())
	if !ok {
		return
	}
	category := networkcheck.PMTUCategory(measurement.PacketSize, true)
	if category == "unknown" {
		return
	}
	t.networkCheckMu.Lock()
	observation, found := t.networkChecks[fingerprint]
	if !found || observation.Validate() != nil {
		observation = networkcheck.STUNObservation{IPv4: "unknown", IPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	}
	observation.PMTU = category
	t.networkChecks[fingerprint] = observation
	t.networkCheckMu.Unlock()
}

func (t *PeerTerminalTunnel) recordRouterMapping(fingerprint networkadaptation.Fingerprint, protocol, category string) {
	if t == nil || !fingerprint.Valid() || !oneOfRouterProtocol(protocol) || !oneOfRouterMapping(category) || category == "verified" && protocol == "unknown" || category != "verified" && protocol != "unknown" {
		return
	}
	t.networkCheckMu.Lock()
	observation, found := t.networkChecks[fingerprint]
	if !found || observation.Validate() != nil {
		observation = networkcheck.STUNObservation{IPv4: "unknown", IPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	}
	observation.RouterProtocol = protocol
	observation.RouterMapping = category
	t.networkChecks[fingerprint] = observation
	t.networkCheckMu.Unlock()
}

func (t *PeerTerminalTunnel) recordMappingLifetime(fingerprint networkadaptation.Fingerprint, category string) {
	if t == nil || !fingerprint.Valid() || !oneOfMappingLifetime(category) {
		return
	}
	t.networkCheckMu.Lock()
	observation, found := t.networkChecks[fingerprint]
	if !found || observation.Validate() != nil {
		observation = networkcheck.STUNObservation{IPv4: "unknown", IPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown"}
	}
	observation.MappingLifetime = category
	t.networkChecks[fingerprint] = observation
	t.networkCheckMu.Unlock()
}

func oneOfMappingLifetime(value string) bool {
	return value == "unknown" || value == "under_30s" || value == "30s_to_2m" || value == "2m_to_10m" || value == "over_10m"
}

func oneOfRouterMapping(value string) bool {
	return value == "unknown" || value == "unavailable" || value == "verified" || value == "untrusted" || value == "unreachable"
}

func oneOfRouterProtocol(value string) bool {
	return value == "unknown" || value == "none" || value == "pcp" || value == "nat_pmp" || value == "upnp"
}

func networkCheckEndpoint(issuer string) string {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	endpoint, err := url.JoinPath(parsed.String(), "network-check/v1")
	if err != nil {
		return ""
	}
	return endpoint
}

func (t *PeerTerminalTunnel) outputQueueChunks() int {
	if t.config.OutputQueueChunks > 0 {
		return t.config.OutputQueueChunks
	}
	return terminalOutputQueueChunks
}

func peerOperationID(cliID, machineID, purpose string, seed [16]byte, operationScope uint64, generation directpath.Generation) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%x\x00%d\x00%d\x00%d", cliID, machineID, purpose, seed, operationScope, generation.Attempt, generation.Network)))
	return "op_peer_terminal_" + hex.EncodeToString(digest[:16])
}

func retryablePeerAPIError(err error) bool {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == http.StatusTooManyRequests || apiErr.Status >= http.StatusInternalServerError
	}
	var networkError net.Error
	return !certificateError(err) && errors.As(err, &networkError)
}

type TargetTunnel struct {
	Machine Tunnel
	Other   Tunnel
}

type ownedPeerTerminalConn struct {
	Conn
	cancel      context.CancelFunc
	monitor     *networkmonitor.Monitor
	fingerprint networkadaptation.Fingerprint
	lease       interface{ Release() }
	path        connectionmanager.Path
	pool        *connectionmanager.Pool
	supervisor  *connectionmanager.RecoverySupervisor
	authority   *clientauthority.Authority
	observer    *localobservation.Publisher
	health      *terminalPathCandidate
	once        sync.Once
	leaseOnce   sync.Once
	err         error
	revoke      func() error
}

type ownedPeerExecConn struct{ *ownedPeerTerminalConn }

func (c *ownedPeerTerminalConn) TerminalRuntimeVersion() string {
	if c == nil {
		return ""
	}
	return TerminalRuntimeVersion(c.Conn)
}

func ownPeerConnection(connection *ownedPeerTerminalConn) Conn {
	if _, ok := connection.Conn.(ExecConn); ok {
		return &ownedPeerExecConn{ownedPeerTerminalConn: connection}
	}
	return connection
}

var _ ExecConn = (*ownedPeerExecConn)(nil)

func (c *ownedPeerTerminalConn) Close() error {
	c.once.Do(func() {
		// Cancel first so a blocked promoted carrier is interrupted before its
		// Close path waits on transport shutdown. The lease remains owned until
		// the application stream has closed, preserving FIN/reset ordering.
		if c.cancel != nil {
			c.cancel()
		}
		// Close the application stream while its carrier is still owned. The
		// final lease may close the machine session, so releasing it first can
		// prevent the stream FIN/reset from reaching the host.
		c.err = errors.Join(c.err, c.Conn.Close())
		c.releaseLease()
		if c.observer != nil {
			observationCtx, cancelObservation := context.WithTimeout(context.Background(), time.Second)
			_ = c.observer.Close(observationCtx)
			cancelObservation()
		}
		if c.supervisor != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			c.err = errors.Join(c.err, c.supervisor.Shutdown(shutdownCtx))
			cancel()
		}
		if c.pool != nil {
			c.err = errors.Join(c.err, c.pool.Close())
		}
		if c.authority != nil {
			c.authority.Clear()
		}
		if c.monitor != nil {
			c.err = errors.Join(c.err, c.monitor.Close())
		}
		if c.revoke != nil {
			c.err = errors.Join(c.err, c.revoke())
		}
	})
	return c.err
}

func (c *ownedPeerTerminalConn) releaseLease() {
	if c == nil || c.lease == nil {
		return
	}
	c.leaseOnce.Do(func() {
		diagnosticlog.TryInfo("peer application lease release", "path", c.path, "operation", c.healthIntentID())
		c.lease.Release()
	})
}

func (c *ownedPeerTerminalConn) healthIntentID() string {
	if c == nil || c.health == nil {
		return ""
	}
	c.health.mu.Lock()
	defer c.health.mu.Unlock()
	return c.health.intentID
}

func (c *ownedPeerTerminalConn) SetDeadline(value time.Time) error {
	if deadline, ok := c.Conn.(interface{ SetDeadline(time.Time) error }); ok {
		return deadline.SetDeadline(value)
	}
	return ErrPeerTerminalInvalid
}
func (c *ownedPeerTerminalConn) SetReadDeadline(value time.Time) error {
	if deadline, ok := c.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		return deadline.SetReadDeadline(value)
	}
	return ErrPeerTerminalInvalid
}
func (c *ownedPeerTerminalConn) SetWriteDeadline(value time.Time) error {
	if deadline, ok := c.Conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return deadline.SetWriteDeadline(value)
	}
	return ErrPeerTerminalInvalid
}

func (c *ownedPeerExecConn) Events() <-chan ExecEvent {
	if exec, ok := c.Conn.(ExecConn); ok {
		return exec.Events()
	}
	closed := make(chan ExecEvent)
	close(closed)
	return closed
}

func (c *ownedPeerExecConn) Signal(signal string) error {
	if exec, ok := c.Conn.(ExecConn); ok {
		return exec.Signal(signal)
	}
	return ErrPeerTerminalInvalid
}

func (c *ownedPeerExecConn) Cancel() error {
	if exec, ok := c.Conn.(ExecConn); ok {
		return exec.Cancel()
	}
	return ErrPeerTerminalInvalid
}

func (c *ownedPeerTerminalConn) CloseWrite() error {
	if exec, ok := c.Conn.(ExecConn); ok {
		return exec.CloseWrite()
	}
	if half, ok := c.Conn.(InputHalfCloser); ok {
		return half.CloseWrite()
	}
	return ErrInputEOFUnsupported
}

func (c *ownedPeerExecConn) Detach() error {
	if exec, ok := c.Conn.(ExecConn); ok {
		err := exec.Detach()
		c.releaseLease()
		return err
	}
	return ErrPeerTerminalInvalid
}

func (t TargetTunnel) Dial(ctx context.Context, info resolver.ConnectInfo) (Conn, error) {
	if info.TargetKind == "machine" {
		if t.Machine == nil {
			return nil, ErrPeerTerminalInvalid
		}
		return t.Machine.Dial(ctx, info)
	}
	if t.Other == nil {
		return nil, ErrPeerTerminalInvalid
	}
	return t.Other.Dial(ctx, info)
}
