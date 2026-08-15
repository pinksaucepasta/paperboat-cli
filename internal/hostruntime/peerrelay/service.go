package peerrelay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	identitystore "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/candidatelease"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/directpath"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/nativepeer"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peersession"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaycarrier"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaynoise"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaypmtu"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/signaling"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/streamauth"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transportstage"
)

var ErrInvalid = errors.New("invalid peer relay service configuration")
var ErrAttemptLimit = errors.New("peer relay attempt limit reached")

const defaultWSSFallbackDelay = time.Second

type Source interface {
	Next(context.Context) (api.PeerAttemptDescriptor, error)
}

type descriptorRejector interface {
	Reject(context.Context, api.PeerAttemptDescriptor) error
}

type FingerprintSource interface {
	CurrentFingerprint() (networkadaptation.Fingerprint, error)
}

type Config struct {
	Source              Source
	Fingerprints        FingerprintSource
	StateRoot           string
	TLS                 *tls.Config
	HTTPClient          *http.Client
	Serve               func(net.Conn) error
	ServePreview        func(context.Context, net.Conn) error
	ServeCodex          func(context.Context, net.Conn) error
	ServeSSH            func(context.Context, net.Conn) error
	ServeTransfer       func(context.Context, net.Conn) error
	AuthorizeStream     StreamAuthorizer
	ServeStream         StreamHandler
	PollInterval        time.Duration
	AttemptLimit        int
	Carrier             relaycarrier.Config
	MaximumDeadline     time.Duration
	Clock               func() time.Time
	Dial                func(context.Context, relaycarrier.WSSDialConfig) (*relaycarrier.Connection, error)
	DialQUIC            func(context.Context, relaycarrier.QUICDialConfig) (*relaycarrier.Connection, error)
	TransferKeys        *transfercrypto.KeyVault
	SocketMapping       directpath.SocketMappingSource
	SignalingSubstrate  *signaling.SubstrateManager
	ObserveError        func(error)
	ObserveRelaySuccess func(string)
}

type Service struct {
	config           Config
	cancel           context.CancelFunc
	done             chan struct{}
	once             sync.Once
	directMu         sync.Mutex
	directGeneration uint64
	directAttempts   map[*directAttempt]struct{}
	transportMu      sync.Mutex
	transportOwners  map[transportKey]*transportOwner
	pmtu             *networkadaptation.PMTUCache
	relayPMTU        *networkadaptation.AsyncPMTU
	lifetime         *networkadaptation.LifetimeCache
	streams          *streamRegistry
	serveAttemptFn   func(context.Context, api.PeerAttemptDescriptor) error
	identityMu       sync.Mutex
	identityLoaded   bool
	identityStore    *identitystore.Store
	identityEndpoint identitystore.PeerEndpoint
}

type directAttempt struct {
	cancel context.CancelFunc
}

type transportOwner struct {
	cancel context.CancelFunc
}

type attemptPermitReleaseKey struct{}

type pathResult struct {
	claimed  bool
	terminal bool
	err      error
}

// transportKey identifies one server-issued peer transport intent. Distinct
// generations must coexist while a client promotes a standby carrier; only a
// duplicate delivery of the same intent may supersede an owner.
type transportKey struct {
	initiator string
	intent    string
	attempt   uint64
}

func New(config Config) (*Service, error) {
	if config.PollInterval == 0 {
		config.PollInterval = 500 * time.Millisecond
	}
	if config.AttemptLimit == 0 {
		config.AttemptLimit = 8
	}
	if config.Carrier.MaximumStreams == 0 {
		config.Carrier = relaycarrier.DevelopmentConfig()
	}
	if config.MaximumDeadline == 0 {
		config.MaximumDeadline = 5 * time.Minute
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.SignalingSubstrate == nil {
		config.SignalingSubstrate = &signaling.SubstrateManager{}
	}
	if config.Dial == nil {
		config.Dial = relaycarrier.DialWSS
	}
	if config.DialQUIC == nil {
		config.DialQUIC = relaycarrier.DialQUIC
	}
	if config.Source == nil || config.StateRoot == "" || config.TLS == nil || config.Serve == nil || (config.AuthorizeStream == nil) != (config.ServeStream == nil) || config.PollInterval < 50*time.Millisecond || config.PollInterval > time.Minute || config.AttemptLimit < 1 || config.AttemptLimit > 64 || config.MaximumDeadline <= 0 || config.MaximumDeadline > 24*time.Hour {
		return nil, ErrInvalid
	}
	pmtu, err := networkadaptation.NewPMTUCache(networkadaptation.DevelopmentPMTUPolicy())
	if err != nil {
		return nil, err
	}
	relayPMTU, err := networkadaptation.NewAsyncPMTU(networkadaptation.AsyncPMTUConfig{Policy: networkadaptation.DevelopmentPMTUPolicy(), Cache: pmtu, Now: config.Clock, Observe: config.ObserveError})
	if err != nil {
		return nil, err
	}
	lifetime, err := networkadaptation.NewLifetimeCache(networkadaptation.DevelopmentLifetimePolicy(), nil)
	if err != nil {
		return nil, err
	}
	return &Service{config: config, done: make(chan struct{}), directAttempts: make(map[*directAttempt]struct{}), transportOwners: make(map[transportKey]*transportOwner), pmtu: pmtu, relayPMTU: relayPMTU, lifetime: lifetime, streams: newStreamRegistry()}, nil
}

// ownTransport admits one owner for an exact server-issued attempt. A repeated
// delivery of the same descriptor is idempotent and must never cancel the
// established carrier. Distinct attempt generations intentionally coexist
// during promotion.
func (s *Service) ownTransport(parent context.Context, key transportKey) (context.Context, func(), bool) {
	ctx, cancel := context.WithCancel(parent)
	owner := &transportOwner{cancel: cancel}
	s.transportMu.Lock()
	if s.transportOwners == nil {
		s.transportOwners = make(map[transportKey]*transportOwner)
	}
	previous := s.transportOwners[key]
	if previous == nil {
		s.transportOwners[key] = owner
	}
	s.transportMu.Unlock()
	if previous != nil {
		cancel()
		return ctx, func() {}, false
	}
	return ctx, func() {
		cancel()
		s.transportMu.Lock()
		if s.transportOwners[key] == owner {
			delete(s.transportOwners, key)
		}
		s.transportMu.Unlock()
	}, true
}

func (s *Service) localIdentity() (identitystore.PeerEndpoint, error) {
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	if s.identityLoaded {
		return s.identityEndpoint, nil
	}
	store, err := identitystore.Open(identitystore.Config{StateRoot: s.config.StateRoot})
	if err != nil {
		return identitystore.PeerEndpoint{}, err
	}
	endpoint, err := store.PeerEndpoint()
	if err != nil {
		return identitystore.PeerEndpoint{}, err
	}
	s.identityStore = store
	s.identityEndpoint = endpoint
	s.identityLoaded = true
	return endpoint, nil
}

func (s *Service) NetworkChanged(generation uint64) bool {
	if s == nil || generation == 0 {
		return false
	}
	s.directMu.Lock()
	if generation <= s.directGeneration {
		s.directMu.Unlock()
		return false
	}
	s.directGeneration = generation
	s.relayPMTU.Invalidate()
	cancels := make([]context.CancelFunc, 0, len(s.directAttempts))
	for attempt := range s.directAttempts {
		cancels = append(cancels, attempt.cancel)
		delete(s.directAttempts, attempt)
	}
	s.directMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	return true
}

func (s *Service) Start(ctx context.Context) error {
	if s == nil || ctx == nil || s.cancel != nil {
		return ErrInvalid
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	go s.run(runCtx)
	return nil
}

func (s *Service) Shutdown(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalid
	}
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
	})
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) run(ctx context.Context) {
	defer close(s.done)
	defer s.streams.Close()
	defer s.config.SignalingSubstrate.Close()
	permits := make(chan struct{}, s.config.AttemptLimit)
	var attempts sync.WaitGroup
	defer attempts.Wait()
	for {
		descriptor, err := s.config.Source.Next(ctx)
		if err == nil {
			s.logWSSStage(ctx, descriptor, "descriptor_acquired", time.Now(), nil)
			select {
			case permits <- struct{}{}:
				attempts.Add(1)
				go func() {
					defer attempts.Done()
					var releaseOnce sync.Once
					releasePermit := func() { releaseOnce.Do(func() { <-permits }) }
					defer releasePermit()
					attemptCtx := context.WithValue(ctx, attemptPermitReleaseKey{}, releasePermit)
					serve := s.serveAttempt
					if s.serveAttemptFn != nil {
						serve = s.serveAttemptFn
					}
					if attemptErr := serve(attemptCtx, descriptor); attemptErr != nil && s.config.ObserveError != nil {
						s.config.ObserveError(attemptErr)
					}
				}()
			default:
				// Never stop polling while an abandoned carrier consumes the
				// bounded attempt set. Revoke the delivered descriptor when the
				// source can do so; the controlling request will receive a
				// deterministic retryable failure instead of wedging the host.
				if rejector, ok := s.config.Source.(descriptorRejector); ok {
					rejectCtx, cancelReject := context.WithTimeout(context.Background(), 2*time.Second)
					go func() {
						defer cancelReject()
						if rejectErr := rejector.Reject(rejectCtx, descriptor); rejectErr != nil && s.config.ObserveError != nil {
							s.config.ObserveError(errors.Join(ErrAttemptLimit, rejectErr))
						}
					}()
				} else if s.config.ObserveError != nil {
					s.config.ObserveError(ErrAttemptLimit)
				}
			case <-ctx.Done():
				return
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}
		// Validation, authorization, and transport failures remain isolated to
		// this poll; a later server-issued attempt must be independently valid.
		timer := time.NewTimer(s.config.PollInterval)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		}
	}
}

func (s *Service) serveAttempt(parent context.Context, descriptor api.PeerAttemptDescriptor) error {
	started := time.Now()
	now := s.config.Clock().UTC()
	if descriptor.Role != "controlled" || descriptor.Purpose != "peer_transport" && descriptor.Purpose != "interactive" && descriptor.Purpose != "private_preview" && descriptor.Purpose != "codex" && descriptor.Purpose != "health_probe" && descriptor.Purpose != "direct_probe" && descriptor.Purpose != "file_transfer_key" || descriptor.Purpose == "peer_transport" && descriptor.Consumer != "peer_transport" || len(descriptor.Relays) != 1 || !descriptor.ExpiresAt.After(now) || (descriptor.Purpose == "file_transfer_key") != (descriptor.Transfer != nil) || descriptor.Purpose == "file_transfer_key" && s.config.TransferKeys == nil {
		return ErrInvalid
	}
	directAllowed, relayAllowed, wssAllowed := descriptorAllowedPaths(descriptor.Policy.AllowedPaths)
	if descriptor.Purpose == "private_preview" && (!directAllowed || relayAllowed || wssAllowed) {
		return ErrInvalid
	}
	if !directAllowed && !relayAllowed && !wssAllowed {
		return ErrInvalid
	}
	local, err := s.localIdentity()
	if err != nil {
		return err
	}
	localCertificate, err := endpointidentity.Verify(local.Certificate, local.RootPublicKey, endpointidentity.Expected{AccountID: descriptor.AccountID, Role: endpointidentity.RoleMachine, EndpointID: descriptor.ResponderEndpointID, Generation: descriptor.HostGeneration}, now)
	if err != nil {
		return err
	}
	peerCertificate, err := descriptorCertificate(descriptor, descriptor.InitiatorEndpointID, local.RootPublicKey, now)
	if err != nil {
		return err
	}
	authority, err := peersession.New(peersession.Config{Descriptor: descriptor, LocalCertificate: localCertificate, PeerCertificate: peerCertificate, LocalNoisePrivate: local.NoisePrivateKey, Consumer: descriptor.Consumer})
	if err != nil {
		return transportstage.Wrap("authority_created", err)
	}
	s.logWSSStage(parent, descriptor, "authority_created", started, nil)
	deadline := descriptor.ExpiresAt.Sub(now)
	if deadline > s.config.MaximumDeadline {
		deadline = s.config.MaximumDeadline
	}
	attemptParent := parent
	releaseTransport := func() {}
	if descriptor.Purpose == "peer_transport" {
		var admitted bool
		attemptParent, releaseTransport, admitted = s.ownTransport(parent, transportKey{initiator: descriptor.InitiatorEndpointID, intent: descriptor.IntentID, attempt: descriptor.AttemptGeneration})
		if !admitted {
			return context.Canceled
		}
		s.logWSSStage(attemptParent, descriptor, "host_attempt_registered", started, nil)
		defer func() {
			releaseTransport()
			s.logWSSStage(parent, descriptor, "transport_owner_released", started, nil)
		}()
	}
	ctx, cancel := context.WithTimeout(attemptParent, deadline)
	defer cancel()
	if lifetimeProbePurpose(descriptor.Purpose) {
		if s.config.Fingerprints == nil {
			return ErrInvalid
		}
		fingerprint, fingerprintErr := s.config.Fingerprints.CurrentFingerprint()
		if fingerprintErr != nil || !fingerprint.Valid() {
			return errors.Join(ErrInvalid, fingerprintErr)
		}
		_, err := s.serveDirect(ctx, ctx, descriptor, authority, local, localCertificate, peerCertificate, fingerprint, true, func() bool { return true }, nil)
		return err
	}
	directCtx, cancelDirect := context.WithCancel(ctx)
	relayCtx, cancelRelay, err := pathSetupContext(ctx, descriptor.Policy.RelayDeadlineMS)
	if err != nil {
		cancelDirect()
		return ErrInvalid
	}
	wssCtx, cancelWSS, err := pathSetupContext(ctx, descriptor.Policy.RelayDeadlineMS)
	if err != nil {
		cancelDirect()
		cancelRelay()
		return ErrInvalid
	}
	carrierLifetime := ctx
	var cancelCarrier context.CancelFunc
	if descriptor.Purpose == "private_preview" {
		// The descriptor deadline bounds authorization and carrier setup. Once a
		// private-preview QUIC session is authenticated, its lifetime follows the
		// active caller/host service, not the already-consumed setup credential.
		carrierLifetime, cancelCarrier = establishedCarrierContext(attemptParent)
	}
	if cancelCarrier != nil {
		defer cancelCarrier()
	}
	defer cancelWSS()
	defer cancelRelay()
	defer cancelDirect()
	results := make(chan pathResult, 3)
	var winner sync.Once
	retainTransportLifecycle := descriptor.Purpose == "peer_transport"
	retainTransportCandidates := retainTransportLifecycle || allowedPathCount(directAllowed, relayAllowed, wssAllowed) > 1
	newOwner := func(path string) *candidateOwner {
		if !retainTransportLifecycle {
			return nil
		}
		return newCandidateOwner(attemptParent, func(stage string) {
			s.logCandidateStage(attemptParent, descriptor, path, stage, started, nil)
		})
	}
	var claim func(...context.CancelFunc) bool
	claimPeer := func(owner *candidateOwner, cancelOthers ...context.CancelFunc) bool {
		if !retainTransportCandidates {
			return claim(cancelOthers...)
		}
		// The client racer is the sole owner of primary/standby selection.
		// The host authenticates every eligible carrier and never cancels one
		// merely because another carrier completed first.
		if owner != nil {
			owner.activity.Ready()
		}
		return true
	}
	claim = func(cancelOthers ...context.CancelFunc) bool {
		if retainTransportCandidates {
			// Reusable transport attempts intentionally admit more than one
			// authenticated carrier. The client pool owns path selection and
			// standby; the host must not cancel direct merely because relay won.
			return true
		}
		claimed := false
		winner.Do(func() {
			claimed = true
			for _, cancelOther := range cancelOthers {
				cancelOther()
			}
		})
		return claimed
	}
	paths := 0
	if retainTransportCandidates {
		if relayAllowed {
			paths++
			if wssAllowed {
				paths++
			}
			relayOwner := newOwner("relay_quic")
			relayLifetime, relayActivity := carrierLifetime, (*transportActivity)(nil)
			if relayOwner != nil {
				relayLifetime, relayActivity = relayOwner.ctx, relayOwner.activity
			}
			relayClaim := func() bool { return claimPeer(relayOwner, cancelDirect) }
			go func() {
				if relayOwner != nil {
					defer relayOwner.Stop()
				}
				claimed, pathErr := s.serveRelayQUIC(relayCtx, relayLifetime, descriptor, authority, relayClaim, relayActivity)
				s.observePathError(relayCtx, pathErr)
				result := pathResult{claimed: claimed, err: pathErr}
				if !claimed && pathErr != nil && !errors.Is(pathErr, context.Canceled) && !relayFailureAllowsFallback(parent, pathErr) {
					result.terminal = true
				}
				results <- result
			}()
			if wssAllowed {
				wssOwner := newOwner("relay_wss")
				wssLifetime, wssActivity := carrierLifetime, (*transportActivity)(nil)
				if wssOwner != nil {
					wssLifetime, wssActivity = wssOwner.ctx, wssOwner.activity
				}
				go func() {
					if wssOwner != nil {
						defer wssOwner.Stop()
					}
					claimed, pathErr := s.serveWSS(wssCtx, wssLifetime, descriptor, authority, func() bool { return claimPeer(wssOwner, cancelDirect) }, wssActivity)
					s.observePathError(wssCtx, pathErr)
					results <- pathResult{claimed: claimed, err: pathErr}
				}()
			}
		} else if wssAllowed {
			paths++
			wssOwner := newOwner("relay_wss")
			wssLifetime, wssActivity := carrierLifetime, (*transportActivity)(nil)
			if wssOwner != nil {
				wssLifetime, wssActivity = wssOwner.ctx, wssOwner.activity
			}
			go func() {
				if wssOwner != nil {
					defer wssOwner.Stop()
				}
				claimed, pathErr := s.serveWSS(wssCtx, wssLifetime, descriptor, authority, func() bool { return claimPeer(wssOwner, cancelDirect, cancelRelay) }, wssActivity)
				s.observePathError(wssCtx, pathErr)
				results <- pathResult{claimed: claimed, err: pathErr}
			}()
		}
	} else {
		if wssAllowed {
			paths++
			go func() {
				claimed, pathErr := s.serveWSS(wssCtx, carrierLifetime, descriptor, authority, func() bool { return claim(cancelDirect, cancelRelay) }, nil)
				s.observePathError(wssCtx, pathErr)
				results <- pathResult{claimed: claimed, err: pathErr}
			}()
		}
		if relayAllowed {
			paths++
			go func() {
				claimed, pathErr := s.serveRelayQUIC(relayCtx, carrierLifetime, descriptor, authority, func() bool { return claim(cancelDirect, cancelWSS) }, nil)
				s.observePathError(relayCtx, pathErr)
				terminal := !claimed && pathErr != nil && !errors.Is(pathErr, context.Canceled) && !relayFailureAllowsFallback(parent, pathErr)
				results <- pathResult{claimed: claimed, terminal: terminal, err: pathErr}
			}()
		}
	}
	if directAllowed && s.config.Fingerprints != nil {
		if fingerprint, fingerprintErr := s.config.Fingerprints.CurrentFingerprint(); fingerprintErr == nil && fingerprint.Valid() {
			paths++
			directOwner := newOwner("direct_quic")
			directLifetime, directActivity := carrierLifetime, (*transportActivity)(nil)
			if directOwner != nil {
				directLifetime, directActivity = directOwner.ctx, directOwner.activity
			}
			go func() {
				claimDirect := func() bool { return claim(cancelWSS, cancelRelay) }
				if retainTransportCandidates {
					claimDirect = func() bool { return claimPeer(directOwner, cancelWSS) }
				}
				if directOwner != nil {
					defer directOwner.Stop()
				}
				claimed, pathErr := s.serveDirect(directCtx, directLifetime, descriptor, authority, local, localCertificate, peerCertificate, fingerprint, lifetimeProbePurpose(descriptor.Purpose), claimDirect, directActivity)
				s.observePathError(directCtx, pathErr)
				terminal := !claimed && pathErr != nil && !errors.Is(pathErr, context.Canceled) && !directFailureAllowsFallback(parent, pathErr)
				results <- pathResult{claimed: claimed, terminal: terminal, err: pathErr}
			}()
		}
	}
	if paths == 0 {
		return ErrInvalid
	}
	// AttemptLimit bounds synchronous descriptor validation and path launch.
	// Carrier setup and lifetime have their own deadlines and ownership. A
	// slow ICE loser must not retain an admission permit after every eligible
	// path has been started, otherwise ordinary sequential races eventually
	// reject unrelated descriptors.
	if releasePermit, ok := parent.Value(attemptPermitReleaseKey{}).(func()); ok {
		releasePermit()
	}
	return awaitPathResults(paths, retainTransportLifecycle, results, cancelWSS, cancelRelay, cancelDirect)
}

func awaitPathResults(paths int, retain bool, results <-chan pathResult, cancels ...context.CancelFunc) error {
	var combined, terminal error
	var selected pathResult
	for range paths {
		result := <-results
		combined = errors.Join(combined, result.err)
		if result.claimed && !retain {
			return result.err
		}
		if result.terminal {
			terminal = errors.Join(terminal, result.err)
			// A peer-transport descriptor owns every authenticated candidate for
			// the machine session. Failure of one candidate must not fence or
			// cancel its siblings; the client pool decides which retained carrier
			// is primary or standby. Only the non-retained race tears down losers.
			if !retain {
				for _, cancel := range cancels {
					cancel()
				}
			}
		}
		if result.claimed {
			selected = result
		}
	}
	if terminal != nil {
		return terminal
	}
	if selected.claimed {
		return selected.err
	}
	return combined
}

func establishedCarrierContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}

func relayTransportContext(parent context.Context, activity *transportActivity) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	if activity == nil || activity.owner == nil {
		return ctx, cancel
	}
	go func() {
		select {
		case <-activity.owner.Released():
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func allowedPathCount(direct, relay, wss bool) int {
	count := 0
	if direct {
		count++
	}
	if relay {
		count++
	}
	if wss {
		count++
	}
	return count
}

func pathSetupContext(parent context.Context, milliseconds int) (context.Context, context.CancelFunc, error) {
	if parent == nil || milliseconds <= 0 {
		return nil, nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(milliseconds)*time.Millisecond)
	return ctx, cancel, nil
}

func descriptorAllowedPaths(paths []string) (direct, relay, wss bool) {
	switch {
	case slices.Equal(paths, []string{"direct_quic", "relay_quic", "relay_wss"}):
		return true, true, true
	case slices.Equal(paths, []string{"direct_quic", "relay_quic"}):
		return true, true, false
	case slices.Equal(paths, []string{"direct_quic"}):
		return true, false, false
	case slices.Equal(paths, []string{"relay_quic"}):
		return false, true, false
	case slices.Equal(paths, []string{"relay_quic", "relay_wss"}):
		return false, true, true
	case slices.Equal(paths, []string{"relay_wss"}):
		return false, false, true
	default:
		return false, false, false
	}
}

func lifetimeProbePurpose(purpose string) bool { return purpose == "direct_probe" }

func (s *Service) observePathError(ctx context.Context, err error) {
	if err != nil && ctx != nil && ctx.Err() == nil && !errors.Is(err, context.Canceled) && s.config.ObserveError != nil {
		s.config.ObserveError(err)
	}
}

func (s *Service) serveWSS(setupCtx, lifetime context.Context, descriptor api.PeerAttemptDescriptor, authority peersession.Authority, claim func() bool, activity *transportActivity) (bool, error) {
	started := time.Now()
	relay := descriptor.Relays[0]
	s.logWSSStage(setupCtx, descriptor, "wss_dial_started", started, nil)
	connection, err := s.config.Dial(setupCtx, relaycarrier.WSSDialConfig{URL: relay.WSSURL, Credential: relay.RouteToken, StreamHandle: authority.RouteHandle, EndpointID: authority.LocalEndpointID(), Role: "responder", RelayID: relay.Region, TLS: s.config.TLS.Clone(), HTTPClient: s.config.HTTPClient, Lifetime: lifetime, MaximumDeadline: s.config.MaximumDeadline, Carrier: s.config.Carrier})
	if err != nil {
		s.logWSSStage(setupCtx, descriptor, "wss_dial_authenticated", started, err)
		return false, transportstage.Wrap("wss_dial_authenticated", err)
	}
	s.logWSSStage(setupCtx, descriptor, "wss_dial_authenticated", started, nil)
	return s.serveRelay(setupCtx, lifetime, connection, descriptor, authority, claim, activity)
}

func (s *Service) serveRelayQUIC(setupCtx, lifetime context.Context, descriptor api.PeerAttemptDescriptor, authority peersession.Authority, claim func() bool, activity *transportActivity) (bool, error) {
	ownerCtx, cancelOwner := context.WithCancel(lifetime)
	owner := &directAttempt{cancel: cancelOwner}
	s.directMu.Lock()
	s.directAttempts[owner] = struct{}{}
	s.directMu.Unlock()
	defer func() {
		cancelOwner()
		s.directMu.Lock()
		delete(s.directAttempts, owner)
		s.directMu.Unlock()
	}()
	relay := descriptor.Relays[0]
	initialPacketSize := s.relayPacketSize(ownerCtx, descriptor)
	connection, err := s.config.DialQUIC(setupCtx, relaycarrier.QUICDialConfig{URL: relay.QUICURL, Credential: relay.RouteToken, EndpointID: authority.LocalEndpointID(), Role: "responder", StreamHandle: authority.RouteHandle, TLS: s.config.TLS.Clone(), Lifetime: ownerCtx, MaximumDeadline: s.config.MaximumDeadline, Carrier: s.config.Carrier, InitialPacketSize: initialPacketSize})
	if err != nil {
		return false, err
	}
	return s.serveRelay(setupCtx, ownerCtx, connection, descriptor, authority, claim, activity)
}

func (s *Service) relayPacketSize(lifetime context.Context, descriptor api.PeerAttemptDescriptor) uint16 {
	const safeMinimum = uint16(1200)
	if s.config.Fingerprints == nil {
		return safeMinimum
	}
	fingerprint, err := s.config.Fingerprints.CurrentFingerprint()
	if err != nil || !fingerprint.Valid() {
		return safeMinimum
	}
	relay := descriptor.Relays[0]
	if relay.Region == "" || relay.PMTUURL == "" || relay.PMTUToken == "" || descriptor.NetworkGeneration == 0 {
		return safeMinimum
	}
	key := networkadaptation.PMTUKey{Fingerprint: fingerprint, PathID: "relay:" + relay.Region, NetworkGeneration: descriptor.NetworkGeneration}
	return s.relayPMTU.PacketSize(lifetime, key, func(ctx context.Context) (networkadaptation.PMTUMeasurement, error) {
		return s.measureRelayPMTU(ctx, descriptor)
	})
}

func (s *Service) measureRelayPMTU(ctx context.Context, descriptor api.PeerAttemptDescriptor) (networkadaptation.PMTUMeasurement, error) {
	policy := networkadaptation.DevelopmentPMTUPolicy()
	relay := descriptor.Relays[0]
	prober, err := relaypmtu.Open(ctx, relay.PMTUURL, relay.PMTUToken, policy.MaximumPayload)
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

func (s *Service) serveRelay(setupCtx, lifetime context.Context, connection *relaycarrier.Connection, descriptor api.PeerAttemptDescriptor, authority peersession.Authority, claim func() bool, activity *transportActivity) (bool, error) {
	responder := nativepeer.Responder{Connection: connection, Authority: authority}
	defer responder.Close()
	transportCtx, cancelTransport := relayTransportContext(lifetime, activity)
	defer cancelTransport()
	healthAuthority, err := authority.Responder("native-health")
	if err != nil {
		return false, transportstage.Wrap("noise_started", err)
	}
	s.logWSSStage(setupCtx, descriptor, "noise_started", time.Now(), nil)
	healthConfig, err := relaycarrier.PeerResponderConfig(healthAuthority, connection.Carrier(), "native-health", func(context.Context, []byte) ([]byte, error) { return nil, nil })
	if err != nil {
		return false, err
	}
	healthConfig.Authorize = nil
	initial, err := connection.AcceptInitialHealth(setupCtx, healthConfig)
	if err != nil {
		s.logWSSStage(setupCtx, descriptor, "health_admission_started", time.Now(), err)
		return false, transportstage.Wrap("health_admission_started", err)
	}
	s.logWSSStage(setupCtx, descriptor, "noise_authenticated", time.Now(), nil)
	s.logWSSStage(setupCtx, descriptor, "health_admission_succeeded", time.Now(), nil)
	claimRelay := func() bool {
		if !claim() {
			return false
		}
		if s.config.ObserveRelaySuccess != nil {
			s.config.ObserveRelaySuccess(descriptor.Relays[0].Region)
		}
		return true
	}
	if authority.Context.Consumer == "health_probe" {
		if !claimRelay() {
			return false, context.Canceled
		}
		healthSource := relaycarrier.HealthResponderConfigSourceFunc(func(_ context.Context, handle [16]byte) (relaycarrier.ResponderConfig, error) {
			periodicAuthority := healthAuthority
			periodicAuthority.Handle = handle
			return relaycarrier.PeerResponderConfig(periodicAuthority, connection.Carrier(), "native-health", func(context.Context, []byte) ([]byte, error) { return nil, nil })
		})
		return true, connection.ServeHealthOnce(lifetime, initial.Prefix, healthSource)
	}
	if authority.Context.Consumer == "peer_transport" {
		if s.config.AuthorizeStream == nil || s.config.ServeStream == nil || descriptor.StreamPolicy == nil {
			return false, fmt.Errorf("%w: authorize=%t serve=%t policy=%t", ErrInvalid, s.config.AuthorizeStream != nil, s.config.ServeStream != nil, descriptor.StreamPolicy != nil)
		}
		if !claimRelay() {
			return false, context.Canceled
		}
		if activity == nil || activity.owner == nil {
			return false, ErrInvalid
		}
		candidateID, candidateErr := candidatelease.NewID(initial.Binding[:], descriptor.IntentID, descriptor.AttemptGeneration, relayCandidatePath(connection.Carrier()))
		if candidateErr != nil || activity.owner.Configure(candidateID, descriptor.AttemptGeneration) != nil {
			return false, errors.Join(candidateErr, ErrInvalid)
		}
		// Candidate adoption belongs to the established physical transport. The
		// setup deadline only bounds initial health admission; applying it here
		// tears down an authenticated relay candidate while its client is still
		// preparing the logical-stream transition.
		control, _, controlErr := responder.AcceptCandidateControl(transportCtx, func(_ context.Context, payload []byte) ([]byte, error) {
			message, parseErr := candidatelease.Parse(payload)
			if parseErr != nil {
				return nil, parseErr
			}
			ack, handleErr := activity.owner.Handle(message)
			if handleErr != nil {
				return nil, handleErr
			}
			return ack.Marshal()
		})
		if controlErr != nil {
			return false, controlErr
		}
		defer control.Close()
		if retainErr := activity.owner.Retained(); retainErr != nil {
			return false, retainErr
		}
		controlDone := make(chan error, 1)
		go func() {
			for {
				message, readErr := candidatelease.FrameReader(control)
				if readErr != nil {
					controlDone <- readErr
					return
				}
				ack, handleErr := activity.owner.Handle(message)
				if handleErr != nil {
					controlDone <- handleErr
					return
				}
				frame, frameErr := candidatelease.Frame(ack)
				if frameErr == nil {
					_, frameErr = control.Write(frame)
				}
				if frameErr != nil || message.Type == candidatelease.Release {
					controlDone <- frameErr
					return
				}
			}
		}()
		healthSource := relaycarrier.HealthResponderConfigSourceFunc(func(_ context.Context, handle [16]byte) (relaycarrier.ResponderConfig, error) {
			periodicAuthority := healthAuthority
			periodicAuthority.Handle = handle
			return relaycarrier.PeerResponderConfig(periodicAuthority, connection.Carrier(), "native-health", func(context.Context, []byte) ([]byte, error) { return nil, nil })
		})
		applicationDone := make(chan error, 1)
		healthDone := make(chan error, 1)
		go func() { applicationDone <- s.serveRelayTransport(transportCtx, responder, descriptor, activity) }()
		go func() { healthDone <- connection.ServeHealth(transportCtx, initial.Prefix, healthSource) }()
		select {
		case applicationErr := <-applicationDone:
			slog.Info("peer retained relay transport ending", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "path", relayCandidatePath(connection.Carrier()), "owner", "application", "error", applicationErr)
			return true, applicationErr
		case healthErr := <-healthDone:
			slog.Info("peer retained relay transport ending", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "path", relayCandidatePath(connection.Carrier()), "owner", "health", "error", healthErr)
			return true, healthErr
		case controlErr := <-controlDone:
			//paperboat:allow-source-policy sensitive-log owner=transport-observability reason=bounded-intent-generation-path-error
			slog.Info("peer retained relay transport ending", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "path", relayCandidatePath(connection.Carrier()), "owner", "candidate_control", "error", controlErr)
			return true, controlErr
		case <-transportCtx.Done():
			slog.Info("peer retained relay transport ending", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration, "path", relayCandidatePath(connection.Carrier()), "owner", "lifetime", "error", transportCtx.Err())
			return true, transportCtx.Err()
		}
	}
	if authority.Context.Consumer == "file_transfer_key" {
		stream, acceptErr := responder.Accept(lifetime, "transfer-key-control")
		if acceptErr != nil {
			return false, acceptErr
		}
		defer stream.Close()
		if !claimRelay() {
			return false, context.Canceled
		}
		return true, s.exchangeTransferKey(stream, descriptor, authority)
	}
	if authority.Context.Consumer == "private_preview" {
		stream, acceptErr := responder.Accept(lifetime, "private-preview")
		if acceptErr != nil {
			return false, acceptErr
		}
		defer stream.Close()
		if s.config.ServePreview == nil || !claimRelay() {
			return false, ErrInvalid
		}
		healthSource := relaycarrier.HealthResponderConfigSourceFunc(func(_ context.Context, handle [16]byte) (relaycarrier.ResponderConfig, error) {
			periodicAuthority := healthAuthority
			periodicAuthority.Handle = handle
			return relaycarrier.PeerResponderConfig(periodicAuthority, connection.Carrier(), "native-health", func(context.Context, []byte) ([]byte, error) { return nil, nil })
		})
		previewDone := make(chan error, 1)
		healthDone := make(chan error, 1)
		go func() { previewDone <- s.config.ServePreview(lifetime, stream) }()
		go func() { healthDone <- connection.ServeHealth(lifetime, initial.Prefix, healthSource) }()
		select {
		case previewErr := <-previewDone:
			return true, previewErr
		case healthErr := <-healthDone:
			return true, healthErr
		case <-lifetime.Done():
			return true, lifetime.Err()
		}
	}
	if authority.Context.Consumer == "codex" {
		stream, acceptErr := responder.Accept(lifetime, "codex-http")
		if acceptErr != nil {
			return false, acceptErr
		}
		defer stream.Close()
		if s.config.ServeCodex == nil || !claimRelay() {
			return false, ErrInvalid
		}
		healthSource := relaycarrier.HealthResponderConfigSourceFunc(func(_ context.Context, handle [16]byte) (relaycarrier.ResponderConfig, error) {
			periodicAuthority := healthAuthority
			periodicAuthority.Handle = handle
			return relaycarrier.PeerResponderConfig(periodicAuthority, connection.Carrier(), "native-health", func(context.Context, []byte) ([]byte, error) { return nil, nil })
		})
		codexDone := make(chan error, 1)
		healthDone := make(chan error, 1)
		go func() { codexDone <- s.config.ServeCodex(lifetime, stream) }()
		go func() { healthDone <- connection.ServeHealth(lifetime, initial.Prefix, healthSource) }()
		select {
		case codexErr := <-codexDone:
			return true, codexErr
		case healthErr := <-healthDone:
			return true, healthErr
		case <-lifetime.Done():
			return true, lifetime.Err()
		}
	}
	if authority.Context.Consumer == "ssh" {
		stream, acceptErr := responder.Accept(lifetime, "ssh")
		if acceptErr != nil {
			return false, acceptErr
		}
		defer stream.Close()
		if s.config.ServeSSH == nil || !claimRelay() {
			return false, ErrInvalid
		}
		return true, s.config.ServeSSH(lifetime, stream)
	}
	served := make(chan error, 3)
	for index, streamID := range []string{"native-control", "native-input", "native-output"} {
		stream, acceptErr := responder.Accept(lifetime, streamID)
		if acceptErr != nil {
			return index > 0, acceptErr
		}
		if index == 0 && !claimRelay() {
			_ = stream.Close()
			return false, context.Canceled
		}
		go func(conn net.Conn) { served <- s.config.Serve(conn) }(stream)
	}
	healthSource := relaycarrier.HealthResponderConfigSourceFunc(func(_ context.Context, handle [16]byte) (relaycarrier.ResponderConfig, error) {
		periodicAuthority := healthAuthority
		periodicAuthority.Handle = handle
		return relaycarrier.PeerResponderConfig(periodicAuthority, connection.Carrier(), "native-health", func(context.Context, []byte) ([]byte, error) { return nil, nil })
	})
	healthDone := make(chan error, 1)
	go func() { healthDone <- connection.ServeHealth(lifetime, initial.Prefix, healthSource) }()
	for range 3 {
		select {
		case <-served:
		case err := <-healthDone:
			return true, err
		case <-lifetime.Done():
			return true, lifetime.Err()
		}
	}
	return true, nil
}

func relayCandidatePath(carrier relaynoise.Carrier) string {
	if carrier == relaynoise.CarrierWSS {
		return "relay_wss"
	}
	return "relay_quic"
}

func (s *Service) logWSSStage(ctx context.Context, descriptor api.PeerAttemptDescriptor, stage string, started time.Time, err error) {
	if !slices.Contains(descriptor.Policy.AllowedPaths, "relay_wss") {
		return
	}
	deadline, _ := ctx.Deadline()
	slog.Info("peer WSS setup stage", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration,
		"network_generation", descriptor.NetworkGeneration, "path", "relay_wss", "stage", stage,
		"elapsed_ms", time.Since(started).Milliseconds(), "context_deadline", deadline.UTC().Format(time.RFC3339Nano), "error", err)
}

func (s *Service) logCandidateStage(ctx context.Context, descriptor api.PeerAttemptDescriptor, path, stage string, started time.Time, err error) {
	deadline, _ := ctx.Deadline()
	//paperboat:allow-source-policy sensitive-log owner=transport-observability reason=bounded-intent-generation-stage-error
	slog.Info("peer candidate lifecycle", "intent_id", descriptor.IntentID, "attempt_generation", descriptor.AttemptGeneration,
		"network_generation", descriptor.NetworkGeneration, "path", path, "stage", stage,
		"elapsed_ms", time.Since(started).Milliseconds(), "context_deadline", deadline.UTC().Format(time.RFC3339Nano), "error", err)
}

func (s *Service) serveRelayTransport(ctx context.Context, responder nativepeer.Responder, descriptor api.PeerAttemptDescriptor, activity *transportActivity) error {
	permits := make(chan struct{}, descriptor.StreamPolicy.MaximumStreams)
	var streams sync.WaitGroup
	defer streams.Wait()
	for {
		connection, header, err := responder.AcceptAuthorized(ctx, func(authorizeCtx context.Context, parsed streamauth.Header) error {
			slog.Info("peer authorized stream authorizing", "consumer", parsed.Consumer, "operation_id", parsed.OperationID, "stream_id", parsed.StreamID)
			if !containsConsumer(descriptor.StreamPolicy.AllowedConsumers, parsed.Consumer) {
				return ErrStreamDispatch
			}
			authorizeErr := s.config.AuthorizeStream(authorizeCtx, parsed)
			slog.Info("peer authorized stream authorized", "consumer", parsed.Consumer, "operation_id", parsed.OperationID, "stream_id", parsed.StreamID, "error", authorizeErr)
			return authorizeErr
		})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		slog.Info("peer authorized stream accepted", "consumer", header.Consumer, "operation_id", header.OperationID, "stream_id", header.StreamID, "resumable", header.Resumable)
		select {
		case permits <- struct{}{}:
		case <-ctx.Done():
			_ = connection.Close()
			return ctx.Err()
		default:
			_ = connection.Close()
			continue
		}
		streams.Add(1)
		go func(conn net.Conn, value streamauth.Header) {
			defer streams.Done()
			defer func() { <-permits }()
			if value.Resumable {
				slog.Info("peer resumable stream attaching", "consumer", value.Consumer, "operation_id", value.OperationID, "stream_id", value.StreamID)
				if err := s.streams.Attach(descriptor.InitiatorEndpointID, value, conn, s.config.ServeStream, activity); err != nil && s.config.ObserveError != nil {
					s.config.ObserveError(err)
				} else {
					slog.Info("peer resumable stream attached", "consumer", value.Consumer, "operation_id", value.OperationID, "stream_id", value.StreamID)
				}
				return
			}
			if activity != nil {
				activity.Open()
				defer activity.Close()
			}
			if err := s.config.ServeStream(ctx, value, conn); err != nil && s.config.ObserveError != nil {
				s.config.ObserveError(fmt.Errorf("authorized %s stream %s failed: %w", value.Consumer, value.StreamID, err))
			}
			_ = conn.Close()
		}(connection, header)
	}
}

func containsConsumer(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func (s *Service) exchangeTransferKey(stream net.Conn, descriptor api.PeerAttemptDescriptor, authority peersession.Authority) error {
	transfer := descriptor.Transfer
	if transfer == nil || s.config.TransferKeys == nil {
		return ErrInvalid
	}
	binding := transfercrypto.KeyControlBinding{OperationID: authority.Context.OperationID, TransferID: transfer.TransferID, Generation: transfer.Generation, ExpiresAt: transfer.ExpiresAt}
	material, _, err := s.config.TransferKeys.LoadLocal(transfer.TransferID, transfer.Generation)
	if err == nil {
		defer material.Destroy()
		if err := transfercrypto.DeliverKey(stream, binding, material); err != nil {
			return err
		}
		return s.config.TransferKeys.SaveLocalBound(transfer.TransferID, transfer.Generation, material, transfer.ExpiresAt, authority.Context)
	}
	if !errors.Is(err, transfercrypto.ErrKeyUnavailable) {
		return err
	}
	return transfercrypto.ReceiveKey(stream, binding, authority.Context, s.config.TransferKeys)
}

func descriptorCertificate(descriptor api.PeerAttemptDescriptor, endpointID string, rootPublic ed25519.PublicKey, now time.Time) (endpointidentity.Certificate, error) {
	for _, document := range descriptor.EndpointCertificates {
		if document.EndpointID != endpointID {
			continue
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(document.Certificate)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != document.Certificate {
			return endpointidentity.Certificate{}, ErrInvalid
		}
		return endpointidentity.Verify(raw, rootPublic, endpointidentity.Expected{AccountID: descriptor.AccountID, Role: endpointidentity.RoleCLI, EndpointID: endpointID}, now)
	}
	return endpointidentity.Certificate{}, ErrInvalid
}
