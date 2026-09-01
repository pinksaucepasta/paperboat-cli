package peerrelay

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/candidatelease"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peersession"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaycarrier"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

func TestOnlyDirectProbeUsesLifetimeProtocol(t *testing.T) {
	if !lifetimeProbePurpose("direct_probe") {
		t.Fatal("direct probe did not select lifetime protocol")
	}
	for _, purpose := range []string{"health_probe", "interactive", "private_preview", "codex", "file_transfer_key"} {
		if lifetimeProbePurpose(purpose) {
			t.Fatalf("purpose %q selected lifetime protocol", purpose)
		}
	}
}

func TestObservePathErrorSuppressesOnlyCanceledPathTeardown(t *testing.T) {
	observed := make(chan error, 1)
	service := &Service{config: Config{ObserveError: func(err error) { observed <- err }}}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	service.observePathError(canceled, io.EOF)
	select {
	case err := <-observed:
		t.Fatalf("observed canceled teardown: %v", err)
	default:
	}

	service.observePathError(context.Background(), io.EOF)
	select {
	case err := <-observed:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("observed error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unexpected EOF was suppressed")
	}
}

func TestDescriptorAllowedPathsSelectsOnlyAuthorizedHostCarriers(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		paths              []string
		direct, relay, wss bool
	}{
		{[]string{"direct_quic", "relay_quic", "relay_wss"}, true, true, true},
		{[]string{"direct_quic", "relay_quic"}, true, true, false},
		{[]string{"direct_quic"}, true, false, false},
		{[]string{"relay_quic"}, false, true, false},
		{[]string{"relay_quic", "relay_wss"}, false, true, true},
		{[]string{"relay_wss"}, false, false, true},
		{[]string{"relay_wss", "direct_quic"}, false, false, false},
		{[]string{"relay_wss", "relay_wss"}, false, false, false},
		{[]string{"unknown"}, false, false, false},
	} {
		direct, relay, wss := descriptorAllowedPaths(test.paths)
		if direct != test.direct || relay != test.relay || wss != test.wss {
			t.Fatalf("paths=%v got=(%t,%t,%t) want=(%t,%t,%t)", test.paths, direct, relay, wss, test.direct, test.relay, test.wss)
		}
	}
}

func TestMultiPathAttemptsLeaveWinnerSelectionToInitiator(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name               string
		direct, relay, wss bool
		want               int
	}{
		{"auto", true, true, true, 3},
		{"direct and relay", true, true, false, 2},
		{"relay race", false, true, true, 2},
		{"direct only", true, false, false, 1},
		{"relay QUIC only", false, true, false, 1},
		{"WSS only", false, false, true, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := allowedPathCount(test.direct, test.relay, test.wss); got != test.want {
				t.Fatalf("allowed path count=%d want=%d", got, test.want)
			}
		})
	}
}

type transferKeySecrets struct {
	mu    sync.Mutex
	items map[string]string
}

func (s *transferKeySecrets) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[key] = value
	return nil
}

func (s *transferKeySecrets) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.items[key]
	if !ok {
		return "", errors.New("missing")
	}
	return value, nil
}

func (s *transferKeySecrets) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
	return nil
}

type sourceFunc func(context.Context) (api.PeerAttemptDescriptor, error)

func (f sourceFunc) Next(ctx context.Context) (api.PeerAttemptDescriptor, error) { return f(ctx) }

type saturatingSource struct {
	descriptors chan api.PeerAttemptDescriptor
	rejected    chan api.PeerAttemptDescriptor
}

func (s *saturatingSource) Next(ctx context.Context) (api.PeerAttemptDescriptor, error) {
	select {
	case descriptor := <-s.descriptors:
		return descriptor, nil
	case <-ctx.Done():
		return api.PeerAttemptDescriptor{}, ctx.Err()
	}
}

func (s *saturatingSource) Reject(ctx context.Context, descriptor api.PeerAttemptDescriptor) error {
	select {
	case s.rejected <- descriptor:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestRunKeepsPollingWhenAttemptLimitIsSaturated(t *testing.T) {
	source := &saturatingSource{descriptors: make(chan api.PeerAttemptDescriptor), rejected: make(chan api.PeerAttemptDescriptor, 1)}
	service := &Service{
		config: Config{Source: source, AttemptLimit: 1, PollInterval: 50 * time.Millisecond},
		done:   make(chan struct{}), streams: newStreamRegistry(),
		serveAttemptFn: func(ctx context.Context, _ api.PeerAttemptDescriptor) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		service.run(ctx)
		close(runDone)
	}()
	first := api.PeerAttemptDescriptor{IntentID: "intent_1", AttemptGeneration: 1}
	second := api.PeerAttemptDescriptor{IntentID: "intent_2", AttemptGeneration: 2}
	source.descriptors <- first
	source.descriptors <- second
	select {
	case rejected := <-source.rejected:
		if rejected.IntentID != second.IntentID {
			t.Fatalf("rejected=%+v", rejected)
		}
	case <-time.After(time.Second):
		t.Fatal("saturated poll did not reject and continue")
	}
	cancel()
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("relay poller did not shut down")
	}
}

func TestPathSetupContextUsesDescriptorDeadline(t *testing.T) {
	started := time.Now()
	ctx, cancel, err := pathSetupContext(context.Background(), 25)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.Before(started.Add(20*time.Millisecond)) || deadline.After(started.Add(100*time.Millisecond)) {
		t.Fatalf("deadline=%v started=%v", deadline, started)
	}
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("err=%v", ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("path setup ignored descriptor deadline")
	}
	if _, _, err := pathSetupContext(context.Background(), 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid deadline err=%v", err)
	}
}

func TestDirectSetupContextUsesShortestEstablishmentDeadline(t *testing.T) {
	now := time.Now()
	policyCtx, cancelPolicy := context.WithDeadline(context.Background(), now.Add(250*time.Millisecond))
	defer cancelPolicy()
	ctx, cancel, err := directSetupContext(policyCtx, now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.Before(now.Add(200*time.Millisecond)) || deadline.After(now.Add(300*time.Millisecond)) {
		t.Fatalf("policy deadline=%v ok=%v", deadline, ok)
	}

	expiresAt := now.Add(100 * time.Millisecond)
	ctx, cancel, err = directSetupContext(context.Background(), expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	deadline, ok = ctx.Deadline()
	if !ok || !deadline.Equal(expiresAt) {
		t.Fatalf("descriptor deadline=%v ok=%v", deadline, ok)
	}

	var nilParent context.Context
	if _, _, err := directSetupContext(nilParent, expiresAt); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil parent error=%v", err)
	}
}

func TestWSSCarrierUsesApplicationLifetimeAfterSetup(t *testing.T) {
	setup, cancelSetup := context.WithCancel(context.Background())
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	captured := make(chan context.Context, 1)
	wantErr := errors.New("dial stopped after capture")
	service := &Service{config: Config{
		TLS: &tls.Config{MinVersion: tls.VersionTLS13},
		Dial: func(_ context.Context, config relaycarrier.WSSDialConfig) (*relaycarrier.Connection, error) {
			captured <- config.Lifetime
			return nil, wantErr
		},
	}}
	descriptor := api.PeerAttemptDescriptor{Relays: []api.PeerAttemptRelay{{Region: "relay_1", WSSURL: "wss://relay.example.test/v1/peer-relay", RouteToken: "one.two.three"}}}
	authority := peersession.Authority{Context: peercontext.Context{}, RouteHandle: [16]byte{1}}
	if _, err := service.serveWSS(setup, lifetime, descriptor, authority, func() bool { return true }, nil); !errors.Is(err, wantErr) {
		t.Fatalf("serve WSS error=%v", err)
	}
	carrierLifetime := <-captured
	cancelSetup()
	select {
	case <-carrierLifetime.Done():
		t.Fatal("setup cancellation closed the WSS carrier lifetime")
	default:
	}
	cancelLifetime()
	select {
	case <-carrierLifetime.Done():
	case <-time.After(time.Second):
		t.Fatal("application cancellation did not close the WSS carrier lifetime")
	}
}

func TestEstablishedCarrierOutlivesSetupDeadline(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	setup, cancelSetup := context.WithTimeout(parent, 20*time.Millisecond)
	carrier, cancelCarrier := establishedCarrierContext(parent)
	defer cancelCarrier()
	<-setup.Done()
	cancelSetup()
	select {
	case <-carrier.Done():
		t.Fatal("setup deadline closed established carrier")
	default:
	}
	cancelParent()
	select {
	case <-carrier.Done():
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not close established carrier")
	}
}

func TestNetworkChangedCancelsAllDirectAttemptsOncePerLocalGeneration(t *testing.T) {
	t.Parallel()
	service, err := New(Config{Source: sourceFunc(func(context.Context) (api.PeerAttemptDescriptor, error) {
		return api.PeerAttemptDescriptor{}, context.Canceled
	}), StateRoot: t.TempDir(), TLS: &tls.Config{MinVersion: tls.VersionTLS13}, Serve: func(net.Conn) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	secondCtx, cancelSecond := context.WithCancel(context.Background())
	service.directAttempts[&directAttempt{cancel: cancelFirst}] = struct{}{}
	service.directAttempts[&directAttempt{cancel: cancelSecond}] = struct{}{}
	if !service.NetworkChanged(1) || service.NetworkChanged(1) || len(service.directAttempts) != 0 {
		t.Fatal("local network generation was not fenced exactly once")
	}
	for name, ctx := range map[string]context.Context{"first": firstCtx, "second": secondCtx} {
		if ctx.Err() != context.Canceled {
			t.Fatalf("%s attempt was not canceled", name)
		}
	}
}

func TestOwnTransportRejectsDuplicateWithoutCancelingEstablishedOwner(t *testing.T) {
	service := &Service{}
	first, releaseFirst, firstAdmitted := service.ownTransport(context.Background(), transportKey{initiator: "cli_1", intent: "intent_1", attempt: 1})
	second, releaseSecond, secondAdmitted := service.ownTransport(context.Background(), transportKey{initiator: "cli_1", intent: "intent_1", attempt: 1})
	third, releaseThird, thirdAdmitted := service.ownTransport(context.Background(), transportKey{initiator: "cli_1", intent: "intent_2", attempt: 2})
	defer releaseFirst()
	defer releaseSecond()
	defer releaseThird()
	if !firstAdmitted || secondAdmitted || !thirdAdmitted {
		t.Fatalf("admission first=%v duplicate=%v distinct=%v", firstAdmitted, secondAdmitted, thirdAdmitted)
	}

	select {
	case <-first.Done():
		t.Fatal("duplicate attempt canceled the established owner")
	default:
	}
	select {
	case <-second.Done():
	default:
		t.Fatal("duplicate attempt was not canceled")
	}
	select {
	case <-third.Done():
		t.Fatal("distinct generation was unexpectedly canceled")
	default:
	}

	// Releasing the established owner makes the exact attempt key available
	// again; cleanup of a rejected duplicate remains a no-op.
	releaseFirst()
	releaseSecond()
	replacement, releaseReplacement, replacementAdmitted := service.ownTransport(context.Background(), transportKey{initiator: "cli_1", intent: "intent_1", attempt: 1})
	if !replacementAdmitted {
		t.Fatal("released attempt key did not admit a fresh owner")
	}
	releaseReplacement()
	select {
	case <-replacement.Done():
	default:
		t.Fatal("fresh owner was not canceled on release")
	}
}

func TestRetainedPathFailureDoesNotCancelOrCompleteSibling(t *testing.T) {
	results := make(chan pathResult, 2)
	canceled := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- awaitPathResults(2, true, results, func() { canceled <- struct{}{} })
	}()
	relayErr := errors.New("relay session shutdown")
	results <- pathResult{claimed: true, terminal: true, err: relayErr}
	select {
	case <-canceled:
		t.Fatal("failed retained path canceled its sibling")
	case err := <-done:
		t.Fatalf("attempt completed while retained sibling was active: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	wssErr := errors.New("WSS candidate closed")
	results <- pathResult{claimed: true, err: wssErr}
	select {
	case err := <-done:
		if !errors.Is(err, relayErr) {
			t.Fatalf("attempt result=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("attempt did not finish after every retained path ended")
	}
}

func TestDescriptorJoinEndsAfterFinalCandidate(t *testing.T) {
	results := make(chan pathResult, 3)
	done := make(chan error, 1)
	go func() { done <- awaitPathResults(3, true, results) }()
	results <- pathResult{claimed: true, err: io.EOF}
	results <- pathResult{claimed: true, err: net.ErrClosed}
	select {
	case err := <-done:
		t.Fatalf("descriptor ended before final candidate: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	results <- pathResult{claimed: true, err: context.Canceled}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("descriptor did not end after final candidate")
	}
}

func TestSetupExpiryDoesNotCancelEstablishedCandidate(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	setup, cancelSetup := context.WithTimeout(parent, 20*time.Millisecond)
	owner := newCandidateOwner(parent, nil)
	defer owner.Stop()
	transport, cancelTransport := relayTransportContext(owner.ctx, owner.activity)
	defer cancelTransport()
	<-setup.Done()
	cancelSetup()
	select {
	case <-owner.ctx.Done():
		t.Fatal("setup expiry canceled established candidate")
	default:
	}
	select {
	case <-transport.Done():
		t.Fatal("setup expiry canceled established candidate control")
	default:
	}
}

func TestRelayCandidateReleaseCancelsTransportLifetime(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	owner := newCandidateOwner(parent, nil)
	id := candidatelease.ID("candidate")
	if err := owner.Configure(id, 7); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := relayTransportContext(parent, owner.activity)
	defer cancel()
	if _, err := owner.Handle(candidatelease.Message{Version: 1, Type: candidatelease.Adopt, Candidate: id, LeaseGeneration: 7}); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Handle(candidatelease.Message{Version: 1, Type: candidatelease.Release, Candidate: id, LeaseGeneration: 7}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("candidate release did not cancel relay transport lifetime")
	}
	select {
	case <-parent.Done():
		t.Fatal("candidate release canceled descriptor authority")
	default:
	}
}

func TestExchangeTransferKeySelectsDirectionFromHostOwnership(t *testing.T) {
	t.Parallel()
	expires := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	binding := transfercrypto.KeyControlBinding{OperationID: "operation_01", TransferID: "transfer_01", Generation: 1, ExpiresAt: expires}
	peer := peercontext.Context{
		AccountID: "account_01", UserID: "account_01", DeviceID: "cli_01", MachineID: "machine_01",
		InitiatorCertificateHash: sha256.Sum256([]byte("initiator")), ResponderCertificateHash: sha256.Sum256([]byte("responder")),
		HostGeneration: 1, AuthorizationGeneration: 1, IntentID: "intent_01", OperationID: binding.OperationID,
		Consumer: "file_transfer_key", InitiatorRole: "controlling", ResponderRole: "controlled", AttemptGeneration: 1,
	}
	descriptor := api.PeerAttemptDescriptor{Transfer: &api.PeerAttemptTransfer{TransferID: binding.TransferID, Generation: binding.Generation, ExpiresAt: expires}}
	authority := peersession.Authority{Context: peer}

	t.Run("receives when host has no key", func(t *testing.T) {
		hostVault, _ := transfercrypto.NewKeyVault(&transferKeySecrets{items: make(map[string]string)})
		acknowledged := make(chan struct{}, 2)
		service := &Service{config: Config{TransferKeys: hostVault, ObserveTransferKeyAcknowledged: func() { acknowledged <- struct{}{} }}}
		material, _ := transfercrypto.GenerateKeyMaterial()
		host, client := net.Pipe()
		result := make(chan error, 1)
		go func() { result <- service.exchangeTransferKey(host, descriptor, authority) }()
		if err := transfercrypto.DeliverKey(client, binding, material); err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		select {
		case <-acknowledged:
		case <-time.After(time.Second):
			t.Fatal("successful receiver acknowledgement was not observed")
		}
		stored, storedPeer, err := hostVault.LoadBound(binding.TransferID, binding.Generation)
		if err != nil || stored != material || storedPeer != peer {
			t.Fatalf("stored key binding mismatch: peer=%+v err=%v", storedPeer, err)
		}
		stored.Destroy()
		retryHost, retryClient := net.Pipe()
		retryResult := make(chan error, 1)
		go func() { retryResult <- service.exchangeTransferKey(retryHost, descriptor, authority) }()
		if err := transfercrypto.DeliverKey(retryClient, binding, material); err != nil {
			t.Fatal(err)
		}
		_ = retryClient.Close()
		if err := <-retryResult; err != nil {
			t.Fatalf("receive retry changed direction: %v", err)
		}
		select {
		case <-acknowledged:
		case <-time.After(time.Second):
			t.Fatal("successful retry acknowledgement was not observed")
		}
		material.Destroy()
	})

	t.Run("delivers when host owns key", func(t *testing.T) {
		hostVault, _ := transfercrypto.NewKeyVault(&transferKeySecrets{items: make(map[string]string)})
		clientVault, _ := transfercrypto.NewKeyVault(&transferKeySecrets{items: make(map[string]string)})
		material, _ := transfercrypto.GenerateKeyMaterial()
		if err := hostVault.Save(binding.TransferID, binding.Generation, material, expires); err != nil {
			t.Fatal(err)
		}
		acknowledged := make(chan struct{}, 1)
		service := &Service{config: Config{TransferKeys: hostVault, ObserveTransferKeyAcknowledged: func() { acknowledged <- struct{}{} }}}
		host, client := net.Pipe()
		result := make(chan error, 1)
		go func() { result <- service.exchangeTransferKey(host, descriptor, authority) }()
		if err := transfercrypto.ReceiveKey(client, binding, peer, clientVault); err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		stored, storedPeer, err := hostVault.LoadBound(binding.TransferID, binding.Generation)
		if err != nil || stored != material || storedPeer != peer {
			t.Fatalf("host binding mismatch: peer=%+v err=%v", storedPeer, err)
		}
		stored.Destroy()
		received, receivedPeer, err := clientVault.LoadBound(binding.TransferID, binding.Generation)
		if err != nil || received != material || receivedPeer != peer {
			t.Fatalf("received key binding mismatch: peer=%+v err=%v", receivedPeer, err)
		}
		received.Destroy()
		retryHost, retryClient := net.Pipe()
		retryResult := make(chan error, 1)
		go func() { retryResult <- service.exchangeTransferKey(retryHost, descriptor, authority) }()
		if err := transfercrypto.ReceiveKey(retryClient, binding, peer, clientVault); err != nil {
			t.Fatal(err)
		}
		_ = retryClient.Close()
		if err := <-retryResult; err != nil {
			t.Fatalf("delivery retry changed direction: %v", err)
		}
		select {
		case <-acknowledged:
			t.Fatal("sender-side transfer-key delivery reported a receiver acknowledgement")
		default:
		}
		material.Destroy()
	})
}
