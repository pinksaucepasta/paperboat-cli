package portmapping

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeBackend struct {
	mu           sync.Mutex
	port         uint16
	mapping      netip.AddrPort
	hasMapping   bool
	probe        func(context.Context) error
	probeCalls   int
	networkDown  int
	closeCalls   int
	mappingHook  func()
	mappingCalls int
	protocol     string
}

func (b *fakeBackend) Protocol() string {
	if b.protocol == "" {
		return "pcp"
	}
	return b.protocol
}

func (b *fakeBackend) SetLocalPort(port uint16) {
	b.mu.Lock()
	b.port = port
	b.mu.Unlock()
}

func (b *fakeBackend) Probe(ctx context.Context) error {
	b.mu.Lock()
	b.probeCalls++
	probe := b.probe
	b.mu.Unlock()
	if probe != nil {
		return probe(ctx)
	}
	return nil
}

func (b *fakeBackend) Mapping() (netip.AddrPort, bool) {
	b.mu.Lock()
	b.mappingCalls++
	mapping, ok, hook := b.mapping, b.hasMapping, b.mappingHook
	b.mu.Unlock()
	if hook != nil {
		hook()
	}
	return mapping, ok
}

func (b *fakeBackend) NetworkDown() {
	b.mu.Lock()
	b.networkDown++
	b.hasMapping = false
	b.mu.Unlock()
}

func (b *fakeBackend) Close() error {
	b.mu.Lock()
	b.closeCalls++
	b.mu.Unlock()
	return nil
}

func (b *fakeBackend) setMapping(mapping netip.AddrPort) {
	b.mu.Lock()
	b.mapping = mapping
	b.hasMapping = true
	b.mu.Unlock()
}

func (b *fakeBackend) probeCallCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.probeCalls
}

func (b *fakeBackend) mappingCallCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.mappingCalls
}

type fakeVerifier struct {
	mu       sync.Mutex
	err      error
	calls    int
	external netip.AddrPort
	port     uint16
	verify   func(context.Context) error
}

func (v *fakeVerifier) VerifyMapping(ctx context.Context, external netip.AddrPort, port uint16) error {
	v.mu.Lock()
	v.calls++
	v.external = external
	v.port = port
	verify := v.verify
	err := v.err
	v.mu.Unlock()
	if verify != nil {
		return verify(ctx)
	}
	return err
}

func newTestManager(t *testing.T, backend *fakeBackend, verifier *fakeVerifier, onState func(State)) *Manager {
	t.Helper()
	manager, err := New(Config{
		Backend:       backend,
		Verifier:      verifier,
		Trust:         func() InterfaceTrust { return TrustPrivateLAN },
		ProbeTimeout:  100 * time.Millisecond,
		CreateTimeout: 500 * time.Millisecond,
		OnState:       onState,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestAcquirePublishesOnlyVerifiedPrivateLANMapping(t *testing.T) {
	external := netip.MustParseAddrPort("198.51.100.4:5443")
	backend := &fakeBackend{mapping: external, hasMapping: true}
	verifier := &fakeVerifier{}
	var manager *Manager
	manager = newTestManager(t, backend, verifier, func(State) {
		_ = manager.State() // Callbacks must be safe to re-enter.
	})

	got, err := manager.Acquire(context.Background(), 7, 4242)
	if err != nil {
		t.Fatal(err)
	}
	if got != external {
		t.Fatalf("mapping = %v, want %v", got, external)
	}
	if published, ok := manager.Mapping(7); !ok || published != external {
		t.Fatalf("published mapping = %v, %v", published, ok)
	}
	verified, ok := manager.Verified(7)
	if !ok || !verified.Valid() || verified.External() != external || verified.LocalPort() != 4242 || verified.Generation() != 7 {
		t.Fatalf("verified mapping = %+v, %v", verified, ok)
	}
	if _, ok := manager.Verified(6); ok {
		t.Fatal("verified mapping issued for stale generation")
	}
	if _, ok := manager.Mapping(6); ok {
		t.Fatal("mapping published for stale generation")
	}
	if state := manager.State(); state.Result != ResultVerified || state.Retryable {
		t.Fatalf("state = %+v", state)
	}
	if backend.port != 4242 || backend.probeCalls != 1 {
		t.Fatalf("backend port/calls = %d/%d", backend.port, backend.probeCalls)
	}
	if verifier.calls != 1 || verifier.external != external || verifier.port != 4242 {
		t.Fatalf("verifier = calls %d, external %v, port %d", verifier.calls, verifier.external, verifier.port)
	}
	backend.setMapping(netip.MustParseAddrPort("198.51.100.4:6443"))
	manager.Changed()
	select {
	case <-verified.Invalidated():
	case <-time.After(time.Second):
		t.Fatal("verified mapping invalidation signal not closed")
	}
	if verified.Valid() {
		t.Fatal("issued mapping remained valid after backend change")
	}
	if _, ok := manager.Mapping(7); ok {
		t.Fatal("mapping remained published after backend change")
	}
	if state := manager.State(); state.Result != ResultInvalidated || !state.Retryable {
		t.Fatalf("changed state=%+v", state)
	}
}

func TestSameExternalRenewalPreservesVerifiedCapability(t *testing.T) {
	external := netip.MustParseAddrPort("198.51.100.4:5443")
	backend := &fakeBackend{mapping: external, hasMapping: true}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	if _, err := manager.Acquire(context.Background(), 7, 4242); err != nil {
		t.Fatal(err)
	}
	verified, ok := manager.Verified(7)
	if !ok || verified.Protocol() != "pcp" {
		t.Fatal("verified mapping not issued")
	}
	manager.Changed()
	if !verified.Valid() {
		t.Fatal("same-external renewal invalidated capability")
	}
	if state := manager.State(); state.Result != ResultVerified || state.Generation != 7 {
		t.Fatalf("state=%+v", state)
	}
}

func TestAcquireRejectsUnclassifiedMappingProtocol(t *testing.T) {
	backend := &fakeBackend{mapping: netip.MustParseAddrPort("198.51.100.4:5443"), hasMapping: true, protocol: "router description 192.0.2.1"}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	if _, err := manager.Acquire(context.Background(), 7, 4242); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error=%v", err)
	}
	if _, ok := manager.Verified(7); ok {
		t.Fatal("unclassified protocol produced verified capability")
	}
}

func TestManagerRebindsSingletonBackendToNewGenerationPort(t *testing.T) {
	backend := &fakeBackend{mapping: netip.MustParseAddrPort("198.51.100.4:5443"), hasMapping: true}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	if _, err := manager.Acquire(context.Background(), 1, 4242); err != nil {
		t.Fatal(err)
	}
	first, ok := manager.Verified(1)
	if !ok || first.LocalPort() != 4242 {
		t.Fatalf("first=%+v ok=%v", first, ok)
	}
	backend.setMapping(netip.MustParseAddrPort("198.51.100.4:6443"))
	if _, err := manager.Acquire(context.Background(), 2, 4343); err != nil {
		t.Fatal(err)
	}
	second, ok := manager.Verified(2)
	if !ok || second.LocalPort() != 4343 || backend.port != 4343 {
		t.Fatalf("second=%+v ok=%v backend port=%d", second, ok, backend.port)
	}
	if first.Valid() {
		t.Fatal("old socket-port capability remained valid")
	}
	select {
	case <-first.Invalidated():
	default:
		t.Fatal("old socket-port invalidation was not published")
	}
}

func TestAcquireRejectsZeroSocketPortBeforeTrustOrBackend(t *testing.T) {
	backend := &fakeBackend{}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	trustCalls := 0
	manager.config.Trust = func() InterfaceTrust { trustCalls++; return TrustPrivateLAN }
	if _, err := manager.Acquire(context.Background(), 1, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error=%v", err)
	}
	if trustCalls != 0 || backend.probeCallCount() != 0 {
		t.Fatalf("trust calls=%d probe calls=%d", trustCalls, backend.probeCallCount())
	}
}

func TestAcquireRejectsEveryNonPrivateInterfaceBeforeProbe(t *testing.T) {
	for _, trust := range []InterfaceTrust{TrustPublic, TrustVPN, TrustCellular, TrustUntrusted} {
		t.Run(string(rune(trust+'0')), func(t *testing.T) {
			backend := &fakeBackend{}
			manager := newTestManager(t, backend, &fakeVerifier{}, nil)
			manager.config.Trust = func() InterfaceTrust { return trust }
			if _, err := manager.Acquire(context.Background(), 1, 4242); !errors.Is(err, ErrUntrusted) {
				t.Fatalf("error = %v", err)
			}
			if backend.probeCalls != 0 {
				t.Fatalf("Probe called %d times", backend.probeCalls)
			}
			if state := manager.State(); state.Result != ResultInvalidated || state.Retryable {
				t.Fatalf("state = %+v", state)
			}
		})
	}
}

func TestAcquireUsesOneOwnedTrustSnapshot(t *testing.T) {
	backend := &fakeBackend{}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	calls := 0
	manager.config.Trust = func() InterfaceTrust {
		calls++
		if calls == 1 {
			return TrustPublic
		}
		return TrustPrivateLAN
	}
	if _, err := manager.Acquire(context.Background(), 1, 4242); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("error=%v", err)
	}
	if calls != 1 || backend.probeCallCount() != 0 {
		t.Fatalf("trust calls=%d probe calls=%d", calls, backend.probeCallCount())
	}
	if state := manager.State(); state.Result != ResultInvalidated || state.Retryable {
		t.Fatalf("state=%+v", state)
	}
}

func TestAcquireRejectsInvalidMappingAndReleasesBackend(t *testing.T) {
	backend := &fakeBackend{mapping: netip.MustParseAddrPort("127.0.0.1:80"), hasMapping: true}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	if _, err := manager.Acquire(context.Background(), 1, 4242); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v", err)
	}
	if backend.networkDown != 1 {
		t.Fatalf("NetworkDown calls = %d", backend.networkDown)
	}
	if state := manager.State(); state.Result != ResultUnavailable || state.Retryable {
		t.Fatalf("state = %+v", state)
	}
}

func TestAcquireVerificationFailureIsNotPublished(t *testing.T) {
	wantErr := errors.New("not reachable")
	backend := &fakeBackend{mapping: netip.MustParseAddrPort("100.64.0.1:443"), hasMapping: true}
	manager := newTestManager(t, backend, &fakeVerifier{err: wantErr}, nil)
	if _, err := manager.Acquire(context.Background(), 2, 4242); !errors.Is(err, wantErr) || !errors.Is(err, ErrUnreachable) {
		t.Fatalf("error = %v", err)
	}
	if _, ok := manager.Mapping(2); ok {
		t.Fatal("failed mapping was published")
	}
	if backend.networkDown != 1 {
		t.Fatalf("NetworkDown calls = %d", backend.networkDown)
	}
}

func TestAcquireProbeFailureIsTypedUnavailable(t *testing.T) {
	wantErr := errors.New("router discovery failed")
	backend := &fakeBackend{probe: func(context.Context) error { return wantErr }}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	if _, err := manager.Acquire(context.Background(), 2, 4242); !errors.Is(err, wantErr) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error=%v", err)
	}
	if state := manager.State(); state.Result != ResultUnavailable || !state.Retryable {
		t.Fatalf("state=%+v", state)
	}
}

func TestBackendChangeDuringVerificationFencesStaleMapping(t *testing.T) {
	verifyStarted := make(chan struct{})
	releaseVerify := make(chan struct{})
	backend := &fakeBackend{mapping: netip.MustParseAddrPort("198.51.100.8:4242"), hasMapping: true}
	verifier := &fakeVerifier{verify: func(context.Context) error {
		close(verifyStarted)
		<-releaseVerify // Deliberately ignore cancellation.
		return nil
	}}
	manager := newTestManager(t, backend, verifier, nil)
	done := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), 2, 4242)
		done <- err
	}()
	<-verifyStarted
	manager.Changed()
	close(releaseVerify)
	if err := <-done; !errors.Is(err, ErrStale) {
		t.Fatalf("error=%v", err)
	}
	if _, ok := manager.Mapping(2); ok {
		t.Fatal("stale mapping published")
	}
	if state := manager.State(); state.Result != ResultInvalidated || !state.Retryable {
		t.Fatalf("state=%+v", state)
	}
}

func TestBackendChangeDuringMappingReadFencesAttempt(t *testing.T) {
	backend := &fakeBackend{mapping: netip.MustParseAddrPort("198.51.100.8:4242"), hasMapping: true}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	var once sync.Once
	backend.mappingHook = func() { once.Do(manager.Changed) }
	if _, err := manager.Acquire(context.Background(), 2, 4242); !errors.Is(err, ErrStale) {
		t.Fatalf("error=%v", err)
	}
	if _, ok := manager.Mapping(2); ok {
		t.Fatal("stale mapping published")
	}
	if state := manager.State(); state.Result != ResultInvalidated || !state.Retryable {
		t.Fatalf("state=%+v", state)
	}
}

func TestAcquireWaitsForBackendChange(t *testing.T) {
	backend := &fakeBackend{}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	external := netip.MustParseAddrPort("192.168.1.2:9000")
	done := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), 3, 4242)
		done <- err
	}()
	waitFor(t, func() bool { return backend.probeCallCount() == 1 })
	backend.setMapping(external)
	manager.Changed()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if mapping, ok := manager.Mapping(3); !ok || mapping != external {
		t.Fatalf("mapping = %v, %v", mapping, ok)
	}
}

func TestNewManagedWiresBackendChangesAndOwnsFailureCleanup(t *testing.T) {
	backend := &fakeBackend{}
	var changed func()
	manager, err := NewManaged(Config{
		Verifier:      &fakeVerifier{},
		Trust:         func() InterfaceTrust { return TrustPrivateLAN },
		ProbeTimeout:  100 * time.Millisecond,
		CreateTimeout: 500 * time.Millisecond,
	}, func(onChange func()) (Backend, error) {
		changed = onChange
		return backend, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), 3, 4242)
		done <- err
	}()
	waitFor(t, func() bool { return backend.probeCallCount() == 1 })
	backend.setMapping(netip.MustParseAddrPort("198.51.100.9:4242"))
	changed()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	badBackend := &fakeBackend{}
	if _, err := NewManaged(Config{}, func(func()) (Backend, error) {
		return badBackend, nil
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid configuration error = %v", err)
	}
	if badBackend.closeCalls != 1 {
		t.Fatalf("failed-construction Close calls = %d", badBackend.closeCalls)
	}
}

func TestManagerRejectsTypedNilOwnersWithoutCleanupPanic(t *testing.T) {
	var backend *fakeBackend
	var verifier *fakeVerifier
	base := Config{Backend: &fakeBackend{}, Verifier: &fakeVerifier{}, Trust: func() InterfaceTrust { return TrustPrivateLAN }, ProbeTimeout: time.Second, CreateTimeout: 2 * time.Second}
	withBackend := base
	withBackend.Backend = backend
	if _, err := New(withBackend); !errors.Is(err, ErrInvalid) {
		t.Fatalf("typed-nil backend error=%v", err)
	}
	withVerifier := base
	withVerifier.Verifier = verifier
	if _, err := New(withVerifier); !errors.Is(err, ErrInvalid) {
		t.Fatalf("typed-nil verifier error=%v", err)
	}
	withoutTrust := base
	withoutTrust.Trust = nil
	if _, err := New(withoutTrust); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing trust source error=%v", err)
	}
	managed := base
	managed.Backend = nil
	if _, err := NewManaged(managed, func(func()) (Backend, error) { return backend, nil }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("typed-nil managed backend error=%v", err)
	}
}

func TestAcquireAttemptExhaustionIsPermanentAndNonMutating(t *testing.T) {
	backend := &fakeBackend{mapping: netip.MustParseAddrPort("198.51.100.4:5443"), hasMapping: true}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	manager.nextAttempt = math.MaxUint64
	wantState := manager.State()

	for range 2 {
		if _, err := manager.Acquire(context.Background(), 7, 4242); !errors.Is(err, ErrExhausted) {
			t.Fatalf("error=%v", err)
		}
		if manager.nextAttempt != math.MaxUint64 || manager.attempt != 0 || manager.generation != 0 || manager.State() != wantState || backend.probeCallCount() != 0 {
			t.Fatalf("manager mutated after exhaustion: next=%d attempt=%d generation=%d state=%+v probes=%d", manager.nextAttempt, manager.attempt, manager.generation, manager.State(), backend.probeCallCount())
		}
	}
}

func TestNetworkChangeCancelsAndFencesStaleCompletion(t *testing.T) {
	probeStarted := make(chan struct{})
	allowReturn := make(chan struct{})
	backend := &fakeBackend{probe: func(context.Context) error {
		close(probeStarted)
		<-allowReturn // Deliberately ignore cancellation.
		return nil
	}}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	done := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), 4, 4242)
		done <- err
	}()
	<-probeStarted
	changed := make(chan struct{})
	go func() {
		manager.NetworkChanged(5)
		close(changed)
	}()
	waitFor(t, func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		return manager.generation == 5
	})
	close(allowReturn)
	if err := <-done; !errors.Is(err, ErrStale) {
		t.Fatalf("error = %v", err)
	}
	<-changed
	if state := manager.State(); state.Generation != 5 || state.Result != ResultInvalidated || !state.Retryable {
		t.Fatalf("state = %+v", state)
	}
	if _, ok := manager.Mapping(4); ok {
		t.Fatal("stale mapping published")
	}
}

func TestSameGenerationNewAttemptSupersedesOldAttempt(t *testing.T) {
	firstStarted := make(chan struct{})
	allowFirst := make(chan struct{})
	var calls int
	var callsMu sync.Mutex
	backend := &fakeBackend{probe: func(context.Context) error {
		callsMu.Lock()
		calls++
		call := calls
		callsMu.Unlock()
		if call == 1 {
			close(firstStarted)
			<-allowFirst
		}
		return nil
	}}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	firstDone := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), 8, 4242)
		firstDone <- err
	}()
	<-firstStarted
	secondDone := make(chan error, 1)
	secondStarted := make(chan struct{})
	go func() {
		close(secondStarted)
		_, err := manager.Acquire(context.Background(), 8, 4242)
		secondDone <- err
	}()
	<-secondStarted
	waitFor(t, func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		return manager.nextAttempt == 2
	})
	close(allowFirst)
	if err := <-firstDone; !errors.Is(err, ErrStale) {
		t.Fatalf("first error = %v", err)
	}
	waitFor(t, func() bool { return backend.mappingCallCount() > 0 })
	backend.setMapping(netip.MustParseAddrPort("203.0.113.2:4242"))
	manager.Changed()
	if err := <-secondDone; err != nil {
		t.Fatalf("second error = %v", err)
	}
}

func TestCloseCancelsAndClosesBackendOnce(t *testing.T) {
	backend := &fakeBackend{probe: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	done := make(chan error, 1)
	go func() {
		_, err := manager.Acquire(context.Background(), 9, 4242)
		done <- err
	}()
	waitFor(t, func() bool { return backend.probeCallCount() == 1 })
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrClosed) {
		t.Fatalf("acquire error = %v", err)
	}
	if backend.closeCalls != 1 {
		t.Fatalf("Close calls = %d", backend.closeCalls)
	}
	if _, ok := manager.Mapping(9); ok {
		t.Fatal("mapping remains after close")
	}
}

func TestStaleGenerationRejected(t *testing.T) {
	backend := &fakeBackend{}
	manager := newTestManager(t, backend, &fakeVerifier{}, nil)
	manager.NetworkChanged(10)
	if _, err := manager.Acquire(context.Background(), 9, 4242); !errors.Is(err, ErrStale) {
		t.Fatalf("error = %v", err)
	}
	if backend.probeCalls != 0 {
		t.Fatalf("Probe called %d times", backend.probeCalls)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(time.Millisecond)
	}
}
