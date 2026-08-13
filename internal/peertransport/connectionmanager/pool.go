package connectionmanager

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

var (
	ErrPoolGenerationExhausted = errors.New("peer connection pool generation exhausted")
	ErrPoolLeaseExhausted      = errors.New("peer connection pool lease count exhausted")
	ErrPoolInvalidated         = errors.New("peer connection pool authority invalidated")
	ErrApplicationPromotion    = errors.New("peer application promotion failed")
)

type Pool struct {
	racer                *Racer
	grace                time.Duration
	after                func(time.Duration, func()) idleTimer
	health               ActiveHealthRunner
	healthTransport      HealthTransportFactory
	disableRelayHealth   bool
	disablePreviewHealth bool
	closeWhenIdle        bool
	candidateSource      CandidateSource
	connectTimeout       time.Duration

	mu                        sync.Mutex
	closed                    bool
	networkGeneration         uint64
	networkExhausted          bool
	classes                   map[peerquic.Class]*classState
	changes                   chan struct{}
	nextSubscriber            uint64
	subscribers               map[uint64]chan struct{}
	nextApplicationSubscriber uint64
	applicationSubscribers    map[uint64]applicationSubscriber
}

type classState struct {
	generation           uint64
	exhausted            bool
	mode                 Mode
	network              NetworkClass
	policySet            bool
	selected             *managedConnection
	standby              *managedConnection
	secondary            *managedConnection
	draining             *managedConnection
	connecting           bool
	connectCancel        context.CancelFunc
	connectToken         *ownershipToken
	warmCancel           context.CancelFunc
	upgradePending       bool
	standbyFuture        *ownershipToken
	replenishment        *standbyReplenishment
	warmHolds            uint64
	wait                 chan struct{}
	idle                 idleTimer
	idleToken            *ownershipToken
	availabilityRevision uint64
}

type AvailabilitySource struct {
	Path       Path
	Generation uint64
	Connection Connection
}

type AvailabilitySnapshot struct {
	Revision  uint64
	Preferred AvailabilitySource
	Available []AvailabilitySource
}

type applicationSubscriber struct {
	class peerquic.Class
	inbox chan AvailabilitySnapshot
}

type standbyReplenishment struct {
	token  *ownershipToken
	cancel context.CancelFunc
	path   Path
	retry  idleTimer
}

const standbyReplenishmentBackoff = 500 * time.Millisecond

type managedConnection struct {
	selection         Selection
	applicationLeases uint64
	selectedRole      bool
	standbyRole       bool
	secondaryRole     bool
	closed            bool
	healthCancel      context.CancelFunc
	healthToken       *ownershipToken
}

func logAvailabilityState(reason string, class peerquic.Class, state *classState) {
	if state == nil {
		return
	}
	slog.Info("peer pool availability transition", "reason", reason, "class", uint8(class), "generation", state.generation,
		"selected_path", entryPath(state.selected), "selected_connection", connectionIdentity(state.selected),
		"standby_path", entryPath(state.standby), "standby_connection", connectionIdentity(state.standby),
		"secondary_path", entryPath(state.secondary), "secondary_connection", connectionIdentity(state.secondary),
		"draining_path", entryPath(state.draining), "draining_connection", connectionIdentity(state.draining))
}

func entryPath(entry *managedConnection) uint8 {
	if entry == nil {
		return 0
	}
	return uint8(entry.selection.Path)
}

func connectionIdentity(entry *managedConnection) string {
	if entry == nil || nilConnection(entry.selection.Connection) {
		return ""
	}
	return fmt.Sprintf("%p", entry.selection.Connection)
}

func (e *managedConnection) draining() bool {
	return e != nil && !e.selectedRole && e.applicationLeases > 0
}

func entryOwned(e *managedConnection) bool {
	return e != nil && (e.selectedRole || e.standbyRole || e.secondaryRole || e.applicationLeases > 0)
}

func syncEntryRoles(state *classState, entries ...*managedConnection) {
	seen := make(map[*managedConnection]struct{}, len(entries)+4)
	for _, entry := range append(entries, state.selected, state.standby, state.secondary, state.draining) {
		if entry == nil {
			continue
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		entry.selectedRole = state.selected == entry
		entry.standbyRole = state.standby == entry
		entry.secondaryRole = state.secondary == entry
	}
}

func uniqueEntries(entries ...*managedConnection) []*managedConnection {
	result := make([]*managedConnection, 0, len(entries))
	seen := make(map[*managedConnection]struct{}, len(entries))
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		result = append(result, entry)
	}
	return result
}

type availabilityNotification struct {
	class              peerquic.Class
	generation         uint64
	previousEntry      *managedConnection
	selectedEntry      *managedConnection
	fallbackEntry      *managedConnection
	previousConnection Connection
	selectedConnection Connection
	fallbackConnection Connection
}

type ownershipToken struct {
	//lint:ignore U1000 The byte keeps independently allocated ownership tokens pointer-distinct.
	marker byte
}

type idleTimer interface {
	Stop() bool
}

type PoolConfig struct {
	IdleGrace                  time.Duration
	CloseWhenIdle              bool
	Health                     ActiveHealthRunner
	HealthTransport            HealthTransportFactory
	DisableRelayActiveHealth   bool
	DisablePreviewActiveHealth bool
	CandidateSource            CandidateSource
}

type ActiveHealthRunner interface {
	Run(context.Context, ActiveHealthBinding, ActiveHealthTransport) error
}

type HealthTransportFactory func(Selection) (ActiveHealthTransport, error)

func DevelopmentPoolConfig() PoolConfig {
	return PoolConfig{CloseWhenIdle: true}
}

func NewPool(racer *Racer, config PoolConfig) (*Pool, error) {
	if config.Health != nil && config.HealthTransport == nil {
		config.HealthTransport = ConnectionHealthTransport
	}
	if racer == nil || config.IdleGrace < 0 || config.IdleGrace > 10*time.Minute || !config.CloseWhenIdle && config.IdleGrace == 0 || config.Health == nil && config.HealthTransport != nil {
		return nil, errors.New("invalid connection pool configuration")
	}
	return &Pool{
		racer:                racer,
		grace:                config.IdleGrace,
		health:               config.Health,
		healthTransport:      config.HealthTransport,
		disableRelayHealth:   config.DisableRelayActiveHealth,
		disablePreviewHealth: config.DisablePreviewActiveHealth,
		closeWhenIdle:        config.CloseWhenIdle,
		candidateSource:      config.CandidateSource,
		connectTimeout:       racer.config.ConnectTimeout,
		networkGeneration:    1,
		after: func(delay time.Duration, callback func()) idleTimer {
			return time.AfterFunc(delay, callback)
		},
		classes:                make(map[peerquic.Class]*classState),
		changes:                make(chan struct{}, 1),
		subscribers:            make(map[uint64]chan struct{}),
		applicationSubscribers: make(map[uint64]applicationSubscriber),
	}, nil
}

type ClassSnapshot struct {
	Class             peerquic.Class
	Path              Path
	ActivePath        Path
	StandbyPath       Path
	RelayRegion       string
	ActiveRelayRegion string
	Generation        uint64
	Leases            uint64
	Warm              bool
	Selected          bool
	Connecting        bool
	UpgradePending    bool
	Closed            bool
}

// Changes is a coalesced wakeup channel. Consumers must read Snapshot after
// every wake; a queued signal represents all state mutations up to that read.
func (p *Pool) Changes() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.changes
}

// SubscribeChanges returns an independent coalesced wakeup queue. Long-lived
// state owners must subscribe instead of competing with observational readers
// on Changes.
func (p *Pool) SubscribeChanges() (<-chan struct{}, func()) {
	if p == nil {
		closed := make(chan struct{})
		close(closed)
		return closed, func() {}
	}
	p.mu.Lock()
	if p.nextSubscriber == math.MaxUint64 {
		p.mu.Unlock()
		closed := make(chan struct{})
		close(closed)
		return closed, func() {}
	}
	p.nextSubscriber++
	id := p.nextSubscriber
	changes := make(chan struct{}, 1)
	p.subscribers[id] = changes
	p.mu.Unlock()
	var once sync.Once
	return changes, func() {
		once.Do(func() {
			p.mu.Lock()
			delete(p.subscribers, id)
			p.mu.Unlock()
		})
	}
}

// SubscribeAvailability registers one stable logical-application owner. The
// inbox is latest-value: every delivered revision describes the complete
// trusted source ordering, so superseded queued revisions may be coalesced.
func (p *Pool) SubscribeAvailability(class peerquic.Class) (<-chan AvailabilitySnapshot, func()) {
	if p == nil || !validClass(class) {
		closed := make(chan AvailabilitySnapshot)
		close(closed)
		return closed, func() {}
	}
	p.mu.Lock()
	if p.closed || p.nextApplicationSubscriber == math.MaxUint64 {
		p.mu.Unlock()
		closed := make(chan AvailabilitySnapshot)
		close(closed)
		return closed, func() {}
	}
	p.nextApplicationSubscriber++
	id := p.nextApplicationSubscriber
	inbox := make(chan AvailabilitySnapshot, 1)
	p.applicationSubscribers[id] = applicationSubscriber{class: class, inbox: inbox}
	if snapshot, ok := p.availabilitySnapshotLocked(class); ok {
		inbox <- snapshot
	}
	p.mu.Unlock()
	var once sync.Once
	return inbox, func() {
		once.Do(func() {
			p.mu.Lock()
			delete(p.applicationSubscribers, id)
			p.mu.Unlock()
		})
	}
}

func (p *Pool) Snapshot(class peerquic.Class) (ClassSnapshot, error) {
	if p == nil || !validClass(class) {
		return ClassSnapshot{}, errors.New("invalid peer connection class snapshot")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.classLocked(class)
	syncEntryRoles(state)
	syncEntryRoles(state)
	snapshot := ClassSnapshot{Class: class, Generation: state.generation, Leases: p.applicationLeasesLocked(state), Warm: state.warmHolds > 0, Connecting: state.connecting, UpgradePending: state.upgradePending, Closed: p.closed}
	if state.selected != nil && !state.selected.closed && state.selected.selectedRole {
		snapshot.Path = state.selected.selection.Path
		snapshot.RelayRegion = state.selected.selection.RelayRegion
		snapshot.Selected = true
	}
	committedObserved := false
	for _, entry := range uniqueEntries(state.selected, state.standby, state.secondary, state.draining) {
		observer, ok := entry.selection.Connection.(CommittedApplicationObserver)
		if !ok {
			continue
		}
		committedObserved = true
		if !entry.closed && observer.CommittedApplications() > 0 {
			snapshot.ActivePath = entry.selection.Path
			snapshot.ActiveRelayRegion = entry.selection.RelayRegion
			break
		}
	}
	if !committedObserved {
		if state.selected != nil && !state.selected.closed && state.selected.applicationLeases > 0 {
			snapshot.ActivePath = state.selected.selection.Path
			snapshot.ActiveRelayRegion = state.selected.selection.RelayRegion
		} else if state.draining != nil && !state.draining.closed && state.draining.applicationLeases > 0 {
			snapshot.ActivePath = state.draining.selection.Path
			snapshot.ActiveRelayRegion = state.draining.selection.RelayRegion
		}
	}
	if snapshot.Leases > 0 {
		for _, entry := range uniqueEntries(state.standby, state.secondary) {
			if entry != nil && !entry.closed && entry.selection.Connection.State() == StateTrusted && entry.selection.Path != snapshot.ActivePath {
				snapshot.StandbyPath = entry.selection.Path
				break
			}
		}
	}
	return snapshot, nil
}

type Lease struct {
	Connection Connection
	Path       Path
	Generation uint64

	once    sync.Once
	release func()
	warm    bool
}

func (l *Lease) Release() { l.once.Do(l.release) }

// Warm establishes a daemon-owned carrier hold. It participates in transport
// health and idle ownership but is excluded from application lease counts.
func (p *Pool) Warm(ctx context.Context, class peerquic.Class, mode Mode, network NetworkClass) (*Lease, error) {
	lease, err := p.Acquire(ctx, class, mode, network)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	state := p.classLocked(class)
	for _, entry := range []*managedConnection{state.selected, state.draining} {
		if entry != nil && entry.selection.Connection == lease.Connection && entry.applicationLeases > 0 {
			entry.applicationLeases--
			state.warmHolds++
			lease.warm = true
			break
		}
	}
	p.signalLocked()
	p.mu.Unlock()
	if !lease.warm {
		lease.Release()
		return nil, errors.New("warm peer lease lost ownership")
	}
	return lease, nil
}

func (p *Pool) Acquire(ctx context.Context, class peerquic.Class, mode Mode, network NetworkClass) (*Lease, error) {
	if ctx == nil || !validClass(class) {
		return nil, errors.New("invalid peer connection class")
	}
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errors.New("peer connection pool is closed")
		}
		state := p.classLocked(class)
		if p.networkExhausted || state.exhausted {
			p.mu.Unlock()
			return nil, ErrPoolGenerationExhausted
		}
		if state.selected != nil && state.selected.selectedRole && !state.selected.closed {
			p.cancelIdleLocked(state)
			lease, err := p.leaseLocked(class, state.selected)
			p.mu.Unlock()
			return lease, err
		}
		if state.connecting {
			wait := state.wait
			p.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		generation, generationErr := advanceClassGenerationLocked(state)
		if generationErr != nil {
			p.mu.Unlock()
			return nil, generationErr
		}
		state.connecting = true
		state.wait = make(chan struct{})
		token := &ownershipToken{}
		state.connectToken = token
		attemptCtx, cancelAttempt := context.WithCancel(ctx)
		state.connectCancel = cancelAttempt
		p.mu.Unlock()

		selection, err := p.connect(attemptCtx, class, generation, mode, network, 0)
		p.mu.Lock()
		state = p.classLocked(class)
		owned := state.connectToken == token
		if owned {
			finishConnectLocked(state)
			if selection.StandbyReady != nil && err == nil {
				state.warmCancel = cancelAttempt
				state.upgradePending = true
			} else {
				cancelAttempt()
			}
		} else {
			cancelAttempt()
		}
		if err != nil {
			p.mu.Unlock()
			return nil, err
		}
		if !owned || p.closed || generation != state.generation {
			p.mu.Unlock()
			_ = selection.Connection.Close()
			return nil, &Failure{Class: FailureGeneration, Path: selection.Path, Cause: errors.New("connection attempt became stale")}
		}
		if state.selected != nil {
			p.mu.Unlock()
			_ = selection.Connection.Close()
			continue
		}
		entry := &managedConnection{selection: withoutStandby(selection)}
		state.mode, state.network, state.policySet = mode, network, true
		state.selected = entry
		p.adoptStandbyLocked(class, state, selection.Standby)
		p.adoptStandbyFutureLocked(class, state, selection.StandbyReady)
		lease, leaseErr := p.leaseLocked(class, entry)
		p.mu.Unlock()
		return lease, leaseErr
	}
}

// Replace establishes a new class connection before draining the selected one.
// Existing leases continue on the old connection; new leases use the replacement.
func (p *Pool) Replace(ctx context.Context, class peerquic.Class, mode Mode, network NetworkClass) error {
	if ctx == nil || !validClass(class) {
		return errors.New("invalid peer connection class")
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errors.New("peer connection pool is closed")
	}
	state := p.classLocked(class)
	if p.networkExhausted || state.exhausted {
		p.mu.Unlock()
		return ErrPoolGenerationExhausted
	}
	if state.connecting || state.draining != nil {
		p.mu.Unlock()
		return errors.New("peer connection class is already changing")
	}
	generation, generationErr := advanceClassGenerationLocked(state)
	if generationErr != nil {
		p.mu.Unlock()
		return generationErr
	}
	state.connecting = true
	state.wait = make(chan struct{})
	token := &ownershipToken{}
	state.connectToken = token
	attemptCtx, cancelAttempt := context.WithCancel(ctx)
	state.connectCancel = cancelAttempt
	p.mu.Unlock()

	selection, err := p.connect(attemptCtx, class, generation, mode, network, 0)
	p.mu.Lock()
	state = p.classLocked(class)
	owned := state.connectToken == token
	if owned {
		finishConnectLocked(state)
		if selection.StandbyReady != nil && err == nil {
			state.warmCancel = cancelAttempt
			state.upgradePending = true
		} else {
			cancelAttempt()
		}
	} else {
		cancelAttempt()
	}
	if err != nil {
		p.mu.Unlock()
		return err
	}
	if !owned || p.closed || generation != state.generation {
		p.mu.Unlock()
		_ = selection.Connection.Close()
		return &Failure{Class: FailureGeneration, Path: selection.Path, Cause: errors.New("connection replacement became stale")}
	}
	previous := state.selected
	state.mode, state.network, state.policySet = mode, network, true
	p.closeEntryLocked(state.standby)
	p.closeEntryLocked(state.secondary)
	state.standby = nil
	state.secondary = nil
	state.selected = &managedConnection{selection: withoutStandby(selection)}
	if state.warmHolds > 0 {
		_ = p.startHealthLocked(class, state.selected)
	}
	p.adoptStandbyLocked(class, state, selection.Standby)
	p.adoptStandbyFutureLocked(class, state, selection.StandbyReady)
	if previous != nil {
		previous.selectedRole = false
		if previous.applicationLeases == 0 {
			p.closeEntryLocked(previous)
		} else {
			state.draining = previous
		}
	}
	if p.classLeasesLocked(state) == 0 {
		p.scheduleIdleLocked(state, state.selected)
	}
	p.signalLocked()
	p.mu.Unlock()
	return nil
}

// PromoteDirect adopts a successful probe connection for new leases and drains
// the currently leased relay selection without interrupting its consumers.
// Ownership transfers only on success.
func (p *Pool) PromoteDirect(class peerquic.Class, connection Connection) error {
	return p.promotePath(class, PathDirectQUIC, connection)
}

// PromoteRelayQUIC promotes a freshly authenticated relay-QUIC probe while
// retaining active logical streams and any WSS fallback.
func (p *Pool) PromoteRelayQUIC(class peerquic.Class, connection Connection) error {
	return p.promotePath(class, PathRelayQUIC, connection)
}

func (p *Pool) promotePath(class peerquic.Class, path Path, connection Connection) error {
	return p.promotePathOwned(class, path, connection, nil, nil)
}

func (p *Pool) promotePathOwned(class peerquic.Class, path Path, connection Connection, expected *classState, token *ownershipToken) error {
	if p == nil || !validClass(class) || !validPath(path) || nilConnection(connection) || connection.State() != StateTrusted {
		return errors.New("invalid peer path promotion")
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errors.New("peer connection pool is closed")
	}
	state := p.classLocked(class)
	if expected != nil && (state != expected || state.standbyFuture != token) {
		p.mu.Unlock()
		return ErrPoolInvalidated
	}
	if p.networkExhausted || state.exhausted {
		p.mu.Unlock()
		return ErrPoolGenerationExhausted
	}
	// A prior promotion can leave a zero-lease draining carrier behind while
	// its replacement is active. It no longer owns application streams and must
	// not block the next verified upgrade (for example WSS -> relay QUIC).
	if state.draining != nil && state.draining.applicationLeases == 0 {
		oldDraining := state.draining
		state.draining = nil
		syncEntryRoles(state, oldDraining)
		p.closeIfUnownedLocked(oldDraining)
	}
	previous := state.selected
	if state.connecting || previous == nil || previous.closed || !previous.selectedRole || previous.applicationLeases == 0 && state.warmHolds == 0 && p.applicationLeasesLocked(state) == 0 || path == PathDirectQUIC && previous.selection.Path != PathRelayQUIC && previous.selection.Path != PathWSS || path == PathRelayQUIC && previous.selection.Path != PathWSS {
		p.mu.Unlock()
		return errors.New("peer connection class is not eligible for path promotion")
	}
	generation := state.generation
	if expected == nil {
		var err error
		generation, err = advanceClassGenerationLocked(state)
		if err != nil {
			p.mu.Unlock()
			return err
		}
	}
	p.cancelIdleLocked(state)
	oldStandby, oldSecondary := state.standby, state.secondary
	// Relay entries retained behind the promoted primary receive the new pool
	// generation below. Cancel their old health ownership before rewriting that
	// identity; otherwise a late result from the previous generation can retire
	// an authenticated fallback after the direct upgrade has completed.
	p.stopHealthLocked(previous)
	p.stopHealthLocked(oldStandby)
	p.stopHealthLocked(oldSecondary)
	previous.selection.Generation = generation
	// A path promotion changes the carrier generation but does not invalidate
	// the authenticated standby race already owned by this active session.
	// Keep its ownership token so a WSS result that completes after direct
	// promotion can still be adopted under the new generation.
	if oldStandby != nil {
		oldStandby.selection.Generation = generation
	}
	if oldSecondary != nil {
		oldSecondary.selection.Generation = generation
	}
	// Keep the authenticated relay hierarchy behind the new direct primary.
	// If relay QUIC was primary, its WSS secondary remains secondary; if WSS
	// was primary, it is the only fallback and stale extras are closed.
	if previous.selection.Path == PathRelayQUIC {
		state.standby, state.secondary = previous, oldStandby
		syncEntryRoles(state, previous, oldStandby, oldSecondary)
		p.closeIfUnownedLocked(oldSecondary)
	} else {
		state.standby, state.secondary = previous, nil
		syncEntryRoles(state, previous, oldStandby, oldSecondary)
		p.closeIfUnownedLocked(oldStandby)
		p.closeIfUnownedLocked(oldSecondary)
	}
	selected := &managedConnection{selection: Selection{Generation: generation, Path: path, Connection: connection}}
	state.selected = selected
	if previous.applicationLeases > 0 {
		state.draining = previous
	}
	syncEntryRoles(state, previous, selected, oldStandby, oldSecondary)
	logAvailabilityState("path_promoted", class, state)
	_ = p.startHealthLocked(class, selected)
	p.startRedundancyHealthLocked(class, state)
	p.signalLocked()
	p.mu.Unlock()
	p.mu.Lock()
	if current := p.classLocked(class); current.selected == selected && !selected.closed {
		p.publishAvailabilityLocked(class, current, previous)
	}
	p.mu.Unlock()
	return nil
}

// Retire removes an application-observed failed selected carrier. If a
// trusted relay standby for the same generation exists, it is promoted for
// new leases without interrupting the pool's ownership bookkeeping.
func (p *Pool) Retire(class peerquic.Class, connection Connection) bool {
	if p == nil || !validClass(class) || nilConnection(connection) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	state := p.classLocked(class)
	if state.selected == nil || state.selected.selection.Connection != connection || state.selected.closed {
		return false
	}
	p.failHealthLocked(class, state.selected)
	p.signalLocked()
	return state.selected != nil && !state.selected.closed && state.selected.selection.Connection.State() == StateTrusted
}

type PoolProbePromoter struct {
	Pool  *Pool
	Class peerquic.Class
}

func (p PoolProbePromoter) Promote(attempt ProbeAttempt, connection Connection) error {
	if attempt.Generation == 0 || attempt.NetworkGeneration == 0 || p.Pool == nil {
		return errors.New("invalid direct probe promotion attempt")
	}
	path := attempt.Path
	if path == 0 {
		path = PathDirectQUIC
	}
	switch path {
	case PathDirectQUIC:
		return p.Pool.PromoteDirect(p.Class, connection)
	case PathRelayQUIC:
		return p.Pool.PromoteRelayQUIC(p.Class, connection)
	default:
		return errors.New("probe path is not promotable")
	}
}

// Invalidate fences every in-flight result and closes all current connections.
func (p *Pool) Invalidate() {
	p.mu.Lock()
	for _, state := range p.classes {
		p.cancelConnectLocked(state)
		p.cancelWarmLocked(state)
		_, _ = advanceClassGenerationLocked(state)
		p.cancelIdleLocked(state)
		for _, entry := range uniqueEntries(state.selected, state.standby, state.secondary, state.draining) {
			if entry != nil && !entry.closed {
				if aborter, ok := entry.selection.Connection.(ApplicationAborter); ok {
					aborter.AbortApplications(ErrPoolInvalidated)
				}
				p.closeEntryLocked(entry)
			}
		}
		state.selected = nil
		state.standby = nil
		state.secondary = nil
		state.draining = nil
		state.availabilityRevision++
	}
	p.signalLocked()
	p.mu.Unlock()
}

// NetworkChanged fences every in-flight race and retires UDP-backed
// selections. WSS is TCP-backed and remains usable until it fails or its
// ordinary lease/idle lifecycle closes it.
func (p *Pool) NetworkChanged() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	if p.networkGeneration == math.MaxUint64 {
		p.networkExhausted = true
	} else {
		p.networkGeneration++
	}
	for class, state := range p.classes {
		p.cancelConnectLocked(state)
		changed := false
		if state.selected != nil && state.selected.selection.Path == PathDirectQUIC {
			generation := state.generation
			p.cancelIdleLocked(state)
			selected := state.selected
			selectedFailed := p.failHealthLocked(class, selected)
			if selectedFailed && state.selected == nil && p.classLeasesLocked(state) > 0 {
				// No authenticated standby was ready at the instant of the
				// network transition. Retire the UDP carrier and immediately
				// begin a fresh fallback attempt instead of leaving consumers
				// attached to a dead selection.
				p.startRecoveryLocked(class, selected.selection.Path)
			}
			if state.generation == generation {
				_, _ = advanceClassGenerationLocked(state)
			}
			changed = true
		} else if state.selected != nil && state.selected.selection.Path == PathRelayQUIC && hasWSSFallbackLocked(state) {
			// A network-generation transition means the UDP substrate that
			// carried both direct and relay QUIC is no longer authoritative.
			// Promote the authenticated TCP-backed WSS standby immediately.
			p.preferWSSStandbyLocked(state)
			p.failHealthLocked(class, state.selected)
			changed = true
		} else if state.selected != nil && state.selected.selection.Path == PathRelayQUIC && p.classLeasesLocked(state) > 0 {
			// UDP-backed relay lost authority and no WSS standby was ready.
			// Retire it first, then launch the fallback race immediately.
			selected := state.selected
			p.failHealthLocked(class, selected)
			if state.selected == nil {
				p.startRecoveryLocked(class, selected.selection.Path)
			}
			changed = true
		} else {
			_, _ = advanceClassGenerationLocked(state)
		}
		if state.standby != nil && state.standby.selection.Path == PathDirectQUIC {
			p.closeEntryLocked(state.standby)
			state.standby = nil
		}
		if state.draining != nil && state.draining.selection.Path == PathDirectQUIC && state.draining.applicationLeases == 0 {
			p.closeEntryLocked(state.draining)
			state.draining = nil
			changed = true
		}
		if state.selected != nil && (state.selected.selection.Path == PathRelayQUIC || state.selected.selection.Path == PathWSS) && p.classLeasesLocked(state) > 0 {
			p.restartHealthLocked(state.selected)
		}
		if changed && state.selected != nil && p.classLeasesLocked(state) == 0 {
			p.scheduleIdleLocked(state, state.selected)
		}
	}
	p.signalLocked()
}

func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	var closeErrors []error
	for _, state := range p.classes {
		slog.Info("peer connection pool closing class", "reason", "pool_close", "generation", state.generation, "selected_leases", entryLeases(state.selected), "standby_leases", entryLeases(state.standby), "draining_leases", entryLeases(state.draining), "warm_holds", state.warmHolds)
		p.cancelConnectLocked(state)
		p.cancelWarmLocked(state)
		_, _ = advanceClassGenerationLocked(state)
		p.cancelIdleLocked(state)
		for _, entry := range uniqueEntries(state.selected, state.standby, state.secondary, state.draining) {
			if entry != nil && !entry.closed {
				p.stopHealthLocked(entry)
				entry.closed = true
				closeErrors = append(closeErrors, entry.selection.Connection.Close())
			}
		}
		state.selected = nil
		state.standby = nil
		state.secondary = nil
		state.draining = nil
	}
	for id, subscriber := range p.applicationSubscribers {
		close(subscriber.inbox)
		delete(p.applicationSubscribers, id)
	}
	p.signalLocked()
	p.mu.Unlock()
	return errors.Join(closeErrors...)
}

func entryLeases(entry *managedConnection) uint64 {
	if entry == nil {
		return 0
	}
	return entry.applicationLeases
}

func (p *Pool) leaseLocked(class peerquic.Class, entry *managedConnection) (*Lease, error) {
	state := p.classLocked(class)
	syncEntryRoles(state, entry)
	if entry == nil || !entry.selectedRole || !validClassPath(class, entry.selection.Path) {
		return nil, errors.New("peer path is not eligible for connection class")
	}
	if entry.applicationLeases == math.MaxUint64 {
		return nil, ErrPoolLeaseExhausted
	}
	startHealth := entry.applicationLeases == 0
	entry.applicationLeases++
	if startHealth {
		if err := p.startHealthLocked(class, entry); err != nil {
			entry.applicationLeases--
			p.failHealthLocked(class, entry)
			return nil, err
		}
		p.startRedundancyHealthLocked(class, p.classLocked(class))
	}
	p.signalLocked()
	lease := &Lease{Connection: entry.selection.Connection, Path: entry.selection.Path, Generation: entry.selection.Generation}
	lease.release = func() { p.release(class, entry, lease) }
	return lease, nil
}

func (p *Pool) release(class peerquic.Class, entry *managedConnection, leases ...*Lease) {
	p.mu.Lock()
	defer p.mu.Unlock()
	defer p.signalLocked()
	var lease *Lease
	if len(leases) > 0 {
		lease = leases[0]
	}
	state := p.classLocked(class)
	syncEntryRoles(state, entry)
	if lease != nil && lease.warm {
		if state.warmHolds == 0 {
			return
		}
		state.warmHolds--
		if state.warmHolds == 0 {
			if p.applicationLeasesLocked(state) == 0 {
				p.cancelStandbyReplenishmentLocked(state)
			}
			if state.selected != nil {
				p.stopHealthLocked(state.selected)
				if state.selected.applicationLeases == 0 {
					p.scheduleIdleLocked(state, state.selected)
				}
			}
		}
		return
	} else {
		if entry.applicationLeases == 0 {
			return
		}
		entry.applicationLeases--
	}
	if entry.applicationLeases != 0 {
		return
	}
	if p.applicationLeasesLocked(state) == 0 && state.warmHolds == 0 {
		p.cancelStandbyReplenishmentLocked(state)
	}
	if state.warmHolds == 0 && state.selected == entry {
		p.stopHealthLocked(entry)
	}
	if state.draining == entry {
		state.draining = nil
	}
	syncEntryRoles(state, entry)
	p.closeIfUnownedLocked(entry)
	if state.selected == entry {
		if state.warmHolds == 0 {
			p.scheduleIdleLocked(state, entry)
		}
	} else if p.classLeasesLocked(state) == 0 {
		p.scheduleIdleLocked(state, state.selected)
	}
}

func (p *Pool) scheduleIdleLocked(state *classState, entry *managedConnection) {
	p.cancelIdleLocked(state)
	if entry == nil || entry.closed || p.classLeasesLocked(state) != 0 || state.selected != entry {
		return
	}
	if p.closeWhenIdle {
		selected, standby, secondary := state.selected, state.standby, state.secondary
		state.selected = nil
		state.standby = nil
		state.secondary = nil
		syncEntryRoles(state, selected, standby, secondary)
		for _, candidate := range uniqueEntries(selected, standby, secondary) {
			p.closeIfUnownedLocked(candidate)
		}
		p.signalLocked()
		return
	}
	token := &ownershipToken{}
	state.idleToken = token
	state.idle = p.after(p.grace, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if state.idleToken != token || state.selected != entry || entry.applicationLeases != 0 || entry.closed || p.closed {
			return
		}
		state.idle = nil
		state.idleToken = nil
		state.selected = nil
		syncEntryRoles(state, entry)
		p.closeIfUnownedLocked(entry)
		p.signalLocked()
	})
}

func (p *Pool) cancelIdleLocked(state *classState) {
	state.idleToken = nil
	if state.idle != nil {
		state.idle.Stop()
		state.idle = nil
	}
}

func (p *Pool) cancelConnectLocked(state *classState) {
	if state == nil {
		return
	}
	if state.connectCancel != nil {
		state.connectCancel()
	}
	finishConnectLocked(state)
}

func (p *Pool) cancelWarmLocked(state *classState) {
	if state != nil && state.warmCancel != nil {
		state.warmCancel()
		state.warmCancel = nil
	}
	if state != nil {
		state.upgradePending = false
		state.standbyFuture = nil
	}
	p.cancelStandbyReplenishmentLocked(state)
}

func finishConnectLocked(state *classState) {
	state.connectCancel = nil
	state.connectToken = nil
	state.connecting = false
	if state.wait != nil {
		close(state.wait)
		state.wait = nil
	}
}

func (p *Pool) classLeasesLocked(state *classState) uint64 {
	leases := p.applicationLeasesLocked(state)
	if math.MaxUint64-leases < state.warmHolds {
		return math.MaxUint64
	}
	return leases + state.warmHolds
}

func (p *Pool) applicationLeasesLocked(state *classState) uint64 {
	if state == nil {
		return 0
	}
	var leases uint64
	for _, entry := range uniqueEntries(state.selected, state.standby, state.secondary, state.draining) {
		if math.MaxUint64-leases < entry.applicationLeases {
			return math.MaxUint64
		}
		leases += entry.applicationLeases
	}
	return leases
}

func (p *Pool) closeEntryLocked(entry *managedConnection) {
	if entry == nil || entry.closed {
		return
	}
	p.stopHealthLocked(entry)
	entry.closed = true
	_ = entry.selection.Connection.Close()
}

func (p *Pool) closeIfUnownedLocked(entry *managedConnection) {
	if entry == nil || entry.closed || entryOwned(entry) {
		return
	}
	p.closeEntryLocked(entry)
}

func (p *Pool) startHealthLocked(class peerquic.Class, entry *managedConnection) error {
	state := p.classLocked(class)
	if p.health == nil || p.healthTransport == nil || entry == nil || entry.closed || entry.healthCancel != nil || p.classLeasesLocked(state) == 0 && state.warmHolds == 0 {
		return nil
	}
	if p.disableRelayHealth && (entry.selection.Path == PathRelayQUIC || entry.selection.Path == PathWSS) {
		return nil
	}
	if p.disablePreviewHealth && class == peerquic.ClassPreview {
		return nil
	}
	transport, err := p.healthTransport(entry.selection)
	if err != nil || transport == nil {
		if err == nil {
			err = errors.New("health transport factory returned no transport")
		}
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	token := &ownershipToken{}
	entry.healthToken = token
	entry.healthCancel = cancel
	binding := ActiveHealthBinding{Path: entry.selection.Path, Generation: entry.selection.Generation, NetworkGeneration: p.networkGeneration}
	go func() {
		err := p.health.Run(ctx, binding, transport)
		if err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("peer active health stopped", "class", uint8(class), "path", uint8(binding.Path), "generation", binding.Generation, "network_generation", binding.NetworkGeneration, "error", err)
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if entry.healthToken != token {
			return
		}
		entry.healthCancel = nil
		entry.healthToken = nil
		if ctx.Err() != nil || p.closed || entry.closed {
			return
		}
		if err != nil {
			selectedFailed := p.failHealthLocked(class, entry)
			if selectedFailed && errors.Is(err, ErrPathSuspect) {
				p.startRecoveryLocked(class, entry.selection.Path)
			}
			p.signalLocked()
		}
	}()
	return nil
}

func (p *Pool) startRedundancyHealthLocked(class peerquic.Class, state *classState) {
	if state == nil {
		return
	}
	syncEntryRoles(state)
	for _, entry := range uniqueEntries(state.standby, state.secondary) {
		if err := p.startHealthLocked(class, entry); err != nil {
			p.failHealthLocked(class, entry)
		}
	}
	p.ensureStandbyReplenishmentLocked(class, state)
}

func (p *Pool) cancelStandbyReplenishmentLocked(state *classState) {
	if state == nil || state.replenishment == nil {
		return
	}
	state.replenishment.cancel()
	if state.replenishment.retry != nil {
		state.replenishment.retry.Stop()
	}
	state.replenishment = nil
}

func (p *Pool) ensureStandbyReplenishmentLocked(class peerquic.Class, state *classState) {
	if state == nil || p.closed || p.candidateSource == nil || state.replenishment != nil ||
		state.standbyFuture != nil ||
		state.selected == nil || state.selected.closed || state.selected.selection.Path != PathRelayQUIC ||
		(state.mode != ModeAuto && state.mode != ModeRelayRace) || hasWSSFallbackLocked(state) ||
		p.classLeasesLocked(state) == 0 {
		return
	}
	selected := state.selected
	generation := state.generation
	token := &ownershipToken{}
	ctx, cancel := context.WithTimeout(context.Background(), p.connectTimeout)
	state.replenishment = &standbyReplenishment{token: token, cancel: cancel, path: PathWSS}
	go func() {
		connection, err := p.candidateSource.OpenCandidate(ctx, Attempt{Generation: generation, Path: PathWSS})
		cancel()
		p.mu.Lock()
		defer p.mu.Unlock()
		current := p.classLocked(class)
		owned := current == state && current.replenishment != nil && current.replenishment.token == token
		valid := err == nil && owned && !p.closed && current.generation == generation && current.selected == selected &&
			!selected.closed && selected.selection.Path == PathRelayQUIC && !hasWSSFallbackLocked(current) &&
			!nilConnection(connection) && connection.State() == StateTrusted
		if !valid {
			attemptFailed := owned && (err != nil || nilConnection(connection) || connection.State() != StateTrusted)
			if !nilConnection(connection) {
				_ = connection.Close()
			}
			if attemptFailed && !p.closed && current.generation == generation && current.selected == selected &&
				!selected.closed && selected.selection.Path == PathRelayQUIC && !hasWSSFallbackLocked(current) &&
				p.classLeasesLocked(current) > 0 {
				current.replenishment.cancel = func() {}
				current.replenishment.retry = p.after(standbyReplenishmentBackoff, func() {
					p.mu.Lock()
					defer p.mu.Unlock()
					state := p.classLocked(class)
					if state.replenishment == nil || state.replenishment.token != token {
						return
					}
					state.replenishment = nil
					p.ensureStandbyReplenishmentLocked(class, state)
				})
			} else if owned {
				current.replenishment = nil
			}
			p.signalLocked()
			return
		}
		current.replenishment = nil
		selection := Selection{Generation: generation, Path: PathWSS, Connection: connection}
		p.adoptStandbyLocked(class, current, &selection)
		slog.Info("peer WSS setup stage", "attempt_generation", generation, "path", "relay_wss", "stage", "candidate_adopted")
		p.signalLocked()
	}()
}

func (p *Pool) preferWSSStandbyLocked(state *classState) {
	if state == nil {
		return
	}
	// A normal relay race installs WSS directly as standby. Keep it in
	// place; older promotion layouts retain it as secondary behind relay
	// QUIC, in which case move that authenticated carrier into standby.
	if state.standby != nil && !state.standby.closed && state.standby.selection.Path == PathWSS && state.standby.selection.Connection.State() == StateTrusted {
		return
	}
	if state.secondary == nil || state.secondary.closed || state.secondary.selection.Path != PathWSS || state.secondary.selection.Connection.State() != StateTrusted {
		return
	}
	oldStandby := state.standby
	state.standby = state.secondary
	state.secondary = nil
	syncEntryRoles(state, oldStandby, state.standby)
	p.closeIfUnownedLocked(oldStandby)
}

func hasWSSFallbackLocked(state *classState) bool {
	if state == nil {
		return false
	}
	for _, entry := range []*managedConnection{state.standby, state.secondary} {
		if entry != nil && !entry.closed && entry.selection.Path == PathWSS && entry.selection.Connection.State() == StateTrusted {
			return true
		}
	}
	return false
}

func (p *Pool) restartHealthLocked(entry *managedConnection) {
	if entry == nil || entry.applicationLeases == 0 {
		return
	}
	p.stopHealthLocked(entry)
	for class, state := range p.classes {
		if state.selected == entry || state.draining == entry {
			if err := p.startHealthLocked(class, entry); err != nil {
				p.failHealthLocked(class, entry)
				p.signalLocked()
			}
			return
		}
	}
}

func (p *Pool) stopHealthLocked(entry *managedConnection) {
	if entry == nil {
		return
	}
	entry.healthToken = nil
	if entry.healthCancel != nil {
		entry.healthCancel()
		entry.healthCancel = nil
	}
}

func (p *Pool) failHealthLocked(class peerquic.Class, entry *managedConnection) bool {
	state := p.classLocked(class)
	syncEntryRoles(state, entry)
	selected := state.selected == entry
	wasDraining := state.draining == entry
	if !selected && state.standby == entry {
		slog.Warn("peer pool candidate health failed", "class", uint8(class), "generation", state.generation, "role", "standby", "path", entryPath(entry), "connection", connectionIdentity(entry))
		state.standby = nil
		if secondary := state.secondary; secondary != nil && !secondary.closed && secondary.selection.Generation == entry.selection.Generation && secondary.selection.Connection.State() == StateTrusted {
			state.standby = secondary
			state.secondary = nil
			syncEntryRoles(state, entry, secondary)
			_ = p.startHealthLocked(class, secondary)
		}
		syncEntryRoles(state, entry)
		p.closeIfUnownedLocked(entry)
		p.publishAvailabilityLocked(class, state, nil)
		p.ensureStandbyReplenishmentLocked(class, state)
		return false
	}
	if !selected && state.secondary == entry {
		slog.Warn("peer pool candidate health failed", "class", uint8(class), "generation", state.generation, "role", "secondary", "path", entryPath(entry), "connection", connectionIdentity(entry))
		state.secondary = nil
		syncEntryRoles(state, entry)
		p.closeIfUnownedLocked(entry)
		p.ensureStandbyReplenishmentLocked(class, state)
		return false
	}
	if state.selected == entry {
		slog.Warn("peer pool candidate health failed", "class", uint8(class), "generation", state.generation, "role", "selected", "path", entryPath(entry), "connection", connectionIdentity(entry))
		state.selected = nil
		if standby := state.standby; standby != nil && !standby.closed && standby.selection.Generation == entry.selection.Generation && standby.selection.Connection.State() == StateTrusted {
			state.standby = nil
			state.selected = standby
			if entry.applicationLeases > 0 {
				state.draining = entry
			}
			if secondary := state.secondary; secondary != nil && !secondary.closed && secondary.selection.Generation == entry.selection.Generation && secondary.selection.Connection.State() == StateTrusted {
				state.standby = secondary
				state.secondary = nil
			}
			syncEntryRoles(state, entry, standby)
			p.closeIfUnownedLocked(entry)
			p.restartHealthLocked(standby)
			p.publishAvailabilityLocked(class, state, entry)
			p.ensureStandbyReplenishmentLocked(class, state)
		} else {
			oldStandby, oldSecondary := state.standby, state.secondary
			state.standby = nil
			state.secondary = nil
			syncEntryRoles(state, entry, oldStandby, oldSecondary)
			p.closeIfUnownedLocked(entry)
			p.closeIfUnownedLocked(oldStandby)
			p.closeIfUnownedLocked(oldSecondary)
			_, _ = advanceClassGenerationLocked(state)
		}
	} else if !wasDraining {
		p.closeIfUnownedLocked(entry)
	}
	// A source can be selected and draining simultaneously after direct fails
	// back to the relay that still owns the original application lease. If that
	// relay then fails and WSS is promoted, the selected branch deliberately
	// retains it as draining. Clear old draining ownership only for a source
	// that was not selected during this failure.
	if !selected && wasDraining && state.draining == entry {
		state.draining = nil
		syncEntryRoles(state, entry)
		p.closeIfUnownedLocked(entry)
	}
	return selected
}

func (p *Pool) publishAvailabilityLocked(class peerquic.Class, state *classState, previous *managedConnection) {
	if p == nil || state == nil || state.selected == nil || state.selected.closed {
		return
	}
	notification := availabilityNotification{class: class, generation: state.generation, previousEntry: previous, selectedEntry: state.selected, fallbackEntry: state.standby, selectedConnection: state.selected.selection.Connection}
	if previous != nil {
		notification.previousConnection = previous.selection.Connection
	}
	if state.standby != nil && !state.standby.closed {
		notification.fallbackConnection = state.standby.selection.Connection
	}
	state.availabilityRevision++
	if snapshot, ok := p.availabilitySnapshotLocked(class); ok {
		p.publishApplicationAvailabilityLocked(class, snapshot)
	}
	go p.publishAvailability(notification)
}

func (p *Pool) availabilitySnapshotLocked(class peerquic.Class) (AvailabilitySnapshot, bool) {
	state := p.classLocked(class)
	if p.closed || state.selected == nil || state.selected.closed || state.selected.selection.Connection.State() != StateTrusted {
		return AvailabilitySnapshot{}, false
	}
	result := AvailabilitySnapshot{Revision: state.availabilityRevision, Preferred: availabilitySource(state.selected)}
	for _, entry := range orderedAvailability(state) {
		if entry == nil || entry.closed || entry.selection.Connection.State() != StateTrusted {
			continue
		}
		result.Available = append(result.Available, availabilitySource(entry))
	}
	return result, true
}

func availabilitySource(entry *managedConnection) AvailabilitySource {
	if entry == nil {
		return AvailabilitySource{}
	}
	return AvailabilitySource{Path: entry.selection.Path, Generation: entry.selection.Generation, Connection: entry.selection.Connection}
}

func orderedAvailability(state *classState) []*managedConnection {
	if state == nil {
		return nil
	}
	entries := uniqueEntries(state.selected, state.standby, state.secondary)
	slices.SortStableFunc(entries, func(left, right *managedConnection) int {
		return cmp.Compare(uint8(left.selection.Path), uint8(right.selection.Path))
	})
	return entries
}

func (p *Pool) publishApplicationAvailabilityLocked(class peerquic.Class, snapshot AvailabilitySnapshot) {
	for _, subscriber := range p.applicationSubscribers {
		if subscriber.class != class {
			continue
		}
		select {
		case <-subscriber.inbox:
		default:
		}
		select {
		case subscriber.inbox <- snapshot:
		default:
		}
	}
}

func (p *Pool) publishAvailability(notification availabilityNotification) {
	p.mu.Lock()
	state := p.classLocked(notification.class)
	valid := !p.closed && state.generation == notification.generation && state.selected == notification.selectedEntry && state.standby == notification.fallbackEntry && !notification.selectedEntry.closed
	p.mu.Unlock()
	if !valid {
		slog.Info("peer pool availability publication rejected", "class", uint8(notification.class), "generation", notification.generation,
			"selected_connection", connectionIdentity(notification.selectedEntry), "fallback_connection", connectionIdentity(notification.fallbackEntry))
		return
	}
	slog.Info("peer pool availability published", "class", uint8(notification.class), "generation", notification.generation,
		"selected_path", entryPath(notification.selectedEntry), "selected_connection", connectionIdentity(notification.selectedEntry),
		"fallback_path", entryPath(notification.fallbackEntry), "fallback_connection", connectionIdentity(notification.fallbackEntry))
	if notification.previousEntry != nil && notification.previousEntry != notification.selectedEntry {
		if owner, ok := notification.previousConnection.(PreferredAware); ok {
			owner.SetPreferred(notification.selectedConnection)
		}
	}
	if owner, ok := notification.selectedConnection.(StandbyAware); ok {
		owner.SetStandby(notification.fallbackConnection)
	}
}

// Selected returns the current trusted carrier without changing application
// lease ownership. It is used only to reattach existing logical streams after
// the pool has promoted a standby.
func (p *Pool) Selected(class peerquic.Class) (Connection, Path, bool) {
	if p == nil || !validClass(class) {
		return nil, 0, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.classLocked(class)
	if p.closed || state.selected == nil || state.selected.closed || state.selected.selection.Connection.State() != StateTrusted {
		return nil, 0, false
	}
	return state.selected.selection.Connection, state.selected.selection.Path, true
}

func withoutStandby(selection Selection) Selection {
	selection.Standby = nil
	selection.StandbyReady = nil
	return selection
}

func (p *Pool) adoptStandbyLocked(class peerquic.Class, state *classState, selection *Selection) {
	if state == nil || selection == nil || selection.Generation != state.generation || selection.Path != PathRelayQUIC && selection.Path != PathWSS || nilConnection(selection.Connection) || selection.Connection.State() != StateTrusted {
		if selection != nil && !nilConnection(selection.Connection) {
			_ = selection.Connection.Close()
		}
		return
	}
	entry := &managedConnection{selection: withoutStandby(*selection)}
	if state.standby == nil {
		state.standby = entry
	} else if state.standby.selection.Path == PathRelayQUIC && selection.Path == PathWSS && state.secondary == nil {
		state.secondary = entry
	} else {
		p.closeEntryLocked(entry)
	}
	syncEntryRoles(state, entry)
	p.publishAvailabilityLocked(class, state, nil)
	p.startRedundancyHealthLocked(class, state)
}

func (p *Pool) adoptStandbyFutureLocked(class peerquic.Class, state *classState, future <-chan StandbyResult) {
	if future == nil || state == nil {
		return
	}
	token := &ownershipToken{}
	state.standbyFuture = token
	go func() {
		defer func() {
			p.mu.Lock()
			current := p.classLocked(class)
			if current == state && current.standbyFuture == token {
				current.upgradePending = false
				current.standbyFuture = nil
				if current.warmCancel != nil {
					current.warmCancel()
					current.warmCancel = nil
				}
				p.signalLocked()
				p.ensureStandbyReplenishmentLocked(class, current)
			}
			p.mu.Unlock()
		}()
		for result := range future {
			if result.Selection.Connection == nil {
				if result.Err != nil && !resultErrAllowsFallback(result.Err) {
					p.mu.Lock()
					if current := p.classLocked(class); current == state && current.standbyFuture == token && current.selected != nil {
						p.closeEntryLocked(current.selected)
						current.selected = nil
						p.signalLocked()
					}
					p.mu.Unlock()
				}
				continue
			}
			p.mu.Lock()
			current := p.classLocked(class)
			selection := result.Selection
			if current != state || p.closed || current.standbyFuture != token || current.selected == nil || !validPath(selection.Path) || selection.Connection.State() != StateTrusted {
				_ = selection.Connection.Close()
				p.mu.Unlock()
				continue
			}
			selection.Generation = current.generation
			selectedPath := current.selected.selection.Path
			if selection.Path == PathDirectQUIC && selectedPath != PathDirectQUIC || selection.Path == PathRelayQUIC && selectedPath == PathWSS {
				p.mu.Unlock()
				promoteErr := p.promotePathOwned(class, selection.Path, selection.Connection, state, token)
				if promoteErr != nil {
					_ = selection.Connection.Close()
				}
				continue
			}
			if selection.Path == PathWSS && current.selected.selection.Path == PathRelayQUIC {
				p.adoptStandbyLocked(class, current, &selection)
				p.signalLocked()
				p.mu.Unlock()
				continue
			}
			if selection.Path == PathRelayQUIC && current.selected.selection.Path == PathDirectQUIC {
				p.adoptStandbyLocked(class, current, &selection)
				p.signalLocked()
				p.mu.Unlock()
				continue
			}
			if selection.Path == PathWSS && current.selected.selection.Path == PathDirectQUIC {
				p.adoptStandbyLocked(class, current, &selection)
				p.signalLocked()
				p.mu.Unlock()
				continue
			}
			_ = selection.Connection.Close()
			p.signalLocked()
			p.mu.Unlock()
		}
	}()
}

func resultErrAllowsFallback(err error) bool {
	var failure *Failure
	return errors.As(err, &failure) && failure.AllowsFallback()
}

func (p *Pool) startRecoveryLocked(class peerquic.Class, excluded Path) {
	state := p.classLocked(class)
	if class == peerquic.ClassTransfer || p.closed || p.networkExhausted || state.exhausted || state.connecting || state.selected != nil || !state.policySet {
		return
	}
	generation, err := advanceClassGenerationLocked(state)
	if err != nil {
		return
	}
	state.connecting = true
	state.wait = make(chan struct{})
	wait := state.wait
	token := &ownershipToken{}
	state.connectToken = token
	mode, network := state.mode, state.network
	attemptCtx, cancelAttempt := context.WithCancel(context.Background())
	state.connectCancel = cancelAttempt
	go func() {
		selection, err := p.connect(attemptCtx, class, generation, mode, network, excluded)
		cancelAttempt()
		p.mu.Lock()
		defer p.mu.Unlock()
		state := p.classLocked(class)
		if state.connectToken == token && state.wait == wait {
			finishConnectLocked(state)
		}
		if err != nil {
			p.signalLocked()
			return
		}
		if p.closed || state.generation != generation || state.selected != nil {
			_ = selection.Connection.Close()
			p.signalLocked()
			return
		}
		state.selected = &managedConnection{selection: selection}
		if state.warmHolds > 0 {
			_ = p.startHealthLocked(class, state.selected)
		}
		p.adoptStandbyLocked(class, state, selection.Standby)
		p.adoptStandbyFutureLocked(class, state, selection.StandbyReady)
		p.scheduleIdleLocked(state, state.selected)
		p.signalLocked()
	}()
}

func (p *Pool) connect(ctx context.Context, class peerquic.Class, generation uint64, mode Mode, network NetworkClass, excluded Path) (Selection, error) {
	if class == peerquic.ClassTransfer {
		if excluded == PathDirectQUIC {
			return Selection{}, &Failure{Class: FailureReachability, Path: PathDirectQUIC, Cause: errors.New("no eligible transfer peer path remains")}
		}
		return p.racer.connectOnly(ctx, generation, mode, network, PathDirectQUIC)
	}
	if excluded != 0 {
		return p.racer.connectExcluding(ctx, generation, mode, network, excluded)
	}
	return p.racer.Connect(ctx, generation, mode, network)
}

func advanceClassGenerationLocked(state *classState) (uint64, error) {
	if state == nil || state.exhausted || state.generation == math.MaxUint64 {
		if state != nil {
			state.exhausted = true
		}
		return 0, ErrPoolGenerationExhausted
	}
	state.generation++
	return state.generation, nil
}

func (p *Pool) classLocked(class peerquic.Class) *classState {
	state := p.classes[class]
	if state == nil {
		state = &classState{}
		p.classes[class] = state
	}
	syncEntryRoles(state)
	return state
}

func validClass(class peerquic.Class) bool {
	return class == peerquic.ClassInteractive || class == peerquic.ClassPreview || class == peerquic.ClassTransfer
}

func validClassPath(class peerquic.Class, path Path) bool {
	return validClass(class) && validPath(path) && (class != peerquic.ClassTransfer || path == PathDirectQUIC)
}

func udpSelection(entry *managedConnection) bool {
	return entry != nil && (entry.selection.Path == PathDirectQUIC || entry.selection.Path == PathRelayQUIC)
}

func (p *Pool) signalLocked() {
	select {
	case p.changes <- struct{}{}:
	default:
	}
	for _, subscriber := range p.subscribers {
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
}
