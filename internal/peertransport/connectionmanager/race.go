// Package connectionmanager owns peer path racing, selection, leases, and cleanup.
package connectionmanager

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
)

type Path uint8

const (
	PathDirectQUIC Path = iota + 1
	PathRelayQUIC
	PathWSS
)

type Mode uint8

const (
	ModeAuto Mode = iota + 1
	ModeQUIC
	ModeWSS
	// These modes are used only by authenticated diagnostics to test one path
	// without allowing the normal race to cancel the other path probes.
	ModeDirectQUIC
	ModeRelayQUIC
	ModeRelayRace
)

type NetworkClass uint8

const (
	NetworkUnknown NetworkClass = iota + 1
	NetworkUDPBlocked
	NetworkDirectInfeasible
	NetworkRelayPreferred
)

type FailureClass uint8

const (
	FailureReachability FailureClass = iota + 1
	FailureTimeout
	FailureUDPBlocked
	FailureNAT
	FailureTransient
	FailureAuthentication
	FailureAuthorization
	FailureCertificate
	FailureProtocol
	FailureRevoked
	FailureGeneration
	FailureInternal
)

type Failure struct {
	Class FailureClass
	Path  Path
	Cause error
}

type State uint8

const (
	StateProbing State = iota + 1
	StateReady
	StateTrusted
	StateSuspect
	StateFailed
)

func (e *Failure) Error() string {
	if e == nil {
		return "peer connection failed"
	}
	if e.Cause != nil {
		return fmt.Sprintf("peer path %d failed (class %d): %v", e.Path, e.Class, e.Cause)
	}
	return fmt.Sprintf("peer path %d failed (class %d)", e.Path, e.Class)
}

func (e *Failure) Unwrap() error { return e.Cause }

func (e *Failure) AllowsFallback() bool {
	return e != nil && e.Class >= FailureReachability && e.Class <= FailureTransient
}

type Connection interface {
	State() State
	Close() error
}

type StandbyAware interface{ SetStandby(Connection) }
type PreferredAware interface{ SetPreferred(Connection) }

// CommittedApplicationObserver reports logical applications which have
// completed their per-stream protocol commit on this candidate. It is
// observational only; pool leases remain bound to their original source.
type CommittedApplicationObserver interface{ CommittedApplications() uint64 }

// ApplicationAborter is implemented by connections that own logical streams
// which must be failed when authority invalidates the entire machine pool.
// Ordinary path retirement must not call it because those streams can migrate.
type ApplicationAborter interface{ AbortApplications(error) }

type RelayRegionProvider interface {
	RelayRegion() string
}

type Connector interface {
	Connect(context.Context, Attempt) (Connection, error)
}

// CandidateSource opens a new authenticated physical candidate for an active
// pool. Each call owns a fresh attempt lifetime; implementations must not
// reuse a completed race result or its context.
type CandidateSource interface {
	OpenCandidate(context.Context, Attempt) (Connection, error)
}

type Attempt struct {
	Generation uint64
	Path       Path
}

type Config struct {
	RelayDelay     time.Duration
	WSSDelay       time.Duration
	ConnectTimeout time.Duration
}

func (c Config) validate() error {
	if c.RelayDelay < 0 || c.WSSDelay < c.RelayDelay || c.ConnectTimeout <= 0 || c.RelayDelay >= c.ConnectTimeout || c.WSSDelay >= c.ConnectTimeout {
		return errors.New("invalid peer connection race configuration")
	}
	return nil
}

func (c Config) Validate() error { return c.validate() }

type Selection struct {
	Generation   uint64
	Path         Path
	RelayRegion  string
	Connection   Connection
	Standby      *Selection
	StandbyReady <-chan StandbyResult
}

// StandbyResult transfers ownership of a path that finished after the first
// authenticated carrier was selected. A race may publish every remaining
// authenticated path before closing the channel.
type StandbyResult struct {
	Selection Selection
	Err       error
}

type Racer struct {
	config    Config
	connector Connector
	after     func(context.Context, time.Duration) <-chan struct{}
}

func NewRacer(config Config, connector Connector) (*Racer, error) {
	if err := config.validate(); err != nil || connector == nil {
		return nil, errors.New("invalid peer connection racer")
	}
	return &Racer{config: config, connector: connector, after: after}, nil
}

type candidate struct {
	path         Path
	delay        time.Duration
	fallbackOnly bool
	start        chan struct{}
	once         sync.Once
}

func (c *candidate) begin() { c.once.Do(func() { close(c.start) }) }

type result struct {
	index       int
	connection  Connection
	relayRegion string
	err         error
}

func (r *Racer) Connect(ctx context.Context, generation uint64, mode Mode, network NetworkClass) (Selection, error) {
	return r.connect(ctx, generation, mode, network, 0, 0)
}

func (r *Racer) connectExcluding(ctx context.Context, generation uint64, mode Mode, network NetworkClass, excluded Path) (Selection, error) {
	if !validPath(excluded) {
		return Selection{}, errors.New("invalid excluded peer path")
	}
	return r.connect(ctx, generation, mode, network, excluded, 0)
}

func (r *Racer) connectOnly(ctx context.Context, generation uint64, mode Mode, network NetworkClass, only Path) (Selection, error) {
	if !validPath(only) {
		return Selection{}, errors.New("invalid required peer path")
	}
	return r.connect(ctx, generation, mode, network, 0, only)
}

func (r *Racer) connect(ctx context.Context, generation uint64, mode Mode, network NetworkClass, excluded, only Path) (Selection, error) {
	if r == nil || r.connector == nil || ctx == nil || generation == 0 {
		return Selection{}, errors.New("invalid peer connection attempt")
	}
	candidates, err := r.candidates(mode, network)
	if err != nil {
		return Selection{}, err
	}
	relayRace := mode == ModeRelayRace
	if excluded != 0 || only != 0 {
		filtered := make([]candidate, 0, len(candidates)-1)
		for index := range candidates {
			item := &candidates[index]
			if item.path != excluded && (only == 0 || item.path == only) {
				filtered = append(filtered, candidate{path: item.path, delay: item.delay, start: make(chan struct{})})
			}
		}
		candidates = filtered
		if len(candidates) == 0 {
			path := excluded
			if only != 0 {
				path = only
			}
			return Selection{}, &Failure{Class: FailureReachability, Path: path, Cause: errors.New("no eligible peer path remains")}
		}
		candidates[0].delay = 0
	}
	attemptCtx, cancel := context.WithTimeout(ctx, r.config.ConnectTimeout)
	cancelOnReturn := true
	defer func() {
		if cancelOnReturn {
			cancel()
		}
	}()
	results := make(chan result, len(candidates))
	for index := range candidates {
		item := &candidates[index]
		go func(index int, item *candidate) {
			var delayed <-chan struct{}
			if !item.fallbackOnly {
				delayed = r.after(attemptCtx, item.delay)
			}
			select {
			case <-item.start:
			case <-delayed:
				item.begin()
			case <-attemptCtx.Done():
				results <- result{index: index, err: attemptCtx.Err()}
				return
			}
			connection, connectErr := r.connector.Connect(attemptCtx, Attempt{Generation: generation, Path: item.path})
			if nilConnection(connection) {
				connection = nil
				if connectErr == nil {
					connectErr = &Failure{Class: FailureInternal, Path: item.path, Cause: errors.New("connector returned no connection")}
				}
			}
			if connectErr == nil && connection.State() == StateReady {
				connectErr = admitInitialHealth(attemptCtx, item.path, connection)
			}
			if connectErr == nil && connection.State() != StateTrusted {
				connectErr = &Failure{Class: FailureProtocol, Path: item.path, Cause: errors.New("connector returned an untrusted path")}
			}
			relayRegion := ""
			if connectErr == nil {
				relayRegion, connectErr = connectionRelayRegion(item.path, connection)
			}
			if connectErr != nil && connection != nil {
				_ = connection.Close()
				connection = nil
			}
			results <- result{index: index, connection: connection, relayRegion: relayRegion, err: connectErr}
		}(index, item)
	}
	if mode == ModeAuto || mode == ModeRelayRace {
		for index := range candidates {
			candidates[index].begin()
		}
	} else {
		candidates[0].begin()
	}
	var winner Selection
	var terminal error
	failures := make([]error, 0, len(candidates))
	// Auto is a latency race. Path priority is enforced by background
	// promotion after the first authenticated carrier starts the consumer.
	preferDirect := mode != ModeAuto && len(candidates) >= 2 && candidates[0].path == PathDirectQUIC && candidates[1].path == PathRelayQUIC
	var preference <-chan struct{}
	if preferDirect {
		preference = r.after(attemptCtx, r.config.RelayDelay)
	}
	directEligible := preferDirect
	directFinished := false
	var readyFallback *result
	var readyWSS *result
	completed := 0
	for completed < len(candidates) {
		var outcome result
		select {
		case outcome = <-results:
			completed++
		case <-preference:
			preference = nil
			directEligible = false
			if readyFallback != nil {
				winner = Selection{Generation: generation, Path: candidates[readyFallback.index].path, RelayRegion: readyFallback.relayRegion, Connection: readyFallback.connection}
				readyFallback = nil
				if readyWSS != nil {
					winner.Standby = &Selection{Generation: generation, Path: PathWSS, RelayRegion: readyWSS.relayRegion, Connection: readyWSS.connection}
					readyWSS = nil
					cancel()
					go drainCandidateResults(results, candidates, len(candidates)-completed, winner.Connection)
				} else {
					standby := make(chan StandbyResult, 2)
					winner.StandbyReady = standby
					cancelOnReturn = false
					go r.awaitWarmFallback(attemptCtx, generation, results, candidates, len(candidates)-completed, standby)
				}
				return winner, nil
			}
			if readyWSS != nil {
				winner = Selection{Generation: generation, Path: PathWSS, RelayRegion: readyWSS.relayRegion, Connection: readyWSS.connection}
				readyWSS = nil
				standby := make(chan StandbyResult, 2)
				winner.StandbyReady = standby
				cancelOnReturn = false
				go r.awaitWarmFallback(attemptCtx, generation, results, candidates, len(candidates)-completed, standby)
				return winner, nil
			}
			continue
		}
		path := candidates[outcome.index].path
		if outcome.err == nil {
			if mode == ModeAuto || relayRace {
				winner = Selection{Generation: generation, Path: path, RelayRegion: outcome.relayRegion, Connection: outcome.connection}
				standby := make(chan StandbyResult, 2)
				winner.StandbyReady = standby
				cancelOnReturn = false
				go r.awaitWarmFallback(attemptCtx, generation, results, candidates, len(candidates)-completed, standby)
				return winner, nil
			}
			if preferDirect && path == PathRelayQUIC && directEligible && !directFinished {
				copy := outcome
				readyFallback = &copy
				continue
			}
			if preferDirect && path == PathWSS && directEligible && !directFinished {
				copy := outcome
				readyWSS = &copy
				continue
			}
			if preferDirect && path == PathDirectQUIC {
				directFinished = true
				if !directEligible {
					_ = outcome.connection.Close()
					continue
				}
				winner = Selection{Generation: generation, Path: path, RelayRegion: outcome.relayRegion, Connection: outcome.connection}
				if readyFallback != nil {
					winner.Standby = &Selection{Generation: generation, Path: PathRelayQUIC, RelayRegion: readyFallback.relayRegion, Connection: readyFallback.connection}
					readyFallback = nil
					if readyWSS != nil {
						standby := make(chan StandbyResult, 1)
						standby <- StandbyResult{Selection: Selection{Generation: generation, Path: PathWSS, RelayRegion: readyWSS.relayRegion, Connection: readyWSS.connection}}
						close(standby)
						winner.StandbyReady = standby
						readyWSS = nil
					}
					cancel()
					go drainCandidateResults(results, candidates, len(candidates)-completed, winner.Connection)
				} else if readyWSS != nil {
					winner.Standby = &Selection{Generation: generation, Path: PathWSS, RelayRegion: readyWSS.relayRegion, Connection: readyWSS.connection}
					readyWSS = nil
					cancel()
					go drainCandidateResults(results, candidates, len(candidates)-completed, winner.Connection)
				} else {
					standby := make(chan StandbyResult, 2)
					winner.StandbyReady = standby
					cancelOnReturn = false
					go r.awaitWarmFallback(attemptCtx, generation, results, candidates, len(candidates)-completed, standby)
				}
				return winner, nil
			}
			if winner.Connection == nil && terminal == nil {
				winner = Selection{Generation: generation, Path: path, RelayRegion: outcome.relayRegion, Connection: outcome.connection}
				if path == PathDirectQUIC && readyFallback != nil {
					winner.Standby = &Selection{Generation: generation, Path: PathRelayQUIC, RelayRegion: readyFallback.relayRegion, Connection: readyFallback.connection}
					readyFallback = nil
				}
				cancel()
			} else {
				_ = outcome.connection.Close()
			}
			continue
		}
		if outcome.connection != nil {
			_ = outcome.connection.Close()
		}
		if terminal != nil {
			continue
		}
		if winner.Connection != nil {
			if relayRace {
				continue
			}
			if errors.Is(outcome.err, context.Canceled) || errors.Is(outcome.err, context.DeadlineExceeded) {
				continue
			}
			failure := typedFailure(path, outcome.err)
			if !failure.AllowsFallback() {
				_ = winner.Connection.Close()
				winner = Selection{}
				terminal = failure
			}
			continue
		}
		failure := typedFailure(path, outcome.err)
		if path == PathDirectQUIC {
			directFinished = true
			directEligible = false
			preference = nil
			if failure.AllowsFallback() && readyFallback != nil {
				winner = Selection{Generation: generation, Path: PathRelayQUIC, RelayRegion: readyFallback.relayRegion, Connection: readyFallback.connection}
				readyFallback = nil
				if readyWSS != nil {
					winner.Standby = &Selection{Generation: generation, Path: PathWSS, RelayRegion: readyWSS.relayRegion, Connection: readyWSS.connection}
					readyWSS = nil
				}
				cancel()
				continue
			}
			if failure.AllowsFallback() && readyWSS != nil {
				winner = Selection{Generation: generation, Path: PathWSS, RelayRegion: readyWSS.relayRegion, Connection: readyWSS.connection}
				readyWSS = nil
				cancel()
				continue
			}
		}
		failures = append(failures, failure)
		if !failure.AllowsFallback() && !relayRace {
			terminal = failure
			cancel()
			continue
		}
		if outcome.index+1 < len(candidates) {
			candidates[outcome.index+1].begin()
		}
		if winner.Connection != nil || terminal != nil {
			cancel()
			for completed < len(candidates) {
				select {
				case pending := <-results:
					completed++
					pendingPath := candidates[pending.index].path
					if pending.err == nil && pending.connection != nil {
						if winner.Path == PathDirectQUIC && (pendingPath == PathRelayQUIC || pendingPath == PathWSS) && winner.Standby == nil {
							winner.Standby = &Selection{Generation: generation, Path: pendingPath, RelayRegion: pending.relayRegion, Connection: pending.connection}
						} else {
							_ = pending.connection.Close()
						}
						continue
					}
					failure := typedFailure(pendingPath, pending.err)
					if !failure.AllowsFallback() {
						terminal = failure
						if winner.Connection != nil {
							_ = winner.Connection.Close()
							winner = Selection{}
						}
					}
				default:
					remaining := len(candidates) - completed
					selected := winner.Connection
					go drainCandidateResults(results, candidates, remaining, selected)
					completed = len(candidates)
				}
			}
			if winner.Connection != nil {
				return winner, nil
			}
			return Selection{}, terminal
		}
	}
	if readyFallback != nil {
		_ = readyFallback.connection.Close()
	}
	if readyWSS != nil {
		_ = readyWSS.connection.Close()
	}
	cancel()
	if winner.Connection != nil {
		return winner, nil
	}
	if terminal != nil {
		return Selection{}, terminal
	}
	if ctx.Err() != nil {
		return Selection{}, ctx.Err()
	}
	if attemptCtx.Err() != nil {
		return Selection{}, &Failure{Class: FailureTimeout, Cause: attemptCtx.Err()}
	}
	return Selection{}, errors.Join(failures...)
}

func (r *Racer) awaitWarmFallback(ctx context.Context, generation uint64, results <-chan result, candidates []candidate, remaining int, ready chan<- StandbyResult) {
	defer close(ready)
	for range remaining {
		select {
		case outcome := <-results:
			path := candidates[outcome.index].path
			if path != PathDirectQUIC && path != PathRelayQUIC && path != PathWSS {
				if outcome.connection != nil {
					_ = outcome.connection.Close()
				}
				continue
			}
			if outcome.err != nil {
				if outcome.connection != nil {
					_ = outcome.connection.Close()
				}
				failure := typedFailure(path, outcome.err)
				if !failure.AllowsFallback() {
					ready <- StandbyResult{Err: failure}
					return
				}
				if outcome.index+1 < len(candidates) {
					candidates[outcome.index+1].begin()
				}
				continue
			}
			ready <- StandbyResult{Selection: Selection{Generation: generation, Path: path, RelayRegion: outcome.relayRegion, Connection: outcome.connection}}
		case <-ctx.Done():
			return
		}
	}
}

func drainCandidateResults(results <-chan result, candidates []candidate, remaining int, selected Connection) {
	for range remaining {
		outcome := <-results
		if outcome.connection != nil {
			_ = outcome.connection.Close()
		}
		if outcome.err != nil && !typedFailure(candidates[outcome.index].path, outcome.err).AllowsFallback() && !nilConnection(selected) {
			_ = selected.Close()
		}
	}
}

func admitInitialHealth(ctx context.Context, path Path, connection Connection) error {
	admissible, ok := connection.(InitialHealthConnection)
	if !ok {
		return &Failure{Class: FailureProtocol, Path: path, Cause: errors.New("ready connection has no initial health admission")}
	}
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return &Failure{Class: FailureInternal, Path: path, Cause: fmt.Errorf("generate initial health nonce: %w", err)}
	}
	if err := admissible.AdmitInitialHealth(ctx, nonce); err != nil {
		var failure *Failure
		if errors.As(err, &failure) {
			return typedFailure(path, failure)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return &Failure{Class: FailureTimeout, Path: path, Cause: err}
		}
		if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return &Failure{Class: FailureTransient, Path: path, Cause: err}
		}
		// An untyped admission error is a transport failure (for example a
		// remote QUIC application close), not an authority verdict. Preserve
		// typed failures above so authentication, authorization, certificate,
		// and protocol violations still fail closed without promotion.
		return &Failure{Class: FailureTransient, Path: path, Cause: err}
	}
	return nil
}

func nilConnection(connection Connection) bool {
	if connection == nil {
		return true
	}
	value := reflect.ValueOf(connection)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func connectionRelayRegion(path Path, connection Connection) (string, error) {
	provider, ok := connection.(RelayRegionProvider)
	if !ok {
		return "", nil
	}
	region := provider.RelayRegion()
	if region == "" {
		return "", nil
	}
	if path == PathDirectQUIC || len(region) > 128 {
		return "", &Failure{Class: FailureProtocol, Path: path, Cause: errors.New("connector returned invalid relay metadata")}
	}
	for _, character := range region {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '.' || character == ':' || character == '-') {
			return "", &Failure{Class: FailureProtocol, Path: path, Cause: errors.New("connector returned invalid relay metadata")}
		}
	}
	return region, nil
}

func (r *Racer) candidates(mode Mode, network NetworkClass) ([]candidate, error) {
	makeCandidate := func(path Path, delay time.Duration, fallbackOnly ...bool) candidate {
		return candidate{path: path, delay: delay, fallbackOnly: len(fallbackOnly) > 0 && fallbackOnly[0], start: make(chan struct{})}
	}
	switch mode {
	case ModeDirectQUIC:
		return []candidate{makeCandidate(PathDirectQUIC, 0)}, nil
	case ModeRelayQUIC:
		return []candidate{makeCandidate(PathRelayQUIC, 0)}, nil
	case ModeRelayRace:
		return []candidate{makeCandidate(PathRelayQUIC, 0), makeCandidate(PathWSS, 0)}, nil
	case ModeWSS:
		return []candidate{makeCandidate(PathWSS, 0)}, nil
	case ModeQUIC:
		switch network {
		case NetworkUDPBlocked:
			return nil, &Failure{Class: FailureUDPBlocked, Cause: errors.New("QUIC disabled by current network classification")}
		case NetworkDirectInfeasible:
			return []candidate{makeCandidate(PathRelayQUIC, 0)}, nil
		case NetworkRelayPreferred:
			return []candidate{makeCandidate(PathDirectQUIC, 0), makeCandidate(PathRelayQUIC, 0)}, nil
		case NetworkUnknown:
			return []candidate{makeCandidate(PathDirectQUIC, 0), makeCandidate(PathRelayQUIC, 0)}, nil
		}
	case ModeAuto:
		switch network {
		case NetworkUDPBlocked:
			return []candidate{makeCandidate(PathWSS, 0)}, nil
		case NetworkDirectInfeasible:
			return []candidate{makeCandidate(PathRelayQUIC, 0), makeCandidate(PathWSS, 0)}, nil
		case NetworkRelayPreferred:
			return []candidate{makeCandidate(PathDirectQUIC, 0), makeCandidate(PathRelayQUIC, 0), makeCandidate(PathWSS, 0)}, nil
		case NetworkUnknown:
			return []candidate{makeCandidate(PathDirectQUIC, 0), makeCandidate(PathRelayQUIC, 0), makeCandidate(PathWSS, 0)}, nil
		}
	}
	return nil, errors.New("invalid peer transport mode or network classification")
}

func typedFailure(path Path, err error) *Failure {
	var failure *Failure
	if errors.As(err, &failure) && failure.Class >= FailureReachability && failure.Class <= FailureInternal {
		copy := *failure
		copy.Path = path
		return &copy
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &Failure{Class: FailureTimeout, Path: path, Cause: err}
	}
	if errors.Is(err, context.Canceled) {
		return &Failure{Class: FailureTransient, Path: path, Cause: err}
	}
	return &Failure{Class: FailureInternal, Path: path, Cause: err}
}

func after(ctx context.Context, delay time.Duration) <-chan struct{} {
	done := make(chan struct{})
	if delay == 0 {
		close(done)
		return done
	}
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			close(done)
		case <-ctx.Done():
		}
	}()
	return done
}
