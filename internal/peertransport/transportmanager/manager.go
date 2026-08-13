// Package transportmanager owns daemon-scoped peer carrier lifetimes.
// It deliberately contains no application protocol or credential policy.
package transportmanager

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

var ErrInvalid = errors.New("invalid peer transport manager request")
var ErrUnavailable = errors.New("peer transport is not cached")

type Factory func(context.Context) (*connectionmanager.Pool, error)
type OwnedFactory func(context.Context) (*connectionmanager.Pool, func() error, error)

type Manager struct {
	mu      sync.Mutex
	closed  bool
	entries map[string]*entry
}

type entry struct {
	pool    *connectionmanager.Pool
	ready   chan struct{}
	err     error
	refs    uint64
	gen     uint64
	cleanup func() error
	retired bool
}

type Lease struct {
	inner   *connectionmanager.Lease
	pool    *connectionmanager.Pool
	once    sync.Once
	release func()
}

type Snapshot struct {
	Key        string
	Generation uint64
	Leases     uint64
	Ready      bool
}

func New() (*Manager, error) {
	return &Manager{entries: make(map[string]*entry)}, nil
}

// Acquire returns a lease on the keyed pool. Factory is called at most once
// for a live key; failed factories are never retained.
func (m *Manager) Acquire(ctx context.Context, key string, class peerquic.Class, mode connectionmanager.Mode, network connectionmanager.NetworkClass, factory Factory) (*Lease, error) {
	if factory == nil {
		return nil, ErrInvalid
	}
	return m.acquire(ctx, key, class, mode, network, func(ctx context.Context) (*connectionmanager.Pool, func() error, error) {
		pool, err := factory(ctx)
		return pool, nil, err
	})
}

func (m *Manager) AcquireOwned(ctx context.Context, key string, class peerquic.Class, mode connectionmanager.Mode, network connectionmanager.NetworkClass, factory OwnedFactory) (*Lease, error) {
	if factory == nil {
		return nil, ErrInvalid
	}
	return m.acquire(ctx, key, class, mode, network, factory)
}

// AcquireCached leases an existing keyed pool without constructing any peer
// authority, descriptor, socket, or carrier state. It waits for an in-flight
// creator, preserving single-flight behavior for concurrent consumers.
func (m *Manager) AcquireCached(ctx context.Context, key string, class peerquic.Class, mode connectionmanager.Mode, network connectionmanager.NetworkClass) (*Lease, error) {
	if m == nil || ctx == nil || key == "" {
		return nil, ErrInvalid
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrInvalid
	}
	e := m.entries[key]
	if e == nil {
		m.mu.Unlock()
		return nil, ErrUnavailable
	}
	m.mu.Unlock()
	select {
	case <-e.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	m.mu.Lock()
	if m.closed || m.entries[key] != e || e.err != nil || e.pool == nil {
		m.mu.Unlock()
		return nil, errors.Join(ErrUnavailable, e.err)
	}
	e.refs++
	m.mu.Unlock()
	inner, err := e.pool.Acquire(ctx, class, mode, network)
	if err != nil {
		m.releaseReservation(key, e)
		return nil, err
	}
	return &Lease{inner: inner, pool: e.pool, release: func() { m.release(key, e, inner) }}, nil
}

func (m *Manager) acquire(ctx context.Context, key string, class peerquic.Class, mode connectionmanager.Mode, network connectionmanager.NetworkClass, factory OwnedFactory) (*Lease, error) {
	if m == nil || ctx == nil || key == "" || factory == nil {
		return nil, ErrInvalid
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrInvalid
	}
	e := m.entries[key]
	creator := false
	if e == nil {
		e = &entry{ready: make(chan struct{}), gen: 1}
		m.entries[key] = e
		creator = true
	}
	m.mu.Unlock()
	if creator {
		pool, cleanup, factoryErr := factory(ctx)
		if pool == nil && factoryErr == nil {
			factoryErr = ErrInvalid
		}
		m.mu.Lock()
		if m.closed || m.entries[key] != e {
			m.mu.Unlock()
			_ = closeOwned(pool, cleanup)
			return nil, ErrInvalid
		}
		e.pool, e.cleanup, e.err = pool, cleanup, factoryErr
		close(e.ready)
		if factoryErr != nil {
			delete(m.entries, key)
		}
		m.mu.Unlock()
		if factoryErr != nil {
			_ = closeOwned(pool, cleanup)
		}
	} else {
		select {
		case <-e.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	m.mu.Lock()
	if m.closed || m.entries[key] != e || e.err != nil || e.pool == nil {
		m.mu.Unlock()
		return nil, errors.Join(ErrInvalid, e.err)
	}
	e.refs++
	m.mu.Unlock()
	inner, err := e.pool.Acquire(ctx, class, mode, network)
	if err != nil {
		m.releaseReservation(key, e)
		return nil, err
	}
	return &Lease{inner: inner, pool: e.pool, release: func() { m.release(key, e, inner) }}, nil
}

func (l *Lease) Connection() connectionmanager.Connection {
	if l == nil || l.inner == nil {
		return nil
	}
	return l.inner.Connection
}
func (l *Lease) Pool() *connectionmanager.Pool {
	if l == nil {
		return nil
	}
	return l.pool
}
func (l *Lease) Path() connectionmanager.Path {
	if l == nil || l.inner == nil {
		return connectionmanager.Path(0)
	}
	return l.inner.Path
}
func (l *Lease) Release() {
	if l != nil {
		l.once.Do(l.release)
	}
}

func (m *Manager) release(key string, e *entry, lease *connectionmanager.Lease) {
	lease.Release()
	m.releaseReservation(key, e)
}

func (m *Manager) releaseReservation(key string, e *entry) {
	m.mu.Lock()
	if e.refs > 0 {
		e.refs--
	}
	if e.refs == 0 && !m.closed && (m.entries[key] == e || e.retired) {
		if m.entries[key] == e {
			delete(m.entries, key)
		}
		m.mu.Unlock()
		slog.Info("peer transport manager closing pool", "reason", "final_reference_released", "generation", e.gen)
		_ = closeEntry(e)
		return
	}
	m.mu.Unlock()
}

// RetirePrefix prevents future consumers from reusing matching pools while
// allowing already-authorized application leases to drain normally.
func (m *Manager) RetirePrefix(prefix string) error {
	if m == nil || prefix == "" {
		return ErrInvalid
	}
	m.mu.Lock()
	var idle []*entry
	for key, e := range m.entries {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		delete(m.entries, key)
		e.retired = true
		if e.pool == nil {
			e.err = ErrInvalid
			close(e.ready)
		} else if e.refs == 0 {
			idle = append(idle, e)
		}
	}
	m.mu.Unlock()
	var result error
	for _, e := range idle {
		result = errors.Join(result, closeEntry(e))
	}
	return result
}

// NetworkChanged fences UDP-backed machine sessions while preserving the
// daemon-wide substrate and any usable WSS selection.
func (m *Manager) NetworkChanged() {
	if m == nil {
		return
	}
	m.mu.Lock()
	pools := make([]*connectionmanager.Pool, 0, len(m.entries))
	for _, e := range m.entries {
		if e.pool != nil {
			pools = append(pools, e.pool)
		}
	}
	m.mu.Unlock()
	for _, pool := range pools {
		pool.NetworkChanged()
	}
}

// Invalidate closes all carriers for key. New acquisition must rebuild state.
func (m *Manager) Invalidate(key string) error {
	if m == nil || key == "" {
		return ErrInvalid
	}
	m.mu.Lock()
	e := m.entries[key]
	delete(m.entries, key)
	if e != nil && e.pool == nil {
		e.err = ErrInvalid
		close(e.ready)
	}
	m.mu.Unlock()
	if e != nil {
		if e.pool == nil {
			return nil
		}
		slog.Info("peer transport manager closing pool", "reason", "authority_invalidated", "generation", e.gen, "references", e.refs)
		e.pool.Invalidate()
		return closeEntry(e)
	}
	return nil
}

// InvalidatePrefix closes carriers belonging to one authority scope.
func (m *Manager) InvalidatePrefix(prefix string) error {
	if m == nil || prefix == "" {
		return ErrInvalid
	}
	m.mu.Lock()
	entries := make([]*entry, 0)
	for key, e := range m.entries {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		delete(m.entries, key)
		if e.pool == nil {
			e.err = ErrInvalid
			close(e.ready)
		}
		entries = append(entries, e)
	}
	m.mu.Unlock()
	var result error
	for _, e := range entries {
		if e.pool != nil {
			slog.Info("peer transport manager closing pool", "reason", "authority_prefix_invalidated", "generation", e.gen, "references", e.refs)
			e.pool.Invalidate()
			result = errors.Join(result, closeEntry(e))
		}
	}
	return result
}

// InvalidateAll is used for installation-wide identity, authorization,
// network, sleep/wake, and power-policy transitions.
func (m *Manager) InvalidateAll() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	entries := make([]*entry, 0, len(m.entries))
	for key, e := range m.entries {
		delete(m.entries, key)
		if e.pool == nil {
			e.err = ErrInvalid
			close(e.ready)
		}
		entries = append(entries, e)
	}
	m.mu.Unlock()
	var result error
	for _, e := range entries {
		if e.pool == nil {
			continue
		}
		slog.Info("peer transport manager closing pool", "reason", "all_authority_invalidated", "generation", e.gen, "references", e.refs)
		e.pool.Invalidate()
		result = errors.Join(result, closeEntry(e))
	}
	return result
}

func (m *Manager) Snapshots() []Snapshot {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Snapshot, 0, len(m.entries))
	for key, e := range m.entries {
		result = append(result, Snapshot{Key: key, Generation: e.gen, Leases: e.refs, Ready: e.pool != nil && e.err == nil})
	}
	return result
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	entries := make([]*entry, 0, len(m.entries))
	for key, e := range m.entries {
		delete(m.entries, key)
		if e.pool == nil {
			e.err = ErrInvalid
			close(e.ready)
		}
		entries = append(entries, e)
	}
	m.mu.Unlock()
	var err error
	for _, e := range entries {
		slog.Info("peer transport manager closing pool", "reason", "manager_shutdown", "generation", e.gen, "references", e.refs)
		err = errors.Join(err, closeEntry(e))
	}
	return err
}

func closeEntry(e *entry) error {
	if e == nil {
		return nil
	}
	return closeOwned(e.pool, e.cleanup)
}

func closeOwned(pool *connectionmanager.Pool, cleanup func() error) error {
	var err error
	if pool != nil {
		err = pool.Close()
	}
	if cleanup != nil {
		err = errors.Join(err, cleanup())
	}
	return err
}
