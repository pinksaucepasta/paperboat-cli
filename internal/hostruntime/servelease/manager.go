package servelease

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

var (
	ErrInvalid   = errors.New("invalid serve management lease")
	ErrConflict  = errors.New("serve management lease already held")
	ErrLeaseLost = errors.New("serve management lease lost")
)

const ProtocolVersion = "1.0"

type Lease struct {
	ID        string    `json:"lease_id"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Config struct {
	TTL      time.Duration
	Interval time.Duration
	Now      func() time.Time
	Expired  func(context.Context, Lease) error
	Metrics  interface {
		Record(string, float64, map[string]string) error
	}
	Events interface {
		Record(context.Context, string, string)
	}
	StatePath string
}

type Manager struct {
	config Config
	mu     sync.Mutex
	leases map[string]Lease
	cancel context.CancelFunc
	done   chan error
}

func New(config Config) (*Manager, error) {
	if config.TTL < 3*time.Second || config.Interval <= 0 || config.Interval >= config.TTL {
		return nil, ErrInvalid
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	manager := &Manager{config: config, leases: make(map[string]Lease)}
	if config.StatePath != "" {
		if !filepath.IsAbs(config.StatePath) {
			return nil, ErrInvalid
		}
		if err := manager.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return manager, nil
}

func (m *Manager) Acquire(name string) (Lease, error) {
	if name == "" {
		return Lease{}, ErrInvalid
	}
	m.mu.Lock()
	now := m.config.Now().UTC()
	if existing, ok := m.leases[name]; ok && existing.ExpiresAt.After(now) {
		m.mu.Unlock()
		return Lease{}, ErrConflict
	}
	idBytes := make([]byte, 24)
	if _, err := rand.Read(idBytes); err != nil {
		m.mu.Unlock()
		return Lease{}, err
	}
	lease := Lease{ID: "sl_" + base64.RawURLEncoding.EncodeToString(idBytes), Name: name, ExpiresAt: now.Add(m.config.TTL)}
	m.leases[name] = lease
	if err := m.persistLocked(); err != nil {
		delete(m.leases, name)
		m.mu.Unlock()
		return Lease{}, err
	}
	m.mu.Unlock()
	m.record("lease_acquire", "ok")
	m.activeMetric()
	return lease, nil
}

func (m *Manager) Renew(id, name string) (Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.config.Now().UTC()
	lease, ok := m.leases[name]
	if !ok || lease.ID != id || !lease.ExpiresAt.After(now) {
		return Lease{}, ErrLeaseLost
	}
	lease.ExpiresAt = now.Add(m.config.TTL)
	previous := m.leases[name]
	m.leases[name] = lease
	if err := m.persistLocked(); err != nil {
		m.leases[name] = previous
		return Lease{}, err
	}
	m.record("lease_renew", "ok")
	return lease, nil
}

func (m *Manager) Release(id, name string) error {
	m.mu.Lock()
	lease, ok := m.leases[name]
	if !ok {
		m.mu.Unlock()
		return nil
	}
	if lease.ID != id {
		m.mu.Unlock()
		return ErrLeaseLost
	}
	delete(m.leases, name)
	if err := m.persistLocked(); err != nil {
		m.leases[name] = lease
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()
	m.record("lease_release", "ok")
	m.activeMetric()
	return nil
}

func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.leases)
}

func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return ErrInvalid
	}
	runCtx, cancel := context.WithCancel(ctx)
	m.cancel, m.done = cancel, make(chan error, 1)
	m.mu.Unlock()
	go m.run(runCtx)
	return nil
}

func (m *Manager) run(ctx context.Context) {
	ticker := time.NewTicker(m.config.Interval)
	defer ticker.Stop()
	defer close(m.done)
	for {
		select {
		case <-ctx.Done():
			m.done <- nil
			return
		case <-ticker.C:
			for _, lease := range m.takeExpired() {
				m.record("lease_loss", "expired")
				m.activeMetric()
				if m.config.Expired != nil {
					started := time.Now()
					cleanupCtx, cancel := context.WithTimeout(context.Background(), m.config.TTL)
					err := m.config.Expired(cleanupCtx, lease)
					cancel()
					if err != nil {
						m.latency("reconciliation", "failed", time.Since(started))
						m.record("cleanup", "failed")
					} else {
						m.latency("reconciliation", "ok", time.Since(started))
						m.record("cleanup", "removed")
						m.completeExpired(lease)
					}
				}
			}
		}
	}
}

func (m *Manager) latency(stage, result string, duration time.Duration) {
	if m.config.Metrics != nil {
		_ = m.config.Metrics.Record("paperboat_runtime_serve_latency_seconds", duration.Seconds(), map[string]string{"stage": stage, "owner": "foreground", "result": result})
	}
}

func (m *Manager) record(event, result string) {
	if m.config.Metrics != nil {
		_ = m.config.Metrics.Record("paperboat_runtime_serve_events_total", 1, map[string]string{"event": event, "result": result})
	}
	if m.config.Events != nil {
		m.config.Events.Record(context.Background(), event, result)
	}
}

func (m *Manager) activeMetric() {
	if m.config.Metrics != nil {
		_ = m.config.Metrics.Record("paperboat_runtime_active_resources", float64(m.Count()), map[string]string{"kind": "serves_foreground"})
	}
}

func (m *Manager) takeExpired() []Lease {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.config.Now().UTC()
	var result []Lease
	for name, lease := range m.leases {
		if !lease.ExpiresAt.After(now) {
			result = append(result, lease)
			lease.ExpiresAt = now.Add(m.config.TTL)
			m.leases[name] = lease
		}
	}
	if len(result) != 0 {
		if err := m.persistLocked(); err != nil {
			return nil
		}
	}
	return result
}

func (m *Manager) completeExpired(lease Lease) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if current := m.leases[lease.Name]; current.ID != lease.ID {
		return
	}
	delete(m.leases, lease.Name)
	_ = m.persistLocked()
}

func (m *Manager) load() error {
	info, err := os.Lstat(m.config.StatePath)
	if err != nil {
		return err
	}
	if !secureStateFile(m.config.StatePath, info) {
		return ErrInvalid
	}
	file, err := os.Open(m.config.StatePath)
	if err != nil {
		return err
	}
	defer file.Close()
	var state struct {
		Schema string  `json:"schema"`
		Leases []Lease `json:"leases"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || state.Schema != "paperboat.serve-leases/v1" {
		return ErrInvalid
	}
	for _, lease := range state.Leases {
		if lease.ID == "" || lease.Name == "" || lease.ExpiresAt.IsZero() || m.leases[lease.Name].ID != "" {
			return ErrInvalid
		}
		m.leases[lease.Name] = lease
	}
	return nil
}

func (m *Manager) persistLocked() error {
	if m.config.StatePath == "" {
		return nil
	}
	state := struct {
		Schema string  `json:"schema"`
		Leases []Lease `json:"leases"`
	}{Schema: "paperboat.serve-leases/v1", Leases: make([]Lease, 0, len(m.leases))}
	for _, lease := range m.leases {
		state.Leases = append(state.Leases, lease)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	directory := filepath.Dir(m.config.StatePath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	return atomicfile.Write(m.config.StatePath, data, atomicfile.CurrentOwnerOptions(0o600))
}

func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	cancel, done := m.cancel, m.done
	m.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
