package tunnelmanager

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

const productionStateDirectory = "tunnels"

// ProductionConfig owns the durable store and reconciliation policy used by
// stable hostd. Factory remains explicit because its authenticated carrier is
// supplied by the connector-v1 transport composition.
type ProductionConfig struct {
	StateRoot         string
	HostID            string
	Factory           Factory
	Refresh           func(context.Context) error
	Report            func(Observation)
	Clock             func() time.Time
	ReconcileInterval time.Duration
	ApplyTimeout      time.Duration
	DrainTimeout      time.Duration
	ActiveObserver    func(ActiveChange)
}

// ConfigApplier returns the production connector-v1 desired-state bridge over
// the same locked store owned by this manager. Callers cannot open a second
// store or acknowledge readiness without the manager's exact active runtime.
func (m *ProductionManager) ConfigApplier(clock connectorprotocol.Clock, stableEndpointID string) (*CoordinatedConfigApplier, error) {
	if m == nil || m.Manager == nil || m.store == nil {
		return nil, ErrInvalidConfig
	}
	if err := hoststate.ValidateStableEndpointID(stableEndpointID); err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	return &CoordinatedConfigApplier{
		State:   &connectorprotocol.HostStateApplier{Store: m.store, Clock: clock, StableEndpointID: stableEndpointID},
		Manager: m.Manager,
	}, nil
}

// ProductionManager keeps the host-state process lock for exactly the
// manager lifecycle. Shutdown is retryable after a caller deadline: the store
// is released only after the manager has actually stopped its active carriers.
type ProductionManager struct {
	*Manager
	store     *hoststate.Store
	closeMu   sync.Mutex
	storeDone bool
}

func OpenProduction(config ProductionConfig) (*ProductionManager, hoststate.StartupStatus, error) {
	if config.StateRoot == "" || !filepath.IsAbs(config.StateRoot) || filepath.Clean(config.StateRoot) != config.StateRoot || config.StateRoot == string(filepath.Separator) {
		return nil, hoststate.StartupStatus{}, ErrInvalidConfig
	}
	store, status, err := hoststate.Open(hoststate.Config{Root: filepath.Join(config.StateRoot, productionStateDirectory), Clock: config.Clock})
	if err != nil {
		return nil, status, err
	}
	manager, err := New(Config{
		Store: store, Factory: config.Factory, HostID: config.HostID,
		Refresh: config.Refresh, Report: config.Report, Clock: config.Clock,
		ReconcileInterval: config.ReconcileInterval, ApplyTimeout: config.ApplyTimeout,
		DrainTimeout: config.DrainTimeout, ActiveObserver: config.ActiveObserver,
	})
	if err != nil {
		return nil, status, errors.Join(err, store.Close())
	}
	return &ProductionManager{Manager: manager, store: store}, status, nil
}

func (m *ProductionManager) Shutdown(ctx context.Context) error {
	if m == nil || m.Manager == nil || ctx == nil {
		return ErrInvalidConfig
	}
	if err := m.Manager.Shutdown(ctx); err != nil {
		return err
	}
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	if m.storeDone {
		return nil
	}
	if err := m.store.Close(); err != nil {
		return err
	}
	m.storeDone = true
	return nil
}
