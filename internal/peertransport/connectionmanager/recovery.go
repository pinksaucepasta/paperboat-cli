package connectionmanager

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

type RecoveryScheduler interface {
	Run(context.Context) error
}

type RecoverySupervisorConfig struct {
	Pool        *Pool
	Interactive RecoveryScheduler
	Preview     RecoveryScheduler
}

type RecoverySupervisor struct {
	pool       *Pool
	schedulers map[peerquic.Class]RecoveryScheduler

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

type recoveryCompletion struct {
	class peerquic.Class
	owner *recoveryOwner
}

type activeRecovery struct {
	owner    *recoveryOwner
	cancel   context.CancelFunc
	path     Path
	stopping bool
}

type recoveryOwner struct {
	//lint:ignore U1000 The byte keeps independently allocated recovery owners pointer-distinct.
	marker byte
}

func NewRecoverySupervisor(config RecoverySupervisorConfig) (*RecoverySupervisor, error) {
	if config.Pool == nil || config.Interactive == nil || config.Preview == nil {
		return nil, errors.New("invalid direct recovery supervisor")
	}
	return &RecoverySupervisor{
		pool: config.Pool,
		schedulers: map[peerquic.Class]RecoveryScheduler{
			peerquic.ClassInteractive: config.Interactive,
			peerquic.ClassPreview:     config.Preview,
		},
	}, nil
}

func (s *RecoverySupervisor) Start(context.Context) error {
	if s == nil || s.pool == nil {
		return errors.New("invalid direct recovery supervisor")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done != nil {
		return errors.New("direct recovery supervisor already started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel, s.done = cancel, make(chan struct{})
	go s.run(ctx, s.done)
	return nil
}

func (s *RecoverySupervisor) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		s.mu.Lock()
		if s.done == done {
			s.cancel, s.done = nil, nil
		}
		s.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *RecoverySupervisor) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	changes, unsubscribe := s.pool.SubscribeChanges()
	defer unsubscribe()
	completed := make(chan recoveryCompletion, len(s.schedulers))
	running := make(map[peerquic.Class]activeRecovery, len(s.schedulers))
	var runners sync.WaitGroup
	reconcile := func() {
		for class, scheduler := range s.schedulers {
			snapshot, err := s.pool.Snapshot(class)
			eligible := err == nil && !snapshot.Closed && !snapshot.UpgradePending && snapshot.Selected && (snapshot.Leases > 0 || snapshot.Warm) && (snapshot.Path == PathRelayQUIC || snapshot.Path == PathWSS)
			active, exists := running[class]
			if !eligible {
				if exists && !active.stopping {
					slog.Info("peer recovery supervisor canceling run", "class", uint8(class), "path", uint8(active.path), "selected", snapshot.Selected, "selected_path", uint8(snapshot.Path), "leases", snapshot.Leases, "warm", snapshot.Warm, "upgrade_pending", snapshot.UpgradePending, "error", err)
					active.cancel()
					active.stopping = true
					running[class] = active
				}
				continue
			}
			if exists {
				if !active.stopping && active.path != snapshot.Path {
					active.cancel()
					active.stopping = true
					running[class] = active
				}
				continue
			}
			owner := &recoveryOwner{}
			runCtx, cancel := context.WithCancel(ctx)
			running[class] = activeRecovery{owner: owner, cancel: cancel, path: snapshot.Path}
			slog.Info("peer recovery supervisor starting run", "class", uint8(class), "selected_path", uint8(snapshot.Path), "leases", snapshot.Leases, "warm", snapshot.Warm)
			runners.Add(1)
			go func(class peerquic.Class, owner *recoveryOwner, scheduler RecoveryScheduler) {
				defer runners.Done()
				_ = scheduler.Run(runCtx)
				select {
				case completed <- recoveryCompletion{class: class, owner: owner}:
				case <-ctx.Done():
				}
			}(class, owner, scheduler)
		}
	}
	reconcile()
	for {
		select {
		case <-ctx.Done():
			for _, active := range running {
				active.cancel()
			}
			runners.Wait()
			return
		case <-changes:
			reconcile()
		case result := <-completed:
			if active, ok := running[result.class]; ok && active.owner == result.owner {
				slog.Info("peer recovery supervisor run completed", "class", uint8(result.class), "path", uint8(active.path), "stopping", active.stopping)
				delete(running, result.class)
				reconcile()
			}
		}
	}
}
