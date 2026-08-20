//go:build darwin || linux || windows

package runtime

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	runtimeidentity "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
)

type managedSSHKeyReconciler struct {
	client           managedSSHControlClient
	identity         managedSSHIdentitySource
	registration     runtimeidentity.Registration
	workerGeneration uint64
	setID            string
	publicKeys       []string
	home             string
	ownerUID         uint32
	interval         time.Duration
	timeout          time.Duration
	sequence         atomic.Uint64

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *managedSSHKeyReconciler) Start(ctx context.Context) error {
	if ctx == nil || s.client == nil || s.identity == nil || s.registration.MachineID == "" || s.registration.InstallationGeneration < 1 || s.workerGeneration == 0 || s.setID == "" || len(s.publicKeys) == 0 || s.home == "" || s.interval <= 0 || s.timeout <= 0 {
		return ErrProductionInvalid
	}
	if err := s.reconcile(ctx); err != nil {
		return errors.Join(ErrManagedSSHUnavailable, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return errors.New("managed SSH key reconciliation is already running")
	}
	workerCtx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})
	go s.run(workerCtx, s.done)
	return nil
}

func (s *managedSSHKeyReconciler) run(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcileCtx, cancel := context.WithTimeout(ctx, s.timeout)
			if err := s.reconcile(reconcileCtx); err != nil {
				// A managed key is only authoritative while the host can obtain a
				// current authority response. Retaining it after a failed refresh
				// would turn a temporary control-plane failure into unbounded
				// revocation latency.
				slog.Warn("managed SSH authority refresh failed; removed managed authorized keys", "error", err)
			}
			cancel()
		}
	}
}

func (s *managedSSHKeyReconciler) reconcile(ctx context.Context) error {
	sequence := s.sequence.Add(1)
	suffix := s.registration.MachineID + "-" + strconv.FormatUint(uint64(s.registration.InstallationGeneration), 10) + "-" + strconv.FormatUint(s.workerGeneration, 10) + "-refresh-" + strconv.FormatUint(sequence, 10)
	keys, active, err := reconcileManagedSSHAuthorityWithOperations(ctx, s.client, s.identity, s.registration, s.workerGeneration, s.setID, s.publicKeys, "managed-ssh-observe-"+suffix, "managed-ssh-keys-"+suffix)
	if err != nil {
		_, cleanupErr := reconcilePlatformAuthorizedKeys(s.home, s.ownerUID, nil)
		return errors.Join(err, cleanupErr)
	}
	if !active {
		keys.Keys = nil
	}
	_, err = reconcilePlatformAuthorizedKeys(s.home, s.ownerUID, keys.Keys)
	return err
}

func (s *managedSSHKeyReconciler) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel, s.done = nil, nil
	s.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		_, err := reconcilePlatformAuthorizedKeys(s.home, s.ownerUID, nil)
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
