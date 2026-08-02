//go:build darwin || linux

package runtime

import (
	"context"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/codexsession"
)

type codexSessionService struct {
	manager *codexsession.Manager
	cancel  context.CancelFunc
	done    chan struct{}
	once    sync.Once
}

func (s *codexSessionService) Start(ctx context.Context) error {
	workerCtx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ticker.C:
				cleanupCtx, cleanupCancel := context.WithTimeout(workerCtx, 15*time.Second)
				_ = s.manager.CleanupExpired(cleanupCtx)
				cleanupCancel()
			}
		}
	}()
	return ctx.Err()
}

func (s *codexSessionService) Shutdown(ctx context.Context) error {
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
	})
	if s.done != nil {
		select {
		case <-s.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.manager.Shutdown(ctx)
}
