package serve

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
)

type PreviewRunConfig struct {
	Name       string
	Port       uint16
	Duration   time.Duration
	Indefinite bool
	Ready      func(preview.ControlRecord) error
}

type PreviewRunner func(context.Context, PreviewRunConfig) error

type ManagementLease interface {
	Run(context.Context) error
	Release(context.Context) error
}

type LifecycleEvent struct {
	Operation string
	Result    string
	Duration  time.Duration
}

type ForegroundConfig struct {
	Source       Source
	Name         string
	Duration     time.Duration
	Indefinite   bool
	SPA          bool
	Preview      PreviewRunner
	ReadyTimeout time.Duration
	DrainTimeout time.Duration
	Lease        ManagementLease
	Observe      func(LifecycleEvent)
}

type Foreground struct {
	Record preview.ControlRecord
	server *Server
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
}

func StartForeground(ctx context.Context, config ForegroundConfig) (*Foreground, error) {
	startedAt := time.Now()
	emit := func(operation, result string, since time.Time) {
		if config.Observe != nil {
			config.Observe(LifecycleEvent{Operation: operation, Result: result, Duration: time.Since(since)})
		}
	}
	if ctx == nil || config.Preview == nil || config.Name == "" || config.Indefinite == (config.Duration > 0) {
		emit("validation", "failed", startedAt)
		return nil, ErrInvalidSource
	}
	if config.ReadyTimeout <= 0 {
		config.ReadyTimeout = 30 * time.Second
	}
	if config.DrainTimeout <= 0 {
		config.DrainTimeout = DefaultDrainTimeout
	}
	handler, err := NewHandler(HandlerConfig{Source: config.Source, SPA: config.SPA})
	if err != nil {
		emit("validation", "failed", startedAt)
		return nil, err
	}
	emit("validation", "ok", startedAt)
	listenerStartedAt := time.Now()
	server, err := Start(handler)
	if err != nil {
		emit("listener_start", "failed", listenerStartedAt)
		return nil, fmt.Errorf("start static server: %w", err)
	}
	emit("listener_start", "ok", listenerStartedAt)
	previewCtx, cancelPreview := context.WithCancel(context.WithoutCancel(ctx))
	leaseDone := make(chan error, 1)
	if config.Lease != nil {
		go func() { leaseDone <- config.Lease.Run(previewCtx) }()
	}
	ready := make(chan preview.ControlRecord, 1)
	previewDone := make(chan error, 1)
	go func() {
		previewDone <- config.Preview(previewCtx, PreviewRunConfig{
			Name: config.Name, Port: server.Port(), Duration: config.Duration, Indefinite: config.Indefinite,
			Ready: func(record preview.ControlRecord) error {
				select {
				case ready <- record:
					return nil
				case <-previewCtx.Done():
					return previewCtx.Err()
				}
			},
		})
		close(previewDone)
	}()

	cleanup := func(primary error) error {
		cleanupStartedAt := time.Now()
		drainCtx, cancelDrain := context.WithTimeout(context.Background(), config.DrainTimeout)
		shutdownErr := server.Shutdown(drainCtx)
		cancelDrain()
		cancelPreview()
		var previewErr error
		select {
		case previewErr = <-previewDone:
			if errors.Is(previewErr, context.Canceled) {
				previewErr = nil
			}
		case <-time.After(config.DrainTimeout):
			previewErr = errors.New("preview cleanup timed out")
		}
		var releaseErr error
		if config.Lease != nil {
			releaseCtx, cancelRelease := context.WithTimeout(context.Background(), config.DrainTimeout)
			releaseErr = config.Lease.Release(releaseCtx)
			cancelRelease()
		}
		result := errors.Join(primary, shutdownErr, previewErr, releaseErr)
		emit("cleanup", eventResult(result), cleanupStartedAt)
		return result
	}

	timer := time.NewTimer(config.ReadyTimeout)
	defer timer.Stop()
	var record preview.ControlRecord
	select {
	case record = <-ready:
		if record.URL == "" || record.State != "ready" {
			return nil, cleanup(errors.New("preview became ready without a public URL"))
		}
		emit("readiness", "ok", startedAt)
	case err = <-previewDone:
		return nil, cleanup(fmt.Errorf("create preview: %w", err))
	case err = <-server.Done():
		return nil, cleanup(fmt.Errorf("static server stopped before readiness: %w", err))
	case <-timer.C:
		emit("readiness", "timeout", startedAt)
		return nil, cleanup(errors.New("preview readiness timed out"))
	case <-ctx.Done():
		return nil, cleanup(ctx.Err())
	case err = <-leaseDone:
		return nil, cleanup(errors.Join(errors.New("serve management lease lost"), err))
	}

	foreground := &Foreground{Record: record, server: server, cancel: cancelPreview, done: make(chan error, 1)}
	go func() {
		var primary error
		var expiry <-chan time.Time
		var expiryTimer *time.Timer
		if record.ExpiresAt != nil {
			remaining := time.Until(record.ExpiresAt.UTC())
			if remaining < 0 {
				remaining = 0
			}
			expiryTimer = time.NewTimer(remaining)
			expiry = expiryTimer.C
			defer expiryTimer.Stop()
		}
		select {
		case primary = <-previewDone:
		case primary = <-server.Done():
		case <-expiry:
		case <-ctx.Done():
			primary = ctx.Err()
		case leaseErr := <-leaseDone:
			primary = errors.Join(errors.New("serve management lease lost"), leaseErr)
		}
		foreground.done <- foreground.stop(config.DrainTimeout, primary, previewDone, config.Lease, config.Observe)
		close(foreground.done)
	}()
	return foreground, nil
}

func (f *Foreground) Wait() error { return <-f.done }

func (f *Foreground) stop(timeout time.Duration, primary error, previewDone <-chan error, lease ManagementLease, observe func(LifecycleEvent)) error {
	var result error
	f.once.Do(func() {
		startedAt := time.Now()
		drainCtx, cancelDrain := context.WithTimeout(context.Background(), timeout)
		shutdownErr := f.server.Shutdown(drainCtx)
		cancelDrain()
		f.cancel()
		var previewErr error
		select {
		case previewErr = <-previewDone:
			if errors.Is(previewErr, context.Canceled) {
				previewErr = nil
			}
		case <-time.After(timeout):
			previewErr = errors.New("preview cleanup timed out")
		}
		if errors.Is(primary, context.Canceled) {
			primary = nil
		}
		var releaseErr error
		if lease != nil {
			releaseCtx, cancelRelease := context.WithTimeout(context.Background(), timeout)
			releaseErr = lease.Release(releaseCtx)
			cancelRelease()
		}
		result = errors.Join(primary, shutdownErr, previewErr, releaseErr)
		if observe != nil {
			observe(LifecycleEvent{Operation: "drain", Result: eventResult(result), Duration: time.Since(startedAt)})
			observe(LifecycleEvent{Operation: "listener_stop", Result: eventResult(shutdownErr), Duration: time.Since(startedAt)})
		}
	})
	return result
}

func eventResult(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "failed"
}
