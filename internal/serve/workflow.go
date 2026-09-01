package serve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
)

// PreviewSession is the canonical v1 foreground lease lifecycle. A session
// owns renewal, carrier reconnect, and revocation; serve only publishes its
// endpoint after WaitReady succeeds.
type PreviewSession interface {
	WaitReady(context.Context) (preview.Lease, error)
	Wait() error
	Stop(context.Context) error
}

// PreviewSessionStarter creates a session after the loopback origin listener
// has selected its actual port.
type PreviewSessionStarter func(context.Context, uint16) (PreviewSession, error)

type LifecycleEvent struct {
	Operation string
	Result    string
	Duration  time.Duration
}

type ForegroundConfig struct {
	Source     Source
	Name       string
	Duration   time.Duration
	Indefinite bool
	SPA        bool
	Session    PreviewSessionStarter
	// LeaseClient and Carrier are the production composition boundary for the
	// canonical foreground preview session. When both are supplied and Session
	// is nil, StartForeground creates the session after the listener chooses its
	// actual port. No URL is published until that session reports readiness.
	LeaseClient    preview.LeaseClient
	Carrier        preview.Carrier
	OwnerDeviceID  string
	OwnerSessionID string
	AccessMode     string
	TargetScheme   string
	// Target is the origin supplied to a canonical preview lease. When set,
	// StartForeground skips the retired static loopback listener and lets the
	// authenticated preview carrier connect to this explicit HTTP/HTTPS/h2c,
	// Unix, or TCP target. It is valid only for the automatic LeaseClient plus
	// Carrier workflow.
	Target       *preview.LeaseTarget
	UserDeadline *time.Time
	ReadyTimeout time.Duration
	DrainTimeout time.Duration
	Observe      func(LifecycleEvent)
}

type Foreground struct {
	Lease   preview.Lease
	server  *Server
	done    chan error
	session PreviewSession
	cancel  context.CancelFunc
	once    sync.Once
}

type Local struct {
	URL    string
	server *Server
	done   chan error
	once   sync.Once
}

type LocalConfig struct {
	Source       Source
	SPA          bool
	ListenPort   uint16
	Duration     time.Duration
	Indefinite   bool
	DrainTimeout time.Duration
	Ready        func(string) error
	Observe      func(LifecycleEvent)
}

// StartLocal serves a pinned source only on the initiating device's IPv4
// loopback interface. It has no control-plane or machine-runtime dependency.
func StartLocal(ctx context.Context, config LocalConfig) (*Local, error) {
	startedAt := time.Now()
	emit := func(operation, result string, since time.Time) {
		if config.Observe != nil {
			config.Observe(LifecycleEvent{Operation: operation, Result: result, Duration: time.Since(since)})
		}
	}
	if ctx == nil || config.Indefinite == (config.Duration > 0) {
		emit("validation", "failed", startedAt)
		return nil, ErrInvalidSource
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
	server, err := StartLoopback(handler, config.ListenPort)
	if err != nil {
		emit("listener_start", "failed", listenerStartedAt)
		return nil, fmt.Errorf("start private serve listener: %w", err)
	}
	emit("listener_start", "ok", listenerStartedAt)
	local := &Local{URL: fmt.Sprintf("http://127.0.0.1:%d", server.Port()), server: server, done: make(chan error, 1)}
	if config.Ready != nil {
		if err := config.Ready(local.URL); err != nil {
			drainCtx, cancel := context.WithTimeout(context.Background(), config.DrainTimeout)
			shutdownErr := server.Shutdown(drainCtx)
			cancel()
			return nil, errors.Join(err, shutdownErr)
		}
	}
	go func() {
		var primary error
		var expiry <-chan time.Time
		var timer *time.Timer
		if !config.Indefinite {
			timer = time.NewTimer(config.Duration)
			expiry = timer.C
			defer timer.Stop()
		}
		select {
		case primary = <-server.Done():
		case <-expiry:
		case <-ctx.Done():
			primary = ctx.Err()
		}
		local.done <- local.stop(config.DrainTimeout, primary, config.Observe)
		close(local.done)
	}()
	return local, nil
}

func (l *Local) Wait() error { return <-l.done }

func (l *Local) stop(timeout time.Duration, primary error, observe func(LifecycleEvent)) error {
	var result error
	l.once.Do(func() {
		startedAt := time.Now()
		drainCtx, cancel := context.WithTimeout(context.Background(), timeout)
		shutdownErr := l.server.Shutdown(drainCtx)
		cancel()
		if errors.Is(primary, context.Canceled) {
			primary = nil
		}
		result = errors.Join(primary, shutdownErr)
		if observe != nil {
			observe(LifecycleEvent{Operation: "listener_stop", Result: eventResult(result), Duration: time.Since(startedAt)})
		}
	})
	return result
}

func cleanupForegroundStartup(server *Server, cancel context.CancelFunc, timeout time.Duration, primary error, observe func(LifecycleEvent)) error {
	startedAt := time.Now()
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), timeout)
	var shutdownErr error
	if server != nil {
		shutdownErr = server.Shutdown(drainCtx)
	}
	cancelDrain()
	cancel()
	result := errors.Join(primary, shutdownErr)
	if observe != nil {
		observe(LifecycleEvent{Operation: "cleanup", Result: eventResult(result), Duration: time.Since(startedAt)})
	}
	return result
}

func validForegroundTarget(target preview.LeaseTarget) bool {
	scheme := strings.ToLower(strings.TrimSpace(target.Scheme))
	if scheme != "http" && scheme != "https" && scheme != "h2c" && scheme != "unix" && scheme != "tcp" {
		return false
	}
	address := strings.TrimSpace(target.Address)
	return address != "" && len(address) <= 512 && !strings.ContainsAny(address, "\x00\r\n")
}

func foregroundServerDone(server *Server) <-chan error {
	if server == nil {
		return nil
	}
	return server.Done()
}

func StartForeground(ctx context.Context, config ForegroundConfig) (*Foreground, error) {
	startedAt := time.Now()
	emit := func(operation, result string, since time.Time) {
		if config.Observe != nil {
			config.Observe(LifecycleEvent{Operation: operation, Result: result, Duration: time.Since(since)})
		}
	}
	autoSession := config.Session == nil && config.LeaseClient != nil && config.Carrier != nil
	partialSession := config.LeaseClient != nil && config.Carrier == nil || config.LeaseClient == nil && config.Carrier != nil
	targetWorkflow := config.Target != nil
	if ctx == nil || partialSession || config.Session != nil && (config.LeaseClient != nil || config.Carrier != nil) || config.Session == nil && !autoSession || config.Name == "" || config.Duration < 0 || targetWorkflow && !autoSession || targetWorkflow && !validForegroundTarget(*config.Target) || !autoSession && config.Session == nil && config.Indefinite == (config.Duration > 0) {
		emit("validation", "failed", startedAt)
		return nil, ErrInvalidSource
	}
	if config.ReadyTimeout <= 0 {
		config.ReadyTimeout = 30 * time.Second
	}
	if config.DrainTimeout <= 0 {
		config.DrainTimeout = DefaultDrainTimeout
	}
	var server *Server
	var err error
	if !targetWorkflow {
		var handler http.Handler
		handler, err = NewHandler(HandlerConfig{Source: config.Source, SPA: config.SPA})
		if err != nil {
			emit("validation", "failed", startedAt)
			return nil, err
		}
		listenerStartedAt := time.Now()
		server, err = Start(handler)
		if err != nil {
			emit("listener_start", "failed", listenerStartedAt)
			return nil, fmt.Errorf("start static server: %w", err)
		}
		emit("listener_start", "ok", listenerStartedAt)
	}
	emit("validation", "ok", startedAt)
	previewCtx, cancelPreview := context.WithCancel(context.WithoutCancel(ctx))
	ready := make(chan preview.Lease, 1)
	previewDone := make(chan error, 1)
	var session PreviewSession
	var readyLease preview.Lease
	sessionStarter := config.Session
	if autoSession {
		sessionStarter = func(sessionCtx context.Context, port uint16) (PreviewSession, error) {
			target := preview.LeaseTarget{}
			if config.Target != nil {
				target = *config.Target
			} else {
				targetScheme := config.TargetScheme
				if targetScheme == "" {
					targetScheme = "http"
				}
				target = preview.LeaseTarget{Scheme: targetScheme, Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))}
			}
			return preview.Start(sessionCtx, preview.SessionConfig{
				LeaseClient: config.LeaseClient, Carrier: config.Carrier,
				OwnerDeviceID: config.OwnerDeviceID, OwnerSessionID: config.OwnerSessionID,
				Target:     target,
				AccessMode: config.AccessMode, UserDeadline: config.UserDeadline,
				Duration: config.Duration,
			})
		}
	}
	if sessionStarter != nil {
		var port uint16
		if server != nil {
			port = server.Port()
		}
		session, err = sessionStarter(previewCtx, port)
		if err != nil {
			return nil, cleanupForegroundStartup(server, cancelPreview, config.DrainTimeout, err, config.Observe)
		}
		if session == nil {
			return nil, cleanupForegroundStartup(server, cancelPreview, config.DrainTimeout, errors.New("preview session starter returned no session"), config.Observe)
		}
		go func() {
			previewDone <- session.Wait()
		}()
		go func() {
			lease, readyErr := session.WaitReady(previewCtx)
			if readyErr != nil {
				return
			}
			readyLease = lease
			select {
			case ready <- lease:
			case <-previewCtx.Done():
			}
		}()
	}

	cleanup := func(primary error) error {
		cleanupStartedAt := time.Now()
		cancelPreview()
		drainCtx, cancelDrain := context.WithTimeout(context.Background(), config.DrainTimeout)
		var shutdownErr error
		if server != nil {
			shutdownErr = server.Shutdown(drainCtx)
		}
		cancelDrain()
		releaseCtx, cancelRelease := context.WithTimeout(context.Background(), config.DrainTimeout)
		previewErr := session.Stop(releaseCtx)
		cancelRelease()
		result := errors.Join(primary, shutdownErr, previewErr)
		emit("cleanup", eventResult(result), cleanupStartedAt)
		return result
	}

	timer := time.NewTimer(config.ReadyTimeout)
	defer timer.Stop()
	var lease preview.Lease
	select {
	case lease = <-ready:
		if lease.Endpoint == "" || lease.State != "ready" {
			return nil, cleanup(errors.New("preview became ready without a public URL"))
		}
		emit("readiness", "ok", startedAt)
	case err = <-previewDone:
		if err == nil {
			err = errors.New("preview stopped before readiness")
		}
		return nil, cleanup(fmt.Errorf("create preview: %w", err))
	case err = <-foregroundServerDone(server):
		return nil, cleanup(fmt.Errorf("static server stopped before readiness: %w", err))
	case <-timer.C:
		emit("readiness", "timeout", startedAt)
		return nil, cleanup(errors.New("preview readiness timed out"))
	case <-ctx.Done():
		return nil, cleanup(ctx.Err())
	}

	foreground := &Foreground{Lease: readyLease, server: server, done: make(chan error, 1), session: session, cancel: cancelPreview}
	go func() {
		var primary error
		var expiry <-chan time.Time
		var expiryTimer *time.Timer
		if lease.UserDeadline != nil {
			remaining := time.Until(lease.UserDeadline.UTC())
			if remaining < 0 {
				remaining = 0
			}
			expiryTimer = time.NewTimer(remaining)
			expiry = expiryTimer.C
			defer expiryTimer.Stop()
		}
		select {
		case primary = <-previewDone:
		case primary = <-foregroundServerDone(server):
		case <-expiry:
		case <-ctx.Done():
			primary = ctx.Err()
		}
		foreground.done <- foreground.stop(config.DrainTimeout, primary, config.Observe)
		close(foreground.done)
	}()
	return foreground, nil
}

func (f *Foreground) Wait() error { return <-f.done }

func (f *Foreground) stop(timeout time.Duration, primary error, observe func(LifecycleEvent)) error {
	var result error
	f.once.Do(func() {
		startedAt := time.Now()
		if f.cancel != nil {
			f.cancel()
		}
		drainCtx, cancelDrain := context.WithTimeout(context.Background(), timeout)
		var shutdownErr error
		if f.server != nil {
			shutdownErr = f.server.Shutdown(drainCtx)
		}
		cancelDrain()
		stopCtx, cancelStop := context.WithTimeout(context.Background(), timeout)
		previewErr := f.session.Stop(stopCtx)
		cancelStop()
		if errors.Is(primary, context.Canceled) {
			primary = nil
		}
		result = errors.Join(primary, shutdownErr, previewErr)
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
