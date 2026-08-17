// Package hostd owns Paperboat workloads which are required to outlive a
// replaceable runtime worker.  In particular, a worker is never allowed to
// acquire a session manager or a live PTY.
package hostd

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/codexsession"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/execprocess"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/servelease"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/session"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
)

var (
	ErrInvalidConfig = errors.New("invalid hostd configuration")
	ErrInvalidState  = errors.New("invalid hostd state")
)

// Service is deliberately the small lifecycle contract shared by stable
// ingress/workload services and replaceable coordination services.
type Service interface {
	Start(context.Context) error
	Shutdown(context.Context) error
}

type Component struct {
	Name     string
	Required bool
	Service  Service
}

// Workloads is the only owner of live workload managers.  It is intentionally
// exposed read-only through Daemon so protocol handlers can use the same
// managers without duplicating process ownership in workers.
type Workloads struct {
	Sessions    *session.Manager
	Executions  *execprocess.Manager
	Transfers   *filetransfer.Service
	Previews    *preview.Registry
	Codex       *codexsession.Manager
	ServeLeases *servelease.Manager
	ManagedSSH  *managedssh.Host
}

func (w Workloads) valid() bool {
	return w.Sessions != nil && w.Executions != nil && w.Transfers != nil
}

type Config struct {
	Workloads       Workloads
	Components      []Component
	ShutdownTimeout time.Duration
}

// Daemon is the stable host supervisor.  Its Shutdown method is reserved for
// actual hostd shutdown.  Worker replacement is performed by WorkerController
// and never invokes Daemon.Shutdown.
type Daemon struct {
	mu      sync.RWMutex
	config  Config
	started []Component
	running bool
	stopped bool
}

func New(config Config) (*Daemon, error) {
	if !config.Workloads.valid() || len(config.Components) == 0 {
		return nil, ErrInvalidConfig
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = 30 * time.Second
	}
	if config.ShutdownTimeout <= 0 {
		return nil, ErrInvalidConfig
	}
	seen := make(map[string]struct{}, len(config.Components))
	for _, component := range config.Components {
		if component.Name == "" || component.Service == nil {
			return nil, ErrInvalidConfig
		}
		if _, exists := seen[component.Name]; exists {
			return nil, ErrInvalidConfig
		}
		seen[component.Name] = struct{}{}
	}
	return &Daemon{config: config}, nil
}

func (d *Daemon) Workloads() Workloads { return d.config.Workloads }

func (d *Daemon) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running || d.stopped {
		return ErrInvalidState
	}
	for _, component := range d.config.Components {
		if err := component.Service.Start(ctx); err != nil {
			if !component.Required {
				continue
			}
			cleanupCtx, cancel := context.WithTimeout(context.Background(), d.config.ShutdownTimeout)
			cleanupErr := d.shutdownStarted(cleanupCtx)
			cancel()
			return errors.Join(fmt.Errorf("start stable %s: %w", component.Name, err), cleanupErr)
		}
		d.started = append(d.started, component)
	}
	d.running = true
	return nil
}

func (d *Daemon) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return nil
	}
	if !d.running {
		return ErrInvalidState
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, d.config.ShutdownTimeout)
	defer cancel()
	err := d.shutdownStarted(shutdownCtx)
	d.running, d.stopped = false, true
	return err
}

func (d *Daemon) shutdownStarted(ctx context.Context) error {
	var result error
	for index := len(d.started) - 1; index >= 0; index-- {
		component := d.started[index]
		result = errors.Join(result, component.Service.Shutdown(ctx))
	}
	d.started = nil
	return result
}

func (d *Daemon) Running() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running && !d.stopped
}

// WorkerController changes coordination workers while retaining daemon-owned
// workloads.  Candidate start happens before the prior worker is stopped so a
// failed candidate cannot interrupt existing coordination.
type WorkerController struct {
	mu      sync.Mutex
	daemon  *Daemon
	active  Service
	running bool
}

func NewWorkerController(daemon *Daemon) (*WorkerController, error) {
	if daemon == nil {
		return nil, ErrInvalidConfig
	}
	return &WorkerController{daemon: daemon}, nil
}

func (c *WorkerController) Start(ctx context.Context, worker Service) error {
	if worker == nil || !c.daemon.Running() {
		return ErrInvalidState
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return ErrInvalidState
	}
	if err := worker.Start(ctx); err != nil {
		return err
	}
	c.active, c.running = worker, true
	return nil
}

// Replace starts a ready candidate, then stops the prior coordination worker.
// It never calls into daemon workloads and therefore cannot terminate a PTY,
// Codex process, transfer, preview, serve listener, or managed SSH stream.
func (c *WorkerController) Replace(ctx context.Context, candidate Service) error {
	if candidate == nil || !c.daemon.Running() {
		return ErrInvalidState
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running || c.active == nil {
		return ErrInvalidState
	}
	if err := candidate.Start(ctx); err != nil {
		return err
	}
	previous := c.active
	c.active = candidate
	if err := previous.Shutdown(ctx); err != nil {
		// The candidate is now the sole worker; do not re-activate a potentially
		// partially shut-down predecessor.
		return fmt.Errorf("stop fenced worker: %w", err)
	}
	return nil
}

func (c *WorkerController) Shutdown(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	worker := c.active
	c.active = nil
	return worker.Shutdown(ctx)
}
