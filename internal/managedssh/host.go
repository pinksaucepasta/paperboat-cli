package managedssh

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

var (
	ErrSSHHostInvalid = errors.New("managed SSH host service is invalid")
	ErrSSHHostStale   = errors.New("managed SSH host target generation is stale")
	ErrSSHHostBusy    = errors.New("managed SSH host stream capacity is exhausted")
)

type HostTarget struct {
	Generation uint64
	Port       uint16
	Readiness  SSHReadiness
}

type HostConfig struct {
	MaxStreams   int
	ProbeTimeout time.Duration
	DialTimeout  time.Duration
}

// Host owns the bounded runtime boundary between an authorized Paperboat SSH
// stream and the machine's existing loopback sshd.
type Host struct {
	mu       sync.RWMutex
	config   HostConfig
	target   HostTarget
	capacity chan struct{}
}

func NewHost(config HostConfig) (*Host, error) {
	if config.MaxStreams < 1 || config.MaxStreams > 1024 || config.ProbeTimeout <= 0 || config.ProbeTimeout > 30*time.Second || config.DialTimeout <= 0 || config.DialTimeout > 30*time.Second {
		return nil, ErrSSHHostInvalid
	}
	return &Host{config: config, capacity: make(chan struct{}, config.MaxStreams)}, nil
}

// ReconcileTarget proves listener readiness before publishing a new target.
// Equal-generation replay is accepted only when the port is unchanged.
func (h *Host) ReconcileTarget(ctx context.Context, generation uint64, port uint16) (HostTarget, error) {
	if h == nil || ctx == nil || generation == 0 || port == 0 {
		return HostTarget{}, ErrSSHHostInvalid
	}
	h.mu.RLock()
	current := h.target
	h.mu.RUnlock()
	if current.Generation > generation || current.Generation == generation && current.Port != port {
		return HostTarget{}, ErrSSHHostStale
	}
	if current.Generation == generation {
		return current, nil
	}
	readiness, err := ProbeLoopbackSSH(ctx, port, h.config.ProbeTimeout)
	if err != nil {
		return HostTarget{}, err
	}
	next := HostTarget{Generation: generation, Port: port, Readiness: readiness}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.target.Generation > generation || h.target.Generation == generation && h.target.Port != port {
		return HostTarget{}, ErrSSHHostStale
	}
	if h.target.Generation == generation {
		return h.target, nil
	}
	h.target = next
	return next, nil
}

func (h *Host) Target() (HostTarget, bool) {
	if h == nil {
		return HostTarget{}, false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.target, h.target.Generation != 0
}

func (h *Host) Serve(ctx context.Context, generation uint64, stream io.ReadWriteCloser) (BridgeResult, error) {
	if h == nil || ctx == nil || generation == 0 || stream == nil {
		return BridgeResult{}, ErrSSHHostInvalid
	}
	h.mu.RLock()
	target := h.target
	h.mu.RUnlock()
	if target.Generation == 0 || target.Generation != generation {
		return BridgeResult{}, ErrSSHHostStale
	}
	select {
	case h.capacity <- struct{}{}:
		defer func() { <-h.capacity }()
	default:
		return BridgeResult{}, ErrSSHHostBusy
	}
	return BridgeSSH(ctx, stream, target.Readiness.Target, h.config.DialTimeout)
}
