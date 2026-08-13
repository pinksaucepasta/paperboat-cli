package localobservation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkcheck"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

type Client interface {
	PublishTransportObservation(context.Context, localapi.TransportObservation) error
}

type Pool interface {
	Changes() <-chan struct{}
	Snapshot(peerquic.Class) (connectionmanager.ClassSnapshot, error)
}

type Config struct {
	Client    Client
	Pool      Pool
	MachineID string
	Classes   []peerquic.Class
	Clock     func() time.Time
	Heartbeat time.Duration
	Lifetime  time.Duration
	Network   func() networkcheck.STUNObservation
}

type Publisher struct {
	client    Client
	pool      Pool
	machineID string
	classes   []peerquic.Class
	clock     func() time.Time
	heartbeat time.Duration
	lifetime  time.Duration
	network   func() networkcheck.STUNObservation
	sourceID  string

	mu       sync.Mutex
	sequence uint64
	closed   bool
}

func New(config Config) (*Publisher, error) {
	if config.Client == nil || config.Pool == nil || config.MachineID == "" || len(config.Classes) == 0 {
		return nil, errors.New("invalid local observation publisher configuration")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Heartbeat == 0 {
		config.Heartbeat = 5 * time.Second
	}
	if config.Lifetime == 0 {
		config.Lifetime = 15 * time.Second
	}
	if config.Heartbeat < 100*time.Millisecond || config.Lifetime <= config.Heartbeat || config.Lifetime > 30*time.Second {
		return nil, errors.New("invalid local observation publisher configuration")
	}
	seen := map[peerquic.Class]bool{}
	for _, class := range config.Classes {
		if seen[class] {
			return nil, errors.New("invalid local observation publisher configuration")
		}
		seen[class] = true
	}
	var source [12]byte
	if _, err := rand.Read(source[:]); err != nil {
		return nil, err
	}
	return &Publisher{client: config.Client, pool: config.Pool, machineID: config.MachineID, classes: append([]peerquic.Class(nil), config.Classes...), clock: config.Clock, heartbeat: config.Heartbeat, lifetime: config.Lifetime, network: config.Network, sourceID: "source_" + hex.EncodeToString(source[:])}, nil
}

func (p *Publisher) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("invalid local observation publisher context")
	}
	if err := p.publish(ctx, false); terminalPublishError(err) {
		return err
	}
	ticker := time.NewTicker(p.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.pool.Changes():
			if err := p.publish(ctx, false); terminalPublishError(err) {
				return err
			}
		case <-ticker.C:
			if err := p.publish(ctx, false); terminalPublishError(err) {
				return err
			}
		}
	}
}

func terminalPublishError(err error) bool {
	return errors.Is(err, localapi.ErrPermission) || errors.Is(err, localapi.ErrVersionMismatch) || errors.Is(err, localapi.ErrInvalidConfig) || errors.Is(err, localapi.ErrInvalidResponse) || errors.Is(err, localapi.ErrStaleObservation)
}

func (p *Publisher) Close(ctx context.Context) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	return p.publish(ctx, true)
}

func (p *Publisher) publish(ctx context.Context, clear bool) error {
	p.mu.Lock()
	if p.sequence == ^uint64(0) {
		p.mu.Unlock()
		return errors.New("local observation sequence exhausted")
	}
	p.sequence++
	sequence := p.sequence
	p.mu.Unlock()

	consumers := uint64(0)
	path := connectionmanager.Path(0)
	standbyPath := connectionmanager.Path(0)
	relayRegion := ""
	if !clear {
		for _, class := range p.classes {
			snapshot, err := p.pool.Snapshot(class)
			if err != nil {
				return err
			}
			consumers += snapshot.Leases
			if snapshot.ActivePath != 0 {
				path = snapshot.ActivePath
				standbyPath = snapshot.StandbyPath
				relayRegion = snapshot.ActiveRelayRegion
			} else if path == 0 && snapshot.Selected {
				path = snapshot.Path
				relayRegion = snapshot.RelayRegion
			}
		}
	}
	selected := observationPath(path)
	if path == 0 {
		selected = "none"
		relayRegion = ""
	}
	standby := observationPath(standbyPath)
	natIPv4, natIPv6, captivePortal, pmtu, routerProtocol, routerMapping, mappingLifetime := "unknown", "unknown", "unknown", "unknown", "unknown", "unknown", "unknown"
	if !clear && p.network != nil {
		observation := p.network()
		if observation.Validate() == nil {
			natIPv4, natIPv6, captivePortal, pmtu, routerProtocol, routerMapping, mappingLifetime = observation.IPv4, observation.IPv6, observation.CaptivePortal, observation.PMTU, observation.RouterProtocol, observation.RouterMapping, observation.MappingLifetime
		}
	}
	now := p.clock().UTC()
	observation := localapi.TransportObservation{Schema: localapi.ObservationSchemaV1, SourceID: p.sourceID, Sequence: sequence, ObservedAt: now, ExpiresAt: now.Add(p.lifetime), MachineID: p.machineID, ActiveConsumers: consumers, SelectedPath: selected, StandbyPath: standby, RelayRegion: relayRegion, NATMappingIPv4: natIPv4, NATMappingIPv6: natIPv6, CaptivePortal: captivePortal, PMTU: pmtu, RouterProtocol: routerProtocol, RouterMapping: routerMapping, MappingLifetime: mappingLifetime}
	return p.client.PublishTransportObservation(ctx, observation)
}

func observationPath(path connectionmanager.Path) string {
	switch path {
	case connectionmanager.PathDirectQUIC:
		return "direct"
	case connectionmanager.PathRelayQUIC:
		return "relay"
	case connectionmanager.PathWSS:
		return "wss"
	default:
		return "none"
	}
}
