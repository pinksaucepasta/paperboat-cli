package networkadaptation

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

type PMTUProbeResult struct {
	Supported bool
	At        time.Time
}

// PMTUProber sends one authenticated, non-fragmenting padded probe of the
// requested UDP payload size on the selected path.
type PMTUProber interface {
	ProbePayload(context.Context, uint16) (PMTUProbeResult, error)
}

type PMTUPolicy struct {
	MinimumPayload   uint16
	MaximumPayload   uint16
	SuccessesPerSize int
	ProbeTimeout     time.Duration
	TotalTimeout     time.Duration
	CacheTTL         time.Duration
	MaximumPaths     int
}

func DevelopmentPMTUPolicy() PMTUPolicy {
	return PMTUPolicy{
		MinimumPayload: 1200, MaximumPayload: 1452, SuccessesPerSize: 3,
		ProbeTimeout: time.Second, TotalTimeout: 30 * time.Second,
		CacheTTL: 5 * time.Minute, MaximumPaths: 256,
	}
}

func (p PMTUPolicy) validate() error {
	if p.MinimumPayload < 1200 || p.MaximumPayload < p.MinimumPayload || p.SuccessesPerSize < 3 || p.SuccessesPerSize > 16 || p.ProbeTimeout <= 0 || p.TotalTimeout <= 0 || p.CacheTTL <= 0 || p.MaximumPaths < 1 || p.MaximumPaths > 4096 {
		return ErrInvalid
	}
	rounds := 1
	for width := int(p.MaximumPayload - p.MinimumPayload); width > 0; width /= 2 {
		rounds++
	}
	maximumAttempts := rounds * p.SuccessesPerSize
	if time.Duration(maximumAttempts) > time.Duration(1<<63-1)/p.ProbeTimeout || time.Duration(maximumAttempts)*p.ProbeTimeout > p.TotalTimeout {
		return ErrInvalid
	}
	return nil
}

type PMTUMeasurement struct {
	Complete   bool
	Eligible   bool
	PacketSize uint16
	Attempts   int
	ObservedAt time.Time
}

type PMTUMeasurer struct {
	policy PMTUPolicy
	prober PMTUProber
}

func NewPMTUMeasurer(policy PMTUPolicy, prober PMTUProber) (*PMTUMeasurer, error) {
	if err := policy.validate(); err != nil || prober == nil {
		return nil, ErrInvalid
	}
	return &PMTUMeasurer{policy: policy, prober: prober}, nil
}

func (m *PMTUMeasurer) Measure(ctx context.Context) (PMTUMeasurement, error) {
	if m == nil || m.prober == nil || ctx == nil {
		return PMTUMeasurement{}, ErrInvalid
	}
	measurementCtx, cancel := context.WithTimeout(ctx, m.policy.TotalTimeout)
	defer cancel()
	measurement := PMTUMeasurement{}
	var previous time.Time
	probe := func(size uint16) (bool, error) {
		for range m.policy.SuccessesPerSize {
			attemptCtx, attemptCancel := context.WithTimeout(measurementCtx, m.policy.ProbeTimeout)
			result, err := m.prober.ProbePayload(attemptCtx, size)
			attemptCancel()
			measurement.Attempts++
			if err != nil {
				return false, err
			}
			if err := measurementCtx.Err(); err != nil {
				return false, err
			}
			if result.At.IsZero() || !previous.IsZero() && !result.At.After(previous) {
				return false, ErrInvalid
			}
			previous, measurement.ObservedAt = result.At, result.At
			if !result.Supported {
				return false, nil
			}
		}
		return true, nil
	}
	supported, err := probe(m.policy.MinimumPayload)
	if err != nil {
		return measurement, err
	}
	if !supported {
		measurement.Complete = true
		return measurement, nil
	}
	measurement.Eligible = true
	measurement.PacketSize = m.policy.MinimumPayload
	low, high := uint32(m.policy.MinimumPayload)+1, uint32(m.policy.MaximumPayload)
	for low <= high {
		candidate := uint16(low + (high-low)/2)
		supported, err := probe(candidate)
		if err != nil {
			return measurement, err
		}
		if supported {
			measurement.PacketSize = candidate
			low = uint32(candidate) + 1
		} else {
			high = uint32(candidate) - 1
		}
	}
	measurement.Complete = true
	return measurement, nil
}

type PMTUKey struct {
	Fingerprint       Fingerprint
	PathID            string
	NetworkGeneration uint64
}

func (k PMTUKey) valid() bool {
	return k.Fingerprint.valid() && k.PathID != "" && len(k.PathID) <= 256 && k.NetworkGeneration > 0
}

func (k PMTUKey) Valid() bool { return k.valid() }

type PMTUObservation struct {
	Eligible   bool
	PacketSize uint16
	ObservedAt time.Time
	ExpiresAt  time.Time
}

type pmtuEntry struct {
	observation PMTUObservation
	lastUsed    time.Time
}

type PMTUCache struct {
	policy PMTUPolicy
	mu     sync.Mutex
	items  map[PMTUKey]pmtuEntry
}

func NewPMTUCache(policy PMTUPolicy) (*PMTUCache, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	return &PMTUCache{policy: policy, items: make(map[PMTUKey]pmtuEntry)}, nil
}

func (c *PMTUCache) Record(key PMTUKey, measurement PMTUMeasurement) error {
	return c.RecordTTL(key, measurement, c.policy.CacheTTL)
}

func (c *PMTUCache) RecordTTL(key PMTUKey, measurement PMTUMeasurement, ttl time.Duration) error {
	if c == nil || !key.valid() || ttl <= 0 || ttl > 2*c.policy.CacheTTL || !measurement.Complete || measurement.ObservedAt.IsZero() || measurement.Attempts < 1 || measurement.Eligible && (measurement.PacketSize < c.policy.MinimumPayload || measurement.PacketSize > c.policy.MaximumPayload) || !measurement.Eligible && measurement.PacketSize != 0 {
		return ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.items[key]; ok && !measurement.ObservedAt.After(existing.observation.ObservedAt) {
		return errors.New("stale PMTU observation")
	}
	if _, exists := c.items[key]; !exists && len(c.items) >= c.policy.MaximumPaths {
		var oldest PMTUKey
		var oldestAt time.Time
		found := false
		for candidate, entry := range c.items {
			if !found || entry.lastUsed.Before(oldestAt) {
				oldest, oldestAt = candidate, entry.lastUsed
				found = true
			}
		}
		delete(c.items, oldest)
	}
	observation := PMTUObservation{Eligible: measurement.Eligible, PacketSize: measurement.PacketSize, ObservedAt: measurement.ObservedAt, ExpiresAt: measurement.ObservedAt.Add(ttl)}
	c.items[key] = pmtuEntry{observation: observation, lastUsed: measurement.ObservedAt}
	return nil
}

func (c *PMTUCache) Lookup(key PMTUKey, now time.Time) (PMTUObservation, bool) {
	if c == nil || !key.valid() || now.IsZero() {
		return PMTUObservation{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.items[key]
	if !ok {
		return PMTUObservation{}, false
	}
	if !now.Before(entry.observation.ExpiresAt) {
		delete(c.items, key)
		return PMTUObservation{}, false
	}
	entry.lastUsed = now
	c.items[key] = entry
	return entry.observation, true
}

func (c *PMTUCache) Invalidate() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	count := len(c.items)
	c.items = make(map[PMTUKey]pmtuEntry)
	c.mu.Unlock()
	return count
}

func ApplyPMTU(config peerquic.SessionConfig, observation PMTUObservation, now time.Time) (peerquic.SessionConfig, error) {
	if !observation.Eligible || observation.PacketSize < 1200 || observation.ObservedAt.IsZero() || now.IsZero() || !now.Before(observation.ExpiresAt) || !observation.ExpiresAt.After(observation.ObservedAt) {
		return peerquic.SessionConfig{}, ErrInvalid
	}
	return config.WithInitialPacketSize(observation.PacketSize)
}
