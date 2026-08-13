package networkadaptation

import (
	"crypto/rand"
	"encoding/binary"
	"sort"
	"sync"
	"time"
)

type LifetimePolicy struct {
	EvidenceTTL           time.Duration
	DefaultInterval       time.Duration
	MinimumInterval       time.Duration
	MaximumInterval       time.Duration
	SafetyMargin          time.Duration
	MinimumSampleInterval time.Duration
	MinimumEvidence       int
	MaximumSamples        int
	MaximumNetworks       int
	JitterFraction        float64
}

func DevelopmentLifetimePolicy() LifetimePolicy {
	return LifetimePolicy{
		EvidenceTTL: 5 * time.Minute, DefaultInterval: 3 * time.Second,
		MinimumInterval: 3 * time.Second, MaximumInterval: 30 * time.Second,
		SafetyMargin: 500 * time.Millisecond, MinimumSampleInterval: time.Second, MinimumEvidence: 3,
		MaximumSamples: 32, MaximumNetworks: 64, JitterFraction: 0.10,
	}
}

func (p LifetimePolicy) validate() error {
	if p.EvidenceTTL <= 0 || p.DefaultInterval <= 0 || p.MinimumInterval <= 0 || p.MaximumInterval < p.MinimumInterval || p.DefaultInterval < p.MinimumInterval || p.DefaultInterval > p.MaximumInterval || p.SafetyMargin < 0 || p.MinimumSampleInterval <= 0 || p.MinimumSampleInterval >= p.EvidenceTTL || p.MinimumEvidence < 2 || p.MaximumSamples < p.MinimumEvidence || p.MaximumSamples > 1024 || p.MaximumNetworks < 1 || p.MaximumNetworks > 4096 || p.JitterFraction < 0 || p.JitterFraction > 0.25 {
		return ErrInvalid
	}
	return nil
}

type Random interface {
	Uint64() (uint64, error)
}

type cryptoRandom struct{}

func (cryptoRandom) Uint64() (uint64, error) {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(value[:]), nil
}

type lifetimeSample struct {
	at   time.Time
	idle time.Duration
}

type lifetimeEntry struct {
	successes []lifetimeSample
	lastUsed  time.Time
}

type LifetimeCache struct {
	policy LifetimePolicy
	random Random

	mu      sync.Mutex
	entries map[Fingerprint]*lifetimeEntry
}

func NewLifetimeCache(policy LifetimePolicy, random Random) (*LifetimeCache, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	if random == nil {
		random = cryptoRandom{}
	}
	return &LifetimeCache{policy: policy, random: random, entries: make(map[Fingerprint]*lifetimeEntry)}, nil
}

// RecordSuccess records an authenticated probe that remained reachable after idle.
func (c *LifetimeCache) RecordSuccess(fingerprint Fingerprint, idle time.Duration, at time.Time) error {
	if c == nil || !fingerprint.valid() || idle <= 0 || at.IsZero() {
		return ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entryLocked(fingerprint, at)
	entry.successes = append(entry.successes, lifetimeSample{at: at, idle: idle})
	if excess := len(entry.successes) - c.policy.MaximumSamples; excess > 0 {
		entry.successes = append([]lifetimeSample(nil), entry.successes[excess:]...)
	}
	return nil
}

// RecordFailure conservatively discards every lower-bound claim at or above
// an authenticated probe's failed idle duration.
func (c *LifetimeCache) RecordFailure(fingerprint Fingerprint, idle time.Duration, at time.Time) error {
	if c == nil || !fingerprint.valid() || idle <= 0 || at.IsZero() {
		return ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entryLocked(fingerprint, at)
	retained := entry.successes[:0]
	cutoff := at.Add(-c.policy.EvidenceTTL)
	for _, sample := range entry.successes {
		if sample.at.After(at) || !sample.at.Before(cutoff) && sample.idle < idle {
			retained = append(retained, sample)
		}
	}
	entry.successes = retained
	return nil
}

type LifetimeDecision struct {
	Interval   time.Duration
	LowerBound time.Duration
	Evidence   int
	Adapted    bool
}

func (c *LifetimeCache) Keepalive(fingerprint Fingerprint, now time.Time) (LifetimeDecision, error) {
	if c == nil || !fingerprint.valid() || now.IsZero() {
		return LifetimeDecision{}, ErrInvalid
	}
	c.mu.Lock()
	entry := c.entryLocked(fingerprint, now)
	entry.successes = retainLifetime(entry.successes, now.Add(-c.policy.EvidenceTTL))
	samples := append([]lifetimeSample(nil), entry.successes...)
	c.mu.Unlock()
	sort.Slice(samples, func(i, j int) bool { return samples[i].at.Before(samples[j].at) })
	idles := make([]time.Duration, 0, len(samples))
	var last time.Time
	for _, sample := range samples {
		if sample.at.After(now) || !last.IsZero() && sample.at.Sub(last) < c.policy.MinimumSampleInterval {
			continue
		}
		idles = append(idles, sample.idle)
		last = sample.at
	}

	decision := LifetimeDecision{Interval: c.policy.DefaultInterval, Evidence: len(idles)}
	if len(idles) >= c.policy.MinimumEvidence {
		sort.Slice(idles, func(i, j int) bool { return idles[i] > idles[j] })
		decision.LowerBound = idles[c.policy.MinimumEvidence-1]
		candidate := decision.LowerBound/3 - c.policy.SafetyMargin
		if candidate > c.policy.DefaultInterval {
			decision.Interval = min(candidate, c.policy.MaximumInterval)
			decision.Adapted = true
		}
	}
	value, err := c.random.Uint64()
	if err != nil {
		return LifetimeDecision{}, err
	}
	if c.policy.JitterFraction > 0 {
		fraction := float64(value) / float64(^uint64(0))
		jitter := time.Duration(float64(decision.Interval) * c.policy.JitterFraction * fraction)
		decision.Interval -= jitter
		decision.Interval = max(decision.Interval, c.policy.MinimumInterval)
	}
	return decision, nil
}

func (c *LifetimeCache) Invalidate() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	count := len(c.entries)
	c.entries = make(map[Fingerprint]*lifetimeEntry)
	c.mu.Unlock()
	return count
}

func (c *LifetimeCache) entryLocked(fingerprint Fingerprint, now time.Time) *lifetimeEntry {
	if entry := c.entries[fingerprint]; entry != nil {
		entry.lastUsed = now
		return entry
	}
	if len(c.entries) >= c.policy.MaximumNetworks {
		var oldest Fingerprint
		oldestAt := now
		for key, entry := range c.entries {
			if !entry.lastUsed.After(oldestAt) {
				oldest, oldestAt = key, entry.lastUsed
			}
		}
		delete(c.entries, oldest)
	}
	entry := &lifetimeEntry{lastUsed: now}
	c.entries[fingerprint] = entry
	return entry
}

func retainLifetime(samples []lifetimeSample, cutoff time.Time) []lifetimeSample {
	retained := samples[:0]
	for _, sample := range samples {
		if !sample.at.Before(cutoff) {
			retained = append(retained, sample)
		}
	}
	return retained
}
