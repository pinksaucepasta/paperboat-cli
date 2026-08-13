package networkadaptation

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

type PMTUMeasureFunc func(context.Context) (PMTUMeasurement, error)

type AsyncPMTUConfig struct {
	Policy  PMTUPolicy
	Cache   *PMTUCache
	Now     func() time.Time
	Jitter  func(time.Duration) time.Duration
	Observe func(error)
}

type AsyncPMTU struct {
	config   AsyncPMTUConfig
	mu       sync.Mutex
	inFlight map[PMTUKey]struct{}
}

func NewAsyncPMTU(config AsyncPMTUConfig) (*AsyncPMTU, error) {
	if err := config.Policy.validate(); err != nil || config.Cache == nil {
		return nil, ErrInvalid
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.Jitter == nil {
		config.Jitter = jitterPMTUTTL
	}
	return &AsyncPMTU{config: config, inFlight: make(map[PMTUKey]struct{})}, nil
}

// PacketSize never waits for discovery. It returns a usable cached value or
// QUIC's safe minimum and schedules one bounded refresh for the key.
func (a *AsyncPMTU) PacketSize(lifetime context.Context, key PMTUKey, measure PMTUMeasureFunc) uint16 {
	if a == nil || lifetime == nil || !key.valid() || measure == nil {
		return 1200
	}
	now := a.config.Now().UTC()
	observation, ok := a.config.Cache.Lookup(key, now)
	refresh := !ok || observation.ExpiresAt.Sub(now) <= a.config.Policy.CacheTTL/5
	if refresh {
		a.refresh(lifetime, key, measure)
	}
	if ok && observation.Eligible && observation.PacketSize >= a.config.Policy.MinimumPayload {
		return observation.PacketSize
	}
	return a.config.Policy.MinimumPayload
}

func (a *AsyncPMTU) Invalidate() int {
	if a == nil {
		return 0
	}
	return a.config.Cache.Invalidate()
}

func (a *AsyncPMTU) refresh(lifetime context.Context, key PMTUKey, measure PMTUMeasureFunc) {
	a.mu.Lock()
	if _, exists := a.inFlight[key]; exists {
		a.mu.Unlock()
		return
	}
	a.inFlight[key] = struct{}{}
	a.mu.Unlock()
	go func() {
		defer func() {
			a.mu.Lock()
			delete(a.inFlight, key)
			a.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(lifetime, a.config.Policy.TotalTimeout)
		measurement, err := measure(ctx)
		cancel()
		if err == nil {
			ttl := a.config.Jitter(a.config.Policy.CacheTTL)
			if ttl <= 0 || ttl > 2*a.config.Policy.CacheTTL {
				err = ErrInvalid
			} else {
				err = a.config.Cache.RecordTTL(key, measurement, ttl)
			}
		}
		if err != nil && !errors.Is(err, context.Canceled) && a.config.Observe != nil {
			a.config.Observe(err)
		}
	}()
}

func jitterPMTUTTL(ttl time.Duration) time.Duration {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return ttl
	}
	// Uniformly vary expiry from 80% through 120% to avoid synchronized probes.
	parts := int64(binary.BigEndian.Uint64(value[:]) % 401)
	return time.Duration(int64(ttl) * (800 + parts) / 1000)
}
