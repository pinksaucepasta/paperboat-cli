package networkcheck

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/relayselection"
)

const (
	maximumRegionalSamples = 3
	regionalSampleTTL      = 5 * time.Minute
)

type regionalSample struct {
	rtt        time.Duration
	observedAt time.Time
}

// RegionalCache retains only bounded RTTs keyed by public region ID. It never
// stores resolved, local, mapped, or candidate addresses.
type RegionalCache struct {
	mu      sync.Mutex
	samples map[string][]regionalSample
}

func NewRegionalCache() *RegionalCache {
	return &RegionalCache{samples: make(map[string][]regionalSample)}
}

func (c *RegionalCache) Record(region string, rtt time.Duration, observedAt time.Time) error {
	if c == nil || !validRegionalID(region) || rtt <= 0 || rtt > time.Minute || observedAt.IsZero() {
		return errors.New("invalid regional latency sample")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(observedAt)
	values := c.samples[region]
	if count := len(values); count > 0 && !observedAt.After(values[count-1].observedAt) {
		return errors.New("regional latency sample is stale")
	}
	values = append(values, regionalSample{rtt: rtt, observedAt: observedAt.UTC()})
	if len(values) > maximumRegionalSamples {
		values = values[len(values)-maximumRegionalSamples:]
	}
	c.samples[region] = values
	return nil
}

func (c *RegionalCache) Vector(now time.Time) relayselection.Vector {
	if c == nil || now.IsZero() {
		return relayselection.Vector{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	regions := make([]string, 0, len(c.samples))
	for region := range c.samples {
		regions = append(regions, region)
	}
	sort.Strings(regions)
	if len(regions) > relayselection.MaximumRegions {
		regions = regions[:relayselection.MaximumRegions]
	}
	result := relayselection.Vector{Samples: make([]relayselection.RegionSample, 0, len(regions))}
	for _, region := range regions {
		values := c.samples[region]
		rtts := make([]time.Duration, len(values))
		for index, value := range values {
			rtts[index] = value.rtt
		}
		sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
		median := rtts[len(rtts)/2]
		if len(rtts)%2 == 0 {
			median = rtts[0] + (rtts[1]-rtts[0])/2
		}
		result.Samples = append(result.Samples, relayselection.RegionSample{Region: region, RTT: median})
	}
	return result
}

func (c *RegionalCache) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.samples = make(map[string][]regionalSample)
	c.mu.Unlock()
}

func (c *RegionalCache) expireLocked(now time.Time) {
	cutoff := now.UTC().Add(-regionalSampleTTL)
	for region, values := range c.samples {
		first := 0
		for first < len(values) && values[first].observedAt.Before(cutoff) {
			first++
		}
		if first == len(values) {
			delete(c.samples, region)
		} else if first > 0 {
			c.samples[region] = append([]regionalSample(nil), values[first:]...)
		}
	}
}

func validRegionalID(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return value[0] != '-' && value[len(value)-1] != '-'
}
