package networkcheck

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

const maximumConcurrentRegionalProbes = 4

type RegionalInventory func(context.Context) ([]ProbeRegion, error)

type RegionalMonitorConfig struct {
	Inventory           RegionalInventory
	Probe               *RegionalProbe
	Cache               *RegionalCache
	Clock               func() time.Time
	CurrentRegion       func() string
	FullInterval        time.Duration
	IncrementalInterval time.Duration
	Jitter              func(time.Duration) time.Duration
}

type RegionalMonitor struct {
	config  RegionalMonitorConfig
	changed chan struct{}
}

func NewRegionalMonitor(config RegionalMonitorConfig) (*RegionalMonitor, error) {
	if config.Inventory == nil || config.Probe == nil || config.Cache == nil || config.Clock == nil || config.CurrentRegion == nil || config.FullInterval < time.Minute || config.FullInterval > 15*time.Minute || config.IncrementalInterval <= 0 || config.IncrementalInterval >= config.FullInterval || config.Jitter == nil {
		return nil, errors.New("invalid regional monitor configuration")
	}
	return &RegionalMonitor{config: config, changed: make(chan struct{}, 1)}, nil
}

func (m *RegionalMonitor) NetworkChanged() {
	if m == nil {
		return
	}
	m.config.Cache.Invalidate()
	select {
	case m.changed <- struct{}{}:
	default:
	}
}

func (m *RegionalMonitor) Run(ctx context.Context) error {
	return m.run(ctx, true)
}

// RunAfterInitialScan runs the recurring schedule when the caller has already
// completed the synchronous startup scan required before issuing an attempt.
func (m *RegionalMonitor) RunAfterInitialScan(ctx context.Context) error {
	return m.run(ctx, false)
}

func (m *RegionalMonitor) run(ctx context.Context, initial bool) error {
	if m == nil || ctx == nil {
		return errors.New("invalid regional monitor run")
	}
	if initial {
		_ = m.Scan(ctx, true)
	}
	full := time.NewTimer(m.nextFullInterval())
	incremental := time.NewTicker(m.config.IncrementalInterval)
	defer full.Stop()
	defer incremental.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.changed:
			_ = m.Scan(ctx, true)
			resetTimer(full, m.nextFullInterval())
		case <-full.C:
			_ = m.Scan(ctx, true)
			full.Reset(m.nextFullInterval())
		case <-incremental.C:
			_ = m.Scan(ctx, false)
		}
	}
}

func (m *RegionalMonitor) Scan(ctx context.Context, full bool) error {
	if m == nil || ctx == nil {
		return errors.New("invalid regional scan")
	}
	regions, err := m.config.Inventory(ctx)
	if err != nil {
		return err
	}
	targets := m.targets(regions, full)
	semaphore := make(chan struct{}, maximumConcurrentRegionalProbes)
	var wait sync.WaitGroup
	for _, region := range targets {
		region := region
		wait.Add(1)
		go func() {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}
			rtt, probeErr := m.config.Probe.Probe(ctx, region)
			if probeErr == nil {
				_ = m.config.Cache.Record(region.Region, rtt, m.config.Clock().UTC())
			}
		}()
	}
	wait.Wait()
	return ctx.Err()
}

func (m *RegionalMonitor) targets(inventory []ProbeRegion, full bool) []ProbeRegion {
	byRegion := make(map[string]ProbeRegion, min(len(inventory), 32))
	for _, region := range inventory {
		if len(byRegion) == 32 || !validRegionalID(region.Region) {
			continue
		}
		if _, exists := byRegion[region.Region]; !exists {
			byRegion[region.Region] = region
		}
	}
	regions := make([]string, 0, len(byRegion))
	for region := range byRegion {
		regions = append(regions, region)
	}
	sort.Strings(regions)
	if full {
		return regionsFromIDs(regions, byRegion)
	}
	selected := make([]string, 0, 4)
	current := m.config.CurrentRegion()
	if _, exists := byRegion[current]; exists {
		selected = append(selected, current)
	}
	vector := m.config.Cache.Vector(m.config.Clock().UTC())
	sort.Slice(vector.Samples, func(i, j int) bool {
		if vector.Samples[i].RTT == vector.Samples[j].RTT {
			return vector.Samples[i].Region < vector.Samples[j].Region
		}
		return vector.Samples[i].RTT < vector.Samples[j].RTT
	})
	for _, sample := range vector.Samples {
		if len(selected) >= 4 {
			break
		}
		if sample.Region != current {
			if _, exists := byRegion[sample.Region]; exists {
				selected = append(selected, sample.Region)
			}
		}
	}
	for _, region := range regions {
		if len(selected) >= 4 {
			break
		}
		if !containsRegion(selected, region) {
			selected = append(selected, region)
		}
	}
	return regionsFromIDs(selected, byRegion)
}

func (m *RegionalMonitor) nextFullInterval() time.Duration {
	value := m.config.Jitter(m.config.FullInterval)
	if value < time.Minute || value > 15*time.Minute {
		return m.config.FullInterval
	}
	return value
}

func regionsFromIDs(ids []string, regions map[string]ProbeRegion) []ProbeRegion {
	result := make([]ProbeRegion, 0, len(ids))
	for _, id := range ids {
		result = append(result, regions[id])
	}
	return result
}

func containsRegion(regions []string, target string) bool {
	for _, region := range regions {
		if region == target {
			return true
		}
	}
	return false
}

func resetTimer(timer *time.Timer, duration time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(duration)
}
