package connectionmanager

import (
	"errors"
	"sort"
	"sync"
	"time"
)

type QualityPolicy struct {
	SampleRetention       time.Duration
	LossWindow            time.Duration
	MinimumSampleInterval time.Duration
	MinimumSampleSpan     time.Duration
	PreferenceTTL         time.Duration
	MinimumSamples        int
	MaximumSamples        int
	MaximumEntries        int
	SuspectLossPercent    float64
	SuspectPTOs           uint32
	RelayMinimumGain      time.Duration
	RelayMinimumPercent   float64
	DirectMinimumGain     time.Duration
	DirectMinimumPercent  float64
}

func DevelopmentQualityPolicy() QualityPolicy {
	return QualityPolicy{
		SampleRetention: 5 * time.Minute, LossWindow: 30 * time.Second,
		MinimumSampleInterval: 3 * time.Second, MinimumSampleSpan: 10 * time.Second,
		PreferenceTTL: 5 * time.Minute, MinimumSamples: 3, MaximumSamples: 64, MaximumEntries: 256,
		SuspectLossPercent: 5, SuspectPTOs: 2,
		RelayMinimumGain: 20 * time.Millisecond, RelayMinimumPercent: 20,
		DirectMinimumGain: 10 * time.Millisecond, DirectMinimumPercent: 10,
	}
}

func (p QualityPolicy) validate() error {
	if p.SampleRetention <= 0 || p.LossWindow <= 0 || p.LossWindow > p.SampleRetention || p.MinimumSampleInterval <= 0 || p.MinimumSampleSpan < p.MinimumSampleInterval || p.PreferenceTTL <= 0 || p.MinimumSamples < 3 || p.MaximumSamples < p.MinimumSamples || p.MaximumSamples > 1024 || p.MaximumEntries < 1 || p.MaximumEntries > 4096 || p.SuspectLossPercent <= 0 || p.SuspectLossPercent >= 100 || p.SuspectPTOs == 0 || p.RelayMinimumGain <= 0 || p.DirectMinimumGain <= 0 || p.RelayMinimumPercent <= 0 || p.RelayMinimumPercent >= 100 || p.DirectMinimumPercent <= 0 || p.DirectMinimumPercent >= 100 {
		return errors.New("invalid peer path quality policy")
	}
	return nil
}

type QualityKey struct {
	NetworkFingerprint      [32]byte
	MachineID               string
	HostNetworkGeneration   uint64
	HostProcessGeneration   uint64
	AuthorizationGeneration uint64
}

func (k QualityKey) valid() bool {
	return !zero32(k.NetworkFingerprint) && k.MachineID != "" && len(k.MachineID) <= 128 && k.HostNetworkGeneration > 0 && k.HostProcessGeneration > 0 && k.AuthorizationGeneration > 0
}

type QualityObservation struct {
	Path       Path
	At         time.Time
	Completion time.Duration
	Succeeded  bool
	PTOs       uint32
}

type QualitySnapshot struct {
	Path        Path
	P95         time.Duration
	Samples     int
	Span        time.Duration
	LossPercent float64
	PTOs        uint32
	Suspect     bool
	Qualified   bool
}

type Preference struct {
	Path      Path
	ExpiresAt time.Time
}

type RelaySelectionCause uint8

const (
	RelaySelectedForReachability RelaySelectionCause = iota + 1
	RelaySelectedForQuality
)

type qualityEntry struct {
	direct     []QualityObservation
	relay      []QualityObservation
	preference Preference
	lastUsed   time.Time
}

type QualityCache struct {
	policy QualityPolicy
	mu     sync.Mutex
	items  map[QualityKey]*qualityEntry
}

func NewQualityCache(policy QualityPolicy) (*QualityCache, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	return &QualityCache{policy: policy, items: make(map[QualityKey]*qualityEntry)}, nil
}

// Invalidate removes observations and preferences bound to the previous local
// network. Callers retain no raw network fingerprint material after a rebind.
func (c *QualityCache) Invalidate() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	count := len(c.items)
	c.items = make(map[QualityKey]*qualityEntry)
	c.mu.Unlock()
	return count
}

func (c *QualityCache) Record(key QualityKey, observation QualityObservation) error {
	if c == nil || !key.valid() || observation.Path != PathDirectQUIC && observation.Path != PathRelayQUIC || observation.At.IsZero() || observation.Completion <= 0 {
		return errors.New("invalid peer path quality observation")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entryLocked(key, observation.At)
	target := &entry.direct
	if observation.Path == PathRelayQUIC {
		target = &entry.relay
	}
	duplicate := sort.Search(len(*target), func(index int) bool { return !(*target)[index].At.Before(observation.At) })
	if duplicate < len(*target) && (*target)[duplicate].At.Equal(observation.At) {
		return errors.New("duplicate peer path quality observation")
	}
	*target = append(*target, observation)
	sort.Slice(*target, func(i, j int) bool { return (*target)[i].At.Before((*target)[j].At) })
	if excess := len(*target) - c.policy.MaximumSamples; excess > 0 {
		copy(*target, (*target)[excess:])
		*target = (*target)[:c.policy.MaximumSamples]
	}
	return nil
}

func (c *QualityCache) Select(key QualityKey, now time.Time) (Preference, QualitySnapshot, QualitySnapshot, error) {
	if c == nil || !key.valid() || now.IsZero() {
		return Preference{}, QualitySnapshot{}, QualitySnapshot{}, errors.New("invalid peer path quality selection")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entryLocked(key, now)
	entry.direct = retain(entry.direct, now.Add(-c.policy.SampleRetention))
	entry.relay = retain(entry.relay, now.Add(-c.policy.SampleRetention))
	direct := c.snapshot(PathDirectQUIC, entry.direct, now)
	relay := c.snapshot(PathRelayQUIC, entry.relay, now)
	if entry.preference.Path == PathRelayQUIC && !now.Before(entry.preference.ExpiresAt) {
		entry.preference = Preference{}
	}
	if entry.preference.Path == PathRelayQUIC {
		if relay.Suspect && direct.Qualified || wins(direct.P95, relay.P95, c.policy.DirectMinimumGain, c.policy.DirectMinimumPercent) && direct.Qualified && !direct.Suspect {
			entry.preference = Preference{}
			return Preference{Path: PathDirectQUIC}, direct, relay, nil
		}
		return entry.preference, direct, relay, nil
	}
	if direct.Qualified && relay.Qualified && !relay.Suspect && wins(relay.P95, direct.P95, c.policy.RelayMinimumGain, c.policy.RelayMinimumPercent) {
		entry.preference = Preference{Path: PathRelayQUIC, ExpiresAt: now.Add(c.policy.PreferenceTTL)}
		return entry.preference, direct, relay, nil
	}
	return Preference{Path: PathDirectQUIC}, direct, relay, nil
}

func (c *QualityCache) NetworkClass(key QualityKey, now time.Time) (NetworkClass, error) {
	preference, _, _, err := c.Select(key, now)
	if err != nil {
		return 0, err
	}
	if preference.Path == PathRelayQUIC {
		return NetworkRelayPreferred, nil
	}
	return NetworkUnknown, nil
}

func (c *QualityCache) DirectRecoveryEligible(key QualityKey, cause RelaySelectionCause, now time.Time) (bool, QualitySnapshot, QualitySnapshot, error) {
	if cause != RelaySelectedForReachability && cause != RelaySelectedForQuality {
		return false, QualitySnapshot{}, QualitySnapshot{}, errors.New("invalid relay selection cause")
	}
	preference, direct, relay, err := c.Select(key, now)
	if err != nil {
		return false, QualitySnapshot{}, QualitySnapshot{}, err
	}
	if cause == RelaySelectedForReachability {
		return preference.Path != PathRelayQUIC, direct, relay, nil
	}
	eligible := direct.Qualified && relay.Qualified && !direct.Suspect && wins(direct.P95, relay.P95, c.policy.DirectMinimumGain, c.policy.DirectMinimumPercent)
	return eligible, direct, relay, nil
}

func (c *QualityCache) snapshot(path Path, observations []QualityObservation, now time.Time) QualitySnapshot {
	result := QualitySnapshot{Path: path}
	lossStart := now.Add(-c.policy.LossWindow)
	var lossTotal, lossFailures int
	for _, observation := range observations {
		if !observation.At.Before(lossStart) && !observation.At.After(now) {
			lossTotal++
			result.PTOs += observation.PTOs
			if !observation.Succeeded {
				lossFailures++
			}
		}
	}
	if lossTotal > 0 {
		result.LossPercent = float64(lossFailures) * 100 / float64(lossTotal)
	}
	result.Suspect = result.LossPercent > c.policy.SuspectLossPercent || result.PTOs >= c.policy.SuspectPTOs
	independent := make([]QualityObservation, 0, len(observations))
	for _, observation := range observations {
		if !observation.Succeeded || observation.At.After(now) {
			continue
		}
		if len(independent) == 0 || observation.At.Sub(independent[len(independent)-1].At) >= c.policy.MinimumSampleInterval {
			independent = append(independent, observation)
		}
	}
	result.Samples = len(independent)
	if len(independent) > 1 {
		result.Span = independent[len(independent)-1].At.Sub(independent[0].At)
	}
	if result.Samples < c.policy.MinimumSamples || result.Span < c.policy.MinimumSampleSpan {
		return result
	}
	durations := make([]time.Duration, len(independent))
	for index := range independent {
		durations[index] = independent[index].Completion
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	index := (95*len(durations)+99)/100 - 1
	result.P95 = durations[index]
	result.Qualified = true
	return result
}

func (c *QualityCache) entryLocked(key QualityKey, now time.Time) *qualityEntry {
	entry := c.items[key]
	if entry == nil {
		if len(c.items) >= c.policy.MaximumEntries {
			var oldestKey QualityKey
			var oldest time.Time
			for candidateKey, candidate := range c.items {
				if oldest.IsZero() || candidate.lastUsed.Before(oldest) {
					oldestKey, oldest = candidateKey, candidate.lastUsed
				}
			}
			delete(c.items, oldestKey)
		}
		entry = &qualityEntry{}
		c.items[key] = entry
	}
	if now.After(entry.lastUsed) {
		entry.lastUsed = now
	}
	return entry
}

func retain(values []QualityObservation, cutoff time.Time) []QualityObservation {
	index := sort.Search(len(values), func(index int) bool { return !values[index].At.Before(cutoff) })
	return append([]QualityObservation(nil), values[index:]...)
}

func wins(candidate, current, minimum time.Duration, percent float64) bool {
	if candidate <= 0 || current <= candidate || current-candidate < minimum {
		return false
	}
	return float64(current-candidate)*100/float64(current) >= percent
}

func zero32(value [32]byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
