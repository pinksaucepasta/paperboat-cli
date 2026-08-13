// Package relayselection owns two-ended relay-region scoring and switch hysteresis.
package relayselection

import (
	"errors"
	"sort"
	"sync"
	"time"
)

const MaximumRegions = 32

var ErrInvalid = errors.New("invalid relay-region selection input")

type Config struct {
	MinimumGain        time.Duration
	MinimumGainPercent uint8
	RequiredSamples    uint8
	MinimumSpacing     time.Duration
	RequiredSpan       time.Duration
	MaximumVectorAge   time.Duration
}

func DevelopmentConfig() Config {
	return Config{
		MinimumGain:        10 * time.Millisecond,
		MinimumGainPercent: 15,
		RequiredSamples:    3,
		MinimumSpacing:     3 * time.Second,
		RequiredSpan:       10 * time.Second,
		MaximumVectorAge:   5 * time.Minute,
	}
}

func (c Config) validate() bool {
	return c.MinimumGain > 0 && c.MinimumGain <= time.Second && c.MinimumGainPercent > 0 && c.MinimumGainPercent < 100 && c.RequiredSamples >= 2 && c.RequiredSamples <= 16 && c.MinimumSpacing > 0 && c.RequiredSpan >= time.Duration(c.RequiredSamples-1)*c.MinimumSpacing && c.MaximumVectorAge >= c.RequiredSpan && c.MaximumVectorAge <= time.Hour
}

type RegionSample struct {
	Region string
	RTT    time.Duration
}

type Vector struct {
	Samples []RegionSample
}

type VectorSet struct {
	Generation uint64
	ObservedAt time.Time
	Client     Vector
	Host       Vector
}

type RegionState struct {
	Healthy  bool
	Capacity bool
}

type Decision struct {
	Region   string
	Combined time.Duration
	Switched bool
}

type Selector struct {
	mu         sync.Mutex
	config     Config
	current    string
	generation uint64
	candidate  string
	first      time.Time
	last       time.Time
	count      uint8
}

func New(config Config) (*Selector, error) {
	if !config.validate() {
		return nil, ErrInvalid
	}
	return &Selector{config: config}, nil
}

func (s *Selector) Select(now time.Time, set VectorSet, states map[string]RegionState) (Decision, error) {
	if s == nil || now.IsZero() || set.Generation == 0 || set.ObservedAt.IsZero() || set.ObservedAt.After(now) || now.Sub(set.ObservedAt) > s.config.MaximumVectorAge || len(states) == 0 || len(states) > MaximumRegions {
		return Decision{}, ErrInvalid
	}
	scores, err := combinedScores(set.Client, set.Host, states)
	if err != nil || len(scores) == 0 {
		return Decision{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if set.Generation <= s.generation {
		return Decision{}, ErrInvalid
	}
	s.generation = set.Generation
	best := scores[0]
	currentScore, currentEligible := scoreFor(scores, s.current)
	if s.current == "" || !currentEligible {
		previous := s.current
		s.current = best.Region
		s.resetCandidate()
		return Decision{Region: best.Region, Combined: best.Combined, Switched: previous != "" && previous != best.Region}, nil
	}
	if best.Region == s.current || !qualifies(currentScore.Combined, best.Combined, s.config) {
		s.resetCandidate()
		return Decision{Region: s.current, Combined: currentScore.Combined}, nil
	}
	if s.candidate != best.Region || s.last.IsZero() || set.ObservedAt.Sub(s.last) < s.config.MinimumSpacing {
		if s.candidate != best.Region {
			s.candidate = best.Region
			s.first = set.ObservedAt
			s.last = set.ObservedAt
			s.count = 1
		}
		return Decision{Region: s.current, Combined: currentScore.Combined}, nil
	}
	s.last = set.ObservedAt
	if s.count < ^uint8(0) {
		s.count++
	}
	if s.count < s.config.RequiredSamples || s.last.Sub(s.first) < s.config.RequiredSpan {
		return Decision{Region: s.current, Combined: currentScore.Combined}, nil
	}
	s.current = best.Region
	s.resetCandidate()
	return Decision{Region: best.Region, Combined: best.Combined, Switched: true}, nil
}

type score struct {
	Region   string
	Combined time.Duration
}

func combinedScores(client, host Vector, states map[string]RegionState) ([]score, error) {
	clientRTT, err := validateVector(client)
	if err != nil {
		return nil, err
	}
	hostRTT, err := validateVector(host)
	if err != nil {
		return nil, err
	}
	result := make([]score, 0, min(len(clientRTT), len(hostRTT)))
	for region, left := range clientRTT {
		right, ok := hostRTT[region]
		state := states[region]
		if !ok || !state.Healthy || !state.Capacity || left > time.Duration(1<<63-1)-right {
			continue
		}
		result = append(result, score{Region: region, Combined: left + right})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Combined == result[j].Combined {
			return result[i].Region < result[j].Region
		}
		return result[i].Combined < result[j].Combined
	})
	return result, nil
}

func validateVector(vector Vector) (map[string]time.Duration, error) {
	if len(vector.Samples) == 0 || len(vector.Samples) > MaximumRegions {
		return nil, ErrInvalid
	}
	result := make(map[string]time.Duration, len(vector.Samples))
	for _, sample := range vector.Samples {
		if !validRegion(sample.Region) || sample.RTT <= 0 || sample.RTT > time.Minute {
			return nil, ErrInvalid
		}
		if _, exists := result[sample.Region]; exists {
			return nil, ErrInvalid
		}
		result[sample.Region] = sample.RTT
	}
	return result, nil
}

func validRegion(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '.' || character == ':' || character == '-') {
			return false
		}
	}
	return true
}

func scoreFor(scores []score, region string) (score, bool) {
	for _, value := range scores {
		if value.Region == region {
			return value, true
		}
	}
	return score{}, false
}

func qualifies(current, candidate time.Duration, config Config) bool {
	if candidate >= current || current-candidate < config.MinimumGain {
		return false
	}
	return uint64(current-candidate)*100 >= uint64(current)*uint64(config.MinimumGainPercent)
}

func (s *Selector) resetCandidate() {
	s.candidate = ""
	s.first = time.Time{}
	s.last = time.Time{}
	s.count = 0
}
