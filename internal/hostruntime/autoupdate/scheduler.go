package autoupdate

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

var ErrInvalidConfig = errors.New("automatic update scheduler configuration is invalid")

const (
	DefaultInterval   = 6 * time.Hour
	DefaultRetryFloor = 5 * time.Minute
	DefaultRetryLimit = 6 * time.Hour
)

type Result struct {
	Version string
	Updated bool
}

type Check func(context.Context) (Result, error)

type Observation struct {
	CheckedAt   time.Time
	NextCheckAt time.Time
	Version     string
	Updated     bool
	Failure     string
	Failures    uint32
}

type Config struct {
	Check      Check
	Observe    func(Observation)
	Interval   time.Duration
	RetryFloor time.Duration
	RetryLimit time.Duration
	Now        func() time.Time
	Random     func(time.Duration) (time.Duration, error)
}

type Scheduler struct {
	config Config
	mu     sync.Mutex
	state  Observation
}

func New(config Config) (*Scheduler, error) {
	if config.Check == nil {
		return nil, ErrInvalidConfig
	}
	if config.Interval == 0 {
		config.Interval = DefaultInterval
	}
	if config.RetryFloor == 0 {
		config.RetryFloor = DefaultRetryFloor
	}
	if config.RetryLimit == 0 {
		config.RetryLimit = DefaultRetryLimit
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = secureDuration
	}
	if config.Interval < time.Minute || config.RetryFloor <= 0 || config.RetryFloor > config.RetryLimit || config.RetryLimit > config.Interval {
		return nil, ErrInvalidConfig
	}
	return &Scheduler{config: config}, nil
}

func (s *Scheduler) Snapshot() Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Scheduler) Run(ctx context.Context) error {
	for {
		if err := s.runOnce(ctx); err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		next := s.Snapshot().NextCheckAt
		delay := next.Sub(s.config.Now())
		if delay < 0 {
			delay = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *Scheduler) CheckNow(ctx context.Context) (Result, error) {
	err := s.runOnce(ctx)
	state := s.Snapshot()
	return Result{Version: state.Version, Updated: state.Updated}, err
}

func (s *Scheduler) runOnce(ctx context.Context) error {
	checkedAt := s.config.Now().UTC()
	result, err := s.config.Check(ctx)
	s.mu.Lock()
	state := s.state
	state.CheckedAt = checkedAt
	state.Version, state.Updated = result.Version, result.Updated
	if err == nil {
		state.Failure, state.Failures = "", 0
		state.NextCheckAt = checkedAt.Add(s.jitteredInterval())
	} else {
		state.Failures++
		state.Failure = "check_failed"
		state.NextCheckAt = checkedAt.Add(s.retryDelay(state.Failures))
	}
	s.state = state
	s.mu.Unlock()
	if s.config.Observe != nil {
		s.config.Observe(state)
	}
	return err
}

func (s *Scheduler) jitteredInterval() time.Duration {
	half := s.config.Interval / 2
	jitter, err := s.config.Random(s.config.Interval)
	if err != nil || jitter < 0 || jitter >= s.config.Interval {
		return s.config.Interval
	}
	return half + jitter
}

func (s *Scheduler) retryDelay(failures uint32) time.Duration {
	delay := s.config.RetryFloor
	for attempt := uint32(1); attempt < failures && delay < s.config.RetryLimit; attempt++ {
		if delay > s.config.RetryLimit/2 {
			return s.config.RetryLimit
		}
		delay *= 2
	}
	if delay > s.config.RetryLimit {
		return s.config.RetryLimit
	}
	return delay
}

func secureDuration(limit time.Duration) (time.Duration, error) {
	if limit <= 0 {
		return 0, ErrInvalidConfig
	}
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0, err
	}
	return time.Duration(binary.LittleEndian.Uint64(value[:]) % uint64(limit)), nil
}
