package connectionmanager

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

// ProbeTransport is the narrow post-authentication surface required by direct
// recovery. Dialers must complete ICE and endpoint-authenticated QUIC before
// returning it. HealthExchange authenticates the nonce on the probe channel;
// this runner never opens a consumer stream.
type ProbeTransport interface {
	Connection
	HealthExchange(context.Context, [16]byte) (uint32, error)
}

type ProbeDialer interface {
	DialProbe(context.Context, ProbeAttempt) (ProbeTransport, error)
}

type HealthSample struct {
	Attempt   ProbeAttempt
	Exchange  int
	Completed time.Duration
	PTOs      uint32
}

type HealthSampleRecorder interface {
	RecordHealthSample(HealthSample) error
}

type DiscardHealthSamples struct{}

func (DiscardHealthSamples) RecordHealthSample(HealthSample) error { return nil }

type ProbePromotionDecider interface {
	PromoteProbe(ProbeAttempt) (bool, error)
}

type VerifiedProbePromotionDecider struct{}

func (VerifiedProbePromotionDecider) PromoteProbe(attempt ProbeAttempt) (bool, error) {
	if attempt.Generation == 0 || attempt.NetworkGeneration == 0 {
		return false, errors.New("invalid verified probe attempt")
	}
	return true, nil
}

type QualityKeySource interface {
	QualityKey(ProbeAttempt) (QualityKey, error)
}

type QualityHealthRecorder struct {
	cache *QualityCache
	keys  QualityKeySource
	now   func() time.Time
}

type QualityProbePromotionDecider struct {
	cache *QualityCache
	keys  QualityKeySource
	cause RelaySelectionCause
	now   func() time.Time
}

func NewQualityProbePromotionDecider(cache *QualityCache, keys QualityKeySource, cause RelaySelectionCause) (*QualityProbePromotionDecider, error) {
	if cache == nil || keys == nil || cause != RelaySelectedForReachability && cause != RelaySelectedForQuality {
		return nil, errors.New("invalid quality probe promotion policy")
	}
	return &QualityProbePromotionDecider{cache: cache, keys: keys, cause: cause, now: time.Now}, nil
}

func (d *QualityProbePromotionDecider) PromoteProbe(attempt ProbeAttempt) (bool, error) {
	if d == nil || d.cache == nil || d.keys == nil || attempt.Generation == 0 || attempt.NetworkGeneration == 0 {
		return false, errors.New("invalid quality probe promotion decision")
	}
	key, err := d.keys.QualityKey(attempt)
	if err != nil {
		return false, err
	}
	eligible, _, _, err := d.cache.DirectRecoveryEligible(key, d.cause, d.now())
	return eligible, err
}

func NewQualityHealthRecorder(cache *QualityCache, keys QualityKeySource) (*QualityHealthRecorder, error) {
	if cache == nil || keys == nil {
		return nil, errors.New("quality cache and key source are required")
	}
	return &QualityHealthRecorder{cache: cache, keys: keys, now: time.Now}, nil
}

func (r *QualityHealthRecorder) RecordHealthSample(sample HealthSample) error {
	if r == nil || r.cache == nil || r.keys == nil || sample.Attempt.Generation == 0 || sample.Attempt.NetworkGeneration == 0 || sample.Exchange < 1 || sample.Exchange > 3 || sample.Completed <= 0 {
		return errors.New("invalid direct health sample")
	}
	key, err := r.keys.QualityKey(sample.Attempt)
	if err != nil {
		return err
	}
	return r.cache.Record(key, QualityObservation{Path: PathDirectQUIC, At: r.now(), Completion: sample.Completed, Succeeded: true, PTOs: sample.PTOs})
}

type HealthProbePolicy struct {
	Exchanges int
}

func DevelopmentHealthProbePolicy() HealthProbePolicy {
	return HealthProbePolicy{Exchanges: 1}
}

func (p HealthProbePolicy) validate() error {
	if p.Exchanges != 1 {
		return errors.New("recovery requires exactly one authenticated health exchange")
	}
	return nil
}

// AuthenticatedHealthProbe adapts an ICE/QUIC probe dialer to ProbeRunner.
// Each exchange uses an independent nonce. Any failed exchange closes the
// transport; session cancellation and network-generation changes stop it.
type AuthenticatedHealthProbe struct {
	dialer   ProbeDialer
	policy   HealthProbePolicy
	now      func() time.Time
	recorder HealthSampleRecorder
	decider  ProbePromotionDecider
}

func NewAuthenticatedHealthProbe(dialer ProbeDialer, policy HealthProbePolicy, recorder HealthSampleRecorder, decider ProbePromotionDecider) (*AuthenticatedHealthProbe, error) {
	if dialer == nil || recorder == nil || decider == nil {
		return nil, errors.New("probe dialer, health recorder, and promotion decider are required")
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}
	return &AuthenticatedHealthProbe{dialer: dialer, policy: policy, now: time.Now, recorder: recorder, decider: decider}, nil
}

func (p *AuthenticatedHealthProbe) Probe(ctx context.Context, attempt ProbeAttempt) (ProbeResult, error) {
	if p == nil || p.dialer == nil || ctx == nil || attempt.Generation == 0 || attempt.NetworkGeneration == 0 {
		return ProbeResult{}, errors.New("invalid authenticated health probe")
	}
	if err := ctx.Err(); err != nil {
		return ProbeResult{}, err
	}
	transport, err := p.dialer.DialProbe(ctx, attempt)
	if err != nil {
		return ProbeResult{}, err
	}
	if nilConnection(transport) || transport.State() != StateTrusted {
		if !nilConnection(transport) {
			_ = transport.Close()
		}
		return ProbeResult{}, &Failure{Class: FailureProtocol, Path: PathDirectQUIC, Cause: errors.New("probe transport is not trusted")}
	}
	owned := true
	defer func() {
		if owned {
			_ = transport.Close()
		}
	}()
	for exchange := 0; exchange < p.policy.Exchanges; exchange++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return ProbeResult{}, fmt.Errorf("generate health nonce: %w", err)
		}
		exchangeStarted := p.now()
		ptos, err := transport.HealthExchange(ctx, nonce)
		if err != nil {
			return ProbeResult{}, fmt.Errorf("health exchange %d: %w", exchange+1, err)
		}
		if err := p.recorder.RecordHealthSample(HealthSample{Attempt: attempt, Exchange: exchange + 1, Completed: p.now().Sub(exchangeStarted), PTOs: ptos}); err != nil {
			return ProbeResult{}, fmt.Errorf("record health exchange %d: %w", exchange+1, err)
		}
	}
	promote, err := p.decider.PromoteProbe(attempt)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("decide verified path probe promotion: %w", err)
	}
	owned = false
	return ProbeResult{Connection: transport, Promote: promote}, nil
}

func waitProbe(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
